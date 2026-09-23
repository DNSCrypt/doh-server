use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

const MIN_BACKOFF: Duration = Duration::from_millis(10);
const MAX_BACKOFF: Duration = Duration::from_secs(1);
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Accepts connections, recovering from errors instead of giving up.
///
/// Errors that only concern the connection being accepted are retried at once.
/// Anything else, such as running out of file descriptors or memory, is
/// retried with an exponential backoff, because retrying immediately would
/// fail again in a tight loop.
/// Error messages are rate limited.
#[derive(Debug, Default)]
pub(crate) struct Acceptor {
    /// Zero until an error calls for a backoff, and again after a success.
    backoff: Duration,
    last_log: Option<Instant>,
    unlogged: u64,
}

impl Acceptor {
    pub(crate) async fn accept(&mut self, listener: &TcpListener) -> (TcpStream, SocketAddr) {
        self.accept_with(|| listener.accept()).await
    }

    async fn accept_with<T, F, Fut>(&mut self, mut accept: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        loop {
            match accept().await {
                Ok(accepted) => {
                    self.backoff = Duration::ZERO;
                    return accepted;
                }
                Err(e) => {
                    if let Some(message) = self.log_message(&e, Instant::now()) {
                        eprintln!("{message}");
                    }
                    if let Some(delay) = self.delay_after(&e) {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    fn delay_after(&mut self, err: &io::Error) -> Option<Duration> {
        if is_connection_error(err) {
            return None;
        }
        self.backoff = (self.backoff * 2).clamp(MIN_BACKOFF, MAX_BACKOFF);
        Some(self.backoff)
    }

    fn log_message(&mut self, err: &io::Error, now: Instant) -> Option<String> {
        self.unlogged += 1;
        if matches!(self.last_log, Some(last_log) if now < last_log + LOG_INTERVAL) {
            return None;
        }
        self.last_log = Some(now);
        let suppressed = std::mem::take(&mut self.unlogged) - 1;
        if suppressed == 0 {
            Some(format!("Unable to accept a connection: {err}"))
        } else {
            Some(format!(
                "Unable to accept a connection: {err} ({suppressed} earlier errors not shown)"
            ))
        }
    }
}

fn is_connection_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource_error() -> io::Error {
        io::Error::new(io::ErrorKind::OutOfMemory, "injected")
    }

    fn connection_error() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, "injected")
    }

    #[test]
    fn resource_errors_back_off_exponentially_up_to_a_cap() {
        let mut acceptor = Acceptor::default();
        let delays: Vec<_> = (0..10)
            .map(|_| acceptor.delay_after(&resource_error()).unwrap())
            .collect();
        let expected: Vec<_> = [10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000]
            .iter()
            .map(|&ms| Duration::from_millis(ms))
            .collect();
        assert_eq!(delays, expected);
    }

    #[test]
    fn a_persistent_error_does_not_cause_a_busy_loop() {
        crate::tests::paused_runtime().block_on(async {
            let start = Instant::now();
            let mut acceptor = Acceptor::default();
            let mut attempts = 0u32;
            // Linux keeps a connection queued when accept() fails with EMFILE, so
            // the same error comes back until a descriptor is released.
            let released_at = start + Duration::from_secs(30);
            let accepted = acceptor
                .accept_with(|| {
                    attempts += 1;
                    assert!(attempts < 1000, "busy loop");
                    let result = if Instant::now() < released_at {
                        Err(resource_error())
                    } else {
                        Ok(attempts)
                    };
                    async move { result }
                })
                .await;
            // 8 attempts to ramp up to the maximum delay, then one per second.
            assert_eq!(accepted, attempts);
            assert!(attempts <= 8 + 30, "{} attempts", attempts);
            let recovered_after = Instant::now() - released_at;
            assert!(recovered_after <= MAX_BACKOFF, "{:?}", recovered_after);
        });
    }

    #[test]
    fn connection_errors_do_not_delay_accepting() {
        let mut acceptor = Acceptor::default();
        assert_eq!(acceptor.delay_after(&connection_error()), None);
        assert_eq!(acceptor.backoff, Duration::ZERO);
    }

    #[test]
    fn logs_are_rate_limited_and_count_suppressed_errors() {
        let start = Instant::now();
        let mut acceptor = Acceptor::default();
        let mut logged = vec![];
        for i in 0..1000u32 {
            let now = start + Duration::from_millis(50) * i;
            let err = if i % 2 == 0 {
                resource_error()
            } else {
                connection_error()
            };
            if let Some(message) = acceptor.log_message(&err, now) {
                logged.push(message);
            }
        }
        // 1000 errors over 50 seconds, at most one line every 10 seconds.
        assert_eq!(logged.len(), 5);
        assert!(!logged[0].contains("not shown"));
        assert!(logged[1].contains("(199 earlier errors not shown)"));
    }
}
