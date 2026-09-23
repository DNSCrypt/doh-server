use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::Duration;

use futures::{select_biased, FutureExt};
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};

use crate::admission::{Pressure, Slot};

const MIN_RETIRE_AFTER: Duration = Duration::from_secs(60);
const IDLE_FLOOR: Duration = Duration::from_secs(1);
#[cfg(feature = "tls")]
const HANDSHAKE_FLOOR: Duration = Duration::from_secs(2);

/// Connection and request deadlines, all derived from the configured timeout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Policy {
    /// Budget of a request, from the moment its head has been received.
    pub(crate) request: Duration,
    /// Connection age at which graceful retirement starts.
    pub(crate) retire_after: Duration,
    /// Time given to a retiring connection to finish its work.
    pub(crate) drain: Duration,
}

impl Policy {
    /// The timeout must have been checked by `Globals::validate()`, which
    /// guarantees that none of the derived values overflow.
    pub(crate) fn new(timeout: Duration) -> Policy {
        Policy {
            request: timeout,
            retire_after: (timeout * 6).max(MIN_RETIRE_AFTER),
            drain: timeout * 2,
        }
    }

    /// How long a connection may stay without any request in progress.
    pub(crate) fn idle_allowance(&self, pressure: Pressure) -> Duration {
        match pressure {
            Pressure::Normal => self.request,
            Pressure::Elevated => (self.request / 2).max(IDLE_FLOOR),
            Pressure::High => (self.request / 10).max(IDLE_FLOOR),
        }
    }

    /// How long a TLS handshake may take, counted from the TCP accept.
    /// The floor leaves room for a few round trips on slow links even under
    /// high pressure.
    #[cfg(feature = "tls")]
    pub(crate) fn handshake_allowance(&self, pressure: Pressure) -> Duration {
        self.idle_allowance(pressure).max(HANDSHAKE_FLOOR)
    }

    fn retire_at(&self, accepted_at: Instant) -> Instant {
        accepted_at + self.retire_after
    }

    fn absolute_deadline(&self, accepted_at: Instant) -> Instant {
        self.retire_at(accepted_at) + self.drain
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ActivityState {
    /// Service futures that have been created and not completed or dropped yet.
    pub(crate) active: usize,
    /// When `active` last dropped to zero, or when the connection became
    /// ready for its first request.
    pub(crate) idle_since: Instant,
}

/// Tracks the requests being processed on a connection.
///
/// The count is updated for every request, but the connection task is only
/// woken up when the connection becomes idle.
/// A request starting doesn't need to wake it: the task rereads the count
/// before acting on an idle deadline.
#[derive(Debug)]
pub(crate) struct Activity(watch::Sender<ActivityState>);

impl Activity {
    pub(crate) fn new(idle_since: Instant) -> Arc<Activity> {
        Arc::new(Activity(watch::Sender::new(ActivityState {
            active: 0,
            idle_since,
        })))
    }

    /// Must be called before the service future is returned, so that the
    /// connection task never sees an accepted request as idle time.
    pub(crate) fn enter(self: &Arc<Self>) -> ActivityGuard {
        self.0.send_if_modified(|state| {
            state.active += 1;
            false
        });
        ActivityGuard(Arc::clone(self))
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> ActivityState {
        *self.0.borrow()
    }

    fn subscribe(&self) -> watch::Receiver<ActivityState> {
        self.0.subscribe()
    }
}

#[derive(Debug)]
pub(crate) struct ActivityGuard(Arc<Activity>);

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0 .0.send_if_modified(|state| {
            state.active -= 1;
            if state.active > 0 {
                return false;
            }
            state.idle_since = Instant::now();
            true
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ending {
    /// The connection finished on its own.
    Closed,
    /// The connection finished after a graceful shutdown.
    Retired,
    /// The connection was still busy when its drain deadline expired.
    Forced,
}

/// Drives a connection until it closes, retiring it gracefully when it has been
/// idle for too long or when it gets too old, and dropping it if it doesn't
/// finish in time after that.
///
/// The idle allowance follows the connection pressure, but always counts from
/// the moment the connection became idle.
/// Once retirement has started, the close deadline is fixed: neither new
/// activity nor pressure changes can postpone it.
pub(crate) async fn drive<C, S>(
    mut conn: Pin<&mut C>,
    shutdown: S,
    policy: &Policy,
    activity: &Activity,
    slot: &Slot,
) -> Ending
where
    C: Future,
    S: FnOnce(Pin<&mut C>),
{
    let accepted_at = slot.accepted_at;
    let retire_at = policy.retire_at(accepted_at);
    let mut activity = activity.subscribe();
    let mut pressure = slot.pressure();
    let mut timer = pin!(sleep_until(retire_at));
    loop {
        let state = *activity.borrow_and_update();
        let level = *pressure.borrow_and_update();
        let mut deadline = retire_at;
        if state.active == 0 {
            deadline = deadline.min(state.idle_since + policy.idle_allowance(level));
        }
        if Instant::now() >= deadline {
            break;
        }
        timer.as_mut().reset(deadline);
        select_biased! {
            _ = conn.as_mut().fuse() => return Ending::Closed,
            _ = timer.as_mut().fuse() => {}
            _ = activity.changed().fuse() => {}
            _ = pressure.changed().fuse() => {}
        }
    }

    shutdown(conn.as_mut());
    let close_at = policy
        .absolute_deadline(accepted_at)
        .min(Instant::now() + policy.drain);
    timer.as_mut().reset(close_at);
    select_biased! {
        _ = conn.as_mut().fuse() => Ending::Retired,
        _ = timer.as_mut().fuse() => Ending::Forced,
    }
}

#[cfg(feature = "tls")]
/// Runs a TLS handshake, giving up once the handshake allowance, counted from
/// the TCP accept, has been used.
///
/// The allowance follows the connection pressure without restarting the
/// handshake or the count.
pub(crate) async fn handshake<F: Future>(
    handshake: F,
    policy: &Policy,
    slot: &Slot,
) -> Option<F::Output> {
    let accepted_at = slot.accepted_at;
    let absolute_deadline = policy.absolute_deadline(accepted_at);
    let deadline = |level| (accepted_at + policy.handshake_allowance(level)).min(absolute_deadline);
    let mut pressure = slot.pressure();
    let mut handshake = pin!(handshake);
    let mut timer = pin!(sleep_until(absolute_deadline));
    loop {
        let current_deadline = deadline(*pressure.borrow_and_update());
        if Instant::now() >= current_deadline {
            return None;
        }
        timer.as_mut().reset(current_deadline);
        select_biased! {
            output = handshake.as_mut().fuse() => {
                // Pressure may have risen since the deadline was computed, moving
                // it into the past while the handshake was completing.
                let in_time = Instant::now() < deadline(*pressure.borrow());
                return in_time.then_some(output);
            }
            _ = timer.as_mut().fuse() => {}
            _ = pressure.changed().fuse() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use tokio::time::sleep;

    use super::*;
    use crate::admission::Admission;

    const T: Duration = Duration::from_secs(10);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A connection that can finish on its own, and that finishes a given time
    /// after a graceful shutdown, or never.
    struct FakeConn {
        inner: Pin<Box<dyn Future<Output = ()> + Send>>,
        finish_after_shutdown: Option<Duration>,
        shutdowns: Vec<Instant>,
    }

    impl FakeConn {
        fn new(finish_at: Option<Instant>, finish_after_shutdown: Option<Duration>) -> FakeConn {
            let inner: Pin<Box<dyn Future<Output = ()> + Send>> = match finish_at {
                Some(finish_at) => Box::pin(sleep_until(finish_at)),
                None => Box::pin(std::future::pending()),
            };
            FakeConn {
                inner,
                finish_after_shutdown,
                shutdowns: vec![],
            }
        }

        fn shutdown(&mut self) {
            self.shutdowns.push(Instant::now());
            if let Some(delay) = self.finish_after_shutdown {
                self.inner = Box::pin(sleep(delay));
            }
        }
    }

    impl Future for FakeConn {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }

    fn paused<F: Future>(test: F) -> F::Output {
        crate::tests::paused_runtime().block_on(test)
    }

    /// Holds an activity guard between two offsets from `start`.
    fn request(activity: &Arc<Activity>, start: Instant, from: Duration, to: Duration) {
        let activity = Arc::clone(activity);
        tokio::spawn(async move {
            sleep_until(start + from).await;
            let guard = activity.enter();
            sleep_until(start + to).await;
            drop(guard);
        });
    }

    /// Drives a connection accepted just now.
    async fn run(conn: &mut FakeConn, activity: &Activity) -> Ending {
        let admission = Admission::new(10);
        let slot = admission.try_admit().unwrap();
        run_with_slot(conn, activity, &slot).await
    }

    async fn run_with_slot(conn: &mut FakeConn, activity: &Activity, slot: &Slot) -> Ending {
        let policy = Policy::new(T);
        drive(
            Pin::new(conn),
            |conn| conn.get_mut().shutdown(),
            &policy,
            activity,
            slot,
        )
        .await
    }

    #[test]
    fn policy_values() {
        let policy = Policy::new(secs(10));
        assert_eq!(policy.retire_after, secs(60));
        assert_eq!(policy.drain, secs(20));
        let policy = Policy::new(secs(20));
        assert_eq!(policy.retire_after, secs(120));
        assert_eq!(policy.drain, secs(40));
        let policy = Policy::new(secs(1));
        assert_eq!(policy.retire_after, secs(60));
        assert_eq!(policy.drain, secs(2));
        let policy = Policy::new(secs(3600));
        assert_eq!(policy.retire_after, secs(21600));
        assert_eq!(policy.drain, secs(7200));
    }

    #[test]
    fn a_connection_that_closes_by_itself() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            let mut conn = FakeConn::new(Some(start + secs(3)), None);
            assert_eq!(run(&mut conn, &activity).await, Ending::Closed);
            assert_eq!(start.elapsed(), secs(3));
            assert!(conn.shutdowns.is_empty());
        });
    }

    #[test]
    fn an_idle_connection_is_retired_after_the_idle_allowance() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            assert_eq!(run(&mut conn, &activity).await, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + T]);
        });
    }

    #[test]
    fn idle_time_starts_when_the_connection_is_ready() {
        paused(async {
            let accepted_at = Instant::now();
            let ready_at = accepted_at + secs(7);
            let activity = Activity::new(ready_at);
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            assert_eq!(run(&mut conn, &activity).await, Ending::Retired);
            assert_eq!(conn.shutdowns, [ready_at + T]);
        });
    }

    #[test]
    fn idle_time_starts_when_the_last_request_completes() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            request(&activity, start, secs(1), secs(5));
            request(&activity, start, secs(2), secs(8));
            request(&activity, start, secs(3), secs(4));
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            assert_eq!(run(&mut conn, &activity).await, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + secs(8) + T]);
        });
    }

    #[test]
    fn a_request_starting_just_before_the_idle_deadline_prevents_retirement() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            request(&activity, start, T - Duration::from_millis(1), secs(12));
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            assert_eq!(run(&mut conn, &activity).await, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + secs(12) + T]);
        });
    }

    #[test]
    fn a_busy_connection_is_retired_by_age_and_allowed_to_finish() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            request(&activity, start, secs(1), secs(70));
            let mut conn = FakeConn::new(None, Some(secs(15)));
            assert_eq!(run(&mut conn, &activity).await, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + secs(60)]);
            assert_eq!(start.elapsed(), secs(75));
        });
    }

    #[test]
    fn a_stalled_connection_is_dropped_at_the_absolute_deadline() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            request(&activity, start, secs(1), secs(100));
            let mut conn = FakeConn::new(None, None);
            assert_eq!(run(&mut conn, &activity).await, Ending::Forced);
            assert_eq!(conn.shutdowns, [start + secs(60)]);
            assert_eq!(start.elapsed(), secs(80));
        });
    }

    #[test]
    fn early_retirement_has_its_own_drain_deadline() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            request(&activity, start, secs(1), secs(4));
            let mut conn = FakeConn::new(None, None);
            assert_eq!(run(&mut conn, &activity).await, Ending::Forced);
            assert_eq!(conn.shutdowns, [start + secs(4) + T]);
            assert_eq!(start.elapsed(), secs(4) + T + 2 * T);
        });
    }

    #[test]
    fn activity_during_the_drain_does_not_postpone_the_close() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            for i in 0..10 {
                request(&activity, start, T + secs(2 * i), T + secs(2 * i + 1));
            }
            request(&activity, start, T + secs(5), T + secs(100));
            let mut conn = FakeConn::new(None, None);
            assert_eq!(run(&mut conn, &activity).await, Ending::Forced);
            assert_eq!(conn.shutdowns, [start + T]);
            assert_eq!(start.elapsed(), T + 2 * T);
        });
    }

    #[test]
    fn a_retirement_started_late_is_still_bounded_by_the_absolute_deadline() {
        paused(async {
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            let accepted_at = slot.accepted_at;
            let activity = Activity::new(accepted_at);
            let _busy = activity.enter();
            sleep(secs(70)).await;
            let mut conn = FakeConn::new(None, None);
            let ending = run_with_slot(&mut conn, &activity, &slot).await;
            assert_eq!(ending, Ending::Forced);
            assert_eq!(conn.shutdowns, [accepted_at + secs(70)]);
            assert_eq!(accepted_at.elapsed(), secs(80));
        });
    }

    /// Occupies `count` more slots of `admission` from `at` until `until`.
    fn occupy(
        admission: &Arc<Admission>,
        start: Instant,
        count: usize,
        at: Duration,
        until: Duration,
    ) {
        let admission = Arc::clone(admission);
        tokio::spawn(async move {
            sleep_until(start + at).await;
            let slots: Vec<_> = (0..count).map(|_| admission.try_admit().unwrap()).collect();
            sleep_until(start + until).await;
            drop(slots);
        });
    }

    #[test]
    fn allowances_under_pressure() {
        let policy = Policy::new(secs(10));
        assert_eq!(policy.idle_allowance(Pressure::Normal), secs(10));
        assert_eq!(policy.idle_allowance(Pressure::Elevated), secs(5));
        assert_eq!(policy.idle_allowance(Pressure::High), secs(1));
        let policy = Policy::new(secs(1));
        assert_eq!(policy.idle_allowance(Pressure::Normal), secs(1));
        assert_eq!(policy.idle_allowance(Pressure::Elevated), secs(1));
        assert_eq!(policy.idle_allowance(Pressure::High), secs(1));
        let policy = Policy::new(secs(30));
        assert_eq!(policy.idle_allowance(Pressure::High), secs(3));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_allowances_have_their_own_floor() {
        let policy = Policy::new(secs(10));
        assert_eq!(policy.handshake_allowance(Pressure::Normal), secs(10));
        assert_eq!(policy.handshake_allowance(Pressure::Elevated), secs(5));
        assert_eq!(policy.handshake_allowance(Pressure::High), secs(2));
        let policy = Policy::new(secs(1));
        assert_eq!(policy.handshake_allowance(Pressure::Normal), secs(2));
    }

    #[test]
    fn rising_pressure_shortens_the_idle_allowance_from_the_original_idle_start() {
        for (extra, retired_at) in [(6, secs(5)), (8, secs(3))] {
            paused(async {
                let start = Instant::now();
                let admission = Admission::new(10);
                let slot = admission.try_admit().unwrap();
                occupy(&admission, start, extra, secs(3), secs(100));
                let activity = Activity::new(start);
                let mut conn = FakeConn::new(None, Some(Duration::ZERO));
                let ending = run_with_slot(&mut conn, &activity, &slot).await;
                assert_eq!(ending, Ending::Retired);
                assert_eq!(conn.shutdowns, [start + retired_at]);
            });
        }
    }

    #[test]
    fn pressure_recovery_does_not_restart_the_idle_interval() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            occupy(&admission, start, 6, secs(1), secs(3));
            let activity = Activity::new(start);
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            let ending = run_with_slot(&mut conn, &activity, &slot).await;
            assert_eq!(ending, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + T]);
        });
    }

    #[test]
    fn pressure_does_not_affect_requests_in_progress() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            occupy(&admission, start, 8, secs(2), secs(100));
            let activity = Activity::new(start);
            request(&activity, start, secs(1), secs(8));
            let mut conn = FakeConn::new(None, Some(Duration::ZERO));
            let ending = run_with_slot(&mut conn, &activity, &slot).await;
            assert_eq!(ending, Ending::Retired);
            assert_eq!(conn.shutdowns, [start + secs(9)]);
        });
    }

    #[test]
    fn pressure_changes_during_the_drain_are_ignored() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            occupy(&admission, start, 8, secs(15), secs(20));
            occupy(&admission, start, 6, secs(22), secs(25));
            let activity = Activity::new(start);
            let mut conn = FakeConn::new(None, None);
            let ending = run_with_slot(&mut conn, &activity, &slot).await;
            assert_eq!(ending, Ending::Forced);
            assert_eq!(conn.shutdowns, [start + T]);
            assert_eq!(start.elapsed(), T + 2 * T);
        });
    }

    #[cfg(feature = "tls")]
    async fn run_handshake(
        admission: &Arc<Admission>,
        completes_at: Option<Duration>,
    ) -> Option<()> {
        let slot = admission.try_admit().unwrap();
        let pending: Pin<Box<dyn Future<Output = ()> + Send>> = match completes_at {
            Some(at) => Box::pin(sleep_until(slot.accepted_at + at)),
            None => Box::pin(std::future::pending()),
        };
        handshake(pending, &Policy::new(T), &slot).await
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pending_handshakes_follow_pressure_from_the_accept_time() {
        for (at, dropped_at) in [(secs(3), secs(3)), (secs(1), secs(2))] {
            paused(async {
                let start = Instant::now();
                let admission = Admission::new(10);
                occupy(&admission, start, 8, at, secs(100));
                assert!(run_handshake(&admission, None).await.is_none());
                assert_eq!(start.elapsed(), dropped_at);
            });
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_allowances_recover_without_restarting() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            occupy(&admission, start, 8, secs(1), Duration::from_millis(1500));
            assert!(run_handshake(&admission, None).await.is_none());
            assert_eq!(start.elapsed(), T);
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_handshake_ready_when_its_deadline_moves_into_the_past_is_dropped() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            occupy(&admission, start, 8, secs(3), secs(100));
            let mut high_pressure = slot.pressure();
            let completes_with_the_pressure_change = async move {
                let _ = high_pressure
                    .wait_for(|level| *level == Pressure::High)
                    .await;
            };
            let result =
                handshake(completes_with_the_pressure_change, &Policy::new(T), &slot).await;
            assert!(result.is_none());
            assert_eq!(start.elapsed(), secs(3));
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_pressure_recovery_at_the_deadline_extends_the_handshake_allowance() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            let slot = admission.try_admit().unwrap();
            let others: Vec<_> = (0..8).map(|_| admission.try_admit().unwrap()).collect();
            // Polled before the timer in the same wakeup, this releases the other
            // slots exactly when the high-pressure allowance runs out.
            let releases_them_at_the_deadline = async move {
                sleep_until(start + secs(2)).await;
                drop(others);
                std::future::pending::<()>().await
            };
            let result = handshake(releases_them_at_the_deadline, &Policy::new(T), &slot).await;
            assert!(result.is_none());
            assert_eq!(start.elapsed(), T);
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_handshake_completing_in_time_is_returned() {
        paused(async {
            let start = Instant::now();
            let admission = Admission::new(10);
            occupy(&admission, start, 8, secs(1), secs(100));
            let completes_at = Duration::from_millis(1900);
            assert!(run_handshake(&admission, Some(completes_at))
                .await
                .is_some());
            assert_eq!(start.elapsed(), completes_at);
        });
    }

    #[test]
    fn the_activity_count_is_exact() {
        paused(async {
            let start = Instant::now();
            let activity = Activity::new(start);
            let first = activity.enter();
            let second = activity.enter();
            assert_eq!(activity.state().active, 2);
            sleep(secs(1)).await;
            drop(first);
            assert_eq!(activity.state().active, 1);
            assert_eq!(activity.state().idle_since, start);
            sleep(secs(1)).await;
            drop(second);
            assert_eq!(activity.state().active, 0);
            assert_eq!(activity.state().idle_since, start + secs(2));
        });
    }
}
