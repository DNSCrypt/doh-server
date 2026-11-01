use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::{self, Runtime};

use crate::odoh::ODoHRotator;
use crate::*;

fn real_time_runtime() -> Runtime {
    runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn test_globals(handle: &runtime::Handle) -> Globals {
    Globals {
        listen_address: "127.0.0.1:0".parse().unwrap(),
        max_clients: 16,
        timeout: Duration::from_secs(1),
        odoh_rotator: Some(Arc::new(ODoHRotator::new(handle.clone()).unwrap())),
        ..Globals::default()
    }
}

/// Allows a single TCP exchange at a time.
fn test_forwarder(server_address: SocketAddr) -> Forwarder {
    let mut forwarder = Forwarder::new(server_address, 1);
    forwarder.local_bind_address = "127.0.0.1:0".parse().unwrap();
    forwarder
}

/// Nothing listens on that port, so queries never get an answer.
fn offline_forwarder() -> Forwarder {
    test_forwarder("127.0.0.1:9".parse().unwrap())
}

fn test_server<R: Resolver>(globals: Globals, resolver: R) -> Arc<Server<R>> {
    Arc::new(Server::new(DoH::new(globals, resolver)).unwrap())
}

/// A server with deadlines shorter than any timeout would allow, so that tests
/// using real time can reach them quickly.
fn test_server_with_policy(
    globals: Globals,
    forwarder: Forwarder,
    policy: lifecycle::Policy,
) -> Arc<Server<Forwarder>> {
    Arc::new(Server::with_policy(DoH::new(globals, forwarder), policy))
}

fn offline_globals(timeout: Duration) -> Globals {
    let mut globals = test_globals(&runtime::Handle::current());
    globals.timeout = timeout;
    globals
}

fn offline_server(timeout: Duration) -> Arc<Server<Forwarder>> {
    test_server(offline_globals(timeout), offline_forwarder())
}

/// An offline server with 10 slots, so that admitting a few more connections
/// is enough to raise the pressure.
fn ten_slot_server() -> Arc<Server<Forwarder>> {
    let mut globals = offline_globals(T);
    globals.max_clients = 10;
    test_server(globals, offline_forwarder())
}

fn upstream_server(upstream: &Upstream) -> Arc<Server<Forwarder>> {
    test_server(
        test_globals(&runtime::Handle::current()),
        test_forwarder(upstream.addr),
    )
}

const T: Duration = Duration::from_secs(10);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn request_context<R>(server: &Server<R>) -> RequestContext {
    RequestContext {
        deadline: tokio::time::Instant::now() + server.policy.request,
        remote_addr: client_addr(),
    }
}

async fn query_upstream(
    server: &Server<Forwarder>,
    ctx: &RequestContext,
) -> Result<DnsResponse, DoHError> {
    server
        .doh
        .resolve(dns_query(), DoHType::Standard, HeaderMap::new(), ctx)
        .await
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.extend([0, 0, 1, 0, 1]);
    query
}

fn answered_over_tcp(packet: &[u8]) -> bool {
    packet[3] & 0x80 != 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tcp {
    Answer,
    Stall,
}

/// A local DNS server answering over UDP and TCP on the same port.
/// Answers echo the query with the QR bit set.
/// UDP answers can be truncated, and TCP answers carry the RA bit so that
/// tests can tell which transport produced them.
struct Upstream {
    addr: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    closed_tcp_connections: Arc<AtomicUsize>,
}

impl Upstream {
    async fn start(truncate: bool, tcp: Tcp) -> Upstream {
        Upstream::with_delays(truncate, tcp, Duration::ZERO, Duration::ZERO).await
    }

    async fn with_delays(
        truncate: bool,
        tcp: Tcp,
        udp_delay: Duration,
        tcp_delay: Duration,
    ) -> Upstream {
        let (udp, listener) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(listener) = TcpListener::bind(udp.local_addr().unwrap()).await {
                break (udp, listener);
            }
        };
        let addr = udp.local_addr().unwrap();
        let udp = Arc::new(udp);
        tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            while let Ok((len, client)) = udp.recv_from(&mut packet).await {
                let mut response = packet[..len].to_vec();
                response[2] |= 0x80;
                if truncate {
                    response[2] |= 0x02;
                }
                let udp = Arc::clone(&udp);
                tokio::spawn(async move {
                    tokio::time::sleep(udp_delay).await;
                    let _ = udp.send_to(&response, client).await;
                });
            }
        });
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let closed_tcp_connections = Arc::new(AtomicUsize::new(0));
        let (opened, closed) = (
            Arc::clone(&tcp_connections),
            Arc::clone(&closed_tcp_connections),
        );
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                opened.fetch_add(1, Ordering::SeqCst);
                let closed = Arc::clone(&closed);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    let mut query = vec![];
                    if stream.read_exact(&mut len).await.is_ok() {
                        query.resize(u16::from_be_bytes(len) as usize, 0);
                        if stream.read_exact(&mut query).await.is_ok() && tcp == Tcp::Answer {
                            tokio::time::sleep(tcp_delay).await;
                            query[2] |= 0x80;
                            query[3] |= 0x80;
                            let _ = stream.write_all(&len).await;
                            let _ = stream.write_all(&query).await;
                        }
                    }
                    let _ = stream.read(&mut [0u8; 1]).await;
                    closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Upstream {
            addr,
            tcp_connections,
            closed_tcp_connections,
        }
    }
}

mod config {
    use super::*;

    #[test]
    fn library_timeout_range() {
        let runtime = real_time_runtime();
        let mut globals = test_globals(runtime.handle());
        let cases = [
            (Duration::ZERO, false),
            (Duration::from_millis(999), false),
            (Duration::from_secs(1), true),
            (Duration::from_millis(1500), true),
            (Duration::from_secs(3600), true),
            (Duration::from_secs(3601), false),
            (Duration::from_secs(u64::MAX), false),
            (Duration::MAX, false),
        ];
        for (timeout, valid) in cases {
            globals.timeout = timeout;
            assert_eq!(globals.validate().is_ok(), valid, "{timeout:?}");
        }
    }

    #[test]
    fn library_limits() {
        let runtime = real_time_runtime();
        let mut globals = test_globals(runtime.handle());
        globals.max_clients = 0;
        assert!(matches!(
            globals.validate(),
            Err(DoHError::InvalidConfig(_))
        ));
        globals.max_clients = 1;
        for (max_query_len, valid) in [(16, false), (17, true), (65535, true), (65536, false)] {
            globals.max_query_len = max_query_len;
            assert_eq!(globals.validate().is_ok(), valid, "{max_query_len}");
        }
    }

    #[test]
    fn entrypoint_validates_before_binding() {
        let runtime = real_time_runtime();
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        for (timeout, max_clients) in [(Duration::ZERO, 16), (Duration::from_secs(10), 0)] {
            let mut globals = test_globals(runtime.handle());
            globals.listen_address = taken.local_addr().unwrap();
            globals.timeout = timeout;
            globals.max_clients = max_clients;
            let result = runtime.block_on(DoH::new(globals, offline_forwarder()).entrypoint());
            assert!(matches!(result, Err(DoHError::InvalidConfig(_))));
        }
    }
}

mod upstream_tcp {
    use super::*;

    #[test]
    fn pool_size() {
        for (max_tcp_connections, permits) in [(0, 1), (1, 1), (64, 64)] {
            let forwarder = Forwarder::new("127.0.0.1:53".parse().unwrap(), max_tcp_connections);
            assert_eq!(forwarder.tcp.available_permits(), permits);
        }
    }

    #[test]
    fn truncated_answers_are_retried_over_tcp() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Answer).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let response = query_upstream(&server, &ctx).await.unwrap();
            assert!(answered_over_tcp(&response.packet));
            assert_eq!(server.doh.resolver.tcp.available_permits(), 1);

            let upstream = Upstream::start(false, Tcp::Answer).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let response = query_upstream(&server, &ctx).await.unwrap();
            assert!(!answered_over_tcp(&response.packet));
            assert_eq!(upstream.tcp_connections.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn a_waiting_lookup_proceeds_when_a_permit_is_released() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Answer).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let permit = server.doh.resolver.tcp.try_acquire().unwrap();
            let lookup = query_upstream(&server, &ctx);
            let mut lookup = std::pin::pin!(lookup);
            let waiting = tokio::time::timeout(Duration::from_millis(300), &mut lookup).await;
            assert!(waiting.is_err());
            assert_eq!(upstream.tcp_connections.load(Ordering::SeqCst), 0);
            drop(permit);
            let response = lookup.await.unwrap();
            assert!(answered_over_tcp(&response.packet));
            assert_eq!(server.doh.resolver.tcp.available_permits(), 1);
        });
    }

    #[test]
    fn cancelling_a_waiting_lookup_leaves_no_waiter_behind() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Answer).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let permit = server.doh.resolver.tcp.try_acquire().unwrap();
            let cancelled =
                tokio::time::timeout(Duration::from_millis(200), query_upstream(&server, &ctx))
                    .await;
            assert!(cancelled.is_err());
            drop(permit);
            assert_eq!(server.doh.resolver.tcp.available_permits(), 1);
            assert!(server.doh.resolver.tcp.try_acquire().is_ok());
        });
    }

    #[test]
    fn a_full_pool_times_out_as_an_upstream_error() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Answer).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let _permit = server.doh.resolver.tcp.try_acquire().unwrap();
            let result = query_upstream(&server, &ctx).await;
            assert!(matches!(result, Err(DoHError::UpstreamTimeout)));
        });
    }

    #[test]
    fn a_stalled_exchange_times_out_and_releases_its_permit() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Stall).await;
            let server = upstream_server(&upstream);
            let ctx = request_context(&server);
            let started = tokio::time::Instant::now();
            let result = query_upstream(&server, &ctx).await;
            assert!(matches!(result, Err(DoHError::UpstreamTimeout)));
            assert!(started.elapsed() >= Duration::from_secs(1));
            assert_eq!(upstream.tcp_connections.load(Ordering::SeqCst), 1);
            assert_eq!(server.doh.resolver.tcp.available_permits(), 1);
        });
    }
}

pub(crate) fn paused_runtime() -> Runtime {
    runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
}

fn client_addr() -> SocketAddr {
    "192.0.2.1:1234".parse().unwrap()
}

/// Serves one in-memory connection, as if it had just been accepted.
fn connect<R: Resolver>(server: &Arc<Server<R>>) -> tokio::io::DuplexStream {
    let (client, server_io) = tokio::io::duplex(64 * 1024);
    let slot = server.admission.try_admit().expect("no free slot");
    let idle_since = slot.accepted_at;
    tokio::spawn(Arc::clone(server).serve_connection(server_io, client_addr(), slot, idle_since));
    client
}

/// Timer deadlines are rounded to the millisecond.
fn assert_at(start: tokio::time::Instant, expected: Duration) {
    let elapsed = start.elapsed();
    assert!(
        elapsed >= expected && elapsed <= expected + Duration::from_millis(1),
        "expected {:?}, got {:?}",
        expected,
        elapsed
    );
}

const ODOH_CONFIGS_GET: &[u8] = b"GET /.well-known/odohconfigs HTTP/1.1\r\nHost: localhost\r\n\r\n";

/// A body too short to be a DNS query, rejected before any upstream access.
const SHORT_QUERY: &[u8] = b"short";

fn post_head(len: usize) -> Vec<u8> {
    format!(
        "POST /dns-query HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/dns-message\r\nContent-Length: {len}\r\n\r\n"
    )
    .into_bytes()
}

#[derive(Debug)]
struct Http1Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Http1Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Just enough of an HTTP/1.1 client to check what the server sends.
struct Http1<IO> {
    io: IO,
    buf: Vec<u8>,
}

impl<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Http1<IO> {
    fn new(io: IO) -> Self {
        Http1 { io, buf: vec![] }
    }

    async fn send(&mut self, data: &[u8]) -> bool {
        self.io.write_all(data).await.is_ok()
    }

    async fn fill(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        match self.io.read(&mut chunk).await {
            Ok(0) | Err(_) => false,
            Ok(len) => {
                self.buf.extend_from_slice(&chunk[..len]);
                true
            }
        }
    }

    async fn response(&mut self) -> Option<Http1Response> {
        let head_len = loop {
            if let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if !self.fill().await {
                return None;
            }
        };
        let head = String::from_utf8(self.buf[..head_len].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers: Vec<(String, String)> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_string(), value.trim().to_string())
            })
            .collect();
        let body_len: usize = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.parse().unwrap())
            .unwrap_or(0);
        while self.buf.len() < head_len + body_len {
            if !self.fill().await {
                return None;
            }
        }
        let body = self.buf[head_len..head_len + body_len].to_vec();
        self.buf.drain(..head_len + body_len);
        Some(Http1Response {
            status,
            headers,
            body,
        })
    }

    /// Returns `true` once the server has closed the connection without
    /// sending anything else.
    async fn closed(&mut self) -> bool {
        self.buf.is_empty() && !self.fill().await
    }
}

mod http1 {
    use super::*;

    #[test]
    fn a_silent_client_is_disconnected_after_the_timeout() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            assert!(client.closed().await);
            assert_at(start, T);
            assert_eq!(server.admission.occupied(), 0);
        });
    }

    #[test]
    fn trickling_an_incomplete_head_does_not_extend_the_timeout() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            let closed = async {
                assert!(client.send(b"GET /dns-query HTTP/1.1\r\n").await);
                for i in 1.. {
                    tokio::time::sleep_until(start + secs(i)).await;
                    if !client.send(b"X-Padding: 1\r\n").await {
                        break;
                    }
                }
                assert!(client.closed().await);
            };
            closed.await;
            assert!(start.elapsed() <= T + secs(1));
        });
    }

    #[test]
    fn idle_time_restarts_after_each_response() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            for offset in [0, 8, 16] {
                tokio::time::sleep_until(start + secs(offset)).await;
                assert!(client.send(ODOH_CONFIGS_GET).await);
                assert_eq!(client.response().await.unwrap().status, 200);
            }
            assert!(client.closed().await);
            assert_at(start, secs(16) + T);
        });
    }

    #[test]
    fn every_route_counts_as_activity() {
        let requests: &[&[u8]] = &[
            b"GET /nowhere HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"PUT /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            b"GET /dns-query HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /dns-query?dns=@@ HTTP/1.1\r\nHost: localhost\r\n\
              Accept: application/dns-message\r\n\r\n",
            ODOH_CONFIGS_GET,
        ];
        for request in requests {
            paused_runtime().block_on(async {
                let server = offline_server(T);
                let start = tokio::time::Instant::now();
                let mut client = Http1::new(connect(&server));
                tokio::time::sleep_until(start + secs(5)).await;
                assert!(client.send(request).await);
                assert!(client.response().await.is_some());
                assert!(client.closed().await);
                assert_at(start, secs(5) + T);
            });
        }
    }

    #[test]
    fn a_request_in_progress_at_retirement_completes_with_connection_close() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            for offset in (0..=56).step_by(8) {
                tokio::time::sleep_until(start + secs(offset)).await;
                assert!(client.send(ODOH_CONFIGS_GET).await);
                let response = client.response().await.unwrap();
                assert_eq!(response.header("connection"), None);
            }
            tokio::time::sleep_until(start + secs(59)).await;
            assert!(client.send(&post_head(SHORT_QUERY.len())).await);
            tokio::time::sleep_until(start + secs(61)).await;
            assert!(client.send(SHORT_QUERY).await);
            let response = client.response().await.unwrap();
            assert_eq!(response.status, 422);
            assert_eq!(response.header("connection"), Some("close"));
            assert!(client.closed().await);
            assert_at(start, secs(61));
        });
    }

    #[test]
    fn a_connection_idle_at_retirement_is_closed_without_a_response() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            for offset in (0..=54).step_by(9) {
                tokio::time::sleep_until(start + secs(offset)).await;
                assert!(client.send(ODOH_CONFIGS_GET).await);
                assert_eq!(client.response().await.unwrap().status, 200);
            }
            assert!(client.closed().await);
            assert_at(start, secs(60));
        });
    }

    #[test]
    fn a_slow_body_gets_a_408_and_the_connection_is_closed() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            assert!(client.send(&post_head(29)).await);
            assert!(client.send(&[0u8; 10]).await);
            let response = client.response().await.unwrap();
            assert_eq!(response.status, 408);
            assert_at(start, T);
            assert_eq!(response.header("connection"), Some("close"));
            client.send(&[0u8; 19]).await;
            client.send(ODOH_CONFIGS_GET).await;
            assert!(client.closed().await);
        });
    }

    #[test]
    fn an_idle_connection_is_closed_as_soon_as_pressure_rises() {
        paused_runtime().block_on(async {
            let server = ten_slot_server();
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            assert!(client.send(ODOH_CONFIGS_GET).await);
            assert_eq!(client.response().await.unwrap().status, 200);
            tokio::time::sleep_until(start + secs(3)).await;
            let others: Vec<_> = (0..6)
                .map(|_| server.admission.try_admit().unwrap())
                .collect();
            assert!(client.closed().await);
            assert_at(start, secs(5));
            drop(others);
        });
    }

    #[test]
    fn keepalive_can_be_disabled() {
        paused_runtime().block_on(async {
            let mut globals = offline_globals(T);
            globals.keepalive = false;
            let server = test_server(globals, offline_forwarder());
            let mut client = Http1::new(connect(&server));
            assert!(client.send(ODOH_CONFIGS_GET).await);
            let response = client.response().await.unwrap();
            assert_eq!(response.status, 200);
            assert!(!response.body.is_empty());
            assert_eq!(response.header("connection"), Some("close"));
            assert!(client.closed().await);
        });
    }
}

struct H2Client {
    send: h2::client::SendRequest<bytes::Bytes>,
    closed: tokio::task::JoinHandle<tokio::time::Instant>,
}

impl H2Client {
    async fn start<IO>(io: IO, window: Option<u32>) -> H2Client
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut builder = h2::client::Builder::new();
        if let Some(window) = window {
            builder.initial_window_size(window);
        }
        let (send, conn) = builder.handshake(io).await.unwrap();
        let closed = tokio::spawn(async move {
            let _ = conn.await;
            tokio::time::Instant::now()
        });
        H2Client { send, closed }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        end_of_stream: bool,
    ) -> Result<(h2::client::ResponseFuture, h2::SendStream<bytes::Bytes>), h2::Error> {
        let request = hyper::http::Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .header("content-type", "application/dns-message")
            .body(())
            .unwrap();
        let mut send = self.send.clone().ready().await?;
        send.send_request(request, end_of_stream)
    }

    /// Sends a query whose body only arrives when `finish()` is called on the
    /// returned stream.
    async fn slow_post(&self) -> SlowPost {
        let (response, body) = self.request("POST", "/dns-query", false).await.unwrap();
        SlowPost { response, body }
    }

    async fn new_stream_refused(&self) -> bool {
        match self.request("GET", "/.well-known/odohconfigs", true).await {
            Err(_) => true,
            Ok((response, _)) => response.await.is_err(),
        }
    }

    async fn odoh_configs(&self) -> hyper::http::Response<h2::RecvStream> {
        let (response, _) = self
            .request("GET", "/.well-known/odohconfigs", true)
            .await
            .unwrap();
        response.await.unwrap()
    }
}

struct SlowPost {
    response: h2::client::ResponseFuture,
    body: h2::SendStream<bytes::Bytes>,
}

impl SlowPost {
    async fn finish(mut self) -> Result<u16, h2::Error> {
        self.body
            .send_data(bytes::Bytes::from_static(SHORT_QUERY), true)?;
        Ok(self.response.await?.status().as_u16())
    }
}

mod http2 {
    use super::*;

    #[test]
    fn an_idle_connection_is_closed_after_the_timeout() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), None).await;
            client.closed.await.unwrap();
            assert_at(start, T);
            assert_eq!(server.admission.occupied(), 0);
        });
    }

    #[test]
    fn a_request_in_progress_at_retirement_completes() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), None).await;
            for offset in (0..=56).step_by(8) {
                tokio::time::sleep_until(start + secs(offset)).await;
                assert_eq!(client.slow_post().await.finish().await.unwrap(), 422);
            }
            tokio::time::sleep_until(start + secs(59)).await;
            let in_progress = client.slow_post().await;
            tokio::time::sleep_until(start + secs(61)).await;
            assert!(
                client.new_stream_refused().await,
                "a new stream was accepted after the final GOAWAY"
            );
            assert_eq!(in_progress.finish().await.unwrap(), 422);
            client.closed.await.unwrap();
            assert_at(start, secs(61));
        });
    }

    #[test]
    fn a_blocked_response_is_dropped_three_timeouts_after_the_service_completed() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), Some(0)).await;
            tokio::time::sleep_until(start + secs(5)).await;
            // Dropping the body would reset the stream instead of leaving it blocked.
            let blocked = client.odoh_configs().await;
            assert_eq!(blocked.status(), 200);
            client.closed.await.unwrap();
            assert_at(start, secs(5) + T + 2 * T);
            assert_eq!(server.admission.occupied(), 0);
        });
    }

    #[test]
    fn a_busy_connection_retired_by_age_is_dropped_at_the_absolute_deadline() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), Some(0)).await;
            for offset in (0..=48).step_by(8) {
                tokio::time::sleep_until(start + secs(offset)).await;
                assert_eq!(client.slow_post().await.finish().await.unwrap(), 422);
            }
            tokio::time::sleep_until(start + secs(55)).await;
            let blocked = client.odoh_configs().await;
            assert_eq!(blocked.status(), 200);
            let busy = client.slow_post().await;
            tokio::time::sleep_until(start + secs(62)).await;
            assert_eq!(busy.finish().await.unwrap(), 422);
            client.closed.await.unwrap();
            assert_at(start, secs(80));
        });
    }

    #[test]
    fn a_reset_stream_restores_idle_tracking() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), None).await;
            tokio::time::sleep_until(start + secs(5)).await;
            let mut abandoned = client.slow_post().await;
            tokio::time::sleep_until(start + secs(7)).await;
            abandoned.body.send_reset(h2::Reason::CANCEL);
            client.closed.await.unwrap();
            assert_at(start, secs(7) + T);
        });
    }

    #[test]
    fn idle_time_starts_when_the_last_stream_completes() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), None).await;
            tokio::time::sleep_until(start + secs(2)).await;
            let first = client.slow_post().await;
            tokio::time::sleep_until(start + secs(3)).await;
            let second = client.slow_post().await;
            tokio::time::sleep_until(start + secs(5)).await;
            assert_eq!(first.finish().await.unwrap(), 422);
            tokio::time::sleep_until(start + secs(8)).await;
            assert_eq!(second.finish().await.unwrap(), 422);
            client.closed.await.unwrap();
            assert_at(start, secs(8) + T);
        });
    }

    #[test]
    fn requests_during_the_drain_do_not_postpone_the_close() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), Some(0)).await;
            let blocked = client.odoh_configs().await;
            assert_eq!(blocked.status(), 200);
            let mut late = vec![];
            for offset in [10, 12, 20] {
                tokio::time::sleep_until(start + secs(offset)).await;
                if let Ok(request) = client.request("POST", "/dns-query", false).await {
                    late.push(request);
                }
            }
            client.closed.await.unwrap();
            assert_at(start, T + 2 * T);
        });
    }
}

#[cfg(feature = "tls")]
mod tls {
    use std::convert::TryFrom;

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{
        ring, ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{
        self, ClientConfig, DigitallySignedStruct, NamedGroup, SignatureScheme,
        SupportedProtocolVersion,
    };
    use tokio_rustls::{client::TlsStream, TlsConnector};

    use super::*;

    pub(super) const CERTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../localhost.pem");

    /// The test certificate is a self-signed X.509 v1 certificate, which
    /// webpki refuses to parse, even just to check handshake signatures.
    #[derive(Debug)]
    struct AcceptAnyCert(Arc<CryptoProvider>);

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn connector(
        provider: CryptoProvider,
        versions: &[&'static SupportedProtocolVersion],
        alpn: &[u8],
    ) -> TlsConnector {
        let provider = Arc::new(provider);
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        TlsConnector::from(Arc::new(config))
    }

    fn connect_tls(server: &Arc<Server<Forwarder>>) -> tokio::io::DuplexStream {
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        accept_tls(server, server_io);
        client
    }

    fn accept_tls(server: &Arc<Server<Forwarder>>, server_io: tokio::io::DuplexStream) {
        let slot = server.admission.try_admit().expect("no free slot");
        let acceptor = crate::tls::create_tls_acceptor(CERTS, CERTS).unwrap();
        tokio::spawn(Arc::clone(server).serve_tls_connection(
            acceptor,
            server_io,
            client_addr(),
            slot,
        ));
    }

    pub(super) async fn handshake<IO>(
        io: IO,
        versions: &[&'static SupportedProtocolVersion],
        alpn: &[u8],
    ) -> std::io::Result<TlsStream<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        handshake_with(ring::default_provider(), io, versions, alpn).await
    }

    async fn handshake_with<IO>(
        provider: CryptoProvider,
        io: IO,
        versions: &[&'static SupportedProtocolVersion],
        alpn: &[u8],
    ) -> std::io::Result<TlsStream<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let name = ServerName::try_from("localhost").unwrap();
        connector(provider, versions, alpn).connect(name, io).await
    }

    /// A group the server doesn't support, offered first so that the server
    /// has to answer with a HelloRetryRequest for X25519.
    #[derive(Debug)]
    struct UnsupportedGroup;

    static UNSUPPORTED_GROUP: UnsupportedGroup = UnsupportedGroup;

    impl SupportedKxGroup for UnsupportedGroup {
        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
            Ok(Box::new(UnsupportedKeyShare))
        }

        fn name(&self) -> NamedGroup {
            NamedGroup::X448
        }
    }

    struct UnsupportedKeyShare;

    impl ActiveKeyExchange for UnsupportedKeyShare {
        fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
            Err(rustls::Error::General(
                "X448 is never negotiated".to_string(),
            ))
        }

        fn pub_key(&self) -> &[u8] {
            &[0x42; 56]
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::X448
        }
    }

    fn hello_retry_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![&UNSUPPORTED_GROUP, ring::kx_group::X25519],
            ..ring::default_provider()
        }
    }

    /// Connects a client and a server through a relay that delays every chunk
    /// by `one_way`, without holding back the chunks that follow it.
    fn slow_link(one_way: Duration) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (client, client_side) = tokio::io::duplex(64 * 1024);
        let (server_side, server) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_side);
        let (server_read, server_write) = tokio::io::split(server_side);
        tokio::spawn(relay(client_read, server_write, one_way));
        tokio::spawn(relay(server_read, client_write, one_way));
        (client, server)
    }

    async fn relay<R, W>(mut from: R, mut to: W, one_way: Duration)
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, mut receiver) =
            tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
        let writer = tokio::spawn(async move {
            while let Some((deliver_at, chunk)) = receiver.recv().await {
                tokio::time::sleep_until(deliver_at).await;
                if to.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            let _ = to.shutdown().await;
        });
        let mut chunk = vec![0u8; 16 * 1024];
        while let Ok(len @ 1..) = from.read(&mut chunk).await {
            let deliver_at = tokio::time::Instant::now() + one_way;
            let _ = sender.send((deliver_at, chunk[..len].to_vec()));
        }
        drop(sender);
        let _ = writer.await;
    }

    /// A server at 90% of its capacity once the connection under test is
    /// admitted, so that pressure is high.
    fn server_under_high_pressure() -> (Arc<Server<Forwarder>>, Vec<crate::admission::Slot>) {
        let server = ten_slot_server();
        let others = (0..8)
            .map(|_| server.admission.try_admit().unwrap())
            .collect();
        (server, others)
    }

    #[test]
    fn a_silent_peer_is_dropped_after_the_handshake_allowance() {
        for (timeout, allowance) in [(T, T), (secs(1), secs(2))] {
            paused_runtime().block_on(async {
                let server = offline_server(timeout);
                let start = tokio::time::Instant::now();
                let mut client = Http1::new(connect_tls(&server));
                assert!(client.closed().await);
                assert_at(start, allowance);
                assert_eq!(server.admission.occupied(), 0);
            });
        }
    }

    #[test]
    fn a_failed_handshake_releases_the_slot() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let mut client = connect_tls(&server);
            client.write_all(ODOH_CONFIGS_GET).await.unwrap();
            let mut alert = vec![];
            client.read_to_end(&mut alert).await.unwrap();
            assert_at(start, Duration::ZERO);
            tokio::task::yield_now().await;
            assert_eq!(server.admission.occupied(), 0);
        });
    }

    #[test]
    fn a_late_handshake_leaves_a_full_idle_allowance_for_the_first_request() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            paused_runtime().block_on(async {
                let server = offline_server(T);
                let start = tokio::time::Instant::now();
                let io = connect_tls(&server);
                tokio::time::sleep_until(start + T - Duration::from_millis(500)).await;
                let stream = handshake(io, &[version], b"http/1.1").await.unwrap();
                let handshake_done = start.elapsed();
                assert!(handshake_done < T);
                let mut client = Http1::new(stream);
                tokio::time::sleep_until(start + handshake_done + T - secs(1)).await;
                assert!(client.send(ODOH_CONFIGS_GET).await);
                assert_eq!(client.response().await.unwrap().status, 200);
                let responded = start.elapsed();
                assert!(client.closed().await);
                assert_at(start, responded + T);
            });
        }
    }

    #[test]
    fn a_silent_client_is_bounded_by_the_handshake_and_idle_allowances() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let io = connect_tls(&server);
            tokio::time::sleep_until(start + T - Duration::from_millis(500)).await;
            let stream = handshake(io, &[&rustls::version::TLS13], b"http/1.1")
                .await
                .unwrap();
            let mut client = Http1::new(stream);
            assert!(client.closed().await);
            assert_at(start, 2 * T - Duration::from_millis(500));
            assert_eq!(server.admission.occupied(), 0);
        });
    }

    #[test]
    fn a_pending_handshake_is_dropped_as_soon_as_pressure_rises() {
        paused_runtime().block_on(async {
            let server = ten_slot_server();
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect_tls(&server));
            tokio::time::sleep_until(start + secs(3)).await;
            let others: Vec<_> = (0..8)
                .map(|_| server.admission.try_admit().unwrap())
                .collect();
            assert!(client.closed().await);
            assert_at(start, secs(3));
            tokio::task::yield_now().await;
            assert_eq!(server.admission.occupied(), others.len());
        });
    }

    #[test]
    fn under_high_pressure_a_late_handshake_still_gets_to_send_its_first_request() {
        paused_runtime().block_on(async {
            let (server, _others) = server_under_high_pressure();
            let start = tokio::time::Instant::now();
            let io = connect_tls(&server);
            tokio::time::sleep_until(start + Duration::from_millis(1500)).await;
            let stream = handshake(io, &[&rustls::version::TLS13], b"http/1.1")
                .await
                .unwrap();
            let mut client = Http1::new(stream);
            tokio::time::sleep_until(start + Duration::from_millis(2400)).await;
            assert!(client.send(ODOH_CONFIGS_GET).await);
            assert_eq!(client.response().await.unwrap().status, 200);
            assert!(client.closed().await);
            assert_at(start, Duration::from_millis(3400));
        });
    }

    #[test]
    fn under_high_pressure_a_silent_client_uses_both_allowances() {
        paused_runtime().block_on(async {
            let (server, _others) = server_under_high_pressure();
            let start = tokio::time::Instant::now();
            let io = connect_tls(&server);
            tokio::time::sleep_until(start + Duration::from_millis(1500)).await;
            let stream = handshake(io, &[&rustls::version::TLS13], b"http/1.1")
                .await
                .unwrap();
            let mut client = Http1::new(stream);
            assert!(client.closed().await);
            assert_at(start, Duration::from_millis(2500));
        });
    }

    #[test]
    fn slow_handshakes_fit_in_the_floor_under_high_pressure() {
        let one_way = Duration::from_millis(250);
        let cases: [(&[&'static SupportedProtocolVersion], bool, u32); 3] = [
            (&[&rustls::version::TLS12], false, 4),
            (&[&rustls::version::TLS13], false, 2),
            (&[&rustls::version::TLS13], true, 4),
        ];
        for (versions, hello_retry, client_one_ways) in cases {
            paused_runtime().block_on(async {
                let (server, _others) = server_under_high_pressure();
                let (client_io, server_io) = slow_link(one_way);
                accept_tls(&server, server_io);
                let start = tokio::time::Instant::now();
                let provider = if hello_retry {
                    hello_retry_provider()
                } else {
                    ring::default_provider()
                };
                let stream = handshake_with(provider, client_io, versions, b"http/1.1")
                    .await
                    .unwrap();
                assert_at(start, one_way * client_one_ways);
                let group = stream.get_ref().1.negotiated_key_exchange_group().unwrap();
                assert_eq!(group.name(), NamedGroup::X25519);
                let mut client = Http1::new(stream);
                assert!(client.send(ODOH_CONFIGS_GET).await);
                assert_eq!(client.response().await.unwrap().status, 200);
            });
        }
    }

    #[test]
    fn a_handshake_slower_than_the_floor_is_dropped_under_high_pressure() {
        paused_runtime().block_on(async {
            let (server, _others) = server_under_high_pressure();
            let (client_io, server_io) = slow_link(Duration::from_millis(450));
            accept_tls(&server, server_io);
            let result = handshake_with(
                hello_retry_provider(),
                client_io,
                &[&rustls::version::TLS13],
                b"http/1.1",
            )
            .await;
            let failed = match result {
                Err(_) => true,
                Ok(stream) => {
                    let mut client = Http1::new(stream);
                    client.send(ODOH_CONFIGS_GET).await;
                    client.response().await.is_none()
                }
            };
            assert!(failed);
        });
    }

    #[test]
    fn http2_over_tls() {
        paused_runtime().block_on(async {
            let server = offline_server(T);
            let start = tokio::time::Instant::now();
            let stream = handshake(connect_tls(&server), &[&rustls::version::TLS13], b"h2")
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let client = H2Client::start(stream, None).await;
            let response = client.odoh_configs().await;
            assert_eq!(response.status(), 200);
            drop(response);
            client.closed.await.unwrap();
            assert_at(start, T);
        });
    }
}

fn encoded_query() -> String {
    use base64::engine::Engine;
    BASE64_URL_SAFE_NO_PAD.encode(dns_query())
}

fn doh_get() -> Vec<u8> {
    get_accepting(
        &format!("dns={}", encoded_query()),
        "application/dns-message",
    )
}

async fn eventually(limit: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + limit;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met in {:?}",
            limit
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Checks a real-time duration, allowing for scheduling delays.
fn assert_about(elapsed: Duration, expected: Duration) {
    assert!(
        elapsed >= expected && elapsed < expected + Duration::from_millis(350),
        "expected about {:?}, got {:?}",
        expected,
        elapsed
    );
}

mod request_budget {
    use super::*;

    const T: Duration = Duration::from_secs(1);

    async fn post_after(server: &Arc<Server<Forwarder>>, body_delay: Duration) -> (u16, Duration) {
        let start = tokio::time::Instant::now();
        let mut client = Http1::new(connect(server));
        let query = dns_query();
        assert!(client.send(&post_head(query.len())).await);
        tokio::time::sleep(body_delay).await;
        assert!(client.send(&query).await);
        let response = client.response().await.unwrap();
        (response.status, start.elapsed())
    }

    #[test]
    fn a_slow_resolver_gets_the_upstream_error() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::with_delays(false, Tcp::Answer, ms(2000), ms(0)).await;
            let server = upstream_server(&upstream);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            assert!(client.send(&doh_get()).await);
            assert_eq!(client.response().await.unwrap().status, 502);
            assert_about(start.elapsed(), T);
        });
    }

    #[test]
    fn time_spent_receiving_the_body_is_not_given_back_for_the_lookup() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::with_delays(false, Tcp::Answer, ms(500), ms(0)).await;
            let server = upstream_server(&upstream);
            assert_eq!(post_after(&server, ms(200)).await.0, 200);
            let (status, elapsed) = post_after(&server, ms(700)).await;
            assert_eq!(status, 502);
            assert_about(elapsed, T);
        });
    }

    #[test]
    fn waiting_for_a_permit_and_falling_back_to_tcp_share_the_budget() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::with_delays(true, Tcp::Answer, ms(200), ms(300)).await;
            let server = upstream_server(&upstream);
            let (status, elapsed) = post_after(&server, ms(400)).await;
            assert_eq!(status, 200);
            assert!(elapsed < T, "{:?}", elapsed);

            let holder = Arc::clone(&server);
            let permit_released = tokio::spawn(async move {
                let _permit = holder.doh.resolver.tcp.acquire().await.unwrap();
                tokio::time::sleep(ms(900)).await;
            });
            let (status, elapsed) = post_after(&server, ms(400)).await;
            assert_eq!(status, 502);
            assert_about(elapsed, T);
            permit_released.await.unwrap();
            assert_eq!(server.doh.resolver.tcp.available_permits(), 1);
        });
    }
}

mod forced_close {
    use super::*;

    fn stalling_server(upstream: &Upstream) -> Arc<Server<Forwarder>> {
        let mut globals = test_globals(&runtime::Handle::current());
        globals.max_clients = 1;
        let policy = lifecycle::Policy {
            request: Duration::from_secs(10),
            retire_after: Duration::from_secs(1),
            drain: Duration::from_secs(1),
        };
        test_server_with_policy(globals, test_forwarder(upstream.addr), policy)
    }

    async fn check_cleanup(server: &Arc<Server<Forwarder>>, upstream: &Upstream) {
        eventually(ms(300), || server.doh.resolver.tcp.available_permits() == 1).await;
        eventually(ms(300), || {
            upstream.closed_tcp_connections.load(Ordering::SeqCst) == 1
        })
        .await;
        eventually(ms(300), || server.admission.occupied() == 0).await;
    }

    #[test]
    fn http2_stream_work_is_cancelled_and_its_permit_released() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Stall).await;
            let server = stalling_server(&upstream);
            let start = tokio::time::Instant::now();
            let client = H2Client::start(connect(&server), None).await;
            let path = format!("/dns-query?dns={}", encoded_query());
            let (response, _) = client.request("GET", &path, true).await.unwrap();
            eventually(ms(500), || server.doh.resolver.tcp.available_permits() == 0).await;
            assert!(response.await.is_err());
            assert_about(start.elapsed(), Duration::from_secs(2));
            check_cleanup(&server, &upstream).await;
        });
    }

    #[test]
    fn http1_work_is_cancelled_and_its_permit_released() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(true, Tcp::Stall).await;
            let server = stalling_server(&upstream);
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(connect(&server));
            assert!(client.send(&doh_get()).await);
            eventually(ms(500), || server.doh.resolver.tcp.available_permits() == 0).await;
            assert!(client.response().await.is_none());
            assert_about(start.elapsed(), Duration::from_secs(2));
            check_cleanup(&server, &upstream).await;
        });
    }
}

mod listeners {
    use tokio::net::TcpStream;

    use super::*;

    fn short_policy(request: Duration, retire_after: Duration) -> lifecycle::Policy {
        lifecycle::Policy {
            request,
            retire_after,
            drain: Duration::from_secs(1),
        }
    }

    async fn listen(server: &Arc<Server<Forwarder>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(server).run(listener));
        addr
    }

    #[test]
    fn connections_beyond_the_limit_are_closed_at_once() {
        real_time_runtime().block_on(async {
            let mut globals = offline_globals(T);
            globals.max_clients = 1;
            let server = test_server(globals, offline_forwarder());
            let addr = listen(&server).await;

            let mut first = Http1::new(TcpStream::connect(addr).await.unwrap());
            assert!(first.send(ODOH_CONFIGS_GET).await);
            assert_eq!(first.response().await.unwrap().status, 200);
            let mut second = Http1::new(TcpStream::connect(addr).await.unwrap());
            let rejected = tokio::time::timeout(ms(500), second.closed()).await;
            assert_eq!(rejected.ok(), Some(true));
            assert_eq!(server.admission.occupied(), 1);

            drop(first);
            eventually(ms(500), || server.admission.occupied() == 0).await;
            let mut third = Http1::new(TcpStream::connect(addr).await.unwrap());
            assert!(third.send(ODOH_CONFIGS_GET).await);
            assert_eq!(third.response().await.unwrap().status, 200);
        });
    }

    #[test]
    fn http1_retirement_over_tcp() {
        real_time_runtime().block_on(async {
            let globals = offline_globals(Duration::from_secs(1));
            let policy = short_policy(Duration::from_secs(2), Duration::from_secs(1));
            let server = test_server_with_policy(globals, offline_forwarder(), policy);
            let addr = listen(&server).await;
            let start = tokio::time::Instant::now();
            let mut client = Http1::new(TcpStream::connect(addr).await.unwrap());
            tokio::time::sleep(ms(700)).await;
            assert!(client.send(&post_head(SHORT_QUERY.len())).await);
            tokio::time::sleep(ms(700)).await;
            assert!(client.send(SHORT_QUERY).await);
            let response = client.response().await.unwrap();
            assert_eq!(response.status, 422);
            assert_eq!(response.header("connection"), Some("close"));
            assert!(client.closed().await);
            assert_about(start.elapsed(), ms(1400));
        });
    }

    #[test]
    fn http2_goaway_and_flow_control_over_tcp() {
        real_time_runtime().block_on(async {
            let globals = offline_globals(Duration::from_secs(1));
            let policy = short_policy(ms(500), Duration::from_secs(60));
            let server = test_server_with_policy(globals, offline_forwarder(), policy);
            let addr = listen(&server).await;
            let start = tokio::time::Instant::now();
            let client = H2Client::start(TcpStream::connect(addr).await.unwrap(), Some(0)).await;
            let blocked = client.odoh_configs().await;
            assert_eq!(blocked.status(), 200);
            tokio::time::sleep(ms(700)).await;
            assert!(client.new_stream_refused().await);
            client.closed.await.unwrap();
            assert_about(start.elapsed(), ms(1500));
            eventually(ms(300), || server.admission.occupied() == 0).await;
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn the_tls_listener_rejects_connections_before_any_tls_work() {
        use tokio_rustls::rustls;

        real_time_runtime().block_on(async {
            let certs = super::tls::CERTS;
            let mut globals = offline_globals(T);
            globals.max_clients = 1;
            globals.tls_cert_path = Some(certs.into());
            globals.tls_cert_key_path = Some(certs.into());
            let server = test_server(globals, offline_forwarder());
            let addr = listen(&server).await;

            let tls13: &[&'static rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
            let mut first = None;
            for _ in 0..50 {
                let tcp = TcpStream::connect(addr).await.unwrap();
                if let Ok(stream) = super::tls::handshake(tcp, tls13, b"http/1.1").await {
                    first = Some(Http1::new(stream));
                    break;
                }
                tokio::time::sleep(ms(20)).await;
            }
            let mut first = first.expect("the certificate was never loaded");
            assert!(first.send(ODOH_CONFIGS_GET).await);
            assert_eq!(first.response().await.unwrap().status, 200);

            let mut second = TcpStream::connect(addr).await.unwrap();
            let mut received = vec![];
            let closed = tokio::time::timeout(ms(500), second.read_to_end(&mut received)).await;
            assert!(matches!(closed, Ok(Ok(0))), "{:?}", closed);
            assert_eq!(server.admission.occupied(), 1);

            drop(first);
            eventually(ms(500), || server.admission.occupied() == 0).await;
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut third = Http1::new(
                super::tls::handshake(tcp, tls13, b"http/1.1")
                    .await
                    .unwrap(),
            );
            assert!(third.send(ODOH_CONFIGS_GET).await);
            assert_eq!(third.response().await.unwrap().status, 200);
        });
    }
}

/// Answers each query with itself, or with an error, and keeps it.
struct Echo {
    allow_connections: bool,
    error: Option<fn() -> DoHError>,
    queries: std::sync::Mutex<Vec<Query>>,
}

impl Echo {
    fn new() -> Echo {
        Echo {
            allow_connections: true,
            error: None,
            queries: Default::default(),
        }
    }
}

impl Resolver for Echo {
    fn allow_connection(&self, _remote_addr: SocketAddr) -> bool {
        self.allow_connections
    }

    async fn resolve(&self, query: Query) -> Result<DnsResponse, DoHError> {
        let packet = query.packet.clone();
        self.queries.lock().unwrap().push(query);
        if let Some(error) = self.error {
            return Err(error());
        }
        let cache = CachePolicy {
            max_age: 42,
            scope: CacheScope::Private,
            ..CachePolicy::default()
        };
        Ok(DnsResponse { packet, cache })
    }
}

fn get_accepting(query_string: &str, content_type: &str) -> Vec<u8> {
    format!(
        "GET /dns-query?{query_string} HTTP/1.1\r\nHost: localhost\r\n\
         Accept: {content_type}\r\n\r\n"
    )
    .into_bytes()
}

mod resolvers {
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn a_resolver_gets_the_queries_and_sets_the_cache_policy() {
        for cors in [false, true] {
            paused_runtime().block_on(async {
                let mut globals = offline_globals(T);
                globals.cors = cors;
                let server = test_server(globals, Echo::new());
                let mut client = Http1::new(connect(&server));
                let query = dns_query();
                let mut post = post_head(query.len());
                post.extend(&query);
                let json = get_accepting("name=example.com&type=A", "application/dns-json");
                let requests = vec![
                    (doh_get(), "application/dns-message"),
                    (post, "application/dns-message"),
                    (json, "application/dns-json"),
                ];
                for (request, content_type) in requests {
                    assert!(client.send(&request).await);
                    let response = client.response().await.unwrap();
                    assert_eq!(response.status, 200);
                    assert_eq!(response.header("content-type"), Some(content_type));
                    assert_eq!(
                        response.header("cache-control"),
                        Some("private, max-age=42")
                    );
                    assert_eq!(
                        response.header("access-control-allow-origin"),
                        cors.then_some("*")
                    );
                }
                let queries = server.doh.resolver.queries.lock().unwrap();
                let kinds: Vec<_> = queries.iter().map(|query| query.kind).collect();
                assert_eq!(kinds, [DoHType::Standard, DoHType::Standard, DoHType::Json]);
                assert_eq!(queries[0].packet, query);
                assert_eq!(queries[1].packet, query);
                for query in queries.iter() {
                    assert_eq!(query.remote_addr, client_addr());
                    assert_eq!(query.headers["host"], "localhost");
                }
            });
        }
    }

    #[test]
    fn errors_become_status_codes() {
        let cases: [(fn() -> DoHError, u16); 2] = [
            (|| DoHError::TooManyRequests, 429),
            (|| DoHError::UpstreamIssue, 502),
        ];
        for (error, status) in cases {
            paused_runtime().block_on(async {
                let mut echo = Echo::new();
                echo.error = Some(error);
                let server = test_server(offline_globals(T), echo);
                let mut client = Http1::new(connect(&server));
                assert!(client.send(&doh_get()).await);
                assert_eq!(client.response().await.unwrap().status, status);

                // Too short to be DNS, so the resolver never sees it.
                let mut post = post_head(SHORT_QUERY.len());
                post.extend(SHORT_QUERY);
                assert!(client.send(&post).await);
                assert_eq!(client.response().await.unwrap().status, 422);
                assert_eq!(server.doh.resolver.queries.lock().unwrap().len(), 1);
            });
        }
    }

    async fn closed_at_once(addr: SocketAddr) -> bool {
        let mut client = Http1::new(TcpStream::connect(addr).await.unwrap());
        let closed = tokio::time::timeout(ms(500), client.closed()).await;
        closed.ok() == Some(true)
    }

    fn refusing_echo() -> Echo {
        Echo {
            allow_connections: false,
            ..Echo::new()
        }
    }

    #[test]
    fn refused_connections_are_closed_at_once() {
        real_time_runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(DoH::new(offline_globals(T), refusing_echo()).serve(listener));
            assert!(closed_at_once(addr).await);
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn refused_connections_are_closed_before_the_tls_handshake() {
        real_time_runtime().block_on(async {
            let server = test_server(offline_globals(T), refusing_echo());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let certs = super::tls::CERTS;
            let tls_acceptor = crate::tls::create_tls_acceptor(certs, certs).unwrap();
            let (_, receiver) = tokio::sync::watch::channel(Some(tls_acceptor));
            tokio::spawn(server.accept_tls_connections(listener, receiver));
            assert!(closed_at_once(addr).await);
        });
    }

    #[test]
    fn routing_follows_the_settings() {
        let dns = format!("dns={}", encoded_query());
        let elsewhere = format!(
            "GET /elsewhere?{dns} HTTP/1.1\r\nHost: localhost\r\n\
             Accept: application/dns-message\r\n\r\n"
        );
        let empty_post = |content_type| {
            format!(
                "POST /dns-query HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Type: {content_type}\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes()
        };
        let requests = [
            elsewhere.into_bytes(),
            get_accepting(&dns, "text/html, */*"),
            get_accepting("name=example.com", "application/dns-json"),
            ODOH_CONFIGS_GET.to_vec(),
            empty_post("application/oblivious-dns-message"),
            empty_post("text/plain"),
        ];
        paused_runtime().block_on(async {
            let mut lenient = offline_globals(T);
            lenient.path = None;
            lenient.require_accept = false;
            let mut without_odoh_and_json = offline_globals(T);
            without_odoh_and_json.odoh_rotator = None;
            without_odoh_and_json.enable_json = false;
            let cases = [
                (offline_globals(T), [404, 406, 200, 200, 400, 415]),
                (lenient, [200, 200, 200, 200, 400, 415]),
                (without_odoh_and_json, [404, 406, 406, 404, 415, 415]),
            ];
            for (globals, statuses) in cases {
                let server = test_server(globals, Echo::new());
                let mut client = Http1::new(connect(&server));
                for (request, status) in requests.iter().zip(statuses) {
                    assert!(client.send(request).await);
                    let response = client.response().await.unwrap();
                    assert_eq!(
                        response.status,
                        status,
                        "{}",
                        String::from_utf8_lossy(request)
                    );
                }
            }
        });
    }

    #[test]
    fn queries_up_to_the_maximum_size_are_accepted() {
        use base64::engine::general_purpose::URL_SAFE;

        paused_runtime().block_on(async {
            let server = test_server(offline_globals(T), Echo::new());
            let max_query_len = server.doh.globals.max_query_len;
            let mut client = Http1::new(connect(&server));
            let accepting = |query: String| get_accepting(&query, "application/dns-message");
            // A body that is too large may leave the connection unusable, so it comes last.
            for (len, statuses) in [
                (max_query_len, [200; 3]),
                (max_query_len + 1, [400, 400, 413]),
            ] {
                let query = vec![0u8; len];
                let mut post = post_head(len);
                post.extend(&query);
                let requests = vec![
                    accepting(format!("dns={}", BASE64_URL_SAFE_NO_PAD.encode(&query))),
                    accepting(format!("dns={}", URL_SAFE.encode(&query))),
                    post,
                ];
                for (request, status) in requests.into_iter().zip(statuses) {
                    assert!(client.send(&request).await);
                    assert_eq!(client.response().await.unwrap().status, status, "{len}");
                }
            }
            assert_eq!(server.doh.resolver.queries.lock().unwrap().len(), 3);

            // The server builds JSON queries itself, and they have the same limit.
            // This one is a 29-byte DNS message.
            let json = get_accepting("name=example.com", "application/dns-json");
            for (max_query_len, status) in [(29, 200), (28, 413)] {
                let mut globals = offline_globals(T);
                globals.max_query_len = max_query_len;
                let server = test_server(globals, Echo::new());
                let mut client = Http1::new(connect(&server));
                assert!(client.send(&json).await);
                assert_eq!(client.response().await.unwrap().status, status);
            }
        });
    }
}

mod client_subnet {
    use super::*;

    /// The ECS option for 198.51.100.0/24.
    const ECS_OPTION: [u8; 11] = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];

    fn has_ecs_option(packet: &[u8]) -> bool {
        packet.windows(ECS_OPTION.len()).any(|w| w == ECS_OPTION)
    }

    #[test]
    fn forwarded_addresses_are_sent_upstream_unless_the_query_is_oblivious() {
        real_time_runtime().block_on(async {
            let upstream = Upstream::start(false, Tcp::Answer).await;
            let mut forwarder = test_forwarder(upstream.addr);
            forwarder.enable_ecs = true;
            let server = test_server(test_globals(&runtime::Handle::current()), forwarder);
            let mut client = Http1::new(connect(&server));
            let request = format!(
                "GET /dns-query?dns={} HTTP/1.1\r\nHost: localhost\r\n\
                 Accept: application/dns-message\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n",
                encoded_query()
            );
            assert!(client.send(request.as_bytes()).await);
            let response = client.response().await.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                response.header("cache-control"),
                Some("max-age=604800, stale-if-error=86400, stale-while-revalidate=60")
            );
            assert_eq!(response.header("access-control-allow-origin"), Some("*"));
            assert!(has_ecs_option(&response.body));

            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
            let ctx = request_context(&server);
            let response = server
                .doh
                .resolve(dns_query(), DoHType::Oblivious, headers, &ctx)
                .await
                .unwrap();
            assert!(!has_ecs_option(&response.packet));
        });
    }
}
