#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod dns;
mod utils;

use base64;
use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use futures::stream::Stream;
use hyper;
use hyper::server::conn::Http;
use hyper::service::Service;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::io;

#[cfg(feature = "tls")]
use native_tls::{self, Identity};

#[cfg(feature = "tls")]
use std::fs::File;

#[cfg(feature = "tls")]
use std::io::{self, Read};
use std::net::SocketAddr;

#[cfg(feature = "tls")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio;
use tokio::net::{TcpListener, UdpSocket};
use tokio::prelude::{AsyncRead, AsyncWrite, FutureExt};

#[cfg(feature = "tls")]
use tokio_tls::TlsAcceptor;

const BLOCK_SIZE: usize = 128;
const DNS_QUERY_PARAM: &str = "dns";
const LISTEN_ADDRESS: &str = "127.0.0.1:3000";
const LOCAL_BIND_ADDRESS: &str = "0.0.0.0:0";
const MAX_CLIENTS: usize = 512;
const MAX_DNS_QUESTION_LEN: usize = 512;
const MAX_DNS_RESPONSE_LEN: usize = 4096;
const MIN_DNS_PACKET_LEN: usize = 17;
const PATH: &str = "/dns-query";
const SERVER_ADDRESS: &str = "9.9.9.9:53";
const TIMEOUT_SEC: u64 = 10;
const MAX_TTL: u32 = 86400 * 7;
const MIN_TTL: u32 = 10;
const ERR_TTL: u32 = 2;

#[derive(Debug, Clone, Default)]
struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0 && self.0.compare_and_swap(count, count - 1, Ordering::Relaxed) != count
        } {}
        count
    }
}

#[derive(Debug)]
struct InnerDoH {
    #[cfg(feature = "tls")]
    tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    tls_cert_password: Option<String>,

    listen_address: SocketAddr,
    local_bind_address: SocketAddr,
    server_address: SocketAddr,
    path: String,
    max_clients: usize,
    timeout: Duration,
    clients_count: ClientsCount,
    min_ttl: u32,
    max_ttl: u32,
    err_ttl: u32,
    keepalive: bool,
    disable_post: bool,
}

#[derive(Clone, Debug)]
struct DoH {
    inner: Arc<InnerDoH>,
}

#[derive(Debug)]
enum Error {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    Hyper(hyper::Error),
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Debug::fmt(self, fmt)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Incomplete => "Incomplete",
            Error::InvalidData => "Invalid data",
            Error::TooLarge => "Too large",
            Error::UpstreamIssue => "Upstream error",
            Error::Hyper(_) => self.description(),
            Error::Io(_) => self.description(),
        }
    }
}

impl From<Error> for StatusCode {
    fn from(e: Error) -> StatusCode {
        match e {
            Error::Incomplete => StatusCode::UNPROCESSABLE_ENTITY,
            Error::InvalidData => StatusCode::BAD_REQUEST,
            Error::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Error::UpstreamIssue => StatusCode::BAD_GATEWAY,
            Error::Hyper(_) => StatusCode::SERVICE_UNAVAILABLE,
            Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl Service for DoH {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<dyn Future<Item = Response<Body>, Error = Self::Error> + Send>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = &self.inner;
        {
            let count = inner.clients_count.current();
            if count >= inner.max_clients {
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
        }
        let fut = self.handle_client(req);
        Box::new(fut)
    }
}

impl DoH {
    fn handle_client(
        &self,
        req: Request<Body>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = Error> + Send> {
        let inner = &self.inner;
        if req.uri().path() != inner.path {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap();
            return Box::new(future::ok(response));
        }
        let headers = req.headers();
        let accept = match headers.get("accept") {
            None => {
                let response = Response::builder()
                    .status(StatusCode::NOT_ACCEPTABLE)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
            Some(accept) => accept.to_str(),
        };
        let accept = match accept {
            Err(_) => {
                let response = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
            Ok(accept) => accept.to_lowercase(),
        };
        let found = accept
            .split(',')
            .take(10)
            .any(|part| part.trim() == "application/dns-message");
        if !found {
            let response = Response::builder()
                .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .body(Body::empty())
                .unwrap();
            return Box::new(future::ok(response));
        }
        match *req.method() {
            Method::POST => {
                if self.inner.disable_post {
                    let response = Response::builder()
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Body::empty())
                        .unwrap();
                    return Box::new(future::ok(response));
                }
                let fut = self.read_body_and_proxy(req.into_body()).or_else(|e| {
                    let response = Response::builder()
                        .status(StatusCode::from(e))
                        .body(Body::empty())
                        .unwrap();
                    future::ok(response)
                });
                Box::new(fut)
            }
            Method::GET => {
                let query = req.uri().query().unwrap_or("");
                let mut question_str = None;
                for parts in query.split('&') {
                    let mut kv = parts.split('=');
                    if let Some(k) = kv.next() {
                        if k == DNS_QUERY_PARAM {
                            question_str = kv.next();
                        }
                    }
                }
                let question = match question_str.and_then(|question_str| {
                    base64::decode_config(question_str, base64::URL_SAFE_NO_PAD).ok()
                }) {
                    Some(question) => question,
                    _ => {
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::empty())
                            .unwrap();
                        return Box::new(future::ok(response));
                    }
                };
                let fut = self.proxy(question).or_else(|e| {
                    let response = Response::builder()
                        .status(StatusCode::from(e))
                        .body(Body::empty())
                        .unwrap();
                    future::ok(response)
                });
                Box::new(fut)
            }
            _ => {
                let response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap();
                Box::new(future::ok(response))
            }
        }
    }

    fn proxy(
        &self,
        mut query: Vec<u8>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = Error> + Send> {
        if query.len() < MIN_DNS_PACKET_LEN {
            return Box::new(future::err(Error::Incomplete));
        }
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as u16);
        let inner = &self.inner;
        let socket = UdpSocket::bind(&inner.local_bind_address).unwrap();
        let expected_server_address = inner.server_address;
        let (min_ttl, max_ttl, err_ttl) = (inner.min_ttl, inner.max_ttl, inner.err_ttl);
        let fut = socket
            .send_dgram(query, &inner.server_address)
            .map_err(Error::Io)
            .and_then(move |(socket, _)| {
                let packet = vec![0; MAX_DNS_RESPONSE_LEN];
                socket.recv_dgram(packet).map_err(Error::Io)
            })
            .and_then(move |(_socket, mut packet, len, response_server_address)| {
                if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
                    return future::err(Error::UpstreamIssue);
                }
                packet.truncate(len);
                let ttl = match dns::min_ttl(&packet, min_ttl, max_ttl, err_ttl) {
                    Err(_) => return future::err(Error::UpstreamIssue),
                    Ok(ttl) => ttl,
                };
                let packet_len = packet.len();
                let response = Response::builder()
                    .header(hyper::header::CONTENT_LENGTH, packet_len)
                    .header(hyper::header::CONTENT_TYPE, "application/dns-message")
                    .header("X-Padding", utils::padding_string(packet_len, BLOCK_SIZE))
                    .header(
                        hyper::header::CACHE_CONTROL,
                        format!("max-age={}", ttl).as_str(),
                    )
                    .body(Body::from(packet))
                    .unwrap();
                future::ok(response)
            });
        Box::new(fut)
    }

    fn read_body_and_proxy(
        &self,
        body: Body,
    ) -> Box<dyn Future<Item = Response<Body>, Error = Error> + Send> {
        let mut sum_size = 0;
        let inner = self.clone();
        let fut = body
            .map_err(Error::Hyper)
            .and_then(move |chunk| {
                sum_size += chunk.len();
                if sum_size > MAX_DNS_QUESTION_LEN {
                    Err(Error::TooLarge)
                } else {
                    Ok(chunk)
                }
            })
            .concat2()
            .map(move |chunk| chunk.to_vec())
            .and_then(move |query| inner.proxy(query));
        Box::new(fut)
    }
}

#[cfg(feature = "tls")]
fn create_tls_acceptor<P>(path: P, password: &str) -> io::Result<TlsAcceptor>
where
    P: AsRef<Path>,
{
    let identity_bin = {
        let mut fp = File::open(path)?;
        let mut identity_bin = vec![];
        fp.read_to_end(&mut identity_bin)?;
        identity_bin
    };
    let identity = Identity::from_pkcs12(&identity_bin, password).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unusable PKCS12-encoded identity. The encoding and/or the password may be wrong",
        )
    })?;
    let native_acceptor = native_tls::TlsAcceptor::new(identity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unable to use the provided PKCS12-encoded identity",
        )
    })?;
    Ok(TlsAcceptor::from(native_acceptor))
}

fn client_serve<I>(
    clients_count: ClientsCount,
    stream: I,
    http: Http,
    service: DoH,
    timeout: Duration,
) where
    I: AsyncRead + AsyncWrite + Send + 'static,
{
    let clients_count_inner = clients_count.clone();
    let conn = http
        .serve_connection(stream, service)
        .timeout(timeout)
        .map_err(|_| {})
        .then(move |fut| {
            clients_count_inner.decrement();
            fut
        });
    clients_count.increment();
    tokio::spawn(conn);
}

#[cfg(feature = "tls")]
fn start_with_tls(
    tls_acceptor: TlsAcceptor,
    listener: TcpListener,
    doh: DoH,
    http: Http,
    timeout: Duration,
) {
    let server = listener.incoming().for_each(move |io| {
        let service = doh.clone();
        let http = http.clone();
        let clients_count = doh.inner.clients_count.clone();
        tls_acceptor
            .accept(io)
            .timeout(timeout)
            .then(move |stream| {
                if let Ok(stream) = stream {
                    client_serve(clients_count, stream, http, service, timeout);
                }
                Ok(())
            })
    });
    tokio::run(server.map_err(|_| {}));
}

fn start_without_tls(listener: TcpListener, doh: DoH, http: Http, timeout: Duration) {
    let server = listener.incoming().for_each(move |stream| {
        let service = doh.clone();
        let http = http.clone();
        let clients_count = doh.inner.clients_count.clone();
        client_serve(clients_count, stream, http, service, timeout);
        Ok(())
    });
    tokio::run(server.map_err(|_| {}));
}

fn main() {
    let mut inner_doh = InnerDoH {
        #[cfg(feature = "tls")]
        tls_cert_path: None,

        #[cfg(feature = "tls")]
        tls_cert_password: None,

        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        local_bind_address: LOCAL_BIND_ADDRESS.parse().unwrap(),
        server_address: SERVER_ADDRESS.parse().unwrap(),
        path: PATH.to_string(),
        max_clients: MAX_CLIENTS,
        timeout: Duration::from_secs(TIMEOUT_SEC),
        clients_count: ClientsCount::default(),
        min_ttl: MIN_TTL,
        max_ttl: MAX_TTL,
        err_ttl: ERR_TTL,
        keepalive: true,
        disable_post: false,
    };
    parse_opts(&mut inner_doh);
    let timeout = inner_doh.timeout;

    #[cfg(feature = "tls")]
    let path = inner_doh.path.clone();
    let doh = DoH {
        inner: Arc::new(inner_doh),
    };
    let listen_address = doh.inner.listen_address;
    let listener = TcpListener::bind(&listen_address).unwrap();

    #[cfg(feature = "tls")]
    let tls_acceptor = match (&doh.inner.tls_cert_path, &doh.inner.tls_cert_password) {
        (Some(tls_cert_path), Some(tls_cert_password)) => {
            println!("Listening on https://{}{}", listen_address, path);
            Some(create_tls_acceptor(tls_cert_path, tls_cert_password).unwrap())
        }
        _ => {
            println!("Listening on http://{}{}", listen_address, path);
            None
        }
    };

    let mut http = Http::new();
    http.keep_alive(doh.inner.keepalive);

    #[cfg(feature = "tls")]
    {
        if let Some(tls_acceptor) = tls_acceptor {
            start_with_tls(tls_acceptor, listener, doh, http, timeout);
            return;
        }
    }
    start_without_tls(listener, doh, http, timeout);
}

fn parse_opts(inner_doh: &mut InnerDoH) {
    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let min_ttl = MIN_TTL.to_string();
    let max_ttl = MAX_TTL.to_string();
    let err_ttl = ERR_TTL.to_string();

    let options = App::new("doh-proxy")
        .about("A DNS-over-HTTP server proxy")
        .arg(
            Arg::with_name("listen_address")
                .short("l")
                .long("listen-address")
                .takes_value(true)
                .default_value(LISTEN_ADDRESS)
                .help("Address to listen to"),
        )
        .arg(
            Arg::with_name("server_address")
                .short("u")
                .long("server-address")
                .takes_value(true)
                .default_value(SERVER_ADDRESS)
                .help("Address to connect to"),
        )
        .arg(
            Arg::with_name("local_bind_address")
                .short("b")
                .long("local-bind-address")
                .takes_value(true)
                .default_value(LOCAL_BIND_ADDRESS)
                .help("Address to connect from"),
        )
        .arg(
            Arg::with_name("path")
                .short("p")
                .long("path")
                .takes_value(true)
                .default_value(PATH)
                .help("URI path"),
        )
        .arg(
            Arg::with_name("max_clients")
                .short("c")
                .long("max-clients")
                .takes_value(true)
                .default_value(&max_clients)
                .help("Maximum number of simultaneous clients"),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .takes_value(true)
                .default_value(&timeout_sec)
                .help("Timeout, in seconds"),
        )
        .arg(
            Arg::with_name("min_ttl")
                .short("T")
                .long("min-ttl")
                .takes_value(true)
                .default_value(&min_ttl)
                .help("Minimum TTL, in seconds"),
        )
        .arg(
            Arg::with_name("max_ttl")
                .short("X")
                .long("max-ttl")
                .takes_value(true)
                .default_value(&max_ttl)
                .help("Maximum TTL, in seconds"),
        )
        .arg(
            Arg::with_name("err_ttl")
                .short("E")
                .long("err-ttl")
                .takes_value(true)
                .default_value(&err_ttl)
                .help("TTL for errors, in seconds"),
        )
        .arg(
            Arg::with_name("disable_keepalive")
                .short("K")
                .long("disable-keepalive")
                .help("Disable keepalive"),
        )
        .arg(
            Arg::with_name("disable_post")
                .short("P")
                .long("disable-post")
                .help("Disable POST queries"),
        );

    #[cfg(feature = "tls")]
    let options = options
        .arg(
            Arg::with_name("tls_cert_path")
                .short("i")
                .long("tls-cert-path")
                .takes_value(true)
                .help("Path to a PKCS12-encoded identity (only required for built-in TLS)"),
        )
        .arg(
            Arg::with_name("tls_cert_password")
                .short("I")
                .long("tls-cert-password")
                .takes_value(true)
                .help("Password for the PKCS12-encoded identity (only required for built-in TLS)"),
        );

    let matches = options.get_matches();
    inner_doh.listen_address = matches.value_of("listen_address").unwrap().parse().unwrap();
    inner_doh.server_address = matches.value_of("server_address").unwrap().parse().unwrap();
    inner_doh.local_bind_address = matches
        .value_of("local_bind_address")
        .unwrap()
        .parse()
        .unwrap();
    inner_doh.path = matches.value_of("path").unwrap().to_string();
    if !inner_doh.path.starts_with('/') {
        inner_doh.path = format!("/{}", inner_doh.path);
    }
    inner_doh.max_clients = matches.value_of("max_clients").unwrap().parse().unwrap();
    inner_doh.timeout = Duration::from_secs(matches.value_of("timeout").unwrap().parse().unwrap());
    inner_doh.min_ttl = matches.value_of("min_ttl").unwrap().parse().unwrap();
    inner_doh.max_ttl = matches.value_of("max_ttl").unwrap().parse().unwrap();
    inner_doh.err_ttl = matches.value_of("err_ttl").unwrap().parse().unwrap();
    inner_doh.keepalive = !matches.is_present("disable_keepalive");
    inner_doh.disable_post = matches.is_present("disable_post");

    #[cfg(feature = "tls")]
    {
        inner_doh.tls_cert_path = matches.value_of("tls_cert_path").map(PathBuf::from);
        inner_doh.tls_cert_password = matches
            .value_of("tls_cert_password")
            .map(ToString::to_string);
    }
}
