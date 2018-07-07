#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate base64;
extern crate clap;
extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate tokio_timer;

mod dns;

use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use hyper::service::Service;
use hyper::server::conn::Http;
use hyper::{Request, Response, Body, Method, StatusCode};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::executor::current_thread;
use tokio::net::{TcpListener, UdpSocket};
use tokio_timer::{timer, Timer};

const DNS_QUERY_PARAM: &str = "dns";
const LISTEN_ADDRESS: &str = "127.0.0.1:3000";
const LOCAL_BIND_ADDRESS: &str = "0.0.0.0:0";
const MAX_CLIENTS: u32 = 512;
const MAX_DNS_QUESTION_LEN: usize = 512;
const MAX_DNS_RESPONSE_LEN: usize = 4096;
const MIN_DNS_PACKET_LEN: usize = 17;
const PATH: &str = "/dns-query";
const SERVER_ADDRESS: &str = "9.9.9.9:53";
const TIMEOUT_SEC: u64 = 10;
const MAX_TTL: u32 = 86400 * 7;
const MIN_TTL: u32 = 1;
const ERR_TTL: u32 = 1;

#[derive(Clone, Debug)]
struct DoH {
    listen_address: SocketAddr,
    local_bind_address: SocketAddr,
    server_address: SocketAddr,
    path: String,
    max_clients: u32,
    timeout: Duration,
    timer_handle: timer::Handle,
    clients_count: Arc<Mutex<u32>>,
}

#[derive(Debug)]
enum Error {
    Timeout,
    Incomplete,
    TooLarge,
    Hyper(hyper::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        // Should match, i'm lazy...
        std::fmt::Debug::fmt(self, fmt)
    }
}
impl std::error::Error for Error {}

impl Service for DoH {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<Future<Item = Response<Body>, Error = Self::Error> + Send>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        {
            let count = self.clients_count.lock().unwrap();
            if *count > self.max_clients {
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
            (*count).saturating_add(1);
        }
        let clients_count_inner = self.clients_count.clone();
        let fut = self
            .handle_client(req)
            .then(move |fut| {
                (*clients_count_inner).lock().unwrap().saturating_sub(1);
                fut
            })
            .map_err(|err| {
                eprintln!("server error: {}", err);
                err
            });
        let timed = self
            .timer_handle
            .deadline(fut.map_err(|_| {}), Instant::now() + self.timeout)
            .map_err(|_| Error::Timeout);
        Box::new(timed)
    }
}

impl DoH {
    fn handle_client(&self, req: Request<Body>) -> Box<Future<Item = Response<Body>, Error = Error> + Send> {
        if req.uri().path() != self.path {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap();
            return Box::new(future::ok(response));
        }
        match *req.method() {
            Method::POST => {
                let fut = self.read_body_and_proxy(req.into_body());
                return Box::new(fut.map_err(|_| Error::Incomplete));
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
                let fut = self.proxy(question);
                return Box::new(fut.map_err(|_| Error::Incomplete));
            }
            _ => {
                let response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
        };
    }

    fn proxy(&self, query: Vec<u8>) -> Box<Future<Item = Response<Body>, Error = ()> + Send> {
        let socket = UdpSocket::bind(&self.local_bind_address).unwrap();
        let expected_server_address = self.server_address;
        let fut = socket
            .send_dgram(query, &self.server_address)
            .map_err(|_| ())
            .and_then(move |(socket, _)| {
                let packet = vec![0; MAX_DNS_RESPONSE_LEN];
                socket.recv_dgram(packet).map_err(|_| {})
            })
            .and_then(move |(_socket, mut packet, len, response_server_address)| {
                if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
                    return future::err(());
                }
                packet.truncate(len);
                let ttl = match dns::min_ttl(&packet, MIN_TTL, MAX_TTL, ERR_TTL) {
                    Err(_) => return future::err(()),
                    Ok(min_ttl) => min_ttl,
                };
                let packet_len = packet.len();
                let response = Response::builder()
                    .header(hyper::header::CONTENT_LENGTH, packet_len)
                    .header(hyper::header::CONTENT_TYPE, "application/dns-message")
                    .header(hyper::header::CACHE_CONTROL, format!("max-age={}", ttl).as_str())
                    .body(Body::from(packet))
                    .unwrap();
                future::ok(response)
            });
        Box::new(fut)
    }

    fn read_body_and_proxy(&self, body: Body) -> Box<Future<Item = Response<Body>, Error = ()> + Send> {
        let mut sum_size = 0;
        let inner = self.clone();
        let fut =
            body.map_err(|e| Error::Hyper(e)).and_then(move |chunk| {
                sum_size += chunk.len();
                if sum_size > MAX_DNS_QUESTION_LEN {
                    Err(Error::TooLarge)
                } else {
                    Ok(chunk)
                }
            }).concat2()
                .map_err(move |_err| ())
                .map(move |chunk| chunk.to_vec())
                .and_then(move |query| {
                    if query.len() < MIN_DNS_PACKET_LEN {
                        return Box::new(future::err(())) as Box<Future<Item = _, Error = _> + Send>;
                    }
                    inner.proxy(query)
                });
        Box::new(fut)
    }
}

fn main() {
    let mut doh = DoH {
        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        local_bind_address: LOCAL_BIND_ADDRESS.parse().unwrap(),
        server_address: SERVER_ADDRESS.parse().unwrap(),
        path: PATH.to_string(),
        max_clients: MAX_CLIENTS,
        timeout: Duration::from_secs(TIMEOUT_SEC),
        clients_count: Arc::new(Mutex::new(0u32)),
        timer_handle: Timer::default().handle(),
    };
    parse_opts(&mut doh);
    let listen_address = doh.listen_address;
    let listener = TcpListener::bind(&listen_address).unwrap();
    println!("Listening on http://{}", listen_address);
    let mut http = Http::new();
    http.keep_alive(false);
    let doh = Arc::new(Mutex::new(doh));
    let server = listener.incoming().for_each(move |io| {
        let service = doh.lock().unwrap().clone();
        let conn = http.serve_connection(io, service).map_err(|_| {});
        current_thread::spawn(conn);
        Ok(())
    });
    current_thread::block_on_all(server).unwrap();
}

fn parse_opts(doh: &mut DoH) {
    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let matches = App::new("doh-proxy")
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
        .get_matches();
    if let Some(listen_address) = matches.value_of("listen_address") {
        doh.listen_address = listen_address.parse().unwrap();
    }
    if let Some(server_address) = matches.value_of("server_address") {
        doh.server_address = server_address.parse().unwrap();
    }
    if let Some(local_bind_address) = matches.value_of("local_bind_address") {
        doh.local_bind_address = local_bind_address.parse().unwrap();
    }
    if let Some(max_clients) = matches.value_of("max_clients") {
        doh.max_clients = max_clients.parse().unwrap();
    }
    if let Some(timeout) = matches.value_of("timeout") {
        doh.timeout = Duration::from_secs(timeout.parse().unwrap());
    }
}
