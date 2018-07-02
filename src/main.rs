#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate base64;
extern crate clap;
extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_timer;

mod dns;

use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, EXPIRES};
use hyper::server::conn::Http;
use hyper::service::{NewService, Service};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};
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
    clients_count: Rc<RefCell<u32>>,
}

impl Service for DoH {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = io::Error;
    type Future = Box<Future<Item = Response<Self::ResBody>, Error = io::Error>>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        {
            let count = self.clients_count.borrow_mut();
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
                (*clients_count_inner).borrow_mut().saturating_sub(1);
                fut
            })
            .map_err(|err| {
                eprintln!("server error: {:?}", err);
                err
            });
        let timed = self
            .timer_handle
            .deadline(fut.map_err(|_| {}), Instant::now() + self.timeout)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timeout"));
        Box::new(timed)
    }
}

impl DoH {
    fn handle_client(
        &self,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error>> {
        if req.uri().path() != self.path {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap();
            return Box::new(future::ok(response));
        }
        match *req.method() {
            Method::POST => {
                let fut = self.read_body_and_proxy(req.body());
                return Box::new(
                    fut.map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
                );
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
                        let mut response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::empty())
                            .unwrap();
                        return Box::new(future::ok(response));
                    }
                };
                let fut = self.proxy(question);
                return Box::new(
                    fut.map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
                );
            }
            _ => {
                let mut response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap();
                return Box::new(future::ok(response));
            }
        };
    }

    fn proxy(&self, query: Vec<u8>) -> Box<Future<Item = Response<Body>, Error = ()>> {
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
                let mut response = Response::builder()
                    .header(CONTENT_LENGTH, format!("{}", packet_len).as_bytes())
                    .header(CONTENT_TYPE, "application/dns-message")
                    .header(
                        EXPIRES,
                        format!(
                            "{}",
                            (SystemTime::now() + Duration::from_secs(ttl as u64))
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or(Duration::new(0, 0))
                                .as_secs()
                        ).as_bytes(),
                    )
                    .body(Body::from(packet))
                    .unwrap();
                future::ok(response)
            });
        Box::new(fut)
    }

    fn read_body_and_proxy(&self, body: &Body) -> Box<Future<Item = Response<Body>, Error = ()>> {
        let mut sum_size = 0;
        let inner = self.clone();
        let fut = body
            .map_err(move |_err| ())
            .and_then(move |chunk| {
                sum_size += chunk.len();
                if sum_size > MAX_DNS_QUESTION_LEN {
                    Err(())
                } else {
                    Ok(chunk)
                }
            })
            .concat2()
            .map_err(move |_err| ())
            .map(move |chunk| chunk.to_vec())
            .and_then(move |query| {
                if query.len() < MIN_DNS_PACKET_LEN {
                    return Box::new(future::err(())) as Box<Future<Item = _, Error = _>>;
                }
                Box::new(inner.proxy(query))
            });
        Box::new(fut)
    }
}

struct DohNewService {
    doh: DoH,
}

impl NewService for DohNewService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = io::Error;
    type Service = DoH;
    type Future = Box<Future<Item = Self::Service, Error = Self::InitError>>;
    type InitError = io::Error;

    fn new_service(&self) -> Self::Future {
        Box::new(future::ok(self.doh.clone()))
    }
}

impl DohNewService {
    fn new(doh: DoH) -> Self {
        DohNewService { doh }
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
        clients_count: Rc::new(RefCell::new(0u32)),
        timer_handle: Timer::default().handle(),
    };
    parse_opts(&mut doh);
    let listen_address = doh.listen_address;
    println!("Listening on http://{}", listen_address);
    let new_service = DohNewService::new(doh);
    let server = Http::new()
        .keep_alive(false)
        .max_buf_size(0xffff)
        .pipeline_flush(true)
        .serve_addr(&listen_address, || new_service)
        .unwrap();
    let fut = server.for_each(move |client_fut| {
        current_thread::spawn(client_fut.map(|_| {}).map_err(|_| {}));
        Ok(())
    });
    current_thread::block_on_all(fut).unwrap();
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
