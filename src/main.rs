#![feature(proc_macro, conservative_impl_trait, generators, conservative_impl_trait,
           universal_impl_trait, nll)]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate base64;
extern crate clap;
extern crate futures_await as futures;
extern crate hyper;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

mod dns;

use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use hyper::{Body, Method, StatusCode};
use hyper::header::{CacheControl, CacheDirective, ContentLength, ContentType};
use hyper::server::{Http, Request, Response, Service};
use std::cell::RefCell;
use std::rc::Rc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;

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
    handle: Handle,
    listen_address: SocketAddr,
    local_bind_address: SocketAddr,
    server_address: SocketAddr,
    path: String,
    max_clients: u32,
    timeout: Duration,
}

impl Service for DoH {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let mut response = Response::new();
        match (req.method(), req.path()) {
            (&Method::Post, path) => {
                if path != self.path {
                    response.set_status(StatusCode::NotFound);
                    return Box::new(future::ok(response));
                }
                let fut = self.read_body_and_proxy(req.body(), self.handle.clone());
                return Box::new(fut.map_err(|_| hyper::Error::Incomplete));
            }
            (&Method::Get, "/dns-query") => {
                let query = req.query().unwrap_or("");
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
                        response.set_status(StatusCode::BadRequest);
                        return Box::new(future::ok(response));
                    }
                };
                let fut = Self::proxy(question, self.handle.clone());
                return Box::new(fut.map_err(|_| hyper::Error::Incomplete));
            }
            _ => {
                response.set_status(StatusCode::NotAcceptable);
            }
        };
        Box::new(future::ok(response))
    }
}

impl DoH {
    #[async]
    fn proxy(query: Vec<u8>, handle: Handle) -> Result<Response, ()> {
        let local_addr = LOCAL_BIND_ADDRESS.parse().unwrap();
        let socket = UdpSocket::bind(&local_addr, &handle).unwrap();
        let remote_addr = SERVER_ADDRESS.parse().unwrap();
        let (socket, _) = await!(socket.send_dgram(query, remote_addr)).map_err(|_| ())?;
        let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];
        let (_socket, mut packet, len, server_addr) =
            await!(socket.recv_dgram(packet)).map_err(|_| ())?;
        if len < MIN_DNS_PACKET_LEN || server_addr != remote_addr {
            return Err(());
        }
        packet.truncate(len);
        let min_ttl = dns::min_ttl(&packet, MIN_TTL, MAX_TTL, ERR_TTL).map_err(|_| {})?;
        Ok((packet, min_ttl)).map(|(body, ttl)| {
            let body_len = body.len();
            let mut response = Response::new();
            response.set_body(body);
            response
                .with_header(ContentLength(body_len as u64))
                .with_header(ContentType(
                    "application/dns-udpwireformat".parse().unwrap(),
                ))
                .with_header(CacheControl(vec![CacheDirective::MaxAge(ttl)]))
        })
    }

    #[async]
    fn read_body_and_proxy(&self, body: Body, handle: Handle) -> Result<Response, ()> {
        let query = await!(
            body.concat2()
                .map_err(|_err| ())
                .map(|chunk| chunk.to_vec())
        )?;
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(());
        }
        await!(Self::proxy(query, handle))
    }
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let handle_inner = handle.clone();
    let mut doh = DoH {
        handle: handle_inner.clone(),
        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        local_bind_address: LOCAL_BIND_ADDRESS.parse().unwrap(),
        server_address: SERVER_ADDRESS.parse().unwrap(),
        path: PATH.to_string(),
        max_clients: MAX_CLIENTS,
        timeout: Duration::from_secs(TIMEOUT_SEC),
    };
    parse_opts(&mut doh);
    let listen_address = doh.listen_address;
    let doh_inner = doh.clone();
    let server = Http::new()
        .keep_alive(false)
        .max_buf_size(MAX_DNS_QUESTION_LEN)
        .serve_addr_handle(&listen_address, &handle, move || Ok(doh_inner.clone()))
        .unwrap();
    println!("Listening on http://{}", server.incoming_ref().local_addr());
    let handle_inner = handle.clone();
    let timers = tokio_timer::wheel().build();
    let client_count = Rc::new(RefCell::new(0u32));
    let fut = server.for_each(move |client_fut| {
        {
            let count = client_count.borrow_mut();
            if *count > doh.max_clients {
                return Ok(());
            }
            (*count).saturating_add(1);
        }
        let client_count_inner = client_count.clone();
        let timers_inner = timers.clone();
        let fut = client_fut
            .map(move |_| {
                (*client_count_inner.borrow_mut()).saturating_sub(1);
            })
            .map_err(|err| eprintln!("server error: {:?}", err));
        let timed = timers_inner.timeout(fut, doh.timeout);
        handle_inner.spawn(timed);
        Ok(())
    });
    handle.spawn(fut.map_err(|_| ()));
    core.run(futures::future::empty::<(), ()>()).unwrap();
}

fn parse_opts(doh: &mut DoH) {
    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let matches = App::new("doh-proxy")
        .about("A DNS-over-HTTP server proxy")
        .arg(
            Arg::with_name("listen_address")
                .short("l")
                .long("listen_address")
                .takes_value(true)
                .default_value(LISTEN_ADDRESS)
                .help("Address to listen to"),
        )
        .arg(
            Arg::with_name("server_address")
                .short("u")
                .long("server_address")
                .takes_value(true)
                .default_value(SERVER_ADDRESS)
                .help("Address to connect to"),
        )
        .arg(
            Arg::with_name("local_bind_address")
                .short("b")
                .long("local_bind_address")
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
                .long("max_clients")
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
