#![feature(proc_macro, conservative_impl_trait, generators, conservative_impl_trait,
           universal_impl_trait, nll)]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate futures_await as futures;
extern crate hyper;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

use tokio_core::reactor::Handle;
use std::time::Duration;
use hyper::{Body, Method, StatusCode};
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, Request, Response, Service};
use futures::prelude::*;
use futures::future;
use tokio_core::reactor::Core;
use tokio_core::net::UdpSocket;
use std::cell::RefCell;
use std::rc::Rc;

const TIMEOUT_SEC: u64 = 10;
const LOCAL_ADDRESS: &str = "127.0.0.1:3000";
const LOCAL_BIND_ADDRESS: &str = "0.0.0.0:0";
const SERVER_ADDRESS: &str = "9.9.9.9:53";
const MIN_DNS_PACKET_LEN: usize = 17;
const MAX_DNS_QUESTION_LEN: usize = 512;
const MAX_DNS_RESPONSE_LEN: usize = 4096;
const MAX_CLIENTS: u32 = 512;

#[derive(Clone, Debug)]
struct DoH {
    handle: Handle,
}

impl Service for DoH {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let mut response = Response::new();
        match (req.method(), req.path()) {
            (&Method::Post, "/dns-query") => {
                let fut = self.body_read(req.body(), self.handle.clone()).map(|body| {
                    let body_len = body.len();
                    response.set_body(body);
                    response
                        .with_header(ContentLength(body_len as u64))
                        .with_header(ContentType(
                            "application/dns-udpwireformat".parse().unwrap(),
                        ))
                });
                return Box::new(fut.map_err(|_| hyper::Error::Incomplete));
            }
            (&Method::Post, _) => {
                response.set_status(StatusCode::NotFound);
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
    fn body_read(&self, body: Body, handle: Handle) -> Result<Vec<u8>, ()> {
        let query = await!(
            body.concat2()
                .map_err(|_err| ())
                .map(|chunk| chunk.to_vec())
        )?;
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(());
        }
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
        Ok(packet)
    }
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let addr = LOCAL_ADDRESS.parse().unwrap();
    let handle_inner = handle.clone();
    let server = Http::new()
        .keep_alive(false)
        .max_buf_size(MAX_DNS_QUESTION_LEN)
        .serve_addr_handle(&addr, &handle, move || {
            Ok(DoH {
                handle: handle_inner.clone(),
            })
        })
        .unwrap();
    println!("Listening on http://{}", server.incoming_ref().local_addr());
    let handle_inner = handle.clone();
    let timers = tokio_timer::wheel().build();
    let client_count = Rc::new(RefCell::new(0u32));
    let fut = server.for_each(move |client_fut| {
        {
            let count = client_count.borrow_mut();
            if *count > MAX_CLIENTS {
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
        let timed = timers_inner.timeout(fut, Duration::from_secs(TIMEOUT_SEC));
        handle_inner.spawn(timed);
        Ok(())
    });
    handle.spawn(fut.map_err(|_| ()));
    core.run(futures::future::empty::<(), ()>()).unwrap();
}
