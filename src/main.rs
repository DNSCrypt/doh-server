#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate clap;

mod config;
mod constants;
mod utils;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use libdoh::odoh::ODoHRotator;
use libdoh::reexports::tokio;
use libdoh::*;

use crate::config::*;
use crate::constants::*;

fn main() {
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    runtime_builder.thread_name("doh-proxy");
    let runtime = runtime_builder.build().unwrap();

    let rotator = match ODoHRotator::new(runtime.handle().clone()) {
        Ok(r) => r,
        Err(_) => panic!("Failed to create ODoHRotator"),
    };

    let mut globals = Globals {
        #[cfg(feature = "tls")]
        tls_cert_path: None,
        #[cfg(feature = "tls")]
        tls_cert_key_path: None,

        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        local_bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_address: SERVER_ADDRESS.parse().unwrap(),
        path: PATH.to_string(),
        max_clients: MAX_CLIENTS,
        timeout: Duration::from_secs(TIMEOUT_SEC),
        clients_count: Default::default(),
        max_concurrent_streams: MAX_CONCURRENT_STREAMS,
        min_ttl: MIN_TTL,
        max_ttl: MAX_TTL,
        err_ttl: ERR_TTL,
        keepalive: true,
        disable_post: false,
        allow_odoh_post: false,
        odoh_configs_path: ODOH_CONFIGS_PATH.to_string(),
        odoh_rotator: Arc::new(rotator),

        runtime_handle: runtime.handle().clone(),
    };
    parse_opts(&mut globals);
    let doh = DoH {
        globals: Arc::new(globals),
    };
    runtime.block_on(doh.entrypoint()).unwrap();
}
