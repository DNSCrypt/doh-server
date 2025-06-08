#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    let runtime = match runtime_builder.build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Error: Failed to create Tokio runtime: {}", e);
            std::process::exit(1);
        }
    };

    let rotator = match ODoHRotator::new(runtime.handle().clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to create ODoH rotator: {}", e);
            std::process::exit(1);
        }
    };

    let listen_address = match LISTEN_ADDRESS.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "Error: Invalid default listen address '{}': {}",
                LISTEN_ADDRESS, e
            );
            std::process::exit(1);
        }
    };

    let server_address = match SERVER_ADDRESS.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "Error: Invalid default server address '{}': {}",
                SERVER_ADDRESS, e
            );
            std::process::exit(1);
        }
    };

    let mut globals = Globals {
        #[cfg(feature = "tls")]
        tls_cert_path: None,
        #[cfg(feature = "tls")]
        tls_cert_key_path: None,

        listen_address,
        local_bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_address,
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

    if let Err(e) = runtime.block_on(doh.entrypoint()) {
        eprintln!("Error: Failed to start DoH server: {}", e);
        std::process::exit(1);
    }
}
