#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[macro_use]
extern crate clap;

mod config;
mod constants;
mod utils;

use std::sync::Arc;

use libdoh::odoh::ODoHRotator;
use libdoh::reexports::tokio;
use libdoh::*;

use crate::config::*;

/// Prints libdoh's log messages to stderr.
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("libdoh")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}", record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

fn main() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);

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

    let mut globals = Globals {
        odoh_rotator: Some(Arc::new(rotator)),
        ..Globals::default()
    };
    let forwarder = parse_opts(&mut globals);
    let doh = DoH::new(globals, forwarder);

    if let Err(e) = runtime.block_on(doh.entrypoint()) {
        eprintln!("Error: Failed to start DoH server: {}", e);
        std::process::exit(1);
    }
}
