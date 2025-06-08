use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::time::Duration;

use clap::{Arg, ArgAction::SetTrue};
use libdoh::*;

use crate::constants::*;

fn exit_with_error(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    std::process::exit(1);
}

pub fn parse_opts(globals: &mut Globals) {
    use crate::utils::{verify_remote_server, verify_sock_addr};

    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let max_concurrent_streams = MAX_CONCURRENT_STREAMS.to_string();
    let min_ttl = MIN_TTL.to_string();
    let max_ttl = MAX_TTL.to_string();
    let err_ttl = ERR_TTL.to_string();

    let _ = include_str!("../Cargo.toml");
    let options = command!()
        .arg(
            Arg::new("hostname")
                .short('H')
                .long("hostname")
                .num_args(1)
                .help("Host name (not IP address) DoH clients will use to connect"),
        )
        .arg(
            Arg::new("public_address")
                .short('g')
                .long("public-address")
                .num_args(1..)
                .action(clap::ArgAction::Append)
                .help("External IP address(es) DoH clients will connect to (can be specified multiple times)"),
        )
        .arg(
            Arg::new("public_port")
                .short('j')
                .long("public-port")
                .num_args(1)
                .help("External port DoH clients will connect to, if not 443"),
        )
        .arg(
            Arg::new("listen_address")
                .short('l')
                .long("listen-address")
                .num_args(1)
                .default_value(LISTEN_ADDRESS)
                .value_parser(verify_sock_addr)
                .help("Address to listen to"),
        )
        .arg(
            Arg::new("server_address")
                .short('u')
                .long("server-address")
                .num_args(1)
                .default_value(SERVER_ADDRESS)
                .value_parser(verify_remote_server)
                .help("Address to connect to"),
        )
        .arg(
            Arg::new("local_bind_address")
                .short('b')
                .long("local-bind-address")
                .num_args(1)
                .value_parser(verify_sock_addr)
                .help("Address to connect from"),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .num_args(1)
                .default_value(PATH)
                .help("URI path"),
        )
        .arg(
            Arg::new("max_clients")
                .short('c')
                .long("max-clients")
                .num_args(1)
                .default_value(max_clients)
                .help("Maximum number of simultaneous clients"),
        )
        .arg(
            Arg::new("max_concurrent")
                .short('C')
                .long("max-concurrent")
                .num_args(1)
                .default_value(max_concurrent_streams)
                .help("Maximum number of concurrent requests per client"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .num_args(1)
                .default_value(timeout_sec)
                .help("Timeout, in seconds"),
        )
        .arg(
            Arg::new("min_ttl")
                .short('T')
                .long("min-ttl")
                .num_args(1)
                .default_value(min_ttl)
                .help("Minimum TTL, in seconds"),
        )
        .arg(
            Arg::new("max_ttl")
                .short('X')
                .long("max-ttl")
                .num_args(1)
                .default_value(max_ttl)
                .help("Maximum TTL, in seconds"),
        )
        .arg(
            Arg::new("err_ttl")
                .short('E')
                .long("err-ttl")
                .num_args(1)
                .default_value(err_ttl)
                .help("TTL for errors, in seconds"),
        )
        .arg(
            Arg::new("disable_keepalive")
                .short('K')
                .action(SetTrue)
                .long("disable-keepalive")
                .help("Disable keepalive"),
        )
        .arg(
            Arg::new("disable_post")
                .short('P')
                .action(SetTrue)
                .long("disable-post")
                .help("Disable POST queries"),
        )
        .arg(
            Arg::new("allow_odoh_post")
                .short('O')
                .action(SetTrue)
                .long("allow-odoh-post")
                .help("Allow POST queries over ODoH even if they have been disabed for DoH"),
        );

    #[cfg(feature = "tls")]
    let options = options
        .arg(
            Arg::new("tls_cert_path")
                .short('i')
                .long("tls-cert-path")
                .num_args(1)
                .help(
                    "Path to the PEM/PKCS#8-encoded certificates (only required for built-in TLS)",
                ),
        )
        .arg(
            Arg::new("tls_cert_key_path")
                .short('I')
                .long("tls-cert-key-path")
                .num_args(1)
                .help("Path to the PEM-encoded secret keys (only required for built-in TLS)"),
        );

    let matches = options.get_matches();

    // Parse listen address
    globals.listen_address = matches
        .get_one::<String>("listen_address")
        .expect("listen_address has a default value")
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid listen address: {}", e)));

    // Parse server address
    let server_address_str = matches
        .get_one::<String>("server_address")
        .expect("server_address has a default value");
    globals.server_address = server_address_str
        .to_socket_addrs()
        .unwrap_or_else(|e| {
            exit_with_error(&format!(
                "Invalid server address '{}': {}",
                server_address_str, e
            ))
        })
        .next()
        .unwrap_or_else(|| {
            exit_with_error(&format!(
                "Cannot resolve server address '{}'",
                server_address_str
            ))
        });

    // Parse local bind address
    globals.local_bind_address = match matches.get_one::<String>("local_bind_address") {
        Some(address) => address.parse().unwrap_or_else(|e| {
            exit_with_error(&format!("Invalid local bind address '{}': {}", address, e))
        }),
        None => match globals.server_address {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(s) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                s.flowinfo(),
                s.scope_id(),
            )),
        },
    };

    // Parse path
    globals.path = matches
        .get_one::<String>("path")
        .expect("path has a default value")
        .to_string();
    if !globals.path.starts_with('/') {
        globals.path = format!("/{}", globals.path);
    }

    // Parse max_clients
    let max_clients_str = matches
        .get_one::<String>("max_clients")
        .expect("max_clients has a default value");
    globals.max_clients = max_clients_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!("Invalid max clients '{}': {}", max_clients_str, e))
    });

    // Parse timeout
    let timeout_str = matches
        .get_one::<String>("timeout")
        .expect("timeout has a default value");
    let timeout_secs: u64 = timeout_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid timeout '{}': {}", timeout_str, e)));
    globals.timeout = Duration::from_secs(timeout_secs);

    // Parse max_concurrent_streams
    let max_concurrent_str = matches
        .get_one::<String>("max_concurrent")
        .expect("max_concurrent has a default value");
    globals.max_concurrent_streams = max_concurrent_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Invalid max concurrent streams '{}': {}",
            max_concurrent_str, e
        ))
    });

    // Parse min_ttl
    let min_ttl_str = matches
        .get_one::<String>("min_ttl")
        .expect("min_ttl has a default value");
    globals.min_ttl = min_ttl_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid min TTL '{}': {}", min_ttl_str, e)));

    // Parse max_ttl
    let max_ttl_str = matches
        .get_one::<String>("max_ttl")
        .expect("max_ttl has a default value");
    globals.max_ttl = max_ttl_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid max TTL '{}': {}", max_ttl_str, e)));

    // Parse err_ttl
    let err_ttl_str = matches
        .get_one::<String>("err_ttl")
        .expect("err_ttl has a default value");
    globals.err_ttl = err_ttl_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!("Invalid error TTL '{}': {}", err_ttl_str, e))
    });
    globals.keepalive = !matches.get_flag("disable_keepalive");
    globals.disable_post = matches.get_flag("disable_post");
    globals.allow_odoh_post = matches.get_flag("allow_odoh_post");

    #[cfg(feature = "tls")]
    {
        globals.tls_cert_path = matches
            .get_one::<String>("tls_cert_path")
            .map(PathBuf::from);
        globals.tls_cert_key_path = matches
            .get_one::<String>("tls_cert_key_path")
            .map(PathBuf::from)
            .or_else(|| globals.tls_cert_path.clone());
    }

    match matches.get_one::<String>("hostname") {
        Some(hostname) => {
            let public_addresses: Vec<&String> = matches
                .get_many::<String>("public_address")
                .map(|values| values.collect())
                .unwrap_or_default();

            let public_port = matches.get_one::<String>("public_port").map(|port| {
                port.parse::<u16>().unwrap_or_else(|e| {
                    exit_with_error(&format!("Invalid public port '{}': {}", port, e))
                })
            });

            if public_addresses.is_empty() {
                // No public addresses specified, generate stamps without IP
                let mut doh_builder =
                    dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string());
                if let Some(port) = public_port {
                    doh_builder = doh_builder.with_port(port);
                }
                match doh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate DoH stamp: {}", e),
                }

                let mut odoh_builder = dnsstamps::ODoHTargetBuilder::new(
                    hostname.to_string(),
                    globals.path.to_string(),
                );
                if let Some(port) = public_port {
                    odoh_builder = odoh_builder.with_port(port);
                }
                match odoh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over Oblivious DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate ODoH stamp: {}", e),
                }
            } else {
                // Generate stamps for each public address
                for public_address in &public_addresses {
                    let mut doh_builder =
                        dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string())
                            .with_address(public_address.to_string());
                    if let Some(port) = public_port {
                        doh_builder = doh_builder.with_port(port);
                    }
                    match doh_builder.serialize() {
                        Ok(stamp) => println!(
                            "Test DNS stamp to reach [{}] via [{}] over DoH: [{}]",
                            hostname, public_address, stamp
                        ),
                        Err(e) => eprintln!(
                            "Warning: Failed to generate DoH stamp for {}: {}",
                            public_address, e
                        ),
                    }
                }
                println!(); // Empty line for readability

                // ODoH stamps don't support IP addresses, so we generate just one
                let mut odoh_builder = dnsstamps::ODoHTargetBuilder::new(
                    hostname.to_string(),
                    globals.path.to_string(),
                );
                if let Some(port) = public_port {
                    odoh_builder = odoh_builder.with_port(port);
                }
                match odoh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over Oblivious DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate ODoH stamp: {}", e),
                }
            }

            println!("Check out https://dnscrypt.info/stamps/ to compute the actual stamps.\n")
        }
        _ => {
            println!(
            "Please provide a fully qualified hostname (-H <hostname> command-line option) to get \
             test DNS stamps for your server.\n"
        );
        }
    }
}
