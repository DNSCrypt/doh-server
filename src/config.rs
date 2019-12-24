use libdoh::*;

use crate::constants::*;

use clap::Arg;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::Duration;

#[cfg(feature = "tls")]
use std::path::PathBuf;

pub fn parse_opts(globals: &mut Globals) {
    use crate::utils::{verify_remote_server, verify_sock_addr};

    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let min_ttl = MIN_TTL.to_string();
    let max_ttl = MAX_TTL.to_string();
    let err_ttl = ERR_TTL.to_string();

    let _ = include_str!("../Cargo.toml");
    let options = app_from_crate!()
        .arg(
            Arg::with_name("listen_address")
                .short("l")
                .long("listen-address")
                .takes_value(true)
                .default_value(LISTEN_ADDRESS)
                .validator(verify_sock_addr)
                .help("Address to listen to"),
        )
        .arg(
            Arg::with_name("server_address")
                .short("u")
                .long("server-address")
                .takes_value(true)
                .default_value(SERVER_ADDRESS)
                .validator(verify_remote_server)
                .help("Address to connect to"),
        )
        .arg(
            Arg::with_name("local_bind_address")
                .short("b")
                .long("local-bind-address")
                .takes_value(true)
                .validator(verify_sock_addr)
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
    globals.listen_address = matches.value_of("listen_address").unwrap().parse().unwrap();

    globals.server_address = matches
        .value_of("server_address")
        .unwrap()
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    globals.local_bind_address = match matches.value_of("local_bind_address") {
        Some(address) => address.parse().unwrap(),
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
    globals.path = matches.value_of("path").unwrap().to_string();
    if !globals.path.starts_with('/') {
        globals.path = format!("/{}", globals.path);
    }
    globals.max_clients = matches.value_of("max_clients").unwrap().parse().unwrap();
    globals.timeout = Duration::from_secs(matches.value_of("timeout").unwrap().parse().unwrap());
    globals.min_ttl = matches.value_of("min_ttl").unwrap().parse().unwrap();
    globals.max_ttl = matches.value_of("max_ttl").unwrap().parse().unwrap();
    globals.err_ttl = matches.value_of("err_ttl").unwrap().parse().unwrap();
    globals.keepalive = !matches.is_present("disable_keepalive");
    globals.disable_post = matches.is_present("disable_post");

    #[cfg(feature = "tls")]
    {
        globals.tls_cert_path = matches.value_of("tls_cert_path").map(PathBuf::from);
        globals.tls_cert_password = matches
            .value_of("tls_cert_password")
            .map(ToString::to_string);
    }
}
