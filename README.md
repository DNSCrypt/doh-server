# doh-proxy

A DNS-over-HTTP server proxy in Rust. Add a webserver and you get DNS-over-HTTPS, which is actually DNS-over-HTTP/2.

## Installation

```sh
cargo install doh-proxy
```

## Usage

```text
A DNS-over-HTTP server proxy

USAGE:
    doh-proxy [FLAGS] [OPTIONS]

FLAGS:
    -K, --disable-keepalive    Disable keepalive
    -h, --help                 Prints help information
    -V, --version              Prints version information

OPTIONS:
    -E, --err-ttl <err_ttl>                          TTL for errors, in seconds [default: 2]
    -l, --listen-address <listen_address>            Address to listen to [default: 127.0.0.1:3000]
    -b, --local-bind-address <local_bind_address>    Address to connect from [default: 0.0.0.0:0]
    -c, --max-clients <max_clients>                  Maximum number of simultaneous clients [default: 512]
    -X, --max-ttl <max_ttl>                          Maximum TTL, in seconds [default: 604800]
    -T, --min-ttl <min_ttl>                          Minimum TTL, in seconds [default: 10]
    -p, --path <path>                                URI path [default: /dns-query]
    -u, --server-address <server_address>            Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                          Timeout, in seconds [default: 10]
    -I, --tls-cert-password <tls_cert_password>
            Password for the PKCS12-encoded identity (only required for built-in TLS)

    -i, --tls-cert-path <tls_cert_path>              Path to a PKCS12-encoded identity (only required for built-in TLS)
```

## Clients

`doh-proxy` can be used with [dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy)
as a client.

`doh-proxy` is currently being used by the `doh.crypto.sx` public DNS resolver.

Other public DoH servers can be found here: [public encrypted DNS servers](https://dnscrypt.info/public-servers).
