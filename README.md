# doh-proxy

A DNS-over-HTTP server proxy in Rust. Add a webserver and you get DNS-over-HTTPS, which is actually DNS-over-HTTP/2.

## Installation

Requires rust-nightly.

```sh
cargo install doh-proxy
```

## Usage

```text
doh-proxy
A DNS-over-HTTP server proxy

USAGE:
    doh-proxy [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --listen_address <listen_address>            Address to listen to [default: 127.0.0.1:3000]
    -b, --local_bind_address <local_bind_address>    Address to connect from [default: 0.0.0.0:0]
    -c, --max_clients <max_clients>                  Maximum number of simultaneous clients [default: 512]
    -p, --path <path>                                URI path [default: /dns-query]
    -u, --server_address <server_address>            Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                          Timeout, in seconds [default: 10]
```

Serves HTTP requests only. DoH is mostly useful to leverage an existing webserver, so just configure your webserver to proxy connections to this.

## Clients

`doh-proxy` can be used with [dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy)
as a client.

`doh-proxy` is currently being used by the `doh.crypto.sx` public DNS resolver.
