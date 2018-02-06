# doh-proxy

A DNS-over-HTTP server proxy in Rust.

## Usage

```
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
    -u, --server_address <server_address>            Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                          Timeout, in seconds [default: 10]
```

## Limitations

Only support `POST` queries. `GET` queries are too noisy in log files, including when they are not yours.

Serves HTTP requests only. DoH is mostly useful to leverage an existing webserver, so just configure your webserver to proxy connections to this.

Path is `/dns-query`.
