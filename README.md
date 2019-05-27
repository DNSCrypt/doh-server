# doh-proxy

A DNS-over-HTTP server proxy in Rust. Add a webserver and you get DNS-over-HTTPS, which is actually DNS-over-HTTP/2.

## Installation

Without built-in support for HTTPS:

```sh
cargo install doh-proxy
```

With built-in support for HTTPS (requires openssl-dev):

```sh
cargo install doh-proxy --features=tls
```

## Usage

```text
A DNS-over-HTTP server proxy

USAGE:
    doh-proxy [FLAGS] [OPTIONS]

FLAGS:
    -K, --disable-keepalive    Disable keepalive
    -P, --disable-post         Disable POST queries
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

## HTTP/2 termination

The recommended way to use `doh-proxy` is to use a TLS termination proxy (such as [hitch](https://github.com/varnish/hitch) or [relayd](https://bsd.plumbing/about.html)), a CDN or a web server with proxying abilities as a front-end.

That way, the DoH service can be exposed as a virtual host, sharing the same IP addresses as existing websites.

If `doh-proxy` and the HTTP/2 front-end run on the same host, using the HTTP protocol to communicate between both is fine.

If both are on distinct networks, such as when using a CDN, `doh-proxy` can handle HTTPS requests, provided that it was compiled with the `tls` feature.

The identity must be encoded in PKCS12 format. Given an existing certificate `cert.pem` and its secret key `cert.key`, this can be achieved using the `openssl` command-line tool:

```sh
openssl pkcs12 -export -out cert.p12 -in cert.pem -inkey cert.key
```

A password will be interactive asked for, but the `-passout` command-line option can be added to provide it non-interactively.

Once done, check that the permissions on `cert.p12` are reasonable.

In order to enable built-in HTTPS support, add the `--tls-cert-path` option to specify the location of the `cert.p12` file, as well as the password using `--tls-cert-password`.

Once HTTPS is enabled, HTTP connections will not be accepted.

## Clients

`doh-proxy` can be used with [dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy)
as a client.

`doh-proxy` is currently being used by the `doh.crypto.sx` public DNS resolver.

Other public DoH servers can be found here: [public encrypted DNS servers](https://dnscrypt.info/public-servers).
