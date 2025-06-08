# ![DoH server (and ODoH - Oblivious DoH server)](logo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/doh-proxy.svg)](https://crates.io/crates/doh-proxy)

A fast and secure DoH (DNS-over-HTTPS) and ODoH (Oblivious DoH) server.

`doh-proxy` is written in Rust, and has been battle-tested in production since February 2018. It doesn't do DNS resolution on its own, but can sit in front of any DNS resolver in order to augment it with DoH support.

## Table of Contents

- [](#)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
    - [Option 1: precompiled binaries for Linux](#option-1-precompiled-binaries-for-linux)
    - [Option 2: from source code](#option-2-from-source-code)
  - [Quick Start](#quick-start)
    - [Basic Usage](#basic-usage)
    - [Complete Usage Reference](#complete-usage-reference)
    - [Example Configurations](#example-configurations)
  - [Deployment Architectures](#deployment-architectures)
    - [Behind a Reverse Proxy (Recommended)](#behind-a-reverse-proxy-recommended)
    - [Standalone with Built-in TLS](#standalone-with-built-in-tls)
  - [Integration Examples](#integration-examples)
    - [With Encrypted DNS Server](#with-encrypted-dns-server)
    - [With nginx](#with-nginx)
    - [With HAProxy](#with-haproxy)
  - [JSON API](#json-api)
    - [Usage](#usage)
    - [Supported Parameters](#supported-parameters)
    - [Response Format](#response-format)
  - [Oblivious DoH (ODoH)](#oblivious-doh-odoh)
  - [Operational recommendations](#operational-recommendations)
  - [DNS Stamps and Certificate Hashes](#dns-stamps-and-certificate-hashes)
    - [Common certificate hashes](#common-certificate-hashes)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
    - [Performance Tuning](#performance-tuning)
  - [Clients](#clients)
  - [Public Deployments](#public-deployments)
  - [Contributing](#contributing)
  - [License](#license)

## Features

- **DNS-over-HTTPS (DoH)** - Encrypts DNS queries using HTTPS
- **JSON API Support** - Compatible with Google DNS-over-HTTPS JSON API format
- **Oblivious DoH (ODoH)** - Provides additional privacy by hiding client IP addresses
- **High Performance** - Built with Rust and Tokio for excellent performance
- **Flexible Deployment** - Can run standalone with built-in TLS or behind a reverse proxy
- **Production Ready** - Battle-tested in production environments since 2018
- **Multiple IP Support** - Supports multiple external IP addresses for load balancing
- **Automatic Certificate Reloading** - No downtime when updating TLS certificates
- **Configurable Caching** - TTL management with configurable min/max values

## Installation

### Option 1: precompiled binaries for Linux

Precompiled tarballs and Debian packages for Linux/x86_64 [can be downloaded here](https://github.com/jedisct1/doh-server/releases/latest).

### Option 2: from source code

This requires the [`rust`](https://rustup.rs) compiler to be installed.

* With built-in support for HTTPS (default):

```sh
cargo install doh-proxy
```

* Without built-in support for HTTPS:

```sh
cargo install doh-proxy --no-default-features
```

## Quick Start

### Basic Usage

```sh
# Simple setup with a local DNS resolver
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53

# With a specific public IP address
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53 -g 203.0.113.1

# With built-in TLS support
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53 -i /path/to/cert.pem -I /path/to/key.pem
```

### Complete Usage Reference

```text
USAGE:
    doh-proxy [FLAGS] [OPTIONS]

FLAGS:
    -O, --allow-odoh-post      Allow POST queries over ODoH even if they have been disabed for DoH
    -K, --disable-keepalive    Disable keepalive
    -P, --disable-post         Disable POST queries
    -h, --help                 Prints help information
    -V, --version              Prints version information

OPTIONS:
    -E, --err-ttl <err_ttl>                          TTL for errors, in seconds [default: 2]
    -H, --hostname <hostname>                        Host name (not IP address) DoH clients will use to connect
    -l, --listen-address <listen_address>            Address to listen to [default: 127.0.0.1:3000]
    -b, --local-bind-address <local_bind_address>    Address to connect from
    -c, --max-clients <max_clients>                  Maximum number of simultaneous clients [default: 512]
    -C, --max-concurrent <max_concurrent>            Maximum number of concurrent requests per client [default: 16]
    -X, --max-ttl <max_ttl>                          Maximum TTL, in seconds [default: 604800]
    -T, --min-ttl <min_ttl>                          Minimum TTL, in seconds [default: 10]
    -p, --path <path>                                URI path [default: /dns-query]
    -g, --public-address <public_address>            External IP address(es) DoH clients will connect to (can be specified multiple times)
    -j, --public-port <public_port>                  External port DoH clients will connect to, if not 443
    -u, --server-address <server_address>            Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                          Timeout, in seconds [default: 10]
    -I, --tls-cert-key-path <tls_cert_key_path>
            Path to the PEM-encoded secret keys (only required for built-in TLS)

    -i, --tls-cert-path <tls_cert_path>
            Path to the PEM/PKCS#8-encoded certificates (only required for built-in TLS)
```

### Example Configurations

**Basic setup with custom DNS resolver:**
```sh
doh-proxy -H 'doh.example.com' -u 8.8.8.8:53 -g 203.0.113.1
```

**Multiple IP addresses for load balancing:**
```sh
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53 -g 203.0.113.1 -g 203.0.113.2 -g 2001:db8::1
```
This generates separate DNS stamps for each IP address, allowing clients to connect via any of them.

**Production setup with TLS and custom limits:**
```sh
doh-proxy -H 'doh.example.com' \
          -u 127.0.0.1:53 \
          -l 0.0.0.0:443 \
          -i /etc/letsencrypt/live/doh.example.com/fullchain.pem \
          -I /etc/letsencrypt/live/doh.example.com/privkey.pem \
          -c 1000 \
          -C 32
```

**Behind a reverse proxy (nginx/Caddy):**
```sh
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53 -l 127.0.0.1:3000
```

## Deployment Architectures

### Behind a Reverse Proxy (Recommended)

The recommended deployment is behind a TLS termination proxy such as nginx, Caddy, HAProxy, or a CDN. This allows:
- Sharing port 443 with existing web services
- Leveraging existing TLS certificate management
- Using HTTP/2 and HTTP/3 features from the proxy
- Better DDoS protection and rate limiting

**Example with nginx:**
```nginx
server {
    listen 443 ssl http2;
    server_name doh.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /dns-query {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Example with Caddy:**
```caddyfile
doh.example.com {
    reverse_proxy /dns-query localhost:3000
}
```

### Standalone with Built-in TLS

For simpler deployments or when running on separate infrastructure:

```sh
doh-proxy -H 'doh.example.com' \
          -u 127.0.0.1:53 \
          -l 0.0.0.0:443 \
          -i /path/to/fullchain.pem \
          -I /path/to/privkey.pem
```

**Certificate Requirements:**
- Certificates and keys must be in PEM/PKCS#8 format
- Can be stored in the same file or separately
- Automatically reloaded when changed (no restart needed)

If using ECDSA certificates that start with `-----BEGIN EC PRIVATE KEY-----`, convert to PKCS#8:

```sh
openssl pkcs8 -topk8 -nocrypt -in example.key -out example.pkcs8.pem
```

**Using Let's Encrypt with acme.sh:**
```sh
# Install acme.sh
curl https://get.acme.sh | sh

# Get certificates
acme.sh --issue -d doh.example.com --webroot /var/www/html

# Run doh-proxy with Let's Encrypt certificates
doh-proxy -H 'doh.example.com' \
          -u 127.0.0.1:53 \
          -i ~/.acme.sh/doh.example.com/fullchain.cer \
          -I ~/.acme.sh/doh.example.com/doh.example.com.key
```

> **Note:** Once HTTPS is enabled, HTTP connections will not be accepted. A sample self-signed certificate [`localhost.pem`](https://github.com/jedisct1/doh-server/raw/master/localhost.pem) is available for testing.

## Integration Examples

### With Encrypted DNS Server

[Encrypted DNS Server](https://github.com/jedisct1/encrypted-dns-server) can handle both DNSCrypt and DoH on the same port:

```toml
# In encrypted-dns-server.toml
[tls]
upstream_addr = "127.0.0.1:3000"
```

This provides:
- Support for both DNSCrypt and DoH protocols
- Built-in DNS caching
- Server-side filtering
- Connection reuse and DDoS protection

### With nginx

```nginx
location /dns-query {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}
```

### With HAProxy

```haproxy
backend doh_backend
    mode http
    server doh1 127.0.0.1:3000 check
```

## JSON API

The server supports Google's DNS-over-HTTPS JSON API format, making it compatible with applications that use this format.

### Usage

Send GET requests to `/dns-query` with `Accept: application/dns-json` header:

```bash
# Query A records
curl -H "Accept: application/dns-json" \
  "http://localhost:3000/dns-query?name=example.com&type=1"

# Query with multiple parameters
curl -H "Accept: application/dns-json" \
  "http://localhost:3000/dns-query?name=example.com&type=28&cd=1&do=1"
```

### Supported Parameters

- `name` - Domain name to query (required)
- `type` - DNS record type (default: 1 for A records)
- `cd` - Disable DNSSEC validation (0 or 1)
- `do` - Request DNSSEC data (0 or 1)
- `edns_client_subnet` - Client subnet for EDNS

### Response Format

```json
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [{
    "name": "example.com",
    "type": 1
  }],
  "Answer": [{
    "name": "example.com",
    "type": 1,
    "TTL": 300,
    "data": "93.184.216.34"
  }]
}
```

## Oblivious DoH (ODoH)

Oblivious DoH is similar to Anonymized DNSCrypt, but for DoH. It requires relays, but also upstream DoH servers that support the protocol.

This proxy supports ODoH termination (not relaying) out of the box.

However, ephemeral keys are currently only stored in memory. In a load-balanced configuration, sticky sessions must be used.

Currently available ODoH relays only use `POST` queries.
So, `POST` queries have been disabled for regular DoH queries, accepting them is required to be compatible with ODoH relays.

This can be achieved with the `--allow-odoh-post` command-line switch.

## Operational recommendations

* DoH can be easily detected and blocked using SNI inspection. As a mitigation, DoH endpoints should preferably share the same virtual host as existing, popular websites, rather than being on dedicated virtual hosts.
* When using DoH, DNS stamps should include a resolver IP address in order to remove a dependency on non-encrypted, non-authenticated, easy-to-block resolvers.
* Unlike DNSCrypt where users must explicitly trust a DNS server's public key, the security of DoH relies on traditional public Certificate Authorities. Additional root certificates (required by governments, security software, enterprise gateways) installed on a client immediately make DoH vulnerable to MITM. In order to prevent this, DNS stamps should include the hash of the parent certificate.
* TLS certificates are tied to host names. But domains expire, get reassigned and switch hands all the time. If a domain originally used for a DoH service gets a new, possibly malicious owner, clients still configured to use the service will blindly keep trusting it if the CA is the same. As a mitigation, the CA should sign an intermediate certificate (the only one present in the stamp), itself used to sign the name used by the DoH server. While commercial CAs offer this, Let's Encrypt currently doesn't.
* Make sure that the front-end supports at least HTTP/2 and TLS 1.3.
* Internal DoH servers still require TLS certificates. So, if you are planning to deploy an internal server, you need to set up an internal CA, or add self-signed certificates to every single client.


## DNS Stamps and Certificate Hashes

Use the online [DNS stamp calculator](https://dnscrypt.info/stamps/) to compute the stamp for your server.

Add it to the `[static]` section of [`dnscrypt-proxy`](https://github.com/DNSCrypt/dnscrypt-proxy) and check that everything works as expected.

Then, start `dnscrypt-proxy` with the `-show-certs` command-line flag to print the hashes for your certificate chain.

Here is an example output:

```text
[NOTICE] Advertised cert: [CN=dohtrial.att.net,O=AT&T Services\, Inc.,L=Dallas,ST=Texas,C=US] [f679e8451940f06141854dc94e1eb79fa5e04463c15b88f3b392da793c16c353]
[NOTICE] Advertised cert: [CN=DigiCert Global CA G2,O=DigiCert Inc,C=US] [f61e576877da9650294cccb5f96c75fcb71bda1bbc4646367c4ebeda89d7318f]
```

The first printed certificate is the certificate of the server itself. The next line is the one that signed that certificate. As you keep going down, you are getting closer to the certificate authority.

Unless you are using intermediate certificates, your safest option is probably to include the last printed hash certificate in your DNS stamp.

Go back to the online DNS stamp calculator, and copy&paste the hash (in this example: `f61e576877da9650294cccb5f96c75fcb71bda1bbc4646367c4ebeda89d7318f`).

If you are using Let's Encrypt, the last line is likely to be:

```text
Advertised cert: [CN=Let's Encrypt Authority R3,O=Let's Encrypt,C=US] [444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce]
```

There you have it. Your certificate hash is `444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce`.

This [Go code snippet](https://gist.github.com/d6cb41742a1ceb54d48cc286f3d5c5fa) can also compute the hash of certificates given a `.der` file.

### Common certificate hashes

* Let's Encrypt E1:
  * `cc1060d39c8329b62b6fbc7d0d6df9309869b981e7e6392d5cd8fa408f4d80e6`
* Let's Encrypt R3:
  * `444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce`
* Let's Encrypt R10:
  * `e644ba6963e335fe765cb9976b12b10eb54294b42477764ccb3a3acca3acb2fc`
* ZeroSSL:
  * `9a3a34f727deb9bca51003d9ce9c39f8f27dd9c5242901c2bab1a44e635a0219`

## Troubleshooting

### Common Issues

**Port already in use:**
```sh
# Check what's using port 3000
lsof -i :3000
# Or use a different port
doh-proxy -l 127.0.0.1:3001 ...
```

**Certificate errors:**
- Ensure certificate file contains the full chain
- Convert ECDSA keys to PKCS#8 format
- Check file permissions (readable by the doh-proxy user)

**DNS resolution failures:**
- Verify the upstream DNS server is reachable
- Check firewall rules for port 53 (UDP/TCP)
- Test with: `dig @127.0.0.1 -p 53 example.com`

### Performance Tuning

For high-traffic deployments:
```sh
doh-proxy -H 'doh.example.com' \
          -u 127.0.0.1:53 \
          -c 10000 \     # Max clients
          -C 100 \       # Max concurrent streams per client
          -t 30          # Timeout in seconds
```

## Clients

Compatible DoH clients include:
- [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) - Supports both DNSCrypt and DoH
- [cloudflared](https://github.com/cloudflare/cloudflared) - Cloudflare's DoH proxy
- Firefox, Chrome, Edge (native DoH support)
- [doh-client](https://github.com/LinkTed/doh-client) - Rust DoH client
- Android 9+ and iOS 14+ (native DoH support)

## Public Deployments

`doh-proxy` powers several public DNS services including:
- `doh.crypto.sx` - Public DNS resolver
- Many other services listed in [public encrypted DNS servers](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/public-resolvers.md)

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on [GitHub](https://github.com/jedisct1/doh-server).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
