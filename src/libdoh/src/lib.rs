//! A DNS-over-HTTPS server.
//!
//! `DoH` serves RFC 8484 queries over HTTP/1.1 and HTTP/2, and optionally
//! Oblivious DoH and a JSON API.
//! With the `tls` feature, it can also handle TLS and reload certificates.
//!
//! The server takes care of connections and timeouts, and a `Resolver` answers
//! the queries.
//! `Forwarder` sends them to a DNS server.
//! Applications can write their own resolver, or wrap a `Forwarder`:
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! use libdoh::{DnsResponse, DoH, DoHError, Forwarder, Globals, Query, Resolver};
//!
//! struct LocalOnly(Forwarder);
//!
//! impl Resolver for LocalOnly {
//!     fn allow_connection(&self, remote_addr: SocketAddr) -> bool {
//!         remote_addr.ip().is_loopback()
//!     }
//!
//!     async fn resolve(&self, query: Query) -> Result<DnsResponse, DoHError> {
//!         self.0.resolve(query).await
//!     }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let forwarder = Forwarder::new("9.9.9.9:53".parse()?, 64);
//! let globals = Globals {
//!     max_clients: 512,
//!     ..Globals::default()
//! };
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//! DoH::new(globals, LocalOnly(forwarder)).serve(listener).await?;
//! # Ok(())
//! # }
//! ```

mod accept;
mod admission;
mod constants;
pub mod dns;
mod dns_json;
mod edns_ecs;
mod errors;
mod forwarder;
mod globals;
mod lifecycle;
pub mod odoh;
mod resolver;
#[cfg(test)]
mod tests;
#[cfg(feature = "tls")]
mod tls;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::Engine;
use bytes::Bytes;
use futures::prelude::*;
use http_body_util::{BodyExt, Full};
use hyper::http;
use hyper::{body::Incoming as IncomingBody, HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::time::Instant;

use crate::accept::Acceptor;
use crate::admission::{Admission, Slot};
use crate::constants::*;
pub use crate::errors::*;
pub use crate::forwarder::Forwarder;
pub use crate::globals::*;
use crate::lifecycle::{Activity, Policy};
pub use crate::resolver::*;

pub mod reexports {
    pub use hyper;
    pub use tokio;
}

type Body = Full<Bytes>;

const BASE64_URL_SAFE_NO_PAD: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

/// A DoH server that answers queries with a `Resolver`.
pub struct DoH<R> {
    globals: Globals,
    resolver: R,
}

#[allow(clippy::unnecessary_wraps)]
fn http_error(status_code: StatusCode) -> Result<Response<Body>, http::Error> {
    let response = Response::builder()
        .status(status_code)
        .body(Body::new(Bytes::new()))
        .unwrap();
    Ok(response)
}

#[allow(clippy::unnecessary_wraps)]
fn http_error_with_cache(status_code: StatusCode) -> Result<Response<Body>, http::Error> {
    // Return error with very long cache time (1 year) to prevent crawler bots from retrying
    let response = Response::builder()
        .status(status_code)
        .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Body::new(Bytes::new()))
        .unwrap();
    Ok(response)
}

/// The HTTP service of a single downstream connection.
struct ConnectionService<R> {
    server: Arc<Server<R>>,
    remote_addr: SocketAddr,
    activity: Arc<Activity>,
}

#[allow(clippy::type_complexity)]
impl<R: Resolver> hyper::service::Service<http::Request<IncomingBody>> for ConnectionService<R> {
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<Body>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        let activity = self.activity.enter();
        let ctx = RequestContext {
            deadline: Instant::now() + self.server.policy.request,
            remote_addr: self.remote_addr,
        };
        let server = Arc::clone(&self.server);
        Box::pin(async move {
            let _activity = activity;
            server.doh.serve_request(req, &ctx).await
        })
    }
}

struct RequestContext {
    /// Receiving the body and resolving the query must both be done by then.
    deadline: Instant,
    remote_addr: SocketAddr,
}

impl<R: Resolver> DoH<R> {
    pub fn new(globals: Globals, resolver: R) -> DoH<R> {
        DoH { globals, resolver }
    }

    /// Serves connections from a listener that is already bound.
    ///
    /// This only returns, with an error, if the settings are invalid.
    pub async fn serve(self, listener: TcpListener) -> Result<(), DoHError> {
        Arc::new(Server::new(self)?).run(listener).await
    }

    /// Binds `listen_address` and serves connections from it.
    pub async fn entrypoint(self) -> Result<(), DoHError> {
        let server = Arc::new(Server::new(self)?);
        let globals = &server.doh.globals;
        let listen_address = globals.listen_address;
        let listener = TcpListener::bind(&listen_address)
            .await
            .map_err(DoHError::Io)?;
        let scheme = if server.uses_tls() { "https" } else { "http" };
        let path = globals.path.as_deref().unwrap_or("/");
        println!("Listening on {scheme}://{listen_address}{path}");
        server.run(listener).await
    }

    async fn serve_request(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let globals = &self.globals;
        let version = req.version();
        let path = req.uri().path();
        let is_odoh_configs = globals.odoh_rotator.is_some() && path == globals.odoh_configs_path;
        let is_query = match &globals.path {
            Some(query_path) => path == query_path,
            None => !is_odoh_configs,
        };
        let mut response = if is_query {
            match *req.method() {
                Method::POST => self.serve_post(req, ctx).await,
                Method::GET => self.serve_get(req, ctx).await,
                _ => http_error(StatusCode::METHOD_NOT_ALLOWED),
            }
        } else if is_odoh_configs {
            match *req.method() {
                Method::GET => self.serve_odoh_configs().await,
                _ => http_error(StatusCode::METHOD_NOT_ALLOWED),
            }
        } else {
            http_error(StatusCode::NOT_FOUND)
        }?;
        // The rest of the body may still be in flight, so the connection can't be reused.
        if response.status() == StatusCode::REQUEST_TIMEOUT && version < http::Version::HTTP_2 {
            response.headers_mut().insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("close"),
            );
        }
        Ok(response)
    }

    async fn serve_get(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let mut response = match self.parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_get(req, ctx).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_get(req, ctx).await,
            Ok(DoHType::Json) => self.serve_json_get(req, ctx).await,
            Err(response) => Ok(*response),
        }?;
        response.headers_mut().insert(
            hyper::header::VARY,
            hyper::header::HeaderValue::from_static("Accept, Content-Type"),
        );
        Ok(response)
    }

    async fn serve_post(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        match self.parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_post(req, ctx).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_post(req, ctx).await,
            Ok(DoHType::Json) => http_error(StatusCode::METHOD_NOT_ALLOWED),
            Err(response) => Ok(*response),
        }
    }

    async fn serve_doh_query(
        &self,
        query: Vec<u8>,
        headers: HeaderMap,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let resp = match self.resolve(query, DoHType::Standard, headers, ctx).await {
            Ok(resp) => self.build_response(
                resp.packet,
                &resp.cache,
                DoHType::Standard.as_str(),
                self.globals.cors,
            ),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn query_from_query_string(&self, req: &Request<IncomingBody>) -> Option<Vec<u8>> {
        let http_query = req.uri().query().unwrap_or("");
        let mut question_str = None;
        for parts in http_query.split('&') {
            let mut kv = parts.split('=');
            if let Some(k) = kv.next() {
                if k == DNS_QUERY_PARAM {
                    question_str = kv.next();
                }
            }
        }
        let max_query_len = self.globals.max_query_len;
        if let Some(question_str) = question_str {
            if base64::encoded_len(max_query_len, true).is_some_and(|max| question_str.len() > max)
            {
                return None;
            }
        }
        let query = match question_str
            .and_then(|question_str| BASE64_URL_SAFE_NO_PAD.decode(question_str).ok())
        {
            Some(query) => query,
            _ => return None,
        };
        (query.len() <= max_query_len).then_some(query)
    }

    async fn serve_doh_get(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let query = match self.query_from_query_string(&req) {
            Some(query) => query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        let (parts, _) = req.into_parts();
        self.serve_doh_query(query, parts.headers, ctx).await
    }

    async fn serve_doh_post(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }

        let (parts, body) = req.into_parts();
        let query = match self.read_body(body, ctx).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_doh_query(query, parts.headers, ctx).await
    }

    async fn serve_odoh(
        &self,
        encrypted_query: Vec<u8>,
        headers: HeaderMap,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let Some(odoh_rotator) = &self.globals.odoh_rotator else {
            return http_error(StatusCode::NOT_FOUND);
        };
        let odoh_public_key = odoh_rotator.current_public_key();
        let (query, context) = match (*odoh_public_key).clone().decrypt_query(encrypted_query) {
            Ok((q, context)) => (q.to_vec(), context),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let resp = match self.resolve(query, DoHType::Oblivious, headers, ctx).await {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let cache = CachePolicy {
            max_age: 0,
            ..resp.cache
        };
        let encrypted_resp = match context.encrypt_response(resp.packet) {
            Ok(resp) => self.build_response(resp, &cache, DoHType::Oblivious.as_str(), false),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match encrypted_resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_get(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        let encrypted_query = match self.query_from_query_string(&req) {
            Some(encrypted_query) => encrypted_query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        let (parts, _) = req.into_parts();
        self.serve_odoh(encrypted_query, parts.headers, ctx).await
    }

    async fn serve_odoh_post(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post && !self.globals.allow_odoh_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        let (parts, body) = req.into_parts();
        let encrypted_query = match self.read_body(body, ctx).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_odoh(encrypted_query, parts.headers, ctx).await
    }

    async fn serve_odoh_configs(&self) -> Result<Response<Body>, http::Error> {
        let Some(odoh_rotator) = &self.globals.odoh_rotator else {
            return http_error(StatusCode::NOT_FOUND);
        };
        let odoh_public_key = odoh_rotator.current_public_key();
        let configs = (*odoh_public_key).clone().into_config();
        let cache = CachePolicy {
            max_age: ODOH_KEY_ROTATION_SECS,
            stale_if_error: Some(STALE_IF_ERROR_SECS),
            stale_while_revalidate: Some(STALE_WHILE_REVALIDATE_SECS),
            ..CachePolicy::default()
        };
        match self.build_response(
            configs,
            &cache,
            "application/octet-stream",
            self.globals.cors,
        ) {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_json_get(
        &self,
        req: Request<IncomingBody>,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, http::Error> {
        use serde_json::json;

        // Parse query parameters
        let query_params = req.uri().query().unwrap_or("");
        let mut json_query = dns_json::DnsJsonQuery {
            name: String::new(),
            qtype: None,
            cd: None,
            ct: None,
            do_: None,
            edns_client_subnet: None,
        };

        // Parse query string
        for parts in query_params.split('&') {
            let mut kv = parts.split('=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                match k {
                    "name" => {
                        json_query.name = urlencoding::decode(v).unwrap_or_default().into_owned()
                    }
                    "type" => json_query.qtype = v.parse().ok(),
                    "cd" => json_query.cd = Some(v == "1" || v == "true"),
                    "ct" => json_query.ct = Some(v.to_string()),
                    "do" => json_query.do_ = Some(v == "1" || v == "true"),
                    "edns_client_subnet" => json_query.edns_client_subnet = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        // Validate query
        if json_query.name.is_empty() {
            let error_response = json!({
                "Status": 400,
                "Comment": "Missing 'name' parameter"
            });
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(hyper::header::CONTENT_TYPE, "application/dns-json")
                .body(Body::new(Bytes::from(error_response.to_string())))
                .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR));
        }

        // Build DNS query packet
        let query_packet = match dns_json::build_dns_query(&json_query) {
            Ok(packet) => packet,
            Err(e) => {
                let error_response = json!({
                    "Status": 400,
                    "Comment": format!("Invalid query: {}", e)
                });
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(hyper::header::CONTENT_TYPE, "application/dns-json")
                    .body(Body::new(Bytes::from(error_response.to_string())))
                    .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };

        // Send query and get response
        let (parts, _) = req.into_parts();
        let dns_response = match self
            .resolve(query_packet, DoHType::Json, parts.headers, ctx)
            .await
        {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e)),
        };

        // Parse DNS response to JSON
        match dns_json::parse_dns_to_json(&dns_response.packet) {
            Ok(json_response) => {
                let json_string = match serde_json::to_string(&json_response) {
                    Ok(s) => s,
                    Err(_) => return http_error(StatusCode::INTERNAL_SERVER_ERROR),
                };
                self.build_response(
                    json_string.into_bytes(),
                    &dns_response.cache,
                    DoHType::Json.as_str(),
                    self.globals.cors,
                )
                .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR))
            }
            Err(e) => {
                let error_response = json!({
                    "Status": 500,
                    "Comment": format!("Failed to parse DNS response: {}", e)
                });
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(hyper::header::CONTENT_TYPE, "application/dns-json")
                    .body(Body::new(Bytes::from(error_response.to_string())))
                    .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR))
            }
        }
    }

    /// The query type for a content type, if the server supports it.
    fn doh_type(&self, content_type: &str) -> Option<DoHType> {
        let doh_type = [DoHType::Standard, DoHType::Oblivious, DoHType::Json]
            .iter()
            .copied()
            .find(|doh_type| doh_type.as_str() == content_type)?;
        let enabled = match doh_type {
            DoHType::Standard => true,
            DoHType::Oblivious => self.globals.odoh_rotator.is_some(),
            DoHType::Json => self.globals.enable_json,
        };
        enabled.then_some(doh_type)
    }

    fn acceptable_content_type(&self, headers: &HeaderMap) -> Option<DoHType> {
        let accept = headers.get(hyper::header::ACCEPT);
        let accept = accept?;
        for part in accept.to_str().unwrap_or("").split(',').map(|s| s.trim()) {
            if let Some(found) = part
                .split(';')
                .next()
                .map(|s| s.trim().to_ascii_lowercase())
            {
                if let Some(doh_type) = self.doh_type(&found) {
                    return Some(doh_type);
                }
            }
        }
        None
    }

    fn parse_content_type(
        &self,
        req: &Request<IncomingBody>,
    ) -> Result<DoHType, Box<Response<Body>>> {
        let headers = req.headers();
        let content_type = match headers.get(hyper::header::CONTENT_TYPE) {
            None => match self.acceptable_content_type(headers) {
                None if !self.globals.require_accept => return Ok(DoHType::Standard),
                None => {
                    // Return NOT_ACCEPTABLE with long cache time for crawler bots
                    let response = Response::builder()
                        .status(StatusCode::NOT_ACCEPTABLE)
                        .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                        .body(Body::new(Bytes::new()))
                        .unwrap();
                    return Err(Box::new(response));
                }
                Some(doh_type) => return Ok(doh_type),
            },
            Some(content_type) => match content_type.to_str() {
                Err(_) => {
                    // Return BAD_REQUEST with long cache time for invalid content type
                    let response = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                        .body(Body::new(Bytes::new()))
                        .unwrap();
                    return Err(Box::new(response));
                }
                Ok(content_type) => content_type,
            },
        };

        match self.doh_type(&content_type.to_ascii_lowercase()) {
            Some(doh_type) => Ok(doh_type),
            None => {
                // Return UNSUPPORTED_MEDIA_TYPE with long cache time
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                    .body(Body::new(Bytes::new()))
                    .unwrap();
                Err(Box::new(response))
            }
        }
    }

    async fn read_body(
        &self,
        mut body: IncomingBody,
        ctx: &RequestContext,
    ) -> Result<Vec<u8>, DoHError> {
        let max_query_len = self.globals.max_query_len;
        let collect = async {
            let mut sum_size = 0;
            let mut query = vec![];
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| DoHError::TooLarge)?;
                let Some(chunk) = frame.data_ref() else {
                    continue;
                };
                sum_size += chunk.len();
                if sum_size > max_query_len {
                    return Err(DoHError::TooLarge);
                }
                query.extend(chunk);
            }
            Ok(query)
        };
        tokio::time::timeout_at(ctx.deadline, collect)
            .await
            .map_err(|_| DoHError::BodyTimeout)?
    }

    async fn resolve(
        &self,
        packet: Vec<u8>,
        kind: DoHType,
        headers: HeaderMap,
        ctx: &RequestContext,
    ) -> Result<DnsResponse, DoHError> {
        if packet.len() < MIN_DNS_PACKET_LEN {
            return Err(DoHError::Incomplete);
        }
        if packet.len() > self.globals.max_query_len {
            return Err(DoHError::TooLarge);
        }
        let query = Query {
            packet,
            kind,
            remote_addr: ctx.remote_addr,
            headers,
        };
        tokio::time::timeout_at(ctx.deadline, self.resolver.resolve(query))
            .await
            .map_err(|_| DoHError::UpstreamTimeout)?
    }

    fn build_response(
        &self,
        packet: Vec<u8>,
        cache: &CachePolicy,
        content_type: &str,
        cors: bool,
    ) -> Result<Response<Body>, DoHError> {
        let packet_len = packet.len();
        let mut response_builder = Response::builder()
            .header(hyper::header::CONTENT_LENGTH, packet_len)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .header(hyper::header::CACHE_CONTROL, cache.to_string());
        if cors {
            response_builder =
                response_builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }
        let response = response_builder
            .body(Body::new(Bytes::from(packet)))
            .map_err(|_| DoHError::InvalidData)?;
        Ok(response)
    }
}

/// Runtime state shared by the listener and all the connections.
struct Server<R> {
    doh: DoH<R>,
    policy: Policy,
    http: HttpBuilder<TokioExecutor>,
    admission: Arc<Admission>,
}

impl<R: Resolver> Server<R> {
    fn new(doh: DoH<R>) -> Result<Server<R>, DoHError> {
        doh.globals.validate()?;
        let policy = Policy::new(doh.globals.timeout);
        Ok(Server::with_policy(doh, policy))
    }

    fn with_policy(doh: DoH<R>, policy: Policy) -> Server<R> {
        let globals = &doh.globals;
        let mut http = HttpBuilder::new(TokioExecutor::new());
        http.http1()
            .timer(TokioTimer::new())
            .header_read_timeout(policy.request)
            .keep_alive(globals.keepalive)
            .pipeline_flush(true);
        http.http2()
            .max_concurrent_streams(globals.max_concurrent_streams);
        let admission = Admission::new(globals.max_clients);
        Server {
            doh,
            policy,
            http,
            admission,
        }
    }

    #[cfg(feature = "tls")]
    fn uses_tls(&self) -> bool {
        let globals = &self.doh.globals;
        globals.tls_cert_path.is_some() && globals.tls_cert_key_path.is_some()
    }

    #[cfg(not(feature = "tls"))]
    fn uses_tls(&self) -> bool {
        false
    }

    async fn run(self: Arc<Self>, listener: TcpListener) -> Result<(), DoHError> {
        #[cfg(feature = "tls")]
        {
            if self.uses_tls() {
                return self.run_with_tls(listener).await;
            }
        }
        self.run_without_tls(listener).await
    }

    /// Serves HTTP on an accepted connection, which has already been given a slot.
    ///
    /// `idle_since` is when the connection became ready for its first request:
    /// the slot's `accepted_at` for plain connections, or the end of the TLS
    /// handshake.
    async fn serve_connection<I>(
        self: Arc<Self>,
        io: I,
        remote_addr: SocketAddr,
        slot: Slot,
        idle_since: Instant,
    ) where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let activity = Activity::new(idle_since);
        let service = ConnectionService {
            server: Arc::clone(&self),
            remote_addr,
            activity: Arc::clone(&activity),
        };
        let conn = std::pin::pin!(self.http.serve_connection(TokioIo::new(io), service));
        lifecycle::drive(
            conn,
            |conn| conn.graceful_shutdown(),
            &self.policy,
            &activity,
            &slot,
        )
        .await;
    }

    async fn run_without_tls(self: Arc<Self>, listener: TcpListener) -> Result<(), DoHError> {
        let mut acceptor = Acceptor::default();
        loop {
            let (stream, remote_addr) = acceptor.accept(&listener).await;
            if !self.doh.resolver.allow_connection(remote_addr) {
                continue;
            }
            let Some(slot) = self.admission.try_admit() else {
                continue;
            };
            let idle_since = slot.accepted_at;
            tokio::spawn(Arc::clone(&self).serve_connection(stream, remote_addr, slot, idle_since));
        }
    }
}
