mod constants;
pub mod dns;
mod dns_json;
mod edns_ecs;
mod errors;
mod globals;
pub mod odoh;
#[cfg(feature = "tls")]
mod tls;

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::Engine;
use byteorder::{BigEndian, ByteOrder};
use futures::prelude::*;
use futures::task::{Context, Poll};
use hyper::http;
use hyper::server::conn::Http;
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::runtime;

use crate::constants::*;
pub use crate::errors::*;
pub use crate::globals::*;

pub mod reexports {
    pub use tokio;
}

const BASE64_URL_SAFE_NO_PAD: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

#[derive(Clone, Debug)]
struct DnsResponse {
    packet: Vec<u8>,
    ttl: u32,
}

#[derive(Clone, Debug)]
enum DoHType {
    Standard,
    Oblivious,
    Json,
}

impl DoHType {
    fn as_str(&self) -> String {
        match self {
            DoHType::Standard => String::from("application/dns-message"),
            DoHType::Oblivious => String::from("application/oblivious-dns-message"),
            DoHType::Json => String::from("application/dns-json"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DoH {
    pub globals: Arc<Globals>,
}

#[allow(clippy::unnecessary_wraps)]
fn http_error(status_code: StatusCode) -> Result<Response<Body>, http::Error> {
    let response = Response::builder()
        .status(status_code)
        .body(Body::empty())
        .unwrap();
    Ok(response)
}

#[allow(clippy::unnecessary_wraps)]
fn http_error_with_cache(status_code: StatusCode) -> Result<Response<Body>, http::Error> {
    // Return error with very long cache time (1 year) to prevent crawler bots from retrying
    let response = Response::builder()
        .status(status_code)
        .header(
            hyper::header::CACHE_CONTROL,
            "max-age=31536000, immutable"
        )
        .body(Body::empty())
        .unwrap();
    Ok(response)
}

#[derive(Clone, Debug)]
pub struct LocalExecutor {
    runtime_handle: runtime::Handle,
}

impl LocalExecutor {
    fn new(runtime_handle: runtime::Handle) -> Self {
        LocalExecutor { runtime_handle }
    }
}

impl<F> hyper::rt::Executor<F> for LocalExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send,
{
    fn execute(&self, fut: F) {
        self.runtime_handle.spawn(fut);
    }
}

#[allow(clippy::type_complexity)]
impl hyper::service::Service<http::Request<Body>> for DoH {
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<Body>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let globals = &self.globals;
        let self_inner = self.clone();
        if req.uri().path() == globals.path {
            match *req.method() {
                Method::POST => Box::pin(async move { self_inner.serve_post(req).await }),
                Method::GET => Box::pin(async move { self_inner.serve_get(req).await }),
                _ => Box::pin(async { http_error(StatusCode::METHOD_NOT_ALLOWED) }),
            }
        } else if req.uri().path() == globals.odoh_configs_path {
            match *req.method() {
                Method::GET => Box::pin(async move { self_inner.serve_odoh_configs().await }),
                _ => Box::pin(async { http_error(StatusCode::METHOD_NOT_ALLOWED) }),
            }
        } else {
            Box::pin(async { http_error(StatusCode::NOT_FOUND) })
        }
    }
}

impl DoH {
    async fn serve_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_get(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_get(req).await,
            Ok(DoHType::Json) => self.serve_json_get(req).await,
            Err(response) => Ok(response),
        }
    }

    async fn serve_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_post(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_post(req).await,
            Ok(DoHType::Json) => http_error(StatusCode::METHOD_NOT_ALLOWED),
            Err(response) => Ok(response),
        }
    }

    async fn serve_doh_query(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<Response<Body>, http::Error> {
        let resp = match self.proxy(query, client_ip).await {
            Ok(resp) => {
                self.build_response(resp.packet, resp.ttl, DoHType::Standard.as_str(), true)
            }
            Err(e) => return http_error(StatusCode::from(e)),
        };
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn query_from_query_string(&self, req: Request<Body>) -> Option<Vec<u8>> {
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
        if let Some(question_str) = question_str {
            if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
                return None;
            }
        }
        let query = match question_str
            .and_then(|question_str| BASE64_URL_SAFE_NO_PAD.decode(question_str).ok())
        {
            Some(query) => query,
            _ => return None,
        };
        Some(query)
    }

    async fn serve_doh_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), None)
        } else {
            None
        };

        let query = match self.query_from_query_string(req) {
            Some(query) => query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        self.serve_doh_query(query, client_ip).await
    }

    async fn serve_doh_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }

        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), None)
        } else {
            None
        };

        let query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_doh_query(query, client_ip).await
    }

    async fn serve_odoh(&self, encrypted_query: Vec<u8>) -> Result<Response<Body>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let (query, context) = match (*odoh_public_key).clone().decrypt_query(encrypted_query) {
            Ok((q, context)) => (q.to_vec(), context),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let resp = match self.proxy(query, None).await {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let encrypted_resp = match context.encrypt_response(resp.packet) {
            Ok(resp) => self.build_response(resp, 0u32, DoHType::Oblivious.as_str(), false),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match encrypted_resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let encrypted_query = match self.query_from_query_string(req) {
            Some(encrypted_query) => encrypted_query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        self.serve_odoh(encrypted_query).await
    }

    async fn serve_odoh_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post && !self.globals.allow_odoh_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        let encrypted_query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_odoh(encrypted_query).await
    }

    async fn serve_odoh_configs(&self) -> Result<Response<Body>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let configs = (*odoh_public_key).clone().into_config();
        match self.build_response(
            configs,
            ODOH_KEY_ROTATION_SECS,
            "application/octet-stream".to_string(),
            true,
        ) {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_json_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
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
                .body(Body::from(error_response.to_string()))
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
                    .body(Body::from(error_response.to_string()))
                    .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };

        // Extract client IP if ECS is enabled
        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), None)
        } else {
            None
        };

        // Send query and get response
        let dns_response = match self.proxy(query_packet, client_ip).await {
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

                Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/dns-json")
                    .header(
                        hyper::header::CACHE_CONTROL,
                        format!(
                            "max-age={}, stale-if-error={}, stale-while-revalidate={}",
                            dns_response.ttl, STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS
                        ),
                    )
                    .header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(Body::from(json_string))
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
                    .body(Body::from(error_response.to_string()))
                    .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR))
            }
        }
    }

    fn acceptable_content_type(
        headers: &HeaderMap,
        content_types: &[&'static str],
    ) -> Option<&'static str> {
        let accept = headers.get(hyper::header::ACCEPT);
        let accept = accept?;
        for part in accept.to_str().unwrap_or("").split(',').map(|s| s.trim()) {
            if let Some(found) = part
                .split(';')
                .next()
                .map(|s| s.trim().to_ascii_lowercase())
            {
                if let Some(&content_type) = content_types
                    .iter()
                    .find(|&&content_type| content_type == found)
                {
                    return Some(content_type);
                }
            }
        }
        None
    }

    fn parse_content_type(req: &Request<Body>) -> Result<DoHType, Response<Body>> {
        const CT_DOH: &str = "application/dns-message";
        const CT_ODOH: &str = "application/oblivious-dns-message";
        const CT_JSON: &str = "application/dns-json";

        let headers = req.headers();
        let content_type = match headers.get(hyper::header::CONTENT_TYPE) {
            None => {
                let acceptable_content_type =
                    Self::acceptable_content_type(headers, &[CT_DOH, CT_ODOH, CT_JSON]);
                match acceptable_content_type {
                    None => {
                        // Return NOT_ACCEPTABLE with long cache time for crawler bots
                        let response = Response::builder()
                            .status(StatusCode::NOT_ACCEPTABLE)
                            .header(
                                hyper::header::CACHE_CONTROL,
                                "max-age=31536000, immutable"
                            )
                            .body(Body::empty())
                            .unwrap();
                        return Err(response);
                    }
                    Some(content_type) => content_type,
                }
            }
            Some(content_type) => match content_type.to_str() {
                Err(_) => {
                    // Return BAD_REQUEST with long cache time for invalid content type
                    let response = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(
                            hyper::header::CACHE_CONTROL,
                            "max-age=31536000, immutable"
                        )
                        .body(Body::empty())
                        .unwrap();
                    return Err(response);
                }
                Ok(content_type) => content_type,
            },
        };

        match content_type.to_ascii_lowercase().as_str() {
            CT_DOH => Ok(DoHType::Standard),
            CT_ODOH => Ok(DoHType::Oblivious),
            CT_JSON => Ok(DoHType::Json),
            _ => {
                // Return UNSUPPORTED_MEDIA_TYPE with long cache time
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header(
                        hyper::header::CACHE_CONTROL,
                        "max-age=31536000, immutable"
                    )
                    .body(Body::empty())
                    .unwrap();
                Err(response)
            }
        }
    }

    async fn read_body(&self, mut body: Body) -> Result<Vec<u8>, DoHError> {
        let mut sum_size = 0;
        let mut query = vec![];
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|_| DoHError::TooLarge)?;
            sum_size += chunk.len();
            if sum_size >= MAX_DNS_QUESTION_LEN {
                return Err(DoHError::TooLarge);
            }
            query.extend(chunk);
        }
        Ok(query)
    }

    async fn proxy(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<DnsResponse, DoHError> {
        let proxy_timeout = self.globals.timeout;
        let timeout_res = tokio::time::timeout(proxy_timeout, self._proxy(query, client_ip)).await;
        timeout_res.map_err(|_| DoHError::UpstreamTimeout)?
    }

    async fn _proxy(
        &self,
        mut query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<DnsResponse, DoHError> {
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(DoHError::Incomplete);
        }
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as _);

        // Add EDNS Client Subnet if enabled and we have a client IP
        if self.globals.enable_ecs {
            if let Some(client_ip) = client_ip {
                if let Err(e) = edns_ecs::add_ecs_to_packet(
                    &mut query,
                    client_ip,
                    self.globals.ecs_prefix_v4,
                    self.globals.ecs_prefix_v6,
                ) {
                    eprintln!("Failed to add EDNS Client Subnet: {}", e);
                }
            }
        }
        let globals = &self.globals;
        let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];
        let (min_ttl, max_ttl, err_ttl) = (globals.min_ttl, globals.max_ttl, globals.err_ttl);

        // UDP
        {
            let socket = UdpSocket::bind(&globals.local_bind_address)
                .await
                .map_err(DoHError::Io)?;
            let expected_server_address = globals.server_address;
            socket
                .send_to(&query, &globals.server_address)
                .map_err(DoHError::Io)
                .await?;
            let (len, response_server_address) =
                socket.recv_from(&mut packet).map_err(DoHError::Io).await?;
            if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
                return Err(DoHError::UpstreamIssue);
            }
            packet.truncate(len);
        }

        // TCP
        if dns::is_truncated(&packet) {
            let clients_count = self.globals.clients_count.current();
            if self.globals.max_clients >= UDP_TCP_RATIO
                && clients_count >= self.globals.max_clients / UDP_TCP_RATIO
            {
                return Err(DoHError::TooManyTcpSessions);
            }
            let socket = match globals.server_address {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }
            .map_err(DoHError::Io)?;
            let mut ext_socket = socket
                .connect(globals.server_address)
                .await
                .map_err(DoHError::Io)?;
            ext_socket.set_nodelay(true).map_err(DoHError::Io)?;
            let mut binlen = [0u8, 0];
            BigEndian::write_u16(&mut binlen, query.len() as u16);
            ext_socket.write_all(&binlen).await.map_err(DoHError::Io)?;
            ext_socket.write_all(&query).await.map_err(DoHError::Io)?;
            ext_socket.flush().await.map_err(DoHError::Io)?;
            ext_socket
                .read_exact(&mut binlen)
                .await
                .map_err(DoHError::Io)?;
            let packet_len = BigEndian::read_u16(&binlen) as usize;
            if !(MIN_DNS_PACKET_LEN..=MAX_DNS_RESPONSE_LEN).contains(&packet_len) {
                return Err(DoHError::UpstreamIssue);
            }
            packet = vec![0u8; packet_len];
            ext_socket
                .read_exact(&mut packet)
                .await
                .map_err(DoHError::Io)?;
        }

        let ttl = if dns::is_recoverable_error(&packet) {
            err_ttl
        } else {
            match dns::min_ttl(&packet, min_ttl, max_ttl, err_ttl) {
                Err(_) => return Err(DoHError::UpstreamIssue),
                Ok(ttl) => ttl,
            }
        };
        dns::add_edns_padding(&mut packet)
            .map_err(|_| DoHError::TooLarge)
            .ok();
        Ok(DnsResponse { packet, ttl })
    }

    fn build_response(
        &self,
        packet: Vec<u8>,
        ttl: u32,
        content_type: String,
        cors: bool,
    ) -> Result<Response<Body>, DoHError> {
        let packet_len = packet.len();
        let mut response_builder = Response::builder()
            .header(hyper::header::CONTENT_LENGTH, packet_len)
            .header(hyper::header::CONTENT_TYPE, content_type.as_str())
            .header(
                hyper::header::CACHE_CONTROL,
                format!(
                    "max-age={ttl}, stale-if-error={STALE_IF_ERROR_SECS}, \
                     stale-while-revalidate={STALE_WHILE_REVALIDATE_SECS}"
                )
                .as_str(),
            );
        if cors {
            response_builder =
                response_builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }
        let response = response_builder
            .body(Body::from(packet))
            .map_err(|_| DoHError::InvalidData)?;
        Ok(response)
    }

    async fn client_serve<I>(self, stream: I, server: Http<LocalExecutor>)
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let clients_count = self.globals.clients_count.clone();
        if clients_count.increment() > self.globals.max_clients {
            clients_count.decrement();
            return;
        }
        self.globals.runtime_handle.clone().spawn(async move {
            tokio::time::timeout(
                self.globals.timeout + Duration::from_secs(1),
                server.serve_connection(stream, self),
            )
            .await
            .ok();
            clients_count.decrement();
        });
    }

    async fn start_without_tls(
        self,
        listener: TcpListener,
        server: Http<LocalExecutor>,
    ) -> Result<(), DoHError> {
        let listener_service = async {
            while let Ok((stream, _client_addr)) = listener.accept().await {
                self.clone().client_serve(stream, server.clone()).await;
            }
            Ok(()) as Result<(), DoHError>
        };
        listener_service.await?;
        Ok(())
    }

    pub async fn entrypoint(self) -> Result<(), DoHError> {
        let listen_address = self.globals.listen_address;
        let listener = TcpListener::bind(&listen_address)
            .await
            .map_err(DoHError::Io)?;
        let path = &self.globals.path;

        let tls_enabled: bool;
        #[cfg(not(feature = "tls"))]
        {
            tls_enabled = false;
        }
        #[cfg(feature = "tls")]
        {
            tls_enabled =
                self.globals.tls_cert_path.is_some() && self.globals.tls_cert_key_path.is_some();
        }
        if tls_enabled {
            println!("Listening on https://{listen_address}{path}");
        } else {
            println!("Listening on http://{listen_address}{path}");
        }

        let mut server = Http::new();
        server.http1_keep_alive(self.globals.keepalive);
        server.http2_max_concurrent_streams(self.globals.max_concurrent_streams);
        server.pipeline_flush(true);
        let executor = LocalExecutor::new(self.globals.runtime_handle.clone());
        let server = server.with_executor(executor);

        #[cfg(feature = "tls")]
        {
            if tls_enabled {
                self.start_with_tls(listener, server).await?;
                return Ok(());
            }
        }
        self.start_without_tls(listener, server).await?;
        Ok(())
    }
}
