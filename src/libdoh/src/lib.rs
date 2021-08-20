mod constants;
pub mod dns;
mod errors;
mod globals;
pub mod odoh;
pub mod odoh_proxy;
#[cfg(feature = "tls")]
mod tls;

use crate::constants::*;
pub use crate::errors::*;
pub use crate::globals::*;

use byteorder::{BigEndian, ByteOrder};
use futures::prelude::*;
use futures::task::{Context, Poll};
use hyper::http;
use hyper::server::conn::Http;
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::runtime;
use urlencoding::decode;

pub mod reexports {
    pub use tokio;
}

#[derive(Clone, Debug)]
struct DnsResponse {
    packet: Vec<u8>,
    ttl: u32,
}

#[derive(Clone, Debug)]
enum DoHType {
    Standard,
    Oblivious,
}

impl DoHType {
    fn as_str(&self) -> String {
        match self {
            DoHType::Standard => String::from("application/dns-message"),
            DoHType::Oblivious => String::from("application/oblivious-dns-message"),
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
    type Response = Response<Body>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

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
        } else if req.uri().path() == globals.odoh_proxy_path {
            // Draft:        https://datatracker.ietf.org/doc/html/draft-pauly-dprive-oblivious-doh-06
            // Golang impl.: https://github.com/cloudflare/odoh-server-go
            // Based on the draft and Golang implementation, only post method is allowed.
            match *req.method() {
                Method::POST => {
                    Box::pin(async move { self_inner.serve_odoh_proxy_post(req).await })
                }
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

struct ParsedUriQuery {
    pub dns_query: Option<Vec<u8>>,
    pub target_uri: Option<String>,
}

impl DoH {
    async fn serve_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_get(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_get(req).await,
            Err(response) => Ok(response),
        }
    }

    async fn serve_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_post(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_post(req).await,
            Err(response) => Ok(response),
        }
    }

    async fn serve_doh_query(&self, query: Vec<u8>) -> Result<Response<Body>, http::Error> {
        let resp = match self.proxy(query).await {
            Ok(resp) => self.build_response(resp.packet, resp.ttl, DoHType::Standard.as_str()),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn parse_query_string(&self, http_query: &str) -> ParsedUriQuery {
        let mut question_str = None;
        let mut targethost = None;
        let mut targetpath = None;
        for parts in http_query.split('&') {
            let mut kv = parts.split('=');
            if let Some(k) = kv.next() {
                match k {
                    DNS_QUERY_PARAM => {
                        question_str = kv.next();
                    }
                    ODOH_TARGET_HOST_QUERY_PARAM => {
                        targethost = kv.next().map(str::to_string);
                    }
                    ODOH_TARGET_PATH_QUERY_PARAM => {
                        targetpath = kv.next().map(str::to_string);
                    }
                    _ => (),
                }
            }
        }
        let target_uri = if let (Some(host), Some(path)) = (targethost, targetpath) {
            // remove percent encoding
            Some(
                decode(&format!("https://{}{}", host, path))
                    .unwrap_or(std::borrow::Cow::Borrowed(""))
                    .to_string(),
            )
        } else {
            None
        };
        if let Some(question_str) = question_str {
            if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
                return ParsedUriQuery {
                    dns_query: None,
                    target_uri,
                };
            }
        }
        let query = match question_str.and_then(|question_str| {
            base64::decode_config(question_str, base64::URL_SAFE_NO_PAD).ok()
        }) {
            Some(query) => query,
            _ => {
                return ParsedUriQuery {
                    dns_query: None,
                    target_uri,
                }
            }
        };
        ParsedUriQuery {
            dns_query: Some(query),
            target_uri,
        }
    }

    async fn serve_doh_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let query = match self
            .parse_query_string(req.uri().query().unwrap_or(""))
            .dns_query
        {
            Some(query) => query,
            _ => return http_error(StatusCode::BAD_REQUEST),
        };
        self.serve_doh_query(query).await
    }

    async fn serve_doh_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        let query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_doh_query(query).await
    }

    async fn serve_odoh(&self, encrypted_query: Vec<u8>) -> Result<Response<Body>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let (query, context) = match (*odoh_public_key).clone().decrypt_query(encrypted_query) {
            Ok((q, context)) => (q.to_vec(), context),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let resp = match self.proxy(query).await {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let encrypted_resp = match context.encrypt_response(resp.packet) {
            Ok(resp) => self.build_response(resp, 0u32, DoHType::Oblivious.as_str()),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match encrypted_resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let encrypted_query = match self
            .parse_query_string(req.uri().query().unwrap_or(""))
            .dns_query
        {
            Some(encrypted_query) => encrypted_query,
            _ => return http_error(StatusCode::BAD_REQUEST),
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

    async fn serve_odoh_proxy(
        &self,
        encrypted_query: Vec<u8>,
        target_uri: &str,
    ) -> Result<Response<Body>, http::Error> {
        let encrypted_response = match self
            .globals
            .odoh_proxy
            .forward_to_target(&encrypted_query, target_uri)
            .await
        {
            Ok(resp) => self.build_response(resp, 0u32, DoHType::Oblivious.as_str()),
            Err(e) => return http_error(e),
        };

        match encrypted_response {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_proxy_post(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post && !self.globals.allow_odoh_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        // Draft:        https://datatracker.ietf.org/doc/html/draft-pauly-dprive-oblivious-doh-06
        // Golang impl.: https://github.com/cloudflare/odoh-server-go
        // The following follows the Golang implementation, which is different from the draft.
        // In the draft, single endpoint, i.e., /dns-query, can accept proxy and target messages,
        // and works as a proxy only when '?targethost' and '?tagetpath' exist in given uri query.
        // However, in Golang implementation, proxy and target endpoints are separated.
        match Self::parse_content_type(&req) {
            Ok(DoHType::Oblivious) => {
                let http_query = req.uri().query().unwrap_or("");
                let target_uri = match self.parse_query_string(http_query) {
                    ParsedUriQuery {
                        dns_query: _,
                        target_uri: Some(uri),
                    } => uri,
                    _ => return http_error(StatusCode::BAD_REQUEST),
                };
                let encrypted_query = match self.read_body(req.into_body()).await {
                    Ok(q) => {
                        if q.len() == 0 {
                            return http_error(StatusCode::BAD_REQUEST);
                        }
                        q
                    },
                    Err(e) => return http_error(StatusCode::from(e)),
                };

                self.serve_odoh_proxy(encrypted_query, &target_uri).await
            },
            Ok(_) => http_error(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            Err(err_response) => Ok(err_response)
        }
    }

    async fn serve_odoh_configs(&self) -> Result<Response<Body>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let configs = (*odoh_public_key).clone().into_config();
        match self.build_response(
            configs,
            ODOH_KEY_ROTATION_SECS,
            "application/octet-stream".to_string(),
        ) {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn acceptable_content_type(
        headers: &HeaderMap,
        content_types: &[&'static str],
    ) -> Option<&'static str> {
        let accept = headers.get(hyper::header::ACCEPT);
        let accept = match accept {
            None => return None,
            Some(accept) => accept,
        };
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

        let headers = req.headers();
        let content_type = match headers.get(hyper::header::CONTENT_TYPE) {
            None => {
                let acceptable_content_type =
                    Self::acceptable_content_type(headers, &[CT_DOH, CT_ODOH]);
                match acceptable_content_type {
                    None => {
                        let response = Response::builder()
                            .status(StatusCode::NOT_ACCEPTABLE)
                            .body(Body::empty())
                            .unwrap();
                        return Err(response);
                    }
                    Some(content_type) => content_type,
                }
            }
            Some(content_type) => match content_type.to_str() {
                Err(_) => {
                    let response = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
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
            _ => {
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
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

    async fn proxy(&self, query: Vec<u8>) -> Result<DnsResponse, DoHError> {
        let proxy_timeout = self.globals.timeout;
        let timeout_res = tokio::time::timeout(proxy_timeout, self._proxy(query)).await;
        timeout_res.map_err(|_| DoHError::UpstreamTimeout)?
    }

    async fn _proxy(&self, mut query: Vec<u8>) -> Result<DnsResponse, DoHError> {
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(DoHError::Incomplete);
        }
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as _);
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
    ) -> Result<Response<Body>, DoHError> {
        let packet_len = packet.len();
        let response = Response::builder()
            .header(hyper::header::CONTENT_LENGTH, packet_len)
            .header(hyper::header::CONTENT_TYPE, content_type.as_str())
            .header(
                hyper::header::CACHE_CONTROL,
                format!(
                    "max-age={}, stale-if-error={}, stale-while-revalidate={}",
                    ttl, STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS
                )
                .as_str(),
            )
            .body(Body::from(packet))
            .unwrap();
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
        let odoh_proxy_path = &self.globals.odoh_proxy_path;

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
            println!("ODoH/DoH Server: Listening on https://{}{}", listen_address, path);
            println!("ODoH Proxy     : Listening on https://{}{}", listen_address, odoh_proxy_path);
        } else {
            println!("ODoH/DoH Server: Listening on http://{}{}", listen_address, path);
            println!("ODoH Proxy     : Listening on http://{}{}", listen_address, odoh_proxy_path);
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
