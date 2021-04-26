mod constants;
pub mod dns;
pub mod odoh;
mod errors;
mod globals;
#[cfg(feature = "tls")]
mod tls;

use crate::constants::*;
pub use crate::errors::*;
pub use crate::globals::*;

use futures::prelude::*;
use futures::task::{Context, Poll};
use hyper::http;
use hyper::server::conn::Http;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime;

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
    pub globals: Arc<Globals>
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
    async fn serve_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }

        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_post(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_post(req).await,
            Err(response) => return Ok(response)
        }
    }

    async fn serve_doh_post(&self, req:Request<Body>) -> Result<Response<Body>, http::Error> {
        let query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e))
        };

        let resp = match self.proxy(query).await {
            Ok(resp) => self.build_response(resp.packet, resp.ttl, DoHType::Standard.as_str()),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    // #[cfg(feature = "odoh")]
    async fn serve_odoh_post(&self, req:Request<Body>) -> Result<Response<Body>, http::Error> {
        let query_body = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e))
        };

        let (query, context) = match (*self.globals.odoh_public_key).clone().decrypt_query(query_body).await {
            Ok((q, context)) => (q.to_vec(), context),
            Err(_) => return http_error(StatusCode::from(DoHError::InvalidData))
        };

        let resp_body = match self.proxy(query).await {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e))
        };

        let resp = match context.encrypt_response(resp_body.packet).await {
            Ok(resp) => self.build_response(resp, 0u32, DoHType::Oblivious.as_str()),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_configs(&self) -> Result<Response<Body>, http::Error> {
        let configs = (*self.globals.odoh_public_key).clone().config();
        match self.build_response(configs, 0, "application/octet-stream".to_string()) {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_get(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let query = req.uri().query().unwrap_or("");
        let mut question_str = None;
        for parts in query.split('&') {
            let mut kv = parts.split('=');
            if let Some(k) = kv.next() {
                if k == DNS_QUERY_PARAM {
                    question_str = kv.next();
                }
            }
        }
        let question = match question_str.and_then(|question_str| {
            base64::decode_config(question_str, base64::URL_SAFE_NO_PAD).ok()
        }) {
            Some(question) => question,
            _ => {
                return http_error(StatusCode::BAD_REQUEST);
            }
        };

        let resp = match self.proxy(question).await {
            Ok(dns_resp) => self.build_response(dns_resp.packet, dns_resp.ttl, DoHType::Standard.as_str()),
            Err(e) => Err(e),
        };
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn parse_content_type(req: &Request<Body>) -> Result<DoHType, Response<Body>> {
        let headers = req.headers();
        let content_type = match headers.get(hyper::header::CONTENT_TYPE) {
            None => {
                let response = Response::builder()
                    .status(StatusCode::NOT_ACCEPTABLE)
                    .body(Body::empty())
                    .unwrap();
                return Err(response);
            }
            Some(content_type) => content_type.to_str(),
        };
        let content_type = match content_type {
            Err(_) => {
                let response = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap();
                return Err(response);
            }
            Ok(content_type) => content_type.to_lowercase(),
        };

        match content_type.as_str() {
            "application/dns-message" => Ok(DoHType::Standard),
            "application/oblivious-dns-message" => Ok(DoHType::Oblivious),
            _ => {
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(Body::empty())
                    .unwrap();
                return Err(response);
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
        let socket = UdpSocket::bind(&globals.local_bind_address)
            .await
            .map_err(DoHError::Io)?;
        let expected_server_address = globals.server_address;
        let (min_ttl, max_ttl, err_ttl) = (globals.min_ttl, globals.max_ttl, globals.err_ttl);
        socket
            .send_to(&query, &globals.server_address)
            .map_err(DoHError::Io)
            .await?;
        let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];
        let (len, response_server_address) =
            socket.recv_from(&mut packet).map_err(DoHError::Io).await?;
        if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
            return Err(DoHError::UpstreamIssue);
        }
        packet.truncate(len);
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
        Ok(DnsResponse{
            packet,
            ttl,
        })
    }

    fn build_response(&self, packet: Vec<u8>, ttl: u32, content_type: String) -> Result<Response<Body>, DoHError> {
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
            println!("Listening on https://{}{}", listen_address, path);
        } else {
            println!("Listening on http://{}{}", listen_address, path);
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
