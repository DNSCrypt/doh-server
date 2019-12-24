mod constants;
mod dns;
mod errors;
mod globals;
#[cfg(feature = "tls")]
mod tls;

use crate::constants::*;
pub use crate::errors::*;
pub use crate::globals::*;

#[cfg(feature = "tls")]
use crate::tls::*;

use futures::prelude::*;
use futures::task::{Context, Poll};
use hyper::http;
use hyper::server::conn::Http;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Debug)]
pub struct DoH {
    pub globals: Arc<Globals>,
}

fn http_error(status_code: StatusCode) -> Result<Response<Body>, http::Error> {
    let response = Response::builder()
        .status(status_code)
        .body(Body::empty())
        .unwrap();
    Ok(response)
}

impl hyper::service::Service<http::Request<Body>> for DoH {
    type Response = Response<Body>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let globals = &self.globals;
        if req.uri().path() != globals.path {
            return Box::pin(async { http_error(StatusCode::NOT_FOUND) });
        }
        let self_inner = self.clone();
        match *req.method() {
            Method::POST => Box::pin(async move { self_inner.serve_post(req).await }),
            Method::GET => Box::pin(async move { self_inner.serve_get(req).await }),
            _ => Box::pin(async { http_error(StatusCode::METHOD_NOT_ALLOWED) }),
        }
    }
}

impl DoH {
    async fn serve_post(&self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        if let Err(response) = Self::check_content_type(&req) {
            return Ok(response);
        }
        match self.read_body_and_proxy(req.into_body()).await {
            Err(e) => http_error(StatusCode::from(e)),
            Ok(res) => Ok(res),
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
        match self.proxy(question).await {
            Err(e) => http_error(StatusCode::from(e)),
            Ok(res) => Ok(res),
        }
    }

    fn check_content_type(req: &Request<Body>) -> Result<(), Response<Body>> {
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
        if content_type != "application/dns-message" {
            let response = Response::builder()
                .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .body(Body::empty())
                .unwrap();
            return Err(response);
        }
        Ok(())
    }

    async fn read_body_and_proxy(&self, mut body: Body) -> Result<Response<Body>, DoHError> {
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
        let response = self.proxy(query).await?;
        Ok(response)
    }

    async fn proxy(&self, mut query: Vec<u8>) -> Result<Response<Body>, DoHError> {
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(DoHError::Incomplete);
        }
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as _);
        let globals = &self.globals;
        let mut socket = UdpSocket::bind(&globals.local_bind_address)
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
        dns::add_edns_padding(&mut packet, BLOCK_SIZE).map_err(|_| DoHError::TooLarge)?;
        let packet_len = packet.len();
        let response = Response::builder()
            .header(hyper::header::CONTENT_LENGTH, packet_len)
            .header(hyper::header::CONTENT_TYPE, "application/dns-message")
            .header(
                hyper::header::CACHE_CONTROL,
                format!("max-age={}", ttl).as_str(),
            )
            .body(Body::from(packet))
            .unwrap();
        Ok(response)
    }

    async fn client_serve<I>(self, stream: I, server: Http)
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let clients_count = self.globals.clients_count.clone();
        if clients_count.increment() > self.globals.max_clients {
            clients_count.decrement();
            return;
        }
        tokio::spawn(async move {
            tokio::time::timeout(self.globals.timeout, server.serve_connection(stream, self))
                .await
                .ok();
            clients_count.decrement();
        });
    }

    async fn start_without_tls(
        self,
        mut listener: TcpListener,
        server: Http,
    ) -> Result<(), DoHError> {
        let listener_service = async {
            while let Some(stream) = listener.incoming().next().await {
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
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

        #[cfg(feature = "tls")]
        let tls_acceptor = match (&self.globals.tls_cert_path, &self.globals.tls_cert_password) {
            (Some(tls_cert_path), Some(tls_cert_password)) => {
                Some(create_tls_acceptor(tls_cert_path, tls_cert_password).unwrap())
            }
            _ => None,
        };
        #[cfg(not(feature = "tls"))]
        let tls_acceptor: Option<()> = None;

        if tls_acceptor.is_some() {
            println!("Listening on https://{}{}", listen_address, path);
        } else {
            println!("Listening on http://{}{}", listen_address, path);
        }

        let mut server = Http::new();
        server.keep_alive(self.globals.keepalive);
        server.pipeline_flush(true);

        #[cfg(feature = "tls")]
        {
            if let Some(tls_acceptor) = tls_acceptor {
                self.start_with_tls(tls_acceptor, listener, server).await?;
                return Ok(());
            }
        }
        self.start_without_tls(listener, server).await?;
        Ok(())
    }
}
