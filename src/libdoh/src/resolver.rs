use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

use hyper::HeaderMap;

use crate::errors::DoHError;

/// How a query reached the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoHType {
    /// RFC 8484 DoH.
    Standard,
    /// Oblivious DoH, sent through a relay.
    Oblivious,
    /// The JSON API.
    Json,
}

impl DoHType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            DoHType::Standard => "application/dns-message",
            DoHType::Oblivious => "application/oblivious-dns-message",
            DoHType::Json => "application/dns-json",
        }
    }
}

/// A DNS query received over HTTP.
#[derive(Debug)]
pub struct Query {
    pub packet: Vec<u8>,
    pub kind: DoHType,
    /// The peer of the HTTP connection.
    ///
    /// For an oblivious query, this is the relay, not the client.
    pub remote_addr: SocketAddr,
    pub headers: HeaderMap,
}

/// Whether shared HTTP caches may store a response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CacheScope {
    /// Sends neither `public` nor `private`.
    #[default]
    Unspecified,
    Public,
    Private,
}

/// The `Cache-Control` header of a response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CachePolicy {
    /// How long the response stays fresh, in seconds.
    pub max_age: u32,
    pub scope: CacheScope,
    /// How long a stale response can be used if the server fails, in seconds.
    pub stale_if_error: Option<u32>,
    /// How long a stale response can be used while it is being refreshed, in seconds.
    pub stale_while_revalidate: Option<u32>,
}

impl fmt::Display for CachePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            CacheScope::Unspecified => {}
            CacheScope::Public => write!(f, "public, ")?,
            CacheScope::Private => write!(f, "private, ")?,
        }
        write!(f, "max-age={}", self.max_age)?;
        if let Some(stale_if_error) = self.stale_if_error {
            write!(f, ", stale-if-error={stale_if_error}")?;
        }
        if let Some(stale_while_revalidate) = self.stale_while_revalidate {
            write!(f, ", stale-while-revalidate={stale_while_revalidate}")?;
        }
        Ok(())
    }
}

/// A DNS response, and how long HTTP caches may keep it.
#[derive(Clone, Debug)]
pub struct DnsResponse {
    pub packet: Vec<u8>,
    pub cache: CachePolicy,
}

/// Answers the queries that a DoH server receives.
///
/// `Forwarder` sends them to a DNS server.
/// Applications can implement their own.
pub trait Resolver: Send + Sync + 'static {
    /// Decides whether to serve a new connection.
    ///
    /// This runs for every accepted connection, before TLS and HTTP, so it must be fast.
    /// Refused connections are closed right away.
    fn allow_connection(&self, _remote_addr: SocketAddr) -> bool {
        true
    }

    /// Answers a query.
    ///
    /// If this takes longer than the request timeout, the client gets a 502.
    /// Errors become HTTP status codes, such as 502 for
    /// `DoHError::UpstreamIssue` and 429 for `DoHError::TooManyRequests`.
    fn resolve(&self, query: Query) -> impl Future<Output = Result<DnsResponse, DoHError>> + Send;
}
