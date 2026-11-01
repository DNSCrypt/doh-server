use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::constants::{MAX_DNS_QUESTION_LEN, MIN_DNS_PACKET_LEN};
use crate::errors::DoHError;
use crate::odoh::ODoHRotator;

pub const MIN_TIMEOUT_SECS: u64 = 1;
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// Settings of a DoH server.
///
/// ODoH stays disabled until `odoh_rotator` is set.
#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    /// Address that `DoH::entrypoint()` listens to.
    pub listen_address: SocketAddr,
    /// URI path of DNS queries.
    ///
    /// With `None`, queries are answered on any path except the ODoH configs
    /// path, which is useful behind a reverse proxy that rewrites paths.
    pub path: Option<String>,
    /// Maximum number of connections, TLS handshakes included.
    pub max_clients: usize,
    /// How long a request may take.
    ///
    /// Connection timeouts are based on it too.
    pub timeout: Duration,
    pub max_concurrent_streams: u32,
    /// Maximum size of a DNS query, in bytes.
    pub max_query_len: usize,
    pub keepalive: bool,
    /// Returns a 406 when neither `Content-Type` nor `Accept` names a
    /// supported type.
    ///
    /// When false, these requests are treated as standard DoH queries.
    pub require_accept: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    /// Serves the JSON API (`application/dns-json`).
    pub enable_json: bool,
    /// Lets web pages from any origin read the responses.
    pub cors: bool,
    pub odoh_configs_path: String,
    /// Oblivious DoH keys.
    ///
    /// ODoH is disabled without them.
    pub odoh_rotator: Option<Arc<ODoHRotator>>,
}

impl Default for Globals {
    fn default() -> Globals {
        Globals {
            #[cfg(feature = "tls")]
            tls_cert_path: None,
            #[cfg(feature = "tls")]
            tls_cert_key_path: None,
            listen_address: SocketAddr::from(([127, 0, 0, 1], 3000)),
            path: Some("/dns-query".to_string()),
            max_clients: 512,
            timeout: Duration::from_secs(10),
            max_concurrent_streams: 16,
            max_query_len: MAX_DNS_QUESTION_LEN,
            keepalive: true,
            require_accept: true,
            disable_post: false,
            allow_odoh_post: false,
            enable_json: true,
            cors: true,
            odoh_configs_path: "/.well-known/odohconfigs".to_string(),
            odoh_rotator: None,
        }
    }
}

impl Globals {
    /// Checks the timeout, the connection limit and the query size limit.
    ///
    /// The server calls this before accepting connections, since the fields
    /// are public.
    pub fn validate(&self) -> Result<(), DoHError> {
        let timeout_range =
            Duration::from_secs(MIN_TIMEOUT_SECS)..=Duration::from_secs(MAX_TIMEOUT_SECS);
        if !timeout_range.contains(&self.timeout) {
            return Err(DoHError::InvalidConfig(format!(
                "the timeout must be between {MIN_TIMEOUT_SECS} and {MAX_TIMEOUT_SECS} seconds"
            )));
        }
        if self.max_clients == 0 {
            return Err(DoHError::InvalidConfig(
                "the maximum number of clients must be at least 1".to_string(),
            ));
        }
        let max_query_len_range = MIN_DNS_PACKET_LEN..=u16::MAX as usize;
        if !max_query_len_range.contains(&self.max_query_len) {
            return Err(DoHError::InvalidConfig(format!(
                "the maximum query size must be between {} and {} bytes",
                max_query_len_range.start(),
                max_query_len_range.end()
            )));
        }
        Ok(())
    }
}
