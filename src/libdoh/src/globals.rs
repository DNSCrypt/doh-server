use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime;

use crate::errors::DoHError;
use crate::odoh::ODoHRotator;

pub const MIN_TIMEOUT_SECS: u64 = 1;
pub const MAX_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    pub listen_address: SocketAddr,
    pub local_bind_address: SocketAddr,
    pub server_address: SocketAddr,
    pub path: String,
    pub max_clients: usize,
    pub timeout: Duration,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub enable_ecs: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,

    pub runtime_handle: runtime::Handle,
}

impl Globals {
    /// Checks the settings that connection and request deadlines are derived from.
    ///
    /// `DoH::entrypoint()` calls this before binding the listener, because the
    /// fields are public and can be set without going through the command line.
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
        Ok(())
    }
}
