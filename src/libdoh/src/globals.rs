use crate::odoh::ODoHRotator;
#[cfg(feature = "odoh-proxy")]
use crate::odoh_proxy::ODoHProxy;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;

#[cfg(feature = "tls")]
use std::path::PathBuf;

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
    pub clients_count: ClientsCount,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,

    #[cfg(feature = "odoh-proxy")]
    pub odoh_proxy_path: String,

    #[cfg(feature = "odoh-proxy")]
    pub odoh_proxy: ODoHProxy,

    pub runtime_handle: runtime::Handle,
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0
                && self
                    .0
                    .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
                    != Ok(count)
        } {}
        count
    }
}
