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
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,

    pub runtime_handle: runtime::Handle,
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0 && self.0.compare_and_swap(count, count - 1, Ordering::Relaxed) != count
        } {}
        count
    }
}
