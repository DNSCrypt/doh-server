use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::join;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
    time::Instant,
};
use tokio_rustls::{
    rustls::{
        pki_types::{
            pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
        },
        sign::{CertifiedKey, SingleCertAndKey},
        ServerConfig,
    },
    TlsAcceptor,
};

use crate::accept::Acceptor;
use crate::admission::Slot;
use crate::constants::CERTS_WATCH_DELAY_SECS;
use crate::errors::*;
use crate::{lifecycle, Server};

pub fn create_tls_acceptor<P, P2>(certs_path: P, certs_keys_path: P2) -> io::Result<TlsAcceptor>
where
    P: AsRef<Path>,
    P2: AsRef<Path>,
{
    let certs: Vec<CertificateDer<'static>> = {
        let certs_path_str = certs_path.as_ref().display().to_string();
        let mut reader = BufReader::new(File::open(certs_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Unable to load the certificates [{certs_path_str}]: {e}"),
            )
        })?);
        CertificateDer::pem_reader_iter(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unable to parse the certificates",
                )
            })?
    };
    let certs_keys: Vec<PrivateKeyDer<'static>> = {
        let certs_keys_path_str = certs_keys_path.as_ref().display().to_string();
        let encoded_keys = {
            let mut encoded_keys = vec![];
            File::open(certs_keys_path)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("Unable to load the certificate keys [{certs_keys_path_str}]: {e}"),
                    )
                })?
                .read_to_end(&mut encoded_keys)?;
            encoded_keys
        };
        let pkcs8_keys = PrivatePkcs8KeyDer::pem_slice_iter(&encoded_keys)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unable to parse the certificates private keys (PKCS8)",
                )
            })?;
        let rsa_keys = PrivatePkcs1KeyDer::pem_slice_iter(&encoded_keys)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unable to parse the certificates private keys (RSA)",
                )
            })?;
        let keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys
            .into_iter()
            .map(Into::into)
            .chain(rsa_keys.into_iter().map(Into::into))
            .collect();
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No private keys found - Make sure that they are in PKCS#8/PEM format",
            ));
        }
        keys
    };

    let mut server_config = certs_keys
        .into_iter()
        .find_map(|certs_key| {
            let server_config_builder = ServerConfig::builder().with_no_client_auth();
            let signing_key = server_config_builder
                .crypto_provider()
                .key_provider
                .load_private_key(certs_key)
                .ok()?;
            let certified_key = CertifiedKey::new(certs.clone(), signing_key);
            Some(
                server_config_builder
                    .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))),
            )
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unable to find a valid certificate and key",
            )
        })?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

impl Server {
    /// Connections accepted before the first certificate has been loaded are closed.
    async fn accept_tls_connections(
        self: Arc<Self>,
        listener: TcpListener,
        tls_acceptor_receiver: watch::Receiver<Option<TlsAcceptor>>,
    ) {
        let mut acceptor = Acceptor::default();
        loop {
            let (raw_stream, remote_addr) = acceptor.accept(&listener).await;
            let Some(tls_acceptor) = tls_acceptor_receiver.borrow().clone() else {
                continue;
            };
            let Some(slot) = self.admission.try_admit() else {
                continue;
            };
            self.spawn(Arc::clone(&self).serve_tls_connection(
                tls_acceptor,
                raw_stream,
                remote_addr,
                slot,
            ));
        }
    }

    pub(crate) async fn serve_tls_connection<I>(
        self: Arc<Self>,
        tls_acceptor: TlsAcceptor,
        raw_stream: I,
        remote_addr: SocketAddr,
        slot: Slot,
    ) where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let handshake = tls_acceptor.accept(raw_stream);
        // The handshake keeps its own reference to the configuration.
        // Holding this one too would keep every reloaded configuration in memory
        // until the connections that used it are closed.
        drop(tls_acceptor);
        if let Some(Ok(stream)) = lifecycle::handshake(handshake, &self.policy, &slot).await {
            self.serve_connection(stream, remote_addr, slot, Instant::now())
                .await
        }
    }

    pub(crate) async fn run_with_tls(
        self: Arc<Self>,
        listener: TcpListener,
    ) -> Result<(), DoHError> {
        let globals = &self.doh.globals;
        let certs_path = globals
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate path not provided",
                ))
            })?
            .clone();
        let certs_keys_path = globals
            .tls_cert_key_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate key path not provided",
                ))
            })?
            .clone();
        let (tls_acceptor_sender, tls_acceptor_receiver) = watch::channel(None);
        let https_service =
            Arc::clone(&self).accept_tls_connections(listener, tls_acceptor_receiver);
        let cert_service = async {
            loop {
                match create_tls_acceptor(&certs_path, &certs_keys_path) {
                    Ok(tls_acceptor) => {
                        tls_acceptor_sender.send_replace(Some(tls_acceptor));
                    }
                    Err(e) => eprintln!("TLS certificates error: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(CERTS_WATCH_DELAY_SECS.into())).await;
            }
        };
        join!(https_service, cert_service);
        Ok(())
    }
}
