use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{future::FutureExt, join, select};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use tokio::{
    net::TcpListener,
    sync::mpsc::{self, Receiver},
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

use crate::constants::CERTS_WATCH_DELAY_SECS;
use crate::errors::*;
use crate::{DoH, LocalExecutor};

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

impl DoH {
    async fn start_https_service(
        self,
        mut tls_acceptor_receiver: Receiver<TlsAcceptor>,
        listener: TcpListener,
        server: Arc<HttpBuilder<LocalExecutor>>,
    ) -> Result<(), DoHError> {
        let mut tls_acceptor: Option<TlsAcceptor> = None;
        let listener_service = async {
            loop {
                select! {
                    tcp_cnx = listener.accept().fuse() => {
                        if tls_acceptor.is_none() || tcp_cnx.is_err() {
                            continue;
                        }
                        let (raw_stream, client_addr) = tcp_cnx.unwrap();
                        let tls_acceptor = tls_acceptor.as_ref().unwrap().clone();
                        let mut doh = self.clone();
                        let server = server.clone();
                        self.globals.runtime_handle.clone().spawn(async move {
                            if let Ok(Ok(stream)) = tokio::time::timeout(
                                doh.globals.timeout + Duration::from_secs(1),
                                tls_acceptor.accept(raw_stream),
                            )
                            .await
                            {
                                doh.remote_addr = Some(client_addr);
                                doh.client_serve(stream, server).await
                            }
                        });
                    }
                    new_tls_acceptor = tls_acceptor_receiver.recv().fuse() => {
                        if new_tls_acceptor.is_none() {
                            break;
                        }
                        tls_acceptor = new_tls_acceptor;
                    }
                    complete => break
                }
            }
            Ok(()) as Result<(), DoHError>
        };
        listener_service.await?;
        Ok(())
    }

    pub async fn start_with_tls(
        self,
        listener: TcpListener,
        server: Arc<HttpBuilder<LocalExecutor>>,
    ) -> Result<(), DoHError> {
        let certs_path = self
            .globals
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate path not provided",
                ))
            })?
            .clone();
        let certs_keys_path = self
            .globals
            .tls_cert_key_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate key path not provided",
                ))
            })?
            .clone();
        let (tls_acceptor_sender, tls_acceptor_receiver) = mpsc::channel(1);
        let https_service = self.start_https_service(tls_acceptor_receiver, listener, server);
        let cert_service = async {
            loop {
                match create_tls_acceptor(&certs_path, &certs_keys_path) {
                    Ok(tls_acceptor) => {
                        if tls_acceptor_sender.send(tls_acceptor).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("TLS certificates error: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(CERTS_WATCH_DELAY_SECS.into())).await;
            }
            Ok::<_, DoHError>(())
        };
        join!(https_service, cert_service).0
    }
}
