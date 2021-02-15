use crate::errors::*;
use crate::{DoH, LocalExecutor};

use futures::{future::FutureExt, join, select};
use hyper::server::conn::Http;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    net::TcpListener,
    sync::mpsc::{self, Receiver},
};
use tokio_rustls::{
    rustls::{internal::pemfile, NoClientAuth, ServerConfig},
    TlsAcceptor,
};

pub fn create_tls_acceptor<P, P2>(certs_path: P, certs_keys_path: P2) -> io::Result<TlsAcceptor>
where
    P: AsRef<Path>,
    P2: AsRef<Path>,
{
    let certs = {
        let certs_path_str = certs_path.as_ref().display().to_string();
        let mut reader = BufReader::new(File::open(certs_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Unable to load the certificates [{}]: {}",
                    certs_path_str,
                    e.to_string()
                ),
            )
        })?);
        pemfile::certs(&mut reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unable to parse the certificates",
            )
        })?
    };
    let certs_keys = {
        let certs_keys_path_str = certs_keys_path.as_ref().display().to_string();
        let encoded_keys = {
            let mut encoded_keys = vec![];
            File::open(certs_keys_path)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "Unable to load the certificate keys [{}]: {}",
                            certs_keys_path_str,
                            e.to_string()
                        ),
                    )
                })?
                .read_to_end(&mut encoded_keys)?;
            encoded_keys
        };
        let mut reader = Cursor::new(encoded_keys);
        let pkcs8_keys = pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unable to parse the certificates private keys (PKCS8)",
            )
        })?;
        reader.set_position(0);
        let mut rsa_keys = pemfile::rsa_private_keys(&mut reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unable to parse the certificates private keys (RSA)",
            )
        })?;
        let mut keys = pkcs8_keys;
        keys.append(&mut rsa_keys);
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No private keys found",
            ));
        }
        keys
    };
    let mut server_config = ServerConfig::new(NoClientAuth::new());
    server_config.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
    let has_valid_cert_and_key = certs_keys.into_iter().any(|certs_key| {
        server_config
            .set_single_cert(certs.clone(), certs_key)
            .is_ok()
    });
    if !has_valid_cert_and_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid private key for the given certificate",
        ));
    }
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

impl DoH {
    async fn start_https_service(
        self,
        mut tls_acceptor_receiver: Receiver<TlsAcceptor>,
        listener: TcpListener,
        server: Http<LocalExecutor>,
    ) -> Result<(), DoHError> {
        let mut tls_acceptor: Option<TlsAcceptor> = None;
        let listener_service = async {
            loop {
                select! {
                    tcp_cnx = listener.accept().fuse() => {
                        if tls_acceptor.is_none() || tcp_cnx.is_err() {
                            continue;
                        }
                        let (raw_stream, _client_addr) = tcp_cnx.unwrap();
                        if let Ok(stream) = tls_acceptor.as_ref().unwrap().accept(raw_stream).await {
                            self.clone().client_serve(stream, server.clone()).await
                        }
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
        server: Http<LocalExecutor>,
    ) -> Result<(), DoHError> {
        let certs_path = self.globals.tls_cert_path.as_ref().unwrap().clone();
        let certs_keys_path = self.globals.tls_cert_key_path.as_ref().unwrap().clone();
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
                    Err(e) => eprintln!("TLS certificates error: {}", e),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Ok::<_, DoHError>(())
        };
        return join!(https_service, cert_service).0;
    }
}
