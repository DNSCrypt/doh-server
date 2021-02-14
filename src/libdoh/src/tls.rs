use crate::errors::*;
use crate::{DoH, LocalExecutor};

use hyper::server::conn::Http;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
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
    pub async fn start_with_tls(
        self,
        tls_acceptor: TlsAcceptor,
        listener: TcpListener,
        server: Http<LocalExecutor>,
    ) -> Result<(), DoHError> {
        let listener_service = async {
            while let Ok((raw_stream, _client_addr)) = listener.accept().await {
                let stream = match tls_acceptor.accept(raw_stream).await {
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
}
