use crate::errors::*;
use crate::{DoH, LocalExecutor};

use hyper::server::conn::Http;
use native_tls::{self, Identity};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use tokio::stream::StreamExt;
pub use tokio_tls::TlsAcceptor;

use tokio::net::TcpListener;

pub fn create_tls_acceptor<P>(path: P, password: &str) -> io::Result<TlsAcceptor>
where
    P: AsRef<Path>,
{
    let identity_bin = {
        let mut fp = File::open(path)?;
        let mut identity_bin = vec![];
        fp.read_to_end(&mut identity_bin)?;
        identity_bin
    };
    let identity = Identity::from_pkcs12(&identity_bin, password).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unusable PKCS12-encoded identity. The encoding and/or the password may be wrong",
        )
    })?;
    let native_acceptor = native_tls::TlsAcceptor::new(identity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unable to use the provided PKCS12-encoded identity",
        )
    })?;
    Ok(TlsAcceptor::from(native_acceptor))
}

impl DoH {
    pub async fn start_with_tls(
        self,
        tls_acceptor: TlsAcceptor,
        mut listener: TcpListener,
        server: Http<LocalExecutor>,
    ) -> Result<(), DoHError> {
        let listener_service = async {
            while let Some(raw_stream) = listener.incoming().next().await {
                let raw_stream = match raw_stream {
                    Ok(raw_stream) => raw_stream,
                    Err(_) => continue,
                };
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
