use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use imap_client::ClientError;
use imap_client::{Capabilities, RawClient, Session, Tls, Unauthenticated};

/// Connects to the given IMAP server over TLS using rustls exclusively.
pub async fn connect_tls(
    domain: &str,
    port: u16,
) -> Result<Session<Unauthenticated, Tls>, ClientError> {
    let addr = format!("{}:{}", domain, port);
    let tcp_stream = TcpStream::connect(&addr).await?;
    connect_with_stream(domain, tcp_stream).await
}

pub(crate) async fn connect_with_stream<S>(
    domain: &str,
    stream: S,
) -> Result<Session<Unauthenticated, Tls>, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Set up rustls with standard web PKI roots
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(domain)
        .map_err(|_| ClientError::CommandFailed("Invalid domain for TLS".into()))?
        .to_owned();

    let tls_stream = connector.connect(server_name, stream).await?;

    let mut raw = RawClient::new(tls_stream);
    let cap_resp = raw.execute_command("CAPABILITY").await?;
    let cap_str = String::from_utf8_lossy(&cap_resp);
    let capabilities = Capabilities::parse(&cap_str);

    Ok(Session::<Unauthenticated, Tls>::new(raw, capabilities))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_connect_with_stream_handshake_failure() {
        let (client_io, server_io) = duplex(1024);
        drop(server_io); // Close the server side immediately to force handshake failure
        let result = connect_with_stream("localhost", client_io).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_with_stream_invalid_domain() {
        let (client_io, _server_io) = duplex(1024);
        let result = connect_with_stream("invalid domain", client_io).await;
        assert!(result.is_err());
    }
}
