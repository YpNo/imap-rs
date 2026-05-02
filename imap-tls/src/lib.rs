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

    // Create the TCP stream
    let tcp_stream = TcpStream::connect(&addr).await?;

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

    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Pass the TLS stream to the RawClient
    let mut raw = RawClient::new(tls_stream);

    // Auto-fetch capabilities
    let cap_resp = raw.execute_command("CAPABILITY").await?;
    let cap_str = String::from_utf8_lossy(&cap_resp);
    let capabilities = Capabilities::parse(&cap_str);

    // Return a session enforcing TLS-only methods (like login)
    Ok(Session::<Unauthenticated, Tls>::new(raw, capabilities))
}
