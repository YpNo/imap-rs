//! TLS adapter for `imap-rs`.
//!
//! Two entry points:
//!
//! - [`connect_tls`] — direct TLS (port 993). The connector validates the
//!   server cert against the Mozilla CA root set (`webpki-roots`).
//! - [`connect_starttls`] — port 143 cleartext, then upgrade to TLS via the
//!   `STARTTLS` capability (RFC 3501 §6.2.1). Capabilities are re-fetched
//!   inside the encrypted channel — pre-TLS server-asserted capabilities
//!   are NEVER trusted.
//!
//! Both entry points enforce a TCP-connect timeout and a TLS-handshake
//! timeout to prevent slowloris-style hangs. Defaults are 30 s; override
//! via the `_with_timeouts` variants.
//!
//! For tests against an in-process TLS endpoint, use
//! [`handshake_with_connector`] with a custom [`TlsConnector`].

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use imap_client::{Capabilities, ClientError, RawClient, Session, Tls, Unauthenticated};
use imap_core::error::ParseError;
use imap_core::parser::parse_response;

/// Default deadline for the TCP connect step.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default deadline for the TLS handshake step.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default deadline for any single pre-TLS request/response (greeting,
/// `CAPABILITY`, `STARTTLS`).
pub const DEFAULT_PRE_TLS_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Connect over TCP and immediately perform a TLS handshake (port 993).
pub async fn connect_tls(
    domain: &str,
    port: u16,
) -> Result<Session<Unauthenticated, Tls>, ClientError> {
    connect_tls_with_timeouts(
        domain,
        port,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Like [`connect_tls`] but with caller-chosen timeouts.
pub async fn connect_tls_with_timeouts(
    domain: &str,
    port: u16,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<Session<Unauthenticated, Tls>, ClientError> {
    let tcp = connect_tcp(domain, port, connect_timeout).await?;
    let connector = default_tls_connector()?;
    handshake_with_connector(connector, domain, tcp, handshake_timeout).await
}

/// Connect to an IMAP server in cleartext (port 143), advertise STARTTLS,
/// upgrade the same TCP stream to TLS, and only then begin trusting the
/// server's capabilities.
pub async fn connect_starttls(
    domain: &str,
    port: u16,
) -> Result<Session<Unauthenticated, Tls>, ClientError> {
    connect_starttls_with_timeouts(
        domain,
        port,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_HANDSHAKE_TIMEOUT,
        DEFAULT_PRE_TLS_TIMEOUT,
    )
    .await
}

/// Like [`connect_starttls`] but with caller-chosen timeouts.
pub async fn connect_starttls_with_timeouts(
    domain: &str,
    port: u16,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    pre_tls_timeout: Duration,
) -> Result<Session<Unauthenticated, Tls>, ClientError> {
    let tcp = connect_tcp(domain, port, connect_timeout).await?;
    let connector = default_tls_connector()?;
    starttls_with_connector(connector, domain, tcp, handshake_timeout, pre_tls_timeout).await
}

/// Build a [`TlsConnector`] using the Mozilla web PKI root certificates.
pub fn default_tls_connector() -> Result<TlsConnector, ClientError> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ClientError::CommandFailed(format!("TLS config failed: {e}")))?
    .with_root_certificates(root_store)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Perform a TLS handshake on `stream` and wrap the resulting TLS stream
/// in a [`Session`]. Re-fetches `CAPABILITY` so the returned session
/// reflects the post-handshake server state.
///
/// This is the building block used by [`connect_tls`] and is also useful
/// for tests that bring their own `TcpStream` and `TlsConnector`.
pub async fn handshake_with_connector<S>(
    connector: TlsConnector,
    domain: &str,
    stream: S,
    handshake_timeout: Duration,
) -> Result<Session<Unauthenticated, Tls>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_name = ServerName::try_from(domain)
        .map_err(|_| ClientError::CommandFailed("Invalid domain for TLS".into()))?
        .to_owned();
    let tls_stream =
        tokio::time::timeout(handshake_timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| ClientError::Timeout)??;
    finalize_session_after_handshake(tls_stream).await
}

/// Drive the cleartext STARTTLS handshake on `stream`, perform the TLS
/// handshake, then return a [`Session`] whose capabilities have been
/// re-fetched in the encrypted channel.
pub async fn starttls_with_connector<S>(
    connector: TlsConnector,
    domain: &str,
    mut stream: S,
    handshake_timeout: Duration,
    pre_tls_timeout: Duration,
) -> Result<Session<Unauthenticated, Tls>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    drive_starttls_exchange(&mut stream, pre_tls_timeout).await?;
    handshake_with_connector(connector, domain, stream, handshake_timeout).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn connect_tcp(domain: &str, port: u16, timeout: Duration) -> Result<TcpStream, ClientError> {
    let addr = format!("{}:{}", domain, port);
    tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::Io)
}

async fn finalize_session_after_handshake<S>(
    tls_stream: S,
) -> Result<Session<Unauthenticated, Tls>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Wrap in the dispatcher and let it consume the greeting frame plus
    // any pre-tagged CAPABILITY untagged response.
    let mut raw = RawClient::new(tls_stream);
    let mut events = raw.events();

    // Some servers send `* OK [CAPABILITY …]` as their greeting; absorb
    // it here so callers don't have to read events themselves.
    let mut capabilities = Capabilities::default();
    let mut got_greeting_caps = false;
    let _ = tokio::time::timeout(Duration::from_millis(250), events.recv())
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|frame| {
            if let Ok((_, response)) = parse_response(&frame) {
                got_greeting_caps = capabilities.try_update_from(&response);
            }
        });

    if !got_greeting_caps {
        let cap_resp = raw.execute_command("CAPABILITY").await?;
        if let Ok((_, response)) = parse_response(&cap_resp) {
            capabilities.try_update_from(&response);
        }
        // The `* CAPABILITY …` data line was broadcast — drain it to
        // pick up the actual capability list.
        while let Ok(event) = events.try_recv() {
            if let Ok((_, response)) = parse_response(&event)
                && capabilities.try_update_from(&response)
            {
                break;
            }
        }
    }

    Ok(Session::new(raw, capabilities))
}

/// Read the initial greeting, run a `CAPABILITY` round-trip, verify the
/// server advertised STARTTLS, then issue `STARTTLS` and await its tagged
/// `OK`. The stream is now ready for a TLS handshake.
async fn drive_starttls_exchange<S>(
    stream: &mut S,
    pre_tls_timeout: Duration,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(4096);

    // 1. Greeting (`* OK …` or `* PREAUTH …` or `* BYE …`).
    let _greeting = read_one_frame(stream, &mut buf, pre_tls_timeout).await?;

    // 2. CAPABILITY round-trip.
    write_all_with_timeout(stream, b"T0001 CAPABILITY\r\n", pre_tls_timeout).await?;

    let mut caps = Capabilities::default();
    loop {
        let frame = read_one_frame(stream, &mut buf, pre_tls_timeout).await?;
        if let Ok((_, response)) = parse_response(&frame) {
            match &response {
                imap_core::ast::Response::Status(s) if s.tag == Some("T0001") => {
                    if !matches!(s.status, imap_core::ast::Status::Ok) {
                        return Err(ClientError::CommandFailed(format!(
                            "CAPABILITY failed: {}",
                            s.text
                        )));
                    }
                    break;
                }
                _ => {
                    caps.try_update_from(&response);
                }
            }
        }
    }

    if !caps.starttls {
        return Err(ClientError::CommandFailed(
            "server does not advertise STARTTLS".into(),
        ));
    }

    // 3. STARTTLS round-trip.
    write_all_with_timeout(stream, b"T0002 STARTTLS\r\n", pre_tls_timeout).await?;

    loop {
        let frame = read_one_frame(stream, &mut buf, pre_tls_timeout).await?;
        if let Ok((_, response)) = parse_response(&frame)
            && let imap_core::ast::Response::Status(s) = &response
            && s.tag == Some("T0002")
        {
            if !matches!(s.status, imap_core::ast::Status::Ok) {
                return Err(ClientError::CommandFailed(format!(
                    "STARTTLS rejected: {}",
                    s.text
                )));
            }
            return Ok(());
        }
        // Otherwise: untagged frame, ignore.
    }
}

async fn write_all_with_timeout<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), ClientError> {
    tokio::time::timeout(timeout, stream.write_all(bytes))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::Io)
}

/// Read enough bytes from `stream` (re-using `buf`) to parse one complete
/// IMAP frame, then return that frame's bytes (split out of `buf`).
async fn read_one_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    timeout: Duration,
) -> Result<Vec<u8>, ClientError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Try to parse any frame already buffered.
        if !buf.is_empty() {
            match parse_response(buf) {
                Ok((remaining, _)) => {
                    let consumed = buf.len() - remaining.len();
                    return Ok(buf.split_to(consumed).to_vec());
                }
                Err(ParseError::Incomplete) => {}
                Err(_) => {
                    return Err(ClientError::CommandFailed(
                        "malformed pre-TLS response".into(),
                    ));
                }
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(ClientError::Timeout);
        }
        let n = tokio::time::timeout(deadline - now, stream.read_buf(buf))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Io)?;
        if n == 0 {
            return Err(ClientError::ConnectionClosed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_connect_tls_invalid_domain() {
        let (client_io, _server_io) = duplex(1024);
        let connector = default_tls_connector().unwrap();
        let r = handshake_with_connector(
            connector,
            "invalid domain",
            client_io,
            DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_connect_tls_handshake_failure() {
        let (client_io, server_io) = duplex(1024);
        drop(server_io);
        let connector = default_tls_connector().unwrap();
        let r = handshake_with_connector(connector, "localhost", client_io, Duration::from_secs(2))
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_connect_tcp_timeout() {
        // RFC 5737 reserved blackhole IP — the connect should hang and we
        // expect the timeout to fire.
        let r = connect_tcp("192.0.2.1", 993, Duration::from_millis(100)).await;
        assert!(matches!(
            r,
            Err(ClientError::Timeout) | Err(ClientError::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_starttls_drive_happy_path() {
        let (mut client_io, mut server_io) = duplex(4096);

        let server_task = tokio::spawn(async move {
            // Greeting
            server_io
                .write_all(b"* OK IMAP service ready\r\n")
                .await
                .unwrap();
            // Read CAPABILITY
            let mut buf = [0u8; 1024];
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("CAPABILITY"));
            server_io
                .write_all(b"* CAPABILITY IMAP4rev2 STARTTLS\r\nT0001 OK done\r\n")
                .await
                .unwrap();
            // Read STARTTLS
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("STARTTLS"));
            server_io
                .write_all(b"T0002 OK begin TLS\r\n")
                .await
                .unwrap();
        });

        drive_starttls_exchange(&mut client_io, Duration::from_secs(5))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_starttls_drive_rejects_no_starttls() {
        let (mut client_io, mut server_io) = duplex(4096);

        let server_task = tokio::spawn(async move {
            server_io.write_all(b"* OK ready\r\n").await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = server_io.read(&mut buf).await.unwrap();
            server_io
                .write_all(b"* CAPABILITY IMAP4rev2\r\nT0001 OK done\r\n")
                .await
                .unwrap();
        });

        let r = drive_starttls_exchange(&mut client_io, Duration::from_secs(5)).await;
        assert!(matches!(r, Err(ClientError::CommandFailed(_))));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_starttls_drive_rejects_starttls_no() {
        let (mut client_io, mut server_io) = duplex(4096);

        let server_task = tokio::spawn(async move {
            server_io.write_all(b"* OK ready\r\n").await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = server_io.read(&mut buf).await.unwrap();
            server_io
                .write_all(b"* CAPABILITY IMAP4rev2 STARTTLS\r\nT0001 OK done\r\n")
                .await
                .unwrap();
            let _ = server_io.read(&mut buf).await.unwrap();
            server_io.write_all(b"T0002 NO not now\r\n").await.unwrap();
        });

        let r = drive_starttls_exchange(&mut client_io, Duration::from_secs(5)).await;
        assert!(matches!(r, Err(ClientError::CommandFailed(_))));
        server_task.await.unwrap();
    }
}
