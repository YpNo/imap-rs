//! End-to-end TLS tests using `rcgen` to generate a self-signed cert and
//! `tokio_rustls::TlsAcceptor` to terminate TLS in-process. These prove
//! that the dispatcher, parser, and TLS adapter actually agree.

use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use imap_tls::{
    DEFAULT_HANDSHAKE_TIMEOUT, connect_tls, handshake_with_connector, starttls_with_connector,
};

#[tokio::test]
async fn test_connect_tls_to_closed_port() {
    // 127.0.0.1:1 should be closed; expect connect or handshake error.
    let result = connect_tls("127.0.0.1", 1).await;
    assert!(result.is_err());
}

struct TestPki {
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_root_store: RootCertStore,
}

fn build_test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();
    TestPki {
        server_cert_chain: vec![cert_der],
        server_key: key_der,
        client_root_store: roots,
    }
}

fn server_acceptor(pki: &TestPki) -> TlsAcceptor {
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS config failed: {e}"))
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(pki.server_cert_chain.clone(), pki.server_key.clone_key())
    .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

fn client_connector(pki: &TestPki) -> TlsConnector {
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS config failed")
    .with_root_certificates(pki.client_root_store.clone())
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn test_handshake_and_capability_round_trip() {
    let pki = build_test_pki();
    let acceptor = server_acceptor(&pki);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        // Greeting first.
        tls.write_all(b"* OK IMAP service ready\r\n").await.unwrap();
        // Read CAPABILITY (or whatever first command).
        let mut buf = [0u8; 1024];
        let n = tls.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("CAPABILITY"));
        let tag = cmd.split_whitespace().next().unwrap().to_owned();
        tls.write_all(
            format!(
                "* CAPABILITY IMAP4rev2 IDLE STARTTLS UNSELECT\r\n{} OK done\r\n",
                tag
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let session = handshake_with_connector(
        client_connector(&pki),
        "localhost",
        tcp,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await
    .unwrap();

    assert!(session.capabilities.imap4rev2);
    assert!(session.capabilities.idle);
    assert!(session.capabilities.unselect);

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_handshake_with_greeting_capability_code() {
    // Server greets with `* OK [CAPABILITY ...]` so the session SHOULD NOT
    // need to issue an explicit CAPABILITY round-trip.
    let pki = build_test_pki();
    let acceptor = server_acceptor(&pki);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        tls.write_all(b"* OK [CAPABILITY IMAP4rev2 IDLE] hello\r\n")
            .await
            .unwrap();
        // The client must NOT send any further command. Wait briefly to
        // confirm nothing is read.
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await;
        // Either the client closed us out (Ok with 0/Err) or the timeout
        // fired (no command sent). Both are fine; what's NOT fine is
        // reading a CAPABILITY string.
        if let Ok(Ok(n)) = r {
            assert!(
                n == 0 || !String::from_utf8_lossy(&buf[..n]).contains("CAPABILITY"),
                "client issued an unnecessary CAPABILITY round-trip"
            );
        }
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let session = handshake_with_connector(
        client_connector(&pki),
        "localhost",
        tcp,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await
    .unwrap();

    assert!(session.capabilities.imap4rev2);
    assert!(session.capabilities.idle);
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_starttls_full_upgrade_path() {
    let pki = build_test_pki();
    let acceptor = server_acceptor(&pki);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        // Cleartext greeting.
        tcp.write_all(b"* OK ready\r\n").await.unwrap();
        // CAPABILITY.
        let mut buf = [0u8; 1024];
        let n = tcp.read(&mut buf).await.unwrap();
        let cap_tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        tcp.write_all(
            format!("* CAPABILITY IMAP4rev2 STARTTLS\r\n{} OK done\r\n", cap_tag).as_bytes(),
        )
        .await
        .unwrap();
        // STARTTLS.
        let n = tcp.read(&mut buf).await.unwrap();
        let st_tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        tcp.write_all(format!("{} OK begin TLS\r\n", st_tag).as_bytes())
            .await
            .unwrap();
        // Now upgrade to TLS server-side.
        let mut tls = acceptor.accept(tcp).await.unwrap();
        // Encrypted greeting? RFC 3501 doesn't require one; jump straight
        // to handling the post-TLS CAPABILITY.
        let n = tls.read(&mut buf).await.unwrap();
        let post_tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        tls.write_all(
            format!("* CAPABILITY IMAP4rev2 IDLE\r\n{} OK done\r\n", post_tag).as_bytes(),
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let session = starttls_with_connector(
        client_connector(&pki),
        "localhost",
        tcp,
        DEFAULT_HANDSHAKE_TIMEOUT,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    // Crucially, the post-TLS capabilities (IMAP4REV2 + IDLE) replace any
    // pre-TLS server-asserted set (which had STARTTLS but no IDLE).
    assert!(session.capabilities.imap4rev2);
    assert!(session.capabilities.idle);
    server_task.await.unwrap();
}
