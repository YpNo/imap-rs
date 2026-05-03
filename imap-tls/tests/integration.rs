use imap_tls::connect_tls;

#[tokio::test]
async fn test_connect_tls_error() {
    // Try to connect to a port that's likely closed
    let result = connect_tls("127.0.0.1", 1).await;
    assert!(result.is_err());
}

// Note: Testing successful TLS connection requires a certificate.
// We'll stick to error path testing for now or use a mock if possible.
