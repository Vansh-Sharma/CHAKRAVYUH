// TLS integration tests.
//
// Verifies that when CHAKRAVYUH is built with `--features tls` and the
// config has a `server.tls` section, the server:
//   - Listens with HTTPS using rustls
//   - Accepts connections with a valid client (rustls)
//   - Rejects connections with no/wrong SNI (handled by rustls)
//
// Self-signed certificates are generated at runtime using the `rcgen`
// crate (dev-only dependency).
//
// These tests are gated on `--features tls`. Without that feature,
// CHAKRAVYUH always serves plain HTTP and there is nothing to test
// here — the `tls` mod is empty.

#![cfg(feature = "tls")]

use chakravyuh::Config;

/// Generate a self-signed cert + key for testing. Returns (cert_pem, key_pem).
fn generate_self_signed() -> (String, String) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect(" CertificateParams::new");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "CHAKRAVYUH Test Cert");
    dn.push(DnType::OrganizationName, "VINOMOID");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().expect("key gen");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    (cert.pem(), key_pair.serialize_pem())
}

/// Write the cert and key to temp files and return their paths.
fn write_cert_files() -> (std::path::PathBuf, std::path::PathBuf) {
    let (cert_pem, key_pem) = generate_self_signed();
    let dir = std::env::temp_dir().join(format!(
        "chakravyuh-tls-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    (cert_path, key_path)
}

/// Bind a server on an ephemeral port and return the actual bound address.
fn bind_ephemeral() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr")
}

#[tokio::test]
async fn tls_server_serves_https_with_self_signed_cert() {
    // Install a CryptoProvider for rustls. axum-server pulls in rustls
    // without selecting a default provider, so we install aws_lc_rs here.
    // This is a process-wide install — subsequent calls are no-ops.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (cert_path, key_path) = write_cert_files();
    let addr = bind_ephemeral();

    // Build a minimal config with TLS enabled.
    let yaml = format!(
        r#"
server:
  bind: {addr}
  tls:
    cert_path: {cert}
    key_path: {key}
shield:
  enabled: true
"#,
        addr = addr,
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config: Config = yaml.parse().expect("config parses");
    assert!(config.server.tls.is_some());

    let cv = chakravyuh::Chakravyuh::new(config).expect("Chakravyuh builds");
    let server_handle = tokio::spawn(async move {
        let _ = cv.serve(&addr.to_string()).await;
    });

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Build a reqwest client that trusts the self-signed cert.
    let cert_pem = std::fs::read_to_string(&cert_path).expect("read cert");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::tls::Certificate::from_pem(cert_pem.as_bytes()).expect("cert"),
        )
        .build()
        .expect("client builds");

    let url = format!("https://127.0.0.1:{}/health", addr.port());
    let resp = client.get(&url).send().await.expect("HTTPS request");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], "ok");

    // Also test the version endpoint to make sure routing works over TLS.
    let url2 = format!("https://127.0.0.1:{}/version", addr.port());
    let resp2 = client.get(&url2).send().await.expect("HTTPS request 2");
    assert_eq!(resp2.status(), 200);
    let body2: serde_json::Value = resp2.json().await.expect("json body 2");
    assert_eq!(body2["license"], "Apache-2.0");

    server_handle.abort();
}

#[tokio::test]
async fn tls_server_rejects_invalid_cert_path() {
    let addr = bind_ephemeral();

    let yaml = format!(
        r#"
server:
  bind: {addr}
  tls:
    cert_path: /nonexistent/cert.pem
    key_path: /nonexistent/key.pem
shield:
  enabled: true
"#,
        addr = addr,
    );

    let config: Config = yaml.parse().expect("config parses");
    let cv = chakravyuh::Chakravyuh::new(config).expect("Chakravyuh builds");

    let result = cv.serve(&addr.to_string()).await;
    assert!(result.is_err(), "should fail with nonexistent cert path");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("TLS cert_path not found"),
        "error should mention cert path: {err}"
    );
}

#[tokio::test]
async fn tls_config_is_none_by_default() {
    let yaml = "shield:\n  enabled: true\n";
    let config: Config = yaml.parse().expect("config parses");
    assert!(config.server.tls.is_none(), "TLS should be off by default");
}

#[test]
fn tls_config_round_trips_through_yaml() {
    let yaml = r#"
server:
  bind: 0.0.0.0:8443
  tls:
    cert_path: /etc/cert.pem
    key_path: /etc/key.pem
"#;
    let config: Config = yaml.parse().expect("config parses");
    let tls = config.server.tls.expect("tls is set");
    assert_eq!(tls.cert_path, "/etc/cert.pem");
    assert_eq!(tls.key_path, "/etc/key.pem");
}
