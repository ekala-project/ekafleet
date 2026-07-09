use super::*;

async fn initialized_ca() -> RootCa {
    let ca = RootCa::new("test.internal");
    ca.initialize(None, None).await.unwrap();
    ca
}

#[tokio::test]
async fn generate_root_ca_keypair() {
    let ca = initialized_ca().await;

    let cert_pem = ca.root_certificate_pem().await;
    let key_pem = ca.root_key_pem().await;

    assert!(cert_pem.is_some(), "root cert must be generated");
    assert!(key_pem.is_some(), "root key must be generated");

    let cert_pem = cert_pem.unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"), "must be PEM format");

    let key_pem = key_pem.unwrap();
    assert!(cert_pem.len() > 100, "cert must be substantial");
    assert!(key_pem.len() > 100, "key must be substantial");
}

#[tokio::test]
async fn load_existing_ca() {
    let ca1 = initialized_ca().await;
    let key_pem = ca1.root_key_pem().await.unwrap();
    let cert_pem = ca1.root_certificate_pem().await.unwrap();

    // Load from persisted state
    let ca2 = RootCa::new("test.internal");
    ca2.initialize(Some(&key_pem), Some(&cert_pem))
        .await
        .unwrap();

    let cert2 = ca2.root_certificate_pem().await.unwrap();
    assert_eq!(cert_pem, cert2, "loaded CA cert must match original");
}

#[tokio::test]
async fn issue_leaf_certificate() {
    let ca = initialized_ca().await;

    let (leaf_pem, chain_pem, expires_at) = ca
        .issue_certificate("my-service", b"dummy-csr", None)
        .await
        .unwrap();

    let leaf_str = String::from_utf8(leaf_pem).unwrap();
    let chain_str = String::from_utf8(chain_pem).unwrap();

    assert!(
        leaf_str.contains("BEGIN CERTIFICATE"),
        "leaf must contain cert PEM"
    );
    assert!(
        leaf_str.contains("PRIVATE KEY"),
        "leaf must contain key PEM"
    );
    assert!(
        chain_str.contains("BEGIN CERTIFICATE"),
        "chain must contain CA cert"
    );
    assert!(expires_at > 0, "expiry must be set");
}

#[tokio::test]
async fn issued_cert_is_valid_x509() {
    let ca = initialized_ca().await;

    let (leaf_pem, _, _) = ca
        .issue_certificate("test-svc", b"csr", None)
        .await
        .unwrap();

    let leaf_str = String::from_utf8(leaf_pem).unwrap();

    // Extract just the certificate portion
    let cert_start = leaf_str.find("-----BEGIN CERTIFICATE-----").unwrap();
    let cert_end =
        leaf_str.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
    let cert_pem = &leaf_str[cert_start..cert_end];

    // Parse as X.509
    let der = pem_to_der(cert_pem).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

    // Check subject
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(cn, "test-svc");
}

#[tokio::test]
async fn each_cert_has_unique_serial() {
    let ca = initialized_ca().await;

    let (leaf1, _, _) = ca.issue_certificate("svc-a", b"csr", None).await.unwrap();
    let (leaf2, _, _) = ca.issue_certificate("svc-b", b"csr", None).await.unwrap();

    // Extract and parse both certs
    let extract_serial = |pem_bytes: Vec<u8>| {
        let s = String::from_utf8(pem_bytes).unwrap();
        let start = s.find("-----BEGIN CERTIFICATE-----").unwrap();
        let end = s.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
        let der = pem_to_der(&s[start..end]).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        cert.raw_serial().to_vec()
    };

    let serial1 = extract_serial(leaf1);
    let serial2 = extract_serial(leaf2);
    assert_ne!(
        serial1, serial2,
        "each certificate must have a unique serial"
    );
}

#[tokio::test]
async fn uninitialized_ca_rejects_issuance() {
    let ca = RootCa::new("test.internal");
    // Don't initialize

    let result = ca.issue_certificate("svc", b"csr", None).await;
    assert!(matches!(result, Err(CaError::NotInitialized)));
}

#[tokio::test]
async fn attestation_rejects_invalid_store_path() {
    let ca = initialized_ca().await;

    let result = ca.issue_certificate("svc", b"csr", Some("/tmp/evil")).await;
    assert!(matches!(result, Err(CaError::AttestationFailed(_))));

    // Valid nix store path should succeed
    let result = ca
        .issue_certificate("svc", b"csr", Some("/nix/store/abc123-pkg"))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn ttl_is_configurable() {
    let ca = initialized_ca().await;

    ca.set_default_ttl(Duration::from_secs(300)).await;

    let (_, _, expires_at) = ca.issue_certificate("svc", b"csr", None).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Should expire ~300s from now (allow 5s tolerance)
    let diff = expires_at - now;
    assert!(
        (295..=305).contains(&diff),
        "TTL should be ~300s, got {diff}s"
    );
}

#[tokio::test]
async fn sign_csr_produces_valid_cert() {
    let ca = initialized_ca().await;

    // Generate a CSR
    let csr_output = crate::ca::csr::generate_service_csr("test.internal", "csr-svc").unwrap();

    // Sign the CSR
    let (cert_pem, chain_pem, expires_at) = ca
        .sign_csr(&csr_output.csr_der, "csr-svc", None)
        .await
        .unwrap();

    let cert_str = String::from_utf8(cert_pem).unwrap();
    let chain_str = String::from_utf8(chain_pem).unwrap();

    // Cert PEM should NOT contain a private key (private key stays with requester)
    assert!(cert_str.contains("BEGIN CERTIFICATE"), "must contain cert");
    assert!(
        !cert_str.contains("PRIVATE KEY"),
        "must NOT contain private key"
    );
    assert!(chain_str.contains("BEGIN CERTIFICATE"), "chain must exist");
    assert!(expires_at > 0);

    // Parse the certificate and verify it
    let der = pem_to_der(&cert_str).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(cn, "csr-svc");
}

#[tokio::test]
async fn issue_server_svid_has_spiffe_uri() {
    let ca = initialized_ca().await;

    let (cert_pem, _, _) = ca.issue_server_svid("srv-001").await.unwrap();
    let cert_str = String::from_utf8(cert_pem).unwrap();

    // Extract SPIFFE ID from the cert
    let spiffe_id = crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&cert_str);
    assert_eq!(
        spiffe_id.as_deref(),
        Some("spiffe://test.internal/server/srv-001")
    );
}

#[tokio::test]
async fn sign_csr_rejects_invalid_csr() {
    let ca = initialized_ca().await;

    let result = ca.sign_csr(b"not-a-real-csr", "svc", None).await;
    assert!(
        matches!(result, Err(CaError::InvalidCsr(_))),
        "invalid CSR must be rejected"
    );
}
