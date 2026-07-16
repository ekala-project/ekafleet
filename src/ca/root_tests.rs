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

/// Extract the first PEM certificate block from a bundle.
fn first_cert_block(pem: &str) -> String {
    let start = pem.find("-----BEGIN CERTIFICATE-----").unwrap();
    let end = pem.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
    pem[start..end].to_string()
}

/// Parse a single-cert PEM into an x509 issuer/subject CN pair.
fn issuer_subject_cn(cert_pem: &str) -> (String, String) {
    let der = pem_to_der(cert_pem).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .map(|a| a.as_str().unwrap().to_string())
        .unwrap_or_default();
    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .map(|a| a.as_str().unwrap().to_string())
        .unwrap_or_default();
    (issuer, subject)
}

#[tokio::test]
async fn intermediate_is_distinct_from_root() {
    let ca = initialized_ca().await;

    let root = ca.root_certificate_pem().await.unwrap();
    let intermediate = ca.intermediate_certificate_pem().await.unwrap();

    assert!(intermediate.contains("BEGIN CERTIFICATE"));
    assert_ne!(root, intermediate, "intermediate must differ from root");

    let (root_issuer, root_subject) = issuer_subject_cn(&root);
    assert_eq!(root_issuer, root_subject, "root must be self-signed");

    let (int_issuer, int_subject) = issuer_subject_cn(&intermediate);
    assert_eq!(
        int_issuer, root_subject,
        "intermediate must be issued by the root"
    );
    assert_ne!(
        int_subject, root_subject,
        "intermediate subject must differ from root"
    );
}

#[tokio::test]
async fn leaf_is_signed_by_intermediate_and_chain_contains_both() {
    let ca = initialized_ca().await;

    let (leaf_pem, chain_pem, _) = ca
        .issue_certificate("chain-svc", b"csr", None)
        .await
        .unwrap();
    let leaf_str = String::from_utf8(leaf_pem).unwrap();
    let chain_str = String::from_utf8(chain_pem).unwrap();

    // The chain must carry two certificates: intermediate then root.
    let cert_count = chain_str.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(cert_count, 2, "chain must contain intermediate + root");

    // The leaf's issuer must be the intermediate, not the root.
    let leaf_cert = first_cert_block(&leaf_str);
    let (leaf_issuer, _) = issuer_subject_cn(&leaf_cert);
    let intermediate = ca.intermediate_certificate_pem().await.unwrap();
    let (_, int_subject) = issuer_subject_cn(&intermediate);
    assert_eq!(
        leaf_issuer, int_subject,
        "leaf must be issued by the intermediate CA"
    );
}

#[tokio::test]
async fn server_svid_bundle_includes_intermediate() {
    let ca = initialized_ca().await;

    let (cert_pem, chain_pem, _) = ca.issue_server_svid("srv-chain").await.unwrap();
    let cert_str = String::from_utf8(cert_pem).unwrap();
    let chain_str = String::from_utf8(chain_pem).unwrap();

    // The identity bundle sent on the wire must carry leaf + intermediate.
    let leaf_and_int = cert_str.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(
        leaf_and_int, 2,
        "server SVID bundle must include leaf + intermediate"
    );
    assert!(
        cert_str.contains("PRIVATE KEY"),
        "bundle must carry the key"
    );

    let chain_count = chain_str.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(chain_count, 2, "chain must contain intermediate + root");
}

#[tokio::test]
async fn expired_intermediate_is_reminted_on_load() {
    let ca1 = initialized_ca().await;
    let root_key = ca1.root_key_pem().await.unwrap();
    let root_cert = ca1.root_certificate_pem().await.unwrap();
    let int_cert = ca1.intermediate_certificate_pem().await.unwrap();

    // Reload with the root but a bogus/empty intermediate: a fresh intermediate
    // must be minted rather than failing.
    let ca2 = RootCa::new("test.internal");
    ca2.initialize_with_intermediate(
        Some(&root_key),
        Some(&root_cert),
        None,
        Some("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"),
    )
    .await
    .unwrap();

    let int_cert2 = ca2.intermediate_certificate_pem().await.unwrap();
    assert!(int_cert2.contains("BEGIN CERTIFICATE"));
    assert_ne!(
        int_cert, int_cert2,
        "a fresh intermediate must be minted when the stored one is unusable"
    );
}

#[tokio::test]
async fn rotate_intermediate_replaces_current() {
    let ca = initialized_ca().await;
    let before = ca.intermediate_certificate_pem().await.unwrap();

    let (rotated_cert, rotated_key) = ca.rotate_intermediate().await.unwrap();
    assert!(rotated_key.contains("PRIVATE KEY"));
    assert_ne!(before, rotated_cert, "rotation must produce a new cert");

    let after = ca.intermediate_certificate_pem().await.unwrap();
    assert_eq!(after, rotated_cert, "rotated cert must be the active one");
}
