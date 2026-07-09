use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType,
};

use super::root::CaError;

/// Result of generating a CSR: the DER-encoded CSR and the keypair
/// that the caller must retain (the private key never leaves this process).
pub struct CsrOutput {
    /// PKCS#10 CSR in DER encoding, to be sent to the CA for signing.
    pub csr_der: Vec<u8>,
    /// The keypair generated for this CSR. The caller must store this
    /// and use it alongside the signed certificate returned by the CA.
    pub keypair: KeyPair,
}

/// Generate a PKCS#10 Certificate Signing Request for a service workload SVID.
///
/// The CSR includes a SPIFFE URI SAN (`spiffe://<trust_domain>/service/<service_name>`)
/// and requests both ServerAuth and ClientAuth extended key usage for mTLS.
///
/// The generated keypair stays local — only the CSR (containing the public key)
/// is sent to the CA. This follows the SPIFFE principle that private keys never
/// leave the workload.
pub fn generate_service_csr(trust_domain: &str, service_name: &str) -> Result<CsrOutput, CaError> {
    let keypair = KeyPair::generate()
        .map_err(|e| CaError::KeyGeneration(format!("CSR keypair generation: {e}")))?;

    let spiffe_uri = format!("spiffe://{trust_domain}/service/{service_name}");

    let mut params = CertificateParams::new(vec![service_name.to_string()])
        .map_err(|e| CaError::KeyGeneration(format!("CSR params: {e}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, service_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ekafleet");
    params.subject_alt_names.push(SanType::URI(
        spiffe_uri
            .try_into()
            .map_err(|e| CaError::KeyGeneration(format!("invalid SPIFFE URI: {e}")))?,
    ));
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);

    let csr = params
        .serialize_request(&keypair)
        .map_err(|e| CaError::KeyGeneration(format!("CSR serialization: {e}")))?;

    Ok(CsrOutput {
        csr_der: csr.der().to_vec(),
        keypair,
    })
}

/// Generate a PKCS#10 Certificate Signing Request for a node SVID.
///
/// The node SVID uses SPIFFE URI `spiffe://<trust_domain>/agent/<node_id>`.
pub fn generate_node_csr(trust_domain: &str, node_id: &str) -> Result<CsrOutput, CaError> {
    let keypair = KeyPair::generate()
        .map_err(|e| CaError::KeyGeneration(format!("node CSR keypair generation: {e}")))?;

    let spiffe_uri = format!("spiffe://{trust_domain}/agent/{node_id}");

    let mut params = CertificateParams::new(vec![])
        .map_err(|e| CaError::KeyGeneration(format!("node CSR params: {e}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("agent-{node_id}"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ekafleet");
    params.subject_alt_names.push(SanType::URI(
        spiffe_uri
            .try_into()
            .map_err(|e| CaError::KeyGeneration(format!("invalid SPIFFE URI: {e}")))?,
    ));
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);

    let csr = params
        .serialize_request(&keypair)
        .map_err(|e| CaError::KeyGeneration(format!("node CSR serialization: {e}")))?;

    Ok(CsrOutput {
        csr_der: csr.der().to_vec(),
        keypair,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_service_csr_produces_valid_der() {
        let output = generate_service_csr("test.internal", "my-service").unwrap();

        // CSR should be non-empty DER starting with ASN.1 SEQUENCE tag
        assert!(!output.csr_der.is_empty());
        assert_eq!(output.csr_der[0], 0x30, "CSR DER must start with SEQUENCE");

        // Keypair should serialize to PEM
        let pem = output.keypair.serialize_pem();
        assert!(pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn generate_node_csr_produces_valid_der() {
        let output = generate_node_csr("test.internal", "node-abc-123").unwrap();

        assert!(!output.csr_der.is_empty());
        assert_eq!(output.csr_der[0], 0x30);
    }

    #[test]
    fn csr_can_be_parsed_by_x509_parser() {
        let output = generate_service_csr("test.internal", "parseable-svc").unwrap();

        // Verify the CSR can be parsed back
        let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(output.csr_der);
        let params = rcgen::CertificateSigningRequestParams::from_der(&csr_der)
            .expect("CSR should be parseable by rcgen");

        // The parsed params should have our DN
        assert!(
            !params
                .params
                .distinguished_name
                .iter()
                .collect::<Vec<_>>()
                .is_empty()
        );
    }

    #[test]
    fn each_csr_has_unique_keypair() {
        let csr1 = generate_service_csr("test.internal", "svc-a").unwrap();
        let csr2 = generate_service_csr("test.internal", "svc-b").unwrap();

        // Different keypairs
        assert_ne!(
            csr1.keypair.serialize_pem(),
            csr2.keypair.serialize_pem(),
            "each CSR must have a unique keypair"
        );

        // Different CSR DER (different keys + different names)
        assert_ne!(csr1.csr_der, csr2.csr_der);
    }
}
