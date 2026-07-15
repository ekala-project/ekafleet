//! Identity-bound signing and verification of WireGuard peer advertisements.
//!
//! Peer public keys are distributed through the fleet control plane. Without a
//! signature, a relayed advertisement carries no proof that the advertised
//! WireGuard public key actually belongs to the claimed node — a compromised
//! relay or a spoofed gossip message could substitute an attacker-controlled
//! key. Here each node signs its advertisement with its **SVID private key**
//! and attaches its SVID certificate. A receiver verifies that:
//!
//!   1. the signature is valid for the advertisement bytes under the public key
//!      in the attached certificate, and
//!   2. the certificate's SPIFFE URI-SAN encodes the same `node_id` the
//!      advertisement claims (`spiffe://<domain>/agent/<node_id>`).
//!
//! This binds the WireGuard public key to the node's cryptographic identity,
//! so a leaked or substituted key cannot be presented as another node's peer.
//! Certificate-chain trust (chaining to the fleet trust bundle) is enforced by
//! the mTLS control channel that transports the advertisement; this module
//! adds the key↔identity binding on top of that.

use ring::signature;

use crate::proto::WireguardPeer;

#[derive(Debug, thiserror::Error)]
pub enum AdvertError {
    #[error("advertisement is missing a signature")]
    MissingSignature,
    #[error("advertisement is missing a signing certificate")]
    MissingCert,
    #[error("signing certificate is malformed: {0}")]
    MalformedCert(String),
    #[error("signing certificate has no SPIFFE URI-SAN")]
    NoSpiffeId,
    #[error("certificate identity {cert_id} does not match advertised node {node_id}")]
    IdentityMismatch { cert_id: String, node_id: String },
    #[error("signature verification failed")]
    BadSignature,
    #[error("signing key is invalid: {0}")]
    InvalidSigningKey(String),
}

/// Canonical byte encoding of the advertisement fields that are signed.
///
/// Length-prefixed fields avoid ambiguity (so `("ab", "c")` and `("a", "bc")`
/// do not collide). Only the identity-relevant fields are covered.
fn canonical_bytes(node_id: &str, public_key: &str, endpoint: &str, allowed_ip: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for field in [node_id, public_key, endpoint, allowed_ip] {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
        buf.extend_from_slice(field.as_bytes());
    }
    buf
}

/// Sign an advertisement with a PKCS#8-encoded ECDSA P-256 SVID private key
/// (as produced by `rcgen`). Returns the ASN.1/DER signature bytes.
pub fn sign_advert(
    node_id: &str,
    public_key: &str,
    endpoint: &str,
    allowed_ip: &str,
    svid_key_pkcs8_der: &[u8],
) -> Result<Vec<u8>, AdvertError> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        svid_key_pkcs8_der,
        &rng,
    )
    .map_err(|e| AdvertError::InvalidSigningKey(e.to_string()))?;

    let msg = canonical_bytes(node_id, public_key, endpoint, allowed_ip);
    let sig = key_pair
        .sign(&rng, &msg)
        .map_err(|e| AdvertError::InvalidSigningKey(e.to_string()))?;
    Ok(sig.as_ref().to_vec())
}

/// Verify a received peer advertisement is identity-bound.
///
/// `expected_domain` is the trust domain; the certificate's SPIFFE ID must be
/// `spiffe://<expected_domain>/agent/<peer.node_id>`.
pub fn verify_advert(peer: &WireguardPeer, expected_domain: &str) -> Result<(), AdvertError> {
    if peer.signature.is_empty() {
        return Err(AdvertError::MissingSignature);
    }
    if peer.signing_cert_pem.is_empty() {
        return Err(AdvertError::MissingCert);
    }

    // Extract the SPIFFE ID from the certificate and check it matches the node.
    let cert_id =
        crate::proxy::mtls::SpiffeAuthorizer::extract_spiffe_id_from_pem(&peer.signing_cert_pem)
            .ok_or(AdvertError::NoSpiffeId)?;
    let expected_id = format!("spiffe://{expected_domain}/agent/{}", peer.node_id);
    if cert_id != expected_id {
        return Err(AdvertError::IdentityMismatch {
            cert_id,
            node_id: peer.node_id.clone(),
        });
    }

    // Pull the SubjectPublicKeyInfo out of the certificate and verify.
    let spki_der = cert_spki_der(&peer.signing_cert_pem)?;
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, spki_der);
    let msg = canonical_bytes(
        &peer.node_id,
        &peer.public_key,
        &peer.endpoint,
        &peer.allowed_ip,
    );
    public_key
        .verify(&msg, &peer.signature)
        .map_err(|_| AdvertError::BadSignature)
}

/// Extract the raw SubjectPublicKeyInfo DER bytes from a PEM certificate.
///
/// `ring` accepts an ECDSA P-256 public key as the `subjectPublicKey` BIT
/// STRING contents (the uncompressed point, 0x04 || X || Y), which x509_parser
/// exposes via `subject_pki.subject_public_key.data`.
fn cert_spki_der(cert_pem: &str) -> Result<Vec<u8>, AdvertError> {
    let cert_start = cert_pem
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| AdvertError::MalformedCert("no certificate block".into()))?;
    let end_marker = "-----END CERTIFICATE-----";
    let cert_end = cert_pem
        .find(end_marker)
        .ok_or_else(|| AdvertError::MalformedCert("no certificate end marker".into()))?
        + end_marker.len();
    let pem_block = &cert_pem[cert_start..cert_end];

    let mut reader = std::io::BufReader::new(pem_block.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AdvertError::MalformedCert(e.to_string()))?;
    let der = certs
        .first()
        .ok_or_else(|| AdvertError::MalformedCert("empty certificate block".into()))?;

    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| AdvertError::MalformedCert(e.to_string()))?;
    Ok(cert.public_key().subject_public_key.data.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a self-consistent SVID cert + PKCS#8 key for `node_id` using rcgen.
    fn make_svid(domain: &str, node_id: &str) -> (String, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        let spiffe_id = format!("spiffe://{domain}/agent/{node_id}");
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(spiffe_id.try_into().unwrap()));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_der = key_pair.serialize_der();
        (cert_pem, key_der)
    }

    fn signed_peer(domain: &str, node_id: &str) -> WireguardPeer {
        let (cert_pem, key_der) = make_svid(domain, node_id);
        let public_key = "wg-pubkey-base64";
        let endpoint = "10.0.0.5:51820";
        let allowed_ip = "10.100.0.5/32";
        let sig = sign_advert(node_id, public_key, endpoint, allowed_ip, &key_der).unwrap();
        WireguardPeer {
            node_id: node_id.to_string(),
            public_key: public_key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ip: allowed_ip.to_string(),
            signature: sig,
            signing_cert_pem: cert_pem,
        }
    }

    #[test]
    fn valid_signed_advert_verifies() {
        let peer = signed_peer("fleet.internal", "node-1");
        assert!(verify_advert(&peer, "fleet.internal").is_ok());
    }

    #[test]
    fn unsigned_advert_rejected() {
        let mut peer = signed_peer("fleet.internal", "node-1");
        peer.signature.clear();
        assert!(matches!(
            verify_advert(&peer, "fleet.internal"),
            Err(AdvertError::MissingSignature)
        ));
    }

    #[test]
    fn tampered_public_key_rejected() {
        let mut peer = signed_peer("fleet.internal", "node-1");
        // Attacker swaps in their own WireGuard key while keeping the signature.
        peer.public_key = "attacker-wg-pubkey".to_string();
        assert!(matches!(
            verify_advert(&peer, "fleet.internal"),
            Err(AdvertError::BadSignature)
        ));
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let mut peer = signed_peer("fleet.internal", "node-1");
        peer.endpoint = "6.6.6.6:51820".to_string();
        assert!(matches!(
            verify_advert(&peer, "fleet.internal"),
            Err(AdvertError::BadSignature)
        ));
    }

    #[test]
    fn node_id_mismatch_rejected() {
        // Cert says node-1 but the advertisement claims node-2.
        let mut peer = signed_peer("fleet.internal", "node-1");
        peer.node_id = "node-2".to_string();
        assert!(matches!(
            verify_advert(&peer, "fleet.internal"),
            Err(AdvertError::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn wrong_domain_rejected() {
        let peer = signed_peer("fleet.internal", "node-1");
        assert!(matches!(
            verify_advert(&peer, "other.domain"),
            Err(AdvertError::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn foreign_cert_cannot_impersonate() {
        // A valid, well-formed cert for node-evil signs an advertisement that
        // *claims* node-1. Identity binding must reject it.
        let (evil_cert, evil_key) = make_svid("fleet.internal", "node-evil");
        let public_key = "wg-pubkey";
        let endpoint = "10.0.0.9:51820";
        let allowed_ip = "10.100.0.9/32";
        // Sign with node-1 in the message so the signature itself is valid for
        // the claimed fields, but present the evil cert.
        let sig = sign_advert("node-1", public_key, endpoint, allowed_ip, &evil_key).unwrap();
        let peer = WireguardPeer {
            node_id: "node-1".to_string(),
            public_key: public_key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ip: allowed_ip.to_string(),
            signature: sig,
            signing_cert_pem: evil_cert,
        };
        assert!(matches!(
            verify_advert(&peer, "fleet.internal"),
            Err(AdvertError::IdentityMismatch { .. })
        ));
    }
}
