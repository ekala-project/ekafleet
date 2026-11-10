//! Identity-bound signing and verification of WireGuard peer advertisements.
//!
//! Each agent advertises its WireGuard public key, endpoint and mesh address
//! to the server over its mTLS control stream, and the server relays the set
//! of adverts to every agent. Without a signature, the server (or anything
//! that can inject into the relay) could substitute a WireGuard key and
//! intercept a node's mesh traffic. So each advert is signed with the
//! advertising node's **SVID private key**, and the SVID chain is attached.
//!
//! [`AdvertVerifier::verify`] accepts an advert only if:
//!
//!   1. its fields are well formed: a valid node ID, a 32-byte base64
//!      WireGuard key, a `host:port` endpoint and a single `/32` mesh address;
//!   2. the attached certificate chains to the fleet CA, is within its
//!      validity period and is valid for client authentication (the same
//!      check the server applies to agent mTLS connections);
//!   3. the leaf's SPIFFE ID is `spiffe://<domain>/agent/<node_id>` for the
//!      advertised `node_id`; and
//!   4. the ECDSA P-256 signature from the leaf key covers the canonical
//!      advert bytes, including `issued_at`.
//!
//! Freshness and rollback (`issued_at` must increase per node) and uniqueness
//! of keys and addresses across nodes are checked by the stateful holders of
//! adverts: `server::peers::PeerRegistry` and [`super::peers::PeerManager`].

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ring::signature;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

use crate::proto::WireguardPeer;

/// Domain separation: these bytes prefix every signed advert so an SVID
/// signature made for another purpose can never be replayed as an advert.
const ADVERT_CONTEXT: &[u8] = b"ekafleet-wireguard-advert-v1";

#[derive(Debug, thiserror::Error)]
pub enum AdvertError {
    #[error("advertisement is missing a signature")]
    MissingSignature,
    #[error("advertisement is missing a signing certificate")]
    MissingCert,
    #[error("advertisement field is invalid: {0}")]
    InvalidField(String),
    #[error("signing certificate is malformed: {0}")]
    MalformedCert(String),
    #[error("signing certificate is not trusted: {0}")]
    UntrustedCert(String),
    #[error("signing certificate has no SPIFFE URI-SAN")]
    NoSpiffeId,
    #[error("certificate identity {cert_id} does not match advertised node {node_id}")]
    IdentityMismatch { cert_id: String, node_id: String },
    #[error("signature verification failed")]
    BadSignature,
    #[error("signing key is invalid: {0}")]
    InvalidSigningKey(String),
    #[error("trust bundle is invalid: {0}")]
    InvalidTrustBundle(String),
}

/// Canonical byte encoding of the signed advert fields.
///
/// Length-prefixed fields avoid ambiguity (so `("ab", "c")` and `("a", "bc")`
/// do not collide).
fn canonical_bytes(peer: &WireguardPeer) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(ADVERT_CONTEXT);
    for field in [
        &peer.node_id,
        &peer.public_key,
        &peer.endpoint,
        &peer.allowed_ip,
    ] {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
        buf.extend_from_slice(field.as_bytes());
    }
    buf.extend_from_slice(&peer.issued_at.to_be_bytes());
    buf
}

/// Sign `peer` in place with the node's SVID.
///
/// `svid_chain_pem` is the SVID leaf followed by its intermediates (attached
/// as `signing_cert_pem`); `svid_key_pkcs8_der` is its PKCS#8 ECDSA P-256 key.
pub fn sign_advert(
    peer: &mut WireguardPeer,
    svid_chain_pem: &str,
    svid_key_pkcs8_der: &[u8],
) -> Result<(), AdvertError> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        svid_key_pkcs8_der,
        &rng,
    )
    .map_err(|e| AdvertError::InvalidSigningKey(e.to_string()))?;
    peer.signing_cert_pem = svid_chain_pem.to_string();
    let sig = key_pair
        .sign(&rng, &canonical_bytes(peer))
        .map_err(|e| AdvertError::InvalidSigningKey(e.to_string()))?;
    peer.signature = sig.as_ref().to_vec();
    Ok(())
}

/// Decode the PKCS#8 DER of a PEM private key (as written for node SVIDs).
pub fn pkcs8_der_from_pem(key_pem: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, AdvertError> {
    let mut reader = std::io::BufReader::new(key_pem.as_bytes());
    match rustls_pemfile::private_key(&mut reader) {
        Ok(Some(rustls::pki_types::PrivateKeyDer::Pkcs8(der))) => {
            Ok(zeroize::Zeroizing::new(der.secret_pkcs8_der().to_vec()))
        }
        Ok(_) => Err(AdvertError::InvalidSigningKey(
            "expected a PKCS#8 private key".into(),
        )),
        Err(e) => Err(AdvertError::InvalidSigningKey(e.to_string())),
    }
}

/// Parse an advert's `allowed_ip`, which must be exactly one `/32` address.
pub fn advert_mesh_ip(allowed_ip: &str) -> Option<Ipv4Addr> {
    let (ip, prefix) = allowed_ip.split_once('/')?;
    (prefix == "32").then(|| ip.parse().ok()).flatten()
}

/// A WireGuard public key is 32 bytes, i.e. 43 base64 characters plus `=`.
fn is_wireguard_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && key[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn validate_fields(peer: &WireguardPeer) -> Result<(), AdvertError> {
    crate::attestation::join_token::validate_node_id(&peer.node_id)
        .map_err(|e| AdvertError::InvalidField(e.to_string()))?;
    if !is_wireguard_key(&peer.public_key) {
        return Err(AdvertError::InvalidField(
            "public_key is not a WireGuard key".into(),
        ));
    }
    if peer.endpoint.parse::<SocketAddr>().is_err() {
        return Err(AdvertError::InvalidField(format!(
            "endpoint '{}' is not ip:port",
            peer.endpoint
        )));
    }
    if advert_mesh_ip(&peer.allowed_ip).is_none() {
        // Anything wider than /32 would let one node claim routes for others
        // (or 0.0.0.0/0 for all traffic) on every receiving peer.
        return Err(AdvertError::InvalidField(format!(
            "allowed_ip '{}' is not a single /32 address",
            peer.allowed_ip
        )));
    }
    Ok(())
}

/// Verifies adverts against the fleet trust bundle and trust domain.
#[derive(Clone)]
pub struct AdvertVerifier {
    trust_domain: String,
    verifier: Arc<dyn ClientCertVerifier>,
}

impl std::fmt::Debug for AdvertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdvertVerifier")
            .field("trust_domain", &self.trust_domain)
            .finish_non_exhaustive()
    }
}

impl AdvertVerifier {
    /// Trust the CA certificates in `trust_bundle_pem` for `trust_domain`.
    pub fn new(trust_bundle_pem: &str, trust_domain: &str) -> Result<Self, AdvertError> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in parse_certs(trust_bundle_pem).map_err(AdvertError::InvalidTrustBundle)? {
            roots
                .add(cert)
                .map_err(|e| AdvertError::InvalidTrustBundle(e.to_string()))?;
        }
        if roots.is_empty() {
            return Err(AdvertError::InvalidTrustBundle("no certificates".into()));
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| AdvertError::InvalidTrustBundle(e.to_string()))?;
        Ok(Self {
            trust_domain: trust_domain.to_string(),
            verifier,
        })
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Verify `peer` at the current time. See the module docs for the checks.
    pub fn verify(&self, peer: &WireguardPeer) -> Result<(), AdvertError> {
        self.verify_at(peer, UnixTime::now())
    }

    fn verify_at(&self, peer: &WireguardPeer, now: UnixTime) -> Result<(), AdvertError> {
        if peer.signature.is_empty() {
            return Err(AdvertError::MissingSignature);
        }
        if peer.signing_cert_pem.is_empty() {
            return Err(AdvertError::MissingCert);
        }
        validate_fields(peer)?;

        let certs = parse_certs(&peer.signing_cert_pem).map_err(AdvertError::MalformedCert)?;
        let (leaf, intermediates) = certs
            .split_first()
            .ok_or_else(|| AdvertError::MalformedCert("no certificate".into()))?;
        self.verifier
            .verify_client_cert(leaf, intermediates, now)
            .map_err(|e| AdvertError::UntrustedCert(e.to_string()))?;

        let (_, cert) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|e| AdvertError::MalformedCert(e.to_string()))?;
        let cert_id = spiffe_id(&cert).ok_or(AdvertError::NoSpiffeId)?;
        let expected_id = format!("spiffe://{}/agent/{}", self.trust_domain, peer.node_id);
        if cert_id != expected_id {
            return Err(AdvertError::IdentityMismatch {
                cert_id,
                node_id: peer.node_id.clone(),
            });
        }

        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            cert.public_key().subject_public_key.data.as_ref(),
        );
        public_key
            .verify(&canonical_bytes(peer), &peer.signature)
            .map_err(|_| AdvertError::BadSignature)
    }
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// The single SPIFFE URI SAN of a certificate.
fn spiffe_id(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    let san = cert.subject_alternative_name().ok()??;
    let mut ids = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::URI(uri) if uri.starts_with("spiffe://") => {
                Some(uri.to_string())
            }
            _ => None,
        });
    let id = ids.next()?;
    // An SVID has exactly one SPIFFE ID.
    ids.next().is_none().then_some(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const WG_KEY_A: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    pub(crate) const WG_KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    /// A fleet CA (root signs leaf directly) that can issue node SVIDs.
    pub(crate) struct TestCa {
        pub(crate) pem: String,
        key: rcgen::KeyPair,
        cert: rcgen::Certificate,
    }

    impl TestCa {
        pub(crate) fn new() -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            let cert = params.self_signed(&key).unwrap();
            Self {
                pem: cert.pem(),
                key,
                cert,
            }
        }

        /// Issue an SVID with the given SPIFFE ID; returns (cert PEM, PKCS#8 DER).
        pub(crate) fn issue(&self, spiffe_id: &str) -> (String, Vec<u8>) {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
            params
                .subject_alt_names
                .push(rcgen::SanType::URI(spiffe_id.try_into().unwrap()));
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
            (cert.pem(), key.serialize_der())
        }

        pub(crate) fn verifier(&self) -> AdvertVerifier {
            AdvertVerifier::new(&self.pem, "fleet.internal").unwrap()
        }
    }

    pub(crate) fn unsigned_peer(node_id: &str, key: &str, ip: &str) -> WireguardPeer {
        WireguardPeer {
            node_id: node_id.to_string(),
            public_key: key.to_string(),
            endpoint: "192.0.2.5:51820".to_string(),
            allowed_ip: format!("{ip}/32"),
            issued_at: 1_000,
            ..Default::default()
        }
    }

    /// An advert for `node_id` signed by its own SVID from `ca`.
    pub(crate) fn signed_peer(ca: &TestCa, node_id: &str, key: &str, ip: &str) -> WireguardPeer {
        let (cert, key_der) = ca.issue(&format!("spiffe://fleet.internal/agent/{node_id}"));
        let mut peer = unsigned_peer(node_id, key, ip);
        sign_advert(&mut peer, &cert, &key_der).unwrap();
        peer
    }

    #[test]
    fn valid_signed_advert_verifies() {
        let ca = TestCa::new();
        let peer = signed_peer(&ca, "node-1", WG_KEY_A, "10.100.0.1");
        ca.verifier().verify(&peer).unwrap();
    }

    #[test]
    fn unsigned_advert_rejected() {
        let ca = TestCa::new();
        let peer = unsigned_peer("node-1", WG_KEY_A, "10.100.0.1");
        assert!(matches!(
            ca.verifier().verify(&peer),
            Err(AdvertError::MissingSignature)
        ));
        let mut no_cert = signed_peer(&ca, "node-1", WG_KEY_A, "10.100.0.1");
        no_cert.signing_cert_pem.clear();
        assert!(matches!(
            ca.verifier().verify(&no_cert),
            Err(AdvertError::MissingCert)
        ));
    }

    #[test]
    fn every_signed_field_is_covered() {
        let ca = TestCa::new();
        let peer = signed_peer(&ca, "node-1", WG_KEY_A, "10.100.0.1");
        let tampers: [fn(&mut WireguardPeer); 4] = [
            |p| p.public_key = WG_KEY_B.into(),
            |p| p.endpoint = "203.0.113.6:51820".into(),
            |p| p.allowed_ip = "10.100.0.9/32".into(),
            |p| p.issued_at += 1,
        ];
        for tamper in tampers {
            let mut p = peer.clone();
            tamper(&mut p);
            assert!(matches!(
                ca.verifier().verify(&p),
                Err(AdvertError::BadSignature)
            ));
        }
        let mut sig = peer.clone();
        let last = sig.signature.len() - 1;
        sig.signature[last] ^= 1;
        assert!(ca.verifier().verify(&sig).is_err());
    }

    #[test]
    fn self_signed_cert_with_right_spiffe_id_rejected() {
        // Correct SPIFFE ID and a valid signature, but not issued by the fleet CA.
        let ca = TestCa::new();
        let rogue = TestCa::new();
        let peer = signed_peer(&rogue, "node-1", WG_KEY_A, "10.100.0.1");
        assert!(matches!(
            ca.verifier().verify(&peer),
            Err(AdvertError::UntrustedCert(_))
        ));
    }

    #[test]
    fn another_nodes_svid_cannot_sign_for_node() {
        // node-evil holds a genuine SVID and signs an advert claiming node-1.
        let ca = TestCa::new();
        let (evil_cert, evil_key) = ca.issue("spiffe://fleet.internal/agent/node-evil");
        let mut peer = unsigned_peer("node-1", WG_KEY_A, "10.100.0.1");
        sign_advert(&mut peer, &evil_cert, &evil_key).unwrap();
        assert!(matches!(
            ca.verifier().verify(&peer),
            Err(AdvertError::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn non_agent_svids_and_other_domains_rejected() {
        let ca = TestCa::new();
        for id in [
            "spiffe://fleet.internal/server/node-1",
            "spiffe://other.domain/agent/node-1",
        ] {
            let (cert, key) = ca.issue(id);
            let mut peer = unsigned_peer("node-1", WG_KEY_A, "10.100.0.1");
            sign_advert(&mut peer, &cert, &key).unwrap();
            assert!(matches!(
                ca.verifier().verify(&peer),
                Err(AdvertError::IdentityMismatch { .. })
            ));
        }
    }

    #[test]
    fn expired_cert_rejected() {
        let ca = TestCa::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://fleet.internal/agent/node-1".try_into().unwrap(),
        ));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
        let mut peer = unsigned_peer("node-1", WG_KEY_A, "10.100.0.1");
        sign_advert(&mut peer, &cert.pem(), &key.serialize_der()).unwrap();
        assert!(matches!(
            ca.verifier().verify(&peer),
            Err(AdvertError::UntrustedCert(_))
        ));
    }

    #[test]
    fn malformed_fields_rejected_before_crypto() {
        let ca = TestCa::new();
        let bad: [fn(&mut WireguardPeer); 6] = [
            |p| p.allowed_ip = "10.100.0.0/16".into(),
            |p| p.allowed_ip = "0.0.0.0/0".into(),
            |p| p.allowed_ip = "10.100.0.1".into(),
            |p| p.public_key = "not-a-key".into(),
            |p| p.endpoint = "example.com".into(),
            |p| p.node_id = "../x".into(),
        ];
        for mutate in bad {
            let mut peer = unsigned_peer("node-1", WG_KEY_A, "10.100.0.1");
            mutate(&mut peer);
            let (cert, key) = ca.issue(&format!("spiffe://fleet.internal/agent/{}", peer.node_id));
            sign_advert(&mut peer, &cert, &key).unwrap();
            assert!(matches!(
                ca.verifier().verify(&peer),
                Err(AdvertError::InvalidField(_))
            ));
        }
    }

    #[test]
    fn key_pem_roundtrip() {
        let key = rcgen::KeyPair::generate().unwrap();
        let der = pkcs8_der_from_pem(&key.serialize_pem()).unwrap();
        assert_eq!(der.as_slice(), key.serialize_der().as_slice());
        assert!(pkcs8_der_from_pem("garbage").is_err());
    }
}
