#![allow(dead_code)]

use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use time::OffsetDateTime;

/// Issue a TLS certificate for an arbitrary domain name (not a SPIFFE SVID).
/// Used for public-facing HTTPS endpoints that need certificates for custom domains.
pub fn issue_domain_cert(
    ca_key_pem: &str,
    ca_cert_pem: &str,
    domain: &str,
    additional_sans: &[String],
    ttl: Duration,
) -> Result<DomainCert, rcgen::Error> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, domain);

    // Add SANs
    params
        .subject_alt_names
        .push(SanType::DnsName(domain.try_into()?));
    for san in additional_sans {
        params
            .subject_alt_names
            .push(SanType::DnsName(san.as_str().try_into()?));
    }

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::seconds(ttl.as_secs() as i64);

    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca_cert, &ca_key)?;

    Ok(DomainCert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        domain: domain.to_string(),
    })
}

/// A TLS certificate issued for a domain name.
pub struct DomainCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub domain: String,
}
