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

/// The certificates in PEM `reader`, in order (other sections skipped).
pub fn pem_certs<R: std::io::BufRead + ?Sized>(
    reader: &mut R,
) -> impl Iterator<Item = std::io::Result<rustls_pki_types::CertificateDer<'static>>> + use<R> {
    use rustls_pki_types::pem::PemObject;
    let mut pem = Vec::new();
    let read = reader.read_to_end(&mut pem);
    let certs: Vec<_> = match read {
        Ok(_) => rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
            .map(|c| c.map_err(std::io::Error::other))
            .collect(),
        Err(e) => vec![Err(e)],
    };
    certs.into_iter()
}

/// The first private key in PEM `reader`, if it holds one.
pub fn pem_private_key<R: std::io::BufRead + ?Sized>(
    reader: &mut R,
) -> std::io::Result<Option<rustls_pki_types::PrivateKeyDer<'static>>> {
    use rustls_pki_types::pem::{self, PemObject};
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    reader.read_to_end(&mut buf)?;
    match rustls_pki_types::PrivateKeyDer::from_pem_slice(&buf) {
        Ok(key) => Ok(Some(key)),
        Err(pem::Error::NoItemsFound) => Ok(None),
        Err(e) => Err(std::io::Error::other(e)),
    }
}
