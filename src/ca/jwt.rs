//! JWT-SVIDs (SPIFFE JWT-SVID specification), signed with ES256.
//!
//! The signing key is an ECDSA P-256 key held next to the X.509 CA (in-process
//! or in the `ca-signer` daemon) and sealed at rest like the CA keys. Its
//! public half is distributed as a JWKS document — the trust domain's JWT
//! bundle — to agents (for `ValidateJWTSVID` / `FetchJWTBundles`) and to
//! external relying parties via the REST API.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use zeroize::Zeroizing;

/// Lifetime of issued JWT-SVIDs. Short, because a bearer token cannot be
/// revoked; agents cache tokens and refresh them at half-life.
pub const JWT_SVID_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Upper bound on a token we are willing to parse.
const MAX_TOKEN_LEN: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("malformed JWT: {0}")]
    Malformed(String),
    #[error("unsupported JWT algorithm '{0}' (only ES256 is accepted)")]
    UnsupportedAlgorithm(String),
    #[error("no JWT authority with key ID '{0}' in the trust bundle")]
    UnknownKey(String),
    #[error("invalid JWT signature")]
    BadSignature,
    #[error("JWT-SVID has expired")]
    Expired,
    #[error("JWT-SVID audience does not include '{0}'")]
    AudienceMismatch(String),
    #[error("JWT-SVID subject '{0}' is not a SPIFFE ID in trust domain '{1}'")]
    WrongTrustDomain(String, String),
    #[error("invalid JWT bundle: {0}")]
    InvalidBundle(String),
    #[error("JWT key error: {0}")]
    Key(String),
}

/// ES256 signer for JWT-SVIDs.
pub struct JwtSigner {
    keypair: EcdsaKeyPair,
    rng: SystemRandom,
    kid: String,
    x: String,
    y: String,
}

impl JwtSigner {
    /// Generate a new signing key. Returns the signer and its PKCS#8 DER
    /// encoding for (sealed) persistence.
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), JwtError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| JwtError::Key("key generation failed".into()))?;
        let pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());
        Ok((Self::from_pkcs8(&pkcs8)?, pkcs8))
    }

    /// Load a signer from a PKCS#8 DER P-256 key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, JwtError> {
        let rng = SystemRandom::new();
        let keypair =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
                .map_err(|e| JwtError::Key(format!("invalid PKCS#8 P-256 key: {e}")))?;
        // Uncompressed SEC1 point: 0x04 || X || Y.
        let point = keypair.public_key().as_ref();
        if point.len() != 65 || point[0] != 0x04 {
            return Err(JwtError::Key("unexpected public key encoding".into()));
        }
        let x = B64.encode(&point[1..33]);
        let y = B64.encode(&point[33..65]);
        let kid = jwk_thumbprint(&x, &y);
        Ok(Self {
            keypair,
            rng,
            kid,
            x,
            y,
        })
    }

    /// Key ID: the RFC 7638 JWK thumbprint of the public key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The JWT bundle: a JWKS document holding this signer's public key.
    pub fn jwks(&self) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": self.x,
                "y": self.y,
                "kid": self.kid,
                "use": "jwt-svid",
                "alg": "ES256",
            }]
        })
        .to_string()
    }

    /// Sign a JWT-SVID for `spiffe_id` valid for `audience` and `ttl`.
    /// Returns the compact JWS and its expiry (unix seconds).
    pub fn sign(
        &self,
        spiffe_id: &str,
        audience: &[String],
        ttl: std::time::Duration,
    ) -> Result<(String, u64), JwtError> {
        if audience.is_empty() {
            return Err(JwtError::Malformed(
                "at least one audience is required".into(),
            ));
        }
        let now = now_secs();
        let exp = now + ttl.as_secs();
        let header = serde_json::json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"});
        let claims = serde_json::json!({
            "sub": spiffe_id,
            "aud": audience,
            "iat": now,
            "exp": exp,
        });
        let signing_input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .keypair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| JwtError::Key("signing failed".into()))?;
        Ok((format!("{signing_input}.{}", B64.encode(sig.as_ref())), exp))
    }
}

/// RFC 7638 thumbprint of a P-256 JWK (members in lexicographic order).
fn jwk_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        canonical.as_bytes(),
    ))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The verified claims of a JWT-SVID.
#[derive(Debug, Clone)]
pub struct VerifiedJwtSvid {
    /// The subject SPIFFE ID.
    pub spiffe_id: String,
    /// Every claim in the token, as sent.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// Verify a JWT-SVID against a JWKS `bundle` for `trust_domain`, requiring
/// `audience`. Only ES256 with a `kid` naming a key in the bundle is
/// accepted; `exp` is mandatory.
pub fn verify_jwt_svid(
    token: &str,
    bundle: &str,
    trust_domain: &str,
    audience: &str,
) -> Result<VerifiedJwtSvid, JwtError> {
    verify_at(token, bundle, trust_domain, audience, now_secs())
}

fn decode_json(part: &str, what: &str) -> Result<serde_json::Value, JwtError> {
    let bytes = B64
        .decode(part)
        .map_err(|e| JwtError::Malformed(format!("{what} is not base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| JwtError::Malformed(format!("{what}: {e}")))
}

fn verify_at(
    token: &str,
    bundle: &str,
    trust_domain: &str,
    audience: &str,
    now: u64,
) -> Result<VerifiedJwtSvid, JwtError> {
    if audience.is_empty() {
        return Err(JwtError::Malformed("an audience is required".into()));
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(JwtError::Malformed("token too large".into()));
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed(
            "expected three dot-separated parts".into(),
        ));
    };

    let header = decode_json(h, "header")?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ES256" {
        return Err(JwtError::UnsupportedAlgorithm(alg.to_string()));
    }
    if let Some(typ) = header.get("typ")
        && !matches!(typ.as_str(), Some("JWT" | "JOSE"))
    {
        return Err(JwtError::Malformed("unsupported typ".into()));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwtError::Malformed("header has no kid".into()))?;

    let public_key = find_es256_key(bundle, kid)?;
    let sig = B64
        .decode(s)
        .map_err(|e| JwtError::Malformed(format!("signature is not base64url: {e}")))?;
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &public_key)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)?;

    // Only now that the signature is verified are the claims trusted.
    let serde_json::Value::Object(claims) = decode_json(p, "claims")? else {
        return Err(JwtError::Malformed("claims are not a JSON object".into()));
    };
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| JwtError::Malformed("missing exp claim".into()))?;
    if now >= exp {
        return Err(JwtError::Expired);
    }
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(a)) => a == audience,
        Some(serde_json::Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(JwtError::AudienceMismatch(audience.to_string()));
    }
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwtError::Malformed("missing sub claim".into()))?;
    let in_domain = sub
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.strip_prefix(trust_domain))
        .is_some_and(|path| path.starts_with('/') && path.len() > 1);
    if !in_domain {
        return Err(JwtError::WrongTrustDomain(
            sub.to_string(),
            trust_domain.to_string(),
        ));
    }

    Ok(VerifiedJwtSvid {
        spiffe_id: sub.to_string(),
        claims,
    })
}

/// Find the P-256 key `kid` in a JWKS document; returns the uncompressed point.
fn find_es256_key(bundle: &str, kid: &str) -> Result<Vec<u8>, JwtError> {
    let jwks: serde_json::Value =
        serde_json::from_str(bundle).map_err(|e| JwtError::InvalidBundle(e.to_string()))?;
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| JwtError::InvalidBundle("no keys array".into()))?;
    let key = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
        .ok_or_else(|| JwtError::UnknownKey(kid.to_string()))?;
    let field = |name: &str| key.get(name).and_then(|v| v.as_str());
    if field("kty") != Some("EC") || field("crv") != Some("P-256") {
        return Err(JwtError::InvalidBundle(format!("key '{kid}' is not P-256")));
    }
    if let Some(usage) = field("use")
        && usage != "jwt-svid"
    {
        return Err(JwtError::InvalidBundle(format!(
            "key '{kid}' is not a JWT-SVID authority"
        )));
    }
    let coord = |name: &str| -> Result<Vec<u8>, JwtError> {
        let c = B64
            .decode(field(name).unwrap_or_default())
            .map_err(|e| JwtError::InvalidBundle(format!("{name}: {e}")))?;
        if c.len() != 32 {
            return Err(JwtError::InvalidBundle(format!("{name} has wrong length")));
        }
        Ok(c)
    };
    let mut point = vec![0x04];
    point.extend(coord("x")?);
    point.extend(coord("y")?);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TD: &str = "fleet.internal";
    const SUB: &str = "spiffe://fleet.internal/service/web";

    fn aud(a: &str) -> Vec<String> {
        vec![a.to_string()]
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let (token, exp) = signer.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        assert!(exp > now_secs());
        let v = verify_jwt_svid(&token, &signer.jwks(), TD, "db").unwrap();
        assert_eq!(v.spiffe_id, SUB);
        assert_eq!(v.claims["exp"].as_u64(), Some(exp));
    }

    #[test]
    fn reloaded_key_keeps_kid_and_verifies() {
        let (signer, pkcs8) = JwtSigner::generate().unwrap();
        let reloaded = JwtSigner::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(signer.kid(), reloaded.kid());
        let (token, _) = reloaded.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        verify_jwt_svid(&token, &signer.jwks(), TD, "db").unwrap();
    }

    #[test]
    fn rejects_wrong_audience_and_trust_domain() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let (token, _) = signer.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        assert!(matches!(
            verify_jwt_svid(&token, &signer.jwks(), TD, "other"),
            Err(JwtError::AudienceMismatch(_))
        ));
        assert!(matches!(
            verify_jwt_svid(&token, &signer.jwks(), "other.internal", "db"),
            Err(JwtError::WrongTrustDomain(..))
        ));
        // A trust domain that is a prefix of the real one must not match.
        assert!(matches!(
            verify_jwt_svid(&token, &signer.jwks(), "fleet", "db"),
            Err(JwtError::WrongTrustDomain(..))
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let (token, exp) = signer.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        assert!(matches!(
            verify_at(&token, &signer.jwks(), TD, "db", exp),
            Err(JwtError::Expired)
        ));
    }

    #[test]
    fn rejects_token_from_another_signer() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let (other, _) = JwtSigner::generate().unwrap();
        let (token, _) = other.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        assert!(matches!(
            verify_jwt_svid(&token, &signer.jwks(), TD, "db"),
            Err(JwtError::UnknownKey(_))
        ));
    }

    #[test]
    fn rejects_tampered_claims() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let (token, _) = signer.sign(SUB, &aud("db"), JWT_SVID_TTL).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let forged_claims = B64.encode(
            serde_json::json!({
                "sub": "spiffe://fleet.internal/service/admin",
                "aud": ["db"],
                "exp": now_secs() + 60,
            })
            .to_string(),
        );
        let forged = format!("{}.{}.{}", parts[0], forged_claims, parts[2]);
        assert!(matches!(
            verify_jwt_svid(&forged, &signer.jwks(), TD, "db"),
            Err(JwtError::BadSignature)
        ));
    }

    #[test]
    fn rejects_alg_none_and_hs256() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let claims = B64.encode(
            serde_json::json!({"sub": SUB, "aud": ["db"], "exp": now_secs() + 60}).to_string(),
        );
        for alg in ["none", "HS256"] {
            let header = B64.encode(
                serde_json::json!({"alg": alg, "kid": signer.kid(), "typ": "JWT"}).to_string(),
            );
            let token = format!("{header}.{claims}.");
            assert!(matches!(
                verify_jwt_svid(&token, &signer.jwks(), TD, "db"),
                Err(JwtError::UnsupportedAlgorithm(_))
            ));
        }
    }

    #[test]
    fn jwks_is_a_spiffe_jwt_bundle() {
        let (signer, _) = JwtSigner::generate().unwrap();
        let jwks: serde_json::Value = serde_json::from_str(&signer.jwks()).unwrap();
        let key = &jwks["keys"][0];
        assert_eq!(key["use"], "jwt-svid");
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["kid"], signer.kid());
        // No private material in the bundle.
        assert!(key.get("d").is_none());
    }
}
