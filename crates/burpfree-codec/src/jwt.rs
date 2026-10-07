//! JWT split + base64url decode / HMAC resign.
//!
//! `jwt_decode()` splits a three-part token and parses the header +
//! payload as JSON. It intentionally does not verify the signature —
//! that's the analyst's job via the Decoder / JWT editor tools.
//!
//! `jwt_sign()` is the matching write path: given a header JSON, a
//! payload JSON and an HMAC algorithm + secret, it produces the
//! base64url-encoded compact-serialization token (`header.payload.sig`).

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};

use crate::text::{base64url_decode, base64url_encode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtParts {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature_b64: String,
    pub signature_bytes: Vec<u8>,
}

/// Which HMAC algorithm to use when resigning a JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JwtAlg {
    HS256,
    HS384,
    HS512,
    /// Alg `"none"` — writes an empty signature. Useful for the
    /// classic unverified-JWT bypass. The caller is responsible for
    /// setting `header.alg = "none"` to match.
    None,
}

impl JwtAlg {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::None => "none",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "HS256" => Some(Self::HS256),
            "HS384" => Some(Self::HS384),
            "HS512" => Some(Self::HS512),
            "NONE" => Some(Self::None),
            _ => None,
        }
    }
}

pub fn jwt_decode(token: &str) -> Result<JwtParts> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("JWT must have 3 dot-separated parts"));
    }
    let header_bytes = base64url_decode(parts[0])?;
    let payload_bytes = base64url_decode(parts[1])?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| anyhow!("JWT header JSON: {e}"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| anyhow!("JWT payload JSON: {e}"))?;
    let signature_bytes = base64url_decode(parts[2]).unwrap_or_default();
    Ok(JwtParts {
        header,
        payload,
        signature_b64: parts[2].to_string(),
        signature_bytes,
    })
}

/// Serialize a header + payload + HMAC secret into a compact-serialized
/// JWT. The algorithm is derived from `alg` and is also stamped into
/// the header so the output is self-consistent. If the caller passes a
/// header without an `alg` field, we insert one; if it has a conflicting
/// value we overwrite it (loudly stamping the operator's intent).
pub fn jwt_sign(
    mut header: serde_json::Value,
    payload: serde_json::Value,
    secret: &[u8],
    alg: JwtAlg,
) -> Result<String> {
    // Stamp the alg into the header so the output is self-consistent.
    match &mut header {
        serde_json::Value::Object(obj) => {
            obj.insert("alg".into(), serde_json::Value::String(alg.as_label().into()));
            // Many JWT consumers expect `typ: "JWT"` — add it only if
            // the operator hasn't set anything explicit.
            obj.entry("typ")
                .or_insert_with(|| serde_json::Value::String("JWT".into()));
        }
        _ => return Err(anyhow!("JWT header must be a JSON object")),
    }

    let header_json = serde_json::to_string(&header)?;
    let payload_json = serde_json::to_string(&payload)?;
    let h_b64 = base64url_encode(header_json.as_bytes());
    let p_b64 = base64url_encode(payload_json.as_bytes());
    let signing_input = format!("{h_b64}.{p_b64}");

    let sig_b64 = match alg {
        JwtAlg::None => String::new(),
        JwtAlg::HS256 => hmac_sign_sha256(secret, signing_input.as_bytes())?,
        JwtAlg::HS384 => hmac_sign_sha384(secret, signing_input.as_bytes())?,
        JwtAlg::HS512 => hmac_sign_sha512(secret, signing_input.as_bytes())?,
    };
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn hmac_sign_sha256(secret: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow!("hmac init: {e}"))?;
    Mac::update(&mut mac, data);
    Ok(base64url_encode(&mac.finalize().into_bytes()))
}

fn hmac_sign_sha384(secret: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow!("hmac init: {e}"))?;
    Mac::update(&mut mac, data);
    Ok(base64url_encode(&mac.finalize().into_bytes()))
}

fn hmac_sign_sha512(secret: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow!("hmac init: {e}"))?;
    Mac::update(&mut mac, data);
    Ok(base64url_encode(&mac.finalize().into_bytes()))
}

/// Verify a HS256/HS384/HS512 JWT. Returns `Ok(true)` if the signature
/// matches, `Ok(false)` if it doesn't, or an error if the token / alg
/// is malformed.
pub fn jwt_verify_hmac(token: &str, secret: &[u8]) -> Result<bool> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("JWT must have 3 dot-separated parts"));
    }
    let header_bytes = base64url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .and_then(JwtAlg::from_label)
        .ok_or_else(|| anyhow!("unsupported or missing alg"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected = match alg {
        JwtAlg::None => String::new(),
        JwtAlg::HS256 => hmac_sign_sha256(secret, signing_input.as_bytes())?,
        JwtAlg::HS384 => hmac_sign_sha384(secret, signing_input.as_bytes())?,
        JwtAlg::HS512 => hmac_sign_sha512(secret, signing_input.as_bytes())?,
    };
    // Constant-time-ish compare on the base64 strings. Both inputs
    // are canonical base64url, so a byte-by-byte comparison is fine
    // as long as the lengths match (both start from the same hash).
    Ok(expected.as_bytes() == parts[2].as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hs256_sample() {
        // Standard HS256 example from jwt.io.
        let t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                 SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let p = jwt_decode(t).unwrap();
        assert_eq!(p.header["alg"], "HS256");
        assert_eq!(p.payload["name"], "John Doe");
        assert!(!p.signature_bytes.is_empty());
    }

    #[test]
    fn errors_on_wrong_shape() {
        assert!(jwt_decode("abc.def").is_err());
    }

    #[test]
    fn sign_hs256_decodes_cleanly_and_verifies() {
        // The exact byte sequence depends on JSON key ordering, so we
        // round-trip through decode + verify instead of pinning the
        // base64url output. The signature test proves the HMAC code is
        // correct across both sides.
        let header = serde_json::json!({ "alg": "HS256", "typ": "JWT" });
        let payload = serde_json::json!({
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1_516_239_022,
        });
        let token = jwt_sign(header, payload, b"your-256-bit-secret", JwtAlg::HS256).unwrap();
        let p = jwt_decode(&token).unwrap();
        assert_eq!(p.header["alg"], "HS256");
        assert_eq!(p.header["typ"], "JWT");
        assert_eq!(p.payload["sub"], "1234567890");
        assert_eq!(p.payload["name"], "John Doe");
        assert_eq!(p.payload["iat"], 1_516_239_022);
        assert!(jwt_verify_hmac(&token, b"your-256-bit-secret").unwrap());
    }

    #[test]
    fn sign_round_trips_through_decode() {
        let header = serde_json::json!({ "alg": "HS256" });
        let payload = serde_json::json!({ "role": "admin" });
        let t = jwt_sign(header, payload.clone(), b"topsecret", JwtAlg::HS256).unwrap();
        let p = jwt_decode(&t).unwrap();
        assert_eq!(p.header["alg"], "HS256");
        assert_eq!(p.payload["role"], "admin");
    }

    #[test]
    fn sign_none_alg_leaves_signature_empty() {
        let t = jwt_sign(
            serde_json::json!({ "alg": "none" }),
            serde_json::json!({ "x": 1 }),
            b"",
            JwtAlg::None,
        )
        .unwrap();
        assert!(t.ends_with('.'), "token must end with trailing dot for empty sig: {t}");
    }

    #[test]
    fn sign_overwrites_alg_header() {
        // Operator passes an HS256 header but asks us to re-sign with HS512;
        // the output header must reflect the actual alg so the token is
        // self-consistent.
        let header = serde_json::json!({ "alg": "HS256", "custom": "x" });
        let payload = serde_json::json!({ "iss": "test" });
        let t = jwt_sign(header, payload, b"k", JwtAlg::HS512).unwrap();
        let p = jwt_decode(&t).unwrap();
        assert_eq!(p.header["alg"], "HS512");
        assert_eq!(p.header["custom"], "x");
    }

    #[test]
    fn verify_hs256_matches_known_secret() {
        let header = serde_json::json!({ "alg": "HS256" });
        let payload = serde_json::json!({ "iss": "test" });
        let t = jwt_sign(header, payload, b"k", JwtAlg::HS256).unwrap();
        assert!(jwt_verify_hmac(&t, b"k").unwrap());
        assert!(!jwt_verify_hmac(&t, b"wrong-secret").unwrap());
    }
}
