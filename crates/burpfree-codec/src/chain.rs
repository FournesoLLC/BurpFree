//! Decoder-tool transformation chain.
//!
//! A `Transform` is a named step. [`apply_chain`] runs the steps in
//! order against an initial input and returns intermediate results so
//! the UI can show the user every stage.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::compression::{decode_body, DecodeLimit};
use crate::html::{html_decode, html_encode};
use crate::jwt::jwt_decode;
use crate::text::{
    base64_decode, base64_encode, base64url_decode, base64url_encode, hex_decode, hex_encode,
    unicode_escape_decode, unicode_escape_encode, url_decode, url_encode,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum Transform {
    UrlEncode,
    UrlDecode,
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    HexEncode,
    HexDecode,
    HtmlEncode,
    HtmlDecode,
    UnicodeEscapeEncode,
    UnicodeEscapeDecode,
    GzipDecode,
    DeflateDecode,
    BrotliDecode,
    JwtDecode,
    Uppercase,
    Lowercase,
    Reverse,
    /// Hex-encoded hash of the current bytes. The output is always
    /// textual so it can be chained again (e.g. `md5 -> base64_encode`).
    Md5,
    Sha1,
    Sha256,
    Blake3,
    /// Hex-encoded HMAC of the current bytes with the given key.
    /// The key is interpreted as UTF-8 bytes (no automatic base64
    /// decode) so the operator can paste a shared secret verbatim.
    HmacSha1 {
        key: String,
    },
    HmacSha256 {
        key: String,
    },
    HmacSha384 {
        key: String,
    },
    HmacSha512 {
        key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub transform: Transform,
    pub output: String,
    pub binary: bool,
    pub error: Option<String>,
}

pub fn apply_chain(input: &str, chain: &[Transform]) -> Vec<ChainStep> {
    let mut steps = Vec::with_capacity(chain.len());
    let mut current = input.to_string();
    let mut current_bytes = input.as_bytes().to_vec();
    for t in chain {
        let res = apply_one(t, &current, &current_bytes);
        match &res {
            Ok((text, bytes, binary)) => {
                let step = ChainStep {
                    transform: t.clone(),
                    output: text.clone(),
                    binary: *binary,
                    error: None,
                };
                current = text.clone();
                current_bytes = bytes.clone();
                steps.push(step);
            }
            Err(e) => {
                steps.push(ChainStep {
                    transform: t.clone(),
                    output: String::new(),
                    binary: false,
                    error: Some(e.to_string()),
                });
                break;
            }
        }
    }
    steps
}

fn apply_one(t: &Transform, text: &str, bytes: &[u8]) -> Result<(String, Vec<u8>, bool)> {
    match t {
        Transform::UrlEncode => {
            let out = url_encode(text);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::UrlDecode => {
            let out = url_decode(text)?;
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Base64Encode => {
            let out = base64_encode(bytes);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Base64Decode => {
            let out = base64_decode(text)?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            let binary = std::str::from_utf8(&out).is_err();
            Ok((as_text, out, binary))
        }
        Transform::Base64UrlEncode => {
            let out = base64url_encode(bytes);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Base64UrlDecode => {
            let out = base64url_decode(text)?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            let binary = std::str::from_utf8(&out).is_err();
            Ok((as_text, out, binary))
        }
        Transform::HexEncode => {
            let out = hex_encode(bytes);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HexDecode => {
            let out = hex_decode(text)?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            let binary = std::str::from_utf8(&out).is_err();
            Ok((as_text, out, binary))
        }
        Transform::HtmlEncode => {
            let out = html_encode(text);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HtmlDecode => {
            let out = html_decode(text);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::UnicodeEscapeEncode => {
            let out = unicode_escape_encode(text);
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::UnicodeEscapeDecode => {
            let out = unicode_escape_decode(text)?;
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::GzipDecode => {
            let out = decode_body("gzip", bytes, DecodeLimit::default())?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            Ok((as_text, out, true))
        }
        Transform::DeflateDecode => {
            let out = decode_body("deflate", bytes, DecodeLimit::default())?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            Ok((as_text, out, true))
        }
        Transform::BrotliDecode => {
            let out = decode_body("br", bytes, DecodeLimit::default())?;
            let as_text = String::from_utf8(out.clone()).unwrap_or_else(|_| format!("<{} bytes binary>", out.len()));
            Ok((as_text, out, true))
        }
        Transform::JwtDecode => {
            let parts = jwt_decode(text)?;
            let out = serde_json::to_string_pretty(&parts)?;
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Uppercase => {
            let out = text.to_uppercase();
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Lowercase => {
            let out = text.to_lowercase();
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Reverse => {
            let out: String = text.chars().rev().collect();
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Md5 => {
            use md5::{Digest, Md5};
            let out = hex_encode(&Md5::digest(bytes));
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Sha1 => {
            use sha1::{Digest, Sha1};
            let out = hex_encode(&Sha1::digest(bytes));
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Sha256 => {
            use sha2::{Digest, Sha256};
            let out = hex_encode(&Sha256::digest(bytes));
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::Blake3 => {
            let out = hex_encode(blake3::hash(bytes).as_bytes());
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HmacSha1 { key } => {
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow::anyhow!("hmac-sha1 init: {e}"))?;
            Mac::update(&mut mac, bytes);
            let out = hex_encode(&mac.finalize().into_bytes());
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HmacSha256 { key } => {
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow::anyhow!("hmac-sha256 init: {e}"))?;
            Mac::update(&mut mac, bytes);
            let out = hex_encode(&mac.finalize().into_bytes());
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HmacSha384 { key } => {
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<sha2::Sha384> as Mac>::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow::anyhow!("hmac-sha384 init: {e}"))?;
            Mac::update(&mut mac, bytes);
            let out = hex_encode(&mac.finalize().into_bytes());
            Ok((out.clone(), out.into_bytes(), false))
        }
        Transform::HmacSha512 { key } => {
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(key.as_bytes())
                .map_err(|e| anyhow::anyhow!("hmac-sha512 init: {e}"))?;
            Mac::update(&mut mac, bytes);
            let out = hex_encode(&mac.finalize().into_bytes());
            Ok((out.clone(), out.into_bytes(), false))
        }
    }
}

// ---------------------------------------------------------------------------
// Smart decode
// ---------------------------------------------------------------------------

/// Pattern-detect the most likely encoding of `input` and keep peeling
/// layers off until no further progress can be made or `max_depth`
/// steps have been applied. Returns the chain of transforms the
/// detector picked, together with each intermediate step — exactly
/// the shape the Decoder UI already renders.
///
/// Priorities (in order): JWT, URL, Hex, Base64/Base64Url, HTML
/// entities, Unicode escapes. The detector only accepts a layer if
/// the decoded output is "plausibly textual" (printable ASCII with
/// optional whitespace) — this stops it chasing random high-entropy
/// strings forever.
pub fn smart_decode(input: &str, max_depth: usize) -> Vec<ChainStep> {
    let mut steps = Vec::new();
    let mut current = input.trim().to_string();
    let depth = max_depth.max(1).min(16);
    for _ in 0..depth {
        let Some((t, next, binary)) = detect_and_decode(&current) else {
            break;
        };
        if next == current {
            break;
        }
        steps.push(ChainStep {
            transform: t,
            output: next.clone(),
            binary,
            error: None,
        });
        current = next;
    }
    steps
}

fn detect_and_decode(s: &str) -> Option<(Transform, String, bool)> {
    let trimmed = s.trim();
    if trimmed.len() < 2 {
        return None;
    }

    // JWT — three base64url segments separated by `.`, header starts eyJ.
    if trimmed.starts_with("eyJ") && trimmed.matches('.').count() == 2 {
        if let Ok(parts) = jwt_decode(trimmed) {
            if let Ok(out) = serde_json::to_string_pretty(&parts) {
                return Some((Transform::JwtDecode, out, false));
            }
        }
    }

    // URL-encoded — look for `%XX` percent-escapes.
    if trimmed.contains('%') {
        if let Ok(out) = url_decode(trimmed) {
            if out != trimmed && looks_printable(&out) {
                return Some((Transform::UrlDecode, out, false));
            }
        }
    }

    // Hex-encoded — all hex digits, even length, long enough.
    if trimmed.len() >= 6
        && trimmed.len() % 2 == 0
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        if let Ok(out_bytes) = hex_decode(trimmed) {
            if let Ok(txt) = String::from_utf8(out_bytes) {
                if looks_printable(&txt) {
                    return Some((Transform::HexDecode, txt, false));
                }
            }
        }
    }

    // Base64url — any `-` or `_` chars signal the url-safe alphabet.
    if looks_like_base64url(trimmed) {
        if let Ok(out_bytes) = base64url_decode(trimmed) {
            if let Ok(txt) = String::from_utf8(out_bytes) {
                if looks_printable(&txt) {
                    return Some((Transform::Base64UrlDecode, txt, false));
                }
            }
        }
    }

    // Base64 (standard alphabet).
    if looks_like_base64(trimmed) {
        if let Ok(out_bytes) = base64_decode(trimmed) {
            if let Ok(txt) = String::from_utf8(out_bytes) {
                if looks_printable(&txt) {
                    return Some((Transform::Base64Decode, txt, false));
                }
            }
        }
    }

    // HTML entities.
    if trimmed.contains('&') && (trimmed.contains(';') || trimmed.contains("&#")) {
        let out = html_decode(trimmed);
        if out != trimmed {
            return Some((Transform::HtmlDecode, out, false));
        }
    }

    // Unicode escapes (\uXXXX).
    if trimmed.contains("\\u") {
        if let Ok(out) = unicode_escape_decode(trimmed) {
            if out != trimmed {
                return Some((Transform::UnicodeEscapeDecode, out, false));
            }
        }
    }

    None
}

fn looks_printable(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // >= 90% of chars must be printable ASCII, including common whitespace.
    let total = s.chars().count();
    let printable = s
        .chars()
        .filter(|c| {
            c.is_ascii_graphic()
                || *c == ' '
                || *c == '\t'
                || *c == '\n'
                || *c == '\r'
                || !c.is_ascii()
        })
        .count();
    printable * 10 >= total * 9
}

fn looks_like_base64(s: &str) -> bool {
    let stripped = s.trim_end_matches('=');
    stripped.len() >= 8
        && stripped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        // Avoid matching a pure-alphabetic word — require at least one digit
        // or symbol so "hellohello" doesn't look base64.
        && stripped.chars().any(|c| !c.is_ascii_alphabetic() || c.is_ascii_uppercase())
        && stripped.chars().any(|c| c.is_ascii_digit() || !c.is_ascii_alphabetic())
}

fn looks_like_base64url(s: &str) -> bool {
    let stripped = s.trim_end_matches('=');
    stripped.len() >= 8
        && stripped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && (stripped.contains('-') || stripped.contains('_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_chain() {
        let steps = apply_chain(
            "hello world",
            &[Transform::UrlEncode, Transform::Base64Encode, Transform::Base64Decode, Transform::UrlDecode],
        );
        assert_eq!(steps.len(), 4);
        assert!(steps.iter().all(|s| s.error.is_none()));
        assert_eq!(steps.last().unwrap().output, "hello world");
    }

    #[test]
    fn chain_stops_on_error() {
        let steps = apply_chain("not valid base64 !!!", &[Transform::Base64Decode, Transform::Base64Decode]);
        assert_eq!(steps.len(), 1);
        assert!(steps[0].error.is_some());
    }

    #[test]
    fn md5_known_vector() {
        let s = apply_chain("hello", &[Transform::Md5]);
        assert_eq!(s[0].output, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn sha1_known_vector() {
        let s = apply_chain("hello", &[Transform::Sha1]);
        assert_eq!(s[0].output, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn sha256_known_vector() {
        let s = apply_chain("hello", &[Transform::Sha256]);
        assert_eq!(
            s[0].output,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn blake3_known_vector() {
        let s = apply_chain("hello", &[Transform::Blake3]);
        // blake3("hello") → ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f
        assert_eq!(
            s[0].output,
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    // Known HMAC vectors from Wikipedia's HMAC article (public-domain
    // examples using `key = "key"` and the pangram as data). These are
    // the same test vectors the operator can double-check against any
    // other HMAC implementation.
    const HMAC_INPUT: &str = "The quick brown fox jumps over the lazy dog";

    #[test]
    fn hmac_sha1_known_vector() {
        let s = apply_chain(
            HMAC_INPUT,
            &[Transform::HmacSha1 { key: "key".into() }],
        );
        assert_eq!(s.len(), 1);
        assert!(s[0].error.is_none());
        assert_eq!(s[0].output, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    }

    #[test]
    fn hmac_sha256_known_vector() {
        let s = apply_chain(
            HMAC_INPUT,
            &[Transform::HmacSha256 { key: "key".into() }],
        );
        assert_eq!(s.len(), 1);
        assert!(s[0].error.is_none());
        assert_eq!(
            s[0].output,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn hmac_sha384_known_vector() {
        let s = apply_chain(
            HMAC_INPUT,
            &[Transform::HmacSha384 { key: "key".into() }],
        );
        assert_eq!(s.len(), 1);
        assert!(s[0].error.is_none());
        assert_eq!(
            s[0].output,
            "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"
        );
    }

    #[test]
    fn hmac_sha512_known_vector() {
        let s = apply_chain(
            HMAC_INPUT,
            &[Transform::HmacSha512 { key: "key".into() }],
        );
        assert_eq!(s.len(), 1);
        assert!(s[0].error.is_none());
        assert_eq!(
            s[0].output,
            "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
        );
    }

    #[test]
    fn hmac_chains_cleanly() {
        // Prove a hmac step composes into further steps — the output
        // is a hex string so a trailing Base64Encode should run clean.
        let s = apply_chain(
            "abc",
            &[
                Transform::HmacSha256 { key: "secret".into() },
                Transform::Base64Encode,
            ],
        );
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|st| st.error.is_none()));
        // The first step is 64 hex chars, the second step must base64 them.
        assert_eq!(s[0].output.len(), 64);
        assert!(!s[1].output.is_empty());
    }

    #[test]
    fn hmac_serializes_with_tagged_key() {
        // Round-trip the serde form the frontend will see.
        let t = Transform::HmacSha256 { key: "shh".into() };
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#"{"op":"hmac_sha256","key":"shh"}"#);
        let back: Transform = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Transform::HmacSha256 { ref key } if key == "shh"));
    }

    #[test]
    fn smart_decode_peels_url_layer() {
        // "hello%20world" → "hello world"
        let s = smart_decode("hello%20world", 4);
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0].transform, Transform::UrlDecode));
        assert_eq!(s[0].output, "hello world");
    }

    #[test]
    fn smart_decode_peels_base64_then_url() {
        // base64("hello%20world") = "aGVsbG8lMjB3b3JsZA=="
        let s = smart_decode("aGVsbG8lMjB3b3JsZA==", 4);
        assert!(s.len() >= 2, "expected >=2 layers, got {}", s.len());
        assert!(matches!(s[0].transform, Transform::Base64Decode));
        assert!(matches!(s[1].transform, Transform::UrlDecode));
        assert_eq!(s.last().unwrap().output, "hello world");
    }

    #[test]
    fn smart_decode_detects_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.aa";
        let s = smart_decode(jwt, 2);
        assert!(matches!(s[0].transform, Transform::JwtDecode));
        assert!(s[0].output.contains("alice"));
    }

    #[test]
    fn smart_decode_stops_on_garbage() {
        // Random short alphanumeric: nothing should fire.
        let s = smart_decode("abc", 4);
        assert!(s.is_empty());
    }
}
