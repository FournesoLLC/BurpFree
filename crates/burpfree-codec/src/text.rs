//! Text-oriented codecs: URL, Base64, Base64URL, hex, Unicode escapes.
//!
//! The functions here are deliberately permissive: they tolerate
//! unexpected padding / whitespace in Base64 and continue on invalid
//! hex nibbles when running in "lossy" mode. The Decoder tool uses
//! this to let security analysts try transforms on real-world,
//! truncated or malformed data.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

const ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'+')
    .add(b'&')
    .add(b'=');

/// Percent-encode (RFC 3986 unreserved + a safe default set).
pub fn url_encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE_SET).to_string()
}

/// Percent-decode. `+` is treated as a space (form semantics) to be
/// forgiving, matching typical pentester expectations.
pub fn url_decode(s: &str) -> Result<String> {
    let swapped = s.replace('+', " ");
    let decoded = percent_encoding::percent_decode_str(&swapped)
        .decode_utf8()
        .with_context(|| "url_decode produced invalid utf-8")?;
    Ok(decoded.into_owned())
}

pub fn base64_encode(s: &[u8]) -> String {
    general_purpose::STANDARD.encode(s)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(cleaned.as_bytes()))
        .map_err(|e| anyhow!("base64 decode: {e}"))
}

pub fn base64url_encode(s: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(s)
}

pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    general_purpose::URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .or_else(|_| general_purpose::URL_SAFE.decode(cleaned.as_bytes()))
        .map_err(|e| anyhow!("base64url decode: {e}"))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    hex::decode(&cleaned).map_err(|e| anyhow!("hex decode: {e}"))
}

/// Encode non-ASCII and control characters as `\uXXXX`.
pub fn unicode_escape_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let code = ch as u32;
        if (0x20..0x7F).contains(&code) && ch != '\\' {
            out.push(ch);
        } else if code <= 0xFFFF {
            out.push_str(&format!("\\u{:04x}", code));
        } else {
            // Encode as surrogate pair.
            let code = code - 0x10000;
            let hi = 0xD800 + (code >> 10);
            let lo = 0xDC00 + (code & 0x3FF);
            out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
        }
    }
    out
}

/// Decode `\uXXXX` sequences. Supports JSON-style escapes.
pub fn unicode_escape_decode(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                'u' => {
                    if i + 5 >= bytes.len() {
                        return Err(anyhow!("truncated \\u escape"));
                    }
                    let hex: String = bytes[i + 2..i + 6].iter().collect();
                    let code = u32::from_str_radix(&hex, 16)
                        .map_err(|_| anyhow!("bad hex in \\u escape"))?;
                    // Surrogate pair handling.
                    if (0xD800..=0xDBFF).contains(&code) {
                        if i + 11 >= bytes.len() || bytes[i + 6] != '\\' || bytes[i + 7] != 'u' {
                            return Err(anyhow!("unpaired surrogate"));
                        }
                        let hex2: String = bytes[i + 8..i + 12].iter().collect();
                        let lo = u32::from_str_radix(&hex2, 16)
                            .map_err(|_| anyhow!("bad hex in surrogate"))?;
                        let combined = 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00);
                        if let Some(c) = char::from_u32(combined) {
                            out.push(c);
                        }
                        i += 12;
                    } else if let Some(c) = char::from_u32(code) {
                        out.push(c);
                        i += 6;
                    } else {
                        return Err(anyhow!("invalid unicode scalar"));
                    }
                }
                'n' => {
                    out.push('\n');
                    i += 2;
                }
                'r' => {
                    out.push('\r');
                    i += 2;
                }
                't' => {
                    out.push('\t');
                    i += 2;
                }
                '\\' => {
                    out.push('\\');
                    i += 2;
                }
                '"' => {
                    out.push('"');
                    i += 2;
                }
                '/' => {
                    out.push('/');
                    i += 2;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_space_and_special() {
        assert_eq!(url_encode("hello world!"), "hello%20world!");
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn url_decode_handles_plus() {
        assert_eq!(url_decode("hello+world").unwrap(), "hello world");
        assert_eq!(url_decode("%E2%9C%93").unwrap(), "✓");
    }

    #[test]
    fn base64_roundtrip() {
        let s = b"hello world";
        assert_eq!(base64_decode(&base64_encode(s)).unwrap(), s);
    }

    #[test]
    fn base64url_without_padding() {
        let s = b"\xff\xff\xff";
        assert_eq!(base64url_decode(&base64url_encode(s)).unwrap(), s);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_encode(b"hi"), "6869");
        assert_eq!(hex_decode("68 69").unwrap(), b"hi");
        assert_eq!(hex_decode("68:69").unwrap(), b"hi");
    }

    #[test]
    fn unicode_escape_roundtrip() {
        let s = "héllo\n✓";
        let enc = unicode_escape_encode(s);
        let dec = unicode_escape_decode(&enc).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn surrogate_pair() {
        // 🚀 = U+1F680
        let dec = unicode_escape_decode("\\ud83d\\ude80").unwrap();
        assert_eq!(dec, "🚀");
    }
}
