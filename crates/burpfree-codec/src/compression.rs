//! Compression helpers for HTTP bodies.
//!
//! The proxy transparently decompresses responses when we need to run
//! match/replace or scanners. We cap the output size by a configurable
//! ratio to resist decompression bombs: the decompressor refuses to
//! grow the output beyond `max_output = max(ratio * input, floor)`.

use std::io::{Read, Write};

use anyhow::{anyhow, Context, Result};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::GzEncoder;
use flate2::Compression;

/// Configurable upper bound on decompressed output size.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimit {
    /// Ratio of output to input bytes allowed before refusing.
    pub ratio: u32,
    /// Lower floor for small bodies.
    pub floor: usize,
    /// Hard ceiling in bytes regardless of ratio.
    pub ceiling: usize,
}

impl DecodeLimit {
    pub const fn default_limit() -> Self {
        Self {
            ratio: 100,
            floor: 1 << 20,       // 1 MiB
            ceiling: 256 << 20,   // 256 MiB
        }
    }

    pub fn max_output(&self, input_len: usize) -> usize {
        let r = (self.ratio as usize).saturating_mul(input_len);
        r.max(self.floor).min(self.ceiling)
    }
}

impl Default for DecodeLimit {
    fn default() -> Self {
        Self::default_limit()
    }
}

/// Decode a body given the raw `Content-Encoding` header value.
pub fn decode_body(encoding: &str, body: &[u8], limit: DecodeLimit) -> Result<Vec<u8>> {
    let max = limit.max_output(body.len());
    let mut out = Vec::with_capacity(body.len());
    for enc in encoding.split(',').map(|s| s.trim().to_ascii_lowercase()).rev() {
        match enc.as_str() {
            "" | "identity" => {
                out = body.to_vec();
            }
            "gzip" | "x-gzip" => {
                let mut d = GzDecoder::new(body);
                read_with_limit(&mut d, &mut out, max)?;
            }
            "deflate" => {
                // RFC 7230 is ambiguous: try zlib first, fall back to raw deflate.
                let mut buf = Vec::new();
                let mut z = ZlibDecoder::new(body);
                match read_with_limit(&mut z, &mut buf, max) {
                    Ok(_) => out = buf,
                    Err(_) => {
                        let mut d = DeflateDecoder::new(body);
                        out.clear();
                        read_with_limit(&mut d, &mut out, max)?;
                    }
                }
            }
            "br" => {
                let mut reader = brotli::Decompressor::new(body, 4096);
                read_with_limit(&mut reader, &mut out, max)?;
            }
            other => return Err(anyhow!("unsupported content-encoding: {other}")),
        }
    }
    Ok(out)
}

/// Decode only if `encoding` is present and recognised; else return
/// `body` as-is. Convenience for the proxy response pipeline.
pub fn maybe_decompress(encoding: Option<&str>, body: &[u8], limit: DecodeLimit) -> Result<Vec<u8>> {
    match encoding.map(str::trim) {
        None | Some("") | Some("identity") => Ok(body.to_vec()),
        Some(enc) => decode_body(enc, body, limit).context("transparent decompression"),
    }
}

pub fn encode_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn read_with_limit<R: Read>(r: &mut R, out: &mut Vec<u8>, max: usize) -> Result<()> {
    let mut tmp = [0u8; 8192];
    loop {
        let n = r.read(&mut tmp).map_err(|e| anyhow!("decompression read: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max {
            return Err(anyhow!(
                "decompression exceeded limit of {max} bytes (bomb protection)"
            ));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_roundtrip() {
        let data = b"hello world, hello world, hello world";
        let enc = encode_gzip(data).unwrap();
        let dec = decode_body("gzip", &enc, DecodeLimit::default()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn maybe_decompress_identity() {
        let body = b"abc";
        assert_eq!(maybe_decompress(None, body, DecodeLimit::default()).unwrap(), body);
        assert_eq!(maybe_decompress(Some("identity"), body, DecodeLimit::default()).unwrap(), body);
    }

    #[test]
    fn bomb_protection() {
        let data = vec![b'a'; 1024];
        let enc = encode_gzip(&data).unwrap();
        let strict = DecodeLimit { ratio: 1, floor: 100, ceiling: 100 };
        let r = decode_body("gzip", &enc, strict);
        assert!(r.is_err(), "expected bomb protection to trigger");
    }
}
