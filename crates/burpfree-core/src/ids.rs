//! ID generation and content hashing.
//!
//! * [`TrafficId`] is a monotonic opaque identifier for request /
//!   response / websocket observations. It is roughly time-ordered
//!   across restarts: the high bits encode milliseconds since the
//!   Unix epoch at process start, the low bits a per-process counter.
//! * [`blake3_hex`] is used to content-address body blobs on disk.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Monotonic traffic identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct TrafficId(pub i64);

impl std::fmt::Display for TrafficId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

static SEQ: Lazy<AtomicI64> = Lazy::new(|| {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    AtomicI64::new(ms << 20)
});

impl TrafficId {
    /// Return a fresh id.
    pub fn new() -> Self {
        Self(SEQ.fetch_add(1, Ordering::Relaxed) + 1)
    }

    /// Underlying integer representation.
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl Default for TrafficId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<i64> for TrafficId {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

/// BLAKE3 hex digest, 20 bytes (160 bits) truncated for compact blob names.
pub fn blake3_hex(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hex::encode(&hash.as_bytes()[..20])
}

/// Short URL-safe hex token used for API bearer tokens and similar.
pub fn random_token(nbytes: usize) -> String {
    use rand::RngCore;
    let n = if nbytes == 0 { 16 } else { nbytes };
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(&buf)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

/// A content-addressed reference to a body blob stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentRef {
    pub sha: String,
    pub size: u64,
}

impl ContentRef {
    /// Hash and length of `data`.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            sha: blake3_hex(data),
            size: data.len() as u64,
        }
    }

    /// Return `(dir, file)` for the blob store layout `<ab>/<rest>`.
    pub fn path_parts(&self) -> (&str, &str) {
        if self.sha.len() >= 2 {
            self.sha.split_at(2)
        } else {
            (self.sha.as_str(), "")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_ids_are_monotonic() {
        let a = TrafficId::new();
        let b = TrafficId::new();
        let c = TrafficId::new();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn content_ref_is_stable() {
        let a = ContentRef::from_bytes(b"hello world");
        let b = ContentRef::from_bytes(b"hello world");
        assert_eq!(a, b);
        assert_eq!(a.size, 11);
        assert_eq!(a.sha.len(), 40);
    }

    #[test]
    fn content_ref_path_parts_split() {
        let r = ContentRef::from_bytes(b"abc");
        let (dir, rest) = r.path_parts();
        assert_eq!(dir.len(), 2);
        assert_eq!(rest.len(), r.sha.len() - 2);
    }

    #[test]
    fn random_token_is_hex() {
        let t = random_token(16);
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
