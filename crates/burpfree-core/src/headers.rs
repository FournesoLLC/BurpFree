//! Case-insensitive, order-preserving, multi-valued HTTP header container.
//!
//! HTTP headers have three semantics that trip up [`HashMap`]:
//!
//! * Field names are case-insensitive but original casing is observable
//!   on the wire and some clients care.
//! * Order matters when re-serializing a message for a replay.
//! * The same name may appear multiple times (`Set-Cookie`).
//!
//! [`Headers`] preserves all three. Internally it stores a vector of
//! `(name, value)` pairs; lookups are case-insensitive.

use serde::{Deserialize, Serialize};

/// A single on-the-wire header pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

impl HeaderField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Order-preserving, case-insensitive, multi-valued header map.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Headers {
    items: Vec<HeaderField>,
}

impl Headers {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            items: Vec::with_capacity(cap),
        }
    }

    pub fn from_pairs<I, N, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let mut h = Self::new();
        for (n, v) in pairs {
            h.add(n, v);
        }
        h
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, HeaderField> {
        self.items.iter()
    }

    pub fn as_slice(&self) -> &[HeaderField] {
        &self.items
    }

    /// Append `(name, value)` without disturbing any existing values.
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.items.push(HeaderField::new(name, value));
    }

    /// Replace all values of `name` with a single `value`. If present,
    /// keeps the position of the first occurrence; otherwise appends.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        let mut placed = false;
        self.items.retain_mut(|f| {
            if eq_ascii(&f.name, &name) {
                if !placed {
                    f.name = name.clone();
                    f.value = value.clone();
                    placed = true;
                    true
                } else {
                    false
                }
            } else {
                true
            }
        });
        if !placed {
            self.items.push(HeaderField::new(name, value));
        }
    }

    pub fn set_if_missing(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        if !self.has(&name) {
            self.add(name, value);
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|f| eq_ascii(&f.name, name))
            .map(|f| f.value.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.items
            .iter()
            .filter(|f| eq_ascii(&f.name, name))
            .map(|f| f.value.as_str())
            .collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.items.iter().any(|f| eq_ascii(&f.name, name))
    }

    /// Remove all values of `name`; returns how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.items.len();
        self.items.retain(|f| !eq_ascii(&f.name, name));
        before - self.items.len()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Names in order of appearance (duplicates preserved).
    pub fn names(&self) -> Vec<&str> {
        self.items.iter().map(|f| f.name.as_str()).collect()
    }

    /// Serialize to the on-the-wire form (CRLF separated, no trailing
    /// blank line).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.items.len() * 32);
        for f in &self.items {
            out.extend_from_slice(f.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(f.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    /// Parse a buffer of CRLF-separated header lines (header block
    /// without the final blank line).
    pub fn parse_block(buf: &[u8]) -> Self {
        let mut headers = Self::new();
        for line in buf.split(|&b| b == b'\n') {
            let line = trim_trailing_cr(line);
            if line.is_empty() {
                continue;
            }
            if let Some(idx) = line.iter().position(|&b| b == b':') {
                let (name, rest) = line.split_at(idx);
                let value = trim_ascii(&rest[1..]);
                headers.add(
                    String::from_utf8_lossy(name).trim().to_string(),
                    String::from_utf8_lossy(value).to_string(),
                );
            }
        }
        headers
    }

    /// Parsed Content-Length header. `None` on absent / invalid.
    pub fn content_length(&self) -> Option<u64> {
        let v = self.get("Content-Length")?;
        v.trim().parse().ok()
    }

    /// True if `Transfer-Encoding` contains the token `chunked`.
    pub fn is_chunked(&self) -> bool {
        self.get("Transfer-Encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get("Content-Type")
    }

    /// Rough text-like detection used by the UI to decide whether to
    /// try UTF-8 decoding.
    pub fn is_text_like(&self) -> bool {
        let Some(ct) = self.content_type() else {
            return false;
        };
        let ct = ct.to_ascii_lowercase();
        if ct.starts_with("text/") {
            return true;
        }
        for token in ["json", "javascript", "xml", "html", "x-www-form-urlencoded"] {
            if ct.contains(token) {
                return true;
            }
        }
        false
    }

    /// Character set from the Content-Type header, or "utf-8".
    pub fn charset(&self) -> String {
        let ct = self.content_type().unwrap_or("");
        for part in ct.split(';') {
            let part = part.trim();
            if let Some(cs) = part.strip_prefix("charset=") {
                return cs.trim_matches('"').to_string();
            }
        }
        "utf-8".to_string()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a HeaderField;
    type IntoIter = std::slice::Iter<'a, HeaderField>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

fn eq_ascii(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().iter().zip(b.as_bytes()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    if let Some(&last) = line.last() {
        if last == b'\r' {
            return &line[..line.len() - 1];
        }
    }
    line
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() {
        if b == b' ' || b == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = s.last() {
        if b == b' ' || b == b'\t' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_preserves_duplicates() {
        let mut h = Headers::new();
        h.add("Set-Cookie", "a=1");
        h.add("Set-Cookie", "b=2");
        assert_eq!(h.get_all("set-cookie"), vec!["a=1", "b=2"]);
    }

    #[test]
    fn set_replaces_duplicates_in_place() {
        let mut h = Headers::new();
        h.add("X-A", "1");
        h.add("X-B", "x");
        h.add("x-a", "2");
        h.set("X-A", "3");
        let names: Vec<&str> = h.names();
        assert_eq!(names, vec!["X-A", "X-B"]);
        assert_eq!(h.get("x-a"), Some("3"));
    }

    #[test]
    fn case_insensitive_lookup() {
        let mut h = Headers::new();
        h.add("CONTENT-type", "text/html");
        assert_eq!(h.get("content-type"), Some("text/html"));
        assert!(h.has("Content-Type"));
    }

    #[test]
    fn parse_block_roundtrip() {
        let raw = b"Host: example.com\r\nContent-Length: 3\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n";
        let h = Headers::parse_block(raw);
        assert_eq!(h.content_length(), Some(3));
        assert_eq!(h.get_all("set-cookie").len(), 2);
        assert_eq!(h.to_wire_bytes(), raw);
    }

    #[test]
    fn chunked_detection() {
        let mut h = Headers::new();
        h.add("Transfer-Encoding", "gzip, chunked");
        assert!(h.is_chunked());
    }

    #[test]
    fn charset_defaults_to_utf8() {
        let mut h = Headers::new();
        h.add("Content-Type", "text/html");
        assert_eq!(h.charset(), "utf-8");
        h.set("Content-Type", "text/html; charset=iso-8859-1");
        assert_eq!(h.charset(), "iso-8859-1");
    }

    #[test]
    fn is_text_like_matches_json_and_html() {
        let mut h = Headers::new();
        h.set("Content-Type", "application/json");
        assert!(h.is_text_like());
        h.set("Content-Type", "image/png");
        assert!(!h.is_text_like());
    }
}
