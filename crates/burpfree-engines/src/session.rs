//! Minimal cookie jar for Session handling.
//!
//! Parses `Set-Cookie` headers from responses and matches them back
//! to request URLs by domain / path / secure / HttpOnly rules. This
//! is intentionally small — Repeater and Intruder optionally pipe
//! their requests through it so an engagement that requires an
//! authenticated session can be scripted in a few lines.

use std::sync::Arc;

use burpfree_core::traffic::{Request, Response};
use chrono::DateTime;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires_at: Option<i64>, // unix ms
    pub max_age: Option<i64>,
    pub host_only: bool,
}

impl Cookie {
    pub fn matches(&self, scheme: &str, host: &str, path: &str) -> bool {
        if self.secure && scheme != "https" {
            return false;
        }
        if !domain_matches(host, &self.domain, self.host_only) {
            return false;
        }
        if !path_matches(path, &self.path) {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if burpfree_core::traffic::now_ms() > exp {
                return false;
            }
        }
        true
    }

    pub fn parse(set_cookie: &str, default_host: &str) -> Option<Cookie> {
        let mut parts = set_cookie.split(';').map(str::trim);
        let first = parts.next()?;
        let (name, value) = match first.find('=') {
            Some(i) => (first[..i].trim().to_string(), first[i + 1..].trim().to_string()),
            None => (first.trim().to_string(), String::new()),
        };
        if name.is_empty() {
            return None;
        }
        let mut c = Cookie {
            name,
            value,
            domain: default_host.to_string(),
            path: "/".into(),
            secure: false,
            http_only: false,
            same_site: None,
            expires_at: None,
            max_age: None,
            host_only: true,
        };
        for p in parts {
            let (k, v) = match p.find('=') {
                Some(i) => (p[..i].trim().to_ascii_lowercase(), p[i + 1..].trim().to_string()),
                None => (p.trim().to_ascii_lowercase(), String::new()),
            };
            match k.as_str() {
                "domain" => {
                    let v = v.trim_start_matches('.').to_string();
                    if !v.is_empty() {
                        c.domain = v;
                        c.host_only = false;
                    }
                }
                "path" => {
                    if !v.is_empty() {
                        c.path = v;
                    }
                }
                "secure" => c.secure = true,
                "httponly" => c.http_only = true,
                "samesite" => c.same_site = Some(v),
                "expires" => {
                    if let Some(ts) = parse_cookie_date(&v) {
                        c.expires_at = Some(ts);
                    }
                }
                "max-age" => {
                    if let Ok(n) = v.parse::<i64>() {
                        c.max_age = Some(n);
                        c.expires_at = Some(burpfree_core::traffic::now_ms() + n * 1000);
                    }
                }
                _ => {}
            }
        }
        Some(c)
    }
}

fn parse_cookie_date(s: &str) -> Option<i64> {
    // Accept RFC 1123 and a couple of common variants.
    for fmt in &[
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.timestamp_millis());
        }
    }
    // Fallback RFC 2822 or RFC 3339.
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.timestamp_millis());
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    None
}

fn domain_matches(host: &str, cookie_domain: &str, host_only: bool) -> bool {
    let host = host.to_ascii_lowercase();
    let dom = cookie_domain.to_ascii_lowercase();
    if host_only {
        return host == dom;
    }
    host == dom || host.ends_with(&format!(".{dom}"))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if request_path.starts_with(cookie_path) {
        if cookie_path.ends_with('/') {
            return true;
        }
        return request_path.as_bytes().get(cookie_path.len()) == Some(&b'/');
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    inner: Arc<RwLock<Vec<Cookie>>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_response(&self, req: &Request, resp: &Response) {
        for sc in resp.headers.get_all("Set-Cookie") {
            if let Some(c) = Cookie::parse(sc, &req.host) {
                self.store(c);
            }
        }
    }

    pub fn store(&self, c: Cookie) {
        let mut v = self.inner.write();
        // Replace existing cookie by (name, domain, path).
        v.retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
        v.push(c);
    }

    pub fn apply_to_request(&self, req: &mut Request) {
        let v = self.inner.read();
        let mut out = Vec::new();
        for c in v.iter() {
            if c.matches(&req.scheme, &req.host, req.path_only()) {
                out.push(format!("{}={}", c.name, c.value));
            }
        }
        if !out.is_empty() {
            let header = out.join("; ");
            req.headers.set("Cookie", header);
        }
    }

    pub fn snapshot(&self) -> Vec<Cookie> {
        self.inner.read().clone()
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Remove the cookie identified by the (name, domain, path)
    /// triple that uniquely addresses a jar entry. Returns `true`
    /// iff a matching cookie was present. Backs the "✕" button on
    /// each CookieJarPanel row.
    pub fn delete(&self, name: &str, domain: &str, path: &str) -> bool {
        let mut v = self.inner.write();
        let before = v.len();
        v.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
        before != v.len()
    }

    /// Alias for `store` with a UI-oriented name. Burp calls the
    /// equivalent action "Add cookie" so the cmd + binding read
    /// cleanly from the operator's perspective.
    pub fn upsert(&self, c: Cookie) {
        self.store(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response};

    #[test]
    fn parses_set_cookie_with_attrs() {
        let c = Cookie::parse(
            "sid=abc123; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600",
            "api.example.com",
        )
        .unwrap();
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.domain, "example.com");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
        assert!(c.expires_at.is_some());
    }

    #[test]
    fn host_only_vs_domain() {
        let c = Cookie::parse("a=1", "api.example.com").unwrap();
        assert!(c.host_only);
        assert!(c.matches("http", "api.example.com", "/"));
        assert!(!c.matches("http", "www.api.example.com", "/"));

        let c = Cookie::parse("a=1; Domain=example.com", "api.example.com").unwrap();
        assert!(!c.host_only);
        assert!(c.matches("http", "example.com", "/"));
        assert!(c.matches("http", "www.example.com", "/"));
        assert!(!c.matches("http", "notexample.com", "/"));
    }

    #[test]
    fn secure_requires_https() {
        let c = Cookie::parse("a=1; Secure", "example.com").unwrap();
        assert!(!c.matches("http", "example.com", "/"));
        assert!(c.matches("https", "example.com", "/"));
    }

    #[test]
    fn jar_applies_cookies_to_request() {
        let jar = CookieJar::new();
        let req = Request::new("GET", "https://api.example.com/x").unwrap();
        let mut resp = Response::new(200);
        resp.headers.add("Set-Cookie", "sid=abc; Secure; Path=/");
        jar.observe_response(&req, &resp);
        let mut r2 = Request::new("GET", "https://api.example.com/x").unwrap();
        jar.apply_to_request(&mut r2);
        assert_eq!(r2.headers.get("Cookie"), Some("sid=abc"));
    }

    #[test]
    fn later_set_cookie_replaces() {
        let jar = CookieJar::new();
        let req = Request::new("GET", "https://api.example.com/").unwrap();
        let mut r1 = Response::new(200);
        r1.headers.add("Set-Cookie", "sid=aaa; Path=/");
        jar.observe_response(&req, &r1);
        let mut r2 = Response::new(200);
        r2.headers.add("Set-Cookie", "sid=bbb; Path=/");
        jar.observe_response(&req, &r2);
        assert_eq!(jar.snapshot().len(), 1);
        assert_eq!(jar.snapshot()[0].value, "bbb");
    }

    /// `delete` must only touch the matching (name, domain, path)
    /// triple — adjacent cookies on the same host survive, and a
    /// miss returns `false`. `upsert` wraps `store` so manual UI
    /// adds take the same replacement semantics as proxy-harvested
    /// cookies.
    #[test]
    fn delete_targets_the_right_cookie_only() {
        let jar = CookieJar::new();
        jar.upsert(Cookie {
            name: "sid".into(),
            value: "aaa".into(),
            domain: "example.com".into(),
            path: "/".into(),
            secure: false,
            http_only: false,
            same_site: None,
            expires_at: None,
            max_age: None,
            host_only: true,
        });
        jar.upsert(Cookie {
            name: "csrf".into(),
            value: "xyz".into(),
            domain: "example.com".into(),
            path: "/".into(),
            secure: false,
            http_only: false,
            same_site: None,
            expires_at: None,
            max_age: None,
            host_only: true,
        });
        assert_eq!(jar.snapshot().len(), 2);
        // Precise match removes exactly one.
        assert!(jar.delete("sid", "example.com", "/"));
        let snap = jar.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "csrf");
        // Second delete on same triple is a no-op (returns false).
        assert!(!jar.delete("sid", "example.com", "/"));
        // Mis-matched path leaves state alone.
        assert!(!jar.delete("csrf", "example.com", "/api"));
        assert_eq!(jar.snapshot().len(), 1);
        // Mis-matched domain also no-op.
        assert!(!jar.delete("csrf", "other.com", "/"));
        assert_eq!(jar.snapshot().len(), 1);
    }
}
