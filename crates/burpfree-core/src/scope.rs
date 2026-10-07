//! Scope engine.
//!
//! Burp-style include/exclude rules. The engine is layered: include
//! rules add surface area, exclude rules take it away. A request is in
//! scope iff **at least one include rule matches and no exclude rule
//! matches**. Rules match on `scheme`, `host`, `port`, `path`.
//!
//! Host matching supports wildcards (`*.example.com`), path matching
//! supports a leading `^` to anchor, and regex can be opted into on a
//! per-rule basis.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::traffic::Request;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMatch {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    InScope,
    OutOfScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub match_kind: ScopeMatch,
    /// Any / http / https / ws / wss.
    pub protocol: String,
    /// Pattern. Supports `*` wildcard anywhere; `^foo$` for exact; or
    /// opt into Rust regex by setting `regex = true`.
    pub host: String,
    /// Empty means "any port".
    pub port: Option<u16>,
    /// Path pattern — same semantics as host.
    pub path: String,
    pub regex: bool,
    pub enabled: bool,
}

impl ScopeRule {
    pub fn include_host(host: impl Into<String>) -> Self {
        Self {
            match_kind: ScopeMatch::Include,
            protocol: "any".into(),
            host: host.into(),
            port: None,
            path: "*".into(),
            regex: false,
            enabled: true,
        }
    }

    pub fn exclude_host(host: impl Into<String>) -> Self {
        Self {
            match_kind: ScopeMatch::Exclude,
            protocol: "any".into(),
            host: host.into(),
            port: None,
            path: "*".into(),
            regex: false,
            enabled: true,
        }
    }

    fn protocol_matches(&self, scheme: &str) -> bool {
        matches!(self.protocol.as_str(), "any" | "" ) || self.protocol.eq_ignore_ascii_case(scheme)
    }

    fn port_matches(&self, p: u16) -> bool {
        match self.port {
            Some(expected) => expected == p,
            None => true,
        }
    }

    fn host_matches(&self, host: &str) -> bool {
        if self.host.is_empty() || self.host == "*" {
            return true;
        }
        if self.regex {
            Regex::new(&self.host).map(|r| r.is_match(host)).unwrap_or(false)
        } else {
            glob_match(&self.host, host)
        }
    }

    fn path_matches(&self, path: &str) -> bool {
        if self.path.is_empty() || self.path == "*" {
            return true;
        }
        if self.regex {
            Regex::new(&self.path).map(|r| r.is_match(path)).unwrap_or(false)
        } else {
            glob_match(&self.path, path)
        }
    }

    pub fn matches(&self, req: &Request) -> bool {
        if !self.enabled {
            return false;
        }
        self.protocol_matches(&req.scheme)
            && self.host_matches(&req.host)
            && self.port_matches(req.port)
            && self.path_matches(req.path_only())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
    /// If true, an empty include set means "everything is in scope".
    /// If false, an empty include set means "nothing is in scope".
    pub default_in_scope_when_empty: bool,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_in_scope_when_empty: true,
        }
    }

    pub fn add(&mut self, rule: ScopeRule) {
        self.rules.push(rule);
    }

    pub fn decide(&self, req: &Request) -> ScopeDecision {
        let mut had_include = false;
        let mut included = false;
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if rule.match_kind == ScopeMatch::Include {
                had_include = true;
                if rule.matches(req) {
                    included = true;
                }
            }
        }
        if !had_include {
            if !self.default_in_scope_when_empty {
                return ScopeDecision::OutOfScope;
            }
            included = true;
        }
        if !included {
            return ScopeDecision::OutOfScope;
        }
        for rule in &self.rules {
            if rule.enabled && rule.match_kind == ScopeMatch::Exclude && rule.matches(req) {
                return ScopeDecision::OutOfScope;
            }
        }
        ScopeDecision::InScope
    }

    pub fn is_in_scope(&self, req: &Request) -> bool {
        matches!(self.decide(req), ScopeDecision::InScope)
    }
}

/// Minimal glob matcher supporting `*` (any sequence) and `?` (any one
/// char). Case-insensitive. If `pattern` begins with `^` the match is
/// anchored at the start of `text`; by default `*` is appended to both
/// ends for substring semantics (which gives us "contains" by default
/// when the pattern has no wildcards).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let anchored_start = pattern.starts_with('^');
    let anchored_end = pattern.ends_with('$');
    let core = pattern.trim_start_matches('^').trim_end_matches('$');
    let pattern_lc = core.to_ascii_lowercase();
    let text_lc = text.to_ascii_lowercase();
    let pat_bytes = pattern_lc.as_bytes();
    let txt_bytes = text_lc.as_bytes();
    // If no wildcards and not anchored → substring.
    if !pattern_lc.contains('*') && !pattern_lc.contains('?') {
        return match (anchored_start, anchored_end) {
            (true, true) => text_lc == pattern_lc,
            (true, false) => text_lc.starts_with(&pattern_lc),
            (false, true) => text_lc.ends_with(&pattern_lc),
            (false, false) => text_lc.contains(&pattern_lc),
        };
    }
    glob_dp(pat_bytes, txt_bytes, anchored_start, anchored_end)
}

/// DP wildcard match for `*` and `?` with optional anchoring.
fn glob_dp(pat: &[u8], txt: &[u8], anchor_start: bool, anchor_end: bool) -> bool {
    // Try each possible starting position in `txt` if not anchored.
    let starts: Box<dyn Iterator<Item = usize>> = if anchor_start {
        Box::new(std::iter::once(0))
    } else {
        Box::new(0..=txt.len())
    };
    for s in starts {
        if try_from(pat, txt, s, anchor_end) {
            return true;
        }
    }
    false
}

fn try_from(pat: &[u8], txt: &[u8], start: usize, anchor_end: bool) -> bool {
    let m = pat.len();
    let n = txt.len();
    // dp[i][j] = pat[..i] matches txt[start..start+j]
    let mut dp = vec![vec![false; n - start + 1]; m + 1];
    dp[0][0] = true;
    for i in 1..=m {
        if pat[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=m {
        for j in 1..=(n - start) {
            dp[i][j] = match pat[i - 1] {
                b'*' => dp[i - 1][j] || dp[i][j - 1],
                b'?' => dp[i - 1][j - 1],
                c => dp[i - 1][j - 1] && txt[start + j - 1] == c,
            };
        }
    }
    // If we require anchor_end, must match exactly to end.
    if anchor_end {
        dp[m][n - start]
    } else {
        // Else: pattern must have matched some prefix of remaining txt.
        (0..=(n - start)).any(|j| dp[m][j])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(url: &str) -> Request {
        Request::new("GET", url).unwrap()
    }

    #[test]
    fn empty_scope_defaults_in_scope() {
        let s = Scope::new();
        assert!(s.is_in_scope(&req("https://example.com/")));
    }

    #[test]
    fn include_then_exclude() {
        let mut s = Scope::new();
        s.add(ScopeRule::include_host("*.example.com"));
        s.add(ScopeRule::exclude_host("*.admin.example.com"));
        assert!(s.is_in_scope(&req("https://api.example.com/users")));
        assert!(!s.is_in_scope(&req("https://api.admin.example.com/users")));
        assert!(!s.is_in_scope(&req("https://other.org/")));
    }

    #[test]
    fn protocol_filter() {
        let mut s = Scope::new();
        let mut r = ScopeRule::include_host("example.com");
        r.protocol = "https".into();
        s.add(r);
        assert!(s.is_in_scope(&req("https://example.com/")));
        assert!(!s.is_in_scope(&req("http://example.com/")));
    }

    #[test]
    fn port_filter() {
        let mut s = Scope::new();
        let mut r = ScopeRule::include_host("example.com");
        r.port = Some(8443);
        s.add(r);
        assert!(s.is_in_scope(&req("https://example.com:8443/")));
        assert!(!s.is_in_scope(&req("https://example.com/")));
    }

    #[test]
    fn path_wildcard() {
        let mut s = Scope::new();
        let mut r = ScopeRule::include_host("example.com");
        r.path = "/api/*".into();
        s.add(r);
        assert!(s.is_in_scope(&req("https://example.com/api/users")));
        assert!(!s.is_in_scope(&req("https://example.com/static/x")));
    }

    #[test]
    fn regex_host() {
        let mut s = Scope::new();
        let mut r = ScopeRule::include_host(r"^(a|b)\.example\.com$");
        r.regex = true;
        s.add(r);
        assert!(s.is_in_scope(&req("https://a.example.com/")));
        assert!(s.is_in_scope(&req("https://b.example.com/")));
        assert!(!s.is_in_scope(&req("https://c.example.com/")));
    }

    #[test]
    fn glob_anchors() {
        assert!(glob_match("example.com", "api.example.com"));
        assert!(glob_match("^example.com", "example.com/"));
        assert!(!glob_match("^example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "api.example.com"));
    }
}
