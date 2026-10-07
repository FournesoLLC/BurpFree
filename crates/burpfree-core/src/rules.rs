//! Declarative passive scan rules.
//!
//! Scanner extensions (and users via UI/config files) can describe
//! custom checks without writing Rust: a rule is a labelled severity +
//! description plus a boolean [`CustomMatcher`] evaluated against a
//! transaction. If the matcher returns true, the scanner emits a
//! finding carrying the rule's metadata.
//!
//! Keeping the type in `burpfree-core` lets both the engines crate and
//! the extensions crate share the same shape, without taking a
//! dependency on each other.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::traffic::Transaction;

/// A labelled passive scanner rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPassiveRule {
    /// Stable detector id used for dedup fingerprinting.
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Only emit the finding when the matcher evaluates to true.
    pub when: CustomMatcher,
    /// Optional label for the insertion point so dedup is distinct per
    /// anchor. Example: "header:Content-Type" or "body".
    #[serde(default)]
    pub insertion_point: Option<String>,
}

/// Composable predicate evaluated against a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CustomMatcher {
    /// Match if the named response (or request) header is present.
    HeaderPresent {
        name: String,
        #[serde(default)]
        response: bool,
    },
    /// Match if the named header value matches the regex.
    HeaderMatches {
        name: String,
        pattern: String,
        #[serde(default)]
        response: bool,
    },
    /// Match if the body contains the regex.
    BodyMatches {
        pattern: String,
        /// `true` = inspect the response body (default); `false` = request body.
        #[serde(default = "default_true")]
        response: bool,
    },
    /// Match if the full URL matches the regex (`scheme://host:port/path?query`).
    UrlMatches { pattern: String },
    /// Match if the response status is within `[min, max]`.
    StatusInRange { min: u16, max: u16 },
    /// Match if the HTTP method equals `method` (case-insensitive).
    MethodIs { method: String },
    /// All children must match.
    All { all: Vec<CustomMatcher> },
    /// At least one child must match.
    Any { any: Vec<CustomMatcher> },
    /// Negate the inner matcher.
    Not { not: Box<CustomMatcher> },
}

fn default_true() -> bool { true }

impl CustomMatcher {
    /// Evaluate against a transaction. Returns `false` for malformed
    /// matchers (e.g. invalid regex) — scanner rules are not supposed
    /// to crash the engine.
    pub fn evaluate(&self, tx: &Transaction) -> bool {
        match self {
            Self::HeaderPresent { name, response } => {
                if *response {
                    tx.response.as_ref().map(|r| r.headers.has(name)).unwrap_or(false)
                } else {
                    tx.request.headers.has(name)
                }
            }
            Self::HeaderMatches { name, pattern, response } => {
                let Ok(re) = Regex::new(pattern) else { return false; };
                let value = if *response {
                    tx.response.as_ref().and_then(|r| r.headers.get(name)).map(|s| s.to_string())
                } else {
                    tx.request.headers.get(name).map(|s| s.to_string())
                };
                match value {
                    Some(v) => re.is_match(&v),
                    None => false,
                }
            }
            Self::BodyMatches { pattern, response } => {
                let Ok(re) = Regex::new(pattern) else { return false; };
                let body = if *response {
                    tx.response.as_ref().map(|r| r.body.as_slice()).unwrap_or(&[])
                } else {
                    tx.request.body.as_slice()
                };
                re.is_match(&String::from_utf8_lossy(body))
            }
            Self::UrlMatches { pattern } => {
                let Ok(re) = Regex::new(pattern) else { return false; };
                re.is_match(&tx.request.url())
            }
            Self::StatusInRange { min, max } => {
                tx.response.as_ref().map(|r| r.status >= *min && r.status <= *max).unwrap_or(false)
            }
            Self::MethodIs { method } => {
                tx.request.method.eq_ignore_ascii_case(method)
            }
            Self::All { all } => all.iter().all(|m| m.evaluate(tx)),
            Self::Any { any } => any.iter().any(|m| m.evaluate(tx)),
            Self::Not { not } => !not.evaluate(tx),
        }
    }
}

/// Validate that a rule's embedded regexes parse. Returns `Ok(())` or
/// the offending pattern.
pub fn validate_rule(r: &CustomPassiveRule) -> Result<(), String> {
    if r.id.is_empty() {
        return Err("rule id is required".into());
    }
    if r.title.is_empty() {
        return Err("rule title is required".into());
    }
    validate_matcher(&r.when)
}

fn validate_matcher(m: &CustomMatcher) -> Result<(), String> {
    match m {
        CustomMatcher::HeaderMatches { pattern, .. }
        | CustomMatcher::BodyMatches { pattern, .. }
        | CustomMatcher::UrlMatches { pattern } => {
            Regex::new(pattern).map_err(|e| format!("bad regex `{pattern}`: {e}"))?;
            Ok(())
        }
        CustomMatcher::All { all } => {
            for c in all {
                validate_matcher(c)?;
            }
            Ok(())
        }
        CustomMatcher::Any { any } => {
            for c in any {
                validate_matcher(c)?;
            }
            Ok(())
        }
        CustomMatcher::Not { not } => validate_matcher(not),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::{Request, Response, Transaction};

    fn mk_tx(method: &str, url: &str, resp_headers: &[(&str, &str)], status: u16, body: &str) -> Transaction {
        let req = Request::new(method, url).unwrap();
        let mut t = Transaction::new(req);
        let mut r = Response::new(status);
        for (n, v) in resp_headers {
            r.headers.add((*n).to_string(), (*v).to_string());
        }
        r.set_text(body);
        t.response = Some(r);
        t
    }

    #[test]
    fn header_present_matches_response() {
        let tx = mk_tx("GET", "http://x/", &[("X-Custom", "yes")], 200, "");
        let m = CustomMatcher::HeaderPresent { name: "X-Custom".into(), response: true };
        assert!(m.evaluate(&tx));
        let m = CustomMatcher::HeaderPresent { name: "Missing".into(), response: true };
        assert!(!m.evaluate(&tx));
    }

    #[test]
    fn header_matches_regex() {
        let tx = mk_tx("GET", "http://x/", &[("Server", "Apache/2.4.59 (Debian)")], 200, "");
        let m = CustomMatcher::HeaderMatches {
            name: "Server".into(),
            pattern: r"Apache/[\d.]+ \(Debian\)".into(),
            response: true,
        };
        assert!(m.evaluate(&tx));
    }

    #[test]
    fn body_matches_regex() {
        let tx = mk_tx("GET", "http://x/", &[], 200, r#"{"debug":true,"secret_key":"abc"}"#);
        let m = CustomMatcher::BodyMatches { pattern: r#""debug"\s*:\s*true"#.into(), response: true };
        assert!(m.evaluate(&tx));
    }

    #[test]
    fn status_in_range() {
        let tx = mk_tx("GET", "http://x/", &[], 500, "");
        let m = CustomMatcher::StatusInRange { min: 500, max: 599 };
        assert!(m.evaluate(&tx));
        let m = CustomMatcher::StatusInRange { min: 400, max: 499 };
        assert!(!m.evaluate(&tx));
    }

    #[test]
    fn all_requires_every_match() {
        let tx = mk_tx("POST", "http://x/", &[("Content-Type", "application/json")], 200, "{}");
        let m = CustomMatcher::All {
            all: vec![
                CustomMatcher::MethodIs { method: "POST".into() },
                CustomMatcher::HeaderMatches {
                    name: "Content-Type".into(),
                    pattern: r"^application/json".into(),
                    response: true,
                },
            ],
        };
        assert!(m.evaluate(&tx));
        // One mismatch collapses the AND.
        let m = CustomMatcher::All {
            all: vec![
                CustomMatcher::MethodIs { method: "GET".into() },
                CustomMatcher::StatusInRange { min: 200, max: 299 },
            ],
        };
        assert!(!m.evaluate(&tx));
    }

    #[test]
    fn not_inverts() {
        let tx = mk_tx("GET", "http://x/", &[("X", "1")], 200, "");
        let m = CustomMatcher::Not {
            not: Box::new(CustomMatcher::HeaderPresent { name: "X".into(), response: true }),
        };
        assert!(!m.evaluate(&tx));
    }

    #[test]
    fn invalid_regex_returns_false() {
        let tx = mk_tx("GET", "http://x/", &[], 200, "");
        let m = CustomMatcher::BodyMatches { pattern: r"(unclosed".into(), response: true };
        assert!(!m.evaluate(&tx));
    }

    #[test]
    fn validate_rejects_bad_regex() {
        let r = CustomPassiveRule {
            id: "r1".into(),
            title: "t".into(),
            severity: "low".into(),
            confidence: "firm".into(),
            description: String::new(),
            remediation: String::new(),
            references: vec![],
            cwe: vec![],
            when: CustomMatcher::BodyMatches { pattern: r"(".into(), response: true },
            insertion_point: None,
        };
        assert!(validate_rule(&r).is_err());
    }
}
