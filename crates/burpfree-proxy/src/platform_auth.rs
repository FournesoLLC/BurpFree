//! Platform-authentication registry — mirror of Burp's
//! `Settings → Network → Platform authentication` page.
//!
//! When the proxy forwards a request and the upstream replies with
//! `401 WWW-Authenticate: Basic realm="…"`, the server consults
//! this list for a matching credential (host pattern + scheme) and
//! re-dispatches the request ONCE with a precomputed `Authorization`
//! header. The result is that the operator's browser or tool sees
//! only the authenticated response, matching Burp's behaviour where
//! platform-auth is invisible to the client.
//!
//! Scope for R73:
//!
//! * `Basic` — fully wired (base64-encode `user:pass`, inject
//!   `Authorization: Basic <token>`).
//! * `Digest` — reserved variant on `AuthScheme`; the matcher skips
//!   it so a stray config value doesn't crash the proxy. Full digest
//!   handshake (nonce / qop / opaque / cnonce / nc counter) ships
//!   later.
//! * `Ntlm` / `Negotiate` — not represented; deferred until an
//!   SSPI binding is available.
//!
//! The matcher is intentionally forgiving: the host pattern is a
//! case-insensitive substring match on the request's host (same
//! shape as `tls_passthrough`), empty / whitespace patterns never
//! match (guard against operator typos), and disabled rows are
//! skipped. Multiple rules can match; the first-enabled wins. That
//! leaves ordering as the operator's lever when overlapping
//! wordlists target the same host under different ports or paths.

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Credential kinds. `Basic` is the only one honoured by the retry
/// path in R73; the other variants round-trip through serde cleanly
/// so an operator's config survives a future Digest implementation
/// without rewriting the project file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    Basic,
    Digest,
}

/// One configured platform-auth row. Matches Burp's dialog fields:
/// `Destination host` → `host_pattern`, `Type` → `scheme`,
/// `Username` + `Password`. The password is stored plaintext in the
/// project file (Burp does the same under its project encryption);
/// operators who care should rely on OS-level file protection or
/// Burp-equivalent project encryption, which is out of scope here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAuthCredential {
    pub host_pattern: String,
    pub scheme: AuthScheme,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl PlatformAuthCredential {
    /// Returns true if this credential's `host_pattern` applies to
    /// `host`. Empty / whitespace-only patterns never match — same
    /// defensive guard the TLS pass-through list uses so a stray
    /// blank row doesn't silently authenticate every target.
    pub fn matches_host(&self, host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let p = self.host_pattern.trim().to_ascii_lowercase();
        if p.is_empty() {
            return false;
        }
        host.to_ascii_lowercase().contains(&p)
    }
}

/// Walk `creds` in order and return the first entry whose host
/// pattern matches `host`, scheme matches `requested_scheme`, and
/// `enabled` is true. Returns `None` if no credential fits — the
/// caller should surface the original 401 to the client in that
/// case.
pub fn find_match<'a>(
    creds: &'a [PlatformAuthCredential],
    host: &str,
    requested_scheme: AuthScheme,
) -> Option<&'a PlatformAuthCredential> {
    creds
        .iter()
        .find(|c| c.scheme == requested_scheme && c.matches_host(host))
}

/// Parse the primary scheme out of a `WWW-Authenticate` header
/// value. The spec allows multiple challenges comma-separated; we
/// only honour the first one and only when it's a scheme we support.
/// Returns `None` on anything we can't satisfy — Digest / NTLM /
/// Negotiate / Bearer all go here.
pub fn parse_challenge_scheme(www_authenticate: &str) -> Option<AuthScheme> {
    let first = www_authenticate.split(',').next()?.trim();
    let token = first.split_whitespace().next()?;
    match token.to_ascii_lowercase().as_str() {
        "basic" => Some(AuthScheme::Basic),
        "digest" => Some(AuthScheme::Digest),
        _ => None,
    }
}

/// Build the `Authorization: Basic <token>` value for a credential.
/// `token = base64("username:password")` per RFC 7617.
pub fn build_basic_header(username: &str, password: &str) -> String {
    let raw = format!("{username}:{password}");
    let token = B64_STANDARD.encode(raw.as_bytes());
    format!("Basic {token}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(host: &str, user: &str, pw: &str) -> PlatformAuthCredential {
        PlatformAuthCredential {
            host_pattern: host.into(),
            scheme: AuthScheme::Basic,
            username: user.into(),
            password: pw.into(),
            enabled: true,
        }
    }

    #[test]
    fn matcher_is_case_insensitive_substring() {
        let c = basic("api.example", "u", "p");
        assert!(c.matches_host("api.example.com"));
        assert!(c.matches_host("API.example.com"));
        assert!(c.matches_host("www.api.example.net"));
        assert!(!c.matches_host("evil.com"));
    }

    #[test]
    fn matcher_skips_disabled_and_blank() {
        let mut c = basic("api.example", "u", "p");
        c.enabled = false;
        assert!(!c.matches_host("api.example.com"));
        c.enabled = true;
        c.host_pattern = "   ".into();
        assert!(!c.matches_host("api.example.com"));
    }

    #[test]
    fn find_match_returns_first_enabled_scheme_match() {
        let creds = vec![
            // Disabled match — must be skipped.
            {
                let mut c = basic("api.example", "u1", "p1");
                c.enabled = false;
                c
            },
            // Wrong scheme — must be skipped.
            {
                let mut c = basic("api.example", "u2", "p2");
                c.scheme = AuthScheme::Digest;
                c
            },
            // Winning entry.
            basic("api.example", "winner", "secret"),
            // Later Basic match — must NOT override.
            basic("api.example", "later", "nope"),
        ];
        let hit = find_match(&creds, "api.example.com", AuthScheme::Basic).unwrap();
        assert_eq!(hit.username, "winner");
    }

    #[test]
    fn find_match_returns_none_on_no_fit() {
        let creds = vec![basic("api.example", "u", "p")];
        assert!(find_match(&creds, "other.local", AuthScheme::Basic).is_none());
        assert!(find_match(&creds, "api.example.com", AuthScheme::Digest).is_none());
    }

    #[test]
    fn parse_challenge_scheme_handles_realm_and_mixed_case() {
        assert_eq!(
            parse_challenge_scheme("Basic realm=\"api\""),
            Some(AuthScheme::Basic)
        );
        assert_eq!(
            parse_challenge_scheme("BASIC realm=api"),
            Some(AuthScheme::Basic)
        );
        assert_eq!(
            parse_challenge_scheme("Digest realm=\"api\", nonce=\"abc\""),
            Some(AuthScheme::Digest)
        );
        // Multi-challenge: only the first counts.
        assert_eq!(
            parse_challenge_scheme("Negotiate, Basic realm=\"api\""),
            None
        );
        assert_eq!(parse_challenge_scheme("Bearer realm=\"api\""), None);
        assert_eq!(parse_challenge_scheme(""), None);
    }

    #[test]
    fn build_basic_header_encodes_user_pass_colon() {
        // RFC 7617 example: "Aladdin:open sesame" → QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        let h = build_basic_header("Aladdin", "open sesame");
        assert_eq!(h, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        // Empty password still base64-encodes with a trailing colon.
        let h2 = build_basic_header("user", "");
        assert_eq!(h2, "Basic dXNlcjo=");
    }
}
