//! Shared network configuration pieces.
//!
//! `HostOverrides` is a shared map `hostname → ip` that the proxy and
//! HTTP client consult before DNS. Entries are enabled individually so
//! the user can keep a library of overrides without applying them all
//! at once. Only exact hostname matches (case-insensitive) resolve; the
//! IP is validated at insert time so a bad entry can't poison lookups.

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOverride {
    pub enabled: bool,
    pub hostname: String,
    pub ip: String,
}

/// Thread-safe, cheap-to-clone override registry.
#[derive(Clone, Default)]
pub struct HostOverrides {
    inner: Arc<RwLock<Vec<HostOverride>>>,
}

impl std::fmt::Debug for HostOverrides {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostOverrides")
            .field("len", &self.inner.read().len())
            .finish()
    }
}

impl HostOverrides {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(entries: Vec<HostOverride>) -> Self {
        let s = Self::default();
        *s.inner.write() = entries;
        s
    }

    /// Replace the entire set of overrides.
    pub fn set_all(&self, entries: Vec<HostOverride>) {
        *self.inner.write() = entries;
    }

    pub fn snapshot(&self) -> Vec<HostOverride> {
        self.inner.read().clone()
    }

    /// Return the override IP for `host` if any enabled entry matches
    /// (case-insensitive). The IP string is validated to be a parseable
    /// `IpAddr`; invalid entries are skipped.
    pub fn resolve(&self, host: &str) -> Option<String> {
        let host_lc = host.to_ascii_lowercase();
        let g = self.inner.read();
        for e in g.iter() {
            if !e.enabled {
                continue;
            }
            if e.hostname.to_ascii_lowercase() == host_lc && e.ip.parse::<IpAddr>().is_ok() {
                return Some(e.ip.clone());
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// What to do when the HTTP client encounters a 3xx with a Location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowRedirectPolicy {
    /// Never follow redirects. The 3xx response is returned as-is.
    Never,
    /// Follow only when the redirect target has the same host:port as
    /// the current request.
    OnSite,
    /// Follow only when the redirect target is in scope (callers must
    /// provide a scope predicate; otherwise this behaves like OnSite).
    InScope,
    /// Follow any redirect, up to the configured hop count.
    Always,
}

impl Default for FollowRedirectPolicy {
    fn default() -> Self {
        Self::Never
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_exact_case_insensitive() {
        let o = HostOverrides::load(vec![HostOverride {
            enabled: true,
            hostname: "Example.COM".into(),
            ip: "127.0.0.1".into(),
        }]);
        assert_eq!(o.resolve("example.com").as_deref(), Some("127.0.0.1"));
        assert_eq!(o.resolve("other.com"), None);
    }

    #[test]
    fn disabled_entries_do_not_resolve() {
        let o = HostOverrides::load(vec![HostOverride {
            enabled: false,
            hostname: "example.com".into(),
            ip: "127.0.0.1".into(),
        }]);
        assert_eq!(o.resolve("example.com"), None);
    }

    #[test]
    fn invalid_ip_is_skipped() {
        let o = HostOverrides::load(vec![HostOverride {
            enabled: true,
            hostname: "example.com".into(),
            ip: "not an ip".into(),
        }]);
        assert_eq!(o.resolve("example.com"), None);
    }

    #[test]
    fn redirect_policy_default_never() {
        assert_eq!(FollowRedirectPolicy::default(), FollowRedirectPolicy::Never);
    }
}
