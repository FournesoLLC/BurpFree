//! Target / Site Map.
//!
//! Builds a tree of hosts → paths from observed transactions.
//! Each node remembers which HTTP methods were seen, status codes,
//! content-types, and whether it's in-scope.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use burpfree_core::ids::TrafficId;
use burpfree_core::traffic::Transaction;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SiteNode {
    pub segment: String,
    #[serde(default)]
    pub children: BTreeMap<String, SiteNode>,
    #[serde(default)]
    pub methods: BTreeSet<String>,
    #[serde(default)]
    pub status_codes: BTreeSet<u16>,
    #[serde(default)]
    pub content_types: BTreeSet<String>,
    #[serde(default)]
    pub transaction_ids: Vec<TrafficId>,
    #[serde(default)]
    pub in_scope: bool,
    #[serde(default)]
    pub comment: String,
}

impl SiteNode {
    pub fn new(segment: impl Into<String>) -> Self {
        Self {
            segment: segment.into(),
            ..Default::default()
        }
    }

    fn insert(&mut self, parts: &[&str], tx: &Transaction) {
        if parts.is_empty() {
            self.methods.insert(tx.request.method.clone());
            if let Some(r) = &tx.response {
                self.status_codes.insert(r.status);
                if let Some(ct) = r.headers.content_type() {
                    self.content_types.insert(ct.to_string());
                }
            }
            self.transaction_ids.push(tx.id);
            self.in_scope = self.in_scope || tx.in_scope;
            return;
        }
        let (head, rest) = parts.split_first().unwrap();
        let child = self
            .children
            .entry(head.to_string())
            .or_insert_with(|| SiteNode::new(*head));
        child.insert(rest, tx);
    }

    pub fn count_endpoints(&self) -> usize {
        let mut n = self.transaction_ids.len();
        for c in self.children.values() {
            n += c.count_endpoints();
        }
        n
    }
}

#[derive(Debug, Default)]
pub struct SiteMap {
    inner: Arc<RwLock<MapInner>>,
}

#[derive(Debug, Default)]
struct MapInner {
    hosts: BTreeMap<String, SiteNode>,
}

impl SiteMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&self, tx: &Transaction) {
        let host_key = format!(
            "{}://{}:{}",
            tx.request.scheme, tx.request.host, tx.request.port
        );
        let mut inner = self.inner.write();
        let node = inner.hosts.entry(host_key.clone()).or_insert_with(|| SiteNode::new(host_key));
        let path = tx.request.path_only();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        node.insert(&parts, tx);
    }

    pub fn hosts(&self) -> Vec<String> {
        self.inner.read().hosts.keys().cloned().collect()
    }

    pub fn get_host(&self, key: &str) -> Option<SiteNode> {
        self.inner.read().hosts.get(key).cloned()
    }

    pub fn root_count(&self) -> usize {
        self.inner.read().hosts.len()
    }

    pub fn total_endpoints(&self) -> usize {
        self.inner
            .read()
            .hosts
            .values()
            .map(|n| n.count_endpoints())
            .sum()
    }

    pub fn snapshot(&self) -> BTreeMap<String, SiteNode> {
        self.inner.read().hosts.clone()
    }

    pub fn clear(&self) {
        self.inner.write().hosts.clear();
    }

    /// Search path contains `q` (case-insensitive); returns (host, path).
    pub fn search(&self, q: &str) -> Vec<(String, String)> {
        let q = q.to_ascii_lowercase();
        let mut out = Vec::new();
        for (host, node) in &self.inner.read().hosts {
            walk(host, "/".to_string(), node, &q, &mut out);
        }
        out
    }
}

fn walk(host: &str, prefix: String, node: &SiteNode, q: &str, out: &mut Vec<(String, String)>) {
    for (segment, child) in &node.children {
        let path = if prefix == "/" {
            format!("/{segment}")
        } else {
            format!("{prefix}/{segment}")
        };
        if path.to_ascii_lowercase().contains(q) {
            out.push((host.to_string(), path.clone()));
        }
        walk(host, path, child, q, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response, Transaction};

    fn mktx(url: &str, method: &str, status: u16) -> Transaction {
        let mut r = Request::new(method, url).unwrap();
        r.source = burpfree_core::traffic::RequestSource::Proxy;
        let mut t = Transaction::new(r);
        let mut resp = Response::new(status);
        resp.headers.set("Content-Type", "application/json");
        t.response = Some(resp);
        t.in_scope = true;
        t
    }

    #[test]
    fn observe_populates_tree() {
        let m = SiteMap::new();
        m.observe(&mktx("http://a.local/users/1", "GET", 200));
        m.observe(&mktx("http://a.local/users/1/profile", "GET", 200));
        m.observe(&mktx("http://a.local/users/2", "DELETE", 204));
        m.observe(&mktx("http://b.local/health", "GET", 200));
        assert_eq!(m.root_count(), 2);
        assert_eq!(m.total_endpoints(), 4);
    }

    #[test]
    fn search_finds_matches() {
        let m = SiteMap::new();
        m.observe(&mktx("http://a.local/users/1", "GET", 200));
        m.observe(&mktx("http://a.local/admin", "GET", 200));
        let hits = m.search("admin");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "/admin");
    }
}
