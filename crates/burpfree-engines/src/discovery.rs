//! Content Discovery — path brute-forcer for a known host.
//!
//! Picks a wordlist and sweeps the target with GETs for each entry,
//! classifying the response. "Interesting" responses are the ones
//! whose status is not 404 (and not a sham-404: a 200 whose body
//! matches the control-baseline body obtained by hitting a
//! deliberately random path first).
//!
//! Results are returned as a `Vec<DiscoveryHit>` and are intended to
//! be persisted into the project history by the caller, tagged
//! `content-discovery` so they're easy to spot and filter on later.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use burpfree_core::traffic::{Request, Response};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::{HttpClient, HttpClientConfig};

/// Default wordlist, embedded at compile time. Roughly 110 entries
/// covering common admin / API / backup / framework paths.
pub const DEFAULT_WORDLIST: &str = include_str!("discovery_common.txt");

/// Target of a discovery run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl DiscoveryTarget {
    pub fn base_url(&self) -> String {
        if (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80)
        {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// Runtime parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub concurrency: usize,
    pub per_request_timeout_ms: u64,
    /// Hard cap on probes per run.
    pub max_probes: usize,
    /// Include 403s as hits. Default: true (gives us "forbidden means
    /// something is there").
    pub include_forbidden: bool,
    /// Skip responses whose status + body-length match the sham-404
    /// baseline, even if the status != 404.
    pub detect_soft_404: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            concurrency: 6,
            per_request_timeout_ms: 8_000,
            max_probes: 2_000,
            include_forbidden: true,
            detect_soft_404: true,
        }
    }
}

/// One accepted hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryHit {
    pub path: String,
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub content_type: Option<String>,
    pub elapsed_ms: u64,
    pub title: Option<String>,
    /// Full request bytes (useful to persist to history).
    pub request_wire: Vec<u8>,
    /// Full response bytes (useful to persist to history).
    pub response_wire: Vec<u8>,
}

/// Rolled-up summary for the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoverySummary {
    pub probes_sent: usize,
    pub probes_errored: usize,
    pub hits: usize,
    pub elapsed_ms: u64,
}

pub struct DiscoveryRunner {
    client: HttpClient,
    config: DiscoveryConfig,
}

impl DiscoveryRunner {
    pub fn new(http: HttpClientConfig, config: DiscoveryConfig) -> Self {
        Self {
            client: HttpClient::new(http),
            config,
        }
    }

    /// Parse a wordlist blob into trimmed, non-empty, non-comment lines.
    pub fn parse_wordlist(src: &str) -> Vec<String> {
        src.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect()
    }

    /// Run the sweep. Returns the hits + a summary.
    pub async fn run(
        &self,
        target: &DiscoveryTarget,
        words: &[String],
    ) -> (Vec<DiscoveryHit>, DiscoverySummary) {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(self.config.per_request_timeout_ms);
        let sem = Arc::new(Semaphore::new(self.config.concurrency.max(1)));

        // Baseline sham-404: hit a random path to learn what the server
        // returns for "definitely absent".
        let baseline = if self.config.detect_soft_404 {
            Some(self.probe_baseline(target, timeout).await)
        } else {
            None
        };

        let capped: Vec<&String> = words.iter().take(self.config.max_probes).collect();
        let mut tasks = Vec::with_capacity(capped.len());
        for w in capped {
            let sem = sem.clone();
            let client = self.client.clone();
            let target = target.clone();
            let word = w.clone();
            let baseline = baseline.clone();
            let include_forbidden = self.config.include_forbidden;
            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                let (hit, err) =
                    probe_one(&client, &target, &word, timeout, baseline.as_ref(), include_forbidden)
                        .await;
                (hit, err)
            }));
        }

        let mut hits = Vec::new();
        let mut errored = 0usize;
        let total = tasks.len();
        for t in tasks {
            match t.await {
                Ok((Some(hit), _)) => hits.push(hit),
                Ok((None, true)) => errored += 1,
                _ => {}
            }
        }
        let summary = DiscoverySummary {
            probes_sent: total,
            probes_errored: errored,
            hits: hits.len(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
        (hits, summary)
    }

    async fn probe_baseline(
        &self,
        target: &DiscoveryTarget,
        timeout: Duration,
    ) -> BaselineProfile {
        let garbage: String = {
            let mut rng = rand::thread_rng();
            (0..24).map(|_| (b'a' + rng.gen_range(0..26)) as char).collect()
        };
        let url = format!("{}/{}", target.base_url(), garbage);
        let req = match Request::new("GET", &url) {
            Ok(r) => r,
            Err(_) => {
                return BaselineProfile::default();
            }
        };
        match tokio::time::timeout(timeout, self.client.send(&req)).await {
            Ok(Ok(resp)) => BaselineProfile {
                status: Some(resp.status),
                body_len: Some(resp.body.len()),
            },
            _ => BaselineProfile::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct BaselineProfile {
    status: Option<u16>,
    body_len: Option<usize>,
}

async fn probe_one(
    client: &HttpClient,
    target: &DiscoveryTarget,
    word: &str,
    timeout: Duration,
    baseline: Option<&BaselineProfile>,
    include_forbidden: bool,
) -> (Option<DiscoveryHit>, bool) {
    let normalized = normalize_path(word);
    let url = format!("{}{}", target.base_url(), normalized);
    let req = match Request::new("GET", &url) {
        Ok(r) => r,
        Err(_) => return (None, true),
    };
    let req_wire = req.to_wire_bytes();
    match tokio::time::timeout(timeout, client.send(&req)).await {
        Ok(Ok(resp)) => {
            if !is_interesting(&resp, baseline, include_forbidden) {
                return (None, false);
            }
            let resp_wire = resp.to_wire_bytes();
            let hit = DiscoveryHit {
                path: normalized,
                url,
                status: resp.status,
                length: resp.body.len(),
                content_type: resp.headers.content_type().map(|s| s.to_string()),
                elapsed_ms: resp.elapsed_ms,
                title: extract_title(&resp),
                request_wire: req_wire,
                response_wire: resp_wire,
            };
            (Some(hit), false)
        }
        Ok(Err(_)) | Err(_) => (None, true),
    }
}

fn is_interesting(resp: &Response, baseline: Option<&BaselineProfile>, include_forbidden: bool) -> bool {
    // 404 is uninteresting unless the baseline differs.
    if resp.status == 404 {
        return false;
    }
    if resp.status == 403 && !include_forbidden {
        return false;
    }
    // Sham-404 detection: 200 whose body length matches the baseline's
    // 404 body is almost certainly the same "catchall" page.
    if let Some(b) = baseline {
        if let (Some(bs), Some(bl)) = (b.status, b.body_len) {
            if resp.status == bs && resp.body.len() == bl {
                return false;
            }
        }
    }
    true
}

fn normalize_path(word: &str) -> String {
    let w = word.trim_start_matches('/');
    format!("/{w}")
}

fn extract_title(resp: &Response) -> Option<String> {
    let body = resp.text();
    let bytes = body.as_bytes();
    if bytes.len() > 262_144 {
        return None;
    }
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title>")? + gt;
    let raw = &body[gt..end];
    let decoded = raw
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .trim()
        .to_string();
    if decoded.is_empty() {
        None
    } else {
        Some(if decoded.chars().count() > 160 {
            let truncated: String = decoded.chars().take(160).collect();
            format!("{truncated}…")
        } else {
            decoded
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wordlist_strips_comments_and_blanks() {
        let src = "# comment\n\n/admin\nlogin  \n\n#another\napi/v1\n";
        let v = DiscoveryRunner::parse_wordlist(src);
        assert_eq!(v, vec!["/admin", "login", "api/v1"]);
    }

    #[test]
    fn normalize_path_adds_leading_slash() {
        assert_eq!(normalize_path("admin"), "/admin");
        assert_eq!(normalize_path("/admin"), "/admin");
        assert_eq!(normalize_path("//admin"), "/admin");
    }

    #[test]
    fn target_base_url_omits_default_ports() {
        let t = DiscoveryTarget {
            scheme: "https".into(),
            host: "x".into(),
            port: 443,
        };
        assert_eq!(t.base_url(), "https://x");
        let t = DiscoveryTarget {
            scheme: "http".into(),
            host: "x".into(),
            port: 8080,
        };
        assert_eq!(t.base_url(), "http://x:8080");
    }

    #[test]
    fn interesting_filters_404_and_sham_404() {
        let mut r = Response::new(404);
        assert!(!is_interesting(&r, None, true));

        r = Response::new(200);
        r.set_text("ok");
        assert!(is_interesting(&r, None, true));

        // Sham-404: status + length match baseline.
        let baseline = BaselineProfile {
            status: Some(200),
            body_len: Some(r.body.len()),
        };
        assert!(!is_interesting(&r, Some(&baseline), true));
    }

    #[test]
    fn forbidden_toggle_respects_config() {
        let r = Response::new(403);
        assert!(is_interesting(&r, None, true));
        assert!(!is_interesting(&r, None, false));
    }

    #[test]
    fn extracts_title() {
        let mut r = Response::new(200);
        r.set_text("<html><head><title> Welcome Home </title></head></html>");
        assert_eq!(extract_title(&r).as_deref(), Some("Welcome Home"));
    }

    #[test]
    fn builtin_wordlist_parses() {
        let v = DiscoveryRunner::parse_wordlist(DEFAULT_WORDLIST);
        assert!(v.len() > 60, "builtin wordlist has {} entries, want > 60", v.len());
        assert!(v.iter().any(|s| s == "admin"));
    }
}
