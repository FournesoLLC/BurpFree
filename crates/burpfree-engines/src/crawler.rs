//! Passive site crawler.
//!
//! Walks HTML responses already in history, extracts link-like URLs
//! (anchors, forms, inline fetch calls, resource references) and
//! returns the candidates the operator hasn't visited yet. No embedded
//! browser is involved — the crawler is deliberately a static scraper
//! so it can run even against archived history.
//!
//! The crawler never issues requests on its own. It produces a
//! `CrawlResult`; the UI decides what to do with the candidates
//! (promote to history via a replay, feed into the Discovery panel,
//! etc.).

use std::collections::{BTreeMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

/// One extracted link candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlCandidate {
    /// Absolute URL after joining with the response's base URL.
    pub url: String,
    /// The source attribute / construct that produced the link
    /// (`a[href]`, `form[action]`, `fetch`, `script[src]`, …). Useful
    /// for the UI to colour the row.
    pub source: String,
    /// URL of the response where the link was found.
    pub referrer: String,
}

/// Aggregated crawl result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrawlResult {
    /// Candidate links grouped by host for the UI tree view.
    pub by_host: BTreeMap<String, Vec<CrawlCandidate>>,
    /// Count of responses the crawler inspected.
    pub pages_scanned: usize,
    /// Count of unique candidate URLs returned.
    pub unique_candidates: usize,
    /// Count of candidate URLs filtered out because they already live
    /// in history / sitemap.
    pub skipped_known: usize,
}

/// Pre-compiled extractors. Each returns the attribute value when the
/// regex matches; the caller joins it with the base URL and classifies
/// it before emitting a candidate.
struct Extractor {
    regex: Regex,
    label: &'static str,
}

static EXTRACTORS: Lazy<Vec<Extractor>> = Lazy::new(|| {
    let patterns: &[(&str, &str)] = &[
        // HTML attributes with URL-shaped values.
        (r#"(?i)<a\b[^>]*\bhref\s*=\s*["']([^"'#\s>]+)"#, "a[href]"),
        (r#"(?i)<form\b[^>]*\baction\s*=\s*["']([^"'\s>]+)"#, "form[action]"),
        (r#"(?i)<link\b[^>]*\bhref\s*=\s*["']([^"'\s>]+)"#, "link[href]"),
        (r#"(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"'\s>]+)"#, "script[src]"),
        (r#"(?i)<iframe\b[^>]*\bsrc\s*=\s*["']([^"'\s>]+)"#, "iframe[src]"),
        (r#"(?i)<img\b[^>]*\bsrc\s*=\s*["']([^"'\s>]+)"#, "img[src]"),
        // JavaScript fetch / axios / XHR patterns.
        (r#"\bfetch\s*\(\s*["']([^"']+)"#, "fetch"),
        (r#"\baxios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)"#, "axios"),
        (r#"\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)"#, "XHR.open"),
    ];
    patterns
        .iter()
        .map(|(p, label)| Extractor {
            regex: Regex::new(p).expect("crawler regex compiles"),
            label,
        })
        .collect()
});

/// Extract every link-like URL from an HTML response body. `base` is
/// the URL that served the body; it is used to resolve relative
/// references.
pub fn extract_links(base: &Url, body: &str) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for ex in EXTRACTORS.iter() {
        for caps in ex.regex.captures_iter(body) {
            let raw = match caps.get(1) {
                Some(m) => m.as_str().trim(),
                None => continue,
            };
            // Drop non-navigable schemes early.
            if raw.starts_with("javascript:")
                || raw.starts_with("mailto:")
                || raw.starts_with("tel:")
                || raw.starts_with("data:")
                || raw.starts_with("about:")
                || raw.starts_with("blob:")
                || raw.is_empty()
                || raw.starts_with('#')
            {
                continue;
            }
            if let Ok(resolved) = base.join(raw) {
                let normalized = normalize(&resolved);
                if seen.insert(normalized.clone()) {
                    out.push((normalized, ex.label));
                }
            }
        }
    }
    out
}

/// Strip the fragment and lower-case the scheme + host so dedup is
/// stable across minor differences.
fn normalize(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    let scheme = u.scheme().to_ascii_lowercase();
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = u.path();
    let query = u.query().map(|q| format!("?{q}")).unwrap_or_default();
    format!("{scheme}://{host}{port}{path}{query}")
}

/// Full crawler run over a batch of HTML pages. The caller supplies the
/// pages (base URL + body) and a set of already-known URLs; the
/// crawler returns de-duplicated candidates grouped by host.
pub fn crawl_batch<'a, I>(pages: I, known: &HashSet<String>) -> CrawlResult
where
    I: IntoIterator<Item = (&'a Url, &'a str)>,
{
    let mut result = CrawlResult::default();
    let mut emitted: HashSet<String> = HashSet::new();

    for (base, body) in pages {
        result.pages_scanned += 1;
        let links = extract_links(base, body);
        for (url, source) in links {
            if known.contains(&url) {
                result.skipped_known += 1;
                continue;
            }
            if !emitted.insert(url.clone()) {
                continue;
            }
            let host = Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_else(|| "(unknown)".into());
            result
                .by_host
                .entry(host)
                .or_default()
                .push(CrawlCandidate {
                    url,
                    source: source.into(),
                    referrer: base.as_str().into(),
                });
        }
    }
    result.unique_candidates = emitted.len();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/app/page.html").unwrap()
    }

    #[test]
    fn finds_anchor_href() {
        let html = r#"<a href="/next">next</a>"#;
        let out = extract_links(&base(), html);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "https://example.com/next");
        assert_eq!(out[0].1, "a[href]");
    }

    #[test]
    fn resolves_relative_paths() {
        let html = r#"<a href="../sibling">x</a><a href="./deeper">y</a>"#;
        let out = extract_links(&base(), html);
        let urls: Vec<_> = out.iter().map(|(u, _)| u.as_str()).collect();
        assert!(urls.contains(&"https://example.com/sibling"));
        assert!(urls.contains(&"https://example.com/app/deeper"));
    }

    #[test]
    fn skips_non_navigable_schemes() {
        let html = r##"
            <a href="javascript:void(0)">js</a>
            <a href="mailto:x@y.com">m</a>
            <a href="tel:+1">t</a>
            <a href="#anchor">anch</a>
            <a href="/real">r</a>
        "##;
        let out = extract_links(&base(), html);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "https://example.com/real");
    }

    #[test]
    fn finds_form_actions() {
        let html = r#"<form action="/submit" method="post"></form>"#;
        let out = extract_links(&base(), html);
        assert_eq!(out[0].1, "form[action]");
    }

    #[test]
    fn finds_fetch_calls() {
        let body = r#"
            const data = await fetch("/api/users?limit=10");
            axios.get('/api/orders')
        "#;
        let out = extract_links(&base(), body);
        let urls: Vec<_> = out.iter().map(|(u, _)| u.as_str()).collect();
        assert!(urls.contains(&"https://example.com/api/users?limit=10"));
        assert!(urls.contains(&"https://example.com/api/orders"));
    }

    #[test]
    fn finds_xhr_open() {
        let body = r#"xhr.open("POST", "/api/legacy", true);"#;
        let out = extract_links(&base(), body);
        let urls: Vec<_> = out.iter().map(|(u, _)| u.as_str()).collect();
        assert!(urls.contains(&"https://example.com/api/legacy"));
    }

    #[test]
    fn deduplicates_within_page() {
        let html = r##"<a href="/a">x</a><a href="/a">x again</a><a href="/a#frag">frag</a>"##;
        let out = extract_links(&base(), html);
        // The anchor-regex's negated class rejects `#` → `/a#frag` yields `/a`.
        // Combined with normalise() stripping any trailing fragment, all three collapse.
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn crawl_batch_groups_by_host_and_filters_known() {
        let html = r#"
            <a href="https://example.com/users">u</a>
            <a href="https://other.local/x">o</a>
            <a href="https://example.com/already-known">k</a>
        "#;
        let base = Url::parse("https://example.com/").unwrap();
        let known: HashSet<String> = [String::from("https://example.com/already-known")]
            .into_iter()
            .collect();
        let r = crawl_batch(vec![(&base, html)], &known);
        assert_eq!(r.pages_scanned, 1);
        assert_eq!(r.unique_candidates, 2);
        assert_eq!(r.skipped_known, 1);
        assert_eq!(r.by_host.len(), 2);
        assert!(r.by_host.contains_key("example.com"));
        assert!(r.by_host.contains_key("other.local"));
    }

    #[test]
    fn ignores_js_strings_without_fetch_prefix() {
        // Must NOT match random string literals.
        let body = r#"const label = "/not-a-url"; console.log(label);"#;
        let out = extract_links(&base(), body);
        assert!(out.is_empty(), "unexpected matches: {:?}", out);
    }
}
