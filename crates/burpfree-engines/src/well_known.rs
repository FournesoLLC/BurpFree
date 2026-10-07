//! Well-known resource auto-import for Target.
//!
//! When an operator picks up a new host, Burp fetches `/robots.txt`
//! and `/sitemap.xml` to seed its site map with URLs the target has
//! advertised to search engines. This module mirrors that behavior:
//! two small HTTP GETs plus pure parsers for both formats. A 404 or
//! connection error on either file is NOT fatal — the import returns
//! whatever partial result it got and records the problem in
//! `WellKnownReport::errors` so the UI can show it inline without
//! aborting.
//!
//! Public surface:
//! * [`parse_robots_txt`] — pure parser for an `/robots.txt` body.
//! * [`parse_sitemap_xml`] — pure parser for a `/sitemap.xml` body
//!   (handles both URL-set and sitemap-index formats).
//! * [`import`] — async entry point: fetches both files via an
//!   [`HttpClient`] and returns a [`WellKnownReport`].

use std::collections::BTreeSet;

use burpfree_core::traffic::Request;
use serde::{Deserialize, Serialize};

use crate::client::HttpClient;

/// Aggregated result of a well-known import. Everything is serde-
/// friendly so the Tauri cmd can hand the whole thing to the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WellKnownReport {
    /// Normalised absolute URL the import was anchored to (scheme +
    /// host[:port] with no path).
    pub base_url: String,
    /// Parsed `/robots.txt` contents — `None` when the fetch failed
    /// or returned a non-2xx. The parse errors (not fetch errors)
    /// land in `errors`.
    pub robots: Option<RobotsParsed>,
    /// Parsed `/sitemap.xml` contents — same `None` semantics as
    /// `robots`.
    pub sitemap: Option<SitemapParsed>,
    /// Raw robots.txt body (first 64 KB), useful for showing in a
    /// collapsible panel. `None` when the fetch failed.
    pub robots_body: Option<String>,
    /// Raw sitemap.xml body (first 64 KB). `None` when the fetch
    /// failed.
    pub sitemap_body: Option<String>,
    /// Union of every URL discovered — `<loc>` entries from the
    /// sitemap plus any `Sitemap:` references from robots.txt
    /// (operators pick one and recurse manually). Sorted +
    /// de-duplicated so the UI can list them cleanly.
    pub discovered_urls: Vec<String>,
    /// Non-fatal errors: 4xx / 5xx fetches, parse hiccups, bad
    /// base URL, etc. Empty when everything went smoothly.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RobotsParsed {
    /// User-agent sections observed in the file (unique, in order).
    pub user_agents: Vec<String>,
    /// `Disallow:` paths (association with user-agent dropped —
    /// operators care about the complete surface a search bot was
    /// told to avoid, which is where the juicy stuff tends to live).
    pub disallow: Vec<String>,
    /// `Allow:` paths — same flattening logic.
    pub allow: Vec<String>,
    /// `Sitemap:` URLs referenced from robots.txt. Absolute as per
    /// RFC 9309; our parser passes them through unchanged.
    pub sitemaps: Vec<String>,
    /// Any `Crawl-delay:` or vendor-specific directives we
    /// recognised but didn't model structurally.
    pub extras: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SitemapParsed {
    /// URLs from `<url><loc>…</loc></url>` entries.
    pub urls: Vec<String>,
    /// URLs from `<sitemap><loc>…</loc></sitemap>` entries — i.e.
    /// a sitemap-index pointing at other sitemap files. The import
    /// doesn't recurse automatically; the UI lists these so the
    /// operator can re-run the import against each one.
    pub nested: Vec<String>,
}

/// Parse an `/robots.txt` body. Tolerant of CRLF/LF, BOM, mixed
/// case (`User-Agent:` / `user-agent:`), and inline comments. Lines
/// without a colon are ignored.
pub fn parse_robots_txt(body: &str) -> RobotsParsed {
    let mut out = RobotsParsed::default();
    let mut seen_ua: BTreeSet<String> = BTreeSet::new();
    // Strip a leading BOM if present.
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    for raw in body.lines() {
        // Trim trailing `#` comments and surrounding whitespace.
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = match line.find(':') {
            Some(i) => (line[..i].trim(), line[i + 1..].trim()),
            None => continue,
        };
        if value.is_empty() && !name.eq_ignore_ascii_case("Allow") && !name.eq_ignore_ascii_case("Disallow") {
            continue;
        }
        match name.to_ascii_lowercase().as_str() {
            "user-agent" => {
                if seen_ua.insert(value.to_string()) {
                    out.user_agents.push(value.to_string());
                }
            }
            "disallow" => {
                // Empty Disallow is spec-defined to mean "allow all"
                // for this UA — we record the literal line so the UI
                // can still render it.
                out.disallow.push(value.to_string());
            }
            "allow" => {
                out.allow.push(value.to_string());
            }
            "sitemap" => {
                out.sitemaps.push(value.to_string());
            }
            "crawl-delay" | "request-rate" | "visit-time" | "noindex" | "host" => {
                out.extras.push(format!("{name}: {value}"));
            }
            _ => {
                // Unknown directive — keep it in extras so the
                // operator sees everything the file carried without
                // pretending we understood it.
                out.extras.push(format!("{name}: {value}"));
            }
        }
    }
    out
}

/// Parse a `/sitemap.xml` body. Minimal XML walker — no namespaces,
/// no attributes — handles both URL-set (`<url><loc>`) and
/// sitemap-index (`<sitemap><loc>`) formats. Robust against the
/// usual XML wire-format differences (CDATA sections, mixed case
/// element names, extra whitespace) via case-insensitive tag
/// matching + explicit CDATA stripping. Returns empty on malformed
/// input rather than erroring — the caller already treats this as
/// best-effort auto-discovery.
pub fn parse_sitemap_xml(body: &str) -> SitemapParsed {
    let mut out = SitemapParsed::default();
    // Strip comments to simplify the state machine. XML comments
    // can't nest and don't carry entity references we care about.
    let stripped = strip_xml_comments(body);
    // Walk the body collecting `<loc>…</loc>` entries, tracking
    // whether the enclosing element is `<url>` or `<sitemap>`.
    let bytes = stripped.as_bytes();
    let mut i = 0;
    // Context stack: last-seen opening tag name (lowercased, no
    // namespace prefix).
    let mut parent_url = false;
    let mut parent_sitemap = false;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let close = match memchr_fallback(&bytes[i..], b'>') {
            Some(idx) => i + idx,
            None => break,
        };
        let tag_raw = &stripped[i + 1..close];
        i = close + 1;
        if tag_raw.is_empty() {
            continue;
        }
        let (name, is_close) = parse_tag_name(tag_raw);
        let name_lc = name.to_ascii_lowercase();
        // Strip optional namespace prefix: `ns:url` → `url`.
        let name_bare = match name_lc.rfind(':') {
            Some(p) => &name_lc[p + 1..],
            None => &name_lc,
        };
        match name_bare {
            "url" => parent_url = !is_close,
            "sitemap" => parent_sitemap = !is_close,
            "loc" if !is_close => {
                // Grab the text between <loc> and </loc>, decoding
                // any CDATA wrapper and basic XML entities.
                let text_end = match find_subslice(&bytes[i..], b"</") {
                    Some(idx) => i + idx,
                    None => break,
                };
                let raw_text = &stripped[i..text_end];
                let url = decode_xml_text(raw_text).trim().to_string();
                if !url.is_empty() {
                    if parent_url {
                        out.urls.push(url);
                    } else if parent_sitemap {
                        out.nested.push(url);
                    } else {
                        // No parent context — fallback to urls so
                        // we don't silently drop valid URLs from a
                        // malformed-but-recoverable file.
                        out.urls.push(url);
                    }
                }
                // Advance past the next `</loc>` close tag.
                if let Some(idx) = find_subslice(&bytes[i..], b">") {
                    i += idx + 1;
                }
            }
            _ => {}
        }
    }
    out
}

/// Fetch the two well-known files for `base_url`, parse them, and
/// return an aggregated report. `base_url` must be an absolute URL
/// (`scheme://host[:port]`); any path/query/fragment is stripped.
/// Errors on the base URL are reported in `errors` and the empty
/// report returned — the UI can still show the context.
pub async fn import(client: &HttpClient, base_url: &str) -> WellKnownReport {
    let mut report = WellKnownReport::default();
    let normalised = match normalise_base(base_url) {
        Ok(u) => u,
        Err(e) => {
            report.errors.push(format!("bad base URL: {e}"));
            report.base_url = base_url.to_string();
            return report;
        }
    };
    report.base_url = normalised.clone();

    // --- /robots.txt ---------------------------------------------------
    let robots_url = format!("{normalised}/robots.txt");
    match fetch_text(client, &robots_url).await {
        Ok((Some(body), status)) => {
            if (200..300).contains(&status) {
                let parsed = parse_robots_txt(&body);
                // Promote absolute Sitemap: refs into discovered_urls
                // AND surface them under RobotsParsed.sitemaps for
                // the detail view.
                for s in &parsed.sitemaps {
                    push_unique(&mut report.discovered_urls, s.clone());
                }
                report.robots = Some(parsed);
                report.robots_body = Some(truncate(body, 65_536));
            } else {
                report
                    .errors
                    .push(format!("robots.txt returned {status}"));
            }
        }
        Ok((None, status)) => {
            // Non-200 with no body — unusual but keep going.
            report
                .errors
                .push(format!("robots.txt returned {status} with empty body"));
        }
        Err(e) => {
            report.errors.push(format!("robots.txt fetch failed: {e}"));
        }
    }

    // --- /sitemap.xml --------------------------------------------------
    let sitemap_url = format!("{normalised}/sitemap.xml");
    match fetch_text(client, &sitemap_url).await {
        Ok((Some(body), status)) => {
            if (200..300).contains(&status) {
                let parsed = parse_sitemap_xml(&body);
                for u in &parsed.urls {
                    push_unique(&mut report.discovered_urls, u.clone());
                }
                for u in &parsed.nested {
                    push_unique(&mut report.discovered_urls, u.clone());
                }
                report.sitemap = Some(parsed);
                report.sitemap_body = Some(truncate(body, 65_536));
            } else {
                report
                    .errors
                    .push(format!("sitemap.xml returned {status}"));
            }
        }
        Ok((None, status)) => {
            report
                .errors
                .push(format!("sitemap.xml returned {status} with empty body"));
        }
        Err(e) => {
            report.errors.push(format!("sitemap.xml fetch failed: {e}"));
        }
    }

    // Final sort so UI output is stable regardless of discovery order.
    report.discovered_urls.sort();
    report.discovered_urls.dedup();
    report
}

// ------------------------- helpers -----------------------------------

async fn fetch_text(client: &HttpClient, url: &str) -> anyhow::Result<(Option<String>, u16)> {
    let req = Request::new("GET", url)?;
    let resp = client.send(&req).await?;
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    Ok((if body.is_empty() { None } else { Some(body) }, resp.status))
}

/// Reduce a URL to `scheme://host[:port]`, dropping path / query /
/// fragment. Rejects URLs without a scheme or host.
fn normalise_base(input: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(input.trim())?;
    let scheme = url.scheme();
    if !matches!(scheme, "http" | "https") {
        anyhow::bail!("only http/https schemes are supported, got `{scheme}`");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;
    let mut out = format!("{scheme}://{host}");
    if let Some(p) = url.port() {
        // Skip the default port in the output to keep /robots.txt
        // URLs clean (http://x/ not http://x:80/).
        let default = matches!((scheme, p), ("http", 80) | ("https", 443));
        if !default {
            out.push(':');
            out.push_str(&p.to_string());
        }
    }
    Ok(out)
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    s.truncate(max);
    s.push_str("…");
    s
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|e| e == &s) {
        v.push(s);
    }
}

fn strip_xml_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() && &bytes[i..i + 4] == b"<!--" {
            match find_subslice(&bytes[i + 4..], b"-->") {
                Some(idx) => i = i + 4 + idx + 3,
                None => break,
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn memchr_fallback(hay: &[u8], c: u8) -> Option<usize> {
    hay.iter().position(|&b| b == c)
}

fn parse_tag_name(raw: &str) -> (&str, bool) {
    // Peel self-closing (`<br/>`) and close-tag (`</foo>`) markers.
    let (is_close, stripped) = if let Some(rest) = raw.strip_prefix('/') {
        (true, rest)
    } else {
        (false, raw)
    };
    // Trim trailing `/` or whitespace and attribute block.
    let stripped = stripped.trim_end_matches('/').trim();
    let name = stripped
        .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .next()
        .unwrap_or("");
    (name, is_close)
}

fn decode_xml_text(raw: &str) -> String {
    // Strip the common `<![CDATA[…]]>` wrapper if present.
    let inner = if let Some(rest) = raw.trim_start().strip_prefix("<![CDATA[") {
        rest.rsplit_once("]]>").map(|(a, _)| a).unwrap_or(rest)
    } else {
        raw
    };
    // Decode the five XML core entities. We skip &NNN; numeric
    // references — URLs almost never need them.
    inner
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_txt_basic() {
        let body = r#"
# comment
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/news-sitemap.xml

User-agent: Googlebot
Disallow:
Crawl-delay: 10
"#;
        let r = parse_robots_txt(body);
        // Two UA sections, in file order.
        assert_eq!(r.user_agents, vec!["*".to_string(), "Googlebot".to_string()]);
        // Three Disallows across both sections (one is empty = allow-all).
        assert_eq!(r.disallow.len(), 3);
        assert!(r.disallow.iter().any(|s| s == "/admin"));
        assert!(r.disallow.iter().any(|s| s == "/private/"));
        assert!(r.disallow.iter().any(|s| s.is_empty()));
        // One Allow.
        assert_eq!(r.allow, vec!["/public"]);
        // Two sitemap refs captured verbatim.
        assert_eq!(r.sitemaps.len(), 2);
        assert!(r
            .sitemaps
            .iter()
            .any(|s| s == "https://example.com/news-sitemap.xml"));
        // Crawl-delay surfaces in extras.
        assert!(r.extras.iter().any(|s| s.contains("Crawl-delay")));
    }

    #[test]
    fn robots_txt_handles_bom_and_comments() {
        let body = "\u{feff}# header\nUser-agent: *   # inline comment\nDisallow: /x\n";
        let r = parse_robots_txt(body);
        assert_eq!(r.user_agents, vec!["*"]);
        assert_eq!(r.disallow, vec!["/x"]);
    }

    #[test]
    fn sitemap_xml_urlset() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/a</loc>
    <lastmod>2026-01-01</lastmod>
  </url>
  <url>
    <loc><![CDATA[https://example.com/b?q=1&amp;r=2]]></loc>
  </url>
  <url><loc>https://example.com/c</loc></url>
</urlset>
"#;
        let s = parse_sitemap_xml(body);
        assert_eq!(s.urls.len(), 3);
        assert!(s.urls.contains(&"https://example.com/a".to_string()));
        // CDATA wrapper peeled; entity decoded.
        assert!(s.urls.contains(&"https://example.com/b?q=1&r=2".to_string()));
        assert!(s.urls.contains(&"https://example.com/c".to_string()));
        assert!(s.nested.is_empty());
    }

    #[test]
    fn sitemap_index_separates_nested() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap-posts.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap-pages.xml</loc>
  </sitemap>
</sitemapindex>"#;
        let s = parse_sitemap_xml(body);
        assert!(s.urls.is_empty());
        assert_eq!(s.nested.len(), 2);
        assert!(s
            .nested
            .contains(&"https://example.com/sitemap-posts.xml".to_string()));
    }

    #[test]
    fn normalise_base_strips_path_and_default_port() {
        assert_eq!(normalise_base("http://a.local/some/path").unwrap(), "http://a.local");
        assert_eq!(normalise_base("https://a.local:443/").unwrap(), "https://a.local");
        assert_eq!(normalise_base("http://a.local:8080/x").unwrap(), "http://a.local:8080");
        assert!(normalise_base("ftp://a.local").is_err());
        assert!(normalise_base("not a url").is_err());
    }

    /// End-to-end import against a tiny stub listener that serves
    /// both files. Confirms the aggregate report contains the
    /// expected URLs + records errors non-fatally when the sitemap
    /// 404s.
    #[tokio::test]
    async fn import_against_stub_listener() {
        use crate::client::HttpClientConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap();
                    let line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let (status, body): (u16, String) = match path.as_str() {
                        "/robots.txt" => (
                            200,
                            "User-agent: *\nDisallow: /admin\nSitemap: http://127.0.0.1/sitemap-extra.xml\n".to_string(),
                        ),
                        "/sitemap.xml" => (
                            200,
                            "<?xml version=\"1.0\"?><urlset><url><loc>http://127.0.0.1/page-a</loc></url><url><loc>http://127.0.0.1/page-b</loc></url></urlset>".to_string(),
                        ),
                        _ => (404, "nope".to_string()),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        let client = HttpClient::new(HttpClientConfig::default());
        let report = import(&client, &format!("http://127.0.0.1:{}/", addr.port())).await;

        // Both files parsed.
        assert!(report.robots.is_some(), "robots.txt should parse");
        assert!(report.sitemap.is_some(), "sitemap.xml should parse");

        let robots = report.robots.as_ref().unwrap();
        assert_eq!(robots.user_agents, vec!["*"]);
        assert!(robots.disallow.iter().any(|s| s == "/admin"));
        assert_eq!(robots.sitemaps.len(), 1);

        let sitemap = report.sitemap.as_ref().unwrap();
        assert_eq!(sitemap.urls.len(), 2);

        // Combined discovered list is sorted + de-duplicated: 2 from
        // sitemap <loc>s + 1 Sitemap: ref from robots.
        assert_eq!(report.discovered_urls.len(), 3);
        assert_eq!(
            report.discovered_urls,
            vec![
                "http://127.0.0.1/page-a".to_string(),
                "http://127.0.0.1/page-b".to_string(),
                "http://127.0.0.1/sitemap-extra.xml".to_string(),
            ]
        );
        assert!(report.errors.is_empty(), "no errors expected; got {:?}", report.errors);

        // Second run against a port with nothing listening — connect
        // refuses. The import must stay non-fatal: empty parsed
        // results, both fetch failures captured in errors.
        let dead_report =
            import(&client, "http://127.0.0.1:1/").await;
        assert!(dead_report.robots.is_none());
        assert!(dead_report.sitemap.is_none());
        assert_eq!(dead_report.errors.len(), 2);
    }
}
