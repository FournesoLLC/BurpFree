//! BChecks-style declarative active-scan rules.
//!
//! A BCheck is a small YAML document that describes an active probe:
//! which paths to try against a target, what to look for in the
//! response, and what finding to emit when a match occurs. The format
//! is intentionally close enough to Burp's BCheck syntax that a reader
//! who knows one can follow the other, without being a bit-for-bit
//! clone — this is BurpFree's own interpretation of the shape.
//!
//! Example (`project/bchecks/admin-exposure.yaml`):
//!
//! ```yaml
//! metadata:
//!   name: Admin / backup path exposure
//!   description: Checks for well-known admin, backup, and VCS paths.
//!   author: BurpFree
//! severity: medium
//! confidence: tentative
//! candidates:
//!   - /admin
//!   - /admin/login
//!   - /.git/config
//!   - /.env
//! match:
//!   status: [200, 301, 302, 401, 403]
//!   body_contains_any: [admin, login, "ref:", DB_, APP_KEY]
//! report:
//!   title: "Interesting path exposed: {path}"
//!   description: "Path {path} returned status {status}."
//!   remediation: "If this path exists in production, lock it down."
//! ```
//!
//! Loader scans a `bchecks/` directory and returns parsed [`BCheck`]
//! documents. The runner sends a GET for every (host, candidate_path)
//! combination via the shared `HttpClient`, scope-gated, and matches
//! the response against the `match` conditions. Each hit produces a
//! `Finding` whose fields are templated from the match context.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use burpfree_core::scope::Scope;
use burpfree_core::traffic::Request;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use super::scanner::{Confidence, Finding, Severity};
use crate::client::{HttpClient, HttpClientConfig};

/// Top-level BCheck document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BCheck {
    pub metadata: Metadata,
    #[serde(default)]
    pub severity: SeverityLabel,
    #[serde(default)]
    pub confidence: ConfidenceLabel,
    /// Paths appended to the target host for each probe.
    #[serde(default)]
    pub candidates: Vec<String>,
    pub r#match: MatchRules,
    pub report: ReportTemplate,
    /// If present, path to the source YAML file. Set by the loader so
    /// errors can point back at the right file.
    #[serde(default)]
    pub source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Response-matching conditions. All sub-conditions in the same rule
/// must be true for the rule to fire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchRules {
    /// Status must be one of these values (or empty = don't filter on status).
    #[serde(default)]
    pub status: Vec<u16>,
    /// Body must contain all of these literals.
    #[serde(default)]
    pub body_contains_all: Vec<String>,
    /// Body must contain at least one of these literals.
    #[serde(default)]
    pub body_contains_any: Vec<String>,
    /// Body must NOT contain any of these literals.
    #[serde(default)]
    pub body_contains_none: Vec<String>,
    /// Header must be present (name match, case-insensitive).
    #[serde(default)]
    pub headers_present: Vec<String>,
    /// Minimum response body length in bytes.
    #[serde(default)]
    pub min_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLabel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for SeverityLabel {
    fn default() -> Self {
        SeverityLabel::Info
    }
}

impl From<SeverityLabel> for Severity {
    fn from(s: SeverityLabel) -> Self {
        match s {
            SeverityLabel::Info => Severity::Info,
            SeverityLabel::Low => Severity::Low,
            SeverityLabel::Medium => Severity::Medium,
            SeverityLabel::High => Severity::High,
            SeverityLabel::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLabel {
    Tentative,
    Firm,
    Certain,
}

impl Default for ConfidenceLabel {
    fn default() -> Self {
        ConfidenceLabel::Tentative
    }
}

impl From<ConfidenceLabel> for Confidence {
    fn from(c: ConfidenceLabel) -> Self {
        match c {
            ConfidenceLabel::Tentative => Confidence::Tentative,
            ConfidenceLabel::Firm => Confidence::Firm,
            ConfidenceLabel::Certain => Confidence::Certain,
        }
    }
}

/// Parse a single YAML document.
pub fn parse(src: &str) -> Result<BCheck> {
    let mut check: BCheck = serde_yaml::from_str(src).context("parsing BCheck YAML")?;
    validate(&check)?;
    check.source_path = None;
    Ok(check)
}

/// Load every `*.yaml` / `*.yml` file in `dir` (recursively).
pub fn load_dir(dir: &Path) -> Vec<(PathBuf, Result<BCheck>)> {
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    for entry in WalkDir::new(dir).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_path_buf();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        let parsed = (|| -> Result<BCheck> {
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let mut c = parse(&src)?;
            c.source_path = Some(path.clone());
            Ok(c)
        })();
        out.push((path, parsed));
    }
    out
}

fn validate(check: &BCheck) -> Result<()> {
    if check.metadata.name.trim().is_empty() {
        return Err(anyhow!("BCheck is missing metadata.name"));
    }
    if check.candidates.is_empty() {
        return Err(anyhow!(
            "BCheck '{}' has no candidates to probe",
            check.metadata.name
        ));
    }
    if check.report.title.trim().is_empty() {
        return Err(anyhow!(
            "BCheck '{}' is missing report.title",
            check.metadata.name
        ));
    }
    Ok(())
}

/// A single probe target reconstituted from a stored transaction.
#[derive(Debug, Clone)]
pub struct TargetHost {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl TargetHost {
    pub fn base_url(&self) -> String {
        if (self.scheme == "https" && self.port == 443) || (self.scheme == "http" && self.port == 80) {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// Runner that evaluates loaded BChecks against a set of targets.
pub struct BCheckRunner {
    client: HttpClient,
    scope: Scope,
    config: BCheckRunConfig,
}

#[derive(Debug, Clone)]
pub struct BCheckRunConfig {
    pub timeout_per_probe: Duration,
    pub honor_scope: bool,
    pub max_probes: usize,
}

impl Default for BCheckRunConfig {
    fn default() -> Self {
        Self {
            timeout_per_probe: Duration::from_secs(10),
            honor_scope: true,
            max_probes: 2_000,
        }
    }
}

impl BCheckRunner {
    pub fn new(http: HttpClientConfig, scope: Scope, config: BCheckRunConfig) -> Self {
        Self {
            client: HttpClient::new(http),
            scope,
            config,
        }
    }

    /// Run every check against every unique target. Returns findings in
    /// order of discovery; errors on individual probes are logged via
    /// `tracing` but don't abort the sweep.
    pub async fn run(&self, checks: &[BCheck], targets: &[TargetHost]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut probes_done = 0usize;
        'outer: for check in checks {
            for target in targets {
                for candidate in &check.candidates {
                    if probes_done >= self.config.max_probes {
                        tracing::warn!(
                            "BCheck sweep hit max_probes={}; truncating",
                            self.config.max_probes
                        );
                        break 'outer;
                    }
                    probes_done += 1;
                    let url = format!("{}{}", target.base_url(), candidate);
                    let req = match Request::new("GET", &url) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!(error = %e, url = %url, "bad probe URL");
                            continue;
                        }
                    };
                    if self.config.honor_scope && !self.scope.is_in_scope(&req) {
                        continue;
                    }
                    match tokio::time::timeout(
                        self.config.timeout_per_probe,
                        self.client.send(&req),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => {
                            if let Some(f) =
                                evaluate_match(check, target, candidate, &resp)
                            {
                                findings.push(f);
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, url = %url, "probe error");
                        }
                        Err(_) => {
                            tracing::debug!(url = %url, "probe timeout");
                        }
                    }
                }
            }
        }
        findings
    }
}

fn evaluate_match(
    check: &BCheck,
    target: &TargetHost,
    candidate: &str,
    resp: &burpfree_core::traffic::Response,
) -> Option<Finding> {
    let rules = &check.r#match;
    let body = resp.text();
    let body_lower = body.to_ascii_lowercase();

    if !rules.status.is_empty() && !rules.status.contains(&resp.status) {
        return None;
    }
    for needle in &rules.body_contains_all {
        if !body_lower.contains(&needle.to_ascii_lowercase()) {
            return None;
        }
    }
    if !rules.body_contains_any.is_empty() {
        let hit = rules
            .body_contains_any
            .iter()
            .any(|n| body_lower.contains(&n.to_ascii_lowercase()));
        if !hit {
            return None;
        }
    }
    for needle in &rules.body_contains_none {
        if body_lower.contains(&needle.to_ascii_lowercase()) {
            return None;
        }
    }
    for name in &rules.headers_present {
        if !resp.headers.has(name) {
            return None;
        }
    }
    if let Some(min) = rules.min_body_bytes {
        if resp.body.len() < min {
            return None;
        }
    }

    let url = format!("{}{}", target.base_url(), candidate);
    let title = template(&check.report.title, target, candidate, resp);
    let description = template(&check.report.description, target, candidate, resp);
    let evidence = format!(
        "{} returned HTTP {} ({} bytes). First 200 bytes of body:\n{}",
        url,
        resp.status,
        body.len(),
        snippet(&body, 200),
    );

    let mut f = Finding::new(
        &format!("bcheck:{}", slugify(&check.metadata.name)),
        &title,
        check.severity.into(),
        check.confidence.into(),
    );
    f.description = description;
    f.remediation = check.report.remediation.clone();
    f.references = check.report.references.clone();
    f.cwe = check.report.cwe.clone();
    f.evidence = evidence;
    f.insertion_point = Some(format!("path={candidate}"));
    Some(f)
}

fn template(src: &str, target: &TargetHost, candidate: &str, resp: &burpfree_core::traffic::Response) -> String {
    src.replace("{path}", candidate)
        .replace("{host}", &target.host)
        .replace("{url}", &format!("{}{}", target.base_url(), candidate))
        .replace("{status}", &resp.status.to_string())
}

fn snippet(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push_str("…");
    }
    out
}

fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Build the complete probe target list from a collection of stored
/// transactions by deduplicating `(scheme, host, port)` tuples.
pub fn targets_from<I>(sources: I) -> Vec<TargetHost>
where
    I: IntoIterator<Item = (String, String, u16)>,
{
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (scheme, host, port) in sources {
        let key = format!("{scheme}://{host}:{port}");
        if seen.insert(key) {
            out.push(TargetHost { scheme, host, port });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::headers::Headers;
    use burpfree_core::traffic::Response;

    fn admin_check() -> BCheck {
        parse(
            r#"metadata:
  name: Admin exposure
  author: BurpFree
severity: medium
confidence: tentative
candidates:
  - /admin
  - /admin/login
match:
  status: [200, 301, 302]
  body_contains_any: [admin, login]
report:
  title: "Admin path exposed: {path}"
  description: "Path {path} on {host} returned {status}."
  remediation: "Lock down admin endpoints."
"#,
        )
        .unwrap()
    }

    fn resp(status: u16, body: &str) -> Response {
        let mut r = Response::new(status);
        r.set_text(body);
        r
    }

    #[test]
    fn parses_minimal_valid_yaml() {
        let c = admin_check();
        assert_eq!(c.metadata.name, "Admin exposure");
        assert_eq!(c.candidates.len(), 2);
        assert!(c.r#match.body_contains_any.contains(&"admin".to_string()));
    }

    #[test]
    fn missing_name_fails_validation() {
        let err = parse(
            r#"metadata:
  name: ""
candidates: [/x]
match: {}
report:
  title: "x"
"#,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("metadata.name"), "got: {err}");
    }

    #[test]
    fn status_filter_matches() {
        let c = admin_check();
        let r = resp(200, "<html>admin login</html>");
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        let f = evaluate_match(&c, &t, "/admin", &r).expect("should fire");
        assert_eq!(f.title, "Admin path exposed: /admin");
        assert!(f.description.contains("x.local"));
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn status_filter_rejects() {
        let c = admin_check();
        let r = resp(404, "not found");
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        assert!(evaluate_match(&c, &t, "/admin", &r).is_none());
    }

    #[test]
    fn body_contains_any_rejects_missing() {
        let c = admin_check();
        let r = resp(200, "<html>welcome home</html>");
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        assert!(evaluate_match(&c, &t, "/admin", &r).is_none());
    }

    #[test]
    fn headers_present_requirement() {
        let c = parse(
            r#"metadata:
  name: Set-Cookie leak
candidates: [/x]
match:
  status: [200]
  headers_present: [Set-Cookie]
report:
  title: "cookie leak at {path}"
"#,
        )
        .unwrap();
        let mut r = resp(200, "ok");
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        assert!(evaluate_match(&c, &t, "/x", &r).is_none(), "no cookie -> no finding");

        r.headers = Headers::new();
        r.headers.add("Set-Cookie", "sid=1");
        assert!(evaluate_match(&c, &t, "/x", &r).is_some());
    }

    #[test]
    fn body_contains_none_blocks_fire() {
        let c = parse(
            r#"metadata:
  name: Must not say maintenance
candidates: [/x]
match:
  status: [200]
  body_contains_none: [maintenance, under construction]
report:
  title: "live at {path}"
"#,
        )
        .unwrap();
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        assert!(evaluate_match(&c, &t, "/x", &resp(200, "under construction")).is_none());
        assert!(evaluate_match(&c, &t, "/x", &resp(200, "live site")).is_some());
    }

    #[test]
    fn targets_from_dedups() {
        let v = targets_from(vec![
            ("https".into(), "a".into(), 443),
            ("https".into(), "a".into(), 443),
            ("http".into(), "a".into(), 80),
            ("https".into(), "b".into(), 443),
        ]);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn slugify_handles_mixed_name() {
        assert_eq!(slugify("Admin / backup exposure"), "admin-backup-exposure");
    }

    #[test]
    fn template_substitutes_placeholders() {
        let t = TargetHost {
            scheme: "https".into(),
            host: "x.local".into(),
            port: 443,
        };
        let r = resp(200, "");
        let s = template(
            "The path {path} on {host} ({url}) returned {status}.",
            &t,
            "/admin",
            &r,
        );
        assert_eq!(
            s,
            "The path /admin on x.local (https://x.local/admin) returned 200."
        );
    }
}
