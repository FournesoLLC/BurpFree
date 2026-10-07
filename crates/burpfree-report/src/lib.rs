//! BurpFree reporting backends.
//!
//! Three formats are supported out of the box:
//!
//! * **HTML**  — a self-contained single-file report.
//! * **JSON**  — the full `StoredFinding` list, ready for machine consumers.
//! * **SARIF 2.1.0** — the OASIS standard; accepted by GitHub Code Scanning,
//!   Azure DevOps, GitLab, SonarQube and most CI pipelines.
//!
//! Every exporter takes the same `ReportContext` and writes to a `Writer`.

use std::io::Write;

use anyhow::Result;
use burpfree_storage::StoredFinding;
use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ReportContext {
    /// Human-readable project name.
    pub project: String,
    /// Absolute path to the project directory (optional).
    pub project_root: Option<String>,
    /// Tool / scanner version string.
    pub tool_version: String,
    /// All findings to include (already filtered as desired).
    pub findings: Vec<StoredFinding>,
}

impl ReportContext {
    pub fn new(project: impl Into<String>, findings: Vec<StoredFinding>) -> Self {
        Self {
            project: project.into(),
            project_root: None,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            findings,
        }
    }
}

pub fn write_json<W: Write>(ctx: &ReportContext, w: &mut W) -> Result<()> {
    let doc = JsonReport {
        project: &ctx.project,
        project_root: ctx.project_root.as_deref(),
        tool: ToolInfo {
            name: "BurpFree",
            version: &ctx.tool_version,
        },
        generated_at: Utc::now().to_rfc3339(),
        count: ctx.findings.len(),
        findings: &ctx.findings,
    };
    serde_json::to_writer_pretty(w, &doc)?;
    Ok(())
}

#[derive(Serialize)]
struct JsonReport<'a> {
    project: &'a str,
    project_root: Option<&'a str>,
    tool: ToolInfo<'a>,
    generated_at: String,
    count: usize,
    findings: &'a [StoredFinding],
}

#[derive(Serialize)]
struct ToolInfo<'a> {
    name: &'a str,
    version: &'a str,
}

pub fn write_html<W: Write>(ctx: &ReportContext, w: &mut W) -> Result<()> {
    let mut counts = std::collections::BTreeMap::new();
    for f in &ctx.findings {
        *counts.entry(f.severity.as_str()).or_insert(0usize) += 1;
    }
    let generated = Utc::now().to_rfc2822();

    writeln!(w, "<!doctype html>")?;
    writeln!(w, "<html lang=\"en\"><head>")?;
    writeln!(w, "<meta charset=\"utf-8\">")?;
    writeln!(
        w,
        "<title>BurpFree report — {}</title>",
        html_escape(&ctx.project)
    )?;
    writeln!(w, "<style>{}</style>", HTML_STYLE)?;
    writeln!(w, "</head><body>")?;
    writeln!(
        w,
        "<header><h1>BurpFree security report</h1>\
         <p class=\"meta\">Project <b>{}</b> · {} finding(s) · generated {}</p></header>",
        html_escape(&ctx.project),
        ctx.findings.len(),
        html_escape(&generated),
    )?;
    writeln!(w, "<section class=\"summary\">")?;
    for sev in ["critical", "high", "medium", "low", "info"] {
        let n = counts.get(sev).copied().unwrap_or(0);
        writeln!(
            w,
            "<div class=\"card sev-{sev}\"><span class=\"n\">{n}</span><span class=\"l\">{sev}</span></div>"
        )?;
    }
    writeln!(w, "</section>")?;

    if ctx.findings.is_empty() {
        writeln!(
            w,
            "<section class=\"empty\">No findings. Either the scope is empty or everything passed.</section>"
        )?;
    } else {
        writeln!(w, "<section class=\"findings\">")?;
        for f in &ctx.findings {
            writeln!(w, "<article class=\"finding sev-{}\">", f.severity)?;
            writeln!(
                w,
                "<h2>{} <small>· {}</small></h2>",
                html_escape(&f.title),
                html_escape(&f.detector)
            )?;
            writeln!(
                w,
                "<p class=\"meta\"><span class=\"badge sev-{}\">{}</span>\
                 <span class=\"badge\">confidence: {}</span>\
                 <span class=\"badge\">status: {}</span>\
                 <span class=\"badge\">verification: {}</span>\
                 <span class=\"badge\">observed × {}</span></p>",
                f.severity, f.severity, f.confidence, f.status, f.verification, f.observation_count
            )?;
            if !f.description.is_empty() {
                writeln!(w, "<h3>Description</h3><p>{}</p>", html_escape(&f.description))?;
            }
            if let Some(ins) = &f.insertion_point {
                if !ins.is_empty() {
                    writeln!(w, "<h3>Insertion point</h3><pre>{}</pre>", html_escape(ins))?;
                }
            }
            if !f.evidence.is_empty() {
                writeln!(w, "<h3>Evidence</h3><pre>{}</pre>", html_escape(&f.evidence))?;
            }
            if !f.remediation.is_empty() {
                writeln!(w, "<h3>Remediation</h3><p>{}</p>", html_escape(&f.remediation))?;
            }
            if !f.references.is_empty() {
                writeln!(w, "<h3>References</h3><ul>")?;
                for r in &f.references {
                    writeln!(w, "<li><a href=\"{0}\">{0}</a></li>", html_escape(r))?;
                }
                writeln!(w, "</ul>")?;
            }
            if !f.tags.is_empty() {
                writeln!(
                    w,
                    "<p>Tags: {}</p>",
                    f.tags
                        .iter()
                        .map(|t| format!("<span class=\"badge\">{}</span>", html_escape(t)))
                        .collect::<Vec<_>>()
                        .join(" ")
                )?;
            }
            if let Some(tid) = f.transaction_id {
                writeln!(w, "<p class=\"meta\">Transaction id: {tid}</p>")?;
            }
            writeln!(w, "</article>")?;
        }
        writeln!(w, "</section>")?;
    }

    writeln!(w, "<footer>Generated by BurpFree {}.</footer>", env!("CARGO_PKG_VERSION"))?;
    writeln!(w, "</body></html>")?;
    Ok(())
}

const HTML_STYLE: &str = r#"
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #1a1b1e; }
header { background: #1e1f22; color: #fff; padding: 20px 32px; }
header h1 { margin: 0 0 4px 0; font-weight: 600; font-size: 22px; }
header .meta { margin: 0; color: #c8ccd4; font-size: 12px; }
.summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; padding: 20px 32px; background: #fff; border-bottom: 1px solid #e2e4e9; }
.card { background: #fafbfc; border: 1px solid #e2e4e9; border-radius: 4px; padding: 10px 14px; display: flex; flex-direction: column; }
.card .n { font-size: 22px; font-weight: 700; }
.card .l { font-size: 11px; letter-spacing: 1px; text-transform: uppercase; color: #656a73; margin-top: 4px; }
.card.sev-critical { border-left: 4px solid #c92a2a; }
.card.sev-high     { border-left: 4px solid #e8742c; }
.card.sev-medium   { border-left: 4px solid #f0a633; }
.card.sev-low      { border-left: 4px solid #4bbf6b; }
.card.sev-info     { border-left: 4px solid #868e96; }
.findings { padding: 20px 32px; }
.finding { background: #fff; border: 1px solid #e2e4e9; border-radius: 4px; padding: 16px 20px; margin-bottom: 16px; border-left: 4px solid #868e96; }
.finding.sev-critical { border-left-color: #c92a2a; }
.finding.sev-high     { border-left-color: #e8742c; }
.finding.sev-medium   { border-left-color: #f0a633; }
.finding.sev-low      { border-left-color: #4bbf6b; }
.finding h2 { font-size: 15px; margin: 0 0 6px 0; }
.finding h2 small { color: #656a73; font-weight: 400; font-size: 12px; }
.finding h3 { font-size: 11px; letter-spacing: 1px; text-transform: uppercase; color: #656a73; margin: 14px 0 4px 0; }
.finding pre { background: #0e1116; color: #f0f3f8; padding: 10px; border-radius: 3px; overflow: auto; font-size: 12px; }
.badge { display: inline-block; background: #eef0f3; border: 1px solid #d9dce3; border-radius: 10px; padding: 1px 8px; font-size: 11px; margin-right: 4px; color: #40444c; }
.badge.sev-critical { background: #fdecec; color: #c92a2a; border-color: #f5b5b5; }
.badge.sev-high     { background: #fbe8d8; color: #a1491a; border-color: #f0bf96; }
.badge.sev-medium   { background: #fcf1d6; color: #8c6816; border-color: #ecd396; }
.badge.sev-low      { background: #e7f5ea; color: #2b7a3f; border-color: #b2dbb9; }
.badge.sev-info     { background: #eaedf2; color: #40444c; border-color: #cfd4dd; }
.empty { padding: 40px; text-align: center; color: #656a73; }
footer { padding: 16px 32px; color: #656a73; font-size: 11px; text-align: center; }
"#;

/// Write a SARIF 2.1.0 log (one run, one tool).
///
/// Compatible with GitHub Code Scanning / GitLab SAST / Azure DevOps
/// consumers.
pub fn write_sarif<W: Write>(ctx: &ReportContext, w: &mut W) -> Result<()> {
    let rules_map: std::collections::BTreeMap<String, SarifRule> = ctx
        .findings
        .iter()
        .map(|f| {
            (
                f.detector.clone(),
                SarifRule {
                    id: f.detector.clone(),
                    name: f.detector.clone(),
                    short_description: SarifMessage { text: f.title.clone() },
                    full_description: SarifMessage {
                        text: if f.description.is_empty() { f.title.clone() } else { f.description.clone() },
                    },
                    help: SarifMessage {
                        text: if f.remediation.is_empty() { "See evidence.".into() } else { f.remediation.clone() },
                    },
                    default_configuration: SarifLevel::from_severity(&f.severity).into(),
                    help_uri: f.references.first().cloned(),
                    properties: SarifRuleProperties { tags: f.tags.clone() },
                },
            )
        })
        .collect();
    let rules: Vec<SarifRule> = rules_map.into_values().collect();

    let results: Vec<SarifResult> = ctx
        .findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.detector.clone(),
            level: SarifLevel::from_severity(&f.severity),
            message: SarifMessage {
                text: if f.evidence.is_empty() {
                    f.title.clone()
                } else {
                    format!("{} — evidence: {}", f.title, f.evidence)
                },
            },
            properties: SarifResultProperties {
                severity: f.severity.clone(),
                confidence: f.confidence.clone(),
                status: f.status.clone(),
                verification: f.verification.clone(),
                tags: f.tags.clone(),
                references: f.references.clone(),
            },
            fingerprints: SarifFingerprints {
                burpfree_v1: f.fingerprint.clone(),
            },
            locations: Vec::new(),
        })
        .collect();

    let doc = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "BurpFree".into(),
                    version: ctx.tool_version.clone(),
                    information_uri: "https://github.com/burpfree/burpfree".into(),
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_writer_pretty(w, &doc)?;
    Ok(())
}

/// Markdown report — GitHub-flavoured syntax, one section per
/// finding, severity emoji + a per-severity summary table on top.
/// Fits in a GitHub issue body or a Teams/Slack post without any
/// extra tooling. Mirrors Burp's "Export → Markdown" affordance that
/// consultancies lean on for bug-report hand-off.
/// Emit a RFC 4180 CSV with one header row and one row per finding.
/// Columns map 1:1 to the `StoredFinding` fields operators care
/// about for triage spreadsheets: id / ts_iso / detector / severity /
/// confidence / title / description / evidence / remediation /
/// status / verification / tags / references / insertion_point /
/// observation_count / fingerprint.
///
/// Mirrors Burp Pro's "Issue → Export → CSV" affordance that triage
/// teams use to filter + sort in Excel / Google Sheets. Fields with
/// commas, quotes, or newlines are quoted; internal quotes are
/// doubled per RFC 4180. Tags + references are joined with `; `
/// inside a single cell so one finding stays on one row.
pub fn write_csv<W: Write>(ctx: &ReportContext, w: &mut W) -> Result<()> {
    // Header row — ordered to match a triage spreadsheet workflow:
    // id first (sort key), then timing + taxonomy, then prose, then
    // provenance (status/verification/tags/references), then
    // fingerprint for dedupe references.
    writeln!(
        w,
        "id,ts_iso,detector,severity,confidence,title,description,evidence,remediation,status,verification,tags,references,insertion_point,observation_count,fingerprint"
    )?;
    for f in &ctx.findings {
        let ts_iso = chrono::DateTime::<Utc>::from_timestamp_millis(f.ts_ms)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let tags = f.tags.join("; ");
        let references = f.references.join("; ");
        let insertion = f.insertion_point.as_deref().unwrap_or("");
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            f.id.0,
            csv_field(&ts_iso),
            csv_field(&f.detector),
            csv_field(&f.severity),
            csv_field(&f.confidence),
            csv_field(&f.title),
            csv_field(&f.description),
            csv_field(&f.evidence),
            csv_field(&f.remediation),
            csv_field(&f.status),
            csv_field(&f.verification),
            csv_field(&tags),
            csv_field(&references),
            csv_field(insertion),
            f.observation_count,
            csv_field(&f.fingerprint),
        )?;
    }
    Ok(())
}

/// RFC 4180 field escape: quote when the field contains a comma,
/// quote, CR, or LF; escape internal quotes by doubling. Returns a
/// bare field when no escaping is needed so numeric / short-text
/// cells read cleanly in a terminal.
fn csv_field(s: &str) -> String {
    let needs_quoting =
        s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if !needs_quoting {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('"');
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

pub fn write_markdown<W: Write>(ctx: &ReportContext, w: &mut W) -> Result<()> {
    let mut counts = std::collections::BTreeMap::new();
    for f in &ctx.findings {
        *counts.entry(f.severity.as_str()).or_insert(0usize) += 1;
    }
    let generated = Utc::now().to_rfc2822();
    writeln!(w, "# BurpFree security report — {}", escape_md(&ctx.project))?;
    writeln!(w)?;
    writeln!(w, "- **Project**: `{}`", escape_md_code(&ctx.project))?;
    if let Some(root) = &ctx.project_root {
        writeln!(w, "- **Root**: `{}`", escape_md_code(root))?;
    }
    writeln!(w, "- **Tool**: BurpFree v{}", escape_md_code(&ctx.tool_version))?;
    writeln!(w, "- **Generated**: {}", escape_md(&generated))?;
    writeln!(w, "- **Finding count**: {}", ctx.findings.len())?;
    writeln!(w)?;
    writeln!(w, "## Severity summary")?;
    writeln!(w)?;
    writeln!(w, "| Severity | Count |")?;
    writeln!(w, "| --- | --- |")?;
    for sev in ["critical", "high", "medium", "low", "info"] {
        let n = counts.get(sev).copied().unwrap_or(0);
        writeln!(w, "| {} {} | {} |", severity_emoji(sev), sev, n)?;
    }
    writeln!(w)?;
    if ctx.findings.is_empty() {
        writeln!(w, "## Findings")?;
        writeln!(w)?;
        writeln!(w, "_No findings. Either the scope is empty or everything passed._")?;
        writeln!(w)?;
        return Ok(());
    }
    writeln!(w, "## Findings")?;
    writeln!(w)?;
    for (idx, f) in ctx.findings.iter().enumerate() {
        writeln!(
            w,
            "### {} {}. {} — `{}`",
            severity_emoji(&f.severity),
            idx + 1,
            escape_md(&f.title),
            escape_md_code(&f.detector)
        )?;
        writeln!(w)?;
        writeln!(
            w,
            "- **Severity**: {} {}",
            severity_emoji(&f.severity),
            escape_md(&f.severity)
        )?;
        writeln!(w, "- **Confidence**: {}", escape_md(&f.confidence))?;
        writeln!(w, "- **Status**: {}", escape_md(&f.status))?;
        writeln!(w, "- **Verification**: {}", escape_md(&f.verification))?;
        writeln!(w, "- **Observations**: {}", f.observation_count)?;
        if let Some(tid) = f.transaction_id {
            writeln!(w, "- **Transaction**: #{tid}")?;
        }
        if let Some(ins) = &f.insertion_point {
            if !ins.is_empty() {
                writeln!(w, "- **Insertion point**: `{}`", escape_md_code(ins))?;
            }
        }
        if !f.tags.is_empty() {
            let tags = f
                .tags
                .iter()
                .map(|t| format!("`{}`", escape_md_code(t)))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(w, "- **Tags**: {tags}")?;
        }
        writeln!(w)?;
        if !f.description.is_empty() {
            writeln!(w, "**Description**")?;
            writeln!(w)?;
            writeln!(w, "{}", escape_md(&f.description))?;
            writeln!(w)?;
        }
        if !f.evidence.is_empty() {
            writeln!(w, "**Evidence**")?;
            writeln!(w)?;
            writeln!(w, "```")?;
            // Evidence can be long + carry backticks. Write verbatim
            // but swap stray triple-backticks → three single quotes
            // so the fence stays balanced.
            writeln!(w, "{}", f.evidence.replace("```", "'''"))?;
            writeln!(w, "```")?;
            writeln!(w)?;
        }
        if !f.remediation.is_empty() {
            writeln!(w, "**Remediation**")?;
            writeln!(w)?;
            writeln!(w, "{}", escape_md(&f.remediation))?;
            writeln!(w)?;
        }
        if !f.references.is_empty() {
            writeln!(w, "**References**")?;
            writeln!(w)?;
            for r in &f.references {
                writeln!(w, "- <{}>", escape_md_url(r))?;
            }
            writeln!(w)?;
        }
        if !f.note.is_empty() {
            writeln!(w, "**Note**")?;
            writeln!(w)?;
            writeln!(w, "> {}", escape_md(&f.note).replace('\n', "\n> "))?;
            writeln!(w)?;
        }
        writeln!(w, "---")?;
        writeln!(w)?;
    }
    writeln!(w, "_Generated by BurpFree {}._", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

fn severity_emoji(sev: &str) -> &'static str {
    match sev {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        "info" => "⚪",
        _ => "⚫",
    }
}

/// Escape Markdown control characters in plain-text spans. We keep the
/// list narrow — the big offenders inside titles / descriptions are
/// backticks, pipes (break tables), angle brackets (consumed as HTML
/// tags). Newlines and asterisks are preserved so operators who wrote
/// bulleted descriptions still get bulleted output.
fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' | '`' | '<' | '>' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Escape content inside a backticked inline code span. Only need
/// to deal with the backtick itself — Markdown treats everything
/// else literally. Replace stray backticks with ``\``` so the span
/// doesn't close early.
fn escape_md_code(s: &str) -> String {
    s.replace('`', "\\`")
}

/// Escape content inside angle-bracket URL spans `<...>` — mostly a
/// defence against `>` characters that would end the span prematurely.
fn escape_md_url(s: &str) -> String {
    s.replace('>', "%3E")
}

// --- SARIF type model --------------------------------------------------------

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}
#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}
#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}
#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}
#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    help: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifDefaultConfig,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    properties: SarifRuleProperties,
}
#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
}
#[derive(Serialize)]
struct SarifDefaultConfig {
    level: &'static str,
}
#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: SarifLevel,
    message: SarifMessage,
    properties: SarifResultProperties,
    fingerprints: SarifFingerprints,
    locations: Vec<serde_json::Value>,
}
#[derive(Serialize)]
struct SarifResultProperties {
    severity: String,
    confidence: String,
    status: String,
    verification: String,
    tags: Vec<String>,
    references: Vec<String>,
}
#[derive(Serialize)]
struct SarifFingerprints {
    #[serde(rename = "burpfreeV1")]
    burpfree_v1: String,
}
#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Clone, Copy)]
enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

impl SarifLevel {
    fn from_severity(s: &str) -> Self {
        match s {
            "critical" | "high" => Self::Error,
            "medium" => Self::Warning,
            "low" => Self::Note,
            _ => Self::None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl Serialize for SarifLevel {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl From<SarifLevel> for SarifDefaultConfig {
    fn from(level: SarifLevel) -> Self {
        Self { level: level.as_str() }
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_storage::StoredFinding;

    fn sample_findings() -> Vec<StoredFinding> {
        vec![
            StoredFinding {
                id: 1.into(),
                ts_ms: 1_700_000_000_000,
                detector: "insecure-cookies".into(),
                title: "Session cookie `sid` missing HttpOnly".into(),
                description: "The session cookie should carry HttpOnly.".into(),
                severity: "medium".into(),
                confidence: "firm".into(),
                evidence: "Set-Cookie: sid=abc; Path=/".into(),
                remediation: "Add HttpOnly.".into(),
                fingerprint: "abc123".into(),
                status: "new".into(),
                verification: "unverified".into(),
                tags: vec!["cookie".into()],
                references: vec!["https://owasp.org/www-community/HttpOnly".into()],
                observation_count: 2,
                ..Default::default()
            },
            StoredFinding {
                id: 2.into(),
                ts_ms: 1_700_000_000_000,
                detector: "security-headers".into(),
                title: "Missing security header: Content-Security-Policy".into(),
                severity: "medium".into(),
                confidence: "certain".into(),
                evidence: "status=200".into(),
                remediation: "Define a CSP.".into(),
                fingerprint: "def456".into(),
                status: "new".into(),
                verification: "unverified".into(),
                observation_count: 1,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn json_round_trip() {
        let ctx = ReportContext::new("demo", sample_findings());
        let mut buf = Vec::new();
        write_json(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert!(txt.contains("\"count\": 2"));
        assert!(txt.contains("insecure-cookies"));
    }

    #[test]
    fn html_contains_findings() {
        let ctx = ReportContext::new("demo", sample_findings());
        let mut buf = Vec::new();
        write_html(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert!(txt.starts_with("<!doctype html>"));
        assert!(txt.contains("Session cookie"));
        assert!(txt.contains("sev-medium"));
    }

    #[test]
    fn sarif_structure_matches_schema_essentials() {
        let ctx = ReportContext::new("demo", sample_findings());
        let mut buf = Vec::new();
        write_sarif(&ctx, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"].as_array().unwrap().len(), 1);
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "BurpFree");
        assert_eq!(run["results"].as_array().unwrap().len(), 2);
        assert_eq!(run["results"][0]["level"], "warning");
        assert!(run["results"][0]["fingerprints"]["burpfreeV1"].is_string());
    }

    #[test]
    fn html_escaping_is_safe() {
        let mut findings = sample_findings();
        findings[0].title = "<img src=x onerror=alert(1)>".into();
        let ctx = ReportContext::new("demo", findings);
        let mut buf = Vec::new();
        write_html(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert!(!txt.contains("<img src=x"));
        assert!(txt.contains("&lt;img src=x"));
    }

    #[test]
    fn markdown_renders_findings_with_severity_table() {
        let ctx = ReportContext::new("demo", sample_findings());
        let mut buf = Vec::new();
        write_markdown(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        // Title + metadata block.
        assert!(txt.contains("# BurpFree security report — demo"));
        assert!(txt.contains("**Project**: `demo`"));
        assert!(txt.contains("**Finding count**: 2"));
        // Severity summary table — the two medium findings show up.
        assert!(txt.contains("| 🟡 medium | 2 |"));
        assert!(txt.contains("| 🔴 critical | 0 |"));
        // Per-finding header + fields. Backticks in the title get
        // escaped (so an inline-code span doesn't start where it
        // shouldn't), so we assert on the escaped form.
        assert!(txt.contains("Session cookie \\`sid\\` missing HttpOnly"));
        assert!(txt.contains("**Severity**: 🟡 medium"));
        assert!(txt.contains("**Observations**: 2"));
        // Evidence rendered inside a fenced code block.
        assert!(txt.contains("```\nSet-Cookie: sid=abc; Path=/\n```"));
        // References as angle-bracket URL spans.
        assert!(txt.contains("<https://owasp.org/www-community/HttpOnly>"));
        // Section separator between findings.
        assert_eq!(txt.matches("\n---\n").count(), 2);
    }

    #[test]
    fn markdown_escapes_pipe_and_backticks_in_titles() {
        let mut findings = sample_findings();
        findings[0].title = "Pipe | breaks tables and `code`".into();
        findings[0].evidence = "Triple ``` backticks in evidence".into();
        let ctx = ReportContext::new("demo", findings);
        let mut buf = Vec::new();
        write_markdown(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        // Pipe + backtick in the title must be escaped so the enclosing
        // table doesn't split, and the inline-code span doesn't start.
        assert!(txt.contains("Pipe \\| breaks tables and \\`code\\`"));
        // Triple-backtick inside evidence collapses to triple-quotes so
        // the fence stays balanced — otherwise the following section
        // would render inside the code block.
        assert!(txt.contains("Triple ''' backticks"));
        assert!(!txt.contains("Triple ``` backticks"));
    }

    #[test]
    fn markdown_empty_findings_shows_passing_note() {
        let ctx = ReportContext::new("demo", vec![]);
        let mut buf = Vec::new();
        write_markdown(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert!(txt.contains("**Finding count**: 0"));
        assert!(txt.contains("_No findings. Either the scope is empty or everything passed._"));
    }

    #[test]
    fn csv_header_plus_one_row_per_finding() {
        let ctx = ReportContext::new("demo", sample_findings());
        let mut buf = Vec::new();
        write_csv(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = txt.lines().collect();
        // Header + 2 findings.
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("id,ts_iso,detector,severity,confidence,title"));
        assert!(lines[0].ends_with(",fingerprint"));
        // Row 1: id=1, severity=medium, confidence=firm, title contains
        // a comma so it must be quoted + any internal commas preserved.
        assert!(lines[1].starts_with("1,"));
        assert!(lines[1].contains(",medium,firm,"));
        assert!(lines[1].contains("Set-Cookie: sid=abc; Path=/"));
        // Row 2: id=2, severity=medium, confidence=certain.
        assert!(lines[2].starts_with("2,"));
        assert!(lines[2].contains(",medium,certain,"));
    }

    #[test]
    fn csv_escapes_commas_quotes_and_newlines() {
        let mut findings = sample_findings();
        // Comma-containing title → must be quoted.
        findings[0].title = "GET /foo, POST /bar".into();
        // Quote-containing description → must have internal quotes
        // doubled per RFC 4180.
        findings[0].description = r#"Says "hello world""#.into();
        // Newline-containing evidence → must be quoted so the row
        // doesn't split; the newline stays as-is inside the quoted
        // cell.
        findings[0].evidence = "line1\nline2".into();
        let ctx = ReportContext::new("demo", findings);
        let mut buf = Vec::new();
        write_csv(&ctx, &mut buf).unwrap();
        let txt = String::from_utf8(buf).unwrap();
        // Comma-escape: title cell wrapped in quotes.
        assert!(txt.contains("\"GET /foo, POST /bar\""));
        // Quote-escape: internal `"` becomes `""`.
        assert!(txt.contains("\"Says \"\"hello world\"\"\""));
        // Newline-escape: evidence cell has a literal newline inside
        // the quoted span. Count total top-level rows (header + 2
        // findings = 3) by splitting on the record-boundary we
        // guarantee: `\n` only outside a quoted cell. A naive
        // lines() split would see 4 lines here — that's correct
        // CSV semantics but confirms the newline stayed in-cell.
        assert_eq!(txt.lines().count(), 4);
    }
}
