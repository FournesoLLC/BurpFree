//! Bambda-style predicate DSL for the HTTP history + Site map.
//!
//! Bambdas in Burp are small Java-syntax expressions evaluated per
//! row against a shaped view of the request / response. We reach the
//! same goal with Rhai: an expression compiled once and evaluated
//! per [`StoredSummary`] row.
//!
//! The exposed scope mirrors Burp's `requestResponse.*` surface:
//!
//! ```text
//! method                — "GET", "POST", …
//! host, port, scheme    — connection coordinates
//! url, path, path_only  — URL pieces
//! status                — response status (0 if no response yet)
//! length                — body byte count (-1 if unknown)
//! mime                  — short MIME string ("json", "html", …)
//! content_type          — full Content-Type header
//! elapsed_ms            — round-trip latency
//! title                 — <title> extracted from HTML responses
//! param_count           — number of query + form params
//! in_scope              — whether the row is in the current scope
//! source                — "Proxy", "Repeater", "Intruder", …
//! has_params            — convenience: param_count > 0
//! has_body              — convenience: length > 0
//! comment               — operator note on the row
//! ```
//!
//! The predicate returns `bool`. Any evaluation error (bad syntax,
//! wrong type, timeout) is reported back to the caller — the UI
//! displays it next to the input instead of silently dropping rows.

use std::time::{Duration, Instant};

use burpfree_storage::StoredSummary;
use rhai::{Dynamic, Engine, Map, Scope, AST};
use serde::{Deserialize, Serialize};

/// Resource caps for Bambda evaluations. Significantly tighter than
/// the full script engine because this runs per-row on potentially
/// thousands of history entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BambdaLimits {
    pub max_operations: u64,
    pub expr_depth: usize,
    pub timeout_per_row: Duration,
    pub max_rows: usize,
}

impl Default for BambdaLimits {
    fn default() -> Self {
        Self {
            max_operations: 10_000,
            expr_depth: 16,
            timeout_per_row: Duration::from_millis(50),
            max_rows: 50_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BambdaError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("evaluation error: {0}")]
    Eval(String),
    #[error("expression returned a {0}, expected bool")]
    WrongType(String),
    #[error("expression exceeded per-row timeout")]
    Timeout,
}

/// A compiled Bambda expression. Keep this around if you'll run the
/// same filter against many rows — compilation is the expensive step.
pub struct Compiled {
    /// The engine the AST was compiled against. Kept so the AST
    /// handle stays valid against an engine with identical limits
    /// configuration; a fresh engine is built per-eval below so the
    /// progress callback can own its own `Instant`.
    #[allow(dead_code)]
    engine: Engine,
    ast: AST,
    limits: BambdaLimits,
}

impl Compiled {
    pub fn limits(&self) -> &BambdaLimits {
        &self.limits
    }

    /// Evaluate the compiled expression against a single row.
    pub fn eval(&self, summary: &StoredSummary) -> Result<bool, BambdaError> {
        let mut scope = Scope::new();
        for (k, v) in summary_scope(summary) {
            scope.push_dynamic(k, v);
        }
        let timeout = self.limits.timeout_per_row;
        let start = Instant::now();
        // Rhai's `on_progress` is `Fn + 'static`; we build a fresh
        // engine per call to isolate the deadline rather than share a
        // mutable timer. Compilation is already paid; this is cheap.
        let mut engine = build_engine(&self.limits);
        engine.on_progress(move |_ops| {
            if start.elapsed() > timeout {
                Some(Dynamic::from("burpfree-timeout"))
            } else {
                None
            }
        });
        match engine.eval_ast_with_scope::<Dynamic>(&mut scope, &self.ast) {
            Ok(v) => {
                let type_name = v.type_name();
                if let Ok(b) = v.clone().as_bool() {
                    Ok(b)
                } else if v.is::<i64>() {
                    Ok(v.as_int().unwrap_or(0) != 0)
                } else if v.is::<()>() {
                    Ok(false)
                } else {
                    Err(BambdaError::WrongType(type_name.to_string()))
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("burpfree-timeout") {
                    Err(BambdaError::Timeout)
                } else {
                    Err(BambdaError::Eval(msg))
                }
            }
        }
    }
}

/// Compile a Bambda expression. Returns a [`Compiled`] that can be
/// evaluated repeatedly without re-parsing.
pub fn compile(expression: &str) -> Result<Compiled, BambdaError> {
    compile_with_limits(expression, BambdaLimits::default())
}

/// Compile with explicit resource caps.
pub fn compile_with_limits(expression: &str, limits: BambdaLimits) -> Result<Compiled, BambdaError> {
    let engine = build_engine(&limits);
    let ast = engine
        .compile(expression)
        .map_err(|e| BambdaError::Parse(e.to_string()))?;
    Ok(Compiled {
        engine,
        ast,
        limits,
    })
}

/// Convenience: compile + apply a Bambda to a slice of summaries, in order.
/// Returns `(kept rows, first error if any)`.
pub fn apply(expression: &str, rows: &[StoredSummary]) -> (Vec<StoredSummary>, Option<BambdaError>) {
    apply_with_limits(expression, rows, BambdaLimits::default())
}

pub fn apply_with_limits(
    expression: &str,
    rows: &[StoredSummary],
    limits: BambdaLimits,
) -> (Vec<StoredSummary>, Option<BambdaError>) {
    let cap = limits.max_rows;
    let compiled = match compile_with_limits(expression, limits) {
        Ok(c) => c,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let mut out = Vec::new();
    let mut first_err: Option<BambdaError> = None;
    for row in rows.iter().take(cap) {
        match compiled.eval(row) {
            Ok(true) => out.push(row.clone()),
            Ok(false) => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    (out, first_err)
}

fn build_engine(limits: &BambdaLimits) -> Engine {
    let mut e = Engine::new();
    e.set_max_operations(limits.max_operations);
    e.set_max_expr_depths(limits.expr_depth, limits.expr_depth);
    // Scripts shouldn't allocate forever.
    e.set_max_string_size(16 * 1024);
    e.set_max_array_size(256);
    e.set_max_map_size(256);
    // No module/eval loading. This disables import statements etc.
    e.disable_symbol("eval");
    e.disable_symbol("import");
    e
}

/// Materialise the Rhai scope entries for a stored summary.
fn summary_scope(s: &StoredSummary) -> Vec<(&'static str, Dynamic)> {
    let path_only = s.path.split('?').next().unwrap_or(&s.path).to_string();
    let url = if (s.scheme == "https" && s.port == 443) || (s.scheme == "http" && s.port == 80) {
        format!("{}://{}{}", s.scheme, s.host, s.path)
    } else {
        format!("{}://{}:{}{}", s.scheme, s.host, s.port, s.path)
    };
    let mime_short = short_mime(s.content_type.as_deref());
    let length = s.content_length.map(|v| v as i64).unwrap_or(-1);
    let elapsed = s.elapsed_ms.map(|v| v as i64).unwrap_or(-1);
    let status = s.status.map(|v| v as i64).unwrap_or(0);
    let param_count = s.param_count as i64;
    let title = s.title.clone().unwrap_or_default();

    let mut tags_arr = rhai::Array::new();
    for t in &s.tags {
        tags_arr.push(Dynamic::from(t.clone()));
    }

    let mut req_map = Map::new();
    req_map.insert("method".into(), Dynamic::from(s.method.clone()));
    req_map.insert("scheme".into(), Dynamic::from(s.scheme.clone()));
    req_map.insert("host".into(), Dynamic::from(s.host.clone()));
    req_map.insert("port".into(), Dynamic::from(s.port as i64));
    req_map.insert("path".into(), Dynamic::from(s.path.clone()));
    req_map.insert("path_only".into(), Dynamic::from(path_only.clone()));
    req_map.insert("url".into(), Dynamic::from(url.clone()));
    req_map.insert("param_count".into(), Dynamic::from(param_count));
    req_map.insert("has_params".into(), Dynamic::from(param_count > 0));
    req_map.insert("in_scope".into(), Dynamic::from(s.in_scope));

    let mut resp_map = Map::new();
    resp_map.insert("status".into(), Dynamic::from(status));
    resp_map.insert("length".into(), Dynamic::from(length));
    resp_map.insert("mime".into(), Dynamic::from(mime_short.clone()));
    resp_map.insert(
        "content_type".into(),
        Dynamic::from(s.content_type.clone().unwrap_or_default()),
    );
    resp_map.insert("elapsed_ms".into(), Dynamic::from(elapsed));
    resp_map.insert("title".into(), Dynamic::from(title.clone()));
    resp_map.insert("has_body".into(), Dynamic::from(length > 0));
    resp_map.insert(
        "error".into(),
        Dynamic::from(s.error.clone().unwrap_or_default()),
    );

    vec![
        // Top-level flat view mirrors Burp's Bambda surface so simple
        // predicates stay concise.
        ("method", Dynamic::from(s.method.clone())),
        ("scheme", Dynamic::from(s.scheme.clone())),
        ("host", Dynamic::from(s.host.clone())),
        ("port", Dynamic::from(s.port as i64)),
        ("path", Dynamic::from(s.path.clone())),
        ("path_only", Dynamic::from(path_only)),
        ("url", Dynamic::from(url)),
        ("status", Dynamic::from(status)),
        ("length", Dynamic::from(length)),
        ("mime", Dynamic::from(mime_short)),
        (
            "content_type",
            Dynamic::from(s.content_type.clone().unwrap_or_default()),
        ),
        ("elapsed_ms", Dynamic::from(elapsed)),
        ("title", Dynamic::from(title)),
        ("param_count", Dynamic::from(param_count)),
        ("has_params", Dynamic::from(param_count > 0)),
        ("has_body", Dynamic::from(length > 0)),
        ("in_scope", Dynamic::from(s.in_scope)),
        ("source", Dynamic::from(s.source.clone())),
        ("comment", Dynamic::from(s.comment.clone())),
        ("tags", Dynamic::from(tags_arr)),
        // Nested maps for operators who prefer the longer form.
        ("request", Dynamic::from(req_map)),
        ("response", Dynamic::from(resp_map)),
    ]
}

/// Collapse `application/json; charset=utf-8` → `json`, etc. Matches
/// the shortMime helper used in the UI history table.
fn short_mime(ct: Option<&str>) -> String {
    let ct = match ct {
        Some(s) => s.trim(),
        None => return String::new(),
    };
    let t = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let slash = match t.find('/') {
        Some(i) => i,
        None => return t,
    };
    let sub = &t[slash + 1..];
    if sub == "html" {
        return "html".into();
    }
    if sub == "plain" {
        return "text".into();
    }
    if sub == "javascript" || sub == "x-javascript" {
        return "js".into();
    }
    if sub.ends_with("+json") || sub == "json" {
        return "json".into();
    }
    if sub.ends_with("+xml") || sub == "xml" {
        return "xml".into();
    }
    if sub == "css" {
        return "css".into();
    }
    if sub.starts_with("x-www-form-urlencoded") {
        return "form".into();
    }
    if sub.starts_with("octet-stream") {
        return "bin".into();
    }
    if t.starts_with("image/") {
        return format!("img:{sub}");
    }
    sub.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::ids::TrafficId;

    fn row() -> StoredSummary {
        StoredSummary {
            id: TrafficId::from(42),
            ts_ms: 1,
            method: "POST".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            path: "/api/login?remember=1".into(),
            status: Some(401),
            content_length: Some(321),
            content_type: Some("application/json; charset=utf-8".into()),
            elapsed_ms: Some(84),
            tags: vec!["auth".into()],
            in_scope: true,
            source: "Proxy".into(),
            tls_summary: None,
            comment: "note".into(),
            error: None,
            param_count: 2,
            title: Some("Sign in".into()),
            highlight: None,
            http_version: Some("HTTP/1.1".into()),
        }
    }

    #[test]
    fn flat_scope_matches() {
        let c = compile("method == \"POST\" && status >= 400").unwrap();
        assert!(c.eval(&row()).unwrap());
    }

    #[test]
    fn nested_scope_matches() {
        let c = compile("request.method == \"POST\" && response.status == 401").unwrap();
        assert!(c.eval(&row()).unwrap());
    }

    #[test]
    fn string_helpers_work() {
        let c = compile("host.contains(\"example\") && path.ends_with(\"=1\")").unwrap();
        assert!(c.eval(&row()).unwrap());
    }

    #[test]
    fn in_scope_filter_falses_cleanly() {
        let c = compile("in_scope && mime == \"json\"").unwrap();
        assert!(c.eval(&row()).unwrap());
    }

    #[test]
    fn apply_filters_a_batch() {
        let mut r2 = row();
        r2.method = "GET".into();
        r2.status = Some(200);
        let rows = vec![row(), r2];
        let (kept, err) = apply("status >= 400", &rows);
        assert!(err.is_none());
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].method, "POST");
    }

    #[test]
    fn parse_error_bubbles_up() {
        let err = compile("this is not rhai !! @@").err().unwrap();
        assert!(matches!(err, BambdaError::Parse(_)));
    }

    #[test]
    fn eval_error_bubbles_up() {
        // Call an undefined function.
        let c = compile("not_a_fn()").unwrap();
        let err = c.eval(&row()).err().unwrap();
        assert!(matches!(err, BambdaError::Eval(_)));
    }

    #[test]
    fn wrong_type_bubbles_up() {
        let c = compile("\"hello\"").unwrap();
        let err = c.eval(&row()).err().unwrap();
        assert!(matches!(err, BambdaError::WrongType(_)));
    }

    #[test]
    fn tag_check_via_tags_array() {
        let c = compile("tags.contains(\"auth\")").unwrap();
        assert!(c.eval(&row()).unwrap());
    }

    #[test]
    fn mime_shortform_matches() {
        assert_eq!(short_mime(Some("application/json; charset=utf-8")), "json");
        assert_eq!(short_mime(Some("text/html")), "html");
        assert_eq!(short_mime(Some("application/x-www-form-urlencoded")), "form");
        assert_eq!(short_mime(Some("image/png")), "img:png");
    }
}
