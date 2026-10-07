//! Session macros — ordered sequences of HTTP requests that establish
//! auth state before a real probe request runs.
//!
//! A [`Macro`] is a list of [`MacroStep`]s. Each step:
//!
//!   1. Expands any `{{var}}` placeholders in URL / headers / body
//!      against the current [`MacroContext`].
//!   2. Sends the request through [`HttpClient`].
//!   3. Observes the response into the shared cookie jar.
//!   4. Runs each [`MacroExtractor`] against the response and stores
//!      the first capture group as a context variable for later steps.
//!
//! A [`SessionRule`] binds a macro to a scope pattern (host + path
//! prefix) and tells the caller which captured variables to splice
//! into the real request before sending it. The scanner evaluates all
//! rules before each probe; the first matching one is applied.
//!
//! The whole module is UI-agnostic and depends only on
//! [`HttpClient`], the cookie jar, and the core traffic model.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use burpfree_core::traffic::{Request, Response};
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::client::HttpClient;
use crate::session::CookieJar;

/// What to pull out of a step response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum ExtractSource {
    /// Match against the raw response body.
    Body,
    /// Match against one response header (case-insensitive name).
    Header { name: String },
    /// Match against the full raw response status line.
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroExtractor {
    /// Variable name — becomes `{{<name>}}` in later steps and in the
    /// session rule's splice list.
    pub var: String,
    pub source: ExtractSource,
    /// Rust regex. Capture group 1 is preferred; fall back to group 0.
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroStep {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<[String; 2]>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub extract: Vec<MacroExtractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Macro {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    pub steps: Vec<MacroStep>,
}

/// Which parts of the real request a session rule should rewrite with
/// captured values before sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpliceAction {
    /// Which header name to set (e.g. `Authorization` or `X-CSRF-Token`).
    pub header: String,
    /// Template string that may reference captured variables, e.g.
    /// `Bearer {{token}}`.
    pub template: String,
}

/// Scope pattern for which real requests a rule applies to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleScope {
    /// Host suffix match. Empty = any host.
    #[serde(default)]
    pub host_suffix: String,
    /// Path prefix match. Empty = any path.
    #[serde(default)]
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRule {
    pub id: String,
    pub name: String,
    /// ID of the macro that establishes session state.
    pub macro_id: String,
    pub scope: RuleScope,
    /// Headers to splice onto the real request after the macro runs.
    #[serde(default)]
    pub splice: Vec<SpliceAction>,
    /// When true, the macro's cookie jar is also applied to the real
    /// request. Default `true`.
    #[serde(default = "default_true")]
    pub apply_cookies: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

/// Thread-local state carried through a single macro run.
#[derive(Debug, Default, Clone)]
pub struct MacroContext {
    pub vars: HashMap<String, String>,
    pub cookies: CookieJar,
    pub transcript: Vec<TranscriptEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptEntry {
    pub step_index: usize,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub elapsed_ms: Option<u64>,
    pub error: Option<String>,
    pub extracted: HashMap<String, String>,
}

/// Run one macro end-to-end against an HttpClient, returning a context
/// enriched with the cookies and variables captured along the way.
pub struct MacroRunner {
    client: HttpClient,
}

impl MacroRunner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn run(&self, m: &Macro) -> Result<MacroContext> {
        let mut ctx = MacroContext::default();
        for (i, step) in m.steps.iter().enumerate() {
            let mut entry = TranscriptEntry {
                step_index: i,
                method: step.method.clone(),
                url: expand_vars(&step.url, &ctx.vars),
                status: None,
                elapsed_ms: None,
                error: None,
                extracted: HashMap::new(),
            };
            match self.exec_step(step, &mut ctx).await {
                Ok((resp, extracted)) => {
                    entry.status = Some(resp.status);
                    entry.elapsed_ms = Some(resp.elapsed_ms);
                    entry.extracted = extracted;
                }
                Err(e) => {
                    entry.error = Some(format!("{e}"));
                    ctx.transcript.push(entry);
                    return Ok(ctx); // partial transcript is useful
                }
            }
            ctx.transcript.push(entry);
        }
        Ok(ctx)
    }

    async fn exec_step(
        &self,
        step: &MacroStep,
        ctx: &mut MacroContext,
    ) -> Result<(Response, HashMap<String, String>)> {
        let url = expand_vars(&step.url, &ctx.vars);
        let method = if step.method.is_empty() { "GET".to_string() } else { step.method.clone() };
        let mut req = Request::new(&method, &url).with_context(|| format!("bad url: {url}"))?;
        // Apply macro-level headers after variable expansion.
        for pair in &step.headers {
            let name = pair[0].trim();
            if name.is_empty() {
                continue;
            }
            req.headers.add(name.to_string(), expand_vars(&pair[1], &ctx.vars));
        }
        // Expand and attach body.
        if !step.body.is_empty() {
            let body = expand_vars(&step.body, &ctx.vars);
            req.set_text(&body);
        }
        // Thread cookies accumulated so far onto the outgoing request.
        ctx.cookies.apply_to_request(&mut req);

        let resp = self.client.send(&req).await?;
        ctx.cookies.observe_response(&req, &resp);

        let mut extracted = HashMap::new();
        for ex in &step.extract {
            if let Some(val) = run_extractor(ex, &resp)? {
                extracted.insert(ex.var.clone(), val.clone());
                ctx.vars.insert(ex.var.clone(), val);
            }
        }
        Ok((resp, extracted))
    }
}

fn run_extractor(ex: &MacroExtractor, resp: &Response) -> Result<Option<String>> {
    let re = Regex::new(&ex.pattern)
        .with_context(|| format!("bad regex for {}: {}", ex.var, ex.pattern))?;
    let hay: std::borrow::Cow<'_, str> = match &ex.source {
        ExtractSource::Body => String::from_utf8_lossy(&resp.body),
        ExtractSource::Status => format!("HTTP/{} {} {}", "1.1", resp.status, resp.reason).into(),
        ExtractSource::Header { name } => match resp.headers.get(name) {
            Some(v) => v.to_string().into(),
            None => return Ok(None),
        },
    };
    if let Some(cap) = re.captures(hay.as_ref()) {
        if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
            return Ok(Some(m.as_str().to_string()));
        }
    }
    Ok(None)
}

/// `{{var}}` placeholder expansion. Unknown placeholders are left as-is
/// so they stand out when they appear in traffic.
pub fn expand_vars(s: &str, vars: &HashMap<String, String>) -> String {
    if !s.contains("{{") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'{' && b[i + 1] == b'{' {
            if let Some(end) = find_close(b, i + 2) {
                let name = std::str::from_utf8(&b[i + 2..end]).unwrap_or("").trim();
                match vars.get(name) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&s[i..end + 2]), // leave intact
                }
                i = end + 2;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn find_close(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < b.len() {
        if b[i] == b'}' && b[i + 1] == b'}' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Rule registry: shared thread-safe view the scanner can consult.
#[derive(Clone, Default)]
pub struct SessionRuleRegistry {
    inner: Arc<RwLock<SessionRuleInner>>,
}

#[derive(Default)]
struct SessionRuleInner {
    macros: Vec<Macro>,
    rules: Vec<SessionRule>,
}

impl SessionRuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_snapshot(&self, macros: Vec<Macro>, rules: Vec<SessionRule>) {
        let mut g = self.inner.write();
        g.macros = macros;
        g.rules = rules;
    }

    pub fn upsert_macro(&self, m: Macro) {
        let mut g = self.inner.write();
        if let Some(existing) = g.macros.iter_mut().find(|e| e.id == m.id) {
            *existing = m;
        } else {
            g.macros.push(m);
        }
    }

    pub fn upsert_rule(&self, r: SessionRule) {
        let mut g = self.inner.write();
        if let Some(existing) = g.rules.iter_mut().find(|e| e.id == r.id) {
            *existing = r;
        } else {
            g.rules.push(r);
        }
    }

    pub fn delete_macro(&self, id: &str) {
        self.inner.write().macros.retain(|m| m.id != id);
    }

    pub fn delete_rule(&self, id: &str) {
        self.inner.write().rules.retain(|r| r.id != id);
    }

    pub fn macros(&self) -> Vec<Macro> {
        self.inner.read().macros.clone()
    }

    pub fn rules(&self) -> Vec<SessionRule> {
        self.inner.read().rules.clone()
    }

    pub fn macro_by_id(&self, id: &str) -> Option<Macro> {
        self.inner.read().macros.iter().find(|m| m.id == id).cloned()
    }

    /// Find the first enabled rule whose scope matches `req`.
    pub fn match_rule(&self, req: &Request) -> Option<SessionRule> {
        let g = self.inner.read();
        for r in &g.rules {
            if !r.enabled { continue; }
            if !r.scope.host_suffix.is_empty()
                && !req.host.ends_with(&r.scope.host_suffix)
            {
                continue;
            }
            if !r.scope.path_prefix.is_empty()
                && !req.path_only().starts_with(&r.scope.path_prefix)
            {
                continue;
            }
            return Some(r.clone());
        }
        None
    }

    /// Apply splice headers + optional cookie jar to a real probe
    /// request, using a prior macro context.
    pub fn apply_rule(rule: &SessionRule, ctx: &MacroContext, req: &mut Request) {
        for sp in &rule.splice {
            let name = sp.header.trim();
            if name.is_empty() {
                continue;
            }
            let value = expand_vars(&sp.template, &ctx.vars);
            req.headers.set(name.to_string(), value);
        }
        if rule.apply_cookies {
            ctx.cookies.apply_to_request(req);
        }
    }
}

/// Validate a macro before persisting / running it.
pub fn validate_macro(m: &Macro) -> Result<()> {
    if m.id.is_empty() {
        bail!("macro id is required");
    }
    if m.name.is_empty() {
        bail!("macro name is required");
    }
    if m.steps.is_empty() {
        bail!("macro must have at least one step");
    }
    for (i, s) in m.steps.iter().enumerate() {
        if s.url.is_empty() {
            bail!("step {} is missing a URL", i + 1);
        }
        for ex in &s.extract {
            if ex.var.is_empty() {
                bail!("step {}: extractor is missing a variable name", i + 1);
            }
            Regex::new(&ex.pattern)
                .with_context(|| format!("step {}: bad regex `{}`", i + 1, ex.pattern))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response};

    fn mk_response(status: u16, body: &str, headers: &[(&str, &str)]) -> Response {
        let mut r = Response::new(status);
        for (n, v) in headers {
            r.headers.add((*n).to_string(), (*v).to_string());
        }
        r.set_text(body);
        r
    }

    #[test]
    fn expand_vars_substitutes_known_names() {
        let mut v = HashMap::new();
        v.insert("token".into(), "abc123".into());
        assert_eq!(expand_vars("Bearer {{token}}", &v), "Bearer abc123");
    }

    #[test]
    fn expand_vars_leaves_unknown_intact() {
        let v = HashMap::new();
        assert_eq!(expand_vars("Bearer {{token}}", &v), "Bearer {{token}}");
    }

    #[test]
    fn extractor_pulls_capture_group_from_body() {
        let r = mk_response(200, "{\"access_token\":\"ZZZ\"}", &[]);
        let ex = MacroExtractor {
            var: "token".into(),
            source: ExtractSource::Body,
            pattern: r#""access_token":"([^"]+)""#.into(),
        };
        let v = run_extractor(&ex, &r).unwrap();
        assert_eq!(v.as_deref(), Some("ZZZ"));
    }

    #[test]
    fn extractor_pulls_header_value() {
        let r = mk_response(200, "", &[("X-CSRF", "nonce-xyz")]);
        let ex = MacroExtractor {
            var: "csrf".into(),
            source: ExtractSource::Header { name: "X-CSRF".into() },
            pattern: r"(.*)".into(),
        };
        let v = run_extractor(&ex, &r).unwrap();
        assert_eq!(v.as_deref(), Some("nonce-xyz"));
    }

    #[test]
    fn validate_rejects_empty() {
        let m = Macro::default();
        assert!(validate_macro(&m).is_err());
    }

    #[test]
    fn validate_rejects_bad_regex() {
        let mut m = Macro::default();
        m.id = "m1".into();
        m.name = "login".into();
        m.steps.push(MacroStep {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: vec![],
            body: String::new(),
            extract: vec![MacroExtractor {
                var: "x".into(),
                source: ExtractSource::Body,
                pattern: r"(".into(),
            }],
        });
        assert!(validate_macro(&m).is_err());
    }

    #[test]
    fn rule_matches_host_suffix_and_path_prefix() {
        let reg = SessionRuleRegistry::new();
        reg.upsert_rule(SessionRule {
            id: "r1".into(),
            name: "api".into(),
            macro_id: "m1".into(),
            scope: RuleScope { host_suffix: "example.com".into(), path_prefix: "/api".into() },
            splice: vec![],
            apply_cookies: true,
            enabled: true,
        });
        let r = Request::new("GET", "https://api.example.com/api/users").unwrap();
        assert!(reg.match_rule(&r).is_some());
        let r = Request::new("GET", "https://api.example.com/public").unwrap();
        assert!(reg.match_rule(&r).is_none());
        let r = Request::new("GET", "https://other.net/api/x").unwrap();
        assert!(reg.match_rule(&r).is_none());
    }

    #[test]
    fn apply_rule_splices_headers_from_ctx_vars() {
        let rule = SessionRule {
            id: "r".into(),
            name: "r".into(),
            macro_id: "m".into(),
            scope: Default::default(),
            splice: vec![SpliceAction {
                header: "Authorization".into(),
                template: "Bearer {{token}}".into(),
            }],
            apply_cookies: false,
            enabled: true,
        };
        let mut ctx = MacroContext::default();
        ctx.vars.insert("token".into(), "abc".into());
        let mut req = Request::new("GET", "https://api.example.com/users").unwrap();
        SessionRuleRegistry::apply_rule(&rule, &ctx, &mut req);
        assert_eq!(req.headers.get("Authorization"), Some("Bearer abc"));
    }

    #[test]
    fn disabled_rule_does_not_match() {
        let reg = SessionRuleRegistry::new();
        reg.upsert_rule(SessionRule {
            id: "r".into(),
            name: "r".into(),
            macro_id: "m".into(),
            scope: RuleScope { host_suffix: "example.com".into(), path_prefix: String::new() },
            splice: vec![],
            apply_cookies: true,
            enabled: false,
        });
        let r = Request::new("GET", "https://example.com/x").unwrap();
        assert!(reg.match_rule(&r).is_none());
    }
}
