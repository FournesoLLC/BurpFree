//! Match/Replace rule engine.
//!
//! Rules fire on requests before they go upstream (and optionally on
//! responses before they return to the client). Each rule targets one
//! of: method, URL, header name/value, body text, or raw first-line.
//! Patterns are either literal strings (case-insensitive) or Rust
//! regexes when `regex: true`.

use burpfree_core::traffic::{now_ms, Request, Response};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    Request,
    Response,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    Method,
    Url,
    Path,
    HeaderName,
    HeaderValue,
    Body,
    FirstLine,
    /// Add a new header. `match_` holds the name, `replace` the value.
    AddHeader,
    /// Remove a header by name (`match_`).
    RemoveHeader,
    /// Set the body outright to `replace`.
    SetBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub scope: RuleScope,
    pub target: RuleTarget,
    #[serde(default)]
    pub match_: String,
    #[serde(default)]
    pub replace: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub host_filter: Option<String>,
    /// Optional Rhai predicate. When present, the rule fires only if
    /// the script returns `true` for the given request/response.
    ///
    /// Variables available: `req` (map), `resp` (map). Helpers:
    /// `header(ctx, name)`, `has_header(ctx, name)`, `matches_regex(s, pat)`.
    #[serde(default)]
    pub predicate_script: Option<String>,
}

impl Rule {
    pub fn applies_to_host(&self, host: &str) -> bool {
        match &self.host_filter {
            None => true,
            Some(pat) => {
                if pat.is_empty() {
                    true
                } else if self.regex {
                    Regex::new(pat).map(|r| r.is_match(host)).unwrap_or(false)
                } else {
                    host.to_ascii_lowercase().contains(&pat.to_ascii_lowercase())
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MatchReplaceEngine {
    pub rules: Vec<Rule>,
    /// Live per-rule fire counter. Shared across clones via Arc so
    /// `h.match_replace.read().clone()` doesn't fragment the data —
    /// every receiver sees the same counters because they all point
    /// at the same Mutex. Reset by [`clear_hits`]; survives
    /// [`update_rules`] swaps so operators can retune a rule chain
    /// without losing the trail. `#[serde(skip)]` — hits are
    /// runtime-only; they live in process memory, not in
    /// `config.json`.
    #[serde(skip, default = "default_hits")]
    hits: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, u64>>>,
    /// Live per-rule last-fire epoch (ms). Updated alongside `hits`
    /// in [`bump_hit`] so the UI can show a "Last fire: 2m ago"
    /// column next to the counter. Same Arc-shared storage pattern
    /// so clones and `update_rules` swaps preserve the trail, and
    /// `clear_hits` wipes both together. `#[serde(skip)]` — runtime
    /// only, like `hits`.
    #[serde(skip, default = "default_last_fire")]
    last_fire: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, i64>>>,
}

fn default_hits() -> std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, u64>>> {
    std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()))
}

fn default_last_fire() -> std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, i64>>>
{
    std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()))
}

impl MatchReplaceEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            hits: default_hits(),
            last_fire: default_last_fire(),
        }
    }

    pub fn with_rules(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            hits: default_hits(),
            last_fire: default_last_fire(),
        }
    }

    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn apply_request(&self, req: &mut Request) -> usize {
        self.apply_request_with_response(req, None)
    }

    /// Variant that also makes the current response available to
    /// predicate scripts. Used by the proxy when a `Both`-scope rule
    /// fires on a response.
    pub fn apply_request_with_response(
        &self,
        req: &mut Request,
        resp: Option<&Response>,
    ) -> usize {
        let engine = burpfree_script::ScriptEngine::with_defaults();
        let mut n = 0;
        for rule in &self.rules {
            if let Some(true) = try_apply_request(&engine, rule, req, resp) {
                n += 1;
                self.bump_hit(&rule.id);
            }
        }
        n
    }

    pub fn apply_response(&self, resp: &mut Response, host: &str) -> usize {
        self.apply_response_with_request(resp, host, None)
    }

    pub fn apply_response_with_request(
        &self,
        resp: &mut Response,
        host: &str,
        req: Option<&Request>,
    ) -> usize {
        let engine = burpfree_script::ScriptEngine::with_defaults();
        let mut n = 0;
        for rule in &self.rules {
            if let Some(true) = try_apply_response(&engine, rule, resp, host, req) {
                n += 1;
                self.bump_hit(&rule.id);
            }
        }
        n
    }

    /// Replace the rule set while preserving the live hit counters.
    /// The Tauri `match_replace_set` cmd routes through here so a
    /// save-from-UI doesn't zero out the "which rule actually fires"
    /// trail. If the operator wants to reset the counts, that goes
    /// through the dedicated `clear_hits` command instead.
    pub fn update_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }

    /// Clone the current per-rule hit map. Keys that haven't fired
    /// yet aren't present — the UI treats absence as zero so a
    /// fresh engine with no fires still renders every rule cleanly.
    pub fn hit_snapshot(&self) -> std::collections::HashMap<String, u64> {
        self.hits.lock().clone()
    }

    /// Clone the current per-rule last-fire epoch (ms) map. Rendered
    /// alongside `hit_snapshot` so the UI can show a humanized
    /// "2m ago" column next to the hit count. Absent keys render as
    /// "—" on the frontend.
    pub fn last_fire_snapshot(&self) -> std::collections::HashMap<String, i64> {
        self.last_fire.lock().clone()
    }

    /// Zero every rule's fire counter and last-fire timestamp. Burp
    /// has no direct equivalent; we expose it because operators
    /// iterating on a rule chain want to re-measure cleanly after
    /// each tweak without an app restart.
    pub fn clear_hits(&self) {
        self.hits.lock().clear();
        self.last_fire.lock().clear();
    }

    /// Internal helper: increment the counter and stamp the
    /// last-fire epoch for `rule_id`. Called from the two apply
    /// paths after a rule's `try_apply_*` returns `Some(true)`.
    /// Deliberately not called from `preview_*` — a dry-run must
    /// leave the trail untouched.
    fn bump_hit(&self, rule_id: &str) {
        let ts = now_ms();
        let mut g = self.hits.lock();
        let entry = g.entry(rule_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
        drop(g);
        self.last_fire.lock().insert(rule_id.to_string(), ts);
    }

    /// Dry-run every rule against `req` without touching live traffic.
    /// Each rule is evaluated through the same gate stack the live
    /// pipeline uses — enabled, scope, host_filter, predicate_script —
    /// so Preview and `apply_request` can't drift silently. `fired`
    /// means the rule's target actually mutated the request (e.g. the
    /// match pattern was found), `scope_matched` means the rule's
    /// gates passed and apply was attempted. Returns before/after
    /// wire snapshots (UTF-8 lossy) so the UI can show a side-by-side.
    pub fn preview_request(
        &self,
        req: &Request,
        resp: Option<&Response>,
    ) -> MatchReplacePreview {
        let before_wire = String::from_utf8_lossy(&req.to_wire_bytes()).to_string();
        let mut after = req.clone();
        let engine = burpfree_script::ScriptEngine::with_defaults();
        let mut hits = Vec::with_capacity(self.rules.len());
        let mut net = 0usize;
        for rule in &self.rules {
            let (scope_matched, fired) =
                match try_apply_request(&engine, rule, &mut after, resp) {
                    None => (false, false),
                    Some(f) => (true, f),
                };
            if fired {
                net += 1;
            }
            hits.push(RuleHit {
                id: rule.id.clone(),
                name: rule.name.clone(),
                enabled: rule.enabled,
                scope_matched,
                fired,
            });
        }
        MatchReplacePreview {
            before_wire,
            after_wire: String::from_utf8_lossy(&after.to_wire_bytes()).to_string(),
            rules_applied: hits,
            net_mutations: net,
        }
    }

    /// Response-direction counterpart to `preview_request`. The paired
    /// `req` lets predicate scripts see the originating request, and
    /// `host` seeds the host-filter check since `Response` doesn't
    /// carry one.
    pub fn preview_response(
        &self,
        resp: &Response,
        host: &str,
        req: Option<&Request>,
    ) -> MatchReplacePreview {
        let before_wire = String::from_utf8_lossy(&resp.to_wire_bytes()).to_string();
        let mut after = resp.clone();
        let engine = burpfree_script::ScriptEngine::with_defaults();
        let mut hits = Vec::with_capacity(self.rules.len());
        let mut net = 0usize;
        for rule in &self.rules {
            let (scope_matched, fired) =
                match try_apply_response(&engine, rule, &mut after, host, req) {
                    None => (false, false),
                    Some(f) => (true, f),
                };
            if fired {
                net += 1;
            }
            hits.push(RuleHit {
                id: rule.id.clone(),
                name: rule.name.clone(),
                enabled: rule.enabled,
                scope_matched,
                fired,
            });
        }
        MatchReplacePreview {
            before_wire,
            after_wire: String::from_utf8_lossy(&after.to_wire_bytes()).to_string(),
            rules_applied: hits,
            net_mutations: net,
        }
    }
}

/// Per-rule outcome returned by `preview_request` / `preview_response`.
/// `scope_matched` tells the UI whether the rule's gate stack
/// (enabled + scope + host_filter + predicate_script) was passed so
/// the operator can see if a rule missed because of a gate vs because
/// the match pattern didn't catch. `fired` tells whether the rule's
/// target actually mutated the message.
#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub scope_matched: bool,
    pub fired: bool,
}

/// Aggregate preview result — before/after UTF-8 lossy wire text so
/// the UI can render a side-by-side, every rule's hit outcome in
/// evaluation order, and the net mutation count (rules that actually
/// changed the message).
#[derive(Debug, Clone, Serialize)]
pub struct MatchReplacePreview {
    pub before_wire: String,
    pub after_wire: String,
    pub rules_applied: Vec<RuleHit>,
    pub net_mutations: usize,
}

/// Shared request-rule evaluator: returns `None` when a gate dropped
/// the rule (so Preview can distinguish "didn't try" from "tried but
/// pattern missed"), `Some(bool)` when apply was attempted — the
/// inner bool is `true` iff the rule actually mutated the request.
/// Factored out of `apply_request_with_response` so Preview and the
/// live pipeline can't drift on gate semantics.
fn try_apply_request(
    engine: &burpfree_script::ScriptEngine,
    rule: &Rule,
    req: &mut Request,
    resp: Option<&Response>,
) -> Option<bool> {
    if !rule.enabled {
        return None;
    }
    if !matches!(rule.scope, RuleScope::Request | RuleScope::Both) {
        return None;
    }
    if !rule.applies_to_host(&req.host) {
        return None;
    }
    if !script_predicate_matches(engine, rule, Some(req), resp) {
        return None;
    }
    Some(apply_request_rule(rule, req))
}

/// Response counterpart to `try_apply_request`. Takes `host`
/// explicitly because `Response` doesn't carry one — the proxy threads
/// in the request's host when evaluating response rules.
fn try_apply_response(
    engine: &burpfree_script::ScriptEngine,
    rule: &Rule,
    resp: &mut Response,
    host: &str,
    req: Option<&Request>,
) -> Option<bool> {
    if !rule.enabled {
        return None;
    }
    if !matches!(rule.scope, RuleScope::Response | RuleScope::Both) {
        return None;
    }
    if !rule.applies_to_host(host) {
        return None;
    }
    if !script_predicate_matches(engine, rule, req, Some(resp)) {
        return None;
    }
    Some(apply_response_rule(rule, resp))
}

/// Evaluate `rule.predicate_script`. Returns `true` if no script is set
/// (so unconditional rules keep firing). On parse/runtime error the
/// rule is skipped — safer-by-default than firing on an un-evaluable
/// predicate.
fn script_predicate_matches(
    engine: &burpfree_script::ScriptEngine,
    rule: &Rule,
    req: Option<&Request>,
    resp: Option<&Response>,
) -> bool {
    let Some(script) = rule.predicate_script.as_deref() else {
        return true;
    };
    if script.trim().is_empty() {
        return true;
    }
    match engine.eval_bool(script, req, resp) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(rule = %rule.id, error = %e, "match/replace predicate error");
            false
        }
    }
}

fn apply_request_rule(rule: &Rule, req: &mut Request) -> bool {
    match rule.target {
        RuleTarget::Method => {
            if matches_text(&rule.match_, &req.method, rule.regex) {
                req.method = rule.replace.clone();
                true
            } else {
                false
            }
        }
        RuleTarget::Url => {
            let url = req.url();
            if let Some(new_url) = substitute(&rule.match_, &rule.replace, &url, rule.regex) {
                if url::Url::parse(&new_url).is_ok() {
                    // Rebuild request parts from the new URL.
                    if let Ok(mut rebuilt) = Request::new(&req.method, &new_url) {
                        rebuilt.id = req.id;
                        rebuilt.parent_id = req.parent_id;
                        rebuilt.headers = req.headers.clone();
                        rebuilt.body = req.body.clone();
                        rebuilt.http_version = req.http_version;
                        rebuilt.source = req.source.clone();
                        rebuilt.annotation = req.annotation.clone();
                        rebuilt.comment = req.comment.clone();
                        *req = rebuilt;
                        return true;
                    }
                }
            }
            false
        }
        RuleTarget::Path => {
            if let Some(np) = substitute(&rule.match_, &rule.replace, &req.path, rule.regex) {
                req.path = np;
                true
            } else {
                false
            }
        }
        RuleTarget::HeaderValue => {
            let mut changed = false;
            let items = req.headers.as_slice().to_vec();
            for f in items {
                if let Some(nv) = substitute(&rule.match_, &rule.replace, &f.value, rule.regex) {
                    if nv != f.value {
                        req.headers.set(&f.name, &nv);
                        changed = true;
                    }
                }
            }
            changed
        }
        RuleTarget::HeaderName => {
            let mut changed = false;
            let items = req.headers.as_slice().to_vec();
            for f in items {
                if matches_text(&rule.match_, &f.name, rule.regex) {
                    let new_name = rule.replace.clone();
                    let value = f.value.clone();
                    req.headers.remove(&f.name);
                    req.headers.add(new_name, value);
                    changed = true;
                }
            }
            changed
        }
        RuleTarget::Body => {
            let text = String::from_utf8_lossy(&req.body).to_string();
            if let Some(nt) = substitute(&rule.match_, &rule.replace, &text, rule.regex) {
                if nt != text {
                    req.set_text(&nt);
                    return true;
                }
            }
            false
        }
        RuleTarget::FirstLine => {
            let line = format!(
                "{} {} {}",
                req.method,
                req.path,
                req.http_version.as_str()
            );
            if let Some(nl) = substitute(&rule.match_, &rule.replace, &line, rule.regex) {
                let parts: Vec<&str> = nl.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    req.method = parts[0].to_string();
                    req.path = parts[1].to_string();
                    return true;
                }
            }
            false
        }
        RuleTarget::AddHeader => {
            if !rule.match_.is_empty() {
                req.headers.add(rule.match_.clone(), rule.replace.clone());
                return true;
            }
            false
        }
        RuleTarget::RemoveHeader => req.headers.remove(&rule.match_) > 0,
        RuleTarget::SetBody => {
            req.set_text(&rule.replace);
            true
        }
    }
}

fn apply_response_rule(rule: &Rule, resp: &mut Response) -> bool {
    match rule.target {
        RuleTarget::HeaderValue => {
            let mut changed = false;
            let items = resp.headers.as_slice().to_vec();
            for f in items {
                if let Some(nv) = substitute(&rule.match_, &rule.replace, &f.value, rule.regex) {
                    if nv != f.value {
                        resp.headers.set(&f.name, &nv);
                        changed = true;
                    }
                }
            }
            changed
        }
        RuleTarget::HeaderName => {
            let mut changed = false;
            let items = resp.headers.as_slice().to_vec();
            for f in items {
                if matches_text(&rule.match_, &f.name, rule.regex) {
                    let new_name = rule.replace.clone();
                    let value = f.value.clone();
                    resp.headers.remove(&f.name);
                    resp.headers.add(new_name, value);
                    changed = true;
                }
            }
            changed
        }
        RuleTarget::Body => {
            let text = String::from_utf8_lossy(&resp.body).to_string();
            if let Some(nt) = substitute(&rule.match_, &rule.replace, &text, rule.regex) {
                if nt != text {
                    resp.set_text(&nt);
                    return true;
                }
            }
            false
        }
        RuleTarget::FirstLine => {
            let line = format!("{} {} {}", resp.http_version.as_str(), resp.status, resp.reason);
            if let Some(nl) = substitute(&rule.match_, &rule.replace, &line, rule.regex) {
                let parts: Vec<&str> = nl.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    if let Ok(s) = parts[1].parse::<u16>() {
                        resp.status = s;
                    }
                    if parts.len() == 3 {
                        resp.reason = parts[2].to_string();
                    }
                    return true;
                }
            }
            false
        }
        RuleTarget::AddHeader => {
            if !rule.match_.is_empty() {
                resp.headers.add(rule.match_.clone(), rule.replace.clone());
                return true;
            }
            false
        }
        RuleTarget::RemoveHeader => resp.headers.remove(&rule.match_) > 0,
        RuleTarget::SetBody => {
            resp.set_text(&rule.replace);
            true
        }
        // Not meaningful on a response.
        RuleTarget::Method | RuleTarget::Url | RuleTarget::Path => false,
    }
}

fn matches_text(pattern: &str, text: &str, is_regex: bool) -> bool {
    if is_regex {
        Regex::new(pattern).map(|r| r.is_match(text)).unwrap_or(false)
    } else {
        text.to_ascii_lowercase().contains(&pattern.to_ascii_lowercase())
    }
}

fn substitute(pattern: &str, replacement: &str, text: &str, is_regex: bool) -> Option<String> {
    if is_regex {
        let re = Regex::new(pattern).ok()?;
        if !re.is_match(text) {
            return None;
        }
        Some(re.replace_all(text, replacement).into_owned())
    } else {
        if pattern.is_empty() {
            return None;
        }
        if !text.to_ascii_lowercase().contains(&pattern.to_ascii_lowercase()) {
            return None;
        }
        // Case-preserving naive replace. Walk and swap exact matches.
        Some(replace_ignore_case(text, pattern, replacement))
    }
}

fn replace_ignore_case(hay: &str, needle: &str, repl: &str) -> String {
    let hay_lc = hay.to_ascii_lowercase();
    let needle_lc = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay_lc[i..].starts_with(&needle_lc) {
            out.push_str(repl);
            i += needle.len();
        } else {
            // Advance one char boundary safely.
            let ch = hay[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response};

    fn req() -> Request {
        Request::new("GET", "http://example.com/api/users?id=1").unwrap()
    }

    #[test]
    fn add_and_remove_header() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "1".into(),
            name: "add".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "2".into(),
            name: "rm".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::RemoveHeader,
            match_: "Accept".into(),
            replace: String::new(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        let mut r = req();
        let n = e.apply_request(&mut r);
        assert_eq!(n, 2);
        assert_eq!(r.headers.get("X-Audit"), Some("yes"));
        assert!(!r.headers.has("Accept"));
    }

    #[test]
    fn url_rewrite() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "1".into(),
            name: "rewrite".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::Url,
            match_: "example.com".into(),
            replace: "127.0.0.1:9000".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        let mut r = req();
        let n = e.apply_request(&mut r);
        assert_eq!(n, 1);
        assert_eq!(r.host, "127.0.0.1");
        assert_eq!(r.port, 9000);
    }

    #[test]
    fn regex_body_substitute_in_response() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "1".into(),
            name: "redact".into(),
            enabled: true,
            scope: RuleScope::Response,
            target: RuleTarget::Body,
            match_: r"token=[A-Za-z0-9]+".into(),
            replace: "token=REDACTED".into(),
            regex: true,
            host_filter: None,
            predicate_script: None,
        });
        let mut resp = Response::new(200);
        resp.set_text("session token=ABC123 next token=DEF456");
        let n = e.apply_response(&mut resp, "example.com");
        assert_eq!(n, 1);
        assert_eq!(resp.text(), "session token=REDACTED next token=REDACTED");
    }

    #[test]
    fn predicate_script_gates_rule() {
        let mut e = MatchReplaceEngine::new();
        let rule = Rule {
            id: "1".into(),
            name: "only-api-posts".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: Some(r#"req.method == "POST" && req.host == "api.example.com""#.into()),
        };
        e.add(rule);
        let mut post = Request::new("POST", "http://api.example.com/u").unwrap();
        let mut get = Request::new("GET", "http://api.example.com/u").unwrap();
        let mut other = Request::new("POST", "http://other.example.com/u").unwrap();
        e.apply_request(&mut post);
        e.apply_request(&mut get);
        e.apply_request(&mut other);
        assert!(post.headers.has("X-Audit"));
        assert!(!get.headers.has("X-Audit"));
        assert!(!other.headers.has("X-Audit"));
    }

    #[test]
    fn bad_predicate_script_skips_rule_silently() {
        let mut e = MatchReplaceEngine::new();
        let rule = Rule {
            id: "1".into(),
            name: "broken".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: Some(r#"this is not valid rhai (( "#.into()),
        };
        e.add(rule);
        let mut r = Request::new("GET", "http://example.com/").unwrap();
        e.apply_request(&mut r);
        assert!(!r.headers.has("X-Audit"));
    }

    #[test]
    fn hits_increment_on_apply_but_not_on_preview() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "add-audit".into(),
            name: "audit".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "never-fires".into(),
            name: "miss".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::HeaderValue,
            match_: "X-Not-Present".into(),
            replace: "whatever".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });

        // Baseline — no hits yet.
        assert!(e.hit_snapshot().is_empty());

        // Apply three times → add-audit fires each time, never-fires
        // never does, so only one key appears with count 3.
        for _ in 0..3 {
            let mut r = req();
            assert_eq!(e.apply_request(&mut r), 1);
        }
        let snap = e.hit_snapshot();
        assert_eq!(snap.get("add-audit"), Some(&3));
        assert!(
            !snap.contains_key("never-fires"),
            "miss rules must not pollute the snapshot"
        );

        // Preview MUST NOT increment — operators run previews to
        // check rule chains before enabling intercept; silently
        // bumping counters would make the trail lie.
        let r = req();
        e.preview_request(&r, None);
        e.preview_request(&r, None);
        assert_eq!(e.hit_snapshot().get("add-audit"), Some(&3));

        // Clone must share the Arc — the Tauri layer clones the
        // engine via `h.match_replace.read().clone()` all over the
        // place; counters would be useless if cloning fragmented
        // them.
        let clone = e.clone();
        let mut r = req();
        clone.apply_request(&mut r);
        assert_eq!(
            e.hit_snapshot().get("add-audit"),
            Some(&4),
            "clone must share the hit counter Arc with the original"
        );

        // update_rules swaps the rule set but preserves hits.
        e.update_rules(vec![]);
        assert_eq!(e.hit_snapshot().get("add-audit"), Some(&4));

        // clear_hits zeroes everything.
        e.clear_hits();
        assert!(e.hit_snapshot().is_empty());
    }

    #[test]
    fn preview_tracks_fired_vs_scope_matched_per_rule() {
        // Four-rule mix: enabled fire, enabled scope-pass but match
        // miss, disabled, host-filtered out.
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "a".into(),
            name: "add-audit".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "b".into(),
            name: "miss-replace".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::HeaderValue,
            match_: "X-Not-Present".into(),
            replace: "whatever".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "c".into(),
            name: "off".into(),
            enabled: false,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Disabled".into(),
            replace: "x".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "d".into(),
            name: "wrong-host".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Wrong".into(),
            replace: "x".into(),
            regex: false,
            host_filter: Some("other.local".into()),
            predicate_script: None,
        });

        let r = req();
        let report = e.preview_request(&r, None);
        assert_eq!(report.rules_applied.len(), 4);
        // r.a — enabled, matches, fires → after includes X-Audit
        assert!(report.rules_applied[0].enabled);
        assert!(report.rules_applied[0].scope_matched);
        assert!(report.rules_applied[0].fired);
        // r.b — enabled, scope passes, but HeaderValue match misses
        //       (no X-Not-Present header) → scope_matched=true, fired=false
        assert!(report.rules_applied[1].scope_matched);
        assert!(!report.rules_applied[1].fired);
        // r.c — disabled → scope_matched=false, fired=false
        assert!(!report.rules_applied[2].enabled);
        assert!(!report.rules_applied[2].scope_matched);
        assert!(!report.rules_applied[2].fired);
        // r.d — host filter rejects → scope_matched=false, fired=false
        assert!(report.rules_applied[3].enabled);
        assert!(!report.rules_applied[3].scope_matched);
        assert!(!report.rules_applied[3].fired);
        assert_eq!(report.net_mutations, 1);
        // Before / after wire snapshots differ by the added header.
        assert!(!report.before_wire.contains("X-Audit: yes"));
        assert!(report.after_wire.contains("X-Audit: yes"));
        // The input Request was NOT mutated — Preview is a dry-run.
        assert!(!r.headers.has("X-Audit"));
    }

    #[test]
    fn last_fire_timestamp_stamps_on_apply_only() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "add-audit".into(),
            name: "audit".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Audit".into(),
            replace: "yes".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });
        e.add(Rule {
            id: "never-fires".into(),
            name: "miss".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::HeaderValue,
            match_: "X-Not-Present".into(),
            replace: "whatever".into(),
            regex: false,
            host_filter: None,
            predicate_script: None,
        });

        // Baseline — no fires yet.
        assert!(e.last_fire_snapshot().is_empty());

        // Apply once → add-audit stamps, never-fires stays absent.
        let before = burpfree_core::traffic::now_ms();
        let mut r = req();
        assert_eq!(e.apply_request(&mut r), 1);
        let after = burpfree_core::traffic::now_ms();
        let snap = e.last_fire_snapshot();
        let ts1 = *snap.get("add-audit").expect("add-audit should have stamped");
        assert!(
            ts1 >= before && ts1 <= after,
            "last_fire timestamp {} must fall within [{}, {}]",
            ts1,
            before,
            after
        );
        assert!(
            !snap.contains_key("never-fires"),
            "rules that didn't fire must not pollute the last_fire map"
        );

        // Preview MUST NOT stamp — same contract as hit counters.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let r = req();
        e.preview_request(&r, None);
        assert_eq!(
            e.last_fire_snapshot().get("add-audit"),
            Some(&ts1),
            "preview must leave the last_fire trail untouched"
        );

        // A fresh fire bumps the stamp forward (strictly ≥, since
        // Instant resolution could coincide on fast systems but
        // sleep above gives it a 5ms cushion).
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut r = req();
        e.apply_request(&mut r);
        let ts2 = *e
            .last_fire_snapshot()
            .get("add-audit")
            .expect("add-audit should still be stamped");
        assert!(
            ts2 >= ts1,
            "second fire stamp {} must be >= first stamp {}",
            ts2,
            ts1
        );

        // clear_hits wipes both counters AND timestamps.
        e.clear_hits();
        assert!(e.last_fire_snapshot().is_empty());
        assert!(e.hit_snapshot().is_empty());

        // Clone shares the Arc — same correctness check we rely on
        // for `hits`; the Tauri layer clones the engine on every
        // read.
        let clone = e.clone();
        let mut r = req();
        clone.apply_request(&mut r);
        assert!(
            e.last_fire_snapshot().contains_key("add-audit"),
            "clone must share the last_fire Arc with the original"
        );
    }

    #[test]
    fn host_filter_narrows() {
        let mut e = MatchReplaceEngine::new();
        e.add(Rule {
            id: "1".into(),
            name: "only-api".into(),
            enabled: true,
            scope: RuleScope::Request,
            target: RuleTarget::AddHeader,
            match_: "X-Only".into(),
            replace: "api".into(),
            regex: false,
            host_filter: Some("api.".into()),
            predicate_script: None,
        });
        let mut r = Request::new("GET", "http://api.example.com/").unwrap();
        let mut r2 = Request::new("GET", "http://cdn.example.com/").unwrap();
        e.apply_request(&mut r);
        e.apply_request(&mut r2);
        assert!(r.headers.has("X-Only"));
        assert!(!r2.headers.has("X-Only"));
    }
}
