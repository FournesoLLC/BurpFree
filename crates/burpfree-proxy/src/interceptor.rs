//! Hold / forward / drop / edit pipeline for intercepted messages.
//!
//! When intercept is turned on, every request (and optionally each
//! response) is parked in [`Interceptor`] until the UI resolves it.
//! The waiting proxy connection awaits a `oneshot` channel that
//! carries the decision.
//!
//! The pipeline is message-type-agnostic: both HTTP requests and
//! responses go through the same queue, distinguished by `direction`.

use std::collections::HashMap;
use std::sync::Arc;

use burpfree_core::ids::TrafficId;
use burpfree_core::traffic::{Request, Response};
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptAction {
    Forward,
    Drop,
}

// ---- Conditional interception rules ---------------------------------------

/// How this rule combines with the running decision from the previous rule.
/// The first rule's operator is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOperator {
    And,
    Or,
}

/// What a rule inspects on the request. Each type takes a `condition`
/// string whose interpretation depends on the match-type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMatchType {
    /// Compare the HTTP method (GET, POST…) against `condition` (case-insensitive).
    Method,
    /// Match the full URL (`scheme://host:port/path?query`) against the regex in `condition`.
    Url,
    /// Match the host against the regex in `condition`.
    Host,
    /// Match the path's file extension (e.g. `js`, `css`) against the regex in `condition`.
    /// Comparison is case-insensitive. Empty / missing extensions never match.
    FileExtension,
    /// True when the request has at least one query or form parameter.
    /// `condition` is ignored.
    HasParams,
    /// True when the request carries a body with `Content-Length > 0`. Ignores `condition`.
    HasBody,
    /// True when the request's target is in scope (as of the Scope engine's decision).
    /// Ignores `condition`.
    InScope,
    /// True when any header with name (case-insensitive) equal to `condition` is present.
    /// For response rules, inspects response headers.
    HeaderPresent,
}

/// Whether a rule's inspection should be inverted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleRelationship {
    /// Rule fires when the match-type returns true.
    Matches,
    /// Rule fires when the match-type returns false.
    DoesNotMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    pub id: String,
    pub enabled: bool,
    pub operator: RuleOperator,
    pub match_type: RuleMatchType,
    pub relationship: RuleRelationship,
    #[serde(default)]
    pub condition: String,
}

/// The complete rule set for one direction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterceptRules {
    pub rules: Vec<InterceptRule>,
}

/// Per-rule breakdown returned by `preview_request` /
/// `preview_response`. `matched` is the raw match-type outcome before
/// `relationship` is applied; `effect` is after. Disabled rules have
/// both filled in so the UI can grey them out while still showing
/// what *would* happen if the operator flipped them on.
#[derive(Debug, Clone, Serialize)]
pub struct RulePreview {
    pub id: String,
    pub enabled: bool,
    pub operator: RuleOperator,
    pub match_type: RuleMatchType,
    pub relationship: RuleRelationship,
    pub condition: String,
    pub matched: bool,
    pub effect: bool,
}

/// Aggregate preview result — the final decision (same shape as
/// `evaluate_request`'s return: `None` when no rules are enabled,
/// `Some(true)` to hold, `Some(false)` to forward) plus the ordered
/// per-rule outcomes so the UI can colour-code each row.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewReport {
    pub decision: Option<bool>,
    pub rules: Vec<RulePreview>,
}

impl InterceptRules {
    /// Evaluate the ruleset against a request. If no rules exist, the
    /// caller falls back to the old global-on behaviour (intercept
    /// everything in-scope). With rules present, the first rule's
    /// relationship produces the initial decision, then subsequent
    /// rules combine with the configured operator.
    pub fn evaluate_request(&self, req: &Request, in_scope: bool) -> Option<bool> {
        self.evaluate_request_counted(req, in_scope).0
    }

    /// Like `evaluate_request` but also returns the ordered IDs of
    /// enabled rules whose effect (after `relationship`) was `true` on
    /// this request. The live intercept pipeline uses this to bump
    /// per-rule hit counters without recomputing the match twice.
    /// Rules in an AND chain still count individual hits even when the
    /// aggregate decision ends up `false` — the counter tracks each
    /// rule's own firing, not whether the message was ultimately held.
    pub(crate) fn evaluate_request_counted(
        &self,
        req: &Request,
        in_scope: bool,
    ) -> (Option<bool>, Vec<String>) {
        if self.rules.iter().all(|r| !r.enabled) {
            return (None, Vec::new());
        }
        let mut acc: Option<bool> = None;
        let mut hits: Vec<String> = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let v = eval_rule_request(rule, req, in_scope);
            if v {
                hits.push(rule.id.clone());
            }
            acc = Some(match acc {
                None => v,
                Some(prev) => match rule.operator {
                    RuleOperator::And => prev && v,
                    RuleOperator::Or => prev || v,
                },
            });
        }
        (acc, hits)
    }

    /// Dry-run the request ruleset without parking any traffic.
    /// Returns a per-rule breakdown (raw match + relationship-applied
    /// effect) alongside the aggregate decision — mirrors Burp's
    /// "Test rules" button. The caller supplies a synthesised
    /// `Request` + `in_scope` flag so operators can preview how a
    /// chain of rules behaves against a sample before enabling
    /// intercept against live traffic.
    pub fn preview_request(&self, req: &Request, in_scope: bool) -> PreviewReport {
        let mut rules_out = Vec::with_capacity(self.rules.len());
        let mut acc: Option<bool> = None;
        for rule in &self.rules {
            let matched = rule_matched_request(rule, req, in_scope);
            let effect = apply_relationship(rule.relationship, matched);
            if rule.enabled {
                acc = Some(match acc {
                    None => effect,
                    Some(prev) => match rule.operator {
                        RuleOperator::And => prev && effect,
                        RuleOperator::Or => prev || effect,
                    },
                });
            }
            rules_out.push(RulePreview {
                id: rule.id.clone(),
                enabled: rule.enabled,
                operator: rule.operator,
                match_type: rule.match_type,
                relationship: rule.relationship,
                condition: rule.condition.clone(),
                matched,
                effect,
            });
        }
        PreviewReport { decision: acc, rules: rules_out }
    }

    /// Dry-run the response ruleset. Needs a paired `Request` because
    /// some response rules still match against request-visible fields
    /// (method / url / host / in-scope). The caller supplies a
    /// placeholder response — the Preview UI typically pairs the
    /// operator's sample request with an empty 200 OK so headers/body
    /// rules have something concrete to probe.
    pub fn preview_response(
        &self,
        req: &Request,
        resp: &Response,
        in_scope: bool,
    ) -> PreviewReport {
        let mut rules_out = Vec::with_capacity(self.rules.len());
        let mut acc: Option<bool> = None;
        for rule in &self.rules {
            let matched = rule_matched_response(rule, req, resp, in_scope);
            let effect = apply_relationship(rule.relationship, matched);
            if rule.enabled {
                acc = Some(match acc {
                    None => effect,
                    Some(prev) => match rule.operator {
                        RuleOperator::And => prev && effect,
                        RuleOperator::Or => prev || effect,
                    },
                });
            }
            rules_out.push(RulePreview {
                id: rule.id.clone(),
                enabled: rule.enabled,
                operator: rule.operator,
                match_type: rule.match_type,
                relationship: rule.relationship,
                condition: rule.condition.clone(),
                matched,
                effect,
            });
        }
        PreviewReport { decision: acc, rules: rules_out }
    }

    /// Evaluate the ruleset against a response. We can only inspect
    /// response-visible fields (headers + status), everything else
    /// evaluates against the paired request.
    pub fn evaluate_response(&self, req: &Request, resp: &Response, in_scope: bool) -> Option<bool> {
        self.evaluate_response_counted(req, resp, in_scope).0
    }

    /// Response-direction twin of `evaluate_request_counted`.
    pub(crate) fn evaluate_response_counted(
        &self,
        req: &Request,
        resp: &Response,
        in_scope: bool,
    ) -> (Option<bool>, Vec<String>) {
        if self.rules.iter().all(|r| !r.enabled) {
            return (None, Vec::new());
        }
        let mut acc: Option<bool> = None;
        let mut hits: Vec<String> = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let v = eval_rule_response(rule, req, resp, in_scope);
            if v {
                hits.push(rule.id.clone());
            }
            acc = Some(match acc {
                None => v,
                Some(prev) => match rule.operator {
                    RuleOperator::And => prev && v,
                    RuleOperator::Or => prev || v,
                },
            });
        }
        (acc, hits)
    }
}

/// Raw match for a request-direction rule — returns whether the
/// match-type's predicate fires, *before* `relationship` is applied.
/// Pulled out of `eval_rule_request` so the Preview path can expose
/// both the raw match and the final effect without duplicating the
/// per-match-type logic (any divergence would silently drift from the
/// live intercept pipeline). Public only within the crate so the
/// Preview helpers in this module can call it directly.
pub(crate) fn rule_matched_request(rule: &InterceptRule, req: &Request, in_scope: bool) -> bool {
    match rule.match_type {
        RuleMatchType::Method => req.method.eq_ignore_ascii_case(rule.condition.trim()),
        RuleMatchType::Url => Regex::new(&rule.condition).map(|r| r.is_match(&req.url())).unwrap_or(false),
        RuleMatchType::Host => Regex::new(&rule.condition).map(|r| r.is_match(&req.host)).unwrap_or(false),
        RuleMatchType::FileExtension => {
            let path = req.path_only();
            let base = path.rsplit('/').next().unwrap_or("");
            let ext = base.rsplit('.').next().unwrap_or("");
            if ext.is_empty() || ext == base {
                false
            } else {
                Regex::new(&format!("(?i){}", rule.condition))
                    .map(|r| r.is_match(ext))
                    .unwrap_or(false)
            }
        }
        RuleMatchType::HasParams => {
            if req.path.contains('?') {
                true
            } else if let Some(ct) = req.headers.content_type() {
                ct.contains("application/x-www-form-urlencoded") && !req.body.is_empty()
            } else {
                false
            }
        }
        RuleMatchType::HasBody => !req.body.is_empty(),
        RuleMatchType::InScope => in_scope,
        RuleMatchType::HeaderPresent => req.headers.has(rule.condition.trim()),
    }
}

fn eval_rule_request(rule: &InterceptRule, req: &Request, in_scope: bool) -> bool {
    apply_relationship(rule.relationship, rule_matched_request(rule, req, in_scope))
}

/// Raw match for a response-direction rule, mirror of
/// `rule_matched_request` for the response pipeline. Response-visible
/// rules differ for `HasParams` (query only, body isn't inspected) and
/// `HasBody` / `HeaderPresent` (both look at the response, not the
/// request).
pub(crate) fn rule_matched_response(
    rule: &InterceptRule,
    req: &Request,
    resp: &Response,
    in_scope: bool,
) -> bool {
    match rule.match_type {
        RuleMatchType::Method => req.method.eq_ignore_ascii_case(rule.condition.trim()),
        RuleMatchType::Url => Regex::new(&rule.condition).map(|r| r.is_match(&req.url())).unwrap_or(false),
        RuleMatchType::Host => Regex::new(&rule.condition).map(|r| r.is_match(&req.host)).unwrap_or(false),
        RuleMatchType::FileExtension => {
            let path = req.path_only();
            let base = path.rsplit('/').next().unwrap_or("");
            let ext = base.rsplit('.').next().unwrap_or("");
            if ext.is_empty() || ext == base {
                false
            } else {
                Regex::new(&format!("(?i){}", rule.condition))
                    .map(|r| r.is_match(ext))
                    .unwrap_or(false)
            }
        }
        RuleMatchType::HasParams => req.path.contains('?'),
        RuleMatchType::HasBody => !resp.body.is_empty(),
        RuleMatchType::InScope => in_scope,
        RuleMatchType::HeaderPresent => resp.headers.has(rule.condition.trim()),
    }
}

fn eval_rule_response(rule: &InterceptRule, req: &Request, resp: &Response, in_scope: bool) -> bool {
    apply_relationship(rule.relationship, rule_matched_response(rule, req, resp, in_scope))
}

fn apply_relationship(rel: RuleRelationship, matched: bool) -> bool {
    match rel {
        RuleRelationship::Matches => matched,
        RuleRelationship::DoesNotMatch => !matched,
    }
}

/// Result returned to the connection awaiting the user's decision.
#[derive(Debug)]
pub enum InterceptDecision {
    /// Forward (possibly edited) request / response.
    Forward(InterceptMessage),
    /// Drop the message. The proxy will respond with 502 or close.
    Drop,
}

#[derive(Debug)]
pub enum InterceptMessage {
    Request(Request),
    Response(Response),
}

#[derive(Debug)]
pub struct Pending {
    pub id: TrafficId,
    pub direction: Direction,
    pub summary: PendingSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingSummary {
    pub id: TrafficId,
    pub direction: String,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status: Option<u16>,
    pub host: Option<String>,
    pub preview: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    RequestToUpstream,
    ResponseToClient,
}

struct Entry {
    sender: oneshot::Sender<InterceptDecision>,
    original: InterceptMessage,
    summary: PendingSummary,
    direction: Direction,
}

/// Thread-safe intercept queue.
///
/// `hits` is a per-rule firing counter kept at the `Interceptor` level
/// (not inside `InterceptRules`) so saving a new ruleset via
/// `set_request_rules` / `set_response_rules` does not reset the
/// counts the operator was already watching. The counter is runtime-
/// only; a fresh process starts at zero.
#[derive(Clone)]
pub struct Interceptor {
    state: Arc<Mutex<State>>,
    hits: Arc<Mutex<HashMap<String, u64>>>,
}

struct State {
    enabled_request: bool,
    enabled_response: bool,
    pending: std::collections::VecDeque<(TrafficId, Entry)>,
    rules_request: InterceptRules,
    rules_response: InterceptRules,
}

impl Interceptor {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                enabled_request: false,
                enabled_response: false,
                pending: Default::default(),
                rules_request: InterceptRules::default(),
                rules_response: InterceptRules::default(),
            })),
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Snapshot of per-rule firing counts since the process started
    /// (or the last `clear_rule_hits` call). The map key is
    /// `InterceptRule.id`. Rules that haven't fired yet are omitted
    /// from the map so the UI can show them as "0" without a backend
    /// entry.
    pub fn rule_hit_snapshot(&self) -> HashMap<String, u64> {
        self.hits.lock().clone()
    }

    /// Reset every rule's hit count. Called from the "Reset hits"
    /// button in the Intercept Rules editor; doesn't touch pending
    /// intercepts or the rules themselves.
    pub fn clear_rule_hits(&self) {
        self.hits.lock().clear();
    }

    /// Increment the counter for each rule id in `ids`. No-ops when
    /// the slice is empty so the hot path can skip taking the lock.
    fn bump_hits(&self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let mut h = self.hits.lock();
        for id in ids {
            let entry = h.entry(id.clone()).or_insert(0);
            *entry = entry.saturating_add(1);
        }
    }

    pub fn set_request_intercept(&self, on: bool) {
        self.state.lock().enabled_request = on;
    }

    pub fn set_response_intercept(&self, on: bool) {
        self.state.lock().enabled_response = on;
    }

    pub fn request_intercept(&self) -> bool {
        self.state.lock().enabled_request
    }

    pub fn response_intercept(&self) -> bool {
        self.state.lock().enabled_response
    }

    pub fn set_request_rules(&self, rules: InterceptRules) {
        self.state.lock().rules_request = rules;
    }

    pub fn set_response_rules(&self, rules: InterceptRules) {
        self.state.lock().rules_response = rules;
    }

    pub fn request_rules(&self) -> InterceptRules {
        self.state.lock().rules_request.clone()
    }

    pub fn response_rules(&self) -> InterceptRules {
        self.state.lock().rules_response.clone()
    }

    /// Called by the proxy for each outbound request. If intercept is
    /// enabled AND the ruleset (if any) says to intercept, parks the
    /// request and returns a future awaiting the user's decision.
    pub fn maybe_intercept_request(&self, req: Request) -> Option<InterceptHandle> {
        self.maybe_intercept_request_with_scope(req, true)
    }

    pub fn maybe_intercept_request_with_scope(
        &self,
        req: Request,
        in_scope: bool,
    ) -> Option<InterceptHandle> {
        let (enabled, rules) = {
            let s = self.state.lock();
            (s.enabled_request, s.rules_request.clone())
        };
        if !enabled {
            return None;
        }
        // Walk the ruleset once, pulling out both the aggregate decision
        // AND the per-rule firings so hit counts stay in sync with what
        // the proxy actually inspected.
        let (decision, hit_ids) = rules.evaluate_request_counted(&req, in_scope);
        self.bump_hits(&hit_ids);
        if let Some(decision) = decision {
            if !decision {
                return None;
            }
        }
        let (tx, rx) = oneshot::channel();
        let summary = summary_for_request(&req);
        let id = req.id;
        let entry = Entry {
            sender: tx,
            original: InterceptMessage::Request(req),
            summary: summary.clone(),
            direction: Direction::RequestToUpstream,
        };
        self.state.lock().pending.push_back((id, entry));
        Some(InterceptHandle { id, direction: Direction::RequestToUpstream, rx, summary })
    }

    pub fn maybe_intercept_response(&self, resp: Response, req_url: &str) -> Option<InterceptHandle> {
        if !self.state.lock().enabled_response {
            return None;
        }
        // Response-side rule evaluation would need the paired request to be
        // meaningful; proxy callers wanting that path should use
        // `maybe_intercept_response_with_request` below.
        let (tx, rx) = oneshot::channel();
        let summary = summary_for_response(&resp, req_url);
        let id = resp.id;
        let entry = Entry {
            sender: tx,
            original: InterceptMessage::Response(resp),
            summary: summary.clone(),
            direction: Direction::ResponseToClient,
        };
        self.state.lock().pending.push_back((id, entry));
        Some(InterceptHandle { id, direction: Direction::ResponseToClient, rx, summary })
    }

    /// Scope-aware response variant used by the proxy worker.
    pub fn maybe_intercept_response_with_request(
        &self,
        resp: Response,
        req: &Request,
        in_scope: bool,
    ) -> Option<InterceptHandle> {
        let (enabled, rules) = {
            let s = self.state.lock();
            (s.enabled_response, s.rules_response.clone())
        };
        if !enabled {
            return None;
        }
        let (decision, hit_ids) = rules.evaluate_response_counted(req, &resp, in_scope);
        self.bump_hits(&hit_ids);
        if let Some(decision) = decision {
            if !decision {
                return None;
            }
        }
        let (tx, rx) = oneshot::channel();
        let summary = summary_for_response(&resp, &req.url());
        let id = resp.id;
        let entry = Entry {
            sender: tx,
            original: InterceptMessage::Response(resp),
            summary: summary.clone(),
            direction: Direction::ResponseToClient,
        };
        self.state.lock().pending.push_back((id, entry));
        Some(InterceptHandle { id, direction: Direction::ResponseToClient, rx, summary })
    }

    pub fn list_pending(&self) -> Vec<PendingSummary> {
        self.state
            .lock()
            .pending
            .iter()
            .map(|(_, e)| e.summary.clone())
            .collect()
    }

    pub fn get_original(&self, id: TrafficId) -> Option<RawView> {
        self.state
            .lock()
            .pending
            .iter()
            .find(|(k, _)| *k == id)
            .map(|(_, e)| match &e.original {
                InterceptMessage::Request(r) => RawView::Request(r.to_wire_bytes()),
                InterceptMessage::Response(r) => RawView::Response(r.to_wire_bytes()),
            })
    }

    /// Resolve a pending intercept with the user's edited bytes.
    ///
    /// `raw` is the on-the-wire replacement for the message; passing
    /// `None` keeps the original.
    pub fn resolve(
        &self,
        id: TrafficId,
        action: InterceptAction,
        raw: Option<Vec<u8>>,
    ) -> Result<(), InterceptError> {
        let mut s = self.state.lock();
        let pos = s
            .pending
            .iter()
            .position(|(k, _)| *k == id)
            .ok_or(InterceptError::NotFound)?;
        let (_, entry) = s.pending.remove(pos).ok_or(InterceptError::NotFound)?;
        drop(s);
        let decision = match action {
            InterceptAction::Drop => InterceptDecision::Drop,
            InterceptAction::Forward => match (entry.direction, raw) {
                (Direction::RequestToUpstream, Some(bytes)) => {
                    let (host, port, scheme) = match &entry.original {
                        InterceptMessage::Request(r) => (r.host.clone(), r.port, r.scheme.clone()),
                        _ => return Err(InterceptError::MessageTypeMismatch),
                    };
                    let edited = parse_edited_request(&bytes, &host, port, &scheme)
                        .map_err(InterceptError::Parse)?;
                    // Preserve id so logs/UI follow.
                    let edited = replace_id(edited, &entry.original);
                    InterceptDecision::Forward(InterceptMessage::Request(edited))
                }
                (Direction::ResponseToClient, Some(bytes)) => {
                    let edited = parse_edited_response(&bytes).map_err(InterceptError::Parse)?;
                    let edited = replace_resp_id(edited, &entry.original);
                    InterceptDecision::Forward(InterceptMessage::Response(edited))
                }
                _ => InterceptDecision::Forward(entry.original),
            },
        };
        entry.sender.send(decision).map_err(|_| InterceptError::ReceiverGone)?;
        Ok(())
    }

    pub fn clear_all(&self) {
        self.state.lock().pending.clear();
    }

    /// Bulk resolve every pending intercept with `action`. Mirrors
    /// Burp's "Forward all" / "Drop all" buttons. Returns how many
    /// entries were resolved. Each is resolved individually so the
    /// waiting proxy connection sees a decision (as opposed to
    /// `clear_all`, which drops silently and starves the receivers).
    pub fn resolve_all(&self, action: InterceptAction) -> usize {
        let ids: Vec<TrafficId> = self
            .state
            .lock()
            .pending
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let mut n = 0usize;
        for id in ids {
            if self.resolve(id, action, None).is_ok() {
                n += 1;
            }
        }
        n
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct InterceptHandle {
    pub id: TrafficId,
    pub direction: Direction,
    pub summary: PendingSummary,
    rx: oneshot::Receiver<InterceptDecision>,
}

impl InterceptHandle {
    pub async fn await_decision(self) -> InterceptDecision {
        self.rx.await.unwrap_or(InterceptDecision::Drop)
    }
}

pub enum RawView {
    Request(Vec<u8>),
    Response(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    #[error("intercept entry not found")]
    NotFound,
    #[error("message type mismatch")]
    MessageTypeMismatch,
    #[error("edited bytes failed to parse: {0}")]
    Parse(anyhow::Error),
    #[error("waiting side went away")]
    ReceiverGone,
}

fn summary_for_request(r: &Request) -> PendingSummary {
    let preview = String::from_utf8_lossy(&r.body)
        .chars()
        .take(200)
        .collect::<String>();
    PendingSummary {
        id: r.id,
        direction: "request".into(),
        method: Some(r.method.clone()),
        url: Some(r.url()),
        status: None,
        host: Some(r.host.clone()),
        preview,
    }
}

fn summary_for_response(r: &Response, req_url: &str) -> PendingSummary {
    let preview = String::from_utf8_lossy(&r.body)
        .chars()
        .take(200)
        .collect::<String>();
    PendingSummary {
        id: r.id,
        direction: "response".into(),
        method: None,
        url: Some(req_url.to_string()),
        status: Some(r.status),
        host: None,
        preview,
    }
}

/// Parse an on-the-wire HTTP/1.x request block into a typed `Request`.
///
/// Public entry point for callers that have the wire bytes + the
/// origin tuple (host / port / scheme) and want a Repeater-ready
/// `Request` — e.g. the Tauri `repeater_add_from_wire` command used
/// by the Proxy → Repeater handoff. Internally shared with the
/// interceptor's "resolve with edits" path so Host-header fixups and
/// HTTP/2-to-1.1 downgrade logic stay in one place.
pub fn parse_edited_request(bytes: &[u8], host: &str, port: u16, scheme: &str) -> anyhow::Result<Request> {
    use crate::http1::parse_request_head;
    use burpfree_core::traffic::{HttpVersion, Request, RequestSource};

    let sep = find_double_crlf(bytes).ok_or_else(|| anyhow::anyhow!("no header terminator"))?;
    let head_block = &bytes[..sep + 2];
    let body = &bytes[sep + 4..];
    let head = parse_request_head(head_block).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // Determine origin from Host header if the user changed it.
    let host_hdr = head.headers.get("Host").unwrap_or(host).to_string();
    let (resolved_host, resolved_port) = split_host_port(&host_hdr, port);
    let mut req = Request {
        id: TrafficId::new(), // overwritten by replace_id
        method: head.method,
        scheme: scheme.to_string(),
        host: resolved_host,
        port: resolved_port,
        path: head.target,
        http_version: head.version,
        headers: head.headers,
        body: body.to_vec(),
        created_at_ms: burpfree_core::traffic::now_ms(),
        source: RequestSource::Proxy,
        parent_id: None,
        annotation: String::new(),
        comment: String::new(),
    };
    // If the user removed Host, re-add.
    if !req.headers.has("Host") {
        req.headers.set(
            "Host",
            if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
                host.to_string()
            } else {
                format!("{host}:{port}")
            },
        );
    }
    // Normalize HTTP/1.0 → 1.1 if unspecified.
    if matches!(req.http_version, HttpVersion::Http2 | HttpVersion::Http3) {
        req.http_version = HttpVersion::Http11;
    }
    Ok(req)
}

fn parse_edited_response(bytes: &[u8]) -> anyhow::Result<Response> {
    use crate::http1::parse_response_head;
    use burpfree_core::traffic::Response;

    let sep = find_double_crlf(bytes).ok_or_else(|| anyhow::anyhow!("no header terminator"))?;
    let head_block = &bytes[..sep + 2];
    let body = &bytes[sep + 4..];
    let head = parse_response_head(head_block).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Response {
        id: TrafficId::new(),
        status: head.status,
        reason: head.reason,
        http_version: head.version,
        headers: head.headers,
        body: body.to_vec(),
        created_at_ms: burpfree_core::traffic::now_ms(),
        elapsed_ms: 0,
        original_body_size: None,
    })
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

fn split_host_port(s: &str, fallback_port: u16) -> (String, u16) {
    if let Some(idx) = s.rfind(':') {
        if let Ok(p) = s[idx + 1..].parse::<u16>() {
            return (s[..idx].to_string(), p);
        }
    }
    (s.to_string(), fallback_port)
}

fn replace_id(mut edited: Request, orig: &InterceptMessage) -> Request {
    if let InterceptMessage::Request(o) = orig {
        edited.id = o.id;
        edited.parent_id = o.parent_id;
    }
    edited
}

fn replace_resp_id(mut edited: Response, orig: &InterceptMessage) -> Response {
    if let InterceptMessage::Response(o) = orig {
        edited.id = o.id;
    }
    edited
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::Request;

    #[tokio::test]
    async fn forward_passthrough() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        let req = Request::new("GET", "http://example.com/").unwrap();
        let id = req.id;
        let handle = it.maybe_intercept_request(req).expect("handle");
        tokio::spawn({
            let it = it.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                it.resolve(id, InterceptAction::Forward, None).unwrap();
            }
        });
        let d = handle.await_decision().await;
        match d {
            InterceptDecision::Forward(InterceptMessage::Request(r)) => {
                assert_eq!(r.host, "example.com");
            }
            _ => panic!("wrong decision"),
        }
    }

    #[tokio::test]
    async fn edit_request_bytes() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        let req = Request::new("GET", "http://example.com/").unwrap();
        let id = req.id;
        let handle = it.maybe_intercept_request(req).unwrap();
        tokio::spawn({
            let it = it.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let edited = b"POST /new HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
                it.resolve(id, InterceptAction::Forward, Some(edited.to_vec())).unwrap();
            }
        });
        let d = handle.await_decision().await;
        if let InterceptDecision::Forward(InterceptMessage::Request(r)) = d {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/new");
            assert_eq!(r.body, b"hello");
        } else {
            panic!("not forwarded");
        }
    }

    #[tokio::test]
    async fn drop_message() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        let req = Request::new("GET", "http://example.com/").unwrap();
        let id = req.id;
        let handle = it.maybe_intercept_request(req).unwrap();
        tokio::spawn({
            let it = it.clone();
            async move { it.resolve(id, InterceptAction::Drop, None).unwrap(); }
        });
        let d = handle.await_decision().await;
        assert!(matches!(d, InterceptDecision::Drop));
    }

    /// `resolve_all(Forward)` must satisfy every waiting handle. We
    /// enqueue three requests, call resolve_all, then await each
    /// handle in a join_all. Every decision must be Forward.
    #[tokio::test]
    async fn resolve_all_forwards_every_pending() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        let mut handles = Vec::new();
        for host in ["example.com", "evil.local", "staging.local"] {
            let req = Request::new("GET", &format!("http://{host}/")).unwrap();
            handles.push(it.maybe_intercept_request(req).unwrap());
        }
        assert_eq!(it.list_pending().len(), 3);
        let n = it.resolve_all(InterceptAction::Forward);
        assert_eq!(n, 3);
        assert_eq!(it.list_pending().len(), 0);
        for h in handles {
            let d = h.await_decision().await;
            assert!(matches!(d, InterceptDecision::Forward(_)));
        }
    }

    /// `get_original` surfaces the queued raw bytes without resolving
    /// the entry — operators can send-to-Repeater without consuming
    /// the intercept slot.
    #[tokio::test]
    async fn peek_raw_returns_bytes_without_resolving() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        let req = Request::new("GET", "http://example.com/path?x=1").unwrap();
        let id = req.id;
        let _handle = it.maybe_intercept_request(req).unwrap();
        // Non-destructive peek.
        let raw = it.get_original(id).expect("entry exists");
        let bytes = match raw {
            RawView::Request(b) => b,
            RawView::Response(_) => panic!("wrong direction"),
        };
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.starts_with("GET /path?x=1 HTTP/1.1"));
        assert!(wire.contains("Host: example.com"));
        // Entry is still pending after the peek.
        assert_eq!(it.list_pending().len(), 1);
        // Unknown ids yield None.
        assert!(it.get_original(TrafficId::new()).is_none());
    }

    #[test]
    fn intercept_off_returns_none() {
        let it = Interceptor::new();
        let req = Request::new("GET", "http://example.com/").unwrap();
        assert!(it.maybe_intercept_request(req).is_none());
    }

    #[test]
    fn file_extension_does_not_match_lets_through() {
        let rules = InterceptRules {
            rules: vec![InterceptRule {
                id: "r1".into(),
                enabled: true,
                operator: RuleOperator::Or,
                match_type: RuleMatchType::FileExtension,
                relationship: RuleRelationship::DoesNotMatch,
                condition: r"^(gif|jpg|png|css|js)$".into(),
            }],
        };
        // CSS fetch — the DoesNotMatch returns false → request is let through
        // (no intercept) because evaluate_request returns Some(false).
        let css = Request::new("GET", "https://example.com/static/app.css").unwrap();
        assert_eq!(rules.evaluate_request(&css, true), Some(false));
        // JSON API request — extension not in list → DoesNotMatch returns true.
        let api = Request::new("GET", "https://example.com/api/users").unwrap();
        assert_eq!(rules.evaluate_request(&api, true), Some(true));
    }

    #[test]
    fn and_or_operators_compose() {
        // (method == POST) AND (host matches ^api\.)
        let rules = InterceptRules {
            rules: vec![
                InterceptRule {
                    id: "a".into(),
                    enabled: true,
                    operator: RuleOperator::Or,
                    match_type: RuleMatchType::Method,
                    relationship: RuleRelationship::Matches,
                    condition: "POST".into(),
                },
                InterceptRule {
                    id: "b".into(),
                    enabled: true,
                    operator: RuleOperator::And,
                    match_type: RuleMatchType::Host,
                    relationship: RuleRelationship::Matches,
                    condition: r"^api\.".into(),
                },
            ],
        };
        let api_post = Request::new("POST", "https://api.example.com/u").unwrap();
        let api_get = Request::new("GET", "https://api.example.com/u").unwrap();
        let other_post = Request::new("POST", "https://cdn.example.com/u").unwrap();
        assert_eq!(rules.evaluate_request(&api_post, true), Some(true));
        assert_eq!(rules.evaluate_request(&api_get, true), Some(false));
        assert_eq!(rules.evaluate_request(&other_post, true), Some(false));
    }

    #[test]
    fn in_scope_filter() {
        let rules = InterceptRules {
            rules: vec![InterceptRule {
                id: "r".into(),
                enabled: true,
                operator: RuleOperator::Or,
                match_type: RuleMatchType::InScope,
                relationship: RuleRelationship::Matches,
                condition: String::new(),
            }],
        };
        let req = Request::new("GET", "https://x.local/").unwrap();
        assert_eq!(rules.evaluate_request(&req, true), Some(true));
        assert_eq!(rules.evaluate_request(&req, false), Some(false));
    }

    #[test]
    fn empty_or_all_disabled_rules_fallthrough() {
        let empty = InterceptRules::default();
        let req = Request::new("GET", "https://x.local/").unwrap();
        assert_eq!(empty.evaluate_request(&req, true), None);

        let all_off = InterceptRules {
            rules: vec![InterceptRule {
                id: "r".into(),
                enabled: false,
                operator: RuleOperator::Or,
                match_type: RuleMatchType::InScope,
                relationship: RuleRelationship::Matches,
                condition: String::new(),
            }],
        };
        assert_eq!(all_off.evaluate_request(&req, true), None);
    }

    #[test]
    fn preview_report_tracks_matched_effect_and_decision() {
        // Three-rule chain:
        //   r1: Host matches ^api\. — fires on api.*
        //   r2 (AND): Method != POST — fires when the method is NOT POST
        //   r3 (OR, disabled): InScope matches — ignored by decision
        // Together r1 AND r2 against api.example.com GET should hold.
        let rules = InterceptRules {
            rules: vec![
                InterceptRule {
                    id: "r1".into(),
                    enabled: true,
                    operator: RuleOperator::Or,
                    match_type: RuleMatchType::Host,
                    relationship: RuleRelationship::Matches,
                    condition: r"^api\.".into(),
                },
                InterceptRule {
                    id: "r2".into(),
                    enabled: true,
                    operator: RuleOperator::And,
                    match_type: RuleMatchType::Method,
                    relationship: RuleRelationship::DoesNotMatch,
                    condition: "POST".into(),
                },
                InterceptRule {
                    id: "r3".into(),
                    enabled: false,
                    operator: RuleOperator::Or,
                    match_type: RuleMatchType::InScope,
                    relationship: RuleRelationship::Matches,
                    condition: String::new(),
                },
            ],
        };

        let api_get = Request::new("GET", "https://api.example.com/u").unwrap();
        let report = rules.preview_request(&api_get, true);
        assert_eq!(report.rules.len(), 3, "every rule is reported, enabled or not");
        // r1: host matches api.* → matched=true, effect=true
        assert!(report.rules[0].matched);
        assert!(report.rules[0].effect);
        // r2: method != POST → matched=false (method IS GET not POST → eq is false),
        //     relationship DoesNotMatch flips effect to true
        assert!(!report.rules[1].matched);
        assert!(report.rules[1].effect);
        // r3 (disabled): still evaluated for display; InScope matched=true
        assert!(!report.rules[2].enabled);
        assert!(report.rules[2].matched);
        // Decision = r1 effect AND r2 effect (r3 disabled) = true (hold).
        assert_eq!(report.decision, Some(true));

        // Flip the method to POST — r2's raw match becomes true,
        // DoesNotMatch flips effect to false, AND drops the chain.
        let api_post = Request::new("POST", "https://api.example.com/u").unwrap();
        let report = rules.preview_request(&api_post, true);
        assert!(report.rules[1].matched);
        assert!(!report.rules[1].effect);
        assert_eq!(report.decision, Some(false), "r1 AND !r2 → forward");

        // All-disabled → decision = None so the UI badges a neutral
        // "no decision" state instead of implying forward.
        let all_off = InterceptRules {
            rules: vec![InterceptRule {
                id: "r".into(),
                enabled: false,
                operator: RuleOperator::Or,
                match_type: RuleMatchType::InScope,
                relationship: RuleRelationship::Matches,
                condition: String::new(),
            }],
        };
        let report = all_off.preview_request(&api_get, true);
        assert_eq!(report.decision, None);
        assert_eq!(report.rules.len(), 1);
    }

    #[tokio::test]
    async fn interceptor_respects_rules() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        // Rule: intercept only when the URL contains "/admin".
        it.set_request_rules(InterceptRules {
            rules: vec![InterceptRule {
                id: "r1".into(),
                enabled: true,
                operator: RuleOperator::Or,
                match_type: RuleMatchType::Url,
                relationship: RuleRelationship::Matches,
                condition: "/admin".into(),
            }],
        });
        let admin = Request::new("GET", "https://example.com/admin").unwrap();
        let home = Request::new("GET", "https://example.com/home").unwrap();
        assert!(it.maybe_intercept_request(admin).is_some());
        assert!(it.maybe_intercept_request(home).is_none());
    }

    /// Per-rule hit counters bump when an enabled rule's `effect` is
    /// `true`, independently of whether the aggregate decision ends up
    /// holding the message. Covers:
    ///   - rule fires but AND-chain drops the message (hit still counts)
    ///   - rule does not fire (no count)
    ///   - a second request with both rules firing increments both
    ///   - `clear_rule_hits` wipes the map
    #[tokio::test]
    async fn intercept_rule_hits_increment_on_fire() {
        let it = Interceptor::new();
        it.set_request_intercept(true);
        it.set_request_rules(InterceptRules {
            rules: vec![
                InterceptRule {
                    id: "r1".into(),
                    enabled: true,
                    operator: RuleOperator::And,
                    match_type: RuleMatchType::Host,
                    relationship: RuleRelationship::Matches,
                    condition: r"example\.com".into(),
                },
                InterceptRule {
                    id: "r2".into(),
                    enabled: true,
                    operator: RuleOperator::And,
                    match_type: RuleMatchType::Method,
                    relationship: RuleRelationship::Matches,
                    condition: "POST".into(),
                },
            ],
        });
        assert!(it.rule_hit_snapshot().is_empty(), "fresh counter");

        // GET example.com — r1 fires, r2 does not; AND => forward, but r1 still counts.
        let get_req = Request::new("GET", "http://example.com/").unwrap();
        assert!(
            it.maybe_intercept_request(get_req).is_none(),
            "aggregate false, no parking"
        );
        let snap = it.rule_hit_snapshot();
        assert_eq!(snap.get("r1").copied(), Some(1), "r1 fired");
        assert_eq!(snap.get("r2").copied(), None, "r2 silent");

        // POST example.com — both fire, aggregate true, message parks.
        let post_req = Request::new("POST", "http://example.com/").unwrap();
        let post_id = post_req.id;
        let handle = it.maybe_intercept_request(post_req).expect("parked");
        tokio::spawn({
            let it = it.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                it.resolve(post_id, InterceptAction::Forward, None).unwrap();
            }
        });
        let _ = handle.await_decision().await;
        let snap = it.rule_hit_snapshot();
        assert_eq!(snap.get("r1").copied(), Some(2));
        assert_eq!(snap.get("r2").copied(), Some(1));

        // Reset clears everything.
        it.clear_rule_hits();
        assert!(it.rule_hit_snapshot().is_empty(), "cleared");
    }
}
