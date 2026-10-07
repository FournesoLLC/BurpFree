//! Intruder-style attack engine.
//!
//! Four attack modes:
//!
//! * **Sniper**        — one insertion point per iteration, iterate
//!   each payload once per position.
//! * **BatteringRam**  — single payload set applied to every insertion
//!   point simultaneously.
//! * **Pitchfork**     — N payload sets, one per insertion point;
//!   iterate parallel.
//! * **ClusterBomb**   — N payload sets, one per insertion point;
//!   iterate the Cartesian product.
//!
//! The engine is UI-agnostic: it emits [`AttackResult`] items on a
//! channel. The caller stores or displays them. Cancellation is a
//! `tokio::sync::watch` passed to the runner.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use burpfree_core::traffic::Request;
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::time::sleep;

use crate::client::{HttpClient, HttpClientConfig};
use crate::payloads::PayloadProvider;
use burpfree_codec::{apply_chain, Transform};

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct DurationShim { secs: u64, nanos: u32 }

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        DurationShim { secs: d.as_secs(), nanos: d.subsec_nanos() }.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let shim = DurationShim::deserialize(d)?;
        Ok(Duration::new(shim.secs, shim.nanos))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
    /// Fire the base template N times unchanged. Markers are stripped
    /// from the template once (keeping the content between the §…§
    /// pairs) and the same request is dispatched for every iteration.
    /// No `payloads` provider is required; `null_count` carries the
    /// iteration count. Mirrors Burp's "Null payloads" attack type —
    /// the canonical way to probe account lockout thresholds, hunt
    /// rate limits, and surface race conditions without burning
    /// position-substitution complexity.
    Null,
}

/// Configuration for one Intruder job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderConfig {
    /// Request with insertion markers (default marker: `§`). Each
    /// pair of markers delimits one insertion point.
    pub template: Request,
    pub marker: char,
    pub mode: AttackMode,
    pub payloads: Vec<PayloadProvider>,
    pub concurrency: usize,
    pub rate_per_sec: Option<u32>,
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    pub retries: u8,
    /// Fixed delay inserted before each dispatch. Independent of
    /// `concurrency` and `rate_per_sec`; useful on rate-limited
    /// targets where even 1 req/s needs a 500 ms stagger between
    /// requests to clear a WAF cooldown. `None` or 0 = disabled.
    #[serde(default)]
    pub delay_ms: Option<u32>,
    /// Uniform random extra delay in `[0, delay_jitter_ms]` added
    /// to `delay_ms`. Burp calls this "Random delay" under Resource
    /// Pool; the jitter makes burst patterns harder to fingerprint.
    #[serde(default)]
    pub delay_jitter_ms: Option<u32>,
    /// After any send error (5xx, timeout, connection reset) the
    /// dispatcher sleeps for this many milliseconds before pulling
    /// the next iteration. Lets the operator back off gracefully
    /// when the target starts rate-limiting mid-attack. `None` or 0
    /// = disabled.
    #[serde(default)]
    pub pause_on_error_ms: Option<u32>,
    /// Burp's "Make payloads unique" — when true, duplicate combos
    /// produced by `plan_iterations` are stripped before dispatch so
    /// the attack only fires each distinct payload tuple once.
    /// Essential when overlapping wordlists or numeric ranges would
    /// otherwise burn requests on repeats.
    #[serde(default)]
    pub deduplicate_payloads: bool,
    pub http: HttpClientConfig,
    pub extract_regex: Option<String>,
    /// Multiple Burp-style "Grep - Extract" rules. Each rule is a
    /// named regex; the engine runs every rule against each response
    /// body, taking capture group 1 if present (else group 0), and
    /// surfaces the matches as `AttackResult::extracted_fields`
    /// indexed by rule position. Legacy `extract_regex` keeps
    /// working alongside — populates the single `extracted` field.
    #[serde(default)]
    pub extracts: Vec<ExtractRule>,
    pub status_filter: StatusFilter,
    /// Chainable processing rules applied to each payload *before* it
    /// is substituted into the request. Burp calls these "payload
    /// processing" rules. Default is empty so existing recipes
    /// deserialise unchanged.
    #[serde(default)]
    pub payload_processing: Vec<PayloadProcessingRule>,
    /// Case-insensitive substring probed against each response body.
    /// Rows that contain the substring get `grep_matched = true` so
    /// the UI can colour them. Burp's "Grep - Match" equivalent.
    #[serde(default)]
    pub grep_match: Option<String>,
    /// Multiple Burp-style "Grep - Match" rules in the multi-pattern
    /// form (parallel to `extracts`). Each rule produces one column
    /// in the results, filled with `true` when the pattern (compiled
    /// as a case-insensitive regex via `(?i)`) hits the response
    /// body. Legacy `grep_match` keeps working alongside and
    /// continues to drive the single `grep_matched: bool`.
    #[serde(default)]
    pub grep_matches: Vec<MatchRule>,
    /// Number of iterations for `AttackMode::Null`. Ignored for all
    /// other modes. Clamped to `[1, 10_000]` inside the dispatcher so
    /// a stray UI control can't launch a runaway attack. `None`
    /// deserialises to the Null-mode default of 1 iteration so
    /// recipes saved before Null existed still load.
    #[serde(default)]
    pub null_count: Option<u32>,
}

/// One link in the Intruder payload-processing chain. Every payload
/// yielded by its provider is run through this chain (in order)
/// before Intruder substitutes it into the template. Failures are
/// swallowed per-rule so one bad regex doesn't blow up a whole
/// attack; the rule becomes a no-op on that invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadProcessingRule {
    /// Prepend `value` to the payload.
    Prefix { value: String },
    /// Append `value` to the payload.
    Suffix { value: String },
    /// Percent-encode the payload (`a&b=c` → `a%26b%3Dc`).
    UrlEncode,
    /// Percent-decode (`a%26b` → `a&b`).
    UrlDecode,
    /// Standard Base64 encode.
    Base64Encode,
    /// Standard Base64 decode (lossy UTF-8).
    Base64Decode,
    /// HTML-encode (`<` → `&lt;`).
    HtmlEncode,
    /// Lowercase hex-encode (`AB` → `4142`).
    HexEncode,
    /// Lowercase hex MD5 of the payload bytes.
    Md5,
    /// Lowercase hex SHA-1 of the payload bytes.
    Sha1,
    /// Lowercase hex SHA-256 of the payload bytes.
    Sha256,
    /// Uppercase ASCII letters (Unicode-correct via `str::to_uppercase`).
    Uppercase,
    /// Lowercase ASCII letters (Unicode-correct via `str::to_lowercase`).
    Lowercase,
    /// Reverse character order.
    Reverse,
    /// Literal or regex match-and-replace. When `regex` is true,
    /// `pattern` is compiled as a Rust regex and the replacement
    /// supports `$1`-style group references. On compile failure the
    /// rule is a no-op for that invocation.
    MatchReplace {
        pattern: String,
        replacement: String,
        #[serde(default)]
        regex: bool,
    },
}

/// Run every rule in `rules` sequentially over `payload` and return
/// the final string. The empty rule list is the identity.
pub fn apply_processing(payload: &str, rules: &[PayloadProcessingRule]) -> String {
    let mut v = payload.to_string();
    for rule in rules {
        v = apply_one_processing(&v, rule);
    }
    v
}

fn apply_one_processing(s: &str, rule: &PayloadProcessingRule) -> String {
    use PayloadProcessingRule::*;
    match rule {
        Prefix { value } => format!("{value}{s}"),
        Suffix { value } => format!("{s}{value}"),
        UrlEncode => codec_single(s, Transform::UrlEncode),
        UrlDecode => codec_single(s, Transform::UrlDecode),
        Base64Encode => codec_single(s, Transform::Base64Encode),
        Base64Decode => codec_single(s, Transform::Base64Decode),
        HtmlEncode => codec_single(s, Transform::HtmlEncode),
        HexEncode => codec_single(s, Transform::HexEncode),
        Md5 => codec_single(s, Transform::Md5),
        Sha1 => codec_single(s, Transform::Sha1),
        Sha256 => codec_single(s, Transform::Sha256),
        Uppercase => s.to_uppercase(),
        Lowercase => s.to_lowercase(),
        Reverse => s.chars().rev().collect(),
        MatchReplace {
            pattern,
            replacement,
            regex,
        } => {
            if *regex {
                match Regex::new(pattern) {
                    Ok(re) => re.replace_all(s, replacement.as_str()).to_string(),
                    Err(_) => s.to_string(),
                }
            } else {
                s.replace(pattern, replacement)
            }
        }
    }
}

/// Apply one codec `Transform` through the shared `apply_chain`
/// pipeline. On error (e.g. bad base64 input) the input is returned
/// unchanged so the rest of the processing chain keeps working.
fn codec_single(s: &str, t: Transform) -> String {
    let steps = apply_chain(s, &[t]);
    match steps.last() {
        Some(st) if st.error.is_none() => st.output.clone(),
        _ => s.to_string(),
    }
}

/// One Burp-style "Grep - Extract" rule. `name` labels the UI
/// column; `regex` is matched against each response body with
/// capture-group-1-or-0 semantics (mirrors the legacy single
/// `extract_regex` behaviour). Invalid regexes are silently skipped
/// at runtime — one broken rule can't take down a whole attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractRule {
    pub name: String,
    pub regex: String,
}

/// One Burp-style "Grep - Match" rule in the multi-pattern form.
/// Each rule carries a human-readable `name` that labels its result
/// column plus a `pattern` evaluated as a case-insensitive regex
/// (operators can opt out of case-insensitivity with the standard
/// `(?-i:...)` scope override). Patterns that fail to compile become
/// silent no-ops — the column fills with `false` on every row rather
/// than taking down the whole attack. Mirrors `ExtractRule`'s shape
/// so recipes written in R31's style read the same for match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusFilter {
    pub include_status_min: Option<u16>,
    pub include_status_max: Option<u16>,
    pub exclude_status: Vec<u16>,
}

impl Default for IntruderConfig {
    fn default() -> Self {
        Self {
            template: Request::new("GET", "http://example.com/").unwrap(),
            marker: '§',
            mode: AttackMode::Sniper,
            payloads: Vec::new(),
            concurrency: 10,
            rate_per_sec: None,
            timeout: Duration::from_secs(10),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackResult {
    pub index: u64,
    pub payloads: Vec<String>,
    pub status: Option<u16>,
    pub length: Option<usize>,
    pub elapsed_ms: Option<u64>,
    pub extracted: Option<String>,
    /// Values produced by each configured `extracts` rule, indexed
    /// by rule position. `None` entries mean the rule's regex didn't
    /// match (or compiled badly). Empty when no `extracts` rules are
    /// configured.
    #[serde(default)]
    pub extracted_fields: Vec<Option<String>>,
    pub error: Option<String>,
    pub filtered: bool,
    pub url: String,
    /// True when the configured `grep_match` substring was found in
    /// the response body (case-insensitive). Default false, including
    /// when `grep_match` is None.
    #[serde(default)]
    pub grep_matched: bool,
    /// Per-rule outcomes for each configured `grep_matches` rule,
    /// indexed by rule position. `true` when the compiled regex
    /// matched this response body; `false` when it didn't (or when
    /// the pattern failed to compile). Empty when no match rules
    /// are configured — the UI uses the length as its column
    /// count signal.
    #[serde(default)]
    pub matched: Vec<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Cancelled,
    Failed,
}

pub struct JobHandle {
    pub status: Arc<Mutex<JobStatus>>,
    pub counter: Arc<AtomicU64>,
    pub total: u64,
    pub cancel: watch::Sender<bool>,
    pub rx: mpsc::Receiver<AttackResult>,
    /// Freeze-new-dispatches flag. The dispatcher polls this at the
    /// top of each iteration — while raised it sleeps 50ms and
    /// re-checks (still honouring cancel so a paused attack can
    /// still be aborted). In-flight tasks already past the gate run
    /// to completion so no partially-sent request gets stranded.
    /// Mirrors Burp's Intruder Pause / Resume toolbar button.
    pub pause: Arc<AtomicBool>,
}

pub struct IntruderJob;

impl IntruderJob {
    pub fn start(cfg: IntruderConfig) -> Result<JobHandle> {
        let marker = cfg.marker;
        // For Null mode the template fires unchanged — strip the
        // §…§ wrappers once up-front so the dispatch path's
        // apply_payloads step is a straight passthrough. For every
        // other mode we keep the original template so the markers
        // survive to drive insertion-point scanning.
        let effective_template = if cfg.mode == AttackMode::Null {
            strip_markers_keep_content(&cfg.template, marker)
        } else {
            cfg.template.clone()
        };
        let positions = find_insertion_points(&effective_template, marker);
        // Null mode legitimately has zero insertion points (markers
        // were stripped). Every other mode still needs at least one
        // §marker§ pair or there's nothing to attack.
        if positions.is_empty() && cfg.mode != AttackMode::Null {
            anyhow::bail!("no insertion points found (template missing `{marker}` markers)");
        }
        let null_count = cfg
            .null_count
            .unwrap_or(1)
            .clamp(1, 10_000) as usize;
        let mut iterator =
            plan_iterations(cfg.mode, &cfg.payloads, positions.len(), null_count)?;
        // Burp "Make payloads unique" — strip duplicate combos while
        // preserving the first-occurrence order so recipe runs stay
        // deterministic across sessions.
        if cfg.deduplicate_payloads && !iterator.is_empty() {
            use std::collections::HashSet;
            let mut seen: HashSet<Vec<String>> = HashSet::with_capacity(iterator.len());
            iterator.retain(|combo| seen.insert(combo.clone()));
        }
        let total = iterator.len() as u64;
        let (tx, rx) = mpsc::channel::<AttackResult>(256);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let counter = Arc::new(AtomicU64::new(0));
        let status = Arc::new(Mutex::new(JobStatus::Running));
        let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        let http = HttpClient::new(cfg.http.clone());
        let status_filter = cfg.status_filter.clone();
        let extract = cfg.extract_regex.clone();
        // Pre-compile every Grep-Extract rule once at job start.
        // Invalid regexes become `None` so one bad rule can't take
        // down the whole attack — the worker just reports None for
        // that column on every row. The Arc wraps the compiled vec
        // so every worker clone pays only a reference-count bump.
        let extract_rules: Vec<(String, Option<Regex>)> = cfg
            .extracts
            .iter()
            .map(|r| (r.name.clone(), Regex::new(&r.regex).ok()))
            .collect();
        let extract_rules_arc = Arc::new(extract_rules);
        // Multi grep-match: compile every pattern once, with a `(?i)`
        // case-insensitive prefix so operators get Burp's default
        // match behaviour without having to type it. A pattern that
        // fails to compile becomes `None` and the column fills with
        // `false` on every row — one broken rule can't take down a
        // whole attack (mirrors the extract_rules behaviour).
        let match_rules: Vec<Option<Regex>> = cfg
            .grep_matches
            .iter()
            .map(|r| Regex::new(&format!("(?i){}", r.pattern)).ok())
            .collect();
        let match_rules_arc = Arc::new(match_rules);
        let rate = cfg.rate_per_sec;
        let delay_ms = cfg.delay_ms.unwrap_or(0);
        let jitter_ms = cfg.delay_jitter_ms.unwrap_or(0);
        let pause_on_error_ms = cfg.pause_on_error_ms.unwrap_or(0);
        // Hot flag the inner task sets to true on failure; the next
        // dispatcher iteration reads+clears it and sleeps for the
        // configured error-pause before launching the next task.
        // Using an atomic avoids wiring an mpsc channel for a 1-bit
        // signal that only the dispatcher consumes.
        let error_backoff = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Pause flag — flipped by `JobHandle::pause` via Tauri. The
        // dispatcher's inner clone (`pause_dispatch`) sleeps on it;
        // the returned `pause` goes back to the caller so UI code can
        // flip it. In-flight tasks that already acquired a semaphore
        // permit complete normally — pause only gates *new* dispatches.
        let pause = Arc::new(AtomicBool::new(false));
        let pause_dispatch = pause.clone();

        // Use the Null-stripped template downstream for Null mode so
        // every spawned task hits the already-processed request; for
        // all other modes this is just cfg.template.clone().
        let template = effective_template;
        let positions_arc = Arc::new(positions);
        let status_outer = status.clone();
        let counter_outer = counter.clone();
        // Payload-processing chain is shared across tasks via an Arc so
        // cloning it per iteration is a cheap reference-bump.
        let processing_arc = Arc::new(cfg.payload_processing.clone());
        // Grep-match substring (lowercased once so each task doesn't
        // allocate). None = feature disabled.
        let grep_lc: Option<String> = cfg
            .grep_match
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let grep_arc = Arc::new(grep_lc);

        tokio::spawn(async move {
            let mut handles = Vec::new();
            let mut rate_tick = rate.map(|r| {
                let interval = Duration::from_micros(1_000_000 / r as u64);
                tokio::time::interval(interval)
            });
            for (i, combo) in iterator.into_iter().enumerate() {
                if *cancel_rx.borrow() {
                    break;
                }
                // Burp Pause / Resume: freeze new dispatches while
                // the flag is raised. Short polling interval keeps
                // resume responsive without hot-looping; cancel is
                // re-checked inside so an aborted attack escapes
                // the pause loop immediately.
                while pause_dispatch.load(Ordering::Relaxed) {
                    if *cancel_rx.borrow() {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
                if *cancel_rx.borrow() {
                    break;
                }
                if let Some(t) = rate_tick.as_mut() {
                    t.tick().await;
                }
                // Burp "Resource pool" delay + jitter. Fixed first,
                // then uniform random in [0, jitter_ms] added on top.
                // Skipped entirely when both are 0 so the common case
                // isn't paying for an await.
                if delay_ms > 0 || jitter_ms > 0 {
                    use rand::Rng;
                    let extra = if jitter_ms > 0 {
                        rand::thread_rng().gen_range(0..=jitter_ms)
                    } else {
                        0
                    };
                    let total = delay_ms as u64 + extra as u64;
                    if total > 0 {
                        sleep(Duration::from_millis(total)).await;
                    }
                }
                // Adaptive pause-on-error. The previous iteration's
                // task may have flipped this on; swap-false clears it
                // atomically so a chain of failures each contribute
                // one pause (not an exponential pile).
                if pause_on_error_ms > 0
                    && error_backoff.swap(false, std::sync::atomic::Ordering::Relaxed)
                {
                    sleep(Duration::from_millis(pause_on_error_ms as u64)).await;
                }
                let permit = sem.clone().acquire_owned().await.unwrap();
                let http = http.clone();
                let template = template.clone();
                let positions = positions_arc.clone();
                let tx_c = tx.clone();
                let counter = counter_outer.clone();
                let cancel_rx = cancel_rx.clone();
                let status_filter = status_filter.clone();
                let extract = extract.clone();
                let extract_rules = extract_rules_arc.clone();
                let match_rules = match_rules_arc.clone();
                let marker_c = marker;
                let timeout_c = cfg.timeout;
                let retries = cfg.retries;
                let processing = processing_arc.clone();
                let grep = grep_arc.clone();
                let error_backoff_c = error_backoff.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    // Run every payload in the combo through the
                    // processing chain *before* substitution so the
                    // request we actually send (and the row we record)
                    // reflect what hit the wire.
                    let processed: Vec<String> = if processing.is_empty() {
                        combo.clone()
                    } else {
                        combo
                            .iter()
                            .map(|p| apply_processing(p, &processing))
                            .collect()
                    };
                    let req = apply_payloads(&template, &positions, &processed, marker_c);
                    let url = req.url();
                    let mut result = AttackResult {
                        index: i as u64,
                        payloads: processed.clone(),
                        status: None,
                        length: None,
                        elapsed_ms: None,
                        extracted: None,
                        extracted_fields: Vec::new(),
                        error: None,
                        filtered: false,
                        url,
                        grep_matched: false,
                        matched: Vec::new(),
                    };
                    let mut attempts = 0u8;
                    loop {
                        if *cancel_rx.borrow() {
                            result.error = Some("cancelled".into());
                            break;
                        }
                        match tokio::time::timeout(timeout_c, http.send(&req)).await {
                            Ok(Ok(resp)) => {
                                result.status = Some(resp.status);
                                result.length = Some(resp.body.len());
                                result.elapsed_ms = Some(resp.elapsed_ms);
                                let body_text = String::from_utf8_lossy(&resp.body);
                                if let Some(pat) = &extract {
                                    if let Ok(re) = Regex::new(pat) {
                                        if let Some(cap) = re.captures(&body_text)
                                        {
                                            // Prefer capture group 1 if present.
                                            if let Some(m) = cap.get(1) {
                                                result.extracted = Some(m.as_str().to_string());
                                            } else if let Some(m) = cap.get(0) {
                                                result.extracted = Some(m.as_str().to_string());
                                            }
                                        }
                                    }
                                }
                                // Multi-extract pass: every pre-
                                // compiled rule gets a column. Invalid
                                // rules compile to None and yield None
                                // per row. Capture-group heuristic
                                // mirrors the legacy single-extract.
                                if !extract_rules.is_empty() {
                                    result.extracted_fields =
                                        Vec::with_capacity(extract_rules.len());
                                    for (_, re_opt) in extract_rules.iter() {
                                        let val = re_opt.as_ref().and_then(|re| {
                                            re.captures(&body_text).and_then(|cap| {
                                                cap.get(1)
                                                    .or_else(|| cap.get(0))
                                                    .map(|m| m.as_str().to_string())
                                            })
                                        });
                                        result.extracted_fields.push(val);
                                    }
                                }
                                // Case-insensitive grep match. The
                                // lowercased body is only computed
                                // when `grep` is Some so we don't
                                // allocate on every iteration.
                                if let Some(needle) = grep.as_ref() {
                                    let body_lc = String::from_utf8_lossy(&resp.body)
                                        .to_ascii_lowercase();
                                    result.grep_matched = body_lc.contains(needle);
                                }
                                // Multi grep-match pass. `body_text`
                                // was already built once above for
                                // the extract-rule pass, so reuse it
                                // instead of a second utf8-lossy.
                                // Patterns that failed to compile are
                                // `None` → push `false` so the
                                // column alignment holds across rows.
                                if !match_rules.is_empty() {
                                    result.matched =
                                        Vec::with_capacity(match_rules.len());
                                    for re_opt in match_rules.iter() {
                                        let hit = re_opt
                                            .as_ref()
                                            .map(|re| re.is_match(&body_text))
                                            .unwrap_or(false);
                                        result.matched.push(hit);
                                    }
                                }
                                result.filtered = apply_filter(&status_filter, resp.status);
                                break;
                            }
                            Ok(Err(e)) => {
                                result.error = Some(e.to_string());
                                if attempts >= retries {
                                    break;
                                }
                            }
                            Err(_) => {
                                result.error = Some("timeout".into());
                                if attempts >= retries {
                                    break;
                                }
                            }
                        }
                        attempts += 1;
                        sleep(Duration::from_millis(50 * attempts as u64)).await;
                    }
                    // Any non-cancellation error (timeout, network,
                    // 5xx captured as `error`) trips the backoff flag
                    // for the dispatcher. "cancelled" doesn't count —
                    // user-initiated abort shouldn't cause a slowdown.
                    if result.error.is_some()
                        && result.error.as_deref() != Some("cancelled")
                    {
                        error_backoff_c.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = tx_c.send(result).await;
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            let final_status = if *cancel_rx.borrow() {
                JobStatus::Cancelled
            } else {
                JobStatus::Completed
            };
            *status_outer.lock() = final_status;
        });

        Ok(JobHandle {
            status,
            counter,
            total,
            cancel: cancel_tx,
            rx,
            pause,
        })
    }
}

fn apply_filter(f: &StatusFilter, status: u16) -> bool {
    // "filtered" == does NOT match the inclusion window / is in the
    // exclusion set.
    if let Some(min) = f.include_status_min {
        if status < min {
            return true;
        }
    }
    if let Some(max) = f.include_status_max {
        if status > max {
            return true;
        }
    }
    if f.exclude_status.contains(&status) {
        return true;
    }
    false
}

/// A single insertion range in the raw-wire representation of the
/// request.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future per-part policies.
struct Insertion {
    /// Which part of the request this falls in.
    part: Part,
    /// Byte range (within `part_bytes`).
    range: std::ops::Range<usize>,
}

#[derive(Debug, Clone, Copy)]
enum Part {
    Target,
    Headers,
    Body,
}

/// Rebuild a concrete request from the Intruder template + marker +
/// one `payloads` tuple (one string per insertion point in template
/// scan order). This is the function the UI calls when it wants to
/// resurrect a specific results row into Repeater without having to
/// know anything about insertion-point scanning.
pub fn rebuild_request(template: &Request, marker: char, payloads: &[String]) -> Request {
    let positions = find_insertion_points(template, marker);
    apply_payloads(template, &positions, payloads, marker)
}

fn find_insertion_points(template: &Request, marker: char) -> Vec<Insertion> {
    let mut points = Vec::new();
    // We look at the target (path+query), each header name and value,
    // and body. For simplicity, insertion points are expressed over the
    // *concatenated* parts; the applier below rebuilds the request.
    let marker_s = marker.to_string();
    scan(&template.path, &marker_s, Part::Target, &mut points);
    for h in template.headers.as_slice() {
        scan(&h.value, &marker_s, Part::Headers, &mut points);
    }
    let body = String::from_utf8_lossy(&template.body).to_string();
    scan(&body, &marker_s, Part::Body, &mut points);
    points
}

fn scan(text: &str, marker: &str, part: Part, out: &mut Vec<Insertion>) {
    let bytes = text.as_bytes();
    let m = marker.as_bytes();
    let mut i = 0;
    while i + m.len() <= bytes.len() {
        if &bytes[i..i + m.len()] == m {
            // find closing marker
            let mut j = i + m.len();
            while j + m.len() <= bytes.len() {
                if &bytes[j..j + m.len()] == m {
                    out.push(Insertion {
                        part,
                        range: i..j + m.len(),
                    });
                    i = j + m.len();
                    break;
                }
                j += 1;
            }
            if j + m.len() > bytes.len() {
                break;
            }
        } else {
            i += 1;
        }
    }
}

fn apply_payloads(template: &Request, positions: &[Insertion], payloads: &[String], marker: char) -> Request {
    let mut copy = template.clone();
    let marker_s = marker.to_string();

    // Replace all `§...§` with the given payloads, one per occurrence.
    // Because insertion-point ordering is determined by the scan order
    // (target → headers → body), we rebuild in that order using a
    // consuming payload iterator.
    let mut iter = payloads.iter();

    let path = replace_markers(&copy.path, &marker_s, &mut iter);
    copy.path = path;

    let items = copy.headers.as_slice().to_vec();
    let mut new_headers = burpfree_core::headers::Headers::new();
    for h in items {
        let new_val = replace_markers(&h.value, &marker_s, &mut iter);
        new_headers.add(h.name, new_val);
    }
    copy.headers = new_headers;

    let body = String::from_utf8_lossy(&copy.body).to_string();
    let body = replace_markers(&body, &marker_s, &mut iter);
    copy.body = body.into_bytes();
    if copy.body.is_empty() {
        copy.headers.remove("Content-Length");
    } else {
        copy.headers.set("Content-Length", copy.body.len().to_string());
    }

    // Avoid unused: Part isn't needed in this applier, but kept for
    // potential future per-part policies.
    let _ = positions;
    copy
}

/// Null-mode helper: walk the template once, replacing every
/// `§CONTENT§` marker pair with just `CONTENT` (markers removed,
/// inner text preserved). The result has zero insertion points so
/// the downstream dispatch path is a pure clone-and-send. Mirrors
/// Burp's Null-payload semantics where the base request fires
/// unchanged — including whatever base values the operator left
/// between the markers (e.g. `/users/§alice§` → `/users/alice`).
///
/// Content-Length is recomputed on the stripped body so the on-wire
/// request stays correct when the stripped length differs from the
/// template's original CL header.
fn strip_markers_keep_content(template: &Request, marker: char) -> Request {
    let marker_s = marker.to_string();
    let mut copy = template.clone();
    copy.path = strip_in_text(&copy.path, &marker_s);
    let items = copy.headers.as_slice().to_vec();
    let mut new_headers = burpfree_core::headers::Headers::new();
    for h in items {
        let new_val = strip_in_text(&h.value, &marker_s);
        new_headers.add(h.name, new_val);
    }
    copy.headers = new_headers;
    let body = String::from_utf8_lossy(&copy.body).to_string();
    copy.body = strip_in_text(&body, &marker_s).into_bytes();
    if copy.body.is_empty() {
        copy.headers.remove("Content-Length");
    } else {
        copy.headers.set("Content-Length", copy.body.len().to_string());
    }
    copy
}

/// Inner helper for `strip_markers_keep_content` — walks `text`
/// one char at a time, and when it finds `§…§` pair it emits the
/// text between (but not the markers themselves). Unterminated
/// markers (opening `§` with no match) are emitted literally so
/// stray marker characters in headers don't blow up the attack.
fn strip_in_text(text: &str, marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let m = marker.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + m.len() <= bytes.len() && &bytes[i..i + m.len()] == m {
            // find the closing marker
            let mut j = i + m.len();
            while j + m.len() <= bytes.len() && &bytes[j..j + m.len()] != m {
                j += 1;
            }
            if j + m.len() > bytes.len() {
                // unterminated — emit the rest literally
                out.push_str(&text[i..]);
                break;
            }
            out.push_str(&text[i + m.len()..j]);
            i = j + m.len();
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn replace_markers<'a, I: Iterator<Item = &'a String>>(
    text: &str,
    marker: &str,
    payloads: &mut I,
) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let m = marker.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + m.len() <= bytes.len() && &bytes[i..i + m.len()] == m {
            // find closing marker
            let mut j = i + m.len();
            while j + m.len() <= bytes.len() && &bytes[j..j + m.len()] != m {
                j += 1;
            }
            if j + m.len() > bytes.len() {
                // unterminated; emit literally
                out.push_str(&text[i..]);
                break;
            }
            if let Some(p) = payloads.next() {
                out.push_str(p);
            }
            i = j + m.len();
        } else {
            // emit one byte at a utf-8 safe boundary
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Pre-compute all `Vec<String>` combinations for `n` insertion
/// points. `null_count` is only consulted when `mode == Null`
/// (ignored for every other mode); the dispatcher clamps it before
/// handing it over so the plan length can't blow up.
fn plan_iterations(
    mode: AttackMode,
    payloads: &[PayloadProvider],
    positions: usize,
    null_count: usize,
) -> Result<Vec<Vec<String>>> {
    match mode {
        AttackMode::Null => {
            // Null mode plans one empty-payload-vec per iteration.
            // apply_payloads on a markerless template with zero
            // payloads is a pure clone, so each iteration produces
            // the exact same wire request. `payloads` is ignored by
            // design — Burp's Null type is standalone from the
            // payload sets.
            Ok(vec![Vec::new(); null_count])
        }
        AttackMode::Sniper => {
            if payloads.len() != 1 {
                anyhow::bail!("Sniper mode needs exactly one payload set");
            }
            let set = &payloads[0];
            let mut out = Vec::new();
            for pos in 0..positions {
                for payload in set.iter() {
                    let combo: Vec<String> = (0..positions)
                        .map(|j| if j == pos { payload.clone() } else { String::new() })
                        .collect();
                    out.push(combo);
                }
            }
            Ok(out)
        }
        AttackMode::BatteringRam => {
            if payloads.len() != 1 {
                anyhow::bail!("BatteringRam mode needs exactly one payload set");
            }
            let set = &payloads[0];
            Ok(set
                .iter()
                .map(|p| std::iter::repeat(p).take(positions).collect())
                .collect())
        }
        AttackMode::Pitchfork => {
            if payloads.len() != positions {
                anyhow::bail!(
                    "Pitchfork mode needs exactly one payload set per insertion point ({positions})"
                );
            }
            let lists: Vec<Vec<String>> = payloads.iter().map(|p| p.iter().collect()).collect();
            let len = lists.iter().map(|l| l.len()).min().unwrap_or(0);
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                let mut combo = Vec::with_capacity(positions);
                for l in &lists {
                    combo.push(l[i].clone());
                }
                out.push(combo);
            }
            Ok(out)
        }
        AttackMode::ClusterBomb => {
            if payloads.len() != positions {
                anyhow::bail!(
                    "ClusterBomb mode needs exactly one payload set per insertion point ({positions})"
                );
            }
            let lists: Vec<Vec<String>> = payloads.iter().map(|p| p.iter().collect()).collect();
            let mut out = Vec::new();
            cartesian(&lists, 0, Vec::new(), &mut out);
            Ok(out)
        }
    }
}

fn cartesian(lists: &[Vec<String>], idx: usize, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    if idx == lists.len() {
        out.push(prefix);
        return;
    }
    for item in &lists[idx] {
        let mut p = prefix.clone();
        p.push(item.clone());
        cartesian(lists, idx + 1, p, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payloads::{PayloadProvider, SimpleListProvider};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn mk_request(path: &str) -> Request {
        Request::new("GET", &format!("http://127.0.0.1:0{path}")).unwrap()
    }

    #[test]
    fn plan_sniper() {
        let list = PayloadProvider::List(SimpleListProvider::new(vec!["a".into(), "b".into()]));
        let plan = plan_iterations(AttackMode::Sniper, &[list], 2, 1).unwrap();
        assert_eq!(plan.len(), 4); // 2 payloads × 2 positions
    }

    #[test]
    fn plan_pitchfork_zips() {
        let a = PayloadProvider::List(SimpleListProvider::new(vec!["a1".into(), "a2".into()]));
        let b = PayloadProvider::List(SimpleListProvider::new(vec!["b1".into(), "b2".into(), "b3".into()]));
        let plan = plan_iterations(AttackMode::Pitchfork, &[a, b], 2, 1).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], vec!["a1", "b1"]);
        assert_eq!(plan[1], vec!["a2", "b2"]);
    }

    #[test]
    fn plan_cluster_product() {
        let a = PayloadProvider::List(SimpleListProvider::new(vec!["a".into(), "b".into()]));
        let b = PayloadProvider::List(SimpleListProvider::new(vec!["1".into(), "2".into()]));
        let plan = plan_iterations(AttackMode::ClusterBomb, &[a, b], 2, 1).unwrap();
        assert_eq!(plan.len(), 4);
    }

    #[test]
    fn processing_prefix_only() {
        // Smallest useful chain: single Prefix rule prepends to every
        // payload. The identity path (empty rules) is implicit in the
        // other tests via the Default IntruderConfig.
        let rules = vec![PayloadProcessingRule::Prefix {
            value: "x_".into(),
        }];
        assert_eq!(apply_processing("admin", &rules), "x_admin");
        assert_eq!(apply_processing("", &rules), "x_");
    }

    #[test]
    fn processing_chained_urlencode_then_base64() {
        // UrlEncode first (so `&` becomes `%26`), then Base64Encode
        // the whole thing. Order matters, so this is the acid test
        // for sequential application.
        let rules = vec![
            PayloadProcessingRule::UrlEncode,
            PayloadProcessingRule::Base64Encode,
        ];
        // "a&b" -> url -> "a%26b" -> base64 -> "YSUyNmI="
        assert_eq!(apply_processing("a&b", &rules), "YSUyNmI=");
    }

    #[test]
    fn processing_match_replace_regex_capture_group() {
        // $1-style capture-group reference in the replacement should
        // work when `regex: true`. When `regex: false`, patterns are
        // treated as literals.
        let rules = vec![PayloadProcessingRule::MatchReplace {
            pattern: r"(\d+)".into(),
            replacement: "[$1]".into(),
            regex: true,
        }];
        assert_eq!(apply_processing("user42admin", &rules), "user[42]admin");

        let literal = vec![PayloadProcessingRule::MatchReplace {
            pattern: "admin".into(),
            replacement: "ROOT".into(),
            regex: false,
        }];
        assert_eq!(apply_processing("adminadmin", &literal), "ROOTROOT");

        // Bad regex must be a no-op, not a panic.
        let bad = vec![PayloadProcessingRule::MatchReplace {
            pattern: "(unclosed".into(),
            replacement: "X".into(),
            regex: true,
        }];
        assert_eq!(apply_processing("hello", &bad), "hello");
    }

    #[test]
    fn processing_hash_outputs_hex() {
        // MD5 of empty string → d41d8cd98f00b204e9800998ecf8427e.
        let rules = vec![PayloadProcessingRule::Md5];
        assert_eq!(
            apply_processing("", &rules),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn rebuild_request_restores_target_and_body() {
        // Use an ASCII marker so the URL parser doesn't percent-encode
        // it inside the path during Request::new. Burp defaults to §
        // but the engine happily accepts any character.
        let mut t = Request::new("POST", "http://127.0.0.1:1/users?id=~X~").unwrap();
        t.body = b"name=~Y~&role=admin".to_vec();
        t.headers.set("Content-Type", "application/x-www-form-urlencoded");
        let r = rebuild_request(&t, '~', &["42".into(), "alice".into()]);
        assert_eq!(r.path, "/users?id=42");
        assert_eq!(r.text(), "name=alice&role=admin");
        // Content-Length is refreshed to match the new body length.
        assert_eq!(
            r.headers.get("Content-Length").unwrap(),
            r.body.len().to_string()
        );
    }

    /// Null-mode attack: fires the base template `null_count` times
    /// unchanged. The mock server counts hits and inspects the
    /// request-line path to confirm the §marker§ pairs were stripped
    /// to just the inner content.
    #[tokio::test]
    async fn null_mode_fires_base_template_n_times() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        // Collect every unique path the server saw. Null mode should
        // produce a single stable path repeated `null_count` times.
        let paths = Arc::new(Mutex::new(Vec::<String>::new()));
        let paths_srv = paths.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let hits = hits_srv.clone();
                let paths = paths_srv.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap();
                    let first = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let path = first
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    paths.lock().push(path);
                    hits.fetch_add(1, Ordering::Relaxed);
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        )
                        .await;
                });
            }
        });

        let mut template = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/", addr.port()),
        )
        .unwrap();
        // Markers wrap a base value ("alice"). Null mode must strip
        // the §…§ wrappers and leave `/users/alice` behind.
        template.path = "/users/~alice~".to_string();

        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Null,
            payloads: Vec::new(),
            concurrency: 1,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: Some(3),
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        assert_eq!(handle.total, 3, "null_count=3 should plan 3 iterations");
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 3, "all three iterations deliver a result");
        // Null-mode payloads tuple is always empty — nothing was
        // substituted. The UI relies on this to render a "—" row.
        for r in &results {
            assert!(
                r.payloads.is_empty(),
                "Null-mode results carry no payload tuple, got: {:?}",
                r.payloads
            );
            assert_eq!(r.status, Some(200));
        }
        // All three sends hit the same stripped path.
        let seen = paths.lock().clone();
        assert_eq!(seen.len(), 3);
        for p in &seen {
            assert_eq!(p, "/users/alice", "markers must be stripped but content kept");
        }
        assert_eq!(hits.load(Ordering::Relaxed), 3);
    }

    /// Pause / Resume: the dispatcher must freeze new iterations
    /// while the flag is raised, then catch up when it clears.
    /// Burp's "Pause attack" button lands here.
    #[tokio::test]
    async fn pause_freezes_dispatch_until_resumed() {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        )
                        .await;
                });
            }
        });

        let mut template = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/", addr.port()),
        )
        .unwrap();
        template.path = "/u/~X~".to_string();

        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "a".into(),
                "b".into(),
                "c".into(),
                "d".into(),
            ]))],
            // Serialize dispatches so we can observe the pause effect
            // deterministically — otherwise 4 concurrent spawns might
            // all land before pause is observed.
            concurrency: 1,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            // 100ms per-dispatch delay gives the pause flag a wide
            // window to engage between iterations.
            delay_ms: Some(100),
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        // Raise the pause flag immediately — before the first
        // dispatch window closes. Any iteration past the gate still
        // runs to completion, so the counter may land on 1.
        handle.pause.store(true, Ordering::Relaxed);
        // Wait longer than 3 × delay_ms (300 ms); if pause isn't
        // working the counter would have reached 4.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let paused_count = handle.counter.load(Ordering::Relaxed);
        assert!(
            paused_count <= 1,
            "paused dispatcher should have ≤1 completion; got {paused_count}"
        );
        // Resume — the three (or four) remaining iterations run.
        handle.pause.store(false, Ordering::Relaxed);
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(
            results.len(),
            4,
            "all 4 iterations deliver results after resume"
        );
        assert_eq!(handle.counter.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn strip_markers_keeps_inner_content_in_all_parts() {
        // Covers the three places insertion points can live: path,
        // headers, and body. Each marker pair must become its inner
        // content and the Content-Length must track the stripped
        // body length.
        let mut t = Request::new("POST", "http://x.local/~id~/edit").unwrap();
        t.headers.set("X-Custom", "pre-~token~-suffix");
        t.body = b"name=~alice~&role=~admin~".to_vec();
        t.headers.set("Content-Length", t.body.len().to_string());

        let stripped = strip_markers_keep_content(&t, '~');
        assert_eq!(stripped.path, "/id/edit");
        assert_eq!(
            stripped.headers.get("X-Custom").unwrap(),
            "pre-token-suffix"
        );
        assert_eq!(stripped.text(), "name=alice&role=admin");
        // CL must match the new body length (21), not the original.
        assert_eq!(
            stripped.headers.get("Content-Length").unwrap(),
            "21"
        );
    }

    #[tokio::test]
    async fn end_to_end_sniper() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap();
                    let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap().to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = format!("got {path}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });

        let mut template = Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        // Set path directly to avoid URL percent-encoding the marker.
        template.path = "/u/~X~".to_string();

        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "alice".into(),
                "bob".into(),
            ]))],
            concurrency: 2,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: Some(r"got /u/(\w+)".into()),
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 2);
        let mut extracted: Vec<_> = results
            .iter()
            .map(|r| r.extracted.clone().unwrap_or_default())
            .collect();
        extracted.sort();
        assert_eq!(extracted, vec!["alice", "bob"]);
    }

    #[tokio::test]
    async fn grep_match_flags_only_matching_rows() {
        // Server returns "welcome admin" when path contains "admin",
        // "no match here" otherwise. The probe fires with two
        // payloads — one triggers the welcome string, the other
        // doesn't — so exactly one row should be `grep_matched = true`.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap();
                    let line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap()
                        .to_string();
                    let path =
                        line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = if path.contains("admin") {
                        "<html><body>Welcome Admin dashboard</body></html>"
                    } else {
                        "<html><body>no match here</body></html>"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        let mut template =
            Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "admin".into(),
                "guest".into(),
            ]))],
            concurrency: 2,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            // Case-insensitive match — mock emits "Welcome Admin".
            grep_match: Some("welcome admin".into()),
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 2);
        let matched: Vec<&AttackResult> =
            results.iter().filter(|r| r.grep_matched).collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].payloads, vec!["admin".to_string()]);
    }

    /// Multi grep-match: three rules against two responses. Rule "a"
    /// matches both (via a case-insensitive regex), rule "b" matches
    /// only the admin response, rule "c" never matches. Every row
    /// must carry a `matched` vec of length 3 with the correct
    /// booleans at each index — regardless of which payload drove
    /// that row. Also seeds a deliberately-broken fourth rule to
    /// confirm invalid regexes compile to a silent false (one bad
    /// pattern can't take down the whole attack).
    #[tokio::test]
    async fn multiple_grep_matches_produce_indexed_columns() {
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
                        .unwrap()
                        .to_string();
                    let path =
                        line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    // Both paths emit the token "welcome" so rule "a"
                    // fires on both; only the admin path adds
                    // "superuser dashboard" so rule "b" fires on it
                    // alone.
                    let body = if path.contains("admin") {
                        "<html>welcome Superuser Dashboard</html>"
                    } else {
                        "<html>welcome visitor</html>"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        let mut template =
            Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "admin".into(),
                "guest".into(),
            ]))],
            concurrency: 2,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: vec![
                MatchRule { name: "welcome".into(), pattern: "welcome".into() },
                MatchRule { name: "superuser".into(), pattern: "superuser dashboard".into() },
                MatchRule { name: "token".into(), pattern: r"TOKEN=[A-F0-9]+".into() },
                // Unbalanced paren — Regex::new fails ⇒ silent false column.
                MatchRule { name: "broken".into(), pattern: r"(unclosed".into() },
            ],
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.matched.len(), 4, "every row has 4 columns");
            // Rule 0 "welcome" fires on both.
            assert!(r.matched[0], "welcome always fires");
            // Rule 2 "token" never fires.
            assert!(!r.matched[2], "token never fires");
            // Rule 3 "broken" always false (regex compile failed).
            assert!(!r.matched[3], "broken rule is silent-false");
        }
        // Rule 1 "superuser dashboard" fires only on the admin row.
        let admin = results.iter().find(|r| r.payloads == vec!["admin".to_string()]).unwrap();
        let guest = results.iter().find(|r| r.payloads == vec!["guest".to_string()]).unwrap();
        assert!(admin.matched[1], "superuser row hits rule 1");
        assert!(!guest.matched[1], "guest row misses rule 1");
        // Legacy single `grep_match` not configured ⇒ grep_matched is
        // false everywhere; multi-match operates independently.
        assert!(results.iter().all(|r| !r.grep_matched));
    }

    /// With `delay_ms = 100` and 3 payloads at `concurrency = 1`, the
    /// whole attack must take at least 2 * 100 ms (first dispatch is
    /// un-delayed in practice when `rate_per_sec` is None — but the
    /// implementation always sleeps if `delay_ms > 0`, so really ≥
    /// 300 ms; be lenient to avoid CI flake).
    #[tokio::test]
    async fn delay_ms_introduces_pause() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    ).await;
                });
            }
        });

        let mut template = Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "a".into(),
                "b".into(),
                "c".into(),
            ]))],
            concurrency: 1,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: Some(100),
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let start = std::time::Instant::now();
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        let elapsed = start.elapsed();
        assert_eq!(results.len(), 3);
        // 3 iterations × 100 ms = 300 ms, give a 50 ms CI-flake margin
        // on the lower bound to still prove the delay actually fires.
        assert!(
            elapsed >= Duration::from_millis(250),
            "expected ≥250 ms with delay_ms=100 over 3 iterations, got {elapsed:?}"
        );
    }

    /// A target that always errors out (we bind the listener then
    /// immediately drop it, so TCP connects fail) with
    /// `pause_on_error_ms = 150` and 3 payloads must take ≥ 2 * 150
    /// ms worth of backoff pauses between dispatches.
    #[tokio::test]
    async fn pause_on_error_delays_after_failure() {
        // Bind & drop so the port is briefly reserved then free —
        // subsequent connects should ECONNREFUSED fast.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let mut template = Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "a".into(),
                "b".into(),
                "c".into(),
            ]))],
            concurrency: 1,
            rate_per_sec: None,
            timeout: Duration::from_millis(500),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: Some(150),
            deduplicate_payloads: false,
            null_count: None,
        };
        let start = std::time::Instant::now();
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        let elapsed = start.elapsed();
        assert_eq!(results.len(), 3);
        // Every send errors so every subsequent dispatch sleeps.
        // Lower bound: iterations 2 and 3 each incur ≥150 ms backoff
        // ⇒ ≥ 300 ms total. Be lenient for CI.
        assert!(
            elapsed >= Duration::from_millis(250),
            "expected ≥250 ms pause-on-error over 3 failing iterations, got {elapsed:?}"
        );
        // Every row carries an error (not "cancelled").
        for r in &results {
            assert!(r.error.is_some(), "row must have an error");
            assert_ne!(r.error.as_deref(), Some("cancelled"));
        }
    }

    /// Two Grep-Extract rules against a server that echoes the path.
    /// Each row's `extracted_fields[i]` must line up with rule i and
    /// carry the matching capture (or None when the rule's regex
    /// didn't match on that response).
    #[tokio::test]
    async fn multiple_extracts_produce_indexed_columns() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Each response's body is `user=<path-tail> role=admin id=42`.
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap();
                    let line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap()
                        .to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let tail = path.rsplit('/').next().unwrap_or("");
                    let body = format!("user={tail} role=admin id=42");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });

        let mut template = Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "alice".into(),
                "bob".into(),
            ]))],
            concurrency: 2,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: vec![
                ExtractRule { name: "user".into(), regex: r"user=(\w+)".into() },
                ExtractRule { name: "id".into(), regex: r"id=(\d+)".into() },
                // A rule that never matches on these responses.
                ExtractRule { name: "token".into(), regex: r"TOKEN=([A-F0-9]+)".into() },
            ],
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.extracted_fields.len(), 3);
            // "user" column — pulls the path tail (either alice or bob).
            let u = r.extracted_fields[0].as_deref().unwrap_or("");
            assert!(u == "alice" || u == "bob", "u was {u:?}");
            // "id" column — always "42".
            assert_eq!(r.extracted_fields[1].as_deref(), Some("42"));
            // "token" column — never matches ⇒ None.
            assert_eq!(r.extracted_fields[2], None);
        }
    }

    /// With `follow_redirects = Always` + max 3 hops, a Sniper over
    /// a server that responds with a 302 → 200 chain must land on
    /// status 200 and extract the final-page body. Mirrors Burp's
    /// per-attack "Redirections" option.
    #[tokio::test]
    async fn follow_redirects_policy_is_honoured() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let resp = if path.starts_with("/final") {
                        // Terminal hop — body carries the token we
                        // assert on so we know the redirect was
                        // actually followed to completion.
                        let body = "done";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                    } else {
                        // Any other path → 302 to /final (relative so
                        // the client resolves against the current URL).
                        "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    };
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        let mut template = Request::new("GET", &format!("http://127.0.0.1:{port}/")).unwrap();
        template.path = "/u/~X~".to_string();
        let http_cfg = HttpClientConfig {
            follow_redirects: burpfree_core::net::FollowRedirectPolicy::Always,
            max_redirect_hops: 3,
            ..HttpClientConfig::default()
        };
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "alice".into(),
                "bob".into(),
            ]))],
            concurrency: 2,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: http_cfg,
            // Extract the body token so we know we're seeing the
            // final response, not a captured 302.
            extract_regex: Some(r"(done)".into()),
            extracts: Vec::new(),
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.status, Some(200), "row did not reach 200: {r:?}");
            assert_eq!(r.extracted.as_deref(), Some("done"));
        }
    }

    /// One well-formed rule plus one with a syntactically invalid
    /// regex. Attack still completes; the bad rule yields None on
    /// every row and the good rule's column is unaffected.
    #[tokio::test]
    async fn extract_rule_bad_regex_yields_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let body = "status=ok count=5";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        let mut template = Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap();
        template.path = "/u/~X~".to_string();
        let cfg = IntruderConfig {
            template,
            marker: '~',
            mode: AttackMode::Sniper,
            payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                "a".into(),
            ]))],
            concurrency: 1,
            rate_per_sec: None,
            timeout: Duration::from_secs(5),
            retries: 0,
            http: HttpClientConfig::default(),
            extract_regex: None,
            extracts: vec![
                ExtractRule {
                    name: "count".into(),
                    regex: r"count=(\d+)".into(),
                },
                // Unbalanced paren — regex::Regex::new fails.
                ExtractRule {
                    name: "broken".into(),
                    regex: r"(unclosed".into(),
                },
            ],
            status_filter: Default::default(),
            payload_processing: Vec::new(),
            grep_match: None,
            grep_matches: Vec::new(),
            delay_ms: None,
            delay_jitter_ms: None,
            pause_on_error_ms: None,
            deduplicate_payloads: false,
            null_count: None,
        };
        let mut handle = IntruderJob::start(cfg).unwrap();
        let mut results = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            results.push(r);
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].extracted_fields.len(), 2);
        assert_eq!(results[0].extracted_fields[0].as_deref(), Some("5"));
        assert_eq!(results[0].extracted_fields[1], None);
    }

    /// With `deduplicate_payloads = true`, a Sniper over a list with
    /// explicit duplicates must only dispatch one row per distinct
    /// payload × position combo. Baseline (flag off) dispatches every
    /// row — we assert both to prove the filter is actually gating.
    #[tokio::test]
    async fn deduplicate_payloads_strips_duplicate_combos() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        async fn mock_server() -> (u16, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                loop {
                    let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 2048];
                        let _ = s.read(&mut buf).await;
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        ).await;
                    });
                }
            });
            (addr.port(), handle)
        }

        let make_cfg = |port: u16, dedupe: bool| {
            let mut template = Request::new("GET", &format!("http://127.0.0.1:{port}/")).unwrap();
            template.path = "/u/~X~".to_string();
            IntruderConfig {
                template,
                marker: '~',
                mode: AttackMode::Sniper,
                payloads: vec![PayloadProvider::List(SimpleListProvider::new(vec![
                    // Two distinct values but `alice` appears thrice.
                    "alice".into(),
                    "alice".into(),
                    "bob".into(),
                    "alice".into(),
                ]))],
                concurrency: 2,
                rate_per_sec: None,
                timeout: Duration::from_secs(5),
                retries: 0,
                http: HttpClientConfig::default(),
                extract_regex: None,
                extracts: Vec::new(),
                status_filter: Default::default(),
                payload_processing: Vec::new(),
                grep_match: None,
                grep_matches: Vec::new(),
                delay_ms: None,
                delay_jitter_ms: None,
                pause_on_error_ms: None,
                deduplicate_payloads: dedupe,
                null_count: None,
            }
        };

        // Baseline — flag off, every raw combo dispatches.
        let (port, _h) = mock_server().await;
        let mut handle = IntruderJob::start(make_cfg(port, false)).unwrap();
        let mut baseline = Vec::new();
        while let Some(r) = handle.rx.recv().await {
            baseline.push(r);
        }
        // 4 payload values × 1 position = 4 raw rows.
        assert_eq!(baseline.len(), 4);

        // Flag on — only 2 unique rows (alice + bob).
        let (port2, _h2) = mock_server().await;
        let mut handle2 = IntruderJob::start(make_cfg(port2, true)).unwrap();
        let mut deduped = Vec::new();
        while let Some(r) = handle2.rx.recv().await {
            deduped.push(r);
        }
        assert_eq!(deduped.len(), 2);
        // Dispatch order is non-deterministic under concurrency; sort
        // by `index` to assert the first-occurrence order preserved
        // by the dedup filter.
        deduped.sort_by_key(|r| r.index);
        assert_eq!(deduped[0].index, 0);
        assert_eq!(deduped[0].payloads, vec!["alice".to_string()]);
        assert_eq!(deduped[1].index, 1);
        assert_eq!(deduped[1].payloads, vec!["bob".to_string()]);
    }
}
