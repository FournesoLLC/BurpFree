//! Tauri commands invoked by the React frontend.
//!
//! Every command returns `Result<T, String>` where errors are
//! stringified for the UI. Internally they call into the engine
//! crates, keeping the frontend as a pure view layer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use burpfree_core::ids::TrafficId;
use burpfree_core::scope::{Scope, ScopeRule};
use burpfree_core::traffic::{Request, Transaction};
use burpfree_engines::intruder::{AttackResult, IntruderConfig, IntruderJob, JobStatus};
use burpfree_engines::repeater::RepeaterTab;
use burpfree_engines::scanner::{passive, Finding};
use burpfree_engines::sequencer::{analyze_tokens, TokenAnalysis};
use burpfree_proxy::server::{ServerConfig, TrafficSink};
use burpfree_proxy::{MatchReplaceEngine, ProxyServer, Upstream};
use burpfree_storage::history::StoredFinding;
use burpfree_storage::StoredSummary;
use burpfree_storage::HistoryFilter;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::{AppState, ProjectHandle};

type AppStateRef<'a> = State<'a, Arc<AppState>>;

fn fail(e: impl std::fmt::Display) -> String {
    format!("{e}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub root: PathBuf,
    pub name: String,
    pub listeners: Vec<String>,
    pub tx_count: i64,
    pub scope_rules: usize,
}

#[tauri::command]
pub async fn project_open_or_create(path: PathBuf, state: AppStateRef<'_>) -> Result<ProjectInfo, String> {
    state.load_project(path).map_err(fail)?;
    project_info(state).await
}

/// Returns the OS-appropriate default project path:
/// * Windows: `%LOCALAPPDATA%\BurpFree\default-project`
/// * macOS:   `~/Library/Application Support/BurpFree/default-project`
/// * Linux:   `~/.local/share/BurpFree/default-project`
#[tauri::command]
pub async fn default_project_path() -> Result<String, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "cannot resolve data local dir".to_string())?;
    let path = base.join("BurpFree").join("default-project");
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn project_info(state: AppStateRef<'_>) -> Result<ProjectInfo, String> {
    let h = state.require().map_err(fail)?;
    let (root, name, listeners, scope_rules, hist) = {
        let p = h.project.read();
        (
            p.root.clone(),
            p.config.name.clone(),
            p.config.listeners.iter().map(|l| l.address.clone()).collect::<Vec<_>>(),
            p.config.scope.rules.len(),
            p.history.clone(),
        )
    };
    let count = hist.count(&HistoryFilter::default()).map_err(fail)?;
    Ok(ProjectInfo { root, name, listeners, tx_count: count, scope_rules })
}

#[tauri::command]
pub async fn proxy_start(state: AppStateRef<'_>) -> Result<Vec<String>, String> {
    let h = state.require().map_err(fail)?;
    if h.proxy.read().is_some() {
        return Err("proxy already running".into());
    }
    let config = { h.project.read().config.clone() };
    let sink: Arc<dyn TrafficSink> = Arc::new(ProjectSink::from_handle(&h));
    let cfg = ServerConfig {
        listeners: config.listen_addrs(),
        ca: h.ca.clone(),
        upstream: h.upstream.clone(),
        scope: h.scope.clone(),
        match_replace: h.match_replace.clone(),
        interceptor: h.interceptor.clone(),
        events: state.events.clone(),
        sink,
        decompression_cap_bytes: config.decompression_cap_mb as usize * 1024 * 1024,
        max_body_bytes: config.max_body_mb as u64 * 1024 * 1024,
        connect_timeout: Duration::from_secs(30),
        record_out_of_scope: state.record_out_of_scope.clone(),
        host_overrides: h.host_overrides.clone(),
        tls_passthrough: state.tls_passthrough.clone(),
        platform_auth: state.platform_auth.clone(),
    };
    let proxy_handle = ProxyServer::start(cfg).await.map_err(fail)?;
    let addrs: Vec<String> = proxy_handle.listen_addrs.iter().map(|a| a.to_string()).collect();
    *h.proxy.write() = Some(proxy_handle);
    Ok(addrs)
}

#[tauri::command]
pub async fn proxy_stop(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let handle = h.proxy.write().take();
    if let Some(ph) = handle {
        ph.shutdown().await.map_err(fail)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatsView {
    pub running: bool,
    pub listeners: Vec<String>,
    pub conns_accepted: u64,
    pub requests_forwarded: u64,
    pub responses_recorded: u64,
    pub errors: u64,
    pub tls_mitm: u64,
}

#[tauri::command]
pub async fn proxy_stats(state: AppStateRef<'_>) -> Result<ProxyStatsView, String> {
    let h = state.require().map_err(fail)?;
    let guard = h.proxy.read();
    match guard.as_ref() {
        Some(ph) => {
            let s = ph.stats();
            Ok(ProxyStatsView {
                running: true,
                listeners: ph.listen_addrs.iter().map(|a| a.to_string()).collect(),
                conns_accepted: s.conns_accepted,
                requests_forwarded: s.requests_forwarded,
                responses_recorded: s.responses_recorded,
                errors: s.errors,
                tls_mitm: s.tls_mitm,
            })
        }
        None => Ok(ProxyStatsView {
            running: false,
            listeners: Vec::new(),
            conns_accepted: 0,
            requests_forwarded: 0,
            responses_recorded: 0,
            errors: 0,
            tls_mitm: 0,
        }),
    }
}

#[tauri::command]
pub async fn ca_export(path: PathBuf, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.ca.export_root(&path).map_err(fail)
}

#[tauri::command]
pub async fn ca_info(state: AppStateRef<'_>) -> Result<burpfree_ca::CaInfo, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ca.info())
}

#[tauri::command]
pub async fn history_list(filter: Option<HistoryFilter>, state: AppStateRef<'_>) -> Result<Vec<StoredSummary>, String> {
    let h = state.require().map_err(fail)?;
    let f = filter.unwrap_or_default();
    let hist = h.project.read().history.clone();
    hist.list(&f).map_err(fail)
}

#[tauri::command]
pub async fn history_count(filter: Option<HistoryFilter>, state: AppStateRef<'_>) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let f = filter.unwrap_or_default();
    let hist = h.project.read().history.clone();
    hist.count(&f).map_err(fail)
}

/// Fetch summaries for a batch of transaction IDs. Used by the site-map
/// right-pane to materialise the rich column view for a selected node.
#[tauri::command]
pub async fn history_summaries(ids: Vec<i64>, state: AppStateRef<'_>) -> Result<Vec<StoredSummary>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(s) = hist.get_summary(TrafficId::from(id)).map_err(fail)? {
            out.push(s);
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct TransactionView {
    pub summary: StoredSummary,
    pub request_raw: String,
    pub response_raw: Option<String>,
}

#[tauri::command]
pub async fn history_show(id: i64, state: AppStateRef<'_>) -> Result<TransactionView, String> {
    let h = state.require().map_err(fail)?;
    let tid = TrafficId::from(id);
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let summary = hist.get_summary(tid).map_err(fail)?.ok_or("not found")?;
    let request_raw = match hist.get_request_blob(tid).map_err(fail)? {
        Some(r) => blobs
            .get(&r)
            .map_err(fail)?
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default(),
        None => String::new(),
    };
    let response_raw = match hist.get_response_blob(tid).map_err(fail)? {
        Some(r) => blobs
            .get(&r)
            .map_err(fail)?
            .map(|b| String::from_utf8_lossy(&b).to_string()),
        None => None,
    };
    Ok(TransactionView { summary, request_raw, response_raw })
}

#[tauri::command]
pub async fn history_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.clear().map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct HistoryHighlightArgs {
    pub id: i64,
    /// Named Burp-style highlight. `None` or an empty string clears the
    /// highlight. The frontend passes one of {red, orange, yellow,
    /// green, cyan, blue, purple} verbatim.
    #[serde(default)]
    pub color: Option<String>,
}

#[tauri::command]
pub async fn history_set_highlight(
    args: HistoryHighlightArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let normalised = args
        .color
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    hist.set_highlight(TrafficId::from(args.id), normalised)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct HistoryCommentArgs {
    pub id: i64,
    pub comment: String,
}

#[tauri::command]
pub async fn history_set_comment(
    args: HistoryCommentArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.set_comment(TrafficId::from(args.id), &args.comment)
        .map_err(fail)
}

/// R320: Replace the row's tag set with the supplied list. The
/// backing `TransactionStore::set_tags` has existed since the
/// column was added (R100-era) but no Tauri command wired it up;
/// adding it now so the HistoryPanel can batch-tag selected rows
/// for jq / Jira / ELK ingest workflows (matches the R312
/// Scanner `+ Add tag` bulk op, which uses the parallel
/// `finding_set_tags` RPC). Replace-mode semantics match the
/// backend method; the frontend handles merge-logic (read-current
/// → union → set) so this stays a plain setter.
#[derive(Debug, Deserialize)]
pub struct HistoryTagsArgs {
    pub id: i64,
    pub tags: Vec<String>,
}

#[tauri::command]
pub async fn history_set_tags(
    args: HistoryTagsArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.set_tags(TrafficId::from(args.id), &args.tags)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct HistoryDeleteArgs {
    pub ids: Vec<i64>,
}

/// Bulk-delete the given transactions. Caller receives the number of
/// rows actually removed (which may be smaller than `ids.len()` if
/// some ids weren't in the project).
#[tauri::command]
pub async fn history_delete(
    args: HistoryDeleteArgs,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let typed: Vec<TrafficId> = args.ids.iter().map(|i| TrafficId::from(*i)).collect();
    hist.delete_many(&typed).map_err(fail)
}

/// Re-fire a stored request through the project's shared HTTP client
/// and record the paired response as a brand-new history row. Mirror
/// of Burp's HTTP history → right-click → "Request in browser" /
/// "Resend request" pathway; here we skip the browser hop and go
/// straight to the client so the operator can quickly re-verify an
/// errored probe or an interesting response without opening a
/// Repeater tab for every one-shot. Returns the new transaction id
/// so the UI can auto-select the fresh row.
///
/// The replay is a direct byte-level resend: no edits, no injected
/// headers, no scope / match-replace reinterpretation. If the source
/// transaction's bytes contained encoded content (gzip / chunked),
/// the replay sends those bytes verbatim and the server decides what
/// to do. `annotation` on the new request carries `"replayed from
/// #<orig_id>"` so the operator can trace back from the history row.
#[tauri::command]
pub async fn history_replay(id: i64, state: AppStateRef<'_>) -> Result<i64, String> {
    use burpfree_core::traffic::RequestSource;
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let tid = TrafficId::from(id);
    let summary = hist
        .get_summary(tid)
        .map_err(fail)?
        .ok_or_else(|| "transaction not found".to_string())?;
    let req_blob = hist
        .get_request_blob(tid)
        .map_err(fail)?
        .ok_or_else(|| "no request blob stored".to_string())?;
    let req_bytes = blobs
        .get(&req_blob)
        .map_err(fail)?
        .ok_or_else(|| "request blob missing from store".to_string())?;
    let orig = rebuild_transaction(&summary, &req_bytes, None).map_err(fail)?;

    // Fresh id so the new row doesn't collide with the source and so
    // scanner/sitemap fingerprints treat it as a distinct observation.
    // `Manual` as the source — this isn't a Repeater tab send, and we
    // don't have a dedicated `Replayed` variant yet. The parent_id
    // chain + the annotation below carry the replay semantics.
    let mut new_req = orig.request.clone_with_new_id(RequestSource::Manual);
    new_req.annotation = format!("replayed from #{id}");

    // One-shot through the shared client. Follow-redirects policy is
    // whatever the Repeater's client is configured with — same as a
    // Repeater send so behaviour is predictable.
    let client = h.repeater.http_client();
    let (response, error) = match client.send(&new_req).await {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(e.to_string())),
    };

    let mut new_tx = Transaction::new(new_req);
    new_tx.in_scope = orig.in_scope;
    new_tx.response = response;
    new_tx.error = error;

    // Serialize both halves back to the wire so the blob store sees
    // the exact bytes the UI will reconstruct — matches how the
    // proxy records transactions (`upsert_transaction` reads blob
    // bytes verbatim when rebuilding).
    let new_req_blob = blobs
        .put(&new_tx.request.to_wire_bytes())
        .map_err(fail)?;
    let new_resp_blob = new_tx
        .response
        .as_ref()
        .map(|r| blobs.put(&r.to_wire_bytes()).map_err(fail))
        .transpose()?;
    hist.upsert_transaction(&new_tx, &new_req_blob, new_resp_blob.as_ref())
        .map_err(fail)?;

    tracing::info!(
        source_id = id,
        new_id = new_tx.id.as_i64(),
        has_response = new_tx.response.is_some(),
        "history_replay recorded"
    );
    Ok(new_tx.id.as_i64())
}

// ---- MCP server surface -------------------------------------------------

#[derive(Debug, Serialize)]
pub struct McpToolView {
    pub name: String,
    pub description: String,
    /// JSON schema accepted by this tool. The Discover-style UI table
    /// doesn't render it fully; it's included so the operator can
    /// inspect it when designing a client prompt.
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct McpStatus {
    pub protocol_version: String,
    pub server_name: String,
    pub server_version: String,
    pub exe_path: String,
    pub project_path: Option<String>,
    /// Argv that an external MCP client (Claude Desktop, Cline, …) should
    /// use. First element is `exe_path`.
    pub command_argv: Vec<String>,
    /// Ready-to-paste Claude Desktop config entry.
    pub claude_config_json: String,
    pub tools: Vec<McpToolView>,
}

#[tauri::command]
pub async fn mcp_status(state: AppStateRef<'_>) -> Result<McpStatus, String> {
    let project_path = state
        .require()
        .ok()
        .map(|h| h.path.to_string_lossy().into_owned());
    Ok(build_mcp_status(project_path))
}

fn build_mcp_status(project_path: Option<String>) -> McpStatus {
    let exe = std::env::current_exe()
        .map(|p| p.with_file_name("burpfree.exe").to_string_lossy().into_owned())
        .unwrap_or_else(|_| "burpfree".into());
    let exe_path = if std::path::Path::new(&exe).exists() {
        exe
    } else {
        "burpfree".into()
    };

    let mut command_argv = vec![exe_path.clone(), "mcp".into()];
    if let Some(p) = project_path.as_ref() {
        command_argv.push("--project".into());
        command_argv.push(p.clone());
    }

    let claude_cfg = serde_json::json!({
        "mcpServers": {
            "burpfree": {
                "command": exe_path.clone(),
                "args": command_argv[1..].to_vec(),
            }
        }
    });
    let claude_config_json = serde_json::to_string_pretty(&claude_cfg).unwrap_or_default();

    let registry = burpfree_mcp::ToolRegistry::with_defaults();
    let tools: Vec<McpToolView> = registry
        .specs()
        .into_iter()
        .map(|s| McpToolView {
            name: s.name,
            description: s.description,
            input_schema: s.input_schema,
        })
        .collect();

    McpStatus {
        protocol_version: burpfree_mcp::MCP_PROTOCOL_VERSION.into(),
        server_name: "burpfree-mcp".into(),
        server_version: env!("CARGO_PKG_VERSION").into(),
        exe_path: command_argv[0].clone(),
        project_path,
        command_argv,
        claude_config_json,
        tools,
    }
}

#[derive(Debug, Serialize)]
pub struct McpTestResult {
    pub ok: bool,
    pub summary: String,
    /// Lines captured from the server's stderr during the test.
    pub stderr_tail: Vec<String>,
}

/// Spawn `burpfree.exe mcp --project P` as a short-lived child, send
/// `initialize` + `ping`, and verify both get a response. Returns a
/// human-readable summary.
#[tauri::command]
pub async fn mcp_test(state: AppStateRef<'_>) -> Result<McpTestResult, String> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let project_path = state
        .require()
        .ok()
        .map(|h| h.path.to_string_lossy().into_owned());
    if project_path.is_none() {
        return Err("open a project first".into());
    }
    let status = build_mcp_status(project_path);

    let mut cmd = tokio::process::Command::new(&status.exe_path);
    cmd.args(&status.command_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(fail)?;

    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;

    let frames = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        "\n",
    );
    stdin.write_all(frames.as_bytes()).await.map_err(fail)?;
    stdin.flush().await.map_err(fail)?;
    drop(stdin); // close so the server sees EOF after the three frames

    // Read responses with a wall-clock timeout so a hung server can't
    // pin the UI thread.
    let read_task = async {
        let mut lines = Vec::new();
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            lines.push(line);
            if lines.len() >= 2 {
                break;
            }
        }
        lines
    };
    let stdout_lines =
        match tokio::time::timeout(Duration::from_secs(5), read_task).await {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

    // Grab stderr tail (whatever's buffered within a short window).
    let stderr_task = async {
        let mut tail = Vec::new();
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            tail.push(line);
            if tail.len() >= 20 {
                break;
            }
        }
        tail
    };
    let stderr_tail =
        match tokio::time::timeout(Duration::from_millis(200), stderr_task).await {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

    let _ = child.start_kill();
    let _ = child.wait().await;

    let mut initialize_ok = false;
    let mut ping_ok = false;
    for line in &stdout_lines {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            match v.get("id").and_then(|x| x.as_i64()) {
                Some(1) if v.get("result").is_some() => initialize_ok = true,
                Some(2) if v.get("result").is_some() => ping_ok = true,
                _ => {}
            }
        }
    }

    let summary = if initialize_ok && ping_ok {
        "server responded to initialize + ping (protocol 2025-06-18)".into()
    } else {
        format!(
            "initialize={} ping={} — {} line(s) captured",
            initialize_ok,
            ping_ok,
            stdout_lines.len()
        )
    };

    Ok(McpTestResult {
        ok: initialize_ok && ping_ok,
        summary,
        stderr_tail,
    })
}

// ---- BChecks (declarative active-scan rules) ----------------------------

#[derive(Debug, Serialize)]
pub struct BCheckLoadRow {
    pub path: String,
    pub ok: bool,
    pub name: Option<String>,
    pub severity: Option<String>,
    pub candidates: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BCheckRunReport {
    pub rules_loaded: usize,
    pub rules_ok: usize,
    pub targets: usize,
    pub findings: usize,
    pub elapsed_ms: u64,
    pub load_errors: Vec<String>,
}

fn bchecks_dir(h: &ProjectHandle) -> std::path::PathBuf {
    h.path.join("bchecks")
}

/// List YAML rules in `project/bchecks/`. Each entry carries metadata
/// if the file parsed, or an error message otherwise.
#[tauri::command]
pub async fn bchecks_list(state: AppStateRef<'_>) -> Result<Vec<BCheckLoadRow>, String> {
    let h = state.require().map_err(fail)?;
    let dir = bchecks_dir(&h);
    let mut rows: Vec<BCheckLoadRow> = burpfree_engines::bchecks::load_dir(&dir)
        .into_iter()
        .map(|(path, res)| match res {
            Ok(c) => BCheckLoadRow {
                path: path.to_string_lossy().into_owned(),
                ok: true,
                name: Some(c.metadata.name.clone()),
                severity: Some(match c.severity {
                    burpfree_engines::bchecks::SeverityLabel::Info => "info",
                    burpfree_engines::bchecks::SeverityLabel::Low => "low",
                    burpfree_engines::bchecks::SeverityLabel::Medium => "medium",
                    burpfree_engines::bchecks::SeverityLabel::High => "high",
                    burpfree_engines::bchecks::SeverityLabel::Critical => "critical",
                }
                .to_string()),
                candidates: c.candidates.len(),
                error: None,
            },
            Err(e) => BCheckLoadRow {
                path: path.to_string_lossy().into_owned(),
                ok: false,
                name: None,
                severity: None,
                candidates: 0,
                error: Some(e.to_string()),
            },
        })
        .collect();
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(rows)
}

/// Run every valid BCheck in `project/bchecks/` against the unique
/// `(scheme, host, port)` tuples observed in HTTP history. Newly
/// generated findings are persisted and returned via the usual
/// findings tables.
#[tauri::command]
pub async fn bchecks_run(state: AppStateRef<'_>) -> Result<BCheckRunReport, String> {
    use burpfree_engines::bchecks::{targets_from, BCheckRunConfig, BCheckRunner};
    use burpfree_engines::client::HttpClientConfig;
    use burpfree_storage::history::StoredFinding;

    let h = state.require().map_err(fail)?;
    let dir = bchecks_dir(&h);
    let loaded = burpfree_engines::bchecks::load_dir(&dir);
    let rules_loaded = loaded.len();
    let mut load_errors = Vec::new();
    let mut checks = Vec::new();
    for (path, res) in loaded {
        match res {
            Ok(c) => checks.push(c),
            Err(e) => load_errors.push(format!("{}: {e}", path.display())),
        }
    }
    let rules_ok = checks.len();

    // Collect unique targets from history.
    let (hist, scope) = {
        let p = h.project.read();
        (p.history.clone(), p.config.scope.clone())
    };
    let summaries = hist
        .list(&Default::default())
        .map_err(fail)?;
    let targets = targets_from(
        summaries
            .into_iter()
            .map(|s| (s.scheme, s.host, s.port)),
    );
    let targets_n = targets.len();

    let cfg = HttpClientConfig {
        host_overrides: Some(h.host_overrides.clone()),
        ..HttpClientConfig::default()
    };
    let runner = BCheckRunner::new(cfg, scope, BCheckRunConfig::default());
    let start = std::time::Instant::now();
    let findings = runner.run(&checks, &targets).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Persist findings. Reuse the same conversion logic the passive
    // scan path uses — a direct `StoredFinding::from(Finding)` would
    // be nicer, but inlining keeps us from touching more crates this
    // round.
    for f in &findings {
        let stored = StoredFinding {
            id: f.id,
            ts_ms: chrono::Utc::now().timestamp_millis(),
            transaction_id: f.transaction_id,
            detector: f.detector.clone(),
            title: f.title.clone(),
            description: f.description.clone(),
            severity: f.severity.as_label().to_string(),
            confidence: f.confidence.as_label().to_string(),
            evidence: f.evidence.clone(),
            remediation: f.remediation.clone(),
            fingerprint: f.fingerprint(),
            status: "new".into(),
            verification: "unverified".into(),
            tags: Vec::new(),
            references: f.references.clone(),
            assignee: None,
            note: String::new(),
            insertion_point: f.insertion_point.clone(),
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
            observation_count: 1,
        };
        if let Err(e) = hist.upsert_finding(&stored) {
            tracing::warn!(error = %e, "store bcheck finding");
        }
    }

    Ok(BCheckRunReport {
        rules_loaded,
        rules_ok,
        targets: targets_n,
        findings: findings.len(),
        elapsed_ms,
        load_errors,
    })
}

/// Live validation of a BCheck YAML snippet. Wraps the engine's
/// `bchecks::parse` so the UI can give operators a composer with
/// instant feedback — paste YAML, see parsed metadata (id, title,
/// severity, candidates, tags) on success, or the parse error on
/// failure, without round-tripping through the project's bchecks
/// directory + full re-list.
#[derive(Debug, Serialize)]
pub struct BCheckValidateResult {
    pub ok: bool,
    /// Error context when parsing failed. Includes the first few
    /// lines of the serde_yaml error so column numbers survive.
    pub error: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
    /// How many `candidates:` entries the YAML carries. Operators
    /// use this as a sanity check — a BCheck with zero candidates
    /// is parse-valid but useless since the runner won't dispatch.
    pub candidates: usize,
}

#[derive(Debug, Deserialize)]
pub struct BCheckSaveArgs {
    /// Leaf filename to write under `project/bchecks/`. Must end
    /// `.yaml` or `.yml` and contain no path separators — path
    /// traversal is rejected explicitly rather than silently
    /// normalised, since the operator might have made a typo
    /// intending to overwrite an existing file.
    pub filename: String,
    pub yaml: String,
    /// When `true`, overwrite an existing file. The composer sets
    /// this after a confirm() on the frontend side.
    #[serde(default)]
    pub overwrite: bool,
}

/// Save a validated BCheck YAML to the project's bchecks directory.
/// Mirrors Burp's "export rule" affordance but writes straight to
/// the project so the Run All path picks it up on next refresh. The
/// cmd re-validates on the server side before touching disk — the
/// composer's live-validate is best-effort UI feedback, not a
/// gatekeeper — so an invalid YAML never lands on disk.
#[tauri::command]
pub async fn bchecks_save(
    args: BCheckSaveArgs,
    state: AppStateRef<'_>,
) -> Result<String, String> {
    // Validate the filename: no path separators, must end .yaml/.yml.
    let fname = args.filename.trim();
    if fname.is_empty() {
        return Err("filename is empty".into());
    }
    if fname.contains('/') || fname.contains('\\') || fname.contains("..") {
        return Err("filename must not contain path separators or `..`".into());
    }
    if !(fname.ends_with(".yaml") || fname.ends_with(".yml")) {
        return Err("filename must end with .yaml or .yml".into());
    }
    // Re-validate the YAML before touching disk — the composer's
    // live-check is UX, this is the actual guard.
    burpfree_engines::bchecks::parse(&args.yaml).map_err(fail)?;

    let h = state.require().map_err(fail)?;
    let dir = bchecks_dir(&h);
    std::fs::create_dir_all(&dir).map_err(fail)?;
    let path = dir.join(fname);
    if path.exists() && !args.overwrite {
        return Err(format!(
            "file already exists: {} (pass overwrite=true to replace)",
            path.display()
        ));
    }
    std::fs::write(&path, &args.yaml).map_err(fail)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Read the raw YAML of a BCheck file from `project/bchecks/`.
/// Backs the "Edit in composer" flow — the R103 composer gets
/// pre-filled with the on-disk YAML so the operator can tweak +
/// re-save (R104). Same filename guards as the other BCheck fs
/// cmds. Returns the file bytes as a UTF-8 string; non-UTF8
/// contents fail with a human-readable error.
#[tauri::command]
pub async fn bchecks_read(filename: String, state: AppStateRef<'_>) -> Result<String, String> {
    let fname = filename.trim();
    if fname.is_empty() {
        return Err("filename is empty".into());
    }
    if fname.contains('/') || fname.contains('\\') || fname.contains("..") {
        return Err("filename must not contain path separators or `..`".into());
    }
    if !(fname.ends_with(".yaml") || fname.ends_with(".yml")) {
        return Err("filename must end with .yaml or .yml".into());
    }
    let h = state.require().map_err(fail)?;
    let path = bchecks_dir(&h).join(fname);
    std::fs::read_to_string(&path).map_err(fail)
}

/// Delete a BCheck YAML from `project/bchecks/<filename>`. Mirror
/// of R104's `bchecks_save` safety guards: filename must be a bare
/// leaf (no path separators, no `..`) and end `.yaml`/`.yml`. The
/// backing file is removed with `std::fs::remove_file`; returns
/// `true` iff the file existed (so the UI can skip a redundant
/// refresh on stale rows). Nothing in-memory needs cleanup — the
/// loader walks the dir each `bchecks_list` call.
#[tauri::command]
pub async fn bchecks_delete(filename: String, state: AppStateRef<'_>) -> Result<bool, String> {
    let fname = filename.trim();
    if fname.is_empty() {
        return Err("filename is empty".into());
    }
    if fname.contains('/') || fname.contains('\\') || fname.contains("..") {
        return Err("filename must not contain path separators or `..`".into());
    }
    if !(fname.ends_with(".yaml") || fname.ends_with(".yml")) {
        return Err("filename must end with .yaml or .yml".into());
    }
    let h = state.require().map_err(fail)?;
    let path = bchecks_dir(&h).join(fname);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path).map_err(fail)?;
    Ok(true)
}

#[tauri::command]
pub async fn bchecks_validate(yaml: String) -> Result<BCheckValidateResult, String> {
    match burpfree_engines::bchecks::parse(&yaml) {
        Ok(c) => Ok(BCheckValidateResult {
            ok: true,
            error: None,
            name: Some(c.metadata.name.clone()),
            description: if c.metadata.description.is_empty() {
                None
            } else {
                Some(c.metadata.description.clone())
            },
            author: if c.metadata.author.is_empty() {
                None
            } else {
                Some(c.metadata.author.clone())
            },
            version: if c.metadata.version.is_empty() {
                None
            } else {
                Some(c.metadata.version.clone())
            },
            severity: Some(
                match c.severity {
                    burpfree_engines::bchecks::SeverityLabel::Info => "info",
                    burpfree_engines::bchecks::SeverityLabel::Low => "low",
                    burpfree_engines::bchecks::SeverityLabel::Medium => "medium",
                    burpfree_engines::bchecks::SeverityLabel::High => "high",
                    burpfree_engines::bchecks::SeverityLabel::Critical => "critical",
                }
                .to_string(),
            ),
            tags: c.metadata.tags.clone(),
            candidates: c.candidates.len(),
        }),
        Err(e) => Ok(BCheckValidateResult {
            ok: false,
            // Format the full error chain so causes (e.g. "unknown
            // variant `foo`" at line N) survive to the UI.
            error: Some(format!("{e:#}")),
            name: None,
            description: None,
            author: None,
            version: None,
            severity: None,
            tags: Vec::new(),
            candidates: 0,
        }),
    }
}

// ---- JWT inspector + editor --------------------------------------------

#[derive(Debug, Serialize)]
pub struct JwtDecoded {
    pub token: String,
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature_b64: String,
    /// Where in the transaction we found the token (header name,
    /// cookie name, body-fragment, query key).
    pub location: String,
}

/// Scan a transaction for JWT-shaped substrings. Returns one entry
/// per detected token with its decoded header + payload and a free-
/// text `location` label.
#[tauri::command]
pub async fn jwt_scan_transaction(id: i64, state: AppStateRef<'_>) -> Result<Vec<JwtDecoded>, String> {
    let h = state.require().map_err(fail)?;
    let tid = TrafficId::from(id);
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let summary = hist.get_summary(tid).map_err(fail)?.ok_or("not found")?;
    let request_raw = match hist.get_request_blob(tid).map_err(fail)? {
        Some(r) => blobs
            .get(&r)
            .map_err(fail)?
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default(),
        None => String::new(),
    };
    let response_raw = match hist.get_response_blob(tid).map_err(fail)? {
        Some(r) => blobs
            .get(&r)
            .map_err(fail)?
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default(),
        None => String::new(),
    };

    let mut out = Vec::new();
    // Scan URL (query), request headers + body, response headers + body.
    scan_text_for_jwts(&summary.path, "URL query", &mut out);
    scan_wire_for_jwts(&request_raw, "request", &mut out);
    scan_wire_for_jwts(&response_raw, "response", &mut out);
    Ok(out)
}

fn scan_wire_for_jwts(wire: &str, side: &str, out: &mut Vec<JwtDecoded>) {
    let (header_block, body) = split_header_body_str(wire);
    let header_lines: Vec<&str> = header_block.split('\n').collect();
    for line in header_lines {
        let line = line.trim_end_matches('\r');
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            let label = format!("{side} header: {name}");
            scan_text_for_jwts(value, &label, out);
        }
    }
    // Body: let the generic token-shape regex do the work.
    let body_label = format!("{side} body");
    scan_text_for_jwts(body, &body_label, out);
}

fn split_header_body_str(wire: &str) -> (&str, &str) {
    if let Some(i) = wire.find("\r\n\r\n") {
        return (&wire[..i], &wire[i + 4..]);
    }
    if let Some(i) = wire.find("\n\n") {
        return (&wire[..i], &wire[i + 2..]);
    }
    (wire, "")
}

/// Find every "A.B.C" base64url-ish token in `text`, attempt to decode
/// each as a JWT, and push the hits to `out`. Keeps dedup by token
/// string so the same JWT showing up in Authorization + Cookie
/// doesn't produce a duplicate entry.
fn scan_text_for_jwts(text: &str, location: &str, out: &mut Vec<JwtDecoded>) {
    // Grab candidates: three base64url segments separated by dots.
    // Minimum length is intentionally tight (3 chars per segment) to
    // keep the scan cheap on huge response bodies.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Scan to the start of a base64url run.
        while i < bytes.len() && !is_b64url_char(bytes[i]) {
            i += 1;
        }
        let start = i;
        let seg1_end = seg_end(bytes, i);
        if seg1_end == i || seg1_end >= bytes.len() || bytes[seg1_end] != b'.' {
            i = seg1_end.max(i + 1);
            continue;
        }
        let seg2_start = seg1_end + 1;
        let seg2_end = seg_end(bytes, seg2_start);
        if seg2_end == seg2_start || seg2_end >= bytes.len() || bytes[seg2_end] != b'.' {
            i = seg2_end.max(seg2_start + 1);
            continue;
        }
        let seg3_start = seg2_end + 1;
        let seg3_end = seg_end(bytes, seg3_start);
        if seg3_end == seg3_start {
            i = seg3_start + 1;
            continue;
        }
        let candidate = &text[start..seg3_end];
        if let Ok(parts) = burpfree_codec::jwt_decode(candidate) {
            if !out.iter().any(|d| d.token == candidate) {
                out.push(JwtDecoded {
                    token: candidate.to_string(),
                    header: parts.header,
                    payload: parts.payload,
                    signature_b64: parts.signature_b64,
                    location: location.to_string(),
                });
            }
        }
        i = seg3_end;
    }
}

fn is_b64url_char(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn seg_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() && is_b64url_char(bytes[i]) {
        i += 1;
    }
    i
}

#[derive(Debug, Deserialize)]
pub struct JwtSignArgs {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub secret: String,
    pub alg: String,
}

#[derive(Debug, Serialize)]
pub struct JwtSignResult {
    pub token: String,
    pub alg: String,
}

/// Re-sign a header + payload with the supplied HMAC secret. The
/// algorithm is one of `HS256` / `HS384` / `HS512` / `none`.
#[tauri::command]
pub async fn jwt_sign(args: JwtSignArgs) -> Result<JwtSignResult, String> {
    let alg = burpfree_codec::JwtAlg::from_label(&args.alg)
        .ok_or_else(|| format!("unsupported JWT alg: {}", args.alg))?;
    let token = burpfree_codec::jwt_sign(args.header, args.payload, args.secret.as_bytes(), alg)
        .map_err(fail)?;
    Ok(JwtSignResult {
        token,
        alg: alg.as_label().to_string(),
    })
}

#[derive(Debug, Deserialize)]
pub struct JwtVerifyArgs {
    pub token: String,
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct JwtVerifyResult {
    pub valid: bool,
}

#[tauri::command]
pub async fn jwt_verify(args: JwtVerifyArgs) -> Result<JwtVerifyResult, String> {
    let v = burpfree_codec::jwt_verify_hmac(&args.token, args.secret.as_bytes()).map_err(fail)?;
    Ok(JwtVerifyResult { valid: v })
}

// ---- Content Discovery -------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DiscoveryRunArgs {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Optional operator-supplied wordlist, one word per line. If
    /// empty, the built-in `discovery_common.txt` is used.
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub include_forbidden: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryRunResult {
    pub hits: Vec<DiscoveryHitView>,
    pub summary: burpfree_engines::discovery::DiscoverySummary,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryHitView {
    pub path: String,
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub content_type: Option<String>,
    pub elapsed_ms: u64,
    pub title: Option<String>,
    pub transaction_id: Option<i64>,
}

#[tauri::command]
pub async fn discovery_run(
    args: DiscoveryRunArgs,
    state: AppStateRef<'_>,
) -> Result<DiscoveryRunResult, String> {
    use burpfree_core::traffic::{Request, Response, RequestSource, Transaction};
    use burpfree_engines::client::HttpClientConfig;
    use burpfree_engines::discovery::{
        DiscoveryConfig, DiscoveryRunner, DiscoveryTarget, DEFAULT_WORDLIST,
    };

    let h = state.require().map_err(fail)?;
    let target = DiscoveryTarget {
        scheme: args.scheme,
        host: args.host,
        port: args.port,
    };
    let words = DiscoveryRunner::parse_wordlist(args.wordlist.as_deref().unwrap_or(DEFAULT_WORDLIST));
    let cfg = DiscoveryConfig {
        concurrency: args.concurrency.unwrap_or(6).clamp(1, 32),
        include_forbidden: args.include_forbidden.unwrap_or(true),
        ..DiscoveryConfig::default()
    };
    let http_cfg = HttpClientConfig {
        host_overrides: Some(h.host_overrides.clone()),
        ..HttpClientConfig::default()
    };
    let runner = DiscoveryRunner::new(http_cfg, cfg);
    let (hits, summary) = runner.run(&target, &words).await;

    // Persist hits to history so the operator can click through from
    // the Discovery panel into Repeater / Organizer / Scanner.
    let (hist, blobs, scope) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone(), p.config.scope.clone())
    };
    let mut rows = Vec::with_capacity(hits.len());
    for hit in hits {
        // Reconstruct the typed Request / Response just enough to persist.
        let mut req =
            Request::new("GET", &hit.url).map_err(fail)?;
        req.source = RequestSource::ActiveScan; // closest existing variant for the "discovery" origin.
        let mut resp = Response::new(hit.status);
        if let Some(ct) = hit.content_type.as_ref() {
            resp.headers.set("Content-Type", ct.clone());
        }
        resp.elapsed_ms = hit.elapsed_ms;
        // Keep the on-wire-ish response body length matching what we saw.
        if hit.length > 0 {
            resp.body = vec![0u8; hit.length.min(16)]; // placeholder bytes; the real body
            // isn't retained here to keep history lean. The content-length header still carries truth.
            resp.headers
                .set("Content-Length", hit.length.to_string());
        }
        let in_scope = scope.is_in_scope(&req);
        let req_ref = blobs.put(&hit.request_wire).map_err(fail)?;
        let resp_ref = blobs.put(&hit.response_wire).map_err(fail)?;
        let mut tx = Transaction::new(req);
        tx.response = Some(resp);
        tx.tag("content-discovery");
        tx.in_scope = in_scope;
        hist.upsert_transaction(&tx, &req_ref, Some(&resp_ref))
            .map_err(fail)?;
        rows.push(DiscoveryHitView {
            path: hit.path,
            url: hit.url,
            status: hit.status,
            length: hit.length,
            content_type: hit.content_type,
            elapsed_ms: hit.elapsed_ms,
            title: hit.title,
            transaction_id: Some(tx.request.id.as_i64()),
        });
    }

    Ok(DiscoveryRunResult {
        hits: rows,
        summary,
    })
}

#[tauri::command]
pub async fn discovery_default_wordlist() -> Result<String, String> {
    Ok(burpfree_engines::discovery::DEFAULT_WORDLIST.to_string())
}

// ---- GraphQL inspector --------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GraphQLEndpoint {
    pub transaction_id: i64,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub operations: Vec<burpfree_engines::graphql::Operation>,
}

/// Walk history, pick out transactions that look like GraphQL, and
/// return a de-duplicated list keyed by (host, path). The UI uses this
/// to populate the endpoint list on the left of the GraphQL tab.
#[tauri::command]
pub async fn graphql_list_endpoints(
    state: AppStateRef<'_>,
) -> Result<Vec<GraphQLEndpoint>, String> {
    use burpfree_engines::graphql;
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let rows = hist
        .list(&burpfree_storage::HistoryFilter {
            limit: Some(5_000),
            ..Default::default()
        })
        .map_err(fail)?;
    let mut out: Vec<GraphQLEndpoint> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in rows {
        let Some(req_blob) = hist.get_request_blob(r.id).map_err(fail)? else {
            continue;
        };
        let Some(req_bytes) = blobs.get(&req_blob).map_err(fail)? else {
            continue;
        };
        let resp_bytes = if let Some(rb) = hist.get_response_blob(r.id).map_err(fail)? {
            blobs.get(&rb).map_err(fail)?
        } else {
            None
        };
        let tx = rebuild_transaction(&r, &req_bytes, resp_bytes.as_deref()).map_err(fail)?;
        if !graphql::looks_like_graphql(&tx) {
            continue;
        }
        let key = format!("{}:{}:{}", tx.request.host, tx.request.port, tx.request.path);
        if !seen.insert(key) {
            continue;
        }
        out.push(GraphQLEndpoint {
            transaction_id: r.id.as_i64(),
            method: tx.request.method.clone(),
            url: tx.request.url(),
            status: r.status,
            operations: graphql::parse_operations(&tx.request.body),
        });
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct GraphQLIntrospectInput {
    pub url: String,
    /// Extra headers (Authorization, API keys) to carry along with the
    /// introspection request. Each entry is `name` / `value`.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
pub struct GraphQLIntrospectResult {
    pub status: u16,
    pub body_text: String,
    pub elapsed_ms: u64,
    pub schema: Option<burpfree_engines::graphql::SchemaView>,
    pub error: Option<String>,
}

/// POST the introspection query to `url` using the project's shared
/// HTTP client config (upstream + host overrides). The raw response
/// body is returned verbatim; when it parses as a GraphQL
/// introspection response we also hand back the compact schema tree.
#[tauri::command]
pub async fn graphql_introspect(
    args: GraphQLIntrospectInput,
    state: AppStateRef<'_>,
) -> Result<GraphQLIntrospectResult, String> {
    use burpfree_engines::client::HttpClientConfig;
    use burpfree_engines::graphql;

    let h = state.require().map_err(fail)?;
    let host_overrides = h.host_overrides.clone();
    let upstream = h.upstream.read().clone();
    let http = HttpClientConfig {
        upstream,
        host_overrides: Some(host_overrides),
        ..HttpClientConfig::default()
    };

    let resp = match graphql::run_introspection(&args.url, &args.headers, http).await {
        Ok(r) => r,
        Err(e) => {
            return Ok(GraphQLIntrospectResult {
                status: 0,
                body_text: String::new(),
                elapsed_ms: 0,
                schema: None,
                error: Some(format!("{e}")),
            });
        }
    };
    let body_text = String::from_utf8_lossy(&resp.body).to_string();
    let schema = serde_json::from_slice::<serde_json::Value>(&resp.body)
        .ok()
        .map(|v| graphql::parse_schema(&v));
    Ok(GraphQLIntrospectResult {
        status: resp.status,
        body_text,
        elapsed_ms: resp.elapsed_ms,
        schema,
        error: None,
    })
}

/// Pure helper: parse an introspection JSON blob the caller already has.
/// Useful when the user pastes a saved introspection file into the UI.
#[tauri::command]
pub async fn graphql_parse_schema_json(
    json: String,
) -> Result<burpfree_engines::graphql::SchemaView, String> {
    let v: serde_json::Value = serde_json::from_str(&json).map_err(fail)?;
    Ok(burpfree_engines::graphql::parse_schema(&v))
}

// ---- Passive site crawler -----------------------------------------------

/// Walk every HTML response in history, extract link candidates
/// (anchors / forms / fetch / scripts / iframes), de-duplicate them
/// against the URLs already present in history, and return the result
/// grouped by host. Nothing is fetched; the UI decides what to do with
/// the candidates.
#[tauri::command]
pub async fn crawler_run_now(
    state: AppStateRef<'_>,
) -> Result<burpfree_engines::crawler::CrawlResult, String> {
    use burpfree_engines::crawler;
    use std::collections::HashSet;

    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let rows = hist
        .list(&burpfree_storage::HistoryFilter {
            limit: Some(20_000),
            ..Default::default()
        })
        .map_err(fail)?;

    // Known URLs (normalised): used to filter candidates.
    let mut known: HashSet<String> = HashSet::new();
    for r in &rows {
        let default_port =
            (r.scheme == "http" && r.port == 80) || (r.scheme == "https" && r.port == 443);
        let authority = if default_port {
            r.host.clone()
        } else {
            format!("{}:{}", r.host, r.port)
        };
        let full = format!(
            "{}://{}{}",
            r.scheme,
            authority,
            r.path.split('#').next().unwrap_or(&r.path)
        );
        known.insert(full);
    }

    // Collect (base_url, body) pairs for HTML responses.
    let mut owned: Vec<(url::Url, String)> = Vec::new();
    for r in &rows {
        let is_html = r
            .content_type
            .as_deref()
            .map(|c| c.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false);
        if !is_html {
            continue;
        }
        let Some(resp_blob) = hist.get_response_blob(r.id).map_err(fail)? else {
            continue;
        };
        let Some(bytes) = blobs.get(&resp_blob).map_err(fail)? else {
            continue;
        };
        // Only scan reasonably-sized bodies to keep crawler latency
        // predictable; HAR imports can have multi-MB rendered HTML.
        if bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let default_port =
            (r.scheme == "http" && r.port == 80) || (r.scheme == "https" && r.port == 443);
        let authority = if default_port {
            r.host.clone()
        } else {
            format!("{}:{}", r.host, r.port)
        };
        if let Ok(base) = url::Url::parse(&format!("{}://{}{}", r.scheme, authority, r.path)) {
            owned.push((base, text));
        }
    }
    let pages = owned.iter().map(|(u, b)| (u, b.as_str()));
    Ok(crawler::crawl_batch(pages, &known))
}

// ---- Dashboard tasks ----------------------------------------------------

/// Return the project's live tasks (opaque JSON values — the UI owns
/// the schema). An empty list means the user has never created one.
#[tauri::command]
pub async fn tasks_list(state: AppStateRef<'_>) -> Result<Vec<serde_json::Value>, String> {
    let h = state.require().map_err(fail)?;
    let tasks = h.project.read().config.dashboard_tasks.clone();
    Ok(tasks)
}

/// Replace the project's task list and persist to config.json.
#[tauri::command]
pub async fn tasks_set(
    tasks: Vec<serde_json::Value>,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    {
        let mut p = h.project.write();
        p.config.dashboard_tasks = tasks;
        p.save_config().map_err(fail)?;
    }
    Ok(())
}

// ---- Bambda history filter ----------------------------------------------

#[derive(Debug, Deserialize)]
pub struct BambdaFilterArgs {
    pub expression: String,
    #[serde(default)]
    pub filter: Option<HistoryFilter>,
}

#[derive(Debug, Serialize)]
pub struct BambdaFilterResult {
    pub rows: Vec<StoredSummary>,
    pub total_scanned: usize,
    pub kept: usize,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Evaluate a Bambda predicate against the project's history. The
/// `filter` arg narrows the input set using the regular
/// [`HistoryFilter`] before Bambda rows are tested, so operators can
/// chain the two filtering mechanisms (coarse SQL filter → fine
/// expression predicate).
#[tauri::command]
pub async fn bambda_filter(args: BambdaFilterArgs, state: AppStateRef<'_>) -> Result<BambdaFilterResult, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let start = std::time::Instant::now();
    let rows = hist
        .list(&args.filter.clone().unwrap_or_default())
        .map_err(fail)?;
    let total_scanned = rows.len();
    let (kept_rows, err) = burpfree_engines::bambda::apply(&args.expression, &rows);
    Ok(BambdaFilterResult {
        kept: kept_rows.len(),
        rows: kept_rows,
        total_scanned,
        error: err.map(|e| e.to_string()),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---- Attack PoC generators (CSRF / Clickjacking) ------------------------

#[derive(Debug, Deserialize)]
pub struct ClickjackArgs {
    pub url: String,
    #[serde(default)]
    pub overlay_label: String,
}

#[derive(Debug, Serialize)]
pub struct PocResult {
    /// The generated HTML, ready to drop into a file.
    pub html: String,
    /// A sensible default filename for a save dialog.
    pub suggested_name: String,
}

/// Generate a cross-origin CSRF PoC from a captured request. The
/// generator is content-type aware (urlencoded / multipart / JSON /
/// GET) — see `burpfree_engines::poc`.
#[tauri::command]
pub async fn poc_csrf(id: i64, state: AppStateRef<'_>) -> Result<PocResult, String> {
    let h = state.require().map_err(fail)?;
    let tid = TrafficId::from(id);
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let summary = hist.get_summary(tid).map_err(fail)?.ok_or("not found")?;
    let raw = hist
        .get_request_blob(tid)
        .map_err(fail)?
        .ok_or("no stored request bytes")?;
    let bytes = blobs
        .get(&raw)
        .map_err(fail)?
        .ok_or("request blob missing")?;

    let req = rebuild_request(&summary, &bytes).map_err(fail)?;
    let html = burpfree_engines::poc::generate_csrf_html(&req);
    let suggested_name = format!(
        "csrf-{}-{}.html",
        summary.host.replace([':', '.'], "-"),
        summary.id.as_i64()
    );
    Ok(PocResult { html, suggested_name })
}

/// Generate a clickjacking HTML template that iframes the target URL
/// with a clickable overlay above it.
#[tauri::command]
pub async fn poc_clickjack(args: ClickjackArgs) -> Result<PocResult, String> {
    if args.url.trim().is_empty() {
        return Err("empty URL".into());
    }
    let html = burpfree_engines::poc::generate_clickjacking_html(&args.url, &args.overlay_label);
    let host = args
        .url
        .splitn(4, '/')
        .nth(2)
        .unwrap_or("target")
        .replace(':', "-");
    let suggested_name = format!("clickjack-{host}.html");
    Ok(PocResult { html, suggested_name })
}

/// Rebuild a typed [`Request`] from the stored summary + raw bytes.
/// The raw blob is in `to_wire_bytes()` format: `METHOD PATH VERSION\r\n`
/// then the header block, a blank line, then the body.
fn rebuild_request(summary: &StoredSummary, raw: &[u8]) -> anyhow::Result<Request> {
    use burpfree_core::headers::Headers;
    use burpfree_core::traffic::HttpVersion;

    // Split header block from body on the first `\r\n\r\n` (or `\n\n`).
    let (header_block, body) = split_header_body(raw);

    // The first CRLF-terminated line is the request line; the remaining
    // lines are headers.
    let (_request_line, headers_bytes) = match header_block.iter().position(|&b| b == b'\n') {
        Some(i) => (&header_block[..i], &header_block[i + 1..]),
        None => (header_block, &b""[..]),
    };
    let headers = Headers::parse_block(headers_bytes);

    // Reuse the summary's method / scheme / host / port / path so we
    // don't rely on the raw line parsing being successful for odd
    // encodings or malformed captures.
    let url = if (summary.scheme == "https" && summary.port == 443)
        || (summary.scheme == "http" && summary.port == 80)
    {
        format!("{}://{}{}", summary.scheme, summary.host, summary.path)
    } else {
        format!(
            "{}://{}:{}{}",
            summary.scheme, summary.host, summary.port, summary.path
        )
    };
    let mut req = Request::new(&summary.method, &url)?;
    req.headers = headers;
    req.http_version = HttpVersion::Http11;
    req.body = body.to_vec();
    Ok(req)
}

fn split_header_body(raw: &[u8]) -> (&[u8], &[u8]) {
    // Prefer `\r\n\r\n`, fall back to `\n\n`.
    if let Some(i) = find_slice(raw, b"\r\n\r\n") {
        return (&raw[..i], &raw[i + 4..]);
    }
    if let Some(i) = find_slice(raw, b"\n\n") {
        return (&raw[..i], &raw[i + 2..]);
    }
    (raw, &[])
}

fn find_slice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---- Scope ---------------------------------------------------------------

#[tauri::command]
pub async fn scope_get(state: AppStateRef<'_>) -> Result<Scope, String> {
    let h = state.require().map_err(fail)?;
    let s = h.scope.read().clone();
    Ok(s)
}

#[tauri::command]
pub async fn scope_add_rule(rule: ScopeRule, state: AppStateRef<'_>) -> Result<Scope, String> {
    let h = state.require().map_err(fail)?;
    h.scope.write().add(rule);
    let snapshot = h.scope.read().clone();
    {
        let mut p = h.project.write();
        p.config.scope = snapshot.clone();
        p.save_config().map_err(fail)?;
    }
    Ok(snapshot)
}

#[tauri::command]
pub async fn scope_remove_rule(index: usize, state: AppStateRef<'_>) -> Result<Scope, String> {
    let h = state.require().map_err(fail)?;
    {
        let mut s = h.scope.write();
        if index < s.rules.len() {
            s.rules.remove(index);
        }
    }
    let snapshot = h.scope.read().clone();
    {
        let mut p = h.project.write();
        p.config.scope = snapshot.clone();
        p.save_config().map_err(fail)?;
    }
    Ok(snapshot)
}

/// Replace the entire scope — rules array + default_in_scope_when_empty.
/// Used by the advanced scope editor so edits can be submitted as a
/// single atomic operation.
#[tauri::command]
pub async fn scope_set(scope: Scope, state: AppStateRef<'_>) -> Result<Scope, String> {
    let h = state.require().map_err(fail)?;
    *h.scope.write() = scope;
    let snapshot = h.scope.read().clone();
    {
        let mut p = h.project.write();
        p.config.scope = snapshot.clone();
        p.save_config().map_err(fail)?;
    }
    Ok(snapshot)
}

// ---- Match/Replace -------------------------------------------------------

#[tauri::command]
pub async fn match_replace_get(state: AppStateRef<'_>) -> Result<MatchReplaceEngine, String> {
    let h = state.require().map_err(fail)?;
    let e = h.match_replace.read().clone();
    Ok(e)
}

#[derive(Debug, Deserialize)]
pub struct MatchReplacePreviewArgs {
    /// `"request"` or `"response"` — picks which direction to dry-run.
    pub direction: String,
    /// Absolute `http(s)://host/path` URL. The sample Request is
    /// built via `Request::new(method, url)`; bad URLs surface as
    /// `Err("bad url: …")` so the UI can show it inline.
    pub url: String,
    /// HTTP method token (`"GET"`, `"POST"`, …). `None` falls back
    /// to `"GET"`.
    #[serde(default)]
    pub method: Option<String>,
    /// Optional request body (for request-direction) OR response
    /// body (for response-direction). Lets Body / SetBody rules have
    /// something concrete to probe.
    #[serde(default)]
    pub body: Option<String>,
    /// Optional Content-Type seed for the body. Only used when
    /// `body` is Some — the UI defaults to `application/json`.
    #[serde(default)]
    pub content_type: Option<String>,
}

/// Dry-run the current match/replace rules against a synthesised
/// sample. Returns a per-rule hit list + before/after wire snapshots.
/// Mirrors Burp's "Test rule" UX for the match/replace tool — lets
/// operators validate a chain of rules before enabling it against
/// live traffic.
#[tauri::command]
pub async fn match_replace_preview(
    args: MatchReplacePreviewArgs,
    state: AppStateRef<'_>,
) -> Result<burpfree_proxy::matchreplace::MatchReplacePreview, String> {
    let h = state.require().map_err(fail)?;
    let method = args.method.as_deref().unwrap_or("GET");
    let mut req = Request::new(method, &args.url).map_err(fail)?;
    let host = req.host.clone();
    let ct = args.content_type.as_deref().unwrap_or("application/json");
    let engine = h.match_replace.read();
    match args.direction.as_str() {
        "request" => {
            if let Some(body) = args.body.as_ref() {
                req.body = body.clone().into_bytes();
                req.headers.set("Content-Type", ct);
                req.headers.set("Content-Length", req.body.len().to_string());
            }
            Ok(engine.preview_request(&req, None))
        }
        "response" => {
            // Pair the sample URL with a synthetic 200 OK response.
            // Response-direction rules match on this; `host` is
            // pulled from the request URL so host_filter still works.
            let mut resp = burpfree_core::traffic::Response::new(200);
            if let Some(body) = args.body.as_ref() {
                resp.body = body.clone().into_bytes();
                resp.headers.set("Content-Type", ct);
                resp.headers.set("Content-Length", resp.body.len().to_string());
            }
            Ok(engine.preview_response(&resp, &host, Some(&req)))
        }
        other => Err(format!("bad direction: {other}")),
    }
}

#[tauri::command]
pub async fn match_replace_set(engine: MatchReplaceEngine, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    // Route through `update_rules` so the live per-rule hit counter
    // survives this save. The engine's `hits` Arc is already shared
    // across clones (Arc::clone bumps refcount), so swapping only
    // the rules vec in place keeps every counter observer happy.
    // Persist into project config so rules survive restarts.
    let serialized: Vec<serde_json::Value> = engine
        .rules
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    h.match_replace.write().update_rules(engine.rules);
    let mut p = h.project.write();
    p.config.match_replace_rules = serialized;
    p.save_config().map_err(fail)?;
    Ok(())
}

/// Snapshot every match/replace rule's live fire count. Missing keys
/// mean the rule hasn't fired yet (the UI renders those as 0). Called
/// by the MatchReplacePane every 2 seconds to refresh the Hits column
/// so operators see which rules are earning their keep against live
/// traffic.
#[tauri::command]
pub async fn match_replace_hits(
    state: AppStateRef<'_>,
) -> Result<std::collections::HashMap<String, u64>, String> {
    let h = state.require().map_err(fail)?;
    // Materialise into a local so the temporary RwLockReadGuard
    // drops before `h` does — otherwise rustc flags the borrow
    // ordering (E0597).
    let snap = h.match_replace.read().hit_snapshot();
    Ok(snap)
}

/// Snapshot every match/replace rule's last-fire epoch (ms). Keys
/// absent from the map correspond to rules that haven't fired this
/// session; the UI renders those as "—". Polled alongside
/// [`match_replace_hits`] so a rule's Hits count and the humanized
/// "Last fire" column stay in lockstep. `clear_hits` resets this
/// map together with the counters — they share a single clear path
/// in the engine.
#[tauri::command]
pub async fn match_replace_last_fires(
    state: AppStateRef<'_>,
) -> Result<std::collections::HashMap<String, i64>, String> {
    let h = state.require().map_err(fail)?;
    // Same E0597 dance as `match_replace_hits` — the RwLockReadGuard
    // must drop before `h` does.
    let snap = h.match_replace.read().last_fire_snapshot();
    Ok(snap)
}

/// Zero every rule's fire counter and last-fire timestamp. Burp
/// has no direct equivalent — operators iterating on a rule chain
/// want to re-measure cleanly after each tweak without an app
/// restart.
#[tauri::command]
pub async fn match_replace_hits_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.match_replace.read().clear_hits();
    Ok(())
}

// ---- Interceptor ---------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InterceptorSetArgs {
    pub request: bool,
    pub response: bool,
}

#[tauri::command]
pub async fn interceptor_set(args: InterceptorSetArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.interceptor.set_request_intercept(args.request);
    h.interceptor.set_response_intercept(args.response);
    Ok(())
}

#[tauri::command]
pub async fn interceptor_pending(state: AppStateRef<'_>) -> Result<Vec<burpfree_proxy::interceptor::PendingSummary>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.interceptor.list_pending())
}

/// Lightweight status view — the UI uses this to render the intercept
/// indicator in the status bar and to decide what Ctrl+T should flip to.
#[derive(Debug, Serialize)]
pub struct InterceptorStatus {
    pub request: bool,
    pub response: bool,
    pub pending: usize,
}

#[tauri::command]
pub async fn interceptor_status(state: AppStateRef<'_>) -> Result<InterceptorStatus, String> {
    let h = state.require().map_err(fail)?;
    Ok(InterceptorStatus {
        request: h.interceptor.request_intercept(),
        response: h.interceptor.response_intercept(),
        pending: h.interceptor.list_pending().len(),
    })
}

#[derive(Debug, Deserialize)]
pub struct InterceptResolveArgs {
    pub id: i64,
    pub action: String, // "forward" | "drop"
    pub raw: Option<String>,
}

#[tauri::command]
pub async fn interceptor_resolve(args: InterceptResolveArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let action = match args.action.as_str() {
        "forward" => burpfree_proxy::interceptor::InterceptAction::Forward,
        _ => burpfree_proxy::interceptor::InterceptAction::Drop,
    };
    h.interceptor
        .resolve(TrafficId::from(args.id), action, args.raw.map(|s| s.into_bytes()))
        .map_err(fail)
}

/// Bulk-resolve every pending intercept with `action` ("forward" or
/// "drop"). Mirrors Burp's "Forward all" / "Drop all" buttons that
/// let an operator empty a backed-up queue. Returns how many
/// entries were resolved.
#[tauri::command]
pub async fn interceptor_resolve_all(
    action: String,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let act = match action.as_str() {
        "forward" => burpfree_proxy::interceptor::InterceptAction::Forward,
        _ => burpfree_proxy::interceptor::InterceptAction::Drop,
    };
    Ok(h.interceptor.resolve_all(act))
}

/// Peek at a queued intercept without resolving it. Returns the raw
/// on-the-wire bytes as a UTF-8 string (lossy for bodies with binary
/// bytes), so operators can send-to-Repeater or Copy-as-curl without
/// consuming the intercept slot.
#[tauri::command]
pub async fn interceptor_show(id: i64, state: AppStateRef<'_>) -> Result<String, String> {
    let h = state.require().map_err(fail)?;
    let bytes = match h.interceptor.get_original(TrafficId::from(id)) {
        Some(burpfree_proxy::interceptor::RawView::Request(b)) => b,
        Some(burpfree_proxy::interceptor::RawView::Response(b)) => b,
        None => return Err("intercept entry not found".into()),
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ---- Interception rules -------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct InterceptRulesView {
    pub request: burpfree_proxy::interceptor::InterceptRules,
    pub response: burpfree_proxy::interceptor::InterceptRules,
}

#[tauri::command]
pub async fn interceptor_rules_get(state: AppStateRef<'_>) -> Result<InterceptRulesView, String> {
    let h = state.require().map_err(fail)?;
    Ok(InterceptRulesView {
        request: h.interceptor.request_rules(),
        response: h.interceptor.response_rules(),
    })
}

#[derive(Debug, Deserialize)]
pub struct InterceptRulesSetArgs {
    pub direction: String, // "request" | "response"
    pub rules: burpfree_proxy::interceptor::InterceptRules,
}

// ---- Hostname overrides + redirect policy -------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct HostOverridesView {
    pub overrides: Vec<burpfree_core::net::HostOverride>,
    pub follow_redirects: String,
}

#[tauri::command]
pub async fn host_overrides_get(state: AppStateRef<'_>) -> Result<HostOverridesView, String> {
    let h = state.require().map_err(fail)?;
    let follow_redirects = h
        .project
        .read()
        .config
        .follow_redirects
        .clone()
        .unwrap_or_else(|| "never".into());
    Ok(HostOverridesView {
        overrides: h.host_overrides.snapshot(),
        follow_redirects,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostOverridesSetArgs {
    pub overrides: Vec<burpfree_core::net::HostOverride>,
    /// never | on_site | in_scope | always
    #[serde(default)]
    pub follow_redirects: Option<String>,
}

#[tauri::command]
pub async fn host_overrides_set(
    args: HostOverridesSetArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    // Apply to the live shared store so new connections see them immediately.
    h.host_overrides.set_all(args.overrides.clone());

    // Serialise entries + redirect policy into project config.
    let serialized: Vec<serde_json::Value> = args
        .overrides
        .iter()
        .map(|o| serde_json::to_value(o).unwrap_or(serde_json::Value::Null))
        .collect();
    let mut p = h.project.write();
    p.config.host_overrides = serialized;
    if let Some(pol) = args.follow_redirects.as_deref() {
        match pol {
            "never" | "on_site" | "in_scope" | "always" => {
                p.config.follow_redirects = Some(pol.to_string());
            }
            other => return Err(format!("bad follow_redirects: {other}")),
        }
    }
    p.save_config().map_err(fail)?;
    Ok(())
}

#[tauri::command]
pub async fn interceptor_rules_set(
    args: InterceptRulesSetArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let serialized: Vec<serde_json::Value> = args
        .rules
        .rules
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    match args.direction.as_str() {
        "request" => {
            h.interceptor.set_request_rules(args.rules);
            let mut p = h.project.write();
            p.config.intercept_rules_request = serialized;
            p.save_config().map_err(fail)
        }
        "response" => {
            h.interceptor.set_response_rules(args.rules);
            let mut p = h.project.write();
            p.config.intercept_rules_response = serialized;
            p.save_config().map_err(fail)
        }
        other => Err(format!("bad direction: {other}")),
    }
}

#[derive(Debug, Deserialize)]
pub struct InterceptorPreviewArgs {
    /// `"request"` or `"response"` — picks which rule set to probe.
    pub direction: String,
    /// Absolute `http(s)://host/path?q` URL. Parsed via `Request::new`;
    /// a bad URL surfaces as `Err("bad url: …")` so the UI can show it
    /// inline instead of silently returning zero matches.
    pub url: String,
    /// HTTP method token. `None` falls back to `"GET"` so a bare URL
    /// still produces a usable preview.
    #[serde(default)]
    pub method: Option<String>,
    /// Flipped by an inline checkbox so operators can preview how
    /// InScope rules behave either way without having to retouch the
    /// Scope engine.
    #[serde(default)]
    pub in_scope: bool,
}

/// Dry-run the current intercept rules against a synthesised sample
/// request. Returns a per-rule match / effect breakdown plus the
/// aggregate hold / forward decision. Mirrors Burp's "Test rule" UX
/// — operators can validate a complex AND / OR chain before enabling
/// intercept against live traffic. The response-direction preview
/// pairs the sample request with an empty 200 OK so response-visible
/// match types (HeaderPresent, HasBody) have something concrete to
/// probe; a V2 could accept a sample response blob.
#[tauri::command]
pub async fn interceptor_rules_preview(
    args: InterceptorPreviewArgs,
    state: AppStateRef<'_>,
) -> Result<burpfree_proxy::interceptor::PreviewReport, String> {
    let h = state.require().map_err(fail)?;
    let method = args.method.as_deref().unwrap_or("GET");
    let req = Request::new(method, &args.url).map_err(fail)?;
    match args.direction.as_str() {
        "request" => Ok(h.interceptor.request_rules().preview_request(&req, args.in_scope)),
        "response" => {
            // Minimal placeholder response — 200 OK, no body, no
            // extra headers — so response rules have something to
            // match against. HeaderPresent against anything but the
            // default Response fields will miss until V2 lets the
            // operator supply a sample response.
            let resp = burpfree_core::traffic::Response::new(200);
            Ok(h.interceptor.response_rules().preview_response(&req, &resp, args.in_scope))
        }
        other => Err(format!("bad direction: {other}")),
    }
}

/// Snapshot every intercept rule's live firing count (request and
/// response directions share the same map because rule IDs are
/// globally unique). Missing keys mean a rule hasn't fired — the UI
/// renders those as 0. Called every 2 seconds by the Intercept Rules
/// editor to populate the Hits column. Mirrors the match/replace hit
/// snapshot: `set_request_rules` / `set_response_rules` don't reset
/// the counter so operators can tweak rules without losing the
/// measurement they're watching.
#[tauri::command]
pub async fn interceptor_rules_hits(
    state: AppStateRef<'_>,
) -> Result<std::collections::HashMap<String, u64>, String> {
    let h = state.require().map_err(fail)?;
    // Local materialisation keeps the parking_lot guard scoped
    // inside this function — otherwise rustc fires E0597 because
    // `h` would drop before the guard temporary.
    let snap = h.interceptor.rule_hit_snapshot();
    Ok(snap)
}

/// Reset every intercept rule's firing counter. Doesn't touch the
/// rules themselves or any pending intercepts — just zeroes the hits
/// map so the next cycle of measurement starts fresh.
#[tauri::command]
pub async fn interceptor_rules_hits_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.interceptor.clear_rule_hits();
    Ok(())
}

// ---- Cookie Jar ----------------------------------------------------------

/// Snapshot of every cookie the project's shared jar currently
/// holds. The jar's internal storage is an `Arc<RwLock<Vec<Cookie>>>`
/// so `snapshot()` deep-clones — safe to call from the UI poller
/// without worrying about contention with the proxy sink.
#[tauri::command]
pub async fn cookie_jar_list(
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_engines::session::Cookie>, String> {
    let h = state.require().map_err(fail)?;
    // Materialise into a local so no RwLockReadGuard temporary
    // outlives `h` (same E0597-dodge pattern R57/R58/R60/R61 use).
    let snap = h.cookie_jar.snapshot();
    Ok(snap)
}

/// Wipe every cookie from the shared jar. Doesn't touch Set-Cookie
/// headers already recorded in history — those stay in the project
/// SQLite under their original transactions. Burp's equivalent is
/// the "Remove all cookies" button on its Cookie Jar page.
#[tauri::command]
pub async fn cookie_jar_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.cookie_jar.clear();
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CookieJarDeleteArgs {
    pub name: String,
    pub domain: String,
    pub path: String,
}

/// Remove the single cookie identified by the (name, domain, path)
/// triple that uniquely addresses a jar entry. Returns `true` iff
/// one was present (so the UI can skip a refresh on a stale id).
#[tauri::command]
pub async fn cookie_jar_delete(
    args: CookieJarDeleteArgs,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.cookie_jar.delete(&args.name, &args.domain, &args.path))
}

/// Insert / replace a cookie manually from the UI. The upsert
/// semantics match the auto-harvested path: an existing entry with
/// the same (name, domain, path) triple is overwritten. Lets the
/// operator inject a session token they captured out-of-band
/// (environment variable, intercepted Set-Cookie from a different
/// tool, hand-crafted) without faking a round-trip through the
/// proxy.
#[tauri::command]
pub async fn cookie_jar_set(
    cookie: burpfree_engines::session::Cookie,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.cookie_jar.upsert(cookie);
    Ok(())
}

// ---- Automatic project backup -------------------------------------------

/// Current auto-backup config, hydrated from the project file.
#[tauri::command]
pub async fn backup_config_get(
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::AutoBackupConfig, String> {
    let h = state.require().map_err(fail)?;
    // Materialise into a local so the RwLockReadGuard temporary
    // drops before `h` — mirrors the E0597-dodge pattern used by
    // R57/R58/R60/R61/R66 cmd handlers.
    let cfg = h.project.read().config.auto_backup.clone();
    Ok(cfg)
}

/// Persist a new auto-backup config and restart the scheduler.
/// Config survives the restart because `save_config` writes it to
/// disk; the running scheduler is swapped out immediately so a
/// shortened interval kicks in without waiting the previous sleep.
#[tauri::command]
pub async fn backup_config_set(
    cfg: burpfree_storage::AutoBackupConfig,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    {
        let mut p = h.project.write();
        p.config.auto_backup = cfg;
        p.save_config().map_err(fail)?;
    }
    // Swap the running task against the just-saved config. Doing
    // this after the project write-lock drops avoids holding both
    // locks across the scheduler-task spawn.
    crate::backup::restart_scheduler(&state);
    Ok(())
}

/// Snapshot of every backup currently on disk — fuel for the
/// SettingsPanel table. Returns newest-first.
#[tauri::command]
pub async fn backup_list(
    state: AppStateRef<'_>,
) -> Result<Vec<crate::backup::BackupInfo>, String> {
    let h = state.require().map_err(fail)?;
    let root = h.project.read().root.clone();
    crate::backup::list_backups(&root).map_err(fail)
}

/// Fire a one-shot backup immediately regardless of the scheduler's
/// state (even when `enabled=false`). Operators reach for this
/// before a risky action — a scan rerun, a config swap — where
/// they want a safety net separate from the periodic rhythm.
#[tauri::command]
pub async fn backup_now(
    state: AppStateRef<'_>,
) -> Result<crate::backup::BackupInfo, String> {
    let h = state.require().map_err(fail)?;
    let (root, keep) = {
        let p = h.project.read();
        (p.root.clone(), p.config.auto_backup.keep_count)
    };
    // The exporter does synchronous I/O (SQLite checkpoint, zip
    // write) so we hop onto a blocking thread rather than stalling
    // the Tauri cmd thread for the duration of the snapshot.
    let info = tokio::task::spawn_blocking(move || crate::backup::write_snapshot(&root, keep))
        .await
        .map_err(fail)?
        .map_err(fail)?;
    Ok(info)
}

#[derive(Debug, Deserialize)]
pub struct BackupDeleteArgs {
    /// Backup filename (just the leaf, no path separators).
    pub filename: String,
}

/// Remove one backup from disk. Validates `filename` against
/// path-traversal in `backup::delete_backup`. Returns `true` iff a
/// file was actually present so the UI can skip a refresh on a
/// stale id.
#[tauri::command]
pub async fn backup_delete(
    args: BackupDeleteArgs,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    let root = h.project.read().root.clone();
    crate::backup::delete_backup(&root, &args.filename).map_err(fail)
}

// ---- Repeater ------------------------------------------------------------

#[tauri::command]
pub async fn repeater_list(state: AppStateRef<'_>) -> Result<Vec<RepeaterTab>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.list_tabs())
}

#[derive(Debug, Deserialize)]
pub struct NewRepeaterTab {
    pub name: String,
    pub url: String,
    pub method: Option<String>,
}

#[tauri::command]
pub async fn repeater_add_tab(args: NewRepeaterTab, state: AppStateRef<'_>) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let method = args.method.unwrap_or_else(|| "GET".into());
    let req = Request::new(&method, &args.url).map_err(fail)?;
    let id = h.repeater.add_tab(RepeaterTab::new(args.name, req));
    Ok(id.as_i64())
}

/// Clone a stored history transaction into a brand-new Repeater tab.
/// The reconstructed `Request` carries the original method + URL +
/// headers + body (not just the URL like `repeater_add_tab`), so an
/// operator sending an issue → Repeater sees the exact bytes the
/// scanner flagged.
#[derive(Debug, Deserialize)]
pub struct RepeaterAddFromHistoryArgs {
    pub tx_id: i64,
    #[serde(default)]
    pub name: Option<String>,
}

#[tauri::command]
pub async fn repeater_add_from_history(
    args: RepeaterAddFromHistoryArgs,
    state: AppStateRef<'_>,
) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let tx_id = TrafficId::from(args.tx_id);
    let summary = hist
        .get_summary(tx_id)
        .map_err(fail)?
        .ok_or_else(|| "transaction not found".to_string())?;
    let req_blob = hist
        .get_request_blob(tx_id)
        .map_err(fail)?
        .ok_or_else(|| "no request blob stored".to_string())?;
    let req_bytes = blobs
        .get(&req_blob)
        .map_err(fail)?
        .ok_or_else(|| "request blob missing from store".to_string())?;
    let tx = rebuild_transaction(&summary, &req_bytes, None).map_err(fail)?;
    let name = args
        .name
        .unwrap_or_else(|| format!("{} {}", tx.request.method, summary.path));
    // Stamp the source transaction id so the Repeater UI can offer
    // a "Jump to parent in HTTP history" button (R99).
    let id = h.repeater.add_tab(
        RepeaterTab::new(name, tx.request).with_source_tx(tx_id),
    );
    Ok(id.as_i64())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterAddFromWireArgs {
    pub name: String,
    /// Raw request bytes exactly as they came off the wire. The
    /// interceptor already captured this; the Proxy → Repeater
    /// handoff passes it through verbatim so the operator gets a
    /// byte-exact replay target (headers / cookies / body preserved).
    pub wire: Vec<u8>,
    /// Origin host — fallback for the `Host` header if the operator
    /// removed it mid-intercept and for the Request's `host` field.
    pub host: String,
    /// Origin port. Must match the host — Burp uses this when
    /// re-serialising the request so the Repeater's HTTP client dials
    /// the right port even on non-standard listener setups.
    pub port: u16,
    /// `"http"` or `"https"`. Determines whether the Repeater's HTTP
    /// client wraps the socket in TLS before sending the bytes.
    pub scheme: String,
}

/// Create a Repeater tab from raw on-the-wire request bytes.
///
/// Backs the Proxy → Repeater handoff in `sendRowToRepeater`. The
/// previous implementation only passed the URL + method, which
/// stripped every header + body the operator may have been
/// inspecting at the time of intercept — a byte-exact replay then
/// required a manual paste into the request editor. Now the wire
/// bytes are parsed via the shared `parse_edited_request` helper
/// (same path the interceptor's "resolve with edits" flow uses) so
/// Host-header fixups + HTTP/2 → 1.1 downgrade + body preservation
/// all land for free, and the resulting Repeater tab is a byte-exact
/// copy of what was mid-flight.
#[tauri::command]
pub async fn repeater_add_from_wire(
    args: RepeaterAddFromWireArgs,
    state: AppStateRef<'_>,
) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let req = burpfree_proxy::parse_edited_request(
        &args.wire,
        &args.host,
        args.port,
        &args.scheme,
    )
    .map_err(fail)?;
    let id = h.repeater.add_tab(RepeaterTab::new(args.name, req));
    Ok(id.as_i64())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterUpdate {
    pub id: i64,
    pub template: Request,
}

#[tauri::command]
pub async fn repeater_update(args: RepeaterUpdate, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.update_template(TrafficId::from(args.id), args.template) {
        return Err("tab not found".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn repeater_send(id: i64, state: AppStateRef<'_>) -> Result<burpfree_engines::repeater::RepeaterSend, String> {
    let h = state.require().map_err(fail)?;
    h.repeater.send(TrafficId::from(id)).await.map_err(fail)
}

/// Fire a cancel signal at any in-flight `send()` /
/// `follow_redirect()` for the given tab. Returns `true` when the
/// Repeater had a Notify registered (i.e. something was mid-flight)
/// and the signal was delivered, `false` otherwise. The pending
/// `repeater_send` call still resolves — with
/// `RepeaterSend::error = Some("send cancelled")` — so the UI gets a
/// normal history row rather than a Promise reject.
#[tauri::command]
pub async fn repeater_cancel(id: i64, state: AppStateRef<'_>) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.cancel(TrafficId::from(id)))
}

/// Fire a cancel at every in-flight Repeater send across every tab.
/// Returns the number of tabs that had a parked Notify. The
/// in-flight promises each resolve with `error = "send cancelled"`
/// so the UI's finally-blocks still clear the inflight set entries
/// one at a time without a mass invalidation. Panic-button for
/// post-`send_group_parallel` meltdowns.
#[tauri::command]
pub async fn repeater_cancel_all(state: AppStateRef<'_>) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.cancel_all())
}

/// Snapshot of every tab currently mid-flight. The frontend fetches
/// this on panel re-mount so the per-tab Cancel buttons highlight
/// correctly even for sends that were started before the panel
/// mounted (reload / tab-switch / navigation). Each `TrafficId` is
/// serialised as an `i64` to match the rest of the Repeater cmds.
#[tauri::command]
pub async fn repeater_inflight_ids(state: AppStateRef<'_>) -> Result<Vec<i64>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.inflight_ids().into_iter().map(|id| id.as_i64()).collect())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterBurstArgs {
    pub id: i64,
    /// Count is clamped on the engine side; the UI should still
    /// present a sensible default (e.g. 10).
    pub count: u32,
    #[serde(default)]
    pub gap_ms: u64,
}

#[tauri::command]
pub async fn repeater_burst_send(
    args: RepeaterBurstArgs,
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_engines::repeater::RepeaterSend>, String> {
    let h = state.require().map_err(fail)?;
    h.repeater
        .burst_send(TrafficId::from(args.id), args.count, args.gap_ms)
        .await
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct RepeaterRenameArgs {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSetCommentArgs {
    pub id: i64,
    pub comment: String,
}

/// Replace the tab's free-form comment. Empty strings clear it.
/// Mirror of Burp's "Set comment" tab action; the UI surfaces a 💬
/// indicator on the chip + the comment as a tooltip.
#[tauri::command]
pub async fn repeater_set_comment(
    args: RepeaterSetCommentArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.set_comment(TrafficId::from(args.id), args.comment) {
        return Err("tab not found".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn repeater_rename(args: RepeaterRenameArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.rename(TrafficId::from(args.id), args.name) {
        return Err("tab not found".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterDuplicateArgs {
    pub id: i64,
    /// Optional explicit name for the new tab. When omitted the
    /// backend appends `" (copy)"` to the source name.
    #[serde(default)]
    pub name: Option<String>,
}

/// Clone a Repeater tab (template + colour + follow-redirect policy +
/// comment) into a fresh tab with a new id. History is dropped so
/// the duplicate starts clean. Returns the new tab's id so the UI
/// can activate it immediately.
#[tauri::command]
pub async fn repeater_duplicate_tab(
    args: RepeaterDuplicateArgs,
    state: AppStateRef<'_>,
) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let new_id = h
        .repeater
        .clone_tab(TrafficId::from(args.id), args.name)
        .ok_or("tab not found")?;
    Ok(new_id.as_i64())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSetColorArgs {
    pub id: i64,
    /// `None` or an empty string clears the colour.
    #[serde(default)]
    pub color: Option<String>,
}

#[tauri::command]
pub async fn repeater_set_color(args: RepeaterSetColorArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.set_color(TrafficId::from(args.id), args.color) {
        return Err("tab not found".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSetGroupArgs {
    pub id: i64,
    /// `None` or an empty / whitespace string clears the group.
    #[serde(default)]
    pub group: Option<String>,
}

/// Assign (or clear) the tab's group label. Burp's "Add to group" /
/// "Remove from group" context-menu action maps here.
#[tauri::command]
pub async fn repeater_set_group(
    args: RepeaterSetGroupArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.set_group(TrafficId::from(args.id), args.group) {
        return Err("tab not found".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterRenameGroupArgs {
    pub old: String,
    pub new: String,
}

/// Rename every tab currently in `old` to be in `new`. Blank `new`
/// clears the group on each member. Returns how many tabs moved.
#[tauri::command]
pub async fn repeater_rename_group(
    args: RepeaterRenameGroupArgs,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.rename_group(&args.old, &args.new))
}

/// Clear the group on every member of `group`. Member tabs are not
/// deleted — just ungrouped. Mirrors Burp's "Delete group" (which
/// also preserves the tabs). Returns how many tabs were affected.
#[tauri::command]
pub async fn repeater_delete_group(
    group: String,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.delete_group(&group))
}

/// Return every unique group label currently assigned to any tab,
/// sorted lexicographically. Used by the "Add to existing group"
/// submenu so the UI can list existing groups without re-walking the
/// tab list on the frontend.
#[tauri::command]
pub async fn repeater_list_groups(state: AppStateRef<'_>) -> Result<Vec<String>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.list_groups())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSetPinnedArgs {
    pub id: i64,
    pub pinned: bool,
}

/// Toggle a Repeater tab's pinned flag. Pinned tabs float left of
/// unpinned peers in `list_tabs` and are skipped by bulk-close
/// context-menu actions. Returns an error when the id doesn't
/// match a tab.
#[tauri::command]
pub async fn repeater_set_pinned(
    args: RepeaterSetPinnedArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.set_pinned(TrafficId::from(args.id), args.pinned) {
        return Err("tab not found".into());
    }
    Ok(())
}

/// Reorder Repeater tabs by walking `ids` in display order and
/// assigning each known tab `order = (i+1)*1000`. Unknown ids are
/// skipped. Tabs whose id isn't present keep their existing order,
/// so a drag-reorder scoped to one group doesn't flatten the rest
/// of the tab bar. Returns the number of tabs updated.
#[tauri::command]
pub async fn repeater_reorder(
    ids: Vec<i64>,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let tids: Vec<TrafficId> = ids.into_iter().map(TrafficId::from).collect();
    Ok(h.repeater.reorder_tabs(&tids))
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSendGroupArgs {
    pub group: String,
    /// `"sequential"` or `"parallel"`.
    #[serde(default)]
    pub mode: Option<String>,
}

/// Fire every tab in `group`, either sequentially (one-after-another)
/// or in parallel (`tokio::spawn` fan-out). Returns the per-send
/// result list. Each send also lands in its own tab's history by
/// virtue of calling the shared `send()`.
#[tauri::command]
pub async fn repeater_send_group(
    args: RepeaterSendGroupArgs,
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_engines::repeater::RepeaterSend>, String> {
    let h = state.require().map_err(fail)?;
    let mode = args.mode.as_deref().unwrap_or("sequential");
    let out = match mode {
        "parallel" => h.repeater.send_group_parallel(&args.group).await,
        _ => h.repeater.send_group_sequential(&args.group).await,
    };
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct RepeaterChangeMethodArgs {
    pub id: i64,
    pub method: String,
}

#[tauri::command]
pub async fn repeater_change_method(
    args: RepeaterChangeMethodArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if !h.repeater.change_method(TrafficId::from(args.id), &args.method) {
        return Err("invalid method or tab not found".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterBodyEncodingArgs {
    pub id: i64,
    /// `"plain" | "gzip" | "chunked"`.
    pub kind: String,
}

#[tauri::command]
pub async fn repeater_set_body_encoding(
    args: RepeaterBodyEncodingArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    use burpfree_engines::repeater::BodyEncoding;
    let kind = match args.kind.as_str() {
        "plain" => BodyEncoding::Plain,
        "gzip" => BodyEncoding::Gzip,
        "chunked" => BodyEncoding::Chunked,
        other => return Err(format!("unknown body encoding `{other}`")),
    };
    let h = state.require().map_err(fail)?;
    let ok = h
        .repeater
        .set_body_encoding(TrafficId::from(args.id), kind)
        .map_err(fail)?;
    if !ok {
        return Err("tab not found".into());
    }
    Ok(())
}

/// Wipe one tab's response history. Keeps the tab itself (template,
/// name, pinned / colour / group / follow-redirects settings all
/// survive) and returns `true` iff the tab existed. Operators
/// iterating on a long payload chain want a clean slate between
/// probes without closing + recreating the tab; this backs the
/// "Clear history" button in the Repeater's history strip + the
/// matching tab-context-menu entry.
#[tauri::command]
pub async fn repeater_tab_clear_history(
    id: i64,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.repeater.clear_tab_history(TrafficId::from(id)))
}

#[tauri::command]
pub async fn repeater_remove(id: i64, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.repeater.remove_tab(TrafficId::from(id));
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RepeaterFollowRedirectsArgs {
    pub id: i64,
    /// Policy name: `never`, `on_site`, `in_scope`, `always`, or
    /// `inherit` / `null` to clear the per-tab override and defer
    /// to the client's configured default.
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepeaterSetUrlArgs {
    pub id: i64,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct RepeaterFollowRedirectArgs {
    pub id: i64,
    pub location: String,
}

/// One-shot: resolve `location` against the tab's current URL and send
/// without touching the tab's template. The resulting `RepeaterSend` is
/// appended to the tab's history, same as any other send.
#[tauri::command]
pub async fn repeater_follow_redirect(
    args: RepeaterFollowRedirectArgs,
    state: AppStateRef<'_>,
) -> Result<burpfree_engines::repeater::RepeaterSend, String> {
    let h = state.require().map_err(fail)?;
    h.repeater
        .follow_redirect(TrafficId::from(args.id), &args.location)
        .await
        .map_err(fail)
}

#[tauri::command]
pub async fn repeater_set_url(
    args: RepeaterSetUrlArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let ok = h
        .repeater
        .set_url(TrafficId::from(args.id), &args.url)
        .map_err(fail)?;
    if !ok {
        return Err("tab not found".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn repeater_set_follow_redirects(
    args: RepeaterFollowRedirectsArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    use burpfree_core::net::FollowRedirectPolicy;
    let policy = match args.policy.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
        None => None,
        Some(ref s) if s.is_empty() || s == "inherit" => None,
        Some(ref s) if s == "never" => Some(FollowRedirectPolicy::Never),
        Some(ref s) if s == "on_site" || s == "onsite" => Some(FollowRedirectPolicy::OnSite),
        Some(ref s) if s == "in_scope" || s == "inscope" => Some(FollowRedirectPolicy::InScope),
        Some(ref s) if s == "always" => Some(FollowRedirectPolicy::Always),
        Some(ref s) => return Err(format!("unknown redirect policy `{s}`")),
    };
    let h = state.require().map_err(fail)?;
    if !h
        .repeater
        .set_follow_redirects(TrafficId::from(args.id), policy)
    {
        return Err("tab not found".into());
    }
    Ok(())
}

// ---- Intruder ------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IntruderStartArgs {
    pub config: IntruderConfig,
}

#[tauri::command]
pub async fn intruder_start(args: IntruderStartArgs, state: AppStateRef<'_>) -> Result<i64, String> {
    let handle = IntruderJob::start(args.config).map_err(fail)?;
    let job_id = handle.counter.load(std::sync::atomic::Ordering::Relaxed) as i64 ^ chrono::Utc::now().timestamp_millis();
    state.intruder_jobs.lock().await.insert(job_id, handle);
    Ok(job_id)
}

#[tauri::command]
pub async fn intruder_cancel(id: i64, state: AppStateRef<'_>) -> Result<(), String> {
    if let Some(h) = state.intruder_jobs.lock().await.get(&id) {
        let _ = h.cancel.send(true);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct IntruderPoll {
    pub status: JobStatus,
    pub done: u64,
    pub total: u64,
    pub new_results: Vec<AttackResult>,
    /// `true` when the operator has raised the pause flag — the
    /// dispatcher has frozen new iterations but in-flight tasks run
    /// to completion. Mirrors `JobHandle::pause.load(Relaxed)`.
    pub paused: bool,
}

#[tauri::command]
pub async fn intruder_poll(id: i64, state: AppStateRef<'_>) -> Result<IntruderPoll, String> {
    let mut jobs = state.intruder_jobs.lock().await;
    let h = jobs.get_mut(&id).ok_or("job not found")?;
    let mut new_results = Vec::new();
    while let Ok(r) = h.rx.try_recv() {
        new_results.push(r);
    }
    let status = *h.status.lock();
    let done = h.counter.load(std::sync::atomic::Ordering::Relaxed);
    let total = h.total;
    let paused = h.pause.load(std::sync::atomic::Ordering::Relaxed);
    Ok(IntruderPoll { status, done, total, new_results, paused })
}

/// Raise the dispatcher's pause flag — in-flight tasks run to
/// completion but no further iterations will dispatch until
/// `intruder_resume` is called. Noop when the job id is unknown
/// (returns false) so the UI can safely fire it against a race'd
/// cancel.
#[tauri::command]
pub async fn intruder_pause(id: i64, state: AppStateRef<'_>) -> Result<bool, String> {
    let jobs = state.intruder_jobs.lock().await;
    match jobs.get(&id) {
        Some(h) => {
            h.pause.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Clear the dispatcher's pause flag so queued iterations resume.
/// Idempotent: calling resume on an already-running job is a no-op.
#[tauri::command]
pub async fn intruder_resume(id: i64, state: AppStateRef<'_>) -> Result<bool, String> {
    let jobs = state.intruder_jobs.lock().await;
    match jobs.get(&id) {
        Some(h) => {
            h.pause.store(false, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Reconstruct one Intruder results row into a concrete Request and
/// spawn it as a new Repeater tab. The caller passes the same
/// `IntruderConfig` it used to start the attack plus the row's
/// `payloads` tuple (which the frontend already has from `intruder_poll`).
///
/// Returns the new Repeater tab id so the UI can navigate straight to it.
#[derive(Debug, Deserialize)]
pub struct IntruderToRepeaterArgs {
    pub config: IntruderConfig,
    pub payloads: Vec<String>,
    #[serde(default)]
    pub tab_name: Option<String>,
}

#[tauri::command]
pub async fn intruder_result_to_repeater(
    args: IntruderToRepeaterArgs,
    state: AppStateRef<'_>,
) -> Result<i64, String> {
    use burpfree_engines::repeater::RepeaterTab;
    let h = state.require().map_err(fail)?;
    let req = burpfree_engines::intruder::rebuild_request(
        &args.config.template,
        args.config.marker,
        &args.payloads,
    );
    let label = args.tab_name.unwrap_or_else(|| {
        if args.payloads.is_empty() {
            "intruder → repeater".into()
        } else {
            format!("intruder: {}", args.payloads.join(" / "))
        }
    });
    let tab_id = h.repeater.add_tab(RepeaterTab::new(label, req));
    Ok(tab_id.as_i64())
}

// ---- Intruder recipes ----------------------------------------------------

/// One saved attack recipe. Serialised into
/// `ProjectConfig::intruder_recipes` as opaque JSON so the storage
/// crate doesn't take a dep on `burpfree-engines::IntruderConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderRecipe {
    pub name: String,
    pub config: serde_json::Value,
    pub created_at_ms: i64,
}

/// Lightweight list view — the UI dropdown only needs the name, size
/// (number of payload rows), and creation timestamp. Full config is
/// fetched via `intruder_recipe_load` on demand.
#[derive(Debug, Clone, Serialize)]
pub struct IntruderRecipeView {
    pub name: String,
    pub created_at_ms: i64,
    pub payload_count: usize,
    pub mode: String,
}

fn load_recipes(h: &crate::state::ProjectHandle) -> Vec<IntruderRecipe> {
    let p = h.project.read();
    p.config
        .intruder_recipes
        .iter()
        .filter_map(|v| serde_json::from_value::<IntruderRecipe>(v.clone()).ok())
        .collect()
}

fn save_recipes(h: &crate::state::ProjectHandle, recipes: &[IntruderRecipe]) -> Result<(), String> {
    let mut p = h.project.write();
    p.config.intruder_recipes = recipes
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    p.save_config().map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct IntruderRecipeSaveArgs {
    pub name: String,
    pub config: serde_json::Value,
}

#[tauri::command]
pub async fn intruder_recipe_save(
    args: IntruderRecipeSaveArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let name = args.name.trim().to_string();
    if name.is_empty() {
        return Err("recipe name is required".into());
    }
    let mut recipes = load_recipes(&h);
    let entry = IntruderRecipe {
        name: name.clone(),
        config: args.config,
        created_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    // Replace existing entry with the same name, otherwise append.
    if let Some(pos) = recipes.iter().position(|r| r.name == name) {
        recipes[pos] = entry;
    } else {
        recipes.push(entry);
    }
    save_recipes(&h, &recipes)
}

#[tauri::command]
pub async fn intruder_recipe_list(
    state: AppStateRef<'_>,
) -> Result<Vec<IntruderRecipeView>, String> {
    let h = state.require().map_err(fail)?;
    let recipes = load_recipes(&h);
    let views = recipes
        .into_iter()
        .map(|r| {
            // Pull a tiny preview out of the opaque config so the dropdown
            // can show "sniper · 50 payloads" without the operator loading
            // the recipe.
            let mode = r
                .config
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("—")
                .to_string();
            let payload_count = r
                .config
                .get("payloads")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|p| p.get("items").and_then(|v| v.as_array()).map_or(0, Vec::len))
                        .sum::<usize>()
                })
                .unwrap_or(0);
            IntruderRecipeView {
                name: r.name,
                created_at_ms: r.created_at_ms,
                payload_count,
                mode,
            }
        })
        .collect();
    Ok(views)
}

#[derive(Debug, Deserialize)]
pub struct IntruderRecipeIdArgs {
    pub name: String,
}

#[tauri::command]
pub async fn intruder_recipe_load(
    args: IntruderRecipeIdArgs,
    state: AppStateRef<'_>,
) -> Result<serde_json::Value, String> {
    let h = state.require().map_err(fail)?;
    let recipes = load_recipes(&h);
    recipes
        .into_iter()
        .find(|r| r.name == args.name)
        .map(|r| r.config)
        .ok_or_else(|| format!("recipe not found: {}", args.name))
}

#[tauri::command]
pub async fn intruder_recipe_delete(
    args: IntruderRecipeIdArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let mut recipes = load_recipes(&h);
    let before = recipes.len();
    recipes.retain(|r| r.name != args.name);
    if recipes.len() == before {
        return Err(format!("recipe not found: {}", args.name));
    }
    save_recipes(&h, &recipes)
}

// ---- Target host notes --------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HostNoteSetArgs {
    pub host: String,
    pub note: String,
}

/// Set / clear the free-form note on a host. Passing an empty string
/// (or whitespace-only) removes the entry so the stored config stays
/// tidy. The hostname is lowercased before use so capitalisation
/// drift between observations doesn't produce ghost entries.
#[tauri::command]
pub async fn host_note_set(
    args: HostNoteSetArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let host = args.host.trim().to_lowercase();
    if host.is_empty() {
        return Err("host is required".into());
    }
    let note = args.note.trim();
    let mut p = h.project.write();
    if note.is_empty() {
        p.config.host_notes.remove(&host);
    } else {
        p.config.host_notes.insert(host, note.to_string());
    }
    p.save_config().map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct HostNoteGetArgs {
    pub host: String,
}

#[tauri::command]
pub async fn host_note_get(
    args: HostNoteGetArgs,
    state: AppStateRef<'_>,
) -> Result<String, String> {
    let h = state.require().map_err(fail)?;
    let host = args.host.trim().to_lowercase();
    let p = h.project.read();
    Ok(p.config.host_notes.get(&host).cloned().unwrap_or_default())
}

/// Dump the whole host → note map. Lets a future "Notes" sub-tab render
/// a project-wide table without hitting the backend per row.
#[tauri::command]
pub async fn host_notes_list(
    state: AppStateRef<'_>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let h = state.require().map_err(fail)?;
    let p = h.project.read();
    Ok(p.config.host_notes.clone())
}

// ---- Payload library -----------------------------------------------------

/// Return the catalog of built-in Intruder wordlists shipped inside the
/// binary. The frontend uses this to populate the Library dropdown in
/// the Intruder toolbar — no project / login state is involved.
#[tauri::command]
pub async fn payloads_library_list() -> Result<Vec<burpfree_engines::PayloadLibraryEntry>, String> {
    Ok(burpfree_engines::payload_library_catalog())
}

#[derive(Debug, Deserialize)]
pub struct PayloadLibraryLoadArgs {
    pub id: String,
}

/// Return the raw newline-separated content of one built-in library.
/// Errors if `id` isn't in the catalog.
#[tauri::command]
pub async fn payloads_library_load(args: PayloadLibraryLoadArgs) -> Result<String, String> {
    burpfree_engines::payload_library_load(&args.id)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("unknown payload library: {}", args.id))
}

// ---- Site map ------------------------------------------------------------

#[tauri::command]
pub async fn sitemap_snapshot(state: AppStateRef<'_>) -> Result<serde_json::Value, String> {
    let h = state.require().map_err(fail)?;
    Ok(serde_json::to_value(h.sitemap.snapshot()).map_err(fail)?)
}

/// Fetch `/robots.txt` + `/sitemap.xml` for `base_url`, parse both,
/// return the aggregated report. Mirrors Burp's "fetch well-known"
/// behavior when an operator adds a new target. Non-fatal — any
/// 4xx/5xx/connect error on either file lands in `report.errors`
/// and the partial result is still returned. The HttpClient is
/// built from the project's HttpClientConfig so follow-redirects
/// policy + host-overrides + upstream proxy all apply (we want to
/// land on the same host-overridden IP the Repeater would).
#[tauri::command]
pub async fn target_import_well_known(
    base_url: String,
    state: AppStateRef<'_>,
) -> Result<burpfree_engines::WellKnownReport, String> {
    let h = state.require().map_err(fail)?;
    // Build a short-lived client inheriting the project's
    // follow-redirects + host-override view so our import follows
    // the same routing rules the rest of the engines use.
    let cfg = burpfree_engines::client::HttpClientConfig {
        host_overrides: Some(h.host_overrides.clone()),
        follow_redirects: match h
            .project
            .read()
            .config
            .follow_redirects
            .as_deref()
            .unwrap_or("never")
        {
            "on_site" => burpfree_core::net::FollowRedirectPolicy::OnSite,
            "in_scope" => burpfree_core::net::FollowRedirectPolicy::InScope,
            "always" => burpfree_core::net::FollowRedirectPolicy::Always,
            _ => burpfree_core::net::FollowRedirectPolicy::Never,
        },
        ..burpfree_engines::client::HttpClientConfig::default()
    };
    let client = burpfree_engines::client::HttpClient::new(cfg);
    Ok(burpfree_engines::well_known_import(&client, &base_url).await)
}

// ---- Decoder / Comparer / Sequencer --------------------------------------

#[derive(Debug, Deserialize)]
pub struct DecoderArgs {
    pub input: String,
    pub chain: Vec<burpfree_codec::chain::Transform>,
}

#[tauri::command]
pub async fn decoder_apply(args: DecoderArgs) -> Result<Vec<burpfree_codec::chain::ChainStep>, String> {
    Ok(burpfree_codec::apply_chain(&args.input, &args.chain))
}

#[derive(Debug, Deserialize)]
pub struct DecoderSmartArgs {
    pub input: String,
    /// Maximum layers to peel. Clamped on the engine side to [1, 16].
    #[serde(default = "default_smart_depth")]
    pub max_depth: usize,
}

fn default_smart_depth() -> usize { 6 }

#[tauri::command]
pub async fn decoder_smart(
    args: DecoderSmartArgs,
) -> Result<Vec<burpfree_codec::chain::ChainStep>, String> {
    Ok(burpfree_codec::smart_decode(&args.input, args.max_depth))
}

#[derive(Debug, Deserialize)]
pub struct ComparerArgs {
    pub left: String,
    pub right: String,
    pub ignore_whitespace: bool,
    /// Optional diff mode: `"line"` (default) or `"word"`.
    #[serde(default)]
    pub mode: Option<String>,
}

#[tauri::command]
pub async fn comparer_diff(args: ComparerArgs) -> Result<burpfree_engines::comparer::DiffReport, String> {
    let mode = match args.mode.as_deref() {
        Some("word") => burpfree_engines::comparer::CompareMode::Word,
        _ => burpfree_engines::comparer::CompareMode::Line,
    };
    Ok(burpfree_engines::comparer::compare_full(
        &args.left,
        &args.right,
        args.ignore_whitespace,
        mode,
    ))
}

#[derive(Debug, Deserialize)]
pub struct ComparerJsonArgs {
    pub left: String,
    pub right: String,
}

/// Structural JSON diff: parses both inputs and walks them in parallel,
/// surfacing a per-path Added / Removed / Changed / Same table. Used
/// by the Comparer's "JSON" mode button for API-response probing where
/// a text diff hides which field actually drifted.
#[tauri::command]
pub async fn comparer_diff_json(
    args: ComparerJsonArgs,
) -> Result<burpfree_engines::comparer::JsonDiffReport, String> {
    Ok(burpfree_engines::comparer::compare_json(
        &args.left,
        &args.right,
    ))
}



#[tauri::command]
pub async fn sequencer_analyze(tokens: Vec<String>) -> Result<TokenAnalysis, String> {
    Ok(analyze_tokens(&tokens))
}

// ---- Scanner -------------------------------------------------------------

/// One row in the passive-detector enable grid — the detector's
/// stable id (matches `Finding::detector`) plus whether the operator
/// has it enabled for this project.
#[derive(Debug, Clone, Serialize)]
pub struct PassiveDetectorInfo {
    pub id: String,
    pub enabled: bool,
}

/// Enumerate every built-in passive detector in registration order,
/// annotated with whether it's currently enabled for this project.
/// Burp's "Audit optimization → disable detectors" UI maps to this.
#[tauri::command]
pub async fn scanner_passive_detectors_list(
    state: AppStateRef<'_>,
) -> Result<Vec<PassiveDetectorInfo>, String> {
    let disabled = state.disabled_passive_detectors.read().clone();
    let out = burpfree_engines::scanner::passive::passive_detector_ids()
        .into_iter()
        .map(|id| PassiveDetectorInfo {
            id: id.to_string(),
            enabled: !disabled.contains(id),
        })
        .collect();
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct ScannerDetectorSetArgs {
    pub id: String,
    pub enabled: bool,
}

/// Enable or disable a specific passive detector for this project.
/// Updates the in-memory AppState set (consumed by the proxy sink on
/// every record) and persists the derived Vec into ProjectConfig so
/// the toggle survives a restart.
#[tauri::command]
pub async fn scanner_passive_detector_set(
    args: ScannerDetectorSetArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    // Validate the id against the known built-in list so a stale UI
    // can't silently stash an unknown id into project config.
    let known: std::collections::HashSet<&'static str> =
        burpfree_engines::scanner::passive::passive_detector_ids()
            .into_iter()
            .collect();
    if !known.contains(args.id.as_str()) {
        return Err(format!("unknown passive detector id: {}", args.id));
    }
    {
        let mut set = state.disabled_passive_detectors.write();
        if args.enabled {
            set.remove(&args.id);
        } else {
            set.insert(args.id.clone());
        }
    }
    // Persist to project config (sorted for a stable JSON diff).
    if let Ok(h) = state.require() {
        let snapshot: Vec<String> = {
            let g = state.disabled_passive_detectors.read();
            let mut v: Vec<String> = g.iter().cloned().collect();
            v.sort();
            v
        };
        let mut p = h.project.write();
        p.config.disabled_passive_detectors = snapshot;
        p.save_config().map_err(fail)?;
    }
    Ok(())
}

/// One row in the active-probe enable grid — the probe's stable
/// kebab-case id, whether the operator has it enabled, and whether
/// it's in the default-disabled set (so the UI can mark the row as
/// opt-in). Mirrors `PassiveDetectorInfo` for the active side.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveProbeInfo {
    pub id: String,
    pub enabled: bool,
    /// `true` when this probe is in `active_probe_default_disabled()`
    /// — the UI greys it with an "opt-in" hint so operators know
    /// turning it on costs extra wall-clock time (BlindSqlTime adds
    /// ~2 s per probed parameter).
    pub default_disabled: bool,
}

/// Enumerate every built-in active probe in registration order,
/// annotated with its current enablement + whether it ships
/// default-disabled.
#[tauri::command]
pub async fn scanner_active_probes_list(
    state: AppStateRef<'_>,
) -> Result<Vec<ActiveProbeInfo>, String> {
    let disabled = state.disabled_active_probes.read().clone();
    let defaults: std::collections::HashSet<&str> =
        burpfree_engines::scanner::active::active_probe_default_disabled()
            .iter()
            .copied()
            .collect();
    let out = burpfree_engines::scanner::active::active_probe_ids()
        .into_iter()
        .map(|id| ActiveProbeInfo {
            id: id.to_string(),
            enabled: !disabled.contains(id),
            default_disabled: defaults.contains(id),
        })
        .collect();
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct ScannerProbeSetArgs {
    pub id: String,
    pub enabled: bool,
}

/// Enable or disable a specific active probe for this project.
/// Validates the id against `Probe::from_id` so a stale UI (or a
/// hand-edited config) can't silently stash an unknown id — the UI
/// surfaces the error inline. Updates the in-memory AppState set
/// (consumed by a future active-scan dispatcher) and persists the
/// derived Vec into ProjectConfig so toggles survive a restart.
#[tauri::command]
pub async fn scanner_active_probe_set(
    args: ScannerProbeSetArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    if burpfree_engines::scanner::active::Probe::from_id(&args.id).is_none() {
        return Err(format!("unknown active probe id: {}", args.id));
    }
    {
        let mut set = state.disabled_active_probes.write();
        if args.enabled {
            set.remove(&args.id);
        } else {
            set.insert(args.id.clone());
        }
    }
    if let Ok(h) = state.require() {
        let snapshot: Vec<String> = {
            let g = state.disabled_active_probes.read();
            let mut v: Vec<String> = g.iter().cloned().collect();
            v.sort();
            v
        };
        let mut p = h.project.write();
        p.config.disabled_active_probes = snapshot;
        p.save_config().map_err(fail)?;
    }
    Ok(())
}

/// Summary returned by `scanner_active_run_tx` — enough signal for
/// the UI to show a tiny toast without having to re-request the
/// findings list on every click. `skipped_reason` is populated when
/// the scan was deliberately not run (no probes enabled, target not
/// in scope) so the frontend can distinguish that from a real error.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveScanReport {
    pub findings_added: usize,
    pub probes_run: usize,
    pub in_scope: bool,
    pub skipped_reason: Option<String>,
}

/// Fire every enabled active probe against the stored transaction
/// identified by `id`. Builds an `ActiveScanner` with the project's
/// current scope, host overrides, OOB listener (if running), and
/// the probe set filtered through `AppState.disabled_active_probes`
/// so R58's toggles finally gate real traffic. Each resulting
/// Finding is persisted via `history.insert_finding` (fingerprint
/// upsert — safe to re-run against the same tx).
///
/// Returns an `ActiveScanReport` instead of raising for the "no
/// probes enabled" / "target out of scope" cases so the UI can
/// render a quiet notice rather than an alert.
#[tauri::command]
pub async fn scanner_active_run_tx(
    id: i64,
    state: AppStateRef<'_>,
) -> Result<ActiveScanReport, String> {
    use burpfree_engines::scanner::active::{ActiveScanConfig, ActiveScanner, Probe};
    let h = state.require().map_err(fail)?;
    let tid = TrafficId::from(id);

    // Snapshot history + blobs + scope under the project read lock,
    // then drop the lock before the (potentially slow) scan.
    let (hist, blobs, scope) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone(), h.scope.read().clone())
    };

    let row = hist
        .get_summary(tid)
        .map_err(fail)?
        .ok_or_else(|| "transaction not found".to_string())?;
    let req_blob = hist
        .get_request_blob(tid)
        .map_err(fail)?
        .ok_or_else(|| "request blob missing".to_string())?;
    let req_bytes = blobs
        .get(&req_blob)
        .map_err(fail)?
        .ok_or_else(|| "request bytes missing in blob store".to_string())?;
    let resp_bytes = if let Some(rb) = hist.get_response_blob(tid).map_err(fail)? {
        blobs.get(&rb).map_err(fail)?
    } else {
        None
    };
    let tx = rebuild_transaction(&row, &req_bytes, resp_bytes.as_deref()).map_err(fail)?;

    // Build the filtered probe list using the operator's disabled
    // set. `Probe::all()` yields static references; copy to Probe
    // values so the ActiveScanConfig can own them.
    let disabled = state.disabled_active_probes.read().clone();
    let probes: Vec<Probe> = Probe::all()
        .iter()
        .copied()
        .filter(|p| !disabled.contains(p.id()))
        .collect();
    let probes_run = probes.len();
    if probes.is_empty() {
        return Ok(ActiveScanReport {
            findings_added: 0,
            probes_run: 0,
            in_scope: scope.is_in_scope(&tx.request),
            skipped_reason: Some("no probes enabled — turn some on in Scanner → Active probes".into()),
        });
    }

    let in_scope = scope.is_in_scope(&tx.request);
    if !in_scope {
        return Ok(ActiveScanReport {
            findings_added: 0,
            probes_run,
            in_scope: false,
            skipped_reason: Some("transaction host is out of scope — add it before scanning".into()),
        });
    }

    // Build the HTTP client config the same way Repeater does so
    // probes dial via the project's host-override registry.
    let http = burpfree_engines::client::HttpClientConfig {
        host_overrides: Some(h.host_overrides.clone()),
        ..burpfree_engines::client::HttpClientConfig::default()
    };
    let scan_cfg = ActiveScanConfig {
        probes,
        ..ActiveScanConfig::default()
    };
    let mut scanner = ActiveScanner::new(scan_cfg, http, scope);
    // Attach the OOB listener if one is running so OobSsrf +
    // OobCommandInjection probes can observe callbacks.
    {
        let guard = h.oob.read();
        if let Some(oh) = guard.as_ref() {
            scanner = scanner.with_oob(oh.clone());
        }
    }

    let findings = scanner.scan(&tx).await.map_err(fail)?;
    let mut inserted = 0usize;
    for mut f in findings {
        f.transaction_id = Some(tx.id);
        hist.insert_finding(&to_stored(&f)).map_err(fail)?;
        inserted += 1;
    }

    Ok(ActiveScanReport {
        findings_added: inserted,
        probes_run,
        in_scope: true,
        skipped_reason: None,
    })
}

#[tauri::command]
pub async fn passive_run_now(state: AppStateRef<'_>) -> Result<usize, String> {
    passive_run_impl(None, state).await
}

/// R139: Run passive detectors over a filtered subset of history.
/// Burp lets operators focus the audit — e.g. "only in-scope",
/// "only hosts matching corp.*", "only 2xx responses" — rather
/// than always sweeping the whole project. The filter respects
/// the full HistoryFilter schema (host_contains, status_classes,
/// error_only, time range, etc.) so the Scanner panel can wire
/// a configured chip set directly. Behaves identically to
/// `passive_run_now` otherwise: writes PassiveScanStatus,
/// honours disabled detectors, pulls custom extension rules.
#[tauri::command]
pub async fn passive_run_filtered(
    filter: HistoryFilter,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    passive_run_impl(Some(filter), state).await
}

async fn passive_run_impl(
    extra_filter: Option<HistoryFilter>,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    // Collect any custom passive rules contributed by enabled extensions
    // once, up front, so a long scan doesn't repeatedly re-lock the registry.
    let custom_rules = h.extensions.passive_rules();
    *h.scan.write() = crate::state::PassiveScanStatus {
        running: true,
        findings_last_run: None,
        started_ms: Some(burpfree_core::traffic::now_ms()),
        finished_ms: None,
    };
    // Build the effective filter: start with the caller's (or default
    // for the all-rows path) then clamp limit to 100_000 so a filter
    // without an explicit limit can't accidentally return a million
    // rows and OOM the backend.
    let mut effective = extra_filter.unwrap_or_default();
    if effective.limit.is_none() {
        effective.limit = Some(100_000);
    }
    let rows = hist.list(&effective).map_err(fail)?;
    // Snapshot the operator's disabled-detector set so the full
    // scan honours the Scanner → Passive detectors toggles. The
    // snapshot is taken once per run so a mid-run flip doesn't
    // split the scan half-with half-without a detector.
    let disabled_snapshot = state.disabled_passive_detectors.read().clone();
    let disabled_refs: std::collections::HashSet<&str> =
        disabled_snapshot.iter().map(|s| s.as_str()).collect();
    let mut findings = 0usize;
    for r in rows {
        let req_blob = match hist.get_request_blob(r.id).map_err(fail)? {
            Some(b) => b,
            None => continue,
        };
        let req_bytes = match blobs.get(&req_blob).map_err(fail)? {
            Some(b) => b,
            None => continue,
        };
        let resp_bytes = if let Some(rb) = hist.get_response_blob(r.id).map_err(fail)? {
            blobs.get(&rb).map_err(fail)?
        } else {
            None
        };
        let tx = rebuild_transaction(&r, &req_bytes, resp_bytes.as_deref()).map_err(fail)?;
        for mut f in passive::run_all_filtered(&tx, &custom_rules, &disabled_refs) {
            findings += 1;
            f.transaction_id = Some(tx.id);
            hist.insert_finding(&to_stored(&f)).map_err(fail)?;
        }
    }
    *h.scan.write() = crate::state::PassiveScanStatus {
        running: false,
        findings_last_run: Some(findings),
        started_ms: h.scan.read().started_ms,
        finished_ms: Some(burpfree_core::traffic::now_ms()),
    };
    Ok(findings)
}

/// Scan every stored WebSocket frame with the passive_ws detectors.
/// Returns the number of findings inserted into the project history.
///
/// Runs the full set of detectors (JWT, Bearer, AWS key, PEM, labelled
/// secret, email, basic-auth URL) across every message in every stored
/// WebSocket session. Dedup is handled by `upsert_finding`.
#[tauri::command]
pub async fn passive_ws_run_now(state: AppStateRef<'_>) -> Result<usize, String> {
    use burpfree_core::traffic::{WebSocketMessage, WsDirection, WsOpcode};
    use burpfree_engines::passive_ws::{self, WsScanContext};

    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let sessions = hist.list_ws_sessions(Some(10_000)).map_err(fail)?;
    let mut inserted = 0usize;
    for s in sessions {
        // Resolve the handshake scheme so we can mark ws:// as insecure.
        let scheme = hist
            .get_summary(s.handshake_id)
            .map_err(fail)?
            .map(|sum| sum.scheme)
            .unwrap_or_else(|| if s.port == 443 { "https".into() } else { "http".into() });
        let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
        let default_port = (ws_scheme == "ws" && s.port == 80)
            || (ws_scheme == "wss" && s.port == 443);
        let authority = if default_port {
            s.host.clone()
        } else {
            format!("{}:{}", s.host, s.port)
        };
        let session_url = format!("{ws_scheme}://{authority}{}", s.path);
        let ctx = WsScanContext {
            session_id: s.id,
            session_url,
            insecure: ws_scheme == "ws",
        };

        let rows = hist.list_ws_messages(s.id).map_err(fail)?;
        for row in rows {
            let blob_ref = burpfree_core::ids::ContentRef {
                sha: row.blob.clone(),
                size: row.size,
            };
            let payload = match blobs.get(&blob_ref).map_err(fail)? {
                Some(bytes) => bytes,
                None => continue,
            };
            let direction = if row.direction == "in" {
                WsDirection::Inbound
            } else {
                WsDirection::Outbound
            };
            let opcode = WsOpcode::from_u8(row.opcode);
            let msg = WebSocketMessage {
                id: row.id,
                session_id: row.session_id,
                direction,
                opcode,
                payload,
                created_at_ms: row.ts_ms,
            };
            for mut f in passive_ws::run_all(&ctx, &msg) {
                f.transaction_id = Some(s.id);
                hist.upsert_finding(&to_stored(&f)).map_err(fail)?;
                inserted += 1;
            }
        }
    }
    Ok(inserted)
}

#[tauri::command]
pub async fn findings_list(state: AppStateRef<'_>) -> Result<Vec<StoredFinding>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.list_findings().map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct FindingAddManualArgs {
    /// Short issue title shown in the Scanner table and advisory
    /// header. Trimmed; empty is rejected.
    pub title: String,
    /// Severity label — must be one of critical / high / medium /
    /// low / info (case-insensitive). Burp uses the same five-level
    /// scale and we mirror it so cross-tool reports line up.
    pub severity: String,
    /// Long-form prose shown in the advisory pane. Optional.
    #[serde(default)]
    pub description: String,
    /// Optional detector label. Defaults to `manual` so operators
    /// can filter manual findings via the detector chip.
    #[serde(default)]
    pub detector: Option<String>,
    /// Optional link to a transaction. When set, Scanner's
    /// group-by-host groups the finding under the tx's host; when
    /// unset, it lands in the `(no transaction)` bucket.
    #[serde(default)]
    pub transaction_id: Option<i64>,
    /// Evidence block (raw request/response fragment, screenshot
    /// path, log snippet). Shown verbatim in the advisory.
    #[serde(default)]
    pub evidence: String,
    /// Remediation guidance. Shown in the advisory + reports.
    #[serde(default)]
    pub remediation: String,
    /// Free-form tags for filtering. Mirror of the R91 tag editor.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Operator-authored finding. Burp's Scanner lets pentesters add
/// manual issues during an engagement — things an automated detector
/// won't catch (business-logic abuse, chained-request exploits,
/// client-side-only XSS proven in-browser). R123 lands the same
/// affordance via a dedicated cmd that upserts a `StoredFinding`
/// with sensible defaults: confidence=firm (operator saw it),
/// verification=verified (operator triaged it), status=new (hasn't
/// been reported yet), observation_count=1. Fingerprint is unique
/// per manual-add so re-firing the same title doesn't collapse
/// into the previous row — manual findings aren't dedupe candidates.
/// Returns the new TrafficId as an i64 so the frontend can pop
/// the row into the detail pane without an extra round-trip.
#[tauri::command]
pub async fn finding_add_manual(
    args: FindingAddManualArgs,
    state: AppStateRef<'_>,
) -> Result<i64, String> {
    let title = args.title.trim();
    if title.is_empty() {
        return Err("title is required".into());
    }
    if title.len() > 500 {
        return Err("title too long (>500 chars) — summarise it".into());
    }
    let sev = args.severity.trim().to_ascii_lowercase();
    if !matches!(sev.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        return Err(format!(
            "severity must be one of critical|high|medium|low|info (got: {})",
            args.severity
        ));
    }
    let detector = args
        .detector
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("manual")
        .to_string();
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let now = burpfree_core::traffic::now_ms();
    let id = TrafficId::new();
    // Fingerprint keyed on the id so each manual-add gets a unique
    // slot — operators who re-add the same title get a fresh row
    // (vs the dedup-on-fingerprint behaviour that detectors use).
    let fingerprint = format!("manual-{}", id.as_i64());
    let finding = StoredFinding {
        id,
        ts_ms: now,
        transaction_id: args.transaction_id.map(TrafficId::from),
        detector,
        title: title.to_string(),
        description: args.description,
        severity: sev,
        confidence: "firm".to_string(),
        evidence: args.evidence,
        remediation: args.remediation,
        fingerprint,
        status: "new".to_string(),
        verification: "verified".to_string(),
        tags: args.tags,
        references: Vec::new(),
        assignee: None,
        note: String::new(),
        insertion_point: None,
        updated_at_ms: now,
        observation_count: 1,
    };
    hist.upsert_finding(&finding).map_err(fail)?;
    tracing::info!(
        id = id.as_i64(),
        severity = %finding.severity,
        detector = %finding.detector,
        "manual finding added"
    );
    Ok(id.as_i64())
}

#[tauri::command]
pub async fn findings_list_filtered(
    filter: Option<burpfree_storage::FindingFilter>,
    state: AppStateRef<'_>,
) -> Result<Vec<StoredFinding>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.list_findings_filtered(&filter.unwrap_or_default()).map_err(fail)
}

#[tauri::command]
pub async fn findings_counts(
    state: AppStateRef<'_>,
) -> Result<std::collections::BTreeMap<String, i64>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.finding_counts_by_severity().map_err(fail)
}

/// Per-host severity count breakdown — backs the Target → SiteMap
/// per-host issue badges. Shape: `host → severity → count`, keyed
/// by lower-cased severity label (critical / high / medium / low /
/// info) so the UI's palette lookup works regardless of how the
/// detector cased it. Findings without a `transaction_id` are
/// omitted (no host to join on). Empty project returns an empty
/// map rather than erroring.
#[tauri::command]
pub async fn findings_count_by_host(
    state: AppStateRef<'_>,
) -> Result<std::collections::HashMap<String, std::collections::HashMap<String, i64>>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let flat = hist.finding_counts_by_host().map_err(fail)?;
    let mut out: std::collections::HashMap<String, std::collections::HashMap<String, i64>> =
        std::collections::HashMap::new();
    for (host, sev, n) in flat {
        out.entry(host).or_default().insert(sev, n);
    }
    Ok(out)
}

// ---- Open response in default browser -------------------------------
//
// Burp has an "Open response in browser" action in the response-pane
// context menu that saves the body to a temp file and spawns the OS
// default handler. Essential UX for operators who want to see what
// the response actually looks like rendered — faster than copying to
// clipboard + hand-crafting an HTML file. The temp path is returned
// so the operator can save it elsewhere if needed; the file lives
// in the system temp dir and is NOT auto-cleaned (Burp's behaviour
// too — a session's worth of responses accumulate until the OS wipes
// the dir).

#[derive(Debug, Deserialize)]
pub struct OpenInBrowserArgs {
    pub content: String,
    /// MIME type used to pick a file extension (text/html → .html,
    /// application/json → .json, else .txt). `None` defaults to
    /// `text/html` since Burp's own menu assumes HTML.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Optional short label baked into the filename (e.g.
    /// "example-com-login" from the request path). Sanitised to
    /// ASCII-alnum + hyphen so a stray `/` or Unicode can't escape.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OpenInBrowserResult {
    pub path: String,
    pub extension: String,
    pub bytes_written: u64,
    pub opener: String,
}

#[tauri::command]
pub async fn response_open_in_browser(
    args: OpenInBrowserArgs,
    _state: AppStateRef<'_>,
) -> Result<OpenInBrowserResult, String> {
    // Pick an extension from the Content-Type. We only honour a
    // short whitelist — anything else gets `.txt` so a stray binary
    // CT doesn't trick the OS into executing something.
    let ct = args.content_type.as_deref().unwrap_or("text/html");
    let ext = match ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "text/html" | "application/xhtml+xml" => "html",
        "application/json" => "json",
        "application/xml" | "text/xml" => "xml",
        "text/css" => "css",
        "application/javascript" | "text/javascript" => "js",
        "image/svg+xml" => "svg",
        _ => "txt",
    };

    // Sanitise the optional label — ASCII-alnum + hyphen only.
    // Fallback to "response" when empty-after-sanitise so the
    // filename always has a stable stem.
    let stem = args
        .label
        .as_deref()
        .map(|s| {
            s.chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
                .collect::<String>()
        })
        .map(|s| {
            // Collapse runs of hyphens + trim leading/trailing.
            let collapsed: String = s
                .chars()
                .fold(String::new(), |mut acc, c| {
                    if c == '-' && acc.ends_with('-') {
                        acc
                    } else {
                        acc.push(c);
                        acc
                    }
                });
            collapsed.trim_matches('-').to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "response".to_string());
    // Cap stem at 60 chars so Windows MAX_PATH doesn't bite.
    let stem: String = stem.chars().take(60).collect();

    // Random token to avoid collisions when operators spam this
    // from Repeater — the backend returns the path so a stale click
    // can't overwrite a file the OS already opened.
    let tok = burpfree_core::ids::random_token(6);
    let filename = format!("burpfree-{stem}-{tok}.{ext}");
    let path = std::env::temp_dir().join(&filename);

    std::fs::write(&path, args.content.as_bytes())
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
    let bytes_written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    // Shell out to the OS default handler. Each platform has its own
    // one-liner — none of this needs tauri-plugin-opener since we're
    // launching a local file, not an untrusted URL.
    let path_str = path.to_string_lossy().into_owned();
    let (prog, cmd_args, opener): (&str, Vec<String>, &str) = if cfg!(target_os = "windows") {
        // `cmd /c start "" "<path>"` — the empty quoted string is
        // the window title arg start swallows otherwise, which eats
        // the real path when it has spaces.
        (
            "cmd",
            vec!["/c".into(), "start".into(), "".into(), path_str.clone()],
            "cmd /c start",
        )
    } else if cfg!(target_os = "macos") {
        ("open", vec![path_str.clone()], "open")
    } else {
        ("xdg-open", vec![path_str.clone()], "xdg-open")
    };

    std::process::Command::new(prog)
        .args(&cmd_args)
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;

    tracing::info!(
        path = %path.display(),
        opener,
        bytes = bytes_written,
        "response opened in browser"
    );

    Ok(OpenInBrowserResult {
        path: path_str,
        extension: ext.to_string(),
        bytes_written,
        opener: opener.to_string(),
    })
}

#[derive(Debug, Deserialize)]
pub struct OpenUrlArgs {
    pub url: String,
}

/// Open an http(s) URL in the OS default browser. Burp has
/// "Request in browser → in current browser session" that reloads
/// the request URL in the operator's live browser; this cmd
/// backs the frontend affordance that fires the same shape.
///
/// Deliberately restrictive to prevent misuse via the IPC layer:
///
///   * only `http://` and `https://` schemes accepted — `file://`,
///     `javascript:`, custom app-protocols, and anything else gets
///     a hard error rather than being handed to the shell;
///   * control characters (newlines, tabs, nul bytes) are rejected
///     — some platform openers (notably Windows `cmd /c start`)
///     split on whitespace / newlines, so a URL carrying a `\n`
///     could inject a second command;
///   * URL length capped at 8 KB — matches the browser URL-length
///     limit most engines settle on, prevents a malicious caller
///     from spamming megabyte payloads through the shell;
///   * no shell interpretation — we spawn `cmd /c start "" "<url>"`
///     on Windows (same empty-title trick as R79), `open "<url>"`
///     on macOS, `xdg-open "<url>"` on Linux. The URL goes in as a
///     single argv entry so even URLs with spaces don't become
///     separate args.
#[tauri::command]
pub async fn shell_open_url(args: OpenUrlArgs) -> Result<String, String> {
    let url = args.url.trim().to_string();
    if url.is_empty() {
        return Err("empty URL".into());
    }
    if url.len() > 8192 {
        return Err(format!("URL too long ({} chars; max 8192)", url.len()));
    }
    if url.chars().any(|c| c.is_control()) {
        return Err("URL contains control characters".into());
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!(
            "only http:// or https:// URLs are allowed (got: {})",
            // Truncate the error to the scheme + a bit so a 7 KB
            // garbage URL doesn't flood the operator's alert box.
            url.chars().take(60).collect::<String>()
        ));
    }
    let (prog, cmd_args): (&str, Vec<String>) = if cfg!(target_os = "windows") {
        // Empty-title arg so `start` doesn't swallow a URL with
        // spaces into the window-title slot (same gotcha as R79's
        // response-in-browser cmd).
        ("cmd", vec!["/c".into(), "start".into(), "".into(), url.clone()])
    } else if cfg!(target_os = "macos") {
        ("open", vec![url.clone()])
    } else {
        ("xdg-open", vec![url.clone()])
    };
    std::process::Command::new(prog)
        .args(&cmd_args)
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    tracing::info!(url = %url, "url opened in browser");
    Ok(url)
}

#[derive(Debug, Deserialize)]
pub struct SaveResponseBodyArgs {
    pub tx_id: i64,
    pub path: String,
    /// When true, write a Burp-style "raw response" dump (status line
    /// + headers + blank line + body). When false (default), write
    /// just the body bytes — the right choice for binary payloads
    /// like PDFs, PNGs, and MP4s where appending header text in front
    /// would corrupt the file. The frontend defaults to body-only
    /// and lets the operator opt in via a context-menu variant.
    #[serde(default)]
    pub include_headers: bool,
}

#[derive(Debug, Serialize)]
pub struct SaveResponseBodyResult {
    pub path: String,
    pub bytes_written: u64,
}

/// Binary-safe response-body save. The pre-R115 Repeater affordance
/// (`downloadText` in the frontend) wrapped the response in a Blob
/// with `text/plain;charset=utf-8` which silently mojibakes binary
/// bodies — PDFs download corrupt, PNGs become unreadable, gzipped
/// JSON ends up stripped of null bytes. This cmd skips the string
/// detour entirely: pulls the raw bytes out of the blob store and
/// writes them to the operator-chosen path. The frontend derives
/// the extension from the Content-Type header (same whitelist R79
/// uses) and prompts for a filename — path validation here is kept
/// defensive but light since the user chose it.
#[tauri::command]
pub async fn history_save_response_body(
    args: SaveResponseBodyArgs,
    state: AppStateRef<'_>,
) -> Result<SaveResponseBodyResult, String> {
    let h = state.require().map_err(fail)?;
    let tid = TrafficId::from(args.tx_id);
    // Snapshot history + blobs under the project read lock, then
    // drop the guard before any filesystem I/O so a slow disk can't
    // block the Dashboard refresh loop.
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    // Light validation on the destination path. The operator picked
    // it via a frontend prompt so we trust the intent, but a few
    // sanity checks protect against obviously-wrong inputs that
    // would turn into cryptic I/O errors on write.
    let path_trimmed = args.path.trim();
    if path_trimmed.is_empty() {
        return Err("empty destination path".into());
    }
    if path_trimmed.chars().any(|c| c.is_control()) {
        return Err("destination path contains control characters".into());
    }
    if path_trimmed.len() > 4096 {
        return Err("destination path too long (>4096 chars)".into());
    }
    // Pull the response bytes out of the blob store. `None` means
    // either (a) the row never had a response (connect refused /
    // handshake fail) or (b) the blob was garbage-collected. Either
    // way the save is a no-op from the operator's perspective.
    let resp_bytes: Vec<u8> = if let Some(rb) = hist
        .get_response_blob(tid)
        .map_err(fail)?
    {
        blobs
            .get(&rb)
            .map_err(fail)?
            .ok_or_else(|| "response blob missing in content-addressed store".to_string())?
    } else {
        return Err("no response body stored for this transaction".into());
    };
    // The stored blob is the raw-wire response — status line +
    // headers + CRLF CRLF + body. `include_headers` controls whether
    // we hand the operator that full dump or strip the header block.
    // Body-only is the default because the common use case is
    // "save this PDF / PNG / mp4 as a file I can double-click" and
    // prepending the HTTP envelope corrupts those formats. Operators
    // who want the raw-wire view (debugging HTTP semantics, filing a
    // bug report) can flip `include_headers=true` via a context-
    // menu variant.
    let bytes_to_write: Vec<u8> = if args.include_headers {
        resp_bytes
    } else {
        // Reuse the existing `body_part` helper so the stripping
        // rule stays consistent with every other place that splits
        // headers from body. It returns an empty slice if no
        // CRLFCRLF separator is found — in that case fall back to
        // the full blob rather than silently emitting a zero-byte
        // file (a chunked-after-reset partial response can land as
        // "no separator yet, all-body").
        let body = body_part(&resp_bytes);
        if body.is_empty() && !resp_bytes.is_empty() {
            resp_bytes
        } else {
            body.to_vec()
        }
    };
    let path = std::path::PathBuf::from(path_trimmed);
    std::fs::write(&path, &bytes_to_write)
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
    tracing::info!(
        tx_id = args.tx_id,
        path = %path.display(),
        bytes = bytes_to_write.len(),
        include_headers = args.include_headers,
        "response body saved to disk"
    );
    Ok(SaveResponseBodyResult {
        path: path.to_string_lossy().into_owned(),
        bytes_written: bytes_to_write.len() as u64,
    })
}

/// Open the current project's root directory in the OS file manager.
/// Mirror of Burp's "Open project folder" action. Shells out to the
/// platform-native opener (same pattern as R79's response-in-browser
/// cmd). No path argument — the project root is read from the live
/// ProjectHandle so the operator can't aim this at an arbitrary
/// path by poking the IPC layer.
#[tauri::command]
pub async fn project_open_folder(state: AppStateRef<'_>) -> Result<String, String> {
    let h = state.require().map_err(fail)?;
    let root = h.project.read().root.clone();
    if !root.exists() {
        return Err(format!("project root does not exist: {}", root.display()));
    }
    let path_str = root.to_string_lossy().into_owned();
    let (prog, cmd_args): (&str, Vec<String>) = if cfg!(target_os = "windows") {
        // `cmd /c start "" "<path>"` — the empty quoted title arg
        // prevents start from swallowing the real path when it
        // contains spaces (same gotcha as R79).
        ("cmd", vec!["/c".into(), "start".into(), "".into(), path_str.clone()])
    } else if cfg!(target_os = "macos") {
        ("open", vec![path_str.clone()])
    } else {
        ("xdg-open", vec![path_str.clone()])
    };
    std::process::Command::new(prog)
        .args(&cmd_args)
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    tracing::info!(path = %path_str, "project folder opened");
    Ok(path_str)
}

// ---- Scanner report export (HTML / JSON / SARIF) ----------------------
//
// Thin UI-facing wrapper around `burpfree-report`. The CLI already
// has the same three formats under `burpfree report --format …`;
// R75 brings the same capability into the GUI so operators can
// generate client-ready HTML / machine-readable JSON / CI-friendly
// SARIF without dropping to the shell.

#[derive(Debug, Deserialize)]
pub struct ScannerReportArgs {
    /// Absolute path on disk. Parent directory must exist — this
    /// cmd does NOT create directories, matching the operator's
    /// expectation when they picked a specific destination.
    pub path: String,
    /// `"html"` / `"json"` / `"sarif"`. Unknown values return a
    /// descriptive error instead of silently defaulting.
    pub format: String,
    /// Optional subset. When present, only findings whose ids are
    /// in this list are included — matches Burp's "Report selected
    /// issues" flow. `None` or empty = include all findings.
    #[serde(default)]
    pub finding_ids: Option<Vec<i64>>,
}

#[derive(Debug, Serialize)]
pub struct ScannerReportResult {
    pub path: String,
    pub format: String,
    pub bytes_written: u64,
    pub findings_count: usize,
}

#[tauri::command]
pub async fn scanner_report_write(
    args: ScannerReportArgs,
    state: AppStateRef<'_>,
) -> Result<ScannerReportResult, String> {
    let h = state.require().map_err(fail)?;
    let (hist, project_name, project_root) = {
        let p = h.project.read();
        (
            p.history.clone(),
            p.config.name.clone(),
            p.root.to_string_lossy().into_owned(),
        )
    };

    // Pull every finding, then filter down to the requested subset
    // in memory. The alternative — a per-id SQL query — would be
    // less code to write but would issue N queries for N selected
    // issues; the full list is already cheap (findings table is
    // small on anything short of a 10 000-issue engagement).
    let all = hist.list_findings().map_err(fail)?;
    let filtered: Vec<burpfree_storage::history::StoredFinding> =
        match args.finding_ids.as_ref() {
            Some(ids) if !ids.is_empty() => {
                let want: std::collections::HashSet<i64> = ids.iter().copied().collect();
                all.into_iter().filter(|f| want.contains(&f.id.0)).collect()
            }
            _ => all,
        };
    let findings_count = filtered.len();

    let mut ctx = burpfree_report::ReportContext::new(project_name, filtered);
    ctx.project_root = Some(project_root);

    // Validate the format BEFORE touching disk so a typo doesn't
    // leave an empty file behind.
    let format = args.format.to_ascii_lowercase();
    if !matches!(
        format.as_str(),
        "html" | "json" | "sarif" | "markdown" | "md" | "csv"
    ) {
        return Err(format!(
            "unknown report format: {} (use html, json, sarif, markdown, or csv)",
            args.format
        ));
    }

    let path = std::path::PathBuf::from(&args.path);
    let file = std::fs::File::create(&path)
        .map_err(|e| format!("create {}: {}", path.display(), e))?;
    let mut writer = std::io::BufWriter::new(file);
    match format.as_str() {
        "html" => burpfree_report::write_html(&ctx, &mut writer).map_err(fail)?,
        "json" => burpfree_report::write_json(&ctx, &mut writer).map_err(fail)?,
        "sarif" => burpfree_report::write_sarif(&ctx, &mut writer).map_err(fail)?,
        "markdown" | "md" => {
            burpfree_report::write_markdown(&ctx, &mut writer).map_err(fail)?
        }
        "csv" => burpfree_report::write_csv(&ctx, &mut writer).map_err(fail)?,
        _ => unreachable!("format validated above"),
    }
    // Flush the BufWriter so the file size we return reflects the
    // actual bytes on disk, not just what passed through the stream.
    use std::io::Write;
    writer.flush().map_err(fail)?;
    let bytes_written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    tracing::info!(
        path = %path.display(),
        format = %format,
        findings = findings_count,
        bytes = bytes_written,
        "scanner report written"
    );

    Ok(ScannerReportResult {
        path: path.to_string_lossy().into_owned(),
        format,
        bytes_written,
        findings_count,
    })
}

#[derive(Debug, Deserialize)]
pub struct FindingStatusArgs {
    pub id: i64,
    pub status: String,
    pub note: Option<String>,
}

#[tauri::command]
pub async fn finding_set_status(args: FindingStatusArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.update_finding_status(TrafficId::from(args.id), &args.status, args.note.as_deref())
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct FindingVerificationArgs {
    pub id: i64,
    pub verification: String,
}

#[tauri::command]
pub async fn finding_set_verification(
    args: FindingVerificationArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.update_finding_verification(TrafficId::from(args.id), &args.verification)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct FindingTagsArgs {
    pub id: i64,
    pub tags: Vec<String>,
}

#[tauri::command]
pub async fn finding_set_tags(args: FindingTagsArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.update_finding_tags(TrafficId::from(args.id), &args.tags)
        .map_err(fail)
}

/// R344: Operator-side note editor. The existing `finding_set_status`
/// RPC optionally carries a note alongside a status change, but
/// operators often want to annotate without moving the finding
/// through the triage lifecycle (e.g. adding "need to re-run after
/// deploy X" to a confirmed finding). This dedicated setter lets
/// the Scanner detail pane expose an inline note editor without
/// polluting the status axis.
#[derive(Debug, Deserialize)]
pub struct FindingNoteArgs {
    pub id: i64,
    pub note: String,
}

#[tauri::command]
pub async fn finding_set_note(args: FindingNoteArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.update_finding_note(TrafficId::from(args.id), &args.note)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct FindingSeverityArgs {
    pub id: i64,
    pub severity: String,
}

/// R164: Operator-driven severity override. Validates `severity`
/// against the five canonical Burp levels (critical/high/medium/low/
/// info) before touching storage so a typo in the frontend doesn't
/// land as a free-form string that breaks downstream filtering.
#[tauri::command]
pub async fn finding_set_severity(
    args: FindingSeverityArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let sev = args.severity.to_ascii_lowercase();
    if !matches!(sev.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        return Err(format!(
            "invalid severity: {} (use critical, high, medium, low, or info)",
            args.severity
        ));
    }
    let hist = h.project.read().history.clone();
    hist.update_finding_severity(TrafficId::from(args.id), &sev)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct FindingsDeleteManyArgs {
    pub ids: Vec<i64>,
}

/// Bulk-delete findings by id. Mirrors `history_delete`'s bulk shape:
/// single `DELETE FROM findings WHERE id IN(?,?,…)` statement under
/// the hood. Returns the count actually removed so the UI can show
/// `Deleted N findings`.
#[tauri::command]
pub async fn findings_delete_many(
    args: FindingsDeleteManyArgs,
    state: AppStateRef<'_>,
) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let tids: Vec<TrafficId> = args.ids.into_iter().map(TrafficId::from).collect();
    hist.delete_findings_many(&tids).map_err(fail)
}

#[tauri::command]
pub async fn finding_delete(id: i64, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.delete_finding(TrafficId::from(id)).map_err(fail)
}

// ---- Upstream + settings -------------------------------------------------

// ---- Browser launch -----------------------------------------------------

#[derive(Debug, Serialize)]
pub struct BrowserLaunchResult {
    pub browser: String,
    pub pid: Option<u32>,
    pub command: String,
    pub note: Option<String>,
}

/// Spawn the system's preferred browser with the proxy pre-configured.
/// We try Chromium-flavoured browsers first (they all accept
/// `--proxy-server`), then fall back to Firefox (needs a per-call
/// profile). If no supported browser is found, return a note telling
/// the user how to configure one manually.
#[tauri::command]
pub async fn browser_launch(url: Option<String>, state: AppStateRef<'_>) -> Result<BrowserLaunchResult, String> {
    let h = state.require().map_err(fail)?;
    let proxy_addr = {
        let guard = h.proxy.read();
        guard
            .as_ref()
            .and_then(|p| p.listen_addrs.first().cloned())
            .map(|a| a.to_string())
            .unwrap_or_else(|| h.project.read().config.listeners.first().map(|l| l.address.clone()).unwrap_or_else(|| "127.0.0.1:8080".into()))
    };
    let target_url = url.unwrap_or_else(|| "about:blank".into());

    let candidates: Vec<(&str, &str)> = if cfg!(target_os = "windows") {
        vec![
            ("Microsoft Edge", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            ("Microsoft Edge", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            ("Google Chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ("Google Chrome", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            ("Brave", r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            ("Microsoft Edge", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            ("Brave", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        ]
    } else {
        vec![
            ("Chromium", "/usr/bin/chromium"),
            ("Google Chrome", "/usr/bin/google-chrome"),
            ("Microsoft Edge", "/usr/bin/microsoft-edge"),
            ("Brave", "/usr/bin/brave-browser"),
        ]
    };
    let chosen = candidates.into_iter().find(|(_, p)| std::path::Path::new(p).exists());
    if let Some((name, path)) = chosen {
        // Use an isolated per-launch profile dir so BurpFree's proxy
        // settings don't leak into the user's main browser profile.
        let profile_dir = std::env::temp_dir().join(format!(
            "burpfree-browser-{}",
            burpfree_core::ids::random_token(6)
        ));
        let _ = std::fs::create_dir_all(&profile_dir);
        let args = vec![
            format!("--proxy-server=http://{proxy_addr}"),
            format!("--user-data-dir={}", profile_dir.display()),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-features=HttpsFirstBalancedMode".into(),
            target_url.clone(),
        ];
        let display_cmd = format!("{} {}", path, args.join(" "));
        let child = std::process::Command::new(path).args(&args).spawn();
        match child {
            Ok(c) => Ok(BrowserLaunchResult {
                browser: name.to_string(),
                pid: Some(c.id()),
                command: display_cmd,
                note: Some(format!("Chromium profile dir: {}", profile_dir.display())),
            }),
            Err(e) => Err(format!("failed to launch {name}: {e}")),
        }
    } else {
        Ok(BrowserLaunchResult {
            browser: "none".into(),
            pid: None,
            command: String::new(),
            note: Some(format!(
                "No supported browser found. Point any browser's HTTP proxy at {proxy_addr} and import the project's CA from Settings → Root CA → Export CA."
            )),
        })
    }
}

// ---- Organizer ---------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OrganizerAddArgs {
    pub transaction_id: Option<i64>,
    pub title: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub collection_id: Option<i64>,
}

#[tauri::command]
pub async fn organizer_add(args: OrganizerAddArgs, state: AppStateRef<'_>) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let now = burpfree_core::traffic::now_ms();
    let id = TrafficId::new();
    let item = burpfree_storage::OrganizerItem {
        id,
        transaction_id: args.transaction_id.map(TrafficId::from),
        title: args.title,
        note: args.note,
        tags: args.tags,
        status: "open".into(),
        ts_ms: now,
        updated_at_ms: now,
        collection_id: args.collection_id,
    };
    hist.organizer_add(&item).map_err(fail)?;
    Ok(id.as_i64())
}

#[derive(Debug, Deserialize)]
pub struct OrganizerListArgs {
    /// None → every item regardless of collection
    /// Some(null) → the Inbox (collection_id IS NULL)
    /// Some(id)   → that collection
    #[serde(default)]
    pub collection_id: Option<Option<i64>>,
}

#[tauri::command]
pub async fn organizer_list(
    args: Option<OrganizerListArgs>,
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_storage::OrganizerItem>, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let filter = args.and_then(|a| a.collection_id);
    hist.organizer_list_in_collection(filter).map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct OrganizerUpdateArgs {
    pub id: i64,
    pub note: String,
    pub tags: Vec<String>,
    pub status: String,
}

#[tauri::command]
pub async fn organizer_update(args: OrganizerUpdateArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.organizer_update_note(TrafficId::from(args.id), &args.note, &args.tags, &args.status)
        .map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct OrganizerMoveArgs {
    pub id: i64,
    pub collection_id: Option<i64>,
}

#[tauri::command]
pub async fn organizer_move(args: OrganizerMoveArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.organizer_move_to_collection(TrafficId::from(args.id), args.collection_id)
        .map_err(fail)
}

#[tauri::command]
pub async fn organizer_delete(id: i64, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.organizer_delete(TrafficId::from(id)).map_err(fail)
}

#[derive(Debug, Serialize)]
pub struct CollectionsView {
    pub collections: Vec<burpfree_storage::OrganizerCollection>,
    pub inbox_count: i64,
}

#[tauri::command]
pub async fn collections_list(state: AppStateRef<'_>) -> Result<CollectionsView, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    let collections = hist.collections_list().map_err(fail)?;
    let inbox_count = hist.collection_inbox_count().map_err(fail)?;
    Ok(CollectionsView { collections, inbox_count })
}

#[tauri::command]
pub async fn collection_create(name: String, state: AppStateRef<'_>) -> Result<i64, String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.collection_create(&name).map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct CollectionRenameArgs {
    pub id: i64,
    pub name: String,
}

#[tauri::command]
pub async fn collection_rename(
    args: CollectionRenameArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.collection_rename(args.id, &args.name).map_err(fail)
}

#[tauri::command]
pub async fn collection_delete(id: i64, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let hist = h.project.read().history.clone();
    hist.collection_delete(id).map_err(fail)
}

// ---- Logger -------------------------------------------------------------

#[tauri::command]
pub async fn logger_recent(
    limit: Option<usize>,
    state: AppStateRef<'_>,
) -> Result<Vec<crate::state::LoggedEvent>, String> {
    let buf = state.logger.read();
    Ok(buf.last_n(limit.unwrap_or(500)))
}

#[tauri::command]
pub async fn logger_drain_since(
    cursor: u64,
    state: AppStateRef<'_>,
) -> Result<Vec<crate::state::LoggedEvent>, String> {
    let buf = state.logger.read();
    Ok(buf.drain_since(cursor))
}

#[tauri::command]
pub async fn logger_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let mut buf = state.logger.write();
    buf.items.clear();
    Ok(())
}

// ---- Extensions ---------------------------------------------------------

#[tauri::command]
pub async fn extensions_list(state: AppStateRef<'_>) -> Result<Vec<burpfree_extensions::Manifest>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.extensions.list())
}

#[derive(Debug, Deserialize)]
pub struct ExtensionToggleArgs {
    pub name: String,
    pub enabled: bool,
}

#[tauri::command]
pub async fn extensions_set_enabled(args: ExtensionToggleArgs, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    if h.extensions.set_enabled(&args.name, args.enabled) {
        Ok(())
    } else {
        Err(format!("extension `{}` not found", args.name))
    }
}

/// One row in the BApp-Store style catalog. Mirrors
/// `burpfree_extensions::CatalogEntry` and tags each row with a live
/// `installed` flag computed against the registry.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntryView {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub permissions: Vec<burpfree_extensions::Permission>,
    pub source_url: String,
    pub category: String,
    pub available: bool,
    pub installed: bool,
}

#[tauri::command]
pub async fn extensions_catalog_list(state: AppStateRef<'_>) -> Result<Vec<CatalogEntryView>, String> {
    let h = state.require().map_err(fail)?;
    let installed: std::collections::HashSet<String> =
        h.extensions.list().into_iter().map(|m| m.name).collect();
    let catalog = burpfree_extensions::catalog();
    Ok(catalog
        .into_iter()
        .map(|c| CatalogEntryView {
            installed: installed.contains(&c.name),
            name: c.name,
            version: c.version,
            author: c.author,
            description: c.description,
            permissions: c.permissions,
            source_url: c.source_url,
            category: c.category,
            available: c.available,
        })
        .collect())
}

#[tauri::command]
pub async fn extensions_install(name: String, state: AppStateRef<'_>) -> Result<Vec<CatalogEntryView>, String> {
    let h = state.require().map_err(fail)?;
    let root = { h.project.read().root.clone() };
    let ok = burpfree_extensions::install_builtin(&h.extensions, &root, &name).map_err(fail)?;
    if !ok {
        return Err(format!(
            "extension `{name}` is not available in the built-in catalog"
        ));
    }
    extensions_catalog_list(state).await
}

#[tauri::command]
pub async fn extensions_uninstall(name: String, state: AppStateRef<'_>) -> Result<Vec<CatalogEntryView>, String> {
    let h = state.require().map_err(fail)?;
    let root = { h.project.read().root.clone() };
    burpfree_extensions::uninstall_builtin(&h.extensions, &root, &name).map_err(fail)?;
    extensions_catalog_list(state).await
}

#[tauri::command]
pub async fn upstream_set(upstream: Upstream, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    *h.upstream.write() = upstream.clone();
    let mut p = h.project.write();
    p.config.upstream = burpfree_storage::project::UpstreamConfig {
        url: upstream.url,
        bypass: p.config.upstream.bypass.clone(),
        username: upstream.username,
        password: upstream.password,
    };
    p.save_config().map_err(fail)?;
    Ok(())
}

#[tauri::command]
pub async fn settings_get(state: AppStateRef<'_>) -> Result<burpfree_storage::project::ProjectConfig, String> {
    let h = state.require().map_err(fail)?;
    let cfg = h.project.read().config.clone();
    Ok(cfg)
}

#[tauri::command]
pub async fn settings_save(config: burpfree_storage::project::ProjectConfig, state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    // Snapshot the toggle-backed values BEFORE taking the project
    // write-lock so we can push them to their AtomicBool mirrors
    // without holding both locks across the store.
    let record_oos = config.record_out_of_scope;
    let live_scan = config.live_passive_scan;
    {
        let mut p = h.project.write();
        p.config = config;
        p.save_config().map_err(fail)?;
    }
    // Sync hot-path atomics so the proxy gate + live scan dispatcher
    // see the new values on the next request — no proxy restart.
    state
        .record_out_of_scope
        .store(record_oos, std::sync::atomic::Ordering::Relaxed);
    state
        .live_passive_scan
        .store(live_scan, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

// ---- Suppress out-of-scope items ----------------------------------------
//
// Thin convenience pair wrapping `ProjectConfig::record_out_of_scope`
// so the HistoryPanel can read + toggle the setting without pulling
// the whole project config object. The underlying field is the SAME
// atomic/config as the SettingsPanel "Record out-of-scope" checkbox —
// writes here update both. "Suppress" is the Burp-facing framing; the
// backend stores `record_out_of_scope` (the inverse) so the default
// (true = record everything) matches Burp's shipping behavior.

/// Return `true` when out-of-scope items are being suppressed from
/// history / sitemap / events. Flipped reading of
/// `AppState::record_out_of_scope` for Burp-matching naming.
#[tauri::command]
pub async fn history_suppress_oos_get(state: AppStateRef<'_>) -> Result<bool, String> {
    Ok(!state
        .record_out_of_scope
        .load(std::sync::atomic::Ordering::Relaxed))
}

/// Flip the suppress toggle live. Writes `!suppress` to
/// `ProjectConfig::record_out_of_scope`, persists the project
/// config, and stores the AtomicBool so the proxy gate picks up
/// the new value on the next request — no restart needed. Used by
/// the HistoryPanel pill click for one-click toggle without
/// opening Settings.
#[tauri::command]
pub async fn history_suppress_oos_set(
    suppress: bool,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let record = !suppress;
    {
        let mut p = h.project.write();
        p.config.record_out_of_scope = record;
        p.save_config().map_err(fail)?;
    }
    state
        .record_out_of_scope
        .store(record, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

// ---- HTTP history column visibility ------------------------------------
//
// Thin wrapper around `ProjectConfig::history_hidden_columns` so the
// HistoryPanel's Columns-dropdown can read + write without pulling
// the whole project config object. Known column ids match the
// SortKey union on the frontend: `highlight`, `id`, `method`,
// `status`, `host`, `path`, `size`, `time`, `comment`. The backend
// stays policy-free — it stores whatever strings the UI sends so
// future columns don't require a cmd signature change.

/// Current list of hidden column ids. Empty = everything visible.
#[tauri::command]
pub async fn history_columns_get(state: AppStateRef<'_>) -> Result<Vec<String>, String> {
    let h = state.require().map_err(fail)?;
    let hidden = h.project.read().config.history_hidden_columns.clone();
    Ok(hidden)
}

// ---- Comparer item collection -------------------------------------------
//
// Mirror of Burp's Comparer "Items" list. Operators stash snippets
// (whole requests, response bodies, extracted tokens, ad-hoc text)
// into the project so they survive restarts and can be compared
// pairwise. The storage layer keeps entries as opaque JSON so this
// crate owns the schema without pulling in a frontend-shaped type;
// the UI treats each entry as `{ id, label, text, created_at_ms }`
// and generates ids client-side.

#[derive(Debug, Serialize, Deserialize)]
pub struct ComparerItem {
    pub id: String,
    pub label: String,
    pub text: String,
    pub created_at_ms: i64,
}

/// Materialise the stored items into typed form, dropping any
/// malformed JSON entries silently — matches the recovery stance
/// of the other opaque-JSON collections (match/replace, intercept,
/// platform_auth).
#[tauri::command]
pub async fn comparer_items_list(state: AppStateRef<'_>) -> Result<Vec<ComparerItem>, String> {
    let h = state.require().map_err(fail)?;
    let raw = h.project.read().config.comparer_items.clone();
    let items: Vec<ComparerItem> = raw
        .into_iter()
        .filter_map(|v| serde_json::from_value::<ComparerItem>(v).ok())
        .collect();
    Ok(items)
}

/// Append a new item. The caller is responsible for the id (the UI
/// generates one via `crypto.randomUUID()` so there's no need to
/// round-trip a backend-assigned id). Duplicates on id replace the
/// existing entry — makes the "upsert from last-sent-to-comparer"
/// UX a one-cmd operation.
#[tauri::command]
pub async fn comparer_items_add(
    item: ComparerItem,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let serialised = serde_json::to_value(&item).map_err(fail)?;
    let mut p = h.project.write();
    // Upsert by id — if an entry with the same id exists, overwrite
    // its slot in place so ordering doesn't flip; otherwise append.
    let existing = p.config.comparer_items.iter().position(|v| {
        v.get("id")
            .and_then(|x| x.as_str())
            .map(|s| s == item.id)
            .unwrap_or(false)
    });
    match existing {
        Some(i) => p.config.comparer_items[i] = serialised,
        None => p.config.comparer_items.push(serialised),
    }
    p.save_config().map_err(fail)
}

/// Remove by id. Returns `true` iff an entry actually existed —
/// lets the UI skip a refresh on a stale click.
#[tauri::command]
pub async fn comparer_items_remove(id: String, state: AppStateRef<'_>) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    let mut p = h.project.write();
    let before = p.config.comparer_items.len();
    p.config.comparer_items.retain(|v| {
        v.get("id")
            .and_then(|x| x.as_str())
            .map(|s| s != id)
            .unwrap_or(true)
    });
    let removed = p.config.comparer_items.len() < before;
    if removed {
        p.save_config().map_err(fail)?;
    }
    Ok(removed)
}

/// Nuke the whole collection. Operators iterating on a scope
/// cleanup action get a single-cmd reset instead of walking the UI.
#[tauri::command]
pub async fn comparer_items_clear(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let mut p = h.project.write();
    p.config.comparer_items.clear();
    p.save_config().map_err(fail)
}

/// Replace the hidden-column list atomically. Trims whitespace, drops
/// empty entries, dedupes — operators sometimes paste the same key
/// twice through a stray double-click; letting that bloat the config
/// just makes future reads more work.
#[tauri::command]
pub async fn history_columns_set(
    hidden: Vec<String>,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let mut seen = std::collections::HashSet::<String>::new();
    let clean: Vec<String> = hidden
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect();
    let mut p = h.project.write();
    p.config.history_hidden_columns = clean;
    p.save_config().map_err(fail)
}

// ---- Platform authentication --------------------------------------------
//
// Read / write the platform-auth credential list. Burp's "Settings
// → Network → Platform authentication" dialog maps 1:1 onto these
// two cmds. The setter writes the typed list through two surfaces
// so a UI edit propagates everywhere:
//
// 1. On-disk `ProjectConfig::platform_auth: Vec<serde_json::Value>` —
//    opaque JSON so the storage crate stays dep-free; survives a
//    restart.
// 2. Shared `AppState::platform_auth: Arc<RwLock<Vec<PlatformAuthCredential>>>` —
//    the hot path the proxy's 401-retry hook reads. Replacing the
//    Vec here means the next upstream 401 picks up the new
//    credentials without a proxy restart.

/// Snapshot the current platform-auth credential list. Returns the
/// typed proxy struct directly — the frontend doesn't need to
/// re-parse opaque JSON.
#[tauri::command]
pub async fn platform_auth_list(
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_proxy::platform_auth::PlatformAuthCredential>, String> {
    let _ = state.require().map_err(fail)?;
    // E0597-dodge: materialise the clone into a local so the
    // RwLockReadGuard temporary drops before the AppState lifetime.
    let snap = state.platform_auth.read().clone();
    Ok(snap)
}

/// Replace the entire platform-auth list atomically. Trims each
/// field, drops entries whose host-pattern is empty after trim
/// (defensive — a stray blank row would authenticate every target
/// matching the empty-pattern-as-substring), persists the typed
/// list as opaque JSON on disk via `settings_save` semantics, then
/// updates the shared Arc so the proxy picks up the new values on
/// the next request.
#[tauri::command]
pub async fn platform_auth_set(
    credentials: Vec<burpfree_proxy::platform_auth::PlatformAuthCredential>,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let clean: Vec<burpfree_proxy::platform_auth::PlatformAuthCredential> = credentials
        .into_iter()
        .map(|mut c| {
            c.host_pattern = c.host_pattern.trim().to_string();
            c.username = c.username.trim().to_string();
            // Password is NOT trimmed — leading/trailing whitespace
            // in a password is unusual but legal; trimming it would
            // silently corrupt credentials.
            c
        })
        .filter(|c| !c.host_pattern.is_empty())
        .collect();
    // Serialise once, so a parse error here (shouldn't happen since
    // we just typed-constructed the Vec) surfaces before we touch
    // the hot-path Arc.
    let opaque: Vec<serde_json::Value> = clean
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
        .collect();
    {
        let mut p = h.project.write();
        p.config.platform_auth = opaque;
        p.save_config().map_err(fail)?;
    }
    *state.platform_auth.write() = clean;
    Ok(())
}

// ---- Helpers -------------------------------------------------------------

struct ProjectSink {
    history: burpfree_storage::HistoryStore,
    blobs: Arc<burpfree_storage::BlobStore>,
    sitemap: Arc<burpfree_engines::sitemap::SiteMap>,
    /// Shared project-level cookie jar — same instance held by
    /// ProjectHandle + the autostart sink + Repeater macros, so
    /// Set-Cookie headers harvested through any surface land in the
    /// one map the CookieJarPanel reads from.
    cookie_jar: burpfree_engines::session::CookieJar,
}

impl ProjectSink {
    fn from_handle(h: &ProjectHandle) -> Self {
        let p = h.project.read();
        Self {
            history: p.history.clone(),
            blobs: p.blobs.clone(),
            sitemap: h.sitemap.clone(),
            cookie_jar: h.cookie_jar.clone(),
        }
    }
}

#[async_trait::async_trait]
impl TrafficSink for ProjectSink {
    async fn record(&self, tx: Transaction) -> anyhow::Result<()> {
        let req_blob = self.blobs.put(&tx.request.to_wire_bytes())?;
        let resp_blob = if let Some(r) = &tx.response {
            Some(self.blobs.put(&r.to_wire_bytes())?)
        } else {
            None
        };
        self.sitemap.observe(&tx);
        self.history.upsert_transaction(&tx, &req_blob, resp_blob.as_ref())?;
        if let Some(resp) = &tx.response {
            self.cookie_jar.observe_response(&tx.request, resp);
        }
        Ok(())
    }
}

fn rebuild_transaction(
    row: &StoredSummary,
    req_bytes: &[u8],
    resp_bytes: Option<&[u8]>,
) -> anyhow::Result<Transaction> {
    let mut req = Request::new(
        &row.method,
        &format!("{}://{}:{}{}", row.scheme, row.host, row.port, row.path),
    )?;
    req.id = row.id;
    req.headers = burpfree_core::headers::Headers::parse_block(header_block(req_bytes));
    req.body = body_part(req_bytes).to_vec();
    let mut t = Transaction::new(req);
    t.in_scope = row.in_scope;
    if let Some(bytes) = resp_bytes {
        let mut r = burpfree_core::traffic::Response::new(row.status.unwrap_or(0));
        r.headers = burpfree_core::headers::Headers::parse_block(header_block(bytes));
        r.body = body_part(bytes).to_vec();
        t.response = Some(r);
    }
    Ok(t)
}

fn header_block(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        if let Some(nl) = bytes[..idx].iter().position(|&b| b == b'\n') {
            &bytes[nl + 1..idx]
        } else {
            &bytes[..idx]
        }
    } else {
        &[]
    }
}

fn body_part(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        &bytes[idx + 4..]
    } else {
        &[]
    }
}

pub(crate) fn to_stored(f: &Finding) -> StoredFinding {
    let now = burpfree_core::traffic::now_ms();
    StoredFinding {
        id: f.id,
        ts_ms: now,
        transaction_id: f.transaction_id,
        detector: f.detector.clone(),
        title: f.title.clone(),
        description: f.description.clone(),
        severity: f.severity.as_label().into(),
        confidence: f.confidence.as_label().into(),
        evidence: f.evidence.clone(),
        remediation: f.remediation.clone(),
        fingerprint: f.fingerprint(),
        status: "new".into(),
        verification: "unverified".into(),
        tags: Vec::new(),
        references: f.references.clone(),
        assignee: None,
        note: String::new(),
        insertion_point: f.insertion_point.clone(),
        updated_at_ms: now,
        observation_count: 1,
    }
}

// ---- Bundle (import/export) ---------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundleExportInput {
    #[serde(default)]
    pub out: PathBuf,
    #[serde(default)]
    pub include_ca_key: bool,
    #[serde(default)]
    pub include_extensions: Option<bool>,
    #[serde(default)]
    pub include_blobs: Option<bool>,
    #[serde(default)]
    pub compress: Option<bool>,
}

#[tauri::command]
pub async fn bundle_export(
    opts: BundleExportInput,
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::BundleSummary, String> {
    let h = state.require().map_err(fail)?;
    let project_root = { h.project.read().root.clone() };
    let bundle_opts = burpfree_storage::BundleOptions {
        compress: opts.compress.unwrap_or(true),
        include_ca_key: opts.include_ca_key,
        include_extensions: opts.include_extensions.unwrap_or(true),
        include_blobs: opts.include_blobs.unwrap_or(true),
    };
    burpfree_storage::export_project(&project_root, &opts.out, bundle_opts).map_err(fail)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleImportInput {
    pub file: PathBuf,
    pub dest: PathBuf,
    /// If true, after extracting switch the running session to the new project.
    #[serde(default = "default_true")]
    pub open_after: bool,
}

fn default_true() -> bool { true }

#[tauri::command]
pub async fn bundle_import(
    opts: BundleImportInput,
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::BundleManifest, String> {
    let manifest = burpfree_storage::import_project(&opts.file, &opts.dest).map_err(fail)?;
    if opts.open_after {
        state.load_project(opts.dest.clone()).map_err(fail)?;
    }
    Ok(manifest)
}

// ---- HAR import / export ------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarImportInput {
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarExportInput {
    pub out: PathBuf,
    #[serde(default)]
    pub filter: Option<burpfree_storage::HistoryFilter>,
}

#[tauri::command]
pub async fn har_import(
    opts: HarImportInput,
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::HarImportSummary, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    burpfree_storage::import_har(&opts.file, &hist, &blobs).map_err(fail)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarExportIdsInput {
    /// Target file on disk. Overwritten if present.
    pub out: PathBuf,
    /// Explicit transaction ids to export. Order is preserved in the
    /// output so a bulk selection reads left-to-right.
    pub ids: Vec<i64>,
}

/// Export a specific set of HTTP history rows as HAR 1.2.
/// Backs the HistoryPanel's "Export selected as HAR" bulk action
/// so operators can round-trip a scoped selection (e.g. the five
/// 500s they're triaging) without exporting the whole history.
/// Mirrors `har_export` but takes explicit ids instead of a
/// generic filter.
#[tauri::command]
pub async fn har_export_ids(
    opts: HarExportIdsInput,
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::HarExportSummary, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let typed: Vec<TrafficId> = opts.ids.iter().map(|i| TrafficId::from(*i)).collect();
    burpfree_storage::export_har_by_ids(&opts.out, &hist, &blobs, &typed).map_err(fail)
}

#[tauri::command]
pub async fn har_export(
    opts: HarExportInput,
    state: AppStateRef<'_>,
) -> Result<burpfree_storage::HarExportSummary, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    burpfree_storage::export_har(&opts.out, &hist, &blobs, opts.filter).map_err(fail)
}

// ---- WebSocket replay --------------------------------------------------

#[derive(Debug, Serialize)]
pub struct WsMessageView {
    pub id: i64,
    pub session_id: i64,
    pub direction: String,
    pub opcode: u8,
    pub opcode_label: String,
    pub size: u64,
    pub ts_ms: i64,
    /// Payload as UTF-8 text (lossy) when the opcode is Text or a small
    /// Binary payload decodes cleanly. Otherwise None.
    pub text: Option<String>,
    /// Base64 of raw payload bytes. Present for Binary / unknown payloads
    /// and small enough text so the frontend can render both views.
    pub base64: Option<String>,
    pub truncated: bool,
}

const WS_PREVIEW_BYTES: usize = 16 * 1024;

// ---- WebSocket frame interceptor ---------------------------------------

#[tauri::command]
pub async fn ws_intercept_status(state: AppStateRef<'_>) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ws_interceptor.is_enabled())
}

#[tauri::command]
pub async fn ws_intercept_set_enabled(
    enabled: bool,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    h.ws_interceptor.set_enabled(enabled);
    Ok(h.ws_interceptor.is_enabled())
}

#[tauri::command]
pub async fn ws_intercept_pending(
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_proxy::PendingFrame>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ws_interceptor.list_pending())
}

#[derive(Debug, Deserialize)]
pub struct WsInterceptReleaseArgs {
    pub id: i64,
    /// Optional edited payload — `text` is UTF-8, `base64` is raw bytes.
    /// If both are `None`, the original queued payload is sent.
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub base64: Option<String>,
}

#[tauri::command]
pub async fn ws_intercept_release(
    args: WsInterceptReleaseArgs,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    let payload: Option<Vec<u8>> = if let Some(b64) = args.base64 {
        Some(base64_decode(&b64).map_err(fail)?)
    } else {
        args.text.map(|t| t.into_bytes())
    };
    Ok(h.ws_interceptor.release(args.id, payload))
}

#[tauri::command]
pub async fn ws_intercept_drop(id: i64, state: AppStateRef<'_>) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ws_interceptor.drop_frame(id))
}

#[tauri::command]
pub async fn ws_intercept_release_all(state: AppStateRef<'_>) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ws_interceptor.release_all())
}

/// Flush every queued WebSocket frame by resolving each submit call
/// with `Verdict::Drop`. Mirrors Burp's "Drop all" button for the
/// WebSockets intercept queue.
#[tauri::command]
pub async fn ws_intercept_drop_all(state: AppStateRef<'_>) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.ws_interceptor.drop_all())
}

#[tauri::command]
pub async fn ws_sessions_list(
    limit: Option<i64>,
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_storage::StoredWsSession>, String> {
    let h = state.require().map_err(fail)?;
    let hist = { h.project.read().history.clone() };
    hist.list_ws_sessions(limit).map_err(fail)
}

#[tauri::command]
pub async fn ws_session_get(
    id: i64,
    state: AppStateRef<'_>,
) -> Result<Option<burpfree_storage::StoredWsSession>, String> {
    let h = state.require().map_err(fail)?;
    let hist = { h.project.read().history.clone() };
    hist.get_ws_session(TrafficId::from(id)).map_err(fail)
}

#[tauri::command]
pub async fn ws_messages_list(
    session_id: i64,
    state: AppStateRef<'_>,
) -> Result<Vec<WsMessageView>, String> {
    let h = state.require().map_err(fail)?;
    let (hist, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let rows = hist
        .list_ws_messages(TrafficId::from(session_id))
        .map_err(fail)?;
    let mut out = Vec::with_capacity(rows.len());
    for m in rows {
        let payload = blobs
            .get_by_sha(&m.blob)
            .map_err(fail)?
            .unwrap_or_default();
        let (preview, truncated) = if payload.len() > WS_PREVIEW_BYTES {
            (&payload[..WS_PREVIEW_BYTES], true)
        } else {
            (payload.as_slice(), false)
        };
        let opcode_label = opcode_label(m.opcode);
        let is_text = opcode_label == "text";
        let text = if is_text {
            Some(String::from_utf8_lossy(preview).to_string())
        } else if preview.iter().all(|b| *b == b'\n' || *b == b'\r' || *b == b'\t' || (*b >= 0x20 && *b < 0x7f)) {
            Some(String::from_utf8_lossy(preview).to_string())
        } else {
            None
        };
        let base64 = Some(base64_encode(preview));
        out.push(WsMessageView {
            id: m.id.as_i64(),
            session_id: m.session_id.as_i64(),
            direction: m.direction,
            opcode: m.opcode,
            opcode_label: opcode_label.into(),
            size: m.size,
            ts_ms: m.ts_ms,
            text,
            base64,
            truncated,
        });
    }
    Ok(out)
}

fn opcode_label(op: u8) -> &'static str {
    match op {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xa => "pong",
        _ => "unknown",
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s.as_bytes())?)
}

#[derive(Debug, Deserialize)]
pub struct WsReplayInput {
    pub url: String,
    pub frames: Vec<WsReplayFrame>,
    /// Optional additional request headers to send during the handshake.
    #[serde(default)]
    pub headers: Vec<[String; 2]>,
    /// How long to wait after sending the last frame for inbound data.
    #[serde(default = "default_wait_ms")]
    pub drain_ms: u64,
}

fn default_wait_ms() -> u64 { 2000 }

#[derive(Debug, Deserialize)]
pub struct WsReplayFrame {
    /// "text" | "binary" | "ping" | "close". Default "text".
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Payload as UTF-8 text. Mutually exclusive with `base64`.
    #[serde(default)]
    pub text: Option<String>,
    /// Payload as base64 bytes. Takes precedence over `text`.
    #[serde(default)]
    pub base64: Option<String>,
    /// Milliseconds to wait before sending this frame.
    #[serde(default)]
    pub delay_ms: u64,
}

fn default_kind() -> String { "text".into() }

#[derive(Debug, Serialize)]
pub struct WsReplayResult {
    pub session_id: i64,
    pub sent: u32,
    pub received: u32,
    pub closed: bool,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub error: Option<String>,
}

/// Open a fresh WebSocket to `url`, send the supplied frames in order,
/// drain inbound frames for `drain_ms`, then close. The whole exchange
/// is recorded as a new session + messages in `ws_sessions` /
/// `ws_messages`, exactly like the proxy's own capture path.
///
/// This connects **directly** to the target — it does not loop through
/// the local proxy. That keeps the TLS story simple (no cert install
/// required) and matches how Repeater works in the HTTP case.
#[tauri::command]
pub async fn ws_replay(
    input: WsReplayInput,
    state: AppStateRef<'_>,
) -> Result<WsReplayResult, String> {
    use burpfree_core::ids::TrafficId as Tid;
    use burpfree_core::traffic::{
        now_ms, Request as CoreReq, Transaction as CoreTx, WebSocketMessage, WebSocketSession,
        WsDirection, WsOpcode,
    };
    use futures_util::{SinkExt, StreamExt};
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::tungstenite::protocol::Message as WsMsg;

    let h = state.require().map_err(fail)?;
    let (history, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };

    // Build a request object for the fake handshake record.
    let mut req = CoreReq::new("GET", &input.url).map_err(fail)?;
    for pair in &input.headers {
        req.headers.add(pair[0].clone(), pair[1].clone());
    }
    req.headers.add("Upgrade", "websocket");
    req.headers.add("Connection", "Upgrade");
    let handshake_tx = CoreTx::new(req);
    let req_blob = blobs.put(&handshake_tx.request.to_wire_bytes()).map_err(fail)?;
    history.upsert_transaction(&handshake_tx, &req_blob, None).map_err(fail)?;

    let session_id = Tid::new();
    let mut session = WebSocketSession::new(handshake_tx);
    session.id = session_id;
    history.insert_ws_session(&session).map_err(fail)?;

    // Build the request with any custom headers so the server honours them.
    let mut req_builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(&input.url)
        .method("GET");
    for pair in &input.headers {
        req_builder = req_builder.header(&pair[0], &pair[1]);
    }
    // tungstenite will fill the WebSocket-specific headers for us if the
    // request is well-formed; but it demands a Host header too.
    let request = match req_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            history
                .close_ws_session(session_id, now_ms(), Some(4000), Some(format!("bad request: {e}")))
                .map_err(fail)?;
            return Ok(WsReplayResult {
                session_id: session_id.as_i64(),
                sent: 0,
                received: 0,
                closed: true,
                close_code: Some(4000),
                close_reason: Some(format!("bad request: {e}")),
                error: Some(format!("{e}")),
            });
        }
    };

    let connect = tokio_tungstenite::connect_async(request);
    let (mut socket, _resp) = match timeout(Duration::from_secs(15), connect).await {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            history
                .close_ws_session(session_id, now_ms(), Some(4001), Some(format!("{e}")))
                .map_err(fail)?;
            return Ok(WsReplayResult {
                session_id: session_id.as_i64(),
                sent: 0,
                received: 0,
                closed: true,
                close_code: Some(4001),
                close_reason: Some(format!("{e}")),
                error: Some(format!("{e}")),
            });
        }
        Err(_) => {
            history
                .close_ws_session(session_id, now_ms(), Some(4002), Some("connect timeout".into()))
                .map_err(fail)?;
            return Ok(WsReplayResult {
                session_id: session_id.as_i64(),
                sent: 0,
                received: 0,
                closed: true,
                close_code: Some(4002),
                close_reason: Some("connect timeout".into()),
                error: Some("connect timeout".into()),
            });
        }
    };

    let mut sent: u32 = 0;
    let mut received: u32 = 0;
    let mut close_code: Option<u16> = None;
    let mut close_reason: Option<String> = None;
    let mut error: Option<String> = None;

    let interceptor = h.ws_interceptor.clone();
    let mut dropped: u32 = 0;

    for f in &input.frames {
        if f.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(f.delay_ms)).await;
        }
        let payload: Vec<u8> = if let Some(b64) = &f.base64 {
            match base64_decode(b64) {
                Ok(v) => v,
                Err(e) => {
                    error = Some(format!("bad base64 frame: {e}"));
                    break;
                }
            }
        } else if let Some(t) = &f.text {
            t.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        let opcode = match f.kind.as_str() {
            "binary" => WsOpcode::Binary,
            "ping" => WsOpcode::Ping,
            "pong" => WsOpcode::Pong,
            "close" => WsOpcode::Close,
            _ => WsOpcode::Text,
        };

        // Consult the WebSocket interceptor. If it's disabled this is
        // a no-op synchronous Release(original). If enabled, blocks
        // until the UI releases / modifies / drops the frame.
        let effective_payload = match interceptor
            .clone()
            .submit(session_id, WsDirection::Outbound, opcode, payload.clone())
            .await
        {
            burpfree_proxy::Verdict::Release(bytes) => bytes,
            burpfree_proxy::Verdict::Drop => {
                dropped += 1;
                continue;
            }
        };

        let ws_msg = match opcode {
            WsOpcode::Binary => WsMsg::Binary(effective_payload.clone()),
            WsOpcode::Ping => WsMsg::Ping(effective_payload.clone()),
            WsOpcode::Pong => WsMsg::Pong(effective_payload.clone()),
            WsOpcode::Close => WsMsg::Close(None),
            _ => WsMsg::Text(String::from_utf8_lossy(&effective_payload).to_string()),
        };
        if let Err(e) = socket.send(ws_msg).await {
            error = Some(format!("send: {e}"));
            break;
        }
        let logged = WebSocketMessage::new(session_id, WsDirection::Outbound, opcode, effective_payload.clone());
        let blob = blobs.put(&effective_payload).map_err(fail)?;
        history.insert_ws_message(&logged, &blob).map_err(fail)?;
        sent += 1;
        if matches!(opcode, WsOpcode::Close) {
            break;
        }
    }
    let _ = dropped; // reported via replay result below

    // Drain inbound frames.
    let drain = Duration::from_millis(input.drain_ms);
    let deadline = tokio::time::Instant::now() + drain;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match timeout(remaining, socket.next()).await {
            Ok(Some(Ok(msg))) => match msg {
                WsMsg::Text(t) => {
                    let payload = t.into_bytes();
                    let logged = WebSocketMessage::new(session_id, WsDirection::Inbound, WsOpcode::Text, payload.clone());
                    let blob = blobs.put(&payload).map_err(fail)?;
                    history.insert_ws_message(&logged, &blob).map_err(fail)?;
                    received += 1;
                }
                WsMsg::Binary(b) => {
                    let logged = WebSocketMessage::new(session_id, WsDirection::Inbound, WsOpcode::Binary, b.clone());
                    let blob = blobs.put(&b).map_err(fail)?;
                    history.insert_ws_message(&logged, &blob).map_err(fail)?;
                    received += 1;
                }
                WsMsg::Ping(b) => {
                    let logged = WebSocketMessage::new(session_id, WsDirection::Inbound, WsOpcode::Ping, b.clone());
                    let blob = blobs.put(&b).map_err(fail)?;
                    history.insert_ws_message(&logged, &blob).map_err(fail)?;
                    received += 1;
                }
                WsMsg::Pong(b) => {
                    let logged = WebSocketMessage::new(session_id, WsDirection::Inbound, WsOpcode::Pong, b.clone());
                    let blob = blobs.put(&b).map_err(fail)?;
                    history.insert_ws_message(&logged, &blob).map_err(fail)?;
                    received += 1;
                }
                WsMsg::Close(frame) => {
                    close_code = frame.as_ref().map(|f| u16::from(f.code));
                    close_reason = frame.map(|f| f.reason.to_string());
                    break;
                }
                WsMsg::Frame(_) => {}
            },
            Ok(Some(Err(e))) => {
                error = Some(format!("recv: {e}"));
                break;
            }
            Ok(None) => break, // stream ended
            Err(_) => break,   // timed out
        }
    }

    // Best-effort graceful close.
    let _ = socket.close(None).await;

    history
        .close_ws_session(session_id, now_ms(), close_code, close_reason.clone())
        .map_err(fail)?;

    Ok(WsReplayResult {
        session_id: session_id.as_i64(),
        sent,
        received,
        closed: true,
        close_code,
        close_reason,
        error,
    })
}

// ---- OOB (Collaborator-style) -----------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct OobStartInput {
    /// HTTP listener bind address. Defaults to `127.0.0.1:7898`.
    #[serde(default)]
    pub http_bind: Option<String>,
    /// DNS listener bind address, or `null` to disable. Defaults to
    /// `127.0.0.1:15353` (admin needed for :53).
    #[serde(default)]
    pub dns_bind: Option<String>,
    /// Public host for payload URLs. Default: same as `http_bind`.
    #[serde(default)]
    pub public_host: Option<String>,
    #[serde(default)]
    pub capacity: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OobStatusView {
    pub running: bool,
    pub http_addr: Option<String>,
    pub dns_addr: Option<String>,
    pub public_host: Option<String>,
    pub interaction_count: usize,
}

#[tauri::command]
pub async fn oob_status(state: AppStateRef<'_>) -> Result<OobStatusView, String> {
    let h = state.require().map_err(fail)?;
    let guard = h.oob.read();
    match guard.as_ref() {
        Some(oh) => Ok(OobStatusView {
            running: true,
            http_addr: oh.http_addr().map(|a| a.to_string()),
            dns_addr: oh.dns_addr().map(|a| a.to_string()),
            public_host: Some(oh.config().public_host.clone()),
            interaction_count: oh.all().len(),
        }),
        None => Ok(OobStatusView {
            running: false,
            http_addr: None,
            dns_addr: None,
            public_host: None,
            interaction_count: 0,
        }),
    }
}

#[tauri::command]
pub async fn oob_start(
    args: OobStartInput,
    state: AppStateRef<'_>,
) -> Result<OobStatusView, String> {
    use burpfree_oob::{OobConfig, OobServer};
    use std::net::SocketAddr;
    let h = state.require().map_err(fail)?;
    if h.oob.read().is_some() {
        return oob_status(state).await;
    }
    let http_bind: SocketAddr = args
        .http_bind
        .as_deref()
        .unwrap_or("127.0.0.1:7898")
        .parse()
        .map_err(|e| format!("bad http_bind: {e}"))?;
    let dns_bind: Option<SocketAddr> = match args.dns_bind.as_deref() {
        Some(s) if !s.is_empty() => Some(s.parse().map_err(|e| format!("bad dns_bind: {e}"))?),
        Some(_) => None,
        None => Some("127.0.0.1:15353".parse().unwrap()),
    };
    let public_host = args
        .public_host
        .unwrap_or_else(|| http_bind.to_string());
    let cfg = OobConfig {
        http_bind,
        dns_bind,
        public_host,
        capacity: args.capacity.unwrap_or(10_000),
    };
    let server = OobServer::start(cfg).await.map_err(fail)?;
    *h.oob.write() = Some(server);
    oob_status(state).await
}

#[tauri::command]
pub async fn oob_stop(state: AppStateRef<'_>) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    let taken = h.oob.write().take();
    if let Some(oh) = taken {
        oh.shutdown().await;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct OobTokenView {
    pub correlation_id: String,
    pub http_url: String,
    pub dns_name: String,
}

#[tauri::command]
pub async fn oob_mint_batch(
    count: usize,
    state: AppStateRef<'_>,
) -> Result<Vec<OobTokenView>, String> {
    let h = state.require().map_err(fail)?;
    let guard = h.oob.read();
    let oh = guard
        .as_ref()
        .ok_or_else(|| "OOB server is not running".to_string())?;
    let max = count.min(1000);
    let tokens = oh.new_tokens(max);
    Ok(tokens
        .into_iter()
        .map(|t| OobTokenView {
            correlation_id: t.correlation_id,
            http_url: t.http_url,
            dns_name: t.dns_name,
        })
        .collect())
}

#[derive(Debug, Clone, Deserialize)]
pub struct OobPollBatchInput {
    pub correlation_ids: Vec<String>,
    #[serde(default = "default_poll_ms")]
    pub timeout_ms: u64,
}

fn default_poll_ms() -> u64 { 5000 }

#[derive(Debug, Clone, Serialize)]
pub struct OobBatchHit {
    pub correlation_id: String,
    pub interactions: Vec<burpfree_oob::Interaction>,
}

#[tauri::command]
pub async fn oob_poll_batch(
    args: OobPollBatchInput,
    state: AppStateRef<'_>,
) -> Result<Vec<OobBatchHit>, String> {
    let h = state.require().map_err(fail)?;
    let oh = {
        let guard = h.oob.read();
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "OOB server is not running".to_string())?
    };
    let hits = oh
        .poll_batch(
            &args.correlation_ids,
            std::time::Duration::from_millis(args.timeout_ms.min(60_000)),
        )
        .await;
    let out = args
        .correlation_ids
        .into_iter()
        .zip(hits)
        .map(|(cid, interactions)| OobBatchHit { correlation_id: cid, interactions })
        .collect();
    Ok(out)
}

#[tauri::command]
pub async fn oob_interactions_all(
    state: AppStateRef<'_>,
) -> Result<Vec<burpfree_oob::Interaction>, String> {
    let h = state.require().map_err(fail)?;
    let guard = h.oob.read();
    match guard.as_ref() {
        Some(oh) => Ok(oh.all()),
        None => Ok(Vec::new()),
    }
}

/// R132: Clear every stored OOB interaction. Burp's Collaborator has
/// a "Clear" button that empties the live interaction log mid-
/// engagement — useful when operators want a clean slate between
/// probes to avoid cross-correlating historical fallout with a
/// fresh test. Returns the count removed so the UI can echo
/// "Cleared N interactions". The id counter stays monotonic so a
/// correlation note that mentioned "interaction #42" doesn't
/// become ambiguous after a clear.
#[tauri::command]
pub async fn oob_interactions_clear(state: AppStateRef<'_>) -> Result<usize, String> {
    let h = state.require().map_err(fail)?;
    let guard = h.oob.read();
    match guard.as_ref() {
        Some(oh) => Ok(oh.clear()),
        None => Ok(0),
    }
}

// ---- Session rules / macros ------------------------------------------

use burpfree_engines::macros::{
    validate_macro, Macro, MacroRunner, SessionRule, SessionRuleRegistry,
};

#[tauri::command]
pub async fn session_macros_list(
    state: AppStateRef<'_>,
) -> Result<Vec<Macro>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.session_rules.macros())
}

#[tauri::command]
pub async fn session_rules_list(
    state: AppStateRef<'_>,
) -> Result<Vec<SessionRule>, String> {
    let h = state.require().map_err(fail)?;
    Ok(h.session_rules.rules())
}

#[tauri::command]
pub async fn session_macro_upsert(
    macro_: Macro,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    validate_macro(&macro_).map_err(fail)?;
    let h = state.require().map_err(fail)?;
    h.session_rules.upsert_macro(macro_);
    persist_session_rules(&h)?;
    Ok(())
}

#[tauri::command]
pub async fn session_macro_delete(
    id: String,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.session_rules.delete_macro(&id);
    persist_session_rules(&h)?;
    Ok(())
}

#[tauri::command]
pub async fn session_rule_upsert(
    rule: SessionRule,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.session_rules.upsert_rule(rule);
    persist_session_rules(&h)?;
    Ok(())
}

#[tauri::command]
pub async fn session_rule_delete(
    id: String,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let h = state.require().map_err(fail)?;
    h.session_rules.delete_rule(&id);
    persist_session_rules(&h)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct MacroRunReport {
    pub vars: std::collections::HashMap<String, String>,
    pub cookies: Vec<burpfree_engines::session::Cookie>,
    pub transcript: Vec<burpfree_engines::macros::TranscriptEntry>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn session_macro_run(
    id: String,
    state: AppStateRef<'_>,
) -> Result<MacroRunReport, String> {
    let h = state.require().map_err(fail)?;
    let m = h.session_rules.macro_by_id(&id).ok_or_else(|| format!("no macro: {id}"))?;
    let client = burpfree_engines::client::HttpClient::new(Default::default());
    let runner = MacroRunner::new(client);
    match runner.run(&m).await {
        Ok(ctx) => Ok(MacroRunReport {
            vars: ctx.vars,
            cookies: ctx.cookies.snapshot(),
            transcript: ctx.transcript,
            error: None,
        }),
        Err(e) => Ok(MacroRunReport {
            vars: Default::default(),
            cookies: Vec::new(),
            transcript: Vec::new(),
            error: Some(format!("{e}")),
        }),
    }
}

fn persist_session_rules(h: &ProjectHandle) -> Result<(), String> {
    let macros = h.session_rules.macros();
    let rules = h.session_rules.rules();
    let mut p = h.project.write();
    p.config.macros = macros
        .into_iter()
        .map(|m| serde_json::to_value(m).unwrap_or(serde_json::Value::Null))
        .collect();
    p.config.session_rules = rules
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    p.save_config().map_err(fail)
}

// silence dead-import warning when SessionRuleRegistry isn't referenced directly
#[allow(dead_code)]
fn _reg_type_fence(_r: SessionRuleRegistry) {}

// ---- Dashboard aggregate -----------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub project: ProjectInfo,
    pub proxy: ProxyStatsView,
    pub findings_by_severity: std::collections::BTreeMap<String, i64>,
    pub findings_total: i64,
    pub oob: OobStatusView,
    pub ws_sessions: i64,
    pub ws_messages: i64,
    pub organizer_items: i64,
    pub macros: i64,
    pub session_rules: i64,
    pub extensions: usize,
    pub custom_rules: usize,
    /// Set when a server-driven passive scan is in flight (we fire-and-forget
    /// `passive_run_now`; the dashboard subscribes to this for a progress chip).
    pub passive_scan_running: bool,
    pub passive_scan_findings_last_run: Option<usize>,
    pub passive_scan_started_ms: Option<i64>,
    pub passive_scan_finished_ms: Option<i64>,
}

#[tauri::command]
pub async fn dashboard_stats(state: AppStateRef<'_>) -> Result<DashboardStats, String> {
    let h = state.require().map_err(fail)?;

    // Project info (inlined so we don't need to clone `state`).
    let (root, name, listeners, scope_rules, hist) = {
        let p = h.project.read();
        (
            p.root.clone(),
            p.config.name.clone(),
            p.config.listeners.iter().map(|l| l.address.clone()).collect::<Vec<_>>(),
            p.config.scope.rules.len(),
            p.history.clone(),
        )
    };
    let tx_count = hist.count(&HistoryFilter::default()).map_err(fail)?;
    let project = ProjectInfo { root, name, listeners, tx_count, scope_rules };

    // Proxy stats (inlined).
    let proxy = {
        let guard = h.proxy.read();
        match guard.as_ref() {
            Some(ph) => {
                let s = ph.stats();
                ProxyStatsView {
                    running: true,
                    listeners: ph.listen_addrs.iter().map(|a| a.to_string()).collect(),
                    conns_accepted: s.conns_accepted,
                    requests_forwarded: s.requests_forwarded,
                    responses_recorded: s.responses_recorded,
                    errors: s.errors,
                    tls_mitm: s.tls_mitm,
                }
            }
            None => ProxyStatsView {
                running: false,
                listeners: Vec::new(),
                conns_accepted: 0,
                requests_forwarded: 0,
                responses_recorded: 0,
                errors: 0,
                tls_mitm: 0,
            },
        }
    };

    let findings_by_severity = hist.finding_counts_by_severity().map_err(fail)?;
    let findings_total: i64 = findings_by_severity.values().sum();

    let ws_sessions = hist
        .list_ws_sessions(Some(10_000))
        .map(|v| v.len() as i64)
        .unwrap_or(0);
    // Message count: approximate by summing per-session message_count values.
    let ws_messages = hist
        .list_ws_sessions(Some(10_000))
        .map(|v| v.iter().map(|s| s.message_count).sum::<i64>())
        .unwrap_or(0);

    let organizer_items = hist.organizer_list().map(|v| v.len() as i64).unwrap_or(0);

    let oob = {
        let guard = h.oob.read();
        match guard.as_ref() {
            Some(oh) => OobStatusView {
                running: true,
                http_addr: oh.http_addr().map(|a| a.to_string()),
                dns_addr: oh.dns_addr().map(|a| a.to_string()),
                public_host: Some(oh.config().public_host.clone()),
                interaction_count: oh.all().len(),
            },
            None => OobStatusView {
                running: false,
                http_addr: None,
                dns_addr: None,
                public_host: None,
                interaction_count: 0,
            },
        }
    };

    let macros = h.session_rules.macros().len() as i64;
    let rules = h.session_rules.rules().len() as i64;
    let extensions = h.extensions.list().len();
    let custom_rules = h.extensions.passive_rules().len();

    let scan = h.scan.read().clone();

    Ok(DashboardStats {
        project,
        proxy,
        findings_by_severity,
        findings_total,
        oob,
        ws_sessions,
        ws_messages,
        organizer_items,
        macros,
        session_rules: rules,
        extensions,
        custom_rules,
        passive_scan_running: scan.running,
        passive_scan_findings_last_run: scan.findings_last_run,
        passive_scan_started_ms: scan.started_ms,
        passive_scan_finished_ms: scan.finished_ms,
    })
}

// ---- Live passive scan toggle --------------------------------------------
//
// Burp's "Live passive scan" option: when enabled, every new in-scope
// transaction recorded by the proxy sink is fed to the passive detector
// chain and the findings are persisted automatically. The hot read lives
// on `AppState::live_passive_scan` so we don't touch the project config
// RwLock on each request. `live_scan_set` syncs the AtomicBool and the
// durable config together.

/// Current state of R131's pause-history-recording toggle. True
/// means the proxy sink is persisting transactions normally; false
/// means it's dropping them silently (extensions still run so an
/// extension-level audit log keeps working — only the on-disk
/// store is paused). Session-ephemeral — a restart resets to on.
#[tauri::command]
pub async fn history_recording_get(state: AppStateRef<'_>) -> Result<bool, String> {
    Ok(state
        .history_recording
        .load(std::sync::atomic::Ordering::Relaxed))
}

/// Flip R131's pause-history-recording toggle. The next transaction
/// that reaches the sink will respect the new value — no restart
/// needed. Burp calls this "Suspend logging to project file"; we
/// expose the same shape as a Proxy toolbar button.
#[tauri::command]
pub async fn history_recording_set(
    enabled: bool,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    state
        .history_recording
        .store(enabled, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(enabled, "history recording toggled");
    Ok(())
}

#[tauri::command]
pub async fn live_scan_get(state: AppStateRef<'_>) -> Result<bool, String> {
    Ok(state
        .live_passive_scan
        .load(std::sync::atomic::Ordering::Relaxed))
}

#[tauri::command]
pub async fn live_scan_set(enabled: bool, state: AppStateRef<'_>) -> Result<(), String> {
    state
        .live_passive_scan
        .store(enabled, std::sync::atomic::Ordering::Relaxed);
    if let Ok(h) = state.require() {
        let mut p = h.project.write();
        p.config.live_passive_scan = enabled;
        p.save_config().map_err(fail)?;
    }
    Ok(())
}

// ---- Bambda saved queries ------------------------------------------------
//
// Named Bambda filter expressions persisted in `ProjectConfig::bambda_queries`
// as opaque JSON values. The frontend scopes its own picker by `scope`
// (currently `"history"` or `"logger"`) so each Bambda bar surfaces only
// its own saved filters.

#[derive(Debug, Serialize, Deserialize)]
pub struct BambdaSavedQuery {
    pub name: String,
    pub expression: String,
    pub scope: String,
    pub created_at_ms: i64,
}

/// Return every saved Bambda query matching `scope`. Deserialises
/// each opaque JSON entry; invalid rows are silently skipped so one
/// bad hand-edit of `config.json` doesn't take down the UI picker.
#[tauri::command]
pub async fn bambda_queries_list(
    scope: String,
    state: AppStateRef<'_>,
) -> Result<Vec<BambdaSavedQuery>, String> {
    let h = state.require().map_err(fail)?;
    let p = h.project.read();
    let out: Vec<BambdaSavedQuery> = p
        .config
        .bambda_queries
        .iter()
        .filter_map(|v| serde_json::from_value::<BambdaSavedQuery>(v.clone()).ok())
        .filter(|q| q.scope == scope)
        .collect();
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct BambdaQuerySaveArgs {
    pub name: String,
    pub expression: String,
    pub scope: String,
}

/// Upsert a Bambda saved query by `(scope, name)`. Blank name or
/// expression is rejected. Bumps `created_at_ms` on overwrite so the
/// picker can show "last saved" ordering if it wants.
#[tauri::command]
pub async fn bambda_queries_save(
    args: BambdaQuerySaveArgs,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let name = args.name.trim();
    let expression = args.expression.trim();
    let scope = args.scope.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if expression.is_empty() {
        return Err("expression is required".into());
    }
    if scope.is_empty() {
        return Err("scope is required".into());
    }
    let h = state.require().map_err(fail)?;
    let entry = BambdaSavedQuery {
        name: name.to_string(),
        expression: expression.to_string(),
        scope: scope.to_string(),
        created_at_ms: burpfree_core::traffic::now_ms(),
    };
    let value = serde_json::to_value(&entry).map_err(fail)?;
    let mut p = h.project.write();
    // Overwrite any existing (scope, name) match in place to preserve
    // list ordering as much as possible.
    let mut replaced = false;
    for existing in p.config.bambda_queries.iter_mut() {
        let same = serde_json::from_value::<BambdaSavedQuery>(existing.clone())
            .ok()
            .map(|q| q.scope == entry.scope && q.name == entry.name)
            .unwrap_or(false);
        if same {
            *existing = value.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        p.config.bambda_queries.push(value);
    }
    p.save_config().map_err(fail)
}

#[derive(Debug, Deserialize)]
pub struct BambdaQueryDeleteArgs {
    pub name: String,
    pub scope: String,
}

/// Remove a saved Bambda query by `(scope, name)`. Returns `true`
/// when an entry was removed, `false` when the name didn't match
/// anything in that scope.
#[tauri::command]
pub async fn bambda_queries_delete(
    args: BambdaQueryDeleteArgs,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let h = state.require().map_err(fail)?;
    let mut p = h.project.write();
    let before = p.config.bambda_queries.len();
    p.config.bambda_queries.retain(|v| {
        match serde_json::from_value::<BambdaSavedQuery>(v.clone()) {
            Ok(q) => !(q.scope == args.scope && q.name == args.name),
            Err(_) => true, // keep unparseable rows alone
        }
    });
    let removed = p.config.bambda_queries.len() < before;
    if removed {
        p.save_config().map_err(fail)?;
    }
    Ok(removed)
}

// ---------------- TLS pass-through list ----------------

/// Return the current TLS pass-through host list. Entries are the
/// case-insensitive substring patterns consulted by the proxy's CONNECT
/// handler to decide whether to tunnel raw instead of MITM-ing.
#[tauri::command]
pub async fn tls_passthrough_get(state: AppStateRef<'_>) -> Result<Vec<String>, String> {
    Ok(state.tls_passthrough.read().clone())
}

/// Replace the TLS pass-through host list. Entries are trimmed and
/// empty lines dropped. Updates the shared Arc the running proxy reads
/// on every CONNECT, then persists to the project config so the list
/// survives a restart.
#[tauri::command]
pub async fn tls_passthrough_set(list: Vec<String>, state: AppStateRef<'_>) -> Result<(), String> {
    let normalized: Vec<String> = list
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    *state.tls_passthrough.write() = normalized.clone();
    if let Ok(h) = state.require() {
        let mut p = h.project.write();
        p.config.tls_passthrough = normalized;
        p.save_config().map_err(fail)?;
    }
    Ok(())
}


// ---------------------------------------------------------------------------
// REST API management commands (R930)
// ---------------------------------------------------------------------------

/// Get the current REST API configuration.
#[tauri::command]
pub async fn rest_api_config_get(
    state: AppStateRef<'_>,
) -> Result<crate::rest_api::RestApiConfig, String> {
    // REST API config is stored separately from project config since
    // it's a user-level setting (like Burp's UserConfig.misc.api).
    let cfg_path = dirs::data_local_dir()
        .unwrap_or_else(|| ".".into())
        .join("BurpFree")
        .join("rest_api.json");
    if cfg_path.exists() {
        let data = std::fs::read_to_string(&cfg_path).map_err(fail)?;
        serde_json::from_str(&data).map_err(fail)
    } else {
        Ok(crate::rest_api::RestApiConfig::default())
    }
}

/// Update the REST API configuration and persist it.
#[tauri::command]
pub async fn rest_api_config_set(
    config: crate::rest_api::RestApiConfig,
    state: AppStateRef<'_>,
) -> Result<(), String> {
    let cfg_path = dirs::data_local_dir()
        .unwrap_or_else(|| ".".into())
        .join("BurpFree")
        .join("rest_api.json");
    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let data = serde_json::to_string_pretty(&config).map_err(fail)?;
    std::fs::write(&cfg_path, data).map_err(fail)?;
    Ok(())
}

/// Create a new API key and return it. The key value is only returned
/// once (at creation time), matching Burp's API key flow.
#[tauri::command]
pub async fn rest_api_key_create(
    name: String,
    state: AppStateRef<'_>,
) -> Result<crate::rest_api::ApiKey, String> {
    let key = crate::rest_api::generate_api_key();
    let entry = crate::rest_api::ApiKey {
        name,
        key: key.clone(),
        enabled: true,
    };

    // Load, append, save
    let cfg_path = dirs::data_local_dir()
        .unwrap_or_else(|| ".".into())
        .join("BurpFree")
        .join("rest_api.json");
    let mut config = if cfg_path.exists() {
        let data = std::fs::read_to_string(&cfg_path).map_err(fail)?;
        serde_json::from_str::<crate::rest_api::RestApiConfig>(&data)
            .unwrap_or_default()
    } else {
        crate::rest_api::RestApiConfig::default()
    };
    config.api_keys.push(entry.clone());
    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let data = serde_json::to_string_pretty(&config).map_err(fail)?;
    std::fs::write(&cfg_path, data).map_err(fail)?;

    Ok(entry)
}

/// List all API keys (without exposing the actual key values — returns
/// names + enabled status only, matching Burp's security model).
#[tauri::command]
pub async fn rest_api_key_list(
    state: AppStateRef<'_>,
) -> Result<Vec<serde_json::Value>, String> {
    let cfg_path = dirs::data_local_dir()
        .unwrap_or_else(|| ".".into())
        .join("BurpFree")
        .join("rest_api.json");
    let config = if cfg_path.exists() {
        let data = std::fs::read_to_string(&cfg_path).map_err(fail)?;
        serde_json::from_str::<crate::rest_api::RestApiConfig>(&data)
            .unwrap_or_default()
    } else {
        crate::rest_api::RestApiConfig::default()
    };

    let keys: Vec<serde_json::Value> = config
        .api_keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "name": k.name,
                "enabled": k.enabled,
                "key_prefix": if k.key.len() > 8 { &k.key[..8] } else { &k.key },
            })
        })
        .collect();

    Ok(keys)
}

/// Delete an API key by name.
#[tauri::command]
pub async fn rest_api_key_delete(
    name: String,
    state: AppStateRef<'_>,
) -> Result<bool, String> {
    let cfg_path = dirs::data_local_dir()
        .unwrap_or_else(|| ".".into())
        .join("BurpFree")
        .join("rest_api.json");
    let mut config = if cfg_path.exists() {
        let data = std::fs::read_to_string(&cfg_path).map_err(fail)?;
        serde_json::from_str::<crate::rest_api::RestApiConfig>(&data)
            .unwrap_or_default()
    } else {
        return Ok(false);
    };

    let before = config.api_keys.len();
    config.api_keys.retain(|k| k.name != name);
    let removed = config.api_keys.len() < before;

    if removed {
        let data = serde_json::to_string_pretty(&config).map_err(fail)?;
        std::fs::write(&cfg_path, data).map_err(fail)?;
    }

    Ok(removed)
}


// ---------------------------------------------------------------------------
// R961: Bambda library + scan profile commands
// ---------------------------------------------------------------------------

/// List all built-in Bambda presets.
#[tauri::command]
pub async fn bambda_presets_list() -> Result<Vec<serde_json::Value>, String> {
    let presets = burpfree_engines::bambda_library::builtin_presets();
    let out: Vec<serde_json::Value> = presets
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "category": p.category,
                "expression": p.expression,
            })
        })
        .collect();
    Ok(out)
}

/// List all built-in scan profiles.
#[tauri::command]
pub async fn scan_profiles_list() -> Result<Vec<serde_json::Value>, String> {
    let profiles = burpfree_engines::scanner::profiles::builtin_profiles();
    let out: Vec<serde_json::Value> = profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "category": p.category.label(),
                "crawl_depth": p.crawl_depth,
                "rate_limit": p.rate_limit,
            })
        })
        .collect();
    Ok(out)
}

/// List all scanner KB issue types.
#[tauri::command]
pub async fn kb_issues_list() -> Result<Vec<serde_json::Value>, String> {
    let kb = burpfree_engines::scanner::knowledge_base::knowledge_base();
    let out: Vec<serde_json::Value> = kb
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id,
                "name": i.name,
                "severity": i.severity_default,
                "cwe": i.cwe,
                "owasp": i.owasp,
            })
        })
        .collect();
    Ok(out)
}

/// Get a single KB issue by id.
#[tauri::command]
pub async fn kb_issue_detail(id: String) -> Result<serde_json::Value, String> {
    let issue = burpfree_engines::scanner::knowledge_base::lookup(&id)
        .ok_or_else(|| format!("KB issue '{}' not found", id))?;
    Ok(serde_json::json!({
        "id": issue.id,
        "name": issue.name,
        "description": issue.description,
        "remediation": issue.remediation,
        "severity": issue.severity_default,
        "cwe": issue.cwe,
        "owasp": issue.owasp,
        "references": issue.references,
    }))
}
