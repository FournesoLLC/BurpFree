//! Tool definitions.
//!
//! Each tool is described declaratively: a name, a human-readable
//! description, a JSON schema for its input, and a sync handler. The
//! schemas are what the AI client sees via `tools/list`.

use std::sync::Arc;

use anyhow::Result;
use burpfree_core::ids::TrafficId;
use burpfree_storage::Project;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP `tools/call` result shape: `{ content: [{ type: "text", text }] }`.
pub fn text_result(s: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": s.into() }], "isError": false })
}

pub fn json_result(v: &Value) -> Value {
    text_result(serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()))
}

pub fn error_result(msg: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": msg.into() }], "isError": true })
}

/// Shared handler signature. Tools get the live `Project` so changes
/// are reflected without a restart.
pub type ToolHandler = Arc<dyn Fn(Arc<Project>, Value) -> Result<Value> + Send + Sync>;

#[derive(Clone)]
pub struct Tool {
    pub spec: ToolSpec,
    pub handler: ToolHandler,
}

/// Named catalogue of tools the server advertises.
#[derive(Clone, Default)]
pub struct ToolRegistry {
    pub tools: Vec<Tool>,
}

impl ToolRegistry {
    pub fn with_defaults() -> Self {
        let mut r = Self::default();
        r.register(project_info_tool());
        r.register(history_list_tool());
        r.register(history_show_tool());
        r.register(scan_passive_tool());
        r.register(findings_list_tool());
        r.register(scope_check_tool());
        r.register(scope_add_tool());
        r
    }

    pub fn register(&mut self, tool: Tool) {
        self.tools.push(tool);
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec.clone()).collect()
    }

    pub fn find(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.spec.name == name)
    }
}

/* ------------------------------------------------------------------ */
/*                            tool implementations                     */
/* ------------------------------------------------------------------ */

fn project_info_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "project_info".into(),
            description:
                "Return summary stats about the current BurpFree project (name, root path, \
                 scope rule count, transaction count, finding count)."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, _args| {
            let hist = &project.history;
            let tx_count = hist.count(&burpfree_storage::HistoryFilter::default())?;
            let findings = hist.list_findings().unwrap_or_default();
            let v = json!({
                "name": project.config.name,
                "root": project.root.display().to_string(),
                "scope_rules": project.config.scope.rules.len(),
                "transactions": tx_count,
                "findings": findings.len(),
            });
            Ok(json_result(&v))
        }),
    }
}

#[derive(Debug, Deserialize)]
struct HistoryListArgs {
    #[serde(default)]
    host_contains: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    status_min: Option<u16>,
    #[serde(default)]
    status_max: Option<u16>,
    #[serde(default)]
    in_scope_only: bool,
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 { 50 }

fn history_list_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "history_list".into(),
            description:
                "List HTTP transactions the proxy has observed, filtered by host / method / \
                 status / scope. Returns up to `limit` summaries (id, method, status, URL, size, \
                 title). Use `history_show` with an id to fetch raw bytes."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host_contains": { "type": "string" },
                    "method":        { "type": "string" },
                    "status_min":    { "type": "integer" },
                    "status_max":    { "type": "integer" },
                    "in_scope_only": { "type": "boolean" },
                    "limit":         { "type": "integer", "minimum": 1, "maximum": 500 }
                },
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, args| {
            let a: HistoryListArgs = serde_json::from_value(args).unwrap_or_else(|_| HistoryListArgs {
                host_contains: None,
                method: None,
                status_min: None,
                status_max: None,
                in_scope_only: false,
                limit: 50,
            });
            let filter = burpfree_storage::HistoryFilter {
                host_contains: a.host_contains,
                method: a.method,
                status_min: a.status_min,
                status_max: a.status_max,
                in_scope_only: a.in_scope_only,
                limit: Some(a.limit.min(500)),
                ..Default::default()
            };
            let rows = project.history.list(&filter)?;
            let summaries: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id.as_i64(),
                        "method": r.method,
                        "status": r.status,
                        "url": format!(
                            "{}://{}{}{}",
                            r.scheme, r.host,
                            if r.port != 80 && r.port != 443 { format!(":{}", r.port) } else { String::new() },
                            r.path
                        ),
                        "length": r.content_length,
                        "mime": r.content_type,
                        "title": r.title,
                        "in_scope": r.in_scope,
                        "elapsed_ms": r.elapsed_ms,
                    })
                })
                .collect();
            Ok(json_result(&json!({ "count": summaries.len(), "items": summaries })))
        }),
    }
}

#[derive(Debug, Deserialize)]
struct HistoryShowArgs { id: i64 }

fn history_show_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "history_show".into(),
            description:
                "Return the raw request + response text for one history transaction. \
                 Use `history_list` first to pick an id."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer", "description": "transaction id from history_list" }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, args| {
            let a: HistoryShowArgs = serde_json::from_value(args)
                .map_err(|e| anyhow::anyhow!("invalid args: {e}"))?;
            let tid = TrafficId::from(a.id);
            let summary = project
                .history
                .get_summary(tid)?
                .ok_or_else(|| anyhow::anyhow!("transaction {} not found", a.id))?;
            let req_bytes = match project.history.get_request_blob(tid)? {
                Some(c) => project.blobs.get(&c)?.unwrap_or_default(),
                None => Vec::new(),
            };
            let resp_bytes = match project.history.get_response_blob(tid)? {
                Some(c) => project.blobs.get(&c)?.unwrap_or_default(),
                None => Vec::new(),
            };
            let v = json!({
                "id": summary.id.as_i64(),
                "method": summary.method,
                "status": summary.status,
                "host": summary.host,
                "port": summary.port,
                "path": summary.path,
                "request":  String::from_utf8_lossy(&req_bytes),
                "response": if resp_bytes.is_empty() {
                    Value::Null
                } else {
                    Value::String(String::from_utf8_lossy(&resp_bytes).into())
                },
            });
            Ok(json_result(&v))
        }),
    }
}

fn scan_passive_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "scan_passive".into(),
            description:
                "Run the built-in passive scanner (and any extension-contributed custom rules) \
                 over every transaction currently in history. Findings are stored in the project \
                 and the count is returned."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, _args| {
            use burpfree_engines::scanner::passive;
            let rows = project.history.list(&burpfree_storage::HistoryFilter {
                limit: Some(100_000),
                ..Default::default()
            })?;
            let mut found = 0usize;
            for r in rows {
                let Some(req_blob) = project.history.get_request_blob(r.id)? else { continue; };
                let Some(req_bytes) = project.blobs.get(&req_blob)? else { continue; };
                let resp_bytes = if let Some(rb) = project.history.get_response_blob(r.id)? {
                    project.blobs.get(&rb)?
                } else { None };
                let tx = crate::server::rebuild_transaction(&r, &req_bytes, resp_bytes.as_deref())?;
                for mut f in passive::run_all(&tx) {
                    f.transaction_id = Some(tx.id);
                    project.history.upsert_finding(&crate::server::finding_to_stored(&f))?;
                    found += 1;
                }
            }
            Ok(json_result(&json!({ "findings": found })))
        }),
    }
}

fn findings_list_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "findings_list".into(),
            description:
                "List issues stored by the scanner. Each row carries detector id, severity, \
                 confidence, title, status, and evidence. Pass `min_severity` to filter."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"]
                    }
                },
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, args| {
            let min = args
                .get("min_severity")
                .and_then(|v| v.as_str())
                .unwrap_or("info");
            let min_rank = severity_rank(min);
            let findings = project.history.list_findings()?;
            let out: Vec<_> = findings
                .into_iter()
                .filter(|f| severity_rank(&f.severity) >= min_rank)
                .map(|f| {
                    json!({
                        "id": f.id.as_i64(),
                        "detector": f.detector,
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "status": f.status,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "transaction_id": f.transaction_id.map(|t| t.as_i64()),
                    })
                })
                .collect();
            Ok(json_result(&json!({ "count": out.len(), "items": out })))
        }),
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[derive(Debug, Deserialize)]
struct ScopeCheckArgs { url: String }

fn scope_check_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "scope_check".into(),
            description:
                "Return whether a given URL is in the project's current scope. Useful for the \
                 AI client to decide where to send attack requests."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Full URL to test" }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|project, args| {
            let a: ScopeCheckArgs = serde_json::from_value(args)
                .map_err(|e| anyhow::anyhow!("invalid args: {e}"))?;
            let req = burpfree_core::traffic::Request::new("GET", &a.url)?;
            let in_scope = project.config.scope.is_in_scope(&req);
            Ok(json_result(&json!({ "url": a.url, "in_scope": in_scope })))
        }),
    }
}

#[derive(Debug, Deserialize)]
struct ScopeAddArgs {
    kind: String, // "include" | "exclude"
    host: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    regex: bool,
}

fn scope_add_tool() -> Tool {
    Tool {
        spec: ToolSpec {
            name: "scope_add".into(),
            description:
                "Add a scope rule to the project. `kind` is \"include\" or \"exclude\"; `host` is \
                 the hostname pattern (literal or regex when `regex`=true); `path` is an \
                 optional path glob (default `*`)."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind":  { "type": "string", "enum": ["include", "exclude"] },
                    "host":  { "type": "string" },
                    "path":  { "type": "string" },
                    "regex": { "type": "boolean" }
                },
                "required": ["kind", "host"],
                "additionalProperties": false
            }),
        },
        handler: Arc::new(|_project, _args| {
            // Scope mutations through the MCP are advisory only in this version
            // — the real Tauri path writes config.json, and we don't want to
            // race the running process. Return a clear note to the client.
            Err(anyhow::anyhow!(
                "scope_add is advisory in MCP mode; edit Target → Scope in the GUI, or use the CLI, to persist rules"
            ))
        }),
    }
}
