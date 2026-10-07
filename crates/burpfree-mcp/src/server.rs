//! `McpServer` — the message-pump that routes JSON-RPC frames to tools.

use std::sync::Arc;

use anyhow::Result;
use burpfree_storage::Project;
use serde_json::{json, Value};
use tracing::warn;

use crate::protocol::{
    error_response, ok_response, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    MCP_PROTOCOL_VERSION,
};
use crate::tools::ToolRegistry;

/// Server identification sent to the client at `initialize`.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "burpfree-mcp".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

#[derive(Clone)]
pub struct McpServer {
    project: Arc<Project>,
    tools: ToolRegistry,
    info: ServerInfo,
}

impl McpServer {
    pub fn new(project: Arc<Project>) -> Self {
        Self {
            project,
            tools: ToolRegistry::with_defaults(),
            info: ServerInfo::default(),
        }
    }

    pub fn with_info(mut self, info: ServerInfo) -> Self {
        self.info = info;
        self
    }

    pub fn with_tools(mut self, tools: ToolRegistry) -> Self {
        self.tools = tools;
        self
    }

    /// Handle one inbound frame; produce an optional response. Notifications
    /// return `None` — the caller must not emit anything to the transport.
    pub async fn handle(&self, msg: JsonRpcMessage) -> Option<JsonRpcResponse> {
        match msg {
            JsonRpcMessage::Invalid(raw) => {
                warn!(frame = %raw, "ignored invalid JSON-RPC frame");
                None
            }
            JsonRpcMessage::Notification(req) => {
                // Known no-ops: `notifications/initialized`, `notifications/cancelled`.
                tracing::debug!(method = %req.method, "notification received");
                None
            }
            JsonRpcMessage::Request(req) => Some(self.handle_request(req).await),
        }
    }

    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone().unwrap_or(Value::Null);
        match req.method.as_str() {
            "initialize" => ok_response(id, self.initialize_result()),
            "ping" => ok_response(id, json!({})),
            "tools/list" => ok_response(id, json!({ "tools": self.tools.specs() })),
            "tools/call" => self.dispatch_tool_call(id, req.params).await,
            other => error_response(id, JsonRpcError::method_not_found(other)),
        }
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverInfo": {
                "name": self.info.name,
                "version": self.info.version
            },
            "capabilities": {
                "tools": { "listChanged": false }
            }
        })
    }

    async fn dispatch_tool_call(&self, id: Value, params: Option<Value>) -> JsonRpcResponse {
        let params = params.unwrap_or(Value::Null);
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));

        let Some(name) = name else {
            return error_response(id, JsonRpcError::invalid_params("missing `name`"));
        };
        let Some(tool) = self.tools.find(&name) else {
            return error_response(id, JsonRpcError::method_not_found(format!("tool `{name}`")));
        };
        // Offload to a blocking thread so sync storage work doesn't block the loop.
        let handler = tool.handler.clone();
        let project = self.project.clone();
        let args_clone = args.clone();
        let res = tokio::task::spawn_blocking(move || handler(project, args_clone)).await;
        match res {
            Ok(Ok(v)) => ok_response(id, v),
            Ok(Err(e)) => ok_response(id, crate::tools::error_result(e.to_string())),
            Err(join) => error_response(id, JsonRpcError::internal(format!("tool panicked: {join}"))),
        }
    }
}

/* ------------------------------------------------------------------ */
/*                            helpers for tools                        */
/* ------------------------------------------------------------------ */

/// Reconstruct a `Transaction` from a stored summary + raw blob bytes.
/// Shared between the passive-scan tool and anywhere else that wants to
/// run engine code against stored traffic.
pub fn rebuild_transaction(
    row: &burpfree_storage::StoredSummary,
    req_bytes: &[u8],
    resp_bytes: Option<&[u8]>,
) -> Result<burpfree_core::traffic::Transaction> {
    use burpfree_core::headers::Headers;
    use burpfree_core::traffic::{Request, Response, Transaction};

    let mut req = Request::new(
        &row.method,
        &format!("{}://{}:{}{}", row.scheme, row.host, row.port, row.path),
    )?;
    req.id = row.id;
    req.headers = Headers::parse_block(header_block(req_bytes));
    req.body = body_part(req_bytes).to_vec();
    let mut t = Transaction::new(req);
    t.in_scope = row.in_scope;
    if let Some(bytes) = resp_bytes {
        let mut r = Response::new(row.status.unwrap_or(0));
        r.headers = Headers::parse_block(header_block(bytes));
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

pub fn finding_to_stored(
    f: &burpfree_engines::scanner::Finding,
) -> burpfree_storage::StoredFinding {
    let now = burpfree_core::traffic::now_ms();
    burpfree_storage::StoredFinding {
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

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_storage::Project;
    use serde_json::json;
    use tempfile::tempdir;

    fn test_project() -> (Arc<Project>, tempfile::TempDir) {
        let td = tempdir().unwrap();
        let p = Project::create(td.path().join("p")).unwrap();
        (Arc::new(p), td)
    }

    #[tokio::test]
    async fn initialize_returns_version_and_capabilities() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let req = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        let resp = s.handle(req).await.unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        let result = &v["result"];
        assert_eq!(result["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "burpfree-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn tools_list_includes_history_and_scanner() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let req = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let resp = s.handle(req).await.unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"project_info"));
        assert!(names.contains(&"history_list"));
        assert!(names.contains(&"history_show"));
        assert!(names.contains(&"scan_passive"));
        assert!(names.contains(&"findings_list"));
        assert!(names.contains(&"scope_check"));
    }

    #[tokio::test]
    async fn tools_call_project_info_returns_name() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let call = json!({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": { "name": "project_info", "arguments": {} }
        });
        let msg = JsonRpcMessage::parse(&call.to_string());
        let resp = s.handle(msg).await.unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"name\""));
        assert!(text.contains("BurpFree project"));
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let req = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#);
        let resp = s.handle(req).await.unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn scope_check_runs_against_project() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let call = json!({
            "jsonrpc": "2.0", "id": 4,
            "method": "tools/call",
            "params": {
                "name": "scope_check",
                "arguments": { "url": "https://example.com/" }
            }
        });
        let resp = s.handle(JsonRpcMessage::parse(&call.to_string())).await.unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("in_scope"));
    }

    #[tokio::test]
    async fn notifications_do_not_produce_a_response() {
        let (p, _td) = test_project();
        let s = McpServer::new(p);
        let msg = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(s.handle(msg).await.is_none());
    }
}
