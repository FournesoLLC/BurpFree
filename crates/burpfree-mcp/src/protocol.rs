//! JSON-RPC 2.0 wire types for MCP.
//!
//! We model the subset we actually need. `JsonRpcMessage` carries either
//! a request, a response, or a notification (request without `id`); the
//! transport layer parses incoming frames into one of these.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP uses this exact protocol version string in `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    /// Absent for notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(flatten)]
    pub body: JsonRpcResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponseBody {
    Result { result: Value },
    Error { error: JsonRpcError },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self { code: -32700, message: msg.into(), data: None }
    }
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self { code: -32600, message: msg.into(), data: None }
    }
    pub fn method_not_found(method: impl Into<String>) -> Self {
        Self { code: -32601, message: format!("method not found: {}", method.into()), data: None }
    }
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self { code: -32602, message: msg.into(), data: None }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { code: -32603, message: msg.into(), data: None }
    }
    pub fn application(msg: impl Into<String>) -> Self {
        // Application-defined error range per JSON-RPC 2.0 spec.
        Self { code: -32000, message: msg.into(), data: None }
    }
}

/// Any inbound JSON frame, after classification.
#[derive(Debug, Clone)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    /// Request without `id` — must not get a response.
    Notification(JsonRpcRequest),
    /// Could not be parsed. Carries the raw bytes so we can log them.
    Invalid(String),
}

impl JsonRpcMessage {
    /// Parse a single JSON-RPC frame.
    pub fn parse(line: &str) -> Self {
        let line = line.trim();
        if line.is_empty() {
            return JsonRpcMessage::Invalid(String::new());
        }
        match serde_json::from_str::<JsonRpcRequest>(line) {
            Ok(req) if req.id.is_some() => JsonRpcMessage::Request(req),
            Ok(req) => JsonRpcMessage::Notification(req),
            Err(_) => JsonRpcMessage::Invalid(line.to_string()),
        }
    }
}

/// Build an error response for a request we did receive.
pub fn error_response(id: Value, err: JsonRpcError) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        body: JsonRpcResponseBody::Error { error: err },
    }
}

/// Build a success response.
pub fn ok_response(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        body: JsonRpcResponseBody::Result { result },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_notification_invalid() {
        let r = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        assert!(matches!(r, JsonRpcMessage::Request(_)));
        let n = JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","method":"initialized"}"#);
        assert!(matches!(n, JsonRpcMessage::Notification(_)));
        let i = JsonRpcMessage::parse(r#"{"not json"#);
        assert!(matches!(i, JsonRpcMessage::Invalid(_)));
    }

    #[test]
    fn error_response_serializes_with_jsonrpc_and_id() {
        let r = error_response(Value::from(5), JsonRpcError::method_not_found("x"));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"id\":5"));
        assert!(s.contains("\"error\":"));
        assert!(s.contains("-32601"));
    }

    #[test]
    fn ok_response_serializes_with_result() {
        let r = ok_response(Value::from("abc"), serde_json::json!({"ok": true}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"result\":"));
        assert!(s.contains("\"ok\":true"));
    }
}
