//! BurpFree Model Context Protocol server.
//!
//! Exposes a curated subset of BurpFree's capabilities as JSON-RPC
//! "tools" that MCP-capable AI clients (e.g. Claude Desktop, Cline) can
//! invoke. The protocol is JSON-RPC 2.0 over newline-delimited JSON,
//! transported over stdio by default.
//!
//! Design points:
//!
//! * One in-process `McpServer` wraps a shared `Project` handle and
//!   handles `initialize`, `tools/list`, `tools/call`, and `ping`
//!   requests. Tools are declarative so the schema we send to the
//!   client always matches what we actually accept.
//! * Everything that could race the proxy — history reads, scanner
//!   runs — goes through `blocking` tasks because the storage layer is
//!   synchronous. Tool bodies stay small so the main loop never
//!   blocks on IO.
//! * Logging is routed through `tracing` and emitted on stderr; stdout
//!   is reserved for protocol frames.

pub mod protocol;
pub mod server;
pub mod tools;
pub mod transport;

pub use protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, MCP_PROTOCOL_VERSION};
pub use server::{McpServer, ServerInfo};
pub use tools::{ToolRegistry, ToolSpec};
pub use transport::stdio_loop;
