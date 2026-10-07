//! BurpFree HTTP proxy.
//!
//! * [`server`] — accept loop + per-connection handler. Supports
//!   plain HTTP, CONNECT with TLS MITM, and WebSocket upgrades.
//! * [`http1`] — sans-I/O HTTP/1.1 parser + serializer.
//! * [`interceptor`] — hold / forward / drop / edit pipeline.
//! * [`matchreplace`] — pre- and post-interception rule engine.
//! * [`upstream`] — direct / HTTP CONNECT / SOCKS5.
//! * [`ws`] — RFC 6455 frame parser used by the websocket forwarder.

pub mod http1;
pub mod interceptor;
pub mod matchreplace;
pub mod platform_auth;
pub mod server;
pub mod upstream;
pub mod ws;
pub mod ws_interceptor;

pub use interceptor::{parse_edited_request, InterceptAction, InterceptDecision, Interceptor, Pending};
pub use matchreplace::{MatchReplaceEngine, Rule, RuleScope, RuleTarget};
pub use platform_auth::{AuthScheme, PlatformAuthCredential};
pub use server::{ProxyHandle, ProxyServer, ServerConfig};
pub use upstream::{Upstream, UpstreamKind};
pub use ws_interceptor::{PendingFrame, Verdict, WsInterceptor};
