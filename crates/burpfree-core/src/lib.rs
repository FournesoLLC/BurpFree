//! BurpFree core primitives.
//!
//! Request/response model, header container, event bus, scope engine,
//! and ID generation shared by every engine.
//!
//! Keep this crate free of I/O: it must be usable from any thread and
//! any async runtime.

pub mod events;
pub mod headers;
pub mod ids;
pub mod net;
pub mod rules;
pub mod scope;
pub mod traffic;

pub use events::{EventBus, EventKind, Subscription, TrafficEvent};
pub use headers::{HeaderField, Headers};
pub use ids::{blake3_hex, random_token, ContentRef, TrafficId};
pub use net::{FollowRedirectPolicy, HostOverride, HostOverrides};
pub use rules::{validate_rule, CustomMatcher, CustomPassiveRule};
pub use scope::{Scope, ScopeDecision, ScopeMatch, ScopeRule};
pub use traffic::{
    HttpVersion, Request, RequestSource, Response, TlsInfo, Transaction, WebSocketMessage,
    WebSocketSession, WsDirection, WsOpcode,
};
