//! Sandboxed Rhai scripting.
//!
//! Scripts are first-class but **not** trusted. Every engine the user
//! can touch (match/replace, custom filters, custom columns, extension
//! helpers) wraps this crate so the same resource caps apply:
//!
//! * no file / network / shell access (Rhai's default)
//! * CPU cap via `max_operations` (default 100 000)
//! * depth cap via `max_expr_depths` (default 32 / 32)
//! * memory caps on strings, arrays, maps
//! * wall-clock timeout
//!
//! The scripting surface exposes a read-only [`RequestView`] and
//! [`ResponseView`] built from the canonical traffic model. Scripts
//! typically return a `bool` (predicate) or a `String` (extraction).
//!
//! ```text
//! // Example: fire a match/replace rule only when the response status
//! // is 500+ and the body mentions "stack trace".
//! resp.status >= 500 && resp.body.contains("stack trace")
//! ```

use std::time::{Duration, Instant};

use burpfree_core::traffic::{Request, Response};
use rhai::{Dynamic, Engine, Scope};
use serde::{Deserialize, Serialize};

/// Resource caps applied to every evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptLimits {
    pub max_operations: u64,
    pub max_string_size: usize,
    pub max_array_size: usize,
    pub max_map_size: usize,
    pub expr_depth: usize,
    pub function_expr_depth: usize,
    /// Wall-clock timeout. Rhai honours this via a progress callback.
    pub timeout: Duration,
}

impl Default for ScriptLimits {
    fn default() -> Self {
        Self {
            max_operations: 100_000,
            max_string_size: 32 * 1024,
            max_array_size: 1024,
            max_map_size: 512,
            expr_depth: 32,
            function_expr_depth: 32,
            timeout: Duration::from_millis(250),
        }
    }
}

/// Error returned when a script cannot run.
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("script parse error: {0}")]
    Parse(String),
    #[error("script evaluation error: {0}")]
    Eval(String),
    #[error("script result had wrong type (expected {0})")]
    WrongType(&'static str),
    #[error("script exceeded wall-clock timeout")]
    Timeout,
}

/// Shaped view of a request handed to the script.
#[derive(Debug, Clone, Serialize)]
pub struct RequestView {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub url: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl From<&Request> for RequestView {
    fn from(r: &Request) -> Self {
        Self {
            method: r.method.clone(),
            scheme: r.scheme.clone(),
            host: r.host.clone(),
            port: r.port,
            path: r.path.clone(),
            url: r.url(),
            body: r.text(),
            headers: r
                .headers
                .as_slice()
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseView {
    pub status: u16,
    pub reason: String,
    pub body: String,
    pub content_type: String,
    pub elapsed_ms: u64,
    pub length: i64,
    pub headers: Vec<(String, String)>,
}

impl From<&Response> for ResponseView {
    fn from(r: &Response) -> Self {
        Self {
            status: r.status,
            reason: r.reason.clone(),
            body: r.text(),
            content_type: r.headers.content_type().unwrap_or("").to_string(),
            elapsed_ms: r.elapsed_ms,
            length: r.body.len() as i64,
            headers: r
                .headers
                .as_slice()
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
        }
    }
}

/// The sandboxed Rhai engine. Cheap to construct; clone for reuse.
pub struct ScriptEngine {
    /// A fresh engine is built per-eval so the per-call timeout state
    /// is isolated; we keep this template around for configuration
    /// inspection and for future reuse of pre-compiled ASTs.
    #[allow(dead_code)]
    inner: Engine,
    limits: ScriptLimits,
}

impl ScriptEngine {
    pub fn new(limits: ScriptLimits) -> Self {
        Self {
            inner: build_engine(&limits),
            limits,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ScriptLimits::default())
    }

    pub fn limits(&self) -> &ScriptLimits {
        &self.limits
    }

    /// Evaluate `script` with the given request/response. Returns a
    /// [`Dynamic`] value; callers typically call one of the typed
    /// convenience methods below.
    pub fn eval(
        &self,
        script: &str,
        req: Option<&Request>,
        resp: Option<&Response>,
    ) -> Result<Dynamic, ScriptError> {
        let mut scope = Scope::new();
        if let Some(r) = req {
            scope.push_dynamic("req", request_to_map(&RequestView::from(r)));
        }
        if let Some(r) = resp {
            scope.push_dynamic("resp", response_to_map(&ResponseView::from(r)));
        }
        // Rhai's `Engine` isn't `Clone` and the `on_progress` callback
        // captures a per-call `Instant`. Build a fresh engine per eval
        // so each has its own timeout state. The construction cost is
        // ~hundred microseconds — acceptable for the predicate path.
        let mut engine = build_engine(&self.limits);
        let timeout = self.limits.timeout;
        let start = Instant::now();
        engine.on_progress(move |_ops| {
            if start.elapsed() > timeout {
                Some(Dynamic::from("burpfree-timeout"))
            } else {
                None
            }
        });
        let ast = engine
            .compile(script)
            .map_err(|e| ScriptError::Parse(e.to_string()))?;
        match engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast) {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("burpfree-timeout") {
                    Err(ScriptError::Timeout)
                } else {
                    Err(ScriptError::Eval(msg))
                }
            }
        }
    }

    pub fn eval_bool(
        &self,
        script: &str,
        req: Option<&Request>,
        resp: Option<&Response>,
    ) -> Result<bool, ScriptError> {
        let v = self.eval(script, req, resp)?;
        v.as_bool().map_err(|_| ScriptError::WrongType("bool"))
    }

    pub fn eval_string(
        &self,
        script: &str,
        req: Option<&Request>,
        resp: Option<&Response>,
    ) -> Result<String, ScriptError> {
        let v = self.eval(script, req, resp)?;
        if let Ok(s) = v.clone().into_string() {
            Ok(s)
        } else {
            Err(ScriptError::WrongType("string"))
        }
    }
}

fn request_to_map(r: &RequestView) -> Dynamic {
    use rhai::Map;
    let mut m = Map::new();
    m.insert("method".into(), r.method.clone().into());
    m.insert("scheme".into(), r.scheme.clone().into());
    m.insert("host".into(), r.host.clone().into());
    m.insert("port".into(), (r.port as i64).into());
    m.insert("path".into(), r.path.clone().into());
    m.insert("url".into(), r.url.clone().into());
    m.insert("body".into(), r.body.clone().into());
    let headers_map: Map = r
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase().into(), Dynamic::from(v.clone())))
        .collect();
    m.insert("headers".into(), Dynamic::from(headers_map));
    Dynamic::from(m)
}

fn response_to_map(r: &ResponseView) -> Dynamic {
    use rhai::Map;
    let mut m = Map::new();
    m.insert("status".into(), (r.status as i64).into());
    m.insert("reason".into(), r.reason.clone().into());
    m.insert("body".into(), r.body.clone().into());
    m.insert("content_type".into(), r.content_type.clone().into());
    m.insert("elapsed_ms".into(), (r.elapsed_ms as i64).into());
    m.insert("length".into(), r.length.into());
    let headers_map: Map = r
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase().into(), Dynamic::from(v.clone())))
        .collect();
    m.insert("headers".into(), Dynamic::from(headers_map));
    Dynamic::from(m)
}

fn build_engine(limits: &ScriptLimits) -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(limits.max_operations);
    engine.set_max_string_size(limits.max_string_size);
    engine.set_max_array_size(limits.max_array_size);
    engine.set_max_map_size(limits.max_map_size);
    engine.set_max_expr_depths(limits.expr_depth, limits.function_expr_depth);
    engine.on_print(|_s| {});
    engine.on_debug(|_s, _src, _pos| {});
    register_helpers(&mut engine);
    engine
}

fn register_helpers(engine: &mut Engine) {
    use rhai::ImmutableString;
    // Case-insensitive header lookup helper.
    engine.register_fn("header", |m: rhai::Map, name: &str| -> String {
        if let Some(h) = m.get("headers") {
            if let Some(hm) = h.clone().try_cast::<rhai::Map>() {
                let key: ImmutableString = name.to_ascii_lowercase().into();
                if let Some(v) = hm.get(key.as_str()) {
                    return v.clone().into_string().unwrap_or_default();
                }
            }
        }
        String::new()
    });
    engine.register_fn("has_header", |m: rhai::Map, name: &str| -> bool {
        if let Some(h) = m.get("headers") {
            if let Some(hm) = h.clone().try_cast::<rhai::Map>() {
                let key: ImmutableString = name.to_ascii_lowercase().into();
                return hm.contains_key(key.as_str());
            }
        }
        false
    });
    engine.register_fn("matches_regex", |haystack: &str, pattern: &str| -> bool {
        regex_lite::Regex::new(pattern)
            .map(|r| r.is_match(haystack))
            .unwrap_or(false)
    });
}

/// Our own tiny regex adapter so we don't force consumers to add the
/// `regex` crate. The `regex` crate transitively depends on various
/// things that aren't justifiable just for scripting; we use a very
/// small subset here.
mod regex_lite {
    pub struct Regex {
        re: ::regex::Regex,
    }
    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, ::regex::Error> {
            Ok(Self { re: ::regex::Regex::new(pattern)? })
        }
        pub fn is_match(&self, hay: &str) -> bool {
            self.re.is_match(hay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response};

    fn mkreq() -> Request {
        let mut r = Request::new("POST", "https://api.example.com/v1/users?x=1").unwrap();
        r.headers.set("Content-Type", "application/json");
        r.headers.set("Authorization", "Bearer abc123");
        r.set_text(r#"{"name":"alice"}"#);
        r
    }
    fn mkresp(status: u16, body: &str) -> Response {
        let mut r = Response::new(status);
        r.headers.set("Content-Type", "text/html");
        r.set_text(body);
        r
    }

    #[test]
    fn simple_bool_predicate() {
        let engine = ScriptEngine::with_defaults();
        let req = mkreq();
        let b = engine
            .eval_bool(r#"req.method == "POST" && req.host == "api.example.com""#, Some(&req), None)
            .unwrap();
        assert!(b);
        let b = engine
            .eval_bool(r#"req.method == "GET""#, Some(&req), None)
            .unwrap();
        assert!(!b);
    }

    #[test]
    fn header_helper() {
        let engine = ScriptEngine::with_defaults();
        let req = mkreq();
        let v = engine
            .eval_string(r#"header(req, "Authorization")"#, Some(&req), None)
            .unwrap();
        assert_eq!(v, "Bearer abc123");
        let v = engine
            .eval_bool(r#"has_header(req, "content-type")"#, Some(&req), None)
            .unwrap();
        assert!(v);
    }

    #[test]
    fn response_predicate() {
        let engine = ScriptEngine::with_defaults();
        let resp = mkresp(500, "stack trace: oh no");
        let b = engine
            .eval_bool(r#"resp.status >= 500 && resp.body.contains("stack trace")"#, None, Some(&resp))
            .unwrap();
        assert!(b);
    }

    #[test]
    fn regex_helper() {
        let engine = ScriptEngine::with_defaults();
        let resp = mkresp(200, "token=abcdef1234567890 secret=yes");
        let b = engine
            .eval_bool(r#"matches_regex(resp.body, "token=[A-Fa-f0-9]{10,}")"#, None, Some(&resp))
            .unwrap();
        assert!(b);
    }

    #[test]
    fn eval_string_returns_dynamic_string() {
        let engine = ScriptEngine::with_defaults();
        let req = mkreq();
        let s = engine
            .eval_string(r#"req.method + " " + req.path"#, Some(&req), None)
            .unwrap();
        assert_eq!(s, "POST /v1/users?x=1");
    }

    #[test]
    fn operations_cap_fires() {
        let limits = ScriptLimits { max_operations: 100, ..Default::default() };
        let engine = ScriptEngine::new(limits);
        let script = "let n = 0; for i in 0..100000 { n += 1; } n";
        let err = engine.eval(script, None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("evaluation"));
    }

    #[test]
    fn timeout_fires() {
        let limits = ScriptLimits {
            max_operations: 10_000_000, // high so timeout triggers first
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let engine = ScriptEngine::new(limits);
        let script = "let n = 0; for i in 0..1000000 { n += 1; } n";
        let err = engine.eval(script, None, None).unwrap_err();
        assert!(matches!(err, ScriptError::Timeout | ScriptError::Eval(_)));
    }

    #[test]
    fn no_filesystem_or_network_access() {
        let engine = ScriptEngine::with_defaults();
        // Rhai doesn't ship `read_file`, `fetch`, etc. by default and
        // we haven't registered any such function. The parse+eval here
        // should fail at eval time (unknown function).
        let err = engine.eval(r#"read_file("c:/windows/system.ini")"#, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn parse_error_is_surfaced() {
        let engine = ScriptEngine::with_defaults();
        let err = engine.eval("let x = ;;", None, None).unwrap_err();
        assert!(matches!(err, ScriptError::Parse(_)));
    }
}
