//! Canonical in-memory traffic model.
//!
//! The proxy, Repeater, Intruder, scanners and extensions all operate
//! on these structures. Keeping a single model lets every engine share
//! scope, match/replace, storage and UI primitives.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::headers::Headers;
use crate::ids::TrafficId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }
}

impl FromStr for HttpVersion {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "HTTP/1.0" | "http/1.0" => Self::Http10,
            "HTTP/1.1" | "http/1.1" => Self::Http11,
            "HTTP/2" | "HTTP/2.0" | "h2" => Self::Http2,
            "HTTP/3" | "h3" => Self::Http3,
            _ => return Err(()),
        })
    }
}

/// TLS metadata attached to transactions that traversed MITM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub version: Option<String>,
    pub cipher: Option<String>,
    /// Fingerprint only; private keys are never stored.
    pub client_cert_fp: Option<String>,
}

impl TlsInfo {
    pub fn summary(&self) -> String {
        [self.version.as_deref(), self.cipher.as_deref()]
            .iter()
            .filter_map(|v| *v)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Where a request originated. Used by history filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestSource {
    Proxy,
    Repeater,
    Intruder,
    ActiveScan,
    Extension(String),
    Manual,
}

impl RequestSource {
    pub fn as_label(&self) -> String {
        match self {
            Self::Proxy => "proxy".into(),
            Self::Repeater => "repeater".into(),
            Self::Intruder => "intruder".into(),
            Self::ActiveScan => "active-scan".into(),
            Self::Extension(n) => format!("extension:{n}"),
            Self::Manual => "manual".into(),
        }
    }
}

impl Default for RequestSource {
    fn default() -> Self {
        Self::Proxy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: TrafficId,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path including query string.
    pub path: String,
    pub http_version: HttpVersion,
    pub headers: Headers,
    #[serde(with = "serde_bytes_vec")]
    pub body: Vec<u8>,
    pub created_at_ms: i64,
    pub source: RequestSource,
    pub parent_id: Option<TrafficId>,
    pub annotation: String,
    pub comment: String,
}

impl Request {
    pub fn new(method: &str, url: &str) -> anyhow::Result<Self> {
        let u = Url::parse(url).map_err(|e| anyhow::anyhow!("bad url: {e}"))?;
        let scheme = u.scheme().to_string();
        let host = u.host_str().unwrap_or_default().to_string();
        let port = u.port_or_known_default().unwrap_or(80);
        let mut path = u.path().to_string();
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        if path.is_empty() {
            path.push('/');
        }
        let mut headers = Headers::new();
        headers.set("Host", host_header(&host, port, &scheme));
        headers.set_if_missing("User-Agent", "BurpFree/0.1");
        headers.set_if_missing("Accept", "*/*");
        headers.set_if_missing("Connection", "close");
        Ok(Self {
            id: TrafficId::new(),
            method: method.to_ascii_uppercase(),
            scheme,
            host,
            port,
            path,
            http_version: HttpVersion::Http11,
            headers,
            body: Vec::new(),
            created_at_ms: now_ms(),
            source: RequestSource::Manual,
            parent_id: None,
            annotation: String::new(),
            comment: String::new(),
        })
    }

    pub fn url(&self) -> String {
        let default_port = self.scheme == "http" && self.port == 80
            || self.scheme == "https" && self.port == 443;
        let authority = if default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        format!("{}://{}{}", self.scheme, authority, self.path)
    }

    pub fn path_only(&self) -> &str {
        match self.path.find('?') {
            Some(i) => &self.path[..i],
            None => &self.path,
        }
    }

    pub fn query_string(&self) -> &str {
        match self.path.find('?') {
            Some(i) => &self.path[i + 1..],
            None => "",
        }
    }

    pub fn set_query_string(&mut self, qs: &str) {
        let base = self.path_only().to_string();
        self.path = if qs.is_empty() {
            base
        } else {
            format!("{base}?{qs}")
        };
    }

    pub fn query_params(&self) -> Vec<(String, String)> {
        parse_query(self.query_string())
    }

    pub fn set_query_params(&mut self, params: &[(String, String)]) {
        self.set_query_string(&encode_query(params));
    }

    pub fn form_params(&self) -> Option<Vec<(String, String)>> {
        let ct = self.headers.content_type()?.to_ascii_lowercase();
        if !ct.contains("application/x-www-form-urlencoded") {
            return None;
        }
        Some(parse_query(&String::from_utf8_lossy(&self.body)))
    }

    pub fn set_form_params(&mut self, params: &[(String, String)]) {
        self.body = encode_query(params).into_bytes();
        self.headers
            .set("Content-Type", "application/x-www-form-urlencoded");
        self.headers.set("Content-Length", self.body.len().to_string());
    }

    pub fn cookies(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for v in self.headers.get_all("Cookie") {
            for part in v.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (k, v) = match part.find('=') {
                    Some(i) => (&part[..i], &part[i + 1..]),
                    None => (part, ""),
                };
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        out
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn set_text(&mut self, text: &str) {
        self.body = text.as_bytes().to_vec();
        self.headers.set("Content-Length", self.body.len().to_string());
    }

    pub fn clone_with_new_id(&self, source: RequestSource) -> Self {
        let mut copy = self.clone();
        copy.parent_id = Some(self.id);
        copy.id = TrafficId::new();
        copy.created_at_ms = now_ms();
        copy.source = source;
        copy
    }

    /// Serialize the request to its on-the-wire representation. Note:
    /// chunked / Content-Length handling and TE compression is left to
    /// the proxy; this helper always writes a plain body.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.http_version.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.headers.to_wire_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn pretty(&self) -> String {
        let mut headers = self.headers.clone();
        headers.set_if_missing("Host", host_header(&self.host, self.port, &self.scheme));
        let body = String::from_utf8_lossy(&self.body);
        format!(
            "{} {} {}\r\n{}\r\n{}",
            self.method,
            self.path,
            self.http_version.as_str(),
            String::from_utf8_lossy(&headers.to_wire_bytes()),
            body
        )
    }
}

fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default_port = scheme == "http" && port == 80 || scheme == "https" && port == 443;
    if default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: TrafficId,
    pub status: u16,
    pub reason: String,
    pub http_version: HttpVersion,
    pub headers: Headers,
    #[serde(with = "serde_bytes_vec")]
    pub body: Vec<u8>,
    pub created_at_ms: i64,
    pub elapsed_ms: u64,
    /// Original encoded size on the wire if we transparently decoded a
    /// compressed body (`gzip`, `br`, `deflate`).
    pub original_body_size: Option<u64>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Self {
            id: TrafficId::new(),
            status,
            reason: reason_phrase(status).to_string(),
            http_version: HttpVersion::Http11,
            headers: Headers::new(),
            body: Vec::new(),
            created_at_ms: now_ms(),
            elapsed_ms: 0,
            original_body_size: None,
        }
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn set_text(&mut self, text: &str) {
        self.body = text.as_bytes().to_vec();
        self.headers.set("Content-Length", self.body.len().to_string());
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("Set-Cookie")
            .into_iter()
            .map(String::from)
            .collect()
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.http_version.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.headers.to_wire_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn pretty(&self) -> String {
        let body = String::from_utf8_lossy(&self.body);
        format!(
            "{} {} {}\r\n{}\r\n{}",
            self.http_version.as_str(),
            self.status,
            self.reason,
            String::from_utf8_lossy(&self.headers.to_wire_bytes()),
            body
        )
    }
}

/// The pair recorded in HTTP history / Repeater / Intruder tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TrafficId,
    pub request: Request,
    pub response: Option<Response>,
    pub tls: Option<TlsInfo>,
    pub client_addr: Option<String>,
    pub upstream_addr: Option<String>,
    pub tags: Vec<String>,
    pub error: Option<String>,
    pub in_scope: bool,
}

impl Transaction {
    pub fn new(request: Request) -> Self {
        Self {
            id: request.id,
            request,
            response: None,
            tls: None,
            client_addr: None,
            upstream_addr: None,
            tags: Vec::new(),
            error: None,
            in_scope: true,
        }
    }

    pub fn tag(&mut self, label: &str) {
        if !label.is_empty() && !self.tags.iter().any(|t| t == label) {
            self.tags.push(label.to_string());
        }
    }

    pub fn untag(&mut self, label: &str) {
        self.tags.retain(|t| t != label);
    }
}

// ---------------------------------------------------------------------------
// WebSocket model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsDirection {
    Outbound, // client → server
    Inbound,  // server → client
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WsOpcode {
    pub fn from_u8(op: u8) -> Self {
        match op & 0x0f {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            _ => Self::Binary,
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub id: TrafficId,
    pub session_id: TrafficId,
    pub direction: WsDirection,
    pub opcode: WsOpcode,
    #[serde(with = "serde_bytes_vec")]
    pub payload: Vec<u8>,
    pub created_at_ms: i64,
}

impl WebSocketMessage {
    pub fn new(session_id: TrafficId, direction: WsDirection, opcode: WsOpcode, payload: Vec<u8>) -> Self {
        Self {
            id: TrafficId::new(),
            session_id,
            direction,
            opcode,
            payload,
            created_at_ms: now_ms(),
        }
    }

    pub fn is_text(&self) -> bool {
        matches!(self.opcode, WsOpcode::Text)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.payload).to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketSession {
    pub id: TrafficId,
    pub handshake: Transaction,
    pub messages: Vec<WebSocketMessage>,
    pub closed_at_ms: Option<i64>,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
}

impl WebSocketSession {
    pub fn new(handshake: Transaction) -> Self {
        Self {
            id: handshake.id,
            handshake,
            messages: Vec::new(),
            closed_at_ms: None,
            close_code: None,
            close_reason: None,
        }
    }

    pub fn url(&self) -> String {
        self.handshake.request.url()
    }

    pub fn append(&mut self, msg: WebSocketMessage) {
        self.messages.push(msg);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_query(qs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if qs.is_empty() {
        return out;
    }
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, ""),
        };
        out.push((
            percent_encoding::percent_decode_str(k)
                .decode_utf8_lossy()
                .to_string(),
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .to_string(),
        ));
    }
    out
}

fn encode_query(params: &[(String, String)]) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    const FORM: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'&')
        .add(b'+')
        .add(b',')
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'<')
        .add(b'=')
        .add(b'>')
        .add(b'?')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}');
    params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, FORM),
                utf8_percent_encode(v, FORM)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

mod serde_bytes_vec {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        // Base64 keeps bodies compact and safe in JSON.
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        s.serialize_str(&STANDARD.encode(data))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use serde::Deserialize;
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

// Minimal base64 dep is pulled by the serde helper above. Reference it
// so `cargo check` keeps it as a direct dep in the crate graph (even
// though the dependency table in Cargo.toml adds it transitively via
// `blake3`'s features list).
#[allow(dead_code)]
fn _ensure_base64_is_linked() {
    use base64::Engine;
    let _ = base64::engine::general_purpose::STANDARD.encode(b"");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_roundtrips() {
        let r = Request::new("GET", "https://example.com:8443/path?a=1&b=2").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 8443);
        assert_eq!(r.path, "/path?a=1&b=2");
        assert_eq!(r.url(), "https://example.com:8443/path?a=1&b=2");
        assert_eq!(r.path_only(), "/path");
        assert_eq!(r.query_string(), "a=1&b=2");
        assert_eq!(r.query_params(), vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
    }

    #[test]
    fn request_wire_contains_target() {
        let mut r = Request::new("POST", "http://x.local/api").unwrap();
        r.set_text("hello");
        let w = r.to_wire_bytes();
        let s = String::from_utf8_lossy(&w);
        assert!(s.starts_with("POST /api HTTP/1.1\r\n"));
        assert!(s.contains("Content-Length: 5"));
        assert!(s.ends_with("hello"));
    }

    #[test]
    fn clone_with_new_id_sets_parent() {
        let r = Request::new("GET", "http://x.local/").unwrap();
        let r2 = r.clone_with_new_id(RequestSource::Repeater);
        assert_ne!(r.id, r2.id);
        assert_eq!(r2.parent_id, Some(r.id));
        assert_eq!(r2.source, RequestSource::Repeater);
    }

    #[test]
    fn query_params_set_roundtrip() {
        let mut r = Request::new("GET", "http://x.local/p?x=1").unwrap();
        r.set_query_params(&[("a".into(), "hello world".into()), ("b".into(), "é".into())]);
        let qp = r.query_params();
        assert_eq!(qp[0].1, "hello world");
        assert_eq!(qp[1].1, "é");
    }

    #[test]
    fn cookies_parse() {
        let mut r = Request::new("GET", "http://x.local/").unwrap();
        r.headers.set("Cookie", "a=1; b=2; c=hello world");
        assert_eq!(
            r.cookies(),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "2".into()),
                ("c".into(), "hello world".into()),
            ]
        );
    }

    #[test]
    fn ws_opcode_roundtrip() {
        for op in [
            WsOpcode::Text,
            WsOpcode::Binary,
            WsOpcode::Close,
            WsOpcode::Ping,
            WsOpcode::Pong,
            WsOpcode::Continuation,
        ] {
            assert_eq!(WsOpcode::from_u8(op.to_u8()), op);
        }
    }
}
