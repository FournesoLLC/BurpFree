//! Passive WebSocket scanner.
//!
//! Observes stored WebSocket frames and emits [`Finding`]s for leaked
//! secrets, tokens, and PII — mirroring the role [`crate::scanner::passive`]
//! plays for HTTP transactions.
//!
//! The detectors here are deliberately conservative, with distinctive
//! patterns (JWT shape, AWS prefix, PEM markers) preferred over broad
//! regexes to limit false positives on busy telemetry channels.

use burpfree_core::ids::TrafficId;
use burpfree_core::traffic::{WebSocketMessage, WsDirection};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{Confidence, Finding, Severity};

/// Minimum body length before we evaluate detectors — Ping/Pong keepalives
/// are too short to carry secrets.
const MIN_PAYLOAD_LEN: usize = 10;

/// Hard cap on evidence snippet length to keep findings readable.
const EVIDENCE_SNIPPET_MAX: usize = 160;

/// Context passed to every detector so findings can reference the owning
/// session and point back to the handshake URL.
#[derive(Debug, Clone)]
pub struct WsScanContext {
    pub session_id: TrafficId,
    /// Handshake URL (`ws://host:port/path` or `wss://...`). Used in
    /// evidence strings and the description.
    pub session_url: String,
    /// True when the handshake used `ws://` instead of `wss://`. Signals
    /// that whatever we flagged is also in transit over plaintext.
    pub insecure: bool,
}

pub trait WsPassiveDetector: Send + Sync {
    fn id(&self) -> &'static str;
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding>;
}

/// Scan a single WebSocket message against every built-in detector.
pub fn run_all(ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
    if msg.payload.len() < MIN_PAYLOAD_LEN {
        return Vec::new();
    }
    let detectors: &[&dyn WsPassiveDetector] = &[
        &JwtDetector,
        &BearerTokenDetector,
        &AwsAccessKeyDetector,
        &PrivateKeyMarkerDetector,
        &LabeledSecretDetector,
        &EmailDetector,
        &BasicAuthUrlDetector,
        // R945: 3 new WS detectors (7→10)
        &InternalIpDetector,
        &SqlErrorDetector,
        &StackTraceDetector,
    ];
    let mut out = Vec::new();
    for d in detectors {
        for mut f in d.run(ctx, msg) {
            f.transaction_id = Some(ctx.session_id);
            out.push(f);
        }
    }
    out
}

/// Convenience: scan all messages of one session.
pub fn scan_session(ctx: &WsScanContext, messages: &[WebSocketMessage]) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in messages {
        out.extend(run_all(ctx, m));
    }
    out
}

// ---------------------------------------------------------------------------
// Detector helpers
// ---------------------------------------------------------------------------

fn snippet(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.len() <= EVIDENCE_SNIPPET_MAX {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..EVIDENCE_SNIPPET_MAX])
    }
}

fn direction_label(d: WsDirection) -> &'static str {
    match d {
        WsDirection::Inbound => "server→client",
        WsDirection::Outbound => "client→server",
    }
}

/// Mask a secret so the evidence pane does not store it verbatim. We
/// keep the first four and last four characters and replace the middle
/// with asterisks — enough to recognise the token in logs without
/// echoing the full secret.
fn mask(token: &str) -> String {
    let n = token.chars().count();
    if n <= 10 {
        "*".repeat(n)
    } else {
        let head: String = token.chars().take(4).collect();
        let tail: String = token.chars().skip(n - 4).collect();
        format!("{head}***{tail}")
    }
}

fn bump_for_insecure(sev: Severity, insecure: bool) -> Severity {
    if !insecure {
        return sev;
    }
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

/// JWT (`eyJ`-prefixed, three dot-separated base64url segments).
pub struct JwtDetector;

static JWT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap());

impl WsPassiveDetector for JwtDetector {
    fn id(&self) -> &'static str { "passive-ws:jwt" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = JWT_RE.find(&text) else { return Vec::new(); };
        let token = m.as_str();
        let mut f = Finding::new(
            self.id(),
            "JWT exposed in WebSocket frame",
            bump_for_insecure(Severity::High, ctx.insecure),
            Confidence::Firm,
        );
        f.description = format!(
            "A JSON Web Token was observed in a {} WebSocket frame on `{}`. \
             Tokens carried over long-lived WebSocket channels linger in server-side \
             logs and in-memory caches, and leak via browser DevTools / HAR exports.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = format!("Token: `{}` (length {} bytes).", mask(token), token.len());
        f.remediation = "Rotate the exposed JWT, shorten its lifetime, and prefer passing it \
                         once during the handshake (via a secure cookie or Authorization header) \
                         rather than embedding it in every frame."
            .into();
        f.references = vec!["https://datatracker.ietf.org/doc/html/rfc7519".into()];
        f.cwe = vec!["CWE-522".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// `Authorization: Bearer ...` style tokens.
pub struct BearerTokenDetector;

static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})"#).unwrap());

impl WsPassiveDetector for BearerTokenDetector {
    fn id(&self) -> &'static str { "passive-ws:bearer-token" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(cap) = BEARER_RE.captures(&text) else { return Vec::new(); };
        let token = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if token.is_empty() {
            return Vec::new();
        }
        let mut f = Finding::new(
            self.id(),
            "Bearer token exposed in WebSocket frame",
            bump_for_insecure(Severity::High, ctx.insecure),
            Confidence::Firm,
        );
        f.description = format!(
            "A `Bearer` token was observed in a {} WebSocket frame on `{}`. \
             Bearer credentials are confidential; a disclosure in a WebSocket stream \
             typically means the token is also present in any proxy, log, or trace \
             along that channel.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = format!("Bearer `{}` (length {} bytes).", mask(token), token.len());
        f.remediation = "Scope the token tightly, keep its lifetime short, and avoid \
                         re-sending it inside the WebSocket data channel if it was already \
                         accepted at the handshake."
            .into();
        f.cwe = vec!["CWE-522".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// AWS access key IDs (`AKIA…` is the publicly documented prefix for
/// long-lived IAM user access keys).
pub struct AwsAccessKeyDetector;

static AWS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap());

impl WsPassiveDetector for AwsAccessKeyDetector {
    fn id(&self) -> &'static str { "passive-ws:aws-access-key" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = AWS_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "AWS access key ID in WebSocket frame",
            bump_for_insecure(Severity::Critical, ctx.insecure),
            Confidence::Certain,
        );
        f.description = format!(
            "An AWS access key ID was observed in a {} WebSocket frame on `{}`. \
             Even without the paired secret this is a credential leak worth rotating.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = format!("Access key: `{}`.", mask(m.as_str()));
        f.remediation = "Rotate the compromised credentials immediately and remove the \
                         access-key material from the application traffic path."
            .into();
        f.references = vec!["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html".into()];
        f.cwe = vec!["CWE-798".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// PEM-encoded private key markers.
pub struct PrivateKeyMarkerDetector;

static PEM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----").unwrap()
});

impl WsPassiveDetector for PrivateKeyMarkerDetector {
    fn id(&self) -> &'static str { "passive-ws:private-key" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = PEM_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "PEM private key marker in WebSocket frame",
            bump_for_insecure(Severity::Critical, ctx.insecure),
            Confidence::Certain,
        );
        f.description = format!(
            "A PEM `BEGIN … PRIVATE KEY` marker was observed in a {} WebSocket frame on `{}`. \
             Private keys should never be transported over an application data channel.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = m.as_str().to_string();
        f.remediation = "Rotate the key, remove it from the payload path, and audit how it \
                         ended up on the wire — it may be present in logs, backups, or \
                         downstream services as well."
            .into();
        f.cwe = vec!["CWE-312".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// Labelled secrets inside structured bodies — e.g.
/// `"password": "swordfish"`, `api_key=abcdef…`. We only trigger when the
/// name is one of a short vocabulary of sensitive keys, which keeps the
/// detector well under control on busy telemetry channels.
pub struct LabeledSecretDetector;

static LABELED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?xi)
        ["']?
        \b(?P<key>password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|session[_-]?token|secret[_-]?key|client[_-]?secret)\b
        ["']?
        \s*[:=]\s*
        ["']?(?P<val>[A-Za-z0-9+/._~\-]{8,})["']?
        "#,
    )
    .unwrap()
});

impl WsPassiveDetector for LabeledSecretDetector {
    fn id(&self) -> &'static str { "passive-ws:labeled-secret" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(cap) = LABELED_RE.captures(&text) else { return Vec::new(); };
        let key = cap.name("key").map(|m| m.as_str()).unwrap_or("secret");
        let val = cap.name("val").map(|m| m.as_str()).unwrap_or("");
        if val.is_empty() {
            return Vec::new();
        }
        let mut f = Finding::new(
            self.id(),
            &format!("Labelled secret `{}` in WebSocket frame", key),
            bump_for_insecure(Severity::High, ctx.insecure),
            Confidence::Firm,
        );
        f.description = format!(
            "A `{key}` field with a non-trivial value was observed in a {} WebSocket frame on `{}`. \
             Credentials and API tokens embedded in frames tend to leak into logs and client-side \
             storage.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = format!("`{key}` = `{}` (length {} bytes).", mask(val), val.len());
        f.remediation = "Prefer short-lived capability tokens exchanged out of band; never \
                         transport long-lived passwords in application traffic."
            .into();
        f.cwe = vec!["CWE-522".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// Simple email-address detector, Info severity. Useful to spot PII
/// egress through a chat / notification channel.
pub struct EmailDetector;

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());

impl WsPassiveDetector for EmailDetector {
    fn id(&self) -> &'static str { "passive-ws:email" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let mut emails: Vec<&str> = EMAIL_RE.find_iter(&text).map(|m| m.as_str()).collect();
        emails.sort();
        emails.dedup();
        if emails.is_empty() {
            return Vec::new();
        }
        let mut f = Finding::new(
            self.id(),
            "Email address observed in WebSocket frame",
            bump_for_insecure(Severity::Info, ctx.insecure),
            Confidence::Firm,
        );
        f.description = format!(
            "{} email address(es) were observed in a {} WebSocket frame on `{}`. \
             This is often expected (notifications, chat) but worth confirming the \
             channel is appropriate for PII.",
            emails.len(),
            direction_label(msg.direction),
            ctx.session_url
        );
        let shown: Vec<String> = emails.iter().take(5).map(|e| mask(e)).collect();
        f.evidence = shown.join(", ");
        f.remediation = "Confirm the WebSocket channel is appropriate for PII and that \
                         it is not relayed to systems with weaker protection."
            .into();
        f.cwe = vec!["CWE-359".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

/// HTTP URL with embedded `user:pass@host` basic auth material.
pub struct BasicAuthUrlDetector;

static AUTH_URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"https?://[^\s/:@]+:[^\s/:@]+@[^\s/]+").unwrap());

impl WsPassiveDetector for BasicAuthUrlDetector {
    fn id(&self) -> &'static str { "passive-ws:auth-url" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = AUTH_URL_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "URL with embedded credentials in WebSocket frame",
            bump_for_insecure(Severity::High, ctx.insecure),
            Confidence::Firm,
        );
        f.description = format!(
            "A URL carrying `user:pass@host` basic auth material was observed in a {} \
             WebSocket frame on `{}`. These URLs leak into referrer headers, server \
             logs, and browser history.",
            direction_label(msg.direction),
            ctx.session_url
        );
        f.evidence = snippet(m.as_str().as_bytes());
        f.remediation = "Pass credentials via an Authorization header instead of embedding \
                         them in the URL authority component."
            .into();
        f.cwe = vec!["CWE-598".into()];
        f.insertion_point = Some(format!("ws:{}", direction_label(msg.direction)));
        vec![f]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::ids::TrafficId;
    use burpfree_core::traffic::{WebSocketMessage, WsOpcode};

    fn ctx(insecure: bool) -> WsScanContext {
        WsScanContext {
            session_id: TrafficId::new(),
            session_url: if insecure {
                "ws://chat.example/room/42".into()
            } else {
                "wss://chat.example/room/42".into()
            },
            insecure,
        }
    }

    fn msg(payload: &[u8], direction: WsDirection) -> WebSocketMessage {
        WebSocketMessage::new(TrafficId::new(), direction, WsOpcode::Text, payload.to_vec())
    }

    #[test]
    fn finds_jwt() {
        let p = br#"{"type":"auth","jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZTEyMyJ9.sign4turebytes"}"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:jwt"));
    }

    #[test]
    fn finds_bearer_token() {
        let p = br#"{"headers":{"Authorization":"Bearer abcdefghijklmnopqrstuvwxyz"}}"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:bearer-token"));
    }

    #[test]
    fn finds_aws_access_key_id() {
        let p = b"region=us-east-1&accessKey=AKIAIOSFODNN7EXAMPLE";
        let f = run_all(&ctx(false), &msg(p, WsDirection::Inbound));
        let hit = f
            .iter()
            .find(|x| x.detector == "passive-ws:aws-access-key")
            .expect("aws key detector should fire");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn finds_private_key_marker() {
        let p = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA...";
        let f = run_all(&ctx(false), &msg(p, WsDirection::Inbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:private-key"));
    }

    #[test]
    fn finds_labeled_password() {
        let p = br#"{"username":"alice","password":"swordfish-9000"}"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:labeled-secret"));
    }

    #[test]
    fn finds_api_key_label() {
        let p = br#"api_key=1234567890abcdef1234567890"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:labeled-secret"));
    }

    #[test]
    fn finds_email_but_as_info() {
        let p = br#"{"to":"user@example.com","subject":"ping"}"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Inbound));
        let hit = f.iter().find(|x| x.detector == "passive-ws:email").unwrap();
        assert_eq!(hit.severity, Severity::Info);
    }

    #[test]
    fn finds_basic_auth_url() {
        let p = br#"redirect to https://admin:hunter2@internal.example/app"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Inbound));
        assert!(f.iter().any(|x| x.detector == "passive-ws:auth-url"));
    }

    #[test]
    fn clean_payload_is_quiet() {
        let p = br#"{"type":"heartbeat","seq":42}"#;
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.is_empty(), "clean payloads should not fire detectors; got {}", f.len());
    }

    #[test]
    fn short_payload_is_skipped() {
        // Even a JWT-like short payload should be ignored under MIN_PAYLOAD_LEN.
        let p = b"abc";
        let f = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        assert!(f.is_empty());
    }

    #[test]
    fn insecure_scheme_bumps_severity() {
        let p = br#"{"headers":{"Authorization":"Bearer abcdefghijklmnopqrstuvwxyz"}}"#;
        let secure = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        let insecure = run_all(&ctx(true), &msg(p, WsDirection::Outbound));
        let s = secure
            .iter()
            .find(|x| x.detector == "passive-ws:bearer-token")
            .unwrap();
        let i = insecure
            .iter()
            .find(|x| x.detector == "passive-ws:bearer-token")
            .unwrap();
        assert_eq!(s.severity, Severity::High);
        assert_eq!(i.severity, Severity::Critical);
    }

    #[test]
    fn mask_hides_middle_of_token() {
        assert_eq!(mask("abcd1234ef"), "**********");
        assert_eq!(mask("abcd1234efghij"), "abcd***ghij");
    }

    #[test]
    fn direction_recorded_in_insertion_point() {
        let p = br#"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signaturebytes"#;
        let f_out = run_all(&ctx(false), &msg(p, WsDirection::Outbound));
        let f_in = run_all(&ctx(false), &msg(p, WsDirection::Inbound));
        assert!(f_out
            .iter()
            .find(|x| x.detector == "passive-ws:jwt")
            .unwrap()
            .insertion_point
            .as_deref()
            .unwrap()
            .contains("client→server"));
        assert!(f_in
            .iter()
            .find(|x| x.detector == "passive-ws:jwt")
            .unwrap()
            .insertion_point
            .as_deref()
            .unwrap()
            .contains("server→client"));
    }
}


// ---------------------------------------------------------------------------
// R945: 3 new WebSocket passive detectors (7→10)
// ---------------------------------------------------------------------------

/// Detect private/internal IP addresses leaked in WebSocket frames.
pub struct InternalIpDetector;

static INTERNAL_IP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b").unwrap());

impl WsPassiveDetector for InternalIpDetector {
    fn id(&self) -> &'static str { "passive-ws:internal-ip" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = INTERNAL_IP_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "Internal IP address in WebSocket frame",
            Severity::Low,
            Confidence::Firm,
        );
        f.evidence = m.as_str().to_string();
        f.description = "A private/internal IP address was found in a WebSocket message, potentially revealing internal network topology.".into();
        vec![f]
    }
}

/// Detect SQL error messages in WebSocket frames.
pub struct SqlErrorDetector;

static SQL_ERROR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(SQL syntax|mysql_fetch|ORA-\d+|pg_query|sqlite3\.OperationalError|SQLSTATE|Unclosed quotation)").unwrap());

impl WsPassiveDetector for SqlErrorDetector {
    fn id(&self) -> &'static str { "passive-ws:sql-error" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = SQL_ERROR_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "SQL error message in WebSocket frame",
            bump_for_insecure(Severity::Medium, ctx.insecure),
            Confidence::Firm,
        );
        f.evidence = m.as_str().to_string();
        f.description = "A database error message was found in a WebSocket message, potentially indicating SQL injection vulnerability or excessive error verbosity.".into();
        vec![f]
    }
}

/// Detect stack traces in WebSocket frames (Java, Python, .NET, Node.js).
pub struct StackTraceDetector;

static STACK_TRACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:at [a-zA-Z0-9$_.]+\([A-Za-z0-9]+\.java:\d+\)|File "[^"]+\.py", line \d+|at [A-Za-z0-9_.]+\.[A-Za-z0-9_]+\([^)]*\) in [A-Za-z]:|at .+\(.+:\d+:\d+\))"#).unwrap());

impl WsPassiveDetector for StackTraceDetector {
    fn id(&self) -> &'static str { "passive-ws:stack-trace" }
    fn run(&self, ctx: &WsScanContext, msg: &WebSocketMessage) -> Vec<Finding> {
        let text = String::from_utf8_lossy(&msg.payload);
        let Some(m) = STACK_TRACE_RE.find(&text) else { return Vec::new(); };
        let mut f = Finding::new(
            self.id(),
            "Stack trace in WebSocket frame",
            Severity::Low,
            Confidence::Firm,
        );
        f.evidence = m.as_str().to_string();
        f.description = "A stack trace was found in a WebSocket message, potentially revealing internal class paths, file paths, and application versions.".into();
        vec![f]
    }
}
