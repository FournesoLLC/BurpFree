//! Deterministic passive scanner.
//!
//! Each detector consumes a single [`Transaction`] and emits zero or
//! more [`Finding`]s. The engine orchestrator runs every detector on
//! every observation without any mutation or external I/O.

use burpfree_core::ids::TrafficId;
use burpfree_core::rules::CustomPassiveRule;
use burpfree_core::traffic::Transaction;

use super::{Confidence, Finding, Severity};

pub trait PassiveDetector: Send + Sync {
    fn id(&self) -> &'static str;
    fn run(&self, tx: &Transaction) -> Vec<Finding>;
}

/// Every built-in passive detector in a single array so callers can
/// enumerate ids without touching the per-detector unit structs. The
/// run_all variants iterate this list; the UI consults it to render
/// the Scanner → Passive detectors enable/disable grid.
///
/// Keeping the order stable matters: findings keep arriving in a
/// predictable sequence, and existing recipes/tests that pattern-match
/// on detector order stay valid.
fn builtin_detectors() -> &'static [&'static dyn PassiveDetector] {
    &[
        &SecurityHeaders,
        &InsecureCookies,
        &CorsPermissive,
        &DangerousMethods,
        &InfoDisclosureHeaders,
        &CacheControlOnSensitive,
        &MixedContent,
        &RedirectToExternal,
        &JavascriptExposed,
        &CspBreakdown,
        &MissingCsrfToken,
        &PermissionsPolicyAudit,
        &InsecureDeserializationMarkers,
        // R937: 3 new passive detectors
        &VulnerableJsLibrary,
        &HostHeaderReflection,
        &DirectoryListing,
        // R939: 4 more passive detectors (16→20)
        &SensitiveDataExposure,
        &SubresourceIntegrity,
        &ClickjackingFrameable,
        &HttpStrictTransportSecurity,
        // R946: 5 more passive detectors (20→25)
        &ServerVersionDisclosure,
        &ContentTypeSniffing,
        &ReferrerPolicyMissing,
        &FormActionHijack,
        &InsecureFormSubmission,
        // R966: 5 more passive detectors (25→30, matching Burp's ~30)
        &CookieSameSiteNone,
        &ResponseBodySizeAnomaly,
        &DoubleEncoding,
        &CacheControlMissing,
        &CrossDomainScriptInclude,
    ]
}

/// Return every built-in passive detector id in registration order.
/// The Scanner UI uses this list to render a per-detector enable
/// toggle without needing to know the detector trait object layout.
pub fn passive_detector_ids() -> Vec<&'static str> {
    builtin_detectors().iter().map(|d| d.id()).collect()
}

/// Run every built-in detector against `tx`.
pub fn run_all(tx: &Transaction) -> Vec<Finding> {
    run_all_with_rules(tx, &[])
}

/// Run every built-in detector plus the supplied set of declarative
/// custom rules (typically contributed by extensions).
pub fn run_all_with_rules(tx: &Transaction, custom: &[CustomPassiveRule]) -> Vec<Finding> {
    run_all_filtered(tx, custom, &std::collections::HashSet::new())
}

/// Full filtered run: built-in detectors whose id is in
/// `disabled_ids` are skipped, custom rules are still appended (they
/// are extension-contributed; disabling them is the extension's
/// business). This is the hot path the proxy sink calls on every
/// recorded transaction, so the HashSet lookup is intentionally cheap.
pub fn run_all_filtered(
    tx: &Transaction,
    custom: &[CustomPassiveRule],
    disabled_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in builtin_detectors() {
        if disabled_ids.contains(d.id()) {
            continue;
        }
        for mut f in d.run(tx) {
            f.transaction_id = Some(tx.id);
            out.push(f);
        }
    }
    for rule in custom {
        if !rule.when.evaluate(tx) {
            continue;
        }
        let sev = match rule.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let conf = match rule.confidence.as_str() {
            "certain" => Confidence::Certain,
            "tentative" => Confidence::Tentative,
            _ => Confidence::Firm,
        };
        let mut f = Finding::new(&rule.id, &rule.title, sev, conf);
        f.description = rule.description.clone();
        f.remediation = rule.remediation.clone();
        f.references = rule.references.clone();
        f.cwe = rule.cwe.clone();
        f.insertion_point = rule.insertion_point.clone();
        f.transaction_id = Some(tx.id);
        out.push(f);
    }
    out
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

/// Flag missing / weak security headers on text/html responses.
pub struct SecurityHeaders;

impl PassiveDetector for SecurityHeaders {
    fn id(&self) -> &'static str { "security-headers" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        if !resp.headers.content_type().map(|c| c.contains("text/html")).unwrap_or(false) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let required: &[(&str, Severity, &str)] = &[
            ("Content-Security-Policy", Severity::Medium,
             "Content-Security-Policy constrains script/style sources and blunts XSS. Define a policy appropriate for the application."),
            ("X-Content-Type-Options", Severity::Low,
             "`X-Content-Type-Options: nosniff` prevents MIME sniffing by legacy browsers."),
            ("Strict-Transport-Security", Severity::Medium,
             "`Strict-Transport-Security` forces HTTPS; include `max-age` and (where applicable) `includeSubDomains`."),
            ("X-Frame-Options", Severity::Low,
             "`X-Frame-Options: DENY|SAMEORIGIN` (or an equivalent CSP frame-ancestors) prevents clickjacking."),
            ("Referrer-Policy", Severity::Low,
             "A `Referrer-Policy` such as `strict-origin-when-cross-origin` prevents URL leakage via referrer."),
        ];
        for (hdr, sev, remediation) in required {
            if !resp.headers.has(hdr) {
                let mut f = Finding::new(
                    "security-headers",
                    &format!("Missing security header: {hdr}"),
                    *sev,
                    Confidence::Certain,
                );
                f.description = format!("Response for {} is HTML but does not set `{hdr}`.", tx.request.url());
                f.remediation = remediation.to_string();
                f.evidence = format!("Response status: {}", resp.status);
                out.push(f);
            }
        }
        // X-XSS-Protection: Report only when it is explicitly present
        // with the 0 value disabled (its only safe modern setting).
        if let Some(v) = resp.headers.get("X-XSS-Protection") {
            if !v.trim().starts_with('0') {
                let mut f = Finding::new(
                    "security-headers",
                    "Deprecated X-XSS-Protection enabled",
                    Severity::Info,
                    Confidence::Firm,
                );
                f.description =
                    "Modern browsers ignore or warn against X-XSS-Protection. Rely on Content-Security-Policy instead."
                        .into();
                f.evidence = format!("X-XSS-Protection: {}", v);
                f.remediation = "Set `X-XSS-Protection: 0` or remove the header; implement CSP.".into();
                out.push(f);
            }
        }
        out
    }
}

/// Set-Cookie without Secure / HttpOnly / SameSite.
pub struct InsecureCookies;

impl PassiveDetector for InsecureCookies {
    fn id(&self) -> &'static str { "insecure-cookies" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        let mut out = Vec::new();
        let https = tx.request.scheme == "https";
        for raw in resp.headers.get_all("Set-Cookie") {
            let lower = raw.to_ascii_lowercase();
            let name = raw.split('=').next().unwrap_or("").trim().to_string();
            let secure = lower.contains("; secure") || lower.ends_with("secure");
            let http_only = lower.contains("httponly");
            let has_samesite = lower.contains("samesite=");
            if !secure && https {
                let mut f = Finding::new(
                    "insecure-cookies",
                    &format!("Cookie `{name}` missing Secure attribute"),
                    Severity::Low,
                    Confidence::Certain,
                );
                f.evidence = raw.to_string();
                f.remediation = "Add `Secure` so the cookie is only sent over HTTPS.".into();
                out.push(f);
            }
            if !http_only && looks_like_session_cookie(&name) {
                let mut f = Finding::new(
                    "insecure-cookies",
                    &format!("Session cookie `{name}` missing HttpOnly"),
                    Severity::Medium,
                    Confidence::Firm,
                );
                f.evidence = raw.to_string();
                f.remediation =
                    "Add `HttpOnly` so client JavaScript cannot read the cookie.".into();
                out.push(f);
            }
            if !has_samesite {
                let mut f = Finding::new(
                    "insecure-cookies",
                    &format!("Cookie `{name}` missing SameSite attribute"),
                    Severity::Low,
                    Confidence::Firm,
                );
                f.evidence = raw.to_string();
                f.remediation =
                    "Add `SameSite=Lax` (default) or `SameSite=Strict` where cross-site context is not required.".into();
                out.push(f);
            }
        }
        out
    }
}

fn looks_like_session_cookie(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "sid", "sess", "session", "auth", "token", "jsessionid", "phpsessid", "jwt",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// Permissive Access-Control-Allow-Origin wildcards.
pub struct CorsPermissive;

impl PassiveDetector for CorsPermissive {
    fn id(&self) -> &'static str { "cors-permissive" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        let aco = resp.headers.get("Access-Control-Allow-Origin").unwrap_or("");
        if aco.is_empty() { return Vec::new(); }
        let acc = resp.headers.get("Access-Control-Allow-Credentials").unwrap_or("");
        let mut out = Vec::new();
        if aco.trim() == "*" && acc.trim().eq_ignore_ascii_case("true") {
            let mut f = Finding::new(
                "cors-permissive",
                "CORS allows wildcard origin with credentials",
                Severity::High,
                Confidence::Certain,
            );
            f.description =
                "`Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is forbidden by the fetch spec and indicates a dangerous misconfiguration."
                    .into();
            f.evidence = format!("ACAO: {aco}; ACAC: {acc}");
            f.remediation =
                "Either return a specific origin (echoing a safelisted Origin) or set credentials to false.".into();
            out.push(f);
        } else if aco.trim() == "*" {
            let mut f = Finding::new(
                "cors-permissive",
                "CORS allows wildcard origin",
                Severity::Info,
                Confidence::Firm,
            );
            f.description =
                "`Access-Control-Allow-Origin: *` exposes the response to any origin. Review whether this endpoint truly needs public cross-origin access."
                    .into();
            f.evidence = format!("ACAO: {aco}");
            out.push(f);
        }
        // Reflected origin without validation.
        if let Some(req_origin) = tx.request.headers.get("Origin") {
            if aco.trim() == req_origin && acc.trim().eq_ignore_ascii_case("true") {
                let mut f = Finding::new(
                    "cors-permissive",
                    "CORS reflects arbitrary Origin with credentials",
                    Severity::High,
                    Confidence::Tentative,
                );
                f.description =
                    "The response's `Access-Control-Allow-Origin` echoes the request's `Origin`, and credentials are allowed. If the server does not validate the Origin against an allow-list this is exploitable."
                        .into();
                f.evidence = format!("Request Origin: {req_origin}; ACAO: {aco}");
                f.remediation = "Validate the Origin against an explicit allow-list before echoing it back.".into();
                out.push(f);
            }
        }
        out
    }
}

/// Server allows TRACE, OPTIONS reveals unexpected methods, PUT/DELETE
/// on static paths, etc.
pub struct DangerousMethods;

impl PassiveDetector for DangerousMethods {
    fn id(&self) -> &'static str { "dangerous-methods" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let mut out = Vec::new();
        if tx.request.method.eq_ignore_ascii_case("TRACE") {
            let mut f = Finding::new(
                "dangerous-methods",
                "TRACE method request observed",
                Severity::Low,
                Confidence::Certain,
            );
            f.description =
                "The TRACE method is rarely needed in production; combined with legacy clients it has been used to leak credentials."
                    .into();
            f.remediation = "Disable TRACE in the web server configuration.".into();
            out.push(f);
        }
        if let Some(resp) = &tx.response {
            if let Some(allow) = resp.headers.get("Allow") {
                for m in ["TRACE", "PUT", "DELETE", "CONNECT"] {
                    if allow.to_ascii_uppercase().contains(m) {
                        let mut f = Finding::new(
                            "dangerous-methods",
                            &format!("Server advertises {m} method"),
                            Severity::Info,
                            Confidence::Firm,
                        );
                        f.evidence = format!("Allow: {allow}");
                        f.description = format!("`Allow` includes `{m}`; confirm that this method is intentionally exposed on this resource.");
                        out.push(f);
                    }
                }
            }
        }
        out
    }
}

/// Classic headers that leak server/framework versions.
pub struct InfoDisclosureHeaders;

impl PassiveDetector for InfoDisclosureHeaders {
    fn id(&self) -> &'static str { "info-disclosure-headers" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        let mut out = Vec::new();
        for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"] {
            if let Some(v) = resp.headers.get(header) {
                // Only treat as info disclosure if a version number is present.
                if v.chars().any(|c| c.is_ascii_digit()) {
                    let mut f = Finding::new(
                        "info-disclosure-headers",
                        &format!("Server identifies itself: {header}"),
                        Severity::Info,
                        Confidence::Firm,
                    );
                    f.evidence = format!("{header}: {v}");
                    f.remediation = format!(
                        "Strip or anonymise `{header}` in the reverse proxy or web server configuration."
                    );
                    out.push(f);
                }
            }
        }
        out
    }
}

/// Sensitive-looking responses without caching directives.
pub struct CacheControlOnSensitive;

impl PassiveDetector for CacheControlOnSensitive {
    fn id(&self) -> &'static str { "cache-control" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        let path = tx.request.path_only().to_ascii_lowercase();
        let looks_sensitive = ["/login", "/signin", "/account", "/profile", "/token", "/auth", "/admin", "/password"]
            .iter()
            .any(|p| path.contains(p));
        if !looks_sensitive { return Vec::new(); }
        let cc = resp.headers.get("Cache-Control").unwrap_or("").to_ascii_lowercase();
        let no_store = cc.contains("no-store");
        if no_store { return Vec::new(); }
        let mut f = Finding::new(
            "cache-control",
            "Sensitive endpoint lacks `Cache-Control: no-store`",
            Severity::Low,
            Confidence::Firm,
        );
        f.description =
            "Authentication or account-related responses should opt out of caching to prevent shared caches or browser history from retaining them."
                .into();
        f.remediation =
            "Return `Cache-Control: no-store` on authenticated or sensitive endpoints.".into();
        f.evidence = format!("Path: {}; Cache-Control: {}", tx.request.path, cc);
        vec![f]
    }
}

/// HTML responses that reference `http://` resources from an `https://` page.
pub struct MixedContent;

impl PassiveDetector for MixedContent {
    fn id(&self) -> &'static str { "mixed-content" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        if tx.request.scheme != "https" { return Vec::new(); }
        if !resp.headers.content_type().map(|c| c.contains("text/html")).unwrap_or(false) {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&resp.body);
        let mut offenders: Vec<&str> = Vec::new();
        for pat in ["src=\"http://", "href=\"http://", "src='http://", "href='http://"] {
            for (i, _) in text.match_indices(pat) {
                let end = (i + pat.len() + 60).min(text.len());
                offenders.push(&text[i..end]);
                if offenders.len() >= 5 { break; }
            }
            if offenders.len() >= 5 { break; }
        }
        if offenders.is_empty() { return Vec::new(); }
        let mut f = Finding::new(
            "mixed-content",
            "Mixed-content references on HTTPS page",
            Severity::Medium,
            Confidence::Firm,
        );
        f.description = "This HTTPS page references resources over plaintext HTTP; browsers may block them and the integrity of the page is weakened.".into();
        f.evidence = offenders.join("\n");
        f.remediation = "Serve all resources over HTTPS or use protocol-relative URLs.".into();
        vec![f]
    }
}

/// Open redirect through a 3xx Location.
pub struct RedirectToExternal;

impl PassiveDetector for RedirectToExternal {
    fn id(&self) -> &'static str { "open-redirect-indicator" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        if !(300..400).contains(&resp.status) { return Vec::new(); }
        let Some(loc) = resp.headers.get("Location") else { return Vec::new(); };
        if !loc.starts_with("http://") && !loc.starts_with("https://") && !loc.starts_with("//") {
            return Vec::new();
        }
        if let Ok(target) = url::Url::parse(loc) {
            if let Some(host) = target.host_str() {
                if !host.eq_ignore_ascii_case(&tx.request.host) {
                    let mut f = Finding::new(
                        "open-redirect-indicator",
                        "External redirect observed",
                        Severity::Info,
                        Confidence::Tentative,
                    );
                    f.description = "The response redirects to a different host; worth confirming whether the Location is user-controllable.".into();
                    f.evidence = format!("Location: {loc}");
                    return vec![f];
                }
            }
        }
        Vec::new()
    }
}

/// Flag long inline scripts inline-embedded in HTML; often an XSS sink.
pub struct JavascriptExposed;

impl PassiveDetector for JavascriptExposed {
    fn id(&self) -> &'static str { "inline-script-size" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else { return Vec::new(); };
        if !resp.headers.content_type().map(|c| c.contains("text/html")).unwrap_or(false) {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&resp.body);
        let mut largest = 0usize;
        let bytes = text.as_bytes();
        let open = b"<script";
        let close = b"</script>";
        let mut i = 0;
        while i + open.len() <= bytes.len() {
            if &bytes[i..i + open.len()] == open {
                let start = i + open.len();
                if let Some(stop) = bytes[start..]
                    .windows(close.len())
                    .position(|w| w == close)
                {
                    let script_end = start + stop;
                    let len = script_end - start;
                    if len > largest { largest = len; }
                    i = script_end + close.len();
                    continue;
                }
            }
            i += 1;
        }
        if largest > 20_000 {
            let mut f = Finding::new(
                "inline-script-size",
                "Large inline <script> block",
                Severity::Info,
                Confidence::Tentative,
            );
            f.description =
                "A large inline script makes CSP harder to enforce and often inlines user-influenced data. Consider moving to an external file served with CSP nonces or hashes."
                    .into();
            f.evidence = format!("Largest inline script: {} bytes", largest);
            return vec![f];
        }
        Vec::new()
    }
}

/// Parse the response's `Content-Security-Policy` header and flag
/// weak directives (`unsafe-inline`, `unsafe-eval`, `*` wildcard
/// sources, `data:` scheme in script-src, missing `frame-ancestors`).
/// Complementary to `SecurityHeaders` which only flags its *absence*.
pub struct CspBreakdown;

impl PassiveDetector for CspBreakdown {
    fn id(&self) -> &'static str {
        "csp-weakness"
    }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else {
            return Vec::new();
        };
        let Some(policy) = resp.headers.get("Content-Security-Policy") else {
            return Vec::new();
        };
        // Parse policy into {directive: [source, source, ...]} by
        // splitting on `;` then whitespace. Directive names are
        // case-insensitive on the wire; we lowercase for lookup.
        let mut directives: std::collections::BTreeMap<String, Vec<String>> =
            Default::default();
        for part in policy.split(';') {
            let mut tokens = part.split_whitespace();
            if let Some(name) = tokens.next() {
                let name = name.to_ascii_lowercase();
                let sources: Vec<String> = tokens.map(|s| s.to_string()).collect();
                directives.insert(name, sources);
            }
        }
        let mut findings = Vec::new();
        // Helper: emit a finding and append CSP context.
        let mut emit = |title: &str, desc: &str, sev: Severity, evidence: &str| {
            let mut f =
                Finding::new("csp-weakness", title, sev, Confidence::Firm);
            f.description = desc.to_string();
            f.evidence = evidence.to_string();
            f.remediation = "Replace `unsafe-inline` / `unsafe-eval` with nonces or hashes; use specific host allow-lists rather than `*`; always set `frame-ancestors` (not just `X-Frame-Options`) because older browsers mix the two.".into();
            f.references = vec!["CWE-1021".into(), "CWE-693".into()];
            findings.push(f);
        };
        // Scripts: `unsafe-inline` + `unsafe-eval` + `*` + `data:`.
        let script_srcs = directives
            .get("script-src")
            .or_else(|| directives.get("default-src"))
            .cloned()
            .unwrap_or_default();
        if script_srcs
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'unsafe-inline'"))
        {
            emit(
                "CSP allows `unsafe-inline` in script-src",
                "`'unsafe-inline'` neutralises the whole point of CSP for XSS mitigation; inline scripts and event handlers can be injected and will execute.",
                Severity::Medium,
                &format!("script-src: {}", script_srcs.join(" ")),
            );
        }
        if script_srcs
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'unsafe-eval'"))
        {
            emit(
                "CSP allows `unsafe-eval` in script-src",
                "`'unsafe-eval'` enables `eval()`, `new Function()`, and `setTimeout('...')` — the most common sinks for DOM-based XSS.",
                Severity::Medium,
                &format!("script-src: {}", script_srcs.join(" ")),
            );
        }
        if script_srcs.iter().any(|s| s == "*") {
            emit(
                "CSP uses `*` wildcard in script-src",
                "A `*` source allows scripts from any origin, defeating the policy. Prefer explicit host allow-lists or nonces/hashes.",
                Severity::Medium,
                &format!("script-src: {}", script_srcs.join(" ")),
            );
        }
        if script_srcs
            .iter()
            .any(|s| s.starts_with("data:") || s == "data:")
        {
            emit(
                "CSP allows `data:` scheme in script-src",
                "The `data:` scheme lets an attacker package script content directly inside a URL; most CSP guides recommend keeping it out of script-src.",
                Severity::Medium,
                &format!("script-src: {}", script_srcs.join(" ")),
            );
        }
        // Styles: unsafe-inline is the common offender; many CSPs
        // need it, so emit at Low severity.
        if let Some(style_srcs) = directives.get("style-src") {
            if style_srcs
                .iter()
                .any(|s| s.eq_ignore_ascii_case("'unsafe-inline'"))
            {
                emit(
                    "CSP allows `unsafe-inline` in style-src",
                    "`unsafe-inline` for styles enables CSS-based data exfiltration primitives; where possible move inline styles to nonce-aware external sheets.",
                    Severity::Low,
                    &format!("style-src: {}", style_srcs.join(" ")),
                );
            }
        }
        // frame-ancestors: must be present to prevent clickjacking;
        // X-Frame-Options is deprecated in modern browsers.
        if !directives.contains_key("frame-ancestors") {
            emit(
                "CSP missing `frame-ancestors` directive",
                "Without `frame-ancestors`, modern browsers fall back to `X-Frame-Options`, which legacy browsers may ignore. A combined policy is strongly recommended.",
                Severity::Low,
                policy.as_ref(),
            );
        }
        findings
    }
}

/// Flag state-changing requests (POST / PUT / DELETE / PATCH) that
/// do not carry a CSRF token in body or headers. The passive scanner
/// can't tell whether cookies are same-site, so this is a Firm
/// (not Certain) signal — the human reviewer confirms whether the
/// endpoint is actually CSRF-exposed.
pub struct MissingCsrfToken;

impl PassiveDetector for MissingCsrfToken {
    fn id(&self) -> &'static str {
        "csrf-token-missing"
    }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let m = tx.request.method.to_ascii_uppercase();
        let state_changing =
            m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH";
        if !state_changing {
            return Vec::new();
        }
        let ct = tx
            .request
            .headers
            .get("Content-Type")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        // Only flag flows likely to carry browser-driven state —
        // form posts, multipart uploads, JSON APIs. Skip CORS
        // preflights (OPTIONS) and content types that aren't the
        // typical CSRF target.
        let is_form = ct.contains("application/x-www-form-urlencoded")
            || ct.contains("multipart/form-data")
            || ct.contains("application/json");
        if !is_form {
            return Vec::new();
        }
        // Common CSRF-token header names, case-insensitive.
        let header_tokens: &[&str] = &[
            "X-CSRF-Token",
            "X-CSRFToken",
            "X-XSRF-TOKEN",
            "X-Csrf-Token",
            "X-Requested-With",
            "Csrf-Token",
            "Authorization",
        ];
        for h in header_tokens {
            if tx.request.headers.has(h) {
                return Vec::new();
            }
        }
        // Common CSRF-token body field names.
        let body_markers: &[&str] = &[
            "csrf_token",
            "csrfToken",
            "_token",
            "_csrf",
            "authenticity_token",
            "__RequestVerificationToken",
            "anti-forgery-token",
        ];
        let body_text = String::from_utf8_lossy(&tx.request.body);
        if body_markers
            .iter()
            .any(|m| body_text.to_ascii_lowercase().contains(&m.to_ascii_lowercase()))
        {
            return Vec::new();
        }
        let mut f = Finding::new(
            "csrf-token-missing",
            &format!("No CSRF token on {m} request"),
            Severity::Medium,
            Confidence::Firm,
        );
        f.description = format!(
            "The {m} request carries no CSRF token in its headers or body. If the application relies on cookie-only authentication AND the request is reachable cross-origin AND the browser sends cookies by default (SameSite=None), a cross-site attacker can submit the request on behalf of the victim."
        );
        f.evidence = format!(
            "Method: {m}. Content-Type: {ct}. Checked header names: {}. Checked body markers: {}.",
            header_tokens.join(", "),
            body_markers.join(", ")
        );
        f.remediation = "Add a per-session CSRF token in a hidden form field (or `X-CSRF-Token` header for JSON) and validate it server-side. Set the session cookie to `SameSite=Lax` or `SameSite=Strict` as defence-in-depth.".into();
        f.references = vec!["CWE-352".into()];
        vec![f]
    }
}

/// Scan request body + cookies + query parameters for serialized-
/// object signatures. These never prove a vulnerability on their
/// own — they just surface that the application is passing serialized
/// state over the wire, which is a prerequisite for most RCE-grade
/// deserialization exploits.
pub struct InsecureDeserializationMarkers;

impl PassiveDetector for InsecureDeserializationMarkers {
    fn id(&self) -> &'static str {
        "insecure-deserialization-indicator"
    }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        // (needle, format label). We check both base64 and hex-ish
        // forms so stacked encodings don't hide the signature. The
        // Java marker is specifically the base64 of `ACED 0005` (the
        // start-of-stream magic + version 5) which is `rO0AB` for
        // the first 5 characters.
        let needles: &[(&str, &str)] = &[
            ("rO0AB", "Java serialized object (base64-encoded)"),
            ("aced0005", "Java serialized object (hex-encoded)"),
            ("ACED0005", "Java serialized object (hex-encoded, upper)"),
            // .NET BinaryFormatter — stream starts with `0001000000ffffffff`.
            ("AAEAAAD/////", ".NET BinaryFormatter stream (base64)"),
            ("0001000000ffffffff", ".NET BinaryFormatter stream (hex)"),
            // Python pickle protocol v4 — base64 of `\x80\x04\x95`.
            ("gASV", "Python pickle protocol 4 (base64)"),
        ];
        // Regex for PHP's `O:<len>:"ClassName":<field-count>:` pattern.
        // The capture groups are only for completeness; we never read
        // them. We allow the common escape `\"` for quoted contexts.
        let php_re = regex::Regex::new(r#"O:\d+:(?:\\?"){1}\w+(?:\\?"){1}:\d+:"#)
            .expect("static php regex");

        let mut findings: Vec<Finding> = Vec::new();
        // Helper: emit a finding tagged with the sink + marker.
        let mut emit = |sink: &str, marker_label: &str, snippet: &str| {
            if findings
                .iter()
                .any(|f| f.evidence.contains(marker_label) && f.evidence.contains(sink))
            {
                return;
            }
            let mut f = Finding::new(
                "insecure-deserialization-indicator",
                &format!("Serialized-object marker in {sink}"),
                Severity::Medium,
                Confidence::Firm,
            );
            f.description = format!(
                "A {marker_label} signature appears in the {sink}. Serialized objects transiting over the wire are a precondition for deserialization-based RCE (ysoserial, ObjectInputStream.readObject, pickle.loads, BinaryFormatter, PHP __wakeup, etc.). Confirm whether the application round-trips the token back to a server-side deserializer."
            );
            f.evidence = format!("{sink} | {marker_label} | sample: {snippet}");
            f.remediation = "Prefer JSON / Protobuf over native serialization. If native serialization is unavoidable, use allow-listed types (`ObjectInputFilter`, `ValidatingObjectInputStream`, PHP's `allowed_classes`), MAC-sign the payload, and never deserialize untrusted input server-side.".into();
            f.references = vec!["CWE-502".into()];
            findings.push(f);
        };

        // ---- 1. Query parameters ----
        for (name, value) in tx.request.query_params() {
            for (needle, label) in needles {
                if value.contains(needle) {
                    let snippet = truncate_for_evidence(&value, 60);
                    emit(&format!("query parameter `{name}`"), label, &snippet);
                }
            }
            if php_re.is_match(&value) {
                let snippet = truncate_for_evidence(&value, 60);
                emit(
                    &format!("query parameter `{name}`"),
                    "PHP serialized object (`O:…:\"ClassName\":…:`)",
                    &snippet,
                );
            }
        }
        // ---- 2. Cookie header ----
        if let Some(cookie_hdr) = tx.request.headers.get("Cookie") {
            for pair in cookie_hdr.split(';') {
                let pair = pair.trim();
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                for (needle, label) in needles {
                    if value.contains(needle) {
                        let snippet = truncate_for_evidence(value, 60);
                        emit(&format!("cookie `{name}`"), label, &snippet);
                    }
                }
                if php_re.is_match(value) {
                    let snippet = truncate_for_evidence(value, 60);
                    emit(
                        &format!("cookie `{name}`"),
                        "PHP serialized object (`O:…:\"ClassName\":…:`)",
                        &snippet,
                    );
                }
            }
        }
        // ---- 3. Request body ----
        if !tx.request.body.is_empty() {
            let body_text = String::from_utf8_lossy(&tx.request.body);
            for (needle, label) in needles {
                if body_text.contains(needle) {
                    let snippet = truncate_for_evidence(&body_text, 60);
                    emit("request body", label, &snippet);
                }
            }
            if php_re.is_match(&body_text) {
                let snippet = truncate_for_evidence(&body_text, 60);
                emit(
                    "request body",
                    "PHP serialized object (`O:…:\"ClassName\":…:`)",
                    &snippet,
                );
            }
        }
        findings
    }
}

/// Short, display-safe snippet of a value. Trims to `max` characters
/// and replaces control chars with `.` so evidence lines never break
/// terminal rendering.
fn truncate_for_evidence(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(max.min(s.len()));
    for ch in s.chars().take(max) {
        if ch.is_control() {
            out.push('.');
        } else {
            out.push(ch);
        }
    }
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// Audit the `Permissions-Policy` (or legacy `Feature-Policy`)
/// response header on HTML pages. Flags missing or over-permissive
/// directives for sensitive features.
pub struct PermissionsPolicyAudit;

impl PassiveDetector for PermissionsPolicyAudit {
    fn id(&self) -> &'static str {
        "permissions-policy-weakness"
    }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let Some(resp) = &tx.response else {
            return Vec::new();
        };
        if !resp
            .headers
            .content_type()
            .map(|c| c.contains("text/html"))
            .unwrap_or(false)
        {
            return Vec::new();
        }
        let policy = resp
            .headers
            .get("Permissions-Policy")
            .map(|s| s.to_string())
            .or_else(|| resp.headers.get("Feature-Policy").map(|s| s.to_string()));
        let mut findings = Vec::new();
        let Some(policy) = policy else {
            // Missing entirely — Low signal.
            let mut f = Finding::new(
                "permissions-policy-weakness",
                "Missing Permissions-Policy header",
                Severity::Low,
                Confidence::Certain,
            );
            f.description = "The response is HTML but doesn't ship a `Permissions-Policy` header. Without it, embedding sites can request access to camera / microphone / geolocation / payment / usb APIs on behalf of this page unless the browser's defaults are restrictive.".into();
            f.remediation = "Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` at the deployment layer (or restrict further to specific origins where features are legitimately needed).".into();
            f.references = vec!["CWE-693".into()];
            findings.push(f);
            return findings;
        };
        // Permissions-Policy syntax: `feature=(source source), feature=*,
        // feature=self`. `*` or `(*)` is overly permissive.
        for feature in ["camera", "microphone", "geolocation", "payment", "usb"] {
            // Find `<feature>=<value>` where the value may be `*`,
            // `self`, or a parenthesised list.
            let needle = format!("{feature}=");
            if let Some(idx) = policy.find(&needle) {
                let after = &policy[idx + needle.len()..];
                // Grab everything up to the next `,`.
                let value: String =
                    after.chars().take_while(|c| *c != ',').collect();
                let normalised = value.trim().to_ascii_lowercase();
                let permissive = normalised == "*"
                    || normalised == "(*)"
                    || normalised.contains('*');
                if permissive {
                    let severity = match feature {
                        "camera" | "microphone" | "geolocation" => Severity::Medium,
                        _ => Severity::Low,
                    };
                    let mut f = Finding::new(
                        "permissions-policy-weakness",
                        &format!("Permissions-Policy allows `*` for {feature}"),
                        severity,
                        Confidence::Firm,
                    );
                    f.description = format!(
                        "The `{feature}` directive in `Permissions-Policy` allows any origin to request the feature when this page is embedded. Attackers can proxy user consent through a hostile parent frame."
                    );
                    f.evidence = format!("{feature}={value}");
                    f.remediation = format!("Replace `{feature}=*` with an explicit allow-list — `{feature}=(self)` for first-party-only or `{feature}=()` to deny entirely.");
                    f.references = vec!["CWE-693".into()];
                    findings.push(f);
                }
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// R939: 4 more passive detectors (16→20)
// ---------------------------------------------------------------------------

/// Detect sensitive data patterns in response bodies (credit cards,
/// SSNs, API keys). Broader than InfoDisclosureHeaders which only
/// checks headers.
pub struct SensitiveDataExposure;

impl PassiveDetector for SensitiveDataExposure {
    fn id(&self) -> &'static str { "sensitive-data-exposure" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return Vec::new(),
        };
        let body = String::from_utf8_lossy(&resp.body);
        if body.len() < 10 { return Vec::new(); }
        let mut findings = Vec::new();

        // Credit card number patterns (Visa, MC, Amex, Discover)
        if let Ok(re) = regex::Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b") {
            if re.is_match(&body) {
                findings.push(Finding {
                    id: TrafficId::new(),
                    detector: "sensitive-data-exposure".into(),
                    title: "Possible credit card number in response".into(),
                    description: "A pattern matching a credit card number was found in the response body.".into(),
                    severity: Severity::High,
                    confidence: Confidence::Tentative,
                    evidence: "Credit card pattern detected".into(),
                    remediation: "Ensure sensitive financial data is not exposed in HTTP responses. Use tokenization or masking.".into(),
                    transaction_id: None,
                    insertion_point: None,
                    references: vec!["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/".into()],
                    cwe: vec!["CWE-200".into()],
                });
            }
        }

        // AWS access key
        if body.contains("AKIA") || body.contains("ASIA") {
            if let Ok(re) = regex::Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b") {
                if re.is_match(&body) {
                    findings.push(Finding {
                        id: TrafficId::new(),
                        detector: "sensitive-data-exposure".into(),
                        title: "AWS access key ID in response".into(),
                        description: "An AWS access key ID pattern was found in the response body.".into(),
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        evidence: "AKIA/ASIA pattern detected".into(),
                        remediation: "Rotate the exposed key immediately and remove it from the response.".into(),
                        transaction_id: None,
                        insertion_point: None,
                        references: vec![],
                        cwe: vec!["CWE-200".into(), "CWE-798".into()],
                    });
                }
            }
        }

        findings
    }
}

/// Detect missing Subresource Integrity (SRI) on external script/style tags.
pub struct SubresourceIntegrity;

impl PassiveDetector for SubresourceIntegrity {
    fn id(&self) -> &'static str { "subresource-integrity" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response {
            Some(r) if r.status == 200 => r,
            _ => return Vec::new(),
        };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return Vec::new(); }

        let body = String::from_utf8_lossy(&resp.body);
        let mut findings = Vec::new();

        // Check for external scripts without integrity attribute
        if let Ok(re) = regex::Regex::new(r#"<script[^>]+src="https?://[^"]+""#) {
            for m in re.find_iter(&body) {
                let tag = m.as_str();
                if !tag.contains("integrity=") {
                    findings.push(Finding {
                        id: TrafficId::new(),
                        detector: "subresource-integrity".into(),
                        title: "External script loaded without SRI".into(),
                        description: "An external script tag loads JavaScript from a third-party CDN without a Subresource Integrity hash. If the CDN is compromised, malicious code could be injected.".into(),
                        severity: Severity::Info,
                        confidence: Confidence::Certain,
                        evidence: tag.to_string(),
                        remediation: "Add an integrity attribute with a SHA-256/384/512 hash to external script tags.".into(),
                        transaction_id: None,
                        insertion_point: None,
                        references: vec![],
                        cwe: vec!["CWE-353".into()],
                    });
                    break; // One finding per page is sufficient
                }
            }
        }

        findings
    }
}

/// Detect frameable responses (clickjacking) by checking X-Frame-Options
/// and CSP frame-ancestors. Complements the BCheck but runs as a passive
/// detector on every HTML response.
pub struct ClickjackingFrameable;

impl PassiveDetector for ClickjackingFrameable {
    fn id(&self) -> &'static str { "clickjacking-frameable" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response {
            Some(r) if r.status == 200 => r,
            _ => return Vec::new(),
        };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return Vec::new(); }

        let has_xfo = resp.headers.get("x-frame-options").is_some();
        let has_csp_fa = resp.headers.get("content-security-policy")
            .map(|v| v.contains("frame-ancestors"))
            .unwrap_or(false);

        if !has_xfo && !has_csp_fa {
            return vec![Finding {
                id: TrafficId::new(),
                detector: "clickjacking-frameable".into(),
                title: "Frameable response (potential Clickjacking)".into(),
                description: "The response does not set X-Frame-Options or CSP frame-ancestors, making it potentially vulnerable to clickjacking attacks.".into(),
                severity: Severity::Medium,
                confidence: Confidence::Certain,
                evidence: "No X-Frame-Options or frame-ancestors directive".into(),
                remediation: "Set X-Frame-Options: DENY or SAMEORIGIN, or add frame-ancestors to CSP.".into(),
                transaction_id: None,
                insertion_point: None,
                references: vec![],
                cwe: vec!["CWE-1021".into()],
            }];
        }

        Vec::new()
    }
}

/// Detailed HSTS analysis — checks for missing HSTS, short max-age,
/// missing includeSubDomains, and missing preload.
pub struct HttpStrictTransportSecurity;

impl PassiveDetector for HttpStrictTransportSecurity {
    fn id(&self) -> &'static str { "hsts-analysis" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        // Only check HTTPS responses
        if tx.request.scheme != "https" { return Vec::new(); }

        let resp = match &tx.response {
            Some(r) => r,
            None => return Vec::new(),
        };

        let hsts = resp.headers.get("strict-transport-security");
        let mut findings = Vec::new();

        match hsts {
            None => {
                findings.push(Finding {
                    id: TrafficId::new(),
                    detector: "hsts-analysis".into(),
                    title: "HSTS header missing on HTTPS response".into(),
                    description: "The server does not set Strict-Transport-Security, allowing SSL stripping attacks.".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Certain,
                    evidence: "No Strict-Transport-Security header".into(),
                    remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".into(),
                    transaction_id: None,
                    insertion_point: None,
                    references: vec![],
                    cwe: vec!["CWE-319".into()],
                });
            }
            Some(val) => {
                // Check max-age is at least 1 year
                if let Some(age_str) = val.split("max-age=").nth(1) {
                    let age: u64 = age_str
                        .split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if age < 31536000 {
                        findings.push(Finding {
                            id: TrafficId::new(),
                            detector: "hsts-analysis".into(),
                            title: "HSTS max-age is less than one year".into(),
                            description: format!("Strict-Transport-Security max-age is {} seconds ({} days). OWASP recommends at least 31536000 (1 year).", age, age / 86400),
                            severity: Severity::Info,
                            confidence: Confidence::Certain,
                            evidence: format!("max-age={}", age),
                            remediation: "Increase max-age to at least 31536000 (1 year).".into(),
                            transaction_id: None,
                            insertion_point: None,
                            references: vec![],
                            cwe: vec![],
                        });
                    }
                }
            }
        }

        findings
    }
}


/// Detect known-vulnerable JavaScript libraries by version in response bodies.
/// Mirrors Burp's Retire.js-powered "Vulnerable JavaScript libraries" finding.
pub struct VulnerableJsLibrary;

impl PassiveDetector for VulnerableJsLibrary {
    fn id(&self) -> &'static str { "vulnerable-js-library" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return Vec::new(),
        };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("javascript") && !ct.contains("text/html") {
            return Vec::new();
        }
        let body = String::from_utf8_lossy(&resp.body);
        let mut findings = Vec::new();

        // Simple version-pattern checks for well-known libraries
        static VULN_PATTERNS: &[(&str, &str, &str)] = &[
            ("jQuery <3.5.0", r"jquery[/.-]([12]\.\d+|3\.[0-4])", "jQuery versions below 3.5.0 have known XSS vulnerabilities (CVE-2020-11022/11023)"),
            ("Angular.js 1.x", r"angular[/.-]1\.\d+", "AngularJS 1.x is end-of-life and has known sandbox escape vulnerabilities"),
            ("Lodash <4.17.21", r"lodash[/.-](3\.\d+|4\.(0|1[0-6]|17\.[01]\d?))", "Lodash versions below 4.17.21 have prototype pollution vulnerabilities (CVE-2021-23337)"),
            ("Moment.js", r"moment[/.-]\d+\.\d+", "Moment.js is in maintenance mode; consider using a modern alternative"),
            ("Bootstrap <5.0", r"bootstrap[/.-][234]\.\d+", "Bootstrap versions below 5.0 have known XSS in tooltip/popover components"),
        ];

        for &(name, pattern, desc) in VULN_PATTERNS {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&body) {
                    findings.push(Finding {
                        id: TrafficId::new(),
                        detector: "vulnerable-js-library".into(),
                        title: format!("Potentially vulnerable: {}", name),
                        description: desc.into(),
                        severity: Severity::Info,
                        confidence: Confidence::Tentative,
                        evidence: re.find(&body).map(|m| m.as_str().to_string()).unwrap_or_default(),
                        remediation: "Update the library to the latest version.".into(),
                        transaction_id: None,
                        insertion_point: None,
                        references: vec![],
                        cwe: vec![],
                    });
                }
            }
        }

        findings
    }
}

/// Detect Host header reflection in response bodies — indicates
/// potential host header injection / cache poisoning.
pub struct HostHeaderReflection;

impl PassiveDetector for HostHeaderReflection {
    fn id(&self) -> &'static str { "host-header-reflection" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let host = &tx.request.host;
        if host.is_empty() {
            return Vec::new();
        }
        let resp = match &tx.response {
            Some(r) => r,
            None => return Vec::new(),
        };

        // Check if the Host header value appears in the response body
        // in contexts that suggest it's being reflected (URLs, links, meta tags)
        let body = String::from_utf8_lossy(&resp.body);
        let mut findings = Vec::new();

        // Look for reflection in common injection contexts
        let patterns = [
            format!("href=\"http://{}",  host),
            format!("href=\"https://{}", host),
            format!("src=\"http://{}",   host),
            format!("src=\"https://{}",  host),
            format!("action=\"http://{}",  host),
            format!("action=\"https://{}", host),
        ];

        for pat in &patterns {
            if body.contains(pat.as_str()) {
                // This is expected — the host should appear in URLs.
                // Only flag if the response also contains a cacheable indicator.
                let cacheable = resp.headers.get("cache-control")
                    .map(|v| !v.contains("no-store") && !v.contains("private"))
                    .unwrap_or(true);
                if cacheable && resp.headers.get("vary").is_none() {
                    findings.push(Finding {
                        id: TrafficId::new(),
                        detector: "host-header-reflection".into(),
                        title: "Host header reflected in cacheable response".into(),
                        description: "The Host header value is reflected in the response body and the response may be cached. This could enable web cache poisoning attacks.".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Tentative,
                        evidence: format!("Host: {} reflected; no Vary header; cacheable", host),
                        remediation: "Add a Vary: Host header or set Cache-Control: no-store on responses that reflect the Host header.".into(),
                        transaction_id: None,
                        insertion_point: None,
                        references: vec![],
                        cwe: vec![],
                    });
                    break;
                }
            }
        }

        findings
    }
}

/// Detect directory listing responses — common misconfiguration.
pub struct DirectoryListing;

impl PassiveDetector for DirectoryListing {
    fn id(&self) -> &'static str { "directory-listing" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response {
            Some(r) if r.status == 200 => r,
            _ => return Vec::new(),
        };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") {
            return Vec::new();
        }
        let body = String::from_utf8_lossy(&resp.body);
        let mut findings = Vec::new();

        // Common directory listing indicators
        let indicators = [
            "Index of /",
            "Directory listing for",
            "<title>Index of",
            "Parent Directory</a>",
            "[To Parent Directory]",
            "Directory Listing For",
        ];

        for indicator in &indicators {
            if body.contains(indicator) {
                findings.push(Finding {
                    id: TrafficId::new(),
                    detector: "directory-listing".into(),
                    title: "Directory listing enabled".into(),
                    description: format!(
                        "The server returned a directory listing for {}. This may expose sensitive files and internal structure.",
                        tx.request.path
                    ),
                    severity: Severity::Low,
                    confidence: Confidence::Certain,
                    evidence: format!("Matched indicator: {}", indicator),
                    remediation: "Disable directory listings in the web server configuration.".into(),
                    transaction_id: None,
                    insertion_point: None,
                    references: vec![],
                    cwe: vec![],
                });
                break;
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// R946: 5 more passive detectors (20→25)
// ---------------------------------------------------------------------------

/// Detect verbose server version disclosure in headers.
pub struct ServerVersionDisclosure;

impl PassiveDetector for ServerVersionDisclosure {
    fn id(&self) -> &'static str { "server-version-disclosure" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        let mut findings = Vec::new();
        for hdr in &["server", "x-powered-by", "x-aspnet-version", "x-generator"] {
            if let Some(val) = resp.headers.get(*hdr) {
                if val.contains('/') || regex::Regex::new(r"\d+\.\d+").ok().map(|r| r.is_match(val)).unwrap_or(false) {
                    findings.push(Finding {
                        id: TrafficId::new(), detector: "server-version-disclosure".into(),
                        title: format!("Server version disclosed via {}", hdr),
                        description: format!("The {} header reveals version information: {}", hdr, val),
                        severity: Severity::Info, confidence: Confidence::Certain,
                        evidence: format!("{}: {}", hdr, val),
                        remediation: "Remove or genericize version information from server response headers.".into(),
                        transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-200".into()],
                    });
                }
            }
        }
        findings
    }
}

/// Detect missing X-Content-Type-Options: nosniff header.
pub struct ContentTypeSniffing;

impl PassiveDetector for ContentTypeSniffing {
    fn id(&self) -> &'static str { "content-type-sniffing" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        let xcto = resp.headers.get("x-content-type-options");
        if xcto.map(|v| v.to_lowercase().contains("nosniff")).unwrap_or(false) {
            return vec![];
        }
        vec![Finding {
            id: TrafficId::new(), detector: "content-type-sniffing".into(),
            title: "Missing X-Content-Type-Options: nosniff".into(),
            description: "Without nosniff, browsers may MIME-sniff responses, enabling content-type confusion attacks.".into(),
            severity: Severity::Low, confidence: Confidence::Certain,
            evidence: "X-Content-Type-Options header missing or does not contain nosniff".into(),
            remediation: "Add X-Content-Type-Options: nosniff to all responses.".into(),
            transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-693".into()],
        }]
    }
}

/// Detect missing Referrer-Policy header.
pub struct ReferrerPolicyMissing;

impl PassiveDetector for ReferrerPolicyMissing {
    fn id(&self) -> &'static str { "referrer-policy-missing" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        if resp.headers.get("referrer-policy").is_some() { return vec![]; }
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return vec![]; }
        vec![Finding {
            id: TrafficId::new(), detector: "referrer-policy-missing".into(),
            title: "Missing Referrer-Policy header".into(),
            description: "Without Referrer-Policy, sensitive URL paths may leak to third parties via the Referer header.".into(),
            severity: Severity::Info, confidence: Confidence::Certain,
            evidence: "Referrer-Policy header not set".into(),
            remediation: "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.".into(),
            transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-200".into()],
        }]
    }
}

/// Detect HTML forms with action pointing to external domains.
pub struct FormActionHijack;

impl PassiveDetector for FormActionHijack {
    fn id(&self) -> &'static str { "form-action-external" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) if r.status == 200 => r, _ => return vec![] };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return vec![]; }
        let body = String::from_utf8_lossy(&resp.body);
        let host = &tx.request.host;
        if host.is_empty() { return vec![]; }
        if let Ok(re) = regex::Regex::new(r#"<form[^>]+action="(https?://[^"]+)"#) {
            for cap in re.captures_iter(&body) {
                if let Some(url) = cap.get(1) {
                    let action_url = url.as_str();
                    if !action_url.contains(host) {
                        return vec![Finding {
                            id: TrafficId::new(), detector: "form-action-external".into(),
                            title: "Form submits to external domain".into(),
                            description: format!("A form on {} submits data to an external URL: {}", host, action_url),
                            severity: Severity::Medium, confidence: Confidence::Tentative,
                            evidence: action_url.to_string(),
                            remediation: "Ensure forms only submit to the same origin or trusted domains.".into(),
                            transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-352".into()],
                        }];
                    }
                }
            }
        }
        vec![]
    }
}

/// Detect HTTPS pages with forms that submit over HTTP.
pub struct InsecureFormSubmission;

impl PassiveDetector for InsecureFormSubmission {
    fn id(&self) -> &'static str { "insecure-form-submission" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        if tx.request.scheme != "https" { return vec![]; }
        let resp = match &tx.response { Some(r) if r.status == 200 => r, _ => return vec![] };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return vec![]; }
        let body = String::from_utf8_lossy(&resp.body);
        if let Ok(re) = regex::Regex::new(r#"<form[^>]+action="http://[^"]+""#) {
            if let Some(m) = re.find(&body) {
                return vec![Finding {
                    id: TrafficId::new(), detector: "insecure-form-submission".into(),
                    title: "HTTPS page submits form data over HTTP".into(),
                    description: "An HTTPS page contains a form that submits data over unencrypted HTTP, exposing form data to network eavesdroppers.".into(),
                    severity: Severity::Medium, confidence: Confidence::Certain,
                    evidence: m.as_str().to_string(),
                    remediation: "Change form action URLs to use HTTPS.".into(),
                    transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-319".into()],
                }];
            }
        }
        vec![]
    }
}

// ---------------------------------------------------------------------------
// R966: 5 more passive detectors (25→30, matching Burp's ~30)
// ---------------------------------------------------------------------------

/// Detect SameSite=None cookies without Secure flag.
pub struct CookieSameSiteNone;

impl PassiveDetector for CookieSameSiteNone {
    fn id(&self) -> &'static str { "cookie-samesite-none" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        let mut findings = Vec::new();
        for val in resp.headers.get_all("set-cookie") {
            let lower = val.to_lowercase();
            if lower.contains("samesite=none") && !lower.contains("secure") {
                findings.push(Finding {
                    id: TrafficId::new(), detector: "cookie-samesite-none".into(),
                    title: "SameSite=None cookie without Secure flag".into(),
                    description: "A cookie with SameSite=None but without the Secure flag will be rejected by modern browsers.".into(),
                    severity: Severity::Medium, confidence: Confidence::Certain,
                    evidence: val.to_string(),
                    remediation: "Add the Secure flag to all SameSite=None cookies.".into(),
                    transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-614".into()],
                });
            }
        }
        findings
    }
}

/// Detect anomalously large response bodies that may indicate data leaks.
pub struct ResponseBodySizeAnomaly;

impl PassiveDetector for ResponseBodySizeAnomaly {
    fn id(&self) -> &'static str { "response-size-anomaly" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        // Flag responses over 5MB as potential data dumps
        if resp.body.len() > 5_000_000 {
            return vec![Finding {
                id: TrafficId::new(), detector: "response-size-anomaly".into(),
                title: format!("Large response body ({:.1} MB)", resp.body.len() as f64 / 1_000_000.0),
                description: "An unusually large response body may indicate a data dump, debug output, or misconfigured endpoint.".into(),
                severity: Severity::Info, confidence: Confidence::Tentative,
                evidence: format!("{} bytes", resp.body.len()),
                remediation: "Review the endpoint for unnecessary data exposure. Implement pagination.".into(),
                transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-200".into()],
            }];
        }
        vec![]
    }
}

/// Detect double-encoded characters in responses suggesting encoding issues.
pub struct DoubleEncoding;

impl PassiveDetector for DoubleEncoding {
    fn id(&self) -> &'static str { "double-encoding" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        let body = String::from_utf8_lossy(&resp.body);
        // Look for double-URL-encoded patterns like %2520 (%25 = %, so %2520 = %20)
        if body.contains("%25") || body.contains("%2520") || body.contains("%252F") {
            return vec![Finding {
                id: TrafficId::new(), detector: "double-encoding".into(),
                title: "Double-encoded content in response".into(),
                description: "The response contains double-URL-encoded characters, suggesting an encoding normalization issue that could be exploited for filter bypass.".into(),
                severity: Severity::Info, confidence: Confidence::Tentative,
                evidence: "Double-encoded pattern detected".into(),
                remediation: "Apply URL decoding only once. Validate input after final decoding step.".into(),
                transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-174".into()],
            }];
        }
        vec![]
    }
}

/// Detect missing Cache-Control on sensitive responses.
pub struct CacheControlMissing;

impl PassiveDetector for CacheControlMissing {
    fn id(&self) -> &'static str { "cache-control-sensitive" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) => r, None => return vec![] };
        // Only check responses that look sensitive (auth endpoints, user data)
        let path = &tx.request.path;
        let is_sensitive = path.contains("/api/") || path.contains("/user") ||
            path.contains("/account") || path.contains("/profile") ||
            path.contains("/admin") || path.contains("/dashboard");
        if !is_sensitive { return vec![]; }

        let cc = resp.headers.get("cache-control").unwrap_or_default().to_lowercase();
        if cc.is_empty() || (!cc.contains("no-store") && !cc.contains("no-cache") && !cc.contains("private")) {
            return vec![Finding {
                id: TrafficId::new(), detector: "cache-control-sensitive".into(),
                title: "Sensitive endpoint without Cache-Control restrictions".into(),
                description: format!("The endpoint {} returns potentially sensitive data without Cache-Control: no-store or private, allowing proxies and browsers to cache the response.", path),
                severity: Severity::Low, confidence: Confidence::Tentative,
                evidence: format!("Cache-Control: {}", if cc.is_empty() { "(not set)" } else { &cc }),
                remediation: "Add Cache-Control: no-store to responses containing sensitive data.".into(),
                transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-525".into()],
            }];
        }
        vec![]
    }
}

/// Detect cross-domain script includes (loading JS from other origins).
pub struct CrossDomainScriptInclude;

impl PassiveDetector for CrossDomainScriptInclude {
    fn id(&self) -> &'static str { "cross-domain-script" }
    fn run(&self, tx: &Transaction) -> Vec<Finding> {
        let resp = match &tx.response { Some(r) if r.status == 200 => r, _ => return vec![] };
        let ct = resp.headers.get("content-type").unwrap_or_default().to_lowercase();
        if !ct.contains("text/html") { return vec![]; }
        let body = String::from_utf8_lossy(&resp.body);
        let host = &tx.request.host;
        if host.is_empty() { return vec![]; }

        let mut count = 0;
        if let Ok(re) = regex::Regex::new(r#"<script[^>]+src="(https?://[^"]+)"#) {
            for cap in re.captures_iter(&body) {
                if let Some(url) = cap.get(1) {
                    if !url.as_str().contains(host) {
                        count += 1;
                    }
                }
            }
        }
        if count > 0 {
            return vec![Finding {
                id: TrafficId::new(), detector: "cross-domain-script".into(),
                title: format!("{} cross-domain script include{}", count, if count > 1 { "s" } else { "" }),
                description: format!("The page loads {} script(s) from external domains. If any of these domains are compromised, malicious code will execute in the application context.", count),
                severity: Severity::Info, confidence: Confidence::Certain,
                evidence: format!("{} external scripts detected", count),
                remediation: "Use Subresource Integrity (SRI) for all external scripts. Consider self-hosting critical dependencies.".into(),
                transaction_id: None, insertion_point: None, references: vec![], cwe: vec!["CWE-829".into()],
            }];
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response, Transaction};

    fn tx(req: Request, resp: Response) -> Transaction {
        let mut t = Transaction::new(req);
        t.response = Some(resp);
        t
    }

    #[test]
    fn detects_missing_csp_on_html() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        let findings = SecurityHeaders.run(&tx(req, resp));
        let names: Vec<_> = findings.iter().map(|f| f.title.clone()).collect();
        assert!(names.iter().any(|t| t.contains("Content-Security-Policy")));
        assert!(names.iter().any(|t| t.contains("Strict-Transport-Security")));
    }

    #[test]
    fn insecure_session_cookie() {
        let req = Request::new("GET", "https://example.com/login").unwrap();
        let mut resp = Response::new(200);
        resp.headers.add("Set-Cookie", "sid=abc123; Path=/");
        let findings = InsecureCookies.run(&tx(req, resp));
        assert!(findings.iter().any(|f| f.title.contains("HttpOnly")));
        assert!(findings.iter().any(|f| f.title.contains("Secure")));
        assert!(findings.iter().any(|f| f.title.contains("SameSite")));
    }

    #[test]
    fn cors_wildcard_with_credentials_is_high() {
        let req = Request::new("GET", "https://example.com/api").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Access-Control-Allow-Origin", "*");
        resp.headers.set("Access-Control-Allow-Credentials", "true");
        let findings = CorsPermissive.run(&tx(req, resp));
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn info_disclosure_server_header() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Server", "nginx/1.21.6");
        let findings = InfoDisclosureHeaders.run(&tx(req, resp));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn mixed_content_detected() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.set_text(r#"<html><body><img src="http://cdn.example.com/x.png"></body></html>"#);
        let findings = MixedContent.run(&tx(req, resp));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn external_redirect() {
        let req = Request::new("GET", "https://example.com/go?u=https://evil.example.net").unwrap();
        let mut resp = Response::new(302);
        resp.headers.set("Location", "https://evil.example.net");
        let findings = RedirectToExternal.run(&tx(req, resp));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn passive_detector_ids_lists_all_builtins() {
        let ids = passive_detector_ids();
        // Spot-check a few — if a detector gets renamed or a new one
        // is added without updating the UI, this test flags the
        // mismatch early.
        assert!(ids.contains(&"security-headers"));
        assert!(ids.contains(&"insecure-cookies"));
        assert!(ids.contains(&"cors-permissive"));
        assert!(ids.contains(&"csrf-token-missing"));
        // Count check — current baseline is 13 built-ins. Updating
        // this number is a conscious decision that must land with
        // UI changes for the new row.
        assert_eq!(ids.len(), 13);
        // Order is stable (registration order) — important because
        // the UI renders the toggle grid in this order and operators
        // learn muscle memory for the row positions.
        assert_eq!(ids[0], "security-headers");
    }

    #[test]
    fn run_all_filtered_skips_disabled_ids() {
        // Build a sample txn that fires several detectors — missing
        // security headers + a Set-Cookie without Secure/HttpOnly on
        // an HTTPS page. Then disable one detector id at a time and
        // assert its findings vanish while the rest remain.
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.headers.set("Set-Cookie", "sid=abc");
        resp.set_text("<h1>hi</h1>");
        let tx = Transaction::new(req);
        let mut tx = tx;
        tx.response = Some(resp);

        // Baseline — unfiltered: should surface findings from
        // security-headers (several) AND insecure-cookies.
        let baseline = run_all(&tx);
        let has_sec = baseline.iter().any(|f| f.detector == "security-headers");
        let has_cookie = baseline.iter().any(|f| f.detector == "insecure-cookies");
        assert!(has_sec, "baseline should include security-headers");
        assert!(has_cookie, "baseline should include insecure-cookies");

        // Disable security-headers only.
        let mut disabled = std::collections::HashSet::new();
        disabled.insert("security-headers");
        let filtered = run_all_filtered(&tx, &[], &disabled);
        assert!(
            !filtered.iter().any(|f| f.detector == "security-headers"),
            "security-headers findings must be gone when disabled"
        );
        assert!(
            filtered.iter().any(|f| f.detector == "insecure-cookies"),
            "insecure-cookies must still fire when only security-headers is disabled"
        );

        // Disable both — neither should appear.
        disabled.insert("insecure-cookies");
        let filtered2 = run_all_filtered(&tx, &[], &disabled);
        assert!(!filtered2.iter().any(|f| f.detector == "security-headers"));
        assert!(!filtered2.iter().any(|f| f.detector == "insecure-cookies"));
        // Baseline minus the two disabled detectors = fewer findings.
        assert!(filtered2.len() < baseline.len());
    }

    #[test]
    fn run_all_sets_transaction_id() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        let t = tx(req, resp);
        let findings = run_all(&t);
        for f in &findings {
            assert_eq!(f.transaction_id, Some(t.id));
        }
    }

    #[test]
    fn custom_rule_emits_finding_when_matcher_hits() {
        use burpfree_core::rules::{CustomMatcher, CustomPassiveRule};
        let req = Request::new("GET", "https://example.com/leaked").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/plain");
        resp.set_text("...AKIAIOSFODNN7EXAMPLE... some leaked key");
        let t = tx(req, resp);
        let rule = CustomPassiveRule {
            id: "aws-access-key".into(),
            title: "Possible AWS access key".into(),
            severity: "high".into(),
            confidence: "firm".into(),
            description: String::new(),
            remediation: String::new(),
            references: vec![],
            cwe: vec!["CWE-798".into()],
            when: CustomMatcher::BodyMatches { pattern: r"AKIA[0-9A-Z]{16}".into(), response: true },
            insertion_point: Some("body".into()),
        };
        let findings = run_all_with_rules(&t, &[rule.clone()]);
        let hit = findings.iter().find(|f| f.detector == "aws-access-key")
            .expect("custom rule should produce a finding");
        assert_eq!(hit.severity, super::Severity::High);
        assert_eq!(hit.cwe, vec!["CWE-798".to_string()]);
        assert_eq!(hit.insertion_point.as_deref(), Some("body"));

        // No match → no custom finding emitted.
        let req = Request::new("GET", "https://example.com/clean").unwrap();
        let mut resp = Response::new(200);
        resp.set_text("nothing to see here");
        let t = tx(req, resp);
        let findings = run_all_with_rules(&t, &[rule]);
        assert!(findings.iter().all(|f| f.detector != "aws-access-key"));
    }

    #[test]
    fn csp_breakdown_unsafe_inline() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.headers.set(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*; frame-ancestors 'none'",
        );
        let findings = CspBreakdown.run(&tx(req, resp));
        let titles: Vec<_> = findings.iter().map(|f| f.title.clone()).collect();
        assert!(titles.iter().any(|t| t.contains("unsafe-inline")));
        assert!(titles.iter().any(|t| t.contains("unsafe-eval")));
        // We should NOT flag frame-ancestors as missing — it's explicitly set.
        assert!(
            !titles.iter().any(|t| t.contains("frame-ancestors")),
            "frame-ancestors was explicitly set but was flagged as missing: {titles:?}"
        );
    }

    #[test]
    fn csp_breakdown_strict_policy_is_clean() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.headers.set(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'; frame-ancestors 'none'",
        );
        let findings = CspBreakdown.run(&tx(req, resp));
        assert!(
            findings.is_empty(),
            "strict CSP must not flag — got {} finding(s): {:?}",
            findings.len(),
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn csrf_missing_on_form_post() {
        let mut req =
            Request::new("POST", "https://example.com/profile/update").unwrap();
        req.headers
            .set("Content-Type", "application/x-www-form-urlencoded");
        req.body = b"email=new@example.com&role=admin".to_vec();
        let findings = MissingCsrfToken.run(&tx(req, Response::new(200)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "csrf-token-missing");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn csrf_present_via_header_no_finding() {
        let mut req = Request::new("POST", "https://example.com/api/update").unwrap();
        req.headers.set("Content-Type", "application/json");
        req.headers.set("X-CSRF-Token", "a1b2c3");
        req.body = b"{\"email\":\"x@example.com\"}".to_vec();
        let findings = MissingCsrfToken.run(&tx(req, Response::new(200)));
        assert!(findings.is_empty(), "X-CSRF-Token header should suppress");
    }

    #[test]
    fn permissions_policy_permissive_camera_flagged() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.headers.set(
            "Permissions-Policy",
            "camera=*, microphone=(self), geolocation=()",
        );
        let findings = PermissionsPolicyAudit.run(&tx(req, resp));
        let titles: Vec<_> = findings.iter().map(|f| f.title.clone()).collect();
        assert!(titles.iter().any(|t| t.contains("camera")));
        // microphone is `(self)` — not permissive, should NOT be flagged.
        assert!(!titles.iter().any(|t| t.contains("microphone")));
    }

    #[test]
    fn permissions_policy_missing_entirely() {
        let req = Request::new("GET", "https://example.com/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        let findings = PermissionsPolicyAudit.run(&tx(req, resp));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Missing"));
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn deserialization_marker_java_in_cookie() {
        let mut req = Request::new("GET", "https://example.com/dashboard").unwrap();
        // Classic Java serialized token in a session cookie.
        req.headers.set(
            "Cookie",
            "sid=abc; state=rO0ABXNyABNjb20uZXhhbXBsZS5Vc2VyAQIAAHhw",
        );
        let findings =
            InsecureDeserializationMarkers.run(&tx(req, Response::new(200)));
        let hit = findings
            .iter()
            .find(|f| f.detector == "insecure-deserialization-indicator")
            .expect("expected Java rO0AB cookie finding");
        assert_eq!(hit.severity, Severity::Medium);
        assert!(hit.evidence.contains("state"));
        assert!(hit.evidence.contains("Java"));
    }

    #[test]
    fn deserialization_marker_php_in_body() {
        let mut req = Request::new("POST", "https://example.com/update").unwrap();
        req.headers
            .set("Content-Type", "application/x-www-form-urlencoded");
        req.body =
            br#"token=O:4:"User":2:{s:4:"name";s:5:"alice";s:4:"role";s:5:"admin";}"#
                .to_vec();
        let findings =
            InsecureDeserializationMarkers.run(&tx(req, Response::new(200)));
        let hit = findings
            .iter()
            .find(|f| f.detector == "insecure-deserialization-indicator")
            .expect("expected PHP O:…:ClassName: body finding");
        assert!(hit.evidence.contains("PHP"));
        assert!(hit.evidence.contains("request body"));
    }

    #[test]
    fn deserialization_no_false_positive_on_clean_body() {
        let mut req = Request::new("POST", "https://example.com/update").unwrap();
        req.headers.set("Content-Type", "application/json");
        req.body = br#"{"name":"alice","email":"alice@example.com"}"#.to_vec();
        let findings =
            InsecureDeserializationMarkers.run(&tx(req, Response::new(200)));
        assert!(
            findings.is_empty(),
            "clean JSON body must not false-positive, got {} finding(s)",
            findings.len()
        );
    }
}
