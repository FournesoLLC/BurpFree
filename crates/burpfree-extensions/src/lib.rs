//! Extension SDK and in-process loader.
//!
//! The SDK gives extension authors stable Rust traits plus a
//! permission-aware `PluginContext`. The loader keeps a registry
//! and routes callbacks on request/response and scan events.
//!
//! Later versions can swap the registry for a `wasmtime` sandbox so
//! extensions can run as portable WASM; the trait boundaries do not
//! change.

pub mod loader;
pub use loader::{install_builtin, load_builtins, uninstall_builtin, ExtensionsConfig};

use std::sync::Arc;

use async_trait::async_trait;
use burpfree_core::rules::CustomPassiveRule;
use burpfree_core::traffic::{Request, Response, Transaction};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Permissions an extension may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read traffic observed by the proxy.
    ObserveTraffic,
    /// Modify traffic before it leaves / arrives.
    ModifyTraffic,
    /// Register passive scan detectors.
    RegisterPassive,
    /// Register active scan probes.
    RegisterActive,
    /// Register payload providers for Intruder.
    RegisterPayloads,
    /// Register UI panels (requires GUI).
    Ui,
    /// Access the filesystem.
    Fs,
    /// Access the network outside the proxy.
    Net,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub permissions: Vec<Permission>,
}

/// Permission-aware context handed to extensions. Methods check the
/// requested permission before granting access.
#[derive(Clone)]
pub struct PluginContext {
    pub manifest: Arc<Manifest>,
    pub granted: Arc<Vec<Permission>>,
    pub project_name: String,
}

impl PluginContext {
    pub fn requires(&self, p: Permission) -> anyhow::Result<()> {
        if self.granted.contains(&p) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("extension `{}` lacks permission {:?}", self.manifest.name, p))
        }
    }
}

/// Traffic-pipeline callbacks every extension can implement.
/// Maps to Burp Suite's Montoya API (`BurpExtension` + listener
/// registration pattern). Extensions implement the methods they
/// care about; default impls are no-ops.
///
/// # Montoya API mapping
///
/// | BurpFree method             | Montoya equivalent                           |
/// |-----------------------------|----------------------------------------------|
/// | `on_request`                | `IHttpListener.processHttpRequestToBeSent`   |
/// | `on_response`               | `IHttpListener.processHttpResponseReceived`  |
/// | `on_transaction`            | Passive scan callback                        |
/// | `on_proxy_request`          | `IProxyListener` (request direction)         |
/// | `on_proxy_response`         | `IProxyListener` (response direction)        |
/// | `on_scope_change`           | `IScopeChangeListener`                       |
/// | `passive_rules`             | Declarative `IScannerCheck` rules             |
/// | `active_scan_checks`        | `IScannerCheck.activeAudit` insertion points  |
/// | `context_menu_items`        | `IContextMenuFactory.createMenuItems`        |
/// | `intruder_payload_generator`| `IIntruderPayloadGeneratorFactory`           |
/// | `session_handling_action`   | `ISessionHandlingAction`                     |
#[async_trait]
pub trait Extension: Send + Sync {
    fn manifest(&self) -> Manifest;

    /// Called when a request has been parsed; may edit (requires `ModifyTraffic`).
    async fn on_request(&self, _ctx: &PluginContext, _req: &mut Request) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called when a response is about to be returned to the client.
    async fn on_response(
        &self,
        _ctx: &PluginContext,
        _req: &Request,
        _resp: &mut Response,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called for every observed transaction (post-storage). Useful for
    /// passive scanners.
    async fn on_transaction(&self, _ctx: &PluginContext, _tx: &Transaction) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called when a request passes through the proxy (before forwarding).
    /// Unlike `on_request`, this fires only for proxy-intercepted traffic,
    /// not Repeater/Intruder/Scanner sends. Maps to Burp's `IProxyListener`.
    async fn on_proxy_request(&self, _ctx: &PluginContext, _req: &mut Request) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called when a response arrives at the proxy (before returning to client).
    async fn on_proxy_response(
        &self,
        _ctx: &PluginContext,
        _req: &Request,
        _resp: &mut Response,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called when the scope configuration changes.
    /// Maps to Burp's `IScopeChangeListener`.
    fn on_scope_change(&self, _ctx: &PluginContext) {
        // default no-op
    }

    /// Declarative passive rules this extension contributes to the
    /// scanner. Each rule is a labelled severity + matcher, evaluated
    /// against every observed transaction when the extension is
    /// enabled and holds `RegisterPassive`.
    fn passive_rules(&self) -> Vec<CustomPassiveRule> {
        Vec::new()
    }

    /// Active scan check definitions. Each entry describes an insertion
    /// point + payload set that the active scanner will probe. Maps to
    /// Burp's `IScannerCheck.activeAudit` + `IScannerInsertionPointProvider`.
    fn active_scan_checks(&self) -> Vec<ActiveScanCheck> {
        Vec::new()
    }

    /// Context menu items this extension contributes. Maps to Burp's
    /// `IContextMenuFactory.createMenuItems`. Called when the user
    /// right-clicks in a message editor, history row, or site map node.
    fn context_menu_items(&self) -> Vec<ContextMenuItem> {
        Vec::new()
    }

    /// Custom Intruder payload generator. Maps to Burp's
    /// `IIntruderPayloadGeneratorFactory`. Returns a list of payload
    /// strings for a given base value. None = this extension doesn't
    /// provide payloads.
    fn intruder_payloads(&self, _base_value: &str) -> Option<Vec<String>> {
        None
    }

    /// Session handling action. Maps to Burp's `ISessionHandlingAction`.
    /// Called during session rule evaluation to let extensions modify
    /// requests (e.g. inject auth tokens, rotate CSRF tokens).
    async fn session_handling_action(
        &self,
        _ctx: &PluginContext,
        _req: &mut Request,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Active scan check definition contributed by an extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveScanCheck {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub payloads: Vec<String>,
    /// Insertion point type: "param" | "header" | "cookie" | "url" | "body"
    pub insertion_point: String,
}

/// Context menu item contributed by an extension.
pub struct ContextMenuItem {
    pub label: String,
    pub description: String,
    /// Called when the user clicks this menu item. The argument is
    /// the currently selected text/URL (empty string if nothing selected).
    pub action: Arc<dyn Fn(&str) + Send + Sync>,
}

impl std::fmt::Debug for ContextMenuItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextMenuItem")
            .field("label", &self.label)
            .field("description", &self.description)
            .field("action", &"<fn>")
            .finish()
    }
}

/// In-process registry of enabled extensions.
#[derive(Default, Clone)]
pub struct ExtensionRegistry {
    inner: Arc<DashMap<String, Loaded>>,
}

struct Loaded {
    ext: Arc<dyn Extension>,
    ctx: PluginContext,
    enabled: parking_lot::RwLock<bool>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, ext: Arc<dyn Extension>, project: &str) -> anyhow::Result<()> {
        let manifest = Arc::new(ext.manifest());
        let granted = Arc::new(manifest.permissions.clone());
        let ctx = PluginContext {
            manifest: manifest.clone(),
            granted,
            project_name: project.to_string(),
        };
        let name = manifest.name.clone();
        self.inner.insert(
            name,
            Loaded {
                ext,
                ctx,
                enabled: parking_lot::RwLock::new(true),
            },
        );
        Ok(())
    }

    pub fn list(&self) -> Vec<Manifest> {
        self.inner.iter().map(|e| (*e.ctx.manifest).clone()).collect()
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        match self.inner.get(name) {
            Some(l) => {
                *l.enabled.write() = enabled;
                true
            }
            None => false,
        }
    }

    pub fn remove(&self, name: &str) -> bool {
        self.inner.remove(name).is_some()
    }

    pub async fn on_request(&self, req: &mut Request) {
        for entry in self.inner.iter() {
            if !*entry.enabled.read() {
                continue;
            }
            if entry.ctx.requires(Permission::ModifyTraffic).is_err() {
                continue;
            }
            if let Err(e) = entry.ext.on_request(&entry.ctx, req).await {
                tracing::warn!(extension = %entry.ctx.manifest.name, error = %e, "extension on_request failed");
            }
        }
    }

    pub async fn on_response(&self, req: &Request, resp: &mut Response) {
        for entry in self.inner.iter() {
            if !*entry.enabled.read() {
                continue;
            }
            if entry.ctx.requires(Permission::ModifyTraffic).is_err() {
                continue;
            }
            if let Err(e) = entry.ext.on_response(&entry.ctx, req, resp).await {
                tracing::warn!(extension = %entry.ctx.manifest.name, error = %e, "extension on_response failed");
            }
        }
    }

    pub async fn on_transaction(&self, tx: &Transaction) {
        for entry in self.inner.iter() {
            if !*entry.enabled.read() {
                continue;
            }
            if entry.ctx.requires(Permission::ObserveTraffic).is_err() {
                continue;
            }
            if let Err(e) = entry.ext.on_transaction(&entry.ctx, tx).await {
                tracing::warn!(extension = %entry.ctx.manifest.name, error = %e, "extension on_transaction failed");
            }
        }
    }

    /// Collect every declarative passive rule from enabled extensions
    /// that hold the `RegisterPassive` permission. The scanner
    /// orchestrator consults this method before each run.
    pub fn passive_rules(&self) -> Vec<CustomPassiveRule> {
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            if !*entry.enabled.read() {
                continue;
            }
            if entry.ctx.requires(Permission::RegisterPassive).is_err() {
                continue;
            }
            out.extend(entry.ext.passive_rules());
        }
        out
    }
}

/// A reference extension: tags every observed transaction with its host.
pub struct HostTagger;

#[async_trait]
impl Extension for HostTagger {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "host-tagger".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: "Tags observed transactions with their host name".into(),
            permissions: vec![Permission::ObserveTraffic],
        }
    }
    async fn on_transaction(&self, _ctx: &PluginContext, _tx: &Transaction) -> anyhow::Result<()> {
        // In a real extension, we'd push a tag through a shared handle;
        // this reference impl is intentionally minimal.
        Ok(())
    }
}

/// Reference extension that strips `X-Powered-By` from responses.
pub struct StripPoweredBy;

#[async_trait]
impl Extension for StripPoweredBy {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "strip-powered-by".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: "Removes `X-Powered-By` from inbound responses".into(),
            permissions: vec![Permission::ModifyTraffic],
        }
    }
    async fn on_response(&self, _ctx: &PluginContext, _req: &Request, resp: &mut Response) -> anyhow::Result<()> {
        resp.headers.remove("X-Powered-By");
        Ok(())
    }
}

/// Reference extension that contributes custom passive rules for a
/// handful of common secret-shaped leaks observed in responses.
///
/// Showcases how an extension can register declarative detectors
/// without writing any Rust against the scanner internals.
pub struct SecretsLeakDetector;

#[async_trait]
impl Extension for SecretsLeakDetector {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "secrets-leak-detector".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description:
                "Flags responses that look like they contain AWS access keys, GitHub tokens, \
                 private key PEM blocks, or JWTs."
                    .into(),
            permissions: vec![Permission::RegisterPassive],
        }
    }

    fn passive_rules(&self) -> Vec<CustomPassiveRule> {
        use burpfree_core::rules::CustomMatcher;
        let rule = |id: &str, title: &str, severity: &str, pattern: &str, cwe: &[&str]| CustomPassiveRule {
            id: id.into(),
            title: title.into(),
            severity: severity.into(),
            confidence: "firm".into(),
            description: format!(
                "The response body contains text matching the pattern used for {title}. \
                 Secrets committed in responses can be exfiltrated by browser scripts, \
                 downstream caches, logs, or man-in-the-middle attackers."
            ),
            remediation:
                "Rotate the leaked credential immediately, revoke it where possible, and \
                 remove the sensitive value from the response. Audit the issuing source \
                 for exposure in VCS history and client-side bundles."
                    .into(),
            references: vec![
                "https://cwe.mitre.org/data/definitions/798.html".into(),
                "https://cwe.mitre.org/data/definitions/200.html".into(),
            ],
            cwe: cwe.iter().map(|s| s.to_string()).collect(),
            when: CustomMatcher::BodyMatches {
                pattern: pattern.into(),
                response: true,
            },
            insertion_point: Some("body".into()),
        };
        vec![
            rule(
                "aws-access-key",
                "Possible AWS access key in response",
                "high",
                r"AKIA[0-9A-Z]{16}",
                &["CWE-798"],
            ),
            rule(
                "github-token",
                "Possible GitHub personal access token in response",
                "high",
                r"gh[pousr]_[A-Za-z0-9]{36,251}",
                &["CWE-798"],
            ),
            rule(
                "slack-token",
                "Possible Slack token in response",
                "high",
                r"xox[baprs]-[A-Za-z0-9-]{10,48}",
                &["CWE-798"],
            ),
            rule(
                "pem-private-key",
                "Private key PEM block in response",
                "critical",
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
                &["CWE-798", "CWE-200"],
            ),
            rule(
                "jwt-token",
                "JWT-shaped token in response",
                "low",
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                &["CWE-200"],
            ),
        ]
    }
}

/// Reference extension: stamps outbound requests with an
/// `X-Request-Id` header so they are easy to grep for in upstream
/// logs. Useful when auditing in parallel with another engineer who is
/// tailing a server log.
pub struct RequestIdStamper;

#[async_trait]
impl Extension for RequestIdStamper {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "request-id-stamper".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description:
                "Adds an `X-Request-Id` header carrying a random token to every outbound \
                 request so individual replays can be correlated with upstream logs."
                    .into(),
            permissions: vec![Permission::ModifyTraffic],
        }
    }
    async fn on_request(&self, _ctx: &PluginContext, req: &mut Request) -> anyhow::Result<()> {
        if !req.headers.has("X-Request-Id") {
            let rid = burpfree_core::ids::random_token(12);
            req.headers.set("X-Request-Id", rid);
        }
        Ok(())
    }
}

/// Reference extension: appends `X-BurpFree-Audit: scanned` to every
/// response the proxy returns, so a downstream browser or Playwright
/// run can detect which pages have been seen by the proxy at least
/// once. Useful as a smoke test that the extension pipeline is live.
pub struct ResponseHeaderInjector;

#[async_trait]
impl Extension for ResponseHeaderInjector {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "response-header-injector".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description:
                "Stamps `X-BurpFree-Audit: scanned` on every response — a lightweight canary \
                 proving the extension pipeline is live without touching semantics."
                    .into(),
            permissions: vec![Permission::ModifyTraffic],
        }
    }
    async fn on_response(&self, _ctx: &PluginContext, _req: &Request, resp: &mut Response) -> anyhow::Result<()> {
        resp.headers.set_if_missing("X-BurpFree-Audit", "scanned");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BApp-Store style catalog
// ---------------------------------------------------------------------------

/// One row in the extension catalog UI. The frontend uses this to
/// render Install / Installed buttons, Preview badges, and
/// documentation links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    /// External docs / source URL rendered on the card.
    pub source_url: String,
    /// Short category label ("passive-scan", "traffic-mod", "ui").
    pub category: String,
    /// Whether BurpFree currently ships a working implementation of
    /// this extension. `false` entries render as preview-only cards.
    pub available: bool,
}

/// The curated list of reference extensions BurpFree knows about.
/// Entries flagged `available = false` are preview rows: they appear
/// in the catalog but cannot be installed yet. New built-in
/// extensions should be registered in `load_builtins` and promoted to
/// `available = true` here in the same change.
pub fn catalog() -> Vec<CatalogEntry> {
    vec![
        CatalogEntry {
            name: "strip-powered-by".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: StripPoweredBy.manifest().description,
            permissions: StripPoweredBy.manifest().permissions,
            source_url: "https://github.com/burpfree/burpfree/tree/main/crates/burpfree-extensions".into(),
            category: "traffic-mod".into(),
            available: true,
        },
        CatalogEntry {
            name: "host-tagger".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: HostTagger.manifest().description,
            permissions: HostTagger.manifest().permissions,
            source_url: "https://github.com/burpfree/burpfree/tree/main/crates/burpfree-extensions".into(),
            category: "observability".into(),
            available: true,
        },
        CatalogEntry {
            name: "secrets-leak-detector".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: SecretsLeakDetector.manifest().description,
            permissions: SecretsLeakDetector.manifest().permissions,
            source_url: "https://github.com/burpfree/burpfree/tree/main/crates/burpfree-extensions".into(),
            category: "passive-scan".into(),
            available: true,
        },
        CatalogEntry {
            name: "request-id-stamper".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: RequestIdStamper.manifest().description,
            permissions: RequestIdStamper.manifest().permissions,
            source_url: "https://github.com/burpfree/burpfree/tree/main/crates/burpfree-extensions".into(),
            category: "traffic-mod".into(),
            available: true,
        },
        CatalogEntry {
            name: "response-header-injector".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: ResponseHeaderInjector.manifest().description,
            permissions: ResponseHeaderInjector.manifest().permissions,
            source_url: "https://github.com/burpfree/burpfree/tree/main/crates/burpfree-extensions".into(),
            category: "traffic-mod".into(),
            available: true,
        },
        CatalogEntry {
            name: "csrf-token-rotator".into(),
            version: "0.0.1".into(),
            author: "BurpFree contributors".into(),
            description:
                "Preview — will rotate CSRF tokens across Repeater sessions by learning the \
                 token source from a first captured request. Shipping in a future round."
                    .into(),
            permissions: vec![Permission::ModifyTraffic, Permission::ObserveTraffic],
            source_url: "https://github.com/burpfree/burpfree/issues?q=csrf".into(),
            category: "traffic-mod".into(),
            available: false,
        },
        CatalogEntry {
            name: "cookie-jar-exporter".into(),
            version: "0.0.1".into(),
            author: "BurpFree contributors".into(),
            description:
                "Preview — will export the active session's cookie jar as a cURL / Playwright \
                 snippet. Shipping in a future round."
                    .into(),
            permissions: vec![Permission::ObserveTraffic, Permission::Fs],
            source_url: "https://github.com/burpfree/burpfree/issues?q=cookie+export".into(),
            category: "observability".into(),
            available: false,
        },
    ]
}

/// Resolve a catalog name to a fresh `Arc<dyn Extension>` suitable for
/// `ExtensionRegistry::register`. Returns `None` for preview entries
/// (anything whose `available` flag is `false`).
pub fn instantiate_builtin(name: &str) -> Option<Arc<dyn Extension>> {
    match name {
        "strip-powered-by" => Some(Arc::new(StripPoweredBy)),
        "host-tagger" => Some(Arc::new(HostTagger)),
        "secrets-leak-detector" => Some(Arc::new(SecretsLeakDetector)),
        "request-id-stamper" => Some(Arc::new(RequestIdStamper)),
        "response-header-injector" => Some(Arc::new(ResponseHeaderInjector)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response};

    #[tokio::test]
    async fn registry_runs_on_response() {
        let reg = ExtensionRegistry::new();
        reg.register(Arc::new(StripPoweredBy), "proj").unwrap();
        let req = Request::new("GET", "http://x.local/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("X-Powered-By", "Express");
        reg.on_response(&req, &mut resp).await;
        assert!(!resp.headers.has("X-Powered-By"));
    }

    #[tokio::test]
    async fn disabled_extension_is_skipped() {
        let reg = ExtensionRegistry::new();
        reg.register(Arc::new(StripPoweredBy), "proj").unwrap();
        reg.set_enabled("strip-powered-by", false);
        let req = Request::new("GET", "http://x.local/").unwrap();
        let mut resp = Response::new(200);
        resp.headers.set("X-Powered-By", "Express");
        reg.on_response(&req, &mut resp).await;
        assert!(resp.headers.has("X-Powered-By"));
    }

    #[test]
    fn registry_returns_passive_rules_from_enabled_extensions() {
        let reg = ExtensionRegistry::new();
        reg.register(Arc::new(SecretsLeakDetector), "proj").unwrap();
        // Extension with no RegisterPassive permission must NOT contribute.
        struct NoPerm;
        #[async_trait]
        impl Extension for NoPerm {
            fn manifest(&self) -> Manifest {
                Manifest {
                    name: "noperm".into(), version: "0".into(), author: "t".into(),
                    description: "".into(), permissions: vec![],
                }
            }
            fn passive_rules(&self) -> Vec<CustomPassiveRule> {
                vec![CustomPassiveRule {
                    id: "noperm.rule".into(), title: "sneaky".into(),
                    severity: "info".into(), confidence: "firm".into(),
                    description: String::new(), remediation: String::new(),
                    references: vec![], cwe: vec![],
                    when: burpfree_core::rules::CustomMatcher::StatusInRange { min: 0, max: 999 },
                    insertion_point: None,
                }]
            }
        }
        reg.register(Arc::new(NoPerm), "proj").unwrap();

        let rules = reg.passive_rules();
        assert!(rules.iter().all(|r| r.id != "noperm.rule"));
        assert!(rules.iter().any(|r| r.id == "aws-access-key"));
        assert!(rules.iter().any(|r| r.id == "pem-private-key"));

        // Disabling the detector should drop its rules.
        reg.set_enabled("secrets-leak-detector", false);
        let rules = reg.passive_rules();
        assert!(rules.iter().all(|r| r.id != "aws-access-key"));
    }

    #[tokio::test]
    async fn permission_gates_access() {
        struct NoPerms;
        #[async_trait]
        impl Extension for NoPerms {
            fn manifest(&self) -> Manifest {
                Manifest {
                    name: "no-perms".into(),
                    version: "0.1.0".into(),
                    author: "test".into(),
                    description: "".into(),
                    permissions: vec![],
                }
            }
            async fn on_response(&self, _ctx: &PluginContext, _req: &Request, resp: &mut Response) -> anyhow::Result<()> {
                resp.headers.set("X-Mutated", "yes");
                Ok(())
            }
        }
        let reg = ExtensionRegistry::new();
        reg.register(Arc::new(NoPerms), "proj").unwrap();
        let req = Request::new("GET", "http://x.local/").unwrap();
        let mut resp = Response::new(200);
        reg.on_response(&req, &mut resp).await;
        assert!(!resp.headers.has("X-Mutated"));
    }
}
