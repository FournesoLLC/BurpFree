//! Shared app state carried by the Tauri runtime.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use burpfree_ca::CertificateAuthority;
use burpfree_core::events::EventBus;
use burpfree_core::scope::Scope;
use burpfree_engines::client::{HttpClient, HttpClientConfig};
use burpfree_engines::repeater::Repeater;
use burpfree_engines::macros::SessionRuleRegistry;
use burpfree_engines::session::CookieJar;
use burpfree_engines::sitemap::SiteMap;
use burpfree_extensions::ExtensionRegistry;
use burpfree_oob::OobServerHandle;
use burpfree_proxy::{Interceptor, MatchReplaceEngine, ProxyHandle, Upstream};
use burpfree_storage::Project;
use parking_lot::RwLock;
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use burpfree_engines::intruder::JobHandle as IntruderJobHandle;

pub struct AppState {
    /// Tokio runtime handle. Kept so Tauri can submit work from the UI
    /// thread into our runtime if needed in future commands.
    #[allow(dead_code)]
    pub rt: Handle,
    pub project: RwLock<Option<ProjectHandle>>,
    pub intruder_jobs: Mutex<std::collections::HashMap<i64, IntruderJobHandle>>,
    /// Handle for the current automatic-backup scheduler task.
    /// Replaced on every project open + every `backup_config_set`
    /// so a tightened interval kicks in without waiting out the
    /// previous sleep. Uses `parking_lot::Mutex` (not tokio's)
    /// because `JoinHandle::abort` is sync — the swap is a tiny
    /// critical section and must work from both the bootstrap
    /// thread (no runtime context) and Tauri command handlers.
    pub backup_task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub events: EventBus,
    /// Ring buffer of the most recent events for the Logger panel.
    pub logger: Arc<RwLock<LoggerBuffer>>,
    /// Live-passive-scan toggle. Read on every `TrafficSink::record`
    /// call so flipping it from the UI takes effect immediately without
    /// restarting the proxy. Mirrors `ProjectConfig::live_passive_scan`
    /// so the AtomicBool is the hot path and the config is the durable
    /// store.
    pub live_passive_scan: Arc<AtomicBool>,
    /// Record-out-of-scope toggle. Read inside the proxy's
    /// `publish_and_record` gate so flipping it from Settings takes
    /// effect on the next request without restarting the proxy.
    /// Mirrors `ProjectConfig::record_out_of_scope` on disk. `true`
    /// = record everything (Burp default); `false` = suppress
    /// out-of-scope items from history / sitemap / events (Burp's
    /// "drop out-of-scope items").
    pub record_out_of_scope: Arc<AtomicBool>,
    /// Pause-history-recording toggle (R131). When `false`, the
    /// main proxy sink skips `history.upsert_transaction` + the
    /// sitemap observe + the live-passive-scan dispatch for every
    /// transaction. Burp calls this "Suspend logging to project
    /// file"; operators flip it off before hitting a credential
    /// endpoint so secrets don't persist. Defaults to `true`
    /// (record everything). This is session-ephemeral — a restart
    /// resets to on so a forgotten "off" doesn't silently stop
    /// capturing the next session's traffic.
    pub history_recording: Arc<AtomicBool>,
    /// TLS pass-through host list. Shared with the running proxy via
    /// `ServerConfig::tls_passthrough` so edits propagate without a
    /// proxy restart. Mirrors `ProjectConfig::tls_passthrough` on disk.
    pub tls_passthrough: Arc<RwLock<Vec<String>>>,
    /// Platform-authentication credential list. Shared with the
    /// running proxy via `ServerConfig::platform_auth` so a Settings
    /// edit (add / toggle / password change) takes effect on the
    /// next upstream 401 without a proxy restart. Mirrors
    /// `ProjectConfig::platform_auth` on disk (opaque JSON there,
    /// typed PlatformAuthCredential here). Mirror of Burp's
    /// `Settings → Network → Platform authentication` page.
    pub platform_auth:
        Arc<RwLock<Vec<burpfree_proxy::platform_auth::PlatformAuthCredential>>>,
    /// Passive detector ids that the operator has turned off for
    /// this project. Shared with the proxy sink via a cheap HashSet
    /// lookup on every recorded transaction so flipping a checkbox
    /// takes effect on the next request without a scanner restart.
    /// Mirrors `ProjectConfig::disabled_passive_detectors` on disk.
    pub disabled_passive_detectors: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Active probe ids the operator has turned off for this project.
    /// Mirrors `ProjectConfig::disabled_active_probes`. Read by a
    /// future active-scan dispatcher to filter the probe list; the
    /// Tauri cmds `scanner_active_probes_list` /
    /// `scanner_active_probe_set` flip membership here and persist
    /// to the project config so toggles survive a restart.
    pub disabled_active_probes: Arc<RwLock<std::collections::HashSet<String>>>,
}

/// Bounded FIFO of event-bus observations, each tagged with a stable
/// monotonic sequence number so the UI can diff.
pub struct LoggerBuffer {
    pub next_seq: u64,
    pub items: std::collections::VecDeque<LoggedEvent>,
    pub capacity: usize,
}

impl LoggerBuffer {
    pub fn new(cap: usize) -> Self {
        Self {
            next_seq: 0,
            items: std::collections::VecDeque::with_capacity(cap.min(2048)),
            capacity: cap,
        }
    }

    pub fn push(&mut self, event: burpfree_core::events::TrafficEvent) {
        self.next_seq += 1;
        let logged = LoggedEvent { seq: self.next_seq, event };
        if self.items.len() >= self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(logged);
    }

    pub fn drain_since(&self, cursor: u64) -> Vec<LoggedEvent> {
        self.items
            .iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect()
    }

    pub fn last_n(&self, n: usize) -> Vec<LoggedEvent> {
        let start = self.items.len().saturating_sub(n);
        self.items.iter().skip(start).cloned().collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LoggedEvent {
    pub seq: u64,
    pub event: burpfree_core::events::TrafficEvent,
}

#[derive(Clone)]
pub struct ProjectHandle {
    pub project: Arc<RwLock<Project>>,
    /// Project root on disk. Retained for future UI commands that may
    /// let the user open a different project.
    #[allow(dead_code)]
    pub path: PathBuf,
    pub ca: CertificateAuthority,
    pub scope: Arc<RwLock<Scope>>,
    pub match_replace: Arc<RwLock<MatchReplaceEngine>>,
    pub interceptor: Interceptor,
    pub upstream: Arc<RwLock<Upstream>>,
    pub proxy: Arc<RwLock<Option<ProxyHandle>>>,
    pub repeater: Repeater,
    pub sitemap: Arc<SiteMap>,
    pub extensions: ExtensionRegistry,
    /// Shared OOB listener handle. Started on demand via Tauri command;
    /// None until the user starts it. Scanner/Intruder can hand this to
    /// their OOB-aware probes.
    pub oob: Arc<RwLock<Option<OobServerHandle>>>,
    /// Session macros + rules. Persisted inside `config.json`.
    pub session_rules: SessionRuleRegistry,
    /// Status of the most-recent passive scan driven from the UI. The
    /// Dashboard polls this so a long-running scan shows live progress.
    pub scan: Arc<RwLock<PassiveScanStatus>>,
    /// Project-level hostname → IP override map. Shared with the proxy
    /// (direct dial path) and the HTTP client for Repeater / Intruder.
    pub host_overrides: burpfree_core::net::HostOverrides,
    /// WebSocket outbound-frame interception queue. Consulted by
    /// `ws_replay` (and, in future rounds, the proxy's WS bridge) on
    /// every outbound frame.
    pub ws_interceptor: burpfree_proxy::WsInterceptor,
    /// Project-level cookie jar. Both proxy sinks call
    /// `observe_response` on every recorded transaction so Set-Cookie
    /// headers from any origin populate the jar. The internal
    /// storage is `Arc<RwLock<Vec<Cookie>>>` so `clone()` shares the
    /// same Vec across every holder (ProjectSink, autostart Sink,
    /// Repeater macros, Tauri cmds). Runtime-only — Burp persists
    /// the jar inside the project file, we keep it in memory this
    /// round and can add disk round-tripping later.
    pub cookie_jar: CookieJar,
}

#[derive(Debug, Clone, Default)]
pub struct PassiveScanStatus {
    pub running: bool,
    pub findings_last_run: Option<usize>,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

impl AppState {
    pub fn new(rt: Handle) -> Self {
        let events = EventBus::default();
        let logger = Arc::new(RwLock::new(LoggerBuffer::new(2048)));
        // Pump the event bus into the ring buffer in a background task.
        let logger_cloned = logger.clone();
        let mut sub = events.subscribe();
        rt.spawn(async move {
            while let Some(ev) = sub.recv().await {
                logger_cloned.write().push(ev);
            }
        });
        Self {
            rt,
            project: RwLock::new(None),
            intruder_jobs: Mutex::new(Default::default()),
            backup_task: parking_lot::Mutex::new(None),
            events,
            logger,
            live_passive_scan: Arc::new(AtomicBool::new(true)),
            record_out_of_scope: Arc::new(AtomicBool::new(true)),
            history_recording: Arc::new(AtomicBool::new(true)),
            tls_passthrough: Arc::new(RwLock::new(Vec::new())),
            platform_auth: Arc::new(RwLock::new(Vec::new())),
            disabled_passive_detectors: Arc::new(RwLock::new(
                std::collections::HashSet::new(),
            )),
            disabled_active_probes: Arc::new(RwLock::new(
                std::collections::HashSet::new(),
            )),
        }
    }

    pub fn require(&self) -> Result<ProjectHandle> {
        self.project
            .read()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("no project is open"))
    }

    pub fn load_project(&self, path: PathBuf) -> Result<ProjectHandle> {
        let project = if path.exists() && path.join("config.json").exists() {
            Project::open(&path)?
        } else {
            Project::create(&path)?
        };
        let ca = CertificateAuthority::load_or_create(project.root.join("ca"))?;
        let scope = Arc::new(RwLock::new(project.config.scope.clone()));
        let mr_rules: Vec<burpfree_proxy::matchreplace::Rule> = project
            .config
            .match_replace_rules
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();
        let match_replace = Arc::new(RwLock::new(MatchReplaceEngine::with_rules(mr_rules)));

        // Hydrate interception rules from the project config.
        let interceptor = Interceptor::new();
        let req_rules: Vec<burpfree_proxy::interceptor::InterceptRule> = project
            .config
            .intercept_rules_request
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();
        let resp_rules: Vec<burpfree_proxy::interceptor::InterceptRule> = project
            .config
            .intercept_rules_response
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();
        interceptor.set_request_rules(burpfree_proxy::interceptor::InterceptRules { rules: req_rules });
        interceptor.set_response_rules(burpfree_proxy::interceptor::InterceptRules { rules: resp_rules });

        // Hostname overrides.
        let host_entries: Vec<burpfree_core::net::HostOverride> = project
            .config
            .host_overrides
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();
        let host_overrides = burpfree_core::net::HostOverrides::load(host_entries);
        let upstream = Arc::new(RwLock::new(Upstream {
            url: project.config.upstream.url.clone(),
            username: project.config.upstream.username.clone(),
            password: project.config.upstream.password.clone(),
        }));
        // Give the Repeater HttpClient the project's current host-override
        // registry + follow-redirect policy so Send honours both.
        let follow_redirects = match project
            .config
            .follow_redirects
            .as_deref()
            .unwrap_or("never")
        {
            "on_site" => burpfree_core::net::FollowRedirectPolicy::OnSite,
            "in_scope" => burpfree_core::net::FollowRedirectPolicy::InScope,
            "always" => burpfree_core::net::FollowRedirectPolicy::Always,
            _ => burpfree_core::net::FollowRedirectPolicy::Never,
        };
        let repeater_cfg = HttpClientConfig {
            host_overrides: Some(host_overrides.clone()),
            follow_redirects,
            ..HttpClientConfig::default()
        };
        let repeater =
            Repeater::load_or_new(&project.repeater_path(), HttpClient::new(repeater_cfg))?;
        let sitemap = Arc::new(SiteMap::new());
        let extensions = burpfree_extensions::load_builtins(&project.root)?;

        // Hydrate session-rule registry from persisted config.
        let (macros, rules) = {
            // The project's `macros`/`session_rules` fields store JSON
            // values so the storage crate stays free of an engines dep.
            let project_guard = &project.config;
            let macros: Vec<_> = project_guard
                .macros
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            let rules: Vec<_> = project_guard
                .session_rules
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            (macros, rules)
        };
        let session_rules = SessionRuleRegistry::new();
        session_rules.load_snapshot(macros, rules);

        let handle = ProjectHandle {
            project: Arc::new(RwLock::new(project)),
            path: path.clone(),
            ca,
            scope,
            match_replace,
            interceptor,
            upstream,
            proxy: Arc::new(RwLock::new(None)),
            repeater,
            sitemap,
            extensions,
            oob: Arc::new(RwLock::new(None)),
            session_rules,
            scan: Arc::new(RwLock::new(PassiveScanStatus::default())),
            host_overrides,
            ws_interceptor: burpfree_proxy::WsInterceptor::new(),
            cookie_jar: CookieJar::new(),
        };
        // Hydrate live-passive-scan from the project config so the
        // AtomicBool and the durable config agree before the sink is
        // first invoked.
        self.live_passive_scan.store(
            handle.project.read().config.live_passive_scan,
            Ordering::Relaxed,
        );
        // Hydrate record-out-of-scope from the project config so the
        // proxy gate sees the right value from the first request.
        // Same shape as live_passive_scan — AtomicBool is the hot
        // path, config.json is the durable store.
        self.record_out_of_scope.store(
            handle.project.read().config.record_out_of_scope,
            Ordering::Relaxed,
        );
        // Hydrate TLS pass-through list from the project config so the
        // shared Arc<RwLock<Vec<String>>> and the durable config agree
        // before the proxy auto-starts.
        {
            let snapshot = handle.project.read().config.tls_passthrough.clone();
            *self.tls_passthrough.write() = snapshot;
        }
        // Hydrate platform-authentication credentials from the project
        // config. Each entry is opaque JSON on disk (the storage crate
        // has no proxy dep); we deserialise defensively so a malformed
        // row doesn't block the project from opening — bad entries
        // are dropped and the operator sees fewer rows in Settings,
        // which matches the project-recovery stance everywhere else
        // (match/replace rules, intercept rules, host overrides).
        {
            let raw: Vec<serde_json::Value> =
                handle.project.read().config.platform_auth.clone();
            let parsed: Vec<burpfree_proxy::platform_auth::PlatformAuthCredential> = raw
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect();
            *self.platform_auth.write() = parsed;
        }
        // Hydrate the disabled passive-detector set from config.
        {
            let snapshot: std::collections::HashSet<String> = handle
                .project
                .read()
                .config
                .disabled_passive_detectors
                .iter()
                .cloned()
                .collect();
            *self.disabled_passive_detectors.write() = snapshot;
        }
        // Hydrate the disabled active-probe set from config.
        {
            let snapshot: std::collections::HashSet<String> = handle
                .project
                .read()
                .config
                .disabled_active_probes
                .iter()
                .cloned()
                .collect();
            *self.disabled_active_probes.write() = snapshot;
        }
        *self.project.write() = Some(handle.clone());
        Ok(handle)
    }
}
