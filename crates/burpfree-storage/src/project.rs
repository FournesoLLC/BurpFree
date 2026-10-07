//! Project directory manager.
//!
//! Everything a user does lives inside a project directory:
//!
//! ```text
//! <project>/
//!   config.json          — proxy, scope, match/replace, upstream, ...
//!   ca/
//!     ca-cert.pem
//!     ca-key.pem         — 0600 on Unix
//!     certs/<host>.pem   — per-host leaf cache
//!   blobs/<ab>/<rest>    — content-addressed body storage
//!   history.db           — SQLite index
//!   repeater.json
//!   intruder.json
//!   log/burpfree.log
//! ```
//!
//! [`Project::open`] loads an existing project; [`Project::create`]
//! initializes a new one with sensible defaults.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use burpfree_core::scope::{Scope, ScopeRule};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use crate::blobs::BlobStore;
use crate::history::HistoryStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub address: String,
    pub tls_intercept: bool,
    pub enabled: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8080".into(),
            tls_intercept: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    /// `""` or `"direct"` = no upstream. `"http://host:port"` for HTTP
    /// proxy. `"socks5://host:port"` for SOCKS5.
    pub url: String,
    pub bypass: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub name: String,
    pub listeners: Vec<ListenerConfig>,
    pub scope: Scope,
    pub upstream: UpstreamConfig,
    pub decompression_cap_mb: u32,
    pub record_out_of_scope: bool,
    pub max_body_mb: u32,
    pub extension_dirs: Vec<String>,
    pub api_bind: String,
    pub ui_bind: String,
    /// Session macros, serialized as opaque JSON values so the storage
    /// crate doesn't take a dep on burpfree-engines. The engines crate
    /// defines the `Macro` schema and (de)serializes it directly.
    #[serde(default)]
    pub macros: Vec<serde_json::Value>,
    #[serde(default)]
    pub session_rules: Vec<serde_json::Value>,
    /// Match/Replace rules, same opaque-JSON approach.
    #[serde(default)]
    pub match_replace_rules: Vec<serde_json::Value>,
    /// Intercept rules for the request direction (opaque JSON).
    #[serde(default)]
    pub intercept_rules_request: Vec<serde_json::Value>,
    /// Intercept rules for the response direction (opaque JSON).
    #[serde(default)]
    pub intercept_rules_response: Vec<serde_json::Value>,
    /// Hostname resolution overrides (opaque JSON — each entry is a
    /// `HostOverride { enabled, hostname, ip }` from burpfree-core).
    #[serde(default)]
    pub host_overrides: Vec<serde_json::Value>,
    /// Default follow-redirect policy for Repeater / Intruder / Scanner.
    /// Serialized as a lowercase string: never | on_site | in_scope | always.
    #[serde(default)]
    pub follow_redirects: Option<String>,
    /// Dashboard tasks (live passive crawl etc.). Opaque JSON because
    /// the task type lives in the engines crate — storage has no need
    /// to understand the shape.
    #[serde(default)]
    pub dashboard_tasks: Vec<serde_json::Value>,
    /// Named Intruder attack recipes. Each entry is `{ name, config,
    /// created_at_ms }`; `config` is the opaque JSON Intruder config
    /// shape owned by burpfree-engines. Stored here so recipes
    /// persist across restarts without needing a sidecar file.
    #[serde(default)]
    pub intruder_recipes: Vec<serde_json::Value>,
    /// Free-form per-host notes shown in the Target panel's SiteMap
    /// right pane. Keyed by hostname (`example.com`) so the mapping
    /// survives port / scheme drift and multiple paths observed on
    /// the same host. Mirrors Burp's "Notes" tab per host.
    #[serde(default)]
    pub host_notes: std::collections::HashMap<String, String>,
    /// Whether the proxy sink runs the passive scanner on every new
    /// in-scope transaction. Burp calls this "Live passive scan"; we
    /// default to on, flipping to off disables the detector pass without
    /// affecting manual `scan_passive` runs.
    #[serde(default = "default_live_passive_scan")]
    pub live_passive_scan: bool,
    /// Named Bambda filter expressions saved by the operator for
    /// reuse across restarts. Each entry is opaque JSON of shape
    /// `{ name, expression, scope, created_at_ms }` where `scope` is
    /// a free-form string (currently `"history"` or `"logger"`) that
    /// lets each UI bar scope its own picker.
    #[serde(default)]
    pub bambda_queries: Vec<serde_json::Value>,
    /// Hosts whose CONNECT tunnels bypass TLS MITM and are forwarded
    /// raw. One entry per pattern; case-insensitive substring match
    /// against the CONNECT target host. Needed for cert-pinned mobile
    /// apps / IoT clients that reject our root CA.
    #[serde(default)]
    pub tls_passthrough: Vec<String>,
    /// Passive scanner detector ids that are turned OFF for this
    /// project. The sink / passive_run_now path filter these out
    /// before firing detectors so operators can silence noisy
    /// checks (e.g. permissions-policy-weakness on apps that will
    /// never adopt it) without recompiling. Empty by default — all
    /// 13 built-in detectors run.
    #[serde(default)]
    pub disabled_passive_detectors: Vec<String>,
    /// Active scanner probe ids that are turned OFF for this
    /// project. The future active-scan dispatcher filters these out
    /// before dispatching each probe. Mirrors the passive-detector
    /// opt-out but applies to the active probe list (reflected-xss,
    /// sql-error, …, graphql-introspection). Empty by default; the
    /// Scanner UI pre-ticks the default-disabled probes
    /// (`blind-sql-time`) when the operator first opens the grid.
    #[serde(default)]
    pub disabled_active_probes: Vec<String>,
    /// Comparer item collection — operator-stashed text snippets
    /// that persist across restarts, matching Burp's numbered
    /// Comparer items list. Each entry is opaque JSON
    /// `{ id, label, text, created_at_ms }`; the frontend owns the
    /// id-generation convention and the display shape. The storage
    /// crate stays unaware of the inner schema so the UI can grow
    /// per-item metadata (bytes, source, highlight) later without
    /// touching this file. Empty by default; a stale corrupt entry
    /// is dropped on hydrate rather than blocking project open —
    /// same recovery stance everywhere else.
    #[serde(default)]
    pub comparer_items: Vec<serde_json::Value>,
    /// HTTP history column ids that the operator has hidden from
    /// the HistoryPanel table. Mirrors Burp's per-table "columns
    /// visible" setting. Known ids: `highlight` / `id` / `method` /
    /// `status` / `host` / `path` / `size` / `time` / `comment` —
    /// anything not in this list stays visible. Empty by default so
    /// a new project shows every column. Persistence lives at the
    /// project level because operators tune column sets per-target
    /// (e.g. a REST-API engagement hides `highlight` + `comment`,
    /// a GraphQL probe hides `method` + `host` since they rarely
    /// change).
    #[serde(default)]
    pub history_hidden_columns: Vec<String>,
    /// Platform-authentication credential list. Each entry is a
    /// `PlatformAuthCredential { host_pattern, scheme, username,
    /// password, enabled }` serialised as opaque JSON so the storage
    /// crate stays free of a `burpfree-proxy` dep — the proxy owns
    /// the schema. Hydrated into `AppState::platform_auth` as a
    /// shared `Arc<RwLock<Vec<..>>>` on project load so flipping
    /// the "enabled" checkbox or editing a password in Settings
    /// takes effect on the next upstream 401 without a proxy
    /// restart. Mirror of Burp's `Settings → Network → Platform
    /// authentication` page.
    #[serde(default)]
    pub platform_auth: Vec<serde_json::Value>,
    /// Automatic project backup settings. Mirrors Burp's
    /// `UserConfig.misc.automatic_project_backup` shape
    /// (enabled / interval / in_scope_only / delete_on_shutdown)
    /// with one addition: a hard cap on how many timestamped
    /// backups the pruner keeps on disk, so a long engagement
    /// doesn't quietly fill the project directory. Defaults mirror
    /// Burp's own: enabled, 30-minute interval, keep 20 copies,
    /// shutdown-delete off.
    #[serde(default)]
    pub auto_backup: AutoBackupConfig,
}

/// Operator-facing config for the periodic project-bundle snapshot
/// scheduler. Mirrors `UserConfig.misc.automatic_project_backup` in
/// Burp's own user config, with `keep_count` added so the
/// disk-pruner has an upper bound that survives restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoBackupConfig {
    /// Master kill-switch. When false the scheduler sleeps forever
    /// until flipped back on. Manual `backup_now()` cmds still fire
    /// regardless so operators can take an on-demand snapshot.
    pub enabled: bool,
    /// Minutes between automatic snapshots. Clamped to `[1, 1440]`
    /// in the scheduler so a stray 0 can't spin a hot loop and a
    /// giant number can't silently disable the feature.
    pub interval_min: u32,
    /// Maximum number of timestamped `backups/*.zip` files to keep
    /// on disk at any time. Older entries get `fs::remove_file`'d
    /// after each successful snapshot.
    pub keep_count: u32,
    /// Wipe every backup zip when the project closes. Matches Burp's
    /// `delete_on_shutdown` option — operators who want to leave no
    /// trail on a shared workstation flip this on.
    pub delete_on_shutdown: bool,
}

impl Default for AutoBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_min: 30,
            keep_count: 20,
            delete_on_shutdown: false,
        }
    }
}

/// Default enabled so new projects pick up findings as the user browses,
/// matching Burp Pro's out-of-the-box behaviour.
fn default_live_passive_scan() -> bool {
    true
}

impl Default for ProjectConfig {
    fn default() -> Self {
        let mut scope = Scope::new();
        // Default: nothing excluded, everything in scope. Users narrow
        // later from the UI.
        scope.default_in_scope_when_empty = true;
        Self {
            name: "BurpFree project".into(),
            listeners: vec![ListenerConfig::default()],
            scope,
            upstream: UpstreamConfig::default(),
            decompression_cap_mb: 256,
            record_out_of_scope: true,
            max_body_mb: 100,
            extension_dirs: vec!["extensions".into()],
            api_bind: "127.0.0.1:8181".into(),
            ui_bind: "127.0.0.1:8182".into(),
            macros: Vec::new(),
            session_rules: Vec::new(),
            match_replace_rules: Vec::new(),
            intercept_rules_request: Vec::new(),
            intercept_rules_response: Vec::new(),
            host_overrides: Vec::new(),
            follow_redirects: None,
            dashboard_tasks: Vec::new(),
            intruder_recipes: Vec::new(),
            host_notes: std::collections::HashMap::new(),
            live_passive_scan: default_live_passive_scan(),
            bambda_queries: Vec::new(),
            tls_passthrough: Vec::new(),
            disabled_passive_detectors: Vec::new(),
            disabled_active_probes: Vec::new(),
            comparer_items: Vec::new(),
            history_hidden_columns: Vec::new(),
            platform_auth: Vec::new(),
            auto_backup: AutoBackupConfig::default(),
        }
    }
}

impl ProjectConfig {
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter(|l| l.enabled)
            .filter_map(|l| SocketAddr::from_str(&l.address).ok())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub config: ProjectConfig,
    pub blobs: Arc<BlobStore>,
    pub history: HistoryStore,
}

impl Project {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.exists() && root.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
            anyhow::bail!("project directory {} is not empty", root.display());
        }
        for sub in ["ca", "blobs", "log", "extensions"] {
            std::fs::create_dir_all(root.join(sub))
                .with_context(|| format!("mkdir {}/{sub}", root.display()))?;
        }
        let config = ProjectConfig::default();
        std::fs::write(
            root.join("config.json"),
            serde_json::to_string_pretty(&config)?,
        )?;
        Self::open(&root)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let cfg_path = root.join("config.json");
        let config: ProjectConfig = if cfg_path.exists() {
            let data = std::fs::read_to_string(&cfg_path)
                .with_context(|| format!("read {}", cfg_path.display()))?;
            serde_json::from_str(&data).with_context(|| format!("parse {}", cfg_path.display()))?
        } else {
            let c = ProjectConfig::default();
            std::fs::write(&cfg_path, serde_json::to_string_pretty(&c)?)?;
            c
        };
        for sub in ["ca", "blobs", "log", "extensions"] {
            std::fs::create_dir_all(root.join(sub))?;
        }
        let blobs = Arc::new(BlobStore::open(root.join("blobs"))?);
        let history = HistoryStore::open(root.join("history.db"))?;
        Ok(Self { root, config, blobs, history })
    }

    pub fn save_config(&self) -> Result<()> {
        let path = self.root.join("config.json");
        std::fs::write(&path, serde_json::to_string_pretty(&self.config)?)
            .with_context(|| format!("write {}", path.display()))
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    pub fn repeater_path(&self) -> PathBuf {
        self.root.join("repeater.json")
    }

    pub fn intruder_path(&self) -> PathBuf {
        self.root.join("intruder.json")
    }

    /// Convenience: add a scope include rule and persist.
    pub fn add_scope_rule(&mut self, rule: ScopeRule) -> Result<()> {
        self.config.scope.add(rule);
        self.save_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_and_reopen() {
        let td = tempdir().unwrap();
        let path = td.path().join("p1");
        let p = Project::create(&path).unwrap();
        assert_eq!(p.config.listeners.len(), 1);
        drop(p);
        let p2 = Project::open(&path).unwrap();
        assert_eq!(p2.config.listeners.len(), 1);
    }

    #[test]
    fn config_round_trips_scope_edits() {
        let td = tempdir().unwrap();
        let path = td.path().join("p");
        let mut p = Project::create(&path).unwrap();
        p.add_scope_rule(ScopeRule::include_host("example.com")).unwrap();
        drop(p);
        let p2 = Project::open(&path).unwrap();
        assert_eq!(p2.config.scope.rules.len(), 1);
    }
}
