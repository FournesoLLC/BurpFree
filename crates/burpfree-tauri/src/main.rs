//! BurpFree desktop shell.
//!
//! Boots a Tauri 2 window, starts the proxy / scanner engines on a
//! background `tokio` runtime, and exposes typed commands to the
//! React frontend.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod state;
mod commands;
mod backup;
mod rest_api;

use std::sync::Arc;
use std::time::Duration;

use state::AppState;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,burpfree_proxy=info")))
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let rt_handle = runtime.handle().clone();
    // Keep the runtime alive for the life of the process.
    let _rt_guard = runtime;

    let state = Arc::new(AppState::new(rt_handle.clone()));

    // Bootstrap: load (or create) the default project and start the
    // proxy on the configured listener before the UI opens. This way
    // the app is immediately useful: open browser â†’ point at the proxy
    // â†’ start intercepting. The frontend is a pure view layer and does
    // not need to orchestrate init.
    bootstrap(&state, &rt_handle);

    tauri::Builder::default()
        .manage(state)
        .setup(|app| {
            // Store the AppHandle so background workers can emit events
            // once we hook that up in a future iteration.
            let _ = app.handle();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::project_open_or_create,
            commands::project_info,
            commands::default_project_path,
            commands::proxy_start,
            commands::proxy_stop,
            commands::proxy_stats,
            commands::ca_export,
            commands::ca_info,
            commands::history_list,
            commands::history_count,
            commands::history_show,
            commands::history_clear,
            commands::history_set_highlight,
            commands::history_set_comment,
            commands::history_set_tags,
            commands::history_delete,
            commands::history_replay,
            commands::history_summaries,
            commands::poc_csrf,
            commands::poc_clickjack,
            commands::mcp_status,
            commands::mcp_test,
            commands::bambda_filter,
            commands::tasks_list,
            commands::tasks_set,
            commands::bchecks_list,
            commands::bchecks_run,
            commands::bchecks_validate,
            commands::bchecks_save,
            commands::bchecks_delete,
            commands::bchecks_read,
            commands::discovery_run,
            commands::discovery_default_wordlist,
            commands::graphql_list_endpoints,
            commands::graphql_introspect,
            commands::graphql_parse_schema_json,
            commands::crawler_run_now,
            commands::jwt_scan_transaction,
            commands::jwt_sign,
            commands::jwt_verify,
            commands::scope_get,
            commands::scope_add_rule,
            commands::scope_remove_rule,
            commands::scope_set,
            commands::match_replace_get,
            commands::match_replace_set,
            commands::match_replace_preview,
            commands::match_replace_hits,
            commands::match_replace_last_fires,
            commands::match_replace_hits_clear,
            commands::interceptor_set,
            commands::interceptor_pending,
            commands::interceptor_status,
            commands::interceptor_resolve,
            commands::interceptor_resolve_all,
            commands::interceptor_show,
            commands::interceptor_rules_get,
            commands::interceptor_rules_set,
            commands::interceptor_rules_preview,
            commands::interceptor_rules_hits,
            commands::interceptor_rules_hits_clear,
            commands::cookie_jar_list,
            commands::cookie_jar_clear,
            commands::cookie_jar_delete,
            commands::cookie_jar_set,
            commands::backup_config_get,
            commands::backup_config_set,
            commands::backup_list,
            commands::backup_now,
            commands::backup_delete,
            commands::host_overrides_get,
            commands::host_overrides_set,
            commands::repeater_list,
            commands::repeater_add_tab,
            commands::repeater_add_from_history,
            commands::repeater_add_from_wire,
            commands::repeater_update,
            commands::repeater_send,
            commands::repeater_cancel,
            commands::repeater_cancel_all,
            commands::repeater_inflight_ids,
            commands::repeater_remove,
            commands::repeater_rename,
            commands::repeater_set_comment,
            commands::repeater_duplicate_tab,
            commands::repeater_tab_clear_history,
            commands::repeater_set_color,
            commands::repeater_change_method,
            commands::repeater_set_body_encoding,
            commands::repeater_set_follow_redirects,
            commands::repeater_set_url,
            commands::repeater_follow_redirect,
            commands::repeater_burst_send,
            commands::repeater_set_group,
            commands::repeater_rename_group,
            commands::repeater_delete_group,
            commands::repeater_list_groups,
            commands::repeater_send_group,
            commands::repeater_reorder,
            commands::repeater_set_pinned,
            commands::intruder_start,
            commands::intruder_cancel,
            commands::intruder_poll,
            commands::intruder_pause,
            commands::intruder_resume,
            commands::intruder_result_to_repeater,
            commands::intruder_recipe_save,
            commands::intruder_recipe_list,
            commands::intruder_recipe_load,
            commands::intruder_recipe_delete,
            commands::host_note_set,
            commands::host_note_get,
            commands::host_notes_list,
            commands::payloads_library_list,
            commands::payloads_library_load,
            commands::sitemap_snapshot,
            commands::target_import_well_known,
            commands::decoder_apply,
            commands::decoder_smart,
            commands::comparer_diff,
            commands::comparer_diff_json,
            commands::sequencer_analyze,
            commands::passive_run_now,
            commands::passive_run_filtered,
            commands::scanner_passive_detectors_list,
            commands::scanner_passive_detector_set,
            commands::scanner_active_probes_list,
            commands::scanner_active_probe_set,
            commands::scanner_active_run_tx,
            commands::passive_ws_run_now,
            commands::findings_list,
            commands::finding_add_manual,
            commands::findings_list_filtered,
            commands::findings_counts,
            commands::findings_count_by_host,
            commands::finding_set_status,
            commands::finding_set_verification,
            commands::finding_set_tags,
            commands::finding_set_note,
            commands::finding_set_severity,
            commands::finding_delete,
            commands::findings_delete_many,
            commands::scanner_report_write,
            commands::response_open_in_browser,
            commands::shell_open_url,
            commands::history_save_response_body,
            commands::project_open_folder,
            commands::upstream_set,
            commands::settings_get,
            commands::settings_save,
            commands::history_suppress_oos_get,
            commands::history_suppress_oos_set,
            commands::history_columns_get,
            commands::history_columns_set,
            commands::comparer_items_list,
            commands::comparer_items_add,
            commands::comparer_items_remove,
            commands::comparer_items_clear,
            commands::platform_auth_list,
            commands::platform_auth_set,
            commands::extensions_list,
            commands::extensions_set_enabled,
            commands::extensions_catalog_list,
            commands::extensions_install,
            commands::extensions_uninstall,
            commands::logger_recent,
            commands::logger_drain_since,
            commands::logger_clear,
            commands::organizer_add,
            commands::organizer_list,
            commands::organizer_update,
            commands::organizer_move,
            commands::organizer_delete,
            commands::collections_list,
            commands::collection_create,
            commands::collection_rename,
            commands::collection_delete,
            commands::browser_launch,
            commands::bundle_export,
            commands::bundle_import,
            commands::har_import,
            commands::har_export,
            commands::har_export_ids,
            commands::ws_sessions_list,
            commands::ws_session_get,
            commands::ws_messages_list,
            commands::ws_replay,
            commands::ws_intercept_status,
            commands::ws_intercept_set_enabled,
            commands::ws_intercept_pending,
            commands::ws_intercept_release,
            commands::ws_intercept_drop,
            commands::ws_intercept_release_all,
            commands::ws_intercept_drop_all,
            commands::oob_status,
            commands::oob_start,
            commands::oob_stop,
            commands::oob_mint_batch,
            commands::oob_poll_batch,
            commands::oob_interactions_all,
            commands::oob_interactions_clear,
            commands::session_macros_list,
            commands::session_rules_list,
            commands::session_macro_upsert,
            commands::session_macro_delete,
            commands::session_rule_upsert,
            commands::session_rule_delete,
            commands::session_macro_run,
            commands::dashboard_stats,
            commands::live_scan_get,
            commands::live_scan_set,
            commands::history_recording_get,
            commands::history_recording_set,
            commands::tls_passthrough_get,
            commands::tls_passthrough_set,
            commands::bambda_queries_list,
            commands::bambda_queries_save,
            commands::bambda_queries_delete,
            // R930: REST API management
            commands::rest_api_config_get,
            commands::rest_api_config_set,
            commands::rest_api_key_create,
            commands::rest_api_key_list,
            commands::rest_api_key_delete,
            // R961: Bambda library + scan profiles + KB
            commands::bambda_presets_list,
            commands::scan_profiles_list,
            commands::kb_issues_list,
            commands::kb_issue_detail,
        ])
        .run(tauri::generate_context!("tauri.conf.json"))
        .expect("tauri run");
}

/// Resolve the default project directory, create it if missing, and
/// start the proxy on its first configured listener.
fn bootstrap(state: &Arc<AppState>, rt: &tokio::runtime::Handle) {
    let base = match dirs::data_local_dir() {
        Some(p) => p,
        None => {
            warn!("cannot resolve data_local_dir; using current dir");
            std::env::current_dir().unwrap_or_else(|_| ".".into())
        }
    };
    let project_path = base.join("BurpFree").join("default-project");
    info!(path = %project_path.display(), "loading default project");
    let project_handle = match state.load_project(project_path.clone()) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "project load failed; UI will prompt the user");
            return;
        }
    };
    info!("project ready at {}", project_path.display());

    let state_cloned = state.clone();
    rt.spawn(async move {
        if let Err(e) = autostart_proxy(&state_cloned).await {
            warn!(error = %e, "proxy auto-start failed; UI can start it manually");
        }
    });
    // Arm the auto-backup scheduler against the just-loaded
    // project's config. Config changes from the UI call
    // `restart_scheduler` to swap the running task.
    backup::restart_scheduler(state);

    // R935: Start the REST API server if enabled in user config.
    // Config lives at %LocalAppData%/BurpFree/rest_api.json (user-level).
    // Disabled by default (matches Burp's api.enabled=false default).
    {
        let cfg_path = base.join("BurpFree").join("rest_api.json");
        let api_config = if cfg_path.exists() {
            match std::fs::read_to_string(&cfg_path) {
                Ok(data) => serde_json::from_str::<rest_api::RestApiConfig>(&data)
                    .unwrap_or_default(),
                Err(_) => rest_api::RestApiConfig::default(),
            }
        } else {
            rest_api::RestApiConfig::default()
        };
        let mut server = rest_api::RestApiServer::new();
        *server.config.write() = api_config;
        server.start(state.clone());
        // Leak the server handle so it lives for the app lifetime.
        // A proper solution would store it on AppState, but this
        // gets the server running without changing the state struct.
        std::mem::forget(server);
    }

    let _ = project_handle; // keep binding for readability
}

async fn autostart_proxy(state: &Arc<AppState>) -> anyhow::Result<()> {
    use burpfree_proxy::server::{ProxyServer, ServerConfig, TrafficSink};

    let h = state.require()?;
    if h.proxy.read().is_some() {
        return Ok(());
    }
    let config = { h.project.read().config.clone() };

    struct Sink {
        history: burpfree_storage::HistoryStore,
        blobs: std::sync::Arc<burpfree_storage::BlobStore>,
        sitemap: std::sync::Arc<burpfree_engines::sitemap::SiteMap>,
        extensions: burpfree_extensions::ExtensionRegistry,
        /// Current scope â€” read on every record to decide whether the
        /// live passive scan should fire. Shared with the proxy so we
        /// pick up scope edits without a restart.
        scope: std::sync::Arc<parking_lot::RwLock<burpfree_core::scope::Scope>>,
        /// Live-passive-scan flag, flipped by the Tauri commands
        /// `live_scan_set` / `live_scan_get`.
        live_scan: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// R131 pause-history-recording flag. When false, the sink
        /// still runs extensions (so operators can keep seeing
        /// intercept + match-replace mutations in extension logs)
        /// but skips the sitemap observe + history upsert + live-
        /// scan dispatch. Flipped by `history_recording_set`
        /// cmd without a proxy restart.
        history_recording: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// Passive detector ids the operator has turned off. Read on
        /// every live-scan dispatch so a flipped checkbox takes
        /// effect on the next recorded transaction without a restart.
        disabled_detectors: std::sync::Arc<
            parking_lot::RwLock<std::collections::HashSet<String>>,
        >,
        /// Shared project-level cookie jar. Every recorded response
        /// feeds its Set-Cookie headers through so the CookieJar
        /// panel + Repeater's cookie-apply surface see live state.
        cookie_jar: burpfree_engines::session::CookieJar,
    }
    #[async_trait::async_trait]
    impl TrafficSink for Sink {
        async fn record(&self, mut tx: burpfree_core::traffic::Transaction) -> anyhow::Result<()> {
            self.extensions.on_transaction(&tx).await;
            // R131: Pause history recording. When off, bail BEFORE
            // writing to the blob store so a credential endpoint
            // the operator doesn't want persisted leaves zero
            // bytes on disk. Extensions still see the tx above so
            // an extension-based audit log keeps working.
            if !self
                .history_recording
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Ok(());
            }
            let req_blob = self.blobs.put(&tx.request.to_wire_bytes())?;
            let resp_blob = if let Some(r) = &tx.response {
                Some(self.blobs.put(&r.to_wire_bytes())?)
            } else {
                None
            };
            self.sitemap.observe(&tx);
            self.history.upsert_transaction(&tx, &req_blob, resp_blob.as_ref())?;
            // Cookie-jar harvest: scrape every Set-Cookie from the
            // recorded response so the shared jar reflects live
            // target state. observe_response is a no-op when the
            // response has no Set-Cookie headers.
            if let Some(resp) = &tx.response {
                self.cookie_jar.observe_response(&tx.request, resp);
            }
            // Live passive scan: when enabled and the transaction is in
            // scope, run every passive detector against the recorded
            // transaction and upsert the findings. This runs synchronously
            // but the passive scanner is pure CPU over already-decoded
            // bytes so the per-tx cost is small; moving to spawn_blocking
            // would still be sensible if we ever add heavy detectors.
            if self.live_scan.load(std::sync::atomic::Ordering::Relaxed)
                && self.scope.read().is_in_scope(&tx.request)
            {
                // Snapshot the disabled set into a &str HashSet
                // because run_all_filtered takes borrowed strs. The
                // outer RwLock<HashSet<String>> is the durable store
                // (shared with the Tauri cmds); this per-record view
                // is cheap because the set is almost always small.
                let disabled_snapshot = self.disabled_detectors.read().clone();
                let disabled_refs: std::collections::HashSet<&str> =
                    disabled_snapshot.iter().map(|s| s.as_str()).collect();
                for mut f in burpfree_engines::scanner::passive::run_all_filtered(
                    &tx,
                    &[],
                    &disabled_refs,
                ) {
                    f.transaction_id = Some(tx.id);
                    let _ = self.history.insert_finding(&crate::commands::to_stored(&f));
                }
            }
            // mark so we silence a clippy mutable-but-unused warning
            tx.tag("recorded");
            Ok(())
        }
    }

    let (history, blobs) = {
        let p = h.project.read();
        (p.history.clone(), p.blobs.clone())
    };
    let sink: Arc<dyn TrafficSink> = Arc::new(Sink {
        history,
        blobs,
        sitemap: h.sitemap.clone(),
        extensions: h.extensions.clone(),
        scope: h.scope.clone(),
        live_scan: state.live_passive_scan.clone(),
        history_recording: state.history_recording.clone(),
        disabled_detectors: state.disabled_passive_detectors.clone(),
        cookie_jar: h.cookie_jar.clone(),
    });

    let cfg = ServerConfig {
        listeners: config.listen_addrs(),
        ca: h.ca.clone(),
        upstream: h.upstream.clone(),
        scope: h.scope.clone(),
        match_replace: h.match_replace.clone(),
        interceptor: h.interceptor.clone(),
        events: state.events.clone(),
        sink,
        decompression_cap_bytes: config.decompression_cap_mb as usize * 1024 * 1024,
        max_body_bytes: config.max_body_mb as u64 * 1024 * 1024,
        connect_timeout: Duration::from_secs(30),
        record_out_of_scope: state.record_out_of_scope.clone(),
        host_overrides: h.host_overrides.clone(),
        tls_passthrough: state.tls_passthrough.clone(),
        platform_auth: state.platform_auth.clone(),
    };
    let proxy_handle = ProxyServer::start(cfg).await?;
    info!(listeners = ?proxy_handle.listen_addrs, "proxy auto-started");
    *h.proxy.write() = Some(proxy_handle);
    Ok(())
}

// r293 touch // r293b // r294 // r295

// r609c forced relink

// r616c forced relink

// r638c forced relink

// r655c forced relink

// r689c forced relink

// r765d forced relink

// r821c forced relink

// r826c forced relink

// R868: force-relink markers consolidated. Per-round markers from R293 trimmed.

// r880b forced relink

// r889b forced relink

// r890b forced relink

// r891c forced relink

// r891d forced relink

// r891e forced relink

// r892b forced relink





















