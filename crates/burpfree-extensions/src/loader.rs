//! Extension loader.
//!
//! The MVP loader is deliberately simple: it walks each configured
//! extension directory and registers the built-in reference extensions
//! (`strip-powered-by`, `host-tagger`, `header-injector`) plus any
//! extensions a project opts into by name in `extensions.json`.
//!
//! Full dynamic loading (WASM via `wasmtime`, or `libloading` for
//! native crates) is on the roadmap and will live in this module.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    Extension, ExtensionRegistry, HostTagger, RequestIdStamper, ResponseHeaderInjector,
    SecretsLeakDetector, StripPoweredBy,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionsConfig {
    /// Names of built-in reference extensions to load.
    #[serde(default)]
    pub builtins: Vec<String>,
}

impl ExtensionsConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data).unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, data)?;
        Ok(())
    }
}

/// Returns a registry populated with the built-ins the project opted
/// into. If no `extensions.json` exists we register every built-in.
pub fn load_builtins(project_root: &Path) -> Result<ExtensionRegistry> {
    let registry = ExtensionRegistry::new();
    let cfg_path = project_root.join("extensions.json");
    let cfg = ExtensionsConfig::load(&cfg_path)?;

    let catalog: Vec<(&str, Arc<dyn Extension>)> = vec![
        ("strip-powered-by", Arc::new(StripPoweredBy)),
        ("host-tagger", Arc::new(HostTagger)),
        ("secrets-leak-detector", Arc::new(SecretsLeakDetector)),
        ("request-id-stamper", Arc::new(RequestIdStamper)),
        ("response-header-injector", Arc::new(ResponseHeaderInjector)),
    ];

    let wanted: Vec<String> = if cfg.builtins.is_empty() {
        catalog.iter().map(|(n, _)| (*n).to_string()).collect()
    } else {
        cfg.builtins.clone()
    };

    let project_name = project_root
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("project")
        .to_string();

    for (name, ext) in catalog {
        if wanted.iter().any(|n| n == name) {
            registry.register(ext, &project_name)?;
        }
    }
    Ok(registry)
}

/// Install a built-in catalog extension into an existing project.
/// Persists the opt-in into `extensions.json` so the extension reloads
/// on the next project open, and immediately registers it in the live
/// registry so the running session picks it up without a restart.
///
/// Returns `true` if the extension is now installed; `false` if the
/// name is unknown or the entry is preview-only.
pub fn install_builtin(
    registry: &ExtensionRegistry,
    project_root: &Path,
    name: &str,
) -> Result<bool> {
    let Some(ext) = crate::instantiate_builtin(name) else {
        return Ok(false);
    };
    let project_name = project_root
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("project")
        .to_string();

    // Live register.
    registry.register(ext, &project_name)?;

    // Persist opt-in.
    let cfg_path = project_root.join("extensions.json");
    let mut cfg = ExtensionsConfig::load(&cfg_path)?;
    if cfg.builtins.is_empty() {
        // Carry forward every currently-loaded extension so a selective
        // install doesn't accidentally disable the ones that were
        // implicitly on.
        cfg.builtins = registry.list().into_iter().map(|m| m.name).collect();
    } else if !cfg.builtins.iter().any(|n| n == name) {
        cfg.builtins.push(name.into());
    }
    cfg.save(&cfg_path)?;
    Ok(true)
}

/// Remove a built-in catalog extension from the project. Updates the
/// live registry and persists the change to `extensions.json`.
pub fn uninstall_builtin(
    registry: &ExtensionRegistry,
    project_root: &Path,
    name: &str,
) -> Result<bool> {
    let removed_live = registry.remove(name);
    let cfg_path = project_root.join("extensions.json");
    let mut cfg = ExtensionsConfig::load(&cfg_path)?;
    if cfg.builtins.is_empty() {
        // Mirror current (post-remove) registry contents so the next
        // open doesn't resurrect the extension via implicit defaults.
        cfg.builtins = registry.list().into_iter().map(|m| m.name).collect();
    } else {
        cfg.builtins.retain(|n| n != name);
    }
    cfg.save(&cfg_path)?;
    Ok(removed_live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn loads_defaults_when_no_config() {
        let td = tempdir().unwrap();
        let reg = load_builtins(td.path()).unwrap();
        let names: Vec<_> = reg.list().into_iter().map(|m| m.name).collect();
        assert!(names.iter().any(|n| n == "strip-powered-by"));
        assert!(names.iter().any(|n| n == "host-tagger"));
    }

    #[test]
    fn respects_config_opt_in() {
        let td = tempdir().unwrap();
        let cfg = ExtensionsConfig {
            builtins: vec!["strip-powered-by".into()],
        };
        cfg.save(&td.path().join("extensions.json")).unwrap();
        let reg = load_builtins(td.path()).unwrap();
        let names: Vec<_> = reg.list().into_iter().map(|m| m.name).collect();
        assert_eq!(names, vec!["strip-powered-by"]);
    }

    #[test]
    fn install_and_uninstall_round_trip() {
        let td = tempdir().unwrap();
        // Start with only strip-powered-by installed.
        let cfg = ExtensionsConfig {
            builtins: vec!["strip-powered-by".into()],
        };
        cfg.save(&td.path().join("extensions.json")).unwrap();
        let reg = load_builtins(td.path()).unwrap();

        // Install request-id-stamper via the catalog helper.
        let installed = install_builtin(&reg, td.path(), "request-id-stamper").unwrap();
        assert!(installed, "install_builtin should succeed for a real catalog entry");
        let names: Vec<_> = reg.list().into_iter().map(|m| m.name).collect();
        assert!(names.iter().any(|n| n == "strip-powered-by"));
        assert!(names.iter().any(|n| n == "request-id-stamper"));

        // The config file should mention both now.
        let saved = ExtensionsConfig::load(&td.path().join("extensions.json")).unwrap();
        assert!(saved.builtins.iter().any(|n| n == "strip-powered-by"));
        assert!(saved.builtins.iter().any(|n| n == "request-id-stamper"));

        // Uninstall request-id-stamper.
        let removed = uninstall_builtin(&reg, td.path(), "request-id-stamper").unwrap();
        assert!(removed);
        let names: Vec<_> = reg.list().into_iter().map(|m| m.name).collect();
        assert!(!names.iter().any(|n| n == "request-id-stamper"));
        let saved = ExtensionsConfig::load(&td.path().join("extensions.json")).unwrap();
        assert!(!saved.builtins.iter().any(|n| n == "request-id-stamper"));
    }

    #[test]
    fn install_unknown_name_returns_false() {
        let td = tempdir().unwrap();
        let reg = ExtensionRegistry::new();
        let installed = install_builtin(&reg, td.path(), "does-not-exist").unwrap();
        assert!(!installed);
    }

    #[test]
    fn install_preview_entry_returns_false() {
        let td = tempdir().unwrap();
        let reg = ExtensionRegistry::new();
        let installed = install_builtin(&reg, td.path(), "csrf-token-rotator").unwrap();
        assert!(!installed, "preview-only catalog entries must not install");
    }

    #[test]
    fn catalog_lists_all_available_builtins() {
        let names: Vec<_> = crate::catalog().into_iter().map(|c| c.name).collect();
        for required in [
            "strip-powered-by",
            "host-tagger",
            "secrets-leak-detector",
            "request-id-stamper",
            "response-header-injector",
        ] {
            assert!(names.iter().any(|n| n == required), "missing: {required}");
        }
        // At least one preview entry present so the UI exercises the badge.
        assert!(crate::catalog().iter().any(|c| !c.available));
    }
}


// ---------------------------------------------------------------------------
// WASM extension loader skeleton (R930 task #7)
// ---------------------------------------------------------------------------
//
// Future: dynamic extension loading via WebAssembly (wasmtime).
// Extensions compiled to WASM can be loaded at runtime without
// recompiling BurpFree. The WASM sandbox provides:
//
//   - Memory isolation (extensions can't corrupt host state)
//   - Permission-gated host functions (extensions call into
//     BurpFree via an imported API surface, not raw FFI)
//   - Cross-platform portability (same .wasm runs everywhere)
//
// The loader will:
//   1. Read `.wasm` files from `<project>/extensions/wasm/`
//   2. Instantiate each module with a host-function API matching
//      the Extension trait methods
//   3. Register the WASM instance as a `dyn Extension` in the
//      ExtensionRegistry
//
// Host functions exposed to WASM extensions (planned):
//
//   bf_log(ptr, len)              → log to extension output
//   bf_get_request(ptr, len)      → read the current request
//   bf_set_request(ptr, len)      → modify the current request
//   bf_get_response(ptr, len)     → read the current response
//   bf_set_response(ptr, len)     → modify the current response
//   bf_make_http_request(ptr,len) → send an HTTP request
//   bf_add_finding(ptr, len)      → report a scanner finding
//   bf_get_scope_rules(ptr, len)  → read scope rules
//   bf_add_context_menu(ptr, len) → register a context menu item
//
// WASM ABI: extensions export `bf_init()`, `bf_on_request()`,
// `bf_on_response()`, `bf_on_transaction()`. The host calls these
// at the appropriate pipeline stages.
//
// Dependencies needed (add when implementing):
//   wasmtime = { version = "26", features = ["async"] }
//

/// Placeholder: scan a directory for `.wasm` extension modules.
/// Returns the count of discovered modules (0 until wasmtime is wired).
pub fn scan_wasm_extensions(extensions_dir: &std::path::Path) -> usize {
    if !extensions_dir.exists() {
        return 0;
    }
    let wasm_dir = extensions_dir.join("wasm");
    if !wasm_dir.exists() {
        return 0;
    }
    std::fs::read_dir(&wasm_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "wasm")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}
