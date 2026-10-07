//! Project import / export.
//!
//! A BurpFree *bundle* is a plain zip archive that captures everything
//! needed to re-open a project on a different machine:
//!
//! ```text
//! manifest.json          — schema version + source project name
//! config.json            — proxy, scope, match/replace, upstream
//! history.db             — SQLite index (durable snapshot)
//! blobs/<ab>/<rest>      — content-addressed request/response bodies
//! ca/
//!   ca-cert.pem
//!   ca-key.pem           — optional: carried only when `include_ca`
//!   certs/<host>.pem     — per-host leaf cache
//! extensions/*           — optional: carried when `include_extensions`
//! ```
//!
//! Volatile files are *not* included: SQLite WAL / SHM sidecars, the
//! `log/` directory, and anything matching the exclusion rules below.
//!
//! The private CA key is sensitive — travelling with it means anyone
//! who holds the bundle can forge certificates that TLS-trusting
//! clients of the destination project will believe. The default is to
//! *exclude* the key material; callers who understand the risk can opt
//! in with `BundleOptions::include_ca_key = true`.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Schema version for the manifest. Bump when the layout changes in a
/// way old importers wouldn't understand.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Current manifest format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema: u32,
    pub tool: String,
    pub tool_version: String,
    pub project_name: String,
    pub created_at_ms: u64,
    /// Did the exporter include the private CA key?
    pub includes_ca_key: bool,
    pub includes_extensions: bool,
    /// Entries recorded; purely informational.
    pub entry_count: u32,
}

impl BundleManifest {
    fn new(project_name: &str, opts: &BundleOptions, entry_count: u32) -> Self {
        Self {
            schema: BUNDLE_SCHEMA_VERSION,
            tool: "BurpFree".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            project_name: project_name.into(),
            created_at_ms: now_ms(),
            includes_ca_key: opts.include_ca_key,
            includes_extensions: opts.include_extensions,
            entry_count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BundleOptions {
    /// Compress entries with deflate; otherwise store uncompressed.
    pub compress: bool,
    /// Include the CA private key. **Dangerous** — enables anyone with
    /// the bundle to issue trusted certs for the destination project.
    pub include_ca_key: bool,
    /// Include the extensions/ directory. Default true because
    /// extensions are part of the project's behaviour.
    pub include_extensions: bool,
    /// Include blobs directory. Default true because without blobs the
    /// history.db rows cannot be rebuilt into viewable transactions.
    pub include_blobs: bool,
}

impl Default for BundleOptions {
    fn default() -> Self {
        Self {
            compress: true,
            include_ca_key: false,
            include_extensions: true,
            include_blobs: true,
        }
    }
}

/// What was packed. Returned by `export_project` for the UI/CLI to
/// report back to the user.
#[derive(Debug, Clone, Serialize)]
pub struct BundleSummary {
    pub manifest: BundleManifest,
    pub file_count: u32,
    pub total_bytes: u64,
    pub out_bytes: u64,
    pub out_path: PathBuf,
}

/// Pack `project_root` into `out_path`. The caller is responsible for
/// quiescing any writers (closing the proxy, flushing wal) before
/// invoking — the exporter forces a `wal_checkpoint(TRUNCATE)` on the
/// SQLite db up front but concurrent inserts after that point will not
/// be captured.
pub fn export_project(
    project_root: impl AsRef<Path>,
    out_path: impl AsRef<Path>,
    opts: BundleOptions,
) -> Result<BundleSummary> {
    let project_root = project_root.as_ref();
    let out_path = out_path.as_ref().to_path_buf();
    if !project_root.join("config.json").exists() {
        bail!("not a BurpFree project (no config.json): {}", project_root.display());
    }

    // Best-effort WAL checkpoint so history.db on disk is a complete
    // snapshot. Open briefly, run PRAGMA, drop.
    let db_path = project_root.join("history.db");
    if db_path.exists() {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
        }
    }

    let project_name = read_project_name(project_root).unwrap_or_else(|| "BurpFree project".into());

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let file = File::create(&out_path)
        .with_context(|| format!("create {}", out_path.display()))?;
    let bw = BufWriter::new(file);
    let mut zw = ZipWriter::new(bw);
    let method = if opts.compress { CompressionMethod::Deflated } else { CompressionMethod::Stored };
    let file_opts: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o644);

    let mut file_count: u32 = 0;
    let mut total_bytes: u64 = 0;

    let candidates: Vec<(&str, bool)> = vec![
        ("config.json", true),
        ("history.db", true),
        ("repeater.json", false),
        ("intruder.json", false),
    ];
    for (rel, required) in candidates {
        let src = project_root.join(rel);
        if !src.exists() {
            if required && rel != "history.db" {
                bail!("missing required file: {rel}");
            }
            continue;
        }
        add_file(&mut zw, &src, rel, file_opts, &mut file_count, &mut total_bytes)?;
    }

    if opts.include_blobs {
        add_dir(
            &mut zw,
            &project_root.join("blobs"),
            "blobs",
            &BundleFilters::blobs(),
            file_opts,
            &mut file_count,
            &mut total_bytes,
        )?;
    }

    add_dir(
        &mut zw,
        &project_root.join("ca"),
        "ca",
        &BundleFilters::ca(opts.include_ca_key),
        file_opts,
        &mut file_count,
        &mut total_bytes,
    )?;

    if opts.include_extensions {
        add_dir(
            &mut zw,
            &project_root.join("extensions"),
            "extensions",
            &BundleFilters::extensions(),
            file_opts,
            &mut file_count,
            &mut total_bytes,
        )?;
    }

    let manifest = BundleManifest::new(&project_name, &opts, file_count);
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    zw.start_file("manifest.json", file_opts)?;
    zw.write_all(&manifest_json)?;
    file_count += 1;
    total_bytes += manifest_json.len() as u64;

    let mut bw = zw.finish()?;
    bw.flush().ok();
    let out_bytes = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);

    Ok(BundleSummary {
        manifest,
        file_count,
        total_bytes,
        out_bytes,
        out_path,
    })
}

/// Unpack `bundle_path` into `dest_root`. `dest_root` must either not
/// exist or be empty.
///
/// Zip-slip protection: entry names containing `..`, absolute paths,
/// or path components matching Windows drive letters are rejected.
pub fn import_project(
    bundle_path: impl AsRef<Path>,
    dest_root: impl AsRef<Path>,
) -> Result<BundleManifest> {
    let bundle_path = bundle_path.as_ref();
    let dest_root = dest_root.as_ref().to_path_buf();
    if dest_root.exists() {
        let has = dest_root.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false);
        if has {
            bail!("destination {} is not empty", dest_root.display());
        }
    }
    std::fs::create_dir_all(&dest_root)
        .with_context(|| format!("mkdir {}", dest_root.display()))?;

    let file = File::open(bundle_path)
        .with_context(|| format!("open {}", bundle_path.display()))?;
    let br = BufReader::new(file);
    let mut archive = ZipArchive::new(br)?;

    // Pass 1: read manifest, if present. Non-fatal if absent; we still
    // import but return a synthetic manifest. This keeps `.burpfree`
    // files produced by third-party tooling importable.
    let mut manifest: Option<BundleManifest> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.name() == "manifest.json" {
            let mut buf = String::new();
            entry.read_to_string(&mut buf)?;
            manifest = serde_json::from_str(&buf).ok();
            break;
        }
    }

    // Pass 2: extract everything safely.
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if name.is_empty() || name.ends_with('/') {
            // Directory entries will be created by their files.
            continue;
        }
        let safe_rel = sanitise_zip_name(&name)
            .ok_or_else(|| anyhow!("rejected unsafe path in bundle: {name}"))?;
        let out = dest_root.join(&safe_rel);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let mut sink = File::create(&out)
            .with_context(|| format!("create {}", out.display()))?;
        std::io::copy(&mut entry, &mut sink)
            .with_context(|| format!("extract {} -> {}", name, out.display()))?;
    }

    // Sanity check: must at least have config.json.
    if !dest_root.join("config.json").exists() {
        bail!("bundle did not contain config.json");
    }

    // Ensure the subdirs the project expects always exist.
    for sub in ["ca", "blobs", "log", "extensions"] {
        std::fs::create_dir_all(dest_root.join(sub)).ok();
    }

    Ok(manifest.unwrap_or_else(|| BundleManifest {
        schema: 0,
        tool: "unknown".into(),
        tool_version: String::new(),
        project_name: "Imported project".into(),
        created_at_ms: 0,
        includes_ca_key: dest_root.join("ca/ca-key.pem").exists(),
        includes_extensions: dest_root.join("extensions").exists(),
        entry_count: 0,
    }))
}

// --- helpers -----------------------------------------------------------

fn read_project_name(root: &Path) -> Option<String> {
    let data = std::fs::read_to_string(root.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

struct BundleFilters {
    exclude_suffixes: &'static [&'static str],
    exclude_names: Vec<String>,
}

impl BundleFilters {
    fn blobs() -> Self {
        Self { exclude_suffixes: &[], exclude_names: vec![] }
    }
    fn ca(include_key: bool) -> Self {
        let mut n: Vec<String> = Vec::new();
        if !include_key {
            n.push("ca-key.pem".into());
        }
        Self { exclude_suffixes: &[], exclude_names: n }
    }
    fn extensions() -> Self {
        Self {
            exclude_suffixes: &[".log"],
            exclude_names: vec![],
        }
    }
    fn allow(&self, rel: &str) -> bool {
        for s in self.exclude_suffixes {
            if rel.ends_with(s) {
                return false;
            }
        }
        let last = rel.rsplit('/').next().unwrap_or(rel);
        for n in &self.exclude_names {
            if last == n {
                return false;
            }
        }
        true
    }
}

fn add_file<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    src: &Path,
    rel: &str,
    opts: SimpleFileOptions,
    file_count: &mut u32,
    total_bytes: &mut u64,
) -> Result<()> {
    let data = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
    zw.start_file(rel, opts)?;
    zw.write_all(&data)?;
    *file_count += 1;
    *total_bytes += data.len() as u64;
    Ok(())
}

fn add_dir<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    dir: &Path,
    rel_root: &str,
    filters: &BundleFilters,
    opts: SimpleFileOptions,
    file_count: &mut u32,
    total_bytes: &mut u64,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(dir)
            .map_err(|_| anyhow!("strip prefix"))?
            .to_string_lossy()
            .replace('\\', "/");
        let full_rel = if rel_root.is_empty() { rel.clone() } else { format!("{rel_root}/{rel}") };
        if !filters.allow(&full_rel) {
            continue;
        }
        add_file(zw, entry.path(), &full_rel, opts, file_count, total_bytes)?;
    }
    Ok(())
}

/// Reject zip entries that would escape the destination directory.
fn sanitise_zip_name(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    // Normalise separators.
    let norm = name.replace('\\', "/");
    // Reject absolute paths and Windows drive specs.
    if norm.starts_with('/') {
        return None;
    }
    if norm.len() >= 2 && norm.as_bytes()[1] == b':' {
        return None;
    }
    let mut out = PathBuf::new();
    for seg in norm.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_fake_project(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        for sub in ["ca", "blobs/ab", "log", "extensions"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(root.join("config.json"), r#"{"name":"demo"}"#).unwrap();
        std::fs::write(root.join("history.db"), b"SQLite format 3\0...").unwrap();
        std::fs::write(root.join("ca/ca-cert.pem"), b"-----BEGIN CERT-----\n").unwrap();
        std::fs::write(root.join("ca/ca-key.pem"), b"-----BEGIN KEY-----\n").unwrap();
        std::fs::write(root.join("blobs/ab/cafe"), b"body-bytes").unwrap();
        std::fs::write(root.join("extensions/strip-powered-by.json"), b"{}").unwrap();
        std::fs::write(root.join("log/burpfree.log"), b"ignored").unwrap();
        std::fs::write(root.join("history.db-wal"), b"ignored-wal").unwrap();
    }

    #[test]
    fn roundtrip_excludes_ca_key_by_default() {
        let td = tempdir().unwrap();
        let src = td.path().join("src");
        let out = td.path().join("bundle.burpfree");
        let dst = td.path().join("dst");
        make_fake_project(&src);
        let summary = export_project(&src, &out, BundleOptions::default()).unwrap();
        assert!(summary.file_count >= 5);
        assert!(!summary.manifest.includes_ca_key);

        let manifest = import_project(&out, &dst).unwrap();
        assert_eq!(manifest.project_name, "demo");
        assert!(dst.join("config.json").exists());
        assert!(dst.join("history.db").exists());
        assert!(dst.join("ca/ca-cert.pem").exists());
        assert!(!dst.join("ca/ca-key.pem").exists(), "ca key must be excluded by default");
        assert!(dst.join("blobs/ab/cafe").exists());
        assert!(dst.join("extensions/strip-powered-by.json").exists());
    }

    #[test]
    fn can_opt_in_ca_key() {
        let td = tempdir().unwrap();
        let src = td.path().join("src");
        let out = td.path().join("bundle.burpfree");
        let dst = td.path().join("dst");
        make_fake_project(&src);
        let opts = BundleOptions { include_ca_key: true, ..Default::default() };
        let _ = export_project(&src, &out, opts).unwrap();
        import_project(&out, &dst).unwrap();
        assert!(dst.join("ca/ca-key.pem").exists());
    }

    #[test]
    fn volatile_files_are_skipped() {
        let td = tempdir().unwrap();
        let src = td.path().join("src");
        let out = td.path().join("bundle.burpfree");
        let dst = td.path().join("dst");
        make_fake_project(&src);
        let _ = export_project(&src, &out, BundleOptions::default()).unwrap();
        import_project(&out, &dst).unwrap();
        assert!(!dst.join("history.db-wal").exists(), "wal must not leak");
        assert!(!dst.join("log/burpfree.log").exists(), "log/ must not leak");
    }

    #[test]
    fn rejects_zip_slip() {
        assert!(sanitise_zip_name("../etc/passwd").is_none());
        assert!(sanitise_zip_name("/etc/passwd").is_none());
        assert!(sanitise_zip_name("C:/windows").is_none());
        assert!(sanitise_zip_name("blobs/../../x").is_none());
        assert_eq!(sanitise_zip_name("blobs/ab/cafe").unwrap(), PathBuf::from("blobs/ab/cafe"));
    }

    #[test]
    fn refuses_non_empty_destination() {
        let td = tempdir().unwrap();
        let src = td.path().join("src");
        let out = td.path().join("bundle.burpfree");
        let dst = td.path().join("dst");
        make_fake_project(&src);
        export_project(&src, &out, BundleOptions::default()).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("existing"), b"x").unwrap();
        let err = import_project(&out, &dst).unwrap_err();
        assert!(err.to_string().contains("not empty"));
    }
}
