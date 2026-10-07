//! Periodic project-bundle snapshots.
//!
//! Mirrors Burp's "Automatic project backup" feature: a Tokio task
//! fires `export_project` into `<project>/backups/<ISO>.zip` on the
//! configured interval, then prunes anything older than
//! `keep_count` entries. Operators can also trigger a one-shot via
//! `backup_now`, delete individual snapshots from the UI, or wipe
//! everything by flipping `delete_on_shutdown`.
//!
//! The scheduler lives on `AppState::backup_task` as an abortable
//! `JoinHandle`; config changes (`backup_config_set`) call
//! `restart_scheduler` which aborts the old loop and spawns a new
//! one so a shorter interval takes effect immediately instead of
//! waiting out the old sleep.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;
use burpfree_storage::bundle::{export_project, BundleOptions};
use burpfree_storage::AutoBackupConfig;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::state::AppState;

/// Metadata about a single `<project>/backups/*.zip` entry — the
/// shape returned by `backup_list` + `backup_now` to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    /// Just the file name — the UI uses this as a stable id for
    /// delete without needing the full path. Validated against
    /// path-traversal in `delete_backup`.
    pub filename: String,
    pub size_bytes: u64,
    /// Unix millis — easier for the UI's `new Date(ms)` than ISO.
    pub created_at_ms: i64,
}

/// Enumerate every `<project>/backups/*.zip` on disk. Returns an
/// empty Vec (not an error) when the backups directory doesn't
/// exist yet; a fresh project simply hasn't produced a snapshot.
/// Entries are sorted newest-first so the UI table reads top-down.
pub fn list_backups(project_root: &Path) -> Result<Vec<BackupInfo>> {
    let dir = backups_dir(project_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("zip") {
            continue;
        }
        let metadata = entry.metadata()?;
        let created_at_ms = metadata
            .created()
            .or_else(|_| metadata.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        out.push(BackupInfo {
            filename: entry.file_name().to_string_lossy().into_owned(),
            size_bytes: metadata.len(),
            created_at_ms,
        });
    }
    // Sort by filename DESC so the newest-first order is purely
    // derived from the ISO timestamp in the filename — no reliance
    // on filesystem `created_at` which doesn't exist on every FS
    // we care about (ext4 pre-crtime, some tmpfs variants).
    out.sort_by(|a, b| b.filename.cmp(&a.filename));
    Ok(out)
}

/// Fire a single bundle export into `<project>/backups/<ISO>.zip`,
/// then prune to `keep_count`. Returns the metadata of the newly
/// created file so the UI can slot it into the list without a
/// second round-trip. `include_ca_key` is intentionally false
/// because an auto-backup can land on removable media / cloud sync
/// — leaking the project's MITM CA private key by default would be
/// a footgun. Operators who want it can still invoke the CLI
/// export directly.
pub fn write_snapshot(project_root: &Path, keep_count: u32) -> Result<BackupInfo> {
    let dir = backups_dir(project_root);
    std::fs::create_dir_all(&dir)?;
    let now = Utc::now();
    let filename = backup_filename(now);
    let out_path = dir.join(&filename);
    let opts = BundleOptions {
        compress: true,
        // CA private key stays out of auto-backups. See doc comment
        // on write_snapshot for the rationale.
        include_ca_key: false,
        // Extensions can be bulky and are usually fine to lose on
        // restore (operators can `extensions_reload`). Skipping
        // them keeps backup zips lean enough to actually keep 20
        // copies without blowing the quota.
        include_extensions: false,
        // Blobs ARE required — without them the history.db rows
        // can't be rebuilt into viewable transactions, which
        // defeats the whole point of a backup.
        include_blobs: true,
    };
    let _summary = export_project(project_root, &out_path, opts)?;
    let metadata = std::fs::metadata(&out_path)?;
    let info = BackupInfo {
        filename,
        size_bytes: metadata.len(),
        created_at_ms: now.timestamp_millis(),
    };
    // Prune after the write so a scheduler tick that fails doesn't
    // delete the previous good snapshot.
    if let Err(e) = prune_old(project_root, keep_count) {
        warn!(err = ?e, "backup prune failed");
    }
    debug!(filename = info.filename.as_str(), size = info.size_bytes, "wrote backup snapshot");
    Ok(info)
}

/// Enforce the `keep_count` cap: `fs::remove_file` every snapshot
/// older than the N newest. Returns the number of entries removed
/// so the Tauri cmd can surface it in the response (even though we
/// don't currently expose that — the pruner's return value is
/// also used by the unit test to assert the policy without
/// mocking the filesystem). A `keep_count` of 0 keeps nothing;
/// `u32::MAX` effectively disables pruning.
pub fn prune_old(project_root: &Path, keep_count: u32) -> Result<usize> {
    let all = list_backups(project_root)?;
    let keep = keep_count as usize;
    if all.len() <= keep {
        return Ok(0);
    }
    let dir = backups_dir(project_root);
    let mut removed = 0usize;
    // `list_backups` returns newest-first, so entries past index
    // `keep` are the ones to drop.
    for stale in all.iter().skip(keep) {
        let path = dir.join(&stale.filename);
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Validate `filename` against path traversal (no `..`, no path
/// separators, must end in `.zip`) then `fs::remove_file` it.
/// Returns `true` iff a file was actually present. Backs the UI's
/// per-row delete button.
pub fn delete_backup(project_root: &Path, filename: &str) -> Result<bool> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        anyhow::bail!("invalid filename: {filename}");
    }
    if !filename.ends_with(".zip") {
        anyhow::bail!("not a backup file: {filename}");
    }
    let path = backups_dir(project_root).join(filename);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path)?;
    Ok(true)
}

/// Wipe every backup zip. Called when the operator sets
/// `delete_on_shutdown=true` and the project is closing. Doesn't
/// touch the directory itself; a fresh snapshot will land there
/// cleanly next time. Currently reachable only from the test
/// suite; the shutdown hook that drives it in production is
/// scheduled for a near-future round.
#[allow(dead_code)]
pub fn wipe_all(project_root: &Path) -> Result<usize> {
    let dir = backups_dir(project_root);
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("zip") {
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Abort the running scheduler (if any) and spawn a fresh one
/// against the latest config. Called from both `AppState::load_project`
/// (after the project opens) and `backup_config_set` (after the
/// operator saves new settings) so a shorter interval kicks in
/// without waiting out the previous sleep.
pub fn restart_scheduler(state: &Arc<AppState>) {
    let project_root = {
        let project = state.project.read();
        match project.as_ref() {
            Some(h) => h.project.read().root.clone(),
            None => return,
        }
    };
    let cfg = {
        let project = state.project.read();
        match project.as_ref() {
            Some(h) => h.project.read().config.auto_backup.clone(),
            None => return,
        }
    };
    let state_cloned = state.clone();
    // Spawn via the AppState's stored runtime handle so this works
    // from both async Tauri command contexts (where tokio::spawn()
    // would be fine) and the sync bootstrap thread (where it would
    // panic because there's no ambient runtime).
    let new_task: JoinHandle<()> = state.rt.spawn(async move {
        run_scheduler_loop(state_cloned, project_root, cfg).await;
    });
    let mut guard = state.backup_task.lock();
    if let Some(old) = guard.take() {
        old.abort();
    }
    *guard = Some(new_task);
}

async fn run_scheduler_loop(
    state: Arc<AppState>,
    project_root: PathBuf,
    cfg: AutoBackupConfig,
) {
    // Clamp the interval so a stray 0 can't hot-spin and a huge
    // value doesn't silently stall the backup for days (operators
    // can still bypass this via `backup_now`).
    let interval_min = cfg.interval_min.clamp(1, 1440);
    let interval = Duration::from_secs(interval_min as u64 * 60);
    info!(
        enabled = cfg.enabled,
        interval_min,
        keep_count = cfg.keep_count,
        "backup scheduler armed"
    );
    loop {
        tokio::time::sleep(interval).await;
        // Re-read `enabled` on every tick so a mid-flight disable
        // takes effect without needing another restart cycle.
        let enabled = state
            .project
            .read()
            .as_ref()
            .map(|h| h.project.read().config.auto_backup.enabled)
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        let keep = state
            .project
            .read()
            .as_ref()
            .map(|h| h.project.read().config.auto_backup.keep_count)
            .unwrap_or(cfg.keep_count);
        match tokio::task::spawn_blocking({
            let root = project_root.clone();
            move || write_snapshot(&root, keep)
        })
        .await
        {
            Ok(Ok(info)) => {
                debug!(filename = info.filename.as_str(), "scheduled backup written");
            }
            Ok(Err(e)) => {
                warn!(err = ?e, "scheduled backup failed");
            }
            Err(e) => {
                warn!(err = ?e, "backup task join failed");
            }
        }
    }
}

fn backups_dir(project_root: &Path) -> PathBuf {
    project_root.join("backups")
}

fn backup_filename(ts: DateTime<Utc>) -> String {
    // Compact ISO form — Windows-safe (no `:`), lexicographically
    // sorts newest-last so a plain filesystem `read_dir` → sort →
    // reverse is enough to show newest-first without parsing dates.
    format!("backup-{}.zip", ts.format("%Y%m%dT%H%M%SZ"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    /// Seed `<dir>/backups/` with N dummy zip files whose names
    /// place them in a known temporal order (oldest → newest).
    /// Returns the filenames in that order so the test can
    /// assert which ones survived the prune. No mtime stamping
    /// needed — `list_backups` sorts by filename, and the ISO
    /// portion of the names below sorts lexicographically.
    fn seed_backups(root: &Path, count: usize) -> Vec<String> {
        let dir = backups_dir(root);
        std::fs::create_dir_all(&dir).unwrap();
        let mut names = Vec::new();
        for i in 0..count {
            // Pad to 2 digits so i=10 sorts after i=9 at the day
            // position, not between i=1 and i=2.
            let name = format!("backup-202601{:02}T000000Z.zip", i + 1);
            let path = dir.join(&name);
            let mut f = File::create(&path).unwrap();
            // Non-empty so `metadata().len()` reports a real size.
            writeln!(f, "backup #{i}").unwrap();
            names.push(name);
        }
        names
    }

    #[test]
    fn prune_old_keeps_newest_n_and_drops_the_rest() {
        let td = tempdir().unwrap();
        let names = seed_backups(td.path(), 7);
        assert_eq!(list_backups(td.path()).unwrap().len(), 7);
        // Keep 3: expect 4 removed, 3 survivors.
        let removed = prune_old(td.path(), 3).unwrap();
        assert_eq!(removed, 4);
        let left = list_backups(td.path()).unwrap();
        assert_eq!(left.len(), 3);
        // Survivors are the lexicographically-last 3 — i.e. the
        // newest 3 given our naming scheme.
        let kept: Vec<String> = left.into_iter().map(|b| b.filename).collect();
        for stale in &names[..4] {
            assert!(!kept.contains(stale), "{stale} should have been pruned");
        }
        for fresh in &names[4..] {
            assert!(kept.contains(fresh), "{fresh} should have survived");
        }
        // Second prune at the same keep_count is a no-op.
        assert_eq!(prune_old(td.path(), 3).unwrap(), 0);
        // keep_count larger than the surviving set is also a no-op.
        assert_eq!(prune_old(td.path(), 10).unwrap(), 0);
    }

    #[test]
    fn list_backups_returns_empty_on_fresh_project() {
        let td = tempdir().unwrap();
        // No `backups/` dir yet — not an error, just empty.
        assert_eq!(list_backups(td.path()).unwrap().len(), 0);
    }

    #[test]
    fn delete_backup_rejects_path_traversal() {
        let td = tempdir().unwrap();
        seed_backups(td.path(), 2);
        // Legit delete.
        let names = list_backups(td.path()).unwrap();
        assert!(delete_backup(td.path(), &names[0].filename).unwrap());
        // Stale filename → false, not an error.
        assert!(!delete_backup(td.path(), &names[0].filename).unwrap());
        // Path-traversal attempts → error.
        assert!(delete_backup(td.path(), "../etc/passwd").is_err());
        assert!(delete_backup(td.path(), "sub/dir/x.zip").is_err());
        assert!(delete_backup(td.path(), "x.txt").is_err()); // not a .zip
    }

    #[test]
    fn wipe_all_removes_every_zip() {
        let td = tempdir().unwrap();
        seed_backups(td.path(), 5);
        assert_eq!(list_backups(td.path()).unwrap().len(), 5);
        assert_eq!(wipe_all(td.path()).unwrap(), 5);
        assert_eq!(list_backups(td.path()).unwrap().len(), 0);
        // Re-run against an already-empty dir is a no-op.
        assert_eq!(wipe_all(td.path()).unwrap(), 0);
    }
}
