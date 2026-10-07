//! Content-addressed blob store.
//!
//! Each blob is written to `root/<first-2-hex>/<rest-hex>` where the
//! hex is the BLAKE3 digest of the content. Writes are atomic: content
//! is written to a `.tmp` file first and renamed. Reads return the
//! bytes; small helpers return hex-encoded hashes.
//!
//! The blob store deduplicates: writing the same bytes twice produces
//! a single file. This makes identical response bodies across many
//! requests cheap.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use burpfree_core::ids::ContentRef;
use parking_lot::Mutex;

#[derive(Debug)]
pub struct BlobStore {
    root: PathBuf,
    stats: Mutex<Stats>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub writes: u64,
    pub dedup_hits: u64,
    pub bytes_written: u64,
}

impl BlobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("mkdir blobs root {}", root.display()))?;
        Ok(Self {
            root,
            stats: Mutex::new(Stats::default()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write bytes if not already present. Returns the `ContentRef`.
    pub fn put(&self, data: &[u8]) -> Result<ContentRef> {
        let r = ContentRef::from_bytes(data);
        let (dir, file) = r.path_parts();
        let sub = self.root.join(dir);
        let path = sub.join(file);
        if path.exists() {
            self.stats.lock().dedup_hits += 1;
            return Ok(r);
        }
        std::fs::create_dir_all(&sub).with_context(|| format!("mkdir {}", sub.display()))?;
        let tmp = sub.join(format!("{file}.tmp"));
        std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
        let mut s = self.stats.lock();
        s.writes += 1;
        s.bytes_written += data.len() as u64;
        Ok(r)
    }

    /// Fetch bytes by content-ref. Returns `None` if the blob is missing.
    pub fn get(&self, r: &ContentRef) -> Result<Option<Vec<u8>>> {
        let (dir, file) = r.path_parts();
        let path = self.root.join(dir).join(file);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(Some(data))
    }

    /// Fetch bytes by the raw sha string (no need to know the length).
    pub fn get_by_sha(&self, sha: &str) -> Result<Option<Vec<u8>>> {
        if sha.len() < 2 {
            return Ok(None);
        }
        let (dir, file) = sha.split_at(2);
        let path = self.root.join(dir).join(file);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(Some(data))
    }

    /// Return the path to a blob (useful for streaming responses in HTTP).
    pub fn path(&self, r: &ContentRef) -> PathBuf {
        let (dir, file) = r.path_parts();
        self.root.join(dir).join(file)
    }

    pub fn exists(&self, r: &ContentRef) -> bool {
        self.path(r).exists()
    }

    pub fn stats(&self) -> Stats {
        *self.stats.lock()
    }

    /// Delete a blob. Used by project maintenance.
    pub fn remove(&self, r: &ContentRef) -> Result<()> {
        let p = self.path(r);
        if p.exists() {
            std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn put_and_get_roundtrips() {
        let dir = tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let r = store.put(b"hello world").unwrap();
        let got = store.get(&r).unwrap().unwrap();
        assert_eq!(got, b"hello world");
    }

    #[test]
    fn dedup_counts_hits() {
        let dir = tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        store.put(b"same").unwrap();
        store.put(b"same").unwrap();
        store.put(b"same").unwrap();
        let s = store.stats();
        assert_eq!(s.writes, 1);
        assert_eq!(s.dedup_hits, 2);
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        let fake = ContentRef::from_bytes(b"never-written-anywhere-xyz");
        assert!(store.get(&fake).unwrap().is_none());
    }
}


/// Milliseconds since the Unix epoch. Exposed as a small helper so other
/// modules in this crate can produce `updated_at_ms` values without
/// depending on `std::time::SystemTime` directly.
pub fn now_ms_hint() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
