//! Persistence layer: project directory, SQLite history index, and
//! content-addressed blob store for request/response bodies.
//!
//! The design keeps large bodies **out of SQLite rows**: each body is
//! hashed and written once under `project/blobs/<ab>/<rest>`; the
//! SQLite index stores only the hash and size. This lets the UI stream
//! bodies on demand and lets duplicate traffic (identical bodies)
//! deduplicate for free.

pub mod blobs;
pub mod bundle;
pub mod har;
pub mod history;
pub mod project;

pub use blobs::BlobStore;
pub use bundle::{
    export_project, import_project, BundleManifest, BundleOptions, BundleSummary,
    BUNDLE_SCHEMA_VERSION,
};
pub use har::{export_har, export_har_by_ids, import_har, import_har_bytes, HarExportSummary, HarImportSummary};
pub use history::{
    compute_fingerprint, FindingFilter, HistoryFilter, HistoryStore, OrganizerCollection,
    OrganizerItem, StoredFinding, StoredSummary, StoredWsMessage, StoredWsSession,
};
pub use project::{AutoBackupConfig, Project, ProjectConfig};
