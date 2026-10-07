//! SQLite-backed HTTP history index.
//!
//! Each row references body blobs by their content-ref so the index
//! stays small (~1 KiB/row even for very large bodies). Filters,
//! search, and pagination are all SQL queries over indexed columns.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use burpfree_core::ids::{ContentRef, TrafficId};
use burpfree_core::traffic::{Transaction, WebSocketMessage, WebSocketSession};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Lightweight row for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSummary {
    pub id: TrafficId,
    pub ts_ms: i64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub elapsed_ms: Option<u64>,
    pub tags: Vec<String>,
    pub in_scope: bool,
    pub source: String,
    pub tls_summary: Option<String>,
    pub comment: String,
    pub error: Option<String>,
    /// Count of query + body parameters observed on this request.
    /// Site map renders a `✓` icon when this is non-zero.
    #[serde(default)]
    pub param_count: u16,
    /// First-pass extraction of `<title>` from an HTML response body.
    /// Trimmed to 160 characters so the index stays small.
    #[serde(default)]
    pub title: Option<String>,
    /// On-wire protocol token for the recorded transaction — one of
    /// `HTTP/1.0` / `HTTP/1.1` / `HTTP/2` / `HTTP/3`. Mirrors Burp's
    /// "Protocol" column in HTTP history. We copy the string as the
    /// backend stores it (via `HttpVersion::as_str()`) rather than
    /// re-enum'ing on the frontend because the UI only ever reads
    /// the token for display. `None` only for pre-R133 rows that
    /// predate the SELECT including this column; new rows always
    /// have a value populated from `tx.request.http_version`.
    #[serde(default)]
    pub http_version: Option<String>,
    /// Optional Burp-style row highlight. Expected values are the
    /// seven named colours (red, orange, yellow, green, cyan, blue,
    /// purple) or `None`. Stored verbatim so a future UI could add
    /// more without needing a storage migration.
    #[serde(default)]
    pub highlight: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryFilter {
    pub host_contains: Option<String>,
    pub method: Option<String>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub content_type_contains: Option<String>,
    pub source: Option<String>,
    pub in_scope_only: bool,
    pub search_text: Option<String>,
    pub tag: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub after_id: Option<TrafficId>,
    /// Inclusive lower bound on `ts_ms`. `None` disables the clause.
    /// Used by the HistoryPanel toolbar's From / preset buttons.
    pub ts_min_ms: Option<i64>,
    /// Inclusive upper bound on `ts_ms`.
    pub ts_max_ms: Option<i64>,
    /// Inclusive lower bound on `response_size` (bytes of the body
    /// blob stored at `blobs/<sha>`). `None` disables the clause.
    /// Burp's HTTP history filter has a matching "Response size (min)"
    /// field; useful for isolating big-leak responses (think a stray
    /// 500 KB JSON directory listing) at the top of a noisy log.
    pub resp_size_min: Option<i64>,
    /// Inclusive upper bound on `response_size`. Pairs with
    /// `resp_size_min` to form a byte range (e.g. 1-10 KB "small
    /// JSON" window).
    pub resp_size_max: Option<i64>,
    /// Response MIME quick-filter: each entry is a substring probed
    /// against `content_type` and the entries OR together in the SQL
    /// predicate (vs `content_type_contains` which stays single-
    /// valued and ANDs). Mirrors Burp's "MIME type" chip row — the
    /// UI exposes HTML / JSON / XML / JS / CSS / Image as toggleable
    /// chips that map to the common substrings. Empty vec is treated
    /// the same as `None` so a cleared chip row doesn't accidentally
    /// zero out the whole result set.
    pub content_type_classes: Option<Vec<String>>,
    /// Keep only transactions whose `error` column is non-NULL —
    /// network drops, TLS handshake failures, parse errors, or any
    /// upstream fault that prevented a response from being
    /// recorded. Useful when triaging flaky targets: operators flip
    /// this on to see just the connection casualties without the
    /// success stream drowning them out. Default false (don't
    /// filter) matches the "show everything" baseline the other
    /// optional-ish filters use.
    #[serde(default)]
    pub error_only: bool,
    /// Multi-select status-class chip row (Burp's HTTP history filter
    /// supports simultaneous 2xx / 3xx / 4xx / 5xx selection, we did
    /// not). Each entry is a hundreds-digit (1 through 5); the SQL
    /// predicate ORs them together as `(status BETWEEN 100 AND 199)
    /// OR (status BETWEEN 200 AND 299) OR ...`. Values outside 1..=5
    /// are silently dropped so a malformed payload can't inject.
    /// Empty vec = no filter (same as `None`). This lives alongside
    /// `status_min`/`status_max` for backwards compat — bambda
    /// scripts + saved filters continue to work; the chip strip
    /// just writes the new field instead.
    pub status_classes: Option<Vec<u16>>,
    /// Keep only transactions whose `highlight` column is non-NULL.
    /// Mirrors Burp's "Show only highlighted items" annotation filter
    /// — operators tag interesting rows with a colour and later
    /// filter the whole log down to just the shortlist.
    #[serde(default)]
    pub highlighted_only: bool,
    /// Keep only transactions whose `comment` column is non-empty.
    /// Mirrors Burp's "Show only commented items" annotation filter.
    /// Operators attach triage notes to rows (via R101-style set-
    /// comment or inline edit) and this filter pivots to the full
    /// commented worklist in one toggle.
    #[serde(default)]
    pub commented_only: bool,
}

/// Thread-safe wrapper around the SQLite database.
#[derive(Debug, Clone)]
pub struct HistoryStore {
    inner: Arc<Mutex<Connection>>,
}

impl HistoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("open sqlite {}", path.as_ref().display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        init_schema(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert or replace a transaction.
    pub fn upsert_transaction(
        &self,
        tx: &Transaction,
        req_blob: &ContentRef,
        resp_blob: Option<&ContentRef>,
    ) -> Result<()> {
        let conn = self.inner.lock();
        let (status, content_length, content_type, elapsed) = match &tx.response {
            Some(r) => (
                Some(r.status),
                r.headers.content_length(),
                r.headers.content_type().map(|s| s.to_string()),
                Some(r.elapsed_ms),
            ),
            None => (None, None, None, None),
        };
        let tags_json = serde_json::to_string(&tx.tags)?;
        let tls_summary = tx.tls.as_ref().map(|t| t.summary());
        let param_count = count_params(&tx.request) as i64;
        let title = tx.response.as_ref().and_then(|r| extract_title(r)).map(|s| truncate_str(&s, 160));
        conn.execute(
            "INSERT OR REPLACE INTO transactions
                (id, ts_ms, method, scheme, host, port, path, http_version,
                 request_blob, request_size,
                 status, reason, response_blob, response_size,
                 content_length, content_type, elapsed_ms, tags,
                 client_addr, upstream_addr, tls_summary, in_scope, source,
                 annotation, comment, error, parent_id,
                 param_count, title)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     ?9, ?10,
                     ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18,
                     ?19, ?20, ?21, ?22, ?23,
                     ?24, ?25, ?26, ?27,
                     ?28, ?29)",
            params![
                tx.id.as_i64(),
                tx.request.created_at_ms,
                tx.request.method,
                tx.request.scheme,
                tx.request.host,
                tx.request.port,
                tx.request.path,
                tx.request.http_version.as_str(),
                req_blob.sha,
                req_blob.size as i64,
                status.map(|s| s as i64),
                tx.response.as_ref().map(|r| r.reason.clone()),
                resp_blob.map(|r| r.sha.clone()),
                resp_blob.map(|r| r.size as i64),
                content_length.map(|v| v as i64),
                content_type,
                elapsed.map(|v| v as i64),
                tags_json,
                tx.client_addr,
                tx.upstream_addr,
                tls_summary,
                tx.in_scope as i32,
                tx.request.source.as_label(),
                tx.request.annotation,
                tx.request.comment,
                tx.error,
                tx.request.parent_id.map(|p| p.as_i64()),
                param_count,
                title,
            ],
        )?;
        Ok(())
    }

    /// Attach / replace response blob for an existing transaction.
    pub fn update_response(
        &self,
        id: TrafficId,
        status: u16,
        reason: &str,
        content_type: Option<&str>,
        content_length: Option<u64>,
        elapsed_ms: u64,
        resp_blob: &ContentRef,
    ) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE transactions
             SET status = ?1,
                 reason = ?2,
                 response_blob = ?3,
                 response_size = ?4,
                 content_type = ?5,
                 content_length = ?6,
                 elapsed_ms = ?7
             WHERE id = ?8",
            params![
                status as i64,
                reason,
                resp_blob.sha,
                resp_blob.size as i64,
                content_type,
                content_length.map(|v| v as i64),
                elapsed_ms as i64,
                id.as_i64(),
            ],
        )?;
        Ok(())
    }

    pub fn set_tags(&self, id: TrafficId, tags: &[String]) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE transactions SET tags = ?1 WHERE id = ?2",
            params![serde_json::to_string(tags)?, id.as_i64()],
        )?;
        Ok(())
    }

    pub fn set_comment(&self, id: TrafficId, comment: &str) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE transactions SET comment = ?1 WHERE id = ?2",
            params![comment, id.as_i64()],
        )?;
        Ok(())
    }

    /// Update the row-level highlight colour. Pass `None` to clear.
    pub fn set_highlight(&self, id: TrafficId, highlight: Option<&str>) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE transactions SET highlight = ?1 WHERE id = ?2",
            params![highlight, id.as_i64()],
        )?;
        Ok(())
    }

    pub fn get_summary(&self, id: TrafficId) -> Result<Option<StoredSummary>> {
        let conn = self.inner.lock();
        let r = conn
            .query_row(
                "SELECT id, ts_ms, method, scheme, host, port, path, status,
                        content_length, content_type, elapsed_ms, tags,
                        in_scope, source, tls_summary, comment, error,
                        param_count, title, highlight, http_version
                 FROM transactions WHERE id = ?1",
                params![id.as_i64()],
                row_to_summary,
            )
            .optional()?;
        Ok(r)
    }

    pub fn get_request_blob(&self, id: TrafficId) -> Result<Option<ContentRef>> {
        let conn = self.inner.lock();
        let r = conn
            .query_row(
                "SELECT request_blob, request_size FROM transactions WHERE id = ?1",
                params![id.as_i64()],
                |row| {
                    Ok(ContentRef {
                        sha: row.get(0)?,
                        size: row.get::<_, i64>(1)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(r)
    }

    pub fn get_response_blob(&self, id: TrafficId) -> Result<Option<ContentRef>> {
        let conn = self.inner.lock();
        let r = conn
            .query_row(
                "SELECT response_blob, response_size FROM transactions WHERE id = ?1",
                params![id.as_i64()],
                |row| {
                    let sha: Option<String> = row.get(0)?;
                    let size: Option<i64> = row.get(1)?;
                    Ok(sha.and_then(|s| size.map(|sz| ContentRef { sha: s, size: sz as u64 })))
                },
            )
            .optional()?
            .flatten();
        Ok(r)
    }

    pub fn list(&self, filter: &HistoryFilter) -> Result<Vec<StoredSummary>> {
        let conn = self.inner.lock();
        let (sql, args) = build_list_query(filter);
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), row_to_summary)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn count(&self, filter: &HistoryFilter) -> Result<i64> {
        let conn = self.inner.lock();
        let (sql, args) = build_count_query(filter);
        let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(args.iter()), |r| r.get(0))?;
        Ok(n)
    }

    pub fn delete(&self, id: TrafficId) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute("DELETE FROM transactions WHERE id = ?1", params![id.as_i64()])?;
        Ok(())
    }

    /// Delete a batch of transactions in a single statement. Returns the
    /// number of rows actually removed (so the caller can tell if any
    /// ids were already gone).
    pub fn delete_many(&self, ids: &[TrafficId]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        // Build `?,?,?` placeholders — rusqlite doesn't bind arrays directly
        // into `IN`.
        let placeholders = std::iter::repeat("?")
            .take(ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM transactions WHERE id IN ({placeholders})");
        let conn = self.inner.lock();
        let i64s: Vec<i64> = ids.iter().map(|i| i.as_i64()).collect();
        let affected = conn.execute(
            &sql,
            rusqlite::params_from_iter(i64s.iter()),
        )?;
        Ok(affected)
    }

    pub fn clear(&self) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute("DELETE FROM transactions", [])?;
        conn.execute("DELETE FROM ws_sessions", [])?;
        conn.execute("DELETE FROM ws_messages", [])?;
        Ok(())
    }

    // ---- Scanner findings (issues) --------------------------------------
    /// Insert or upsert a finding. If the fingerprint already exists we
    /// bump `observation_count`, refresh `evidence`/`description`, and
    /// touch `updated_at_ms` while preserving user-set state (status,
    /// verification, tags, note, assignee, references).
    pub fn upsert_finding(&self, f: &StoredFinding) -> Result<()> {
        let conn = self.inner.lock();
        let fingerprint = if f.fingerprint.is_empty() {
            compute_fingerprint(f)
        } else {
            f.fingerprint.clone()
        };
        let now = f.updated_at_ms.max(f.ts_ms);
        // Try to find by fingerprint.
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM findings WHERE fingerprint = ?1",
                params![fingerprint],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing_id {
            conn.execute(
                "UPDATE findings
                 SET evidence = ?1,
                     description = ?2,
                     severity = ?3,
                     confidence = ?4,
                     transaction_id = COALESCE(?5, transaction_id),
                     updated_at_ms = ?6,
                     observation_count = observation_count + 1
                 WHERE id = ?7",
                params![
                    f.evidence,
                    f.description,
                    f.severity,
                    f.confidence,
                    f.transaction_id.map(|t| t.as_i64()),
                    now,
                    id,
                ],
            )?;
        } else {
            conn.execute(
                "INSERT INTO findings
                 (id, ts_ms, transaction_id, detector, title, description,
                  severity, confidence, evidence, remediation,
                  fingerprint, status, verification, tags, references_json,
                  assignee, note, insertion_point, updated_at_ms, observation_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                params![
                    f.id.as_i64(),
                    f.ts_ms,
                    f.transaction_id.map(|t| t.as_i64()),
                    f.detector,
                    f.title,
                    f.description,
                    f.severity,
                    f.confidence,
                    f.evidence,
                    f.remediation,
                    fingerprint,
                    if f.status.is_empty() { "new".to_string() } else { f.status.clone() },
                    if f.verification.is_empty() { "unverified".to_string() } else { f.verification.clone() },
                    serde_json::to_string(&f.tags).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&f.references).unwrap_or_else(|_| "[]".into()),
                    f.assignee,
                    f.note,
                    f.insertion_point,
                    now,
                    f.observation_count.max(1),
                ],
            )?;
        }
        Ok(())
    }

    /// Backwards-compat shim: previous callers inserted raw findings
    /// unconditionally. Rewires to `upsert_finding` so dedup works.
    pub fn insert_finding(&self, f: &StoredFinding) -> Result<()> {
        self.upsert_finding(f)
    }

    pub fn update_finding_status(&self, id: TrafficId, status: &str, note: Option<&str>) -> Result<()> {
        let conn = self.inner.lock();
        let now = crate::blobs::now_ms_hint();
        conn.execute(
            "UPDATE findings SET status = ?1, note = COALESCE(?2, note), updated_at_ms = ?3 WHERE id = ?4",
            params![status, note, now, id.as_i64()],
        )?;
        Ok(())
    }

    pub fn update_finding_verification(&self, id: TrafficId, verification: &str) -> Result<()> {
        let conn = self.inner.lock();
        let now = crate::blobs::now_ms_hint();
        conn.execute(
            "UPDATE findings SET verification = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![verification, now, id.as_i64()],
        )?;
        Ok(())
    }

    /// R344: Dedicated note setter. The existing
    /// `update_finding_status` can take an optional `note` but
    /// only alongside a status change; this one updates the note
    /// in isolation so operators can annotate a finding without
    /// also moving it through the triage lifecycle. Empty string
    /// clears the note; the schema's NOT NULL default handles that
    /// transparently.
    pub fn update_finding_note(&self, id: TrafficId, note: &str) -> Result<()> {
        let conn = self.inner.lock();
        let now = crate::blobs::now_ms_hint();
        conn.execute(
            "UPDATE findings SET note = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![note, now, id.as_i64()],
        )?;
        Ok(())
    }

    /// R164: Operator-driven severity override. Caller validates that
    /// `severity` is one of the five canonical levels
    /// (critical/high/medium/low/info); we persist whatever string
    /// they pass to keep this honest + leave the enum policy at the
    /// edge. Mirror of `update_finding_status` / `_verification`.
    pub fn update_finding_severity(&self, id: TrafficId, severity: &str) -> Result<()> {
        let conn = self.inner.lock();
        let now = crate::blobs::now_ms_hint();
        conn.execute(
            "UPDATE findings SET severity = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![severity, now, id.as_i64()],
        )?;
        Ok(())
    }

    pub fn update_finding_tags(&self, id: TrafficId, tags: &[String]) -> Result<()> {
        let conn = self.inner.lock();
        let now = crate::blobs::now_ms_hint();
        conn.execute(
            "UPDATE findings SET tags = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![serde_json::to_string(tags)?, now, id.as_i64()],
        )?;
        Ok(())
    }

    /// Delete every finding whose id matches one in `ids`. Single
    /// `DELETE ... IN(?, ?, ...)` statement so bulk clears from the
    /// UI's multi-select action strip stay snappy. Returns the count
    /// actually removed so the caller can show "N findings deleted".
    pub fn delete_findings_many(&self, ids: &[TrafficId]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = std::iter::repeat("?")
            .take(ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM findings WHERE id IN ({placeholders})");
        let conn = self.inner.lock();
        let i64s: Vec<i64> = ids.iter().map(|i| i.as_i64()).collect();
        let affected = conn.execute(&sql, rusqlite::params_from_iter(i64s.iter()))?;
        Ok(affected)
    }

    pub fn delete_finding(&self, id: TrafficId) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute("DELETE FROM findings WHERE id = ?1", params![id.as_i64()])?;
        Ok(())
    }

    pub fn list_findings(&self) -> Result<Vec<StoredFinding>> {
        self.list_findings_filtered(&FindingFilter::default())
    }

    pub fn list_findings_filtered(&self, f: &FindingFilter) -> Result<Vec<StoredFinding>> {
        let conn = self.inner.lock();
        let mut sql = String::from(
            "SELECT id, ts_ms, transaction_id, detector, title, description,
                    severity, confidence, evidence, remediation,
                    fingerprint, status, verification, tags, references_json,
                    assignee, note, insertion_point, updated_at_ms, observation_count
             FROM findings WHERE 1=1",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(s) = &f.severity { sql.push_str(" AND severity = ?"); args.push(Box::new(s.clone())); }
        if let Some(s) = &f.status   { sql.push_str(" AND status   = ?"); args.push(Box::new(s.clone())); }
        if let Some(d) = &f.detector { sql.push_str(" AND detector = ?"); args.push(Box::new(d.clone())); }
        if let Some(t) = &f.tag      { sql.push_str(" AND tags LIKE ?"); args.push(Box::new(format!("%\"{t}\"%"))); }
        if let Some(id) = f.transaction_id { sql.push_str(" AND transaction_id = ?"); args.push(Box::new(id.as_i64())); }
        if let Some(q) = &f.search {
            sql.push_str(" AND (title LIKE ? OR description LIKE ? OR evidence LIKE ? OR note LIKE ?)");
            let p = format!("%{q}%");
            args.push(Box::new(p.clone()));
            args.push(Box::new(p.clone()));
            args.push(Box::new(p.clone()));
            args.push(Box::new(p));
        }
        sql.push_str(" ORDER BY \
            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
            id DESC");
        if let Some(l) = f.limit  { sql.push_str(&format!(" LIMIT {l}")); }
        if let Some(o) = f.offset { sql.push_str(&format!(" OFFSET {o}")); }
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), row_to_finding)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Count findings grouped by severity.
    pub fn finding_counts_by_severity(&self) -> Result<std::collections::BTreeMap<String, i64>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare("SELECT severity, COUNT(*) FROM findings GROUP BY severity")?;
        let mut out = std::collections::BTreeMap::new();
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            if let Ok((sev, n)) = row {
                out.insert(sev, n);
            }
        }
        Ok(out)
    }

    /// Count findings grouped by host AND severity. Returns a flat
    /// list of (host, severity, count) tuples — the caller is
    /// responsible for shaping into a nested map if needed.
    ///
    /// Backs the Target → SiteMap per-host issue badges. Findings
    /// without a `transaction_id` are omitted (no host to join on);
    /// the rest JOIN against `transactions.host` to get the origin.
    /// `severity` is lower-cased on the storage side so the UI's
    /// palette lookup works regardless of how the detector cased it.
    pub fn finding_counts_by_host(&self) -> Result<Vec<(String, String, i64)>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT t.host, LOWER(f.severity), COUNT(*)
             FROM findings f
             JOIN transactions t ON f.transaction_id = t.id
             WHERE f.transaction_id IS NOT NULL
             GROUP BY t.host, LOWER(f.severity)
             ORDER BY t.host, LOWER(f.severity)",
        )?;
        let mut out = Vec::new();
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })? {
            if let Ok(tup) = row {
                out.push(tup);
            }
        }
        Ok(out)
    }

    // ---- WebSocket -------------------------------------------------------
    pub fn insert_ws_session(&self, s: &WebSocketSession) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT OR REPLACE INTO ws_sessions
             (id, handshake_id, host, port, path, opened_at_ms, closed_at_ms, close_code, close_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                s.id.as_i64(),
                s.handshake.id.as_i64(),
                s.handshake.request.host,
                s.handshake.request.port,
                s.handshake.request.path,
                s.handshake.request.created_at_ms,
                s.closed_at_ms,
                s.close_code.map(|c| c as i64),
                s.close_reason,
            ],
        )?;
        Ok(())
    }

    pub fn insert_ws_message(&self, m: &WebSocketMessage, payload_blob: &ContentRef) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT OR REPLACE INTO ws_messages
             (id, session_id, direction, opcode, blob, size, ts_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                m.id.as_i64(),
                m.session_id.as_i64(),
                match m.direction {
                    burpfree_core::traffic::WsDirection::Outbound => "out",
                    burpfree_core::traffic::WsDirection::Inbound => "in",
                },
                m.opcode.to_u8() as i64,
                payload_blob.sha,
                payload_blob.size as i64,
                m.created_at_ms,
            ],
        )?;
        Ok(())
    }

    pub fn close_ws_session(
        &self,
        session_id: TrafficId,
        closed_at_ms: i64,
        code: Option<u16>,
        reason: Option<String>,
    ) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE ws_sessions SET closed_at_ms = ?1, close_code = ?2, close_reason = ?3 WHERE id = ?4",
            params![closed_at_ms, code.map(|c| c as i64), reason, session_id.as_i64()],
        )?;
        Ok(())
    }

    /// List WebSocket sessions, newest first. Pure read; the UI uses this to
    /// populate the WebSocket Replay panel.
    pub fn list_ws_sessions(&self, limit: Option<i64>) -> Result<Vec<StoredWsSession>> {
        let conn = self.inner.lock();
        let lim = limit.unwrap_or(200);
        let mut stmt = conn.prepare(
            "SELECT s.id, s.handshake_id, s.host, s.port, s.path,
                    s.opened_at_ms, s.closed_at_ms, s.close_code, s.close_reason,
                    (SELECT COUNT(*) FROM ws_messages m WHERE m.session_id = s.id)
             FROM ws_sessions s
             ORDER BY s.opened_at_ms DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![lim], |r| {
            Ok(StoredWsSession {
                id: TrafficId::from(r.get::<_, i64>(0)?),
                handshake_id: TrafficId::from(r.get::<_, i64>(1)?),
                host: r.get(2)?,
                port: r.get::<_, i64>(3)? as u16,
                path: r.get(4)?,
                opened_at_ms: r.get(5)?,
                closed_at_ms: r.get(6)?,
                close_code: r.get::<_, Option<i64>>(7)?.map(|v| v as u16),
                close_reason: r.get(8)?,
                message_count: r.get::<_, i64>(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Read messages for one session, in chronological order.
    pub fn list_ws_messages(&self, session_id: TrafficId) -> Result<Vec<StoredWsMessage>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, direction, opcode, blob, size, ts_ms
             FROM ws_messages WHERE session_id = ?1
             ORDER BY ts_ms ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![session_id.as_i64()], |r| {
            Ok(StoredWsMessage {
                id: TrafficId::from(r.get::<_, i64>(0)?),
                session_id: TrafficId::from(r.get::<_, i64>(1)?),
                direction: r.get(2)?,
                opcode: r.get::<_, i64>(3)? as u8,
                blob: r.get(4)?,
                size: r.get::<_, i64>(5)? as u64,
                ts_ms: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Return a session row by id (or None if missing).
    pub fn get_ws_session(&self, session_id: TrafficId) -> Result<Option<StoredWsSession>> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT s.id, s.handshake_id, s.host, s.port, s.path,
                        s.opened_at_ms, s.closed_at_ms, s.close_code, s.close_reason,
                        (SELECT COUNT(*) FROM ws_messages m WHERE m.session_id = s.id)
                 FROM ws_sessions s WHERE s.id = ?1",
                params![session_id.as_i64()],
                |r| {
                    Ok(StoredWsSession {
                        id: TrafficId::from(r.get::<_, i64>(0)?),
                        handshake_id: TrafficId::from(r.get::<_, i64>(1)?),
                        host: r.get(2)?,
                        port: r.get::<_, i64>(3)? as u16,
                        path: r.get(4)?,
                        opened_at_ms: r.get(5)?,
                        closed_at_ms: r.get(6)?,
                        close_code: r.get::<_, Option<i64>>(7)?.map(|v| v as u16),
                        close_reason: r.get(8)?,
                        message_count: r.get::<_, i64>(9)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }
}

/// A stored WebSocket session row, enriched with message count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWsSession {
    pub id: TrafficId,
    pub handshake_id: TrafficId,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub opened_at_ms: i64,
    pub closed_at_ms: Option<i64>,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub message_count: i64,
}

/// A stored WebSocket message row. `blob` points into the content-addressed
/// blob store; use `BlobStore::get` with that sha to materialise the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWsMessage {
    pub id: TrafficId,
    pub session_id: TrafficId,
    /// "in" (server→client) or "out" (client→server).
    pub direction: String,
    pub opcode: u8,
    pub blob: String,
    pub size: u64,
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: TrafficId,
    pub ts_ms: i64,
    pub transaction_id: Option<TrafficId>,
    pub detector: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub evidence: String,
    pub remediation: String,
    /// Deterministic fingerprint used for dedup across runs. Issues with
    /// the same fingerprint collapse into one row (last-write-wins for
    /// mutable attributes, with observation counters tracked separately).
    #[serde(default)]
    pub fingerprint: String,
    /// Issue lifecycle: new | triaging | confirmed | false_positive | fixed | wontfix
    #[serde(default = "default_status")]
    pub status: String,
    /// Verification state: unverified | verified | false_positive
    #[serde(default = "default_verification")]
    pub verification: String,
    /// Free-form tags set by the user.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Known-vuln references (CWE / OWASP / RFC links).
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub note: String,
    /// Where in the request the finding points (parameter name, header, body region).
    #[serde(default)]
    pub insertion_point: Option<String>,
    /// Updated timestamp (ms since epoch).
    #[serde(default)]
    pub updated_at_ms: i64,
    /// How many times this fingerprint has been observed.
    #[serde(default = "default_count")]
    pub observation_count: i64,
}

fn default_status() -> String { "new".into() }
fn default_verification() -> String { "unverified".into() }
fn default_count() -> i64 { 1 }

/// Filter for the issues/findings list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub detector: Option<String>,
    pub tag: Option<String>,
    pub transaction_id: Option<TrafficId>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFinding> {
    let tags_json: String = row.get(13).unwrap_or_else(|_| "[]".into());
    let refs_json: String = row.get(14).unwrap_or_else(|_| "[]".into());
    Ok(StoredFinding {
        id: TrafficId(row.get(0)?),
        ts_ms: row.get(1)?,
        transaction_id: row.get::<_, Option<i64>>(2)?.map(TrafficId),
        detector: row.get(3)?,
        title: row.get(4)?,
        description: row.get(5)?,
        severity: row.get(6)?,
        confidence: row.get(7)?,
        evidence: row.get(8)?,
        remediation: row.get(9)?,
        fingerprint: row.get(10).unwrap_or_default(),
        status: row.get(11).unwrap_or_else(|_| "new".into()),
        verification: row.get(12).unwrap_or_else(|_| "unverified".into()),
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        references: serde_json::from_str(&refs_json).unwrap_or_default(),
        assignee: row.get(15).ok(),
        note: row.get(16).unwrap_or_default(),
        insertion_point: row.get(17).ok(),
        updated_at_ms: row.get(18).unwrap_or_default(),
        observation_count: row.get(19).unwrap_or(1),
    })
}

/// Compute a stable fingerprint for an issue so re-scans dedup correctly.
///
/// We combine: detector id, host, path (sans query), method, insertion-point
/// label. Severity/confidence intentionally excluded so a detector that
/// adjusts them later still collapses onto the same issue.
pub fn compute_fingerprint(f: &StoredFinding) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(f.detector.as_bytes());
    h.update(b"|");
    h.update(f.title.as_bytes());
    h.update(b"|");
    h.update(f.insertion_point.as_deref().unwrap_or("").as_bytes());
    // Transaction host/path if available via evidence hint.
    h.update(b"|");
    h.update(f.evidence.as_bytes());
    let hex = h.finalize();
    hex::encode(&hex.as_bytes()[..16])
}

mod hex {
    pub fn encode(b: &[u8]) -> String {
        const H: &[u8] = b"0123456789abcdef";
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push(H[(x >> 4) as usize] as char);
            s.push(H[(x & 0x0f) as usize] as char);
        }
        s
    }
}

/// Count observable params on a request: query-string pairs + form-encoded
/// body pairs. Non-form bodies (JSON, binary, …) contribute 0 — the UI's
/// insertion-point surface already renders them separately.
fn count_params(req: &burpfree_core::traffic::Request) -> usize {
    // Query params: split path at '?', count '='-containing segments.
    let mut n = 0usize;
    if let Some(q) = req.path.split_once('?').map(|(_, q)| q) {
        for seg in q.split('&') {
            if seg.contains('=') && !seg.is_empty() {
                n += 1;
            }
        }
    }
    if let Some(ct) = req.headers.content_type() {
        if ct.contains("application/x-www-form-urlencoded") && !req.body.is_empty() {
            let body = String::from_utf8_lossy(&req.body);
            for seg in body.split('&') {
                if seg.contains('=') && !seg.is_empty() {
                    n += 1;
                }
            }
        } else if ct.contains("multipart/form-data") && !req.body.is_empty() {
            // Approximate: count `name="..."` disposition declarations.
            let body = String::from_utf8_lossy(&req.body);
            n += body.matches("Content-Disposition").count();
        }
    }
    n
}

/// Pull the first `<title>...</title>` from a text/html response body
/// using a very small forgiving parser (no HTML parser dep).
fn extract_title(resp: &burpfree_core::traffic::Response) -> Option<String> {
    let ct = resp.headers.content_type().unwrap_or("");
    if !ct.contains("text/html") {
        return None;
    }
    // Only scan the first 128 KB — pathological pages don't justify loading
    // a megabyte of DOM into memory for a column.
    let n = resp.body.len().min(128 * 1024);
    let haystack = String::from_utf8_lossy(&resp.body[..n]);
    let lower = haystack.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = &lower[start..];
    let gt = after.find('>')?;
    let begin = start + gt + 1;
    let end = lower[begin..].find("</title>")?;
    let raw = &haystack[begin..begin + end];
    let decoded = raw
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");
    let trimmed = decoded.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Clamp a string to `max` characters, preserving UTF-8 boundaries.
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSummary> {
    let tags_json: String = row.get(11)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    Ok(StoredSummary {
        id: TrafficId(row.get(0)?),
        ts_ms: row.get(1)?,
        method: row.get(2)?,
        scheme: row.get(3)?,
        host: row.get(4)?,
        port: row.get::<_, i64>(5)? as u16,
        path: row.get(6)?,
        status: row.get::<_, Option<i64>>(7)?.map(|v| v as u16),
        content_length: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        content_type: row.get(9)?,
        elapsed_ms: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
        tags,
        in_scope: row.get::<_, i64>(12)? != 0,
        source: row.get(13)?,
        tls_summary: row.get(14)?,
        comment: row.get(15)?,
        error: row.get(16)?,
        // Columns added by the site-map 2.0 migration; use `.ok()` so
        // pre-migration schemas still read cleanly during the one-time
        // open before migrate_transactions runs.
        param_count: row.get::<_, Option<i64>>(17).ok().flatten().map(|v| v as u16).unwrap_or(0),
        title: row.get::<_, Option<String>>(18).ok().flatten(),
        highlight: row.get::<_, Option<String>>(19).ok().flatten(),
        // R133: Protocol column, surfacing the on-wire HTTP version.
        // `http_version` lives on the schema as `TEXT NOT NULL` from
        // the first revision (see init_schema), so this read is
        // always safe. We wrap in Option<String> so a future
        // migration that stores NULL for synthetic rows survives.
        http_version: row.get::<_, Option<String>>(20).ok().flatten(),
    })
}

fn build_list_query(f: &HistoryFilter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut sql = String::from(
        "SELECT id, ts_ms, method, scheme, host, port, path, status,
                content_length, content_type, elapsed_ms, tags,
                in_scope, source, tls_summary, comment, error,
                param_count, title, highlight, http_version
         FROM transactions WHERE 1=1",
    );
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    apply_filter_sql(f, &mut sql, &mut args);
    sql.push_str(" ORDER BY id DESC");
    if let Some(l) = f.limit {
        sql.push_str(&format!(" LIMIT {l}"));
    }
    if let Some(o) = f.offset {
        sql.push_str(&format!(" OFFSET {o}"));
    }
    (sql, args)
}

fn build_count_query(f: &HistoryFilter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut sql = String::from("SELECT COUNT(*) FROM transactions WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    apply_filter_sql(f, &mut sql, &mut args);
    (sql, args)
}

fn apply_filter_sql(f: &HistoryFilter, sql: &mut String, args: &mut Vec<Box<dyn rusqlite::ToSql>>) {
    if let Some(h) = &f.host_contains {
        sql.push_str(" AND host LIKE ?");
        args.push(Box::new(format!("%{h}%")));
    }
    if let Some(m) = &f.method {
        sql.push_str(" AND method = ?");
        args.push(Box::new(m.clone()));
    }
    if let Some(min) = f.status_min {
        sql.push_str(" AND status >= ?");
        args.push(Box::new(min as i64));
    }
    if let Some(max) = f.status_max {
        sql.push_str(" AND status <= ?");
        args.push(Box::new(max as i64));
    }
    if let Some(c) = &f.content_type_contains {
        sql.push_str(" AND content_type LIKE ?");
        args.push(Box::new(format!("%{c}%")));
    }
    if let Some(s) = &f.source {
        sql.push_str(" AND source = ?");
        args.push(Box::new(s.clone()));
    }
    if f.in_scope_only {
        sql.push_str(" AND in_scope = 1");
    }
    if let Some(ts) = f.ts_min_ms {
        sql.push_str(" AND ts_ms >= ?");
        args.push(Box::new(ts));
    }
    if let Some(ts) = f.ts_max_ms {
        sql.push_str(" AND ts_ms <= ?");
        args.push(Box::new(ts));
    }
    if let Some(min) = f.resp_size_min {
        // response_size can be NULL for in-flight / errored txns;
        // SQLite's `>=` on NULL returns NULL (falsy), so a lower
        // bound naturally excludes response-less rows — matching
        // operator intent ("show me big responses" implies there IS
        // a response).
        sql.push_str(" AND response_size >= ?");
        args.push(Box::new(min));
    }
    if let Some(max) = f.resp_size_max {
        sql.push_str(" AND response_size <= ?");
        args.push(Box::new(max));
    }
    if let Some(classes) = &f.content_type_classes {
        // OR each substring together inside a parenthesised subclause
        // so the whole thing composes with the surrounding AND
        // predicates. Empty vec is treated as "no filter" to match
        // the UI's cleared-all-chips state (otherwise an empty IN
        // list would nuke the result set).
        let non_empty: Vec<&String> = classes.iter().filter(|s| !s.trim().is_empty()).collect();
        if !non_empty.is_empty() {
            sql.push_str(" AND (");
            for (i, c) in non_empty.iter().enumerate() {
                if i > 0 {
                    sql.push_str(" OR ");
                }
                sql.push_str("content_type LIKE ?");
                args.push(Box::new(format!("%{c}%")));
            }
            sql.push(')');
        }
    }
    if f.error_only {
        // `error` is NULL for every happy-path transaction and the
        // text of the failure (connect refused / TLS alert / parse
        // error / etc.) when the proxy couldn't finish a round-trip.
        // Checking `error IS NOT NULL` is enough — we don't need an
        // additional `!= ''` guard because the proxy only sets the
        // column when there's a real message to record.
        sql.push_str(" AND error IS NOT NULL");
    }
    if let Some(classes) = f.status_classes.as_ref() {
        // Multi-select chip row: an operator can OR 2xx + 4xx + 5xx
        // together to see successes plus failure signals in one view.
        // Values outside 1..=5 are silently dropped — a mal-formed
        // payload (e.g. a 42 slipping through serde because `u16` is
        // wide) can't inject arbitrary SQL. Empty vec = no filter so
        // a cleared chip row doesn't nuke the result set. Parameter-
        // ised the comparisons so the body stays in the same style
        // as every other clause.
        let clean: Vec<u16> = classes
            .iter()
            .copied()
            .filter(|c| (1..=5).contains(c))
            .collect();
        if !clean.is_empty() {
            sql.push_str(" AND (");
            for (i, c) in clean.iter().enumerate() {
                if i > 0 {
                    sql.push_str(" OR ");
                }
                sql.push_str("(status >= ? AND status <= ?)");
                args.push(Box::new((*c as i64) * 100));
                args.push(Box::new((*c as i64) * 100 + 99));
            }
            sql.push(')');
        }
    }
    if f.highlighted_only {
        // Burp's annotation filter: operators tag interesting rows
        // with a highlight colour via R112-style right-click, then
        // flip this on to prune the log to just the shortlist. We
        // store the colour name (red/orange/yellow/green/cyan/blue/
        // purple) so IS NOT NULL is the right check — any non-null
        // value is a "tagged" row.
        sql.push_str(" AND highlight IS NOT NULL");
    }
    if f.commented_only {
        // Pair of `highlighted_only`. `comment` is stored as `TEXT
        // NOT NULL DEFAULT ''` so the right check is != '' rather
        // than IS NOT NULL — a cleared comment lands as an empty
        // string, not a NULL, and the operator expects "comment
        // cleared" to drop the row from this filter.
        sql.push_str(" AND comment != ''");
    }
    if let Some(q) = &f.search_text {
        // Search path and host (full-text-ish). This stays cheap on
        // indexed columns.
        sql.push_str(" AND (path LIKE ? OR host LIKE ? OR comment LIKE ?)");
        let pattern = format!("%{q}%");
        args.push(Box::new(pattern.clone()));
        args.push(Box::new(pattern.clone()));
        args.push(Box::new(pattern));
    }
    if let Some(t) = &f.tag {
        sql.push_str(" AND tags LIKE ?");
        args.push(Box::new(format!("%\"{t}\"%")));
    }
    if let Some(id) = f.after_id {
        sql.push_str(" AND id > ?");
        args.push(Box::new(id.as_i64()));
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            method TEXT NOT NULL,
            scheme TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            path TEXT NOT NULL,
            http_version TEXT NOT NULL,
            request_blob TEXT NOT NULL,
            request_size INTEGER NOT NULL,
            status INTEGER,
            reason TEXT,
            response_blob TEXT,
            response_size INTEGER,
            content_length INTEGER,
            content_type TEXT,
            elapsed_ms INTEGER,
            tags TEXT NOT NULL DEFAULT '[]',
            client_addr TEXT,
            upstream_addr TEXT,
            tls_summary TEXT,
            in_scope INTEGER NOT NULL DEFAULT 1,
            source TEXT NOT NULL DEFAULT 'proxy',
            annotation TEXT NOT NULL DEFAULT '',
            comment TEXT NOT NULL DEFAULT '',
            error TEXT,
            parent_id INTEGER,
            param_count INTEGER NOT NULL DEFAULT 0,
            title TEXT,
            highlight TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tx_host     ON transactions(host);
        CREATE INDEX IF NOT EXISTS idx_tx_method   ON transactions(method);
        CREATE INDEX IF NOT EXISTS idx_tx_status   ON transactions(status);
        CREATE INDEX IF NOT EXISTS idx_tx_source   ON transactions(source);
        CREATE INDEX IF NOT EXISTS idx_tx_in_scope ON transactions(in_scope);
        CREATE INDEX IF NOT EXISTS idx_tx_ts       ON transactions(ts_ms);

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            transaction_id INTEGER,
            detector TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'new',
            verification TEXT NOT NULL DEFAULT 'unverified',
            tags TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            assignee TEXT,
            note TEXT NOT NULL DEFAULT '',
            insertion_point TEXT,
            updated_at_ms INTEGER NOT NULL DEFAULT 0,
            observation_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_find_tx ON findings(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_find_severity ON findings(severity);
        -- idx_find_fp is created inside migrate_findings so legacy
        -- projects can first add the column.

        CREATE TABLE IF NOT EXISTS ws_sessions (
            id INTEGER PRIMARY KEY,
            handshake_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            path TEXT NOT NULL,
            opened_at_ms INTEGER NOT NULL,
            closed_at_ms INTEGER,
            close_code INTEGER,
            close_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS ws_messages (
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            direction TEXT NOT NULL,
            opcode INTEGER NOT NULL,
            blob TEXT NOT NULL,
            size INTEGER NOT NULL,
            ts_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ws_session ON ws_messages(session_id);

        CREATE TABLE IF NOT EXISTS organizer (
            id INTEGER PRIMARY KEY,
            transaction_id INTEGER,
            title TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'open',
            ts_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            collection_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_org_tx ON organizer(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_org_status ON organizer(status);
        -- idx_org_coll is created inside migrate_transactions so legacy
        -- projects can first add the column.

        CREATE TABLE IF NOT EXISTS organizer_collections (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL
        );
        ",
    )?;
    // Migrate older findings tables that pre-date the issue 2.0 columns.
    migrate_findings(conn)?;
    migrate_transactions(conn)?;
    Ok(())
}

/// Backfill columns on transactions created before site-map 2.0.
fn migrate_transactions(conn: &Connection) -> Result<()> {
    let have_col = |table: &str, name: &str| -> bool {
        conn.prepare(&format!("SELECT {name} FROM {table} LIMIT 0"))
            .is_ok()
    };
    for (col, decl) in [
        ("param_count", "INTEGER NOT NULL DEFAULT 0"),
        ("title", "TEXT"),
        ("highlight", "TEXT"),
    ] {
        if !have_col("transactions", col) {
            conn.execute(
                &format!("ALTER TABLE transactions ADD COLUMN {col} {decl}"),
                [],
            )
            .ok();
        }
    }
    // Organizer collections: pre-collection projects need the fk column.
    if !have_col("organizer", "collection_id") {
        conn.execute("ALTER TABLE organizer ADD COLUMN collection_id INTEGER", [])
            .ok();
    }
    // Index is always safe to re-run; the fresh-schema path needs it too since
    // we moved it out of the init batch for migration ordering reasons.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_org_coll ON organizer(collection_id)",
        [],
    )
    .ok();
    Ok(())
}

/// Backfill columns on projects created before issue-engine 2.0. SQLite's
/// `ALTER TABLE ADD COLUMN` is idempotent only via a probe query.
fn migrate_findings(conn: &Connection) -> Result<()> {
    let have_col = |name: &str| -> bool {
        conn.prepare(&format!("SELECT {name} FROM findings LIMIT 0"))
            .is_ok()
    };
    for (col, decl) in [
        ("fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ("status", "TEXT NOT NULL DEFAULT 'new'"),
        ("verification", "TEXT NOT NULL DEFAULT 'unverified'"),
        ("tags", "TEXT NOT NULL DEFAULT '[]'"),
        ("references_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("assignee", "TEXT"),
        ("note", "TEXT NOT NULL DEFAULT ''"),
        ("insertion_point", "TEXT"),
        ("updated_at_ms", "INTEGER NOT NULL DEFAULT 0"),
        ("observation_count", "INTEGER NOT NULL DEFAULT 1"),
    ] {
        if !have_col(col) {
            conn.execute(&format!("ALTER TABLE findings ADD COLUMN {col} {decl}"), [])
                .ok();
        }
    }
    // Ensure the unique fingerprint index exists.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_find_fp ON findings(fingerprint) WHERE fingerprint <> ''",
        [],
    )
    .ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, RequestSource, Response, Transaction};
    use tempfile::tempdir;

    fn mkreq(path: &str) -> Transaction {
        let mut r = Request::new("GET", &format!("http://example.com{path}")).unwrap();
        r.source = RequestSource::Proxy;
        let mut t = Transaction::new(r);
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html");
        resp.set_text("<h1>hi</h1>");
        t.response = Some(resp);
        t
    }

    #[test]
    fn upsert_and_list() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        let t = mkreq("/first");
        let req_blob = ContentRef::from_bytes(&t.request.body);
        let resp_blob = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
        store.upsert_transaction(&t, &req_blob, Some(&resp_blob)).unwrap();
        let rows = store.list(&HistoryFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "example.com");
        assert_eq!(rows[0].status, Some(200));
    }

    #[test]
    fn filters_narrow_results() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        for p in ["/a", "/b", "/c-admin"] {
            let t = mkreq(p);
            let req_blob = ContentRef::from_bytes(&t.request.body);
            let resp_blob = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
            store.upsert_transaction(&t, &req_blob, Some(&resp_blob)).unwrap();
        }
        let f = HistoryFilter { search_text: Some("admin".into()), ..Default::default() };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/c-admin");
    }

    #[test]
    fn count_matches_rows() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        for _ in 0..10 {
            let t = mkreq("/x");
            let b = ContentRef::from_bytes(&t.request.body);
            store.upsert_transaction(&t, &b, None).unwrap();
        }
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 10);
    }

    #[test]
    fn summary_carries_param_count_and_title() {
        use burpfree_core::traffic::{Request, Response};
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();

        // Query string with 2 params + form body with 2 more = 4 params total.
        let mut req = Request::new("POST", "https://example.com/login?return=/home&flash=1").unwrap();
        req.headers.set("Content-Type", "application/x-www-form-urlencoded");
        req.body = b"user=alice&password=secret".to_vec();
        let mut t = Transaction::new(req);
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "text/html; charset=utf-8");
        resp.set_text("<html><head><title> Welcome &amp; Hello </title></head><body>…</body></html>");
        t.response = Some(resp);

        let req_blob = ContentRef::from_bytes(&t.request.body);
        let resp_blob = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
        store.upsert_transaction(&t, &req_blob, Some(&resp_blob)).unwrap();

        let rows = store.list(&HistoryFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].param_count, 4);
        assert_eq!(rows[0].title.as_deref(), Some("Welcome & Hello"));
    }

    #[test]
    fn non_html_response_has_no_title() {
        use burpfree_core::traffic::{Request, Response};
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        let req = Request::new("GET", "https://example.com/api/users").unwrap();
        let mut t = Transaction::new(req);
        let mut resp = Response::new(200);
        resp.headers.set("Content-Type", "application/json");
        resp.set_text(r#"{"users":[]}"#);
        t.response = Some(resp);
        let rb = ContentRef::from_bytes(&t.request.body);
        let xb = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
        store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        let rows = store.list(&HistoryFilter::default()).unwrap();
        assert!(rows[0].title.is_none());
        assert_eq!(rows[0].param_count, 0);
    }

    #[test]
    fn organizer_collection_lifecycle() {
        use burpfree_core::traffic::Request;
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();

        // Add two inbox items first.
        let item_a = OrganizerItem {
            id: TrafficId::new(),
            transaction_id: None,
            title: "A".into(),
            note: String::new(),
            tags: vec![],
            status: "open".into(),
            ts_ms: 1,
            updated_at_ms: 1,
            collection_id: None,
        };
        let item_b = OrganizerItem {
            id: TrafficId::new(),
            transaction_id: None,
            title: "B".into(),
            note: String::new(),
            tags: vec![],
            status: "open".into(),
            ts_ms: 2,
            updated_at_ms: 2,
            collection_id: None,
        };
        store.organizer_add(&item_a).unwrap();
        store.organizer_add(&item_b).unwrap();

        // Collections start empty, inbox has 2.
        assert_eq!(store.collections_list().unwrap().len(), 0);
        assert_eq!(store.collection_inbox_count().unwrap(), 2);

        // Create a collection, move item A into it.
        let cid = store.collection_create("Session fixation").unwrap();
        store.organizer_move_to_collection(item_a.id, Some(cid)).unwrap();
        let colls = store.collections_list().unwrap();
        assert_eq!(colls.len(), 1);
        assert_eq!(colls[0].name, "Session fixation");
        assert_eq!(colls[0].item_count, 1);
        assert_eq!(store.collection_inbox_count().unwrap(), 1);

        // Rename.
        store.collection_rename(cid, "Session issues").unwrap();
        let colls = store.collections_list().unwrap();
        assert_eq!(colls[0].name, "Session issues");

        // Filter: list items only in collection.
        let in_coll = store.organizer_list_in_collection(Some(Some(cid))).unwrap();
        assert_eq!(in_coll.len(), 1);
        assert_eq!(in_coll[0].title, "A");

        let in_inbox = store.organizer_list_in_collection(Some(None)).unwrap();
        assert_eq!(in_inbox.len(), 1);
        assert_eq!(in_inbox[0].title, "B");

        // Delete collection → items return to inbox.
        store.collection_delete(cid).unwrap();
        assert_eq!(store.collections_list().unwrap().len(), 0);
        assert_eq!(store.collection_inbox_count().unwrap(), 2);
        let all_inbox = store.organizer_list_in_collection(Some(None)).unwrap();
        assert_eq!(all_inbox.len(), 2);
    }

    #[test]
    fn ws_round_trip() {
        use burpfree_core::traffic::{WebSocketMessage, WebSocketSession, WsDirection, WsOpcode};
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();

        // Open a session and append two messages.
        let handshake = mkreq("/ws");
        let mut sess = WebSocketSession::new(handshake);
        let sid = sess.id;
        store.insert_ws_session(&sess).unwrap();

        let m1 = WebSocketMessage::new(sid, WsDirection::Outbound, WsOpcode::Text, b"hello".to_vec());
        let m2 = WebSocketMessage::new(sid, WsDirection::Inbound,  WsOpcode::Text, b"world".to_vec());
        store.insert_ws_message(&m1, &ContentRef::from_bytes(&m1.payload)).unwrap();
        store.insert_ws_message(&m2, &ContentRef::from_bytes(&m2.payload)).unwrap();

        let sessions = store.list_ws_sessions(None).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, sid);
        assert_eq!(sessions[0].message_count, 2);
        assert!(sessions[0].closed_at_ms.is_none());

        let msgs = store.list_ws_messages(sid).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, "out");
        assert_eq!(msgs[1].direction, "in");
        assert_eq!(msgs[0].opcode, 0x1);

        // Close and verify fields are set.
        sess.closed_at_ms = Some(42);
        sess.close_code = Some(1000);
        sess.close_reason = Some("ok".into());
        store.close_ws_session(sid, 42, Some(1000), Some("ok".into())).unwrap();

        let got = store.get_ws_session(sid).unwrap().unwrap();
        assert_eq!(got.closed_at_ms, Some(42));
        assert_eq!(got.close_code, Some(1000));
        assert_eq!(got.close_reason.as_deref(), Some("ok"));
    }

    #[test]
    fn time_range_filter_narrows_results() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Seed three transactions with manual ts values 100 / 200 / 300.
        for (p, ts) in [("/a", 100i64), ("/b", 200), ("/c", 300)] {
            let mut t = mkreq(p);
            t.request.created_at_ms = ts;
            let rb = ContentRef::from_bytes(&t.request.body);
            let xb = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
            store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        }
        // Baseline — no range filter returns all three.
        assert_eq!(
            store.list(&HistoryFilter::default()).unwrap().len(),
            3
        );
        // Window around the middle entry only — ts in [150, 250].
        let f = HistoryFilter {
            ts_min_ms: Some(150),
            ts_max_ms: Some(250),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/b");
        // Only lower bound — ts >= 250 drops /a and /b.
        let f = HistoryFilter {
            ts_min_ms: Some(250),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/c");
        // Only upper bound — ts <= 150 keeps only /a.
        let f = HistoryFilter {
            ts_max_ms: Some(150),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/a");
    }

    #[test]
    fn mime_classes_filter_ors_substrings() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Seed four txns with distinct response content-types. We
        // override the mkreq default by patching the response header
        // post-construction before the upsert reads it.
        for (path, ct) in [
            ("/a", "text/html; charset=utf-8"),
            ("/b", "application/json"),
            ("/c", "application/xml"),
            ("/d", "image/png"),
        ] {
            let mut t = mkreq(path);
            if let Some(resp) = t.response.as_mut() {
                resp.headers.set("Content-Type", ct);
            }
            let rb = ContentRef::from_bytes(&t.request.body);
            let xb = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
            store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        }
        // Baseline — four rows, no MIME filter.
        assert_eq!(store.list(&HistoryFilter::default()).unwrap().len(), 4);
        // HTML + JSON chips → /a and /b.
        let f = HistoryFilter {
            content_type_classes: Some(vec!["text/html".into(), "application/json".into()]),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        let paths: Vec<_> = rows.iter().map(|r| r.path.clone()).collect();
        assert_eq!(rows.len(), 2);
        assert!(paths.contains(&"/a".to_string()));
        assert!(paths.contains(&"/b".to_string()));
        // Image chip → /d only.
        let f = HistoryFilter {
            content_type_classes: Some(vec!["image/".into()]),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/d");
        // Empty vec is treated as "no chip row" so all four rows
        // survive — the UI's cleared-chips state must not nuke the
        // result set.
        let f = HistoryFilter {
            content_type_classes: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(store.list(&f).unwrap().len(), 4);
        // Whitespace-only entries are stripped before the OR clause
        // so a mis-typed chip never silently matches everything.
        let f = HistoryFilter {
            content_type_classes: Some(vec!["   ".into(), "application/xml".into()]),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/c");
        // Combined with status filter — AND behaviour. All four txns
        // are 200, so this still returns /a + /b.
        let f = HistoryFilter {
            content_type_classes: Some(vec!["text/html".into(), "application/json".into()]),
            status_min: Some(200),
            status_max: Some(299),
            ..Default::default()
        };
        assert_eq!(store.list(&f).unwrap().len(), 2);
        assert_eq!(store.count(&f).unwrap(), 2);
    }

    #[test]
    fn resp_size_filter_narrows_results() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Seed three transactions whose response bodies are 100 B
        // (small), 5 KB (mid), and 200 KB (large). `response_size`
        // is set from the resp_blob's byte count, so sizing the body
        // directly is all we need.
        for (p, size) in [("/small", 100usize), ("/mid", 5 * 1024), ("/large", 200 * 1024)] {
            let mut t = mkreq(p);
            let body = vec![b'A'; size];
            // Overwrite the mkreq default "<h1>hi</h1>" body.
            if let Some(resp) = t.response.as_mut() {
                resp.body = body.clone();
            }
            let rb = ContentRef::from_bytes(&t.request.body);
            let xb = ContentRef::from_bytes(&body);
            store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        }
        // Baseline — no size filter returns all three.
        assert_eq!(
            store.list(&HistoryFilter::default()).unwrap().len(),
            3
        );
        // Lower bound only — `>=1024` drops the 100 B row.
        let f = HistoryFilter {
            resp_size_min: Some(1024),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        let paths: Vec<_> = rows.iter().map(|r| r.path.clone()).collect();
        assert_eq!(rows.len(), 2);
        assert!(paths.contains(&"/mid".to_string()));
        assert!(paths.contains(&"/large".to_string()));
        // Upper bound only — `<=10_000` drops the 200 KB row.
        let f = HistoryFilter {
            resp_size_max: Some(10_000),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        let paths: Vec<_> = rows.iter().map(|r| r.path.clone()).collect();
        assert_eq!(rows.len(), 2);
        assert!(paths.contains(&"/small".to_string()));
        assert!(paths.contains(&"/mid".to_string()));
        // Combined window — mid-only slice [1 KB, 10 KB].
        let f = HistoryFilter {
            resp_size_min: Some(1024),
            resp_size_max: Some(10_000),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/mid");
        // count() tracks list() so the toolbar's "N of M" badge stays
        // honest under the same filter.
        assert_eq!(store.count(&f).unwrap(), 1);
    }

    /// `error_only=true` must keep only transactions whose `error`
    /// column is non-NULL. We seed three rows: an ordinary 200 OK,
    /// a connection-refused failure (no response), and a parse
    /// error that still carries a response (error can co-exist
    /// with a partial response, e.g. an upstream reset mid-body —
    /// the filter should keep it). Default filter returns all three;
    /// error_only=true returns the two with errors.
    #[test]
    fn error_only_filter_isolates_failed_transactions() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Row 1: happy path — no error.
        let t_ok = mkreq("/ok");
        let rb = ContentRef::from_bytes(&t_ok.request.body);
        let xb = ContentRef::from_bytes(&t_ok.response.as_ref().unwrap().body);
        store.upsert_transaction(&t_ok, &rb, Some(&xb)).unwrap();
        // Row 2: upstream connection refused — no response at all.
        let mut t_refused = mkreq("/refused");
        t_refused.response = None;
        t_refused.error = Some("connection refused by upstream".into());
        let rb = ContentRef::from_bytes(&t_refused.request.body);
        store.upsert_transaction(&t_refused, &rb, None).unwrap();
        // Row 3: partial response + parse error (headers finished but
        // body truncated by an upstream reset — the proxy still logs
        // the response bytes it got). Belongs in the error bucket.
        let mut t_partial = mkreq("/partial");
        t_partial.error = Some("upstream reset mid-body".into());
        let rb = ContentRef::from_bytes(&t_partial.request.body);
        let xb = ContentRef::from_bytes(&t_partial.response.as_ref().unwrap().body);
        store.upsert_transaction(&t_partial, &rb, Some(&xb)).unwrap();
        // Baseline — no filter returns all three.
        assert_eq!(store.list(&HistoryFilter::default()).unwrap().len(), 3);
        // Error-only flips the filter.
        let f = HistoryFilter {
            error_only: true,
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        let paths: Vec<_> = rows.iter().map(|r| r.path.clone()).collect();
        assert_eq!(rows.len(), 2);
        assert!(paths.contains(&"/refused".to_string()));
        assert!(paths.contains(&"/partial".to_string()));
        assert!(!paths.contains(&"/ok".to_string()));
        // count() tracks list() so the "N of M" badge stays honest.
        assert_eq!(store.count(&f).unwrap(), 2);
        // Combined with status filter — AND behaviour. The partial
        // row has status 200 (its response headers landed before the
        // reset); refused has no status. `status_min=200` keeps
        // partial, drops refused.
        let f = HistoryFilter {
            error_only: true,
            status_min: Some(200),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/partial");
    }

    /// Multi-select `status_classes` ORs 2xx + 4xx + 5xx into one
    /// result set so the operator can triage successes-plus-failures
    /// without the 3xx redirect noise. Plus the annotation filters
    /// (`highlighted_only` / `commented_only`) keep only tagged rows.
    /// We seed six rows spanning every class + a highlight + a
    /// comment and probe every chip combination.
    #[test]
    fn status_classes_and_annotation_filters() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Seed one row per status class (100 / 200 / 302 / 404 / 500)
        // plus a 200 with highlight + comment so the annotation
        // probes have something to pass through.
        for (p, status) in [
            ("/info", 100u16),
            ("/ok", 200),
            ("/redir", 302),
            ("/notfound", 404),
            ("/boom", 500),
        ] {
            let mut t = mkreq(p);
            if let Some(resp) = t.response.as_mut() {
                resp.status = status;
            }
            let rb = ContentRef::from_bytes(&t.request.body);
            let xb = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
            store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        }
        // Extra row with the annotations set: /tagged is 200,
        // commented "triage", highlighted red.
        let mut t = mkreq("/tagged");
        if let Some(resp) = t.response.as_mut() {
            resp.status = 200;
        }
        t.request.comment = "triage".into();
        let rb = ContentRef::from_bytes(&t.request.body);
        let xb = ContentRef::from_bytes(&t.response.as_ref().unwrap().body);
        store.upsert_transaction(&t, &rb, Some(&xb)).unwrap();
        // Grab the tagged row's id so we can paint the highlight.
        let tagged_id = store
            .list(&HistoryFilter::default())
            .unwrap()
            .iter()
            .find(|r| r.path == "/tagged")
            .expect("tagged row stored")
            .id;
        store.set_highlight(tagged_id, Some("red")).unwrap();
        // Baseline — 6 rows total.
        assert_eq!(store.list(&HistoryFilter::default()).unwrap().len(), 6);
        // Single chip: 4xx → /notfound only.
        let f = HistoryFilter {
            status_classes: Some(vec![4]),
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/notfound");
        // Two chips: 2xx + 5xx → /ok + /boom + /tagged (/tagged is 200).
        let f = HistoryFilter {
            status_classes: Some(vec![2, 5]),
            ..Default::default()
        };
        let paths: Vec<_> = store
            .list(&f)
            .unwrap()
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&"/ok".into()));
        assert!(paths.contains(&"/boom".into()));
        assert!(paths.contains(&"/tagged".into()));
        // Empty vec treated as "no filter" — all 6 rows.
        let f = HistoryFilter {
            status_classes: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(store.list(&f).unwrap().len(), 6);
        // Out-of-range digits are silently dropped — [0, 7, 42]
        // becomes [] which again means "no filter".
        let f = HistoryFilter {
            status_classes: Some(vec![0, 7, 42]),
            ..Default::default()
        };
        assert_eq!(store.list(&f).unwrap().len(), 6);
        // highlighted_only keeps only /tagged.
        let f = HistoryFilter {
            highlighted_only: true,
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/tagged");
        // commented_only also keeps only /tagged (same row got both).
        let f = HistoryFilter {
            commented_only: true,
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/tagged");
        // Combined: status_classes=[2] + commented_only → still /tagged
        // but not /ok (no comment). Confirms the ANDing.
        let f = HistoryFilter {
            status_classes: Some(vec![2]),
            commented_only: true,
            ..Default::default()
        };
        let rows = store.list(&f).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/tagged");
        // count() tracks list() under the composite filter.
        assert_eq!(store.count(&f).unwrap(), 1);
    }

    #[test]
    fn delete_findings_many_removes_only_targeted_ids() {
        let td = tempdir().unwrap();
        let store = HistoryStore::open(td.path().join("h.db")).unwrap();
        // Seed four findings with distinct fingerprints so the upsert
        // treats each as a new row.
        let ids: Vec<TrafficId> = (0..4)
            .map(|i| {
                let mut f = StoredFinding::default();
                f.id = TrafficId::new();
                f.detector = format!("det-{i}");
                f.title = format!("finding {i}");
                f.severity = "info".into();
                f.confidence = "firm".into();
                f.fingerprint = format!("fp-{i}");
                f.status = "new".into();
                f.verification = "unverified".into();
                let id = f.id;
                store.upsert_finding(&f).unwrap();
                id
            })
            .collect();
        let before = store.list_findings().unwrap();
        assert_eq!(before.len(), 4);
        // Delete the middle two.
        let targets = vec![ids[1], ids[2]];
        let removed = store.delete_findings_many(&targets).unwrap();
        assert_eq!(removed, 2);
        let after = store.list_findings().unwrap();
        assert_eq!(after.len(), 2);
        let remaining_ids: Vec<_> = after.iter().map(|f| f.id).collect();
        assert!(remaining_ids.contains(&ids[0]));
        assert!(remaining_ids.contains(&ids[3]));
        // Empty slice is a no-op (not an error).
        assert_eq!(store.delete_findings_many(&[]).unwrap(), 0);
    }
}


// --- Organizer -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizerItem {
    pub id: TrafficId,
    pub transaction_id: Option<TrafficId>,
    pub title: String,
    pub note: String,
    pub tags: Vec<String>,
    pub status: String,
    pub ts_ms: i64,
    pub updated_at_ms: i64,
    /// Which collection this item belongs to. `None` → the project's
    /// implicit "Inbox" (shown as the default pseudo-collection in the UI).
    #[serde(default)]
    pub collection_id: Option<i64>,
}

/// A named grouping of organizer items ("Collection" in Burp parlance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizerCollection {
    pub id: i64,
    pub name: String,
    pub created_at_ms: i64,
    /// Count of items currently in this collection (joined server-side so
    /// the UI stays snappy).
    #[serde(default)]
    pub item_count: i64,
}

impl HistoryStore {
    pub fn organizer_add(&self, item: &OrganizerItem) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT OR REPLACE INTO organizer
             (id, transaction_id, title, note, tags, status, ts_ms, updated_at_ms, collection_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                item.id.as_i64(),
                item.transaction_id.map(|t| t.as_i64()),
                item.title,
                item.note,
                serde_json::to_string(&item.tags)?,
                item.status,
                item.ts_ms,
                item.updated_at_ms,
                item.collection_id,
            ],
        )?;
        Ok(())
    }

    pub fn organizer_list(&self) -> Result<Vec<OrganizerItem>> {
        self.organizer_list_in_collection(None)
    }

    /// List items filtered by collection.
    /// * `Some(Some(id))` → items in that collection
    /// * `Some(None)`     → items in the implicit Inbox (null collection_id)
    /// * `None`           → every item regardless of collection
    pub fn organizer_list_in_collection(
        &self,
        collection: Option<Option<i64>>,
    ) -> Result<Vec<OrganizerItem>> {
        let conn = self.inner.lock();
        let mut sql = String::from(
            "SELECT id, transaction_id, title, note, tags, status, ts_ms, updated_at_ms, collection_id
             FROM organizer",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        match collection {
            None => {}
            Some(None) => {
                sql.push_str(" WHERE collection_id IS NULL");
            }
            Some(Some(id)) => {
                sql.push_str(" WHERE collection_id = ?1");
                args.push(Box::new(id));
            }
        }
        sql.push_str(" ORDER BY ts_ms DESC");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter().map(|b| &**b)), |r| {
                let tags_json: String = r.get(4)?;
                Ok(OrganizerItem {
                    id: TrafficId(r.get(0)?),
                    transaction_id: r.get::<_, Option<i64>>(1)?.map(TrafficId),
                    title: r.get(2)?,
                    note: r.get(3)?,
                    tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                    status: r.get(5)?,
                    ts_ms: r.get(6)?,
                    updated_at_ms: r.get(7)?,
                    collection_id: r.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn organizer_update_note(
        &self,
        id: TrafficId,
        note: &str,
        tags: &[String],
        status: &str,
    ) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE organizer SET note = ?1, tags = ?2, status = ?3, updated_at_ms = ?4 WHERE id = ?5",
            params![
                note,
                serde_json::to_string(tags)?,
                status,
                crate::blobs::now_ms_hint(),
                id.as_i64(),
            ],
        )?;
        Ok(())
    }

    pub fn organizer_move_to_collection(
        &self,
        id: TrafficId,
        collection_id: Option<i64>,
    ) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE organizer SET collection_id = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![collection_id, crate::blobs::now_ms_hint(), id.as_i64()],
        )?;
        Ok(())
    }

    pub fn organizer_delete(&self, id: TrafficId) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute("DELETE FROM organizer WHERE id = ?1", params![id.as_i64()])?;
        Ok(())
    }

    /// Create a named collection; returns the new `id`.
    pub fn collection_create(&self, name: &str) -> Result<i64> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO organizer_collections (name, created_at_ms) VALUES (?1, ?2)",
            params![name, crate::blobs::now_ms_hint()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn collection_rename(&self, id: i64, name: &str) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE organizer_collections SET name = ?1 WHERE id = ?2",
            params![name, id],
        )?;
        Ok(())
    }

    /// Delete a collection. Items in the collection are **not** removed —
    /// they are moved back to Inbox (collection_id NULL).
    pub fn collection_delete(&self, id: i64) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE organizer SET collection_id = NULL WHERE collection_id = ?1",
            params![id],
        )?;
        conn.execute(
            "DELETE FROM organizer_collections WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn collections_list(&self) -> Result<Vec<OrganizerCollection>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.name, c.created_at_ms,
                    (SELECT COUNT(*) FROM organizer o WHERE o.collection_id = c.id)
             FROM organizer_collections c
             ORDER BY c.name ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(OrganizerCollection {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created_at_ms: r.get(2)?,
                    item_count: r.get(3)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Count of items with no collection — the Inbox badge.
    pub fn collection_inbox_count(&self) -> Result<i64> {
        let conn = self.inner.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM organizer WHERE collection_id IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }
}
