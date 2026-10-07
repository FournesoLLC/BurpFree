//! HAR 1.2 (HTTP Archive) import + export.
//!
//! HAR is the universal interchange format produced by browser dev
//! tools (Chrome / Firefox / Safari) and automation tools (Playwright,
//! Puppeteer). Supporting it on both ends means practitioners can
//! walk into BurpFree with a HAR a developer gave them, and walk back
//! out with a HAR that opens cleanly in those same tools.
//!
//! The import side is deliberately tolerant — we accept unknown
//! fields (newer HAR extensions keep showing up) and fall back to
//! best-effort when fields are missing. On export we emit a
//! RFC-7234-friendly minimum: entries carry request + optional
//! response, with raw headers / body and timings pulled from history.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose;
use base64::Engine;
use burpfree_core::headers::Headers;
use burpfree_core::ids::{ContentRef, TrafficId};
use burpfree_core::traffic::{
    now_ms, HttpVersion, Request, RequestSource, Response, Transaction,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::blobs::BlobStore;
use crate::history::{HistoryFilter, HistoryStore};

/// Minimum HAR 1.2 subset we accept on import.
#[derive(Debug, Deserialize)]
struct HarDoc {
    #[serde(default)]
    log: HarLog,
}

#[derive(Debug, Default, Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    #[serde(default, rename = "startedDateTime")]
    started_date_time: Option<String>,
    #[serde(default)]
    time: Option<f64>,
    request: HarRequest,
    #[serde(default)]
    response: Option<HarResponse>,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    #[serde(default, rename = "httpVersion")]
    http_version: Option<String>,
    #[serde(default)]
    headers: Vec<NameValue>,
    #[serde(default, rename = "postData")]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarResponse {
    status: i64,
    #[serde(default, rename = "statusText")]
    status_text: Option<String>,
    #[serde(default, rename = "httpVersion")]
    http_version: Option<String>,
    #[serde(default)]
    headers: Vec<NameValue>,
    #[serde(default)]
    content: Option<HarContent>,
}

#[derive(Debug, Deserialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(default, rename = "mimeType")]
    mime_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    /// Some tools base64-encode binary bodies and signal via `encoding`.
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HarContent {
    #[serde(default)]
    size: Option<i64>,
    #[serde(default, rename = "mimeType")]
    mime_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarImportSummary {
    pub imported: usize,
    pub skipped: usize,
    /// First N skip reasons for the UI to surface; capped so a bad HAR
    /// can't DoS the response.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarExportSummary {
    pub entries: usize,
    pub bytes_written: u64,
}

/// Parse `path`, insert each entry as a `Transaction`, and reuse the
/// project's blob store for request + response bodies.
pub fn import_har(
    path: &Path,
    history: &HistoryStore,
    blobs: &BlobStore,
) -> Result<HarImportSummary> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let doc: HarDoc = serde_json::from_reader(reader).context("parse HAR JSON")?;
    import_har_doc(doc, history, blobs)
}

/// Parse raw bytes as HAR and import. Used by the Tauri command when
/// the frontend hands us the file contents directly (no disk round-trip).
pub fn import_har_bytes(
    bytes: &[u8],
    history: &HistoryStore,
    blobs: &BlobStore,
) -> Result<HarImportSummary> {
    let doc: HarDoc = serde_json::from_slice(bytes).context("parse HAR JSON")?;
    import_har_doc(doc, history, blobs)
}

fn import_har_doc(
    doc: HarDoc,
    history: &HistoryStore,
    blobs: &BlobStore,
) -> Result<HarImportSummary> {
    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    for (idx, entry) in doc.log.entries.into_iter().enumerate() {
        match har_entry_to_transaction(entry) {
            Ok((tx, req_bytes, resp_bytes)) => {
                let req_blob = blobs
                    .put(&req_bytes)
                    .with_context(|| format!("blobs.put request {idx}"))?;
                let resp_blob = resp_bytes
                    .map(|b| blobs.put(&b))
                    .transpose()
                    .with_context(|| format!("blobs.put response {idx}"))?;
                history
                    .upsert_transaction(&tx, &req_blob, resp_blob.as_ref())
                    .with_context(|| format!("upsert tx {idx}"))?;
                imported += 1;
            }
            Err(e) => {
                skipped += 1;
                if errors.len() < 10 {
                    errors.push(format!("entry {idx}: {e}"));
                }
            }
        }
    }
    Ok(HarImportSummary {
        imported,
        skipped,
        errors,
    })
}

fn har_entry_to_transaction(
    entry: HarEntry,
) -> Result<(Transaction, Vec<u8>, Option<Vec<u8>>)> {
    // --- request --------------------------------------------------------
    let url = Url::parse(&entry.request.url)
        .with_context(|| format!("parse url `{}`", entry.request.url))?;
    let scheme = url.scheme().to_string();
    if !matches!(scheme.as_str(), "http" | "https") {
        bail!("unsupported scheme `{scheme}`");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("url missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or_else(|| {
        if scheme == "https" {
            443
        } else {
            80
        }
    });
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    if path.is_empty() {
        path.push('/');
    }
    let http_version = parse_http_version(entry.request.http_version.as_deref());
    let mut headers = Headers::new();
    for h in entry.request.headers.iter() {
        if is_pseudo_header(&h.name) {
            continue;
        }
        headers.add(h.name.clone(), h.value.clone());
    }
    headers.set_if_missing("Host", host_header(&host, port, &scheme));
    let (req_body, req_mime) = decode_post_data(entry.request.post_data.as_ref());
    if let Some(mime) = req_mime.as_deref() {
        headers.set_if_missing("Content-Type", mime);
    }
    if !req_body.is_empty() && !headers.has("Content-Length") {
        headers.set("Content-Length", req_body.len().to_string());
    }
    let created_at_ms = entry
        .started_date_time
        .as_deref()
        .and_then(parse_iso8601_ms)
        .unwrap_or_else(now_ms);
    let request = Request {
        id: TrafficId::new(),
        method: entry.request.method.to_ascii_uppercase(),
        scheme,
        host,
        port,
        path,
        http_version,
        headers,
        body: req_body.clone(),
        created_at_ms,
        source: RequestSource::Manual,
        parent_id: None,
        annotation: "imported from HAR".into(),
        comment: String::new(),
    };

    // --- response -------------------------------------------------------
    let response = entry.response.map(|r| {
        let mut rh = Headers::new();
        for h in &r.headers {
            if is_pseudo_header(&h.name) {
                continue;
            }
            rh.add(h.name.clone(), h.value.clone());
        }
        let (resp_body, resp_mime) = decode_content(r.content.as_ref());
        if let Some(mime) = resp_mime {
            rh.set_if_missing("Content-Type", mime);
        }
        if !resp_body.is_empty() && !rh.has("Content-Length") {
            rh.set("Content-Length", resp_body.len().to_string());
        }
        Response {
            id: TrafficId::new(),
            status: r.status.clamp(0, 999) as u16,
            reason: r.status_text.unwrap_or_default(),
            http_version: parse_http_version(r.http_version.as_deref()),
            headers: rh,
            body: resp_body,
            created_at_ms,
            elapsed_ms: entry.time.map(|t| t.max(0.0) as u64).unwrap_or(0),
            original_body_size: None,
        }
    });

    let resp_body_opt = response.as_ref().map(|r| r.body.clone());
    let req_wire = request_wire_bytes(&request);

    let mut tx = Transaction::new(request);
    tx.response = response;
    Ok((tx, req_wire, resp_body_opt))
}

fn request_wire_bytes(r: &Request) -> Vec<u8> {
    // We store the request as its raw HTTP/1.1 wire representation so
    // downstream editors render it with the familiar method/path/CRLF
    // layout — matching how the live proxy stores inbound traffic.
    r.to_wire_bytes()
}

fn parse_http_version(s: Option<&str>) -> HttpVersion {
    match s.unwrap_or("HTTP/1.1").to_ascii_uppercase().as_str() {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/2" | "HTTP/2.0" | "H2" => HttpVersion::Http2,
        "HTTP/3" | "H3" => HttpVersion::Http3,
        _ => HttpVersion::Http11,
    }
}

/// HAR captured from HTTP/2 traffic will carry `:method` / `:scheme`
/// pseudo-headers; those are illegal in HTTP/1.1 and we already
/// synthesise the real `Host` header separately.
fn is_pseudo_header(name: &str) -> bool {
    name.starts_with(':')
}

fn parse_iso8601_ms(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).timestamp_millis())
}

fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    if default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn decode_post_data(pd: Option<&HarPostData>) -> (Vec<u8>, Option<String>) {
    let Some(pd) = pd else { return (Vec::new(), None) };
    let bytes = match (pd.encoding.as_deref(), pd.text.as_deref()) {
        (Some("base64"), Some(t)) => general_purpose::STANDARD
            .decode(t.trim())
            .unwrap_or_else(|_| t.as_bytes().to_vec()),
        (_, Some(t)) => t.as_bytes().to_vec(),
        _ => Vec::new(),
    };
    (bytes, pd.mime_type.clone())
}

fn decode_content(c: Option<&HarContent>) -> (Vec<u8>, Option<String>) {
    let Some(c) = c else { return (Vec::new(), None) };
    let bytes = match (c.encoding.as_deref(), c.text.as_deref()) {
        (Some("base64"), Some(t)) => general_purpose::STANDARD
            .decode(t.trim())
            .unwrap_or_else(|_| t.as_bytes().to_vec()),
        (_, Some(t)) => t.as_bytes().to_vec(),
        _ => Vec::new(),
    };
    (bytes, c.mime_type.clone())
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HarDocOut<'a> {
    log: HarLogOut<'a>,
}

#[derive(Serialize)]
struct HarLogOut<'a> {
    version: &'static str,
    creator: HarCreatorOut<'a>,
    entries: Vec<HarEntryOut>,
}

#[derive(Serialize)]
struct HarCreatorOut<'a> {
    name: &'a str,
    version: &'static str,
}

#[derive(Serialize)]
struct HarEntryOut {
    #[serde(rename = "startedDateTime")]
    started_date_time: String,
    time: u64,
    request: HarRequestOut,
    response: HarResponseOut,
    cache: EmptyObj,
    timings: HarTimingsOut,
}

#[derive(Serialize)]
struct HarRequestOut {
    method: String,
    url: String,
    #[serde(rename = "httpVersion")]
    http_version: String,
    headers: Vec<NameValueOut>,
    #[serde(rename = "queryString")]
    query_string: Vec<NameValueOut>,
    cookies: Vec<NameValueOut>,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    post_data: Option<HarPostDataOut>,
}

#[derive(Serialize)]
struct HarResponseOut {
    status: u16,
    #[serde(rename = "statusText")]
    status_text: String,
    #[serde(rename = "httpVersion")]
    http_version: String,
    cookies: Vec<NameValueOut>,
    headers: Vec<NameValueOut>,
    content: HarContentOut,
    #[serde(rename = "redirectURL")]
    redirect_url: String,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
}

#[derive(Serialize)]
struct HarContentOut {
    size: usize,
    #[serde(rename = "mimeType")]
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Serialize)]
struct HarPostDataOut {
    #[serde(rename = "mimeType")]
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Serialize)]
struct NameValueOut {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct HarTimingsOut {
    send: f64,
    wait: f64,
    receive: f64,
}

#[derive(Serialize, Default)]
struct EmptyObj {}

/// Serialise every history entry (optionally filtered) back into a
/// HAR 1.2 document. Request + response bodies are decoded from the
/// blob store and inlined into `postData.text` and `content.text`;
/// binary bodies are tagged with `encoding: "base64"` so Chrome / HAR
/// viewers decode them correctly.
/// Export a specific set of transactions by id. Mirrors
/// [`export_har`] but skips the generic `HistoryFilter` and pulls
/// each requested row via `get_summary` + its request / response
/// blobs. Preserves the order of `ids` so an operator's bulk
/// selection reads left-to-right in the output file. Silently skips
/// ids that don't resolve (deleted mid-export, race) rather than
/// erroring the whole export — the `entries` count on the summary
/// reflects how many actually landed.
pub fn export_har_by_ids(
    path: &Path,
    history: &HistoryStore,
    blobs: &BlobStore,
    ids: &[burpfree_core::ids::TrafficId],
) -> Result<HarExportSummary> {
    let mut rows: Vec<crate::history::StoredSummary> = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(row) = history.get_summary(*id)? {
            rows.push(row);
        }
    }
    let mut entries: Vec<HarEntryOut> = Vec::with_capacity(rows.len());
    for r in &rows {
        let Some(req_cr) = history.get_request_blob(r.id)? else {
            continue;
        };
        let req_bytes = blobs.get(&req_cr)?.unwrap_or_default();
        let resp_cr = history.get_response_blob(r.id)?;
        let resp_bytes = match resp_cr.as_ref() {
            Some(cr) => blobs.get(cr)?.unwrap_or_default(),
            None => Vec::new(),
        };
        entries.push(build_entry(r, &req_bytes, resp_bytes.as_slice(), resp_cr.as_ref()));
    }

    let doc = HarDocOut {
        log: HarLogOut {
            version: "1.2",
            creator: HarCreatorOut {
                name: "BurpFree",
                version: env!("CARGO_PKG_VERSION"),
            },
            entries,
        },
    };

    let bytes = serde_json::to_vec_pretty(&doc).context("serialize HAR")?;
    let mut file = BufWriter::new(
        File::create(path).with_context(|| format!("create {}", path.display()))?,
    );
    file.write_all(&bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.flush()?;
    Ok(HarExportSummary {
        entries: doc.log.entries.len(),
        bytes_written: bytes.len() as u64,
    })
}

pub fn export_har(
    path: &Path,
    history: &HistoryStore,
    blobs: &BlobStore,
    filter: Option<HistoryFilter>,
) -> Result<HarExportSummary> {
    let rows = history
        .list(&filter.unwrap_or_default())
        .context("history.list")?;
    let mut entries: Vec<HarEntryOut> = Vec::with_capacity(rows.len());
    for r in &rows {
        let Some(req_cr) = history.get_request_blob(r.id)? else {
            continue;
        };
        let req_bytes = blobs.get(&req_cr)?.unwrap_or_default();
        let resp_cr = history.get_response_blob(r.id)?;
        let resp_bytes = match resp_cr.as_ref() {
            Some(cr) => blobs.get(cr)?.unwrap_or_default(),
            None => Vec::new(),
        };
        entries.push(build_entry(r, &req_bytes, resp_bytes.as_slice(), resp_cr.as_ref()));
    }

    let doc = HarDocOut {
        log: HarLogOut {
            version: "1.2",
            creator: HarCreatorOut {
                name: "BurpFree",
                version: env!("CARGO_PKG_VERSION"),
            },
            entries,
        },
    };

    let bytes = serde_json::to_vec_pretty(&doc).context("serialize HAR")?;
    let mut file = BufWriter::new(
        File::create(path).with_context(|| format!("create {}", path.display()))?,
    );
    file.write_all(&bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.flush()?;
    Ok(HarExportSummary {
        entries: doc.log.entries.len(),
        bytes_written: bytes.len() as u64,
    })
}

fn build_entry(
    summary: &crate::history::StoredSummary,
    req_wire: &[u8],
    resp_body: &[u8],
    resp_cr: Option<&ContentRef>,
) -> HarEntryOut {
    // The stored request blob is a full HTTP/1.1 wire payload — we need
    // to split it into (headers, body) to produce the HAR structure.
    let (req_headers, req_body) = split_wire(req_wire);
    let header_map = parse_header_lines(&req_headers);

    let url = compose_url(summary);
    let query = url::Url::parse(&url)
        .ok()
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| NameValueOut {
                    name: k.into_owned(),
                    value: v.into_owned(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let cookies = header_map
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
        .flat_map(|(_, v)| {
            v.split(';').filter_map(|kv| {
                let kv = kv.trim();
                let (k, v) = kv.split_once('=')?;
                Some(NameValueOut {
                    name: k.trim().to_string(),
                    value: v.trim().to_string(),
                })
            })
        })
        .collect();

    let (post_data, body_size) = if req_body.is_empty() {
        (None, 0)
    } else {
        let ct = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let (text, encoding) = encode_body(&req_body);
        (
            Some(HarPostDataOut {
                mime_type: ct,
                text,
                encoding,
            }),
            req_body.len() as i64,
        )
    };

    let req_headers_vec: Vec<NameValueOut> = header_map
        .iter()
        .map(|(k, v)| NameValueOut {
            name: k.clone(),
            value: v.clone(),
        })
        .collect();

    // --- response --------------------------------------------------------
    let (text, encoding) = encode_body(resp_body);
    let content = HarContentOut {
        size: resp_cr.map(|c| c.size as usize).unwrap_or(resp_body.len()),
        mime_type: summary.content_type.clone().unwrap_or_default(),
        text,
        encoding,
    };

    HarEntryOut {
        started_date_time: epoch_ms_to_iso(summary.ts_ms),
        time: summary.elapsed_ms.unwrap_or(0),
        request: HarRequestOut {
            method: summary.method.clone(),
            url,
            http_version: "HTTP/1.1".into(),
            headers: req_headers_vec,
            query_string: query,
            cookies,
            headers_size: req_headers.len() as i64,
            body_size,
            post_data,
        },
        response: HarResponseOut {
            status: summary.status.unwrap_or(0),
            status_text: summary.content_type.as_deref().map(|_| "").unwrap_or("").to_string(),
            http_version: "HTTP/1.1".into(),
            cookies: Vec::new(),
            headers: Vec::new(),
            content,
            redirect_url: String::new(),
            headers_size: -1,
            body_size: resp_body.len() as i64,
        },
        cache: EmptyObj::default(),
        timings: HarTimingsOut {
            send: 0.0,
            wait: summary.elapsed_ms.map(|v| v as f64).unwrap_or(0.0),
            receive: 0.0,
        },
    }
}

fn compose_url(s: &crate::history::StoredSummary) -> String {
    let default = (s.scheme == "http" && s.port == 80) || (s.scheme == "https" && s.port == 443);
    let authority = if default {
        s.host.clone()
    } else {
        format!("{}:{}", s.host, s.port)
    };
    format!("{}://{}{}", s.scheme, authority, s.path)
}

fn split_wire(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Split on the first `\r\n\r\n`. If missing, treat whole buffer as
    // headers and leave the body empty.
    for i in 0..bytes.len().saturating_sub(3) {
        if &bytes[i..i + 4] == b"\r\n\r\n" {
            let (h, rest) = bytes.split_at(i);
            return (h.to_vec(), rest[4..].to_vec());
        }
    }
    (bytes.to_vec(), Vec::new())
}

fn parse_header_lines(header_bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(header_bytes);
    text.lines()
        .skip(1) // request line
        .filter_map(|l| {
            let l = l.trim_end_matches('\r');
            if l.is_empty() {
                return None;
            }
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn encode_body(body: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(body) {
        Ok(s) => (s.to_string(), None),
        Err(_) => (
            general_purpose::STANDARD.encode(body),
            Some("base64".into()),
        ),
    }
}

fn epoch_ms_to_iso(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::BlobStore;
    use crate::history::{HistoryFilter, HistoryStore};
    use tempfile::tempdir;

    fn fresh_project() -> (tempfile::TempDir, HistoryStore, BlobStore) {
        let td = tempdir().unwrap();
        let hist = HistoryStore::open(td.path().join("history.db")).unwrap();
        let blobs = BlobStore::open(td.path().join("blobs")).unwrap();
        (td, hist, blobs)
    }

    #[test]
    fn parses_minimal_har() {
        let (_td, hist, blobs) = fresh_project();
        let har = r#"{
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1"},
                "entries": [{
                    "startedDateTime": "2024-05-01T12:00:00.000Z",
                    "time": 123,
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users?limit=10",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "pytest/1.0"},
                            {"name": "Accept", "value": "application/json"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "content": {
                            "size": 15,
                            "mimeType": "application/json",
                            "text": "{\"count\": 10}"
                        }
                    }
                }]
            }
        }"#;
        let summary = import_har_bytes(har.as_bytes(), &hist, &blobs).unwrap();
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped, 0);
        let rows = hist.list(&HistoryFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "api.example.com");
        assert_eq!(rows[0].scheme, "https");
        assert_eq!(rows[0].path, "/users?limit=10");
        assert_eq!(rows[0].status, Some(200));
    }

    #[test]
    fn decodes_base64_body() {
        let (_td, hist, blobs) = fresh_project();
        let har = r#"{
            "log": {
                "entries": [{
                    "request": {"method": "GET", "url": "http://x.local/", "httpVersion": "HTTP/1.1"},
                    "response": {
                        "status": 200,
                        "content": {
                            "size": 3,
                            "mimeType": "application/octet-stream",
                            "text": "AAEC",
                            "encoding": "base64"
                        }
                    }
                }]
            }
        }"#;
        import_har_bytes(har.as_bytes(), &hist, &blobs).unwrap();
        let rows = hist.list(&HistoryFilter::default()).unwrap();
        let resp_cr = hist.get_response_blob(rows[0].id).unwrap().unwrap();
        let bytes = blobs.get(&resp_cr).unwrap().unwrap();
        assert_eq!(bytes, vec![0u8, 1, 2]);
    }

    #[test]
    fn skips_entry_with_bad_url() {
        let (_td, hist, blobs) = fresh_project();
        let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"not a url"}},
            {"request":{"method":"GET","url":"http://ok.local/"}}
        ]}}"#;
        let summary = import_har_bytes(har.as_bytes(), &hist, &blobs).unwrap();
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped, 1);
        assert!(summary.errors[0].contains("entry 0"));
    }

    #[test]
    fn pseudo_headers_dropped() {
        let (_td, hist, blobs) = fresh_project();
        let har = r#"{"log":{"entries":[{
            "request": {
                "method": "GET",
                "url": "https://x.local/",
                "httpVersion": "HTTP/2",
                "headers": [
                    {"name": ":method", "value": "GET"},
                    {"name": ":scheme", "value": "https"},
                    {"name": "x-custom", "value": "yes"}
                ]
            }
        }]}}"#;
        import_har_bytes(har.as_bytes(), &hist, &blobs).unwrap();
        let rows = hist.list(&HistoryFilter::default()).unwrap();
        let req_cr = hist.get_request_blob(rows[0].id).unwrap().unwrap();
        let wire = String::from_utf8(blobs.get(&req_cr).unwrap().unwrap()).unwrap();
        assert!(!wire.contains(":method"));
        assert!(wire.contains("x-custom: yes"));
    }

    #[test]
    fn round_trip_import_then_export() {
        let (_td, hist, blobs) = fresh_project();
        let har = r#"{
            "log": {
                "entries": [{
                    "startedDateTime": "2024-05-01T12:00:00.000Z",
                    "time": 42,
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/orders",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"mimeType": "application/json", "text": "{\"id\":1}"}
                    },
                    "response": {
                        "status": 201,
                        "statusText": "Created",
                        "content": {"size": 4, "mimeType": "text/plain", "text": "done"}
                    }
                }]
            }
        }"#;
        import_har_bytes(har.as_bytes(), &hist, &blobs).unwrap();
        let out = _td.path().join("round-trip.har");
        let summary = export_har(&out, &hist, &blobs, None).unwrap();
        assert_eq!(summary.entries, 1);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("api.example.com"));
        assert!(text.contains("\"method\": \"POST\""));
        assert!(text.contains("\"status\": 201"));
        assert!(text.contains("\"text\": \"done\""));
    }

    #[test]
    fn export_tags_binary_body_as_base64() {
        let (_td, hist, blobs) = fresh_project();
        // Store a transaction with a binary response body (non-UTF-8 bytes).
        let req = Request::new("GET", "http://x.local/bin").unwrap();
        let mut resp = Response::new(200);
        resp.body = vec![0xff, 0x00, 0xfe];
        let mut tx = Transaction::new(req);
        tx.response = Some(resp);
        let req_cr = blobs.put(&tx.request.to_wire_bytes()).unwrap();
        let resp_cr = blobs.put(&tx.response.as_ref().unwrap().body).unwrap();
        hist.upsert_transaction(&tx, &req_cr, Some(&resp_cr)).unwrap();
        let out = _td.path().join("binary.har");
        export_har(&out, &hist, &blobs, None).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("\"encoding\": \"base64\""), "{text}");
    }
}
