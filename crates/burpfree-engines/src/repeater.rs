//! Repeater: named tabs that keep an editable request plus a send
//! history of its responses. Persisted to `project/repeater.json`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use burpfree_core::ids::TrafficId;
use burpfree_core::traffic::{Request, RequestSource, Response, Transaction};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::client::HttpClient;

/// Options for the Repeater "body encoding" toggle. Mirrors the three
/// common transports the operator switches between while probing a
/// target: plain bytes, gzip-compressed, and HTTP/1.1 chunked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    Plain,
    Gzip,
    Chunked,
}

/// Return the current template's body in its decoded (plain-bytes)
/// form, undoing any gzip wrapping or chunked framing that was last
/// applied. Public so the Tauri layer can preview the plain body
/// without having to flip encodings.
pub fn decode_body_to_plain(req: &Request) -> anyhow::Result<Vec<u8>> {
    use burpfree_codec::compression::{maybe_decompress, DecodeLimit};
    let is_chunked = req
        .headers
        .get("Transfer-Encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false);
    let bytes = if is_chunked {
        decode_chunked(&req.body)?
    } else {
        req.body.clone()
    };
    let ce = req.headers.get("Content-Encoding").map(|s| s.to_string());
    let plain = if let Some(enc) = ce.as_deref() {
        let limit = DecodeLimit {
            ratio: 100,
            floor: 1 << 20,
            ceiling: 128 << 20,
        };
        maybe_decompress(Some(enc), &bytes, limit).unwrap_or(bytes)
    } else {
        bytes
    };
    Ok(plain)
}

/// Minimal HTTP/1.1 chunked encoder: one chunk carrying the whole
/// body, then the zero-length terminator.
fn encode_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    if !data.is_empty() {
        out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn decode_chunked(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        // Read hex length until \r\n.
        let mut j = i;
        while j + 1 < data.len() && !(data[j] == b'\r' && data[j + 1] == b'\n') {
            j += 1;
        }
        if j + 1 >= data.len() {
            anyhow::bail!("truncated chunked body: missing CRLF after length");
        }
        let hex = std::str::from_utf8(&data[i..j])
            .map_err(|e| anyhow::anyhow!("non-UTF8 chunk length: {e}"))?
            .trim();
        // Chunk extensions after ';' are ignored.
        let hex = hex.split(';').next().unwrap_or("").trim();
        let n = usize::from_str_radix(hex, 16)
            .map_err(|e| anyhow::anyhow!("bad chunk length `{hex}`: {e}"))?;
        i = j + 2;
        if n == 0 {
            break;
        }
        if i + n > data.len() {
            anyhow::bail!("chunk length overruns buffer");
        }
        out.extend_from_slice(&data[i..i + n]);
        i += n;
        if i + 1 < data.len() && data[i] == b'\r' && data[i + 1] == b'\n' {
            i += 2;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterSend {
    pub id: TrafficId,
    pub request: Request,
    pub response: Option<Response>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: TrafficId,
    /// Source transaction id when the tab was created via
    /// `Send to Repeater` from HTTP history or a Proxy intercept.
    /// `None` for tabs created blank via `repeater_add_tab`. The
    /// frontend uses this to surface a "Jump to parent in HTTP
    /// history" button so operators can trace a Repeater tab back
    /// to the original observation. `#[serde(default)]` keeps the
    /// repeater.json schema backward-compatible with pre-R99 saves.
    #[serde(default)]
    pub source_tx_id: Option<TrafficId>,
    pub name: String,
    pub template: Request,
    #[serde(default)]
    pub history: Vec<RepeaterSend>,
    #[serde(default)]
    pub comment: String,
    /// Optional CSS colour string (`#rrggbb` or named CSS colour)
    /// rendered as a pip next to the tab label. Lets the operator
    /// group related tabs visually (red for high-impact probes, green
    /// for working requests, etc.).
    #[serde(default)]
    pub color: Option<String>,
    /// Per-tab override of the client's redirect policy. `None`
    /// defers to the globally-configured policy (which is `Never`
    /// by default so Repeater sends get the raw 3xx response). The
    /// UI exposes a dropdown to flip this per tab.
    #[serde(default)]
    pub follow_redirects: Option<burpfree_core::net::FollowRedirectPolicy>,
    /// Optional group label. Tabs sharing the same group label render
    /// clustered under a group header in the UI, and can be fired as
    /// a batch via `send_group_sequential` / `send_group_parallel`.
    /// `None` means the tab is ungrouped.
    #[serde(default)]
    pub group: Option<String>,
    /// Explicit display order inside the Repeater tab bar. Burp lets
    /// operators drag tabs to reorder them; we persist that ordering
    /// here. `list_tabs()` sorts by `(order, id)` so the natural
    /// creation sequence survives when the operator hasn't dragged
    /// anything. New tabs are assigned the current max-order + 1000
    /// at `add_tab` time so they always land at the end of the bar.
    #[serde(default)]
    pub order: i64,
    /// Pinned flag — Burp's "Pin tab" protects a probing tab from
    /// bulk closes. `list_tabs()` floats pinned tabs ahead of
    /// unpinned ones within the same group; the UI renders a 📌
    /// icon and the context menu "Close other / to the right"
    /// skip pinned victims entirely.
    #[serde(default)]
    pub pinned: bool,
}

impl RepeaterTab {
    pub fn new(name: impl Into<String>, template: Request) -> Self {
        Self {
            id: TrafficId::new(),
            source_tx_id: None,
            name: name.into(),
            template,
            history: Vec::new(),
            comment: String::new(),
            color: None,
            follow_redirects: None,
            group: None,
            order: 0,
            pinned: false,
        }
    }

    /// Stamp the source transaction id for traceback. Returns `self`
    /// so the Tauri cmds can one-liner the setter during tab
    /// construction without a separate statement.
    pub fn with_source_tx(mut self, tx_id: TrafficId) -> Self {
        self.source_tx_id = Some(tx_id);
        self
    }
}

/// Hard cap on the number of `RepeaterSend` entries kept per tab.
/// Burp's Repeater also tracks every send, but the UI collapses old
/// ones; we trim at the backend so a long probing session can't
/// balloon memory + the on-disk `repeater.json`. 500 entries ≈ a few
/// MB per tab even with 10 KB bodies — enough for an operator's
/// day's worth of probes, cheap enough the trim is invisible.
pub const MAX_HISTORY_PER_TAB: usize = 500;

/// Drop the oldest sends when `h.len()` exceeds `MAX_HISTORY_PER_TAB`.
/// Called immediately after every `history.push(send)` on the Repeater
/// so the Vec never grows past the cap. `drain(0..n)` keeps the most
/// recent entries at the tail (the natural order the UI expects —
/// `history[history.len() - 1]` is still the latest send).
fn trim_history(h: &mut Vec<RepeaterSend>) {
    if h.len() > MAX_HISTORY_PER_TAB {
        let drop = h.len() - MAX_HISTORY_PER_TAB;
        h.drain(0..drop);
    }
}

#[derive(Debug, Clone)]
pub struct Repeater {
    tabs: Arc<RwLock<BTreeMap<TrafficId, RepeaterTab>>>,
    disk: Option<PathBuf>,
    client: HttpClient,
    /// Per-tab cancel channel. Each call to `send()` /
    /// `follow_redirect()` registers its own [`Notify`] here and
    /// selects on `notify.notified()` alongside the HTTP future, so
    /// `cancel(id)` can drop the in-flight request immediately by
    /// waking the parked branch. Cleaned up on completion via
    /// `Arc::ptr_eq` so overlapping sends on the same tab don't
    /// double-remove each other's slot.
    inflight: Arc<RwLock<HashMap<TrafficId, Arc<Notify>>>>,
}

impl Repeater {
    pub fn new(client: HttpClient) -> Self {
        Self {
            tabs: Arc::new(RwLock::new(BTreeMap::new())),
            disk: None,
            client,
            inflight: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn load_or_new(path: &Path, client: HttpClient) -> Result<Self> {
        let tabs: BTreeMap<TrafficId, RepeaterTab> = if path.exists() {
            let data = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Default::default()
        };
        Ok(Self {
            tabs: Arc::new(RwLock::new(tabs)),
            disk: Some(path.to_path_buf()),
            client,
            inflight: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Hand out a clone of the underlying HTTP client. Lets callers
    /// outside the Repeater (e.g. the Tauri `history_replay` cmd)
    /// fire a one-shot request through the same stack — same
    /// upstream proxy, host overrides, follow-redirect policy — that
    /// a Repeater tab would use, without having to go through the
    /// tab machinery. `HttpClient` is `Clone` (an `Arc` under the
    /// hood) so this is cheap.
    pub fn http_client(&self) -> HttpClient {
        self.client.clone()
    }

    /// Cancel the in-flight `send()` / `follow_redirect()` for the
    /// given tab, if any. Returns `true` when a cancel signal was
    /// delivered (i.e. the tab had at least one awaiter parked on its
    /// Notify), `false` when nothing was in flight. Burp's Repeater
    /// "Cancel" button maps directly to this call.
    pub fn cancel(&self, id: TrafficId) -> bool {
        let g = self.inflight.read();
        match g.get(&id) {
            Some(n) => {
                // `notify_waiters` wakes every parked `.notified()`
                // future at once (vs `notify_one`'s single-waiter +
                // permit store) which matches our "stop everything on
                // this tab" semantics.
                n.notify_waiters();
                true
            }
            None => false,
        }
    }

    /// Fire a cancel at every in-flight send across every tab.
    /// Returns the number of tabs that were mid-flight. Each inner
    /// `Notify` is woken via `notify_waiters()` so parallel sends on
    /// the same tab all unpark together, matching the single-tab
    /// `cancel()` semantics. Useful as a panic button after a
    /// `send_group_parallel` fan-out starts starving the target.
    pub fn cancel_all(&self) -> usize {
        let g = self.inflight.read();
        for n in g.values() {
            n.notify_waiters();
        }
        g.len()
    }

    /// Snapshot of every tab currently mid-flight. The UI calls this
    /// on reconnect / panel re-mount so the Cancel buttons re-highlight
    /// without waiting for a status poll — the Set returned by
    /// `useState` only tracks sends started this session, which is
    /// empty if the panel just mounted mid-attack.
    pub fn inflight_ids(&self) -> Vec<TrafficId> {
        self.inflight.read().keys().copied().collect()
    }

    pub fn add_tab(&self, mut tab: RepeaterTab) -> TrafficId {
        tab.template.source = RequestSource::Repeater;
        let id = tab.id;
        let mut tabs = self.tabs.write();
        // Only overwrite order when the caller left it at the default
        // (0). This lets `clone_tab` (and future callers) hand us a
        // specific slot — e.g. "right after the source tab".
        if tab.order == 0 {
            let max_order = tabs.values().map(|t| t.order).max().unwrap_or(0);
            tab.order = max_order + 1000;
        }
        tabs.insert(id, tab);
        drop(tabs);
        self.save();
        id
    }

    /// Clone an existing tab into a new one. Preserves the template,
    /// colour pip, follow-redirect policy, and comment so a
    /// Burp-style "Duplicate tab" lands the operator somewhere that
    /// *looks* like the source. History is intentionally dropped so
    /// the copy starts clean.
    pub fn clone_tab(&self, id: TrafficId, new_name: Option<String>) -> Option<TrafficId> {
        let mut tabs = self.tabs.write();
        let orig = tabs.get(&id)?.clone();
        let name = new_name.unwrap_or_else(|| format!("{} (copy)", orig.name));
        let mut copy = RepeaterTab::new(name, orig.template.clone());
        copy.color = orig.color.clone();
        copy.follow_redirects = orig.follow_redirects;
        copy.comment = orig.comment.clone();
        copy.group = orig.group.clone();
        // Place the clone immediately after the source so the UI
        // doesn't send the duplicate to the far right of the bar.
        copy.order = orig.order + 500;
        // Pinning intent transfers so an operator who pinned the
        // source tab for safety doesn't lose that on duplicate.
        copy.pinned = orig.pinned;
        copy.history.clear();
        let new_id = copy.id;
        tabs.insert(new_id, copy);
        drop(tabs);
        self.save();
        Some(new_id)
    }

    pub fn remove_tab(&self, id: TrafficId) -> bool {
        let r = self.tabs.write().remove(&id).is_some();
        if r {
            self.save();
        }
        r
    }

    pub fn list_tabs(&self) -> Vec<RepeaterTab> {
        let mut out: Vec<RepeaterTab> = self.tabs.read().values().cloned().collect();
        // Sort key: `(!pinned, order, id)` so pinned tabs float left
        // of unpinned peers (Ord treats `false < true`, negation
        // flips so pinned=true sorts first). `order` + `id` keep
        // ties deterministic across restarts.
        out.sort_by(|a, b| {
            (!a.pinned)
                .cmp(&!b.pinned)
                .then_with(|| a.order.cmp(&b.order))
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }

    /// Flip the tab's pinned flag. Returns `true` on success,
    /// `false` when the id doesn't match. Mirrors Burp's "Pin tab" /
    /// "Unpin tab" context-menu entry.
    pub fn set_pinned(&self, id: TrafficId, pinned: bool) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                if t.pinned == pinned {
                    return true;
                }
                t.pinned = pinned;
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Reorder tabs: walks `ids` in order and assigns each known tab
    /// a fresh `order` value `(i+1)*1000`. Tabs whose id isn't in
    /// `ids` keep their existing order, which lets the UI reorder a
    /// subset (e.g. just one group's tabs) without flattening every
    /// unrelated tab. Returns how many tabs were updated.
    pub fn reorder_tabs(&self, ids: &[TrafficId]) -> usize {
        let mut tabs = self.tabs.write();
        let mut changed = 0usize;
        for (i, id) in ids.iter().enumerate() {
            if let Some(t) = tabs.get_mut(id) {
                let new_order = ((i + 1) as i64) * 1000;
                if t.order != new_order {
                    t.order = new_order;
                    changed += 1;
                }
            }
        }
        drop(tabs);
        if changed > 0 {
            self.save();
        }
        changed
    }

    pub fn get_tab(&self, id: TrafficId) -> Option<RepeaterTab> {
        self.tabs.read().get(&id).cloned()
    }

    pub fn update_template(&self, id: TrafficId, template: Request) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.template = template;
                t.template.source = RequestSource::Repeater;
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Replace the tab's free-form comment. Empty strings clear the
    /// comment. Returns true if the tab existed. Burp's Repeater
    /// shows the comment on the tab chip + in the detail viewer;
    /// we reserve it for a chip tooltip + a 💬 indicator glyph.
    pub fn set_comment(&self, id: TrafficId, comment: impl Into<String>) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.comment = comment.into();
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    pub fn rename(&self, id: TrafficId, name: impl Into<String>) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.name = name.into();
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Set / clear the tab's colour pip. Pass `None` to clear.
    pub fn set_color(&self, id: TrafficId, color: Option<String>) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.color = color.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Set / clear the per-tab redirect policy override. Pass `None`
    /// to fall back to the client's configured policy on the next
    /// send.
    pub fn set_follow_redirects(
        &self,
        id: TrafficId,
        policy: Option<burpfree_core::net::FollowRedirectPolicy>,
    ) -> bool {
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.follow_redirects = policy;
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Set / clear the tab's group label. Blank or all-whitespace
    /// strings clear the grouping (treated as `None`). Burp's
    /// "Add to group" / "Remove from group" context-menu action maps
    /// one-to-one to this call.
    pub fn set_group(&self, id: TrafficId, group: Option<String>) -> bool {
        let normalized = group
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.group = normalized;
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Rename every tab currently in `old` to be in `new`. Used by
    /// the group-header "Rename group" context-menu action so the
    /// operator can retitle a whole swarm without touching individual
    /// tabs. Returns the number of tabs updated. If `new` is blank
    /// the group is effectively cleared on each member.
    pub fn rename_group(&self, old: &str, new: &str) -> usize {
        let new_normalized = new.trim();
        let new_opt = if new_normalized.is_empty() {
            None
        } else {
            Some(new_normalized.to_string())
        };
        let mut tabs = self.tabs.write();
        let mut changed = 0usize;
        for t in tabs.values_mut() {
            if t.group.as_deref() == Some(old) {
                t.group = new_opt.clone();
                changed += 1;
            }
        }
        drop(tabs);
        if changed > 0 {
            self.save();
        }
        changed
    }

    /// Clear the group on every member of `group`. The tabs
    /// themselves are not deleted — Burp operators expect
    /// "Delete group" to free the tabs, not destroy them. Returns
    /// the number of tabs touched.
    pub fn delete_group(&self, group: &str) -> usize {
        self.rename_group(group, "")
    }

    /// Return every unique group label currently assigned to any
    /// tab, sorted lexicographically. Used by the frontend's
    /// "Add to existing group" submenu.
    pub fn list_groups(&self) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for t in self.tabs.read().values() {
            if let Some(g) = &t.group {
                set.insert(g.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Error placeholder for group batch sends. We can't synthesize
    /// a real `Request` without a URL, and the tab the send was
    /// targeting may no longer exist by the time the error surfaces,
    /// so we return a minimal error-only RepeaterSend record whose
    /// `request` is a well-formed sentinel.
    fn error_send(err: String) -> RepeaterSend {
        let request = Request::new("GET", "http://invalid.local/")
            .expect("sentinel URL always parses");
        RepeaterSend {
            id: request.id,
            request,
            response: None,
            error: Some(err),
            elapsed_ms: 0,
            ts_ms: burpfree_core::traffic::now_ms(),
        }
    }

    /// Fire every tab in `group` sequentially: await send N, then
    /// send N+1. Returns the ordered list of sends in the order the
    /// tabs appear in the Repeater's BTreeMap (insertion order
    /// stable by `TrafficId`). Each send is appended to its tab's
    /// own history, matching the shape of `send()`.
    pub async fn send_group_sequential(&self, group: &str) -> Vec<RepeaterSend> {
        let ids: Vec<TrafficId> = self
            .tabs
            .read()
            .values()
            .filter(|t| t.group.as_deref() == Some(group))
            .map(|t| t.id)
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            match self.send(id).await {
                Ok(s) => out.push(s),
                Err(e) => out.push(Self::error_send(e.to_string())),
            }
        }
        out
    }

    /// Fire every tab in `group` in parallel via `tokio::spawn`,
    /// then join and return results in completion order. Each send
    /// is appended to its tab's history by the shared `send()`
    /// implementation, so the UI picks them up normally. `Repeater`
    /// is already `Clone` via internal `Arc`s, so each spawned task
    /// gets its own cheap handle.
    pub async fn send_group_parallel(&self, group: &str) -> Vec<RepeaterSend> {
        let ids: Vec<TrafficId> = self
            .tabs
            .read()
            .values()
            .filter(|t| t.group.as_deref() == Some(group))
            .map(|t| t.id)
            .collect();
        let mut handles = Vec::with_capacity(ids.len());
        for id in ids {
            let this = self.clone();
            handles.push(tokio::spawn(async move { this.send(id).await }));
        }
        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            match h.await {
                Ok(Ok(s)) => out.push(s),
                Ok(Err(e)) => out.push(Self::error_send(e.to_string())),
                Err(e) => out.push(Self::error_send(format!("join error: {e}"))),
            }
        }
        out
    }

    /// Toggle the current request-body encoding on the fly. The
    /// operator picks one of `plain | gzip | chunked`; this method
    /// (de-)compresses or re-frames the body and rewires the
    /// `Content-Length`, `Content-Encoding`, and `Transfer-Encoding`
    /// headers so the resulting request stays wire-correct.
    ///
    /// When the body is already in the requested encoding we leave
    /// the headers alone and return `true` — the UI treats this as a
    /// no-op success. If the body is gzip-encoded and the operator
    /// flips back to `plain`, we transparently decompress.
    pub fn set_body_encoding(&self, id: TrafficId, kind: BodyEncoding) -> anyhow::Result<bool> {
        let mut tabs = self.tabs.write();
        let Some(t) = tabs.get_mut(&id) else { return Ok(false) };

        // Decode any current wrapping into a plain byte stream first,
        // so switching e.g. gzip → chunked goes via a clean body.
        let plain = decode_body_to_plain(&t.template)?;

        match kind {
            BodyEncoding::Plain => {
                t.template.body = plain.clone();
                t.template.headers.remove("Content-Encoding");
                t.template.headers.remove("Transfer-Encoding");
                if plain.is_empty() {
                    t.template.headers.remove("Content-Length");
                } else {
                    t.template
                        .headers
                        .set("Content-Length", plain.len().to_string());
                }
            }
            BodyEncoding::Gzip => {
                let gzipped = burpfree_codec::compression::encode_gzip(&plain)?;
                t.template.body = gzipped.clone();
                t.template.headers.set("Content-Encoding", "gzip");
                t.template.headers.remove("Transfer-Encoding");
                t.template
                    .headers
                    .set("Content-Length", gzipped.len().to_string());
            }
            BodyEncoding::Chunked => {
                let chunked = encode_chunked(&plain);
                t.template.body = chunked;
                t.template.headers.set("Transfer-Encoding", "chunked");
                // The body has been decompressed back to plain bytes
                // first, so any previous Content-Encoding is stale.
                t.template.headers.remove("Content-Encoding");
                // Chunked framing is self-describing; CL is forbidden.
                t.template.headers.remove("Content-Length");
            }
        }
        drop(tabs);
        self.save();
        Ok(true)
    }

    /// Rewrite the target URL on the tab's template request in one
    /// atomic update. Updates `template.scheme/host/port/path` from
    /// the parsed URL and realigns the `Host` header so the wire
    /// representation stays coherent. Everything else — method /
    /// other headers / body / http_version — is preserved so the
    /// operator can retarget an existing recipe at a new endpoint
    /// without losing their edits.
    ///
    /// Errors if `url` doesn't parse as an absolute `http(s)://…`
    /// URL. On error the tab is left untouched.
    pub fn set_url(&self, id: TrafficId, url: &str) -> Result<bool> {
        use url::Url;
        let u = Url::parse(url.trim())
            .map_err(|e| anyhow::anyhow!("bad url: {e}"))?;
        let scheme = u.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(anyhow::anyhow!("scheme must be http or https"));
        }
        let host = u
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("url has no host"))?
            .to_string();
        let port = u.port_or_known_default().unwrap_or(80);
        let mut path = u.path().to_string();
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        if path.is_empty() {
            path.push('/');
        }
        // Match the Request::new / host_header convention: include the port
        // only when it isn't the scheme's default.
        let default_port =
            (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
        let host_hdr = if default_port {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut tabs = self.tabs.write();
        let Some(t) = tabs.get_mut(&id) else { return Ok(false) };
        t.template.scheme = scheme;
        t.template.host = host;
        t.template.port = port;
        t.template.path = path;
        t.template.headers.set("Host", host_hdr);
        drop(tabs);
        self.save();
        Ok(true)
    }

    /// Swap the HTTP method on the tab's template request.
    ///
    /// Preserves everything else — URL / headers / body — so the
    /// operator can flip GET → POST (or any other verb) and keep
    /// hammering the same endpoint. Content-Length is left on the
    /// request as-is since the body hasn't changed; downstream HTTP
    /// clients re-serialize it correctly.
    pub fn change_method(&self, id: TrafficId, method: &str) -> bool {
        let m = method.trim();
        if m.is_empty() {
            return false;
        }
        let mut tabs = self.tabs.write();
        match tabs.get_mut(&id) {
            Some(t) => {
                t.template.method = m.to_ascii_uppercase();
                drop(tabs);
                self.save();
                true
            }
            None => false,
        }
    }

    /// Send the current template `count` times with `gap_ms` between
    /// successive sends. Returns the list of per-send results in
    /// chronological order; each send is also appended to the tab's
    /// history, so the normal response-viewer picks them up as well.
    ///
    /// `count` is clamped to `[1, 500]` and `gap_ms` to `[0, 60_000]`
    /// so a stray click can't flood the target or starve the UI loop.
    pub async fn burst_send(
        &self,
        id: TrafficId,
        count: u32,
        gap_ms: u64,
    ) -> Result<Vec<RepeaterSend>> {
        let count = count.clamp(1, 500) as usize;
        let gap_ms = gap_ms.min(60_000);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            if i > 0 && gap_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(gap_ms)).await;
            }
            // Reuse the single-shot path so each burst entry is
            // recorded with the exact same semantics (history append,
            // save-to-disk, elapsed timing).
            let send = self.send(id).await?;
            out.push(send);
        }
        Ok(out)
    }

    /// One-shot: resolve `location` against the tab's current URL and
    /// fire a single send against the resolved target. The tab's
    /// template stays untouched — a subsequent regular `send` still
    /// goes to the original URL. Useful for "follow this redirect"
    /// UX where the operator wants to trace a redirect chain by hand
    /// without rewriting their request.
    ///
    /// The resolver handles both absolute (`https://host/path`) and
    /// relative (`/new-path`, `../other`) Location values via
    /// `url::Url::join`.
    pub async fn follow_redirect(
        &self,
        id: TrafficId,
        location: &str,
    ) -> Result<RepeaterSend> {
        use url::Url;
        let (template, policy) = {
            let tabs = self.tabs.read();
            let t = tabs.get(&id).ok_or_else(|| anyhow::anyhow!("tab not found"))?;
            (t.template.clone(), t.follow_redirects)
        };
        let base = Url::parse(&template.url())
            .map_err(|e| anyhow::anyhow!("bad base url: {e}"))?;
        let resolved = base
            .join(location.trim())
            .map_err(|e| anyhow::anyhow!("bad location: {e}"))?;
        let scheme = resolved.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(anyhow::anyhow!("redirect scheme must be http(s)"));
        }
        let host = resolved
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("redirect has no host"))?
            .to_string();
        let port = resolved.port_or_known_default().unwrap_or(80);
        let mut path = resolved.path().to_string();
        if let Some(q) = resolved.query() {
            path.push('?');
            path.push_str(q);
        }
        if path.is_empty() {
            path.push('/');
        }
        let default_port =
            (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
        let host_hdr = if default_port {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        // Build the one-shot request from the template so headers +
        // body ride along. Swap in the redirect target before dialing.
        let mut request = template.clone_with_new_id(RequestSource::Repeater);
        request.scheme = scheme;
        request.host = host;
        request.port = port;
        request.path = path;
        request.headers.set("Host", host_hdr);
        let notify = self.register_inflight(id);
        let started = Instant::now();
        let (response, error) = {
            let fut = self.client.send_with_policy(&request, policy);
            tokio::select! {
                r = fut => match r {
                    Ok(r) => (Some(r), None),
                    Err(e) => (None, Some(e.to_string())),
                },
                _ = notify.notified() => (None, Some("send cancelled".to_string())),
            }
        };
        self.clear_inflight(id, &notify);
        let send = RepeaterSend {
            id: request.id,
            request,
            response,
            error,
            elapsed_ms: started.elapsed().as_millis() as u64,
            ts_ms: burpfree_core::traffic::now_ms(),
        };
        {
            let mut tabs = self.tabs.write();
            if let Some(t) = tabs.get_mut(&id) {
                t.history.push(send.clone());
                trim_history(&mut t.history);
            }
        }
        self.save();
        Ok(send)
    }

    /// Send the current template; append the result to the tab's history.
    ///
    /// Cancellable: the in-flight HTTP future is raced against a
    /// per-tab [`Notify`] registered in `self.inflight`. If
    /// [`Repeater::cancel`] fires while the request is pending, the
    /// client future is dropped (which closes the socket) and the
    /// returned [`RepeaterSend`] carries `error = Some("send cancelled")`
    /// so callers see a normal history row instead of a propagated Rust
    /// error. Overlapping sends on the same tab each register their own
    /// Notify; cleanup uses `Arc::ptr_eq` so only the slot we own gets
    /// removed when we complete.
    pub async fn send(&self, id: TrafficId) -> Result<RepeaterSend> {
        let (template, policy) = {
            let tabs = self.tabs.read();
            let t = tabs.get(&id).ok_or_else(|| anyhow::anyhow!("tab not found"))?;
            (t.template.clone(), t.follow_redirects)
        };
        let request = template.clone_with_new_id(RequestSource::Repeater);
        let notify = self.register_inflight(id);
        let started = Instant::now();
        let (response, error) = {
            let fut = self.client.send_with_policy(&request, policy);
            tokio::select! {
                r = fut => match r {
                    Ok(r) => (Some(r), None),
                    Err(e) => (None, Some(e.to_string())),
                },
                _ = notify.notified() => (None, Some("send cancelled".to_string())),
            }
        };
        self.clear_inflight(id, &notify);
        let send = RepeaterSend {
            id: request.id,
            request,
            response,
            error,
            elapsed_ms: started.elapsed().as_millis() as u64,
            ts_ms: burpfree_core::traffic::now_ms(),
        };
        {
            let mut tabs = self.tabs.write();
            if let Some(t) = tabs.get_mut(&id) {
                t.history.push(send.clone());
                trim_history(&mut t.history);
            }
        }
        self.save();
        Ok(send)
    }

    /// Wipe a single tab's `history` Vec. Keeps the tab, its
    /// template, name, pinned / color / group / order / follow-redirects
    /// settings — only the `RepeaterSend` list is nuked. Returns
    /// `true` iff the tab existed. Burp has no direct equivalent; the
    /// operator reaches for this when iterating on a long chain of
    /// probes and wants a clean slate without closing + recreating
    /// the tab. Persists the trimmed state to disk so a project
    /// re-open sees the cleared history.
    pub fn clear_tab_history(&self, id: TrafficId) -> bool {
        let hit = {
            let mut tabs = self.tabs.write();
            if let Some(t) = tabs.get_mut(&id) {
                t.history.clear();
                true
            } else {
                false
            }
        };
        if hit {
            self.save();
        }
        hit
    }

    /// Install a fresh [`Notify`] for `id` in `self.inflight` and
    /// return the handle. Overwrites any existing entry; the caller
    /// paired with `clear_inflight` guards cleanup via `Arc::ptr_eq`
    /// so overlapping sends don't yank each other's slot.
    fn register_inflight(&self, id: TrafficId) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        self.inflight.write().insert(id, notify.clone());
        notify
    }

    /// Remove the inflight entry for `id` only if it still points at
    /// the Notify we installed. A later overlapping send that bumped
    /// our slot stays untouched.
    fn clear_inflight(&self, id: TrafficId, own: &Arc<Notify>) {
        let mut g = self.inflight.write();
        if let Some(cur) = g.get(&id) {
            if Arc::ptr_eq(cur, own) {
                g.remove(&id);
            }
        }
    }

    /// Convert any history item into a [`Transaction`] for recording
    /// in the HTTP history.
    pub fn send_to_transaction(send: &RepeaterSend) -> Transaction {
        let mut t = Transaction::new(send.request.clone());
        t.response = send.response.clone();
        t.error = send.error.clone();
        t
    }

    fn save(&self) {
        if let Some(path) = &self.disk {
            let data = serde_json::to_string_pretty(&*self.tabs.read()).unwrap_or_default();
            let _ = std::fs::write(path, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::HttpClientConfig;
    use burpfree_core::traffic::Request;
    use tempfile::tempdir;

    #[tokio::test]
    async fn tabs_persist() {
        let td = tempdir().unwrap();
        let path = td.path().join("r.json");
        let r = Repeater::load_or_new(&path, HttpClient::new(HttpClientConfig::default())).unwrap();
        let id = r.add_tab(RepeaterTab::new("t1", Request::new("GET", "http://x.local/").unwrap()));
        assert_eq!(r.list_tabs().len(), 1);
        drop(r);
        let r2 = Repeater::load_or_new(&path, HttpClient::new(HttpClientConfig::default())).unwrap();
        assert_eq!(r2.list_tabs().len(), 1);
        assert!(r2.get_tab(id).is_some());
    }

    #[tokio::test]
    async fn clone_without_history() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new("t", Request::new("GET", "http://x.local/").unwrap()));
        let id2 = r.clone_tab(id, Some("copy".into())).unwrap();
        let a = r.get_tab(id).unwrap();
        let b = r.get_tab(id2).unwrap();
        assert_eq!(a.name, "t");
        assert_eq!(b.name, "copy");
        assert!(b.history.is_empty());
    }

    #[tokio::test]
    async fn clone_preserves_color_follow_redirects_and_comment() {
        // Burp's "Duplicate tab" copies cosmetic + behavioural state so
        // the new tab looks and acts like the original minus history.
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "login-flow",
            Request::new("POST", "http://x.local/login").unwrap(),
        ));
        assert!(r.set_color(id, Some("#ff5544".into())));
        assert!(r.set_follow_redirects(
            id,
            Some(burpfree_core::net::FollowRedirectPolicy::InScope),
        ));
        // Default clone (no custom name) stamps "(copy)" suffix.
        let id2 = r.clone_tab(id, None).unwrap();
        let b = r.get_tab(id2).unwrap();
        assert_eq!(b.name, "login-flow (copy)");
        assert_eq!(b.color.as_deref(), Some("#ff5544"));
        assert!(matches!(
            b.follow_redirects,
            Some(burpfree_core::net::FollowRedirectPolicy::InScope)
        ));
        assert!(b.history.is_empty());
        // IDs must be distinct — a stale id would alias the source tab.
        assert_ne!(id, id2);
    }

    #[tokio::test]
    async fn rename_persists() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new("original", Request::new("GET", "http://x.local/").unwrap()));
        assert!(r.rename(id, "login-flow"));
        assert_eq!(r.get_tab(id).unwrap().name, "login-flow");
        assert!(!r.rename(TrafficId::new(), "nope"));
    }

    #[tokio::test]
    async fn set_color_round_trip() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new("t", Request::new("GET", "http://x.local/").unwrap()));
        assert!(r.set_color(id, Some("#ff5544".into())));
        assert_eq!(r.get_tab(id).unwrap().color.as_deref(), Some("#ff5544"));
        // Blank clears the colour.
        assert!(r.set_color(id, Some("   ".into())));
        assert_eq!(r.get_tab(id).unwrap().color, None);
    }

    #[tokio::test]
    async fn set_url_rewrites_template_and_host_header() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/old?a=1").unwrap(),
        ));
        // Flip to https with a non-default port and new path.
        assert!(r
            .set_url(id, "https://example.com:8443/new?b=2")
            .unwrap());
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.template.scheme, "https");
        assert_eq!(tab.template.host, "example.com");
        assert_eq!(tab.template.port, 8443);
        assert_eq!(tab.template.path, "/new?b=2");
        // Host header must include the non-default port.
        assert_eq!(
            tab.template.headers.get("Host").map(|s| s.to_string()),
            Some("example.com:8443".into())
        );
        // Method is preserved.
        assert_eq!(tab.template.method, "GET");

        // Default-port URL drops the port from the Host header.
        assert!(r.set_url(id, "http://example.com/").unwrap());
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.template.port, 80);
        assert_eq!(
            tab.template.headers.get("Host").map(|s| s.to_string()),
            Some("example.com".into())
        );
    }

    #[tokio::test]
    async fn follow_redirect_preserves_template_and_resolves_relative() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept exactly one request, echo the raw request-line back so
        // the test can assert which path got dialled.
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path_line = req.lines().next().unwrap_or("").to_string();
                let body = format!("saw:{path_line}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });

        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", &format!("http://127.0.0.1:{port}/orig")).unwrap(),
        ));

        // Relative Location → joined against the current URL.
        let send = r.follow_redirect(id, "/next?q=1").await.unwrap();
        assert_eq!(send.response.as_ref().unwrap().status, 200);
        // The dialled request line reached /next?q=1 (not /orig).
        let body = String::from_utf8_lossy(&send.response.as_ref().unwrap().body).to_string();
        assert!(body.contains("/next?q=1"), "body was {body:?}");
        // The tab's template is unchanged.
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.template.path, "/orig");
        // The follow-redirect call still appended to history.
        assert_eq!(tab.history.len(), 1);
    }

    #[tokio::test]
    async fn set_url_rejects_non_http_schemes() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/").unwrap(),
        ));
        assert!(r.set_url(id, "ftp://example.com/").is_err());
        assert!(r.set_url(id, "not a url").is_err());
        // The tab is left untouched.
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.template.host, "x.local");
    }

    #[tokio::test]
    async fn set_follow_redirects_round_trip() {
        use burpfree_core::net::FollowRedirectPolicy;
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/").unwrap(),
        ));
        // Default is None (defer to global).
        assert_eq!(r.get_tab(id).unwrap().follow_redirects, None);
        assert!(r.set_follow_redirects(id, Some(FollowRedirectPolicy::OnSite)));
        assert_eq!(
            r.get_tab(id).unwrap().follow_redirects,
            Some(FollowRedirectPolicy::OnSite)
        );
        assert!(r.set_follow_redirects(id, None));
        assert_eq!(r.get_tab(id).unwrap().follow_redirects, None);
        // Unknown id returns false, doesn't mutate.
        assert!(!r.set_follow_redirects(TrafficId::new(), Some(FollowRedirectPolicy::Always)));
    }

    #[tokio::test]
    async fn burst_send_runs_count_times() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    ).await;
                });
            }
        });
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "burst",
            Request::new("GET", &format!("http://127.0.0.1:{}/x", addr.port())).unwrap(),
        ));
        let results = r.burst_send(id, 4, 0).await.unwrap();
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|s| s.response.as_ref().map(|r| r.status) == Some(200)));
        // History carries all four plus they are the whole history.
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.history.len(), 4);
    }

    #[tokio::test]
    async fn burst_send_clamps_count() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new("x", Request::new("GET", "http://127.0.0.1:1/").unwrap()));
        // 0 → clamped up to 1; the single attempt fails (nothing listens on :1)
        // but the loop should still run once and return a result row.
        let results = r.burst_send(id, 0, 0).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn chunked_round_trip() {
        let data = b"The quick brown fox jumps over the lazy dog".to_vec();
        let encoded = encode_chunked(&data);
        assert!(encoded.ends_with(b"0\r\n\r\n"));
        assert_eq!(decode_chunked(&encoded).unwrap(), data);
    }

    #[tokio::test]
    async fn set_body_encoding_flips_between_all_three() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let mut req = Request::new("POST", "http://x.local/upload").unwrap();
        req.body = b"name=alice&role=admin".to_vec();
        req.headers.set("Content-Type", "application/x-www-form-urlencoded");
        req.headers.set("Content-Length", "21");
        let id = r.add_tab(RepeaterTab::new("t", req));

        // Flip plain → gzip.
        assert!(r.set_body_encoding(id, BodyEncoding::Gzip).unwrap());
        let g = r.get_tab(id).unwrap();
        assert_eq!(g.template.headers.get("Content-Encoding").unwrap(), "gzip");
        assert!(g.template.headers.get("Transfer-Encoding").is_none());
        assert_ne!(g.template.body, b"name=alice&role=admin");

        // Flip gzip → chunked (should decode gzip first, then re-chunk).
        assert!(r.set_body_encoding(id, BodyEncoding::Chunked).unwrap());
        let c = r.get_tab(id).unwrap();
        assert_eq!(c.template.headers.get("Transfer-Encoding").unwrap(), "chunked");
        assert!(c.template.headers.get("Content-Encoding").is_none());
        assert!(c.template.headers.get("Content-Length").is_none());
        // The chunked framing wraps the original plain body.
        assert_eq!(decode_chunked(&c.template.body).unwrap(), b"name=alice&role=admin");

        // Flip chunked → plain restores the original bytes + CL.
        assert!(r.set_body_encoding(id, BodyEncoding::Plain).unwrap());
        let p = r.get_tab(id).unwrap();
        assert_eq!(p.template.body, b"name=alice&role=admin");
        assert_eq!(p.template.headers.get("Content-Length").unwrap(), "21");
        assert!(p.template.headers.get("Transfer-Encoding").is_none());
        assert!(p.template.headers.get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn change_method_preserves_body_and_url() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let mut req = Request::new("GET", "http://x.local/orders").unwrap();
        req.body = br#"{"id":1}"#.to_vec();
        let id = r.add_tab(RepeaterTab::new("t", req));

        assert!(r.change_method(id, "post"));
        let tab = r.get_tab(id).unwrap();
        assert_eq!(tab.template.method, "POST");
        assert_eq!(tab.template.path, "/orders");
        assert_eq!(tab.template.body, br#"{"id":1}"#);

        // Empty / whitespace method is rejected.
        assert!(!r.change_method(id, "   "));
        assert_eq!(r.get_tab(id).unwrap().template.method, "POST");
    }

    #[tokio::test]
    async fn set_group_normalizes_and_persists() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/").unwrap(),
        ));
        // Default is ungrouped.
        assert_eq!(r.get_tab(id).unwrap().group, None);
        // Normal assignment.
        assert!(r.set_group(id, Some("Login flow".into())));
        assert_eq!(
            r.get_tab(id).unwrap().group.as_deref(),
            Some("Login flow")
        );
        // Whitespace is trimmed.
        assert!(r.set_group(id, Some("   admin probes   ".into())));
        assert_eq!(
            r.get_tab(id).unwrap().group.as_deref(),
            Some("admin probes")
        );
        // Blank clears the group.
        assert!(r.set_group(id, Some("   ".into())));
        assert_eq!(r.get_tab(id).unwrap().group, None);
        // None also clears.
        assert!(r.set_group(id, Some("Checkout".into())));
        assert!(r.set_group(id, None));
        assert_eq!(r.get_tab(id).unwrap().group, None);
        // Unknown id → false, no mutation.
        assert!(!r.set_group(TrafficId::new(), Some("stray".into())));
    }

    #[tokio::test]
    async fn list_groups_dedupes_and_sorts() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", "http://x.local/a").unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", "http://x.local/b").unwrap()));
        let c = r.add_tab(RepeaterTab::new("c", Request::new("GET", "http://x.local/c").unwrap()));
        r.set_group(a, Some("Login".into()));
        r.set_group(b, Some("Checkout".into()));
        r.set_group(c, Some("Login".into()));
        let groups = r.list_groups();
        // Sorted alphabetical, de-duplicated.
        assert_eq!(groups, vec!["Checkout".to_string(), "Login".to_string()]);
    }

    #[tokio::test]
    async fn rename_group_moves_all_members() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", "http://x.local/a").unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", "http://x.local/b").unwrap()));
        let c = r.add_tab(RepeaterTab::new("c", Request::new("GET", "http://x.local/c").unwrap()));
        r.set_group(a, Some("Old".into()));
        r.set_group(b, Some("Old".into()));
        r.set_group(c, Some("Keep".into()));
        assert_eq!(r.rename_group("Old", "New"), 2);
        assert_eq!(r.get_tab(a).unwrap().group.as_deref(), Some("New"));
        assert_eq!(r.get_tab(b).unwrap().group.as_deref(), Some("New"));
        assert_eq!(r.get_tab(c).unwrap().group.as_deref(), Some("Keep"));
        // Blank renames clear the group.
        assert_eq!(r.rename_group("New", ""), 2);
        assert_eq!(r.get_tab(a).unwrap().group, None);
        assert_eq!(r.get_tab(b).unwrap().group, None);
    }

    #[tokio::test]
    async fn clone_preserves_group() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/").unwrap(),
        ));
        r.set_group(id, Some("Attack chain".into()));
        let id2 = r.clone_tab(id, Some("t2".into())).unwrap();
        assert_eq!(
            r.get_tab(id2).unwrap().group.as_deref(),
            Some("Attack chain")
        );
    }

    #[tokio::test]
    async fn send_group_sequential_fires_every_tab_in_group() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept any number of connections, respond 200 OK.
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    ).await;
                });
            }
        });
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        // Three in group, one outside.
        let base = format!("http://127.0.0.1:{}/x", addr.port());
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", &base).unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", &base).unwrap()));
        let c = r.add_tab(RepeaterTab::new("c", Request::new("GET", &base).unwrap()));
        let orphan = r.add_tab(RepeaterTab::new(
            "d",
            Request::new("GET", &base).unwrap(),
        ));
        r.set_group(a, Some("Attack".into()));
        r.set_group(b, Some("Attack".into()));
        r.set_group(c, Some("Attack".into()));
        // orphan stays ungrouped
        let out = r.send_group_sequential("Attack").await;
        assert_eq!(out.len(), 3);
        for s in &out {
            assert_eq!(s.response.as_ref().map(|r| r.status), Some(200));
        }
        // Every grouped tab's history grew by exactly 1.
        assert_eq!(r.get_tab(a).unwrap().history.len(), 1);
        assert_eq!(r.get_tab(b).unwrap().history.len(), 1);
        assert_eq!(r.get_tab(c).unwrap().history.len(), 1);
        // The ungrouped tab is untouched.
        assert_eq!(r.get_tab(orphan).unwrap().history.len(), 0);
    }

    #[tokio::test]
    async fn set_pinned_round_trips_and_floats_pinned_tabs_first() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", "http://x.local/a").unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", "http://x.local/b").unwrap()));
        let c = r.add_tab(RepeaterTab::new("c", Request::new("GET", "http://x.local/c").unwrap()));
        // Default order: a, b, c. Pin c so it floats to the front.
        assert!(r.set_pinned(c, true));
        let names: Vec<String> = r.list_tabs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["c", "a", "b"]);
        // Pin a too — pinned tabs keep their own order (a before c
        // by `order`), so result is a, c, b.
        assert!(r.set_pinned(a, true));
        let names: Vec<String> = r.list_tabs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["a", "c", "b"]);
        // Unpin a — c jumps back to front, a drops back to the
        // unpinned section.
        assert!(r.set_pinned(a, false));
        let names: Vec<String> = r.list_tabs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["c", "a", "b"]);
        // Unknown id → false, no mutation.
        assert!(!r.set_pinned(TrafficId::new(), true));
    }

    #[tokio::test]
    async fn clone_tab_carries_pinned_flag() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "t",
            Request::new("GET", "http://x.local/").unwrap(),
        ));
        assert!(r.set_pinned(id, true));
        let id2 = r.clone_tab(id, Some("t2".into())).unwrap();
        let copy = r.get_tab(id2).unwrap();
        assert!(copy.pinned, "clone should inherit pinned=true");
    }

    #[tokio::test]
    async fn list_tabs_sorts_by_order() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", "http://x.local/a").unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", "http://x.local/b").unwrap()));
        let c = r.add_tab(RepeaterTab::new("c", Request::new("GET", "http://x.local/c").unwrap()));
        // Natural order after creation: a, b, c (each got max+1000).
        let names: Vec<String> = r.list_tabs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
        // Reorder c→a→b.
        assert_eq!(r.reorder_tabs(&[c, a, b]), 3);
        let names: Vec<String> = r.list_tabs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["c", "a", "b"]);
    }

    #[tokio::test]
    async fn reorder_assigns_sequential_positions() {
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let ids: Vec<TrafficId> = (0..5)
            .map(|i| {
                r.add_tab(RepeaterTab::new(
                    format!("t{i}"),
                    Request::new("GET", "http://x.local/").unwrap(),
                ))
            })
            .collect();
        // Partial reorder: only move the first three. The remaining
        // two must keep their existing order relative to each other.
        let partial: Vec<TrafficId> = vec![ids[2], ids[0], ids[1]];
        let n = r.reorder_tabs(&partial);
        assert_eq!(n, 3);
        let tabs = r.list_tabs();
        // The partially-ordered ids got (1000, 2000, 3000) and sit
        // ahead of the untouched tabs whose order remained in the
        // 4000+ range from add_tab.
        assert_eq!(tabs[0].id, ids[2]);
        assert_eq!(tabs[1].id, ids[0]);
        assert_eq!(tabs[2].id, ids[1]);
        // Partial reorder with an unknown id just skips it.
        let bogus = TrafficId::new();
        let n2 = r.reorder_tabs(&[bogus, ids[3]]);
        assert_eq!(n2, 1);
    }

    #[tokio::test]
    async fn cancel_aborts_in_flight_send() {
        // Listener that accepts the TCP connect but never writes a
        // response — mirrors the "server-is-hung" scenario Burp's
        // Cancel button exists to escape from.
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                // Drain client bytes so our write finishes, then stall
                // forever instead of writing a response. Dropping `s`
                // on cancel is fine; the test only cares that the
                // Repeater side wakes.
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                // Hold the socket open indefinitely.
                std::future::pending::<()>().await;
            }
        });
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let id = r.add_tab(RepeaterTab::new(
            "slow",
            Request::new("GET", &format!("http://127.0.0.1:{}/x", addr.port())).unwrap(),
        ));
        // Cancel while send is parked waiting for the response head.
        let r_c = r.clone();
        tokio::spawn(async move {
            // Give send() enough time to register its Notify + enter
            // tokio::select! before we fire cancel.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(r_c.cancel(id), "cancel should find the inflight send");
        });
        let send = r.send(id).await.unwrap();
        // The send returns normally with a cancelled marker rather
        // than bubbling a Rust error, so the UI can render it as a
        // regular history row.
        assert!(
            send.error.as_deref().unwrap_or("").contains("cancel"),
            "expected cancel marker in error, got: {:?}",
            send.error
        );
        assert!(send.response.is_none(), "no response arrived before cancel");
        // History still records the cancelled send so the operator
        // can inspect the attempt.
        assert_eq!(r.get_tab(id).unwrap().history.len(), 1);
        // Second cancel on a tab with no inflight entry returns
        // false — the UI uses this to grey out its Cancel button.
        assert!(!r.cancel(id), "no inflight after send resolved");
    }

    #[tokio::test]
    async fn cancel_all_wakes_every_in_flight_send() {
        // Stand up a listener that accepts but never writes — three
        // concurrent sends against it all park on response-head read.
        // cancel_all() must wake every one.
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    std::future::pending::<()>().await;
                });
            }
        });
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        // Three tabs each start their own send concurrently.
        let mut ids = Vec::new();
        let mut handles = Vec::new();
        for i in 0..3 {
            let id = r.add_tab(RepeaterTab::new(
                format!("t{i}"),
                Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port())).unwrap(),
            ));
            ids.push(id);
            let r_c = r.clone();
            handles.push(tokio::spawn(async move { r_c.send(id).await }));
        }
        // Give every send a moment to register its Notify.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        // inflight_ids must list all three.
        let snapshot = r.inflight_ids();
        assert_eq!(snapshot.len(), 3, "all three sends registered");
        for id in &ids {
            assert!(snapshot.contains(id), "snapshot should contain {id:?}");
        }
        // Single bulk cancel wakes all three in-flight sends.
        let woken = r.cancel_all();
        assert_eq!(woken, 3);
        // Every send resolves with a cancel marker.
        for (i, h) in handles.into_iter().enumerate() {
            let send = h.await.unwrap().unwrap();
            assert!(
                send.error.as_deref().unwrap_or("").contains("cancel"),
                "send #{i} should carry cancel marker, got {:?}",
                send.error
            );
            assert!(send.response.is_none());
        }
        // After every send resolves the inflight map is empty.
        assert_eq!(r.inflight_ids().len(), 0);
        // cancel_all on an empty map returns 0 (no-op).
        assert_eq!(r.cancel_all(), 0);
    }

    #[tokio::test]
    async fn send_group_parallel_fires_every_member() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    ).await;
                });
            }
        });
        let r = Repeater::new(HttpClient::new(HttpClientConfig::default()));
        let base = format!("http://127.0.0.1:{}/x", addr.port());
        let a = r.add_tab(RepeaterTab::new("a", Request::new("GET", &base).unwrap()));
        let b = r.add_tab(RepeaterTab::new("b", Request::new("GET", &base).unwrap()));
        r.set_group(a, Some("race".into()));
        r.set_group(b, Some("race".into()));
        let out = r.send_group_parallel("race").await;
        assert_eq!(out.len(), 2);
        // Each grouped tab's history grew by exactly 1.
        assert_eq!(r.get_tab(a).unwrap().history.len(), 1);
        assert_eq!(r.get_tab(b).unwrap().history.len(), 1);
    }

    /// Pure test on the standalone `trim_history` helper. Verifies
    /// that (a) a vec at the cap is a no-op, (b) a vec over the cap
    /// drops the OLDEST entries from the front so the newest sends
    /// stay accessible at the tail (where the UI reads them), and
    /// (c) a vec well below the cap is untouched. Avoids spinning up
    /// 500+ real sends against a mock listener which would be slow.
    #[test]
    fn trim_history_drops_oldest_over_cap() {
        let req = Request::new("GET", "http://x.local/").unwrap();
        let make = |i: u64| RepeaterSend {
            id: TrafficId::new(),
            request: req.clone(),
            response: None,
            error: Some(format!("send-{i}")),
            elapsed_ms: i,
            ts_ms: i as i64,
        };

        // Under cap — no-op.
        let mut small: Vec<RepeaterSend> = (0..10u64).map(make).collect();
        trim_history(&mut small);
        assert_eq!(small.len(), 10);

        // Exactly at cap — still no-op.
        let mut at_cap: Vec<RepeaterSend> =
            (0..MAX_HISTORY_PER_TAB as u64).map(make).collect();
        trim_history(&mut at_cap);
        assert_eq!(at_cap.len(), MAX_HISTORY_PER_TAB);
        // First entry index 0 is preserved — nothing dropped.
        assert_eq!(at_cap[0].elapsed_ms, 0);

        // Over cap by 20 — drops oldest 20.
        let overflow = MAX_HISTORY_PER_TAB + 20;
        let mut over: Vec<RepeaterSend> = (0..overflow as u64).map(make).collect();
        trim_history(&mut over);
        assert_eq!(over.len(), MAX_HISTORY_PER_TAB);
        // Oldest 20 are gone — the first retained send is the one
        // originally at index 20, so `elapsed_ms == 20`.
        assert_eq!(over[0].elapsed_ms, 20);
        // Latest send sits at the tail unchanged — the UI's
        // `history[len-1]` idiom still finds the most recent.
        assert_eq!(
            over[MAX_HISTORY_PER_TAB - 1].elapsed_ms,
            (overflow - 1) as u64,
        );
    }

    /// `clear_tab_history` wipes a tab's send Vec in place and
    /// leaves everything else (name / template / pinned / color /
    /// group) intact. Also returns `false` for a non-existent tab.
    #[tokio::test]
    async fn clear_tab_history_wipes_sends_but_keeps_tab() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let _ = s.read(&mut buf).await.unwrap();
                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
                    s.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        let td = tempdir().unwrap();
        let path = td.path().join("r.json");
        let r = Repeater::load_or_new(
            &path,
            HttpClient::new(HttpClientConfig::default()),
        )
        .unwrap();
        let template =
            Request::new("GET", &format!("http://127.0.0.1:{}/", addr.port()))
                .unwrap();
        let mut tab = RepeaterTab::new("probe", template);
        tab.pinned = true;
        tab.color = Some("#ff8844".into());
        let id = r.add_tab(tab);
        // Fire two sends so history has content to clear.
        r.send(id).await.unwrap();
        r.send(id).await.unwrap();
        assert_eq!(r.get_tab(id).unwrap().history.len(), 2);

        // Clear hits.
        assert!(r.clear_tab_history(id));
        let after = r.get_tab(id).unwrap();
        assert_eq!(after.history.len(), 0, "sends wiped");
        // Everything else survives — the tab, its name, template,
        // and pinned / color flags all come through untouched.
        assert_eq!(after.name, "probe");
        assert_eq!(after.template.host, "127.0.0.1");
        assert!(after.pinned);
        assert_eq!(after.color.as_deref(), Some("#ff8844"));

        // Non-existent id → false, no-op.
        assert!(!r.clear_tab_history(TrafficId::new()));

        // Persistence round-trip: re-opening the project reads the
        // cleared state (the clear path calls save() so the on-disk
        // JSON doesn't still carry the two sends).
        drop(r);
        let r2 = Repeater::load_or_new(
            &path,
            HttpClient::new(HttpClientConfig::default()),
        )
        .unwrap();
        assert_eq!(r2.get_tab(id).unwrap().history.len(), 0);
    }
}
