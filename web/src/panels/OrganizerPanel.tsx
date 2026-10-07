import { useCallback, useEffect, useMemo, useState } from "react";
import { api, CollectionsView, OrganizerItem } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";

type CollectionMenu = { id: number | null; name: string };

/** Which collection is currently selected in the sidebar.
 *  `null`           → every item (All)
 *  `-1`             → Inbox (items with collection_id IS NULL)
 *  other id         → that collection
 */
type Selection = number | null;

export function OrganizerPanel() {
  const [view, setView] = useState<CollectionsView>({ collections: [], inbox_count: 0 });
  const [collMenu, setCollMenu] = useState<MenuState<CollectionMenu> | null>(null);
  const [itemMenu, setItemMenu] = useState<MenuState<OrganizerItem> | null>(null);
  const [sel, setSel] = useState<Selection>(-1); // default to Inbox
  const [items, setItems] = useState<OrganizerItem[]>([]);
  const [search, setSearch] = useState("");
  const [active, setActive] = useState<OrganizerItem | null>(null);
  const [draftNote, setDraftNote] = useState("");
  const [draftTags, setDraftTags] = useState("");
  const [draftStatus, setDraftStatus] = useState("open");

  const refreshCollections = useCallback(async () => {
    try { setView(await api.collectionsList()); } catch (e) { console.error(e); }
  }, []);

  const refreshItems = useCallback(async () => {
    try {
      let args: { collection_id?: number | null } | undefined;
      if (sel === null)       args = undefined;              // all items
      else if (sel === -1)    args = { collection_id: null }; // Inbox
      else                    args = { collection_id: sel };  // specific
      const list = await api.organizerList(args);
      setItems(list);
      if (active) {
        const fresh = list.find((i) => i.id === active.id);
        if (fresh) {
          setActive(fresh);
          setDraftNote(fresh.note);
          setDraftTags(fresh.tags.join(", "));
          setDraftStatus(fresh.status);
        }
      }
    } catch (e) { console.error(e); }
  }, [sel, active?.id]);

  useEffect(() => { void refreshCollections(); }, [refreshCollections]);
  useEffect(() => { void refreshItems(); }, [refreshItems]);

  // R275: Alt+0..9 switches the sidebar selection — Alt-digit
  // family continuation across findings-adjacent panels (R194
  // Repeater tab jump, R230 Scanner sev, R231 Intruder mode,
  // R232 Target Issues sev, R233 Collaborator kind, R235 Logger
  // kind). Mapping matches the sidebar order:
  //   Alt+0 → Inbox (sel = -1)
  //   Alt+1..9 → first N collections in view.collections (sel = c.id)
  // "All items" (sel = null) stays mouse-only — operators rarely
  // want it + it has no stable numeric position. Guards: plain
  // Alt only (no Ctrl/Meta/Shift), digit 0..9 only, text-input
  // focus skip so the search box and the note / tag editor stay
  // unaffected.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const digit = e.key;
      if (digit < "0" || digit > "9") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (digit === "0") {
        e.preventDefault();
        setSel(-1);
        return;
      }
      const idx = parseInt(digit, 10) - 1;
      if (idx < 0 || idx >= view.collections.length) return;
      e.preventDefault();
      setSel(view.collections[idx].id);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [view.collections]);

  async function newCollection() {
    const name = prompt("New collection name");
    if (!name?.trim()) return;
    const id = await api.collectionCreate(name.trim());
    await refreshCollections();
    setSel(id);
  }

  async function renameCollection(id: number, cur: string) {
    const name = prompt("Rename collection", cur);
    if (!name || name === cur) return;
    await api.collectionRename(id, name);
    await refreshCollections();
  }

  async function deleteCollection(id: number, name: string) {
    if (!confirm(`Delete "${name}"? Items will return to Inbox.`)) return;
    await api.collectionDelete(id);
    if (sel === id) setSel(-1);
    await refreshCollections();
    await refreshItems();
  }

  async function addItem() {
    const title = prompt("Title for this organizer item");
    if (!title) return;
    const col = sel && sel > 0 ? sel : null;
    await api.organizerAdd({ title, collection_id: col });
    await refreshCollections();
    await refreshItems();
  }

  async function saveActive() {
    if (!active) return;
    const tags = draftTags.split(",").map((t) => t.trim()).filter(Boolean);
    await api.organizerUpdate(active.id, draftNote, tags, draftStatus);
    await refreshItems();
  }

  async function removeItem(id: number) {
    if (!confirm("Delete this organizer item?")) return;
    await api.organizerDelete(id);
    if (active?.id === id) setActive(null);
    await refreshCollections();
    await refreshItems();
  }

  async function moveItem(itemId: number, targetId: number | null) {
    await api.organizerMove(itemId, targetId);
    await refreshCollections();
    await refreshItems();
  }

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((i) =>
      i.title.toLowerCase().includes(q) ||
      i.note.toLowerCase().includes(q) ||
      i.tags.join(" ").toLowerCase().includes(q)
    );
  }, [items, search]);

  // R212: J / K vim-style navigation across `filteredItems`.
  // Mirror of R197 (Scanner J/K) + R208 (History J/K alias).
  // Walks the currently-shown items (post-search), updates
  // `active` + the three draft fields in lockstep with the click
  // handler so operators get the full detail-pane follow-through
  // on each keystroke. Guards: no modifiers (pure j/k only),
  // text-input focus skip (so J inside the note textarea doesn't
  // flash rows), empty-list no-op. Case-insensitive so a stuck
  // CapsLock doesn't surprise anyone.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const isJ = e.key === "j" || e.key === "J";
      const isK = e.key === "k" || e.key === "K";
      if (!isJ && !isK) return;
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (filteredItems.length === 0) return;
      e.preventDefault();
      const curIdx = active
        ? filteredItems.findIndex((i) => i.id === active.id)
        : -1;
      let nextIdx: number;
      if (curIdx < 0) {
        nextIdx = isJ ? 0 : filteredItems.length - 1;
      } else {
        nextIdx = isJ
          ? Math.min(curIdx + 1, filteredItems.length - 1)
          : Math.max(curIdx - 1, 0);
      }
      const next = filteredItems[nextIdx];
      if (!next) return;
      setActive(next);
      setDraftNote(next.note);
      setDraftTags(next.tags.join(", "));
      setDraftStatus(next.status);
      // Scroll the newly-selected row into view on the next tick.
      setTimeout(() => {
        document
          .querySelector(".org-item.active")
          ?.scrollIntoView({ block: "nearest" });
      }, 0);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredItems, active?.id]);

  const activeTitle = (() => {
    if (sel === null) return "All items";
    if (sel === -1)   return "Inbox";
    return view.collections.find((c) => c.id === sel)?.name ?? "Collection";
  })();

  return (
    <div className="panel org-panel">
      <div className="org-grid">
        <aside className="org-sidebar">
          <div className="org-sidebar-head">
            <strong>Collections</strong>
            <button className="ghost" onClick={newCollection} title="New collection">+ New</button>
          </div>
          <input
            className="org-sidebar-search"
            placeholder="Search collections…"
            value=""
            readOnly
            onFocus={(e) => e.target.blur()}
            style={{ display: "none" }}
          />
          <div
            className={`org-coll ${sel === null ? "active" : ""}`}
            onClick={() => setSel(null)}
          >
            <span className="org-coll-icon">◎</span>
            <span className="org-coll-name">All items</span>
            <span className="org-coll-count">{items.length}</span>
          </div>
          <div
            className={`org-coll ${sel === -1 ? "active" : ""}`}
            onClick={() => setSel(-1)}
          >
            <span className="org-coll-icon">📥</span>
            <span className="org-coll-name">Inbox</span>
            <span className="org-coll-count">{view.inbox_count}</span>
          </div>
          <div className="org-coll-divider">Collections</div>
          {view.collections.length === 0 && (
            <div className="dim" style={{ padding: 10, fontSize: 11 }}>
              No collections yet. "+ New" to create one.
            </div>
          )}
          {view.collections.map((c) => (
            <div
              key={c.id}
              className={`org-coll ${sel === c.id ? "active" : ""}`}
              onClick={() => setSel(c.id)}
              onContextMenu={(e) => {
                e.preventDefault();
                setSel(c.id);
                setCollMenu({ x: e.clientX, y: e.clientY, data: { id: c.id, name: c.name } });
              }}
              title="Right-click to rename or delete"
            >
              <span className="org-coll-icon">▸</span>
              <span className="org-coll-name">{c.name}</span>
              <span className="org-coll-count">{c.item_count}</span>
            </div>
          ))}
        </aside>
        <div className="org-main">
          <div className="toolbar">
            <strong>{activeTitle}</strong>
            <input
              placeholder="Search title / note / tags…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ width: 220 }}
            />
            <button className="primary" onClick={addItem}>+ New item</button>
            {/* R169: "Mark all reviewed" bulk op. Operators triaging a */}
            {/* long Inbox mark items one at a time via the detail      */}
            {/* pane's Status select; this flips every currently-       */}
            {/* visible (filter-respecting) item to status=reviewed in  */}
            {/* one shot. Scoped to the search-filtered view so a       */}
            {/* search of "/admin" + Mark all only touches admin rows.  */}
            {/* Promise.allSettled so one bad write doesn't strand      */}
            {/* the rest. Confirm with count because this writes to     */}
            {/* every item + bumps their updated_at_ms.                 */}
            {(() => {
              const victims = filteredItems.filter((i) => i.status !== "reviewed");
              return (
                <button
                  disabled={victims.length === 0}
                  onClick={async () => {
                    if (
                      !confirm(
                        `Mark ${victims.length} item${victims.length === 1 ? "" : "s"} as reviewed? (Items already reviewed are untouched.)`,
                      )
                    )
                      return;
                    try {
                      await Promise.allSettled(
                        victims.map((i) =>
                          api.organizerUpdate(i.id, i.note, i.tags, "reviewed"),
                        ),
                      );
                      await refreshItems();
                      await refreshCollections();
                    } catch (e) {
                      alert(`Mark all reviewed failed: ${e}`);
                    }
                  }}
                  title={
                    victims.length === 0
                      ? "All visible items are already reviewed"
                      : `Mark ${victims.length} unreviewed item${victims.length === 1 ? "" : "s"} as reviewed (respects the current search filter)`
                  }
                >
                  ✓ Mark reviewed ({victims.length})
                </button>
              );
            })()}
            {/* R313: Export visible items as JSONL. Follows the R193  */}
            {/* / R284 / R285 / R286 / R311 convention — newline-      */}
            {/* delimited JSON, one OrganizerItem per line, every      */}
            {/* field preserved (title + note + tags + status +         */}
            {/* collection_id + ts timestamps + the full saved         */}
            {/* request/response blob). Scope respects the search       */}
            {/* filter + the sidebar collection selection so operators */}
            {/* exporting a specific research list get just that       */}
            {/* subset. Streaming-friendly: no top-level array wrapper */}
            {/* so an ELK ingest / `jq -c` consumer can start before    */}
            {/* the write finishes.                                     */}
            <button
              disabled={filteredItems.length === 0}
              onClick={() => {
                try {
                  const body = filteredItems
                    .map((it) => JSON.stringify(it))
                    .join("\n");
                  const blob = new Blob([body + "\n"], {
                    type: "application/x-ndjson;charset=utf-8",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  const stamp = new Date()
                    .toISOString()
                    .replace(/[:T]/g, "-")
                    .replace(/\..*$/, "");
                  a.href = url;
                  a.download = `burpfree-organizer-${stamp}.jsonl`;
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  URL.revokeObjectURL(url);
                } catch (err) {
                  alert(`${err}`);
                }
              }}
              title={
                filteredItems.length === 0
                  ? "No items to export"
                  : `Export ${filteredItems.length} item${filteredItems.length === 1 ? "" : "s"} as JSONL (one JSON object per line${filteredItems.length !== items.length ? ` — respects the current search filter` : ""}). Preserves every OrganizerItem field — pipe into jq / grep / ELK.`
              }
            >
              ⬇ Export JSONL
            </button>
            <span className="spacer" style={{ flex: 1 }} />
            <span className="badge">{filteredItems.length} shown</span>
          </div>
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
            <div className="org-items">
              {filteredItems.length === 0 && (
                <div className="empty">
                  {sel === -1 ? "Inbox is empty. Save traffic with ★ in HTTP history, or press Ctrl+O on a row."
                   : "No items in this view."}
                </div>
              )}
              {filteredItems.map((it) => {
                // R302: Status row tint — eighth entry in the
                // row-tint family. Organizer items are typed by
                // status (open / triaging / reviewed / etc) and
                // operators triaging a long engagement want to
                // see at-a-glance which items are still in
                // progress vs cleared. Low-saturation tints —
                // open stays default (the baseline), triaging
                // tints amber (needs attention), reviewed tints
                // green (dismissed/handled). The status-badge
                // chip in the row still carries the primary cue
                // so the row tint is a reinforcing hint.
                const status = (it.status || "open").toLowerCase();
                let statusBg: string | undefined;
                if (status === "triaging")
                  statusBg = "rgba(240, 192, 48, 0.07)";
                else if (status === "reviewed")
                  statusBg = "rgba(76, 175, 80, 0.06)";
                // "open" and anything else stays default
                const isActive = active?.id === it.id;
                return (
                <div
                  key={it.id}
                  onClick={() => {
                    setActive(it);
                    setDraftNote(it.note);
                    setDraftTags(it.tags.join(", "));
                    setDraftStatus(it.status);
                  }}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setActive(it);
                    setDraftNote(it.note);
                    setDraftTags(it.tags.join(", "));
                    setDraftStatus(it.status);
                    setItemMenu({ x: e.clientX, y: e.clientY, data: it });
                  }}
                  className={`org-item ${isActive ? "active" : ""}`}
                  style={isActive ? undefined : statusBg ? { background: statusBg } : undefined}
                >
                  <div className="org-item-head">
                    <span className={`badge ${statusBadge(it.status)}`}>{it.status}</span>
                    <strong>{it.title}</strong>
                  </div>
                  {it.transaction_id && (
                    <div className="mono dim" style={{ fontSize: 11 }}>
                      txn #{it.transaction_id}
                    </div>
                  )}
                  {it.tags.length > 0 && (
                    <div style={{ marginTop: 3 }}>
                      {it.tags.map((t) => (
                        <span key={t} className="badge" style={{ marginRight: 3 }}>{t}</span>
                      ))}
                    </div>
                  )}
                </div>
                );
              })}
            </div>
            <div className="org-detail">
              {!active && <div className="empty">Select an item to edit.</div>}
              {active && (
                <>
                  <h3 style={{ marginTop: 0 }}>{active.title}</h3>
                  <div className="dim" style={{ fontSize: 11, marginBottom: 10 }}>
                    #{active.id} · created {new Date(active.ts_ms).toLocaleString()}
                    {active.transaction_id ? ` · txn #${active.transaction_id}` : ""}
                  </div>
                  <div className="form-row">
                    <label>Collection</label>
                    <select
                      value={active.collection_id ?? ""}
                      onChange={(e) => {
                        const v = e.target.value;
                        const target = v === "" ? null : Number(v);
                        void moveItem(active.id, target);
                      }}
                    >
                      <option value="">(Inbox)</option>
                      {view.collections.map((c) => (
                        <option key={c.id} value={c.id}>{c.name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="form-row">
                    <label>Status</label>
                    <select value={draftStatus} onChange={(e) => setDraftStatus(e.target.value)}>
                      <option value="open">open</option>
                      <option value="in_review">in review</option>
                      <option value="confirmed">confirmed</option>
                      <option value="deferred">deferred</option>
                      <option value="closed">closed</option>
                    </select>
                  </div>
                  <div className="form-row">
                    <label>Tags</label>
                    <input
                      value={draftTags}
                      onChange={(e) => setDraftTags(e.target.value)}
                      placeholder="comma, separated"
                    />
                  </div>
                  <div className="form-row" style={{ alignItems: "flex-start" }}>
                    <label>Note</label>
                    <textarea
                      value={draftNote}
                      onChange={(e) => setDraftNote(e.target.value)}
                      style={{ flex: 1, minHeight: 180 }}
                    />
                  </div>
                  <div className="form-row">
                    <label></label>
                    <button className="primary" onClick={saveActive}>Save</button>
                    <button className="danger" onClick={() => removeItem(active.id)}>Delete</button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
      <FloatingMenu
        state={itemMenu}
        onClose={() => setItemMenu(null)}
        items={
          itemMenu?.data
            ? [
                {
                  label: "Mark reviewed",
                  onClick: () => {
                    const it = itemMenu.data!;
                    void api
                      .organizerUpdate(it.id, it.note, it.tags, "reviewed")
                      .then(refreshItems);
                  },
                },
                {
                  label: "Mark triaging",
                  onClick: () => {
                    const it = itemMenu.data!;
                    void api
                      .organizerUpdate(it.id, it.note, it.tags, "triaging")
                      .then(refreshItems);
                  },
                },
                { separator: true },
                ...view.collections.map((c) => ({
                  label: `Move to “${c.name}”`,
                  onClick: () => void moveItem(itemMenu.data!.id, c.id),
                  disabled: itemMenu.data!.collection_id === c.id,
                })),
                {
                  label: "Move to Inbox",
                  onClick: () => void moveItem(itemMenu.data!.id, null),
                  disabled: itemMenu.data!.collection_id == null,
                },
                { separator: true },
                {
                  label: "Copy title",
                  onClick: () => void navigator.clipboard.writeText(itemMenu.data!.title),
                },
                { separator: true },
                {
                  label: "Delete item",
                  danger: true,
                  onClick: () => void removeItem(itemMenu.data!.id),
                },
              ]
            : []
        }
      />
      <FloatingMenu
        state={collMenu}
        onClose={() => setCollMenu(null)}
        items={
          collMenu?.data
            ? [
                {
                  label: `Rename “${collMenu.data.name}”`,
                  onClick: () => {
                    if (collMenu.data!.id != null)
                      void renameCollection(collMenu.data!.id, collMenu.data!.name);
                  },
                  disabled: collMenu.data.id == null,
                },
                {
                  label: `Delete “${collMenu.data.name}”`,
                  danger: true,
                  onClick: () => {
                    if (collMenu.data!.id != null)
                      void deleteCollection(collMenu.data!.id, collMenu.data!.name);
                  },
                  disabled: collMenu.data.id == null,
                  hint: "items move back to Inbox",
                },
              ]
            : []
        }
      />
    </div>
  );
}

function statusBadge(status: string): string {
  switch (status) {
    case "open":      return "accent";
    case "confirmed": return "red";
    case "closed":    return "green";
    default:          return "";
  }
}
