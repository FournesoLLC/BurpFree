import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, HistoryFilter, Scope, StoredSummary, TransactionView } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import {
  buildCurl,
  buildFetch,
  buildHarEntry,
  buildHarLog,
  buildPowerShell,
  buildPython,
  copyToClipboard,
  fromSummaryAndRaw,
  urlFromSummary,
} from "../copyAs";
import {
  buildHostIncludeRule,
  buildPathIncludeRule,
  hasHostIncludeRule,
  hasPathIncludeRule,
  withoutHost,
} from "../scopeHelpers";

/** Seven Burp-style highlight colours. The key is the storage value
 *  (what the backend persists); the value is the CSS colour we use to
 *  paint the left-edge stripe. Keeping the mapping here (rather than
 *  in CSS variables) means a project exported from one BurpFree
 *  install and re-opened in another renders identically regardless
 *  of the host's theme. */
const HIGHLIGHT_COLORS: Record<string, string> = {
  red: "#ef4b4b",
  orange: "#f39c3b",
  yellow: "#f0d234",
  green: "#4bbf6b",
  cyan: "#4bc5bf",
  blue: "#4b8def",
  purple: "#a670ef",
};

type SortKey =
  | "id"
  | "method"
  | "proto"
  | "status"
  | "host"
  | "path"
  | "size"
  | "time"
  | "comment"
  | "highlight";

/**
 * HTTP history column definitions. One entry per visible column. The
 * HistoryPanel iterates this array (filtered by `hiddenColumns`) to
 * drive the colgroup, thead, and every tbody row — so adding or
 * removing a column is a single edit here. Keys match
 * `ProjectConfig::history_hidden_columns` string ids and the SortKey
 * union; renaming any key would orphan projects that have the old
 * value in config.
 *
 * `renderCell` returns the full `<td>` so each column owns its own
 * className / style / title. The parent passes a stable `key` prop
 * to React via the mapped Fragment at the call site.
 */
interface ColumnDef {
  key: SortKey;
  /** Header label; empty string is legal (the highlight gutter). */
  label: string;
  /** Hover tooltip on the <th>. */
  title: string;
  /** Fixed <col> width in px. `undefined` = flex / remaining. */
  width?: number;
  renderCell: (r: StoredSummary) => React.ReactNode;
}

const HISTORY_COLUMNS: ColumnDef[] = [
  {
    key: "highlight",
    label: "",
    title: "Row highlight — click to sort by colour",
    width: 10,
    renderCell: (r) => (
      <td
        style={{
          background: r.highlight ? HIGHLIGHT_COLORS[r.highlight] : undefined,
          padding: 0,
        }}
        title={r.highlight ?? ""}
      />
    ),
  },
  {
    key: "id",
    label: "ID",
    title: "Click to sort by id",
    width: 70,
    renderCell: (r) => (
      <td className="mono" title={`source: ${r.source || "proxy"}`}>
        {r.id}
        {r.source && r.source !== "proxy" && (
          <span
            style={{
              marginLeft: 4,
              padding: "0 4px",
              fontSize: 9,
              borderRadius: 3,
              background: "rgba(100,150,255,0.18)",
              color: "var(--accent)",
              fontWeight: 700,
              verticalAlign: "middle",
            }}
            title={`Origin: ${r.source}`}
          >
            {r.source === "repeater"
              ? "R"
              : r.source === "intruder"
                ? "I"
                : r.source === "scanner"
                  ? "S"
                  : r.source === "manual"
                    ? "M"
                    : r.source === "extension"
                      ? "X"
                      : r.source[0].toUpperCase()}
          </span>
        )}
      </td>
    ),
  },
  {
    key: "method",
    label: "Method",
    title: "Click to sort by method (lexicographic)",
    width: 60,
    /* R255: Tint the method cell by destructiveness. Mirrors R210  */
    /* Dashboard methods card + R254 Repeater tab method badges —   */
    /* GET=green, POST=accent, PUT/PATCH=amber, DELETE=red, others= */
    /* dim. Operators scanning HTTP history can tell safe reads     */
    /* from state-mutating or destructive rows at a glance.         */
    renderCell: (r) => {
      const m = (r.method || "").toUpperCase();
      const color =
        m === "GET"
          ? "var(--green, #4caf50)"
          : m === "POST"
            ? "var(--accent)"
            : m === "PUT" || m === "PATCH"
              ? "var(--amber)"
              : m === "DELETE"
                ? "var(--red)"
                : undefined;
      return (
        <td className="mono" style={color ? { color, fontWeight: 600 } : undefined}>
          {r.method}
        </td>
      );
    },
  },
  {
    key: "proto",
    label: "Proto",
    title: "On-wire HTTP version (HTTP/1.0 / 1.1 / 2 / 3). Click to sort lexicographically.",
    width: 55,
    renderCell: (r) => {
      // Compact form: drop the `HTTP/` prefix so a 55-px column fits
      // 1.1 / 2 / 3 without truncation. `—` for pre-R133 rows that
      // predate the column.
      const compact = (r.http_version ?? "").replace(/^HTTP\//, "");
      return (
        <td
          className="mono"
          style={{
            color:
              compact === "2" || compact === "3"
                ? "var(--accent)"
                : "var(--text-dim)",
            fontSize: 10,
          }}
          title={r.http_version ?? "unknown"}
        >
          {compact || "—"}
        </td>
      );
    },
  },
  {
    key: "status",
    label: "Status",
    title: "Click to sort by HTTP status",
    width: 55,
    renderCell: (r) => (
      <td className={`mono status-${Math.floor((r.status || 0) / 100)}xx`}>
        {r.status ?? "—"}
      </td>
    ),
  },
  {
    key: "host",
    label: "Host",
    title: "Click to sort by host:port",
    width: 220,
    renderCell: (r) => (
      <td className="mono">
        {r.scheme}://{r.host}
        {r.port !== 80 && r.port !== 443 ? `:${r.port}` : ""}
      </td>
    ),
  },
  {
    key: "path",
    label: "Path",
    title: "Click to sort by path",
    width: 320,
    renderCell: (r) => <td className="mono">{r.path}</td>,
  },
  {
    key: "size",
    label: "Size",
    title: "Click to sort by response size",
    width: 90,
    // R871: Burp-identical human-readable byte size. Burp Suite
    // 2026.8's History table shows "1.2 KB" / "3.4 MB" instead of
    // the raw byte count. Operators scanning the Size column want
    // "is this response small (API JSON) or big (HTML page / asset)?"
    // at a glance — a 5-digit raw byte number makes that hard.
    // Keep raw count in title tooltip for operators who want exact.
    renderCell: (r) => {
      const n = r.content_length;
      if (n == null) return <td className="mono">—</td>;
      let label: string;
      if (n < 1024) label = `${n} B`;
      else if (n < 1024 * 1024) label = `${(n / 1024).toFixed(1)} KB`;
      else label = `${(n / 1024 / 1024).toFixed(2)} MB`;
      // R873: Enrich the Size column tooltip with the response's
      // content-type so operators hovering a cell see both the
      // exact byte count AND the MIME in a single pop. Avoids a
      // detail-pane trip when scanning for "is this big response
      // JSON or HTML?".
      const ct = r.content_type ? ` · ${r.content_type}` : "";
      return (
        <td className="mono" title={`${n.toLocaleString()} bytes${ct}`}>
          {label}
        </td>
      );
    },
  },
  {
    key: "time",
    label: "Time",
    title: "Click to sort by elapsed time",
    width: 70,
    // R872: Burp-identical time formatting — "N ms" for sub-second,
    // "N.N s" for ≥1s, dim red tint for >5s (slow). Matches Burp
    // Suite 2026.8's History display where slow responses jump out
    // visually. Operators eyeballing the Time column want to spot
    // outliers; a raw "5432 ms" mixed with "42 ms" rows is harder
    // to scan than "5.4s" vs "42 ms".
    renderCell: (r) => {
      const n = r.elapsed_ms;
      if (n == null) return <td className="mono">—</td>;
      let label: string;
      let color: string | undefined;
      if (n < 1000) label = `${n} ms`;
      else if (n < 10000) label = `${(n / 1000).toFixed(1)} s`;
      else label = `${(n / 1000).toFixed(0)} s`;
      if (n >= 5000) color = "var(--red)";
      else if (n >= 1000) color = "var(--amber)";
      return (
        <td
          className="mono"
          style={color ? { color } : undefined}
          title={`${n} ms (${(n / 1000).toFixed(3)} seconds)`}
        >
          {label}
        </td>
      );
    },
  },
  {
    key: "comment",
    label: "Comment",
    title: "Click to sort by comment text",
    renderCell: (r) => (
      <td
        className="mono"
        style={{
          color: r.comment ? "var(--text)" : "var(--text-faint)",
          fontStyle: r.comment ? "normal" : "italic",
          maxWidth: 320,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={r.comment || "right-click → Edit comment"}
      >
        {r.comment || ""}
      </td>
    ),
  },
];

/** Columns that should default to descending when the operator
 *  switches sort key for the first time (bigger / newer / larger =
 *  most interesting first). All other columns default to ascending. */
const DESC_FIRST_KEYS: ReadonlySet<SortKey> = new Set<SortKey>([
  "id",
  "status",
  "size",
  "time",
]);

/** R778: Detect whether any HistoryFilter dimension is "narrowing" —
 *  used by the empty-state card to decide between "No HTTP history
 *  yet" (fresh project) and "No rows match the current filter" (type
 *  loosening suggested). We ignore `limit`/`offset`/`after_id` since
 *  those are pagination controls, not user-visible filter dimensions. */
function hasActiveFilter(f: HistoryFilter): boolean {
  if (f.ts_min_ms != null || f.ts_max_ms != null) return true;
  if (f.resp_size_min != null || f.resp_size_max != null) return true;
  if (f.content_type_classes && f.content_type_classes.length > 0) return true;
  if (f.error_only) return true;
  if (f.host_contains && f.host_contains.trim() !== "") return true;
  if (f.method && f.method.trim() !== "") return true;
  if (f.status_min != null || f.status_max != null) return true;
  if (f.status_classes && f.status_classes.length > 0) return true;
  if (f.highlighted_only) return true;
  if (f.commented_only) return true;
  if (f.content_type_contains && f.content_type_contains.trim() !== "")
    return true;
  if (f.source && f.source.trim() !== "") return true;
  if (f.in_scope_only) return true;
  if (f.search_text && f.search_text.trim() !== "") return true;
  if (f.tag && f.tag.trim() !== "") return true;
  return false;
}

export function HistoryPanel() {
  const [rows, setRows] = useState<StoredSummary[]>([]);
  const [filter, setFilter] = useState<HistoryFilter>({ limit: 1000 });
  const [selected, setSelected] = useState<StoredSummary | null>(null);
  const [tx, setTx] = useState<TransactionView | null>(null);
  const [auto, setAuto] = useState(true);
  // Burp-style click-to-sort column headers. Default `id` + `desc`
  // mirrors the backend's natural order (newest first).
  const [sortKey, setSortKey] = useState<SortKey>("id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(DESC_FIRST_KEYS.has(key) ? "desc" : "asc");
    }
  }
  const [menu, setMenu] = useState<MenuState<StoredSummary> | null>(null);
  const [commentDraft, setCommentDraft] = useState<{ id: number; text: string } | null>(null);
  const [scope, setScope] = useState<Scope | null>(null);
  useEffect(() => {
    api.scopeGet().then(setScope).catch(() => setScope(null));
  }, []);
  // Mirror of the ProjectConfig::record_out_of_scope toggle so the
  // toolbar can show a pill while out-of-scope traffic is being
  // suppressed. The backend atomic is the source of truth — writes
  // from either SettingsPanel or the pill's toggle button update it
  // and the next 5-s poll reflects the change. Silent on error so
  // "no project loaded" doesn't flash an alert.
  const [suppressOos, setSuppressOos] = useState(false);
  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const v = await api.historySuppressOosGet();
        if (alive) setSuppressOos(v);
      } catch {
        /* no project yet — keep the stale value */
      }
    };
    void pull();
    const t = setInterval(pull, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  const resumeRecording = async () => {
    try {
      await api.historySuppressOosSet(false);
      setSuppressOos(false);
    } catch (e) {
      alert(`Could not resume: ${e}`);
    }
  };
  // Column visibility — Set of hidden column keys. Backend stores
  // the hidden list (empty = everything visible) so legacy project
  // files round-trip cleanly through serde defaults. Hydrated once
  // on mount; every subsequent toggle fires `historyColumnsSet` so
  // the config stays in sync without a save step.
  const [hiddenColumns, setHiddenColumns] = useState<Set<string>>(new Set());
  // R137: Ctrl+F focuses the search input. Operators coming from
  // Burp expect browser-style find-in-page to narrow the history
  // view instead of popping the native browser's find dialog.
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    function onFind(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      if (e.key.toLowerCase() !== "f") return;
      // Only hijack when the operator isn't already typing in a
      // different text input — a search inside the comment editor
      // deserves the native browser find, not panel navigation.
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      const alreadyEditing =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable;
      // Allow re-fire when the operator is already in our own
      // search box (so Ctrl+F selects-all for easy replace).
      const inOurSearch = el === searchInputRef.current;
      if (alreadyEditing && !inOurSearch) return;
      const input = searchInputRef.current;
      if (!input) return;
      e.preventDefault();
      input.focus();
      input.select();
    }
    document.addEventListener("keydown", onFind);
    return () => document.removeEventListener("keydown", onFind);
  }, []);
  useEffect(() => {
    api
      .historyColumnsGet()
      .then((hidden) => setHiddenColumns(new Set(hidden ?? [])))
      .catch(() => {
        /* no project yet — stay empty, defaults to show-all */
      });
  }, []);
  const toggleColumnVisible = (key: string) => {
    setHiddenColumns((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      // Fire-and-forget persist; silent on error so a transient blip
      // keeps the UI responsive — the next successful toggle will
      // sync it anyway.
      void api.historyColumnsSet([...next]).catch(() => {});
      return next;
    });
  };
  // Memoised list of visible columns so the table render doesn't
  // re-filter on every row paint.
  const visibleColumns = useMemo(
    () => HISTORY_COLUMNS.filter((c) => !hiddenColumns.has(c.key)),
    [hiddenColumns],
  );

  // Columns-dropdown open/close state. The dropdown is a plain
  // absolute-positioned panel beneath the toolbar button; it closes
  // on outside-click or Escape so the operator can toggle multiple
  // columns in one go without the menu auto-dismissing (which
  // FloatingMenu would do on item click).
  const [columnsMenuOpen, setColumnsMenuOpen] = useState(false);
  useEffect(() => {
    if (!columnsMenuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      const t = e.target as Node;
      const btn = document.querySelector("[data-columns-btn]");
      const pop = document.querySelector("[data-columns-popover]");
      if (btn && btn.contains(t)) return;
      if (pop && pop.contains(t)) return;
      setColumnsMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setColumnsMenuOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [columnsMenuOpen]);
  // Cross-panel handoff: Scanner Issues / Target can dispatch
  // `burpfree:history-focus` with { id } to pop the matching row into
  // the detail pane. If the row isn't in the current filter window
  // we clear filters and refetch — otherwise the operator stares at
  // an empty list wondering what the menu did.
  useEffect(() => {
    const onFocus = async (e: Event) => {
      const detail = (e as CustomEvent<{ id?: number }>).detail;
      const id = detail?.id;
      if (typeof id !== "number") return;
      // First, see if the row is already visible.
      let row = rows.find((r) => r.id === id);
      if (!row) {
        // Reload without filters so we're guaranteed to see the row.
        try {
          const fresh = await api.historyList({ limit: 1000 });
          setRows(fresh);
          row = fresh.find((r) => r.id === id);
        } catch {}
      }
      if (row) setSelected(row);
    };
    window.addEventListener("burpfree:history-focus", onFocus as EventListener);
    return () =>
      window.removeEventListener(
        "burpfree:history-focus",
        onFocus as EventListener,
      );
  }, [rows]);

  // Cross-panel handoff from SiteMap "Open host in HTTP history" and
  // potentially other panels: merge the host (and future-proof: other
  // fields) into the filter so the operator lands here pre-narrowed.
  // One-shot event — the filter stays until the operator clears it.
  useEffect(() => {
    const onFilter = (e: Event) => {
      // R217 extended the detail payload with `status_class` (a 1..5
      // bucket digit, matching StatusClassChips' encoding) so the
      // Dashboard R162 status-code chips can deep-link into History
      // pre-narrowed. A `method` passthrough is also handy for the
      // R210 methods card (ships separately as needed).
      // R264 extended the detail payload with status_min / status_max
      // so the Dashboard "Top status codes" card can deep-link into
      // History pre-narrowed to the exact code (both bounds collapsed
      // to the same number). This coexists with the R217 status_class
      // path — callers pick one or the other depending on whether
      // they want a bucket (status_class=4) or a specific code
      // (status_min=404, status_max=404). When exact codes are set
      // the status_classes array is cleared so the two filters don't
      // narrow against each other.
      //
      // R273 further extended with search_text so the Dashboard
      // "Top paths" card can deep-link into History pre-narrowed
      // to requests whose URL (or any indexed field) contains the
      // path string. The backend uses this as a LIKE %x% probe
      // across method / url / host / path / content-type so a
      // path like /api/users will match every request that touched
      // that endpoint across hosts + methods.
      const detail = (
        e as CustomEvent<{
          host?: string;
          scope?: boolean;
          status_class?: number;
          status_min?: number;
          status_max?: number;
          method?: string;
          ts_min_ms?: number;
          ts_max_ms?: number;
          search_text?: string;
        }>
      ).detail;
      if (!detail) return;
      setFilter((prev) => ({
        ...prev,
        host_contains: detail.host ?? prev.host_contains,
        in_scope_only:
          detail.scope != null ? detail.scope || undefined : prev.in_scope_only,
        status_classes:
          detail.status_min != null || detail.status_max != null
            ? undefined
            : detail.status_class != null
              ? [detail.status_class]
              : prev.status_classes,
        status_min: detail.status_min ?? prev.status_min,
        status_max: detail.status_max ?? prev.status_max,
        method: detail.method ?? prev.method,
        ts_min_ms: detail.ts_min_ms ?? prev.ts_min_ms,
        ts_max_ms: detail.ts_max_ms ?? prev.ts_max_ms,
        search_text: detail.search_text ?? prev.search_text,
      }));
    };
    window.addEventListener("burpfree:history-filter", onFilter as EventListener);
    return () =>
      window.removeEventListener(
        "burpfree:history-filter",
        onFilter as EventListener,
      );
  }, []);
  async function reloadScope() {
    try { setScope(await api.scopeGet()); } catch {}
  }
  async function addHostToScope(r: StoredSummary) {
    try {
      await api.scopeAddRule(buildHostIncludeRule(r.host));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }
  async function addPathToScope(r: StoredSummary) {
    try {
      await api.scopeAddRule(buildPathIncludeRule(r.host, r.path));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }
  async function removeHostFromScope(r: StoredSummary) {
    if (!scope) return;
    try {
      await api.scopeSet(withoutHost(scope, r.host));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }
  // Multi-select state. `selectedIds` is a stable set across refreshes so
  // auto-refresh doesn't wipe the operator's bulk pick. `lastClickId`
  // anchors Shift+click range extension.
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [lastClickId, setLastClickId] = useState<number | null>(null);

  /** Click handler that keeps three UX paths crisp:
   *   plain click    → single-select, replace set
   *   Ctrl/Cmd+click → toggle this id in the current set
   *   Shift+click    → range-select from `lastClickId` to this row (inclusive)
   * All three also update `selected` (for the viewer pane) to the clicked row. */
  function onRowClick(e: React.MouseEvent, r: StoredSummary) {
    const idList = rows.map((x) => x.id);
    const thisIdx = idList.indexOf(r.id);
    setSelected(r);
    if (e.shiftKey && lastClickId != null) {
      const anchorIdx = idList.indexOf(lastClickId);
      if (anchorIdx >= 0 && thisIdx >= 0) {
        const [lo, hi] = anchorIdx < thisIdx ? [anchorIdx, thisIdx] : [thisIdx, anchorIdx];
        const next = new Set(selectedIds);
        for (let i = lo; i <= hi; i++) next.add(idList[i]);
        setSelectedIds(next);
        return;
      }
    }
    if (e.ctrlKey || e.metaKey) {
      const next = new Set(selectedIds);
      if (next.has(r.id)) next.delete(r.id);
      else next.add(r.id);
      setSelectedIds(next);
      setLastClickId(r.id);
      return;
    }
    setSelectedIds(new Set([r.id]));
    setLastClickId(r.id);
  }

  function clearSelection() {
    setSelectedIds(new Set());
    setLastClickId(null);
  }

  async function refresh() {
    const list = await api.historyList(filter);
    setRows(list);
    // Keep the selected row's `highlight` / `comment` fresh after an
    // update so the editor pane doesn't lag the row list.
    if (selected) {
      const found = list.find((r) => r.id === selected.id);
      if (found) setSelected(found);
    }
  }
  useEffect(() => { refresh(); }, [filter]);

  useEffect(() => {
    if (!auto) return;
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [auto, filter]);

  useEffect(() => {
    if (selected) api.historyShow(selected.id).then(setTx).catch(() => setTx(null));
    else setTx(null);
  }, [selected?.id]);

  // Apply the column sort client-side. Stable fallback on `id` so
  // ties stay deterministic across re-sorts. Null-safe: `null` and
  // `undefined` always sort last regardless of direction.
  const sortedRows = useMemo(() => {
    if (rows.length === 0) return rows;
    const dir = sortDir === "asc" ? 1 : -1;
    const keyOf = (r: StoredSummary): string | number | null => {
      switch (sortKey) {
        case "id":
          return r.id;
        case "method":
          return r.method ?? "";
        case "proto":
          return r.http_version ?? "";
        case "status":
          return r.status ?? null;
        case "host":
          return `${r.host ?? ""}:${r.port ?? 0}`;
        case "path":
          return r.path ?? "";
        case "size":
          return r.content_length ?? null;
        case "time":
          return r.elapsed_ms ?? null;
        case "comment":
          return r.comment ?? "";
        case "highlight":
          return r.highlight ?? "";
        default:
          return r.id;
      }
    };
    const copy = rows.slice();
    copy.sort((a, b) => {
      const av = keyOf(a);
      const bv = keyOf(b);
      // Null / undefined always sorts last — direction-independent.
      const aNil = av === null || av === undefined || av === "";
      const bNil = bv === null || bv === undefined || bv === "";
      if (aNil && bNil) return a.id - b.id;
      if (aNil) return 1;
      if (bNil) return -1;
      let cmp = 0;
      if (typeof av === "number" && typeof bv === "number") {
        cmp = av - bv;
      } else {
        cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      }
      if (cmp !== 0) return cmp * dir;
      // Stable fallback by id for ties.
      return a.id - b.id;
    });
    return copy;
  }, [rows, sortKey, sortDir]);

  const stats = useMemo(() => {
    const by: Record<string, number> = {};
    for (const r of rows) {
      const code = r.status ? Math.floor(r.status / 100) : 0;
      by[code] = (by[code] || 0) + 1;
    }
    return by;
  }, [rows]);

  // Keyboard row navigation: ↑ / ↓ step one row, Home / End jump to
  // the ends. Mirror of Burp's HTTP history keyboard pattern. Document-
  // level listener because the <tr> rows aren't individually focusable;
  // the HistoryPanel only mounts when `section === "history"` (App.tsx
  // ternary), so the listener is implicitly scoped to that section
  // without checking any global. We bail out when the operator is
  // typing in a text input / textarea / select / contenteditable so
  // the filter box + inline comment editor keep native caret motion.
  // The handler walks `sortedRows` (what the operator actually sees),
  // updates `selected` + `selectedIds` to the single new row, and
  // scrolls the new <tr> into view via a `data-row-id` lookup so the
  // row doesn't fall off the top / bottom of the scrollable table.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // R216: text-input focus skip is a hard gate — never consume
      // keystrokes meant for a focused editor. Modifier gating is
      // branch-specific now so Alt+digit can light up quick-highlight
      // (R216) while Ctrl/Meta still bail out globally.
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        if (el.isContentEditable) return;
      }
      // R262: Alt+Shift+1..5 toggles the status-class filter chip
      // for the matching HTTP bucket (1=1xx info, 2=2xx success,
      // 3=3xx redirect, 4=4xx client error, 5=5xx server error).
      // Alt+Shift+0 clears every chip in one key. Mirrors R230
      // (Scanner sev), R231 (Intruder mode), R232 (Target Issues
      // sev), R233 (Collaborator kind), R235 (Logger kind) — same
      // one-stroke chip-toggle convention, but offset by Shift so
      // the plain Alt+digit keys stay reserved for R216's highlight
      // palette. Toggle semantics match the StatusClassChips click
      // handler so keyboard + mouse land on the same state. Must
      // come BEFORE the Alt-only block below so Shift gating is
      // honored in the right order.
      if (e.altKey && e.shiftKey && !e.ctrlKey && !e.metaKey) {
        const digit = e.key;
        if (digit === "0") {
          e.preventDefault();
          setFilter({ ...filter, status_classes: undefined });
          return;
        }
        const bucket = parseInt(digit, 10);
        if (Number.isFinite(bucket) && bucket >= 1 && bucket <= 5) {
          e.preventDefault();
          const current = new Set(filter.status_classes ?? []);
          if (current.has(bucket)) current.delete(bucket);
          else current.add(bucket);
          const arr = Array.from(current).sort((a, b) => a - b);
          setFilter({
            ...filter,
            status_classes: arr.length ? arr : undefined,
          });
          return;
        }
        // Alt+Shift + non-digit — stay out of the way of other
        // handlers (e.g. the browser's built-in Shift combos).
        return;
      }
      // R216: Alt+1..7 applies the color at that slot to the active
      // row (or bulk-selection when multi-selected). Alt+0 clears
      // the highlight. Keys-of-HIGHLIGHT_COLORS is iteration-order-
      // stable in modern engines so the mapping 1→red, 2→orange,
      // 3→yellow, 4→green, 5→cyan, 6→blue, 7→purple is deterministic
      // across restarts. Mirrors Burp's "Highlight by colour"
      // context-menu subset, delivered as a one-stroke shortcut for
      // triage-heavy workflows. Must come BEFORE the Ctrl/Meta
      // bail-out below so Alt as a modifier can land here.
      if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
        const digit = e.key;
        if (digit === "0") {
          e.preventDefault();
          if (selectedIds.size > 1) {
            void bulkHighlight(null);
          } else if (selected) {
            void setHighlight(selected, null);
          }
          return;
        }
        const idx = parseInt(digit, 10);
        if (
          Number.isFinite(idx) &&
          idx >= 1 &&
          idx <= Object.keys(HIGHLIGHT_COLORS).length
        ) {
          e.preventDefault();
          const name = Object.keys(HIGHLIGHT_COLORS)[idx - 1];
          if (selectedIds.size > 1) {
            void bulkHighlight(name);
          } else if (selected) {
            void setHighlight(selected, name);
          }
          return;
        }
        // Alt + a non-digit — stay out of the way of other handlers.
        return;
      }
      if (e.ctrlKey || e.metaKey) return;
      // Delete key: nuke the current bulk selection via the existing
      // bulkDelete helper (which handles the confirm + API call +
      // selection reset). Guarded on an empty selection so an idle
      // Delete press doesn't cost the operator a modal they'd just
      // dismiss. Mirrors Burp's HTTP history where the key is wired
      // straight to the "Delete selected items" context-menu action.
      if (e.key === "Delete" && selectedIds.size > 0) {
        e.preventDefault();
        void bulkDelete();
        return;
      }
      // R208: J / K vim-style aliases for ArrowDown / ArrowUp —
      // consistent with R197 (Scanner J/K) + the vim-ergonomic
      // convention operators coming from Gmail / GitHub / Burp Pro
      // already know. Case-insensitive on purpose so a stuck
      // CapsLock doesn't surprise anyone.
      const key = e.key;
      const isJ = key === "j" || key === "J";
      const isK = key === "k" || key === "K";
      if (
        key !== "ArrowUp" &&
        key !== "ArrowDown" &&
        key !== "Home" &&
        key !== "End" &&
        !isJ &&
        !isK
      )
        return;
      if (sortedRows.length === 0) return;
      const curIdx = selected ? sortedRows.findIndex((r) => r.id === selected.id) : -1;
      let nextIdx = curIdx;
      if (key === "ArrowUp" || isK) {
        nextIdx = curIdx <= 0 ? 0 : curIdx - 1;
      } else if (key === "ArrowDown" || isJ) {
        nextIdx = curIdx < 0 ? 0 : Math.min(sortedRows.length - 1, curIdx + 1);
      } else if (key === "Home") {
        nextIdx = 0;
      } else if (key === "End") {
        nextIdx = sortedRows.length - 1;
      }
      if (nextIdx === curIdx || nextIdx < 0) return;
      e.preventDefault();
      const next = sortedRows[nextIdx];
      setSelected(next);
      setSelectedIds(new Set([next.id]));
      setLastClickId(next.id);
      // Scroll on the next frame so the DOM has `.selected` applied.
      // `block: nearest` keeps the row from jumping to the top on
      // every arrow press — only scrolls when the row is actually
      // off-screen.
      requestAnimationFrame(() => {
        const tr = document.querySelector(
          `tr[data-row-id="${next.id}"]`,
        ) as HTMLElement | null;
        tr?.scrollIntoView({ block: "nearest" });
      });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // Delete-key branch reads selectedIds + bulkDelete closures;
    // re-register whenever either changes so a stale selection
    // doesn't trip a confirm with the wrong count. R262's Alt+Shift
    // status-class branch reads `filter` so re-register on filter
    // change too — otherwise the toggle closure sees stale chips.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortedRows, selected?.id, selectedIds, filter]);

  // R365: Alt+Shift+F toggles the "commented-only" filter —
  // operators who annotated rows with R169 comments or R339 bulk
  // comments want a one-key way to zoom into just those rows.
  // Mirror of R354 Alt+Shift+H but for the comment filter axis.
  // **Guards + text-input skip** mirror R354 / R349.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "F" && e.key !== "f") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      e.preventDefault();
      setFilter((prev) => ({
        ...prev,
        commented_only: prev.commented_only ? undefined : true,
      }));
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // R437: Alt+Shift+I inverts the bulk selection across the
  // current filtered + sorted view — cross-panel mirror of R415
  // Scanner Alt+Shift+I. Operators who want "everything EXCEPT
  // these three" workflow (narrow filter → walk to 3 outliers →
  // click each → Alt+Shift+I → bulk flips to complement) now
  // have a one-key path for this common inversion on History
  // too. **Letter choice** I = Invert. **Scope** `sortedRows`
  // (the display order after filter + sort) so operators who
  // narrowed via host / method / status-class / scope / search
  // chips get the invert within just the visible subset.
  // **Mechanism** rebuild `selectedIds` from `sortedRows.filter(r
  // => !prev.has(r.id)).map(r => r.id)` — rows outside the
  // filter stay untouched. **Guards** Alt+Shift only, text-input
  // focus skip. **No-op silent** when `sortedRows` is empty.
  useEffect(() => {
    function onInvertKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "I" && e.key !== "i") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (sortedRows.length === 0) return;
      e.preventDefault();
      setSelectedIds((prev) => {
        const next = new Set<number>();
        for (const r of sortedRows) {
          if (!prev.has(r.id)) next.add(r.id);
        }
        return next;
      });
    }
    document.addEventListener("keydown", onInvertKey);
    return () => document.removeEventListener("keydown", onInvertKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortedRows]);

  // R394: Alt+Shift+P copies every bulk-selected row as a
  // "METHOD /path" line to clipboard — keyboard companion to
  // R377's "📋 Copy method+path" toolbar bulk button. Pairs
  // with R387 Alt+Shift+U to give operators two cross-panel
  // History keyboard shortcuts for the common clipboard dumps:
  // Alt+Shift+U = full URLs, Alt+Shift+P = METHOD /path lines
  // (authz-tester / method-aware wordlist shape). **Scope**
  // `rows.filter(r → selectedIds.has(r.id))` not all filtered
  // rows, mirroring R377's button (which disables when
  // `selectedIds.size === 0`). **Format** `${method} ${path}` so
  // output is Burp-list-friendly (same shape as HTTP request
  // lines) — great for a crafted Intruder run or an authz-tester
  // input file. **Dedupe + sort alpha** for diff-friendly stable
  // output. **TDZ workaround** `selectedRows` is declared later
  // in file order, compute `rows.filter(...)` inline (same
  // pattern as R387). **Guards + text-input skip** mirror R387.
  // **No-op silent** when nothing selected.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "P" && e.key !== "p") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      const picked = rows.filter((r) => selectedIds.has(r.id));
      if (picked.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(picked.map((r) => `${r.method} ${r.path}`)),
          ).sort();
          await navigator.clipboard.writeText(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, selectedIds]);

  // R387: Alt+Shift+U copies every bulk-selected row's URL to
  // clipboard — keyboard companion to R353's "📋 Copy URLs"
  // toolbar button. Pairs with the Alt+Shift+U keystroke in
  // Repeater (R386) so operators get a consistent cross-panel
  // "copy URL batch" muscle memory: Alt+Shift+U copies the
  // currently-visible URL batch, scoped to the panel's primary
  // selection concept (Repeater: all tabs; History: bulk-
  // selected rows). **Scope** `selectedRows` not `rows` so
  // operators always know which URLs they're copying — mirrors
  // R353's button exactly (which is disabled when
  // `selectedIds.size === 0`). **Mechanism** `${scheme}://${host}${path}`
  // reconstruction + `Set` dedupe + `sort` for diff-friendly
  // stable output. **Guards + text-input skip** mirror R354 /
  // R349 / R365. **No-op when nothing selected** silent — the
  // keystroke stays safe to spam during ramp-up.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "U" && e.key !== "u") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      // selectedRows is defined later in the file (after this
      // effect), so compute it inline here from the primitives
      // this handler closes over — React's commit order means
      // the dep array still catches updates via `rows` + `selectedIds`.
      const picked = rows.filter((r) => selectedIds.has(r.id));
      if (picked.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(
              picked.map((r) => `${r.scheme}://${r.host}${r.path}`),
            ),
          ).sort();
          await navigator.clipboard.writeText(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, selectedIds]);

  // R354: Alt+Shift+H toggles the "highlighted-only" filter —
  // operators marking a session's interesting rows via Alt+1..7
  // (R216) want a one-key way to zoom into just the marked set
  // without walking the toolbar's commented/highlighted
  // checkboxes. Toggle semantics: on → off → on. **Guards +
  // text-input skip** mirror R349.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "H" && e.key !== "h") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      e.preventDefault();
      setFilter((prev) => ({
        ...prev,
        highlighted_only: prev.highlighted_only ? undefined : true,
      }));
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // R349: Alt+C clears every active filter in one keystroke —
  // keyboard version of the R240 "⨯ clear N filters" ghost
  // button. Operators pivoting filter sets a lot during triage
  // (host + status class + method + search) want a one-key
  // reset without a mouse pivot. **Mechanism** resets filter
  // state to just the limit field — matches the R240 click
  // behaviour exactly. **Guards** plain Alt only, text-input
  // focus skip so Alt+C inside the Host / Search box doesn't
  // nuke the current filter while the operator was typing.
  // **No-op when no filter is active** short-circuit so the
  // keystroke doesn't trigger a refresh on a clean panel.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "c" && e.key !== "C") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      // Check if any filter is active — mirrors the R240 button's
      // visibility logic.
      const hasActive =
        !!filter.host_contains ||
        !!filter.method ||
        !!filter.source ||
        !!filter.status_classes?.length ||
        filter.status_min != null ||
        filter.status_max != null ||
        !!filter.content_type_contains ||
        !!filter.search_text ||
        !!filter.in_scope_only ||
        !!filter.highlighted_only ||
        !!filter.commented_only;
      if (!hasActive) return;
      e.preventDefault();
      setFilter({ limit: filter.limit ?? 1000 });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  // R329: Ctrl+A selects every row in the current filtered view —
  // parallel to R328 Scanner Ctrl+A. Chains cleanly with every
  // bulk op already in the toolbar: Export CSV, Export JSONL,
  // Export HAR, → Repeater, Compare first two, Delete, Highlight ▾,
  // R320 + Add tag. Scoped to `sortedRows` (what the operator
  // actually sees after host / method / status-class / scope /
  // search filters apply) — matches Burp Pro's own HTTP history
  // "Select all" context-menu which also respects the filter.
  // Guards mirror R328: no Meta/Alt/Shift combos, bail inside
  // text inputs / textareas / contenteditables (so Ctrl+A in the
  // filter box or comment modal keeps native select-all).
  useEffect(() => {
    function onCtrlA(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key !== "a" && e.key !== "A") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (sortedRows.length === 0) return;
      e.preventDefault();
      setSelectedIds(new Set(sortedRows.map((r) => r.id)));
    }
    document.addEventListener("keydown", onCtrlA);
    return () => document.removeEventListener("keydown", onCtrlA);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortedRows]);

  function onRowContextMenu(e: React.MouseEvent, r: StoredSummary) {
    e.preventDefault();
    setSelected(r);
    setMenu({ x: e.clientX, y: e.clientY, data: r });
  }

  async function sendToRepeater(r: StoredSummary) {
    try {
      const url = urlFromSummary(r);
      const name = `${r.method} ${r.host}${r.path}`;
      await api.repeaterAddTab(name, url);
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } catch (err) {
      alert(`${err}`);
    }
  }

  // "Replay request" — re-fire the stored bytes through the shared
  // HTTP client without opening a Repeater tab. The backend records
  // the result as a fresh history row with annotation "replayed from
  // #<orig>". We refresh then try to pop the new row into the detail
  // pane; the id comes back from the cmd so we can select it even
  // when it falls outside the current filter window (which would
  // normally hide it until refresh picks it up).
  async function replayRow(r: StoredSummary) {
    try {
      const newId = await api.historyReplay(r.id);
      await refresh();
      // Dispatch the cross-panel focus event so the row selection
      // runs through the same code path other panels use (Scanner,
      // Target). If the row isn't in the current filter window the
      // focus handler clears filters and refetches.
      window.dispatchEvent(
        new CustomEvent("burpfree:history-focus", { detail: { id: newId } }),
      );
    } catch (err) {
      alert(`Replay failed: ${err}`);
    }
  }

  // Ctrl+R / Ctrl+I quick-sends — fire against the currently-selected
  // row (same semantics as the context-menu entries). We stay quiet
  // when no row is active so the hotkey can silently fall through to
  // another listener in another panel.
  useEffect(() => {
    const onR = () => { if (selected) void sendToRepeater(selected); };
    const onI = () => { if (selected) void sendToIntruder(selected); };
    window.addEventListener("burpfree:send-to-repeater", onR as EventListener);
    window.addEventListener("burpfree:send-to-intruder", onI as EventListener);
    return () => {
      window.removeEventListener("burpfree:send-to-repeater", onR as EventListener);
      window.removeEventListener("burpfree:send-to-intruder", onI as EventListener);
    };
  }, [selected?.id]);

  async function sendToIntruder(r: StoredSummary) {
    const url = urlFromSummary(r);
    window.dispatchEvent(
      new CustomEvent("burpfree:intruder-load", {
        detail: { url, method: r.method, transactionId: r.id },
      }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "intruder" } }),
    );
  }

  async function sendToComparerAction(r: StoredSummary, slot: "left" | "right") {
    try {
      const view = await api.historyShow(r.id);
      const label = `${r.method} ${r.host}${r.path}`;
      // ComparerPanel listens for `burpfree:comparer-load` with
      // {left,right,label}. For single-slot sends we fill one side
      // and leave the other alone — the receiving panel merges only
      // the fields present in the detail payload.
      window.dispatchEvent(
        new CustomEvent("burpfree:comparer-load", {
          detail:
            slot === "left"
              ? { left: view.request_raw ?? "", right: "", label }
              : { left: "", right: view.request_raw ?? "", label },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
      );
    } catch (err) {
      alert(`${err}`);
    }
  }

  /// Fire every enabled active probe against this stored row.
  /// Burp's "Do active scan" context-menu entry. Returns an
  /// `ActiveScanReport` instead of erroring on the "no probes"
  /// / "out of scope" cases so operators see a quiet notice rather
  /// than an alert. Findings land in the project history via
  /// fingerprint upsert so running twice on the same row dedupes.
  async function activeScanRow(r: StoredSummary) {
    try {
      const report = await api.scannerActiveRunTx(r.id);
      if (report.skipped_reason) {
        // Non-error short-circuit — show a quiet info notice so the
        // operator knows nothing fired. Keep it as a native alert
        // for now (same style as the other context-menu handlers).
        alert(`Active scan skipped: ${report.skipped_reason}`);
        return;
      }
      alert(
        `Active scan complete — ${report.findings_added} new finding${
          report.findings_added === 1 ? "" : "s"
        } across ${report.probes_run} probe${
          report.probes_run === 1 ? "" : "s"
        }.`,
      );
    } catch (err) {
      alert(`${err}`);
    }
  }

  async function sendToOrganizer(r: StoredSummary) {
    try {
      await api.organizerAdd({
        transaction_id: r.id,
        title: `${r.method} ${r.host}${r.path}`,
      });
      console.info(`saved tx #${r.id} to Organizer Inbox`);
    } catch (err) {
      alert(`${err}`);
    }
  }

  async function copyAs(r: StoredSummary, kind: "url" | "curl" | "powershell" | "python" | "fetch" | "har") {
    try {
      if (kind === "url") {
        await copyToClipboard(urlFromSummary(r));
        return;
      }
      // R470: HAR branch needs both request_raw + response_raw to
      // produce a complete HAR entry; the per-command kinds only
      // need request_raw so we keep the common fetch below but
      // branch out when the caller asks for HAR. Mirrors R453's
      // bulk-HAR fan-out logic one-row at a time.
      if (kind === "har") {
        let view: Awaited<ReturnType<typeof api.historyShow>> | null = null;
        try {
          view = await api.historyShow(r.id);
        } catch (err) {
          alert(`Could not resolve request/response bytes for history row #${r.id}: ${err}`);
          return;
        }
        if (!view?.request_raw) {
          alert(`History row #${r.id} has no stored request_raw — cannot build a HAR entry.`);
          return;
        }
        const req = fromSummaryAndRaw(r, view.request_raw);
        let resp: Parameters<typeof buildHarEntry>[2] = undefined;
        if (view.response_raw) {
          const text = view.response_raw.replace(/\r\n/g, "\n");
          const headerEnd = text.indexOf("\n\n");
          const headerBlock = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
          const body = headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
          const lines = headerBlock.split("\n");
          const statusLine = (lines.shift() ?? "").trim();
          const m = statusLine.match(/^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/);
          const httpVersion = m?.[1] ?? "HTTP/1.1";
          const status = m ? parseInt(m[2], 10) : 0;
          const statusText = m?.[3] ?? "";
          const headers: Array<[string, string]> = [];
          let mimeType = "";
          for (const l of lines) {
            const colon = l.indexOf(":");
            if (colon <= 0) continue;
            const n = l.slice(0, colon).trim();
            const v = l.slice(colon + 1).trim();
            if (!n) continue;
            headers.push([n, v]);
            if (n.toLowerCase() === "content-type") mimeType = v;
          }
          resp = { status, statusText, httpVersion, headers, mimeType, body };
        }
        const startedDateTime = new Date(r.ts_ms).toISOString();
        const entry = buildHarEntry(req, startedDateTime, resp);
        const har = buildHarLog([entry]);
        await copyToClipboard(JSON.stringify(har, null, 2));
        return;
      }
      let raw = "";
      try {
        const view = await api.historyShow(r.id);
        raw = view.request_raw ?? "";
      } catch {
        // ignore
      }
      const req = fromSummaryAndRaw(r, raw);
      const out =
        kind === "curl"
          ? buildCurl(req)
          : kind === "powershell"
            ? buildPowerShell(req)
            : kind === "fetch"
              ? buildFetch(req)
              : buildPython(req);
      await copyToClipboard(out);
    } catch (err) {
      alert(`${err}`);
    }
  }

  // R515: HistoryPanel row-right-click "⬇ Save as HAR file" —
  // file-save variant of R470 clipboard. Completes HistoryPanel's
  // clip + file HAR row pair, parallel to Scanner (R482 clip +
  // R507 file), Target Issues (R483 clip + R508 file), Logger
  // (R506 clip + R509 file), and ProxyPanel (R513 clip + R514
  // file). HistoryPanel now carries the full HAR surface at every
  // level: row clipboard (R470) + row file (R515) + bulk
  // clipboard (R453) + bulk file (R490) — four input paths per
  // panel, more than any other. Mechanism matches R470 exactly
  // for the HAR 1.2 build (`historyShow` → `fromSummaryAndRaw` →
  // inline response-parse → `buildHarEntry` → `buildHarLog`) and
  // matches R507/R508/R509/R514 for the on-disk save
  // (`Blob` → `URL.createObjectURL` → anchor click → revoke).
  // **Filename pattern** `history-har-tx-<id>.har` — tx id is the
  // canonical identifier for a HistoryPanel row and parallels
  // R509 Logger's `logger-har-tx-<id>.har` + R514 Proxy's
  // `proxy-har-tx-<id>.har` naming scheme. The `history-` prefix
  // distinguishes these per-row dumps from R490's bulk
  // `burpfree-har-<timestamp>.har` so operators archiving both
  // flavors keep them identifiable.
  async function saveAsHar(r: StoredSummary) {
    try {
      const view = await api.historyShow(r.id);
      if (!view?.request_raw) {
        alert(
          `History row #${r.id} has no stored request_raw — cannot build a HAR entry.`,
        );
        return;
      }
      const req = fromSummaryAndRaw(r, view.request_raw);
      let resp: Parameters<typeof buildHarEntry>[2] = undefined;
      if (view.response_raw) {
        const text = view.response_raw.replace(/\r\n/g, "\n");
        const headerEnd = text.indexOf("\n\n");
        const headerBlock = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
        const body = headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
        const lines = headerBlock.split("\n");
        const statusLine = (lines.shift() ?? "").trim();
        const m = statusLine.match(/^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/);
        const httpVersion = m?.[1] ?? "HTTP/1.1";
        const status = m ? parseInt(m[2], 10) : 0;
        const statusText = m?.[3] ?? "";
        const headers: Array<[string, string]> = [];
        let mimeType = "";
        for (const l of lines) {
          const colon = l.indexOf(":");
          if (colon <= 0) continue;
          const n = l.slice(0, colon).trim();
          const v = l.slice(colon + 1).trim();
          if (!n) continue;
          headers.push([n, v]);
          if (n.toLowerCase() === "content-type") mimeType = v;
        }
        resp = { status, statusText, httpVersion, headers, mimeType, body };
      }
      const startedDateTime = new Date(r.ts_ms).toISOString();
      const entry = buildHarEntry(req, startedDateTime, resp);
      const har = buildHarLog([entry]);
      const name = `history-har-tx-${r.id}.har`;
      const blob = new Blob([JSON.stringify(har, null, 2)], {
        type: "application/json;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`${err}`);
    }
  }

  /** Fetch the response body for `r`, write it to a temp file via
   *  the backend, and ask the OS default handler to open it. Burp-
   *  parity "Open in browser" workflow — one click from the history
   *  row to a rendered page. Content-Type is parsed out of the raw
   *  response block so an HTML response renders, JSON gets a JSON
   *  viewer, etc. */
  async function openResponseInBrowser(r: StoredSummary) {
    try {
      const view = await api.historyShow(r.id);
      const raw = view.response_raw ?? "";
      if (!raw.trim()) {
        alert("No stored response body for this row — nothing to open.");
        return;
      }
      // Split head / body on the first blank line (CRLF-aware).
      const idx = raw.search(/\r?\n\r?\n/);
      const head = idx >= 0 ? raw.slice(0, idx) : raw;
      const body = idx >= 0 ? raw.slice(idx).replace(/^\r?\n\r?\n/, "") : "";
      const ctLine = head
        .split(/\r?\n/)
        .find((l) => /^content-type\s*:/i.test(l));
      const contentType = ctLine
        ? ctLine.replace(/^content-type\s*:\s*/i, "").trim()
        : "text/html";
      await api.responseOpenInBrowser({
        content: body || raw,
        contentType,
        label: `${r.host}${r.path}`,
      });
    } catch (err) {
      alert(`Could not open response in browser: ${err}`);
    }
  }

  /** Ask the OS default browser to fetch the request URL fresh —
   *  Burp's "Request in browser → current browser session". The
   *  backend validates http/https + length + control chars so a
   *  mis-shaped row (file:// scheme / embedded CRLF) can't be
   *  weaponised into shell injection. The URL is reconstructed from
   *  the stored summary via `urlFromSummary` so an edited path /
   *  query string survives round-trip through the history row. */
  async function requestInBrowser(r: StoredSummary) {
    try {
      const url = urlFromSummary(r);
      await api.shellOpenUrl(url);
    } catch (err) {
      alert(`Could not open request URL in browser: ${err}`);
    }
  }

  /** Burp-style "Save response" — binary-safe write of the stored
   *  response bytes to a path the operator chooses. `includeHeaders`
   *  toggles between body-only (good for binary payloads: PDFs,
   *  PNGs, mp4s) and raw-wire dump (good for debugging HTTP
   *  semantics). Derives a sensible default filename from host +
   *  last-path-segment + tx_id + extension. The extension comes
   *  from Content-Type via the same whitelist R79's
   *  `openResponseInBrowser` uses so the saved file opens with the
   *  right OS handler. */
  async function saveResponseBody(r: StoredSummary, includeHeaders: boolean) {
    try {
      // Pick an extension off Content-Type. Default to `.bin` for
      // body-only + unknown CT (safer than `.txt` because the OS
      // won't try to open it in a text editor), `.txt` for the
      // raw-wire dump (headers are text so `.txt` is correct).
      const ct = (r.content_type ?? "").toLowerCase().split(";")[0].trim();
      let ext = includeHeaders ? "txt" : "bin";
      if (!includeHeaders) {
        switch (ct) {
          case "text/html":
          case "application/xhtml+xml":
            ext = "html";
            break;
          case "application/json":
            ext = "json";
            break;
          case "application/xml":
          case "text/xml":
            ext = "xml";
            break;
          case "text/css":
            ext = "css";
            break;
          case "application/javascript":
          case "text/javascript":
            ext = "js";
            break;
          case "image/png":
            ext = "png";
            break;
          case "image/jpeg":
            ext = "jpg";
            break;
          case "image/gif":
            ext = "gif";
            break;
          case "image/svg+xml":
            ext = "svg";
            break;
          case "image/webp":
            ext = "webp";
            break;
          case "application/pdf":
            ext = "pdf";
            break;
          case "application/zip":
            ext = "zip";
            break;
          case "application/octet-stream":
            ext = "bin";
            break;
          case "text/plain":
          case "text/csv":
            ext = "txt";
            break;
          default:
            // Fall through to .bin for anything else — safe default.
            break;
        }
      }
      // Build a stable filename stem from host + last path segment.
      const lastSeg =
        (r.path || "/").split("?")[0].split("/").filter(Boolean).pop() ?? "root";
      const stem = `${r.host}-${lastSeg}-${r.id}`
        .replace(/[^a-zA-Z0-9.-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 80);
      const defaultPath = `${stem}.${ext}`;
      const path = prompt(
        includeHeaders
          ? "Save raw response (headers + body) to…"
          : "Save response body to…",
        defaultPath,
      );
      if (!path) return;
      const result = await api.historySaveResponseBody({
        tx_id: r.id,
        path,
        include_headers: includeHeaders,
      });
      alert(
        `Saved ${result.bytes_written.toLocaleString()} bytes to:\n${result.path}`,
      );
    } catch (err) {
      alert(`Save failed: ${err}`);
    }
  }

  async function setHighlight(r: StoredSummary, color: string | null) {
    try {
      await api.historySetHighlight(r.id, color);
      await refresh();
    } catch (err) {
      alert(`${err}`);
    }
  }

  async function saveComment(id: number, text: string) {
    try {
      await api.historySetComment(id, text);
      setCommentDraft(null);
      await refresh();
    } catch (err) {
      alert(`${err}`);
    }
  }

  // ---- Bulk operations ---------------------------------------------------

  const selectedRows = rows.filter((r) => selectedIds.has(r.id));

  async function bulkHighlight(color: string | null) {
    try {
      // Fire all highlight updates concurrently — SQLite serialises the
      // writes internally and this keeps the UI snappy for 100+ rows.
      await Promise.all(
        [...selectedIds].map((id) => api.historySetHighlight(id, color)),
      );
      await refresh();
    } catch (err) {
      alert(`${err}`);
    }
  }

  // R278: Clear every highlight across the currently-fetched rows.
  // Operators who burn through 50-100 colour picks during triage
  // need a one-shot reset — the per-row "Alt+0" from R216 is one-at-
  // a-time and the bulk toolbar only applies to the current
  // multi-selection. This helper walks the full `rows` set, finds
  // rows with any highlight colour set, and nulls them concurrently
  // via api.historySetHighlight(id, null). Confirms pre-fire with
  // the exact victim count because clearing is destructive and the
  // operator may have spent real time annotating.
  async function clearAllHighlights() {
    const victims = rows.filter((r) => !!r.highlight).map((r) => r.id);
    if (victims.length === 0) return;
    if (
      !confirm(
        `Clear highlights on ${victims.length} row${victims.length === 1 ? "" : "s"}? The highlight colour drops back to default — the rows themselves stay.`,
      )
    )
      return;
    try {
      await Promise.all(
        victims.map((id) => api.historySetHighlight(id, null)),
      );
      await refresh();
    } catch (err) {
      alert(`${err}`);
    }
  }

  async function bulkDelete() {
    const n = selectedIds.size;
    if (n === 0) return;
    if (!confirm(`Delete ${n} transaction${n === 1 ? "" : "s"} from history?`)) return;
    try {
      await api.historyDelete([...selectedIds]);
      clearSelection();
      setSelected(null);
      await refresh();
    } catch (err) {
      alert(`${err}`);
    }
  }

  /** R129: Prune errored transactions. Burp's HTTP history has a
   *  "Clear history" action — we have the general bulk delete but
   *  nothing targeted at the "clean up the noise" workflow where an
   *  operator just wants to drop every connection-refused / TLS-
   *  handshake-failed / parse-error row before diffing clean
   *  responses. Pulls the full `error_only=true` list via the
   *  existing filter path (capped at 10k so a hostile scan can't
   *  OOM the client), confirms with the count, and fires
   *  `historyDelete` in one batch. The current filter in `filter`
   *  state is NOT applied — this always deletes every errored row,
   *  matching Burp's "clean the whole project" intent. */
  async function pruneErroredRows() {
    try {
      const errored = await api.historyList({
        error_only: true,
        limit: 10_000,
      });
      if (errored.length === 0) {
        alert("No errored transactions in history — nothing to prune.");
        return;
      }
      if (
        !confirm(
          `Delete ${errored.length} errored transaction${errored.length === 1 ? "" : "s"} from history? This includes connect-refused, TLS handshake fails, parse errors, and upstream resets. Cannot be undone.`,
        )
      ) {
        return;
      }
      const n = await api.historyDelete(errored.map((r) => r.id));
      await refresh();
      alert(`Pruned ${n} errored transaction${n === 1 ? "" : "s"}.`);
    } catch (err) {
      alert(`Prune failed: ${err}`);
    }
  }

  // Export the current bulk selection as a HAR 1.2 file. Pure-cmd
  // path — the backend's export_har_by_ids pulls each tx + its
  // request / response blobs by id, inlines them into the entry
  // list, and writes to disk. Preserves selection order. We prompt
  // the operator for an output path since Tauri 2 doesn't ship a
  // save dialog in Community so a one-click button would need to
  // guess somewhere sensible — the prompt pre-fills with a sane
  // default under the user's home dir.
  async function bulkExportHar() {
    const n = selectedIds.size;
    if (n === 0) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const defaultPath = `burpfree-selection-${stamp}.har`;
    const out = prompt(
      `Export ${n} selected transaction${n === 1 ? "" : "s"} as HAR.\n\nOutput path (absolute preferred; relative resolves against the Tauri process CWD):`,
      defaultPath,
    );
    if (!out) return;
    try {
      const report = await api.harExportIds(out, [...selectedIds]);
      alert(
        `HAR written: ${report.entries} entr${report.entries === 1 ? "y" : "ies"}, ${(
          report.bytes_written / 1024
        ).toFixed(1)} KB.\n→ ${out}`,
      );
    } catch (err) {
      alert(`HAR export failed: ${err}`);
    }
  }

  async function bulkSendToRepeater() {
    if (selectedRows.length === 0) return;
    // 25-tab guardrail: beyond that the Repeater tab bar gets unwieldy
    // and the operator almost certainly meant to narrow their selection.
    // We confirm instead of silently truncating so no requests are lost.
    const SOFT_LIMIT = 25;
    if (selectedRows.length > SOFT_LIMIT) {
      const ok = confirm(
        `${selectedRows.length} rows selected — open ${selectedRows.length} new Repeater tabs?\n` +
          `Click Cancel and pick fewer rows if that's a lot.`,
      );
      if (!ok) return;
    }
    try {
      // Serialise the AddFromHistory calls — Repeater's add_tab holds the
      // tabs lock briefly, and concurrent calls can race against
      // persistence. 25 sequential invokes finishes well under a second.
      for (const r of selectedRows) {
        await api.repeaterAddFromHistory(r.id, `${r.method} ${r.host}${r.path}`);
      }
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } catch (err) {
      alert(`${err}`);
    }
  }

  async function bulkSendToComparer() {
    if (selectedRows.length < 2) {
      alert("Pick at least two rows (Ctrl+click) to compare.");
      return;
    }
    const [a, b] = selectedRows;
    try {
      const [va, vb] = await Promise.all([
        api.historyShow(a.id),
        api.historyShow(b.id),
      ]);
      const label = `${a.method} ${a.host}${a.path}  vs  ${b.method} ${b.host}${b.path}`;
      window.dispatchEvent(
        new CustomEvent("burpfree:comparer-load", {
          detail: {
            left: va.request_raw ?? "",
            right: vb.request_raw ?? "",
            label,
          },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
      );
    } catch (err) {
      alert(`${err}`);
    }
  }

  function bulkExportCsv() {
    if (selectedRows.length === 0) return;
    const headers = [
      "id",
      "ts_ms",
      "method",
      "http_version",
      "scheme",
      "host",
      "port",
      "path",
      "status",
      "content_length",
      "content_type",
      "elapsed_ms",
      "highlight",
      "comment",
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = selectedRows
      .map((r) =>
        [
          r.id,
          r.ts_ms,
          r.method,
          r.http_version ?? "",
          r.scheme,
          r.host,
          r.port,
          r.path,
          r.status ?? "",
          r.content_length ?? "",
          r.content_type ?? "",
          r.elapsed_ms ?? "",
          r.highlight ?? "",
          r.comment ?? "",
        ]
          .map(esc)
          .join(","),
      )
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `history-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // 🎯 R600: Clipboard-only CSV counterpart to bulkExportCsv.
  // Operators pasting into Excel/Sheets/Google Docs want the
  // CSV table directly on the clipboard without the file-save
  // + open roundtrip. Byte-identical column shape to bulkExportCsv
  // (same 14 columns + same esc rules) so the clipboard and file
  // outputs stay interchangeable. Round-number milestone — R600,
  // the second R600 round-number in BurpFree history after R500
  // Scanner Copy as Python shipped the first R500 round-number
  // (R500 was a 500-round streak milestone; R600 continues the
  // tempo as a 600-round-adjacent milestone).
  function bulkCopyCsv() {
    if (selectedRows.length === 0) return;
    const headers = [
      "id",
      "ts_ms",
      "method",
      "http_version",
      "scheme",
      "host",
      "port",
      "path",
      "status",
      "content_length",
      "content_type",
      "elapsed_ms",
      "highlight",
      "comment",
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = selectedRows
      .map((r) =>
        [
          r.id,
          r.ts_ms,
          r.method,
          r.http_version ?? "",
          r.scheme,
          r.host,
          r.port,
          r.path,
          r.status ?? "",
          r.content_length ?? "",
          r.content_type ?? "",
          r.elapsed_ms ?? "",
          r.highlight ?? "",
          r.comment ?? "",
        ]
          .map(esc)
          .join(","),
      )
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    void navigator.clipboard.writeText(csv);
  }

  // R285: Bulk JSONL export — companion to bulkExportCsv. CSV
  // flattens history rows to columns and loses nested fields like
  // `tags: string[]` (which gets stringified ambiguously) + any
  // forward-compat fields the backend adds later. JSONL preserves
  // the full StoredSummary shape so operators piping into jq /
  // grep / ELK ingest can keep every field accessible by key.
  // Scope matches CSV: current multi-selection. One JSON object
  // per line — no top-level array wrapper — so streaming consumers
  // can start processing before the write finishes.
  function bulkExportJsonl() {
    if (selectedRows.length === 0) return;
    const body = selectedRows
      .map((r) => JSON.stringify(r))
      .join("\n");
    const blob = new Blob([body + "\n"], {
      type: "application/x-ndjson;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `history-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R605: Clipboard-only JSON array counterpart to the JSONL file
  // export. Operators dropping transaction records into test
  // fixtures / API mocks / jq pipelines want a top-level JSON array
  // (not JSONL) on the clipboard directly — easy to paste into a
  // JS/TS test, Python unit test, or a REST client body. Pretty-
  // printed with 2-space indent so the pasted output is diff-
  // friendly. Starts a new cross-panel "📋 Copy as JSON" family;
  // mirrors the Copy-as-CSV family growth from R600-R604.
  function bulkCopyJson() {
    if (selectedRows.length === 0) return;
    void navigator.clipboard.writeText(JSON.stringify(selectedRows, null, 2));
  }

  // R614: Clipboard-only JSONL counterpart to the JSONL file export.
  // Where R605 Copy as JSON array produces a top-level array (great
  // for JS/TS tests), R614 produces one-object-per-line JSONL —
  // which is the shape jq / ELK / Splunk ingest actually prefers
  // for streaming consumers. The file export already writes this
  // shape; R614 just drops it on the clipboard. No indentation
  // (dense format — matches the file export byte-for-byte).
  function bulkCopyJsonl() {
    if (selectedRows.length === 0) return;
    const body = selectedRows.map((r) => JSON.stringify(r)).join("\n");
    void navigator.clipboard.writeText(body);
  }

  return (
    <div className="panel">
      <div className="toolbar">
        <label>Host</label>
        <input
          value={filter.host_contains || ""}
          onChange={(e) => setFilter({ ...filter, host_contains: e.target.value || undefined })}
          placeholder="any"
          style={{ width: 160 }}
        />
        <label>Method</label>
        <select
          value={filter.method || ""}
          onChange={(e) => setFilter({ ...filter, method: e.target.value || undefined })}
        >
          <option value="">any</option>
          {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"].map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <label title="Filter by origin tool: Proxy traffic / Repeater sends / Intruder attacks / Scanner probes / Manual edits / Extension calls">
          Source
        </label>
        <select
          value={filter.source || ""}
          onChange={(e) =>
            setFilter({ ...filter, source: e.target.value || undefined })
          }
          title="RequestSource filter — mirrors burpfree_core::traffic::RequestSource"
        >
          <option value="">any</option>
          <option value="proxy">Proxy</option>
          <option value="repeater">Repeater</option>
          <option value="intruder">Intruder</option>
          <option value="scanner">Scanner</option>
          <option value="manual">Manual</option>
          <option value="extension">Extension</option>
        </select>
        <StatusClassChips filter={filter} setFilter={setFilter} rows={rows} />
        <div className="sep" />
        <AnnotationChips filter={filter} setFilter={setFilter} rows={rows} />
        {/* R278: Clear-all-highlights ghost — only renders when at    */}
        {/* least one row in the current fetched set carries a         */}
        {/* highlight colour. Operators triaging via Alt+1..7 colour   */}
        {/* picks (R216) can accumulate dozens of highlights across a  */}
        {/* long engagement; this is the one-click reset. Confirms     */}
        {/* pre-fire with the exact victim count because clearing is   */}
        {/* destructive and operators may have spent real time         */}
        {/* annotating.                                                 */}
        {(() => {
          const n = rows.filter((r) => !!r.highlight).length;
          if (n === 0) return null;
          return (
            <button
              type="button"
              className="ghost"
              onClick={() => void clearAllHighlights()}
              title={`Clear every highlight colour across the ${n} highlighted row${n === 1 ? "" : "s"} in the current view (asks before firing)`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              ⨯ clear {n} highlight{n === 1 ? "" : "s"}
            </button>
          );
        })()}
        <label>Content</label>
        <input
          value={filter.content_type_contains || ""}
          onChange={(e) =>
            setFilter({ ...filter, content_type_contains: e.target.value || undefined })
          }
          placeholder="json, html…"
          style={{ width: 100 }}
        />
        <label>Search</label>
        {/* R877: Burp-identical visible × clear button next to the
            History search input. Esc already clears (R201) but a
            mouse-first × affordance makes the clear action
            discoverable — operators who don't use keyboard
            shortcuts get the same escape hatch. Only renders when
            the search has text so an empty search doesn't carry
            a stub button. */}
        <span style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
          <input
            ref={searchInputRef}
            value={filter.search_text || ""}
            onChange={(e) => setFilter({ ...filter, search_text: e.target.value || undefined })}
            onKeyDown={(e) => {
              if (e.key === "Escape" && filter.search_text) {
                e.preventDefault();
                setFilter({ ...filter, search_text: undefined });
              }
            }}
            placeholder="path / host / comment (Ctrl+F · Esc clears)"
            style={{ width: 180, paddingRight: filter.search_text ? 22 : 6 }}
          />
          {filter.search_text && (
            <button
              type="button"
              onClick={() => setFilter({ ...filter, search_text: undefined })}
              title="Clear search (same as Esc)"
              aria-label="Clear search"
              style={{
                position: "absolute",
                right: 2,
                top: "50%",
                transform: "translateY(-50%)",
                border: "none",
                background: "transparent",
                color: "var(--text-dim)",
                cursor: "pointer",
                padding: "0 4px",
                fontSize: 13,
                lineHeight: 1,
                borderRadius: 2,
              }}
            >
              ×
            </button>
          )}
        </span>
        <div className="sep" />
        <label>
          <input type="checkbox" checked={filter.in_scope_only || false}
            onChange={(e) => setFilter({ ...filter, in_scope_only: e.target.checked || undefined })} />{" "}
          In-scope only
        </label>
        <label>
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Auto-refresh
        </label>
        <div className="sep" />
        <TimeRangeControls filter={filter} setFilter={setFilter} />
        <div className="sep" />
        <SizeRangeControls filter={filter} setFilter={setFilter} />
        <div className="sep" />
        <MimeChipsControls filter={filter} setFilter={setFilter} />
        <div className="sep" />
        <ErrorOnlyControl filter={filter} setFilter={setFilter} />
        <div className="sep" />
        <div style={{ position: "relative", display: "inline-block" }}>
          <button
            data-columns-btn
            onClick={() => setColumnsMenuOpen((v) => !v)}
            title="Show or hide table columns. Changes persist in the project config so a reopened session restores the same layout."
          >
            Columns {hiddenColumns.size > 0 ? `(${visibleColumns.length}/${HISTORY_COLUMNS.length})` : ""} ▾
          </button>
          {/* R129: Prune errored. One-click clean-up for the common */}
          {/* "drop all the connection-refused noise before diffing" */}
          {/* workflow. Always acts on every errored row in the      */}
          {/* project, not just the current filter view, matching    */}
          {/* Burp's "clean history" intent.                          */}
          <button
            className="ghost"
            onClick={() => void pruneErroredRows()}
            title="Delete every transaction whose `error` column is non-NULL (connection refused, TLS handshake fail, parse error, upstream reset). Cannot be undone."
            style={{ marginLeft: 4 }}
          >
            ⚠ Prune errored
          </button>
          {columnsMenuOpen && (
            <div
              data-columns-popover
              style={{
                position: "absolute",
                top: "calc(100% + 2px)",
                right: 0,
                minWidth: 180,
                padding: 4,
                background: "var(--bg-raised)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                boxShadow: "0 4px 10px rgba(0,0,0,0.25)",
                zIndex: 100,
              }}
            >
              {HISTORY_COLUMNS.map((c) => {
                const checked = !hiddenColumns.has(c.key);
                const displayLabel = c.label || c.key;
                return (
                  <label
                    key={c.key}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "4px 8px",
                      cursor: "pointer",
                      fontSize: 12,
                      borderRadius: 3,
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background = "var(--bg-hover, rgba(255,255,255,0.05))")
                    }
                    onMouseLeave={(e) => (e.currentTarget.style.background = "")}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleColumnVisible(c.key)}
                    />
                    <span style={{ textTransform: "capitalize" }}>{displayLabel}</span>
                  </label>
                );
              })}
              {hiddenColumns.size > 0 && (
                <>
                  <div
                    style={{
                      borderTop: "1px solid var(--border)",
                      margin: "4px 0",
                    }}
                  />
                  <button
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "4px 8px",
                      background: "transparent",
                      border: "none",
                      cursor: "pointer",
                      color: "var(--text-dim)",
                      fontSize: 11,
                    }}
                    onClick={() => {
                      setHiddenColumns(new Set());
                      void api.historyColumnsSet([]).catch(() => {});
                    }}
                    title="Reset to Burp's default — every column visible"
                  >
                    Show all columns
                  </button>
                </>
              )}
            </div>
          )}
        </div>
        <button onClick={refresh}>Refresh</button>
        <button
          className="danger"
          onClick={async () => {
            if (confirm("Clear all history?")) {
              await api.historyClear();
              refresh();
            }
          }}
        >
          Clear
        </button>
        {/* R240: Count active filters + offer a single-click reset. */}
        {/* Mirror of R238's "clear N filters" label pattern in       */}
        {/* ScannerPanel but at a bigger scale — HistoryFilter has    */}
        {/* 12+ dimensions. Operators pivot filter sets a lot and     */}
        {/* were previously clearing each dimension one-at-a-time or  */}
        {/* refreshing the project. Only renders when ≥ 1 filter is  */}
        {/* active so the toolbar stays minimal on fresh sessions.    */}
        {(() => {
          const activeFilters: string[] = [];
          if (filter.host_contains) activeFilters.push("host");
          if (filter.method) activeFilters.push("method");
          if (filter.source) activeFilters.push("source");
          if (filter.content_type_contains) activeFilters.push("content");
          if (filter.search_text) activeFilters.push("search");
          if (filter.in_scope_only) activeFilters.push("in-scope");
          if (filter.highlighted_only) activeFilters.push("highlighted");
          if (filter.commented_only) activeFilters.push("commented");
          if (filter.error_only) activeFilters.push("errored");
          if (filter.status_classes && filter.status_classes.length > 0)
            activeFilters.push("status");
          if (
            filter.content_type_classes &&
            filter.content_type_classes.length > 0
          )
            activeFilters.push("mime");
          if (filter.ts_min_ms != null || filter.ts_max_ms != null)
            activeFilters.push("time");
          if (filter.resp_size_min != null || filter.resp_size_max != null)
            activeFilters.push("size");
          const n = activeFilters.length;
          if (n === 0) return null;
          return (
            <button
              className="ghost"
              onClick={() => setFilter({ limit: filter.limit ?? 1000 })}
              title={`Clear all ${n} active filter${n === 1 ? "" : "s"}: ${activeFilters.join(", ")} — keep the limit setting`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              ⨯ clear {n} filter{n === 1 ? "" : "s"}
            </button>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        {suppressOos && (
          <button
            onClick={() => void resumeRecording()}
            title="Out-of-scope traffic is being forwarded by the proxy but NOT recorded in history, sitemap, or events. Click to resume recording everything. Mirrors Burp's 'drop out-of-scope items' option — same toggle as Settings → Record out-of-scope."
            style={{
              background: "var(--accent, #e07c50)",
              color: "white",
              border: "1px solid var(--accent, #e07c50)",
              borderRadius: 10,
              padding: "2px 10px",
              fontSize: 11,
              fontWeight: 600,
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            ⚑ Out-of-scope suppressed · resume
          </button>
        )}
        <span className="badge">{rows.length} rows</span>
        <span className="badge">
          {Object.entries(stats)
            .map(([k, v]) => `${k}xx:${v}`)
            .join(" ")}
        </span>
        {/* R442: Unique host count badge — operators doing a   */}
        {/* scope-pass want a quick read of how many hosts    */}
        {/* this filtered view covers. Pure client-side        */}
        {/* derivation over `rows` (filtered subset) — zero    */}
        {/* RPC. Hides when rows.length === 0 to avoid noise.  */}
        {rows.length > 0 && (() => {
          const uniqHosts = new Set(rows.map((r) => r.host)).size;
          return (
            <span
              className="badge"
              title={`${uniqHosts} unique host${uniqHosts === 1 ? "" : "s"} across the ${rows.length} filtered row${rows.length === 1 ? "" : "s"}. Scope-pass breadth indicator.`}
            >
              📊 {uniqHosts} host{uniqHosts === 1 ? "" : "s"}
            </span>
          );
        })()}
        {/* R468: HTTP method breakdown badge — operators eyeballing  */}
        {/* a filtered traffic view want a quick read of the method   */}
        {/* composition without opening the method chip strip. GETs   */}
        {/* vs POSTs vs other verbs is a useful at-a-glance indicator */}
        {/* of what kind of app this is (static-heavy, API-heavy,     */}
        {/* GraphQL-only, etc.). Companion to R442 hosts badge        */}
        {/* right above — both are at-a-glance scope-pass stats on   */}
        {/* the same filtered row set. **Format** top-3 methods as   */}
        {/* "verb:count" joined with space, "+N more" when more than */}
        {/* 3 distinct methods exist (so a mixed-verb API doesn't    */}
        {/* overflow the toolbar). **Visibility gate** `rows.length` */}
        {/* > 0, same as the hosts badge sibling.                     */}
        {rows.length > 0 && (() => {
          const counts = new Map<string, number>();
          for (const r of rows) {
            counts.set(r.method, (counts.get(r.method) ?? 0) + 1);
          }
          const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
          const top = sorted.slice(0, 3);
          const extra = sorted.length - top.length;
          const summary = top.map(([m, n]) => `${m}:${n}`).join(" ");
          const full = sorted
            .map(([m, n]) => `${m}=${n}`)
            .join(", ");
          return (
            <span
              className="badge"
              title={`HTTP method breakdown across the ${rows.length} filtered row${rows.length === 1 ? "" : "s"}: ${full}. Companion to the hosts badge — one glance tells you the method mix.`}
            >
              📊 {summary}{extra > 0 ? ` +${extra} more` : ""}
            </span>
          );
        })()}
      </div>
      {selectedIds.size > 0 && (
        <div
          style={{
            padding: "4px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexWrap: "wrap",
            fontSize: 11.5,
          }}
          role="toolbar"
          aria-label="Bulk actions"
        >
          <strong style={{ color: "var(--accent)" }}>
            {selectedIds.size} selected
          </strong>
          <span style={{ color: "var(--text-dim)" }}>
            Ctrl+click toggle · Shift+click range
          </span>
          <span className="sep" />
          <select
            value=""
            onChange={(e) => {
              const v = e.target.value;
              e.target.value = "";
              if (!v) return;
              void bulkHighlight(v === "clear" ? null : v);
            }}
            title="Set the highlight on every selected row"
          >
            <option value="">Highlight ▾</option>
            {Object.keys(HIGHLIGHT_COLORS).map((name) => (
              <option key={name} value={name}>
                ● {name}
              </option>
            ))}
            <option value="clear">clear</option>
          </select>
          <button
            onClick={bulkSendToRepeater}
            disabled={selectedIds.size === 0}
            title="Open one Repeater tab per selected row"
          >
            → Repeater ({selectedIds.size})
          </button>
          <button onClick={bulkSendToComparer} disabled={selectedIds.size < 2}>
            Compare first two
          </button>
          <button onClick={bulkExportCsv}>Export CSV</button>
          {/* 🎯 R600: Clipboard-only CSV counterpart to Export CSV.
              Operators pasting into Excel/Sheets want the table
              on the clipboard directly without a file-save + open
              roundtrip. Byte-identical column shape to the file
              export so clipboard + file stay interchangeable. */}
          <button
            onClick={bulkCopyCsv}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as a CSV table to clipboard (14 columns: id, ts_ms, method, http_version, scheme, host, port, path, status, content_length, content_type, elapsed_ms, highlight, comment). Paste into Excel / Sheets / Google Docs without the file-save roundtrip. Byte-identical column shape to Export CSV.`
            }
          >
            📋 Copy as CSV
          </button>
          <button
            onClick={bulkExportJsonl}
            title="Export the selected transactions as JSONL (one JSON object per line). Preserves every StoredSummary field (tags array, highlight, comment, http_version, …) so you can `jq '.host' history-*.jsonl` without a column-flattened loss. Pipe into grep / jq / ELK ingest."
          >
            Export JSONL
          </button>
          {/* R605: Clipboard-only JSON array counterpart to the
              JSONL file export. Starts a new cross-panel "📋 Copy
              as JSON" family; operators dropping transaction
              records into test fixtures / API mocks / jq
              pipelines want a top-level JSON array (not JSONL)
              on the clipboard directly. Pretty-printed with
              2-space indent so the pasted output is diff-
              friendly. */}
          <button
            onClick={bulkCopyJson}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed, preserves every StoredSummary field including tags, highlight, comment, http_version). Great for test fixtures, API mocks, jq pipelines. Starts the cross-panel Copy-as-JSON family.`
            }
          >
            📋 Copy as JSON
          </button>
          {/* R614: Clipboard-only JSONL counterpart to Export JSONL.
              Pairs with R605 Copy as JSON — JSON array for test
              fixtures, JSONL for jq/ELK streaming consumers. Byte-
              identical shape to the file export (no indent, one
              object per line). */}
          <button
            onClick={bulkCopyJsonl}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line, no indent — byte-identical to Export JSONL). Great for jq / grep / ELK / Splunk ingest. Pairs with Copy as JSON for the array variant.`
            }
          >
            📋 Copy as JSONL
          </button>
          {/* R624: Clipboard-only Markdown table variant. Pastes
              cleanly into Jira / GitHub PR descriptions / Slack
              in a reader-friendly format. Keeps the same 6 most-
              useful columns as the HistoryPanel row display rather
              than the full 14-column CSV shape — Markdown tables
              get hard to read past 6-7 columns. */}
          <button
            onClick={() => {
              if (selectedRows.length === 0) return;
              const headers = ["id", "method", "host", "path", "status", "size"];
              const esc = (v: unknown) =>
                String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
              const sep = headers.map(() => "---").join(" | ");
              const body = selectedRows
                .map((r) =>
                  [r.id, r.method, r.host, r.path, r.status ?? "", r.content_length ?? ""]
                    .map(esc)
                    .join(" | "),
                )
                .join("\n");
              const md = `| ${headers.join(" | ")} |\n| ${sep} |\n${body
                .split("\n")
                .map((line) => `| ${line} |`)
                .join("\n")}`;
              void navigator.clipboard.writeText(md);
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"} as a GitHub-flavored Markdown table (6 columns: id, method, host, path, status, size). Great for Jira / PR description / Slack paste. Pipe chars in cell content are escaped as \\|.`
            }
          >
            📋 Copy as Markdown
          </button>
          {/* R639: HistoryPanel bulk "Copy as Markdown (full)" —
              document-style variant complementing R624 table form.
              Where R624 emits a single compact 6-column table,
              R639 emits H3-per-row blocks with method+URL header +
              status + size + comment + highlight — richer per-row
              detail for ticket write-ups where each tx needs its
              own section. --- separator between rows. */}
          <button
            onClick={() => {
              if (selectedRows.length === 0) return;
              const sections = selectedRows.map((r) => {
                const lines = [
                  `### ${r.method} ${r.host}${r.path}`,
                  "",
                  `- **Status**: ${r.status ?? "—"}`,
                  `- **Content-Type**: ${r.content_type || "—"}`,
                  `- **Size**: ${r.content_length ?? "—"} bytes`,
                ];
                if (r.highlight) lines.push(`- **Highlight**: ${r.highlight}`);
                if (r.comment) lines.push(`- **Comment**: ${r.comment}`);
                if (r.tags && r.tags.length > 0)
                  lines.push(`- **Tags**: ${r.tags.join(", ")}`);
                return lines.join("\n");
              });
              const md = sections.join("\n\n---\n\n");
              void navigator.clipboard.writeText(md);
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"} as a Markdown document (H3 header per row with method+URL + status + content-type + size + highlight + comment + tags; --- separator between rows). Document-style complement to Copy as Markdown table.`
            }
          >
            📋 Copy as Markdown (full)
          </button>
          {/* R320: Bulk "+ Add tag" — merge-mode add to every       */}
          {/* selected row's tag set. Matches the R312 Scanner       */}
          {/* bulk-tag UX exactly: prompt → trim → bail on empty →   */}
          {/* read each row's current `tags ?? []` → union with the */}
          {/* new tag → write back via the new `history_set_tags`    */}
          {/* RPC (R320 backend wire-up). Idempotent — rows that    */}
          {/* already carry the tag are skipped and reported in the */}
          {/* final toast as "(M already had it)". Serial per-id    */}
          {/* because SQLite serialises writes under its mutex       */}
          {/* anyway — Promise.all would just stack contention.     */}
          <button
            onClick={() => {
              const next = prompt(
                `Add a tag to ${selectedRows.length} selected transaction${selectedRows.length === 1 ? "" : "s"}:\n\n(Merge mode — existing tags on each row are preserved. Rows that already have the tag are skipped.)`,
                "",
              );
              if (next === null) return;
              const tag = next.trim();
              if (tag.length === 0) {
                alert("Empty tag — nothing to apply.");
                return;
              }
              void (async () => {
                let ok = 0;
                let skipped = 0;
                let failed = 0;
                for (const r of selectedRows) {
                  const cur = r.tags ?? [];
                  if (cur.includes(tag)) {
                    skipped += 1;
                    continue;
                  }
                  try {
                    const merged = Array.from(new Set([...cur, tag]));
                    await api.historySetTags(r.id, merged);
                    ok += 1;
                  } catch {
                    failed += 1;
                  }
                }
                await refresh();
                alert(
                  `Tagged ${ok} transaction${ok === 1 ? "" : "s"} with "${tag}"${skipped > 0 ? ` (${skipped} already had it)` : ""}${failed > 0 ? ` (${failed} failed)` : ""}.`,
                );
              })();
            }}
            disabled={selectedIds.size === 0}
            title={`Add a tag to each of the ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"} (merge semantics — existing tags survive). Great for marking a cluster "campaign-X" / "jwt-leak-sweep" / "pre-exploit-baseline" for later jq / Jira / grep workflows.`}
          >
            + Add tag
          </button>
          {/* R339: Bulk + Comment — drop one shared comment on       */}
          {/* every selected row. Operators triaging a batch (e.g.    */}
          {/* "jwt-leak sweep: these all leak the same token in a    */}
          {/* response header") want one annotation applied across    */}
          {/* the cluster so later Export CSV / JSONL carries the    */}
          {/* note on every row. **Replace semantics** unlike R320   */}
          {/* +Add tag which merges, comments overwrite — most ops   */}
          {/* workflows treat comments as one-shot context, not an   */}
          {/* accumulating list. Confirms pre-fire when any row     */}
          {/* already has a non-empty comment so operators don't    */}
          {/* nuke prior annotations by accident. Serial per-id      */}
          {/* because SQLite serializes writes anyway.               */}
          <button
            onClick={() => {
              const existing = selectedRows.filter((r) => r.comment && r.comment.length > 0).length;
              const next = prompt(
                `Set a comment on ${selectedRows.length} selected transaction${selectedRows.length === 1 ? "" : "s"}:\n\n` +
                (existing > 0
                  ? `(Replace mode — ${existing} row${existing === 1 ? "" : "s"} already have${existing === 1 ? "s" : ""} a comment that will be overwritten.)`
                  : "(Replace mode — no rows currently have a comment.)"),
                "",
              );
              if (next === null) return;
              const comment = next; // allow empty to clear
              if (existing > 0 && !confirm(
                `${existing} selected row${existing === 1 ? "" : "s"} already have${existing === 1 ? "s" : ""} a comment that will be overwritten.\n\nContinue?`,
              )) {
                return;
              }
              void (async () => {
                let ok = 0;
                let failed = 0;
                for (const r of selectedRows) {
                  try {
                    await api.historySetComment(r.id, comment);
                    ok += 1;
                  } catch {
                    failed += 1;
                  }
                }
                await refresh();
                alert(
                  `Commented ${ok} transaction${ok === 1 ? "" : "s"}${failed > 0 ? ` (${failed} failed)` : ""}.`,
                );
              })();
            }}
            disabled={selectedIds.size === 0}
            title={`Set a shared comment on each of the ${selectedIds.size} selected transaction${selectedIds.size === 1 ? "" : "s"}. Overwrites — confirms pre-fire when any row already has a comment. Empty string clears the comment on every selected row.`}
          >
            + Comment
          </button>
          <button
            onClick={bulkExportHar}
            title="Export the selected transactions as a HAR 1.2 file (opens in Chrome DevTools / HAR viewers)"
          >
            Export HAR
          </button>
          {/* R353: Copy every selected row's URL to clipboard as a   */}
          {/* newline-joined list. Operators building a wordlist out */}
          {/* of a scope-pass's history, feeding a shell pipeline    */}
          {/* with xargs curl / nuclei -l / dirb, or just pasting    */}
          {/* a URL set into a ticket need this often — currently    */}
          {/* only the per-row Copy URL right-click supports it,     */}
          {/* which is tedious across a 50-row selection. Scopes to  */}
          {/* `selectedRows` so operators pivot Ctrl+A → 📋 Copy URLs */}
          {/* for a filtered-view wordlist in two clicks. Dedupe via */}
          {/* Set because operators often want unique URLs; sort     */}
          {/* alphabetically for stable diff.                        */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    selectedRows.map(
                      (r) => `${r.scheme}://${r.host}${r.path}`,
                    ),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected URL${selectedIds.size === 1 ? "" : "s"} as a newline-joined list (deduped + sorted). Great for feeding xargs / nuclei / dirb — operators building a wordlist out of a scope-pass's history.`
            }
          >
            📋 Copy URLs
          </button>
          {/* R662: Copy "URL (status)" pairs — bulk sibling of
              R353 Copy URLs with each URL annotated by its
              response status. Great for a smoke-test readout
              ("which of my 50 endpoints returned 2xx?") or a
              post-attack triage ("which /admin paths are now
              403?"). Each line: `<URL> → <status>`. Dedupe via
              Set keyed on the composite string; sort alpha. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    selectedRows.map(
                      (r) =>
                        `${r.scheme}://${r.host}${r.path} → ${r.status ?? "—"}`,
                    ),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as "URL → status" pairs (deduped + alpha sort). Great for smoke-test readouts or post-attack triage.`
            }
          >
            📋 URL+status
          </button>
          {/* R360: Copy just unique hosts (not full URLs) —          */}
          {/* operators building a scope-expansion list / mass-nmap   */}
          {/* / amass-piped-wordlist want hostnames without paths.   */}
          {/* Dedupe heavily since one host usually has 100s of      */}
          {/* paths in a scope-pass. Sorted alpha for stable output. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(selectedRows.map((r) => r.host)),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(selectedRows.map((r) => r.host)).size;
                    return `Copy ${uniq} unique hostname${uniq === 1 ? "" : "s"} to clipboard (deduped from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Great for scope-expansion / amass / mass-nmap wordlists.`;
                  })()
            }
          >
            📋 Copy hosts
          </button>
          {/* R689: HistoryPanel bulk "📋 Copy stats" — one-shot
              scope-pass summary. Operators writing a scope-pass
              report want "N rows, M unique hosts, K unique paths,
              X MB total" at once. Format: multi-line KV block. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const hosts = new Set<string>();
                const paths = new Set<string>();
                let bytesIn = 0;
                let elapsedTotal = 0;
                let elapsedN = 0;
                for (const r of selectedRows) {
                  if (r.host) hosts.add(r.host);
                  if (r.host && r.path) paths.add(`${r.host}${r.path}`);
                  if (typeof r.content_length === "number")
                    bytesIn += r.content_length;
                  if (typeof r.elapsed_ms === "number") {
                    elapsedTotal += r.elapsed_ms;
                    elapsedN += 1;
                  }
                }
                const fmt = (n: number) =>
                  n >= 1_000_000
                    ? `${(n / 1_000_000).toFixed(1)} MB`
                    : n >= 1_000
                      ? `${(n / 1_000).toFixed(1)} KB`
                      : `${n} B`;
                const lines = [
                  `Rows: ${selectedRows.length}`,
                  `Unique hosts: ${hosts.size}`,
                  `Unique endpoints: ${paths.size}`,
                  `Response bytes: ${fmt(bytesIn)}`,
                ];
                if (elapsedN > 0) {
                  const avgMs = Math.round(elapsedTotal / elapsedN);
                  lines.push(`Avg elapsed: ${avgMs} ms`);
                }
                await navigator.clipboard.writeText(lines.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy one-shot summary stats across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} (rows / unique hosts / unique endpoints / response bytes). Great for a scope-pass report.`
            }
          >
            📋 Copy stats
          </button>
          {/* R688: HistoryPanel bulk "📋 Copy time range" —
              min + max timestamp + duration summary across
              selected rows. Great for "when did this scope-pass
              actually run?" audit — operators report "scope pass
              ran 14:03 to 15:47, 1h 44m" in ticket write-ups.
              ISO 8601 timestamps. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                let min = Infinity;
                let max = -Infinity;
                for (const r of selectedRows) {
                  if (typeof r.ts_ms !== "number") continue;
                  if (r.ts_ms < min) min = r.ts_ms;
                  if (r.ts_ms > max) max = r.ts_ms;
                }
                if (!isFinite(min) || !isFinite(max)) {
                  alert("No timestamp data in the selected rows.");
                  return;
                }
                const durMs = max - min;
                const durS = Math.floor(durMs / 1000);
                const durLabel =
                  durS < 60
                    ? `${durS}s`
                    : durS < 3600
                      ? `${Math.floor(durS / 60)}m ${durS % 60}s`
                      : durS < 86_400
                        ? `${Math.floor(durS / 3600)}h ${Math.floor((durS % 3600) / 60)}m`
                        : `${Math.floor(durS / 86_400)}d ${Math.floor((durS % 86_400) / 3600)}h`;
                const minIso = new Date(min).toISOString();
                const maxIso = new Date(max).toISOString();
                const text = `From ${minIso}\nTo   ${maxIso}\nDuration: ${durLabel}\nRows: ${selectedRows.length}`;
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy time range (min/max ISO timestamps + duration) across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"}. Great for "when did this scope-pass run?" audit in ticket write-ups.`
            }
          >
            📋 Copy time range
          </button>
          {/* R686: HistoryPanel bulk "📋 Copy tag counts" —
              tally variant of R561 Copy tags. Each tag counts
              once per row that carries it (multi-value). Mirror
              of R685 Scanner tag counts. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const r of selectedRows) {
                  for (const t of r.tags ?? []) {
                    if (!t) continue;
                    counts[t] = (counts[t] ?? 0) + 1;
                  }
                }
                if (Object.keys(counts).length === 0) {
                  alert("No tags across the selected rows.");
                  return;
                }
                const sorted = Object.entries(counts).sort(
                  (a, b) => b[1] - a[1],
                );
                const text = sorted.map(([t, n]) => `${t}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy tag counts across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} as a one-line tally. Each tag counts once per row that carries it (multi-value). Sorted desc by count. Mirror of R685 Scanner.`
            }
          >
            📋 Copy tag counts
          </button>
          {/* R673: HistoryPanel bulk "📋 Copy host counts" —
              tally variant of R360 Copy hosts. Where R360 dumps
              unique host list, R673 dumps counts per host so
              operators see which host dominates the traffic.
              Sorted desc by count (highest first) so the top-
              trafficked host is at the top. Capped at 20 hosts
              with "… +N more" suffix when the long tail is
              long. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const r of selectedRows) {
                  counts[r.host] = (counts[r.host] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort(
                  (a, b) => b[1] - a[1],
                );
                const head = sorted.slice(0, 20);
                const tailCount = sorted.length - head.length;
                let text = head
                  .map(([h, n]) => `${h}: ${n}`)
                  .join("\n");
                if (tailCount > 0) {
                  text += `\n… +${tailCount} more host${tailCount === 1 ? "" : "s"}`;
                }
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy per-host transaction counts across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} as a newline-separated list (top-20 descending by count). Great for "which host am I hammering?" audit. Rows that share a host collapse to one line.`
            }
          >
            📋 Copy host counts
          </button>
          {/* R672: HistoryPanel bulk "📋 Copy mime counts" —
              tally variant of R555 Copy content-types. Groups
              by MIME family prefix (html / json / xml / js / css
              / image / text / etc.) via the shortMime helper
              used by HistoryPanel's row display. Format
              "json: 50, html: 20, img:png: 10". Alpha sort for
              stable output. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const r of selectedRows) {
                  const ct = r.content_type || "";
                  const t = ct.split(";")[0].trim().toLowerCase();
                  const slash = t.indexOf("/");
                  let bucket: string;
                  if (!t) {
                    bucket = "(none)";
                  } else if (slash < 0) {
                    bucket = t;
                  } else {
                    const sub = t.slice(slash + 1);
                    if (sub.endsWith("+json") || sub === "json") bucket = "json";
                    else if (sub.endsWith("+xml") || sub === "xml") bucket = "xml";
                    else if (sub === "html") bucket = "html";
                    else if (sub === "plain") bucket = "text";
                    else if (sub === "javascript" || sub === "x-javascript")
                      bucket = "js";
                    else if (sub === "css") bucket = "css";
                    else if (t.startsWith("image/")) bucket = `img:${sub}`;
                    else bucket = sub;
                  }
                  counts[bucket] = (counts[bucket] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort((a, b) =>
                  a[0].localeCompare(b[0]),
                );
                const text = sorted.map(([c, n]) => `${c}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy MIME-type bucket counts across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "html: 20, json: 50, img:png: 10"). Buckets collapse MIME variants (application/vnd.api+json → json, image/png → img:png) for a readable summary.`
            }
          >
            📋 Copy mime counts
          </button>
          {/* R671: HistoryPanel bulk "📋 Copy status counts" —
              tally variant of R556 Copy statuses. Groups by
              status class (2xx/3xx/4xx/5xx) so the output stays
              compact (not one per status code). Format "2xx: 90,
              4xx: 10". */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const r of selectedRows) {
                  if (r.status == null) {
                    counts["(no status)"] = (counts["(no status)"] ?? 0) + 1;
                    continue;
                  }
                  const cls = `${Math.floor(r.status / 100)}xx`;
                  counts[cls] = (counts[cls] ?? 0) + 1;
                }
                const order = ["2xx", "3xx", "4xx", "5xx", "1xx", "(no status)"];
                const sorted = Object.entries(counts).sort((a, b) => {
                  const ai = order.indexOf(a[0]);
                  const bi = order.indexOf(b[0]);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                const text = sorted.map(([c, n]) => `${c}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy status-class counts across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "2xx: 90, 4xx: 10"). Great for a scope-pass summary. Rows without status code land in "(no status)".`
            }
          >
            📋 Copy status counts
          </button>
          {/* 🎯 R670: HistoryPanel bulk "📋 Copy method counts" —
              tally variant of R554 Copy methods on HistoryPanel.
              Mirrors R669 Scanner "Copy sev counts" pattern.
              Format "GET: 100, POST: 42, PUT: 5". Great for a
              one-line scope-pass summary. Sorted by canonical
              HTTP method order (GET > POST > PUT > DELETE >
              PATCH > HEAD > OPTIONS). 🎯 R670 round-number
              milestone. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const order = [
                  "GET",
                  "POST",
                  "PUT",
                  "DELETE",
                  "PATCH",
                  "HEAD",
                  "OPTIONS",
                ];
                const counts: Record<string, number> = {};
                for (const r of selectedRows) {
                  const m = r.method || "(none)";
                  counts[m] = (counts[m] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort((a, b) => {
                  const ai = order.indexOf(a[0]);
                  const bi = order.indexOf(b[0]);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                const text = sorted.map(([m, n]) => `${m}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy HTTP-method counts across ${selectedRows.length} selected row${selectedRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "GET: 100, POST: 42, PUT: 5"). Great for a scope-pass summary. Sorted by canonical HTTP method order. 🎯 R670 round-number milestone.`
            }
          >
            📋 Copy method counts
          </button>
          {/* R599: Copy host:port pairs — distinct from R360
              "hosts" which drops port info. Operators doing
              nmap/masscan-style scans across non-standard ports
              or multi-service hosts want the port carried along
              ("api.example.com:8443" + "example.com:443" are
              often different services). Dedupe via Set + alpha
              sort for stable output. Fallback to plain host when
              port is missing/0 so edge cases don't produce
              "example.com:0" noise. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    selectedRows.map((r) =>
                      r.port ? `${r.host}:${r.port}` : r.host,
                    ),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows.map((r) =>
                        r.port ? `${r.host}:${r.port}` : r.host,
                      ),
                    ).size;
                    return `Copy ${uniq} unique host:port pair${uniq === 1 ? "" : "s"} to clipboard (deduped from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Great for nmap/masscan wordlists where non-standard ports matter. Rows with missing or 0 port fall back to plain hostname.`;
                  })()
            }
          >
            📋 Copy host:port
          </button>
          {/* R554: Copy methods — bulk clipboard dump of unique
              HTTP methods seen across selected rows. Operators
              auditing API-surface shape ("does this endpoint
              only serve GET? / are PUT and DELETE enabled?")
              want a quick method-distribution grab. Dedupe via
              Set + sort for a stable output. Complements R353
              Copy URLs + R360 Copy hosts. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(selectedRows.map((r) => r.method || "?")),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows.map((r) => r.method || "?"),
                    ).size;
                    return `Copy ${uniq} unique HTTP method${uniq === 1 ? "" : "s"} to clipboard (deduped from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Great for auditing API-surface shape — "does this endpoint only serve GET?".`;
                  })()
            }
          >
            📋 Copy methods
          </button>
          {/* R555: Copy content-types — bulk clipboard dump of
              unique Content-Type values seen across selected
              rows. Operators auditing API shape ("is this API
              JSON-only or does it serve XML/HTML too?") want
              a quick type-distribution grab. Dedupe via Set +
              sort. Fallback "(empty)" for rows with missing
              content_type so edge cases don't collapse the
              output. Complements R353 URLs / R360 hosts / R554
              methods. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    selectedRows.map((r) => r.content_type || "(empty)"),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows.map((r) => r.content_type || "(empty)"),
                    ).size;
                    return `Copy ${uniq} unique content-type${uniq === 1 ? "" : "s"} to clipboard (deduped from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Rows with missing content-type render as "(empty)".`;
                  })()
            }
          >
            📋 Copy content-types
          </button>
          {/* R556: Copy status codes — bulk clipboard dump of
              unique HTTP status codes seen across selected rows.
              Operators auditing status-code distribution ("do I
              have unexpected 5xx? / is this endpoint still
              returning 401 after my fix?") want a quick status
              audit. Completes the Copy X family (URLs / hosts /
              methods / content-types / status codes). Dedupe via
              Set + sort numeric. Fallback "0" for rows with no
              response (errored requests). */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(selectedRows.map((r) => r.status ?? 0)),
                ).sort((a, b) => a - b);
                await navigator.clipboard.writeText(
                  uniq.map((s) => String(s)).join("\n"),
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(selectedRows.map((r) => r.status ?? 0)).size;
                    return `Copy ${uniq} unique status code${uniq === 1 ? "" : "s"} to clipboard (deduped + numeric-sorted from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Errored requests render as "0".`;
                  })()
            }
          >
            📋 Copy statuses
          </button>
          {/* R557: Copy paths — bulk clipboard dump of unique
              URL paths (no host, no query) seen across selected
              rows. Operators building a path-wordlist for
              mass-fuzzing (ffuf / dirsearch / nuclei) want
              hostless paths. Dedupe via Set + alpha sort.
              Complements R353 URLs / R360 hosts / R554 methods /
              R555 content-types / R556 statuses — path is the
              remaining per-row attribute. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(selectedRows.map((r) => r.path || "/")),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(selectedRows.map((r) => r.path || "/")).size;
                    return `Copy ${uniq} unique URL path${uniq === 1 ? "" : "s"} to clipboard (deduped + alpha-sorted from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}). Paths only — no scheme / host / query. Great for ffuf / dirsearch wordlists.`;
                  })()
            }
          >
            📋 Copy paths
          </button>
          {/* R561: Copy tags — bulk clipboard dump of unique tag
              values across selected rows. Operators auditing a
              tag campaign ("which rows got the 'auth-attempt'
              tag? / what's my tag coverage?") want the full
              distinct list. Each row's tags array is flattened
              into a single Set before serialising. Rows without
              tags simply contribute nothing. Dedupe + alpha
              sort. Completes the 7-op Copy family (URLs /
              hosts / paths / methods / content-types / statuses
              / tags). */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const seen = new Set<string>();
                for (const r of selectedRows) {
                  for (const t of r.tags ?? []) {
                    if (t) seen.add(t);
                  }
                }
                const uniq = Array.from(seen).sort();
                if (uniq.length === 0) {
                  alert("No tags found across the selected rows.");
                  return;
                }
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const seen = new Set<string>();
                    for (const r of selectedRows) {
                      for (const t of r.tags ?? []) if (t) seen.add(t);
                    }
                    return `Copy ${seen.size} unique tag${seen.size === 1 ? "" : "s"} to clipboard (deduped + alpha-sorted from ${selectedIds.size} row${selectedIds.size === 1 ? "" : "s"}' tags arrays). Rows without tags contribute nothing. Alerts if the selection has no tags at all.`;
                  })()
            }
          >
            📋 Copy tags
          </button>
          {/* R569: Bulk "+ Add hosts to scope" — Burp-parity
              scope-expansion workflow. Operators doing a scope
              pass want to pick a cluster of history rows, hit
              one button, and add every unique host to the
              scope's include rules. Dedupe via Set so hitting
              100 rows across 5 hosts creates 5 new rules, not
              100. Pre-filter via existing `hasHostIncludeRule`
              helper so already-in-scope hosts skip gracefully.
              Fires `scopeAddRule` sequentially (not Promise.all)
              so the backend's unique-rule guard sees each add
              in order and the final `reloadScope()` reads the
              right snapshot. Confirms pre-fire with the add
              count because scope changes are session-wide. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              const uniqHosts = Array.from(
                new Set(selectedRows.map((r) => r.host).filter((h) => !!h)),
              );
              if (uniqHosts.length === 0) return;
              const newHosts = uniqHosts.filter(
                (h) => !hasHostIncludeRule(scope, h),
              );
              if (newHosts.length === 0) {
                alert(
                  `All ${uniqHosts.length} host${uniqHosts.length === 1 ? "" : "s"} across the selection are already in scope.`,
                );
                return;
              }
              if (
                !confirm(
                  `Add ${newHosts.length} new host${newHosts.length === 1 ? "" : "s"} to scope include rules?\n\n${newHosts.slice(0, 10).join("\n")}${newHosts.length > 10 ? `\n…+${newHosts.length - 10} more` : ""}`,
                )
              ) {
                return;
              }
              try {
                for (const h of newHosts) {
                  await api.scopeAddRule(buildHostIncludeRule(h));
                }
                await reloadScope();
                alert(
                  `Added ${newHosts.length} host${newHosts.length === 1 ? "" : "s"} to scope.`,
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows.map((r) => r.host).filter((h) => !!h),
                    ).size;
                    return `Add every unique host across ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} to scope include rules (${uniq} unique host${uniq === 1 ? "" : "s"}). Hosts already in scope are skipped. Confirms pre-fire with the host preview.`;
                  })()
            }
          >
            + Add hosts to scope
          </button>
          {/* 🎯 R570: Bulk "+ Add paths to scope" — path-level
              complement to R569 host-level. Burp distinguishes
              broad host-scope and narrow path-exact scope.
              Operators doing a precise scope lockdown ("include
              only these 12 specific endpoints, nothing else")
              want path-exact rules in one click. Dedupe via Set
              on `host|path` composite key so {host="x" path="/a",
              host="x" path="/a"} folds to one, but {host="x"
              path="/a", host="x" path="/b"} stays as 2. Pre-
              filter via `hasPathIncludeRule` so already-in-scope
              exact pairs skip. Confirms pre-fire with preview.
              R570 round-number milestone. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              const uniqPairs = Array.from(
                new Set(
                  selectedRows
                    .filter((r) => r.host && r.path)
                    .map((r) => `${r.host}|${r.path}`),
                ),
              ).map((p) => {
                const [host, ...rest] = p.split("|");
                return { host, path: rest.join("|") };
              });
              if (uniqPairs.length === 0) return;
              const newPairs = uniqPairs.filter(
                (p) => !hasPathIncludeRule(scope, p.host, p.path),
              );
              if (newPairs.length === 0) {
                alert(
                  `All ${uniqPairs.length} host+path pair${uniqPairs.length === 1 ? "" : "s"} across the selection are already in scope.`,
                );
                return;
              }
              const preview = newPairs
                .slice(0, 10)
                .map((p) => `${p.host}${p.path}`)
                .join("\n");
              if (
                !confirm(
                  `Add ${newPairs.length} new host+path pair${newPairs.length === 1 ? "" : "s"} to scope include rules?\n\n${preview}${newPairs.length > 10 ? `\n…+${newPairs.length - 10} more` : ""}`,
                )
              ) {
                return;
              }
              try {
                for (const p of newPairs) {
                  await api.scopeAddRule(buildPathIncludeRule(p.host, p.path));
                }
                await reloadScope();
                alert(
                  `Added ${newPairs.length} host+path pair${newPairs.length === 1 ? "" : "s"} to scope.`,
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows
                        .filter((r) => r.host && r.path)
                        .map((r) => `${r.host}|${r.path}`),
                    ).size;
                    return `Add every unique host+path pair across ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} to scope include rules (${uniq} unique pair${uniq === 1 ? "" : "s"}). Pairs already in scope are skipped. Path-exact rules — narrower than R569's host-level.`;
                  })()
            }
          >
            + Add paths to scope
          </button>
          {/* R571: Bulk "− Exclude hosts" — counter op to R569
              "+ Add hosts to scope". Operators scope-exclude a
              cluster of noisy hosts (CDN beacons, analytics
              trackers, third-party widgets) in one click rather
              than per-row right-click. Builds an exclude-match
              rule inline (no exclude helper yet in
              scopeHelpers.ts; same shape as include but
              `match_kind: "exclude"`). Dedupe via Set, confirm
              pre-fire with preview. **Mechanism** mirrors R569
              but with the opposite match_kind — same sequential
              fan-out so backend's unique-rule guard sees adds in
              order. **No pre-filter** — we always add fresh
              exclude rules since operators often want multiple
              exclude passes with different narrowness; the
              backend handles dup-rule semantics. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              const uniqHosts = Array.from(
                new Set(selectedRows.map((r) => r.host).filter((h) => !!h)),
              );
              if (uniqHosts.length === 0) return;
              if (
                !confirm(
                  `Add ${uniqHosts.length} host${uniqHosts.length === 1 ? "" : "s"} to scope EXCLUDE rules?\n\n${uniqHosts.slice(0, 10).join("\n")}${uniqHosts.length > 10 ? `\n…+${uniqHosts.length - 10} more` : ""}\n\nTraffic matching these hosts will be excluded from scope-filtered views.`,
                )
              ) {
                return;
              }
              try {
                for (const h of uniqHosts) {
                  await api.scopeAddRule({
                    match_kind: "exclude",
                    protocol: "any",
                    host: h.trim(),
                    port: null as unknown as undefined,
                    path: "*",
                    regex: false,
                    enabled: true,
                  });
                }
                await reloadScope();
                alert(
                  `Excluded ${uniqHosts.length} host${uniqHosts.length === 1 ? "" : "s"} from scope.`,
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows.map((r) => r.host).filter((h) => !!h),
                    ).size;
                    return `Add every unique host across ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} to scope EXCLUDE rules (${uniq} unique host${uniq === 1 ? "" : "s"}). Great for scope-excluding noisy third-party hosts (CDNs, analytics, widgets) in one shot. Confirms pre-fire.`;
                  })()
            }
            className="danger"
          >
            − Exclude hosts
          </button>
          {/* R572: Bulk "− Exclude paths" — counter op to R570
              "+ Add paths to scope". Operators narrow-exclude
              specific endpoints (health checks like /healthz,
              static assets like /static/*, instrumentation like
              /telemetry/*) in one click. Composite-key dedup +
              inline exclude-rule build (match_kind: "exclude").
              Danger-styled like R571. Completes the 4-way
              scope-ops cluster (+ hosts / + paths / − hosts /
              − paths) matching Burp Pro's scope include/exclude
              pattern. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              const uniqPairs = Array.from(
                new Set(
                  selectedRows
                    .filter((r) => r.host && r.path)
                    .map((r) => `${r.host}|${r.path}`),
                ),
              ).map((p) => {
                const [host, ...rest] = p.split("|");
                return { host, path: rest.join("|") };
              });
              if (uniqPairs.length === 0) return;
              const preview = uniqPairs
                .slice(0, 10)
                .map((p) => `${p.host}${p.path}`)
                .join("\n");
              if (
                !confirm(
                  `Add ${uniqPairs.length} host+path pair${uniqPairs.length === 1 ? "" : "s"} to scope EXCLUDE rules?\n\n${preview}${uniqPairs.length > 10 ? `\n…+${uniqPairs.length - 10} more` : ""}\n\nTraffic matching these exact pairs will be excluded from scope-filtered views.`,
                )
              ) {
                return;
              }
              try {
                for (const p of uniqPairs) {
                  // Strip query string from path to match
                  // buildPathIncludeRule's convention — exclude
                  // rules should be stable across varying params.
                  const cleanPath = p.path.split("?")[0] || "/";
                  await api.scopeAddRule({
                    match_kind: "exclude",
                    protocol: "any",
                    host: p.host.trim(),
                    port: null as unknown as undefined,
                    path: cleanPath,
                    regex: false,
                    enabled: true,
                  });
                }
                await reloadScope();
                alert(
                  `Excluded ${uniqPairs.length} host+path pair${uniqPairs.length === 1 ? "" : "s"} from scope.`,
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : (() => {
                    const uniq = new Set(
                      selectedRows
                        .filter((r) => r.host && r.path)
                        .map((r) => `${r.host}|${r.path}`),
                    ).size;
                    return `Add every unique host+path pair across ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} to scope EXCLUDE rules (${uniq} unique pair${uniq === 1 ? "" : "s"}). Path-exact exclusion — narrower than R571's host-level. Great for excluding health checks (/healthz) / static assets / instrumentation endpoints. Confirms pre-fire.`;
                  })()
            }
            className="danger"
          >
            − Exclude paths
          </button>
          {/* R377: Copy METHOD + URL pairs — operators building a   */}
          {/* method-aware wordlist (e.g. `POST /login` + `GET      */}
          {/* /dashboard` + `PUT /api/user/42`) want this often      */}
          {/* for a crafted follow-up Burp Intruder run or an       */}
          {/* automated authz-tester. Format: `METHOD /path` so    */}
          {/* the output is Burp-list-friendly (same shape as      */}
          {/* request lines). Dedupe + sort alpha.                   */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    selectedRows.map((r) => `${r.method} ${r.path}`),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as "METHOD /path" lines (deduped + sorted). Great for authz-tester / method-aware wordlist / Burp Intruder input.`
            }
          >
            📋 Copy method+path
          </button>
          {/* R407: Bulk Copy as cURL — operators building a bash   */}
          {/* replay script, a CI smoke-test, or a teammate paste  */}
          {/* for "run these N requests in order" want cURL         */}
          {/* commands for every selected row concatenated with    */}
          {/* `\n\n` separators (double newline so a `bash` paste  */}
          {/* keeps each command on its own line). **Fan-out**     */}
          {/* needs per-row `historyShow(id)` because the summary   */}
          {/* row doesn't carry the raw request bytes (headers +   */}
          {/* body) that `buildCurl` needs — one RPC per selected  */}
          {/* row, Promise.allSettled so one failing row doesn't    */}
          {/* strand the rest. For 50 selected rows this is ~1s on */}
          {/* a healthy backend. **Progress** silent — the button   */}
          {/* flips disabled during the fan-out so operators see   */}
          {/* the busy state. **Order** preserves the display order */}
          {/* (not sorted) so operators can arrange a specific     */}
          {/* request sequence by sorting the history view first.  */}
          {/* **Mechanism** reuses `fromSummaryAndRaw` + `buildCurl`*/}
          {/* from the per-row copy flow so the output is byte-   */}
          {/* identical to the single-row Copy-as-cURL right-click. */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    const req = fromSummaryAndRaw(r, view.request_raw ?? "");
                    return buildCurl(req);
                  }),
                );
                const parts: string[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") parts.push(res.value);
                  else failed += 1;
                }
                if (parts.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes — the stored request_raw may be missing. Try a smaller selection to narrow down.`,
                  );
                  return;
                }
                await navigator.clipboard.writeText(parts.join("\n\n"));
                if (failed > 0) {
                  alert(
                    `Copied ${parts.length} cURL command${parts.length === 1 ? "" : "s"}; ${failed} row${failed === 1 ? "" : "s"} failed (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as cURL commands joined by blank lines (one historyShow RPC per row — expect ~${Math.max(1, Math.ceil(selectedIds.size * 20))} ms). Great for a bash replay script, CI smoke-test, or teammate paste.`
            }
          >
            📋 Copy as cURL
          </button>
          {/* R432: Bulk Copy as PowerShell — Windows-native sibling */}
          {/* of R407 bulk Copy as cURL. Operators building a       */}
          {/* PowerShell-based replay script, a scheduled task set, */}
          {/* or a Windows CI smoke-test prefer Invoke-WebRequest   */}
          {/* over cURL to avoid WSL/git-bash dependencies.         */}
          {/* **Fan-out + partial-failure UX** identical to R407,  */}
          {/* just with `buildPowerShell` instead of `buildCurl`.   */}
          {/* **Separator** `\n\n` same as R407 so each command    */}
          {/* lands on its own PowerShell line.                     */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    const req = fromSummaryAndRaw(r, view.request_raw ?? "");
                    return buildPowerShell(req);
                  }),
                );
                const parts: string[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") parts.push(res.value);
                  else failed += 1;
                }
                if (parts.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes — the stored request_raw may be missing. Try a smaller selection to narrow down.`,
                  );
                  return;
                }
                await navigator.clipboard.writeText(parts.join("\n\n"));
                if (failed > 0) {
                  alert(
                    `Copied ${parts.length} PowerShell command${parts.length === 1 ? "" : "s"}; ${failed} row${failed === 1 ? "" : "s"} failed (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as PowerShell Invoke-WebRequest commands joined by blank lines (one historyShow RPC per row — expect ~${Math.max(1, Math.ceil(selectedIds.size * 20))} ms). Great for a Windows replay script or scheduled task.`
            }
          >
            📋 Copy as PowerShell
          </button>
          {/* R433: Bulk Copy as Python (requests) — completes the  */}
          {/* bulk copy-as trio alongside R407 cURL + R432          */}
          {/* PowerShell. Operators building a Python-based test   */}
          {/* harness, pytest smoke suite, or scripted replay      */}
          {/* prefer the `requests` library over curl/PowerShell   */}
          {/* subprocess wrappers. **Fan-out + partial-failure UX***/}
          {/* identical to R407/R432, just with `buildPython`      */}
          {/* instead of `buildCurl`/`buildPowerShell`.             */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    const req = fromSummaryAndRaw(r, view.request_raw ?? "");
                    return buildPython(req);
                  }),
                );
                const parts: string[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") parts.push(res.value);
                  else failed += 1;
                }
                if (parts.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes — the stored request_raw may be missing. Try a smaller selection to narrow down.`,
                  );
                  return;
                }
                await navigator.clipboard.writeText(parts.join("\n\n"));
                if (failed > 0) {
                  alert(
                    `Copied ${parts.length} Python requests snippet${parts.length === 1 ? "" : "s"}; ${failed} row${failed === 1 ? "" : "s"} failed (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as Python requests snippets joined by blank lines (one historyShow RPC per row — expect ~${Math.max(1, Math.ceil(selectedIds.size * 20))} ms). Great for a pytest smoke suite or scripted replay.`
            }
          >
            📋 Copy as Python
          </button>
          {/* R434: Bulk Copy as fetch() — completes the bulk copy- */}
          {/* as quartet alongside R407 cURL + R432 PowerShell +    */}
          {/* R433 Python. Operators debugging in DevTools (browser */}
          {/* console paste → F12 → run) prefer fetch() over cURL/*/}
          {/* PowerShell. **Fan-out + partial-failure UX** identical*/}
          {/* to R407/R432/R433, just with `buildFetch` instead.    */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    const req = fromSummaryAndRaw(r, view.request_raw ?? "");
                    return buildFetch(req);
                  }),
                );
                const parts: string[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") parts.push(res.value);
                  else failed += 1;
                }
                if (parts.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes — the stored request_raw may be missing. Try a smaller selection to narrow down.`,
                  );
                  return;
                }
                await navigator.clipboard.writeText(parts.join("\n\n"));
                if (failed > 0) {
                  alert(
                    `Copied ${parts.length} fetch() snippet${parts.length === 1 ? "" : "s"}; ${failed} row${failed === 1 ? "" : "s"} failed (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as fetch() snippets joined by blank lines (one historyShow RPC per row — expect ~${Math.max(1, Math.ceil(selectedIds.size * 20))} ms). Great for DevTools console replay.`
            }
          >
            📋 Copy as fetch()
          </button>
          {/* R453: Bulk Copy as HAR — fifth bulk copy-as member     */}
          {/* alongside R407 cURL + R432 PowerShell + R433 Python + */}
          {/* R434 fetch(). HAR 1.2 is an open W3C spec for         */}
          {/* exchanging HTTP captures between tools (DevTools /    */}
          {/* intercepting proxies / test harnesses); copying as    */}
          {/* HAR lets operators replay a selection in Chrome /     */}
          {/* Firefox / HTTP Toolkit / Fiddler without any format   */}
          {/* translation. **Container format** HAR is a single     */}
          {/* JSON object with an entries[] array — unlike the      */}
          {/* R407/R432-R434 per-command outputs that join with     */}
          {/* \n\n, this emits one JSON object via buildHarLog().   */}
          {/* **Fan-out + partial-failure UX** identical to the     */}
          {/* siblings, but we also pull response_raw via the same  */}
          {/* historyShow() RPC so each entry carries request +     */}
          {/* response fields (status / headers / body) when the    */}
          {/* backend has them. Rows missing request_raw are        */}
          {/* skipped silently rather than inserted as blank        */}
          {/* entries — a half-populated HAR confuses downstream    */}
          {/* viewers more than a shorter but complete one.         */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    if (!view.request_raw) throw new Error("missing request_raw");
                    const req = fromSummaryAndRaw(r, view.request_raw);
                    // Parse response_raw opportunistically — HAR
                    // tolerates missing response fields but a 200
                    // + body is friendlier for DevTools paste-back.
                    let resp: Parameters<typeof buildHarEntry>[2] = undefined;
                    if (view.response_raw) {
                      const text = view.response_raw.replace(/\r\n/g, "\n");
                      const headerEnd = text.indexOf("\n\n");
                      const headerBlock =
                        headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                      const body = headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                      const lines = headerBlock.split("\n");
                      const statusLine = (lines.shift() ?? "").trim();
                      // "HTTP/1.1 200 OK" or "HTTP/2 200"
                      const m = statusLine.match(/^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/);
                      const httpVersion = m?.[1] ?? "HTTP/1.1";
                      const status = m ? parseInt(m[2], 10) : 0;
                      const statusText = m?.[3] ?? "";
                      const headers: Array<[string, string]> = [];
                      let mimeType = "";
                      for (const l of lines) {
                        const colon = l.indexOf(":");
                        if (colon <= 0) continue;
                        const n = l.slice(0, colon).trim();
                        const v = l.slice(colon + 1).trim();
                        if (!n) continue;
                        headers.push([n, v]);
                        if (n.toLowerCase() === "content-type") mimeType = v;
                      }
                      resp = { status, statusText, httpVersion, headers, mimeType, body };
                    }
                    const startedDateTime = new Date(r.ts_ms).toISOString();
                    return buildHarEntry(req, startedDateTime, resp);
                  }),
                );
                const entries: object[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") entries.push(res.value);
                  else failed += 1;
                }
                if (entries.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes — the stored request_raw may be missing. Try a smaller selection to narrow down.`,
                  );
                  return;
                }
                const har = buildHarLog(entries);
                await navigator.clipboard.writeText(JSON.stringify(har, null, 2));
                if (failed > 0) {
                  alert(
                    `Copied ${entries.length} HAR entr${entries.length === 1 ? "y" : "ies"}; ${failed} row${failed === 1 ? "" : "s"} skipped (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Copy ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as a HAR 1.2 log (one historyShow RPC per row — expect ~${Math.max(1, Math.ceil(selectedIds.size * 20))} ms). Container format: a single JSON object with entries[] carrying request + response fields when available. Paste into Chrome DevTools "Network → Import HAR", Firefox, HTTP Toolkit, Fiddler.`
            }
          >
            📋 Copy as HAR
          </button>
          {/* R490: Bulk "⬇ Save as HAR file" — file-save variant   */}
          {/* of R453 Copy as HAR. Same HAR 1.2 content + same       */}
          {/* fan-out pattern (Promise.allSettled per row), but      */}
          {/* writes a .har file to disk via Blob + anchor click    */}
          {/* instead of copying to clipboard. Operators attaching  */}
          {/* HAR to tickets / sharing with teammates / archiving   */}
          {/* for a reproducible repro want a file not a clipboard  */}
          {/* paste (large HAR dumps blow past clipboard caps on   */}
          {/* some OSes). Filename pattern                           */}
          {/* `burpfree-har-<timestamp>.har` matches Chrome        */}
          {/* DevTools' default export filename convention so      */}
          {/* downstream viewers recognize the extension.          */}
          <button
            onClick={async () => {
              if (selectedRows.length === 0) return;
              try {
                const results = await Promise.allSettled(
                  selectedRows.map(async (r) => {
                    const view = await api.historyShow(r.id);
                    if (!view.request_raw) throw new Error("missing request_raw");
                    const req = fromSummaryAndRaw(r, view.request_raw);
                    let resp: Parameters<typeof buildHarEntry>[2] = undefined;
                    if (view.response_raw) {
                      const text = view.response_raw.replace(/\r\n/g, "\n");
                      const headerEnd = text.indexOf("\n\n");
                      const headerBlock =
                        headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                      const body = headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                      const lines = headerBlock.split("\n");
                      const statusLine = (lines.shift() ?? "").trim();
                      const m = statusLine.match(/^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/);
                      const httpVersion = m?.[1] ?? "HTTP/1.1";
                      const status = m ? parseInt(m[2], 10) : 0;
                      const statusText = m?.[3] ?? "";
                      const headers: Array<[string, string]> = [];
                      let mimeType = "";
                      for (const l of lines) {
                        const colon = l.indexOf(":");
                        if (colon <= 0) continue;
                        const n = l.slice(0, colon).trim();
                        const v = l.slice(colon + 1).trim();
                        if (!n) continue;
                        headers.push([n, v]);
                        if (n.toLowerCase() === "content-type") mimeType = v;
                      }
                      resp = { status, statusText, httpVersion, headers, mimeType, body };
                    }
                    const startedDateTime = new Date(r.ts_ms).toISOString();
                    return buildHarEntry(req, startedDateTime, resp);
                  }),
                );
                const entries: object[] = [];
                let failed = 0;
                for (const res of results) {
                  if (res.status === "fulfilled") entries.push(res.value);
                  else failed += 1;
                }
                if (entries.length === 0) {
                  alert(
                    `All ${selectedRows.length} row${selectedRows.length === 1 ? "" : "s"} failed to resolve request bytes.`,
                  );
                  return;
                }
                const har = buildHarLog(entries);
                const stamp = new Date()
                  .toISOString()
                  .replace(/[:T]/g, "-")
                  .replace(/\..*$/, "");
                const name = `burpfree-har-${stamp}.har`;
                const blob = new Blob([JSON.stringify(har, null, 2)], {
                  type: "application/json;charset=utf-8",
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = name;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                if (failed > 0) {
                  alert(
                    `Saved ${entries.length} HAR entr${entries.length === 1 ? "y" : "ies"} to ${name}; ${failed} row${failed === 1 ? "" : "s"} skipped (missing request_raw).`,
                  );
                }
              } catch (e) {
                alert(`${e}`);
              }
            }}
            disabled={selectedIds.size === 0}
            title={
              selectedIds.size === 0
                ? "No rows selected"
                : `Save ${selectedIds.size} selected row${selectedIds.size === 1 ? "" : "s"} as a .har file — file-save variant of "Copy as HAR" (clipboard). Filename pattern burpfree-har-<timestamp>.har matches Chrome DevTools' export convention. Great for ticket attachments / long-term archive / sharing with teammates where clipboard-paste doesn't fit.`
            }
          >
            ⬇ Save as HAR file
          </button>
          <button className="danger" onClick={bulkDelete}>
            Delete
          </button>
          <span className="spacer" style={{ flex: 1 }} />
          <button onClick={clearSelection}>Clear selection</button>
        </div>
      )}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
          <div className="table">
            {/* R778: Burp-identical empty-state card for the HTTP
                history table. Mirrors Burp Suite 2026.8's history
                empty state which shows a friendly centered card
                with an SVG request-silhouette icon, a bold "No HTTP
                history yet" headline, descriptive subhead
                explaining how traffic lands in history, and a
                shortcut hint. Only renders when `rows.length === 0`
                AND there's no active filter — a filtered empty
                view would benefit from a different "no matches"
                message (which we leave to the toolbar filter
                summary for now). Lets operators who've just opened
                BurpFree understand "I need to browse through the
                proxied browser or send manual requests" without
                reading the docs. */}
            {rows.length === 0 && !hasActiveFilter(filter) && (
              <div className="hist-empty-card">
                <div className="hist-empty-icon">
                  <svg
                    width="56"
                    height="56"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M4 5h16M4 10h16M4 15h10M4 20h7" />
                  </svg>
                </div>
                <div className="hist-empty-title">No HTTP history yet</div>
                <div className="hist-empty-sub">
                  Every proxied request that passes the scope filter lands
                  here. Open the proxied browser (Proxy → Options → Open
                  browser) and start browsing, or send manual requests via
                  Repeater. Live traffic auto-refreshes every 2 seconds
                  when auto-refresh is on.
                </div>
                <div className="hist-empty-hints">
                  Shortcuts: <b>J</b>/<b>K</b> walk rows · <b>Ctrl+A</b>{" "}
                  select all · <b>Ctrl+F</b> filter · <b>Esc</b> clear
                  filter · right-click a row for Send-to-Repeater /
                  Scanner / Intruder / Decoder / Comparer handoff
                </div>
              </div>
            )}
            {/* R778: Filtered empty state — distinct from the
                initial empty state. When the operator has an active
                filter but there are 0 matches, surface that
                explicitly so they know to loosen the filter rather
                than wonder why their traffic vanished. */}
            {rows.length === 0 && hasActiveFilter(filter) && (
              <div className="hist-empty-card">
                <div className="hist-empty-icon">
                  <svg
                    width="56"
                    height="56"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <circle cx="11" cy="11" r="7" />
                    <path d="M20 20l-4-4" />
                  </svg>
                </div>
                <div className="hist-empty-title">
                  No rows match the current filter
                </div>
                <div className="hist-empty-sub">
                  Try loosening a dimension — widen the time range, drop a
                  method chip, remove a status filter, or clear the
                  search text. Click the <b>Clear filters</b> button in
                  the toolbar to reset every dimension at once.
                </div>
              </div>
            )}
            <table>
              <colgroup>
                {visibleColumns.map((c) => (
                  <col
                    key={c.key}
                    style={c.width !== undefined ? { width: c.width } : undefined}
                  />
                ))}
              </colgroup>
              {/* R244: Sticky header mirror of R243 Scanner. */}
              {/* Operators scrolling long history lists keep */}
              {/* column labels visible as rows slide under.    */}
              {/* Background var(--bg) prevents semi-transparent*/}
              {/* bleed-through on scroll.                      */}
              <thead
                style={{
                  position: "sticky",
                  top: 0,
                  zIndex: 1,
                  background: "var(--bg)",
                }}
              >
                <tr>
                  {visibleColumns.map((c) => {
                    const active = sortKey === c.key;
                    return (
                      <th
                        key={c.key}
                        title={c.title}
                        style={{ cursor: "pointer", userSelect: "none" }}
                        onClick={() => toggleSort(c.key)}
                      >
                        {c.label}
                        {active && (
                          <span style={{ marginLeft: 4, color: "var(--accent)" }}>
                            {sortDir === "asc" ? "▲" : "▼"}
                          </span>
                        )}
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((r) => {
                  const stripe = r.highlight ? HIGHLIGHT_COLORS[r.highlight] : undefined;
                  const isBulkSelected = selectedIds.has(r.id);
                  const isActive = selected?.id === r.id;
                  const rowStyle: React.CSSProperties = {};
                  // Keep the row-stripe boxShadow on the <tr> itself so
                  // hiding the "highlight" column via the Columns menu
                  // doesn't erase the colour cue — operators who hide
                  // the gutter still get the inset accent on the row.
                  if (stripe) rowStyle.boxShadow = `inset 3px 0 0 ${stripe}`;
                  // R295: Status-class row tint — mirror of R294
                  // Intruder results tint applied to HTTP history.
                  // 2xx = green, 3xx = accent-blue, 4xx = amber,
                  // 5xx = red; alpha scales up progressively with
                  // "severity" so a 5xx row pops hardest while a
                  // 2xx row barely registers. Lower precedence than
                  // bulk-select (which trumps with --accent-dim)
                  // and the inset-shadow stripe (which stacks on
                  // top). Only tints when status is set so in-
                  // flight / errored rows stay default.
                  const s = r.status || 0;
                  if (s >= 200 && s < 300)
                    rowStyle.background = "rgba(76, 175, 80, 0.06)";
                  else if (s >= 300 && s < 400)
                    rowStyle.background = "rgba(90, 160, 220, 0.06)";
                  else if (s >= 400 && s < 500)
                    rowStyle.background = "rgba(240, 192, 48, 0.08)";
                  else if (s >= 500 && s < 600)
                    rowStyle.background = "rgba(224, 68, 68, 0.10)";
                  // Bulk selection trumps the active-viewer highlight so the
                  // operator can tell at-a-glance which rows a bulk op will act on.
                  if (isBulkSelected) rowStyle.background = "var(--accent-dim)";
                  return (
                    <tr
                      key={r.id}
                      data-row-id={r.id}
                      className={isActive ? "selected" : ""}
                      onClick={(e) => onRowClick(e, r)}
                      onContextMenu={(e) => onRowContextMenu(e, r)}
                      style={Object.keys(rowStyle).length > 0 ? rowStyle : undefined}
                    >
                      {visibleColumns.map((c) => (
                        <React.Fragment key={c.key}>{c.renderCell(r)}</React.Fragment>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
        <div style={{ width: "50%", minWidth: 0, borderLeft: "1px solid var(--border)" }}>
          <TransactionViewer tx={tx} />
        </div>
      </div>
      <FloatingMenu
        state={menu}
        onClose={() => setMenu(null)}
        items={
          menu?.data
            ? [
                {
                  label: "Send to Repeater",
                  hotkey: "→ R",
                  onClick: () => void sendToRepeater(menu.data!),
                },
                {
                  label: "Send to Intruder",
                  hotkey: "→ I",
                  onClick: () => void sendToIntruder(menu.data!),
                },
                {
                  label: "Replay request",
                  hint: "re-fire bytes through the shared client",
                  onClick: () => void replayRow(menu.data!),
                },
                {
                  label: "Run active scan",
                  hint: "fires every enabled probe against this request",
                  onClick: () => void activeScanRow(menu.data!),
                },
                {
                  label: "Send to Comparer (left)",
                  onClick: () => void sendToComparerAction(menu.data!, "left"),
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () => void sendToComparerAction(menu.data!, "right"),
                },
                {
                  label: "Send to Organizer",
                  hotkey: "Ctrl+O",
                  onClick: () => void sendToOrganizer(menu.data!),
                },
                { separator: true },
                {
                  label: "Copy URL",
                  onClick: () => void copyAs(menu.data!, "url"),
                },
                {
                  label: "Copy as cURL",
                  hint: "full headers + body",
                  onClick: () => void copyAs(menu.data!, "curl"),
                },
                // 🎯 R640: HistoryPanel row-right-click "Copy as
                // Markdown" — single-row version of R639 bulk
                // Markdown (full). Right-click → "Copy as Markdown"
                // produces one H3 section with method+URL + status +
                // content-type + size + optional highlight/comment/
                // tags. R640 round-number milestone. Mirrors R625
                // Target Issues row-right-click Markdown pattern
                // (which uses table format for findings).
                {
                  label: "Copy as Markdown",
                  hint: "H3 section · request+annotations",
                  onClick: () => {
                    const r = menu.data!;
                    const lines = [
                      `### ${r.method} ${r.host}${r.path}`,
                      "",
                      `- **Status**: ${r.status ?? "—"}`,
                      `- **Content-Type**: ${r.content_type || "—"}`,
                      `- **Size**: ${r.content_length ?? "—"} bytes`,
                    ];
                    if (r.highlight) lines.push(`- **Highlight**: ${r.highlight}`);
                    if (r.comment) lines.push(`- **Comment**: ${r.comment}`);
                    if (r.tags && r.tags.length > 0)
                      lines.push(`- **Tags**: ${r.tags.join(", ")}`);
                    void navigator.clipboard.writeText(lines.join("\n"));
                  },
                },
                // R651: HistoryPanel row-right-click "Copy as JSON"
                // — single-row version of R605 bulk Copy as JSON.
                // Right-click → Copy as JSON produces one JSON
                // object (the full StoredSummary record) on the
                // clipboard, pretty-printed. Great for pasting
                // into a test case or scratch note.
                {
                  label: "Copy as JSON",
                  hint: "full StoredSummary record · pretty-printed",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!, null, 2),
                    ),
                },
                // R708: HistoryPanel row "Copy JSONL line" —
                // single-row NDJSON format (one JSON object on
                // one line, no array wrap, no pretty-print).
                // Different shape from R651 Copy as JSON pretty-
                // printed — JSONL line is for operators building
                // a scratch jq input one row at a time or
                // appending to an existing .jsonl log. Trailing
                // newline so repeated clicks concat cleanly in
                // a text buffer. Byte-identical to R614 bulk
                // Copy-as-JSONL per-line output.
                {
                  label: "Copy JSONL line",
                  hint: "one object, one line + newline",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!) + "\n",
                    ),
                },
                // R717: HistoryPanel row "Copy method+URL+status"
                // — ultra-compact single-line triage format
                // "GET https://example.com/path 200 (1.2 KB)"
                // for a quick scratch note / Slack ping / ticket
                // comment where neither JSON nor Markdown nor
                // cURL fits. Status + size optional (fall back
                // to the request-only "GET https://..." when a
                // response isn't recorded).
                {
                  label: "Copy method+URL+status",
                  hint: "compact triage line",
                  onClick: () => {
                    const r = menu.data!;
                    const scheme = r.scheme || "http";
                    const portTag =
                      (scheme === "http" && r.port !== 80) ||
                      (scheme === "https" && r.port !== 443)
                        ? `:${r.port}`
                        : "";
                    const url = `${scheme}://${r.host}${portTag}${r.path}`;
                    const parts: string[] = [r.method, url];
                    if (typeof r.status === "number") {
                      parts.push(String(r.status));
                      const b = r.content_length;
                      if (typeof b === "number" && b >= 0) {
                        const sz =
                          b < 1024
                            ? `${b} B`
                            : b < 1024 * 1024
                              ? `${(b / 1024).toFixed(1)} KB`
                              : `${(b / 1024 / 1024).toFixed(2)} MB`;
                        parts.push(`(${sz})`);
                      }
                    }
                    void navigator.clipboard.writeText(parts.join(" "));
                  },
                },
                // R663: HistoryPanel row-right-click "Copy table
                // row" — single-row Markdown table variant of
                // R624 bulk Copy as Markdown table. Just the
                // row-content Markdown line (no header, no
                // separator) so it slots cleanly into an existing
                // table in a doc. Great for "add this request to
                // the smoke-test table I'm maintaining".
                {
                  label: "Copy table row",
                  hint: "Markdown table body line · no header",
                  onClick: () => {
                    const r = menu.data!;
                    const esc = (v: unknown) =>
                      String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
                    const cells = [
                      r.id,
                      r.method,
                      r.host,
                      r.path,
                      r.status ?? "",
                      r.content_length ?? "",
                    ]
                      .map(esc)
                      .join(" | ");
                    void navigator.clipboard.writeText(`| ${cells} |`);
                  },
                },
                {
                  label: "Copy as PowerShell",
                  onClick: () => void copyAs(menu.data!, "powershell"),
                },
                {
                  label: "Copy as Python (requests)",
                  onClick: () => void copyAs(menu.data!, "python"),
                },
                {
                  label: "Copy as fetch()",
                  hint: "paste into DevTools console",
                  onClick: () => void copyAs(menu.data!, "fetch"),
                },
                /* R470: Row-scope "Copy as HAR entry" — per-row       */
                /* mirror of R453's bulk Copy as HAR button. Builds   */
                /* a single-entry HAR 1.2 log from this row's         */
                /* request_raw + response_raw and copies the pretty-  */
                /* printed JSON to clipboard. Operators grabbing      */
                /* just one row for a tool handoff (Chrome DevTools  */
                /* "Network → Import HAR", HTTP Toolkit, Fiddler)    */
                /* get a one-click path without a bulk-select pivot. */
                {
                  label: "Copy as HAR entry",
                  hint: "single-entry HAR log · W3C spec",
                  onClick: () => void copyAs(menu.data!, "har"),
                },
                {
                  label: "⬇ Save as HAR file",
                  hint: "single-entry HAR log · to disk",
                  onClick: () => void saveAsHar(menu.data!),
                },
                /* R404: Request-side copy trio — complements the      */
                /* response-side R166 (body / raw) + R403 (headers)   */
                /* with parallel entries for the request. Operators   */
                /* debugging CORS preflights, replaying a POST body   */
                /* into a sibling tool, or auditing request headers   */
                /* (Authorization, Cookie, X-CSRF-Token, Content-Type) */
                /* now have one-click access without a Repeater round */
                /* trip. Mechanism: `historyShow(id)` to pull          */
                /* request_raw, then slice around the first CRLF-CRLF */
                /* / LF-LF boundary (same split logic as R166 /       */
                /* R403). Headers-only = pre-boundary slice; body-only*/
                /* = post-boundary slice; raw = full dump.             */
                {
                  label: "Copy raw request (headers + body)",
                  hint: "clipboard · everything",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      await navigator.clipboard.writeText(tx.request_raw ?? "");
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                {
                  label: "Copy request headers",
                  hint: "clipboard · headers only",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      const raw = tx.request_raw ?? "";
                      const crlfIdx = raw.indexOf("\r\n\r\n");
                      const lfIdx = raw.indexOf("\n\n");
                      let headerEnd = -1;
                      if (crlfIdx >= 0) headerEnd = crlfIdx;
                      else if (lfIdx >= 0) headerEnd = lfIdx;
                      const headers = headerEnd > 0 ? raw.slice(0, headerEnd) : raw;
                      await navigator.clipboard.writeText(headers);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                {
                  label: "Copy request body",
                  hint: "clipboard · body only",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      const raw = tx.request_raw ?? "";
                      const idx =
                        raw.indexOf("\r\n\r\n") >= 0
                          ? raw.indexOf("\r\n\r\n") + 4
                          : raw.indexOf("\n\n") >= 0
                            ? raw.indexOf("\n\n") + 2
                            : 0;
                      const body = idx > 0 ? raw.slice(idx) : "";
                      await navigator.clipboard.writeText(body);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                { separator: true },
                {
                  label: "Open response in browser",
                  hint: "render body via OS default handler",
                  onClick: () => void openResponseInBrowser(menu.data!),
                },
                {
                  label: "Request in browser",
                  hint: "fire URL at the OS default browser",
                  onClick: () => void requestInBrowser(menu.data!),
                },
                {
                  label: "Save response body…",
                  hint: "binary-safe write, body only",
                  onClick: () => void saveResponseBody(menu.data!, false),
                },
                {
                  label: "Save raw response (headers + body)…",
                  hint: "status line + headers + body as one file",
                  onClick: () => void saveResponseBody(menu.data!, true),
                },
                /* R166: Copy response body / copy raw response to     */
                /* clipboard. The existing Save-to-file menu is great  */
                /* for large or binary responses, but operators often  */
                /* just want the response bytes in their clipboard for */
                /* a quick jq / grep / Slack paste. We fetch the raw   */
                /* response via historyShow (same API the detail pane */
                /* already uses) and strip the headers for body-only.  */
                /* UTF-8-ish responses only — binary content gets      */
                /* mangled on clipboard, so stick with Save for those. */
                {
                  label: "Copy response body",
                  hint: "clipboard · body only",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      const raw = tx.response_raw ?? "";
                      // Split at the first CRLF-CRLF (or LF-LF) that
                      // separates headers from body. Fall back to the
                      // whole response when there's no obvious split
                      // (chunk-only / malformed response).
                      const idx =
                        raw.indexOf("\r\n\r\n") >= 0
                          ? raw.indexOf("\r\n\r\n") + 4
                          : raw.indexOf("\n\n") >= 0
                            ? raw.indexOf("\n\n") + 2
                            : 0;
                      const body = idx > 0 ? raw.slice(idx) : raw;
                      await navigator.clipboard.writeText(body);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                /* R414: Copy response body (pretty JSON) — operators */
                /* reading JSON APIs want pretty-printed output for   */
                /* easier eyeballing / jq-less exploration. Attempt    */
                /* JSON.parse(body); on success, re-stringify with    */
                /* 2-space indent and copy. On parse failure, fall    */
                /* back to the raw body (same output as "Copy response*/
                /* body") so the entry is never a dead-end. The       */
                /* `hint` labels this behavior so operators know the  */
                /* parse-vs-raw fallback up front.                     */
                {
                  label: "Copy response body (pretty JSON)",
                  hint: "parses + reformats; falls back to raw if not JSON",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      const raw = tx.response_raw ?? "";
                      const idx =
                        raw.indexOf("\r\n\r\n") >= 0
                          ? raw.indexOf("\r\n\r\n") + 4
                          : raw.indexOf("\n\n") >= 0
                            ? raw.indexOf("\n\n") + 2
                            : 0;
                      const body = idx > 0 ? raw.slice(idx) : raw;
                      let pretty = body;
                      try {
                        pretty = JSON.stringify(JSON.parse(body), null, 2);
                      } catch {
                        // Not JSON — leave body as-is so operators
                        // still get something copied.
                      }
                      await navigator.clipboard.writeText(pretty);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                {
                  label: "Copy raw response (headers + body)",
                  hint: "clipboard · everything",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      await navigator.clipboard.writeText(tx.response_raw ?? "");
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                /* R403: Copy response headers only — slice between the */
                /* status line and the header/body boundary.             */
                /* Complements the existing body-only + raw full-dump   */
                /* entries. Operators auditing security headers (CSP,  */
                /* HSTS, X-Frame-Options, Content-Security-Policy,     */
                /* Set-Cookie flags, CORS Access-Control-* headers)    */
                /* want just the response header block without the    */
                /* body noise. Falls back to the whole response when */
                /* there's no obvious CRLF-CRLF/LF-LF split (chunk-   */
                /* only or malformed response). Same split logic as   */
                /* R166's body extraction, just the complementary     */
                /* slice.                                               */
                {
                  label: "Copy response headers",
                  hint: "clipboard · headers only",
                  onClick: async () => {
                    try {
                      const tx = await api.historyShow(menu.data!.id);
                      const raw = tx.response_raw ?? "";
                      const crlfIdx = raw.indexOf("\r\n\r\n");
                      const lfIdx = raw.indexOf("\n\n");
                      let headerEnd = -1;
                      if (crlfIdx >= 0) headerEnd = crlfIdx;
                      else if (lfIdx >= 0) headerEnd = lfIdx;
                      const headers = headerEnd > 0 ? raw.slice(0, headerEnd) : raw;
                      await navigator.clipboard.writeText(headers);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                { separator: true },
                {
                  label: `Open ${menu.data!.host} in SiteMap`,
                  hint: "preseeds the host search box",
                  onClick: () => {
                    window.dispatchEvent(
                      new CustomEvent("burpfree:target-sitemap-search", {
                        detail: { host: menu.data!.host },
                      }),
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "target" },
                      }),
                    );
                  },
                },
                {
                  label: `Add host ${menu.data!.host} to scope`,
                  disabled: hasHostIncludeRule(scope, menu.data!.host),
                  hint: hasHostIncludeRule(scope, menu.data!.host) ? "already in scope" : undefined,
                  onClick: () => void addHostToScope(menu.data!),
                },
                {
                  label: "Add path to scope",
                  hint: menu.data!.path,
                  disabled: hasPathIncludeRule(scope, menu.data!.host, menu.data!.path),
                  onClick: () => void addPathToScope(menu.data!),
                },
                {
                  label: "Remove host from scope",
                  disabled: !hasHostIncludeRule(scope, menu.data!.host),
                  danger: hasHostIncludeRule(scope, menu.data!.host),
                  onClick: () => void removeHostFromScope(menu.data!),
                },
                // R590: Row-right-click "− Exclude host from scope" — single-row
                // counterpart to R571's bulk "− Exclude hosts". Semantically
                // DIFFERENT from "Remove host from scope" above: this ADDS an
                // explicit exclude rule (match_kind: "exclude") so the host is
                // actively filtered out even if an include rule exists higher up
                // in the chain. Mirrors the R571 bulk inline-rule shape since
                // scopeHelpers.ts has no exclude helper yet. Backend's
                // unique-rule guard idempotently no-ops on duplicate exclude
                // adds. Danger-styled to make it clear this is a destructive
                // scope op. Always enabled when the row has a host — unlike
                // the include/remove ops above which gate on hasHostIncludeRule.
                {
                  label: `Exclude host ${menu.data!.host}`,
                  danger: true,
                  hint: "add scope EXCLUDE rule",
                  onClick: async () => {
                    const host = menu.data!.host;
                    if (!host) return;
                    try {
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: host.trim(),
                        port: null as unknown as undefined,
                        path: "*",
                        regex: false,
                        enabled: true,
                      });
                      await reloadScope();
                      alert(`Excluded host "${host}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R591: Row-right-click "− Exclude path from scope" — path-exact
                // counterpart to R590's host-wide exclude. Operators often want
                // narrower exclude rules (just /healthz, not the whole host) so
                // actively noisy endpoints disappear from scope-filtered views
                // without hiding the rest of the host. Same inline exclude-rule
                // shape as R590 but with path-exact `path: menu.data.path`.
                // Backend's unique-rule guard idempotently no-ops on duplicate
                // adds. Danger-styled. Disabled when the row has no path.
                {
                  label: "Exclude path from scope",
                  hint: menu.data!.path || "no path",
                  disabled: !menu.data!.path,
                  danger: !!menu.data!.path,
                  onClick: async () => {
                    const host = menu.data!.host;
                    const path = menu.data!.path;
                    if (!host || !path) return;
                    try {
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: host.trim(),
                        port: null as unknown as undefined,
                        path,
                        regex: false,
                        enabled: true,
                      });
                      await reloadScope();
                      alert(`Excluded "${host}${path}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                { separator: true },
                ...Object.entries(HIGHLIGHT_COLORS).map(([name, hex]) => ({
                  label: `Highlight · ${name}`,
                  hint: menu.data!.highlight === name ? "current" : hex,
                  onClick: () => void setHighlight(menu.data!, name),
                })),
                {
                  label: "Highlight · clear",
                  disabled: !menu.data!.highlight,
                  onClick: () => void setHighlight(menu.data!, null),
                },
                { separator: true },
                {
                  label: menu.data.comment ? "Edit comment…" : "Add comment…",
                  hint: menu.data.comment || undefined,
                  onClick: () =>
                    setCommentDraft({
                      id: menu.data!.id,
                      text: menu.data!.comment ?? "",
                    }),
                },
                // R321: Single-row companion to R320's bulk +Add tag.
                // Operators triaging a specific row (not the current
                // bulk selection) often want to drop one tag onto
                // just this transaction — merge mode so existing
                // tags survive. Reuses the R320 historySetTags RPC +
                // the same prompt/trim/union/write/toast flow but
                // scoped to the right-clicked row. Hint shows the
                // current tag count so operators have context before
                // the prompt lands.
                {
                  label: "Add tag…",
                  hint:
                    (menu.data.tags?.length ?? 0) > 0
                      ? `currently: ${(menu.data.tags ?? []).join(", ")}`
                      : "no tags yet",
                  onClick: () => {
                    const r = menu.data!;
                    const next = prompt(
                      `Add a tag to this transaction (${r.method} ${r.host}${r.path.length > 40 ? r.path.slice(0, 37) + "…" : r.path}):\n\n(Merge mode — existing tags survive. No-op if the tag's already here.)`,
                      "",
                    );
                    if (next === null) return;
                    const tag = next.trim();
                    if (tag.length === 0) {
                      alert("Empty tag — nothing to apply.");
                      return;
                    }
                    void (async () => {
                      const cur = r.tags ?? [];
                      if (cur.includes(tag)) {
                        alert(`Already has tag "${tag}" — no change.`);
                        return;
                      }
                      try {
                        const merged = Array.from(new Set([...cur, tag]));
                        await api.historySetTags(r.id, merged);
                        await refresh();
                      } catch (e) {
                        alert(`${e}`);
                      }
                    })();
                  },
                },
              ]
            : []
        }
      />
      {commentDraft && (
        <CommentModal
          initial={commentDraft.text}
          onCancel={() => setCommentDraft(null)}
          onSave={(text) => void saveComment(commentDraft.id, text)}
        />
      )}
    </div>
  );
}

/** Minimal modal that lets the operator type / clear a comment on
 *  the active history row. Uses a backdrop so Esc / click-outside
 *  cancels without saving. */
function CommentModal({
  initial,
  onCancel,
  onSave,
}: {
  initial: string;
  onCancel: () => void;
  onSave: (text: string) => void;
}) {
  const [text, setText] = useState(initial);
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.45)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 2000,
      }}
      onClick={onCancel}
    >
      <div
        className="panel"
        style={{
          width: 500,
          minHeight: 160,
          background: "var(--bg-raised)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: 14,
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <strong>Edit comment</strong>
        <textarea
          autoFocus
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onCancel();
            else if ((e.ctrlKey || e.metaKey) && e.key === "Enter") onSave(text);
          }}
          style={{ minHeight: 80, resize: "vertical" }}
          placeholder="Notes for this request — searchable in the top-level filter."
        />
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button onClick={onCancel}>Cancel</button>
          <button className="primary" onClick={() => onSave(text)}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

function TransactionViewer({ tx }: { tx: TransactionView | null }) {
  if (!tx) return <div className="empty">Select a request</div>;
  // R408: Save helper for the detail-pane 📋/⬇ buttons. Inline
  // Blob+anchor idiom (matches R401 Scanner / R402 Target /
  // R406 Repeater save buttons) — browser blob download so no
  // Tauri file-system permission required.
  const saveBlob = (name: string, body: string) => {
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };
  const copyBlob = async (body: string) => {
    try {
      await navigator.clipboard.writeText(body);
    } catch (e) {
      alert(`${e}`);
    }
  };
  // R543: Sticky URL header at the top of the detail pane. Mirrors
  // R491 Scanner + R492 Target Issues detail-pane "📎 Copy URL"
  // sticky header, applied to HistoryPanel. Operators previewing a
  // transaction want the URL on the clipboard without a right-click
  // + Copy URL pivot — the sticky header is one click. Shows the
  // URL inline (truncated with ellipsis if long) + a "📎 Copy URL"
  // button. The host:method:status triple is already in the row
  // table, but a URL-first header makes the detail pane feel like
  // a Burp-style focused view. **🎯 100-round chunk mark** —
  // R444-R543 inclusive, streak R27-R543 = 517 continuous rounds.
  const url = tx.summary ? urlFromSummary(tx.summary) : "";
  return (
    <div className="viewer">
      {url && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "4px 8px",
            background: "var(--bg-faint)",
            borderBottom: "1px solid var(--border)",
            marginBottom: 6,
            fontSize: 11.5,
          }}
        >
          <span
            className="mono"
            style={{
              flex: 1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              color: "var(--text-faint)",
            }}
            title={url}
          >
            {url}
          </span>
          <button
            className="ghost"
            onClick={() => void copyBlob(url)}
            title="Copy the full URL to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📎 Copy URL
          </button>
          {/* R546: Sibling "📋 cURL" button in the sticky header —
              one-click cURL copy from the detail pane. Operators
              previewing a tx want shell-replay in reach without
              a row-right-click pivot. Mechanism: reuses R404-era
              fromSummaryAndRaw + buildCurl. Needs the raw request
              bytes — fetches via tx.request_raw already in scope.
              Byte-identical output to the row-right-click
              "Copy as cURL" entry so operators get a consistent
              artifact regardless of entry point. */}
          <button
            className="ghost"
            onClick={() => {
              if (!tx.summary || !tx.request_raw) {
                alert("Transaction has no stored request_raw — cannot build cURL.");
                return;
              }
              try {
                const req = fromSummaryAndRaw(tx.summary, tx.request_raw);
                void copyBlob(buildCurl(req));
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title="Copy as cURL (headers + body) to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 cURL
          </button>
          {/* 🎯 R550: Sticky-header "📋 HAR" button — third button
              in the sticky header, round-number milestone. One-
              click HAR entry copy from the detail pane without a
              row-right-click pivot. Byte-identical output to R470
              row-right-click "Copy as HAR entry" since both build
              the same single-entry HAR 1.2 log via buildHarEntry +
              buildHarLog. Inline response-parse replicated from
              R470/R543 pattern. */}
          <button
            className="ghost"
            onClick={() => {
              if (!tx.summary || !tx.request_raw) {
                alert("Transaction has no stored request_raw — cannot build HAR entry.");
                return;
              }
              try {
                const req = fromSummaryAndRaw(tx.summary, tx.request_raw);
                let resp: Parameters<typeof buildHarEntry>[2] = undefined;
                if (tx.response_raw) {
                  const text = tx.response_raw.replace(/\r\n/g, "\n");
                  const headerEnd = text.indexOf("\n\n");
                  const headerBlock =
                    headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                  const body =
                    headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                  const lines = headerBlock.split("\n");
                  const statusLine = (lines.shift() ?? "").trim();
                  const m = statusLine.match(
                    /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                  );
                  const httpVersion = m?.[1] ?? "HTTP/1.1";
                  const status = m ? parseInt(m[2], 10) : 0;
                  const statusText = m?.[3] ?? "";
                  const headers: Array<[string, string]> = [];
                  let mimeType = "";
                  for (const l of lines) {
                    const colon = l.indexOf(":");
                    if (colon <= 0) continue;
                    const n = l.slice(0, colon).trim();
                    const v = l.slice(colon + 1).trim();
                    if (!n) continue;
                    headers.push([n, v]);
                    if (n.toLowerCase() === "content-type") mimeType = v;
                  }
                  resp = { status, statusText, httpVersion, headers, mimeType, body };
                }
                const startedDateTime = new Date(
                  tx.summary.ts_ms,
                ).toISOString();
                const entry = buildHarEntry(req, startedDateTime, resp);
                const har = buildHarLog([entry]);
                void copyBlob(JSON.stringify(har, null, 2));
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title="Copy single-entry HAR 1.2 log (request + response) to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 HAR
          </button>
          {/* 🎯 R583: Sticky-header "+ scope" button — mirror of
              R582 ProxyPanel. Scope-add from the detail pane
              header without a row-right-click pivot. Backend's
              unique-rule guard idempotently no-ops on duplicate
              adds (TransactionViewer is a child component that
              doesn't own HistoryPanel's scope state). 140-round
              chunk mark passed. */}
          <button
            className="ghost"
            onClick={async () => {
              if (!tx.summary?.host) {
                alert("Transaction has no host — cannot add to scope.");
                return;
              }
              try {
                await api.scopeAddRule(buildHostIncludeRule(tx.summary.host));
                alert(`Added host "${tx.summary.host}" to scope.`);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Add host ${tx.summary?.host ?? ""} to scope include rules. Backend dedupes if already in scope.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            + scope
          </button>
          {/* R587: Sticky-header "+ path" button — path-exact
              mirror of R586 Scanner on HistoryPanel. Operators
              previewing a tx often want narrower scope rules
              ("just this specific endpoint, not the whole host").
              Uses `buildPathIncludeRule` which strips the query
              string. Backend idempotency keeps double-adds safe. */}
          <button
            className="ghost"
            onClick={async () => {
              const host = tx.summary?.host;
              const path = tx.summary?.path;
              if (!host || !path) {
                alert("Transaction missing host or path — cannot add path-exact rule.");
                return;
              }
              try {
                await api.scopeAddRule(buildPathIncludeRule(host, path));
                alert(`Added "${host}${path.split("?")[0] || "/"}" to scope.`);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Add ${tx.summary?.host ?? ""}${(tx.summary?.path ?? "").split("?")[0] || "/"} to scope include rules — path-exact, narrower than + scope.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            + path
          </button>
        </div>
      )}
      <div>
        {/* R408: Detail-pane Request/Response headings grow         */}
        {/* "📋 Copy" + "⬇ Save" affordances. The context-menu       */}
        {/* row-right-click Copy/Save entries (R166 / R403 / R404)   */}
        {/* require clicking back on the row — operators previewing  */}
        {/* in the detail pane want direct access without the row    */}
        {/* round-trip. Filename pattern `request-tx<id>.txt` /      */}
        {/* `response-tx<id>.txt` ties the file to the transaction   */}
        {/* id so operators correlating a saved artefact back to the */}
        {/* history row can grep by id.                               */}
        <div
          className="label"
          style={{ display: "flex", alignItems: "baseline", gap: 8 }}
        >
          <span>Request</span>
          <button
            className="ghost"
            onClick={() => void copyBlob(tx.request_raw ?? "")}
            title="Copy the raw request (headers + body) to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 Copy
          </button>
          <button
            className="ghost"
            onClick={() => saveBlob(`request-tx${tx.summary?.id ?? "unknown"}.txt`, tx.request_raw ?? "")}
            title={`Save the raw request to "request-tx${tx.summary?.id ?? "unknown"}.txt"`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            ⬇ Save
          </button>
        </div>
        <pre className="mono">{tx.request_raw}</pre>
      </div>
      <div>
        <div
          className="label"
          style={{ display: "flex", alignItems: "baseline", gap: 8 }}
        >
          <span>Response</span>
          {tx.response_raw && (
            <>
              <button
                className="ghost"
                onClick={() => void copyBlob(tx.response_raw ?? "")}
                title="Copy the raw response (status line + headers + body) to clipboard"
                style={{ fontSize: 10.5, padding: "1px 6px" }}
              >
                📋 Copy
              </button>
              <button
                className="ghost"
                onClick={() => saveBlob(`response-tx${tx.summary?.id ?? "unknown"}.txt`, tx.response_raw ?? "")}
                title={`Save the raw response to "response-tx${tx.summary?.id ?? "unknown"}.txt"`}
                style={{ fontSize: 10.5, padding: "1px 6px" }}
              >
                ⬇ Save
              </button>
            </>
          )}
        </div>
        <pre className="mono">{tx.response_raw || "(no response)"}</pre>
      </div>
    </div>
  );
}

/** Time-range filter chunk — datetime-local inputs for From / To
 *  plus three quick-pick preset buttons. Writes through to the parent
 *  `HistoryFilter` so the main refresh pipeline re-fetches on change. */
function TimeRangeControls({
  filter,
  setFilter,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
}) {
  // datetime-local inputs want `YYYY-MM-DDTHH:mm` strings. Convert
  // ms-epoch → local-time ISO slice; empty when the field is unset.
  const toInputValue = (ms?: number) => {
    if (ms == null) return "";
    const d = new Date(ms);
    const pad = (n: number) => n.toString().padStart(2, "0");
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      `T${pad(d.getHours())}:${pad(d.getMinutes())}`
    );
  };

  // Parse the input back to ms; blank or NaN clears the bound.
  const fromInput = (v: string): number | undefined => {
    if (!v) return undefined;
    const t = new Date(v).getTime();
    return Number.isFinite(t) ? t : undefined;
  };

  // Preset `Last Nm` — set ts_min to now - windowMs, clear ts_max so
  // "live tail" semantics survive subsequent auto-refreshes.
  function applyPreset(windowMs: number) {
    setFilter({
      ...filter,
      ts_min_ms: Date.now() - windowMs,
      ts_max_ms: undefined,
    });
  }

  // Preset active when ts_min_ms is set + ts_max unset + the delta is
  // close enough to the preset. Compare with 2s slack so refresh churn
  // doesn't un-highlight the active button.
  function presetActive(windowMs: number) {
    if (filter.ts_min_ms == null || filter.ts_max_ms != null) return false;
    const delta = Date.now() - filter.ts_min_ms;
    return Math.abs(delta - windowMs) < 2000;
  }

  const presetStyle = (active: boolean) => ({
    background: active ? "rgba(100,150,255,0.14)" : undefined,
    border: active ? "1px solid rgba(100,150,255,0.5)" : undefined,
  });

  return (
    <>
      <label title="Only include transactions on or after this time.">
        From
        <input
          type="datetime-local"
          value={toInputValue(filter.ts_min_ms)}
          onChange={(e) =>
            setFilter({ ...filter, ts_min_ms: fromInput(e.target.value) })
          }
          style={{ marginLeft: 4, width: 150 }}
        />
      </label>
      <label title="Only include transactions on or before this time.">
        To
        <input
          type="datetime-local"
          value={toInputValue(filter.ts_max_ms)}
          onChange={(e) =>
            setFilter({ ...filter, ts_max_ms: fromInput(e.target.value) })
          }
          style={{ marginLeft: 4, width: 150 }}
        />
      </label>
      <button
        onClick={() => applyPreset(5 * 60 * 1000)}
        style={presetStyle(presetActive(5 * 60 * 1000))}
        title="Transactions in the last 5 minutes"
      >
        5m
      </button>
      <button
        onClick={() => applyPreset(60 * 60 * 1000)}
        style={presetStyle(presetActive(60 * 60 * 1000))}
        title="Transactions in the last hour"
      >
        1h
      </button>
      <button
        onClick={() => applyPreset(24 * 60 * 60 * 1000)}
        style={presetStyle(presetActive(24 * 60 * 60 * 1000))}
        title="Transactions in the last 24 hours"
      >
        24h
      </button>
      {(filter.ts_min_ms != null || filter.ts_max_ms != null) && (
        <button
          className="ghost"
          onClick={() =>
            setFilter({ ...filter, ts_min_ms: undefined, ts_max_ms: undefined })
          }
          title="Clear the time range"
        >
          ×
        </button>
      )}
    </>
  );
}

/** Response-size filter chunk — two numeric byte-count inputs plus
 *  four preset chips (<1 KB, 1-10 KB, 10-100 KB, >100 KB) that stamp
 *  the common ranges in one click. Mirrors Burp's "Response size"
 *  filter under Proxy → HTTP history. Writes through to the parent
 *  `HistoryFilter`; the backend SQL path narrows via
 *  `response_size >= ?` / `<= ?` on the transactions table. */
function SizeRangeControls({
  filter,
  setFilter,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
}) {
  // Blank or NaN clears the bound; otherwise accept the raw byte
  // count the operator typed. Negative values are clamped to 0 so a
  // stray `-` can't flip the SQL predicate semantics.
  const parse = (v: string): number | undefined => {
    if (!v) return undefined;
    const n = parseInt(v, 10);
    if (!Number.isFinite(n)) return undefined;
    return Math.max(0, n);
  };

  // Preset writes both min and max in one setFilter call so the two
  // auto-refreshes don't race.
  function applyPreset(min: number | undefined, max: number | undefined) {
    setFilter({ ...filter, resp_size_min: min, resp_size_max: max });
  }

  // Highlight the active preset when the current (min, max) tuple
  // exactly matches. Undefined === undefined is true in JS so this
  // handles the open-ended cases naturally.
  function presetActive(min: number | undefined, max: number | undefined) {
    return filter.resp_size_min === min && filter.resp_size_max === max;
  }

  const presetStyle = (active: boolean) => ({
    background: active ? "rgba(100,150,255,0.14)" : undefined,
    border: active ? "1px solid rgba(100,150,255,0.5)" : undefined,
  });

  return (
    <>
      <label title="Only include transactions whose response body is at least this many bytes.">
        Size ≥
        <input
          type="number"
          min={0}
          step={100}
          placeholder="min"
          value={filter.resp_size_min ?? ""}
          onChange={(e) =>
            setFilter({ ...filter, resp_size_min: parse(e.target.value) })
          }
          style={{ marginLeft: 4, width: 90 }}
        />
      </label>
      <label title="Only include transactions whose response body is at most this many bytes.">
        ≤
        <input
          type="number"
          min={0}
          step={100}
          placeholder="max"
          value={filter.resp_size_max ?? ""}
          onChange={(e) =>
            setFilter({ ...filter, resp_size_max: parse(e.target.value) })
          }
          style={{ marginLeft: 4, width: 90 }}
        />
      </label>
      <button
        onClick={() => applyPreset(undefined, 1023)}
        style={presetStyle(presetActive(undefined, 1023))}
        title="Responses smaller than 1 KB (error pages, 304s, empty bodies)"
      >
        &lt;1KB
      </button>
      <button
        onClick={() => applyPreset(1024, 10_239)}
        style={presetStyle(presetActive(1024, 10_239))}
        title="Responses between 1 KB and 10 KB (typical JSON API payloads)"
      >
        1-10KB
      </button>
      <button
        onClick={() => applyPreset(10_240, 102_399)}
        style={presetStyle(presetActive(10_240, 102_399))}
        title="Responses between 10 KB and 100 KB (small HTML pages)"
      >
        10-100KB
      </button>
      <button
        onClick={() => applyPreset(102_400, undefined)}
        style={presetStyle(presetActive(102_400, undefined))}
        title="Responses larger than 100 KB (file downloads, data dumps, verbose JSON)"
      >
        &gt;100KB
      </button>
      {(filter.resp_size_min != null || filter.resp_size_max != null) && (
        <button
          className="ghost"
          onClick={() =>
            setFilter({
              ...filter,
              resp_size_min: undefined,
              resp_size_max: undefined,
            })
          }
          title="Clear the response-size range"
        >
          ×
        </button>
      )}
    </>
  );
}

/** Response MIME filter chunk — six toggleable chips (HTML / JSON /
 *  XML / JS / CSS / Image) each mapped to a canonical substring that
 *  the SQL side matches via `content_type LIKE %?%`. Multiple chips
 *  OR together. Mirrors Burp's MIME chip row under Proxy → HTTP
 *  history. Writes through to the parent `HistoryFilter`. */
function MimeChipsControls({
  filter,
  setFilter,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
}) {
  // Each entry maps a human label → the substring the backend
  // probes against `content_type`. Covers the ~95% of responses an
  // operator wants to isolate at a glance; everything else still
  // routes through `content_type_contains` (which keeps working
  // alongside — the two fields AND together server-side).
  const chips: Array<{ label: string; token: string; title: string }> = [
    { label: "HTML",   token: "text/html",         title: "Matches text/html (and HTML variants)" },
    { label: "JSON",   token: "application/json",  title: "Matches application/json" },
    { label: "XML",    token: "/xml",              title: "Matches application/xml, text/xml, application/soap+xml …" },
    { label: "JS",     token: "javascript",        title: "Matches application/javascript, text/javascript, application/x-javascript" },
    { label: "CSS",    token: "text/css",          title: "Matches text/css" },
    { label: "Image",  token: "image/",            title: "Matches image/png, image/jpeg, image/webp, image/gif …" },
  ];

  const active = filter.content_type_classes ?? [];
  const isOn = (token: string) => active.includes(token);

  function toggle(token: string) {
    const next = isOn(token)
      ? active.filter((t) => t !== token)
      : [...active, token];
    // Empty vec is treated as "no filter" server-side, but the parent
    // auto-refreshes on every setFilter change — avoid the extra
    // query by stripping the key entirely when the operator clears
    // the last chip.
    setFilter({
      ...filter,
      content_type_classes: next.length > 0 ? next : undefined,
    });
  }

  const chipStyle = (on: boolean) => ({
    padding: "2px 8px",
    borderRadius: 10,
    fontSize: 11,
    cursor: "pointer",
    background: on ? "rgba(100,150,255,0.14)" : undefined,
    border: on ? "1px solid rgba(100,150,255,0.5)" : "1px solid var(--border)",
    whiteSpace: "nowrap" as const,
  });

  return (
    <>
      <span style={{ color: "var(--text-dim)", fontSize: 11 }}>MIME</span>
      {chips.map((c) => (
        <button
          key={c.token}
          onClick={() => toggle(c.token)}
          style={chipStyle(isOn(c.token))}
          title={c.title}
        >
          {c.label}
        </button>
      ))}
      {active.length > 0 && (
        <button
          className="ghost"
          onClick={() => setFilter({ ...filter, content_type_classes: undefined })}
          title="Clear every MIME chip"
        >
          ×
        </button>
      )}
    </>
  );
}

/** Single-chip toggle that narrows the view to transactions with a
 *  non-NULL `error` column (connect refused / TLS failure / parse
 *  error / upstream reset). Mirrors Burp's "Only show responses with
 *  errors" checkbox. Styled to match `MimeChipsControls` so the
 *  toolbar reads as one coherent chip row. */
function ErrorOnlyControl({
  filter,
  setFilter,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
}) {
  const on = !!filter.error_only;
  const chipStyle = {
    padding: "2px 8px",
    borderRadius: 10,
    fontSize: 11,
    cursor: "pointer",
    // Error chip picks a red accent (vs the MIME chips' blue) so the
    // operator sees at a glance that this one is "filter out the
    // happy path", not "filter in by category".
    background: on ? "rgba(224,68,68,0.14)" : undefined,
    border: on
      ? "1px solid rgba(224,68,68,0.55)"
      : "1px solid var(--border)",
    whiteSpace: "nowrap" as const,
    color: on ? "var(--red, #e04444)" : undefined,
    fontWeight: on ? 600 : 400,
  };
  return (
    <>
      <span style={{ color: "var(--text-dim)", fontSize: 11 }}>Status</span>
      <button
        onClick={() =>
          // Strip the key when turning off so a stale undefined-value
          // doesn't persist in the serialised filter object the
          // parent auto-refreshes against.
          setFilter(
            on
              ? { ...filter, error_only: undefined }
              : { ...filter, error_only: true },
          )
        }
        style={chipStyle}
        title={
          on
            ? "Showing only errored transactions. Click to show everything."
            : "Keep only transactions whose `error` column is non-NULL — connect refused, TLS alert, parse error, upstream reset. Burp's `Only show responses with errors` checkbox."
        }
      >
        Errors only
      </button>
    </>
  );
}

/** Multi-select status-class chip row. 5 chips (1xx/2xx/3xx/4xx/5xx)
 *  with per-chip live counts drawn from the current `rows` so an
 *  operator can see "oh there are 12 5xx hiding in the noise" without
 *  flipping the filter. Reuses the `.issue-status-chip` + `intr-b-*`
 *  tint CSS from the Intruder panel so the colour semantics stay
 *  consistent across BurpFree. Clicking a chip toggles its class in
 *  `filter.status_classes`; empty array auto-clears the field so the
 *  backend treats it as "no filter". The legacy `status_min` /
 *  `status_max` fields keep working alongside — bambda scripts +
 *  saved filters that write them continue to narrow via the AND
 *  pathway, this chip row just drives the common multi-select case. */
function StatusClassChips({
  filter,
  setFilter,
  rows,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
  rows: StoredSummary[];
}) {
  const active = new Set(filter.status_classes ?? []);
  // Count rows per status class from the currently-loaded page so
  // the chip badges read "live" against what the operator can see.
  const counts = useMemo(() => {
    const c: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    for (const r of rows) {
      if (r.status == null) continue;
      const k = Math.floor(r.status / 100);
      if (k >= 1 && k <= 5) c[k] = (c[k] ?? 0) + 1;
    }
    return c;
  }, [rows]);
  const toggle = (k: number) => {
    const next = new Set(active);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    // Empty set → strip the field so an empty-array doesn't persist
    // in the serialised filter (matches MimeChips behaviour).
    const arr = [...next].sort();
    setFilter({ ...filter, status_classes: arr.length ? arr : undefined });
  };
  return (
    <>
      <span style={{ color: "var(--text-dim)", fontSize: 11 }}>Status</span>
      {[1, 2, 3, 4, 5].map((k) => {
        const on = active.has(k);
        return (
          <button
            key={k}
            onClick={() => toggle(k)}
            className={`issue-status-chip ${on ? `on intr-b-${k}xx` : "off"}`}
            title={
              on
                ? `Hide ${k}xx responses`
                : `Keep ${k}xx responses (currently ${counts[k] ?? 0} visible). Click to add this class to the filter.`
            }
          >
            <span className="chip-label">{k}xx</span>
            <span className="chip-count">{counts[k] ?? 0}</span>
          </button>
        );
      })}
      {active.size > 0 && (
        <button
          onClick={() => setFilter({ ...filter, status_classes: undefined })}
          className="issue-filter-clear"
          title="Clear status-class filter — show every response class"
        >
          clear
        </button>
      )}
    </>
  );
}

/** Burp-style annotation filters: "💬 Commented" + "🎨 Highlighted".
 *  Each toggle narrows the result set to rows whose comment or
 *  highlight columns are set — operators tag interesting rows during
 *  triage and later flip these on to see just the shortlist. Counts
 *  are drawn from the current `rows` so the chip badges match the
 *  visible table under the active filter stack. Shares the chip
 *  styling with StatusClassChips for cross-panel consistency. */
function AnnotationChips({
  filter,
  setFilter,
  rows,
}: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
  rows: StoredSummary[];
}) {
  const highlighted = useMemo(() => rows.filter((r) => !!r.highlight).length, [rows]);
  const commented = useMemo(
    () => rows.filter((r) => (r.comment ?? "").trim().length > 0).length,
    [rows],
  );
  const commentOn = !!filter.commented_only;
  const highlightOn = !!filter.highlighted_only;
  return (
    <>
      <button
        onClick={() =>
          setFilter(
            commentOn
              ? { ...filter, commented_only: undefined }
              : { ...filter, commented_only: true },
          )
        }
        className={`issue-status-chip ${commentOn ? "on" : "off"}`}
        title={
          commentOn
            ? "Showing only commented rows — click to show everything."
            : "Keep only rows with a non-empty comment. Burp's `Show only commented items` annotation filter."
        }
      >
        <span className="chip-label">💬 Commented</span>
        <span className="chip-count">{commented}</span>
      </button>
      <button
        onClick={() =>
          setFilter(
            highlightOn
              ? { ...filter, highlighted_only: undefined }
              : { ...filter, highlighted_only: true },
          )
        }
        className={`issue-status-chip ${highlightOn ? "on" : "off"}`}
        title={
          highlightOn
            ? "Showing only highlighted rows — click to show everything."
            : "Keep only rows with a highlight colour set. Burp's `Show only highlighted items` annotation filter."
        }
      >
        <span className="chip-label">🎨 Highlighted</span>
        <span className="chip-count">{highlighted}</span>
      </button>
    </>
  );
}
