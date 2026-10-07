import { MouseEvent, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import {
  buildCurl,
  buildHarEntry,
  buildHarLog,
  buildPowerShell,
  buildPython,
  copyToClipboard,
  fromSummaryAndRaw,
  urlFromSummary,
} from "../copyAs";
import { BambdaSavedPicker } from "../BambdaSavedPicker";

type Logged = { seq: number; event: { ts_ms: number; kind: any } };
type KindFilter = "all" | "transaction" | "log" | "intercept" | "finding" | "ws";

/** Shape passed to the Bambda-style predicate. Flattens the event
 *  payload so expressions like `kind == "finding"` just work. */
type EventRow = {
  seq: number;
  ts_ms: number;
  kind: string;
  level?: string;
  source?: string;
  message?: string;
  id?: number | string;
  session_id?: number | string;
  message_id?: number | string;
  direction?: string;
  severity?: string;
  action?: string;
  raw: any;
};

const BAMBDA_EXAMPLES = [
  'kind == "finding"',
  'kind == "transaction"',
  'kind == "log" && level == "warn"',
  'kind == "ws_message" && direction == "out"',
  'kind == "finding" && severity == "high"',
];

export function LoggerPanel() {
  const [events, setEvents] = useState<Logged[]>([]);
  const [follow, setFollow] = useState(true);
  const [filter, setFilter] = useState<KindFilter>("all");
  const [search, setSearch] = useState("");
  // R235: Alt+1..6 switches kind filter — mirrors R230 / R231 /
  // R232 / R233's Alt-digit pattern. Mapping matches the chip
  // strip order rendered below (Transaction=2, Intercept=3,
  // Finding=4, WS=5, Log=6; All=1 is the reset-to-everything).
  useEffect(() => {
    const KIND_BY_DIGIT: Record<string, KindFilter> = {
      "1": "all",
      "2": "transaction",
      "3": "intercept",
      "4": "finding",
      "5": "ws",
      "6": "log",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const k = KIND_BY_DIGIT[e.key];
      if (!k) return;
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
      setFilter(k);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  // R228: Case-sensitive search toggle. Off by default (matches the
  // pre-R228 behaviour where both sides were lower-cased). Operators
  // grepping for exact-case identifiers (`BurpFree` vs `burpfree`,
  // `Bearer` vs `bearer`) can flip this on without changing their
  // query. Persisted per-session only (no localStorage) — a scan
  // session doesn't carry across restarts.
  const [searchCase, setSearchCase] = useState(false);
  const [paused, setPaused] = useState(false);
  const [bambdaDraft, setBambdaDraft] = useState("");
  const [bambda, setBambda] = useState("");

  // R410: Alt+C clears every active filter (kind / search / bambda)
  // in one keystroke — keyboard version of the "Clear filters"
  // ghost button lower in the toolbar. Mirror of R349 History /
  // R409 Collaborator Alt+C pattern. Operators pivoting across
  // Logger sessions (narrow to findings, widen to everything,
  // narrow to high-sev transactions, etc.) want a one-key reset
  // without hunting for the clear button or walking three
  // selectors. **Scope** `filter !== "all" || search.length > 0 ||
  // bambda.length > 0` — the handler short-circuits when all three
  // are at defaults. **Mechanism** fires setFilter("all") +
  // setSearch("") + setBambda("") + setBambdaDraft("") to match
  // the Clear-filters button exactly. **Guards** plain Alt only
  // (so Ctrl+Shift+C DevTools stays intact), text-input focus
  // skip. **No-op silent** when all filters at defaults so the
  // keystroke stays safe to spam. **Positioning** declared below
  // bambda to sidestep the TDZ error that would arise from a
  // top-of-file useEffect closing over bambda.
  useEffect(() => {
    function onClearKey(e: KeyboardEvent) {
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
      const anyActive =
        filter !== "all" || search.length > 0 || bambda.length > 0;
      if (!anyActive) return;
      e.preventDefault();
      setFilter("all");
      setSearch("");
      setBambda("");
      setBambdaDraft("");
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, search, bambda]);

  // R446: Alt+Shift+C clears the stored logger events — mirrors the
  // existing visible "Clear" toolbar button exactly (fires
  // `api.loggerClear()` on the backend, resets the drain cursor,
  // empties the local events array). Extends the Alt+Shift+C
  // clear-results family — R418 Intruder (clear results) and R435
  // Sequencer (clear tokens + report). Keeps the filter triplet
  // (filter/search/bambda) on Alt+C exactly as before; the only
  // difference is Shift to distinguish "wipe events" from "wipe
  // filters". **Guards** plain Alt+Shift only (no Ctrl/Meta) +
  // text-input / textarea / contenteditable focus skip. **Scope**
  // only fires if there are events to clear (so a stray keystroke
  // on an empty logger is a no-op).
  useEffect(() => {
    function onClearEventsKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "C" && e.key !== "c") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (events.length === 0) return;
      e.preventDefault();
      void clear();
    }
    document.addEventListener("keydown", onClearEventsKey);
    return () => document.removeEventListener("keydown", onClearEventsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events.length]);

  // Right-click menu for an event row. `data` is the full Logged
  // row so the menu actions can read kind / level / source without
  // re-walking the events array.
  const [logMenu, setLogMenu] = useState<MenuState<Logged> | null>(null);
  // Multi-select for bulk copy / export. Keyed on `seq` so the set
  // survives arrival of fresh events (seqs are monotonic).
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [lastClickedSeq, setLastClickedSeq] = useState<number | null>(null);
  const cursor = useRef<number>(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const seed = await api.loggerRecent(500);
        setEvents(seed);
        if (seed.length) cursor.current = seed[seed.length - 1].seq;
      } catch (e) {
        console.error(e);
      }
    })();
  }, []);

  useEffect(() => {
    if (paused) return;
    const t = setInterval(async () => {
      try {
        const batch = await api.loggerDrainSince(cursor.current);
        if (batch.length) {
          cursor.current = batch[batch.length - 1].seq;
          setEvents((prev) => {
            const merged = [...prev, ...batch];
            // Keep client-side buffer bounded.
            return merged.slice(-5000);
          });
        }
      } catch {}
    }, 500);
    return () => clearInterval(t);
  }, [paused]);

  useEffect(() => {
    if (follow && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, follow]);

  async function clear() {
    await api.loggerClear();
    cursor.current = 0;
    setEvents([]);
  }

  // Compile the user's Bambda-style expression into a predicate.
  // On error, mark the state so the toolbar can surface it; the
  // predicate becomes a pass-through so the row list stays visible.
  const { predicate, bambdaError } = useMemo(() => compileBambda(bambda), [bambda]);

  // Row click handler: single-click resets selection to just the row,
  // Ctrl/⌘ toggles the row, Shift extends the range over the currently
  // visible list (so filtered-out rows don't sneak into the selection).
  function onRowClick(e: MouseEvent, row: Logged) {
    if (e.ctrlKey || e.metaKey) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        if (next.has(row.seq)) next.delete(row.seq);
        else next.add(row.seq);
        return next;
      });
      setLastClickedSeq(row.seq);
    } else if (e.shiftKey && lastClickedSeq != null) {
      const seqs = visible.map((v) => v.seq);
      const a = seqs.indexOf(lastClickedSeq);
      const b = seqs.indexOf(row.seq);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        setSelectedIds((prev) => {
          const next = new Set(prev);
          for (let i = lo; i <= hi; i++) next.add(seqs[i]);
          return next;
        });
      }
    } else {
      setSelectedIds(new Set([row.seq]));
      setLastClickedSeq(row.seq);
    }
  }

  // Per-kind event counter — feeds the chip strip badges so the
  // operator sees the current ring buffer's distribution at a glance.
  // Mirrors the matchesKind bucket logic exactly so "ws" catches
  // every ws_* flavour.
  const kindCounts = useMemo(() => {
    const c: Record<KindFilter, number> = {
      all: events.length,
      transaction: 0,
      intercept: 0,
      finding: 0,
      ws: 0,
      log: 0,
    };
    for (const e of events) {
      const k = (e.event as any).kind?.kind;
      if (!k) continue;
      if (k === "transaction") c.transaction++;
      else if (k === "intercept") c.intercept++;
      else if (k === "finding") c.finding++;
      else if (k === "log") c.log++;
      else if (
        k === "ws_message" ||
        k === "ws_opened" ||
        k === "ws_closed" ||
        (typeof k === "string" && k.startsWith("ws_"))
      )
        c.ws++;
    }
    return c;
  }, [events]);

  const visible = events.filter((e) => {
    if (!matchesKind(e, filter)) return false;
    if (!matchesSearch(e, search, searchCase)) return false;
    if (predicate) {
      const row = flattenEvent(e);
      try {
        if (!predicate(row)) return false;
      } catch {
        return false;
      }
    }
    return true;
  });

  const bambdaActive = bambda.trim().length > 0;

  // Resolve the current multi-selection to concrete rows against the
  // visible list — Logger events aren't persisted, so if the operator
  // scrolls past the 5000-row buffer the selection self-trims.
  const bulkRows = useMemo(
    () => visible.filter((e) => selectedIds.has(e.seq)),
    [visible, selectedIds],
  );

  // R258: J / K vim-style aliases for ↓ / ↑ row nav plus
  // ArrowUp/Down/Home/End — fifth J/K panel after Scanner (R197),
  // History (R208), Organizer (R212), and Target Issues (R222).
  // Logger is multi-select (Ctrl / Shift click), so the cursor is
  // the single selected row when exactly one is picked; a cold
  // J / ↓ press from the "nothing selected" state lands on the
  // first visible row, K / ↑ lands on the last — predictable
  // either way. The move replaces the multi-selection with a
  // single pick so the bulk toolbar reflects the row the operator
  // just navigated to. Guards against modifier keys + typing in
  // inputs so the existing Alt+1..6 (R235) + Esc-clears-search
  // (R224) handlers keep their lane.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
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
      if (visible.length === 0) return;
      const only = selectedIds.size === 1 ? Array.from(selectedIds)[0] : null;
      const curIdx =
        only !== null ? visible.findIndex((r) => r.seq === only) : -1;
      let nextIdx = curIdx;
      if (key === "ArrowUp" || isK) {
        // From "nothing selected" K lands on the last row (natural
        // when the operator is scrolled to the bottom of the live
        // feed); from a selected row, step up one.
        nextIdx =
          curIdx < 0 ? visible.length - 1 : Math.max(0, curIdx - 1);
      } else if (key === "ArrowDown" || isJ) {
        nextIdx =
          curIdx < 0 ? 0 : Math.min(visible.length - 1, curIdx + 1);
      } else if (key === "Home") {
        nextIdx = 0;
      } else if (key === "End") {
        nextIdx = visible.length - 1;
      }
      if (nextIdx === curIdx || nextIdx < 0) return;
      e.preventDefault();
      const next = visible[nextIdx];
      setSelectedIds(new Set([next.seq]));
      setLastClickedSeq(next.seq);
      // Scroll on next frame so the DOM has the new selected
      // background applied; block:nearest avoids jumping to the
      // top on every arrow press — only moves when the row is
      // actually off-screen.
      requestAnimationFrame(() => {
        const tr = document.querySelector(
          `tr[data-row-seq="${next.seq}"]`,
        ) as HTMLElement | null;
        tr?.scrollIntoView({ block: "nearest" });
      });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [visible, selectedIds]);

  function copyBulkJson() {
    if (bulkRows.length === 0) return;
    const payload = bulkRows.map((r) => r.event);
    void copyToClipboard(JSON.stringify(payload, null, 2));
  }

  function copyBulkSummaries() {
    if (bulkRows.length === 0) return;
    const text = bulkRows
      .map((r) => `#${r.seq} ${fmtTime(r.event.ts_ms)} ${kindLabel(r.event.kind)}  ${summary(r.event.kind)}`)
      .join("\n");
    void copyToClipboard(text);
  }

  // R141: Export selected events as JSON Lines (JSONL) — one JSON
  // object per line. Operators pipe this into `jq`, `grep`, or
  // Splunk / ELK ingest without needing to parse a top-level
  // array wrapper. Mirror of exportBulkCsv but with the event
  // object serialised whole rather than flattened to columns.
  function exportBulkJsonl() {
    if (bulkRows.length === 0) return;
    const body = bulkRows
      .map((r) =>
        JSON.stringify({
          seq: r.seq,
          ts_ms: r.event.ts_ms,
          event: r.event,
        }),
      )
      .join("\n");
    const blob = new Blob([body + "\n"], {
      type: "application/x-ndjson;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logger-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  /** CSV writer parameterised on which rows to dump. Shared by the
   *  R120 bulk-selection "Export CSV" button and the R214 toolbar-
   *  level "Export all CSV" button so one escaping / header
   *  definition serves both export paths. */
  function writeCsv(rows: Logged[], tag: string) {
    if (rows.length === 0) return;
    const headers = ["seq", "ts_ms", "kind", "level", "source", "summary"];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = rows
      .map((r) => {
        const k: any = r.event?.kind ?? {};
        return [
          r.seq,
          r.event.ts_ms,
          typeof k.kind === "string" ? k.kind : "",
          typeof k.level === "string" ? k.level : "",
          typeof k.source === "string" ? k.source : "",
          summary(k),
        ]
          .map(esc)
          .join(",");
      })
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logger-${tag}-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }
  function exportBulkCsv() {
    writeCsv(bulkRows, "selection");
  }
  // R214: Toolbar-level "Export all CSV" — exports the whole
  // post-filter visible list so operators can grab a dump without
  // first selecting every row (Logger has no "select-all" chip and
  // 5000 Ctrl+clicks aren't a path).
  function exportAllVisibleCsv() {
    writeCsv(visible, "visible");
  }

  // R602: Clipboard-only CSV counterpart to writeCsv — third entry
  // in the cross-panel "📋 Copy as CSV" family after HistoryPanel
  // R600 and Scanner R601. Operators pasting into Excel / Sheets
  // want the Logger event table on the clipboard directly without
  // the file-save + open roundtrip. Byte-identical column shape to
  // writeCsv (same 6 columns: seq, ts_ms, kind, level, source,
  // summary) so clipboard + file outputs stay interchangeable.
  // Parameterised on `rows` so it can serve both bulk-selection
  // (bulkRows) and all-visible paths from a shared helper.
  function copyCsv(rows: Logged[]) {
    if (rows.length === 0) return;
    const headers = ["seq", "ts_ms", "kind", "level", "source", "summary"];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = rows
      .map((r) => {
        const k: any = r.event?.kind ?? {};
        return [
          r.seq,
          r.event.ts_ms,
          typeof k.kind === "string" ? k.kind : "",
          typeof k.level === "string" ? k.level : "",
          typeof k.source === "string" ? k.source : "",
          summary(k),
        ]
          .map(esc)
          .join(",");
      })
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    void navigator.clipboard.writeText(csv);
  }
  function copyBulkCsv() {
    copyCsv(bulkRows);
  }

  // R284: Toolbar-level "Export all JSONL" — companion to R214
  // CSV. CSV flattens events to columns; JSONL preserves the
  // whole event payload shape so operators piping into jq / grep /
  // ELK ingest can keep the nested structure (kind.kind,
  // event.severity, event.direction, …) accessible by key rather
  // than hunting across comma-separated columns. One JSON object
  // per line — no top-level array wrapper, so a streaming
  // consumer can start processing before download finishes.
  function exportAllVisibleJsonl() {
    if (visible.length === 0) return;
    const body = visible
      .map((r) =>
        JSON.stringify({
          seq: r.seq,
          ts_ms: r.event.ts_ms,
          event: r.event,
        }),
      )
      .join("\n");
    const blob = new Blob([body + "\n"], {
      type: "application/x-ndjson;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logger-visible-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  return (
    <div className="panel">
      <div
        className={`bambda-bar ${bambdaError ? "error" : ""} ${bambdaActive ? "on" : ""}`}
      >
        <span className="bambda-label">λ Bambda</span>
        <input
          className="bambda-input mono"
          value={bambdaDraft}
          onChange={(e) => setBambdaDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") setBambda(bambdaDraft);
          }}
          placeholder='e.g. kind == "finding" && severity == "high"'
          title='Client-side predicate over the event. Fields: kind, level, source, message, id, session_id, direction, severity, action, ts_ms. Any JS expression returning truthy keeps the row.'
        />
        <button
          className="primary"
          onClick={() => setBambda(bambdaDraft)}
          disabled={!bambdaDraft.trim()}
        >
          Apply
        </button>
        <button
          className="ghost"
          onClick={() => {
            setBambda("");
            setBambdaDraft("");
          }}
          disabled={!bambdaActive && !bambdaDraft}
        >
          Clear
        </button>
        <span className="bambda-stats">
          {bambdaError ? (
            <span style={{ color: "var(--red)" }}>✗ {bambdaError}</span>
          ) : bambdaActive ? (
            <>
              kept <strong>{visible.length}</strong> of {events.length}
            </>
          ) : null}
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <select
          className="bambda-presets"
          value=""
          onChange={(e) => {
            if (e.target.value) {
              setBambdaDraft(e.target.value);
              setBambda(e.target.value);
            }
          }}
        >
          <option value="">Examples…</option>
          {BAMBDA_EXAMPLES.map((ex) => (
            <option key={ex} value={ex}>
              {ex}
            </option>
          ))}
        </select>
        <BambdaSavedPicker
          scope="logger"
          current={bambdaDraft}
          onLoad={(expr) => {
            setBambdaDraft(expr);
            setBambda(expr);
          }}
        />
      </div>
      <div className="toolbar">
        <span>Logger</span>
        {/* R171: Red "PAUSED" badge next to the title when the Pause  */}
        {/* checkbox is on. Operators flipping Pause then switching to */}
        {/* another tab and coming back can't tell at a glance whether */}
        {/* the stream is live or buffered — the checkbox is tiny and  */}
        {/* buried mid-toolbar. The red pill makes it unambiguous.      */}
        {paused && (
          <span
            style={{
              marginLeft: 6,
              padding: "1px 6px",
              borderRadius: 3,
              fontSize: 10,
              fontWeight: 700,
              color: "#fff",
              background: "var(--red)",
              letterSpacing: 0.5,
            }}
            title="Stream is paused — new events accumulate on the backend but aren't pulled into the view until Pause is cleared."
          >
            PAUSED
          </span>
        )}
        <div className="sep" />
        <label>Kind</label>
        {/* Kind chip strip — replaces the old <select>. Click a chip  */}
        {/* to narrow; click the active chip to go back to All. Each    */}
        {/* chip shows the live count from the current event ring       */}
        {/* buffer so operators see the distribution at a glance.       */}
        {(() => {
          const chips: Array<{ key: KindFilter; label: string }> = [
            { key: "transaction", label: "Traffic" },
            { key: "intercept", label: "Intercept" },
            { key: "finding", label: "Findings" },
            { key: "ws", label: "WebSocket" },
            { key: "log", label: "Logs" },
          ];
          return (
            <>
              <button
                className={`logger-kind-chip ${filter === "all" ? "on" : "off"}`}
                onClick={() => setFilter("all")}
                title="Show every event — click a kind to narrow"
              >
                <span className="chip-label">All</span>
                <span className="chip-count">{events.length}</span>
              </button>
              {chips.map(({ key, label }) => {
                const active = filter === key;
                const count = kindCounts[key] ?? 0;
                return (
                  <button
                    key={key}
                    className={`logger-kind-chip kind-${key} ${active ? "on" : "off"}`}
                    onClick={() => setFilter(active ? "all" : key)}
                    disabled={count === 0 && !active}
                    title={
                      active
                        ? `Showing ${label} — click to go back to All`
                        : count === 0
                          ? `No ${label} events`
                          : `Click to filter to ${label}`
                    }
                  >
                    <span className="chip-label">{label}</span>
                    <span className="chip-count">{count}</span>
                  </button>
                );
              })}
            </>
          );
        })()}
        <label>Search</label>
        {/* R878: Mirror of R877 — visible × clear button on the
            Logger search input. Mouse-first clear affordance
            alongside the existing R224 Esc-clear keystroke. */}
        <span style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && search) {
                e.preventDefault();
                setSearch("");
              }
            }}
            placeholder="substring (Esc clears)"
            style={{ width: 240, paddingRight: search ? 22 : 6 }}
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
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
        {/* R228: Case-sensitive toggle — mirror of MessageEditor's  */}
        {/* R72 Aa button so operators get the same muscle memory    */}
        {/* across Find bars. Compact 3-char button (`Aa`) with      */}
        {/* on/off styling via the existing `.ghost.on` CSS. Tooltip */}
        {/* explains which mode is active. */}
        <button
          className={`ghost ${searchCase ? "on" : ""}`}
          onClick={() => setSearchCase((v) => !v)}
          title={
            searchCase
              ? "Case-sensitive search is ON — click to switch back to case-insensitive"
              : "Match case — only identical capitalisation counts (click to toggle)"
          }
          style={{ padding: "2px 6px", fontSize: 11 }}
        >
          Aa
        </button>
        <div className="sep" />
        <label><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> Follow tail</label>
        <label><input type="checkbox" checked={paused} onChange={(e) => setPaused(e.target.checked)} /> Pause</label>
        <button onClick={clear} className="danger">Clear</button>
        <button
          onClick={exportAllVisibleCsv}
          disabled={visible.length === 0}
          title={
            visible.length === 0
              ? "No visible events to export"
              : `Export every post-filter visible event (${visible.length}) as a CSV. Honours the current Bambda / search / level filters.`
          }
        >
          ⬇ CSV
        </button>
        {/* R284: Toolbar-level JSONL export — companion to R214  */}
        {/* CSV. Preserves the nested event payload shape so       */}
        {/* operators piping into jq / grep / ELK ingest can keep  */}
        {/* the full event metadata accessible by key.             */}
        <button
          onClick={exportAllVisibleJsonl}
          disabled={visible.length === 0}
          title={
            visible.length === 0
              ? "No visible events to export"
              : `Export every post-filter visible event (${visible.length}) as JSONL (one JSON object per line; preserves nested event payload — pipe into jq / grep / ELK ingest without re-parsing a column-flattened CSV)`
          }
        >
          ⬇ JSONL
        </button>
        {/* R263: Clear-N-filters button — sixth entry in the family */}
        {/* after R238 Scanner, R240 History, R241 Collaborator,     */}
        {/* R242 Target Issues, and R249 Proxy main. Counts and       */}
        {/* clears exactly three real filter dimensions (kind,        */}
        {/* search, bambda); searchCase/follow/paused are view modes */}
        {/* not filters, so they stay untouched. The button only     */}
        {/* renders when at least one dimension is active, with a    */}
        {/* tooltip listing exactly what's cleared so operators know */}
        {/* the blast radius before clicking.                         */}
        {(() => {
          const activeFilters: string[] = [];
          if (filter !== "all") activeFilters.push(`kind=${filter}`);
          if (search.trim()) activeFilters.push("search");
          if (bambda.trim()) activeFilters.push("bambda");
          if (activeFilters.length === 0) return null;
          const n = activeFilters.length;
          return (
            <button
              className="ghost"
              onClick={() => {
                setFilter("all");
                setSearch("");
                setBambda("");
                setBambdaDraft("");
              }}
              title={`Clear all ${n} active filter${n === 1 ? "" : "s"}: ${activeFilters.join(", ")} — resets view to every event in the ring buffer`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              ⨯ clear {n} filter{n === 1 ? "" : "s"}
            </button>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        {/* R520: "📊" stats badge — 9th panel in the family alongside */}
        {/* R440 Repeater workspace / R442 History hosts / R451         */}
        {/* Collaborator kind-split / R452 Target Issues severity-split */}
        {/* / R466 Decoder chain / R469 Sequencer tokens / R471        */}
        {/* CookieJar jar stats / R476 Intruder results. Replaces the  */}
        {/* bare "visible/total" badge with a richer kind-split that    */}
        {/* mirrors the chip-strip above: tx / finding / ws / log /    */}
        {/* intercept counts across the entire stream (not the        */}
        {/* filtered view) so operators scanning the toolbar see the  */}
        {/* traffic shape at a glance. The leading                     */}
        {/* "visible / total" count stays — it tracks how aggressive  */}
        {/* the current filter is. **Zero backend** — pure reduce      */}
        {/* over the already-polled `events` array.                    */}
        <span
          className="badge"
          title={`${visible.length} visible of ${events.length} total · kind breakdown across the whole stream (not filtered)`}
        >
          {(() => {
            let tx = 0,
              finding = 0,
              ws = 0,
              log = 0,
              intercept = 0;
            for (const e of events) {
              const k = e.event.kind?.kind ?? "";
              if (k === "transaction") tx++;
              else if (k === "finding") finding++;
              else if (k === "intercept") intercept++;
              else if (k === "log") log++;
              else if (typeof k === "string" && k.startsWith("ws_")) ws++;
            }
            // Build a compact kind-split string. Omit zero-count
            // segments to keep the badge terse on sparse streams.
            const parts: string[] = [];
            if (tx > 0) parts.push(`${tx} tx`);
            if (finding > 0) parts.push(`${finding} find`);
            if (ws > 0) parts.push(`${ws} ws`);
            if (intercept > 0) parts.push(`${intercept} intercept`);
            if (log > 0) parts.push(`${log} log`);
            const kindsStr = parts.length > 0 ? ` · ${parts.join(" · ")}` : "";
            return `📊 ${visible.length} / ${events.length}${kindsStr}`;
          })()}
        </span>
      </div>
      {bulkRows.length > 0 && (
        <div
          style={{
            padding: "6px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            display: "flex",
            gap: 8,
            alignItems: "center",
            flexWrap: "wrap",
            fontSize: 12,
          }}
        >
          <strong>{bulkRows.length} event{bulkRows.length === 1 ? "" : "s"} selected</strong>
          <span className="sep" />
          <button onClick={copyBulkJson}>Copy as JSON array</button>
          <button onClick={copyBulkSummaries}>Copy summaries</button>
          {/* R563: Bulk "📋 Copy kinds" — Logger-only complement
              to R554-R561 HistoryPanel bulk-metadata-copy family.
              Operators auditing event-kind distribution across a
              selected cluster ("do these 50 events come from one
              detector or spread across many?") want a quick
              kind-distribution grab. Flattens each event's
              `event.kind.kind` field into a Set + alpha sort.
              Falls back to empty string "" filter. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    bulkRows
                      .map((r) => r.event.kind?.kind ?? "")
                      .filter((k) => k.length > 0),
                  ),
                ).sort();
                if (uniq.length === 0) {
                  alert("No event kinds across the selected rows.");
                  return;
                }
                await copyToClipboard(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected event${bulkRows.length === 1 ? "'s kind" : "s' unique kinds"} to clipboard as a newline-joined list (deduped + alpha-sorted). Great for auditing which detectors / sources are active in a cluster.`}
          >
            📋 Copy kinds
          </button>
          <button onClick={exportBulkCsv}>Export CSV</button>
          {/* R602: Clipboard-only CSV counterpart to Export CSV on
              Logger. Third entry in the cross-panel "Copy as CSV"
              family after HistoryPanel R600 + Scanner R601.
              Operators pasting into Excel / Sheets want the event
              table on the clipboard directly without the file-save
              + open roundtrip. Byte-identical column shape to
              Export CSV. */}
          <button
            onClick={copyBulkCsv}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} as a CSV table to clipboard (6 columns: seq, ts_ms, kind, level, source, summary). Paste into Excel / Sheets / Google Docs without the file-save roundtrip. Byte-identical column shape to Export CSV. Third entry in the cross-panel Copy-as-CSV family (HistoryPanel R600 + Scanner R601 + Logger R602).`
            }
          >
            📋 Copy as CSV
          </button>
          <button
            onClick={exportBulkJsonl}
            title="One JSON object per line — pipe into jq / grep / ELK ingest without parsing a top-level array"
          >
            Export JSONL
          </button>
          {/* R683: Logger "📋 Copy level counts" — tally for
              log-level distribution (debug/info/warn/error/
              fatal). Sorted by severity (fatal first). */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const order = ["fatal", "error", "warn", "info", "debug"];
              const counts: Record<string, number> = {};
              for (const r of bulkRows) {
                const k: any = r.event?.kind ?? {};
                const level = typeof k.level === "string" ? k.level : "";
                if (!level) continue;
                counts[level] = (counts[level] ?? 0) + 1;
              }
              if (Object.keys(counts).length === 0) {
                alert("No events in the selection have a level field.");
                return;
              }
              const sorted = Object.entries(counts).sort((a, b) => {
                const ai = order.indexOf(a[0]);
                const bi = order.indexOf(b[0]);
                return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
              });
              const text = sorted.map(([l, n]) => `${l}: ${n}`).join(", ");
              void navigator.clipboard.writeText(text);
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy log-level counts across ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} as a one-line tally (fatal/error/warn/info/debug ordered). Skips events without a level field.`
            }
          >
            📋 Copy level counts
          </button>
          {/* R682: Logger "📋 Copy kind counts" — tally variant.
              Logger kinds (transaction/intercept/finding/log/
              ws_*) with counts. Great for a one-line incident
              timeline summary. */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const counts: Record<string, number> = {};
              for (const r of bulkRows) {
                const k: any = r.event?.kind ?? {};
                const kindStr = typeof k.kind === "string" ? k.kind : "(unknown)";
                counts[kindStr] = (counts[kindStr] ?? 0) + 1;
              }
              const sorted = Object.entries(counts).sort(
                (a, b) => b[1] - a[1],
              );
              const text = sorted.map(([k, n]) => `${k}: ${n}`).join(", ");
              void navigator.clipboard.writeText(text);
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy Logger-kind counts across ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "transaction: 100, log: 20, finding: 5"). Sorted desc by count.`
            }
          >
            📋 Copy kind counts
          </button>
          {/* R693: Logger "📋 Copy stats" — 5th panel in
              the metadata summary family (History R688 time
              range + R689 stats, Scanner R690, Target R691,
              Collaborator R692, Logger R693). Shape adapted
              for log-stream metrics: Events / Unique kinds /
              Unique levels / Unique sources / Time range
              (earliest → latest with adaptive duration). */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const kinds = new Set<string>();
              const levels = new Set<string>();
              const sources = new Set<string>();
              let minTs = Number.POSITIVE_INFINITY;
              let maxTs = Number.NEGATIVE_INFINITY;
              for (const r of bulkRows) {
                const k: any = r.event?.kind ?? {};
                const kindStr = typeof k.kind === "string" ? k.kind : "";
                if (kindStr) kinds.add(kindStr);
                const level = typeof k.level === "string" ? k.level : "";
                if (level) levels.add(level);
                const source = typeof k.source === "string" ? k.source : "";
                if (source) sources.add(source);
                const ts = r.event?.ts_ms ?? 0;
                if (ts > 0) {
                  if (ts < minTs) minTs = ts;
                  if (ts > maxTs) maxTs = ts;
                }
              }
              const lines: string[] = [];
              lines.push(`Events: ${bulkRows.length}`);
              lines.push(`Unique kinds: ${kinds.size}`);
              lines.push(`Unique levels: ${levels.size}`);
              lines.push(`Unique sources: ${sources.size}`);
              if (isFinite(minTs) && isFinite(maxTs)) {
                const from = new Date(minTs).toISOString();
                const to = new Date(maxTs).toISOString();
                const dur = maxTs - minTs;
                let durStr: string;
                if (dur < 60_000) durStr = `${(dur / 1000).toFixed(1)}s`;
                else if (dur < 3_600_000)
                  durStr = `${Math.floor(dur / 60_000)}m ${Math.floor((dur % 60_000) / 1000)}s`;
                else if (dur < 86_400_000)
                  durStr = `${Math.floor(dur / 3_600_000)}h ${Math.floor((dur % 3_600_000) / 60_000)}m`;
                else
                  durStr = `${Math.floor(dur / 86_400_000)}d ${Math.floor((dur % 86_400_000) / 3_600_000)}h`;
                lines.push(`From: ${from}`);
                lines.push(`To: ${to}`);
                lines.push(`Duration: ${durStr}`);
              }
              void navigator.clipboard.writeText(lines.join("\n"));
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy a multi-line KV summary across ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} (Events / Unique kinds / Unique levels / Unique sources / From / To / Duration). 5th panel in the metadata summary family (History R688-R689, Scanner R690, Target R691, Collaborator R692, Logger R693). Great for log-stream audit summaries.`
            }
          >
            📋 Copy stats
          </button>
          {/* R699: Logger "📋 Copy time range" — standalone
              2nd metadata-summary op on Logger (companion to
              R693 Copy stats which embeds time range among
              count metrics). This dedicated op offers just
              the time info without the counts noise — some
              operators pasting ticket metadata want ONLY
              timestamps + duration. Mirrors R688 History +
              R697 Scanner + R698 Target shape. */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              let minTs = Number.POSITIVE_INFINITY;
              let maxTs = Number.NEGATIVE_INFINITY;
              for (const r of bulkRows) {
                const ts = r.event?.ts_ms ?? 0;
                if (ts > 0) {
                  if (ts < minTs) minTs = ts;
                  if (ts > maxTs) maxTs = ts;
                }
              }
              if (!isFinite(minTs) || !isFinite(maxTs)) {
                alert("No events in the selection have a timestamp.");
                return;
              }
              const from = new Date(minTs).toISOString();
              const to = new Date(maxTs).toISOString();
              const dur = maxTs - minTs;
              let durStr: string;
              if (dur < 60_000) durStr = `${(dur / 1000).toFixed(1)}s`;
              else if (dur < 3_600_000)
                durStr = `${Math.floor(dur / 60_000)}m ${Math.floor((dur % 60_000) / 1000)}s`;
              else if (dur < 86_400_000)
                durStr = `${Math.floor(dur / 3_600_000)}h ${Math.floor((dur % 3_600_000) / 60_000)}m`;
              else
                durStr = `${Math.floor(dur / 86_400_000)}d ${Math.floor((dur % 86_400_000) / 3_600_000)}h`;
              const lines = [
                `From: ${from}`,
                `To: ${to}`,
                `Duration: ${durStr}`,
                `Events: ${bulkRows.length}`,
              ];
              void navigator.clipboard.writeText(lines.join("\n"));
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy time range across ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} (earliest → latest ISO 8601 + adaptive duration + count). Mirror of R688 History + R697 Scanner + R698 Target — "when did these events actually land?" audit answer. Standalone companion to R693 Copy stats.`
            }
          >
            📋 Copy time range
          </button>
          {/* R627: Logger "Copy as Markdown table" — fourth entry
              in cross-panel "Copy as Markdown" family (History
              R624 + Target Issues R625 + Scanner R626 + Logger
              R627). Table variant for Jira / PR descriptions.
              6 columns: seq, ts, kind, level, source, summary. */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const headers = ["seq", "ts_ms", "kind", "level", "source", "summary"];
              const esc = (v: unknown) =>
                String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
              const sep = headers.map(() => "---").join(" | ");
              const body = bulkRows
                .map((r) => {
                  const k: any = r.event?.kind ?? {};
                  return [
                    r.seq,
                    r.event.ts_ms,
                    typeof k.kind === "string" ? k.kind : "",
                    typeof k.level === "string" ? k.level : "",
                    typeof k.source === "string" ? k.source : "",
                    summary(k),
                  ]
                    .map(esc)
                    .join(" | ");
                })
                .join("\n");
              const md = `| ${headers.join(" | ")} |\n| ${sep} |\n${body
                .split("\n")
                .map((line) => `| ${line} |`)
                .join("\n")}`;
              void navigator.clipboard.writeText(md);
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} as a GitHub-flavored Markdown table (6 cols: seq, ts_ms, kind, level, source, summary). Great for Jira / PR description / Slack. Fourth entry in cross-panel Copy-as-Markdown family.`
            }
          >
            📋 Copy as Markdown
          </button>
          {/* R616: Clipboard-only JSONL counterpart to Export JSONL
              on Logger. Third entry in cross-panel "Copy as JSONL"
              family (History R614 + Scanner R615 + Logger R616).
              Streaming-friendly dense format for jq / ELK ingest. */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const body = bulkRows
                .map((r) =>
                  JSON.stringify({
                    seq: r.seq,
                    ts_ms: r.event.ts_ms,
                    event: r.event,
                  }),
                )
                .join("\n");
              void navigator.clipboard.writeText(body);
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No events selected"
                : `Copy ${bulkRows.length} selected event${bulkRows.length === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line — byte-identical to Export JSONL). Great for jq / grep / ELK / Splunk ingest. Third entry in cross-panel Copy-as-JSONL family (History R614 + Scanner R615 + Logger R616).`
            }
          >
            📋 Copy as JSONL
          </button>
          <span className="spacer" style={{ flex: 1 }} />
          <button onClick={clearSelection}>Clear selection</button>
        </div>
      )}
      <div ref={scrollRef} style={{ flex: 1, overflow: "auto", padding: 6, background: "var(--bg)" }}>
        {/* R783: Burp-identical Logger empty-state card. Replaces
            the one-line "No events yet" placeholder with the full
            Burp 2026.8 empty-state affordance — centered SVG log-
            stream silhouette, bold headline, descriptive subhead
            explaining the 5-kind event bus (transaction, intercept,
            finding, log, ws_*), and a shortcut hint strip. Completes
            the 5-panel empty-state family (R776 Proxy intercept +
            R778 History + R781 Scanner + R782 Collaborator + R783
            Logger). Different flavor from the others — Logger is a
            live event bus so the empty state's narrative is
            "nothing happening yet" vs "no stored data". */}
        {visible.length === 0 && (
          <div className="log-empty-card">
            <div className="log-empty-icon">
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
                <path d="M3 6h14M3 11h14M3 16h8" />
                <circle cx="19" cy="16" r="2" />
              </svg>
            </div>
            <div className="log-empty-title">
              No events yet
            </div>
            <div className="log-empty-sub">
              Logger streams the live event bus — <b>HTTP transactions</b>{" "}
              as they flow through the proxy, <b>Scanner findings</b> as
              passive detectors fire, <b>Intercept</b> forwards/drops,{" "}
              <b>WebSocket</b> frames, and <b>system logs</b>. Interact
              with the proxied browser, send a Repeater request, or run
              a passive scan over history to see events start landing
              here in real time. Auto-scroll keeps the latest events in
              view; use <b>Pause</b> above to freeze the stream for
              inspection.
            </div>
            <div className="log-empty-hints">
              Shortcuts: <b>P</b> pause/resume · <b>Esc</b> clear filter ·{" "}
              right-click a row for Copy raw / Copy summary / Filter by
              kind / Clear filters · <b>Alt+Shift+C</b> clear all events
            </div>
          </div>
        )}
        <table
          className="mono logger-table"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          {/* R839: Burp-identical sticky column-header row. Burp's
              Logger always carries labeled columns (#, Time, Kind,
              Summary) at the top of the table — ours previously had
              only rows with no header, which left operators guessing
              what each column meant. Sticky positioning so the
              header stays visible when scrolling through a long
              event stream. Shares the `.logger-table thead th`
              typography with the rest of BurpFree's data tables for
              family consistency. */}
          {visible.length > 0 && (
            <thead>
              <tr>
                <th style={{ width: 60, textAlign: "left" }}>#</th>
                <th style={{ width: 90, textAlign: "left" }}>Time</th>
                <th style={{ width: 110, textAlign: "left" }}>Kind</th>
                <th style={{ textAlign: "left" }}>Summary</th>
              </tr>
            </thead>
          )}
          <tbody>
            {visible.map((e) => {
              // R297: Event-kind row tint — complete the row-tint
              // trio (R294 Intruder status / R295 History status /
              // R297 Logger kind). Different axis for Logger
              // because events don't have a status code — they're
              // typed by `kind`. Findings get a sev-tinted
              // background derived from the embedded severity so
              // operators scrolling the event stream spot
              // critical/high findings at a glance; log entries
              // tint by level (error = red, warn = amber, info /
              // debug = default). WS / transaction / intercept
              // kinds stay default — they're high-volume + their
              // kind-chip badge already carries the colour cue.
              const k = e.event.kind;
              const kindStr = typeof k.kind === "string" ? k.kind : "";
              let kindBg: string | undefined;
              if (kindStr === "finding") {
                const sev = (
                  typeof k.severity === "string" ? k.severity : "info"
                ).toLowerCase();
                if (sev === "critical")
                  kindBg = "rgba(224, 68, 68, 0.14)";
                else if (sev === "high")
                  kindBg = "rgba(240, 140, 60, 0.10)";
                else if (sev === "medium")
                  kindBg = "rgba(240, 210, 60, 0.08)";
                else if (sev === "low")
                  kindBg = "rgba(100, 170, 220, 0.07)";
                // info stays default
              } else if (kindStr === "log") {
                const lvl = (
                  typeof k.level === "string" ? k.level : "info"
                ).toLowerCase();
                if (lvl === "error")
                  kindBg = "rgba(224, 68, 68, 0.10)";
                else if (lvl === "warn")
                  kindBg = "rgba(240, 192, 48, 0.08)";
              }
              const isSelected = selectedIds.has(e.seq);
              return (
              <tr
                key={e.seq}
                data-row-seq={e.seq}
                onClick={(evt) => onRowClick(evt, e)}
                onContextMenu={(evt) => {
                  evt.preventDefault();
                  setLogMenu({ x: evt.clientX, y: evt.clientY, data: e });
                }}
                style={{
                  cursor: "pointer",
                  // Selection trumps kind tint so the operator
                  // always sees which rows a bulk op will act on.
                  background: isSelected
                    ? "var(--accent-dim)"
                    : kindBg,
                }}
              >
                <td style={{ color: "var(--text-faint)", width: 60, padding: "2px 6px" }}>#{e.seq}</td>
                <td style={{ color: "var(--text-dim)", width: 90, padding: "2px 6px" }}>{fmtTime(e.event.ts_ms)}</td>
                <td style={{ width: 110, padding: "2px 6px" }}>
                  <span className={`badge ${badgeClass(e.event.kind)}`}>{kindLabel(e.event.kind)}</span>
                </td>
                <td style={{ padding: "2px 6px", wordBreak: "break-all" }}>{summary(e.event.kind)}</td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <FloatingMenu
        state={logMenu}
        onClose={() => setLogMenu(null)}
        items={
          logMenu?.data
            ? (() => {
                const k = logMenu.data!.event?.kind ?? {};
                const kindStr = typeof k.kind === "string" ? k.kind : "";
                const level = typeof k.level === "string" ? k.level : "";
                const source = typeof k.source === "string" ? k.source : "";
                return [
                  {
                    label: "Copy raw entry (JSON)",
                    onClick: () =>
                      void copyToClipboard(
                        JSON.stringify(logMenu.data!.event, null, 2),
                      ),
                  },
                  // R713: Logger row "Copy JSONL line" — 6th
                  // panel in the row-level JSONL-line family
                  // (HistoryPanel R708 + Scanner R709 + Target
                  // R710 + ProxyPanel R711 + Intruder R712 +
                  // Logger R713). Single-line NDJSON for
                  // appending to a .jsonl log / piping to jq.
                  // Trailing newline. Byte-identical to R616
                  // Logger bulk Copy-as-JSONL per-line output.
                  // Serialises the event (not the Logged
                  // wrapper) to match the bulk shape.
                  {
                    label: "Copy JSONL line",
                    hint: "one object, one line + newline",
                    onClick: () =>
                      void copyToClipboard(
                        JSON.stringify(logMenu.data!.event) + "\n",
                      ),
                  },
                  // R731: Logger row "Copy triage line" — 5th
                  // panel in the row-level Copy triage-line
                  // family (HistoryPanel R717 + ProxyPanel R718
                  // + Scanner R728 + Target R729 + Logger R731).
                  // Compact single-line log-event summary.
                  // Format: "LEVEL kind source · summary ·
                  // seq#N". Level upper-cased when present
                  // (fatal/error/warn/info/debug); kind always
                  // present; source optional. Great for a Slack
                  // ping of a specific error with full context.
                  {
                    label: "Copy triage line",
                    hint: "compact LEVEL kind source · summary · seq",
                    onClick: () => {
                      const r = logMenu.data!;
                      const parts: string[] = [];
                      const levelStr = level ? level.toUpperCase() : "";
                      const head = levelStr
                        ? `${levelStr} ${kindStr || "(unknown)"}`
                        : kindStr || "(unknown)";
                      parts.push(head);
                      if (source) parts.push(source);
                      const sum = summary(k);
                      if (sum) parts.push(sum);
                      parts.push(`seq#${r.seq}`);
                      void copyToClipboard(parts.join(" · "));
                    },
                  },
                  {
                    label: "Copy summary",
                    onClick: () => void copyToClipboard(summary(k)),
                  },
                  // R667: Logger row-right-click "Copy table row"
                  // — single-row Markdown table variant matching
                  // R627 Logger bulk Copy as Markdown's 6-column
                  // shape (seq/ts_ms/kind/level/source/summary).
                  // Great for appending a single event to an
                  // existing incident timeline table.
                  {
                    label: "Copy table row",
                    hint: "Markdown table body line · no header",
                    onClick: () => {
                      const r = logMenu.data!;
                      const esc = (v: unknown) =>
                        String(v ?? "")
                          .replace(/\|/g, "\\|")
                          .replace(/\n/g, " ");
                      const cells = [
                        r.seq,
                        r.event.ts_ms,
                        kindStr,
                        level,
                        source,
                        summary(k),
                      ]
                        .map(esc)
                        .join(" | ");
                      void copyToClipboard(`| ${cells} |`);
                    },
                  },
                  { separator: true },
                  {
                    label: kindStr
                      ? `Filter by kind: ${kindStr}`
                      : "Filter by kind",
                    disabled: !isFilterableKind(kindStr),
                    onClick: () => {
                      // The main filter dropdown is one of 6 fixed
                      // buckets, so we snap to the matching bucket.
                      if (kindStr === "transaction") setFilter("transaction");
                      else if (kindStr === "intercept") setFilter("intercept");
                      else if (kindStr === "finding") setFilter("finding");
                      else if (kindStr === "log") setFilter("log");
                      else if (kindStr.startsWith("ws_")) setFilter("ws");
                    },
                  },
                  {
                    label: level
                      ? `Filter by level: ${level}`
                      : "Filter by level",
                    disabled: !level,
                    onClick: () => {
                      // Levels aren't in the main filter dropdown;
                      // use the search field as a scrappy pseudo-
                      // filter so the operator sees matching rows.
                      setSearch(`"level":"${level}"`);
                    },
                  },
                  {
                    label: source
                      ? `Search by source: ${source}`
                      : "Search by source",
                    disabled: !source,
                    onClick: () => {
                      setSearch(`"source":"${source}"`);
                    },
                  },
                  { separator: true },
                  // R510: Logger transaction-kind "→ Send to Repeater"
                  // — new cross-panel pivot that mirrors Target Issues'
                  // "Send to Repeater" row entry applied to Logger
                  // transaction events. Logger has long been a dead-end
                  // for shipping a transaction into Repeater — operators
                  // had to pivot via R485 "→ Open in HTTP history" first,
                  // then right-click the matching HistoryPanel row and
                  // use its "Send to Repeater" entry. Two clicks and a
                  // panel flip. R510 collapses that into one click
                  // directly from Logger. **Mechanism** matches
                  // TargetPanel's sendIssueToRepeater exactly: calls
                  // `api.repeaterAddFromHistory(k.id, "logger tx #<id>")`
                  // then fires `burpfree:navigate` to flip to the
                  // Repeater tab. The tab title is prefixed with
                  // "logger" so the Repeater tab bar makes the origin
                  // panel obvious at a glance — HistoryPanel's
                  // sendToRepeater uses a URL-derived title and Target
                  // uses the issue title, so Logger using a stream-
                  // origin tag keeps the three origins distinguishable
                  // in the Repeater tab list. **Disabled gate**
                  // `kindStr === "transaction" && typeof k.id ===
                  // "number"` — passive-only kinds (log / intercept /
                  // finding / ws_*) skip gracefully. Logger's
                  // transaction-pivot menu now carries 8 ops at the
                  // top of the per-row context menu.
                  {
                    label: "→ Send to Repeater",
                    hotkey: "→ R",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · new Repeater tab`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        await api.repeaterAddFromHistory(
                          k.id,
                          `logger tx #${k.id}`,
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "repeater" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Repeater failed: ${e}`);
                      }
                    },
                  },
                  // R511: Logger transaction-kind "→ Send to Intruder"
                  // — parallel to R510 Send to Repeater, extending the
                  // Logger pivot family with the second cross-panel
                  // send-op that Target Issues (R131-era) and
                  // HistoryPanel ship on their row-right-click menus.
                  // Mechanism matches TargetPanel's sendIssueToIntruder
                  // exactly: fetch the parent summary via
                  // `api.historyShow(k.id)`, build the URL via
                  // `urlFromSummary`, then dispatch
                  // `burpfree:intruder-load` with url + method + tx id
                  // and `burpfree:navigate` to flip to the Intruder
                  // tab. Logger uses the RPC fetch (rather than relying
                  // on an in-memory tx map like TargetPanel does)
                  // because Logger doesn't maintain a parallel tx map
                  // — the stream model keeps a flat event list and
                  // defers transaction detail to historyShow() on
                  // demand. **Disabled gate** matches R510:
                  // `kindStr === "transaction" && typeof k.id ===
                  // "number"` — passive-only kinds skip gracefully.
                  // Logger's transaction-pivot menu now carries 9
                  // ops: → Send to Repeater / → Send to Intruder /
                  // Copy tx URL / Copy as cURL / Copy as PowerShell /
                  // Copy as Python / Copy as HAR entry / ⬇ Save as
                  // HAR file / → Open in HTTP history — the full
                  // send+copy+pivot taxonomy that Target Issues
                  // carries, applied to Logger transaction rows.
                  {
                    label: "→ Send to Intruder",
                    hotkey: "→ I",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · Intruder load`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.summary) {
                          alert(`Transaction #${k.id} could not be resolved.`);
                          return;
                        }
                        const url = urlFromSummary(view.summary);
                        window.dispatchEvent(
                          new CustomEvent("burpfree:intruder-load", {
                            detail: {
                              url,
                              method: view.summary.method,
                              transactionId: k.id,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "intruder" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Intruder failed: ${e}`);
                      }
                    },
                  },
                  // R512: Logger transaction-kind "→ Send to Comparer
                  // (left/right)" — closes the Target Issues send-
                  // pivot parity on Logger. Target Issues ships four
                  // send pivots (Repeater / Intruder / Comparer-left /
                  // Comparer-right); R510 + R511 covered the first
                  // two; R512 ships both Comparer slots together
                  // since they share the full mechanism and differ
                  // only in which slot the raw payload lands.
                  // Mechanism matches TargetPanel's sendIssueToComparer
                  // exactly: fetches the parent view via
                  // `api.historyShow(k.id)` to get the raw request
                  // bytes, then dispatches `burpfree:comparer-load`
                  // with `{ left/right: raw, right/left: "", label }`.
                  // The label embeds "logger tx #<id>" so Comparer's
                  // slot header makes the origin obvious — parallel
                  // to R511's tab-title prefix convention. Then
                  // dispatches `burpfree:navigate` to the Comparer
                  // tab. **Disabled gate** matches R510/R511:
                  // transaction-kind events only. Logger's
                  // transaction-pivot menu now carries 11 ops at the
                  // top of the per-row context menu — matching Target
                  // Issues' full 4-way send pivot plus Logger's full
                  // 5-way copy/pivot bottom-half.
                  {
                    label: "→ Send to Comparer (left)",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · Comparer left slot`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        const raw = view?.request_raw ?? "";
                        window.dispatchEvent(
                          new CustomEvent("burpfree:comparer-load", {
                            detail: {
                              left: raw,
                              right: "",
                              label: `logger tx #${k.id}`,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "comparer" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Comparer (left) failed: ${e}`);
                      }
                    },
                  },
                  {
                    label: "→ Send to Comparer (right)",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · Comparer right slot`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        const raw = view?.request_raw ?? "";
                        window.dispatchEvent(
                          new CustomEvent("burpfree:comparer-load", {
                            detail: {
                              left: "",
                              right: raw,
                              label: `logger tx #${k.id}`,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "comparer" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Comparer (right) failed: ${e}`);
                      }
                    },
                  },
                  // R493: Transaction-kind URL copy — right-click a
                  // transaction row and get its URL on the clipboard
                  // without navigating away. Companion to R485's
                  // "→ Open in HTTP history" entry (which flips to
                  // the HTTP history tab) — this one keeps the
                  // operator in the Logger stream and just copies
                  // the URL. Pattern matches R486 Scanner row
                  // "Copy parent tx URL" + R491 Scanner detail +
                  // R492 Target Issues detail. **Mechanism** fetches
                  // the parent summary via `api.historyShow(k.id)`
                  // + builds the URL via `urlFromSummary`. One RPC
                  // per click. **Disabled gate** `kindStr ===
                  // "transaction" && typeof k.id === "number"` —
                  // only transaction-kind rows carry a tx id.
                  {
                    label: "Copy tx URL",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id}`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.summary) {
                          alert(`Transaction #${k.id} could not be resolved.`);
                          return;
                        }
                        await copyToClipboard(urlFromSummary(view.summary));
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  // R496: Logger transaction-kind "Copy as cURL" —
                  // completes the transaction-pivot family in Logger
                  // alongside R485 "→ Open in HTTP history" (navigate
                  // pivot) + R493 "Copy tx URL" (URL copy). This one
                  // emits the full cURL command for shell replay
                  // from Logger directly, without a cross-panel pivot
                  // into HistoryPanel. Pattern matches R494 Scanner
                  // row + R495 Target Issues row — same historyShow
                  // + fromSummaryAndRaw + buildCurl pipeline.
                  // **Disabled gate** same as R493: only transaction-
                  // kind events carry a tx id.
                  {
                    label: "Copy as cURL",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · full headers + body`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.request_raw) {
                          alert(
                            `Transaction #${k.id} has no stored request_raw.`,
                          );
                          return;
                        }
                        const req = fromSummaryAndRaw(
                          view.summary,
                          view.request_raw,
                        );
                        await copyToClipboard(buildCurl(req));
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  // R499: Logger transaction-kind "Copy as PowerShell"
                  // — completes the Scanner (R497) / Target (R498) /
                  // Logger (R499) PowerShell per-row parity across the
                  // three transaction-pivot panels. Mechanism matches
                  // R496 cURL exactly, just swaps `buildCurl` for
                  // `buildPowerShell`. Operators on Windows triaging
                  // the Logger stream get Invoke-WebRequest replay
                  // commands without the cross-panel pivot.
                  {
                    label: "Copy as PowerShell",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · Invoke-WebRequest`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.request_raw) {
                          alert(
                            `Transaction #${k.id} has no stored request_raw.`,
                          );
                          return;
                        }
                        const req = fromSummaryAndRaw(
                          view.summary,
                          view.request_raw,
                        );
                        await copyToClipboard(buildPowerShell(req));
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  // R502: Logger transaction-kind "Copy as Python
                  // (requests)" — completes the Scanner/Target/Logger
                  // three-panel Python parity (R500/R501/R502).
                  // Mechanism matches R496/R499 exactly, swapping
                  // the builder for `buildPython`. All three
                  // transaction-pivot panels now carry the full
                  // shell-replay triad (cURL + PowerShell + Python)
                  // at matching menu positions.
                  {
                    label: "Copy as Python (requests)",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · import requests`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.request_raw) {
                          alert(
                            `Transaction #${k.id} has no stored request_raw.`,
                          );
                          return;
                        }
                        const req = fromSummaryAndRaw(
                          view.summary,
                          view.request_raw,
                        );
                        await copyToClipboard(buildPython(req));
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  // R506: Logger transaction-kind "Copy as HAR entry"
                  // — completes the Scanner (R482) / Target (R483) /
                  // Logger (R506) HAR-row triad across the three
                  // transaction-pivot panels. Scanner and Target
                  // got HAR row-right-click back in R482/R483 but
                  // Logger lagged behind until R506. Mechanism
                  // matches R482/R483 exactly: historyShow(k.id)
                  // for request_raw + response_raw, fromSummaryAndRaw
                  // for the request half, inline response-parse
                  // (status/headers/body) for the response half,
                  // buildHarEntry + buildHarLog + copyToClipboard
                  // for the single-entry HAR 1.2 output. Logger's
                  // transaction-pivot menu now carries the full
                  // six-way surface: Copy tx URL (R493) / Copy as
                  // cURL (R496) / Copy as PowerShell (R499) / Copy
                  // as Python (R502) / Copy as HAR entry (R506) /
                  // → Open in HTTP history (R485). HAR surface now
                  // spans 12 input paths across 5 panels.
                  // **Disabled gate** same as R493/R496/R499/R502:
                  // only transaction-kind events carry a tx id.
                  {
                    label: "Copy as HAR entry",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · single-entry HAR 1.2 log`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      try {
                        const view = await api.historyShow(k.id);
                        if (!view?.request_raw) {
                          alert(
                            `Transaction #${k.id} has no stored request_raw — cannot build a HAR entry.`,
                          );
                          return;
                        }
                        const req = fromSummaryAndRaw(
                          view.summary,
                          view.request_raw,
                        );
                        let resp: Parameters<typeof buildHarEntry>[2] =
                          undefined;
                        if (view.response_raw) {
                          const text = view.response_raw.replace(/\r\n/g, "\n");
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
                            if (n.toLowerCase() === "content-type")
                              mimeType = v;
                          }
                          resp = {
                            status,
                            statusText,
                            httpVersion,
                            headers,
                            mimeType,
                            body,
                          };
                        }
                        const startedDateTime = new Date(
                          view.summary.ts_ms,
                        ).toISOString();
                        const entry = buildHarEntry(
                          req,
                          startedDateTime,
                          resp,
                        );
                        const har = buildHarLog([entry]);
                        await copyToClipboard(
                          JSON.stringify(har, null, 2),
                        );
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  // R509: Logger transaction-kind "⬇ Save as HAR
                  // file" — closes the Scanner/Target/Logger HAR-row
                  // file-save triad after R507 Scanner + R508 Target.
                  // Logger's row-right-click HAR surface now carries
                  // both clipboard (R506) and file-save (R509)
                  // variants at matching menu positions, parallel to
                  // Scanner (R482 clip + R507 file) and Target (R483
                  // clip + R508 file). Mechanism matches R506 for the
                  // HAR 1.2 build and R507/R508 for the on-disk save.
                  // **Filename pattern** `logger-har-tx-<id>.har` —
                  // Logger transaction events don't carry a title
                  // like Scanner/Target findings do, so the file name
                  // encodes just the tx id (which is the canonical
                  // identifier for a Logger transaction row anyway).
                  // Operators dumping several Logger HARs from one
                  // triage session keep the files identifiable by tx
                  // id without a slug collision. Disabled gate same
                  // as R506 / R493 / R496 / R499 / R502: only
                  // transaction-kind events carry a tx id — other
                  // kinds (finding, intercept, ws_*, log) skip
                  // gracefully. Logger's transaction-pivot menu now
                  // carries seven ops: Copy tx URL / Copy as cURL /
                  // Copy as PowerShell / Copy as Python / Copy as
                  // HAR entry / ⬇ Save as HAR file / → Open in HTTP
                  // history. HAR surface now spans 15 input paths
                  // across 5 panels.
                  {
                    label: "⬇ Save as HAR file",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id} · single-entry HAR 1.2 log · to disk`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: async () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      const txId = k.id;
                      try {
                        const view = await api.historyShow(txId);
                        if (!view?.request_raw) {
                          alert(
                            `Transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
                          );
                          return;
                        }
                        const req = fromSummaryAndRaw(
                          view.summary,
                          view.request_raw,
                        );
                        let resp: Parameters<typeof buildHarEntry>[2] =
                          undefined;
                        if (view.response_raw) {
                          const text = view.response_raw.replace(/\r\n/g, "\n");
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
                            if (n.toLowerCase() === "content-type")
                              mimeType = v;
                          }
                          resp = {
                            status,
                            statusText,
                            httpVersion,
                            headers,
                            mimeType,
                            body,
                          };
                        }
                        const startedDateTime = new Date(
                          view.summary.ts_ms,
                        ).toISOString();
                        const entry = buildHarEntry(
                          req,
                          startedDateTime,
                          resp,
                        );
                        const har = buildHarLog([entry]);
                        const name = `logger-har-tx-${txId}.har`;
                        const blob = new Blob(
                          [JSON.stringify(har, null, 2)],
                          { type: "application/json;charset=utf-8" },
                        );
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
                    },
                  },
                  // R485: Transaction-kind pivot — right-click a
                  // transaction row and jump to HTTP history with
                  // the matching tx focused in the detail pane.
                  // Parallels R161 Scanner detail-pane "→ History"
                  // button, R419 Scanner row-right-click "→ History
                  // (parent tx)" entry, and R420/R421 Alt+Shift+H
                  // keyboard pivots. The Logger has long been a
                  // dead-end for transaction events — kind filter
                  // narrows the view but there's no one-click path
                  // back to the full history row. **Mechanism**
                  // same CustomEvent duo as R161/R419: fire
                  // `burpfree:history-focus` with the tx id, then
                  // `burpfree:navigate` to flip the main tab.
                  // **Disabled gate** only transaction-kind events
                  // carry a tx id — other kinds (finding, intercept,
                  // ws_*, log) skip gracefully. Hint shows the tx
                  // id so operators preview the target.
                  {
                    label: "→ Open in HTTP history",
                    hint:
                      kindStr === "transaction" && typeof k.id === "number"
                        ? `tx #${k.id}`
                        : "transaction-kind events only",
                    disabled: !(kindStr === "transaction" && typeof k.id === "number"),
                    onClick: () => {
                      if (kindStr !== "transaction" || typeof k.id !== "number") return;
                      const txId = k.id;
                      window.dispatchEvent(
                        new CustomEvent("burpfree:history-focus", {
                          detail: { id: txId },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                    },
                  },
                  {
                    label: "Clear filters",
                    disabled: filter === "all" && !search && !bambda,
                    onClick: () => {
                      setFilter("all");
                      setSearch("");
                      setBambda("");
                      setBambdaDraft("");
                    },
                  },
                ];
              })()
            : []
        }
      />
    </div>
  );
}

/** Only a handful of event kinds map to our fixed filter buckets.
 *  Returns true if the dropdown can snap to this kind. */
function isFilterableKind(kind: string): boolean {
  return (
    kind === "transaction" ||
    kind === "intercept" ||
    kind === "finding" ||
    kind === "log" ||
    kind.startsWith("ws_")
  );
}

function matchesKind(e: Logged, f: KindFilter): boolean {
  const k = e.event.kind;
  if (f === "all") return true;
  if (f === "transaction") return k?.kind === "transaction";
  if (f === "intercept") return k?.kind === "intercept";
  if (f === "finding") return k?.kind === "finding";
  if (f === "ws") return k?.kind?.startsWith?.("ws_") || k?.kind === "ws_message" || k?.kind === "ws_opened" || k?.kind === "ws_closed";
  if (f === "log") return k?.kind === "log";
  return true;
}

function matchesSearch(e: Logged, q: string, caseSensitive: boolean): boolean {
  if (!q) return true;
  const raw = JSON.stringify(e.event.kind);
  if (caseSensitive) {
    return raw.includes(q);
  }
  return raw.toLowerCase().includes(q.toLowerCase());
}

function kindLabel(k: any): string {
  if (!k || !k.kind) return "?";
  return String(k.kind).replace(/_/g, " ");
}

function badgeClass(k: any): string {
  if (!k) return "";
  switch (k.kind) {
    case "transaction": return "accent";
    case "finding": return "red";
    case "intercept": return "red";
    case "log": return k.level === "warn" ? "red" : "";
    default: return "";
  }
}

function summary(k: any): string {
  if (!k) return "";
  switch (k.kind) {
    case "transaction": return `txn id=${k.id}`;
    case "ws_opened": return `ws opened id=${k.id}`;
    case "ws_closed": return `ws closed id=${k.id}`;
    case "ws_message": return `ws msg session=${k.session_id} msg=${k.message_id}`;
    case "finding": return `finding id=${k.id}`;
    case "intercept": return `${k.direction} intercept id=${k.id}`;
    case "log": return `[${k.source}] ${k.level}: ${k.message}`;
    case "project": return `project ${k.action}`;
    default: return JSON.stringify(k);
  }
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms3 = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms3}`;
}

/** Flatten an event into a predicate-friendly bag of fields. The raw
 *  original payload is attached as `raw` for anything the expression
 *  wants to introspect manually. */
function flattenEvent(e: Logged): EventRow {
  const k = e.event?.kind ?? {};
  return {
    seq: e.seq,
    ts_ms: e.event?.ts_ms ?? 0,
    kind: typeof k.kind === "string" ? k.kind : "",
    level: k.level,
    source: k.source,
    message: k.message,
    id: k.id,
    session_id: k.session_id,
    message_id: k.message_id,
    direction: k.direction,
    severity: k.severity,
    action: k.action,
    raw: k,
  };
}

/** Compile the user's Bambda-style expression into a predicate. The
 *  expression runs inside a `new Function` with the flattened event
 *  as the single parameter. We disallow `return` keywords so authors
 *  can write pure expressions without wrapping them. */
function compileBambda(
  expr: string,
): { predicate: ((row: EventRow) => boolean) | null; bambdaError: string | null } {
  const trimmed = expr.trim();
  if (!trimmed) return { predicate: null, bambdaError: null };
  try {
    // Destructure the row for ergonomic expressions.
    const fn = new Function(
      "ev",
      `const { kind, level, source, message, id, session_id, message_id, direction, severity, action, ts_ms, seq, raw } = ev; return (${trimmed});`,
    ) as (row: EventRow) => unknown;
    return {
      predicate: (row) => Boolean(fn(row)),
      bambdaError: null,
    };
  } catch (e) {
    return { predicate: null, bambdaError: String(e) };
  }
}
