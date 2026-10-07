import { useEffect, useMemo, useRef, useState } from "react";
import { api, ComparerItem, JsonDiffEntry, JsonDiffReport } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { copyToClipboard } from "../copyAs";

/** Short relative-age label used by the items collection rail. */
function relativeAge(tsMs: number): string {
  if (!tsMs || tsMs <= 0) return "—";
  const d = Math.max(0, Date.now() - tsMs);
  if (d < 2_000) return "just now";
  const s = Math.floor(d / 1_000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const dd = Math.floor(h / 24);
  if (dd < 7) return `${dd}d ago`;
  return new Date(tsMs).toISOString().slice(0, 10);
}

/** Build a human-readable label out of a free-form text payload.
 *  Returns the first non-empty line, trimmed, up to 60 chars. Used
 *  when the caller doesn't supply an explicit label. */
function deriveLabel(text: string): string {
  const line =
    text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.length > 0) ?? "";
  if (line.length === 0) return "(empty)";
  return line.length > 60 ? line.slice(0, 60) + "…" : line;
}

type DiffLine = {
  op: "equal" | "insert" | "delete";
  left_line?: number;
  right_line?: number;
  text: string;
};

type Mode = "line" | "word" | "byte" | "json";

/** Payload format for the global `burpfree:comparer-load` CustomEvent. */
export type ComparerLoadDetail = {
  left: string;
  right: string;
  label?: string;
};

const BYTES_PER_ROW = 16;

/** One row of a side-by-side hex dump. `undefined` byte = past end of input. */
type ByteRow = {
  offset: number;
  left: Array<number | undefined>;
  right: Array<number | undefined>;
};

/** Encode a string as UTF-8 bytes. Needed because textareas are text, but
 *  the operator still wants a byte-oriented view. */
function toBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Build the row-aligned view of two byte arrays — one row per 16 bytes
 *  of the longer side. Shorter side gets `undefined` placeholders so the
 *  renderer can draw blank cells and the diff logic doesn't need special
 *  cases for length mismatches. */
function buildRows(leftBytes: Uint8Array, rightBytes: Uint8Array): ByteRow[] {
  const total = Math.max(leftBytes.length, rightBytes.length);
  const rowCount = total === 0 ? 0 : Math.ceil(total / BYTES_PER_ROW);
  const rows: ByteRow[] = [];
  for (let r = 0; r < rowCount; r++) {
    const offset = r * BYTES_PER_ROW;
    const left: Array<number | undefined> = [];
    const right: Array<number | undefined> = [];
    for (let i = 0; i < BYTES_PER_ROW; i++) {
      const idx = offset + i;
      left.push(idx < leftBytes.length ? leftBytes[idx] : undefined);
      right.push(idx < rightBytes.length ? rightBytes[idx] : undefined);
    }
    rows.push({ offset, left, right });
  }
  return rows;
}

function hex2(n: number | undefined): string {
  return n === undefined ? "  " : n.toString(16).padStart(2, "0");
}

function asciiChar(n: number | undefined): string {
  if (n === undefined) return " ";
  // Printable ASCII, matches `xxd`'s guard.
  return n >= 0x20 && n <= 0x7e ? String.fromCharCode(n) : ".";
}

export function ComparerPanel() {
  const [left, setLeft] = useState("line 1\nline 2\nline 3");
  const [right, setRight] = useState("line 1\nchanged\nline 3");
  // Hidden file inputs for R120's `⬆ Left` / `⬆ Right` buttons —
  // separate refs so each slot can be loaded independently without
  // one input's file reset clobbering the other. Same pattern as
  // R118 (Intruder payload load) + R119 (Decoder input load).
  const leftFileRef = useRef<HTMLInputElement | null>(null);
  const rightFileRef = useRef<HTMLInputElement | null>(null);
  const [ignoreWs, setIgnoreWs] = useState(false);
  const [mode, setMode] = useState<Mode>("line");
  const [label, setLabel] = useState<string | null>(null);
  const [diff, setDiff] = useState<{
    lines: DiffLine[];
    similarity: number;
  } | null>(null);
  const [jsonDiff, setJsonDiff] = useState<JsonDiffReport | null>(null);
  // Comparer item collection — mirror of Burp's numbered item list.
  // Operators stash snippets here across restarts; the list is
  // persisted in `ProjectConfig::comparer_items`. Hydrated once on
  // mount; mutations go through the backend upsert cmds + refresh
  // locally so the display always reflects the canonical state.
  // Silent-on-error (no project yet) so a fresh install's Comparer
  // panel doesn't flash alerts before an operator picks a project.
  const [items, setItems] = useState<ComparerItem[]>([]);
  const [itemsExpanded, setItemsExpanded] = useState(true);
  const [itemsBusy, setItemsBusy] = useState(false);
  // R489: Right-click menu state for a Comparer item row — carries the
  // ComparerItem so menu handlers can reach label / text / ts_ms /
  // id without threading props. First row-right-click surface on
  // Comparer — previously the items table was click-only (load left /
  // load right / delete, all via inline buttons on each row).
  const [itemMenu, setItemMenu] = useState<MenuState<ComparerItem> | null>(
    null,
  );
  // R260: Items collection search filter — case-insensitive substring
  // match against both the derived label and the raw text body. Lets
  // operators scrubbing a long-running engagement (dozens of stashed
  // snippets) find the row they want without eyeballing every label.
  // Esc inside the input clears it (consistent with R201 / R219 /
  // R223 / R224 / R227 Esc-clear-search family). Not persisted across
  // restarts — the Items list IS persisted, but the search is a
  // scratch filter that resets on panel reload.
  const [itemsSearch, setItemsSearch] = useState("");
  useEffect(() => {
    api
      .comparerItemsList()
      .then((rows) => setItems(rows ?? []))
      .catch(() => setItems([]));
  }, []);
  async function refreshItems() {
    try {
      setItems((await api.comparerItemsList()) ?? []);
    } catch {
      /* no project yet — keep stale snapshot */
    }
  }
  async function stashItem(side: "left" | "right") {
    const text = side === "left" ? left : right;
    if (!text.trim()) {
      alert(`The ${side}-hand side is empty — nothing to stash.`);
      return;
    }
    setItemsBusy(true);
    try {
      const item: ComparerItem = {
        id: crypto.randomUUID(),
        label: label?.trim() || deriveLabel(text),
        text,
        created_at_ms: Date.now(),
      };
      await api.comparerItemsAdd(item);
      await refreshItems();
    } catch (e) {
      alert(`Could not stash item: ${e}`);
    } finally {
      setItemsBusy(false);
    }
  }
  async function stashPaste() {
    setItemsBusy(true);
    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) {
        alert("Clipboard is empty or whitespace-only.");
        return;
      }
      const item: ComparerItem = {
        id: crypto.randomUUID(),
        label: deriveLabel(text),
        text,
        created_at_ms: Date.now(),
      };
      await api.comparerItemsAdd(item);
      await refreshItems();
    } catch (e) {
      alert(`Could not paste from clipboard: ${e}`);
    } finally {
      setItemsBusy(false);
    }
  }
  async function removeItem(id: string) {
    setItemsBusy(true);
    try {
      await api.comparerItemsRemove(id);
      await refreshItems();
    } catch (e) {
      alert(`Could not remove item: ${e}`);
    } finally {
      setItemsBusy(false);
    }
  }
  async function clearItems() {
    if (items.length === 0) return;
    if (
      !confirm(
        `Clear all ${items.length} Comparer item${items.length === 1 ? "" : "s"}? The current left/right text stays.`,
      )
    )
      return;
    setItemsBusy(true);
    try {
      await api.comparerItemsClear();
      setItems([]);
    } catch (e) {
      alert(`Could not clear items: ${e}`);
    } finally {
      setItemsBusy(false);
    }
  }
  function loadItemInto(side: "left" | "right", item: ComparerItem) {
    if (side === "left") setLeft(item.text);
    else setRight(item.text);
    setLabel(item.label);
  }

  // R260: Apply the search filter against both the derived label
  // (first non-empty line, truncated) and the raw text body. Match
  // is case-insensitive. Empty search is a pass-through so the full
  // list stays visible — the count badge in the toolbar switches
  // from "N items" to "F / N items" once a search is active, so
  // operators always see both the matched and total counts.
  const filteredItems = useMemo(() => {
    const q = itemsSearch.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (it) =>
        it.label.toLowerCase().includes(q) ||
        it.text.toLowerCase().includes(q),
    );
  }, [items, itemsSearch]);

  // Listen for the comparer-load event so other panels (Repeater, Scanner,
  // HTTP history) can push a text pair here with one click.
  useEffect(() => {
    const onLoad = (e: Event) => {
      const detail = (e as CustomEvent<ComparerLoadDetail>).detail;
      if (!detail) return;
      setLeft(detail.left ?? "");
      setRight(detail.right ?? "");
      setLabel(detail.label ?? null);
    };
    window.addEventListener("burpfree:comparer-load", onLoad as EventListener);
    return () =>
      window.removeEventListener("burpfree:comparer-load", onLoad as EventListener);
  }, []);

  // R391: Alt+S swaps the left and right slots — keyboard version
  // of the "⇄ Swap" toolbar button. Operators coming here via
  // Send-to-Comparer (R319 Target, R299 Scanner, R309 History)
  // sometimes realize the wrong side was pushed into the "left"
  // vs "right" slot — rather than two Send-to-Comparer rounds to
  // overwrite, the swap gets the right ordering in one keystroke.
  // Common enough to deserve a one-key shortcut. **Letter choice**
  // S = Swap; plain Alt+S (no Ctrl/Shift/Meta) sits in the "Alt +
  // single letter" panel-scoped family that Repeater (Alt+W/N/P)
  // uses. Doesn't collide with the browser's native Ctrl+S save
  // because we require Alt without Ctrl. **Mechanism** mirrors
  // the button exactly: capture `left` into a temp, call
  // `setLeft(right)`, then `setRight(prevLeft)`. React batches
  // the two setters so the diff memo sees a consistent state.
  // **Guards** plain Alt only, text-input focus skip so Alt+S
  // inside a textarea doesn't trigger (operators often tweak
  // sides mid-edit). **No-op** when both sides empty — nothing
  // to swap.
  useEffect(() => {
    function onSwapKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "s" && e.key !== "S") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!left && !right) return;
      e.preventDefault();
      const prevLeft = left;
      setLeft(right);
      setRight(prevLeft);
    }
    document.addEventListener("keydown", onSwapKey);
    return () => document.removeEventListener("keydown", onSwapKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [left, right]);

  // R474: Alt+Shift+C clears both slots + the stashed items collection
  // in one keystroke — comprehensive comparer reset. Extends the
  // Alt+Shift+C clear-results family to a seventh panel: R418 Intruder
  // / R435 Sequencer / R446 Logger / R447 Collaborator / R448 BChecks /
  // R450 CookieJar / R474 Comparer. The deliberate separation stays
  // consistent across panels: Alt+C handles filter-only resets (none
  // exists in Comparer today), Alt+Shift+C handles the destructive
  // workspace reset. **Mechanism** reuses the existing `clearItems()`
  // function for the stashed collection (so the confirm dialog +
  // backend `comparer_items_clear` call fire exactly like the
  // "⚠ Clear items" button does), then wipes `left` / `right` / the
  // label in the same tick so React batches the three setters. The
  // confirm from `clearItems()` already gates the destructive action
  // when items.length > 0; if items is empty, we still fire the
  // slot wipe synchronously since those don't need confirm. **Guards**
  // Alt+Shift only (no Ctrl/Meta so Ctrl+Shift+C DevTools muscle
  // memory stays untouched), text-input focus skip (Comparer's
  // textareas are the primary workspace). **Short-circuit** when
  // everything is already empty — stray keystroke on a fresh panel
  // is a silent no-op.
  useEffect(() => {
    function onClearAllKey(e: KeyboardEvent) {
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
      if (!left && !right && items.length === 0) return;
      e.preventDefault();
      // Items clear path has its own confirm; slot wipe is unconditional
      // after the items path resolves (or immediately if items empty).
      void (async () => {
        if (items.length > 0) {
          await clearItems();
        }
        setLeft("");
        setRight("");
        setLabel(null);
      })();
    }
    document.addEventListener("keydown", onClearAllKey);
    return () => document.removeEventListener("keydown", onClearAllKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [left, right, items.length]);

  useEffect(() => {
    // Byte mode is a browser-side view — don't bother the backend. We
    // also clear the previous line/word report so stale "similarity 60%"
    // from a line diff doesn't bleed through into the byte toolbar.
    if (mode === "byte") {
      setDiff(null);
      setJsonDiff(null);
      return;
    }
    if (mode === "json") {
      setDiff(null);
      api
        .comparerDiffJson(left, right)
        .then(setJsonDiff)
        .catch(() => setJsonDiff(null));
      return;
    }
    setJsonDiff(null);
    api
      .comparerDiff(left, right, ignoreWs, mode)
      .then(setDiff)
      .catch(() => setDiff(null));
  }, [left, right, ignoreWs, mode]);

  // Byte-mode derived values — computed only when the operator is on
  // this view so switching back to line/word is instant.
  const bytesView = useMemo(() => {
    if (mode !== "byte") return null;
    const lb = toBytes(left);
    const rb = toBytes(right);
    const rows = buildRows(lb, rb);
    let matches = 0;
    let compared = 0;
    const minLen = Math.min(lb.length, rb.length);
    for (let i = 0; i < minLen; i++) {
      compared++;
      if (lb[i] === rb[i]) matches++;
    }
    // Treat the length-mismatch tail as "different" for the similarity
    // ratio — otherwise a prefix match of two very different-length
    // payloads reports 100% similar.
    const totalForRatio = Math.max(lb.length, rb.length);
    const similarity = totalForRatio === 0 ? 1 : matches / totalForRatio;
    return { lb, rb, rows, similarity, matches, compared };
  }, [mode, left, right]);

  const leftTotal =
    mode === "byte"
      ? bytesView?.lb.length ?? 0
      : mode === "json"
        ? jsonDiff?.left_total ?? 0
        : diff?.lines.filter((l) => l.op !== "insert").length ?? 0;
  const rightTotal =
    mode === "byte"
      ? bytesView?.rb.length ?? 0
      : mode === "json"
        ? jsonDiff?.right_total ?? 0
        : diff?.lines.filter((l) => l.op !== "delete").length ?? 0;
  const unitLabel =
    mode === "byte"
      ? "bytes"
      : mode === "word"
        ? "tokens"
        : mode === "json"
          ? "leaves"
          : "lines";
  const similarityPct =
    mode === "byte"
      ? bytesView
        ? bytesView.similarity * 100
        : null
      : mode === "json"
        ? jsonDiff && !jsonDiff.parse_error_left && !jsonDiff.parse_error_right
          ? jsonDiff.similarity * 100
          : null
        : diff
          ? diff.similarity * 100
          : null;

  return (
    <div className="panel">
      <div className="toolbar">
        <span>Comparer</span>
        <button
          className={mode === "line" ? "primary" : ""}
          onClick={() => setMode("line")}
        >
          Line
        </button>
        <button
          className={mode === "word" ? "primary" : ""}
          onClick={() => setMode("word")}
        >
          Word
        </button>
        <button
          className={mode === "byte" ? "primary" : ""}
          onClick={() => setMode("byte")}
          title="Byte-level hex dump for binary payloads (gzip, protobuf, raw bytes)"
        >
          Byte
        </button>
        <button
          className={mode === "json" ? "primary" : ""}
          onClick={() => setMode("json")}
          title="Structural JSON diff: parses both sides and surfaces per-path Added / Removed / Changed rows"
        >
          JSON
        </button>
        <div className="sep" />
        <button
          className="ghost"
          onClick={() => {
            // Atomic swap — React batches both setters so a stale
            // closure can't half-swap when the diff memo recomputes.
            const prevLeft = left;
            setLeft(right);
            setRight(prevLeft);
          }}
          disabled={!left && !right}
          title="Swap the left and right texts. Useful after a Send-to-Comparer loaded the wrong side."
        >
          ⇄ Swap
        </button>
        {/* ------------------------------------------------------- */}
        {/* R120: Load Left / Load Right from file. Burp's Comparer */}
        {/* lets you load either slot from disk. Operators who want */}
        {/* to diff two captured JSONs or two reference HTML dumps  */}
        {/* can skip the paste-via-editor step. Each button triggers */}
        {/* its own hidden `<input type="file">` so Left + Right can */}
        {/* be loaded independently without stomping each other.    */}
        <input
          ref={leftFileRef}
          type="file"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 10 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Comparer caps at 10 MB (line/word diff is quadratic). Pre-slice before loading.`,
              );
              return;
            }
            if (left.trim().length > 0 && !confirm(`Replace Left with ${file.name}?`))
              return;
            try {
              setLeft(await file.text());
            } catch (err) {
              alert(`Load Left failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => leftFileRef.current?.click()}
          title="Load Left slot from a file (UTF-8, 10 MB cap). Confirms before overwriting non-empty content."
        >
          ⬆ Left
        </button>
        <input
          ref={rightFileRef}
          type="file"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 10 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Comparer caps at 10 MB (line/word diff is quadratic). Pre-slice before loading.`,
              );
              return;
            }
            if (right.trim().length > 0 && !confirm(`Replace Right with ${file.name}?`))
              return;
            try {
              setRight(await file.text());
            } catch (err) {
              alert(`Load Right failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => rightFileRef.current?.click()}
          title="Load Right slot from a file (UTF-8, 10 MB cap). Confirms before overwriting non-empty content."
        >
          ⬆ Right
        </button>
        {/* R143: Clear both. Burp's Comparer has a Clear button    */}
        {/* that drops both slots at once — operators who've been    */}
        {/* diffing a chain want a quick reset between rounds        */}
        {/* without hand-emptying each textarea.                      */}
        <button
          className="ghost"
          disabled={!left && !right}
          onClick={() => {
            if (!confirm(`Clear both slots (${left.length}+${right.length} chars)?`)) return;
            setLeft("");
            setRight("");
            setLabel(null);
          }}
          title={
            !left && !right
              ? "Both slots are empty"
              : `Drop ${left.length}+${right.length} chars from Left/Right`
          }
        >
          ⌫ Clear
        </button>
        {/* ------------------------------------------------------- */}
        {/* R157: Copy diff — emits a unified-diff text block        */}
        {/* (space/-/+ prefixes, no @@ hunk headers) suitable for    */}
        {/* pasting into tickets, PR comments, chat. Only lights up  */}
        {/* in Line / Word mode because Byte is a hex dump + JSON   */}
        {/* is a structural table (both have their own text         */}
        {/* representations the operator can copy via browser       */}
        {/* select+copy). Writes to clipboard via navigator; silent  */}
        {/* fail with an alert on error.                             */}
        <button
          className="ghost"
          disabled={
            mode === "byte" ||
            mode === "json" ||
            !diff ||
            diff.lines.length === 0
          }
          onClick={async () => {
            if (!diff || diff.lines.length === 0) return;
            const text = diff.lines
              .map((l) => {
                const prefix =
                  l.op === "insert" ? "+" : l.op === "delete" ? "-" : " ";
                return `${prefix} ${l.text}`;
              })
              .join("\n");
            try {
              await navigator.clipboard.writeText(text);
            } catch (e) {
              alert(`Copy failed: ${e}`);
            }
          }}
          title={
            mode === "byte" || mode === "json"
              ? `Copy diff is a Line / Word mode affordance — ${mode} mode has its own representation`
              : !diff || diff.lines.length === 0
                ? "No diff yet"
                : `Copy ${diff.lines.length} diff line${diff.lines.length === 1 ? "" : "s"} to clipboard (unified-diff style: space / - / + prefixes)`
          }
        >
          ⎘ Copy diff
        </button>
        {/* ------------------------------------------------------- */}
        {/* R198: Save diff — writes the same unified-diff block     */}
        {/* R157 emits to clipboard, but to a `.diff` file via a    */}
        {/* programmatic anchor download. Great for ticket evidence,*/}
        {/* long diffs that overflow the clipboard, teammate hand-  */}
        {/* off ("here's the exact byte-level change"). Same enable */}
        {/* gating as Copy diff: Line / Word mode only; byte + JSON */}
        {/* have their own representations. File name includes an   */}
        {/* ISO-ish timestamp like other exports (CSV, JSONL).      */}
        <button
          className="ghost"
          disabled={
            mode === "byte" ||
            mode === "json" ||
            !diff ||
            diff.lines.length === 0
          }
          onClick={() => {
            if (!diff || diff.lines.length === 0) return;
            const text = diff.lines
              .map((l) => {
                const prefix =
                  l.op === "insert" ? "+" : l.op === "delete" ? "-" : " ";
                return `${prefix} ${l.text}`;
              })
              .join("\n");
            const blob = new Blob([text], {
              type: "text/x-diff;charset=utf-8",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `burpfree-diff-${new Date()
              .toISOString()
              .replace(/[:.]/g, "-")}.diff`;
            a.click();
            URL.revokeObjectURL(url);
          }}
          title={
            mode === "byte" || mode === "json"
              ? `Save diff is a Line / Word mode affordance — ${mode} mode has its own representation`
              : !diff || diff.lines.length === 0
                ? "No diff yet"
                : `Save ${diff.lines.length} diff line${diff.lines.length === 1 ? "" : "s"} as a .diff file (unified-diff style: space / - / + prefixes)`
          }
        >
          ⬇ Save diff
        </button>
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            opacity: mode === "byte" || mode === "json" ? 0.4 : 1,
          }}
          title={
            mode === "byte" || mode === "json"
              ? "Whitespace handling only applies in Line / Word mode"
              : "Collapse multiple spaces + ignore trailing whitespace when diffing"
          }
        >
          <input
            type="checkbox"
            checked={ignoreWs}
            disabled={mode === "byte" || mode === "json"}
            onChange={(e) => setIgnoreWs(e.target.checked)}
          />
          Ignore whitespace
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        {label && (
          <span className="badge" title={label}>
            {label}
          </span>
        )}
        {similarityPct !== null && (
          <span className="badge">similarity {similarityPct.toFixed(1)}%</span>
        )}
        <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
          {leftTotal} ↔ {rightTotal} {unitLabel}
        </span>
      </div>
      <div
        style={{
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-raised)",
          padding: "4px 10px",
          display: "flex",
          flexDirection: "column",
          gap: 4,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <button
            className="ghost"
            style={{ fontSize: 11, padding: "2px 8px" }}
            onClick={() => setItemsExpanded((v) => !v)}
            title={
              itemsExpanded
                ? "Collapse the Items collection"
                : "Expand the Items collection"
            }
          >
            {itemsExpanded ? "▾" : "▸"} Items
          </button>
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
            {items.length === 0
              ? "(no stashed items — persisted across restarts)"
              : itemsSearch.trim()
                ? `${filteredItems.length} / ${items.length} item${items.length === 1 ? "" : "s"}`
                : `${items.length} item${items.length === 1 ? "" : "s"}`}
          </span>
          {items.length > 0 && (
            <input
              type="text"
              value={itemsSearch}
              onChange={(e) => setItemsSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape" && itemsSearch) {
                  e.preventDefault();
                  e.stopPropagation();
                  setItemsSearch("");
                }
              }}
              placeholder="Filter items…"
              title="Case-insensitive substring match on label + text. Esc clears."
              style={{
                fontSize: 11,
                padding: "2px 6px",
                width: 140,
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                color: "var(--text)",
              }}
            />
          )}
          <span className="spacer" style={{ flex: 1 }} />
          <button
            onClick={() => void stashItem("left")}
            disabled={itemsBusy || !left.trim()}
            title="Add the current left-hand text as a new numbered item"
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            ← Stash left
          </button>
          <button
            onClick={() => void stashItem("right")}
            disabled={itemsBusy || !right.trim()}
            title="Add the current right-hand text as a new numbered item"
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            Stash right →
          </button>
          <button
            onClick={() => void stashPaste()}
            disabled={itemsBusy}
            title="Add a new item from the clipboard"
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            + Paste
          </button>
          <button
            className="danger"
            onClick={() => void clearItems()}
            disabled={itemsBusy || items.length === 0}
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            Clear all
          </button>
          {/* R649: Comparer "📋 Copy items JSON" — 8th entry in
              cross-panel Copy-as-JSON family (History R605 /
              Scanner R606 / Intruder R607 / Target R611 /
              Collaborator R612 / Decoder R647 / Sequencer R648 /
              Comparer R649). Operators sharing their stash with
              a teammate ("compare these 10 payloads") want the
              JSON on the clipboard. Preserves every ComparerItem
              field (id, label, text, created_at_ms). */}
          {items.length > 0 && (
            <button
              onClick={() =>
                void copyToClipboard(JSON.stringify(items, null, 2))
              }
              title={`Copy ${items.length} Comparer item${items.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed). Great for sharing a stash with a teammate or restoring in a sibling session.`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              📋 JSON
            </button>
          )}
        </div>
        {itemsExpanded && items.length > 0 && (
          <div style={{ maxHeight: 160, overflow: "auto" }}>
            {filteredItems.length === 0 && (
              <div
                className="empty"
                style={{
                  fontSize: 11,
                  padding: "6px 10px",
                  color: "var(--text-dim)",
                }}
              >
                No items match "{itemsSearch}" — Esc to clear the filter.
              </div>
            )}
            <table className="mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <tbody>
                {filteredItems.map((it) => {
                  // Preserve the original 1-based position so a
                  // filtered view keeps the stable numbering operators
                  // see when scrubbing the full list.
                  const originalIdx = items.findIndex((x) => x.id === it.id);
                  return (
                  <tr
                    key={it.id}
                    title={it.text.slice(0, 400)}
                    onContextMenu={(evt) => {
                      evt.preventDefault();
                      setItemMenu({ x: evt.clientX, y: evt.clientY, data: it });
                    }}
                    style={{ cursor: "context-menu" }}
                  >
                    <td style={{ width: 28, color: "var(--text-faint)", textAlign: "right", paddingRight: 6 }}>
                      {originalIdx + 1}.
                    </td>
                    <td
                      style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        maxWidth: 420,
                      }}
                    >
                      {it.label}
                    </td>
                    <td style={{ width: 70, color: "var(--text-faint)", fontSize: 10, textAlign: "right", paddingRight: 6 }}>
                      {it.text.length.toLocaleString()} B
                    </td>
                    <td style={{ width: 70, color: "var(--text-faint)", fontSize: 10, textAlign: "right", paddingRight: 6 }}>
                      {relativeAge(it.created_at_ms)}
                    </td>
                    <td style={{ width: 220, textAlign: "right", whiteSpace: "nowrap" }}>
                      <button
                        className="ghost"
                        onClick={() => loadItemInto("left", it)}
                        title="Load this item into the left-hand side"
                        style={{ fontSize: 10, padding: "0 6px" }}
                      >
                        ← Left
                      </button>
                      <button
                        className="ghost"
                        onClick={() => loadItemInto("right", it)}
                        title="Load this item into the right-hand side"
                        style={{ fontSize: 10, padding: "0 6px" }}
                      >
                        Right →
                      </button>
                      <button
                        className="ghost danger"
                        onClick={() => void removeItem(it.id)}
                        disabled={itemsBusy}
                        title="Delete this item"
                        style={{ fontSize: 10, padding: "0 6px" }}
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {/* R837: Burp Comparer-style pane headers above each slot.
          Burp's real Comparer wraps each item slot (Item 1 / Item 2)
          with a header strip showing the slot label, line + char
          counts, and compact per-slot actions (clear this slot,
          copy to clipboard). Our previous layout had bare textareas
          with just a placeholder — operators had no at-a-glance
          read of "how big is this side" and no way to clear or
          copy a single slot without going to the shared ⌫ Clear /
          ⇄ Swap toolbar entries. **Layout** two-column grid with
          each column being a flex-column of `{header, textarea}`,
          header locked to a 24px row so the two slots stay
          vertically aligned. **Counts** derived inline from `left`
          / `right` state (char + line count) so they reconcile on
          every keystroke. Byte counts available via the hex-dump
          view already — kept the header lean. */}
      <div
        className="compare-slots"
        style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, flex: 0 }}
      >
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div className="compare-slot-head">
            <span className="compare-slot-label">Item 1</span>
            <span className="compare-slot-stats mono">
              {left.length.toLocaleString()} ch · {left.split(/\r?\n/).length} ln
            </span>
            <span style={{ flex: 1 }} />
            <button
              type="button"
              className="compare-slot-btn"
              disabled={left.length === 0}
              onClick={() => void copyToClipboard(left).catch(() => {})}
              title="Copy Item 1 to clipboard"
            >
              📋
            </button>
            <button
              type="button"
              className="compare-slot-btn"
              disabled={left.length === 0}
              onClick={() => {
                if (
                  left.length > 50 &&
                  !confirm(`Clear Item 1 (${left.length} chars)?`)
                )
                  return;
                setLeft("");
              }}
              title="Clear Item 1 (asks when >50 chars)"
            >
              ⌫
            </button>
          </div>
          <textarea
            value={left}
            onChange={(e) => setLeft(e.target.value)}
            style={{ height: 160 }}
            placeholder="Item 1 — paste or load the left-hand sample"
          />
        </div>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div className="compare-slot-head">
            <span className="compare-slot-label">Item 2</span>
            <span className="compare-slot-stats mono">
              {right.length.toLocaleString()} ch · {right.split(/\r?\n/).length} ln
            </span>
            <span style={{ flex: 1 }} />
            <button
              type="button"
              className="compare-slot-btn"
              disabled={right.length === 0}
              onClick={() => void copyToClipboard(right).catch(() => {})}
              title="Copy Item 2 to clipboard"
            >
              📋
            </button>
            <button
              type="button"
              className="compare-slot-btn"
              disabled={right.length === 0}
              onClick={() => {
                if (
                  right.length > 50 &&
                  !confirm(`Clear Item 2 (${right.length} chars)?`)
                )
                  return;
                setRight("");
              }}
              title="Clear Item 2 (asks when >50 chars)"
            >
              ⌫
            </button>
          </div>
          <textarea
            value={right}
            onChange={(e) => setRight(e.target.value)}
            style={{ height: 160 }}
            placeholder="Item 2 — paste or load the right-hand sample"
          />
        </div>
      </div>
      <div style={{ padding: 10, overflow: "auto", flex: 1, background: "var(--bg)" }}>
        {mode === "byte" ? (
          bytesView && <ByteDiffView view={bytesView} />
        ) : mode === "json" ? (
          <JsonDiffView report={jsonDiff} />
        ) : (
            <table className="mono compare-diff-table" style={{ width: "100%", borderCollapse: "collapse" }}>
              {/* R874: Burp-identical Comparer diff header + hover
                  tint. Burp Suite 2026.8's diff pane carries a
                  minimal column-header strip ("L" / "R" / "Diff")
                  so operators scanning a long diff can tell left/
                  right line numbers apart; ours previously had bare
                  tbody rows. Also added `.compare-diff-table` class
                  so a hover-tint CSS rule can highlight the current
                  row for easier reading. */}
              <thead>
                <tr>
                  <th
                    style={{
                      width: 40,
                      color: "var(--text-faint)",
                      fontSize: 10,
                      textAlign: "right",
                      padding: "2px 6px",
                      textTransform: "uppercase",
                      letterSpacing: 0.3,
                      borderBottom: "1px solid var(--border)",
                    }}
                    title="Item 1 (left) line number"
                  >
                    L
                  </th>
                  <th
                    style={{
                      width: 40,
                      color: "var(--text-faint)",
                      fontSize: 10,
                      textAlign: "right",
                      padding: "2px 6px",
                      textTransform: "uppercase",
                      letterSpacing: 0.3,
                      borderBottom: "1px solid var(--border)",
                    }}
                    title="Item 2 (right) line number"
                  >
                    R
                  </th>
                  <th
                    style={{
                      color: "var(--text-faint)",
                      fontSize: 10,
                      textAlign: "left",
                      padding: "2px 6px",
                      textTransform: "uppercase",
                      letterSpacing: 0.3,
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    Diff
                  </th>
                </tr>
              </thead>
              <tbody>
                {diff?.lines.map((l, i) => (
                  <tr key={i}>
                    <td
                      style={{
                        width: 40,
                        color: "var(--text-dim)",
                        padding: "2px 6px",
                        textAlign: "right",
                      }}
                    >
                      {l.left_line ?? ""}
                    </td>
                    <td
                      style={{
                        width: 40,
                        color: "var(--text-dim)",
                        padding: "2px 6px",
                        textAlign: "right",
                      }}
                    >
                      {l.right_line ?? ""}
                    </td>
                    <td
                      style={{
                        background:
                          l.op === "insert"
                            ? "rgba(75,191,107,0.1)"
                            : l.op === "delete"
                              ? "rgba(239,75,75,0.1)"
                              : "transparent",
                        padding: "2px 6px",
                      }}
                    >
                      <span style={{ marginRight: 6 }}>
                        {l.op === "equal" ? " " : l.op === "insert" ? "+" : "-"}
                      </span>
                      {l.text}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div>
      {/* R489: FloatingMenu for Comparer item row right-click.      */}
      {/* Lives at the panel's root level so the menu floats above   */}
      {/* every other UI element. Menu entries read from the full   */}
      {/* ComparerItem (`itemMenu.data`) and run clipboard-only      */}
      {/* operations + the existing loadItemInto / removeItem helpers*/}
      {/* for slot moves + per-row delete. Mirrors R487 BChecks +   */}
      {/* R488 Collaborator scaffold pattern.                          */}
      <FloatingMenu
        state={itemMenu}
        onClose={() => setItemMenu(null)}
        items={
          itemMenu?.data
            ? (() => {
                const it = itemMenu.data!;
                return [
                  {
                    label: "Load into left",
                    hint: `← slot gets this item's ${it.text.length} chars`,
                    onClick: () => loadItemInto("left", it),
                  },
                  {
                    label: "Load into right",
                    hint: `→ slot gets this item's ${it.text.length} chars`,
                    onClick: () => loadItemInto("right", it),
                  },
                  { separator: true },
                  {
                    label: "Copy text",
                    hint: `${it.text.length} char${it.text.length === 1 ? "" : "s"}`,
                    onClick: () => void copyToClipboard(it.text),
                  },
                  {
                    label: `Copy label: ${it.label.length > 32 ? it.label.slice(0, 32) + "…" : it.label}`,
                    onClick: () => void copyToClipboard(it.label),
                  },
                  {
                    label: "Copy as JSON",
                    hint: "clipboard · raw record",
                    onClick: () =>
                      void copyToClipboard(JSON.stringify(it, null, 2)),
                  },
                  { separator: true },
                  {
                    label: `Captured ${relativeAge(it.created_at_ms)}`,
                    disabled: true,
                  },
                  { separator: true },
                  {
                    label: "Delete this item",
                    danger: true,
                    disabled: itemsBusy,
                    onClick: () => void removeItem(it.id),
                  },
                ];
              })()
            : []
        }
      />
    </div>
  );
}

/** Compact stringifier for inline cell values — sorted-keyed JSON
 *  so output is deterministic even when the backend hasn't normalised
 *  key order; trims to `max` chars with an ellipsis. */
function formatVal(v: unknown, max = 60): string {
  if (v === null || v === undefined) return "—";
  let s: string;
  try {
    s = JSON.stringify(v, (_k, val) => {
      if (val && typeof val === "object" && !Array.isArray(val)) {
        const sorted: Record<string, unknown> = {};
        for (const key of Object.keys(val as Record<string, unknown>).sort()) {
          sorted[key] = (val as Record<string, unknown>)[key];
        }
        return sorted;
      }
      return val;
    });
  } catch {
    s = String(v);
  }
  return s.length > max ? s.slice(0, max) + "…" : s;
}

/** Structural JSON diff table: path + left + right + kind, color-
 *  coded by kind. Parse errors render a red banner instead of the
 *  table so the operator knows which pane needs fixing. */
function JsonDiffView({ report }: { report: JsonDiffReport | null }) {
  if (!report) {
    return <div className="empty">Analysing…</div>;
  }
  if (report.parse_error_left || report.parse_error_right) {
    return (
      <div
        style={{
          padding: 12,
          background: "rgba(239,75,75,0.12)",
          border: "1px solid rgba(239,75,75,0.5)",
          borderRadius: 6,
          color: "var(--text)",
          fontSize: 12,
          lineHeight: 1.6,
        }}
      >
        <div style={{ fontWeight: 600, marginBottom: 6 }}>
          JSON parse error — switch to Line mode or fix the input:
        </div>
        {report.parse_error_left && (
          <div className="mono">
            <strong>LEFT:</strong> {report.parse_error_left}
          </div>
        )}
        {report.parse_error_right && (
          <div className="mono">
            <strong>RIGHT:</strong> {report.parse_error_right}
          </div>
        )}
      </div>
    );
  }
  if (report.entries.length === 0) {
    return <div className="empty">Both sides are empty JSON.</div>;
  }
  const kindMeta: Record<
    JsonDiffEntry["kind"],
    { glyph: string; label: string; color: string }
  > = {
    added: { glyph: "+", label: "Added", color: "rgba(75,191,107,0.9)" },
    removed: { glyph: "−", label: "Removed", color: "rgba(239,75,75,0.9)" },
    changed: { glyph: "≠", label: "Changed", color: "rgba(255,170,60,0.9)" },
    same: { glyph: "=", label: "Same", color: "var(--text-dim)" },
  };
  // Count by kind so the header can show the actual drift at a glance.
  const counts = report.entries.reduce<Record<string, number>>((acc, e) => {
    acc[e.kind] = (acc[e.kind] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div>
      <div
        style={{
          display: "flex",
          gap: 10,
          flexWrap: "wrap",
          padding: "4px 0 10px",
          color: "var(--text-dim)",
          fontSize: 11,
        }}
      >
        {(["added", "removed", "changed", "same"] as const).map((k) => (
          <span key={k}>
            <span
              style={{
                color: kindMeta[k].color,
                marginRight: 3,
                fontWeight: 700,
              }}
            >
              {kindMeta[k].glyph}
            </span>
            {kindMeta[k].label}: {counts[k] ?? 0}
          </span>
        ))}
        {report.truncated && (
          <span style={{ color: "rgba(239,75,75,0.9)" }}>
            truncated at {report.entries.length} entries
          </span>
        )}
      </div>
      <table className="mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <colgroup>
          <col style={{ width: 28 }} />
          <col style={{ width: "32%" }} />
          <col />
          <col />
        </colgroup>
        <thead>
          <tr style={{ color: "var(--text-dim)", textAlign: "left" }}>
            <th style={{ padding: "2px 6px" }}></th>
            <th style={{ padding: "2px 6px" }}>Path</th>
            <th style={{ padding: "2px 6px" }}>Left</th>
            <th style={{ padding: "2px 6px" }}>Right</th>
          </tr>
        </thead>
        <tbody>
          {report.entries.map((e, i) => {
            const meta = kindMeta[e.kind];
            // Dim container rows (where left/right are both null and
            // kind is same) so leaves pop visually.
            const isContainerSame =
              e.kind === "same" && e.left == null && e.right == null;
            return (
              <tr
                key={i}
                style={{
                  background:
                    e.kind === "added"
                      ? "rgba(75,191,107,0.08)"
                      : e.kind === "removed"
                        ? "rgba(239,75,75,0.08)"
                        : e.kind === "changed"
                          ? "rgba(255,170,60,0.08)"
                          : "transparent",
                  opacity: isContainerSame ? 0.5 : 1,
                }}
              >
                <td
                  style={{
                    padding: "2px 6px",
                    color: meta.color,
                    fontWeight: 700,
                    textAlign: "center",
                  }}
                  title={meta.label}
                >
                  {meta.glyph}
                </td>
                <td style={{ padding: "2px 6px", color: "var(--text)" }}>
                  {e.path}
                </td>
                <td
                  style={{ padding: "2px 6px", color: "var(--text-dim)" }}
                  title={e.left == null ? "" : JSON.stringify(e.left)}
                >
                  {formatVal(e.left)}
                </td>
                <td
                  style={{ padding: "2px 6px", color: "var(--text-dim)" }}
                  title={e.right == null ? "" : JSON.stringify(e.right)}
                >
                  {formatVal(e.right)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Side-by-side hex dump with per-byte diff highlighting. */
function ByteDiffView({
  view,
}: {
  view: {
    lb: Uint8Array;
    rb: Uint8Array;
    rows: ByteRow[];
    similarity: number;
    matches: number;
    compared: number;
  };
}) {
  if (view.rows.length === 0) {
    return <div className="empty">Both sides are empty.</div>;
  }
  const { lb, rb } = view;
  return (
    <div style={{ fontSize: 11.5, lineHeight: 1.5 }}>
      <table
        className="mono"
        style={{ width: "100%", borderCollapse: "collapse", whiteSpace: "pre" }}
      >
        <thead>
          <tr style={{ color: "var(--text-dim)" }}>
            <th style={{ textAlign: "right", padding: "2px 10px" }}>offset</th>
            <th style={{ textAlign: "left", padding: "2px 10px" }}>left (hex)</th>
            <th style={{ textAlign: "left", padding: "2px 6px" }}>left (ascii)</th>
            <th style={{ textAlign: "left", padding: "2px 10px" }}>right (hex)</th>
            <th style={{ textAlign: "left", padding: "2px 6px" }}>right (ascii)</th>
          </tr>
        </thead>
        <tbody>
          {view.rows.map((row) => (
            <ByteRowView key={row.offset} row={row} />
          ))}
        </tbody>
      </table>
      <div
        style={{
          marginTop: 10,
          color: "var(--text-dim)",
          fontSize: 11,
          display: "flex",
          gap: 14,
          flexWrap: "wrap",
        }}
      >
        <span>
          left: <span className="mono">{lb.length}</span>B
        </span>
        <span>
          right: <span className="mono">{rb.length}</span>B
        </span>
        <span>
          matched: <span className="mono">{view.matches}</span>/{view.compared}
        </span>
        {lb.length !== rb.length && (
          <span style={{ color: "var(--amber)" }}>
            length mismatch: Δ {Math.abs(lb.length - rb.length)}B
          </span>
        )}
      </div>
    </div>
  );
}

function ByteRowView({ row }: { row: ByteRow }) {
  return (
    <tr>
      <td
        className="mono"
        style={{
          textAlign: "right",
          padding: "1px 10px",
          color: "var(--text-dim)",
          verticalAlign: "top",
        }}
      >
        {row.offset.toString(16).padStart(6, "0")}
      </td>
      <td style={{ padding: "1px 10px", verticalAlign: "top" }}>
        <HexBytes bytes={row.left} other={row.right} side="left" />
      </td>
      <td style={{ padding: "1px 6px", verticalAlign: "top" }}>
        <AsciiCells bytes={row.left} other={row.right} side="left" />
      </td>
      <td style={{ padding: "1px 10px", verticalAlign: "top" }}>
        <HexBytes bytes={row.right} other={row.left} side="right" />
      </td>
      <td style={{ padding: "1px 6px", verticalAlign: "top" }}>
        <AsciiCells bytes={row.right} other={row.left} side="right" />
      </td>
    </tr>
  );
}

/** Diff colour for a byte cell. `undefined` means "no counterpart" and
 *  colours the cell amber on the side that has data. */
function cellBg(
  own: number | undefined,
  theirs: number | undefined,
  side: "left" | "right",
): string | undefined {
  if (own === undefined && theirs === undefined) return undefined;
  if (own === undefined) return undefined;
  if (theirs === undefined) return "rgba(240,166,51,0.18)"; // amber — length overrun
  if (own === theirs) return undefined;
  return side === "left" ? "rgba(239,75,75,0.22)" : "rgba(75,191,107,0.22)";
}

function HexBytes({
  bytes,
  other,
  side,
}: {
  bytes: Array<number | undefined>;
  other: Array<number | undefined>;
  side: "left" | "right";
}) {
  return (
    <span className="mono">
      {bytes.map((b, i) => (
        <span
          key={i}
          style={{
            background: cellBg(b, other[i], side),
            padding: "0 2px",
            marginRight: i === 7 ? 6 : 2,
          }}
        >
          {hex2(b)}
        </span>
      ))}
    </span>
  );
}

function AsciiCells({
  bytes,
  other,
  side,
}: {
  bytes: Array<number | undefined>;
  other: Array<number | undefined>;
  side: "left" | "right";
}) {
  return (
    <span className="mono">
      |
      {bytes.map((b, i) => (
        <span key={i} style={{ background: cellBg(b, other[i], side) }}>
          {asciiChar(b)}
        </span>
      ))}
      |
    </span>
  );
}

/** Helper for other panels: dispatch a comparer-load event and set the
 *  current section to `comparer`. The caller is responsible for the
 *  navigate side via its own `setSection`. */
export function sendToComparer(left: string, right: string, label?: string) {
  window.dispatchEvent(
    new CustomEvent("burpfree:comparer-load", {
      detail: { left, right, label },
    }),
  );
}
