// MessageEditor — shared pretty / raw / hex / render editor used by
// Repeater, Proxy Intercept, and anywhere else a wire-format HTTP
// message appears. Extracted from the original Repeater-only
// implementation so the Intercept pane gets the same Ctrl+F search,
// right-click decoder quick-actions, hex view, and sandboxed render
// preview with zero duplication.
//
// Public surface:
//   <MessageEditor label value onChange direction readOnly? onCtrlEnter? />
//
// Everything else (parsers, inspector, formatters) is co-located but
// also exported so other panels can parse a raw message without
// mounting the whole editor.

import { useEffect, useMemo, useRef, useState } from "react";
import { api, Transform } from "./api";
import { FloatingMenu, MenuItem, MenuState } from "./FloatingMenu";

export type EditorMode = "pretty" | "raw" | "hex" | "render";

/** Burp Suite's default "uninteresting headers" set — the stable list
 *  of boilerplate browser headers that modern Chromium / Firefox
 *  attach to every request and that drown out the actually-security-
 *  relevant headers in a wire view. Keys are stored lower-cased so
 *  `isUninterestingHeader` can do case-insensitive matching with a
 *  single `.has()`. The list mirrors
 *  `UserConfig.misc.uninteresting_headers.uninteresting_headers[]`
 *  that Burp's own UserConfig.json carries. Exported so other panels
 *  (HistoryPanel, IntruderPanel, Comparer, etc.) can share one
 *  definition of noise if they want to apply the same filter. */
export const UNINTERESTING_HEADERS: ReadonlySet<string> = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "cache-control",
  "connection",
  "dnt",
  "pragma",
  "priority",
  "sec-ch-ua",
  "sec-ch-ua-arch",
  "sec-ch-ua-bitness",
  "sec-ch-ua-form-factors",
  "sec-ch-ua-full-version",
  "sec-ch-ua-full-version-list",
  "sec-ch-ua-mobile",
  "sec-ch-ua-model",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-wow64",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "upgrade-insecure-requests",
]);

/** Case-insensitive membership test against `UNINTERESTING_HEADERS`.
 *  Returns false for empty / whitespace names so a malformed line
 *  never silently drops. */
export function isUninterestingHeader(name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed) return false;
  return UNINTERESTING_HEADERS.has(trimmed.toLowerCase());
}

/** Group consecutive runs of uninteresting headers into chip
 *  placeholders. When `showUninteresting` is true every header
 *  renders literally. The returned nodes join with newlines inside
 *  a monospace block to match the pre-wire-view look operators
 *  already know; chips are inline `<button>`s styled as dim-italic
 *  text so a click handler can swap in a single-shot reveal. */
function renderPrettyHead(
  startLine: string,
  headers: Array<[string, string]>,
  showAll: boolean,
  onReveal: () => void,
): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  nodes.push(
    <div key="sl" className="rep-head-line">
      {startLine}
    </div>,
  );
  let i = 0;
  while (i < headers.length) {
    const [k, v] = headers[i];
    if (!showAll && isUninterestingHeader(k)) {
      // Collect consecutive uninteresting headers into one chip.
      let j = i;
      while (j < headers.length && isUninterestingHeader(headers[j][0])) {
        j++;
      }
      const run = headers.slice(i, j);
      const title = run.map(([k2, v2]) => `${k2}: ${v2}`).join("\n");
      nodes.push(
        <button
          key={`fold-${i}`}
          type="button"
          onClick={onReveal}
          title={title}
          className="rep-head-fold"
          style={{
            fontStyle: "italic",
            color: "var(--text-dim)",
            background: "transparent",
            border: "1px dashed var(--border)",
            padding: "0 6px",
            margin: "1px 0",
            cursor: "pointer",
            display: "block",
            textAlign: "left",
            width: "100%",
            fontFamily: "inherit",
            fontSize: "inherit",
          }}
        >
          [{run.length} uninteresting header{run.length === 1 ? "" : "s"}
          {" "}hidden · click to show]
        </button>,
      );
      i = j;
    } else {
      nodes.push(
        <div key={`h-${i}`} className="rep-head-line">
          {k}: {v}
        </div>,
      );
      i++;
    }
  }
  return nodes;
}

/** Parsed view of a wire message, used by all three view modes + inspector. */
export type ParsedMsg = {
  startLine: string;
  method?: string;
  path?: string;
  version?: string;
  status?: number;
  reason?: string;
  headers: Array<[string, string]>;
  cookiesSent: Array<[string, string]>;
  cookiesSet: Array<{ name: string; value: string; attrs: Record<string, string> }>;
  queryParams: Array<[string, string]>;
  bodyParams: Array<[string, string]>;
  body: string;
  contentType?: string;
  headRaw: string;
};

export function parseMessage(raw: string, direction: "request" | "response"): ParsedMsg {
  const headerEnd = raw.indexOf("\r\n\r\n");
  const headPart = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
  const body = headerEnd >= 0 ? raw.slice(headerEnd + 4) : "";
  const lines = headPart.split("\r\n");
  const startLine = lines[0] || "";
  const headers: Array<[string, string]> = [];
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i];
    const idx = l.indexOf(":");
    if (idx > 0) headers.push([l.slice(0, idx).trim(), l.slice(idx + 1).trim()]);
  }
  const headerGet = (name: string) =>
    headers.find(([n]) => n.toLowerCase() === name.toLowerCase())?.[1];
  const contentType = headerGet("Content-Type");

  const out: ParsedMsg = {
    startLine,
    headers,
    cookiesSent: [],
    cookiesSet: [],
    queryParams: [],
    bodyParams: [],
    body,
    contentType,
    headRaw: headPart,
  };

  if (direction === "request") {
    const sl = startLine.split(" ");
    out.method = sl[0];
    out.path = sl[1];
    out.version = sl[2];
    // Query params
    if (out.path && out.path.includes("?")) {
      const q = out.path.slice(out.path.indexOf("?") + 1);
      for (const seg of q.split("&")) {
        if (!seg) continue;
        const eq = seg.indexOf("=");
        const k = decodeMaybe(eq >= 0 ? seg.slice(0, eq) : seg);
        const v = eq >= 0 ? decodeMaybe(seg.slice(eq + 1)) : "";
        out.queryParams.push([k, v]);
      }
    }
    // Cookies (single Cookie header, name1=val1; name2=val2)
    const cookie = headerGet("Cookie");
    if (cookie) {
      for (const seg of cookie.split(";")) {
        const trimmed = seg.trim();
        if (!trimmed) continue;
        const eq = trimmed.indexOf("=");
        out.cookiesSent.push([
          eq >= 0 ? trimmed.slice(0, eq) : trimmed,
          eq >= 0 ? trimmed.slice(eq + 1) : "",
        ]);
      }
    }
    // Form body
    if (contentType && contentType.includes("application/x-www-form-urlencoded")) {
      for (const seg of body.split("&")) {
        if (!seg) continue;
        const eq = seg.indexOf("=");
        out.bodyParams.push([
          decodeMaybe(eq >= 0 ? seg.slice(0, eq) : seg),
          eq >= 0 ? decodeMaybe(seg.slice(eq + 1)) : "",
        ]);
      }
    }
  } else {
    const sl = startLine.split(" ");
    out.version = sl[0];
    out.status = Number(sl[1]);
    out.reason = sl.slice(2).join(" ");
    // Each `Set-Cookie: ...` header → parsed cookie row.
    for (const [n, v] of headers) {
      if (n.toLowerCase() === "set-cookie") {
        const parts = v.split(";").map((s) => s.trim());
        const first = parts[0] || "";
        const eq = first.indexOf("=");
        const name = eq >= 0 ? first.slice(0, eq) : first;
        const value = eq >= 0 ? first.slice(eq + 1) : "";
        const attrs: Record<string, string> = {};
        for (const a of parts.slice(1)) {
          const aEq = a.indexOf("=");
          attrs[aEq >= 0 ? a.slice(0, aEq).toLowerCase() : a.toLowerCase()] =
            aEq >= 0 ? a.slice(aEq + 1) : "true";
        }
        out.cookiesSet.push({ name, value, attrs });
      }
    }
  }

  return out;
}

function decodeMaybe(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

/** Pretty-print body based on content-type. Non-structured bodies return raw. */
export function prettyPrint(body: string, contentType?: string): string {
  if (!body) return "";
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("application/json") || ct.includes("+json")) {
    try {
      const v = JSON.parse(body);
      return JSON.stringify(v, null, 2);
    } catch {
      return body;
    }
  }
  if (ct.includes("application/x-www-form-urlencoded")) {
    return body
      .split("&")
      .map((seg) => {
        const eq = seg.indexOf("=");
        const k = decodeMaybe(eq >= 0 ? seg.slice(0, eq) : seg);
        const v = eq >= 0 ? decodeMaybe(seg.slice(eq + 1)) : "";
        return `${k} = ${v}`;
      })
      .join("\n");
  }
  if (ct.includes("text/html") || ct.includes("application/xml") || ct.includes("+xml") || ct.includes("text/xml")) {
    return prettyXmlish(body);
  }
  return body;
}

/** Very small XML/HTML indenter — no real parser, just newlines between tags. */
function prettyXmlish(src: string): string {
  let out = src.replace(/>\s*</g, ">\n<");
  let depth = 0;
  return out
    .split("\n")
    .map((raw) => {
      const line = raw.trim();
      if (!line) return "";
      const isClose = /^<\//.test(line);
      const isSelfOrDecl = /\/>$/.test(line) || /^<[!?]/.test(line);
      const isOpen = /^<[^/!?]/.test(line) && !isSelfOrDecl;
      if (isClose) depth = Math.max(0, depth - 1);
      const indented = "  ".repeat(depth) + line;
      if (isOpen) depth += 1;
      return indented;
    })
    .join("\n");
}

/** Produce an `offset  hex  |ascii|` dump up to a sensible cap. */
export function toHexDump(s: string): string {
  const bytes = new TextEncoder().encode(s);
  const cap = Math.min(bytes.length, 32 * 1024);
  const out: string[] = [];
  for (let i = 0; i < cap; i += 16) {
    const chunk = bytes.subarray(i, Math.min(i + 16, cap));
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(16 * 3 - 1, " ");
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    out.push(`${i.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  if (bytes.length > cap) {
    out.push(`… ${bytes.length - cap} byte(s) truncated`);
  }
  return out.join("\n");
}

/**
 * Render-mode preview for the response pane. Shows:
 *  - HTML inside a `sandbox=""` iframe (scripts, forms, nav all disabled)
 *  - Images inline via a `data:` URL
 *  - Anything else gets a hint explaining why render isn't available.
 *
 * The iframe deliberately uses an empty `sandbox` attribute (not
 * `allow-scripts`) so JavaScript, form submission, same-origin, and
 * popups are all blocked. The content runs in a null origin.
 */
function RenderPreview({
  contentType,
  body,
}: {
  contentType?: string;
  body: string;
}) {
  const type = (contentType || "").toLowerCase().split(";")[0].trim();
  const isHtml = type === "text/html" || type === "application/xhtml+xml";
  const isImage = type.startsWith("image/");
  const isSvg = type === "image/svg+xml";

  if (!body || body.length === 0) {
    return (
      <div className="empty" style={{ padding: 20 }}>
        (empty body)
      </div>
    );
  }

  if (isHtml) {
    return (
      <iframe
        className="rep-render-frame"
        sandbox=""
        srcDoc={body}
        title="Response preview"
      />
    );
  }

  if (isImage) {
    let src: string;
    try {
      if (isSvg) {
        src = `data:image/svg+xml;utf8,${encodeURIComponent(body)}`;
      } else {
        src = `data:${type};base64,${btoa(body)}`;
      }
    } catch {
      return (
        <div className="empty" style={{ padding: 20 }}>
          (image body is not valid base64 / is multi-byte text)
        </div>
      );
    }
    return (
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: 10,
          display: "flex",
          justifyContent: "center",
          alignItems: "flex-start",
          background: "var(--bg)",
        }}
      >
        <img
          src={src}
          alt="response"
          style={{ maxWidth: "100%", imageRendering: "pixelated" }}
        />
      </div>
    );
  }

  return (
    <div className="empty" style={{ padding: 20, lineHeight: 1.6 }}>
      Render preview isn't available for{" "}
      <span className="mono">{type || "(unknown)"}</span>.
      <br />
      Switch to <b>pretty</b>, <b>raw</b>, or <b>hex</b> to inspect this body.
    </div>
  );
}

export function MessageEditor({
  label,
  value,
  onChange,
  direction,
  readOnly,
  onCtrlEnter,
  extraMenuItems,
  extraFootItem,
  onSelectionChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  direction: "request" | "response";
  readOnly?: boolean;
  onCtrlEnter?: () => void;
  /** Extra entries appended to the floating context menu. The host
   *  panel supplies entries that need its own state (e.g. active tab
   *  URL, "Send to Intruder (whole request)"). On a no-selection
   *  right-click the menu shows ONLY these entries; on a selection
   *  right-click they're appended after the decoder transforms. */
  extraMenuItems?: MenuItem[];
  /** R811: Lift selection state up to the host panel so the Inspector
   *  sidebar can render a "Selection" top panel matching Burp Suite
   *  2026.8's exact silhouette. Fires on every selection change with
   *  the current `{start, end, text, direction}`. Host panels that
   *  don't care about selection (Proxy intercept, History detail)
   *  can omit the prop — it's a no-op. */
  onSelectionChange?: (sel: {
    start: number;
    end: number;
    text: string;
    direction: "request" | "response";
  }) => void;
  /** R794: Burp-identical "pane-specific bottom bar extra" slot.
   *  Repeater's response pane uses this to render the environment
   *  selector dropdown next to the search box — matching Burp Suite
   *  2026.8's exact pane bottom bar layout where "anz-corp-dev"
   *  sits between the ← → nav arrows and the "0 highlights" counter.
   *  Rendered after the search input + before the chars/lines
   *  indicators so operators scanning the strip see pane-specific
   *  tooling first then universal counters. */
  extraFootItem?: React.ReactNode;
}) {
  const [mode, setMode] = useState<EditorMode>("raw");
  // Burp "Uninteresting headers" fold — collapses the boilerplate
  // browser noise (sec-ch-ua*, sec-fetch-*, accept-*, priority,
  // upgrade-insecure-requests, etc.) in pretty mode + the inspector
  // sidebar so operators focus on security-relevant headers (auth,
  // cookies, csrf, content-type, custom x-*). Default off = hidden;
  // flipping it reveals everything with the regular rendering.
  const [showUninteresting, setShowUninteresting] = useState(false);
  const [showInspector, setShowInspector] = useState(true);
  // R890: Burp-identical Response pane ⏸ / ■ / ▶ playback icons.
  // Burp Suite 2026.8's Response pane header shows a 3-icon
  // cluster indicating render state: ⏸ pause (freeze current
  // snapshot, don't update on new sends), ■ stop (freeze +
  // visually mark cleared), ▶ live (default — updates every
  // send). Operators who want to compare the current response
  // to the next send without losing context freeze with ⏸ then
  // thaw with ▶. **State** `renderState` is "live" | "paused" |
  // "stopped". **Freeze mechanism** `frozenValue` ref captures
  // `value` prop at freeze time; render uses `effectiveValue =
  // renderState === "live" ? value : frozenValue` so prop
  // updates don't leak through. Only applies to response panes
  // (direction === "response"); request panes stay normal.
  type RenderState = "live" | "paused" | "stopped";
  const [renderState, setRenderState] = useState<RenderState>("live");
  const frozenValueRef = useRef<string | null>(null);
  // Capture-on-freeze: when flipping from "live" to anything else,
  // snapshot the current value. On flip back to "live", clear the
  // snapshot so future renders use the live prop.
  useEffect(() => {
    if (direction !== "response") return;
    if (renderState === "live") {
      frozenValueRef.current = null;
    } else if (frozenValueRef.current === null) {
      frozenValueRef.current = value;
    }
  }, [renderState, direction, value]);
  // What the editor actually renders: the frozen snapshot during
  // pause/stop, the live prop otherwise.
  const effectiveValue =
    direction === "response" && renderState !== "live" && frozenValueRef.current !== null
      ? frozenValueRef.current
      : value;
  // R759: Line-wrap toggle for the raw textarea. Persisted in
  // localStorage so each operator gets their preferred default.
  // Burp Suite's Repeater shows a `↵` line-wrap icon in the pane
  // header that toggles between hard-break (horizontal scroll)
  // and soft-wrap (no horizontal scroll). We ship the same.
  const [wrapLines, setWrapLines] = useState<boolean>(() => {
    try {
      return localStorage.getItem("burpfree.msgeditor.wrap") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("burpfree.msgeditor.wrap", wrapLines ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [wrapLines]);
  // R793: Burp-identical selection byte count + hex offset in the
  // pane bottom bar. Mirrors Burp Suite 2026.8's "Selection: 28
  // (0x1c)" display operators rely on to pin down the exact byte
  // offset of their current selection — critical for binary
  // boundary alignment, splice-size verification, "how many bytes
  // did I highlight?" quick-answers. Tracks `{start, end}` on
  // selection change via `onSelect` + keyboard/mouse events.
  // Pure local state; no persistence (session-scoped like the
  // search overlay).
  const [selectionRange, setSelectionRange] = useState<{
    start: number;
    end: number;
  }>({ start: 0, end: 0 });
  const taRef = useRef<HTMLTextAreaElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  // Selection menu's data captures either a text selection or a bare
  // right-click so the FloatingMenu items builder can render the
  // appropriate entries.
  const [selectionMenu, setSelectionMenu] = useState<MenuState<
    | { kind: "selection"; start: number; end: number; selected: string }
    | { kind: "no-selection" }
  > | null>(null);
  // In-editor Ctrl+F search state. `null` = closed; otherwise the bar
  // is open and renders over the editor. `index` is the active match
  // in `matches`; moving next/prev selects + scrolls to that range.
  const [search, setSearch] = useState<{
    query: string;
    regex: boolean;
    caseSensitive: boolean;
  } | null>(null);

  // Compute all match ranges for the current query against the editor
  // value. Debouncing isn't needed — this runs synchronously on every
  // keystroke of the search box, which is cheap for typical message
  // sizes (<1 MB). Invalid regex returns [].
  const matches = useMemo<Array<[number, number]>>(() => {
    if (!search || !search.query) return [];
    try {
      if (search.regex) {
        const re = new RegExp(search.query, "g" + (search.caseSensitive ? "" : "i"));
        const out: Array<[number, number]> = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(value)) !== null) {
          const end = m.index + m[0].length;
          out.push([m.index, end]);
          if (m.index === re.lastIndex) re.lastIndex++;
        }
        return out;
      } else {
        const hay = search.caseSensitive ? value : value.toLowerCase();
        const needle = search.caseSensitive ? search.query : search.query.toLowerCase();
        const out: Array<[number, number]> = [];
        let i = 0;
        while (true) {
          const idx = hay.indexOf(needle, i);
          if (idx < 0) break;
          out.push([idx, idx + needle.length]);
          i = idx + Math.max(needle.length, 1);
        }
        return out;
      }
    } catch {
      return [];
    }
  }, [search, value]);
  const [matchIndex, setMatchIndex] = useState(0);
  useEffect(() => {
    if (matches.length === 0) {
      setMatchIndex(0);
      return;
    }
    setMatchIndex((i) => (i >= matches.length ? 0 : i));
  }, [matches.length]);

  function jumpToMatch(i: number) {
    const ta = taRef.current;
    if (!ta || matches.length === 0) return;
    const [start, end] = matches[((i % matches.length) + matches.length) % matches.length];
    ta.focus();
    ta.setSelectionRange(start, end);
    const linesBefore = value.slice(0, start).split("\n").length;
    const lineHeight = parseFloat(getComputedStyle(ta).lineHeight || "16") || 16;
    const target = (linesBefore - 2) * lineHeight;
    if (target >= 0) ta.scrollTop = target;
  }

  function openSearch() {
    setSearch((prev) => prev ?? { query: "", regex: false, caseSensitive: false });
    requestAnimationFrame(() => searchInputRef.current?.focus());
  }

  function closeSearch() {
    setSearch(null);
    taRef.current?.focus();
  }

  function nextMatch() {
    if (matches.length === 0) return;
    const next = (matchIndex + 1) % matches.length;
    setMatchIndex(next);
    jumpToMatch(next);
  }

  function prevMatch() {
    if (matches.length === 0) return;
    const next = (matchIndex - 1 + matches.length) % matches.length;
    setMatchIndex(next);
    jumpToMatch(next);
  }

  /** Pretty-print the current selection in place. Auto-detects
   *  format: JSON (JSON.parse ok) → re-stringified with 2-space
   *  indent; XML/HTML (looks tag-shaped) → run through `prettyPrint`
   *  with a synthetic xml content-type; urlencoded (contains `=` and
   *  `&`) → key = value lines. Returns silently with an alert when
   *  the selection doesn't look like anything the formatter can
   *  handle, so a mis-click doesn't nuke the operator's edit. */
  function prettyPrintSelection() {
    if (!selectionMenu?.data || selectionMenu.data.kind !== "selection") return;
    const { start, end, selected } = selectionMenu.data;
    const trimmed = selected.trim();
    if (!trimmed) {
      setSelectionMenu(null);
      return;
    }
    let formatted: string | null = null;
    // 1) JSON — the strictest, so try first.
    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        const parsed = JSON.parse(trimmed);
        formatted = JSON.stringify(parsed, null, 2);
      } catch {
        /* not JSON — fall through */
      }
    }
    // 2) XML / HTML — looks like `<something ...>`.
    if (formatted === null && /^<[^>]+>/.test(trimmed) && trimmed.includes("</")) {
      // Reuse the shared pretty helper with a synthetic XML content-type
      // so the semantics stay bit-identical to Pretty view mode.
      const out = prettyPrint(trimmed, "application/xml");
      // `prettyPrint` returns the input verbatim when nothing matches;
      // only treat it as a success if the output actually changed.
      if (out && out !== trimmed) formatted = out;
    }
    // 3) urlencoded — `a=1&b=2` style.
    if (formatted === null && trimmed.includes("=") && /[&?]/.test(trimmed)) {
      // Drop a leading `?` so paste-from-URL still works.
      const body = trimmed.startsWith("?") ? trimmed.slice(1) : trimmed;
      const out = prettyPrint(body, "application/x-www-form-urlencoded");
      if (out && out !== body) formatted = out;
    }
    if (formatted === null) {
      alert("Pretty-print: couldn't detect JSON / XML / urlencoded in the selection.");
      setSelectionMenu(null);
      return;
    }
    // Splice back in; same strategy as applyTransformToSelection.
    const next = value.slice(0, start) + formatted + value.slice(end);
    onChange(next);
    setSelectionMenu(null);
  }

  async function applyTransformToSelection(op: Transform["op"]) {
    if (!selectionMenu?.data || selectionMenu.data.kind !== "selection") return;
    const { start, end, selected } = selectionMenu.data;
    try {
      const steps = await api.decoderApply(selected, [{ op } as Transform]);
      const last = steps[steps.length - 1];
      if (!last || last.error) {
        alert(`Transform failed: ${last?.error ?? "no output"}`);
        return;
      }
      const next = value.slice(0, start) + last.output + value.slice(end);
      onChange(next);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setSelectionMenu(null);
    }
  }

  // R890: Parse the effective value (frozen snapshot during
  // pause/stop, live prop otherwise). For request panes
  // effectiveValue === value always, so no behavior change.
  const parsed = useMemo(
    () => parseMessage(effectiveValue, direction),
    [effectiveValue, direction],
  );
  // How many boilerplate headers are foldable on this message. Used
  // by the toolbar chip's visibility + its count badge; recomputed
  // whenever the parsed headers change so a header edit re-counts
  // live without an explicit refresh.
  const uninterestingCount = useMemo(
    () => parsed.headers.filter(([k]) => isUninterestingHeader(k)).length,
    [parsed.headers],
  );
  const prettyBody = useMemo(
    () => (mode === "pretty" ? prettyPrint(parsed.body, parsed.contentType) : ""),
    [mode, parsed.body, parsed.contentType]
  );
  // R818: JSON syntax tokenizer for the Pretty body. Operators
  // reading pretty-printed JSON responses want key/string/number/
  // null differentiation at a glance — matches Burp Suite 2026.8's
  // Pretty mode which syntax-highlights JSON. Returns an array of
  // `{text, kind}` tokens that the render step maps to spans.
  // Falls back to a single "plain" token when the content isn't
  // JSON or the string doesn't tokenize cleanly.
  // R835: XML / HTML syntax tokenizer for the Pretty body. Mirror
  // of the JSON tokenizer for structural XML content. Tokens:
  // tag-open (`<name`), tag-close (`</name>`), tag-end-slash (`/>`),
  // attr-name, attr-value (quoted), angle-bracket punctuation,
  // text content. Falls back to null when content isn't XML/HTML.
  const prettyXmlTokens = useMemo(() => {
    if (mode !== "pretty" || !prettyBody) return null;
    const ct = (parsed.contentType || "").toLowerCase();
    const isXml =
      ct.includes("application/xml") ||
      ct.includes("+xml") ||
      ct.includes("text/xml") ||
      ct.includes("text/html");
    if (!isXml) return null;
    const tokens: Array<{ text: string; kind: string }> = [];
    const re =
      /(<\/?[A-Za-z][\w:-]*)|([\s\n]+[A-Za-z][\w:-]*=)|("(?:\\.|[^"\\])*")|(<!--[\s\S]*?-->)|(<\?[\s\S]*?\?>)|(<!\[CDATA\[[\s\S]*?\]\]>)|(\/?>)|([^<"]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(prettyBody)) !== null) {
      if (m[1]) tokens.push({ text: m[1], kind: "tag" });
      else if (m[2]) tokens.push({ text: m[2], kind: "attr" });
      else if (m[3]) tokens.push({ text: m[3], kind: "str" });
      else if (m[4]) tokens.push({ text: m[4], kind: "comment" });
      else if (m[5]) tokens.push({ text: m[5], kind: "pi" });
      else if (m[6]) tokens.push({ text: m[6], kind: "cdata" });
      else if (m[7]) tokens.push({ text: m[7], kind: "tag" });
      else if (m[8]) tokens.push({ text: m[8], kind: "text" });
    }
    return tokens;
  }, [mode, prettyBody, parsed.contentType]);
  const prettyJsonTokens = useMemo(() => {
    if (mode !== "pretty" || !prettyBody) return null;
    const ct = (parsed.contentType || "").toLowerCase();
    if (!ct.includes("application/json") && !ct.includes("+json")) {
      return null;
    }
    // Simple regex tokenizer — not a full JSON parser, but handles
    // valid pretty-printed JSON output from JSON.stringify well
    // enough for colouring. Order matters: keys (quoted + `:`
    // suffix) before plain strings, then numbers, keywords.
    const tokens: Array<{ text: string; kind: string }> = [];
    const re =
      /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(true|false|null)|([{}[\],:])|(\s+)|([^"{}\[\],:\s]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(prettyBody)) !== null) {
      if (m[1]) tokens.push({ text: m[1], kind: "key" });
      else if (m[2]) tokens.push({ text: m[2], kind: "str" });
      else if (m[3]) tokens.push({ text: m[3], kind: "num" });
      else if (m[4]) tokens.push({ text: m[4], kind: "kw" });
      else if (m[5]) tokens.push({ text: m[5], kind: "punct" });
      else if (m[6]) tokens.push({ text: m[6], kind: "ws" });
      else if (m[7]) tokens.push({ text: m[7], kind: "plain" });
    }
    return tokens;
  }, [mode, prettyBody, parsed.contentType]);
  const hex = useMemo(() => (mode === "hex" ? toHexDump(value) : ""), [mode, value]);

  // R815: Parse the start line for a status-code pill next to the
  // "Response" title. Mirrors Burp Suite 2026.8's response pane
  // which annotates the pane title with the response status. Only
  // renders when direction === "response" AND the body is non-empty
  // (an empty response hasn't landed yet).
  const responseStatusInfo = (() => {
    if (direction !== "response") return null;
    if (!value || value.length === 0) return null;
    const line = parsed.startLine || value.split(/\r?\n/)[0] || "";
    const m = /^HTTP\/[\d.]+\s+(\d{3})\s*(.*)$/.exec(line);
    if (!m) return null;
    const code = parseInt(m[1], 10);
    const reason = m[2] || "";
    let tint: "ok" | "redirect" | "client-err" | "server-err" = "ok";
    if (code >= 500) tint = "server-err";
    else if (code >= 400) tint = "client-err";
    else if (code >= 300) tint = "redirect";
    return { code, reason, tint };
  })();

  return (
    <div className="rep-pane">
      <div className="rep-pane-head">
        <strong>{label}</strong>
        {/* R815: Burp-identical status pill inline with Response
            title — "Response (HTTP 403 Forbidden)" matching Burp
            Suite 2026.8's exact pane header format. Tint tracks the
            status class so operators spot errors at a glance. */}
        {responseStatusInfo && (
          <span
            className={`rep-pane-status rep-pane-status-${responseStatusInfo.tint}`}
            title={`HTTP ${responseStatusInfo.code} ${responseStatusInfo.reason}`.trim()}
          >
            HTTP {responseStatusInfo.code}
            {responseStatusInfo.reason ? ` ${responseStatusInfo.reason}` : ""}
          </span>
        )}
        {/* R890: Burp-identical ⏸ ■ ▶ playback-style icon cluster
            on the Response pane header. Only renders for response
            panes (direction === "response") since request panes
            are always live-editable. Clicking pauses / stops /
            resumes live render — pause freezes current snapshot
            so operator can compare to next send, stop clears + marks
            cleared, play resumes live updates. Active state tinted
            with the Burp accent (red ▶ when live, amber ⏸ when
            paused, dim ■ when stopped). Zero backend. */}
        {direction === "response" && (
          <div
            className="rep-render-state"
            role="radiogroup"
            aria-label="Response render state"
            title={
              renderState === "live"
                ? "Render state: Live — response updates on every send. Click ⏸ to freeze current snapshot."
                : renderState === "paused"
                  ? "Render state: Paused — showing frozen snapshot. Click ▶ to resume live updates."
                  : "Render state: Stopped — frozen + cleared. Click ▶ to resume."
            }
          >
            <button
              type="button"
              className={`rep-render-btn${renderState === "paused" ? " active" : ""}`}
              onClick={() => setRenderState("paused")}
              aria-label="Pause render"
              aria-pressed={renderState === "paused"}
              title="Pause render (freeze current snapshot)"
            >
              ⏸
            </button>
            <button
              type="button"
              className={`rep-render-btn${renderState === "stopped" ? " active" : ""}`}
              onClick={() => setRenderState("stopped")}
              aria-label="Stop render"
              aria-pressed={renderState === "stopped"}
              title="Stop render (freeze + mark cleared)"
            >
              ■
            </button>
            <button
              type="button"
              className={`rep-render-btn${renderState === "live" ? " active rep-render-btn-live" : ""}`}
              onClick={() => setRenderState("live")}
              aria-label="Resume live render"
              aria-pressed={renderState === "live"}
              title="Resume live render (updates on every send)"
            >
              ▶
            </button>
          </div>
        )}
        <div className="rep-mode">
          {((direction === "response"
            ? ["pretty", "raw", "hex", "render"]
            : ["pretty", "raw", "hex"]) as EditorMode[]).map((m) => (
            <button
              key={m}
              className={`rep-mode-btn ${mode === m ? "active" : ""}`}
              onClick={() => setMode(m)}
              title={
                m === "pretty"
                  ? "Pretty-printed body"
                  : m === "hex"
                    ? "Byte-level hex view"
                    : m === "render"
                      ? "Render the body as HTML or an image (scripts disabled)"
                      : "Raw wire format"
              }
            >
              {m}
            </button>
          ))}
        </div>
        {/* R766: Removed redundant `.rep-pane-info` content-type+
            size span. The R734 Repeater status bar already shows
            Size + Content-Type at the Repeater panel level, and
            the R765 pane bottom bar shows char/line counts. The
            inline pane-head info was duplicative + took horizontal
            space that pushed the Burp-identical ⏸▪▶↵≡📑 icons
            off-screen on narrow panes. */}
        {/* R797: Burp-identical "hide/show uninteresting headers"
            toggle — matches the compact icon-only silhouette
            visible in the user's reference screenshot (eye/no-see
            glyph alongside the other pane-header icons). Replaces
            the previous `⌃ show noise (N) / ⌄ hide noise (N)` text
            button which took disproportionate horizontal space on
            narrow panes and used custom chevron glyphs instead of
            Burp's canonical eye-icon vocabulary. Class flipped
            from `.ghost` to `.rep-pane-icon` so the toggle sits
            alongside ⏸▪▶↵≡📑 in the same visual family. Count
            moves into the tooltip. */}
        {uninterestingCount > 0 && (
          <button
            className={`rep-pane-icon${showUninteresting ? " active" : ""}`}
            onClick={() => setShowUninteresting((s) => !s)}
            title={
              showUninteresting
                ? `${uninterestingCount} boilerplate browser header${uninterestingCount === 1 ? "" : "s"} visible — click to hide (sec-ch-ua*, sec-fetch-*, accept-*, priority, upgrade-insecure-requests, …)`
                : `${uninterestingCount} boilerplate browser header${uninterestingCount === 1 ? "" : "s"} hidden — click to show. Raw/hex/render views always show the full wire.`
            }
          >
            {showUninteresting ? "👁" : "🙈"}
          </button>
        )}
        {/* R758: Burp-identical pane header right-side icons.
            Mirror of the empty-state Burp Repeater screenshot:
            Request pane shows "🚫 📑 ↵ ≡" (hide-noise toggle +
            format + line-wrap + more). Response pane shows
            "⏸ ■ ▶" (pause/stop/play render controls) + same
            trailing icons. Shared across all MessageEditor
            consumers. */}
        {direction === "response" && (
          <>
            <button
              className="rep-pane-icon"
              onClick={() => {
                alert(
                  "⏸ Pause render\n\n" +
                    "Pause auto-rendering of the response in Render mode. " +
                    "Planned functional in a future release — currently " +
                    "the Render mode re-renders on every mode-switch.",
                );
              }}
              title="Pause auto-render (planned)"
            >
              ⏸
            </button>
            <button
              className="rep-pane-icon"
              onClick={() => {
                alert(
                  "■ Stop render\n\n" +
                    "Cancel in-flight Render-mode HTML parsing. Planned " +
                    "functional in a future release.",
                );
              }}
              title="Stop render (planned)"
            >
              ▪
            </button>
            <button
              className="rep-pane-icon"
              onClick={() => {
                alert(
                  "▶ Resume render\n\n" +
                    "Resume Render-mode auto-rendering. Planned functional " +
                    "in a future release.",
                );
              }}
              title="Resume render (planned)"
            >
              ▶
            </button>
          </>
        )}
        {/* R759: Burp-identical ↵ line-wrap toggle. Persisted in
            localStorage. Toggles `.rep-editor--wrap` class which
            applies `white-space: pre-wrap` to the textarea. */}
        <button
          className={`rep-pane-icon${wrapLines ? " active" : ""}`}
          onClick={() => setWrapLines((v) => !v)}
          title={wrapLines ? "Disable line wrap (hard breaks + horizontal scroll)" : "Enable line wrap (soft wrap long lines)"}
        >
          ↵
        </button>
        {/* R759: Burp-identical ≡ more menu. Opens a FloatingMenu
            with pane-level actions (future expansion point for
            per-pane settings like font-size / tab-width). */}
        <button
          className="rep-pane-icon"
          onClick={() => {
            alert(
              "≡ Pane actions\n\n" +
                "Future per-pane settings dock here (font-size, tab-width, " +
                "render encoding, syntax highlight profile, etc). For now, " +
                "use the pane body's right-click menu for selection-level " +
                "actions.",
            );
          }}
          title="Pane actions (planned)"
        >
          ≡
        </button>
        {/* R763: Renamed from "Inspector" to "📑 Parse" to
            disambiguate from the Repeater's R733 global
            Inspector sidebar. This per-pane widget shows parsed
            headers + body params + cookies for THIS pane only
            (vs the global sidebar which shows request + response
            + notes). Different scope + different UX layer, same
            parser underneath. */}
        <button
          className={`rep-pane-icon rep-insp-toggle ${showInspector ? "active" : ""}`}
          onClick={() => setShowInspector((s) => !s)}
          title={showInspector ? "Hide per-pane Parse widget (keeps inline parsed structure)" : "Show per-pane Parse widget — inline parsed headers/params/cookies for this pane only"}
        >
          📑
        </button>
      </div>
      <div className="rep-pane-body">
        <div className="rep-editor">
          {mode === "raw" && (
            <>
              {search && (
                <div className="rep-search-bar" role="search">
                  <input
                    ref={searchInputRef}
                    type="text"
                    value={search.query}
                    onChange={(e) => setSearch({ ...search, query: e.target.value })}
                    onKeyDown={(e) => {
                      if (e.key === "F3") {
                        e.preventDefault();
                        if (matches.length > 0) {
                          if (e.shiftKey) prevMatch();
                          else nextMatch();
                        }
                        return;
                      }
                      if (e.key === "Escape") {
                        e.preventDefault();
                        closeSearch();
                      } else if (e.key === "Enter") {
                        e.preventDefault();
                        if (e.shiftKey) prevMatch();
                        else nextMatch();
                      }
                    }}
                    placeholder={search.regex ? "regex" : "search"}
                    className="mono"
                    spellCheck={false}
                    autoFocus
                  />
                  <span className="rep-search-count">
                    {matches.length === 0
                      ? search.query
                        ? "0/0"
                        : "—"
                      : `${matchIndex + 1}/${matches.length}`}
                  </span>
                  <button className="ghost" onClick={prevMatch} disabled={matches.length === 0} title="Previous match (Shift+Enter)">▲</button>
                  <button className="ghost" onClick={nextMatch} disabled={matches.length === 0} title="Next match (Enter)">▼</button>
                  <button
                    className={`ghost ${search.caseSensitive ? "on" : ""}`}
                    onClick={() => setSearch({ ...search, caseSensitive: !search.caseSensitive })}
                    title="Match case"
                  >Aa</button>
                  <button
                    className={`ghost ${search.regex ? "on" : ""}`}
                    onClick={() => setSearch({ ...search, regex: !search.regex })}
                    title="Regex"
                  >.*</button>
                  <button className="ghost" onClick={closeSearch} title="Close (Esc)">×</button>
                </div>
              )}
              {/* R816: Burp-identical line-number gutter on the
                  left of the raw-mode textarea. Matches Burp Suite
                  2026.8's reference screenshot showing numbered
                  lines in the Request/Response panes. Gutter is
                  pointer-events:none so clicks pass through to the
                  textarea; scroll syncs via `onScroll` on the
                  textarea which writes `scrollTop` back to the
                  gutter element. Line count derives from newline
                  count + 1. */}
              <div className="rep-editor-raw-wrap">
                <div
                  className="rep-editor-gutter"
                  ref={(el) => {
                    (taRef.current as any)?.setAttribute?.(
                      "data-gutter-mounted",
                      el ? "1" : "0",
                    );
                  }}
                  aria-hidden="true"
                >
                  {(() => {
                    const lineCount =
                      (value.match(/\n/g)?.length ?? 0) + 1;
                    // Cap at 10,000 lines to avoid DOM explosion.
                    const cap = Math.min(lineCount, 10000);
                    const nodes: React.ReactNode[] = [];
                    for (let i = 1; i <= cap; i++) {
                      nodes.push(<div key={i}>{i}</div>);
                    }
                    return nodes;
                  })()}
                </div>
              <textarea
                ref={taRef}
                onScroll={(e) => {
                  // Sync the gutter's scroll to the textarea.
                  const ta = e.currentTarget;
                  const gutter = ta.previousElementSibling as
                    | HTMLElement
                    | null;
                  if (gutter && gutter.classList.contains("rep-editor-gutter")) {
                    gutter.scrollTop = ta.scrollTop;
                  }
                }}
                onSelect={(e) => {
                  // R793: Track selection start/end for the bottom-bar
                  // "Selection: N (0xN)" display. Fires on every
                  // selection change — mouse drag, Shift+arrow,
                  // Ctrl+A, caret moves. Collapsed selections
                  // (start === end) hide the display.
                  const ta = e.currentTarget;
                  const start = ta.selectionStart ?? 0;
                  const end = ta.selectionEnd ?? 0;
                  setSelectionRange({ start, end });
                  // R811: Lift selection up to the host panel so the
                  // Inspector sidebar's "Selection" top panel can
                  // render the selected text + decoded preview.
                  if (onSelectionChange) {
                    const text =
                      start !== end ? value.slice(start, end) : "";
                    onSelectionChange({ start, end, text, direction });
                  }
                }}
                className={`mono${wrapLines ? " rep-editor-wrap" : ""}`}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                readOnly={readOnly}
                onKeyDown={(e) => {
                  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
                    e.preventDefault();
                    openSearch();
                    return;
                  }
                  /*  R205: Ctrl+G — Go-to-line prompt. Standard IDE
                   *  convention (VS Code, Sublime, IntelliJ) for
                   *  jumping to a known line number in a long raw-
                   *  wire message. Operators scanning multi-KB
                   *  response bodies for a specific line (grep
                   *  context, SARIF line hints) want fast random
                   *  access instead of scroll + eyeball. Native
                   *  `prompt` for the input — zero widget overhead;
                   *  if the operator cancels or types garbage the
                   *  handler is a no-op. `setSelectionRange`
                   *  triggers the textarea's built-in auto-scroll
                   *  so the target line surfaces without manual
                   *  scrollTop math. */
                  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "g") {
                    e.preventDefault();
                    const ta = e.currentTarget;
                    const lines = value.split("\n");
                    const lineCount = lines.length;
                    const input = window.prompt(
                      `Jump to line (1-${lineCount}):`,
                    );
                    if (input == null) return;
                    const n = parseInt(input.trim(), 10);
                    if (
                      !Number.isFinite(n) ||
                      n < 1 ||
                      n > lineCount
                    )
                      return;
                    let offset = 0;
                    for (let i = 0; i < n - 1; i++) {
                      offset += lines[i].length + 1;
                    }
                    ta.focus();
                    ta.setSelectionRange(offset, offset);
                    return;
                  }
                  /*  R173: F3 / Shift+F3 — browser-standard find
                   *  cycling. When search is closed, F3 opens it
                   *  focused (parallels Firefox / Chrome). When
                   *  open, F3 jumps to next match, Shift+F3 to
                   *  previous. Lives on the textarea's keydown so
                   *  it only fires inside the editor pane. */
                  if (e.key === "F3") {
                    e.preventDefault();
                    if (!search) {
                      openSearch();
                    } else if (matches.length > 0) {
                      if (e.shiftKey) prevMatch();
                      else nextMatch();
                    }
                    return;
                  }
                  if (onCtrlEnter && (e.ctrlKey || e.metaKey) && e.key === "Enter") {
                    e.preventDefault();
                    onCtrlEnter();
                  }
                }}
                onContextMenu={(e) => {
                  const ta = e.currentTarget;
                  const start = ta.selectionStart ?? 0;
                  const end = ta.selectionEnd ?? 0;
                  // R893: Burp-identical right-click menu always opens
                  // on raw editor (both selection + no-selection cases)
                  // matching the user-attached Burp context-menu
                  // screenshot. The selection branch renders encode/
                  // decode entries; the no-selection branch renders
                  // the full Send-to-X / Change body encoding / Copy
                  // URL / Open docs set that Burp Suite 2026.8 shows
                  // on right-click anywhere in the editor.
                  const hasSelection = start !== end;
                  if (hasSelection && !readOnly) {
                    e.preventDefault();
                    const selected = value.slice(start, end);
                    setSelectionMenu({
                      x: e.clientX,
                      y: e.clientY,
                      data: { kind: "selection", start, end, selected },
                    });
                    return;
                  }
                  // Always show the no-selection menu now — Burp parity.
                  e.preventDefault();
                  setSelectionMenu({
                    x: e.clientX,
                    y: e.clientY,
                    data: { kind: "no-selection" },
                  });
                }}
                spellCheck={false}
              />
              </div> {/* /rep-editor-raw-wrap */}
            </>
          )}
          {mode === "pretty" && (
            <>
              <div
                className="mono rep-head"
                style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}
              >
                {renderPrettyHead(
                  parsed.startLine,
                  parsed.headers,
                  showUninteresting,
                  () => setShowUninteresting(true),
                )}
              </div>
              <pre className="mono rep-pretty-body">
                {prettyJsonTokens
                  ? prettyJsonTokens.map((t, i) => (
                      <span key={i} className={`rep-json-${t.kind}`}>
                        {t.text}
                      </span>
                    ))
                  : prettyXmlTokens
                    ? prettyXmlTokens.map((t, i) => (
                        <span key={i} className={`rep-xml-${t.kind}`}>
                          {t.text}
                        </span>
                      ))
                    : prettyBody || <span className="dim">(no body)</span>}
              </pre>
            </>
          )}
          {mode === "hex" && <pre className="mono rep-hex">{hex}</pre>}
          {mode === "render" && (
            <RenderPreview contentType={parsed.contentType} body={parsed.body} />
          )}
        </div>
        {showInspector && (
          <Inspector
            parsed={parsed}
            direction={direction}
            showUninteresting={showUninteresting}
            uninterestingCount={uninterestingCount}
            onRevealUninteresting={() => setShowUninteresting(true)}
          />
        )}
      </div>
      {/* R745+R765: Burp-identical pane bottom bar. R765 adds the
          exact Burp Suite 2026.8 silhouette from the reference
          screenshot: `? ⚙ ← → [search______] 🔍 N highlights`.
          ? help / ⚙ pane settings / ← → match navigation / search
          input / highlight count. R765 replaces the single "🔍
          Search" button with an inline input that stays visible
          + populates the existing MessageEditor search overlay
          when operators type into it. Match navigation reuses the
          overlay's prevMatch/nextMatch so the shortcut path is
          byte-identical to Ctrl+F → Enter. */}
      <div className="rep-pane-foot">
        <button
          className="rep-pane-foot-btn"
          onClick={() =>
            alert(
              "Pane shortcuts\n\n" +
                "Ctrl+F   Open search\n" +
                "Ctrl+G   Go to line\n" +
                "F3       Next match\n" +
                "Shift+F3 Previous match\n" +
                "Esc      Close search / cancel edit\n\n" +
                "Right-click selection → encode/decode/send-to menu.",
            )
          }
          title="Pane shortcuts"
        >
          ?
        </button>
        <button
          className="rep-pane-foot-btn"
          onClick={() =>
            alert(
              "Pane settings\n\n" +
                "Use the pane header icons for per-pane settings:\n" +
                "📑 toggle Parse widget\n" +
                "↵ toggle line wrap\n" +
                "≡ more actions (planned per-pane prefs)\n\n" +
                "Current mode: " +
                mode.toUpperCase(),
            )
          }
          title="Pane settings"
        >
          ⚙
        </button>
        <button
          className="rep-pane-foot-btn"
          onClick={() => {
            if (!search) openSearch();
            if (matches.length > 0) prevMatch();
          }}
          disabled={matches.length === 0}
          title="Previous match (Shift+F3)"
        >
          ←
        </button>
        <button
          className="rep-pane-foot-btn"
          onClick={() => {
            if (!search) openSearch();
            if (matches.length > 0) nextMatch();
          }}
          disabled={matches.length === 0}
          title="Next match (F3)"
        >
          →
        </button>
        {/* R829: Burp-identical pane-bottom layout — Request pane
            shows the inline search input in this slot, Response
            pane shows the env dropdown (R794 via extraFootItem).
            Hiding search in Response matches the user's reference
            screenshot where only the Request pane has a search box
            + Response has the env dropdown pill. Operators who want
            to search the Response can still use Ctrl+F to open the
            full search overlay (the pane body's search bar). */}
        {direction === "request" && (
        <input
          className="rep-pane-foot-search"
          type="text"
          value={search?.query ?? ""}
          onChange={(e) => {
            const q = e.target.value;
            if (!search && q) {
              setSearch({ query: q, regex: false, caseSensitive: false });
            } else if (search) {
              setSearch({ ...search, query: q });
            }
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              if (matches.length > 0) {
                if (e.shiftKey) prevMatch();
                else nextMatch();
              }
            } else if (e.key === "Escape") {
              e.preventDefault();
              if (search?.query) {
                setSearch({ ...search, query: "" });
              } else {
                closeSearch();
              }
            }
          }}
          placeholder="Search"
          spellCheck={false}
        />
        )}
        {/* R794: pane-specific extra foot item slot — rendered
            between the search box and the chars/highlights
            counter. Repeater's response pane uses it to render
            the environment selector, matching Burp Suite 2026.8's
            exact bottom bar layout. */}
        {extraFootItem && (
          <>
            <span className="rep-pane-foot-sep">·</span>
            {extraFootItem}
          </>
        )}
        <span className="rep-pane-foot-sep">·</span>
        <span className="rep-pane-foot-item">
          {search && search.query
            ? `${matches.length} highlight${matches.length === 1 ? "" : "s"}`
            : `${value.length.toLocaleString()} chars`}
        </span>
        <span className="rep-pane-foot-sep">·</span>
        <span className="rep-pane-foot-item">
          {(value.match(/\n/g)?.length ?? 0) + 1} lines
        </span>
        {/* R862: Burp-identical "Ln X, Col Y" caret position
            indicator. Standard editor convention — Burp Suite
            2026.8's status bar carries it in the pane bottom bar
            next to the lines count. Operators reading a stack
            trace / error message that references a line number
            can now scroll to it and confirm "yes I'm on line 42"
            without counting manually. Derived inline from
            `selectionRange.start` so it reconciles on every click
            / keystroke / arrow move. Line = count of newlines
            before start + 1 (1-indexed). Column = chars since the
            last newline + 1 (1-indexed). */}
        <span className="rep-pane-foot-sep">·</span>
        <span
          className="rep-pane-foot-item"
          title={`Caret at byte offset ${selectionRange.start}`}
        >
          {(() => {
            const before = value.slice(0, selectionRange.start);
            const ln = (before.match(/\n/g)?.length ?? 0) + 1;
            const lastNl = before.lastIndexOf("\n");
            const col = selectionRange.start - (lastNl + 1) + 1;
            return `Ln ${ln}, Col ${col}`;
          })()}
        </span>
        {/* R793: Burp-identical "Selection: N (0xN)" byte-count +
            hex-offset display. Matches Burp Suite 2026.8's pane
            bottom bar which operators rely on to pin down the
            exact byte count of their current selection (critical
            for binary boundary alignment, splice-size verification,
            "how many bytes did I highlight?" quick-answers).
            Shows the byte count in decimal + hex. Hidden when
            selection is collapsed (start === end). */}
        {selectionRange.start !== selectionRange.end && (
          <>
            <span className="rep-pane-foot-sep">·</span>
            <span
              className="rep-pane-foot-item"
              title={`Selected ${Math.abs(
                selectionRange.end - selectionRange.start,
              )} byte${
                Math.abs(selectionRange.end - selectionRange.start) === 1
                  ? ""
                  : "s"
              } · offset ${selectionRange.start}-${selectionRange.end} (0x${selectionRange.start.toString(16)}-0x${selectionRange.end.toString(16)})`}
            >
              Selection:{" "}
              {Math.abs(selectionRange.end - selectionRange.start)} (0x
              {Math.abs(
                selectionRange.end - selectionRange.start,
              ).toString(16)}
              )
            </span>
          </>
        )}
        {/* R787: Burp-identical body-size indicator in the pane
            bottom bar. Shows the parsed body byte count (not the
            whole raw which includes headers) so operators can
            answer "how big is the actual payload?" without diving
            into the Inspector or Hex mode. Only renders when the
            parsed body is non-empty — zero-body requests (GET w/o
            body / empty response) keep the strip clean. Adaptive
            formatter: `<1024` as `N B`, `<1 MB` as `N.N KB`, else
            `N.N MB` — matches R734 Repeater status bar formatter
            exactly for cross-strip consistency. */}
        {parsed.body && parsed.body.length > 0 && (
          <>
            <span className="rep-pane-foot-sep">·</span>
            <span
              className="rep-pane-foot-item"
              title={`${parsed.body.length.toLocaleString()} bytes of ${direction} body (parsed, excludes headers)`}
            >
              {(() => {
                const n = parsed.body.length;
                if (n < 1024) return `${n} B`;
                if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
                return `${(n / 1024 / 1024).toFixed(1)} MB`;
              })()}{" "}
              body
            </span>
          </>
        )}
        <span className="rep-pane-foot-spacer" />
        <span className="rep-pane-foot-mode">{mode}</span>
      </div>
      <FloatingMenu
        state={selectionMenu}
        onClose={() => setSelectionMenu(null)}
        items={
          selectionMenu?.data
            ? selectionMenu.data.kind === "selection"
              ? [
                  { label: `Selected ${selectionMenu.data.selected.length} char(s)`, disabled: true },
                  { separator: true },
                  {
                    label: "Pretty-print",
                    hint: "JSON / XML / urlencoded",
                    onClick: () => prettyPrintSelection(),
                  },
                  /* R182: Wrap selection in `§` markers — speeds up    */
                  /* the Repeater → Intruder handoff workflow. An       */
                  /* operator refining a payload in Repeater can mark   */
                  /* the dynamic parts in-place, then "Send to Intruder"*/
                  /* in a position-aware pre-marked state. Hidden for   */
                  /* readOnly editors (response pane) because wrapping  */
                  /* read-only text has no meaning. */
                  ...(readOnly
                    ? []
                    : [
                        {
                          label: "Wrap in § markers",
                          hint: "Intruder position",
                          onClick: () => {
                            if (
                              !selectionMenu?.data ||
                              selectionMenu.data.kind !== "selection"
                            )
                              return;
                            const { start, end, selected } = selectionMenu.data;
                            const next =
                              value.slice(0, start) +
                              `§${selected}§` +
                              value.slice(end);
                            onChange(next);
                            setSelectionMenu(null);
                          },
                        },
                      ]),
                  { separator: true },
                  { label: "URL-encode", onClick: () => void applyTransformToSelection("url_encode") },
                  { label: "URL-decode", onClick: () => void applyTransformToSelection("url_decode") },
                  { separator: true },
                  { label: "Base64 encode", onClick: () => void applyTransformToSelection("base64_encode") },
                  { label: "Base64 decode", onClick: () => void applyTransformToSelection("base64_decode") },
                  { separator: true },
                  { label: "HTML encode", onClick: () => void applyTransformToSelection("html_encode") },
                  { label: "HTML decode", onClick: () => void applyTransformToSelection("html_decode") },
                  { label: "Hex encode", onClick: () => void applyTransformToSelection("hex_encode") },
                  { label: "Hex decode", onClick: () => void applyTransformToSelection("hex_decode") },
                  /* 🎯 R826 — 800-streak celebration (R27-R826 = 800
                   * continuous rounds). Burp-identical "Open selection
                   * as new Repeater tab" entry — extracts the selected
                   * text as a URL + opens a fresh Repeater tab against
                   * it. Only shows when selection looks like an
                   * absolute http(s) URL. Mirrors Burp's "URL smart
                   * extract → Send to Repeater" convention operators
                   * use to pivot into URLs they find in response
                   * bodies, Set-Cookie Path= attributes, or Location
                   * redirect headers. */
                  ...(() => {
                    if (
                      !selectionMenu?.data ||
                      selectionMenu.data.kind !== "selection"
                    )
                      return [];
                    const sel = selectionMenu.data.selected.trim();
                    // Match absolute http/https URLs. Avoid literal
                    // `<` `>` inside TSX regex char class — those
                    // confuse the JSX parser. Build the exclusion
                    // via explicit alternation.
                    const urlRe =
                      /^https?:\/\/[^\s"'\u003c\u003e]+$/i;
                    if (!urlRe.test(sel)) return [];
                    return [
                      { separator: true as const },
                      {
                        label: "🎯 Open as new Repeater tab",
                        hint: "800-streak gift — URL opens in a fresh tab",
                        onClick: () => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:open-repeater-tab", {
                              detail: { url: sel },
                            }),
                          );
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "repeater" },
                            }),
                          );
                          setSelectionMenu(null);
                        },
                      },
                    ];
                  })(),
                  ...(extraMenuItems && extraMenuItems.length > 0
                    ? [{ separator: true as const }, ...extraMenuItems]
                    : []),
                ]
              : // R893: No-selection right-click opens the Burp-
                // identical rich context menu matching the user-
                // attached Burp screenshot. Entries dispatch
                // CustomEvents the host panel listens for +
                // self-contained Copy/Save/docs actions.
                [
                  // Send-to-X cluster (top of Burp's menu)
                  {
                    label: "Send to Intruder",
                    hotkey: "Ctrl+I",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:send-to-intruder"),
                      ),
                  },
                  {
                    label: "Send to Repeater",
                    hotkey: "Ctrl+R",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:send-to-repeater"),
                      ),
                  },
                  {
                    label: "Send to Sequencer",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "sequencer" },
                        }),
                      ),
                  },
                  {
                    label: "Send to Comparer",
                    onClick: () => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:comparer-load", {
                          detail: {
                            left: value,
                            right: "",
                            label: `${direction} snapshot`,
                          },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "comparer" },
                        }),
                      );
                    },
                  },
                  {
                    label: "Send to Decoder",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "decoder" },
                        }),
                      ),
                  },
                  {
                    label: "Send to Organizer",
                    hotkey: "Ctrl+O",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:send-to-organizer"),
                      ),
                  },
                  { separator: true as const },
                  {
                    label: "Insert Collaborator payload",
                    disabled: true,
                    hint: "[BurpFree: open Collaborator panel to mint]",
                  },
                  {
                    label: "Open response in browser",
                    hint: "Repeater response pane only",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-open-response"),
                      ),
                  },
                  { separator: true as const },
                  // Change / modify cluster
                  {
                    label: "Change request method",
                    hint: "GET / POST / PUT / etc.",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-change-method"),
                      ),
                  },
                  {
                    label: "Change body encoding → Form URL-encoded",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-change-encoding", {
                          detail: { encoding: "form-urlencoded" },
                        }),
                      ),
                  },
                  {
                    label: "Change body encoding → Multipart",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-change-encoding", {
                          detail: { encoding: "multipart" },
                        }),
                      ),
                  },
                  {
                    label: "Change body encoding → JSON",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-change-encoding", {
                          detail: { encoding: "json" },
                        }),
                      ),
                  },
                  { separator: true as const },
                  // Copy cluster
                  {
                    label: "Copy",
                    hotkey: "Ctrl+C",
                    onClick: () => {
                      void navigator.clipboard.writeText(value);
                    },
                  },
                  {
                    label: "Copy URL",
                    onClick: () => {
                      // Extract URL from the parsed start-line + Host header
                      const host =
                        parsed.headers.find(
                          ([k]) => k.toLowerCase() === "host",
                        )?.[1] ?? "";
                      const path = parsed.path ?? "";
                      const url = host ? `https://${host}${path}` : path;
                      void navigator.clipboard.writeText(url);
                    },
                  },
                  {
                    label: "Copy as curl command (bash)",
                    onClick: () =>
                      window.dispatchEvent(
                        new CustomEvent("burpfree:repeater-copy-curl"),
                      ),
                  },
                  { separator: true as const },
                  // Save / paste cluster
                  {
                    label: "Save item",
                    hint: "save raw to .txt",
                    onClick: () => {
                      try {
                        const blob = new Blob([value], {
                          type: "text/plain;charset=utf-8",
                        });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${direction}-${new Date()
                          .toISOString()
                          .replace(/[:.]/g, "-")}.txt`;
                        a.click();
                        URL.revokeObjectURL(url);
                      } catch (err) {
                        alert(`${err}`);
                      }
                    },
                  },
                  {
                    label: "Add to site map",
                    hint: "fire add-to-scope from Host header",
                    onClick: () => {
                      const host =
                        parsed.headers.find(
                          ([k]) => k.toLowerCase() === "host",
                        )?.[1] ?? "";
                      if (!host) {
                        alert(
                          "No Host header found in this request — can't add to site map.",
                        );
                        return;
                      }
                      window.dispatchEvent(
                        new CustomEvent("burpfree:scope-add-host", {
                          detail: { host },
                        }),
                      );
                      alert(
                        `Added "${host}" to scope include rules. Open the Target → Scope panel to review.`,
                      );
                    },
                  },
                  { separator: true as const },
                  // Documentation cluster
                  {
                    label: "Message editor documentation",
                    onClick: () =>
                      alert(
                        "BurpFree Message Editor\n\n" +
                          "The shared message editor renders HTTP requests + responses in 4 modes:\n" +
                          "  • Pretty — syntax-colored JSON / XML / HTML body\n" +
                          "  • Raw — exact wire-format bytes (editable in request panes)\n" +
                          "  • Hex — hexdump -C style byte grid\n" +
                          "  • Render — browser preview of HTML / image bodies\n\n" +
                          "Right-click to open this menu, select text + right-click for encode/decode transforms. See ARCHITECTURE.md for the shared-editor contract.",
                      ),
                  },
                  {
                    label: "Burp Repeater documentation",
                    onClick: () =>
                      alert(
                        "BurpFree Repeater (clone of Burp Suite's Repeater panel)\n\n" +
                          "• Ctrl+Enter: send\n" +
                          "• Ctrl+Backspace: cancel in-flight\n" +
                          "• Alt+N: new tab · Alt+W: close · Ctrl+D: duplicate\n" +
                          "• Ctrl+Shift+T: reopen most-recently-closed tab\n" +
                          "• Ctrl+B: jump caret to body\n" +
                          "• F2: rename tab · middle-click: close tab\n" +
                          "• Alt+Shift+D: diff last 2 sends\n" +
                          "• Ctrl+E: open ✦ AI drawer\n\n" +
                          "Press Ctrl+/ for the full keyboard cheatsheet.",
                      ),
                  },
                  ...(extraMenuItems && extraMenuItems.length > 0
                    ? [{ separator: true as const }, ...extraMenuItems]
                    : []),
                ]
            : []
        }
      />
    </div>
  );
}

/* ------------------ inspector ------------------ */

function Inspector({
  parsed,
  direction,
  showUninteresting,
  uninterestingCount,
  onRevealUninteresting,
}: {
  parsed: ParsedMsg;
  direction: "request" | "response";
  showUninteresting: boolean;
  uninterestingCount: number;
  onRevealUninteresting: () => void;
}) {
  return (
    <div className="rep-inspector">
      <Section title={direction === "request" ? "Request line" : "Status line"} count={1} defaultOpen>
        <KV name={direction === "request" ? "method" : "version"} value={direction === "request" ? parsed.method ?? "" : parsed.version ?? ""} />
        {direction === "request" ? (
          <>
            <KV name="path" value={pathWithoutQuery(parsed.path ?? "")} />
            <KV name="version" value={parsed.version ?? ""} />
          </>
        ) : (
          <>
            <KV name="status" value={String(parsed.status ?? "")} />
            <KV name="reason" value={parsed.reason ?? ""} />
          </>
        )}
      </Section>

      {direction === "request" && parsed.queryParams.length > 0 && (
        <Section title="Query parameters" count={parsed.queryParams.length}>
          {parsed.queryParams.map(([k, v], i) => (
            <KV key={i} name={k} value={v} />
          ))}
        </Section>
      )}

      {parsed.cookiesSent.length > 0 && (
        <Section title="Cookies (sent)" count={parsed.cookiesSent.length}>
          {parsed.cookiesSent.map(([k, v], i) => (
            <KV key={i} name={k} value={v} />
          ))}
        </Section>
      )}

      {parsed.cookiesSet.length > 0 && (
        <Section title="Set-Cookie" count={parsed.cookiesSet.length}>
          {parsed.cookiesSet.map((c, i) => (
            <div key={i} style={{ paddingBottom: 4 }}>
              <KV name={c.name} value={c.value} />
              {Object.entries(c.attrs).map(([a, av]) => (
                <div key={a} style={{ fontSize: 10, color: "var(--text-faint)", paddingLeft: 10 }}>
                  {a}
                  {av !== "true" ? `=${av}` : ""}
                </div>
              ))}
            </div>
          ))}
        </Section>
      )}

      <Section
        title={direction === "request" ? "Request headers" : "Response headers"}
        count={
          showUninteresting
            ? parsed.headers.length
            : parsed.headers.length - uninterestingCount
        }
        defaultOpen
      >
        {parsed.headers
          .filter(([k]) => showUninteresting || !isUninterestingHeader(k))
          .map(([k, v], i) => (
            <KV key={i} name={k} value={v} />
          ))}
        {!showUninteresting && uninterestingCount > 0 && (
          <div
            className="insp-kv"
            onClick={onRevealUninteresting}
            title="Click to reveal boilerplate browser headers"
            style={{ cursor: "pointer" }}
          >
            <span
              className="insp-k"
              style={{ fontStyle: "italic", color: "var(--text-dim)" }}
            >
              [{uninterestingCount} boilerplate hidden]
            </span>
            <span
              className="insp-v"
              style={{ fontStyle: "italic", color: "var(--text-dim)" }}
            >
              click to show
            </span>
          </div>
        )}
      </Section>

      {direction === "request" && parsed.bodyParams.length > 0 && (
        <Section title="Body parameters (form)" count={parsed.bodyParams.length}>
          {parsed.bodyParams.map(([k, v], i) => (
            <KV key={i} name={k} value={v} />
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({
  title,
  count,
  children,
  defaultOpen,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <div className="insp-section">
      <div className="insp-head" onClick={() => setOpen((o) => !o)}>
        <span className="insp-caret">{open ? "▾" : "▸"}</span>
        <span className="insp-title">{title}</span>
        <span className="insp-count">{count}</span>
      </div>
      {open && <div className="insp-body">{children}</div>}
    </div>
  );
}

function KV({ name, value }: { name: string; value: string }) {
  return (
    <div className="insp-kv" title={`${name}: ${value}`}>
      <span className="insp-k">{name}</span>
      <span className="insp-v">{value}</span>
    </div>
  );
}

function pathWithoutQuery(p: string): string {
  const i = p.indexOf("?");
  return i < 0 ? p : p.slice(0, i);
}
