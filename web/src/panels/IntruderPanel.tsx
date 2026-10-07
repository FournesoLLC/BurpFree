import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  IntruderRecipeView,
  OobBatchHit,
  OobToken,
  PayloadLibraryEntry,
} from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import {
  buildCurl,
  buildFetch,
  buildPowerShell,
  buildPython,
  copyToClipboard,
  fromUrlAndRaw,
} from "../copyAs";

/** One payload set — Burp's "Payload sets" row. In Sniper /
 *  BatteringRam only set[0] is used; Pitchfork / ClusterBomb use one
 *  set per insertion point. We carry params for every supported
 *  type so switching between types doesn't lose data. */
type PayloadSet = {
  type: "list" | "numbers" | "null";
  /** Textarea content for list-mode payloads (one per line). */
  list: string;
  numFrom: number;
  numTo: number;
  numStep: number;
  numPadTo: number;
  nullCount: number;
};

/** Fresh PayloadSet with Burp-style defaults. The `list` argument
 *  seeds the textarea so the operator sees something immediately. */
function makeDefaultPayloadSet(list = ""): PayloadSet {
  return {
    type: "list",
    list,
    numFrom: 1,
    numTo: 100,
    numStep: 1,
    numPadTo: 0,
    nullCount: 50,
  };
}

/** One link in the Intruder payload-processing chain. Mirrors
 *  `burpfree_engines::intruder::PayloadProcessingRule` on the Rust
 *  side exactly — Serde consumes `{ kind, …params }` thanks to its
 *  `tag = "kind"` representation. Everything but Prefix / Suffix /
 *  MatchReplace is parameterless. */
export type ProcessingRule =
  | { kind: "prefix"; value: string }
  | { kind: "suffix"; value: string }
  | { kind: "url_encode" }
  | { kind: "url_decode" }
  | { kind: "base64_encode" }
  | { kind: "base64_decode" }
  | { kind: "html_encode" }
  | { kind: "hex_encode" }
  | { kind: "md5" }
  | { kind: "sha1" }
  | { kind: "sha256" }
  | { kind: "uppercase" }
  | { kind: "lowercase" }
  | { kind: "reverse" }
  | {
      kind: "match_replace";
      pattern: string;
      replacement: string;
      regex: boolean;
    };

/** Human labels for the processing-rule dropdown — grouped so the
 *  common ones (prefix / suffix / match-replace) sit at the top. */
const PROCESSING_RULE_CATALOG: Array<{
  kind: ProcessingRule["kind"];
  label: string;
  group: string;
}> = [
  { kind: "prefix", label: "Add prefix", group: "Common" },
  { kind: "suffix", label: "Add suffix", group: "Common" },
  { kind: "match_replace", label: "Match / replace", group: "Common" },
  { kind: "url_encode", label: "URL-encode", group: "Encode" },
  { kind: "url_decode", label: "URL-decode", group: "Encode" },
  { kind: "base64_encode", label: "Base64-encode", group: "Encode" },
  { kind: "base64_decode", label: "Base64-decode", group: "Encode" },
  { kind: "html_encode", label: "HTML-encode", group: "Encode" },
  { kind: "hex_encode", label: "Hex-encode", group: "Encode" },
  { kind: "md5", label: "MD5 (hex)", group: "Hash" },
  { kind: "sha1", label: "SHA-1 (hex)", group: "Hash" },
  { kind: "sha256", label: "SHA-256 (hex)", group: "Hash" },
  { kind: "uppercase", label: "UPPERCASE", group: "Case" },
  { kind: "lowercase", label: "lowercase", group: "Case" },
  { kind: "reverse", label: "Reverse", group: "Case" },
];

/** Build a fresh default rule of the given kind — fills in sensible
 *  starter values for the variants that carry params. */
function newRule(kind: ProcessingRule["kind"]): ProcessingRule {
  switch (kind) {
    case "prefix":
      return { kind: "prefix", value: "" };
    case "suffix":
      return { kind: "suffix", value: "" };
    case "match_replace":
      return { kind: "match_replace", pattern: "", replacement: "", regex: false };
    default:
      return { kind } as ProcessingRule;
  }
}

export function IntruderPanel() {
  // Default to Burp's `§` paired marker. The backend `rebuild_request`
  // takes a `char` so the marker is swappable per-attack — legacy `~ID~`
  // recipes keep working as long as the Marker input is edited.
  const [url, setUrl] = useState("https://example.com/users/§ID§");
  const [method, setMethod] = useState("GET");
  const [marker, setMarker] = useState("§");
  const [mode, setMode] = useState<
    "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb" | "null"
  >("sniper");
  // Burp "Null payloads": attack-mode-Null fires the base template
  // this many times with markers stripped (inner content kept).
  // Decoupled from the payload-set `"null"` kind so changing one
  // doesn't surprise the other. Clamped engine-side to [1, 10_000].
  const [nullCount, setNullCount] = useState<number>(10);
  // Default-on: when the operator edits the URL, the Host header is
  // rewritten to match. Off for Host-header injection probes.
  const [updateHost, setUpdateHost] = useState(true);
  const urlRef = useRef<HTMLInputElement | null>(null);
  // Hidden `<input type="file">` for R118's `⬆ Load file` button
  // — using the ref so a visible button can trigger the native
  // file picker without rendering the ugly default input.
  const payloadFileInputRef = useRef<HTMLInputElement | null>(null);
  // Payload sets — one per Intruder "insertion point" in pitchfork /
  // cluster-bomb modes. Sniper / BatteringRam use just set[0]. Each
  // set carries its own type picker + per-type params so Burp's full
  // 4-mode matrix is reachable from the UI.
  const [payloadSets, setPayloadSets] = useState<PayloadSet[]>([
    makeDefaultPayloadSet("admin\nroot\ntest\n123\nalice\nbob"),
  ]);
  const [concurrency, setConcurrency] = useState(5);
  const [rate, setRate] = useState<number | null>(null);
  // Resource-pool knobs. Blank input ↔ null = feature disabled. All
  // round-trip in recipes alongside concurrency / rate.
  const [delayMs, setDelayMs] = useState<number | null>(null);
  const [delayJitterMs, setDelayJitterMs] = useState<number | null>(null);
  const [pauseOnErrorMs, setPauseOnErrorMs] = useState<number | null>(null);
  const [showPool, setShowPool] = useState(false);
  // Per-attack redirect policy. Mirrors Burp's "Redirections" option.
  // Defaults to never so raw 3xx responses are visible for probing.
  const [followRedirects, setFollowRedirects] = useState<
    "never" | "on_site" | "in_scope" | "always"
  >("never");
  // Burp's "Make payloads unique" — strips duplicate combos
  // client-safely via a HashSet in the engine's dispatch planner.
  const [deduplicatePayloads, setDeduplicatePayloads] = useState(false);
  // Burp "Grep - Extract" rules. Each one becomes a column in the
  // results table. Index 0 → column 1, etc. Shape mirrors backend
  // `ExtractRule { name, regex }`.
  const [extracts, setExtracts] = useState<Array<{ name: string; regex: string }>>(
    [],
  );
  const [showExtracts, setShowExtracts] = useState(false);
  // Multi grep-match rules. Each rule's `pattern` is compiled on the
  // backend as a case-insensitive regex (prefixed with `(?i)`) so
  // operators get Burp's default matching semantics; the per-row
  // `matched: Vec<bool>` indexed by rule position drives one column
  // per rule in the results table. Shape mirrors backend
  // `MatchRule { name, pattern }`.
  const [matches, setMatches] = useState<Array<{ name: string; pattern: string }>>(
    [],
  );
  const [showMatches, setShowMatches] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  const [results, setResults] = useState<any[]>([]);
  // Case-insensitive substring filter over the Intruder results
  // table. Matches across payload / status / url / extracted / error
  // / each `extracted_fields` entry. Mirrors Burp's results filter.
  const [resultsFilter, setResultsFilter] = useState("");
  const [status, setStatus] = useState<string>("");
  const [progress, setProgress] = useState<{ done: number; total: number }>({ done: 0, total: 0 });
  // Mirror of `JobHandle::pause` on the backend — flipped by the
  // Pause/Resume button and re-synced from each `intruder_poll` tick.
  const [paused, setPaused] = useState(false);
  // Keep the exact config used for the running / most recent attack so
  // we can reconstruct any row into a Repeater tab or export it to CSV.
  const [lastConfig, setLastConfig] = useState<any | null>(null);
  const poll = useRef<any>(null);

  // Burp-style status chip filter — multi-select Set, empty = any.
  // Buckets: 2xx / 3xx / 4xx / 5xx / ERR mirroring the existing
  // `.status-Nxx` CSS classes + the histogram builder below. The
  // chip strip lives under the toolbar and lets operators pivot to
  // just the 5xx rows (classic error-hunt) or just 4xx (auth probe)
  // with one click, instead of typing partial status codes into the
  // text filter.
  const [statusFilter, setStatusFilter] = useState<Set<string>>(() => new Set());

  function statusBucket(r: any): string {
    if (r.status == null) return r.error ? "ERR" : "—";
    return `${Math.floor(r.status / 100)}xx`;
  }

  // Apply the client-side text filter to the results table. Match is
  // a case-insensitive substring probed across every operator-visible
  // field so operators can grep for "500", "admin", "/users/42",
  // "timeout", or any extracted-field value with one input. Split
  // from the chip filter below so the chip counts stay accurate as
  // the text filter narrows the result set.
  const textFilteredResults = useMemo(() => {
    const q = resultsFilter.trim().toLowerCase();
    if (!q) return results;
    return results.filter((r) => {
      const parts: string[] = [];
      if (Array.isArray(r.payloads)) parts.push(r.payloads.join(" "));
      if (r.status != null) parts.push(String(r.status));
      if (r.url) parts.push(String(r.url));
      if (r.extracted) parts.push(String(r.extracted));
      if (r.error) parts.push(String(r.error));
      if (Array.isArray(r.extracted_fields)) {
        for (const v of r.extracted_fields) {
          if (v != null) parts.push(String(v));
        }
      }
      // Multi grep-match: let the operator type a rule's name to
      // narrow to rows where that rule fired. We push the rule
      // name (not an index) because the user types what they see.
      if (Array.isArray(r.matched) && matches.length > 0) {
        for (let i = 0; i < matches.length && i < r.matched.length; i++) {
          if (r.matched[i]) parts.push(matches[i].name || `match-${i + 1}`);
        }
      }
      return parts.join(" ").toLowerCase().includes(q);
    });
  }, [results, resultsFilter, matches]);

  // Bucket counts from the text-filtered rows so chip badges reflect
  // what the operator sees after search narrowing (matches R81's
  // Target Issues chip-count semantics).
  const bucketCounts = useMemo(() => {
    const c: Record<string, number> = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "ERR": 0 };
    for (const r of textFilteredResults) {
      const k = statusBucket(r);
      if (k in c) c[k]++;
    }
    return c;
  }, [textFilteredResults]);

  // Second filter layer — the chip strip. Empty set = any.
  const filteredResults = useMemo(() => {
    if (statusFilter.size === 0) return textFilteredResults;
    return textFilteredResults.filter((r) => statusFilter.has(statusBucket(r)));
  }, [textFilteredResults, statusFilter]);

  function toggleStatusBucket(k: string) {
    setStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  }
  // OOB-aware payload state. When non-empty, each row maps the payload
  // text back to the correlation id so we can post-run correlate hits.
  const [oobTokens, setOobTokens] = useState<OobToken[]>([]);
  const [oobHits, setOobHits] = useState<OobBatchHit[]>([]);
  const [oobBusy, setOobBusy] = useState(false);
  // Built-in payload library catalog — fetched once on mount.
  const [library, setLibrary] = useState<PayloadLibraryEntry[]>([]);
  const [libraryBusy, setLibraryBusy] = useState(false);
  // Saved attack recipes — refreshed after each save / delete so the
  // dropdown stays current without full-panel re-renders.
  const [recipes, setRecipes] = useState<IntruderRecipeView[]>([]);
  // Payload-processing chain (Burp "Payload processing"). Applied in
  // order to every payload before substitution. Default empty.
  const [processingRules, setProcessingRules] = useState<ProcessingRule[]>([]);
  const [processingExpanded, setProcessingExpanded] = useState(false);
  // Positions preview (Burp "Positions" tab) — read-only reconstructed
  // raw-wire request showing where markers will become insertion
  // points. Default expanded because operators glance here constantly.
  const [positionsExpanded, setPositionsExpanded] = useState(true);
  // Right-click context menu for an Intruder results row. `data` is
  // the row we're acting on so the menu items can read url / payloads
  // / extracted without extra plumbing.
  const [rowMenu, setRowMenu] = useState<MenuState<any> | null>(null);
  // Baseline reference for the ΔLen column (Burp "Comparator"
  // behaviour). When `null`, the first `filteredResults` row with a
  // non-null `length` acts as the implicit baseline — matches Burp's
  // default where the first request is treated as the reference. The
  // operator can right-click any row → "Set as baseline" to pin a
  // specific index; "Clear baseline" reverts to the implicit first
  // row. Reset on every `setResults([])` so a fresh attack doesn't
  // inherit a stale pin from the previous run.
  const [baselineIndex, setBaselineIndex] = useState<number | null>(null);
  // Baseline length for the ΔLen column. When `baselineIndex` is set
  // and a matching row exists in `filteredResults`, use its length;
  // otherwise fall back to the first row with a non-null length so
  // operators get a sensible delta out of the box. Resolved AFTER
  // the filter so rows filtered out don't silently skew every delta
  // — if a filtered pin disappears, the implicit first-row fallback
  // takes over.
  const baselineLength = useMemo<number | null>(() => {
    if (baselineIndex != null) {
      const row = filteredResults.find((r) => r.index === baselineIndex);
      if (row && typeof row.length === "number") return row.length;
    }
    for (const r of filteredResults) {
      if (typeof r.length === "number") return r.length;
    }
    return null;
  }, [filteredResults, baselineIndex]);
  // Burp "Grep - Match" string. Case-insensitive substring the backend
  // probes against each response body. Empty string = feature off.
  const [grepMatch, setGrepMatch] = useState("");

  useEffect(() => {
    api
      .payloadsLibraryList()
      .then(setLibrary)
      .catch(() => setLibrary([]));
    void refreshRecipes();
  }, []);

  async function refreshRecipes() {
    try {
      setRecipes(await api.intruderRecipeList());
    } catch {
      setRecipes([]);
    }
  }

  // ---- Payload-position toolbar ------------------------------------------

  /** Wrap the current selection in the URL input with the active
   *  marker pair, e.g. `§abc§`. When the operator has no selection,
   *  we insert `§§` at the caret so they can type the position name
   *  between the marks. Mirrors Burp's "Add §" behaviour. */
  function addMarker() {
    const el = urlRef.current;
    if (!el) return;
    const start = el.selectionStart ?? url.length;
    const end = el.selectionEnd ?? url.length;
    const inner = url.slice(start, end);
    const next = `${url.slice(0, start)}${marker}${inner}${marker}${url.slice(end)}`;
    setUrl(next);
    // Place caret inside the newly-added markers so the operator can
    // start typing a position name immediately.
    requestAnimationFrame(() => {
      el.focus();
      const caret = start + marker.length + inner.length;
      el.setSelectionRange(caret, caret);
    });
  }

  /** Strip every marker char from the URL. We don't attempt to parse
   *  payload-position names — the operator reset is the goal. */
  function clearMarkers() {
    if (!marker) return;
    // Escape in case the marker is a regex metachar.
    const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(esc, "g");
    setUrl(url.replace(re, ""));
  }

  /** Auto-detect common insertion points and wrap them with markers.
   *  Rules (applied in order; already-marked sections are skipped):
   *    1. Query-string values  — `?name=VALUE` and `&name=VALUE`
   *    2. Form body values     — `name=VALUE` segments following a `?`
   *                              where `?` acts as a separator for the
   *                              URL in our current flat model.
   *    3. Cookie values        — captured when a `Cookie: name=VALUE`
   *                              header is present in the URL text.
   *    4. Authorization tokens — `Bearer <token>` payload.
   *  Only the URL field is scanned; `method`/body aren't editable here
   *  in a raw-request sense, so the markers live where the operator
   *  can see them. */
  function autoMarkers() {
    if (!marker) return;
    // Already-marked sections look like `§...§`; skip them so a second
    // Auto click is idempotent.
    const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const markedPair = new RegExp(`${esc}[^${esc}]*${esc}`, "g");
    // Replace query-string values. The regex captures `name=` and the
    // value up to `&` or end-of-string; we rebuild with markers around
    // the value only if the value isn't already wrapped.
    const next = url.replace(/([?&])([^=&]+)=([^&]*)/g, (full, sep, name, value) => {
      // If the value is empty, insert `§§` so the operator can fill in.
      if (!value) return `${sep}${name}=${marker}${marker}`;
      // If value already contains a marker, leave it alone.
      if (markedPair.test(`${marker}${value}${marker}`)) return full;
      return `${sep}${name}=${marker}${value}${marker}`;
    });
    setUrl(next);
  }

  // ---- Positions preview --------------------------------------------------

  /** Reconstruct the raw-wire HTTP/1.1 request from the current UI
   *  state and split it into alternating plain / marker-pair segments
   *  so the preview can colour the insertion points. Burp's Positions
   *  tab shows the same thing (its is editable; ours is read-only
   *  because our template is URL-driven). */
  function renderPositionsPreview(): {
    segments: Array<{ text: string; isMarker: boolean }>;
    positionCount: number;
  } {
    // Parse the URL once, with markers stripped so new URL() doesn't
    // choke on `§`. The stripped version is only used for host/port
    // extraction; the preview itself keeps markers in-place.
    const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const markedPair = new RegExp(`${esc}[^${esc}]*${esc}`, "g");
    const scheme = url.startsWith("https") ? "https" : "http";
    let host = "example.com";
    let port = scheme === "https" ? 443 : 80;
    let path = "/";
    try {
      const safe = url.replace(markedPair, "MARKER");
      const u = new URL(safe);
      host = u.hostname || host;
      port = Number(u.port) || port;
      path = (u.pathname || "/") + (u.search || "");
      // Markers in path/search were replaced by "MARKER"; put them
      // back by slicing the original URL from the first `/` after the
      // `scheme://authority` prefix. This preserves markers verbatim
      // regardless of regex-special chars in `marker`.
      const protoEnd = url.indexOf("://");
      if (protoEnd >= 0) {
        const afterProto = url.slice(protoEnd + 3);
        const firstSlash = afterProto.indexOf("/");
        if (firstSlash >= 0) {
          path = afterProto.slice(firstSlash);
        }
      }
    } catch {
      host = url.split("://")[1]?.split("/")[0] || host;
      path = url.replace(/^https?:\/\/[^/]+/, "") || "/";
    }
    const portStr =
      (scheme === "https" && port === 443) || (scheme === "http" && port === 80)
        ? ""
        : `:${port}`;
    // Build the request lines. Keep headers minimal + Burp-style
    // defaults — these mirror what IntruderJob::start actually sends
    // (plus User-Agent / Accept, which the Rust client supplies).
    const lines: string[] = [];
    lines.push(`${method} ${path} HTTP/1.1`);
    if (updateHost) {
      lines.push(`Host: ${host}${portStr}`);
    } else {
      lines.push(`Host: <manual — Update Host checkbox off>`);
    }
    lines.push(`User-Agent: BurpFree/0.1`);
    lines.push(`Accept: */*`);
    lines.push(`Accept-Encoding: gzip, deflate`);
    lines.push(`Connection: close`);
    lines.push(``);
    // We don't carry a body in the UI yet — reserve the slot so the
    // preview looks like a real raw request.
    lines.push(``);
    const raw = lines.join("\n");
    // Split the whole raw text into alternating plain / marker-pair
    // segments. Each pair becomes a highlighted `<span>` on render.
    const segments: Array<{ text: string; isMarker: boolean }> = [];
    const re = new RegExp(`${esc}[^${esc}]*${esc}`, "g");
    let lastIdx = 0;
    let m: RegExpExecArray | null;
    let positionCount = 0;
    while ((m = re.exec(raw)) !== null) {
      if (m.index > lastIdx) {
        segments.push({ text: raw.slice(lastIdx, m.index), isMarker: false });
      }
      segments.push({ text: m[0], isMarker: true });
      positionCount += 1;
      lastIdx = m.index + m[0].length;
    }
    if (lastIdx < raw.length) {
      segments.push({ text: raw.slice(lastIdx), isMarker: false });
    }
    return { segments, positionCount };
  }

  // ---- Payload-set assembly ---------------------------------------------

  /** Which sets to send to the backend. Sniper / BatteringRam only
   *  use set[0]; the backend rejects extras. Pitchfork / ClusterBomb
   *  use every set, one per insertion point. */
  function activePayloadSets(): PayloadSet[] {
    if (mode === "pitchfork" || mode === "cluster_bomb") {
      return payloadSets;
    }
    return payloadSets.slice(0, 1);
  }

  /** Count how many payloads the set emits. Used by the per-set
   *  live preview + the mode-level iteration estimate below. */
  function payloadSetSize(s: PayloadSet): number {
    switch (s.type) {
      case "numbers": {
        const step = s.numStep || 1;
        if ((step > 0 && s.numTo < s.numFrom) || (step < 0 && s.numTo > s.numFrom)) {
          return 0;
        }
        return Math.abs(Math.floor((s.numTo - s.numFrom) / step)) + 1;
      }
      case "null":
        return Math.max(0, s.nullCount | 0);
      case "list":
      default:
        return s.list.split(/\r?\n/).filter((x) => x.length > 0).length;
    }
  }

  /** Serialise a single PayloadSet into the shape
   *  `IntruderConfig.payloads[i]` expects. Keep this one function so
   *  `start()` + `buildCurrentConfig()` + recipes can't drift. */
  function buildPayloadProvider(s: PayloadSet): any {
    switch (s.type) {
      case "numbers": {
        const pad = Math.max(0, s.numPadTo | 0);
        return {
          kind: "numbers",
          from: s.numFrom | 0,
          to: s.numTo | 0,
          step: s.numStep || 1, // zero step → infinite loop on backend; coerce to 1
          pad_to: pad > 0 ? pad : null,
        };
      }
      case "null":
        return { kind: "null", count: Math.max(0, s.nullCount | 0) };
      case "list":
      default: {
        const list = s.list.split(/\r?\n/).filter((x) => x.length > 0);
        return { kind: "list", items: list };
      }
    }
  }

  /** Full array of payload providers to emit to the backend. */
  function buildPayloadProviders(): any[] {
    return activePayloadSets().map(buildPayloadProvider);
  }

  // ---- Payload-set state helpers ----------------------------------------

  function updatePayloadSet(idx: number, patch: Partial<PayloadSet>) {
    setPayloadSets((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)),
    );
  }

  function addPayloadSet() {
    // Hard-cap at 8 sets so the UI stays usable. Burp has no limit
    // but realistic ClusterBomb attacks blow up combinatorially so
    // this encourages operators to think.
    setPayloadSets((prev) =>
      prev.length >= 8 ? prev : [...prev, makeDefaultPayloadSet()],
    );
  }

  function removePayloadSet(idx: number) {
    if (idx === 0) return; // never remove the primary set
    setPayloadSets((prev) => prev.filter((_, i) => i !== idx));
  }

  /*  R190: Clone a payload set — deep-copy with insert right
   *  after the source. Pitchfork / ClusterBomb operators often
   *  want two payload sets with the same base + slight tweaks
   *  (e.g. one wordlist with path chars, one without). Hard-
   *  capped at 8 sets to match addPayloadSet's limit. */
  function clonePayloadSet(idx: number) {
    setPayloadSets((prev) => {
      if (prev.length >= 8) return prev;
      const src = prev[idx];
      if (!src) return prev;
      const clone: PayloadSet = JSON.parse(JSON.stringify(src));
      const next = [...prev];
      next.splice(idx + 1, 0, clone);
      return next;
    });
  }

  // ---- Processing rules helpers ------------------------------------------

  function addProcessingRule(kind: ProcessingRule["kind"]) {
    setProcessingRules((prev) => [...prev, newRule(kind)]);
    setProcessingExpanded(true);
  }

  function removeProcessingRule(idx: number) {
    setProcessingRules((prev) => prev.filter((_, i) => i !== idx));
  }

  function moveProcessingRule(idx: number, delta: -1 | 1) {
    setProcessingRules((prev) => {
      const target = idx + delta;
      if (target < 0 || target >= prev.length) return prev;
      const copy = prev.slice();
      [copy[idx], copy[target]] = [copy[target], copy[idx]];
      return copy;
    });
  }

  function updateProcessingRule(idx: number, patch: Partial<ProcessingRule>) {
    setProcessingRules((prev) =>
      prev.map((r, i) => (i === idx ? ({ ...r, ...patch } as ProcessingRule) : r)),
    );
  }

  /** Serialise the current UI into a config blob the backend can
   *  persist. Mirrors the shape built inside `start()` so a loaded
   *  recipe round-trips cleanly through the save / load dance. */
  function buildCurrentConfig() {
    let host = "";
    let port = 80;
    try {
      // Markers in the authority would break parsing — replace them
      // with a stand-in so we still extract host/port correctly.
      const safe = url.replace(/§[^§]*§/g, "MARKER");
      const u = new URL(safe);
      host = u.hostname;
      port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
    } catch {
      host = url.split("://")[1]?.split("/")[0] || "";
    }
    const headerItems: Array<{ name: string; value: string }> = [
      { name: "Connection", value: "close" },
    ];
    if (updateHost) {
      headerItems.unshift({
        name: "Host",
        value: host + (port === 80 || port === 443 ? "" : `:${port}`),
      });
    }
    return {
      template: {
        id: 0,
        method,
        scheme: url.startsWith("https") ? "https" : "http",
        host,
        port,
        path: url.replace(/^https?:\/\/[^/]+/, "") || "/",
        http_version: "Http11",
        headers: { items: headerItems },
        body: "",
        created_at_ms: Date.now(),
        source: "intruder",
        parent_id: null,
        annotation: "",
        comment: "",
      },
      url,
      marker,
      mode,
      update_host: updateHost,
      payloads: buildPayloadProviders(),
      concurrency,
      rate_per_sec: rate,
      delay_ms: delayMs,
      delay_jitter_ms: delayJitterMs,
      pause_on_error_ms: pauseOnErrorMs,
      deduplicate_payloads: deduplicatePayloads,
      null_count: mode === "null" ? nullCount : null,
      timeout: { secs: 10, nanos: 0 },
      retries: 0,
      http: {
        upstream: { url: "", username: null, password: null },
        timeout: { secs: 10, nanos: 0 },
        max_body_bytes: 10_000_000,
        transparent_decompress: true,
        validate_tls: false,
        follow_redirects: followRedirects,
        max_redirect_hops: 5,
      },
      extract_regex: null,
      extracts: extracts.filter((e) => e.name.trim() && e.regex.trim()),
      grep_matches: matches.filter((m) => m.name.trim() && m.pattern.trim()),
      status_filter: {
        include_status_min: null,
        include_status_max: null,
        exclude_status: [],
      },
      payload_processing: processingRules,
      grep_match: grepMatch.trim() || null,
    };
  }

  async function saveRecipe() {
    const name = prompt("Recipe name", `recipe-${recipes.length + 1}`);
    if (!name) return;
    try {
      await api.intruderRecipeSave(name.trim(), buildCurrentConfig());
      await refreshRecipes();
    } catch (e) {
      alert(`Save failed: ${e}`);
    }
  }

  async function loadRecipe(name: string) {
    if (!name) return;
    try {
      const cfg = await api.intruderRecipeLoad(name);
      // Restore the user-visible fields from the loaded config. We
      // deliberately take `url` from the recipe (recorded alongside
      // the template) rather than re-building it from the template,
      // because the operator may have typed a non-canonical URL.
      if (typeof cfg.url === "string") setUrl(cfg.url);
      if (typeof cfg.method === "string") setMethod(cfg.method);
      else if (cfg.template?.method) setMethod(cfg.template.method);
      if (typeof cfg.marker === "string") setMarker(cfg.marker);
      if (typeof cfg.mode === "string") setMode(cfg.mode);
      if (typeof cfg.update_host === "boolean") setUpdateHost(cfg.update_host);
      if (typeof cfg.concurrency === "number") setConcurrency(cfg.concurrency);
      setRate(typeof cfg.rate_per_sec === "number" ? cfg.rate_per_sec : null);
      setDelayMs(typeof cfg.delay_ms === "number" ? cfg.delay_ms : null);
      setDelayJitterMs(
        typeof cfg.delay_jitter_ms === "number" ? cfg.delay_jitter_ms : null,
      );
      setPauseOnErrorMs(
        typeof cfg.pause_on_error_ms === "number" ? cfg.pause_on_error_ms : null,
      );
      if (Array.isArray(cfg.extracts)) {
        setExtracts(
          cfg.extracts
            .filter((e: any) => typeof e?.name === "string" && typeof e?.regex === "string")
            .map((e: any) => ({ name: e.name, regex: e.regex })),
        );
      } else {
        setExtracts([]);
      }
      if (Array.isArray(cfg.grep_matches)) {
        setMatches(
          cfg.grep_matches
            .filter((m: any) => typeof m?.name === "string" && typeof m?.pattern === "string")
            .map((m: any) => ({ name: m.name, pattern: m.pattern })),
        );
      } else {
        setMatches([]);
      }
      const fr = cfg.http?.follow_redirects;
      if (fr === "never" || fr === "on_site" || fr === "in_scope" || fr === "always") {
        setFollowRedirects(fr);
      } else {
        setFollowRedirects("never");
      }
      setDeduplicatePayloads(cfg.deduplicate_payloads === true);
      // Null-mode iteration count (Burp's "Null payloads" attack type).
      // Only meaningful when mode === "null"; legacy recipes have no
      // field so we fall back to the current default (10).
      if (typeof cfg.null_count === "number" && cfg.null_count > 0) {
        setNullCount(Math.max(1, Math.min(10000, cfg.null_count | 0)));
      }
      // Restore the payload sets array — map each provider shape
      // back into a PayloadSet. Unknown kinds fall back to an empty
      // list set so the recipe round-trips without crashing.
      const providers = Array.isArray(cfg.payloads) ? cfg.payloads : [];
      if (providers.length > 0) {
        const sets: PayloadSet[] = providers.map((p: any) => {
          const base = makeDefaultPayloadSet();
          if (p?.kind === "numbers") {
            return {
              ...base,
              type: "numbers",
              numFrom: typeof p.from === "number" ? p.from : base.numFrom,
              numTo: typeof p.to === "number" ? p.to : base.numTo,
              numStep: typeof p.step === "number" ? p.step : base.numStep,
              numPadTo:
                typeof p.pad_to === "number" ? p.pad_to : base.numPadTo,
            };
          }
          if (p?.kind === "null") {
            return {
              ...base,
              type: "null",
              nullCount:
                typeof p.count === "number" ? p.count : base.nullCount,
            };
          }
          // Default + unknown kinds → list.
          const items = Array.isArray(p?.items) ? (p.items as string[]) : [];
          return { ...base, type: "list", list: items.join("\n") };
        });
        setPayloadSets(sets);
      } else {
        setPayloadSets([makeDefaultPayloadSet()]);
      }
      // Restore processing chain if the recipe carries one. We keep
      // only known rule kinds so a hand-edited recipe can't crash the
      // panel with an unexpected variant.
      if (Array.isArray(cfg.payload_processing)) {
        const known = new Set(PROCESSING_RULE_CATALOG.map((r) => r.kind));
        const rules = cfg.payload_processing
          .filter((r: any): r is ProcessingRule => r && typeof r.kind === "string" && known.has(r.kind))
          .map((r: any) => ({ ...r }) as ProcessingRule);
        setProcessingRules(rules);
        if (rules.length > 0) setProcessingExpanded(true);
      } else {
        setProcessingRules([]);
      }
      // Grep-match substring (new in Round 24).
      if (typeof cfg.grep_match === "string") setGrepMatch(cfg.grep_match);
      else setGrepMatch("");
    } catch (e) {
      alert(`Load failed: ${e}`);
    }
  }

  async function deleteRecipe(name: string) {
    if (!confirm(`Delete recipe '${name}'?`)) return;
    try {
      await api.intruderRecipeDelete(name);
      await refreshRecipes();
    } catch (e) {
      alert(`Delete failed: ${e}`);
    }
  }

  // Cross-panel handoff: other tools (History, Repeater, Scanner issues)
  // can dispatch `burpfree:intruder-load` to pre-fill the URL/method on
  // this panel without plumbing a prop tree. detail: {url, method,
  // transactionId?}. We bump a visible banner so the operator knows
  // where the inputs came from.
  const [handoffBanner, setHandoffBanner] = useState<string | null>(null);
  useEffect(() => {
    const onLoad = (e: Event) => {
      const detail = (e as CustomEvent<{ url?: string; method?: string; transactionId?: number }>).detail;
      if (!detail?.url) return;
      // Only overwrite the URL + method — leave payload list / marker /
      // mode intact so the operator can keep tweaking a running recipe.
      // Append `~ID~` marker if the URL has none so the attack is
      // runnable immediately.
      // Insert a marker if the handoff URL doesn't already have one.
      // We check against both common marker chars so the matching stays
      // forgiving across the legacy `~ID~` and new Burp-style `§ID§`.
      const hasMarker = /[§~]/.test(detail.url);
      const m = marker || "§";
      setUrl(
        hasMarker
          ? detail.url
          : detail.url
              .replace(/\?/, `?id=${m}ID${m}&`)
              .replace(/^([^?]+)$/, `$1?id=${m}ID${m}`),
      );
      if (detail.method) setMethod(detail.method);
      setHandoffBanner(
        detail.transactionId
          ? `Loaded from tx #${detail.transactionId}`
          : "Loaded from another panel",
      );
    };
    window.addEventListener("burpfree:intruder-load", onLoad as EventListener);
    return () => window.removeEventListener("burpfree:intruder-load", onLoad as EventListener);
  }, []);

  async function loadLibrary(id: string) {
    if (!id) return;
    setLibraryBusy(true);
    try {
      const content = await api.payloadsLibraryLoad(id);
      // Replace set[0]'s textarea verbatim. We don't merge so the
      // operator always sees exactly what the library contains.
      // Force set[0] to list mode in case it was mid-switch.
      updatePayloadSet(0, { type: "list", list: content.trim() });
    } catch (e) {
      alert(`Load library failed: ${e}`);
    } finally {
      setLibraryBusy(false);
    }
  }

  async function start() {
    try {
      // URL parsing — `§` isn't a valid hostname char so operators keep
      // markers in the path/query; the `new URL(...)` call will throw if
      // they stray into the authority. We let it bubble up as a friendly
      // alert rather than silently rewriting.
      const parsed = new URL(url.replace(/§[^§]*§/g, "MARKER"));
      // Headers: Connection: close is always present. Host only when the
      // operator wants it auto-managed; off = don't set it so Host-header
      // injection probes don't fight our template.
      const headerItems: Array<{ name: string; value: string }> = [
        { name: "Connection", value: "close" },
      ];
      if (updateHost) {
        headerItems.unshift({ name: "Host", value: parsed.host });
      }
      const config = {
        template: {
          id: 0,
          method,
          scheme: url.startsWith("https") ? "https" : "http",
          host: parsed.hostname,
          port: Number(parsed.port) || (url.startsWith("https") ? 443 : 80),
          path: url.replace(/^https?:\/\/[^/]+/, ""),
          http_version: "Http11",
          headers: { items: headerItems },
          body: "",
          created_at_ms: Date.now(),
          source: "intruder",
          parent_id: null,
          annotation: "",
          comment: "",
        },
        marker,
        mode,
        payloads: buildPayloadProviders(),
        concurrency,
        rate_per_sec: rate,
        delay_ms: delayMs,
        delay_jitter_ms: delayJitterMs,
        pause_on_error_ms: pauseOnErrorMs,
        deduplicate_payloads: deduplicatePayloads,
        null_count: mode === "null" ? nullCount : null,
        timeout: { secs: 10, nanos: 0 },
        retries: 0,
        http: {
          upstream: { url: "", username: null, password: null },
          timeout: { secs: 10, nanos: 0 },
          max_body_bytes: 10_000_000,
          transparent_decompress: true,
          validate_tls: false,
          follow_redirects: followRedirects,
          max_redirect_hops: 5,
        },
        extract_regex: null,
        extracts: extracts.filter((e) => e.name.trim() && e.regex.trim()),
        grep_matches: matches.filter((m) => m.name.trim() && m.pattern.trim()),
        status_filter: {
          include_status_min: null,
          include_status_max: null,
          exclude_status: [],
        },
        payload_processing: processingRules,
        grep_match: grepMatch.trim() || null,
      };
      const id = await api.intruderStart(config);
      setJobId(id);
      setResults([]);
      setBaselineIndex(null);
      setProgress({ done: 0, total: 0 });
      setLastConfig(config);
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function cancel() {
    if (jobId == null) return;
    await api.intruderCancel(jobId);
  }

  /** Toggle the dispatcher pause flag — Burp's "Pause attack".
   *  Optimistic update: flip local state immediately so the Pause /
   *  Resume label swaps without waiting for the next poll tick, and
   *  the backend confirms on the next 500ms poll. */
  async function togglePause() {
    if (jobId == null) return;
    const next = !paused;
    setPaused(next);
    try {
      if (next) await api.intruderPause(jobId);
      else await api.intruderResume(jobId);
    } catch (e) {
      // On failure, revert optimistic state so the UI matches the
      // backend. Likely cause: job finished between poll and click.
      setPaused(!next);
      console.warn("pause toggle failed:", e);
    }
  }

  // R331: Ctrl+Enter starts the attack (or stops it when running).
  // Matches Repeater's Ctrl+Enter-to-send convention so operators
  // moving between the two panels get a consistent "fire the thing
  // I've been configuring" muscle memory. Guards mirror R153
  // Ctrl+Space: text-input skip so Ctrl+Enter inside the payload
  // textarea / URL field keeps native newline insertion; no Alt
  // combo so the Alt+1..6 mode ladder (R186+) stays free.
  useEffect(() => {
    function onFireKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key !== "Enter") return;
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
      // Toggle semantics: running → cancel; otherwise → start.
      if (jobId != null && status === "running") {
        void cancel();
      } else {
        void start();
      }
    }
    document.addEventListener("keydown", onFireKey);
    return () => document.removeEventListener("keydown", onFireKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, status]);

  /*  R153: Ctrl+Space toggles pause/resume while an attack is
   *  running. Only fires when:
   *    - a job is active (jobId != null)
   *    - that job is currently `running` (the toolbar button is
   *      enabled under the same conditions)
   *    - the active element is NOT a text input / textarea /
   *      contenteditable (Ctrl+Space is "accept suggestion" or
   *      "trigger IME" in many editors — stealing it there would
   *      break the operator's muscle memory in the payload box or
   *      target URL field).
   *  Document-level keydown mirrors the RepeaterPanel pattern. */
  useEffect(() => {
    function onPauseKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.code !== "Space") return;
      if (jobId == null || status !== "running") return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        if (el.isContentEditable) return;
      }
      e.preventDefault();
      void togglePause();
    }
    document.addEventListener("keydown", onPauseKey);
    return () => document.removeEventListener("keydown", onPauseKey);
    // togglePause is stable-enough — it reads jobId/paused via
    // closure every call. Including it in deps would thrash the
    // listener on every poll tick; the status/jobId deps catch the
    // enablement transitions we actually care about.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, status, paused]);

  /*  R231: Alt+1..4 switches attack mode without the mouse — one
   *  key per mode, matching the <select> dropdown's order:
   *    Alt+1 → sniper
   *    Alt+2 → battering_ram
   *    Alt+3 → pitchfork
   *    Alt+4 → cluster_bomb
   *  Null mode (Alt+5) is deliberately NOT keyboard-mapped since
   *  it fires the base template N times — operators who want it
   *  pick it from the dropdown deliberately. Guards: plain Alt
   *  only (no co-modifiers); text-input focus skip (so Alt+N in
   *  the URL doesn't flip modes). */
  useEffect(() => {
    const MODE_BY_DIGIT: Record<
      string,
      "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
    > = {
      "1": "sniper",
      "2": "battering_ram",
      "3": "pitchfork",
      "4": "cluster_bomb",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const m = MODE_BY_DIGIT[e.key];
      if (!m) return;
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
      setMode(m);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  /*  R204: Esc clears every payload marker from the URL. Mirror of
   *  R201 (History search clear) + R202 (Scanner chip clear) — the
   *  one-key reset after misplacing markers while probing a tricky
   *  endpoint. Gates:
   *    - no modifiers (pure Esc; Ctrl+Esc / Shift+Esc bail out)
   *    - URL actually contains a `marker…marker` pair (so Esc with
   *      no markers in the URL is a true no-op, letting other Esc
   *      handlers — modals / popovers — react normally)
   *    - focus is NOT inside an INPUT / TEXTAREA / SELECT /
   *      contenteditable (so Esc inside the URL input or payload
   *      editor doesn't blow away the operator's typing — the
   *      "Clear" button in the toolbar is still the explicit path
   *      for that case). */
  useEffect(() => {
    function onEsc(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
      if (!marker) return;
      const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const markedPair = new RegExp(`${esc}[^${esc}]*${esc}`);
      if (!markedPair.test(url)) return;
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
      clearMarkers();
    }
    document.addEventListener("keydown", onEsc);
    return () => document.removeEventListener("keydown", onEsc);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, marker]);

  // R388: Alt+Shift+U copies every filtered results row's URL to
  // clipboard — keyboard companion to R384's "📋 Copy URLs"
  // toolbar button. Closes the cross-panel Alt+Shift+U family:
  // Repeater R386 copies all tab URLs, History R387 copies
  // bulk-selected URLs, Intruder R388 copies filtered results'
  // URLs. **Scope** `filteredResults` so both text + chip filter
  // layers are honoured — matches R384's button exactly. **No
  // bulk-selection concept** in Intruder results yet (would be
  // a sizeable refactor), so "every filtered row" is the natural
  // scope. **Mechanism** mirrors R384: filter → Set dedupe →
  // sort alpha → clipboard write with smart fallback alerts.
  // **Guards** Alt+Shift only, text-input focus skip. **No-op**
  // when there are no results to copy — unlike R384 which
  // surfaces an alert, the keystroke version stays silent so it
  // can be spammed safely while a job ramps up.
  useEffect(() => {
    function onCopyUrlsKey(e: KeyboardEvent) {
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
      if (filteredResults.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(
              filteredResults
                .map((r) => (r.url ?? "").trim())
                .filter((s) => s.length > 0),
            ),
          ).sort();
          if (uniq.length === 0) return;
          await copyToClipboard(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onCopyUrlsKey);
    return () => document.removeEventListener("keydown", onCopyUrlsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredResults]);

  // R418: Alt+Shift+C clears every results-table row (with confirm
  // when non-empty) + resets the baseline pin + wipes the results
  // filter. Keyboard version of the "Clear results" toolbar button.
  // Operators doing iterative attack tuning (adjust payload set →
  // run → look at results → adjust → re-run) often want a fast
  // table-reset between runs to avoid eyeballing stale rows mixed
  // with new ones. **Letter choice** C = Clear. **Guards** Alt+Shift
  // only, text-input focus skip. **Confirm gate** fires `confirm()`
  // when `results.length > 0` — mirrors the button's gate exactly
  // so operators can't accidentally wipe 500 rows with one keystroke.
  // **No-op silent** when results is empty — the keystroke stays
  // safe to spam on a fresh / cleared attack panel.
  useEffect(() => {
    function onClearResultsKey(e: KeyboardEvent) {
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
      if (results.length === 0) return;
      e.preventDefault();
      if (
        !confirm(
          `Clear ${results.length} result row${results.length === 1 ? "" : "s"}?`,
        )
      )
        return;
      setResults([]);
      setBaselineIndex(null);
      setResultsFilter("");
    }
    document.addEventListener("keydown", onClearResultsKey);
    return () =>
      document.removeEventListener("keydown", onClearResultsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [results.length]);

  // R393: Alt+Shift+P copies every filtered results row's payload
  // text to clipboard — keyboard companion to R380's "📋 Copy
  // payloads" toolbar button. Pairs with R388 Alt+Shift+U (filtered
  // URLs) so the Intruder keyboard surface mirrors the panel's
  // existing "📋 Copy payloads" + "📋 Copy URLs" button pair:
  // Alt+Shift+U for URLs, Alt+Shift+P for Payloads. **Scope**
  // `filteredResults` so text + chip filter layers are honoured.
  // **Format** matches R380: multi-position attacks (cluster bomb
  // / pitchfork) join each row's positions with " · " so the
  // full payload set lands on one line. **Mechanism** map
  // r.payloads → join " · " → Set dedupe → sort alpha → clipboard
  // write. **Guards** Alt+Shift only, text-input focus skip.
  // **No-op silent** when no results — matches R388's spam-safe
  // contract.
  useEffect(() => {
    function onCopyPayloadsKey(e: KeyboardEvent) {
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
      if (filteredResults.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(
              filteredResults
                .map((r) =>
                  Array.isArray(r.payloads) ? r.payloads.join(" · ") : "",
                )
                .filter((s) => s.length > 0),
            ),
          ).sort();
          if (uniq.length === 0) return;
          await copyToClipboard(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onCopyPayloadsKey);
    return () => document.removeEventListener("keydown", onCopyPayloadsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredResults]);

  /** Compose a minimal raw-wire representation of an Intruder results
   *  row so the Copy-as builders have something to parse. We don't
   *  have the real response-era headers here (the row was emitted
   *  before interception middleware ran), so we synthesise the
   *  essentials — method + path + Host + Connection — and let the
   *  copy builders drop Host/Content-Length etc. themselves. */
  function buildRowRaw(row: { url: string; payloads: string[] }): string {
    const method = (lastConfig?.template?.method as string) || "GET";
    let path = "/";
    let host = "";
    try {
      const u = new URL(row.url);
      path = (u.pathname || "/") + (u.search || "");
      host = u.host;
    } catch {
      // Non-standard URL; fall back to the raw string.
      path = row.url;
    }
    const lines = [
      `${method} ${path} HTTP/1.1`,
      host ? `Host: ${host}` : "",
      "Connection: close",
      "",
      "",
    ].filter((s, i) => s.length > 0 || i >= 3);
    return lines.join("\r\n");
  }

  async function copyRowAs(
    row: { url: string; payloads: string[] },
    kind: "curl" | "powershell" | "python" | "fetch",
  ) {
    try {
      const raw = buildRowRaw(row);
      const req = fromUrlAndRaw(row.url, raw);
      const text =
        kind === "curl"
          ? buildCurl(req)
          : kind === "powershell"
            ? buildPowerShell(req)
            : kind === "python"
              ? buildPython(req)
              : buildFetch(req);
      await copyToClipboard(text);
    } catch (e) {
      alert(`Copy failed: ${e}`);
    }
  }

  function sendRowToComparer(row: { url: string; payloads: string[] }) {
    // Comparer accepts raw text; feed it the reconstructed request
    // so operators can diff two attack rows side-by-side.
    const raw = buildRowRaw(row);
    window.dispatchEvent(
      new CustomEvent("burpfree:comparer-load", {
        detail: { slot: "left", text: raw, label: `intruder #${row.payloads.join(" / ") || "(empty)"}` },
      }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
    );
  }

  async function sendRowPayloadToDecoder(row: { payloads: string[] }) {
    // Decoder reads from the clipboard on panel focus; copy the
    // joined payloads so chained transforms can run on them.
    const text = (row.payloads ?? []).join(" ").trim();
    if (!text) {
      alert("Row has no payload text to send to Decoder.");
      return;
    }
    try {
      await copyToClipboard(text);
    } catch (e) {
      console.warn("clipboard write failed", e);
    }
    window.dispatchEvent(
      new CustomEvent("burpfree:decoder-load", { detail: { text } }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "decoder" } }),
    );
  }

  async function sendRowToRepeater(row: { payloads: string[] }) {
    if (!lastConfig) {
      alert("No attack config in state — start an attack first.");
      return;
    }
    try {
      const tabId = await api.intruderResultToRepeater(
        lastConfig,
        row.payloads,
        `intruder: ${row.payloads.join(" / ") || "(empty)"}`,
      );
      // Navigate to Repeater so the user sees the new tab.
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
      console.log("intruder → repeater tab", tabId);
    } catch (e) {
      alert(`Send to Repeater failed: ${e}`);
    }
  }

  function sendResultsToSequencer() {
    // Prefer the extracted field (set by `extract_regex` on each row);
    // fall back to the payload text so operators can at least run a
    // "payload echo" analysis on sniper runs that didn't configure
    // an extractor. Honours the current filter so operators can
    // sequence just the matching subset.
    const tokens = filteredResults
      .map((r) => {
        const extracted = (r.extracted ?? "").trim();
        if (extracted) return extracted;
        const payloads = Array.isArray(r.payloads) ? r.payloads : [];
        return payloads.join(" ").trim();
      })
      .filter((s) => s.length > 0);
    if (tokens.length === 0) {
      alert(
        "No tokens to send — run an attack first (and set an Extract regex if the token appears in the response body).",
      );
      return;
    }
    window.dispatchEvent(
      new CustomEvent("burpfree:sequencer-load", { detail: { tokens } }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "sequencer" } }),
    );
  }

  function exportCsv() {
    if (filteredResults.length === 0) {
      alert(
        resultsFilter.trim()
          ? "No rows match the current filter — clear the filter or widen it to export."
          : "No results to export yet.",
      );
      return;
    }
    const headers = [
      "index",
      "status",
      "length",
      "elapsed_ms",
      "filtered",
      "oob_hits",
      "grep_matched",
      "payloads",
      "extracted",
      "error",
      "url",
      // Multi grep-match columns prefixed to distinguish them from
      // extract columns (whose names could otherwise collide — e.g.
      // operator naming both an extract and a match "token").
      ...matches.map((m, i) => `match:${m.name || `m${i + 1}`}`),
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      if (s.includes(",") || s.includes("\"") || s.includes("\n")) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };
    const rows = filteredResults.map((r) => {
      const oobN = hitsForIndex(r.index);
      return [
        r.index,
        r.status ?? "",
        r.length ?? "",
        r.elapsed_ms ?? "",
        r.filtered ? 1 : 0,
        oobTokens.length === 0 ? "" : oobN,
        grepMatch ? (r.grep_matched ? 1 : 0) : "",
        (r.payloads ?? []).join(" | "),
        r.extracted ?? "",
        r.error ?? "",
        r.url ?? "",
        ...matches.map((_, i) => ((r.matched ?? [])[i] ? 1 : 0)),
      ]
        .map(esc)
        .join(",");
    });
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `intruder-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R603: Clipboard-only CSV counterpart to exportCsv — fourth entry
  // in the cross-panel "📋 Copy as CSV" family after HistoryPanel
  // R600 / Scanner R601 / Logger R602. Operators pasting attack
  // results into Excel / Sheets for payload-vs-status pivot analysis
  // want the table on the clipboard directly without the file-save
  // + open roundtrip. Byte-identical column shape to exportCsv
  // (same 11 base columns + the match:N dynamic columns + same
  // esc rules) so clipboard + file outputs stay interchangeable.
  function copyCsv() {
    if (filteredResults.length === 0) {
      alert(
        resultsFilter.trim()
          ? "No rows match the current filter — clear the filter or widen it to copy."
          : "No results to copy yet.",
      );
      return;
    }
    const headers = [
      "index",
      "status",
      "length",
      "elapsed_ms",
      "filtered",
      "oob_hits",
      "grep_matched",
      "payloads",
      "extracted",
      "error",
      "url",
      ...matches.map((m, i) => `match:${m.name || `m${i + 1}`}`),
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      if (s.includes(",") || s.includes("\"") || s.includes("\n")) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };
    const rows = filteredResults.map((r) => {
      const oobN = hitsForIndex(r.index);
      return [
        r.index,
        r.status ?? "",
        r.length ?? "",
        r.elapsed_ms ?? "",
        r.filtered ? 1 : 0,
        oobTokens.length === 0 ? "" : oobN,
        grepMatch ? (r.grep_matched ? 1 : 0) : "",
        (r.payloads ?? []).join(" | "),
        r.extracted ?? "",
        r.error ?? "",
        r.url ?? "",
        ...matches.map((_, i) => ((r.matched ?? [])[i] ? 1 : 0)),
      ]
        .map(esc)
        .join(",");
    });
    const csv = [headers.join(","), ...rows].join("\n");
    void navigator.clipboard.writeText(csv);
  }

  // R286: JSONL export — companion to exportCsv. CSV flattens the
  // result row to a fixed column set and the per-match columns are
  // positional, so an operator analyzing with jq / grep / ELK ingest
  // has to re-parse the column order. JSONL preserves the full
  // result shape — including the nested `matched` array keyed by
  // match-definition index, the `payloads` array, and any
  // `extracted` content — so operators can jq a single key like
  // `.payloads[0]` or `.matched[2]` without column arithmetic.
  // Scope matches CSV: current filtered-results view (post results
  // filter), so narrowing with resultsFilter respected before export.
  // Attack metadata (match definitions, OOB tokens) embedded in the
  // header line so the export is self-describing.
  function exportJsonl() {
    if (filteredResults.length === 0) {
      alert(
        resultsFilter.trim()
          ? "No rows match the current filter — clear the filter or widen it to export."
          : "No results to export yet.",
      );
      return;
    }
    // First line: an attack-level metadata header so the dump is
    // self-describing — operators processing a stand-alone .jsonl
    // dump can tell which match definitions / OOB tokens / grep
    // config was in effect when the attack ran.
    const header = JSON.stringify({
      _meta: true,
      ts_iso: new Date().toISOString(),
      total_rows: filteredResults.length,
      match_definitions: matches.map((m, i) => ({
        index: i,
        name: m.name || `m${i + 1}`,
      })),
      oob_tokens_count: oobTokens.length,
      grep_match_active: grepMatch,
    });
    const body = filteredResults.map((r) => {
      const oobN = hitsForIndex(r.index);
      return JSON.stringify({
        index: r.index,
        status: r.status ?? null,
        length: r.length ?? null,
        elapsed_ms: r.elapsed_ms ?? null,
        filtered: !!r.filtered,
        oob_hits: oobTokens.length === 0 ? null : oobN,
        grep_matched: grepMatch ? !!r.grep_matched : null,
        payloads: r.payloads ?? [],
        extracted: r.extracted ?? null,
        error: r.error ?? null,
        url: r.url ?? null,
        matched: matches.map((_, i) => !!((r.matched ?? [])[i])),
      });
    });
    const text = [header, ...body].join("\n") + "\n";
    const blob = new Blob([text], {
      type: "application/x-ndjson;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `intruder-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R607: Clipboard-only JSON array counterpart to exportJsonl —
  // third entry in the cross-panel "📋 Copy as JSON" family after
  // HistoryPanel R605 + Scanner R606 (Logger already shipped its
  // own copyBulkJson at R141-era so skipped). Operators dropping
  // attack result rows into test fixtures / regression-suite
  // seeds / jq pipelines want a top-level JSON array (not JSONL)
  // on the clipboard directly. Pretty-printed with 2-space indent
  // for diff-friendly paste. Includes the same _meta header
  // object as the first element (not JSONL's separate first
  // line) so the array is self-describing.
  function copyJson() {
    if (filteredResults.length === 0) {
      alert(
        resultsFilter.trim()
          ? "No rows match the current filter — clear the filter or widen it to copy."
          : "No results to copy yet.",
      );
      return;
    }
    const meta = {
      _meta: true,
      ts_iso: new Date().toISOString(),
      total_rows: filteredResults.length,
      match_definitions: matches.map((m, i) => ({
        index: i,
        name: m.name || `m${i + 1}`,
      })),
      oob_tokens_count: oobTokens.length,
      grep_match_active: grepMatch,
    };
    const rows = filteredResults.map((r) => {
      const oobN = hitsForIndex(r.index);
      return {
        index: r.index,
        status: r.status ?? null,
        length: r.length ?? null,
        elapsed_ms: r.elapsed_ms ?? null,
        filtered: !!r.filtered,
        oob_hits: oobTokens.length === 0 ? null : oobN,
        grep_matched: grepMatch ? !!r.grep_matched : null,
        payloads: r.payloads ?? [],
        extracted: r.extracted ?? null,
        error: r.error ?? null,
        url: r.url ?? null,
        matched: matches.map((_, i) => !!((r.matched ?? [])[i])),
      };
    });
    void navigator.clipboard.writeText(
      JSON.stringify([meta, ...rows], null, 2),
    );
  }

  // Status-code histogram derived from results.
  const histogram = (() => {
    const buckets: Record<string, number> = {};
    for (const r of results) {
      const key =
        r.status == null
          ? r.error
            ? "ERR"
            : "—"
          : `${Math.floor(r.status / 100)}xx`;
      buckets[key] = (buckets[key] ?? 0) + 1;
    }
    return buckets;
  })();

  async function mintOobPayloads(kind: "http" | "dns") {
    setOobBusy(true);
    try {
      // Make sure the OOB server is running; auto-start on default ports.
      let status = await api.oobStatus();
      if (!status.running) {
        status = await api.oobStart();
      }
      // Count how many lines set[0] already has; default to 50 if empty.
      const firstSet = payloadSets[0];
      const lineCount = Math.max(
        1,
        firstSet.list.split(/\r?\n/).filter((s) => s.length).length,
      );
      const count = Math.max(lineCount, 10);
      const tokens = await api.oobMintBatch(count);
      setOobTokens(tokens);
      setOobHits([]);
      updatePayloadSet(0, {
        type: "list",
        list: tokens
          .map((t) => (kind === "http" ? t.http_url : t.dns_name))
          .join("\n"),
      });
    } catch (e) {
      alert(`OOB mint failed: ${e}`);
    } finally {
      setOobBusy(false);
    }
  }

  async function correlateOob(timeoutMs = 5000) {
    if (oobTokens.length === 0) return;
    setOobBusy(true);
    try {
      const ids = oobTokens.map((t) => t.correlation_id);
      const hits = await api.oobPollBatch({ correlation_ids: ids, timeout_ms: timeoutMs });
      setOobHits(hits);
    } catch (e) {
      alert(`OOB poll failed: ${e}`);
    } finally {
      setOobBusy(false);
    }
  }

  function hitsForIndex(index: number): number {
    const token = oobTokens[index];
    if (!token) return 0;
    const row = oobHits.find((h) => h.correlation_id === token.correlation_id);
    return row ? row.interactions.length : 0;
  }

  useEffect(() => {
    if (poll.current) clearInterval(poll.current);
    if (jobId == null) return;
    poll.current = setInterval(async () => {
      try {
        const p = await api.intruderPoll(jobId);
        setStatus(p.status);
        setProgress({ done: p.done, total: p.total });
        setPaused(p.paused);
        if (p.new_results.length) setResults((prev) => [...prev, ...p.new_results]);
        if (p.status === "completed" || p.status === "cancelled" || p.status === "failed") {
          clearInterval(poll.current);
          poll.current = null;
          // Clear pause marker on completion so a fresh attack starts
          // with a fresh toolbar state.
          setPaused(false);
        }
      } catch (e) {
        clearInterval(poll.current);
        poll.current = null;
      }
    }, 500);
    return () => poll.current && clearInterval(poll.current);
  }, [jobId]);

  return (
    <div className="panel">
      {/* R768: Burp-identical Intruder attack status header. Shows
          the current attack state (idle/running/paused/done/failed/
          cancelled) as a tinted pill + progress bar + numeric
          progress + results count. Mirrors Burp Suite 2026.8's
          Intruder attack dashboard header which is always visible
          regardless of whether an attack is running. Operators get
          instant feedback on "did my attack finish? how many
          results came back?" without having to pivot to the
          results table. */}
      <div className="int-status-strip">
        {(() => {
          const label =
            status === "running"
              ? paused
                ? "Paused"
                : "Running"
              : status === "completed"
                ? "Completed"
                : status === "cancelled"
                  ? "Cancelled"
                  : status === "failed"
                    ? "Failed"
                    : status || "Idle";
          const cls =
            status === "running" && !paused
              ? "int-status-pill running"
              : status === "running" && paused
                ? "int-status-pill paused"
                : status === "completed"
                  ? "int-status-pill done"
                  : status === "cancelled"
                    ? "int-status-pill cancelled"
                    : status === "failed"
                      ? "int-status-pill failed"
                      : "int-status-pill idle";
          return <span className={cls}>{label}</span>;
        })()}
        {progress.total > 0 && (
          <>
            <div className="int-status-progress">
              <div
                className="int-status-progress-fill"
                style={{
                  width: `${Math.min(100, Math.round((progress.done / progress.total) * 100))}%`,
                }}
              />
            </div>
            <span className="int-status-item">
              {progress.done} / {progress.total}
              {progress.total > 0 &&
                ` (${Math.round((progress.done / progress.total) * 100)}%)`}
            </span>
          </>
        )}
        <span className="int-status-spacer" />
        {results.length > 0 && (
          <span className="int-status-item">
            {results.length} result{results.length === 1 ? "" : "s"}
            {filteredResults.length !== results.length && (
              <> · {filteredResults.length} shown</>
            )}
          </span>
        )}
        {jobId != null && (
          <span className="int-status-item int-status-jobid">
            job #{jobId}
          </span>
        )}
      </div>
      <div className="toolbar">
        {/* R779: Burp-identical Attack-type pill selector. Replaces
            the plain <select> dropdown with Burp Suite 2026.8's
            canonical 5-pill horizontal row (Sniper / Battering Ram
            / Pitchfork / Cluster Bomb / Null). Each pill carries
            its attack-type name + a tooltip describing when to
            use it. Active state uses accent-dim background + bold
            text + accent border. Zero functionality change — same
            `setMode()` state + same Alt+1..4 keyboard shortcuts.
            Matches Burp's Attack type bar which is the single most
            prominent control on the Intruder tab, so operators can
            see at a glance which attack strategy they've picked. */}
        {/* R799: Burp-identical Intruder "?" help button at the
            left of the Attack type row. Mirrors Burp Suite 2026.8's
            `? [Sniper attack ▼]` layout visible in the user's
            Intruder reference screenshot — the help affordance sits
            immediately left of the attack-type selector so operators
            get one-click access to a modal explaining when to pick
            each attack type. Reuses the same `.rep-help-btn` chrome
            as the Repeater help button so the two panels share
            visual language. */}
        <button
          className="rep-help-btn"
          onClick={() => {
            alert(
              "Intruder — Attack types\n\n" +
                "Sniper (Alt+1)\n" +
                "  One payload set, walks every § position one at a time.\n" +
                "  Best for finding a single injection point.\n\n" +
                "Battering Ram (Alt+2)\n" +
                "  One payload set, same payload substituted into every §\n" +
                "  position simultaneously. Great for same-value-everywhere\n" +
                "  probes.\n\n" +
                "Pitchfork (Alt+3)\n" +
                "  One payload set per § position, iterated in parallel\n" +
                "  (row-aligned, shortest set wins). Great for username+\n" +
                "  password pair-wise brute force.\n\n" +
                "Cluster Bomb (Alt+4)\n" +
                "  One payload set per § position, Cartesian product.\n" +
                "  Blows up combinatorially — Pitchfork × Pitchfork. Great\n" +
                "  for exhaustive multi-dim fuzzing.\n\n" +
                "Null\n" +
                "  Fires the base template N times with markers stripped.\n" +
                "  Payload sets ignored. Great for load / rate-limit /\n" +
                "  cache tests.\n\n" +
                "Markers: wrap with § on either side. Add § button wraps\n" +
                "the URL-field selection; Auto § auto-detects query-string\n" +
                "values; Clear § strips every marker.",
            );
          }}
          title="Intruder attack-type help — explains Sniper / Battering Ram / Pitchfork / Cluster Bomb / Null"
        >
          ?
        </button>
        <label>Attack type</label>
        <div className="int-attack-pills" role="radiogroup" aria-label="Intruder attack type">
          {([
            {
              v: "sniper" as const,
              label: "Sniper",
              hint: "One payload set, one position at a time. Burp's default. Best for finding a single injection point.",
              hotkey: "Alt+1",
            },
            {
              v: "battering_ram" as const,
              label: "Battering Ram",
              hint: "One payload set, same payload substituted into every § position simultaneously. Great for same-value-everywhere probes.",
              hotkey: "Alt+2",
            },
            {
              v: "pitchfork" as const,
              label: "Pitchfork",
              hint: "One payload set per § position, iterated in parallel (row-aligned). Shortest set wins. Great for username+password pair-wise brute force.",
              hotkey: "Alt+3",
            },
            {
              v: "cluster_bomb" as const,
              label: "Cluster Bomb",
              hint: "One payload set per § position, Cartesian product. Blows up combinatorially — Pitchfork × Pitchfork. Great for exhaustive multi-dim fuzzing.",
              hotkey: "Alt+4",
            },
            {
              v: "null" as const,
              label: "Null",
              hint: "Fires the base template N times with markers stripped (inner content kept). Payload sets ignored. Great for load / rate-limit / cache tests.",
              hotkey: undefined,
            },
          ]).map((opt) => (
            <button
              key={opt.v}
              role="radio"
              aria-checked={mode === opt.v}
              className={`int-attack-pill${mode === opt.v ? " active" : ""}`}
              onClick={() => setMode(opt.v)}
              title={`${opt.hint}${opt.hotkey ? ` (${opt.hotkey})` : ""}`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        {/* 🎯 R780 — 25th round-number milestone this chunk after
            R500/R540/R550/R560/R570/R580/R600/R620/R630/R640/
            R650/R660/R670/R680/R690/R700/R710/R720/R726(700-streak)/
            R730(50-tile)/R740/R750/R760/R770/R777(triple-7).
            Burp parity stage 49: Burp-identical "Attack preview"
            summary pill under the Attack-type pills. Mirrors Burp
            Suite 2026.8's Intruder preview strip which gives
            operators a one-line "here's what's about to happen"
            summary before they click Start. Shows: (1) selected
            mode name; (2) live § position count (regex-matched
            against the URL template); (3) active payload-set count;
            (4) rough iteration-count estimate matching the
            `estimate` function used by the "iterations" badge
            below the payload editor; (5) a mode-specific hint
            sentence explaining what the attack will do with
            today's inputs. Tint matches the mode: Sniper/Battering
            Ram = neutral; Pitchfork = cyan; Cluster Bomb = amber
            (combinatorial blow-up warning); Null = dim. Zero
            state additions — all values derive from existing
            `mode` + `url` + `payloadSets` + `marker` + `nullCount`. */}
        {(() => {
          const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const re = new RegExp(`${esc}[^${esc}]*${esc}`, "g");
          const positions = (url.match(re) ?? []).length;
          const needSetsPerPosition =
            mode === "pitchfork" || mode === "cluster_bomb";
          const activeSets = needSetsPerPosition
            ? payloadSets.length
            : mode === "null"
              ? 0
              : 1;
          // Rough iteration estimator mirroring estimateIterations()
          // defined below but inlined so we don't have to lift it
          // above the component. For sniper/battering-ram we don't
          // know the actual payload size at the strip layer (set
          // sizes live in the editor state we can't inspect from
          // here easily), so we show "~" + set count × positions
          // for sniper and "~" + set count for battering ram as
          // placeholders. The authoritative count still shows on
          // the payload-sets editor badge below.
          const iter = (() => {
            if (mode === "null") return `${nullCount} iterations`;
            if (mode === "sniper") {
              const factor = Math.max(1, positions);
              return `${factor} position${factor === 1 ? "" : "s"} × payload-set size`;
            }
            if (mode === "battering_ram") {
              return "payload-set size iterations";
            }
            if (mode === "pitchfork") {
              return `min(payload-set sizes) across ${activeSets} set${activeSets === 1 ? "" : "s"}`;
            }
            if (mode === "cluster_bomb") {
              return `product(payload-set sizes) across ${activeSets} set${activeSets === 1 ? "" : "s"} ⚠ combinatorial`;
            }
            return "?";
          })();
          const hint = (() => {
            if (mode === "null") {
              return `Fire the base template ${nullCount} time${nullCount === 1 ? "" : "s"} with markers stripped. Payload sets ignored.`;
            }
            // Null-mode already returned above, so a positions === 0
            // branch here only applies to sniper/battering_ram/
            // pitchfork/cluster_bomb — all of which need markers.
            if (positions === 0) {
              return "⚠ No § positions — attack is a no-op. Click 'Add §' or 'Auto §' to mark payload positions.";
            }
            if (mode === "sniper") {
              return `Walk ${positions} § position${positions === 1 ? "" : "s"} one at a time; each fires the full payload set with marker stripped elsewhere.`;
            }
            if (mode === "battering_ram") {
              return `Fire payload-set[0] into every § position simultaneously (same value everywhere).`;
            }
            if (mode === "pitchfork") {
              if (positions !== activeSets && positions > 0) {
                return `⚠ ${positions} position${positions === 1 ? "" : "s"} but ${activeSets} payload set${activeSets === 1 ? "" : "s"} — Pitchfork needs 1 set per position.`;
              }
              return `Row-align ${activeSets} payload set${activeSets === 1 ? "" : "s"} across ${positions} position${positions === 1 ? "" : "s"} (shortest set wins).`;
            }
            if (mode === "cluster_bomb") {
              if (positions !== activeSets && positions > 0) {
                return `⚠ ${positions} position${positions === 1 ? "" : "s"} but ${activeSets} payload set${activeSets === 1 ? "" : "s"} — ClusterBomb needs 1 set per position.`;
              }
              return `Cartesian product of ${activeSets} payload set${activeSets === 1 ? "" : "s"} across ${positions} position${positions === 1 ? "" : "s"} — iterations grow combinatorially.`;
            }
            return "";
          })();
          const tint =
            mode === "cluster_bomb"
              ? "amber"
              : mode === "pitchfork"
                ? "cyan"
                : mode === "null"
                  ? "dim"
                  : "neutral";
          const modeLabel =
            mode === "sniper"
              ? "Sniper"
              : mode === "battering_ram"
                ? "Battering Ram"
                : mode === "pitchfork"
                  ? "Pitchfork"
                  : mode === "cluster_bomb"
                    ? "Cluster Bomb"
                    : "Null";
          return (
            <div className={`int-attack-preview int-attack-preview-${tint}`} title={hint}>
              <span className="int-attack-preview-mode">{modeLabel}</span>
              <span className="int-attack-preview-sep">·</span>
              <span className="int-attack-preview-pos">
                {positions} § position{positions === 1 ? "" : "s"}
              </span>
              {mode !== "null" && (
                <>
                  <span className="int-attack-preview-sep">·</span>
                  <span className="int-attack-preview-sets">
                    {activeSets} payload set{activeSets === 1 ? "" : "s"}
                  </span>
                </>
              )}
              <span className="int-attack-preview-sep">·</span>
              <span className="int-attack-preview-iter">{iter}</span>
              <span className="int-attack-preview-spacer" />
              <span className="int-attack-preview-hint">{hint}</span>
            </div>
          );
        })()}
        {mode === "null" && (
          <label title="Number of times to fire the base template. Markers are stripped (inner content kept). Payload sets are ignored in Null mode.">
            Count
            <input
              type="number"
              min={1}
              max={10000}
              step={1}
              value={nullCount}
              onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                setNullCount(Number.isFinite(n) ? Math.max(1, Math.min(10000, n)) : 1);
              }}
              style={{ marginLeft: 4, width: 80 }}
            />
          </label>
        )}
        <label>Method</label>
        <select value={method} onChange={(e) => setMethod(e.target.value)}>
          {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <label>Marker</label>
        <input
          value={marker}
          onChange={(e) => setMarker(e.target.value.slice(0, 1) || "§")}
          style={{ width: 36, textAlign: "center" }}
          title="Payload position delimiter. Burp uses `§` (pair = one position); legacy `~ID~` style still works."
        />
        <button
          onClick={addMarker}
          title="Wrap the URL-field selection in markers (one payload position)"
        >
          Add {marker}
        </button>
        <button
          onClick={clearMarkers}
          title="Strip every marker from the URL"
        >
          Clear {marker}
        </button>
        <button
          onClick={autoMarkers}
          title="Auto-detect query-string values and wrap each in markers"
        >
          Auto {marker}
        </button>
        {/* R181: Position-count badge — operators need to know how    */}
        {/* many §...§ pairs are in the URL before they fire. Zero     */}
        {/* positions = attack is a no-op; too many for the mode (e.g. */}
        {/* 5 pitchfork but only 3 payload sets) is a mode mismatch.   */}
        {/* Compute by regex over the live URL string. Mode-aware tint */}
        {/* so a mismatch between position count and active payload    */}
        {/* sets in pitchfork / cluster-bomb reads as a warning.       */}
        {(() => {
          const esc = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const re = new RegExp(`${esc}[^${esc}]*${esc}`, "g");
          const positions = (url.match(re) ?? []).length;
          const needSetsPerPosition = mode === "pitchfork" || mode === "cluster_bomb";
          const activeSets = needSetsPerPosition ? payloadSets.length : 1;
          const mismatch = needSetsPerPosition && positions > 0 && activeSets !== positions;
          return (
            <span
              className="badge"
              style={{
                background: positions === 0
                  ? "rgba(239,75,75,0.14)"
                  : mismatch
                    ? "rgba(255,170,60,0.14)"
                    : "rgba(63,180,100,0.14)",
                color: positions === 0
                  ? "var(--red)"
                  : mismatch
                    ? "var(--amber)"
                    : "#3fb464",
                fontWeight: 600,
              }}
              title={
                positions === 0
                  ? "No payload positions — add markers with the Add/Auto buttons"
                  : mismatch
                    ? `${positions} position(s) but ${activeSets} payload set(s) — ${mode} needs one set per position`
                    : `${positions} payload position${positions === 1 ? "" : "s"}`
              }
            >
              {positions} pos
            </span>
          );
        })()}
        <label>Conc</label>
        <input
          type="number"
          value={concurrency}
          min={1}
          max={100}
          onChange={(e) => setConcurrency(Number(e.target.value))}
          style={{ width: 60 }}
        />
        <label>Rate/s</label>
        <input
          type="number"
          value={rate ?? ""}
          onChange={(e) => setRate(e.target.value ? Number(e.target.value) : null)}
          style={{ width: 60 }}
        />
        <button
          onClick={() => setShowPool((v) => !v)}
          title="Burp 'Resource pool': fixed delay, random jitter, pause-on-error, redirect policy, dedupe payloads"
          style={{
            background:
              delayMs || delayJitterMs || pauseOnErrorMs || followRedirects !== "never" || deduplicatePayloads
                ? "rgba(100,150,255,0.14)"
                : undefined,
            border:
              delayMs || delayJitterMs || pauseOnErrorMs || followRedirects !== "never" || deduplicatePayloads
                ? "1px solid rgba(100,150,255,0.5)"
                : undefined,
          }}
        >
          {showPool ? "▾" : "▸"} Pool
          {(delayMs || delayJitterMs || pauseOnErrorMs) && (
            <span style={{ color: "var(--accent)", marginLeft: 4 }}>●</span>
          )}
          {followRedirects !== "never" && (
            <span style={{ color: "rgba(255,170,60,0.9)", marginLeft: 4 }}>↷</span>
          )}
          {deduplicatePayloads && (
            <span style={{ color: "rgba(75,191,107,0.95)", marginLeft: 4 }}>★</span>
          )}
        </button>
        <button
          onClick={() => setShowExtracts((v) => !v)}
          title="Burp 'Grep - Extract': named regexes that each become a column in the results table"
          style={{
            background:
              extracts.length > 0 ? "rgba(100,255,150,0.14)" : undefined,
            border:
              extracts.length > 0
                ? "1px solid rgba(100,255,150,0.5)"
                : undefined,
          }}
        >
          {showExtracts ? "▾" : "▸"} Extracts
          {extracts.length > 0 && (
            <span style={{ color: "var(--accent)", marginLeft: 4 }}>
              ({extracts.length})
            </span>
          )}
        </button>
        <button
          onClick={() => setShowMatches((v) => !v)}
          title="Burp 'Grep - Match': named case-insensitive regexes that each become a ✓/· column; firing shows which responses contain each pattern"
          style={{
            background:
              matches.length > 0 ? "rgba(130,180,255,0.14)" : undefined,
            border:
              matches.length > 0
                ? "1px solid rgba(130,180,255,0.5)"
                : undefined,
          }}
        >
          {showMatches ? "▾" : "▸"} Matches
          {matches.length > 0 && (
            <span style={{ color: "var(--accent)", marginLeft: 4 }}>
              ({matches.length})
            </span>
          )}
        </button>
        <label title="Case-insensitive substring probed against each response body. Matching rows highlight green.">
          Grep
        </label>
        <input
          value={grepMatch}
          onChange={(e) => setGrepMatch(e.target.value)}
          placeholder="match string…"
          style={{ width: 140 }}
          title="Burp 'Grep - Match' equivalent. Matching rows get a green left-edge accent + ✓ in the Grep column. Leave empty to disable."
        />
        {/* R753: Burp-identical Intruder "Start attack" button —
            same `.burp-send` orange styling as the Repeater Send
            button since both are the primary action in their
            respective panels. Matches Burp Suite 2026.8's
            Intruder which uses the same prominent orange button. */}
        <button
          className="burp-send"
          disabled={!!jobId && status === "running"}
          onClick={start}
          title="Start attack (Ctrl+Enter)"
        >
          Start attack
        </button>
        <button
          disabled={!jobId || status !== "running"}
          onClick={() => void togglePause()}
          title={
            paused
              ? "Resume the attack — new dispatches will start again. (Ctrl+Space)"
              : "Pause new dispatches. In-flight requests still complete; nothing new fires until Resume. (Ctrl+Space)"
          }
          style={{
            background: paused ? "rgba(100,150,255,0.14)" : undefined,
            border: paused ? "1px solid rgba(100,150,255,0.5)" : undefined,
          }}
        >
          {paused ? "▶ Resume" : "⏸ Pause"}
        </button>
        <button
          className="danger"
          disabled={!jobId || status !== "running"}
          onClick={cancel}
          title="Stop the running attack (Ctrl+Enter also toggles)"
        >
          Stop
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        <select
          value=""
          onChange={(e) => {
            const v = e.target.value;
            e.target.value = "";
            if (!v) return;
            if (v === "__save__") {
              void saveRecipe();
            } else if (v.startsWith("__del__:")) {
              void deleteRecipe(v.slice("__del__:".length));
            } else {
              void loadRecipe(v);
            }
          }}
          title="Save / load named attack recipes — persisted to the project config"
        >
          <option value="">Recipes ▾ ({recipes.length})</option>
          <option value="__save__">Save current as…</option>
          {recipes.length > 0 && (
            <optgroup label="Load">
              {recipes.map((r) => (
                <option key={`l:${r.name}`} value={r.name} title={`${r.mode} · ${r.payload_count} payloads`}>
                  {r.name} ({r.payload_count})
                </option>
              ))}
            </optgroup>
          )}
          {recipes.length > 0 && (
            <optgroup label="Delete">
              {recipes.map((r) => (
                <option key={`d:${r.name}`} value={`__del__:${r.name}`}>
                  Delete {r.name}
                </option>
              ))}
            </optgroup>
          )}
        </select>
        <select
          disabled={libraryBusy || library.length === 0}
          value=""
          onChange={(e) => {
            void loadLibrary(e.target.value);
            // Reset so re-picking the same entry still fires.
            e.target.value = "";
          }}
          title="Load a built-in Intruder wordlist into the payload box"
        >
          <option value="">
            {libraryBusy ? "Loading…" : `Library ▾ (${library.length})`}
          </option>
          {Array.from(new Set(library.map((l) => l.category))).map((cat) => (
            <optgroup key={cat} label={cat}>
              {library
                .filter((l) => l.category === cat)
                .map((l) => (
                  <option key={l.id} value={l.id} title={l.description}>
                    {l.name} ({l.size})
                  </option>
                ))}
            </optgroup>
          ))}
        </select>
        {/* ------------------------------------------------------- */}
        {/* Save + load payloads to/from file. Burp's Intruder has   */}
        {/* `Save` + `Load` next to the Library catalog on the       */}
        {/* Payloads tab — exports/imports the current list set to a */}
        {/* .txt file so operators can hand off between projects or  */}
        {/* share a curated wordlist with teammates. Only visible    */}
        {/* for list-mode set[0] since numbers / null don't have a   */}
        {/* "list" (and multi-set modes still use set[0] as the      */}
        {/* authoritative starter list).                             */}
        {(() => {
          const first = payloadSets[0];
          const list = first?.type === "list" ? first.list.trim() : "";
          const lineCount =
            list.length === 0 ? 0 : list.split(/\r?\n/).filter(Boolean).length;
          return (
            <>
              <button
                disabled={lineCount === 0}
                onClick={() => {
                  try {
                    const blob = new Blob([list + "\n"], {
                      type: "text/plain;charset=utf-8",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    const stamp = new Date()
                      .toISOString()
                      .replace(/[:T]/g, "-")
                      .replace(/\..*$/, "");
                    a.href = url;
                    a.download = `payloads-${stamp}.txt`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(url);
                  } catch (err) {
                    alert(`${err}`);
                  }
                }}
                title={
                  lineCount === 0
                    ? "Payload box is empty — nothing to save."
                    : `Save ${lineCount} payload${lineCount === 1 ? "" : "s"} to a .txt file (one per line, UTF-8)`
                }
              >
                ⬇ Save payloads
              </button>
              {/* Load uses a hidden <input type="file"> + FileReader */}
              {/* so operators get the native file picker. The button */}
              {/* click delegates via `.click()` on the hidden input, */}
              {/* and `onChange` reads the file as UTF-8 text. We     */}
              {/* confirm before overwriting an existing non-empty    */}
              {/* list so a mis-click can't nuke a hand-tuned set.    */}
              <input
                ref={payloadFileInputRef}
                type="file"
                accept=".txt,.lst,.wordlist,.list,text/plain"
                style={{ display: "none" }}
                onChange={async (e) => {
                  const file = e.currentTarget.files?.[0];
                  // Reset immediately so re-picking the same file still fires.
                  e.currentTarget.value = "";
                  if (!file) return;
                  // Hard cap at 50 MB — anything larger is almost
                  // certainly a mis-pick (SQL dumps, binary blobs).
                  // Burp has a similar guard with a prompt; we just
                  // reject with a clear message to keep R118 small.
                  if (file.size > 50 * 1024 * 1024) {
                    alert(
                      `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — hard capped at 50 MB. Pre-filter the list before loading.`,
                    );
                    return;
                  }
                  if (
                    lineCount > 0 &&
                    !confirm(
                      `Overwrite the current payload set (${lineCount} entries) with ${file.name}?`,
                    )
                  ) {
                    return;
                  }
                  try {
                    const text = await file.text();
                    // Normalise CRLF → LF so a Windows-sourced list
                    // doesn't leave stray \r on every entry. Drop
                    // trailing whitespace per line but keep leading
                    // whitespace in case the operator needs a payload
                    // that starts with a space (Burp doesn't trim
                    // leading-WS either).
                    const lines = text
                      .replace(/\r\n/g, "\n")
                      .split("\n")
                      .map((l) => l.replace(/[ \t]+$/, ""))
                      .filter((l) => l.length > 0);
                    updatePayloadSet(0, {
                      type: "list",
                      list: lines.join("\n"),
                    });
                  } catch (err) {
                    alert(`Load file failed: ${err}`);
                  }
                }}
              />
              <button
                onClick={() => payloadFileInputRef.current?.click()}
                title="Load payloads from a .txt / .lst file on disk. One entry per line, UTF-8. Replaces the current set[0] content."
              >
                ⬆ Load file
              </button>
            </>
          );
        })()}
        <button
          onClick={() => mintOobPayloads("http")}
          disabled={oobBusy}
          title="Mint one OOB (Collaborator-style) URL per payload row and fill the list"
        >
          OOB: HTTP URLs
        </button>
        <button
          onClick={() => mintOobPayloads("dns")}
          disabled={oobBusy}
          title="Mint one OOB DNS name per payload row and fill the list"
        >
          OOB: DNS names
        </button>
        <button
          onClick={() => correlateOob(5000)}
          disabled={oobBusy || oobTokens.length === 0}
          title="Poll the OOB listener for callbacks matching the active token batch"
        >
          Correlate hits
        </button>
        <button
          onClick={sendResultsToSequencer}
          disabled={results.length === 0}
          title="Pipe every extracted/payload value into the Sequencer for randomness analysis"
        >
          → Sequencer
        </button>
        <button
          onClick={exportCsv}
          disabled={results.length === 0}
          title="Export the current results table as a CSV file"
        >
          Export CSV
        </button>
        {/* R603: Clipboard-only CSV counterpart to Export CSV on
            Intruder. Fourth entry in the cross-panel "Copy as CSV"
            family after HistoryPanel R600 / Scanner R601 / Logger
            R602. Operators pasting attack results into Excel /
            Sheets for payload-vs-status pivot analysis want the
            table on the clipboard directly without the file-save
            + open roundtrip. Byte-identical column shape to
            Export CSV (including dynamic match:N columns). */}
        <button
          onClick={copyCsv}
          disabled={results.length === 0}
          title={
            results.length === 0
              ? "No results to copy yet"
              : `Copy ${filteredResults.length} filtered result${filteredResults.length === 1 ? "" : "s"} as a CSV table to clipboard (11 base columns + match:N dynamic columns). Paste into Excel / Sheets / Google Docs without the file-save roundtrip. Byte-identical column shape to Export CSV. Fourth entry in the cross-panel Copy-as-CSV family (HistoryPanel R600 + Scanner R601 + Logger R602 + Intruder R603).`
          }
        >
          📋 Copy as CSV
        </button>
        <button
          onClick={exportJsonl}
          disabled={results.length === 0}
          title="Export the current results as JSONL (one JSON object per line). Preserves nested fields — payloads array, matched array indexed by match-def, extracted content — and includes a _meta header line with match definitions + OOB token count + grep-match state so the dump is self-describing. Pipe into jq / grep / ELK ingest."
        >
          Export JSONL
        </button>
        {/* R607: Clipboard-only JSON array counterpart to Export
            JSONL on Intruder. Third entry in the cross-panel
            "Copy as JSON" family after HistoryPanel R605 +
            Scanner R606 (Logger already shipped its own
            copyBulkJson at R141-era so skipped). Operators
            dropping attack result rows into test fixtures /
            regression-suite seeds / jq pipelines want a
            top-level JSON array on the clipboard directly. */}
        <button
          onClick={copyJson}
          disabled={results.length === 0}
          title={
            results.length === 0
              ? "No results to copy yet"
              : `Copy ${filteredResults.length} filtered result${filteredResults.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed; first element is a _meta header object with match definitions + OOB token count + grep-match state so the array is self-describing). Great for test fixtures, regression seeds, jq pipelines. Third entry in cross-panel Copy-as-JSON family (History R605 + Scanner R606 + Intruder R607).`
          }
        >
          📋 Copy as JSON
        </button>
        {/* R687: Intruder "📋 Copy status counts" — tally variant
            for Intruder attack results, sorted by status class
            priority (ERR > 5xx > 4xx > 3xx > 2xx). Reuses the
            existing `statusBucket` + `bucketCounts` memo so the
            output matches the chip-strip exactly byte-for-byte. */}
        <button
          onClick={() => {
            if (filteredResults.length === 0) {
              alert(
                resultsFilter.trim() || statusFilter.size > 0
                  ? "No rows match the current filter."
                  : "No results to tally yet.",
              );
              return;
            }
            const order = ["ERR", "5xx", "4xx", "3xx", "2xx"];
            const entries = order
              .map((k) => [k, bucketCounts[k] ?? 0] as [string, number])
              .filter(([, n]) => n > 0);
            const text = entries.map(([k, n]) => `${k}: ${n}`).join(", ");
            void navigator.clipboard.writeText(text);
          }}
          disabled={results.length === 0}
          title={
            results.length === 0
              ? "No results to copy yet"
              : `Copy status-bucket counts across ${filteredResults.length} filtered result${filteredResults.length === 1 ? "" : "s"} as a one-line tally (sorted ERR > 5xx > 4xx > 3xx > 2xx — most interesting first). Byte-identical to the chip-strip summary.`
          }
        >
          📋 Copy status counts
        </button>
        {/* R694: Intruder "📋 Copy stats" — 6th panel in the
            metadata summary family (History R688-R689, Scanner
            R690, Target R691, Collaborator R692, Logger R693,
            Intruder R694). Shape adapted for attack-result
            metrics: Results / Status split / Match hits /
            OOB hits / Avg elapsed / Total length. Reuses the
            existing bucketCounts memo + hitsForIndex helper so
            output matches chip-strip semantics byte-for-byte. */}
        <button
          onClick={() => {
            if (filteredResults.length === 0) {
              alert(
                resultsFilter.trim() || statusFilter.size > 0
                  ? "No rows match the current filter."
                  : "No results to summarise yet.",
              );
              return;
            }
            let totalLen = 0;
            let elapsedSum = 0;
            let elapsedN = 0;
            let matchHits = 0;
            let oobHits = 0;
            for (const r of filteredResults) {
              totalLen += r.length ?? 0;
              if (typeof r.elapsed_ms === "number") {
                elapsedSum += r.elapsed_ms;
                elapsedN += 1;
              }
              const matched = r.matched ?? [];
              if (matched.some((m: boolean) => !!m)) matchHits += 1;
              if (hitsForIndex(r.index) > 0) oobHits += 1;
            }
            const order = ["ERR", "5xx", "4xx", "3xx", "2xx"];
            const statusLine = order
              .map((k) => [k, bucketCounts[k] ?? 0] as [string, number])
              .filter(([, n]) => n > 0)
              .map(([k, n]) => `${k}: ${n}`)
              .join(", ");
            const fmtBytes = (n: number) => {
              if (n < 1024) return `${n} B`;
              if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
              return `${(n / 1024 / 1024).toFixed(2)} MB`;
            };
            const lines: string[] = [];
            lines.push(`Results: ${filteredResults.length}`);
            if (statusLine) lines.push(`Status: ${statusLine}`);
            if (matches.length > 0)
              lines.push(
                `Match hits: ${matchHits} / ${filteredResults.length}`,
              );
            if (oobTokens.length > 0)
              lines.push(
                `OOB hits: ${oobHits} / ${filteredResults.length}`,
              );
            if (elapsedN > 0)
              lines.push(
                `Avg elapsed: ${(elapsedSum / elapsedN).toFixed(1)} ms`,
              );
            lines.push(`Total length: ${fmtBytes(totalLen)}`);
            void navigator.clipboard.writeText(lines.join("\n"));
          }}
          disabled={results.length === 0}
          title={
            results.length === 0
              ? "No results to copy yet"
              : `Copy a multi-line KV summary across ${filteredResults.length} filtered result${filteredResults.length === 1 ? "" : "s"} (Results / Status split / Match hits / OOB hits / Avg elapsed / Total length). 6th panel in the metadata summary family (History R688-R689, Scanner R690, Target R691, Collaborator R692, Logger R693, Intruder R694). Status split reuses the chip-strip bucket counts byte-for-byte; match/OOB rows only render when there are match defs / OOB tokens.`
          }
        >
          📋 Copy stats
        </button>
        {/* R617: Clipboard-only JSONL counterpart to Export JSONL
            on Intruder. Fourth entry in cross-panel "Copy as JSONL"
            family (History R614 + Scanner R615 + Logger R616 +
            Intruder R617). Streaming-friendly dense format. Keeps
            the _meta header as the first line (JSONL convention)
            so the dump stays self-describing. */}
        <button
          onClick={() => {
            if (filteredResults.length === 0) {
              alert(
                resultsFilter.trim()
                  ? "No rows match the current filter — clear the filter or widen it to copy."
                  : "No results to copy yet.",
              );
              return;
            }
            const header = JSON.stringify({
              _meta: true,
              ts_iso: new Date().toISOString(),
              total_rows: filteredResults.length,
              match_definitions: matches.map((m, i) => ({
                index: i,
                name: m.name || `m${i + 1}`,
              })),
              oob_tokens_count: oobTokens.length,
              grep_match_active: grepMatch,
            });
            const body = filteredResults.map((r) => {
              const oobN = hitsForIndex(r.index);
              return JSON.stringify({
                index: r.index,
                status: r.status ?? null,
                length: r.length ?? null,
                elapsed_ms: r.elapsed_ms ?? null,
                filtered: !!r.filtered,
                oob_hits: oobTokens.length === 0 ? null : oobN,
                grep_matched: grepMatch ? !!r.grep_matched : null,
                payloads: r.payloads ?? [],
                extracted: r.extracted ?? null,
                error: r.error ?? null,
                url: r.url ?? null,
                matched: matches.map((_, i) => !!((r.matched ?? [])[i])),
              });
            });
            void navigator.clipboard.writeText([header, ...body].join("\n"));
          }}
          disabled={results.length === 0}
          title={
            results.length === 0
              ? "No results to copy yet"
              : `Copy ${filteredResults.length} filtered result${filteredResults.length === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line, first line is a _meta header for self-describing dumps — byte-identical to Export JSONL). Great for jq / grep / ELK ingest. Fourth entry in cross-panel Copy-as-JSONL family.`
          }
        >
          📋 Copy as JSONL
        </button>
        {/* R380: Clipboard dump of the filtered-results payloads —   */}
        {/* lighter-weight sibling of Export CSV/JSONL for the common */}
        {/* "copy my working wordlist into a sibling tool" flow.     */}
        {/* Honours both text + chip filters so operators can narrow */}
        {/* down (e.g. "status: 200 rows only" + "contains admin")   */}
        {/* then one click yields the payload list for a Repeater   */}
        {/* bulk retry, a cURL loop, or a teammate paste. Dedupe +   */}
        {/* sort alpha for stable diff-friendly output, matching    */}
        {/* R357 Repeater pinned-URL and R353 History URLs patterns. */}
        {/* Multi-position attacks (cluster bomb / pitchfork) join   */}
        {/* positions with " · " so each row's full payload set     */}
        {/* lands on one line.                                        */}
        <button
          onClick={async () => {
            if (filteredResults.length === 0) {
              alert(
                resultsFilter.trim() || statusFilter.size > 0
                  ? "No rows match the current filter — clear filters or widen them to copy."
                  : "No results to copy yet — run an attack first.",
              );
              return;
            }
            try {
              const lines = Array.from(
                new Set(
                  filteredResults
                    .map((r) =>
                      Array.isArray(r.payloads)
                        ? r.payloads.join(" · ")
                        : "",
                    )
                    .filter((s) => s.length > 0),
                ),
              ).sort();
              if (lines.length === 0) {
                alert("Filtered rows have no payload text to copy.");
                return;
              }
              await copyToClipboard(lines.join("\n"));
            } catch (e) {
              alert(`${e}`);
            }
          }}
          disabled={results.length === 0}
          title={`Copy every filtered row's payload text to clipboard (deduped + sorted alpha). Honours both text + chip filters. Multi-position attacks join positions with " · " per line. Great for feeding a working wordlist into a sibling tool / Jira paste / shell pipeline.`}
        >
          📋 Copy payloads
        </button>
        {/* R384: Clipboard dump of the filtered-results URLs —      */}
        {/* companion to R380 Copy payloads. Operators often want    */}
        {/* the URL list (not the payload list) when the payload   */}
        {/* already lives in the URL template — e.g. a path-based   */}
        {/* enum attack where every row's URL is unique and         */}
        {/* valuable for a sidecar ffuf run, a wordlist for the     */}
        {/* next session, or a Jira paste. **Same filter scope**    */}
        {/* as R380 — honours text + chip layers. **Dedupe + sort** */}
        {/* identical. **Diff** stays on URLs not payloads so       */}
        {/* cluster-bomb runs with duplicate payloads but distinct */}
        {/* URLs give the full URL inventory. Smart alerts match   */}
        {/* R380.                                                     */}
        <button
          onClick={async () => {
            if (filteredResults.length === 0) {
              alert(
                resultsFilter.trim() || statusFilter.size > 0
                  ? "No rows match the current filter — clear filters or widen them to copy."
                  : "No results to copy yet — run an attack first.",
              );
              return;
            }
            try {
              const lines = Array.from(
                new Set(
                  filteredResults
                    .map((r) => (r.url ?? "").trim())
                    .filter((s) => s.length > 0),
                ),
              ).sort();
              if (lines.length === 0) {
                alert("Filtered rows have no URL field to copy.");
                return;
              }
              await copyToClipboard(lines.join("\n"));
            } catch (e) {
              alert(`${e}`);
            }
          }}
          disabled={results.length === 0}
          title={`Copy every filtered row's URL to clipboard (deduped + sorted alpha). Honours both text + chip filters. Great for a sidecar ffuf run / wordlist for the next session / Jira paste. Companion to 📋 Copy payloads.`}
        >
          📋 Copy URLs
        </button>
        <input
          value={resultsFilter}
          onChange={(e) => setResultsFilter(e.target.value)}
          onKeyDown={(e) => {
            // R372: Esc clears the Intruder results filter — joins
            // the Esc-clear-search family (History R201, Target
            // Issues R219, Target sitemap R223, Logger R224,
            // Collaborator R227, Comparer R260, Proxy WsPane R281,
            // BChecks R282). Fires only when the input has text
            // so Esc stays available for modals / popovers when
            // the input is empty.
            if (e.key === "Escape" && resultsFilter) {
              e.preventDefault();
              setResultsFilter("");
            }
          }}
          placeholder="Filter rows… (Esc clears)"
          title="Case-insensitive substring filter across payload / status / url / extracted / error / extract columns"
          style={{
            width: 180,
            background: resultsFilter
              ? "rgba(100,150,255,0.14)"
              : undefined,
            border: resultsFilter
              ? "1px solid rgba(100,150,255,0.5)"
              : undefined,
          }}
        />
        <button
          className="danger"
          onClick={() => {
            if (!confirm(`Clear ${results.length} result row${results.length === 1 ? "" : "s"}?`)) return;
            setResults([]);
            setBaselineIndex(null);
            setResultsFilter("");
          }}
          disabled={results.length === 0}
          title="Clear the results table"
        >
          Clear results
        </button>
        <span
          className="badge"
          style={paused ? { background: "rgba(100,150,255,0.14)" } : undefined}
          title={paused ? "Attack is paused — in-flight requests may still land." : undefined}
        >
          {status || "idle"} · {progress.done}/{progress.total}
          {paused && " · paused"}
          {oobTokens.length > 0 &&
            ` · OOB ${oobHits.reduce((n, h) => n + (h.interactions.length > 0 ? 1 : 0), 0)}/${oobTokens.length}`}
        </span>
        {/* R476: Intruder results stats badge "📊 N · 2xx S / E err  */}
        {/* · N% hit rate". 8th panel to carry a toolbar "📊" quick-   */}
        {/* stats chip — joins R440 Repeater workspace stats + R442   */}
        {/* History hosts + R451 Collaborator kind-split + R452        */}
        {/* Target Issues severity-split + R466 Decoder chain stats + */}
        {/* R469 Sequencer tokens + R471 CookieJar jar stats. The     */}
        {/* existing status chip strip below shows per-bucket counts, */}
        {/* but a single toolbar-level "hit rate" summary is the      */}
        {/* clearest at-a-glance read of attack efficacy — operators  */}
        {/* judging a running attack want "am I getting 200s?" in     */}
        {/* one glance without walking the five status chips. **Hit  */}
        {/* rate** = 2xx count / total non-error results — the ratio */}
        {/* that typically marks a successful password / token /     */}
        {/* path discovery. Errors are excluded from the denominator  */}
        {/* so a network-flake rate doesn't deflate the real-world    */}
        {/* 2xx rate. Rate tint: accent when > 0 (hits exist), dim    */}
        {/* when 0. **Visibility gate** `results.length > 0` — hides  */}
        {/* for a fresh / cleared results table (same gate as the    */}
        {/* chip strip below).                                        */}
        {results.length > 0 && (() => {
          const total = results.length;
          const twoXx = results.filter((r) => {
            if (r.status == null) return false;
            return Math.floor(r.status / 100) === 2;
          }).length;
          const errCount = results.filter((r) => r.error).length;
          const nonErr = total - errCount;
          const rate = nonErr > 0 ? Math.round((twoXx / nonErr) * 100) : 0;
          return (
            <span
              className="mono"
              title={`${total} total result${total === 1 ? "" : "s"} · ${twoXx} with 2xx status · ${errCount} transport/network error${errCount === 1 ? "" : "s"} · hit rate ${rate}% (2xx / non-error rows). Attack efficacy at a glance — chip strip below shows the full per-bucket breakdown.`}
              style={{ fontSize: 10.5, color: "var(--text-faint)", marginLeft: 4 }}
            >
              📊
              <span style={{ color: "var(--text)", marginLeft: 4 }}>
                {total}
              </span>
              <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
              <span style={{ color: twoXx > 0 ? "var(--accent)" : "var(--text-dim)" }}>
                {twoXx} 2xx
              </span>
              {errCount > 0 && (
                <>
                  <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
                  <span style={{ color: "var(--red, #ff6060)" }}>
                    {errCount} err
                  </span>
                </>
              )}
              <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
              <span style={{ color: rate > 0 ? "var(--accent)" : "var(--text-dim)" }}>
                {rate}%
              </span>
            </span>
          );
        })()}
        {handoffBanner && (
          <span
            style={{
              padding: "2px 8px",
              borderRadius: 10,
              background: "var(--bg-raised)",
              color: "var(--accent)",
              fontSize: 11,
              cursor: "pointer",
            }}
            title="Dismiss"
            onClick={() => setHandoffBanner(null)}
          >
            {handoffBanner}
          </span>
        )}
      </div>
      {/* ---------------------------------------------------------- */}
      {/* Status bucket chip filter — Burp-style. Multi-select, Set    */}
      {/* state, counts respect the text filter above. Buckets are     */}
      {/* only rendered once the attack has produced some rows so the  */}
      {/* strip doesn't eat screen space on an empty table.            */}
      {results.length > 0 && (
        <div className="issue-filter-strip">
          <div className="issue-filter-row">
            <span className="issue-filter-label">status</span>
            {([
              { key: "2xx", label: "2xx", cls: "intr-b-2xx" },
              { key: "3xx", label: "3xx", cls: "intr-b-3xx" },
              { key: "4xx", label: "4xx", cls: "intr-b-4xx" },
              { key: "5xx", label: "5xx", cls: "intr-b-5xx" },
              { key: "ERR", label: "err", cls: "intr-b-err" },
            ] as const).map(({ key, label, cls }) => {
              const active = statusFilter.has(key);
              const count = bucketCounts[key] ?? 0;
              return (
                <button
                  key={key}
                  type="button"
                  className={`issue-status-chip ${cls} ${active ? "on" : "off"}`}
                  onClick={() => toggleStatusBucket(key)}
                  disabled={count === 0 && !active}
                  title={
                    active
                      ? `Showing ${label} — click to hide`
                      : count === 0
                        ? `No ${label} rows yet`
                        : `Click to filter to ${label}`
                  }
                >
                  <span className="chip-label">{label}</span>
                  <span className="chip-count">{count}</span>
                </button>
              );
            })}
            <span className="dim" style={{ fontSize: 10.5, marginLeft: 8 }}>
              {filteredResults.length} / {textFilteredResults.length} shown
            </span>
            {statusFilter.size > 0 && (
              <button
                type="button"
                className="issue-filter-clear"
                onClick={() => setStatusFilter(new Set())}
                title="Clear status filter"
              >
                clear
              </button>
            )}
          </div>
        </div>
      )}
      {showPool && (
        <div
          style={{
            padding: "6px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            display: "flex",
            gap: 12,
            alignItems: "center",
            fontSize: 12,
            flexWrap: "wrap",
          }}
        >
          <span style={{ color: "var(--text-dim)", fontWeight: 600 }}>
            Resource pool:
          </span>
          {/* R168: Pool-timing presets — three canonical profiles so  */}
          {/* operators can pick a safe starting point without walking */}
          {/* every knob. Mirrors Burp Pro's "Resource pool" presets.  */}
          {/* Clicking a preset writes delay / jitter / pause-on-error */}
          {/* / concurrency atomically. Doesn't touch dedupe or        */}
          {/* follow-redirects — those are per-attack semantic choices */}
          {/* rather than throttling knobs.                             */}
          <div style={{ display: "flex", gap: 2 }}>
            {([
              {
                label: "🏃 Aggressive",
                hint: "0ms delay, 0ms jitter, 0ms backoff, concurrency 20 — fast + loud",
                delay: 0,
                jitter: 0,
                backoff: 0,
                conc: 20,
              },
              {
                label: "🚶 Balanced",
                hint: "100ms delay, 50ms jitter, 1000ms backoff, concurrency 5 — safe default",
                delay: 100,
                jitter: 50,
                backoff: 1000,
                conc: 5,
              },
              {
                label: "🐌 Polite",
                hint: "500ms delay, 200ms jitter, 2000ms backoff, concurrency 1 — minimal footprint",
                delay: 500,
                jitter: 200,
                backoff: 2000,
                conc: 1,
              },
            ] as const).map((p) => {
              const active =
                (delayMs ?? 0) === p.delay &&
                (delayJitterMs ?? 0) === p.jitter &&
                (pauseOnErrorMs ?? 0) === p.backoff &&
                concurrency === p.conc;
              return (
                <button
                  key={p.label}
                  type="button"
                  className={active ? "primary" : ""}
                  onClick={() => {
                    setDelayMs(p.delay === 0 ? null : p.delay);
                    setDelayJitterMs(p.jitter === 0 ? null : p.jitter);
                    setPauseOnErrorMs(p.backoff === 0 ? null : p.backoff);
                    setConcurrency(p.conc);
                  }}
                  title={p.hint}
                  style={{ fontSize: 11, padding: "2px 6px" }}
                >
                  {p.label}
                </button>
              );
            })}
          </div>
          <label title="Fixed pause inserted before every dispatch (applies even when concurrency = 1). Burp calls this 'Delay between requests'.">
            Delay
            <input
              type="number"
              min={0}
              max={600000}
              value={delayMs ?? ""}
              placeholder="0"
              onChange={(e) =>
                setDelayMs(e.target.value ? Number(e.target.value) : null)
              }
              style={{ width: 70, marginLeft: 4 }}
            />
            <span style={{ color: "var(--text-faint)", marginLeft: 2 }}>ms</span>
          </label>
          <label title="Uniform random extra delay in [0, jitter_ms]; added on top of the fixed delay. Helps evade WAF fingerprinting.">
            Jitter ±
            <input
              type="number"
              min={0}
              max={600000}
              value={delayJitterMs ?? ""}
              placeholder="0"
              onChange={(e) =>
                setDelayJitterMs(
                  e.target.value ? Number(e.target.value) : null,
                )
              }
              style={{ width: 70, marginLeft: 4 }}
            />
            <span style={{ color: "var(--text-faint)", marginLeft: 2 }}>ms</span>
          </label>
          <label title="Adaptive pause after any send error (timeout / 5xx / network). Lets the engine back off gracefully when the target starts rate-limiting mid-attack.">
            Pause-on-error
            <input
              type="number"
              min={0}
              max={600000}
              value={pauseOnErrorMs ?? ""}
              placeholder="0"
              onChange={(e) =>
                setPauseOnErrorMs(
                  e.target.value ? Number(e.target.value) : null,
                )
              }
              style={{ width: 70, marginLeft: 4 }}
            />
            <span style={{ color: "var(--text-faint)", marginLeft: 2 }}>ms</span>
          </label>
          <label
            style={{ display: "flex", alignItems: "center", gap: 4 }}
            title="Burp 'Make payloads unique'. Strips duplicate combos (same payload tuple appearing twice in the planned iterator) before dispatch so the attack doesn't burn requests on repeats. Reduces total iterations client-visibly in the preview."
          >
            <input
              type="checkbox"
              checked={deduplicatePayloads}
              onChange={(e) => setDeduplicatePayloads(e.target.checked)}
            />
            Make payloads unique
          </label>
          <label title="Burp 'Redirections' per attack. Never = raw 3xx shows up in the row; On-site = follow only to same host:port; In-scope = same as on-site (project scope not re-evaluated per hop here); Always = follow any Location up to 5 hops.">
            Redirects
            <select
              value={followRedirects}
              onChange={(e) =>
                setFollowRedirects(
                  e.target.value as "never" | "on_site" | "in_scope" | "always",
                )
              }
              style={{ marginLeft: 4 }}
            >
              <option value="never">Never</option>
              <option value="on_site">On-site</option>
              <option value="in_scope">In-scope</option>
              <option value="always">Always</option>
            </select>
          </label>
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>
            {(() => {
              const d = delayMs ?? 0;
              const j = delayJitterMs ?? 0;
              const p = pauseOnErrorMs ?? 0;
              const parts: string[] = [];
              if (d === 0 && j === 0 && p === 0) {
                parts.push("No pacing — requests fire as fast as concurrency / rate allow.");
              } else {
                const lo = d;
                const hi = d + j;
                if (d > 0 || j > 0) {
                  parts.push(
                    lo === hi
                      ? `Each dispatch sleeps ${lo} ms`
                      : `Each dispatch sleeps ${lo}–${hi} ms`,
                  );
                }
                if (p > 0) parts.push(`${p} ms backoff after errors`);
              }
              if (followRedirects !== "never") {
                parts.push(`redirects: ${followRedirects.replace("_", "-")} (≤5 hops)`);
              }
              if (deduplicatePayloads) {
                parts.push("unique only (duplicate combos stripped)");
              }
              return parts.join(" · ");
            })()}
          </span>
        </div>
      )}
      {showExtracts && (
        <div
          style={{
            padding: "6px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            fontSize: 12,
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              marginBottom: 6,
            }}
          >
            <span style={{ color: "var(--text-dim)", fontWeight: 600 }}>
              Grep-Extract:
            </span>
            <span style={{ color: "var(--text-faint)", fontSize: 11 }}>
              Each rule becomes a column in the results table. Regex captures
              group 1 or group 0.
            </span>
            <span style={{ flex: 1 }} />
            <button
              onClick={() =>
                setExtracts((prev) => [...prev, { name: "", regex: "" }])
              }
              title="Add a new Grep-Extract rule"
              disabled={extracts.length >= 10}
            >
              + Add extract
            </button>
          </div>
          {extracts.length === 0 && (
            <div
              style={{
                color: "var(--text-faint)",
                fontStyle: "italic",
                padding: "4px 0",
              }}
            >
              No extract rules yet. Click <strong>+ Add extract</strong> to
              harvest session tokens, response codes, or JSON fields.
            </div>
          )}
          {extracts.map((rule, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                gap: 6,
                alignItems: "center",
                marginBottom: 4,
              }}
            >
              <span
                style={{
                  color: "var(--text-faint)",
                  minWidth: 22,
                  textAlign: "right",
                }}
              >
                #{idx + 1}
              </span>
              <input
                value={rule.name}
                placeholder="name (column header)"
                onChange={(e) =>
                  setExtracts((prev) =>
                    prev.map((r, i) =>
                      i === idx ? { ...r, name: e.target.value } : r,
                    ),
                  )
                }
                style={{ width: 150 }}
              />
              <input
                value={rule.regex}
                placeholder="regex (prefers capture group 1)"
                onChange={(e) =>
                  setExtracts((prev) =>
                    prev.map((r, i) =>
                      i === idx ? { ...r, regex: e.target.value } : r,
                    ),
                  )
                }
                style={{ flex: 1, fontFamily: "var(--font-mono, monospace)" }}
              />
              <button
                className="danger"
                onClick={() =>
                  setExtracts((prev) => prev.filter((_, i) => i !== idx))
                }
                title="Remove this rule"
              >
                ✕
              </button>
            </div>
          ))}
          {extracts.length >= 5 && (
            <div
              style={{
                color: "var(--text-faint)",
                fontSize: 11,
                marginTop: 4,
              }}
            >
              {extracts.length} rules — results table starts getting wide
              above ~5 columns.
            </div>
          )}
        </div>
      )}
      {showMatches && (
        <div
          style={{
            padding: "8px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              marginBottom: 6,
            }}
          >
            <strong style={{ fontSize: 12 }}>Grep match rules</strong>
            <span
              style={{
                color: "var(--text-dim)",
                fontSize: 11,
                flex: 1,
              }}
            >
              Named case-insensitive regexes. Each becomes a ✓/· column
              in the results. Legacy single <code>Grep</code> input
              still works alongside.
            </span>
            <button
              onClick={() =>
                setMatches((prev) => [...prev, { name: "", pattern: "" }])
              }
              title="Add a new Grep-Match rule"
              disabled={matches.length >= 10}
            >
              + Add match
            </button>
          </div>
          {matches.length === 0 && (
            <div
              style={{
                color: "var(--text-dim)",
                fontSize: 11,
                padding: "6px 0",
              }}
            >
              No match rules yet. Click <strong>+ Add match</strong> to
              flag rows containing session markers, error strings, or
              success indicators.
            </div>
          )}
          {matches.map((rule, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                gap: 6,
                alignItems: "center",
                marginBottom: 4,
              }}
            >
              <input
                value={rule.name}
                placeholder="name (column header)"
                onChange={(e) =>
                  setMatches((prev) =>
                    prev.map((r, i) =>
                      i === idx ? { ...r, name: e.target.value } : r,
                    ),
                  )
                }
                style={{ width: 150 }}
              />
              <input
                value={rule.pattern}
                placeholder="regex pattern (case-insensitive by default)"
                onChange={(e) =>
                  setMatches((prev) =>
                    prev.map((r, i) =>
                      i === idx ? { ...r, pattern: e.target.value } : r,
                    ),
                  )
                }
                style={{ flex: 1, fontFamily: "var(--font-mono, monospace)" }}
              />
              <button
                className="danger"
                onClick={() =>
                  setMatches((prev) => prev.filter((_, i) => i !== idx))
                }
                title="Remove this rule"
              >
                ✕
              </button>
            </div>
          ))}
          {matches.length >= 5 && (
            <div
              style={{
                color: "var(--text-faint)",
                fontSize: 11,
                marginTop: 4,
              }}
            >
              {matches.length} rules — results table starts getting wide
              above ~5 columns.
            </div>
          )}
        </div>
      )}
      {results.length > 0 && (
        <div
          style={{
            padding: "4px 10px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            gap: 10,
            alignItems: "center",
            fontSize: 11,
            flexWrap: "wrap",
          }}
        >
          <span style={{ color: "var(--text-dim)" }}>Status histogram:</span>
          {Object.entries(histogram)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, n]) => (
              <span
                key={k}
                className={`mono status-${k.replace("xx", "")}`}
                style={{
                  padding: "2px 8px",
                  borderRadius: 10,
                  border: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                }}
                title={`${n} result(s) with status class ${k}`}
              >
                {k}: {n}
              </span>
            ))}
          <span style={{ color: "var(--text-dim)" }}>
            {resultsFilter.trim()
              ? `· Showing ${filteredResults.length} of ${results.length}`
              : `· ${results.length} total`}
          </span>
        </div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 26px", flex: 1, minHeight: 0, position: "relative" }}>
        <div style={{ padding: 10, display: "flex", flexDirection: "column", gap: 8 }}>
          <div className="form-row" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <label style={{ flex: 1 }}>
              URL (place markers like {marker}X{marker})
            </label>
            <label
              style={{ fontSize: 11, color: "var(--text-dim)" }}
              title="When on, the Host header is kept in sync with the target URL as you type. Turn off for Host-header injection probes."
            >
              <input
                type="checkbox"
                checked={updateHost}
                onChange={(e) => setUpdateHost(e.target.checked)}
                style={{ marginRight: 4 }}
              />
              Update Host header to match target
            </label>
          </div>
          <input
            ref={urlRef}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <PositionsPreview
            expanded={positionsExpanded}
            onToggle={() => setPositionsExpanded((v) => !v)}
            {...renderPositionsPreview()}
          />
          {mode === "null" ? (
            <div
              style={{
                padding: 10,
                margin: "4px 0",
                border: "1px dashed var(--border)",
                borderRadius: 4,
                background: "var(--bg-raised)",
                fontSize: 12,
                color: "var(--text-dim)",
                lineHeight: 1.5,
              }}
              title="Null mode fires the base template unchanged — payload sets are not consulted."
            >
              <strong style={{ color: "var(--text)" }}>
                Null mode — payload sets unused
              </strong>
              <br />
              The base template fires{" "}
              <strong>{nullCount.toLocaleString()}</strong>{" "}
              time{nullCount === 1 ? "" : "s"} with every{" "}
              <code>§…§</code> marker stripped to its inner content.
              Common uses: account lockout thresholds, rate-limit
              discovery, race-condition probing.
            </div>
          ) : (
            /* R796: Scroll anchor for the R795 "Payloads" side rail.
               Clicking the rail scrolls this editor into view via
               the matching data-int-payload-sets selector. */
            <div data-int-payload-sets>
            <PayloadSetsEditor
              sets={payloadSets}
              activeMode={mode}
              onUpdate={updatePayloadSet}
              onAdd={addPayloadSet}
              onRemove={removePayloadSet}
              onClone={clonePayloadSet}
              sizeOf={payloadSetSize}
            />
            </div>
          )}
          <ProcessingRulesEditor
            rules={processingRules}
            expanded={processingExpanded}
            onToggle={() => setProcessingExpanded((v) => !v)}
            onAdd={addProcessingRule}
            onRemove={removeProcessingRule}
            onMove={moveProcessingRule}
            onUpdate={updateProcessingRule}
          />
        </div>
        <div style={{ borderLeft: "1px solid var(--border)", overflow: "hidden" }}>
          <div className="table">
            <table>
              <colgroup>
                <col style={{ width: 40 }} />
                <col style={{ width: 56 }} />
                <col style={{ width: 56 }} />
                <col style={{ width: 64 }} />
                <col style={{ width: 56 }} />
                <col style={{ width: 44 }} />
                <col style={{ width: 60 }} />
                <col style={{ width: 44 }} />
                <col />
                <col style={{ width: 40 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Status</th>
                  <th>Len</th>
                  <th
                    title={
                      baselineIndex != null
                        ? `Response length relative to row #${baselineIndex} (right-click → Clear baseline to revert to implicit first-row).`
                        : "Response length relative to the first row with a response. Right-click any row → Set as baseline to pin a different reference."
                    }
                    style={{
                      color: baselineIndex != null ? "var(--accent)" : undefined,
                    }}
                  >
                    ΔLen{baselineIndex != null ? ` (${baselineIndex})` : ""}
                  </th>
                  <th>Time</th>
                  <th>Filt</th>
                  <th>OOB</th>
                  <th title="Grep match — ✓ when the response body contained the configured substring.">Grep</th>
                  <th>Payload / Extract</th>
                  {extracts.map((rule, i) => (
                    <th
                      key={`extract-${i}`}
                      title={`Extract #${i + 1}: ${rule.regex}`}
                      style={{ color: "var(--accent)" }}
                    >
                      {rule.name || `#${i + 1}`}
                    </th>
                  ))}
                  {matches.map((rule, i) => (
                    <th
                      key={`match-${i}`}
                      title={`Match #${i + 1}: /${rule.pattern}/i`}
                      style={{
                        color: "rgba(130,180,255,1)",
                        textAlign: "center",
                      }}
                    >
                      {rule.name || `m${i + 1}`}
                    </th>
                  ))}
                  <th />
                </tr>
              </thead>
              <tbody>
                {filteredResults.map((r, i) => {
                  const oobN = hitsForIndex(r.index);
                  return (
                    <tr
                      key={i}
                      onContextMenu={(e) => {
                        e.preventDefault();
                        setRowMenu({ x: e.clientX, y: e.clientY, data: r });
                      }}
                      style={{
                        cursor: "context-menu",
                        // Burp-style accent for grep-matched rows:
                        // 3-px inset left-edge green stripe.
                        boxShadow: r.grep_matched
                          ? "inset 3px 0 0 var(--green, #4caf50)"
                          : undefined,
                        // R294: Status-class row tint — color-code
                        // 2xx / 3xx / 4xx / 5xx responses so
                        // operators eyeballing an attack output can
                        // spot server-errors (5xx) and unauthorised
                        // (4xx) at a glance without reading each
                        // status column. Low-saturation rgba tints
                        // so the row text stays legible on both
                        // light + dark themes. Only tinted when a
                        // status landed — in-flight / errored rows
                        // (status null) stay default so the "no
                        // response yet" rows don't shout.
                        background: (() => {
                          const s = r.status || 0;
                          if (s >= 200 && s < 300)
                            return "rgba(76, 175, 80, 0.06)";
                          if (s >= 300 && s < 400)
                            return "rgba(90, 160, 220, 0.06)";
                          if (s >= 400 && s < 500)
                            return "rgba(240, 192, 48, 0.08)";
                          if (s >= 500 && s < 600)
                            return "rgba(224, 68, 68, 0.10)";
                          return undefined;
                        })(),
                      }}
                    >
                      <td className="mono">{r.index}</td>
                      <td className={`mono status-${Math.floor((r.status || 0) / 100)}xx`}>
                        {r.status ?? "—"}
                      </td>
                      <td className="mono">{r.length ?? "—"}</td>
                      {(() => {
                        const effectiveBaseline =
                          baselineIndex != null ? baselineIndex : filteredResults[0]?.index;
                        const isBaseline =
                          effectiveBaseline != null && r.index === effectiveBaseline;
                        const hasLen = typeof r.length === "number";
                        const hasBase = typeof baselineLength === "number";
                        if (isBaseline) {
                          return (
                            <td
                              className="mono"
                              style={{
                                color: "var(--text-faint)",
                                fontStyle: "italic",
                                textAlign: "right",
                              }}
                              title={
                                baselineIndex != null
                                  ? "Pinned baseline. All other rows' ΔLen is measured against this row."
                                  : "Implicit baseline (first row). Right-click a different row to pin it instead."
                              }
                            >
                              base
                            </td>
                          );
                        }
                        if (!hasLen || !hasBase) {
                          return (
                            <td
                              className="mono"
                              style={{
                                color: "var(--text-faint)",
                                textAlign: "right",
                              }}
                              title={hasLen ? "No baseline yet" : "No response"}
                            >
                              —
                            </td>
                          );
                        }
                        const delta = (r.length as number) - (baselineLength as number);
                        const sign = delta > 0 ? "+" : delta < 0 ? "−" : "±";
                        const color =
                          delta > 0
                            ? "var(--green, #4caf50)"
                            : delta < 0
                              ? "var(--red, #e04444)"
                              : "var(--text-faint)";
                        return (
                          <td
                            className="mono"
                            style={{
                              color,
                              fontWeight: delta === 0 ? 400 : 600,
                              textAlign: "right",
                            }}
                            title={`Baseline ${baselineLength} B · this row ${r.length} B · delta ${sign}${Math.abs(delta)} B`}
                          >
                            {sign}
                            {Math.abs(delta)}
                          </td>
                        );
                      })()}
                      <td className="mono">{r.elapsed_ms ?? "—"}</td>
                      <td className="mono">{r.filtered ? "yes" : ""}</td>
                      <td
                        className="mono"
                        style={{
                          color: oobN > 0 ? "var(--accent)" : "var(--text-faint)",
                          fontWeight: oobN > 0 ? 600 : 400,
                        }}
                        title={oobN > 0 ? "Target emitted an OOB callback for this payload" : ""}
                      >
                        {oobTokens.length === 0 ? "—" : oobN > 0 ? `★ ${oobN}` : "0"}
                      </td>
                      <td
                        className="mono"
                        style={{
                          color: r.grep_matched
                            ? "var(--green, #4caf50)"
                            : "var(--text-faint)",
                          fontWeight: r.grep_matched ? 700 : 400,
                          textAlign: "center",
                        }}
                        title={
                          r.grep_matched
                            ? `Response body contained "${grepMatch}"`
                            : grepMatch
                              ? "No match"
                              : "Grep disabled"
                        }
                      >
                        {grepMatch ? (r.grep_matched ? "✓" : "·") : "—"}
                      </td>
                      <td className="mono">
                        {r.payloads.join(" · ")} {r.extracted && `→ ${r.extracted}`}
                      </td>
                      {extracts.map((_, i) => {
                        const v = (r.extracted_fields ?? [])[i];
                        const shown =
                          v == null
                            ? "—"
                            : v.length > 60
                              ? v.slice(0, 60) + "…"
                              : v;
                        return (
                          <td
                            key={`ex-${i}`}
                            className="mono"
                            title={v ?? ""}
                            style={{
                              color:
                                v == null
                                  ? "var(--text-faint)"
                                  : "var(--accent)",
                            }}
                          >
                            {shown}
                          </td>
                        );
                      })}
                      {matches.map((rule, i) => {
                        const hit = (r.matched ?? [])[i] === true;
                        return (
                          <td
                            key={`m-${i}`}
                            className="mono"
                            title={
                              hit
                                ? `Response body matched /${rule.pattern}/i`
                                : `No match for /${rule.pattern}/i`
                            }
                            style={{
                              color: hit
                                ? "rgba(130,180,255,1)"
                                : "var(--text-faint)",
                              fontWeight: hit ? 700 : 400,
                              textAlign: "center",
                            }}
                          >
                            {hit ? "✓" : "·"}
                          </td>
                        );
                      })}
                      <td>
                        <button
                          className="ghost"
                          onClick={() => void sendRowToRepeater(r)}
                          title="Open this exact request in a new Repeater tab"
                        >
                          ↗
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
        {/* R795: Burp-identical Intruder right-side vertical rails
            (Payloads / Resource pool / Settings) — mirrors Burp
            Suite 2026.8's Intruder layout visible in the user's
            reference screenshot where three rotated-text buttons
            sit on the far right. Clicking each rail triggers the
            matching panel action: Payloads scrolls to payload
            sets, Resource pool opens the throttling panel,
            Settings navigates to the Settings panel. Rail chrome
            matches R756 Repeater's `.rep-side-rails` so the two
            panels share visual language. */}
        <div className="int-side-rails">
          <button
            className="int-side-rail"
            onClick={() => {
              // Scroll payload-sets editor into view in the right pane.
              setTimeout(() => {
                const el = document.querySelector<HTMLElement>(
                  "[data-int-payload-sets]",
                );
                el?.scrollIntoView({ behavior: "smooth", block: "start" });
              }, 10);
            }}
            title="Payloads — jump to the payload-sets editor (where you pick wordlists, generators, grep matches)"
          >
            Payloads
          </button>
          <button
            className={`int-side-rail${showPool ? " active" : ""}`}
            onClick={() => setShowPool((v) => !v)}
            title="Resource pool — delay / jitter / pause-on-error / concurrency / redirect policy / dedupe payloads"
          >
            Resource pool
          </button>
          <button
            className="int-side-rail"
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent("burpfree:navigate", {
                  detail: { target: "settings" },
                }),
              );
            }}
            title="Settings — navigate to the Settings panel for engine-wide tuning"
          >
            Settings
          </button>
        </div>
      </div>
      <FloatingMenu
        state={rowMenu}
        onClose={() => setRowMenu(null)}
        items={
          rowMenu?.data
            ? [
                {
                  label: "Send to Repeater",
                  onClick: () => void sendRowToRepeater(rowMenu.data!),
                  disabled: !lastConfig,
                  hint: lastConfig ? undefined : "run an attack first",
                },
                {
                  label: "Send to Comparer (request)",
                  onClick: () => sendRowToComparer(rowMenu.data!),
                },
                {
                  label: "Send payload to Decoder",
                  onClick: () => void sendRowPayloadToDecoder(rowMenu.data!),
                  disabled: !(rowMenu.data!.payloads?.length > 0),
                },
                { separator: true },
                {
                  label: "Copy as cURL",
                  onClick: () => void copyRowAs(rowMenu.data!, "curl"),
                },
                {
                  label: "Copy as PowerShell",
                  onClick: () => void copyRowAs(rowMenu.data!, "powershell"),
                },
                {
                  label: "Copy as Python-requests",
                  onClick: () => void copyRowAs(rowMenu.data!, "python"),
                },
                // R705: Intruder row "Copy as fetch()" — 4th
                // panel in the cross-panel row-level shell-
                // replay fetch family (HistoryPanel + Scanner
                // R632 + Target R633 + Intruder R705). DevTools-
                // ready snippet operators can paste into a
                // browser console to replay a single attack-
                // row request. Completes Intruder's row-level
                // shell-replay quartet (cURL / PowerShell /
                // Python / fetch) matching HistoryPanel's menu
                // neighbourhood.
                {
                  label: "Copy as fetch()",
                  hint: "paste into DevTools console",
                  onClick: () => void copyRowAs(rowMenu.data!, "fetch"),
                },
                // R702: Intruder row "Copy as JSON" — 5th panel
                // in the cross-panel row-level Copy-as-JSON family
                // (HistoryPanel R651 + Scanner R652 + Target R653
                // + ProxyPanel R654 + Intruder R702). Operators
                // dumping a single row into a test fixture / jq
                // pipeline / regression seed want the full result
                // record without the bulk-copy array wrapping.
                // Pretty-printed with 2-space indent so paste-into-
                // editor renders cleanly.
                {
                  label: "Copy row as JSON",
                  hint: "full result record · pretty-printed",
                  onClick: () => {
                    const r: any = rowMenu.data!;
                    const oobN = hitsForIndex(r.index);
                    const payload = {
                      index: r.index,
                      status: r.status ?? null,
                      length: r.length ?? null,
                      elapsed_ms: r.elapsed_ms ?? null,
                      filtered: !!r.filtered,
                      oob_hits: oobTokens.length === 0 ? null : oobN,
                      grep_matched: grepMatch ? !!r.grep_matched : null,
                      payloads: r.payloads ?? [],
                      extracted: r.extracted ?? null,
                      error: r.error ?? null,
                      url: r.url ?? null,
                      matched: matches.map(
                        (_, i) => !!((r.matched ?? [])[i]),
                      ),
                    };
                    void copyToClipboard(
                      JSON.stringify(payload, null, 2),
                    );
                  },
                },
                // R712: Intruder row "Copy JSONL line" — 5th
                // panel in the row-level JSONL-line family
                // (HistoryPanel R708 + Scanner R709 + Target
                // R710 + ProxyPanel R711 + Intruder R712).
                // Single-line NDJSON for appending to a .jsonl
                // log / piping to jq. Byte-identical shape to
                // the pretty variant above but on one line
                // (no indent) + trailing newline. Byte-
                // identical to R617 Intruder bulk Copy-as-
                // JSONL per-line output.
                {
                  label: "Copy JSONL line",
                  hint: "one object, one line + newline",
                  onClick: () => {
                    const r: any = rowMenu.data!;
                    const oobN = hitsForIndex(r.index);
                    const payload = {
                      index: r.index,
                      status: r.status ?? null,
                      length: r.length ?? null,
                      elapsed_ms: r.elapsed_ms ?? null,
                      filtered: !!r.filtered,
                      oob_hits: oobTokens.length === 0 ? null : oobN,
                      grep_matched: grepMatch ? !!r.grep_matched : null,
                      payloads: r.payloads ?? [],
                      extracted: r.extracted ?? null,
                      error: r.error ?? null,
                      url: r.url ?? null,
                      matched: matches.map(
                        (_, i) => !!((r.matched ?? [])[i]),
                      ),
                    };
                    void copyToClipboard(
                      JSON.stringify(payload) + "\n",
                    );
                  },
                },
                // R704: Intruder row "Copy table row" — 6th
                // panel in the cross-panel row-level Copy-table-
                // row family (HistoryPanel R663 + Scanner R664
                // + Target R665 + ProxyPanel R666 + Logger R667
                // + Intruder R704). Just the row-content
                // Markdown line (no header, no separator) so it
                // slots cleanly into an existing table in a
                // doc. 6 columns: index, payload, status, length,
                // elapsed, extracted — mirrors R617 JSONL dense
                // field set but as a table line.
                {
                  label: "Copy table row",
                  hint: "Markdown table body line · no header",
                  onClick: () => {
                    const r: any = rowMenu.data!;
                    const esc = (v: unknown) =>
                      String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
                    const payloadStr = ((r.payloads ?? []) as string[]).join(
                      " · ",
                    );
                    const cells = [
                      r.index,
                      payloadStr,
                      r.status ?? "",
                      r.length ?? "",
                      typeof r.elapsed_ms === "number" ? r.elapsed_ms : "",
                      r.extracted ?? "",
                    ]
                      .map(esc)
                      .join(" | ");
                    void copyToClipboard(`| ${cells} |`);
                  },
                },
                // R703: Intruder row "Copy as Markdown" — 5th
                // panel in the cross-panel row-level Copy-as-
                // Markdown family (HistoryPanel R640 + Target
                // R625 + ProxyPanel R659 + Scanner R660 +
                // Intruder R703). H3 section per row with
                // Index + URL + Status + Length + Elapsed +
                // optional Payloads/Extracted/OOB/Error.
                // Great for Jira / PR description where
                // document-style prose fits better than JSON.
                {
                  label: "Copy row as Markdown",
                  hint: "H3 section · result+payload+status",
                  onClick: () => {
                    const r: any = rowMenu.data!;
                    const oobN = hitsForIndex(r.index);
                    const lines: string[] = [];
                    lines.push(`### Intruder result #${r.index}`);
                    lines.push("");
                    if (r.url) lines.push(`- **URL**: \`${r.url}\``);
                    lines.push(`- **Status**: ${r.status ?? "—"}`);
                    lines.push(`- **Length**: ${r.length ?? "—"} bytes`);
                    if (typeof r.elapsed_ms === "number")
                      lines.push(`- **Elapsed**: ${r.elapsed_ms} ms`);
                    const payloads = (r.payloads ?? []) as string[];
                    if (payloads.length > 0)
                      lines.push(
                        `- **Payload${payloads.length === 1 ? "" : "s"}**: ${payloads.map((p) => `\`${p}\``).join(", ")}`,
                      );
                    if (r.extracted)
                      lines.push(`- **Extracted**: \`${r.extracted}\``);
                    if (oobTokens.length > 0 && oobN > 0)
                      lines.push(`- **OOB hits**: ${oobN}`);
                    if (grepMatch && r.grep_matched)
                      lines.push(`- **Grep**: matched`);
                    if (r.filtered) lines.push(`- **Filtered**: yes`);
                    if (r.error) lines.push(`- **Error**: ${r.error}`);
                    void copyToClipboard(lines.join("\n"));
                  },
                },
                { separator: true },
                {
                  label: "Copy URL",
                  onClick: () =>
                    void copyToClipboard(rowMenu.data!.url ?? ""),
                  disabled: !rowMenu.data!.url,
                },
                {
                  label: "Copy payload(s)",
                  onClick: () =>
                    void copyToClipboard(
                      (rowMenu.data!.payloads ?? []).join(" "),
                    ),
                  disabled: !(rowMenu.data!.payloads?.length > 0),
                },
                {
                  label: "Copy extracted value",
                  onClick: () =>
                    void copyToClipboard(rowMenu.data!.extracted ?? ""),
                  disabled: !rowMenu.data!.extracted,
                },
                { separator: true },
                {
                  label: "Show full URL",
                  onClick: () => alert(rowMenu.data!.url ?? "(no URL)"),
                  disabled: !rowMenu.data!.url,
                },
                { separator: true },
                {
                  label:
                    baselineIndex === rowMenu.data!.index
                      ? "Clear baseline (this row)"
                      : "Set as baseline",
                  hint:
                    typeof rowMenu.data!.length === "number"
                      ? `length ${rowMenu.data!.length} B`
                      : "no response — can't be a baseline reference",
                  disabled: typeof rowMenu.data!.length !== "number",
                  onClick: () => {
                    if (baselineIndex === rowMenu.data!.index) {
                      setBaselineIndex(null);
                    } else {
                      setBaselineIndex(rowMenu.data!.index);
                    }
                  },
                },
                ...(baselineIndex != null && baselineIndex !== rowMenu.data!.index
                  ? [
                      {
                        label: `Clear baseline (currently #${baselineIndex})`,
                        hint: "revert to implicit first-row baseline",
                        onClick: () => setBaselineIndex(null),
                      },
                    ]
                  : []),
              ]
            : []
        }
      />
    </div>
  );
}

// ---- Positions preview strip ---------------------------------------------

interface PositionsPreviewProps {
  segments: Array<{ text: string; isMarker: boolean }>;
  positionCount: number;
  expanded: boolean;
  onToggle: () => void;
}

/** Read-only reconstructed raw-wire HTTP request with payload-marker
 *  pairs highlighted in red. Mirrors Burp's Positions tab in intent
 *  without being an editable raw editor — the authoritative template
 *  still lives in the URL input + method dropdown, this view is just
 *  for auditing where markers land. */
function PositionsPreview({
  segments,
  positionCount,
  expanded,
  onToggle,
}: PositionsPreviewProps) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 4,
        background: "var(--bg-raised)",
      }}
    >
      <div
        onClick={onToggle}
        style={{
          padding: "4px 8px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 11,
          color: "var(--text-dim)",
          userSelect: "none",
        }}
        title="Reconstructed raw-wire request. Highlighted spans are payload-insertion points."
      >
        <span style={{ fontFamily: "var(--font-mono)" }}>{expanded ? "▼" : "▶"}</span>
        <span style={{ fontWeight: 600 }}>Positions preview</span>
        <span>
          · {positionCount} payload position{positionCount === 1 ? "" : "s"}
        </span>
        {/* R798: Burp-identical "Length: N" display matching the
            exact format visible in the user's Intruder reference
            screenshot ("5 highlights · 5 payload positions ·
            Length: 107"). Computes total character length of the
            reconstructed request including § markers so operators
            see "how big is the whole attack template?" without
            scrolling. */}
        {(() => {
          const totalLen = segments.reduce(
            (acc, s) =>
              acc + s.text.length + (s.isMarker ? 2 : 0),
            0,
          );
          return (
            <span title={`Total raw-wire length including § markers (${totalLen} characters)`}>
              · Length: {totalLen}
            </span>
          );
        })()}
        {positionCount === 0 && (
          <span style={{ color: "var(--text-faint)" }}>
            — add markers with the "Add" button or type them inline
          </span>
        )}
      </div>
      {expanded && (
        <pre
          className="mono"
          style={{
            margin: 0,
            padding: 8,
            background: "var(--bg)",
            fontSize: 11,
            lineHeight: 1.5,
            maxHeight: 180,
            overflow: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
            borderTop: "1px solid var(--border)",
          }}
        >
          {segments.map((s, i) =>
            s.isMarker ? (
              <span
                key={i}
                style={{
                  background: "#ff6b6b",
                  color: "#000",
                  borderRadius: 2,
                  padding: "0 2px",
                  fontWeight: 600,
                }}
                title="Payload insertion point"
              >
                {s.text}
              </span>
            ) : (
              <span key={i}>{s.text}</span>
            ),
          )}
        </pre>
      )}
    </div>
  );
}

// ---- Payload-sets editor -------------------------------------------------

interface PayloadSetsEditorProps {
  sets: PayloadSet[];
  activeMode: "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb" | "null";
  onUpdate: (idx: number, patch: Partial<PayloadSet>) => void;
  onAdd: () => void;
  onRemove: (idx: number) => void;
  onClone: (idx: number) => void;
  sizeOf: (s: PayloadSet) => number;
}

/** Burp "Payload sets" block. Renders one row per PayloadSet (type
 *  picker + per-type params + remove button); shows an "+ Add set"
 *  only when the mode actually consumes multiple sets. Also surfaces
 *  a live iteration-count estimate so operators notice before they
 *  fire a 10-million-request ClusterBomb by accident. */
function PayloadSetsEditor({
  sets,
  activeMode,
  onUpdate,
  onAdd,
  onRemove,
  onClone,
  sizeOf,
}: PayloadSetsEditorProps) {
  const multiSetMode =
    activeMode === "pitchfork" || activeMode === "cluster_bomb";
  const activeSets = multiSetMode ? sets : sets.slice(0, 1);
  const iterationCount = estimateIterations(activeMode, activeSets, sizeOf);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {activeSets.map((s, i) => (
        <PayloadSetRow
          key={i}
          idx={i}
          set={s}
          isPrimary={i === 0}
          onUpdate={onUpdate}
          onRemove={onRemove}
          onClone={onClone}
          size={sizeOf(s)}
        />
      ))}
      {multiSetMode && (
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={onAdd}
            disabled={sets.length >= 8}
            title="Add another payload set — one per insertion point for Pitchfork / ClusterBomb"
          >
            + Add payload set
          </button>
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>
            {activeMode === "pitchfork"
              ? "Pitchfork needs one set per § position; iterates in parallel (shortest set wins)."
              : "ClusterBomb needs one set per § position; iterates the Cartesian product."}
          </span>
        </div>
      )}
      {!multiSetMode && sets.length > 1 && (
        <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
          {sets.length - 1} extra set{sets.length - 1 === 1 ? "" : "s"} hidden
          — current mode uses only set #1.
        </span>
      )}
      <span
        style={{
          color:
            iterationCount > 100_000
              ? "var(--red, #e04444)"
              : "var(--text-faint)",
          fontSize: 11,
        }}
        title="Approximate number of requests this attack will send. Red when > 100k."
      >
        Est. iterations: {iterationCount.toLocaleString()}
      </span>
    </div>
  );
}

/** How many iterations the backend will produce from these sets +
 *  mode. Mirrors the planner in `plan_iterations` on the Rust side. */
function estimateIterations(
  mode: "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb" | "null",
  sets: PayloadSet[],
  sizeOf: (s: PayloadSet) => number,
): number {
  // Null mode's iteration count comes from `null_count` in the parent
  // state; PayloadSetsEditor isn't rendered for Null, so this branch
  // only matters as a defensive fallback. Return 0 so the editor
  // doesn't display a confusing non-zero estimate if ever rendered.
  if (mode === "null") return 0;
  if (sets.length === 0) return 0;
  const sizes = sets.map(sizeOf);
  switch (mode) {
    case "sniper":
      // Sniper = positions × set-size; we don't know the position
      // count here so just report set-size (the actual count is
      // bounded by positions × size which Burp also under-reports).
      return sizes[0] ?? 0;
    case "battering_ram":
      return sizes[0] ?? 0;
    case "pitchfork":
      return Math.min(...sizes);
    case "cluster_bomb":
      return sizes.reduce((acc, n) => acc * n, 1);
    default:
      return 0;
  }
}

interface PayloadSetRowProps {
  idx: number;
  set: PayloadSet;
  isPrimary: boolean;
  size: number;
  onUpdate: (idx: number, patch: Partial<PayloadSet>) => void;
  onRemove: (idx: number) => void;
  onClone?: (idx: number) => void;
}

function PayloadSetRow({
  idx,
  set,
  isPrimary,
  size,
  onUpdate,
  onRemove,
  onClone,
}: PayloadSetRowProps) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 4,
        background: "var(--bg-raised)",
        padding: 6,
      }}
    >
      <div
        className="form-row"
        style={{ display: "flex", alignItems: "center", gap: 8 }}
      >
        <span className="badge">Set #{idx + 1}</span>
        <select
          value={set.type}
          onChange={(e) =>
            onUpdate(idx, {
              type: e.target.value as PayloadSet["type"],
            })
          }
          style={{ width: 120 }}
          title="Burp 'Payload type'. List = textarea (default); Numbers = range from/to/step; Null = fire the same request N times."
        >
          <option value="list">List</option>
          <option value="numbers">Numbers</option>
          <option value="null">Null</option>
        </select>
        <span
          style={{
            color: "var(--text-dim)",
            fontSize: 11,
          }}
        >
          {set.type === "list" && "one per line"}
          {set.type === "numbers" && "range from / to / step"}
          {set.type === "null" && "same request × count"}
          {" · "}
          {size.toLocaleString()} payload{size === 1 ? "" : "s"}
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        {/* R190: Clone — duplicate this set as a sibling. Only shows */}
        {/* when under the 8-set cap. Primary set can also be cloned  */}
        {/* so operators iterating on their base can keep the         */}
        {/* original + variants side-by-side.                          */}
        {onClone && (
          <button
            className="ghost"
            onClick={() => onClone(idx)}
            title="Clone this payload set (duplicate + edit the copy)"
          >
            ⎘
          </button>
        )}
        {!isPrimary && (
          <button
            className="ghost danger"
            onClick={() => onRemove(idx)}
            title="Remove this payload set"
          >
            ✕
          </button>
        )}
      </div>
      {set.type === "list" && (
        <textarea
          value={set.list}
          onChange={(e) => onUpdate(idx, { list: e.target.value })}
          style={{ width: "100%", marginTop: 6, minHeight: 80 }}
          placeholder="one payload per line"
        />
      )}
      {set.type === "numbers" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "70px 1fr 70px 1fr",
            gap: 6,
            alignItems: "center",
            marginTop: 6,
          }}
        >
          <label style={{ fontSize: 11 }}>From</label>
          <input
            type="number"
            value={set.numFrom}
            onChange={(e) =>
              onUpdate(idx, { numFrom: Number(e.target.value) || 0 })
            }
          />
          <label style={{ fontSize: 11 }}>To</label>
          <input
            type="number"
            value={set.numTo}
            onChange={(e) =>
              onUpdate(idx, { numTo: Number(e.target.value) || 0 })
            }
          />
          <label style={{ fontSize: 11 }}>Step</label>
          <input
            type="number"
            value={set.numStep}
            onChange={(e) =>
              onUpdate(idx, { numStep: Number(e.target.value) || 1 })
            }
            title="Negative step counts down. Zero is coerced to 1."
          />
          <label style={{ fontSize: 11 }}>Pad to</label>
          <input
            type="number"
            value={set.numPadTo}
            min={0}
            onChange={(e) =>
              onUpdate(idx, { numPadTo: Number(e.target.value) || 0 })
            }
            title="Zero-pad each number to this width (e.g. pad_to=4 → 0001, 0002…). 0 = no padding."
          />
        </div>
      )}
      {set.type === "null" && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginTop: 6,
          }}
        >
          <label style={{ fontSize: 11 }}>Count</label>
          <input
            type="number"
            value={set.nullCount}
            min={1}
            onChange={(e) =>
              onUpdate(idx, {
                nullCount: Math.max(0, Number(e.target.value) || 0),
              })
            }
            style={{ width: 100 }}
            title="How many times to fire the same request. Each iteration substitutes markers with the empty string."
          />
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>
            Useful for session-ID brute, race conditions, counting
            side-channels.
          </span>
        </div>
      )}
    </div>
  );
}

// ---- Payload-processing rules editor -------------------------------------

interface ProcessingRulesEditorProps {
  rules: ProcessingRule[];
  expanded: boolean;
  onToggle: () => void;
  onAdd: (kind: ProcessingRule["kind"]) => void;
  onRemove: (idx: number) => void;
  onMove: (idx: number, delta: -1 | 1) => void;
  onUpdate: (idx: number, patch: Partial<ProcessingRule>) => void;
}

/** Collapsible section showing the payload-processing chain. Each
 *  rule renders as one row with a kind label, inline param inputs,
 *  Up / Down / Remove buttons. "Add rule ▾" dropdown at the bottom
 *  appends a fresh rule of the chosen kind. */
function ProcessingRulesEditor({
  rules,
  expanded,
  onToggle,
  onAdd,
  onRemove,
  onMove,
  onUpdate,
}: ProcessingRulesEditorProps) {
  const groups = Array.from(new Set(PROCESSING_RULE_CATALOG.map((r) => r.group)));
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 4,
        background: "var(--bg-raised)",
      }}
    >
      <div
        onClick={onToggle}
        style={{
          padding: "4px 8px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 11,
          color: "var(--text-dim)",
          userSelect: "none",
        }}
        title="Chain of transforms applied to every payload before it's substituted into the request"
      >
        <span style={{ fontFamily: "var(--font-mono)" }}>{expanded ? "▼" : "▶"}</span>
        <span style={{ fontWeight: 600 }}>Payload processing</span>
        <span>· {rules.length} rule{rules.length === 1 ? "" : "s"}</span>
        <span className="spacer" style={{ flex: 1 }} />
        {rules.length > 0 && !expanded && (
          <span className="mono" style={{ color: "var(--text-faint)" }}>
            {rules.map((r) => r.kind).join(" → ")}
          </span>
        )}
      </div>
      {expanded && (
        <div style={{ padding: 8, display: "flex", flexDirection: "column", gap: 6 }}>
          {rules.length === 0 && (
            <div style={{ color: "var(--text-faint)", fontSize: 11 }}>
              No rules — payloads are substituted verbatim. Add a rule below.
            </div>
          )}
          {rules.map((rule, idx) => (
            <ProcessingRuleRow
              key={idx}
              rule={rule}
              isFirst={idx === 0}
              isLast={idx === rules.length - 1}
              onUp={() => onMove(idx, -1)}
              onDown={() => onMove(idx, 1)}
              onRemove={() => onRemove(idx)}
              onUpdate={(patch) => onUpdate(idx, patch)}
            />
          ))}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <select
              value=""
              onChange={(e) => {
                const kind = e.target.value as ProcessingRule["kind"] | "";
                e.target.value = "";
                if (kind) onAdd(kind);
              }}
              style={{ fontSize: 11 }}
            >
              <option value="">+ Add rule ▾</option>
              {groups.map((g) => (
                <optgroup key={g} label={g}>
                  {PROCESSING_RULE_CATALOG.filter((r) => r.group === g).map((r) => (
                    <option key={r.kind} value={r.kind}>
                      {r.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
              Rules apply top-to-bottom. Each payload is transformed once per
              iteration.
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

interface ProcessingRuleRowProps {
  rule: ProcessingRule;
  isFirst: boolean;
  isLast: boolean;
  onUp: () => void;
  onDown: () => void;
  onRemove: () => void;
  onUpdate: (patch: Partial<ProcessingRule>) => void;
}

function ProcessingRuleRow({
  rule,
  isFirst,
  isLast,
  onUp,
  onDown,
  onRemove,
  onUpdate,
}: ProcessingRuleRowProps) {
  const label =
    PROCESSING_RULE_CATALOG.find((r) => r.kind === rule.kind)?.label ?? rule.kind;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        fontSize: 11,
        padding: "2px 4px",
        border: "1px solid var(--border)",
        borderRadius: 3,
        background: "var(--bg)",
      }}
    >
      <span style={{ minWidth: 110, fontWeight: 500 }}>{label}</span>
      {rule.kind === "prefix" && (
        <input
          value={rule.value}
          onChange={(e) => onUpdate({ value: e.target.value } as Partial<ProcessingRule>)}
          placeholder="prefix…"
          style={{ flex: 1, fontSize: 11 }}
        />
      )}
      {rule.kind === "suffix" && (
        <input
          value={rule.value}
          onChange={(e) => onUpdate({ value: e.target.value } as Partial<ProcessingRule>)}
          placeholder="suffix…"
          style={{ flex: 1, fontSize: 11 }}
        />
      )}
      {rule.kind === "match_replace" && (
        <>
          <input
            value={rule.pattern}
            onChange={(e) => onUpdate({ pattern: e.target.value } as Partial<ProcessingRule>)}
            placeholder={rule.regex ? "pattern (regex)" : "match (literal)"}
            style={{ flex: 1, fontSize: 11 }}
          />
          <span style={{ color: "var(--text-faint)" }}>→</span>
          <input
            value={rule.replacement}
            onChange={(e) =>
              onUpdate({ replacement: e.target.value } as Partial<ProcessingRule>)
            }
            placeholder={rule.regex ? "replacement ($1…)" : "replacement"}
            style={{ flex: 1, fontSize: 11 }}
          />
          <label
            style={{ color: "var(--text-dim)", display: "flex", alignItems: "center", gap: 2 }}
            title="Interpret the pattern as a Rust regex. Replacement supports $1-style capture-group references."
          >
            <input
              type="checkbox"
              checked={rule.regex}
              onChange={(e) =>
                onUpdate({ regex: e.target.checked } as Partial<ProcessingRule>)
              }
            />
            re
          </label>
        </>
      )}
      <span className="spacer" style={{ flex: rule.kind === "match_replace" ? 0 : 1 }} />
      <button
        className="ghost"
        disabled={isFirst}
        onClick={onUp}
        title="Move rule up"
        style={{ padding: "0 6px" }}
      >
        ↑
      </button>
      <button
        className="ghost"
        disabled={isLast}
        onClick={onDown}
        title="Move rule down"
        style={{ padding: "0 6px" }}
      >
        ↓
      </button>
      <button
        className="ghost danger"
        onClick={onRemove}
        title="Remove rule"
        style={{ padding: "0 6px" }}
      >
        ✕
      </button>
    </div>
  );
}
