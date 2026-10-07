import { CSSProperties, useEffect, useMemo, useRef, useState } from "react";
import { api, Scope, ScopeRule, StoredFinding, StoredSummary } from "../api";
import { DiscoveryModal, DiscoveryTargetPreset } from "./DiscoveryModal";
import { WellKnownImportModal, WellKnownPreset } from "./WellKnownImportModal";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import {
  buildHostIncludeRule,
  buildPathIncludeRule,
  hasHostIncludeRule,
  hasPathIncludeRule,
  withoutHost,
} from "../scopeHelpers";
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

type Sub = "sitemap" | "scope" | "issues" | "analyzer";

/** Deep-link payload from the SiteMap host-badge click to the
 *  Issues sub-tab. Both fields optional so the operator can jump
 *  with just a host (click the host row's total count), just a
 *  severity (click a severity pill with no host context), or both
 *  (click a specific severity pill on a specific host — the common
 *  path). IssuesPane consumes it once on mount and clears via
 *  `onFilterConsumed`. */
type IssueDeepLink = {
  host?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
};

export function TargetPanel() {
  const [sub, setSub] = useState<Sub>("sitemap");
  // Pending host + severity filter staged by a SiteMap badge click
  // or a cross-panel deep-link (Dashboard "Findings by host" row).
  // Consumed exactly once by IssuesPane on mount — the pane's own
  // chip filters take over from that point on so the operator stays
  // in control.
  const [pendingIssueFilter, setPendingIssueFilter] =
    useState<IssueDeepLink | null>(null);
  // Pending sitemap search term staged by a cross-panel deep-link
  // (HistoryPanel "Open host in SiteMap"). Same consume-once rails
  // as pendingIssueFilter.
  const [pendingSitemapSearch, setPendingSitemapSearch] =
    useState<string | null>(null);

  function openIssuesWithFilter(payload: IssueDeepLink) {
    setPendingIssueFilter(payload);
    setSub("issues");
  }

  // Cross-panel deep-link: other panels (currently just Dashboard's
  // "Findings by host" rows) dispatch `burpfree:target-filter-issues`
  // with `{ host?, severity? }` to pivot into Target → Issues with
  // the filter pre-applied. The listener stages the filter + flips
  // the sub tab; App.tsx is the one firing the navigate event so we
  // just need to catch the detail and stage.
  useEffect(() => {
    const onFilter = (e: Event) => {
      const detail = (e as CustomEvent<IssueDeepLink>).detail;
      if (!detail) return;
      openIssuesWithFilter(detail);
    };
    window.addEventListener("burpfree:target-filter-issues", onFilter as EventListener);
    return () =>
      window.removeEventListener(
        "burpfree:target-filter-issues",
        onFilter as EventListener,
      );
  }, []);

  // R110 cross-panel deep-link: HistoryPanel's "Open host in
  // SiteMap" row action fires `burpfree:target-sitemap-search`
  // with `{host}` + an App-level navigate to "target". We stage
  // the host here and flip to the sitemap sub so SiteMapPane
  // mounts with the pending value already in scope.
  useEffect(() => {
    const onSitemapSearch = (e: Event) => {
      const detail = (e as CustomEvent<{ host?: string }>).detail;
      if (!detail?.host) return;
      setPendingSitemapSearch(detail.host);
      setSub("sitemap");
    };
    window.addEventListener("burpfree:target-sitemap-search", onSitemapSearch as EventListener);
    return () =>
      window.removeEventListener(
        "burpfree:target-sitemap-search",
        onSitemapSearch as EventListener,
      );
  }, []);
  return (
    <div className="panel">
      <div className="sub-tabs">
        <div className={`tab ${sub === "sitemap"  ? "active" : ""}`} onClick={() => setSub("sitemap")}>Site map</div>
        <div className={`tab ${sub === "scope"    ? "active" : ""}`} onClick={() => setSub("scope")}>Scope</div>
        <div className={`tab ${sub === "issues"   ? "active" : ""}`} onClick={() => setSub("issues")}>Issues</div>
        <div className={`tab ${sub === "analyzer" ? "active" : ""}`} onClick={() => setSub("analyzer")}>Analyzer</div>
      </div>
      {sub === "sitemap"  && (
        <SiteMapPane
          onFilterIssues={openIssuesWithFilter}
          pendingSearch={pendingSitemapSearch}
          onSearchConsumed={() => setPendingSitemapSearch(null)}
        />
      )}
      {sub === "scope"    && <ScopePane />}
      {sub === "issues"   && (
        <IssuesPane
          pendingFilter={pendingIssueFilter}
          onFilterConsumed={() => setPendingIssueFilter(null)}
        />
      )}
      {sub === "analyzer" && <AnalyzerPane />}
    </div>
  );
}

type SiteNode = {
  segment: string;
  children: Record<string, SiteNode>;
  methods: string[];
  status_codes: number[];
  content_types: string[];
  transaction_ids: number[];
  in_scope: boolean;
};

/** Burp-style highlight palette — mirrors `HIGHLIGHT_COLORS` in
 *  HistoryPanel. Kept local so TargetPanel doesn't import across
 *  sibling panel files. */
const SITEMAP_HIGHLIGHTS: Array<{ name: string; hex: string }> = [
  { name: "red", hex: "#ef4b4b" },
  { name: "orange", hex: "#f39c3b" },
  { name: "yellow", hex: "#f0d234" },
  { name: "green", hex: "#4bbf6b" },
  { name: "cyan", hex: "#4bc5bf" },
  { name: "blue", hex: "#4b8def" },
  { name: "purple", hex: "#a670ef" },
];

function SiteMapPane({
  onFilterIssues,
  pendingSearch,
  onSearchConsumed,
}: {
  onFilterIssues: (payload: IssueDeepLink) => void;
  /** Pre-seeded search term from a cross-panel deep-link
   *  (HistoryPanel "Open host in SiteMap"). Consumed on mount
   *  exactly once; the sub-tab remount pattern (SiteMapPane
   *  unmounts when the operator leaves "sitemap") means a stale
   *  pending value needs to be nulled by the parent via
   *  `onSearchConsumed` so a back-and-forth round-trip doesn't
   *  re-apply it. */
  pendingSearch?: string | null;
  onSearchConsumed?: () => void;
}) {
  const [snap, setSnap] = useState<Record<string, SiteNode>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<SiteNode | null>(null);
  // Node key for the current selection — `host/seg1/seg2` style, so we can
  // extract the host when writing the per-host note without walking the
  // tree each render.
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [rows, setRows] = useState<StoredSummary[]>([]);
  // Current host-note draft + the saved value on disk. Keeping them
  // separate lets us surface an unsaved indicator without racing the
  // save round-trip.
  const [noteDraft, setNoteDraft] = useState("");
  const [noteSaved, setNoteSaved] = useState("");
  const selectedHost = selectedKey ? selectedKey.split("/")[0] : null;

  // Refresh the saved note whenever the selected host changes.
  useEffect(() => {
    if (!selectedHost) {
      setNoteSaved("");
      setNoteDraft("");
      return;
    }
    api
      .hostNoteGet(selectedHost)
      .then((n) => {
        setNoteSaved(n ?? "");
        setNoteDraft(n ?? "");
      })
      .catch(() => {
        setNoteSaved("");
        setNoteDraft("");
      });
  }, [selectedHost]);

  async function commitHostNote() {
    if (!selectedHost) return;
    if (noteDraft === noteSaved) return;
    try {
      await api.hostNoteSet(selectedHost, noteDraft);
      setNoteSaved(noteDraft);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // Per-host finding count breakdown. Polled on the same 2 s cadence
  // as the sitemap snapshot so the badges track live scanner output.
  // Shape: host → severity → count (lower-cased severity keys).
  const [hostCounts, setHostCounts] = useState<Record<string, Record<string, number>>>({});
  // Case-insensitive substring filter against host names. Empty =
  // show everything. Operators pivot to a specific host in a 50-
  // host engagement without scrolling the whole tree. Path-level
  // matches aren't included — operators can expand a matched host
  // manually. Mirror of Burp's SiteMap search box.
  const [siteSearch, setSiteSearch] = useState(pendingSearch ?? "");
  // R184: Hide-empty-hosts toggle — operators often see 20+ hosts
  // in the site map but only 5 have actual observed endpoints
  // (DNS-only lookups, CORS pre-flights to never-reached hosts,
  // etc). When on, filters the host list to only those with
  // transaction_ids.length > 0. Persisted via localStorage so a
  // reload keeps the operator's chosen layout.
  const [hideEmptyHosts, setHideEmptyHosts] = useState<boolean>(() => {
    try {
      return localStorage.getItem("target.hideEmptyHosts") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("target.hideEmptyHosts", hideEmptyHosts ? "1" : "0");
    } catch {
      /* localStorage disabled — persist best-effort */
    }
  }, [hideEmptyHosts]);

  // Consume the deep-link exactly once on mount — same pattern as
  // IssuesPane's pendingFilter in R92. The useState initialiser
  // picks up the value; this effect fires the consumed callback so
  // TargetPanel nulls the pending value and a round-trip doesn't
  // re-apply it.
  useEffect(() => {
    if (pendingSearch) onSearchConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const t = setInterval(() => {
      api.sitemapSnapshot().then(setSnap).catch(() => {});
      api.findingsCountByHost().then(setHostCounts).catch(() => {});
    }, 2000);
    return () => clearInterval(t);
  }, []);

  // When the selected node changes, fetch its enriched transaction rows.
  useEffect(() => {
    if (!selected || selected.transaction_ids.length === 0) {
      setRows([]);
      return;
    }
    // Cap at 500 to keep the right pane snappy.
    const ids = selected.transaction_ids.slice(-500);
    api.historySummaries(ids).then(setRows).catch(() => setRows([]));
  }, [selected?.transaction_ids]);

  function toggle(key: string) {
    const next = new Set(expanded);
    next.has(key) ? next.delete(key) : next.add(key);
    setExpanded(next);
  }

  const scopeFilter = selected?.in_scope ? "" : "out of scope";
  const [discoveryOpen, setDiscoveryOpen] = useState(false);
  const [discoveryPreset, setDiscoveryPreset] = useState<DiscoveryTargetPreset | null>(null);
  const [wellKnownOpen, setWellKnownOpen] = useState(false);
  const [wellKnownPreset, setWellKnownPreset] = useState<WellKnownPreset | null>(null);
  const [nodeMenu, setNodeMenu] = useState<MenuState<{
    node: SiteNode;
    host: string;
    path: string;
  }> | null>(null);
  // Scope state so the sitemap menu can grey out already-in-scope ops
  // without refetching on every open.
  const [scope, setScope] = useState<Scope | null>(null);
  useEffect(() => {
    api.scopeGet().then(setScope).catch(() => setScope(null));
  }, []);
  async function reloadScope() {
    try { setScope(await api.scopeGet()); } catch {}
  }

  function onTreeContextMenu(e: React.MouseEvent, node: SiteNode, nodeKey: string) {
    e.preventDefault();
    setSelected(node);
    // `nodeKey` is "host/seg1/seg2" — the top-level key is the host.
    const parts = nodeKey.split("/");
    const host = parts[0] || node.segment || "";
    // The path is everything after the host; empty → "/".
    const rawPath = "/" + parts.slice(1).join("/");
    const path = rawPath === "/" ? "/" : rawPath;
    setNodeMenu({ x: e.clientX, y: e.clientY, data: { node, host, path } });
  }

  async function addNodeHostToScope(host: string) {
    try {
      await api.scopeAddRule(buildHostIncludeRule(host));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }
  async function addNodePathToScope(host: string, path: string) {
    try {
      await api.scopeAddRule(buildPathIncludeRule(host, path));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }
  async function removeNodeHostFromScope(host: string) {
    if (!scope) return;
    try {
      await api.scopeSet(withoutHost(scope, host));
      await reloadScope();
    } catch (e) { alert(`${e}`); }
  }

  async function copyNodePathToClipboard(node: SiteNode) {
    try {
      await navigator.clipboard.writeText(node.segment || "/");
    } catch (e) {
      alert(`${e}`);
    }
  }

  /** Bulk-set the highlight on every transaction whose `host` matches
   *  the supplied value. Pulls up to 2000 rows via `history_list` so a
   *  host with 50k entries doesn't DDOS the UI; confirms when the
   *  affected count is sizeable. `color` null clears the highlight. */
  async function bulkHighlightHost(host: string, color: string | null) {
    try {
      const rows = await api.historyList({ host_contains: host, limit: 2000 });
      const victims = rows.filter((r) => r.host === host).map((r) => r.id);
      if (victims.length === 0) {
        alert(`No stored transactions found for ${host}.`);
        return;
      }
      if (
        victims.length > 100 &&
        !confirm(
          `${color == null ? "Clear highlight on" : "Highlight"} ${victims.length} transaction${victims.length === 1 ? "" : "s"} from ${host}?`,
        )
      ) {
        return;
      }
      await Promise.all(
        victims.map((id) => api.historySetHighlight(id, color)),
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  /** Jump to the HTTP History panel with the filter already narrowed
   *  to this host. Fires `burpfree:history-filter` so HistoryPanel can
   *  merge it into its own filter state, then navigates. */
  function openHostInHistory(host: string) {
    window.dispatchEvent(
      new CustomEvent("burpfree:history-filter", {
        detail: { host },
      }),
    );
    // R248: Same stale {section} key fix as R247 — App.tsx's
    // burpfree:navigate listener consumes {target}. This navigate
    // was a no-op before the fix (only the burpfree:history-filter
    // event ahead of it landed, so operators saw their host filter
    // applied but had to switch to the History tab manually).
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", {
        detail: { target: "history" },
      }),
    );
  }

  function openDiscoveryForNode(node: SiteNode) {
    const first = node.transaction_ids[0];
    if (first == null) {
      alert("No transactions on this node yet — pick a leaf with observed traffic.");
      return;
    }
    api.historySummaries([first]).then((rows) => {
      const summary = rows[0];
      if (!summary) return;
      setDiscoveryPreset({ scheme: summary.scheme, host: summary.host, port: summary.port });
      setDiscoveryOpen(true);
    });
  }

  function openDiscoveryForSelected() {
    if (rows.length === 0) {
      alert("No observations on this node yet — browse through the proxy first, or open Discovery and set a host manually.");
      return;
    }
    const first = rows[0];
    setDiscoveryPreset({ scheme: first.scheme, host: first.host, port: first.port });
    setDiscoveryOpen(true);
  }

  /** Open the well-known import modal with a preset derived from
   *  the currently-selected sitemap node — the first observed row
   *  on that node gives us scheme + host + port. Nothing selected
   *  (or no observations yet) → modal still opens, operator types
   *  a base URL manually. */
  function openWellKnownForSelected() {
    const first = rows[0];
    setWellKnownPreset(
      first
        ? { scheme: first.scheme, host: first.host, port: first.port }
        : null,
    );
    setWellKnownOpen(true);
  }

  /** Context-menu entry: fire the well-known import against a
   *  right-clicked host. The sitemap's host key is just the host
   *  string so we don't have scheme/port in hand — synthesize
   *  https/443 as the default (Burp's own choice) and let the
   *  operator tweak the URL in the modal if they wanted http. */
  function openWellKnownForHost(host: string) {
    setWellKnownPreset({ scheme: "https", host, port: 443 });
    setWellKnownOpen(true);
  }

  const coverage = useMemo(() => computeCoverage(snap), [snap]);

  return (
    <div style={{ display: "flex", flex: 1, minHeight: 0, flexDirection: "column" }}>
      <div
        style={{
          display: "flex",
          gap: 10,
          padding: "4px 10px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-raised)",
          fontSize: 11,
          alignItems: "center",
          flexWrap: "wrap",
        }}
        title="Live site-map coverage. In-scope ratios let you see which hosts your scope rules actually catch."
      >
        <span>
          <b>Hosts:</b> {coverage.inScopeHosts}/{coverage.totalHosts} in scope
        </span>
        <span>
          <b>Endpoints:</b> {coverage.totalEndpoints}
        </span>
        <span>
          <b>In-scope endpoints:</b> {coverage.inScopeEndpoints}
        </span>
        <span>
          <b>Deep paths:</b> {coverage.deepPaths}
        </span>
        <span>
          <b>Leaves:</b> {coverage.leaves}
        </span>
        <span className="dim" style={{ marginLeft: "auto" }}>
          Observed requests: {coverage.totalRequests}
        </span>
        <button
          className="ghost"
          onClick={openWellKnownForSelected}
          title="Fetch /robots.txt and /sitemap.xml for the selected host (or any URL you type). Discovered URLs can be sent to Repeater or bulk-added to scope."
          style={{ fontSize: 11 }}
        >
          Import robots.txt + sitemap.xml
        </button>
      </div>
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
      <div style={{ width: 360, borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column" }}>
        {/* --------- Search box ---------- */}
        {(() => {
          const totalHosts = Object.keys(snap).length;
          const q = siteSearch.trim().toLowerCase();
          const filteredKeys = Object.keys(snap).filter((h) => {
            if (q && !h.toLowerCase().includes(q)) return false;
            if (
              hideEmptyHosts &&
              (snap[h]?.transaction_ids?.length ?? 0) === 0
            )
              return false;
            return true;
          });
          const matchCount = filteredKeys.length;
          const hiddenEmpty = hideEmptyHosts
            ? Object.values(snap).filter(
                (n) => (n?.transaction_ids?.length ?? 0) === 0,
              ).length
            : 0;
          return (
            <>
              <div
                style={{
                  padding: "6px 8px",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                  fontSize: 11.5,
                }}
              >
                <input
                  type="text"
                  value={siteSearch}
                  onChange={(e) => setSiteSearch(e.target.value)}
                  onKeyDown={(e) => {
                    // R223: Esc clears the sitemap host filter —
                    // consistent with R201 (History search), R219
                    // (Target Issues search). Fires only when the
                    // input has text so Esc stays available for
                    // modals / popovers elsewhere when empty.
                    if (e.key === "Escape" && siteSearch) {
                      e.preventDefault();
                      setSiteSearch("");
                    }
                  }}
                  placeholder="Filter hosts… (Esc clears)"
                  style={{
                    flex: 1,
                    padding: "3px 6px",
                    fontSize: 11.5,
                    background: siteSearch ? "rgba(100,150,255,0.14)" : undefined,
                    border: siteSearch
                      ? "1px solid rgba(100,150,255,0.5)"
                      : "1px solid var(--border)",
                    borderRadius: 3,
                    color: "var(--text)",
                  }}
                />
                {siteSearch && (
                  <button
                    className="ghost"
                    onClick={() => setSiteSearch("")}
                    title="Clear filter"
                    style={{ padding: "2px 6px", fontSize: 11 }}
                  >
                    ×
                  </button>
                )}
                {/* R184: Hide-empty-hosts toggle. When on, filters   */}
                {/* out hosts with no observed endpoints (DNS-only,   */}
                {/* pre-flight ghosts, etc). Live hidden-count         */}
                {/* subscript tells the operator the blast radius.    */}
                <button
                  className={`ghost ${hideEmptyHosts ? "on" : ""}`}
                  onClick={() => setHideEmptyHosts((v) => !v)}
                  title={
                    hideEmptyHosts
                      ? `Hiding ${hiddenEmpty} host${hiddenEmpty === 1 ? "" : "s"} with no observed endpoints — click to show`
                      : "Hide hosts with zero observed endpoints (DNS-only / pre-flight ghosts)"
                  }
                  style={{
                    padding: "2px 6px",
                    fontSize: 11,
                    whiteSpace: "nowrap",
                  }}
                >
                  {hideEmptyHosts ? "👁️‍🗨️ hiding empty" : "👁 show empty"}
                </button>
                {/* R128: Expand / Collapse all. Burp's Site map   */}
                {/* has these as toolbar actions — invaluable when */}
                {/* an engagement touches 50+ hosts and the        */}
                {/* operator wants a bird's-eye view of the whole  */}
                {/* path tree without clicking every chevron.      */}
                <button
                  className="ghost"
                  onClick={() => {
                    // Walk the whole tree and collect every nodeKey
                    // that has at least one child — these are the
                    // togglable rows. Leaf nodes with no children
                    // don't need to be in the expanded set.
                    const all = new Set<string>();
                    const walk = (key: string, node: SiteNode | undefined) => {
                      if (!node) return;
                      const kids = Object.entries(node.children || {});
                      if (kids.length === 0) return;
                      all.add(key);
                      for (const [childSeg, childNode] of kids) {
                        walk(`${key}/${childSeg}`, childNode);
                      }
                    };
                    for (const hostKey of Object.keys(snap)) {
                      walk(hostKey, snap[hostKey]);
                    }
                    setExpanded(all);
                  }}
                  disabled={Object.keys(snap).length === 0}
                  title="Expand every host + path in the site map"
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  ⇲ all
                </button>
                <button
                  className="ghost"
                  onClick={() => setExpanded(new Set())}
                  disabled={expanded.size === 0}
                  title={
                    expanded.size === 0
                      ? "Nothing to collapse"
                      : `Collapse all ${expanded.size} open node${expanded.size === 1 ? "" : "s"}`
                  }
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  ⇱ all
                </button>
                {/* R135: Export sitemap as JSON. Burp has an        */}
                {/* "Export sitemap" action in the Target menu —      */}
                {/* snapshots the entire observed path tree for      */}
                {/* teammate handoff or diffing between engagements. */}
                {/* We dump the current `snap` state (host → nested  */}
                {/* SiteNode tree) as pretty JSON. Zero backend —    */}
                {/* snap is already in memory on the frontend.       */}
                <button
                  className="ghost"
                  disabled={Object.keys(snap).length === 0}
                  onClick={() => {
                    try {
                      const payload = JSON.stringify(snap, null, 2);
                      const blob = new Blob([payload], {
                        type: "application/json;charset=utf-8",
                      });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      const stamp = new Date()
                        .toISOString()
                        .replace(/[:T]/g, "-")
                        .replace(/\..*$/, "");
                      a.href = url;
                      a.download = `burpfree-sitemap-${stamp}.json`;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  }}
                  title={
                    Object.keys(snap).length === 0
                      ? "No hosts observed yet — nothing to export"
                      : `Export the entire site map (${Object.keys(snap).length} host${Object.keys(snap).length === 1 ? "" : "s"}) as a JSON snapshot`
                  }
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  ⬇ JSON
                </button>
                {/* R292: CSV companion to R135 JSON export. JSON is  */}
                {/* great for teammate handoff / nested-structure     */}
                {/* diffing but hard to triage visually in Excel /    */}
                {/* Sheets. CSV flattens the tree to one-row-per-     */}
                {/* endpoint so operators can sort by host / method   */}
                {/* count / in-scope state in a spreadsheet. Walks    */}
                {/* snap depth-first and emits a row for every node    */}
                {/* that has at least one observed transaction (leaf   */}
                {/* OR directory with its own traffic — e.g. /api).    */}
                <button
                  className="ghost"
                  disabled={Object.keys(snap).length === 0}
                  onClick={() => {
                    try {
                      type Row = {
                        host: string;
                        path: string;
                        in_scope: boolean;
                        methods: string[];
                        status_codes: number[];
                        content_types: string[];
                        tx_count: number;
                      };
                      const rows: Row[] = [];
                      // Depth-first walk emitting a row for every node
                      // that has at least one observed tx. The segment
                      // tree stores path parts; join with "/" and
                      // prepend "/" for the leading-slash convention.
                      function walk(
                        host: string,
                        node: SiteNode,
                        pathParts: string[],
                      ) {
                        const path =
                          pathParts.length === 0
                            ? "/"
                            : "/" + pathParts.join("/");
                        if (node.transaction_ids.length > 0) {
                          rows.push({
                            host,
                            path,
                            in_scope: node.in_scope,
                            methods: node.methods,
                            status_codes: node.status_codes,
                            content_types: node.content_types,
                            tx_count: node.transaction_ids.length,
                          });
                        }
                        for (const child of Object.values(node.children)) {
                          walk(host, child, [...pathParts, child.segment]);
                        }
                      }
                      for (const [host, rootNode] of Object.entries(snap)) {
                        walk(host, rootNode as SiteNode, []);
                      }
                      // Stable sort — by host, then path — so repeat
                      // exports diff cleanly.
                      rows.sort((a, b) => {
                        const h = a.host.localeCompare(b.host);
                        return h !== 0 ? h : a.path.localeCompare(b.path);
                      });
                      const headers = [
                        "host",
                        "path",
                        "in_scope",
                        "methods",
                        "status_codes",
                        "content_types",
                        "tx_count",
                      ];
                      const esc = (v: unknown) => {
                        const s = v == null ? "" : String(v);
                        return /[",\n]/.test(s)
                          ? `"${s.replace(/"/g, '""')}"`
                          : s;
                      };
                      const body = rows
                        .map((r) =>
                          [
                            r.host,
                            r.path,
                            r.in_scope ? 1 : 0,
                            r.methods.join("|"),
                            r.status_codes.join("|"),
                            r.content_types.join("|"),
                            r.tx_count,
                          ]
                            .map(esc)
                            .join(","),
                        )
                        .join("\n");
                      const csv = [headers.join(","), body].join("\n");
                      const blob = new Blob([csv], {
                        type: "text/csv;charset=utf-8",
                      });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      const stamp = new Date()
                        .toISOString()
                        .replace(/[:T]/g, "-")
                        .replace(/\..*$/, "");
                      a.href = url;
                      a.download = `burpfree-sitemap-${stamp}.csv`;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  }}
                  title={
                    Object.keys(snap).length === 0
                      ? "No hosts observed yet — nothing to export"
                      : `Export the sitemap as a CSV (one row per endpoint with observed traffic — flattens the tree for Excel / Sheets triage).`
                  }
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  ⬇ CSV
                </button>
                {/* R604: Clipboard-only CSV counterpart to the
                    sitemap "⬇ CSV" export. Fifth entry in the
                    cross-panel "📋 Copy as CSV" family (HistoryPanel
                    R600 / Scanner R601 / Logger R602 / Intruder R603
                    / Target sitemap R604). Operators pasting
                    endpoint tables into Excel / Sheets for scope
                    audits ("which hosts have I actually hit?") want
                    the clipboard shortcut. Byte-identical column
                    shape to the file export (same 7 columns, same
                    esc rules, same depth-first walk + stable sort). */}
                <button
                  className="ghost"
                  disabled={Object.keys(snap).length === 0}
                  onClick={() => {
                    try {
                      type Row = {
                        host: string;
                        path: string;
                        in_scope: boolean;
                        methods: string[];
                        status_codes: number[];
                        content_types: string[];
                        tx_count: number;
                      };
                      const rows: Row[] = [];
                      function walk(
                        host: string,
                        node: SiteNode,
                        pathParts: string[],
                      ) {
                        const path =
                          pathParts.length === 0
                            ? "/"
                            : "/" + pathParts.join("/");
                        if (node.transaction_ids.length > 0) {
                          rows.push({
                            host,
                            path,
                            in_scope: node.in_scope,
                            methods: node.methods,
                            status_codes: node.status_codes,
                            content_types: node.content_types,
                            tx_count: node.transaction_ids.length,
                          });
                        }
                        for (const child of Object.values(node.children)) {
                          walk(host, child, [...pathParts, child.segment]);
                        }
                      }
                      for (const [host, rootNode] of Object.entries(snap)) {
                        walk(host, rootNode as SiteNode, []);
                      }
                      rows.sort((a, b) => {
                        const h = a.host.localeCompare(b.host);
                        return h !== 0 ? h : a.path.localeCompare(b.path);
                      });
                      const headers = [
                        "host",
                        "path",
                        "in_scope",
                        "methods",
                        "status_codes",
                        "content_types",
                        "tx_count",
                      ];
                      const esc = (v: unknown) => {
                        const s = v == null ? "" : String(v);
                        return /[",\n]/.test(s)
                          ? `"${s.replace(/"/g, '""')}"`
                          : s;
                      };
                      const body = rows
                        .map((r) =>
                          [
                            r.host,
                            r.path,
                            r.in_scope ? 1 : 0,
                            r.methods.join("|"),
                            r.status_codes.join("|"),
                            r.content_types.join("|"),
                            r.tx_count,
                          ]
                            .map(esc)
                            .join(","),
                        )
                        .join("\n");
                      const csv = [headers.join(","), body].join("\n");
                      void navigator.clipboard.writeText(csv);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  }}
                  title={
                    Object.keys(snap).length === 0
                      ? "No hosts observed yet — nothing to copy"
                      : `Copy the sitemap as CSV to clipboard (one row per endpoint with observed traffic — same 7 columns as ⬇ CSV: host, path, in_scope, methods, status_codes, content_types, tx_count). Paste into Excel / Sheets without the file-save roundtrip. Fifth entry in the cross-panel Copy-as-CSV family.`
                  }
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  📋 CSV
                </button>
                <span
                  className="dim"
                  title={
                    q
                      ? `Showing ${matchCount} of ${totalHosts} hosts whose name contains "${q}"`
                      : `${totalHosts} host${totalHosts === 1 ? "" : "s"} observed`
                  }
                  style={{ fontSize: 10.5, whiteSpace: "nowrap" }}
                >
                  {q ? `${matchCount} / ${totalHosts}` : `${totalHosts}`}
                </span>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: 4 }}>
                {/* R847: Burp-identical Target sitemap empty state.
                    Completes the empty-state card family (R776 Proxy
                    intercept / R778 History / R781 Scanner / R782
                    Collaborator / R783 Logger). Replaces the previous
                    one-line "No hosts observed yet" placeholder with
                    a full card: centered SVG tree-icon silhouette,
                    bold headline, descriptive subhead explaining the
                    passive sitemap building block, and a hint strip
                    with the typical kick-off actions. */}
                {totalHosts === 0 && (
                  <div className="log-empty-card" style={{ margin: "20px 10px" }}>
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
                        {/* Tree with hostname + 3 branches — matches Burp's
                            Target sitemap canonical empty icon. */}
                        <circle cx="12" cy="4" r="2" />
                        <path d="M12 6v4M6 10h12M6 10v4M12 10v4M18 10v4" />
                        <circle cx="6" cy="16" r="2" />
                        <circle cx="12" cy="16" r="2" />
                        <circle cx="18" cy="16" r="2" />
                      </svg>
                    </div>
                    <div className="log-empty-title">
                      No hosts in site map yet
                    </div>
                    <div className="log-empty-sub">
                      Target's site map populates as traffic flows through the proxy —{" "}
                      <b>point your browser at this listener</b> and start browsing, or{" "}
                      <b>import an OpenAPI / Postman collection</b> from the sitemap toolbar,
                      or run <b>robots.txt + sitemap.xml import</b> for a known host. Every
                      observed URL lands here with its scope status, methods, status codes,
                      and content types.
                    </div>
                    <div className="log-empty-hints">
                      Shortcuts: right-click a tree node for Add-to-scope / Open-Discover /
                      Expand-all / Copy-URL · hosts carry a • dot when they have observed
                      traffic · the Scope sub-tab controls what's considered in-bounds
                    </div>
                  </div>
                )}
                {totalHosts > 0 && matchCount === 0 && (
                  <div className="empty">
                    No hosts match <code className="mono">{siteSearch}</code>.
                  </div>
                )}
                {filteredKeys.map((key) => (
                  <TreeRow
                    key={key}
                    nodeKey={key}
                    node={snap[key]}
                    depth={0}
                    expanded={expanded}
                    toggle={toggle}
                    onSelect={(n, k) => { setSelected(n); setSelectedKey(k); }}
                    selected={selected}
                    onContextMenu={onTreeContextMenu}
                    hostCounts={hostCounts}
                    onFilterIssues={onFilterIssues}
                  />
                ))}
              </div>
            </>
          );
        })()}
      </div>
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        {!selected && <div className="empty">Select a node to inspect its observed requests.</div>}
        {selected && (
          <>
            <div className="toolbar" style={{ borderBottom: "1px solid var(--border)" }}>
              <strong style={{ fontFamily: "var(--mono)" }}>{selected.segment || "/"}</strong>
              <span className="dim">{rows.length} / {selected.transaction_ids.length} obs</span>
              {scopeFilter && <span className="badge red">{scopeFilter}</span>}
              <span className="spacer" style={{ flex: 1 }} />
              <button className="ghost" onClick={openDiscoveryForSelected} title="Brute-force paths against this host">
                Discover content
              </button>
              <span className="dim mono">{selected.methods.join(" · ") || "—"}</span>
            </div>
            {selectedHost && (
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 8,
                  padding: "6px 10px",
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                  fontSize: 11.5,
                }}
              >
                <strong
                  style={{
                    color: "var(--text-dim)",
                    minWidth: 60,
                    paddingTop: 4,
                    userSelect: "none",
                  }}
                  title={`Free-form note scoped to ${selectedHost}; persists in the project config`}
                >
                  Note
                </strong>
                <textarea
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  onBlur={() => void commitHostNote()}
                  onKeyDown={(e) => {
                    if (e.key === "Escape") {
                      e.preventDefault();
                      setNoteDraft(noteSaved);
                      (e.target as HTMLTextAreaElement).blur();
                    } else if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                      e.preventDefault();
                      void commitHostNote();
                      (e.target as HTMLTextAreaElement).blur();
                    }
                  }}
                  placeholder={`Add notes for ${selectedHost} — persists across restarts`}
                  spellCheck={false}
                  style={{
                    flex: 1,
                    minHeight: 36,
                    maxHeight: 120,
                    resize: "vertical",
                    padding: "4px 6px",
                    border: `1px solid ${noteDraft === noteSaved ? "var(--border)" : "var(--accent)"}`,
                    borderRadius: 4,
                    background: "var(--bg)",
                    color: "var(--text)",
                    fontFamily: "var(--mono)",
                    fontSize: 11.5,
                  }}
                />
                {noteDraft !== noteSaved && (
                  <span
                    style={{ color: "var(--accent)", fontSize: 10.5, paddingTop: 6 }}
                    title="Blur or Ctrl+Enter to save; Esc to revert"
                  >
                    unsaved
                  </span>
                )}
              </div>
            )}
            <div className="table" style={{ flex: 1, overflow: "auto" }}>
              <table>
                <colgroup>
                  <col style={{ width: 60 }} />
                  <col style={{ width: 60 }} />
                  <col style={{ width: 55 }} />
                  <col />
                  <col style={{ width: 38 }} />
                  <col style={{ width: 70 }} />
                  <col style={{ width: 90 }} />
                  <col style={{ width: 240 }} />
                  <col style={{ width: 70 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>URL</th>
                    <th title="Request has params">P</th>
                    <th>Length</th>
                    <th>MIME</th>
                    <th>Title</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <td className="mono">{r.id}</td>
                      <td className="mono">{r.method}</td>
                      <td className={`mono status-${Math.floor((r.status || 0) / 100)}xx`}>{r.status ?? "—"}</td>
                      <td className="mono" title={r.path}>{r.path}</td>
                      <td
                        className="mono"
                        style={{ textAlign: "center", color: (r.param_count ?? 0) > 0 ? "var(--accent)" : "var(--text-faint)" }}
                        title={(r.param_count ?? 0) > 0 ? `${r.param_count} parameter(s)` : "no parameters"}
                      >
                        {(r.param_count ?? 0) > 0 ? "✓" : ""}
                      </td>
                      <td className="mono">{r.content_length ?? "—"}</td>
                      <td className="mono" style={{ color: "var(--text-dim)" }} title={r.content_type ?? ""}>{shortMime(r.content_type)}</td>
                      <td style={{ color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.title ?? ""}>
                        {r.title ?? ""}
                      </td>
                      <td className="mono">{r.elapsed_ms ?? "—"} ms</td>
                    </tr>
                  ))}
                  {rows.length === 0 && (
                    <tr><td colSpan={9} className="dim" style={{ padding: 10, textAlign: "center" }}>no observations on this node</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
      <DiscoveryModal
        open={discoveryOpen}
        preset={discoveryPreset}
        onClose={() => setDiscoveryOpen(false)}
      />
      <WellKnownImportModal
        open={wellKnownOpen}
        preset={wellKnownPreset}
        onClose={() => setWellKnownOpen(false)}
      />
      <FloatingMenu
        state={nodeMenu}
        onClose={() => setNodeMenu(null)}
        items={
          nodeMenu?.data
            ? [
                {
                  label: nodeMenu.data.node.in_scope ? "✓ In scope" : "Out of scope",
                  disabled: true,
                },
                { separator: true },
                {
                  label: `Add host ${nodeMenu.data.host} to scope`,
                  disabled: hasHostIncludeRule(scope, nodeMenu.data.host),
                  hint: hasHostIncludeRule(scope, nodeMenu.data.host) ? "already in scope" : undefined,
                  onClick: () => void addNodeHostToScope(nodeMenu.data!.host),
                },
                {
                  label: "Add path to scope",
                  hint: nodeMenu.data.path,
                  disabled:
                    nodeMenu.data.path === "/" ||
                    hasPathIncludeRule(scope, nodeMenu.data.host, nodeMenu.data.path),
                  onClick: () =>
                    void addNodePathToScope(nodeMenu.data!.host, nodeMenu.data!.path),
                },
                {
                  label: "Remove host from scope",
                  disabled: !hasHostIncludeRule(scope, nodeMenu.data.host),
                  danger: hasHostIncludeRule(scope, nodeMenu.data.host),
                  onClick: () => void removeNodeHostFromScope(nodeMenu.data!.host),
                },
                { separator: true },
                {
                  label: "Open host in HTTP history",
                  hint: "pre-filters by host + navigates",
                  onClick: () => openHostInHistory(nodeMenu.data!.host),
                },
                {
                  label: `Open https://${nodeMenu.data.host}${nodeMenu.data.path} in browser`,
                  hint: "fire URL at the OS default browser",
                  onClick: () => {
                    const path =
                      nodeMenu.data!.path === "/" ? "/" : nodeMenu.data!.path;
                    void api
                      .shellOpenUrl(`https://${nodeMenu.data!.host}${path}`)
                      .catch((e) => alert(`${e}`));
                  },
                },
                ...SITEMAP_HIGHLIGHTS.map((c) => ({
                  label: `Highlight all tx on host · ${c.name}`,
                  hint: c.hex,
                  onClick: () =>
                    void bulkHighlightHost(nodeMenu.data!.host, c.name),
                })),
                {
                  label: "Highlight all tx on host · clear",
                  onClick: () => void bulkHighlightHost(nodeMenu.data!.host, null),
                },
                { separator: true },
                {
                  label: "Discover content on this host",
                  onClick: () => openDiscoveryForNode(nodeMenu.data!.node),
                  disabled: (nodeMenu.data.node.transaction_ids?.length ?? 0) === 0,
                  hint: "brute-force paths against this host",
                },
                {
                  label: "Import robots.txt + sitemap.xml",
                  onClick: () => openWellKnownForHost(nodeMenu.data!.host),
                  hint: "well-known fetch",
                },
                {
                  label: "Expand / collapse node",
                  onClick: () => {
                    const key =
                      Object.entries(snap).find(([_k, v]) => v === nodeMenu.data!.node)?.[0];
                    if (key) toggle(key);
                  },
                },
                { separator: true },
                {
                  label: `Copy segment: ${nodeMenu.data.node.segment || "/"}`,
                  onClick: () => void copyNodePathToClipboard(nodeMenu.data!.node),
                },
                /* R163: Copy host (just host[:port] without path /    */
                /* scheme) + Copy full URL (https://host/path) — the  */
                /* existing Copy segment is useful but incomplete; a   */
                /* bug-report / Slack paste typically wants the whole  */
                /* URL + a separate host for a config entry. Both      */
                /* reuse the already-imported copyToClipboard helper.  */
                {
                  label: `Copy host: ${nodeMenu.data.host}`,
                  hint: "clipboard · host only",
                  onClick: () => void copyToClipboard(nodeMenu.data!.host),
                },
                {
                  label: `Copy URL: https://${nodeMenu.data.host}${nodeMenu.data.path}`,
                  hint: "clipboard · full URL",
                  onClick: () => {
                    const path =
                      nodeMenu.data!.path === "/" ? "/" : nodeMenu.data!.path;
                    void copyToClipboard(
                      `https://${nodeMenu.data!.host}${path}`,
                    );
                  },
                },
              ]
            : []
        }
      />
      </div>
    </div>
  );
}

type SiteMapCoverage = {
  totalHosts: number;
  inScopeHosts: number;
  totalEndpoints: number;
  inScopeEndpoints: number;
  deepPaths: number;
  leaves: number;
  totalRequests: number;
};

/** Walk the sitemap snapshot and compute coverage stats for the strip
 *  above the tree. A "deep path" is a node that itself has children;
 *  a "leaf" is any node whose children map is empty. "Endpoints" are
 *  every node seen, excluding the top-level host rows themselves. */
function computeCoverage(snap: Record<string, SiteNode>): SiteMapCoverage {
  const out: SiteMapCoverage = {
    totalHosts: 0,
    inScopeHosts: 0,
    totalEndpoints: 0,
    inScopeEndpoints: 0,
    deepPaths: 0,
    leaves: 0,
    totalRequests: 0,
  };
  const visit = (node: SiteNode, depth: number) => {
    if (depth > 0) {
      out.totalEndpoints += 1;
      if (node.in_scope) out.inScopeEndpoints += 1;
      if (Object.keys(node.children).length > 0) out.deepPaths += 1;
      else out.leaves += 1;
    }
    out.totalRequests += node.transaction_ids.length;
    for (const child of Object.values(node.children)) visit(child, depth + 1);
  };
  for (const host of Object.values(snap)) {
    out.totalHosts += 1;
    if (host.in_scope) out.inScopeHosts += 1;
    visit(host, 0);
  }
  return out;
}

function shortMime(ct?: string | null): string {
  if (!ct) return "";
  const t = ct.split(";")[0].trim().toLowerCase();
  const slash = t.indexOf("/");
  if (slash < 0) return t;
  const sub = t.slice(slash + 1);
  if (sub === "html") return "html";
  if (sub === "plain") return "text";
  if (sub === "javascript" || sub === "x-javascript") return "js";
  if (sub.endsWith("+json") || sub === "json") return "json";
  if (sub.endsWith("+xml") || sub === "xml") return "xml";
  if (sub === "css") return "css";
  if (sub.startsWith("x-www-form-urlencoded")) return "form";
  if (sub.startsWith("octet-stream")) return "bin";
  if (t.startsWith("image/")) return `img:${sub}`;
  return sub;
}

function TreeRow({
  nodeKey, node, depth, expanded, toggle, onSelect, selected, onContextMenu, hostCounts, onFilterIssues,
}: {
  nodeKey: string;
  node: SiteNode;
  depth: number;
  expanded: Set<string>;
  toggle: (k: string) => void;
  onSelect: (n: SiteNode, nodeKey: string) => void;
  selected: SiteNode | null;
  onContextMenu?: (e: React.MouseEvent, n: SiteNode, nodeKey: string) => void;
  /** Host → severity → count. Only rendered on depth-0 (host) nodes;
   *  passed through so recursive descendants have access when we
   *  ever surface per-path badges too. */
  hostCounts?: Record<string, Record<string, number>>;
  /** Click handler for the per-host severity badges. Fires with
   *  `{host, severity}` so TargetPanel can switch to the Issues
   *  sub-tab + stage the filter. Threaded through recursion but
   *  only invoked on depth-0 rows. */
  onFilterIssues?: (payload: IssueDeepLink) => void;
}) {
  const children = Object.entries(node.children || {});
  const isOpen = expanded.has(nodeKey);
  const isSelected = selected === node;
  // Host-level issue badges — only on root nodes. `nodeKey` for a
  // root is just the host string (no `/`); descendants are
  // `host/seg1/seg2…`. Burp's SiteMap tags each origin row with a
  // tiny severity breakdown so the operator sees at a glance which
  // hosts hold the scary findings. We mirror that with a right-
  // aligned chip strip: one coloured pill per non-zero severity.
  const host = depth === 0 ? nodeKey : null;
  const counts = host ? hostCounts?.[host] : undefined;
  const SEV_ORDER: Array<{
    k: string;
    bg: string;
    fg: string;
  }> = [
    { k: "critical", bg: "#e13c3c",      fg: "#fff" },
    { k: "high",     bg: "var(--red)",   fg: "#fff" },
    { k: "medium",   bg: "var(--amber)", fg: "#1a1206" },
    { k: "low",      bg: "#6b7fbf",      fg: "#fff" },
    { k: "info",     bg: "var(--bg-elev)", fg: "var(--text-dim)" },
  ];
  const totalCount = counts
    ? SEV_ORDER.reduce((n, s) => n + (counts[s.k] ?? 0), 0)
    : 0;
  return (
    <div>
      <div
        style={{
          paddingLeft: 8 + depth * 14,
          display: "flex",
          gap: 6,
          alignItems: "center",
          padding: "3px 6px",
          cursor: "pointer",
          background: isSelected ? "var(--accent-dim)" : "transparent",
          color: isSelected ? "#fff" : "var(--text)",
          // Fade out-of-scope rows so the operator sees scope at a
          // glance — mirror of Burp's SiteMap behaviour. Selected
          // rows keep full opacity so the operator can inspect an
          // OOS node without losing visual acuity. Hover doesn't
          // boost opacity (unlike .issue-sev-chip.off:hover) because
          // the row is still functional — click, right-click, and
          // scope-add all work on dimmed rows.
          opacity: !node.in_scope && !isSelected ? 0.55 : 1,
        }}
        onClick={() => { onSelect(node, nodeKey); children.length && toggle(nodeKey); }}
        onContextMenu={(e) => { onContextMenu?.(e, node, nodeKey); }}
      >
        <span style={{ color: "var(--text-faint)", width: 12 }}>
          {children.length ? (isOpen ? "▾" : "▸") : "·"}
        </span>
        <span className="mono">{node.segment || "/"}</span>
        {node.methods?.length > 0 && <span className="badge">{node.methods.join(",")}</span>}
        {node.status_codes?.length > 0 && <span className="badge">{node.status_codes.join(",")}</span>}
        {node.transaction_ids?.length > 0 && <span className="badge">×{node.transaction_ids.length}</span>}
        {depth === 0 && !node.in_scope && (
          <span
            className="badge"
            title="This host is not in the current project scope. Right-click to add it."
            style={{
              background: "var(--bg-elev)",
              color: "var(--text-dim)",
              fontSize: 9.5,
              padding: "0 5px",
              textTransform: "uppercase",
              letterSpacing: 0.4,
            }}
          >
            oos
          </span>
        )}
        {totalCount > 0 && host && (
          <span
            style={{
              marginLeft: "auto",
              display: "inline-flex",
              gap: 2,
              alignItems: "center",
            }}
            title={
              onFilterIssues
                ? `${totalCount} finding${totalCount === 1 ? "" : "s"} on ${host} — click a pill to open Issues filtered by severity, or the total to see all`
                : `${totalCount} finding${totalCount === 1 ? "" : "s"} on this host`
            }
          >
            {SEV_ORDER.map(({ k, bg, fg }) => {
              const n = counts?.[k] ?? 0;
              if (n === 0) return null;
              return (
                <span
                  key={k}
                  title={
                    onFilterIssues
                      ? `${n} ${k} — click to filter Issues to ${host} + ${k}`
                      : `${n} ${k}`
                  }
                  onClick={(e) => {
                    if (!onFilterIssues) return;
                    // Prevent the click from bubbling to the row's
                    // select-and-expand handler — the operator wants
                    // the pivot, not a tree expansion.
                    e.stopPropagation();
                    onFilterIssues({
                      host,
                      severity: k as IssueDeepLink["severity"],
                    });
                  }}
                  style={{
                    fontSize: 9.5,
                    lineHeight: "13px",
                    padding: "0 4px",
                    minWidth: 14,
                    textAlign: "center",
                    borderRadius: 7,
                    background: bg,
                    color: fg,
                    fontWeight: 700,
                    border: k === "info" ? "1px solid var(--border)" : "none",
                    cursor: onFilterIssues ? "pointer" : "default",
                  }}
                >
                  {n}
                </span>
              );
            })}
          </span>
        )}
      </div>
      {isOpen && children.map(([key, child]) => (
        <TreeRow
          key={`${nodeKey}/${key}`}
          nodeKey={`${nodeKey}/${key}`}
          node={child}
          depth={depth + 1}
          expanded={expanded}
          toggle={toggle}
          onSelect={onSelect}
          selected={selected}
          onContextMenu={onContextMenu}
          hostCounts={hostCounts}
          onFilterIssues={onFilterIssues}
        />
      ))}
    </div>
  );
}

function ScopePane() {
  const [original, setOriginal] = useState<Scope | null>(null);
  const [draft, setDraft] = useState<Scope | null>(null);
  const [subTab, setSubTab] = useState<"include" | "exclude">("include");
  // R124: Hidden file input for the "⬆ Import scope" button. One
  // ref so a single click fires the OS picker; same pattern as
  // R118-R121 file-loaders.
  const scopeFileRef = useRef<HTMLInputElement | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.scopeGet().then((s) => {
      setOriginal(s);
      setDraft(s);
    }).catch(() => {});
  }, []);

  const dirty = useMemo(() => {
    if (!original || !draft) return false;
    return JSON.stringify(original) !== JSON.stringify(draft);
  }, [original, draft]);

  function patch(update: (s: Scope) => Scope) {
    if (!draft) return;
    setDraft(update(structuredClone(draft)));
  }

  function addRule(kind: "include" | "exclude") {
    patch((s) => {
      s.rules.push({
        match_kind: kind,
        protocol: "any",
        host: "*.example.com",
        path: "*",
        regex: false,
        enabled: true,
      });
      return s;
    });
    setSubTab(kind);
  }

  function updateRule(index: number, field: keyof ScopeRule, value: unknown) {
    patch((s) => {
      const row = { ...s.rules[index] } as ScopeRule;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (row as any)[field] = value;
      s.rules[index] = row;
      return s;
    });
  }

  function removeRule(index: number) {
    patch((s) => {
      s.rules.splice(index, 1);
      return s;
    });
  }

  function moveRule(index: number, delta: -1 | 1) {
    patch((s) => {
      const to = index + delta;
      if (to < 0 || to >= s.rules.length) return s;
      const tmp = s.rules[index];
      s.rules[index] = s.rules[to];
      s.rules[to] = tmp;
      return s;
    });
  }

  async function save() {
    if (!draft) return;
    setSaving(true);
    try {
      const saved = await api.scopeSet(draft);
      setOriginal(saved);
      setDraft(saved);
    } finally {
      setSaving(false);
    }
  }

  function discard() {
    if (!original) return;
    setDraft(structuredClone(original));
  }

  if (!draft) {
    return <div style={{ padding: 10, color: "var(--text-dim)" }}>Loading scope…</div>;
  }

  const indexed = draft.rules.map((r, idx) => ({ rule: r, idx }));
  const include = indexed.filter(({ rule }) => rule.match_kind === "include");
  const exclude = indexed.filter(({ rule }) => rule.match_kind === "exclude");
  const visible = subTab === "include" ? include : exclude;
  const counts = {
    include: include.length,
    includeEnabled: include.filter((r) => r.rule.enabled).length,
    exclude: exclude.length,
    excludeEnabled: exclude.filter((r) => r.rule.enabled).length,
  };

  return (
    <div style={{ padding: 10, overflow: "auto", display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="toolbar" style={{ border: "1px solid var(--border)" }}>
        <button
          className={subTab === "include" ? "primary" : ""}
          onClick={() => setSubTab("include")}
        >
          Include ({counts.includeEnabled}/{counts.include})
        </button>
        <button
          className={subTab === "exclude" ? "primary" : ""}
          onClick={() => setSubTab("exclude")}
        >
          Exclude ({counts.excludeEnabled}/{counts.exclude})
        </button>
        {/* -------------------------------------------------- */}
        {/* R261: Bulk Enable all / Disable all for the current */}
        {/* sub-tab's rules. Mirrors R156 (session rules),      */}
        {/* R160 (match-and-replace), R256 (passive detectors), */}
        {/* R257 (active probes) — same enable/disable-all     */}
        {/* ergonomics applied to scope rules.                  */}
        {/*                                                      */}
        {/* Semantics: lands in draft (same flow as every other */}
        {/* scope mutation), so operators retain the Discard   */}
        {/* escape hatch before Save actually persists.         */}
        {/*                                                      */}
        {/* Confirm policy: enable-all needs no confirm (safely */}
        {/* arms every rule — operator still has Save to       */}
        {/* review). Disable-all does confirm because turning   */}
        {/* every rule off in a sub-tab can materially widen or */}
        {/* narrow the live scope depending on which sub-tab    */}
        {/* it is (include disable → fall through to default;   */}
        {/* exclude disable → remove every carve-out).         */}
        {/*                                                      */}
        {/* Visibility: both buttons only render when there's   */}
        {/* at least one rule in the sub-tab. Each is also      */}
        {/* disabled when every rule is already in the target  */}
        {/* state so a redundant press is impossible.          */}
        {(() => {
          const subRules = subTab === "include" ? include : exclude;
          if (subRules.length === 0) return null;
          const allOn = subRules.every((r) => r.rule.enabled);
          const allOff = subRules.every((r) => !r.rule.enabled);
          function setAll(enabled: boolean) {
            patch((s) => {
              for (const row of s.rules) {
                if (row.match_kind === subTab) row.enabled = enabled;
              }
              return s;
            });
          }
          return (
            <>
              <button
                className="ghost"
                disabled={allOn}
                title={
                  allOn
                    ? `Every ${subTab} rule is already enabled`
                    : `Enable every ${subTab} rule (${subRules.length}) — lands in draft, Save to persist`
                }
                style={{ fontSize: 11, padding: "2px 8px" }}
                onClick={() => setAll(true)}
              >
                ✓ Enable all
              </button>
              <button
                className="ghost"
                disabled={allOff}
                title={
                  allOff
                    ? `Every ${subTab} rule is already disabled`
                    : `Disable every ${subTab} rule (${subRules.length}) — ${
                        subTab === "include"
                          ? "falls through to the \"treat everything as in-scope when no Include rule is defined\" default"
                          : "removes every carve-out — URLs that were explicitly excluded come back into scope"
                      }. Lands in draft, Save to persist.`
                }
                style={{ fontSize: 11, padding: "2px 8px" }}
                onClick={() => {
                  if (
                    !confirm(
                      `Disable every ${subTab} rule (${subRules.length})? ${
                        subTab === "include"
                          ? "Nothing will match any Include rule — scope falls through to the \"treat everything as in-scope when no Include rule is defined\" default."
                          : "Every URL that was explicitly excluded comes back into scope."
                      } Lands in draft — Save to persist, Discard to abort.`,
                    )
                  )
                    return;
                  setAll(false);
                }}
              >
                ∅ Disable all
              </button>
            </>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        {/* ------------------------------------------------------- */}
        {/* R124: Export + Import scope as JSON. Burp lets teams    */}
        {/* share scope profiles via file; same here. Export dumps  */}
        {/* the current draft (so unsaved tweaks don't get lost on  */}
        {/* a round-trip); import reads a .burp.json / .json file  */}
        {/* and loads it into the draft (confirms if the current    */}
        {/* draft is non-empty). Save is still a separate click so  */}
        {/* operators get a chance to review before persisting.     */}
        <button
          onClick={() => {
            const payload = JSON.stringify(draft, null, 2);
            const blob = new Blob([payload], {
              type: "application/json;charset=utf-8",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            const stamp = new Date()
              .toISOString()
              .replace(/[:T]/g, "-")
              .replace(/\..*$/, "");
            a.href = url;
            a.download = `burpfree-scope-${stamp}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
          }}
          title="Export the current scope draft as a JSON file (teammates can import to mirror your scope)"
        >
          ⬇ Export scope
        </button>
        <input
          ref={scopeFileRef}
          type="file"
          accept=".json,.burp,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Scope caps at 2 MB (realistic scopes are a few KB).`,
              );
              return;
            }
            const haveDraft =
              draft &&
              (draft.rules.length > 0 || draft.default_in_scope_when_empty !== true);
            if (haveDraft && !confirm(`Replace the current scope with ${file.name}?`))
              return;
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              // Light shape validation — the imported object must look
              // like a Scope (rules array + default_in_scope_when_empty).
              // Anything else is a mis-pick and we bail with a clear
              // error rather than passing garbage to the backend.
              if (
                !parsed ||
                typeof parsed !== "object" ||
                !Array.isArray(parsed.rules) ||
                typeof parsed.default_in_scope_when_empty !== "boolean"
              ) {
                alert(
                  "Not a scope file — expected { rules: [...], default_in_scope_when_empty: bool }.",
                );
                return;
              }
              setDraft(parsed as Scope);
            } catch (err) {
              alert(`Import failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => scopeFileRef.current?.click()}
          title="Import a scope JSON into the draft. You can review and Save after loading."
        >
          ⬆ Import scope
        </button>
        {/* ------------------------------------------------------- */}
        {/* R152: Reset scope — one-click wipe of every rule plus    */}
        {/* restore of the `default_in_scope_when_empty=true` safe   */}
        {/* default. Lands in the draft (same pattern as R124       */}
        {/* Import), so operators get a Discard escape hatch before */}
        {/* Save actually persists the empty scope. Danger-styled   */}
        {/* because starting a scan with no scope at all is a       */}
        {/* "everything in scope" footgun and operators should     */}
        {/* confirm.                                                 */}
        <button
          className="danger"
          disabled={
            saving ||
            (draft.rules.length === 0 && draft.default_in_scope_when_empty === true)
          }
          onClick={() => {
            if (
              !confirm(
                `Clear every scope rule (${draft.rules.length}) and reset "treat every request as in-scope when no Include rule is defined" to on? Lands in draft — Save to persist, Discard to abort.`,
              )
            )
              return;
            setDraft({ rules: [], default_in_scope_when_empty: true });
          }}
          title={
            draft.rules.length === 0 && draft.default_in_scope_when_empty === true
              ? "Scope is already at defaults."
              : `Reset to defaults: zero rules + default_in_scope_when_empty=true. Lands in draft; Save to persist.`
          }
        >
          ⌫ Reset scope
        </button>
        <div className="sep" />
        <button onClick={() => addRule(subTab)}>+ Add {subTab} rule</button>
        <button disabled={!dirty || saving} onClick={discard}>Discard</button>
        <button
          className={dirty ? "primary" : ""}
          disabled={!dirty || saving}
          onClick={save}
          title="Replace the whole scope atomically"
        >
          {saving ? "Saving…" : dirty ? "Save changes" : "Saved"}
        </button>
      </div>

      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
        <input
          type="checkbox"
          checked={draft.default_in_scope_when_empty}
          onChange={(e) =>
            patch((s) => {
              s.default_in_scope_when_empty = e.target.checked;
              return s;
            })
          }
        />
        Treat every request as in-scope when no Include rule is defined
        <span style={{ color: "var(--text-dim)" }}>
          (safe default for exploratory testing; turn off before a scan)
        </span>
      </label>

      <ScopeRulesTable
        rows={visible}
        onUpdate={updateRule}
        onRemove={removeRule}
        onMove={moveRule}
        total={draft.rules.length}
      />

      <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
        Rule order matters — includes and excludes are evaluated in the order shown. Scope is enforced
        by the interceptor, scanner, intruder and spider — not only the UI.
      </div>
    </div>
  );
}

function ScopeRulesTable({
  rows,
  onUpdate,
  onRemove,
  onMove,
  total,
}: {
  rows: { rule: ScopeRule; idx: number }[];
  onUpdate: (index: number, field: keyof ScopeRule, value: unknown) => void;
  onRemove: (index: number) => void;
  onMove: (index: number, delta: -1 | 1) => void;
  total: number;
}) {
  return (
    <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
      <colgroup>
        <col style={{ width: 32 }} />
        <col style={{ width: 70 }} />
        <col style={{ width: 90 }} />
        <col />
        <col style={{ width: 90 }} />
        <col />
        <col style={{ width: 70 }} />
        <col style={{ width: 110 }} />
      </colgroup>
      <thead>
        <tr>
          <th style={th()}>#</th>
          <th style={th()}>Enabled</th>
          <th style={th()}>Protocol</th>
          <th style={th()}>Host</th>
          <th style={th()}>Port</th>
          <th style={th()}>Path</th>
          <th style={th()}>Regex</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {rows.length === 0 && (
          <tr>
            <td colSpan={8} style={{ color: "var(--text-dim)", padding: 14 }}>
              No rules in this list. Click <b>+ Add rule</b> to create one.
            </td>
          </tr>
        )}
        {rows.map(({ rule, idx }, visualOrder) => (
          <tr key={idx}>
            <td style={td()}>{visualOrder + 1}</td>
            <td style={td()}>
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(e) => onUpdate(idx, "enabled", e.target.checked)}
              />
            </td>
            <td style={td()}>
              <select
                value={rule.protocol}
                onChange={(e) => onUpdate(idx, "protocol", e.target.value)}
                style={{ width: "100%" }}
              >
                <option value="any">any</option>
                <option value="http">http</option>
                <option value="https">https</option>
                <option value="ws">ws</option>
                <option value="wss">wss</option>
              </select>
            </td>
            <td style={td()}>
              <input
                type="text"
                value={rule.host}
                onChange={(e) => onUpdate(idx, "host", e.target.value)}
                placeholder={rule.regex ? "regex pattern" : "*.example.com"}
                style={{ width: "100%" }}
              />
            </td>
            <td style={td()}>
              <input
                type="number"
                value={rule.port ?? ""}
                placeholder="any"
                min={1}
                max={65535}
                onChange={(e) => {
                  const v = e.target.value.trim();
                  onUpdate(idx, "port", v === "" ? undefined : parseInt(v, 10));
                }}
                style={{ width: "100%" }}
              />
            </td>
            <td style={td()}>
              <input
                type="text"
                value={rule.path}
                onChange={(e) => onUpdate(idx, "path", e.target.value)}
                placeholder={rule.regex ? "regex pattern" : "/api/*"}
                style={{ width: "100%" }}
              />
            </td>
            <td style={td()}>
              <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <input
                  type="checkbox"
                  checked={rule.regex}
                  onChange={(e) => onUpdate(idx, "regex", e.target.checked)}
                />
                <span style={{ color: "var(--text-dim)", fontSize: 11 }}>regex</span>
              </label>
            </td>
            <td style={td()}>
              <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                <button
                  className="ghost"
                  disabled={idx === 0}
                  onClick={() => onMove(idx, -1)}
                  title="Move up"
                >
                  ↑
                </button>
                <button
                  className="ghost"
                  disabled={idx >= total - 1}
                  onClick={() => onMove(idx, 1)}
                  title="Move down"
                >
                  ↓
                </button>
                <button className="ghost danger" onClick={() => onRemove(idx)} title="Delete rule">
                  ✕
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function th(): CSSProperties {
  return {
    textAlign: "left",
    color: "var(--text-dim)",
    fontSize: 11,
    padding: "4px 6px",
    borderBottom: "1px solid var(--border)",
  };
}

function td(): CSSProperties {
  return {
    padding: "4px 6px",
    borderBottom: "1px solid var(--border-dim, rgba(128,128,128,0.1))",
    verticalAlign: "middle",
  };
}

/* ------------------------------------------------------------------ *
 * Issues sub-tab
 *
 * A Target-scoped view onto the scanner's findings table. Mirrors
 * Burp's Target → Issues: left column lists issues (severity glyph +
 * title + host), right column shows the detail (evidence, remediation,
 * references, status / verification controls). A host dropdown lets
 * the operator narrow down to a single site; "any host" surfaces
 * everything the scanner has produced.
 * ------------------------------------------------------------------ */

type SeverityKey = "critical" | "high" | "medium" | "low" | "info";
const SEVERITY_ORDER: Record<SeverityKey, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Status choices on the issue list. The display label is lower-cased
 *  to match Burp's style; the storage value stays snake_case. */
const ISSUE_STATUSES: Array<{ value: string; label: string }> = [
  { value: "new", label: "new" },
  { value: "triaging", label: "triaging" },
  { value: "confirmed", label: "confirmed" },
  { value: "false_positive", label: "false positive" },
  { value: "fixed", label: "fixed" },
  { value: "wontfix", label: "wontfix" },
];

/** Three-way verification state Burp uses: unverified → verified →
 *  false_positive. These must line up with the Rust enum variants
 *  — `burpfree-storage` writes the string verbatim into the DB. */
const ISSUE_VERIFICATIONS: Array<{ value: string; label: string }> = [
  { value: "unverified", label: "unverified" },
  { value: "verified", label: "verified" },
  { value: "false_positive", label: "false positive" },
];

function IssuesPane({
  pendingFilter,
  onFilterConsumed,
}: {
  /** Deep-link payload from a SiteMap host-badge click. Applied
   *  exactly once on mount: `host` becomes the host filter, `severity`
   *  seeds the sevFilter Set. Both fields optional. Null is the
   *  no-deep-link base case (operator opened Issues directly). */
  pendingFilter?: IssueDeepLink | null;
  /** Callback the pane fires after it consumes the deep-link so
   *  TargetPanel can null the pendingIssueFilter — otherwise a
   *  Issues ↔ SiteMap ↔ Issues round-trip would re-apply the stale
   *  filter and clobber the operator's manual chip picks. */
  onFilterConsumed?: () => void;
}) {
  const [findings, setFindings] = useState<StoredFinding[]>([]);
  const [tx, setTx] = useState<Record<number, StoredSummary>>({});
  // Burp-style multi-select chip filters. Empty set == "any". The old
  // single-value <select> dropdowns were lossy — operators often want
  // to see "high and medium" at once, or "new and triaging". The
  // chip strip below the toolbar is the direct replacement.
  const [sevFilter, setSevFilter] = useState<Set<SeverityKey>>(() => {
    const s = new Set<SeverityKey>();
    if (pendingFilter?.severity) s.add(pendingFilter.severity);
    return s;
  });
  const [statusFilter, setStatusFilter] = useState<Set<string>>(() => new Set());
  const [host, setHost] = useState<string>(pendingFilter?.host ?? "");

  // Consume the deep-link exactly once on mount. The useState
  // initialisers above pick up the initial values; this effect fires
  // the "consumed" callback so TargetPanel nulls the staged filter
  // and future remounts don't re-apply a stale pivot.
  useEffect(() => {
    if (pendingFilter) onFilterConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [search, setSearch] = useState<string>("");
  const [selected, setSelected] = useState<StoredFinding | null>(null);
  const [busy, setBusy] = useState(false);
  // Right-click menu on an issue row — carries the StoredFinding so
  // menu actions can hop to Repeater / Intruder / Comparer / History
  // without threading props.
  const [issueMenu, setIssueMenu] = useState<MenuState<StoredFinding> | null>(null);

  async function refresh() {
    setBusy(true);
    try {
      // We ask the backend to narrow on `search` only — severity and
      // status filtering is a Set operation now and done client-side
      // in the `filtered` memo. Full-text search still goes through
      // the DB so we don't pull everything on each keystroke.
      const list = await api.findingsListFiltered({
        search: search || undefined,
      });
      setFindings(list);
      // Join transactions in one batch so the host column has data.
      const ids = Array.from(
        new Set(list.map((f) => f.transaction_id).filter((x): x is number => typeof x === "number"))
      );
      if (ids.length > 0) {
        try {
          const sums = await api.historySummaries(ids);
          const map: Record<number, StoredSummary> = {};
          for (const s of sums) map[s.id] = s;
          setTx(map);
        } catch {}
      } else {
        setTx({});
      }
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { refresh(); }, [search]);
  // Light polling so new scanner results surface without a reload.
  useEffect(() => {
    const t = setInterval(() => { void refresh(); }, 5000);
    return () => clearInterval(t);
  }, [search]);

  const hosts = useMemo(() => {
    const s = new Set<string>();
    for (const f of findings) {
      const t = f.transaction_id ? tx[f.transaction_id] : null;
      if (t) s.add(t.host);
    }
    return Array.from(s).sort();
  }, [findings, tx]);

  // Rows after host filter + search — but BEFORE chip filters apply.
  // Chip counts use this baseline so each chip shows "what would be
  // visible if I clicked here", respecting host/search but not the
  // other chips. Matches Burp's filter-count behaviour.
  const preChipFiltered = useMemo(() => {
    return findings.filter((f) => {
      if (!host) return true;
      const t = f.transaction_id ? tx[f.transaction_id] : null;
      return t?.host === host;
    });
  }, [findings, host, tx]);

  const sevCounts = useMemo(() => {
    const c: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of preChipFiltered) {
      const k = f.severity.toLowerCase() as SeverityKey;
      if (k in c) c[k]++;
    }
    return c;
  }, [preChipFiltered]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of ISSUE_STATUSES) c[s.value] = 0;
    for (const f of preChipFiltered) {
      const s = (f.status ?? "new").toLowerCase();
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [preChipFiltered]);

  const filtered = useMemo(() => {
    const rows = preChipFiltered.filter((f) => {
      const k = f.severity.toLowerCase() as SeverityKey;
      if (sevFilter.size > 0 && !sevFilter.has(k)) return false;
      const s = (f.status ?? "new").toLowerCase();
      if (statusFilter.size > 0 && !statusFilter.has(s)) return false;
      return true;
    });
    rows.sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity.toLowerCase() as SeverityKey] ?? 99;
      const sb = SEVERITY_ORDER[b.severity.toLowerCase() as SeverityKey] ?? 99;
      if (sa !== sb) return sa - sb;
      return (b.ts_ms || 0) - (a.ts_ms || 0);
    });
    return rows;
  }, [preChipFiltered, sevFilter, statusFilter]);

  // R222: J / K vim-style navigation across the IssuesPane's
  // filtered findings. Fourth panel to carry J/K (R197 Scanner,
  // R208 History, R212 Organizer, R222 Target Issues). Same shape
  // as R197 — document-level keydown; walks the current post-chip
  // view; clamps at list ends; case-insensitive; text-input skip.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // R363: ArrowDown / ArrowUp aliases for J / K — parallel to
      // R362 Scanner. Target Issues was J/K-only; this brings it
      // to parity with HistoryPanel R208 (dual-key nav) and the
      // just-landed Scanner R362.
      const isDown = e.key === "j" || e.key === "J" || e.key === "ArrowDown";
      const isUp = e.key === "k" || e.key === "K" || e.key === "ArrowUp";
      if (!isDown && !isUp) return;
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
      if (filtered.length === 0) return;
      e.preventDefault();
      const curIdx = selected
        ? filtered.findIndex((f) => f.id === selected.id)
        : -1;
      let nextIdx: number;
      if (curIdx < 0) {
        nextIdx = isDown ? 0 : filtered.length - 1;
      } else {
        nextIdx = isDown
          ? Math.min(curIdx + 1, filtered.length - 1)
          : Math.max(curIdx - 1, 0);
      }
      const next = filtered[nextIdx];
      if (!next) return;
      setSelected(next);
      setTimeout(() => {
        document
          .querySelector("tr.selected")
          ?.scrollIntoView({ block: "nearest" });
      }, 0);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, selected?.id]);

  // R232: Alt+1..5 toggle severity chip filter inside IssuesPane
  // — mirrors R230 (Scanner Alt+1..5) so operators get the same
  // muscle memory across findings-adjacent panels. Mapping order
  // matches the chip strip: 1=critical / 2=high / 3=medium /
  // 4=low / 5=info. Toggles rather than sets so operators can
  // stack picks. Clears via the "clear filters" button (no Esc
  // keybinding on IssuesPane — the search-box Esc from R219
  // takes precedence).
  useEffect(() => {
    const SEV_BY_DIGIT: Record<string, SeverityKey> = {
      "1": "critical",
      "2": "high",
      "3": "medium",
      "4": "low",
      "5": "info",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const sev = SEV_BY_DIGIT[e.key];
      if (!sev) return;
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
      toggleSev(sev);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // R271: Alt+Shift+1..6 toggle status chip filter inside IssuesPane
  // — mirror of R270 (Scanner Alt+Shift+1..6) applied to Target
  // Issues. Keeps the "plain Alt = severity axis, Alt+Shift = status
  // axis" convention consistent across the two highest-volume triage
  // panels. Mapping matches the ISSUE_STATUSES declaration order so
  // the digit → chip correspondence is predictable without hunting:
  // 1=new, 2=triaging, 3=confirmed, 4=false_positive, 5=fixed,
  // 6=wontfix. Alt+Shift+0 clears every status chip in one key.
  useEffect(() => {
    const STATUS_BY_DIGIT: Record<string, string> = {
      "1": "new",
      "2": "triaging",
      "3": "confirmed",
      "4": "false_positive",
      "5": "fixed",
      "6": "wontfix",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      const digit = e.key;
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
        setStatusFilter(new Set());
        return;
      }
      const status = STATUS_BY_DIGIT[digit];
      if (!status) return;
      e.preventDefault();
      toggleStatus(status);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // R412: Alt+C clears every active filter on the Target Issues
  // sub-tab (sev chips + status chips + host dropdown + search
  // box) in one keystroke. Keyboard version of the "Clear all
  // filters" toolbar button lower in the tab. Completes the
  // cross-panel Alt+C clear-filters family: R349 History / R392
  // Decoder / R409 Collaborator / R410 Logger / R412 Target
  // Issues. Operators pivoting across a scope-pass's issue list
  // (narrow to "critical + confirmed on admin.example.com" →
  // widen to "all" → narrow to "high + false_positive") want a
  // one-key reset without walking four selectors. **Scope**
  // `sevFilter.size > 0 || statusFilter.size > 0 || host.length > 0
  // || search.length > 0` — short-circuits when all are at
  // defaults so the keystroke stays silent. **Mechanism** fires
  // four state setters to match the toolbar button exactly.
  // **Guards** plain Alt only (no Ctrl/Meta/Shift so Ctrl+Shift+C
  // DevTools stays intact), text-input focus skip. **No-op silent**
  // when nothing active so operators can spam the keystroke safely.
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
        sevFilter.size > 0 ||
        statusFilter.size > 0 ||
        host.length > 0 ||
        search.length > 0;
      if (!anyActive) return;
      e.preventDefault();
      setSevFilter(new Set());
      setStatusFilter(new Set());
      setHost("");
      setSearch("");
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sevFilter, statusFilter, host, search]);

  // R421: Alt+Shift+H pivots the selected Target-issue finding's
  // parent tx into HTTP history. Keyboard version of the existing
  // "Open in HTTP history" row-right-click entry + cross-panel
  // mirror of R420 Scanner Alt+Shift+H. Operators J/K-walk the
  // issue list and pivot without touching the mouse. **Letter
  // choice** H = History. **Scope** `selected` (single finding).
  // **Guards** `selected != null && selected.transaction_id != null`
  // — passive-only findings skipped. Alt+Shift only, text-input
  // focus skip. **Mechanism** reuses the existing
  // `openIssueInHistory()` helper from line ~2313 so the pivot
  // path is byte-identical to the row-right-click entry. **No-op
  // silent** when no selection or tx-less.
  useEffect(() => {
    function onPivotHistoryKey(e: KeyboardEvent) {
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
      if (!selected || !selected.transaction_id) return;
      e.preventDefault();
      openIssueInHistory(selected);
    }
    document.addEventListener("keydown", onPivotHistoryKey);
    return () => document.removeEventListener("keydown", onPivotHistoryKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R430: Alt+F marks the selected Target-issue finding as
  // false_positive status (not verification axis) — completes
  // the Target Issues single-row status quartet alongside R424
  // Alt+W (wontfix), R428 Alt+V (verified via verification axis),
  // R429 Alt+T (triaging). Cross-panel mirror of R342 Scanner
  // Alt+F. **Semantic distinction** `status=false_positive` is
  // the workflow label ("deprioritised in triage") while
  // `verification=false_positive` is the reproducibility assertion
  // ("I tried, couldn't trigger it"); this keybind targets status.
  // **Mechanism** reuses the existing `setFindingStatus(id,
  // "false_positive")` helper. **Guards** plain Alt only, text-
  // input focus skip. **No-op silent** when nothing selected.
  useEffect(() => {
    function onFKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "f" && e.key !== "F") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void setFindingStatus(selected.id, "false_positive");
    }
    document.addEventListener("keydown", onFKey);
    return () => document.removeEventListener("keydown", onFKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R429: Alt+T marks the selected Target-issue finding as
  // triaging — cross-panel mirror of R338 Scanner Alt+T. Pairs
  // with R424 Alt+W (wontfix) and R428 Alt+V (verified) to build
  // out the Target Issues single-row status keyboard surface.
  // Operators J/K-walking a scope-pass want one-key promotion
  // through the triage lifecycle: inspect → Alt+T (promote to
  // triaging) → Alt+V (verify after reproducing) or Alt+W
  // (dismiss). **Letter choice** T = Triaging. **Mechanism** reuses
  // the existing `setFindingStatus(id, "triaging")` helper.
  // **Guards** plain Alt only, text-input focus skip. **No-op silent**
  // when nothing selected.
  useEffect(() => {
    function onTKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "t" && e.key !== "T") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void setFindingStatus(selected.id, "triaging");
    }
    document.addEventListener("keydown", onTKey);
    return () => document.removeEventListener("keydown", onTKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R428: Alt+V marks the selected Target-issue finding as verified
  // — cross-panel mirror of R337 Scanner Alt+V. Pairs with R427
  // Alt+Shift+Y (undo-verify) to give operators triaging in Target
  // Issues the same single-key verify + undo-verify muscle memory
  // as Scanner. **Letter choice** V = Verified. **Mechanism** reuses
  // the existing `setFindingVerification(id, "verified")` helper so
  // the write path is byte-identical to the detail-pane dropdown or
  // the row-right-click menu. **Guards** plain Alt only (no
  // Ctrl/Meta/Shift so Alt+Shift+V stays free for a future bulk
  // keyboard), text-input focus skip. **No-op silent** when nothing
  // selected.
  useEffect(() => {
    function onVKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "v" && e.key !== "V") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void setFindingVerification(selected.id, "verified");
    }
    document.addEventListener("keydown", onVKey);
    return () => document.removeEventListener("keydown", onVKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R427: Alt+Shift+Y marks the selected Target-issue finding's
  // verification axis back to "unverified" — cross-panel mirror
  // of R426 Scanner Alt+Shift+Y. Undo-ish companion to R337 Alt+V
  // (which exists in Scanner; Target Issues verifies via the row-
  // right-click menu or the detail-pane verification dropdown).
  // Operators triaging in Target Issues who misclicked a verify
  // flip want a fast rollback. **Letter choice** Y = Yank. Alt+Shift
  // modifier matches R426's family pairing. **Mechanism** reuses
  // the existing `setFindingVerification(id, "unverified")` helper
  // (line ~2274 in IssuesPane) so the write path is byte-identical
  // to the dropdown. **Guards** Alt+Shift only, text-input focus
  // skip. **No-op silent** when nothing selected.
  useEffect(() => {
    function onYKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "y" && e.key !== "Y") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void setFindingVerification(selected.id, "unverified");
    }
    document.addEventListener("keydown", onYKey);
    return () => document.removeEventListener("keydown", onYKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R457: Alt+Shift+E saves the selected Target-issue finding's
  // evidence blob — cross-panel mirror of R456 Scanner Alt+Shift+E.
  // Extends the Scanner↔Target Issues keyboard parity set from the
  // existing six-family group (Alt+V/T/F/W status + Alt+Shift+Y
  // undo-verify + Alt+Shift+H history pivot) to a seventh shortcut.
  // Operators J/K-walking a Target Issues scope-pass who want to
  // bundle evidence for ticketing can keystroke-save without a
  // mouse pivot into IssueSection's "⬇ Save" button (R402). Note
  // that R402 saves PER-SECTION with a timestamp-based filename;
  // R457 saves the whole evidence blob with the finding's id + slug
  // (matching R401/R456 Scanner for byte-identical output across
  // the two panels). Filename pattern `evidence-<id>-<slug>.txt`
  // mirrors R456 exactly so a mixed Scanner + Target workflow
  // produces consistent on-disk artifacts. **Letter choice** E =
  // Evidence; distinct from the status axis letters (V/T/F/W/Y/H)
  // and the C/I selection letters so the Alt+Shift family stays
  // mnemonic. **Scope** `selected` (single finding). **Guards**
  // `selected != null && selected.evidence` (no-op on title-only
  // findings), Alt+Shift only (no Ctrl/Meta so Ctrl+Shift+E muscle
  // memory stays untouched), text-input focus skip. **No-op silent**
  // when no selection or no evidence.
  useEffect(() => {
    function onSaveEvidenceKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "E" && e.key !== "e") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected || !selected.evidence) return;
      e.preventDefault();
      const slug =
        (selected.title || "")
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .slice(0, 40) || "evidence";
      const name = `evidence-${selected.id}-${slug}.txt`;
      try {
        const blob = new Blob([selected.evidence], {
          type: "text/plain;charset=utf-8",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
      } catch (err) {
        alert(`${err}`);
      }
    }
    document.addEventListener("keydown", onSaveEvidenceKey);
    return () => document.removeEventListener("keydown", onSaveEvidenceKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R424: Alt+W marks the selected Target-issue finding as wontfix.
  // Cross-panel mirror of R423 Scanner Alt+W. Operators triaging
  // in Target Issues get the same single-row status muscle memory
  // as Scanner (Alt+V/T/F already exist via other panels; here W
  // completes the quartet for the Target Issues sub-tab). **Letter
  // choice** W = Wontfix. **Scope** `selected` (single finding).
  // **Guards** plain Alt only (so Alt+Shift+W stays free), text-
  // input focus skip. **Mechanism** reuses the existing
  // `setFindingStatus(id, "wontfix")` helper so the write path is
  // byte-identical to any menu-driven status flip. **No-op silent**
  // when nothing selected.
  useEffect(() => {
    function onWKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "w" && e.key !== "W") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void setFindingStatus(selected.id, "wontfix");
    }
    document.addEventListener("keydown", onWKey);
    return () => document.removeEventListener("keydown", onWKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  function toggleSev(k: SeverityKey) {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  }
  function toggleStatus(v: string) {
    setStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(v)) next.delete(v);
      else next.add(v);
      return next;
    });
  }
  function clearFilters() {
    setSevFilter(new Set());
    setStatusFilter(new Set());
  }

  async function runPassive() {
    try {
      const n = await api.passiveRunNow();
      alert(`Passive scan: ${n} new finding(s).`);
      await refresh();
    } catch (e) { alert(`${e}`); }
  }

  async function setFindingStatus(id: number, newStatus: string) {
    await api.findingSetStatus(id, newStatus);
    await refresh();
  }
  async function setFindingVerification(id: number, newVerif: string) {
    await api.findingSetVerification(id, newVerif);
    await refresh();
  }
  async function setFindingNote(id: number, newNote: string) {
    try {
      await api.findingSetNote(id, newNote);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }
  async function deleteFinding(id: number) {
    if (!confirm("Delete this issue?")) return;
    await api.findingDelete(id);
    if (selected?.id === id) setSelected(null);
    await refresh();
  }

  // ---- Issue row context-menu actions -----------------------------------

  async function sendIssueToRepeater(f: StoredFinding) {
    if (!f.transaction_id) {
      alert("Issue has no parent transaction to send.");
      return;
    }
    try {
      await api.repeaterAddFromHistory(f.transaction_id, f.title);
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } catch (e) {
      alert(`Send to Repeater failed: ${e}`);
    }
  }

  function sendIssueToIntruder(f: StoredFinding) {
    if (!f.transaction_id) {
      alert("Issue has no parent transaction to send.");
      return;
    }
    const t = tx[f.transaction_id];
    if (!t) {
      alert("Parent transaction not loaded yet.");
      return;
    }
    const url = urlFromSummary(t);
    window.dispatchEvent(
      new CustomEvent("burpfree:intruder-load", {
        detail: { url, method: t.method, transactionId: t.id },
      }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "intruder" } }),
    );
  }

  async function sendIssueToComparer(f: StoredFinding, slot: "left" | "right") {
    if (!f.transaction_id) {
      alert("Issue has no parent transaction to send.");
      return;
    }
    try {
      // Fetch the raw request bytes so Comparer has something to diff.
      const view = await api.historyShow(f.transaction_id);
      const raw = view.request_raw ?? "";
      // R319: Fixed the payload-shape bug — the old `{slot, text}`
      // shape was never consumed because ComparerPanel's listener
      // (see ComparerLoadDetail) only reads `detail.left` /
      // `detail.right` / `detail.label`. So before this fix,
      // clicking "Send to Comparer (left/right)" from an Issue row
      // blanked both Comparer slots silently (left="" + right="")
      // instead of loading the chosen slot. HistoryPanel's R208
      // sendToComparerAction + the R318 Scanner impl use the
      // correct shape — this now matches.
      window.dispatchEvent(
        new CustomEvent("burpfree:comparer-load", {
          detail:
            slot === "left"
              ? { left: raw, right: "", label: `issue ${f.id}: ${f.title}` }
              : { left: "", right: raw, label: `issue ${f.id}: ${f.title}` },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
      );
    } catch (e) {
      alert(`Send to Comparer failed: ${e}`);
    }
  }

  function copyIssueSummary(f: StoredFinding) {
    const t = f.transaction_id ? tx[f.transaction_id] : null;
    const parts = [
      `[${f.severity.toUpperCase()}] ${f.title}`,
      t ? `URL: ${urlFromSummary(t)}` : null,
      `Detector: ${f.detector}`,
      `Confidence: ${f.confidence}`,
      f.evidence ? `Evidence: ${f.evidence}` : null,
      f.remediation ? `Remediation: ${f.remediation}` : null,
    ]
      .filter(Boolean)
      .join("\n");
    void copyToClipboard(parts);
  }

  function openIssueInHistory(f: StoredFinding) {
    if (!f.transaction_id) {
      alert("Issue has no parent transaction.");
      return;
    }
    // HistoryPanel listens for this and auto-selects the row.
    window.dispatchEvent(
      new CustomEvent("burpfree:history-focus", {
        detail: { id: f.transaction_id },
      }),
    );
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: "history" } }),
    );
  }

  const anyChipActive = sevFilter.size > 0 || statusFilter.size > 0;

  // Chip strip definitions. SEVERITY_CHIPS is a const row of the five
  // Burp-standard severities in the Burp-standard order; STATUS_CHIPS
  // reuses the ISSUE_STATUSES array so there's a single source of
  // truth for status labels/values.
  const severityChipDefs: Array<{ key: SeverityKey; label: string }> = [
    { key: "critical", label: "critical" },
    { key: "high", label: "high" },
    { key: "medium", label: "medium" },
    { key: "low", label: "low" },
    { key: "info", label: "info" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div className="toolbar">
        <label>host</label>
        <select value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">any</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <label>search</label>
        {/* R879: Mirror of R877/R878 — visible × clear button
            on the Target Issues search input. Mouse-first clear
            alongside the existing R219 Esc-clear keystroke. */}
        <span style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => {
            // R219: Esc clears the Target → Issues search input —
            // consistent with R201 (History search Esc-clear) and
            // the general "Esc = reset the thing you're focused on"
            // theme (R201 / R202 / R204). Only fires when there's
            // text to clear so Esc elsewhere stays available for
            // modals / popovers.
            if (e.key === "Escape" && search) {
              e.preventDefault();
              setSearch("");
            }
          }}
          placeholder="title / evidence / detector (Esc clears)"
          style={{ width: 200, paddingRight: search ? 22 : 6 }}
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
        <div className="sep" />
        <button onClick={refresh} disabled={busy}>{busy ? "…" : "Refresh"}</button>
        <button className="primary" onClick={runPassive}>Run passive scan</button>
        {/* R311: Export filtered issues as JSONL. Direct transplant   */}
        {/* of the R285 history-bulk pattern + R193 collab-interactions */}
        {/* pattern (both newline-delimited JSON exports). Scope       */}
        {/* respects the current post-chip view (`filtered`) so        */}
        {/* operators pivoting on a sev + status combo export exactly */}
        {/* that subset for a ticket note / grep pipeline / ELK ingest */}
        {/* without having to re-filter at the shell. One JSON object  */}
        {/* per line — no top-level array wrapper — so streaming       */}
        {/* consumers can start before the write finishes. Preserves   */}
        {/* every TargetFinding field (severity / status / confidence  */}
        {/* / description / evidence / insertion_point / remediation / */}
        {/* references / tags / etc.) so `jq .severity issues-*.jsonl` */}
        {/* works out of the box.                                       */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            try {
              const body = filtered.map((f) => JSON.stringify(f)).join("\n");
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
              a.download = `burpfree-issues-${stamp}.jsonl`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            filtered.length === 0
              ? "No issues to export"
              : `Export ${filtered.length} issue${filtered.length === 1 ? "" : "s"} as JSONL (one JSON object per line${filtered.length !== findings.length ? ` — respects the current filter` : ""}). Preserves every TargetFinding field — pipe into jq / grep / ELK.`
          }
        >
          ⬇ Export JSONL
        </button>
        {/* R679: Target Issues "📋 Copy status counts" — second
            counts tally op on Target, mirrors R675 Scanner. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            const order = [
              "new",
              "triaging",
              "confirmed",
              "fixed",
              "wontfix",
              "false_positive",
            ];
            const counts: Record<string, number> = {};
            for (const f of filtered) {
              const s = f.status || "new";
              counts[s] = (counts[s] ?? 0) + 1;
            }
            const sorted = Object.entries(counts).sort((a, b) => {
              const ai = order.indexOf(a[0]);
              const bi = order.indexOf(b[0]);
              return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
            });
            const text = sorted.map(([s, n]) => `${s}: ${n}`).join(", ");
            void navigator.clipboard.writeText(text);
          }}
          title={
            filtered.length === 0
              ? "No issues to tally"
              : `Copy status counts across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} as a one-line tally (new/triaging/confirmed/fixed/wontfix/false_positive). Great for triage standups. Mirror of R675 Scanner.`
          }
        >
          📋 Copy status counts
        </button>
        {/* R691: Target Issues "📋 Copy stats" — mirror of R690
            Scanner stats on Target Issues. Same 5-line KV block
            structure since Target shares the finding-focused
            metric shape. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            let critHigh = 0;
            const detectors = new Set<string>();
            let verified = 0;
            let unverified = 0;
            let falsePositive = 0;
            let withEvidence = 0;
            for (const f of filtered) {
              const sev = (f.severity || "info").toLowerCase();
              if (sev === "critical" || sev === "high") critHigh++;
              if (f.detector) detectors.add(f.detector);
              const v = (f.verification || "unverified").toLowerCase();
              if (v === "verified") verified++;
              else if (v === "false_positive") falsePositive++;
              else unverified++;
              if (f.evidence && f.evidence.length > 0) withEvidence++;
            }
            const lines = [
              `Findings: ${filtered.length}`,
              `Critical+High: ${critHigh}`,
              `Unique detectors: ${detectors.size}`,
              `Verified · Unverified · FP: ${verified} · ${unverified} · ${falsePositive}`,
              `With evidence: ${withEvidence}`,
            ];
            void navigator.clipboard.writeText(lines.join("\n"));
          }}
          title={
            filtered.length === 0
              ? "No issues to summarize"
              : `Copy one-shot summary across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} (total / crit+high / unique detectors / triage split / with-evidence). Mirror of R690 Scanner.`
          }
        >
          📋 Copy stats
        </button>
        {/* R698: Target Issues "📋 Copy time range" — 2nd
            metadata-summary op on Target (companion to R691
            Copy stats). Mirrors R697 Scanner time range as
            an issue-focused variant. Same 4-line KV format:
            From / To / Duration / Findings. Reuses the same
            adaptive duration formatter (<60s / <1h / <1d /
            d+h). Scope: `filtered` (post-filter view). */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            let minTs = Number.POSITIVE_INFINITY;
            let maxTs = Number.NEGATIVE_INFINITY;
            for (const f of filtered) {
              const ts = f.ts_ms ?? 0;
              if (ts > 0) {
                if (ts < minTs) minTs = ts;
                if (ts > maxTs) maxTs = ts;
              }
            }
            if (!isFinite(minTs) || !isFinite(maxTs)) {
              alert("No issues in the filtered view have a timestamp.");
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
              `Findings: ${filtered.length}`,
            ];
            void navigator.clipboard.writeText(lines.join("\n"));
          }}
          title={
            filtered.length === 0
              ? "No issues to summarize"
              : `Copy time range across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} (earliest → latest ISO 8601 + adaptive duration + count). Mirror of R697 Scanner — "when did these issues actually land?" audit answer.`
          }
        >
          📋 Copy time range
        </button>
        {/* R684: Target Issues "📋 Copy detector counts" —
            fourth counts tally on Target. Groups by detector,
            sorted desc by count. Great for "which rule
            dominated this scope-pass?" audit. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            const counts: Record<string, number> = {};
            for (const f of filtered) {
              const d = f.detector || "(unknown)";
              counts[d] = (counts[d] ?? 0) + 1;
            }
            const sorted = Object.entries(counts).sort(
              (a, b) => b[1] - a[1],
            );
            const text = sorted.map(([d, n]) => `${d}: ${n}`).join("\n");
            void navigator.clipboard.writeText(text);
          }}
          title={
            filtered.length === 0
              ? "No issues to tally"
              : `Copy detector counts across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} as a newline-separated list (sorted desc by count). Chatty detectors cluster at the top.`
          }
        >
          📋 Copy detector counts
        </button>
        {/* 🎯 R680: Target Issues "📋 Copy verif counts" — third
            counts tally on Target. 🎯 R680 round-number milestone
            — 14th this chunk after R500/540/550/560/570/580/600/
            620/630/640/650/660/670/680. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            const order = ["verified", "false_positive", "unverified"];
            const counts: Record<string, number> = {};
            for (const f of filtered) {
              const v = f.verification || "unverified";
              counts[v] = (counts[v] ?? 0) + 1;
            }
            const sorted = Object.entries(counts).sort((a, b) => {
              const ai = order.indexOf(a[0]);
              const bi = order.indexOf(b[0]);
              return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
            });
            const text = sorted.map(([v, n]) => `${v}: ${n}`).join(", ");
            void navigator.clipboard.writeText(text);
          }}
          title={
            filtered.length === 0
              ? "No issues to tally"
              : `Copy verification counts across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} as a one-line tally (verified/false_positive/unverified). Great for triage-progress audit. 🎯 R680 round-number milestone — 14th this chunk.`
          }
        >
          📋 Copy verif counts
        </button>
        {/* R678: Target Issues "📋 Copy sev counts" — tally
            variant for Target Issues, mirrors R669 Scanner. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            const order = ["critical", "high", "medium", "low", "info"];
            const counts: Record<string, number> = {};
            for (const f of filtered) {
              const s = f.severity || "info";
              counts[s] = (counts[s] ?? 0) + 1;
            }
            const sorted = Object.entries(counts).sort((a, b) => {
              const ai = order.indexOf(a[0]);
              const bi = order.indexOf(b[0]);
              return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
            });
            const text = sorted.map(([s, n]) => `${s}: ${n}`).join(", ");
            void navigator.clipboard.writeText(text);
          }}
          title={
            filtered.length === 0
              ? "No issues to tally"
              : `Copy severity counts across ${filtered.length} filtered issue${filtered.length === 1 ? "" : "s"} as a one-line tally (critical/high/medium/low/info ordered). Great for a Jira summary or standup update. Mirror of R669 Scanner.`
          }
        >
          📋 Copy sev counts
        </button>
        {/* R611: Clipboard-only JSON array counterpart to Export
            JSONL on Target Issues. Fourth entry in cross-panel
            "Copy as JSON" family (History R605 + Scanner R606 +
            Intruder R607 + Target Issues R611). Operators dropping
            Target finding records into test fixtures / tracking-
            tool imports / jq pipelines want a top-level JSON array
            on the clipboard directly. Pretty-printed 2-space
            indent. Scope matches Export JSONL: `filtered` (post-
            filter view) so narrowing with host/search/sev/status
            filters is respected. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            try {
              void navigator.clipboard.writeText(
                JSON.stringify(filtered, null, 2),
              );
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            filtered.length === 0
              ? "No issues to copy"
              : `Copy ${filtered.length} issue${filtered.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed${filtered.length !== findings.length ? ` — respects the current filter` : ""}). Preserves every TargetFinding field (tags, references, remediation, note, assignee). Great for test fixtures, Jira import, jq pipelines. Fourth entry in cross-panel Copy-as-JSON family.`
          }
        >
          📋 Copy as JSON
        </button>
        {/* R618: Clipboard-only JSONL counterpart to the Target
            Issues JSONL export. Fifth entry in cross-panel "Copy
            as JSONL" family (History R614 + Scanner R615 + Logger
            R616 + Intruder R617 + Target Issues R618). Streaming-
            friendly dense format for jq / ELK / Jira import. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            try {
              const body = filtered
                .map((f) => JSON.stringify(f))
                .join("\n");
              void navigator.clipboard.writeText(body);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            filtered.length === 0
              ? "No issues to copy"
              : `Copy ${filtered.length} issue${filtered.length === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line${filtered.length !== findings.length ? ` — respects the current filter` : ""}). Byte-identical to Export JSONL. Great for jq / grep / Jira import. Fifth entry in cross-panel Copy-as-JSONL family.`
          }
        >
          📋 Copy as JSONL
        </button>
        {/* 🎯 R620: Target Issues "Copy as CSV" — Target Issues
            findings variant of R601 Scanner Copy as CSV. Where R604
            on sitemap tree covers endpoints, R620 covers the
            findings list. Byte-identical column shape to Scanner
            Export CSV (same 9 columns: id, severity, confidence,
            detector, title, status, verification, evidence,
            transaction_id). Rounds out Copy-as-CSV family to 7
            panels (R600-R604 + R613 + R620); R620 is a round-
            number milestone. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            try {
              const headers = [
                "id",
                "severity",
                "confidence",
                "detector",
                "title",
                "status",
                "verification",
                "evidence",
                "transaction_id",
              ];
              const esc = (v: unknown) => {
                const s = v == null ? "" : String(v);
                return /[",\n]/.test(s)
                  ? `"${s.replace(/"/g, '""')}"`
                  : s;
              };
              const body = filtered
                .map((f) =>
                  [
                    f.id,
                    f.severity,
                    f.confidence,
                    f.detector,
                    f.title,
                    f.status,
                    f.verification,
                    f.evidence ?? "",
                    f.transaction_id ?? "",
                  ]
                    .map(esc)
                    .join(","),
                )
                .join("\n");
              const csv = [headers.join(","), body].join("\n");
              void navigator.clipboard.writeText(csv);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            filtered.length === 0
              ? "No issues to copy"
              : `Copy ${filtered.length} issue${filtered.length === 1 ? "" : "s"} as a CSV table to clipboard (9 columns: id, severity, confidence, detector, title, status, verification, evidence, transaction_id${filtered.length !== findings.length ? ` — respects the current filter` : ""}). Byte-identical column shape to Scanner Export CSV. Great for Excel / Sheets / Jira CSV import. 🎯 R620 round-number milestone — 7th panel in cross-panel Copy-as-CSV family.`
          }
        >
          📋 Copy as CSV
        </button>
        {/* R625: Target Issues "Copy as Markdown table" — second
            entry in the cross-panel "Copy as Markdown" family
            (History R624 + Target Issues R625). Markdown table
            variant pastes cleanly into Jira / GitHub PR
            descriptions / Slack. Kept to 6 most-useful columns
            for findings (id, sev, title, status, verification,
            detector) — fewer than the 9-column CSV because
            Markdown tables get hard to read past 6-7 cols. */}
        <button
          disabled={filtered.length === 0}
          onClick={() => {
            const headers = ["id", "sev", "title", "status", "verification", "detector"];
            const esc = (v: unknown) =>
              String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
            const sep = headers.map(() => "---").join(" | ");
            const body = filtered
              .map((f) =>
                [f.id, f.severity, f.title, f.status, f.verification, f.detector]
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
          title={
            filtered.length === 0
              ? "No issues to copy"
              : `Copy ${filtered.length} issue${filtered.length === 1 ? "" : "s"} as a GitHub-flavored Markdown table (6 cols: id, sev, title, status, verification, detector${filtered.length !== findings.length ? ` — respects the current filter` : ""}). Great for Jira / PR description / Slack. Second entry in cross-panel Copy-as-Markdown family.`
          }
        >
          📋 Copy as Markdown
        </button>
        {/* R242: Clear all active filters in Target → Issues sub- */}
        {/* tab. 4 dimensions: host, search, sevFilter, statusFilter. */}
        {/* Mirror of R238/R240/R241. Only renders when ≥1 active.  */}
        {(() => {
          const activeFilters: string[] = [];
          if (host) activeFilters.push(`host=${host}`);
          if (search) activeFilters.push("search");
          if (sevFilter.size > 0) activeFilters.push(`sev×${sevFilter.size}`);
          if (statusFilter.size > 0)
            activeFilters.push(`status×${statusFilter.size}`);
          const n = activeFilters.length;
          if (n === 0) return null;
          return (
            <button
              className="ghost"
              onClick={() => {
                setHost("");
                setSearch("");
                setSevFilter(new Set());
                setStatusFilter(new Set());
              }}
              title={`Clear all ${n} active filter${n === 1 ? "" : "s"}: ${activeFilters.join(", ")}`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              ⨯ clear {n} filter{n === 1 ? "" : "s"}
            </button>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        {/* R452: 📊 severity-split stats badge. Mirror of R440 Repeater */}
        {/* workspace stats + R442 History hosts badge + R451            */}
        {/* Collaborator kind-split — four panels now carry a toolbar    */}
        {/* "📊" quick-stats chip. The existing N / M "shown / total"    */}
        {/* badge to the right is a flat total; this chip breaks the    */}
        {/* total down by severity so operators eyeballing the strip    */}
        {/* can tell at a glance which severity dominates the issue     */}
        {/* set without walking the chip strip below. Derived from the  */}
        {/* already-computed `sevCounts` useMemo (zero new work per     */}
        {/* render). Each count is severity-tinted when > 0 so the eye  */}
        {/* lands on hotspots; dim when 0 so an all-info list doesn't   */}
        {/* shout. Only renders when there is at least one issue so a   */}
        {/* fresh target doesn't carry a strip of zero chips.           */}
        {preChipFiltered.length > 0 && (
          <span
            className="mono"
            title={`Severity breakdown across ${preChipFiltered.length} issue${preChipFiltered.length === 1 ? "" : "s"} on this host — critical × ${sevCounts.critical}, high × ${sevCounts.high}, medium × ${sevCounts.medium}, low × ${sevCounts.low}, info × ${sevCounts.info}`}
            style={{ fontSize: 10.5, color: "var(--text-faint)", marginRight: 8 }}
          >
            📊
            {(["critical", "high", "medium", "low", "info"] as const).map((k, idx) => {
              const n = sevCounts[k];
              const letter = k[0].toUpperCase();
              const active = n > 0;
              return (
                <span key={k} style={{ marginLeft: idx === 0 ? 4 : 6 }}>
                  <span className={`severity-${k}`} style={{ opacity: active ? 1 : 0.35 }}>
                    {n} {letter}
                  </span>
                </span>
              );
            })}
          </span>
        )}
        <span className="badge">{filtered.length} / {preChipFiltered.length}</span>
      </div>
      <div className="issue-filter-strip">
        <div className="issue-filter-row">
          <span className="issue-filter-label">severity</span>
          {severityChipDefs.map(({ key, label }) => {
            const active = sevFilter.has(key);
            const count = sevCounts[key];
            return (
              <button
                key={key}
                type="button"
                className={`issue-sev-chip severity-${key} ${active ? "on" : "off"}`}
                onClick={() => toggleSev(key)}
                title={active ? `Showing ${label}. Click to hide.` : `Click to filter to ${label}.`}
              >
                <span className="chip-label">{label}</span>
                <span className="chip-count">{count}</span>
              </button>
            );
          })}
        </div>
        <div className="issue-filter-row">
          <span className="issue-filter-label">status</span>
          {ISSUE_STATUSES.map(({ value, label }) => {
            const active = statusFilter.has(value);
            const count = statusCounts[value] ?? 0;
            return (
              <button
                key={value}
                type="button"
                className={`issue-status-chip ${active ? "on" : "off"}`}
                onClick={() => toggleStatus(value)}
                title={active ? `Showing ${label}. Click to hide.` : `Click to filter to ${label}.`}
              >
                <span className="chip-label">{label}</span>
                <span className="chip-count">{count}</span>
              </button>
            );
          })}
          {anyChipActive && (
            <button
              type="button"
              className="issue-filter-clear"
              onClick={clearFilters}
              title="Clear all chip filters"
            >
              clear filters
            </button>
          )}
        </div>
      </div>
      <div className="issues-grid">
        <div className="issues-list">
          <table>
            <colgroup>
              <col style={{ width: 70 }} />
              <col />
              <col style={{ width: 160 }} />
              <col style={{ width: 56 }} />
              <col style={{ width: 110 }} />
              <col style={{ width: 110 }} />
            </colgroup>
            {/* R245: Sticky header mirror of R243 Scanner /       */}
            {/* R244 History. Operators scrolling long Issues lists */}
            {/* keep column labels visible as rows slide underneath.*/}
            <thead
              style={{
                position: "sticky",
                top: 0,
                zIndex: 1,
                background: "var(--bg)",
              }}
            >
              <tr>
                <th>Severity</th>
                <th>Issue</th>
                <th>Host</th>
                <th>Conf.</th>
                <th>Status</th>
                <th>Verif.</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={6} className="dim" style={{ padding: 12, textAlign: "center" }}>
                  no issues. Run a passive scan to populate.
                </td></tr>
              )}
              {filtered.map((f) => {
                const t = f.transaction_id ? tx[f.transaction_id] : null;
                const verif = (f.verification ?? "unverified").toLowerCase();
                // R298: Severity row tint — fourth entry in the
                // row-tint family after R294 Intruder status,
                // R295 History status, R297 Logger kind. Different
                // axis for Issues because findings are typed by
                // severity, not response status. Low-saturation
                // rgba tints — critical pops hardest, info stays
                // default so the long tail of info-level findings
                // (which is usually noise) doesn't clutter the
                // view. Palette matches the sev-chip badge so the
                // row + chip read as a coherent cue.
                const sev = (f.severity || "info").toLowerCase();
                let sevBg: string | undefined;
                if (sev === "critical") sevBg = "rgba(224, 68, 68, 0.14)";
                else if (sev === "high") sevBg = "rgba(240, 140, 60, 0.10)";
                else if (sev === "medium") sevBg = "rgba(240, 210, 60, 0.08)";
                else if (sev === "low") sevBg = "rgba(100, 170, 220, 0.07)";
                // info stays default.
                return (
                  <tr
                    key={f.id}
                    className={selected?.id === f.id ? "selected" : ""}
                    onClick={() => setSelected(f)}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setSelected(f);
                      setIssueMenu({ x: e.clientX, y: e.clientY, data: f });
                    }}
                    style={{ cursor: "context-menu", background: sevBg }}
                  >
                    <td>
                      <span className={`sev-chip severity-${f.severity.toLowerCase()}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td title={f.title}>{f.title}</td>
                    <td className="mono dim" title={t ? `${t.scheme}://${t.host}${t.path}` : ""}>
                      {t?.host ?? ""}
                    </td>
                    <td className="mono dim">{f.confidence}</td>
                    <td
                      className="mono"
                      // Click directly on the select shouldn't propagate to the
                      // row-click handler, otherwise the operator loses the
                      // dropdown's focus right after opening it.
                      onClick={(e) => e.stopPropagation()}
                    >
                      <select
                        value={f.status ?? "new"}
                        onChange={(e) => void setFindingStatus(f.id, e.target.value)}
                        style={{ width: "100%", fontSize: 11 }}
                      >
                        {ISSUE_STATUSES.map((s) => (
                          <option key={s.value} value={s.value}>
                            {s.label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td
                      className="mono"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <select
                        value={verif}
                        onChange={(e) => void setFindingVerification(f.id, e.target.value)}
                        style={{
                          width: "100%",
                          fontSize: 11,
                          color:
                            verif === "verified"
                              ? "var(--green)"
                              : verif === "false_positive"
                                ? "var(--red)"
                                : undefined,
                        }}
                      >
                        {ISSUE_VERIFICATIONS.map((v) => (
                          <option key={v.value} value={v.value}>
                            {v.label}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="issues-detail">
          {!selected && <div className="empty">Select an issue to inspect it.</div>}
          {selected && (
            <IssueDetail
              finding={selected}
              tx={selected.transaction_id ? tx[selected.transaction_id] : undefined}
              onStatusChange={setFindingStatus}
              onVerificationChange={setFindingVerification}
              onNoteChange={setFindingNote}
              onDelete={deleteFinding}
            />
          )}
        </div>
      </div>
      <FloatingMenu
        state={issueMenu}
        onClose={() => setIssueMenu(null)}
        items={
          issueMenu?.data
            ? [
                {
                  label: "Send to Repeater",
                  onClick: () => void sendIssueToRepeater(issueMenu.data!),
                  disabled: !issueMenu.data!.transaction_id,
                  hint: !issueMenu.data!.transaction_id
                    ? "no transaction"
                    : undefined,
                },
                {
                  label: "Send to Intruder",
                  onClick: () => sendIssueToIntruder(issueMenu.data!),
                  disabled: !issueMenu.data!.transaction_id,
                },
                {
                  label: "Send to Comparer (left)",
                  onClick: () =>
                    void sendIssueToComparer(issueMenu.data!, "left"),
                  disabled: !issueMenu.data!.transaction_id,
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () =>
                    void sendIssueToComparer(issueMenu.data!, "right"),
                  disabled: !issueMenu.data!.transaction_id,
                },
                // R576: Target Issues row-right-click "Replay
                // request" — cross-panel mirror of HistoryPanel
                // R158 + ProxyPanel R534. Fires the parent
                // transaction's stored bytes through the shared
                // HTTP client; records the paired result as a
                // fresh history row. Distinct from Send to
                // Repeater (clone + edit) — Replay is immediate /
                // no editing. Dispatches burpfree:history-focus
                // for the new tx + burpfree:navigate to flip into
                // HTTP history so operators see the row land.
                {
                  label: "Replay request",
                  hint: "re-fire parent tx through the shared client",
                  disabled: !issueMenu.data!.transaction_id,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const newId = await api.historyReplay(txId);
                      window.dispatchEvent(
                        new CustomEvent("burpfree:history-focus", {
                          detail: { id: newId },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                    } catch (err) {
                      alert(`Replay failed: ${err}`);
                    }
                  },
                },
                // R577: Target Issues row-right-click "Run active
                // scan" — cross-panel mirror of HistoryPanel's
                // active scan + Scanner's "Run active scan". Fires
                // every enabled active-scan probe against the
                // parent transaction. Findings dedupe via
                // fingerprint upsert so running twice on the same
                // tx is safe. Shows a quiet info alert for
                // skipped_reason (no probes enabled / target out
                // of scope); successful run surfaces findings_added
                // + probes_run count.
                {
                  label: "Run active scan",
                  hint: "fires every enabled probe against parent tx",
                  disabled: !issueMenu.data!.transaction_id,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const report = await api.scannerActiveRunTx(txId);
                      if (report.skipped_reason) {
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
                  },
                },
                { separator: true },
                {
                  label: "Copy issue URL",
                  onClick: () => {
                    const t = issueMenu.data!.transaction_id
                      ? tx[issueMenu.data!.transaction_id]
                      : null;
                    void copyToClipboard(t ? urlFromSummary(t) : "");
                  },
                  disabled:
                    !issueMenu.data!.transaction_id ||
                    !tx[issueMenu.data!.transaction_id!],
                },
                {
                  label: "Copy issue summary",
                  onClick: () => copyIssueSummary(issueMenu.data!),
                },
                { separator: true },
                {
                  label: "Open in HTTP history",
                  onClick: () => openIssueInHistory(issueMenu.data!),
                  disabled: !issueMenu.data!.transaction_id,
                },
                // R578: Target Issues row-right-click "Add host
                // to scope" — row-level scope-expansion for
                // operators discovering a new target host via a
                // finding. Reuses existing `scopeAddRule` +
                // `buildHostIncludeRule`. **No pre-filter via
                // hasHostIncludeRule** since IssuesPane doesn't
                // own the scope state (ScopePane / TargetPanel
                // do) — backend's unique-rule guard idempotently
                // no-ops if the rule is already present, so a
                // double-add is safe. Resolves the host from the
                // parent tx (loaded via `tx[txId]`); passive-only
                // findings without a tx disable the entry.
                {
                  label: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    const host = t?.host ?? "";
                    return host
                      ? `+ Add host ${host} to scope`
                      : "+ Add host to scope";
                  })(),
                  disabled: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !t?.host;
                  })(),
                  hint: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host) return "parent tx not loaded";
                    return "backend dedupes if already in scope";
                  })(),
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host) return;
                    try {
                      await api.scopeAddRule(buildHostIncludeRule(t.host));
                      alert(`Added host "${t.host}" to scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // 🎯 R580: Target Issues row-right-click
                // "+ Add host:path to scope" — path-exact variant
                // of R578 for narrower scope-expansion. Operators
                // doing precision scope ("include only this exact
                // endpoint, not the whole host") want path-level
                // rules in one click. Uses `buildPathIncludeRule`
                // which strips the query string so the rule stays
                // stable across varying parameters. R580 round-
                // number milestone. Backend idempotency keeps
                // double-adds safe.
                {
                  label: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    const host = t?.host ?? "";
                    const path = t?.path ?? "";
                    const combined =
                      host && path
                        ? `${host}${path.split("?")[0] || "/"}`
                        : "";
                    return combined
                      ? `+ Add ${combined.length > 40 ? combined.slice(0, 37) + "…" : combined} to scope`
                      : "+ Add host:path to scope";
                  })(),
                  disabled: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !t?.host || !t?.path;
                  })(),
                  hint: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host || !t?.path) return "parent tx not loaded";
                    return "path-exact, narrower than R578";
                  })(),
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host || !t?.path) return;
                    try {
                      await api.scopeAddRule(
                        buildPathIncludeRule(t.host, t.path),
                      );
                      alert(
                        `Added "${t.host}${t.path.split("?")[0] || "/"}" to scope.`,
                      );
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R592: Target Issues row-right-click "− Exclude host" —
                // first mirror of R590 HistoryPanel row-exclude on
                // Target Issues. Operators triaging a finding often
                // want to actively suppress noise from the parent tx's
                // host (e.g. a third-party analytics host that keeps
                // flagging a benign finding) without hiding every
                // finding on included hosts. Builds an inline exclude
                // rule (same shape as R590). Needs the tx lookup via
                // `tx[txId]` since issues are stored separately from
                // the StoredSummary map (IssuesPane holds the map,
                // same pattern as the R578 include-side op above).
                // Backend's unique-rule guard idempotently no-ops on
                // duplicate exclude adds. Danger-styled.
                {
                  label: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    const host = t?.host ?? "";
                    return host
                      ? `− Exclude host ${host}`
                      : "− Exclude host from scope";
                  })(),
                  disabled: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !t?.host;
                  })(),
                  danger: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !!t?.host;
                  })(),
                  hint: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host) return "parent tx not loaded";
                    return "add scope EXCLUDE rule";
                  })(),
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host) return;
                    try {
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: t.host.trim(),
                        port: null as unknown as undefined,
                        path: "*",
                        regex: false,
                        enabled: true,
                      });
                      alert(`Excluded host "${t.host}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R593: Target Issues row-right-click "− Exclude host:path" —
                // path-exact variant of R592. Operators often want narrower
                // exclude rules (just this endpoint, not the whole host) to
                // suppress noise from a single noisy URL without hiding other
                // findings on the same host. Same inline exclude-rule shape
                // as R592 but path-exact (`path: t.path`, stripping query
                // string via split("?")[0] for stable rules across varying
                // parameters). Needs tx lookup via `tx[txId]`. Backend's
                // unique-rule guard idempotently no-ops. Danger-styled when
                // both host + path are loaded; disabled otherwise.
                {
                  label: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    const host = t?.host ?? "";
                    const path = t?.path ?? "";
                    const combined =
                      host && path
                        ? `${host}${path.split("?")[0] || "/"}`
                        : "";
                    return combined
                      ? `− Exclude ${combined.length > 40 ? combined.slice(0, 37) + "…" : combined}`
                      : "− Exclude host:path from scope";
                  })(),
                  disabled: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !t?.host || !t?.path;
                  })(),
                  danger: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !!(t?.host && t?.path);
                  })(),
                  hint: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host || !t?.path) return "parent tx not loaded";
                    return "path-exact, narrower than R592";
                  })(),
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host || !t?.path) return;
                    const path = t.path.split("?")[0] || "/";
                    try {
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: t.host.trim(),
                        port: null as unknown as undefined,
                        path,
                        regex: false,
                        enabled: true,
                      });
                      alert(`Excluded "${t.host}${path}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R629: Target Issues row-right-click "Request in
                // browser" — mirror of R628 Scanner. Fires the
                // parent tx's URL at the OS default browser via
                // shellOpenUrl. tx is a resolved StoredSummary in
                // IssueDetail (not a map), so URL building reads
                // directly from the tx prop. Passive-only findings
                // disable the entry.
                {
                  label: "Request in browser",
                  hint: issueMenu.data!.transaction_id
                    ? "fire URL at the OS default browser"
                    : "passive-only — no parent tx",
                  disabled: (() => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    return !t?.host || !t?.path;
                  })(),
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    const t = txId ? tx[txId] : null;
                    if (!t?.host || !t?.path) return;
                    const url = `${t.scheme}://${t.host}${t.port && t.port !== (t.scheme === "https" ? 443 : 80) ? `:${t.port}` : ""}${t.path}`;
                    try {
                      await api.shellOpenUrl(url);
                    } catch (err) {
                      alert(`Could not open URL in browser: ${err}`);
                    }
                  },
                },
                // R653: Target Issues row-right-click "Copy as JSON"
                // — single-row counterpart to R611 bulk Copy as
                // JSON. Mirror of R651/R652. Dumps the full
                // TargetFinding record (tags, references,
                // remediation, note, assignee) pretty-printed.
                {
                  label: "Copy as JSON",
                  hint: "full TargetFinding record · pretty-printed",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(issueMenu.data!, null, 2),
                    ),
                },
                // R710: Target row "Copy JSONL line" — 3rd panel
                // in the row-level JSONL-line family (History
                // R708 + Scanner R709 + Target R710). Single-
                // line NDJSON for appending to a .jsonl log or
                // piping to jq. Trailing newline. Byte-identical
                // to R618 Target bulk Copy-as-JSONL per-line
                // output.
                {
                  label: "Copy JSONL line",
                  hint: "one object, one line + newline",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(issueMenu.data!) + "\n",
                    ),
                },
                // R729: Target row "Copy triage line" — 4th panel
                // in the row-level Copy triage-line family
                // (HistoryPanel R717 + ProxyPanel R718 + Scanner
                // R728 + Target R729). Byte-identical shape to
                // R728 since Target shares the finding data
                // model: SEV detector · 'title' · verification ·
                // tx:#N · 📎evidence. Perfect for a quick ticket
                // annotation on a single issue.
                {
                  label: "Copy triage line",
                  hint: "compact SEV detector title · tx · evidence",
                  onClick: () => {
                    const f = issueMenu.data!;
                    const sev = (f.severity || "info").toUpperCase();
                    const parts: string[] = [`${sev} ${f.detector || "(unknown)"}`];
                    if (f.title) parts.push(`'${f.title}'`);
                    const v = (f.verification || "").toLowerCase();
                    if (v && v !== "unverified") parts.push(v);
                    if (typeof f.transaction_id === "number")
                      parts.push(`tx:#${f.transaction_id}`);
                    if (f.evidence && f.evidence.length > 0)
                      parts.push("📎evidence");
                    void navigator.clipboard.writeText(parts.join(" · "));
                  },
                },
                // R665: Target Issues row-right-click "Copy table
                // row" — single-row Markdown table variant of
                // R625 bulk Copy as Markdown. Row-content line
                // matching R625's 6-column shape (id/sev/title/
                // status/verification/detector).
                {
                  label: "Copy table row",
                  hint: "Markdown table body line · no header",
                  onClick: () => {
                    const f = issueMenu.data!;
                    const esc = (v: unknown) =>
                      String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
                    const cells = [
                      f.id,
                      f.severity,
                      f.title,
                      f.status,
                      f.verification,
                      f.detector,
                    ]
                      .map(esc)
                      .join(" | ");
                    void navigator.clipboard.writeText(`| ${cells} |`);
                  },
                },
                // R631: Target Issues row-right-click "Open response
                // in browser" — mirror of R630 Scanner. Renders the
                // stored response body via OS default handler. Uses
                // historyShow(txId) to pull response_raw since
                // IssueDetail's tx prop is a StoredSummary (not a
                // TransactionView); content-type parsed from stored
                // head.
                {
                  label: "Open response in browser",
                  hint: issueMenu.data!.transaction_id
                    ? "render stored body via OS default handler"
                    : "passive-only — no parent tx",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const raw = view?.response_raw ?? "";
                      if (!raw.trim()) {
                        alert(`Parent transaction #${txId} has no stored response body — nothing to open.`);
                        return;
                      }
                      const idx = raw.search(/\r?\n\r?\n/);
                      const head = idx >= 0 ? raw.slice(0, idx) : raw;
                      const body =
                        idx >= 0 ? raw.slice(idx).replace(/^\r?\n\r?\n/, "") : "";
                      const ctLine = head
                        .split(/\r?\n/)
                        .find((l) => /^content-type\s*:/i.test(l));
                      const contentType = ctLine
                        ? ctLine.replace(/^content-type\s*:\s*/i, "").trim()
                        : "text/html";
                      const label = view?.summary
                        ? `${view.summary.host}${view.summary.path}`
                        : `tx-${txId}`;
                      await api.responseOpenInBrowser({
                        content: body || raw,
                        contentType,
                        label,
                      });
                    } catch (err) {
                      alert(`Could not open response in browser: ${err}`);
                    }
                  },
                },
                // R327: Row-scope "⬇ Export JSON" — right-click
                // equivalent of R325 Target Issues detail-pane JSON
                // export + direct parallel to R326 Scanner row-right-
                // click. Same filename pattern + output format as
                // R324/R325/R326 so operators get byte-for-byte
                // identical JSON regardless of which path they use
                // (detail pane button, Scanner row menu, Target
                // Issues row menu).
                {
                  label: "⬇ Export JSON",
                  hint: "pretty-printed, single-finding",
                  onClick: () => {
                    const f = issueMenu.data!;
                    try {
                      const blob = new Blob(
                        [JSON.stringify(f, null, 2)],
                        { type: "application/json;charset=utf-8" },
                      );
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      const stamp = new Date()
                        .toISOString()
                        .replace(/[:T]/g, "-")
                        .replace(/\..*$/, "");
                      a.href = url;
                      a.download = `burpfree-finding-${f.id}-${f.severity}-${stamp}.json`;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R495: Row-scope "Copy as cURL" — cross-panel mirror
                // of R494 Scanner row-right-click cURL applied to
                // Target Issues. For a selected issue with
                // transaction_id, pulls parent tx request_raw via
                // historyShow() + builds cURL command via
                // buildCurl(fromSummaryAndRaw()). Byte-identical
                // output to R494 Scanner + R407 HistoryPanel bulk
                // cURL. Completes the Target Issues per-row copy
                // triad alongside "Copy issue URL" (existing) and
                // R483 "Copy as HAR entry" — URL / command /
                // exchange taxonomy fully covered. Operators moving
                // a Target issue to a shell replay get the cURL
                // directly without pivoting into HistoryPanel.
                // **Disabled gate** `transaction_id == null` —
                // passive-only findings skip gracefully.
                {
                  label: "Copy as cURL",
                  hint: "parent tx · full headers + body",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
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
                // R498: Row-scope "Copy as PowerShell" — cross-panel
                // mirror of R497 Scanner row PowerShell. Target Issues
                // now carries both cURL (R495) + PowerShell (R498)
                // Windows shell replay commands, matching Scanner's
                // R494/R497 pair. Operators on Windows triaging a
                // Target issue get Invoke-WebRequest directly from
                // the row-right-click without a cross-panel pivot.
                {
                  label: "Copy as PowerShell",
                  hint: "parent tx · Invoke-WebRequest",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
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
                // R501: Row-scope "Copy as Python (requests)" —
                // cross-panel mirror of R500 Scanner Python. Target
                // Issues now carries the full shell-replay triad
                // (cURL R495 + PowerShell R498 + Python R501),
                // matching Scanner's R494/R497/R500 triad.
                // Mechanism matches R500 Scanner exactly, swapping
                // buildPowerShell for buildPython.
                {
                  label: "Copy as Python (requests)",
                  hint: "parent tx · import requests",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
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
                // R633: Target Issues row-right-click "Copy as fetch()"
                // — mirror of R632 Scanner. Completes the Target Issues
                // shell-replay quartet: cURL (R495) + PowerShell (R498)
                // + Python (R501) + fetch (R633). All 4 primary panels
                // (History/Scanner/Target/ProxyPanel) now carry the
                // full quartet. Same mechanism — historyShow →
                // fromSummaryAndRaw → buildFetch.
                {
                  label: "Copy as fetch()",
                  hint: "parent tx · DevTools console paste",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      await copyToClipboard(buildFetch(req));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R483: Row-scope "Copy as HAR entry" — cross-panel
                // mirror of R482 Scanner row-right-click HAR applied
                // to Target Issues. For a selected issue with
                // transaction_id, pulls parent tx request_raw +
                // response_raw via historyShow() and emits a single-
                // entry HAR 1.2 log to clipboard. Byte-identical
                // output to R478 Target detail-pane button + R470
                // History row + R477/R482 Scanner surfaces. The
                // Scanner↔Target row-right-click HAR parity now
                // matches the keyboard parity (R457 Alt+Shift+E save
                // evidence) and the detail-pane parity (R477/R478).
                // Disabled when transaction_id is null — passive-
                // only findings skip gracefully.
                {
                  label: "Copy as HAR entry",
                  hint: "single-entry HAR 1.2 log · parent tx",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = issueMenu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
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
                      await navigator.clipboard.writeText(
                        JSON.stringify(har, null, 2),
                      );
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R508: Row-scope "⬇ Save as HAR file" — cross-panel
                // mirror of R507 Scanner row-right-click file-save,
                // applied to Target Issues. Completes the Target
                // Issues per-row HAR surface to clipboard+file at
                // the row level (R478 detail-pane clipboard + R483
                // row clipboard + R508 row file-save). Target Issues
                // and Scanner now carry identical HAR-row ops at
                // matching menu positions — the "Copy as HAR entry"
                // + "⬇ Save as HAR file" pair sits in both menus
                // right after the shell-replay triad (cURL /
                // PowerShell / Python). Mechanism matches R483 for
                // the HAR 1.2 build and R507 for the on-disk save.
                // **Filename pattern** `target-issue-har-<fid>-<slug>.har`
                // where `<slug>` is the sanitized issue title — ties
                // the saved HAR back to the issue id + human-readable
                // name, parallel to R507's `scanner-har-<fid>-<slug>.har`.
                // Disabled gate `transaction_id == null` same as R483 /
                // sibling detail-pane HAR button. HAR surface now
                // spans 14 input paths across 5 panels.
                {
                  label: "⬇ Save as HAR file",
                  hint: "single-entry HAR 1.2 log · parent tx · to disk",
                  disabled: issueMenu.data!.transaction_id == null,
                  onClick: async () => {
                    const f = issueMenu.data!;
                    const txId = f.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
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
                      const slug =
                        (f.title || "")
                          .toLowerCase()
                          .replace(/[^a-z0-9]+/g, "-")
                          .replace(/^-|-$/g, "")
                          .slice(0, 40) || "issue";
                      const name = `target-issue-har-${f.id}-${slug}.har`;
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
                // R463: Row-scope "⬇ Save evidence" — visible mirror
                // of R457 Alt+Shift+E keyboard shortcut. Right-click
                // → "⬇ Save evidence" produces the exact same
                // `evidence-<id>-<slug>.txt` file as the keyboard
                // path and R456 Scanner Alt+Shift+E, so operators
                // can use whichever input style they prefer and get
                // byte-identical artifacts. Lives right after
                // "⬇ Export JSON" (which saves the whole finding
                // record as JSON) so the two save-to-disk entries
                // sit together — JSON for programmatic re-ingest,
                // Evidence TXT for ticket attachments / PoC bundles.
                // Hint explains the difference between the two.
                // Disabled when `!f.evidence` so title-only findings
                // skip gracefully.
                {
                  label: "⬇ Save evidence",
                  hint: "the evidence blob only — complements Export JSON above (whole record)",
                  disabled: !issueMenu.data!.evidence,
                  onClick: () => {
                    const f = issueMenu.data!;
                    if (!f.evidence) return;
                    const slug =
                      (f.title || "")
                        .toLowerCase()
                        .replace(/[^a-z0-9]+/g, "-")
                        .replace(/^-|-$/g, "")
                        .slice(0, 40) || "evidence";
                    const name = `evidence-${f.id}-${slug}.txt`;
                    try {
                      const blob = new Blob([f.evidence], {
                        type: "text/plain;charset=utf-8",
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
                  },
                },
                // R323: Row-scope "Add tag…" — final member of the
                // row-level annotation triad (R321 History row,
                // R322 Scanner row, R323 Target Issues row). Target
                // Issues share the StoredFinding model with Scanner
                // so this reuses `findingSetTags` + the same
                // merge-mode logic (union with existing). Placed
                // right before "Delete issue" so quick-annotation
                // sits next to the destructive op, mirroring the
                // History + Scanner panel structures.
                {
                  label: "Add tag…",
                  hint:
                    (issueMenu.data.tags?.length ?? 0) > 0
                      ? `currently: ${(issueMenu.data.tags ?? []).join(", ")}`
                      : "no tags yet",
                  onClick: () => {
                    const f = issueMenu.data!;
                    const next = prompt(
                      `Add a tag to this issue ([${f.severity}] ${f.title.length > 50 ? f.title.slice(0, 47) + "…" : f.title}):\n\n(Merge mode — existing tags survive. No-op if the tag's already here.)`,
                      "",
                    );
                    if (next === null) return;
                    const tag = next.trim();
                    if (tag.length === 0) {
                      alert("Empty tag — nothing to apply.");
                      return;
                    }
                    void (async () => {
                      const cur = f.tags ?? [];
                      if (cur.includes(tag)) {
                        alert(`Already has tag "${tag}" — no change.`);
                        return;
                      }
                      try {
                        const merged = Array.from(new Set([...cur, tag]));
                        await api.findingSetTags(f.id, merged);
                        await refresh();
                      } catch (e) {
                        alert(`${e}`);
                      }
                    })();
                  },
                },
                { separator: true },
                {
                  label: "Delete issue",
                  danger: true,
                  onClick: () => void deleteFinding(issueMenu.data!.id),
                },
              ]
            : []
        }
      />
    </div>
  );
}

function IssueDetail({
  finding,
  tx,
  onStatusChange,
  onVerificationChange,
  onNoteChange,
  onDelete,
}: {
  finding: StoredFinding;
  tx?: StoredSummary;
  onStatusChange: (id: number, s: string) => void;
  onVerificationChange: (id: number, v: string) => void;
  onNoteChange: (id: number, note: string) => void;
  onDelete: (id: number) => void;
}) {
  return (
    <div className="issue-detail">
      <div className="issue-head" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span className={`sev-chip big severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
        <strong style={{ flex: 1 }}>{finding.title}</strong>
        <span className="dim mono">detector: {finding.detector}</span>
        {/* R492: Target Issues detail-pane "📎 Copy URL" button —   */}
        {/* cross-panel mirror of R491 Scanner detail-pane. Always- */}
        {/* visible URL copy for findings with a transaction_id, so */}
        {/* operators don't need to round-trip into R478's HAR     */}
        {/* button or the row-right-click menu's "Copy issue URL".  */}
        {/* Byte-identical output to R491 — same historyShow(txId) */}
        {/* + urlFromSummary(view.summary). **Visibility gate**     */}
        {/* `finding.transaction_id != null` — passive-only skip.   */}
        {finding.transaction_id != null && (
          <button
            className="ghost"
            onClick={async () => {
              const txId = finding.transaction_id;
              if (txId == null) return;
              try {
                const view = await api.historyShow(txId);
                if (!view?.summary) {
                  alert(
                    `Parent transaction #${txId} could not be resolved.`,
                  );
                  return;
                }
                const url = urlFromSummary(view.summary);
                await copyToClipboard(url);
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Copy the parent transaction's URL to clipboard — scheme + host + path. Cross-panel mirror of R491 Scanner detail-pane.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📎 Copy URL
          </button>
        )}
        {/* R549: Target Issues detail-pane "📋 cURL" button —
            completes the 4-panel sticky-header cURL family
            (Scanner R548 / HistoryPanel R546 / ProxyPanel R547 /
            Target R549). Byte-identical output to R495 row-right-
            click "Copy as cURL" since both use the same
            historyShow + fromSummaryAndRaw + buildCurl pipeline.
            Visibility same as R492: transaction_id required. */}
        {finding.transaction_id != null && (
          <button
            className="ghost"
            onClick={async () => {
              const txId = finding.transaction_id;
              if (txId == null) return;
              try {
                const view = await api.historyShow(txId);
                if (!view?.summary || !view.request_raw) {
                  alert(
                    `Parent transaction #${txId} has no stored request_raw — cannot build cURL.`,
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
            }}
            title={`Copy as cURL (headers + body) from the parent transaction — mirrors R495 row-right-click.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 cURL
          </button>
        )}
        {/* R553: Target Issues detail-pane "📋 HAR" button —
            completes the 4-panel sticky-header URL/cURL/HAR
            triad (Scanner R491/R548/R552 / HistoryPanel R543/
            R546/R550 / ProxyPanel R544/R547/R551 / Target R492/
            R549/R553). Byte-identical output to R483 row-right-
            click "Copy as HAR entry" since both use the same
            historyShow + buildHarEntry + buildHarLog pipeline. */}
        {finding.transaction_id != null && (
          <button
            className="ghost"
            onClick={async () => {
              const txId = finding.transaction_id;
              if (txId == null) return;
              try {
                const view = await api.historyShow(txId);
                if (!view?.summary || !view.request_raw) {
                  alert(
                    `Parent transaction #${txId} has no stored request_raw — cannot build HAR entry.`,
                  );
                  return;
                }
                const req = fromSummaryAndRaw(
                  view.summary,
                  view.request_raw,
                );
                let resp: Parameters<typeof buildHarEntry>[2] = undefined;
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
                    if (n.toLowerCase() === "content-type") mimeType = v;
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
                const entry = buildHarEntry(req, startedDateTime, resp);
                const har = buildHarLog([entry]);
                await copyToClipboard(JSON.stringify(har, null, 2));
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Copy single-entry HAR 1.2 log (request + response) — mirrors R483 row-right-click.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 HAR
          </button>
        )}
        {/* R585: Target Issues sticky-header "+ scope" button —
            completes the 4-panel sticky-header "+ scope" family
            (ProxyPanel R582 / HistoryPanel R583 / Scanner R584 /
            Target R585). Operators previewing a finding want to
            one-click scope-add the parent tx's host without a
            row-right-click pivot. Uses `tx` prop directly — in
            IssueDetail it's already the resolved StoredSummary
            (not a map like in IssuesPane). TS2304 caught the
            type mismatch mid-build: the row-right-click uses
            `tx[txId]` because IssuesPane holds a tx map, but
            IssueDetail gets a single StoredSummary as a prop.
            Backend's unique-rule guard idempotently no-ops. */}
        {finding.transaction_id != null && tx?.host && (
          <button
            className="ghost"
            onClick={async () => {
              const host = tx?.host;
              if (!host) return;
              try {
                await api.scopeAddRule(buildHostIncludeRule(host));
                alert(`Added host "${host}" to scope.`);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Add host ${tx?.host ?? ""} to scope include rules. Backend dedupes if already in scope.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            + scope
          </button>
        )}
        {/* R589: Target Issues sticky-header "+ path" button —
            completes the 4-panel sticky-header "+ path" family
            (Scanner R586 / HistoryPanel R587 / ProxyPanel R588 /
            Target R589). Path-exact variant of R585. Operators
            previewing a finding often want narrower scope rules
            ("just this specific endpoint, not the whole host").
            Uses `buildPathIncludeRule(host, path)` which strips
            the query string. Reads `host` + `path` from the
            resolved `tx` prop (StoredSummary, not a map in
            IssueDetail). Backend's unique-rule guard
            idempotently no-ops on duplicate adds. */}
        {finding.transaction_id != null && tx?.host && tx?.path && (
          <button
            className="ghost"
            onClick={async () => {
              const host = tx?.host;
              const path = tx?.path;
              if (!host || !path) return;
              try {
                await api.scopeAddRule(buildPathIncludeRule(host, path));
                alert(`Added "${host}${path}" to scope.`);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Add path ${tx?.host ?? ""}${tx?.path ?? ""} to scope include rules (query string stripped). Backend dedupes if already in scope.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            + path
          </button>
        )}
      </div>
      <div className="issue-controls">
        <label>Status</label>
        <select value={finding.status ?? "new"} onChange={(e) => onStatusChange(finding.id, e.target.value)}>
          <option value="new">new</option>
          <option value="triaging">triaging</option>
          <option value="confirmed">confirmed</option>
          <option value="false_positive">false positive</option>
          <option value="fixed">fixed</option>
          <option value="wontfix">wontfix</option>
        </select>
        <label>Verification</label>
        <select value={finding.verification ?? "unverified"} onChange={(e) => onVerificationChange(finding.id, e.target.value)}>
          <option value="unverified">unverified</option>
          <option value="verified">verified</option>
          <option value="false_positive">false positive</option>
        </select>
        <span className="dim">Confidence: {finding.confidence}</span>
        {finding.observation_count && finding.observation_count > 1 && (
          <span className="dim">Seen ×{finding.observation_count}</span>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        {tx && (
          <button
            onClick={async () => {
              try {
                await api.repeaterAddFromHistory(
                  tx.id,
                  `${tx.method} ${tx.path}`,
                );
                window.dispatchEvent(
                  new CustomEvent("burpfree:navigate", {
                    detail: { target: "repeater" },
                  }),
                );
              } catch (e) {
                alert(`Send to Repeater failed: ${e}`);
              }
            }}
            title="Clone this issue's request into a new Repeater tab"
          >
            Send to Repeater
          </button>
        )}
        {/* R325: Single-finding JSON export — companion to the    */}
        {/* R311 bulk JSONL + R324 Scanner single-finding JSON.   */}
        {/* Operators pulling one issue for a Jira ticket don't   */}
        {/* want the bulk JSONL (one line is awkward overhead);    */}
        {/* this button writes a pretty-printed two-space-indented */}
        {/* JSON blob of the selected StoredFinding so the Target */}
        {/* → Issues detail pane matches the Scanner workflow.    */}
        <button
          onClick={() => {
            try {
              const blob = new Blob(
                [JSON.stringify(finding, null, 2)],
                { type: "application/json;charset=utf-8" },
              );
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              a.href = url;
              a.download = `burpfree-finding-${finding.id}-${finding.severity}-${stamp}.json`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title="Export this single finding as a pretty-printed JSON file. Great for Jira ticket attachments or sharing a specific finding with a teammate without the bulk JSONL wrapper."
        >
          ⬇ JSON
        </button>
        {/* R345: Note editor — parallel to R344 Scanner detail      */}
        {/* pane. Target → Issues shares the StoredFinding model so  */}
        {/* reuses the new findingSetNote RPC. Button label pivots   */}
        {/* "+ Note" ↔ "✎ Note" so operators see at a glance when   */}
        {/* annotation is already present. Prompt-based editor       */}
        {/* keeps the UX minimal and consistent with R321/R322/R323 */}
        {/* add-tag + R344 note workflows.                           */}
        <button
          onClick={() => {
            const next = prompt(
              `Note for issue "${finding.title.length > 50 ? finding.title.slice(0, 47) + "…" : finding.title}":\n\n(Empty string clears the note.)`,
              finding.note ?? "",
            );
            if (next === null) return;
            onNoteChange(finding.id, next);
          }}
          title={
            finding.note
              ? `Edit this issue's operator note (currently: ${finding.note.slice(0, 80)}${finding.note.length > 80 ? "…" : ""})`
              : "Add an operator-side note to this issue — stored separately from the status + stays with the finding across exports"
          }
        >
          {finding.note ? "✎ Note" : "+ Note"}
        </button>
        {/* R352: Inline "+ Tag" quick button — parallel to R351    */}
        {/* Scanner detail pane. Operators triaging an issue in the */}
        {/* Target → Issues detail pane don't have to right-click   */}
        {/* + Add tag then re-focus back here — one toolbar click.  */}
        {/* Fires the same merge-mode logic as R322/R323 row entry. */}
        {/* Direct api call since we're already in the parent      */}
        {/* component (unlike R345's prop-threading pattern); the   */}
        {/* 5s polling catches the refresh naturally.               */}
        <button
          onClick={() => {
            const next = prompt(
              `Add a tag to "${finding.title.length > 50 ? finding.title.slice(0, 47) + "…" : finding.title}":\n\n(Merge mode — existing tags survive. No-op if the tag's already here.)`,
              "",
            );
            if (next === null) return;
            const tag = next.trim();
            if (tag.length === 0) {
              alert("Empty tag — nothing to apply.");
              return;
            }
            const cur = finding.tags ?? [];
            if (cur.includes(tag)) {
              alert(`Already has tag "${tag}" — no change.`);
              return;
            }
            const merged = Array.from(new Set([...cur, tag]));
            // Direct api call — the IssuesPane's 5s polling will
            // catch the refresh. We could add a dedicated callback
            // but the extra prop isn't worth it for a sub-5s UX hit
            // on an annotation action that most operators only fire
            // once per finding.
            void api
              .findingSetTags(finding.id, merged)
              .catch((err) => alert(`${err}`));
          }}
          title={
            (finding.tags?.length ?? 0) > 0
              ? `Add a tag to this issue (currently: ${(finding.tags ?? []).join(", ")})`
              : "Add a tag to this issue (no tags yet)"
          }
        >
          + Tag
        </button>
        {/* R478: Target Issues detail-pane "📋 Copy as HAR" button —   */}
        {/* cross-panel mirror of R477 Scanner detail-pane HAR button.   */}
        {/* For a selected issue with transaction_id, pulls parent tx's */}
        {/* request_raw + response_raw via historyShow() and emits a    */}
        {/* single-entry HAR 1.2 log to the clipboard. Byte-identical    */}
        {/* output to R470 HistoryPanel per-row HAR + R477 Scanner       */}
        {/* detail HAR — operators mixing per-finding (Scanner / Target  */}
        {/* Issues) + per-history-row flows get consistent artifacts.    */}
        {/* Only renders when transaction_id != null — passive-only      */}
        {/* findings skip gracefully.                                     */}
        {finding.transaction_id != null && (
          <button
            className="ghost"
            onClick={async () => {
              const txId = finding.transaction_id;
              if (txId == null) return;
              try {
                const view = await api.historyShow(txId);
                if (!view?.request_raw) {
                  alert(
                    `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
                  );
                  return;
                }
                const req = fromSummaryAndRaw(
                  view.summary,
                  view.request_raw,
                );
                let resp: Parameters<typeof buildHarEntry>[2] = undefined;
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
                    if (n.toLowerCase() === "content-type") mimeType = v;
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
                const entry = buildHarEntry(req, startedDateTime, resp);
                const har = buildHarLog([entry]);
                await navigator.clipboard.writeText(
                  JSON.stringify(har, null, 2),
                );
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Copy parent transaction (tx #${finding.transaction_id}) as a single-entry HAR 1.2 log — paste into Chrome DevTools "Network → Import HAR", Firefox DevTools, HTTP Toolkit, Fiddler. Cross-panel mirror of R477 Scanner detail-pane HAR.`}
          >
            📋 Copy as HAR
          </button>
        )}
        <button className="ghost danger" onClick={() => onDelete(finding.id)}>Delete</button>
      </div>
      {tx && (
        <div className="issue-tx">
          <code className="mono">{tx.method} {tx.scheme}://{tx.host}{tx.path}</code>
          {tx.status && (
            <span className={`status-${Math.floor((tx.status || 0) / 100)}xx mono`}>{tx.status}</span>
          )}
        </div>
      )}
      {/* R371: Tag chips row — parallel to R370 Scanner detail  */}
      {/* pane. Target → Issues shares the StoredFinding so the  */}
      {/* chip-with-⨯ pattern transplants directly. 5s polling   */}
      {/* catches the refresh after remove (same threading note */}
      {/* as R345 + R352 note/tag editors).                      */}
      {finding.tags && finding.tags.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
            padding: "4px 10px",
            fontSize: 11,
          }}
        >
          <span className="dim" style={{ alignSelf: "center" }}>
            tags:
          </span>
          {finding.tags.map((t) => (
            <span
              key={t}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "1px 6px",
                borderRadius: 10,
                background: "rgba(100,150,255,0.14)",
                border: "1px solid rgba(100,150,255,0.4)",
              }}
            >
              {t}
              <button
                onClick={() => {
                  const next = (finding.tags ?? []).filter((x) => x !== t);
                  void api
                    .findingSetTags(finding.id, next)
                    .catch((err) => alert(`${err}`));
                }}
                title={`Remove tag "${t}"`}
                style={{
                  background: "transparent",
                  border: "none",
                  padding: 0,
                  cursor: "pointer",
                  color: "var(--text-dim)",
                  fontSize: 12,
                  lineHeight: 1,
                }}
              >
                ⨯
              </button>
            </span>
          ))}
        </div>
      )}
      <IssueSection title="Description" body={finding.description} />
      {finding.evidence && <IssueSection title="Evidence" body={finding.evidence} mono />}
      {finding.insertion_point && (
        <IssueSection title="Insertion point" body={finding.insertion_point} mono />
      )}
      {finding.remediation && <IssueSection title="Remediation" body={finding.remediation} />}
      {finding.references && finding.references.length > 0 && (
        <div className="issue-section">
          <h4>References</h4>
          <ul>
            {finding.references.map((r, i) => <li key={i} className="mono">{r}</li>)}
          </ul>
        </div>
      )}
      {finding.note && <IssueSection title="Note" body={finding.note} />}
    </div>
  );
}

function IssueSection({ title, body, mono = false }: { title: string; body: string; mono?: boolean }) {
  return (
    <div className="issue-section">
      {/* R305: Inline copy button next to the section heading —  */}
      {/* mirror of R304 Scanner evidence-copy pattern applied to */}
      {/* every Target Issues detail-pane section (Description,  */}
      {/* Evidence, Insertion point, Remediation). Operators      */}
      {/* pasting into tickets want one-click copy per section    */}
      {/* instead of select-all + Ctrl+C.                         */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 2 }}>
        <h4 style={{ margin: 0 }}>{title}</h4>
        <button
          className="ghost"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(body);
            } catch (e) {
              alert(`Copy failed: ${e}`);
            }
          }}
          title={`Copy ${title} to clipboard`}
          style={{ fontSize: 10.5, padding: "1px 6px" }}
        >
          📋 Copy
        </button>
        {/* R402: Save section body to .txt — mirror of R401's      */}
        {/* Scanner evidence-save button, applied to every Target   */}
        {/* Issues detail-pane section. Evidence blobs can run      */}
        {/* large (full response bodies, stack traces); other       */}
        {/* sections (Description, Remediation) are typically       */}
        {/* smaller but still useful to pin to disk for a           */}
        {/* reference pack / PoC bundle. **Filename pattern**       */}
        {/* `<title-slug>-section-<timestamp>.txt` so repeated      */}
        {/* saves don't clobber each other — no finding id in       */}
        {/* scope here (R305's IssueSection is a reusable            */}
        {/* component without the parent finding), so the timestamp */}
        {/* disambiguates. **Visibility gate** only renders when     */}
        {/* `body` is non-empty so empty sections (e.g. Evidence =  */}
        {/* "(none)") don't flash a dead-end download.               */}
        {body && body !== "(none)" && body !== "(not specified)" && (
          <button
            className="ghost"
            onClick={() => {
              const slug =
                title
                  .toLowerCase()
                  .replace(/[^a-z0-9]+/g, "-")
                  .replace(/^-|-$/g, "")
                  .slice(0, 40) || "section";
              const stamp = new Date()
                .toISOString()
                .replace(/[:.]/g, "-")
                .slice(0, 19);
              const name = `${slug}-section-${stamp}.txt`;
              const blob = new Blob([body], {
                type: "text/plain;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = name;
              a.click();
              URL.revokeObjectURL(url);
            }}
            title={`Save ${title} as "${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "section"}-section-<timestamp>.txt" — great for PoC bundles / reference packs / large evidence blobs.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            ⬇ Save
          </button>
        )}
      </div>
      <pre className={mono ? "mono issue-body" : "issue-body"}>{body}</pre>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Analyzer sub-tab
 *
 * Per-host summary stats pulled directly from HTTP history. The idea
 * is Burp's "Target → Analyze target" engagement tool: give the
 * operator a one-glance read of how large and complex a host is
 * before they start probing. Everything is computed client-side over
 * the result of `historyList({ host_contains })`.
 * ------------------------------------------------------------------ */

type AnalysisStats = {
  total: number;
  dynamicUrls: number;
  staticUrls: number;
  forms: number;
  uniqueParams: Set<string>;
  authLikeEndpoints: Set<string>;
  externalHosts: Set<string>;
  longestPath: string;
  statusHistogram: Record<string, number>;
  mimeHistogram: Record<string, number>;
  methodHistogram: Record<string, number>;
};

function AnalyzerPane() {
  const [hostQuery, setHostQuery] = useState("");
  const [rows, setRows] = useState<StoredSummary[]>([]);
  const [hostOptions, setHostOptions] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Populate the host dropdown once.
  useEffect(() => {
    (async () => {
      try {
        const sample = await api.historyList({ limit: 5000 });
        const hs = new Set<string>();
        for (const r of sample) hs.add(r.host);
        setHostOptions(Array.from(hs).sort());
        if (!hostQuery && hs.size > 0) setHostQuery(Array.from(hs)[0]);
      } catch (e) {
        setErr(`${e}`);
      }
    })();
  }, []);

  async function analyze() {
    if (!hostQuery.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      // host_contains is a substring match — fine for the picker use
      // case, and allows an operator to broaden to a wildcard.
      const list = await api.historyList({ host_contains: hostQuery.trim(), limit: 10000 });
      setRows(list);
    } catch (e) {
      setErr(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  const stats: AnalysisStats | null = useMemo(() => {
    if (rows.length === 0) return null;
    return computeStats(rows, hostQuery);
  }, [rows, hostQuery]);

  const sortedStatuses = useMemo(
    () => (stats ? Object.entries(stats.statusHistogram).sort((a, b) => a[0].localeCompare(b[0])) : []),
    [stats]
  );
  const sortedMimes = useMemo(
    () => (stats ? Object.entries(stats.mimeHistogram).sort((a, b) => b[1] - a[1]).slice(0, 10) : []),
    [stats]
  );

  return (
    <div className="analyzer-root">
      <div className="toolbar">
        <label>Host</label>
        <input
          list="analyzer-hosts"
          value={hostQuery}
          onChange={(e) => setHostQuery(e.target.value)}
          placeholder="example.com"
          style={{ width: 260 }}
        />
        <datalist id="analyzer-hosts">
          {hostOptions.map((h) => <option key={h} value={h} />)}
        </datalist>
        <button className="primary" onClick={analyze} disabled={busy || !hostQuery.trim()}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        {err && <span style={{ color: "var(--red)", fontSize: 11 }}>✗ {err}</span>}
      </div>
      {!stats && !busy && (
        <div className="empty">Pick a host and click Analyze to summarize what BurpFree has seen for it.</div>
      )}
      {stats && (
        <div className="analyzer-grid">
          <AnalyzerCard title="Volume">
            <Metric label="Observations" value={stats.total} />
            <Metric label="Dynamic URLs" value={stats.dynamicUrls} />
            <Metric label="Static URLs"  value={stats.staticUrls} />
            <Metric
              label="Dynamic ratio"
              value={stats.total === 0 ? "—" : `${Math.round((stats.dynamicUrls / stats.total) * 100)}%`}
            />
          </AnalyzerCard>
          <AnalyzerCard title="Interaction surface">
            <Metric label="Forms observed" value={stats.forms} />
            <Metric label="Unique param names" value={stats.uniqueParams.size} />
            <Metric label="Auth-like endpoints" value={stats.authLikeEndpoints.size} />
            <Metric label="External hosts referenced" value={stats.externalHosts.size} />
          </AnalyzerCard>
          <AnalyzerCard title="Longest observed path">
            <code className="mono analyzer-path" title={stats.longestPath}>
              {stats.longestPath || "—"}
            </code>
          </AnalyzerCard>
          <AnalyzerCard title="Status histogram">
            {sortedStatuses.length === 0 && <span className="dim">no responses</span>}
            {sortedStatuses.map(([k, n]) => (
              <Bar key={k} label={k} value={n} max={maxVal(stats.statusHistogram)} colorClass={statusColor(k)} />
            ))}
          </AnalyzerCard>
          <AnalyzerCard title="Method histogram">
            {Object.entries(stats.methodHistogram)
              .sort((a, b) => b[1] - a[1])
              .map(([k, n]) => (
                <Bar key={k} label={k} value={n} max={maxVal(stats.methodHistogram)} />
              ))}
          </AnalyzerCard>
          <AnalyzerCard title="Top MIME types">
            {sortedMimes.length === 0 && <span className="dim">no responses</span>}
            {sortedMimes.map(([k, n]) => (
              <Bar key={k} label={k} value={n} max={maxVal(stats.mimeHistogram)} />
            ))}
          </AnalyzerCard>
          {stats.authLikeEndpoints.size > 0 && (
            <AnalyzerCard title={`Auth-looking endpoints (${stats.authLikeEndpoints.size})`} wide>
              <ul className="analyzer-list">
                {Array.from(stats.authLikeEndpoints).sort().slice(0, 50).map((p) => (
                  <li key={p} className="mono">{p}</li>
                ))}
                {stats.authLikeEndpoints.size > 50 && (
                  <li className="dim">… and {stats.authLikeEndpoints.size - 50} more</li>
                )}
              </ul>
            </AnalyzerCard>
          )}
          {stats.externalHosts.size > 0 && (
            <AnalyzerCard title={`External hosts referenced (${stats.externalHosts.size})`} wide>
              <ul className="analyzer-list">
                {Array.from(stats.externalHosts).sort().slice(0, 50).map((h) => (
                  <li key={h} className="mono">{h}</li>
                ))}
                {stats.externalHosts.size > 50 && (
                  <li className="dim">… and {stats.externalHosts.size - 50} more</li>
                )}
              </ul>
            </AnalyzerCard>
          )}
        </div>
      )}
    </div>
  );
}

function AnalyzerCard({ title, children, wide = false }: { title: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className={`analyzer-card ${wide ? "wide" : ""}`}>
      <div className="analyzer-card-title">{title}</div>
      <div className="analyzer-card-body">{children}</div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="analyzer-metric">
      <span className="analyzer-metric-value">{value}</span>
      <span className="analyzer-metric-label">{label}</span>
    </div>
  );
}

function Bar({ label, value, max, colorClass = "" }: { label: string; value: number; max: number; colorClass?: string }) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div className="analyzer-bar">
      <span className={`analyzer-bar-label mono ${colorClass}`}>{label}</span>
      <div className="analyzer-bar-track">
        <div className={`analyzer-bar-fill ${colorClass}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="analyzer-bar-val mono">{value}</span>
    </div>
  );
}

function statusColor(k: string): string {
  if (k.startsWith("2")) return "ok-2xx";
  if (k.startsWith("3")) return "ok-3xx";
  if (k.startsWith("4")) return "ok-4xx";
  if (k.startsWith("5")) return "ok-5xx";
  return "";
}

function maxVal(h: Record<string, number>): number {
  let m = 0;
  for (const v of Object.values(h)) if (v > m) m = v;
  return m;
}

function computeStats(rows: StoredSummary[], hostQuery: string): AnalysisStats {
  const stats: AnalysisStats = {
    total: rows.length,
    dynamicUrls: 0,
    staticUrls: 0,
    forms: 0,
    uniqueParams: new Set(),
    authLikeEndpoints: new Set(),
    externalHosts: new Set(),
    longestPath: "",
    statusHistogram: {},
    mimeHistogram: {},
    methodHistogram: {},
  };
  const STATIC_EXT = /\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webm|webp)(?:\?|$)/i;
  const AUTH_RE = /(?:login|signin|sign-in|logon|logoff|logout|auth|signup|sign-up|register|oauth|sso|saml|jwks|token|password|forgot)/i;
  const DYNAMIC_EXT = /\.(?:php|aspx?|jsp|cfm|cgi|action|do)(?:\?|$)/i;
  const hostLower = hostQuery.trim().toLowerCase();

  for (const r of rows) {
    // Longest path.
    if (r.path.length > stats.longestPath.length) stats.longestPath = r.path;

    // Status histogram keyed by hundred (2xx, 3xx, ...) + the specific
    // code. We bucket by class to keep the chart readable.
    if (r.status != null) {
      const bucket = `${Math.floor(r.status / 100)}xx`;
      stats.statusHistogram[bucket] = (stats.statusHistogram[bucket] ?? 0) + 1;
    }
    // Method histogram.
    const m = r.method || "GET";
    stats.methodHistogram[m] = (stats.methodHistogram[m] ?? 0) + 1;

    // MIME histogram (short form).
    const mime = shortMime(r.content_type);
    if (mime) stats.mimeHistogram[mime] = (stats.mimeHistogram[mime] ?? 0) + 1;

    // Dynamic vs static classification.
    const query = r.path.indexOf("?") > 0;
    const hasParams = (r.param_count ?? 0) > 0;
    const isDyn = query || hasParams || DYNAMIC_EXT.test(r.path) || !STATIC_EXT.test(r.path);
    if (STATIC_EXT.test(r.path) && !query && !hasParams) {
      stats.staticUrls++;
    } else if (isDyn) {
      stats.dynamicUrls++;
    } else {
      stats.staticUrls++;
    }

    // Forms heuristic: POST/PUT with urlencoded or multipart content-type.
    if ((r.method === "POST" || r.method === "PUT" || r.method === "PATCH") && hasParams) {
      stats.forms++;
    }

    // Unique param names: scrape "name=value" pairs from the query
    // string. Form-body names aren't on the summary, so this is
    // query-only — an acceptable approximation.
    const q = r.path.indexOf("?");
    if (q > 0) {
      const qs = r.path.slice(q + 1);
      for (const pair of qs.split("&")) {
        const eq = pair.indexOf("=");
        const name = eq >= 0 ? pair.slice(0, eq) : pair;
        if (name) stats.uniqueParams.add(decodeURIComponent(name));
      }
    }

    // Auth-looking endpoint detection.
    if (AUTH_RE.test(r.path)) {
      stats.authLikeEndpoints.add(r.path.split("?")[0]);
    }

    // External hosts: any row whose host doesn't match the search
    // input is considered "external" relative to the target.
    if (hostLower && r.host.toLowerCase() !== hostLower && !r.host.toLowerCase().includes(hostLower)) {
      stats.externalHosts.add(r.host);
    }
  }
  return stats;
}
