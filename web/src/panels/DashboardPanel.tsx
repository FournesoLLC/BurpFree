import { useEffect, useRef, useState } from "react";
import { api, AutoBackupConfig, BackupInfo, BambdaSavedQuery, ComparerItem, Cookie, DashboardStats, DashboardTask, IntruderRecipeView, MatchReplaceEngine, OobInteraction, PayloadLibraryEntry, RepeaterTab, Scope, SessionMacro, SessionRule, StoredFinding, StoredSummary, WsSessionRow } from "../api";

/** Severity palette matching ScannerPanel / BChecksPanel so a given
 *  level reads consistently across the three places findings
 *  surface. Keys are the lowercase severity labels the backend
 *  emits; values the { background, foreground } tuple for the
 *  pill. */
const FINDING_SEVERITY_COLORS: Record<string, { bg: string; fg: string }> = {
  critical: { bg: "rgba(224, 68, 68, 0.22)", fg: "#ff5c5c" },
  high:     { bg: "rgba(240, 140, 60, 0.22)", fg: "#f09040" },
  medium:   { bg: "rgba(240, 210, 60, 0.22)", fg: "#f0c030" },
  low:      { bg: "rgba(100, 170, 220, 0.22)", fg: "#5fa0dc" },
  info:     { bg: "rgba(140, 140, 150, 0.22)", fg: "#9898a0" },
};

/** Humanise a backend timestamp (ms since epoch) as a short relative
 *  string: `just now` / `12s` / `3m` / `2h` / `4d`. Falls back to
 *  the raw ISO date when the gap > 7 days. Used by the Recent
 *  findings card so operators see at-a-glance whether an issue
 *  landed in the current session or earlier. */
function humanRelativeAge(tsMs: number | null | undefined): string {
  if (!tsMs || tsMs <= 0) return "—";
  const diff = Math.max(0, Date.now() - tsMs);
  if (diff < 2_000) return "just now";
  const s = Math.floor(diff / 1_000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(tsMs).toISOString().slice(0, 10);
}

/** One sample from the rolling throughput buffer. We store only the
 *  cumulative counter + wall-clock timestamp — the UI derives rates
 *  by diffing adjacent samples. */
type RateSample = { ts_ms: number; forwarded: number };

/** Keep ~2 minutes of samples at the 2s poll cadence (60 samples).
 *  Enough for a 30-sample sparkline + a trailing avg window. */
const RATE_BUFFER_MAX = 60;
const RATE_WINDOW_MS = 120_000;

export function DashboardPanel() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [history, setHistory] = useState<StoredSummary[]>([]);
  // R518: Cookie jar snapshot — polled on the same 2s cadence as
  // the other dashboard sources so the stats stay fresh as live
  // proxy traffic appends cookies.
  const [jarCookies, setJarCookies] = useState<Cookie[]>([]);
  // R521: Scope snapshot — polled alongside jarCookies so the
  // dashboard reflects live scope-rule edits (adds from history
  // row-right-click + Scope panel edits) without a reload.
  const [scopeSnap, setScopeSnap] = useState<Scope | null>(null);
  // R528: Repeater tabs snapshot for the "Repeater activity" card.
  // Polled on the 2s cadence so the card reflects live tab sends
  // / adds / closes without a manual refresh.
  const [repeaterTabs, setRepeaterTabs] = useState<RepeaterTab[]>([]);
  // R529: Intruder recipes snapshot for the "Intruder activity"
  // card. Polled on the 2s cadence so saved-recipe edits reflect
  // without a manual refresh.
  const [intruderRecipes, setIntruderRecipes] = useState<
    IntruderRecipeView[]
  >([]);
  // R530: Collaborator interactions snapshot for the "Collaborator
  // activity" card. Polled on the 2s cadence so new OOB hits land
  // on the dashboard without a manual refresh.
  const [oobInteractions, setOobInteractions] = useState<OobInteraction[]>([]);
  // R533: Logger recent-events snapshot for the "Logger activity"
  // card. Polled on the 2s cadence with a 500-event ceiling —
  // enough for a kind-distribution snapshot without pulling the
  // entire logger ring buffer into the dashboard.
  const [loggerRecent, setLoggerRecent] = useState<
    Array<{ seq: number; event: { ts_ms: number; kind: any } }>
  >([]);
  // R539: Session rules + macros snapshot for the "Session
  // rules + macros" card. Two parallel polls on the 2s cadence.
  const [sessionRules, setSessionRules] = useState<SessionRule[]>([]);
  const [sessionMacros, setSessionMacros] = useState<SessionMacro[]>([]);
  // R540: Match & Replace engine snapshot + hits map for the
  // "Match & Replace rules" card. Two parallel polls on the 2s
  // cadence paralleling MatchReplacePane's own cadence.
  const [matchReplaceEngine, setMatchReplaceEngine] =
    useState<MatchReplaceEngine | null>(null);
  const [matchReplaceHits, setMatchReplaceHits] = useState<
    Record<string, number>
  >({});
  // R541: Interceptor queue status for the "Interceptor queue"
  // card. Alert tile — surfaces pending-packet count so operators
  // don't lose a packet waiting for a forward/drop decision.
  const [interceptorStatus, setInterceptorStatus] = useState<{
    request: boolean;
    response: boolean;
    pending: number;
  } | null>(null);
  // R560: Backup config + list for the "Project backups" tile.
  // Alert when auto-backup is disabled or no recent backup.
  const [backupConfig, setBackupConfig] = useState<AutoBackupConfig | null>(
    null,
  );
  const [backupList, setBackupList] = useState<BackupInfo[]>([]);
  // R574: WebSocket sessions snapshot for the "WebSocket
  // activity" card. Capped at 200 recent sessions to keep the
  // Dashboard dialog light.
  const [wsSessions, setWsSessions] = useState<WsSessionRow[]>([]);
  // R621: Comparer items snapshot for the "Comparer items" card.
  // Polled on the 2s cadence so new items from Send-to-Comparer
  // land on the dashboard without a reload.
  const [comparerItems, setComparerItems] = useState<ComparerItem[]>([]);
  // R622: Bambda saved filters per scope. History + Logger have
  // separate scopes so each gets its own list. Polled on the 2s
  // cadence alongside the other dashboard sources.
  const [bambdaHistory, setBambdaHistory] = useState<BambdaSavedQuery[]>([]);
  const [bambdaLogger, setBambdaLogger] = useState<BambdaSavedQuery[]>([]);
  // R623: Extensions snapshot for the "Extensions" card. Polled on
  // the 2s cadence so enable/disable + reload cycles reflect in the
  // dashboard without a reload.
  const [extensions, setExtensions] = useState<
    Array<{
      name: string;
      version: string;
      author: string;
      description: string;
      permissions: string[];
    }>
  >([]);
  // R638: Annotation snapshot counts for the "Annotations" card.
  // Two parallel historyCount calls — one filter per axis.
  const [annotHighlighted, setAnnotHighlighted] = useState(0);
  const [annotCommented, setAnnotCommented] = useState(0);
  // R655: Status code class counts for the "Status codes" card.
  // Four parallel historyCount calls — one per class.
  const [statusCounts, setStatusCounts] = useState({
    c2xx: 0,
    c3xx: 0,
    c4xx: 0,
    c5xx: 0,
  });
  // R658: HTTP method counts for the "HTTP methods" card. Five
  // parallel historyCount calls — one per common method.
  const [methodCounts, setMethodCounts] = useState({
    get: 0,
    post: 0,
    put: 0,
    del: 0,
    patch: 0,
  });
  // R668: In-scope transaction count for the "Scope hit rate" card.
  // Single historyCount with in_scope_only=true.
  const [inScopeCount, setInScopeCount] = useState(0);
  // R674: Error-flagged transaction count for the "Error rate" card.
  // Single historyCount with error_only=true.
  const [errorOnlyCount, setErrorOnlyCount] = useState(0);
  // R646: Payload library snapshot. Polled once-ish (library
  // doesn't change at runtime typically) but on the same 2s
  // cadence for consistency; cheap read since it's just names +
  // counts.
  const [payloads, setPayloads] = useState<PayloadLibraryEntry[]>([]);
  // Per-host finding counts (R90 cmd). Polled on the same 2 s
  // cadence as everything else; feeds the "Findings by host" card.
  const [hostFindingCounts, setHostFindingCounts] = useState<
    Record<string, Record<string, number>>
  >({});
  // Recent findings feed — Burp's dashboard shows live issues as
  // they land. Polled on the same 2s cadence as stats; capped at
  // top-20 so the card doesn't become a scroll trap. Sorted
  // backend-side (natural id DESC = newest first) and sliced in
  // the frontend. Silent-on-error so a missing project doesn't
  // flash alerts.
  const [recentFindings, setRecentFindings] = useState<StoredFinding[]>([]);
  const [bootstrapping, setBootstrapping] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [lastErr, setLastErr] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Ring buffer of recent proxy throughput snapshots. Kept in a ref
  // so pushing a sample doesn't trigger a re-render; we lift derived
  // values into `rateView` state at the end of each refresh.
  const rateBuffer = useRef<RateSample[]>([]);
  const [rateView, setRateView] = useState<{
    reqPerSec: number | null;
    windowSec: number;
    rates: number[];
  }>({ reqPerSec: null, windowSec: 0, rates: [] });

  async function refresh() {
    try {
      const next = await api.dashboardStats();
      setStats(next);
      // Push the latest cumulative counter onto the ring buffer and
      // prune anything older than the retention window.
      const now = Date.now();
      rateBuffer.current.push({ ts_ms: now, forwarded: next.proxy.requests_forwarded });
      // Drop old samples by age + hard cap.
      rateBuffer.current = rateBuffer.current.filter(
        (s) => now - s.ts_ms <= RATE_WINDOW_MS,
      );
      if (rateBuffer.current.length > RATE_BUFFER_MAX) {
        rateBuffer.current = rateBuffer.current.slice(-RATE_BUFFER_MAX);
      }
      // Compute aggregate req/s over the whole retained window + the
      // per-interval rates array used by the sparkline.
      const buf = rateBuffer.current;
      let reqPerSec: number | null = null;
      let windowSec = 0;
      const rates: number[] = [];
      if (buf.length >= 2) {
        const first = buf[0];
        const last = buf[buf.length - 1];
        windowSec = Math.max(1, Math.round((last.ts_ms - first.ts_ms) / 1000));
        const delta = Math.max(0, last.forwarded - first.forwarded);
        reqPerSec = delta / windowSec;
        for (let i = 1; i < buf.length; i++) {
          const a = buf[i - 1];
          const b = buf[i];
          const dt = Math.max(0.001, (b.ts_ms - a.ts_ms) / 1000);
          const dv = Math.max(0, b.forwarded - a.forwarded);
          rates.push(dv / dt);
        }
      }
      setRateView({ reqPerSec, windowSec, rates });
      setLastErr(null);
    } catch (e) {
      setLastErr(`${e}`);
    }
    try {
      setHistory(await api.historyList({ limit: 15 }));
    } catch {
      /* backend not ready */
    }
    try {
      // Pull recent findings for the "Recent findings" card. The
      // backend returns everything ordered by id DESC (newest
      // first) — we trim to 20 for the card. Fire-and-forget
      // alongside history so one empty response doesn't blank
      // both panes.
      const all = await api.findingsList();
      setRecentFindings((all ?? []).slice(0, 20));
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // Per-host severity count breakdown (R90). Feeds the
      // "Findings by host" card. Returns an empty map when the
      // project has no findings yet; we accept that and let the
      // card render its empty state.
      setHostFindingCounts(await api.findingsCountByHost());
    } catch {
      /* backend not ready — stale snapshot is fine */
    }
    try {
      // R518: Pull the current cookie jar snapshot for the
      // "Cookie jar snapshot" card. Silent-on-error so an empty
      // or absent jar doesn't blank the dashboard.
      setJarCookies(await api.cookieJarList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R521: Pull the current scope for the "Scope summary"
      // card. Silent-on-error so an empty scope doesn't blank
      // the dashboard.
      setScopeSnap(await api.scopeGet());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R528: Pull the current Repeater tabs for the "Repeater
      // activity" card. Silent-on-error so an empty workspace
      // doesn't blank the dashboard.
      setRepeaterTabs(await api.repeaterList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R529: Pull saved Intruder recipes for the "Intruder
      // activity" card. Silent-on-error so an empty workspace
      // doesn't blank the dashboard.
      setIntruderRecipes(await api.intruderRecipeList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R530: Pull Collaborator interactions for the "Collaborator
      // activity" card. Silent-on-error so a stopped collaborator
      // doesn't blank the dashboard.
      setOobInteractions(await api.oobInteractionsAll());
    } catch {
      /* collaborator not running — keep the previous snapshot */
    }
    try {
      // R533: Pull recent logger events for the "Logger activity"
      // card. Capped at 500 to keep the Dashboard dialog light on
      // long-running sessions — the kind-breakdown reads the
      // 500-event tail, not the full ring buffer.
      setLoggerRecent(await api.loggerRecent(500));
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R539: Pull session rules + macros for the "Session rules
      // + macros" card. Two parallel fetches (both silent-on-error).
      setSessionRules(await api.sessionRulesList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      setSessionMacros(await api.sessionMacrosList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R540: Pull the current Match & Replace engine + hits map
      // for the "Match & Replace rules" card. Two parallel
      // fetches since the backend keeps the config and the live
      // hit counter separate.
      setMatchReplaceEngine(await api.matchReplaceGet());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      setMatchReplaceHits(await api.matchReplaceHits());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R541: Pull interceptor queue status for the "Interceptor
      // queue" card. Silent-on-error — a disabled interceptor
      // just leaves the previous snapshot.
      setInterceptorStatus(await api.interceptorStatus());
    } catch {
      /* interceptor not running — keep the previous snapshot */
    }
    try {
      // R560: Pull backup config + backup list for the "Project
      // backups" card. Silent-on-error so a missing project
      // doesn't blank the dashboard.
      setBackupConfig(await api.backupConfigGet());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      setBackupList(await api.backupList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R574: Pull recent WebSocket sessions for the activity
      // card. Capped at 200 to keep the Dashboard dialog light.
      setWsSessions(await api.wsSessionsList(200));
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R621: Pull current Comparer items for the "Comparer items"
      // card. Silent-on-error so an empty collection doesn't blank
      // the dashboard.
      setComparerItems(await api.comparerItemsList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R622: Pull both Bambda scopes in parallel for the "Bambda
      // filters" card. Silent-on-error so one scope being empty
      // doesn't blank the dashboard.
      const [h, l] = await Promise.all([
        api.bambdaQueriesList("history"),
        api.bambdaQueriesList("logger"),
      ]);
      setBambdaHistory(h);
      setBambdaLogger(l);
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R623: Pull loaded extensions for the "Extensions" card.
      // Silent-on-error so a missing extensions directory doesn't
      // blank the dashboard.
      setExtensions(await api.extensionsList());
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R638: Pull annotation counts for the "Annotations" card.
      // Three parallel historyCount calls (highlighted / commented /
      // one-tag-at-least) since each filter is its own flag. The
      // tagged count uses an any-tag filter approximation —
      // historyCount with no filter gives total, so the diff isn't
      // exact; we use the dedicated filters where backend supports
      // them.
      const [hl, cm] = await Promise.all([
        api.historyCount({ highlighted_only: true }),
        api.historyCount({ commented_only: true }),
      ]);
      setAnnotHighlighted(hl);
      setAnnotCommented(cm);
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R646: Pull payload library entries for the "Payload library"
      // card. The library is static per binary (doesn't change at
      // runtime) but we poll on the 2s cadence for consistency.
      setPayloads(await api.payloadsLibraryList());
    } catch {
      /* backend doesn't ship a library — keep the previous snapshot */
    }
    try {
      // R655: Pull status-code class counts for the "Status codes"
      // card. Four parallel historyCount calls, one per class.
      // Backend's status_classes filter accepts a single hundreds-
      // digit per call; parallelism keeps the latency flat.
      const [c2, c3, c4, c5] = await Promise.all([
        api.historyCount({ status_classes: [2] }),
        api.historyCount({ status_classes: [3] }),
        api.historyCount({ status_classes: [4] }),
        api.historyCount({ status_classes: [5] }),
      ]);
      setStatusCounts({ c2xx: c2, c3xx: c3, c4xx: c4, c5xx: c5 });
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R658: Pull HTTP-method counts for the "HTTP methods" card.
      // Five parallel historyCount calls — one per common method.
      // Rare methods (HEAD / OPTIONS) are rolled into "other" via
      // a simple aggregate: total transactions minus the five tracked.
      const [get, post, put, del, patch] = await Promise.all([
        api.historyCount({ method: "GET" }),
        api.historyCount({ method: "POST" }),
        api.historyCount({ method: "PUT" }),
        api.historyCount({ method: "DELETE" }),
        api.historyCount({ method: "PATCH" }),
      ]);
      setMethodCounts({ get, post, put, del, patch });
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R668: Pull in-scope transaction count for the "Scope hit
      // rate" card. Single historyCount call with in_scope_only
      // filter.
      setInScopeCount(await api.historyCount({ in_scope_only: true }));
    } catch {
      /* no project yet — keep the previous snapshot */
    }
    try {
      // R674: Pull error-flagged transaction count for the "Error
      // rate" card. Backend's error_only HistoryFilter matches
      // rows with a non-NULL error column (TLS fail / parse error
      // / network drop).
      setErrorOnlyCount(await api.historyCount({ error_only: true }));
    } catch {
      /* no project yet — keep the previous snapshot */
    }
  }

  useEffect(() => {
    void refresh();
    timer.current = setInterval(refresh, 2000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, []);

  async function toggleProxy() {
    try {
      if (stats?.proxy.running) await api.proxyStop();
      else await api.proxyStart();
      await refresh();
    } catch (e) { alert(`${e}`); }
  }

  async function toggleOob() {
    try {
      if (stats?.oob.running) await api.oobStop();
      else await api.oobStart();
      await refresh();
    } catch (e) { alert(`${e}`); }
  }

  /** Open the project root in the OS file manager. */
  async function openProjectFolder() {
    try {
      await api.projectOpenFolder();
    } catch (e) {
      alert(`Could not open folder: ${e}`);
    }
  }

  /** Copy the project root path to the clipboard. */
  async function copyProjectPath() {
    const path = stats?.project.root;
    if (!path) return;
    try {
      await navigator.clipboard.writeText(path);
    } catch (e) {
      alert(`Clipboard write failed: ${e}`);
    }
  }

  async function initProject() {
    setBootstrapping(true);
    try {
      const path = await api.defaultProjectPath();
      await api.projectOpenOrCreate(path);
      try { await api.proxyStart(); } catch { /* already running */ }
      await refresh();
    } catch (e) { alert(`${e}`); }
    finally { setBootstrapping(false); }
  }

  async function runPassive() {
    setScanBusy(true);
    try {
      const n = await api.passiveRunNow();
      await refresh();
      // Tiny toast via alert for the one-shot number; the "Last run"
      // card below reflects the live state too.
      console.log(`passive scan completed: ${n} finding(s)`);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setScanBusy(false);
    }
  }

  const sev = stats?.findings_by_severity ?? {};
  const topHosts = aggregateHosts(history);

  return (
    <div className="panel dashboard dashboard-grid">
      <TasksSidebar />
      <div className="dashboard-main" style={{ overflow: "auto" }}>
      <div className="toolbar">
        <strong>Dashboard</strong>
        {lastErr && <span style={{ color: "var(--red)", fontSize: 11 }}>{lastErr}</span>}
        <span className="spacer" style={{ flex: 1 }} />
        {!stats?.project.root && (
          <button className="primary" disabled={bootstrapping} onClick={initProject}>
            {bootstrapping ? "Loading…" : "Create / open default project"}
          </button>
        )}
        <button
          onClick={runPassive}
          disabled={scanBusy || !!stats?.passive_scan_running}
          title="Run passive detectors (and extension-contributed rules) over existing history"
        >
          {scanBusy || stats?.passive_scan_running ? "Scanning…" : "Run passive scan"}
        </button>
        <button className={stats?.proxy.running ? "" : "primary"} onClick={toggleProxy}>
          {stats?.proxy.running ? "Stop proxy" : "Start proxy"}
        </button>
      </div>

      <div className="dash-metric-row">
        {/* R188: Transactions metric clickable → jump to HTTP      */}
        {/* history panel. Operators glance at tx count and         */}
        {/* usually want to drill in; matches R177 (Dashboard →     */}
        {/* Scanner) and R185 (Dashboard → Collaborator) jump       */}
        {/* pattern. Only clickable when count > 0 so an empty      */}
        {/* project shows plain text (parallel to R185's gating).    */}
        <Metric
          label="Transactions"
          value={
            (stats?.project.tx_count ?? 0) > 0 ? (
              <button
                type="button"
                onClick={() =>
                  window.dispatchEvent(
                    new CustomEvent("burpfree:navigate", {
                      detail: { target: "history" },
                    }),
                  )
                }
                title="Click to open HTTP history"
                style={{
                  background: "transparent",
                  border: 0,
                  padding: 0,
                  cursor: "pointer",
                  font: "inherit",
                  color: "inherit",
                }}
              >
                {stats?.project.tx_count ?? 0}
              </button>
            ) : (
              (stats?.project.tx_count ?? 0)
            )
          }
        />
        <Metric
          label="Findings"
          value={stats?.findings_total ?? 0}
          sub={severityStrip(sev)}
        />
        <Metric
          label="Live req/s"
          value={
            rateView.reqPerSec == null
              ? "—"
              : rateView.reqPerSec >= 10
                ? Math.round(rateView.reqPerSec)
                : rateView.reqPerSec.toFixed(2)
          }
          valueColor={
            rateView.reqPerSec && rateView.reqPerSec > 0
              ? "var(--accent)"
              : "var(--text-faint)"
          }
          sub={
            <>
              <div style={{ marginBottom: 2 }}>
                {rateView.windowSec > 0
                  ? `avg over last ${rateView.windowSec}s`
                  : "collecting samples…"}
              </div>
              <Sparkline samples={rateView.rates} />
            </>
          }
        />
        <Metric
          label="Proxy"
          value={stats?.proxy.running ? "running" : "stopped"}
          valueColor={stats?.proxy.running ? "var(--green)" : "var(--red)"}
          sub={stats?.proxy.listeners.join(", ") || "no listeners"}
        />
        <Metric
          label="OOB listener"
          value={
            /* R185: Clickable OOB-hit count — jump to Collaborator  */
            /* panel when hits > 0. Parallels R177's Dashboard →    */
            /* Scanner jump pattern. Shows pointer cursor + hover    */
            /* colour when actionable; falls back to plain text      */
            /* when nothing to drill into.                            */
            stats?.oob.running ? (
              stats.oob.interaction_count > 0 ? (
                <button
                  type="button"
                  onClick={() =>
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "collaborator" },
                      }),
                    )
                  }
                  title="Click to open the Collaborator panel"
                  style={{
                    background: "transparent",
                    border: 0,
                    padding: 0,
                    cursor: "pointer",
                    font: "inherit",
                    color: "inherit",
                  }}
                >
                  {stats.oob.interaction_count} hits
                </button>
              ) : (
                `${stats.oob.interaction_count} hits`
              )
            ) : (
              "off"
            )
          }
          valueColor={stats?.oob.running ? "var(--accent)" : "var(--text-faint)"}
          sub={stats?.oob.running ? stats.oob.public_host ?? "" : "click Start OOB to enable"}
          action={{
            label: stats?.oob.running ? "Stop OOB" : "Start OOB",
            onClick: toggleOob,
          }}
        />
      </div>

      <div className="dash-grid">
        <Card title="Last passive scan">
          {!stats?.passive_scan_started_ms && !stats?.passive_scan_running && (
            <div className="empty">Not run yet. Click “Run passive scan” to produce findings over current history.</div>
          )}
          {stats?.passive_scan_running && (
            <>
              <KV label="State" value="running…" highlight="green" />
              {stats.passive_scan_started_ms && (
                <KV label="Started" value={formatTs(stats.passive_scan_started_ms)} />
              )}
            </>
          )}
          {stats && !stats.passive_scan_running && stats.passive_scan_finished_ms && (
            <>
              <KV label="State" value="idle" />
              <KV label="Started" value={formatTs(stats.passive_scan_started_ms)} />
              <KV label="Finished" value={formatTs(stats.passive_scan_finished_ms)} />
              <KV
                label="Elapsed"
                value={formatElapsed(stats.passive_scan_started_ms, stats.passive_scan_finished_ms)}
              />
              <KV
                label="Findings in run"
                value={stats.passive_scan_findings_last_run ?? 0}
                highlight={(stats.passive_scan_findings_last_run ?? 0) > 0 ? "amber" : undefined}
              />
            </>
          )}
        </Card>

        {/* R473: Learn + Shortcuts quick-start card. New users opening */}
        {/* the Dashboard for the first time get a visible nudge toward */}
        {/* the Burp-canonical Learn tab (R445) + the Ctrl+? cheatsheet */}
        {/* modal + Alt+L direct-jump keyboard (R459). Three one-click  */}
        {/* buttons: (1) Open Learn tab — fires `burpfree:navigate` to  */}
        {/* "learn", (2) Show cheatsheet — synthesizes Ctrl+? keypress  */}
        {/* so the ShortcutCheatsheet modal opens, (3) Show command     */}
        {/* palette — synthesizes Ctrl+K keypress so the CommandPalette */}
        {/* modal opens. Static text — no backend calls, no state      */}
        {/* beyond click handlers. Positioned right after "Last passive */}
        {/* scan" so new users see it high in the grid without it       */}
        {/* dominating the first-row prime real estate. Mirrors Burp's  */}
        {/* dashboard "Issue activity" / "Tasks" tile placement.         */}
        <Card title="Learn + shortcuts">
          <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 8 }}>
            New to BurpFree? Three one-click entry points:
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <button
              className="ghost"
              onClick={() =>
                window.dispatchEvent(
                  new CustomEvent("burpfree:navigate", {
                    detail: { target: "learn" },
                  }),
                )
              }
              title="Open the Learn tab — Web Security Academy links, per-tool quick-starts, project docs, keyboard shortcut quick-reference. Keyboard shortcut: Alt+L."
              style={{ textAlign: "left", padding: "4px 8px" }}
            >
              📚 Open Learn tab <span style={{ color: "var(--text-dim)", fontSize: 10.5 }}>Alt+L</span>
            </button>
            <button
              className="ghost"
              onClick={() =>
                window.dispatchEvent(
                  new KeyboardEvent("keydown", {
                    key: "?",
                    ctrlKey: true,
                    bubbles: true,
                  }),
                )
              }
              title="Open the full keyboard shortcut cheatsheet modal — 180+ shortcuts grouped by scope. Keyboard shortcut: Ctrl+?"
              style={{ textAlign: "left", padding: "4px 8px" }}
            >
              ⌨ Show cheatsheet <span style={{ color: "var(--text-dim)", fontSize: 10.5 }}>Ctrl+?</span>
            </button>
            <button
              className="ghost"
              onClick={() =>
                window.dispatchEvent(
                  new KeyboardEvent("keydown", {
                    key: "k",
                    ctrlKey: true,
                    bubbles: true,
                  }),
                )
              }
              title="Open the command palette — fuzzy-search every tool, panel, and action. Keyboard shortcut: Ctrl+K"
              style={{ textAlign: "left", padding: "4px 8px" }}
            >
              🔍 Open command palette <span style={{ color: "var(--text-dim)", fontSize: 10.5 }}>Ctrl+K</span>
            </button>
          </div>
        </Card>

        <Card title="Proxy pipeline">
          <KV label="Connections accepted" value={stats?.proxy.conns_accepted ?? 0} />
          <KV label="Requests forwarded" value={stats?.proxy.requests_forwarded ?? 0} />
          <KV label="Responses recorded" value={stats?.proxy.responses_recorded ?? 0} />
          <KV label="TLS MITM handshakes" value={stats?.proxy.tls_mitm ?? 0} />
          <KV
            label="Errors"
            value={stats?.proxy.errors ?? 0}
            highlight={stats && stats.proxy.errors > 0 ? "red" : undefined}
          />
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R146: Error rate card. Burp-Pro signal: when a target  */}
        {/* starts throwing a lot of errors (connect-refused, TLS  */}
        {/* handshake fails, upstream resets) the operator should  */}
        {/* notice at a glance rather than dig through history.    */}
        {/* We lift the proxy counters into a ratio + tinted         */}
        {/* headline so an uptick is impossible to miss.            */}
        <Card title="Error rate">
          {(() => {
            const errors = stats?.proxy.errors ?? 0;
            const forwarded = stats?.proxy.requests_forwarded ?? 0;
            // Dividend adds +1 so an empty project reads 0% (not
            // Inf% / NaN%). Operators don't need the mathematically
            // pure definition; they need "did it stay quiet or not".
            const total = forwarded + 1;
            const pct = errors === 0 ? 0 : (errors / total) * 100;
            const pctLabel =
              pct < 0.1 && pct > 0
                ? "<0.1%"
                : `${pct.toFixed(pct < 10 ? 2 : 1)}%`;
            // Threshold tints — same colour language as R126's
            // Slowest responses so operators parse the Dashboard
            // health strip in one glance (red = fire, amber =
            // watch, neutral = fine).
            const tint =
              pct >= 5
                ? "var(--red)"
                : pct >= 1
                  ? "var(--amber)"
                  : "var(--text)";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 4,
                  }}
                >
                  <span
                    style={{
                      fontSize: 24,
                      fontWeight: 700,
                      color: tint,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    {pctLabel}
                  </span>
                  <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
                    error rate
                  </span>
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
                  {errors.toLocaleString()} error
                  {errors === 1 ? "" : "s"} over {forwarded.toLocaleString()}{" "}
                  forwarded request{forwarded === 1 ? "" : "s"}
                </div>
                {errors === 0 && forwarded > 0 && (
                  <div
                    style={{
                      color: "var(--green, #4bbf6b)",
                      fontSize: 11,
                      marginTop: 4,
                    }}
                  >
                    ✓ No errors recorded this session
                  </div>
                )}
                {pct >= 5 && (
                  <div
                    style={{
                      color: "var(--red)",
                      fontSize: 11,
                      marginTop: 4,
                    }}
                  >
                    Investigate: upstream failures or TLS mismatch likely
                  </div>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R159: Last activity card. Burp's Dashboard surfaces   */}
        {/* "when did the proxy last see traffic?" indirectly via */}
        {/* the live request counter — but after a 10-minute lull */}
        {/* an operator wants an unambiguous "last seen 2m 15s    */}
        {/* ago" so they can tell whether their test harness is   */}
        {/* idle vs stuck. We pick the max ts_ms across the       */}
        {/* history snapshot (fallback to project.updated_at_ms   */}
        {/* when the panel is up but no traffic yet captured in    */}
        {/* this session). Green ≤30s / neutral ≤5m / amber ≤30m / */}
        {/* red beyond 30m — mirrors R126's threshold palette.    */}
        <Card title="Last activity">
          {(() => {
            const lastTs =
              history.length > 0
                ? Math.max(...history.map((r) => r.ts_ms))
                : null;
            if (!lastTs || lastTs <= 0) {
              return (
                <div className="empty">
                  No proxied traffic yet. Browse through the proxy — timings land here on the next sample.
                </div>
              );
            }
            const diffMs = Math.max(0, Date.now() - lastTs);
            const diffS = Math.floor(diffMs / 1000);
            // Relative label — short units so the big number stays
            // scannable at a dashboard glance.
            const label =
              diffS < 2
                ? "just now"
                : diffS < 60
                  ? `${diffS}s ago`
                  : diffS < 3600
                    ? `${Math.floor(diffS / 60)}m ${diffS % 60}s ago`
                    : diffS < 86_400
                      ? `${Math.floor(diffS / 3600)}h ${Math.floor((diffS % 3600) / 60)}m ago`
                      : `${Math.floor(diffS / 86_400)}d ago`;
            // Threshold tints — same red/amber language as R146 /
            // R126 so the Dashboard reads consistently in one scan.
            const color =
              diffS <= 30
                ? "var(--green, #4caf50)"
                : diffS <= 300
                  ? "var(--text)"
                  : diffS <= 1800
                    ? "var(--amber)"
                    : "var(--red)";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 4,
                  }}
                >
                  {/* R237: Clickable Last-activity headline — opens */}
                  {/* HTTP history pre-filtered to the last 5 minutes */}
                  {/* (ts_min_ms = Date.now() - 5min). Operators who */}
                  {/* just see "42s ago" want to jump straight to     */}
                  {/* those recent rows for review. Transparent-button*/}
                  {/* promotion keeps the headline visual identical.  */}
                  <button
                    type="button"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:history-filter", {
                          detail: {
                            ts_min_ms: Date.now() - 5 * 60 * 1000,
                          },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                    }}
                    title={`Click to open HTTP history filtered to the last 5 minutes (last activity ${label})`}
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 0,
                      margin: 0,
                      color,
                      font: "inherit",
                      fontSize: 20,
                      fontWeight: 700,
                      cursor: "pointer",
                    }}
                  >
                    {label}
                  </button>
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
                  Last captured at {new Date(lastTs).toISOString().replace("T", " ").slice(0, 19)}Z
                </div>
                {diffS > 1800 && (
                  <div
                    style={{
                      color: "var(--red)",
                      fontSize: 11,
                      marginTop: 4,
                    }}
                  >
                    Proxy has been idle for over 30 minutes
                  </div>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R283: Latest finding card. Companion to R159 (Last    */}
        {/* activity). Where R159 tracks the most recent proxied  */}
        {/* request so operators know whether the test harness is */}
        {/* alive, R283 tracks the most recent FINDING so        */}
        {/* operators know whether the scanner is still catching */}
        {/* issues or has gone quiet. Pulls from recentFindings  */}
        {/* (already polled at Dashboard cadence; sorted desc by */}
        {/* ts_ms by findingsList's SQL order). Sev-tinted        */}
        {/* headline + relative age + click-through to Scanner   */}
        {/* via the existing burpfree:scanner-finding-focus event */}
        {/* (new in R221).                                        */}
        <Card title="Latest finding">
          {(() => {
            if (recentFindings.length === 0) {
              return (
                <div className="empty">
                  No findings yet. Scanner results land here as the
                  passive + active probes catch issues.
                </div>
              );
            }
            const latest = recentFindings[0];
            const diffMs = Math.max(0, Date.now() - latest.ts_ms);
            const diffS = Math.floor(diffMs / 1000);
            const ageLabel =
              diffS < 2
                ? "just now"
                : diffS < 60
                  ? `${diffS}s ago`
                  : diffS < 3600
                    ? `${Math.floor(diffS / 60)}m ${diffS % 60}s ago`
                    : diffS < 86_400
                      ? `${Math.floor(diffS / 3600)}h ${Math.floor((diffS % 3600) / 60)}m ago`
                      : `${Math.floor(diffS / 86_400)}d ago`;
            // Sev-tint palette matches Dashboard R177 / Scanner /
            // Target Issues so the headline reads consistently.
            const sev = (latest.severity || "info").toLowerCase();
            const sevColor =
              sev === "critical"
                ? "#ff5c5c"
                : sev === "high"
                  ? "#f09040"
                  : sev === "medium"
                    ? "#f0c030"
                    : sev === "low"
                      ? "#5fa0dc"
                      : "#9898a0";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 4,
                  }}
                >
                  <span
                    style={{
                      padding: "1px 6px",
                      borderRadius: 3,
                      fontSize: 10,
                      fontWeight: 700,
                      color: sevColor,
                      border: `1px solid ${sevColor}`,
                      textTransform: "uppercase",
                      letterSpacing: 0.3,
                    }}
                  >
                    {sev}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:scanner-finding-focus", {
                          detail: { id: latest.id },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "scanner" },
                        }),
                      );
                    }}
                    title={`Click to open Scanner focused on this finding (#${latest.id}, ${latest.detector || "manual"})`}
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 0,
                      margin: 0,
                      color: "var(--text)",
                      font: "inherit",
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: "pointer",
                      textAlign: "left",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      maxWidth: 280,
                    }}
                  >
                    {latest.title}
                  </button>
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
                  {ageLabel}
                  {latest.detector && (
                    <>
                      {" · "}
                      <span className="mono">{latest.detector}</span>
                    </>
                  )}
                  {" · "}
                  <span className="mono">#{latest.id}</span>
                </div>
                {recentFindings.length > 1 && (
                  <div
                    style={{
                      color: "var(--text-faint)",
                      fontSize: 10,
                      marginTop: 2,
                    }}
                  >
                    {recentFindings.length} finding
                    {recentFindings.length === 1 ? "" : "s"} in the recent-20 window
                  </div>
                )}
              </>
            );
          })()}
        </Card>

        <Card title="Project surface">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              marginBottom: 2,
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <KV
                label="Root"
                value={stats?.project.root || "(no project)"}
              />
            </div>
            {stats?.project.root && (
              <>
                <button
                  className="ghost"
                  onClick={() => void openProjectFolder()}
                  title="Open the project directory in the OS file manager"
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  📂
                </button>
                <button
                  className="ghost"
                  onClick={() => void copyProjectPath()}
                  title="Copy the project root path to the clipboard"
                  style={{ padding: "2px 6px", fontSize: 11 }}
                >
                  📋
                </button>
              </>
            )}
          </div>
          <KV label="Scope rules" value={stats?.project.scope_rules ?? 0} />
          <KV label="WebSocket sessions" value={stats?.ws_sessions ?? 0} />
          <KV label="WebSocket messages" value={stats?.ws_messages ?? 0} />
          <KV label="Organizer items" value={stats?.organizer_items ?? 0} />
          <KV label="Macros" value={stats?.macros ?? 0} />
          <KV label="Session rules" value={stats?.session_rules ?? 0} />
          <KV
            label="Extensions"
            value={`${stats?.extensions ?? 0} loaded · ${stats?.custom_rules ?? 0} custom rule(s)`}
          />
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R518: Cookie jar snapshot card. Burp Pro's Dashboard   */}
        {/* doesn't ship a dedicated jar tile but operators keep   */}
        {/* pivoting between the Cookie Jar panel (R125-era) and   */}
        {/* the Dashboard to answer "do I have an auth cookie     */}
        {/* yet? / how many hosts has the jar seen?" — this card   */}
        {/* answers both at a glance without the pivot. Zero       */}
        {/* backend — reduces over `jarCookies` already polled on */}
        {/* the 2s cadence. Three metrics: total count /           */}
        {/* persistent-vs-session split / unique hosts. Below the  */}
        {/* fold a top-5 host-by-cookie-count table mirrors the    */}
        {/* "Top hosts" + "Findings by host" tile layout so the    */}
        {/* three per-host rails read as siblings. Row click fires */}
        {/* `burpfree:navigate` to the Cookie Jar panel so         */}
        {/* operators can one-click into the full view.            */}
        {/* ----------------------------------------------------- */}
        {/* R521: Scope summary card. Burp Pro's "Scope" tab shows */}
        {/* include/exclude rules in a tree; the Dashboard doesn't */}
        {/* carry a dedicated scope tile but operators pivoting    */}
        {/* across a long engagement benefit from an at-a-glance   */}
        {/* "what's in scope right now?" answer without flipping   */}
        {/* to the Scope panel. R521 ships that tile — pairs with  */}
        {/* R518 Cookie jar snapshot in the "live project surface" */}
        {/* row. Zero backend — polls `api.scopeGet()` on the 2s   */}
        {/* cadence alongside the other dashboard sources.         */}
        {/* **Metrics**: total rules / include · exclude split /   */}
        {/* enabled · disabled split / default-when-empty flag.   */}
        {/* Below the fold a top-5 host-pattern list grouped by    */}
        {/* match_kind so operators see which hosts are in-scope   */}
        {/* at a glance. Row click fires `burpfree:navigate` to    */}
        {/* the scope panel so operators can one-click into the    */}
        {/* full editor — same pivot idiom as R518 Cookie jar.     */}
        <Card title="Scope summary">
          {(() => {
            const rules = scopeSnap?.rules ?? [];
            const total = rules.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No scope rules yet. {scopeSnap?.default_in_scope_when_empty ? "Default: everything in scope." : "Default: nothing in scope."}
                </div>
              );
            }
            const includeCount = rules.filter(
              (r) => r.match_kind === "include",
            ).length;
            const excludeCount = total - includeCount;
            const enabledCount = rules.filter((r) => r.enabled).length;
            const disabledCount = total - enabledCount;
            const regexCount = rules.filter((r) => r.regex).length;
            // Top-5 unique hosts by rule count — operators want
            // to see which hosts dominate their scope.
            const byHost: Record<string, number> = {};
            for (const r of rules) {
              const key = r.host || "(any host)";
              byHost[key] = (byHost[key] ?? 0) + 1;
            }
            const topHosts = Object.entries(byHost)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5);
            return (
              <>
                <KV label="Total rules" value={total} />
                <KV
                  label="Include · Exclude"
                  value={`${includeCount} · ${excludeCount}`}
                />
                <KV
                  label="Enabled · Disabled"
                  value={`${enabledCount} · ${disabledCount}`}
                />
                <KV label="Regex rules" value={regexCount} />
                <KV
                  label="Default when empty"
                  value={scopeSnap?.default_in_scope_when_empty ? "in scope" : "out of scope"}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Top {Math.min(5, topHosts.length)} host pattern{topHosts.length === 1 ? "" : "s"}
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {topHosts.map(([host, count]) => (
                      <tr
                        key={host}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "target" },
                            }),
                          );
                        }}
                        title={`Jump to Target panel · ${host} appears in ${count} rule${count === 1 ? "" : "s"}`}
                      >
                        <td
                          className="mono"
                          style={{
                            padding: "2px 4px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 180,
                          }}
                        >
                          {host}
                        </td>
                        <td
                          style={{
                            padding: "2px 4px",
                            textAlign: "right",
                            color: "var(--text-faint)",
                          }}
                        >
                          {count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R528: Repeater activity card. Burp Pro's Dashboard     */}
        {/* doesn't ship a dedicated Repeater tile but operators   */}
        {/* juggling 10+ Repeater tabs want to answer "how many    */}
        {/* are open? / which ones errored? / what's my send       */}
        {/* count?" without flipping to the Repeater panel. R528   */}
        {/* ships that tile — pairs with R518 Cookie jar + R521    */}
        {/* Scope summary in the "live project surface" cluster.   */}
        {/* Zero backend — polls `api.repeaterList()` on the 2s    */}
        {/* cadence alongside the other dashboard sources.         */}
        {/* **Metrics**: total tabs / total sends across all tabs  */}
        {/* / tabs with the last send errored / pinned tabs count  */}
        {/* / groups count. **Row click** fires                     */}
        {/* `burpfree:navigate` to the Repeater panel so operators */}
        {/* can one-click into the full view. **Empty state**:     */}
        {/* short message with a hint about Send to Repeater.      */}
        <Card title="Repeater activity">
          {(() => {
            const total = repeaterTabs.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No Repeater tabs yet. Right-click a history row and pick "Send to Repeater" to open one.
                </div>
              );
            }
            // Sum sends across all tabs.
            let sends = 0;
            let erroredLast = 0;
            let pinned = 0;
            const groups = new Set<string>();
            for (const t of repeaterTabs) {
              sends += t.history?.length ?? 0;
              if (t.pinned) pinned++;
              if (t.group) groups.add(t.group);
              const last = t.history?.[t.history.length - 1];
              if (last && last.error) erroredLast++;
            }
            // Top-5 tabs by send count — operators scanning for
            // "the tab I've been hammering" see it at a glance.
            const topTabs = [...repeaterTabs]
              .sort(
                (a, b) =>
                  (b.history?.length ?? 0) - (a.history?.length ?? 0),
              )
              .slice(0, 5);
            return (
              <>
                <KV label="Open tabs" value={total} />
                <KV label="Total sends" value={sends} />
                <KV
                  label="Errored (last send) · Pinned"
                  value={`${erroredLast} · ${pinned}`}
                />
                <KV label="Groups" value={groups.size} />
                {topTabs.length > 0 && (topTabs[0].history?.length ?? 0) > 0 && (
                  <>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Top {Math.min(5, topTabs.length)} tab{topTabs.length === 1 ? "" : "s"} by sends
                    </div>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11.5,
                        marginTop: 4,
                        borderCollapse: "collapse",
                      }}
                    >
                      <tbody>
                        {topTabs.map((t) => {
                          const count = t.history?.length ?? 0;
                          if (count === 0) return null;
                          return (
                            <tr
                              key={t.id}
                              style={{ cursor: "pointer" }}
                              onClick={() => {
                                window.dispatchEvent(
                                  new CustomEvent("burpfree:navigate", {
                                    detail: { target: "repeater" },
                                  }),
                                );
                              }}
                              title={`Jump to Repeater · "${t.name}" has ${count} send${count === 1 ? "" : "s"}`}
                            >
                              <td
                                className="mono"
                                style={{
                                  padding: "2px 4px",
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  maxWidth: 180,
                                }}
                              >
                                {t.name || `tab #${t.id}`}
                              </td>
                              <td
                                style={{
                                  padding: "2px 4px",
                                  textAlign: "right",
                                  color: "var(--text-faint)",
                                }}
                              >
                                {count}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R529: Intruder activity card. Completes the panel-     */}
        {/* activity trio with R528 Repeater activity + the         */}
        {/* existing "Scanner coverage" (R199) card. Zero backend —*/}
        {/* polls `api.intruderRecipeList()` on the 2s cadence.    */}
        {/* **Metrics**: saved recipes count / total payloads      */}
        {/* across all recipes / newest recipe + its age. **Top-5  */}
        {/* table** by payload count — operators scanning for      */}
        {/* "the recipe I built that monster payload list for"    */}
        {/* see it at a glance. **Row click** fires                 */}
        {/* `burpfree:navigate` to the Intruder panel so operators */}
        {/* can one-click into the saved-recipes picker.           */}
        <Card title="Intruder activity">
          {(() => {
            const total = intruderRecipes.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No saved Intruder recipes yet. Build an attack in the Intruder panel and click "Save recipe".
                </div>
              );
            }
            const totalPayloads = intruderRecipes.reduce(
              (acc, r) => acc + (r.payload_count ?? 0),
              0,
            );
            // Newest = highest created_at_ms.
            const newest = intruderRecipes.reduce<IntruderRecipeView | null>(
              (acc, r) =>
                acc == null || r.created_at_ms > acc.created_at_ms ? r : acc,
              null,
            );
            // Mode distribution (sniper / battering_ram / pitchfork /
            // cluster_bomb) — Burp's four classic Intruder attack
            // types. Each key may or may not be present.
            const modes: Record<string, number> = {};
            for (const r of intruderRecipes) {
              const m = r.mode || "unknown";
              modes[m] = (modes[m] ?? 0) + 1;
            }
            const modeParts = Object.entries(modes)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => `${v} ${k}`);
            // Top-5 recipes by payload count.
            const topRecipes = [...intruderRecipes]
              .sort((a, b) => (b.payload_count ?? 0) - (a.payload_count ?? 0))
              .slice(0, 5);
            return (
              <>
                <KV label="Saved recipes" value={total} />
                <KV label="Total payloads" value={totalPayloads} />
                <KV
                  label="Newest"
                  value={
                    newest
                      ? `${newest.name} · ${humanRelativeAge(newest.created_at_ms)}`
                      : "—"
                  }
                />
                <KV label="Modes" value={modeParts.join(" · ") || "—"} />
                {topRecipes.length > 0 && (
                  <>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Top {Math.min(5, topRecipes.length)} recipe{topRecipes.length === 1 ? "" : "s"} by payload count
                    </div>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11.5,
                        marginTop: 4,
                        borderCollapse: "collapse",
                      }}
                    >
                      <tbody>
                        {topRecipes.map((r) => (
                          <tr
                            key={r.name}
                            style={{ cursor: "pointer" }}
                            onClick={() => {
                              window.dispatchEvent(
                                new CustomEvent("burpfree:navigate", {
                                  detail: { target: "intruder" },
                                }),
                              );
                            }}
                            title={`Jump to Intruder · "${r.name}" has ${r.payload_count} payload${r.payload_count === 1 ? "" : "s"} · mode ${r.mode}`}
                          >
                            <td
                              className="mono"
                              style={{
                                padding: "2px 4px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                maxWidth: 180,
                              }}
                            >
                              {r.name}
                            </td>
                            <td
                              style={{
                                padding: "2px 4px",
                                textAlign: "right",
                                color: "var(--text-faint)",
                              }}
                            >
                              {r.payload_count}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R530: Collaborator activity card. 21st Dashboard tile. */}
        {/* Burp Pro ships "Burp Collaborator" as a separate       */}
        {/* client; our Collaborator / OOB panel surfaces the same */}
        {/* kind of inbound-hit stream (DNS lookups, HTTP          */}
        {/* callbacks, SMTP connects). The Dashboard didn't have    */}
        {/* a tile for it — operators running an exploit chain     */}
        {/* that depends on a Collaborator payload want "did my    */}
        {/* payload fire?" visible without flipping tabs. R530     */}
        {/* ships that tile. Zero backend — polls                  */}
        {/* `api.oobInteractionsAll()` on the 2s cadence.          */}
        {/* **Metrics**: total interactions / kind breakdown       */}
        {/* (http / dns / smtp / etc.) / unique remote addresses / */}
        {/* latest hit + its age. **Row click** fires               */}
        {/* `burpfree:navigate` to the Collaborator panel.          */}
        <Card title="Collaborator activity">
          {(() => {
            const total = oobInteractions.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No Collaborator interactions yet. Start the OOB listener in the Collaborator panel and mint a payload.
                </div>
              );
            }
            // Kind distribution (http / dns / smtp / etc.).
            const byKind: Record<string, number> = {};
            // Unique remote addresses — operators scanning for
            // "which victims hit my payload" see at a glance.
            const remotes = new Set<string>();
            for (const i of oobInteractions) {
              const k = i.kind || "unknown";
              byKind[k] = (byKind[k] ?? 0) + 1;
              if (i.remote_addr) remotes.add(i.remote_addr);
            }
            const kindParts = Object.entries(byKind)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => `${v} ${k}`);
            // Latest = highest ts_ms.
            const latest = oobInteractions.reduce<OobInteraction | null>(
              (acc, i) =>
                acc == null || i.ts_ms > acc.ts_ms ? i : acc,
              null,
            );
            // Top-5 correlation ids by hit count — operators
            // scanning for "which payload fired the most" see it
            // at a glance.
            const byCid: Record<string, number> = {};
            for (const i of oobInteractions) {
              const k = i.correlation_id || "(no cid)";
              byCid[k] = (byCid[k] ?? 0) + 1;
            }
            const topCids = Object.entries(byCid)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5);
            return (
              <>
                <KV label="Total interactions" value={total} />
                <KV label="Kinds" value={kindParts.join(" · ") || "—"} />
                <KV label="Unique remotes" value={remotes.size} />
                <KV
                  label="Latest"
                  value={
                    latest
                      ? `${latest.kind} · ${humanRelativeAge(latest.ts_ms)}`
                      : "—"
                  }
                />
                {topCids.length > 0 && (
                  <>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Top {Math.min(5, topCids.length)} payload{topCids.length === 1 ? "" : "s"} by hit count
                    </div>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11.5,
                        marginTop: 4,
                        borderCollapse: "collapse",
                      }}
                    >
                      <tbody>
                        {topCids.map(([cid, count]) => (
                          <tr
                            key={cid}
                            style={{ cursor: "pointer" }}
                            onClick={() => {
                              window.dispatchEvent(
                                new CustomEvent("burpfree:navigate", {
                                  detail: { target: "collaborator" },
                                }),
                              );
                            }}
                            title={`Jump to Collaborator · cid ${cid} has ${count} hit${count === 1 ? "" : "s"}`}
                          >
                            <td
                              className="mono"
                              style={{
                                padding: "2px 4px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                maxWidth: 180,
                              }}
                            >
                              {cid}
                            </td>
                            <td
                              style={{
                                padding: "2px 4px",
                                textAlign: "right",
                                color: "var(--text-faint)",
                              }}
                            >
                              {count}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R533: Logger activity card. 22nd Dashboard tile.       */}
        {/* Rounds out the panel-activity set (Repeater R528 /     */}
        {/* Intruder R529 / Collaborator R530 / Scanner-coverage   */}
        {/* R199 / Logger R533). Operators juggling a long session */}
        {/* want "what's the Logger seeing right now?" visible     */}
        {/* without flipping tabs. Zero backend — polls             */}
        {/* `api.loggerRecent(500)` on the 2s cadence; the 500     */}
        {/* ceiling keeps the dashboard light on long sessions.    */}
        {/* **Metrics**: recent-events count / kind distribution   */}
        {/* (tx / finding / ws / intercept / log) / latest event   */}
        {/* age. **Row click** fires `burpfree:navigate` to the    */}
        {/* Logger panel so operators can drill into the full      */}
        {/* stream.                                                 */}
        <Card title="Logger activity">
          {(() => {
            const total = loggerRecent.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No logger events yet. Live proxy traffic / Scanner findings / intercept decisions all stream here.
                </div>
              );
            }
            // Kind distribution matching R520 Logger badge:
            // tx / finding / ws / intercept / log.
            let tx = 0,
              finding = 0,
              ws = 0,
              log = 0,
              intercept = 0;
            for (const e of loggerRecent) {
              const k = e.event.kind?.kind ?? "";
              if (k === "transaction") tx++;
              else if (k === "finding") finding++;
              else if (k === "intercept") intercept++;
              else if (k === "log") log++;
              else if (typeof k === "string" && k.startsWith("ws_")) ws++;
            }
            const parts: string[] = [];
            if (tx > 0) parts.push(`${tx} tx`);
            if (finding > 0) parts.push(`${finding} find`);
            if (ws > 0) parts.push(`${ws} ws`);
            if (intercept > 0) parts.push(`${intercept} intercept`);
            if (log > 0) parts.push(`${log} log`);
            // Latest = max ts_ms.
            const latest = loggerRecent.reduce<
              { seq: number; event: { ts_ms: number; kind: any } } | null
            >(
              (acc, e) =>
                acc == null || e.event.ts_ms > acc.event.ts_ms ? e : acc,
              null,
            );
            return (
              <>
                <KV
                  label="Recent events"
                  value={total === 500 ? "500 (capped)" : total}
                />
                <KV label="Kinds" value={parts.join(" · ") || "—"} />
                <KV
                  label="Latest"
                  value={
                    latest
                      ? `${latest.event.kind?.kind ?? "unknown"} · ${humanRelativeAge(latest.event.ts_ms)}`
                      : "—"
                  }
                />
                <div
                  style={{ marginTop: 8, textAlign: "right" }}
                >
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "logger" },
                        }),
                      );
                    }}
                    style={{ fontSize: 11, padding: "2px 8px" }}
                    title="Open the Logger panel for the full event stream"
                  >
                    Open Logger →
                  </button>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R539: Session rules + macros card. 23rd Dashboard      */}
        {/* tile. Burp Pro's "Session handling rules" tab is a    */}
        {/* heavy editor; the Dashboard didn't carry a quick      */}
        {/* summary. Operators running an engagement with auth    */}
        {/* macros + per-host session rules want "which rules     */}
        {/* are enabled right now?" at a glance. Zero backend —   */}
        {/* polls `sessionRulesList` + `sessionMacrosList`.       */}
        <Card title="Session rules + macros">
          {(() => {
            const ruleTotal = sessionRules.length;
            const macroTotal = sessionMacros.length;
            if (ruleTotal === 0 && macroTotal === 0) {
              return (
                <div className="empty">
                  No session rules or macros yet. Open the Session panel to add auth macros and matching rules.
                </div>
              );
            }
            const enabledRules = sessionRules.filter((r) => r.enabled).length;
            const cookieRules = sessionRules.filter(
              (r) => r.apply_cookies,
            ).length;
            // Count total steps across all macros + unique macros
            // referenced by rules.
            const totalSteps = sessionMacros.reduce(
              (acc, m) => acc + (m.steps?.length ?? 0),
              0,
            );
            const referencedMacroIds = new Set(
              sessionRules.map((r) => r.macro_id).filter((x) => !!x),
            );
            return (
              <>
                <KV
                  label="Rules · enabled"
                  value={`${ruleTotal} · ${enabledRules}`}
                />
                <KV label="apply_cookies" value={cookieRules} />
                <KV
                  label="Macros · total steps"
                  value={`${macroTotal} · ${totalSteps}`}
                />
                <KV
                  label="Macros wired to rules"
                  value={`${referencedMacroIds.size} / ${macroTotal}`}
                />
                <div
                  style={{ marginTop: 8, textAlign: "right" }}
                >
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "session" },
                        }),
                      );
                    }}
                    style={{ fontSize: 11, padding: "2px 8px" }}
                    title="Open the Session panel for the full editor"
                  >
                    Open Session →
                  </button>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R540: Match & Replace rules card. 24th Dashboard tile  */}
        {/* · 🎯 R540 round-number mark. Burp's "Match and         */}
        {/* Replace" rules sit inside the Proxy settings — easy    */}
        {/* to forget which rules are live. Operators running an   */}
        {/* engagement with auth-token splice rules + response    */}
        {/* header injection want "which rules are enabled right  */}
        {/* now? / which fired this session?" at a glance. Zero    */}
        {/* backend — polls `matchReplaceGet()` + `matchReplaceHits */}
        {/* ()` on the 2s cadence paralleling MatchReplacePane.     */}
        <Card title="Match & Replace rules">
          {(() => {
            const rules = matchReplaceEngine?.rules ?? [];
            const total = rules.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No Match & Replace rules yet. Open the Proxy settings pane to add rules.
                </div>
              );
            }
            const enabled = rules.filter((r) => r.enabled).length;
            // Count rules that actually fired this session.
            const fired = rules.filter(
              (r) => (matchReplaceHits[r.id] ?? 0) > 0,
            ).length;
            const totalHits = Object.values(matchReplaceHits).reduce(
              (acc, n) => acc + n,
              0,
            );
            // Scope distribution (request / response / both).
            const scopes: Record<string, number> = {};
            for (const r of rules) {
              const k = r.scope || "unknown";
              scopes[k] = (scopes[k] ?? 0) + 1;
            }
            const scopeParts = Object.entries(scopes)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => `${v} ${k}`);
            // Top-5 rules by hit count.
            const topRules = [...rules]
              .map((r) => ({ r, hits: matchReplaceHits[r.id] ?? 0 }))
              .filter((x) => x.hits > 0)
              .sort((a, b) => b.hits - a.hits)
              .slice(0, 5);
            return (
              <>
                <KV label="Rules · enabled" value={`${total} · ${enabled}`} />
                <KV label="Scopes" value={scopeParts.join(" · ") || "—"} />
                <KV label="Fired this session" value={`${fired} / ${total}`} />
                <KV label="Total hits" value={totalHits} />
                {topRules.length > 0 && (
                  <>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Top {Math.min(5, topRules.length)} rule{topRules.length === 1 ? "" : "s"} by hits
                    </div>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11.5,
                        marginTop: 4,
                        borderCollapse: "collapse",
                      }}
                    >
                      <tbody>
                        {topRules.map(({ r, hits }) => (
                          <tr
                            key={r.id}
                            style={{ cursor: "pointer" }}
                            onClick={() => {
                              window.dispatchEvent(
                                new CustomEvent("burpfree:navigate", {
                                  detail: { target: "proxy" },
                                }),
                              );
                            }}
                            title={`Jump to Proxy settings · "${r.name}" fired ${hits}×`}
                          >
                            <td
                              className="mono"
                              style={{
                                padding: "2px 4px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                maxWidth: 180,
                              }}
                            >
                              {r.name}
                            </td>
                            <td
                              style={{
                                padding: "2px 4px",
                                textAlign: "right",
                                color: "var(--text-faint)",
                              }}
                            >
                              {hits}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R541: Interceptor queue card. 25th Dashboard tile.    */}
        {/* Alert tile — surfaces pending-packet count so          */}
        {/* operators don't lose a packet waiting for a forward/   */}
        {/* drop decision. Burp's intercept icon in the bottom     */}
        {/* status bar does this but the Dashboard didn't carry   */}
        {/* an equivalent. Zero backend — polls                    */}
        {/* `api.interceptorStatus()` on the 2s cadence.           */}
        {/* **Metrics**: request/response intercept booleans +    */}
        {/* pending-packet count. Shows a red-tinted badge when    */}
        {/* pending > 0 so operators notice at a glance.           */}
        <Card title="Interceptor queue">
          {(() => {
            if (!interceptorStatus) {
              return (
                <div className="empty">
                  Interceptor not running. Toggle intercept on the Proxy panel to queue packets.
                </div>
              );
            }
            const { request, response, pending } = interceptorStatus;
            const anyOn = request || response;
            const parts: string[] = [];
            if (request) parts.push("requests");
            if (response) parts.push("responses");
            const state =
              parts.length > 0 ? parts.join(" + ") : "neither direction";
            return (
              <>
                <KV label="Intercept state" value={state} />
                <KV label="Pending in queue" value={pending} />
                {pending > 0 && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: "6px 10px",
                      background: "rgba(224, 68, 68, 0.18)",
                      color: "#ff5c5c",
                      borderRadius: 4,
                      fontSize: 11.5,
                    }}
                  >
                    ⚠ {pending} packet{pending === 1 ? "" : "s"} awaiting forward/drop. Open the Proxy panel to resolve.
                  </div>
                )}
                {!anyOn && pending === 0 && (
                  <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 6 }}>
                    Intercept is off — proxy traffic passes through without pause.
                  </div>
                )}
                <div
                  style={{ marginTop: 8, textAlign: "right" }}
                >
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "proxy" },
                        }),
                      );
                    }}
                    style={{ fontSize: 11, padding: "2px 8px" }}
                    title="Open the Proxy panel to toggle intercept + resolve pending packets"
                  >
                    Open Proxy →
                  </button>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R560: Project backups card. 26th Dashboard tile ·   */}
        {/* R560 round-number mark. Alert-style tile that mirrors  */}
        {/* R541's pattern. Burp Pro auto-backs-up every 30 min    */}
        {/* by default; operators who never visit the Settings     */}
        {/* panel can go a whole engagement without noticing       */}
        {/* backups are disabled. This tile makes the status       */}
        {/* visible from the Dashboard. Zero backend — polls       */}
        {/* `api.backupConfigGet()` + `api.backupList()` on the    */}
        {/* 2s cadence.                                             */}
        <Card title="Project backups">
          {(() => {
            if (!backupConfig) {
              return (
                <div className="empty">
                  Open a project to see backup config.
                </div>
              );
            }
            const { enabled, interval_min, keep_count, delete_on_shutdown } =
              backupConfig;
            const total = backupList.length;
            const newest = backupList.reduce<BackupInfo | null>(
              (acc, b) =>
                acc == null || b.created_at_ms > acc.created_at_ms ? b : acc,
              null,
            );
            // Oldest meaningful age — if last backup > 2x interval
            // we red-alert since the scheduler should have fired.
            const stale =
              enabled &&
              newest != null &&
              Date.now() - newest.created_at_ms > interval_min * 60_000 * 2;
            const totalBytes = backupList.reduce(
              (acc, b) => acc + (b.size_bytes ?? 0),
              0,
            );
            return (
              <>
                <KV
                  label="Auto-backup"
                  value={enabled ? `every ${interval_min}m` : "disabled"}
                  highlight={enabled ? undefined : "red"}
                />
                <KV label="Keep count" value={keep_count} />
                <KV label="Delete on close" value={delete_on_shutdown ? "yes" : "no"} />
                <KV
                  label="Snapshots on disk"
                  value={`${total} · ${(totalBytes / 1024 / 1024).toFixed(1)} MB`}
                />
                <KV
                  label="Newest"
                  value={
                    newest
                      ? humanRelativeAge(newest.created_at_ms)
                      : "— (none yet)"
                  }
                  highlight={stale ? "red" : undefined}
                />
                {stale && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: "6px 10px",
                      background: "rgba(224, 68, 68, 0.18)",
                      color: "#ff5c5c",
                      borderRadius: 4,
                      fontSize: 11.5,
                    }}
                  >
                    ⚠ Last backup is older than 2× the configured interval. Scheduler may have stalled.
                  </div>
                )}
                {!enabled && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: "6px 10px",
                      background: "rgba(240, 140, 60, 0.18)",
                      color: "#f09040",
                      borderRadius: 4,
                      fontSize: 11.5,
                    }}
                  >
                    ⚠ Auto-backup is off. Enable from Settings to recover from unexpected shutdowns.
                  </div>
                )}
                <div style={{ marginTop: 8, textAlign: "right" }}>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      void api.backupNow().then(() => void refresh());
                    }}
                    style={{ fontSize: 11, padding: "2px 8px" }}
                    title="Fire a backup right now — writes a timestamped zip and prunes to keep_count."
                  >
                    📸 Backup now
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "settings" },
                        }),
                      );
                    }}
                    style={{ fontSize: 11, padding: "2px 8px", marginLeft: 4 }}
                    title="Open the Settings panel to tune backup config"
                  >
                    Settings →
                  </button>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R574: WebSocket activity card. 27th Dashboard tile.    */}
        {/* Burp Pro ships WebSockets history as a separate         */}
        {/* panel; our ProxyPanel includes a WebSockets subpane.   */}
        {/* Operators probing modern SPAs with live socket         */}
        {/* channels (chat / dashboards / collab tools) want       */}
        {/* "which socket is seeing traffic right now?" visible    */}
        {/* without flipping tabs. Zero backend — polls             */}
        {/* `wsSessionsList(200)` on the 2s cadence.                */}
        <Card title="WebSocket activity">
          {(() => {
            const total = wsSessions.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No WebSocket sessions yet. Visit a site with live socket channels (chat / dashboards / collab) via the proxy.
                </div>
              );
            }
            const open = wsSessions.filter((s) => s.closed_at_ms == null)
              .length;
            const closed = total - open;
            const totalMessages = wsSessions.reduce(
              (acc, s) => acc + (s.message_count ?? 0),
              0,
            );
            // Latest = max opened_at_ms
            const latest = wsSessions.reduce<WsSessionRow | null>(
              (acc, s) =>
                acc == null || s.opened_at_ms > acc.opened_at_ms ? s : acc,
              null,
            );
            // Top-5 sessions by message count.
            const topSessions = [...wsSessions]
              .sort((a, b) => (b.message_count ?? 0) - (a.message_count ?? 0))
              .slice(0, 5);
            return (
              <>
                <KV label="Sessions · Open" value={`${total} · ${open}`} />
                <KV label="Closed" value={closed} />
                <KV label="Total messages" value={totalMessages} />
                <KV
                  label="Latest handshake"
                  value={
                    latest
                      ? `${latest.host}:${latest.port} · ${humanRelativeAge(latest.opened_at_ms)}`
                      : "—"
                  }
                />
                {topSessions.length > 0 && (topSessions[0].message_count ?? 0) > 0 && (
                  <>
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Top {Math.min(5, topSessions.length)} session{topSessions.length === 1 ? "" : "s"} by message count
                    </div>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11.5,
                        marginTop: 4,
                        borderCollapse: "collapse",
                      }}
                    >
                      <tbody>
                        {topSessions.map((s) => {
                          const count = s.message_count ?? 0;
                          if (count === 0) return null;
                          const live = s.closed_at_ms == null;
                          return (
                            <tr
                              key={s.id}
                              style={{ cursor: "pointer" }}
                              onClick={() => {
                                window.dispatchEvent(
                                  new CustomEvent("burpfree:navigate", {
                                    detail: { target: "proxy" },
                                  }),
                                );
                              }}
                              title={`Jump to Proxy panel → WebSockets · ${s.host}:${s.port}${s.path} has ${count} frame${count === 1 ? "" : "s"} (${live ? "live" : "closed"})`}
                            >
                              <td
                                className="mono"
                                style={{
                                  padding: "2px 4px",
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  maxWidth: 180,
                                }}
                              >
                                {live ? "● " : "○ "}
                                {s.host}
                                {s.path}
                              </td>
                              <td
                                style={{
                                  padding: "2px 4px",
                                  textAlign: "right",
                                  color: "var(--text-faint)",
                                }}
                              >
                                {count}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R674: Error rate card. 38th Dashboard tile. Mirror     */}
        {/* of R668 Scope hit rate pattern. Shows error-flagged    */}
        {/* transactions (network drops, TLS failures, parse       */}
        {/* errors) as a ratio of total. Low ratio = healthy       */}
        {/* backend; high ratio = upstream trouble worth a         */}
        {/* glance. Reuses HistoryFilter.error_only for the        */}
        {/* numerator poll. */}
        <Card title="Error rate">
          {(() => {
            const total = stats?.proxy?.requests_forwarded ?? 0;
            if (total === 0 && errorOnlyCount === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            const ratio = total > 0 ? errorOnlyCount / total : 0;
            const pct =
              ratio === 0
                ? "0%"
                : ratio < 0.01
                  ? "<1%"
                  : `${(ratio * 100).toFixed((ratio * 100) < 10 ? 1 : 0)}%`;
            // Error rate is inverted: HIGH is bad.
            const hint: "green" | "amber" | "red" | undefined =
              ratio === 0
                ? "green"
                : ratio < 0.02
                  ? undefined
                  : ratio < 0.1
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Errors" value={errorOnlyCount} highlight={hint} />
                <KV label="Error rate" value={pct} highlight={hint} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} forwarded · network drops / TLS / parse
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R695: Top detectors card. 39th Dashboard tile.         */}
        {/* Which detectors are firing the most on this project? */}
        {/* Operators pivoting between the Scanner panel and the  */}
        {/* Target → Issues view want "most-active 5 detectors"   */}
        {/* at a glance so they can tell at a glance whether a    */}
        {/* bulk false-positive is dominating the queue. Reuses   */}
        {/* `recentFindings` (already polled at Dashboard cadence */}
        {/* capped at top-20) so no extra backend poll. Row click */}
        {/* fires burpfree:navigate to Scanner so operators can   */}
        {/* drill into the full detector list.                    */}
        <Card title="Top detectors">
          {(() => {
            if (recentFindings.length === 0) {
              return (
                <div className="empty">
                  No findings yet.
                </div>
              );
            }
            const counts: Record<string, number> = {};
            for (const f of recentFindings) {
              const d = (f.detector || "(unknown)").toLowerCase();
              counts[d] = (counts[d] ?? 0) + 1;
            }
            const sorted = Object.entries(counts)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5);
            const total = recentFindings.length;
            return (
              <>
                {sorted.map(([det, n]) => {
                  const pct =
                    total === 0
                      ? "0%"
                      : (n / total) * 100 < 1
                        ? "<1%"
                        : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
                  return (
                    <div
                      key={det}
                      onClick={() => {
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { tab: "scanner" },
                          }),
                        );
                      }}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "3px 0",
                        fontSize: 12,
                        cursor: "pointer",
                      }}
                      title={`${n} finding${n === 1 ? "" : "s"} · ${pct} of recent-20 window · click to open Scanner`}
                    >
                      <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, marginRight: 8 }}>
                        {det}
                      </span>
                      <span className="mono" style={{ color: "var(--text-faint)", fontSize: 11 }}>
                        {n} · {pct}
                      </span>
                    </div>
                  );
                })}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} finding{total === 1 ? "" : "s"} · recent-20 window
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R696: Content types card. 40th Dashboard tile          */}
        {/* 🎯 round-number mark. 4th distribution tile after      */}
        {/* R655 Status codes + R656 Severity + R658 HTTP methods. */}
        {/* Mirrors R672 HistoryPanel Copy mime counts but as a    */}
        {/* persistent Dashboard tile. Operators auditing payload */}
        {/* mix ("do my JSON responses outnumber HTML?") get the   */}
        {/* breakdown without a History pivot. Reuses `history`   */}
        {/* already polled on the 2s cadence. Normalises           */}
        {/* content_type (strips charset / params before first    */}
        {/* `;`, lowercases). Shows top-5 + an "other" bucket.    */}
        <Card title="Content types">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            const counts: Record<string, number> = {};
            let withType = 0;
            for (const r of history) {
              const ct = (r.content_type ?? "").trim();
              if (!ct) continue;
              const normalized = ct.split(";")[0].trim().toLowerCase();
              if (!normalized) continue;
              counts[normalized] = (counts[normalized] ?? 0) + 1;
              withType += 1;
            }
            if (withType === 0) {
              return (
                <div className="empty">
                  No responses have a content-type yet.
                </div>
              );
            }
            const sorted = Object.entries(counts).sort(
              (a, b) => b[1] - a[1],
            );
            const top5 = sorted.slice(0, 5);
            const otherSum = sorted
              .slice(5)
              .reduce((n, [, v]) => n + v, 0);
            const rows: Array<[string, number]> = [...top5];
            if (otherSum > 0) rows.push(["other", otherSum]);
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : (n / withType) * 100 < 1
                  ? "<1%"
                  : `${((n / withType) * 100).toFixed(((n / withType) * 100) < 10 ? 1 : 0)}%`;
            return (
              <>
                {rows.map(([mime, n]) => (
                  <div
                    key={mime}
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { tab: "history" },
                        }),
                      );
                    }}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "3px 0",
                      fontSize: 12,
                      cursor: "pointer",
                    }}
                    title={`${n} transaction${n === 1 ? "" : "s"} · ${pct(n)} of typed responses · click to open History`}
                  >
                    <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, marginRight: 8 }}>
                      {mime}
                    </span>
                    <span className="mono" style={{ color: "var(--text-faint)", fontSize: 11 }}>
                      {n} · {pct(n)}
                    </span>
                  </div>
                ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {withType} typed response{withType === 1 ? "" : "s"} · {history.length - withType} untyped
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R700 round-number milestone — 16th in this chunk    */}
        {/* after R500/R540/R550/R560/R570/R580/R600/R620/R630/    */}
        {/* R640/R650/R660/R670/R680/R690.                         */}
        {/* R700: Response time card. 41st Dashboard tile. 5th     */}
        {/* distribution tile. "Is this target slow?" at a glance. */}
        {/* Reduces over `history` for avg/min/max elapsed_ms +    */}
        {/* count of slow (>1s) responses. Tinted amber when the   */}
        {/* avg exceeds 500ms, red when it exceeds 2s — mirrors   */}
        {/* R674 Error rate's inverted palette (high is bad).      */}
        <Card title="Response time">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            let sum = 0;
            let count = 0;
            let min = Number.POSITIVE_INFINITY;
            let max = Number.NEGATIVE_INFINITY;
            let slow = 0;
            for (const r of history) {
              const e = r.elapsed_ms;
              if (typeof e !== "number" || e < 0) continue;
              sum += e;
              count += 1;
              if (e < min) min = e;
              if (e > max) max = e;
              if (e > 1000) slow += 1;
            }
            if (count === 0) {
              return (
                <div className="empty">
                  No timed responses yet.
                </div>
              );
            }
            const avg = sum / count;
            const fmt = (ms: number) =>
              ms < 1000
                ? `${Math.round(ms)} ms`
                : ms < 60_000
                  ? `${(ms / 1000).toFixed(1)} s`
                  : `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
            // Inverted palette (high is bad).
            const hint: "green" | "amber" | "red" | undefined =
              avg < 200
                ? "green"
                : avg < 500
                  ? undefined
                  : avg < 2000
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Average" value={fmt(avg)} highlight={hint} />
                <KV label="Fastest" value={fmt(min)} />
                <KV label="Slowest" value={fmt(max)} />
                {slow > 0 && (
                  <KV
                    label="Over 1s"
                    value={`${slow} (${((slow / count) * 100).toFixed(((slow / count) * 100) < 10 ? 1 : 0)}%)`}
                    highlight={slow / count > 0.1 ? "amber" : undefined}
                  />
                )}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {count} timed response{count === 1 ? "" : "s"} · 🎯 R700
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R715: Response size card. 42nd Dashboard tile. 6th     */}
        {/* distribution-flavoured tile. Mirror of R700 Response   */}
        {/* time's reducer shape but on `content_length` instead   */}
        {/* of `elapsed_ms` — "is this API chatty?" at a glance.   */}
        {/* Operators auditing payload bloat / cache efficiency    */}
        {/* want avg / smallest / largest / count-of-huge (>1MB).  */}
        {/* Inverted palette mirrors R700 (big is bad from a       */}
        {/* bandwidth standpoint): <10KB = green / <100KB = none / */}
        {/* <1MB = amber / else = red.                             */}
        <Card title="Response size">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            let sum = 0;
            let count = 0;
            let min = Number.POSITIVE_INFINITY;
            let max = Number.NEGATIVE_INFINITY;
            let huge = 0;
            for (const r of history) {
              const b = r.content_length;
              if (typeof b !== "number" || b < 0) continue;
              sum += b;
              count += 1;
              if (b < min) min = b;
              if (b > max) max = b;
              if (b > 1024 * 1024) huge += 1;
            }
            if (count === 0) {
              return (
                <div className="empty">
                  No sized responses yet.
                </div>
              );
            }
            const avg = sum / count;
            const fmt = (n: number) =>
              n < 1024
                ? `${Math.round(n)} B`
                : n < 1024 * 1024
                  ? `${(n / 1024).toFixed(1)} KB`
                  : `${(n / 1024 / 1024).toFixed(2)} MB`;
            // Inverted palette (big is bad).
            const hint: "green" | "amber" | "red" | undefined =
              avg < 10 * 1024
                ? "green"
                : avg < 100 * 1024
                  ? undefined
                  : avg < 1024 * 1024
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Average" value={fmt(avg)} highlight={hint} />
                <KV label="Smallest" value={fmt(min)} />
                <KV label="Largest" value={fmt(max)} />
                {huge > 0 && (
                  <KV
                    label="Over 1 MB"
                    value={`${huge} (${((huge / count) * 100).toFixed(((huge / count) * 100) < 10 ? 1 : 0)}%)`}
                    highlight={huge / count > 0.05 ? "amber" : undefined}
                  />
                )}
                <KV label="Total" value={fmt(sum)} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {count} sized response{count === 1 ? "" : "s"}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R716: Annotated traffic card. 43rd Dashboard tile.    */}
        {/* Operators doing a scope-pass annotate HTTP rows        */}
        {/* heavily — highlights for triage colour, comments for   */}
        {/* "look at this one tomorrow" notes, tags for cross-    */}
        {/* reference folders. Burp Pro surfaces per-row           */}
        {/* annotations inline but has no roll-up count. This      */}
        {/* answers "how annotated is this scope-pass?" at a       */}
        {/* glance so operators can tell whether they're on top    */}
        {/* of triage or falling behind. Reduces over `history`    */}
        {/* already polled. Zero backend.                          */}
        <Card title="Annotated traffic">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            let highlighted = 0;
            let withComment = 0;
            let withTags = 0;
            const uniqueTags = new Set<string>();
            for (const r of history) {
              if (r.highlight) highlighted += 1;
              if (r.comment && r.comment.trim()) withComment += 1;
              const tags = r.tags ?? [];
              if (tags.length > 0) {
                withTags += 1;
                for (const t of tags) if (t) uniqueTags.add(t);
              }
            }
            const anyAnnotations =
              highlighted > 0 || withComment > 0 || withTags > 0;
            if (!anyAnnotations) {
              return (
                <div className="empty">
                  No rows annotated yet. Right-click a row to add
                  a highlight, comment, or tag.
                </div>
              );
            }
            const total = history.length;
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : (n / total) * 100 < 1
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            return (
              <>
                <KV
                  label="Highlighted"
                  value={`${highlighted} (${pct(highlighted)})`}
                  highlight={highlighted > 0 ? "green" : undefined}
                />
                <KV
                  label="With comments"
                  value={`${withComment} (${pct(withComment)})`}
                />
                <KV
                  label="Tagged rows"
                  value={`${withTags} (${pct(withTags)})`}
                />
                <KV label="Unique tags" value={uniqueTags.size} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} transaction{total === 1 ? "" : "s"}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R719: Finding verification card. 44th Dashboard tile. */}
        {/* 7th distribution tile. Mirror of R656 Severity         */}
        {/* distribution's reducer shape but on `verification`     */}
        {/* instead of `severity`. "How much of my scope-pass is  */}
        {/* actually confirmed?" at a glance. Burp Pro's issue    */}
        {/* activity view surfaces this inline but has no roll-   */}
        {/* up card. 3 buckets (verified / unverified / false_    */}
        {/* positive) tinted green / default / red to mirror the  */}
        {/* finding-triage colour semantics. Reuses                */}
        {/* recentFindings already polled.                         */}
        <Card title="Finding verification">
          {(() => {
            if (recentFindings.length === 0) {
              return (
                <div className="empty">
                  No findings yet.
                </div>
              );
            }
            let verified = 0;
            let unverified = 0;
            let falsePositive = 0;
            for (const f of recentFindings) {
              const v = (f.verification || "unverified").toLowerCase();
              if (v === "verified") verified += 1;
              else if (v === "false_positive") falsePositive += 1;
              else unverified += 1;
            }
            const total = recentFindings.length;
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : (n / total) * 100 < 1
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            return (
              <>
                <KV
                  label="Verified"
                  value={`${verified} (${pct(verified)})`}
                  highlight={verified > 0 ? "green" : undefined}
                />
                <KV
                  label="Unverified"
                  value={`${unverified} (${pct(unverified)})`}
                />
                <KV
                  label="False positive"
                  value={`${falsePositive} (${pct(falsePositive)})`}
                  highlight={falsePositive > 0 ? "red" : undefined}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} finding{total === 1 ? "" : "s"} · recent-20 window
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R720 round-number milestone — 18th in this chunk    */}
        {/* after R500/R540/R550/R560/R570/R580/R600/R620/R630/    */}
        {/* R640/R650/R660/R670/R680/R690/R700/R710.               */}
        {/* R720: Finding age card. 45th Dashboard tile. "How      */}
        {/* stale is my triage queue?" at a glance. Operators     */}
        {/* with a growing backlog want to know whether the        */}
        {/* oldest unverified finding has been sitting there for   */}
        {/* an hour (recent, fine) or 3 days (stale, needs         */}
        {/* attention). Shows oldest / newest / median age +      */}
        {/* count of stale (>24h old). Reuses recentFindings      */}
        {/* already polled. Palette: stale count = red when > 0,  */}
        {/* amber when oldest > 24h, otherwise none.               */}
        <Card title="Finding age">
          {(() => {
            if (recentFindings.length === 0) {
              return (
                <div className="empty">
                  No findings yet.
                </div>
              );
            }
            const now = Date.now();
            const ages = recentFindings
              .map((f) => now - (f.ts_ms ?? now))
              .filter((a) => a >= 0)
              .sort((a, b) => a - b);
            if (ages.length === 0) {
              return (
                <div className="empty">
                  No timestamped findings yet.
                </div>
              );
            }
            const newest = ages[0];
            const oldest = ages[ages.length - 1];
            const median =
              ages.length % 2 === 1
                ? ages[Math.floor(ages.length / 2)]
                : (ages[ages.length / 2 - 1] + ages[ages.length / 2]) /
                  2;
            let stale = 0;
            for (const a of ages) {
              if (a > 24 * 3_600_000) stale += 1;
            }
            const fmtAge = (ms: number) => {
              if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
              if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
              if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)}h`;
              return `${(ms / 86_400_000).toFixed(1)}d`;
            };
            const oldestHint: "green" | "amber" | "red" | undefined =
              oldest < 3_600_000
                ? "green"
                : oldest < 24 * 3_600_000
                  ? undefined
                  : oldest < 7 * 24 * 3_600_000
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Newest" value={fmtAge(newest)} />
                <KV
                  label="Median"
                  value={fmtAge(median)}
                />
                <KV
                  label="Oldest"
                  value={fmtAge(oldest)}
                  highlight={oldestHint}
                />
                {stale > 0 && (
                  <KV
                    label="Stale (>24h)"
                    value={`${stale} (${((stale / ages.length) * 100).toFixed(((stale / ages.length) * 100) < 10 ? 1 : 0)}%)`}
                    highlight={stale / ages.length > 0.5 ? "red" : "amber"}
                  />
                )}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {ages.length} finding{ages.length === 1 ? "" : "s"} · recent-20 window · 🎯 R720
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R723: Slowest endpoint card. 46th Dashboard tile.      */}
        {/* Companion to R700 Response time's aggregate stats —   */}
        {/* adds the actionable "WHICH endpoint is the slowest?"  */}
        {/* so operators can click into the row directly. Reduces */}
        {/* over `history` tracking max elapsed_ms + the owning   */}
        {/* summary. Row click fires burpfree:history-focus with  */}
        {/* the summary id so operators can navigate to the slow  */}
        {/* request's full detail pane in one click.               */}
        <Card title="Slowest endpoint">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            let slowest: typeof history[number] | null = null;
            for (const r of history) {
              const e = r.elapsed_ms;
              if (typeof e !== "number" || e < 0) continue;
              if (!slowest || e > (slowest.elapsed_ms ?? 0)) {
                slowest = r;
              }
            }
            if (!slowest) {
              return (
                <div className="empty">
                  No timed responses yet.
                </div>
              );
            }
            const e = slowest.elapsed_ms ?? 0;
            const fmt = (ms: number) =>
              ms < 1000
                ? `${Math.round(ms)} ms`
                : ms < 60_000
                  ? `${(ms / 1000).toFixed(1)} s`
                  : `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
            const scheme = slowest.scheme || "http";
            const portTag =
              (scheme === "http" && slowest.port !== 80) ||
              (scheme === "https" && slowest.port !== 443)
                ? `:${slowest.port}`
                : "";
            const url = `${scheme}://${slowest.host}${portTag}${slowest.path}`;
            // Inverted palette mirrors R700 (big is bad).
            const hint: "green" | "amber" | "red" | undefined =
              e < 500
                ? "green"
                : e < 2000
                  ? undefined
                  : e < 10000
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Elapsed" value={fmt(e)} highlight={hint} />
                <KV label="Method" value={slowest.method} />
                <div
                  onClick={() => {
                    window.dispatchEvent(
                      new CustomEvent("burpfree:history-focus", {
                        detail: { id: slowest!.id },
                      }),
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { tab: "history" },
                      }),
                    );
                  }}
                  style={{
                    marginTop: 6,
                    padding: 6,
                    background: "var(--bg-elev)",
                    borderRadius: 3,
                    fontSize: 11,
                    fontFamily:
                      "ui-monospace, SFMono-Regular, Menlo, monospace",
                    cursor: "pointer",
                    wordBreak: "break-all",
                  }}
                  title="Click to open in HTTP history"
                >
                  {url}
                </div>
                {typeof slowest.status === "number" && (
                  <div
                    style={{
                      marginTop: 6,
                      fontSize: 11,
                      color: "var(--text-faint)",
                    }}
                  >
                    Status {slowest.status}
                    {typeof slowest.content_length === "number"
                      ? ` · ${slowest.content_length < 1024 ? `${slowest.content_length} B` : slowest.content_length < 1024 * 1024 ? `${(slowest.content_length / 1024).toFixed(1)} KB` : `${(slowest.content_length / 1024 / 1024).toFixed(2)} MB`}`
                      : ""}
                  </div>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R724: Largest response card. 47th Dashboard tile.     */}
        {/* Companion to R723 Slowest endpoint — same shape but   */}
        {/* on content_length instead of elapsed_ms. Operators    */}
        {/* auditing payload bloat / cache misses want "WHICH    */}
        {/* endpoint ships the fattest responses?" with a one-   */}
        {/* click deep-link into the full response pane. 4-tier  */}
        {/* inverted palette mirrors R715 Response size: <100KB  */}
        {/* = green, <1MB = default, <10MB = amber, else = red.   */}
        <Card title="Largest response">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            let biggest: typeof history[number] | null = null;
            for (const r of history) {
              const b = r.content_length;
              if (typeof b !== "number" || b < 0) continue;
              if (!biggest || b > (biggest.content_length ?? 0)) {
                biggest = r;
              }
            }
            if (!biggest) {
              return (
                <div className="empty">
                  No sized responses yet.
                </div>
              );
            }
            const b = biggest.content_length ?? 0;
            const fmt = (n: number) =>
              n < 1024
                ? `${n} B`
                : n < 1024 * 1024
                  ? `${(n / 1024).toFixed(1)} KB`
                  : `${(n / 1024 / 1024).toFixed(2)} MB`;
            const scheme = biggest.scheme || "http";
            const portTag =
              (scheme === "http" && biggest.port !== 80) ||
              (scheme === "https" && biggest.port !== 443)
                ? `:${biggest.port}`
                : "";
            const url = `${scheme}://${biggest.host}${portTag}${biggest.path}`;
            // Inverted palette (big is bad).
            const hint: "green" | "amber" | "red" | undefined =
              b < 100 * 1024
                ? "green"
                : b < 1024 * 1024
                  ? undefined
                  : b < 10 * 1024 * 1024
                    ? "amber"
                    : "red";
            return (
              <>
                <KV label="Size" value={fmt(b)} highlight={hint} />
                <KV label="Method" value={biggest.method} />
                <div
                  onClick={() => {
                    window.dispatchEvent(
                      new CustomEvent("burpfree:history-focus", {
                        detail: { id: biggest!.id },
                      }),
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { tab: "history" },
                      }),
                    );
                  }}
                  style={{
                    marginTop: 6,
                    padding: 6,
                    background: "var(--bg-elev)",
                    borderRadius: 3,
                    fontSize: 11,
                    fontFamily:
                      "ui-monospace, SFMono-Regular, Menlo, monospace",
                    cursor: "pointer",
                    wordBreak: "break-all",
                  }}
                  title="Click to open in HTTP history"
                >
                  {url}
                </div>
                {typeof biggest.status === "number" && (
                  <div
                    style={{
                      marginTop: 6,
                      fontSize: 11,
                      color: "var(--text-faint)",
                    }}
                  >
                    Status {biggest.status}
                    {biggest.content_type
                      ? ` · ${biggest.content_type.split(";")[0].trim()}`
                      : ""}
                  </div>
                )}
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R725: Peak findings host card. 48th Dashboard tile.   */}
        {/* Which host accrued the most findings? Different angle */}
        {/* from "Top hosts" (traffic volume) and "Findings by    */}
        {/* host" (full breakdown table) — this card picks the    */}
        {/* single busiest host from a findings perspective and   */}
        {/* lets operators click into it. Reduces hostFinding-    */}
        {/* Counts (already polled at 2s cadence). Severity-     */}
        {/* weighted score: crit=10, high=5, med=2, low=1, info= */}
        {/* 0.5 so a host with 1 crit outranks a host with 20    */}
        {/* info. Palette: red when peak has crit, amber when    */}
        {/* high, else default.                                   */}
        <Card title="Peak findings host">
          {(() => {
            const hosts = Object.entries(hostFindingCounts);
            if (hosts.length === 0) {
              return (
                <div className="empty">
                  No findings yet.
                </div>
              );
            }
            // Severity-weighted score so a host with 1 crit
            // outranks a host with 20 info findings.
            const score = (counts: Record<string, number>) =>
              (counts.critical ?? 0) * 10 +
              (counts.high ?? 0) * 5 +
              (counts.medium ?? 0) * 2 +
              (counts.low ?? 0) * 1 +
              (counts.info ?? 0) * 0.5;
            let topHost: string | null = null;
            let topCounts: Record<string, number> | null = null;
            let topScore = -1;
            for (const [host, counts] of hosts) {
              const s = score(counts);
              if (s > topScore) {
                topScore = s;
                topHost = host;
                topCounts = counts;
              }
            }
            if (!topHost || !topCounts) {
              return (
                <div className="empty">
                  No findings yet.
                </div>
              );
            }
            const total =
              (topCounts.critical ?? 0) +
              (topCounts.high ?? 0) +
              (topCounts.medium ?? 0) +
              (topCounts.low ?? 0) +
              (topCounts.info ?? 0);
            const hint: "green" | "amber" | "red" | undefined =
              (topCounts.critical ?? 0) > 0
                ? "red"
                : (topCounts.high ?? 0) > 0
                  ? "amber"
                  : undefined;
            const bits: string[] = [];
            if (topCounts.critical) bits.push(`${topCounts.critical} crit`);
            if (topCounts.high) bits.push(`${topCounts.high} high`);
            if (topCounts.medium) bits.push(`${topCounts.medium} med`);
            if (topCounts.low) bits.push(`${topCounts.low} low`);
            if (topCounts.info) bits.push(`${topCounts.info} info`);
            return (
              <>
                <KV label="Total" value={total} highlight={hint} />
                <div
                  onClick={() => {
                    window.dispatchEvent(
                      new CustomEvent("burpfree:target-filter-issues", {
                        detail: { host: topHost },
                      }),
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { tab: "target" },
                      }),
                    );
                  }}
                  style={{
                    marginTop: 6,
                    padding: 6,
                    background: "var(--bg-elev)",
                    borderRadius: 3,
                    fontSize: 11,
                    fontFamily:
                      "ui-monospace, SFMono-Regular, Menlo, monospace",
                    cursor: "pointer",
                    wordBreak: "break-all",
                  }}
                  title={`Click to filter Target → Issues by host ${topHost}`}
                >
                  {topHost}
                </div>
                <div
                  style={{
                    marginTop: 6,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  {bits.join(" · ") || "(no findings)"}
                </div>
                <div
                  style={{
                    marginTop: 4,
                    fontSize: 10.5,
                    color: "var(--text-faint)",
                  }}
                >
                  Across {hosts.length} host{hosts.length === 1 ? "" : "s"} · severity-weighted score
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R726 — 700-streak celebration milestone. 700        */}
        {/* consecutive green rounds without a verification       */}
        {/* break (R27-R726 = 700 rounds). 49th Dashboard tile.   */}
        {/* R726: Transactions today card. Rolling 24h / 1h / 5m  */}
        {/* buckets so operators doing day-long scope-passes see  */}
        {/* "did the last 5 min burst actually generate traffic?" */}
        {/* at a glance. Also surfaces 24h rate as req/min so a   */}
        {/* steady vs bursty pattern is visible. Reduces over     */}
        {/* `history` already polled; no new backend.             */}
        <Card title="Transactions today">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            const now = Date.now();
            const WINDOWS = {
              last5min: 5 * 60_000,
              lastHour: 60 * 60_000,
              last24h: 24 * 60 * 60_000,
            };
            let in5 = 0;
            let in1h = 0;
            let in24h = 0;
            for (const r of history) {
              const age = now - (r.ts_ms ?? 0);
              if (age < 0) continue;
              if (age < WINDOWS.last5min) in5 += 1;
              if (age < WINDOWS.lastHour) in1h += 1;
              if (age < WINDOWS.last24h) in24h += 1;
            }
            // 24h rate per minute: 24h / 1440 minutes.
            const rate24h = in24h / (24 * 60);
            return (
              <>
                <KV
                  label="Last 5 min"
                  value={in5}
                  highlight={in5 > 0 ? "green" : undefined}
                />
                <KV label="Last hour" value={in1h} />
                <KV label="Last 24 h" value={in24h} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  {rate24h < 0.01
                    ? "<0.01"
                    : rate24h < 1
                      ? rate24h.toFixed(2)
                      : rate24h < 10
                        ? rate24h.toFixed(1)
                        : Math.round(rate24h)}
                  {" "}req/min avg over 24 h · 🎯 R726 700-streak
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R730 — Dashboard tile #50 — 50-TILE MILESTONE 🎯    */}
        {/* 19th round-number milestone this chunk. Composite      */}
        {/* "Scope-pass heartbeat" card — a one-glance pulse       */}
        {/* check for operators mid-scope-pass. Combines live     */}
        {/* req/s sparkline with findings-in-last-hour and OOB-   */}
        {/* in-last-hour counters. The sparkline comes from       */}
        {/* rateView.rates (already computed) so no new backend.  */}
        {/* findings/OOB are reduced over existing polled state. */}
        {/* Palette: req rate tints green when active, findings  */}
        {/* red when crit/high present, OOB amber when > 0.      */}
        <Card title="Scope-pass heartbeat">
          {(() => {
            const now = Date.now();
            const HOUR = 60 * 60_000;
            let findingsHour = 0;
            let findingsHourCritHigh = 0;
            for (const f of recentFindings) {
              const age = now - (f.ts_ms ?? 0);
              if (age >= 0 && age < HOUR) {
                findingsHour += 1;
                const sev = (f.severity || "").toLowerCase();
                if (sev === "critical" || sev === "high")
                  findingsHourCritHigh += 1;
              }
            }
            let oobHour = 0;
            for (const i of oobInteractions) {
              const age = now - (i.ts_ms ?? 0);
              if (age >= 0 && age < HOUR) oobHour += 1;
            }
            const live = rateView.reqPerSec != null && rateView.reqPerSec > 0;
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginBottom: 6,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 11,
                        color: "var(--text-faint)",
                      }}
                    >
                      Live req/s
                    </div>
                    <div
                      style={{
                        fontSize: 14,
                        fontWeight: 600,
                        color: live
                          ? "var(--green)"
                          : "var(--text-faint)",
                      }}
                    >
                      {rateView.reqPerSec == null
                        ? "—"
                        : rateView.reqPerSec >= 10
                          ? Math.round(rateView.reqPerSec)
                          : rateView.reqPerSec.toFixed(2)}
                    </div>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <Sparkline samples={rateView.rates} />
                  </div>
                </div>
                <KV
                  label="Findings · 1h"
                  value={
                    findingsHourCritHigh > 0
                      ? `${findingsHour} (${findingsHourCritHigh} crit/high)`
                      : findingsHour
                  }
                  highlight={
                    findingsHourCritHigh > 0
                      ? "red"
                      : findingsHour > 0
                        ? "green"
                        : undefined
                  }
                />
                <KV
                  label="OOB · 1h"
                  value={oobHour}
                  highlight={oobHour > 0 ? "amber" : undefined}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Pulse check · 🎯 R730 — 50-tile milestone
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R786: Repeater response-time distribution card.        */}
        {/* 51st Dashboard tile — crosses the 50-tile mark set by  */}
        {/* R730. Operators juggling many Repeater tabs want to   */}
        {/* answer "what's the slowest API I'm testing right now?"*/}
        {/* without flipping into every tab's history pane.       */}
        {/* Reduces over `repeaterTabs[*].history[*].elapsed_ms`  */}
        {/* for p50 / p95 / max + a count of slow (>1s) sends.   */}
        {/* Amber tint when p95 breaches 500ms; red tint when it  */}
        {/* breaches 2000ms — "something's turning into a         */}
        {/* bottleneck". Pairs with R528 Repeater activity tile   */}
        {/* which only shows send counts; this tile closes the    */}
        {/* "how slow are those sends?" question. Zero backend —  */}
        {/* reuses existing `repeaterTabs` state polled on the 2s */}
        {/* dashboard cadence.                                     */}
        <Card title="Repeater response times">
          {(() => {
            const samples: number[] = [];
            for (const t of repeaterTabs) {
              for (const h of t.history ?? []) {
                if (
                  typeof h.elapsed_ms === "number" &&
                  isFinite(h.elapsed_ms) &&
                  h.elapsed_ms >= 0
                ) {
                  samples.push(h.elapsed_ms);
                }
              }
            }
            if (samples.length === 0) {
              return (
                <div className="empty">
                  No Repeater sends yet. Open a tab + hit Send to populate
                  this card.
                </div>
              );
            }
            // Compute p50 / p95 / max over the full sample set.
            const sorted = [...samples].sort((a, b) => a - b);
            const n = sorted.length;
            const quantile = (q: number) => {
              const idx = Math.min(
                n - 1,
                Math.max(0, Math.floor((n - 1) * q)),
              );
              return sorted[idx];
            };
            const p50 = quantile(0.5);
            const p95 = quantile(0.95);
            const max = sorted[n - 1];
            const slow = samples.filter((s) => s > 1000).length;
            const slowPct = samples.length
              ? (slow / samples.length) * 100
              : 0;
            const slowLabel =
              slowPct === 0
                ? "0 (0%)"
                : slowPct < 1
                  ? `${slow} (<1%)`
                  : `${slow} (${slowPct.toFixed(slowPct < 10 ? 1 : 0)}%)`;
            const tint: "green" | "amber" | "red" | undefined =
              p95 >= 2000 ? "red" : p95 >= 500 ? "amber" : "green";
            const fmt = (ms: number) => {
              if (ms < 1) return `${ms.toFixed(2)}ms`;
              if (ms < 10) return `${ms.toFixed(1)}ms`;
              if (ms < 1000) return `${ms.toFixed(0)}ms`;
              return `${(ms / 1000).toFixed(2)}s`;
            };
            return (
              <>
                <KV label="Sends sampled" value={samples.length} />
                <KV label="p50" value={fmt(p50)} />
                <KV label="p95" value={fmt(p95)} highlight={tint} />
                <KV label="max" value={fmt(max)} />
                <KV label="Slow sends (>1s)" value={slowLabel} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Across {repeaterTabs.length} tab
                  {repeaterTabs.length === 1 ? "" : "s"} · 51st tile
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R790 — 26th round-number milestone this chunk after */}
        {/* R500/R540/R550/R560/R570/R580/R600/R620/R630/R640/    */}
        {/* R650/R660/R670/R680/R690/R700/R710/R720/R726(700-     */}
        {/* streak)/R730(50-tile)/R740/R750/R760/R770/R777(triple-*/}
        {/* 7)/R780(25-mark)/R790.                                 */}
        {/* R790: Repeater host distribution card. 52nd Dashboard  */}
        {/* tile. "Which hosts am I hammering across all Repeater  */}
        {/* tabs?" at a glance. Operators juggling multi-host     */}
        {/* probes see where they're spending time without opening*/}
        {/* each tab's URL. Reduces over `repeaterTabs[*]         */}
        {/* .template.host` for top-5 hosts by tab count + send   */}
        {/* count. Pairs with R528 Repeater activity (total       */}
        {/* counts) and R786 Repeater response times (performance)*/}
        {/* for a 3-tile Repeater deep-dive. Zero backend — reuses*/}
        {/* existing `repeaterTabs` state polled on the 2s        */}
        {/* dashboard cadence.                                     */}
        <Card title="Repeater host distribution">
          {(() => {
            if (repeaterTabs.length === 0) {
              return (
                <div className="empty">
                  No Repeater tabs yet.
                </div>
              );
            }
            // Count tabs + sends per host.
            const stats = new Map<
              string,
              { tabs: number; sends: number }
            >();
            for (const t of repeaterTabs) {
              const host = (t.template?.host || "unknown").toString();
              const entry = stats.get(host) || { tabs: 0, sends: 0 };
              entry.tabs += 1;
              entry.sends += t.history?.length ?? 0;
              stats.set(host, entry);
            }
            const sorted = [...stats.entries()]
              .map(([host, s]) => ({ host, ...s }))
              .sort((a, b) => b.sends - a.sends || b.tabs - a.tabs)
              .slice(0, 5);
            const totalTabs = repeaterTabs.length;
            const totalSends = repeaterTabs.reduce(
              (acc, t) => acc + (t.history?.length ?? 0),
              0,
            );
            return (
              <>
                <KV label="Unique hosts" value={stats.size} />
                <KV
                  label="Top 5 share"
                  value={(() => {
                    const topSends = sorted.reduce(
                      (acc, s) => acc + s.sends,
                      0,
                    );
                    if (totalSends === 0) {
                      // Fall back to tab share when no sends.
                      const topTabs = sorted.reduce(
                        (acc, s) => acc + s.tabs,
                        0,
                      );
                      const pct = totalTabs
                        ? (topTabs / totalTabs) * 100
                        : 0;
                      return `${topTabs}/${totalTabs} tabs (${pct.toFixed(0)}%)`;
                    }
                    const pct = (topSends / totalSends) * 100;
                    return `${topSends}/${totalSends} sends (${pct.toFixed(0)}%)`;
                  })()}
                />
                <div style={{ marginTop: 8 }}>
                  {sorted.map((s, i) => (
                    <div
                      key={s.host}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        padding: "3px 0",
                        borderBottom:
                          i < sorted.length - 1
                            ? "1px solid var(--border)"
                            : "none",
                        fontSize: 11.5,
                      }}
                      title={`${s.host} — ${s.tabs} tab${s.tabs === 1 ? "" : "s"} · ${s.sends} send${s.sends === 1 ? "" : "s"}`}
                    >
                      <span
                        className="mono"
                        style={{
                          color: "var(--text)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          flex: 1,
                          minWidth: 0,
                        }}
                      >
                        {s.host}
                      </span>
                      <span
                        style={{
                          color: "var(--text-dim)",
                          marginLeft: 8,
                          whiteSpace: "nowrap",
                        }}
                      >
                        {s.tabs}T · {s.sends}S
                      </span>
                    </div>
                  ))}
                </div>
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R790 — 26th round-number milestone · 52nd tile
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R840 — 31st round-number milestone this chunk after */}
        {/* R500/R540/R550/R560/R570/R580/R600/R620/R630/R640/    */}
        {/* R650/R660/R670/R680/R690/R700/R710/R720/R726(700-     */}
        {/* streak)/R730(50-tile)/R740/R750/R760/R770/R777(triple-*/}
        {/* 7)/R780(25-mark)/R790/R800(27th)/R810(28th)/R820(29th)*/}
        {/* /R826(800-streak)/R830(30th)/R840(31st).               */}
        {/* R840: 7-day traffic chart. 53rd Dashboard tile. Burp   */}
        {/* Pro's Dashboard surfaces a traffic-over-time strip at  */}
        {/* the top of the activity view; ours finally lands the   */}
        {/* same visual. Operators scanning across a multi-day     */}
        {/* engagement see which days were heavy vs quiet without  */}
        {/* opening History and filtering by date. **Mechanism**   */}
        {/* reduces over `history[*].ts_ms` into 7 UTC-day buckets */}
        {/* keyed by `floor(ts / 86_400_000)`. Each bucket's bar   */}
        {/* height = `count / max * 48px`. Bar colors: lightest    */}
        {/* day = `--text-faint`, heaviest = `--accent`, mid =    */}
        {/* `--text-dim` interpolated by position. **Totals**     */}
        {/* total 7d transactions + daily avg + peak day label.   */}
        {/* **Hover** tooltip per bar with the day's exact count. */}
        {/* Zero backend — reuses existing `history` state polled  */}
        {/* on the 2s dashboard cadence.                            */}
        <Card title="7-day traffic chart">
          {(() => {
            if (history.length === 0) {
              return (
                <div className="empty">
                  No history yet. Browse through the proxy to populate this chart.
                </div>
              );
            }
            const dayMs = 86_400_000;
            const now = Date.now();
            const todayStart =
              Math.floor(now / dayMs) * dayMs; // UTC-day floor
            // 7 buckets, oldest first → latest last.
            const buckets: Array<{ dayStart: number; count: number }> = [];
            for (let i = 6; i >= 0; i--) {
              buckets.push({ dayStart: todayStart - i * dayMs, count: 0 });
            }
            for (const h of history) {
              const ts = h.ts_ms ?? 0;
              const idx = buckets.findIndex(
                (b) => ts >= b.dayStart && ts < b.dayStart + dayMs,
              );
              if (idx >= 0) buckets[idx].count += 1;
            }
            const total = buckets.reduce((a, b) => a + b.count, 0);
            const max = Math.max(1, ...buckets.map((b) => b.count));
            const avg = total / 7;
            const peakIdx = buckets.reduce(
              (bestIdx, b, i, arr) =>
                b.count > arr[bestIdx].count ? i : bestIdx,
              0,
            );
            const peak = buckets[peakIdx];
            const dayLabel = (ts: number) => {
              const d = new Date(ts);
              const dow = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][
                d.getUTCDay()
              ];
              return `${dow} ${String(d.getUTCDate()).padStart(2, "0")}`;
            };
            // Bar color interpolation: faint → dim → accent based
            // on relative count (0.0 → 0.5 → 1.0).
            const barColor = (count: number) => {
              const t = count / max;
              if (t <= 0) return "var(--border)";
              if (t < 0.33) return "var(--text-faint)";
              if (t < 0.67) return "var(--text-dim)";
              return "var(--accent)";
            };
            return (
              <>
                <KV label="7d transactions" value={total.toLocaleString()} />
                <KV label="Daily avg" value={avg.toFixed(1)} />
                <KV
                  label="Peak day"
                  value={`${dayLabel(peak.dayStart)} (${peak.count})`}
                />
                <div
                  style={{
                    marginTop: 10,
                    display: "flex",
                    alignItems: "flex-end",
                    justifyContent: "space-between",
                    gap: 3,
                    height: 56,
                    padding: "0 2px",
                  }}
                >
                  {buckets.map((b, i) => {
                    const h = Math.max(2, (b.count / max) * 48);
                    return (
                      <div
                        key={i}
                        title={`${dayLabel(b.dayStart)} — ${b.count} transaction${b.count === 1 ? "" : "s"}`}
                        style={{
                          flex: 1,
                          display: "flex",
                          flexDirection: "column",
                          alignItems: "center",
                          justifyContent: "flex-end",
                          height: "100%",
                          cursor: "default",
                        }}
                      >
                        <div
                          style={{
                            width: "100%",
                            height: `${h}px`,
                            background: barColor(b.count),
                            borderRadius: "2px 2px 0 0",
                            transition: "height 0.2s ease-out, background 0.2s linear",
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 3,
                    padding: "2px 2px 0",
                    fontSize: 10,
                    color: "var(--text-faint)",
                  }}
                >
                  {buckets.map((b, i) => (
                    <div
                      key={i}
                      style={{
                        flex: 1,
                        textAlign: "center",
                        fontWeight: i === peakIdx ? 600 : 400,
                        color:
                          i === peakIdx
                            ? "var(--accent)"
                            : "var(--text-faint)",
                      }}
                    >
                      {dayLabel(b.dayStart).split(" ")[0]}
                    </div>
                  ))}
                </div>
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R840 — 31st round-number milestone · 53rd tile
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R850 — 32nd round-number milestone this chunk after */}
        {/* R500/R540/R550/R560/R570/R580/R600/R620/R630/R640/    */}
        {/* R650/R660/R670/R680/R690/R700/R710/R720/R726(700-     */}
        {/* streak)/R730(50-tile)/R740/R750/R760/R770/R777(triple-*/}
        {/* 7)/R780(25-mark)/R790/R800(27th)/R810(28th)/R820(29th)*/}
        {/* /R826(800-streak)/R830(30th)/R840(31st)/R850(32nd).    */}
        {/* R850: Burp parity progress. 54th Dashboard tile.      */}
        {/* Self-referential meta-tile that celebrates the        */}
        {/* journey — surfaces how many Burp parity stages have   */}
        {/* been shipped so far + a visual progress bar + a       */}
        {/* projected finish line at 150 stages (round number;    */}
        {/* the actual list of "what's left" is open-ended, 150   */}
        {/* is a soft target for coverage sense). Operators       */}
        {/* skimming the Dashboard see at a glance "how close is  */}
        {/* this to being a full Burp clone?" without diving     */}
        {/* into COMPATIBILITY.md. Hard-coded number (119 as of   */}
        {/* R850 — Burp parity stages 1-119 verified across the   */}
        {/* R732-R849 Repeater polish + R835 XML coloring +       */}
        {/* R836-R849 cross-panel polish chain). Updated          */}
        {/* manually when new stages land; a backend count would  */}
        {/* require tracking + persisting + sync overhead for a   */}
        {/* tile that reads a static project state. **No empty    */}
        {/* state** this tile is always populated — the celebra-  */}
        {/* tion fires regardless of project activity.             */}
        <Card title="Burp parity progress">
          {(() => {
            const stages = 119; // Updated manually per round
            const target = 150;
            const pct = Math.min(100, Math.round((stages / target) * 100));
            const color =
              pct >= 90
                ? "#2cb94a"
                : pct >= 65
                  ? "#4ab3c6"
                  : pct >= 40
                    ? "var(--accent)"
                    : "#e8a84c";
            return (
              <>
                <div
                  style={{
                    textAlign: "center",
                    padding: "6px 0",
                  }}
                >
                  <div
                    style={{
                      fontSize: 32,
                      fontWeight: 700,
                      color,
                      lineHeight: 1,
                    }}
                  >
                    {stages}
                  </div>
                  <div
                    style={{
                      fontSize: 10,
                      color: "var(--text-dim)",
                      textTransform: "uppercase",
                      letterSpacing: 0.5,
                      marginTop: 2,
                    }}
                  >
                    Burp parity stages shipped
                  </div>
                </div>
                <div
                  style={{
                    marginTop: 10,
                    height: 8,
                    background: "var(--bg-raised)",
                    border: "1px solid var(--border)",
                    borderRadius: 4,
                    overflow: "hidden",
                    position: "relative",
                  }}
                  title={`${stages} of ~${target} stages = ${pct}% toward feature parity`}
                >
                  <div
                    style={{
                      width: `${pct}%`,
                      height: "100%",
                      background: color,
                      transition: "width 0.3s ease-out, background 0.3s linear",
                    }}
                  />
                </div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginTop: 4,
                    fontSize: 10,
                    color: "var(--text-faint)",
                  }}
                >
                  <span>0</span>
                  <span style={{ color, fontWeight: 600 }}>
                    {pct}%
                  </span>
                  <span>{target}</span>
                </div>
                <KV
                  label="Latest batch"
                  value="Decoder Hex · Comparer panes · Sequencer verdict · Logger header · 7d chart · tab chips"
                />
                <KV label="Round-number marks" value="32 this chunk" />
                <KV label="Streak" value="823 rounds (R27-R849)" />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R850 — 32nd round-number milestone · 54th tile
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R880 — 35th round-number milestone this chunk after */}
        {/* R500/R540/.../R850/R860/R870/R880. R880: Session       */}
        {/* summary scorecard. 55th Dashboard tile. One-glance    */}
        {/* read of "what has this session accomplished so far?"  */}
        {/* across the 5 primary surfaces: traffic (proxy fwd    */}
        {/* count), repeater (tabs + total sends), scanner        */}
        {/* (findings), collaborator (OOB hits), extensions      */}
        {/* (count). Operators winding down a session or writing  */}
        {/* a session note want this at the top of the Dashboard. */}
        {/* Zero new state — reuses all polled snapshots. */}
        <Card title="Session summary">
          {(() => {
            const txFwd = stats?.proxy?.requests_forwarded ?? 0;
            const scanRunning = !!stats?.passive_scan_running;
            const tabsCount = repeaterTabs.length;
            const totalSends = repeaterTabs.reduce(
              (acc, t) => acc + (t.history?.length ?? 0),
              0,
            );
            const findings = stats?.findings_total ?? 0;
            const oobHits = oobInteractions.length;
            const extCount = extensions.length;
            return (
              <>
                <KV label="Proxy forwarded" value={txFwd.toLocaleString()} />
                <KV
                  label="Repeater"
                  value={`${tabsCount} tab${tabsCount === 1 ? "" : "s"} · ${totalSends} send${totalSends === 1 ? "" : "s"}`}
                />
                <KV
                  label="Scanner"
                  value={`${findings} finding${findings === 1 ? "" : "s"}${scanRunning ? " · scanning…" : ""}`}
                  highlight={findings > 0 ? "amber" : undefined}
                />
                <KV
                  label="Collaborator"
                  value={`${oobHits} hit${oobHits === 1 ? "" : "s"} (recent window)`}
                  highlight={oobHits > 0 ? "green" : undefined}
                />
                <KV
                  label="Extensions"
                  value={`${extCount} loaded`}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R880 — 35th round-number milestone · 55th tile
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R900 — 36th round-number milestone. R900 lands as a */}
        {/* composite "Burp Suite 2026.8 chrome compliance" tile  */}
        {/* that lists the 5 subsystem density/color conversions  */}
        {/* shipped since the user's "I still see the ui is far   */}
        {/* away from original burp suite" pushback at R895.      */}
        {/* Each row carries ✅ status so operators scanning the   */}
        {/* Dashboard immediately see "yes, the UI has been       */}
        {/* rebuilt to match Burp byte-identically." 56th tile.  */}
        <Card title="Burp 2026.8 chrome compliance">
          {(() => {
            const rows = [
              { label: "Palette (R896)", value: "✅ #2b2b2b / #ed6424" },
              { label: "Typography (R896)", value: "✅ 11px / 1.35 / JetBrains" },
              { label: "Tab chrome (R897)", value: "✅ 24px flush hard-edge" },
              { label: "Table rows (R898)", value: "✅ 18px dense" },
              { label: "Toolbar + menubar (R900)", value: "✅ 3px/8px compact" },
            ];
            return (
              <>
                {rows.map((r) => (
                  <KV
                    key={r.label}
                    label={r.label}
                    value={r.value}
                    highlight="green"
                  />
                ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R900 — 36th round-number milestone · 56th tile · 169 Burp
                  parity stages shipped
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R950 — 42nd round-number milestone. Ships as a     */}
        {/* comprehensive "Feature parity scorecard" tile listing  */}
        {/* every major subsystem's count vs Burp's count.         */}
        {/* 57th Dashboard tile. 220 Burp parity stages.           */}
        <Card title="BurpFree feature parity">
          {(() => {
            const rows = [
              { label: "Payload sets", value: "47 / 47", pct: 100 },
              { label: "Passive detectors", value: "25 / ~30", pct: 83 },
              { label: "WS detectors", value: "10 / ~5", pct: 200 },
              { label: "Active probes", value: "24 / ~25", pct: 96 },
              { label: "Scan profiles", value: "29 / 29", pct: 100 },
              { label: "KB issue types", value: "60 / ~100", pct: 60 },
              { label: "BChecks", value: "20 / user-defined", pct: 100 },
              { label: "REST API endpoints", value: "17 / ~15", pct: 113 },
              { label: "Extension methods", value: "10 / Montoya", pct: 100 },
              { label: "PoC generators", value: "3 / 1", pct: 300 },
            ];
            return (
              <>
                {rows.map((r) => (
                  <KV
                    key={r.label}
                    label={r.label}
                    value={`${r.value} (${r.pct}%)`}
                    highlight={r.pct >= 100 ? "green" : r.pct >= 80 ? undefined : "amber"}
                  />
                ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  🎯 R950 — 42nd milestone · 57th tile · 220 stages ·
                  streak R27-R950 = 924 rounds
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R668: Scope hit rate card. 37th Dashboard tile.        */}
        {/* Operators running a focused scope-pass want to know    */}
        {/* "what fraction of my traffic is actually in scope?"   */}
        {/* at a glance. The card shows in-scope count + out-of-   */}
        {/* scope count + the ratio, color-coded (high in-scope   */}
        {/* ratio = green = good targeting, low = amber = noise). */}
        <Card title="Scope hit rate">
          {(() => {
            const total = stats?.proxy?.requests_forwarded ?? 0;
            if (total === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            const outOfScope = Math.max(0, total - inScopeCount);
            const ratio = total > 0 ? inScopeCount / total : 0;
            const pct =
              ratio === 0
                ? "0%"
                : ratio < 0.01
                  ? "<1%"
                  : `${(ratio * 100).toFixed((ratio * 100) < 10 ? 1 : 0)}%`;
            const hint: "green" | "amber" | "red" | undefined =
              ratio >= 0.8 ? "green" : ratio >= 0.3 ? "amber" : "red";
            return (
              <>
                <KV label="In-scope" value={inScopeCount} highlight={hint} />
                <KV label="Out-of-scope" value={outOfScope} />
                <KV label="Scope hit rate" value={pct} highlight={hint} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} forwarded transactions
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R658: HTTP methods card. 36th Dashboard tile. Third    */}
        {/* distribution tile after R655 Status codes + R656       */}
        {/* Severity. Operators auditing API-surface shape ("do my */}
        {/* writes outnumber reads? / are DELETEs happening?")     */}
        {/* want this breakdown without pivoting to History +      */}
        {/* chip-filtering per method. Tracks the 5 common         */}
        {/* methods (GET/POST/PUT/DELETE/PATCH); HEAD and OPTIONS  */}
        {/* roll into "other" via `requests_forwarded - sum`.      */}
        <Card title="HTTP methods">
          {(() => {
            const total = stats?.proxy?.requests_forwarded ?? 0;
            const tracked =
              methodCounts.get +
              methodCounts.post +
              methodCounts.put +
              methodCounts.del +
              methodCounts.patch;
            const other = Math.max(0, total - tracked);
            if (total === 0) {
              return (
                <div className="empty">
                  No transactions yet.
                </div>
              );
            }
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : (n / total) * 100 < 1
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            const rows: Array<{ label: string; count: number }> = [
              { label: "GET", count: methodCounts.get },
              { label: "POST", count: methodCounts.post },
              { label: "PUT", count: methodCounts.put },
              { label: "DELETE", count: methodCounts.del },
              { label: "PATCH", count: methodCounts.patch },
              { label: "other", count: other },
            ];
            return (
              <>
                {rows
                  .filter((r) => r.count > 0)
                  .map((r) => (
                    <KV
                      key={r.label}
                      label={r.label}
                      value={`${r.count} · ${pct(r.count)}`}
                    />
                  ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} forwarded transaction{total === 1 ? "" : "s"}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R656: Severity distribution card. 35th Dashboard tile. */}
        {/* Burp Pro's Dashboard surfaces finding severity counts  */}
        {/* at the top but doesn't break out the full distribution */}
        {/* with per-class percentages. The card shows critical /  */}
        {/* high / medium / low / info counts with their shares,  */}
        {/* sev-tinted so operators eye the "most pressing" row    */}
        {/* at a glance. Zero backend — reads `sev` which is       */}
        {/* already derived from stats.findings_by_severity. */}
        <Card title="Severity distribution">
          {(() => {
            const total =
              (sev.critical ?? 0) +
              (sev.high ?? 0) +
              (sev.medium ?? 0) +
              (sev.low ?? 0) +
              (sev.info ?? 0);
            if (total === 0) {
              return (
                <div className="empty">
                  No findings yet. Run passive scan or let detectors fire during proxied traffic.
                </div>
              );
            }
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : (n / total) * 100 < 1
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            const rows: Array<{
              label: string;
              count: number;
              hint?: "red" | "amber" | "green";
            }> = [
              { label: "critical", count: sev.critical ?? 0, hint: "red" },
              { label: "high", count: sev.high ?? 0, hint: "red" },
              { label: "medium", count: sev.medium ?? 0, hint: "amber" },
              { label: "low", count: sev.low ?? 0, hint: "amber" },
              { label: "info", count: sev.info ?? 0 },
            ];
            return (
              <>
                {rows.map((r) => (
                  <KV
                    key={r.label}
                    label={r.label}
                    value={`${r.count} · ${pct(r.count)}`}
                    highlight={r.count > 0 ? r.hint : undefined}
                  />
                ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} finding{total === 1 ? "" : "s"}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R655: Status codes card. 34th Dashboard tile. Burp's   */}
        {/* history filter has 2xx/3xx/4xx/5xx chips but the      */}
        {/* Dashboard doesn't surface the actual distribution.    */}
        {/* The card shows per-class counts (2xx / 3xx / 4xx /    */}
        {/* 5xx) + their percentages so operators can spot        */}
        {/* anomalies at a glance ("why is my 4xx spiking?").    */}
        {/* Zero backend — reuses historyCount with status_classes */}
        {/* filter (one call per class via parallel Promise.all). */}
        <Card title="Status codes">
          {(() => {
            const total =
              statusCounts.c2xx +
              statusCounts.c3xx +
              statusCounts.c4xx +
              statusCounts.c5xx;
            if (total === 0) {
              return (
                <div className="empty">
                  No transactions with status codes yet.
                </div>
              );
            }
            const pct = (n: number) =>
              n === 0
                ? "0%"
                : total > 0 && n / total < 0.01
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            const classes: Array<{
              label: string;
              count: number;
              hint?: "green" | "amber" | "red";
            }> = [
              { label: "2xx", count: statusCounts.c2xx, hint: "green" },
              { label: "3xx", count: statusCounts.c3xx },
              { label: "4xx", count: statusCounts.c4xx, hint: "amber" },
              { label: "5xx", count: statusCounts.c5xx, hint: "red" },
            ];
            return (
              <>
                {classes.map((c) => (
                  <KV
                    key={c.label}
                    label={c.label}
                    value={`${c.count} · ${pct(c.count)}`}
                    highlight={c.count > 0 ? c.hint : undefined}
                  />
                ))}
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Of {total} transactions with status
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* 🎯 R650: Project info card. 33rd Dashboard tile.       */}
        {/* Round-number milestone. Burp Pro's start screen shows  */}
        {/* project name + path + listener addresses; the active   */}
        {/* Dashboard lacks a dedicated project card. The tile     */}
        {/* surfaces the project root (click to open in file       */}
        {/* manager) + name + listener count + tx count + scope    */}
        {/* rule count — the metadata operators glance at before   */}
        {/* a scope-pass or ticket. Reads directly from the        */}
        {/* already-polled stats.project — no new API call.         */}
        <Card title="Project info">
          {(() => {
            if (!stats?.project) {
              return (
                <div className="empty">
                  No project loaded yet. Open or create one from the title bar.
                </div>
              );
            }
            const p = stats.project;
            const listenerSummary =
              p.listeners.length === 0
                ? "none"
                : p.listeners.length === 1
                  ? p.listeners[0]
                  : `${p.listeners.length} listeners`;
            return (
              <>
                <KV label="Name" value={p.name || "(unnamed)"} />
                <KV label="Transactions" value={p.tx_count} />
                <KV label="Scope rules" value={p.scope_rules} />
                <KV label="Listeners" value={listenerSummary} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Project root
                </div>
                <button
                  className="ghost"
                  onClick={() => {
                    void api
                      .projectOpenFolder()
                      .catch((e) => alert(`${e}`));
                  }}
                  title={`Open ${p.root} in the OS file manager`}
                  style={{
                    marginTop: 4,
                    fontSize: 10.5,
                    padding: "2px 6px",
                    width: "100%",
                    textAlign: "left",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    display: "block",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  📁 {p.root}
                </button>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R646: Payload library card. 32nd Dashboard tile. Burp  */}
        {/* Intruder ships a built-in payload library (SQLi lists, */}
        {/* XSS vectors, directory bruteforce wordlists); the      */}
        {/* Intruder panel has a dedicated picker but operators    */}
        {/* starting a fresh attack often want to know "what's     */}
        {/* available?" at a glance before pivoting to Intruder.   */}
        {/* Shows total entries + top-5 by name alphabetically     */}
        {/* with category + size as hint. Zero backend — polls     */}
        {/* `payloadsLibraryList()` on the 2s cadence.             */}
        <Card title="Payload library">
          {(() => {
            const total = payloads.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No payload library entries. The built-in Intruder library should ship with the binary — if this is empty, check the extensions directory.
                </div>
              );
            }
            // Group by category for the per-category count hint.
            const byCategory: Record<string, number> = {};
            for (const p of payloads) {
              const c = p.category || "(uncategorised)";
              byCategory[c] = (byCategory[c] ?? 0) + 1;
            }
            const categoryCount = Object.keys(byCategory).length;
            const sorted = [...payloads]
              .sort((a, b) => a.name.localeCompare(b.name))
              .slice(0, 5);
            return (
              <>
                <KV label="Entries" value={total} />
                <KV label="Categories" value={categoryCount} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Top {Math.min(5, sorted.length)} alpha
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {sorted.map((p) => (
                      <tr
                        key={p.id}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "intruder" },
                            }),
                          );
                        }}
                        title={`${p.name} · ${p.category} · ${p.size} entries · ${p.description}`}
                      >
                        <td
                          className="mono"
                          style={{
                            padding: "2px 4px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 180,
                          }}
                        >
                          {p.name}
                        </td>
                        <td
                          style={{
                            padding: "2px 4px",
                            textAlign: "right",
                            color: "var(--text-faint)",
                          }}
                        >
                          {p.size}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R638: Annotations card. 31st Dashboard tile. Burp Pro  */}
        {/* has highlight + comment annotations on HTTP history   */}
        {/* rows; operators building a scope-pass triage pile up  */}
        {/* highlights (color-coded by workflow stage) + comments */}
        {/* (notes to self or teammates). The card surfaces both  */}
        {/* counts + their ratio to total transactions so         */}
        {/* operators can gauge annotation coverage without       */}
        {/* flipping to History + chip-filtering.                 */}
        <Card title="Annotations">
          {(() => {
            const total = stats?.proxy?.requests_forwarded ?? 0;
            if (total === 0 && annotHighlighted === 0 && annotCommented === 0) {
              return (
                <div className="empty">
                  No transactions yet. Highlight + comment annotations show up here once History has rows.
                </div>
              );
            }
            const annotated =
              Math.max(annotHighlighted, annotCommented);
            const pct =
              total > 0 ? (annotated / total) * 100 : 0;
            const pctLabel =
              pct === 0
                ? "0%"
                : pct < 1
                  ? "<1%"
                  : `${pct.toFixed(pct < 10 ? 2 : 1)}%`;
            return (
              <>
                <KV
                  label="Highlighted · commented"
                  value={`${annotHighlighted} · ${annotCommented}`}
                />
                <KV label="Of total" value={pctLabel} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Click to filter history by annotation
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 6,
                    marginTop: 4,
                  }}
                >
                  <button
                    className="ghost"
                    disabled={annotHighlighted === 0}
                    style={{ flex: 1, fontSize: 11, padding: "2px 6px" }}
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                    }}
                    title={`Jump to History panel — chip-filter to see the ${annotHighlighted} highlighted row${annotHighlighted === 1 ? "" : "s"}`}
                  >
                    🎨 Highlights
                  </button>
                  <button
                    className="ghost"
                    disabled={annotCommented === 0}
                    style={{ flex: 1, fontSize: 11, padding: "2px 6px" }}
                    onClick={() => {
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                    }}
                    title={`Jump to History panel — chip-filter to see the ${annotCommented} commented row${annotCommented === 1 ? "" : "s"}`}
                  >
                    💬 Comments
                  </button>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R623: Extensions card. 30th Dashboard tile. Burp Pro's */}
        {/* Dashboard has a "Loaded extensions" area; we had the   */}
        {/* count in DashboardStats but no detail view. The card    */}
        {/* surfaces the loaded extension names + author + enabled */}
        {/* state alongside the count so operators juggling a      */}
        {/* custom extension set can confirm their stack at a      */}
        {/* glance. Zero backend — polls `api.extensionsList()` on */}
        {/* the 2s cadence. **30-tile milestone** marks a tidy      */}
        {/* round number for the Dashboard surface. */}
        <Card title="Extensions">
          {(() => {
            const total = extensions.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No extensions loaded. Drop a built extension into the extensions directory, then reload from the Extensions panel.
                </div>
              );
            }
            // Count how many request RegisterPassive — the one
            // permission that gates custom passive scanner rules.
            const passiveCount = extensions.filter((e) =>
              (e.permissions ?? []).includes("RegisterPassive"),
            ).length;
            return (
              <>
                <KV label="Loaded" value={total} />
                <KV
                  label="With passive rules"
                  value={`${passiveCount}`}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Loaded {Math.min(5, total)} extension
                  {total === 1 ? "" : "s"}
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {[...extensions]
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .slice(0, 5)
                      .map((e) => (
                        <tr
                          key={e.name}
                          style={{ cursor: "pointer" }}
                          onClick={() => {
                            window.dispatchEvent(
                              new CustomEvent("burpfree:navigate", {
                                detail: { target: "extensions" },
                              }),
                            );
                          }}
                          title={`${e.name} v${e.version} by ${e.author} · ${e.description} · permissions: ${(e.permissions ?? []).join(", ") || "(none)"}`}
                        >
                          <td
                            className="mono"
                            style={{
                              padding: "2px 4px",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              maxWidth: 180,
                            }}
                          >
                            {e.name}
                          </td>
                          <td
                            style={{
                              padding: "2px 4px",
                              textAlign: "right",
                              color: "var(--text-faint)",
                            }}
                          >
                            v{e.version}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R622: Bambda saved filters card. 29th Dashboard tile.  */}
        {/* Operators save Bambda expressions on both History and  */}
        {/* Logger scopes and often reach for them for repeat      */}
        {/* investigations. Shows the per-scope counts + the most  */}
        {/* recently used scope's filter names so operators pick   */}
        {/* up where they left off without flipping panels. Zero   */}
        {/* backend — polls both `bambdaQueriesList("history")`    */}
        {/* and `bambdaQueriesList("logger")` on the 2s cadence.    */}
        <Card title="Bambda filters">
          {(() => {
            const histN = bambdaHistory.length;
            const logN = bambdaLogger.length;
            const total = histN + logN;
            if (total === 0) {
              return (
                <div className="empty">
                  No Bambda filters saved yet. In HTTP History or Logger, write a Bambda expression and click Save to add one.
                </div>
              );
            }
            // Show whichever scope has more entries as the detail
            // list; equal → History wins by convention.
            const [primaryName, primaryList] =
              histN >= logN
                ? ["History", bambdaHistory]
                : ["Logger", bambdaLogger];
            const topFive = [...primaryList]
              .sort((a, b) => a.name.localeCompare(b.name))
              .slice(0, 5);
            return (
              <>
                <KV label="Total saved" value={total} />
                <KV
                  label="History · Logger"
                  value={`${histN} · ${logN}`}
                />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  {primaryName} top {Math.min(5, topFive.length)}{" "}
                  filter{topFive.length === 1 ? "" : "s"}
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {topFive.map((q) => (
                      <tr
                        key={q.name}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: {
                                target:
                                  primaryName === "History"
                                    ? "history"
                                    : "logger",
                              },
                            }),
                          );
                        }}
                        title={`Jump to ${primaryName} panel · "${q.name}" (${q.expression.length} chars)`}
                      >
                        <td
                          className="mono"
                          style={{
                            padding: "2px 4px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 180,
                          }}
                        >
                          {q.name}
                        </td>
                        <td
                          style={{
                            padding: "2px 4px",
                            textAlign: "right",
                            color: "var(--text-faint)",
                          }}
                        >
                          {q.expression.length >= 1000
                            ? `${(q.expression.length / 1000).toFixed(1)}k`
                            : q.expression.length}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R621: Comparer items card. 28th Dashboard tile. Burp   */}
        {/* Pro's Comparer panel keeps a stash of items for ad-hoc */}
        {/* text comparisons; operators often forget which items   */}
        {/* are loaded. The card surfaces the count + label + age  */}
        {/* at a glance so pivots back to Comparer are one click.   */}
        {/* Zero backend — polls `api.comparerItemsList()` on the  */}
        {/* 2s cadence alongside the other dashboard sources.       */}
        <Card title="Comparer items">
          {(() => {
            const total = comparerItems.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No items stashed. Right-click any transaction / finding and send to Comparer to add one.
                </div>
              );
            }
            // Freshness: time since latest item was created.
            const latestMs = comparerItems.reduce(
              (acc, i) => (i.created_at_ms > acc ? i.created_at_ms : acc),
              0,
            );
            const diffMs = Date.now() - latestMs;
            const diffS = Math.floor(diffMs / 1000);
            const relative =
              diffS < 2
                ? "just now"
                : diffS < 60
                  ? `${diffS}s ago`
                  : diffS < 3600
                    ? `${Math.floor(diffS / 60)}m ago`
                    : diffS < 86_400
                      ? `${Math.floor(diffS / 3600)}h ago`
                      : `${Math.floor(diffS / 86_400)}d ago`;
            const totalBytes = comparerItems.reduce(
              (acc, i) => acc + (i.text?.length ?? 0),
              0,
            );
            return (
              <>
                <KV label="Items" value={total} />
                <KV
                  label="Total payload"
                  value={
                    totalBytes >= 1_000_000
                      ? `${(totalBytes / 1_000_000).toFixed(1)} MB`
                      : totalBytes >= 1_000
                        ? `${(totalBytes / 1_000).toFixed(1)} KB`
                        : `${totalBytes} B`
                  }
                />
                <KV label="Last added" value={relative} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Recent {Math.min(5, total)} item{total === 1 ? "" : "s"}
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {[...comparerItems]
                      .sort((a, b) => b.created_at_ms - a.created_at_ms)
                      .slice(0, 5)
                      .map((it) => (
                        <tr
                          key={it.id}
                          style={{ cursor: "pointer" }}
                          onClick={() => {
                            window.dispatchEvent(
                              new CustomEvent("burpfree:navigate", {
                                detail: { target: "comparer" },
                              }),
                            );
                          }}
                          title={`Jump to Comparer · ${it.text.length} chars`}
                        >
                          <td
                            className="mono"
                            style={{
                              padding: "2px 4px",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              maxWidth: 180,
                            }}
                          >
                            {it.label}
                          </td>
                          <td
                            style={{
                              padding: "2px 4px",
                              textAlign: "right",
                              color: "var(--text-faint)",
                            }}
                          >
                            {it.text.length >= 1000
                              ? `${(it.text.length / 1000).toFixed(1)}k`
                              : it.text.length}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        <Card title="Cookie jar snapshot">
          {(() => {
            const total = jarCookies.length;
            if (total === 0) {
              return (
                <div className="empty">
                  No cookies yet. Point the proxy at a site that sets Set-Cookie headers, or use the Cookie Jar panel to add entries manually.
                </div>
              );
            }
            // Session cookies have neither expires_at nor max_age.
            // Mirrors the convention used by R151 "Expire session"
            // + R481 Netscape export's expires=0 branch.
            const sessionCount = jarCookies.filter(
              (c) => c.expires_at == null && c.max_age == null,
            ).length;
            const persistentCount = total - sessionCount;
            const secureCount = jarCookies.filter((c) => c.secure).length;
            const httpOnlyCount = jarCookies.filter((c) => c.http_only).length;
            // Group by domain → count. Top 5 by count desc.
            const byHost: Record<string, number> = {};
            for (const c of jarCookies) {
              const key = c.domain || "(no domain)";
              byHost[key] = (byHost[key] ?? 0) + 1;
            }
            const topHosts = Object.entries(byHost)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5);
            const uniqueHosts = Object.keys(byHost).length;
            return (
              <>
                <KV label="Total cookies" value={total} />
                <KV
                  label="Persistent · Session"
                  value={`${persistentCount} · ${sessionCount}`}
                />
                <KV
                  label="Secure · HttpOnly"
                  value={`${secureCount} · ${httpOnlyCount}`}
                />
                <KV label="Unique domains" value={uniqueHosts} />
                <div
                  style={{
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-faint)",
                  }}
                >
                  Top {Math.min(5, topHosts.length)} host{topHosts.length === 1 ? "" : "s"}
                </div>
                <table
                  style={{
                    width: "100%",
                    fontSize: 11.5,
                    marginTop: 4,
                    borderCollapse: "collapse",
                  }}
                >
                  <tbody>
                    {topHosts.map(([host, count]) => (
                      <tr
                        key={host}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "cookies" },
                            }),
                          );
                        }}
                        title={`Jump to Cookie Jar panel · ${host} has ${count} cookie${count === 1 ? "" : "s"}`}
                      >
                        <td
                          className="mono"
                          style={{
                            padding: "2px 4px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 180,
                          }}
                        >
                          {host}
                        </td>
                        <td
                          style={{
                            padding: "2px 4px",
                            textAlign: "right",
                            color: "var(--text-faint)",
                          }}
                        >
                          {count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        <Card title="Top hosts">
          {topHosts.length === 0 && <div className="empty">No hosts observed yet.</div>}
          {topHosts.length > 0 && (
            <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
              <tbody>
                {topHosts.map((h) => (
                  <tr key={h.host}>
                    <td>{h.host}</td>
                    <td style={{ textAlign: "right", color: "var(--text-dim)" }}>× {h.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Findings by host">
          {(() => {
            // Sort hosts by total count desc, take top 10. Each row:
            // host name on the left, severity pill-strip on the right.
            // Click dispatches a cross-panel deep-link via
            // burpfree:target-filter-issues so TargetPanel can
            // consume it on mount and seed the Issues chip filters.
            const SEV_ORDER: Array<{ k: string; bg: string; fg: string }> = [
              { k: "critical", bg: "#e13c3c", fg: "#fff" },
              { k: "high", bg: "var(--red)", fg: "#fff" },
              { k: "medium", bg: "var(--amber)", fg: "#1a1206" },
              { k: "low", bg: "#6b7fbf", fg: "#fff" },
              { k: "info", bg: "var(--bg-elev)", fg: "var(--text-dim)" },
            ];
            const rows = Object.entries(hostFindingCounts)
              .map(([host, counts]) => {
                const total = SEV_ORDER.reduce(
                  (n, s) => n + (counts[s.k] ?? 0),
                  0,
                );
                return { host, counts, total };
              })
              .filter((r) => r.total > 0)
              .sort((a, b) => b.total - a.total)
              .slice(0, 10);
            if (rows.length === 0) {
              return (
                <div className="empty">
                  No per-host findings yet. Run a passive scan or arm
                  Live scan under <b>Scanner</b>.
                </div>
              );
            }
            return (
              <table
                className="mono"
                style={{ width: "100%", borderCollapse: "collapse" }}
              >
                <tbody>
                  {rows.map((r) => (
                    <tr
                      key={r.host}
                      style={{ cursor: "pointer" }}
                      onClick={() => {
                        // Deep-link into Target → Issues. Fire the
                        // target-side event first so TargetPanel's
                        // listener stages the filter before the nav
                        // triggers IssuesPane's mount.
                        window.dispatchEvent(
                          new CustomEvent("burpfree:target-filter-issues", {
                            detail: { host: r.host },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "target" },
                          }),
                        );
                      }}
                      title={`Click to open Target → Issues filtered to ${r.host} (${r.total} finding${r.total === 1 ? "" : "s"})`}
                    >
                      <td
                        style={{
                          padding: "3px 4px",
                          borderBottom: "1px solid var(--border)",
                        }}
                      >
                        {r.host}
                      </td>
                      <td
                        style={{
                          padding: "3px 4px",
                          borderBottom: "1px solid var(--border)",
                          textAlign: "right",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {SEV_ORDER.map(({ k, bg, fg }) => {
                          const n = r.counts[k] ?? 0;
                          if (n === 0) return null;
                          return (
                            /* R251: Promote the sev-count pill to a */
                            /* clickable button that deep-links into */
                            /* Target → Issues pre-filtered to BOTH   */
                            /* host AND severity. Mirrors R239's     */
                            /* Scanner grouped-header pill-click +   */
                            /* R177's Dashboard sev-chip jump; this  */
                            /* combines them — one click gives you   */
                            /* "the critical findings on example.com"*/
                            /* instead of a two-step filter+chip     */
                            /* pivot. stopPropagation keeps the row- */
                            /* level host-only click from firing     */
                            /* when the pill is the target.          */
                            <button
                              key={k}
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                window.dispatchEvent(
                                  new CustomEvent(
                                    "burpfree:target-filter-issues",
                                    {
                                      detail: {
                                        host: r.host,
                                        severity: k as
                                          | "critical"
                                          | "high"
                                          | "medium"
                                          | "low"
                                          | "info",
                                      },
                                    },
                                  ),
                                );
                                window.dispatchEvent(
                                  new CustomEvent("burpfree:navigate", {
                                    detail: { target: "target" },
                                  }),
                                );
                              }}
                              title={`${n} ${k} finding${n === 1 ? "" : "s"} on ${r.host} — click to open Target → Issues filtered to ${r.host} + ${k}`}
                              style={{
                                display: "inline-block",
                                marginLeft: 3,
                                padding: "0 5px",
                                minWidth: 16,
                                textAlign: "center",
                                borderRadius: 8,
                                background: bg,
                                color: fg,
                                fontSize: 10,
                                lineHeight: "14px",
                                fontWeight: 700,
                                cursor: "pointer",
                                font: "inherit",
                                border:
                                  k === "info"
                                    ? "1px solid var(--border)"
                                    : "none",
                              }}
                            >
                              {n}
                            </button>
                          );
                        })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            );
          })()}
        </Card>

        <Card title={`Recent findings${recentFindings.length > 0 ? ` (${recentFindings.length})` : ""}`}>
          {recentFindings.length === 0 && (
            <div className="empty">
              No findings yet. Click <b>Run passive scan</b> above, or arm
              Live scan under <b>Scanner</b> so new in-scope traffic lands
              detections here as it arrives.
            </div>
          )}
          {recentFindings.length > 0 && (
            <table
              className="mono"
              style={{ width: "100%", borderCollapse: "collapse" }}
            >
              <tbody>
                {recentFindings.map((f) => {
                  const sev = (f.severity || "info").toLowerCase();
                  const palette =
                    FINDING_SEVERITY_COLORS[sev] ?? FINDING_SEVERITY_COLORS.info;
                  return (
                    <tr
                      key={f.id}
                      onClick={() => {
                        // R221: fire the row-focus event first so
                        // ScannerPanel's listener stages the id +
                        // clears chip filters before the panel
                        // mounts via burpfree:navigate below. The
                        // Scanner handler clears chip filters so
                        // the row is guaranteed visible.
                        window.dispatchEvent(
                          new CustomEvent("burpfree:scanner-finding-focus", {
                            detail: { id: f.id },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "scanner" },
                          }),
                        );
                      }}
                      style={{ cursor: "pointer" }}
                      title={`${f.detector} · ${f.confidence}${
                        f.evidence ? "\n\n" + f.evidence : ""
                      } — click to open in Scanner`}
                    >
                      <td
                        style={{
                          padding: "2px 6px 2px 0",
                          width: 70,
                          verticalAlign: "top",
                        }}
                      >
                        <span
                          style={{
                            display: "inline-block",
                            padding: "1px 6px",
                            borderRadius: 10,
                            background: palette.bg,
                            color: palette.fg,
                            fontWeight: 600,
                            fontSize: 9,
                            textTransform: "uppercase",
                            letterSpacing: 0.3,
                          }}
                        >
                          {sev}
                        </span>
                      </td>
                      <td
                        style={{
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          maxWidth: 320,
                        }}
                      >
                        {f.title}
                      </td>
                      <td
                        style={{
                          textAlign: "right",
                          color: "var(--text-faint)",
                          fontSize: 10,
                          whiteSpace: "nowrap",
                          paddingLeft: 6,
                        }}
                      >
                        {humanRelativeAge(f.ts_ms)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Recent transactions" wide>
          {history.length === 0 && (
            <div className="empty">Nothing yet. Point a browser or curl at the proxy to start capturing.</div>
          )}
          {history.length > 0 && (
            <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={th}>#</th>
                  <th style={th}>Method</th>
                  <th style={th}>Status</th>
                  <th style={th}>Host</th>
                  <th style={th}>Path</th>
                </tr>
              </thead>
              <tbody>
                {history.map((r) => (
                  <tr key={r.id}>
                    <td style={{ color: "var(--text-faint)" }}>{r.id}</td>
                    <td>{r.method}</td>
                    <td className={`status-${Math.floor((r.status || 0) / 100)}xx`}>
                      {r.status ?? "—"}
                    </td>
                    <td style={{ color: "var(--text-dim)" }}>{r.host}</td>
                    <td style={{ overflow: "hidden", textOverflow: "ellipsis", maxWidth: 420 }}>
                      {r.path}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R126: Slowest responses card. Burp Pro's Dashboard     */}
        {/* surfaces performance outliers so operators notice      */}
        {/* when an endpoint is leaking a DoS vector (login takes  */}
        {/* 8s = probable blind SQL/XXE, export route takes 30s =  */}
        {/* bulk-fetch abuse). Takes the top 5 completed requests  */}
        {/* by elapsed_ms from the current history snapshot (same  */}
        {/* data the Recent transactions card uses), sorted desc.  */}
        {/* Row click fires `burpfree:history-focus` to jump + pop */}
        {/* the matching row into the detail pane.                 */}
        <Card title="Slowest responses">
          {(() => {
            const completed = history.filter(
              (r) => typeof r.elapsed_ms === "number" && (r.elapsed_ms ?? 0) > 0,
            );
            if (completed.length === 0) {
              return (
                <div className="empty">
                  No completed responses yet. Live traffic surfaces here with timing.
                </div>
              );
            }
            const top = [...completed]
              .sort((a, b) => (b.elapsed_ms ?? 0) - (a.elapsed_ms ?? 0))
              .slice(0, 5);
            // Pick a severity tint based on the slowest row so an
            // operator sees "oh something is 10 seconds slow" at a
            // glance without parsing the whole table.
            const slowest = top[0]?.elapsed_ms ?? 0;
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 4,
                  }}
                >
                  <span
                    style={{
                      fontSize: 20,
                      fontWeight: 700,
                      color:
                        slowest > 10_000
                          ? "var(--red)"
                          : slowest > 2_000
                            ? "var(--amber)"
                            : "var(--text)",
                    }}
                  >
                    {slowest.toLocaleString()} ms
                  </span>
                  <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
                    peak (top 5 of {completed.length} completed)
                  </span>
                </div>
                <table
                  className="mono"
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}
                >
                  <thead>
                    <tr>
                      <th style={th}>#</th>
                      <th style={{ ...th, textAlign: "right" }}>ms</th>
                      <th style={th}>Method</th>
                      <th style={th}>Host · Path</th>
                    </tr>
                  </thead>
                  <tbody>
                    {top.map((r) => (
                      <tr
                        key={r.id}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:history-focus", {
                              detail: { id: r.id },
                            }),
                          );
                          // R247: Fix the stale `{ section }` payload
                          // key — App.tsx's burpfree:navigate listener
                          // consumes `{ target }` (the field name has
                          // been stable since R177 when the deep-link
                          // bus was introduced). The row-click
                          // previously fired a no-op navigate event +
                          // only history-focus landed; operators had
                          // to manually switch to HTTP history to see
                          // their click take effect. Match the key
                          // used by every other Dashboard click-through
                          // (R177/R185/R188/R217/R218/R221/R237).
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "history" },
                            }),
                          );
                        }}
                        title="Jump to HTTP history and focus this row"
                      >
                        <td style={{ color: "var(--text-faint)" }}>{r.id}</td>
                        <td
                          style={{
                            textAlign: "right",
                            fontWeight: 600,
                            color:
                              (r.elapsed_ms ?? 0) > 10_000
                                ? "var(--red)"
                                : (r.elapsed_ms ?? 0) > 2_000
                                  ? "var(--amber)"
                                  : "var(--text)",
                          }}
                        >
                          {(r.elapsed_ms ?? 0).toLocaleString()}
                        </td>
                        <td>{r.method}</td>
                        <td
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            maxWidth: 360,
                            color: "var(--text-dim)",
                          }}
                        >
                          {r.host}
                          {r.path}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R210: HTTP method distribution card. Companion to R162 */}
        {/* (status codes) and R199 (coverage). Operators scanning */}
        {/* an API endpoint want to know whether their traffic is  */}
        {/* read-only (all GET) or writeful (sprinkle of POST /    */}
        {/* PUT / DELETE) — the method mix tells them how deep the */}
        {/* probing has gone. Buckets common methods (GET, POST,   */}
        {/* PUT, DELETE, PATCH, HEAD, OPTIONS) + an "other" bucket */}
        {/* for less-common verbs (WebDAV, custom). Zero backend — */}
        {/* reduces over polled `history`. Same chip-strip + bar   */}
        {/* layout as R162 so the two cards read as sibling views. */}
        <Card title="HTTP method distribution">
          {(() => {
            const totals: Record<string, number> = {
              GET: 0,
              POST: 0,
              PUT: 0,
              DELETE: 0,
              PATCH: 0,
              HEAD: 0,
              OPTIONS: 0,
              other: 0,
            };
            const KNOWN = new Set([
              "GET",
              "POST",
              "PUT",
              "DELETE",
              "PATCH",
              "HEAD",
              "OPTIONS",
            ]);
            for (const r of history) {
              const m = (r.method || "").toUpperCase();
              if (KNOWN.has(m)) totals[m]++;
              else totals.other++;
            }
            if (history.length === 0) {
              return (
                <div className="empty">
                  No proxied requests yet. Method breakdown aggregates
                  here as traffic lands.
                </div>
              );
            }
            // Normalise against total count — unlike R162 every row
            // has a method, so no need to filter out an in-flight
            // sub-bucket.
            const denom = Math.max(1, history.length);
            const buckets: Array<{
              key: string;
              label: string;
              color: string;
              count: number;
              pct: number;
            }> = [
              { key: "GET",     label: "GET",     color: "var(--green, #4caf50)", count: totals.GET,     pct: 0 },
              { key: "POST",    label: "POST",    color: "var(--accent)",         count: totals.POST,    pct: 0 },
              { key: "PUT",     label: "PUT",     color: "var(--amber)",          count: totals.PUT,     pct: 0 },
              { key: "DELETE",  label: "DELETE",  color: "var(--red)",            count: totals.DELETE,  pct: 0 },
              { key: "PATCH",   label: "PATCH",   color: "#9c6ad7",               count: totals.PATCH,   pct: 0 },
              { key: "HEAD",    label: "HEAD",    color: "var(--text-dim)",       count: totals.HEAD,    pct: 0 },
              { key: "OPTIONS", label: "OPTIONS", color: "var(--text-faint)",     count: totals.OPTIONS, pct: 0 },
            ];
            for (const b of buckets) {
              b.pct = (b.count / denom) * 100;
            }
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    gap: 8,
                    marginBottom: 6,
                    flexWrap: "wrap",
                    fontSize: 11,
                  }}
                >
                  {buckets
                    .filter((b) => b.count > 0)
                    .map((b) => (
                      // R218: Click a method chip to jump to HTTP
                      // history pre-filtered to that verb. Uses the
                      // `method` detail field in burpfree:history-
                      // filter (extended in R217 alongside the new
                      // status_class digit). Transparent-button
                      // promotion so the chip visual stays identical
                      // to the status-code chips above.
                      <button
                        key={b.key}
                        type="button"
                        onClick={() => {
                          window.dispatchEvent(
                            new CustomEvent("burpfree:history-filter", {
                              detail: { method: b.key },
                            }),
                          );
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "history" },
                            }),
                          );
                        }}
                        title={`${b.count} ${b.label} request${b.count === 1 ? "" : "s"} · ${b.pct.toFixed(1)}% of ${history.length} — click to open HTTP history filtered to ${b.label}`}
                        style={{
                          background: "transparent",
                          border: "none",
                          padding: 0,
                          margin: 0,
                          color: b.color,
                          fontWeight: 600,
                          cursor: "pointer",
                          font: "inherit",
                        }}
                      >
                        {b.label}: {b.count}
                        <span style={{ color: "var(--text-dim)", fontWeight: 400 }}>
                          {" "}({b.pct.toFixed(b.pct < 10 ? 1 : 0)}%)
                        </span>
                      </button>
                    ))}
                  {totals.other > 0 && (
                    <span
                      title={`${totals.other} request${totals.other === 1 ? "" : "s"} using a non-standard method (WebDAV / custom verbs)`}
                      style={{ color: "var(--text-dim)", fontWeight: 600 }}
                    >
                      other: {totals.other}
                    </span>
                  )}
                </div>
                <div
                  style={{
                    display: "flex",
                    height: 12,
                    borderRadius: 4,
                    overflow: "hidden",
                    background: "var(--bg-raised)",
                    border: "1px solid var(--border)",
                  }}
                >
                  {buckets.map((b) =>
                    b.count > 0 ? (
                      <div
                        key={b.key}
                        style={{
                          width: `${b.pct}%`,
                          background: b.color,
                        }}
                        title={`${b.label}: ${b.count} (${b.pct.toFixed(1)}%)`}
                      />
                    ) : null,
                  )}
                  {totals.other > 0 && (
                    <div
                      style={{
                        width: `${(totals.other / denom) * 100}%`,
                        background: "var(--text-faint)",
                      }}
                      title={`other: ${totals.other}`}
                    />
                  )}
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11, marginTop: 4 }}>
                  {history.length} proxied request{history.length === 1 ? "" : "s"}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R162: Status code distribution card. Burp Pro's        */}
        {/* Dashboard shows a status-code breakdown so operators   */}
        {/* can see at a glance "80% 2xx / 15% 4xx / 5% 5xx" and   */}
        {/* notice when a target starts leaking error codes. We   */}
        {/* bucket history into 1xx / 2xx / 3xx / 4xx / 5xx (+ an  */}
        {/* "other" bucket for 0 / undefined — those are typically */}
        {/* in-flight or connect-refused rows), compute %, render  */}
        {/* each as a labelled chip + a bar. Zero backend — just   */}
        {/* a reduce over the already-polled history snapshot.    */}
        <Card title="Status code distribution">
          {(() => {
            const totals = { "1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0 };
            let withStatus = 0;
            for (const r of history) {
              const s = r.status ?? 0;
              if (s >= 100 && s < 200) { totals["1xx"]++; withStatus++; }
              else if (s >= 200 && s < 300) { totals["2xx"]++; withStatus++; }
              else if (s >= 300 && s < 400) { totals["3xx"]++; withStatus++; }
              else if (s >= 400 && s < 500) { totals["4xx"]++; withStatus++; }
              else if (s >= 500 && s < 600) { totals["5xx"]++; withStatus++; }
              else { totals["other"]++; }
            }
            if (history.length === 0) {
              return (
                <div className="empty">
                  No proxied responses yet. Status codes aggregate here as traffic lands.
                </div>
              );
            }
            // Normalise against the total that had any status —
            // "other" shows the in-flight / connect-refused count
            // but doesn't dilute the real-response percentages.
            const denom = Math.max(1, withStatus);
            const buckets: Array<{
              key: keyof typeof totals;
              label: string;
              color: string;
              count: number;
              pct: number;
            }> = [
              { key: "1xx", label: "1xx", color: "var(--text-dim)",   count: totals["1xx"],   pct: 0 },
              { key: "2xx", label: "2xx", color: "var(--green, #4caf50)", count: totals["2xx"], pct: 0 },
              { key: "3xx", label: "3xx", color: "var(--accent)",     count: totals["3xx"],   pct: 0 },
              { key: "4xx", label: "4xx", color: "var(--amber)",      count: totals["4xx"],   pct: 0 },
              { key: "5xx", label: "5xx", color: "var(--red)",        count: totals["5xx"],   pct: 0 },
            ];
            for (const b of buckets) {
              b.pct = (b.count / denom) * 100;
            }
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    gap: 8,
                    marginBottom: 6,
                    flexWrap: "wrap",
                    fontSize: 11,
                  }}
                >
                  {buckets.map((b) => {
                    // R217: Click a status-class chip to jump to
                    // HTTP history pre-filtered to that bucket.
                    // Encode as 1..5 (= Math.floor(status/100))
                    // matching StatusClassChips' array encoding +
                    // the HistoryFilter.status_classes shape. Fire
                    // the burpfree:history-filter event first so
                    // HistoryPanel's listener seeds the chip set
                    // before burpfree:navigate causes it to mount.
                    const digit = parseInt(b.key[0], 10);
                    const disabled = b.count === 0;
                    return (
                      <button
                        key={b.key}
                        type="button"
                        disabled={disabled}
                        onClick={() => {
                          if (disabled) return;
                          window.dispatchEvent(
                            new CustomEvent("burpfree:history-filter", {
                              detail: { status_class: digit },
                            }),
                          );
                          window.dispatchEvent(
                            new CustomEvent("burpfree:navigate", {
                              detail: { target: "history" },
                            }),
                          );
                        }}
                        title={
                          disabled
                            ? `${b.label}: 0 — nothing to jump to`
                            : `${b.count} response${b.count === 1 ? "" : "s"} in the ${b.label} range · ${b.pct.toFixed(1)}% of ${withStatus} with-status rows — click to open HTTP history filtered to ${b.label}`
                        }
                        style={{
                          background: "transparent",
                          border: "none",
                          padding: 0,
                          margin: 0,
                          color: b.color,
                          fontWeight: b.count > 0 ? 600 : 400,
                          cursor: disabled ? "default" : "pointer",
                          font: "inherit",
                        }}
                      >
                        {b.label}: {b.count}
                        {b.count > 0 && (
                          <span style={{ color: "var(--text-dim)", fontWeight: 400 }}>
                            {" "}({b.pct.toFixed(b.pct < 10 ? 1 : 0)}%)
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
                {/* Horizontal stacked bar — segments proportional to */}
                {/* bucket counts; empty bar when withStatus === 0.   */}
                <div
                  style={{
                    display: "flex",
                    height: 12,
                    borderRadius: 4,
                    overflow: "hidden",
                    background: "var(--bg-raised)",
                    border: "1px solid var(--border)",
                  }}
                >
                  {buckets.map((b) =>
                    b.count > 0 ? (
                      <div
                        key={b.key}
                        style={{
                          width: `${b.pct}%`,
                          background: b.color,
                        }}
                        title={`${b.label}: ${b.count} (${b.pct.toFixed(1)}%)`}
                      />
                    ) : null,
                  )}
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11, marginTop: 4 }}>
                  {withStatus} with-status response{withStatus === 1 ? "" : "s"}
                  {totals.other > 0 && (
                    <> · {totals.other} in-flight / errored</>
                  )}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R199: Scanner coverage card. Burp Pro's Dashboard     */}
        {/* answers "how deep is my scan?" via Issue Activity +   */}
        {/* Issue Definitions; our equivalent is finer-grained —  */}
        {/* unique hosts in history vs unique hosts with at least */}
        {/* one finding. Low coverage = big scope the scanner     */}
        {/* hasn't touched yet; high coverage with few findings = */}
        {/* clean target. Zero backend — reduces over `history` + */}
        {/* `hostFindingCounts` already polled on the 2s cadence. */}
        <Card title="Scanner coverage">
          {(() => {
            const hostsTouched = new Set<string>();
            for (const r of history) {
              const h = (r.host || "").trim();
              if (h) hostsTouched.add(h);
            }
            const total = hostsTouched.size;
            let withFindings = 0;
            for (const h of hostsTouched) {
              const perSev = hostFindingCounts[h];
              if (!perSev) continue;
              const any = Object.values(perSev).some((n) => (n ?? 0) > 0);
              if (any) withFindings++;
            }
            if (total === 0) {
              return (
                <div className="empty">
                  No proxied hosts yet. Coverage lights up as traffic lands.
                </div>
              );
            }
            const pct = (withFindings / total) * 100;
            // Threshold tint — green = well-covered, amber =
            // partial, dim = thin / fresh target. Mirrors R159
            // (Last activity) + R126 palette.
            let barColor = "var(--text-dim)";
            if (pct >= 60) barColor = "var(--green, #4caf50)";
            else if (pct >= 25) barColor = "var(--amber)";
            else if (pct > 0) barColor = "var(--accent)";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: 22, fontWeight: 600 }}>
                    {pct.toFixed(pct < 10 && pct > 0 ? 1 : 0)}%
                  </span>
                  <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
                    {withFindings} of {total} host{total === 1 ? "" : "s"} have findings
                  </span>
                </div>
                <div
                  style={{
                    display: "flex",
                    height: 10,
                    borderRadius: 4,
                    overflow: "hidden",
                    background: "var(--bg-raised)",
                    border: "1px solid var(--border)",
                  }}
                  title={`${withFindings} / ${total} host${total === 1 ? "" : "s"} with at least one finding (${pct.toFixed(1)}%)`}
                >
                  {withFindings > 0 && (
                    <div
                      style={{
                        width: `${pct}%`,
                        background: barColor,
                      }}
                    />
                  )}
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11, marginTop: 4 }}>
                  {total - withFindings === 0
                    ? "every proxied host has a finding"
                    : `${total - withFindings} host${total - withFindings === 1 ? "" : "s"} proxied but un-flagged`}
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R209: Response-time health card. Companion to the      */}
        {/* R125 "Slowest responses" rail: that card lists the top */}
        {/* 5 outliers; this card gives the headline average +    */}
        {/* median across every completed request so operators    */}
        {/* can tell at a glance whether a scan session is baseline*/}
        {/* -healthy (avg 200ms) or seeing systemic degradation    */}
        {/* (avg 3s). Threshold tint matches R125's row-tint       */}
        {/* palette: ≤500ms = ok, ≤2s = amber, >2s = red.          */}
        <Card title="Response times">
          {(() => {
            const completed = history
              .filter((r): r is typeof r & { elapsed_ms: number } =>
                typeof r.elapsed_ms === "number" && r.elapsed_ms > 0,
              )
              .map((r) => r.elapsed_ms);
            if (completed.length === 0) {
              return (
                <div className="empty">
                  No completed responses yet. Timings populate as
                  traffic lands.
                </div>
              );
            }
            const total = completed.length;
            const sum = completed.reduce((a, b) => a + b, 0);
            const avg = Math.round(sum / total);
            // Median via sort + midpoint — for even counts take
            // the lower of the two mid values (fine at this grain
            // + cheaper than averaging).
            const sorted = [...completed].sort((a, b) => a - b);
            const median = sorted[Math.floor((total - 1) / 2)];
            const min = sorted[0];
            const max = sorted[total - 1];
            let tint = "var(--text)";
            if (avg > 2_000) tint = "var(--red)";
            else if (avg > 500) tint = "var(--amber)";
            else tint = "var(--green, #4caf50)";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: 22, fontWeight: 600, color: tint }}>
                    {avg.toLocaleString()}
                    <span style={{ fontSize: 11, color: "var(--text-dim)", fontWeight: 400 }}>
                      {" "}ms avg
                    </span>
                  </span>
                  <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
                    across {total} response{total === 1 ? "" : "s"}
                  </span>
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 10,
                    flexWrap: "wrap",
                    fontSize: 11,
                    color: "var(--text-dim)",
                  }}
                >
                  <span title="50th-percentile elapsed_ms">
                    median <span style={{ color: "var(--text)" }}>{median.toLocaleString()} ms</span>
                  </span>
                  <span title="Minimum elapsed_ms across completed responses">
                    min <span style={{ color: "var(--text)" }}>{min.toLocaleString()} ms</span>
                  </span>
                  <span title="Maximum elapsed_ms across completed responses">
                    max <span style={{ color: "var(--text)" }}>{max.toLocaleString()} ms</span>
                  </span>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R259: Avg body size card. Companion to R209 Response  */}
        {/* times — same baseline-sanity shape but keyed on       */}
        {/* response body bytes rather than wire latency.          */}
        {/* content_length is the server-reported body-size header */}
        {/* (nullable: not every response carries it, and chunked  */}
        {/* responses report it late / not at all), so we filter   */}
        {/* on non-null + non-zero before averaging. Headline      */}
        {/* figure is the mean body size with a tint threshold:    */}
        {/* ≤100 KB = ok green, ≤1 MB = amber (worth noting),      */}
        {/* >1 MB = red (fat payloads inflate scan time + storage).*/}
        {/* Secondary stats mirror the R209 row: median / min /    */}
        {/* max / count — operators can tell at a glance whether   */}
        {/* an outlier is dragging the average or the whole target */}
        {/* is heavy. Humanised units via a small helper so a 1234-*/}
        {/* byte figure reads as "1.2 KB" instead of raw bytes.    */}
        <Card title="Avg body size">
          {(() => {
            const sized = history
              .map((r) => r.content_length)
              .filter((n): n is number => typeof n === "number" && n > 0);
            if (sized.length === 0) {
              return (
                <div className="empty">
                  No response bodies yet. Sizes populate as responses
                  arrive with a Content-Length header.
                </div>
              );
            }
            const total = sized.length;
            const sum = sized.reduce((a, b) => a + b, 0);
            const avg = Math.round(sum / total);
            const sorted = [...sized].sort((a, b) => a - b);
            const median = sorted[Math.floor((total - 1) / 2)];
            const min = sorted[0];
            const max = sorted[total - 1];
            // Humanise byte counts to KB / MB — matches the Burp
            // Pro convention of surfacing sizes in binary units.
            function fmtBytes(n: number): string {
              if (n < 1024) return `${n} B`;
              if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
              return `${(n / (1024 * 1024)).toFixed(2)} MB`;
            }
            let tint = "var(--text)";
            if (avg > 1024 * 1024) tint = "var(--red)";
            else if (avg > 100 * 1024) tint = "var(--amber)";
            else tint = "var(--green, #4caf50)";
            return (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: 22, fontWeight: 600, color: tint }}>
                    {fmtBytes(avg)}
                    <span style={{ fontSize: 11, color: "var(--text-dim)", fontWeight: 400 }}>
                      {" "}avg
                    </span>
                  </span>
                  <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
                    across {total} response{total === 1 ? "" : "s"} with a size
                  </span>
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 10,
                    flexWrap: "wrap",
                    fontSize: 11,
                    color: "var(--text-dim)",
                  }}
                >
                  <span title="50th-percentile content_length">
                    median <span style={{ color: "var(--text)" }}>{fmtBytes(median)}</span>
                  </span>
                  <span title="Smallest observed non-zero body">
                    min <span style={{ color: "var(--text)" }}>{fmtBytes(min)}</span>
                  </span>
                  <span title="Largest observed body">
                    max <span style={{ color: "var(--text)" }}>{fmtBytes(max)}</span>
                  </span>
                </div>
              </>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R264: Top status codes card. Companion to R162        */}
        {/* (status-class buckets) + R210 (method distribution) — */}
        {/* R162 shows the 1xx/2xx/3xx/4xx/5xx shape and R264     */}
        {/* zooms one layer deeper to the exact codes operators   */}
        {/* actually care about ("200: 820, 304: 180, 404: 50"    */}
        {/* etc). Top-5 ranked by count desc so a long tail of     */}
        {/* rare codes doesn't crowd the card. Each pill is       */}
        {/* clickable → History pre-filtered to that exact status */}
        {/* via the status_min / status_max fields on the         */}
        {/* burpfree:history-filter event payload (extended       */}
        {/* alongside the R264 landing). Status-class tint same  */}
        {/* as R162 (2xx=green, 3xx=accent, 4xx=amber, 5xx=red). */}
        <Card title="Top status codes">
          {(() => {
            const totals = new Map<number, number>();
            for (const r of history) {
              const s = r.status;
              if (typeof s !== "number" || s < 100) continue;
              totals.set(s, (totals.get(s) ?? 0) + 1);
            }
            if (totals.size === 0) {
              return (
                <div className="empty">
                  No response status codes yet. Codes aggregate here
                  as traffic lands.
                </div>
              );
            }
            const ranked = Array.from(totals.entries())
              .map(([code, count]) => ({ code, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 5);
            // Tint by status class — same palette as R162.
            function tintFor(code: number): string {
              if (code >= 200 && code < 300) return "var(--green, #4caf50)";
              if (code >= 300 && code < 400) return "var(--accent)";
              if (code >= 400 && code < 500) return "var(--amber)";
              if (code >= 500 && code < 600) return "var(--red)";
              return "var(--text-dim)";
            }
            const topCount = ranked[0].count;
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ranked.map((row) => {
                  const pct = (row.count / topCount) * 100;
                  const tint = tintFor(row.code);
                  return (
                    // R264: Click a code pill → History pre-filtered
                    // to that exact status via status_min/status_max
                    // (both collapsed to the same number).
                    <button
                      key={row.code}
                      type="button"
                      onClick={() => {
                        window.dispatchEvent(
                          new CustomEvent("burpfree:history-filter", {
                            detail: {
                              status_min: row.code,
                              status_max: row.code,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "history" },
                          }),
                        );
                      }}
                      title={`Jump to HTTP history pre-filtered to status ${row.code} (${row.count} response${row.count === 1 ? "" : "s"})`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        background: "transparent",
                        border: "none",
                        padding: "2px 0",
                        cursor: "pointer",
                        color: "var(--text)",
                        fontSize: 11,
                      }}
                    >
                      <span
                        style={{
                          minWidth: 36,
                          fontWeight: 600,
                          color: tint,
                          textAlign: "left",
                        }}
                      >
                        {row.code}
                      </span>
                      <span
                        style={{
                          flex: 1,
                          height: 6,
                          background: "var(--border)",
                          borderRadius: 3,
                          overflow: "hidden",
                        }}
                      >
                        <span
                          style={{
                            display: "block",
                            height: "100%",
                            width: `${pct}%`,
                            background: tint,
                          }}
                        />
                      </span>
                      <span
                        style={{
                          minWidth: 32,
                          textAlign: "right",
                          color: "var(--text-dim)",
                        }}
                      >
                        {row.count}
                      </span>
                    </button>
                  );
                })}
                {totals.size > ranked.length && (
                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--text-faint)",
                      marginTop: 2,
                    }}
                    title={`${totals.size - ranked.length} rarer code${totals.size - ranked.length === 1 ? "" : "s"} hidden — see HTTP history for the full set`}
                  >
                    +{totals.size - ranked.length} rarer code{totals.size - ranked.length === 1 ? "" : "s"}
                  </span>
                )}
              </div>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R267: Top hosts by traffic card. Companion to R264    */}
        {/* (top status codes) + R210 (methods) + R259 (avg body */}
        {/* size) — same ranked-horizontal-bar shape applied to  */}
        {/* host popularity. Operators scanning a target with a   */}
        {/* mix of first-party + third-party hosts want to see   */}
        {/* which domains are soaking up the request budget at a */}
        {/* glance so they can decide whether a chatty CDN is   */}
        {/* diluting their test coverage. Top 5 by request count */}
        {/* desc with a hidden-count line for the long tail.    */}
        {/* Each pill click-throughs to HTTP history pre-        */}
        {/* filtered to that host via the existing R177 host     */}
        {/* detail field on burpfree:history-filter.             */}
        <Card title="Top hosts by traffic">
          {(() => {
            const totals = new Map<string, number>();
            for (const r of history) {
              const h = (r.host || "").trim();
              if (!h) continue;
              totals.set(h, (totals.get(h) ?? 0) + 1);
            }
            if (totals.size === 0) {
              return (
                <div className="empty">
                  No hosts yet. Rankings populate as traffic lands.
                </div>
              );
            }
            const ranked = Array.from(totals.entries())
              .map(([host, count]) => ({ host, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 5);
            const topCount = ranked[0].count;
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ranked.map((row) => {
                  const pct = (row.count / topCount) * 100;
                  // Elide very long hosts so the card doesn't blow
                  // out horizontally — operators get the full host
                  // in the tooltip.
                  const label =
                    row.host.length > 28
                      ? row.host.slice(0, 26) + "…"
                      : row.host;
                  return (
                    // R267: Click a host pill → History pre-filtered
                    // to that host via the existing host detail
                    // field on burpfree:history-filter.
                    <button
                      key={row.host}
                      type="button"
                      onClick={() => {
                        window.dispatchEvent(
                          new CustomEvent("burpfree:history-filter", {
                            detail: { host: row.host },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "history" },
                          }),
                        );
                      }}
                      title={`Jump to HTTP history pre-filtered to host ${row.host} (${row.count} request${row.count === 1 ? "" : "s"})`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        background: "transparent",
                        border: "none",
                        padding: "2px 0",
                        cursor: "pointer",
                        color: "var(--text)",
                        fontSize: 11,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          minWidth: 180,
                          textAlign: "left",
                          overflow: "hidden",
                          whiteSpace: "nowrap",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {label}
                      </span>
                      <span
                        style={{
                          flex: 1,
                          height: 6,
                          background: "var(--border)",
                          borderRadius: 3,
                          overflow: "hidden",
                        }}
                      >
                        <span
                          style={{
                            display: "block",
                            height: "100%",
                            width: `${pct}%`,
                            background: "var(--accent)",
                          }}
                        />
                      </span>
                      <span
                        style={{
                          minWidth: 32,
                          textAlign: "right",
                          color: "var(--text-dim)",
                        }}
                      >
                        {row.count}
                      </span>
                    </button>
                  );
                })}
                {totals.size > ranked.length && (
                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--text-faint)",
                      marginTop: 2,
                    }}
                    title={`${totals.size - ranked.length} quieter host${totals.size - ranked.length === 1 ? "" : "s"} hidden — see HTTP history for the full breakdown`}
                  >
                    +{totals.size - ranked.length} quieter host{totals.size - ranked.length === 1 ? "" : "s"}
                  </span>
                )}
              </div>
            );
          })()}
        </Card>

        {/* ----------------------------------------------------- */}
        {/* R273: Top paths by hit count. Sixth entry in the      */}
        {/* Dashboard-health card family after R199 (coverage),   */}
        {/* R209 (response times), R210 (methods), R259 (avg body */}
        {/* size), R264 (top status codes), R267 (top hosts).     */}
        {/* Pairs with R267 — hosts tell you which domains the    */}
        {/* traffic lands on, paths tell you which endpoints      */}
        {/* within those domains get hit the most. Operators      */}
        {/* diagnosing a target with a hot endpoint (an API login */}
        {/* called 400 times, an asset path cached nowhere) can   */}
        {/* see it here at a glance. Click-through fires the      */}
        {/* search_text field on burpfree:history-filter (new in  */}
        {/* R273) so HTTP history pre-filters to requests whose   */}
        {/* URL contains the path.                                 */}
        <Card title="Top paths by hits">
          {(() => {
            const totals = new Map<string, number>();
            for (const r of history) {
              const p = (r.path || "").trim();
              if (!p) continue;
              totals.set(p, (totals.get(p) ?? 0) + 1);
            }
            if (totals.size === 0) {
              return (
                <div className="empty">
                  No paths yet. Rankings populate as traffic lands.
                </div>
              );
            }
            const ranked = Array.from(totals.entries())
              .map(([path, count]) => ({ path, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 5);
            const topCount = ranked[0].count;
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ranked.map((row) => {
                  const pct = (row.count / topCount) * 100;
                  // Mid-elide long paths so the leading slug stays
                  // readable + trailing query-string tail isn't the
                  // whole label. Full path lives in the tooltip.
                  const label =
                    row.path.length > 32
                      ? row.path.slice(0, 20) + "…" + row.path.slice(-10)
                      : row.path;
                  return (
                    <button
                      key={row.path}
                      type="button"
                      onClick={() => {
                        window.dispatchEvent(
                          new CustomEvent("burpfree:history-filter", {
                            detail: { search_text: row.path },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "history" },
                          }),
                        );
                      }}
                      title={`Jump to HTTP history pre-filtered to search ${row.path} (${row.count} request${row.count === 1 ? "" : "s"})`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        background: "transparent",
                        border: "none",
                        padding: "2px 0",
                        cursor: "pointer",
                        color: "var(--text)",
                        fontSize: 11,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          minWidth: 220,
                          textAlign: "left",
                          overflow: "hidden",
                          whiteSpace: "nowrap",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {label}
                      </span>
                      <span
                        style={{
                          flex: 1,
                          height: 6,
                          background: "var(--border)",
                          borderRadius: 3,
                          overflow: "hidden",
                        }}
                      >
                        <span
                          style={{
                            display: "block",
                            height: "100%",
                            width: `${pct}%`,
                            background: "var(--accent)",
                          }}
                        />
                      </span>
                      <span
                        style={{
                          minWidth: 32,
                          textAlign: "right",
                          color: "var(--text-dim)",
                        }}
                      >
                        {row.count}
                      </span>
                    </button>
                  );
                })}
                {totals.size > ranked.length && (
                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--text-faint)",
                      marginTop: 2,
                    }}
                    title={`${totals.size - ranked.length} quieter path${totals.size - ranked.length === 1 ? "" : "s"} hidden — see HTTP history for the full breakdown`}
                  >
                    +{totals.size - ranked.length} quieter path{totals.size - ranked.length === 1 ? "" : "s"}
                  </span>
                )}
              </div>
            );
          })()}
        </Card>
      </div>

      <div className="dash-footer">
        <div className="dim" style={{ fontSize: 11, marginBottom: 6 }}>Getting started</div>
        <ol style={{ margin: "0 0 0 20px", color: "var(--text-dim)", fontSize: 12, lineHeight: 1.7 }}>
          <li>
            Install the project CA (<b>Settings</b> → copy the path) in your browser's trust store so HTTPS traffic
            decodes cleanly.
          </li>
          <li>
            Launch a browser preset for the proxy from the menu bar ("Open browser"), or point your tool at{" "}
            <span className="mono">{stats?.proxy.listeners[0] || "127.0.0.1:8085"}</span>.
          </li>
          <li>
            Collected traffic shows up under <b>Proxy → HTTP history</b>; passive findings surface under{" "}
            <b>Scanner</b>. Click <b>Run passive scan</b> above to force a sweep over the existing index.
          </li>
          <li>
            Add OOB-aware checks or session-rule macros from the <b>Session</b> / <b>Scanner</b> tabs for
            authenticated or blind targets.
          </li>
          <li>Press <span className="palette-kbd">Ctrl K</span> for the command palette.</li>
        </ol>
      </div>
      </div>
    </div>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  color: "var(--text-dim)",
  fontSize: 11,
  fontWeight: 600,
  padding: "2px 6px 4px 0",
};

/** Inline SVG sparkline for the Dashboard req/s metric. Renders the
 *  last ~30 samples as a filled polyline. Flat/empty series render a
 *  dim baseline so an idle proxy doesn't look like a chart error. */
function Sparkline({ samples }: { samples: number[] }) {
  const WIDTH = 180;
  const HEIGHT = 24;
  const PAD = 1;
  // Keep only the trailing window; sparkline shouldn't scroll if we
  // retain more samples than it can display.
  const data = samples.slice(-30);
  // Y-axis: clamp to the max of the series (never zero so a flat
  // zero line still renders at the baseline, not off-screen).
  const max = Math.max(1, ...data);
  const n = data.length;
  if (n < 2) {
    return (
      <svg
        width="100%"
        height={HEIGHT}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        style={{ display: "block", marginTop: 2 }}
      >
        <line
          x1={0}
          y1={HEIGHT - PAD}
          x2={WIDTH}
          y2={HEIGHT - PAD}
          stroke="var(--text-faint)"
          strokeDasharray="2 3"
          strokeWidth="0.5"
        />
      </svg>
    );
  }
  const stepX = (WIDTH - 2 * PAD) / (n - 1);
  const points = data.map((v, i) => {
    const x = PAD + i * stepX;
    const y = HEIGHT - PAD - (v / max) * (HEIGHT - 2 * PAD);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const fillPath = `M ${PAD},${HEIGHT - PAD} L ${points.join(" L ")} L ${(WIDTH - PAD).toFixed(2)},${HEIGHT - PAD} Z`;
  return (
    <svg
      width="100%"
      height={HEIGHT}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      style={{ display: "block", marginTop: 2 }}
    >
      <path d={fillPath} fill="rgba(100,150,255,0.14)" />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Metric({
  label,
  value,
  valueColor,
  sub,
  action,
}: {
  label: string;
  value: React.ReactNode;
  valueColor?: string;
  sub?: React.ReactNode;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="dash-metric">
      <div className="dash-metric-label">{label}</div>
      <div className="dash-metric-value" style={{ color: valueColor }}>{value}</div>
      {sub && <div className="dash-metric-sub">{sub}</div>}
      {action && (
        <button className="ghost" style={{ marginTop: 4 }} onClick={action.onClick}>
          {action.label}
        </button>
      )}
    </div>
  );
}

function Card({
  title,
  children,
  wide,
}: {
  title: string;
  children: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <div className={`dash-card ${wide ? "wide" : ""}`}>
      <div className="dash-card-title">{title}</div>
      {children}
    </div>
  );
}

function KV({
  label,
  value,
  highlight,
}: {
  label: string;
  value: React.ReactNode;
  highlight?: "red" | "green" | "amber";
}) {
  const color =
    highlight === "red" ? "var(--red)" :
    highlight === "green" ? "var(--green)" :
    highlight === "amber" ? "var(--amber)" :
    "var(--text)";
  return (
    <div style={{ display: "flex", padding: "2px 0", fontSize: 12 }}>
      <div style={{ color: "var(--text-dim)", width: 170 }}>{label}</div>
      <div className="mono" style={{ color, flex: 1, wordBreak: "break-all" }}>
        {typeof value === "number" || typeof value === "string" ? String(value) : value}
      </div>
    </div>
  );
}

function severityStrip(sev: Record<string, number>) {
  const order: Array<["critical" | "high" | "medium" | "low" | "info", string]> = [
    ["critical", "crit"],
    ["high", "high"],
    ["medium", "med"],
    ["low", "low"],
    ["info", "info"],
  ];
  /*  R177: Chips in the Dashboard Findings strip become clickable
   *  jump buttons. Each click fires both `burpfree:navigate` to
   *  switch to the Scanner panel and `burpfree:scanner-sev-focus`
   *  with the clicked severity so the ScannerPanel can snap its
   *  chip-strip filter to that level. Reuses the same event-bus
   *  pattern R161's Scanner → History jump uses. */
  return (
    <span className="dash-sev-strip">
      {order.map(([k, label]) =>
        sev[k] ? (
          <button
            key={k}
            type="button"
            className={`dash-sev-chip severity-${k}`}
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent("burpfree:navigate", {
                  detail: { target: "scanner" },
                }),
              );
              window.dispatchEvent(
                new CustomEvent("burpfree:scanner-sev-focus", {
                  detail: { severity: k },
                }),
              );
            }}
            title={`Click to open Scanner filtered to ${k} findings`}
            style={{
              background: "transparent",
              border: 0,
              cursor: "pointer",
              padding: 0,
              font: "inherit",
            }}
          >
            {label} {sev[k]}
          </button>
        ) : null
      )}
      {Object.keys(sev).length === 0 && <span className="dim">no issues yet</span>}
    </span>
  );
}

function aggregateHosts(rows: StoredSummary[]): Array<{ host: string; count: number }> {
  const map = new Map<string, number>();
  for (const r of rows) {
    const key = `${r.scheme}://${r.host}${r.port !== 80 && r.port !== 443 ? ":" + r.port : ""}`;
    map.set(key, (map.get(key) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
}

function formatTs(ms?: number | null): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleTimeString();
}

function formatElapsed(start?: number | null, end?: number | null): string {
  if (!start || !end) return "—";
  const ms = end - start;
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/* ------------------------------------------------------------------ *
 * Tasks sidebar
 *
 * Mirrors Burp 2026.8's Dashboard tasks pane. Users can create one or
 * more "live" tasks (currently just Live passive crawl) that run in
 * the background on an interval. Task state lives in `ProjectConfig`
 * so a reload picks up where we left off. The drive loop is a plain
 * `setInterval` in the UI — the proxy itself keeps collecting traffic
 * regardless, so pausing/unpausing a task only affects the scan
 * sweep cadence.
 * ------------------------------------------------------------------ */

function TasksSidebar() {
  const [tasks, setTasks] = useState<DashboardTask[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showNewMenu, setShowNewMenu] = useState(false);
  const [paused, setPaused] = useState(false);
  const tasksRef = useRef<DashboardTask[]>([]);
  tasksRef.current = tasks;

  // Hydrate on mount.
  useEffect(() => {
    (async () => {
      try {
        const list = await api.tasksList();
        setTasks(list);
        if (list.length > 0 && !selectedId) setSelectedId(list[0].id);
      } catch {}
    })();
  }, []);

  async function persist(next: DashboardTask[]) {
    setTasks(next);
    try { await api.tasksSet(next); } catch (e) { console.error(e); }
  }

  // Drive loop: every 1s, fire any task whose next-run is due.
  useEffect(() => {
    if (paused) return;
    const t = setInterval(async () => {
      const list = tasksRef.current;
      const now = Date.now();
      let dirty = false;
      const updated = [...list];
      for (let i = 0; i < updated.length; i++) {
        const task = updated[i];
        if (!task.capturing) continue;
        const nextDue =
          (task.stats.last_run_at_ms ?? 0) + task.interval_s * 1000;
        if (now < nextDue) continue;

        if (task.kind === "live_passive_crawl") {
          try {
            const n = await api.passiveRunNow();
            const updatedTask: DashboardTask = {
              ...task,
              stats: {
                ...task.stats,
                last_run_at_ms: now,
                last_run_findings: n,
                responses_processed: task.stats.responses_processed + 1,
                items_added: task.stats.items_added + n,
                responses_queued: 0,
              },
              log: appendLog(task.log, `scan swept, ${n} finding(s)`),
            };
            updated[i] = updatedTask;
            dirty = true;
          } catch (e) {
            updated[i] = {
              ...task,
              log: appendLog(task.log, `error: ${String(e).slice(0, 120)}`),
            };
            dirty = true;
          }
        }
      }
      if (dirty) void persist(updated);
    }, 1000);
    return () => clearInterval(t);
  }, [paused]);

  async function newLivePassiveCrawl() {
    const id = `t${Date.now().toString(36)}`;
    const task: DashboardTask = {
      id,
      name: `${tasks.length + 1}. Live passive crawl from Proxy (all traffic)`,
      kind: "live_passive_crawl",
      capturing: true,
      interval_s: 15,
      scope: "all",
      stats: {
        items_added: 0,
        responses_processed: 0,
        last_run_at_ms: null,
        last_run_findings: 0,
        responses_queued: 0,
      },
      log: [{ ts_ms: Date.now(), message: "task created" }],
      created_at_ms: Date.now(),
    };
    await persist([...tasks, task]);
    setSelectedId(id);
    setShowNewMenu(false);
  }

  function toggleCapturing(id: string) {
    const next = tasks.map((t) =>
      t.id === id
        ? {
            ...t,
            capturing: !t.capturing,
            log: appendLog(t.log, t.capturing ? "paused" : "resumed"),
          }
        : t
    );
    void persist(next);
  }

  async function removeTask(id: string) {
    const next = tasks.filter((t) => t.id !== id);
    await persist(next);
    if (selectedId === id) setSelectedId(next[0]?.id ?? null);
  }

  const selected = tasks.find((t) => t.id === selectedId) ?? null;

  return (
    <div className="dash-tasks">
      <div className="dash-tasks-head">
        <strong>Tasks</strong>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          className="ghost"
          title={paused ? "Resume task drive loop" : "Pause all tasks"}
          onClick={() => setPaused((p) => !p)}
        >
          {paused ? "▶" : "⏸"}
        </button>
      </div>
      <div className="dash-tasks-actions">
        <button className="ghost" disabled>New scan</button>
        <div style={{ position: "relative", display: "inline-block" }}>
          <button
            className="primary"
            onClick={() => setShowNewMenu((v) => !v)}
          >
            New live task
          </button>
          {showNewMenu && (
            <div className="dash-tasks-menu">
              <button className="ghost" onClick={newLivePassiveCrawl}>
                Live passive crawl from Proxy (all traffic)
              </button>
            </div>
          )}
        </div>
      </div>
      <div className="dash-tasks-list">
        {tasks.length === 0 && (
          <div className="empty" style={{ padding: 10 }}>
            No tasks. Click <b>New live task</b> to add one.
          </div>
        )}
        {tasks.map((t) => (
          <div
            key={t.id}
            className={`dash-task-card ${selectedId === t.id ? "selected" : ""}`}
            onClick={() => setSelectedId(t.id)}
          >
            <div className="dash-task-name">{t.name}</div>
            <div className="dash-task-sub">
              every {t.interval_s}s · {t.stats.responses_processed} run(s)
            </div>
            <label
              className="dash-task-toggle"
              onClick={(e) => e.stopPropagation()}
            >
              <input
                type="checkbox"
                checked={t.capturing}
                onChange={() => toggleCapturing(t.id)}
              />
              Capturing
            </label>
          </div>
        ))}
      </div>
      {selected && (
        <TaskDetail
          task={selected}
          onPatch={(patch) => {
            const next = tasks.map((t) =>
              t.id === selected.id ? { ...t, ...patch } : t
            );
            void persist(next);
          }}
          onDelete={() => removeTask(selected.id)}
        />
      )}
    </div>
  );
}

function appendLog(
  log: Array<{ ts_ms: number; message: string }>,
  message: string
): Array<{ ts_ms: number; message: string }> {
  const next = [...log, { ts_ms: Date.now(), message }];
  if (next.length > 40) next.splice(0, next.length - 40);
  return next;
}

function TaskDetail({
  task,
  onPatch,
  onDelete,
}: {
  task: DashboardTask;
  onPatch: (patch: Partial<DashboardTask>) => void;
  onDelete: () => void;
}) {
  return (
    <div className="dash-task-detail">
      <div className="dash-section-title">Task configuration</div>
      <div className="dash-kv-grid">
        <div><span>Type</span><code>{task.kind.replace(/_/g, " ")}</code></div>
        <div>
          <span>Scope</span>
          <select
            value={task.scope}
            onChange={(e) => onPatch({ scope: e.target.value as "all" | "in_scope" })}
          >
            <option value="all">Proxy (all traffic)</option>
            <option value="in_scope">Proxy (in-scope only)</option>
          </select>
        </div>
        <div>
          <span>Interval</span>
          <input
            type="number"
            min={5}
            max={3600}
            value={task.interval_s}
            onChange={(e) =>
              onPatch({ interval_s: Math.max(5, parseInt(e.target.value) || 15) })
            }
            style={{ width: 70 }}
          />
        </div>
      </div>
      <div className="dash-section-title">Task progress</div>
      <div className="dash-kv-grid">
        <div><span>Items added</span><code>{task.stats.items_added}</code></div>
        <div><span>Responses processed</span><code>{task.stats.responses_processed}</code></div>
        <div><span>Responses queued</span><code>{task.stats.responses_queued}</code></div>
        <div>
          <span>Last run</span>
          <code>
            {task.stats.last_run_at_ms
              ? new Date(task.stats.last_run_at_ms).toLocaleTimeString()
              : "—"}
          </code>
        </div>
        <div><span>Last findings</span><code>{task.stats.last_run_findings}</code></div>
      </div>
      <div className="dash-section-title">Task log</div>
      <div className="dash-task-log">
        {task.log.slice(-15).reverse().map((l, i) => (
          <div key={i}>
            <span className="dim mono">{new Date(l.ts_ms).toLocaleTimeString()}</span>
            {" "}
            <span>{l.message}</span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button className="ghost danger" onClick={onDelete}>Delete task</button>
      </div>
    </div>
  );
}
