// CollaboratorPanel.tsx
//
// Top-level tab that surfaces the OOB (out-of-band) listener as a
// first-class capability — the BurpFree equivalent of Burp's
// Collaborator client. Operators can:
//
//   • Start / stop the embedded HTTP + DNS listener
//   • Mint fresh correlation payloads (http_url + dns_name)
//   • Watch incoming interactions update live
//
// The server itself is unchanged; this panel just gives it a visible
// home outside of Intruder's OOB column.

import { useEffect, useMemo, useRef, useState } from "react";
import { api, OobInteraction, OobStatus, OobToken } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";

export function CollaboratorPanel() {
  const [status, setStatus] = useState<OobStatus | null>(null);
  const [tokens, setTokens] = useState<OobToken[]>([]);
  const [interactions, setInteractions] = useState<OobInteraction[]>([]);
  const [mintCount, setMintCount] = useState(5);
  const [httpBind, setHttpBind] = useState("127.0.0.1:7898");
  const [dnsBind, setDnsBind] = useState("127.0.0.1:15353");
  const [publicHost, setPublicHost] = useState("127.0.0.1:7898");
  const [capacity, setCapacity] = useState(10000);
  const [filterKind, setFilterKind] = useState<"all" | "http" | "dns">("all");
  const [filterCid, setFilterCid] = useState<string>("");
  const [search, setSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selected, setSelected] = useState<OobInteraction | null>(null);
  // R488: Right-click menu state for an OOB interaction row — carries
  // the full OobInteraction so menu handlers can reach correlation_id
  // / remote_addr / summary / kind / ts_ms without threading props.
  // First row-right-click surface on CollaboratorPanel — previously
  // the interactions table was click-only.
  const [interactionMenu, setInteractionMenu] =
    useState<MenuState<OobInteraction> | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const copyTimer = useRef<number | null>(null);

  async function refreshStatus() {
    try { setStatus(await api.oobStatus()); } catch {}
  }
  async function refreshInteractions() {
    try { setInteractions(await api.oobInteractionsAll()); } catch {}
  }

  useEffect(() => {
    void refreshStatus();
    void refreshInteractions();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(() => {
      void refreshStatus();
      void refreshInteractions();
    }, 2000);
    return () => clearInterval(t);
  }, [autoRefresh]);

  // R233: Alt+1..3 switches the kind filter — mirrors R230 /
  // R231 / R232's Alt-digit pattern across findings-adjacent
  // panels. Mapping: 1=all / 2=http / 3=dns, matching the
  // dropdown's option order. Guards: plain Alt only (no co-
  // modifiers), digit 1..3 only, text-input focus skip.
  useEffect(() => {
    const KIND_BY_DIGIT: Record<string, "all" | "http" | "dns"> = {
      "1": "all",
      "2": "http",
      "3": "dns",
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
      setFilterKind(k);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // R409: Alt+C clears every active filter (kind / cid / search)
  // in one keystroke — keyboard version of the toolbar's
  // "clear N filter(s)" ghost button. Mirror of R349 History
  // Alt+C pattern. Operators pivoting across OOB interaction
  // sets want a one-key reset without hunting for the clear
  // button or walking three selectors. **Guards** plain Alt
  // only (no Ctrl/Meta/Shift so Ctrl+Shift+C DevTools muscle
  // memory stays untouched), text-input focus skip. **No-op**
  // silent when no filter is active — the keystroke stays safe
  // to spam.
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
        filterKind !== "all" || filterCid.length > 0 || search.length > 0;
      if (!anyActive) return;
      e.preventDefault();
      setFilterKind("all");
      setFilterCid("");
      setSearch("");
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKind, filterCid, search]);

  // R447: Alt+Shift+C fires the "⚠ Clear" destructive action — wipes
  // every stored OOB interaction via `api.oobInteractionsClear()`,
  // then refreshes the interactions list + listener status. Confirm
  // dialog gates the keystroke exactly like the visible button does,
  // so a stray Alt+Shift+C can't silently drop callbacks. Extends
  // the Alt+Shift+C clear-results family — R418 Intruder (clear
  // attack results), R435 Sequencer (clear tokens + report), R446
  // Logger (clear stored events) — making Collaborator the fourth
  // panel to pick it up. Note the deliberate separation from the
  // R409 Alt+C above: Alt+C resets only the filter triplet
  // (kind / cid / search), Alt+Shift+C is the destructive variant
  // that drops the interaction log itself. **Guards** plain
  // Alt+Shift only (rejects Ctrl/Meta), text-input focus skip, and
  // a short-circuit when `interactions.length === 0` so the
  // keystroke stays safe to spam on a fresh listener.
  useEffect(() => {
    function onClearInteractionsKey(e: KeyboardEvent) {
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
      if (interactions.length === 0) return;
      e.preventDefault();
      if (
        !confirm(
          `Clear ${interactions.length} stored interaction${interactions.length === 1 ? "" : "s"}? The id counter stays monotonic — this just drops the log.`,
        )
      ) {
        return;
      }
      void (async () => {
        setBusy(true);
        try {
          const n = await api.oobInteractionsClear();
          setSelected(null);
          await refreshInteractions();
          await refreshStatus();
          alert(`Cleared ${n} interaction${n === 1 ? "" : "s"}.`);
        } catch (err) {
          alert(`${err}`);
        } finally {
          setBusy(false);
        }
      })();
    }
    document.addEventListener("keydown", onClearInteractionsKey);
    return () => document.removeEventListener("keydown", onClearInteractionsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [interactions.length]);

  async function start() {
    setBusy(true);
    try {
      const next = await api.oobStart({
        http_bind: httpBind,
        dns_bind: dnsBind || null,
        public_host: publicHost,
        capacity,
      });
      setStatus(next);
    } catch (e) {
      alert(`${e}`);
    } finally { setBusy(false); }
  }

  async function stop() {
    setBusy(true);
    try {
      await api.oobStop();
      await refreshStatus();
      setTokens([]);
    } finally { setBusy(false); }
  }

  async function mint() {
    setBusy(true);
    try {
      const batch = await api.oobMintBatch(mintCount);
      setTokens(batch);
    } catch (e) {
      alert(`${e}`);
    } finally { setBusy(false); }
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(null), 1500);
    } catch (e) { console.error(e); }
  }

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return interactions
      .filter((i) => filterKind === "all" || i.kind.toLowerCase() === filterKind)
      .filter((i) => !filterCid || i.correlation_id === filterCid)
      .filter((i) =>
        !q ||
        i.summary.toLowerCase().includes(q) ||
        i.remote_addr.toLowerCase().includes(q) ||
        i.correlation_id.toLowerCase().includes(q)
      )
      .sort((a, b) => b.ts_ms - a.ts_ms);
  }, [interactions, filterKind, filterCid, search]);

  // R266: J / K vim-style row cursor plus ArrowUp/Down/Home/End —
  // sixth J/K panel after Scanner (R197), History (R208), Organizer
  // (R212), Target Issues (R222), and Logger (R258). Collaborator
  // is single-select (clicking a row sets `selected`), so the cursor
  // is defined as the currently selected row; from "nothing selected"
  // J / ↓ lands on the first filtered interaction and K / ↑ on the
  // last — matches the Logger pattern. The move replaces the single
  // selection with the new row and scrolls into view via a data-row-
  // id lookup. Guards against modifiers + typing in inputs so the
  // existing R227 Esc-clear-search + R233 Alt+1..3 kind filter
  // handlers keep their lane.
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
      if (filtered.length === 0) return;
      const curIdx = selected
        ? filtered.findIndex((r) => r.id === selected.id)
        : -1;
      let nextIdx = curIdx;
      if (key === "ArrowUp" || isK) {
        nextIdx =
          curIdx < 0 ? filtered.length - 1 : Math.max(0, curIdx - 1);
      } else if (key === "ArrowDown" || isJ) {
        nextIdx =
          curIdx < 0 ? 0 : Math.min(filtered.length - 1, curIdx + 1);
      } else if (key === "Home") {
        nextIdx = 0;
      } else if (key === "End") {
        nextIdx = filtered.length - 1;
      }
      if (nextIdx === curIdx || nextIdx < 0) return;
      e.preventDefault();
      const next = filtered[nextIdx];
      setSelected(next);
      // Scroll on next frame so the DOM has `.selected` applied;
      // block:nearest avoids jumping to the top on every arrow
      // press — only scrolls when the row is actually off-screen.
      requestAnimationFrame(() => {
        const tr = document.querySelector(
          `tr[data-row-id="${next.id}"]`,
        ) as HTMLElement | null;
        tr?.scrollIntoView({ block: "nearest" });
      });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [filtered, selected]);

  const correlationIds = useMemo(() => {
    const s = new Set<string>();
    for (const i of interactions) s.add(i.correlation_id);
    for (const t of tokens) s.add(t.correlation_id);
    return Array.from(s);
  }, [interactions, tokens]);

  const running = !!status?.running;

  return (
    <div className="collab-root">
      {/* ---- Top-row status strip ---------------------------- */}
      {/* Running dot + interaction count + public host readout. */}
      {/* Mirrors Burp's Collaborator header: a glance at this    */}
      {/* strip tells the operator the listener's alive, how     */}
      {/* many hits have landed since boot, and the public DNS   */}
      {/* label payloads should carry. Polled on the existing 2s */}
      {/* cadence from `refreshStatus` so flipping start/stop    */}
      {/* reflects immediately.                                  */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "6px 10px",
          marginBottom: 10,
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-raised)",
          fontSize: 11.5,
        }}
      >
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontWeight: 600,
          }}
          title={
            running
              ? "Listener is running — mint a payload and watch for hits"
              : "Listener is stopped — click Start to accept callbacks"
          }
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: 999,
              background: running ? "#3fb464" : "#777",
              boxShadow: running
                ? "0 0 0 2px rgba(63, 180, 100, 0.22)"
                : "none",
              display: "inline-block",
            }}
          />
          {running ? "RUNNING" : "STOPPED"}
        </span>
        <span className="sep" />
        <span className="dim">interactions</span>
        <strong
          className="mono"
          title="Total OOB callbacks the listener has caught since startup"
        >
          {status?.interaction_count ?? 0}
        </strong>
        {/* R451: HTTP/DNS kind-split stats badge. The interaction  */}
        {/* count above is a running total since boot; this chip    */}
        {/* breaks it down by kind so operators eyeballing the      */}
        {/* strip can tell at a glance whether their blind-SSRF     */}
        {/* HTTP callback is landing or whether only DNS is         */}
        {/* resolving (a common state for a half-firewalled target  */}
        {/* that lets DNS egress but not HTTP). Mirror of R440      */}
        {/* Repeater workspace stats and R442 History hosts badge   */}
        {/* — three panels now carry a toolbar "📊" quick-stats     */}
        {/* chip. Derived from the already-polled interactions      */}
        {/* array (no new backend poll), computed inline so the     */}
        {/* two counts stay in sync with the running listener's    */}
        {/* in-memory state. Dim-tinted when the respective kind    */}
        {/* count is 0 so an idle listener doesn't shout; accent-   */}
        {/* tinted when > 0 so a received hit draws the eye.        */}
        {(() => {
          let httpCount = 0;
          let dnsCount = 0;
          for (const i of interactions) {
            const k = i.kind.toLowerCase();
            if (k === "http") httpCount++;
            else if (k === "dns") dnsCount++;
          }
          return (
            <>
              <span className="sep" />
              <span
                className="mono"
                title={
                  interactions.length === 0
                    ? "No interactions yet — fire a request against a minted payload to populate this"
                    : `${httpCount} HTTP callback${httpCount === 1 ? "" : "s"} · ${dnsCount} DNS lookup${dnsCount === 1 ? "" : "s"} · across ${interactions.length} total interaction${interactions.length === 1 ? "" : "s"}`
                }
                style={{ fontSize: 10.5, color: "var(--text-faint)" }}
              >
                📊
                <span style={{ color: httpCount > 0 ? "var(--accent)" : "var(--text-dim)", marginLeft: 4 }}>
                  {httpCount} http
                </span>
                <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
                <span style={{ color: dnsCount > 0 ? "var(--accent)" : "var(--text-dim)" }}>
                  {dnsCount} dns
                </span>
              </span>
            </>
          );
        })()}
        {/* R276: Tokens-minted count badge in the top status strip. */}
        {/* Operators running a long engagement mint payloads from   */}
        {/* the Mint section below, but once they scroll into the    */}
        {/* interactions table + attached detail they can't tell how */}
        {/* many payloads are armed without scrolling back up. This  */}
        {/* badge mirrors the interaction count's layout right next  */}
        {/* to it so the two glance-values ("hits received / tokens  */}
        {/* in play") read as a pair. Tint-promotes when > 0 so an   */}
        {/* idle no-token state doesn't shout; dim when 0. Count     */}
        {/* comes from the `tokens` list (already polled at refresh  */}
        {/* cadence) so this is a zero-new-poll render.              */}
        <span className="sep" />
        <span className="dim">tokens</span>
        <strong
          className="mono"
          title={
            tokens.length > 0
              ? `${tokens.length} active correlation payload${tokens.length === 1 ? "" : "s"} minted — operators await callbacks on these`
              : "No tokens minted yet — scroll to the Mint panel to request a batch"
          }
          style={{
            color: tokens.length > 0 ? "var(--accent)" : "var(--text-dim)",
          }}
        >
          {tokens.length}
        </strong>
        {/* R174: Relative "last Xs ago" badge for the most recent    */}
        {/* interaction. Operators waiting on a blind-SSRF callback   */}
        {/* want to see at a glance whether a hit landed recently or  */}
        {/* the listener has been idle. Reuses the already-polled     */}
        {/* interactions array; derives Max(ts_ms) on every 2s tick.  */}
        {/* Threshold tints match Dashboard Last activity (R159):     */}
        {/* green ≤30s, neutral ≤5m, amber ≤30m, red beyond.          */}
        {(() => {
          if (interactions.length === 0) return null;
          const lastTs = Math.max(...interactions.map((i) => i.ts_ms));
          const diffS = Math.max(0, Math.floor((Date.now() - lastTs) / 1000));
          const label =
            diffS < 2
              ? "just now"
              : diffS < 60
                ? `${diffS}s ago`
                : diffS < 3600
                  ? `${Math.floor(diffS / 60)}m ago`
                  : diffS < 86400
                    ? `${Math.floor(diffS / 3600)}h ago`
                    : `${Math.floor(diffS / 86400)}d ago`;
          const color =
            diffS <= 30
              ? "#3fb464"
              : diffS <= 300
                ? "var(--text)"
                : diffS <= 1800
                  ? "var(--amber)"
                  : "var(--red)";
          return (
            <>
              <span className="sep" />
              <span className="dim">last</span>
              <strong
                className="mono"
                title={`Most recent interaction landed ${new Date(lastTs).toISOString().replace("T", " ").slice(0, 19)}Z`}
                style={{ color }}
              >
                {label}
              </strong>
            </>
          );
        })()}
        {status?.public_host && (
          <>
            <span className="sep" />
            <span className="dim">public</span>
            <code
              className="mono"
              style={{
                background: "var(--bg)",
                padding: "1px 6px",
                borderRadius: 3,
                border: "1px solid var(--border)",
              }}
              title="Public hostname payloads will embed when minted"
            >
              {status.public_host}
            </code>
          </>
        )}
        {status?.http_addr && (
          <>
            <span className="sep" />
            <span className="dim">HTTP</span>
            <code className="mono" title="HTTP listener bind address">
              {status.http_addr}
            </code>
          </>
        )}
        {status?.dns_addr && (
          <>
            <span className="sep" />
            <span className="dim">DNS</span>
            <code className="mono" title="DNS listener bind address">
              {status.dns_addr}
            </code>
          </>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        <label
          style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
          title="Toggle the 2s poll loop that refreshes the listener state + interactions"
        >
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          Auto-refresh
        </label>
      </div>
      <h2 className="collab-title">Collaborator (OOB)</h2>
      <p className="collab-sub">
        BurpFree's embedded out-of-band listener. Mint a correlation
        payload, plant it in a request, watch the listener catch the
        callback — the classic DNS/HTTP OOB loop for SSRF, blind XXE,
        command injection, Log4Shell, and friends.
      </p>

      <div className="collab-grid">
        <section className="collab-card">
          <h3>Listener</h3>
          <div className="collab-kv">
            <div><span>State</span>
              <code>
                <span className={`dot ${running ? "on" : ""}`} />
                {running ? "running" : "stopped"}
              </code>
            </div>
            <div><span>HTTP</span><code>{status?.http_addr ?? "—"}</code></div>
            <div><span>DNS</span><code>{status?.dns_addr ?? "—"}</code></div>
            <div><span>Public host</span><code>{status?.public_host ?? "—"}</code></div>
            <div><span>Observed</span><code>{status?.interaction_count ?? 0} interactions</code></div>
          </div>
          <div className="collab-controls">
            <label>http bind</label>
            <input value={httpBind} onChange={(e) => setHttpBind(e.target.value)} disabled={running} style={{ width: 160 }} />
            <label>dns bind</label>
            <input value={dnsBind} onChange={(e) => setDnsBind(e.target.value)} disabled={running} placeholder="(none)" style={{ width: 160 }} />
            <label>public host</label>
            <input value={publicHost} onChange={(e) => setPublicHost(e.target.value)} disabled={running} style={{ width: 180 }} />
            <label>capacity</label>
            <input type="number" min={100} max={100000} value={capacity} onChange={(e) => setCapacity(parseInt(e.target.value) || 10000)} disabled={running} style={{ width: 80 }} />
            {/* R755: Burp-identical primary-action styling on
                the Collaborator "Start listener" button. Fourth
                panel in the primary-action consistency pass
                (Repeater R732 / Intruder R753 / Proxy R754 /
                Collaborator R755). */}
            {!running
              ? <button className="burp-send" onClick={start} disabled={busy}>Start listener</button>
              : <button className="danger" onClick={stop} disabled={busy}>Stop listener</button>}
          </div>
        </section>

        <section className="collab-card">
          <h3>Mint payloads</h3>
          <p className="collab-blurb">
            Each payload is a correlation-id'd HTTP URL and a matching DNS name.
            Plant them in request fields, then watch the Interactions pane for callbacks.
          </p>
          <div className="collab-controls">
            <label>count</label>
            <input
              type="number"
              min={1}
              max={1000}
              value={mintCount}
              onChange={(e) => setMintCount(Math.max(1, Math.min(1000, parseInt(e.target.value) || 1)))}
              style={{ width: 70 }}
            />
            <button className="primary" onClick={mint} disabled={busy || !running}>Mint</button>
            <span className="dim" style={{ fontSize: 11 }}>
              {tokens.length > 0 ? `${tokens.length} active payload(s)` : "no payloads minted"}
            </span>
            {/* R314: Export the currently-minted token batch as     */}
            {/* JSONL. Companion to R193 (interactions export) +    */}
            {/* R310 (CIDs copy) — closes the Collaborator export   */}
            {/* triad. Operators who mint 20 payloads for an        */}
            {/* Intruder run want to save that correlation_id ↔      */}
            {/* http_url ↔ dns_name mapping to a file so they can   */}
            {/* grep the payload file after the attack vs the token */}
            {/* list without reconstructing it manually. Follows    */}
            {/* the R193 / R284 / R285 / R286 / R311 / R313 pattern */}
            {/* — newline-delimited JSON, one OobToken per line.    */}
            {/* **Scope** every currently-minted token (not just    */}
            {/* ones with hits); operators mapping unused payloads  */}
            {/* back to the token file need those too. **Disabled   */}
            {/* when empty** `tokens.length === 0`. **Filename**     */}
            {/* `burpfree-oob-tokens-<ISO-stamp>.jsonl` matches     */}
            {/* R193's naming convention. Zero backend — pure        */}
            {/* frontend `JSON.stringify(t)` over the OobToken.     */}
            <button
              disabled={tokens.length === 0}
              onClick={() => {
                try {
                  const body = tokens.map((t) => JSON.stringify(t)).join("\n");
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
                  a.download = `burpfree-oob-tokens-${stamp}.jsonl`;
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  URL.revokeObjectURL(url);
                } catch (err) {
                  alert(`${err}`);
                }
              }}
              title={
                tokens.length === 0
                  ? "No tokens to export — mint a batch first"
                  : `Export ${tokens.length} token${tokens.length === 1 ? "" : "s"} as JSONL (one JSON object per line). Preserves correlation_id + http_url + dns_name — great for grepping an Intruder payload file against the token list after the attack.`
              }
              style={{ marginLeft: 6, fontSize: 11, padding: "2px 8px" }}
            >
              ⬇ Export tokens
            </button>
          </div>
          {tokens.length > 0 && (
            <div className="collab-tokens">
              {tokens.map((t) => {
                /* R180: Per-token hit count — how many interactions   */
                /* landed against this specific payload. Operators     */
                /* firing 20 payloads at once need to know "which      */
                /* one triggered". Counts interactions whose           */
                /* correlation_id matches. Reuses the already-polled   */
                /* interactions array; O(N) each render but N stays    */
                /* small (ring buffer + typical operator mints ≤ 10    */
                /* tokens so the inner multiply is cheap).             */
                const hitCount = interactions.filter(
                  (i) => i.correlation_id === t.correlation_id,
                ).length;
                return (
                <div key={t.correlation_id} className="collab-token">
                  <div
                    className="collab-token-id mono"
                    title={t.correlation_id}
                    style={{ display: "flex", gap: 6, alignItems: "center" }}
                  >
                    <span style={{ flex: 1 }}>{t.correlation_id}</span>
                    {/* R203: Copy correlation_id — operators pivot    */}
                    {/* back and forth between the token list + the   */}
                    {/* interactions table filter dropdown (which     */}
                    {/* is keyed on correlation_id). Having the id    */}
                    {/* behind one click lets them paste it into      */}
                    {/* ticket notes / grep logs without hunting      */}
                    {/* through the token row metadata.               */}
                    <button
                      className="ghost"
                      onClick={() =>
                        copy(t.correlation_id, `cid-${t.correlation_id}`)
                      }
                      title="Copy correlation_id to clipboard"
                      style={{ padding: "1px 6px", fontSize: 10 }}
                    >
                      {copied === `cid-${t.correlation_id}` ? "✓" : "copy"}
                    </button>
                    <span
                      className="badge"
                      style={{
                        background: hitCount > 0 ? "rgba(63,180,100,0.2)" : undefined,
                        color: hitCount > 0 ? "#3fb464" : undefined,
                        fontWeight: 600,
                      }}
                      title={
                        hitCount > 0
                          ? `${hitCount} interaction${hitCount === 1 ? "" : "s"} landed against this payload`
                          : "No interactions yet — fire a request embedding this payload"
                      }
                    >
                      {hitCount} hit{hitCount === 1 ? "" : "s"}
                    </span>
                  </div>
                  <div className="collab-token-row">
                    <code className="mono" title={t.http_url}>{t.http_url}</code>
                    <button className="ghost" onClick={() => copy(t.http_url, `http-${t.correlation_id}`)}>
                      {copied === `http-${t.correlation_id}` ? "✓" : "copy"}
                    </button>
                  </div>
                  <div className="collab-token-row">
                    <code className="mono" title={t.dns_name}>{t.dns_name}</code>
                    <button className="ghost" onClick={() => copy(t.dns_name, `dns-${t.correlation_id}`)}>
                      {copied === `dns-${t.correlation_id}` ? "✓" : "copy"}
                    </button>
                  </div>
                </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="collab-card collab-card-wide">
          <h3>Interactions ({filtered.length}{filtered.length !== interactions.length ? ` of ${interactions.length}` : ""})</h3>
          <div className="collab-controls">
            <label>kind</label>
            <select value={filterKind} onChange={(e) => setFilterKind(e.target.value as "all" | "http" | "dns")}>
              <option value="all">any</option>
              <option value="http">http</option>
              <option value="dns">dns</option>
            </select>
            <label>correlation</label>
            <select value={filterCid} onChange={(e) => setFilterCid(e.target.value)}>
              <option value="">any</option>
              {correlationIds.map((c) => (
                <option key={c} value={c}>{c.slice(0, 10)}…</option>
              ))}
            </select>
            <label>search</label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                // R227: Esc clears the Collaborator search — fifth
                // in the Esc-clear family (R201/R219/R223/R224).
                if (e.key === "Escape" && search) {
                  e.preventDefault();
                  setSearch("");
                }
              }}
              placeholder="path / remote / cid (Esc clears)"
              style={{ width: 220 }}
            />
            {/* R241: Clear every active interaction filter in one   */}
            {/* click — mirror of R240 (History clear-N-filters) +   */}
            {/* R238 (Scanner). Collaborator has 3 dimensions: kind, */}
            {/* correlation, search. Only renders when ≥ 1 active.   */}
            {(() => {
              const activeFilters: string[] = [];
              if (filterKind !== "all") activeFilters.push(`kind=${filterKind}`);
              if (filterCid) activeFilters.push("correlation");
              if (search) activeFilters.push("search");
              const n = activeFilters.length;
              if (n === 0) return null;
              return (
                <button
                  className="ghost"
                  onClick={() => {
                    setFilterKind("all");
                    setFilterCid("");
                    setSearch("");
                  }}
                  title={`Clear all ${n} active filter${n === 1 ? "" : "s"}: ${activeFilters.join(", ")}`}
                  style={{ fontSize: 11, padding: "2px 8px" }}
                >
                  ⨯ clear {n} filter{n === 1 ? "" : "s"}
                </button>
              );
            })()}
            {/* Auto-refresh checkbox lives in the header status strip above (R98). */}
            <button onClick={() => { void refreshInteractions(); void refreshStatus(); }} disabled={busy}>Refresh</button>
            {/* R193: Export interactions as JSONL. Mirror of R155    */}
            {/* (WebSocket per-session export) + R141 (Logger JSONL). */}
            {/* Respects the current filter so operators pivoting on  */}
            {/* a specific correlation / remote / kind export just    */}
            {/* that subset — great for teammate hand-off or ticket   */}
            {/* evidence attach. */}
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                try {
                  const lines = filtered.map((i) =>
                    JSON.stringify({
                      id: i.id,
                      ts_ms: i.ts_ms,
                      kind: i.kind,
                      correlation_id: i.correlation_id,
                      remote_addr: i.remote_addr,
                      summary: i.summary,
                    }),
                  );
                  const blob = new Blob([lines.join("\n") + "\n"], {
                    type: "application/x-ndjson;charset=utf-8",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  const stamp = new Date()
                    .toISOString()
                    .replace(/[:T]/g, "-")
                    .replace(/\..*$/, "");
                  a.href = url;
                  a.download = `burpfree-oob-${stamp}.jsonl`;
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  URL.revokeObjectURL(url);
                } catch (e) {
                  alert(`${e}`);
                }
              }}
              title={
                filtered.length === 0
                  ? "No interactions to export"
                  : `Export ${filtered.length} interaction${filtered.length === 1 ? "" : "s"} as JSONL (one JSON object per line${filtered.length !== interactions.length ? ` — respects the current filter` : ""})`
              }
            >
              ⬇ Export JSONL
            </button>
            {/* R612: Clipboard-only JSON array counterpart to the
                interactions Export JSONL. Fifth entry in cross-panel
                "Copy as JSON" family (History R605 + Scanner R606 +
                Intruder R607 + Target Issues R611 + Collaborator
                R612). Operators dropping OOB interactions into
                incident write-ups / correlation-id grep targets /
                jq pipelines want a top-level JSON array on the
                clipboard directly. Pretty-printed 2-space indent.
                Scope matches Export JSONL: `filtered` (post-filter)
                so kind/cid/search filters are respected. Reuses the
                existing copy() helper so the ✓ toast lands on hit. */}
            <button
              disabled={filtered.length === 0}
              onClick={() =>
                void copy(JSON.stringify(filtered, null, 2), "all-json")
              }
              title={
                filtered.length === 0
                  ? "No interactions to copy"
                  : `Copy ${filtered.length} interaction${filtered.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed${filtered.length !== interactions.length ? ` — respects the current filter` : ""}). Preserves every OobInteraction field. Great for incident write-ups, jq pipelines. Fifth entry in cross-panel Copy-as-JSON family.`
              }
            >
              {copied === "all-json" ? "✓ copied" : "📋 Copy as JSON"}
            </button>
            {/* R692: Collaborator "📋 Copy stats" — OOB-focused
                summary. Format: interactions / unique
                correlation IDs / unique remote addrs / earliest/
                latest timestamps + duration. 4th panel in
                metadata summary family. */}
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                const cids = new Set<string>();
                const addrs = new Set<string>();
                let min = Infinity;
                let max = -Infinity;
                for (const i of filtered) {
                  if (i.correlation_id) cids.add(i.correlation_id);
                  if (i.remote_addr) addrs.add(i.remote_addr);
                  if (typeof i.ts_ms === "number") {
                    if (i.ts_ms < min) min = i.ts_ms;
                    if (i.ts_ms > max) max = i.ts_ms;
                  }
                }
                const lines = [
                  `Interactions: ${filtered.length}`,
                  `Unique correlation IDs: ${cids.size}`,
                  `Unique remote addrs: ${addrs.size}`,
                ];
                if (isFinite(min) && isFinite(max)) {
                  const durS = Math.max(0, Math.floor((max - min) / 1000));
                  const durLabel =
                    durS < 60
                      ? `${durS}s`
                      : durS < 3600
                        ? `${Math.floor(durS / 60)}m ${durS % 60}s`
                        : `${Math.floor(durS / 3600)}h ${Math.floor((durS % 3600) / 60)}m`;
                  lines.push(`From: ${new Date(min).toISOString()}`);
                  lines.push(`To:   ${new Date(max).toISOString()}`);
                  lines.push(`Duration: ${durLabel}`);
                }
                void copy(lines.join("\n"), "stats");
              }}
              title={
                filtered.length === 0
                  ? "No interactions to summarize"
                  : `Copy OOB summary across ${filtered.length} filtered interaction${filtered.length === 1 ? "" : "s"} (count / unique CIDs / unique remote addrs / time range). Great for an incident write-up section.`
              }
            >
              {copied === "stats" ? "✓ copied" : "📋 Copy stats"}
            </button>
            {/* R681: Collaborator "📋 Copy kind counts" — tally
                variant for OOB interactions. Groups by kind
                (http/dns/smtp/ldap/…) with counts. Great for a
                one-line "what did my payload do?" summary. */}
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                const counts: Record<string, number> = {};
                for (const i of filtered) {
                  const k = i.kind || "(unknown)";
                  counts[k] = (counts[k] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort(
                  (a, b) => b[1] - a[1],
                );
                const text = sorted.map(([k, n]) => `${k}: ${n}`).join(", ");
                void copy(text, "kind-counts");
              }}
              title={
                filtered.length === 0
                  ? "No interactions to tally"
                  : `Copy OOB kind counts across ${filtered.length} filtered interaction${filtered.length === 1 ? "" : "s"} as a one-line tally (e.g. "http: 12, dns: 5"). Sorted desc by count. Great for payload-impact summary.`
              }
            >
              {copied === "kind-counts" ? "✓ copied" : "📋 Copy kind counts"}
            </button>
            {/* R613: Clipboard-only CSV counterpart to the JSONL
                export. Sixth entry in cross-panel "Copy as CSV"
                family (History R600 + Scanner R601 + Logger R602 +
                Intruder R603 + Target sitemap R604 + Collaborator
                R613). Operators pasting OOB interactions into
                Excel / Sheets for correlation-id pivot analysis
                want the clipboard shortcut. 7 columns: id, ts_ms,
                kind, correlation_id, remote_addr, summary, preview.
                Standard CSV escape rules for commas/quotes/newlines. */}
            {/* R619: Clipboard-only JSONL counterpart to the
                interactions Export JSONL. Sixth entry in cross-
                panel "Copy as JSONL" family (History R614 +
                Scanner R615 + Logger R616 + Intruder R617 +
                Target Issues R618 + Collaborator R619). Byte-
                identical to the file export. */}
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                const body = filtered
                  .map((i) => JSON.stringify(i))
                  .join("\n");
                void copy(body, "all-jsonl");
              }}
              title={
                filtered.length === 0
                  ? "No interactions to copy"
                  : `Copy ${filtered.length} interaction${filtered.length === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line${filtered.length !== interactions.length ? ` — respects the current filter` : ""}). Byte-identical to Export JSONL. Great for jq / ELK ingest. Sixth entry in cross-panel Copy-as-JSONL family — completes 6-panel coverage.`
              }
            >
              {copied === "all-jsonl" ? "✓ copied" : "📋 Copy as JSONL"}
            </button>
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                const headers = [
                  "id",
                  "ts_ms",
                  "kind",
                  "correlation_id",
                  "remote_addr",
                  "summary",
                  "preview",
                ];
                const esc = (v: unknown) => {
                  const s = v == null ? "" : String(v);
                  return /[",\n]/.test(s)
                    ? `"${s.replace(/"/g, '""')}"`
                    : s;
                };
                const body = filtered
                  .map((i) =>
                    [
                      i.id,
                      i.ts_ms,
                      i.kind,
                      i.correlation_id,
                      i.remote_addr,
                      i.summary,
                      i.preview,
                    ]
                      .map(esc)
                      .join(","),
                  )
                  .join("\n");
                const csv = [headers.join(","), body].join("\n");
                void copy(csv, "all-csv");
              }}
              title={
                filtered.length === 0
                  ? "No interactions to copy"
                  : `Copy ${filtered.length} interaction${filtered.length === 1 ? "" : "s"} as a CSV table to clipboard (7 columns: id, ts_ms, kind, correlation_id, remote_addr, summary, preview${filtered.length !== interactions.length ? ` — respects the current filter` : ""}). Paste into Excel / Sheets for correlation-id pivot analysis. Sixth entry in cross-panel Copy-as-CSV family.`
              }
            >
              {copied === "all-csv" ? "✓ copied" : "📋 Copy as CSV"}
            </button>
            {/* R310: Copy every unique correlation_id in the         */}
            {/* currently-filtered interaction set to the clipboard   */}
            {/* as a newline-joined list. Operators triaging an       */}
            {/* alert cluster paste the list into ticket notes /      */}
            {/* grep logs / a payload file for a follow-up Intruder   */}
            {/* run; same clipboard round-trip as the per-token       */}
            {/* "copy" button (R203) but batched over the filtered    */}
            {/* table. Dedupe via a Set so a token that fired 50      */}
            {/* times only lands once in the clipboard. Respects      */}
            {/* current kind / cid / search filters just like the     */}
            {/* R193 Export JSONL button so operators can pivot on a  */}
            {/* subset first then grab just those ids.                */}
            <button
              disabled={filtered.length === 0}
              onClick={() => {
                const uniq = Array.from(
                  new Set(filtered.map((i) => i.correlation_id)),
                );
                void copy(uniq.join("\n"), "all-cids");
              }}
              title={
                filtered.length === 0
                  ? "No interactions to copy"
                  : (() => {
                      const uniq = new Set(filtered.map((i) => i.correlation_id)).size;
                      return `Copy ${uniq} unique correlation_id${uniq === 1 ? "" : "s"} (deduped from ${filtered.length} filtered interaction${filtered.length === 1 ? "" : "s"}) as a newline-joined list — paste into ticket notes / grep / an Intruder payload file.`;
                    })()
              }
            >
              {copied === "all-cids" ? "✓ copied" : "📋 Copy all CIDs"}
            </button>
            {/* R132: Clear every stored interaction. Mirror of    */}
            {/* Burp's Collaborator "Clear" button — useful when   */}
            {/* operators want a clean slate between probes to     */}
            {/* avoid cross-correlating historical callbacks with  */}
            {/* a fresh test. The id counter stays monotonic so a  */}
            {/* note that mentions "interaction #42" doesn't become */}
            {/* ambiguous after a clear.                            */}
            <button
              className="danger"
              disabled={busy || interactions.length === 0}
              onClick={async () => {
                if (
                  !confirm(
                    `Clear ${interactions.length} stored interaction${interactions.length === 1 ? "" : "s"}? The id counter stays monotonic — this just drops the log.`,
                  )
                ) {
                  return;
                }
                setBusy(true);
                try {
                  const n = await api.oobInteractionsClear();
                  setSelected(null);
                  await refreshInteractions();
                  await refreshStatus();
                  alert(`Cleared ${n} interaction${n === 1 ? "" : "s"}.`);
                } catch (e) {
                  alert(`${e}`);
                } finally {
                  setBusy(false);
                }
              }}
              title={
                interactions.length === 0
                  ? "No interactions to clear"
                  : "Drop every stored OOB interaction. Cannot be undone."
              }
            >
              ⚠ Clear
            </button>
          </div>
          <div className="collab-split">
            <div className="collab-interactions">
              <table>
                <colgroup>
                  <col style={{ width: 60 }} />
                  <col style={{ width: 70 }} />
                  {/* R853: new relative-age column — operators
                      triaging interactions want to see "when did
                      this hit land?" at a glance without reading
                      the raw timestamp. */}
                  <col style={{ width: 70 }} />
                  <col style={{ width: 110 }} />
                  <col style={{ width: 130 }} />
                  <col />
                </colgroup>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Kind</th>
                    <th title="Relative age of this interaction (time since ts_ms)">Age</th>
                    <th>Remote</th>
                    <th>Correlation</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {/* R782: Burp-identical Collaborator empty-state
                      card. Replaces the one-line placeholder we
                      shipped before with the full empty-state
                      affordance (SVG icon + headline + descriptive
                      subhead + action strip + shortcut hints) —
                      matches Burp Suite 2026.8's Collaborator tab
                      which shows a clear "listener is stopped,
                      start it" vs "listener is running, mint a
                      payload" dichotomy. Rendered as a <tr> with
                      colspan=5 so it slots into the table layout
                      without breaking the column structure. */}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={5}>
                        <div className="oob-empty-card">
                          <div className="oob-empty-icon">
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
                              <circle cx="12" cy="12" r="2" />
                              <path d="M3 12a9 9 0 0 1 18 0" />
                              <path d="M7 12a5 5 0 0 1 10 0" />
                            </svg>
                          </div>
                          <div className="oob-empty-title">
                            {running
                              ? "Waiting for the first callback…"
                              : "Listener is stopped"}
                          </div>
                          <div className="oob-empty-sub">
                            {running ? (
                              <>
                                Interactions arrive here when a target
                                reaches out to a <b>minted payload</b>{" "}
                                over HTTP or DNS. Mint a payload above,
                                embed it in a request (SSRF probe, blind
                                XSS, log4j JNDI, header exfil, …), hit
                                send, and watch this table light up.
                                Correlation IDs link callbacks back to
                                the request that triggered them.
                              </>
                            ) : (
                              <>
                                Click <b>Start listener</b> above to start
                                receiving out-of-band callbacks. BurpFree
                                binds a local port + registers DNS wild-
                                cards; minted payloads route back to this
                                listener. Great for SSRF / blind XSS /
                                log4j JNDI / header exfiltration /
                                time-based oracle probes.
                              </>
                            )}
                          </div>
                          <div className="oob-empty-hints">
                            Shortcuts: <b>Alt+Shift+C</b> clear all ·{" "}
                            right-click a row for <b>Send to Comparer</b>,{" "}
                            <b>Copy raw</b>, <b>Copy correlation</b>, Mark
                            as false-positive · export filtered to{" "}
                            <b>JSONL</b> / <b>CSV</b> / <b>JSON</b> for jq
                            / Splunk / ELK ingest
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                  {filtered.map((i) => {
                    // R301: Kind row tint — seventh entry in the
                    // row-tint family. OOB interactions come in
                    // two kinds — http callbacks and dns lookups
                    // — and operators scanning a mixed stream
                    // want to pick out the kind at a glance
                    // without reading each chip. Subtle rgba
                    // tints: http stays slightly green-tinged
                    // (fuller signal; more operator context in
                    // the request), dns slightly blue-tinged (a
                    // bare lookup, less context). Low saturation
                    // keeps rows readable across light + dark
                    // themes; the kind-chip badge still carries
                    // the primary colour cue so the row tint is
                    // a reinforcing hint rather than a load-
                    // bearing one.
                    const kind = (i.kind || "").toLowerCase();
                    let kindBg: string | undefined;
                    if (kind === "http")
                      kindBg = "rgba(76, 175, 80, 0.05)";
                    else if (kind === "dns")
                      kindBg = "rgba(90, 160, 220, 0.05)";
                    const isSelected = selected?.id === i.id;
                    return (
                    <tr
                      key={i.id}
                      data-row-id={i.id}
                      className={isSelected ? "selected" : ""}
                      onClick={() => setSelected(i)}
                      onContextMenu={(evt) => {
                        evt.preventDefault();
                        setSelected(i);
                        setInteractionMenu({
                          x: evt.clientX,
                          y: evt.clientY,
                          data: i,
                        });
                      }}
                      style={isSelected ? undefined : kindBg ? { background: kindBg } : undefined}
                    >
                      <td className="mono">{i.id}</td>
                      <td>
                        <span className={`collab-chip ${i.kind.toLowerCase() === "dns" ? "dns" : "http"}`}>
                          {i.kind}
                        </span>
                      </td>
                      {/* R853: relative-age cell. Reuses the panel's
                          existing hit-age formatter semantics —
                          `just now` <2s, N`s` <60s, N`m` <60m,
                          N`h` <24h, N`d` ≥24h. Dim text so the
                          column reads as metadata not a key field. */}
                      <td className="mono dim" title={new Date(i.ts_ms).toISOString()}>
                        {(() => {
                          const diffMs = Math.max(0, Date.now() - i.ts_ms);
                          if (diffMs < 2000) return "just now";
                          const s = Math.floor(diffMs / 1000);
                          if (s < 60) return `${s}s`;
                          const m = Math.floor(s / 60);
                          if (m < 60) return `${m}m`;
                          const h = Math.floor(m / 60);
                          if (h < 24) return `${h}h`;
                          const d = Math.floor(h / 24);
                          return `${d}d`;
                        })()}
                      </td>
                      <td className="mono dim">{i.remote_addr}</td>
                      <td className="mono dim" title={i.correlation_id}>{i.correlation_id.slice(0, 12)}…</td>
                      <td className="mono" title={i.summary}>{i.summary}</td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="collab-detail">
              {!selected && <div className="empty">Select an interaction to see the raw preview.</div>}
              {selected && (
                <div className="collab-detail-body">
                  <div className="collab-detail-head">
                    <span className={`collab-chip ${selected.kind.toLowerCase() === "dns" ? "dns" : "http"}`}>
                      {selected.kind}
                    </span>
                    <strong>{selected.summary}</strong>
                    <span className="dim mono">
                      {new Date(selected.ts_ms).toISOString()}
                    </span>
                  </div>
                  <div className="collab-detail-kv">
                    <div><span>Remote</span><code>{selected.remote_addr}</code></div>
                    <div><span>Correlation</span><code>{selected.correlation_id}</code></div>
                    <div><span>Interaction</span><code>#{selected.id}</code></div>
                  </div>
                  <pre className="collab-preview mono">{selected.preview || "(no preview captured)"}</pre>
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
      {/* R488: FloatingMenu for interaction row right-click.         */}
      {/* Lives at the panel's root level so the menu floats above    */}
      {/* every other UI element. Menu entries read from the full    */}
      {/* OobInteraction (`interactionMenu.data`) and run clipboard-  */}
      {/* only operations + filter-state writes — zero backend calls, */}
      {/* zero destructive actions.                                   */}
      <FloatingMenu
        state={interactionMenu}
        onClose={() => setInteractionMenu(null)}
        items={
          interactionMenu?.data
            ? (() => {
                const i = interactionMenu.data!;
                return [
                  {
                    label: "Copy correlation_id",
                    hint: i.correlation_id,
                    onClick: () => void copy(i.correlation_id, `cid-${i.id}`),
                  },
                  {
                    label: "Copy remote_addr",
                    hint: i.remote_addr,
                    disabled: !i.remote_addr,
                    onClick: () =>
                      void copy(i.remote_addr ?? "", `addr-${i.id}`),
                  },
                  {
                    label: "Copy summary",
                    onClick: () => void copy(i.summary, `sum-${i.id}`),
                  },
                  {
                    label: "Copy as JSON",
                    hint: "clipboard · raw record",
                    onClick: () =>
                      void copy(JSON.stringify(i, null, 2), `json-${i.id}`),
                  },
                  // R714: Collaborator row "Copy JSONL line" —
                  // 7th panel in the row-level JSONL-line family
                  // (HistoryPanel R708 + Scanner R709 + Target
                  // R710 + ProxyPanel R711 + Intruder R712 +
                  // Logger R713 + Collaborator R714). Single-
                  // line NDJSON for appending to a .jsonl log /
                  // piping to jq. Trailing newline. Byte-
                  // identical to R619 Collaborator bulk Copy-
                  // as-JSONL per-line output. Completes the
                  // family across every panel with a row
                  // context menu.
                  {
                    label: "Copy JSONL line",
                    hint: "one object, one line + newline",
                    onClick: () =>
                      void copy(
                        JSON.stringify(i) + "\n",
                        `jsonl-${i.id}`,
                      ),
                  },
                  // R732: Collaborator row "Copy triage line" —
                  // 6th panel in the row-level Copy triage-line
                  // family (HistoryPanel R717 + ProxyPanel R718
                  // + Scanner R728 + Target R729 + Logger R731
                  // + Collaborator R732). Compact single-line
                  // OOB interaction summary. Format: "KIND
                  // remote_addr · cid:xxxxx · captured ISO".
                  // Perfect for a Slack ping of a specific OOB
                  // hit with full context.
                  {
                    label: "Copy triage line",
                    hint: "compact KIND remote_addr · cid · captured",
                    onClick: () => {
                      const parts: string[] = [];
                      const head = (i.kind || "unknown").toUpperCase();
                      parts.push(
                        i.remote_addr ? `${head} ${i.remote_addr}` : head,
                      );
                      if (i.correlation_id)
                        parts.push(`cid:${i.correlation_id.slice(0, 12)}`);
                      parts.push(
                        `captured ${new Date(i.ts_ms).toISOString()}`,
                      );
                      void copy(parts.join(" · "), `tri-${i.id}`);
                    },
                  },
                  // R707: Collaborator row "Copy table row" —
                  // 7th panel in the cross-panel row-level
                  // Copy-table-row family (HistoryPanel R663 +
                  // Scanner R664 + Target R665 + ProxyPanel R666
                  // + Logger R667 + Intruder R704 + Collaborator
                  // R707). Just the row-content Markdown table
                  // line (no header, no separator). 5 columns:
                  // id, kind, correlation_id, remote_addr,
                  // captured (ISO 8601). Great for appending to
                  // an incident-log table in a Jira ticket.
                  {
                    label: "Copy table row",
                    hint: "Markdown table body line · no header",
                    onClick: () => {
                      const esc = (v: unknown) =>
                        String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
                      const cells = [
                        i.id,
                        i.kind,
                        i.correlation_id || "",
                        i.remote_addr || "",
                        new Date(i.ts_ms).toISOString(),
                      ]
                        .map(esc)
                        .join(" | ");
                      void copy(`| ${cells} |`, `tr-${i.id}`);
                    },
                  },
                  // R706: Collaborator row "Copy as Markdown" —
                  // 6th panel in the cross-panel row-level
                  // Copy-as-Markdown H3-section family
                  // (HistoryPanel R640 + Target R625 + ProxyPanel
                  // R659 + Scanner R660 + Intruder R703 +
                  // Collaborator R706). Document-style single-
                  // interaction section for incident write-ups:
                  // "### OOB interaction #id (kind)" + a KV
                  // bullet list carrying every field an operator
                  // would quote in a ticket (Kind, Correlation
                  // ID, Remote addr, Summary, Captured timestamp).
                  {
                    label: "Copy as Markdown",
                    hint: "H3 section · OOB interaction",
                    onClick: () => {
                      const lines: string[] = [];
                      lines.push(
                        `### OOB interaction #${i.id} (${i.kind})`,
                      );
                      lines.push("");
                      lines.push(`- **Kind**: ${i.kind}`);
                      if (i.correlation_id)
                        lines.push(
                          `- **Correlation ID**: \`${i.correlation_id}\``,
                        );
                      if (i.remote_addr)
                        lines.push(
                          `- **Remote addr**: \`${i.remote_addr}\``,
                        );
                      if (i.summary)
                        lines.push(`- **Summary**: ${i.summary}`);
                      lines.push(
                        `- **Captured**: ${new Date(i.ts_ms).toISOString()}`,
                      );
                      void copy(lines.join("\n"), `md-${i.id}`);
                    },
                  },
                  { separator: true },
                  {
                    label: `Filter to this correlation_id`,
                    hint: `${i.correlation_id.slice(0, 12)}…`,
                    disabled: filterCid === i.correlation_id,
                    onClick: () => setFilterCid(i.correlation_id),
                  },
                  {
                    label: `Filter to kind: ${i.kind}`,
                    disabled:
                      filterKind === (i.kind.toLowerCase() as any),
                    onClick: () =>
                      setFilterKind(i.kind.toLowerCase() as any),
                  },
                  { separator: true },
                  {
                    label: `Captured ${new Date(i.ts_ms)
                      .toISOString()
                      .replace("T", " ")
                      .slice(0, 19)}Z`,
                    disabled: true,
                  },
                ];
              })()
            : []
        }
      />
    </div>
  );
}
