import { useEffect, useRef, useState } from "react";
import {
  api,
  HistoryFilter,
  InterceptRule,
  InterceptRuleMatchType,
  InterceptRuleOperator,
  InterceptRuleRelationship,
  InterceptRules,
  PreviewReport,
  StoredSummary,
  TransactionView,
  WsMessageRow,
  WsSessionRow,
} from "../api";
import { MatchReplacePane } from "./MatchReplacePane";
import { PocModal, PocPayload } from "./PocModal";
import { JwtModal } from "./JwtModal";
import { sendToComparer } from "./ComparerPanel";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { MessageEditor } from "../MessageEditor";
import {
  buildCurl,
  buildFetch,
  buildHarEntry,
  buildHarLog,
  buildPowerShell,
  buildPython,
  copyToClipboard,
  fromSummaryAndRaw,
  fromUrlAndRaw,
  urlFromSummary,
} from "../copyAs";
import { BambdaSavedPicker } from "../BambdaSavedPicker";
import {
  buildHostIncludeRule,
  buildPathIncludeRule,
  hasHostIncludeRule,
  hasPathIncludeRule,
  withoutHost,
} from "../scopeHelpers";
import type { Scope } from "../api";

type Sub = "intercept" | "history" | "websockets" | "matchreplace" | "options";

export function ProxyPanel() {
  const [sub, setSub] = useState<Sub>("intercept");
  // R368: Alt+1..5 switch Proxy sub-tabs — 1=Intercept, 2=HTTP
  // history, 3=WebSockets history, 4=Match & replace, 5=Proxy
  // settings. Matches the sub-tab display order so the digit → tab
  // mapping is predictable without hunting. Mirror of R275
  // Organizer Alt+0..9 collection switch + R191 top-level Ctrl+1..9
  // tab switch. **Guards** plain Alt only (no Ctrl/Meta/Shift to
  // avoid collisions with the global Ctrl+1..9 panel-switcher) +
  // text-input / textarea / contenteditable focus skip.
  useEffect(() => {
    const SUB_BY_DIGIT: Record<string, Sub> = {
      "1": "intercept",
      "2": "history",
      "3": "websockets",
      "4": "matchreplace",
      "5": "options",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const target = SUB_BY_DIGIT[e.key];
      if (!target) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (target === sub) return;
      e.preventDefault();
      setSub(target);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [sub]);
  // Global Intercept status — poll every second so the badge reflects
  // flips made from the InterceptPane toggles, Ctrl+T, or an MCP tool.
  const [intercept, setIntercept] = useState<{
    request: boolean;
    response: boolean;
    pending: number;
  }>({ request: false, response: false, pending: 0 });
  // R279: Match & replace enabled rule count. Polled at a slower
  // 5s cadence than the interceptor status (1s) because M&R rules
  // rarely change without an explicit Save from the operator —
  // the slower cadence keeps overhead low while still catching
  // flips landed via MCP / CLI without a hard refresh.
  const [mrEnabled, setMrEnabled] = useState<number>(0);
  // R842: Burp-identical WebSockets history sub-tab count badge.
  // Burp 2026.8 shows a live session count on the WebSockets
  // history tab chip when there's active or recent traffic, so
  // operators on sibling sub-tabs (Intercept / HTTP history / M&R
  // / Options) see at-a-glance "something is streaming on WS right
  // now" without clicking across. Polled at 5s (same cadence as
  // M&R since WS sessions don't flap often; a 1s cadence would
  // over-ping for a seldom-changing counter). Zero backend —
  // reuses `wsSessionsList(50)` and counts the response length.
  const [wsSessions, setWsSessions] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;
    const refresh = () =>
      api
        .interceptorStatus()
        .then((s) => {
          if (!cancelled) setIntercept(s);
        })
        .catch(() => {});
    refresh();
    const t = setInterval(refresh, 1000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const refresh = () =>
      api
        .matchReplaceGet()
        .then((e) => {
          if (cancelled) return;
          setMrEnabled(e.rules.filter((r) => r.enabled).length);
        })
        .catch(() => {});
    refresh();
    const t = setInterval(refresh, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // R842: Poll WebSockets session count on 5s cadence for the
  // WebSockets history sub-tab badge.
  useEffect(() => {
    let cancelled = false;
    const refresh = () =>
      api
        .wsSessionsList(50)
        .then((rows) => {
          if (cancelled) return;
          setWsSessions(rows?.length ?? 0);
        })
        .catch(() => {});
    refresh();
    const t = setInterval(refresh, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  async function toggleInterceptBoth() {
    try {
      const anyOn = intercept.request || intercept.response;
      await api.interceptorSet(!anyOn, !anyOn);
      // Optimistic — the next poll tick reconciles anyway.
      setIntercept((prev) => ({
        ...prev,
        request: !anyOn,
        response: !anyOn,
      }));
    } catch (e) {
      console.warn("Intercept toggle failed:", e);
    }
  }

  const anyOn = intercept.request || intercept.response;

  return (
    <div className="panel">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "6px 10px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-raised)",
        }}
      >
        <button
          onClick={toggleInterceptBoth}
          title="Toggle proxy interception for both directions (Ctrl+T)"
          style={{
            padding: "4px 14px",
            fontSize: 12,
            fontWeight: 600,
            background: anyOn ? "#e04444" : "var(--bg)",
            color: anyOn ? "#fff" : "var(--text-dim)",
            border: `1px solid ${anyOn ? "#c13333" : "var(--border)"}`,
            borderRadius: 4,
            cursor: "pointer",
            minWidth: 150,
          }}
        >
          <span style={{ fontSize: 10, marginRight: 4 }}>{anyOn ? "●" : "○"}</span>
          Intercept is {anyOn ? "ON" : "OFF"}
        </button>
        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Requests: {intercept.request ? "ON" : "OFF"} · Responses:{" "}
          {intercept.response ? "ON" : "OFF"}
        </span>
        {intercept.pending > 0 && (
          <span
            className="badge"
            style={{
              background: "var(--accent)",
              color: "#fff",
              cursor: sub === "intercept" ? "default" : "pointer",
            }}
            onClick={() => {
              if (sub !== "intercept") setSub("intercept");
            }}
            title={
              sub === "intercept"
                ? "Pending messages are waiting on the Intercept tab"
                : "Click to jump to the Intercept tab"
            }
          >
            {intercept.pending} pending
          </span>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        <span style={{ fontSize: 10, color: "var(--text-faint)" }}>
          Ctrl+T to toggle
        </span>
      </div>
      <div className="sub-tabs" style={{ display: "flex", alignItems: "center" }}>
        {/* R269: Intercept queue count badge on the sub-tab —      */}
        {/* operators on HTTP history, WebSockets history, Match &   */}
        {/* replace, or Options can't currently see that intercept   */}
        {/* has pending traffic awaiting a forward/drop decision. The*/}
        {/* existing `intercept.pending` state is already polled at  */}
        {/* 1s cadence from `api.interceptorStatus()` so this is a   */}
        {/* zero-new-poll render. The badge only shows when the      */}
        {/* queue is non-empty so an idle intercept doesn't shout.   */}
        {/* Tint matches the intercept "on" accent so the badge pops */}
        {/* visually from any adjacent sub-tab.                      */}
        <div className={`tab ${sub === "intercept"    ? "active" : ""}`} onClick={() => setSub("intercept")}>
          Intercept
          {intercept.pending > 0 && (
            <span
              className="badge"
              style={{
                marginLeft: 6,
                fontSize: 10,
                padding: "0 5px",
                background: "rgba(240, 140, 60, 0.22)",
                color: "var(--amber)",
                borderColor: "rgba(240, 140, 60, 0.5)",
                fontWeight: 600,
              }}
              title={`${intercept.pending} message${intercept.pending === 1 ? "" : "s"} awaiting forward/drop — switch to the Intercept sub-tab to resolve.`}
            >
              {intercept.pending}
            </span>
          )}
        </div>
        <div className={`tab ${sub === "history"      ? "active" : ""}`} onClick={() => setSub("history")}>HTTP history</div>
        {/* R842: WebSockets history sub-tab chip + session count   */}
        {/* badge. Mirrors R279 Match-and-replace enabled-count     */}
        {/* badge pattern but with a muted blue tint (WS traffic    */}
        {/* is observational, not state-mutating like M&R, so the   */}
        {/* badge should pop less loudly). Only renders when there  */}
        {/* are ≥1 sessions — a project with no WS activity doesn't */}
        {/* carry a noisy "(0)" chip.                                */}
        <div className={`tab ${sub === "websockets"   ? "active" : ""}`} onClick={() => setSub("websockets")}>
          WebSockets history
          {wsSessions > 0 && (
            <span
              className="badge"
              style={{
                marginLeft: 6,
                fontSize: 10,
                padding: "0 5px",
                background: "rgba(90, 150, 220, 0.14)",
                color: "#88b4ff",
                borderColor: "rgba(90, 150, 220, 0.35)",
                fontWeight: 600,
              }}
              title={`${wsSessions} WebSocket session${wsSessions === 1 ? "" : "s"} in the recent-50 window. Switch to the sub-tab to inspect frames, replay messages, or close hung connections.`}
            >
              {wsSessions}
            </span>
          )}
        </div>
        {/* R279: Match & replace enabled-rule count badge on the  */}
        {/* sub-tab chip. Mirrors R269 (Intercept queue badge) —   */}
        {/* a glance-value "how many rules are mutating traffic    */}
        {/* right now" that operators on other sub-tabs (Intercept */}
        {/* / HTTP history / Options) can see without switching    */}
        {/* over. Tint uses accent (M&R modifications are a        */}
        {/* feature, not an urgency state like Intercept amber)    */}
        {/* so the badge pops but doesn't shout. Only renders      */}
        {/* when the enabled count > 0 — a Project with no         */}
        {/* rules armed doesn't carry a noisy "(0)" chip.          */}
        <div className={`tab ${sub === "matchreplace" ? "active" : ""}`} onClick={() => setSub("matchreplace")}>
          Match and replace
          {mrEnabled > 0 && (
            <span
              className="badge"
              style={{
                marginLeft: 6,
                fontSize: 10,
                padding: "0 5px",
                background: "rgba(90, 160, 220, 0.18)",
                color: "var(--accent)",
                borderColor: "rgba(90, 160, 220, 0.4)",
                fontWeight: 600,
              }}
              title={`${mrEnabled} match-and-replace rule${mrEnabled === 1 ? "" : "s"} armed — these are rewriting live proxy traffic. Switch to the sub-tab to review or disable them.`}
            >
              {mrEnabled}
            </span>
          )}
        </div>
        <div className={`tab ${sub === "options"      ? "active" : ""}`} onClick={() => setSub("options")}>Proxy settings</div>
        <span style={{ flex: 1 }} />
        {/* R131: Pause-history-recording toggle. Burp calls this     */}
        {/* "Suspend logging to project file" — flip off before       */}
        {/* hitting a credential endpoint so secrets don't persist.   */}
        {/* Session-ephemeral — a restart resets to on. The 2s poll   */}
        {/* in RecordingToggle syncs state flips from the CLI / MCP   */}
        {/* so the badge stays honest.                                 */}
        <RecordingToggle />
      </div>
      {sub === "intercept"    && <InterceptPane />}
      {sub === "history"      && <HistoryPane />}
      {sub === "websockets"   && <WebSocketsPane />}
      {sub === "matchreplace" && <MatchReplacePane />}
      {sub === "options"      && <OptionsPane />}
    </div>
  );
}

/** R131: Pause-history-recording toggle rendered inline in the
 *  Proxy sub-tab strip. Polls `historyRecordingGet` every 2s so
 *  flips from the CLI / MCP tool show up here too. Optimistic
 *  update on click — reverts on error. Red tint when paused so
 *  the operator can't miss it. Session-ephemeral by design (a
 *  restart resets to on so a forgotten "paused" doesn't silently
 *  skip the next session's traffic). */
function RecordingToggle() {
  const [recording, setRecording] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    const poll = () =>
      api
        .historyRecordingGet()
        .then((v) => {
          if (!cancelled) setRecording(v);
        })
        .catch(() => {});
    poll();
    const t = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);
  if (recording === null) return null;
  const paused = !recording;
  return (
    <button
      onClick={async () => {
        if (busy) return;
        setBusy(true);
        const next = !recording;
        setRecording(next);
        try {
          await api.historyRecordingSet(next);
        } catch (e) {
          setRecording(!next);
          alert(`${e}`);
        } finally {
          setBusy(false);
        }
      }}
      disabled={busy}
      style={{
        padding: "2px 10px",
        marginRight: 6,
        fontSize: 11,
        fontWeight: 600,
        borderRadius: 10,
        border: paused
          ? "1px solid var(--red)"
          : "1px solid var(--border)",
        background: paused ? "rgba(224,68,68,0.15)" : "transparent",
        color: paused ? "var(--red)" : "var(--text-dim)",
        cursor: busy ? "wait" : "pointer",
      }}
      title={
        paused
          ? "Proxy sink is NOT persisting transactions. Extensions still see them. Click to resume recording."
          : "Pause history recording. Mirrors Burp's `Suspend logging to project file` — flip off before hitting a credential endpoint so secrets don't persist. Session-ephemeral."
      }
    >
      ● Recording: {paused ? "PAUSED" : "ON"}
    </button>
  );
}

// --------------------------------------------------------------------- Intercept

type Pending = {
  id: number;
  direction: string;
  method?: string;
  url?: string;
  status?: number;
  host?: string;
  preview: string;
};

function InterceptPane() {
  const [reqOn, setReqOn] = useState(false);
  const [respOn, setRespOn] = useState(false);
  const [pending, setPending] = useState<Pending[]>([]);
  const [selected, setSelected] = useState<Pending | null>(null);
  const [raw, setRaw] = useState("");
  const [rulesOpen, setRulesOpen] = useState(false);
  // Per-row context menu — opened on right-click, carries the Pending
  // item so each action can read url / method / direction.
  const [rowMenu, setRowMenu] = useState<MenuState<Pending> | null>(null);
  // R296: Per-row arrival timestamp map for the age-tint feature.
  // Pending items don't carry a timestamp in the Pending type (they
  // come fresh from the interceptor's queue each poll), so we track
  // first-seen time locally. On each pending-state change we add
  // newly-seen ids and drop ids that have left the queue (forwarded
  // / dropped). Date.now() is recorded once per id so a row's age
  // is monotonic even if the poll cadence varies.
  const arrivalRef = useRef<Map<number, number>>(new Map());
  // Ticks a counter to force re-render roughly every 2s so the
  // tint evolves without requiring a backend poll change. The
  // actual arrival map lives in the ref — this is just a render
  // trigger.
  const [ageTick, setAgeTick] = useState(0);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = setInterval(() => {
      api.interceptorPending().then((p) => setPending(p as any)).catch(() => {});
    }, 500);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    api.interceptorSet(reqOn, respOn).catch(() => {});
  }, [reqOn, respOn]);

  // R296: Reconcile the arrival-time map against the current
  // pending list — add first-seen timestamps for ids that just
  // showed up and drop timestamps for ids that have left the
  // queue (forwarded / dropped / cleared). Runs after every
  // pending-state change so the map stays bounded by |pending|.
  useEffect(() => {
    const map = arrivalRef.current;
    const live = new Set(pending.map((p) => p.id));
    const now = Date.now();
    for (const p of pending) {
      if (!map.has(p.id)) map.set(p.id, now);
    }
    for (const id of Array.from(map.keys())) {
      if (!live.has(id)) map.delete(id);
    }
  }, [pending]);

  // R296: 2s ticker so age tints evolve smoothly without needing
  // a backend poll. The arrival map lives in the ref — this just
  // triggers a re-render so the derived tint recomputes.
  useEffect(() => {
    if (pending.length === 0) return; // skip when queue empty
    const t = setInterval(() => setAgeTick((n) => n + 1), 2000);
    return () => clearInterval(t);
  }, [pending.length]);

  // R332: J / K vim-style navigation across the pending intercept
  // queue — eighth entry in the J/K family after R197 Scanner,
  // R208 History, R212 Organizer, R222 Target Issues, R258
  // Logger, R266 Collaborator, R272 BChecks. Operators holding a
  // long intercept queue (debug session with intercept ON) want
  // keyboard-first walk through the queue so they can inspect
  // each pending message without mouse pivots. Walks the `pending`
  // list in arrival order (what the UI renders), clamps at list
  // ends, no-op when empty. **Guards** mirror R197: plain J/K
  // only (no modifiers), text-input / textarea / contenteditable
  // skip so J/K inside the message editor keeps native caret
  // motion. **Also loads the raw bytes** into the editor pane
  // (`setRaw(summarize(...))`) so the right-pane updates as the
  // operator moves — matches the behaviour of clicking a row.
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
      if (pending.length === 0) return;
      e.preventDefault();
      const curIdx = selected
        ? pending.findIndex((p) => p.id === selected.id)
        : -1;
      let nextIdx: number;
      if (curIdx < 0) {
        nextIdx = isJ ? 0 : pending.length - 1;
      } else {
        nextIdx = isJ
          ? Math.min(curIdx + 1, pending.length - 1)
          : Math.max(curIdx - 1, 0);
      }
      const next = pending[nextIdx];
      if (!next || next.id === selected?.id) return;
      setSelected(next);
      setRaw(next.preview);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending, selected?.id]);

  // R330: Keyboard shortcuts for the intercept pane — Burp Pro's
  // canonical Forward/Drop + bulk variants:
  //   Ctrl+F        → Forward the currently selected intercept
  //   Ctrl+D        → Drop the currently selected intercept
  //   Ctrl+Shift+F  → Forward every pending intercept
  //   Ctrl+Shift+D  → Drop every pending intercept
  //
  // Operators holding a long queue (debug session with intercept
  // ON) want keystroke-speed resolution without a mouse pivot.
  // Guards mirror R328 / R329 patterns: bail inside text inputs
  // / textareas / contenteditables so Ctrl+F in the editor pane
  // still fires the native MessageEditor find box; same deal for
  // Ctrl+D in a comment-ish box (though none exist here today).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      const key = e.key.toLowerCase();
      if (key !== "f" && key !== "d") return;
      if (e.shiftKey) {
        if (pending.length === 0 || busy) return;
        e.preventDefault();
        if (key === "f") void resolveAll("forward");
        else void resolveAll("drop");
      } else {
        if (!selected) return;
        e.preventDefault();
        if (key === "f") void resolve("forward");
        else void resolve("drop");
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, pending.length, busy, raw]);

  async function resolve(action: "forward" | "drop") {
    if (!selected) return;
    try {
      await api.interceptorResolve(selected.id, action, raw || undefined);
      setSelected(null);
      setRaw("");
    } catch (e) { alert(`${e}`); }
  }

  // Bulk Forward-all / Drop-all. Clears local selection too so the
  // right pane doesn't dangle a reference to a resolved id.
  async function resolveAll(action: "forward" | "drop") {
    const n = pending.length;
    if (n === 0) return;
    if (
      action === "drop" &&
      !confirm(`Drop every pending intercept (${n})? Each dropped request returns 502 to the client.`)
    ) {
      return;
    }
    setBusy(true);
    try {
      await api.interceptorResolveAll(action);
      setSelected(null);
      setRaw("");
    } catch (e) {
      alert(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  // Send a pending item to Repeater without resolving — Burp lets
  // operators triage a queued request into Repeater while keeping
  // the intercept held so they can still forward/drop separately.
  async function sendRowToRepeater(p: Pending) {
    if (p.direction !== "request") {
      alert("Only pending requests can be sent to Repeater.");
      return;
    }
    try {
      const wire = await api.interceptorShow(p.id);
      // Pull the request line out for naming + method display.
      const firstLine = wire.split(/\r?\n/)[0] || "";
      const [method = "GET", pathOrUrl = "/"] = firstLine.split(" ");

      // Resolve origin tuple (scheme / host / port) for the parser.
      // Prefer the Pending.url field when it carries a full URL —
      // that's the authoritative origin captured at intercept time.
      // Fall back to Pending.host + the request line's path with
      // scheme defaulting to http and port to 80 / 443 by scheme.
      let scheme = "http";
      let host = p.host || "";
      let port = 80;
      if (p.url && /^https?:\/\//i.test(p.url)) {
        try {
          const u = new URL(p.url);
          scheme = u.protocol.replace(":", "");
          host = u.hostname;
          port = u.port
            ? parseInt(u.port, 10)
            : scheme === "https"
              ? 443
              : 80;
        } catch {
          // Malformed URL — fall through with the host/scheme defaults.
        }
      } else if (p.host) {
        // Infer port from host:port shape if the Pending.host carries one.
        const m = p.host.match(/^(.+?):(\d+)$/);
        if (m) {
          host = m[1];
          port = parseInt(m[2], 10);
        }
      }

      const name = `Intercept: ${method} ${host}${pathOrUrl}`.slice(0, 60);
      // Byte-exact: pass the full wire bytes through to the parser so
      // the Repeater tab carries every header + cookie + body chunk
      // the operator was mid-inspecting. TextEncoder gives us the
      // UTF-8 byte array matching what the backend expects
      // (`Vec<u8>`). Binary bodies that `interceptor_show` already
      // lossy-converted stay lossy; that's a pre-existing limit.
      const bytes = Array.from(new TextEncoder().encode(wire));
      await api.repeaterAddFromWire({ name, wire: bytes, host, port, scheme });

      // Nudge the operator into the Repeater tab. Fixed from the
      // dead `burpfree:nav` event name — App.tsx listens for
      // `burpfree:navigate` with `{target}`, not `{section}`.
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R341: Send a pending-intercept request straight into the
  // Intruder composer. Operators intercepting a login / auth
  // flow / submission often want to pivot into a password-spray
  // or payload-sweep immediately. Reuses the burpfree:intruder-
  // load CustomEvent shape {url, method, transactionId?} already
  // consumed by IntruderPanel for the Scanner / Target / History
  // handoffs. **Requests only** — responses can't be re-fired as
  // Intruder jobs. **URL construction** reuses the same scheme /
  // host / port derivation as sendRowToRepeater so the two paths
  // stay byte-consistent on which origin they target.
  async function sendRowToIntruder(p: Pending) {
    if (p.direction !== "request") {
      alert("Only pending requests can be sent to Intruder.");
      return;
    }
    try {
      const wire = await api.interceptorShow(p.id);
      const firstLine = wire.split(/\r?\n/)[0] || "";
      const [method = "GET", pathOrUrl = "/"] = firstLine.split(" ");
      let scheme = "http";
      let host = p.host || "";
      let port = 80;
      if (p.url && /^https?:\/\//i.test(p.url)) {
        try {
          const u = new URL(p.url);
          scheme = u.protocol.replace(":", "");
          host = u.hostname;
          port = u.port
            ? parseInt(u.port, 10)
            : scheme === "https"
              ? 443
              : 80;
        } catch {
          // fall through
        }
      } else if (p.host) {
        const m = p.host.match(/^(.+?):(\d+)$/);
        if (m) {
          host = m[1];
          port = parseInt(m[2], 10);
        }
      }
      // Build canonical URL — suppress default ports to match the
      // urlFromSummary convention.
      const portSuffix =
        (scheme === "https" && port === 443) || (scheme === "http" && port === 80)
          ? ""
          : `:${port}`;
      const url = `${scheme}://${host}${portSuffix}${pathOrUrl.startsWith("/") ? pathOrUrl : "/" + pathOrUrl}`;
      window.dispatchEvent(
        new CustomEvent("burpfree:intruder-load", {
          detail: { url, method },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "intruder" } }),
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function sendRowToComparer(p: Pending, slot: "left" | "right") {
    try {
      const wire = await api.interceptorShow(p.id);
      window.dispatchEvent(
        new CustomEvent("burpfree:comparer-load", {
          detail: { text: wire, slot, label: `${p.direction} ${p.method ?? p.status} ${p.host ?? ""}` },
        }),
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function copyRowAs(p: Pending, kind: "url" | "curl" | "powershell") {
    try {
      if (kind === "url") {
        const u = p.url || (p.host ? `http://${p.host}/` : "");
        await copyToClipboard(u);
        return;
      }
      const wire = await api.interceptorShow(p.id);
      const url =
        p.url && p.url.startsWith("http")
          ? p.url
          : p.host
            ? `http://${p.host}/`
            : "http://localhost/";
      const parsed = fromUrlAndRaw(url, wire);
      const built = kind === "curl" ? buildCurl(parsed) : buildPowerShell(parsed);
      await copyToClipboard(built);
    } catch (e) {
      alert(`${e}`);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div className="toolbar">
        <div className={`toggle ${reqOn ? "on" : ""}`} onClick={() => setReqOn(!reqOn)}>
          <span className="dot" /> Intercept requests {reqOn ? "ON" : "OFF"}
        </div>
        <div className={`toggle ${respOn ? "on" : ""}`} onClick={() => setRespOn(!respOn)}>
          <span className="dot" /> Intercept responses {respOn ? "ON" : "OFF"}
        </div>
        <div className="sep" />
        {/* R754: Burp-identical primary-action styling on the
            Proxy Intercept "Forward" button. Mirrors Burp Suite
            2026.8's intercept panel which uses the same orange
            prominent burp-send button for the Forward action.
            Consistency with R732 Repeater Send + R753 Intruder
            Start attack — every panel's primary action gets the
            same highly-visible treatment. */}
        <button
          className="burp-send"
          disabled={!selected}
          onClick={() => resolve("forward")}
          title="Forward this intercept (Ctrl+F)"
        >
          Forward
        </button>
        <button
          className="danger"
          disabled={!selected}
          onClick={() => resolve("drop")}
          title="Drop this intercept — client sees 502 (Ctrl+D)"
        >
          Drop
        </button>
        <button
          disabled={busy || pending.length === 0}
          onClick={() => void resolveAll("forward")}
          title="Forward every pending intercept with no edits (Ctrl+Shift+F)"
        >
          Forward all ({pending.length})
        </button>
        <button
          className="danger"
          disabled={busy || pending.length === 0}
          onClick={() => void resolveAll("drop")}
          title="Drop every pending intercept (each returns 502 to the client) (Ctrl+Shift+D)"
        >
          Drop all ({pending.length})
        </button>
        <button
          className={`ghost ${rulesOpen ? "on" : ""}`}
          onClick={() => setRulesOpen((o) => !o)}
          title="Configure which requests should be held — leave empty to intercept all in-scope traffic"
        >
          Rules
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="badge">{pending.length} pending</span>
      </div>
      {rulesOpen && <InterceptRulesEditor onClose={() => setRulesOpen(false)} />}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div style={{ width: 380, borderRight: "1px solid var(--border)", overflow: "auto", background: "var(--bg)" }}>
          {pending.length === 0 && (
            <div className="empty">
              {reqOn || respOn
                ? "Interception is ON. In-scope messages pause here awaiting your decision."
                : "Toggle intercept to pause traffic before forwarding."}
            </div>
          )}
          {pending.map((p) => {
            // R296: Age-tint — colour-code pending rows by how long
            // they've been waiting for forward/drop. Fresh (<10s)
            // stay default so operators don't see noise on a quick
            // intercept; stale (10-60s) go amber so slow decisions
            // start standing out; very stale (>60s) go red so a
            // forgotten intercept blocking the browser gets a visual
            // nag. The 60s threshold is deliberately short because
            // a browser request held for a minute is already past
            // the typical operator attention span — anything older
            // means the operator forgot about it. Arrival time
            // comes from the ref map populated on pending-state
            // change; fallback to "now" for the first render pass
            // before the effect has run.
            void ageTick;
            const arrivedAt = arrivalRef.current.get(p.id) ?? Date.now();
            const waitMs = Math.max(0, Date.now() - arrivedAt);
            let ageBg: string | undefined;
            let ageLabel = "";
            if (waitMs >= 60_000) {
              ageBg = "rgba(224, 68, 68, 0.12)";
              ageLabel = `${Math.floor(waitMs / 1000)}s wait`;
            } else if (waitMs >= 10_000) {
              ageBg = "rgba(240, 192, 48, 0.09)";
              ageLabel = `${Math.floor(waitMs / 1000)}s wait`;
            }
            const isSelected = selected?.id === p.id;
            return (
            <div
              key={p.id}
              onClick={() => { setSelected(p); setRaw(p.preview); }}
              onContextMenu={(e) => {
                e.preventDefault();
                setSelected(p);
                setRaw(p.preview);
                setRowMenu({ x: e.clientX, y: e.clientY, data: p });
              }}
              style={{
                padding: "6px 10px",
                borderBottom: "1px solid var(--border)",
                // R296: Selection trumps age so operators always
                // see which row the right-pane editor is bound to.
                background: isSelected
                  ? "var(--accent-dim)"
                  : ageBg ?? "transparent",
                cursor: "pointer",
              }}
              title={ageLabel ? `In the queue for ${ageLabel} — forward or drop to clear` : undefined}
            >
              <div className="mono" style={{ fontSize: 12 }}>
                <span className={`badge ${p.direction === "request" ? "accent" : ""}`}>{p.direction}</span>{" "}
                {p.method || p.status} {p.host || p.url}
                {ageLabel && (
                  <span
                    className="dim"
                    style={{
                      marginLeft: 6,
                      fontSize: 10,
                      color: waitMs >= 60_000 ? "var(--red)" : "var(--amber)",
                    }}
                  >
                    {ageLabel}
                  </span>
                )}
              </div>
              <div className="mono" style={{ color: "var(--text-dim)", fontSize: 11, marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {p.preview}
              </div>
            </div>
            );
          })}
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {selected ? (
            <MessageEditor
              label={selected.direction === "response" ? "Pending response" : "Pending request"}
              value={raw}
              onChange={setRaw}
              direction={selected.direction === "response" ? "response" : "request"}
              onCtrlEnter={() => void resolve("forward")}
            />
          ) : (
            /* R776: Burp-identical intercept-pane empty state.
               Mirrors Burp Suite 2026.8's Proxy intercept empty state
               which shows an SVG "pause/intercept" icon, a bold "No
               request is currently being intercepted" headline, a
               descriptive subhead, and a secondary-action strip that
               explains what to do next — toggle intercept, open the
               proxied browser, or review rules. Replaces the one-
               liner we shipped before with the full Burp affordance
               so operators who've just opened the Proxy tool know
               exactly how to start intercepting without opening the
               docs. Only renders when there's no selected pending
               message AND the pane isn't rendering a Pending entry. */
            <div
              className="prx-intercept-empty"
              style={{ padding: 24, lineHeight: 1.5 }}
            >
              <div className="prx-intercept-empty-icon">
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
                  <circle cx="12" cy="12" r="9" />
                  <rect x="9" y="8" width="2" height="8" />
                  <rect x="13" y="8" width="2" height="8" />
                </svg>
              </div>
              <div className="prx-intercept-empty-title">
                {reqOn || respOn
                  ? "Waiting for in-scope traffic…"
                  : "No request is currently being intercepted"}
              </div>
              <div className="prx-intercept-empty-sub">
                {reqOn || respOn
                  ? "Interception is ON. In-scope messages pause here awaiting your forward/drop decision. Browse through the proxied browser to generate traffic."
                  : "Intercept is OFF — every request is forwarded straight through. Toggle intercept ON (Ctrl+T) to start pausing in-scope traffic, then click a pending row on the left to inspect, edit, forward, or drop."}
              </div>
              <div className="prx-intercept-empty-actions">
                {!(reqOn || respOn) && (
                  <button
                    className="burp-send"
                    onClick={() => {
                      setReqOn(true);
                      setRespOn(false);
                    }}
                    title="Enable intercept for requests (Ctrl+T) — in-scope requests will pause here"
                  >
                    Turn intercept ON
                  </button>
                )}
                <button
                  onClick={() => setRulesOpen(true)}
                  title="Configure which requests should be intercepted — leave empty to intercept all in-scope traffic"
                >
                  Review interception rules…
                </button>
              </div>
              <div className="prx-intercept-empty-hints">
                Shortcuts: <b>Ctrl+T</b> toggle intercept · <b>Ctrl+F</b> forward
                selected · <b>Ctrl+D</b> drop selected · <b>Ctrl+Shift+F</b>{" "}
                forward all · <b>Ctrl+Shift+D</b> drop all · <b>J</b>/<b>K</b>{" "}
                vim-walk the pending queue · right-click a selection in the
                editor for <b>Decoder</b> transforms
              </div>
            </div>
          )}
        </div>
      </div>
      <FloatingMenu
        state={rowMenu}
        onClose={() => setRowMenu(null)}
        items={
          rowMenu?.data
            ? [
                {
                  label: "Forward",
                  onClick: () => {
                    setSelected(rowMenu.data!);
                    setRaw(rowMenu.data!.preview);
                    void resolve("forward");
                  },
                },
                {
                  label: "Drop",
                  danger: true,
                  onClick: () => {
                    setSelected(rowMenu.data!);
                    setRaw(rowMenu.data!.preview);
                    void resolve("drop");
                  },
                },
                { separator: true },
                {
                  label: "Send to Repeater",
                  disabled: rowMenu.data.direction !== "request",
                  hint:
                    rowMenu.data.direction !== "request"
                      ? "requests only"
                      : undefined,
                  onClick: () => void sendRowToRepeater(rowMenu.data!),
                },
                {
                  label: "Send to Intruder",
                  disabled: rowMenu.data.direction !== "request",
                  hint:
                    rowMenu.data.direction !== "request"
                      ? "requests only"
                      : "seeds the Intruder composer with url + method",
                  onClick: () => void sendRowToIntruder(rowMenu.data!),
                },
                {
                  label: "Send to Comparer (left)",
                  onClick: () => void sendRowToComparer(rowMenu.data!, "left"),
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () => void sendRowToComparer(rowMenu.data!, "right"),
                },
                { separator: true },
                {
                  label: "Copy URL",
                  disabled: !rowMenu.data.url && !rowMenu.data.host,
                  onClick: () => void copyRowAs(rowMenu.data!, "url"),
                },
                {
                  label: "Copy as cURL",
                  onClick: () => void copyRowAs(rowMenu.data!, "curl"),
                },
                {
                  label: "Copy as PowerShell",
                  onClick: () => void copyRowAs(rowMenu.data!, "powershell"),
                },
              ]
            : []
        }
      />
    </div>
  );
}

// --------------------------------------------------------------------- Intercept rules

const MATCH_TYPES: Array<{ id: InterceptRuleMatchType; label: string; needsCondition: boolean; hint: string }> = [
  { id: "method",          label: "Method",              needsCondition: true,  hint: "Exact method (GET, POST…)" },
  { id: "url",             label: "URL (regex)",         needsCondition: true,  hint: "Regex matched against the full URL" },
  { id: "host",            label: "Host (regex)",        needsCondition: true,  hint: "Regex matched against the host" },
  { id: "file_extension",  label: "File extension (re)", needsCondition: true,  hint: "Case-insensitive regex over the last path segment's extension" },
  { id: "has_params",      label: "Has parameters",      needsCondition: false, hint: "Query string or form body present" },
  { id: "has_body",        label: "Has body",            needsCondition: false, hint: "Content-Length > 0" },
  { id: "in_scope",        label: "In scope",            needsCondition: false, hint: "Target is in the Scope engine's include set" },
  { id: "header_present",  label: "Header present",      needsCondition: true,  hint: "Header name (case-insensitive)" },
];

function InterceptRulesEditor({ onClose }: { onClose: () => void }) {
  const [direction, setDirection] = useState<"request" | "response">("request");
  const [reqRules, setReqRules] = useState<InterceptRules>({ rules: [] });
  const [respRules, setRespRules] = useState<InterceptRules>({ rules: [] });
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  // Live per-rule firing counter. Polled every 2s from
  // `interceptor_rules_hits`; the backend stores it on an
  // Arc<Mutex> at the Interceptor level (not inside InterceptRules)
  // so saving a new ruleset doesn't zero the trail the operator is
  // watching. Shared between request + response rules because rule
  // IDs are globally unique.
  const [hits, setHits] = useState<Record<string, number>>({});
  const [hitsBusy, setHitsBusy] = useState(false);
  // Preview-on-sample inputs — persist for the lifetime of the
  // editor so an operator who runs a preview, tweaks a rule, saves,
  // and runs again doesn't have to re-type the URL every time.
  const [previewUrl, setPreviewUrl] = useState("https://example.com/api/users");
  const [previewMethod, setPreviewMethod] = useState("GET");
  const [previewInScope, setPreviewInScope] = useState(true);
  const [previewReport, setPreviewReport] = useState<PreviewReport | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  async function runPreview() {
    setPreviewing(true);
    setPreviewError(null);
    try {
      const report = await api.interceptorRulesPreview({
        direction,
        url: previewUrl.trim(),
        method: previewMethod,
        in_scope: previewInScope,
      });
      setPreviewReport(report);
    } catch (e) {
      setPreviewReport(null);
      setPreviewError(`${e}`);
    } finally {
      setPreviewing(false);
    }
  }

  useEffect(() => {
    api.interceptorRulesGet().then((v) => {
      setReqRules(v.request);
      setRespRules(v.response);
      setDirty(false);
    }).catch(() => {});
  }, []);

  // Poll per-rule hits every 2s so the operator sees fires land in
  // near-real-time without having to reopen the editor. The command
  // silently rejects when there's no project — leave the last
  // snapshot in place so a transient race doesn't blank the column.
  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const next = await api.interceptorRulesHits();
        if (alive) setHits(next ?? {});
      } catch {
        /* no project yet or cmd race — keep the stale snapshot */
      }
    };
    void pull();
    const t = setInterval(pull, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  async function resetHits() {
    if (hitsBusy) return;
    setHitsBusy(true);
    try {
      await api.interceptorRulesHitsClear();
      setHits({});
    } catch (e) {
      alert(`Could not reset hits: ${e}`);
    } finally {
      setHitsBusy(false);
    }
  }

  // Total firings across every rule in both directions — the Reset
  // button surfaces this so the operator sees how much state the
  // click will wipe.
  const totalHits = Object.values(hits).reduce((a, b) => a + b, 0);

  const active = direction === "request" ? reqRules : respRules;
  const setActive = (next: InterceptRules) => {
    if (direction === "request") setReqRules(next); else setRespRules(next);
    setDirty(true);
  };

  function addRule() {
    const id = `irule_${Math.random().toString(36).slice(2, 10)}`;
    const r: InterceptRule = {
      id,
      enabled: true,
      operator: active.rules.length === 0 ? "or" : "or",
      match_type: "file_extension",
      relationship: "does_not_match",
      condition: "^(gif|jpg|png|css|js|ico|woff2?)$",
    };
    setActive({ rules: [...active.rules, r] });
  }
  function patch(id: string, p: Partial<InterceptRule>) {
    setActive({
      rules: active.rules.map((r) => (r.id === id ? { ...r, ...p } : r)),
    });
  }
  function remove(id: string) {
    setActive({ rules: active.rules.filter((r) => r.id !== id) });
  }
  function move(id: string, delta: -1 | 1) {
    const idx = active.rules.findIndex((r) => r.id === id);
    if (idx < 0) return;
    const to = idx + delta;
    if (to < 0 || to >= active.rules.length) return;
    const next = active.rules.slice();
    const [m] = next.splice(idx, 1);
    next.splice(to, 0, m);
    setActive({ rules: next });
  }

  async function save() {
    setSaving(true);
    try {
      await api.interceptorRulesSet("request", reqRules);
      await api.interceptorRulesSet("response", respRules);
      setDirty(false);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="irule-panel">
      <div className="irule-head">
        <strong>Interception rules</strong>
        <span className="dim">
          Fired in order; empty list = intercept everything in-scope.
        </span>
        <div className="rep-mode">
          {(["request", "response"] as const).map((d) => (
            <button
              key={d}
              className={`rep-mode-btn ${direction === d ? "active" : ""}`}
              onClick={() => setDirection(d)}
            >
              {d}
            </button>
          ))}
        </div>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          onClick={() => void resetHits()}
          disabled={hitsBusy || totalHits === 0}
          title="Zero every intercept rule's live firing counter. Useful when iterating on a rule chain — re-measure cleanly after each tweak without an app restart. Does not touch pending intercepts."
        >
          Reset hits{totalHits > 0 ? ` (${totalHits.toLocaleString()})` : ""}
        </button>
        <button onClick={addRule}>+ Rule</button>
        <button
          className={dirty ? "primary" : ""}
          onClick={save}
          disabled={!dirty || saving}
        >
          {saving ? "Saving…" : dirty ? "Save" : "Saved"}
        </button>
        <button className="ghost" onClick={onClose}>Close</button>
      </div>
      <div className="irule-body">
        <table className="mono irule-table">
          <colgroup>
            <col style={{ width: 50 }} />
            <col style={{ width: 60 }} />
            <col style={{ width: 170 }} />
            <col style={{ width: 150 }} />
            <col />
            <col style={{ width: 60 }} />
            <col style={{ width: 70 }} />
          </colgroup>
          <thead>
            <tr>
              <th>Enabled</th>
              <th>Op</th>
              <th>Match type</th>
              <th>Relationship</th>
              <th>Condition</th>
              <th title="Live firing count — how many times this rule's `effect` (match-type outcome with relationship applied) has been true since the last Reset. Counts fires independently of the aggregate AND/OR decision: a rule in a losing AND chain still bumps on each firing. Polled every 2s.">Hits</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {active.rules.map((r, i) => {
              const meta = MATCH_TYPES.find((m) => m.id === r.match_type);
              return (
                <tr key={r.id}>
                  <td style={{ textAlign: "center" }}>
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      onChange={(e) => patch(r.id, { enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    {i === 0 ? (
                      <span className="dim">—</span>
                    ) : (
                      <select
                        value={r.operator}
                        onChange={(e) => patch(r.id, { operator: e.target.value as InterceptRuleOperator })}
                      >
                        <option value="or">Or</option>
                        <option value="and">And</option>
                      </select>
                    )}
                  </td>
                  <td>
                    <select
                      value={r.match_type}
                      onChange={(e) => patch(r.id, { match_type: e.target.value as InterceptRuleMatchType })}
                    >
                      {MATCH_TYPES.map((m) => (
                        <option key={m.id} value={m.id}>{m.label}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select
                      value={r.relationship}
                      onChange={(e) => patch(r.id, { relationship: e.target.value as InterceptRuleRelationship })}
                    >
                      <option value="matches">Matches</option>
                      <option value="does_not_match">Does not match</option>
                    </select>
                  </td>
                  <td>
                    <input
                      value={r.condition}
                      onChange={(e) => patch(r.id, { condition: e.target.value })}
                      placeholder={meta?.needsCondition ? meta.hint : "(not used)"}
                      disabled={!meta?.needsCondition}
                      style={{ width: "100%" }}
                    />
                  </td>
                  <td
                    style={{
                      textAlign: "right",
                      color: (hits[r.id] ?? 0) > 0 ? "var(--accent, #e07c50)" : "var(--text-faint)",
                      fontWeight: (hits[r.id] ?? 0) > 0 ? 600 : 400,
                    }}
                    title={
                      (hits[r.id] ?? 0) === 0
                        ? "No fires yet. Each proxy request/response that passes while intercept is ON evaluates this rule; the counter bumps whenever its `effect` is true (independent of the aggregate decision)."
                        : `This rule has fired ${hits[r.id]} time(s) since the last Reset.`
                    }
                  >
                    {(hits[r.id] ?? 0).toLocaleString()}
                  </td>
                  <td>
                    <button className="ghost" onClick={() => move(r.id, -1)} title="Move up">▲</button>
                    <button className="ghost" onClick={() => move(r.id, +1)} title="Move down">▼</button>
                    <button className="ghost danger" onClick={() => remove(r.id)} title="Delete">✕</button>
                  </td>
                </tr>
              );
            })}
            {active.rules.length === 0 && (
              <tr>
                <td colSpan={7} className="dim" style={{ textAlign: "center", padding: 10 }}>
                  No rules — every {direction} is intercepted while intercept is ON.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div
          style={{
            marginTop: 10,
            padding: 8,
            borderTop: "1px solid var(--border)",
            background: "var(--bg-raised)",
          }}
        >
          <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
            <strong style={{ fontSize: 12 }}>Preview on sample</strong>
            <select
              value={previewMethod}
              onChange={(e) => setPreviewMethod(e.target.value)}
              title="HTTP method for the sample"
            >
              {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input
              value={previewUrl}
              onChange={(e) => setPreviewUrl(e.target.value)}
              placeholder="https://example.com/path?q=1"
              style={{ flex: 1, minWidth: 240, fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}
              title="Absolute URL for the sample request. Rules that regex over URL / host / file-extension probe this."
            />
            <label title="Flipped by the InScope rule-type without having to retouch the Scope engine">
              <input
                type="checkbox"
                checked={previewInScope}
                onChange={(e) => setPreviewInScope(e.target.checked)}
              />{" "}
              In scope
            </label>
            <button
              disabled={previewing || !previewUrl.trim()}
              onClick={() => void runPreview()}
              title={
                dirty
                  ? "Save your edits first — the preview runs against the persisted ruleset"
                  : "Dry-run the current saved rules against this sample"
              }
            >
              {previewing ? "Running…" : dirty ? "Run (saved rules only)" : "Run preview"}
            </button>
            {previewReport && (
              <span
                className="badge"
                style={{
                  background:
                    previewReport.decision === true
                      ? "rgba(224, 68, 68, 0.18)"
                      : previewReport.decision === false
                        ? "rgba(75, 191, 107, 0.18)"
                        : undefined,
                  color:
                    previewReport.decision === true
                      ? "var(--red, #e04444)"
                      : previewReport.decision === false
                        ? "var(--green, #4bbf6b)"
                        : "var(--text-dim)",
                }}
                title="Aggregate decision from the enabled rules"
              >
                {previewReport.decision === true
                  ? "Decision: HOLD"
                  : previewReport.decision === false
                    ? "Decision: FORWARD"
                    : "Decision: — (no rules enabled)"}
              </span>
            )}
          </div>
          {previewError && (
            <div
              style={{
                marginTop: 6,
                color: "var(--red, #e04444)",
                fontSize: 11,
                fontFamily: "var(--font-mono, monospace)",
              }}
            >
              {previewError}
            </div>
          )}
          {previewReport && previewReport.rules.length > 0 && (
            <table className="mono" style={{ marginTop: 8, width: "100%", fontSize: 11 }}>
              <colgroup>
                <col style={{ width: 60 }} />
                <col style={{ width: 50 }} />
                <col style={{ width: 110 }} />
                <col style={{ width: 110 }} />
                <col />
                <col style={{ width: 70 }} />
                <col style={{ width: 60 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Enabled</th>
                  <th>Op</th>
                  <th>Match type</th>
                  <th>Relationship</th>
                  <th>Condition</th>
                  <th>Matched</th>
                  <th>Effect</th>
                </tr>
              </thead>
              <tbody>
                {previewReport.rules.map((rp, i) => (
                  <tr
                    key={rp.id}
                    style={{
                      opacity: rp.enabled ? 1 : 0.5,
                      background: rp.enabled && rp.effect ? "rgba(100,150,255,0.08)" : undefined,
                    }}
                    title={rp.enabled ? undefined : "Disabled — effect shown but not folded into the decision"}
                  >
                    <td style={{ textAlign: "center" }}>{rp.enabled ? "✓" : "·"}</td>
                    <td>{i === 0 ? "—" : rp.operator}</td>
                    <td>{rp.match_type}</td>
                    <td>{rp.relationship === "matches" ? "matches" : "does not match"}</td>
                    <td style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {rp.condition || <span className="dim">(no condition)</span>}
                    </td>
                    <td
                      style={{
                        textAlign: "center",
                        color: rp.matched ? "var(--green, #4bbf6b)" : "var(--text-dim)",
                      }}
                    >
                      {rp.matched ? "✓" : "✕"}
                    </td>
                    <td
                      style={{
                        textAlign: "center",
                        color: rp.effect ? "var(--red, #e04444)" : "var(--text-dim)",
                        fontWeight: rp.effect ? 600 : 400,
                      }}
                    >
                      {rp.effect ? "HOLD" : "fwd"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {dirty && (
            <div style={{ marginTop: 6, color: "var(--text-dim)", fontSize: 11 }}>
              Rule edits are unsaved — preview still reflects the last Save.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------- HTTP history

function HistoryPane() {
  const [rows, setRows] = useState<StoredSummary[]>([]);
  const [filter, setFilter] = useState<HistoryFilter>({ limit: 2000 });
  const [selected, setSelected] = useState<StoredSummary | null>(null);
  const [tx, setTx] = useState<TransactionView | null>(null);
  const [auto, setAuto] = useState(true);
  const [poc, setPoc] = useState<PocPayload | null>(null);
  const [menu, setMenu] = useState<MenuState<StoredSummary> | null>(null);
  const [jwtTxId, setJwtTxId] = useState<number | null>(null);
  const [bambdaDraft, setBambdaDraft] = useState("");
  // Current scope — refreshed after any add / remove so menu entries
  // disable themselves when they'd be a no-op.
  const [scope, setScope] = useState<Scope | null>(null);
  useEffect(() => {
    api.scopeGet().then(setScope).catch(() => setScope(null));
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
  const [bambda, setBambda] = useState("");
  const [bambdaMeta, setBambdaMeta] = useState<{
    total: number;
    kept: number;
    error: string | null;
    elapsed_ms: number;
  } | null>(null);

  async function refresh() {
    try {
      if (bambda.trim()) {
        const res = await api.bambdaFilter(bambda, filter);
        setRows(res.rows);
        setBambdaMeta({
          total: res.total_scanned,
          kept: res.kept,
          error: res.error,
          elapsed_ms: res.elapsed_ms,
        });
      } else {
        setRows(await api.historyList(filter));
        setBambdaMeta(null);
      }
    } catch (e) {
      setBambdaMeta({
        total: 0,
        kept: 0,
        error: `${e}`,
        elapsed_ms: 0,
      });
    }
  }
  useEffect(() => { refresh(); }, [filter, bambda]);
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [auto, filter, bambda]);
  useEffect(() => {
    if (selected) api.historyShow(selected.id).then(setTx).catch(() => setTx(null));
    else setTx(null);
  }, [selected?.id]);

  async function sendToRepeater(r: StoredSummary) {
    try {
      const url = `${r.scheme}://${r.host}${r.port !== 80 && r.port !== 443 ? ":" + r.port : ""}${r.path}`;
      await api.repeaterAddTab(`${r.method} ${r.path}`, url, r.method);
      alert("Added to Repeater");
    } catch (e) { alert(`${e}`); }
  }

  async function sendToOrganizer(r: StoredSummary) {
    try {
      await api.organizerAdd({
        transaction_id: r.id,
        title: `${r.method} ${r.host}${r.path}`,
      });
      // Soft toast — a hard alert interrupts the flow when triggered via Ctrl+O.
      console.info(`saved tx #${r.id} to Organizer Inbox`);
    } catch (e) { alert(`${e}`); }
  }

  // Ctrl+O → Organizer, Ctrl+R → Repeater, Ctrl+I → Intruder when a
  // row is selected. We listen for all three on the same effect so the
  // dep array stays simple and the cleanup is symmetrical.
  useEffect(() => {
    const onOrg = () => { if (selected) void sendToOrganizer(selected); };
    const onRep = () => { if (selected) void sendToRepeater(selected); };
    const onInt = () => {
      if (!selected) return;
      const url = `${selected.scheme}://${selected.host}${selected.port !== 80 && selected.port !== 443 ? ":" + selected.port : ""}${selected.path}`;
      window.dispatchEvent(
        new CustomEvent("burpfree:intruder-load", {
          detail: { url, method: selected.method, transactionId: selected.id },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "intruder" } }),
      );
    };
    window.addEventListener("burpfree:send-to-organizer", onOrg);
    window.addEventListener("burpfree:send-to-repeater", onRep);
    window.addEventListener("burpfree:send-to-intruder", onInt);
    return () => {
      window.removeEventListener("burpfree:send-to-organizer", onOrg);
      window.removeEventListener("burpfree:send-to-repeater", onRep);
      window.removeEventListener("burpfree:send-to-intruder", onInt);
    };
  }, [selected?.id]);

  async function generateCsrfPoc(r: StoredSummary) {
    try {
      const res = await api.pocCsrf(r.id);
      setPoc({ title: `CSRF PoC — ${r.method} ${r.host}${r.path}`, html: res.html, suggestedName: res.suggested_name });
    } catch (e) { alert(`${e}`); }
  }

  // Copy-as helpers — fetch the raw request bytes, build the one-liner,
  // and push it to the clipboard. Falls back to a summary-only command
  // if the fetch fails so the user always gets something copyable.
  async function copyAs(r: StoredSummary, kind: "curl" | "powershell" | "python" | "fetch") {
    try {
      let raw = "";
      try {
        const tx = await api.historyShow(r.id);
        raw = tx.request_raw ?? "";
      } catch {
        // ignore — summary-only command is better than nothing
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
      console.info(`Copied ${kind} command for tx #${r.id} (${out.length} chars)`);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R527: ProxyPanel row-right-click "Set highlight…" + "Clear
  // highlight" — minimal HistoryPanel R216 parity. HistoryPanel
  // ships a 7-color palette with Alt+1..7 keyboard + inline
  // chips + bulk highlight + clear-all. ProxyPanel's HTTP
  // history StoredSummary row has the same `highlight` field
  // (nullable string) but no UI for setting it. R527 ships two
  // row-right-click entries that cover the common case: Set via
  // prompt (operator types one of red/orange/yellow/green/cyan/
  // blue/purple), Clear via one click. Full chip palette + Alt+
  // 1..7 keyboard + gutter rendering can land in a later round
  // if operators ask. Mechanism: reuses existing
  // `api.historySetHighlight(id, color)` cmd that HistoryPanel
  // uses — zero backend. **Palette validation** rejects anything
  // outside the 7 Burp canonical names so a typo doesn't persist
  // an unrenderable value. **Clear entry disabled gate** only
  // lights up when the row currently has a highlight set, so
  // the menu doesn't show a no-op entry for unhighlighted rows.
  async function setRowHighlight(r: StoredSummary) {
    const PALETTE = [
      "red",
      "orange",
      "yellow",
      "green",
      "cyan",
      "blue",
      "purple",
    ];
    const current = r.highlight ?? "";
    const picked = prompt(
      `Highlight color for tx #${r.id}\n\nOne of: ${PALETTE.join(" / ")}\nBlank + OK clears.`,
      current,
    );
    if (picked == null) return; // Cancel
    const next = picked.trim().toLowerCase();
    if (next === "") {
      try {
        await api.historySetHighlight(r.id, null);
      } catch (e) {
        alert(`${e}`);
      }
      return;
    }
    if (!PALETTE.includes(next)) {
      alert(`"${picked}" is not a valid highlight color. Use one of: ${PALETTE.join(" / ")}.`);
      return;
    }
    try {
      await api.historySetHighlight(r.id, next);
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function clearRowHighlight(r: StoredSummary) {
    try {
      await api.historySetHighlight(r.id, null);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R531: ProxyPanel row-right-click "Set comment…" — Burp
  // parity for per-row annotations. HistoryPanel edits comments
  // inline via a column renderer, but a right-click prompt is
  // the convention Burp Pro uses for quick-annotate "mark this
  // tx as 'auth attempt'" workflows without the operator having
  // to visually scroll back to the comment column. ProxyPanel's
  // row already has the `comment: string` field (StoredSummary)
  // but no UI for setting it. R531 ships a prompt-based entry
  // that pre-fills with the current comment so operators can
  // edit vs replace. Mechanism: reuses existing
  // `api.historySetComment(id, comment)` cmd — zero backend.
  // Empty string + OK clears the comment (same convention
  // HistoryPanel inline editor uses).
  async function setRowComment(r: StoredSummary) {
    const current = r.comment ?? "";
    const next = prompt(
      `Comment for tx #${r.id}\n\nEmpty + OK clears. Cancel keeps the current comment.`,
      current,
    );
    if (next == null) return; // Cancel
    try {
      await api.historySetComment(r.id, next);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R532: ProxyPanel row-right-click "Add tag…" — HistoryPanel
  // R321 parity. HistoryPanel ships both bulk "+ Add tag" and
  // row-level add; ProxyPanel's HTTP history row carries the
  // same `tags: string[]` field on StoredSummary but no UI for
  // tagging. R532 ships a prompt-based entry that merges a new
  // tag into the existing tag set (dedup via Set). Zero backend
  // — reuses `api.historySetTags(id, tags)` which HistoryPanel
  // already uses. **Merge semantics** matches R321 Scanner /
  // R322 History: read current tags, add new, Set-dedup to drop
  // duplicates, write back. **Fast-path short-circuit** when the
  // tag is already present — the handler early-returns to avoid
  // a no-op backend round-trip. **Hint display** shows the
  // current tag count (and first tag as a preview) so operators
  // see at-a-glance what the row already carries.
  async function addRowTag(r: StoredSummary) {
    const current = r.tags ?? [];
    const picked = prompt(
      `Add tag to tx #${r.id}\n\nCurrent tags: ${current.length === 0 ? "(none)" : current.join(", ")}`,
      "",
    );
    if (picked == null) return; // Cancel
    const tag = picked.trim();
    if (!tag) return;
    if (current.includes(tag)) {
      alert(`Tag "${tag}" is already set on this row.`);
      return;
    }
    try {
      const merged = Array.from(new Set([...current, tag]));
      await api.historySetTags(r.id, merged);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R535: ProxyPanel row-right-click "Run active scan" —
  // HistoryPanel parity. Fires every enabled active-scan probe
  // against the row's stored request. Findings land in the
  // project history via fingerprint upsert so running twice on
  // the same row dedupes. Operators triaging want "which
  // probes match this request?" visible without manually
  // pivoting to the Scanner panel + loading the tx + clicking
  // Run. Mechanism: reuses existing `api.scannerActiveRunTx(id)`
  // cmd — zero backend. The backend returns an ActiveScanReport
  // with `skipped_reason` for "no probes enabled" / "target out
  // of scope" cases so we show a quiet info alert rather than
  // throwing; a successful run shows the findings_added +
  // probes_run count.
  async function activeScanRow(r: StoredSummary) {
    try {
      const report = await api.scannerActiveRunTx(r.id);
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
  }

  // R534: ProxyPanel row-right-click "Replay request" —
  // HistoryPanel R158 parity. Fires the stored request bytes
  // through the shared HTTP client and records the paired
  // result as a fresh history row. Distinct from Send to
  // Repeater (which clones the request into a new Repeater tab
  // for interactive editing) — Replay is immediate / one-shot
  // / no editing. Operators triaging want "re-fire this exact
  // request and see if the response changed" without the full
  // Repeater round-trip. Mechanism: reuses existing
  // `api.historyReplay(id)` cmd — zero backend; the backend
  // call fires the stored request bytes, records the new tx,
  // returns the new id. Then dispatches `burpfree:history-focus`
  // with the new id so HistoryPanel scrolls the replayed row
  // into view — same cross-panel focus bridge R134 (Scanner),
  // R161 (Scanner detail), R419 (Scanner row-right-click),
  // R420/R421 (Alt+Shift+H keyboard), R485 (Logger), R523/R524
  // (ProxyPanel browser pivots) use.
  async function replayRow(r: StoredSummary) {
    try {
      const newId = await api.historyReplay(r.id);
      window.dispatchEvent(
        new CustomEvent("burpfree:history-focus", { detail: { id: newId } }),
      );
      // Also flip to HTTP history so operators see the new row
      // land — ProxyPanel's own view may not refresh if the new
      // tx falls outside the current filter.
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "history" } }),
      );
    } catch (err) {
      alert(`Replay failed: ${err}`);
    }
  }

  // R525: ProxyPanel row-right-click "Save response body…" —
  // HistoryPanel R148 parity. HistoryPanel's row-right-click
  // ships Save response body + Save raw response (headers+body);
  // ProxyPanel never got either, so operators triaging the
  // Proxy HTTP history had to pivot to HistoryPanel first for a
  // binary-safe response save. R525 ports the body-only variant
  // first (binary payloads: PDFs, PNGs, mp4s, JSON blobs — the
  // operator's common case); R526 (next round) will add the
  // raw-wire variant. Mechanism matches HistoryPanel's
  // saveResponseBody(r, includeHeaders=false) exactly: pick an
  // extension from Content-Type via the same whitelist R79's
  // `openResponseInBrowser` uses, build a stable filename stem
  // from host + last-path-segment + tx_id, prompt for the save
  // path, dispatch `api.historySaveResponseBody` which is a
  // backend-side binary-safe write (no base64 round-trip
  // through the frontend). Backend-side save is critical for
  // large payloads where a JS-side atob would strand hundreds of
  // MB in memory.
  async function saveResponseBody(r: StoredSummary, includeHeaders = false) {
    try {
      // Raw-wire dump always goes .txt (headers are text so an
      // operator can diff them in VS Code / less); body-only
      // picks an extension off Content-Type via the HistoryPanel
      // R148 whitelist.
      let ext = includeHeaders ? "txt" : "bin";
      if (includeHeaders) {
        // skip the switch; .txt is correct for raw-wire text
      } else {
      const ct = (r.content_type ?? "").toLowerCase().split(";")[0].trim();
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
          /* fall through to .bin — safe default */
          break;
      }
      }
      const lastSeg =
        (r.path || "/")
          .split("?")[0]
          .split("/")
          .filter(Boolean)
          .pop() ?? "root";
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

  // R524: ProxyPanel row-right-click "Request in browser" —
  // HistoryPanel parity (companion to R523's "Open response in
  // browser"). Where R523 renders the stored response via the OS
  // default handler, R524 asks the OS default browser to fetch
  // the request URL fresh — operators often want to re-issue
  // the request through their own browser (with the browser's
  // cookies / session / developer tools) to compare the response
  // vs the proxy'd one. Mechanism matches HistoryPanel's
  // `requestInBrowser` exactly: build the URL via urlFromSummary,
  // dispatch `api.shellOpenUrl(url)` which backend-validates
  // http/https scheme + length + control chars so a mis-shaped
  // row (file:// / embedded CRLF) can't be weaponised into shell
  // injection.
  async function requestInBrowser(r: StoredSummary) {
    try {
      const url = urlFromSummary(r);
      await api.shellOpenUrl(url);
    } catch (err) {
      alert(`Could not open request URL in browser: ${err}`);
    }
  }

  // R523: ProxyPanel row-right-click "Open response in browser" —
  // HistoryPanel parity. HistoryPanel has R79-era
  // `openResponseInBrowser` + its row-right-click entry but
  // ProxyPanel never got the equivalent, so operators triaging
  // directly in the Proxy history view had to pivot to
  // HistoryPanel first to render a response in the OS browser.
  // R523 closes that gap by porting the same mechanism: fetch
  // the raw response via `historyShow(id)`, parse the Content-
  // Type header (case-insensitive), dispatch
  // `api.responseOpenInBrowser({ content, contentType, label })`
  // which writes the body to a temp file and asks the OS
  // default handler to open it. HTML renders, JSON gets the JSON
  // viewer, binary gets the proper default app.
  async function openResponseInBrowser(r: StoredSummary) {
    try {
      const view = await api.historyShow(r.id);
      const raw = view.response_raw ?? "";
      if (!raw.trim()) {
        alert("No stored response body for this row — nothing to open.");
        return;
      }
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

  // R514: ProxyPanel row-right-click "⬇ Save as HAR file" —
  // file-save variant of R513 Copy as HAR entry. Completes
  // ProxyPanel's HAR surface to clipboard + file at the row level,
  // parallel to Scanner (R482 clip + R507 file), Target Issues
  // (R483 clip + R508 file), and Logger (R506 clip + R509 file).
  // Mechanism matches R513 exactly for the HAR 1.2 build and
  // R507/R508/R509 for the on-disk save. **Filename pattern**
  // `proxy-har-tx-<id>.har` — Proxy transaction rows are
  // identified by their stored tx id (no title field on raw proxy
  // traffic), so the file name encodes the tx id like R509
  // Logger. Operators juggling several Proxy HARs during one
  // triage session keep the files identifiable by id without a
  // slug collision.
  async function saveAsHar(r: StoredSummary) {
    try {
      const view = await api.historyShow(r.id);
      if (!view?.request_raw) {
        alert(
          `Transaction #${r.id} has no stored request_raw — cannot build a HAR entry.`,
        );
        return;
      }
      const req = fromSummaryAndRaw(view.summary ?? r, view.request_raw);
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
      const startedDateTime = new Date(
        (view.summary ?? r).ts_ms,
      ).toISOString();
      const entry = buildHarEntry(req, startedDateTime, resp);
      const har = buildHarLog([entry]);
      const name = `proxy-har-tx-${r.id}.har`;
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
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R513: ProxyPanel row-right-click "Copy as HAR entry" — closes
  // the HAR surface gap on ProxyPanel's HTTP history menu. Scanner /
  // Target Issues / Logger / HistoryPanel / RepeaterPanel already
  // ship HAR row-level copy; ProxyPanel was the last findings-/
  // traffic-adjacent panel without one. Pattern matches R482 Scanner
  // + R483 Target + R506 Logger: historyShow(id) for request_raw +
  // response_raw, fromSummaryAndRaw for the request half, inline
  // response-parse (status line / headers / body split on blank
  // line) for the response half, buildHarEntry + buildHarLog +
  // copyToClipboard for the single-entry HAR 1.2 pretty-printed
  // output. The HAR 1.2 content is byte-identical across all 6
  // panels so operators collecting HAR entries during a session
  // get a consistent artifact regardless of which panel they
  // right-clicked from.
  async function copyAsHar(r: StoredSummary) {
    try {
      const view = await api.historyShow(r.id);
      if (!view?.request_raw) {
        alert(
          `Transaction #${r.id} has no stored request_raw — cannot build a HAR entry.`,
        );
        return;
      }
      const req = fromSummaryAndRaw(view.summary ?? r, view.request_raw);
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
      const startedDateTime = new Date(
        (view.summary ?? r).ts_ms,
      ).toISOString();
      const entry = buildHarEntry(req, startedDateTime, resp);
      const har = buildHarLog([entry]);
      await copyToClipboard(JSON.stringify(har, null, 2));
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function generateClickjackPoc(r: StoredSummary) {
    try {
      const url = `${r.scheme}://${r.host}${r.port !== 80 && r.port !== 443 ? ":" + r.port : ""}${r.path}`;
      const res = await api.pocClickjack(url);
      setPoc({ title: `Clickjacking PoC — ${r.host}`, html: res.html, suggestedName: res.suggested_name });
    } catch (e) { alert(`${e}`); }
  }

  function onRowContextMenu(e: React.MouseEvent, r: StoredSummary) {
    e.preventDefault();
    setSelected(r);
    setMenu({ x: e.clientX, y: e.clientY, data: r });
  }

  const bambdaActive = bambda.trim().length > 0;
  const bambdaExamples = [
    'method == "POST" && status >= 400',
    'host.contains("api") && has_params',
    '!path.ends_with(".css") && !path.ends_with(".js")',
    'response.length > 10000',
    'tags.contains("auth")',
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div className={`bambda-bar ${bambdaMeta?.error ? "error" : ""} ${bambdaActive ? "on" : ""}`}>
        <span className="bambda-label">λ Bambda</span>
        <input
          className="bambda-input mono"
          value={bambdaDraft}
          onChange={(e) => setBambdaDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") setBambda(bambdaDraft); }}
          placeholder='e.g. method == "POST" && status >= 400'
          title="Rhai expression evaluated per-row. Available: method, host, path, url, status, length, mime, elapsed_ms, in_scope, has_params, tags, title, request.*, response.*"
        />
        <button className="primary" onClick={() => setBambda(bambdaDraft)} disabled={!bambdaDraft.trim()}>
          Apply
        </button>
        <button
          className="ghost"
          onClick={() => { setBambda(""); setBambdaDraft(""); }}
          disabled={!bambdaActive && !bambdaDraft}
        >
          Clear
        </button>
        {bambdaMeta && (
          <span className="bambda-stats">
            {bambdaMeta.error
              ? <span style={{ color: "var(--red)" }}>✗ {bambdaMeta.error}</span>
              : <>kept <strong>{bambdaMeta.kept}</strong> of {bambdaMeta.total} · {bambdaMeta.elapsed_ms} ms</>}
          </span>
        )}
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
          title="Pick an example to prefill the filter"
        >
          <option value="">Examples…</option>
          {bambdaExamples.map((ex) => <option key={ex} value={ex}>{ex}</option>)}
        </select>
        <BambdaSavedPicker
          scope="history"
          current={bambdaDraft}
          onLoad={(expr) => {
            setBambdaDraft(expr);
            setBambda(expr);
          }}
        />
      </div>
      <div className="toolbar">
        <label>Filter: host</label>
        <input value={filter.host_contains || ""} onChange={(e) => setFilter({ ...filter, host_contains: e.target.value || undefined })} placeholder="any" style={{ width: 160 }} />
        <label>method</label>
        <select value={filter.method || ""} onChange={(e) => setFilter({ ...filter, method: e.target.value || undefined })}>
          <option value="">any</option>
          {["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"].map((m) => <option key={m}>{m}</option>)}
        </select>
        <label>status</label>
        <select
          value={filter.status_min ? `${filter.status_min}xx` : ""}
          onChange={(e) => {
            const v = e.target.value;
            if (!v) setFilter({ ...filter, status_min: undefined, status_max: undefined });
            else {
              const n = parseInt(v[0]);
              setFilter({ ...filter, status_min: n * 100, status_max: n * 100 + 99 });
            }
          }}
        >
          <option value="">any</option>
          <option value="2xx">2xx</option>
          <option value="3xx">3xx</option>
          <option value="4xx">4xx</option>
          <option value="5xx">5xx</option>
        </select>
        <label>content</label>
        <input value={filter.content_type_contains || ""} onChange={(e) => setFilter({ ...filter, content_type_contains: e.target.value || undefined })} placeholder="json, html..." style={{ width: 100 }} />
        <label>search</label>
        <input value={filter.search_text || ""} onChange={(e) => setFilter({ ...filter, search_text: e.target.value || undefined })} placeholder="path / host / comment" style={{ width: 200 }} />
        <label><input type="checkbox" checked={filter.in_scope_only || false} onChange={(e) => setFilter({ ...filter, in_scope_only: e.target.checked || undefined })} /> In-scope only</label>
        <label><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Auto-refresh</label>
        {/* R249: Clear-N-filters mirror of R240 (HistoryPanel) +   */}
        {/* R238 (Scanner) + R241 (Collaborator) + R242 (Target).   */}
        {/* ProxyPanel's HistoryPane has 6 filter dimensions:       */}
        {/* host, method, status (via min/max), content, search,    */}
        {/* in_scope_only. Only renders when ≥1 is active.          */}
        {(() => {
          const activeFilters: string[] = [];
          if (filter.host_contains) activeFilters.push("host");
          if (filter.method) activeFilters.push("method");
          if (filter.status_min != null || filter.status_max != null)
            activeFilters.push("status");
          if (filter.content_type_contains) activeFilters.push("content");
          if (filter.search_text) activeFilters.push("search");
          if (filter.in_scope_only) activeFilters.push("in-scope");
          const n = activeFilters.length;
          if (n === 0) return null;
          return (
            <button
              className="ghost"
              onClick={() => setFilter({ limit: filter.limit ?? 2000 })}
              title={`Clear all ${n} active filter${n === 1 ? "" : "s"}: ${activeFilters.join(", ")} — keep the limit`}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              ⨯ clear {n} filter{n === 1 ? "" : "s"}
            </button>
          );
        })()}
        <div className="sep" />
        <button onClick={refresh}>Refresh</button>
        <button className="danger" onClick={async () => { if (confirm("Clear all history?")) { await api.historyClear(); refresh(); } }}>Clear</button>
        <span className="spacer" style={{ flex: 1 }} />
        {/* R545: "📊" stats badge — 10th panel in the "📊" family. */}
        {/* Burp Pro's HTTP history header shows a status-class       */}
        {/* breakdown; our ProxyPanel toolbar had just a raw row     */}
        {/* count. R545 upgrades the badge with a status-class +     */}
        {/* method split so operators scanning the toolbar see the   */}
        {/* traffic shape at a glance — "80% 2xx / 15% 4xx / 5% 5xx" */}
        {/* / "mostly GET + POST". Zero backend — pure single-pass   */}
        {/* reduce over the already-fetched `rows` array; computed   */}
        {/* inside an IIFE so no additional state hooks are needed.  */}
        {/* Companion to R440 Repeater / R442 History hosts / R451   */}
        {/* Collaborator / R452 Target severity / R466 Decoder /     */}
        {/* R469 Sequencer / R471 CookieJar / R476 Intruder / R520   */}
        {/* Logger "📊" badges.                                      */}
        <span
          className="badge"
          title={`${rows.length} row${rows.length === 1 ? "" : "s"} · status-class + method breakdown across the fetched set`}
        >
          {(() => {
            if (rows.length === 0) return `📊 0 rows`;
            let s2 = 0, s3 = 0, s4 = 0, s5 = 0, sOther = 0;
            const methods: Record<string, number> = {};
            for (const r of rows) {
              const s = r.status ?? 0;
              if (s >= 200 && s < 300) s2++;
              else if (s >= 300 && s < 400) s3++;
              else if (s >= 400 && s < 500) s4++;
              else if (s >= 500 && s < 600) s5++;
              else sOther++;
              const m = r.method || "?";
              methods[m] = (methods[m] ?? 0) + 1;
            }
            const classParts: string[] = [];
            if (s2 > 0) classParts.push(`${s2} 2xx`);
            if (s3 > 0) classParts.push(`${s3} 3xx`);
            if (s4 > 0) classParts.push(`${s4} 4xx`);
            if (s5 > 0) classParts.push(`${s5} 5xx`);
            if (sOther > 0) classParts.push(`${sOther} other`);
            // Top 2 methods only — keeps the badge terse on a
            // GET-heavy stream.
            const topMethods = Object.entries(methods)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 2)
              .map(([k, v]) => `${v} ${k}`);
            const classStr = classParts.length > 0 ? ` · ${classParts.join(" ")}` : "";
            const methodStr = topMethods.length > 0 ? ` · ${topMethods.join(" ")}` : "";
            return `📊 ${rows.length} rows${classStr}${methodStr}`;
          })()}
        </span>
      </div>
      <div className="split-v" style={{ flex: 1 }}>
        <div className="table">
          <table>
            <colgroup>
              <col style={{ width: 60 }} />
              <col style={{ width: 60 }} />
              <col style={{ width: 50 }} />
              <col style={{ width: 220 }} />
              <col />
              <col style={{ width: 38 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 90 }} />
              <col style={{ width: 200 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 100 }} />
            </colgroup>
            {/* R246: Sticky header mirror of R243/R244/R245.    */}
            {/* Operators scrolling the proxy history table keep */}
            {/* column labels visible on scroll.                 */}
            <thead
              style={{
                position: "sticky",
                top: 0,
                zIndex: 1,
                background: "var(--bg)",
              }}
            >
              <tr>
                <th>#</th>
                <th>Method</th>
                <th>Status</th>
                <th>Host</th>
                <th>Path</th>
                <th title="Request has query / form params">P</th>
                <th>Length</th>
                <th>MIME</th>
                <th>Title</th>
                <th>Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={selected?.id === r.id ? "selected" : ""} onClick={() => setSelected(r)} onContextMenu={(e) => onRowContextMenu(e, r)}>
                  <td className="mono">{r.id}</td>
                  <td className="mono">{r.method}</td>
                  <td className={`mono status-${Math.floor((r.status || 0) / 100)}xx`}>{r.status ?? "—"}</td>
                  <td className="mono" title={`${r.scheme}://${r.host}${r.port !== 80 && r.port !== 443 ? ":" + r.port : ""}`}>
                    {r.scheme}://{r.host}{r.port !== 80 && r.port !== 443 ? ":" + r.port : ""}
                  </td>
                  <td className="mono" title={r.path}>{r.path}</td>
                  <td
                    className="mono"
                    style={{ textAlign: "center", color: (r.param_count ?? 0) > 0 ? "var(--accent)" : "var(--text-faint)" }}
                    title={(r.param_count ?? 0) > 0 ? `${r.param_count} parameter(s)` : "no parameters"}
                  >
                    {(r.param_count ?? 0) > 0 ? "✓" : ""}
                  </td>
                  <td className="mono">{r.content_length ?? "—"}</td>
                  <td className="mono" style={{ color: "var(--text-dim)" }} title={r.content_type ?? ""}>
                    {shortMime(r.content_type)}
                  </td>
                  <td style={{ color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.title ?? ""}>
                    {r.title ?? ""}
                  </td>
                  <td className="mono">{r.elapsed_ms ?? "—"} ms</td>
                  <td>
                    <button className="ghost" onClick={(e) => { e.stopPropagation(); sendToRepeater(r); }}>→ Repeater</button>
                    <button className="ghost" onClick={(e) => { e.stopPropagation(); sendToOrganizer(r); }}>★</button>
                    <button className="ghost" title="Generate CSRF PoC HTML" onClick={(e) => { e.stopPropagation(); void generateCsrfPoc(r); }}>CSRF</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ borderTop: "1px solid var(--border)", minHeight: 0 }}>
          <TransactionViewer tx={tx} />
        </div>
      </div>
      <PocModal payload={poc} onClose={() => setPoc(null)} />
      <JwtModal
        open={jwtTxId != null}
        transactionId={jwtTxId}
        onClose={() => setJwtTxId(null)}
      />
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
                  label: "Send to Organizer",
                  hotkey: "Ctrl+O",
                  onClick: () => void sendToOrganizer(menu.data!),
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
                { separator: true },
                {
                  label: "Generate CSRF PoC",
                  onClick: () => void generateCsrfPoc(menu.data!),
                  hint: "cross-origin form that reissues this request",
                },
                {
                  label: "Generate clickjacking PoC",
                  onClick: () => void generateClickjackPoc(menu.data!),
                  hint: "iframe + overlay",
                },
                { separator: true },
                {
                  label: "Inspect / edit JWTs",
                  onClick: () => setJwtTxId(menu.data!.id),
                  hint: "decode header + claims, edit, re-sign",
                },
                { separator: true },
                {
                  label: "Copy URL",
                  onClick: () =>
                    void copyToClipboard(urlFromSummary(menu.data!)),
                },
                {
                  label: "Copy as cURL",
                  hint: "with full headers + body",
                  onClick: () => void copyAs(menu.data!, "curl"),
                },
                {
                  label: "Copy as PowerShell",
                  hint: "Invoke-WebRequest",
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
                // R537: HistoryPanel R166/R403 parity — three
                // clipboard copy variants for the request bytes.
                // The existing shell-replay copies (cURL /
                // PowerShell / Python / fetch) reconstruct the
                // request from a parsed shape; these three dump
                // the raw stored bytes directly so operators who
                // want to feed them into another tool (Burp
                // Repeater on a sibling box, a scratch editor,
                // Fiddler) get the exact wire bytes. Shared
                // header/body split logic matches HistoryPanel
                // exactly: find CRLF-CRLF or LF-LF boundary;
                // headers-only = pre-boundary; body-only = post-
                // boundary.
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
                {
                  label: "Copy as HAR entry",
                  hint: "single-entry HAR 1.2 log",
                  onClick: () => void copyAsHar(menu.data!),
                },
                {
                  label: "⬇ Save as HAR file",
                  hint: "single-entry HAR 1.2 log · to disk",
                  onClick: () => void saveAsHar(menu.data!),
                },
                {
                  label: "Open response in browser",
                  hint: "render body via OS default handler",
                  onClick: () => void openResponseInBrowser(menu.data!),
                },
                {
                  label: "Request in browser",
                  hint: "re-fetch the URL via OS default browser",
                  onClick: () => void requestInBrowser(menu.data!),
                },
                {
                  label: "Save response body…",
                  hint: "binary-safe write, body only",
                  onClick: () => void saveResponseBody(menu.data!, false),
                },
                {
                  label: "Save raw response…",
                  hint: "status line + headers + body as .txt",
                  onClick: () => void saveResponseBody(menu.data!, true),
                },
                // R538: HistoryPanel R166/R403/R414 parity — four
                // response-copy variants complementing R537's
                // request-copy trio. Operators auditing security
                // headers (CSP, HSTS, Set-Cookie flags, CORS)
                // want just the response header block; those
                // reading JSON API responses want pretty-printed
                // output for eyeballing without a jq pipe. Same
                // shared header/body split logic as R537: find
                // CRLF-CRLF or LF-LF boundary. Pretty-JSON branch
                // attempts JSON.parse + re-stringify with 2-space
                // indent; falls back to raw body on parse failure
                // so the entry never dead-ends.
                {
                  label: "Copy response body",
                  hint: "clipboard · body only",
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
                      await navigator.clipboard.writeText(body);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
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
                  label: "Set highlight…",
                  hint: menu.data!.highlight
                    ? `currently: ${menu.data!.highlight}`
                    : "red/orange/yellow/green/cyan/blue/purple",
                  onClick: () => void setRowHighlight(menu.data!),
                },
                {
                  label: "Clear highlight",
                  hint: menu.data!.highlight ?? "no highlight set",
                  disabled: !menu.data!.highlight,
                  onClick: () => void clearRowHighlight(menu.data!),
                },
                {
                  label: "Set comment…",
                  hint: menu.data!.comment
                    ? `currently: ${menu.data!.comment.slice(0, 40)}${menu.data!.comment.length > 40 ? "…" : ""}`
                    : "annotate this transaction",
                  onClick: () => void setRowComment(menu.data!),
                },
                {
                  label: "Add tag…",
                  hint:
                    (menu.data!.tags?.length ?? 0) > 0
                      ? `${menu.data!.tags.length} tag${menu.data!.tags.length === 1 ? "" : "s"} · ${menu.data!.tags[0]}${menu.data!.tags.length > 1 ? "…" : ""}`
                      : "no tags yet",
                  onClick: () => void addRowTag(menu.data!),
                },
                { separator: true },
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
                // R654: ProxyPanel row-right-click "Copy as JSON" —
                // completes the 4-panel row-level Copy-as-JSON set
                // (HistoryPanel R651 + Scanner R652 + Target R653
                // + ProxyPanel R654). Dumps the full StoredSummary
                // record pretty-printed, matching R651 behavior
                // byte-for-byte since both panels share StoredSummary.
                {
                  label: "Copy as JSON",
                  hint: "full StoredSummary record · pretty-printed",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!, null, 2),
                    ),
                },
                // R711: ProxyPanel row "Copy JSONL line" — 4th
                // panel in the row-level JSONL-line family
                // (HistoryPanel R708 + Scanner R709 + Target
                // R710 + ProxyPanel R711). Single-line NDJSON
                // for appending to a .jsonl log / piping to jq.
                // Trailing newline for clean concat. Byte-
                // identical to R708 HistoryPanel entry since
                // both panels share StoredSummary.
                {
                  label: "Copy JSONL line",
                  hint: "one object, one line + newline",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!) + "\n",
                    ),
                },
                // R718: ProxyPanel row "Copy method+URL+status"
                // — 2nd panel in the ultra-compact triage-line
                // family (HistoryPanel R717 + ProxyPanel R718).
                // Byte-identical format since both panels share
                // StoredSummary: "METHOD url [status (size)]".
                // Scheme-aware port suppression (:80 for http,
                // :443 for https). Falls back to request-only
                // when status isn't recorded.
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
                // R659: ProxyPanel row-right-click "Copy as
                // Markdown" — mirror of R640 HistoryPanel row-
                // right-click Markdown on ProxyPanel. Produces one
                // H3 section with method+URL + status + content-
                // type + size + optional highlight/comment/tags.
                // Byte-identical to R640 output since both share
                // StoredSummary.
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
                // R666: ProxyPanel row-right-click "Copy table row"
                // — single-row Markdown table variant matching
                // R663 HistoryPanel pattern. Byte-identical cells
                // since both share StoredSummary. Completes the
                // 4-panel row-level Copy-as-table family
                // (HistoryPanel R663 / Scanner R664 / Target R665
                // / ProxyPanel R666).
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
                // R596: ProxyPanel row-right-click "− Exclude host" — mirror
                // of R590 HistoryPanel + R592 Target + R594 Scanner on
                // ProxyPanel. Semantically DIFFERENT from "Remove host from
                // scope" above: that one removes an existing include rule;
                // R596 ADDS an explicit exclude rule (`match_kind:
                // "exclude"`) that actively filters the host out even when
                // a broader include rule exists higher up. Builds the same
                // inline exclude-rule shape as R590/R592/R594. Backend's
                // unique-rule guard idempotently no-ops. Danger-styled.
                // Always enabled when the row has a host.
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
                // R597: ProxyPanel row-right-click "− Exclude path" — path-
                // exact variant of R596 on ProxyPanel. Completes the
                // 4-panel exclude family (HistoryPanel R590/R591 +
                // Target R592/R593 + Scanner R594/R595 + ProxyPanel
                // R596/R597) for full cross-panel symmetry with the
                // row-level include family (R578-R581 host + path).
                // Same inline exclude-rule shape as R591 but reads
                // `menu.data!.path` directly since ProxyPanel's rows
                // ARE StoredSummary (same pattern as R591 on History).
                // Danger-styled when the row has a path; disabled with
                // "no path" hint when it doesn't. Backend's unique-rule
                // guard idempotently no-ops.
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
              ]
            : []
        }
      />
    </div>
  );
}

/** Collapse `application/json; charset=utf-8` → `json`, etc. */
function shortMime(ct?: string | null): string {
  if (!ct) return "";
  const t = ct.split(";")[0].trim().toLowerCase();
  const slash = t.indexOf("/");
  if (slash < 0) return t;
  const sub = t.slice(slash + 1);
  // Common knowns.
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

function TransactionViewer({ tx }: { tx: TransactionView | null }) {
  if (!tx) return <div className="empty">Select a request to view the raw request and response.</div>;
  // R544: Sticky URL header — completes the sticky-URL family
  // (R491 Scanner / R492 Target Issues / R543 History / R544
  // ProxyPanel). Operators previewing a transaction want the
  // URL on the clipboard without a right-click + Copy URL pivot.
  // Shows the URL inline (truncated with ellipsis if long + full
  // URL in title attr) + a "📎 Copy URL" button. Byte-identical
  // visual + mechanism to R543 for cross-panel consistency.
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
            onClick={() => void copyToClipboard(url)}
            title="Copy the full URL to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📎 Copy URL
          </button>
          {/* R547: Sibling "📋 cURL" button — mirror of R546 on
              HistoryPanel sticky URL header. One-click cURL from
              the detail pane without a row-right-click pivot.
              Byte-identical output to the row-right-click "Copy
              as cURL" entry since both use the same buildCurl +
              fromSummaryAndRaw pipeline. */}
          <button
            className="ghost"
            onClick={() => {
              if (!tx.summary || !tx.request_raw) {
                alert("Transaction has no stored request_raw — cannot build cURL.");
                return;
              }
              try {
                const req = fromSummaryAndRaw(tx.summary, tx.request_raw);
                void copyToClipboard(buildCurl(req));
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title="Copy as cURL (headers + body) to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 cURL
          </button>
          {/* R551: Sticky-header "📋 HAR" button — mirror of R550
              HistoryPanel sticky-header HAR, applied to ProxyPanel.
              Byte-identical output to R513 row-right-click "Copy
              as HAR entry" since both use the same buildHarEntry +
              buildHarLog pipeline with inline response-parse. */}
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
                void copyToClipboard(JSON.stringify(har, null, 2));
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title="Copy single-entry HAR 1.2 log (request + response) to clipboard"
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            📋 HAR
          </button>
          {/* R582: Sticky-header "+ Add host" button — scope-add
              from the detail pane without a row-right-click
              pivot. Extends the Copy URL / cURL / HAR trio with
              a scope op. Backend's unique-rule guard idempotently
              no-ops on duplicate adds so no pre-filter needed
              (TransactionViewer is a child component that doesn't
              own ProxyPanel's scope state). */}
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
          {/* R588: Sticky-header "+ Add host:path" button — path-exact
              variant of R582 at the sticky-header level, mirror of
              R586 (Scanner) + R587 (History) on ProxyPanel. Operators
              often want narrower scope rules — just this endpoint,
              not the whole host. Uses buildPathIncludeRule which
              strips the query string. Backend's unique-rule guard
              idempotently no-ops on duplicate adds. */}
          <button
            className="ghost"
            onClick={async () => {
              if (!tx.summary?.host) {
                alert("Transaction has no host — cannot add to scope.");
                return;
              }
              if (!tx.summary?.path) {
                alert("Transaction has no path — cannot add to scope.");
                return;
              }
              try {
                await api.scopeAddRule(
                  buildPathIncludeRule(tx.summary.host, tx.summary.path),
                );
                alert(
                  `Added "${tx.summary.host}${tx.summary.path}" to scope.`,
                );
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Add path ${tx.summary?.host ?? ""}${tx.summary?.path ?? ""} to scope include rules (query string stripped). Backend dedupes if already in scope.`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            + path
          </button>
        </div>
      )}
      <div>
        <div className="header">Request <span style={{ color: "var(--text-faint)" }}>#{tx.summary.id}</span></div>
        <pre>{tx.request_raw}</pre>
      </div>
      <div>
        <div className="header">Response <span style={{ color: "var(--text-faint)" }}>{tx.summary.status} · {tx.summary.content_type || "—"}</span></div>
        <pre>{tx.response_raw || "(no response captured)"}</pre>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------- WebSockets history

function WebSocketsPane() {
  const [sessions, setSessions] = useState<WsSessionRow[]>([]);
  const [selected, setSelected] = useState<WsSessionRow | null>(null);
  const [messages, setMessages] = useState<WsMessageRow[]>([]);
  const [auto, setAuto] = useState(true);
  const [loading, setLoading] = useState(false);
  // R281: WS sessions search filter — case-insensitive substring
  // match against host + path. Operators scanning a target with
  // dozens of concurrent WS sessions (chat apps, live dashboards)
  // need a way to narrow down without scrolling. Esc clears per
  // the R201/R219/R223/R224/R227/R260 Esc-clear-search family.
  // Not persisted across restarts — the sessions themselves are
  // persisted, but the search is a scratch filter.
  const [sessionSearch, setSessionSearch] = useState("");
  // Two separate right-click menus for the two tables in this pane.
  const [sessionMenu, setSessionMenu] = useState<MenuState<WsSessionRow> | null>(null);
  const [messageMenu, setMessageMenu] = useState<MenuState<WsMessageRow> | null>(null);

  // ---- Session context-menu actions ---------------------------------

  function sessionUrl(s: WsSessionRow): string {
    const scheme = s.port === 443 ? "wss" : "ws";
    const port = s.port === 80 || s.port === 443 ? "" : `:${s.port}`;
    return `${scheme}://${s.host}${port}${s.path}`;
  }

  async function sendHandshakeToRepeater(s: WsSessionRow) {
    try {
      const id = await api.repeaterAddFromHistory(
        s.handshake_id,
        `WS ${s.host}${s.path}`,
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
      console.log("ws handshake → repeater tab", id);
    } catch (e) {
      alert(`Send handshake to Repeater failed: ${e}`);
    }
  }

  // ---- Message context-menu actions ---------------------------------

  /** Hex-dump a message's payload for Copy-as-hex. We prefer the
   *  textual payload when available (UTF-8 encode to bytes), falling
   *  back to decoding base64 for binary frames. */
  function messageToHex(m: WsMessageRow): string {
    let bytes: Uint8Array;
    if (m.text) {
      bytes = new TextEncoder().encode(m.text);
    } else if (m.base64) {
      try {
        const raw = atob(m.base64);
        bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      } catch {
        return "";
      }
    } else {
      return "";
    }
    const out: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      const ascii = Array.from(chunk)
        .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
        .join("");
      out.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
    }
    return out.join("\n");
  }

  function messagePayload(m: WsMessageRow): string {
    return m.text ?? m.base64 ?? "";
  }

  async function replayMessage(m: WsMessageRow) {
    if (!selected) return;
    const kind: "text" | "binary" | "ping" | "pong" | "close" =
      m.opcode_label === "binary"
        ? "binary"
        : m.opcode_label === "ping"
          ? "ping"
          : m.opcode_label === "pong"
            ? "pong"
            : m.opcode_label === "close"
              ? "close"
              : "text";
    try {
      const result = await api.wsReplay({
        url: sessionUrl(selected),
        frames: [
          {
            kind,
            text: m.text ?? undefined,
            base64: m.base64 ?? undefined,
          },
        ],
        drain_ms: 500,
      });
      alert(
        `Replayed via new session ${result.session_id}: ${result.sent} sent, ${result.received} received${result.error ? ` · error: ${result.error}` : ""}.`,
      );
    } catch (e) {
      alert(`Replay failed: ${e}`);
    }
  }

  async function refreshSessions() {
    try {
      const list = await api.wsSessionsList(500);
      setSessions(list);
      // Follow latest selection — if the previously selected session's row
      // has a new message count, pull its messages so the right pane keeps up.
      if (selected) {
        const found = list.find((s) => s.id === selected.id);
        if (found) {
          setSelected(found);
          if (found.message_count !== selected.message_count) {
            await loadMessages(found.id);
          }
        }
      }
    } catch (e) {
      console.warn("ws sessions:", e);
    }
  }

  async function loadMessages(sessionId: number) {
    setLoading(true);
    try {
      const list = await api.wsMessagesList(sessionId);
      setMessages(list);
    } catch (e) {
      alert(`${e}`);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refreshSessions();
  }, []);

  useEffect(() => {
    if (!auto) return;
    const t = setInterval(() => void refreshSessions(), 3000);
    return () => clearInterval(t);
  }, [auto, selected?.id, selected?.message_count]);

  useEffect(() => {
    if (selected) void loadMessages(selected.id);
    else setMessages([]);
  }, [selected?.id]);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div className="toolbar">
        <button onClick={() => void refreshSessions()}>Refresh</button>
        <label>
          <input
            type="checkbox"
            checked={auto}
            onChange={(e) => setAuto(e.target.checked)}
          />{" "}
          Auto-refresh
        </label>
        {/* ------------------------------------------------------- */}
        {/* R155: Export the selected session's messages as JSONL —  */}
        {/* mirror of R141's Logger export. One JSON object per line */}
        {/* is friendlier than CSV for binary (base64) frames + lets */}
        {/* operators jq-filter / grep the dump without re-encoding. */}
        {/* Scope: the currently-selected session (host + path).     */}
        {/* Operators who want "everything" select each session and  */}
        {/* export in turn — a wholesale all-sessions dump would be  */}
        {/* ambiguous (which host's messages? which order?) + would  */}
        {/* need N round-trips to loadMessages anyway.               */}
        <button
          disabled={!selected || messages.length === 0}
          onClick={() => {
            if (!selected || messages.length === 0) return;
            try {
              const lines = messages.map((m) =>
                JSON.stringify({
                  session_id: selected.id,
                  host: selected.host,
                  port: selected.port,
                  path: selected.path,
                  ts_ms: m.ts_ms,
                  direction: m.direction,
                  opcode: m.opcode_label,
                  size_bytes: m.size,
                  // Only emit the populated side so the row isn't
                  // bloated with null fields. Text frames get `text`,
                  // binary frames get `base64` as the raw payload.
                  ...(m.text != null ? { text: m.text } : {}),
                  ...(m.base64 != null ? { base64: m.base64 } : {}),
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
              const hostSlug = selected.host.replace(/[^a-z0-9.-]/gi, "_");
              a.href = url;
              a.download = `burpfree-ws-${hostSlug}-${stamp}.jsonl`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            !selected
              ? "Select a session to export its messages."
              : messages.length === 0
                ? "Selected session has no messages to export."
                : `Export ${messages.length} message${messages.length === 1 ? "" : "s"} from ${selected.host}${selected.path} as JSONL (one JSON object per line; binary frames base64-encoded)`
          }
        >
          ⬇ Export JSONL
        </button>
        {/* ------------------------------------------------------- */}
        {/* R215: Export the selected session's messages as CSV —    */}
        {/* companion to the R155 JSONL writer above. CSV is easier */}
        {/* for Excel / pivot-table triage; binary frames collapse  */}
        {/* to a `<binary N bytes>` placeholder in the payload       */}
        {/* column since CSV + binary don't mix cleanly. Text       */}
        {/* frames export their payload directly (with CSV-escaped  */}
        {/* quotes + newlines). Headers: session_id, host, port,    */}
        {/* path, ts_ms, direction, opcode, size_bytes, payload.    */}
        <button
          disabled={!selected || messages.length === 0}
          onClick={() => {
            if (!selected || messages.length === 0) return;
            try {
              const headers = [
                "session_id",
                "host",
                "port",
                "path",
                "ts_ms",
                "direction",
                "opcode",
                "size_bytes",
                "payload",
              ];
              const esc = (v: unknown) => {
                const s = v == null ? "" : String(v);
                return /[",\n]/.test(s)
                  ? `"${s.replace(/"/g, '""')}"`
                  : s;
              };
              const body = messages
                .map((m) => {
                  const payload =
                    m.text != null
                      ? m.text
                      : m.base64 != null
                        ? `<binary ${m.size} bytes>`
                        : "";
                  return [
                    selected.id,
                    selected.host,
                    selected.port,
                    selected.path,
                    m.ts_ms,
                    m.direction,
                    m.opcode_label,
                    m.size,
                    payload,
                  ]
                    .map(esc)
                    .join(",");
                })
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
              const hostSlug = selected.host.replace(/[^a-z0-9.-]/gi, "_");
              a.href = url;
              a.download = `burpfree-ws-${hostSlug}-${stamp}.csv`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            !selected
              ? "Select a session to export its messages."
              : messages.length === 0
                ? "Selected session has no messages to export."
                : `Export ${messages.length} message${messages.length === 1 ? "" : "s"} from ${selected.host}${selected.path} as CSV (text frames inline; binary frames show as "<binary N bytes>" placeholder)`
          }
        >
          ⬇ Export CSV
        </button>
        {sessions.length > 0 && (
          <input
            type="text"
            value={sessionSearch}
            onChange={(e) => setSessionSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && sessionSearch) {
                e.preventDefault();
                e.stopPropagation();
                setSessionSearch("");
              }
            }}
            placeholder="Filter host / path…"
            title="Case-insensitive substring match on session host + path. Esc clears."
            style={{
              fontSize: 11,
              padding: "2px 6px",
              width: 180,
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text)",
            }}
          />
        )}
        <span className="spacer" style={{ flex: 1 }} />
        <span className="badge">
          {sessionSearch.trim()
            ? `${sessions.filter((s) => {
                const q = sessionSearch.trim().toLowerCase();
                return (
                  s.host.toLowerCase().includes(q) ||
                  s.path.toLowerCase().includes(q)
                );
              }).length} / ${sessions.length} sessions`
            : `${sessions.length} sessions`}
        </span>
        {selected && (
          <span className="badge">
            {selected.message_count} msg · {selected.closed_at_ms ? "closed" : "open"}
          </span>
        )}
      </div>
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div
          style={{
            width: 360,
            borderRight: "1px solid var(--border)",
            overflow: "auto",
            background: "var(--bg)",
          }}
        >
          {sessions.length === 0 && (
            <div className="empty" style={{ padding: 20, lineHeight: 1.5 }}>
              No WebSocket sessions captured yet. The proxy records every ws
              handshake it tunnels; sessions appear here as soon as a frame
              crosses the wire.
            </div>
          )}
          {(() => {
            const q = sessionSearch.trim().toLowerCase();
            if (!q || sessions.length === 0) return null;
            const matches = sessions.filter(
              (s) =>
                s.host.toLowerCase().includes(q) ||
                s.path.toLowerCase().includes(q),
            );
            if (matches.length > 0) return null;
            return (
              <div
                className="empty"
                style={{
                  fontSize: 11,
                  padding: "6px 10px",
                  color: "var(--text-dim)",
                }}
              >
                No sessions match "{sessionSearch}" — Esc to clear the filter.
              </div>
            );
          })()}
          <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ color: "var(--text-dim)", fontSize: 11, textAlign: "left" }}>
                <th style={{ padding: "4px 6px" }}>Host</th>
                <th style={{ padding: "4px 6px" }}>Path</th>
                <th style={{ padding: "4px 6px", textAlign: "right" }}>Msgs</th>
                <th style={{ padding: "4px 6px" }}>State</th>
              </tr>
            </thead>
            <tbody>
              {sessions
                .filter((s) => {
                  const q = sessionSearch.trim().toLowerCase();
                  if (!q) return true;
                  return (
                    s.host.toLowerCase().includes(q) ||
                    s.path.toLowerCase().includes(q)
                  );
                })
                .map((s) => (
                <tr
                  key={s.id}
                  onClick={() => setSelected(s)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setSelected(s);
                    setSessionMenu({ x: e.clientX, y: e.clientY, data: s });
                  }}
                  style={{
                    cursor: "context-menu",
                    background:
                      selected?.id === s.id ? "var(--accent-dim)" : "transparent",
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  <td style={{ padding: "4px 6px" }}>
                    {s.host}
                    {s.port !== 80 && s.port !== 443 ? `:${s.port}` : ""}
                  </td>
                  <td
                    style={{
                      padding: "4px 6px",
                      maxWidth: 150,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={s.path}
                  >
                    {s.path}
                  </td>
                  <td style={{ padding: "4px 6px", textAlign: "right" }}>
                    {s.message_count}
                  </td>
                  <td style={{ padding: "4px 6px", color: "var(--text-dim)" }}>
                    {s.closed_at_ms
                      ? `${s.close_code ?? "—"}`
                      : "open"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
          {!selected ? (
            <div className="empty" style={{ padding: 20 }}>
              Select a session on the left to inspect frames.
            </div>
          ) : (
            <>
              <div
                style={{
                  padding: "6px 10px",
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                  fontSize: 11.5,
                }}
              >
                <strong className="mono">
                  wss://{selected.host}:{selected.port}
                  {selected.path}
                </strong>
                <span style={{ color: "var(--text-dim)", marginLeft: 10 }}>
                  opened {new Date(selected.opened_at_ms).toLocaleTimeString()}
                  {selected.closed_at_ms &&
                    ` · closed ${new Date(selected.closed_at_ms).toLocaleTimeString()}`}
                  {selected.close_reason && ` · ${selected.close_reason}`}
                </span>
              </div>
              <div style={{ flex: 1, overflow: "auto" }}>
                {loading && (
                  <div className="empty" style={{ padding: 10 }}>
                    Loading messages…
                  </div>
                )}
                <table className="mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
                  <colgroup>
                    <col style={{ width: 60 }} />
                    <col style={{ width: 70 }} />
                    <col style={{ width: 56 }} />
                    <col style={{ width: 90 }} />
                    <col />
                  </colgroup>
                  <thead>
                    <tr style={{ color: "var(--text-dim)", textAlign: "left" }}>
                      <th style={{ padding: "4px 6px" }}>Dir</th>
                      <th style={{ padding: "4px 6px" }}>Opcode</th>
                      <th style={{ padding: "4px 6px", textAlign: "right" }}>Size</th>
                      <th style={{ padding: "4px 6px" }}>Time</th>
                      <th style={{ padding: "4px 6px" }}>Payload preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {messages.map((m) => (
                      <tr
                        key={m.id}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setMessageMenu({ x: e.clientX, y: e.clientY, data: m });
                        }}
                        style={{
                          borderBottom: "1px solid var(--border)",
                          cursor: "context-menu",
                          background:
                            m.direction === "out"
                              ? "transparent"
                              : "rgba(75,139,239,0.05)",
                        }}
                      >
                        <td
                          style={{
                            padding: "3px 6px",
                            color:
                              m.direction === "out"
                                ? "var(--accent)"
                                : "var(--text)",
                            fontWeight: 600,
                          }}
                        >
                          {m.direction === "out" ? "↑ out" : "↓ in"}
                        </td>
                        <td style={{ padding: "3px 6px" }}>
                          {m.opcode_label}
                        </td>
                        <td
                          style={{
                            padding: "3px 6px",
                            textAlign: "right",
                            color: "var(--text-dim)",
                          }}
                        >
                          {m.size}B
                        </td>
                        <td
                          style={{
                            padding: "3px 6px",
                            color: "var(--text-dim)",
                          }}
                        >
                          {new Date(m.ts_ms).toLocaleTimeString()}
                        </td>
                        <td
                          style={{
                            padding: "3px 6px",
                            maxWidth: 500,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                          title={m.text ?? m.base64 ?? ""}
                        >
                          {m.text
                            ? m.text
                            : m.base64
                              ? `${m.base64.slice(0, 80)}${m.base64.length > 80 ? "…" : ""}`
                              : "(binary)"}
                          {m.truncated && (
                            <span style={{ color: "var(--amber)" }}> …truncated</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!loading && messages.length === 0 && (
                  <div className="empty" style={{ padding: 20 }}>
                    No messages captured for this session.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
      <FloatingMenu
        state={sessionMenu}
        onClose={() => setSessionMenu(null)}
        items={
          sessionMenu?.data
            ? [
                {
                  label: "Copy handshake URL",
                  onClick: () =>
                    void copyToClipboard(sessionUrl(sessionMenu.data!)),
                },
                {
                  label: "Send handshake to Repeater",
                  onClick: () => void sendHandshakeToRepeater(sessionMenu.data!),
                },
                { separator: true },
                {
                  label: "Refresh messages",
                  onClick: () => void loadMessages(sessionMenu.data!.id),
                },
              ]
            : []
        }
      />
      <FloatingMenu
        state={messageMenu}
        onClose={() => setMessageMenu(null)}
        items={
          messageMenu?.data
            ? [
                {
                  label: "Copy frame payload",
                  onClick: () =>
                    void copyToClipboard(messagePayload(messageMenu.data!)),
                  disabled: !messagePayload(messageMenu.data!),
                },
                {
                  label: "Copy as hex dump",
                  onClick: () =>
                    void copyToClipboard(messageToHex(messageMenu.data!)),
                  disabled: !messagePayload(messageMenu.data!),
                },
                { separator: true },
                {
                  label: "Send to Comparer (left)",
                  onClick: () => {
                    sendToComparer(
                      messagePayload(messageMenu.data!),
                      "",
                      `WS ${messageMenu.data!.direction} ${messageMenu.data!.opcode_label}`,
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "comparer" },
                      }),
                    );
                  },
                  disabled: !messagePayload(messageMenu.data!),
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () => {
                    sendToComparer(
                      "",
                      messagePayload(messageMenu.data!),
                      `WS ${messageMenu.data!.direction} ${messageMenu.data!.opcode_label}`,
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "comparer" },
                      }),
                    );
                  },
                  disabled: !messagePayload(messageMenu.data!),
                },
                { separator: true },
                {
                  label: "Replay this frame",
                  onClick: () => void replayMessage(messageMenu.data!),
                  disabled:
                    !selected ||
                    messageMenu.data!.direction !== "out",
                  hint:
                    messageMenu.data!.direction !== "out"
                      ? "only outbound frames"
                      : undefined,
                },
              ]
            : []
        }
      />
    </div>
  );
}

// --------------------------------------------------------------------- Options

function OptionsPane() {
  const [listener, setListener] = useState("127.0.0.1:8080");
  const [tls, setTls] = useState(true);
  const [running, setRunning] = useState<boolean>(false);
  // TLS pass-through: hosts whose CONNECT bypasses MITM so pinned
  // clients don't reject our leaf. The textarea is the live edit
  // buffer; `savedPassthrough` is the last-persisted value used to
  // compute the dirty flag so the Save button only lights up when
  // something changed.
  const [passthrough, setPassthrough] = useState<string>("");
  const [savedPassthrough, setSavedPassthrough] = useState<string>("");
  const [savingPt, setSavingPt] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const cfg = await api.settingsGet();
        if (cfg.listeners?.[0]) {
          setListener(cfg.listeners[0].address);
          setTls(cfg.listeners[0].tls_intercept);
        }
      } catch {}
      try {
        setRunning((await api.proxyStats()).running);
      } catch {}
      try {
        const list = await api.tlsPassthroughGet();
        const text = list.join("\n");
        setPassthrough(text);
        setSavedPassthrough(text);
      } catch {}
    })();
  }, []);

  async function save() {
    const cfg = await api.settingsGet();
    cfg.listeners = [{ address: listener, tls_intercept: tls, enabled: true }];
    await api.settingsSave(cfg);
    alert("Saved. Restart the proxy for listener changes to take effect.");
  }
  async function toggle() {
    try {
      if (running) await api.proxyStop();
      else await api.proxyStart();
      setRunning(!running);
    } catch (e) { alert(`${e}`); }
  }
  async function savePassthrough() {
    setSavingPt(true);
    try {
      const list = passthrough
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      await api.tlsPassthroughSet(list);
      // Normalise the local buffer to match what the backend persisted
      // so the Save button clears without an extra round-trip.
      const normalised = list.join("\n");
      setPassthrough(normalised);
      setSavedPassthrough(normalised);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setSavingPt(false);
    }
  }

  const ptDirty = passthrough !== savedPassthrough;
  const ptCount = passthrough
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0).length;

  return (
    <div style={{ padding: 14, maxWidth: 640 }}>
      <h3 style={{ marginTop: 0 }}>Proxy listeners</h3>
      <div className="form-row">
        <label>Listener address</label>
        <input value={listener} onChange={(e) => setListener(e.target.value)} />
      </div>
      <div className="form-row">
        <label>TLS interception</label>
        <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} />
        <span style={{ color: "var(--text-dim)" }}>Generate per-host leaf certs for HTTPS CONNECT tunnels</span>
      </div>
      <div className="form-row">
        <label>Status</label>
        <span className={running ? "badge green" : "badge red"}>{running ? "running" : "stopped"}</span>
        <button onClick={toggle}>{running ? "Stop proxy" : "Start proxy"}</button>
      </div>
      <div className="form-row">
        <label></label>
        <button className="primary" onClick={save}>Save</button>
      </div>

      <h3 style={{ marginTop: 24 }}>TLS pass-through</h3>
      <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 6, lineHeight: 1.5 }}>
        One host pattern per line. CONNECT targets whose hostname contains
        any pattern (case-insensitive substring) will be forwarded raw
        instead of MITM-terminated. Use this for cert-pinned mobile apps or
        hardware clients that reject our root CA. Takes effect on the next
        CONNECT — no proxy restart required.
      </div>
      <textarea
        value={passthrough}
        onChange={(e) => setPassthrough(e.target.value)}
        rows={6}
        spellCheck={false}
        placeholder={"e.g.\napi.pinned.example.com\nbank.example"}
        style={{
          width: "100%",
          fontFamily: "var(--font-mono, monospace)",
          fontSize: 12,
          padding: 6,
          background: "var(--bg)",
          color: "var(--text)",
          border: "1px solid var(--border)",
          borderRadius: 4,
          resize: "vertical",
          boxSizing: "border-box",
        }}
      />
      <div
        style={{
          marginTop: 6,
          display: "flex",
          alignItems: "center",
          gap: 10,
        }}
      >
        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
          {ptCount} {ptCount === 1 ? "pattern" : "patterns"}
          {ptDirty ? " · unsaved changes" : ""}
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          className={ptDirty ? "primary" : ""}
          onClick={savePassthrough}
          disabled={!ptDirty || savingPt}
          title="Replace the TLS pass-through list"
        >
          {savingPt ? "Saving…" : ptDirty ? "Save" : "Saved"}
        </button>
      </div>
    </div>
  );
}
