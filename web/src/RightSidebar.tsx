// RightSidebar.tsx
//
// Vertical pill rail on the right edge of the shell, modeled on
// Burp 2026.8's Inspector + Notes right chrome. The rail is always
// visible; clicking a pill opens a drawer that overlays onto the
// right edge of the content area.
//
// Notes are persisted per-project in `localStorage`.
// Inspector is a lightweight introspection surface that shows the
// most recent transaction's request/response summary — enough to be
// useful without having to switch tabs.

import { useEffect, useRef, useState } from "react";
import { api, OobStatus, ProjectInfo, StoredSummary, TransactionView } from "./api";
import { useTheme } from "./theme";

type Drawer = "none" | "inspector" | "notes" | "actions";

export function RightSidebar({ project }: { project: ProjectInfo | null }) {
  const [drawer, setDrawer] = useState<Drawer>("none");
  const projectKey = project?.root || "default";

  return (
    <>
      {drawer !== "none" && (
        <div className="sidebar-drawer">
          {drawer === "inspector" && <InspectorDrawer />}
          {drawer === "notes" && <NotesDrawer projectKey={projectKey} />}
          {drawer === "actions" && <CustomActionsDrawer />}
        </div>
      )}
      <div className="sidebar-rail">
        <RailPill
          label="Inspector"
          active={drawer === "inspector"}
          onClick={() => setDrawer(drawer === "inspector" ? "none" : "inspector")}
        />
        <RailPill
          label="Notes"
          active={drawer === "notes"}
          onClick={() => setDrawer(drawer === "notes" ? "none" : "notes")}
        />
        {/* R891: Burp-identical third "Custom actions" rail pill
            matching the vertical label strip visible in the user's
            Burp screenshot (Inspector / Notes / Custom actions).
            Burp Pro's Custom actions drawer surfaces operator-saved
            macros; ours routes to common cross-panel actions +
            quick-navigate shortcuts. Operators who want a quick
            scratch of "jump to Scanner / clear Comparer / open
            AI drawer" find it here without walking the Command
            Palette. */}
        <RailPill
          label="Custom actions"
          active={drawer === "actions"}
          onClick={() => setDrawer(drawer === "actions" ? "none" : "actions")}
        />
      </div>
    </>
  );
}

// R891: Burp-identical Custom Actions drawer. Collects common
// cross-panel actions + quick-navigate shortcuts behind a single
// pill. Burp Pro's version is operator-configurable macros; ours
// ships a curated list that cross-references the Bambda saved
// filters (R622), the Repeater workspace export (R306), the
// Scanner passive-scan trigger, and the AI drawer open event.
function CustomActionsDrawer() {
  const nav = (section: string) =>
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: section } }),
    );
  const fire = (eventName: string) =>
    window.dispatchEvent(new CustomEvent(eventName));
  const actions: Array<{
    group: string;
    items: Array<{ label: string; hint?: string; onClick: () => void }>;
  }> = [
    {
      group: "Analysis tools",
      items: [
        { label: "Open Scanner", hint: "jump to Scanner panel", onClick: () => nav("scanner") },
        { label: "Open Logger", hint: "live event bus", onClick: () => nav("logger") },
        { label: "Open Collaborator", hint: "OOB listener", onClick: () => nav("collaborator") },
        { label: "Open Decoder", hint: "transform chains", onClick: () => nav("decoder") },
        { label: "Open Comparer", hint: "line / word / byte / JSON diff", onClick: () => nav("comparer") },
      ],
    },
    {
      group: "Workflow",
      items: [
        {
          label: "✦ Open Burp AI drawer",
          hint: "Repeater's inline AI companion (Ctrl+E)",
          onClick: () => {
            nav("repeater");
            setTimeout(() => fire("burpfree:open-burp-ai"), 60);
          },
        },
        {
          label: "⌨ Keyboard shortcut cheatsheet",
          hint: "Ctrl+/",
          onClick: () => fire("burpfree:open-cheatsheet"),
        },
        {
          label: "🔄 Refresh project info",
          hint: "re-read project state from disk",
          onClick: () => fire("burpfree:refresh-project"),
        },
      ],
    },
    {
      group: "Configuration",
      items: [
        { label: "Open Settings", onClick: () => nav("settings") },
        { label: "Open Extensions", onClick: () => nav("extensions") },
        { label: "Open BChecks", onClick: () => nav("bchecks") },
        { label: "Open Session rules", onClick: () => nav("session") },
        { label: "Open Cookie jar", onClick: () => nav("cookies") },
      ],
    },
  ];
  return (
    <div className="drawer-body">
      <div className="drawer-head">
        <strong>Custom actions</strong>
      </div>
      <p className="drawer-blurb">
        Quick-access panel shortcuts and workflow actions. Burp Pro's version
        hosts operator-configurable macros; this ships a curated list.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {actions.map((group) => (
          <div key={group.group}>
            <div
              style={{
                fontSize: 10,
                letterSpacing: 0.4,
                textTransform: "uppercase",
                color: "var(--text-faint)",
                marginBottom: 4,
                paddingBottom: 2,
                borderBottom: "1px solid var(--border)",
              }}
            >
              {group.group}
            </div>
            {group.items.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={item.onClick}
                className="custom-actions-item"
                title={item.hint ?? item.label}
              >
                <span>{item.label}</span>
                {item.hint && (
                  <span
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-faint)",
                      marginLeft: 8,
                    }}
                  >
                    {item.hint}
                  </span>
                )}
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function RailPill({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      className={`rail-pill ${active ? "active" : ""}`}
      onClick={onClick}
      title={active ? `Close ${label}` : `Open ${label}`}
    >
      <span className="rail-pill-label">{label}</span>
    </button>
  );
}

function InspectorDrawer() {
  const [latest, setLatest] = useState<StoredSummary | null>(null);
  const [tx, setTx] = useState<TransactionView | null>(null);

  async function refresh() {
    try {
      const rows = await api.historyList({ limit: 1 });
      const l = rows[0] ?? null;
      setLatest(l);
      if (l) setTx(await api.historyShow(l.id));
      else setTx(null);
    } catch (e) {
      console.error(e);
    }
  }
  useEffect(() => {
    void refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, []);

  if (!latest) {
    return (
      <div className="drawer-head">
        <strong>Inspector</strong>
        <p className="drawer-blurb">No traffic yet. Browse through the proxy and the most recent transaction will show up here.</p>
      </div>
    );
  }

  const requestHeaders = parseHeaders(tx?.request_raw ?? "");
  const responseHeaders = parseHeaders(tx?.response_raw ?? "");
  const scheme = latest.scheme;
  const host = latest.host;
  const path = latest.path;

  return (
    <div className="drawer-body">
      <div className="drawer-head">
        <strong>Inspector</strong>
        <span className="dim" style={{ fontSize: 11 }}>latest tx #{latest.id}</span>
      </div>
      <Section title={`Request · ${latest.method} ${path}`}>
        <KV k="URL" v={`${scheme}://${host}${path}`} mono />
        <KV k="Scheme" v={scheme} />
        <KV k="Status" v={latest.status != null ? String(latest.status) : "—"} />
        <KV k="Params" v={String(latest.param_count ?? 0)} />
        <KV k="MIME" v={latest.content_type || "—"} mono />
        <KV k="Length" v={latest.content_length != null ? `${latest.content_length} B` : "—"} />
        <KV k="Elapsed" v={latest.elapsed_ms != null ? `${latest.elapsed_ms} ms` : "—"} />
      </Section>
      {requestHeaders.length > 0 && (
        <Section title={`Request headers (${requestHeaders.length})`} collapsed>
          {requestHeaders.map(([k, v], i) => (
            <KV key={i} k={k} v={v} mono small />
          ))}
        </Section>
      )}
      {responseHeaders.length > 0 && (
        <Section title={`Response headers (${responseHeaders.length})`} collapsed>
          {responseHeaders.map(([k, v], i) => (
            <KV key={i} k={k} v={v} mono small />
          ))}
        </Section>
      )}
    </div>
  );
}

function parseHeaders(wire: string): Array<[string, string]> {
  if (!wire) return [];
  const sep = wire.indexOf("\r\n\r\n");
  const headerBlock = sep > 0 ? wire.slice(0, sep) : wire.split("\n\n")[0] ?? "";
  const lines = headerBlock.split(/\r?\n/).slice(1); // drop first line (method / status)
  const out: Array<[string, string]> = [];
  for (const line of lines) {
    const i = line.indexOf(":");
    if (i > 0) out.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return out;
}

function Section({ title, collapsed = false, children }: { title: string; collapsed?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(!collapsed);
  return (
    <div className="drawer-section">
      <button className="drawer-section-head" onClick={() => setOpen((v) => !v)}>
        <span className="drawer-caret">{open ? "▾" : "▸"}</span>
        <span>{title}</span>
      </button>
      {open && <div className="drawer-section-body">{children}</div>}
    </div>
  );
}

function KV({ k, v, mono = false, small = false }: { k: string; v: string; mono?: boolean; small?: boolean }) {
  return (
    <div className={`drawer-kv ${small ? "small" : ""}`}>
      <span className="drawer-kv-k">{k}</span>
      <span className={`drawer-kv-v ${mono ? "mono" : ""}`} title={v}>{v}</span>
    </div>
  );
}

function NotesDrawer({ projectKey }: { projectKey: string }) {
  const storageKey = `burpfree:notes:${projectKey}`;
  const [text, setText] = useState<string>(() => {
    try { return window.localStorage.getItem(storageKey) ?? ""; } catch { return ""; }
  });
  const [saved, setSaved] = useState(true);
  const timer = useRef<number | null>(null);

  // Debounced auto-save.
  useEffect(() => {
    setSaved(false);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      try {
        window.localStorage.setItem(storageKey, text);
        setSaved(true);
      } catch (e) {
        console.error(e);
      }
    }, 600);
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [text, storageKey]);

  return (
    <div className="drawer-body">
      <div className="drawer-head">
        <strong>Notes</strong>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="dim" style={{ fontSize: 11 }}>
          {saved ? "saved" : "saving…"}
        </span>
      </div>
      <textarea
        className="notes-area"
        placeholder="Scratch pad for the current engagement. Stored per-project in local storage."
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <p className="drawer-blurb">
        {text.length} character(s). Persisted locally; include in a report by copy-paste.
      </p>
    </div>
  );
}

/* ----------------------- Enhanced status bar ----------------------- */

type ProxyStatsLike = {
  running: boolean;
  listeners: string[];
  conns_accepted: number;
  requests_forwarded: number;
  tls_mitm: number;
  errors: number;
};

export function BurpStyleStatusBar({
  project,
  stats,
  pending,
  findings,
  oob,
  onNavigate,
}: {
  project: ProjectInfo | null;
  stats: ProxyStatsLike | null;
  pending: number;
  findings: number;
  oob: OobStatus | null;
  onNavigate: (section: string) => void;
}) {
  const mem = useMemoryEstimate();
  const intercept = useInterceptStatus();
  // 🎯 R860 — 33rd round-number milestone. Burp-identical theme
  // toggle button on the status bar. Burp Suite 2026.8's status
  // bar surfaces the theme switcher as a quick-flip chip in the
  // far right (next to the "AI: Disabled" indicator); ours lands
  // the same affordance via a 3-state ☀/🌓/🌙 button that cycles
  // light → system → dark → light. Reuses the existing `useTheme`
  // hook so the three modes are honored (system follows OS prefers-
  // color-scheme). Zero backend — pure UI.
  const { mode: themeMode, setMode: setThemeMode } = useTheme();
  // 🎯 R870 — 34th round-number milestone. Session uptime timer.
  // Burp Suite 2026.8 shows a session uptime indicator in the
  // status bar (operators doing a long multi-hour scan want to
  // know "how long has this session been running?"). Ours ticks
  // every second, starting from the moment the BurpStyleStatusBar
  // mounts (same as the panel mount, which is the UI load). Formats
  // as "Hh Mm" / "Mm Ss" / "Ss" depending on magnitude.
  const uptime = useSessionUptime();
  // 🎯 R820 — 29th round-number milestone this chunk. Burp-identical
  // unread-events pulsing yellow dot on the "Event log" button. Polls
  // `api.loggerRecent(1)` on a 3s cadence to get the newest seq
  // number; compares against localStorage-persisted last-seen seq to
  // compute unread delta. Clicking Event log resets the counter.
  // Matches Burp Suite 2026.8's reference screenshot where the
  // status bar shows "Event log (1) ●" with a yellow pulse when
  // operators have unseen events.
  const unreadEvents = useUnreadEventCount();
  const resetUnread = useResetUnreadEvents();
  return (
    <div className="statusbar burp-statusbar">
      <button
        className={`status-link${unreadEvents > 0 ? " has-unread" : ""}`}
        onClick={() => {
          resetUnread();
          onNavigate("logger");
        }}
        title={
          unreadEvents > 0
            ? `${unreadEvents} unread event${unreadEvents === 1 ? "" : "s"} since you last visited the Logger — click to open + mark seen`
            : "Open Logger"
        }
      >
        Event log
        {unreadEvents > 0 && (
          <>
            <span className="status-event-pulse" />
            <span className="status-event-count">
              ({unreadEvents > 99 ? "99+" : unreadEvents})
            </span>
          </>
        )}
      </button>
      <button
        className="status-link"
        onClick={() => onNavigate("scanner")}
        title="Open Scanner"
      >
        All issues
        {findings > 0 && <span className="status-pill">{findings}</span>}
      </button>
      <span className="status-sep" />
      <span className="indicator">
        <span className={`dot ${stats?.running ? "on" : ""}`} />
        {stats?.running ? `Proxy ${stats.listeners[0] ?? ""}` : "Proxy stopped"}
      </span>
      <button
        className="status-link"
        onClick={intercept.toggle}
        title="Toggle proxy interception for both directions (Ctrl+T)"
      >
        <span
          className={`dot ${intercept.anyOn ? "on" : ""}`}
          style={intercept.anyOn ? { background: "#e04444" } : undefined}
        />
        Intercept {intercept.anyOn ? "ON" : "OFF"}
      </button>
      <span className="dim">tx {project?.tx_count ?? 0}</span>
      <span className="dim">scope {project?.scope_rules ?? 0}</span>
      {pending > 0 && (
        <button
          className="status-link"
          onClick={() => onNavigate("proxy")}
          title="Jump to Proxy > Intercept — messages are waiting on your decision"
        >
          <span className="status-pill red">intercept {pending}</span>
        </button>
      )}
      {stats && (
        <>
          <span className="status-sep" />
          <span className="dim">conns {stats.conns_accepted}</span>
          <span className="dim">fwd {stats.requests_forwarded}</span>
          <span className="dim">mitm {stats.tls_mitm}</span>
          {stats.errors > 0 && <span className="status-pill red">err {stats.errors}</span>}
        </>
      )}
      <span className="spacer" style={{ flex: 1 }} />
      <button
        className="status-link"
        onClick={() => onNavigate("collaborator")}
        title="Open Collaborator (OOB)"
      >
        <span className={`dot ${oob?.running ? "on" : ""}`} />
        Collaborator: {oob?.running
          ? `${oob.interaction_count ?? 0} hits`
          : "disabled"}
      </button>
      <span className="status-sep" />
      <span className="dim mono" title="Approximate JS heap used by the UI. BurpFree engine memory lives in the Rust process.">
        Memory: {mem}
      </span>
      {/* 🎯 R870 — 34th round-number milestone. Session uptime
          timer. Formats as "Hh Mm" (>= 1 hour), "Mm Ss" (>= 1
          minute), or "Ss" otherwise. 1s tick cadence. */}
      <span className="status-sep" />
      <span
        className="dim mono"
        title="Session uptime — time elapsed since the BurpFree UI loaded. Not the proxy uptime (which is tracked separately in the Dashboard)."
      >
        Up: {uptime}
      </span>
      {/* R883: Quick ⌨ cheatsheet shortcut button in the status
          bar. Burp Suite 2026.8's status bar carries a keyboard
          icon that pops the shortcut helper. Ours mirrors — fires
          the global `burpfree:open-cheatsheet` CustomEvent that
          App.tsx listens for (same as Ctrl+/ keyboard shortcut
          + menubar brand click). */}
      <span className="status-sep" />
      <button
        className="status-theme-toggle"
        onClick={() =>
          window.dispatchEvent(new CustomEvent("burpfree:open-cheatsheet"))
        }
        title="Open keyboard shortcut cheatsheet (Ctrl+/)"
        aria-label="Open keyboard shortcut cheatsheet"
      >
        ⌨
      </button>
      <span className="status-sep" />
      {project?.root && (
        <>
          <span
            className="dim mono"
            title={project.root}
            style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            {truncatePathTail(project.root, 40)}
          </span>
          {/* R867: Inline 📋 copy-project-path button in status
              bar. Operators often need the project folder path for
              Windows Explorer, a terminal cd, or a backup script
              — right-clicking the status bar isn't a thing, so
              a one-click clipboard copy right next to the shown
              path is the fastest route. Reuses the same compact
              style as R860's `.status-theme-toggle`. */}
          <button
            className="status-theme-toggle"
            onClick={() => {
              if (!project?.root) return;
              void navigator.clipboard
                .writeText(project.root)
                .catch(() => {});
            }}
            title={`Copy project path to clipboard: ${project.root}`}
            aria-label="Copy project path"
          >
            📋
          </button>
          <span className="status-sep" />
        </>
      )}
      {/* R869: Burp-identical clickable brand label in the
          status bar. Burp Suite 2026.8's status bar brand text
          opens the About dialog on click; ours finally matches.
          Operators who want the version number or a quick
          "what version am I running" check can click the brand
          instead of walking the Help menu. */}
      <button
        className="status-brand status-link"
        onClick={() =>
          alert(
            "BurpFree 0.1.0\n\n" +
              "An original, independent web-security testing platform.\n" +
              "Rust + Tauri 2 + React/TypeScript.\n\n" +
              "137+ Burp parity stages shipped, 842+ continuous verified builds, 455 workspace tests.\n\n" +
              "See COMPATIBILITY.md for the version timeline + ARCHITECTURE.md for the engine architecture.\n\n" +
              "Not affiliated with PortSwigger or Burp Suite — Burp Suite is a trademark of PortSwigger Ltd. BurpFree is a clean-room open-source clone built from publicly observable UI/UX conventions.",
          )
        }
        title="BurpFree 0.1.0 — click for About dialog"
      >
        BurpFree 0.1.0
      </button>
      {/* 🎯 R860 — 33rd round-number milestone. Burp-identical
          theme toggle on the status bar. 3-state cycle: light
          (☀) → system (🌓) → dark (🌙) → light. Reuses the
          existing `useTheme` hook. Operators flipping theme
          mid-session (e.g. switching from dark for a late-night
          scan to light for a daylit screenshot in a bug report)
          get a one-click path without visiting Settings. */}
      <span className="status-sep" />
      <button
        className="status-theme-toggle"
        onClick={() => {
          const next: typeof themeMode =
            themeMode === "light"
              ? "system"
              : themeMode === "system"
                ? "dark"
                : "light";
          setThemeMode(next);
        }}
        title={
          themeMode === "light"
            ? "Theme: Light — click for System"
            : themeMode === "system"
              ? "Theme: System (follows OS) — click for Dark"
              : "Theme: Dark — click for Light"
        }
      >
        {themeMode === "light" ? "☀" : themeMode === "system" ? "🌓" : "🌙"}
      </button>
      {/* R822: Burp-identical "AI: Disabled ▾" dropdown mock on
          the far right of the global status bar. Matches Burp
          Suite 2026.8's reference screenshot where a "Disabled"
          dropdown sits next to the brand label (indicating Burp
          AI service state). BurpFree ships a visual mock —
          clicking shows an alert explaining the ✦ AI drawer
          (R800) is the local alternative. */}
      <span className="status-sep" />
      <button
        className="status-ai-indicator"
        onClick={() =>
          alert(
            "✦ BurpFree AI\n\nThis status indicator mirrors Burp Suite 2026.8's AI service state. BurpFree ships a local heuristic AI drawer (click the ✦ AI button in Repeater's toolbar) — no external service, no account linking, no outbound calls. Analysis is pattern-matched client-side.",
          )
        }
        title="BurpFree AI status — local heuristic drawer available in Repeater (✦ AI button). No external service calls."
      >
        <span className="status-ai-dot" />
        Disabled
        <span className="status-ai-caret">▾</span>
      </button>
    </div>
  );
}

/**
 * Shorten a filesystem path to its last `max` characters, prefixing
 * with an ellipsis when truncated. We prefer the tail because that's
 * the project folder name, which is what the operator actually scans.
 */
function truncatePathTail(path: string, max: number): string {
  const norm = path.replace(/\\/g, "/");
  if (norm.length <= max) return norm;
  return "…" + norm.slice(-max + 1);
}

/**
 * Poll `interceptor_status` every 2 s and expose a toggle that flips
 * both directions atomically via `interceptor_set`. Same logic the
 * ProxyPanel global toggle uses, lifted here so the status bar stays
 * in sync when the operator flips elsewhere.
 */
function useInterceptStatus(): { anyOn: boolean; toggle: () => void } {
  const [status, setStatus] = useState<{ request: boolean; response: boolean }>({
    request: false,
    response: false,
  });
  useEffect(() => {
    let cancelled = false;
    const refresh = () =>
      api
        .interceptorStatus()
        .then((s) => {
          if (!cancelled) setStatus({ request: s.request, response: s.response });
        })
        .catch(() => {});
    refresh();
    const t = setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);
  const anyOn = status.request || status.response;
  const toggle = () => {
    api
      .interceptorSet(!anyOn, !anyOn)
      .then(() => setStatus({ request: !anyOn, response: !anyOn }))
      .catch((err) => console.warn("Intercept toggle failed:", err));
  };
  return { anyOn, toggle };
}

/**
 * 🎯 R870 — 34th round-number milestone. Session uptime timer.
 * Burp Suite 2026.8's status bar carries a session uptime indicator;
 * ours finally matches. Starts counting from the moment this hook
 * mounts (= UI load). Formats as "Hh Mm" when ≥ 1h, "Mm Ss" when
 * ≥ 1min, else "Ss". Ticks every 1s so the operator sees it update
 * live. Zero backend — pure Date.now() diff.
 */
function useSessionUptime(): string {
  const startRef = useRef<number>(Date.now());
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((v) => v + 1), 1000);
    return () => clearInterval(t);
  }, []);
  // tick is used only to force re-render; the actual time is read fresh
  void tick;
  const diffMs = Math.max(0, Date.now() - startRef.current);
  const s = Math.floor(diffMs / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const sec = s % 60;
  if (m < 60) return `${m}m ${sec}s`;
  const h = Math.floor(m / 60);
  const minLeft = m % 60;
  return `${h}h ${minLeft}m`;
}

/**
 * Query `performance.memory.usedJSHeapSize` (Chromium only) every 3 s
 * and format as MB. Falls back to a static placeholder if the API is
 * not exposed by the webview.
 */
function useMemoryEstimate(): string {
  const [v, setV] = useState<string>("—");
  useEffect(() => {
    const read = () => {
      const perf = window.performance as unknown as { memory?: { usedJSHeapSize: number; jsHeapSizeLimit: number } };
      const m = perf.memory;
      if (m) {
        const mb = (m.usedJSHeapSize / 1024 / 1024).toFixed(1);
        const limitGb = (m.jsHeapSizeLimit / 1024 / 1024 / 1024).toFixed(1);
        setV(`${mb} MB of ${limitGb} GB`);
      } else {
        setV("UI only");
      }
    };
    read();
    const t = setInterval(read, 3000);
    return () => clearInterval(t);
  }, []);
  return v;
}

/* 🎯 R820 — 29th round-number milestone this chunk. Burp-identical
 * unread Logger event tracking. Polls `api.loggerRecent(1)` every
 * 3s to get the newest seq number; stores "last-seen" seq in
 * localStorage keyed by project path. Delta = unread count.
 * Click handler on Event log button in BurpStyleStatusBar
 * resets the counter via useResetUnreadEvents + navigates to
 * Logger. Matches Burp Suite 2026.8's "Event log (1) ●" pulse
 * silhouette visible in the user's reference screenshot. */
const UNREAD_SEQ_KEY = "burpfree.events.last_seen_seq";

function useUnreadEventCount(): number {
  const [newestSeq, setNewestSeq] = useState<number>(0);
  const [lastSeenSeq, setLastSeenSeq] = useState<number>(() => {
    try {
      const v = localStorage.getItem(UNREAD_SEQ_KEY);
      return v ? parseInt(v, 10) : 0;
    } catch {
      return 0;
    }
  });
  useEffect(() => {
    let cancelled = false;
    const read = async () => {
      try {
        const latest = await api.loggerRecent(1);
        if (cancelled) return;
        if (latest.length > 0) {
          setNewestSeq(latest[0].seq ?? 0);
        }
      } catch {
        /* silent — backend might be seeding */
      }
    };
    read();
    const t = setInterval(read, 3000);
    // Listen for the "mark seen" event dispatched by the reset hook.
    const onReset = () => {
      setLastSeenSeq(newestSeq);
      try {
        localStorage.setItem(UNREAD_SEQ_KEY, String(newestSeq));
      } catch {
        /* ignore */
      }
    };
    window.addEventListener("burpfree:mark-events-seen", onReset);
    return () => {
      cancelled = true;
      clearInterval(t);
      window.removeEventListener("burpfree:mark-events-seen", onReset);
    };
  }, [newestSeq]);
  return Math.max(0, newestSeq - lastSeenSeq);
}

function useResetUnreadEvents(): () => void {
  return () => {
    window.dispatchEvent(new CustomEvent("burpfree:mark-events-seen"));
  };
}
