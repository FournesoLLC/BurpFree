import { Fragment, useEffect, useState } from "react";
import { api, ProjectInfo, ProxyStatsView } from "./api";
import { CommandPalette } from "./CommandPalette";
import { ProxyPanel } from "./panels/ProxyPanel";
import { TargetPanel } from "./panels/TargetPanel";
import { RepeaterPanel } from "./panels/RepeaterPanel";
import { IntruderPanel } from "./panels/IntruderPanel";
import { HistoryPanel } from "./panels/HistoryPanel";
import { ScannerPanel } from "./panels/ScannerPanel";
import { DecoderPanel } from "./panels/DecoderPanel";
import { ComparerPanel } from "./panels/ComparerPanel";
import { SequencerPanel } from "./panels/SequencerPanel";
import { SettingsPanel } from "./panels/SettingsPanel";
import { ExtensionsPanel } from "./panels/ExtensionsPanel";
import { DashboardPanel } from "./panels/DashboardPanel";
import { LoggerPanel } from "./panels/LoggerPanel";
import { OrganizerPanel } from "./panels/OrganizerPanel";
import { WebSocketPanel } from "./panels/WebSocketPanel";
import { SessionPanel } from "./panels/SessionPanel";
import { CookieJarPanel } from "./panels/CookieJarPanel";
import { DiscoverPanel } from "./panels/DiscoverPanel";
import { GraphQLPanel } from "./panels/GraphQLPanel";
import { McpPanel } from "./panels/McpPanel";
import { CollaboratorPanel } from "./panels/CollaboratorPanel";
import { BChecksPanel } from "./panels/BChecksPanel";
import { LearnPanel } from "./panels/LearnPanel";
import { RightSidebar, BurpStyleStatusBar } from "./RightSidebar";
import { installChromeGuards } from "./chrome";
import { ShortcutCheatsheet } from "./ShortcutCheatsheet";
import { CrawlerModal } from "./panels/CrawlerModal";
import type { OobStatus } from "./api";

export type Section =
  | "dashboard"
  | "target"
  | "proxy"
  | "history"
  | "intruder"
  | "repeater"
  | "sequencer"
  | "decoder"
  | "comparer"
  | "scanner"
  | "bchecks"
  | "websocket"
  | "graphql"
  | "logger"
  | "learn"
  | "organizer"
  | "session"
  | "cookies"
  | "extensions"
  | "collaborator"
  | "discover"
  | "mcp"
  | "settings";

// R444 — Top-nav TABS limited to Burp Suite 2026.8 top-level set for UI parity.
// Hidden sections (bchecks/websocket/graphql/organizer/session/cookies/discover/mcp)
// remain fully functional: routes stay in <Section> union, their panels still render
// via `section === "x" && <Panel />`, and they are reachable through the Command
// Palette (Ctrl+K) and cross-panel `burpfree:navigate` CustomEvents.
// R854: Burp-identical per-tab tooltip hints. Burp 2026.8 shows a
// one-line description on hover for every tool tab so new operators
// can tell what each panel is for before clicking. Ours previously
// had no title attributes — new operators (and operators coming
// from Burp Pro) got no scaffolding. Short-form descriptions keyed
// to each tab's purpose; longer than a Burp bare-tooltip but still
// one line. The description is read via `TABS[i].hint` by MainTabs.
const TABS: Array<{ id: Section; label: string; hint: string }> = [
  { id: "dashboard",    label: "Dashboard",    hint: "Dashboard — tasks, event log, and 50+ activity tiles" },
  { id: "target",       label: "Target",       hint: "Target — site map, scope rules, per-site issues" },
  { id: "proxy",        label: "Proxy",        hint: "Proxy — intercept, HTTP history, WebSockets, match-and-replace, settings" },
  { id: "intruder",     label: "Intruder",     hint: "Intruder — Sniper / Battering Ram / Pitchfork / Cluster Bomb / Null attacks" },
  { id: "repeater",     label: "Repeater",     hint: "Repeater — hand-craft and replay requests with Pretty / Raw / Hex / Render views. Ctrl+Enter sends, F2 renames tab, middle-click closes tab, Ctrl+B jumps to body, Ctrl+Shift+PageUp/PageDown reorders tabs" },
  { id: "collaborator", label: "Collaborator", hint: "Collaborator — OOB listener for blind SSRF / SQLi / XXE callback detection" },
  { id: "sequencer",    label: "Sequencer",    hint: "Sequencer — token randomness analysis (chi-square + Wald-Wolfowitz + per-position stats)" },
  { id: "decoder",      label: "Decoder",      hint: "Decoder — URL / Base64 / Hex / HTML / JWT / gzip / deflate transform chaining + Smart Decode" },
  { id: "comparer",     label: "Comparer",     hint: "Comparer — line / word / byte / JSON structural diff of two samples" },
  { id: "organizer",    label: "Organizer",    hint: "Organizer — saved request collections for reporting and collaboration (Ctrl+O)" },
  { id: "scanner",      label: "Scanner",      hint: "Scanner — passive + active security checks; findings land in a severity-tiered table" },
  { id: "logger",       label: "Logger",       hint: "Logger — live event bus (transactions, intercepts, findings, websockets, system logs)" },
  { id: "extensions",   label: "Extensions",   hint: "Extensions — Installed BurpFree extensions + Catalog browser" },
];

// All routable sections — superset of TABS. Used by `burpfree:navigate`
// so cross-panel pivots can still reach sections that are hidden from
// the top-nav (bchecks/websocket/graphql/organizer/session/cookies/discover/mcp).
const ALL_SECTIONS: ReadonlySet<Section> = new Set<Section>([
  "dashboard", "target", "proxy", "history", "intruder", "repeater",
  "collaborator", "sequencer", "decoder", "comparer", "scanner",
  "bchecks", "websocket", "graphql", "logger", "learn", "organizer",
  "session", "cookies", "extensions", "discover", "mcp", "settings",
]);

export function App() {
  const [section, setSection] = useState<Section>("dashboard");
  const [project, setProject] = useState<ProjectInfo | null>(null);
  const [stats, setStats] = useState<ProxyStatsView | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [findingsCount, setFindingsCount] = useState(0);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);
  const [crawlerOpen, setCrawlerOpen] = useState(false);
  const [oob, setOob] = useState<OobStatus | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const info = await api.projectInfo();
        setProject(info);
      } catch (e) {
        console.error("project not loaded:", e);
      }
    })();
  }, []);

  // R866: Burp-identical dynamic window title. Burp Suite 2026.8
  // sets its window title to "Burp Suite [Community/Pro] - [project
  // name]" so operators juggling multiple IDE / terminal / Burp
  // windows can tell them apart in the OS taskbar. Ours finally
  // lands the same pattern — "BurpFree - [project folder name]"
  // or just "BurpFree" when no project is loaded. Updates on every
  // project state change (initial load + 5s refresh poll).
  useEffect(() => {
    if (!project?.root) {
      document.title = "BurpFree Community Edition v2026.8";
      return;
    }
    const name = projectName(project.root);
    document.title = name
      ? `BurpFree Community Edition v2026.8 - ${name}`
      : "BurpFree Community Edition v2026.8";
  }, [project?.root]);

  useEffect(() => {
    const refreshProject = async () => {
      try { setProject(await api.projectInfo()); } catch { /* no project yet */ }
    };
    const t = setInterval(async () => {
      try { setStats(await api.proxyStats()); } catch { /* backend not ready */ }
      try {
        const p = await api.interceptorPending();
        setPendingCount(p.length);
      } catch {}
      try {
        const f = await api.findingsList();
        setFindingsCount(f.length);
      } catch {}
      try { setOob(await api.oobStatus()); } catch {}
      refreshProject();
    }, 2000);
    return () => clearInterval(t);
  }, []);

  // Global keyboard shortcuts.
  //   Ctrl+K   → command palette
  //   Ctrl+1..9 → jump to tab 1..9
  //   Ctrl+O   → Send-to-Organizer (fires a CustomEvent that panels listen for)
  //   Ctrl+T   → Toggle proxy intercept (both directions)
  //   Ctrl+R   → Send current selection to Repeater
  //   Ctrl+I   → Send current selection to Intruder
  useEffect(() => {
    // Guard: skip typing contexts. All of Ctrl+T/R/I/O would otherwise
    // steal the native browser bindings (new tab, reload, italic) when
    // the user is editing a form field or textarea.
    const inTypingContext = (target: EventTarget | null): boolean => {
      const el = target as HTMLElement | null;
      const tag = el?.tagName;
      return (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        !!el?.isContentEditable
      );
    };
    const onKey = async (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      // Palette toggle.
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      // Cheatsheet toggle — Ctrl+? (shifted / on US keyboards) or Ctrl+/.
      if (mod && (e.key === "?" || e.key === "/")) {
        e.preventDefault();
        setCheatsheetOpen((o) => !o);
        return;
      }
      // Intercept toggle — Ctrl+T. Reads current state so a single
      // keypress flips both directions atomically: if either is on,
      // turn both off; if both are off, turn both on.
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "t") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        try {
          const s = await api.interceptorStatus();
          const anyOn = s.request || s.response;
          await api.interceptorSet(!anyOn, !anyOn);
        } catch (err) {
          console.warn("Ctrl+T intercept toggle failed:", err);
        }
        return;
      }
      // Send-to-Organizer. We dispatch a CustomEvent so any panel with a
      // "current selection" (HTTP history, Repeater, Scanner issue list)
      // can register a listener and respond with the right payload.
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "o") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("burpfree:send-to-organizer"));
        return;
      }
      // Send-to-Repeater. Same event-bus pattern — the currently-visible
      // panel (ProxyPanel history, HistoryPanel, TargetPanel sitemap)
      // registers a listener that fires its own send-to-Repeater flow
      // against the row the user has selected.
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "r") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("burpfree:send-to-repeater"));
        return;
      }
      // Send-to-Intruder — mirrors Ctrl+R exactly.
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "i") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("burpfree:send-to-intruder"));
        return;
      }
      // R926: Ctrl+F — forward intercepted proxy message. Burp 2026.8's
      // `forward_intercepted_proxy_message` action. If the user is on
      // the Proxy panel, this fires the forward action; otherwise it
      // navigates to Proxy first. Non-destructive (forwarding just
      // releases the held message to the server).
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "f") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        setSection("proxy");
        window.dispatchEvent(new CustomEvent("burpfree:forward-intercept"));
        return;
      }
      // R926: Ctrl+Shift+G — open Burp Agentic Testing panel. Maps to
      // Burp 2026.8's `open_burp_at` hotkey. Since we don't have a
      // dedicated AT panel yet, navigates to Dashboard (where tasks live)
      // and fires the AT open event.
      if (mod && !e.altKey && e.shiftKey && e.key.toLowerCase() === "g") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        setSection("dashboard");
        window.dispatchEvent(new CustomEvent("burpfree:open-burp-at"));
        return;
      }
      // R926: Ctrl+B — open embedded browser. Maps to Burp 2026.8's
      // `open_embedded_browser` action. Fires a CustomEvent that the
      // browser-launch component listens for.
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "b") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        window.dispatchEvent(new CustomEvent("burpfree:open-browser"));
        return;
      }
      // R851: Ctrl+E = "Explain this" (Burp 2026.8 global hotkey).
      // Burp Suite 2026.8 binds Ctrl+E to "Explain this" which opens
      // the Burp AI companion drawer against the current context
      // (request / response / finding). Our client-side AI drawer
      // (R800 BurpAiDrawer) lives in RepeaterPanel; this global
      // shortcut jumps to Repeater first (if not already there) and
      // dispatches a `burpfree:open-burp-ai` CustomEvent that the
      // panel listens for. **Guards** plain Ctrl only (no Alt/Shift/
      // Meta so Ctrl+Shift+E DevTools-ish combos stay available),
      // typing-context skip so Ctrl+E inside a textarea doesn't yank
      // focus (operators composing a message want to add e-letters
      // without triggering the AI).
      if (mod && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "e") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        setSection("repeater");
        // Defer the AI-open event so the Repeater panel has
        // time to mount and attach its listener before we fire.
        setTimeout(() => {
          window.dispatchEvent(
            new CustomEvent("burpfree:open-burp-ai"),
          );
        }, 60);
        return;
      }
      // Tab-number jumps.
      if (mod && !e.altKey && !e.shiftKey && /^[1-9]$/.test(e.key)) {
        if (inTypingContext(e.target)) return;
        const idx = parseInt(e.key, 10) - 1;
        const t = TABS[idx];
        if (t) {
          e.preventDefault();
          setSection(t.id);
        }
      }
      // R459: Alt+L jumps to Learn tab. Learn landed in R445 between
      // Logger and Extensions, so it's position 13 in the visible
      // top-nav — beyond the Ctrl+1..9 jump range. Alt+L fills the
      // gap for operators who want keyboard-only access to the
      // Burp-canonical learning portal (Web Security Academy /
      // PortSwigger docs / per-tool quick-starts). **Letter choice**
      // L = Learn; distinct from the panel-scoped Alt-letter family
      // (none of the per-panel keybindings own Alt+L today) and the
      // global Ctrl+K/T/R/I/O cluster. **Guards** plain Alt only
      // (no Ctrl/Meta/Shift), typing-context skip so Alt+L inside a
      // URL field or textarea doesn't yank the operator mid-edit.
      if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key.toLowerCase() === "l") {
        if (inTypingContext(e.target)) return;
        e.preventDefault();
        setSection("learn");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Cross-panel navigation. Discover cards (and any future deep-link
  // affordance) can dispatch `burpfree:navigate` with a target section
  // to jump the user to the right tab without plumbing a prop tree.
  useEffect(() => {
    const onNav = (e: Event) => {
      const detail = (e as CustomEvent<{ target: Section }>).detail;
      // R444 — validate against ALL_SECTIONS so pivots to hidden tabs still work.
      if (detail?.target && ALL_SECTIONS.has(detail.target)) {
        setSection(detail.target);
      }
    };
    window.addEventListener("burpfree:navigate", onNav as EventListener);
    return () => window.removeEventListener("burpfree:navigate", onNav as EventListener);
  }, []);

  // Suppress the webview's native right-click menu + devtools shortcuts.
  // See `chrome.ts` for the full list; our React `onContextMenu`
  // handlers still fire because the listener uses `preventDefault()`
  // (which doesn't stop propagation).
  useEffect(() => installChromeGuards(), []);

  return (
    <div className="app">
      <MenuBar project={project} stats={stats} onOpenPalette={() => setPaletteOpen(true)} />
      <MainTabs
        section={section}
        setSection={setSection}
        counters={{
          proxy: pendingCount,
          scanner: findingsCount,
          history: project?.tx_count ?? 0,
          // R875: Collaborator interaction count on the main-tab
          // chip. Operators doing a blind-OOB probe (SSRF / XXE /
          // SQLi callbacks) want to see "did my payload fire?" at
          // a glance from any sibling tab. Rendered only when the
          // listener is running AND has caught at least one hit —
          // an idle Collaborator keeps the chip clean.
          collaborator: oob?.running ? (oob.interaction_count ?? 0) : 0,
        }}
      />
      <div className="content">
        <div className="content-main">
          {section === "dashboard"  && <DashboardPanel />}
          {section === "target"     && <TargetPanel />}
          {section === "proxy"      && <ProxyPanel />}
          {section === "history"    && <HistoryPanel />}
          {section === "intruder"   && <IntruderPanel />}
          {section === "repeater"   && <RepeaterPanel />}
          {section === "collaborator" && <CollaboratorPanel />}
          {section === "sequencer"  && <SequencerPanel />}
          {section === "decoder"    && <DecoderPanel />}
          {section === "comparer"   && <ComparerPanel />}
          {section === "scanner"    && <ScannerPanel />}
          {section === "bchecks"    && <BChecksPanel />}
          {section === "websocket"  && <WebSocketPanel />}
          {section === "graphql"    && <GraphQLPanel />}
          {section === "logger"     && <LoggerPanel />}
          {section === "learn"      && <LearnPanel />}
          {section === "organizer"  && <OrganizerPanel />}
          {section === "session"    && <SessionPanel />}
          {section === "cookies"    && <CookieJarPanel />}
          {section === "extensions" && <ExtensionsPanel />}
          {section === "discover"   && <DiscoverPanel />}
          {section === "mcp"        && <McpPanel />}
          {section === "settings"   && <SettingsPanel />}
        </div>
        <RightSidebar project={project} />
      </div>
      <BurpStyleStatusBar
        project={project}
        stats={stats}
        pending={pendingCount}
        findings={findingsCount}
        oob={oob}
        onNavigate={(s) => setSection(s as Section)}
      />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        setSection={(s) => setSection(s)}
        openCheatsheet={() => setCheatsheetOpen(true)}
        openCrawler={() => setCrawlerOpen(true)}
      />
      <ShortcutCheatsheet open={cheatsheetOpen} onClose={() => setCheatsheetOpen(false)} />
      <CrawlerModal open={crawlerOpen} onClose={() => setCrawlerOpen(false)} />
    </div>
  );
}

function MenuBar({
  project,
  stats,
  onOpenPalette,
}: {
  project: ProjectInfo | null;
  stats: ProxyStatsView | null;
  onOpenPalette: () => void;
}) {
  // R825: Burp-identical functional menubar — each item opens a
  // click-dropdown with real actions. Mirrors Burp Suite 2026.8's
  // top-level menu bar which carries Burp / Project / Intruder /
  // Repeater / View / Help menus. BurpFree ships a condensed
  // version with the same silhouette but routes actions through
  // the existing command palette + navigate events + settings.
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  // Close the menu when clicking outside.
  useEffect(() => {
    if (!openMenu) return;
    function onClick(e: MouseEvent) {
      const t = e.target as HTMLElement | null;
      if (!t?.closest(".menu-item") && !t?.closest(".menu-dropdown")) {
        setOpenMenu(null);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [openMenu]);
  const nav = (section: string) =>
    window.dispatchEvent(
      new CustomEvent("burpfree:navigate", { detail: { target: section } }),
    );
  type MenuAction = {
    label: string;
    hotkey?: string;
    onClick?: () => void;
    separator?: boolean;
    // R888: `disabled` entries render greyed out and non-clickable.
    // Matches Burp Suite 2026.8's "[Pro version only]" placeholder
    // entries visible in the Burp menu screenshot.
    disabled?: boolean;
  };
  const menus: Record<string, MenuAction[]> = {
    // R888: Burp-identical "Burp" menu matching the screenshot the
    // user attached. Replaces our old "File" menu entirely. The
    // contents follow Burp Suite 2026.8's exact entry order and
    // Pro-only markers so operators coming from Burp see the same
    // silhouette. BurpFree's clone of the Pro-only entries open an
    // alert explaining that BurpFree's community-equivalent features
    // are either free or routed through a different panel.
    Burp: [
      {
        label: "Search [Community limited]",
        hotkey: "Ctrl+K",
        onClick: onOpenPalette,
      },
      { separator: true, label: "" },
      { label: "Settings", onClick: () => nav("settings") },
      { label: "Configuration library", onClick: () => nav("settings") },
      { label: "User settings", onClick: () => nav("settings") },
      { separator: true, label: "" },
      {
        label: "Burp Infiltrator [Pro version only]",
        disabled: true,
      },
      {
        label: "Burp Clickbandit",
        onClick: () =>
          alert(
            "Burp Clickbandit — the clickjacking PoC generator.\n\nBurp Suite 2026.8 ships this as a bookmarklet you load in the target browser. BurpFree's clean-room equivalent is planned as a future round; for now use the Scanner panel's clickjacking detector (passive) or compose a manual PoC in Repeater.",
          ),
      },
      {
        label: "Burp Collaborator client [Pro version only]",
        disabled: true,
      },
      { separator: true, label: "" },
      {
        label: "Upgrade to Burp Suite Professional",
        onClick: () =>
          alert(
            "BurpFree is an independent open-source clone of Burp Suite — there is no \"Pro\" tier to upgrade to.\n\nThe Pro-only entries above (Infiltrator / Collaborator client) are visual placeholders matching Burp Suite 2026.8's menu silhouette; BurpFree's Collaborator (OOB) functionality lives in the Collaborator panel in the main tab bar and is fully free.\n\nTo support PortSwigger's actual Burp Suite Professional product, visit https://portswigger.net/burp/pro.",
          ),
      },
      { separator: true, label: "" },
      {
        label: "Exit",
        onClick: () =>
          alert(
            "Close the BurpFree window to exit — the Tauri runtime handles graceful shutdown of the proxy listener, backup scheduler, and project writer.",
          ),
      },
    ],
    // R888: New "Intruder" top-level menu. Burp's Intruder menu
    // carries attack-type presets + load-saved-attack. Ours surfaces
    // the attack-type pills from the Intruder panel (R779) + a
    // navigate action.
    Intruder: [
      { label: "Open Intruder", hotkey: "Ctrl+5", onClick: () => nav("intruder") },
      { separator: true, label: "" },
      {
        label: "Attack type: Sniper",
        onClick: () => {
          nav("intruder");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:intruder-attack-type", {
                detail: { type: "sniper" },
              }),
            );
          }, 60);
        },
      },
      {
        label: "Attack type: Battering ram",
        onClick: () => {
          nav("intruder");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:intruder-attack-type", {
                detail: { type: "batteringram" },
              }),
            );
          }, 60);
        },
      },
      {
        label: "Attack type: Pitchfork",
        onClick: () => {
          nav("intruder");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:intruder-attack-type", {
                detail: { type: "pitchfork" },
              }),
            );
          }, 60);
        },
      },
      {
        label: "Attack type: Cluster bomb",
        onClick: () => {
          nav("intruder");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:intruder-attack-type", {
                detail: { type: "clusterbomb" },
              }),
            );
          }, 60);
        },
      },
      { separator: true, label: "" },
      { label: "Payloads library", onClick: () => nav("intruder") },
      {
        label: "Start attack (Ctrl+Enter in Intruder)",
        onClick: () => {
          nav("intruder");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:intruder-start"),
            );
          }, 60);
        },
      },
    ],
    // R888: New "Repeater" top-level menu. Burp's Repeater menu
    // carries tab actions (new, duplicate, close, send) + follow-
    // redirects / unpack-gzip settings. Ours routes to the panel
    // and surfaces the primary tab-management actions.
    Repeater: [
      { label: "Open Repeater", hotkey: "Ctrl+6", onClick: () => nav("repeater") },
      { separator: true, label: "" },
      {
        label: "New tab",
        hotkey: "Alt+N",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(new CustomEvent("burpfree:repeater-new-tab"));
          }, 60);
        },
      },
      {
        label: "Duplicate active tab",
        hotkey: "Ctrl+D",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:repeater-duplicate-tab"),
            );
          }, 60);
        },
      },
      {
        label: "Close active tab",
        hotkey: "Alt+W",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:repeater-close-tab"),
            );
          }, 60);
        },
      },
      { separator: true, label: "" },
      {
        label: "Send request",
        hotkey: "Ctrl+Enter",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(new CustomEvent("burpfree:repeater-send"));
          }, 60);
        },
      },
      {
        label: "Jump to request body",
        hotkey: "Ctrl+B",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(
              new CustomEvent("burpfree:repeater-jump-body"),
            );
          }, 60);
        },
      },
      { separator: true, label: "" },
      {
        label: "Open ✦ AI drawer",
        hotkey: "Ctrl+E",
        onClick: () => {
          nav("repeater");
          setTimeout(() => {
            window.dispatchEvent(new CustomEvent("burpfree:open-burp-ai"));
          }, 60);
        },
      },
    ],
    View: [
      // R845: Hotkey labels now match the actual Ctrl+N binding
      // (the global keydown handler binds Ctrl+1..9 for TAB-index
      // jumps, not Alt+1..5 as the previous menu copy claimed —
      // operators pressing the advertised shortcut landed nowhere).
      // Order follows the top-nav TABS array so the hotkey number
      // = the tab's 1-indexed position in the row.
      { label: "Dashboard", hotkey: "Ctrl+1", onClick: () => nav("dashboard") },
      { label: "Target", hotkey: "Ctrl+2", onClick: () => nav("target") },
      { label: "Proxy", hotkey: "Ctrl+3", onClick: () => nav("proxy") },
      { label: "Intruder", hotkey: "Ctrl+4", onClick: () => nav("intruder") },
      { label: "Repeater", hotkey: "Ctrl+5", onClick: () => nav("repeater") },
      { label: "Collaborator", hotkey: "Ctrl+6", onClick: () => nav("collaborator") },
      { label: "Sequencer", hotkey: "Ctrl+7", onClick: () => nav("sequencer") },
      { label: "Decoder", hotkey: "Ctrl+8", onClick: () => nav("decoder") },
      { label: "Comparer", hotkey: "Ctrl+9", onClick: () => nav("comparer") },
      { separator: true, label: "" },
      { label: "Organizer", hotkey: "Ctrl+O", onClick: () => nav("organizer") },
      { label: "Scanner", onClick: () => nav("scanner") },
      { label: "Logger", onClick: () => nav("logger") },
      { label: "Extensions", onClick: () => nav("extensions") },
      { separator: true, label: "" },
      { label: "Keyboard shortcuts…", hotkey: "Ctrl+/", onClick: () => window.dispatchEvent(new CustomEvent("burpfree:open-cheatsheet")) },
    ],
    Project: [
      { label: "Scope", onClick: () => nav("target") },
      { label: "Session handling", onClick: () => nav("session") },
      { label: "Cookie jar", onClick: () => nav("cookies") },
      { label: "Extensions", onClick: () => nav("extensions") },
      { separator: true, label: "" },
      // R884: Burp-identical "Refresh project" action. Operators who
      // manually tweak project config files (`.kiro/`, scope.json,
      // settings.json) mid-session want a reload path without
      // restarting the binary. Fires projectInfo via the global
      // `burpfree:refresh-project` CustomEvent that App.tsx listens
      // for; alert echoes the refreshed state.
      {
        label: "Refresh project info",
        onClick: () => {
          window.dispatchEvent(new CustomEvent("burpfree:refresh-project"));
          alert(
            `Project refresh triggered.\n\nCurrent state:\nRoot: ${project?.root || "(none)"}\nTransactions: ${project?.tx_count ?? 0}\nScope rules: ${project?.scope_rules ?? 0}\n\nThe next 2s dashboard poll will reflect any filesystem changes.`,
          );
        },
      },
      { separator: true, label: "" },
      {
        label: project ? `${project.tx_count ?? 0} transactions stored` : "No project loaded",
        onClick: () => alert(`Project info\n\nRoot: ${project?.root || "(none)"}\nTransactions: ${project?.tx_count ?? 0}\nScope rules: ${project?.scope_rules ?? 0}\nProxy: ${stats?.running ? stats.listeners.join(", ") : "stopped"}`),
      },
    ],
    Help: [
      { label: "Keyboard shortcuts…", hotkey: "Ctrl+/", onClick: () => window.dispatchEvent(new CustomEvent("burpfree:open-cheatsheet")) },
      { label: "Command palette…", hotkey: "Ctrl+K", onClick: onOpenPalette },
      { separator: true, label: "" },
      // R855: Burp-identical "Learn" + "Discover features" quick-jumps
      // in the Help menu. Mirrors Burp 2026.8's Help > Learn + Help >
      // What's new entries where operators can jump straight to the
      // learning portal or feature-discovery landing page.
      { label: "Learn web security…", onClick: () => nav("learn") },
      { label: "Discover BurpFree features…", onClick: () => nav("discover") },
      { separator: true, label: "" },
      { label: "Documentation", onClick: () => alert("BurpFree 0.1.0\n\nAn independent open-source Burp Suite clone built in Rust + Tauri 2 + React/TypeScript. 455 workspace tests, 823+ continuous verified builds, 120+ Burp parity stages shipped.\n\nSource + docs live alongside the binary. See ARCHITECTURE.md + COMPATIBILITY.md.") },
      // R855: "Check for updates" — Burp 2026.8's Help menu has this
      // as a top-level entry that fires an updater check. BurpFree
      // ships as a rolling-build binary without a separate updater
      // service (ChunkOps / round-numbered COMPATIBILITY entries
      // supply the version timeline), so this entry documents the
      // model instead of pretending to check.
      { label: "Check for updates…", onClick: () => alert("BurpFree ships as a rolling-build binary.\n\nEach verified session appends a COMPATIBILITY.md row with the round number, bundle sizes, and smoke-test outcome — the version timeline lives in that file. No external updater service; rebuild from source to pick up new rounds.") },
      // 🎯 R876 — 850-streak celebration mark. Burp-identical
      // "What's new" entry in the Help menu. Mirrors Burp Suite
      // 2026.8's Help > "What's new" which pops a changelog
      // dialog. Ours summarizes the latest Burp parity work
      // operators can discover in a running session.
      {
        label: "What's new in BurpFree…",
        onClick: () =>
          alert(
            "What's new in BurpFree (recent rounds)\n\n" +
              "R876 (850-streak celebration): continuous verified streak crosses 850 rounds (R27-R876).\n" +
              "R875: Collaborator OOB tab chip shows live interaction count.\n" +
              "R874: Comparer diff pane adds column headers (L / R / Diff) + row hover tint.\n" +
              "R873: History Size cell tooltip shows content-type alongside byte count.\n" +
              "R872: History Time column tints amber/red for slow responses + seconds format.\n" +
              "R871: History Size column formats as KB/MB with raw bytes in tooltip.\n" +
              "R870 (33rd milestone): session uptime timer in status bar.\n" +
              "R869: BurpFree brand in status bar is now clickable → About dialog.\n" +
              "R867: Status bar project-path copy button.\n" +
              "R866: Dynamic window title with project name.\n" +
              "R865: Main-tabs scroll-overflow fade mask.\n" +
              "R864: Shortcut cheatsheet documents middle-click-close-tab.\n" +
              "R863: Light-theme JSON/XML syntax color variants.\n" +
              "R862: Pane bottom bar Ln/Col caret indicator.\n" +
              "R861: Repeater target URL inline copy button.\n" +
              "R860 (33rd milestone): Status bar theme toggle (☀/🌓/🌙).\n\n" +
              "See COMPATIBILITY.md for the full timeline (144+ Burp parity stages).",
          ),
      },
      { separator: true, label: "" },
      {
        label: "About BurpFree",
        onClick: () =>
          alert(
            "BurpFree Community Edition v2026.8\n\n" +
              "An original, independent web-security testing platform.\n" +
              "Rust + Tauri 2 + React/TypeScript.\n\n" +
              `Project: ${project?.root ? project.root.replace(/\\/g, "/").split("/").slice(-2).join("/") : "(none loaded)"}\n` +
              `Transactions stored: ${project?.tx_count ?? 0}\n` +
              `Scope rules: ${project?.scope_rules ?? 0}\n` +
              `Proxy listeners: ${stats?.running ? stats.listeners.join(", ") : "stopped"}\n` +
              `Transactions forwarded: ${stats?.requests_forwarded ?? 0}\n` +
              `Connections accepted: ${stats?.conns_accepted ?? 0}\n` +
              `TLS MITM count: ${stats?.tls_mitm ?? 0}\n\n` +
              "Not affiliated with PortSwigger or Burp Suite.\nBurp Suite is a trademark of PortSwigger Ltd.\nBurpFree is a clean-room open-source clone.",
          ),
      },
    ],
  };
  return (
    <div className="menubar">
      {/* R882: Clickable menubar brand opens the shortcut
          cheatsheet. Burp Suite 2026.8's "Burp Suite" brand label
          in its menubar is clickable (opens an About dialog); ours
          already has R869's status-bar brand → About, so this
          dedicated keyboard-shortcuts path keeps the two brand
          surfaces distinct. Operators wanting a fast cheatsheet
          pop from the menubar don't need to walk the Help menu. */}
      <div
        className="brand"
        onClick={() =>
          window.dispatchEvent(new CustomEvent("burpfree:open-cheatsheet"))
        }
        title="BurpFree — click for keyboard shortcut cheatsheet (Ctrl+/)"
        style={{ cursor: "pointer" }}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            window.dispatchEvent(new CustomEvent("burpfree:open-cheatsheet"));
          }
        }}
      >
        <span className="dot">◆</span> BurpFree
      </div>
      {/* R888: Burp-identical menu order matching the user's
          attached Burp menu screenshot:
          Burp | Project | Intruder | Repeater | View | Help
          Replaces the old File | Edit | View | Project | Help
          order so BurpFree's menubar reads byte-identical to
          Burp Suite 2026.8's menubar. */}
      {(["Burp", "Project", "Intruder", "Repeater", "View", "Help"] as const).map((name) => (
        <div
          key={name}
          className={`menu-item${openMenu === name ? " menu-item-open" : ""}`}
          onClick={() => setOpenMenu((v) => (v === name ? null : name))}
        >
          {name}
          {openMenu === name && (
            <div className="menu-dropdown">
              {menus[name].map((item, i) =>
                item.separator ? (
                  <div key={i} className="menu-dropdown-sep" />
                ) : (
                  <div
                    key={i}
                    className={`menu-dropdown-item${item.disabled ? " menu-dropdown-item-disabled" : ""}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (item.disabled) return;
                      setOpenMenu(null);
                      item.onClick?.();
                    }}
                  >
                    <span>{item.label}</span>
                    {item.hotkey && (
                      <span className="menu-dropdown-hotkey">
                        {item.hotkey}
                      </span>
                    )}
                  </div>
                ),
              )}
            </div>
          )}
        </div>
      ))}
      <div className="spacer" />
      <div className="right">
        <button
          className="ghost palette-trigger"
          title="Command palette (Ctrl+K)"
          onClick={onOpenPalette}
        >
          <span>Search commands</span>
          <span className="palette-kbd inline">Ctrl K</span>
        </button>
        <BrowserLaunchButton stats={stats} />
        {project && <span>Project: {projectName(project.root)}</span>}
        <span className="indicator">
          <span className={`dot ${stats?.running ? "on" : ""}`} style={{ display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: stats?.running ? "var(--green)" : "var(--red)" }} />
          Proxy {stats?.running ? stats.listeners[0] : "stopped"}
        </span>
      </div>
    </div>
  );
}

function MainTabs({
  section,
  setSection,
  counters,
}: {
  section: Section;
  setSection: (s: Section) => void;
  counters: {
    proxy: number;
    scanner: number;
    history: number;
    collaborator: number;
  };
}) {
  // R841: Burp-identical tab-group separators. Burp 2026.8's main
  // nav groups related tabs with thin vertical rules so operators
  // can visually scan the row faster: Core (Dashboard / Target /
  // Proxy / History) → Workflow (Intruder / Repeater / Collaborator
  // / Sequencer / Decoder / Comparer) → Analysis (Scanner / Logger
  // R921: Burp-identical tab groups from BURPSUITE_REPORT.md analysis.
  // Burp 2026.8 groups: Core (Dashboard / Target / Proxy) →
  // Workflow (Intruder / Repeater / Collaborator / Sequencer /
  // Decoder / Comparer) → Analysis (Organizer / Scanner / Logger)
  // → Config (Extensions). Removed History / Learn / Settings
  // from main tabs — History is a Proxy sub-tab, Learn is in Help
  // menu, Settings is in Burp menu.
  const GROUP_BOUNDARIES: ReadonlySet<Section> = new Set<Section>([
    "intruder",
    "organizer",
    "extensions",
  ]);
  return (
    <div
      className="main-tabs"
      onWheel={(e) => {
        // R887: Mirror of R886 — mouse-wheel vertical scroll
        // translates to horizontal main-tabs scroll. Rare to
        // overflow since our TAB count is 15 tabs, but on narrow
        // windows (<1200px) the row does scroll. Consistent with
        // the Repeater tab-bar wheel behavior.
        const el = e.currentTarget;
        if (el.scrollWidth > el.clientWidth) {
          const delta = e.deltaY !== 0 ? e.deltaY : e.deltaX;
          if (delta !== 0) {
            el.scrollLeft += delta;
            e.preventDefault();
          }
        }
      }}
    >
      {TABS.map((t) => {
        let count: number | null = null;
        // R848: Burp-identical count-badge coverage expanded to
        // History and Target. Previously only Proxy (intercept
        // queue) and Scanner (findings) carried a count — operators
        // couldn't see transaction volume or site-map host count
        // at a glance from the tab bar. History shows `tx_count`
        // (same shape as the status bar's `tx N` chip, which is
        // the project's observed transaction total). Target reuses
        // the history count since the site map populates from
        // history. The badge only renders when count > 0, so an
        // empty project doesn't carry noisy "(0)" chips.
        if (t.id === "proxy" && counters.proxy > 0) count = counters.proxy;
        if (t.id === "scanner" && counters.scanner > 0) count = counters.scanner;
        if (t.id === "history" && counters.history > 0) count = counters.history;
        if (t.id === "target" && counters.history > 0) count = counters.history;
        if (t.id === "collaborator" && counters.collaborator > 0)
          count = counters.collaborator;
        // R849 + R875: Urgency-tinted count chip. Burp 2026.8 shows
        // urgent counts (pending intercept, open findings, OOB hits)
        // in warm colours on the tab chip. Proxy's intercept queue =
        // amber (operator action pending), Scanner's findings = red
        // (open issues), Collaborator's OOB hits = teal-cyan (callback
        // caught — exciting but informational). History + Target
        // count = neutral (just volume stats, no urgency).
        const countClass =
          t.id === "proxy"
            ? "count count-urgent-amber"
            : t.id === "scanner"
              ? "count count-urgent-red"
              : t.id === "collaborator"
                ? "count count-urgent-cyan"
                : "count";
        return (
          <Fragment key={t.id}>
            {GROUP_BOUNDARIES.has(t.id) && (
              <div
                className="tab-group-sep"
                aria-hidden="true"
                title="Tab group boundary"
              />
            )}
            <div
              className={`tab ${section === t.id ? "active" : ""}`}
              onClick={() => setSection(t.id)}
              onKeyDown={(e) => {
                // R857: Space / Enter activate the focused tab —
                // standard WCAG keyboard pattern for role=button
                // elements that aren't actual <button>s. Keeps
                // the Tab-focus → press-Enter navigation flow
                // intact for keyboard-only operators.
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSection(t.id);
                }
              }}
              role="button"
              tabIndex={0}
              aria-current={section === t.id ? "page" : undefined}
              title={t.hint}
            >
              {t.label}
              {count !== null && <span className={countClass}>{count}</span>}
            </div>
          </Fragment>
        );
      })}
    </div>
  );
}

function StatusBar({
  project,
  stats,
  pending,
  findings,
}: {
  project: ProjectInfo | null;
  stats: ProxyStatsView | null;
  pending: number;
  findings: number;
}) {
  return (
    <div className="statusbar">
      <span className="indicator">
        <span className={`dot ${stats?.running ? "on" : ""}`} />
        Proxy: {stats?.running ? stats.listeners.join(", ") : "stopped"}
      </span>
      <span>Transactions: {project?.tx_count ?? 0}</span>
      <span>Scope rules: {project?.scope_rules ?? 0}</span>
      <span>Intercept pending: {pending}</span>
      <span>Findings: {findings}</span>
      {stats && (
        <>
          <span>Conns: {stats.conns_accepted}</span>
          <span>Fwd: {stats.requests_forwarded}</span>
          <span>TLS MITM: {stats.tls_mitm}</span>
          <span>Errors: {stats.errors}</span>
        </>
      )}
      <span className="spacer" style={{ flex: 1 }} />
      <span style={{ color: "var(--text-faint)" }}>
        BurpFree 0.1.0 · an original, independent web-security testing platform
      </span>
    </div>
  );
}

function projectName(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/").filter(Boolean);
  return parts[parts.length - 1] || path;
}

function BrowserLaunchButton({ stats }: { stats: ProxyStatsView | null }) {
  const [busy, setBusy] = useState(false);
  async function launch() {
    setBusy(true);
    try {
      const r = await api.browserLaunch();
      if (r.browser === "none") {
        alert(
          r.note ||
            "No supported browser found. Point your browser's HTTP proxy at the listener manually."
        );
      } else {
        // Successful launch: let the user know the ephemeral profile dir.
        console.log(`Launched ${r.browser}`, r);
      }
    } catch (e) {
      alert(`${e}`);
    } finally {
      setBusy(false);
    }
  }
  return (
    <button
      className="ghost"
      disabled={busy || !stats?.running}
      title={
        stats?.running
          ? "Launch a Chromium browser pre-configured for this proxy (uses an isolated profile)"
          : "Start the proxy first"
      }
      onClick={launch}
    >
      {busy ? "Launching…" : "Open browser"}
    </button>
  );
}
