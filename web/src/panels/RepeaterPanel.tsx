import { useEffect, useMemo, useRef, useState } from "react";
import { api, RepeaterTab } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { sendToComparer } from "./ComparerPanel";
import { DiscoveryModal, DiscoveryTargetPreset } from "./DiscoveryModal";
import { MessageEditor } from "../MessageEditor";
import {
  buildCurl,
  buildFetch,
  buildPowerShell,
  buildHarEntry,
  buildHarLog,
  buildPython,
  copyToClipboard,
  fromUrlAndRaw,
} from "../copyAs";

// EditorMode / MessageEditor / Inspector / parseMessage / prettyPrint /
// toHexDump all live in `../MessageEditor` since Round 11 so the Proxy
// Intercept pane can share them.

export function RepeaterPanel() {
  const [tabs, setTabs] = useState<RepeaterTab[]>([]);
  // R309: Hidden file input ref for the "â¬† Import tabs" button ””
  // reciprocal of R306 export. One ref so a single click fires
  // the OS picker. Same pattern as R124 scope-import + R291
  // settings-import + R308 chain-import.
  const importTabsFileRef = useRef<HTMLInputElement | null>(null);
  // R739: Burp-identical ⚙ settings button position in the primary
  // action group. Click toggles a FloatingMenu with per-tab Repeater
  // settings (encoding, follow-redirects, clear this tab's history).
  // Replaces the always-visible encoding + follow-redirects selects
  // on the toolbar ”” freeing horizontal space while keeping all
  // functionality one click away.
  const [settingsMenu, setSettingsMenu] =
    useState<{ x: number; y: number } | null>(null);
  // R773: Burp-identical "environment" selector dropdown in the
  // Repeater toolbar. Burp Suite 2026.8 ships a cosmetic environment
  // picker next to the target URL that lets operators visualize
  // which deployment they're hitting ("dev", "staging", "anz-corp-dev",
  // etc.). BurpFree derives the env name from the active host suffix
  // (api.dev.example.com â†’ "dev"; falls back to the first dot-segment
  // when no well-known env token is found). Clicking opens a
  // FloatingMenu with common env tokens ”” selection is cosmetic only
  // and does NOT rewrite the host (operators retain full control via
  // the ✎ pencil). Matches Burp's "no destructive change" behavior.
  const [envMenu, setEnvMenu] =
    useState<{ x: number; y: number } | null>(null);
  // ðŸŽ¯ R800 ”” 27th round-number milestone this chunk. Burp AI
  // drawer open state. Clicking the âœ¦ AI button opens a Burp-
  // identical right-side drawer with a mock chat conversation ””
  // a visible stand-in for the Burp Suite 2026.8 "Burp AI"
  // companion drawer visible in the user's reference screenshot.
  // The drawer carries: header (âœ¦ title + âœ• close), chat scroll
  // area pre-populated with a canned greeting + the active tab's
  // method/URL/status/size summary, free-text prompt input +
  // "Analyze" button that appends a canned analysis response.
  // Entirely client-side ”” no AI backend. Operators pivoting
  // from Burp see the familiar silhouette without the dead-end
  // of a non-existent button, and the mock gives useful inline
  // analysis derived from the parsed request/response.
  const [burpAiOpen, setBurpAiOpen] = useState<boolean>(false);
  const [burpAiMessages, setBurpAiMessages] = useState<
    Array<{ role: "user" | "assistant"; text: string }>
  >([]);
  const [burpAiPrompt, setBurpAiPrompt] = useState<string>("");
  // R851: Listen for the global `burpfree:open-burp-ai` CustomEvent
  // dispatched by Ctrl+E (Burp Suite 2026.8's "Explain this" hotkey).
  // The App-level keydown handler navigates to Repeater first and
  // then fires this event on a 60ms delay so the panel has time to
  // mount its listener before the dispatch lands. Idempotent ”” if
  // the drawer is already open, firing again is a no-op.
  useEffect(() => {
    function onOpenAi() {
      setBurpAiOpen(true);
    }
    window.addEventListener("burpfree:open-burp-ai", onOpenAi);
    return () => window.removeEventListener("burpfree:open-burp-ai", onOpenAi);
  }, []);
  // R811: Lifted selection state so the Inspector sidebar's "Selection"
  // top panel can render the current selection + decoder dropdown.
  // Mirrors Burp Suite 2026.8's exact Inspector header visible in the
  // user's reference screenshot: "Selection 28 (0x1c)" + "Selected text"
  // box + "Decoded from: Select â–¼" + decoded content + Cancel/Apply.
  // `direction` identifies which pane the selection came from so the
  // Inspector can target the right pane for Apply-changes writes.
  const [editorSelection, setEditorSelection] = useState<{
    start: number;
    end: number;
    text: string;
    direction: "request" | "response";
  } | null>(null);
  // R788: Burp-identical "Focus mode" for the Repeater editor
  // grid. Three states: "both" (default ”” Request + Response
  // visible), "request" (collapse Response pane for a wide
  // request editor), "response" (collapse Request pane for a
  // wide response viewer). Mirrors Burp Suite 2026.8's split-
  // pane toggle operators use when they want the entire panel
  // width for one side ”” great for responses with long JSON
  // bodies or deeply-nested XML. Persisted in localStorage so
  // the preference survives panel re-mount. Cycle via a single
  // toggle button in the toolbar.
  const [focusPane, setFocusPane] = useState<
    "both" | "request" | "response"
  >(() => {
    try {
      const v = localStorage.getItem("burpfree.repeater.focuspane");
      if (v === "request" || v === "response" || v === "both") return v;
    } catch {
      /* ignore */
    }
    return "both";
  });
  useEffect(() => {
    try {
      localStorage.setItem("burpfree.repeater.focuspane", focusPane);
    } catch {
      /* ignore */
    }
  }, [focusPane]);
  // ðŸŽ¯ R750 ”” 21st round-number milestone + Compact tabs mode.
  // Toggles the tab chip decoration between "full" (method badge
  // + status dot + count + pin + color + comment emoji) and
  // "compact" (just name + status dot + close Ã—). Compact matches
  // Burp Suite's clean tab bar. Persisted in localStorage so the
  // operator's preference survives panel re-mount.
  // R764: Tab filter state ”” case-folded substring match against
  // tab name OR URL. Session-local only (not persisted).
  const [tabFilter, setTabFilter] = useState<string>("");
  const tabFilterText = tabFilter.trim().toLowerCase();
  const [compactTabs, setCompactTabs] = useState<boolean>(() => {
    try {
      const v = localStorage.getItem("burpfree.repeater.compacttabs");
      return v === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "burpfree.repeater.compacttabs",
        compactTabs ? "1" : "0",
      );
    } catch {
      /* ignore */
    }
  }, [compactTabs]);
  // R751: Burp-identical draggable Inspector width. Operators who
  // want more space for key/value pair content can widen the
  // sidebar; those on narrow screens can shrink it. Stored in
  // localStorage so the preference survives panel re-mount.
  // Clamped to 220px-500px to prevent accidental too-narrow or
  // too-wide states that would starve the Request/Response panes.
  const [inspectorWidth, setInspectorWidth] = useState<number>(() => {
    try {
      const v = Number(localStorage.getItem("burpfree.repeater.inspectorwidth"));
      if (v >= 220 && v <= 500) return v;
    } catch {
      /* ignore */
    }
    return 280;
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "burpfree.repeater.inspectorwidth",
        String(inspectorWidth),
      );
    } catch {
      /* ignore */
    }
  }, [inspectorWidth]);
  const inspectorResizingRef = useRef<{ startX: number; startW: number } | null>(
    null,
  );
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const ref = inspectorResizingRef.current;
      if (!ref) return;
      // Dragging right-to-left expands the sidebar; left-to-right shrinks.
      const dx = ref.startX - e.clientX;
      const next = Math.max(220, Math.min(500, ref.startW + dx));
      setInspectorWidth(next);
    };
    const onUp = () => {
      inspectorResizingRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
  }, []);
  const [active, setActive] = useState<number | null>(null);
  const [raw, setRaw] = useState("");
  const [respRaw, setRespRaw] = useState("");
  const [busy, setBusy] = useState(false);
  // Tabs with an in-flight `repeaterSend` right now. Flips the active
  // tab's Send toolbar button to a red Cancel while any of its
  // requests are on the wire ”” mirrors Burp's Repeater cancel button.
  const [inflight, setInflight] = useState<Set<number>>(new Set());
  const [tabMenu, setTabMenu] = useState<MenuState<RepeaterTab> | null>(null);
  // R889: Burp-identical + add-tab context menu + closed-tab
  // history for the "Reopen closed tab" affordance. The + button
  // now opens a FloatingMenu matching Burp Suite 2026.8's visible
  // tab-strip dropdown (New HTTP tab / New tab group / Close all /
  // Reopen closed tab). `closedTabHistory` is a session-only ring
  // buffer (last 10 closed tabs) so operators who accidentally
  // close a tab can recover it. Rings on push: if at capacity, the
  // oldest entry drops off the front.
  const [addMenu, setAddMenu] = useState<MenuState<null> | null>(null);
  // R894: Burp-identical "Configure target details" modal matching
  // the user-attached screenshot. Opens from the ✎ pencil next to
  // the target URL. Fields: Host (text), Override SNI (toggle),
  // Port (number), Use HTTPS (toggle). Replaces our old `prompt()`
  // for URL editing ”” the modal matches Burp Suite 2026.8's exact
  // dialog layout. `null` means closed.
  const [configureTargetOpen, setConfigureTargetOpen] = useState(false);
  const [configureTargetDraft, setConfigureTargetDraft] = useState<{
    host: string;
    port: number;
    useHttps: boolean;
    overrideSni: boolean;
    sniValue: string;
    path: string;
  } | null>(null);
  const [closedTabHistory, setClosedTabHistory] = useState<
    Array<{
      name: string;
      url: string;
      method: string;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      template: any;
      comment?: string | null;
      group?: string | null;
      color?: string | null;
    }>
  >([]);
  const [renaming, setRenaming] = useState<{ id: number; name: string } | null>(null);
  // Group chip right-click + collapse state. `groupCollapsed[g] = true`
  // hides the group's member tabs behind the chip. `groupMenu` carries
  // the group label the operator right-clicked.
  const [groupMenu, setGroupMenu] = useState<MenuState<string> | null>(null);
  const [groupCollapsed, setGroupCollapsed] = useState<Record<string, boolean>>({});
  // Drag-and-drop state: `source` is the id being dragged, `target`
  // is the hovered id, `side` is which half of the target the cursor
  // sits over (before = left half, after = right half). All null when
  // idle. Used both to style the drop indicator and to compute the
  // final order on drop.
  const [dragState, setDragState] = useState<{
    source: number;
    target: number;
    side: "before" | "after";
  } | null>(null);
  // Pre-computed list of all existing group labels, refreshed when
  // tabs change. Used by the "Add to existing group â–¸ …" submenu.
  const existingGroups = useMemo(() => {
    const s = new Set<string>();
    for (const t of tabs) if (t.group) s.add(t.group);
    return [...s].sort();
  }, [tabs]);
  // Content-Discovery modal preset (opened from the "ðŸ”Ž Discover"
  // button). `null` keeps the modal closed; derived from the active
  // tab's template on click so operators don't have to retype host.
  const [discoveryPreset, setDiscoveryPreset] =
    useState<DiscoveryTargetPreset | null>(null);
  // Burst-send + diff state. Pinned to the active tab; cleared when
  // the user switches tabs.
  const [bursting, setBursting] = useState(false);
  const [sendIndex, setSendIndex] = useState<number | null>(null);
  const [diffA, setDiffA] = useState<number | null>(null);
  const [diffB, setDiffB] = useState<number | null>(null);
  const [diffReport, setDiffReport] = useState<any | null>(null);
  // R733: Inspector sidebar ”” Burp-identical right-side panel showing
  // parsed request/response structure (query params, body params,
  // cookies, headers, response headers). Persisted in localStorage so
  // the operator's preference survives panel re-mount.
  const [showInspector, setShowInspector] = useState<boolean>(() => {
    try {
      const v = localStorage.getItem("burpfree.repeater.inspector");
      return v === null ? true : v === "1";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "burpfree.repeater.inspector",
        showInspector ? "1" : "0",
      );
    } catch {
      /* ignore storage failures */
    }
  }, [showInspector]);
  // R733: Which Inspector sections are expanded. Persist in a single
  // record so the operator's "collapsed state" survives re-mount.
  const [inspectorExpanded, setInspectorExpanded] = useState<
    Record<string, boolean>
  >(() => {
    try {
      const v = localStorage.getItem("burpfree.repeater.inspector.expanded");
      if (v) return JSON.parse(v) as Record<string, boolean>;
    } catch {
      /* ignore */
    }
    // Default: all expanded on first visit so operators discover the
    // sections. Collapsing is one click per section.
    return {
      attrs: true,
      query: true,
      body: true,
      cookies: true,
      headers: true,
      respHeaders: true,
      notes: false, // R738: Notes default-collapsed so it doesn't dominate.
    };
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "burpfree.repeater.inspector.expanded",
        JSON.stringify(inspectorExpanded),
      );
    } catch {
      /* ignore */
    }
  }, [inspectorExpanded]);
  function toggleInspectorSection(key: string) {
    setInspectorExpanded((prev) => ({ ...prev, [key]: !prev[key] }));
  }
  // R737: Collapsible "bulk ops" overflow ”” Export/Import/All cURL/
  // HAR/PS/Py/fetch/MD/Tab-stats etc. live behind a `â‹¯` toggle so
  // the toolbar matches Burp Suite's clean minimal row. Operators
  // who use bulk ops frequently can keep it expanded; others get
  // the clean toolbar. Persisted in localStorage.
  const [showBulkOps, setShowBulkOps] = useState<boolean>(() => {
    try {
      const v = localStorage.getItem("burpfree.repeater.bulkops");
      return v === null ? false : v === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "burpfree.repeater.bulkops",
        showBulkOps ? "1" : "0",
      );
    } catch {
      /* ignore */
    }
  }, [showBulkOps]);

  async function refresh() {
    const list = await api.repeaterList();
    setTabs(list);
    if (!active && list.length) setActive(list[0].id);
  }
  useEffect(() => {
    refresh();
    // Hydrate the inflight set from the engine so Cancel buttons
    // light up for sends started before this panel mounted (reload
    // / navigation / tab switch). The useState default is an empty
    // Set which would otherwise disable Cancel until the next send.
    (async () => {
      try {
        const ids = await api.repeaterInflightIds();
        if (ids.length > 0) setInflight(new Set(ids));
      } catch (e) {
        // Non-fatal ”” Cancel buttons just stay disabled until the
        // next local send registers an entry.
        console.warn("inflight resync failed:", e);
      }
    })();
  }, []);

  // Alt+Left / Alt+Right nudges the active tab left / right by one
  // slot inside its current section (ungrouped or specific group).
  // Scoped at the document level so it fires regardless of which
  // pane has focus ”” mirrors Burp's behaviour where the shortcut
  // works from anywhere in the Repeater view.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (active == null) return;
      // Skip when the user is editing text (so Alt+Arrow doesn't
      // steal from text-field navigation).
      const el = e.target as HTMLElement | null;
      const tag = el?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || el?.isContentEditable) return;
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        void nudgeActiveTab("left");
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        void nudgeActiveTab("right");
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // nudgeActiveTab closes over `tabs` + `active`; re-register when
    // either changes so the closure sees fresh state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, tabs]);

  // Ctrl+Backspace while the active tab is in-flight â†’ cancel it.
  // Ctrl+Shift+Backspace â†’ cancel every in-flight send across every
  // tab (panic button). Picked Ctrl+Backspace because it's unused in
  // text fields (Delete-last-word uses Alt+Backspace on Windows text
  // widgets) and reads intuitively as "undo send". Scoped to the
  // Repeater panel so a misplaced shortcut in Comparer/Scanner won't
  // fire this.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey) || !e.key || e.key !== "Backspace") return;
      if (e.shiftKey) {
        if (inflight.size === 0) return;
        e.preventDefault();
        void cancelAll();
        return;
      }
      if (active == null || !inflight.has(active)) return;
      e.preventDefault();
      void cancelActive();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, inflight]);

  // R136: Ctrl+D duplicates the current active tab. Mirror of
  // Burp's "Duplicate tab" context-menu entry promoted to a
  // top-level hotkey ”” operators who iterate on a request chain
  // branch quickly: tweak, Ctrl+D, tweak the clone, Ctrl+Enter,
  // diff. Backend `clone_tab` copies template + colour + follow-
  // redirects + comment (but intentionally not history, since
  // the clone is a fresh starting point). Guarded on `active`
  // being set so a focused text input doesn't accidentally fire.
  useEffect(() => {
    function onDupKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      if (e.key.toLowerCase() !== "d") return;
      if (active == null) return;
      const el = document.activeElement as HTMLElement | null;
      // Skip when the operator is typing ”” Ctrl+D in a textarea /
      // input / contenteditable is likely a browser-level action
      // (bookmark on some platforms) or an editor shortcut.
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      const src = tabs.find((t) => t.id === active);
      if (!src) return;
      e.preventDefault();
      void duplicateTab(src);
    }
    document.addEventListener("keydown", onDupKey);
    return () => document.removeEventListener("keydown", onDupKey);
  }, [tabs, active]);

  // R346: Alt+Shift+N opens a new Repeater tab seeded with the
  // URL currently in the clipboard ”” skips the two-prompt dance
  // (URL + name) that Alt+N (R229) walks the operator through.
  // Common workflow: copy URL from Jira ticket / Slack message /
  // browser URL bar â†’ Alt+Shift+N â†’ tab appears pre-filled with
  // that URL + the host as the tab name. Falls back to Alt+N
  // semantics if the clipboard doesn't contain a parseable URL
  // (empty / plain text / etc.) so the keystroke never becomes
  // a dead end. **Guards** plain Alt+Shift (no Ctrl/Meta),
  // text-input focus skip so Alt+Shift+N inside the URL field
  // stays available for native insert. **Clipboard async**
  // navigator.clipboard.readText requires the window to be
  // focused; a reject (permission denied / unsupported) falls
  // through to the standard Alt+N prompt with a toast note.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "N" && e.key !== "n") return;
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
      void (async () => {
        try {
          const text = await navigator.clipboard.readText();
          const trimmed = text.trim();
          // Minimal URL sanity: must have scheme + host.
          if (!/^https?:\/\/[^\s]+/i.test(trimmed)) {
            // Fall back to the Alt+N prompt path so the keystroke
            // isn't a dead end.
            void addTab();
            return;
          }
          let host = trimmed;
          try {
            host = new URL(trimmed).host || trimmed;
          } catch {
            // keep host = trimmed if URL ctor rejects
          }
          const name = `Tab ${tabs.length + 1} ”” ${host.slice(0, 40)}`;
          const id = await api.repeaterAddTab(name, trimmed);
          await refresh();
          setActive(id);
        } catch {
          // Clipboard rejected; fall back to the Alt+N prompt.
          void addTab();
        }
      })();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs.length]);

  // R381: Alt+Shift+D runs "Diff last 2" on the active tab ””
  // keyboard companion to R340's one-click toolbar button in the
  // HistoryStrip. Operators doing iterative probing (tweak â†’
  // Ctrl+Enter â†’ is it different? â†’ tweak â†’ Ctrl+Enter â†’ …) can
  // skip the mouse pivot entirely: Ctrl+Enter sends, Alt+Shift+D
  // diffs the two most recent sends. **Mechanism** mirrors R340
  // exactly ”” set diffA = n-2, diffB = n-1 so the UI reflects
  // which anchors are being compared, then fire `runDiff(active,
  // n-2, n-1)`. runDiff reads its indices as args (not state) so
  // no setTimeout tick-flush is needed, unlike R340's HistoryStrip
  // button which lives below the state owner. **Guards** Alt+Shift
  // only (no Ctrl/Meta so Ctrl+Shift+D "duplicate line" muscle
  // memory in text editors stays untouched), text-input focus
  // skip. **No-op** when `active == null` or the tab has fewer
  // than 2 sends ”” silent, no alert, so the keystroke stays safe
  // to spam during the iteration loop. **Letter choice** D =
  // Diff; sits right next to the Ctrl+D "duplicate active tab"
  // shortcut (plain Ctrl+D, no Alt) so the "duplicate / diff"
  // mental grouping lives on one key.
  useEffect(() => {
    function onDiffLastKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "D" && e.key !== "d") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (active == null) return;
      const tab = tabs.find((t) => t.id === active);
      if (!tab || tab.history.length < 2) return;
      e.preventDefault();
      const n = tab.history.length;
      setDiffA(n - 2);
      setDiffB(n - 1);
      void runDiff(active, n - 2, n - 1);
    }
    document.addEventListener("keydown", onDiffLastKey);
    return () => document.removeEventListener("keydown", onDiffLastKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, tabs]);

  // R385: Alt+Shift+P copies every pinned tab's URL to the
  // clipboard ”” keyboard companion to R357's "ðŸ“‹ Copy pinned"
  // toolbar button. Operators iterating on a working set (login
  // + probe + canary) frequently paste the URL list into Jira /
  // Slack / sidecar shell pipelines; a keystroke keeps the hand
  // on the home row rather than hunting for the mouse. **Letter
  // choice** P pairs with R336's plain Alt+P (toggle pin on
  // active tab) ”” Shift modifier differentiates "do something
  // with ALL pins" (Alt+Shift+P) vs "toggle THIS pin" (Alt+P).
  // Same mental grouping. **Mechanism** mirrors R357 exactly:
  // filter tabs â†’ pinned â†’ dedupe via Set â†’ sort alpha for
  // stable output. **Guards** Alt+Shift only, text-input focus
  // skip. **No-op when nothing pinned** silent ”” the keystroke
  // stays safe to spam, won't throw a confusing empty-clipboard
  // alert during ramp-up before any tabs are pinned.
  useEffect(() => {
    function onCopyPinnedKey(e: KeyboardEvent) {
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
      const pinned = tabs.filter((t) => t.pinned);
      if (pinned.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(pinned.map((t) => buildUrlFromTemplate(t.template))),
          ).sort();
          await navigator.clipboard.writeText(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onCopyPinnedKey);
    return () => document.removeEventListener("keydown", onCopyPinnedKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs]);

  // R566: Alt+Shift+A alphabetically sorts the tab bar ”” keyboard
  // companion to R564's "ðŸ”¤ Sort Aâ†’Z" toolbar button. Operators
  // juggling 20+ tabs frequently want the alpha sort without
  // reaching for the mouse. **Letter choice** A = Alphabetical.
  // **Guards** Alt+Shift only, text-input focus skip, â‰¥2 tabs
  // required. **Mechanism** mirrors R564 exactly: group-first
  // bucketing, intra-group alpha sort via case-insensitive
  // localeCompare, ungrouped bucket pushed last.
  useEffect(() => {
    function onSortAlphaKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "A" && e.key !== "a") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (tabs.length < 2) return;
      e.preventDefault();
      void (async () => {
        try {
          const buckets: Record<string, RepeaterTab[]> = {};
          for (const t of tabs) {
            const g = t.group ?? "";
            (buckets[g] ??= []).push(t);
          }
          const sortedIds: number[] = [];
          const groupKeys = Object.keys(buckets).sort((a, b) => {
            if (a === "") return 1;
            if (b === "") return -1;
            return a.localeCompare(b);
          });
          for (const g of groupKeys) {
            const rows = buckets[g];
            rows.sort((a, b) =>
              (a.name || "").localeCompare(b.name || "", undefined, {
                sensitivity: "base",
              }),
            );
            for (const r of rows) sortedIds.push(r.id);
          }
          await api.repeaterReorder(sortedIds);
          await refresh();
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onSortAlphaKey);
    return () => document.removeEventListener("keydown", onSortAlphaKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs]);

  // R567: Alt+Shift+B sorts the tab bar by send count desc ””
  // keyboard companion to R565's "ðŸ” Sort by sends" toolbar
  // button. Operators scanning a crowded workbench for "the
  // tab I've been hammering" want the frequency-first sort via
  // a keystroke, not a mouse. **Letter choice** B = Busiest-
  // first. (Alt+Shift+N was unavailable ”” R346 owns it for
  // clipboard-seeded new tab.) **Guards** mirror R566:
  // Alt+Shift only, text-input skip, â‰¥2 tabs AND at least one
  // with history (so a workbench of blank-template tabs
  // doesn't spin a no-op). **Mechanism** mirrors R565 exactly:
  // group-first bucket, intra-group sort by history length
  // desc with name tie-breaker.
  useEffect(() => {
    function onSortByCountKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "B" && e.key !== "b") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (tabs.length < 2) return;
      if (!tabs.some((t) => (t.history?.length ?? 0) > 0)) return;
      e.preventDefault();
      void (async () => {
        try {
          const buckets: Record<string, RepeaterTab[]> = {};
          for (const t of tabs) {
            const g = t.group ?? "";
            (buckets[g] ??= []).push(t);
          }
          const sortedIds: number[] = [];
          const groupKeys = Object.keys(buckets).sort((a, b) => {
            if (a === "") return 1;
            if (b === "") return -1;
            return a.localeCompare(b);
          });
          for (const g of groupKeys) {
            const rows = buckets[g];
            rows.sort((a, b) => {
              const diff =
                (b.history?.length ?? 0) - (a.history?.length ?? 0);
              if (diff !== 0) return diff;
              return (a.name || "").localeCompare(b.name || "", undefined, {
                sensitivity: "base",
              });
            });
            for (const r of rows) sortedIds.push(r.id);
          }
          await api.repeaterReorder(sortedIds);
          await refresh();
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onSortByCountKey);
    return () => document.removeEventListener("keydown", onSortByCountKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs]);

  // R386: Alt+Shift+U copies every tab's URL (not just pinned)
  // to the clipboard ”” keyboard companion to R373's "ðŸ“‹ Copy all
  // URLs" toolbar button. Natural extension of R385 Alt+Shift+P
  // (pinned only): same mental model, broader scope. Operators
  // winding down an engagement often want the full workspace
  // URL dump before closing ”” one keystroke yields it. **Letter
  // choice** U = URLs; keeps the "copy-batch" shortcuts on
  // mnemonic letters (Alt+Shift+P = Pinned, Alt+Shift+U = URLs,
  // Alt+Shift+N = clipboard-seeded new tab from R346). **Scope**
  // every tab, not just pinned ”” if operators want pinned-only
  // they use Alt+Shift+P. **Mechanism** mirrors R373 exactly:
  // tabs.map â†’ buildUrlFromTemplate â†’ Set dedupe â†’ sort alpha.
  // **Guards** Alt+Shift only, text-input focus skip. **Threshold
  // guard** mirrors R373's render gate ”” only acts when
  // tabs.length >= 2 so single-tab sessions reach for the per-
  // tab menu Copy URL instead (consistent with the toolbar
  // button's visibility rule).
  useEffect(() => {
    function onCopyAllUrlsKey(e: KeyboardEvent) {
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
      if (tabs.length < 2) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(tabs.map((t) => buildUrlFromTemplate(t.template))),
          ).sort();
          await navigator.clipboard.writeText(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onCopyAllUrlsKey);
    return () => document.removeEventListener("keydown", onCopyAllUrlsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs]);

  // R396: Alt+Shift+F fires every pinned tab in parallel ””
  // keyboard companion to the "âš² Fire pinned" toolbar button
  // (R94 era). Operators iterating on a working set (login +
  // authenticated probe + audit canary) want to re-fire the
  // whole set after a backend tweak / cookie refresh / rebuild;
  // one keystroke replaces the mouse pivot. Natural pairing
  // with R385 Alt+Shift+P (copy pinned URLs) ”” F for Fire, P
  // for Pinned, side by side on the keyboard. **Letter choice**
  // F = Fire; sits adjacent to R385's P so operators can "copy
  // pinned â†’ fire pinned" with two adjacent keystrokes. **Why
  // not Alt+F** reserving the plain-Alt family for single-tab
  // ops (Alt+W close, Alt+P pin toggle, Alt+N new) ”” Shift
  // modifier marks "do something with ALL pins". **Mechanism**
  // delegates to the existing `sendPinnedTabs()` function so
  // the `busy`-guard + Promise.allSettled parallel firing
  // semantics match the button exactly. **Guards** Alt+Shift
  // only (no Ctrl/Meta so Ctrl+Shift+F "find in files" muscle
  // memory stays untouched), text-input focus skip. **No-op**
  // when nothing is pinned OR when busy ”” silent, matches the
  // button's disabled state. The busy-check ensures operators
  // can't spam the keystroke to fire concurrent batches.
  useEffect(() => {
    function onFirePinnedKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "F" && e.key !== "f") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (busy) return;
      const pinned = tabs.filter((t) => t.pinned);
      if (pinned.length === 0) return;
      e.preventDefault();
      void sendPinnedTabs();
    }
    document.addEventListener("keydown", onFirePinnedKey);
    return () => document.removeEventListener("keydown", onFirePinnedKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs, busy]);

  // R454: Alt+Shift+S saves the currently-selected send's response ””
  // keyboard version of R406's "ðŸ’¾ Save" button in HistoryStrip.
  // Operators walking the sends list (click chip N â†’ eyeball
  // response â†’ want it saved â†’ click N+1 â†’ …) through a batch of
  // interesting captures can skip the mouse pivot entirely ”” just
  // keystroke each one. **Letter choice** S = Save; aligns with
  // R438 Decoder Alt+Shift+S (save final output) + R401 Scanner
  // detail-pane "â¬‡ Save evidence" button, extending the "save
  // visible artifact" cross-panel family. **Mechanism** inline
  // Blob + anchor + click (same idiom as R406's button) using
  // the module-level `renderRawResponse` helper to assemble the
  // full status-line + headers + body text. Filename pattern
  // `response-send<idx>-<status>.txt` mirrors the button exactly
  // so a mixed keystroke-and-mouse workflow doesn't produce
  // inconsistent filenames. **Guards** Alt+Shift only (no
  // Ctrl/Meta so Ctrl+S "save page" muscle memory stays
  // untouched), text-input / textarea / contenteditable focus
  // skip. **Visibility gate** mirrors R406 exactly: active tab
  // must exist, sendIndex must be set, the selected send must
  // have a response (not an error-only). Silent no-op when any
  // gate fails so a stray keystroke on an idle Repeater is safe.
  useEffect(() => {
    function onSaveKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "S" && e.key !== "s") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (active == null || sendIndex == null) return;
      const t = tabs.find((x) => x.id === active);
      if (!t) return;
      const s = t.history[sendIndex];
      if (!s || !s.response) return;
      e.preventDefault();
      const status = s.response.status ?? "unknown";
      const name = `response-send${sendIndex + 1}-${status}.txt`;
      const body = renderRawResponse(s.response, s.error);
      try {
        const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
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
    document.addEventListener("keydown", onSaveKey);
    return () => document.removeEventListener("keydown", onSaveKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, tabs, sendIndex]);

  // R336: Alt+P toggles the pin state on the active tab ””
  // keyboard companion to the "ðŸ“Œ Pin tab / ðŸ“Œ Unpin tab" entry
  // in the right-click menu. Operators building a working set of
  // tabs (login + authenticated probe + audit canary) want to
  // pin/unpin without a mouse pivot. **Mechanism** reuses
  // `togglePinned(id, !pinned)` + relies on `repeaterSetPinned`
  // for the backend write + refresh. **Guards** plain Alt only
  // (no Ctrl/Meta/Shift), text-input focus skip so Alt+P inside
  // the URL field doesn't flash the pin state. **No-op** when
  // no tab is active.
  useEffect(() => {
    function onPinKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "p" && e.key !== "P") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (active == null) return;
      const t = tabs.find((x) => x.id === active);
      if (!t) return;
      e.preventDefault();
      void togglePinned(t.id, !t.pinned);
    }
    document.addEventListener("keydown", onPinKey);
    return () => document.removeEventListener("keydown", onPinKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, tabs]);

  // R229: Alt+N opens the "new tab" prompt. Companion to R225
  // (Alt+W close) + R194 (Alt+1..9 jump). Browser-standard
  // Ctrl+T would collide with the OS/webview new-window action;
  // R833: Ctrl+B ”” Burp-identical "Jump to request body" shortcut.
  // Operators composing a request want to drop their caret into
  // the body area without manually scrolling + clicking. Finds
  // the first blank line in the raw text (headers/body separator)
  // + sets textarea selection to that offset + scrolls into view.
  // Mirrors Burp Suite 2026.8's Ctrl+B binding. Guards: text-input
  // focus skip (so Ctrl+B inside URL bar / Notes doesn't fire).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.ctrlKey && !e.metaKey) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key.toLowerCase() !== "b") return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (
          tag === "INPUT" ||
          (tag === "TEXTAREA" && !el.classList.contains("mono")) ||
          tag === "SELECT" ||
          el.isContentEditable
        ) {
          return;
        }
      }
      e.preventDefault();
      // Find the first blank-line separator (CRLF or LF).
      const sepCrlf = raw.indexOf("\r\n\r\n");
      const sepLf = raw.indexOf("\n\n");
      const sep =
        sepCrlf >= 0 && (sepLf < 0 || sepCrlf <= sepLf)
          ? { idx: sepCrlf, len: 4 }
          : sepLf >= 0
            ? { idx: sepLf, len: 2 }
            : null;
      if (!sep) return;
      const target = sep.idx + sep.len;
      // Grab the first mono textarea (the request editor).
      const ta = document.querySelector<HTMLTextAreaElement>(
        ".rep-editor-raw-wrap > textarea.mono",
      );
      if (!ta) return;
      ta.focus();
      ta.setSelectionRange(target, target);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [raw]);

  // Alt+N stays in the Alt-modifier family we've carved out for
  // Repeater keyboard operations. **Mechanism** fires the
  // existing `addTab()` fn which prompts for URL + name then
  // delegates to `repeater_add_tab`. **Guards** plain Alt only
  // (no Ctrl/Meta/Shift), key `n` / `N`, text-input focus skip.
  useEffect(() => {
    function onNewKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key.toLowerCase() !== "n") return;
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
      void addTab();
    }
    document.addEventListener("keydown", onNewKey);
    return () => document.removeEventListener("keydown", onNewKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // R892: Ctrl+Shift+T reopens the most-recently-closed tab ””
  // Chrome's canonical "reopen closed tab" convention. Operators
  // who accidentally Alt+W a tab or middle-click (R856) can
  // recover with one keystroke. Guards: Ctrl+Shift only (no Alt
  // / Meta), text-input focus skip (so Ctrl+Shift+T inside a
  // search field or editor doesn't fire), no-op when
  // closedTabHistory is empty.
  useEffect(() => {
    function onReopenKey(e: KeyboardEvent) {
      if (!e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey) return;
      if (e.key.toLowerCase() !== "t") return;
      if (closedTabHistory.length === 0) return;
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
      void reopenLastClosedTab();
    }
    document.addEventListener("keydown", onReopenKey);
    return () => document.removeEventListener("keydown", onReopenKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closedTabHistory.length]);

  // R225: Alt+W closes the active tab. Companion to R136 (Ctrl+D
  // duplicate) + R170 (F2 rename). Browser-standard Ctrl+W is
  // reserved by the OS/webview for closing the whole window on
  // some platforms, so Alt+W avoids that collision while staying
  // in the "W = close" muscle-memory family. Guards:
  //   - plain Alt (no Ctrl/Meta/Shift) so Alt+Shift+W etc. don't
  //     collide with potential future shortcuts
  //   - text-input focus skip (so Alt+W inside a URL field or
  //     message editor doesn't blow away the tab)
  //   - no-op when there's no active tab
  //   - pinned tabs route through closeTab() which refuses the
  //     close itself (R27 pin semantic ”” honoured here too)
  useEffect(() => {
    function onCloseKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key.toLowerCase() !== "w") return;
      if (active == null) return;
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
      void closeTab(active);
    }
    document.addEventListener("keydown", onCloseKey);
    return () => document.removeEventListener("keydown", onCloseKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // R274: Alt+Shift+W closes every unpinned tab in one stroke ””
  // the keyboard shortcut companion to R165's "Close all unpinned
  // tabs" right-click entry. Operators finishing an engagement
  // can clear the workspace without reaching for the mouse.
  // Pinned tabs always survive (matching R165 + R27 pin semantic).
  // Guards:
  //   - Alt+Shift only (no Ctrl/Meta co-modifiers)
  //   - text-input focus skip
  //   - no-op when the unpinned set is empty
  //   - confirm pre-close with the exact victim count because the
  //     keyboard path is faster than the right-click menu and a
  //     mis-fire would blow away work
  useEffect(() => {
    async function closeAllUnpinnedKb() {
      const victims = tabs.filter((t) => !t.pinned).map((t) => t.id);
      if (victims.length === 0) return;
      const pinnedKept = tabs.length - victims.length;
      const extra =
        pinnedKept > 0
          ? ` (${pinnedKept} pinned tab${pinnedKept === 1 ? "" : "s"} kept)`
          : "";
      if (
        !confirm(
          `Close ${victims.length} unpinned Repeater tab${victims.length === 1 ? "" : "s"}${extra}?`,
        )
      )
        return;
      try {
        await Promise.allSettled(
          victims.map((id) => api.repeaterRemove(id)),
        );
        if (active != null && victims.includes(active)) {
          setActive(null);
        }
        await refresh();
      } catch (err) {
        alert(`Close all unpinned failed: ${err}`);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key.toLowerCase() !== "w") return;
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
      void closeAllUnpinnedKb();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs, active]);

  // Alt+Left / Alt+Right â†’ switch to the previous / next tab in
  // the active tabs list order. Mirror of Burp's keyboard tab
  // navigation. Deliberately uses Alt instead of Ctrl because
  // Ctrl+Tab is the standard browser tab-switch shortcut and
  // Tauri doesn't fully suppress it on Windows. Guards against
  // text-input focus so the hotkey doesn't collide with
  // word-boundary navigation in the request editor.
  //
  // R333: Alt+Home / Alt+End extend the family ”” jump straight
  // to the first / last tab. Mirrors browser tab convention +
  // the Home/End row-navigation already in HistoryPanel (R208).
  // Pairs cleanly with the Alt+1..9 direct-index jumps (R194).
  useEffect(() => {
    function onTabKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey) return;
      if (
        e.key !== "ArrowLeft" &&
        e.key !== "ArrowRight" &&
        e.key !== "Home" &&
        e.key !== "End"
      )
        return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        if (el.isContentEditable) return;
      }
      if (tabs.length === 0) return;
      const idx = active != null ? tabs.findIndex((t) => t.id === active) : -1;
      // Alt+Home / Alt+End land unconditionally on the ends so the
      // operator doesn't have to think about where the cursor is.
      if (e.key === "Home") {
        if (idx === 0) return; // already at first
        e.preventDefault();
        setActive(tabs[0].id);
        return;
      }
      if (e.key === "End") {
        if (idx === tabs.length - 1) return; // already at last
        e.preventDefault();
        setActive(tabs[tabs.length - 1].id);
        return;
      }
      if (idx < 0) {
        setActive(tabs[0].id);
        e.preventDefault();
        return;
      }
      const nextIdx =
        e.key === "ArrowLeft"
          ? Math.max(0, idx - 1)
          : Math.min(tabs.length - 1, idx + 1);
      if (nextIdx === idx) return;
      e.preventDefault();
      setActive(tabs[nextIdx].id);
    }
    document.addEventListener("keydown", onTabKey);
    return () => document.removeEventListener("keydown", onTabKey);
  }, [tabs, active]);

  /*  R194: Alt+1..9 ”” direct tab jump by index. Mirrors browser
   *  tab-switch convention + Burp's own keyboard shortcuts.
   *  Guards: no Ctrl/Meta/Shift to avoid collisions with system
   *  menu shortcuts; text-input-focus skip so Alt+N inside the
   *  URL / message editor doesn't flash tabs; tabs.length >= N
   *  check so Alt+9 on a 3-tab list silently no-ops rather than
   *  jumping to a nonexistent slot. */
  useEffect(() => {
    function onDigitKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (!/^[1-9]$/.test(e.key)) return;
      const idx = parseInt(e.key, 10) - 1;
      if (idx >= tabs.length) return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        if (el.isContentEditable) return;
      }
      e.preventDefault();
      setActive(tabs[idx].id);
    }
    document.addEventListener("keydown", onDigitKey);
    return () => document.removeEventListener("keydown", onDigitKey);
  }, [tabs]);

  // Ctrl+Shift+Left / Ctrl+Shift+Right â†’ cycle through the active
  // tab's send history. Mirrors Burp's Repeater ◀ ▶ arrows + their
  // hotkeys. Scoped to the Repeater panel via the active-tab check
  // so this doesn't fire inside Scanner / Comparer when they're
  // mounted. Shift is required so the shortcut doesn't clash with
  // the text-editor word-boundary navigation operators are muscle-
  // memory for.
  useEffect(() => {
    function onNavKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey) || !e.shiftKey) return;
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      if (active == null) return;
      const tab = tabs.find((t) => t.id === active);
      if (!tab || tab.history.length === 0) return;
      const effective =
        sendIndex !== null && sendIndex < tab.history.length
          ? sendIndex
          : tab.history.length - 1;
      e.preventDefault();
      if (e.key === "ArrowLeft") {
        if (effective > 0) setSendIndex(effective - 1);
      } else {
        if (effective < tab.history.length - 1) setSendIndex(effective + 1);
      }
    }
    document.addEventListener("keydown", onNavKey);
    return () => document.removeEventListener("keydown", onNavKey);
  }, [active, tabs, sendIndex]);

  useEffect(() => {
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return;
    setRaw(renderRaw(tab.template));
    // Default the response pane to whichever history index the user
    // last clicked; otherwise follow the latest send.
    const idx =
      sendIndex !== null && sendIndex < tab.history.length
        ? sendIndex
        : tab.history.length - 1;
    const pick = idx >= 0 ? tab.history[idx] : null;
    setRespRaw(pick ? renderRawResponse(pick.response, pick.error) : "");
  }, [active, tabs, sendIndex]);

  // Clear burst / diff state when the active tab changes.
  useEffect(() => {
    setSendIndex(null);
    setDiffA(null);
    setDiffB(null);
    setDiffReport(null);
  }, [active]);

  // ðŸŽ¯ R826 ”” 800-streak celebration listener. When the operator
  // right-clicks a URL selection in any MessageEditor + picks
  // "ðŸŽ¯ Open as new Repeater tab", MessageEditor dispatches
  // `burpfree:open-repeater-tab` with `{url}`. This handler
  // creates a fresh tab targeted at that URL + navigates to it.
  useEffect(() => {
    async function onOpen(e: Event) {
      const detail = (e as CustomEvent<{ url: string }>).detail;
      if (!detail?.url) return;
      try {
        const highestNumeric = tabs.reduce((max, t) => {
          const m = /^(\d+)$/.exec((t.name || "").trim());
          return m ? Math.max(max, parseInt(m[1], 10)) : max;
        }, 0);
        const name = `${highestNumeric + 1}`;
        const id = await api.repeaterAddTab(name, detail.url);
        await refresh();
        setActive(id);
      } catch (err) {
        alert(`Open-as-tab failed: ${err}`);
      }
    }
    window.addEventListener(
      "burpfree:open-repeater-tab",
      onOpen as EventListener,
    );
    return () =>
      window.removeEventListener(
        "burpfree:open-repeater-tab",
        onOpen as EventListener,
      );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs]);

  async function addTab() {
    const url = prompt("Target URL (e.g. https://example.com/)", "https://example.com/");
    if (!url) return;
    // R809: Burp-identical default tab naming ”” matches Burp Suite
    // 2026.8's reference screenshot showing just number ("1", "2",
    // "3", "4") as tab labels. Operators can still override with
    // F2 rename. Picks the next number by finding the highest
    // numeric-named tab + incrementing, so renumbering works even
    // after some tabs were closed.
    const highestNumeric = tabs.reduce((max, t) => {
      const m = /^(\d+)$/.exec((t.name || "").trim());
      return m ? Math.max(max, parseInt(m[1], 10)) : max;
    }, 0);
    const defaultName = `${highestNumeric + 1}`;
    const name = prompt("Tab name", defaultName) || defaultName;
    const id = await api.repeaterAddTab(name, url);
    await refresh();
    setActive(id);
  }

  async function send() {
    if (active == null) return;
    if (inflight.has(active)) return; // guard: don't double-send on Enter spam
    markInflight(active, true);
    setBusy(true);
    try {
      const tab = tabs.find((t) => t.id === active);
      if (tab) {
        const edited = parseRaw(raw, tab.template);
        await api.repeaterUpdate(active, edited);
      }
      const resp = await api.repeaterSend(active);
      setRespRaw(renderRawResponse(resp.response, resp.error));
      await refresh();
    } catch (e) {
      // The engine turns cancels into a RepeaterSend row with
      // error = "send cancelled" rather than a Promise reject, so
      // this catch really is for network / IPC errors. We still
      // defensively silence anything that mentions "cancel" so a
      // future transport change doesn't bombard the user with alerts.
      const msg = `${e}`;
      if (!/cancel/i.test(msg)) alert(msg);
    } finally {
      setBusy(false);
      markInflight(active, false);
    }
  }

  /// Cancel any in-flight send for the active tab. The engine's
  /// `cancel()` wakes `notify_waiters()`; the pending `repeaterSend`
  /// resolves with `error = "send cancelled"` which the `send()`
  /// finally-block clears from `inflight`.
  async function cancelActive() {
    if (active == null) return;
    if (!inflight.has(active)) return;
    try {
      await api.repeaterCancel(active);
    } catch (e) {
      console.warn("cancel failed:", e);
    }
  }

  /// Cancel every in-flight send across every tab. The engine's
  /// `cancel_all()` wakes every registered Notify at once; each
  /// pending `repeaterSend` promise resolves with the usual cancel
  /// marker so the per-tab finally-blocks clear their inflight slot.
  /// No local state update needed ”” the Set reconciles via the
  /// natural per-send cleanup.
  async function cancelAll() {
    if (inflight.size === 0) return;
    try {
      await api.repeaterCancelAll();
    } catch (e) {
      console.warn("cancel-all failed:", e);
    }
  }

  /// Cancel the send for a specific tab (from the tab context menu).
  /// Mirrors `cancelActive` but targets `id` directly so operators
  /// can abort a background tab's send without having to activate it
  /// first.
  async function cancelTab(id: number) {
    if (!inflight.has(id)) return;
    try {
      await api.repeaterCancel(id);
    } catch (e) {
      console.warn("cancel failed:", e);
    }
  }

  /// Immutably flip the inflight-set membership for `id` so React
  /// picks up the state change. Called from `send()`'s try/finally
  /// pair so even an abrupt exception still frees the slot.
  function markInflight(id: number, flag: boolean) {
    setInflight((prev) => {
      const next = new Set(prev);
      if (flag) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  // ---- Follow-redirect one-shot ---------------------------------------
  // Peek at the currently-displayed response for a 3xx + Location pair.
  // The banner only appears when both are present; a plain 200 or a 3xx
  // without a Location leaves the UI quiet.
  const redirectInfo = useMemo<{ status: number; location: string } | null>(() => {
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return null;
    const idx =
      sendIndex !== null && sendIndex < tab.history.length
        ? sendIndex
        : tab.history.length - 1;
    const pick = idx >= 0 ? tab.history[idx] : null;
    const resp = pick?.response;
    if (!resp || typeof resp.status !== "number") return null;
    if (resp.status < 300 || resp.status >= 400) return null;
    const items: Array<{ name: string; value: string }> =
      resp.headers?.items ?? [];
    const loc = items.find((h) => h.name?.toLowerCase() === "location")?.value;
    if (!loc) return null;
    return { status: resp.status, location: loc };
  }, [active, tabs, sendIndex]);

  // ---- Burp-style context-menu builders ---------------------------------

  /** Download a text blob with the given filename. Uses the standard
   *  anchor+click trick so no backend file-system API is involved. */
  function downloadText(filename: string, body: string) {
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function activeTabUrl(): string | null {
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return null;
    return buildUrlFromTemplate(tab.template);
  }

  /** Build the request-pane right-click entries. The menu only appears
   *  when a tab is active + the cursor has no selection; each entry
   *  reads the active-tab URL / raw request / method via the panel's
   *  state closure. */
  function buildRequestMenu() {
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return [];
    const url = buildUrlFromTemplate(tab.template);
    const method = (tab.template?.method as string) ?? "GET";
    const items = [
      { label: "Request actions", disabled: true },
      { separator: true as const },
      {
        label: "Send to Intruder",
        hotkey: "Ctrl+I",
        onClick: () => {
          window.dispatchEvent(
            new CustomEvent("burpfree:intruder-load", { detail: { url, method } }),
          );
          window.dispatchEvent(
            new CustomEvent("burpfree:navigate", { detail: { target: "intruder" } }),
          );
        },
      },
      {
        label: "Send to Comparer (request)",
        onClick: () => {
          sendToComparer(raw, "", `${method} ${url}`);
          window.dispatchEvent(
            new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
          );
        },
      },
      {
        label: "Send to Decoder",
        onClick: () => {
          // Decoder has no "load" event bus listener yet; copy to clipboard
          // + navigate so the operator can paste. Easier than plumbing a
          // bus event for a single panel.
          void copyToClipboard(raw);
          window.dispatchEvent(
            new CustomEvent("burpfree:navigate", { detail: { target: "decoder" } }),
          );
        },
      },
      { separator: true as const },
      {
        label: "Copy URL",
        onClick: () => void copyToClipboard(url),
      },
      /* R183: Copy raw request bytes ”” complement to the response-   */
      /* side "Copy response to clipboard" R176 pattern. Operators    */
      /* pasting a reproducer into a ticket want the exact wire       */
      /* bytes they'll fire, not a cURL / fetch reconstruction.       */
      {
        label: "Copy raw request",
        hint: "bytes as shown",
        onClick: () => void copyToClipboard(raw),
      },
      {
        label: "Copy as cURL",
        hint: "with full headers + body",
        onClick: () => {
          const req = fromUrlAndRaw(url, raw);
          void copyToClipboard(buildCurl(req));
        },
      },
      {
        label: "Copy as PowerShell",
        onClick: () => {
          const req = fromUrlAndRaw(url, raw);
          void copyToClipboard(buildPowerShell(req));
        },
      },
      {
        label: "Copy as Python (requests)",
        onClick: () => {
          const req = fromUrlAndRaw(url, raw);
          void copyToClipboard(buildPython(req));
        },
      },
      {
        label: "Copy as fetch()",
        hint: "paste into DevTools console",
        onClick: () => {
          const req = fromUrlAndRaw(url, raw);
          void copyToClipboard(buildFetch(req));
        },
      },
      { separator: true as const },
      {
        label: "Save request to file",
        hint: "download .txt",
        onClick: () => {
          const safe =
            `${method}-${new URL(url).host}${new URL(url).pathname}`
              .replace(/[/?&=:]/g, "-")
              .replace(/-+/g, "-")
              .replace(/^-|-$/g, "")
              .slice(0, 80) || "request";
          downloadText(`${safe}.txt`, raw);
        },
      },
      {
        label: "Paste URL as request",
        hint: "clipboard â†’ new URL",
        onClick: () => void pasteUrlAsRequest(),
      },
    ];
    return items;
  }

  /** Response-pane right-click entries. Response can't be edited so the
   *  menu is a read-only set of "do something with these bytes" shortcuts. */
  function buildResponseMenu() {
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return [];
    const url = buildUrlFromTemplate(tab.template);
    const method = (tab.template?.method as string) ?? "GET";
    const items = [
      { label: "Response actions", disabled: true },
      { separator: true as const },
      {
        label: "Send to Comparer (response)",
        onClick: () => {
          // Send to the right slot so operator can compare two responses
          // side-by-side in one hop by firing this menu twice.
          sendToComparer("", respRaw, `${method} ${url} (response)`);
          window.dispatchEvent(
            new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
          );
        },
      },
      {
        label: "Copy response to clipboard",
        onClick: () => void copyToClipboard(respRaw || ""),
      },
      /* R176: Narrower copy affordances. Operators pasting a Burp    */
      /* finding into a ticket often want just the status line + N    */
      /* interesting headers ”” the full response is too much, the     */
      /* body alone drops the status / content-type context.          */
      {
        label: "Copy status line",
        hint: "e.g. HTTP/1.1 302 Found",
        onClick: () => {
          const line = (respRaw ?? "").split(/\r?\n/)[0] ?? "";
          void copyToClipboard(line);
        },
      },
      {
        label: "Copy headers only",
        hint: "status + header block, no body",
        onClick: () => {
          const r = respRaw ?? "";
          // CRLF-aware split so a Windows-style capture doesn't lose
          // its header boundary. Falls back to the whole response
          // when there's no obvious split.
          const idx = r.search(/\r?\n\r?\n/);
          const head = idx >= 0 ? r.slice(0, idx) : r;
          void copyToClipboard(head);
        },
      },
      {
        label: "Copy body only",
        hint: "no status line, no headers",
        onClick: () => {
          const r = respRaw ?? "";
          const idx = r.search(/\r?\n\r?\n/);
          const body = idx >= 0 ? r.slice(idx).replace(/^\r?\n\r?\n/, "") : r;
          void copyToClipboard(body);
        },
      },
      {
        label: "Save response to file",
        hint: "download .txt",
        onClick: () => {
          const safe =
            `response-${new URL(url).host}${new URL(url).pathname}`
              .replace(/[/?&=:]/g, "-")
              .replace(/-+/g, "-")
              .replace(/^-|-$/g, "")
              .slice(0, 80) || "response";
          downloadText(`${safe}.txt`, respRaw || "");
        },
      },
      {
        label: "Open response in browser",
        hint: "render body via the OS default handler",
        onClick: () => void openResponseInBrowser(url, respRaw || ""),
      },
    ];
    return items;
  }

  /** Save the response bytes to a temp file and ask the OS to open
   *  it with the default handler. Content-type is parsed out of
   *  the first response header block so an HTML response renders,
   *  JSON gets a JSON viewer, etc. The temp file lives in the OS
   *  temp dir; no auto-cleanup ”” mirrors Burp's "Open in browser"
   *  which also leaves a trail for a session. */
  async function openResponseInBrowser(url: string, respRaw: string) {
    if (!respRaw.trim()) {
      alert("Nothing to open ”” the response pane is empty.");
      return;
    }
    // Split the raw response on the first blank line to separate
    // headers from body. Keep CRLF-aware so we don't drop bytes on
    // Windows-style stored responses.
    const idx = respRaw.search(/\r?\n\r?\n/);
    const headerBlock = idx >= 0 ? respRaw.slice(0, idx) : respRaw;
    const body = idx >= 0 ? respRaw.slice(idx).replace(/^\r?\n\r?\n/, "") : "";
    // Pull Content-Type out of the header lines (case-insensitive).
    const ctLine = headerBlock
      .split(/\r?\n/)
      .find((l) => /^content-type\s*:/i.test(l));
    const contentType = ctLine
      ? ctLine.replace(/^content-type\s*:\s*/i, "").trim()
      : "text/html";
    // Derive a stable label from the URL so sibling tabs don't
    // clobber each other's temp files.
    let label: string | undefined;
    try {
      const u = new URL(url);
      label = `${u.host}${u.pathname}`;
    } catch {
      /* leave undefined ”” backend falls back to "response" */
    }
    try {
      const result = await api.responseOpenInBrowser({
        content: body || respRaw,
        contentType,
        label,
      });
      console.log("open-in-browser:", result);
    } catch (e) {
      alert(`Could not open response in browser: ${e}`);
    }
  }

  /** Read a URL from the clipboard and retarget the active tab to it.
   *  Rejects non-http(s) schemes with an alert so the operator doesn't
   *  silently point Repeater at `file://` or similar. */
  async function pasteUrlAsRequest() {
    if (active == null) return;
    try {
      const text = (await navigator.clipboard.readText()).trim();
      if (!text) {
        alert("Clipboard is empty.");
        return;
      }
      if (!/^https?:\/\//i.test(text)) {
        alert("Clipboard doesn't look like an http(s) URL.");
        return;
      }
      await api.repeaterSetUrl(active, text);
      await refresh();
      const next = (await api.repeaterList()).find((t) => t.id === active);
      if (next) setRaw(renderRaw(next.template));
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function followRedirect() {
    if (active == null || !redirectInfo) return;
    setBusy(true);
    try {
      const send = await api.repeaterFollowRedirect(active, redirectInfo.location);
      setRespRaw(renderRawResponse(send.response, send.error));
      await refresh();
      // Jump the history strip to the just-appended entry so the
      // operator sees the follow-up response, not the original redirect.
      const next = (await api.repeaterList()).find((t) => t.id === active);
      if (next) setSendIndex(next.history.length - 1);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function closeTab(id: number) {
    const tab = tabs.find((t) => t.id === id);
    if (tab?.pinned) {
      if (
        !confirm(
          `Close pinned tab "${tab.name}"? Pinning is meant to protect it from accidental closes.`,
        )
      )
        return;
    }
    // R889: Push the tab into the closed-tab history before deleting
    // so operators can reopen it via the + context menu. Capped at
    // 10 entries ”” oldest drops off the front. Template is cloned
    // so later mutations don't retroactively mutate the snapshot.
    if (tab) {
      const snapshot = {
        name: tab.name,
        url: String(tab.template?.url ?? ""),
        method: String(tab.template?.method ?? "GET"),
        template: tab.template ? structuredClone(tab.template) : null,
        comment: tab.comment ?? null,
        group: tab.group ?? null,
        color: tab.color ?? null,
      };
      setClosedTabHistory((prev) => {
        const next = [...prev, snapshot];
        return next.length > 10 ? next.slice(next.length - 10) : next;
      });
    }
    await api.repeaterRemove(id);
    if (active === id) setActive(null);
    await refresh();
  }

  // R889: Reopen the most-recently-closed tab from `closedTabHistory`.
  // Pops the top (newest) entry, creates a new tab with the same
  // template + metadata. If the history is empty, no-op.
  async function reopenLastClosedTab() {
    if (closedTabHistory.length === 0) return;
    const snapshot = closedTabHistory[closedTabHistory.length - 1];
    setClosedTabHistory((prev) => prev.slice(0, prev.length - 1));
    try {
      const url = snapshot.url || "https://example.com/";
      const id = await api.repeaterAddTab(snapshot.name, url, snapshot.method);
      if (snapshot.template) {
        try {
          await api.repeaterUpdate(id, snapshot.template);
        } catch {
          // template update failed ”” the tab still exists with the
          // base URL, so we don't fail the whole reopen.
        }
      }
      if (snapshot.comment) {
        try {
          await api.repeaterSetComment(id, snapshot.comment);
        } catch {
          /* ignore */
        }
      }
      if (snapshot.group) {
        try {
          await api.repeaterSetGroup(id, snapshot.group);
        } catch {
          /* ignore */
        }
      }
      await refresh();
      setActive(id);
    } catch (e) {
      alert(`Reopen failed: ${e}`);
    }
  }

  // R889: Create an empty tab group. Burp Suite 2026.8's + context
  // menu "New tab group" prompts for a name, then subsequent tabs
  // can be added to it. Our group model requires at least one tab
  // (groups are implicit via tab.group); we honor this by creating
  // a placeholder tab in the group named "(group placeholder)" that
  // the operator can rename or delete after adding real tabs.
  async function newTabGroup() {
    const name = prompt(
      "New tab group name:",
      `group-${new Date().toISOString().slice(5, 16).replace(/[-:T]/g, "")}`,
    );
    if (!name || !name.trim()) return;
    const groupName = name.trim();
    try {
      // Create a placeholder tab that holds the group open.
      const id = await api.repeaterAddTab(
        `(${groupName} placeholder)`,
        "https://example.com/",
      );
      await api.repeaterSetGroup(id, groupName);
      await refresh();
      setActive(id);
      alert(
        `Group "${groupName}" created with a placeholder tab. Add real tabs via right-click â†’ Move to group, or rename the placeholder once you have your first request.`,
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  /** Prompt for a free-form comment on a tab, call set_comment on
   *  the backend, refresh. Empty / cancelled prompt is a no-op; the
   *  operator passing an empty string explicitly (OK on an empty
   *  prompt box) clears the comment. */
  async function editComment(tab: RepeaterTab) {
    const next = prompt(
      `Comment for "${tab.name}"\n\nEmpty + OK clears. Cancel keeps the current comment.`,
      tab.comment ?? "",
    );
    if (next === null) return; // Cancel
    try {
      await api.repeaterSetComment(tab.id, next);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  /** Pin or unpin every member of a group in parallel. Follows the
   *  same Promise.allSettled pattern as R94 sendPinnedTabs so one
   *  failed call doesn't strand the rest. Refreshes at the end so
   *  the chip glyphs catch up atomically. */
  async function pinAllInGroup(group: string, pinned: boolean) {
    const members = tabs.filter((t) => t.group === group);
    const victims = members.filter((t) => t.pinned !== pinned);
    if (victims.length === 0) return;
    try {
      await Promise.allSettled(
        victims.map((t) => api.repeaterSetPinned(t.id, pinned)),
      );
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  /** Toggle a tab's pinned flag. Pinned tabs skip bulk-close
   *  sweeps and render a ðŸ“Œ glyph. */
  async function togglePinned(id: number, pinned: boolean) {
    try {
      await api.repeaterSetPinned(id, pinned);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  // ------- Group operations ---------------------------------------------
  // Assign a tab to a group (or clear it with `null`). After the
  // round-trip we auto-expand the destination group so the operator
  // can see where their tab landed.
  async function addToGroup(id: number, group: string | null) {
    const normalized = group ? group.trim() : null;
    await api.repeaterSetGroup(id, normalized && normalized.length ? normalized : null);
    if (normalized) {
      setGroupCollapsed((prev) => ({ ...prev, [normalized]: false }));
    }
    await refresh();
  }

  // Prompt for a new group name, then move `id` into it. Operator
  // can hit Cancel for a no-op.
  async function addToNewGroup(id: number) {
    const name = prompt("New group name:", "");
    if (name == null) return;
    const trimmed = name.trim();
    if (!trimmed) return;
    await addToGroup(id, trimmed);
  }

  // Rename every member of `old` to `next`. Blank clears the group
  // on the whole swarm, matching the backend's rename_group.
  async function renameGroup(old: string) {
    const next = prompt(`Rename group "${old}" to:`, old);
    if (next == null) return;
    const trimmed = next.trim();
    if (trimmed === old) return;
    const moved = await api.repeaterRenameGroup(old, trimmed);
    if (!moved) return;
    // Transfer the collapse flag onto the new name.
    setGroupCollapsed((prev) => {
      const copy = { ...prev };
      if (trimmed) copy[trimmed] = copy[old] ?? false;
      delete copy[old];
      return copy;
    });
    await refresh();
  }

  // Clear the group on every member ”” tabs survive. Confirmation
  // because this touches multiple tabs' metadata at once.
  async function deleteGroup(group: string) {
    const members = tabs.filter((t) => t.group === group).length;
    if (
      !confirm(
        `Ungroup ${members} tab${members === 1 ? "" : "s"} currently in "${group}"? Tabs are not deleted.`,
      )
    )
      return;
    await api.repeaterDeleteGroup(group);
    setGroupCollapsed((prev) => {
      const copy = { ...prev };
      delete copy[group];
      return copy;
    });
    await refresh();
  }

  // ------- Reorder operations ------------------------------------------
  // Compute the new order of tab ids with `sourceId` moved to the
  // position before (or after) `targetId`. Operates on the CURRENT
  // tabs array in display order. Returns null when the result is
  // unchanged (dragging a tab onto itself).
  function computeReorder(
    sourceId: number,
    targetId: number,
    side: "before" | "after",
  ): number[] | null {
    if (sourceId === targetId) return null;
    const ids = tabs.map((t) => t.id);
    const sourceIdx = ids.indexOf(sourceId);
    if (sourceIdx < 0) return null;
    // Pull source out, then splice in at the target index.
    ids.splice(sourceIdx, 1);
    let targetIdx = ids.indexOf(targetId);
    if (targetIdx < 0) return null;
    if (side === "after") targetIdx += 1;
    ids.splice(targetIdx, 0, sourceId);
    return ids;
  }

  // Commit a reorder to the backend and refresh. Scoped so a drop
  // between groups does nothing if the two tabs aren't in the same
  // section ”” Burp keeps grouping intent sacrosanct, so should we.
  // R834: Ctrl+Shift+PageUp / PageDown ”” Burp-identical tab-reorder
  // shortcut. Moves the active tab one position left/right within
  // its section (ungrouped or current group). Mirrors Burp Suite
  // 2026.8's canonical tab-reorder bindings + matches common
  // browser muscle memory (Chrome/Firefox use the same keys for
  // tab reorder).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.ctrlKey && !e.metaKey) return;
      if (!e.shiftKey) return;
      if (e.key !== "PageUp" && e.key !== "PageDown") return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (
          tag === "INPUT" ||
          tag === "SELECT" ||
          el.isContentEditable
        ) {
          return;
        }
      }
      if (active == null) return;
      e.preventDefault();
      void nudgeActiveTab(e.key === "PageUp" ? "left" : "right");
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, tabs]);

  async function commitReorder(sourceId: number, targetId: number, side: "before" | "after") {
    const source = tabs.find((t) => t.id === sourceId);
    const target = tabs.find((t) => t.id === targetId);
    if (!source || !target) return;
    // Reject cross-section drops ”” adding to / removing from a group
    // happens via the context menu, not drag.
    if ((source.group ?? null) !== (target.group ?? null)) return;
    const next = computeReorder(sourceId, targetId, side);
    if (!next) return;
    await api.repeaterReorder(next);
    await refresh();
  }

  // Alt+Left / Alt+Right nudges the active tab one slot. Scoped to
  // the active tab's section (ungrouped or a given group) so a nudge
  // never silently pulls a tab out of its group.
  async function nudgeActiveTab(dir: "left" | "right") {
    if (active == null) return;
    const cur = tabs.find((t) => t.id === active);
    if (!cur) return;
    const section = tabs.filter((t) => (t.group ?? null) === (cur.group ?? null));
    const idx = section.findIndex((t) => t.id === active);
    const newIdx = dir === "left" ? idx - 1 : idx + 1;
    if (newIdx < 0 || newIdx >= section.length) return;
    const neighbour = section[newIdx];
    await commitReorder(active, neighbour.id, dir === "left" ? "before" : "after");
  }

  // Fire every tab in `group` sequentially or in parallel. Auto-
  // expand the group afterwards and surface a terse completion
  // summary in an alert so the operator knows what landed.
  async function sendGroup(group: string, mode: "sequential" | "parallel") {
    setBusy(true);
    try {
      const results = await api.repeaterSendGroup(group, mode);
      setGroupCollapsed((prev) => ({ ...prev, [group]: false }));
      await refresh();
      const ok = results.filter((r: any) => r.response && !r.error).length;
      const bad = results.length - ok;
      alert(
        `Group "${group}" sent ${mode}: ${ok} ok, ${bad} failed (of ${results.length}).`,
      );
    } catch (e) {
      alert(`Send group failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  /** Close every tab except the one with id `keepId`. Called from
   *  the tab context menu's "Close other tabs" entry. Needs a
   *  snapshot so we don't walk a shrinking array. Pinned tabs are
   *  preserved so the pin promise holds. */
  async function closeOtherTabs(keepId: number) {
    const victims = tabs
      .filter((t) => t.id !== keepId && !t.pinned)
      .map((t) => t.id);
    if (victims.length === 0) return;
    const pinnedKept = tabs.filter((t) => t.id !== keepId && t.pinned).length;
    const extra =
      pinnedKept > 0
        ? ` (${pinnedKept} pinned tab${pinnedKept === 1 ? "" : "s"} kept)`
        : "";
    if (
      !confirm(
        `Close ${victims.length} other tab${victims.length === 1 ? "" : "s"}${extra}?`,
      )
    )
      return;
    for (const id of victims) {
      try {
        await api.repeaterRemove(id);
      } catch (e) {
        console.warn("repeaterRemove failed for", id, e);
      }
    }
    setActive(keepId);
    await refresh();
  }

  /** Close every tab appearing after `pivotId` in the current tab
   *  order. Mirrors browser "Close tabs to the right". Pinned tabs
   *  are preserved so the pin promise holds. */
  async function closeTabsToRight(pivotId: number) {
    const pivot = tabs.findIndex((t) => t.id === pivotId);
    if (pivot < 0) return;
    const rightSlice = tabs.slice(pivot + 1);
    const victims = rightSlice.filter((t) => !t.pinned).map((t) => t.id);
    if (victims.length === 0) return;
    const pinnedKept = rightSlice.filter((t) => t.pinned).length;
    const extra =
      pinnedKept > 0
        ? ` (${pinnedKept} pinned tab${pinnedKept === 1 ? "" : "s"} kept)`
        : "";
    if (
      !confirm(
        `Close ${victims.length} tab${victims.length === 1 ? "" : "s"} to the right${extra}?`,
      )
    )
      return;
    for (const id of victims) {
      try {
        await api.repeaterRemove(id);
      } catch (e) {
        console.warn("repeaterRemove failed for", id, e);
      }
    }
    if (active != null && victims.includes(active)) setActive(pivotId);
    await refresh();
  }

  async function duplicateTab(src: RepeaterTab) {
    try {
      // Use the backend `repeater_duplicate_tab` cmd so colour,
      // follow-redirects policy, comment, *and* the full header +
      // body of the template survive the clone. The frontend-only
      // AddTab path we used before only preserved the URL.
      const newId = await api.repeaterDuplicateTab(src.id);
      await refresh();
      setActive(newId);
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function clearTabHistory(id: number) {
    try {
      const existed = await api.repeaterTabClearHistory(id);
      if (!existed) {
        // Tab vanished between the UI showing it and the click; ignore.
        return;
      }
      await refresh();
      // The response pane follows `sendIndex` ”” a cleared history
      // leaves nothing to show, so reset the selector and blank the
      // raw-response view if the cleared tab is active.
      if (active === id) {
        setSendIndex(null);
        setRespRaw("");
        setDiffA(null);
        setDiffB(null);
        setDiffReport(null);
      }
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function copyRequestWire(src: RepeaterTab) {
    try {
      await navigator.clipboard.writeText(renderRaw(src.template));
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function copyLastResponse(src: RepeaterTab) {
    const last = src.history[src.history.length - 1];
    if (!last) return;
    try {
      await navigator.clipboard.writeText(renderRawResponse(last.response, last.error));
    } catch (e) {
      alert(`${e}`);
    }
  }

  /*  R170: F2 keyboard shortcut ”” mirrors browser / IDE rename
   *  convention. Fires `setRenaming({ id, name })` on the active
   *  tab, which lights up the inline input (same path the context
   *  menu's "Rename…" entry + the tab's own double-click fire).
   *  Guards: active != null, no text-input focus (so F2 inside
   *  the message editor doesn't collide), no modifier keys. */
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "F2") return;
      if (e.ctrlKey || e.altKey || e.shiftKey || e.metaKey) return;
      if (active == null) return;
      // If already renaming, let the F2-inside-the-input case fall
      // through to the browser's default (nothing) ”” operators
      // pressing F2 in the rename input probably hit it twice.
      if (renaming) return;
      const el = document.activeElement as HTMLElement | null;
      if (el) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        if (el.isContentEditable) return;
      }
      const tab = tabs.find((t) => t.id === active);
      if (!tab) return;
      e.preventDefault();
      setRenaming({ id: tab.id, name: tab.name });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active, tabs, renaming]);

  async function commitRename() {
    if (!renaming) return;
    const next = renaming.name.trim();
    const target = renaming.id;
    setRenaming(null);
    if (!next) return;
    try {
      await api.repeaterRename(target, next);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function setColor(tabId: number, color: string | null) {
    try {
      await api.repeaterSetColor(tabId, color);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function changeMethod(tabId: number, method: string) {
    try {
      await api.repeaterChangeMethod(tabId, method);
      await refresh();
      // Refresh the editor pane to show the new method on the request line.
      const tab = (await api.repeaterList()).find((t) => t.id === tabId);
      if (tab) setRaw(renderRaw(tab.template));
    } catch (e) {
      alert(`${e}`);
    }
  }

  /// Pop the request editor back to a past send's bytes. The operator
  /// is viewing send #idx in the Sends strip; this writes that send's
  /// `request` back onto the tab's template so the request editor
  /// shows those bytes again. A fresh Send after this appends a new
  /// row at the end of history ”” nothing in the past is destroyed.
  /// Mirrors Burp's "Edit this request" / revert pathway. Guarded on
  /// active == null and on idx out of range so a stale callback can't
  /// corrupt the template.
  async function revertToSend(idx: number) {
    if (active == null) return;
    const tab = tabs.find((t) => t.id === active);
    if (!tab) return;
    if (idx < 0 || idx >= tab.history.length) return;
    const past = tab.history[idx];
    if (!past || !past.request) return;
    try {
      await api.repeaterUpdate(active, past.request);
      await refresh();
      // Pop the raw-editor view to the past bytes too ”” the useEffect
      // above would do this on the next tabs refresh, but we want it
      // immediate so the operator sees the revert land without lag.
      setRaw(renderRaw(past.request));
    } catch (e) {
      alert(`Revert failed: ${e}`);
    }
  }

  /// Fire every pinned tab in parallel. Burp doesn't have an exact
  /// equivalent ”” the closest is "Send selected tabs" with Ctrl-click
  /// multi-select. We piggy-back on the pin promise instead: the
  /// operator curates a working set of tabs they want to re-fire on
  /// demand (login + the authenticated probe + the audit canary),
  /// pins them, and one click re-fires the whole batch. Parallel
  /// sends via Promise.allSettled so a single failing tab doesn't
  /// strand the others. Refreshes once at the end so the Sends chip
  /// strips + N/M counters catch up atomically.
  async function sendPinnedTabs() {
    const pinned = tabs.filter((t) => t.pinned);
    if (pinned.length === 0) return;
    const ids = pinned.map((t) => t.id);
    // Mark each pinned tab inflight up front so the per-tab Cancel
    // buttons highlight immediately ”” otherwise the state only
    // transitions in `send()` which this bulk path bypasses.
    setInflight((prev) => {
      const next = new Set(prev);
      for (const id of ids) next.add(id);
      return next;
    });
    try {
      const results = await Promise.allSettled(
        ids.map((id) => api.repeaterSend(id)),
      );
      await refresh();
      const ok = results.filter((r) => r.status === "fulfilled").length;
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) {
        const firstErr = results.find(
          (r): r is PromiseRejectedResult => r.status === "rejected",
        );
        alert(
          `Fire pinned: ${ok} / ${ids.length} succeeded, ${failed} failed. First error: ${firstErr?.reason}`,
        );
      }
    } finally {
      setInflight((prev) => {
        const next = new Set(prev);
        for (const id of ids) next.delete(id);
        return next;
      });
    }
  }

  async function burstSend() {
    if (active == null) return;
    const countStr = prompt("How many sends? (max 500)", "10");
    if (!countStr) return;
    const count = parseInt(countStr, 10);
    if (!Number.isFinite(count) || count < 1) {
      alert("Invalid count.");
      return;
    }
    const gapStr = prompt("Gap between sends (ms, 0—60000)", "0") || "0";
    const gap = Math.max(0, Math.min(60_000, parseInt(gapStr, 10) || 0));
    const tab = tabs.find((t) => t.id === active);
    if (tab) {
      try {
        const edited = parseRaw(raw, tab.template);
        await api.repeaterUpdate(active, edited);
      } catch (e) {
        alert(`${e}`);
        return;
      }
    }
    setBursting(true);
    try {
      await api.repeaterBurstSend(active, count, gap);
      await refresh();
      // Jump the response viewer to the last of the burst sends.
      const latest = (await api.repeaterList()).find((t) => t.id === active);
      if (latest) setSendIndex(latest.history.length - 1);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setBursting(false);
    }
  }

  async function runDiff(tabId: number, a: number, b: number) {
    const tab = (await api.repeaterList()).find((t) => t.id === tabId);
    if (!tab) return;
    const left = tab.history[a];
    const right = tab.history[b];
    if (!left || !right) return;
    const leftText = renderRawResponse(left.response, left.error);
    const rightText = renderRawResponse(right.response, right.error);
    try {
      const report = await api.comparerDiff(leftText, rightText, false);
      setDiffReport(report);
    } catch (e) {
      alert(`${e}`);
    }
  }

  // Render one tab chip. Pulled into a helper so the grouped layout
  // below doesn't duplicate 60 lines of JSX for each section.
  const renderTabChip = (t: RepeaterTab) => {
    // Drop indicator visuals: hovered tab in the current drag gets a
    // bright left-edge accent (`before` side) or right-edge accent
    // (`after` side). Null drag state clears all indicators.
    const dropIndicator =
      dragState && dragState.target === t.id
        ? dragState.side === "before"
          ? "2px solid var(--accent)"
          : undefined
        : undefined;
    const dropIndicatorAfter =
      dragState && dragState.target === t.id && dragState.side === "after"
        ? "2px solid var(--accent)"
        : undefined;
    // Auto status indicator based on the tab's last send. Null when
    // the tab has never been sent so the chip stays uncluttered.
    const statusHint = tabStatusGlyph(t);
    const isActive = active === t.id;
    const isRenaming = renaming?.id === t.id;
    // R772: Live-request pulse indicator ”” tracks whether this
    // specific tab has an in-flight send. Mirrors Burp Suite's
    // tab chip which pulses the status dot while a probe is on
    // the wire. Uses the existing `inflight: Set<number>` state.
    const tabInflight = inflight.has(t.id);
    // R764: Tab-filter visibility gate ”” hide tabs whose name AND
    // URL don't contain the filter substring. Active tab is always
    // visible so operators don't lose their current context.
    if (tabFilterText && !isActive) {
      const url = buildUrlFromTemplate(t.template).toLowerCase();
      const name = (t.name || "").toLowerCase();
      if (!name.includes(tabFilterText) && !url.includes(tabFilterText)) {
        return null;
      }
    }
    return (
    <div
      key={t.id}
      className={`rep-tab${isActive ? " active" : ""}${
        // R805: Burp-identical "unsaved edits" edge indicator ””
        // when the active tab's raw differs from its saved template,
        // show a thin left-edge accent border signalling "operator
        // has pending edits not yet saved to backend template" so
        // tab-switch doesn't catch them by surprise. Only applies
        // to the active tab since we only know the live `raw` state
        // for it. Other tabs show the saved template so no edge.
        isActive && raw.trim() !== renderRaw(t.template).trim()
          ? " rep-tab-dirty"
          : ""
      }`}
      draggable={!isRenaming}
      title={(() => {
        // R743+R771: Burp-identical rich tab tooltip. Format
        // matches Burp's Repeater which shows "METHOD URL\n
        // Status · N sends · last fired · comment" on hover.
        // R771 adds the "last fired" relative-time line so
        // operators quickly see how recent each tab's probe is.
        const method = (t.template?.method as string) ?? "GET";
        const url = buildUrlFromTemplate(t.template);
        const parts: string[] = [`${method} ${url}`];
        if (statusHint?.tooltip) parts.push(statusHint.tooltip);
        if (t.history.length > 0) {
          parts.push(
            `${t.history.length} send${t.history.length === 1 ? "" : "s"}`,
          );
          // R771: Relative-time formatter for "last fired X ago".
          // The last send's ts_ms sits on the newest history entry.
          const lastSend = t.history[t.history.length - 1];
          const ts = (lastSend as any)?.ts_ms;
          if (typeof ts === "number" && ts > 0) {
            const ageMs = Math.max(0, Date.now() - ts);
            const ageStr =
              ageMs < 60_000
                ? `${Math.round(ageMs / 1000)}s`
                : ageMs < 3_600_000
                  ? `${Math.round(ageMs / 60_000)}m`
                  : ageMs < 86_400_000
                    ? `${(ageMs / 3_600_000).toFixed(1)}h`
                    : `${(ageMs / 86_400_000).toFixed(1)}d`;
            parts.push(`last fired ${ageStr} ago`);
          }
        }
        if (t.pinned) parts.push("ðŸ“Œ pinned");
        if (t.group) parts.push(`group: ${t.group}`);
        if (t.comment) parts.push(`ðŸ’¬ ${t.comment}`);
        return parts.join("\n");
      })()}
      style={{
        cursor: dragState?.source === t.id ? "grabbing" : "grab",
        opacity: dragState?.source === t.id ? 0.5 : 1,
        borderLeft: dropIndicator,
        borderRight: dropIndicatorAfter ?? undefined,
      }}
      onDragStart={(e) => {
        e.dataTransfer.setData("text/plain", String(t.id));
        e.dataTransfer.effectAllowed = "move";
        setDragState({ source: t.id, target: t.id, side: "before" });
      }}
      onDragOver={(e) => {
        if (!dragState) return;
        // Only accept drops within the same section (ungrouped vs
        // the same group). `commitReorder` enforces the same rule
        // but shortcutting here keeps the UI honest.
        const source = tabs.find((tt) => tt.id === dragState.source);
        if (!source || (source.group ?? null) !== (t.group ?? null)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
        const side: "before" | "after" =
          e.clientX < rect.left + rect.width / 2 ? "before" : "after";
        if (
          dragState.target !== t.id ||
          dragState.side !== side ||
          dragState.source !== source.id
        ) {
          setDragState({ source: source.id, target: t.id, side });
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        const src = Number(e.dataTransfer.getData("text/plain"));
        if (dragState && src === dragState.source) {
          void commitReorder(dragState.source, dragState.target, dragState.side);
        }
        setDragState(null);
      }}
      onDragEnd={() => setDragState(null)}
      onClick={() => setActive(t.id)}
      onDoubleClick={(e) => {
        e.stopPropagation();
        setRenaming({ id: t.id, name: t.name });
      }}
      onAuxClick={(e) => {
        // R856: Middle-click to close tab ”” Burp 2026.8 and every
        // modern browser bind this. e.button === 1 is the middle
        // mouse button. Pinned tabs are handled inside `closeTab`
        // (confirm gate ”” pin owners are protected per R27). Right
        // button is handled by `onContextMenu` separately; this
        // branch fires only on middle click to avoid stomping on
        // right-click â†’ menu. `e.preventDefault()` suppresses the
        // browser's native autoscroll affordance.
        if (e.button !== 1) return;
        e.preventDefault();
        e.stopPropagation();
        void closeTab(t.id);
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        setActive(t.id);
        setTabMenu({ x: e.clientX, y: e.clientY, data: t });
      }}
    >
      {!compactTabs && t.comment && (
        <span
          className="rep-tab-comment"
          aria-label="has comment"
          title={t.comment}
          style={{
            fontSize: 10,
            marginRight: 2,
            opacity: 0.8,
            cursor: "help",
          }}
        >
          ðŸ’¬
        </span>
      )}
      {!compactTabs && t.pinned && (
        <span
          className="rep-tab-pin"
          aria-label="pinned"
          title="Pinned ”” right-click to unpin"
        >
          âš²
        </span>
      )}
      {!compactTabs && t.color && (
        <span
          className="rep-tab-color"
          aria-label="tab colour"
          style={{ background: t.color }}
        />
      )}
      {isRenaming ? (
        <input
          autoFocus
          value={renaming!.name}
          onChange={(e) => setRenaming({ id: t.id, name: e.target.value })}
          onBlur={commitRename}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void commitRename();
            } else if (e.key === "Escape") {
              e.preventDefault();
              setRenaming(null);
            }
          }}
          onClick={(e) => e.stopPropagation()}
          style={{
            flex: 1,
            minWidth: 60,
            padding: "0 2px",
            fontSize: 11.5,
            background: "transparent",
            border: "1px solid var(--accent)",
            color: "var(--text)",
            outline: "none",
          }}
        />
      ) : (
        <span className="rep-tab-label">
          {/* R253: Dim method prefix on the tab chip so operators */}
          {/* juggling 10 tabs on the same URL can tell GET from   */}
          {/* POST from DELETE at a glance. R254 adds a destruct- */}
          {/* iveness-tinted colour per verb ”” same palette as R210*/}
          {/* Dashboard method card so operators get consistent    */}
          {/* colour semantics (GET=green safe, DELETE=red         */}
          {/* destructive, etc.). R750: hidden in compact mode. */}
          {!compactTabs && t.template?.method && (
            <span
              style={{
                color: (() => {
                  const m = t.template?.method?.toUpperCase() || "";
                  if (m === "GET") return "var(--green, #4caf50)";
                  if (m === "POST") return "var(--accent)";
                  if (m === "PUT" || m === "PATCH") return "var(--amber)";
                  if (m === "DELETE") return "var(--red)";
                  return "var(--text-dim)";
                })(),
                fontSize: 10,
                marginRight: 3,
                fontWeight: 600,
                fontFamily: "var(--font-mono)",
              }}
            >
              {t.template.method}
            </span>
          )}
          {t.name}
        </span>
      )}
      {tabInflight && (
        /* R772: Pulsing live-request indicator ”” supersedes the
           static statusHint when the tab is mid-flight. */
        <span
          className="rep-tab-inflight"
          aria-label="request in flight"
          title="Request in flight ”” Ctrl+Backspace cancels"
        >
          â—
        </span>
      )}
      {!tabInflight && statusHint && (
        <span
          className="rep-tab-status"
          aria-label="last-send status"
          style={{ color: statusHint.color }}
        >
          â—
        </span>
      )}
      {/* R807: Burp-identical "AI insight" âœ¦ indicator ”” shows
          when this tab's Notes contain the R802 Burp AI chat
          header. Operators scanning their tab bar instantly see
          which tabs have AI analysis saved + can click to jump
          into the Inspector â†’ Notes section to read it. Hidden
          in compact mode to keep the chip minimal. */}
      {!compactTabs &&
        !!t.comment &&
        /--- Burp AI chat ·/.test(t.comment) && (
          <span
            className="rep-tab-ai"
            aria-label="AI insight saved"
            title="This tab has Burp AI chat saved to Notes. Open Inspector â†’ Notes to read."
          >
            âœ¦
          </span>
        )}
      {/* ðŸŽ¯ R810 ”” 28th round-number milestone this chunk. Burp-
          identical response-time sparkline on tab chips with â‰¥3
          sends. Encodes the elapsed-ms trend across the last 8
          sends as a 4-char Unicode block-element sparkline
          (`â–â–‚â–ƒâ–„â–…â–†â–‡â–ˆ`). Operators juggling 10+ tabs instantly see
          "this one's getting slower" without opening history.
          Hidden in compact mode. Only renders when â‰¥3 sends so
          2-send tabs don't display a near-useless 1-char
          sparkline. */}
      {!compactTabs && !isRenaming && t.history.length >= 3 && (
        <span
          className="rep-tab-sparkline"
          title={(() => {
            const last8 = t.history.slice(-8);
            const times = last8
              .map((h) => h.elapsed_ms ?? 0)
              .filter((n) => n > 0);
            if (times.length === 0) return "";
            const min = Math.min(...times);
            const max = Math.max(...times);
            return `Response-time trend (last ${times.length} send${times.length === 1 ? "" : "s"}): min ${min}ms · max ${max}ms`;
          })()}
        >
          {(() => {
            const last8 = t.history.slice(-8);
            const times = last8
              .map((h) => h.elapsed_ms ?? 0)
              .filter((n) => n > 0);
            if (times.length === 0) return "";
            const min = Math.min(...times);
            const max = Math.max(...times);
            const chars = ["â–", "â–‚", "â–ƒ", "â–„", "â–…", "â–†", "â–‡", "â–ˆ"];
            // Rendering 4-char sparkline ”” pick last 4 samples (or
            // use full window if <=4) + bucket into 8 levels.
            const samples = times.slice(-4);
            const span = Math.max(1, max - min);
            return samples
              .map((t) => {
                const idx = Math.min(
                  7,
                  Math.max(0, Math.floor(((t - min) / span) * 7)),
                );
                return chars[idx];
              })
              .join("");
          })()}
        </span>
      )}
      {!compactTabs && !isRenaming && t.history.length > 0 && (
        /* R226: Response-count badge next to the status dot. Shows */
        /* how many sends this tab has recorded ”” useful signal for */
        /* operators iterating on a request chain + wondering "did  */
        /* my Ctrl+Enter land?" without having to switch to the     */
        /* response pane. Only renders when > 0 so a blank tab      */
        /* stays visually minimal. Styled dim so the badge doesn't  */
        /* compete with the tab label or the status dot.            */
        <span
          aria-label="response count"
          title={`${t.history.length} response${t.history.length === 1 ? "" : "s"} recorded in this tab`}
          style={{
            fontSize: 9,
            color: "var(--text-dim)",
            marginLeft: 1,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {t.history.length}
        </span>
      )}
      {!isRenaming && (
        // R769: Burp-identical close Ã— button. Active tab shows
        // the Ã— always + full-brightness; inactive tabs show it
        // smaller + dimmer so the tab-bar silhouette stays
        // clean. Hover brightens to red-tinted for destructive
        // affordance. className-based styling for better
        // precedence than inline so the dim-on-inactive wins
        // over the hover.
        <span
          className={`rep-tab-close${isActive ? " rep-tab-close-active" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            closeTab(t.id);
          }}
          title="Close tab"
        >
          Ã—
        </span>
      )}
    </div>
    );
  };

  // Visual layout: ungrouped tabs first, then one chip-and-tabs
  // cluster per group. The chip toggles collapse; the chip's
  // context menu holds the Send-all / Rename / Delete actions.
  const ungroupedTabs = tabs.filter((t) => !t.group);
  const orderedGroups = (() => {
    const seen = new Set<string>();
    const out: string[] = [];
    // Preserve the order the groups first appear in the BTreeMap so
    // the UI doesn't shuffle when a tab is renamed. Dedup via `seen`.
    for (const t of tabs) {
      if (t.group && !seen.has(t.group)) {
        seen.add(t.group);
        out.push(t.group);
      }
    }
    return out;
  })();

  return (
    <div className="panel">
      <div
        className="rep-tabs"
        onWheel={(e) => {
          // R886: Burp-identical mouse-wheel horizontal scroll on
          // the tab bar. Chrome / Firefox / Edge don't natively
          // translate vertical wheel scrolls to `scrollLeft` on
          // `overflow-x: auto` containers; operators with many
          // tabs want wheel-to-scroll like every other IDE tab
          // bar (VS Code, IntelliJ, Chrome tabs). Mapping both
          // deltaY and deltaX so touchpad horizontal swipes also
          // work. Only intercepts when there's actual overflow.
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
        {ungroupedTabs.map(renderTabChip)}
        {orderedGroups.map((g) => {
          const members = tabs.filter((t) => t.group === g);
          const collapsed = groupCollapsed[g] ?? false;
          return (
            <div key={`group-${g}`} style={{ display: "contents" }}>
              <div
                className="rep-group"
                title={`Group: ${g} (${members.length} tab${members.length === 1 ? "" : "s"}) ”” click to ${collapsed ? "expand" : "collapse"}, right-click for actions`}
                onClick={() =>
                  setGroupCollapsed((prev) => ({ ...prev, [g]: !collapsed }))
                }
                onContextMenu={(e) => {
                  e.preventDefault();
                  setGroupMenu({ x: e.clientX, y: e.clientY, data: g });
                }}
              >
                <span className="rep-group-chevron">
                  {collapsed ? "â–¸" : "â–¾"}
                </span>
                <span>{g}</span>
                <span className="rep-group-count">({members.length})</span>
              </div>
              {!collapsed && members.map(renderTabChip)}
            </div>
          );
        })}
        {/* R764: Burp-identical tab-search box on the far right
            of the tab bar. The reference screenshot shows a ðŸ”
            icon with a dropdown arrow at the top-right of the
            tab strip (way past the "+" button). Operators
            juggling 20+ tabs filter by name without pivoting to
            the Target panel. The input is a thin inline search
            that filters tab visibility by substring match. */}
        <div
          className="rep-add"
          onClick={addTab}
          onContextMenu={(e) => {
            // R889: Right-click opens the Burp-identical + context
            // menu with New HTTP tab / New tab group / Close all /
            // Reopen closed tab. Left-click still fires the quick
            // addTab() so muscle memory is preserved.
            e.preventDefault();
            setAddMenu({ x: e.clientX, y: e.clientY, data: null });
          }}
          title={(() => {
            // R881: Richer tooltip surfaces "N tabs · M pinned ·
            // K sends total" so operators see workspace scale at
            // a glance when hovering the "+" button. Zero new
            // state ”” reduces over existing `tabs` array.
            // R889: Appended "right-click for more options" hint
            // so operators discover the context menu.
            const n = tabs.length;
            const pinned = tabs.filter((t) => t.pinned).length;
            const sends = tabs.reduce(
              (acc, t) => acc + (t.history?.length ?? 0),
              0,
            );
            const base =
              n === 0
                ? "Add a new Repeater tab"
                : `Add a new Repeater tab · workspace: ${n} tab${n === 1 ? "" : "s"}${pinned > 0 ? ` (${pinned} pinned)` : ""}${sends > 0 ? ` · ${sends} send${sends === 1 ? "" : "s"} total` : ""}`;
            return `${base} · right-click for more (New tab group / Close all / Reopen closed)`;
          })()}
        >
          +
        </div>
        {/* R236: Dim-text count badge after the + add button so    */}
        {/* operators get an at-a-glance tab count without eyeballing*/}
        {/* the whole bar. Hidden when 0 tabs (empty state already  */}
        {/* communicates that visually). Pinned-count sub-badge      */}
        {/* when there are pinned tabs ”” "N tabs · M pinned".        */}
        {tabs.length > 0 && (
          <span
            style={{
              marginLeft: 6,
              fontSize: 10.5,
              color: "var(--text-dim)",
              alignSelf: "center",
              whiteSpace: "nowrap",
            }}
            title={
              tabs.filter((t) => t.pinned).length > 0
                ? `${tabs.length} tab${tabs.length === 1 ? "" : "s"} total ”” ${tabs.filter((t) => t.pinned).length} pinned`
                : `${tabs.length} tab${tabs.length === 1 ? "" : "s"}`
            }
          >
            {tabs.length} tab{tabs.length === 1 ? "" : "s"}
            {tabs.filter((t) => t.pinned).length > 0 && (
              <> · {tabs.filter((t) => t.pinned).length}ðŸ“Œ</>
            )}
          </span>
        )}
        <span style={{ flex: 1 }} />
        {/* R764: Burp-identical ðŸ” tab-search input on far right.
            Matches the Burp Repeater reference screenshot which
            shows a search icon + dropdown arrow at the top-right
            of the tab strip. Filters tab visibility by substring
            match on tab name or URL. Empty filter shows all. */}
        <div className="rep-tab-search">
          <span className="rep-tab-search-icon" aria-hidden>ðŸ”</span>
          <input
            type="text"
            value={tabFilter}
            onChange={(e) => setTabFilter(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && tabFilter) {
                e.preventDefault();
                setTabFilter("");
              }
            }}
            placeholder="Search tabs…"
            title="Filter tabs by name or URL substring (Esc clears)"
          />
          {tabFilter && (
            <button
              className="rep-tab-search-clear"
              onClick={() => setTabFilter("")}
              title="Clear filter (Esc)"
            >
              Ã—
            </button>
          )}
        </div>
        {/* R767: Burp-identical "N tabs filtered" feedback label.
            Renders when the tab-search filter hides at least one
            tab. Clicking the label clears the filter ”” same path
            as the Ã— clear button, just a wider click target when
            the operator wants to bail out of a filter. */}
        {(() => {
          if (!tabFilterText) return null;
          const hiddenCount = tabs.filter((t) => {
            if (t.id === active) return false;
            const url = buildUrlFromTemplate(t.template).toLowerCase();
            const name = (t.name || "").toLowerCase();
            return !name.includes(tabFilterText) && !url.includes(tabFilterText);
          }).length;
          if (hiddenCount === 0) return null;
          return (
            <button
              className="rep-tab-filter-count"
              onClick={() => setTabFilter("")}
              title={`${hiddenCount} tab${hiddenCount === 1 ? "" : "s"} hidden by filter ”” click to clear`}
            >
              {hiddenCount} hidden
            </button>
          );
        })()}
      </div>
      {/* R913: UrlBar REMOVED ”” Burp Suite 2026.8 has NO separate URL
          input row. The target URL is shown as a small "Target: ..."
          label on the far right of the toolbar, not as an editable
          input field. The user explicitly called out "remove the stupid
          url long box" ”” this is it. URL editing happens via the ✎
          pencil button which opens the Configure Target Details modal
          (R894). */}
      <div className="toolbar">
        {/* R821: Burp-identical Send + Cancel always-visible pair.
            Matches Burp Suite 2026.8's reference screenshot where
            both buttons stay in the toolbar permanently ”” Send
            disables while in-flight, Cancel enables only when
            there's something to cancel. Operators get a stable
            visual anchor + muscle-memory lands on the same pixel
            each round regardless of send state. */}
        {/* ðŸŽ¯ R830 ”” 30th round-number milestone this chunk. Burp-
            identical Send button pulse when the active tab has
            unsent operator edits (raw differs from saved template).
            Matches Burp Suite 2026.8's subtle "ready to fire" cue
            without being noisy ”” pulse only shows when there's
            something new to send. */}
        {(() => {
          const activeTab = tabs.find((t) => t.id === active);
          const hasDirty =
            !!activeTab &&
            raw.trim() !== renderRaw(activeTab.template).trim();
          const canSend =
            !busy && active != null && !inflight.has(active);
          return (
            <button
              className={`burp-send${hasDirty && canSend ? " burp-send-pulse" : ""}`}
              disabled={!canSend}
              onClick={send}
              title={
                active == null
                  ? "Select a tab first"
                  : inflight.has(active)
                    ? "Send is in-flight ”” use Cancel to abort"
                    : hasDirty
                      ? "Send the current request (unsent edits detected). Ctrl+Enter."
                      : "Send the current request (Ctrl+Enter from the editor)"
              }
            >
              Send
            </button>
          );
        })()}
        <button
          className="burp-send-cancel"
          disabled={active == null || !inflight.has(active)}
          onClick={() => void cancelActive()}
          title={
            active == null
              ? "Select a tab first"
              : !inflight.has(active)
                ? "No in-flight send to cancel"
                : "Cancel the in-flight send (Ctrl+Backspace). The engine wakes the pending future; a cancelled history row is still appended."
          }
        >
          Cancel
        </button>
        {/* R913: Toolbar stripped to Burp-identical layout.
            Only: Send | Cancel | ⚙ | ◀▶ | [spacer] | Target: URL ✎ HTTP/1 ?
            Removed: Reset, AI, ↶ Revert, separator, Cancel all,
            Bulk toggle + all bulk ops, Compact/Inspector/Focus toggles.
            None of these are visible in the user-attached Burp screenshot. */}
        <button
          className="ghost rep-send-gear"
          disabled={active == null}
          onClick={(e) => {
            const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
            setSettingsMenu({ x: rect.left, y: rect.bottom + 2 });
          }}
          title="Repeater tab settings (encoding, follow-redirects, clear history)"
          style={{ padding: "4px 8px" }}
        >
          ⚙
        </button>
        {(() => {
          const activeTab = tabs.find((t) => t.id === active);
          const historyLen = activeTab?.history.length ?? 0;
          const effectiveIdx =
            sendIndex !== null && sendIndex < historyLen
              ? sendIndex
              : historyLen - 1;
          const canPrev = effectiveIdx > 0;
          const canNext = effectiveIdx >= 0 && effectiveIdx < historyLen - 1;
          return (
            <>
              <button
                className="ghost"
                disabled={!canPrev}
                onClick={() =>
                  setSendIndex(Math.max(0, effectiveIdx - 1))
                }
                title="Previous send (Ctrl+Shift+Left)"
                style={{ padding: "4px 6px" }}
              >
                ◀
              </button>
              <button
                className="ghost"
                disabled={!canNext}
                onClick={() =>
                  setSendIndex(Math.min(historyLen - 1, effectiveIdx + 1))
                }
                title="Next send (Ctrl+Shift+Right)"
                style={{ padding: "4px 6px" }}
              >
                ▶
              </button>
            </>
          );
        })()}
        {/* R732/R913: Target display ”” kept on far right */}
        {/* R735: Removed the "N responses" badge and the
            "Ctrl+Enter to send · Ctrl+Backspace to cancel …"
            keyboard-hint span. Both are now redundant with the
            R734 bottom status bar (send counter "N/Total" + help
            text in button tooltips). Removing them matches Burp
            Suite's clean toolbar which has no inline hints. */}
        {/* R732: Burp-identical "Target: URL · ✎ · HTTP/1" display
            on the right side of the toolbar. Mirrors Burp's Repeater
            which anchors the target URL + protocol badge on the far
            right of the Send-row so operators always know which host
            they're hitting without reading the Host header. The
            pencil button pops a prompt to rewrite the URL (host +
            port + scheme + path); the backend `repeaterUpdate` call
            re-renders the raw buffer. HTTP/1 is static ”” BurpFree
            speaks HTTP/1.1 end-to-end for now. */}
        {(() => {
          const activeTab = tabs.find((t) => t.id === active);
          if (!activeTab) return null;
          const url = buildUrlFromTemplate(activeTab.template);
          // R762: Burp-identical "Not specified" fallback when
          // the URL is empty or trivially "https://example.com/".
          // Matches Burp Suite 2026.8's exact empty-target label
          // visible in the reference screenshot. Operators who
          // haven't typed a request yet see the familiar text.
          const hasRealTarget = !!url && !url.startsWith("https://example.com");
          return (
            <div className="rep-target-display">
              <span className="rep-target-label">Target:</span>
              <span
                className={`rep-target-url${hasRealTarget ? "" : " rep-target-url-empty"}`}
                title={hasRealTarget ? url : "No target host set ”” type a Host header or a URL into the request to set it"}
              >
                {hasRealTarget ? url : "Not specified"}
              </span>
              <button
                className="rep-target-edit"
                onClick={() => {
                  // R894: Open the Burp-identical "Configure target
                  // details" modal instead of a native prompt. The
                  // modal has 4 fields (Host / Override SNI / Port /
                  // Use HTTPS) matching Burp Suite 2026.8's exact
                  // dialog layout from the user screenshot.
                  const tpl = activeTab.template ?? {};
                  const scheme = String(tpl.scheme ?? "https");
                  const host = String(tpl.host ?? "");
                  const port =
                    typeof tpl.port === "number"
                      ? tpl.port
                      : scheme === "https"
                        ? 443
                        : 80;
                  const path = String(tpl.path ?? "/");
                  setConfigureTargetDraft({
                    host,
                    port,
                    useHttps: scheme === "https",
                    overrideSni: false,
                    sniValue: "",
                    path,
                  });
                  setConfigureTargetOpen(true);
                }}
                title="Configure target details (host, port, HTTPS, SNI override) ”” Burp-identical modal"
              >
                ✎
              </button>
              <span className="rep-http-badge" title="HTTP protocol version ”” BurpFree speaks HTTP/1.1 end-to-end">
                HTTP/1
              </span>
              {/* R773 â†’ R794: env selector moved to the Response
                  pane bottom bar via MessageEditor's extraFootItem
                  prop ”” matches Burp Suite 2026.8's exact layout
                  visible in the user's reference screenshot where
                  "anz-corp-dev" sits in the pane bottom bar, not
                  the top toolbar. Clearing the top-toolbar version
                  keeps the target display row minimal (Burp-style:
                  just URL + ✎ + HTTP/N + ? help). */}
              {/* R761: Burp-identical "?" help button on the far
                  right of the toolbar. Opens a help dialog with
                  Repeater keyboard shortcuts + basic usage tips.
                  Mirrors Burp Suite 2026.8's help affordance. */}
              <button
                className="rep-help-btn"
                onClick={() => {
                  alert(
                    "BurpFree Repeater ”” Keyboard shortcuts\n\n" +
                      "Primary actions:\n" +
                      "  Ctrl+Enter        Send request\n" +
                      "  Ctrl+Backspace    Cancel in-flight send\n" +
                      "  Ctrl+Shift+Backspace  Cancel ALL in-flight sends\n\n" +
                      "Navigation:\n" +
                      "  Ctrl+Shift+Left   Previous send in this tab\n" +
                      "  Ctrl+Shift+Right  Next send in this tab\n" +
                      "  Ctrl+Shift+T      New tab\n" +
                      "  Ctrl+W            Close active tab\n" +
                      "  Ctrl+Tab          Next tab\n" +
                      "  Alt+1..9          Jump to tab N\n\n" +
                      "Editing:\n" +
                      "  Ctrl+F            Search in pane\n" +
                      "  Ctrl+G            Go to line\n" +
                      "  Esc               Close search / cancel edit\n\n" +
                      "Tab actions:\n" +
                      "  Alt+Shift+P       Fire every pinned tab\n" +
                      "  Alt+Shift+D       Diff last 2 sends\n" +
                      "  Alt+Shift+U       Copy all URLs\n" +
                      "  Alt+Shift+S       Save selected response\n\n" +
                      "Right-click anywhere for context-menu actions.\n" +
                      "Right-click tabs for pin/rename/duplicate/color/group.\n" +
                      "â‹¯ Bulk toggle reveals Export/Import/All-cURL/...\n" +
                      "⚙ gear opens per-tab settings (Protocol/Encoding/Redirects).",
                  );
                }}
                title="Repeater keyboard shortcuts + usage help"
              >
                ?
              </button>
            </div>
          );
        })()}
      </div>
      {redirectInfo && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "4px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            fontSize: 11.5,
          }}
          role="status"
        >
          <span style={{ color: "var(--accent)", fontWeight: 600 }}>
            {redirectInfo.status} â†’
          </span>
          <span
            className="mono"
            style={{
              flex: 1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={redirectInfo.location}
          >
            {redirectInfo.location}
          </span>
          <button
            disabled={busy}
            onClick={() => void followRedirect()}
            title="Resolve the Location against the current URL and fire one more send; appends to history, leaves the tab's URL unchanged"
          >
            Follow this redirect
          </button>
        </div>
      )}
      <div
        className={`rep-grid${showInspector ? " rep-grid--with-inspector" : ""}${focusPane === "request" ? " rep-grid--focus-request" : focusPane === "response" ? " rep-grid--focus-response" : ""}`}
        style={
          showInspector
            ? ({ ["--rep-inspector-width" as any]: `${inspectorWidth}px` } as any)
            : undefined
        }
      >
        <MessageEditor
          label="Request"
          value={raw}
          onChange={setRaw}
          direction="request"
          onCtrlEnter={send}
          extraMenuItems={buildRequestMenu()}
          onSelectionChange={(sel) => setEditorSelection(sel)}
        />
        <MessageEditor
          label="Response"
          value={respRaw}
          onSelectionChange={(sel) => setEditorSelection(sel)}
          extraFootItem={(() => {
            // R804: Burp-identical "âœ¨ Analyze with AI" quick-fire
            // button next to the env dropdown ”” one-click opens
            // the R800 AI drawer with "Explain the response"
            // auto-fired as if operator typed + hit Analyze.
            // Only renders when there IS a response to analyze.
            const activeTab = tabs.find((t) => t.id === active);
            const hasResponse =
              !!activeTab &&
              activeTab.history.length > 0 &&
              !!activeTab.history[activeTab.history.length - 1].response;
            // R794: Burp-identical environment-selector dropdown in
            // the Response pane bottom bar (moved from the top toolbar
            // where R773 originally placed it ”” matches the exact
            // layout visible in the user's Burp 2026.8 reference
            // screenshot where "anz-corp-dev" sits between the pane
            // nav arrows and the "0 highlights" counter). Env derivation
            // keeps the R773 two-tier logic (well-known tokens â†’ first
            // dot-segment â†’ "default"); FloatingMenu wiring reuses the
            // existing `envMenu` state so one dropdown anchor serves
            // both click target + rendered menu.
            const host = (activeTab?.template.host || "").toLowerCase();
            const envTokens = [
              "preprod",
              "staging",
              "stg",
              "dev",
              "qa",
              "uat",
              "test",
              "prod",
              "local",
            ];
            let envName = "default";
            for (const t of envTokens) {
              if (host.includes(t)) {
                envName = t;
                break;
              }
            }
            if (envName === "default" && host) {
              const parts = host.split(".");
              if (parts.length >= 2 && parts[0]) {
                envName = parts[0];
              }
            }
            // R814: Burp-identical "N bytes · N millis" indicator on
            // the Response pane bottom-right. Matches Burp Suite
            // 2026.8's exact silhouette visible in the user's
            // reference screenshot where the response pane shows
            // "646 bytes · 283 millis" far-right. Pulls from the
            // active tab's latest history entry so operators see
            // the stored response size + round-trip time without
            // scrolling to find it.
            const lastSend = activeTab && hasResponse
              ? activeTab.history[activeTab.history.length - 1]
              : null;
            return (
              <>
                {hasResponse && (
                  <button
                    className="rep-ai-foot-btn"
                    onClick={() => {
                      // Pre-fire the "Explain the response" prompt
                      // so operators get an immediate analysis
                      // without typing. Opens the R800 drawer.
                      setBurpAiOpen(true);
                      // Seed messages with the greeting + an
                      // auto-fired explain prompt via a tiny
                      // delay so the drawer's own useEffect
                      // populates the greeting first.
                      setTimeout(() => {
                        setBurpAiMessages((prev) => [
                          ...prev,
                          {
                            role: "user",
                            text: "Explain the response",
                          },
                        ]);
                      }, 50);
                    }}
                    title="Open Burp AI drawer + auto-fire 'Explain the response' prompt. Great for one-click triage on surprising status codes."
                  >
                    âœ¨ Analyze
                  </button>
                )}
                <button
                  className="rep-env-selector"
                  onClick={(e) => {
                    const rect = (
                      e.currentTarget as HTMLElement
                    ).getBoundingClientRect();
                    setEnvMenu({ x: rect.left, y: rect.bottom + 2 });
                  }}
                  title={`Target environment: ${envName} ”” derived from host "${host || "(none)"}" (cosmetic selector, click to see other envs; does not rewrite the host)`}
                >
                  <span className="rep-env-dot" />
                  {envName}
                  <span className="rep-env-caret">â–¾</span>
                </button>
                {/* R814: Response size + elapsed-time indicator ””
                    far-right of the pane bottom bar matching Burp's
                    "646 bytes · 283 millis" exactly. Only shows
                    when a response is stored. */}
                {lastSend && (
                  <span
                    className="rep-resp-size-ms"
                    title={`Response: ${
                      lastSend.response?.body?.length ?? 0
                    } body bytes · ${
                      lastSend.elapsed_ms ?? 0
                    }ms round-trip time (from the stored response)`}
                  >
                    {lastSend.response?.body?.length ?? 0} bytes ·{" "}
                    {lastSend.elapsed_ms ?? 0} millis
                  </span>
                )}
              </>
            );
          })()}
          onChange={() => { /* read-only */ }}
          direction="response"
          readOnly
          extraMenuItems={buildResponseMenu()}
        />
        {showInspector && (
          <>
            {/* R751: Draggable left-edge gutter ”” operators drag
                to resize the Inspector width between 220-500px.
                Mouse-down captures the starting X + width into
                a ref; mousemove updates width via inspectorWidth
                state (clamped). The gutter is a thin 3px vertical
                strip that becomes a resize cursor on hover. */}
            <div
              className="rep-inspector-resizer"
              onMouseDown={(e) => {
                inspectorResizingRef.current = {
                  startX: e.clientX,
                  startW: inspectorWidth,
                };
                document.body.style.cursor = "col-resize";
                document.body.style.userSelect = "none";
              }}
              title="Drag to resize Inspector (220-500px)"
            />
            <InspectorSidebar
              requestRaw={raw}
              responseRaw={respRaw}
              activeTab={tabs.find((t) => t.id === active) ?? null}
              expanded={inspectorExpanded}
              onToggle={toggleInspectorSection}
              selection={editorSelection}
              onApplyRequest={(nextRaw) => setRaw(nextRaw)}
              onBulkExpand={(expand) => {
                // R791: Toggle every known Inspector section at
                // once. Keys mirror the sections rendered in
                // InspectorSidebar (attrs / query / body /
                // cookies / headers / respHeaders / notes).
                setInspectorExpanded(() => ({
                  attrs: expand,
                  query: expand,
                  body: expand,
                  cookies: expand,
                  headers: expand,
                  respHeaders: expand,
                  notes: expand,
                }));
              }}
              onClose={() => setShowInspector(false)}
              onCommentChange={async (tabId, comment) => {
                try {
                  await api.repeaterSetComment(tabId, comment);
                  await refresh();
                } catch {
                  /* ignore ”” comment save failures shouldn't crash the UI */
                }
              }}
            />
          </>
        )}
        {/* R756: Burp-identical vertical side rails on the far
            right ”” "Inspector / Notes / Custom actions" rotated
            text buttons that are ALWAYS visible (even when the
            Inspector sidebar is hidden). Click opens the sidebar
            + scrolls to the matching section. Mirrors Burp Suite
            2026.8's canonical right-edge vertical tab trio. */}
        <div className="rep-side-rails">
          <button
            className={`rep-side-rail${showInspector ? " active" : ""}`}
            onClick={() => {
              if (showInspector) {
                setShowInspector(false);
              } else {
                setShowInspector(true);
                // Collapse other sections, expand only the headers
                // one as the default "landing" when operators
                // click Inspector cold.
                setInspectorExpanded((p) => ({
                  ...p,
                  attrs: true,
                  headers: true,
                }));
              }
            }}
            title={showInspector ? "Hide Inspector sidebar" : "Show Inspector sidebar"}
          >
            Inspector
          </button>
          <button
            className="rep-side-rail"
            onClick={() => {
              setShowInspector(true);
              // Expand only Notes section, collapse others, so
              // clicking Notes rail jumps straight to notes.
              setInspectorExpanded((p) => ({ ...p, notes: true }));
              // Scroll Notes into view after a tick.
              setTimeout(() => {
                const notesHead = document.querySelector<HTMLElement>(
                  ".rep-insp-section-head[title*='Notes']",
                );
                notesHead?.scrollIntoView({ behavior: "smooth", block: "start" });
              }, 50);
            }}
            title="Open Notes (per-tab free-form comment)"
          >
            Notes
          </button>
          <button
            className="rep-side-rail"
            onClick={() => {
              alert(
                "Custom actions\n\n" +
                  "Custom actions let operators attach saved scripts " +
                  "(Rhai / shell / curl) that run against the current " +
                  "request/response on demand. Planned for a future " +
                  "BurpFree release ”” the Rhai scripting engine is " +
                  "already wired (see burpfree-script crate); the UI " +
                  "integration ships soon.\n\n" +
                  "For now, use the Bambda filter + the Extensions " +
                  "panel to run custom logic.",
              );
            }}
            title="Custom actions (planned feature)"
          >
            Custom actions
          </button>
        </div>
      </div>
      {/* R734: Burp-identical status bar at the bottom of the
          Repeater panel showing the active tab's last send stats:
          status code (tinted by response class), response size in
          human units (B/KB/MB), elapsed ms, content-type. Mirrors
          Burp's bottom-right "646 bytes · 283 millis" display.
          Pulls data from the active tab's history[sendIndex] or
          falls back to history[last] when sendIndex is null. */}
      <RepeaterStatusBar
        activeTab={tabs.find((t) => t.id === active) ?? null}
        sendIndex={sendIndex}
      />
      <HistoryStrip
        tab={tabs.find((t) => t.id === active) ?? null}
        selected={sendIndex}
        onSelect={(i) => {
          setSendIndex(i);
          setDiffReport(null);
        }}
        diffA={diffA}
        diffB={diffB}
        onDiffA={(i) => setDiffA(i)}
        onDiffB={(i) => setDiffB(i)}
        onRunDiff={() => {
          if (active != null && diffA != null && diffB != null)
            void runDiff(active, diffA, diffB);
        }}
        onClearDiff={() => {
          setDiffA(null);
          setDiffB(null);
          setDiffReport(null);
        }}
        onClearHistory={(id) => void clearTabHistory(id)}
      />
      {/* ðŸŽ¯ R800 ”” 27th round-number milestone this chunk. Burp-
          identical âœ¦ AI companion drawer. Opens from the âœ¦ AI
          toolbar button (R740); renders as a right-side drawer
          overlaying the editor grid. Mock chat UI: canned greeting
          + request/response context summary pre-filled on open,
          prompt input + Analyze button that appends a canned
          analysis response derived from the parsed request. 100%
          client-side ”” no AI backend, matches Burp Suite 2026.8's
          silhouette for operator muscle memory without pretending
          to call a real AI service. */}
      {/* R894: Burp-identical "Configure target details" modal.
          Matches the exact dialog from the user-attached screenshot:
          Host (text) / Override SNI (checkbox) / Port (number) /
          Use HTTPS (checkbox) + OK / Cancel buttons. Replaces the
          old `prompt()` for URL editing. OK commits via
          `repeaterUpdate` with the recomposed template; Cancel just
          closes without changes. */}
      {configureTargetOpen && configureTargetDraft && (
        <div
          className="rep-config-target-overlay"
          onClick={() => setConfigureTargetOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Configure target details"
        >
          <div
            className="rep-config-target-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="rep-config-target-head">
              <span>Configure target details</span>
              <button
                type="button"
                className="rep-config-target-close"
                onClick={() => setConfigureTargetOpen(false)}
                aria-label="Close"
                title="Close (Esc)"
              >
                Ã—
              </button>
            </div>
            <div className="rep-config-target-body">
              <p className="rep-config-target-blurb">
                Specify the details of the server to which the request will
                be sent.
              </p>
              <div className="rep-config-target-field">
                <label htmlFor="rep-config-target-host">Host:</label>
                <input
                  id="rep-config-target-host"
                  type="text"
                  value={configureTargetDraft.host}
                  autoFocus
                  onChange={(e) =>
                    setConfigureTargetDraft({
                      ...configureTargetDraft,
                      host: e.target.value,
                    })
                  }
                />
              </div>
              <div className="rep-config-target-field">
                <label className="rep-config-target-check">
                  <input
                    type="checkbox"
                    checked={configureTargetDraft.overrideSni}
                    onChange={(e) =>
                      setConfigureTargetDraft({
                        ...configureTargetDraft,
                        overrideSni: e.target.checked,
                      })
                    }
                  />
                  Override SNI
                </label>
                {configureTargetDraft.overrideSni && (
                  <input
                    type="text"
                    placeholder="SNI value"
                    value={configureTargetDraft.sniValue}
                    onChange={(e) =>
                      setConfigureTargetDraft({
                        ...configureTargetDraft,
                        sniValue: e.target.value,
                      })
                    }
                    style={{ marginTop: 4 }}
                  />
                )}
              </div>
              <div className="rep-config-target-field">
                <label htmlFor="rep-config-target-port">Port:</label>
                <input
                  id="rep-config-target-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={configureTargetDraft.port}
                  onChange={(e) =>
                    setConfigureTargetDraft({
                      ...configureTargetDraft,
                      port: Number(e.target.value) || 0,
                    })
                  }
                />
              </div>
              <div className="rep-config-target-field">
                <label className="rep-config-target-check">
                  <input
                    type="checkbox"
                    checked={configureTargetDraft.useHttps}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setConfigureTargetDraft({
                        ...configureTargetDraft,
                        useHttps: next,
                        // Auto-flip default port when toggling
                        // scheme if the operator still has the
                        // old default.
                        port:
                          configureTargetDraft.port === (next ? 80 : 443)
                            ? next
                              ? 443
                              : 80
                            : configureTargetDraft.port,
                      });
                    }}
                  />
                  Use HTTPS
                </label>
              </div>
            </div>
            <div className="rep-config-target-foot">
              <button
                type="button"
                className="primary"
                disabled={!configureTargetDraft.host.trim()}
                onClick={async () => {
                  const activeTab = tabs.find((t) => t.id === active);
                  if (!activeTab) {
                    setConfigureTargetOpen(false);
                    return;
                  }
                  const d = configureTargetDraft;
                  const scheme = d.useHttps ? "https" : "http";
                  const defaultPort = d.useHttps ? 443 : 80;
                  const portPart =
                    d.port === defaultPort ? "" : `:${d.port}`;
                  const nextUrl = `${scheme}://${d.host.trim()}${portPart}${d.path || "/"}`;
                  try {
                    const nextTpl = {
                      ...activeTab.template,
                      scheme,
                      host: d.host.trim(),
                      port: d.port || defaultPort,
                      path: d.path || "/",
                      url: nextUrl,
                    };
                    await api.repeaterUpdate(active!, nextTpl);
                    await refresh();
                    setConfigureTargetOpen(false);
                  } catch (e) {
                    alert(`Update failed: ${e}`);
                  }
                }}
              >
                OK
              </button>
              <button
                type="button"
                onClick={() => setConfigureTargetOpen(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      {burpAiOpen && (
        <BurpAiDrawer
          open={burpAiOpen}
          onClose={() => setBurpAiOpen(false)}
          messages={burpAiMessages}
          setMessages={setBurpAiMessages}
          prompt={burpAiPrompt}
          setPrompt={setBurpAiPrompt}
          activeTab={tabs.find((t) => t.id === active) ?? null}
          respRaw={respRaw}
        />
      )}
      {diffReport && (
        <DiffPane
          report={diffReport}
          a={diffA}
          b={diffB}
          onClose={() => setDiffReport(null)}
        />
      )}
      {/* R760: Burp-identical "Ready" status strip at the very
          bottom of the Repeater panel. Mirrors Burp Suite 2026.8's
          global status bar which shows "Ready" at the bottom-left.
          Shows live status: Ready / Sending / Cancelled / Burst
          (while bursting). Right side shows the active tab's
          send count + a hint ("Ctrl+Enter to send"). Collapses
          to just the status when there's no active tab. */}
      <div className="rep-ready-strip">
        <span className="rep-ready-status">
          {(() => {
            if (active == null) return "No tab";
            if (bursting) return "Bursting…";
            if (busy) return "Sending…";
            if (inflight.has(active)) return "Request in flight…";
            return "Ready";
          })()}
        </span>
        <span className="rep-ready-spacer" />
        {(() => {
          const t = tabs.find((x) => x.id === active);
          if (!t) return null;
          return (
            <span className="rep-ready-tab">
              {t.name || `tab-${t.id}`} · {t.history.length} send
              {t.history.length === 1 ? "" : "s"}
            </span>
          );
        })()}
      </div>
      {/* R739: Repeater settings FloatingMenu (⚙ button). Shows
          per-tab config: encoding + follow-redirects + clear history.
          Replaces the always-visible encoding + follow-redirects
          selects on the toolbar ”” frees horizontal space while
          keeping every setting one click away. */}
      <FloatingMenu
        state={
          settingsMenu
            ? { x: settingsMenu.x, y: settingsMenu.y, data: null as any }
            : null
        }
        onClose={() => setSettingsMenu(null)}
        items={(() => {
          const activeTab = tabs.find((t) => t.id === active);
          if (!activeTab) {
            return [{ label: "(no tab selected)", disabled: true, onClick: () => {} }];
          }
          const currentEncoding = detectEncoding(activeTab.template);
          const currentRedirects = activeTab.follow_redirects ?? "inherit";
          const items: Array<any> = [
            // R895: Burp-identical "Repeater settings for this tab"
            // header + the 11 toggle entries visible in the user-
            // attached Repeater settings screenshot. BurpFree
            // currently honors a subset of these; the rest render
            // as planned-feature mocks with alerts explaining
            // state. Matches Burp Suite 2026.8's exact silhouette.
            {
              label: "Repeater settings for this tab",
              disabled: true,
              hint: "shown entries honor per-tab · click items below to toggle",
            },
            {
              label: "Restore global defaults",
              hint: "re-apply the project-level Repeater defaults",
              onClick: () => {
                alert(
                  "Restore global defaults: BurpFree's current settings surface is per-tab only. Project-level defaults are planned ”” for now, flip entries individually below.",
                );
                setSettingsMenu(null);
              },
            },
            { separator: true },
            {
              label: "âœ“ Update Content-Length",
              hint: "auto-fixes CL header on every send · default on",
              onClick: () => {
                alert(
                  "Update Content-Length is always ON in BurpFree ”” the backend's parsing layer recomputes Content-Length on every send so operators can edit the body without manual sync. Making this toggleable is planned.",
                );
                setSettingsMenu(null);
              },
            },
            {
              label: "âœ“ Unpack compressed responses",
              hint: "gzip / deflate / brotli decode · default on",
              onClick: () => {
                alert(
                  "Unpack compressed responses is always ON in BurpFree ”” the engine auto-decodes gzip / deflate / brotli-wrapped response bodies before passing to the Pretty / Raw / Hex / Render views. Making this toggleable is planned.",
                );
                setSettingsMenu(null);
              },
            },
            // Follow redirections already lives below as a native
            // submenu picker so operators get full inherit/never/
            // ... control. Reference it here with a hint.
            {
              label: "Follow redirections â–¸",
              hint: "pick a policy in the submenu below",
              disabled: true,
            },
            {
              label: "Process cookies in redirections",
              hint: "merge Set-Cookie headers into the jar across hops",
              onClick: () => {
                alert(
                  "Process cookies in redirections is implicit when follow-redirects is enabled ”” the engine carries the cookie jar across hops automatically. Making this independently toggleable is planned.",
                );
                setSettingsMenu(null);
              },
            },
            {
              label: "Enforce protocol choice on cross-domain redirections",
              hint: "block httpâ†’https or httpsâ†’http hops",
              onClick: () => {
                alert(
                  "Enforce protocol choice on cross-domain redirections is planned. Currently BurpFree follows the redirect's scheme regardless of the original request's scheme.",
                );
                setSettingsMenu(null);
              },
            },
            {
              label: "âœ“ Normalize HTTP/1 line endings",
              hint: "LF â†’ CRLF on wire · default on",
              onClick: () => {
                alert(
                  "Normalize HTTP/1 line endings is always ON in BurpFree ”” the wire serializer forces CRLF on every header + body chunk per RFC 9112. Making this toggleable (to intentionally test non-conformant servers) is planned.",
                );
                setSettingsMenu(null);
              },
            },
            {
              label: "Enable HTTP/1 connection reuse",
              hint: "keep-alive · default off (one send = one connection)",
              onClick: () => {
                alert(
                  "Enable HTTP/1 connection reuse is OFF in BurpFree ”” every Repeater send opens a fresh connection, matching Burp's default. Keep-alive-based connection reuse is planned (needed for session-tied targets).",
                );
                setSettingsMenu(null);
              },
            },
            {
              label: "â—‹ Enable HTTP/2 connection reuse",
              disabled: true,
              hint: "HTTP/2 end-to-end is planned",
            },
            {
              label: "â—‹ Strip Connection header over HTTP/2",
              disabled: true,
              hint: "HTTP/2 end-to-end is planned",
            },
            {
              label: "â—‹ Allow HTTP/2 ALPN override",
              disabled: true,
              hint: "HTTP/2 end-to-end is planned",
            },
            {
              label: "Streaming response timeout",
              hint: "millis before Repeater gives up waiting for body chunks",
              onClick: () => {
                alert(
                  "Streaming response timeout: BurpFree's engine currently uses a fixed 30s timeout per send. Operator-configurable timeout (and streaming body chunk delivery) is planned.",
                );
                setSettingsMenu(null);
              },
            },
            { separator: true },
            // R752: Burp-identical "Protocol" section. HTTP/1
            // is the only functional path in BurpFree; HTTP/2
            // and HTTP/3 are visual stubs that explain the
            // state ("planned") when clicked. Matches Burp
            // Suite's protocol selector exactly.
            {
              label: `Protocol ”” HTTP/1`,
              disabled: true,
              hint: "pick one below (BurpFree only speaks HTTP/1.1 end-to-end)",
            },
            {
              label: `  â— HTTP/1`,
              disabled: true,
              hint: "default · functional",
              onClick: () => setSettingsMenu(null),
            },
            {
              label: `  â—‹ HTTP/2`,
              onClick: () => {
                alert(
                  "HTTP/2 support is planned for a future BurpFree release. BurpFree currently speaks HTTP/1.1 end-to-end.",
                );
                setSettingsMenu(null);
              },
              hint: "planned",
            },
            {
              label: `  â—‹ HTTP/3`,
              onClick: () => {
                alert(
                  "HTTP/3 support is planned for a future BurpFree release. BurpFree currently speaks HTTP/1.1 end-to-end.",
                );
                setSettingsMenu(null);
              },
              hint: "planned",
            },
            { separator: true },
            {
              label: `Encoding ”” ${currentEncoding}`,
              disabled: true,
              hint: "pick one below to apply",
            },
            ...(["plain", "gzip", "chunked"] as const).map((kind) => ({
              label: `  ${kind === currentEncoding ? "â—" : "â—‹"} ${kind}`,
              onClick: async () => {
                try {
                  const edited = parseRaw(raw, activeTab.template);
                  await api.repeaterUpdate(activeTab.id, edited);
                  await api.repeaterSetBodyEncoding(activeTab.id, kind);
                  await refresh();
                  const next = (await api.repeaterList()).find(
                    (t) => t.id === activeTab.id,
                  );
                  if (next) setRaw(renderRaw(next.template));
                } catch (e) {
                  alert(`${e}`);
                }
                setSettingsMenu(null);
              },
              disabled: kind === currentEncoding,
            })),
            { separator: true },
            {
              label: `Follow redirects ”” ${currentRedirects}`,
              disabled: true,
              hint: "pick one below to apply",
            },
            ...(["inherit", "never", "on_site", "in_scope", "always"] as const).map(
              (policy) => ({
                label: `  ${policy === currentRedirects ? "â—" : "â—‹"} ${policy.replace("_", "-")}`,
                onClick: async () => {
                  try {
                    await api.repeaterSetFollowRedirects(activeTab.id, policy);
                    await refresh();
                  } catch (e) {
                    alert(`${e}`);
                  }
                  setSettingsMenu(null);
                },
                disabled: policy === currentRedirects,
              }),
            ),
            { separator: true },
            {
              label: "Clear this tab's history",
              danger: true,
              disabled: (activeTab.history?.length ?? 0) === 0,
              hint: `${activeTab.history?.length ?? 0} send(s) will be wiped`,
              onClick: async () => {
                if (
                  !confirm(
                    `Clear ${activeTab.history.length} send${activeTab.history.length === 1 ? "" : "s"} from "${activeTab.name}"? The tab itself stays.`,
                  )
                ) {
                  return;
                }
                try {
                  await api.repeaterTabClearHistory(activeTab.id);
                  await refresh();
                } catch (e) {
                  alert(`${e}`);
                }
                setSettingsMenu(null);
              },
            },
          ];
          return items;
        })()}
      />
      {/* R773: Repeater environment-selector FloatingMenu. Shows
          the common env tokens Burp operators swap between ””
          "default", "dev", "staging", "qa", "prod", "preprod",
          "test", "uat", "local". Selection is cosmetic (does NOT
          rewrite the host ”” operators retain full control via the
          ✎ pencil); matches Burp Suite 2026.8's env picker which
          is also non-destructive by default. The "Manage
          environments…" item surfaces that BurpFree does not yet
          persist a per-env host override, matching Burp's
          "planned" state for custom env mapping. */}
      <FloatingMenu
        state={
          envMenu
            ? { x: envMenu.x, y: envMenu.y, data: null as any }
            : null
        }
        onClose={() => setEnvMenu(null)}
        items={(() => {
          const activeTab = tabs.find((t) => t.id === active);
          const host = (activeTab?.template.host || "").toLowerCase();
          const envTokens = [
            "default",
            "dev",
            "staging",
            "qa",
            "prod",
            "preprod",
            "test",
            "uat",
            "local",
          ];
          let currentEnv = "default";
          for (const t of envTokens) {
            if (t !== "default" && host.includes(t)) {
              currentEnv = t;
              break;
            }
          }
          const items: Array<any> = [
            {
              label: "Environment",
              disabled: true,
              hint: "cosmetic picker · does not rewrite the host",
            },
          ];
          for (const t of envTokens) {
            const sel = t === currentEnv ? "â—" : "â—‹";
            items.push({
              label: `  ${sel} ${t}`,
              onClick: () => {
                if (t === currentEnv) {
                  setEnvMenu(null);
                  return;
                }
                alert(
                  `Environment swap to "${t}" is cosmetic in this BurpFree build.\n\nTo actually hit a different host, use the ✎ pencil button next to the Target URL (or edit the Host header inline). Burp Suite 2026.8 behaves the same way ”” the env picker is non-destructive by default; mapping hosts to envs is a planned feature.`,
                );
                setEnvMenu(null);
              },
              hint: t === currentEnv ? "current" : undefined,
            });
          }
          items.push({
            label: "Manage environments…",
            onClick: () => {
              alert(
                "Per-environment host mapping is planned for a future BurpFree release.\n\nIn Burp Suite 2026.8 this opens Settings â†’ Environments. BurpFree currently derives the env name from the active host suffix; use the ✎ pencil button next to the Target URL to switch hosts.",
              );
              setEnvMenu(null);
            },
            hint: "planned",
          });
          return items;
        })()}
      />
      {/* R889: Burp-identical + add-tab context menu matching
          the user-attached screenshot (New HTTP tab / New tab
          group / Close all tabs / Reopen closed tab). Opens on
          right-click of the + button. */}
      <FloatingMenu
        state={addMenu}
        onClose={() => setAddMenu(null)}
        items={
          addMenu
            ? [
                {
                  label: "+ New HTTP tab",
                  hint: "same as left-click on +",
                  onClick: () => void addTab(),
                },
                {
                  label: "+ New WebSocket tab",
                  hint: "WebSocket support is planned",
                  disabled: true,
                  onClick: () =>
                    alert(
                      "WebSocket tab support is planned for a future release.\n\n" +
                        "BurpFree currently supports HTTP/1.1 requests.\n" +
                        "WebSocket proxy interception is available in the\n" +
                        "Proxy > WebSockets history sub-tab.",
                    ),
                },
                {
                  label: "+ New tab group",
                  hint: "prompt for group name, create placeholder tab",
                  onClick: () => void newTabGroup(),
                },
                { separator: true },
                {
                  label: "Close all tabs",
                  danger: true,
                  disabled: tabs.length === 0,
                  hint:
                    tabs.length === 0
                      ? "no tabs to close"
                      : `${tabs.length} tab${tabs.length === 1 ? "" : "s"} (pinned ones survive)`,
                  onClick: async () => {
                    const victims = tabs.filter((t) => !t.pinned);
                    if (victims.length === 0) {
                      alert("Only pinned tabs remain ”” unpin first to close them.");
                      return;
                    }
                    if (
                      !confirm(
                        `Close ${victims.length} unpinned tab${victims.length === 1 ? "" : "s"}? Pinned tabs survive.`,
                      )
                    )
                      return;
                    for (const t of victims) await closeTab(t.id);
                  },
                },
                {
                  label: `Reopen closed tab${closedTabHistory.length > 0 ? ` (${closedTabHistory.length})` : ""}`,
                  disabled: closedTabHistory.length === 0,
                  hint:
                    closedTabHistory.length === 0
                      ? "no closed tabs in history"
                      : `last closed: ${closedTabHistory[closedTabHistory.length - 1]?.name ?? ""}`,
                  onClick: () => void reopenLastClosedTab(),
                },
              ]
            : []
        }
      />
      <FloatingMenu
        state={tabMenu}
        onClose={() => setTabMenu(null)}
        items={
          tabMenu?.data
            ? [
                {
                  label: "Send",
                  hotkey: "Ctrl+Enter",
                  onClick: () => void send(),
                },
                {
                  label: "Rename…",
                  hotkey: "double-click",
                  onClick: () =>
                    setRenaming({ id: tabMenu.data!.id, name: tabMenu.data!.name }),
                },
                {
                  label: tabMenu.data!.comment
                    ? "Edit comment…"
                    : "Set comment…",
                  hint: tabMenu.data!.comment || "add a free-form note; shows as ðŸ’¬ on the chip",
                  onClick: () => void editComment(tabMenu.data!),
                },
                {
                  label: "Duplicate tab",
                  onClick: () => void duplicateTab(tabMenu.data!),
                },
                /* R211: Copy URL ”” operators juggling 10+ tabs often  */
                /* want the URL in their clipboard for terminal grep / */
                /* ticket paste / curl replay without having to click  */
                /* the tab, select the URL field, and ctrl+a + copy.   */
                /* The tab's template.url is already in state so this  */
                /* is a one-line copy with no backend round-trip.      */
                {
                  label: "Copy URL",
                  hint: tabMenu.data!.template?.url || "no URL yet",
                  disabled: !tabMenu.data!.template?.url,
                  onClick: async () => {
                    const url = tabMenu.data!.template?.url;
                    if (!url) return;
                    try {
                      await navigator.clipboard.writeText(url);
                    } catch (e) {
                      alert(`Copy failed: ${e}`);
                    }
                  },
                },
                /* R220: Open originating request in HTTP history ””    */
                /* tabs created from history (via Send to Repeater or  */
                /* repeater_add_from_history) carry their source_tx_id */
                /* so operators can trace a Repeater tab back to the   */
                /* row that spawned it. Fires burpfree:history-focus   */
                /* with the stored id, then burpfree:navigate to flip  */
                /* to the HTTP history tab. For tabs without a source  */
                /* (blank tab, Proxy intercept handoff), the entry is  */
                /* disabled with a hint explaining why.                */
                {
                  label: "Open in HTTP history",
                  hint:
                    tabMenu.data!.source_tx_id != null
                      ? `tx #${tabMenu.data!.source_tx_id}`
                      : "no source (blank / intercept tab)",
                  disabled: tabMenu.data!.source_tx_id == null,
                  onClick: () => {
                    const txId = tabMenu.data!.source_tx_id;
                    if (txId == null) return;
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
                  label: "Cancel send",
                  disabled: !inflight.has(tabMenu.data!.id),
                  hint: inflight.has(tabMenu.data!.id)
                    ? "wakes the pending future"
                    : "no send in flight",
                  danger: true,
                  onClick: () => void cancelTab(tabMenu.data!.id),
                },
                {
                  label: tabMenu.data!.pinned ? "ðŸ“Œ Unpin tab" : "ðŸ“Œ Pin tab",
                  hint: tabMenu.data!.pinned
                    ? "removes bulk-close protection"
                    : "protects from bulk closes + floats left",
                  onClick: () =>
                    void togglePinned(
                      tabMenu.data!.id,
                      !tabMenu.data!.pinned,
                    ),
                },
                { separator: true },
                ...METHOD_PRESETS.map((m) => ({
                  label: `Change method â†’ ${m}`,
                  onClick: () => void changeMethod(tabMenu.data!.id, m),
                  disabled: tabMenu.data!.template?.method === m,
                })),
                { separator: true },
                ...COLOR_PRESETS.map((c) => ({
                  label: c.label,
                  onClick: () => void setColor(tabMenu.data!.id, c.value),
                })),
                {
                  label: "Clear colour",
                  onClick: () => void setColor(tabMenu.data!.id, null),
                  disabled: !tabMenu.data!.color,
                },
                { separator: true },
                {
                  label: "Copy request (raw)",
                  onClick: () => void copyRequestWire(tabMenu.data!),
                },
                {
                  label: "Copy last response (raw)",
                  onClick: () => void copyLastResponse(tabMenu.data!),
                  disabled: (tabMenu.data!.history.length ?? 0) === 0,
                },
                // R727: Repeater tab "Copy triage line" ”” compact
                // per-tab format for a quick ticket note / Slack
                // ping where neither cURL nor raw request fits.
                // Format: "METHOD url · 'name' · N sends · Xms avg
                // · ðŸ“Œ pinned · group:foo". Only renders rows that
                // apply (sends/avg omitted when history empty,
                // pinned/group omitted when not set). Mirrors R717
                // HistoryPanel row "Copy method+URL+status" but
                // adapted for Repeater's tab-centric data shape.
                {
                  label: "Copy triage line",
                  hint: "compact tab summary",
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const method =
                      (t.template?.method as string) ?? "GET";
                    const url =
                      (t.template?.url as string) ||
                      buildUrlFromTemplate(t.template) ||
                      "";
                    const parts: string[] = [`${method} ${url}`];
                    parts.push(`'${t.name}'`);
                    const h = t.history ?? [];
                    if (h.length > 0) {
                      parts.push(`${h.length} send${h.length === 1 ? "" : "s"}`);
                      let sum = 0;
                      let n = 0;
                      for (const s of h) {
                        if (
                          typeof s.elapsed_ms === "number" &&
                          s.elapsed_ms >= 0
                        ) {
                          sum += s.elapsed_ms;
                          n += 1;
                        }
                      }
                      if (n > 0)
                        parts.push(`${(sum / n).toFixed(1)}ms avg`);
                    }
                    if (t.pinned) parts.push("ðŸ“Œ pinned");
                    if (t.group && t.group.trim())
                      parts.push(`group:${t.group.trim()}`);
                    try {
                      await copyToClipboard(parts.join(" · "));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R467: Tab-menu "â¬‡ Save last response" ”” third
                // input path for saving a response, alongside R406
                // HistoryStrip "ðŸ’¾ Save" button (per-selected-send)
                // and R454 Alt+Shift+S keyboard. Right-click â†’ â¬‡
                // Save last response targets the most recent send
                // on the tab regardless of which chip is selected,
                // so operators who just want "the latest" without
                // navigating the strip get a one-click path.
                // **Mechanism** reads the tab's last history entry
                // (not sendIndex) so the output is "whatever just
                // came back" ”” natural pair with "Copy last response"
                // which sits right above. **Filename pattern**
                // `response-send<idx>-<status>.txt` matches R406 +
                // R454 byte-identically so a mixed workflow stays
                // consistent. **Disabled gate** zero history + the
                // last entry must have a response (not error-only).
                // R484: Tab-menu "ðŸ“‹ Copy last send as HAR entry" ””
                // zero-RPC HAR copy that uses the Repeater tab's own
                // state (template + last history entry). Unlike R470
                // HistoryPanel / R477 Scanner / R478 Target / R482
                // Scanner-row / R483 Target-row (all of which call
                // historyShow() to fetch request_raw + response_raw),
                // this one reads directly from the tab's template +
                // last history entry ”” no backend round-trip, no
                // transaction_id required. **Mechanism** synthesizes
                // a RequestForCopy inline from `template.url` +
                // `template.method` + `template.headers.items` +
                // base64-decoded `template.body`; parses the last
                // send's rendered response text via renderRawResponse;
                // feeds both into buildHarEntry + buildHarLog, copies
                // pretty-printed JSON to clipboard. Byte-identical
                // HAR 1.2 shape to R470/R477/R478/R479/R482/R483.
                // Natural pair with R467 "Save last response" + R454
                // Alt+Shift+S save ”” three input paths for Repeater
                // response export (txt save / txt save keyboard /
                // HAR copy). **Disabled gate** history empty OR last
                // entry has no response (error-only skip).
                {
                  label: "ðŸ“‹ Copy last send as HAR entry",
                  hint: "zero-RPC HAR 1.2 log · template + last send",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    if (!last || !last.response) return true;
                    return !tabMenu.data!.template?.url;
                  })(),
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const tpl = t.template;
                    const h = t.history ?? [];
                    if (h.length === 0 || !tpl?.url) return;
                    const last = h[h.length - 1];
                    if (!last || !last.response) return;
                    try {
                      // Build RequestForCopy from the tab's template.
                      const headers: Array<[string, string]> = (
                        tpl.headers?.items ?? []
                      ).map((hdr: any) => [hdr.name, hdr.value] as [string, string]);
                      let body = "";
                      if (tpl.body) {
                        try {
                          body = atob(tpl.body);
                        } catch {
                          body = "";
                        }
                      }
                      const req = {
                        url: tpl.url,
                        method: (tpl.method || "GET").toUpperCase(),
                        headers,
                        body,
                      };
                      // Parse the stored response from renderRawResponse.
                      const respText = renderRawResponse(
                        last.response,
                        last.error,
                      );
                      const normalized = respText.replace(/\r\n/g, "\n");
                      const headerEnd = normalized.indexOf("\n\n");
                      const headerBlock =
                        headerEnd >= 0
                          ? normalized.slice(0, headerEnd)
                          : normalized;
                      const respBody =
                        headerEnd >= 0 ? normalized.slice(headerEnd + 2) : "";
                      const lines = headerBlock.split("\n");
                      const statusLine = (lines.shift() ?? "").trim();
                      const m = statusLine.match(
                        /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                      );
                      const httpVersion = m?.[1] ?? "HTTP/1.1";
                      const status = m ? parseInt(m[2], 10) : 0;
                      const statusText = m?.[3] ?? "";
                      const respHeaders: Array<[string, string]> = [];
                      let mimeType = "";
                      for (const l of lines) {
                        const colon = l.indexOf(":");
                        if (colon <= 0) continue;
                        const n = l.slice(0, colon).trim();
                        const v = l.slice(colon + 1).trim();
                        if (!n) continue;
                        respHeaders.push([n, v]);
                        if (n.toLowerCase() === "content-type") mimeType = v;
                      }
                      const resp = {
                        status,
                        statusText,
                        httpVersion,
                        headers: respHeaders,
                        mimeType,
                        body: respBody,
                      };
                      // Repeater sends don't carry a ts_ms directly ””
                      // fall back to "now" so the HAR entry gets a
                      // plausible startedDateTime (HAR consumers
                      // tolerate drift here, so this is cosmetic).
                      const startedDateTime = new Date().toISOString();
                      const entry = buildHarEntry(req, startedDateTime, resp);
                      const har = buildHarLog([entry]);
                      await navigator.clipboard.writeText(
                        JSON.stringify(har, null, 2),
                      );
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R505: Tab-menu "â¬‡ Save last send as HAR file" ””
                // file-save variant of R484 Repeater clipboard HAR.
                // Mirrors R490 History bulk + R504 Scanner bulk
                // file-save pattern. Writes a .har file to disk
                // via Blob + anchor click instead of clipboard,
                // using the same zero-RPC in-memory tab state
                // synthesis as R484 (template URL + method +
                // headers + body + renderRawResponse). Operators
                // attaching Repeater exchanges to tickets want
                // a .har file not a clipboard paste. Filename
                // pattern `repeater-<tab-name>-<timestamp>.har`
                // ”” includes the tab name so operators juggling
                // multiple Repeater tabs can identify the source
                // in a shared ticket inbox.
                {
                  label: "â¬‡ Save last send as HAR file",
                  hint: "zero-RPC HAR 1.2 · template + last send",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    if (!last || !last.response) return true;
                    return !tabMenu.data!.template?.url;
                  })(),
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const tpl = t.template;
                    const h = t.history ?? [];
                    if (h.length === 0 || !tpl?.url) return;
                    const last = h[h.length - 1];
                    if (!last || !last.response) return;
                    try {
                      const headers: Array<[string, string]> = (
                        tpl.headers?.items ?? []
                      ).map((hdr: any) => [hdr.name, hdr.value] as [string, string]);
                      let body = "";
                      if (tpl.body) {
                        try {
                          body = atob(tpl.body);
                        } catch {
                          body = "";
                        }
                      }
                      const req = {
                        url: tpl.url,
                        method: (tpl.method || "GET").toUpperCase(),
                        headers,
                        body,
                      };
                      const respText = renderRawResponse(
                        last.response,
                        last.error,
                      );
                      const normalized = respText.replace(/\r\n/g, "\n");
                      const headerEnd = normalized.indexOf("\n\n");
                      const headerBlock =
                        headerEnd >= 0
                          ? normalized.slice(0, headerEnd)
                          : normalized;
                      const respBody =
                        headerEnd >= 0 ? normalized.slice(headerEnd + 2) : "";
                      const lines = headerBlock.split("\n");
                      const statusLine = (lines.shift() ?? "").trim();
                      const m = statusLine.match(
                        /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                      );
                      const httpVersion = m?.[1] ?? "HTTP/1.1";
                      const status = m ? parseInt(m[2], 10) : 0;
                      const statusText = m?.[3] ?? "";
                      const respHeaders: Array<[string, string]> = [];
                      let mimeType = "";
                      for (const l of lines) {
                        const colon = l.indexOf(":");
                        if (colon <= 0) continue;
                        const n = l.slice(0, colon).trim();
                        const v = l.slice(colon + 1).trim();
                        if (!n) continue;
                        respHeaders.push([n, v]);
                        if (n.toLowerCase() === "content-type") mimeType = v;
                      }
                      const resp = {
                        status,
                        statusText,
                        httpVersion,
                        headers: respHeaders,
                        mimeType,
                        body: respBody,
                      };
                      const startedDateTime = new Date().toISOString();
                      const entry = buildHarEntry(req, startedDateTime, resp);
                      const har = buildHarLog([entry]);
                      const stamp = new Date()
                        .toISOString()
                        .replace(/[:T]/g, "-")
                        .replace(/\..*$/, "");
                      const safeName = (t.name || "repeater")
                        .replace(/[^a-z0-9_-]+/gi, "-")
                        .slice(0, 40) || "repeater";
                      const name = `repeater-${safeName}-${stamp}.har`;
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
                // R522: Tab-menu "â¬‡ Save last request" ”” parallel
                // to R467 "â¬‡ Save last response", completes the
                // request/response save pair at the Repeater tab
                // level. Operators attaching Repeater exchanges to
                // tickets want both halves on disk; R467 handled
                // the response half, R522 ships the request half.
                // Zero backend ”” the request text is already in-
                // memory via the `renderRaw(template)` helper that
                // the raw-request editor pane uses. Mechanism:
                // renderRaw builds the same `METHOD path HTTP/x\r\n
                // headers\r\n\r\nbody` text that the editor shows,
                // Blob + anchor save writes it to disk. **Filename
                // pattern** `request-<safeName>.txt` where safeName
                // is the sanitized tab name ”” ties the saved
                // request back to the tab even after the tab is
                // closed, parallel to R505's `repeater-<safeName>-
                // <timestamp>.har` convention. Omits a timestamp
                // since the request template is pre-send (not
                // per-attempt); if an operator wants a specific
                // send's request, R454 Alt+Shift+S saves the full
                // response of the selected send and operators can
                // combine it with the stable request template.
                // Disabled gate: tabMenu.data must exist (always
                // true in this context) ”” the request template
                // exists for every tab, even an empty one, so no
                // further gate needed.
                {
                  label: "â¬‡ Save last request",
                  hint: "the raw request text (method + headers + body)",
                  onClick: () => {
                    const t = tabMenu.data!;
                    const text = renderRaw(t.template);
                    const safeName =
                      (t.name || "")
                        .replace(/[^A-Za-z0-9_-]+/g, "-")
                        .replace(/^-|-$/g, "")
                        .slice(0, 40) || "repeater";
                    const name = `request-${safeName}.txt`;
                    try {
                      const blob = new Blob([text], {
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
                // R610: Tab-menu "ðŸ“‹ Copy last request" ”” clipboard
                // mirror of R522 "â¬‡ Save last request". Where R522
                // writes the raw request text to disk for ticket
                // attachments, R610 drops the same text onto the
                // clipboard so operators can paste directly into a
                // chat / scratchpad / curl --data-raw @- stdin
                // without the file-save roundtrip. Reuses renderRaw
                // for byte-identical output.
                {
                  label: "ðŸ“‹ Copy last request",
                  hint: "the raw request text ”” clipboard-only",
                  onClick: async () => {
                    const t = tabMenu.data!;
                    try {
                      await navigator.clipboard.writeText(renderRaw(t.template));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                {
                  label: "â¬‡ Save last response",
                  hint: "the most recent send's raw response",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    return !last || !last.response;
                  })(),
                  onClick: () => {
                    const t = tabMenu.data!;
                    const h = t.history ?? [];
                    if (h.length === 0) return;
                    const idx = h.length - 1;
                    const s = h[idx];
                    if (!s || !s.response) return;
                    const status = s.response.status ?? "unknown";
                    const name = `response-send${idx + 1}-${status}.txt`;
                    const body = renderRawResponse(s.response, s.error);
                    try {
                      const blob = new Blob([body], {
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
                // R519: Tab-menu "ðŸ“‹ Copy last response body" ””
                // clipboard mirror of R516's "â¬‡ Save last response
                // body". Where R516 writes a .json/.html/.bin/… file
                // for OS-level inspection (hex editor, browser,
                // viewer), R519 drops just the decoded body text
                // onto the clipboard for pasting into another tool
                // (jq / grep / an online JSON formatter / a text
                // diff viewer / a scratch note). Natural pair with
                // R516 and completes the body-ops cluster: Save /
                // Copy for the body, plus R467 Save / R484 Copy as
                // HAR for the full response. Mechanism matches R516
                // for the base64 â†’ bytes decode but takes a different
                // branch for the clipboard target: text content types
                // (json / html / xml / javascript / css / text/*) get
                // the decoded UTF-8 string copied as text; binary
                // content types (image/* / application/pdf / etc.)
                // skip with a hint explaining the clipboard isn't
                // a sensible sink for the payload. **Content-type
                // routing** reuses the extension-switch logic from
                // R516 but inverts the decision: "textish" => copy,
                // "binary" => skip. Disabled gate matches R516 ”” no
                // last send with a response body skips gracefully.
                {
                  label: "ðŸ“‹ Copy last response body",
                  hint: "just the payload ”” text types only (json/html/xml/…)",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    return !last || !last.response || !last.response.body;
                  })(),
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const h = t.history ?? [];
                    if (h.length === 0) return;
                    const idx = h.length - 1;
                    const s = h[idx];
                    if (!s || !s.response || !s.response.body) return;
                    // Content-Type gate ”” clipboard is for text,
                    // not binary. Walk headers case-insensitively.
                    const ctHeader = (s.response.headers?.items || []).find(
                      (h: any) => h.name?.toLowerCase?.() === "content-type",
                    );
                    const ctRaw = (ctHeader?.value ?? "").toLowerCase();
                    const mime =
                      ctRaw.split(";")[0].trim() || "application/octet-stream";
                    const isTextish =
                      mime.includes("json") ||
                      mime.includes("html") ||
                      mime.includes("xml") ||
                      mime.includes("javascript") ||
                      mime.includes("css") ||
                      mime.startsWith("text/") ||
                      mime === "application/octet-stream";
                    if (!isTextish) {
                      alert(
                        `Response body is ${mime} ”” clipboard copy is only sensible for text content types. Use "â¬‡ Save last response body" to write the binary bytes to a file instead.`,
                      );
                      return;
                    }
                    try {
                      // atob decodes base64 to a Latin-1 string
                      // where each char code is the original byte.
                      // For UTF-8 text, we re-encode by walking the
                      // bytes through a TextDecoder so multibyte
                      // sequences (emoji, non-ASCII chars) render
                      // correctly on the clipboard. Fallback to
                      // raw atob output for safety if TextDecoder
                      // isn't available.
                      const bin = atob(s.response.body);
                      let text = bin;
                      try {
                        const bytes = new Uint8Array(bin.length);
                        for (let i = 0; i < bin.length; i++)
                          bytes[i] = bin.charCodeAt(i);
                        text = new TextDecoder("utf-8", { fatal: false }).decode(
                          bytes,
                        );
                      } catch {
                        /* fall through to Latin-1 string */
                      }
                      await navigator.clipboard.writeText(text);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R608: Tab-menu "ðŸ“‹ Copy last response headers" ””
                // headers-only clipboard sibling of R519 "ðŸ“‹ Copy
                // last response body". Operators debugging CORS /
                // auth / caching behaviour want just the header
                // block without the status line, the body, or the
                // request portion. Format "Name: value" per line,
                // which is the same shape a server-sent response
                // uses. Byte-safe for any content type since we
                // never touch the body. Disabled when the tab has
                // no sends or the last send has no response.
                {
                  label: "ðŸ“‹ Copy last response headers",
                  hint: "just the Name: value block",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    const items = last?.response?.headers?.items ?? [];
                    return items.length === 0;
                  })(),
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const h = t.history ?? [];
                    if (h.length === 0) return;
                    const last = h[h.length - 1];
                    const items = last?.response?.headers?.items ?? [];
                    if (items.length === 0) return;
                    const text = items
                      .map((h: any) => `${h.name}: ${h.value}`)
                      .join("\r\n");
                    try {
                      await navigator.clipboard.writeText(text);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R609: Tab-menu "ðŸ“‹ Copy last response status line" ””
                // the single-line status + reason + http version.
                // Operators often screenshot or log just this one
                // line as evidence ("got 401 instead of 200") so a
                // dedicated clipboard entry saves them hunting
                // through the full-raw copy. Format matches the
                // wire: "HTTP/<ver> <status> <reason>". Falls back
                // to just the status when reason is empty.
                {
                  label: "ðŸ“‹ Copy last response status line",
                  hint: "HTTP/x.y 200 OK ”” one line",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    return last?.response?.status == null;
                  })(),
                  onClick: async () => {
                    const t = tabMenu.data!;
                    const h = t.history ?? [];
                    if (h.length === 0) return;
                    const last = h[h.length - 1];
                    const resp = last?.response;
                    if (!resp || resp.status == null) return;
                    const ver = httpVersionToken(resp.http_version);
                    const reason = resp.reason || "";
                    const line = reason
                      ? `${ver} ${resp.status} ${reason}`
                      : `${ver} ${resp.status}`;
                    try {
                      await navigator.clipboard.writeText(line);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R516: Tab-menu "â¬‡ Save last response body" ”” body-
                // only variant of R467's "Save last response". R467
                // saves the full raw response text (status line +
                // headers + body) as .txt, which is great for
                // ticket attachments but awkward when operators
                // want just the payload ”” e.g., a downloaded JSON
                // blob, an HTML page to render, a binary file. R516
                // extracts just the base64-decoded response body
                // and writes it with a content-type-aware
                // extension (.json / .html / .xml / .png / .js /
                // .css / .bin fallback) so the OS picks the right
                // default viewer. Mechanism: `atob(resp.body)` for
                // the raw bytes, Content-Type header lookup for the
                // extension pick, Blob with the matching MIME type
                // for a browser-friendly save dialog. **Filename
                // pattern** `response-body-send<idx>-<status>.<ext>`
                // mirrors R467's `response-send<idx>-<status>.txt`
                // naming but with the content-aware extension and
                // a `-body` marker so operators archiving both
                // flavors keep them distinct. Disabled gate matches
                // R467 ”” needs a last send with a response.
                {
                  label: "â¬‡ Save last response body",
                  hint: "just the payload ”” content-aware extension (.json/.html/.bin/…)",
                  disabled: (() => {
                    const h = tabMenu.data!.history ?? [];
                    if (h.length === 0) return true;
                    const last = h[h.length - 1];
                    return !last || !last.response || !last.response.body;
                  })(),
                  onClick: () => {
                    const t = tabMenu.data!;
                    const h = t.history ?? [];
                    if (h.length === 0) return;
                    const idx = h.length - 1;
                    const s = h[idx];
                    if (!s || !s.response || !s.response.body) return;
                    const status = s.response.status ?? "unknown";
                    // Base64-decode the body bytes. atob returns a
                    // Latin-1 string where each char code is the
                    // original byte; we round-trip through
                    // Uint8Array for a proper binary blob so .png
                    // / .pdf / etc. are preserved intact.
                    let bytes: Uint8Array;
                    try {
                      const bin = atob(s.response.body);
                      bytes = new Uint8Array(bin.length);
                      for (let i = 0; i < bin.length; i++)
                        bytes[i] = bin.charCodeAt(i);
                    } catch (err) {
                      alert(`Could not decode response body: ${err}`);
                      return;
                    }
                    // Parse Content-Type for a sensible extension
                    // + MIME. Default to .bin / octet-stream so
                    // unknown types still produce a usable file.
                    const ctHeader = (s.response.headers?.items || []).find(
                      (h: any) => h.name?.toLowerCase?.() === "content-type",
                    );
                    const ctRaw = (ctHeader?.value ?? "").toLowerCase();
                    const mime = ctRaw.split(";")[0].trim() ||
                      "application/octet-stream";
                    const ext = (() => {
                      if (mime.includes("json")) return "json";
                      if (mime.includes("html")) return "html";
                      if (mime.includes("xml")) return "xml";
                      if (mime.includes("javascript")) return "js";
                      if (mime.includes("css")) return "css";
                      if (mime === "text/plain") return "txt";
                      if (mime.startsWith("image/")) {
                        const sub = mime.slice(6);
                        return sub === "jpeg" ? "jpg" : sub || "img";
                      }
                      if (mime === "application/pdf") return "pdf";
                      if (mime.startsWith("text/")) return "txt";
                      return "bin";
                    })();
                    const name = `response-body-send${idx + 1}-${status}.${ext}`;
                    try {
                      // Copy bytes into a fresh ArrayBuffer to
                      // satisfy TS strict's BlobPart constraint
                      // (Uint8Array.buffer is ArrayBufferLike which
                      // may include SharedArrayBuffer; Blob wants
                      // a plain ArrayBuffer).
                      const buf = new ArrayBuffer(bytes.length);
                      new Uint8Array(buf).set(bytes);
                      const blob = new Blob([buf], { type: mime });
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
                {
                  label: `Clear history (${tabMenu.data!.history.length})`,
                  disabled: (tabMenu.data!.history.length ?? 0) === 0,
                  danger: true,
                  hint: "wipe sends, keep tab",
                  onClick: () => {
                    const t = tabMenu.data!;
                    const n = t.history.length;
                    if (!confirm(`Clear ${n} response${n === 1 ? "" : "s"} from "${t.name}"? The tab itself stays.`)) return;
                    void clearTabHistory(t.id);
                  },
                },
                { separator: true },
                // ---- Group operations ---------------------------------
                ...(existingGroups.length > 0
                  ? existingGroups
                      .filter((g) => g !== tabMenu.data!.group)
                      .map((g) => ({
                        label: `Add to group â†’ ${g}`,
                        onClick: () => void addToGroup(tabMenu.data!.id, g),
                      }))
                  : []),
                {
                  label: "Add to new group…",
                  onClick: () => void addToNewGroup(tabMenu.data!.id),
                },
                {
                  label: "Remove from group",
                  disabled: !tabMenu.data!.group,
                  hint: tabMenu.data!.group ?? undefined,
                  onClick: () => void addToGroup(tabMenu.data!.id, null),
                },
                { separator: true },
                {
                  label: "Close tab",
                  danger: true,
                  onClick: () => void closeTab(tabMenu.data!.id),
                },
                {
                  label: "Close other tabs",
                  danger: true,
                  disabled: tabs.length <= 1,
                  onClick: () => void closeOtherTabs(tabMenu.data!.id),
                },
                {
                  label: "Close tabs to the right",
                  danger: true,
                  disabled:
                    tabs.findIndex((t) => t.id === tabMenu.data!.id) >=
                    tabs.length - 1,
                  onClick: () => void closeTabsToRight(tabMenu.data!.id),
                },
                /* R165: Close every unpinned tab in one shot ”” the    */
                /* "clean slate between engagements" operation. Pinned */
                /* tabs always survive matching the existing close-*   */
                /* semantics. Disabled when there are zero unpinned.   */
                /* tabs. Confirms with the exact victim count so the   */
                /* operator sees the blast radius pre-click.           */
                {
                  label: "Close all unpinned tabs",
                  danger: true,
                  disabled: tabs.filter((t) => !t.pinned).length === 0,
                  hint: `${tabs.filter((t) => !t.pinned).length} unpinned`,
                  onClick: async () => {
                    const victims = tabs.filter((t) => !t.pinned).map((t) => t.id);
                    const pinnedKept = tabs.length - victims.length;
                    if (victims.length === 0) return;
                    const extra =
                      pinnedKept > 0
                        ? ` (${pinnedKept} pinned tab${pinnedKept === 1 ? "" : "s"} kept)`
                        : "";
                    if (
                      !confirm(
                        `Close ${victims.length} unpinned tab${victims.length === 1 ? "" : "s"}${extra}?`,
                      )
                    )
                      return;
                    try {
                      await Promise.allSettled(
                        victims.map((id) => api.repeaterRemove(id)),
                      );
                      // Match closeOtherTabs' active-tab handling:
                      // if the current active was in the victims
                      // list, drop the selection so the UI doesn't
                      // flash a dead highlight.
                      if (active != null && victims.includes(active)) {
                        setActive(null);
                      }
                      await refresh();
                    } catch (e) {
                      alert(`Close all unpinned failed: ${e}`);
                    }
                  },
                },
              ]
            : []
        }
      />
      <FloatingMenu
        state={groupMenu}
        onClose={() => setGroupMenu(null)}
        items={
          groupMenu?.data
            ? [
                {
                  label: `Send all in group (sequential)`,
                  hint: `${tabs.filter((t) => t.group === groupMenu.data).length} tabs`,
                  disabled: busy,
                  onClick: () => void sendGroup(groupMenu.data!, "sequential"),
                },
                {
                  label: `Send all in group (parallel)`,
                  hint: "fan-out",
                  disabled: busy,
                  onClick: () => void sendGroup(groupMenu.data!, "parallel"),
                },
                { separator: true },
                {
                  label: "ðŸ“Œ Pin all tabs in group",
                  hint: "protects every member from bulk closes",
                  onClick: () => void pinAllInGroup(groupMenu.data!, true),
                  disabled: tabs
                    .filter((t) => t.group === groupMenu.data)
                    .every((t) => t.pinned),
                },
                {
                  label: "ðŸ“Œ Unpin all tabs in group",
                  hint: "removes bulk-close protection for every member",
                  onClick: () => void pinAllInGroup(groupMenu.data!, false),
                  disabled: tabs
                    .filter((t) => t.group === groupMenu.data)
                    .every((t) => !t.pinned),
                },
                { separator: true },
                {
                  label: (groupCollapsed[groupMenu.data!] ?? false)
                    ? "Expand group"
                    : "Collapse group",
                  onClick: () =>
                    setGroupCollapsed((prev) => ({
                      ...prev,
                      [groupMenu.data!]: !(prev[groupMenu.data!] ?? false),
                    })),
                },
                {
                  label: "Rename group…",
                  onClick: () => void renameGroup(groupMenu.data!),
                },
                { separator: true },
                {
                  label: "Ungroup all members",
                  danger: true,
                  onClick: () => void deleteGroup(groupMenu.data!),
                },
              ]
            : []
        }
      />
      <DiscoveryModal
        open={discoveryPreset !== null}
        preset={discoveryPreset}
        onClose={() => setDiscoveryPreset(null)}
      />
    </div>
  );
}

const METHOD_PRESETS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/** Human-readable age for a timestamp. Buckets at s/m/h/d so the
 *  rendered chip hint stays compact (operators hover tabs ”” not
 *  stare ”” so precision past the bucket isn't useful). */
function formatAge(tsMs: number, now: number = Date.now()): string {
  const d = Math.max(0, Math.floor((now - tsMs) / 1000));
  if (d < 60) return `${d}s`;
  if (d < 3600) return `${Math.floor(d / 60)}m`;
  if (d < 86_400) return `${Math.floor(d / 3600)}h`;
  return `${Math.floor(d / 86_400)}d`;
}

/** Compact byte size for the chip hint. Mirrors Burp's "1.2K" /
 *  "340K" / "2.1M" formatting. */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)}K`;
  return `${(bytes / 1024 / 1024).toFixed(1)}M`;
}

/** Last-send status glyph for a Repeater tab chip. Returns null
 *  when the tab has never been sent so the chip stays uncluttered.
 *  Order matters: an errored send shows orange even if `response`
 *  carried something earlier. */
function tabStatusGlyph(tab: RepeaterTab): {
  color: string;
  tooltip: string;
} | null {
  const last = tab.history?.[tab.history.length - 1];
  if (!last) return null;
  const age = formatAge(last.ts_ms);
  if (last.error) {
    return {
      color: "rgba(243,156,59,0.95)",
      tooltip: `Last send: ${age} ago · error: ${last.error}`,
    };
  }
  const status = last.response?.status;
  if (status == null) {
    return {
      color: "rgba(243,156,59,0.95)",
      tooltip: `Last send: ${age} ago · no response`,
    };
  }
  const bodyLen = last.response?.body?.length ?? 0;
  const elapsed = last.elapsed_ms ?? 0;
  const color =
    status >= 200 && status < 300
      ? "rgba(75,191,107,0.95)"
      : status >= 300 && status < 400
        ? "rgba(240,210,52,0.95)"
        : "rgba(239,75,75,0.95)";
  const tooltip = `Last send: ${age} ago · status ${status} · ${formatSize(bodyLen)} body · ${elapsed} ms`;
  return { color, tooltip };
}

/** Inspect a RepeaterTab's template to figure out which body-encoding
 *  the dropdown should show as currently selected. */
function detectEncoding(template: any): "plain" | "gzip" | "chunked" {
  const headers = template?.headers?.items ?? [];
  const te = headers.find((h: any) => (h.name || "").toLowerCase() === "transfer-encoding");
  if (te && String(te.value).toLowerCase().includes("chunked")) return "chunked";
  const ce = headers.find((h: any) => (h.name || "").toLowerCase() === "content-encoding");
  if (ce && String(ce.value).toLowerCase().includes("gzip")) return "gzip";
  return "plain";
}
const COLOR_PRESETS = [
  { label: "Colour: red",    value: "#e04444" },
  { label: "Colour: orange", value: "#e08844" },
  { label: "Colour: yellow", value: "#d4c344" },
  { label: "Colour: green",  value: "#4ac66c" },
  { label: "Colour: blue",   value: "#3a9df7" },
  { label: "Colour: violet", value: "#a56cf0" },
];


/* ------------------ history strip + diff ------------------ */

function HistoryStrip({
  tab,
  selected,
  onSelect,
  diffA,
  diffB,
  onDiffA,
  onDiffB,
  onRunDiff,
  onClearDiff,
  onClearHistory,
}: {
  tab: RepeaterTab | null;
  selected: number | null;
  onSelect: (i: number) => void;
  diffA: number | null;
  diffB: number | null;
  onDiffA: (i: number) => void;
  onDiffB: (i: number) => void;
  onRunDiff: () => void;
  onClearDiff: () => void;
  // Nukes every send in this tab's history; the parent is
  // responsible for confirming + refreshing. Receives the tab id so
  // one callback can serve multiple tabs if we ever surface it in a
  // non-active context.
  onClearHistory: (id: number) => void;
}) {
  if (!tab || tab.history.length === 0) return null;
  return (
    <div
      style={{
        padding: "4px 10px",
        borderTop: "1px solid var(--border)",
        display: "flex",
        gap: 6,
        alignItems: "center",
        overflowX: "auto",
        fontSize: 11,
      }}
    >
      <span style={{ color: "var(--text-dim)" }}>Sends:</span>
      {tab.history.map((s, i) => {
        const status = s.response?.status ?? (s.error ? "ERR" : "””");
        const size = s.response?.body?.length ?? 0;
        const isSel = selected === i;
        const isA = diffA === i;
        const isB = diffB === i;
        return (
          <button
            key={s.id}
            onClick={() => onSelect(i)}
            onContextMenu={(e) => {
              e.preventDefault();
              // Right-click toggles diff anchors: first fills A, second fills B.
              if (diffA === null) onDiffA(i);
              else if (diffB === null && diffA !== i) onDiffB(i);
              else {
                onDiffA(i);
                onDiffB(null as unknown as number);
              }
            }}
            className={isSel ? "primary" : "ghost"}
            style={{
              padding: "2px 8px",
              borderRadius: 10,
              fontSize: 11,
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              border:
                isA || isB ? `1px solid var(--accent, #3a9df7)` : "1px solid var(--border)",
              whiteSpace: "nowrap",
            }}
            title={`Send #${i + 1} · ${status} · ${size}B · ${s.elapsed_ms}ms (right-click = pin for diff)${(() => {
              // R789: Rich tooltip with trend info ”” relative-time
              // delta vs previous send surfaces whether the target
              // got noticeably slower or faster between sends.
              // Threshold: 10% change = ignore (noise), else show
              // the direction with the delta.
              if (i === 0) return "";
              const prev = tab.history[i - 1];
              const curMs = s.elapsed_ms ?? 0;
              const prevMs = prev.elapsed_ms ?? 0;
              if (!curMs || !prevMs) return "";
              const delta = curMs - prevMs;
              const pct = Math.abs(delta) / prevMs;
              if (pct < 0.1) return "";
              if (delta > 0) return `\nâ†— ${delta}ms slower vs #${i} (+${(pct * 100).toFixed(0)}%)`;
              return `\nâ†˜ ${-delta}ms faster vs #${i} (-${(pct * 100).toFixed(0)}%)`;
            })()}`}
          >
            <span className={`severity-${severityFromStatus(status)}`}>#{i + 1}</span>
            <span className="mono">{status}</span>
            <span style={{ color: "var(--text-dim)" }}>
              {size}B · {s.elapsed_ms}ms
            </span>
            {/* R789: Burp-identical response-time trend arrow ””
                compares current send's elapsed_ms with the
                previous send's. â†— amber when slower by >10%, â†˜
                green when faster by >10%, hidden when first send
                or delta is within Â±10% noise. Operators probing
                for behavior changes (did my payload make the
                server slower?) spot the trend without opening a
                diff pane. */}
            {(() => {
              if (i === 0) return null;
              const prev = tab.history[i - 1];
              const curMs = s.elapsed_ms ?? 0;
              const prevMs = prev.elapsed_ms ?? 0;
              if (!curMs || !prevMs) return null;
              const delta = curMs - prevMs;
              const pct = Math.abs(delta) / prevMs;
              if (pct < 0.1) return null;
              if (delta > 0) {
                return (
                  <span
                    style={{
                      color: "var(--amber, #e3a74a)",
                      fontSize: 10,
                    }}
                  >
                    â†—
                  </span>
                );
              }
              return (
                <span
                  style={{
                    color: "var(--green, #4caf50)",
                    fontSize: 10,
                  }}
                >
                  â†˜
                </span>
              );
            })()}
            {isA && <span style={{ color: "var(--accent, #3a9df7)" }}> A</span>}
            {isB && <span style={{ color: "var(--accent, #3a9df7)" }}> B</span>}
          </button>
        );
      })}
      <span style={{ flex: 1 }} />
      {/* R406: "ðŸ’¾ Save" button for the currently-selected send's   */}
      {/* raw response. Operators previewing a specific send in the  */}
      {/* response pane want one-click file save without a right-   */}
      {/* click â†’ "Save response to file" dance; the HistoryStrip   */}
      {/* button fires on the currently-selected send so operators  */}
      {/* can walk the sends list (click chip N â†’ ðŸ’¾ Save â†’ click    */}
      {/* chip N+1 â†’ ðŸ’¾ Save) through a batch of interesting        */}
      {/* responses. **Visibility gate** `selected != null` AND     */}
      {/* the selected send has a response (not an error-only).     */}
      {/* **Filename** `response-send<idx>-<status>.txt` so repeat  */}
      {/* saves across sends don't clobber each other; the status  */}
      {/* code tags the file as success / redirect / server-error. */}
      {/* **Mechanism** inline Blob+anchor since RepeaterPanel's   */}
      {/* `downloadText` lives inside the parent closure, not       */}
      {/* module-scope. Matches R401's Scanner save idiom.          */}
      {tab && selected != null && tab.history[selected]?.response && (() => {
        const s = tab.history[selected];
        const status = s.response?.status ?? "unknown";
        const name = `response-send${selected + 1}-${status}.txt`;
        const body = renderRawResponse(s.response, s.error);
        return (
          <button
            className="ghost"
            onClick={() => {
              const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = name;
              a.click();
              URL.revokeObjectURL(url);
            }}
            title={`Save the response from send #${selected + 1} (status ${status}, ${s.response?.body?.length ?? 0}B body, ${s.elapsed_ms}ms) to "${name}" ”” full status line + headers + body. Great for a PoC bundle or ticket attachment where you want the specific captured response rather than the current live state.`}
          >
            ðŸ’¾ Save
          </button>
        );
      })()}
      {/* R405: Aggregate stats badge for the active tab's sends ””   */}
      {/* n (count), avg ms, p95 ms, total bytes. Operators doing   */}
      {/* perf-sensitive flows (rate-limit probing, timing attacks,  */}
      {/* cache-warming) want a one-glance read of latency trends    */}
      {/* across the send history without eyeballing each chip's    */}
      {/* "Xms" number. Only renders with 2+ sends ”” a single send  */}
      {/* has no meaningful average/percentile. **p95 computation** */}
      {/* sorts in-memory which is O(n log n) but n is bounded by  */}
      {/* the tab history cap (currently 50 sends), so this stays   */}
      {/* under 1 ms even on a saturated tab. **Rendering** compact */}
      {/* "n=12 · avg 48 ms · p95 112 ms · 2.4K" so the badge        */}
      {/* doesn't crowd the toolbar. Tooltip spells out each stat.   */}
      {tab && tab.history.length >= 2 && (() => {
        const sends = tab.history.filter((s) => !s.error);
        if (sends.length === 0) return null;
        const elapsed = sends
          .map((s) => s.elapsed_ms ?? 0)
          .filter((n) => n > 0);
        if (elapsed.length === 0) return null;
        const sorted = [...elapsed].sort((a, b) => a - b);
        const avg = elapsed.reduce((a, b) => a + b, 0) / elapsed.length;
        const p95Idx = Math.min(
          sorted.length - 1,
          Math.ceil(sorted.length * 0.95) - 1,
        );
        const p95 = sorted[Math.max(0, p95Idx)];
        const totalBytes = sends.reduce(
          (acc, s) => acc + (s.response?.body?.length ?? 0),
          0,
        );
        const fmtBytes = (n: number) =>
          n < 1024
            ? `${n}B`
            : n < 1024 * 1024
              ? `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)}K`
              : `${(n / 1024 / 1024).toFixed(1)}M`;
        return (
          <span
            style={{
              fontSize: 10.5,
              color: "var(--text-dim)",
              padding: "2px 6px",
              borderRadius: 10,
              border: "1px solid var(--border-dim, rgba(128,128,128,0.2))",
              whiteSpace: "nowrap",
            }}
            title={`Aggregate stats across ${sends.length} successful send${sends.length === 1 ? "" : "s"} on "${tab.name}":\n”¢ n = ${sends.length} successful (of ${tab.history.length} total)\n”¢ avg elapsed = ${avg.toFixed(1)} ms\n”¢ p95 elapsed = ${p95} ms\n”¢ total response body = ${fmtBytes(totalBytes)}`}
          >
            ðŸ“Š n={sends.length} · avg {avg.toFixed(0)}ms · p95 {p95}ms · {fmtBytes(totalBytes)}
          </span>
        );
      })()}
      {/* R340: "Diff last two" quick button ”” operators iterating    */}
      {/* on a request body often want to see what changed between    */}
      {/* the two most recent sends. Rather than right-click A then  */}
      {/* right-click B then click "Diff Aâ†”B", this one-click sets    */}
      {/* diffA = history.length-2 + diffB = history.length-1 +      */}
      {/* immediately runs the comparer. Renders when the tab has    */}
      {/* â‰¥2 sends so idle sessions / fresh tabs don't carry a dead  */}
      {/* button. Replaces whatever diff anchors were set previously */}
      {/* (operators iterating keep hitting it between tweaks).      */}
      {tab && tab.history.length >= 2 && (
        <button
          onClick={() => {
            if (!tab || tab.history.length < 2) return;
            const n = tab.history.length;
            onDiffA(n - 2);
            onDiffB(n - 1);
            // onRunDiff reads diffA/diffB from closure. Give React a
            // tick to flush the setters before firing the diff.
            setTimeout(() => onRunDiff(), 0);
          }}
          title={`Diff the two most recent sends (#${tab.history.length - 1} vs #${tab.history.length}). One-click shortcut for the common "did my tweak change anything?" iteration flow ”” replaces whatever diff anchors were set previously.`}
        >
          Diff last 2
        </button>
      )}
      {(diffA !== null || diffB !== null) && (
        <>
          <button
            disabled={diffA === null || diffB === null || diffA === diffB}
            onClick={onRunDiff}
            title="Compare response bodies of sends A vs B inline"
          >
            Diff Aâ†”B
          </button>
          <button
            disabled={diffA === null || diffB === null || diffA === diffB}
            onClick={() => {
              if (!tab) return;
              if (diffA == null || diffB == null) return;
              const left = tab.history[diffA];
              const right = tab.history[diffB];
              if (!left || !right) return;
              const toText = (x: typeof left) =>
                renderRawResponse(x.response, x.error);
              sendToComparer(
                toText(left),
                toText(right),
                `${tab.name} · send #${diffA + 1} vs #${diffB + 1}`,
              );
              window.dispatchEvent(
                new CustomEvent("burpfree:navigate", { detail: { target: "comparer" } }),
              );
            }}
            title="Open these two responses in the Comparer tab"
          >
            Send to Comparer
          </button>
          <button className="ghost" onClick={onClearDiff}>
            clear
          </button>
        </>
      )}
      <button
        className="ghost danger"
        onClick={() => {
          if (!tab) return;
          const n = tab.history.length;
          if (!confirm(`Clear ${n} response${n === 1 ? "" : "s"} from "${tab.name}"? The tab itself stays.`)) return;
          onClearHistory(tab.id);
        }}
        title={`Wipe this tab's ${tab.history.length} response${tab.history.length === 1 ? "" : "s"}. The template, name, pins, colour and group all survive ”” only the Sends list is nuked. Useful for a clean slate between probe iterations.`}
      >
        Clear history
      </button>
    </div>
  );
}

function severityFromStatus(status: number | string): string {
  if (typeof status !== "number") return "info";
  if (status >= 500) return "high";
  if (status >= 400) return "medium";
  if (status >= 300) return "low";
  return "info";
}

/* ðŸŽ¯ R800 ”” 27th round-number milestone this chunk. BurpAiDrawer
 * is the client-side mock of Burp Suite 2026.8's "Burp AI"
 * companion drawer visible in the user's reference screenshot.
 * Renders as a right-side 420px drawer with: header (âœ¦ Burp AI
 * title + âœ• close), chat scroll area pre-populated with a canned
 * greeting + the active tab's method/URL/status/size summary
 * context, prompt input + "Analyze" button that appends a canned
 * analysis response synthesized from the parsed request/response.
 * No AI backend ”” pure template substitution. Operators get a
 * useful inline summary even without a real AI integration. */
function BurpAiDrawer({
  open,
  onClose,
  messages,
  setMessages,
  prompt,
  setPrompt,
  activeTab,
  respRaw,
}: {
  open: boolean;
  onClose: () => void;
  messages: Array<{ role: "user" | "assistant"; text: string }>;
  setMessages: React.Dispatch<
    React.SetStateAction<Array<{ role: "user" | "assistant"; text: string }>>
  >;
  prompt: string;
  setPrompt: (v: string) => void;
  activeTab: RepeaterTab | null;
  respRaw: string;
}) {
  // Build the context message once when the drawer opens ”” a
  // compact summary of the active tab for the AI to "see".
  useEffect(() => {
    if (!open || messages.length > 0) return;
    const lines: string[] = [];
    lines.push("Hi, I'm your BurpFree AI companion âœ¦");
    lines.push("");
    if (!activeTab) {
      lines.push(
        "No active tab ”” click a tab in the Repeater tab bar, send a request, then come back here and I'll analyze the exchange.",
      );
    } else {
      const method = (activeTab.template?.method as string) ?? "GET";
      const url = buildUrlFromTemplate(activeTab.template);
      lines.push(`Target: ${method} ${url}`);
      const last =
        activeTab.history.length > 0
          ? activeTab.history[activeTab.history.length - 1]
          : null;
      if (!last) {
        lines.push("");
        lines.push(
          "No sends recorded yet. Click Send + fire this request, then ask me about the response.",
        );
      } else {
        const status = last.response?.status ?? "(error)";
        const bodyLen = last.response?.body?.length ?? 0;
        const elapsed = last.elapsed_ms ?? 0;
        lines.push(
          `Last send: HTTP ${status} · ${bodyLen} bytes · ${elapsed}ms`,
        );
        if (last.error) lines.push(`Error: ${last.error}`);
      }
      lines.push("");
      lines.push(
        "Ask me anything ”” \"Why is this 403?\", \"Explain the response\", \"Suggest injection probes\", \"What auth is in use?\"",
      );
    }
    setMessages([{ role: "assistant", text: lines.join("\n") }]);
  }, [open, activeTab, messages.length, setMessages]);

  function synthesizeResponse(userPrompt: string): string {
    const p = userPrompt.toLowerCase();
    if (!activeTab) {
      return "I don't have an active Repeater tab to look at. Please pick one and send a request first.";
    }
    const method = (activeTab.template?.method as string) ?? "GET";
    const url = buildUrlFromTemplate(activeTab.template);
    const last =
      activeTab.history.length > 0
        ? activeTab.history[activeTab.history.length - 1]
        : null;
    const status = last?.response?.status;
    // Pattern-match the prompt against common operator questions
    // and synthesize a useful heuristic answer. All text is pure
    // template substitution ”” no AI call.
    const headers: Array<[string, string]> =
      (last?.response?.headers as any) ?? [];
    const header = (name: string): string | null => {
      for (const h of headers) {
        if (
          Array.isArray(h) &&
          h.length >= 2 &&
          typeof h[0] === "string" &&
          h[0].toLowerCase() === name.toLowerCase()
        ) {
          return h[1];
        }
      }
      return null;
    };
    if (/403|forbid/.test(p)) {
      const server = header("Server");
      const auth = header("WWW-Authenticate");
      const parts: string[] = [];
      parts.push("A 403 Forbidden means the server received the request + authenticated the client (if any) but refused to serve the resource. Common causes:");
      parts.push("");
      parts.push("”¢ Missing / wrong authorization (Bearer token, Cookie, API key)");
      parts.push("”¢ IP allow-list (try adding X-Forwarded-For / X-Real-IP headers)");
      parts.push("”¢ CORS pre-flight rejection (check Origin header)");
      parts.push("”¢ Rate limiting (back off + check Retry-After)");
      parts.push("”¢ WAF blocked the request (payload fingerprinting)");
      if (server) parts.push(`\nServer header: ${server}`);
      if (auth) parts.push(`WWW-Authenticate: ${auth}`);
      parts.push("\nTry: Inspector â†’ Request headers to inspect current auth; copy a working request from History â†’ Send to Repeater to compare.");
      return parts.join("\n");
    }
    if (/auth|token|cookie|session/.test(p)) {
      const headerItems: Array<{ name?: string; value?: string }> =
        activeTab.template?.headers?.items ?? [];
      const authHeader = headerItems.find(
        (h) => h.name?.toLowerCase() === "authorization",
      );
      const cookieHeader = headerItems.find(
        (h) => h.name?.toLowerCase() === "cookie",
      );
      const parts: string[] = ["Auth analysis:"];
      if (authHeader?.value) {
        if (/^bearer /i.test(authHeader.value)) {
          parts.push(`\n”¢ Authorization: Bearer <token> ”” JWT or opaque bearer. Try the Decoder panel to decode the JWT payload.`);
        } else if (/^basic /i.test(authHeader.value)) {
          parts.push(`\n”¢ Authorization: Basic <base64> ”” HTTP Basic auth. Decoder panel will base64-decode to 'user:pass'.`);
        } else {
          parts.push(`\n”¢ Authorization: ${authHeader.value.slice(0, 40)}…`);
        }
      } else {
        parts.push("\n”¢ No Authorization header.");
      }
      if (cookieHeader?.value) {
        const cookieNames = cookieHeader.value
          .split(";")
          .map((c) => c.split("=")[0].trim())
          .filter(Boolean);
        parts.push(
          `”¢ Cookies: ${cookieNames.join(", ") || "(empty)"} (${cookieNames.length} total)`,
        );
      } else {
        parts.push("”¢ No Cookie header.");
      }
      parts.push("\nTry: Inspector â†’ Request cookies to see parsed cookies. CookieJar panel manages persisted cookies.");
      return parts.join("\n");
    }
    if (/injection|probe|attack|xss|sqli|ssrf/.test(p)) {
      const parts: string[] = [
        "Injection probe suggestions for " + method + " " + url + ":",
        "",
        "1. Click â†’ Intruder to send this request to Intruder, then mark payload positions with Â§ on query values or body params",
        "2. Pick Sniper mode (single injection point) or Cluster Bomb (multi-param)",
        "3. Load a wordlist from the Payload library ”” SQLi / XSS / SSTI / LFI / CRLF / SSRF each have canonical lists",
        "4. For blind probes (SSRF / blind XSS / log4j JNDI): use the Collaborator panel to mint an OOB payload + embed it",
        "5. Click â†’ ðŸŽ¯ Scan to let Scanner's active engine run every enabled probe against this transaction",
      ];
      return parts.join("\n");
    }
    if (/explain|what|why/.test(p) && last) {
      const parts: string[] = [];
      const sizeKb = ((last.response?.body?.length ?? 0) / 1024).toFixed(1);
      parts.push(
        `This exchange was ${method} ${url} returning HTTP ${status} in ${last.elapsed_ms ?? 0}ms with a ${sizeKb}KB body.`,
      );
      const ct = header("Content-Type");
      if (ct) parts.push(`Content-Type: ${ct}`);
      const server = header("Server");
      if (server) parts.push(`Server: ${server}`);
      if (typeof status === "number") {
        if (status >= 200 && status < 300) parts.push("\n2xx = success ”” the server accepted + served the resource.");
        else if (status >= 300 && status < 400) parts.push("\n3xx = redirect ”” check the Location header + enable follow-redirects in ⚙ settings.");
        else if (status >= 400 && status < 500) parts.push("\n4xx = client error ”” your request was malformed, unauthorized, forbidden, or hit a rate limit.");
        else if (status >= 500) parts.push("\n5xx = server error ”” the target had an internal fault. Could be injection pay-dirt; check the body for stack traces.");
      }
      return parts.join("\n");
    }
    // Fallback ”” summarize what we know
    const parts: string[] = [
      `About ${method} ${url}:`,
      "",
    ];
    if (last) {
      parts.push(`”¢ Last response: HTTP ${status} · ${last.response?.body?.length ?? 0} bytes · ${last.elapsed_ms ?? 0}ms`);
    } else {
      parts.push("”¢ No sends yet ”” click Send to populate the response pane.");
    }
    parts.push(
      "",
      "Specific prompts I can help with:",
      "  \"Why is this 403?\" / \"Explain the response\"",
      "  \"What auth is in use?\" / \"Analyze cookies\"",
      "  \"Suggest injection probes\" / \"How do I test SSRF?\"",
      "  \"What's the content-type?\" / \"How big is the response?\"",
    );
    return parts.join("\n");
  }

  function sendPrompt() {
    const q = prompt.trim();
    if (!q) return;
    const next = [
      ...messages,
      { role: "user" as const, text: q },
      { role: "assistant" as const, text: synthesizeResponse(q) },
    ];
    setMessages(next);
    setPrompt("");
  }

  // ESC closes the drawer; Enter in prompt sends. R823: route
  // Esc through startClose() so the slide-out animation plays.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        startClose();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  // reference respRaw so TS doesn't flag the prop as unused ”” we
  // may wire it into analysis synthesis in a future round.
  void respRaw;
  // R823: Closing-animation state. When operator triggers close
  // we flip `closing` to true + delay the actual onClose() call
  // 180ms so the CSS slide-out animation plays. Keystroke close
  // (Esc) + button close + close-after-save all funnel through
  // startClose() so the exit animation is consistent.
  const [closing, setClosing] = useState(false);
  const startClose = () => {
    if (closing) return;
    setClosing(true);
    setTimeout(() => {
      setMessages([]);
      setClosing(false);
      onClose();
    }, 180);
  };

  return (
    <div
      className={`burp-ai-drawer${closing ? " burp-ai-drawer-closing" : ""}`}
    >
      <div className="burp-ai-head">
        <span className="burp-ai-title">
          <span className="burp-ai-spark">âœ¦</span> Burp AI
        </span>
        <span className="burp-ai-sub">(mock · client-side only)</span>
        <span style={{ flex: 1 }} />
        {/* R801: Clear chat button ”” wipes the conversation
            without closing the drawer so the operator can start
            fresh without re-opening. */}
        {messages.length > 1 && (
          <button
            className="burp-ai-close"
            onClick={() => setMessages([])}
            title="Clear chat history (starts a fresh conversation)"
            style={{ marginRight: 2 }}
          >
            âŒ«
          </button>
        )}
        <button
          className="burp-ai-close"
          onClick={startClose}
          title="Close Burp AI drawer (Esc)"
        >
          âœ•
        </button>
      </div>
      <div className="burp-ai-chat">
        {messages.map((m, i) => (
          <div
            key={i}
            className={`burp-ai-msg burp-ai-msg-${m.role}`}
          >
            <div className="burp-ai-msg-role">
              {m.role === "user" ? "You" : "âœ¦ AI"}
              {/* R803: Per-message copy button ”” hover-only so the
                  chat stays visually clean. Mirrors Burp Suite
                  2026.8's AI companion which also lets operators
                  one-click copy any AI reply for sharing. */}
              <button
                className="burp-ai-msg-copy"
                onClick={() => void navigator.clipboard.writeText(m.text)}
                title={`Copy this ${m.role === "user" ? "prompt" : "AI reply"} to clipboard`}
              >
                ðŸ“‹
              </button>
            </div>
            <div className="burp-ai-msg-text">{m.text}</div>
          </div>
        ))}
        {/* R801: Burp-identical quick-ask suggestion chips. When
            the chat is still at the opening greeting, show a row
            of canned prompts so operators who've never used an AI
            companion have a one-click entry into useful queries.
            Chips hide once the operator has sent anything. */}
        {messages.length <= 1 && (
          <div className="burp-ai-suggestions">
            <div className="burp-ai-suggestions-label">Quick asks:</div>
            {[
              "Explain the response",
              "What auth is in use?",
              "Why is this 403?",
              "Suggest injection probes",
              "Analyze cookies",
            ].map((q) => (
              <button
                key={q}
                className="burp-ai-chip"
                onClick={() => {
                  const next = [
                    ...messages,
                    { role: "user" as const, text: q },
                    {
                      role: "assistant" as const,
                      text: synthesizeResponse(q),
                    },
                  ];
                  setMessages(next);
                }}
                title={`Send "${q}" as a prompt`}
              >
                {q}
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="burp-ai-prompt-row">
        {/* R806: Multi-line prompt input ”” operators composing a
            longer prompt (paste a snippet, ask multi-step question)
            need Shift+Enter to insert a newline. Plain Enter still
            sends to match chat-app muscle memory. Textarea auto-
            sizes vertically within a 2-5 line range via CSS. */}
        <textarea
          className="burp-ai-prompt"
          placeholder="Ask about this request… (Enter sends, Shift+Enter = newline)"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              sendPrompt();
            }
          }}
          rows={1}
          autoFocus
        />
        <button
          className="burp-ai-send"
          onClick={sendPrompt}
          disabled={!prompt.trim()}
          title="Send prompt (Enter)"
        >
          Analyze
        </button>
        {/* R802: "ðŸ“‘ Save to Notes" quick-action ”” appends the
            current chat conversation to the active tab's Notes
            section (R738) so operators keep a record of the AI
            session alongside the tab. Only shows when conversation
            has â‰¥2 messages (past the greeting) + an active tab
            exists. */}
        {messages.length > 1 && activeTab && (
          <button
            className="burp-ai-send"
            style={{
              background:
                "linear-gradient(90deg, rgba(100,180,120,0.9) 0%, rgba(80,160,100,0.9) 100%)",
            }}
            onClick={async () => {
              const header = `--- Burp AI chat · ${new Date().toISOString()} ---`;
              const body = messages
                .map(
                  (m) =>
                    `${m.role === "user" ? "You" : "âœ¦ AI"}: ${m.text}`,
                )
                .join("\n\n");
              const existing = (activeTab.comment || "").trim();
              const next = existing
                ? `${existing}\n\n${header}\n${body}`
                : `${header}\n${body}`;
              try {
                await api.repeaterSetComment(activeTab.id, next);
                alert(
                  `Saved ${messages.length} message${
                    messages.length === 1 ? "" : "s"
                  } to the tab's Notes section. Open the Inspector â†’ Notes to see them.`,
                );
              } catch (e) {
                alert(`Failed to save: ${e}`);
              }
            }}
            title="Append this chat conversation to the active tab's Notes (R738). Great for keeping a record of AI analysis alongside the tab."
          >
            ðŸ“‘ Save to Notes
          </button>
        )}
      </div>
    </div>
  );
}

function DiffPane({
  report,
  a,
  b,
  onClose,
}: {
  report: any;
  a: number | null;
  b: number | null;
  onClose: () => void;
}) {
  const lines: Array<{ op: string; text: string; left?: number; right?: number }> =
    report?.lines ?? [];
  const similarity = report?.similarity ?? 0;
  return (
    <div
      style={{
        padding: "6px 10px",
        borderTop: "1px solid var(--border)",
        maxHeight: 240,
        overflow: "auto",
        background: "var(--bg-raised)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <strong style={{ fontSize: 12 }}>
          Diff · A=#{(a ?? -1) + 1} â†” B=#{(b ?? -1) + 1}
        </strong>
        <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
          similarity {Math.round(similarity * 100)}%
        </span>
        <span style={{ flex: 1 }} />
        <button className="ghost" onClick={onClose}>
          âœ•
        </button>
      </div>
      <table className="mono" style={{ width: "100%", fontSize: 11 }}>
        <tbody>
          {lines.map((l, i) => (
            <tr key={i}>
              <td style={{ color: "var(--text-dim)", width: 32, textAlign: "right" }}>
                {l.left ?? ""}
              </td>
              <td style={{ color: "var(--text-dim)", width: 32, textAlign: "right" }}>
                {l.right ?? ""}
              </td>
              <td
                style={{
                  padding: "1px 6px",
                  background:
                    l.op === "insert"
                      ? "rgba(74, 198, 108, 0.15)"
                      : l.op === "delete"
                      ? "rgba(224, 68, 68, 0.15)"
                      : "transparent",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                <span style={{ marginRight: 4, color: "var(--text-dim)" }}>
                  {l.op === "insert" ? "+" : l.op === "delete" ? "âˆ’" : " "}
                </span>
                {l.text}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------ (editor + inspector + render + parsers moved to `../MessageEditor` in Round 11) ------------------ */
/*
 * Render-mode preview, MessageEditor, Inspector, Section, KV,
 * parseMessage, decodeMaybe, prettyPrint, prettyXmlish, toHexDump,
 * pathWithoutQuery ”” all previously inlined here ”” were extracted into
 * the shared `web/src/MessageEditor.tsx` module so the Proxy Intercept
 * pane could reuse them. The RepeaterPanel still imports MessageEditor
 * from there at the top of this file.
 *
 * The iframe deliberately uses an empty `sandbox` attribute (not
 * `allow-scripts`) so JavaScript, form submission, same-origin, and
 * popups are all blocked. The content runs in a null origin.
 */

/* ------------------ wire render helpers (kept from previous version) ------------------ */

function buildUrlFromTemplate(template: any): string {
  // The repeater template carries method / path / headers only ”” reconstruct
  // the host from the Host header so we can seed a sibling tab via
  // `repeaterAddTab(name, url)`. Fall back to a dummy if nothing matches.
  const headers = template?.headers?.items ?? [];
  const hostField = headers.find((h: any) => h.name?.toLowerCase() === "host");
  // R828: Burp-identical URL rendering with non-standard port.
  // Host header may already carry `:port` suffix; template.host +
  // template.port give authoritative values. Prefer template fields
  // + fall through to Host header. Omit the port when it matches
  // the scheme default (443/https or 80/http) so standard URLs
  // stay clean.
  const rawHost =
    (template?.host as string) ||
    hostField?.value?.trim() ||
    "example.com";
  const scheme = template?.scheme ?? "https";
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = Number(template?.port);
  // Strip any existing `:port` from host so we don't double-add.
  const bareHost = rawHost.split(":")[0];
  const hostWithPort =
    port && port !== defaultPort && isFinite(port)
      ? `${bareHost}:${port}`
      : rawHost;
  const path = template?.path ?? "/";
  return `${scheme}://${hostWithPort}${path.startsWith("/") ? path : "/" + path}`;
}

function renderRaw(template: any): string {
  const headerLines = (template.headers?.items || [])
    .map((h: any) => `${h.name}: ${h.value}`)
    .join("\r\n");
  const bodyText = template.body ? atob(template.body) : "";
  // Use the stored http_version so a tab that was captured over
  // HTTP/2 doesn't lie by claiming HTTP/1.1 in the request line.
  // Operators who want to re-fire over H2 will see the matching
  // start-line; the HttpClient still negotiates on the wire so this
  // is purely a visual honesty fix (R127).
  const version = httpVersionToken(template.http_version);
  return `${template.method} ${template.path} ${version}\r\n${headerLines}\r\n\r\n${bodyText}`;
}

function parseRaw(raw: string, base: any): any {
  const lines = raw.split("\r\n");
  const first = lines[0] || "";
  const parts = first.split(" ");
  const method = parts[0] || base.method;
  const path = parts[1] || base.path;
  const headers: { name: string; value: string }[] = [];
  let i = 1;
  while (i < lines.length && lines[i] !== "") {
    const line = lines[i];
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
    i++;
  }
  const body = lines.slice(i + 1).join("\r\n");
  return {
    ...base,
    method,
    path,
    headers: { items: headers },
    body: btoa(unescape(encodeURIComponent(body))),
  };
}

/** Map backend HttpVersion enum variants to the on-wire token the
 *  response's start-line should carry. Burp's Repeater surfaces the
 *  actual negotiated protocol (HTTP/1.0 for ancient CDNs, HTTP/2 for
 *  modern H2 upstreams, HTTP/3 when QUIC lands) so operators notice
 *  when a target downgrades or renegotiates. Falls back to
 *  `HTTP/1.1` for unknown payloads so a mis-serialised row doesn't
 *  render a broken start-line. */
function httpVersionToken(v: unknown): string {
  switch (v) {
    case "Http10":
      return "HTTP/1.0";
    case "Http11":
      return "HTTP/1.1";
    case "Http2":
      return "HTTP/2";
    case "Http3":
      return "HTTP/3";
    default:
      return "HTTP/1.1";
  }
}

function renderRawResponse(resp: any, error?: string): string {
  if (error) return `-- error --\n${error}`;
  if (!resp) return "(no response)";
  const headerLines = (resp.headers?.items || [])
    .map((h: any) => `${h.name}: ${h.value}`)
    .join("\r\n");
  const bodyText = resp.body ? atob(resp.body) : "";
  const version = httpVersionToken(resp.http_version);
  return `${version} ${resp.status} ${resp.reason}\r\n${headerLines}\r\n\r\n${bodyText}`;
}

/* ---------------------- Inspector sidebar (R733) ----------------------
 * Burp-identical right-side panel showing parsed request + response
 * structure as collapsible accordion sections. Parses the current raw
 * request + response strings on every render ”” fast enough since both
 * are small (typical < 8KB) and the parsers are single-pass. Zero
 * backend state; everything comes from the already-rendered editor
 * buffers so the Inspector stays in lockstep with operator edits
 * without a round-trip to the Rust engines.
 * ---------------------------------------------------------------------- */

type KVPair = { k: string; v: string };

/** Parse a raw HTTP request string into its structural pieces. */
function parseInspectorRequest(raw: string): {
  method: string;
  path: string;
  version: string;
  queryParams: KVPair[];
  cookies: KVPair[];
  headers: KVPair[];
  bodyParams: KVPair[];
  rawBody: string;
} {
  const empty = {
    method: "",
    path: "",
    version: "",
    queryParams: [] as KVPair[],
    cookies: [] as KVPair[],
    headers: [] as KVPair[],
    bodyParams: [] as KVPair[],
    rawBody: "",
  };
  if (!raw) return empty;
  // Split head from body on the first blank line (CRLF or LF tolerant).
  const sep = raw.indexOf("\r\n\r\n");
  const altSep = sep < 0 ? raw.indexOf("\n\n") : -1;
  const headEnd = sep >= 0 ? sep : altSep >= 0 ? altSep : raw.length;
  const head = raw.slice(0, headEnd);
  const body = sep >= 0 ? raw.slice(sep + 4) : altSep >= 0 ? raw.slice(altSep + 2) : "";
  const headLines = head.split(/\r?\n/);
  if (headLines.length === 0) return empty;
  // Request line: "METHOD /path?x=1 HTTP/1.1"
  const requestLine = headLines[0] || "";
  const rlParts = requestLine.split(" ");
  const method = rlParts[0] || "";
  const pathFull = rlParts[1] || "";
  const version = rlParts.slice(2).join(" ") || "";
  const qIdx = pathFull.indexOf("?");
  const path = qIdx >= 0 ? pathFull.slice(0, qIdx) : pathFull;
  const query = qIdx >= 0 ? pathFull.slice(qIdx + 1) : "";
  const parseKV = (s: string, pairSep: string): KVPair[] => {
    const out: KVPair[] = [];
    if (!s) return out;
    for (const chunk of s.split(pairSep)) {
      if (!chunk) continue;
      const eq = chunk.indexOf("=");
      if (eq < 0) {
        out.push({ k: chunk.trim(), v: "" });
      } else {
        out.push({
          k: chunk.slice(0, eq).trim(),
          v: chunk.slice(eq + 1).trim(),
        });
      }
    }
    return out;
  };
  const queryParams = parseKV(query, "&").map((p) => {
    try {
      return { k: decodeURIComponent(p.k), v: decodeURIComponent(p.v) };
    } catch {
      return p;
    }
  });
  // Parse headers from head lines 1..n
  const headers: KVPair[] = [];
  let cookieHeader = "";
  let contentType = "";
  for (let i = 1; i < headLines.length; i++) {
    const line = headLines[i];
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    headers.push({ k: name, v: value });
    const nl = name.toLowerCase();
    if (nl === "cookie") cookieHeader = value;
    if (nl === "content-type") contentType = value.toLowerCase();
  }
  const cookies = parseKV(cookieHeader, ";");
  // Body params only if form-encoded or JSON
  let bodyParams: KVPair[] = [];
  if (body && contentType.includes("application/x-www-form-urlencoded")) {
    bodyParams = parseKV(body, "&").map((p) => {
      try {
        return { k: decodeURIComponent(p.k), v: decodeURIComponent(p.v) };
      } catch {
        return p;
      }
    });
  } else if (body && contentType.includes("application/json")) {
    try {
      const obj = JSON.parse(body);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [k, v] of Object.entries(obj)) {
          bodyParams.push({
            k,
            v: typeof v === "string" ? v : JSON.stringify(v),
          });
        }
      }
    } catch {
      /* body isn't valid JSON ”” leave bodyParams empty */
    }
  }
  return {
    method,
    path,
    version,
    queryParams,
    cookies,
    headers,
    bodyParams,
    rawBody: body,
  };
}

/** Parse a raw HTTP response string's status + headers. */
function parseInspectorResponse(raw: string): {
  status: string;
  version: string;
  reason: string;
  headers: KVPair[];
} {
  const empty = { status: "", version: "", reason: "", headers: [] as KVPair[] };
  if (!raw) return empty;
  const sep = raw.indexOf("\r\n\r\n");
  const altSep = sep < 0 ? raw.indexOf("\n\n") : -1;
  const headEnd = sep >= 0 ? sep : altSep >= 0 ? altSep : raw.length;
  const head = raw.slice(0, headEnd);
  const headLines = head.split(/\r?\n/);
  const statusLine = headLines[0] || "";
  const slParts = statusLine.split(" ");
  const version = slParts[0] || "";
  const status = slParts[1] || "";
  const reason = slParts.slice(2).join(" ") || "";
  const headers: KVPair[] = [];
  for (let i = 1; i < headLines.length; i++) {
    const line = headLines[i];
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    headers.push({
      k: line.slice(0, colon).trim(),
      v: line.slice(colon + 1).trim(),
    });
  }
  return { status, version, reason, headers };
}

/* R811+R813: Burp-identical "Selection" top panel inside the
 * Inspector sidebar. Mirrors Burp Suite 2026.8's exact silhouette:
 * section header "Selection N (0xN)" + collapsible body carrying
 * "Selected text" box + "Decoded from:" dropdown with 8 codecs +
 * decoded preview (editable in R813) + Cancel/Apply buttons.
 * R813: Apply splices the (possibly-edited) decoded value back
 * into the Request pane at the selection offsets. Response-side
 * selections make Apply read-only (Response is server-controlled).
 */
function SelectionInspectorPanel({
  selection,
  requestRaw,
  onApplyRequest,
}: {
  selection: {
    start: number;
    end: number;
    text: string;
    direction: "request" | "response";
  };
  /** R813: current Request raw ”” used for Apply splice. */
  requestRaw: string;
  /** R813: splice-back callback on Apply. Null-safe no-op when
   *  parent doesn't provide (e.g. Proxy/History pane reuse). */
  onApplyRequest: (nextRaw: string) => void;
}) {
  const [expanded, setExpanded] = useState<boolean>(true);
  const [decodeMode, setDecodeMode] = useState<string>("");
  // R813: Editable decoded-value state. Lets operators tweak the
  // decoded view before clicking Apply changes ”” mirrors Burp's
  // flow where you decode something, edit the plain-text, then
  // apply the (possibly-mutated) decoded value back into the pane.
  const [editedDecoded, setEditedDecoded] = useState<string>("");
  // Reset the edited view whenever selection or codec changes.
  useEffect(() => {
    setEditedDecoded("");
  }, [selection.text, selection.start, selection.end, decodeMode]);
  const byteCount = Math.abs(selection.end - selection.start);

  // R812: Full Burp-identical codec roster ”” URL encoding, URL+plus
  // (RFC 1738), HTML entities (named + numeric decimal + numeric
  // hex), Base64 (standard + URL-safe + auto-pad), ASCII-hex,
  // JWT (base64url header.payload.signature parse â†’ pretty JSON),
  // Auto (sniff the shape + try each codec in rank order). Each
  // codec returns the decoded string or a "(decode error: …)" tag
  // if the input doesn't parse.
  const decoded = (() => {
    if (!decodeMode) return null;
    const txt = selection.text;
    try {
      switch (decodeMode) {
        case "url":
          return decodeURIComponent(txt);
        case "url-plus":
          // RFC 1738: `+` means space in form bodies. Burp calls
          // this "URL (plus)".
          return decodeURIComponent(txt.replace(/\+/g, " "));
        case "base64":
          // atob is strict; auto-pad to multiple of 4 with = so
          // operator pastes without the trailing padding still work.
          {
            const pad = txt.padEnd(
              txt.length + ((4 - (txt.length % 4)) % 4),
              "=",
            );
            return atob(pad);
          }
        case "base64url":
          // base64url: `-` â†’ `+`, `_` â†’ `/`, pad with `=`.
          {
            const normalized = txt
              .replace(/-/g, "+")
              .replace(/_/g, "/");
            const pad = normalized.padEnd(
              normalized.length + ((4 - (normalized.length % 4)) % 4),
              "=",
            );
            return atob(pad);
          }
        case "hex":
          return (
            txt
              .replace(/\s/g, "")
              .match(/.{1,2}/g)
              ?.map((h) => String.fromCharCode(parseInt(h, 16)))
              .join("") ?? ""
          );
        case "html":
          return txt
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&quot;/g, '"')
            .replace(/&#x([0-9a-fA-F]+);/g, (_, h) =>
              String.fromCharCode(parseInt(h, 16)),
            )
            .replace(/&#(\d+);/g, (_, n) =>
              String.fromCharCode(parseInt(n, 10)),
            );
        case "jwt": {
          // JWT = base64url(header).base64url(payload).signature
          const parts = txt.split(".");
          if (parts.length !== 3) {
            return `(not a JWT ”” expected 3 dot-separated parts, got ${parts.length})`;
          }
          const b64url = (s: string) => {
            const normalized = s.replace(/-/g, "+").replace(/_/g, "/");
            const pad = normalized.padEnd(
              normalized.length +
                ((4 - (normalized.length % 4)) % 4),
              "=",
            );
            return atob(pad);
          };
          const header = JSON.parse(b64url(parts[0]));
          const payload = JSON.parse(b64url(parts[1]));
          return (
            "Header:\n" +
            JSON.stringify(header, null, 2) +
            "\n\nPayload:\n" +
            JSON.stringify(payload, null, 2) +
            "\n\nSignature: " +
            parts[2].slice(0, 32) +
            (parts[2].length > 32 ? "…" : "")
          );
        }
        case "auto": {
          // Sniff shape + try each codec in rank order. Return the
          // first that produces printable output. Order: JWT first
          // (3-dot pattern), base64 (long alphanumeric+/+=), URL
          // (contains %), hex (even hex chars), html (contains &).
          const trimmed = txt.trim();
          if (trimmed.split(".").length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(trimmed)) {
            try {
              const parts = trimmed.split(".");
              const b64url = (s: string) => {
                const n = s.replace(/-/g, "+").replace(/_/g, "/");
                return atob(
                  n.padEnd(n.length + ((4 - (n.length % 4)) % 4), "="),
                );
              };
              const payload = JSON.parse(b64url(parts[1]));
              return `(auto â†’ JWT)\n${JSON.stringify(payload, null, 2)}`;
            } catch {
              /* fall through */
            }
          }
          if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
            try {
              return `(auto â†’ URL)\n${decodeURIComponent(trimmed)}`;
            } catch {
              /* fall through */
            }
          }
          if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length >= 8) {
            try {
              const pad = trimmed.padEnd(
                trimmed.length + ((4 - (trimmed.length % 4)) % 4),
                "=",
              );
              return `(auto â†’ Base64)\n${atob(pad)}`;
            } catch {
              /* fall through */
            }
          }
          if (/^[0-9a-fA-F\s]+$/.test(trimmed) && trimmed.replace(/\s/g, "").length % 2 === 0) {
            try {
              const chars = trimmed
                .replace(/\s/g, "")
                .match(/.{1,2}/g)
                ?.map((h) => String.fromCharCode(parseInt(h, 16)))
                .join("");
              if (chars) return `(auto â†’ Hex)\n${chars}`;
            } catch {
              /* fall through */
            }
          }
          if (/&(amp|lt|gt|quot|#\d+|#x[0-9a-f]+);/i.test(trimmed)) {
            return `(auto â†’ HTML entities)\n${trimmed
              .replace(/&amp;/g, "&")
              .replace(/&lt;/g, "<")
              .replace(/&gt;/g, ">")
              .replace(/&quot;/g, '"')
              .replace(/&#(\d+);/g, (_, n) =>
                String.fromCharCode(parseInt(n, 10)),
              )}`;
          }
          return "(auto: no codec matched ”” try picking a specific one)";
        }
        default:
          return null;
      }
    } catch (e) {
      return `(decode error: ${e})`;
    }
  })();

  return (
    <div className="rep-insp-section rep-insp-selection">
      <div
        className="rep-insp-section-head"
        onClick={() => setExpanded((v) => !v)}
        title={`${expanded ? "Collapse" : "Expand"} Selection`}
      >
        <span className="rep-insp-chevron">{expanded ? "â–¾" : "â–¸"}</span>
        <span className="rep-insp-title">Selection</span>
        <span className="rep-insp-count">
          {byteCount} (0x{byteCount.toString(16)})
        </span>
      </div>
      {expanded && (
        <div className="rep-insp-section-body rep-insp-selection-body">
          <div className="rep-insp-selection-sub">Selected text</div>
          <div
            className="rep-insp-selection-text"
            title={`${byteCount} byte${byteCount === 1 ? "" : "s"} from the ${selection.direction} pane · offset ${selection.start}-${selection.end}`}
          >
            {selection.text.length > 500
              ? selection.text.slice(0, 500) + "…"
              : selection.text}
          </div>
          <div className="rep-insp-selection-row">
            <label className="rep-insp-selection-label">
              Decoded from:
            </label>
            <select
              className="rep-insp-selection-decoder"
              value={decodeMode}
              onChange={(e) => setDecodeMode(e.target.value)}
            >
              <option value="">Select</option>
              <option value="auto">Auto (detect shape)</option>
              <option value="url">URL encoding</option>
              <option value="url-plus">URL (plus = space)</option>
              <option value="base64">Base64</option>
              <option value="base64url">Base64 URL-safe</option>
              <option value="hex">ASCII hex</option>
              <option value="html">HTML entities</option>
              <option value="jwt">JWT (header.payload.sig)</option>
            </select>
            <button
              className="rep-insp-selection-add"
              title="Add another decode step (planned ”” multi-step decoder chain)"
              onClick={() =>
                alert(
                  "Multi-step decoder chain is planned for a future release. For now, pick a single decode method above or use the Decoder panel for multi-step chains.",
                )
              }
            >
              +
            </button>
          </div>
          {decoded !== null && (
            /* R813: Decoded preview is now editable ”” operators tweak
                the decoded view then click Apply changes to splice
                the mutated value back into the pane. Textarea
                shows the decoded value by default; editing captures
                into `editedDecoded` state so Apply gets the current
                buffer not the auto-derived original. */
            <textarea
              className="rep-insp-selection-decoded rep-insp-selection-decoded-edit"
              title={`Decoded via ${decodeMode} · edit + Apply splices back into the ${selection.direction} pane`}
              value={editedDecoded || decoded}
              onChange={(e) => setEditedDecoded(e.target.value)}
              spellCheck={false}
              rows={Math.min(
                6,
                Math.max(
                  2,
                  ((editedDecoded || decoded).match(/\n/g)?.length ?? 0) + 1,
                ),
              )}
            />
          )}
          <div className="rep-insp-selection-actions">
            <button
              className="rep-insp-selection-cancel"
              onClick={() => {
                setDecodeMode("");
                setEditedDecoded("");
              }}
              title="Clear the decode selection + any edited decoded value"
              disabled={!decodeMode && !editedDecoded}
            >
              Cancel
            </button>
            <button
              className="rep-insp-selection-apply"
              onClick={() => {
                if (!decodeMode || decoded === null) return;
                if (selection.direction !== "request") {
                  alert(
                    "Apply changes only works on the Request pane. Response is server-controlled + read-only.",
                  );
                  return;
                }
                const applyValue = editedDecoded || decoded;
                // Splice the decoded value back into Request raw at
                // the original selection offsets. The result is
                // literal ”” we don't re-encode the value, matching
                // the common Burp use case ("decode this %-encoded
                // chunk inline"). Operators who want to re-encode
                // can use the Decoder panel for the encode step +
                // paste back.
                const nextRaw =
                  requestRaw.slice(0, selection.start) +
                  applyValue +
                  requestRaw.slice(selection.end);
                onApplyRequest(nextRaw);
                setEditedDecoded("");
                setDecodeMode("");
              }}
              disabled={
                !decodeMode ||
                decoded === null ||
                selection.direction === "response" ||
                decoded.startsWith("(decode error:") ||
                decoded.startsWith("(auto:") ||
                decoded.startsWith("(not a JWT")
              }
              title={
                !decodeMode
                  ? "Pick a decode method first"
                  : selection.direction === "response"
                    ? "Apply only works on the Request pane (Response is server-controlled)"
                    : decoded?.startsWith("(decode error:") ||
                        decoded?.startsWith("(auto:") ||
                        decoded?.startsWith("(not a JWT")
                      ? "Decode failed ”” can't apply an error placeholder back into the pane"
                      : `Splice the decoded value back into the Request pane at offset ${selection.start}-${selection.end}`
              }
            >
              Apply changes
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function InspectorSidebar({
  requestRaw,
  responseRaw,
  activeTab,
  expanded,
  onToggle,
  onBulkExpand,
  selection,
  onApplyRequest,
  onClose,
  onCommentChange,
}: {
  requestRaw: string;
  responseRaw: string;
  activeTab: RepeaterTab | null;
  expanded: Record<string, boolean>;
  onToggle: (key: string) => void;
  /** R791: Expand or collapse every section at once. True = expand all,
   *  false = collapse all. The callback inside the panel resolves to
   *  a `setInspectorExpanded` write with every known key flipped. */
  onBulkExpand?: (expand: boolean) => void;
  /** R811: Current editor selection (lifted from MessageEditor so the
   *  "Selection" top panel can render it). Null when no selection. */
  selection?: {
    start: number;
    end: number;
    text: string;
    direction: "request" | "response";
  } | null;
  /** R813: Apply-changes callback for the Selection panel. Fires
   *  when operator clicks Apply after decoding + editing ”” splices
   *  the decoded value back into the Request raw. */
  onApplyRequest: (nextRaw: string) => void;
  onClose: () => void;
  onCommentChange?: (tabId: number, comment: string) => void | Promise<void>;
}) {
  // R738: Notes section ”” local-state debounced textarea that saves
  // back to tab.comment. We debounce 400ms after the last keystroke
  // so operators typing a note don't trigger a storm of backend
  // writes. Local state resets when the active tab changes.
  const [noteDraft, setNoteDraft] = useState<string>(activeTab?.comment ?? "");
  const activeTabId = activeTab?.id;
  useEffect(() => {
    setNoteDraft(activeTab?.comment ?? "");
  }, [activeTabId, activeTab?.comment]);
  useEffect(() => {
    if (!onCommentChange || activeTabId == null) return;
    if (noteDraft === (activeTab?.comment ?? "")) return;
    const timer = setTimeout(() => {
      void onCommentChange(activeTabId, noteDraft);
    }, 400);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [noteDraft, activeTabId]);
  const req = useMemo(() => parseInspectorRequest(requestRaw), [requestRaw]);
  const resp = useMemo(
    () => parseInspectorResponse(responseRaw),
    [responseRaw],
  );
  const attrs: KVPair[] = useMemo(() => {
    const out: KVPair[] = [];
    if (req.method) out.push({ k: "Method", v: req.method });
    if (req.path) out.push({ k: "Path", v: req.path });
    if (req.version) out.push({ k: "Version", v: req.version });
    if (activeTab?.template?.scheme)
      out.push({ k: "Scheme", v: String(activeTab.template.scheme) });
    const hostHeader = req.headers.find(
      (h) => h.k.toLowerCase() === "host",
    );
    if (hostHeader) out.push({ k: "Host", v: hostHeader.v });
    if (resp.status)
      out.push({
        k: "Response status",
        v: `${resp.status}${resp.reason ? " " + resp.reason : ""}`,
      });
    return out;
  }, [req, resp, activeTab]);

  const sections: Array<{
    key: string;
    title: string;
    rows: KVPair[];
  }> = [
    { key: "attrs", title: "Request attributes", rows: attrs },
    { key: "query", title: "Request query parameters", rows: req.queryParams },
    { key: "body", title: "Request body parameters", rows: req.bodyParams },
    { key: "cookies", title: "Request cookies", rows: req.cookies },
    { key: "headers", title: "Request headers", rows: req.headers },
    { key: "respHeaders", title: "Response headers", rows: resp.headers },
  ];

  // R738: Notes section renders separately at the bottom because
  // its content is a free-form textarea, not a KV table ”” doesn't
  // fit the section-row renderer above.
  const notesExpanded = expanded["notes"] ?? false;
  const notesCount = (noteDraft || "").length;
  // R746: Inspector filter input ”” operators searching for a
  // specific header / param (e.g. "cookie", "authorization",
  // "x-csrf") don't want to eyeball through 20 rows. The filter
  // input case-folds + substring-matches across every section's
  // key AND value, so searching "sess" finds "session_id" rows
  // and "SessionCookie: xyz" rows alike. Empty filter = all rows.
  const [inspectorFilter, setInspectorFilter] = useState<string>("");
  const filterText = inspectorFilter.trim().toLowerCase();
  const filterRows = (rows: KVPair[]): KVPair[] => {
    if (!filterText) return rows;
    return rows.filter(
      (r) =>
        r.k.toLowerCase().includes(filterText) ||
        r.v.toLowerCase().includes(filterText),
    );
  };

  // R757: Determine whether to render the Burp-identical empty
  // state (hat icon + description + Learn more) or the sections.
  // Empty state fires when there's no active tab OR when the
  // request is blank and the response is empty ”” i.e. nothing to
  // inspect. Mirrors Burp Suite 2026.8's empty-state exactly.
  const isEmpty =
    !activeTab ||
    ((!requestRaw || requestRaw.trim().length === 0) &&
      (!responseRaw || responseRaw.trim().length === 0));

  return (
    <div className="rep-inspector">
      <div className="rep-inspector-head">
        <strong>Inspector</strong>
        <span style={{ flex: 1 }} />
        {/* R791: Burp-identical Inspector "expand all / collapse all"
            quick toggles. Operators pivoting through 7 sections
            (attrs/query/body/cookies/headers/resp-headers/notes)
            want one-click to see everything or hide everything.
            Mirrors Burp Suite 2026.8's "expand/collapse all"
            affordance in the Inspector header. The two glyphs
            match the sections' chevron glyph language (⊟ = full /
            ⊞ = empty) so the Inspector header carries consistent
            visual signifiers. */}
        {onBulkExpand && (
          <>
            <button
              className="rep-inspector-close"
              onClick={() => onBulkExpand(true)}
              title="Expand all Inspector sections"
              style={{ marginRight: 2 }}
            >
              ⊞⊞
            </button>
            <button
              className="rep-inspector-close"
              onClick={() => onBulkExpand(false)}
              title="Collapse all Inspector sections"
              style={{ marginRight: 2 }}
            >
              ⊟⊟
            </button>
          </>
        )}
        <button
          className="rep-inspector-close"
          onClick={onClose}
          title="Hide the Inspector sidebar"
        >
          âœ•
        </button>
      </div>
      {isEmpty && (
        <div className="rep-inspector-empty">
          <div className="rep-inspector-empty-icon" aria-hidden>
            {/* Burp-style detective-hat icon rendered as inline
                SVG so no asset round-trip + colours track theme */}
            <svg
              viewBox="0 0 64 64"
              width="52"
              height="52"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M8 44 L56 44" />
              <path d="M12 44 Q12 20 32 20 Q52 20 52 44" />
              <ellipse cx="32" cy="52" rx="26" ry="4" />
              <circle cx="24" cy="32" r="2" />
              <circle cx="40" cy="32" r="2" />
              <path d="M28 40 Q32 42 36 40" />
            </svg>
          </div>
          <div className="rep-inspector-empty-title">Inspector</div>
          <div className="rep-inspector-empty-desc">
            The message inspector provides a quick way to analyse
            interesting details and features of HTTP messages, and
            perform common operations on them.
          </div>
          <button
            className="rep-inspector-empty-learn"
            onClick={() => {
              alert(
                "Inspector\n\n" +
                  "Expand the sections below to inspect parsed structure:\n" +
                  "”¢ Request attributes ”” method, path, version, scheme, host\n" +
                  "”¢ Request query parameters ”” URL ?key=value pairs\n" +
                  "”¢ Request body parameters ”” form-encoded or JSON body\n" +
                  "”¢ Request cookies ”” Cookie header split into pairs\n" +
                  "”¢ Request headers ”” every header line\n" +
                  "”¢ Response headers ”” the server's response headers\n" +
                  "”¢ Notes ”” free-form note bound to this tab\n\n" +
                  "Use the filter input to grep for a specific key/value " +
                  "across all sections. Click any row to copy 'key: value' " +
                  "to the clipboard.",
              );
            }}
          >
            Learn more
          </button>
        </div>
      )}
      {!isEmpty && null}
      {!isEmpty && (<>
      {/* R811: Burp-identical "Selection" top panel in the Inspector
          sidebar ”” mirrors Burp Suite 2026.8's exact silhouette
          visible in the user's reference screenshot. Shows the
          current editor selection byte count + hex offset in the
          collapsible section header; expanded body carries:
          "Selected text" box (mono, blue-tinted) + "Decoded from"
          dropdown + decoded preview + Cancel/Apply buttons.
          Only renders when there IS a non-empty selection. */}
      {selection && selection.start !== selection.end && (
        <SelectionInspectorPanel
          selection={selection}
          requestRaw={requestRaw}
          onApplyRequest={onApplyRequest}
        />
      )}
      {/* R746: Inspector filter input ”” grep rows by key/value
          substring. Shows a Ã— clear button when filter is set. */}
      <div className="rep-inspector-filter">
        <input
          type="text"
          placeholder="Filter rows (key or value)…"
          value={inspectorFilter}
          onChange={(e) => setInspectorFilter(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape" && inspectorFilter) {
              e.preventDefault();
              setInspectorFilter("");
            }
          }}
        />
        {inspectorFilter && (
          <button
            className="rep-inspector-filter-clear"
            onClick={() => setInspectorFilter("")}
            title="Clear filter (Esc)"
          >
            Ã—
          </button>
        )}
      </div>
      <div className="rep-inspector-body">
        {sections.map((sec) => {
          const isExpanded = expanded[sec.key] ?? true;
          const filteredRows = filterRows(sec.rows);
          return (
            <div key={sec.key} className="rep-insp-section">
              <div
                className="rep-insp-section-head"
                onClick={() => onToggle(sec.key)}
                title={`${isExpanded ? "Collapse" : "Expand"} ${sec.title}`}
              >
                <span className="rep-insp-chevron">
                  {isExpanded ? "â–¾" : "â–¸"}
                </span>
                <span className="rep-insp-title">{sec.title}</span>
                <span className="rep-insp-count">
                  {filterText
                    ? `${filteredRows.length}/${sec.rows.length}`
                    : sec.rows.length}
                </span>
                {/* R792: Burp-identical per-section "Copy section"
                    button. Mirrors Burp Suite 2026.8's Inspector
                    where each section header carries a copy
                    affordance for operators who want "all cookies"
                    or "all headers" without clicking individual
                    rows. Writes `key: value` lines (newline-joined)
                    to the clipboard. Only renders when the section
                    has at least one row (zero-row sections keep the
                    header clean). Click-stops the toggle so the
                    section doesn't collapse on copy. */}
                {sec.rows.length > 0 && (
                  <button
                    className="rep-insp-copy"
                    onClick={(e) => {
                      e.stopPropagation();
                      const rowsToCopy = filterText
                        ? filteredRows
                        : sec.rows;
                      if (rowsToCopy.length === 0) return;
                      const text = rowsToCopy
                        .map((r) => `${r.k}: ${r.v}`)
                        .join("\n");
                      void navigator.clipboard.writeText(text);
                    }}
                    title={`Copy ${filterText ? filteredRows.length : sec.rows.length} ${sec.title.toLowerCase()} row${(filterText ? filteredRows.length : sec.rows.length) === 1 ? "" : "s"} as "key: value" lines to clipboard${filterText ? " (filter-aware)" : ""}`}
                  >
                    ðŸ“‹
                  </button>
                )}
              </div>
              {isExpanded && (
                <div className="rep-insp-section-body">
                  {filteredRows.length === 0 ? (
                    <div className="rep-insp-empty">
                      {filterText ? "(no match)" : "(none)"}
                    </div>
                  ) : (
                    filteredRows.map((row, i) => (
                      <div
                        key={`${sec.key}-${i}-${row.k}`}
                        className="rep-insp-row"
                        title={`${row.k}: ${row.v}`}
                        onClick={() => {
                          // Copy "key: value" on click so operators can
                          // paste into a scratch note / another request.
                          void navigator.clipboard.writeText(
                            `${row.k}: ${row.v}`,
                          );
                        }}
                      >
                        <span className="rep-insp-key">{row.k}</span>
                        <span className="rep-insp-val">{row.v || "””"}</span>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          );
        })}
        {/* R738: Notes section ”” free-form textarea bound to
            tab.comment with debounced save. Default-collapsed so
            it doesn't dominate the sidebar; expands to show a
            6-row textarea. */}
        <div className="rep-insp-section">
          <div
            className="rep-insp-section-head"
            onClick={() => onToggle("notes")}
            title={`${notesExpanded ? "Collapse" : "Expand"} Notes`}
          >
            <span className="rep-insp-chevron">
              {notesExpanded ? "â–¾" : "â–¸"}
            </span>
            <span className="rep-insp-title">Notes</span>
            <span className="rep-insp-count">
              {notesCount > 0 ? notesCount : 0}
            </span>
            {/* R824: Burp-identical Clear Notes affordance in the
                Notes section header. Hover-only to keep the chip
                clean when there's nothing to clear. Click stops
                propagation so the section doesn't collapse on
                clear. Confirms before wiping. */}
            {activeTab != null && noteDraft.length > 0 && (
              <button
                className="rep-insp-copy"
                onClick={(e) => {
                  e.stopPropagation();
                  if (
                    !confirm(
                      "Clear this tab's Notes?\n\nThis wipes the free-form comment bound to the active Repeater tab. The request template + send history are untouched.",
                    )
                  ) {
                    return;
                  }
                  setNoteDraft("");
                  if (onCommentChange) {
                    void onCommentChange(activeTab.id, "");
                  }
                }}
                title={`Clear ${notesCount} character${notesCount === 1 ? "" : "s"} of notes (confirms before wipe)`}
              >
                âœ•
              </button>
            )}
          </div>
          {notesExpanded && (
            <div className="rep-insp-section-body rep-insp-notes-body">
              {activeTab == null ? (
                <div className="rep-insp-empty">
                  (no tab selected)
                </div>
              ) : (
                <textarea
                  className="rep-insp-notes-area"
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  placeholder="Add a free-form note for this tab… (saves automatically; shows as ðŸ’¬ on the tab chip)"
                  rows={6}
                />
              )}
            </div>
          )}
        </div>
      </div>
      </>)}
    </div>
  );
}


/* ---------------------- Repeater status bar (R734) --------------------
 * Burp-identical bottom-row status display. Reads the active tab's
 * last send + renders tinted status code + size + elapsed + mime so
 * operators always see "what came back" without eyeballing the full
 * response pane. Empty state renders "no sends yet" to teach new
 * operators that firing Send populates this bar.
 * ---------------------------------------------------------------------- */
function RepeaterStatusBar({
  activeTab,
  sendIndex,
}: {
  activeTab: RepeaterTab | null;
  sendIndex: number | null;
}) {
  if (!activeTab) {
    return (
      <div className="rep-status-bar">
        <span className="rep-status-empty">no tab selected</span>
      </div>
    );
  }
  const history = activeTab.history ?? [];
  if (history.length === 0) {
    return (
      <div className="rep-status-bar">
        <span className="rep-status-empty">
          no sends yet · press Ctrl+Enter or click Send
        </span>
      </div>
    );
  }
  const idx =
    sendIndex !== null && sendIndex >= 0 && sendIndex < history.length
      ? sendIndex
      : history.length - 1;
  const send = history[idx];
  const resp = send?.response;
  const err = send?.error;
  const elapsed = send?.elapsed_ms ?? 0;

  // Determine response size in bytes. Response body is base64 encoded
  // in the backend payload; we approximate decoded length by base64
  // length * 3/4 (good enough for a status-bar readout).
  let bodyBytes = 0;
  if (resp?.body) {
    try {
      // Prefer actual decoded length when fast ”” atob rarely throws on
      // valid base64 even for binary bodies, and the status bar runs
      // only on explicit renders so cost is negligible.
      bodyBytes = atob(resp.body).length;
    } catch {
      bodyBytes = Math.max(0, Math.floor(resp.body.length * 0.75));
    }
  }
  const headerBytes = (resp?.headers?.items ?? [])
    .map((h: any) => `${h.name}: ${h.value}\r\n`.length)
    .reduce((a: number, b: number) => a + b, 0);
  const totalBytes = headerBytes + bodyBytes;

  const fmtBytes = (n: number) =>
    n < 1024
      ? `${n} B`
      : n < 1024 * 1024
        ? `${(n / 1024).toFixed(1)} KB`
        : `${(n / 1024 / 1024).toFixed(2)} MB`;

  const fmtMs = (ms: number) =>
    ms < 1000
      ? `${ms} ms`
      : ms < 60_000
        ? `${(ms / 1000).toFixed(2)} s`
        : `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;

  const status = resp?.status;
  const statusText = typeof status === "number"
    ? `${status}${resp?.reason ? " " + resp.reason : ""}`
    : err
      ? "ERR"
      : "””";
  // Class name for status-code tinting, matching Burp's status palette.
  let statusClass = "";
  if (err) {
    statusClass = "err";
  } else if (typeof status === "number") {
    if (status >= 500) statusClass = "server-error";
    else if (status >= 400) statusClass = "client-error";
    else if (status >= 300) statusClass = "redirect";
    else if (status >= 200) statusClass = "success";
  }
  // Content-Type from response headers, stripped of charset bit.
  const ctHeader = (resp?.headers?.items ?? []).find(
    (h: any) => (h?.name ?? "").toLowerCase() === "content-type",
  );
  const contentType = ctHeader?.value?.split(";")[0]?.trim() || "";

  return (
    <div className="rep-status-bar">
      <span
        className={`rep-status-code${statusClass ? " " + statusClass : ""}`}
        title={err ? `Error: ${err}` : `HTTP ${statusText}`}
      >
        {statusText}
      </span>
      <span className="rep-status-sep">·</span>
      <span className="rep-status-item">
        <strong>Size:</strong>
        {fmtBytes(totalBytes)}
      </span>
      <span className="rep-status-sep">·</span>
      <span className="rep-status-item">
        <strong>Elapsed:</strong>
        {fmtMs(elapsed)}
      </span>
      {contentType && (
        <>
          <span className="rep-status-sep">·</span>
          <span className="rep-status-item">
            <strong>Type:</strong>
            {contentType}
          </span>
        </>
      )}
      <span className="rep-status-spacer" />
      <span className="rep-status-item">
        <strong>Send:</strong>
        {idx + 1} / {history.length}
      </span>
    </div>
  );
}
