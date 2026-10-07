import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type { Section } from "./App";
import { applyTheme, readMode, resolveTheme, writeMode } from "./theme";

/** A single executable entry shown in the palette. */
export type PaletteAction = {
  id: string;
  title: string;
  /** Short group label shown on the right (e.g. "Navigate", "Proxy"). */
  group: string;
  /** Lower-case search haystack. */
  keywords: string;
  /** Optional keyboard-shortcut hint rendered on the row. */
  shortcut?: string;
  /** The actual work. Return value is ignored. */
  run: () => void | Promise<void>;
};

export type { Section };

type Props = {
  open: boolean;
  onClose: () => void;
  setSection: (s: Section) => void;
  /** Optional: let a palette entry pop the shortcut cheatsheet. */
  openCheatsheet?: () => void;
  /** Optional: let a palette entry pop the passive crawler. */
  openCrawler?: () => void;
};

export function CommandPalette({
  open,
  onClose,
  setSection,
  openCheatsheet,
  openCrawler,
}: Props) {
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const actions = useMemo(
    () => buildActions(setSection, onClose, openCheatsheet, openCrawler),
    [setSection, onClose, openCheatsheet, openCrawler],
  );

  const filtered = useMemo(() => fuzzyFilter(actions, query), [actions, query]);

  // When palette opens, focus input and reset state.
  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      // Micro-defer so the <input> is in the DOM.
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  // Clamp cursor when the filtered list shrinks.
  useEffect(() => {
    if (cursor >= filtered.length) {
      setCursor(Math.max(0, filtered.length - 1));
    }
  }, [filtered.length, cursor]);

  // Keep selected row scrolled into view.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-row="${cursor}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  if (!open) return null;

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(filtered.length - 1, c + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(0, c - 1));
    } else if (e.key === "Home") {
      e.preventDefault();
      setCursor(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setCursor(Math.max(0, filtered.length - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const act = filtered[cursor];
      if (act) runAction(act, onClose);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div
      className="palette-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="palette" role="dialog" aria-label="Command palette">
        <input
          ref={inputRef}
          className="palette-input"
          placeholder="Search commands… (↑ ↓ to move, Enter to run, Esc to close)"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setCursor(0);
          }}
          onKeyDown={onKey}
        />
        <div className="palette-list" ref={listRef}>
          {filtered.length === 0 && (
            <div className="palette-empty">No commands match “{query}”.</div>
          )}
          {filtered.map((act, i) => (
            <div
              key={act.id}
              data-row={i}
              className={`palette-row ${i === cursor ? "active" : ""}`}
              onMouseEnter={() => setCursor(i)}
              onMouseDown={(e) => {
                // Prevent input blur so the click actually fires.
                e.preventDefault();
              }}
              onClick={() => runAction(act, onClose)}
            >
              <span className="palette-title">
                <Highlight text={act.title} query={query} />
              </span>
              <span className="palette-meta">
                {act.shortcut && <span className="palette-kbd">{act.shortcut}</span>}
                <span className="palette-group">{act.group}</span>
              </span>
            </div>
          ))}
        </div>
        <div className="palette-footer">
          <span>{filtered.length} / {actions.length} commands</span>
          <span className="palette-hint">
            <span className="palette-kbd">↑↓</span> navigate
            <span className="palette-kbd">↵</span> run
            <span className="palette-kbd">Esc</span> close
          </span>
        </div>
      </div>
    </div>
  );
}

function runAction(act: PaletteAction, onClose: () => void) {
  try {
    const result = act.run();
    if (result && typeof (result as Promise<void>).then === "function") {
      (result as Promise<void>).catch((e) => console.error(`palette ${act.id}:`, e));
    }
  } catch (e) {
    console.error(`palette ${act.id}:`, e);
  } finally {
    onClose();
  }
}

/* --------------------------- action registry --------------------------- */

function buildActions(
  setSection: (s: Section) => void,
  close: () => void,
  openCheatsheet?: () => void,
  openCrawler?: () => void,
): PaletteAction[] {
  const nav = (id: string, title: string, section: Section, shortcut?: string): PaletteAction => ({
    id: `nav.${id}`,
    title,
    group: "Navigate",
    keywords: `${title.toLowerCase()} nav go to ${section}`,
    shortcut,
    run: () => setSection(section),
  });
  // R444 — includes nav entries for sections that are hidden from the top-nav
  // (bchecks, websocket, graphql, organizer, session, cookies, discover, mcp)
  // so Ctrl+K remains the full-coverage navigator across every routed panel.
  const sysNav: PaletteAction[] = [
    nav("dashboard",  "Go to Dashboard",  "dashboard",  "Ctrl+1"),
    nav("target",     "Go to Target",     "target",     "Ctrl+2"),
    nav("proxy",      "Go to Proxy",      "proxy",      "Ctrl+3"),
    nav("history",    "Go to HTTP history", "history"),
    nav("intruder",   "Go to Intruder",   "intruder",   "Ctrl+4"),
    nav("repeater",   "Go to Repeater",   "repeater",   "Ctrl+5"),
    nav("collaborator", "Go to Collaborator (OOB)", "collaborator"),
    nav("sequencer",  "Go to Sequencer",  "sequencer"),
    nav("decoder",    "Go to Decoder",    "decoder"),
    nav("comparer",   "Go to Comparer",   "comparer"),
    nav("scanner",    "Go to Scanner",    "scanner"),
    nav("bchecks",    "Go to BChecks",    "bchecks"),
    nav("websocket",  "Go to WebSocket",  "websocket"),
    nav("graphql",    "Go to GraphQL",    "graphql"),
    nav("logger",     "Go to Logger",     "logger"),
    nav("learn",      "Go to Learn",      "learn",      "Alt+L"),
    nav("organizer",  "Go to Organizer",  "organizer"),
    nav("session",    "Go to Session rules", "session"),
    nav("cookies",    "Go to Cookie jar", "cookies"),
    nav("extensions", "Go to Extensions", "extensions"),
    nav("discover",   "Go to Discover",   "discover"),
    nav("mcp",        "Go to MCP server", "mcp"),
    nav("settings",   "Go to Settings",   "settings"),
  ];

  const proxy: PaletteAction[] = [
    {
      id: "proxy.start",
      title: "Proxy: start listener",
      group: "Proxy",
      keywords: "start proxy listener run",
      run: async () => { await api.proxyStart(); setSection("proxy"); },
    },
    {
      id: "proxy.stop",
      title: "Proxy: stop listener",
      group: "Proxy",
      keywords: "stop proxy listener halt",
      run: async () => { await api.proxyStop(); setSection("proxy"); },
    },
    {
      id: "proxy.intercept.req",
      title: "Intercept: enable requests only",
      group: "Proxy",
      keywords: "intercept hold request",
      run: () => api.interceptorSet(true, false),
    },
    {
      id: "proxy.intercept.both",
      title: "Intercept: enable requests + responses",
      group: "Proxy",
      keywords: "intercept both request response",
      run: () => api.interceptorSet(true, true),
    },
    {
      id: "proxy.intercept.off",
      title: "Intercept: off",
      group: "Proxy",
      keywords: "intercept off disable forward",
      run: () => api.interceptorSet(false, false),
    },
    {
      id: "proxy.browser",
      title: "Browser: launch Chromium pre-proxied",
      group: "Proxy",
      keywords: "browser chromium chrome edge brave launch",
      run: async () => { await api.browserLaunch(); },
    },
  ];

  const scanner: PaletteAction[] = [
    {
      id: "scanner.passive.run",
      title: "Scanner: run passive scan over history",
      group: "Scanner",
      keywords: "passive scan run findings",
      run: async () => {
        const n = await api.passiveRunNow();
        setSection("scanner");
        if (typeof n === "number") console.log(`passive scan: ${n} finding(s)`);
      },
    },
    {
      id: "scanner.passive.ws.run",
      title: "Scanner: scan stored WebSocket frames",
      group: "Scanner",
      keywords: "passive websocket ws secrets tokens jwt bearer",
      run: async () => {
        const n = await api.passiveWsRunNow();
        setSection("scanner");
        if (typeof n === "number") console.log(`passive ws scan: ${n} finding(s)`);
      },
    },
    ...(openCrawler
      ? [
          {
            id: "scanner.crawler.run",
            title: "Scanner: passive site crawl (walk HTML in history for links)",
            group: "Scanner",
            keywords: "crawl spider links href form fetch discovery",
            run: () => {
              close();
              openCrawler();
            },
          } satisfies PaletteAction,
        ]
      : []),
  ];

  const help: PaletteAction[] = openCheatsheet
    ? [
        {
          id: "help.shortcuts",
          title: "Help: show keyboard shortcuts cheatsheet",
          group: "Help",
          keywords: "help shortcut cheatsheet keybinding hotkey",
          shortcut: "Ctrl+?",
          run: () => {
            close();
            openCheatsheet();
          },
        },
      ]
    : [];

  const history: PaletteAction[] = [
    {
      id: "history.clear",
      title: "History: clear all transactions",
      group: "History",
      keywords: "clear history wipe reset transactions",
      run: async () => {
        if (!confirm("Clear ALL HTTP history? This cannot be undone.")) return;
        await api.historyClear();
      },
    },
    {
      id: "history.goto",
      title: "History: go to Proxy › HTTP history",
      group: "History",
      keywords: "history transactions traffic goto",
      run: () => setSection("proxy"),
    },
  ];

  const logger: PaletteAction[] = [
    {
      id: "logger.clear",
      title: "Logger: clear buffer",
      group: "Logger",
      keywords: "clear logger events",
      run: async () => { await api.loggerClear(); },
    },
  ];

  const oob: PaletteAction[] = [
    {
      id: "oob.start",
      title: "OOB: start Collaborator-style listener",
      group: "OOB",
      keywords: "oob collaborator ssrf dns listener start",
      run: async () => {
        const s = await api.oobStart();
        alert(
          `OOB listener running\nHTTP: ${s.http_addr ?? "—"}\nDNS: ${s.dns_addr ?? "—"}\npublic host: ${s.public_host}`
        );
      },
    },
    {
      id: "oob.stop",
      title: "OOB: stop listener",
      group: "OOB",
      keywords: "oob stop listener collaborator",
      run: async () => { await api.oobStop(); },
    },
    {
      id: "oob.status",
      title: "OOB: show listener status",
      group: "OOB",
      keywords: "oob status listener info",
      run: async () => {
        const s = await api.oobStatus();
        alert(
          s.running
            ? `Running\nHTTP: ${s.http_addr}\nDNS: ${s.dns_addr ?? "—"}\ninteractions: ${s.interaction_count}`
            : "OOB listener is not running"
        );
      },
    },
  ];

  const project: PaletteAction[] = [
    {
      id: "project.info",
      title: "Project: show info in console",
      group: "Project",
      keywords: "project info name path",
      run: async () => {
        const info = await api.projectInfo();
        console.log("project:", info);
      },
    },
    {
      id: "project.ca.export",
      title: "Project: copy CA path to prompt",
      group: "Project",
      keywords: "ca certificate export root",
      run: async () => {
        const info = await api.projectInfo();
        const path = `${info.root}\\ca\\ca-cert.pem`;
        prompt("Import this file into your browser trust store:", path);
      },
    },
    {
      id: "project.ca.info",
      title: "Project: show CA fingerprint",
      group: "Project",
      keywords: "ca certificate authority fingerprint info",
      run: async () => {
        const info = await api.caInfo();
        alert(
          `${info.subject}\n` +
          `serial:   ${info.serial}\n` +
          `valid:    ${info.not_before} → ${info.not_after}\n` +
          `sha256:   ${info.sha256_fingerprint}`
        );
      },
    },
    {
      id: "project.har.import",
      title: "Project: import HAR archive into history",
      group: "Project",
      keywords: "har import chrome firefox playwright archive history",
      run: async () => {
        const file = prompt(
          "Path to a .har file (Chrome / Firefox / Playwright):",
          "",
        );
        if (!file) return;
        try {
          const r = await api.harImport(file);
          alert(
            `Imported ${r.imported} entr${r.imported === 1 ? "y" : "ies"}` +
              (r.skipped ? ` (skipped ${r.skipped})` : "") +
              ".",
          );
        } catch (e) {
          alert(`HAR import failed: ${e}`);
        }
      },
    },
    {
      id: "project.har.export",
      title: "Project: export history to HAR archive",
      group: "Project",
      keywords: "har export chrome firefox playwright archive share",
      run: async () => {
        const info = await api.projectInfo();
        const dflt = `${info.root}\\export-${Date.now()}.har`;
        const out = prompt("Write history to this .har file:", dflt);
        if (!out) return;
        try {
          const r = await api.harExport(out);
          alert(
            `Wrote ${r.entries} entr${r.entries === 1 ? "y" : "ies"} ` +
              `(${(r.bytes_written / 1024).toFixed(1)} KB) to ${out}.`,
          );
        } catch (e) {
          alert(`HAR export failed: ${e}`);
        }
      },
    },
  ];

  const theme: PaletteAction[] = [
    {
      id: "theme.dark",
      title: "Theme: dark",
      group: "View",
      keywords: "theme dark appearance mode night",
      run: () => { writeMode("dark"); applyTheme(resolveTheme("dark")); },
    },
    {
      id: "theme.light",
      title: "Theme: light",
      group: "View",
      keywords: "theme light appearance mode day",
      run: () => { writeMode("light"); applyTheme(resolveTheme("light")); },
    },
    {
      id: "theme.system",
      title: "Theme: follow system",
      group: "View",
      keywords: "theme system appearance mode auto prefers-color-scheme",
      run: () => { writeMode("system"); applyTheme(resolveTheme("system")); },
    },
    {
      id: "theme.toggle",
      title: "Theme: toggle",
      group: "View",
      keywords: "theme toggle flip swap",
      run: () => {
        const current = resolveTheme(readMode());
        const next = current === "dark" ? "light" : "dark";
        writeMode(next);
        applyTheme(next);
      },
    },
  ];

  return [...sysNav, ...help, ...theme, ...proxy, ...scanner, ...history, ...logger, ...oob, ...project];
}

/* ---------------------- fuzzy matching ---------------------- */

type Scored = PaletteAction & { score: number };

/**
 * Order filtered actions by a simple fuzzy score:
 *   - +100  all tokens matched as a prefix on title
 *   - +60   all tokens matched as a substring on title
 *   - +30   all tokens matched on the keyword blob
 *   - -idx  penalise matches later in the title
 */
function fuzzyFilter(actions: PaletteAction[], query: string): PaletteAction[] {
  const q = query.trim().toLowerCase();
  if (!q) return actions;
  const tokens = q.split(/\s+/).filter(Boolean);

  const scored: Scored[] = [];
  for (const a of actions) {
    const title = a.title.toLowerCase();
    const kw = a.keywords.toLowerCase();
    let score = 0;
    let allInTitle = true;
    let earliest = Infinity;
    for (const t of tokens) {
      const idx = title.indexOf(t);
      if (idx < 0) { allInTitle = false; break; }
      earliest = Math.min(earliest, idx);
      if (idx === 0) score += 20; // prefix bonus per token
    }
    if (allInTitle) {
      score += 60 - Math.min(60, earliest);
    } else {
      const allInKw = tokens.every((t) => kw.includes(t));
      if (!allInKw) continue;
      score += 10;
    }
    scored.push({ ...a, score });
  }
  scored.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  return scored;
}

/* -------------------- highlighting -------------------- */

function Highlight({ text, query }: { text: string; query: string }) {
  const q = query.trim().toLowerCase();
  if (!q) return <>{text}</>;
  const tokens = q.split(/\s+/).filter(Boolean);
  // Highlight the longest contiguous match of each token in order.
  const lower = text.toLowerCase();
  const ranges: Array<[number, number]> = [];
  for (const t of tokens) {
    const i = lower.indexOf(t);
    if (i >= 0) ranges.push([i, i + t.length]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  // Merge overlapping.
  const merged: Array<[number, number]> = [];
  for (const r of ranges) {
    if (merged.length && merged[merged.length - 1][1] >= r[0]) {
      merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], r[1]);
    } else {
      merged.push([...r]);
    }
  }
  if (merged.length === 0) return <>{text}</>;
  const parts: React.ReactNode[] = [];
  let last = 0;
  merged.forEach(([a, b], i) => {
    if (a > last) parts.push(<span key={`t${i}`}>{text.slice(last, a)}</span>);
    parts.push(<mark key={`m${i}`}>{text.slice(a, b)}</mark>);
    last = b;
  });
  if (last < text.length) parts.push(<span key="tail">{text.slice(last)}</span>);
  return <>{parts}</>;
}
