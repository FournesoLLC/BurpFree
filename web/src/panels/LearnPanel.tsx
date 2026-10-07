// LearnPanel — R445. Burp Suite 2026.8 ships a "Learn" tab in the top-nav
// (between Logger and Extensions) that collects links to the Web Security
// Academy, PortSwigger documentation, and quick-start pointers for each tool.
// BurpFree's Learn panel mirrors that layout with locally-relevant links:
// our in-app shortcut cheatsheet (Ctrl+?), our project docs, and external
// learning resources that complement the toolset.
//
// Everything stays static — no backend calls — so this is a pure UI parity
// addition. The panel is a plain React component that reads nothing from
// state; it just groups anchors into Burp-style sections.
import { useEffect, useMemo, useRef, useState } from "react";

type Link = { label: string; href: string; blurb?: string };
type LearnSection = { title: string; links: Link[] };

const SECTIONS: LearnSection[] = [
  {
    title: "Start here",
    links: [
      {
        label: "Keyboard shortcut cheatsheet (Ctrl+?)",
        href: "burpfree:cheatsheet",
        blurb: "Press Ctrl+? anywhere in BurpFree to pop the full cheatsheet modal. 180+ shortcuts across Repeater, Intruder, Proxy, History, Scanner, Target, Comparer, Sequencer, Decoder, Collaborator, Logger, Cookie jar and BChecks.",
      },
      {
        label: "Command palette (Ctrl+K)",
        href: "burpfree:palette",
        blurb: "Fuzzy-search every tool, panel, and action — including hidden routes like BChecks, WebSocket, GraphQL, Organizer, Session rules, Cookie jar, Discover and MCP.",
      },
    ],
  },
  {
    title: "Learn web security",
    links: [
      {
        label: "PortSwigger Web Security Academy",
        href: "https://portswigger.net/web-security",
        blurb: "Free, interactive labs covering SQLi, XSS, SSRF, access control, business logic, deserialization, OAuth, JWT, request smuggling and more. The canonical companion curriculum for Burp Suite.",
      },
      {
        label: "OWASP Top 10 (2021)",
        href: "https://owasp.org/Top10/",
        blurb: "The flagship awareness list of the ten most critical web app risks, maintained by OWASP.",
      },
      {
        label: "OWASP Testing Guide",
        href: "https://owasp.org/www-project-web-security-testing-guide/",
        blurb: "A comprehensive manual-testing playbook keyed to each class of vulnerability.",
      },
      {
        label: "PayloadsAllTheThings",
        href: "https://github.com/swisskyrepo/PayloadsAllTheThings",
        blurb: "Community-maintained catalogue of attack payloads and bypass tricks for every major vulnerability class.",
      },
      {
        label: "HackTricks (web)",
        href: "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html",
        blurb: "Opinionated field notes for pentesting the web, kept current with recent CVEs and bypass techniques.",
      },
    ],
  },
  {
    title: "Learn each tool",
    links: [
      {
        label: "Proxy / HTTP history",
        href: "burpfree:nav:proxy",
        blurb: "Intercept, modify and queue requests and responses. Ctrl+T toggles both directions at once; the HTTP history tab mirrors Burp's chronological traffic log with filter DSL, bulk send-to-* and copy-as-{cURL,PowerShell,Python,fetch()}.",
      },
      {
        label: "Repeater",
        href: "burpfree:nav:repeater",
        blurb: "Ctrl+R from any history/scanner/target row to open a new tab. Alt+Shift+D diffs the last two responses, Alt+Shift+P copies pinned URLs, Alt+Shift+F fires every pinned tab, Alt+Shift+N opens a numbered-named tab clone.",
      },
      {
        label: "Intruder",
        href: "burpfree:nav:intruder",
        blurb: "Positional attack configurator. Ctrl+Enter kicks off the active attack from any field; Alt+Shift+U copies filtered URLs, Alt+Shift+P copies filtered payloads, Alt+Shift+C clears results.",
      },
      {
        label: "Scanner",
        href: "burpfree:nav:scanner",
        blurb: "Passive + active checks over the current project. Alt+V/T/F/W set verification on single rows; Alt+Shift+{V,T,F,K} do the bulk variants; Alt+Shift+Y undoes the last verification. Alt+Shift+R rescans; Alt+Shift+S sends to Repeater; Alt+Shift+H pivots to the parent history row.",
      },
      {
        label: "Target / Issues",
        href: "burpfree:nav:target",
        blurb: "Site-map and scope controls, plus a per-site issue list that mirrors Scanner's keyboard surface (Alt+V/T/F/W + Alt+Shift+Y undo + Alt+Shift+H history pivot).",
      },
      {
        label: "Collaborator (OOB)",
        href: "burpfree:nav:collaborator",
        blurb: "Generate payloads with unique DNS/HTTP sinks so you can detect blind SSRF, blind SQLi, blind XXE and other out-of-band findings. Alt+C clears the interaction filters.",
      },
      {
        label: "Sequencer",
        href: "burpfree:nav:sequencer",
        blurb: "Collect tokens from a repeated request and analyze randomness. Ctrl+Enter runs the analysis; Alt+Shift+C clears the token set and report.",
      },
      {
        label: "Decoder / Comparer",
        href: "burpfree:nav:decoder",
        blurb: "Decoder: chainable encode/decode/hash ops (Alt+C clears, Alt+Shift+S saves). Comparer: diff two blobs (Alt+S swaps left/right).",
      },
      {
        label: "Logger",
        href: "burpfree:nav:logger",
        blurb: "Project-wide chronological traffic log, filterable with the same expression DSL as History. Alt+C clears filters.",
      },
    ],
  },
  {
    title: "Keyboard shortcuts quick-reference",
    links: [
      {
        label: "Global · open command palette (Ctrl+K)",
        href: "burpfree:palette",
        blurb: "Fuzzy-search every tool, panel, and action — including the hidden routes (BChecks, WebSocket, GraphQL, Organizer, Session, Cookies, Discover, MCP).",
      },
      {
        label: "Global · open cheatsheet (Ctrl+?)",
        href: "burpfree:cheatsheet",
        blurb: "The full keyboard surface — 180+ shortcuts grouped by scope (Global / Repeater / HTTP history / Intruder / Scanner / Target / Decoder / Comparer / Sequencer / Collaborator / Logger / BChecks / Cookie jar / Message editor / palette). Hit Ctrl+? anywhere.",
      },
      {
        label: "Global · jump to a tab (Ctrl+1 … Ctrl+9)",
        href: "burpfree:cheatsheet",
        blurb: "Direct tab-number jumps for the first 9 top-nav tabs — Dashboard / Target / Proxy / HTTP history / Intruder / Repeater / Collaborator / Sequencer / Decoder.",
      },
      {
        label: "Global · jump to Learn (Alt+L)",
        href: "burpfree:cheatsheet",
        blurb: "Learn sits at position 13 in the top-nav, beyond the Ctrl+1..9 range. Alt+L is the direct keyboard jump — handy when you forgot which shortcut family does what.",
      },
      {
        label: "Everywhere · send-to-{Repeater, Intruder, Organizer}",
        href: "burpfree:cheatsheet",
        blurb: "Ctrl+R send to Repeater, Ctrl+I send to Intruder, Ctrl+O send to Organizer. Fires a CustomEvent so whichever panel is currently rendered picks up the selection. Ctrl+T toggles proxy intercept in both directions.",
      },
      {
        label: "Clear-filters family · Alt+C",
        href: "burpfree:cheatsheet",
        blurb: "One keystroke clears every active filter in the current panel. Reaches 7 panels — HTTP history / Decoder / Collaborator / Logger / Target Issues / Cookie jar / BChecks.",
      },
      {
        label: "Clear-results family · Alt+Shift+C",
        href: "burpfree:cheatsheet",
        blurb: "Destructive variant of Alt+C — wipes the actual stored results, not just the filter state. Reaches 6 panels — Intruder (clear attack results) / Sequencer (clear tokens + report) / Logger (clear events) / Collaborator (clear interactions) / BChecks (clear last run) / Cookie jar (clear jar).",
      },
      {
        label: "Save-visible-artifact family · Alt+Shift+S / Alt+Shift+E",
        href: "burpfree:cheatsheet",
        blurb: "Save the currently-visible artifact to a file. Alt+Shift+S in Decoder (final chain output) + Repeater (selected send response). Alt+Shift+E in Scanner (finding evidence) + Target Issues (finding evidence) + BChecks (last run report JSON). Scanner's E-vs-S choice avoids collision with its own Alt+Shift+S send-to-Repeater.",
      },
      {
        label: "Scanner ↔ Target Issues 7-shortcut parity",
        href: "burpfree:cheatsheet",
        blurb: "Both findings panels share identical single-row triage keyboard: Alt+V (verified) / Alt+T (triaging) / Alt+F (false_positive status) / Alt+W (wontfix) / Alt+Shift+Y (undo-verify) / Alt+Shift+H (pivot to parent in HTTP history) / Alt+Shift+E (save evidence).",
      },
    ],
  },
  {
    title: "Project docs",
    links: [
      {
        label: "ARCHITECTURE.md",
        href: "file://ARCHITECTURE.md",
        blurb: "How BurpFree is laid out: Rust workspace crates, the Tauri frontend bridge, the proxy engine, the extension loader, the MCP server, the OOB server.",
      },
      {
        label: "COMPATIBILITY.md",
        href: "file://COMPATIBILITY.md",
        blurb: "Round-by-round feature catalogue — every added shortcut, button, panel refinement, and compatibility note from R1 to today.",
      },
    ],
  },
];

export function LearnPanel() {
  const rootRef = useRef<HTMLDivElement | null>(null);
  // R844: Burp-identical cross-section search filter state. Case-
  // insensitive substring match across link labels + blurbs. Empty
  // query = render all sections. Section is dropped when none of its
  // links match, so operators scrolling don't see empty headers.
  const [query, setQuery] = useState("");
  const filteredSections = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return SECTIONS;
    return SECTIONS.map((sec) => ({
      ...sec,
      links: sec.links.filter(
        (lnk) =>
          lnk.label.toLowerCase().includes(q) ||
          (lnk.blurb ?? "").toLowerCase().includes(q) ||
          sec.title.toLowerCase().includes(q),
      ),
    })).filter((sec) => sec.links.length > 0);
  }, [query]);
  const filteredSectionCount = filteredSections.length;
  const filteredLinkCount = filteredSections.reduce(
    (acc, sec) => acc + sec.links.length,
    0,
  );

  // Click-handling for the pseudo-URLs we embed:
  //   burpfree:cheatsheet    → opens Ctrl+? cheatsheet
  //   burpfree:palette       → opens Ctrl+K palette
  //   burpfree:nav:<section> → fires a navigate CustomEvent (works for hidden tabs too)
  //   file://<path>          → no-op (eventually: open-in-editor)
  //   https?://*             → opens via Tauri shell if available, else noop
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const onClick = (e: MouseEvent) => {
      const a = (e.target as HTMLElement | null)?.closest("a") as HTMLAnchorElement | null;
      if (!a) return;
      const href = a.getAttribute("href") || "";
      if (href.startsWith("burpfree:cheatsheet")) {
        e.preventDefault();
        // Trigger the Ctrl+? cheatsheet via its global listener — ShortcutCheatsheet
        // doesn't export an imperative API, so we synthesize the keystroke.
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "?", ctrlKey: true, bubbles: true }));
        return;
      }
      if (href.startsWith("burpfree:palette")) {
        e.preventDefault();
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }));
        return;
      }
      if (href.startsWith("burpfree:nav:")) {
        e.preventDefault();
        const target = href.slice("burpfree:nav:".length);
        window.dispatchEvent(new CustomEvent("burpfree:navigate", { detail: { target } }));
        return;
      }
      if (href.startsWith("file://")) {
        e.preventDefault();
        // No-op for now. The Tauri shell plugin would be the natural hook here,
        // but we don't want to add that dependency for a single Learn link.
        return;
      }
      // External https: in Tauri, <a href="https://…"> opens in the system
      // default browser automatically if the webview security policy allows it.
      // We leave the default behavior intact.
    };
    el.addEventListener("click", onClick);
    return () => el.removeEventListener("click", onClick);
  }, []);

  return (
    <div
      ref={rootRef}
      style={{
        padding: 16,
        maxWidth: 1100,
        overflowY: "auto",
        height: "100%",
        boxSizing: "border-box",
      }}
    >
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ margin: "0 0 4px 0", fontSize: 18 }}>Learn</h2>
        <div style={{ fontSize: 12, color: "var(--text-faint)" }}>
          Welcome to BurpFree. This page points at the in-app shortcuts, the external
          learning material we recommend, and the project docs. Everything here is a
          link — anchors with the <code>burpfree:</code> scheme pop the matching
          BurpFree action, external <code>https:</code> links open in your system browser.
        </div>
        {/* R844: Burp-identical cross-section search filter. Burp's
            Academy page has a global filter box; ours finally lands
            the same visual. Case-insensitive substring match across
            every link label + blurb. Esc clears. Section is hidden
            when all its links filter out, so operators scrolling
            don't see empty headers. Match count surfaced inline next
            to the filter input. */}
        <div
          style={{
            marginTop: 10,
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <input
            type="text"
            placeholder="Filter learn resources by label or description…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && query) {
                e.preventDefault();
                setQuery("");
              }
            }}
            style={{ flex: 1, maxWidth: 420 }}
            title="Case-insensitive substring match across link labels + blurbs across all sections. Esc clears."
          />
          {query && (
            <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
              Showing <b>{filteredSectionCount}</b> section{filteredSectionCount === 1 ? "" : "s"} · <b>{filteredLinkCount}</b> link{filteredLinkCount === 1 ? "" : "s"}
            </span>
          )}
        </div>
      </div>
      {filteredLinkCount === 0 && query && (
        <div
          style={{
            padding: 20,
            color: "var(--text-dim)",
            textAlign: "center",
            border: "1px dashed var(--border)",
            borderRadius: 4,
          }}
        >
          No resources match <code>{query}</code>. Clear the filter or try a different query.
        </div>
      )}
      {filteredSections.map((sec) => (
        <section
          key={sec.title}
          style={{
            marginBottom: 20,
            border: "1px solid var(--border)",
            borderRadius: 4,
            padding: 12,
            background: "var(--bg-sunken)",
          }}
        >
          <h3 style={{ margin: "0 0 8px 0", fontSize: 14, color: "var(--text)" }}>{sec.title}</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {sec.links.map((lnk) => (
              <div key={lnk.href + lnk.label} style={{ padding: 6, borderLeft: "3px solid var(--accent)", paddingLeft: 10 }}>
                <a
                  href={lnk.href}
                  target={lnk.href.startsWith("http") ? "_blank" : undefined}
                  rel={lnk.href.startsWith("http") ? "noreferrer noopener" : undefined}
                  style={{ color: "var(--accent)", fontSize: 13, fontWeight: 500 }}
                >
                  {lnk.label}
                </a>
                {lnk.blurb && (
                  <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 3, lineHeight: 1.45 }}>
                    {lnk.blurb}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      ))}
      <div style={{ fontSize: 11, color: "var(--text-faint)", textAlign: "center", padding: 12 }}>
        BurpFree — an original, independent web-security testing platform.
      </div>
    </div>
  );
}
