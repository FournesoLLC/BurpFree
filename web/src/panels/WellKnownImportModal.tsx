// WellKnownImportModal — Burp-style "fetch /robots.txt + /sitemap.xml"
// engagement tool.
//
// Operator supplies a base URL (pre-filled from the right-clicked
// host in the Site Map); modal fires `targetImportWellKnown` and
// renders the parsed breakdown: robots directives, sitemap URLs,
// nested sitemaps, a flat deduped discovered-URLs list, and any
// non-fatal fetch / parse errors. Each discovered URL gets per-row
// actions (Send to Repeater, Copy, Add host to scope). Bulk
// "Send all to Repeater" + "Add all hosts to scope" buttons at
// the top of the discovered list for the hot path.

import { useEffect, useState } from "react";

import { api, RobotsParsed, SitemapParsed, WellKnownReport } from "../api";
import { buildHostIncludeRule } from "../scopeHelpers";

export type WellKnownPreset = {
  scheme: string;
  host: string;
  port: number;
};

interface Props {
  open: boolean;
  preset?: WellKnownPreset | null;
  onClose: () => void;
}

function presetToUrl(p: WellKnownPreset | null | undefined): string {
  if (!p) return "https://";
  const defaultPort =
    (p.scheme === "https" && p.port === 443) ||
    (p.scheme === "http" && p.port === 80);
  const authority = defaultPort ? p.host : `${p.host}:${p.port}`;
  return `${p.scheme}://${authority}`;
}

export function WellKnownImportModal({ open, preset, onClose }: Props) {
  const [baseUrl, setBaseUrl] = useState<string>(presetToUrl(preset));
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<WellKnownReport | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);

  // Re-prefill when the preset changes between opens (e.g. operator
  // right-clicks a different host).
  useEffect(() => {
    if (open) {
      setBaseUrl(presetToUrl(preset));
      setReport(null);
    }
  }, [open, preset]);

  if (!open) return null;

  async function runImport() {
    const url = baseUrl.trim();
    if (!url) return;
    setRunning(true);
    setReport(null);
    try {
      const r = await api.targetImportWellKnown(url);
      setReport(r);
    } catch (e) {
      alert(`Import failed: ${e}`);
    } finally {
      setRunning(false);
    }
  }

  async function sendUrlToRepeater(url: string) {
    try {
      const label = labelForUrl(url);
      await api.repeaterAddTab(label, url, "GET");
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function copyUrl(url: string) {
    try {
      await navigator.clipboard.writeText(url);
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function addHostToScope(url: string) {
    try {
      const host = new URL(url).hostname;
      await api.scopeAddRule(buildHostIncludeRule(host));
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function sendAllToRepeater() {
    if (!report || report.discovered_urls.length === 0) return;
    const n = report.discovered_urls.length;
    if (
      n > 25 &&
      !confirm(
        `Open ${n} Repeater tabs — one per discovered URL? Burp caps this at a few dozen; above that you probably want to seed Intruder or the crawler instead.`,
      )
    ) {
      return;
    }
    setBulkBusy(true);
    try {
      for (const url of report.discovered_urls) {
        try {
          await api.repeaterAddTab(labelForUrl(url), url, "GET");
        } catch {
          // One bad URL shouldn't stop the batch — keep going.
        }
      }
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", { detail: { target: "repeater" } }),
      );
    } finally {
      setBulkBusy(false);
    }
  }

  async function addAllHostsToScope() {
    if (!report || report.discovered_urls.length === 0) return;
    setBulkBusy(true);
    try {
      // De-dupe hosts across the whole URL set — a sitemap tends to
      // list the same host N times, no point in adding the same
      // scope rule N times.
      const seen = new Set<string>();
      for (const url of report.discovered_urls) {
        try {
          const host = new URL(url).hostname;
          if (seen.has(host)) continue;
          seen.add(host);
          await api.scopeAddRule(buildHostIncludeRule(host));
        } catch {
          /* skip bad URLs */
        }
      }
    } finally {
      setBulkBusy(false);
    }
  }

  const robots = report?.robots ?? null;
  const sitemap = report?.sitemap ?? null;
  const totalDiscovered = report?.discovered_urls.length ?? 0;

  return (
    <div
      className="poc-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="poc-modal"
        style={{
          minWidth: 820,
          maxWidth: "90vw",
          maxHeight: "90vh",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          className="toolbar"
          style={{
            display: "flex",
            gap: 8,
            alignItems: "center",
            padding: "6px 10px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <strong>Import robots.txt + sitemap.xml</strong>
          <span className="dim" style={{ fontSize: 11 }}>
            Fetches the two well-known files for a host and seeds the UI with everything they advertise.
          </span>
          <span className="spacer" style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose}>
            Close
          </button>
        </div>

        <div
          style={{
            display: "flex",
            gap: 6,
            alignItems: "center",
            padding: "8px 10px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <label className="dim" style={{ fontSize: 11 }}>
            Base URL
          </label>
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://example.com"
            style={{ flex: 1, fontFamily: "var(--font-mono, monospace)" }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !running) void runImport();
            }}
          />
          <button
            className="primary"
            onClick={() => void runImport()}
            disabled={running || !baseUrl.trim()}
            title="Fetch /robots.txt and /sitemap.xml for this base URL. Both fetches are tolerant: a 404 or connect-refused on either file lands in Errors below and the other one is still parsed."
          >
            {running ? "Running…" : "Run import"}
          </button>
        </div>

        <div style={{ flex: 1, overflow: "auto", padding: 10 }}>
          {!report && !running && (
            <div className="empty" style={{ color: "var(--text-dim)" }}>
              Enter a base URL above and click Run import. The modal will show robots directives, sitemap URLs, and a merged discovered-URLs list that you can send to Repeater or add to scope.
            </div>
          )}
          {running && (
            <div className="empty" style={{ color: "var(--text-dim)" }}>
              Fetching /robots.txt and /sitemap.xml…
            </div>
          )}

          {report && (
            <>
              {report.errors.length > 0 && (
                <Section
                  title="Errors"
                  count={report.errors.length}
                  titleColor="var(--red, #e04444)"
                >
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: 11 }}>
                    {report.errors.map((e, i) => (
                      <li key={i} className="mono">
                        {e}
                      </li>
                    ))}
                  </ul>
                </Section>
              )}

              <Section
                title="Discovered URLs"
                count={totalDiscovered}
                extraRight={
                  totalDiscovered > 0 && (
                    <>
                      <button
                        disabled={bulkBusy}
                        onClick={() => void sendAllToRepeater()}
                        title="Open each discovered URL as its own Repeater tab. Confirms above 25."
                      >
                        → Repeater ({totalDiscovered})
                      </button>
                      <button
                        disabled={bulkBusy}
                        onClick={() => void addAllHostsToScope()}
                        title="Walk the discovered-URLs list and add every distinct host to the scope include-list."
                      >
                        Add all hosts to scope
                      </button>
                    </>
                  )
                }
              >
                {totalDiscovered === 0 ? (
                  <div className="dim" style={{ fontSize: 11 }}>
                    No URLs discovered. Both files are either absent, returned non-2xx, or contained no &lt;loc&gt; / Sitemap: entries.
                  </div>
                ) : (
                  <table className="mono" style={{ width: "100%", fontSize: 11 }}>
                    <colgroup>
                      <col />
                      <col style={{ width: 220 }} />
                    </colgroup>
                    <tbody>
                      {report.discovered_urls.map((url, i) => (
                        <tr key={i}>
                          <td
                            title={url}
                            style={{
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              maxWidth: 0,
                            }}
                          >
                            {url}
                          </td>
                          <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                            <button
                              className="ghost"
                              onClick={() => void sendUrlToRepeater(url)}
                              title="New Repeater tab"
                            >
                              → Repeater
                            </button>
                            <button
                              className="ghost"
                              onClick={() => void copyUrl(url)}
                              title="Copy URL"
                            >
                              Copy
                            </button>
                            <button
                              className="ghost"
                              onClick={() => void addHostToScope(url)}
                              title="Add this URL's host to the scope include-list"
                            >
                              Scope
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Section>

              {robots && <RobotsSection robots={robots} />}
              {sitemap && <SitemapSection sitemap={sitemap} />}

              {report.robots_body && (
                <Section title="robots.txt (raw)" collapsed>
                  <pre
                    className="mono"
                    style={{
                      maxHeight: 260,
                      overflow: "auto",
                      background: "var(--bg)",
                      padding: 6,
                      border: "1px solid var(--border)",
                      fontSize: 11,
                    }}
                  >
                    {report.robots_body}
                  </pre>
                </Section>
              )}
              {report.sitemap_body && (
                <Section title="sitemap.xml (raw)" collapsed>
                  <pre
                    className="mono"
                    style={{
                      maxHeight: 260,
                      overflow: "auto",
                      background: "var(--bg)",
                      padding: 6,
                      border: "1px solid var(--border)",
                      fontSize: 11,
                    }}
                  >
                    {report.sitemap_body}
                  </pre>
                </Section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function RobotsSection({ robots }: { robots: RobotsParsed }) {
  const total =
    robots.user_agents.length +
    robots.disallow.length +
    robots.allow.length +
    robots.sitemaps.length +
    robots.extras.length;
  return (
    <Section title="robots.txt" count={total}>
      <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "4px 10px", fontSize: 11 }}>
        {robots.user_agents.length > 0 && (
          <>
            <div className="dim">User-agents</div>
            <div className="mono">{robots.user_agents.join(" · ")}</div>
          </>
        )}
        {robots.disallow.length > 0 && (
          <>
            <div className="dim">Disallow ({robots.disallow.length})</div>
            <ListColumn items={robots.disallow} emptyLabel="(allow-all)" />
          </>
        )}
        {robots.allow.length > 0 && (
          <>
            <div className="dim">Allow ({robots.allow.length})</div>
            <ListColumn items={robots.allow} />
          </>
        )}
        {robots.sitemaps.length > 0 && (
          <>
            <div className="dim">Sitemap refs</div>
            <ListColumn items={robots.sitemaps} />
          </>
        )}
        {robots.extras.length > 0 && (
          <>
            <div className="dim">Other</div>
            <ListColumn items={robots.extras} />
          </>
        )}
      </div>
    </Section>
  );
}

function SitemapSection({ sitemap }: { sitemap: SitemapParsed }) {
  const total = sitemap.urls.length + sitemap.nested.length;
  return (
    <Section title="sitemap.xml" count={total}>
      <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "4px 10px", fontSize: 11 }}>
        {sitemap.urls.length > 0 && (
          <>
            <div className="dim">URLs ({sitemap.urls.length})</div>
            <ListColumn items={sitemap.urls.slice(0, 50)} />
          </>
        )}
        {sitemap.nested.length > 0 && (
          <>
            <div className="dim">Nested sitemaps</div>
            <ListColumn items={sitemap.nested} />
          </>
        )}
        {sitemap.urls.length > 50 && (
          <>
            <div />
            <div className="dim" style={{ fontStyle: "italic" }}>
              …and {sitemap.urls.length - 50} more; see Discovered URLs for the full flat list.
            </div>
          </>
        )}
      </div>
    </Section>
  );
}

function ListColumn({
  items,
  emptyLabel,
}: {
  items: string[];
  emptyLabel?: string;
}) {
  return (
    <div className="mono" style={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {items.map((it, i) => (
        <span key={i} title={it}>
          {it === "" && emptyLabel ? <span className="dim">{emptyLabel}</span> : it}
        </span>
      ))}
    </div>
  );
}

function Section({
  title,
  count,
  children,
  titleColor,
  extraRight,
  collapsed,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
  titleColor?: string;
  extraRight?: React.ReactNode;
  collapsed?: boolean;
}) {
  const [open, setOpen] = useState(!collapsed);
  return (
    <div
      style={{
        marginBottom: 10,
        border: "1px solid var(--border)",
        borderRadius: 4,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "4px 8px",
          background: "var(--bg-raised)",
          borderBottom: open ? "1px solid var(--border)" : undefined,
          cursor: "pointer",
          userSelect: "none",
          fontSize: 12,
        }}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="dim" style={{ width: 10 }}>
          {open ? "▾" : "▸"}
        </span>
        <strong style={{ color: titleColor }}>{title}</strong>
        {count != null && <span className="dim">({count})</span>}
        <span className="spacer" style={{ flex: 1 }} />
        {open && (
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ display: "flex", gap: 6 }}
          >
            {extraRight}
          </div>
        )}
      </div>
      {open && <div style={{ padding: 8 }}>{children}</div>}
    </div>
  );
}

function labelForUrl(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname === "/" ? "" : u.pathname;
    return `${u.hostname}${path}`.slice(0, 60);
  } catch {
    return url.slice(0, 60);
  }
}
