import { CSSProperties, useEffect, useState } from "react";
import { api, CrawlCandidate, CrawlResult } from "../api";

/**
 * Minimal modal that triggers a passive site-crawl pass over every
 * HTML response in history and shows the candidate links grouped by
 * host. The crawler itself never issues requests — this is a review
 * surface so the operator can decide what to do next (promote to
 * Discovery, add to scope, send to Repeater, …).
 */
export function CrawlerModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<CrawlResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.crawlerRunNow());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;

  const q = filter.trim().toLowerCase();
  const filteredHosts = result
    ? Object.entries(result.by_host).filter(
        ([host, candidates]) =>
          !q ||
          host.toLowerCase().includes(q) ||
          candidates.some((c) => c.url.toLowerCase().includes(q)),
      )
    : [];

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.55)",
        zIndex: 1900,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        padding: "6vh 20px",
        overflow: "auto",
      }}
    >
      <div
        className="modal"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "var(--bg)",
          color: "var(--text)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          width: "min(820px, 100%)",
          maxHeight: "88vh",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            padding: "10px 14px",
            borderBottom: "1px solid var(--border)",
            gap: 10,
          }}
        >
          <strong>Passive site crawler</strong>
          <span style={{ color: "var(--text-dim)", fontSize: 12 }}>
            {result
              ? `${result.unique_candidates} candidate(s) across ${filteredHosts.length} host(s) · scanned ${result.pages_scanned} page(s) · skipped ${result.skipped_known} known`
              : "Scans every HTML response in history. No requests are issued."}
          </span>
          <span style={{ flex: 1 }} />
          <button className="primary" disabled={busy} onClick={run}>
            {busy ? "Crawling…" : result ? "Re-run" : "Run crawl"}
          </button>
          <button className="ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        {result && (
          <div
            style={{
              padding: "6px 14px",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <input
              type="text"
              placeholder="Filter host / URL…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>
        )}
        <div style={{ padding: 14, overflow: "auto" }}>
          {error && (
            <div className="severity-high" style={{ marginBottom: 8 }}>
              {error}
            </div>
          )}
          {!result && !error && (
            <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
              Click <b>Run crawl</b> to walk every HTML response in history
              and surface the links / forms / fetch calls that aren't already
              part of the project.
            </div>
          )}
          {result && filteredHosts.length === 0 && (
            <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
              No candidates match your filter.
            </div>
          )}
          {filteredHosts.map(([host, candidates]) => (
            <HostGroup key={host} host={host} candidates={candidates} filter={q} />
          ))}
        </div>
      </div>
    </div>
  );
}

function HostGroup({
  host,
  candidates,
  filter,
}: {
  host: string;
  candidates: CrawlCandidate[];
  filter: string;
}) {
  const shown = filter
    ? candidates.filter((c) => c.url.toLowerCase().includes(filter))
    : candidates;
  if (shown.length === 0) return null;
  return (
    <details open style={{ marginBottom: 10 }}>
      <summary style={{ cursor: "pointer", fontSize: 13 }}>
        <b className="mono">{host}</b>{" "}
        <span style={{ color: "var(--text-dim)", fontSize: 11 }}>
          {shown.length} candidate(s)
        </span>
      </summary>
      <table className="mono" style={{ width: "100%", fontSize: 11, marginTop: 4 }}>
        <colgroup>
          <col style={{ width: 90 }} />
          <col />
          <col style={{ width: 32 }} />
        </colgroup>
        <tbody>
          {shown.map((c) => (
            <tr key={c.url}>
              <td style={td()}>
                <span className="badge">{c.source}</span>
              </td>
              <td style={td()} title={c.referrer}>
                {c.url}
              </td>
              <td style={td()}>
                <button
                  className="ghost"
                  title="Copy URL"
                  onClick={() => navigator.clipboard.writeText(c.url)}
                >
                  ⧉
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

function td(): CSSProperties {
  return {
    padding: "3px 6px",
    borderBottom: "1px solid var(--border-dim, rgba(128,128,128,0.1))",
    verticalAlign: "middle",
    wordBreak: "break-all",
  };
}
