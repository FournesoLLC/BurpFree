// DiscoveryModal.tsx
//
// Content Discovery engagement tool. Operator picks a target host,
// optionally supplies a wordlist, hits Start — the backend brute-
// forces paths, filters sham-404s, and the hits appear in the live
// table. Each hit is also recorded in HTTP history (tagged
// `content-discovery`) so it can be sent to Repeater / Scanner.

import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export type DiscoveryHit = {
  path: string;
  url: string;
  status: number;
  length: number;
  content_type?: string | null;
  elapsed_ms: number;
  title?: string | null;
  transaction_id?: number | null;
};

export type DiscoverySummary = {
  probes_sent: number;
  probes_errored: number;
  hits: number;
  elapsed_ms: number;
};

export type DiscoveryTargetPreset = {
  scheme: string;
  host: string;
  port: number;
};

interface Props {
  open: boolean;
  preset?: DiscoveryTargetPreset | null;
  onClose: () => void;
}

export function DiscoveryModal({ open, preset, onClose }: Props) {
  const [scheme, setScheme] = useState<"http" | "https">("https");
  const [host, setHost] = useState("");
  const [port, setPort] = useState<number>(443);
  const [wordlist, setWordlist] = useState<string>("");
  const [wordCount, setWordCount] = useState(0);
  const [concurrency, setConcurrency] = useState(6);
  const [includeForbidden, setIncludeForbidden] = useState(true);
  const [running, setRunning] = useState(false);
  const [hits, setHits] = useState<DiscoveryHit[]>([]);
  const [summary, setSummary] = useState<DiscoverySummary | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    setErr(null);
    setHits([]);
    setSummary(null);
    if (!loaded) {
      invoke<string>("discovery_default_wordlist")
        .then((src) => {
          setWordlist(src);
          setWordCount(countWords(src));
          setLoaded(true);
        })
        .catch((e) => setErr(`${e}`));
    }
    if (preset) {
      setScheme(preset.scheme === "http" ? "http" : "https");
      setHost(preset.host);
      setPort(preset.port);
    }
  }, [open, preset, loaded]);

  // Esc to close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  function countWords(src: string): number {
    return src.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#")).length;
  }

  async function start() {
    if (!host.trim()) { setErr("host required"); return; }
    setRunning(true);
    setErr(null);
    setHits([]);
    setSummary(null);
    try {
      const res = await invoke<{ hits: DiscoveryHit[]; summary: DiscoverySummary }>(
        "discovery_run",
        {
          args: {
            scheme,
            host: host.trim(),
            port,
            wordlist: wordlist.length > 0 ? wordlist : undefined,
            concurrency,
            include_forbidden: includeForbidden,
          },
        }
      );
      setHits(res.hits.sort((a, b) => a.status - b.status || a.path.localeCompare(b.path)));
      setSummary(res.summary);
    } catch (e) {
      setErr(`${e}`);
    } finally {
      setRunning(false);
    }
  }

  function updateWordlist(src: string) {
    setWordlist(src);
    setWordCount(countWords(src));
  }

  return (
    <div className="poc-backdrop" onClick={onClose}>
      <div
        className="poc-dialog discovery-dialog"
        ref={panelRef}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="poc-head">
          <strong>Content Discovery</strong>
          <span className="dim" style={{ fontSize: 11 }}>
            path brute-force · {wordCount} words · tags each hit `content-discovery`
          </span>
          <span style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
        <div className="discovery-head">
          <div className="discovery-target">
            <label>Scheme</label>
            <select value={scheme} onChange={(e) => setScheme(e.target.value as "http" | "https")} disabled={running}>
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
            <label>Host</label>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="example.com"
              disabled={running}
              style={{ width: 220 }}
            />
            <label>Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(parseInt(e.target.value) || 0)}
              disabled={running}
              style={{ width: 70 }}
            />
            <label>Concurrency</label>
            <input
              type="number"
              min={1}
              max={32}
              value={concurrency}
              onChange={(e) => setConcurrency(Math.max(1, Math.min(32, parseInt(e.target.value) || 6)))}
              disabled={running}
              style={{ width: 60 }}
            />
            <label>
              <input
                type="checkbox"
                checked={includeForbidden}
                onChange={(e) => setIncludeForbidden(e.target.checked)}
                disabled={running}
              /> Include 403
            </label>
            <span style={{ flex: 1 }} />
            {!running && <button className="primary" onClick={start} disabled={!host.trim()}>Start</button>}
            {running && <span style={{ color: "var(--accent)" }}>Running…</span>}
          </div>
          {err && <div style={{ color: "var(--red)", padding: "6px 10px" }}>✗ {err}</div>}
        </div>
        <div className="discovery-body">
          <div className="discovery-list">
            <table>
              <colgroup>
                <col style={{ width: 60 }} />
                <col />
                <col style={{ width: 80 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 220 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Path</th>
                  <th>Length</th>
                  <th>Time</th>
                  <th>Title / Type</th>
                </tr>
              </thead>
              <tbody>
                {hits.length === 0 && !running && (
                  <tr><td colSpan={5} className="dim" style={{ padding: 12, textAlign: "center" }}>
                    No hits yet. Fill in the target above and click Start.
                  </td></tr>
                )}
                {hits.map((h, i) => (
                  <tr key={i}>
                    <td className={`mono status-${Math.floor(h.status / 100)}xx`}>{h.status}</td>
                    <td className="mono" title={h.url}>{h.path}</td>
                    <td className="mono dim">{h.length}</td>
                    <td className="mono dim">{h.elapsed_ms}ms</td>
                    <td className="dim" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.content_type ?? ""}>
                      {h.title || h.content_type || ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="discovery-wordlist">
            <label className="discovery-wordlist-label">
              Wordlist · {wordCount} words
            </label>
            <textarea
              value={wordlist}
              onChange={(e) => updateWordlist(e.target.value)}
              disabled={running}
              placeholder="One path per line. Lines starting with # are ignored."
            />
          </div>
        </div>
        {summary && (
          <div className="poc-foot">
            {summary.hits} hit(s) · {summary.probes_sent} probe(s) sent · {summary.probes_errored} errored · {summary.elapsed_ms} ms
            {" "}· Each hit was recorded in HTTP history with tag <code>content-discovery</code>.
          </div>
        )}
      </div>
    </div>
  );
}
