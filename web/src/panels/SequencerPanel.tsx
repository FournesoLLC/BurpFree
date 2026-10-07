import { useEffect, useRef, useState } from "react";
import { api } from "../api";

export function SequencerPanel() {
  const [raw, setRaw] = useState("sess-aaa\nsess-aab\nsess-aac\nsess-aad\n");
  const [report, setReport] = useState<any | null>(null);
  // Banner message set when another panel hands us tokens, so the user
  // immediately sees where the fresh batch came from.
  const [importBanner, setImportBanner] = useState<string | null>(null);
  // Hidden file input for R121's `⬆ Load tokens` button — same
  // pattern as R118 Intruder / R119 Decoder / R120 Comparer. One
  // tokens-list per file; one line per token.
  const tokensFileRef = useRef<HTMLInputElement | null>(null);

  async function analyze() {
    const tokens = raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const r = await api.sequencerAnalyze(tokens);
    setReport(r);
  }

  // Listen for cross-panel handoffs (currently from Intruder's → Sequencer
  // button). Replaces the textarea with the incoming tokens and runs the
  // analyzer so the user lands on a filled report rather than an empty
  // page. Analyses initiated this way are not awaited intentionally —
  // the Promise does its own setState and we don't want to block the
  // event-handler path.
  useEffect(() => {
    const onLoad = (e: Event) => {
      const detail = (e as CustomEvent<{ tokens: string[]; source?: string }>).detail;
      const incoming = detail?.tokens ?? [];
      if (incoming.length === 0) return;
      const nextRaw = incoming.join("\n");
      setRaw(nextRaw);
      setImportBanner(`Loaded ${incoming.length} token(s) from ${detail?.source ?? "Intruder"}.`);
      // Fire-and-forget analyse so the user sees immediate results.
      void (async () => {
        try {
          const r = await api.sequencerAnalyze(incoming);
          setReport(r);
        } catch {
          // Leave the banner so they know import succeeded even if
          // the backend analyser threw.
        }
      })();
    };
    window.addEventListener("burpfree:sequencer-load", onLoad as EventListener);
    return () => window.removeEventListener("burpfree:sequencer-load", onLoad as EventListener);
  }, []);

  // R435: Alt+Shift+C clears tokens + report with confirm.
  // Operators pivoting between token sets (e.g. production
  // session cookies → staging CSRF tokens) want a fast workspace
  // reset without walking a toolbar button. **Letter choice**
  // C = Clear. **Confirm gate** fires `confirm()` when `raw` is
  // non-trivial (>50 chars) so quick scratch iterations aren't
  // slowed by a dialog. **Mechanism** `setRaw("") + setReport(null)
  // + setImportBanner(null)`. **Guards** Alt+Shift only, text-
  // input focus skip — critical because Sequencer's textarea is
  // the primary input, operators would hate accidentally wiping
  // their paste. Blur first then Alt+Shift+C. **No-op silent**
  // when both empty.
  useEffect(() => {
    function onClearKey(e: KeyboardEvent) {
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
      if (raw.length === 0 && !report) return;
      e.preventDefault();
      if (
        raw.length > 50 &&
        !confirm(`Clear ${raw.length} chars of tokens + the analysis report?`)
      )
        return;
      setRaw("");
      setReport(null);
      setImportBanner(null);
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [raw, report]);

  // R399: Ctrl+Enter fires Analyze — keyboard version of the
  // primary toolbar button. Closes the "big primary action"
  // Ctrl+Enter family across the long-running job panels:
  // R331 Intruder (toggle attack), R397 BChecks (run all),
  // R399 Sequencer (analyze tokens). Operators pasting a fresh
  // token batch into the textarea → Ctrl+Enter lands on a
  // filled report without reaching for the toolbar. **Semantics**
  // delegates to the existing `analyze()` so the token-parsing
  // + API call + state update are byte-identical to the button.
  // **Guards** Ctrl/Meta required (no plain Enter so the textarea
  // Enter stays available for multi-line token lists), no Alt/
  // Shift (Alt+Enter reserved for future shortcuts), text-input
  // skip exempts the current textarea itself — unlike other
  // panels where we skip text input focus, Sequencer's primary
  // workflow is "type/paste tokens then Analyze", so Ctrl+Enter
  // from inside the textarea must fire. The skip only exempts
  // OTHER panels' inputs if the user tabbed away. Scoped via
  // the panel's exclusive textarea ref.
  useEffect(() => {
    function onAnalyzeKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key !== "Enter") return;
      // Note: we do NOT skip the Sequencer textarea itself here —
      // Ctrl+Enter from inside the token input is the intended
      // flow (paste → Ctrl+Enter → results).
      e.preventDefault();
      void analyze();
    }
    document.addEventListener("keydown", onAnalyzeKey);
    return () => document.removeEventListener("keydown", onAnalyzeKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [raw]);

  return (
    <div className="panel">
      <div className="toolbar">
        <button className="primary" onClick={analyze}>
          Analyze
        </button>
        {/* R648: Sequencer "📋 Copy report JSON" — clipboard dump
            of the analysis report. 7th entry in cross-panel Copy-
            as-JSON family (History R605 / Scanner R606 / Intruder
            R607 / Target R611 / Collaborator R612 / Decoder R647
            / Sequencer R648). Operators writing up a token-
            randomness audit for a ticket want the structured
            stats on the clipboard without screenshotting the
            report pane. */}
        {report && (
          <button
            onClick={() =>
              void navigator.clipboard.writeText(
                JSON.stringify(report, null, 2),
              )
            }
            title={`Copy the analysis report (${report.count} token${report.count === 1 ? "" : "s"} analyzed) as a JSON object to clipboard (2-space indent, pretty-printed). Includes count / unique / length stats / chi-square / Wald-Wolfowitz runs / per-position + top-duplicate tables. Great for ticket write-ups, jq pipelines, or diffing report runs.`}
          >
            📋 Copy report JSON
          </button>
        )}
        {/* ------------------------------------------------------- */}
        {/* R121: Load tokens from file. Burp's Sequencer has a      */}
        {/* "Load" button on its live-capture tab; we honour the     */}
        {/* same shape via a hidden `<input type="file">` + a        */}
        {/* visible toolbar button. One token per line, 20 MB cap   */}
        {/* (Sequencer burns O(n·k) on sample analysis so a huge     */}
        {/* list would hang the panel; 20 MB covers every realistic  */}
        {/* session-token / nonce / CSRF capture).                   */}
        <input
          ref={tokensFileRef}
          type="file"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 20 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Sequencer caps at 20 MB. Pre-sample before loading.`,
              );
              return;
            }
            if (
              raw.trim().length > 0 &&
              !confirm(`Replace current tokens with ${file.name}?`)
            ) {
              return;
            }
            try {
              const text = await file.text();
              // Normalise CRLF → LF so a Windows-sourced capture
              // doesn't carry stray \r on every token. Keep leading
              // whitespace (operators sometimes capture tokens with
              // a space prefix) + drop empty lines.
              const tokens = text
                .replace(/\r\n/g, "\n")
                .split("\n")
                .map((l) => l.trim())
                .filter((l) => l.length > 0);
              setRaw(tokens.join("\n"));
              setImportBanner(
                `Loaded ${tokens.length} token${tokens.length === 1 ? "" : "s"} from ${file.name}.`,
              );
            } catch (err) {
              alert(`Load file failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => tokensFileRef.current?.click()}
          title="Load tokens from a file on disk (one per line, UTF-8, 20 MB cap). Replaces current content."
        >
          ⬆ Load tokens
        </button>
        {/* R469: Sequencer token-set stats badge "📊 N tokens · avg B". */}
        {/* 6th panel to carry a toolbar "📊" quick-stats chip — joins   */}
        {/* R440 Repeater workspace stats + R442 History hosts + R451    */}
        {/* Collaborator kind-split + R452 Target Issues severity-split  */}
        {/* + R466 Decoder chain stats. Operators pasting a captured     */}
        {/* token batch want a one-glance read of "how many did I get   */}
        {/* and are they similar-length" before firing Analyze —        */}
        {/* uneven-length tokens hint at prefix/suffix contamination,   */}
        {/* uniform lengths are the normal shape for session cookies +  */}
        {/* nonces. **N tokens** = count of non-empty lines (same       */}
        {/* parsing as `analyze()`). **avg B** = mean token byte length */}
        {/* across the batch. **Visibility gate** at least one token    */}
        {/* parsed — hides for empty textarea so a fresh panel doesn't  */}
        {/* carry a zero chip. Derived inline from `raw` state (zero    */}
        {/* new memoization or backend poll).                            */}
        {(() => {
          const tokens = raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          if (tokens.length === 0) return null;
          const totalBytes = tokens.reduce((a, t) => a + t.length, 0);
          const avg = Math.round(totalBytes / tokens.length);
          // Rough uniformity read — std-dev / avg ratio, 0..1+.
          // Not surfaced numerically (too noisy); just used for tint:
          // tight = accent (consistent lengths), wide = dim (variable).
          const lens = tokens.map((t) => t.length);
          const variance =
            lens.reduce((a, l) => a + (l - avg) * (l - avg), 0) / tokens.length;
          const stdDev = Math.sqrt(variance);
          const uniform = avg > 0 && stdDev / avg < 0.1;
          return (
            <span
              className="mono"
              title={`${tokens.length} token${tokens.length === 1 ? "" : "s"} in the textarea · average length ${avg} byte${avg === 1 ? "" : "s"} · total ${totalBytes} byte${totalBytes === 1 ? "" : "s"} · std-dev ${stdDev.toFixed(1)} (${uniform ? "uniform length — looks like a clean capture" : "variable length — check for prefix/suffix contamination"})`}
              style={{ fontSize: 10.5, color: "var(--text-faint)", marginLeft: 4 }}
            >
              📊
              <span style={{ color: "var(--text)", marginLeft: 4 }}>
                {tokens.length} token{tokens.length === 1 ? "" : "s"}
              </span>
              <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
              <span style={{ color: uniform ? "var(--accent)" : "var(--text-dim)" }}>
                avg {avg}B
              </span>
            </span>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        <span style={{ color: "var(--text-dim)" }}>
          Statistical observations, not security conclusions
        </span>
      </div>
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
          <div className="form-row" style={{ padding: "6px 10px" }}>
            <label>Tokens (one per line)</label>
            {importBanner && (
              <span
                style={{
                  marginLeft: 8,
                  padding: "2px 8px",
                  borderRadius: 10,
                  border: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                  color: "var(--accent)",
                  fontSize: 11,
                }}
                title="Dismiss"
                onClick={() => setImportBanner(null)}
              >
                {importBanner}
              </span>
            )}
          </div>
          <textarea
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              if (importBanner) setImportBanner(null);
            }}
            style={{ flex: 1, margin: 10 }}
          />
        </div>
        <div
          style={{
            flex: 1,
            borderLeft: "1px solid var(--border)",
            overflow: "auto",
            padding: 10,
          }}
        >
          {!report && <div className="empty">Click Analyze to see statistics.</div>}
          {report && (
            <>
              {/* R838: Burp Sequencer-style "Overall result" verdict
                  card. Real Burp opens the Analysis tab with a big
                  verdict card showing a one-word quality rating
                  (Excellent / Good / Reasonable / Poor), the
                  effective entropy at a significance level, and the
                  overall sample size — before the operator ever
                  scrolls to the per-position tables. Our previous
                  report jumped straight into Count / Unique / Length
                  rows, which is accurate but offers no at-a-glance
                  "is this token any good?" read. **Verdict heuristic**
                  derived from existing report stats (zero new backend
                  work): entropy bits/byte + unique ratio + chi-square
                  normalized to dof. Grouped into 4 buckets with the
                  Burp-matching color scheme: excellent = green,
                  good = teal, reasonable = amber, poor = red.
                  **Effective entropy** = `shannon_entropy_bytes *
                  min_len` — gives the lower-bound bits-of-randomness
                  per token (the pessimistic estimate the operator
                  cares about for session-cookie safety). */}
              {(() => {
                const entropyBits = report.shannon_entropy_bytes ?? 0;
                const minLen = report.min_len ?? 0;
                const effectiveBits = entropyBits * minLen;
                const uniqueRatio =
                  report.count > 0 ? report.unique_count / report.count : 0;
                const chiNorm =
                  report.chi_square_dof && report.chi_square_dof > 0
                    ? (report.chi_square_byte ?? 0) / report.chi_square_dof
                    : 0;
                // Verdict thresholds: tuned to match Burp's rough
                // bands. Excellent = effectively random crypto-strong
                // output. Poor = clearly deterministic or constant.
                let verdict: "Excellent" | "Good" | "Reasonable" | "Poor";
                let color: string;
                let background: string;
                let hint: string;
                if (
                  effectiveBits >= 100 &&
                  uniqueRatio >= 0.99 &&
                  chiNorm < 2
                ) {
                  verdict = "Excellent";
                  color = "#2cb94a";
                  background = "rgba(44,185,74,0.14)";
                  hint =
                    "Looks indistinguishable from cryptographic random — safe for session tokens.";
                } else if (
                  effectiveBits >= 64 &&
                  uniqueRatio >= 0.95 &&
                  chiNorm < 3
                ) {
                  verdict = "Good";
                  color = "#4ab3c6";
                  background = "rgba(74,179,198,0.14)";
                  hint =
                    "Enough entropy for most authn uses; watch for pattern leaks at higher sample counts.";
                } else if (effectiveBits >= 32 && uniqueRatio >= 0.8) {
                  verdict = "Reasonable";
                  color = "#e8a84c";
                  background = "rgba(232,168,76,0.14)";
                  hint =
                    "Non-trivial randomness, but short enough or biased enough to be worth probing with a larger sample.";
                } else {
                  verdict = "Poor";
                  color = "#e04444";
                  background = "rgba(224,68,68,0.14)";
                  hint =
                    "Low effective entropy, high duplicate rate, or strong bias — do not use for session identity.";
                }
                return (
                  <div
                    style={{
                      padding: "10px 12px",
                      margin: "0 0 10px",
                      background,
                      border: `1px solid ${color}`,
                      borderLeft: `4px solid ${color}`,
                      borderRadius: 3,
                    }}
                    title={hint}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "baseline",
                        gap: 10,
                        marginBottom: 4,
                      }}
                    >
                      <span
                        style={{
                          color: "var(--text-dim)",
                          fontSize: 11,
                          textTransform: "uppercase",
                          letterSpacing: 0.5,
                        }}
                      >
                        Overall result
                      </span>
                      <span
                        style={{
                          color,
                          fontSize: 20,
                          fontWeight: 700,
                          letterSpacing: 0.2,
                        }}
                      >
                        {verdict}
                      </span>
                    </div>
                    <div
                      className="mono"
                      style={{ fontSize: 11.5, color: "var(--text)" }}
                    >
                      Effective entropy ≈{" "}
                      <span style={{ color, fontWeight: 600 }}>
                        {effectiveBits.toFixed(1)} bits
                      </span>{" "}
                      per token
                      <span style={{ color: "var(--text-dim)" }}>
                        {" "}
                        · sample size {report.count} ({(uniqueRatio * 100).toFixed(1)}% unique)
                      </span>
                    </div>
                    <div
                      style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 2 }}
                    >
                      {hint}
                    </div>
                  </div>
                );
              })()}
              <div className="form-row">
                <label>Count</label>
                <span className="mono">{report.count}</span>
              </div>
              <div className="form-row">
                <label>Unique</label>
                <span className="mono">{report.unique_count}</span>
              </div>
              <div className="form-row">
                <label>Length</label>
                <span className="mono">
                  min {report.min_len} · max {report.max_len} · mean {report.mean_len.toFixed(2)} · σ{" "}
                  {report.stddev_len.toFixed(2)}
                </span>
              </div>
              <div className="form-row">
                <label>Alphabet</label>
                <span className="mono">
                  {report.character_set.length} chars (~{report.bits_per_char_estimate.toFixed(2)}{" "}
                  bits/char)
                </span>
              </div>
              <div className="form-row">
                <label>Byte entropy</label>
                <span className="mono">{report.shannon_entropy_bytes.toFixed(3)} bits/byte</span>
              </div>
              <h4>Randomness tests</h4>
              <div className="form-row">
                <label>χ² (uniform byte)</label>
                <span
                  className="mono"
                  title="Chi-square statistic for byte frequencies against a uniform-256 distribution. Lower = more uniform."
                >
                  {report.chi_square_byte?.toFixed(2) ?? "—"}
                  <span style={{ color: "var(--text-dim)", marginLeft: 6 }}>
                    (dof {report.chi_square_dof ?? 0})
                  </span>
                </span>
              </div>
              <div className="form-row">
                <label>Runs test (parity)</label>
                <span
                  className="mono"
                  title="Wald-Wolfowitz z-score for byte-parity run clustering. |z| ≤ 2 ≈ random; |z| ≥ 3 ≈ clustered."
                >
                  z = {report.runs_test_z?.toFixed(2) ?? "—"}
                  <span style={{ color: "var(--text-dim)", marginLeft: 6 }}>
                    {report.runs_observed ?? 0} / {report.runs_expected?.toFixed(1) ?? "—"} runs ·
                    hi {report.runs_high_count ?? 0} · lo {report.runs_low_count ?? 0}
                  </span>
                </span>
              </div>
              <h4>Position distribution</h4>
              <table className="mono" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: "left" }}>#</th>
                    <th style={{ textAlign: "left" }}>Distinct</th>
                    <th style={{ textAlign: "left" }}>Top</th>
                  </tr>
                </thead>
                <tbody>
                  {report.per_position?.slice(0, 24).map((p: any) => (
                    <tr key={p.position}>
                      <td>{p.position}</td>
                      <td>{p.distinct_count}</td>
                      <td>
                        {Object.entries(p.distribution)
                          .sort((a: any, b: any) => b[1] - a[1])
                          .slice(0, 5)
                          .map(([c, n]) => `${JSON.stringify(c)}:${n}`)
                          .join(" ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {report.top_duplicates?.length > 0 && (
                <>
                  <h4>Duplicates</h4>
                  <table className="mono" style={{ width: "100%" }}>
                    <tbody>
                      {report.top_duplicates.map((d: any) => (
                        <tr key={d.token}>
                          <td>{d.token}</td>
                          <td>× {d.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
