import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  MatchReplaceEngine,
  MatchReplacePreview,
  MatchReplaceRule,
  MatchReplaceRuleScope,
  MatchReplaceRuleTarget,
} from "../api";

const TARGETS: Array<{ id: MatchReplaceRuleTarget; label: string; description: string }> = [
  { id: "method",         label: "Method",        description: "Rewrite the HTTP method (GET → POST…)" },
  { id: "url",            label: "URL",           description: "Rewrite the full request URL" },
  { id: "path",           label: "Path",          description: "Rewrite the request path + query" },
  { id: "header_name",    label: "Header name",   description: "Rename a header" },
  { id: "header_value",   label: "Header value",  description: "Rewrite header values" },
  { id: "body",           label: "Body",          description: "Rewrite the raw body" },
  { id: "first_line",     label: "First line",    description: "Rewrite the start-line (method path version / status reason)" },
  { id: "add_header",     label: "Add header",    description: "Match = name, Replace = value" },
  { id: "remove_header",  label: "Remove header", description: "Match = header name to drop" },
  { id: "set_body",       label: "Set body",      description: "Replace the entire body with Replace" },
];

const SCOPES: Array<{ id: MatchReplaceRuleScope; label: string }> = [
  { id: "request",  label: "Request" },
  { id: "response", label: "Response" },
  { id: "both",     label: "Both" },
];

/// Humanize a wall-clock age for the "Last fire" column. Returns
/// "—" when the rule has never fired (undefined / 0 timestamp), a
/// coarse bucket under a minute so sub-second churn doesn't thrash
/// the display, and otherwise the biggest unit that fits
/// ("5s"/"2m"/"1h"/"3d"). Deliberately short — the column is
/// narrow and the exact timestamp lives in the tooltip.
function humanizeAge(tsMs: number | undefined): string {
  if (!tsMs || tsMs <= 0) return "—";
  const now = Date.now();
  const diff = Math.max(0, now - tsMs);
  if (diff < 1_000) return "just now";
  const s = Math.floor(diff / 1_000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function MatchReplacePane() {
  const [engine, setEngine] = useState<MatchReplaceEngine>({ rules: [] });
  // R140: Hidden file input for the "⬆ Import" button.
  const mrFileRef = useRef<HTMLInputElement | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  // Live per-rule fire counter. Polled every 2s from
  // `match_replace_hits`; the backend stores it on an Arc<Mutex>
  // shared across engine clones so Save (which only swaps the rule
  // vec in place via `update_rules`) doesn't zero the trail.
  const [hits, setHits] = useState<Record<string, number>>({});
  // Live per-rule last-fire epoch (ms). Polled alongside `hits` so
  // the "Last fire" column tracks the same tick as the counter.
  // Absent keys render as "—" via `humanizeAge`. Reset by
  // `resetHits` through the backend's `clear_hits` which wipes both
  // maps together.
  const [lastFires, setLastFires] = useState<Record<string, number>>({});
  // Wall-clock pulse: forces `humanizeAge` to re-render every 30s
  // so a "2m ago" cell doesn't go stale between actual fires on
  // long-idle rules. Cheap — just a counter bump; the table rows
  // only read it indirectly through the humanize call.
  const [, setTickTock] = useState(0);
  const [hitsBusy, setHitsBusy] = useState(false);
  // Preview-on-sample state. Persists for the pane's lifetime so an
  // operator who runs a preview, tweaks a rule, saves, and runs again
  // doesn't have to re-type the URL / body each pass. The preview
  // runs against the *saved* ruleset — a dirty-badge calls that out.
  const [previewDirection, setPreviewDirection] = useState<"request" | "response">("request");
  const [previewUrl, setPreviewUrl] = useState("https://example.com/api/users");
  const [previewMethod, setPreviewMethod] = useState("GET");
  const [previewBody, setPreviewBody] = useState("");
  const [previewReport, setPreviewReport] = useState<MatchReplacePreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  async function runPreview() {
    setPreviewing(true);
    setPreviewError(null);
    try {
      const report = await api.matchReplacePreview({
        direction: previewDirection,
        url: previewUrl.trim(),
        method: previewMethod,
        body: previewBody || undefined,
      });
      setPreviewReport(report);
    } catch (e) {
      setPreviewReport(null);
      setPreviewError(`${e}`);
    } finally {
      setPreviewing(false);
    }
  }

  const refresh = useCallback(async () => {
    try {
      const e = await api.matchReplaceGet();
      setEngine(e ?? { rules: [] });
      setDirty(false);
    } catch (err) {
      console.error("match/replace load:", err);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  // Poll the hit counter and last-fire timestamps every 2s so the
  // operator sees fires land in near-real-time without a Refresh
  // click. Both pulls go out in parallel — the backend serves each
  // from the same engine lock, so the lockstep is best-effort but
  // close enough for a "last fire" display. Guard against the
  // "no project loaded" case — the cmds return a Promise reject
  // and we silently keep the stale value.
  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const [nextHits, nextFires] = await Promise.all([
          api.matchReplaceHits(),
          api.matchReplaceLastFires(),
        ]);
        if (alive) {
          setHits(nextHits ?? {});
          setLastFires(nextFires ?? {});
        }
      } catch {
        /* no project yet or cmd race — leave the last snapshot */
      }
    };
    void pull();
    const t = setInterval(pull, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // Pulse every 30s so idle rules' "2m ago / 5m ago" labels advance
  // between fires. Separate from the 2s poll loop so we don't thrash
  // the Tauri bridge just to re-render humanized labels.
  useEffect(() => {
    const t = setInterval(() => setTickTock((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, []);

  async function resetHits() {
    if (hitsBusy) return;
    setHitsBusy(true);
    try {
      await api.matchReplaceHitsClear();
      setHits({});
      setLastFires({});
    } catch (e) {
      alert(`Could not reset hits: ${e}`);
    } finally {
      setHitsBusy(false);
    }
  }

  // Total firings across every rule — surfaced in the Reset button
  // label so the operator knows how much state the click clears.
  const totalHits = Object.values(hits).reduce((a, b) => a + b, 0);

  async function save() {
    setSaving(true);
    try {
      await api.matchReplaceSet(engine);
      setDirty(false);
    } catch (e) {
      alert(`${e}`);
    } finally {
      setSaving(false);
    }
  }

  function patchRule(id: string, patch: Partial<MatchReplaceRule>) {
    setEngine((prev) => ({
      rules: prev.rules.map((r) => (r.id === id ? { ...r, ...patch } : r)),
    }));
    setDirty(true);
  }

  function addRule() {
    const id = `rule_${Math.random().toString(36).slice(2, 10)}`;
    const r: MatchReplaceRule = {
      id,
      name: "New rule",
      enabled: true,
      scope: "request",
      target: "header_value",
      match_: "",
      replace: "",
      regex: false,
      host_filter: null,
      predicate_script: null,
    };
    setEngine((prev) => ({ rules: [...prev.rules, r] }));
    setSelected(id);
    setDirty(true);
  }

  /*  R189: Clone a rule — deep-copy with a fresh id, insert
   *  right after the original so operators tweak the clone
   *  in-place next to its sibling. Lands in draft so Save/
   *  Revert still gate persistence. Mirrors Burp Pro's
   *  "Duplicate rule" action from the Match & Replace context
   *  menu. */
  function cloneRule(id: string) {
    setEngine((prev) => {
      const idx = prev.rules.findIndex((r) => r.id === id);
      if (idx < 0) return prev;
      const src = prev.rules[idx];
      const newId = `rule_${Math.random().toString(36).slice(2, 10)}`;
      const clone: MatchReplaceRule = {
        ...src,
        id: newId,
        name: `${src.name} (copy)`,
      };
      const next = [...prev.rules];
      next.splice(idx + 1, 0, clone);
      return { ...prev, rules: next };
    });
    setDirty(true);
  }

  function removeRule(id: string) {
    setEngine((prev) => ({ rules: prev.rules.filter((r) => r.id !== id) }));
    if (selected === id) setSelected(null);
    setDirty(true);
  }

  function move(id: string, delta: -1 | 1) {
    setEngine((prev) => {
      const idx = prev.rules.findIndex((r) => r.id === id);
      if (idx < 0) return prev;
      const to = idx + delta;
      if (to < 0 || to >= prev.rules.length) return prev;
      const rules = prev.rules.slice();
      const [moved] = rules.splice(idx, 1);
      rules.splice(to, 0, moved);
      return { rules };
    });
    setDirty(true);
  }

  const sel = engine.rules.find((r) => r.id === selected) ?? null;

  return (
    <div className="mr-panel">
      <div className="toolbar">
        <strong>Match and replace</strong>
        <span className="dim">
          Rules fire on in-scope traffic before it reaches upstream. Scripts (optional) gate the rule.
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          onClick={() => void resetHits()}
          disabled={hitsBusy || totalHits === 0}
          title="Zero every rule's live fire counter. Useful when iterating on a rule chain — re-measure cleanly after each tweak without an app restart."
        >
          Reset hits{totalHits > 0 ? ` (${totalHits.toLocaleString()})` : ""}
        </button>
        <button onClick={addRule}>+ Rule</button>
        {/* ------------------------------------------------------- */}
        {/* R160: Bulk enable / disable — mirror of R156 for         */}
        {/* Session rules. Operators flipping a project between     */}
        {/* passive-recon mode and active-attack mode want to turn   */}
        {/* every Match & Replace rule off (or on) in one click      */}
        {/* without walking each per-row checkbox. Lands in draft    */}
        {/* via `setDirty(true)` so operators get a Save/Revert      */}
        {/* escape hatch before the engine applies — matches the    */}
        {/* existing flow for per-rule toggles.                      */}
        <button
          disabled={engine.rules.length === 0 || engine.rules.every((r) => r.enabled)}
          onClick={() => {
            setEngine((prev) => ({
              ...prev,
              rules: prev.rules.map((r) => (r.enabled ? r : { ...r, enabled: true })),
            }));
            setDirty(true);
          }}
          title={
            engine.rules.length === 0
              ? "No rules to enable"
              : engine.rules.every((r) => r.enabled)
                ? "All rules are already enabled"
                : `Enable ${engine.rules.filter((r) => !r.enabled).length} disabled rule(s). Lands in draft; Save to persist.`
          }
        >
          ✓ Enable all
        </button>
        <button
          disabled={engine.rules.length === 0 || engine.rules.every((r) => !r.enabled)}
          onClick={() => {
            const enabledCount = engine.rules.filter((r) => r.enabled).length;
            if (
              !confirm(
                `Disable ${enabledCount} rule${enabledCount === 1 ? "" : "s"}? Lands in draft — Save to actually stop the engine from mutating live traffic.`,
              )
            )
              return;
            setEngine((prev) => ({
              ...prev,
              rules: prev.rules.map((r) => (r.enabled ? { ...r, enabled: false } : r)),
            }));
            setDirty(true);
          }}
          title={
            engine.rules.length === 0
              ? "No rules to disable"
              : engine.rules.every((r) => !r.enabled)
                ? "All rules are already disabled"
                : `Disable ${engine.rules.filter((r) => r.enabled).length} enabled rule(s). Lands in draft; Save to actually freeze.`
          }
        >
          ∅ Disable all
        </button>
        <button onClick={refresh} disabled={saving}>Revert</button>
        {/* R303: Export M&R rules as JSON — companion to R124    */}
        {/* scope export + R280 settings export. Operators         */}
        {/* managing shared Match & Replace rules across machines  */}
        {/* or teammates can now round-trip the rule set as a      */}
        {/* portable JSON blob. Dumps the current draft engine    */}
        {/* (unsaved tweaks included) so operators can share a    */}
        {/* work-in-progress rule set without having to persist   */}
        {/* first. Timestamped filename so overlapping exports     */}
        {/* don't collide on disk.                                  */}
        <button
          disabled={engine.rules.length === 0}
          onClick={() => {
            try {
              const payload = JSON.stringify(engine, null, 2);
              const blob = new Blob([payload], {
                type: "application/json;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              a.href = url;
              a.download = `burpfree-matchreplace-${stamp}.json`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            engine.rules.length === 0
              ? "No rules to export"
              : `Export the current Match & Replace engine (${engine.rules.length} rule${engine.rules.length === 1 ? "" : "s"}) as a JSON file. Includes unsaved draft tweaks.`
          }
        >
          ⬇ Export
        </button>
        <button
          className={dirty ? "primary" : ""}
          onClick={save}
          disabled={!dirty || saving}
        >
          {saving ? "Saving…" : dirty ? "Save" : "Saved"}
        </button>
        {/* R140: Export / Import Match & Replace rules as JSON.    */}
        {/* Burp's Match & Replace tab has these for sharing       */}
        {/* curated rule sets between projects / teammates. Export  */}
        {/* dumps the current engine state (not just rules — the    */}
        {/* whole MatchReplaceEngine so a round-trip restores any    */}
        {/* top-level knobs); Import loads via engine replace +     */}
        {/* Save round-trip so the hit counters reset cleanly.      */}
        <button
          disabled={engine.rules.length === 0}
          onClick={() => {
            try {
              const payload = JSON.stringify(engine, null, 2);
              const blob = new Blob([payload], {
                type: "application/json;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              a.href = url;
              a.download = `burpfree-match-replace-${stamp}.json`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            engine.rules.length === 0
              ? "No rules to export"
              : `Export ${engine.rules.length} rule${engine.rules.length === 1 ? "" : "s"} as JSON`
          }
        >
          ⬇ Export
        </button>
        <input
          ref={mrFileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Match & Replace caps at 2 MB.`,
              );
              return;
            }
            if (
              engine.rules.length > 0 &&
              !confirm(
                `Replace ${engine.rules.length} rule${engine.rules.length === 1 ? "" : "s"} with ${file.name}?`,
              )
            ) {
              return;
            }
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              if (
                !parsed ||
                typeof parsed !== "object" ||
                !Array.isArray(parsed.rules)
              ) {
                alert(
                  "Not a Match & Replace file — expected { rules: [...] } shape.",
                );
                return;
              }
              // Lands in draft via Save so the backend applies the
              // engine + persists atomically. The dirty-flag flow
              // doesn't apply here because we overwrite everything
              // in one shot — treat it like a full engine replace.
              setEngine(parsed as MatchReplaceEngine);
              setDirty(true);
            } catch (err) {
              alert(`Import failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => mrFileRef.current?.click()}
          title="Import Match & Replace rules from a JSON file. Lands in draft; Save after reviewing."
        >
          ⬆ Import
        </button>
        <span className="dim mono">{engine.rules.length} rule(s)</span>
      </div>
      <div className="mr-grid">
        <div className="mr-table">
          <table>
            <colgroup>
              <col style={{ width: 70 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 110 }} />
              <col />
              <col />
              <col style={{ width: 40 }} />
              <col style={{ width: 60 }} />
              <col style={{ width: 70 }} />
            </colgroup>
            <thead>
              <tr>
                <th>Enabled</th>
                <th>Scope</th>
                <th>Target</th>
                <th>Match</th>
                <th>Replace</th>
                <th title="regex / literal">R</th>
                <th title="Live fire count — how many times this rule's apply path has mutated a message since the last Reset. Polled every 2s.">Hits</th>
                <th title="Wall-clock age of the most recent fire. Blank until the rule fires at least once. Updates on the same 2s poll as Hits.">Last fire</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {engine.rules.map((r) => (
                <tr
                  key={r.id}
                  className={selected === r.id ? "selected" : ""}
                  onClick={() => setSelected(r.id)}
                >
                  <td style={{ textAlign: "center" }}>
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      onChange={(e) => patchRule(r.id, { enabled: e.target.checked })}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </td>
                  <td className="mono">{r.scope}</td>
                  <td className="mono">{labelFor(r.target)}</td>
                  <td className="mono mr-ellipsis" title={r.match_}>{r.match_ || <span className="dim">—</span>}</td>
                  <td className="mono mr-ellipsis" title={r.replace}>{r.replace || <span className="dim">—</span>}</td>
                  <td style={{ textAlign: "center", color: r.regex ? "var(--accent)" : "var(--text-faint)" }}>
                    {r.regex ? "re" : ""}
                  </td>
                  <td
                    style={{
                      textAlign: "right",
                      color: (hits[r.id] ?? 0) > 0 ? "var(--accent, #e07c50)" : "var(--text-faint)",
                      fontWeight: (hits[r.id] ?? 0) > 0 ? 600 : 400,
                    }}
                    title={
                      (hits[r.id] ?? 0) === 0
                        ? "No fires yet. Live traffic that passes this rule's gate (enabled + scope + host filter + predicate) and matches its pattern bumps this counter."
                        : `This rule has fired ${hits[r.id]} time(s) since the last Reset.`
                    }
                  >
                    {(hits[r.id] ?? 0).toLocaleString()}
                  </td>
                  <td
                    className="mono"
                    style={{
                      textAlign: "right",
                      color: lastFires[r.id] ? "var(--text)" : "var(--text-faint)",
                      whiteSpace: "nowrap",
                      fontSize: 11,
                    }}
                    title={
                      lastFires[r.id]
                        ? `Last fired at ${new Date(lastFires[r.id]).toLocaleString()}`
                        : "No fires yet — timestamp will populate on the first apply."
                    }
                  >
                    {humanizeAge(lastFires[r.id])}
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <button className="ghost" onClick={() => move(r.id, -1)} title="Move up">▲</button>
                    <button className="ghost" onClick={() => move(r.id, +1)} title="Move down">▼</button>
                    <button className="ghost" onClick={() => cloneRule(r.id)} title="Clone rule">⎘</button>
                    <button className="ghost danger" onClick={() => removeRule(r.id)} title="Delete">✕</button>
                  </td>
                </tr>
              ))}
              {engine.rules.length === 0 && (
                <tr><td colSpan={9} style={{ textAlign: "center", padding: 20, color: "var(--text-dim)" }}>
                  No rules yet. Click “+ Rule” to add your first.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mr-editor">
          {!sel && <div className="empty">Select a rule on the left to edit its details, or add a new one.</div>}
          {sel && <RuleEditor rule={sel} onChange={(p) => patchRule(sel.id, p)} />}
        </div>
      </div>
      <div
        style={{
          padding: 8,
          borderTop: "1px solid var(--border)",
          background: "var(--bg-raised)",
        }}
      >
        <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
          <strong style={{ fontSize: 12 }}>Preview on sample</strong>
          <select
            value={previewDirection}
            onChange={(e) => setPreviewDirection(e.target.value as "request" | "response")}
            title="Which direction's rules to dry-run"
          >
            <option value="request">Request</option>
            <option value="response">Response</option>
          </select>
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
            style={{ flex: 1, minWidth: 220, fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}
            title="Absolute URL for the sample. host_filter + URL/host/path targets probe this."
          />
          <button
            disabled={previewing || !previewUrl.trim()}
            onClick={() => void runPreview()}
            title={
              dirty
                ? "Save your edits first — the preview runs against the persisted ruleset"
                : "Dry-run the saved rules against this sample"
            }
          >
            {previewing ? "Running…" : dirty ? "Run (saved rules only)" : "Run preview"}
          </button>
          {previewReport && (
            <span
              className="badge"
              title="Number of rules that actually mutated the sample"
              style={{
                background:
                  previewReport.net_mutations > 0
                    ? "rgba(224,124,80,0.18)"
                    : undefined,
                color:
                  previewReport.net_mutations > 0
                    ? "var(--accent, #e07c50)"
                    : "var(--text-dim)",
              }}
            >
              {previewReport.net_mutations} rule
              {previewReport.net_mutations === 1 ? "" : "s"} fired
            </span>
          )}
        </div>
        <textarea
          value={previewBody}
          onChange={(e) => setPreviewBody(e.target.value)}
          rows={2}
          placeholder={previewDirection === "request" ? "optional request body (JSON/form)" : "optional response body"}
          style={{
            marginTop: 6,
            width: "100%",
            fontFamily: "var(--font-mono, monospace)",
            fontSize: 11,
            boxSizing: "border-box",
          }}
          title="Body is seeded with Content-Type: application/json + Content-Length so Body / SetBody / HeaderValue rules have something concrete to probe. Leave empty to skip."
        />
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
        {previewReport && previewReport.rules_applied.length > 0 && (
          <table className="mono" style={{ marginTop: 8, width: "100%", fontSize: 11 }}>
            <colgroup>
              <col style={{ width: 60 }} />
              <col />
              <col style={{ width: 90 }} />
              <col style={{ width: 60 }} />
            </colgroup>
            <thead>
              <tr>
                <th>Enabled</th>
                <th>Rule</th>
                <th title="scope + host_filter + predicate passed">Scope</th>
                <th>Fired</th>
              </tr>
            </thead>
            <tbody>
              {previewReport.rules_applied.map((rh) => (
                <tr
                  key={rh.id}
                  style={{
                    opacity: rh.enabled ? 1 : 0.5,
                    background: rh.enabled && rh.fired ? "rgba(224,124,80,0.08)" : undefined,
                  }}
                  title={rh.enabled ? undefined : "Disabled rule — not evaluated"}
                >
                  <td style={{ textAlign: "center" }}>{rh.enabled ? "✓" : "·"}</td>
                  <td style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {rh.name || <span className="dim">{rh.id}</span>}
                  </td>
                  <td
                    style={{
                      textAlign: "center",
                      color: rh.scope_matched ? "var(--green, #4bbf6b)" : "var(--text-dim)",
                    }}
                  >
                    {rh.scope_matched ? "✓" : "·"}
                  </td>
                  <td
                    style={{
                      textAlign: "center",
                      color: rh.fired ? "var(--accent, #e07c50)" : "var(--text-dim)",
                      fontWeight: rh.fired ? 600 : 400,
                    }}
                  >
                    {rh.fired ? "✓" : "·"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {previewReport && (
          <div
            style={{
              marginTop: 8,
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 6,
              fontSize: 11,
            }}
          >
            <div>
              <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 2 }}>Before</div>
              <pre
                className="mono"
                style={{
                  margin: 0,
                  padding: 6,
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 240,
                  overflow: "auto",
                }}
              >
                {previewReport.before_wire}
              </pre>
            </div>
            <div>
              <div
                style={{
                  fontSize: 10,
                  color: previewReport.net_mutations > 0 ? "var(--accent, #e07c50)" : "var(--text-dim)",
                  marginBottom: 2,
                }}
              >
                After {previewReport.net_mutations > 0 ? "(mutated)" : "(no change)"}
              </div>
              <pre
                className="mono"
                style={{
                  margin: 0,
                  padding: 6,
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 240,
                  overflow: "auto",
                }}
              >
                {previewReport.after_wire}
              </pre>
            </div>
          </div>
        )}
        {dirty && (
          <div style={{ marginTop: 6, color: "var(--text-dim)", fontSize: 11 }}>
            Rule edits are unsaved — preview still reflects the last Save.
          </div>
        )}
      </div>
    </div>
  );
}

function RuleEditor({
  rule,
  onChange,
}: {
  rule: MatchReplaceRule;
  onChange: (patch: Partial<MatchReplaceRule>) => void;
}) {
  const targetMeta = TARGETS.find((t) => t.id === rule.target);
  return (
    <div className="mr-editor-inner">
      <div className="form-row">
        <label style={{ width: 110 }}>Name</label>
        <input value={rule.name} onChange={(e) => onChange({ name: e.target.value })} style={{ flex: 1 }} />
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Scope</label>
        <select value={rule.scope} onChange={(e) => onChange({ scope: e.target.value as MatchReplaceRuleScope })}>
          {SCOPES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <label style={{ width: 90, marginLeft: 10 }}>Target</label>
        <select value={rule.target} onChange={(e) => onChange({ target: e.target.value as MatchReplaceRuleTarget })} style={{ flex: 1 }}>
          {TARGETS.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
      </div>
      {targetMeta?.description && (
        <div className="dim" style={{ paddingLeft: 110, marginTop: -4, fontSize: 11 }}>
          {targetMeta.description}
        </div>
      )}
      <div className="form-row">
        <label style={{ width: 110 }}>Match</label>
        <textarea
          value={rule.match_}
          onChange={(e) => onChange({ match_: e.target.value })}
          rows={2}
          style={{ flex: 1 }}
          placeholder={rule.target === "add_header" ? "header name" : rule.target === "remove_header" ? "header name" : "literal substring OR regex"}
        />
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Replace</label>
        <textarea
          value={rule.replace}
          onChange={(e) => onChange({ replace: e.target.value })}
          rows={2}
          style={{ flex: 1 }}
          placeholder={rule.target === "add_header" ? "header value" : rule.target === "remove_header" ? "(ignored)" : "replacement text"}
        />
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Regex</label>
        <input
          type="checkbox"
          checked={rule.regex}
          onChange={(e) => onChange({ regex: e.target.checked })}
        />
        <span className="dim">Rust regex syntax; capture groups ($1, $2…) usable in Replace.</span>
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Host filter</label>
        <input
          value={rule.host_filter ?? ""}
          onChange={(e) => onChange({ host_filter: e.target.value || null })}
          placeholder="(any) — leave blank, or substring / regex to narrow"
          style={{ flex: 1 }}
        />
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Predicate</label>
        <textarea
          value={rule.predicate_script ?? ""}
          onChange={(e) => onChange({ predicate_script: e.target.value || null })}
          placeholder='Optional Rhai boolean (empty = always fire). Example: req.method == "POST" && header(req, "Content-Type").contains("json")'
          rows={3}
          style={{ flex: 1, fontFamily: "var(--mono)" }}
        />
      </div>
    </div>
  );
}

function labelFor(t: MatchReplaceRuleTarget): string {
  return TARGETS.find((x) => x.id === t)?.label ?? t;
}
