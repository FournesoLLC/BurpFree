import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  MacroRunReport,
  SessionMacro,
  SessionMacroStep,
  SessionRule,
} from "../api";

/**
 * Session rules / macros editor.
 *
 * Left pane: list of macros + rules. Right pane: editor for the
 * selection. Bottom pane: run output when a macro is executed.
 */
export function SessionPanel() {
  const [macros, setMacros] = useState<SessionMacro[]>([]);
  const [rules, setRules] = useState<SessionRule[]>([]);
  // R142: Hidden file input for the "⬆ Import" button.
  const sessionFileRef = useRef<HTMLInputElement | null>(null);
  const [sel, setSel] = useState<
    | { kind: "macro"; id: string }
    | { kind: "rule"; id: string }
    | null
  >(null);
  const [report, setReport] = useState<MacroRunReport | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setMacros(await api.sessionMacrosList());
      setRules(await api.sessionRulesList());
    } catch (e) {
      console.error("session rules:", e);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function newMacro() {
    const id = `m_${Math.random().toString(36).slice(2, 10)}`;
    const m: SessionMacro = {
      id,
      name: "Login macro",
      notes: "",
      steps: [{
        method: "POST",
        url: "https://example.com/login",
        headers: [["Content-Type", "application/x-www-form-urlencoded"]],
        body: "username=alice&password=secret",
        extract: [{
          var: "token",
          source: { source: "body" },
          pattern: '"access_token"\\s*:\\s*"([^"]+)"',
        }],
      }],
    };
    await api.sessionMacroUpsert(m);
    await refresh();
    setSel({ kind: "macro", id });
  }

  async function newRule() {
    const id = `r_${Math.random().toString(36).slice(2, 10)}`;
    const r: SessionRule = {
      id,
      name: "Attach Bearer to /api",
      macro_id: macros[0]?.id ?? "",
      scope: { host_suffix: "example.com", path_prefix: "/api" },
      splice: [{ header: "Authorization", template: "Bearer {{token}}" }],
      apply_cookies: true,
      enabled: true,
    };
    await api.sessionRuleUpsert(r);
    await refresh();
    setSel({ kind: "rule", id });
  }

  /*  R192: Clone a macro — deep-copy with fresh id. Operators
   *  often iterate on auth flows (one for admin login, one for
   *  user login) that share most steps; cloning + tweaking is
   *  faster than re-building from newMacro's defaults. */
  async function cloneMacro(src: SessionMacro) {
    const id = `m_${Math.random().toString(36).slice(2, 10)}`;
    const clone: SessionMacro = JSON.parse(JSON.stringify(src));
    clone.id = id;
    clone.name = `${src.name} (copy)`;
    await api.sessionMacroUpsert(clone);
    await refresh();
    setSel({ kind: "macro", id });
  }

  /*  R191: Clone a session rule — deep-copy with fresh id +
   *  "(copy)" suffix. Mirror of R189 (M&R clone) + R190
   *  (Intruder payload-set clone). Operators iterating on an
   *  auth-splice rule for a different route want a copy to
   *  tweak in-place without re-filling every field. */
  async function cloneRule(src: SessionRule) {
    const id = `r_${Math.random().toString(36).slice(2, 10)}`;
    // Deep clone via JSON — scope and splice are nested, structuredClone
    // would also work but JSON stays dependency-free + bundle-slim.
    const clone: SessionRule = JSON.parse(JSON.stringify(src));
    clone.id = id;
    clone.name = `${src.name} (copy)`;
    await api.sessionRuleUpsert(clone);
    await refresh();
    setSel({ kind: "rule", id });
  }

  async function runMacro(id: string) {
    setBusy(true);
    setReport(null);
    try {
      const r = await api.sessionMacroRun(id);
      setReport(r);
    } catch (e) {
      setReport({ vars: {}, cookies: [], transcript: [], error: `${e}` });
    } finally {
      setBusy(false);
    }
  }

  const current = sel
    ? sel.kind === "macro"
      ? macros.find((m) => m.id === sel.id)
      : rules.find((r) => r.id === sel.id)
    : null;

  return (
    <div className="panel session-panel">
      <div className="toolbar">
        <strong>Session rules</strong>
        <button onClick={newMacro}>+ Macro</button>
        <button onClick={newRule} disabled={macros.length === 0} title={macros.length === 0 ? "Create a macro first" : ""}>+ Rule</button>
        <button onClick={refresh}>Refresh</button>
        {/* ------------------------------------------------------- */}
        {/* R156: Bulk enable / disable rules. Operators quickly    */}
        {/* flip every rule off between engagements (so stale       */}
        {/* auth-replay doesn't contaminate a new target) + flip    */}
        {/* back on when the project is live. Clicking per-rule in  */}
        {/* a dozen-rule project is painful; these two buttons do   */}
        {/* it in one shot. Fires per-rule upserts via              */}
        {/* Promise.allSettled so a bad write doesn't strand the    */}
        {/* rest. Macros aren't touched — they don't have an        */}
        {/* "enabled" flag; only rules reference macros under the   */}
        {/* splice/apply_cookies dispatch.                           */}
        <button
          disabled={rules.length === 0 || rules.every((r) => r.enabled)}
          onClick={async () => {
            const disabled = rules.filter((r) => !r.enabled);
            if (disabled.length === 0) return;
            try {
              const results = await Promise.allSettled(
                disabled.map((r) => api.sessionRuleUpsert({ ...r, enabled: true })),
              );
              const failures = results.filter((r) => r.status === "rejected");
              await refresh();
              if (failures.length > 0) {
                alert(
                  `Enabled ${disabled.length - failures.length} / ${disabled.length}. ${failures.length} failed — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              }
            } catch (e) {
              alert(`Enable all failed: ${e}`);
            }
          }}
          title={
            rules.length === 0
              ? "No rules to enable"
              : rules.every((r) => r.enabled)
                ? "All rules are already enabled"
                : `Enable ${rules.filter((r) => !r.enabled).length} disabled rule(s)`
          }
        >
          ✓ Enable all
        </button>
        <button
          disabled={rules.length === 0 || rules.every((r) => !r.enabled)}
          onClick={async () => {
            const enabled = rules.filter((r) => r.enabled);
            if (enabled.length === 0) return;
            if (
              !confirm(
                `Disable ${enabled.length} rule${enabled.length === 1 ? "" : "s"}? No incoming requests will have the macro's variables spliced until re-enabled.`,
              )
            )
              return;
            try {
              const results = await Promise.allSettled(
                enabled.map((r) => api.sessionRuleUpsert({ ...r, enabled: false })),
              );
              const failures = results.filter((r) => r.status === "rejected");
              await refresh();
              if (failures.length > 0) {
                alert(
                  `Disabled ${enabled.length - failures.length} / ${enabled.length}. ${failures.length} failed — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              }
            } catch (e) {
              alert(`Disable all failed: ${e}`);
            }
          }}
          title={
            rules.length === 0
              ? "No rules to disable"
              : rules.every((r) => !r.enabled)
                ? "All rules are already disabled"
                : `Disable ${rules.filter((r) => r.enabled).length} enabled rule(s)`
          }
        >
          ∅ Disable all
        </button>
        {/* R142: Export + Import macros + rules as a single JSON  */}
        {/* profile. Burp's Session handling tab has these — ops   */}
        {/* share curated auth-replay / scope-rewrite rule sets    */}
        {/* between projects. Export dumps {macros, rules}; import */}
        {/* merges via per-entry upsert so existing ids survive.   */}
        <button
          disabled={macros.length === 0 && rules.length === 0}
          onClick={() => {
            try {
              const payload = JSON.stringify({ macros, rules }, null, 2);
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
              a.download = `burpfree-session-${stamp}.json`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            macros.length === 0 && rules.length === 0
              ? "No macros or rules to export"
              : `Export ${macros.length} macro${macros.length === 1 ? "" : "s"} + ${rules.length} rule${rules.length === 1 ? "" : "s"}`
          }
        >
          ⬇ Export
        </button>
        <input
          ref={sessionFileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Session rules cap at 2 MB.`,
              );
              return;
            }
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              if (
                !parsed ||
                typeof parsed !== "object" ||
                !Array.isArray(parsed.macros) ||
                !Array.isArray(parsed.rules)
              ) {
                alert(
                  "Not a Session profile — expected { macros: [...], rules: [...] }.",
                );
                return;
              }
              const inMacros: SessionMacro[] = parsed.macros;
              const inRules: SessionRule[] = parsed.rules;
              if (
                (macros.length > 0 || rules.length > 0) &&
                !confirm(
                  `Merge ${inMacros.length} macro(s) + ${inRules.length} rule(s) with the existing set (${macros.length} + ${rules.length})? Entries with the same id get overwritten.`,
                )
              ) {
                return;
              }
              // Upsert each entry sequentially so the backend's id
              // dedup + validation runs per-row — partial failure
              // leaves successful upserts in place rather than
              // rolling back everything.
              const results = await Promise.allSettled([
                ...inMacros.map((m) => api.sessionMacroUpsert(m)),
                ...inRules.map((r) => api.sessionRuleUpsert(r)),
              ]);
              const failures = results.filter((r) => r.status === "rejected");
              await refresh();
              const total = inMacros.length + inRules.length;
              const ok = total - failures.length;
              if (failures.length > 0) {
                alert(
                  `Imported ${ok} / ${total}. ${failures.length} rejected — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              } else {
                alert(`Imported ${ok} session item${ok === 1 ? "" : "s"}.`);
              }
            } catch (err) {
              alert(`Import failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => sessionFileRef.current?.click()}
          title="Import a Session profile. Merges by id — existing entries get overwritten."
        >
          ⬆ Import
        </button>
        {/* R144: Clear all macros + rules. Operators resetting a   */}
        {/* project between engagements want a clean slate without  */}
        {/* clicking through each row's delete. Mirror of           */}
        {/* CookieJar's Clear all (R125 era).                        */}
        <button
          className="danger"
          disabled={macros.length === 0 && rules.length === 0}
          onClick={async () => {
            const total = macros.length + rules.length;
            if (
              !confirm(
                `Delete all ${macros.length} macro(s) + ${rules.length} rule(s)? Cannot be undone.`,
              )
            )
              return;
            try {
              // Fire deletes concurrently. Backend serialises on
              // the same lock so order doesn't matter.
              const results = await Promise.allSettled([
                ...macros.map((m) => api.sessionMacroDelete(m.id)),
                ...rules.map((r) => api.sessionRuleDelete(r.id)),
              ]);
              const failures = results.filter((r) => r.status === "rejected");
              setSel(null);
              await refresh();
              if (failures.length > 0) {
                alert(
                  `Deleted ${total - failures.length} / ${total}. ${failures.length} failed — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              } else {
                alert(`Cleared ${total} session item${total === 1 ? "" : "s"}.`);
              }
            } catch (err) {
              alert(`Clear failed: ${err}`);
            }
          }}
          title={
            macros.length === 0 && rules.length === 0
              ? "No macros or rules to clear"
              : `Delete all ${macros.length + rules.length} session item${macros.length + rules.length === 1 ? "" : "s"}`
          }
        >
          Clear all
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="dim">{macros.length} macro(s) · {rules.length} rule(s)</span>
      </div>
      <div className="session-grid">
        <div className="session-list">
          <div className="session-section-title">Macros</div>
          {macros.map((m) => (
            <div
              key={m.id}
              className={`session-row ${sel?.kind === "macro" && sel.id === m.id ? "active" : ""}`}
              onClick={() => setSel({ kind: "macro", id: m.id })}
            >
              <div><strong>{m.name}</strong></div>
              <div className="dim mono">{m.id} · {m.steps.length} step(s)</div>
            </div>
          ))}
          {macros.length === 0 && (
            <div className="dim" style={{ padding: 10 }}>No macros yet. Add one with "+ Macro".</div>
          )}
          <div className="session-section-title">Rules</div>
          {rules.map((r) => (
            <div
              key={r.id}
              className={`session-row ${sel?.kind === "rule" && sel.id === r.id ? "active" : ""}`}
              onClick={() => setSel({ kind: "rule", id: r.id })}
            >
              <div>
                <strong>{r.name}</strong>
                {!r.enabled && <span className="dim"> (disabled)</span>}
              </div>
              <div className="dim mono">
                {r.scope.host_suffix || "*"}{r.scope.path_prefix || "/*"}
              </div>
            </div>
          ))}
          {rules.length === 0 && (
            <div className="dim" style={{ padding: 10 }}>No rules yet.</div>
          )}
        </div>

        <div className="session-editor">
          {!current && (
            <div className="dim" style={{ padding: 20 }}>
              Select or create a macro to establish auth state, or a rule to apply
              captured variables to scanner / repeater requests.
            </div>
          )}
          {current && sel?.kind === "macro" && (
            <MacroEditor
              m={current as SessionMacro}
              onSave={async (m) => { await api.sessionMacroUpsert(m); await refresh(); }}
              onRun={() => runMacro((current as SessionMacro).id)}
              onClone={() => cloneMacro(current as SessionMacro)}
              onDelete={async () => {
                if (!confirm(`Delete macro "${(current as SessionMacro).name}"?`)) return;
                await api.sessionMacroDelete((current as SessionMacro).id);
                setSel(null);
                await refresh();
              }}
              busy={busy}
            />
          )}
          {current && sel?.kind === "rule" && (
            <RuleEditor
              r={current as SessionRule}
              macros={macros}
              onSave={async (r) => { await api.sessionRuleUpsert(r); await refresh(); }}
              onClone={() => cloneRule(current as SessionRule)}
              onDelete={async () => {
                if (!confirm(`Delete rule "${(current as SessionRule).name}"?`)) return;
                await api.sessionRuleDelete((current as SessionRule).id);
                setSel(null);
                await refresh();
              }}
            />
          )}
        </div>
      </div>

      {report && (
        <RunReport report={report} onClose={() => setReport(null)} />
      )}
    </div>
  );
}

/* ------------------ macro editor ------------------ */

function MacroEditor({
  m,
  onSave,
  onRun,
  onClone,
  onDelete,
  busy,
}: {
  m: SessionMacro;
  onSave: (m: SessionMacro) => void | Promise<void>;
  onRun: () => void;
  onClone?: () => void | Promise<void>;
  onDelete: () => void;
  busy: boolean;
}) {
  const [draft, setDraft] = useState<SessionMacro>(m);
  // When selection changes externally, reset the draft.
  useEffect(() => setDraft(m), [m.id]);

  function updateStep(i: number, patch: Partial<SessionMacroStep>) {
    setDraft({ ...draft, steps: draft.steps.map((s, j) => j === i ? { ...s, ...patch } : s) });
  }
  function addStep() {
    setDraft({
      ...draft,
      steps: [...draft.steps, { method: "GET", url: "", headers: [], body: "", extract: [] }],
    });
  }
  function removeStep(i: number) {
    setDraft({ ...draft, steps: draft.steps.filter((_, j) => j !== i) });
  }

  return (
    <div className="session-editor-inner">
      <div className="session-editor-head">
        <input
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          style={{ fontSize: 14, fontWeight: 600, flex: 1 }}
        />
        <button onClick={onRun} disabled={busy}>{busy ? "Running…" : "▶ Run macro"}</button>
        <button className="primary" onClick={() => onSave(draft)}>Save</button>
        {onClone && (
          <button
            onClick={() => void onClone()}
            title="Duplicate this macro — the copy opens in the editor so you can tweak steps in place"
          >
            ⎘ Clone
          </button>
        )}
        <button className="danger" onClick={onDelete}>Delete</button>
      </div>
      <div className="dim mono">ID: {draft.id}</div>
      <textarea
        placeholder="notes (what this macro establishes, where it logs in …)"
        value={draft.notes ?? ""}
        onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
        rows={2}
      />
      <div className="session-steps">
        {draft.steps.map((s, i) => (
          <div key={i} className="session-step">
            <div className="session-step-head">
              <select
                value={s.method}
                onChange={(e) => updateStep(i, { method: e.target.value })}
                style={{ width: 90 }}
              >
                {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"].map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </select>
              <input
                placeholder="https://host/path"
                value={s.url}
                onChange={(e) => updateStep(i, { url: e.target.value })}
                style={{ flex: 1 }}
              />
              <button onClick={() => removeStep(i)}>✕</button>
            </div>
            <KeyValueEditor
              items={s.headers}
              label="Headers"
              onChange={(headers) => updateStep(i, { headers })}
            />
            <textarea
              placeholder="request body (supports {{var}} substitution)"
              value={s.body}
              onChange={(e) => updateStep(i, { body: e.target.value })}
              rows={2}
            />
            <ExtractEditor
              items={s.extract}
              onChange={(extract) => updateStep(i, { extract })}
            />
          </div>
        ))}
        <button onClick={addStep}>+ Step</button>
      </div>
    </div>
  );
}

function KeyValueEditor({
  items,
  label,
  onChange,
}: {
  items: Array<[string, string]>;
  label: string;
  onChange: (next: Array<[string, string]>) => void;
}) {
  return (
    <div className="kv-editor">
      <div className="dim">{label}</div>
      {items.map((h, i) => (
        <div key={i} className="kv-row">
          <input
            placeholder="name"
            value={h[0]}
            onChange={(e) =>
              onChange(items.map((row, j) => (j === i ? [e.target.value, row[1]] : row)))
            }
            style={{ width: 180 }}
          />
          <input
            placeholder="value"
            value={h[1]}
            onChange={(e) =>
              onChange(items.map((row, j) => (j === i ? [row[0], e.target.value] : row)))
            }
            style={{ flex: 1 }}
          />
          <button onClick={() => onChange(items.filter((_, j) => j !== i))}>✕</button>
        </div>
      ))}
      <button onClick={() => onChange([...items, ["", ""]])}>+ Add</button>
    </div>
  );
}

function ExtractEditor({
  items,
  onChange,
}: {
  items: SessionMacro["steps"][number]["extract"];
  onChange: (next: SessionMacro["steps"][number]["extract"]) => void;
}) {
  return (
    <div className="kv-editor">
      <div className="dim">Capture variables</div>
      {items.map((ex, i) => {
        const kind = ex.source.source;
        const headerName = kind === "header" ? (ex.source as any).name ?? "" : "";
        return (
          <div key={i} className="kv-row">
            <input
              placeholder="var"
              value={ex.var}
              onChange={(e) =>
                onChange(items.map((row, j) => (j === i ? { ...row, var: e.target.value } : row)))
              }
              style={{ width: 100 }}
            />
            <select
              value={kind}
              onChange={(e) => {
                const v = e.target.value as "body" | "status" | "header";
                const source =
                  v === "header"
                    ? { source: "header" as const, name: headerName || "Set-Cookie" }
                    : { source: v };
                onChange(items.map((row, j) => (j === i ? { ...row, source } : row)));
              }}
              style={{ width: 90 }}
            >
              <option value="body">body</option>
              <option value="header">header</option>
              <option value="status">status</option>
            </select>
            {kind === "header" && (
              <input
                placeholder="header name"
                value={headerName}
                onChange={(e) =>
                  onChange(items.map((row, j) =>
                    j === i ? { ...row, source: { source: "header", name: e.target.value } } : row
                  ))
                }
                style={{ width: 120 }}
              />
            )}
            <input
              placeholder="regex (capture group 1)"
              value={ex.pattern}
              onChange={(e) =>
                onChange(items.map((row, j) => (j === i ? { ...row, pattern: e.target.value } : row)))
              }
              style={{ flex: 1 }}
            />
            <button onClick={() => onChange(items.filter((_, j) => j !== i))}>✕</button>
          </div>
        );
      })}
      <button
        onClick={() =>
          onChange([
            ...items,
            { var: "", source: { source: "body" }, pattern: "" },
          ])
        }
      >
        + Extract
      </button>
    </div>
  );
}

/* ------------------ rule editor ------------------ */

function RuleEditor({
  r,
  macros,
  onSave,
  onClone,
  onDelete,
}: {
  r: SessionRule;
  macros: SessionMacro[];
  onSave: (r: SessionRule) => void | Promise<void>;
  onClone?: () => void | Promise<void>;
  onDelete: () => void;
}) {
  const [draft, setDraft] = useState<SessionRule>(r);
  useEffect(() => setDraft(r), [r.id]);

  return (
    <div className="session-editor-inner">
      <div className="session-editor-head">
        <input
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          style={{ fontSize: 14, fontWeight: 600, flex: 1 }}
        />
        <label className="indicator">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          Enabled
        </label>
        <button className="primary" onClick={() => onSave(draft)}>Save</button>
        {onClone && (
          <button
            onClick={() => void onClone()}
            title="Duplicate this rule — the copy opens in the editor so you can tweak it in place"
          >
            ⎘ Clone
          </button>
        )}
        <button className="danger" onClick={onDelete}>Delete</button>
      </div>
      <div className="dim mono">ID: {draft.id}</div>
      <div className="form-row">
        <label style={{ width: 110 }}>Macro</label>
        <select
          value={draft.macro_id}
          onChange={(e) => setDraft({ ...draft, macro_id: e.target.value })}
          style={{ flex: 1 }}
        >
          <option value="">— pick a macro —</option>
          {macros.map((m) => (
            <option key={m.id} value={m.id}>{m.name}</option>
          ))}
        </select>
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Host suffix</label>
        <input
          placeholder="example.com (empty = any host)"
          value={draft.scope.host_suffix}
          onChange={(e) => setDraft({ ...draft, scope: { ...draft.scope, host_suffix: e.target.value } })}
          style={{ flex: 1 }}
        />
      </div>
      <div className="form-row">
        <label style={{ width: 110 }}>Path prefix</label>
        <input
          placeholder="/api (empty = any path)"
          value={draft.scope.path_prefix}
          onChange={(e) => setDraft({ ...draft, scope: { ...draft.scope, path_prefix: e.target.value } })}
          style={{ flex: 1 }}
        />
      </div>
      <label className="indicator">
        <input
          type="checkbox"
          checked={draft.apply_cookies}
          onChange={(e) => setDraft({ ...draft, apply_cookies: e.target.checked })}
        />
        Also forward the macro's cookie jar
      </label>

      <div className="kv-editor">
        <div className="dim">Headers to splice onto matching requests</div>
        {draft.splice.map((s, i) => (
          <div key={i} className="kv-row">
            <input
              placeholder="header"
              value={s.header}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  splice: draft.splice.map((row, j) =>
                    j === i ? { ...row, header: e.target.value } : row
                  ),
                })
              }
              style={{ width: 180 }}
            />
            <input
              placeholder="value template (e.g. Bearer {{token}})"
              value={s.template}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  splice: draft.splice.map((row, j) =>
                    j === i ? { ...row, template: e.target.value } : row
                  ),
                })
              }
              style={{ flex: 1 }}
            />
            <button
              onClick={() =>
                setDraft({ ...draft, splice: draft.splice.filter((_, j) => j !== i) })
              }
            >
              ✕
            </button>
          </div>
        ))}
        <button
          onClick={() =>
            setDraft({ ...draft, splice: [...draft.splice, { header: "", template: "" }] })
          }
        >
          + Header
        </button>
      </div>
    </div>
  );
}

/* ------------------ run report ------------------ */

function RunReport({ report, onClose }: { report: MacroRunReport; onClose: () => void }) {
  return (
    <div className="session-report">
      <div className="session-report-head">
        <strong>Run report</strong>
        <span className="spacer" style={{ flex: 1 }} />
        <button onClick={onClose}>Close</button>
      </div>
      {report.error && <div style={{ color: "var(--red)" }}>Error: {report.error}</div>}
      <div className="session-report-grid">
        <div>
          <div className="dim">Transcript</div>
          {report.transcript.map((t, i) => (
            <div key={i} className="session-report-row">
              <div>
                <strong>{t.method}</strong>{" "}
                <span className="mono">{t.url}</span>
              </div>
              <div className="dim mono">
                {t.status != null ? `HTTP ${t.status}` : "—"}
                {t.elapsed_ms != null ? ` · ${t.elapsed_ms}ms` : ""}
                {t.error ? ` · ${t.error}` : ""}
              </div>
              {Object.entries(t.extracted).length > 0 && (
                <div className="mono dim">
                  captured: {Object.entries(t.extracted).map(([k, v]) => `${k}=${v}`).join(" · ")}
                </div>
              )}
            </div>
          ))}
          {report.transcript.length === 0 && <div className="dim">No steps ran.</div>}
        </div>
        <div>
          <div className="dim">Variables ({Object.keys(report.vars).length})</div>
          {Object.entries(report.vars).map(([k, v]) => (
            <div key={k} className="mono">
              <strong>{k}</strong> = {v}
            </div>
          ))}
          <div className="dim" style={{ marginTop: 8 }}>Cookies ({report.cookies.length})</div>
          {report.cookies.map((c, i) => (
            <div key={i} className="mono">
              {c.name}={c.value}
              <span className="dim"> · {c.domain}{c.path}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
