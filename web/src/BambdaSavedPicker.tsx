// Shared "Saved ▾" picker for Bambda filter bars. Both the HTTP
// history (ProxyPanel) and the LoggerPanel surface the same shape —
// a project-scoped list of named expressions with save / load /
// delete entries — so the dropdown logic lives here.

import { useCallback, useEffect, useState } from "react";
import { api, BambdaSavedQuery } from "./api";

type Props = {
  /** `"history"` or `"logger"` — namespaces the saved rows. */
  scope: string;
  /** Current draft expression in the bar; used as the Save source. */
  current: string;
  /** Called when the picker loads a saved expression into the bar. */
  onLoad: (expression: string) => void;
};

/** Slug the first 24 chars of the expression into a default name for
 *  the Save prompt — removes punctuation / lowercases so operators
 *  don't have to think up a name every time. */
function slugFromExpression(expr: string): string {
  const base = expr.replace(/[^A-Za-z0-9_ -]/g, " ").trim();
  const compact = base.replace(/\s+/g, " ").slice(0, 24);
  return compact || "query";
}

export function BambdaSavedPicker({ scope, current, onLoad }: Props) {
  const [saved, setSaved] = useState<BambdaSavedQuery[]>([]);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setSaved(await api.bambdaQueriesList(scope));
    } catch {
      // Project not open yet — leave the list empty rather than
      // alerting on every reload.
    }
  }, [scope]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function saveCurrent() {
    const trimmed = current.trim();
    if (!trimmed) {
      alert("Nothing to save — type an expression first.");
      return;
    }
    if (trimmed.length > 100) {
      alert("Expression exceeds 100-char save limit.");
      return;
    }
    const defaultName = slugFromExpression(trimmed);
    const nameRaw = prompt("Save Bambda query as:", defaultName);
    if (nameRaw == null) return;
    const name = nameRaw.trim();
    if (!name) return;
    if (name.length > 60) {
      alert("Name exceeds 60-char limit.");
      return;
    }
    setBusy(true);
    try {
      await api.bambdaQueriesSave(name, trimmed, scope);
      await refresh();
    } catch (e) {
      alert(`Save failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function deleteSaved(name: string) {
    if (!confirm(`Delete saved Bambda query "${name}"?`)) return;
    setBusy(true);
    try {
      await api.bambdaQueriesDelete(name, scope);
      await refresh();
    } catch (e) {
      alert(`Delete failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <select
      className="bambda-presets"
      disabled={busy}
      value=""
      onChange={(e) => {
        const v = e.target.value;
        e.target.value = "";
        if (!v) return;
        if (v === "__save__") {
          void saveCurrent();
        } else if (v.startsWith("__del__:")) {
          void deleteSaved(v.slice("__del__:".length));
        } else {
          const match = saved.find((q) => q.name === v);
          if (match) onLoad(match.expression);
        }
      }}
      title={`Saved Bambda queries scoped to ${scope} (${saved.length})`}
    >
      <option value="">Saved ▾ ({saved.length})</option>
      <option value="__save__">Save current as…</option>
      {saved.length > 0 && (
        <optgroup label="Load">
          {saved.map((q) => (
            <option
              key={`l:${q.name}`}
              value={q.name}
              title={q.expression}
            >
              {q.name}
            </option>
          ))}
        </optgroup>
      )}
      {saved.length > 0 && (
        <optgroup label="Delete">
          {saved.map((q) => (
            <option key={`d:${q.name}`} value={`__del__:${q.name}`}>
              Delete {q.name}
            </option>
          ))}
        </optgroup>
      )}
    </select>
  );
}
