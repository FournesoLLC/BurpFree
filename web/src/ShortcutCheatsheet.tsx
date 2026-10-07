import { useEffect, useMemo, useState } from "react";
import { SHORTCUT_GROUPS, SHORTCUT_REGISTRY } from "./shortcuts";

/**
 * Modal that renders every shortcut registered in `shortcuts.ts`,
 * grouped by scope. Opened via Ctrl+? / Ctrl+/ from `App.tsx`.
 *
 * There is no persistent state; mount once and the parent toggles
 * `open` to show / hide. A small search box filters entries by key
 * combination or description.
 */
export function ShortcutCheatsheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");

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

  const q = query.trim().toLowerCase();
  const filteredGroups = useMemo(() => {
    if (!q) return SHORTCUT_GROUPS;
    return SHORTCUT_GROUPS.map((g) => ({
      ...g,
      entries: g.entries.filter(
        (e) =>
          e.description.toLowerCase().includes(q) ||
          e.keys.some((k) => k.toLowerCase().includes(q)),
      ),
    })).filter((g) => g.entries.length > 0);
  }, [q]);

  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.55)",
        zIndex: 2000,
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
          width: "min(760px, 100%)",
          maxHeight: "88vh",
          boxShadow: "0 20px 48px rgba(0,0,0,0.5)",
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
          <strong>Keyboard shortcuts</strong>
          <span style={{ color: "var(--text-dim)", fontSize: 12 }}>
            {SHORTCUT_REGISTRY.length} total
          </span>
          <span style={{ flex: 1 }} />
          <input
            autoFocus
            type="text"
            placeholder="Filter — type a key or description"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ width: 240 }}
          />
          <button className="ghost" onClick={onClose} title="Close (Esc)">
            ✕
          </button>
        </div>

        <div style={{ padding: "6px 14px 14px", overflow: "auto" }}>
          {filteredGroups.length === 0 && (
            <div style={{ color: "var(--text-dim)", padding: "16px 0" }}>
              No shortcuts match <code>{query}</code>.
            </div>
          )}
          {filteredGroups.map((g) => (
            <section key={g.scope} style={{ marginTop: 14 }}>
              <h4
                style={{
                  margin: "4px 0 6px",
                  color: "var(--text-dim)",
                  fontSize: 11,
                  letterSpacing: 0.5,
                  textTransform: "uppercase",
                }}
              >
                {g.label}
              </h4>
              <table
                className="mono"
                style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}
              >
                <colgroup>
                  <col style={{ width: 220 }} />
                  <col />
                </colgroup>
                <tbody>
                  {g.entries.map((e, i) => (
                    <tr key={i}>
                      <td
                        style={{
                          padding: "4px 8px 4px 0",
                          borderBottom: "1px solid var(--border-dim, rgba(128,128,128,0.1))",
                          verticalAlign: "top",
                        }}
                      >
                        {e.keys.map((k, kIdx) => (
                          <span key={kIdx}>
                            {kIdx > 0 ? <span style={{ color: "var(--text-dim)" }}> or </span> : null}
                            <kbd
                              style={{
                                background: "rgba(128,128,128,0.15)",
                                padding: "1px 6px",
                                borderRadius: 3,
                                border: "1px solid var(--border)",
                                fontFamily: "inherit",
                              }}
                            >
                              {k}
                            </kbd>
                          </span>
                        ))}
                      </td>
                      <td
                        style={{
                          padding: "4px 0",
                          borderBottom: "1px solid var(--border-dim, rgba(128,128,128,0.1))",
                        }}
                      >
                        {e.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ))}
        </div>

        <div
          style={{
            padding: "8px 14px",
            borderTop: "1px solid var(--border)",
            color: "var(--text-dim)",
            fontSize: 11,
          }}
        >
          Press <kbd>Ctrl+?</kbd> or <kbd>Ctrl+/</kbd> anywhere to reopen this cheatsheet.
        </div>
      </div>
    </div>
  );
}
