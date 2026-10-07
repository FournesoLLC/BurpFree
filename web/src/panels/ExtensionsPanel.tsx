import { useEffect, useMemo, useState } from "react";
import { api, CatalogEntry } from "../api";

type ExtManifest = {
  name: string;
  version: string;
  author: string;
  description: string;
  permissions: string[];
};

type SubTab = "installed" | "catalog";

export function ExtensionsPanel() {
  const [exts, setExts] = useState<ExtManifest[]>([]);
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [sub, setSub] = useState<SubTab>("installed");
  const [busy, setBusy] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  async function refreshInstalled() {
    const list = await api.extensionsList();
    setExts(list);
  }
  async function refreshCatalog() {
    const list = await api.extensionsCatalogList();
    setCatalog(list);
  }
  useEffect(() => {
    refreshInstalled();
    refreshCatalog();
  }, []);

  async function toggle(name: string) {
    const next = !(enabled[name] ?? true);
    setEnabled({ ...enabled, [name]: next });
    await api.extensionsSetEnabled(name, next);
  }

  async function install(name: string) {
    setBusy(name);
    try {
      setCatalog(await api.extensionsInstall(name));
      await refreshInstalled();
    } catch (e) {
      alert(`Install failed: ${e}`);
    } finally {
      setBusy(null);
    }
  }

  async function uninstall(name: string) {
    if (!confirm(`Uninstall ${name}? Its live hooks will stop firing immediately.`)) return;
    setBusy(name);
    try {
      setCatalog(await api.extensionsUninstall(name));
      await refreshInstalled();
    } catch (e) {
      alert(`Uninstall failed: ${e}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="panel">
      <div className="toolbar">
        <button
          className={sub === "installed" ? "primary" : ""}
          onClick={() => setSub("installed")}
        >
          Installed ({exts.length})
        </button>
        <button
          className={sub === "catalog" ? "primary" : ""}
          onClick={() => setSub("catalog")}
        >
          Catalog ({catalog.filter((c) => c.available).length} available)
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        {/* R843: Shared search input across BOTH Installed and
            Catalog sub-tabs. Burp's Extensions panel has a filter
            box at the top of each view. Previously our Catalog
            had it but Installed didn't, so operators with many
            installed extensions couldn't filter down to the one
            they wanted to toggle. Reuses the same `query` state so
            flipping sub-tabs preserves the search — operators
            using "Catalog → install a thing → Installed → check
            it works" don't lose their filter mid-pivot. */}
        <input
          type="text"
          placeholder={
            sub === "installed"
              ? `Filter ${exts.length} installed extension${exts.length === 1 ? "" : "s"}…`
              : `Filter catalog…`
          }
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape" && query) {
              e.preventDefault();
              setQuery("");
            }
          }}
          style={{ width: 220 }}
          title="Case-insensitive substring match across name / description / author / permissions. Esc clears the filter."
        />
      </div>
      <div style={{ padding: 10, overflow: "auto" }}>
        {sub === "installed" ? (
          <InstalledView
            exts={exts}
            enabled={enabled}
            onToggle={toggle}
            onUninstall={uninstall}
            busy={busy}
            query={query}
          />
        ) : (
          <CatalogView
            entries={catalog}
            query={query}
            busy={busy}
            onInstall={install}
            onUninstall={uninstall}
          />
        )}
      </div>
    </div>
  );
}

function InstalledView({
  exts,
  enabled,
  onToggle,
  onUninstall,
  busy,
  query,
}: {
  exts: ExtManifest[];
  enabled: Record<string, boolean>;
  onToggle: (n: string) => void;
  onUninstall: (n: string) => void;
  busy: string | null;
  query: string;
}) {
  // R843: Case-insensitive substring filter across name /
  // description / author / permissions. Matches the Catalog
  // view's filter shape so the two sub-tabs behave identically.
  const q = query.trim().toLowerCase();
  const filtered = q
    ? exts.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          e.author.toLowerCase().includes(q) ||
          e.permissions.some((p) => p.toLowerCase().includes(q)),
      )
    : exts;
  return (
    <>
      <p style={{ color: "var(--text-dim)" }}>
        BurpFree extensions declare required permissions in their manifest; the registry
        enforces them at every callback boundary.
        {q && (
          <span style={{ marginLeft: 10, fontSize: 11 }}>
            Showing <b>{filtered.length}</b> of {exts.length} match
            <code style={{ marginLeft: 4 }}>{query}</code>
          </span>
        )}
      </p>
      {exts.length === 0 && (
        <div className="empty">
          No extensions loaded. Open the <b>Catalog</b> tab to install reference extensions.
        </div>
      )}
      {exts.length > 0 && filtered.length === 0 && (
        <div className="empty">
          No installed extensions match <code>{query}</code>. Clear the filter or try a
          different query.
        </div>
      )}
      {filtered.map((e) => (
        <div
          key={e.name}
          style={{
            padding: 10,
            marginBottom: 10,
            background: "var(--bg-raised)",
            border: "1px solid var(--border)",
            borderRadius: 4,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h4 style={{ margin: 0 }}>
              {e.name} <span className="badge">v{e.version}</span>
            </h4>
            <span className="spacer" style={{ flex: 1 }} />
            <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <input
                type="checkbox"
                checked={enabled[e.name] ?? true}
                onChange={() => onToggle(e.name)}
              />{" "}
              Enabled
            </label>
            <button
              className="ghost danger"
              disabled={busy === e.name}
              onClick={() => onUninstall(e.name)}
              title="Remove this extension from the project"
            >
              Uninstall
            </button>
          </div>
          <div style={{ color: "var(--text-dim)", marginTop: 4 }}>
            {e.description} — by {e.author}
          </div>
          <div style={{ marginTop: 6 }}>
            {e.permissions.map((p) => (
              <span key={p} className="badge" style={{ marginRight: 4 }}>
                {p}
              </span>
            ))}
          </div>
        </div>
      ))}
    </>
  );
}

function CatalogView({
  entries,
  query,
  busy,
  onInstall,
  onUninstall,
}: {
  entries: CatalogEntry[];
  query: string;
  busy: string | null;
  onInstall: (n: string) => void;
  onUninstall: (n: string) => void;
}) {
  const q = query.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!q) return entries;
    return entries.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q) ||
        c.author.toLowerCase().includes(q),
    );
  }, [entries, q]);

  if (filtered.length === 0) {
    return (
      <div style={{ color: "var(--text-dim)", padding: 20 }}>
        No catalog entries match <code>{query}</code>.
      </div>
    );
  }

  return (
    <>
      <p style={{ color: "var(--text-dim)" }}>
        BurpFree ships a small set of reference extensions. Click <b>Install</b> to add one
        to your project; the choice is persisted in <code>extensions.json</code> and loads
        automatically on the next session.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
          gap: 10,
        }}
      >
        {filtered.map((c) => (
          <CatalogCard
            key={c.name}
            entry={c}
            busy={busy === c.name}
            onInstall={() => onInstall(c.name)}
            onUninstall={() => onUninstall(c.name)}
          />
        ))}
      </div>
    </>
  );
}

function CatalogCard({
  entry,
  busy,
  onInstall,
  onUninstall,
}: {
  entry: CatalogEntry;
  busy: boolean;
  onInstall: () => void;
  onUninstall: () => void;
}) {
  const statusLabel = !entry.available
    ? "Preview"
    : entry.installed
    ? "Installed"
    : "Available";
  const statusColor = !entry.available
    ? "var(--text-dim)"
    : entry.installed
    ? "var(--success, #4ac66c)"
    : "var(--accent, #3a9df7)";

  return (
    <div
      style={{
        padding: 12,
        background: "var(--bg-raised)",
        border: "1px solid var(--border)",
        borderRadius: 6,
        display: "flex",
        flexDirection: "column",
        gap: 6,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <h4 style={{ margin: 0 }}>{entry.name}</h4>
        <span className="badge" style={{ fontSize: 10 }}>v{entry.version}</span>
        <span className="spacer" style={{ flex: 1 }} />
        <span style={{ color: statusColor, fontSize: 11, fontWeight: 600 }}>{statusLabel}</span>
      </div>
      <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
        by {entry.author} · {entry.category}
      </div>
      <div style={{ fontSize: 12 }}>{entry.description}</div>
      <div>
        {entry.permissions.map((p) => (
          <span key={p} className="badge" style={{ marginRight: 4, fontSize: 10 }}>
            {p}
          </span>
        ))}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
        <a
          href={entry.source_url}
          target="_blank"
          rel="noreferrer noopener"
          style={{ fontSize: 11, color: "var(--text-dim)" }}
          title={entry.source_url}
        >
          source ↗
        </a>
        <span className="spacer" style={{ flex: 1 }} />
        {!entry.available ? (
          <button className="ghost" disabled title="Preview-only — not yet shipped">
            Coming soon
          </button>
        ) : entry.installed ? (
          <button className="ghost danger" disabled={busy} onClick={onUninstall}>
            {busy ? "Working…" : "Uninstall"}
          </button>
        ) : (
          <button className="primary" disabled={busy} onClick={onInstall}>
            {busy ? "Installing…" : "Install"}
          </button>
        )}
      </div>
    </div>
  );
}
