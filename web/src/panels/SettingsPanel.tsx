import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  AutoBackupConfig,
  AuthScheme,
  BackupInfo,
  HostOverride,
  PlatformAuthCredential,
  Scope,
  ScopeRule,
} from "../api";
import { SHORTCUT_GROUPS, type ShortcutEntry } from "../shortcuts";
import { ThemeMode, useTheme } from "../theme";

/**
 * Burp-style hierarchical left nav. Clicking a leaf scrolls the
 * right pane to the section with the matching `data-settings-id`.
 */
type NavLeaf = { id: string; label: string; scope: "user" | "project" | "both" };
type NavGroup = { id: string; label: string; children?: NavLeaf[] };

const SETTINGS_NAV: NavGroup[] = [
  { id: "backup",     label: "Automatic backup" },
  { id: "logging",    label: "Logging" },
  { id: "sessions",   label: "Sessions" },
  { id: "rest-api",   label: "REST API" },
  {
    id: "network",
    label: "Network",
    children: [
      { id: "network-listener",  label: "Listener",         scope: "project" },
      { id: "network-upstream",  label: "Upstream proxy",   scope: "user" },
      { id: "network-redirects", label: "Follow redirects", scope: "project" },
      { id: "network-overrides", label: "Hostname overrides", scope: "project" },
      { id: "network-platform-auth", label: "Platform authentication", scope: "project" },
    ],
  },
  {
    id: "ui",
    label: "User interface",
    children: [
      { id: "ui-theme",    label: "Theme",         scope: "user" },
      { id: "ui-layout",   label: "Layout",        scope: "user" },
      { id: "ui-hotkeys",  label: "Hotkeys",       scope: "user" },
    ],
  },
  {
    id: "suite",
    label: "Suite",
    children: [
      { id: "suite-limits",   label: "Limits",        scope: "project" },
      { id: "suite-scope",    label: "Scope",         scope: "project" },
      { id: "suite-ca",       label: "Root CA",       scope: "user" },
    ],
  },
  { id: "extensions", label: "Extensions" },
  { id: "ai",         label: "AI / MCP" },
];

export function SettingsPanel() {
  const [cfg, setCfg] = useState<any | null>(null);
  const [scope, setScope] = useState<Scope | null>(null);
  const [caInfo, setCaInfo] = useState<any | null>(null);
  const [hostOverrides, setHostOverrides] = useState<HostOverride[]>([]);
  const [followRedirects, setFollowRedirects] = useState<string>("never");
  const [netDirty, setNetDirty] = useState(false);
  const theme = useTheme();
  const [activeNav, setActiveNav] = useState<string>("network-listener");
  const [expanded, setExpanded] = useState<Set<string>>(
    new Set(["network", "ui", "suite"])
  );
  const scrollRef = useRef<HTMLDivElement>(null);
  // R291: Hidden file input ref for the "⬆ Import settings"
  // button. One ref so a single click fires the OS picker.
  const importFileRef = useRef<HTMLInputElement | null>(null);

  function toggleExpand(id: string) {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id); else next.add(id);
    setExpanded(next);
  }

  function jumpToSection(id: string) {
    setActiveNav(id);
    const el = document.querySelector(`[data-settings-id="${id}"]`) as HTMLElement | null;
    if (el && scrollRef.current) {
      scrollRef.current.scrollTo({ top: el.offsetTop - 10, behavior: "smooth" });
    }
  }

  useEffect(() => {
    api.settingsGet().then(setCfg);
    api.scopeGet().then(setScope);
    api.caInfo().then(setCaInfo);
    api.hostOverridesGet().then((v) => {
      setHostOverrides(v.overrides);
      setFollowRedirects(v.follow_redirects);
    }).catch(() => {});
  }, []);

  async function save() {
    if (!cfg) return;
    await api.settingsSave(cfg);
    alert("saved");
  }

  async function addRule(kind: "include" | "exclude") {
    const host = prompt("Host pattern (supports * wildcards)", "example.com");
    if (!host) return;
    const rule: ScopeRule = {
      match_kind: kind,
      protocol: "any",
      host,
      port: undefined,
      path: "*",
      regex: false,
      enabled: true,
    };
    const s = await api.scopeAddRule(rule);
    setScope(s);
  }

  async function removeRule(i: number) {
    const s = await api.scopeRemoveRule(i);
    setScope(s);
  }

  async function exportCA() {
    const path = prompt("Save path for CA PEM", "burpfree-ca.pem");
    if (!path) return;
    await api.caExport(path);
    alert("exported");
  }

  if (!cfg) return <div className="empty">Loading…</div>;

  return (
    <div className="panel settings-grid">
      <aside className="settings-nav">
        <input
          placeholder="Search settings…"
          className="settings-search"
          onChange={(e) => {
            // Lightweight filter: hide groups whose children don't match.
            // The real tree is rendered beneath; a filter attr highlights
            // matching leaves.
            const q = e.target.value.toLowerCase().trim();
            const nav = e.currentTarget.parentElement!.querySelectorAll<HTMLElement>("[data-nav-leaf]");
            nav.forEach((n) => {
              const t = n.textContent?.toLowerCase() ?? "";
              n.style.display = !q || t.includes(q) ? "" : "none";
            });
          }}
        />
        {SETTINGS_NAV.map((g) => {
          const isOpen = expanded.has(g.id);
          const hasChildren = g.children && g.children.length > 0;
          return (
            <div key={g.id} className="settings-nav-group">
              <div
                className={`settings-nav-group-head ${!hasChildren && activeNav === g.id ? "active" : ""}`}
                onClick={() => {
                  if (hasChildren) toggleExpand(g.id);
                  else jumpToSection(g.id);
                }}
              >
                <span className="settings-nav-caret">
                  {hasChildren ? (isOpen ? "▾" : "▸") : "·"}
                </span>
                <span>{g.label}</span>
              </div>
              {hasChildren && isOpen && (
                <div className="settings-nav-children">
                  {g.children!.map((leaf) => (
                    <div
                      key={leaf.id}
                      data-nav-leaf
                      className={`settings-nav-leaf ${activeNav === leaf.id ? "active" : ""}`}
                      onClick={() => jumpToSection(leaf.id)}
                    >
                      <span>{leaf.label}</span>
                      <span className={`settings-scope-pill scope-${leaf.scope}`}>
                        {leaf.scope === "user" ? "User" : leaf.scope === "project" ? "Project" : "Both"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </aside>
      <div className="settings-right" ref={scrollRef}>
      <div className="toolbar">
        <span>Settings</span>
        <span className="spacer" style={{ flex: 1 }} />
        <button className="primary" onClick={save}>
          Save
        </button>
        {/* R280: Export settings as JSON — operators moving a      */}
        {/* project between machines (laptop → engagement VM, or    */}
        {/* two team-mates on different hosts) want to carry over   */}
        {/* their timeouts / limits / scope / overrides without      */}
        {/* re-typing. The downloaded blob mirrors `cfg` + `scope`  */}
        {/* + host override state so a reciprocal import (via the  */}
        {/* Backup / Open-project flow) can rehydrate the project. */}
        {/* Pure client-side — no backend round-trip; blob is       */}
        {/* stamped with ISO timestamp so overlapping exports      */}
        {/* don't collide on disk.                                   */}
        <button
          onClick={() => {
            const payload = {
              exported_at_ms: Date.now(),
              exported_at_iso: new Date().toISOString(),
              settings: cfg,
              scope,
              host_overrides: hostOverrides,
              follow_redirects: followRedirects,
            };
            const blob = new Blob([JSON.stringify(payload, null, 2)], {
              type: "application/json;charset=utf-8",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            const stamp = new Date()
              .toISOString()
              .replace(/[:T]/g, "-")
              .replace(/\..*$/, "");
            a.href = url;
            a.download = `burpfree-settings-${stamp}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
          }}
          title="Export the current settings + scope + host overrides as a JSON file. Operators moving a project between machines (or sharing config with a teammate) can import this on the other end to mirror the setup."
        >
          ⬇ Export settings
        </button>
        {/* R291: Import settings — reciprocal of R280 export.      */}
        {/* Closes the round-trip so operators can move a project   */}
        {/* between machines or share config across teammates.      */}
        {/* Reads the JSON blob R280 wrote and dispatches the three */}
        {/* backend commands (settingsSave, scopeSet, hostOverrides */}
        {/* Set) in sequence. Confirms pre-fire with the import     */}
        {/* source filename because the operation overwrites every  */}
        {/* key in the current project config. On success reloads   */}
        {/* the local state so the right pane reflects the imported */}
        {/* values immediately.                                      */}
        <input
          ref={importFileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — settings exports are typically <100 KB. Pick a smaller file or confirm this is a settings export.`,
              );
              return;
            }
            if (
              !confirm(
                `Import settings from "${file.name}"? Overwrites the current project config, scope rules, and host overrides. The Save step still fires separately so you can review before persisting.`,
              )
            )
              return;
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              if (
                !parsed ||
                typeof parsed !== "object" ||
                !parsed.settings ||
                !parsed.scope
              ) {
                alert(
                  "Not a settings export — expected { settings, scope, host_overrides, follow_redirects }.",
                );
                return;
              }
              // Dispatch the three commands in sequence. Settings
              // first because it's the biggest + a scope-save in
              // the middle would leave settings stale on failure.
              await api.settingsSave(parsed.settings);
              await api.scopeSet(parsed.scope);
              if (Array.isArray(parsed.host_overrides)) {
                await api.hostOverridesSet({
                  overrides: parsed.host_overrides,
                  follow_redirects: parsed.follow_redirects ?? null,
                });
              }
              // Pull every field back from the backend so the UI
              // reflects the imported values immediately.
              const freshCfg = await api.settingsGet();
              setCfg(freshCfg);
              const freshScope = await api.scopeGet();
              setScope(freshScope);
              const freshOverrides = await api.hostOverridesGet();
              setHostOverrides(freshOverrides.overrides);
              setFollowRedirects(freshOverrides.follow_redirects);
              alert(
                `Imported ${file.name} — ${parsed.scope.rules?.length ?? 0} scope rule${parsed.scope.rules?.length === 1 ? "" : "s"}, ${Array.isArray(parsed.host_overrides) ? parsed.host_overrides.length : 0} host override${Array.isArray(parsed.host_overrides) && parsed.host_overrides.length === 1 ? "" : "s"} applied. Settings now reflect the imported state.`,
              );
            } catch (err) {
              alert(`Import failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => importFileRef.current?.click()}
          title="Import a settings JSON (produced by R280 Export settings) into the current project. Overwrites the live config / scope / host overrides. Asks before firing."
        >
          ⬆ Import settings
        </button>
      </div>
      <div style={{ padding: 10 }}>
        <BackupSection />
        <RestApiSection />
        <h3 data-settings-id="ui-theme">Theme</h3>
        <div className="form-row">
          <label>Appearance</label>
          <select
            value={theme.mode}
            onChange={(e) => theme.setMode(e.target.value as ThemeMode)}
            style={{ width: 220 }}
          >
            <option value="system">Follow system ({theme.effective})</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
          <span className="dim" style={{ fontSize: 11, marginLeft: 8 }}>
            Choice is stored in local storage per user. The system mode watches{" "}
            <code>prefers-color-scheme</code> and flips automatically.
          </span>
        </div>

        <LayoutSection />

        <HotkeysSection />

        <h3 data-settings-id="network-listener">Listener</h3>
        <div className="form-row">
          <label>Address</label>
          <input
            value={cfg.listeners[0]?.address || ""}
            onChange={(e) =>
              setCfg({
                ...cfg,
                listeners: [{ ...cfg.listeners[0], address: e.target.value }],
              })
            }
          />
        </div>
        <h3 data-settings-id="network-upstream">Upstream proxy</h3>
        <div className="form-row">
          <label>URL</label>
          <input
            value={cfg.upstream.url}
            placeholder="direct — or http://host:port / socks5://host:port"
            onChange={(e) => setCfg({ ...cfg, upstream: { ...cfg.upstream, url: e.target.value } })}
          />
        </div>
        <div className="form-row">
          <label>Username</label>
          <input
            value={cfg.upstream.username || ""}
            onChange={(e) =>
              setCfg({
                ...cfg,
                upstream: { ...cfg.upstream, username: e.target.value || null },
              })
            }
          />
        </div>
        <div className="form-row">
          <label>Password</label>
          <input
            type="password"
            value={cfg.upstream.password || ""}
            onChange={(e) =>
              setCfg({
                ...cfg,
                upstream: { ...cfg.upstream, password: e.target.value || null },
              })
            }
          />
        </div>
        <h3 data-settings-id="suite-limits">Limits</h3>
        <div className="form-row">
          <label>Max body (MiB)</label>
          <input
            type="number"
            value={cfg.max_body_mb}
            onChange={(e) => setCfg({ ...cfg, max_body_mb: Number(e.target.value) })}
          />
        </div>
        <div className="form-row">
          <label>Decompression cap (MiB)</label>
          <input
            type="number"
            value={cfg.decompression_cap_mb}
            onChange={(e) => setCfg({ ...cfg, decompression_cap_mb: Number(e.target.value) })}
          />
        </div>
        <div
          className="form-row"
          title="When off, out-of-scope traffic is still forwarded by the proxy but is NOT persisted to history, sitemap, or events — mirrors Burp's 'drop out-of-scope items'. On (default) matches Burp's shipping behaviour: everything is recorded. HistoryPanel shows a 'suppressed' pill while this is off so filtered traffic doesn't look like a bug."
        >
          <label>Record out-of-scope items</label>
          <input
            type="checkbox"
            checked={cfg.record_out_of_scope}
            onChange={(e) => setCfg({ ...cfg, record_out_of_scope: e.target.checked })}
          />
        </div>

        <h3 data-settings-id="suite-scope">Scope</h3>
        <div className="toolbar">
          <button onClick={() => addRule("include")}>+ include</button>
          <button onClick={() => addRule("exclude")}>+ exclude</button>
        </div>
        <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>#</th>
              <th style={{ textAlign: "left" }}>Kind</th>
              <th style={{ textAlign: "left" }}>Protocol</th>
              <th style={{ textAlign: "left" }}>Host</th>
              <th style={{ textAlign: "left" }}>Port</th>
              <th style={{ textAlign: "left" }}>Path</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scope?.rules.map((r, i) => (
              <tr key={i}>
                <td>{i + 1}</td>
                <td>{r.match_kind}</td>
                <td>{r.protocol}</td>
                <td>{r.host}</td>
                <td>{r.port ?? "any"}</td>
                <td>{r.path}</td>
                <td>
                  <button onClick={() => removeRule(i)}>x</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <h3 data-settings-id="network-redirects">Network</h3>
        <div className="form-row">
          <label>Follow redirects</label>
          <select
            value={followRedirects}
            onChange={(e) => { setFollowRedirects(e.target.value); setNetDirty(true); }}
          >
            <option value="never">Never</option>
            <option value="on_site">On-site only (same host:port)</option>
            <option value="in_scope">In-scope only</option>
            <option value="always">Always</option>
          </select>
          <span className="dim">
            Applies to Repeater, Intruder, and the Scanner HTTP client. The proxy never follows
            redirects on behalf of clients.
          </span>
        </div>
        <div data-settings-id="network-overrides" style={{ marginTop: 10, marginBottom: 6, fontSize: 11, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
          Hostname resolution overrides
        </div>
        <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
          <colgroup>
            <col style={{ width: 70 }} />
            <col />
            <col style={{ width: 170 }} />
            <col style={{ width: 50 }} />
          </colgroup>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Enabled</th>
              <th style={{ textAlign: "left" }}>Hostname</th>
              <th style={{ textAlign: "left" }}>IP address</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {hostOverrides.map((o, i) => (
              <tr key={i}>
                <td style={{ textAlign: "center" }}>
                  <input
                    type="checkbox"
                    checked={o.enabled}
                    onChange={(e) => {
                      const next = hostOverrides.slice();
                      next[i] = { ...o, enabled: e.target.checked };
                      setHostOverrides(next);
                      setNetDirty(true);
                    }}
                  />
                </td>
                <td>
                  <input
                    value={o.hostname}
                    onChange={(e) => {
                      const next = hostOverrides.slice();
                      next[i] = { ...o, hostname: e.target.value };
                      setHostOverrides(next);
                      setNetDirty(true);
                    }}
                    style={{ width: "100%" }}
                    placeholder="example.com"
                  />
                </td>
                <td>
                  <input
                    value={o.ip}
                    onChange={(e) => {
                      const next = hostOverrides.slice();
                      next[i] = { ...o, ip: e.target.value };
                      setHostOverrides(next);
                      setNetDirty(true);
                    }}
                    style={{ width: "100%" }}
                    placeholder="127.0.0.1"
                  />
                </td>
                <td>
                  <button
                    className="ghost danger"
                    onClick={() => {
                      setHostOverrides(hostOverrides.filter((_, j) => j !== i));
                      setNetDirty(true);
                    }}
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
            {hostOverrides.length === 0 && (
              <tr><td colSpan={4} className="dim" style={{ padding: 8 }}>No overrides.</td></tr>
            )}
          </tbody>
        </table>
        <div style={{ marginTop: 6 }}>
          <button
            onClick={() => {
              setHostOverrides([...hostOverrides, { enabled: true, hostname: "", ip: "" }]);
              setNetDirty(true);
            }}
          >
            + Add override
          </button>
          <button
            className={netDirty ? "primary" : ""}
            disabled={!netDirty}
            onClick={async () => {
              await api.hostOverridesSet({
                overrides: hostOverrides,
                follow_redirects: followRedirects,
              });
              setNetDirty(false);
            }}
            style={{ marginLeft: 8 }}
          >
            {netDirty ? "Save network settings" : "Saved"}
          </button>
        </div>

        <PlatformAuthSection />

        <h3 data-settings-id="suite-ca">Root CA</h3>
        {caInfo && (
          <>
            <div>
              <span className="badge">Subject</span> <span className="mono">{caInfo.subject}</span>
            </div>
            <div>
              <span className="badge">Serial</span> <span className="mono">{caInfo.serial}</span>
            </div>
            <div>
              <span className="badge">Valid</span>{" "}
              <span className="mono">
                {caInfo.not_before} → {caInfo.not_after}
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className="badge">Fingerprint</span>{" "}
              <span className="mono" style={{ flex: 1 }}>{caInfo.sha256_fingerprint}</span>
              {/* R175: Copy fingerprint — operators verifying the        */}
              {/* browser is seeing the right MITM cert can paste the      */}
              {/* fingerprint into their browser's certificate manager +  */}
              {/* compare. The fingerprint is long + colon-separated, so   */}
              {/* a dedicated copy button beats triple-click + Ctrl+C.    */}
              <button
                className="ghost"
                style={{ fontSize: 11, padding: "2px 6px" }}
                onClick={() => {
                  void navigator.clipboard
                    .writeText(caInfo.sha256_fingerprint ?? "")
                    .catch((e) => alert(`${e}`));
                }}
                title="Copy the SHA-256 fingerprint to clipboard — paste into the browser's cert manager to verify a match"
              >
                📋 copy
              </button>
            </div>
            <div style={{ marginTop: 10 }}>
              <button onClick={exportCA}>Export CA (PEM)</button>
            </div>
          </>
        )}
      </div>
      </div>
    </div>
  );
}

/** Automatic project backup section. Reads the live config +
 *  backup list from the backend, shows an edit form (Save button
 *  lights up only on dirty), and renders a table of existing
 *  snapshots with per-row delete + a toolbar "Backup now" that
 *  fires an immediate zip. */
function BackupSection() {
  const [cfg, setCfg] = useState<AutoBackupConfig | null>(null);
  const [draft, setDraft] = useState<AutoBackupConfig | null>(null);
  const [list, setList] = useState<BackupInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [c, l] = await Promise.all([
        api.backupConfigGet(),
        api.backupList(),
      ]);
      setCfg(c);
      setDraft(c);
      setList(l);
    } catch (e) {
      setError(`${e}`);
    }
  }

  useEffect(() => {
    void refresh();
    // Light refresh of the list only (not the whole config) every
    // 15 s so a scheduler tick that lands between operator views
    // shows up without a manual click.
    const t = setInterval(() => {
      api.backupList().then(setList).catch(() => {});
    }, 15_000);
    return () => clearInterval(t);
  }, []);

  if (!cfg || !draft) {
    return (
      <>
        <h3 data-settings-id="backup">Automatic backup</h3>
        <div className="dim" style={{ fontSize: 11 }}>
          Loading…
          {error && <div style={{ color: "var(--red)" }}>{error}</div>}
        </div>
      </>
    );
  }

  // `dirty` only triggers on a semantic change — plain re-renders
  // don't mislead the Save button into pulsing.
  const dirty =
    draft.enabled !== cfg.enabled ||
    draft.interval_min !== cfg.interval_min ||
    draft.keep_count !== cfg.keep_count ||
    draft.delete_on_shutdown !== cfg.delete_on_shutdown;

  async function save() {
    if (!draft) return;
    setBusy(true);
    try {
      await api.backupConfigSet(draft);
      setCfg(draft);
      // Config change restarts the scheduler on the backend. The
      // next scheduled snapshot lands on the new interval; nothing
      // to refresh client-side beyond `cfg`.
    } catch (e) {
      setError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function backupNow() {
    setBusy(true);
    try {
      await api.backupNow();
      const l = await api.backupList();
      setList(l);
    } catch (e) {
      setError(`backup_now failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function deleteOne(filename: string) {
    if (!confirm(`Delete backup ${filename}? The file goes to the OS trash is NOT invoked — this is a hard delete.`)) {
      return;
    }
    setBusy(true);
    try {
      await api.backupDelete(filename);
      const l = await api.backupList();
      setList(l);
    } catch (e) {
      setError(`backup_delete failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h3 data-settings-id="backup">Automatic backup</h3>
      <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
        Periodically snapshots the project (config + history.db + blobs) into{" "}
        <code>&lt;project&gt;/backups/*.zip</code>. Extensions and the CA
        private key are intentionally excluded from auto-backups — use the CLI
        export when you want a full bundle.
      </div>
      <div className="form-row">
        <label>Enabled</label>
        <label>
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />{" "}
          Run the scheduler. When off, only manual <code>Backup now</code>{" "}
          takes a snapshot.
        </label>
      </div>
      <div className="form-row">
        <label>Interval (minutes)</label>
        <input
          type="number"
          min={1}
          max={1440}
          value={draft.interval_min}
          onChange={(e) =>
            setDraft({
              ...draft,
              interval_min: Math.max(
                1,
                Math.min(1440, parseInt(e.target.value || "30", 10) || 30),
              ),
            })
          }
          style={{ width: 100 }}
        />
        <span className="dim" style={{ fontSize: 11, marginLeft: 8 }}>
          Clamped to [1, 1440]. Burp's own default is 30.
        </span>
      </div>
      <div className="form-row">
        <label>Keep count</label>
        <input
          type="number"
          min={1}
          max={100}
          value={draft.keep_count}
          onChange={(e) =>
            setDraft({
              ...draft,
              keep_count: Math.max(
                1,
                Math.min(100, parseInt(e.target.value || "20", 10) || 20),
              ),
            })
          }
          style={{ width: 100 }}
        />
        <span className="dim" style={{ fontSize: 11, marginLeft: 8 }}>
          Older snapshots are deleted after each successful write.
        </span>
      </div>
      <div className="form-row">
        <label>Delete on shutdown</label>
        <label>
          <input
            type="checkbox"
            checked={draft.delete_on_shutdown}
            onChange={(e) =>
              setDraft({ ...draft, delete_on_shutdown: e.target.checked })
            }
          />{" "}
          Wipe every backup zip when the project closes.
        </label>
      </div>
      <div className="form-row">
        <label />
        <div style={{ display: "flex", gap: 6 }}>
          <button
            className={dirty ? "primary" : ""}
            disabled={!dirty || busy}
            onClick={() => void save()}
          >
            {busy ? "Saving…" : dirty ? "Save" : "Saved"}
          </button>
          <button disabled={busy} onClick={() => void backupNow()}>
            Backup now
          </button>
          <button
            disabled={busy}
            onClick={() => void refresh()}
            title="Reload config + list from disk"
          >
            Refresh
          </button>
          {/* R187: Open project folder — operators who want to copy  */}
          {/* a backup .zip off-disk or hand one to a teammate need   */}
          {/* to find it on filesystem. The backups land under        */}
          {/* <project>/backups/ so opening the project folder puts   */}
          {/* them one directory away. Reuses projectOpenFolder cmd. */}
          <button
            disabled={busy}
            onClick={() => {
              void api
                .projectOpenFolder()
                .catch((e) => alert(`Could not open folder: ${e}`));
            }}
            title="Open the project folder in the OS file manager (backups live in the backups/ subdirectory)"
          >
            📂 Open folder
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            color: "var(--red)",
            fontSize: 11,
            marginBottom: 6,
          }}
        >
          {error}
        </div>
      )}

      <div
        style={{
          marginTop: 10,
          marginBottom: 6,
          fontSize: 11,
          color: "var(--text-dim)",
          textTransform: "uppercase",
          letterSpacing: 0.6,
        }}
      >
        Backups on disk ({list.length})
      </div>
      <table className="mono" style={{ width: "100%", fontSize: 11 }}>
        <colgroup>
          <col />
          <col style={{ width: 100 }} />
          <col style={{ width: 180 }} />
          <col style={{ width: 40 }} />
        </colgroup>
        <thead>
          <tr>
            <th style={{ textAlign: "left" }}>Filename</th>
            <th style={{ textAlign: "right" }}>Size</th>
            <th style={{ textAlign: "left" }}>Created</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {list.map((b) => (
            <tr key={b.filename}>
              <td title={b.filename}>{b.filename}</td>
              <td style={{ textAlign: "right" }}>{formatSize(b.size_bytes)}</td>
              <td>{new Date(b.created_at_ms).toLocaleString()}</td>
              <td style={{ textAlign: "center" }}>
                <button
                  className="ghost danger"
                  disabled={busy}
                  onClick={() => void deleteOne(b.filename)}
                  title={`Delete ${b.filename}`}
                >
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {list.length === 0 && (
            <tr>
              <td
                colSpan={4}
                style={{
                  color: "var(--text-dim)",
                  textAlign: "center",
                  padding: 10,
                }}
              >
                No backups yet. The scheduler fires every{" "}
                <code>{cfg.interval_min}m</code>, or click <code>Backup now</code>{" "}
                for an immediate snapshot.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/**
 * REST API section — Burp's `Settings → REST API`.
 * Enables external tools to interact with BurpFree via localhost HTTP.
 * Matches Burp Suite 2026.8's REST API settings panel.
 */
function RestApiSection() {
  const [cfg, setCfg] = useState<{
    enabled: boolean;
    port: number;
    listen_address: string;
    api_keys: Array<{ name: string; key: string; enabled: boolean }>;
    allow_without_key: boolean;
  } | null>(null);
  const [keys, setKeys] = useState<
    Array<{ name: string; enabled: boolean; key_prefix: string }>
  >([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [lastCreatedKey, setLastCreatedKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.restApiConfigGet().then(setCfg).catch(() => {});
    api.restApiKeyList().then(setKeys).catch(() => {});
  }, []);

  async function saveConfig() {
    if (!cfg) return;
    setBusy(true);
    try {
      await api.restApiConfigSet(cfg);
    } catch (e) {
      alert(`Failed to save REST API config: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function createKey() {
    if (!newKeyName.trim()) return;
    setBusy(true);
    try {
      const created = await api.restApiKeyCreate(newKeyName.trim());
      setLastCreatedKey(created.key);
      setNewKeyName("");
      setKeys(await api.restApiKeyList());
    } catch (e) {
      alert(`Failed to create API key: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function deleteKey(name: string) {
    if (!confirm(`Delete API key "${name}"?`)) return;
    setBusy(true);
    try {
      await api.restApiKeyDelete(name);
      setKeys(await api.restApiKeyList());
    } catch (e) {
      alert(`Failed to delete API key: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  if (!cfg) {
    return (
      <>
        <h3 data-settings-id="rest-api">REST API</h3>
        <div className="dim" style={{ fontSize: 11 }}>Loading…</div>
      </>
    );
  }

  return (
    <>
      <h3 data-settings-id="rest-api">REST API</h3>
      <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
        The REST API enables external tools to integrate with BurpFree.
        Mirrors Burp Suite's REST API on localhost:{cfg.port}. Disabled by
        default.
      </div>
      <div className="form-row">
        <label>
          <input
            type="checkbox"
            checked={cfg.enabled}
            onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })}
          />{" "}
          Service running
        </label>
      </div>
      <div className="form-row">
        <label>Port</label>
        <input
          type="number"
          value={cfg.port}
          min={1}
          max={65535}
          onChange={(e) =>
            setCfg({ ...cfg, port: parseInt(e.target.value) || 1337 })
          }
          style={{ width: 80 }}
        />
      </div>
      <div className="form-row">
        <label>Listen address</label>
        <input
          type="text"
          value={cfg.listen_address}
          onChange={(e) =>
            setCfg({ ...cfg, listen_address: e.target.value })
          }
          style={{ width: 140 }}
          placeholder="127.0.0.1"
        />
      </div>
      <div className="form-row">
        <label>
          <input
            type="checkbox"
            checked={cfg.allow_without_key}
            onChange={(e) =>
              setCfg({ ...cfg, allow_without_key: e.target.checked })
            }
          />{" "}
          Allow access without API key (not recommended)
        </label>
      </div>
      <div style={{ marginTop: 6 }}>
        <button disabled={busy} onClick={() => void saveConfig()}>
          {busy ? "Saving…" : "Save"}
        </button>
      </div>

      <div
        style={{
          marginTop: 12,
          fontSize: 11,
          color: "var(--text-dim)",
          textTransform: "uppercase",
          letterSpacing: 0.6,
        }}
      >
        API keys
      </div>
      <div className="dim" style={{ fontSize: 11, marginBottom: 6 }}>
        API keys are required to authenticate REST API calls via{" "}
        <code>Authorization: Bearer &lt;key&gt;</code> or{" "}
        <code>?api_key=&lt;key&gt;</code>.
      </div>
      {lastCreatedKey && (
        <div
          style={{
            padding: "6px 10px",
            background: "var(--accent-dim)",
            border: "1px solid var(--accent)",
            borderRadius: 2,
            fontSize: 11,
            marginBottom: 8,
            fontFamily: "var(--mono)",
            wordBreak: "break-all",
          }}
        >
          <strong>New key created — copy it now (shown only once):</strong>
          <br />
          {lastCreatedKey}
          <button
            style={{ marginLeft: 8 }}
            onClick={() => {
              navigator.clipboard.writeText(lastCreatedKey);
              setLastCreatedKey(null);
            }}
          >
            Copy
          </button>
        </div>
      )}
      <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
        <input
          type="text"
          value={newKeyName}
          onChange={(e) => setNewKeyName(e.target.value)}
          placeholder="Key name (e.g. CI pipeline)"
          onKeyDown={(e) => e.key === "Enter" && void createKey()}
          style={{ width: 200 }}
        />
        <button disabled={busy || !newKeyName.trim()} onClick={() => void createKey()}>
          New
        </button>
      </div>
      {keys.length > 0 && (
        <table style={{ width: "100%", fontSize: 11 }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Name</th>
              <th>Prefix</th>
              <th>Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.name}>
                <td>{k.name}</td>
                <td style={{ fontFamily: "var(--mono)" }}>
                  {k.key_prefix}…
                </td>
                <td style={{ textAlign: "center" }}>
                  {k.enabled ? "✓" : "○"}
                </td>
                <td>
                  <button
                    className="danger"
                    onClick={() => void deleteKey(k.name)}
                    style={{ padding: "1px 6px", fontSize: 10 }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {keys.length === 0 && (
        <div className="dim" style={{ fontSize: 11 }}>
          No API keys configured. Create one to authenticate REST API calls.
        </div>
      )}
    </>
  );
}

/**
 * Platform-authentication section — Burp's `Settings → Network →
 * Platform authentication`. Operators list host-pattern + scheme +
 * username/password + enabled; when the proxy sees an upstream
 * 401 WWW-Authenticate for a supported scheme, it consults this
 * list, picks the first matching enabled credential, and
 * re-dispatches the request once with an Authorization header. R73
 * ships Basic end-to-end; Digest is listed in the scheme dropdown
 * but the proxy retry path logs TODO and falls through — the row
 * still round-trips through serde so operators can preconfigure
 * for a future Digest handshake.
 *
 * Edits are live: the backend syncs the shared Arc the proxy reads
 * on every save, so a password change takes effect on the next
 * 401 without a proxy restart. Save button only lights up on
 * semantic drift between the hydrated snapshot and the current
 * draft.
 */
function PlatformAuthSection() {
  const [snap, setSnap] = useState<PlatformAuthCredential[]>([]);
  const [draft, setDraft] = useState<PlatformAuthCredential[]>([]);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [showPasswords, setShowPasswords] = useState(false);

  useEffect(() => {
    api
      .platformAuthList()
      .then((rows) => {
        setSnap(rows ?? []);
        setDraft(rows ?? []);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, []);

  // Semantic diff — same shape as BackupSection's draft/cfg split.
  // JSON compare is good enough since every field is a primitive and
  // row order is operator-controlled (first-enabled-match wins).
  const dirty = JSON.stringify(draft) !== JSON.stringify(snap);

  function patchRow(i: number, patch: Partial<PlatformAuthCredential>) {
    setDraft((prev) => prev.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  function addRow() {
    setDraft((prev) => [
      ...prev,
      {
        host_pattern: "",
        scheme: "basic" as AuthScheme,
        username: "",
        password: "",
        enabled: true,
      },
    ]);
  }

  function removeRow(i: number) {
    setDraft((prev) => prev.filter((_, j) => j !== i));
  }

  function moveRow(i: number, delta: -1 | 1) {
    setDraft((prev) => {
      const target = i + delta;
      if (target < 0 || target >= prev.length) return prev;
      const copy = [...prev];
      [copy[i], copy[target]] = [copy[target], copy[i]];
      return copy;
    });
  }

  async function save() {
    setBusy(true);
    try {
      // Backend trims host + username and drops blank-host rows,
      // but we don't echo those edits back into draft here — the
      // next render reflects the server's canonical state via
      // another list() so the operator sees exactly what was
      // persisted.
      await api.platformAuthSet(draft);
      const fresh = await api.platformAuthList();
      setSnap(fresh ?? []);
      setDraft(fresh ?? []);
    } catch (e) {
      alert(`Could not save platform auth: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  function revert() {
    setDraft(snap);
  }

  if (!loaded) {
    return (
      <>
        <h3 data-settings-id="network-platform-auth">Platform authentication</h3>
        <div className="dim" style={{ fontSize: 11 }}>
          Loading…
        </div>
      </>
    );
  }

  return (
    <>
      <h3 data-settings-id="network-platform-auth">Platform authentication</h3>
      <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
        When the proxy receives a <code>401 WWW-Authenticate</code> for a
        supported scheme, the first matching enabled credential is injected
        and the request is retried once — invisible to the client. Host
        pattern is a case-insensitive substring match. Digest round-trips
        but isn't honoured by the retry path yet (R73 ships Basic only).
      </div>

      <div className="toolbar" style={{ marginBottom: 6 }}>
        <button onClick={addRow}>+ Add credential</button>
        <label style={{ marginLeft: 8, fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4 }}>
          <input
            type="checkbox"
            checked={showPasswords}
            onChange={(e) => setShowPasswords(e.target.checked)}
          />
          Show passwords
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        <button onClick={revert} disabled={!dirty || busy}>
          Revert
        </button>
        <button
          className={dirty ? "primary" : ""}
          disabled={!dirty || busy}
          onClick={() => void save()}
          style={{ marginLeft: 6 }}
        >
          {busy ? "Saving…" : dirty ? "Save credentials" : "Saved"}
        </button>
      </div>

      {draft.length === 0 ? (
        <div
          className="dim"
          style={{
            fontSize: 11,
            padding: 10,
            border: "1px dashed var(--border)",
            borderRadius: 4,
            textAlign: "center",
          }}
        >
          No platform-authentication credentials configured. Click{" "}
          <strong>+ Add credential</strong> to add one.
        </div>
      ) : (
        <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "center", width: 44 }}>On</th>
              <th style={{ textAlign: "left" }}>Host pattern</th>
              <th style={{ textAlign: "left", width: 80 }}>Scheme</th>
              <th style={{ textAlign: "left" }}>Username</th>
              <th style={{ textAlign: "left" }}>Password</th>
              <th style={{ width: 80 }} />
            </tr>
          </thead>
          <tbody>
            {draft.map((r, i) => (
              <tr key={i}>
                <td style={{ textAlign: "center" }}>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={(e) => patchRow(i, { enabled: e.target.checked })}
                    title="Disabled rows are skipped during the 401 retry match"
                  />
                </td>
                <td>
                  <input
                    value={r.host_pattern}
                    onChange={(e) => patchRow(i, { host_pattern: e.target.value })}
                    placeholder="api.example.com"
                    style={{ width: "100%", fontSize: 11 }}
                    title="Case-insensitive substring match on the request host"
                  />
                </td>
                <td>
                  <select
                    value={r.scheme}
                    onChange={(e) =>
                      patchRow(i, { scheme: e.target.value as AuthScheme })
                    }
                    style={{ width: "100%", fontSize: 11 }}
                    title="Basic ships end-to-end; Digest reserved for a future round"
                  >
                    <option value="basic">Basic</option>
                    <option value="digest">Digest (TODO)</option>
                  </select>
                </td>
                <td>
                  <input
                    value={r.username}
                    onChange={(e) => patchRow(i, { username: e.target.value })}
                    placeholder="user"
                    style={{ width: "100%", fontSize: 11 }}
                  />
                </td>
                <td>
                  <input
                    type={showPasswords ? "text" : "password"}
                    value={r.password}
                    onChange={(e) => patchRow(i, { password: e.target.value })}
                    placeholder="••••"
                    style={{ width: "100%", fontSize: 11 }}
                    autoComplete="new-password"
                  />
                </td>
                <td style={{ textAlign: "right" }}>
                  <button
                    className="ghost"
                    onClick={() => moveRow(i, -1)}
                    disabled={i === 0}
                    title="Move up — earlier rows match first when host patterns overlap"
                  >
                    ▲
                  </button>
                  <button
                    className="ghost"
                    onClick={() => moveRow(i, +1)}
                    disabled={i === draft.length - 1}
                    title="Move down"
                  >
                    ▼
                  </button>
                  <button
                    className="ghost danger"
                    onClick={() => removeRow(i)}
                    title="Delete this credential"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/**
 * R207: Layout section — gives operators a "Reset UI layout" button
 * that clears every persistent panel-layout preference (group modes,
 * collapsed-group sets, hide-empty-hosts flags, etc.) while
 * preserving data the operator *does* want to keep: theme choice,
 * per-project notes. Enumerates every localStorage key with a known
 * UI-layout prefix + deletes them; silent on quota / disabled
 * localStorage. Confirm modal shows the count so operators know
 * what they're about to lose. Mirrors Burp Pro's "Reset to defaults"
 * affordance in Settings → User interface.
 */
function LayoutSection() {
  // Keys to preserve (prefix match). Everything else that matches
  // a UI-layout prefix gets wiped.
  const PRESERVE_PREFIXES = ["burpfree:theme", "burpfree:notes:"];
  // Prefixes that count as "UI layout" — only keys starting with
  // one of these are candidates for deletion. Keeps the reset from
  // accidentally wiping unrelated keys that some library might
  // have stashed under its own namespace.
  const LAYOUT_PREFIXES = [
    "scanner.",
    "target.",
    "history.",
    "repeater.",
    "intruder.",
    "comparer.",
    "proxy.",
    "organizer.",
    "collaborator.",
    "dashboard.",
    "bchecks.",
    "decoder.",
    "settings.",
    "websocket.",
    "logger.",
    "cookiejar.",
    "sitemap.",
    "wellknown.",
  ];
  function layoutKeys(): string[] {
    const out: string[] = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k) continue;
        if (PRESERVE_PREFIXES.some((p) => k.startsWith(p))) continue;
        if (!LAYOUT_PREFIXES.some((p) => k.startsWith(p))) continue;
        out.push(k);
      }
    } catch {
      /* localStorage disabled — return empty */
    }
    return out;
  }
  const [keyCount, setKeyCount] = useState(() => layoutKeys().length);
  function reset() {
    const keys = layoutKeys();
    if (keys.length === 0) return;
    if (
      !confirm(
        `Reset UI layout — delete ${keys.length} localStorage key${keys.length === 1 ? "" : "s"}? Theme + per-project notes stay. Panel group modes, collapsed sections, hide-empty toggles reset to defaults on the next refresh.`,
      )
    )
      return;
    try {
      for (const k of keys) localStorage.removeItem(k);
    } catch {
      /* localStorage disabled */
    }
    setKeyCount(0);
    alert(
      `Cleared ${keys.length} layout key${keys.length === 1 ? "" : "s"}. Reload the window to see every panel in its default layout.`,
    );
  }
  return (
    <>
      <h3 data-settings-id="ui-layout">Layout</h3>
      <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
        Panel preferences (group modes, collapsed sections, hide-empty
        toggles) are persisted in <code>localStorage</code>. Reset wipes
        every UI-layout key but keeps your theme + per-project notes.
      </div>
      <div className="form-row">
        <button
          className="danger"
          disabled={keyCount === 0}
          onClick={reset}
          title={
            keyCount === 0
              ? "No layout preferences to reset — everything is at its default"
              : `Delete ${keyCount} layout key${keyCount === 1 ? "" : "s"} (confirm first). Reload after to see every panel in its default layout.`
          }
        >
          Reset UI layout
        </button>
        <span className="dim" style={{ fontSize: 11, marginLeft: 8 }}>
          {keyCount === 0
            ? "every panel is already at its default layout"
            : `${keyCount} layout preference${keyCount === 1 ? "" : "s"} saved`}
        </span>
      </div>
    </>
  );
}

/**
 * Hotkeys section — read-only renderer for `SHORTCUT_REGISTRY` /
 * `SHORTCUT_GROUPS` so operators can see every keybinding without
 * popping the Ctrl+? cheatsheet modal. Mirrors Burp's
 * `Settings → User interface → Hotkeys` page in shape (one scope
 * per group header, keys shown as `<kbd>` chips, description right
 * of the key). Rebinding is deferred to a later round — this one
 * fills the previously-dead `ui-hotkeys` nav leaf so the Hotkeys
 * entry in the SETTINGS_NAV finally scrolls somewhere.
 *
 * The search box filters across the keys / description / scope
 * label so an operator looking for "intruder" or "ctrl+r" lands
 * on the match without reading the whole table.
 */
function HotkeysSection() {
  const [query, setQuery] = useState("");

  const q = query.trim().toLowerCase();
  const filteredGroups = useMemo(() => {
    if (!q) return SHORTCUT_GROUPS;
    return SHORTCUT_GROUPS.map((g) => ({
      ...g,
      entries: g.entries.filter(
        (e: ShortcutEntry) =>
          e.description.toLowerCase().includes(q) ||
          e.keys.some((k) => k.toLowerCase().includes(q)) ||
          g.label.toLowerCase().includes(q),
      ),
    })).filter((g) => g.entries.length > 0);
  }, [q]);

  const totalShown = filteredGroups.reduce(
    (n: number, g: { entries: ShortcutEntry[] }) => n + g.entries.length,
    0,
  );

  return (
    <>
      <h3 data-settings-id="ui-hotkeys">Hotkeys</h3>
      <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
        Keyboard shortcuts registered across the app. Read-only in this
        release — rebinding ships in a future round. The same list opens as
        a floating cheatsheet via <code>Ctrl+?</code> or <code>Ctrl+/</code>.
      </div>

      <div className="form-row">
        <label>Filter</label>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="scope · keys · description"
          style={{ width: 260 }}
          autoComplete="off"
        />
        <span className="dim" style={{ fontSize: 11, marginLeft: 8 }}>
          {totalShown} shortcut{totalShown === 1 ? "" : "s"}
          {q ? ` matching "${query}"` : " total"}
        </span>
        {/* R186: Export the full (or filtered) hotkey list as     */}
        {/* Markdown — team wikis, onboarding docs, and release    */}
        {/* notes all benefit from a dumpable cheatsheet. Respects */}
        {/* the current filter so operators can export just the    */}
        {/* subset they care about (e.g. all intruder shortcuts).  */}
        <button
          disabled={totalShown === 0}
          onClick={() => {
            const parts: string[] = [];
            parts.push("## BurpFree keyboard shortcuts");
            parts.push("");
            for (const g of filteredGroups) {
              parts.push(`### ${g.label}`);
              parts.push("");
              parts.push("| Keys | Action |");
              parts.push("| --- | --- |");
              for (const e of g.entries) {
                const keys = e.keys.map((k) => `\`${k}\``).join(" / ");
                const desc = e.description.replace(/\|/g, "\\|");
                parts.push(`| ${keys} | ${desc} |`);
              }
              parts.push("");
            }
            void navigator.clipboard
              .writeText(parts.join("\n"))
              .catch((err) => alert(`${err}`));
          }}
          title={
            totalShown === 0
              ? "No shortcuts match the filter"
              : `Copy ${totalShown} shortcut${totalShown === 1 ? "" : "s"} as Markdown table${q ? ` (filtered to "${query}")` : ""}`
          }
          style={{ marginLeft: 8 }}
        >
          📋 Copy as Markdown
        </button>
      </div>

      {filteredGroups.length === 0 && (
        <div
          className="dim"
          style={{
            fontSize: 11,
            padding: 10,
            textAlign: "center",
            border: "1px dashed var(--border)",
            borderRadius: 4,
          }}
        >
          No shortcut matches <code>{query}</code>.
        </div>
      )}

      {filteredGroups.map((g: { scope: string; label: string; entries: ShortcutEntry[] }) => (
        <div key={g.scope} style={{ marginBottom: 10 }}>
          <div
            style={{
              fontSize: 10,
              textTransform: "uppercase",
              letterSpacing: 0.6,
              color: "var(--text-dim)",
              padding: "4px 2px",
              borderBottom: "1px solid var(--border)",
              marginBottom: 4,
            }}
          >
            {g.label}
          </div>
          <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
            <tbody>
              {g.entries.map((e: ShortcutEntry, i: number) => (
                <tr key={`${g.scope}-${i}`}>
                  <td
                    style={{
                      width: 260,
                      verticalAlign: "top",
                      padding: "3px 10px 3px 2px",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {e.keys.map((k, j) => (
                      <span key={j} style={{ marginRight: 4 }}>
                        {j > 0 && (
                          <span style={{ color: "var(--text-faint)" }}> or </span>
                        )}
                        <kbd
                          style={{
                            display: "inline-block",
                            padding: "1px 6px",
                            background: "var(--bg-raised)",
                            border: "1px solid var(--border)",
                            borderRadius: 3,
                            fontSize: 11,
                            fontFamily: "var(--font-mono)",
                            color: "var(--text)",
                          }}
                        >
                          {k}
                        </kbd>
                      </span>
                    ))}
                  </td>
                  <td
                    style={{
                      padding: "3px 2px",
                      color: "var(--text)",
                      fontFamily: "var(--font-sans)",
                      fontSize: 12,
                    }}
                  >
                    {e.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </>
  );
}
