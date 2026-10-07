// McpPanel.tsx
//
// Surfaces the `burpfree-mcp` crate in its own top-level tab.
// Shows how to connect an AI client (Claude Desktop / Cline / Codex) to
// BurpFree's project data, lists the exposed tools, and provides a
// "Test server" button that spawns a short-lived helper and verifies
// `initialize` + `ping` round-trip.

import { useEffect, useState } from "react";
import { api, McpStatus, McpTestResult, McpToolView } from "../api";

export function McpPanel() {
  const [status, setStatus] = useState<McpStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<McpTestResult | null>(null);
  const [copiedCfg, setCopiedCfg] = useState(false);
  const [copiedArgv, setCopiedArgv] = useState(false);

  useEffect(() => {
    api.mcpStatus().then(setStatus).catch((e) => setErr(`${e}`));
  }, []);

  async function copy(txt: string, mark: (b: boolean) => void) {
    try {
      await navigator.clipboard.writeText(txt);
      mark(true);
      setTimeout(() => mark(false), 2000);
    } catch (e) {
      console.error(e);
    }
  }

  async function runTest() {
    setTesting(true);
    setTest(null);
    try {
      setTest(await api.mcpTest());
    } catch (e) {
      setTest({ ok: false, summary: `${e}`, stderr_tail: [] });
    } finally {
      setTesting(false);
    }
  }

  if (err) return <div className="pad">MCP status unavailable: {err}</div>;
  if (!status) return <div className="pad">Loading MCP status…</div>;

  const argvText = status.command_argv.map(quoteIfNeeded).join(" ");

  return (
    <div className="mcp-root">
      <h2 className="mcp-title">Model Context Protocol server</h2>
      <p className="mcp-sub">
        BurpFree ships an MCP server that exposes project state to AI
        clients over JSON-RPC on stdio. The protocol version is{" "}
        <code>{status.protocol_version}</code>.
      </p>

      <div className="mcp-grid">
        <section className="mcp-card">
          <h3>Server identity</h3>
          <div className="mcp-kv">
            <div><span>Name</span><code>{status.server_name}</code></div>
            <div><span>Version</span><code>{status.server_version}</code></div>
            <div><span>Protocol</span><code>{status.protocol_version}</code></div>
            <div><span>Executable</span><code title={status.exe_path}>{status.exe_path}</code></div>
            <div>
              <span>Project</span>
              <code title={status.project_path ?? ""}>
                {status.project_path ?? "— open a project first —"}
              </code>
            </div>
          </div>
        </section>

        <section className="mcp-card">
          <h3>Launch command</h3>
          <p className="mcp-blurb">
            Any MCP client that spawns a stdio child can connect by running
            this invocation. Logs go to <code>stderr</code>; <code>stdout</code>
            is reserved for JSON-RPC frames.
          </p>
          <pre className="mcp-cmd">{argvText}</pre>
          <button className="ghost" onClick={() => void copy(argvText, setCopiedArgv)}>
            {copiedArgv ? "✓ Copied" : "Copy command"}
          </button>
        </section>

        <section className="mcp-card mcp-card-wide">
          <h3>Claude Desktop config</h3>
          <p className="mcp-blurb">
            Drop this entry into Claude Desktop's <code>claude_desktop_config.json</code>{" "}
            and restart the app — BurpFree will show up under the MCP server list.
          </p>
          <pre className="mcp-cmd">{status.claude_config_json}</pre>
          <button className="ghost" onClick={() => void copy(status.claude_config_json, setCopiedCfg)}>
            {copiedCfg ? "✓ Copied" : "Copy JSON"}
          </button>
        </section>

        <section className="mcp-card mcp-card-wide">
          <h3>Exposed tools ({status.tools.length})</h3>
          <table className="mcp-tools">
            <thead>
              <tr>
                <th style={{ width: 180 }}>Name</th>
                <th>Description</th>
                <th style={{ width: 90 }}>Inputs</th>
              </tr>
            </thead>
            <tbody>
              {status.tools.map((t) => (
                <tr key={t.name}>
                  <td className="mono"><strong>{t.name}</strong></td>
                  <td>{t.description}</td>
                  <td className="mono" title={JSON.stringify(t.input_schema, null, 2)}>
                    {summarizeInputs(t)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="mcp-card mcp-card-wide">
          <h3>Connection test</h3>
          <p className="mcp-blurb">
            Spawn the helper child, send <code>initialize</code> and{" "}
            <code>ping</code>, verify both get a response. Does not require any
            external MCP client to be installed.
          </p>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button className="primary" onClick={runTest} disabled={testing || !status.project_path}>
              {testing ? "Testing…" : "Test server"}
            </button>
            {test && (
              <span style={{ color: test.ok ? "var(--green)" : "var(--red)" }}>
                {test.ok ? "✓" : "✗"} {test.summary}
              </span>
            )}
          </div>
          {test && test.stderr_tail.length > 0 && (
            <pre className="mcp-cmd mcp-stderr">{test.stderr_tail.join("\n")}</pre>
          )}
        </section>
      </div>
    </div>
  );
}

function quoteIfNeeded(arg: string): string {
  return /\s/.test(arg) ? `"${arg}"` : arg;
}

function summarizeInputs(t: McpToolView): string {
  const schema = t.input_schema as { properties?: Record<string, unknown>; required?: string[] };
  const props = schema?.properties ? Object.keys(schema.properties) : [];
  const req = new Set(schema?.required ?? []);
  if (props.length === 0) return "—";
  return props.map((p) => (req.has(p) ? p : `${p}?`)).join(", ");
}
