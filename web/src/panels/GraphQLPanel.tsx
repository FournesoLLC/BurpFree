import { useEffect, useMemo, useState } from "react";
import {
  api,
  GraphQLEndpoint,
  GraphQLIntrospectResult,
  GraphQLOperation,
  GraphQLSchemaType,
} from "../api";

/**
 * GraphQL inspector tab.
 *
 * Shows every GraphQL endpoint BurpFree has seen in history, lets the
 * operator pick one, enumerates its carried operations, and offers an
 * Introspect button that fires the canonical introspection query and
 * renders the resulting schema as a two-column tree.
 */
export function GraphQLPanel() {
  const [endpoints, setEndpoints] = useState<GraphQLEndpoint[]>([]);
  const [selected, setSelected] = useState<GraphQLEndpoint | null>(null);
  const [headersText, setHeadersText] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<GraphQLIntrospectResult | null>(null);

  async function refresh() {
    try {
      const list = await api.graphqlListEndpoints();
      setEndpoints(list);
      if (!selected && list.length > 0) setSelected(list[0]);
    } catch (e) {
      console.error("graphql: list endpoints failed", e);
    }
  }
  useEffect(() => {
    refresh();
  }, []);

  async function introspect() {
    if (!selected) return;
    const hdrs = parseHeaders(headersText);
    setBusy(true);
    try {
      const r = await api.graphqlIntrospect(selected.url, hdrs);
      setResult(r);
    } catch (e) {
      setResult({
        status: 0,
        body_text: "",
        elapsed_ms: 0,
        schema: null,
        error: String(e),
      });
    } finally {
      setBusy(false);
    }
  }

  const ops = selected?.operations ?? [];

  return (
    <div className="panel">
      <div className="toolbar">
        <strong>GraphQL</strong>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="badge">{endpoints.length} endpoint(s)</span>
        <button onClick={refresh}>Refresh</button>
      </div>
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <aside
          style={{
            width: 260,
            borderRight: "1px solid var(--border)",
            overflow: "auto",
          }}
        >
          {endpoints.length === 0 ? (
            <div style={{ color: "var(--text-dim)", padding: 10, fontSize: 12 }}>
              No GraphQL traffic detected yet. Proxy a request through
              BurpFree and this list will populate automatically.
            </div>
          ) : (
            endpoints.map((e) => (
              <div
                key={e.transaction_id}
                onClick={() => {
                  setSelected(e);
                  setResult(null);
                }}
                style={{
                  padding: "6px 10px",
                  cursor: "pointer",
                  borderBottom: "1px solid var(--border-dim, rgba(128,128,128,0.1))",
                  background:
                    selected?.transaction_id === e.transaction_id
                      ? "var(--bg-raised)"
                      : "transparent",
                }}
              >
                <div style={{ fontSize: 12, fontFamily: "monospace" }}>
                  {e.method} {new URL(e.url).pathname}
                </div>
                <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
                  {new URL(e.url).host} · {e.operations.length} op(s)
                </div>
              </div>
            ))
          )}
        </aside>
        <main style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
          {!selected ? (
            <div style={{ padding: 20, color: "var(--text-dim)" }}>
              Select an endpoint on the left.
            </div>
          ) : (
            <>
              <div
                style={{
                  padding: 10,
                  borderBottom: "1px solid var(--border)",
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {selected.method} {selected.url}
                  </span>
                  <span className="spacer" style={{ flex: 1 }} />
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={introspect}
                    title="POST the canonical introspection query"
                  >
                    {busy ? "Running…" : "Run introspection"}
                  </button>
                </div>
                <textarea
                  placeholder={
                    "Extra headers for the introspection POST, one per line:\nAuthorization: Bearer xyz\nX-Api-Key: abc"
                  }
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                  rows={3}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 11 }}
                />
              </div>
              <OperationList ops={ops} />
              <SchemaView result={result} />
            </>
          )}
        </main>
      </div>
    </div>
  );
}

function OperationList({ ops }: { ops: GraphQLOperation[] }) {
  if (ops.length === 0) {
    return (
      <div style={{ padding: 10, color: "var(--text-dim)", fontSize: 12 }}>
        No operations parsed from the captured request body — this endpoint was
        probably recognised via its URL path.
      </div>
    );
  }
  return (
    <div style={{ padding: 10, borderBottom: "1px solid var(--border)" }}>
      <div style={{ color: "var(--text-dim)", fontSize: 11, marginBottom: 4 }}>
        Operations in captured request ({ops.length})
      </div>
      {ops.map((op, i) => (
        <details key={i} style={{ marginBottom: 4 }}>
          <summary style={{ cursor: "pointer", fontSize: 12 }}>
            <span className="badge" style={{ marginRight: 6 }}>
              {op.kind}
            </span>
            <span className="mono">{op.name ?? "(anonymous)"}</span>
          </summary>
          <pre
            className="mono"
            style={{
              fontSize: 11,
              background: "var(--bg-raised)",
              padding: 8,
              overflow: "auto",
              maxHeight: 160,
              marginTop: 4,
            }}
          >
            {op.text}
          </pre>
        </details>
      ))}
    </div>
  );
}

function SchemaView({ result }: { result: GraphQLIntrospectResult | null }) {
  const [filter, setFilter] = useState("");

  const filteredTypes = useMemo(() => {
    if (!result?.schema) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return result.schema.types;
    return result.schema.types.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.fields.some((f) => f.name.toLowerCase().includes(q)),
    );
  }, [result, filter]);

  if (!result) {
    return (
      <div style={{ flex: 1, padding: 10, color: "var(--text-dim)", fontSize: 12 }}>
        Introspection has not been run yet. Click <b>Run introspection</b> above to fetch the schema.
      </div>
    );
  }

  if (result.error) {
    return (
      <div style={{ flex: 1, padding: 10 }}>
        <div className="severity-high" style={{ fontWeight: 600 }}>
          Introspection failed
        </div>
        <pre
          className="mono"
          style={{ fontSize: 12, background: "var(--bg-raised)", padding: 8 }}
        >
          {result.error}
        </pre>
      </div>
    );
  }

  if (!result.schema) {
    return (
      <div style={{ flex: 1, padding: 10, display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
          HTTP {result.status} · {result.elapsed_ms} ms — response did not look like a GraphQL
          introspection payload. Raw body shown below.
        </div>
        <pre
          className="mono"
          style={{
            flex: 1,
            fontSize: 11,
            background: "var(--bg-raised)",
            padding: 8,
            overflow: "auto",
          }}
        >
          {result.body_text}
        </pre>
      </div>
    );
  }

  const schema = result.schema;
  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div
        style={{
          padding: "6px 10px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 12,
        }}
      >
        <span>
          <b>Query:</b> {schema.query_type ?? "—"}
        </span>
        <span>
          <b>Mutation:</b> {schema.mutation_type ?? "—"}
        </span>
        <span>
          <b>Subscription:</b> {schema.subscription_type ?? "—"}
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <input
          type="text"
          placeholder="Filter types / fields…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ width: 220 }}
        />
      </div>
      <div style={{ flex: 1, overflow: "auto", padding: 10 }}>
        {filteredTypes.map((t) => (
          <TypeCard key={t.name} t={t} />
        ))}
        {filteredTypes.length === 0 && (
          <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
            No types match <code>{filter}</code>.
          </div>
        )}
      </div>
    </div>
  );
}

function TypeCard({ t }: { t: GraphQLSchemaType }) {
  return (
    <details
      style={{
        marginBottom: 6,
        background: "var(--bg-raised)",
        border: "1px solid var(--border)",
        borderRadius: 4,
        padding: "4px 8px",
      }}
    >
      <summary style={{ cursor: "pointer" }}>
        <span className="badge" style={{ marginRight: 6, fontSize: 10 }}>
          {t.kind}
        </span>
        <span className="mono" style={{ fontWeight: 600 }}>
          {t.name}
        </span>
        {t.fields.length > 0 && (
          <span style={{ color: "var(--text-dim)", fontSize: 11, marginLeft: 6 }}>
            {t.fields.length} field(s)
          </span>
        )}
        {t.enum_values.length > 0 && (
          <span style={{ color: "var(--text-dim)", fontSize: 11, marginLeft: 6 }}>
            {t.enum_values.length} enum value(s)
          </span>
        )}
      </summary>
      {t.description && (
        <div style={{ color: "var(--text-dim)", fontSize: 11, margin: "4px 0" }}>
          {t.description}
        </div>
      )}
      {t.fields.length > 0 && (
        <table className="mono" style={{ width: "100%", fontSize: 11, marginTop: 4 }}>
          <tbody>
            {t.fields.map((f) => (
              <tr key={f.name}>
                <td style={{ padding: "2px 6px", verticalAlign: "top" }}>
                  {f.deprecated ? (
                    <s title="deprecated">{f.name}</s>
                  ) : (
                    f.name
                  )}
                  {f.args.length > 0 && (
                    <span style={{ color: "var(--text-dim)" }}>
                      (
                      {f.args
                        .map((a) => `${a.name}: ${a.type_label}`)
                        .join(", ")}
                      )
                    </span>
                  )}
                </td>
                <td style={{ padding: "2px 6px", color: "var(--accent, #3a9df7)" }}>
                  {f.type_label}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {t.enum_values.length > 0 && (
        <div style={{ fontSize: 11, marginTop: 4 }}>
          {t.enum_values.map((v) => (
            <span key={v} className="badge" style={{ marginRight: 4 }}>
              {v}
            </span>
          ))}
        </div>
      )}
    </details>
  );
}

function parseHeaders(text: string): Array<[string, string]> {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"))
    .map((l) => {
      const idx = l.indexOf(":");
      if (idx < 0) return [l, ""] as [string, string];
      return [l.slice(0, idx).trim(), l.slice(idx + 1).trim()] as [string, string];
    });
}
