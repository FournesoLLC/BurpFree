import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  WsMessageRow,
  WsReplayFrame,
  WsReplayResult,
  WsSessionRow,
} from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { copyToClipboard } from "../copyAs";

export function WebSocketPanel() {
  const [sessions, setSessions] = useState<WsSessionRow[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [messages, setMessages] = useState<WsMessageRow[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filterHost, setFilterHost] = useState("");

  const refresh = useCallback(async () => {
    try {
      const list = await api.wsSessionsList(200);
      setSessions(list);
      if (selectedId == null && list.length > 0) {
        setSelectedId(list[0].id);
      }
    } catch (e) {
      console.error("ws sessions:", e);
    }
  }, [selectedId]);

  const refreshMessages = useCallback(async () => {
    if (selectedId == null) {
      setMessages([]);
      return;
    }
    try {
      setMessages(await api.wsMessagesList(selectedId));
    } catch (e) {
      console.error("ws messages:", e);
    }
  }, [selectedId]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => { void refreshMessages(); }, [refreshMessages]);
  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(() => {
      void refresh();
      void refreshMessages();
    }, 2000);
    return () => clearInterval(t);
  }, [autoRefresh, refresh, refreshMessages]);

  const filteredSessions = useMemo(() => {
    const q = filterHost.trim().toLowerCase();
    if (!q) return sessions;
    return sessions.filter(
      (s) => s.host.toLowerCase().includes(q) || s.path.toLowerCase().includes(q)
    );
  }, [sessions, filterHost]);

  const selected = sessions.find((s) => s.id === selectedId) ?? null;

  const [subTab, setSubTab] = useState<"sessions" | "interceptor">("sessions");

  return (
    <div className="panel ws-panel">
      <div className="toolbar">
        <button
          className={subTab === "sessions" ? "primary" : ""}
          onClick={() => setSubTab("sessions")}
        >
          Sessions
        </button>
        <button
          className={subTab === "interceptor" ? "primary" : ""}
          onClick={() => setSubTab("interceptor")}
          title="Pause outbound ws_replay frames before they are sent"
        >
          Interceptor
        </button>
        {subTab === "sessions" && (
          <>
            <input
              placeholder="filter host / path"
              value={filterHost}
              onChange={(e) => setFilterHost(e.target.value)}
              style={{ width: 220 }}
            />
            <button onClick={() => { void refresh(); void refreshMessages(); }}>Refresh</button>
            <label className="indicator">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              Auto-refresh
            </label>
          </>
        )}
        <div className="spacer" style={{ flex: 1 }} />
        <span className="dim">{sessions.length} session(s)</span>
      </div>

      {subTab === "interceptor" && <WsInterceptorPane />}

      {subTab === "sessions" && (<>
      <div className="ws-grid">
        <div className="ws-sessions">
          <table className="rows">
            <thead>
              <tr>
                <th style={{ width: 50 }}>ID</th>
                <th>Target</th>
                <th style={{ width: 60 }}>Msgs</th>
                <th style={{ width: 70 }}>State</th>
                <th style={{ width: 110 }}>Opened</th>
              </tr>
            </thead>
            <tbody>
              {filteredSessions.map((s) => (
                <tr
                  key={s.id}
                  className={s.id === selectedId ? "active" : ""}
                  onClick={() => setSelectedId(s.id)}
                >
                  <td className="mono">{s.id}</td>
                  <td className="mono" title={`${s.host}:${s.port}${s.path}`}>
                    {s.host}:{s.port}
                    <span className="dim"> {s.path}</span>
                  </td>
                  <td>{s.message_count}</td>
                  <td>
                    {s.closed_at_ms ? (
                      <span className="dim">closed{s.close_code ? ` (${s.close_code})` : ""}</span>
                    ) : (
                      <span style={{ color: "var(--green)" }}>open</span>
                    )}
                  </td>
                  <td className="dim">{formatTime(s.opened_at_ms)}</td>
                </tr>
              ))}
              {filteredSessions.length === 0 && (
                <tr><td colSpan={5} className="dim" style={{ padding: 20, textAlign: "center" }}>
                  No WebSocket sessions yet. Use the composer below to launch a replay.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="ws-messages">
          <SessionDetail session={selected} />
          <MessageList messages={messages} />
        </div>
      </div>

      <WsComposer
        initialUrl={selected ? `wss://${selected.host}:${selected.port}${selected.path}` : ""}
        onDone={() => {
          void refresh();
          void refreshMessages();
        }}
      />
      </>)}
    </div>
  );
}

/** Pane that polls the backend interceptor queue and lets the operator
 *  release, modify, or drop pending outbound ws_replay frames. */
function WsInterceptorPane() {
  const [enabled, setEnabled] = useState(false);
  const [pending, setPending] = useState<WsPendingFrame[]>([]);
  const [editing, setEditing] = useState<Record<number, string>>({});
  // Per-frame right-click menu, mirrors the HTTP intercept row menu
  // shipped in Round 32 so the two queues feel consistent.
  const [rowMenu, setRowMenu] = useState<MenuState<WsPendingFrame> | null>(
    null,
  );

  async function refresh() {
    try {
      setEnabled(await api.wsInterceptStatus());
      setPending(await api.wsInterceptPending());
    } catch (e) {
      console.error("ws intercept poll:", e);
    }
  }

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 500);
    return () => clearInterval(t);
  }, []);

  async function toggle() {
    try {
      const next = await api.wsInterceptSetEnabled(!enabled);
      setEnabled(next);
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function release(id: number) {
    const edited = editing[id];
    try {
      await api.wsInterceptRelease(id, edited ?? null, null);
      setEditing((m) => {
        const n = { ...m };
        delete n[id];
        return n;
      });
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function drop(id: number) {
    try {
      await api.wsInterceptDrop(id);
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  async function releaseAll() {
    try {
      const n = await api.wsInterceptReleaseAll();
      console.log("released", n, "frames");
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  // Mirror of release_all for operators who want to flush unwanted
  // outbound frames. Confirms first because dropping each queued
  // frame rejects it to the submitting ws_replay caller.
  async function dropAll() {
    const n = pending.length;
    if (n === 0) return;
    if (
      !confirm(
        `Drop every pending WebSocket frame (${n})? Each dropped frame returns Drop to the sender.`,
      )
    )
      return;
    try {
      await api.wsInterceptDropAll();
      await refresh();
    } catch (e) {
      alert(`${e}`);
    }
  }

  // Per-frame right-click context menu. Carries the full pending
  // frame so the Send-to actions can read id / direction / preview
  // without extra plumbing.
  function sendFrameToComparer(f: WsPendingFrame, slot: "left" | "right") {
    const text = f.preview_text ?? `(binary — ${f.payload_size} bytes)`;
    window.dispatchEvent(
      new CustomEvent("burpfree:comparer-load", {
        detail: {
          text,
          slot,
          label: `ws ${f.direction} ${opcodeLabel(f.opcode)} #${f.id}`,
        },
      }),
    );
  }

  return (
    <div style={{ padding: 10, flex: 1, overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <button
          className={enabled ? "primary" : ""}
          onClick={toggle}
          title="Toggle outbound ws_replay frame interception"
        >
          {enabled ? "Interception ON" : "Interception OFF"}
        </button>
        <button disabled={pending.length === 0} onClick={releaseAll}>
          Forward all ({pending.length})
        </button>
        <button
          className="danger"
          disabled={pending.length === 0}
          onClick={dropAll}
          title="Drop every queued frame — each submit resolves to Drop"
        >
          Drop all ({pending.length})
        </button>
        <span className="dim" style={{ fontSize: 11 }}>
          {enabled
            ? "Outbound ws_replay frames queue here until you release or drop them."
            : "Turn interception on to pause outbound frames the moment they're submitted."}
        </span>
        <div className="spacer" style={{ flex: 1 }} />
        <span className="badge">{pending.length} queued</span>
      </div>
      {pending.length === 0 ? (
        <div className="dim" style={{ padding: 20, textAlign: "center", fontSize: 12 }}>
          No frames queued.
        </div>
      ) : (
        pending.map((f) => (
          <div
            key={f.id}
            onContextMenu={(e) => {
              e.preventDefault();
              setRowMenu({ x: e.clientX, y: e.clientY, data: f });
            }}
            style={{
              padding: 10,
              marginBottom: 8,
              background: "var(--bg-raised)",
              border: "1px solid var(--border)",
              borderRadius: 4,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span className="badge">#{f.id}</span>
              <span className="badge">{opcodeLabel(f.opcode)}</span>
              <span className="badge">{f.direction}</span>
              <span className="dim mono">{f.payload_size}B</span>
              <span style={{ flex: 1 }} />
              <button onClick={() => void release(f.id)}>Release</button>
              <button className="ghost danger" onClick={() => void drop(f.id)}>
                Drop
              </button>
            </div>
            <textarea
              value={editing[f.id] ?? f.preview_text ?? "(binary — edit as text to replace)"}
              onChange={(e) => setEditing((m) => ({ ...m, [f.id]: e.target.value }))}
              rows={Math.min(6, Math.max(2, (f.preview_text?.split("\n").length ?? 2)))}
              style={{ width: "100%", fontFamily: "monospace", fontSize: 11 }}
            />
          </div>
        ))
      )}
      <FloatingMenu
        state={rowMenu}
        onClose={() => setRowMenu(null)}
        items={
          rowMenu?.data
            ? [
                {
                  label: "Release",
                  onClick: () => void release(rowMenu.data!.id),
                },
                {
                  label: "Drop",
                  danger: true,
                  onClick: () => void drop(rowMenu.data!.id),
                },
                { separator: true },
                {
                  label: "Copy preview text",
                  disabled: !rowMenu.data.preview_text,
                  onClick: () =>
                    void copyToClipboard(rowMenu.data!.preview_text ?? ""),
                },
                {
                  label: "Send to Comparer (left)",
                  onClick: () => sendFrameToComparer(rowMenu.data!, "left"),
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () => sendFrameToComparer(rowMenu.data!, "right"),
                },
              ]
            : []
        }
      />
    </div>
  );
}

type WsPendingFrame = {
  id: number;
  session_id: number;
  direction: "outbound" | "inbound";
  opcode: number;
  payload_size: number;
  preview_text: string | null;
  payload_base64: string;
  queued_at_ms: number;
};

function opcodeLabel(op: number): string {
  switch (op) {
    case 0x0: return "continuation";
    case 0x1: return "text";
    case 0x2: return "binary";
    case 0x8: return "close";
    case 0x9: return "ping";
    case 0xa: return "pong";
    default:   return `op${op}`;
  }
}

function SessionDetail({ session }: { session: WsSessionRow | null }) {
  if (!session) {
    return (
      <div className="ws-detail dim" style={{ padding: 10 }}>
        Select a session to inspect its message log, or send a replay below.
      </div>
    );
  }
  return (
    <div className="ws-detail">
      <div><strong>Session {session.id}</strong></div>
      <div>
        <span className="dim">target:</span>{" "}
        <code>
          {session.host}:{session.port}{session.path}
        </code>
      </div>
      <div>
        <span className="dim">opened:</span> {formatTime(session.opened_at_ms)}
        {session.closed_at_ms && (
          <>
            <span className="dim"> · closed:</span> {formatTime(session.closed_at_ms)}
            {session.close_code != null && (
              <>
                <span className="dim"> · code:</span> {session.close_code}
              </>
            )}
            {session.close_reason && (
              <>
                <span className="dim"> · reason:</span> {session.close_reason}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function MessageList({ messages }: { messages: WsMessageRow[] }) {
  const [preview, setPreview] = useState<"text" | "base64">("text");
  return (
    <div className="ws-messages-inner">
      <div className="ws-messages-toolbar">
        <strong>Messages</strong>
        <span className="dim">{messages.length}</span>
        <div className="spacer" style={{ flex: 1 }} />
        <label>
          view:&nbsp;
          <select
            value={preview}
            onChange={(e) => setPreview(e.target.value as "text" | "base64")}
          >
            <option value="text">text</option>
            <option value="base64">base64</option>
          </select>
        </label>
      </div>
      <div className="ws-messages-list">
        {messages.map((m) => (
          <div key={m.id} className={`ws-msg ${m.direction}`}>
            <div className="ws-msg-head">
              <span className={`arrow ${m.direction}`}>
                {m.direction === "out" ? "→" : "←"}
              </span>
              <span className="dim">{m.opcode_label}</span>
              <span className="dim mono">{m.size}B</span>
              <span className="dim">{formatTime(m.ts_ms)}</span>
              {m.truncated && <span className="dim">(truncated)</span>}
            </div>
            <pre className="ws-msg-body mono">
              {preview === "text"
                ? m.text ?? "(binary — switch to base64 view)"
                : m.base64 ?? ""}
            </pre>
          </div>
        ))}
        {messages.length === 0 && (
          <div className="dim" style={{ padding: 10 }}>No messages captured in this session.</div>
        )}
      </div>
    </div>
  );
}

function WsComposer({ initialUrl, onDone }: { initialUrl: string; onDone: () => void }) {
  const [url, setUrl] = useState(initialUrl);
  const [frameText, setFrameText] = useState("");
  const [frameKind, setFrameKind] = useState<"text" | "binary" | "ping" | "close">("text");
  const [frames, setFrames] = useState<WsReplayFrame[]>([]);
  const [drainMs, setDrainMs] = useState(2000);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<WsReplayResult | null>(null);

  // Keep url in sync when a different session is selected but don't
  // steal user edits mid-flight.
  useEffect(() => {
    if (!url && initialUrl) setUrl(initialUrl);
  }, [initialUrl, url]);

  const addFrame = () => {
    setFrames([...frames, { kind: frameKind, text: frameText, delay_ms: 0 }]);
    setFrameText("");
  };
  const removeFrame = (i: number) => setFrames(frames.filter((_, j) => j !== i));

  const send = async () => {
    if (!url.trim()) {
      alert("WebSocket URL is required (e.g. wss://echo.websocket.events)");
      return;
    }
    const list = frames.length > 0 ? frames : [{ kind: frameKind, text: frameText }];
    setBusy(true);
    setResult(null);
    try {
      const r = await api.wsReplay({
        url,
        frames: list,
        drain_ms: drainMs,
      });
      setResult(r);
      onDone();
    } catch (e) {
      setResult({
        session_id: 0,
        sent: 0,
        received: 0,
        closed: true,
        error: `${e}`,
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ws-composer">
      <div className="ws-composer-head">
        <strong>Composer</strong>
        <span className="dim">
          Opens a direct connection to the target and records it as a new
          session. Does not pass through the local proxy.
        </span>
      </div>
      <div className="ws-composer-row">
        <input
          placeholder="wss://host/path"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1 }}
        />
        <label className="indicator">
          drain&nbsp;
          <input
            type="number"
            min={0}
            max={60000}
            step={100}
            value={drainMs}
            onChange={(e) => setDrainMs(parseInt(e.target.value || "0", 10) || 0)}
            style={{ width: 80 }}
          />
          &nbsp;ms
        </label>
        <button onClick={send} disabled={busy}>
          {busy ? "Sending…" : "Send"}
        </button>
      </div>

      <div className="ws-composer-row">
        <select
          value={frameKind}
          onChange={(e) => setFrameKind(e.target.value as any)}
          style={{ width: 100 }}
        >
          <option value="text">text</option>
          <option value="binary">binary (base64)</option>
          <option value="ping">ping</option>
          <option value="close">close</option>
        </select>
        <textarea
          placeholder={frameKind === "binary" ? "base64 payload" : "frame payload"}
          value={frameText}
          onChange={(e) => setFrameText(e.target.value)}
          rows={2}
          style={{ flex: 1, resize: "vertical", minHeight: 32 }}
        />
        <button onClick={addFrame}>Enqueue</button>
      </div>

      {frames.length > 0 && (
        <div className="ws-composer-frames">
          <div className="dim">Queued frames ({frames.length}):</div>
          {frames.map((f, i) => (
            <div key={i} className="ws-composer-frame">
              <span className="dim mono">[{i}]</span>
              <span className="dim">{f.kind ?? "text"}</span>
              <code className="mono" style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {f.base64 ? `b64: ${f.base64.slice(0, 60)}` : (f.text ?? "").slice(0, 60)}
              </code>
              <button onClick={() => removeFrame(i)}>✕</button>
            </div>
          ))}
          <button onClick={() => setFrames([])}>Clear queue</button>
        </div>
      )}

      {result && (
        <div className="ws-composer-result mono" style={{ color: result.error ? "var(--red)" : "var(--text-dim)" }}>
          {result.error
            ? `error: ${result.error}`
            : `session ${result.session_id} · sent=${result.sent} received=${result.received}` +
              (result.close_code ? ` · close ${result.close_code}` : "")}
        </div>
      )}
    </div>
  );
}

function formatTime(ms: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toLocaleTimeString();
}
