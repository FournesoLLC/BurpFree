// JwtModal.tsx
//
// JWT inspector + editor. Opened from the history row context menu —
// scans the stored transaction for any JWT-shaped tokens, lists them,
// and lets the operator decode / edit / re-sign.

import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export type JwtDecoded = {
  token: string;
  header: unknown;
  payload: unknown;
  signature_b64: string;
  location: string;
};

type Alg = "HS256" | "HS384" | "HS512" | "none";

interface Props {
  open: boolean;
  /** The transaction to scan for JWTs. */
  transactionId: number | null;
  onClose: () => void;
}

export function JwtModal({ open, transactionId, onClose }: Props) {
  const [found, setFound] = useState<JwtDecoded[]>([]);
  const [sel, setSel] = useState<number>(0);
  const [err, setErr] = useState<string | null>(null);
  const [headerText, setHeaderText] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [secret, setSecret] = useState("");
  const [alg, setAlg] = useState<Alg>("HS256");
  const [resigned, setResigned] = useState<string | null>(null);
  const [verify, setVerify] = useState<"idle" | "valid" | "invalid" | "error">("idle");
  const [verifyMsg, setVerifyMsg] = useState<string>("");
  const [copied, setCopied] = useState<string | null>(null);
  const copyTimer = useRef<number | null>(null);

  useEffect(() => {
    if (!open || transactionId == null) return;
    setErr(null);
    setResigned(null);
    setVerify("idle");
    (async () => {
      try {
        const rows = await invoke<JwtDecoded[]>("jwt_scan_transaction", { id: transactionId });
        setFound(rows);
        setSel(0);
        if (rows[0]) {
          setHeaderText(JSON.stringify(rows[0].header, null, 2));
          setPayloadText(JSON.stringify(rows[0].payload, null, 2));
        } else {
          setHeaderText("");
          setPayloadText("");
        }
      } catch (e) {
        setErr(`${e}`);
      }
    })();
  }, [open, transactionId]);

  // Esc to close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const current = found[sel] ?? null;

  // When the user picks a different token, reset the editable buffers.
  useEffect(() => {
    if (!current) return;
    setHeaderText(JSON.stringify(current.header, null, 2));
    setPayloadText(JSON.stringify(current.payload, null, 2));
    setResigned(null);
    setVerify("idle");
  }, [sel, current?.token]);

  const parsedHeader = useMemo(() => safeParse(headerText), [headerText]);
  const parsedPayload = useMemo(() => safeParse(payloadText), [payloadText]);
  const headerOk = parsedHeader.ok;
  const payloadOk = parsedPayload.ok;
  const detectedAlg = useMemo(() => {
    if (parsedHeader.ok && typeof parsedHeader.value === "object" && parsedHeader.value) {
      const a = (parsedHeader.value as { alg?: string }).alg;
      if (a && ["HS256", "HS384", "HS512", "none"].includes(a)) return a as Alg;
    }
    return null;
  }, [parsedHeader]);

  async function resign() {
    if (!headerOk || !payloadOk) { setErr("header/payload JSON invalid"); return; }
    setErr(null);
    try {
      const r = await invoke<{ token: string; alg: string }>("jwt_sign", {
        args: {
          header: parsedHeader.value,
          payload: parsedPayload.value,
          secret,
          alg,
        },
      });
      setResigned(r.token);
    } catch (e) {
      setErr(`${e}`);
    }
  }

  async function verifyToken() {
    if (!current) return;
    try {
      const r = await invoke<{ valid: boolean }>("jwt_verify", {
        args: { token: current.token, secret },
      });
      if (r.valid) {
        setVerify("valid");
        setVerifyMsg("signature matches the supplied secret");
      } else {
        setVerify("invalid");
        setVerifyMsg("signature does not match");
      }
    } catch (e) {
      setVerify("error");
      setVerifyMsg(`${e}`);
    }
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(null), 1500);
    } catch (e) { console.error(e); }
  }

  if (!open) return null;

  return (
    <div className="poc-backdrop" onClick={onClose}>
      <div className="poc-dialog jwt-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="poc-head">
          <strong>JWT inspector + editor</strong>
          <span className="dim" style={{ fontSize: 11 }}>
            {transactionId != null ? `transaction #${transactionId}` : "no transaction"} ·
            {" "}{found.length} token(s) found
          </span>
          <span style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
        {err && <div style={{ color: "var(--red)", padding: "6px 12px" }}>✗ {err}</div>}
        {found.length === 0 ? (
          <div className="empty" style={{ padding: 24 }}>
            No JWT-shaped tokens detected in this transaction's URL, headers, or body.
          </div>
        ) : (
          <div className="jwt-grid">
            <aside className="jwt-list">
              {found.map((t, i) => (
                <div
                  key={i}
                  className={`jwt-list-row ${i === sel ? "active" : ""}`}
                  onClick={() => setSel(i)}
                >
                  <div className="jwt-list-loc">{t.location}</div>
                  <code className="mono jwt-list-token" title={t.token}>
                    {t.token.length > 48 ? `${t.token.slice(0, 48)}…` : t.token}
                  </code>
                </div>
              ))}
            </aside>
            <div className="jwt-detail">
              <div className="jwt-section">
                <div className="jwt-section-head">
                  <strong>Header</strong>
                  {!headerOk && <span className="dim" style={{ color: "var(--red)" }}>parse error</span>}
                  <span style={{ flex: 1 }} />
                  {detectedAlg && (
                    <span className="dim" style={{ fontSize: 11 }}>
                      header.alg = <code>{detectedAlg}</code>
                    </span>
                  )}
                </div>
                <textarea
                  className="jwt-area mono"
                  value={headerText}
                  onChange={(e) => setHeaderText(e.target.value)}
                />
              </div>
              <div className="jwt-section">
                <div className="jwt-section-head">
                  <strong>Payload (claims)</strong>
                  {!payloadOk && <span className="dim" style={{ color: "var(--red)" }}>parse error</span>}
                </div>
                <textarea
                  className="jwt-area mono"
                  value={payloadText}
                  onChange={(e) => setPayloadText(e.target.value)}
                />
              </div>
              <div className="jwt-controls">
                <label>Alg</label>
                <select value={alg} onChange={(e) => setAlg(e.target.value as Alg)}>
                  <option value="HS256">HS256</option>
                  <option value="HS384">HS384</option>
                  <option value="HS512">HS512</option>
                  <option value="none">none (alg bypass)</option>
                </select>
                <label>Secret</label>
                <input
                  type="text"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="HMAC key"
                  style={{ flex: 1, minWidth: 160 }}
                />
                <button className="ghost" onClick={verifyToken} disabled={!current}>
                  Verify
                </button>
                <button className="primary" onClick={resign} disabled={!headerOk || !payloadOk}>
                  Re-sign
                </button>
              </div>
              {verify !== "idle" && (
                <div
                  className="jwt-verify"
                  style={{
                    color:
                      verify === "valid"
                        ? "var(--green)"
                        : verify === "invalid"
                        ? "var(--red)"
                        : "var(--amber)",
                  }}
                >
                  {verify === "valid" ? "✓" : verify === "invalid" ? "✗" : "⚠"} {verifyMsg}
                </div>
              )}
              {resigned && (
                <div className="jwt-output">
                  <div className="jwt-section-head">
                    <strong>Re-signed token</strong>
                    <span style={{ flex: 1 }} />
                    <button className="ghost" onClick={() => void copy(resigned, "resigned")}>
                      {copied === "resigned" ? "✓ Copied" : "Copy"}
                    </button>
                  </div>
                  <code className="mono jwt-output-token">{resigned}</code>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function safeParse(src: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(src) };
  } catch (e) {
    return { ok: false, error: `${e}` };
  }
}
