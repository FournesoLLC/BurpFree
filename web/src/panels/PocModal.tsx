// PocModal.tsx
//
// A reusable modal for displaying a generated attack PoC (CSRF or
// clickjacking). Shows the HTML in a scrollable <pre>, plus Copy and
// Save-to-file buttons.

import { useEffect, useRef, useState } from "react";

export interface PocPayload {
  title: string;
  html: string;
  suggestedName: string;
}

interface Props {
  payload: PocPayload | null;
  onClose: () => void;
}

export function PocModal({ payload, onClose }: Props) {
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  // Reset transient state when payload swaps.
  useEffect(() => {
    setCopied(false);
    setSaved(null);
  }, [payload?.html]);

  // Close on Esc.
  useEffect(() => {
    if (!payload) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [payload, onClose]);

  if (!payload) return null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(payload!.html);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error(e);
    }
  }

  function saveAs() {
    const blob = new Blob([payload!.html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = payload!.suggestedName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setSaved(payload!.suggestedName);
    setTimeout(() => setSaved(null), 2500);
  }

  return (
    <div className="poc-backdrop" onClick={onClose}>
      <div className="poc-dialog" ref={dialogRef} onClick={(e) => e.stopPropagation()}>
        <div className="poc-head">
          <strong>{payload.title}</strong>
          <span className="poc-sub">{payload.suggestedName}</span>
          <span style={{ flex: 1 }} />
          <button className="ghost" onClick={copy}>{copied ? "✓ Copied" : "Copy HTML"}</button>
          <button className="ghost" onClick={saveAs}>{saved ? "✓ Saved" : "Save as…"}</button>
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
        <pre className="poc-body">{payload.html}</pre>
        <div className="poc-foot">
          Drop this file into a browser from a different origin than the target to drive the exploit.
          Opens read-only here; use <kbd>Copy</kbd> or <kbd>Save as…</kbd> to extract.
        </div>
      </div>
    </div>
  );
}
