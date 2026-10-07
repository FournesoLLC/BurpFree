import { useEffect, useRef, useState } from "react";
import { api, ChainStep, Transform } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { copyToClipboard } from "../copyAs";
import { sendToComparer } from "./ComparerPanel";

const OPS: Transform["op"][] = [
  "url_encode",
  "url_decode",
  "base64_encode",
  "base64_decode",
  "base64_url_encode",
  "base64_url_decode",
  "hex_encode",
  "hex_decode",
  "html_encode",
  "html_decode",
  "unicode_escape_encode",
  "unicode_escape_decode",
  "gzip_decode",
  "deflate_decode",
  "brotli_decode",
  "jwt_decode",
  "uppercase",
  "lowercase",
  "reverse",
  "md5",
  "sha1",
  "sha256",
  "blake3",
  "hmac_sha1",
  "hmac_sha256",
  "hmac_sha384",
  "hmac_sha512",
];

/** Grouped labels used for the add-transform dropdown. */
const OP_GROUPS: Array<{ label: string; ops: Transform["op"][] }> = [
  {
    label: "Encode / decode",
    ops: [
      "url_encode",
      "url_decode",
      "base64_encode",
      "base64_decode",
      "base64_url_encode",
      "base64_url_decode",
      "hex_encode",
      "hex_decode",
      "html_encode",
      "html_decode",
      "unicode_escape_encode",
      "unicode_escape_decode",
    ],
  },
  { label: "Compression", ops: ["gzip_decode", "deflate_decode", "brotli_decode"] },
  { label: "JWT", ops: ["jwt_decode"] },
  { label: "Case / order", ops: ["uppercase", "lowercase", "reverse"] },
  { label: "Hash", ops: ["md5", "sha1", "sha256", "blake3"] },
  { label: "HMAC (keyed)", ops: ["hmac_sha1", "hmac_sha256", "hmac_sha384", "hmac_sha512"] },
];

/** Ops that require an operator-supplied key. */
const HMAC_OPS: ReadonlyArray<Transform["op"]> = [
  "hmac_sha1",
  "hmac_sha256",
  "hmac_sha384",
  "hmac_sha512",
];

function isHmacOp(op: Transform["op"]): boolean {
  return HMAC_OPS.includes(op);
}

export function DecoderPanel() {
  const [input, setInput] = useState("hello world");
  const [chain, setChain] = useState<Transform[]>([]);
  // R308: Hidden file input ref for the "⬆ Import chain" button —
  // one ref so a single click fires the OS picker. Same pattern
  // as R124 scope-import + R291 settings-import.
  const importChainFileRef = useRef<HTMLInputElement | null>(null);
  const [steps, setSteps] = useState<ChainStep[]>([]);
  const [smartBusy, setSmartBusy] = useState(false);
  // R836: Burp Decoder's per-pane "Text / Hex" radio toggle. Each
  // output pane in the real Burp Decoder carries this toggle in the
  // top-left corner — switching between a raw-text render and a
  // `hexdump -C` style byte grid. **Why** Operators decoding a
  // chain (base64 → gzip → …) frequently land on binary bytes and
  // need to see hex to spot structure (file magic, null-padded
  // strings, UTF-16 BOMs, endianness markers). Our previous pane
  // showed raw text only, which renders as mojibake for anything
  // non-ASCII. **Mechanism** per-step view-mode map keyed by chain
  // index — explicit `"text"` / `"hex"` wins over the auto-default.
  // **Auto-default** steps flagged `binary: true` (hash digests,
  // gzip/deflate raw bytes) default to Hex view so the operator
  // sees the structure immediately; non-binary steps default to
  // Text. **Also drives the Input pane** at the top via the same
  // state keyed with the sentinel `-1`, so operators pasting a
  // binary sample (hex-escaped from a packet capture) can flip the
  // Input to Hex for inspection.
  const [paneView, setPaneView] = useState<Record<number, "text" | "hex">>({});
  function getPaneView(i: number): "text" | "hex" {
    const explicit = paneView[i];
    if (explicit) return explicit;
    if (i < 0) return "text"; // Input pane default = text
    return steps[i]?.binary ? "hex" : "text";
  }
  function setPane(i: number, mode: "text" | "hex") {
    setPaneView((prev) => ({ ...prev, [i]: mode }));
  }
  // Right-click menu on a chain-step output pane. We stash both the
  // step index + the step itself so menu handlers can reach the
  // operator-visible output and the chain entry's op label.
  const [outMenu, setOutMenu] = useState<
    MenuState<{ idx: number; step: ChainStep; op: string }> | null
  >(null);
  // Hidden `<input type="file">` for R119's `⬆ Load input` button —
  // use the ref so a visible toolbar button triggers the native OS
  // file picker without rendering the ugly default input. Same
  // pattern as R118's Intruder payload-load button.
  const inputFileRef = useRef<HTMLInputElement | null>(null);

  /** Download the current step's output as a file. Blob + anchor so
   *  we don't need a Tauri file-system permission. */
  function downloadStepOutput(idx: number, step: ChainStep, op: string) {
    const ext = step.binary ? ".bin" : ".txt";
    const name = `decoder-step-${idx + 1}-${op}${ext}`;
    const blob = new Blob([step.output ?? ""], {
      type: step.binary ? "application/octet-stream" : "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  /** R150: Save the final step's output as a file via a toolbar
   *  one-click. The per-step right-click already offers this; the
   *  toolbar button covers the common "I'm done decoding, give me
   *  the result on disk" workflow where the operator doesn't want
   *  to right-click on the last preview pane. Reuses the existing
   *  helper. Named after the final op so the file is immediately
   *  distinguishable from Smart-Decode runs. */
  function downloadFinalOutput() {
    if (chain.length === 0) return;
    const idx = chain.length - 1;
    const step = steps[idx];
    const op = String(chain[idx].op);
    if (!step || !step.output) return;
    const ext = step.binary ? ".bin" : ".txt";
    const name = `decoder-output-${op}${ext}`;
    const blob = new Blob([step.output], {
      type: step.binary ? "application/octet-stream" : "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R150: derive the final-step save button's disabled state so the
  // JSX stays readable + the enablement reconciles on every chain /
  // steps update tick. Enabled only when the chain has at least one
  // step AND that final step produced output (no error, non-empty).
  const lastStep = chain.length > 0 ? steps[chain.length - 1] : undefined;
  const canSaveOutput = Boolean(
    chain.length > 0 && lastStep && lastStep.output && lastStep.output.length > 0,
  );

  useEffect(() => {
    api.decoderApply(input, chain).then(setSteps).catch(() => setSteps([]));
  }, [input, chain]);

  // R438: Alt+Shift+S saves the final chain step's output to a
  // file — keyboard version of R150's toolbar "⬇ Save output"
  // button. Operators iterating on a decode chain who have
  // landed on their target format often want to persist the
  // final bytes without walking to the toolbar. **Letter choice**
  // S = Save. Alt+Shift modifier (not plain Alt+S which could
  // collide with Comparer R391's swap). **Mechanism** reuses
  // the existing `downloadFinalOutput()` helper so the file
  // naming + binary/text handling + Blob+anchor idiom is byte-
  // identical to the toolbar button. **Guards** Alt+Shift only,
  // text-input focus skip, `canSaveOutput` gate (chain not empty
  // AND last step produced output) — mirrors the button's
  // disabled state so the keystroke stays safe to spam without
  // firing a dead download.
  useEffect(() => {
    function onSaveKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "S" && e.key !== "s") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!canSaveOutput) return;
      e.preventDefault();
      downloadFinalOutput();
    }
    document.addEventListener("keydown", onSaveKey);
    return () => document.removeEventListener("keydown", onSaveKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canSaveOutput]);

  // R392: Alt+C clears both the Decoder input and the transform
  // chain in one keystroke — keyboard version of R172's "⌫ Clear
  // input" toolbar button. Operators iterating on sample A then
  // pivoting to sample B need a fast reset to avoid stale state
  // (a loaded chain running against nothing / a loaded sample
  // with no chain). **Letter choice** C = Clear; follows R349
  // History's Alt+C and the broader "C = clear" muscle memory.
  // **Mechanism** mirrors the button's confirm gate: fires the
  // confirm only when there's non-trivial state (input + chain
  // combined > 50 chars) so quick scratch iterations aren't
  // slowed by a dialog, but a real workspace reset gets guarded.
  // **Guards** plain Alt only (no Ctrl/Meta/Shift so Ctrl+Shift+C
  // DevTools stays intact), text-input/textarea/select/contentEditable
  // focus skip. **No-op when empty** silent so the keystroke
  // stays safe to spam.
  useEffect(() => {
    function onClearKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "c" && e.key !== "C") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (input.length === 0 && chain.length === 0) return;
      e.preventDefault();
      const total = input.length + chain.length;
      if (
        total > 50 &&
        !confirm(
          `Clear input (${input.length} chars) and chain (${chain.length} transform${chain.length === 1 ? "" : "s"})?`,
        )
      ) {
        return;
      }
      setInput("");
      setChain([]);
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, chain]);

  function add(op: Transform["op"]) {
    if (isHmacOp(op)) {
      // HMAC steps always carry a key; start empty and let the operator
      // fill it inline. Backend treats "" as a legitimate (if useless)
      // key, so the chain stays runnable while they type.
      setChain([...chain, { op, key: "" } as Transform]);
    } else {
      setChain([...chain, { op } as Transform]);
    }
  }

  function remove(i: number) {
    setChain(chain.filter((_, j) => j !== i));
  }

  function updateKey(i: number, key: string) {
    setChain(
      chain.map((t, j) => {
        if (j !== i) return t;
        if (!isHmacOp(t.op)) return t;
        return { ...t, key } as Transform;
      }),
    );
  }

  async function smartDecode() {
    setSmartBusy(true);
    try {
      const smart = await api.decoderSmart(input, 6);
      if (smart.length === 0) {
        alert("Smart Decode didn't find any additional encoding layers.");
        return;
      }
      // Append the discovered chain to the current one.
      setChain([...chain, ...smart.map((s) => s.transform)]);
    } catch (e) {
      alert(`Smart Decode failed: ${e}`);
    } finally {
      setSmartBusy(false);
    }
  }

  // R836: `hexdump -C` style formatter. 16 bytes per row, 8-digit
  // offset in hex + two 8-byte hex columns + ASCII gutter (non-
  // printable bytes rendered as `.`, matching the Unix tool). Uses
  // TextEncoder to turn the step's string into bytes — because our
  // chain output is a string even for binary steps (the backend
  // base64-rolls binary into a UTF-8 safe representation), this
  // may not be byte-identical to the original binary payload, but
  // for text-encoded strings the mapping is 1:1. Empty input
  // returns the empty string so a fresh pane doesn't render a
  // misleading `00000000  |` row.
  function hexDump(s: string): string {
    if (!s) return "";
    const enc = new TextEncoder();
    const bytes = enc.encode(s);
    if (bytes.length === 0) return "";
    const rows: string[] = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const row = bytes.slice(off, off + 16);
      const hexPieces: string[] = [];
      for (let i = 0; i < 16; i++) {
        if (i < row.length) {
          hexPieces.push(row[i].toString(16).padStart(2, "0"));
        } else {
          hexPieces.push("  ");
        }
        if (i === 7) hexPieces.push(" "); // extra gap mid-row like `hexdump -C`
      }
      const ascii = Array.from(row)
        .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
        .join("");
      rows.push(
        `${off.toString(16).padStart(8, "0")}  ${hexPieces.join(" ")}  |${ascii}|`,
      );
    }
    return rows.join("\n");
  }

  // Validate OPS array covers all groups (dev-time guard).
  void OPS;

  return (
    <div className="panel">
      <div className="toolbar">
        <span>Decoder</span>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          className="primary"
          disabled={smartBusy || !input.trim()}
          onClick={smartDecode}
          title="Auto-detect the encoding and append the decode chain"
        >
          {smartBusy ? "Analysing…" : "Smart Decode"}
        </button>
        <select onChange={(e) => e.target.value && add(e.target.value as Transform["op"])}>
          <option value="">+ add transform</option>
          {OP_GROUPS.map((g) => (
            <optgroup key={g.label} label={g.label}>
              {g.ops.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        <button onClick={() => setChain([])}>Clear chain</button>
        {/* R466: Decoder chain stats badge "📊 N steps · M bytes".   */}
        {/* 5th panel to carry a toolbar "📊" quick-stats chip —      */}
        {/* parallel to R440 Repeater workspace stats, R442 History   */}
        {/* hosts, R451 Collaborator kind-split, R452 Target Issues  */}
        {/* severity-split. Operators iterating on a long decode     */}
        {/* chain (SmartDecode → url_decode → base64 → json_pretty…)  */}
        {/* want a one-glance read of "how deep is this chain + what */}
        {/* did the output grow to" without eyeballing the whole     */}
        {/* right pane. **N steps** = chain.length (number of        */}
        {/* transforms configured). **M bytes** = output length of   */}
        {/* the final step — "did the input shrink or balloon?" is a */}
        {/* useful at-a-glance decode-success signal. **Visibility   */}
        {/* gate** `chain.length > 0` so a fresh empty-chain panel   */}
        {/* doesn't carry the chip. Derived inline from `chain` and  */}
        {/* `steps` state (no new memoization — these are already    */}
        {/* re-rendered on every change via the useEffect on          */}
        {/* [input, chain]).                                          */}
        {chain.length > 0 && (() => {
          const finalBytes = lastStep?.output?.length ?? 0;
          const inputBytes = input.length;
          const delta = finalBytes - inputBytes;
          const deltaStr =
            delta === 0 ? "±0" : delta > 0 ? `+${delta}` : `${delta}`;
          return (
            <span
              className="mono"
              title={`${chain.length} transform${chain.length === 1 ? "" : "s"} in the chain · final step produced ${finalBytes} byte${finalBytes === 1 ? "" : "s"} (input was ${inputBytes}, delta ${deltaStr})`}
              style={{ fontSize: 10.5, color: "var(--text-faint)", marginLeft: 4 }}
            >
              📊
              <span style={{ color: "var(--text)", marginLeft: 4 }}>
                {chain.length} step{chain.length === 1 ? "" : "s"}
              </span>
              <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
              <span style={{ color: finalBytes > 0 ? "var(--accent)" : "var(--text-dim)" }}>
                {finalBytes}B
              </span>
            </span>
          );
        })()}
        {/* R179: Copy chain summary. Operators iterating on a decode  */}
        {/* chain want to document "the one that worked" in a ticket  */}
        {/* or a Jira comment. Format: "op1 → op2 → op3" with HMAC    */}
        {/* keys surfaced inline when present. Reads chain state      */}
        {/* without touching the backend.                              */}
        <button
          disabled={chain.length === 0}
          onClick={() => {
            const summary = chain
              .map((t) => {
                if (isHmacOp(t.op)) {
                  const k = (t as Transform & { key: string }).key;
                  return `${t.op}(key=${k || "<empty>"})`;
                }
                return String(t.op);
              })
              .join(" → ");
            void navigator.clipboard.writeText(summary).catch((e) => alert(`${e}`));
          }}
          title={
            chain.length === 0
              ? "No chain to copy"
              : `Copy "${chain.map((t) => String(t.op)).join(" → ")}" to clipboard`
          }
        >
          📋 Copy chain
        </button>
        {/* ------------------------------------------------------- */}
        {/* R119: Load input from file. Burp's Decoder lets you      */}
        {/* paste in anything; a file-load affordance covers the use */}
        {/* case where the operator wants to decode a captured blob  */}
        {/* (dumped from a scanner / debugger / mobile app) without  */}
        {/* round-tripping through a text editor. Hidden input +     */}
        {/* visible button, same pattern as R118. 10 MB cap because  */}
        {/* the Decoder operates in-memory on strings — anything     */}
        {/* bigger would make the smart-decode loop sluggish and     */}
        {/* probably isn't the right tool anyway.                    */}
        <input
          ref={inputFileRef}
          type="file"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 10 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Decoder caps at 10 MB. Pre-slice before loading.`,
              );
              return;
            }
            if (
              input.trim().length > 0 &&
              !confirm(`Replace current input with ${file.name}?`)
            ) {
              return;
            }
            try {
              const text = await file.text();
              setInput(text);
            } catch (err) {
              alert(`Load file failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => inputFileRef.current?.click()}
          title="Load the input from a file on disk (UTF-8). Replaces the current Input textarea content."
        >
          ⬆ Load input
        </button>
        {/* R213: Load from clipboard — operators coming from a       */}
        {/* terminal grep / cURL dump / log aggregator usually have   */}
        {/* the sample they want to decode already on their           */}
        {/* clipboard; "Load from clipboard" skips the file-save /    */}
        {/* file-upload round-trip. Shows a confirm when the current */}
        {/* input has text so a stale sample isn't silently blown    */}
        {/* away. Reads via `navigator.clipboard.readText` (same      */}
        {/* pattern Comparer R120's stashPaste uses). Silent-on-     */}
        {/* empty-clipboard: an alert tells the operator what's up.  */}
        <button
          onClick={async () => {
            try {
              const text = await navigator.clipboard.readText();
              if (!text) {
                alert("Clipboard is empty or whitespace-only.");
                return;
              }
              if (
                input.trim().length > 0 &&
                !confirm(
                  `Replace current input (${input.length} char${input.length === 1 ? "" : "s"}) with clipboard content (${text.length} char${text.length === 1 ? "" : "s"})?`,
                )
              ) {
                return;
              }
              setInput(text);
            } catch (err) {
              alert(`Load from clipboard failed: ${err}`);
            }
          }}
          title="Load the input from the clipboard. Replaces the current Input textarea content (asks when non-empty)."
        >
          📋 Paste
        </button>
        {/* R172: Clear input + chain in one click. Operators iterating */}
        {/* on sample A then pivoting to sample B need a fast reset.    */}
        {/* Clearing input alone leaves a stale chain running against   */}
        {/* nothing; clearing chain alone leaves a loaded sample. We    */}
        {/* clear both so operators get a true blank slate. Confirms   */}
        {/* on non-trivial state to avoid losing in-progress work.     */}
        <button
          disabled={input.length === 0 && chain.length === 0}
          onClick={() => {
            const total = input.length + chain.length * 100;
            if (
              total > 50 &&
              !confirm(
                `Clear input (${input.length} chars) and chain (${chain.length} transform${chain.length === 1 ? "" : "s"})?`,
              )
            ) {
              return;
            }
            setInput("");
            setChain([]);
          }}
          title={
            input.length === 0 && chain.length === 0
              ? "Nothing to clear"
              : `Clear input (${input.length} chars) + chain (${chain.length} transform${chain.length === 1 ? "" : "s"})`
          }
        >
          ⌫ Clear input
        </button>
        {/* ------------------------------------------------------- */}
        {/* R150: Save output — one-click save of the FINAL step's   */}
        {/* output. The per-step right-click menu offers this too,   */}
        {/* but the toolbar button covers the common end-of-chain    */}
        {/* workflow without forcing a right-click into the preview  */}
        {/* pane. Disabled when there's no chain or the final step   */}
        {/* produced no output (error / empty).                      */}
        <button
          disabled={!canSaveOutput}
          onClick={downloadFinalOutput}
          title={
            canSaveOutput
              ? `Save the final step's output as a file (${lastStep?.binary ? "binary" : "text"})`
              : "No output to save — add at least one transform that produces output"
          }
        >
          ⬇ Save output
        </button>
        {/* R480: "📋 Copy output" — mouse-first mirror of R438        */}
        {/* Alt+Shift+S save-output keyboard, and clipboard-first      */}
        {/* companion to R150's "⬇ Save output" file button. Operators */}
        {/* iterating on a decode chain who want to paste the final    */}
        {/* bytes into a sibling tool (Repeater request body, Jira    */}
        {/* ticket, chat) get a one-click clipboard path without the  */}
        {/* file-system round-trip. **Mechanism** reads the final     */}
        {/* step's output directly from `lastStep.output` (same       */}
        {/* source as R150 Save), uses `copyToClipboard` from         */}
        {/* ../copyAs for the clipboard write. **Disabled gate**      */}
        {/* reuses the same `canSaveOutput` boolean so the two        */}
        {/* buttons share a visibility rhythm — operators always see  */}
        {/* both enabled or both disabled, never a mismatched state.  */}
        {/* **Binary caveat** binary outputs (hash digests, raw       */}
        {/* bytes) copy as their text representation — the clipboard  */}
        {/* only carries strings, so a binary hash renders as its     */}
        {/* hex / base64 display form. For true binary preservation   */}
        {/* operators use the file-save path (R150). Tooltip notes    */}
        {/* this.                                                       */}
        <button
          disabled={!canSaveOutput}
          onClick={async () => {
            if (!canSaveOutput || !lastStep?.output) return;
            try {
              await copyToClipboard(lastStep.output);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            canSaveOutput
              ? `Copy the final step's output (${lastStep?.output?.length ?? 0} ${lastStep?.binary ? "bytes — binary rendered as display text" : "chars"}) to clipboard — mouse-first mirror of Alt+Shift+S file save`
              : "No output to copy — add at least one transform that produces output"
          }
        >
          📋 Copy output
        </button>
        {/* R307: Export chain as JSON — fifth entry in the JSON   */}
        {/* export family (R124 Scope / R280 Settings / R303 M&R / */}
        {/* R306 Repeater tabs / R307 Decoder chain). Operators   */}
        {/* who build a complex decode chain (e.g. url_decode →    */}
        {/* base64_decode → gzip_decode → jwt_decode) want to      */}
        {/* share it with a teammate or save it as a reusable      */}
        {/* preset. Payload is just the current chain array —      */}
        {/* input text is deliberately excluded because an export  */}
        {/* is a transformation recipe, not a specific sample.    */}
        {/* R647: Decoder "📋 Copy chain JSON" — clipboard-only
            version of R307 Export chain. Consistent with the
            cross-panel Copy-as-JSON family (R605 History / R606
            Scanner / R607 Intruder / R611 Target / R612
            Collaborator). Operators scripting a chain into a
            custom detector or sharing in a chat want the JSON
            on the clipboard without the file-save roundtrip.
            Pretty-printed 2-space indent for diff-friendly paste. */}
        {chain.length > 0 && (
          <button
            onClick={() =>
              void copyToClipboard(JSON.stringify(chain, null, 2))
            }
            title={`Copy the current transform chain (${chain.length} step${chain.length === 1 ? "" : "s"}) as a JSON array to clipboard (2-space indent, pretty-printed; same shape as ⬇ Export chain). Great for sharing in chat or scripting into a custom detector.`}
          >
            📋 Copy chain JSON
          </button>
        )}
        {chain.length > 0 && (
          <button
            onClick={() => {
              try {
                const payload = {
                  exported_at_ms: Date.now(),
                  exported_at_iso: new Date().toISOString(),
                  chain,
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
                a.download = `burpfree-decoder-chain-${stamp}.json`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Export the current transform chain (${chain.length} step${chain.length === 1 ? "" : "s"}) as a JSON file. Input text is excluded — this is a recipe, not a sample.`}
          >
            ⬇ Export chain
          </button>
        )}
        {/* R308: Import chain — reciprocal of R307 export. Closes */}
        {/* the round-trip so operators can share decoder recipes  */}
        {/* across machines or teammates. Reads the JSON blob R307 */}
        {/* wrote and swaps the chain state. Confirms pre-fire     */}
        {/* when the current chain is non-empty so a drag-and-drop */}
        {/* mis-pick doesn't overwrite in-progress work. Light     */}
        {/* shape validation — a chain field must be present and   */}
        {/* an array of objects with an `op` string — anything    */}
        {/* else is a mis-pick and we bail with a clear error.    */}
        <input
          ref={importChainFileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 1 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024).toFixed(0)} KB — chain exports are typically <5 KB. Pick a smaller file or confirm this is a chain export.`,
              );
              return;
            }
            if (
              chain.length > 0 &&
              !confirm(
                `Replace the current chain (${chain.length} step${chain.length === 1 ? "" : "s"}) with ${file.name}?`,
              )
            )
              return;
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              const nextChain = Array.isArray(parsed?.chain)
                ? parsed.chain
                : Array.isArray(parsed)
                  ? parsed
                  : null;
              if (
                !nextChain ||
                !nextChain.every(
                  (t: unknown) =>
                    typeof t === "object" &&
                    t !== null &&
                    typeof (t as { op?: unknown }).op === "string",
                )
              ) {
                alert(
                  "Not a chain export — expected { chain: [{op:…}, …] } or a bare [{op:…}, …] array.",
                );
                return;
              }
              setChain(nextChain as Transform[]);
            } catch (err) {
              alert(`Import failed: ${err}`);
            }
          }}
        />
        <button
          onClick={() => importChainFileRef.current?.click()}
          title="Import a transform chain JSON (produced by R307 Export chain) into the composer. Replaces the current chain — asks when non-empty."
        >
          ⬆ Import chain
        </button>
      </div>
      <div style={{ padding: 10 }}>
        <div
          className="form-row"
          style={{ display: "flex", alignItems: "center", gap: 10 }}
        >
          <label style={{ margin: 0 }}>Input</label>
          {/* R836: Mirror Text / Hex toggle on the Input pane — Burp
              Decoder shows this radio on the top input panel too so
              operators pasting hex-escaped sample from a packet
              capture can inspect byte structure before applying any
              transforms. Keyed by the sentinel index `-1`. */}
          <div
            className="decoder-view-toggle"
            role="radiogroup"
            aria-label="Input view mode"
          >
            <button
              type="button"
              className={getPaneView(-1) === "text" ? "active" : ""}
              onClick={() => setPane(-1, "text")}
              role="radio"
              aria-checked={getPaneView(-1) === "text"}
              title="Edit the input as raw text (default)"
            >
              Text
            </button>
            <button
              type="button"
              className={getPaneView(-1) === "hex" ? "active" : ""}
              onClick={() => setPane(-1, "hex")}
              role="radio"
              aria-checked={getPaneView(-1) === "hex"}
              title="Preview the input as a `hexdump -C` style byte grid (read-only; flip back to Text to edit)"
            >
              Hex
            </button>
          </div>
          <span
            className="mono"
            style={{ fontSize: 10.5, color: "var(--text-faint)", marginLeft: "auto" }}
            title={`Input length: ${input.length} chars (${new TextEncoder().encode(input).length} bytes)`}
          >
            {input.length} chars · {new TextEncoder().encode(input).length} B
          </span>
        </div>
        {getPaneView(-1) === "text" ? (
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            style={{ width: "100%", minHeight: 60 }}
          />
        ) : (
          <pre
            className="mono"
            style={{
              width: "100%",
              minHeight: 60,
              margin: 0,
              padding: 8,
              background: "var(--bg-raised)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              fontSize: 11,
              lineHeight: "14px",
              overflow: "auto",
              color: "var(--text)",
            }}
            title="Hex view is read-only — flip to Text to edit the input."
          >
            {hexDump(input)}
          </pre>
        )}
      </div>
      <div style={{ padding: 10, flex: 1, overflow: "auto" }}>
        {chain.length === 0 && (
          <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
            Add a transform from the dropdown — or click <b>Smart Decode</b> to let BurpFree
            detect the encoding layers automatically.
          </div>
        )}
        {chain.map((t, i) => {
          const hmac = isHmacOp(t.op);
          // Narrow the tagged union to read the `key` field.
          const keyValue = hmac ? (t as Transform & { key: string }).key : "";
          const keyMissing = hmac && keyValue.length === 0;
          return (
            <div key={i} style={{ marginBottom: 10 }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  color: "var(--text-dim)",
                  flexWrap: "wrap",
                }}
              >
                <span className="badge">#{i + 1}</span>
                <span className="mono">{t.op}</span>
                {hmac && (
                  <>
                    <span style={{ fontSize: 11 }}>key:</span>
                    <input
                      type="text"
                      value={keyValue}
                      placeholder="shared secret"
                      onChange={(e) => updateKey(i, e.target.value)}
                      style={{ width: 180, fontFamily: "var(--font-mono)" }}
                      title="HMAC key (UTF-8). Empty keys still produce a valid digest but defeat the point."
                    />
                    {keyMissing && (
                      <span style={{ color: "var(--amber)", fontSize: 11 }}>empty key</span>
                    )}
                  </>
                )}
                {/* R836: Burp Decoder's "Text / Hex" radio toggle.
                    Lives inline in the step header next to the op
                    name — same slot Burp uses in the top-left of
                    each output pane. Clicks are no-op when already
                    selected (idempotent). Auto-defaults to Hex for
                    binary-tagged steps (hash digests, raw deflate
                    bytes) so the operator sees structure instead of
                    mojibake. */}
                <div
                  className="decoder-view-toggle"
                  role="radiogroup"
                  aria-label="Pane view mode"
                >
                  <button
                    type="button"
                    className={getPaneView(i) === "text" ? "active" : ""}
                    onClick={() => setPane(i, "text")}
                    role="radio"
                    aria-checked={getPaneView(i) === "text"}
                    title="Render the output as raw text (default for non-binary steps)"
                  >
                    Text
                  </button>
                  <button
                    type="button"
                    className={getPaneView(i) === "hex" ? "active" : ""}
                    onClick={() => setPane(i, "hex")}
                    role="radio"
                    aria-checked={getPaneView(i) === "hex"}
                    title="Render the output as a `hexdump -C` style byte grid (default for binary-flagged steps). Useful for spotting file magic, null-padded strings, UTF-16 BOMs."
                  >
                    Hex
                  </button>
                </div>
                <button onClick={() => remove(i)}>remove</button>
                {steps[i]?.binary && <span className="badge">binary</span>}
                {steps[i]?.error && (
                  <span style={{ color: "var(--red)" }}>{steps[i].error}</span>
                )}
              </div>
              <pre
                className="mono"
                onContextMenu={(e) => {
                  const step = steps[i];
                  if (!step) return;
                  e.preventDefault();
                  setOutMenu({
                    x: e.clientX,
                    y: e.clientY,
                    data: { idx: i, step, op: String(t.op) },
                  });
                }}
                style={{
                  margin: "4px 0 0",
                  padding: 8,
                  background: "var(--bg-raised)",
                  cursor: "context-menu",
                  // R836: narrower letter spacing + smaller font in
                  // Hex mode so the 16-byte row fits in a reasonable
                  // width without horizontal scroll on the typical
                  // Decoder pane. Text mode uses the default.
                  fontSize: getPaneView(i) === "hex" ? 11 : 12,
                  lineHeight: getPaneView(i) === "hex" ? "14px" : "normal",
                }}
              >
                {getPaneView(i) === "hex"
                  ? hexDump(steps[i]?.output ?? "")
                  : (steps[i]?.output ?? "")}
              </pre>
            </div>
          );
        })}
      </div>
      <FloatingMenu
        state={outMenu}
        onClose={() => setOutMenu(null)}
        items={
          outMenu?.data
            ? [
                {
                  label: "Copy output",
                  onClick: () =>
                    void copyToClipboard(outMenu.data!.step.output ?? ""),
                  disabled: !outMenu.data!.step.output,
                },
                {
                  label: "Save output to file",
                  onClick: () =>
                    downloadStepOutput(
                      outMenu.data!.idx,
                      outMenu.data!.step,
                      outMenu.data!.op,
                    ),
                  disabled: !outMenu.data!.step.output,
                },
                { separator: true },
                {
                  label: "Send to Comparer (left)",
                  onClick: () => {
                    sendToComparer(
                      outMenu.data!.step.output ?? "",
                      "",
                      `Decoder #${outMenu.data!.idx + 1} ${outMenu.data!.op}`,
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "comparer" },
                      }),
                    );
                  },
                  disabled: !outMenu.data!.step.output,
                },
                {
                  label: "Send to Comparer (right)",
                  onClick: () => {
                    sendToComparer(
                      "",
                      outMenu.data!.step.output ?? "",
                      `Decoder #${outMenu.data!.idx + 1} ${outMenu.data!.op}`,
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "comparer" },
                      }),
                    );
                  },
                  disabled: !outMenu.data!.step.output,
                },
                { separator: true },
                {
                  label: "Set as new input",
                  onClick: () => {
                    setInput(outMenu.data!.step.output ?? "");
                    setChain([]);
                  },
                  disabled: !outMenu.data!.step.output,
                  hint: "clears chain",
                },
              ]
            : []
        }
      />
    </div>
  );
}
