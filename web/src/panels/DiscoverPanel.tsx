// DiscoverPanel.tsx
//
// A "Getting started" landing page modeled on Burp's Discover tab.
// Each card advertises a BurpFree capability and jumps to the matching
// tab when clicked. Illustrations are inline SVG so the panel has no
// asset dependencies.

type NavTarget =
  | "dashboard" | "target" | "proxy" | "intruder" | "repeater"
  | "sequencer" | "decoder" | "comparer" | "scanner" | "websocket"
  | "logger" | "organizer" | "session" | "extensions" | "collaborator"
  | "mcp" | "settings";

interface Card {
  title: string;
  blurb: string;
  target: NavTarget;
  cta: string;
  art: () => JSX.Element;
}

/** Fire a tab-change request. App.tsx listens for this event. */
function navigate(target: NavTarget) {
  window.dispatchEvent(new CustomEvent("burpfree:navigate", { detail: { target } }));
}

const CARDS: Card[] = [
  {
    title: "Set the target scope",
    blurb: "Choose which hosts and URLs BurpFree should include or ignore so every tool focuses on the right parts of your application.",
    target: "target",
    cta: "Open scope editor",
    art: ScopeArt,
  },
  {
    title: "Map the website",
    blurb: "Browse through your target with a proxy-aware browser and BurpFree assembles the complete site tree — pages, endpoints, params, titles.",
    target: "target",
    cta: "Open site map",
    art: MapArt,
  },
  {
    title: "Repeat requests",
    blurb: "Hand-craft and replay any request through the Repeater with Pretty / Raw / Hex views, an inspector sidebar, and follow-redirect policy.",
    target: "repeater",
    cta: "Open Repeater",
    art: RepeaterArt,
  },
  {
    title: "Fuzz inputs",
    blurb: "Automate request variants with Intruder — Sniper, Battering Ram, Pitchfork, Cluster Bomb — with payload providers and OOB probes.",
    target: "intruder",
    cta: "Open Intruder",
    art: IntruderArt,
  },
  {
    title: "Decode data",
    blurb: "Chain Base64, URL, hex, HTML, gzip, deflate, brotli, Unicode and JWT transforms. Live, reversible, two-way.",
    target: "decoder",
    cta: "Open Decoder",
    art: DecoderArt,
  },
  {
    title: "Compare data",
    blurb: "Diff two requests or responses line-by-line with longest-common-subsequence highlighting to spot subtle server behaviour changes.",
    target: "comparer",
    cta: "Open Comparer",
    art: CompareArt,
  },
  {
    title: "Analyze token randomness",
    blurb: "Collect a sample of session or CSRF tokens and let the Sequencer measure entropy, character-level bias, and transition probabilities.",
    target: "sequencer",
    cta: "Open Sequencer",
    art: SequencerArt,
  },
  {
    title: "Find security issues",
    blurb: "Nine built-in passive detectors plus active probes for XSS, SQLi, open redirect, SSRF, and command injection with Collaborator OOB.",
    target: "scanner",
    cta: "Open Scanner",
    art: ScannerArt,
  },
  {
    title: "Replay WebSockets",
    blurb: "Capture live WebSocket sessions and replay individual frames to probe real-time endpoints without rebuilding the handshake.",
    target: "websocket",
    cta: "Open WebSocket",
    art: WebSocketArt,
  },
  {
    title: "Expose BurpFree to AI",
    blurb: "Launch the Model Context Protocol server over stdio and let an AI client query history, run scans, and check scope through callable tools.",
    target: "mcp",
    cta: "Open MCP",
    art: McpArt,
  },
  {
    title: "Organize your findings",
    blurb: "Collect interesting requests into collections, annotate with notes, and move them around as the engagement progresses.",
    target: "organizer",
    cta: "Open Organizer",
    art: OrganizerArt,
  },
  {
    title: "Extend BurpFree",
    blurb: "Load Rust or Rhai extensions through a trait-based SDK with a permission model, declarative passive rules, and a sandboxed script engine.",
    target: "extensions",
    cta: "Open Extensions",
    art: ExtensionsArt,
  },
];

export function DiscoverPanel() {
  return (
    <div className="discover-root">
      <h1 className="discover-title">Getting started with BurpFree</h1>
      <p className="discover-sub">
        BurpFree is an open, independent web-security testing platform. The cards below point to the
        tools you reach for first on a new engagement.
      </p>
      <div className="discover-grid">
        {CARDS.map((c, i) => (
          <div key={i} className="discover-card">
            <div className="discover-art">{c.art()}</div>
            <h3>{c.title}</h3>
            <p>{c.blurb}</p>
            <button className="discover-cta" onClick={() => navigate(c.target)}>
              {c.cta} →
            </button>
          </div>
        ))}
      </div>
      <div className="discover-footer">
        <span>Keyboard-first: <kbd>Ctrl+K</kbd> command palette, <kbd>Ctrl+1</kbd>..<kbd>9</kbd> jump tabs, <kbd>Ctrl+O</kbd> send-to-Organizer.</span>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- *
 * Inline SVG illustrations — small, static, no external deps.
 * Shared stroke / fill palette comes from CSS variables so they
 * follow the active theme.
 * ---------------------------------------------------------------- */

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 200 100" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
      {children}
    </svg>
  );
}

function ScopeArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="92" rx="4" fill="none" stroke="var(--border)" />
      <text x="10" y="18" fontSize="10" fill="var(--text-faint)">Include in scope</text>
      <rect x="10" y="24" width="180" height="14" fill="var(--bg-elev)" />
      <text x="14" y="34" fontSize="9" fill="var(--accent)">https://example.com/*</text>
      <text x="10" y="54" fontSize="10" fill="var(--text-faint)">Exclude from scope</text>
      <rect x="10" y="60" width="180" height="14" fill="var(--bg-elev)" />
      <text x="14" y="70" fontSize="9" fill="var(--red)">https://example.com/admin/*</text>
      <rect x="10" y="80" width="30" height="10" rx="2" fill="var(--accent)" />
      <text x="25" y="88" fontSize="7" fill="#000" textAnchor="middle">+ Add</text>
    </Frame>
  );
}

function MapArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="60" height="92" fill="none" stroke="var(--border)" />
      <text x="8" y="18" fontSize="9" fill="var(--text)">▾ example.com</text>
      <text x="14" y="30" fontSize="8" fill="var(--text-faint)">▸ /blog</text>
      <text x="14" y="42" fontSize="8" fill="var(--text-faint)">▸ /login</text>
      <text x="14" y="54" fontSize="8" fill="var(--text-faint)">▸ /api</text>
      <text x="14" y="66" fontSize="8" fill="var(--text-faint)">▸ /assets</text>
      <rect x="68" y="4" width="128" height="92" fill="none" stroke="var(--border)" />
      {Array.from({ length: 6 }).map((_, i) => (
        <g key={i} transform={`translate(72 ${10 + i * 14})`}>
          <rect x="0" y="0" width="22" height="10" fill="var(--accent)" opacity="0.3" />
          <text x="2" y="8" fontSize="7" fill="var(--accent)">GET</text>
          <text x="28" y="8" fontSize="7" fill="var(--text-faint)">/path/{i + 1}</text>
          <text x="100" y="8" fontSize="7" fill="var(--green)">200</text>
        </g>
      ))}
    </Frame>
  );
}

function RepeaterArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="92" height="92" fill="none" stroke="var(--border)" />
      <text x="8" y="16" fontSize="9" fill="var(--text-faint)">Request</text>
      <text x="8" y="30" fontSize="8" fill="var(--accent)">POST /login HTTP/1.1</text>
      <text x="8" y="42" fontSize="7" fill="var(--text-faint)">Host: example.com</text>
      <text x="8" y="54" fontSize="7" fill="var(--text-faint)">Content-Type: form</text>
      <text x="8" y="70" fontSize="7" fill="var(--text)">user=admin&amp;pass=…</text>
      <rect x="104" y="4" width="92" height="92" fill="none" stroke="var(--border)" />
      <text x="108" y="16" fontSize="9" fill="var(--text-faint)">Response</text>
      <text x="108" y="30" fontSize="8" fill="var(--green)">HTTP/1.1 302 Found</text>
      <text x="108" y="42" fontSize="7" fill="var(--text-faint)">Location: /dashboard</text>
      <text x="108" y="54" fontSize="7" fill="var(--text-faint)">Set-Cookie: sid=…</text>
      <text x="108" y="80" fontSize="7" fill="var(--accent)">Send →</text>
    </Frame>
  );
}

function IntruderArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="30" fill="none" stroke="var(--border)" />
      <text x="10" y="16" fontSize="8" fill="var(--text-faint)">Target</text>
      <text x="10" y="28" fontSize="8" fill="var(--accent)">GET /api/user?id=§1§</text>
      <rect x="4" y="40" width="192" height="56" fill="none" stroke="var(--border)" />
      {["1","admin","root","test","0"].map((v, i) => (
        <g key={i} transform={`translate(0 ${48 + i * 10})`}>
          <text x="10" y="0" fontSize="7" fill="var(--text-faint)">#{i + 1}</text>
          <text x="28" y="0" fontSize="7" fill="var(--text)">{v}</text>
          <text x="140" y="0" fontSize="7" fill={i === 1 ? "var(--green)" : "var(--text-faint)"}>{i === 1 ? "200" : "404"}</text>
        </g>
      ))}
    </Frame>
  );
}

function DecoderArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="30" fill="none" stroke="var(--border)" />
      <text x="10" y="16" fontSize="8" fill="var(--text-faint)">Input</text>
      <text x="10" y="28" fontSize="8" fill="var(--text)">aGVsbG8gd29ybGQ=</text>
      <text x="100" y="42" fontSize="9" fill="var(--accent)" textAnchor="middle">↓ base64</text>
      <rect x="4" y="48" width="192" height="18" fill="none" stroke="var(--border)" />
      <text x="10" y="60" fontSize="8" fill="var(--green)">hello world</text>
      <text x="100" y="78" fontSize="9" fill="var(--accent)" textAnchor="middle">↓ hex</text>
      <rect x="4" y="82" width="192" height="12" fill="none" stroke="var(--border)" />
      <text x="10" y="91" fontSize="7" fill="var(--text)">68 65 6c 6c 6f 20 77 6f 72 6c 64</text>
    </Frame>
  );
}

function CompareArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="92" height="92" fill="none" stroke="var(--border)" />
      <text x="8" y="18" fontSize="8" fill="var(--text)">GET /a HTTP/1.1</text>
      <text x="8" y="30" fontSize="8" fill="var(--text)">Host: ex.com</text>
      <text x="8" y="42" fontSize="8" fill="var(--red)">User: alice</text>
      <text x="8" y="54" fontSize="8" fill="var(--text)">(empty)</text>
      <rect x="104" y="4" width="92" height="92" fill="none" stroke="var(--border)" />
      <text x="108" y="18" fontSize="8" fill="var(--text)">GET /a HTTP/1.1</text>
      <text x="108" y="30" fontSize="8" fill="var(--text)">Host: ex.com</text>
      <text x="108" y="42" fontSize="8" fill="var(--green)">User: bob</text>
      <text x="108" y="54" fontSize="8" fill="var(--green)">X-Debug: 1</text>
    </Frame>
  );
}

function SequencerArt() {
  return (
    <Frame>
      <polyline fill="none" stroke="var(--accent)" strokeWidth="1.5"
        points="4,80 20,60 36,70 52,40 68,55 84,30 100,45 116,25 132,55 148,20 164,50 180,30 196,60" />
      <text x="100" y="94" fontSize="8" fill="var(--text-faint)" textAnchor="middle">entropy: 7.84 bits / char</text>
    </Frame>
  );
}

function ScannerArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="92" fill="none" stroke="var(--border)" />
      {[
        { label: "Reflected XSS", sev: "high", color: "var(--red)" },
        { label: "SQL error disclosure", sev: "high", color: "var(--red)" },
        { label: "Open redirect", sev: "medium", color: "orange" },
        { label: "Missing CSP header", sev: "low", color: "var(--accent)" },
        { label: "Server banner leak", sev: "info", color: "var(--text-faint)" },
      ].map((f, i) => (
        <g key={i} transform={`translate(0 ${14 + i * 14})`}>
          <circle cx="14" cy="0" r="3" fill={f.color} />
          <text x="24" y="3" fontSize="8" fill="var(--text)">{f.label}</text>
          <text x="160" y="3" fontSize="7" fill={f.color} textAnchor="start">{f.sev}</text>
        </g>
      ))}
    </Frame>
  );
}

function WebSocketArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="92" fill="none" stroke="var(--border)" />
      <text x="10" y="16" fontSize="8" fill="var(--text-faint)">wss://chat.example.com/stream</text>
      {[
        { dir: "→", color: "var(--accent)", msg: '{"op":"subscribe","topic":"orders"}' },
        { dir: "←", color: "var(--green)", msg: '{"ack":true,"id":42}' },
        { dir: "←", color: "var(--green)", msg: '{"order":"abc","total":99}' },
        { dir: "→", color: "var(--accent)", msg: '{"op":"ping"}' },
      ].map((m, i) => (
        <g key={i} transform={`translate(10 ${30 + i * 14})`}>
          <text x="0" y="0" fontSize="9" fill={m.color}>{m.dir}</text>
          <text x="14" y="0" fontSize="7" fill="var(--text)">{m.msg}</text>
        </g>
      ))}
    </Frame>
  );
}

function McpArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="80" height="92" fill="none" stroke="var(--border)" />
      <text x="8" y="16" fontSize="8" fill="var(--text-faint)">AI client</text>
      <text x="44" y="52" fontSize="9" fill="var(--text)" textAnchor="middle">◆ Claude</text>
      <text x="44" y="66" fontSize="7" fill="var(--text-faint)" textAnchor="middle">Cline, Codex…</text>
      <path d="M 86 50 L 112 50" stroke="var(--accent)" strokeWidth="1.5" />
      <text x="99" y="46" fontSize="7" fill="var(--accent)" textAnchor="middle">stdio</text>
      <text x="99" y="60" fontSize="7" fill="var(--text-faint)" textAnchor="middle">JSON-RPC</text>
      <rect x="114" y="4" width="82" height="92" fill="none" stroke="var(--border)" />
      <text x="118" y="16" fontSize="8" fill="var(--text-faint)">burpfree-mcp</text>
      {["project_info","history_list","scan_passive","findings_list","scope_check"].map((t, i) => (
        <text key={i} x="120" y={30 + i * 11} fontSize="7" fill="var(--accent)">• {t}</text>
      ))}
    </Frame>
  );
}

function OrganizerArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="60" height="92" fill="none" stroke="var(--border)" />
      <text x="8" y="16" fontSize="8" fill="var(--text)">All items</text>
      <text x="8" y="30" fontSize="8" fill="var(--accent)">◆ Inbox 3</text>
      <text x="8" y="46" fontSize="8" fill="var(--text-faint)">▸ Auth</text>
      <text x="8" y="60" fontSize="8" fill="var(--text-faint)">▸ API</text>
      <text x="8" y="74" fontSize="8" fill="var(--text-faint)">▸ Static</text>
      <rect x="68" y="4" width="128" height="92" fill="none" stroke="var(--border)" />
      {["POST /login — 200","GET /api/me — 200","GET /admin — 403"].map((row, i) => (
        <text key={i} x="74" y={22 + i * 18} fontSize="8" fill="var(--text)">{row}</text>
      ))}
    </Frame>
  );
}

function ExtensionsArt() {
  return (
    <Frame>
      <rect x="4" y="4" width="192" height="92" fill="none" stroke="var(--border)" />
      {["strip-powered-by","host-tagger","secrets-leak-detector","custom-rhai-script"].map((e, i) => (
        <g key={i} transform={`translate(0 ${18 + i * 18})`}>
          <rect x="10" y="-6" width="6" height="12" fill={i < 3 ? "var(--green)" : "var(--text-faint)"} />
          <text x="22" y="3" fontSize="9" fill="var(--text)">{e}</text>
          <text x="160" y="3" fontSize="7" fill={i < 3 ? "var(--green)" : "var(--text-faint)"}>
            {i < 3 ? "loaded" : "paused"}
          </text>
        </g>
      ))}
    </Frame>
  );
}
