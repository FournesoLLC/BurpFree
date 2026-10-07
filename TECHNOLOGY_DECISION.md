# Technology decision

Status: **accepted**, 2026-10-01. Stack: **Rust 1.x + Tauri 2.0**.

## Problem

Build a professional, Burp-class web-security testing workstation that
must handle 100k–1M+ captured requests, large bodies, HTTPS MITM,
WebSockets, long-running proxy sessions, dense professional desktop
workflows, and an extension system — on Windows / macOS / Linux.

## Options evaluated

| Stack | Proxy / MITM | UI | Extensions | Packaging | Verdict |
| --- | --- | --- | --- | --- | --- |
| **Rust + Tauri 2.0 + hudsucker** | `hudsucker` crate already solves HTTP/1.1, HTTP/2, HTTPS MITM, WebSocket, decompression. `hyper`, `rustls`, `tokio` are production-grade and used by hyperscalers. | Tauri 2.0: native desktop shell with WebView2/WebKit + web UI (React + TypeScript + Vite). Dense dock-widget / virtualized-table UX via `tanstack-table`, Monaco editors, `allotment` panes. | WASM plug-ins via `wasmtime` (sandboxed by default); native plug-ins via dynamic crates. | Native installer per OS, 3–15 MB bundle, sub-second cold start. | **Chosen** |
| Go 1.23 + embedded web UI | `net/http` + custom MITM. Mature but we hand-roll the stack hudsucker already provides. | Localhost web app; no native desktop shell. | WASM via `wazero`. | Single binary; no desktop shell. | Second place. Rejected: hudsucker gives Rust a decisive proxy headstart; Tauri delivers a true desktop app. |
| Python 3.14 + PySide6 + asyncio | mitmproxy-grade with `cryptography` + `h11`. Known performance ceiling for large sessions (GIL, interpretation). | Qt dock widgets. | Natural (Python modules). | PyInstaller. | Rejected: performance for 1M-request target. |
| TypeScript + Electron | Node TLS MITM is less battle-tested than Rust or Go. | Rich. | npm. | electron-builder, 100–250 MB bundles. | Rejected: memory footprint for workstation tools. |
| Java + Swing/JavaFX | What Burp itself uses. | Dated UI. | OSGi/JPMS. | jpackage. | Rejected on principle (deliberate separation from Burp's implementation stack) and UX ceiling. |

## Rationale

1. **The MITM is already written.** `hudsucker` is a mature, actively
   maintained Rust MITM proxy library covering HTTP/1.1, HTTP/2, HTTPS,
   WebSocket upgrade and frame interception, decompression helpers, and
   `rcgen`/OpenSSL CA factories. Picking it collapses what would be
   weeks of HTTP-plumbing in another language.
2. **The ecosystem has validated the choice.** Caido, Sniper,
   int3rceptor and MitmRust — the credible modern Burp-alternatives —
   are all Rust. Caido in particular is Rust + Tauri. Content was
   rephrased for compliance with licensing.
3. **No GC pauses.** Burp-class projects accumulate huge histories and
   stream large bodies. Rust's zero-cost abstractions and no-GC
   runtime fit this workload without tuning.
4. **Compile-time safety for attacker-controlled input.** The proxy
   routinely parses malformed HTTP/WebSocket frames and malicious
   bodies. Rust eliminates whole classes of memory-safety bugs that a
   security tool must not have.
5. **Tauri 2.0 ships a real desktop app.** Native window chrome,
   installer, system integration, auto-update seam, 3–15 MB bundles,
   sub-second cold start — all without us writing per-OS shell code.
6. **Toolchain:** installed in-session via `rustup` with the
   `x86_64-pc-windows-gnu` toolchain so no MSVC Build Tools dependency
   on Windows. Linux and macOS use the native toolchain.

## Consequences

* **Workspace layout.** A Cargo workspace with the following crates:
  * `burpfree-core` — traffic model, headers, scope, event bus.
  * `burpfree-codec` — URL/base64/base64url/hex/HTML/JWT codecs,
    compression helpers.
  * `burpfree-ca` — root CA + leaf cert factory on top of `rcgen`.
  * `burpfree-proxy` — proxy orchestrator; wraps `hudsucker` with our
    interceptor, match/replace, scope and extension hooks.
  * `burpfree-storage` — SQLite (`rusqlite` bundled) + content-addressed
    blob store.
  * `burpfree-engines` — Repeater, Intruder, Scanner (passive +
    active), Site map, Session cookie jar, Decoder, Comparer,
    Sequencer-style token analysis.
  * `burpfree-extensions` — SDK + `wasmtime` sandbox + loader.
  * `burpfree-cli` — headless CLI binary.
  * `burpfree-tauri` — Tauri 2.0 app binary; depends on all of the
    above, exposes commands and events to the UI.
* **Frontend.** `web/` is a Vite + React + TypeScript app bundled by
  Tauri at build time.
* **Threading.** The async runtime is `tokio` (multi-thread). Tauri
  commands are `async fn` dispatched off the UI thread. Progress is
  emitted back to the UI via Tauri events.
* **Testing.** Pure Rust `cargo test` for every library crate; a
  loopback end-to-end test spins up the proxy against `hyper`'s test
  server.
* **Storage.** `rusqlite` is used with the `bundled` feature so no
  external SQLite install is required. Large bodies are
  content-addressed blobs on disk under `project/blobs/<ab>/<rest>`.
* **Platform availability.** Tauri targets Windows (WebView2), macOS
  (WKWebView), Linux (WebKitGTK).
