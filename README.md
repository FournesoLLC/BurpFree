# BurpFree

An open, independent **desktop web-security testing application**
written in **Rust** with a **Tauri 2 / React / TypeScript** UI.

BurpFree covers the major workflows practitioners expect from a
professional intercepting-proxy suite: Proxy with TLS MITM, HTTP
History, Repeater, Intruder-style automation, Target / Site Map,
Passive and Active scanners (including Out-of-Band callbacks),
WebSocket inspection, Match/Replace with scripting, Session handling,
Decoder, Comparer, Sequencer-style token analysis, Organizer, Logger,
API-definition importers (OpenAPI 3, Postman v2.1), reporting
(HTML / JSON / SARIF 2.1.0), a CI-friendly command-line, a documented
Extension SDK, and a sandboxed Rhai scripting engine.

BurpFree is **not** a port, fork or clone of Burp Suite source, assets,
or branding. See `TECHNOLOGY_DECISION.md`, `ARCHITECTURE.md`, and
`COMPATIBILITY.md` for the design.

## Repository layout

```
Cargo.toml                — workspace root
crates/
  burpfree-core/          — Request/Response/Transaction model, Headers,
                            scope, event bus, IDs.
  burpfree-codec/         — URL/Base64/Hex/HTML/JWT codecs,
                            compression helpers, Decoder chain.
  burpfree-ca/            — Root CA + per-host leaf cert factory.
  burpfree-storage/       — SQLite index (history, findings, organizer,
                            ws sessions) + content-addressed blob store.
  burpfree-proxy/         — HTTP/1.1 + HTTPS MITM proxy, interceptor,
                            match/replace with scripted predicates,
                            direct/HTTP/SOCKS5 upstream, WS frame parser.
  burpfree-engines/       — Repeater, Intruder, passive + active
                            scanner (incl. OOB probes), site map,
                            session jar, decoder/comparer/sequencer.
  burpfree-oob/           — Collaborator-style HTTP+DNS listener,
                            unique interaction ids, payload builders.
  burpfree-api/           — OpenAPI 3.x + Postman v2.1 importers.
  burpfree-report/        — HTML + JSON + SARIF 2.1.0 report writers.
  burpfree-script/        — Sandboxed Rhai scripting (resource caps).
  burpfree-extensions/    — Extension SDK, permission model, loader.
  burpfree-cli/           — Headless CLI `burpfree`.
  burpfree-tauri/         — Tauri 2 desktop shell.

web/                      — React + TypeScript + Vite UI.
examples/extensions/      — Reference extension code.
scripts/                  — PowerShell dev / release / smoke scripts.
```

## Install prerequisites

* **Rust toolchain** (`rustup`, stable channel).
  * Windows users with the GNU toolchain: install `mingw-w64` (WinLibs)
    and overlay its `dlltool.exe` into
    `~/.rustup/toolchains/*/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/`
    (the self-contained version can't create import libs for a few
    system DLLs). See `scripts/build-release.ps1` for the pattern.
* **Node 18+** (for the Vite frontend).
* **Linux:** `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`.
* **Windows:** Microsoft Edge WebView2 Runtime (ships with modern
  Windows).

## Build

```powershell
# Dev launch (vite dev server + Tauri attached):
pwsh -ExecutionPolicy Bypass -File .\scripts\dev.ps1

# Release build (single executable with embedded frontend):
pwsh -ExecutionPolicy Bypass -File .\scripts\build-release.ps1

# Or manually:
npm --prefix web install
npm --prefix web run build
cargo build --workspace --release
```

Binaries end up under `target/debug/` or `target/release/`:
* `burpfree.exe` — headless CLI.
* `burpfree-tauri.exe` — desktop app.

## Desktop app

On first launch the desktop app automatically:

1. Creates a project at `%LOCALAPPDATA%\BurpFree\default-project` (or
   the OS equivalent).
2. Generates a root CA under `<project>/ca/`.
3. Starts the intercepting proxy on `127.0.0.1:8080`.

The top bar has an **"Open browser"** button that spawns a Chromium-
flavoured browser with `--proxy-server` and an isolated profile dir,
so you can start intercepting without touching your main browser's
settings. HTTPS still needs the project's CA — export it from
**Settings → Root CA → Export CA (PEM)** and install it in the trust
store (per-browser or system).

Main workflow tabs: `Dashboard · Target · Proxy · Intruder · Repeater ·
Sequencer · Decoder · Comparer · Scanner · Logger · Organizer ·
Extensions · Settings`. Each tool with sub-tools (Proxy, Target) has
inline sub-tabs, matching the Burp-style workflow.

## Headless CLI

```powershell
burpfree project new .\MyAssessment
burpfree proxy  --project .\MyAssessment --listen 127.0.0.1:8080
burpfree ca     export --project .\MyAssessment --out burpfree-ca.pem
burpfree history --project .\MyAssessment list --limit 20
burpfree scan   passive --project .\MyAssessment --save
burpfree send   https://example.com/ -H "User-Agent: BurpFree"
burpfree codec  base64-encode "hello world"
burpfree import --project .\MyAssessment .\openapi.yaml
burpfree report --project .\MyAssessment --format html --out report.html
burpfree ci scan --project .\MyAssessment --fail-on medium \
                 --report-format sarif --out findings.sarif
```

`ci scan` exits with status **1** when any finding is at or above
`--fail-on` (`info|low|medium|high|critical`) and emits the chosen
report alongside, so it can gate CI pipelines directly.

## Project layout on disk

```
MyAssessment/
  config.json        # proxy listeners, scope, upstream, limits
  extensions.json    # which built-in extensions to load
  ca/
    ca-cert.pem
    ca-key.pem       # 0600 on Unix (best-effort ACLs on Windows)
    certs/<host>.pem # cached leaf certs
  blobs/<ab>/<rest>  # content-addressed body storage
  history.db         # SQLite index: transactions, findings, organizer,
                     # ws sessions, ws messages
  repeater.json      # Repeater tabs
  intruder.json      # Intruder jobs
  log/               # rotating logs
```

## Compatibility matrix

See `COMPATIBILITY.md` for the full matrix. Highlights:

* **HTTP/1.1 proxy, HTTPS MITM, interception, match/replace** — ✅
* **Repeater, Intruder (all 4 attack modes)** — ✅
* **Passive + active scanner incl. OOB callbacks** — ✅
* **Site map, scope, cookie jar, decoder, comparer, sequencer** — ✅
* **OpenAPI / Postman import** — ✅
* **HTML / JSON / SARIF reports + CI threshold command** — ✅
* **Logger, Organizer, browser launch, extensions** — ✅
* **Sandboxed Rhai scripting (match/replace predicates)** — ✅
* **HTTP/2 proxy, embedded Chromium, enterprise/RBAC, agentic AI** — 🔲

## Tests

```powershell
cargo test --workspace --exclude burpfree-tauri
```

The desktop crate is excluded from the standard `--workspace` test run
because its binary target requires the full Tauri build; the engines,
proxy, storage, oob, api, codec, report, script, and extension crates
all have their own unit and integration tests, and the engines crate
ships an end-to-end integration test that spins up a proxy against a
loopback origin and runs passive scanning on the recorded transaction.

## Documentation

* `ARCHITECTURE.md` — module map, request lifecycle, trust boundaries.
* `TECHNOLOGY_DECISION.md` — rationale for Rust + Tauri.
* `COMPATIBILITY.md` — detailed workflow matrix.
* `examples/extensions/README.md` — writing extensions.

## License

Apache-2.0.
