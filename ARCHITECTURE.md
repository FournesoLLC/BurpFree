# BurpFree — Architecture

BurpFree is an open, independent desktop web-security testing
workstation that provides the major workflows practitioners expect from
a professional intercepting-proxy suite: Proxy with TLS MITM, HTTP
History, Repeater, Intruder-style automation, Target/Site Map, Passive
and Active scanners (incl. Out-of-Band callbacks), WebSocket
inspection, Match/Replace with scripting, Session handling, Decoder,
Comparer, Sequencer-style token analysis, Organizer, Logger, Reporting
(HTML/JSON/SARIF), API-definition importers (OpenAPI 3, Postman v2.1),
a documented Extension SDK, a sandboxed Rhai scripting engine, and a
CI-friendly command-line.

BurpFree is **not** a port, fork, or clone of Burp Suite source,
assets, or branding. It is an original implementation of the same
public workflow concepts, written on top of standard HTTP/networking
primitives.

## Technology (see `TECHNOLOGY_DECISION.md`)

* **Backend language:** Rust 1.75+ (GNU toolchain on Windows, MSVC/
  native on macOS/Linux).
* **Async runtime:** Tokio (multi-thread).
* **TLS:** `rustls` + `rcgen` CA + per-host leaf certs.
* **Storage:** `rusqlite` (bundled) + content-addressed blob directory.
* **Scripting:** `rhai` sandboxed with resource caps.
* **UI delivery:** Tauri 2 + React 18 + TypeScript + Vite.
* **Testing:** stdlib + tokio + per-crate integration tests.

## Workspace layout

```
Cargo.toml                — workspace root
crates/
  burpfree-core/          — Request/Response/Transaction model, Headers,
                            IDs, scope, event bus.
  burpfree-codec/         — URL/Base64/Hex/HTML/JWT codecs,
                            compression helpers, Decoder chain engine.
  burpfree-ca/            — Root CA + per-host leaf cert factory (rcgen).
  burpfree-storage/       — SQLite index (history, findings, organizer,
                            websocket sessions) + content-addressed
                            blob store; schema migration.
  burpfree-proxy/         — HTTP/1.1 + HTTPS MITM proxy, interceptor,
                            match/replace (with scripted predicates),
                            direct / HTTP / SOCKS5 upstream, WS frame
                            parser.
  burpfree-engines/       — Repeater, Intruder (sniper/BR/pitchfork/CB),
                            passive & active scanners (incl. OOB probes),
                            site map, session jar, decoder/comparer/
                            sequencer, HTTP client used by all engines.
  burpfree-oob/           — Collaborator-style HTTP + optional DNS
                            listener, unique correlation ids, bounded
                            interaction buffer, poll_for API, payload
                            builders (SSRF/CmdInj/DNS/Log4Shell).
  burpfree-api/           — API-definition importers: OpenAPI 3.x
                            (JSON + YAML) and Postman Collection v2.1.
  burpfree-report/        — Report writers: HTML, JSON, SARIF 2.1.0.
  burpfree-script/        — Sandboxed Rhai scripting engine with
                            configurable limits (ops / strings / arrays /
                            maps / depth / wall-clock), req/resp maps,
                            header()/has_header()/matches_regex() helpers.
  burpfree-extensions/    — Extension SDK, permission model, in-process
                            registry, loader, built-in reference
                            extensions.
  burpfree-cli/           — Headless CLI binary `burpfree`
                            (project, proxy, send, history, scan,
                            report, ci, import, codec, ca).
  burpfree-tauri/         — Tauri 2 desktop shell: bootstrap,
                            auto-start proxy, event-bus ring buffer,
                            browser launcher, Tauri commands used by
                            the UI.

web/                      — React + TypeScript + Vite frontend sources.
examples/extensions/      — Reference extension code.
scripts/                  — PowerShell helpers (dev, release build,
                            CI smoke, import smoke).
```

## Thread / task model

```
    GUI window (Tauri / WebView2 / React)
            │  invoke(…)
            ▼
   ┌──────────────────────────────┐
   │ Tauri command dispatcher     │
   └───────────┬──────────────────┘
               │ async
               ▼
   ┌──────────────────────────────┐
   │ Tokio multi-thread runtime   │
   └──┬──────────────────────┬────┘
      ▼                      ▼
  ProxyServer         Scanner / Intruder / Repeater
      │                      │
      ▼                      ▼
  EventBus (broadcast) ─────────▶ Logger ring buffer ───▶ UI poll
      │
      ▼
  TrafficSink ─▶ HistoryStore + BlobStore + SiteMap + Extensions
```

Everything the GUI shows is a snapshot of these engines — the Rust
side is the source of truth, the UI only visualises it.

## Request lifecycle

```
Browser ──▶ Proxy acceptor
            │
            ├─ Loop-guard: refuse requests whose target is a listener  (421)
            ├─ parse ──▶ Request
            │   │
            │   ├─ MatchReplace (request rules, inc. scripted predicates)
            │   ├─ Scope.tag(request)
            │   ├─ Interceptor (if intercept on)
            │   └─ Extensions.OnRequest()
            │
            ├─ Dial upstream (direct / HTTP-proxy / SOCKS5)
            │
            ├─ Read response (streaming) ──▶ Response
            │   │
            │   ├─ Transparent decompression (bomb-capped)
            │   ├─ MatchReplace (response rules)
            │   ├─ Interceptor (if intercept on)
            │   ├─ Extensions.OnResponse()
            │   ├─ EventBus.Publish(TrafficEvent)
            │   │        ├──▶ HistoryStore.insert
            │   │        ├──▶ SiteMap.observe
            │   │        ├──▶ PassiveScanner enqueue (optional)
            │   │        ├──▶ Logger ring buffer (always)
            │   │        └──▶ UI (via Tauri events on request)
            │   └─▶ Write to client
            ▼
         Browser
```

## OOB (Collaborator-style) flow

```
Scanner builds payload with a unique correlation id → injects into param
                                                           │
                                           ┌───────────────▼───────────────┐
                                           │ Vulnerable target             │
                                           │ (SSRF, blind cmd injection,   │
                                           │  Log4Shell, blind SQLi, …)    │
                                           └───────────────┬───────────────┘
                                                           ▼
                                               Outbound HTTP / DNS probe
                                                           │
                                                           ▼
                                     burpfree-oob HTTP+DNS listener
                                                           │
                                                           ▼
                                   Interaction record (correlation_id ↔ probe)
                                                           │
                                                           ▼
                            Scanner poll_for() ─▶ Finding emitted (high confidence)
```

## Security boundaries

* The root CA private key lives under `<project>/ca/ca-key.pem` with
  `0600` perms on Unix (best-effort ACLs on Windows).
* The proxy refuses to forward requests whose target resolves to one of
  its own listeners (prevents feedback loops).
* Transparent decompression respects a configurable ratio bound to
  resist decompression bombs.
* Active scanning is scope-gated at submit time and re-checked per
  request.
* Rhai scripts run with `max_operations`, string/array/map ceilings,
  expression-depth caps and a wall-clock timeout; no filesystem /
  network / shell access is registered.
* Extensions declare required permissions in a manifest. The registry
  enforces grants at every callback boundary.
* Browser launcher spawns Chromium with an **isolated per-launch
  `--user-data-dir`** so proxy settings don't leak into the user's
  normal browser profile.
* The HTTP API binds to `127.0.0.1` by default. The desktop shell runs
  entirely in-process through Tauri IPC — nothing listens on the
  network for the UI.
* Response HTML / JavaScript in the UI is rendered as source text; the
  frontend never evaluates target scripts.

## Reporting

The reporting crate emits three formats:

* **HTML** — self-contained single-file report with severity cards.
* **JSON** — the raw `StoredFinding[]`, ready for machine consumers.
* **SARIF 2.1.0** — accepted by GitHub Code Scanning, Azure DevOps,
  GitLab SAST, and SonarQube.

CI gating is done by `burpfree ci scan --project P --fail-on medium
--report-format sarif --out findings.sarif`. The CLI exits with status
`1` when any finding is at or above the threshold.

## Compatibility matrix

Lives in `README.md` and `COMPATIBILITY.md`.
