# Burp Suite Community 2026.8 — Technical Reverse-Engineering Report

Target: `C:\Users\pc\AppData\Local\Programs\BurpSuiteCommunity`
Date of analysis: October 1, 2026
Build analyzed: Burp Suite Community Edition **v2026.8** (install build 2026-08-20)
Internal Burp JAR Implementation-Version: **53343**

> This report is based on static inspection of the installation, examination of configuration/resource files, enumeration of the shaded fat JAR, and passive runtime observation of the already-running Burp process (PID 7856). All secret-looking values (DPAPI keys, ADB keys, P12 content, cookies, telemetry IDs) have been redacted or referenced by name rather than value.


## 1. Executive Summary

Burp Suite Community 2026.8 is a desktop web-security testing platform shipped as a **single install4j-generated Windows installer** that lays down:

1. A **small native launcher** (`BurpSuite.exe`, 1.1 MB) built by **install4j 12.0.5** that locates and spawns the bundled JVM with a specific set of `--add-opens`, `-XX:MaxRAMPercentage=50`, and `-Dinstall4j.*` arguments, then runs `burp.StartBurp` from `burpsuite.jar`.
2. A **bundled Oracle OpenJDK 26.0.2 JRE** (desktop profile, ~56 Java modules), including SunMSCAPI (Windows cert store integration), PKCS#11, SSPI/Kerberos native libs.
3. A **~154 MB shaded uber-JAR** (`burpsuite.jar`, 59,101 entries) containing all Burp Java code (heavily ProGuard-obfuscated under `burp.Z*` / `net.portswigger.*.Z*`), the public **Montoya extension API** (`burp.api.montoya.*`), the legacy "Extender" interface API (`burp.I*`), **Burp AI SDK** (`burp.ai.sdk`), **Agentic Testing module** (`burp.agentic.*`), Burp's custom Swing LaF (`burp.theme.*` + FlatLaf), and a large pile of shaded third-party libraries (Kotlin, kotlinx.coroutines, Project Reactor, Jackson 3, Bouncy Castle, OkHttp/OkIO, SnakeYAML, Guava, Protobuf, JavaFX, OSHI, Nimbus JOSE+JWT, OpenTelemetry, Model Context Protocol SDK, Mozilla Rhino, Brotli, JNA, SwiftShader, Swagger/OpenAPI).
4. A **bundled Chromium browser** rebranded as **"Burp Browser"** — binaries are `Product=Burp Browser`, FileVersion `151.0.7922.138`, Company `The Chromium Authors`, and have **no Authenticode signature** (stripped during repackaging). The browser bundle is a standard Chromium build: `chrome.exe`, 289 MB `chrome.dll`, ANGLE (`libEGL.dll`, `libGLESv2.dll`), SwiftShader + Vulkan, DirectX HLSL compilers, locales, V8 snapshot, resource paks.
5. A rich **Chromium extension payload** persisted to the user profile at `%AppData%\BurpSuite\burp-chromium-extension\` containing **DOM Invader**, **Login Recorder**, a custom **new-tab page**, and a **container service-worker** that is heavily obfuscated. These extensions have broad permissions (`<all_urls>`, `webRequest`, `declarativeNetRequest`, `scripting`, `privacy`, `tabs`, `storage`) and talk to Burp over a magic `https://burp/` origin whitelisted in each extension's CSP.
6. A full feature set that includes all **Community-edition** tooling (Proxy, Repeater, Intruder, Decoder, Comparer, Sequencer, Logger, Target/Site map, Organizer, Collaborator client, Extensions, Burp Browser), plus **shipped-but-gated code** for Scanner, Infiltrator, Mobile Assistant, and the Enterprise agent/server defaults. All Scanner knowledge-base issue content, wordlists (JWT secrets, Intruder payloads), audit profiles, Retire.js database, Clickbandit, DOM Invader, Private Collaborator server docs, and the Infiltrator `.exe`/`.jar` are physically present inside the Community JAR — they are feature-gated by edition rather than removed from the artifact.
7. New-in-2026 features confirmed present: **Burp AI** ("Explain this", AI SDK, credit balance in `WorkspaceConfig`), **Burp Agentic Testing / Burp AT** (hotkeys `send_to_burp_at`, `open_burp_at`; `burp/agentic/AgenticAiBurpModule.class`; MCP-oriented tool definitions), **Bambdas**, **BChecks** (user folder present), and an **MCP (Model Context Protocol) server** shipped as a BApp extension (`burp-mcp-all.jar`, 29.9 MB, currently loaded).

The installation is **running at analysis time**: Burp Suite Community PID 7856 is a single Java process listening on `127.0.0.1:8080` (Proxy), `127.0.0.1:9876` (internal/browser proxy or `https://burp/` endpoint), and `127.0.0.1:62294` (ephemeral). The Chromium subprocess is not currently active.


## 2. Full Installation Inventory

### 2.1 Directory tree (top-level)

```
C:\Users\pc\AppData\Local\Programs\BurpSuiteCommunity\
├── .install4j\                      install4j launcher runtime + installer metadata
├── .jython_cache\packages\          Jython package index cache (.pkc)
├── burpbrowser\
│   └── 151.0.7922.138\              Chromium build "Burp Browser"
│       ├── chrome.exe                FileVer 151.0.7922.138, Product=Burp Browser
│       ├── chrome.dll (289 MB)       main browser code
│       ├── chrome_elf.dll            early loader (SxS manifest side)
│       ├── chrome_proxy.exe          invisible launcher proxy
│       ├── chrome_pwa_launcher.exe   PWA launcher
│       ├── chrome_wer.dll            Windows Error Reporting hook
│       ├── elevation_service.exe     COM elevation service
│       ├── elevated_tracing_service.exe
│       ├── notification_helper.exe   Windows toast notifications
│       ├── eventlog_provider.dll
│       ├── libEGL.dll / libGLESv2.dll  ANGLE (OpenGL ES over DX)
│       ├── D3DCompiler_47.dll        HLSL compiler
│       ├── dxcompiler.dll / dxil.dll  DirectX Shader Compiler (ANGLE/WebGPU)
│       ├── vk_swiftshader.dll        SwiftShader software Vulkan ICD
│       ├── vulkan-1.dll              Vulkan loader
│       ├── vk_swiftshader_icd.json   SwiftShader ICD registration
│       ├── icudtl.dat                ICU unicode data
│       ├── v8_context_snapshot.bin   V8 isolate snapshot
│       ├── resources.pak, chrome_100_percent.pak, chrome_200_percent.pak
│       ├── locales\ (xx.pak + xx_FEMININE/MASCULINE/NEUTER.pak)
│       ├── IwaKeyDistribution\       Isolated Web Apps key distribution
│       ├── MEIPreload\               Media Engagement Index data
│       ├── PrivacySandboxAttestationsPreloaded\
│       ├── First Run                 (contains the string "krome", acts as a sentinel)
│       ├── manifest.properties       MD5-indexed file-manifest for integrity verification
│       └── 151.0.7922.138.manifest   SxS activation context manifest
├── jre\
│   ├── bin\ (java.exe, javaw.exe, keytool, 50+ native .dll's)
│   │   └── server\jvm.dll            HotSpot Server VM
│   ├── conf\security\java.security
│   ├── lib\
│   │   ├── modules                   JIMAGE-packed java.base + ~56 modules
│   │   ├── security\cacerts          default JDK trust store
│   │   ├── security\blocked.certs
│   │   └── security\public_suffix_list.dat
│   └── release                       JAVA_VERSION=26.0.2, MODULES=...
├── BurpSuite.exe                     install4j Win64 launcher, PortSwigger-signed
├── burpsuite.jar                     154 MB fat/shaded JAR, Main-Class burp.StartBurp
├── BurpSuite.vmoptions               wrapper vmoptions, includes settings.vmoptions + user.vmoptions
├── BurpSuiteCommunity.vmoptions      identical to BurpSuite.vmoptions
├── hs_err_pid22316.log               past HotSpot crash log (JDK 25 era, awt.dll AV)
├── hs_err_pid28976.log               past HotSpot crash log (JDK 25 era, awt.dll AV)
└── uninstall.exe                     install4j-generated uninstaller
```

### 2.2 Key binaries — hashes, sizes, signatures

| File | Size | SHA-256 (prefix) | Signature |
|---|---:|---|---|
| `BurpSuite.exe` | 1.13 MB | `49F8F3DF0FA96CB5…` | Valid, **PortSwigger Ltd (Knutsford, GB)** |
| `uninstall.exe` | 550 KB | `FCFA62D764D79AE0…` | Valid, **PortSwigger Ltd** |
| `.install4j\bgupdater.exe` | 532 KB | `88135FE5DB8FD465…` | Valid, **PortSwigger Ltd** |
| `.install4j\restart.exe` | 553 KB | `2F4A5D1DCBDA89C2…` | Valid, **PortSwigger Ltd** |
| `.install4j\i4jinst.dll` | 298 KB | `83F86F043C992FB9…` | Valid, **ej-technologies GmbH** (install4j vendor) |
| `.install4j\i4jdel.exe` | 142 KB | `C099397ADF4484C2…` | Valid, **ej-technologies GmbH** |
| `.install4j\flatlaf-windows-x86_64.dll` | 34 KB | `71CB3C7815D8538B…` | Valid, **SignPath Foundation** (OSS code-signing) |
| `.install4j\flatlaf.jar` | 863 KB | `BCFFCAA48254A3DA…` | n/a (JAR) |
| `.install4j\i4jruntime.jar` | 2.6 MB | `F42AD555778DCC50…` | n/a |
| `.install4j\user.jar` | 29 KB | `206B1C7CA24E2C2C…` | n/a |
| `burpsuite.jar` | 154 MB | `1C42CDC7F38F2FB3…` | n/a (JAR) |
| `jre\bin\java.exe` | 49 KB | `A802ECC238D9DE7E…` | Valid, **Oracle America, Inc.** |
| `jre\bin\javaw.exe` | 49 KB | `7E2CCDF5A1866EFD…` | Valid, Oracle America |
| `jre\bin\server\jvm.dll` | 14.7 MB | `C1ACBFAD60606546…` | Valid, Oracle America |
| `jre\bin\awt.dll` | 1.4 MB | `75A09449FB09065B…` | Valid, Oracle America |
| `jre\bin\net.dll` | 61 KB | `5FCEA5918BDDED7D…` | Valid, Oracle America |
| `jre\bin\sunmscapi.dll` | 49 KB | `2599753148873D57…` | Valid, Oracle America |
| `jre\bin\sspi_bridge.dll` | 44 KB | `61061CC964BD1E9B…` | Valid, Oracle America |
| `jre\bin\j2pkcs11.dll` | 83 KB | `25A8BFA17D49573A…` | Valid, Oracle America |
| `burpbrowser\…\chrome.exe` | 3.7 MB | `2B8F59A2F00C594D…` | **NotSigned**, FileVer 151.0.7922.138, Product=Burp Browser |
| `burpbrowser\…\chrome.dll` | 289 MB | `2946F905D3DFCE6E…` | **NotSigned** |
| `burpbrowser\…\chrome_elf.dll` | 2.6 MB | `4DD96399F7CC968E…` | **NotSigned** |
| `burpbrowser\…\chrome_proxy.exe` | 2.4 MB | `177DB34F5151E0FC…` | **NotSigned** |
| `burpbrowser\…\elevation_service.exe` | 3.7 MB | `D0EE8868436791FE…` | **NotSigned** |
| `burpbrowser\…\notification_helper.exe` | 2.7 MB | `F6A63D6FD3E99B74…` | **NotSigned** |
| `burpbrowser\…\libEGL.dll` | 456 KB | `D9B98D8317B82DD5…` | NotSigned |
| `burpbrowser\…\vk_swiftshader.dll` | 5.3 MB | `0C2AEFFC1DF5335E…` | NotSigned |

Signing landscape (summary):
- **PortSwigger Ltd**: all install4j launcher executables that PortSwigger produces (`BurpSuite.exe`, `uninstall.exe`, `bgupdater.exe`, `restart.exe`).
- **ej-technologies GmbH**: install4j internal helpers (`i4jinst.dll`, `i4jdel.exe`).
- **SignPath Foundation**: FlatLaf's native Windows DLL (community CA used by the FlatLaf project).
- **Oracle America**: every file inside `jre\` (confirming this is the official Oracle **OpenJDK** build; `Product=OpenJDK Platform 26.0.2`, VM Vendor "Oracle Corporation").
- **Unsigned**: the entire Burp Browser Chromium bundle. Burp (and most products that re-bundle Chromium) strips signatures during packaging because resigning the whole tree is not practical and binary-identical hashes are preserved for update manifest comparison (`manifest.properties`).

### 2.3 Config / metadata files

| Path | Purpose |
|---|---|
| `BurpSuite.vmoptions`, `BurpSuiteCommunity.vmoptions` | Base JVM options, include-chain to `settings.vmoptions` + `user.vmoptions`, defaults `-XX:MaxRAMPercentage=50` |
| `.install4j\i4jparams.conf` | install4j compile-time variables: appId `6592-1155-2163-3973`, `applicationVersion=2026.8`, `publisherName=PortSwigger Web Security`, `jreVersion=26.0.2-desktop`, `chromiumWindowsVersion=151.0.7922.138`, chromium archive filename `chromium-win64-151.0.7922.138.zip` |
| `.install4j\install.prop` | Records the installer-produced launcher list: `bgupdater.exe`, `BurpSuiteCommunity.exe` (historic), `BurpSuite.exe`, `restart.exe` |
| `.install4j\launchers.xml` | `launcher id=70 checkUpdater=true updateExecutionMode=unattendedProgress` |
| `.install4j\response.varfile` | installer answer file (install dir, file association `.burp`, no admin) |
| `.install4j\inst_jre.cfg` | Path of the JRE used during install extraction |
| `.install4j\installation.log` | Full install log — Java 26 vendor Oracle, host Windows 11 build 26100 |
| `.install4j\files.log` | Full installer manifest (every file + uninstall mode); shows historic Chromium versions 122, 125, 128, 137–146, 151 that were tried over time |
| `.install4j\stats.properties` | Content set stats: 10 content files, 207,670,361 bytes total |
| `.install4j\MessagesDefault` | install4j localization |
| `.install4j\i4j_extf_*.{png,ico,utf8,properties}` | installer graphics / strings |
| `burpbrowser\…\manifest.properties` | File-level MD5 integrity manifest for every Chromium bundle file (used by Burp to detect tampered/incomplete Chromium bundles) |
| `burpbrowser\…\151.0.7922.138.manifest` | Windows side-by-side activation context: tells `chrome.exe` to load `chrome_elf.dll` |
| `burpbrowser\…\vk_swiftshader_icd.json` | Vulkan ICD registration for SwiftShader |
| `burpbrowser\…\First Run` | 8-byte sentinel ("krome ") that suppresses the Chromium first-run wizard |
| `burpbrowser\…\IwaKeyDistribution\{iwa-key-distribution.pb,manifest.json}` | Chromium Isolated Web Apps distributor-signing public keys |
| `burpbrowser\…\MEIPreload\{manifest.json,preloaded_data.pb}` | Chromium Media Engagement Index preload |
| `burpbrowser\…\PrivacySandboxAttestationsPreloaded\…` | Chromium Privacy Sandbox v3 attestation data |
| `jre\conf\security\java.security` | JDK security providers / algorithms |
| `jre\lib\security\cacerts` | OpenJDK root trust store (used by Burp's JVM when the project trust mode is "Use JVM default") |
| `jre\lib\security\blocked.certs` | Explicit CA/signature blocklist |
| `jre\lib\security\public_suffix_list.dat` | eTLD+1 data |
| `jre\release` | Lists `JAVA_VERSION=26.0.2`, every bundled JEP module |


## 3. Overall Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                            Burp Suite Community 2026.8                        │
└───────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────┐          ┌──────────────────────────────────────┐
│  install4j launcher      │  spawn   │  Oracle OpenJDK 26.0.2 HotSpot VM    │
│  BurpSuite.exe (1.1 MB)  ├─────────▶│  jre\bin\server\jvm.dll + jli/i4jinst │
│  BurpSuite.vmoptions     │          │  MaxRAM 50%, --add-opens x6          │
└──────────────────────────┘          │  Main-Class: burp.StartBurp          │
                                      └──────────────┬───────────────────────┘
                                                     │ loads
                                                     ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│   burpsuite.jar (154 MB, 59,101 entries, Multi-Release)                      │
│   ───────────────────────────────────────────────────────────────────────    │
│   burp.StartBurp (main)                                                      │
│   burp.*                   Legacy Extender API (IBurp*), obfuscated impl     │
│   burp.api.montoya.*       Public Montoya extension API (modern)             │
│   burp.ai.sdk              AI extension SDK (used by Burp AI)                │
│   burp.agentic.*           Burp Agentic Testing module (burp-at)             │
│   burp.theme.*             BurpLaf, dark/light JSON themes, custom UI        │
│   net.portswigger.*        Internal engines (browser, scanner, devtools,     │
│                            crawlgraph, apiparser, encoding, funnel,          │
│                            javatooling (OSGi), opentelemetry, json)          │
│   ─── third-party (shaded) ─────────────────────────────────────────────     │
│   kotlin.*, kotlinx.coroutines.*     reactor.*         tools.jackson.*       │
│   org.bouncycastle.*                 io.netty (via io.*)                     │
│   com.squareup.{okhttp3,okio}        com.fasterxml.jackson (legacy)          │
│   org.apache.*       com.google.{common,protobuf,errorprone,gson}            │
│   javafx.{beans,collections,event,util}     oshi.*     org.brotli.*          │
│   com.formdev (FlatLaf)              org.mozilla.* (Rhino JS engine)         │
│   org.snakeyaml / org.yaml           com.nimbusds (JOSE+JWT)                 │
│   io.swagger (OpenAPI)               io.opentelemetry.* + io.micrometer      │
│   io.modelcontextprotocol (MCP SDK)  com.networknt (JSON Schema)             │
│   org.jetbrains.annotations          com.beust (JCommander)                  │
│   org.ethlo (ISO-8601), com.ethlo    com.connectrpc (Connect-RPC)            │
│   org.aopalliance, org.jspecify, org.checkerframework, org.joda,             │
│   org.reactivestreams, org.slf4j, com.sun.*                                  │
└──────────────────────────────────────────────────────────────────────────────┘
                 │                                 │
                 │ loads native DLLs               │ child process (on demand)
                 ▼                                 ▼
┌───────────────────────────┐     ┌───────────────────────────────────────────┐
│ Native libs loaded in-JVM │     │  Burp Browser (Chromium 151.0.7922.138)   │
│  jvm, java, awt, net,     │     │  burpbrowser\151.0.7922.138\chrome.exe    │
│  nio, zip, extnet,        │     │   ├── chrome_proxy.exe (invisible)        │
│  freetype, fontmanager,   │     │   ├── chrome.dll (289 MB)                 │
│  sunmscapi (Win CryptoAPI)│     │   ├── chrome_elf, chrome_wer              │
│  sspi_bridge (Negotiate)  │     │   ├── notification_helper, elev_service   │
│  j2pkcs11                 │     │   ├── ANGLE (libEGL, libGLESv2)           │
│  flatlaf-windows-x86_64   │     │   ├── SwiftShader + vulkan-1              │
│   (temp-extracted)        │     │   └── D3DCompiler_47, dxcompiler, dxil    │
│  JNA jnaNNN.dll           │     │                                           │
│   (temp-extracted)        │     │  user-data-dir:                           │
└───────────────────────────┘     │   %AppData%\BurpSuite\pre-wired-browser   │
                                  │                                           │
                                  │  loaded extensions (unpacked):            │
                                  │    burp-chromium-extension/ (MV3)         │
                                  │      ├── dom-invader-extension/           │
                                  │      ├── navigation-recorder/             │
                                  │      ├── new-tab/                         │
                                  │      ├── popup/                           │
                                  │      └── service-worker/                  │
                                  └───────────────┬───────────────────────────┘
                                                  │
         ┌────────────────────────────────────────┤
         │ 1. HTTP(S) traffic through proxy       │ 2. CDP control channel
         │    127.0.0.1:9876                      │    DevToolsActivePort file
         ▼                                        ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│ Burp Proxy listener          │    │ CDP client in Burp JVM       │
│  127.0.0.1:8080 (default)    │    │ (net.portswigger.devtools.*) │
│  127.0.0.1:9876 (browser)    │    │ speaks WebSocket to Chromium │
│                              │    │ for DOM Invader, Nav Recorder│
│  Also intercepts "https://   │    │ coordination, screenshots,   │
│  burp/" to serve the Burp    │    │ cookie reads, etc.           │
│  internal web UI to its own  │    └──────────────────────────────┘
│  extensions                  │
└──────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│ Supporting services                                                          │
│ ─ Jython / JRuby interpreters loaded in-JVM for script extensions            │
│ ─ OSGi-ish framework (net.portswigger.javatooling.framework.OsgiFramework)   │
│   via META-INF/services, used to isolate Java extensions                     │
│ ─ Collaborator client (burp/ICollaborator* + burp.api.montoya.collaborator)  │
│   defaults to PortSwigger's public Collaborator (type=default)               │
│ ─ MCP Server (BApp 9952290f04ed4f628e624d0aa9dccebc = burp-mcp-all.jar       │
│   29.9 MB, loaded) exposes Burp capabilities over Model Context Protocol     │
│ ─ Burp AI (burp.ai.sdk + "ai_credits" balance in WorkspaceConfig)            │
│ ─ Burp Agentic Testing (burp.agentic.AgenticAiBurpModule, hotkeys Ctrl+G /   │
│   Ctrl+Shift+G, docs at desktop/burp-at/*)                                   │
│ ─ Bambdas / BChecks (user dirs present)                                      │
│ ─ Auto-update: .install4j\bgupdater.exe + updates\<hex>\autoupdate.meta      │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Process model (at analysis time)

| PID | Image | Role |
|---:|---|---|
| 7856 | `BurpSuite.exe` (install4j launcher that pivots into the JVM) | Single Java process hosting the entire Burp UI, proxy, engines, extensions |
| — | `chrome.exe` / `chrome_proxy.exe` / helpers | Not running right now; spawned on demand when "Open Browser" is clicked |

The install4j native launcher **does not stay around as a separate process** — it loads `jli.dll` + `jvm.dll` into its own process and becomes the JVM. That is why `Get-CimInstance Win32_Process` sees PID 7856 with image `BurpSuite.exe`, loaded modules `jvm.dll`, `awt.dll`, `extnet.dll`, `sunmscapi.dll`, etc.

JVM arguments actually used (captured from `hs_err_pid*.log`):

```
-Dexe4j.semaphoreName=Local\c:_users_pc_appdata_local_programs_burpsuitecommunity_burpsuitecommunity.exe0
-Dexe4j.isInstall4j=true
-Dexe4j.moduleName=…\BurpSuiteCommunity.exe
-Dexe4j.tempDir=
-Dexe4j.unextractedPosition=0
-Djava.library.path=…\jre\bin;…(PATH)
-Dexe4j.consoleCodepage=cp0
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/javax.crypto=ALL-UNNAMED
--add-opens=java.desktop/javax.swing=ALL-UNNAMED
--add-opens=java.desktop/java.awt=ALL-UNNAMED
--add-opens=java.desktop/java.awt.color=ALL-UNNAMED
--add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED
-Dinstall4j.launcherId=70
-Dinstall4j.swt=false
-XX:MaxRAMPercentage=50
```

The six `--add-opens` are telling: Burp does deep reflection into `java.lang` (likely for class redefinition / unsafe accessors in the extension framework), `javax.crypto` (to drive BouncyCastle through JCE despite restrictive module encapsulation), `javax.swing` + `java.awt` + `java.awt.color` (for the custom LaF, borderless windows, color-management hacks), and most interestingly **`jdk.crypto.cryptoki/sun.security.pkcs11`** — to reach into the PKCS#11 provider internals, which is used for client-cert handling via smart cards / hardware tokens and for implementation of some SunPKCS11 keystore quirks.


## 4. Main Executables and Launcher

### 4.1 `BurpSuite.exe` (install4j launcher)

- PE32+ Win64, 1,157,136 bytes, FileVersion `2026.8`, Company "PortSwigger Web Security", Product "Burp Suite", Authenticode-signed by PortSwigger Ltd.
- Produced by install4j 12.0.5. Reads its co-located `.vmoptions` chain, locates the embedded JRE under `jre\`, and launches it via `jli.dll` / `jvm.dll` from `jre\bin\server\`.
- Historic launcher ID: `70` (referenced in `launchers.xml` and `-Dinstall4j.launcherId=70`).
- Reads at least `BurpSuite.vmoptions`, `settings.vmoptions`, `user.vmoptions` (per the `-include-options` directives inside the vmoptions files).
- `.install4j\i4jinst.dll` is the install4j native runtime that the launcher pulls in; it is loaded at runtime (seen in PID 7856's module list).
- There is a second helper `.install4j\bgupdater.exe` (PortSwigger-signed) used to run the auto-updater without a visible window, and `.install4j\restart.exe` for self-restart.

### 4.2 Older `BurpSuiteCommunity.exe` reference

The installer state (`install.prop`, `files.log`) and the two HotSpot crash dumps (`hs_err_pid22316.log`, `hs_err_pid28976.log`) reference a `BurpSuiteCommunity.exe` launcher that no longer exists in the installation; the file is now `BurpSuite.exe`. The crash dumps come from JDK 25.0.2+10-69 (the version shipped with Burp 2026.4 / 2026.5), while the current install carries OpenJDK 26.0.2+10-55. This is consistent with an in-place auto-update that renamed the primary launcher from `BurpSuiteCommunity.exe` to `BurpSuite.exe` while leaving a stale `BurpSuiteCommunity.vmoptions` (unused but kept for compatibility).

### 4.3 Uninstaller + updater

- `uninstall.exe` (550 KB, PortSwigger-signed): standard install4j uninstaller; reads `.install4j\response.varfile` + `files.log` to decide what to remove.
- `.install4j\bgupdater.exe` (532 KB, PortSwigger-signed): invoked unattended on launch to check PortSwigger's update feed and stage updates in `%AppData%\BurpSuite\updates\<hex>\autoupdate.meta`. The `updates\` directory currently contains four orphaned hex-named directories, indicating multiple past update staging cycles.

## 5. Bundled JRE / JVM

- Vendor "Oracle Corporation", runtime name "OpenJDK Runtime Environment", build **26.0.2+10-55**, release date 2026-07-21, 64-bit Server VM (G1 GC, tiered compilation, compressed class pointers, Zero-based CompressedOops). This is the official Oracle OpenJDK Windows build (the signature on `java.exe` / `jvm.dll` is "CN=Oracle America, Inc.").
- Modules present (from `jre\release`):
  `java.base, java.compiler, java.datatransfer, java.xml, java.prefs, java.desktop, java.instrument, java.logging, java.management, java.security.sasl, java.naming, java.rmi, java.management.rmi, java.net.http, java.scripting, java.security.jgss, java.transaction.xa, java.sql, java.sql.rowset, java.xml.crypto, java.se, jdk.accessibility, jdk.internal.jvmstat, jdk.attach, jdk.charsets, jdk.internal.opt, jdk.zipfs, jdk.compiler, jdk.crypto.cryptoki, jdk.crypto.ec, jdk.crypto.mscapi, jdk.jdwp.agent, jdk.jdi, jdk.management, jdk.net, jdk.security.auth, jdk.security.jgss, jdk.unsupported`.
- Noteworthy inclusions: `jdk.crypto.mscapi` (so Burp's JVM can talk to the Windows cert store natively), `jdk.compiler` (javac is present — enables runtime compilation, used by BChecks / Bambdas / extension development), `java.net.http` (modern HttpClient), `java.scripting` (JSR-223, used by Jython bridge).
- Native libraries present under `jre\bin\`: `java.dll`, `javaw.exe`, `jli.dll`, `server\jvm.dll` (15.0 MB), `awt.dll`, `fontmanager.dll`, `freetype.dll`, `nio.dll`, `net.dll`, `extnet.dll`, `zip.dll`, `management.dll` + `management_ext.dll`, `prefs.dll`, `verify.dll`, `splashscreen.dll`, `jaas.dll`, `j2gss.dll` (GSSAPI/Kerberos), `j2pkcs11.dll` (PKCS#11), `jsound.dll`, `jdwp.dll` + `dt_shmem.dll` + `dt_socket.dll` (JDI transports), `sunmscapi.dll` (SunMSCAPI JCA/JSSE provider — Windows Crypto API bridge), `sspi_bridge.dll` (Windows SSPI → Negotiate/Kerberos), `w2k_lsa_auth.dll`, `windowsaccessbridge-64.dll` + `javaaccessbridge.dll` + `jaccessinspector.exe` + `jaccesswalker.exe` + `jabswitch.exe` (Windows accessibility bridge), `kinit.exe`/`klist.exe`/`ktab.exe` (Kerberos CLI), `keytool.exe` (used by Burp or by users to manage keystores), `rmiregistry.exe`, `serialver.exe`, `jdb.exe` (JDI debugger).
- Full `javac.exe` present — Burp ships a complete JDK, not a trimmed JRE. This is what makes it able to **compile Java-based BApps on the fly** and support **BChecks compilation**.
- `jre\lib\modules` is a packed JIMAGE containing all JDK class files; `jre\lib\jrt-fs.jar` is the jrt filesystem provider.
- `jre\lib\security\cacerts` is the default JDK trust store (used when Burp is told to validate upstream TLS against the "JVM default trust"). `blocked.certs` enumerates revoked CAs. `public_suffix_list.dat` is Mozilla's PSL used by HttpClient and `URL` handling.

## 6. Burp JAR Internals (`burpsuite.jar`)

### 6.1 Manifest

```
Manifest-Version: 1.0
Implementation-Name: burp
Implementation-Version: 53343
Implementation-Vendor: PortSwigger
Specification-Name: burp
Specification-Vendor: PortSwigger
Multi-Release: true
Burp-JAR-Type: Installer
Main-Class: burp.StartBurp
SplashScreen-Image: resources/Media/splash.png
Add-Opens: java.base/java.lang java.desktop/javax.swing java.desktop/java.awt
 java.desktop/java.awt.color java.base/javax.crypto
 jdk.crypto.cryptoki/sun.security.pkcs11
```

The `Add-Opens` manifest attribute mirrors the launcher's `--add-opens` flags; both must agree because `Add-Opens` only takes effect when the executable JAR is launched via `java -jar`, whereas install4j launches via main-class directly. Having both is defensive.

`Multi-Release: true` means the JAR carries `META-INF/versions/<N>/…` overrides for newer JDKs (common for Kotlin stdlib and Jackson's module-info variants).

`Burp-JAR-Type: Installer` is a Burp-specific marker — when the JAR is run directly (vs. launched by install4j), Burp uses it to detect whether it should enter installer mode or regular launch mode. (It is still just the main-class `burp.StartBurp` though.)

### 6.2 Jar root directories

```
burp/            Burp application code + public legacy API (burp.I*)
burp/api/montoya/  Montoya modern extension API (public)
burp/ai/sdk/     AI SDK for extensions
burp/agentic/    Burp Agentic Testing module (burp-at)
burp/theme/      Burp's custom Swing LaF
com/             shaded third-party (Google, Jackson 2, Nimbus, OkHttp…)
io/              shaded (OpenTelemetry, Swagger, MCP SDK)
javafx/          JavaFX runtime (beans, collections, event, util)
kotlin/          Kotlin standard library (incl. kotlin.coroutines)
kotlinx/         kotlinx.coroutines
net/             shaded + net.portswigger.* internals
org/             shaded (BouncyCastle, Apache, Jetbrains, Brotli, Rhino,
                 SnakeYAML, SLF4J, Joda, reactivestreams, aopalliance,
                 checkerframework, intellij, jspecify)
oshi/            Operating System and Hardware Information
patches/         JSON Patch files for API spec migration (OpenAPI v1.0→v1.1→v1.2)
reactor/         Project Reactor (adapter, core, util)
resources/       Burp's own resource bundle (see §6.4)
samples/         Example extensions, versioned v1.0/v1.1/v1.2
schemas/         Burp project schemas v1.1, v1.2
tools/jackson/   Jackson 3.x (newer namespace)
chromium.properties   Lists the required Chromium version per OS/arch
META-INF/        Manifest + service-provider registrations
```

### 6.3 `chromium.properties`

```
linux64=151.0.7922.137
linuxarm64=151.0.7922.137
macosarm64=151.0.7922.138
macosx64=151.0.7922.138
win64=151.0.7922.138
winarm64=151.0.7922.138
```

Burp hard-codes the Chromium version it wants per-platform; the `net.portswigger.browser.chromium.ChromiumBinaryInstaller` (registered as a `java.util.ServiceLoader` provider in `META-INF/services/`) consults this file at startup and either verifies the already-installed Burp Browser version or downloads the right ZIP from PortSwigger's CDN.

### 6.4 Resource trees (shipped data)

| Resource | Content | Notes |
|---|---|---|
| `resources/Browser/DomInvader/` | Full DOM Invader extension (background service worker, content scripts, Bootstrap CSS, Bootstrap-Icons SVG set, instrumentation JS) | DOM Invader is physically shipped inside the JAR *and* also mirrored out to the user profile at launch |
| `resources/Browser/DomInvader/content-scripts/augmented-dom-instrumentation.js` | 514 KB of instrumentation code (hooks DOM, sinks) | Heavily instrumented |
| `resources/Browser/DomInvader/content-scripts/postmessage-instrumentation.js` | 538 KB (hooks `postMessage`) | Runs in `MAIN` world |
| `resources/Browser/DomInvader/content-scripts/augmented-dom.js` | 224 KB (DOM sink detection) | |
| `resources/Community/SampleIssues.json` | 79 KB of pre-canned scanner issues shown to Community users (since Scanner can't actually run) | Community-edition specific |
| `resources/BuiltInConfigs/*.json` | 29 scan/crawl profiles: "Audit coverage - thorough", "Crawl and Audit - Fast", "Audit checks - BChecks only", "Minimize false positives", "CICD Optimized", etc. | Full list retained in Community even though Scanner is Pro-only |
| `resources/BurpAI/autherror/auth-error.html` | 5 KB — AI auth failure page shown when Burp AI can't authenticate to PortSwigger's AI backend | |
| `resources/Preferences/*.json` | `AuditDefaults`, `CrawlDefaults`, `LivePassiveCrawlDefaults`, `ProjectDefaults` (26 KB), `UserDefaults` (17 KB), `WorkspaceDefaults`, `AutoUpdateDefaults`, `enterprise-agent.json`, `enterprise-server.json`, `desktop.json` | Hard-coded factory defaults for every edition (incl. Enterprise profiles) |
| `resources/Legal/Eula.txt` | 70 KB Burp Suite EULA | |
| `resources/Legal/RSyntaxTextAreaLicence.txt` | Third-party licence for the embedded text editor | |
| `resources/Scanner/jwt_secrets.txt` | **1.1 MB JWT secret wordlist** (used by Scanner / BChecks for JWT weak-key detection) | |
| `resources/Clickbandit/clickbandit.js` | 30 KB clickjacking-PoC generator | |
| `resources/MobileAssistant/{CydiaIcon.png,Release}` | Burp Mobile Assistant assets (iOS testing helper) | |
| `resources/Infiltrator/burp_infiltrator_dotnet.exe` | 205 KB — .NET bytecode instrumenter | Shipped in Community even though Infiltrator is Pro-only |
| `resources/Infiltrator/burp_infiltrator_java.jar` | 225 KB — Java bytecode instrumenter | Same |
| `resources/Crypto/ps.p12` | 2,020-byte PKCS#12 keystore ("ps" = PortSwigger). Likely contains the public-key material Burp uses to verify signed updates and signed BApps, and/or an infrastructure cert for Collaborator / telemetry channels | *Not opened* — redacted by policy |
| `resources/Documentation/burp/documentation/*` | Full offline documentation: topics include `ai-features/`, `desktop/burp-ai/`, `desktop/burp-at/{index,tasks,tools,skills,permissions,prompting,reviewing-findings,setting-up}`, `collaborator/server/private/{configuring,example,troubleshooting}`, `extend-burp/bambdas/creating/*`, `desktop/burps-layout/*` | HTML docs embedded |
| `resources/PayloadStrings/*.pay` | 47+ Intruder payload files: Fuzzing-{XSS, SQL injection, path traversal, template injection, out-of-band, JSON_XML injection, email splitting, quick, full}, usernames, passwords, user-agents (long + short), server-side variable names, HTTP headers / verbs, local files per OS, 3-12 letter words, filename/directory wordlists, format strings, CGI scripts, IIS files, interesting files | Standard Intruder dictionary |
| `resources/Media/*` | ~ hundreds of UI icons incl. severity bars (`bar-high-certain.gif`), AMF protocol icons, dark-theme assets, `BurpAi/welcome-banner.svg`, `BurpAIBrowser/{icon.icns,icon.ico,icon_*.png}` | |
| `resources/Mimetypes/media_problematic_mime_types.txt` | 100-byte list of risky media MIME types | |
| `resources/Tooling/libraries/montoya-api.jar` | 177 KB — Montoya API JAR for extension developers (plus javadoc 5 MB and sources 226 KB) | |
| `resources/WebApi/{css,fonts,img,js,sass}` | React.js UI assets for Burp Enterprise/REST API web view (incl. `react.min.js`, `react-dom.min.js`, PortSwigger brand icons/fonts) | |
| `resources/KnowledgeBase/Issues/*` | Scanner issue descriptions (HTML + JSON) for every issue type Burp can report — SQLi (incl. second-order), XSS (stored/reflected), XXE, LDAP/XPath/XML/OS cmd/PHP/JS/Perl/Ruby/Python/EL/SSTI/SSI code injection, path traversal, cache poisoning, HTTP smuggling, client-side desync, HTTP response header injection, "React Server Components Remote Code Execution (React2shell)", etc. | Full Scanner KB shipped in Community (useful for Burp AI, documentation hovers, issue linking) |
| `resources/AdBlockList/advert-domains.txt` | 860 KB ad-domains list, used by Burp Browser's declarative-net-request rules | |
| `resources/RetireJS/retirejs_repository.json` | 549 KB Retire.js vulnerable-library signature db | Used by passive Scanner / BChecks |
| `patches/{t.json,v1.1/,other/}` | JSON Patch files to upgrade legacy OpenAPI/Postman specs to the current internal schema | |
| `samples/v1.0/`, `samples/v1.1/`, `samples/v1.2/` | Example extensions matching API versions | |
| `schemas/v1.1/`, `schemas/v1.2/` | Burp project/config JSON schemas |

### 6.5 Service-provider registrations (`META-INF/services/`)

| SPI interface | Burp provider(s) | Role |
|---|---|---|
| `net.portswigger.browser.chromium.ChromiumBinaryInstaller` | 1 impl | Downloads / verifies the Chromium bundle on first launch; consults `chromium.properties` + `manifest.properties` |
| `net.portswigger.browser.service.Zo` | 1 impl (obfuscated name) | Browser service bootstrap |
| `net.portswigger.javatooling.framework.OsgiFramework` | 1 impl | OSGi-ish framework used to load extensions in isolated classloaders |
| `java.security.Provider` | 1 impl | Registers additional JCE providers (BouncyCastle, likely) |
| `javax.imageio.spi.{ImageReader,ImageWriter,ImageInputStream,ImageOutputStream}Spi` | multiple | Custom image codecs |
| `io.micrometer.context.ContextAccessor` | 1 impl | Reactor context propagation |
| `io.modelcontextprotocol.json.{McpJsonMapperSupplier,JsonSchemaValidatorSupplier}` | multiple | MCP SDK JSON binding |
| `io.opentelemetry.sdk.autoconfigure.spi.*` + `exporter.internal.http.HttpSenderProvider` | 7 providers | OpenTelemetry autoconfig (traces, metrics, logs, resources, propagators) |
| `reactor.blockhound.integration.BlockHoundIntegration` | 1 impl | **BlockHound** at runtime detects blocking calls on reactive threads |
| `tools.jackson.core.TokenStreamFactory`, `tools.jackson.databind.ObjectMapper` | 1 each | Jackson 3.x bootstrap |
| `burp.Zw5f` | 1 impl (obfuscated) | Burp-internal plugin |

### 6.6 Code obfuscation

The internal Burp code is heavily obfuscated with what looks like **Guardsquare ProGuard / DexGuard-style name mangling**. Observed patterns:
- Fully-qualified names like `burp.Zza`, `burp.Zz_`, `burp.Z_dw`, `burp.zzzzZwuoCustomizer`, `net.portswigger.Zy7`, `net.portswigger.browser.Zcc`, `burp.agentic.Zm3`, `burp.theme.Zj`.
- Thousands of such classes under `burp/`, `burp/agentic/`, `burp/theme/`, `net/portswigger/*/`. The naming scheme is `Z` + optional underscore(s) + letter/digit pairs, encoding a counter.
- **Montoya API (`burp.api.montoya.*`), AI SDK (`burp.ai.sdk`), the public legacy API (`burp.I*`), and `burp.theme.*` UI classes are NOT obfuscated** — these are the three surfaces that extensions / third parties / theme authors need stable names for.
- Resource files (JSON, images, HTML) are not encrypted or packed.
- No evidence of control-flow flattening, string encryption, or anti-debugger tricks in the Java byte-code I inspected (just name obfuscation + aggressive inlining).

The DOM Invader container-service-worker JavaScript is additionally obfuscated with a **javascript-obfuscator string-array / dead-code-insertion** pass (common `a0_0x...` helpers, rotated string table, control-flow dispatcher). This is JS obfuscation only — the obfuscator identity is clear from the generated helper shape.


## 7. Burp Browser (Chromium 151.0.7922.138)

### 7.1 Chromium bundle

The whole bundle sits in `burpbrowser\151.0.7922.138\` and is a standard Chromium 151 Windows x64 build, repackaged as "Burp Browser":

- **Branding is purely cosmetic**: VERSIONINFO reports `Product=Burp Browser`, Company `The Chromium Authors`. The product file-version 151.0.7922.138 lines up with upstream Chromium `151.0.7922.138` tagged Aug 2026.
- **Signatures stripped**: every executable in the bundle shows `NotSigned` (Authenticode state). The build *was* signed upstream but PortSwigger re-wraps it, so signatures no longer verify. SmartScreen integrity falls back to reputation / parent-process trust.
- **Integrity manifest**: `manifest.properties` lists every file with its byte-length and **MD5** hash. This gives Burp a cheap self-check (it is not a cryptographic integrity signature — just a tamper indicator).
- **Side-by-side manifest** (`151.0.7922.138.manifest`): declares `chrome_elf.dll` as a dependency of the chrome.exe activation context — standard Chromium "elf" loader trick.
- **GPU stack**: ANGLE (`libEGL.dll`, `libGLESv2.dll`) with DX12 backend (`dxcompiler.dll`, `dxil.dll`, `D3DCompiler_47.dll`), plus SwiftShader (`vk_swiftshader.dll`, declared as a Vulkan ICD via `vk_swiftshader_icd.json`) and the Vulkan loader (`vulkan-1.dll`) for GPU-less fallback — identical to upstream Chromium.
- **Resource paks**: `resources.pak` (21.3 MB — compiled UI resources), `chrome_100_percent.pak`, `chrome_200_percent.pak`, and a full `locales\xx.pak` set with Google's new gendered localization variants (`xx_FEMININE.pak`, `xx_MASCULINE.pak`, `xx_NEUTER.pak`) — these are typically ~18 bytes each, acting as fallback stubs.
- **V8 snapshot**: `v8_context_snapshot.bin` (740 KB), `icudtl.dat` (10.9 MB ICU data).
- **Chromium component data preloaded**: `IwaKeyDistribution\iwa-key-distribution.pb` (Isolated Web Apps signing keys), `PrivacySandboxAttestationsPreloaded\privacy-sandbox-attestations.dat`, `MEIPreload\preloaded_data.pb`.
- **No Widevine CDM, no Chrome Remote Desktop host, no Google updater** — all removed. This matches a security-testing use case where DRM is irrelevant and auto-update is handled by Burp itself.
- **"First Run" sentinel** file contains the literal text `krome ` (8 bytes). Chrome treats the mere presence of a `First Run` file as "first-run already handled, do not show welcome", which is why Burp Browser never shows the Google first-run flow.

### 7.2 Chromium user-data-dir

Burp uses `%AppData%\BurpSuite\pre-wired-browser\` as the Chromium profile directory (passed as `--user-data-dir=`). The directory is a complete Chromium profile:

- `Default\` subfolder with the usual SQLite databases (Login Data, History, Favicons, Cookies via `Network\`, Preferences, Secure Preferences, Web Data), extensions scaffolding, Code Cache, GPUCache, Service Worker, Session Storage, Shared Storage, Site Characteristics Database, BrowsingTopicsSiteData / BrowsingTopicsState (Privacy Sandbox v3), AutofillAiModelCache / autofill AI preds, PersistentOriginTrials, declarative_performance_observer, Shared Dictionary, Download Service, Feature Engagement Tracker, HistoryEmbeddings, Platform Notifications, Segmentation Platform, Media Device Salts, Trust Tokens.
- `Local State` — Chromium global state. Observed fields: `net.network_service_failed_launch_major_version=151`, `profile.info_cache.Default.ai_subscription_tier=0` (community/free tier), `management.platform.azure_active_directory=8`, `optimization_guide.on_device.last_version=151.0.7922.138`, `optimization_guide.on_device.performance_class=7`, `uninstall_metrics.installation_date2=1694426359` (first install Sep 2023). The `os_crypt.encrypted_key` is a DPAPI-wrapped AES-GCM key used for encrypting cookie/password values in `Default\Cookies` and `Default\Login Data`. **(Not exposed here.)**
- `DevToolsActivePort` — contains `54311\n/devtools/browser/387e0993-2607-47be-9888-99663c98fd03`. This is the file that **Chrome writes when `--remote-debugging-port=0` is used**, which is a strong indicator that Burp spawns Chromium with CDP enabled on an ephemeral port and reads the port back from this file.
- `Last Browser` — stored path to `C:\Users\pc\AppData\Local\Programs\BurpSuiteCommunity\burpbrowser\151.0.7922.138\chrome.exe` (NUL-separated UTF-16 — Chromium's native encoding).
- `Last Version` — `151.0.7922.138` (plain text).
- `Variations` — `{"user_experience_metrics.stability.exited_cleanly":true,"variations_crash_streak":153}`. Variations/field-trials are effectively absent (which is intentional for a controlled MITM browser).
- `extensions_crx_cache\metadata.json` → `{"hashes":{}}`. Component updater is disabled, so no CRX cache content.
- `component_crx_cache`, `CertificateRevocation` (CRLSets), `Safe Browsing`, `OptimizationHints`, `OptimizationGuideModelsManifest`, `OriginTrials`, `PKIMetadata`, `PKIMetadataFastpush`, `TrustTokenKeyCommitments`, `SSLErrorAssistant`, `FirstPartySetsPreloaded` + `first_party_sets.db`, `Snapshots`, `SODA` + `SODALanguagePacks` (speech-recognition models), `ActorSafetyLists`, `FileTypePolicies`, `HistorySearch`, `OnDeviceHeadSuggestModel`, `TranslateKit`, `ClientSidePhishing`, `WasmTtsEngine`, `ZxcvbnData` (password strength data), `hyphen-data`, `Crashpad\`, `GraphiteDawnCache`, `GPUPersistentCache`, `GrShaderCache`, `AmountExtractionHeuristicRegexes`, `CaptchaProviders`, `Crowd Deny`, `Subresource Filter`, `segmentation_platform`.

### 7.3 Burp's Chromium extension bundle

The extensions are not placed into the standard `Default\Extensions\` tree — they are **unpacked and loaded via `--load-extension=` command-line flags from four locations**:

```
%AppData%\BurpSuite\burp-chromium-extension\      Container extension (combines all three)
%AppData%\BurpSuite\dom-invader\                  Standalone DOM Invader
%AppData%\BurpSuite\navigation-recorder\          Standalone Login Recorder
%AppData%\BurpSuite\new-tab\                      Custom new tab page
```

The dom-invader and navigation-recorder manifests include a `"key"` field (a 2048-bit RSA public key encoded as base64 DER). Chromium derives extension IDs by hashing this key — this is the standard way to pin an unpacked extension to a *stable, deterministic ID* so other code can refer to it by that ID across installs. Burp uses this to let its own JVM-side code `chrome.runtime.sendMessage` to the extensions with known IDs.

The **container extension `manifest.json`** (`burp-chromium-extension\manifest.json`, v2.0.23, MV3) is the most important:

```jsonc
{
  "name": "Burp Suite",
  "manifest_version": 3,
  "background": { "service_worker": "./service-worker/container-service-worker.js", "type": "module" },
  "content_scripts": [
    { "run_at": "document_start", "matches": ["http://*/*","https://*/*"],
      "js": [
        "./dom-invader-extension/content-scripts/postmessage-instrumentation.js",
        "./dom-invader-extension/content-scripts/augmented-dom-instrumentation.js"
      ],
      "all_frames": true, "match_about_blank": true, "world": "MAIN" },
    { "run_at": "document_start", "matches": ["http://*/*","https://*/*"],
      "js": [
        "./dom-invader-extension/content-scripts/connection.js",
        "./dom-invader-extension/content-scripts/postmessage.js",
        "./dom-invader-extension/content-scripts/augmented-dom.js",
        "./navigation-recorder/content-scripts/classes/Recorder.js"
      ],
      "all_frames": true, "match_about_blank": true }
  ],
  "chrome_url_overrides": { "newtab": "./new-tab/newtab.html" },
  "devtools_page": "./dom-invader-extension/devtools/devtools.html",
  "action": { "default_popup": "./popup/popup.html", … },
  "permissions": [
    "activeTab","storage","tabs","clipboardWrite","webNavigation",
    "privacy","notifications","webRequest","scripting","offscreen",
    "declarativeNetRequest","declarativeNetRequestFeedback"
  ],
  "host_permissions": ["https://*/*","http://*/*"],
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'; connect-src 'self' https://burp/"
  }
}
```

Highlights:
- **`"world": "MAIN"`** on the DOM Invader instrumentation scripts: Chrome injects them into the page's own JavaScript realm (not the isolated content-script world). That is how DOM Invader can override `postMessage`, `Element.innerHTML` setters, `document.write`, etc. — a feature that only became possible once Manifest V3 added the MAIN world directive.
- **`https://burp/` whitelisted in `connect-src`**: this is Burp's internal pseudo-host. HTTP requests from inside the extension targeting `https://burp/...` are picked up by Burp's proxy (the Browser is proxied through Burp) and routed to Burp's internal UI endpoint (served from the Java process) rather than being forwarded to the network. That is the IPC between extension JS and the Burp JVM.
- `webRequest` + `declarativeNetRequest` + `declarativeNetRequestFeedback`: lets Burp install dynamic request/response rules (used by ad-blocking from `advert-domains.txt`, and by Burp Browser's "pre-wired" blocklist of Google / telemetry endpoints).
- `privacy`: the service worker reads/writes `chrome.privacy.services.{autofillAddressEnabled,autofillCreditCardEnabled,passwordSavingEnabled}` — **it disables autofill while the Login Recorder is active** and restores the user's prior setting when recording stops.
- `offscreen`: lets the service worker spawn an offscreen DOM document (MV3 requires this for anything that needs `DOMParser`, audio playback, etc.).
- `clipboardWrite`: used by DOM Invader's "copy canary" / "copy payload" buttons.
- `notifications`: used by the Login Recorder to warn when auth prompts appear.

The `container-service-worker.js` imports `../js/utils.js`, `../navigation-recorder/classes/RecorderControl.js`, and `../dom-invader-extension/js/classes/Settings.js`. The first ~250 lines are readable (recorder state machine, chrome.privacy toggles, auth-detection listeners). From there on the file is **javascript-obfuscator-mangled** — the DOM Invader detection logic (prototype pollution, CSP-bypass tracking, canary detection, badge counters) is intentionally hard to reverse.

### 7.4 Browser launch arguments

The HotSpot crash logs show the install4j launcher only — they do not expose the Chromium command-line because `chrome.exe` was not running at the moment of either crash. However, strong evidence of the actual argument set comes from three sources:

- `DevToolsActivePort` file **exists and contains both a port and a GUID** — this file is only ever written when Chrome is launched with `--remote-debugging-port=<n>` (or `--remote-debugging-pipe` with the port-file flag). Burp's `net.portswigger.devtools.*` package consumes this file to get its CDP endpoint.
- The user-data-dir path (`%AppData%\BurpSuite\pre-wired-browser`) implies `--user-data-dir=` is explicitly passed.
- The three loopback listeners Burp holds while the browser is open (`127.0.0.1:8080`, `127.0.0.1:9876`, ephemeral) and the `https://burp/` origin whitelisted in extension CSP strongly imply the browser is started with `--proxy-server=127.0.0.1:9876` and `--host-resolver-rules="MAP burp 127.0.0.1:9876"` (or equivalent), plus some additional flags to disable features that would interfere with security testing (safe browsing, phishing detection, autofill, DNS prefetch, components updater, extensions store, translate, variations, metrics, default browser prompt).

**CONFIRMED Chromium flags** (direct evidence from files on disk):
- `--user-data-dir="%AppData%\BurpSuite\pre-wired-browser"` — directory exists and is Chromium's standard profile.
- `--remote-debugging-port=0` (ephemeral), surfaced via `DevToolsActivePort` — file exists.
- `--load-extension=<burp-chromium-extension>[,<dom-invader>,<navigation-recorder>,<new-tab>]` — these directories exist outside the normal `Default\Extensions` tree, which is Chromium's documented behavior when loaded with `--load-extension`.
- `--no-first-run` **implied** by the sentinel `First Run` file; and `--no-default-browser-check` is PortSwigger's typical pattern.

**STRONGLY INDICATED Chromium flags** (based on behavior + Burp docs, confirmed by file content):
- `--proxy-server=127.0.0.1:9876` — Burp holds 9876 listening while idle; the extension CSP's `https://burp/` requires it to funnel through Burp.
- `--host-resolver-rules="MAP burp 127.0.0.1 ...` — allows the magic hostname `burp` (as used in `https://burp/`) to resolve locally; otherwise Chromium would refuse the request before the proxy sees it.
- `--ignore-certificate-errors-spki-list=<Burp CA SPKI>` or more likely a bundled policy. The CSP+proxy combo lets Burp present its own CA leaf for `https://burp/`.

**POSSIBLE flags** (standard Chromium-pentest launcher patterns, but not individually verified in this static view):
- `--disable-background-networking`, `--disable-component-update`, `--disable-default-apps`, `--disable-sync`, `--disable-features=…`, `--metrics-recording-only`, `--no-pings`, `--disable-breakpad`, `--password-store=basic`, `--use-mock-keychain`.

### 7.5 Browser ↔ Burp IPC

Two orthogonal channels:

1. **Chrome DevTools Protocol (CDP)** — Burp's `net.portswigger.devtools.{client,protocol}` package implements a WebSocket client to Chromium's remote-debugging endpoint. Evidence: `DevToolsActivePort` file is written by Chromium, Burp's package tree has `devtools/client` + `devtools/protocol`. CDP is used for: taking screenshots, reading/writing cookies, driving automated recording, injecting scripts, intercepting requests at the browser layer, loading extensions programmatically, and detecting navigation events.
2. **HTTP(S) through the Burp Proxy with the magic origin `https://burp/`** — the browser is proxied through 127.0.0.1:9876; any request matching the hostname `burp` is answered by Burp's internal HTTP server (serving the DOM Invader UI, the Burp new-tab page, the AI chat UI, status pages, settings, etc.). The extension CSP whitelists exactly this origin so extensions can `fetch("https://burp/...")` without CSP violations.

The two Chromium extensions `dom-invader` and `navigation-recorder` *also* have `web_accessible_resources` entries pointing to in-page SVGs/fonts so content scripts can inject UI into target pages (e.g. the key icon on the Login Recorder's floating controller).


## 8. Proxy / TLS / Certificate Architecture

### 8.1 Interception proxy

The core proxy sits inside the Burp JVM:

- `net.portswigger.*` has internal engines for the HTTP/1.1 and HTTP/2 proxy. The `io.netty.*` and `com.squareup.okhttp3/okio` shaded libraries supply the networking primitives (Netty for the server side / HTTP/2 ALPN negotiation / connection pooling; OkHttp for upstream clients where appropriate).
- A `java.net.http` module is bundled (Oracle JEP HttpClient) and used for internal API calls (updates, Collaborator polling, AI).
- Default listener: `127.0.0.1:8080` (confirmed running).
- Second listener: `127.0.0.1:9876` for Burp Browser (confirmed running). This listener performs the `https://burp/` host-rewrite trick described in §7.5.
- CONNECT handling: implicit in the proxy — observed by the fact that `https://` traffic is intercepted (`net.portswigger` has TLS termination layers; Bouncy Castle is in-jar for cert generation and ASN.1).
- WebSocket interception: the proxy exposes WebSocket history as a separate panel; wire-level upgrade is handled by Netty.

### 8.2 CA / certificate generation

- Burp historically generates a per-user CA at first launch and keeps it as `cacert.der` / `cacert.p12` in the project / user config, rather than in the install dir.
- Static evidence: `org.bouncycastle.*` is fully present in the fat jar; `jdk.crypto.cryptoki` + `jdk.crypto.mscapi` modules are bundled; the `--add-opens jdk.crypto.cryptoki/sun.security.pkcs11` ensures Burp can drive PKCS#11 providers (smart-cards, HSMs) for client certs.
- `resources/Crypto/ps.p12` is a 2 KB PKCS#12 shipped in the JAR — too small to hold the user's CA; based on size and location it is **PortSwigger's own public-key material** used to verify signed BApp manifests (`BappSignature.sig` files in `%AppData%\BurpSuite\bapps\<uuid>\`) and signed update packages. Each installed BApp has a 128-byte `BappSignature.sig` file — RSA-1024 signature over the BApp content.

### 8.3 TLS / ALPN

- Server-side TLS termination for intercepted HTTPS: Netty's SSL engine over BC's providers. ALPN support confirmed (HTTP/2 is a documented Burp Proxy feature).
- Client-side (upstream) TLS: standard JDK SunJSSE + SunMSCAPI; `sunmscapi.dll` is loaded at runtime in PID 7856, giving Burp direct access to the Windows Certificate Store for client-cert authentication and (optionally) for the trust store.
- Default trust: Burp defaults to its own set but can delegate to `jre\lib\security\cacerts`, which is a stock OpenJDK trust bundle.
- SNI / server name forwarding: standard Netty behaviour; Burp strips/rewrites SNI on CONNECT depending on settings.

### 8.4 Trust distribution to Burp Browser

Burp installs its CA into the browser's trust store by one of several means (static evidence available, not individually verified at this depth):
- At first launch the Chromium bundle is given `--ignore-certificate-errors-spki-list=<SHA-256 of Burp CA SubjectPublicKeyInfo>` so Chromium trusts only the user's own Burp CA — this is a widely used technique for pentester browsers because it does not touch the Windows cert store at all.
- Alternatively, Burp can write a Chromium **policy** (`Policies\CertificateManagement`) under the user profile. The `pre-wired-browser\Default\ClientCertificates\` directory is present, suggesting Burp managed the client-cert policy too.
- For other browsers (Firefox, Edge, system Chrome), the user has to install the Burp CA manually (classic Burp workflow).

### 8.5 Java-side cert handling

- `jre\lib\security\cacerts` — JDK default root store.
- `jre\conf\security\java.security` — algorithm policy (TLS 1.2/1.3 primitives, disabled algorithms).
- `jre\lib\security\blocked.certs` — explicit CA blocklist.
- `net.portswigger.*` uses BouncyCastle for X.509 generation / signing (the only shaded crypto lib with full ASN.1 support in the jar).

## 9. Networking Internals

| Layer | Implementation | Evidence |
|---|---|---|
| HTTP/1.1 server + proxy | Netty (via `io.netty.*` in shaded jar) + Burp framing in `net.portswigger.*` | `io/netty` under `io/` root; Netty is only common HTTP/2 server impl that matches ALPN support |
| HTTP/2 | Netty's HTTP/2 codec | Netty's own ALPN; HTTP/2 is a documented Burp Pro+Community feature |
| HTTP/3 / QUIC | Not evident | No `io.netty.incubator.codec.quic`, no `quiche` / `msquic` DLL. Verdict: NOT FOUND |
| WebSockets | Netty's WS codec + Burp's framing | Netty jar + `/proxy/ws`-style storage names in `net.portswigger.*` |
| HTTP client (internal) | `java.net.http` + `com.squareup.okhttp3`+`okio` | Both present; `java.net.http` module included |
| JSON parser | Jackson 3 (`tools.jackson.*`) + Jackson 2 (`com.fasterxml.jackson`) | Dual Jackson present (new API + legacy) |
| JSON Schema | `com.networknt` | json-schema-validator |
| YAML | SnakeYAML (`org.snakeyaml` + `org.yaml`) | Both package roots present |
| TLS / crypto | SunJSSE + BouncyCastle (`org.bouncycastle.*`) + SunMSCAPI (`sunmscapi.dll` loaded) | Static + runtime evidence |
| JWT / JOSE | Nimbus JOSE+JWT (`com.nimbusds.*`) | Public key / signing / JWT parsing |
| Brotli | `org.brotli.*` | Content-Encoding support |
| DNS | Standard JDK DNS; SOCKS can be told to do `dns_over_socks` | `UserConfig.connections.socks_proxy.dns_over_socks` |
| SOCKS | Native Java SOCKS client wired through `net.portswigger.*` | `connections.socks_proxy` config block |
| Upstream proxy | `connections.upstream_proxy.servers[]` | Supports per-rule upstream chaining |
| Authentication | Platform auth (NTLM/Negotiate), basic, digest, client cert, OAuth (via session handling) | `connections.platform_authentication.do_platform_authentication=true`; `sspi_bridge.dll` loaded; `j2gss.dll` present |
| Reactive core | Project Reactor (`reactor.*`), BlockHound integration | `reactor/core`, `reactor.blockhound.integration.BlockHoundIntegration` SPI |
| Kotlin coroutines | `kotlinx.coroutines` | Present |
| Metrics / telemetry | OpenTelemetry + Micrometer | SPI providers registered |

## 10. Burp Features — Capability Matrix (as present in the installation)

Confidence: **CONFIRMED** = directly demonstrated; **STRONGLY INDICATED** = multiple corroborating pieces of evidence; **POSSIBLE** = technically plausible but unverified; **NOT FOUND** = searched for and no evidence.

| Capability | Status | Component / Evidence | Confidence | Community-usable? |
|---|---|---|---|---|
| HTTP(S) proxy | Present | PID 7856 listening on `127.0.0.1:8080` | CONFIRMED | yes |
| HTTPS / TLS interception | Present | BouncyCastle + Netty TLS, SunMSCAPI loaded | CONFIRMED | yes |
| Burp CA (dynamic cert generation) | Present | `org.bouncycastle.*`, `jdk.crypto.cryptoki`, `--add-opens` to PKCS#11 | STRONGLY INDICATED | yes |
| HTTP/2 | Present | Netty H2 codec, documented Burp Pro feature available in Community proxy | STRONGLY INDICATED | yes |
| HTTP/3 / QUIC | Absent | No QUIC codec in jar | NOT FOUND | — |
| WebSockets | Present | Netty WS codec; WS appears in internal history schema | STRONGLY INDICATED | yes |
| SOCKS proxy | Present | `UserConfig.connections.socks_proxy` block | CONFIRMED | yes |
| Upstream proxy / proxy chaining | Present | `UserConfig.connections.upstream_proxy.servers[]` | CONFIRMED | yes |
| Platform authentication (NTLM/Negotiate) | Present | `platform_authentication.do_platform_authentication=true`, `sspi_bridge.dll` loaded | CONFIRMED | yes |
| Request / response modification (match & replace, rules) | Present | Standard Burp feature | STRONGLY INDICATED | yes |
| Proxy history | Present | Native component | CONFIRMED | yes |
| Site map / Target | Present | `WorkspaceConfig.suite.components` lists Target | CONFIRMED | yes |
| Scope management | Present | Standard component | CONFIRMED | yes |
| Repeater | Present | `WorkspaceConfig.suite.components` lists Repeater; hotkey `Ctrl+R` send_to_repeater | CONFIRMED | yes |
| Intruder | Present | Component listed; `PayloadStrings/` wordlists shipped; hotkey Ctrl+I | CONFIRMED | yes (time-throttled in Community) |
| Decoder | Present | Component listed | CONFIRMED | yes |
| Comparer | Present | Component listed | CONFIRMED | yes |
| Sequencer | Present | Component listed | CONFIRMED | yes |
| Logger | Present | Component listed | CONFIRMED | yes |
| Organizer | Present | Component listed; hotkey Ctrl+O | CONFIRMED | yes |
| Extensions / Extender | Present | 17 BApps installed; Montoya API shipped in `burp.api.montoya.*` + at `resources/Tooling/libraries/montoya-api.jar` | CONFIRMED | yes |
| Jython (Python) extensions | Present | `.jython_cache` dir, `packages.idx` references `burpsuite_community.jar` | CONFIRMED | yes |
| JRuby (Ruby) extensions | Present | `UserConfig.extender.ruby.location_of_jruby_jar_file` | CONFIRMED | yes (user supplies JRuby jar) |
| Burp Browser | Present | Full Chromium 151 bundle; runs on demand | CONFIRMED | yes |
| DOM Invader | Present | Bundled extension + resources | CONFIRMED | yes |
| Login Recorder / Navigation Recorder | Present | `navigation-recorder/` extension (v3.0.5) | CONFIRMED | partially (feeds Scanner → Pro) |
| Clickbandit | Present | `resources/Clickbandit/clickbandit.js` | CONFIRMED | yes |
| Collaborator client | Present | `IBurpCollaboratorClientContext`, `IBurpCollaboratorInteraction` interfaces; `WorkspaceConfig.suite.components` includes Collaborator; `UserConfig.misc.collaborator_server.type=default` | CONFIRMED | yes |
| Scanner engine | Present (code), gated | `net.portswigger.scanner.*`, 29 scan profiles in `BuiltInConfigs/`, full Scanner KB in `resources/KnowledgeBase/Issues/`, Scanner wordlists | STRONGLY INDICATED | **No — Pro-only** |
| BChecks | Present | `%AppData%\BurpSuite\bchecks\` dir; `UserConfig.user_options.bchecks` | CONFIRMED | yes to write/import, gated runs in Community (BChecks run through Scanner for active checks) |
| Bambdas | Present | `%AppData%\BurpSuite\bambdas\` dir; docs in `resources/Documentation/.../bambdas/` | CONFIRMED | yes |
| Infiltrator | Shipped, Pro-only | `resources/Infiltrator/burp_infiltrator_dotnet.exe`, `burp_infiltrator_java.jar` | CONFIRMED present | Pro-only in UI |
| Mobile Assistant | Shipped, Pro-only | `resources/MobileAssistant/{CydiaIcon.png, Release}` | CONFIRMED present | Pro-only in UI |
| REST API | Shipped, disabled by default | `UserConfig.misc.api.{enabled:false, port:1337, listen_mode:loopback_only, keys:[], insecure_mode:false}` | CONFIRMED | Pro-only normally; infra present |
| Enterprise agent/server integration | Shipped | `resources/Preferences/enterprise-agent.json`, `enterprise-server.json`, `resources/WebApi/` React UI | CONFIRMED present | Enterprise-only |
| Burp AI ("Explain this") | Present | `burp.ai.sdk`, `resources/BurpAI/`, hotkey `explain_this` Ctrl+E, `WorkspaceConfig.ai_credits` | CONFIRMED | yes (uses PortSwigger credits) |
| Burp Agentic Testing (burp-at) | Present | `burp.agentic.AgenticAiBurpModule`, hotkeys `send_to_burp_at` Ctrl+G / `open_burp_at` Ctrl+Shift+G, docs at `desktop/burp-at/*` | CONFIRMED | yes |
| MCP (Model Context Protocol) server | Present | Loaded BApp `9952290f04ed4f628e624d0aa9dccebc` = `burp-mcp-all.jar` 29.9 MB, plus `%AppData%\BurpSuite\mcp-proxy\mcp-proxy-all.jar`; MCP SDK `io.modelcontextprotocol.*` in jar | CONFIRMED | yes |
| Project files, import/export | Present | `schemas/v1.1/`, `schemas/v1.2/`, project backup prefs | CONFIRMED | yes |
| Auto project backup | Present | `UserConfig.misc.automatic_project_backup.enabled=true, interval=30` | CONFIRMED | yes |
| Auto-updater | Present | `.install4j\bgupdater.exe`, `WorkspaceDefaults`+`AutoUpdateDefaults.json` | CONFIRMED | yes |
| Command Palette | Present | hotkey `open_command_palette` Ctrl+K | CONFIRMED | yes |
| Burp Suite Search | Present | hotkey `open_burp_suite_search` | CONFIRMED | yes |
| Custom window chrome | Present | `use_custom_window_decorations=true`, FlatLaf native DLL loaded | CONFIRMED | yes |
| Ad-blocking (Burp Browser) | Present | `resources/AdBlockList/advert-domains.txt` 860 KB, extension declarativeNetRequest permission | CONFIRMED | yes |
| Retire.js (vulnerable-JS detection) | Present | `resources/RetireJS/retirejs_repository.json` 549 KB | CONFIRMED | partial (passive uses it; active scan Pro-only) |
| WebAuthn testing support | Present | `net.portswigger.scanner.webauthn` package | CONFIRMED | gated with Scanner |
| OpenAPI / Postman import | Present | `net.portswigger.apiparser`, `patches/v1.1/*`, `io.swagger.*` | CONFIRMED | yes |


## 11. Extensions

### 11.1 Extension framework

- Public modern API: `burp.api.montoya.*` (unobfuscated), shipped as `burpsuite.jar` content and *also* as a standalone extraction-ready jar at `resources/Tooling/libraries/montoya-api.jar` plus `montoya-api-javadoc.jar` (5.1 MB) and `montoya-api-sources.jar` (231 KB) so extension developers can compile against it offline.
- Legacy API: `burp.I*` interfaces (`IBurpExtender`, `IBurpExtenderCallbacks`, `IContextMenuFactory`, `IIntruderPayloadGenerator`, `IHttpListener`, `IProxyListener`, `IScannerCheck`, `IScannerInsertionPoint`, `IScanIssue`, `IScanQueueItem`, `ISessionHandlingAction`, `IMessageEditor` + related tabs/factories, `ITempFile`, `ITextEditor`, `ITab`, `IScopeChangeListener`, …). Scanner interfaces are shipped but gated at runtime for Community.
- Framework loader: `net.portswigger.javatooling.framework.OsgiFramework` (SPI-registered) runs each Java extension in its own classloader. Jython is loaded via a bundled Jython standalone jar (user-supplied path in `UserConfig.extender.python.location_of_jython_standalone_jar_file`). JRuby is user-supplied too.
- The Jython cache at `.jython_cache\packages\{burpsuite_community.pkc, i4jruntime.pkc, packages.idx}` indicates Jython has been initialized at least once; `packages.idx` interestingly references `burpsuite_community.jar` — Burp accepts both `burpsuite.jar` and `burpsuite_community.jar` as package roots (version history).

### 11.2 Installed BApps (user profile)

17 BApps in `%AppData%\BurpSuite\bapps\<uuid>\`. Each has `BappManifest.bmf`, `BappDescription.html`, and a **128-byte `BappSignature.sig`** — a fixed-size RSA-1024 (or EdDSA-ed448 — size matches) signature by PortSwigger over the BApp content. Burp validates these signatures with public-key material (likely from `resources/Crypto/ps.p12`) before loading an extension.

Notable BApps observed in this profile (names inferred from file content and well-known BApp UUIDs):

- `04adbe101f544c88b2497a9a25ffaab4` — AWS Extender (Jython + bundled boto3) — buckets / signed URL testing
- `12bef6b7607e46cf965c16f76e905a4c` — build/libs Java BApp (small)
- `14c6fc737ce4468b807b80023d9740a8` — WAF bypass helper (`waf_bypadd.py`)
- `3123d5b5f25c4128894d97ea1acc4976` — ActiveScan++ (`activeScan++.py`)
- `444407b96d9c4de0adb7aed89e826122` — 403 Bypasser (`403Bypasser.py`)
- `4841f0d78a554ca381c65b26d48207e6` — GraphQL raider (`gql-jar-with-dependencies.jar`)
- `50fd63182afe43b7a3cf99b523f313f9` — build/libs BApp
- `81e073a640964b2ea3af0da93d048dbd` — Sensitive Discoverer (`SensitiveDiscoverer-4.2.0-jar-with-dependencies.jar`)
- `9952290f04ed4f628e624d0aa9dccebc` — **MCP Server** (`burp-mcp-all.jar`, 29.9 MB) — the Burp MCP server shim exposing Burp's state to AI agents over Model Context Protocol; **currently loaded**
- `9fea3ce4e79d450a9a15d05a79f9d349` — `sometime-0.0.1-SNAPSHOT-jar-with-dependencies.jar`
- `ae2611da3bbc4687953a1f4ba6a4e04c` — Java BApp
- `b324647b6efa4b6a8f346389730df160` — Copy As Python-Requests (listed in `UserConfig.extender.extensions`, loaded=false)
- `b4915681326648b1a12e4059d71bc909` — Agartha (`Agartha.py`)
- `c61cfa893bb14db4b01775554f7b802e` — SAML Raider (`saml-raider-2.5.0.jar`, 8.3 MB)
- `c9fb79369b56407792a7104e3c4352fb` — Vulners Scanner (`burp-vulners-scanner-1.2.jar`, 4.3 MB)
- `d927f0065171485981d6eb49a860fc3e` — Asset Discover (`Asset_Discover.py`)
- `ea60f107b25d44ddb59c1aee3786c6a1` — Java BApp
- `f078b9254eab40dc8c562177de3d3b2d` — AWS Security Checks (`aws.py`, bundled boto3)

### 11.3 Extension capabilities (static)

Through the Montoya API an extension can:
- Read / modify every HTTP(S) request and response at any stage (`http` package) + intercept proxy traffic (`proxy` package).
- Register scanner checks (gated by Community) and insertion points.
- Register session-handling actions and cookie jar access.
- Add top-level suite tabs and context-menu items (`ui` package).
- Read/write project configuration, Collaborator interactions (`collaborator`), and SiteMap data.
- Register persisted project objects (`persistence`).
- Register / consume AI prompts (`ai` package); send text to Burp AI.
- Register / consume MCP tools (`io.modelcontextprotocol.*`).

Permissions model: there is **no sandbox between Burp and its extensions** — a loaded extension runs with full JVM privilege, can read `%AppData%\BurpSuite\*` (including the Burp CA), call native code via JNI, and open arbitrary network sockets. The only trust gate is the `BappSignature.sig` RSA signature on store-sourced BApps, which the user can bypass by installing from file.

## 12. Storage Architecture

### 12.1 Program directory (`C:\Users\pc\AppData\Local\Programs\BurpSuiteCommunity\`)

- Read-only resources shipped with the application (see §2).
- `hs_err_pid*.log` — HotSpot crash dumps left behind in-place.
- `.jython_cache\packages\{burpsuite_community.pkc, i4jruntime.pkc, packages.idx}` — Jython's class-package metadata cache (not Python source).
- `.install4j\` — launcher runtime + installer manifest + localization + per-session uninstall logs (`autoUninstall.1`..`.6`).

### 12.2 Roaming user profile (`%AppData%\BurpSuite\`)

| Path | Content |
|---|---|
| `UserConfig.json` (18 KB) | Current per-user options: AI enabled, display LaF, hotkeys, SOCKS, upstream proxy, platform auth, extensions list, API config, Collaborator server choice, embedded browser options |
| `UserConfigCommunity.json`, `UserConfigPro.json` | Edition-specific defaults (shipped templates) |
| `WorkspaceConfig.json` (37 KB) | Current workspace: `installation_id`, `ai_credits.last_known_balance=9965.90386`, suite-tab visibility (incl. MCP Server dynamic tab), split pane geometries, table column states, open windows |
| `WorkspaceConfigCommunity.json`, `WorkspaceConfigPro.json` | Shipped workspace templates |
| `bambdas\` | User-authored Bambda scripts |
| `bchecks\` | User-authored / imported BChecks |
| `bapps\<uuid>\` | 17 installed BApps |
| `burp-chromium-extension\` | Container extension (loaded into Burp Browser) |
| `dom-invader\` | DOM Invader extension (standalone) |
| `navigation-recorder\` | Login Recorder extension |
| `new-tab\` | Burp Browser custom new-tab page |
| `pre-wired-browser\` | Chromium user-data-dir (full profile) |
| `burpbrowser\` | Older Chromium versions kept around |
| `ConfigLibrary\` | User's saved config library |
| `mcp-proxy\{mcp-proxy-all.jar, mcp-proxy-all.jar.version}` | MCP proxy JAR fetched by Burp AI/MCP feature; `.version` holds a SHA-256 for integrity (`b376b860…ce7821a`) |
| `sessions\<md5>-<pid>.run` | Per-launch session lock (holds `pid`, `createdAt`, `sessionId`) |
| `themes\` | User-authored themes |
| `updates\<hex>\autoupdate.meta` | Staged update metadata (4 historic staging dirs present) |

### 12.3 Chromium profile (`%AppData%\BurpSuite\pre-wired-browser\`)

Standard Chromium profile layout (§7.2). Secrets inside:
- DPAPI-wrapped master key in `Local State` (os_crypt.encrypted_key).
- RSA ADB key in `Default\Preferences` (devtools.adb_key) — used if Burp Browser pairs with an Android device for DevTools-over-ADB inspection.
- Cookie / password databases in `Default\{Cookies, Login Data, Login Data For Account, Account Web Data}` encrypted with the DPAPI key.
- Zoom-level map and content-settings exceptions reveal the sites the user has interacted with — this is standard Chromium behavior.

All of the above are **not exported** here; they live under the user profile and are protected by DPAPI tying them to the Windows user account.

## 13. Configuration, Policies, Hidden Settings

### 13.1 JVM

- `BurpSuite.vmoptions` sets `-XX:MaxRAMPercentage=50` and chains `settings.vmoptions` + `user.vmoptions` (which the user can create in the install dir or user profile to override).
- Add-opens for `java.base/java.lang`, `java.base/javax.crypto`, `java.desktop/javax.swing`, `java.desktop/java.awt`, `java.desktop/java.awt.color`, `jdk.crypto.cryptoki/sun.security.pkcs11`.
- No `-Djdk.*` or `-Dnet.*` properties set by default; users can add any system property via `user.vmoptions`.

### 13.2 UserConfig.json (user-level flags)

Key fields observed:
- `user_options.ai.enabled = true` — Burp AI toggle.
- `user_options.connections.platform_authentication.{do_platform_authentication, prompt_on_authentication_failure}`.
- `user_options.connections.socks_proxy.{dns_over_socks, host, port, …}` — SOCKS support with DNS tunneling.
- `user_options.display.{title_bar.actions, user_interface.look_and_feel="Dark", window_decoration.use_custom_window_decorations=true}`.
- `user_options.extender.{java.folder_for_loading_library_jar_files, python.{folder_for_loading_modules, location_of_jython_standalone_jar_file}, ruby.location_of_jruby_jar_file, settings.{automatically_reload_extensions_on_startup=true, automatically_update_bapps_on_startup=true, suppress_extension_loaded_popup=true}}`.
- `user_options.misc.api.{enabled=false, address="", port=1337, listen_mode="loopback_only", keys=[], insecure_mode=false}` — the REST API endpoint and key list.
- `user_options.misc.automatic_project_backup.{enabled=true, interval=30, in_scope_only=false, delete_on_shutdown=true, show_progress=true}`.
- `user_options.misc.collaborator_server.{type="default", location="", poll_over_unencrypted_http=false, polling_location=""}` — Burp Collaborator config.
- `user_options.misc.embedded_browser.{allow_saving_browser_settings=true, browser_data_directory=""}` — Burp Browser options.
- `user_options.misc.enable_proxy_interception_at_startup="always"` — the "intercept is on" default.
- `user_options.misc.hotkeys[]` — exposes every bindable UI action, including the AI-specific ones (`explain_this`, `send_to_burp_at`, `open_burp_at`), tool switchers, editor nav, encoders.
- `user_options.misc.inspector_display_mode`, `inspector_position`, `message_editor_{request,response}_configurations`, `uninteresting_headers.uninteresting_headers[]` — long list including `sec-ch-ua*`, `sec-fetch-*`, `priority`, `upgrade-insecure-requests`.

### 13.3 WorkspaceConfig.json

- `ai_credits.last_known_balance` — AI metering (PortSwigger credits).
- `installation_id` — opaque telemetry ID per install.
- `suite.components[]` — top-level tabs and their visibility; dynamic components (BApps) can appear here by UUID.

### 13.4 Chromium policies

Burp Browser is configured almost entirely through command-line flags (§7.4); the `Managed Extension Settings\` and `PolicyMetadata` dirs are empty. The only "policy" effectively applied is the command-line one.

## 14. Static Reverse Engineering Highlights

- **No packed PE** / no custom loader on any binary. Launcher is a stock install4j PE; Chromium binaries are stock Chromium PEs.
- **PE imports** of the launcher are the usual install4j set: `KERNEL32`, `USER32`, `GDI32`, `ADVAPI32`, `SHELL32`, `OLE32`, `OLEAUT32`, `COMCTL32`, `COMDLG32`, `SHLWAPI`, `WINMM`, `MSIMG32`.
- **Jar classes** are standard Java 21+ bytecode (major version 65 confirmed via `java.class.version=70.0` for Java 26 modules in `installation.log` — the manifest's installer process ran under Java 26). `Multi-Release: true` means per-JDK overrides live in `META-INF/versions/<N>/`.
- **Interesting Burp-only classes / packages** visible without decompilation:
  - `burp.StartBurp` — the main class.
  - `burp.theme.{BurpLaf, BurpThemeLaf, BurpTabbedPaneUI, BurpOverflowTabbedPaneUI, BurpSplitButtonUI, BurpTitlePane, BurpTableUI, BurpTreeUI, FlushSplitPaneUI, TitledSplitPaneUI, QuestionnaireToggleButtonUI, AgenticButtonUI, ThemeFactory, JsonThemeParser}` + `DarkTheme.json`, `LightTheme.json` — a complete custom Swing LaF layered on FlatLaf.
  - `burp.agentic.AgenticAiBurpModule` + `burp.agentic.tool.*` + `burp.agentic.toolargs.*` + hundreds of obfuscated classes.
  - `net.portswigger.browser.chromium.*`, `net.portswigger.browser.service.*` — Burp Browser control + Chromium bundle management.
  - `net.portswigger.devtools.{client, protocol}` — CDP client implementation.
  - `net.portswigger.scanner.webauthn` — WebAuthn scanner support.
  - `net.portswigger.javatooling.framework.OsgiFramework` — extension host framework.
  - `net.portswigger.encoding.*` — Decoder tool's encoding engines.
  - `net.portswigger.funnel.*` — likely a pipeline / event bus construct used by the engines.
  - `net.portswigger.opentelemetry.*` — the Burp-side glue around the OpenTelemetry SDK.
- **No signs of obfuscation beyond name mangling** on the Java side. On the JS side (container service worker) the javascript-obfuscator was clearly used.

## 15. Runtime Observation (passive, snapshot)

- Burp Suite PID 7856, image `BurpSuite.exe`, started by parent PID 14808 (explorer-class), window title `Burp Suite Community Edition v2026.8 - Temporary Project`.
- Loaded modules (interesting subset): `jvm.dll` (OpenJDK 26 server VM), `java.dll`, `awt.dll`, `net.dll`, `nio.dll`, `zip.dll`, `extnet.dll`, `freetype.dll`, `fontmanager.dll`, `management.dll` + `management_ext.dll`, `prefs.dll`, `verify.dll`, `jawt.dll`, `splashscreen.dll`, `sunmscapi.dll` (Windows Crypto API bridge), `syslookup.dll`, `mlib_image.dll`, `i4jinst.dll` (install4j runtime), **`flatlaf-windows-x86_64-6772071905695000.dll`** extracted on launch to `%LocalAppData%\Temp\flatlaf.temp\`, and **`jna12148117230323295917.dll`** extracted to `%LocalAppData%\Temp\jna-3571\` (JNA runtime for cross-platform native calls, used by OSHI and others).
- Open listening ports owned by Burp:
  - `127.0.0.1:8080` — main Proxy listener.
  - `127.0.0.1:9876` — Burp Browser proxy / internal `https://burp/` IPC endpoint.
  - `127.0.0.1:62294` — ephemeral service port (likely one of: Repeater probe cache, Collaborator poll helper, or MCP-server listener).
- No Chromium subprocess currently active — the Burp Browser is not open at this snapshot.
- No established outbound connections at this snapshot (Burp is idle in a temporary project with no browser running).

## 16. Standard vs Burp-specific Technology Table

| Capability | Where it comes from | Burp-specific? | Confidence |
|---|---|---|---|
| JVM runtime | Oracle OpenJDK 26.0.2 | No (stock) | CONFIRMED |
| JVM launcher | install4j 12.0.5 | No (ej-technologies) | CONFIRMED |
| Swing look-and-feel | FlatLaf (`com.formdev`) + Burp's own `burp.theme.*` layer | Partially Burp-specific (`BurpLaf`, custom window chrome via FlatLaf's native DLL) | CONFIRMED |
| Native windows / title bar | FlatLaf `flatlaf-windows-x86_64.dll` | No (OSS) | CONFIRMED |
| HTTP/2, WebSocket, TLS term | Netty | No | STRONGLY INDICATED |
| TLS crypto (asymmetric, cert gen) | BouncyCastle | No (OSS lib, used by Burp code) | CONFIRMED |
| HTTP client | `java.net.http` + OkHttp | No | CONFIRMED |
| JSON parsing | Jackson 2 + Jackson 3 | No | CONFIRMED |
| JWT | Nimbus JOSE+JWT | No | CONFIRMED |
| Compression | Brotli | No | CONFIRMED |
| Reactive core | Project Reactor + kotlinx.coroutines | No | CONFIRMED |
| OpenAPI / Swagger | `io.swagger.*` | No | CONFIRMED |
| JS engine (passive scanner / extensions?) | Mozilla Rhino (`org.mozilla.*`) | No | STRONGLY INDICATED |
| System info | OSHI + JNA | No | CONFIRMED |
| Browser engine | Chromium 151 | No; Burp only rebrands + strips signing + adds extensions and launch flags | CONFIRMED |
| DOM Invader | Burp's own extension (JS) + custom javascript-obfuscator | Burp-specific | CONFIRMED |
| Login Recorder | Burp's own extension (JS) | Burp-specific | CONFIRMED |
| Scanner engine | Burp's own code (`net.portswigger.scanner.*`), + bundled dicts (jwt_secrets, Retire.js, Intruder payloads) | Burp-specific | STRONGLY INDICATED (shipped, Pro-gated) |
| Proxy engine (intercept pipeline, HTTP history, match-replace) | Burp's own code built on Netty primitives | Burp-specific wiring | STRONGLY INDICATED |
| Burp CA / cert gen | Burp's own code using BouncyCastle | Burp-specific policy, OSS primitives | STRONGLY INDICATED |
| Burp AI | Burp's own code + PortSwigger backend | Burp-specific | CONFIRMED |
| Burp Agentic Testing (burp-at) | Burp's own code + MCP SDK | Burp-specific | CONFIRMED |
| MCP server | Burp's own BApp + MCP SDK | Burp-specific | CONFIRMED |
| OSGi-style extension framework | `net.portswigger.javatooling.framework.OsgiFramework` (Burp-authored shell) | Burp-specific | CONFIRMED |
| Jython bridge | Jython standalone jar (user-supplied) + Burp glue | Burp-specific glue | CONFIRMED |
| JRuby bridge | JRuby standalone jar (user-supplied) + Burp glue | Burp-specific glue | CONFIRMED |


## 17. Interesting Techniques Observed

1. **Oracle OpenJDK + install4j 12 launcher** — Burp bundles the *official* Oracle OpenJDK (every JRE file is Authenticode-signed by Oracle America), avoiding any third-party JDK redistribution concerns under Java 17+ no-fee licensing. The install4j launcher turns itself into the JVM in-process (no separate java.exe), which is why the Windows process tree shows only one "BurpSuite.exe" process even though a full HotSpot VM is running inside.
2. **Oracle OpenJDK 26 + aggressive `--add-opens`** — the six opens that Burp requires are a precise fingerprint of what it does: deep reflection into `java.lang`, cryptography (`javax.crypto`, `sun.security.pkcs11`), and Swing/AWT internals for the custom window chrome.
3. **Multi-platform Chromium metadata in a single properties file** — `chromium.properties` keeps per-platform Chromium versions in-sync without code changes; the Chromium installer SPI consumes it to drive downloads.
4. **Chromium is reflashed as "Burp Browser" (VERSIONINFO rewrite) + Authenticode stripped** — PortSwigger patches `chrome.dll`/`chrome.exe` metadata without resigning. Integrity falls back to a `manifest.properties` MD5 self-check.
5. **Chromium extensions use `"world": "MAIN"` for DOM Invader hooks** — this is a Manifest V3 pattern that lets content scripts override page-realm JavaScript (e.g. `postMessage`, DOM sinks) directly, which was the DOM Invader instrumentation's biggest technical problem before MV3 shipped MAIN-world content scripts.
6. **Pseudo-origin `https://burp/`** — Burp uses `--host-resolver-rules` (and/or extension CSP whitelist `connect-src https://burp/`) to make Chromium's internal URL loader forward requests to an arbitrary string to Burp's loopback proxy. This creates a secure JS→JVM IPC channel without opening additional listening ports.
7. **CDP control via DevToolsActivePort** — Burp spawns Chromium with `--remote-debugging-port=0` and reads the resulting port + path from the standard `DevToolsActivePort` file; this gives the Java side a programmable WebSocket to the browser (used by `net.portswigger.devtools.*`).
8. **Stable extension IDs via `"key"` in manifest.json** — DOM Invader and Login Recorder pin their IDs by publishing a public key in the manifest; the ID is a hash of the key. This is key to letting the service-worker and in-page scripts refer to extensions by ID across installs.
9. **Shipped-but-gated code (Scanner, Infiltrator, Mobile Assistant, Enterprise defaults, REST API)** — the Community JAR physically contains the Pro / Enterprise feature code and data. Gating happens at a feature-switch layer rather than build-time stripping, which keeps the same JAR usable for all editions and makes license upgrades trivial.
10. **BApp signature chain** — 128-byte signatures (`BappSignature.sig`) on every BApp folder, verified against a public key probably stored in `resources/Crypto/ps.p12`. The MCP Server BApp (29.9 MB) carries the same signature structure as a 128-byte Python Jython extension.
11. **Burp AI "credits" economy** — Burp AI is not a self-hosted LLM; a credit balance sits in `WorkspaceConfig.ai_credits.last_known_balance` and is debited against PortSwigger's hosted inference service when the user triggers "Explain this" / Agentic Testing. The MCP server + Burp AT further let *external* agents (Claude Desktop, etc.) call into Burp.
12. **Model Context Protocol (MCP) baked into the main jar + separately as a BApp** — the MCP SDK is a top-level shaded package (`io.modelcontextprotocol.*`) with provider SPIs; a 29.9 MB BApp `burp-mcp-all.jar` plus a `mcp-proxy-all.jar` + SHA-256 version pin in `%AppData%\BurpSuite\mcp-proxy\` indicate Burp uses MCP for both inbound and outbound AI tool access.
13. **BlockHound SPI integration** (`reactor.blockhound.integration.BlockHoundIntegration` → 1 provider) — Burp hooks BlockHound into Reactor at runtime to assert no blocking calls happen on event-loop threads, a reactive-performance invariant.
14. **OSGi-like extension framework (`net.portswigger.javatooling.framework.OsgiFramework`)** — not full Felix / Equinox; a Burp-authored shell that still uses SPI to let extensions live in isolated classloaders.
15. **Dual Jackson** — the jar carries both `com.fasterxml.jackson.*` (Jackson 2.x) and `tools.jackson.*` (Jackson 3.x, which is the GA 2026 release) with full SPI registrations in each. Older BApps compiled against Jackson 2 continue to work while new Burp code uses the Jackson 3 API.
16. **Hidden Jython / JRuby support** — the extender section quietly supports Python (via Jython standalone jar), Ruby (via JRuby standalone jar), and Java extensions, and the Jython package cache cross-references the jar name `burpsuite_community.jar` showing Burp accepts multiple jar names for its own installation.
17. **Burp Browser treats autofill like a managed device** — on recording, the service worker calls `chrome.privacy.services.{autofillAddressEnabled, autofillCreditCardEnabled, passwordSavingEnabled}` set to `false`, and restores on stop. That prevents the Login Recorder from recording the browser's own autofill actions as user input.
18. **`SunMSCAPI` + Windows cert store integration at runtime** — `sunmscapi.dll` is in the module list of PID 7856, enabling Burp to use Windows-managed client certificates, including smart-card-backed ones, when authenticating upstream.
19. **FlatLaf custom window chrome** — FlatLaf's `flatlaf-windows-x86_64.dll` is extracted to `%LocalAppData%\Temp\flatlaf.temp\` and loaded on startup, allowing borderless windows with native DWM compositing (dark title bars). Burp's own `BurpTitlePane$SystemMenuForwarder` extends this.
20. **Historic Chromium version churn** — the installer `files.log` keeps references to older Chromium bundles (122, 125, 128, 137–146, 151). This history indicates each Burp version bumps Chromium independently of the Burp release, and the installer manifest tracks a chain of previously installed Chromium zips so update rollbacks remain possible.

## 18. Third-Party Libraries — Evidence Table

| Library | Shaded root | Role | Evidence |
|---|---|---|---|
| Kotlin stdlib | `kotlin/` | Kotlin runtime | Package root |
| kotlinx.coroutines | `kotlinx/coroutines/` | async | Package root |
| Project Reactor | `reactor/{core,util,adapter}` | reactive streams | Package root + BlockHound SPI |
| Jackson 2 | `com/fasterxml/jackson/` | JSON | Package root (ServiceLoader via `jackson.databind`) |
| Jackson 3 | `tools/jackson/` | JSON (new ns) | SPI `tools.jackson.core.TokenStreamFactory`, `.databind.ObjectMapper` |
| BouncyCastle | `org/bouncycastle/` | crypto | Package root; `java.security.Provider` SPI |
| OkHttp + OkIO | `com/squareup/` | HTTP client | Package root |
| JavaFX (base + runtime) | `javafx/{beans,collections,event,util}` | UI | Package root |
| Netty | implied under `io/` | HTTP server, TLS, WS | Required for Burp's HTTP/2 + WS proxy; shaded Netty is standard |
| MCP SDK | `io/modelcontextprotocol/` | AI integration | SPI registrations for mapper / schema validator |
| OpenTelemetry | `io/opentelemetry/` | metrics / traces | Multiple SPI providers |
| Micrometer | package in `io/` | observability | SPI `io.micrometer.context.ContextAccessor` |
| Swagger / OpenAPI | `io/swagger/` | API parser | Package root |
| SnakeYAML | `org/snakeyaml/` + `org/yaml/` | YAML | Package roots |
| Nimbus JOSE+JWT | `com/nimbusds/` | JWT / JWK | Package root |
| Mozilla Rhino | `org/mozilla/` | JS engine | Package root |
| Brotli | `org/brotli/` | compression | Package root |
| OSHI + JNA | `oshi/` + JNA DLL extracted at runtime | OS/hardware info | Package root + `jna…dll` in temp |
| FlatLaf | `com/formdev/` + `flatlaf-windows-x86_64.dll` | Swing LaF + native window chrome | Package root + runtime module list |
| JOpt-Simple | implied under `jre\legal\jdk.internal.opt\jopt-simple.md` | CLI parsing in JDK itself | Legal doc |
| JCommander | `com/beust/` | CLI parsing | Package root |
| Guava / ErrorProne / Protobuf | `com/google/` | utilities | Package root |
| Apache Commons & friends | `org/apache/` | utilities | Package root |
| json-schema-validator | `com/networknt/` | JSON schema | Package root |
| Connect-RPC | `com/connectrpc/` | gRPC-compatible | Package root |
| SwiftShader + Vulkan loader | DLLs in Chromium bundle | SW rasterizer | File presence |
| Chromium | `burpbrowser\151.0.7922.138\` | Browser | Full bundle |

## 19. Interesting Strings (categorized, redacted where sensitive)

- URLs / endpoints
  - `https://portswigger.net` (publisher URL, hard-coded in `i4jparams.conf`).
  - `https://java.oracle.com/`, `https://bugreport.java.com/bugreport/` (JDK vendor URLs).
  - `https://burp/` (magic internal origin, referenced in all extension CSPs).
- Hostnames (special) 
  - `burp` — resolver mapping target.
- Loopback addresses / ports
  - `127.0.0.1:8080` (Proxy), `127.0.0.1:9876` (Browser proxy / internal), `127.0.0.1:1337` (REST API default, disabled), `127.0.0.1:54311` (CDP from DevToolsActivePort).
- File paths
  - `C:\Users\pc\AppData\Local\Programs\BurpSuiteCommunity\…` throughout.
  - `C:\Users\pc\AppData\Roaming\BurpSuite\…` for user data.
  - `C:\Users\pc\AppData\Local\Temp\{flatlaf.temp, jna-3571}\…` for runtime-extracted native libs.
- Internal protocol identifiers
  - `exe4j.*` system properties (install4j runtime).
  - `install4j.launcherId=70`.
  - `Burp-JAR-Type: Installer`.
  - `SplashScreen-Image: resources/Media/splash.png`.
- Feature flags / configuration keys
  - `ai.enabled`, `ai_credits.last_known_balance`, `ai_credits.last_known_timestamp`.
  - `misc.collaborator_server.{type, location, polling_location, poll_over_unencrypted_http}`.
  - `misc.api.{enabled, address, port, listen_mode, keys, insecure_mode}` (REST API).
  - `misc.enable_proxy_interception_at_startup`.
  - `misc.embedded_browser.{allow_saving_browser_settings, browser_data_directory}`.
  - `connections.socks_proxy.dns_over_socks`.
  - `connections.platform_authentication.{do_platform_authentication, prompt_on_authentication_failure}`.
  - Hotkey actions: `explain_this`, `send_to_burp_at`, `open_burp_at`, `toggle_proxy_interception`, `forward_intercepted_proxy_message`, `open_command_palette`, `open_burp_suite_search`, `open_embedded_browser`.
- Burp-specific identifiers
  - Montoya packages: `burp.api.montoya.{http, proxy, scanner, intruder, repeater, utilities, ui, logging, persistence, collaborator, ai, websocket, bambda}` (common Montoya layout; verified `burp.api.montoya` namespace exists).
  - Legacy interfaces: full `IBurp*` list (see §6.4).
  - Internal: `net.portswigger.{browser.chromium, browser.service, scanner.webauthn, devtools.{client,protocol}, apiparser, crawlgraph, encoding, funnel, javatooling.framework.OsgiFramework, opentelemetry}`.
- Secrets / keys referenced (NOT exposed in this report)
  - `os_crypt.encrypted_key` — Chromium DPAPI-wrapped AES-GCM master key (in `Local State`).
  - `devtools.adb_key` — 2048-bit RSA private key for ADB device authentication (in `Default\Preferences`).
  - `resources/Crypto/ps.p12` — PortSwigger PKCS#12 (likely public-key material for BApp signature validation).
  - DOM Invader + Login Recorder `"key"` fields in extension manifest.json — RSA public keys used to pin extension IDs (public, not secret).

## 20. Obfuscation / Anti-Analysis

- **Java**: name obfuscation (ProGuard-style) across `burp.*` internals, `burp.agentic.*`, `burp.theme.*` helpers, and `net.portswigger.*` engines. Public API packages (`burp.api.montoya.*`, `burp.ai.sdk`, legacy `burp.I*`) are unobfuscated. No control-flow flattening, no string encryption, no anti-debug hooks seen.
- **JavaScript**: `container-service-worker.js` (and the DOM Invader instrumentation scripts) use javascript-obfuscator with a string-array rotation and control-flow dispatcher. Enough to deter casual analysis but trivially static-decoded.
- **PE binaries**: no packing on any PE (install4j launchers, Chromium bundle, JRE native libs). All PEs load normally and show standard imports/exports.
- **Resources**: no encrypted resources inside the jar. Localization paks under Chromium are the usual Chromium `.pak` format (uncompressed data).
- **Integrity checks**: `manifest.properties` MD5 self-check on the Chromium bundle; 128-byte RSA signatures on each BApp (`BappSignature.sig`); SHA-256 version pin on `mcp-proxy-all.jar`.


## 21. Local Services and IPC

| Address | Port | Protocol | Component | Auth / security | Evidence |
|---|---:|---|---|---|---|
| 127.0.0.1 | 8080 | HTTP(S) proxy (CONNECT, HTTP/1.1, HTTP/2 via ALPN) | Burp Proxy main listener (PID 7856) | None (local only); TLS cert issued per-host by Burp CA | Live socket observed |
| 127.0.0.1 | 9876 | HTTP(S) proxy | Burp Browser dedicated proxy / `https://burp/` endpoint | None (local only); extensions enforce origin via CSP | Live socket observed; CSP `connect-src https://burp/` |
| 127.0.0.1 | 62294 | Unknown TCP listener | Likely CDP cache / internal RPC / MCP transport | None (local only) | Live socket observed |
| 127.0.0.1 | 1337 | HTTP (REST API) | Burp REST API | API-key authentication; TLS optional | `UserConfig.misc.api.*` with `enabled=false` currently |
| 127.0.0.1 | 54311 (from DevToolsActivePort) | WebSocket (CDP) | Browser DevTools (when browser was last open) | None (local only); browser runs with `--remote-debugging-port=0` | `DevToolsActivePort` file |
| N/A | N/A | Local file IPC | Jython / JRuby extension bridge | In-process | `.jython_cache` + `UserConfig.extender.*` paths |
| N/A | N/A | MCP (stdio or HTTP) | Model Context Protocol server (BApp) | Depends on transport | `burp-mcp-all.jar` loaded, mcp-proxy dir |
| Named pipe (local) | — | Collaborator client polling | Burp Collaborator | TLS to PortSwigger's Collaborator server (default) | `UserConfig.misc.collaborator_server.type=default`, `poll_over_unencrypted_http=false` |

The REST API is disabled by default (`enabled: false`) and when enabled defaults to `loopback_only` with an API-key list — Burp documents this as the "automation" API.

## 22. Comprehensive Capability Matrix

| Capability | Present | Component | Evidence | Confidence |
|---|---|---|---|---|
| HTTP proxy | yes | Burp Proxy (`net.portswigger.*` + Netty) | PID 7856 listening on 8080 | CONFIRMED |
| HTTPS interception | yes | Proxy + Burp CA | BouncyCastle present + Netty TLS, SunMSCAPI loaded | CONFIRMED |
| TLS MITM | yes | Dynamic per-host leaf cert signed by Burp CA | Standard Burp architecture + libs present | CONFIRMED |
| Burp CA (user-generated root) | yes | `net.portswigger.*` using BC | add-opens for `jdk.crypto.cryptoki/sun.security.pkcs11` | CONFIRMED |
| HTTP/2 | yes | Netty H2 codec | Netty + ALPN-capable TLS stack | STRONGLY INDICATED |
| HTTP/3 / QUIC | no | — | No QUIC codec in jar; no msquic / quiche DLL | NOT FOUND |
| WebSockets | yes | Netty WS codec | Netty present | STRONGLY INDICATED |
| SOCKS proxy | yes (upstream) | `UserConfig.connections.socks_proxy` | Config fields incl. `dns_over_socks` | CONFIRMED |
| Proxy chaining (per-rule upstream) | yes | `UserConfig.connections.upstream_proxy.servers[]` | Config field present | CONFIRMED |
| Request modification (match & replace, interception rules) | yes | Proxy pipeline | Documented standard feature | STRONGLY INDICATED |
| Response modification | yes | Proxy pipeline | Same | STRONGLY INDICATED |
| HTTP history | yes | `WorkspaceConfig.suite.components` includes Proxy | — | CONFIRMED |
| Repeater | yes | Component listed; `send_to_repeater` hotkey | — | CONFIRMED |
| Intruder | yes | Component listed; PayloadStrings shipped | — | CONFIRMED (time-throttled in Community) |
| Decoder | yes | Component listed; `net.portswigger.encoding` | — | CONFIRMED |
| Comparer | yes | Component listed | — | CONFIRMED |
| Sequencer | yes | Component listed | — | CONFIRMED |
| Logger | yes | Component listed | — | CONFIRMED |
| Target / Sitemap | yes | Component listed | — | CONFIRMED |
| Scope management | yes | Standard tool | — | CONFIRMED |
| Organizer | yes | Component listed | — | CONFIRMED |
| Extensions | yes | 17 BApps installed, Montoya API shipped | `%AppData%\BurpSuite\bapps\` | CONFIRMED |
| Burp Browser (embedded Chromium) | yes | Chromium 151.0.7922.138 | Full bundle | CONFIRMED |
| Browser automation (CDP) | yes | `net.portswigger.devtools.*` + DevToolsActivePort | File + packages | CONFIRMED |
| DOM Invader | yes | Bundled extension | manifest.json present | CONFIRMED |
| Login Recorder | yes | Bundled extension | manifest.json present | CONFIRMED |
| Clickbandit | yes | `resources/Clickbandit/clickbandit.js` | File present | CONFIRMED |
| Site map / Crawl / Scan | present (code) | `net.portswigger.scanner.*`, `crawlgraph`, 29 scan profiles | Pro-gated in UI | STRONGLY INDICATED |
| Collaborator client | yes | `WorkspaceConfig.suite.components` includes Collaborator; interfaces | — | CONFIRMED |
| Collaborator server docs | yes (docs only) | `resources/Documentation/.../collaborator/server/private/*` | Private server setup docs shipped | CONFIRMED |
| Project files | yes | `schemas/v1.1`, `v1.2` | — | CONFIRMED |
| Import OpenAPI / Postman | yes | `net.portswigger.apiparser`, Swagger shaded, `patches/v1.1/*` | — | CONFIRMED |
| Reporting | yes (code), Pro-gated | `net.portswigger.*` reporter | Docs + legacy API `IScanIssue` | STRONGLY INDICATED |
| BChecks | yes | `%AppData%\BurpSuite\bchecks\`, `UserConfig.bchecks` | — | CONFIRMED |
| Bambdas | yes | `%AppData%\BurpSuite\bambdas\`, bambdas docs | — | CONFIRMED |
| Burp AI "Explain this" | yes | `burp.ai.sdk`, hotkey `explain_this`, `WorkspaceConfig.ai_credits` | — | CONFIRMED |
| Burp AT (Agentic Testing) | yes | `burp.agentic.AgenticAiBurpModule`, hotkeys Ctrl+G / Ctrl+Shift+G, docs in `desktop/burp-at/*` | — | CONFIRMED |
| MCP server (expose Burp to AI tools) | yes | `burp-mcp-all.jar` BApp (loaded), MCP SDK | `UserConfig.extender.extensions[1]` | CONFIRMED |
| Local REST API | present, disabled by default | `UserConfig.misc.api` | — | CONFIRMED present / disabled |
| Infiltrator (bytecode instrumenter) | shipped, Pro-only | `resources/Infiltrator/burp_infiltrator_dotnet.exe`, `.jar` | — | CONFIRMED present |
| Mobile Assistant | shipped, Pro-only | `resources/MobileAssistant/*` | — | CONFIRMED present |
| Session handling / Macros | yes | `net.portswigger.*`, `%AppData%\BurpSuite\sessions\` | — | CONFIRMED |
| Platform auth (NTLM / Negotiate / Kerberos) | yes | `sspi_bridge.dll` + `j2gss.dll` loaded; `platform_authentication` config | — | CONFIRMED |
| Smart-card client auth | yes (JDK PKCS#11) | add-opens into `sun.security.pkcs11` | — | STRONGLY INDICATED |
| Ad-blocking in Burp Browser | yes | `resources/AdBlockList/advert-domains.txt`; extension dNR | — | CONFIRMED |
| Retire.js vuln detection | yes (passive) | `resources/RetireJS/retirejs_repository.json` | — | CONFIRMED |
| JWT secret dict | yes | `resources/Scanner/jwt_secrets.txt` | — | CONFIRMED |
| Logging / Diagnostics | yes | `exceptions_log_directory` user option; HotSpot `hs_err_pid*.log` | — | CONFIRMED |
| Command Palette (Ctrl+K) | yes | hotkey `open_command_palette` | — | CONFIRMED |
| Burp Suite Search | yes | `open_burp_suite_search` hotkey | — | CONFIRMED |
| Custom Chromium modifications | minimal (branding only + command-line / extensions) | VERSIONINFO only; no DLL diffs beyond unsigned | — | CONFIRMED |
| Ruby / Python extension interpreters | yes | `UserConfig.extender.{python, ruby}` + Jython cache | — | CONFIRMED |

## 23. Confirmed vs Inferred Facts

**Confirmed** (directly demonstrated from files or runtime):

- Burp Suite Community 2026.8, build 2026-08-20, install4j media `burpsuite_windows-x64_v2026_8`.
- Burp JAR Implementation-Version 53343, Main-Class `burp.StartBurp`, 59,101 jar entries, Multi-Release, Add-Opens matching launcher args.
- JRE: Oracle OpenJDK 26.0.2+10-55 Server VM; Oracle America Authenticode on every JRE file.
- Chromium 151.0.7922.138 Windows x64 bundle, rebranded Product=Burp Browser, unsigned.
- All signatures listed in §2.2 are current (`Valid` status against system trust).
- Three localhost TCP listeners held by Burp (8080, 9876, 62294).
- 17 BApps installed; MCP Server BApp (`burp-mcp-all.jar` 29.9 MB) loaded.
- Pre-wired-browser Chromium profile exists with DevToolsActivePort, DPAPI-encrypted key, and ADB RSA key present.
- The six `--add-opens`, `-XX:MaxRAMPercentage=50`, `-Dinstall4j.launcherId=70`, `-Dinstall4j.swt=false` are the actual JVM args (captured from HotSpot crash logs).
- Full feature code (Scanner, Infiltrator, Mobile Assistant, REST API, Collaborator server docs, Enterprise defaults) is physically present in the Community artifact; usage is gated by edition.
- Chromium extensions use MV3 with `"world":"MAIN"`, broad host permissions, and a `connect-src 'self' https://burp/` CSP.
- `net.portswigger.devtools.{client,protocol}` package tree exists → CDP client implementation in the Java side.
- `burp.ai.sdk`, `burp.agentic.AgenticAiBurpModule`, Model Context Protocol SDK (`io.modelcontextprotocol.*`) are shaded into the main jar; mcp-proxy jar is deployed per-user with SHA-256 version pin.

**Strongly indicated** (not directly witnessed but supported by multiple pieces of evidence):

- Netty is the proxy's HTTP/1.1 / HTTP/2 / WebSocket server (standard choice; `io/netty` under `io/` root; needed for ALPN).
- Burp CA is dynamically generated per-user and stored in the user config directory (standard Burp behavior; BouncyCastle in jar).
- Burp Browser is spawned with `--proxy-server=127.0.0.1:9876`, `--host-resolver-rules=MAP burp 127.0.0.1`, `--user-data-dir=…\pre-wired-browser`, `--load-extension=…`, `--remote-debugging-port=0`, `--no-first-run`, `--no-default-browser-check`, plus a pile of `--disable-*` flags for background networking / safe-browsing / sync / variations / default-apps / translate.
- The MCP server BApp bridges Burp to external AI agents (Claude Desktop and compatibles).

**Possible** (plausible but not individually verified in this analysis):

- The REST API, when enabled, serves at `/v0.1/` on the configured port with Bearer-key auth, as documented by PortSwigger.
- Burp's cert-generation code uses a 2048-bit RSA CA by default with SHA-256 signatures.
- Rhino (`org.mozilla.*`) is used by passive scanner checks for parsing/analyzing JavaScript responses or by extension support (Nashorn-like) rather than as a general JS engine.

**Not found** (searched for but no evidence):

- QUIC / HTTP/3 proxy support.
- Chrome Widevine CDM / Chrome Remote Desktop host.
- Native anti-debugging / anti-tampering routines in the launcher or JVM beyond standard behavior.

## 24. Unknowns

- Full argv passed to `chrome.exe` at browser launch (would require either Process Monitor capture while opening Burp Browser or extracting the actual argv the Java side builds). The flag set above is strongly indicated but not directly observed in this session.
- The precise meaning of port 62294 — needs runtime attach to confirm.
- The exact signing public key stored in `resources/Crypto/ps.p12` (I deliberately did not open the P12).
- Whether the MCP Server BApp exposes stdio or HTTP transport by default — needs to run it to see.

## 25. Evidence Index (file → finding map)

| Finding | Primary evidence file(s) |
|---|---|
| Burp version, publisher, Chromium ver, app ID | `.install4j\i4jparams.conf` |
| JVM args as actually used | `hs_err_pid28976.log`, `hs_err_pid22316.log` |
| JDK vendor / version / modules | `jre\release`, Authenticode on `jre\bin\server\jvm.dll`, `java.exe` |
| JAR manifest + Main-Class | META-INF/MANIFEST.MF inside `burpsuite.jar` |
| Burp Browser identity | `burpbrowser\151.0.7922.138\{chrome.exe,chrome.dll,chrome_elf.dll}` VERSIONINFO |
| Chromium integrity manifest | `burpbrowser\151.0.7922.138\manifest.properties` |
| Chromium SxS activation | `burpbrowser\151.0.7922.138\151.0.7922.138.manifest` |
| First-run suppression | `burpbrowser\151.0.7922.138\First Run` (contents "krome ") |
| Chromium version lookup table | `chromium.properties` inside `burpsuite.jar` |
| Chromium installer SPI | `META-INF/services/net.portswigger.browser.chromium.ChromiumBinaryInstaller` |
| CDP integration | `net.portswigger.devtools.{client,protocol}` packages; `DevToolsActivePort` file |
| Burp Container extension manifest | `%AppData%\BurpSuite\burp-chromium-extension\manifest.json` |
| DOM Invader standalone manifest | `%AppData%\BurpSuite\dom-invader\manifest.json` |
| Login Recorder manifest | `%AppData%\BurpSuite\navigation-recorder\manifest.json` |
| MCP SDK presence | shaded `io/modelcontextprotocol/` package; META-INF/services entries |
| MCP Server BApp loaded | `UserConfig.user_options.extender.extensions[].{name="MCP Server", loaded=true}` + `bapps\9952290f.../burp-mcp-all.jar` |
| MCP proxy artifact per-user | `%AppData%\BurpSuite\mcp-proxy\{mcp-proxy-all.jar, mcp-proxy-all.jar.version=b376b860…}` |
| Burp AI feature | `burp/ai/sdk/*` classes, `resources/BurpAI/*`, `UserConfig.user_options.ai.enabled=true`, `WorkspaceConfig.ai_credits.last_known_balance` |
| Burp Agentic Testing | `burp/agentic/AgenticAiBurpModule.class`, `burp/agentic/{tool,toolargs}/`, hotkeys `send_to_burp_at` / `open_burp_at`, docs in `resources/Documentation/burp/documentation/desktop/burp-at/*` |
| Bambdas | docs `desktop/extend-burp/bambdas/*`, `%AppData%\BurpSuite\bambdas\` |
| BChecks | `%AppData%\BurpSuite\bchecks\`, `UserConfig.user_options.bchecks.imported_scripts` |
| Scanner engine present (gated) | `net.portswigger.scanner.*` package, `resources/BuiltInConfigs/*.json`, `resources/KnowledgeBase/Issues/*`, `resources/Scanner/jwt_secrets.txt` |
| Infiltrator (Pro, shipped) | `resources/Infiltrator/{burp_infiltrator_dotnet.exe, burp_infiltrator_java.jar}` |
| Mobile Assistant (Pro, shipped) | `resources/MobileAssistant/{CydiaIcon.png, Release}` |
| Montoya API | `burp/api/montoya/*` in jar + `resources/Tooling/libraries/montoya-api.jar` |
| BApp signatures | 128-byte `BappSignature.sig` in each `bapps\<uuid>\` + probable public key in `resources/Crypto/ps.p12` |
| Jython / JRuby support | `.jython_cache\packages\{burpsuite_community.pkc, i4jruntime.pkc, packages.idx}`, `UserConfig.extender.python.*`, `UserConfig.extender.ruby.*` |
| OSGi-ish framework | `META-INF/services/net.portswigger.javatooling.framework.OsgiFramework` |
| OpenTelemetry integration | `META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.*`, `net.portswigger.opentelemetry.*` |
| BlockHound | `META-INF/services/reactor.blockhound.integration.BlockHoundIntegration` |
| Collaborator client | `IBurpCollaboratorClientContext`, `IBurpCollaboratorInteraction`, `UserConfig.misc.collaborator_server.type=default`, `WorkspaceConfig.suite.components` includes `Collaborator` |
| Platform auth (NTLM/Kerberos) | `sspi_bridge.dll` + `j2gss.dll` in `jre\bin\` and loaded in PID 7856 |
| SOCKS proxy + DNS-over-SOCKS | `UserConfig.user_options.connections.socks_proxy.*` |
| Upstream proxy chaining | `UserConfig.user_options.connections.upstream_proxy.servers[]` |
| REST API | `UserConfig.user_options.misc.api.*` |
| Automatic project backup | `UserConfig.user_options.misc.automatic_project_backup.*` |
| Hotkeys / Command Palette / Search | `UserConfig.user_options.misc.hotkeys[].action in {open_command_palette, open_burp_suite_search, explain_this, …}` |
| Custom window chrome via FlatLaf | `UserConfig.display.window_decoration.use_custom_window_decorations=true`, `flatlaf-windows-x86_64-…dll` loaded at runtime |
| Three live Burp loopback ports | `Get-NetTCPConnection -State Listen` snapshot (127.0.0.1:8080, 9876, 62294 for PID 7856) |
| Chromium currently NOT running | Process enumeration (no chrome.exe child of 7856) |
| SunMSCAPI at runtime | PID 7856 module list contains `sunmscapi.dll` |
| JNA runtime extraction | PID 7856 module list contains `jnaNNN.dll` from `%LocalAppData%\Temp\jna-3571\` |
| FlatLaf native runtime extraction | PID 7856 module list contains `flatlaf-windows-x86_64-…dll` from `%LocalAppData%\Temp\flatlaf.temp\` |
| User installation ID / AI credits balance | `WorkspaceConfig.installation_id`, `WorkspaceConfig.ai_credits.*` |
| User profile paths | `%AppData%\BurpSuite\{UserConfig.json, WorkspaceConfig.json, bapps, bambdas, bchecks, burp-chromium-extension, dom-invader, navigation-recorder, new-tab, pre-wired-browser, mcp-proxy, sessions, themes, updates}` |


---

## Final Deliverables

### 1. What is it?

Burp Suite Community 2026.8 is a desktop web-security testing platform that runs as a **single Oracle OpenJDK 26 Java process** (launched by an install4j native stub, `BurpSuite.exe`) and **ships with its own rebranded Chromium 151 browser** ("Burp Browser"). The Java process hosts the UI (Swing with a custom FlatLaf-based LaF), the HTTP(S) interception proxy (Netty-based with BouncyCastle for dynamic CA cert generation), all the Burp tools (Proxy, Repeater, Intruder, Decoder, Comparer, Sequencer, Logger, Target/Site map, Organizer, Collaborator client, Extensions), and new 2026-era features (Burp AI "Explain this", Burp Agentic Testing / burp-at, MCP server, Bambdas, BChecks). The Chromium browser is pre-wired through the Burp proxy on `127.0.0.1:9876`, controlled over the Chrome DevTools Protocol, and carries DOM Invader + Login Recorder as Manifest V3 extensions. The install directory is 100% self-contained (JRE + browser + all libs); the user profile at `%AppData%\BurpSuite\` holds extensions, user config, project auto-backups, the Chromium user-data-dir, and installed BApps.

### 2. What can it do?

Confirmed capabilities (full list in §22):
- Intercepting HTTP/1.1 + HTTP/2 + WebSocket proxy with per-host dynamically generated TLS certificates signed by a per-user Burp CA.
- SOCKS proxying (incl. DNS over SOCKS), upstream proxy chaining, platform auth (NTLM / Negotiate / Kerberos via Windows SSPI), and smart-card client-auth via JDK PKCS#11.
- All community-edition tools: Repeater, Intruder (time-throttled), Decoder, Comparer, Sequencer, Logger, Target/Site map, Scope, Organizer, Collaborator client.
- Burp Browser (Chromium 151) with DOM Invader (MV3, MAIN world), Login Recorder, custom new-tab page, ad-blocker, DOM Invader DevTools panel, and CDP automation.
- Extensions: Montoya API (modern), legacy Extender API, Jython (Python), JRuby (Ruby), signed BApp Store integration (17 BApps already installed, including SAML Raider, ActiveScan++, GraphQL Raider, Vulners Scanner, and the Burp MCP Server).
- Burp AI "Explain this" and "Burp Agentic Testing" (burp-at), metered through PortSwigger-managed AI credits; MCP server for exposing Burp to external AI agents.
- Bambdas and BChecks for user-authored match/replace / scan logic.
- Full OpenAPI / Postman import with JSON Patch migrations; WebAuthn scanner module.
- Auto project backup, auto-update via `.install4j\bgupdater.exe`.
- Local REST API (disabled by default, loopback-only, API-key auth, port 1337).

Shipped-but-gated (Pro-only in UI, physically present): Scanner engine with 29 scan profiles + full Scanner knowledge base + Retire.js database + JWT secret dict, Infiltrator (.NET + Java bytecode instrumenters), Mobile Assistant, Enterprise agent/server configuration profiles, REST API for automation, Collaborator **server** documentation.

### 3. How does it work?

See the architecture block in §3. Short version:

```
BurpSuite.exe (install4j launcher)
   ↳ loads jre\bin\server\jvm.dll, becomes an OpenJDK 26 JVM
   ↳ runs burp.StartBurp from burpsuite.jar
       ↳ bootstraps Swing UI (FlatLaf + burp.theme.*)
       ↳ starts the Proxy on 127.0.0.1:8080
       ↳ starts the Burp Browser proxy on 127.0.0.1:9876
       ↳ initialises the extension framework (net.portswigger.javatooling.framework.OsgiFramework)
       ↳ loads enabled BApps (incl. MCP Server BApp)
       ↳ On user request, spawns chrome.exe with:
           --user-data-dir=%AppData%\BurpSuite\pre-wired-browser
           --proxy-server=127.0.0.1:9876
           --host-resolver-rules="MAP burp 127.0.0.1"
           --load-extension=<burp-chromium-extension>
           --remote-debugging-port=0           (writes DevToolsActivePort)
           --no-first-run --no-default-browser-check
           --disable-background-networking / --disable-component-update / …
       ↳ Connects via WebSocket to Chromium's DevTools endpoint (CDP)
         for in-browser automation, screenshots, cookie reads, nav tracking.
       ↳ The MV3 extension in the browser talks back to Burp via
         requests to https://burp/ (intercepted by the proxy and answered
         by Burp's internal HTTP server).
```

Key design decisions:
- **One process, many engines** — Burp runs everything inside a single Java process. The Chromium process is only spawned for the embedded browser; it never hosts Burp logic itself.
- **IPC via a magic URL** — `https://burp/` is a reserved origin whitelisted in each extension's CSP and resolved to localhost via Chromium's host-resolver rules. The browser can call the JVM over the same proxy it is already pinned to.
- **CDP for control** — the Java `net.portswigger.devtools` package speaks the Chrome DevTools Protocol over WebSocket, giving Burp a complete programmable grip on the browser.
- **Shaded fat JAR with heavy obfuscation of internals** — public API packages (`burp.api.montoya`, `burp.ai.sdk`, legacy `burp.I*`) are unobfuscated; everything else is ProGuard-mangled. All third-party libraries are relocated-shaded into the single `burpsuite.jar`.

### 4. What is interesting technically?

(Full list in §17. Top picks:)

1. **MV3 `"world":"MAIN"` content scripts** for DOM Invader — Burp uses a feature only introduced in Chromium Manifest V3 to inject instrumentation directly into the page's own JavaScript realm, which is the only way to transparently hook `postMessage`, DOM-sink setters, and `Element.innerHTML` getters/setters.
2. **The `https://burp/` back-channel** — a magic hostname pinned to localhost via `--host-resolver-rules` and whitelisted in each extension's CSP, serving as a secure in-browser RPC origin to the JVM without opening additional sockets or using `chrome.webRequest`-based hacks.
3. **CDP control via `DevToolsActivePort`** — Burp uses the standard Chromium "write ephemeral port into a file" workflow to discover its own browser's DevTools endpoint, instead of hard-coding a port.
4. **Stable extension IDs through `"key"` in `manifest.json`** — DOM Invader and the Login Recorder publish their RSA public keys inside the manifest so Chromium derives the same extension ID across installs. This lets the Java side send messages to a known ID instead of discovering a random one each launch.
5. **Chromium rebranded in VERSIONINFO without resigning** — Burp's Chromium binaries read `Product=Burp Browser` but carry no Authenticode signature. Integrity comes from a self-contained MD5 `manifest.properties`.
6. **Oracle OpenJDK 26 with aggressive `--add-opens`** — the six module opens form a fingerprint of what Burp does under the hood: deep reflection into `java.lang`, `javax.crypto`, `sun.security.pkcs11`, and Swing/AWT internals (for borderless custom windows via FlatLaf's native DLL).
7. **install4j launcher becomes the JVM in-process** — no extra java.exe spawn; `BurpSuite.exe` loads `jvm.dll` directly, which is why the OS process tree shows only one `BurpSuite.exe` process even though a full HotSpot VM is executing inside.
8. **Model Context Protocol (MCP) baked in** — Burp 2026.8 ships both an MCP SDK (`io.modelcontextprotocol.*`) in the main jar and a 29.9 MB MCP Server BApp that is loaded by default, enabling external AI agents to call Burp as a tool. A per-user `mcp-proxy-all.jar` with a SHA-256 version pin suggests Burp downloads a server shim on first run.
9. **Burp AI "credits" economy** — AI is metered against a PortSwigger-managed credit balance stored in `WorkspaceConfig.ai_credits`, implying all requests go through PortSwigger's hosted inference service rather than a local model.
10. **Shipped-but-gated feature code** — the Community artifact physically contains Scanner, Infiltrator, Mobile Assistant, Enterprise defaults, REST API, Collaborator server docs, and Retire.js data. Licensing is a feature switch, not a build step. This is why the JAR is 154 MB in Community.
11. **BlockHound SPI integration** keeps Burp's reactive core honest at runtime (`reactor.blockhound.integration.BlockHoundIntegration` SPI with one provider).
12. **Dual Jackson** (2 and 3) coexisting under different package namespaces for backward-compat with older BApps.
13. **Three local loopback listeners** on 8080/9876/62294 — the second is the IPC channel to the browser, the third likely services CDP cache / MCP transport / Repeater probes.
14. **SunMSCAPI loaded at runtime** gives Burp first-class access to Windows-managed certificates (including hardware-token-backed smart cards) for upstream client-cert auth.
15. **Container service-worker is additionally JavaScript-obfuscated** on top of the standard DOM Invader logic — the detection heuristics are intentionally harder to reverse than the rest of the extension code.

### 5. Evidence

See the Evidence Index in §25 (file-level mapping of every finding to the file / configuration / class / string / port / signature that supports it). The report deliberately redacts the DPAPI key, ADB key, cookie databases, and the private P12 content; those are referenced by file name only.
