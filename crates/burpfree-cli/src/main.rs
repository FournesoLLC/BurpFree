//! BurpFree headless CLI.
//!
//! Covers: project create / open, proxy run, CA export, history
//! inspect, scan passive, repeater send, and ad-hoc utility commands.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use burpfree_ca::CertificateAuthority;
use burpfree_core::events::{EventBus, EventKind};
use burpfree_core::ids::TrafficId;
use burpfree_core::traffic::{Request, Transaction};
use burpfree_engines::client::{HttpClient, HttpClientConfig};
use burpfree_engines::scanner::passive;
use burpfree_proxy::{Interceptor, MatchReplaceEngine, ProxyServer, ServerConfig, Upstream};
use burpfree_storage::{HistoryFilter, Project};
use clap::{Parser, Subcommand};
use parking_lot::RwLock;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "burpfree", about = "Open, original web-security testing platform.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Project operations.
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Certificate authority operations.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Launch the intercepting proxy for a project.
    Proxy {
        #[arg(long)]
        project: PathBuf,
        /// Override the first listener address.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Inspect HTTP history.
    History {
        #[arg(long)]
        project: PathBuf,
        #[command(subcommand)]
        action: HistoryAction,
    },
    /// Run passive scanner over existing history.
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },
    /// Repeater: send a request straight through, no proxy.
    Send {
        /// URL to send a GET to.
        url: String,
        /// Request method.
        #[arg(long, default_value = "GET")]
        method: String,
        /// Add a header `Name: value`.
        #[arg(long, short = 'H')]
        header: Vec<String>,
        /// Body data.
        #[arg(long, short = 'd')]
        data: Option<String>,
    },
    /// Encode/decode utilities (one-shot).
    Codec {
        #[command(subcommand)]
        action: CodecAction,
    },
    /// Export findings to HTML / JSON / SARIF.
    Report {
        #[arg(long)]
        project: PathBuf,
        /// Output format.
        #[arg(long, default_value = "html")]
        format: String,
        /// Output file. Use `-` for stdout.
        #[arg(long, short = 'o')]
        out: PathBuf,
        /// Only include findings at this severity or higher.
        #[arg(long)]
        min_severity: Option<String>,
    },
    /// Continuous-integration entrypoints.
    Ci {
        #[command(subcommand)]
        action: CiAction,
    },
    /// Import an API definition (OpenAPI 3 JSON/YAML or Postman v2.1).
    Import {
        #[arg(long)]
        project: PathBuf,
        /// Path to the definition file.
        file: PathBuf,
        /// Format hint: `auto`, `openapi` or `postman`.
        #[arg(long, default_value = "auto")]
        format: String,
        /// Record every imported endpoint as a Transaction (no response).
        /// Useful so passive detectors / Target map pick them up.
        #[arg(long, default_value_t = true)]
        record: bool,
    },
    /// Pack a project directory into a portable .burpfree bundle.
    Export {
        #[arg(long)]
        project: PathBuf,
        /// Output path for the bundle.
        #[arg(long, short = 'o')]
        out: PathBuf,
        /// Include the CA private key. DANGEROUS: anyone with the
        /// bundle can forge trusted certs for projects importing it.
        #[arg(long, default_value_t = false)]
        include_ca_key: bool,
        /// Skip the extensions/ directory.
        #[arg(long, default_value_t = false)]
        no_extensions: bool,
        /// Skip the blobs directory (history will reference missing bodies).
        #[arg(long, default_value_t = false)]
        no_blobs: bool,
        /// Store entries uncompressed (faster, larger).
        #[arg(long, default_value_t = false)]
        no_compress: bool,
    },
    /// Unpack a .burpfree bundle into a new project directory.
    ImportBundle {
        /// Bundle to extract.
        file: PathBuf,
        /// Destination directory. Must be empty or missing.
        #[arg(long)]
        dest: PathBuf,
    },
    /// Import a HAR 1.2 archive (Chrome / Firefox / Playwright) into history.
    ImportHar {
        #[arg(long)]
        project: PathBuf,
        /// Path to the .har file.
        file: PathBuf,
    },
    /// Export the project's history to a HAR 1.2 archive.
    ExportHar {
        #[arg(long)]
        project: PathBuf,
        /// Output path for the .har file.
        #[arg(long, short = 'o')]
        out: PathBuf,
    },
    /// Run a Model Context Protocol server over stdio, exposing BurpFree
    /// capabilities to AI clients (Claude Desktop, Cline, etc.).
    Mcp {
        #[arg(long)]
        project: PathBuf,
    },
}

#[derive(Subcommand)]
enum CiAction {
    /// Run passive scanning over the project history and exit with
    /// `1` if any finding at or above `--fail-on` is present.
    ///
    /// Writes a report alongside so the pipeline has artifact output.
    Scan {
        #[arg(long)]
        project: PathBuf,
        /// Minimum severity that fails the build: info|low|medium|high|critical.
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Report format to emit: html|json|sarif|markdown.
        #[arg(long, default_value = "sarif")]
        report_format: String,
        /// Output file (default: `./burpfree-report.{ext}`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also persist new findings into the project database.
        #[arg(long, default_value_t = true)]
        save: bool,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Create a new project directory.
    New {
        path: PathBuf,
    },
    /// Print project info.
    Info {
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Export the project root CA certificate.
    Export {
        #[arg(long)]
        project: PathBuf,
        #[arg(long, default_value = "burpfree-ca.pem")]
        out: PathBuf,
    },
    /// Print CA info.
    Info {
        #[arg(long)]
        project: PathBuf,
    },
}

#[derive(Subcommand)]
enum HistoryAction {
    /// List recent transactions.
    List {
        #[arg(long, default_value = "20")]
        limit: i64,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        in_scope: bool,
    },
    /// Count all transactions matching filter.
    Count {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
    },
    /// Show one transaction (raw request + response).
    Show {
        id: i64,
    },
    /// Delete all transactions.
    Clear,
}

#[derive(Subcommand)]
enum ScanAction {
    /// Run passive scanner over every transaction in the project history.
    Passive {
        #[arg(long)]
        project: PathBuf,
        #[arg(long, default_value = "false")]
        save: bool,
    },
}

#[derive(Subcommand)]
enum CodecAction {
    UrlEncode { s: String },
    UrlDecode { s: String },
    Base64Encode { s: String },
    Base64Decode { s: String },
    HexEncode { s: String },
    HexDecode { s: String },
    JwtDecode { token: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // All tracing goes to stderr. The MCP sub-command uses stdout exclusively
    // for JSON-RPC frames, so mixing tracing into stdout would corrupt the
    // protocol stream.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Project { action } => project_cmd(action).await,
        Command::Ca { action } => ca_cmd(action).await,
        Command::Proxy { project, listen } => proxy_cmd(project, listen).await,
        Command::History { project, action } => history_cmd(project, action).await,
        Command::Scan { action } => scan_cmd(action).await,
        Command::Send { url, method, header, data } => send_cmd(url, method, header, data).await,
        Command::Codec { action } => codec_cmd(action).await,
        Command::Report { project, format, out, min_severity } =>
            report_cmd(project, format, out, min_severity).await,
        Command::Ci { action } => ci_cmd(action).await,
        Command::Import { project, file, format, record } =>
            import_cmd(project, file, format, record).await,
        Command::Export { project, out, include_ca_key, no_extensions, no_blobs, no_compress } =>
            export_cmd(project, out, include_ca_key, no_extensions, no_blobs, no_compress).await,
        Command::ImportBundle { file, dest } =>
            import_bundle_cmd(file, dest).await,
        Command::ImportHar { project, file } =>
            import_har_cmd(project, file).await,
        Command::ExportHar { project, out } =>
            export_har_cmd(project, out).await,
        Command::Mcp { project } => mcp_cmd(project).await,
    }
}

// --- MCP server --------------------------------------------------------

async fn mcp_cmd(project: PathBuf) -> Result<()> {
    use std::sync::Arc;
    let p = Project::open(&project)?;
    let server = Arc::new(burpfree_mcp::McpServer::new(Arc::new(p)));
    eprintln!("burpfree-mcp: project ready at {}", project.display());
    eprintln!("burpfree-mcp: speaking JSON-RPC over stdio (newline-delimited)");
    burpfree_mcp::stdio_loop(server).await?;
    Ok(())
}

// --- Bundle import/export ---------------------------------------------

async fn export_cmd(
    project: PathBuf,
    out: PathBuf,
    include_ca_key: bool,
    no_extensions: bool,
    no_blobs: bool,
    no_compress: bool,
) -> Result<()> {
    let opts = burpfree_storage::BundleOptions {
        compress: !no_compress,
        include_ca_key,
        include_extensions: !no_extensions,
        include_blobs: !no_blobs,
    };
    let summary = burpfree_storage::export_project(&project, &out, opts)?;
    println!("bundle written to {}", summary.out_path.display());
    println!("  entries        : {}", summary.file_count);
    println!("  logical bytes  : {}", summary.total_bytes);
    println!("  on-disk bytes  : {}", summary.out_bytes);
    println!("  schema         : {}", summary.manifest.schema);
    println!("  project name   : {}", summary.manifest.project_name);
    if summary.manifest.includes_ca_key {
        println!("  WARNING: this bundle contains the CA private key.");
    }
    Ok(())
}

async fn import_bundle_cmd(file: PathBuf, dest: PathBuf) -> Result<()> {
    let manifest = burpfree_storage::import_project(&file, &dest)?;
    println!("imported into {}", dest.display());
    println!("  schema         : {}", manifest.schema);
    println!("  tool           : {} {}", manifest.tool, manifest.tool_version);
    println!("  project name   : {}", manifest.project_name);
    println!("  entries recorded: {}", manifest.entry_count);
    if manifest.includes_ca_key {
        println!("  note: CA private key present — trust implications apply.");
    }
    Ok(())
}

async fn import_har_cmd(project: PathBuf, file: PathBuf) -> Result<()> {
    let p = Project::open(&project)?;
    let summary = burpfree_storage::import_har(&file, &p.history, &p.blobs)?;
    println!("imported {} entries from {}", summary.imported, file.display());
    if summary.skipped > 0 {
        println!("  skipped: {}", summary.skipped);
        for e in summary.errors.iter().take(5) {
            println!("    - {}", e);
        }
    }
    Ok(())
}

async fn export_har_cmd(project: PathBuf, out: PathBuf) -> Result<()> {
    let p = Project::open(&project)?;
    let summary = burpfree_storage::export_har(&out, &p.history, &p.blobs, None)?;
    println!(
        "wrote {} entries ({} bytes) to {}",
        summary.entries,
        summary.bytes_written,
        out.display()
    );
    Ok(())
}

// --- API import --------------------------------------------------------

async fn import_cmd(project: PathBuf, file: PathBuf, format: String, record: bool) -> Result<()> {
    let p = Project::open(&project)?;
    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("read {}", file.display()))?;
    let (fmt, items) = match format.as_str() {
        "openapi" => (burpfree_api::ImportFormat::OpenApi, burpfree_api::openapi::parse(&text)?),
        "postman" => (burpfree_api::ImportFormat::Postman, burpfree_api::postman::parse(&text)?),
        _ => burpfree_api::import_auto(&text)?,
    };
    eprintln!("imported {} endpoint(s) as {:?}", items.len(), fmt);
    for item in &items {
        let req = match item.to_request() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  skip {} {}: {e}", item.method, item.url);
                continue;
            }
        };
        println!("{:<6} {}", req.method, req.url());
        if record {
            let wire = req.to_wire_bytes();
            let req_blob = p.blobs.put(&wire)?;
            let tx = burpfree_core::traffic::Transaction::new(req);
            p.history.upsert_transaction(&tx, &req_blob, None)?;
        }
    }
    Ok(())
}

// --- Reporting ---------------------------------------------------------

async fn report_cmd(
    project: PathBuf,
    format: String,
    out: PathBuf,
    min_severity: Option<String>,
) -> Result<()> {
    let p = Project::open(&project)?;
    let findings = filter_by_min_severity(p.history.list_findings()?, min_severity.as_deref());
    let ctx = burpfree_report::ReportContext {
        project: p.config.name.clone(),
        project_root: Some(p.root.display().to_string()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        findings,
    };
    emit_report(&ctx, &format, &out)?;
    Ok(())
}

fn emit_report(ctx: &burpfree_report::ReportContext, format: &str, out: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let format = format.to_ascii_lowercase();
    let mut writer: Box<dyn Write> = if out == std::path::Path::new("-") {
        Box::new(std::io::stdout().lock())
    } else {
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        Box::new(std::fs::File::create(out)?)
    };
    match format.as_str() {
        "html" => burpfree_report::write_html(ctx, &mut writer)?,
        "json" => burpfree_report::write_json(ctx, &mut writer)?,
        "sarif" => burpfree_report::write_sarif(ctx, &mut writer)?,
        "markdown" | "md" => burpfree_report::write_markdown(ctx, &mut writer)?,
        "csv" => burpfree_report::write_csv(ctx, &mut writer)?,
        other => anyhow::bail!("unknown format: {other} (use html|json|sarif|markdown|csv)"),
    }
    if out != std::path::Path::new("-") {
        eprintln!("report written to {}", out.display());
    }
    Ok(())
}

fn filter_by_min_severity(
    findings: Vec<burpfree_storage::StoredFinding>,
    min: Option<&str>,
) -> Vec<burpfree_storage::StoredFinding> {
    let min_rank = severity_rank(min.unwrap_or("info"));
    findings
        .into_iter()
        .filter(|f| severity_rank(&f.severity) >= min_rank)
        .collect()
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// --- CI ----------------------------------------------------------------

async fn ci_cmd(action: CiAction) -> Result<()> {
    match action {
        CiAction::Scan { project, fail_on, report_format, out, save } => {
            let p = Project::open(&project)?;
            // Load extensions so custom passive rules contribute to CI scans too.
            let extensions = burpfree_extensions::load_builtins(&p.root)?;
            let custom_rules = extensions.passive_rules();
            // Reuse the passive scan over existing history.
            let rows = p.history.list(&burpfree_storage::HistoryFilter {
                limit: Some(100_000),
                ..Default::default()
            })?;
            let mut found = 0usize;
            for r in rows {
                let Some(req_blob) = p.history.get_request_blob(r.id)? else { continue; };
                let Some(req_bytes) = p.blobs.get(&req_blob)? else { continue; };
                let resp_bytes = if let Some(rb) = p.history.get_response_blob(r.id)? {
                    p.blobs.get(&rb)?
                } else { None };
                let tx = rebuild_transaction(&r, &req_bytes, resp_bytes.as_deref())?;
                for f in burpfree_engines::scanner::passive::run_all_with_rules(&tx, &custom_rules) {
                    found += 1;
                    if save {
                        let mut mapped = finding_to_stored(&f);
                        mapped.transaction_id = Some(tx.id);
                        p.history.upsert_finding(&mapped)?;
                    }
                }
            }
            let findings = p.history.list_findings()?;
            let threshold = severity_rank(&fail_on);
            let failing: Vec<&burpfree_storage::StoredFinding> =
                findings.iter().filter(|f| severity_rank(&f.severity) >= threshold).collect();
            let ext = match report_format.as_str() {
                "html" => "html",
                "json" => "json",
                _ => "sarif",
            };
            let out_path = out.unwrap_or_else(|| PathBuf::from(format!("burpfree-report.{ext}")));
            let ctx = burpfree_report::ReportContext {
                project: p.config.name.clone(),
                project_root: Some(p.root.display().to_string()),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                findings: findings.clone(),
            };
            emit_report(&ctx, &report_format, &out_path)?;
            let mut counts = std::collections::BTreeMap::new();
            for f in &findings {
                *counts.entry(f.severity.clone()).or_insert(0usize) += 1;
            }
            eprintln!(
                "scanned {found} finding(s) during this run; project total: {} across {} severity classes",
                findings.len(),
                counts.len()
            );
            for sev in ["critical", "high", "medium", "low", "info"] {
                if let Some(n) = counts.get(sev) {
                    eprintln!("  {sev}: {n}");
                }
            }
            if !failing.is_empty() {
                eprintln!(
                    "FAIL: {} finding(s) at or above `{}`",
                    failing.len(),
                    fail_on
                );
                std::process::exit(1);
            }
            eprintln!("PASS: no findings at or above `{fail_on}`");
            Ok(())
        }
    }
}

async fn project_cmd(a: ProjectAction) -> Result<()> {
    match a {
        ProjectAction::New { path } => {
            let p = Project::create(&path).with_context(|| format!("create {}", path.display()))?;
            // Also materialise the CA so first-run is painless.
            let _ca = CertificateAuthority::load_or_create(p.ca_dir())?;
            println!("project created at {}", p.root.display());
            println!("  listener: {}", p.config.listeners[0].address);
            println!("  CA path:  {}", p.ca_dir().join("ca-cert.pem").display());
        }
        ProjectAction::Info { path } => {
            let p = Project::open(&path)?;
            let hist = p.history.count(&HistoryFilter::default())?;
            println!("project       : {}", p.root.display());
            println!("name          : {}", p.config.name);
            println!("listeners     : {}", p.config.listeners.len());
            println!("transactions  : {hist}");
            println!("scope rules   : {}", p.config.scope.rules.len());
        }
    }
    Ok(())
}

async fn ca_cmd(a: CaAction) -> Result<()> {
    match a {
        CaAction::Export { project, out } => {
            let p = Project::open(&project)?;
            let ca = CertificateAuthority::load_or_create(p.ca_dir())?;
            ca.export_root(&out)?;
            println!("CA exported to {}", out.display());
        }
        CaAction::Info { project } => {
            let p = Project::open(&project)?;
            let ca = CertificateAuthority::load_or_create(p.ca_dir())?;
            let info = ca.info();
            println!("subject     : {}", info.subject);
            println!("serial      : {}", info.serial);
            println!("not before  : {}", info.not_before);
            println!("not after   : {}", info.not_after);
            println!("fingerprint : {}", info.sha256_fingerprint);
        }
    }
    Ok(())
}

async fn proxy_cmd(project: PathBuf, listen: Option<String>) -> Result<()> {
    let mut p = Project::open(&project)?;
    if let Some(addr) = listen {
        if !p.config.listeners.is_empty() {
            p.config.listeners[0].address = addr;
            p.save_config()?;
        }
    }
    let ca = CertificateAuthority::load_or_create(p.ca_dir())?;
    let bus = EventBus::default();
    let interceptor = Interceptor::new();
    let upstream = Arc::new(RwLock::new(Upstream {
        url: p.config.upstream.url.clone(),
        username: p.config.upstream.username.clone(),
        password: p.config.upstream.password.clone(),
    }));
    let scope = Arc::new(RwLock::new(p.config.scope.clone()));
    let match_replace = Arc::new(RwLock::new(MatchReplaceEngine::new()));
    let sink: Arc<dyn burpfree_proxy::server::TrafficSink> =
        Arc::new(RecordingSink::new(p.history.clone(), p.blobs.clone()));
    let host_entries: Vec<burpfree_core::net::HostOverride> = p
        .config
        .host_overrides
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();
    let host_overrides = burpfree_core::net::HostOverrides::load(host_entries);
    let cfg = ServerConfig {
        listeners: p.config.listen_addrs(),
        ca,
        upstream,
        scope,
        match_replace,
        interceptor,
        events: bus.clone(),
        sink,
        decompression_cap_bytes: p.config.decompression_cap_mb as usize * 1024 * 1024,
        max_body_bytes: p.config.max_body_mb as u64 * 1024 * 1024,
        connect_timeout: Duration::from_secs(30),
        // CLI runs headless with no AppState — build a one-shot
        // AtomicBool from the project config value. Live-reload
        // doesn't apply here since there's no UI to flip the toggle;
        // operators adjust record_out_of_scope by editing config.json
        // and restarting the daemon.
        record_out_of_scope: std::sync::Arc::new(
            std::sync::atomic::AtomicBool::new(p.config.record_out_of_scope),
        ),
        host_overrides,
        tls_passthrough: std::sync::Arc::new(parking_lot::RwLock::new(
            p.config.tls_passthrough.clone(),
        )),
        // CLI is headless — load the stored platform-auth
        // credentials once; no UI to flip them so there's nothing
        // to live-reload against.
        platform_auth: std::sync::Arc::new(parking_lot::RwLock::new(
            p.config
                .platform_auth
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect(),
        )),
    };
    let handle = ProxyServer::start(cfg).await?;
    // Tail event bus.
    let mut sub = bus.subscribe();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down …");
            handle.shutdown().await?;
        }
        _ = async {
            while let Some(ev) = sub.recv().await {
                match ev.kind {
                    EventKind::Transaction { id } => println!("[tx]  id={id}"),
                    EventKind::Log { source, level, message } => println!("[{level}] ({source}) {message}"),
                    EventKind::Intercept { id, direction } => println!("[intercept] {direction} id={id}"),
                    _ => {}
                }
            }
        } => {}
    };
    println!("stats: {:?}", handle.stats());
    Ok(())
}

async fn history_cmd(project: PathBuf, a: HistoryAction) -> Result<()> {
    let p = Project::open(&project)?;
    match a {
        HistoryAction::List { limit, host, method, in_scope } => {
            let f = HistoryFilter {
                host_contains: host,
                method,
                in_scope_only: in_scope,
                limit: Some(limit),
                ..Default::default()
            };
            let rows = p.history.list(&f)?;
            for r in rows {
                println!(
                    "{:>8} {} {:<6} {:<32} {}  ({} ms)",
                    r.id,
                    r.method,
                    r.status.map(|s| s.to_string()).unwrap_or_else(|| "---".into()),
                    truncate(&format!("{}://{}:{}", r.scheme, r.host, r.port), 32),
                    truncate(&r.path, 60),
                    r.elapsed_ms.unwrap_or(0),
                );
            }
        }
        HistoryAction::Count { host, method } => {
            let f = HistoryFilter { host_contains: host, method, ..Default::default() };
            println!("{}", p.history.count(&f)?);
        }
        HistoryAction::Show { id } => {
            let id = TrafficId::from(id);
            if let Some(summary) = p.history.get_summary(id)? {
                println!("# transaction {}", summary.id);
                if let Some(blob) = p.history.get_request_blob(id)? {
                    if let Some(data) = p.blobs.get(&blob)? {
                        println!("== REQUEST ==");
                        println!("{}", String::from_utf8_lossy(&data));
                    }
                }
                if let Some(blob) = p.history.get_response_blob(id)? {
                    if let Some(data) = p.blobs.get(&blob)? {
                        println!("== RESPONSE ==");
                        println!("{}", String::from_utf8_lossy(&data));
                    }
                }
            } else {
                anyhow::bail!("transaction {id} not found");
            }
        }
        HistoryAction::Clear => {
            p.history.clear()?;
            println!("history cleared");
        }
    }
    Ok(())
}

async fn scan_cmd(a: ScanAction) -> Result<()> {
    match a {
        ScanAction::Passive { project, save } => {
            let p = Project::open(&project)?;
            let rows = p.history.list(&HistoryFilter { limit: Some(100_000), ..Default::default() })?;
            let mut findings = 0usize;
            for r in rows {
                let Some(req_blob) = p.history.get_request_blob(r.id)? else { continue; };
                let Some(req_bytes) = p.blobs.get(&req_blob)? else { continue; };
                let resp_bytes = if let Some(rb) = p.history.get_response_blob(r.id)? {
                    p.blobs.get(&rb)?
                } else { None };
                let tx = rebuild_transaction(&r, &req_bytes, resp_bytes.as_deref())?;
                let found = passive::run_all(&tx);
                findings += found.len();
                for f in &found {
                    println!(
                        "[{}][{}] {}  (tx #{})",
                        f.severity.as_label(),
                        f.detector,
                        f.title,
                        tx.id
                    );
                    if save {
                        p.history.upsert_finding(&finding_to_stored(&f))?;
                    }
                }
            }
            println!("scan complete: {findings} finding(s)");
        }
    }
    Ok(())
}

async fn send_cmd(
    url: String,
    method: String,
    headers: Vec<String>,
    data: Option<String>,
) -> Result<()> {
    let mut req = Request::new(&method, &url)?;
    for h in headers {
        if let Some(i) = h.find(':') {
            req.headers.add(h[..i].trim().to_string(), h[i + 1..].trim().to_string());
        }
    }
    if let Some(body) = data {
        req.set_text(&body);
    }
    let client = HttpClient::new(HttpClientConfig::default());
    let resp = client.send(&req).await?;
    println!("HTTP/{} {} {}", match resp.http_version {
        burpfree_core::traffic::HttpVersion::Http10 => "1.0".to_string(),
        _ => "1.1".into(),
    }, resp.status, resp.reason);
    for h in resp.headers.iter() {
        println!("{}: {}", h.name, h.value);
    }
    println!();
    println!("{}", resp.text());
    println!("[{} bytes, {} ms]", resp.body.len(), resp.elapsed_ms);
    Ok(())
}

async fn codec_cmd(a: CodecAction) -> Result<()> {
    use burpfree_codec::*;
    match a {
        CodecAction::UrlEncode { s } => println!("{}", text::url_encode(&s)),
        CodecAction::UrlDecode { s } => println!("{}", text::url_decode(&s)?),
        CodecAction::Base64Encode { s } => println!("{}", text::base64_encode(s.as_bytes())),
        CodecAction::Base64Decode { s } => {
            let b = text::base64_decode(&s)?;
            print!("{}", String::from_utf8_lossy(&b));
        }
        CodecAction::HexEncode { s } => println!("{}", text::hex_encode(s.as_bytes())),
        CodecAction::HexDecode { s } => {
            let b = text::hex_decode(&s)?;
            print!("{}", String::from_utf8_lossy(&b));
        }
        CodecAction::JwtDecode { token } => {
            let p = jwt_decode(&token)?;
            println!("{}", serde_json::to_string_pretty(&p)?);
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn rebuild_transaction(
    row: &burpfree_storage::StoredSummary,
    req_bytes: &[u8],
    resp_bytes: Option<&[u8]>,
) -> Result<Transaction> {
    let mut req = Request::new(&row.method, &format!("{}://{}:{}{}", row.scheme, row.host, row.port, row.path))?;
    req.id = row.id;
    req.body = find_body(req_bytes).to_vec();
    req.headers = burpfree_core::headers::Headers::parse_block(header_block(req_bytes));
    let mut t = Transaction::new(req);
    t.in_scope = row.in_scope;
    if let Some(bytes) = resp_bytes {
        let mut r = burpfree_core::traffic::Response::new(row.status.unwrap_or(0));
        r.headers = burpfree_core::headers::Headers::parse_block(header_block(bytes));
        r.body = find_body(bytes).to_vec();
        t.response = Some(r);
    }
    Ok(t)
}

fn header_block(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        // Skip the first line (start-line).
        if let Some(nl) = bytes[..idx].iter().position(|&b| b == b'\n') {
            &bytes[nl + 1..idx]
        } else {
            &bytes[..idx]
        }
    } else {
        &[]
    }
}

fn find_body(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        &bytes[idx + 4..]
    } else {
        &[]
    }
}

/// Sink that writes transactions to the project's SQLite + blob store.
struct RecordingSink {
    history: burpfree_storage::HistoryStore,
    blobs: Arc<burpfree_storage::BlobStore>,
}

impl RecordingSink {
    fn new(history: burpfree_storage::HistoryStore, blobs: Arc<burpfree_storage::BlobStore>) -> Self {
        Self { history, blobs }
    }
}

#[async_trait::async_trait]
impl burpfree_proxy::server::TrafficSink for RecordingSink {
    async fn record(&self, tx: Transaction) -> Result<()> {
        let req_wire = tx.request.to_wire_bytes();
        let req_blob = self.blobs.put(&req_wire)?;
        let resp_blob = if let Some(r) = &tx.response {
            Some(self.blobs.put(&r.to_wire_bytes())?)
        } else {
            None
        };
        self.history
            .upsert_transaction(&tx, &req_blob, resp_blob.as_ref())?;
        Ok(())
    }
}




fn finding_to_stored(
    f: &burpfree_engines::scanner::Finding,
) -> burpfree_storage::history::StoredFinding {
    let now = burpfree_core::traffic::now_ms();
    burpfree_storage::history::StoredFinding {
        id: f.id,
        ts_ms: now,
        transaction_id: f.transaction_id,
        detector: f.detector.clone(),
        title: f.title.clone(),
        description: f.description.clone(),
        severity: f.severity.as_label().into(),
        confidence: f.confidence.as_label().into(),
        evidence: f.evidence.clone(),
        remediation: f.remediation.clone(),
        fingerprint: f.fingerprint(),
        status: "new".into(),
        verification: "unverified".into(),
        tags: Vec::new(),
        references: f.references.clone(),
        assignee: None,
        note: String::new(),
        insertion_point: f.insertion_point.clone(),
        updated_at_ms: now,
        observation_count: 1,
    }
}
