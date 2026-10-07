//! Intercepting HTTP/1.1 + HTTPS MITM proxy.
//!
//! Lifecycle:
//!
//! 1. `ProxyServer::start(cfg).await` binds every listener in `cfg`
//!    and returns a [`ProxyHandle`] you can clone, poll for stats, and
//!    use to shut the proxy down.
//! 2. For each accepted connection:
//!    * Read the first request head.
//!    * If `CONNECT`: perform a TLS handshake using a freshly minted
//!      leaf certificate signed by the project CA, then recurse into
//!      the HTTP loop over the TLS stream.
//!    * Else: treat the first request's absolute-form URL as the
//!      upstream target, open an upstream connection, and forward
//!      request/response pairs.
//! 3. Each request/response pair is published on the event bus and
//!    stored (if the caller supplied a `TrafficSink`).
//!
//! Interception, match/replace, scope and extensions are inserted
//! between the parse and forward steps.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use burpfree_ca::CertificateAuthority;
use burpfree_codec::compression::{maybe_decompress, DecodeLimit};
use burpfree_core::events::{EventBus, EventKind, TrafficEvent};
use burpfree_core::scope::Scope;
use burpfree_core::traffic::{HttpVersion, Request, RequestSource, Response, TlsInfo, Transaction};
use parking_lot::RwLock;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::http1::{
    read_body, read_request_head, read_response_head, request_body_framing, response_body_framing,
    write_request, RequestHead, ResponseHead,
};
use crate::interceptor::{InterceptDecision, InterceptMessage, Interceptor};
use crate::matchreplace::MatchReplaceEngine;
use crate::upstream::Upstream;

/// Pluggable sink for recording transactions. Implementors can persist
/// to SQLite, push to extensions, broadcast to the UI, etc.
#[async_trait::async_trait]
pub trait TrafficSink: Send + Sync + 'static {
    async fn record(&self, tx: Transaction) -> Result<()>;
}

/// No-op sink used in tests that only care about the proxy.
#[derive(Default)]
pub struct NullSink;

#[async_trait::async_trait]
impl TrafficSink for NullSink {
    async fn record(&self, _tx: Transaction) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listeners: Vec<SocketAddr>,
    pub ca: CertificateAuthority,
    pub upstream: Arc<RwLock<Upstream>>,
    pub scope: Arc<RwLock<Scope>>,
    pub match_replace: Arc<RwLock<MatchReplaceEngine>>,
    pub interceptor: Interceptor,
    pub events: EventBus,
    pub sink: Arc<dyn TrafficSink>,
    pub decompression_cap_bytes: usize,
    pub max_body_bytes: u64,
    pub connect_timeout: Duration,
    /// When `false`, out-of-scope transactions are forwarded by the
    /// proxy but NOT persisted to history / sitemap and no
    /// `TrafficEvent::Transaction` is emitted — mirrors Burp's
    /// "Suppress out-of-scope items" option. Lifted to an `AtomicBool`
    /// (shared with `AppState::record_out_of_scope`) so flipping the
    /// SettingsPanel checkbox takes effect on the next request
    /// without restarting the proxy. `true` = record everything
    /// (default, matches Burp).
    pub record_out_of_scope: Arc<AtomicBool>,
    /// Shared hostname → IP overrides consulted before the proxy's own
    /// DNS resolution. Empty by default; applied only for Direct upstream.
    pub host_overrides: burpfree_core::net::HostOverrides,
    /// Hosts whose CONNECT tunnels should be forwarded raw rather than
    /// MITM-terminated. Matching is a case-insensitive substring on the
    /// CONNECT target host; empty patterns are ignored. Needed for
    /// cert-pinned mobile apps / IoT clients that reject our leaf cert.
    pub tls_passthrough: Arc<RwLock<Vec<String>>>,
    /// Platform-authentication credential list. When the upstream
    /// returns `401 WWW-Authenticate: Basic`, the handler consults
    /// this list for a matching enabled credential and re-dispatches
    /// the request ONCE with an `Authorization: Basic …` header
    /// precomputed from `base64(user:password)`. Shared with
    /// `AppState::platform_auth` as an `Arc<RwLock<Vec<…>>>` so
    /// Settings-pane edits propagate without a proxy restart. Mirror
    /// of Burp's `Settings → Network → Platform authentication`
    /// page.
    pub platform_auth: Arc<RwLock<Vec<crate::platform_auth::PlatformAuthCredential>>>,
}

/// Returns true if `host` matches any non-empty pattern in `patterns`
/// via a case-insensitive substring compare. Used by the CONNECT
/// handler to decide whether to tunnel raw instead of MITM-ing.
pub fn is_passthrough_host(host: &str, patterns: &[String]) -> bool {
    let hl = host.to_ascii_lowercase();
    patterns.iter().any(|pat| {
        let p = pat.trim().to_ascii_lowercase();
        !p.is_empty() && hl.contains(&p)
    })
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProxyStats {
    pub conns_accepted: u64,
    pub requests_forwarded: u64,
    pub responses_recorded: u64,
    pub errors: u64,
    pub tls_mitm: u64,
}

#[derive(Clone)]
pub struct ProxyHandle {
    pub listen_addrs: Vec<SocketAddr>,
    stats: Arc<AtomicStats>,
    shutdown: watch::Sender<bool>,
}

impl ProxyHandle {
    pub fn stats(&self) -> ProxyStats {
        self.stats.snapshot()
    }
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.shutdown.send(true);
        Ok(())
    }
}

#[derive(Default)]
struct AtomicStats {
    conns_accepted: AtomicU64,
    requests_forwarded: AtomicU64,
    responses_recorded: AtomicU64,
    errors: AtomicU64,
    tls_mitm: AtomicU64,
}

impl AtomicStats {
    fn snapshot(&self) -> ProxyStats {
        ProxyStats {
            conns_accepted: self.conns_accepted.load(Ordering::Relaxed),
            requests_forwarded: self.requests_forwarded.load(Ordering::Relaxed),
            responses_recorded: self.responses_recorded.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            tls_mitm: self.tls_mitm.load(Ordering::Relaxed),
        }
    }
}

/// Top-level entry point.
pub struct ProxyServer;

impl ProxyServer {
    pub async fn start(mut cfg: ServerConfig) -> Result<ProxyHandle> {
        if cfg.listeners.is_empty() {
            return Err(anyhow!("no listeners configured"));
        }
        let stats = Arc::new(AtomicStats::default());
        let (sd_tx, sd_rx) = watch::channel(false);
        // Bind every listener up front and collect the actual addresses.
        let mut listeners_and_addrs = Vec::new();
        for addr in &cfg.listeners {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind {addr}"))?;
            let actual = listener.local_addr()?;
            info!(listener = %actual, "proxy listener started");
            cfg.events.publish_log("proxy", "info", format!("listener started on {actual}"));
            listeners_and_addrs.push((listener, actual));
        }
        // Replace the pre-bind addresses (which may contain port 0) with
        // the actual bound ones so the self-loop guard works correctly.
        let bound: Vec<SocketAddr> = listeners_and_addrs.iter().map(|(_, a)| *a).collect();
        cfg.listeners = bound.clone();

        for (listener, _actual) in listeners_and_addrs {
            let cfg2 = cfg.clone();
            let stats2 = stats.clone();
            let mut sd = sd_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        res = listener.accept() => match res {
                            Ok((stream, peer)) => {
                                stats2.conns_accepted.fetch_add(1, Ordering::Relaxed);
                                let cfg3 = cfg2.clone();
                                let stats3 = stats2.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(stream, peer, cfg3, stats3.clone()).await {
                                        stats3.errors.fetch_add(1, Ordering::Relaxed);
                                        debug!(error = %e, "connection ended");
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                                stats2.errors.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        },
                        _ = sd.changed() => {
                            if *sd.borrow() {
                                info!("listener shutting down");
                                break;
                            }
                        }
                    }
                }
            });
        }
        Ok(ProxyHandle {
            listen_addrs: bound,
            stats,
            shutdown: sd_tx,
        })
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: ServerConfig,
    stats: Arc<AtomicStats>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut reader = BufReader::new(stream);
    // Read the first request head.
    let head = match read_request_head(&mut reader).await {
        Ok(h) => h,
        Err(crate::http1::HttpError::UnexpectedEof) => return Ok(()),
        Err(e) => {
            debug!(error = %e, "bad request on first line");
            return Err(e.into());
        }
    };
    if head.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(reader, peer, head, cfg, stats).await
    } else {
        // Treat as proxy-form absolute URL request (plain HTTP).
        handle_proxied_http(reader, peer, head, cfg, stats, None, "http", 80, None).await
    }
}

async fn handle_connect(
    reader: BufReader<TcpStream>,
    peer: SocketAddr,
    head: RequestHead,
    cfg: ServerConfig,
    stats: Arc<AtomicStats>,
) -> Result<()> {
    let (host, port) = split_hostport(&head.target).ok_or_else(|| anyhow!("bad CONNECT target: {}", head.target))?;
    // Confirm the tunnel to the client.
    let mut inner = reader.into_inner();
    // Pass-through branch: if the operator added this host to the
    // bypass list, open a raw TCP tunnel between the client and the
    // real origin instead of minting a leaf cert and MITM-ing. Needed
    // for cert-pinned clients that would otherwise refuse our root CA.
    let passthrough = {
        let list = cfg.tls_passthrough.read();
        is_passthrough_host(&host, &list)
    };
    if passthrough {
        cfg.events.publish_log(
            "proxy",
            "info",
            format!("TLS pass-through for {host}:{port} (peer {peer})"),
        );
        inner
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: BurpFree\r\n\r\n")
            .await?;
        inner.flush().await?;
        // Open the raw origin socket and pump bytes in both directions
        // until either side closes. We deliberately skip tls_mitm
        // counter bump since no MITM happened.
        let upstream = match tokio::time::timeout(
            cfg.connect_timeout,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                cfg.events.publish_log(
                    "proxy",
                    "warn",
                    format!("TLS pass-through dial failed for {host}:{port}: {e}"),
                );
                return Ok(());
            }
            Err(_) => {
                cfg.events.publish_log(
                    "proxy",
                    "warn",
                    format!("TLS pass-through dial timeout for {host}:{port}"),
                );
                return Ok(());
            }
        };
        let _ = upstream.set_nodelay(true);
        let (mut cl_r, mut cl_w) = tokio::io::split(inner);
        let (mut up_r, mut up_w) = tokio::io::split(upstream);
        let c2u = tokio::io::copy(&mut cl_r, &mut up_w);
        let u2c = tokio::io::copy(&mut up_r, &mut cl_w);
        let _ = tokio::try_join!(c2u, u2c);
        return Ok(());
    }
    inner
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: BurpFree\r\n\r\n")
        .await?;
    inner.flush().await?;
    // Wrap in TLS using a leaf cert for `host`.
    let leaf = cfg.ca.leaf_for(&host).context("mint leaf cert")?;
    let server_config = Arc::new(build_rustls_server_config(leaf)?);
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = match acceptor.accept(inner).await {
        Ok(s) => s,
        Err(e) => {
            cfg.events.publish_log("proxy", "warn", format!("TLS handshake failed with {peer}: {e}"));
            return Err(anyhow!("TLS accept: {e}"));
        }
    };
    stats.tls_mitm.fetch_add(1, Ordering::Relaxed);
    let (negotiated_alpn, server_tls_version) = {
        let (_, conn) = tls_stream.get_ref();
        (
            conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string()),
            conn.protocol_version().map(|v| format!("{:?}", v)),
        )
    };
    let tls_info = TlsInfo {
        sni: Some(host.clone()),
        alpn: negotiated_alpn.clone(),
        version: server_tls_version,
        cipher: None,
        client_cert_fp: None,
    };
    let mut reader = BufReader::new(tls_stream);
    // Now read HTTP requests over TLS until the client disconnects or
    // we are told to shut down.
    loop {
        let head = match read_request_head(&mut reader).await {
            Ok(h) => h,
            Err(crate::http1::HttpError::UnexpectedEof) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        handle_proxied_http(
            reader,
            peer,
            head,
            cfg.clone(),
            stats.clone(),
            Some(tls_info.clone()),
            "https",
            port,
            Some(host.clone()),
        )
        .await?;
        // The call consumed `reader` for one txn; we exit the loop so
        // tokio's connection reuse works through a single accept. Real
        // keep-alive requires splitting the stream — a future
        // enhancement. For now, each CONNECT handles one TLS request.
        return Ok(());
    }
}

async fn handle_proxied_http(
    mut reader: BufReader<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>,
    peer: SocketAddr,
    head: RequestHead,
    cfg: ServerConfig,
    stats: Arc<AtomicStats>,
    tls: Option<TlsInfo>,
    scheme_hint: &str,
    default_port: u16,
    forced_host: Option<String>,
) -> Result<()> {
    let (host, port, scheme, path) = resolve_target(&head, scheme_hint, default_port, forced_host);

    // Loop guard: refuse to proxy to one of our own listeners. Without
    // this, a plain HTTP request addressed at the proxy itself (common
    // from browser dial-home probes or misconfigured clients) would be
    // "forwarded" to us, which would be read as the next request, and
    // so on — an infinite feedback loop.
    if is_self_target(&cfg, &host, port) {
        let (_, mut w) = tokio::io::split(reader.into_inner());
        let msg = b"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 46\r\nConnection: close\r\n\r\nBurpFree: refusing to proxy to our own address\n";
        let _ = w.write_all(msg).await;
        let _ = w.flush().await;
        return Ok(());
    }

    let framing = request_body_framing(&head);
    let body = read_body(&mut reader, framing, cfg.max_body_bytes).await?;
    let mut request = Request {
        id: burpfree_core::ids::TrafficId::new(),
        method: head.method.clone(),
        scheme: scheme.clone(),
        host: host.clone(),
        port,
        path,
        http_version: head.version,
        headers: head.headers,
        body,
        created_at_ms: burpfree_core::traffic::now_ms(),
        source: RequestSource::Proxy,
        parent_id: None,
        annotation: String::new(),
        comment: String::new(),
    };
    strip_hop_headers(&mut request.headers);

    // Pre-forward hooks: match/replace, scope, interceptor.
    cfg.match_replace.read().apply_request(&mut request);

    let in_scope = cfg.scope.read().is_in_scope(&request);
    // Gate honored in `publish_and_record` below so BOTH the normal
    // and the interceptor-drop branches reach it; the suppress check
    // can't live here because we'd still have to record on the
    // interceptor-drop path otherwise.
    if !in_scope && !cfg.record_out_of_scope.load(Ordering::Relaxed) {
        debug!(host = %request.host, "out-of-scope request forwarded without recording");
    }

    if cfg.interceptor.request_intercept() {
        if let Some(handle) =
            cfg.interceptor.maybe_intercept_request_with_scope(request.clone(), in_scope)
        {
            cfg.events.publish(TrafficEvent::new(EventKind::Intercept {
                id: handle.id,
                direction: "request".into(),
            }));
            match handle.await_decision().await {
                InterceptDecision::Drop => {
                    debug!("intercept dropped request");
                    // Return 502 to client.
                    let (_, mut tx) = tokio::io::split(reader.into_inner());
                    let _ = tx
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return Ok(());
                }
                InterceptDecision::Forward(InterceptMessage::Request(edited)) => {
                    request = edited;
                }
                _ => return Err(anyhow!("intercept returned non-request forward")),
            }
        }
    }

    // Forward.
    let started = Instant::now();
    let mut upstream_result = forward_upstream(&cfg, &request).await;
    stats.requests_forwarded.fetch_add(1, Ordering::Relaxed);

    // Platform-authentication retry — mirror of Burp's auto-401
    // response. If upstream returned 401 WWW-Authenticate for a
    // scheme we support AND we have a matching credential, inject
    // the Authorization header and dispatch ONCE more. The record
    // the operator sees is the FINAL (authenticated) attempt so
    // history / sitemap stay as if the client sent the credential
    // the first time, matching Burp's invisible-to-the-client
    // behaviour. Capped at one retry to avoid infinite loops on a
    // broken credential or a server that keeps challenging.
    if let Ok((ref head, _, _)) = upstream_result {
        if head.status == 401 && !request.headers.has("Authorization") {
            if let Some(challenge) = head.headers.get("WWW-Authenticate") {
                if let Some(scheme) =
                    crate::platform_auth::parse_challenge_scheme(challenge)
                {
                    let creds = cfg.platform_auth.read().clone();
                    if let Some(cred) =
                        crate::platform_auth::find_match(&creds, &request.host, scheme)
                    {
                        match scheme {
                            crate::platform_auth::AuthScheme::Basic => {
                                let header = crate::platform_auth::build_basic_header(
                                    &cred.username,
                                    &cred.password,
                                );
                                tracing::info!(
                                    host = %request.host,
                                    user = %cred.username,
                                    "platform-auth: injecting Basic credentials and retrying 401",
                                );
                                request.headers.set("Authorization", &header);
                                stats.requests_forwarded.fetch_add(1, Ordering::Relaxed);
                                upstream_result = forward_upstream(&cfg, &request).await;
                            }
                            crate::platform_auth::AuthScheme::Digest => {
                                // Digest handshake isn't implemented yet
                                // (nonce / qop / cnonce / nc counter + MD5
                                // of A1:A2). Log once and fall through —
                                // the 401 reaches the client as if no
                                // credential were configured.
                                tracing::warn!(
                                    host = %request.host,
                                    "platform-auth: Digest matched but handshake isn't implemented; forwarding original 401 to client",
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let mut tx = Transaction::new(request);
    tx.tls = tls.clone();
    tx.client_addr = Some(peer.to_string());
    tx.in_scope = in_scope;

    let (resp_bytes, resp) = match upstream_result {
        Ok((resp_head, body, upstream_addr)) => {
            tx.upstream_addr = Some(upstream_addr);
            let mut r = Response {
                id: burpfree_core::ids::TrafficId::new(),
                status: resp_head.status,
                reason: resp_head.reason.clone(),
                http_version: resp_head.version,
                headers: resp_head.headers.clone(),
                body: body.clone(),
                created_at_ms: burpfree_core::traffic::now_ms(),
                elapsed_ms,
                original_body_size: Some(body.len() as u64),
            };
            // Transparent decompression for history / scanners.
            let enc = r.headers.get("Content-Encoding").map(|s| s.to_string());
            if let Some(e) = enc.as_deref() {
                let limit = DecodeLimit {
                    ratio: 100,
                    floor: cfg.decompression_cap_bytes,
                    ceiling: cfg.decompression_cap_bytes,
                };
                match maybe_decompress(Some(e), &r.body, limit) {
                    Ok(decoded) => {
                        r.body = decoded;
                        r.headers.remove("Content-Encoding");
                    }
                    Err(err) => {
                        warn!(error = %err, "transparent decompression failed; forwarding compressed body");
                    }
                }
            }
            strip_hop_headers(&mut r.headers);

            cfg.match_replace.read().apply_response(&mut r, &tx.request.host);

            if cfg.interceptor.response_intercept() {
                if let Some(handle) = cfg
                    .interceptor
                    .maybe_intercept_response_with_request(r.clone(), &tx.request, tx.in_scope)
                {
                    cfg.events.publish(TrafficEvent::new(EventKind::Intercept {
                        id: handle.id,
                        direction: "response".into(),
                    }));
                    match handle.await_decision().await {
                        InterceptDecision::Drop => {
                            // Reply with 502 but still record what was planned.
                            let (_, mut tx_w) = tokio::io::split(reader.into_inner());
                            let _ = tx_w
                                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                                .await;
                            tx.error = Some("response dropped by interceptor".into());
                            publish_and_record(&cfg, &stats, tx).await?;
                            return Ok(());
                        }
                        InterceptDecision::Forward(InterceptMessage::Response(edited)) => {
                            r = edited;
                        }
                        _ => return Err(anyhow!("intercept returned non-response forward")),
                    }
                }
            }
            let wire = r.clone();
            (Some(serialize_response(&wire)), Some(r))
        }
        Err(e) => {
            warn!(error = %e, "upstream failed");
            tx.error = Some(format!("upstream: {e}"));
            let msg = format!("Bad Gateway: {e}");
            let body = msg.into_bytes();
            let mut headers = burpfree_core::headers::Headers::new();
            headers.set("Content-Type", "text/plain; charset=utf-8");
            headers.set("Content-Length", body.len().to_string());
            headers.set("Connection", "close");
            let r = Response {
                id: burpfree_core::ids::TrafficId::new(),
                status: 502,
                reason: "Bad Gateway".into(),
                http_version: HttpVersion::Http11,
                headers,
                body,
                created_at_ms: burpfree_core::traffic::now_ms(),
                elapsed_ms,
                original_body_size: None,
            };
            (Some(serialize_response(&r)), Some(r))
        }
    };
    tx.response = resp;

    // Write response to client.
    if let Some(bytes) = resp_bytes {
        let (_, mut tx_w) = tokio::io::split(reader.into_inner());
        if let Err(e) = tx_w.write_all(&bytes).await {
            debug!(error = %e, "write to client failed");
        }
        let _ = tx_w.flush().await;
    }

    stats.responses_recorded.fetch_add(1, Ordering::Relaxed);
    publish_and_record(&cfg, &stats, tx).await?;
    Ok(())
}

async fn forward_upstream(
    cfg: &ServerConfig,
    req: &Request,
) -> Result<(ResponseHead, Vec<u8>, String)> {
    let upstream = cfg.upstream.read().clone();
    let is_https = req.scheme == "https";
    // Resolve against hostname overrides for direct connections.
    // Overrides don't apply when going through an HTTP/SOCKS5 upstream
    // because the upstream handles DNS itself.
    let dial_host: String = if matches!(upstream.kind(), crate::upstream::UpstreamKind::Direct) {
        cfg.host_overrides
            .resolve(&req.host)
            .unwrap_or_else(|| req.host.clone())
    } else {
        req.host.clone()
    };
    let stream = upstream
        .dial(&dial_host, req.port, cfg.connect_timeout)
        .await
        .with_context(|| format!("dial {}:{}", dial_host, req.port))?;
    let upstream_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("{}:{}", req.host, req.port));

    let bytes = if is_https {
        // TLS to the real server (we are the client here).
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(req.host.clone())
            .map_err(|e| anyhow!("bad server name: {e}"))?;
        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| anyhow!("tls connect: {e}"))?;
        let mut tls_reader = BufReader::new(tls_stream);
        send_request_and_read(&mut tls_reader, req).await?
    } else {
        let mut reader = BufReader::new(stream);
        send_request_and_read(&mut reader, req).await?
    };
    Ok((bytes.0, bytes.1, upstream_addr))
}

/// Minimal built-in root cert bundle for upstream TLS validation.
/// Avoids pulling the `webpki-roots` crate — we hardcode zero roots
/// and skip verification when no roots are present. In a hardened
/// build we would ship a webpki-roots dependency; for a security tool
/// that itself MITMs, upstream validation strictness is a config
/// toggle. For now we trust the system; downstream clients already
/// trust *our* leaf.
mod webpki_root_certs {
    use rustls::pki_types::TrustAnchor;
    pub static TLS_SERVER_ROOT_CERTS: &[TrustAnchor<'static>] = &[];
}

async fn send_request_and_read<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    req: &Request,
) -> Result<(ResponseHead, Vec<u8>)> {
    // Build a request suitable for origin servers: origin-form target,
    // Host header, no proxy-specific hop-by-hop headers.
    let mut head = RequestHead {
        method: req.method.clone(),
        target: req.path.clone(),
        version: HttpVersion::Http11,
        headers: req.headers.clone(),
    };
    // Ensure the Host header matches.
    let host_value = if (req.scheme == "http" && req.port == 80)
        || (req.scheme == "https" && req.port == 443)
    {
        req.host.clone()
    } else {
        format!("{}:{}", req.host, req.port)
    };
    head.headers.set("Host", host_value);
    head.headers.set("Connection", "close");
    strip_hop_headers_outbound(&mut head.headers);
    if req.body.is_empty() {
        head.headers.remove("Content-Length");
    } else {
        head.headers.set("Content-Length", req.body.len().to_string());
    }

    let (mut rd, mut wr) = tokio::io::split(reader.get_mut());
    write_request(&mut wr, &head, &req.body).await?;

    let mut buf_reader = BufReader::new(&mut rd);
    let resp_head = read_response_head(&mut buf_reader).await?;
    let framing = response_body_framing(&req.method, &resp_head);
    let body = read_body(&mut buf_reader, framing, 128 * 1024 * 1024).await?;
    Ok((resp_head, body))
}

async fn publish_and_record(cfg: &ServerConfig, _stats: &AtomicStats, tx: Transaction) -> Result<()> {
    // Suppress out-of-scope items: when the flag is off and this
    // transaction was flagged as out-of-scope by the scope engine
    // (set at `tx.in_scope = in_scope;` earlier in handle_request),
    // skip BOTH the event emission AND the sink — Burp's "drop
    // out-of-scope items" leaves no trace in history, sitemap,
    // logger, or scanner. The forward itself has already happened by
    // the time we reach here; this gate only affects persistence +
    // observability.
    if !tx.in_scope && !cfg.record_out_of_scope.load(Ordering::Relaxed) {
        return Ok(());
    }
    let id = tx.id;
    cfg.events.publish(TrafficEvent::new(EventKind::Transaction { id }));
    cfg.sink.record(tx).await?;
    Ok(())
}

/// Public helper for callers (and tests) that need to decide whether
/// a transaction would be recorded under the current gate. Returns
/// `true` if the transaction's `in_scope` flag OR the record-OOS
/// toggle allows it through. Matches the predicate baked into
/// [`publish_and_record`] so UI code and tests stay in lockstep.
pub fn should_record(in_scope: bool, record_oos: &Arc<AtomicBool>) -> bool {
    in_scope || record_oos.load(Ordering::Relaxed)
}

fn serialize_response(r: &Response) -> Vec<u8> {
    r.to_wire_bytes()
}

fn resolve_target(
    head: &RequestHead,
    scheme_hint: &str,
    default_port: u16,
    forced_host: Option<String>,
) -> (String, u16, String, String) {
    // Absolute-form target? Then it's an upstream URL (plain HTTP proxy).
    if head.target.starts_with("http://") || head.target.starts_with("https://") {
        if let Ok(u) = url::Url::parse(&head.target) {
            let host = u.host_str().unwrap_or_default().to_string();
            let scheme = u.scheme().to_string();
            let port = u.port_or_known_default().unwrap_or(default_port);
            let mut path = u.path().to_string();
            if let Some(q) = u.query() {
                path.push('?');
                path.push_str(q);
            }
            if path.is_empty() {
                path.push('/');
            }
            return (host, port, scheme, path);
        }
    }
    // Origin-form target: use Host header or forced host (CONNECT path).
    let host_header = head.headers.get("Host").unwrap_or("").to_string();
    let host_candidate = forced_host.clone().unwrap_or(host_header.clone());
    let (host, port) = split_hostport_default(&host_candidate, default_port);
    (host, port, scheme_hint.to_string(), head.target.clone())
}

fn split_hostport(target: &str) -> Option<(String, u16)> {
    let mut iter = target.rsplitn(2, ':');
    let port = iter.next()?;
    let host = iter.next()?;
    Some((host.to_string(), port.parse().ok()?))
}

fn split_hostport_default(target: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = split_hostport(target) {
        (h, p)
    } else {
        (target.to_string(), default_port)
    }
}

/// Returns true if `(host, port)` resolves to one of our own listener
/// sockets. Protects against the "proxy forwards to itself" feedback loop
/// that happens when a client sends a plain-HTTP request addressed at
/// the proxy's own listener.
fn is_self_target(cfg: &ServerConfig, host: &str, port: u16) -> bool {
    // Fast path: compare port + loopback host literals.
    let is_loopback_name = matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0");
    if is_loopback_name {
        if cfg.listeners.iter().any(|l| l.port() == port) {
            return true;
        }
    }
    // Resolve to IPs and compare against bound listeners.
    use std::net::ToSocketAddrs;
    let target = format!("{host}:{port}");
    if let Ok(iter) = target.to_socket_addrs() {
        for addr in iter {
            if cfg.listeners.iter().any(|l| l == &addr) {
                return true;
            }
            if addr.ip().is_loopback() && cfg.listeners.iter().any(|l| l.port() == port) {
                return true;
            }
        }
    }
    false
}

fn strip_hop_headers(h: &mut burpfree_core::headers::Headers) {
    for name in [
        "Proxy-Connection",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Upgrade-Insecure-Requests",
    ] {
        h.remove(name);
    }
}

fn strip_hop_headers_outbound(h: &mut burpfree_core::headers::Headers) {
    for name in [
        "Proxy-Connection",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "Keep-Alive",
        "Transfer-Encoding",
    ] {
        h.remove(name);
    }
}

fn build_rustls_server_config(leaf: Arc<rustls::sign::CertifiedKey>) -> Result<RustlsServerConfig> {
    let resolver = Arc::new(SingleLeafResolver { leaf });
    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

#[derive(Debug)]
struct SingleLeafResolver {
    leaf: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for SingleLeafResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.leaf.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::events::EventBus;
    use burpfree_core::scope::Scope;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Spin up a tiny origin server that echoes the request path in
    /// the response body.
    async fn start_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = match s.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let body = format!("echo:{path}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut s, resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn make_cfg() -> ServerConfig {
        let ca = CertificateAuthority::generate(None).unwrap();
        ServerConfig {
            listeners: vec!["127.0.0.1:0".parse().unwrap()],
            ca,
            upstream: Arc::new(RwLock::new(Upstream::default())),
            scope: Arc::new(RwLock::new(Scope::new())),
            match_replace: Arc::new(RwLock::new(MatchReplaceEngine::new())),
            interceptor: Interceptor::new(),
            events: EventBus::default(),
            sink: Arc::new(NullSink::default()),
            decompression_cap_bytes: 16 << 20,
            max_body_bytes: 32 << 20,
            connect_timeout: Duration::from_secs(5),
            record_out_of_scope: Arc::new(AtomicBool::new(true)),
            host_overrides: burpfree_core::net::HostOverrides::default(),
            tls_passthrough: Arc::new(RwLock::new(Vec::new())),
            platform_auth: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Counting TrafficSink for the gate-integration test: records
    /// how many transactions reached the sink so we can assert
    /// out-of-scope items got dropped at `publish_and_record` under
    /// the right toggle state.
    #[derive(Default)]
    struct CountingSink(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl TrafficSink for CountingSink {
        async fn record(&self, _tx: Transaction) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn publish_and_record_suppresses_oos_when_flag_off() {
        // Build a cfg with a counting sink; drive publish_and_record
        // directly with crafted Transactions so we can control the
        // in_scope flag independently of the proxy pipeline.
        let mut cfg = make_cfg();
        let sink = Arc::new(CountingSink::default());
        cfg.sink = sink.clone() as Arc<dyn TrafficSink>;
        let stats = AtomicStats::default();

        let mut tx_oos = Transaction::new(
            burpfree_core::traffic::Request::new("GET", "http://evil.example/x").unwrap(),
        );
        tx_oos.in_scope = false;
        let mut tx_in = Transaction::new(
            burpfree_core::traffic::Request::new("GET", "http://ok.example/x").unwrap(),
        );
        tx_in.in_scope = true;

        // Flag ON (default) → everything records.
        cfg.record_out_of_scope.store(true, Ordering::Relaxed);
        publish_and_record(&cfg, &stats, tx_oos.clone()).await.unwrap();
        publish_and_record(&cfg, &stats, tx_in.clone()).await.unwrap();
        assert_eq!(
            sink.0.load(Ordering::Relaxed),
            2,
            "with flag on, both OOS and in-scope must be recorded"
        );

        // Flag OFF → OOS is dropped at the gate, in-scope still records.
        cfg.record_out_of_scope.store(false, Ordering::Relaxed);
        publish_and_record(&cfg, &stats, tx_oos.clone()).await.unwrap();
        publish_and_record(&cfg, &stats, tx_in.clone()).await.unwrap();
        assert_eq!(
            sink.0.load(Ordering::Relaxed),
            3,
            "with flag off, OOS must be suppressed; only the in-scope tx reaches the sink"
        );

        // Flip ON again → live-reload picks up on the next call,
        // no proxy restart needed.
        cfg.record_out_of_scope.store(true, Ordering::Relaxed);
        publish_and_record(&cfg, &stats, tx_oos.clone()).await.unwrap();
        assert_eq!(
            sink.0.load(Ordering::Relaxed),
            4,
            "flipping the atomic back on restores recording immediately"
        );
    }

    #[test]
    fn should_record_honors_scope_and_oos_toggle() {
        // Four-cell truth table for the gate predicate shared by
        // `publish_and_record` and the public helper.
        let flag_on = Arc::new(AtomicBool::new(true));
        let flag_off = Arc::new(AtomicBool::new(false));
        // In-scope ALWAYS records regardless of toggle — scope wins.
        assert!(should_record(true, &flag_on));
        assert!(should_record(true, &flag_off));
        // Out-of-scope: toggle controls recording.
        assert!(should_record(false, &flag_on));
        assert!(!should_record(false, &flag_off));
        // Flipping the atomic takes effect on the next load (live
        // reload semantics — no restart needed).
        flag_off.store(true, Ordering::Relaxed);
        assert!(should_record(false, &flag_off));
    }

    #[test]
    fn passthrough_host_substring_case_insensitive() {
        let patterns = vec!["API.pin.example".to_string(), "  ".to_string(), "".to_string()];
        assert!(is_passthrough_host("api.pin.example", &patterns));
        assert!(is_passthrough_host("www.API.PIN.example.com", &patterns));
        assert!(!is_passthrough_host("evil.com", &patterns));
        // Empty/whitespace patterns never match (guard against operator typo).
        assert!(!is_passthrough_host("anything", &[]));
        assert!(!is_passthrough_host("anything", &["   ".to_string()]));
    }

    #[tokio::test]
    async fn plain_http_round_trip() {
        let origin = start_origin().await;
        let mut cfg = make_cfg();
        cfg.listeners = vec!["127.0.0.1:0".parse().unwrap()];
        let handle = ProxyServer::start(cfg.clone()).await.unwrap();
        let proxy_addr = handle.listen_addrs[0];
        // Send an absolute-form request to the proxy.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            origin.port(),
            origin.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(text.contains("echo:/hello"), "body missing in: {text}");
    }

    #[tokio::test]
    async fn self_target_returns_421_not_loop() {
        // A client that sends a plain HTTP request addressed at the
        // proxy's own listener used to cause an infinite feedback
        // loop. The guard must short-circuit with 421 Misdirected.
        let cfg = make_cfg();
        let handle = ProxyServer::start(cfg).await.unwrap();
        let proxy_addr = handle.listen_addrs[0];
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            proxy_addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with("HTTP/1.1 421"),
            "expected 421 Misdirected Request, got: {text}"
        );
    }

    #[tokio::test]
    async fn interceptor_drop_returns_502() {
        let origin = start_origin().await;
        let cfg = make_cfg();
        cfg.interceptor.set_request_intercept(true);
        let handle = ProxyServer::start(cfg.clone()).await.unwrap();
        let proxy_addr = handle.listen_addrs[0];
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            origin.port()
        );
        // Drop in a background task after the proxy parks the request.
        let it = cfg.interceptor.clone();
        tokio::spawn(async move {
            loop {
                let pending = it.list_pending();
                if let Some(p) = pending.first() {
                    it.resolve(p.id, crate::interceptor::InterceptAction::Drop, None).unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 502"), "got: {text}");
    }
}
