//! HTTP + DNS OOB listener.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Configuration for the OOB listener.
#[derive(Debug, Clone)]
pub struct OobConfig {
    /// Address the HTTP collector binds on. Default `127.0.0.1:7898`.
    pub http_bind: SocketAddr,
    /// Address the DNS collector binds on, if any. Defaults to
    /// `127.0.0.1:15353` on first launch — users with elevated rights
    /// can set this to `0.0.0.0:53` for real-world OOB.
    pub dns_bind: Option<SocketAddr>,
    /// Public hostname under which this OOB server appears to targets.
    /// A payload for correlation id `abc` becomes `abc.{public_host}` and
    /// `http://abc.{public_host}/`. When the server runs locally for
    /// testing this is typically `127.0.0.1:7898`.
    pub public_host: String,
    /// Max number of interactions kept in memory. Older ones are
    /// evicted FIFO. Defaults to 10_000.
    pub capacity: usize,
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1:7898".parse().unwrap(),
            dns_bind: Some("127.0.0.1:15353".parse().unwrap()),
            public_host: "127.0.0.1:7898".to_string(),
            capacity: 10_000,
        }
    }
}

/// Kind of observed OOB callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionKind {
    Http,
    Dns,
    Smtp,
}

/// A single observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub id: u64,
    pub ts_ms: i64,
    pub kind: InteractionKind,
    pub correlation_id: String,
    pub remote_addr: String,
    /// Short textual summary (method+path for HTTP, qname+qtype for DNS).
    pub summary: String,
    /// First kilobyte of raw bytes received, hex-escaped for storage.
    pub preview: String,
}

/// A mint-time payload for a specific correlation attempt.
#[derive(Debug, Clone, Serialize)]
pub struct OobToken {
    pub correlation_id: String,
    pub public_host: String,
    /// `http://{id}.{host}/` form.
    pub http_url: String,
    /// `{id}.{host}` form, suitable for a DNS A query.
    pub dns_name: String,
}

/// Public server handle. Cheap to clone (`Arc` under the hood).
#[derive(Clone)]
pub struct OobServerHandle {
    inner: Arc<Inner>,
}

struct Inner {
    config: OobConfig,
    interactions: Mutex<InteractionBuffer>,
    next_id: AtomicU64,
    shutdown: watch::Sender<bool>,
    http_addr: Mutex<Option<SocketAddr>>,
    dns_addr: Mutex<Option<SocketAddr>>,
}

struct InteractionBuffer {
    items: std::collections::VecDeque<Interaction>,
    capacity: usize,
}

impl InteractionBuffer {
    fn new(cap: usize) -> Self {
        Self {
            items: std::collections::VecDeque::with_capacity(cap.min(1024)),
            capacity: cap,
        }
    }
    fn push(&mut self, i: Interaction) {
        if self.items.len() >= self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(i);
    }
}

impl OobServerHandle {
    /// Mint a fresh token.
    pub fn new_token(&self) -> OobToken {
        let id = random_hex(5);
        let host = self.inner.config.public_host.clone();
        OobToken {
            http_url: format!("http://{id}.{host}/"),
            dns_name: format!("{id}.{host}"),
            correlation_id: id,
            public_host: host,
        }
    }

    /// Mint `count` unique tokens in one batch. Used by Intruder to
    /// generate a payload set where each row has its own correlation id.
    pub fn new_tokens(&self, count: usize) -> Vec<OobToken> {
        (0..count).map(|_| self.new_token()).collect()
    }

    /// Poll until every supplied correlation id has at least one hit,
    /// or `timeout` elapses. Returns a parallel vector of hit lists in
    /// the same order as `correlation_ids`. Entries without hits are
    /// returned as empty vectors.
    pub async fn poll_batch(
        &self,
        correlation_ids: &[String],
        timeout: Duration,
    ) -> Vec<Vec<Interaction>> {
        let deadline = Instant::now() + timeout;
        loop {
            let hits: Vec<Vec<Interaction>> = correlation_ids
                .iter()
                .map(|cid| self.interactions_for(cid))
                .collect();
            if hits.iter().all(|v| !v.is_empty()) {
                return hits;
            }
            if Instant::now() >= deadline {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// Current size of the HTTP listener.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        *self.inner.http_addr.lock()
    }
    pub fn dns_addr(&self) -> Option<SocketAddr> {
        *self.inner.dns_addr.lock()
    }

    /// Return all interactions whose storage id is greater than
    /// `cursor`, together with the new high-water mark cursor the
    /// caller should use next time.
    pub fn drain_since(&self, cursor: u64) -> (Vec<Interaction>, u64) {
        let buf = self.inner.interactions.lock();
        let mut out = Vec::new();
        let mut hi = cursor;
        for i in buf.items.iter() {
            if i.id > cursor {
                hi = hi.max(i.id);
                out.push(i.clone());
            }
        }
        (out, hi)
    }

    /// Return all interactions that match a correlation id.
    pub fn interactions_for(&self, correlation_id: &str) -> Vec<Interaction> {
        self.inner
            .interactions
            .lock()
            .items
            .iter()
            .filter(|i| i.correlation_id == correlation_id)
            .cloned()
            .collect()
    }

    /// Poll until at least one interaction with the given correlation
    /// id is observed, or `timeout` elapses.
    pub async fn poll_for(&self, correlation_id: &str, timeout: Duration) -> Vec<Interaction> {
        let deadline = Instant::now() + timeout;
        loop {
            let hits = self.interactions_for(correlation_id);
            if !hits.is_empty() {
                return hits;
            }
            if Instant::now() >= deadline {
                return Vec::new();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// All stored interactions, in insertion order.
    pub fn all(&self) -> Vec<Interaction> {
        self.inner.interactions.lock().items.iter().cloned().collect()
    }

    /// Drop every stored interaction. Returns the count removed so
    /// callers can echo it back ("Cleared 42 interactions"). The
    /// in-memory buffer is a `VecDeque` behind a Mutex; `.clear()`
    /// is O(n) but every entry is a small `Interaction` so even
    /// 10k entries clear in sub-ms. The id counter is NOT reset —
    /// subsequent recordings continue the monotonic sequence so a
    /// correlation flagged "we saw interaction #42" stays coherent
    /// if the operator re-correlates after a clear.
    pub fn clear(&self) -> usize {
        let mut buf = self.inner.interactions.lock();
        let n = buf.items.len();
        buf.items.clear();
        n
    }

    pub async fn shutdown(&self) {
        let _ = self.inner.shutdown.send(true);
    }

    /// Record an interaction. Exposed for tests / in-process scanners.
    pub fn record(&self, kind: InteractionKind, correlation_id: &str, remote_addr: &str, summary: &str, preview: &str) {
        let i = Interaction {
            id: self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1,
            ts_ms: now_ms(),
            kind,
            correlation_id: correlation_id.to_string(),
            remote_addr: remote_addr.to_string(),
            summary: summary.to_string(),
            preview: preview.to_string(),
        };
        self.inner.interactions.lock().push(i);
    }

    pub fn config(&self) -> &OobConfig {
        &self.inner.config
    }
}

pub struct OobServer;

impl OobServer {
    /// Start the HTTP (always) + DNS (best effort) listeners.
    pub async fn start(config: OobConfig) -> Result<OobServerHandle> {
        let (sd_tx, sd_rx) = watch::channel(false);
        let inner = Arc::new(Inner {
            config: config.clone(),
            interactions: Mutex::new(InteractionBuffer::new(config.capacity.max(64))),
            next_id: AtomicU64::new(0),
            shutdown: sd_tx,
            http_addr: Mutex::new(None),
            dns_addr: Mutex::new(None),
        });
        let handle = OobServerHandle { inner: inner.clone() };

        // HTTP listener.
        let http_listener = TcpListener::bind(config.http_bind)
            .await
            .with_context(|| format!("bind HTTP OOB on {}", config.http_bind))?;
        let actual_http = http_listener.local_addr()?;
        *inner.http_addr.lock() = Some(actual_http);
        info!(addr = %actual_http, "OOB HTTP listener started");
        let h = handle.clone();
        let mut sd = sd_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = http_listener.accept() => match res {
                        Ok((s, peer)) => {
                            let h = h.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http(s, peer, h).await {
                                    debug!(error = %e, "OOB HTTP conn ended");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "OOB accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                    _ = sd.changed() => {
                        if *sd.borrow() { break; }
                    }
                }
            }
        });

        // DNS listener (best effort). On Windows binding :53 needs admin
        // so by default we use a high port; the server still logs any
        // query that reaches it.
        if let Some(dns_bind) = config.dns_bind {
            match UdpSocket::bind(dns_bind).await {
                Ok(sock) => {
                    let actual = sock.local_addr()?;
                    *inner.dns_addr.lock() = Some(actual);
                    info!(addr = %actual, "OOB DNS listener started");
                    let h = handle.clone();
                    let mut sd = sd_rx.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 1500];
                        loop {
                            tokio::select! {
                                res = sock.recv_from(&mut buf) => match res {
                                    Ok((n, peer)) => {
                                        let packet = &buf[..n];
                                        if let Some(q) = parse_dns_query(packet) {
                                            if let Some(cid) = correlation_from_hostname(&q.qname, &h.inner.config.public_host) {
                                                h.record(
                                                    InteractionKind::Dns,
                                                    &cid,
                                                    &peer.to_string(),
                                                    &format!("DNS {} {}", q.qtype, q.qname),
                                                    &hex::encode(&packet[..packet.len().min(128)]),
                                                );
                                                // Reply with a minimal NXDOMAIN so resolvers move on.
                                                let reply = build_nxdomain_reply(packet);
                                                let _ = sock.send_to(&reply, peer).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "OOB DNS recv failed");
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }
                                },
                                _ = sd.changed() => {
                                    if *sd.borrow() { break; }
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "OOB DNS bind failed; continuing with HTTP only");
                }
            }
        }
        Ok(handle)
    }
}

async fn handle_http(mut s: tokio::net::TcpStream, peer: SocketAddr, h: OobServerHandle) -> Result<()> {
    s.set_nodelay(true).ok();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let data = &buf[..n];
    let text = String::from_utf8_lossy(data);
    // Parse request-line and Host.
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut method = "";
    let mut target = "";
    let mut parts = request_line.split_whitespace();
    if let Some(m) = parts.next() { method = m; }
    if let Some(t) = parts.next() { target = t; }
    let mut host = "";
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Host: ").or_else(|| line.strip_prefix("host: ")) {
            host = rest.trim();
            break;
        }
    }
    // Correlation id is either in the Host subdomain or in the path.
    let correlation_id =
        correlation_from_hostname(host, &h.inner.config.public_host)
            .or_else(|| correlation_from_path(target))
            .unwrap_or_else(|| "unknown".to_string());

    let summary = format!("{method} {target}");
    let preview = text.chars().take(512).collect::<String>();
    h.record(
        InteractionKind::Http,
        &correlation_id,
        &peer.to_string(),
        &summary,
        &preview,
    );

    // Minimal 200 response so the target thinks the fetch succeeded.
    let body = b"burpfree-oob";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.write_all(body).await;
    let _ = s.flush().await;
    Ok(())
}

/// Extract the leading subdomain if the host matches the public host suffix.
pub(crate) fn correlation_from_hostname(host: &str, public_host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    let (host_name, _port) = match host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p),
        _ => (host, ""),
    };
    let (public_name, _public_port) = match public_host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p),
        _ => (public_host, ""),
    };
    if host_name == public_name {
        return None;
    }
    if host_name.ends_with(&format!(".{}", public_name)) {
        let subdomain = &host_name[..host_name.len() - public_name.len() - 1];
        // Correlation id is the first label of whatever remains.
        return Some(subdomain.split('.').next()?.to_string());
    }
    None
}

/// Correlation id encoded in the request path, e.g. `/abc123`.
pub(crate) fn correlation_from_path(path: &str) -> Option<String> {
    let p = path.split('?').next().unwrap_or("");
    let token = p.trim_start_matches('/').split('/').next().unwrap_or("");
    if token.len() >= 4 && token.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(token.to_string())
    } else {
        None
    }
}

fn random_hex(nbytes: usize) -> String {
    let n = nbytes.max(4);
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// --- Minimal DNS parsing / replies -----------------------------------------

#[derive(Debug)]
pub(crate) struct DnsQuery {
    pub qname: String,
    pub qtype: &'static str,
}

/// Parse a DNS query packet enough to extract the first question.
pub(crate) fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if qdcount == 0 {
        return None;
    }
    let (qname, idx) = read_qname(packet, 12)?;
    if idx + 4 > packet.len() {
        return None;
    }
    let qtype_num = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    let qtype = match qtype_num {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "ANY",
    };
    Some(DnsQuery { qname, qtype })
}

fn read_qname(packet: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    while i < packet.len() {
        let len = packet[i] as usize;
        if len == 0 {
            i += 1;
            return Some((labels.join("."), i));
        }
        if len & 0xc0 == 0xc0 {
            // Compressed label — not expected in queries we care about.
            return None;
        }
        i += 1;
        if i + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[i..i + len]).to_string());
        i += len;
    }
    None
}

/// Build a 1-question NXDOMAIN reply for the given query packet.
pub(crate) fn build_nxdomain_reply(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut reply = Vec::with_capacity(query.len());
    reply.extend_from_slice(&query[..2]); // id
    // flags: QR=1, Opcode=0, AA=0, TC=0, RD=same, RA=0, RCODE=3 (NXDOMAIN).
    reply.push(0x80 | (query[2] & 0x01));
    reply.push(0x03);
    reply.extend_from_slice(&query[4..6]); // qdcount
    reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ancount=0, nscount=0, arcount=0
    reply.extend_from_slice(&query[12..]); // echo question section
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    async fn start_server() -> OobServerHandle {
        let config = OobConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            dns_bind: None,
            public_host: "oob.local:7898".into(),
            capacity: 128,
        };
        let handle = OobServer::start(config).await.unwrap();
        handle
    }

    #[tokio::test]
    async fn http_hits_are_correlated_via_path() {
        let h = start_server().await;
        let addr = h.http_addr().unwrap();
        let token = h.new_token();
        let cid = token.correlation_id.clone();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET /{} HTTP/1.1\r\nHost: oob.local\r\nConnection: close\r\n\r\n", cid);
        s.write_all(req.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        drop(s);

        let hits = h.poll_for(&cid, Duration::from_secs(2)).await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, InteractionKind::Http);
        assert!(hits[0].summary.contains(&cid));
    }

    #[tokio::test]
    async fn http_hits_are_correlated_via_subdomain() {
        let h = start_server().await;
        let addr = h.http_addr().unwrap();
        let token = h.new_token();
        let cid = token.correlation_id.clone();
        let mut s = TcpStream::connect(addr).await.unwrap();
        // Pretend the HTTP client sent a Host header carrying the token.
        let req = format!("GET /ping HTTP/1.1\r\nHost: {}.oob.local:7898\r\nConnection: close\r\n\r\n", cid);
        s.write_all(req.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        drop(s);
        let hits = h.poll_for(&cid, Duration::from_secs(2)).await;
        assert_eq!(hits.len(), 1);
    }

    #[tokio::test]
    async fn drain_since_cursor_works() {
        let h = start_server().await;
        let addr = h.http_addr().unwrap();
        let token = h.new_token();
        for i in 0..3 {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let req = format!("GET /{} HTTP/1.1\r\nHost: oob.local\r\n\r\n", token.correlation_id);
            s.write_all(req.as_bytes()).await.unwrap();
            s.flush().await.unwrap();
            let _ = i;
        }
        let _hits = h.poll_for(&token.correlation_id, Duration::from_secs(2)).await;
        let (first, cursor) = h.drain_since(0);
        assert!(first.len() >= 1);
        let (second, _) = h.drain_since(cursor);
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn ignores_hits_for_other_correlation_ids() {
        let h = start_server().await;
        let addr = h.http_addr().unwrap();
        let token1 = h.new_token();
        let token2 = h.new_token();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET /{} HTTP/1.1\r\nHost: oob.local\r\n\r\n", token1.correlation_id);
        s.write_all(req.as_bytes()).await.unwrap();
        drop(s);
        let hits = h.interactions_for(&token2.correlation_id);
        assert!(hits.is_empty());
        let _ = h.poll_for(&token1.correlation_id, Duration::from_secs(2)).await;
    }

    #[test]
    fn parses_dns_query_name() {
        // Minimal DNS query for "abc.oob.local" A record.
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0, 1]); // id
        packet.extend_from_slice(&[0x01, 0x00]); // flags RD
        packet.extend_from_slice(&[0, 1]); // qdcount
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in ["abc", "oob", "local"] {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1]); // qtype=A
        packet.extend_from_slice(&[0, 1]); // qclass=IN
        let q = parse_dns_query(&packet).unwrap();
        assert_eq!(q.qname, "abc.oob.local");
        assert_eq!(q.qtype, "A");
    }

    #[test]
    fn correlation_from_hostname_strips_port_and_suffix() {
        assert_eq!(
            correlation_from_hostname("abc.oob.local:7898", "oob.local:7898").as_deref(),
            Some("abc")
        );
        assert_eq!(
            correlation_from_hostname("other.example.com", "oob.local:7898"),
            None
        );
    }

    #[test]
    fn correlation_from_path_extracts_leading_token() {
        assert_eq!(correlation_from_path("/abc12?x=1").as_deref(), Some("abc12"));
        assert_eq!(correlation_from_path("/"), None);
        assert_eq!(correlation_from_path("/abc_"), None); // underscore disallowed
    }

    #[tokio::test]
    async fn new_tokens_are_unique() {
        let h = start_server().await;
        let tokens = h.new_tokens(16);
        let mut ids: Vec<&str> = tokens.iter().map(|t| t.correlation_id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 16, "all 16 correlation ids must be distinct");
    }

    #[tokio::test]
    async fn poll_batch_returns_hits_in_order() {
        let h = start_server().await;
        let addr = h.http_addr().unwrap();
        let tokens = h.new_tokens(3);
        // Hit the middle one.
        let hit_cid = tokens[1].correlation_id.clone();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET /{} HTTP/1.1\r\nHost: oob.local\r\nConnection: close\r\n\r\n", hit_cid);
        s.write_all(req.as_bytes()).await.unwrap();
        drop(s);

        let ids: Vec<String> = tokens.iter().map(|t| t.correlation_id.clone()).collect();
        let batch = h.poll_batch(&ids, Duration::from_millis(500)).await;
        assert_eq!(batch.len(), 3);
        assert!(batch[0].is_empty(), "token 0 should not have hits");
        assert_eq!(batch[1].len(), 1, "token 1 should have one hit");
        assert!(batch[2].is_empty(), "token 2 should not have hits");
    }
}
