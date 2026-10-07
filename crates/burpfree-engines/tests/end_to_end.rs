//! End-to-end test: proxy → origin → persistence → passive scan.

use std::sync::Arc;
use std::time::Duration;

use burpfree_ca::CertificateAuthority;
use burpfree_core::events::EventBus;
use burpfree_core::scope::Scope;
use burpfree_core::traffic::Transaction;
use burpfree_engines::scanner::passive;
use burpfree_proxy::server::{ProxyServer, ServerConfig, TrafficSink};
use burpfree_proxy::{Interceptor, MatchReplaceEngine, Upstream};
use burpfree_storage::{HistoryFilter, Project};
use parking_lot::RwLock;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start_echo_origin() -> std::net::SocketAddr {
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
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let body = format!("<html><body>Path={path}</body></html>");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nSet-Cookie: sid=abc\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

struct SinkToProject {
    project: Project,
    sitemap: Arc<burpfree_engines::sitemap::SiteMap>,
}

#[async_trait::async_trait]
impl TrafficSink for SinkToProject {
    async fn record(&self, tx: Transaction) -> anyhow::Result<()> {
        let req_wire = tx.request.to_wire_bytes();
        let req_blob = self.project.blobs.put(&req_wire)?;
        let resp_blob = if let Some(r) = &tx.response {
            Some(self.project.blobs.put(&r.to_wire_bytes())?)
        } else {
            None
        };
        self.sitemap.observe(&tx);
        self.project
            .history
            .upsert_transaction(&tx, &req_blob, resp_blob.as_ref())?;
        Ok(())
    }
}

#[tokio::test]
async fn proxy_persists_and_passive_scans_find_issues() {
    let origin = start_echo_origin().await;
    let td = tempdir().unwrap();
    let project_path = td.path().join("proj");
    let project = Project::create(&project_path).unwrap();
    let ca = CertificateAuthority::load_or_create(project.ca_dir()).unwrap();
    let sitemap = Arc::new(burpfree_engines::sitemap::SiteMap::new());

    let sink: Arc<dyn TrafficSink> = Arc::new(SinkToProject {
        project: project.clone(),
        sitemap: sitemap.clone(),
    });
    let cfg = ServerConfig {
        listeners: vec!["127.0.0.1:0".parse().unwrap()],
        ca,
        upstream: Arc::new(RwLock::new(Upstream::default())),
        scope: Arc::new(RwLock::new(Scope::new())),
        match_replace: Arc::new(RwLock::new(MatchReplaceEngine::new())),
        interceptor: Interceptor::new(),
        events: EventBus::default(),
        sink,
        decompression_cap_bytes: 16 << 20,
        max_body_bytes: 32 << 20,
        connect_timeout: Duration::from_secs(5),
        record_out_of_scope: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        host_overrides: burpfree_core::net::HostOverrides::default(),
        tls_passthrough: Arc::new(RwLock::new(Vec::new())),
        platform_auth: Arc::new(RwLock::new(Vec::new())),
    };
    let handle = ProxyServer::start(cfg).await.unwrap();
    let proxy_addr = handle.listen_addrs[0];

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{}/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port(),
        origin.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).contains("Path=/login"));

    tokio::time::sleep(Duration::from_millis(200)).await;

    let rows = project.history.list(&HistoryFilter::default()).unwrap();
    assert_eq!(rows.len(), 1, "expected one recorded transaction, found {}", rows.len());
    let row = &rows[0];
    assert_eq!(row.method, "GET");
    assert_eq!(row.status, Some(200));

    let resp_blob = project
        .history
        .get_response_blob(row.id)
        .unwrap()
        .expect("response blob");
    let resp_bytes = project.blobs.get(&resp_blob).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&resp_bytes).contains("Path=/login"));

    let req_blob = project.history.get_request_blob(row.id).unwrap().unwrap();
    let req_bytes = project.blobs.get(&req_blob).unwrap().unwrap();

    let mut tx = Transaction::new(parse_request(&req_bytes, row));
    tx.response = Some(parse_response(&resp_bytes));
    tx.in_scope = true;

    let findings = passive::run_all(&tx);
    assert!(findings.iter().any(|f| f.detector == "cache-control"), "cache-control finding missing");
    assert!(findings.iter().any(|f| f.detector == "insecure-cookies"), "insecure-cookies finding missing");

    assert!(sitemap.root_count() >= 1);

    handle.shutdown().await.unwrap();
}

fn parse_request(bytes: &[u8], row: &burpfree_storage::StoredSummary) -> burpfree_core::traffic::Request {
    let mut r = burpfree_core::traffic::Request::new(
        &row.method,
        &format!("{}://{}:{}{}", row.scheme, row.host, row.port, row.path),
    )
    .unwrap();
    r.headers = parse_header_block(bytes);
    r.body = body_after(bytes).to_vec();
    r
}

fn parse_response(bytes: &[u8]) -> burpfree_core::traffic::Response {
    let mut r = burpfree_core::traffic::Response::new(0);
    r.headers = parse_header_block(bytes);
    if let Some(line) = bytes.split(|&b| b == b'\n').next() {
        let line = String::from_utf8_lossy(line);
        if let Some(sc) = line.split_whitespace().nth(1) {
            if let Ok(n) = sc.parse() {
                r.status = n;
            }
        }
    }
    r.body = body_after(bytes).to_vec();
    r
}

fn parse_header_block(bytes: &[u8]) -> burpfree_core::headers::Headers {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        if let Some(nl) = bytes[..idx].iter().position(|&b| b == b'\n') {
            return burpfree_core::headers::Headers::parse_block(&bytes[nl + 1..idx]);
        }
    }
    burpfree_core::headers::Headers::new()
}

fn body_after(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        &bytes[idx + 4..]
    } else {
        &[]
    }
}
