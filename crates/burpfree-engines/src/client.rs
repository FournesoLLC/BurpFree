//! Minimal HTTP/1.1 client used by Repeater, Intruder, and Active
//! Scanner. Reuses the proxy's `http1` parser and the `Upstream`
//! dialer so these engines go through the same code paths (and the
//! same scope / match-replace / event-bus plumbing).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use burpfree_codec::compression::{maybe_decompress, DecodeLimit};
use burpfree_core::traffic::{HttpVersion, Request, Response};
use burpfree_proxy::http1::{
    read_body, read_response_head, response_body_framing, write_request, RequestHead,
};
use burpfree_proxy::Upstream;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpClientConfig {
    pub upstream: Upstream,
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    pub max_body_bytes: u64,
    pub transparent_decompress: bool,
    pub validate_tls: bool,
    /// Hostname → IP overrides, applied before DNS resolution. The field
    /// is `#[serde(skip)]` because `HostOverrides` is an in-process shared
    /// handle; project persistence is handled by the owning app state.
    #[serde(skip)]
    pub host_overrides: Option<burpfree_core::net::HostOverrides>,
    /// Follow-redirect policy for Repeater/Intruder/Scanner clients.
    /// Defaults to Never — the proxy itself never follows redirects.
    #[serde(default)]
    pub follow_redirects: burpfree_core::net::FollowRedirectPolicy,
    /// Maximum redirect hops before we bail out.
    #[serde(default = "default_redirect_hops")]
    pub max_redirect_hops: u8,
}

fn default_redirect_hops() -> u8 { 5 }

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct DurationShim { secs: u64, nanos: u32 }

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        DurationShim { secs: d.as_secs(), nanos: d.subsec_nanos() }.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let shim = DurationShim::deserialize(d)?;
        Ok(Duration::new(shim.secs, shim.nanos))
    }
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            upstream: Upstream::default(),
            timeout: Duration::from_secs(30),
            max_body_bytes: 128 * 1024 * 1024,
            transparent_decompress: true,
            validate_tls: false,
            host_overrides: None,
            follow_redirects: burpfree_core::net::FollowRedirectPolicy::Never,
            max_redirect_hops: 5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpClient {
    cfg: HttpClientConfig,
}

impl HttpClient {
    pub fn new(cfg: HttpClientConfig) -> Self {
        Self { cfg }
    }

    pub async fn send(&self, req: &Request) -> Result<Response> {
        self.send_following_with_policy(req, self.cfg.follow_redirects)
            .await
    }

    /// Send with an explicit redirect policy override — used by the
    /// Repeater when a tab opts out of the global policy. Falls back
    /// to `self.cfg.follow_redirects` when `policy` is `None`.
    pub async fn send_with_policy(
        &self,
        req: &Request,
        policy: Option<burpfree_core::net::FollowRedirectPolicy>,
    ) -> Result<Response> {
        let effective = policy.unwrap_or(self.cfg.follow_redirects);
        self.send_following_with_policy(req, effective).await
    }

    /// One raw request/response round-trip, bypassing redirect handling.
    pub async fn send_one(&self, req: &Request) -> Result<Response> {
        let start = Instant::now();
        // Hostname override lookup for direct dialing.
        let dial_host: String = match &self.cfg.host_overrides {
            Some(ov) if matches!(
                self.cfg.upstream.kind(),
                burpfree_proxy::upstream::UpstreamKind::Direct
            ) => ov.resolve(&req.host).unwrap_or_else(|| req.host.clone()),
            _ => req.host.clone(),
        };
        let stream = self
            .cfg
            .upstream
            .dial(&dial_host, req.port, self.cfg.timeout)
            .await?;
        if req.scheme == "https" {
            let root_store = rustls::RootCertStore::empty();
            // Empty root store + skip verification when validate_tls is false.
            let config = if self.cfg.validate_tls {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            } else {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                    .with_no_client_auth()
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let name = rustls::pki_types::ServerName::try_from(req.host.clone())
                .map_err(|e| anyhow::anyhow!("bad server name: {e}"))?;
            let tls = connector.connect(name, stream).await?;
            let r = send_and_recv(tls, req, self.cfg.max_body_bytes).await?;
            self.finish(r, start)
        } else {
            let r = send_and_recv(stream, req, self.cfg.max_body_bytes).await?;
            self.finish(r, start)
        }
    }

    async fn send_following_with_policy(
        &self,
        req: &Request,
        policy: burpfree_core::net::FollowRedirectPolicy,
    ) -> Result<Response> {
        use burpfree_core::net::FollowRedirectPolicy;
        if matches!(policy, FollowRedirectPolicy::Never) {
            return self.send_one(req).await;
        }
        let mut current = req.clone();
        let mut hops = 0u8;
        loop {
            let resp = self.send_one(&current).await?;
            // Only 3xx with a Location header are candidates.
            if !(300..400).contains(&resp.status) {
                return Ok(resp);
            }
            let Some(loc) = resp.headers.get("Location").map(|s| s.to_string()) else {
                return Ok(resp);
            };
            if hops >= self.cfg.max_redirect_hops {
                return Ok(resp);
            }
            // Resolve the redirect target against the current URL.
            let next_url = resolve_redirect_target(&current, &loc);
            let next = match burpfree_core::traffic::Request::new(&current.method, &next_url) {
                Ok(mut r) => {
                    // Preserve id so the UI follows the chain.
                    r.id = current.id;
                    // Preserve body for 307/308; strip for 301/302/303.
                    match resp.status {
                        307 | 308 => {
                            r.body = current.body.clone();
                            r.headers = current.headers.clone();
                        }
                        _ => {
                            r.method = if r.method.eq_ignore_ascii_case("GET")
                                || r.method.eq_ignore_ascii_case("HEAD")
                            {
                                r.method
                            } else {
                                "GET".to_string()
                            };
                        }
                    }
                    r
                }
                Err(_) => return Ok(resp),
            };
            // Apply policy.
            let allowed = match policy {
                FollowRedirectPolicy::Never => false,
                FollowRedirectPolicy::OnSite => {
                    current.host.eq_ignore_ascii_case(&next.host) && current.port == next.port
                }
                FollowRedirectPolicy::InScope => {
                    // Without a scope predicate injected here, we conservatively
                    // treat InScope as OnSite — the proxy enforces real scope.
                    current.host.eq_ignore_ascii_case(&next.host) && current.port == next.port
                }
                FollowRedirectPolicy::Always => true,
            };
            if !allowed {
                return Ok(resp);
            }
            current = next;
            hops += 1;
        }
    }

    fn finish(&self, mut r: Response, start: Instant) -> Result<Response> {
        r.elapsed_ms = start.elapsed().as_millis() as u64;
        if self.cfg.transparent_decompress {
            let enc = r.headers.get("Content-Encoding").map(|s| s.to_string());
            if let Some(e) = enc.as_deref() {
                let limit = DecodeLimit {
                    ratio: 100,
                    floor: 1 << 20,
                    ceiling: 256 << 20,
                };
                if let Ok(decoded) = maybe_decompress(Some(e), &r.body, limit) {
                    r.body = decoded;
                    r.headers.remove("Content-Encoding");
                }
            }
        }
        Ok(r)
    }
}

/// One-shot convenience that constructs a client with defaults.
pub async fn send_once(req: &Request) -> Result<Response> {
    HttpClient::new(HttpClientConfig::default()).send(req).await
}

async fn send_and_recv<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    req: &Request,
    max_body: u64,
) -> Result<Response> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let head = build_outbound_head(req);
    write_request(&mut wr, &head, &req.body).await?;
    let mut reader = BufReader::new(&mut rd);
    let resp_head = read_response_head(&mut reader).await?;
    let framing = response_body_framing(&req.method, &resp_head);
    let body = read_body(&mut reader, framing, max_body).await?;
    Ok(Response {
        id: burpfree_core::ids::TrafficId::new(),
        status: resp_head.status,
        reason: resp_head.reason,
        http_version: resp_head.version,
        headers: resp_head.headers,
        body,
        created_at_ms: burpfree_core::traffic::now_ms(),
        elapsed_ms: 0,
        original_body_size: None,
    })
}

fn build_outbound_head(req: &Request) -> RequestHead {
    let mut headers = req.headers.clone();
    let host_val = if (req.scheme == "http" && req.port == 80)
        || (req.scheme == "https" && req.port == 443)
    {
        req.host.clone()
    } else {
        format!("{}:{}", req.host, req.port)
    };
    headers.set("Host", host_val);
    headers.set("Connection", "close");
    headers.remove("Proxy-Connection");
    if req.body.is_empty() {
        headers.remove("Content-Length");
    } else {
        headers.set("Content-Length", req.body.len().to_string());
    }
    RequestHead {
        method: req.method.clone(),
        target: req.path.clone(),
        version: HttpVersion::Http11,
        headers,
    }
}

/// Resolve a Location header against the current request's URL. Handles
/// absolute (`http://...`), scheme-relative (`//host/path`), and
/// path-relative (`/path`, `./x`) forms.
fn resolve_redirect_target(base: &Request, location: &str) -> String {
    let loc = location.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    if let Some(rest) = loc.strip_prefix("//") {
        return format!("{}://{}", base.scheme, rest);
    }
    let host_part = if (base.scheme == "http" && base.port == 80)
        || (base.scheme == "https" && base.port == 443)
    {
        base.host.clone()
    } else {
        format!("{}:{}", base.host, base.port)
    };
    if loc.starts_with('/') {
        return format!("{}://{}{}", base.scheme, host_part, loc);
    }
    // Relative path: resolve against current path's directory.
    let base_path = base.path_only();
    let dir = base_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    format!("{}://{}{}/{}", base.scheme, host_part, dir, loc)
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn send_plain_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let txt = String::from_utf8_lossy(&buf[..n]);
            assert!(txt.starts_with("GET /abc HTTP/1.1"));
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nokok",
            )
            .await
            .unwrap();
        });
        let req = Request::new("GET", &format!("http://127.0.0.1:{}/abc", addr.port())).unwrap();
        let resp = HttpClient::new(HttpClientConfig::default()).send(&req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"okok");
    }

    #[tokio::test]
    async fn host_override_redirects_dial_to_loopback() {
        use burpfree_core::net::{HostOverride, HostOverrides};
        // Server bound to loopback; the client thinks it's going to
        // "fake.local" but the override redirects the dial to 127.0.0.1.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
        });
        let overrides = HostOverrides::load(vec![HostOverride {
            enabled: true,
            hostname: "fake.local".into(),
            ip: "127.0.0.1".into(),
        }]);
        let mut cfg = HttpClientConfig::default();
        cfg.host_overrides = Some(overrides);
        let req = Request::new("GET", &format!("http://fake.local:{}/x", addr.port())).unwrap();
        let resp = HttpClient::new(cfg).send(&req).await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn follow_redirects_on_site_follows_same_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // First request → 302 to /final; second request → 200 "done".
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let _ = s1.read(&mut buf).await;
            let r = "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n";
            s1.write_all(r.as_bytes()).await.unwrap();
            drop(s1);
            let (mut s2, _) = listener.accept().await.unwrap();
            let n = s2.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET /final"));
            s2.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone").await.unwrap();
        });
        let mut cfg = HttpClientConfig::default();
        cfg.follow_redirects = burpfree_core::net::FollowRedirectPolicy::OnSite;
        let req = Request::new("GET", &format!("http://127.0.0.1:{}/start", addr.port())).unwrap();
        let resp = HttpClient::new(cfg).send(&req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"done");
    }

    #[test]
    fn resolve_redirect_absolute_relative_schemeless() {
        let base = Request::new("GET", "http://example.com/api/users").unwrap();
        assert_eq!(
            resolve_redirect_target(&base, "https://other.com/x"),
            "https://other.com/x"
        );
        assert_eq!(
            resolve_redirect_target(&base, "//cdn.example.com/js/a.js"),
            "http://cdn.example.com/js/a.js"
        );
        assert_eq!(
            resolve_redirect_target(&base, "/login"),
            "http://example.com/login"
        );
    }
}
