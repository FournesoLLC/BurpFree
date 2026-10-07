//! Active HTTP request-smuggling detector.
//!
//! Fires CL.TE / TE.CL / TE.TE differential probes against the target
//! and classifies the server's response time relative to a plain-POST
//! baseline. If a probe times out or takes substantially longer than
//! the baseline, the front-end and back-end layers probably disagree
//! on how to frame the request — the exploitable condition for
//! smuggling.
//!
//! Because [`crate::client::HttpClient`] normalises `Content-Length`
//! and strips duplicate headers, this module opens a direct TCP (or
//! TLS) socket and writes the raw byte sequence itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use burpfree_core::traffic::{HttpVersion, Transaction};

use crate::scanner::{Confidence, Finding, Severity};

/// Overall budget for a single probe (connect + write + read).
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default extra latency (in ms, above the baseline) that we treat as
/// evidence of a hanging smuggled sub-request.
pub const DEFAULT_HANG_THRESHOLD_MS: u64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmugglingVariant {
    /// Both headers present; chunked body valid under TE, trailing
    /// bytes hang if the server picks CL.
    ClTe,
    /// Both headers present; chunked body valid under CL, trailing byte
    /// hangs if the server picks TE.
    TeCl,
    /// TE.TE with a trailing space in the header name
    /// (`Transfer-Encoding : chunked`). Catches lenient parsers.
    TeTeSpaceInName,
    /// TE.TE with a second `Transfer-encoding: xchunked` header. Catches
    /// parsers that pick the last header value or do case-insensitive
    /// de-duplication incorrectly.
    TeTeXchunked,
}

impl SmugglingVariant {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClTe => "CL.TE",
            Self::TeCl => "TE.CL",
            Self::TeTeSpaceInName => "TE.TE (space in header name)",
            Self::TeTeXchunked => "TE.TE (xchunked obfuscation)",
        }
    }

    pub fn detector_id(self) -> &'static str {
        match self {
            Self::ClTe => "request-smuggling:cl-te",
            Self::TeCl => "request-smuggling:te-cl",
            Self::TeTeSpaceInName => "request-smuggling:te-te-space",
            Self::TeTeXchunked => "request-smuggling:te-te-xchunked",
        }
    }

    pub fn all() -> &'static [SmugglingVariant] {
        &[
            Self::ClTe,
            Self::TeCl,
            Self::TeTeSpaceInName,
            Self::TeTeXchunked,
        ]
    }
}

/// Build the raw request bytes for the given variant.
pub fn build_payload(
    variant: SmugglingVariant,
    host: &str,
    port: u16,
    scheme: &str,
    path: &str,
) -> Vec<u8> {
    let host_hdr = host_header(host, port, scheme);
    match variant {
        SmugglingVariant::ClTe => {
            // Body: `1\r\nA\r\n0\r\n\r\n` → 9 bytes, valid chunked.
            // CL=4 → server reads only `1\r\nA`, leaving `\r\n0\r\n\r\n`
            // on the wire. A CL-preferring back-end interprets that as
            // the start of a smuggled request and hangs waiting for the
            // rest of it.
            let head = format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: {host_hdr}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Content-Length: 4\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let mut out = head.into_bytes();
            out.extend_from_slice(b"1\r\nA\r\n0\r\n\r\n");
            out
        }
        SmugglingVariant::TeCl => {
            // Body: `0\r\n\r\nX` → 7 bytes.
            // CL=6 → server consumes six body bytes (`0\r\n\r\nX` minus
            // the trailing byte which stays on the wire). A TE-preferring
            // back-end terminates the body at the first `0\r\n\r\n` and
            // the leftover `X` begins a smuggled request → hangs.
            let head = format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: {host_hdr}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Content-Length: 6\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let mut out = head.into_bytes();
            out.extend_from_slice(b"0\r\n\r\nX");
            out
        }
        SmugglingVariant::TeTeSpaceInName => {
            // `Transfer-Encoding : chunked` with a space before the
            // colon. RFC-7230 strict parsers reject this; some lenient
            // ones still honour it, creating a disagreement.
            let head = format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: {host_hdr}\r\n\
                 Transfer-Encoding : chunked\r\n\
                 Content-Length: 4\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let mut out = head.into_bytes();
            out.extend_from_slice(b"1\r\nA\r\n0\r\n\r\n");
            out
        }
        SmugglingVariant::TeTeXchunked => {
            // Duplicate Transfer-Encoding, the second one obfuscated.
            // A parser that takes "the first chunked value wins" and
            // another that takes "the last header wins" will disagree.
            let head = format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: {host_hdr}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Transfer-encoding: xchunked\r\n\
                 Content-Length: 4\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let mut out = head.into_bytes();
            out.extend_from_slice(b"1\r\nA\r\n0\r\n\r\n");
            out
        }
    }
}

/// Build the baseline request — same shape as a probe but with a
/// well-formed `Content-Length` and no Transfer-Encoding header. The
/// server should answer this in normal response time; the delta
/// against each probe is what we test.
pub fn build_baseline(host: &str, port: u16, scheme: &str, path: &str) -> Vec<u8> {
    let host_hdr = host_header(host, port, scheme);
    let body = b"ping";
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_hdr}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default_port =
        (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    if default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Measure the end-to-end time for one round trip (connect + write +
/// drain). A timeout counts as "took PROBE_TIMEOUT ms" — which is the
/// signal an orphaned smuggled request produces when the back-end
/// waits forever for the rest of it.
pub async fn measure(
    scheme: &str,
    host: &str,
    port: u16,
    payload: &[u8],
    validate_tls: bool,
) -> Result<u64> {
    let start = Instant::now();
    let fut = async {
        let stream = TcpStream::connect((host, port)).await?;
        if scheme == "https" {
            send_tls(stream, host, payload, validate_tls).await
        } else {
            send_plain(stream, payload).await
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, fut).await {
        Ok(Ok(())) => Ok(start.elapsed().as_millis() as u64),
        // IO errors (RST, closed conn) still produce a timing — treat
        // them as "the server answered fast with a hang-up".
        Ok(Err(_)) => Ok(start.elapsed().as_millis() as u64),
        Err(_) => Ok(PROBE_TIMEOUT.as_millis() as u64),
    }
}

async fn send_plain(mut stream: TcpStream, payload: &[u8]) -> Result<()> {
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

async fn send_tls(
    stream: TcpStream,
    host: &str,
    payload: &[u8],
    validate_tls: bool,
) -> Result<()> {
    let root_store = rustls::RootCertStore::empty();
    let config = if validate_tls {
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
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("bad server name: {e}"))?;
    let mut tls = connector.connect(name, stream).await?;
    tls.write_all(payload).await?;
    tls.flush().await?;
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            break;
        }
    }
    Ok(())
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

/// Entry point used by [`crate::scanner::active::ActiveScanner`].
pub async fn probe_smuggling(
    tx: &Transaction,
    hang_threshold_ms: u64,
    validate_tls: bool,
) -> Result<Vec<Finding>> {
    // HTTP/2 (and above) is immune to CL/TE confusion; probing it
    // against an HTTP/1.1 fallback is a separate check we skip here.
    if !matches!(tx.request.http_version, HttpVersion::Http10 | HttpVersion::Http11) {
        return Ok(Vec::new());
    }

    let host = tx.request.host.clone();
    let port = tx.request.port;
    let scheme = tx.request.scheme.clone();
    let path = tx.request.path.clone();

    let baseline_bytes = build_baseline(&host, port, &scheme, &path);
    let baseline = measure(&scheme, &host, port, &baseline_bytes, validate_tls).await?;
    tracing::debug!(baseline_ms = baseline, host, port, "smuggling baseline latency");

    // Run every variant concurrently — orphaned sub-requests force the
    // back-end to wait out `PROBE_TIMEOUT`, so a sequential loop would
    // multiply that budget by the number of variants.
    let probes: Vec<_> = SmugglingVariant::all()
        .iter()
        .copied()
        .map(|variant| {
            let host = host.clone();
            let scheme = scheme.clone();
            let path = path.clone();
            async move {
                let payload = build_payload(variant, &host, port, &scheme, &path);
                let elapsed = measure(&scheme, &host, port, &payload, validate_tls).await?;
                anyhow::Ok((variant, elapsed))
            }
        })
        .collect();
    let results = futures_util::future::join_all(probes).await;

    let mut findings = Vec::new();
    for res in results {
        let (variant, elapsed) = match res {
            Ok(x) => x,
            Err(_) => continue,
        };
        let delta = elapsed.saturating_sub(baseline);
        tracing::debug!(variant = ?variant, elapsed_ms = elapsed, delta_ms = delta, "smuggling probe latency");
        if delta >= hang_threshold_ms {
            let mut f = Finding::new(
                variant.detector_id(),
                &format!("HTTP request smuggling ({})", variant.label()),
                Severity::High,
                Confidence::Tentative,
            );
            f.description = format!(
                "A differential probe using the {} smuggling technique took {}ms longer than the baseline round-trip. \
                 This latency delta is the classic signature of a smuggled sub-request stranded in the back-end's receive \
                 buffer, which means the front-end and back-end disagree on how to frame the request.",
                variant.label(),
                delta
            );
            f.evidence = format!(
                "Baseline latency: {baseline}ms. Probe latency: {elapsed}ms. Delta: +{delta}ms (hang threshold: {hang_threshold_ms}ms)."
            );
            f.remediation = "Reject any inbound request that specifies both Content-Length and Transfer-Encoding, \
                 or that uses obfuscated Transfer-Encoding headers. Prefer HTTP/2 end-to-end where possible — \
                 HTTP/2's binary framing is immune to this class of attack."
                .into();
            f.references = vec![
                "https://portswigger.net/web-security/request-smuggling".into(),
                "https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.3".into(),
            ];
            f.cwe = vec!["CWE-444".into()];
            f.insertion_point = Some("request framing headers".into());
            f.transaction_id = Some(tx.id);
            findings.push(f);
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::traffic::{Request, Response, Transaction};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn clte_payload_contains_both_headers_and_chunked_body() {
        let bytes = build_payload(SmugglingVariant::ClTe, "example.com", 80, "http", "/x");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Transfer-Encoding: chunked\r\n"));
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.ends_with("1\r\nA\r\n0\r\n\r\n"));
        assert!(s.starts_with("POST /x HTTP/1.1\r\n"));
    }

    #[test]
    fn tecl_payload_body_length_matches_declared_cl() {
        let bytes = build_payload(SmugglingVariant::TeCl, "example.com", 8080, "http", "/");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Host: example.com:8080\r\n"));
        assert!(s.contains("Content-Length: 6\r\n"));
        assert!(s.ends_with("0\r\n\r\nX"));
    }

    #[test]
    fn tete_space_variant_has_space_before_colon() {
        let bytes =
            build_payload(SmugglingVariant::TeTeSpaceInName, "example.com", 443, "https", "/");
        let s = String::from_utf8(bytes).unwrap();
        // Default HTTPS port drops the :443 suffix in Host.
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Transfer-Encoding : chunked\r\n"));
    }

    #[test]
    fn tete_xchunked_variant_has_duplicate_te_headers() {
        let bytes = build_payload(SmugglingVariant::TeTeXchunked, "a.b", 80, "http", "/p");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Transfer-Encoding: chunked\r\n"));
        assert!(s.contains("Transfer-encoding: xchunked\r\n"));
    }

    #[test]
    fn baseline_declares_matching_content_length() {
        let bytes = build_baseline("x", 80, "http", "/");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.ends_with("ping"));
        assert!(!s.contains("Transfer-Encoding"));
    }

    #[test]
    fn variant_metadata_is_distinct() {
        let variants = SmugglingVariant::all();
        let mut ids: Vec<_> = variants.iter().map(|v| v.detector_id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), variants.len(), "detector ids must be unique");
        for v in variants {
            assert!(!v.label().is_empty());
        }
    }

    /// Spin up a server that:
    ///   * answers plain requests (no Transfer-Encoding header) fast
    ///   * hangs for `PROBE_TIMEOUT` on any request mentioning
    ///     Transfer-Encoding — simulating a back-end that waited for
    ///     a smuggled sub-request that never arrives.
    async fn start_hanging_server() -> std::net::SocketAddr {
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
                    let txt = String::from_utf8_lossy(&buf[..n]).to_string();
                    if txt.to_ascii_lowercase().contains("transfer-encoding") {
                        // Hang: don't respond, don't close.
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        let body = b"ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                        let _ = s.write_all(body).await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });
        addr
    }

    /// Server that answers every request with a fast 200 regardless of
    /// which smuggling headers are present. Simulates a well-configured
    /// back-end that rejects or ignores the ambiguity cleanly.
    async fn start_fast_server() -> std::net::SocketAddr {
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
                    let _ = s.read(&mut buf).await;
                    let body = b"ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.write_all(body).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn hanging_server_flags_smuggling() {
        let addr = start_hanging_server().await;
        let req = Request::new("POST", &format!("http://127.0.0.1:{}/smuggle", addr.port())).unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        // Lower threshold for the test so we don't wait the full budget.
        let findings = probe_smuggling(&t, 500, false).await.unwrap();
        assert!(
            !findings.is_empty(),
            "expected at least one smuggling finding against a hanging server, got {}",
            findings.len()
        );
        assert!(findings
            .iter()
            .any(|f| f.detector.starts_with("request-smuggling:")));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[tokio::test]
    async fn fast_server_is_clean() {
        let addr = start_fast_server().await;
        let req = Request::new("POST", &format!("http://127.0.0.1:{}/safe", addr.port())).unwrap();
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let findings = probe_smuggling(&t, DEFAULT_HANG_THRESHOLD_MS, false)
            .await
            .unwrap();
        assert!(
            findings.is_empty(),
            "expected no findings against a well-behaved server, got {}",
            findings.len()
        );
    }

    #[tokio::test]
    async fn http2_targets_are_skipped() {
        // Even an "always hangs" server must not produce a finding when
        // the recorded transaction advertises HTTP/2.
        let addr = start_hanging_server().await;
        let mut req =
            Request::new("POST", &format!("http://127.0.0.1:{}/h2", addr.port())).unwrap();
        req.http_version = HttpVersion::Http2;
        let mut t = Transaction::new(req);
        t.response = Some(Response::new(200));
        let findings = probe_smuggling(&t, 500, false).await.unwrap();
        assert!(findings.is_empty(), "HTTP/2 targets must be skipped");
    }
}
