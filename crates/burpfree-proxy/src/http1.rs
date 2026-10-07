//! Hand-rolled sans-I/O HTTP/1.1 parser and serializer.
//!
//! The design is driven by three facts:
//!
//! 1. We must preserve bytes-level fidelity for the on-the-wire form.
//! 2. We must not pull the entire body into memory before deciding
//!    whether we can forward it; the IO layer streams.
//! 3. We tolerate malformed messages — we are a security tool and
//!    *will* see malformed inputs; the parser must fail cleanly, not
//!    panic.
//!
//! This parser handles the subset the proxy actually needs: request
//! and response start-lines, headers (including LWS continuation),
//! and body framing via Content-Length or Transfer-Encoding: chunked.
//! `h2` traffic is handed off to the `hyper` HTTP/2 path (TODO).

use std::io;

use burpfree_core::{headers::Headers, traffic::HttpVersion};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Maximum header block size we accept — bigger than real browsers emit.
pub const MAX_HEADER_BYTES: usize = 128 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed start line")]
    BadStartLine,
    #[error("malformed header line")]
    BadHeaderLine,
    #[error("header block too large")]
    HeaderTooLarge,
    #[error("body too large: {0} bytes")]
    BodyTooLarge(u64),
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("chunked encoding error: {0}")]
    Chunked(&'static str),
    #[error("unsupported http version: {0}")]
    UnsupportedVersion(String),
}

/// The parsed start line + headers of a request.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    /// The request target as sent on the wire. May be an absolute URI
    /// for CONNECT or a proxy-style absolute-form, or an origin-form
    /// path. Our server disambiguates.
    pub target: String,
    pub version: HttpVersion,
    pub headers: Headers,
}

#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body (GET/HEAD, 1xx/204/304, …).
    None,
    /// `Content-Length: N` was present.
    FixedLength(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Read until connection close (HTTP/1.0 or missing framing).
    UntilClose,
}

pub fn request_body_framing(head: &RequestHead) -> BodyFraming {
    if head.headers.is_chunked() {
        return BodyFraming::Chunked;
    }
    if let Some(n) = head.headers.content_length() {
        if n == 0 {
            return BodyFraming::None;
        }
        return BodyFraming::FixedLength(n);
    }
    // Methods that typically have no body.
    match head.method.as_str() {
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE" => BodyFraming::None,
        _ => BodyFraming::None, // conservative — require explicit length for POST
    }
}

pub fn response_body_framing(req_method: &str, head: &ResponseHead) -> BodyFraming {
    // RFC 9112 §6.3: HEAD and 1xx/204/304 have no body.
    if req_method == "HEAD" {
        return BodyFraming::None;
    }
    if (100..200).contains(&head.status) || head.status == 204 || head.status == 304 {
        return BodyFraming::None;
    }
    if head.headers.is_chunked() {
        return BodyFraming::Chunked;
    }
    if let Some(n) = head.headers.content_length() {
        if n == 0 {
            return BodyFraming::None;
        }
        return BodyFraming::FixedLength(n);
    }
    // Connection close as framing (common for HTTP/1.0 origin servers).
    BodyFraming::UntilClose
}

/// Parse the request head from a buffered reader. Reads until the
/// terminating `\r\n\r\n`.
pub async fn read_request_head<R: tokio::io::AsyncRead + Unpin>(
    r: &mut BufReader<R>,
) -> Result<RequestHead, HttpError> {
    let block = read_head_block(r).await?;
    parse_request_head(&block)
}

pub async fn read_response_head<R: tokio::io::AsyncRead + Unpin>(
    r: &mut BufReader<R>,
) -> Result<ResponseHead, HttpError> {
    let block = read_head_block(r).await?;
    parse_response_head(&block)
}

async fn read_head_block<R: tokio::io::AsyncRead + Unpin>(
    r: &mut BufReader<R>,
) -> Result<Vec<u8>, HttpError> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        let n_before = buf.len();
        let read = r.read_until(b'\n', &mut buf).await?;
        if read == 0 {
            if buf.is_empty() {
                return Err(HttpError::UnexpectedEof);
            }
            return Err(HttpError::BadHeaderLine);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(HttpError::HeaderTooLarge);
        }
        // Detect end of head block: empty line (CRLF or LF).
        let tail = &buf[n_before..];
        if tail == b"\r\n" || tail == b"\n" {
            break;
        }
    }
    Ok(buf)
}

pub fn parse_request_head(buf: &[u8]) -> Result<RequestHead, HttpError> {
    let (start, rest) = split_once(buf, &[b'\n']).ok_or(HttpError::BadStartLine)?;
    let start = trim_cr(start);
    let mut parts = start.splitn(3, |&b| b == b' ');
    let method = parts.next().ok_or(HttpError::BadStartLine)?;
    let target = parts.next().ok_or(HttpError::BadStartLine)?;
    let version_bytes = parts.next().ok_or(HttpError::BadStartLine)?;
    let version = parse_version(version_bytes)?;
    let headers = Headers::parse_block(rest);
    Ok(RequestHead {
        method: String::from_utf8_lossy(method).to_string(),
        target: String::from_utf8_lossy(target).to_string(),
        version,
        headers,
    })
}

pub fn parse_response_head(buf: &[u8]) -> Result<ResponseHead, HttpError> {
    let (start, rest) = split_once(buf, &[b'\n']).ok_or(HttpError::BadStartLine)?;
    let start = trim_cr(start);
    let mut parts = start.splitn(3, |&b| b == b' ');
    let version_bytes = parts.next().ok_or(HttpError::BadStartLine)?;
    let status_bytes = parts.next().ok_or(HttpError::BadStartLine)?;
    let reason_bytes = parts.next().unwrap_or(b"");
    let version = parse_version(version_bytes)?;
    let status = std::str::from_utf8(status_bytes)
        .map_err(|_| HttpError::BadStartLine)?
        .parse::<u16>()
        .map_err(|_| HttpError::BadStartLine)?;
    let reason = String::from_utf8_lossy(reason_bytes).to_string();
    let headers = Headers::parse_block(rest);
    Ok(ResponseHead { version, status, reason, headers })
}

fn parse_version(b: &[u8]) -> Result<HttpVersion, HttpError> {
    match b {
        b"HTTP/1.0" => Ok(HttpVersion::Http10),
        b"HTTP/1.1" => Ok(HttpVersion::Http11),
        b"HTTP/2" | b"HTTP/2.0" => Ok(HttpVersion::Http2),
        other => Err(HttpError::UnsupportedVersion(
            String::from_utf8_lossy(other).to_string(),
        )),
    }
}

fn split_once<'a>(buf: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    for i in 0..buf.len().saturating_sub(sep.len() - 1) {
        if buf[i..i + sep.len()] == *sep {
            return Some((&buf[..i], &buf[i + sep.len()..]));
        }
    }
    None
}

fn trim_cr(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 {
        match b[end - 1] {
            b'\n' | b'\r' => end -= 1,
            _ => break,
        }
    }
    &b[..end]
}

// ---------------------------------------------------------------------------
// Body reading
// ---------------------------------------------------------------------------

pub async fn read_body<R: tokio::io::AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    framing: BodyFraming,
    max_bytes: u64,
) -> Result<Vec<u8>, HttpError> {
    match framing {
        BodyFraming::None => Ok(Vec::new()),
        BodyFraming::FixedLength(n) => {
            if n > max_bytes {
                return Err(HttpError::BodyTooLarge(n));
            }
            let mut buf = vec![0u8; n as usize];
            r.read_exact(&mut buf).await?;
            Ok(buf)
        }
        BodyFraming::Chunked => read_chunked_body(r, max_bytes).await,
        BodyFraming::UntilClose => {
            let mut buf = Vec::with_capacity(1024);
            r.read_to_end(&mut buf).await?;
            if (buf.len() as u64) > max_bytes {
                return Err(HttpError::BodyTooLarge(buf.len() as u64));
            }
            Ok(buf)
        }
    }
}

async fn read_chunked_body<R: tokio::io::AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    max_bytes: u64,
) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Err(HttpError::UnexpectedEof);
        }
        let trimmed = trim_cr(&line);
        let size_str = std::str::from_utf8(trimmed)
            .map_err(|_| HttpError::Chunked("non-utf8 chunk size"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = u64::from_str_radix(size_str, 16)
            .map_err(|_| HttpError::Chunked("bad hex chunk size"))?;
        if size == 0 {
            // read trailing headers (if any) up to \r\n
            loop {
                line.clear();
                let n = r.read_until(b'\n', &mut line).await?;
                if n == 0 {
                    return Err(HttpError::UnexpectedEof);
                }
                let t = trim_cr(&line);
                if t.is_empty() {
                    return Ok(out);
                }
            }
        }
        if out.len() as u64 + size > max_bytes {
            return Err(HttpError::BodyTooLarge(out.len() as u64 + size));
        }
        let mut chunk = vec![0u8; size as usize];
        r.read_exact(&mut chunk).await?;
        out.append(&mut chunk);
        // read trailing CRLF
        line.clear();
        r.read_until(b'\n', &mut line).await?;
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Write a request head and body to a writer. If `chunked` is false we
/// recompute `Content-Length`. The caller is responsible for keeping
/// `Transfer-Encoding` consistent.
pub async fn write_request<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    head: &RequestHead,
    body: &[u8],
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(256 + body.len());
    buf.extend_from_slice(head.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(head.target.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(head.version.as_str().as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&head.headers.to_wire_bytes());
    buf.extend_from_slice(b"\r\n");
    w.write_all(&buf).await?;
    if !body.is_empty() {
        w.write_all(body).await?;
    }
    w.flush().await
}

pub async fn write_response<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    head: &ResponseHead,
    body: &[u8],
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(256 + body.len());
    buf.extend_from_slice(head.version.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(head.status.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(head.reason.as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&head.headers.to_wire_bytes());
    buf.extend_from_slice(b"\r\n");
    w.write_all(&buf).await?;
    if !body.is_empty() {
        w.write_all(body).await?;
    }
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn br(bytes: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(bytes.to_vec()))
    }

    #[tokio::test]
    async fn parse_simple_request() {
        let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        let mut r = br(raw);
        let h = read_request_head(&mut r).await.unwrap();
        assert_eq!(h.method, "GET");
        assert_eq!(h.target, "/path");
        assert_eq!(h.headers.get("host"), Some("example.com"));
    }

    #[tokio::test]
    async fn parse_response_and_fixed_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut r = br(raw);
        let h = read_response_head(&mut r).await.unwrap();
        assert_eq!(h.status, 200);
        let framing = response_body_framing("GET", &h);
        assert_eq!(framing, BodyFraming::FixedLength(5));
        let body = read_body(&mut r, framing, 1024).await.unwrap();
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn parse_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut r = br(raw);
        let h = read_response_head(&mut r).await.unwrap();
        let framing = response_body_framing("GET", &h);
        assert_eq!(framing, BodyFraming::Chunked);
        let body = read_body(&mut r, framing, 1024).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn body_too_large_errs() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let mut r = br(raw);
        let h = read_response_head(&mut r).await.unwrap();
        let err = read_body(&mut r, response_body_framing("GET", &h), 10).await.err();
        assert!(matches!(err, Some(HttpError::BodyTooLarge(100))));
    }

    #[tokio::test]
    async fn head_too_large_errs() {
        let mut long = Vec::new();
        long.extend_from_slice(b"GET / HTTP/1.1\r\n");
        for i in 0..(MAX_HEADER_BYTES / 20 + 5) {
            long.extend_from_slice(format!("X-Big-{i}: aaaaaaaaaa\r\n").as_bytes());
        }
        long.extend_from_slice(b"\r\n");
        let mut r = br(&long);
        let err = read_request_head(&mut r).await.err();
        assert!(matches!(err, Some(HttpError::HeaderTooLarge)));
    }
}
