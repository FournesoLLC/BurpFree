//! Upstream dialer. Supports direct connect, HTTP proxy (CONNECT for
//! TLS, absolute-form GET for plaintext), and SOCKS5 (hand-written
//! client — no extra deps).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Upstream {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    Direct,
    Http,
    Socks5,
}

impl Upstream {
    pub fn kind(&self) -> UpstreamKind {
        if self.url.is_empty() || self.url == "direct" {
            UpstreamKind::Direct
        } else if self.url.starts_with("socks5") {
            UpstreamKind::Socks5
        } else {
            UpstreamKind::Http
        }
    }

    pub fn parsed(&self) -> Result<Option<Url>> {
        if matches!(self.kind(), UpstreamKind::Direct) {
            return Ok(None);
        }
        Ok(Some(Url::parse(&self.url).map_err(|e| anyhow!("upstream url parse: {e}"))?))
    }

    /// Dial the target host:port, respecting `self`.
    pub async fn dial(
        &self,
        target_host: &str,
        target_port: u16,
        connect_timeout: Duration,
    ) -> Result<TcpStream> {
        match self.kind() {
            UpstreamKind::Direct => {
                dial_direct(target_host, target_port, connect_timeout).await
            }
            UpstreamKind::Http => {
                let url = self
                    .parsed()?
                    .ok_or_else(|| anyhow!("missing upstream url"))?;
                let host = url.host_str().ok_or_else(|| anyhow!("no host in upstream"))?;
                let port = url.port_or_known_default().unwrap_or(8080);
                let mut stream = dial_direct(host, port, connect_timeout).await?;
                http_connect(
                    &mut stream,
                    target_host,
                    target_port,
                    self.username.as_deref(),
                    self.password.as_deref(),
                )
                .await?;
                Ok(stream)
            }
            UpstreamKind::Socks5 => {
                let url = self
                    .parsed()?
                    .ok_or_else(|| anyhow!("missing upstream url"))?;
                let host = url.host_str().ok_or_else(|| anyhow!("no host in upstream"))?;
                let port = url.port_or_known_default().unwrap_or(1080);
                let mut stream = dial_direct(host, port, connect_timeout).await?;
                socks5_connect(
                    &mut stream,
                    target_host,
                    target_port,
                    self.username.as_deref(),
                    self.password.as_deref(),
                )
                .await?;
                Ok(stream)
            }
        }
    }
}

async fn dial_direct(host: &str, port: u16, to: Duration) -> Result<TcpStream> {
    // Try IP parse first for stable behavior; else use DNS.
    let s = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let addr: SocketAddr = SocketAddr::new(ip, port);
        timeout(to, TcpStream::connect(addr)).await
    } else {
        let addrs = format!("{host}:{port}");
        timeout(to, TcpStream::connect(addrs)).await
    };
    let s = s.map_err(|_| anyhow!("connect timeout"))?;
    Ok(s?)
}

async fn http_connect(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<()> {
    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let (Some(u), Some(p)) = (user, pass) {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let creds = STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;
    // Read until \r\n\r\n.
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("upstream closed during CONNECT"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(anyhow!("CONNECT response too large"));
        }
    }
    // Parse status.
    let first_line = buf
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or_default();
    let line = String::from_utf8_lossy(first_line);
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let status_str = parts.next().unwrap_or("0");
    let status: u16 = status_str.parse().unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(anyhow!("CONNECT failed: {status}"));
    }
    Ok(())
}

async fn socks5_connect(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<()> {
    // Greeting: we support no-auth (0x00) and user/pass (0x02).
    let auth_methods: &[u8] = if user.is_some() && pass.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greet = vec![0x05u8, auth_methods.len() as u8];
    greet.extend_from_slice(auth_methods);
    s.write_all(&greet).await?;
    s.flush().await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(anyhow!("socks: unexpected version {}", reply[0]));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let u = user.ok_or_else(|| anyhow!("socks: user required"))?.as_bytes();
            let p = pass.ok_or_else(|| anyhow!("socks: pass required"))?.as_bytes();
            if u.len() > 255 || p.len() > 255 {
                return Err(anyhow!("socks: credentials too long"));
            }
            let mut buf = Vec::with_capacity(3 + u.len() + p.len());
            buf.push(0x01);
            buf.push(u.len() as u8);
            buf.extend_from_slice(u);
            buf.push(p.len() as u8);
            buf.extend_from_slice(p);
            s.write_all(&buf).await?;
            s.flush().await?;
            let mut auth_reply = [0u8; 2];
            s.read_exact(&mut auth_reply).await?;
            if auth_reply[0] != 0x01 || auth_reply[1] != 0x00 {
                return Err(anyhow!("socks: auth failed"));
            }
        }
        0xff => return Err(anyhow!("socks: no acceptable auth methods")),
        other => return Err(anyhow!("socks: unsupported auth {other}")),
    }
    // Request: CONNECT (0x01), with domain-name addressing.
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(anyhow!("socks: hostname too long"));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    s.flush().await?;
    // Reply: 4 header bytes + variable address.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(anyhow!("socks: CONNECT reply status {}", head[1]));
    }
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        other => return Err(anyhow!("socks: unknown ATYP {other}")),
    };
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn kind_detection() {
        assert_eq!(Upstream::default().kind(), UpstreamKind::Direct);
        let mut u = Upstream::default();
        u.url = "http://127.0.0.1:3128".into();
        assert_eq!(u.kind(), UpstreamKind::Http);
        u.url = "socks5://127.0.0.1:1080".into();
        assert_eq!(u.kind(), UpstreamKind::Socks5);
    }

    #[tokio::test]
    async fn direct_dial_connects_to_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { let _ = listener.accept().await; });
        let u = Upstream::default();
        let s = u.dial("127.0.0.1", addr.port(), Duration::from_secs(2)).await.unwrap();
        drop(s);
    }

    #[tokio::test]
    async fn http_connect_handshake_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read CONNECT request.
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let s_req = String::from_utf8_lossy(&buf[..n]);
            assert!(s_req.starts_with("CONNECT example.com:443"));
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let mut up = Upstream::default();
        up.url = format!("http://{}", addr);
        let _conn = up.dial("example.com", 443, Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_handshake_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Greeting.
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05);
            s.write_all(&[0x05, 0x00]).await.unwrap();
            // CONNECT req.
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await.unwrap();
            // ATYP domain-name
            assert_eq!(head[3], 0x03);
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut host = vec![0u8; l[0] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            // Reply.
            let reply = [0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0];
            s.write_all(&reply).await.unwrap();
        });
        let mut up = Upstream::default();
        up.url = format!("socks5://{}", addr);
        up.dial("example.com", 443, Duration::from_secs(2)).await.unwrap();
    }
}
