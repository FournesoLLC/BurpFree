//! RFC 6455 WebSocket frame parser used by the proxy's upgrade path.
//!
//! Once the HTTP Upgrade handshake has succeeded, the proxy switches
//! to byte-oriented frame forwarding. Each frame is parsed, published
//! on the event bus (so the UI can show it in real time), then
//! re-serialized onto the opposite side.
//!
//! The parser is streaming: it accepts arbitrary byte chunks and
//! yields frames as they become available via [`FrameParser::feed`].

use burpfree_core::traffic::WsOpcode;

#[derive(Debug, Clone)]
pub struct Frame {
    pub fin: bool,
    pub opcode: WsOpcode,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("payload too large: {0}")]
    TooLarge(u64),
    #[error("reserved bits set")]
    ReservedBits,
    #[error("truncated frame")]
    Truncated,
}

/// Streaming parser.
#[derive(Default)]
pub struct FrameParser {
    buf: Vec<u8>,
    max_payload: u64,
}

impl FrameParser {
    pub fn new(max_payload: u64) -> Self {
        Self { buf: Vec::new(), max_payload }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, FrameError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            match self.try_parse_one()? {
                Some(frame) => out.push(frame),
                None => break,
            }
        }
        Ok(out)
    }

    fn try_parse_one(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let fin = b0 & 0x80 != 0;
        if b0 & 0x70 != 0 {
            return Err(FrameError::ReservedBits);
        }
        let opcode = WsOpcode::from_u8(b0 & 0x0f);
        let masked = b1 & 0x80 != 0;
        let short_len = (b1 & 0x7f) as u64;
        let (payload_len, mut idx) = match short_len {
            0..=125 => (short_len, 2usize),
            126 => {
                if self.buf.len() < 4 {
                    return Ok(None);
                }
                let n = u16::from_be_bytes([self.buf[2], self.buf[3]]) as u64;
                (n, 4usize)
            }
            127 => {
                if self.buf.len() < 10 {
                    return Ok(None);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&self.buf[2..10]);
                let n = u64::from_be_bytes(arr);
                (n, 10usize)
            }
            _ => unreachable!(),
        };
        if payload_len > self.max_payload {
            return Err(FrameError::TooLarge(payload_len));
        }
        let mask = if masked {
            if self.buf.len() < idx + 4 {
                return Ok(None);
            }
            let mut m = [0u8; 4];
            m.copy_from_slice(&self.buf[idx..idx + 4]);
            idx += 4;
            Some(m)
        } else {
            None
        };
        if self.buf.len() < idx + payload_len as usize {
            return Ok(None);
        }
        let mut payload = self.buf[idx..idx + payload_len as usize].to_vec();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        self.buf.drain(..idx + payload_len as usize);
        Ok(Some(Frame { fin, opcode, mask, payload }))
    }
}

/// Serialize a frame. If `mask` is `Some`, the payload is XOR-masked
/// (clients MUST mask; servers MUST NOT).
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + frame.payload.len());
    let b0 = (if frame.fin { 0x80 } else { 0x00 }) | (frame.opcode.to_u8() & 0x0f);
    out.push(b0);
    let masked = frame.mask.is_some();
    let payload_len = frame.payload.len();
    let b1 = (if masked { 0x80 } else { 0x00 })
        | (match payload_len {
            n if n <= 125 => n as u8,
            n if n <= u16::MAX as usize => 126,
            _ => 127,
        });
    out.push(b1);
    match payload_len {
        n if n <= 125 => {}
        n if n <= u16::MAX as usize => out.extend_from_slice(&(n as u16).to_be_bytes()),
        n => out.extend_from_slice(&(n as u64).to_be_bytes()),
    }
    if let Some(m) = frame.mask {
        out.extend_from_slice(&m);
        let start = out.len();
        out.extend_from_slice(&frame.payload);
        for (i, b) in out[start..].iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    } else {
        out.extend_from_slice(&frame.payload);
    }
    out
}

/// Build the Sec-WebSocket-Accept value from a client's Sec-WebSocket-Key.
pub fn ws_accept(key: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sha2::{Digest, Sha1Legacy};
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1Legacy::new();
    hasher.update(key.as_bytes());
    hasher.update(MAGIC.as_bytes());
    STANDARD.encode(hasher.finalize())
}

// SHA-1 is required for the WebSocket handshake. The modern `sha2`
// crate exposes it under `sha2::Sha1` via a feature, but to keep deps
// minimal we embed a tiny SHA-1 implementation here.
mod sha2 {
    pub trait Digest: Sized {
        fn new() -> Self;
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> [u8; 20];
    }

    pub struct Sha1Legacy {
        state: [u32; 5],
        buf: [u8; 64],
        buf_len: usize,
        total: u64,
    }

    impl Digest for Sha1Legacy {
        fn new() -> Self {
            Self {
                state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                buf: [0u8; 64],
                buf_len: 0,
                total: 0,
            }
        }
        fn update(&mut self, mut data: &[u8]) {
            self.total += data.len() as u64;
            while !data.is_empty() {
                let n = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
                self.buf_len += n;
                data = &data[n..];
                if self.buf_len == 64 {
                    compress(&mut self.state, &self.buf);
                    self.buf_len = 0;
                }
            }
        }
        fn finalize(mut self) -> [u8; 20] {
            let bits = self.total * 8;
            // Append 0x80 and pad with zeros to 56 bytes mod 64.
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 56 {
                for i in self.buf_len..64 { self.buf[i] = 0; }
                compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
            for i in self.buf_len..56 { self.buf[i] = 0; }
            self.buf[56..64].copy_from_slice(&bits.to_be_bytes());
            compress(&mut self.state, &self.buf);
            let mut out = [0u8; 20];
            for i in 0..5 {
                out[i*4..i*4+4].copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }
    }

    fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i*4], block[i*4+1], block[i*4+2], block[i*4+3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tiny_text_frame_masked() {
        // FIN+text, masked, len=5, mask=0a0b0c0d, payload "hello" XOR mask.
        let mut raw = vec![0x81, 0x85, 0x0a, 0x0b, 0x0c, 0x0d];
        for (i, b) in b"hello".iter().enumerate() {
            raw.push(b ^ [0x0a, 0x0b, 0x0c, 0x0d][i % 4]);
        }
        let mut p = FrameParser::new(1024);
        let frames = p.feed(&raw).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].fin);
        assert_eq!(frames[0].opcode, WsOpcode::Text);
        assert_eq!(frames[0].payload, b"hello");
    }

    #[test]
    fn roundtrip_encode_decode() {
        let f = Frame {
            fin: true,
            opcode: WsOpcode::Binary,
            mask: Some([1, 2, 3, 4]),
            payload: (0..200).map(|i| (i & 0xff) as u8).collect(),
        };
        let bytes = encode_frame(&f);
        let mut p = FrameParser::new(1024);
        let out = p.feed(&bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, f.payload);
    }

    #[test]
    fn streaming_frame_chunks() {
        let f = Frame { fin: true, opcode: WsOpcode::Text, mask: None, payload: b"hello world".to_vec() };
        let bytes = encode_frame(&f);
        let mut p = FrameParser::new(1024);
        // Feed one byte at a time.
        let mut got = Vec::new();
        for &b in &bytes {
            let frames = p.feed(&[b]).unwrap();
            got.extend(frames);
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"hello world");
    }

    #[test]
    fn large_frame_rejected() {
        // length indicator 127 with 8-byte big length greater than max.
        let mut raw = vec![0x82, 0x7f];
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        let mut p = FrameParser::new(1024);
        let err = p.feed(&raw).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn ws_accept_rfc_example() {
        // RFC 6455 example: dGhlIHNhbXBsZSBub25jZQ== → s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        assert_eq!(ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
