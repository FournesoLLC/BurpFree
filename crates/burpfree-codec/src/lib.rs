//! Encoding/decoding helpers used by the Decoder tool, the proxy's
//! transparent-decompression pipeline, and various engines.
//!
//! All functions are side-effect free and allocate only to produce
//! their results. None takes a lock or does I/O.

pub mod chain;
pub mod compression;
pub mod html;
pub mod jwt;
pub mod text;

pub use chain::{apply_chain, smart_decode, ChainStep, Transform};
pub use compression::{decode_body, encode_gzip, maybe_decompress, DecodeLimit};
pub use html::{html_decode, html_encode};
pub use jwt::{jwt_decode, jwt_sign, jwt_verify_hmac, JwtAlg, JwtParts};
pub use text::{
    base64_decode, base64_encode, base64url_decode, base64url_encode, hex_decode, hex_encode,
    unicode_escape_decode, unicode_escape_encode, url_decode, url_encode,
};
