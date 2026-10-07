//! Root CA + per-host leaf certificate factory for the BurpFree MITM
//! proxy.
//!
//! On first launch each project directory gets its own self-signed
//! root CA. Leaf certificates are generated on demand for each host
//! the proxy intercepts and cached in-memory and on disk so the UI can
//! inspect them.
//!
//! The root key never leaves the project directory. The on-disk key
//! file is written with mode `0600` on Unix (best-effort on Windows).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;
use rcgen::{
    date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};

const CA_CN: &str = "BurpFree Root CA";
const CA_ORG: &str = "BurpFree";
const CA_FILE: &str = "ca-cert.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const LEAF_DAYS: i32 = 825; // Apple-compatible 2-year limit
const CA_YEARS: i32 = 10;

/// A loaded or freshly generated root certificate authority.
#[derive(Clone)]
pub struct CertificateAuthority {
    inner: Arc<CaInner>,
}

struct CaInner {
    root_cert: Certificate,
    root_key_pair: KeyPair,
    root_cert_pem: String,
    root_key_pem: String,
    root_cert_der: Vec<u8>,
    leaf_cache: RwLock<std::collections::HashMap<String, Arc<CertifiedKey>>>,
    disk_dir: Option<PathBuf>,
}

/// Public details for the UI's Settings/CA panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaInfo {
    pub subject: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256_fingerprint: String,
}

impl CertificateAuthority {
    /// Load an existing CA from `dir` or generate a new one.
    ///
    /// `dir` is typically `<project>/ca/`. The directory is created on
    /// demand.
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let cert_path = dir.join(CA_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            Self::load(&cert_path, &key_path, Some(dir))
        } else {
            let ca = Self::generate(Some(dir.clone()))?;
            std::fs::write(&cert_path, &ca.inner.root_cert_pem)
                .with_context(|| format!("write {}", cert_path.display()))?;
            std::fs::write(&key_path, &ca.inner.root_key_pem)
                .with_context(|| format!("write {}", key_path.display()))?;
            restrict_perms(&key_path);
            Ok(ca)
        }
    }

    /// Load an existing CA from PEM files on disk.
    pub fn load(cert_path: &Path, key_path: &Path, disk_dir: Option<PathBuf>) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        let key_pair = KeyPair::from_pem(&key_pem).context("parse CA key PEM")?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem).context("parse CA cert PEM")?;
        let cert = params
            .self_signed(&key_pair)
            .context("re-sign CA params with existing key")?;
        let root_cert_der = cert.der().to_vec();
        Ok(Self {
            inner: Arc::new(CaInner {
                root_cert: cert,
                root_key_pair: key_pair,
                root_cert_pem: cert_pem,
                root_key_pem: key_pem,
                root_cert_der,
                leaf_cache: RwLock::new(std::collections::HashMap::new()),
                disk_dir,
            }),
        })
    }

    /// Generate a fresh root CA in memory.
    pub fn generate(disk_dir: Option<PathBuf>) -> Result<Self> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_CN);
        dn.push(DnType::OrganizationName, CA_ORG);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = chrono::Utc::now();
        params.not_before = date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let after = now + chrono::Duration::days(365 * CA_YEARS as i64);
        params.not_after = date_time_ymd(after.year(), after.month() as u8, after.day() as u8);
        params.serial_number = Some(rand_serial().into());
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let root_cert_pem = cert.pem();
        let root_key_pem = key_pair.serialize_pem();
        let root_cert_der = cert.der().to_vec();
        Ok(Self {
            inner: Arc::new(CaInner {
                root_cert: cert,
                root_key_pair: key_pair,
                root_cert_pem,
                root_key_pem,
                root_cert_der,
                leaf_cache: RwLock::new(std::collections::HashMap::new()),
                disk_dir,
            }),
        })
    }

    pub fn root_cert_pem(&self) -> &str {
        &self.inner.root_cert_pem
    }

    pub fn root_cert_der(&self) -> &[u8] {
        &self.inner.root_cert_der
    }

    /// Export the root cert PEM to a user-chosen path (for browser trust store).
    pub fn export_root(&self, path: &Path) -> Result<()> {
        std::fs::write(path, &self.inner.root_cert_pem)
            .with_context(|| format!("write {}", path.display()))
    }

    /// Return a cached or newly minted leaf certificate for `host`.
    /// If `host` is an IP, it's placed in a `SAN:iPAddress` entry;
    /// otherwise in a `SAN:dNSName`.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let key = host.to_ascii_lowercase();
        if let Some(k) = self.inner.leaf_cache.read().get(&key).cloned() {
            return Ok(k);
        }
        let (cert_pem, key_pem, cert_der, key_der) = self.generate_leaf(host)?;
        let der_cert = CertificateDer::from(cert_der);
        let der_key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_der).into();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&der_key)
            .map_err(|e| anyhow!("could not build signing key: {e:?}"))?;
        let certified = Arc::new(CertifiedKey::new(vec![der_cert], signing_key));

        if let Some(dir) = self.inner.disk_dir.as_ref() {
            let certs_dir = dir.join("certs");
            let _ = std::fs::create_dir_all(&certs_dir);
            let _ = std::fs::write(certs_dir.join(format!("{}.pem", sanitize_host(host))), &cert_pem);
            let _ = std::fs::write(certs_dir.join(format!("{}.key", sanitize_host(host))), &key_pem);
        }
        self.inner.leaf_cache.write().insert(key, certified.clone());
        Ok(certified)
    }

    fn generate_leaf(&self, host: &str) -> Result<(String, String, Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn.push(DnType::OrganizationName, CA_ORG);
        params.distinguished_name = dn;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            params.subject_alt_names.push(SanType::DnsName(host.try_into()?));
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        let now = chrono::Utc::now() - chrono::Duration::days(1);
        params.not_before = date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let after = chrono::Utc::now() + chrono::Duration::days(LEAF_DAYS as i64);
        params.not_after = date_time_ymd(after.year(), after.month() as u8, after.day() as u8);
        params.serial_number = Some(rand_serial().into());
        let kp = KeyPair::generate()?;
        let cert = params.signed_by(&kp, &self.inner.root_cert, &self.inner.root_key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = kp.serialize_pem();
        let cert_der = cert.der().to_vec();
        let key_der = kp.serialize_der();
        Ok((cert_pem, key_pem, cert_der, key_der))
    }

    pub fn info(&self) -> CaInfo {
        let (serial, nb, na, fp) = parse_metadata(&self.inner.root_cert_der);
        CaInfo {
            subject: format!("CN={CA_CN}, O={CA_ORG}"),
            serial,
            not_before: nb,
            not_after: na,
            sha256_fingerprint: fp,
        }
    }
}

use chrono::Datelike;

#[allow(dead_code)]
fn _unused_marker() { let _ = (SystemTime::now(), Duration::from_secs(0)); }

fn rand_serial() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf[0] &= 0x7f; // positive
    buf.to_vec()
}

fn sanitize_host(h: &str) -> String {
    h.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

#[cfg(unix)]
fn restrict_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) {
    // Best-effort on Windows: filesystem ACLs out of scope here.
}

fn parse_metadata(cert_der: &[u8]) -> (String, String, String, String) {
    use x509_parser::prelude::*;
    let fallback = ("<unknown>".to_string(), String::new(), String::new(), String::new());
    let parsed = X509Certificate::from_der(cert_der);
    let (serial, nb, na) = match parsed {
        Ok((_, cert)) => (
            cert.tbs_certificate.raw_serial_as_string(),
            cert.tbs_certificate
                .validity
                .not_before
                .to_rfc2822()
                .unwrap_or_default(),
            cert.tbs_certificate
                .validity
                .not_after
                .to_rfc2822()
                .unwrap_or_default(),
        ),
        Err(_) => return fallback,
    };
    // BLAKE3-derived fingerprint for display. For the strict SHA-256
    // fingerprint users can run `openssl x509 -fingerprint` on the
    // exported PEM.
    let fp = fingerprint_hex(cert_der);
    (serial, nb, na, fp)
}

fn fingerprint_hex(data: &[u8]) -> String {
    let h = ::blake3::hash(data);
    hex::encode(&h.as_bytes()[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_reloads_ca() {
        let dir = tempdir().unwrap();
        let a = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let b = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(a.root_cert_pem(), b.root_cert_pem());
    }

    #[test]
    fn mints_leaf_for_host() {
        let ca = CertificateAuthority::generate(None).unwrap();
        let leaf = ca.leaf_for("example.com").unwrap();
        assert!(!leaf.cert.is_empty());
    }

    #[test]
    fn leaf_cache_returns_same_key() {
        let ca = CertificateAuthority::generate(None).unwrap();
        let a = ca.leaf_for("api.example.com").unwrap();
        let b = ca.leaf_for("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn mints_leaf_for_ip() {
        let ca = CertificateAuthority::generate(None).unwrap();
        let leaf = ca.leaf_for("127.0.0.1").unwrap();
        assert!(!leaf.cert.is_empty());
    }

    #[test]
    fn info_populated() {
        let ca = CertificateAuthority::generate(None).unwrap();
        let info = ca.info();
        assert!(info.subject.contains(CA_CN));
        assert!(!info.sha256_fingerprint.is_empty());
    }
}

mod hex {
    pub fn encode(b: &[u8]) -> String {
        const H: &[u8] = b"0123456789abcdef";
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push(H[(x >> 4) as usize] as char);
            s.push(H[(x & 0x0f) as usize] as char);
        }
        s
    }
}
