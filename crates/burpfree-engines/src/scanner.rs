//! Scanner subsystem.
//!
//! * [`passive`] — deterministic checks over observed transactions.
//! * [`active`] — mutate-and-replay checks that only run on in-scope
//!   requests and never cross the configured budget.
//!
//! Both engines emit [`Finding`]s via a channel. The CLI and UI
//! subscribe and either print them or store them in the history DB.

pub mod passive;
pub mod passive_ws;
pub mod active;
pub mod profiles;
pub mod knowledge_base;

use serde::{Deserialize, Serialize};

use burpfree_core::ids::TrafficId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Firm => "firm",
            Self::Certain => "certain",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: TrafficId,
    pub detector: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: String,
    pub remediation: String,
    pub transaction_id: Option<TrafficId>,
    /// Where in the request the finding is anchored (parameter name,
    /// header name, body section). Used for issue dedup and reporting.
    #[serde(default)]
    pub insertion_point: Option<String>,
    /// External references for the issue (CWE / OWASP / RFC URLs).
    #[serde(default)]
    pub references: Vec<String>,
    /// Related CWE identifiers (e.g. ["CWE-79"]).
    #[serde(default)]
    pub cwe: Vec<String>,
}

impl Finding {
    pub fn new(detector: &str, title: &str, severity: Severity, confidence: Confidence) -> Self {
        Self {
            id: TrafficId::new(),
            detector: detector.to_string(),
            title: title.to_string(),
            description: String::new(),
            severity,
            confidence,
            evidence: String::new(),
            remediation: String::new(),
            transaction_id: None,
            insertion_point: None,
            references: Vec::new(),
            cwe: Vec::new(),
        }
    }

    /// Deterministic dedup fingerprint: detector + title + insertion point.
    /// Severity/confidence are intentionally excluded — a detector that
    /// upgrades severity later still collapses onto the same issue row.
    pub fn fingerprint(&self) -> String {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(self.detector.as_bytes());
        h.update(b"|");
        h.update(self.title.as_bytes());
        h.update(b"|");
        h.update(self.insertion_point.as_deref().unwrap_or("").as_bytes());
        let hex = h.finalize();
        hex::encode(&hex.as_bytes()[..16])
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
