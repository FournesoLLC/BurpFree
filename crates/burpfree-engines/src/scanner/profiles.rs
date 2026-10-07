//! Scan profiles — built-in configurations matching Burp Suite 2026.8's
//! `BuiltInConfigs/*.json` (29 profiles). Each profile defines which
//! passive detectors + active probes + crawl settings are enabled.
//!
//! Operators select a profile from the Scanner UI; the profile name
//! is persisted in `ProjectConfig::scan_profile`.

use serde::{Deserialize, Serialize};

/// A scan profile definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: ProfileCategory,
    /// Which passive detectors are enabled (empty = all).
    pub passive_detectors: Vec<&'static str>,
    /// Which active probe families are enabled (empty = all).
    pub active_probes: Vec<&'static str>,
    /// Crawl depth limit (0 = no crawl).
    pub crawl_depth: u32,
    /// Max requests per second (0 = unlimited).
    pub rate_limit: u32,
    /// Follow redirects during active scan.
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileCategory {
    Audit,
    Crawl,
    CrawlAndAudit,
    Passive,
    Custom,
}

impl ProfileCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Audit => "Audit",
            Self::Crawl => "Crawl",
            Self::CrawlAndAudit => "Crawl and Audit",
            Self::Passive => "Passive",
            Self::Custom => "Custom",
        }
    }
}

/// Return all 29 built-in scan profiles matching Burp's BuiltInConfigs.
pub fn builtin_profiles() -> Vec<ScanProfile> {
    vec![
        // --- Crawl and Audit ---
        ScanProfile {
            id: "crawl-audit-lightweight",
            name: "Crawl and Audit - Lightweight",
            description: "Fast crawl + lightweight audit. Good for quick recon.",
            category: ProfileCategory::CrawlAndAudit,
            passive_detectors: vec![],
            active_probes: vec!["xss-reflected", "sqli-error"],
            crawl_depth: 3,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "crawl-audit-fast",
            name: "Crawl and Audit - Fast",
            description: "Balanced speed and coverage. Default for most assessments.",
            category: ProfileCategory::CrawlAndAudit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 5,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "crawl-audit-balanced",
            name: "Crawl and Audit - Balanced",
            description: "Moderate crawl depth with full audit checks.",
            category: ProfileCategory::CrawlAndAudit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 8,
            rate_limit: 20,
            follow_redirects: true,
        },
        ScanProfile {
            id: "crawl-audit-thorough",
            name: "Crawl and Audit - Thorough",
            description: "Deep crawl with all audit checks. Slow but comprehensive.",
            category: ProfileCategory::CrawlAndAudit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 12,
            rate_limit: 10,
            follow_redirects: true,
        },
        // --- Audit only ---
        ScanProfile {
            id: "audit-coverage-thorough",
            name: "Audit coverage - thorough",
            description: "All passive + active checks with maximum insertion points.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 10,
            follow_redirects: true,
        },
        ScanProfile {
            id: "audit-coverage-maximum",
            name: "Audit coverage - maximum",
            description: "Maximum audit coverage including time-intensive checks.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 5,
            follow_redirects: true,
        },
        ScanProfile {
            id: "audit-checks-passive",
            name: "Audit checks - passive only",
            description: "Only passive checks. No active probes sent.",
            category: ProfileCategory::Passive,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: false,
        },
        ScanProfile {
            id: "audit-checks-bchecks-only",
            name: "Audit checks - BChecks only",
            description: "Only run BCheck rules. Ignores built-in detectors.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec!["bchecks"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "audit-checks-critical-high",
            name: "Audit checks - critical and high only",
            description: "Only checks that can produce critical or high severity findings.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec!["sqli-error", "sqli-blind", "xss-reflected", "xss-stored", "cmd-injection", "ssti", "xxe", "deserialization", "path-traversal"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "minimize-false-positives",
            name: "Minimize false positives",
            description: "Conservative checks that rarely produce false positives.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["security-headers", "insecure-cookies", "info-disclosure-headers"],
            active_probes: vec!["sqli-error", "xss-reflected"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "minimize-false-negatives",
            name: "Minimize false negatives",
            description: "Aggressive checks that maximize detection at the cost of noise.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 5,
            follow_redirects: true,
        },
        // --- CI/CD ---
        ScanProfile {
            id: "cicd-optimized",
            name: "CICD Optimized",
            description: "Fast scan optimized for CI/CD pipelines. Limited crawl, fast checks.",
            category: ProfileCategory::CrawlAndAudit,
            passive_detectors: vec![],
            active_probes: vec!["sqli-error", "xss-reflected", "cmd-injection", "path-traversal"],
            crawl_depth: 2,
            rate_limit: 50,
            follow_redirects: true,
        },
        ScanProfile {
            id: "cicd-lightweight",
            name: "CICD Lightweight",
            description: "Minimal scan for quick pipeline checks.",
            category: ProfileCategory::Passive,
            passive_detectors: vec!["security-headers", "insecure-cookies", "cors-permissive"],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: false,
        },
        // --- Crawl only ---
        ScanProfile {
            id: "crawl-fast",
            name: "Crawl - Fast",
            description: "Quick crawl for site mapping. No audit.",
            category: ProfileCategory::Crawl,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 3,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "crawl-normal",
            name: "Crawl - Normal",
            description: "Standard crawl depth for site mapping.",
            category: ProfileCategory::Crawl,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 8,
            rate_limit: 20,
            follow_redirects: true,
        },
        ScanProfile {
            id: "crawl-thorough",
            name: "Crawl - Thorough",
            description: "Deep crawl covering all discoverable content.",
            category: ProfileCategory::Crawl,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 15,
            rate_limit: 10,
            follow_redirects: true,
        },
        // --- Specialized ---
        ScanProfile {
            id: "api-scan",
            name: "API Scan",
            description: "Optimized for REST/GraphQL API testing.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["security-headers", "cors-permissive", "info-disclosure-headers"],
            active_probes: vec!["sqli-error", "sqli-blind", "cmd-injection", "xxe", "ssti", "nosqli"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "owasp-top-10",
            name: "OWASP Top 10",
            description: "Checks aligned with the OWASP Top 10 2021 categories.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 10,
            follow_redirects: true,
        },
        ScanProfile {
            id: "injection-only",
            name: "Injection vulnerabilities only",
            description: "Focus on injection-class vulnerabilities (SQLi, XSS, CMDi, SSTI, XXE).",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec!["sqli-error", "sqli-blind", "xss-reflected", "xss-stored", "cmd-injection", "ssti", "xxe", "ldap-injection", "xpath-injection", "nosqli", "el-injection"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "auth-checks",
            name: "Authentication and session checks",
            description: "Focus on authentication, session management, and access control.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["insecure-cookies", "csrf-token-missing"],
            active_probes: vec!["auth-bypass", "session-fixation", "privilege-escalation"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "header-analysis",
            name: "Security header analysis",
            description: "Passive-only check of HTTP security headers and cookies.",
            category: ProfileCategory::Passive,
            passive_detectors: vec!["security-headers", "insecure-cookies", "cors-permissive", "csp-weakness", "permissions-policy-weakness", "cache-control"],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: false,
        },
        ScanProfile {
            id: "javascript-analysis",
            name: "JavaScript analysis",
            description: "Focus on client-side JavaScript vulnerabilities.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["vulnerable-js-library", "inline-script-size", "mixed-content"],
            active_probes: vec!["xss-reflected", "xss-stored", "xss-dom"],
            crawl_depth: 3,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "deserialization-check",
            name: "Deserialization checks",
            description: "Focus on insecure deserialization vulnerabilities.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["insecure-deserialization-indicator"],
            active_probes: vec!["deserialization-java", "deserialization-php", "deserialization-python", "deserialization-dotnet"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "smuggling-check",
            name: "HTTP request smuggling",
            description: "Focus on HTTP request smuggling / desync attacks.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec!["smuggling-cl-te", "smuggling-te-cl", "smuggling-te-te", "smuggling-h2"],
            crawl_depth: 0,
            rate_limit: 2,
            follow_redirects: false,
        },
        ScanProfile {
            id: "ssrf-check",
            name: "SSRF checks",
            description: "Focus on server-side request forgery via OOB callbacks.",
            category: ProfileCategory::Audit,
            passive_detectors: vec![],
            active_probes: vec!["ssrf-oob", "ssrf-blind", "ssrf-header"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "cache-poisoning",
            name: "Web cache poisoning",
            description: "Focus on cache poisoning via Host header and unkeyed headers.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["host-header-reflection"],
            active_probes: vec!["cache-poison-host", "cache-poison-xfh", "cache-poison-unkeyed"],
            crawl_depth: 0,
            rate_limit: 5,
            follow_redirects: false,
        },
        ScanProfile {
            id: "cors-audit",
            name: "CORS misconfiguration audit",
            description: "Comprehensive CORS misconfiguration testing.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["cors-permissive"],
            active_probes: vec!["cors-reflected", "cors-null", "cors-subdomain", "cors-wildcard"],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: true,
        },
        ScanProfile {
            id: "compliance-pci",
            name: "PCI DSS compliance",
            description: "Checks aligned with PCI DSS requirements for web applications.",
            category: ProfileCategory::Audit,
            passive_detectors: vec!["security-headers", "insecure-cookies", "mixed-content", "info-disclosure-headers"],
            active_probes: vec!["sqli-error", "xss-reflected", "path-traversal"],
            crawl_depth: 3,
            rate_limit: 10,
            follow_redirects: true,
        },
        ScanProfile {
            id: "live-passive",
            name: "Live passive scan",
            description: "Continuous passive monitoring of proxied traffic.",
            category: ProfileCategory::Passive,
            passive_detectors: vec![],
            active_probes: vec![],
            crawl_depth: 0,
            rate_limit: 0,
            follow_redirects: false,
        },
    ]
}

/// Return profile names as a list for UI dropdowns.
pub fn profile_names() -> Vec<(&'static str, &'static str)> {
    builtin_profiles()
        .iter()
        .map(|p| (p.id, p.name))
        .collect()
}
