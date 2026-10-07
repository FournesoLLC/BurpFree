//! Bambda expression library — pre-built filter expressions matching
//! Burp Suite 2026.8's Bambda library feature (released in 2025.2).
//!
//! Each entry is a named, documented Rhai expression that operators
//! can load into the History/Logger filter bar with one click.

use serde::{Deserialize, Serialize};

/// A saved Bambda expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BambdaPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub expression: &'static str,
}

/// Return all built-in Bambda presets.
pub fn builtin_presets() -> &'static [BambdaPreset] {
    PRESETS
}

static PRESETS: &[BambdaPreset] = &[
    // --- Filtering ---
    BambdaPreset {
        id: "in-scope-only",
        name: "In-scope requests only",
        description: "Show only requests matching the current scope rules.",
        category: "Scope",
        expression: "in_scope",
    },
    BambdaPreset {
        id: "out-of-scope",
        name: "Out-of-scope requests",
        description: "Show requests that do NOT match scope rules.",
        category: "Scope",
        expression: "!in_scope",
    },
    BambdaPreset {
        id: "errors-only",
        name: "5xx server errors",
        description: "Show only responses with 500+ status codes.",
        category: "Status",
        expression: "status >= 500",
    },
    BambdaPreset {
        id: "client-errors",
        name: "4xx client errors",
        description: "Show only 400-499 responses.",
        category: "Status",
        expression: "status >= 400 && status < 500",
    },
    BambdaPreset {
        id: "redirects",
        name: "3xx redirects",
        description: "Show redirect responses.",
        category: "Status",
        expression: "status >= 300 && status < 400",
    },
    BambdaPreset {
        id: "success-only",
        name: "2xx success only",
        description: "Show only successful responses.",
        category: "Status",
        expression: "status >= 200 && status < 300",
    },
    BambdaPreset {
        id: "post-requests",
        name: "POST requests only",
        description: "Filter to POST method requests.",
        category: "Method",
        expression: "method == \"POST\"",
    },
    BambdaPreset {
        id: "json-responses",
        name: "JSON responses",
        description: "Show only responses with JSON content type.",
        category: "Content",
        expression: "content_type.contains(\"json\")",
    },
    BambdaPreset {
        id: "html-responses",
        name: "HTML responses",
        description: "Show only HTML responses.",
        category: "Content",
        expression: "content_type.contains(\"html\")",
    },
    BambdaPreset {
        id: "large-responses",
        name: "Large responses (>100KB)",
        description: "Show responses larger than 100KB.",
        category: "Size",
        expression: "content_length > 102400",
    },
    BambdaPreset {
        id: "slow-responses",
        name: "Slow responses (>2s)",
        description: "Show responses that took longer than 2 seconds.",
        category: "Performance",
        expression: "elapsed_ms > 2000",
    },
    BambdaPreset {
        id: "very-slow",
        name: "Very slow responses (>5s)",
        description: "Show responses taking more than 5 seconds.",
        category: "Performance",
        expression: "elapsed_ms > 5000",
    },
    BambdaPreset {
        id: "has-params",
        name: "Requests with parameters",
        description: "Show only requests that have query or body parameters.",
        category: "Parameters",
        expression: "param_count > 0",
    },
    BambdaPreset {
        id: "api-endpoints",
        name: "API endpoints",
        description: "Show requests to common API paths.",
        category: "Path",
        expression: "path.contains(\"/api/\") || path.contains(\"/graphql\") || path.contains(\"/rest/\")",
    },
    BambdaPreset {
        id: "auth-endpoints",
        name: "Authentication endpoints",
        description: "Show requests to login/auth/token endpoints.",
        category: "Path",
        expression: "path.contains(\"/login\") || path.contains(\"/auth\") || path.contains(\"/token\") || path.contains(\"/oauth\")",
    },
    BambdaPreset {
        id: "file-uploads",
        name: "File upload requests",
        description: "Show requests with multipart content type.",
        category: "Content",
        expression: "method == \"POST\" && content_type.contains(\"multipart\")",
    },
    BambdaPreset {
        id: "specific-host",
        name: "Specific host pattern",
        description: "Filter to a specific host (edit the host value).",
        category: "Host",
        expression: "host.contains(\"example.com\")",
    },
    BambdaPreset {
        id: "exclude-static",
        name: "Exclude static assets",
        description: "Hide CSS, JS, images, fonts from the view.",
        category: "Content",
        expression: "!content_type.contains(\"css\") && !content_type.contains(\"javascript\") && !content_type.contains(\"image\") && !content_type.contains(\"font\")",
    },
    BambdaPreset {
        id: "tls-only",
        name: "HTTPS only",
        description: "Show only TLS-encrypted requests.",
        category: "Scheme",
        expression: "scheme == \"https\"",
    },
    BambdaPreset {
        id: "http-cleartext",
        name: "HTTP cleartext only",
        description: "Show only unencrypted HTTP requests.",
        category: "Scheme",
        expression: "scheme == \"http\"",
    },
];
