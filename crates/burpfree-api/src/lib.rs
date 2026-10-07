//! API definition importers.
//!
//! Turn an OpenAPI (JSON or YAML) or Postman Collection (v2.1 JSON)
//! document into a list of [`burpfree_core::Request`] objects that can
//! be stored in HTTP history, pushed to the site map, or sent to the
//! active scanner.
//!
//! The intent is to seed the attack surface before any manual
//! browsing. Users who have an OpenAPI spec or a Postman export can go
//! directly from "I have the spec" to "run passive + active scanner
//! against every documented endpoint".

pub mod openapi;
pub mod postman;

use burpfree_core::traffic::Request;
use serde::{Deserialize, Serialize};

/// Result of importing one endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedEndpoint {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// Source of the endpoint, for annotation (`openapi` or `postman`).
    pub source: String,
    /// Human-readable name (operationId, Postman item name, …).
    pub name: Option<String>,
}

impl ImportedEndpoint {
    pub fn to_request(&self) -> anyhow::Result<Request> {
        let mut req = Request::new(&self.method, &self.url)?;
        for (name, value) in &self.headers {
            req.headers.set(name.clone(), value.clone());
        }
        if let Some(body) = &self.body {
            req.set_text(body);
        }
        if let Some(n) = &self.name {
            req.annotation = n.clone();
        }
        Ok(req)
    }
}

/// Format auto-detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    OpenApi,
    Postman,
}

/// Try both formats; prefer whichever actually parses as a known shape.
pub fn import_auto(input: &str) -> anyhow::Result<(ImportFormat, Vec<ImportedEndpoint>)> {
    if let Ok(items) = postman::parse(input) {
        if !items.is_empty() {
            return Ok((ImportFormat::Postman, items));
        }
    }
    let items = openapi::parse(input)?;
    Ok((ImportFormat::OpenApi, items))
}
