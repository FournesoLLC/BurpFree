//! Example extension: inject an `X-Audit-Session` request header
//! with a per-session random token.
//!
//! Register with the host via:
//!
//! ```ignore
//! use burpfree_extensions::ExtensionRegistry;
//! let reg = ExtensionRegistry::new();
//! reg.register(std::sync::Arc::new(HeaderInjector::new("eng-review-2026")), "my-project")?;
//! ```

use async_trait::async_trait;
use burpfree_core::traffic::{Request, Response};
use burpfree_extensions::{Extension, Manifest, Permission, PluginContext};

pub struct HeaderInjector {
    label: String,
}

impl HeaderInjector {
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into() }
    }
}

#[async_trait]
impl Extension for HeaderInjector {
    fn manifest(&self) -> Manifest {
        Manifest {
            name: "header-injector".into(),
            version: "0.1.0".into(),
            author: "BurpFree contributors".into(),
            description: "Injects an X-Audit-Session header on outbound requests".into(),
            permissions: vec![Permission::ModifyTraffic],
        }
    }

    async fn on_request(&self, _ctx: &PluginContext, req: &mut Request) -> anyhow::Result<()> {
        req.headers.set("X-Audit-Session", &self.label);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn injects_header() {
        let reg = burpfree_extensions::ExtensionRegistry::new();
        reg.register(std::sync::Arc::new(HeaderInjector::new("test-1")), "proj")
            .unwrap();
        let mut r = Request::new("GET", "http://example.com/").unwrap();
        reg.on_request(&mut r).await;
        assert_eq!(r.headers.get("X-Audit-Session"), Some("test-1"));
    }
}
