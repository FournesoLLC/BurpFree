//! Minimal OpenAPI 3.x importer.
//!
//! We don't try to be a validating OpenAPI parser; we extract the data
//! the active/passive scanner needs:
//!
//! * `servers[0].url` → base
//! * each `paths./foo./get.parameters[]` with `in: query` → query example
//! * each `paths./foo./get.parameters[]` with `in: header` → header example
//! * `requestBody.content."application/json".schema` → placeholder JSON
//! * `operationId` → endpoint name
//!
//! JSON and YAML are both accepted (we try JSON first; on failure we
//! parse as YAML).

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::ImportedEndpoint;

/// Parse an OpenAPI document (JSON or YAML).
pub fn parse(input: &str) -> Result<Vec<ImportedEndpoint>> {
    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => serde_yml::from_str(input)
            .map_err(|e| anyhow!("not valid JSON or YAML: {e}"))?,
    };
    parse_value(&v)
}

fn parse_value(v: &Value) -> Result<Vec<ImportedEndpoint>> {
    let paths = v
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or_else(|| anyhow!("OpenAPI: missing `paths` object"))?;
    let base = base_url(v);
    let mut out = Vec::new();
    for (path_str, path_item) in paths {
        let obj = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };
        for (method, op) in obj {
            if !is_http_method(method) {
                continue;
            }
            let op_obj = match op.as_object() {
                Some(o) => o,
                None => continue,
            };
            let endpoint = build_endpoint(path_str, method, op_obj, &base)?;
            out.push(endpoint);
        }
    }
    Ok(out)
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" | "trace"
    )
}

fn base_url(v: &Value) -> String {
    let s = v
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("url"))
        .and_then(|u| u.as_str())
        .unwrap_or("http://localhost");
    // Substitute `{var}` with defaults if an OpenAPI `servers[0].variables` map exists.
    let vars = v
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("variables"))
        .and_then(|m| m.as_object())
        .cloned();
    let mut url = s.to_string();
    if let Some(vars) = vars {
        for (name, def) in vars {
            let default = def
                .get("default")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default();
            url = url.replace(&format!("{{{name}}}"), &default);
        }
    }
    url
}

fn build_endpoint(
    path: &str,
    method: &str,
    op: &serde_json::Map<String, Value>,
    base: &str,
) -> Result<ImportedEndpoint> {
    let name = op
        .get("operationId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Substitute path parameters with example / default or placeholder.
    let mut full_path = path.to_string();
    let mut query_pairs: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();

    if let Some(params) = op.get("parameters").and_then(|p| p.as_array()) {
        for p in params {
            let name = match p.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let in_ = p.get("in").and_then(|v| v.as_str()).unwrap_or("");
            let example = p
                .get("example")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    p.get("schema")
                        .and_then(|s| s.get("default"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .or_else(|| {
                    p.get("schema")
                        .and_then(|s| s.get("example"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| default_for_param(p));
            match in_ {
                "path" => {
                    full_path =
                        full_path.replace(&format!("{{{name}}}"), &example);
                }
                "query" => {
                    query_pairs.push((name.to_string(), example));
                }
                "header" => {
                    headers.push((name.to_string(), example));
                }
                _ => {}
            }
        }
    }

    // Build URL.
    let mut url = format!("{}{}", base.trim_end_matches('/'), full_path);
    if !query_pairs.is_empty() {
        let qs = query_pairs
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    percent(k.as_bytes()),
                    percent(v.as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        url.push('?');
        url.push_str(&qs);
    }

    // Request body.
    let body = op
        .get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.as_object())
        .and_then(|m| {
            m.get("application/json")
                .or_else(|| m.get("application/x-www-form-urlencoded"))
                .or_else(|| m.get("text/plain"))
                .map(|v| (v, "application/json"))
        });
    let body_str = if let Some((media, _mime)) = body {
        let schema = media.get("schema").cloned().unwrap_or(Value::Null);
        headers.push(("Content-Type".into(), "application/json".into()));
        Some(serde_json::to_string_pretty(&example_from_schema(&schema))?)
    } else {
        None
    };

    Ok(ImportedEndpoint {
        method: method.to_ascii_uppercase(),
        url,
        headers,
        body: body_str,
        source: "openapi".into(),
        name,
    })
}

fn default_for_param(p: &Value) -> String {
    let schema = p.get("schema");
    let ty = schema
        .and_then(|s| s.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("string");
    match ty {
        "integer" | "number" => "1".to_string(),
        "boolean" => "true".to_string(),
        _ => "x".to_string(),
    }
}

/// Build a plausible example payload from a JSON Schema fragment.
fn example_from_schema(schema: &Value) -> Value {
    if schema.is_null() {
        return Value::Object(serde_json::Map::new());
    }
    if let Some(ex) = schema.get("example") {
        return ex.clone();
    }
    let ty = schema.get("type").and_then(|v| v.as_str()).unwrap_or("object");
    match ty {
        "object" => {
            let mut map = serde_json::Map::new();
            if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
                for (k, child) in props {
                    map.insert(k.clone(), example_from_schema(child));
                }
            }
            Value::Object(map)
        }
        "array" => {
            let items = schema.get("items").cloned().unwrap_or(Value::Null);
            Value::Array(vec![example_from_schema(&items)])
        }
        "integer" | "number" => Value::Number(1.into()),
        "boolean" => Value::Bool(true),
        "string" => {
            if let Some(enum_vals) = schema.get("enum").and_then(|v| v.as_array()) {
                enum_vals.first().cloned().unwrap_or_else(|| Value::String("x".into()))
            } else {
                Value::String("x".into())
            }
        }
        _ => Value::String("x".into()),
    }
}

fn percent(bytes: &[u8]) -> String {
    // Minimal percent-encoder for query values. Keep the alphabet
    // small so the output is readable.
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_openapi_json() {
        let doc = r#"
        {
          "openapi": "3.0.0",
          "info": {"title": "test", "version": "1.0.0"},
          "servers": [{"url": "https://api.example.com/v1"}],
          "paths": {
            "/users/{id}": {
              "get": {
                "operationId": "getUser",
                "parameters": [
                  {"name": "id", "in": "path", "schema": {"type": "integer"}},
                  {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
                ]
              },
              "post": {
                "operationId": "createUser",
                "requestBody": {
                  "content": {
                    "application/json": {
                      "schema": {
                        "type": "object",
                        "properties": {
                          "name": {"type": "string"},
                          "age": {"type": "integer"}
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        "#;
        let items = parse(doc).unwrap();
        assert_eq!(items.len(), 2);
        let get = items.iter().find(|e| e.method == "GET").unwrap();
        assert!(get.url.contains("https://api.example.com/v1/users/1"));
        assert!(get.url.contains("verbose=true"));
        let post = items.iter().find(|e| e.method == "POST").unwrap();
        assert!(post.body.as_ref().unwrap().contains("\"name\""));
        assert!(post.headers.iter().any(|(k, v)| k == "Content-Type" && v.contains("json")));
    }

    #[test]
    fn imports_openapi_yaml() {
        let doc = r#"
openapi: 3.0.0
info:
  title: hello
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /health:
    get:
      operationId: health
"#;
        let items = parse(doc).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].url, "https://api.example.com/health");
    }

    #[test]
    fn servers_variables_substituted() {
        let doc = r#"
        {
          "openapi": "3.0.0",
          "info": {"title":"t","version":"1"},
          "servers": [{
            "url": "https://{host}.example.com",
            "variables": {"host": {"default": "api"}}
          }],
          "paths": {"/ping": {"get": {}}}
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items[0].url, "https://api.example.com/ping");
    }
}
