//! Postman Collection v2.1 importer.
//!
//! The format nests `item[]` arrays recursively. Each leaf has a
//! `request` object (either a string URL or a full object).

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::ImportedEndpoint;

pub fn parse(input: &str) -> Result<Vec<ImportedEndpoint>> {
    let v: Value = serde_json::from_str(input)
        .map_err(|e| anyhow!("postman: not valid JSON: {e}"))?;
    let items = v
        .get("item")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("postman: no `item[]` array (not a Postman collection?)"))?;
    let mut out = Vec::new();
    for item in items {
        walk(item, &mut out)?;
    }
    Ok(out)
}

fn walk(item: &Value, out: &mut Vec<ImportedEndpoint>) -> Result<()> {
    if let Some(children) = item.get("item").and_then(|v| v.as_array()) {
        for child in children {
            walk(child, out)?;
        }
    }
    let name = item.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
    if let Some(req) = item.get("request") {
        if let Some(ep) = parse_request(req, name)? {
            out.push(ep);
        }
    }
    Ok(())
}

fn parse_request(req: &Value, name: Option<String>) -> Result<Option<ImportedEndpoint>> {
    let (method, url, headers, body) = match req {
        Value::String(s) => ("GET".to_string(), substitute_vars(s), Vec::new(), None),
        Value::Object(_) => {
            let method = req
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_ascii_uppercase();
            let url = extract_url(req);
            if url.is_empty() {
                return Ok(None);
            }
            let headers = extract_headers(req);
            let body = extract_body(req);
            (method, url, headers, body)
        }
        _ => return Ok(None),
    };
    Ok(Some(ImportedEndpoint {
        method,
        url,
        headers,
        body,
        source: "postman".into(),
        name,
    }))
}

fn extract_url(req: &Value) -> String {
    let u = match req.get("url") {
        Some(u) => u,
        None => return String::new(),
    };
    if let Some(s) = u.as_str() {
        return substitute_vars(s);
    }
    // Object form: when the structured host/path/query is present we
    // prefer it (so disabled flags are honoured). Falling back to raw
    // only when the structured representation is absent.
    let has_structured = u.get("host").is_some() || u.get("path").is_some();
    if !has_structured {
        if let Some(raw) = u.get("raw").and_then(|v| v.as_str()) {
            return substitute_vars(raw);
        }
    }
    let protocol = u.get("protocol").and_then(|v| v.as_str()).unwrap_or("http");
    let host = u.get("host").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(".")
    });
    let path = u.get("path").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join("/")
    });
    let port = u.get("port").and_then(|v| v.as_str());
    let mut built = String::new();
    built.push_str(protocol);
    built.push_str("://");
    if let Some(h) = host {
        built.push_str(&h);
    }
    if let Some(p) = port {
        built.push(':');
        built.push_str(p);
    }
    if let Some(p) = path {
        if !p.starts_with('/') {
            built.push('/');
        }
        built.push_str(&p);
    }
    if let Some(query) = u.get("query").and_then(|v| v.as_array()) {
        let qs: Vec<String> = query
            .iter()
            .filter(|q| q.get("disabled").and_then(|v| v.as_bool()) != Some(true))
            .filter_map(|q| {
                let k = q.get("key").and_then(|v| v.as_str())?;
                let v = q.get("value").and_then(|v| v.as_str()).unwrap_or("");
                Some(format!("{k}={v}"))
            })
            .collect();
        if !qs.is_empty() {
            built.push('?');
            built.push_str(&qs.join("&"));
        }
    }
    substitute_vars(&built)
}

fn extract_headers(req: &Value) -> Vec<(String, String)> {
    let arr = match req.get("header").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter(|h| h.get("disabled").and_then(|v| v.as_bool()) != Some(true))
        .filter_map(|h| {
            let k = h.get("key").and_then(|v| v.as_str())?;
            let v = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

fn extract_body(req: &Value) -> Option<String> {
    let b = req.get("body")?;
    let mode = b.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    match mode {
        "raw" => b.get("raw").and_then(|v| v.as_str()).map(|s| s.to_string()),
        "urlencoded" => {
            let arr = b.get("urlencoded").and_then(|v| v.as_array())?;
            Some(
                arr.iter()
                    .filter(|p| p.get("disabled").and_then(|v| v.as_bool()) != Some(true))
                    .filter_map(|p| {
                        let k = p.get("key").and_then(|v| v.as_str())?;
                        let v = p.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        Some(format!("{k}={v}"))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            )
        }
        _ => None,
    }
}

fn substitute_vars(s: &str) -> String {
    // Postman uses `{{var}}` placeholders. Without an environment we
    // leave the placeholder names as-is but strip the braces so the URL
    // parses — if downstream wants smarter resolution, they can run the
    // full Postman environment through.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = s[i + 2..].find("}}") {
                let name = &s[i + 2..i + 2 + end];
                out.push_str(name);
                i += 2 + end + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_postman_v21_url_string_form() {
        let doc = r#"
        {
          "info": {"name":"t","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item": [
            {"name":"get-users","request":"https://api.example.com/users"}
          ]
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].method, "GET");
        assert_eq!(items[0].url, "https://api.example.com/users");
        assert_eq!(items[0].name.as_deref(), Some("get-users"));
    }

    #[test]
    fn imports_postman_v21_full_object() {
        let doc = r#"
        {
          "info": {"name":"t","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item": [
            {"name":"login","request":{
              "method":"POST",
              "header":[{"key":"Content-Type","value":"application/json"}],
              "body":{"mode":"raw","raw":"{\"user\":\"alice\"}"},
              "url":{"raw":"https://api.example.com/auth?remember=1","protocol":"https","host":["api","example","com"],"path":["auth"],"query":[{"key":"remember","value":"1"}]}
            }}
          ]
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].method, "POST");
        assert!(items[0].url.contains("https://api.example.com/auth"));
        assert!(items[0].url.contains("remember=1"));
        assert_eq!(items[0].headers[0].0, "Content-Type");
        assert!(items[0].body.as_ref().unwrap().contains("alice"));
    }

    #[test]
    fn walks_nested_items() {
        let doc = r#"
        {
          "info":{"name":"t","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item":[
            {"name":"users-folder","item":[
              {"name":"list","request":"https://api.example.com/users"},
              {"name":"create","request":{"method":"POST","url":"https://api.example.com/users"}}
            ]}
          ]
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items.iter().filter(|e| e.method == "POST").count(), 1);
    }

    #[test]
    fn disabled_headers_and_query_params_skipped() {
        let doc = r#"
        {
          "info":{"name":"t","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item":[
            {"name":"n","request":{
              "method":"GET",
              "header":[{"key":"X-Keep","value":"yes"},{"key":"X-Skip","value":"no","disabled":true}],
              "url":{"raw":"https://a/b","protocol":"https","host":["a"],"path":["b"],
                     "query":[{"key":"a","value":"1"},{"key":"b","value":"2","disabled":true}]}
            }}
          ]
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items[0].headers.len(), 1);
        assert!(items[0].url.contains("a=1"));
        assert!(!items[0].url.contains("b=2"));
    }

    #[test]
    fn vars_in_curly_braces_are_kept_without_braces() {
        let doc = r#"
        {
          "info":{"name":"t","schema":"v2.1"},
          "item":[{"name":"n","request":"{{baseUrl}}/health"}]
        }"#;
        let items = parse(doc).unwrap();
        assert_eq!(items[0].url, "baseUrl/health");
    }
}
