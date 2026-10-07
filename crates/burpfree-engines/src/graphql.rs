//! GraphQL detection, operation parsing, and introspection.
//!
//! GraphQL endpoints are a security-relevant surface Burp practitioners
//! reach for often. This module gives the UI three primitives:
//!
//! 1. [`looks_like_graphql`] — passive detection against a stored
//!    transaction (URL path hints + body shape + content-type).
//! 2. [`parse_operations`] — enumerate every operation (`query` /
//!    `mutation` / `subscription`) carried by a request body, with
//!    name + raw text so the UI can list them.
//! 3. [`introspection_query`] + [`run_introspection`] — fire the
//!    canonical introspection POST and return the raw JSON for the
//!    frontend to render as a schema tree.

use anyhow::{Context, Result};
use burpfree_core::traffic::{HttpVersion, Request, Response, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{HttpClient, HttpClientConfig};

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Heuristic: does this transaction look like it talks GraphQL?
///
/// Signals (any one is enough):
/// * URL path contains `/graphql` / `/gql` / `/graphiql` / `/v1/graphql`
/// * Request body is JSON with a top-level `query` string field
/// * Request `Content-Type` is `application/graphql`
/// * Response body is JSON containing a top-level `data` and / or
///   `errors` object (classic GraphQL shape) together with any of the
///   above hints.
pub fn looks_like_graphql(tx: &Transaction) -> bool {
    let path_lc = tx.request.path_only().to_ascii_lowercase();
    let path_hit = ["/graphql", "/gql", "/graphiql", "/v1/graphql", "/api/graphql"]
        .iter()
        .any(|p| path_lc.contains(p));

    let ct = tx
        .request
        .headers
        .content_type()
        .unwrap_or("")
        .to_ascii_lowercase();
    let ct_hit = ct.contains("application/graphql");

    let body_hit = tx
        .request
        .headers
        .content_type()
        .map(|c| c.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false)
        && body_mentions_query(&tx.request.body);

    path_hit || ct_hit || body_hit
}

fn body_mentions_query(body: &[u8]) -> bool {
    if body.len() < 2 || body.len() > 1 << 20 {
        return false;
    }
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Full JSON parse is more reliable than regex but still cheap.
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) {
        if map.get("query").and_then(|v| v.as_str()).is_some() {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Operation parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Query,
    Mutation,
    Subscription,
    Anonymous,
}

impl OperationKind {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
            Self::Anonymous => "anonymous",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub kind: OperationKind,
    /// Operation name, if the author declared one.
    pub name: Option<String>,
    /// Raw operation text as it would appear in the GQL document.
    pub text: String,
    /// Byte offset of this operation within the request body (for the
    /// UI to deep-link into the editor pane).
    pub offset: usize,
}

/// Extract every operation declaration from a GraphQL request body.
///
/// Accepts two body shapes:
///  * Plain `application/graphql` (whole body is the GraphQL document).
///  * `application/json` with `{ "query": "...", "operationName": "...", ... }`.
///
/// Returns an empty vector when the body does not look like GraphQL.
/// The parser is intentionally simple: it scans for the `query`,
/// `mutation`, and `subscription` keywords at top level of a document
/// and reads up to the matching closing brace. It does not validate
/// the schema or type-check anything.
pub fn parse_operations(body: &[u8]) -> Vec<Operation> {
    let text = extract_graphql_document(body).unwrap_or_default();
    parse_document(&text)
}

fn extract_graphql_document(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    // JSON envelope → read .query.
    if s.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            if let Some(q) = v.get("query").and_then(|v| v.as_str()) {
                return Some(q.to_string());
            }
        }
    }
    // Otherwise treat the whole body as a GQL document.
    Some(s.to_string())
}

fn parse_document(doc: &str) -> Vec<Operation> {
    let mut out = Vec::new();
    let bytes = doc.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Skip whitespace and comments.
        i = skip_whitespace(bytes, i);
        if i >= bytes.len() {
            break;
        }
        // Shorthand query (just a `{ ... }` block) counts as anonymous.
        if bytes[i] == b'{' {
            if let Some(end) = find_matching_brace(bytes, i) {
                out.push(Operation {
                    kind: OperationKind::Anonymous,
                    name: None,
                    text: doc[i..=end].to_string(),
                    offset: i,
                });
                i = end + 1;
                continue;
            } else {
                break;
            }
        }
        // Read an identifier (the keyword).
        let kw_start = i;
        while i < bytes.len() && is_ident_byte(bytes[i]) {
            i += 1;
        }
        if i == kw_start {
            i += 1;
            continue;
        }
        let kw = &doc[kw_start..i];
        let kind = match kw {
            "query" => OperationKind::Query,
            "mutation" => OperationKind::Mutation,
            "subscription" => OperationKind::Subscription,
            _ => continue,
        };
        // Optional name.
        let name_start = skip_whitespace(bytes, i);
        let mut name_end = name_start;
        while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
            name_end += 1;
        }
        let name = if name_end > name_start {
            Some(doc[name_start..name_end].to_string())
        } else {
            None
        };
        // Skip variables / directives up to the opening brace.
        let brace = {
            let mut j = name_end;
            while j < bytes.len() && bytes[j] != b'{' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            j
        };
        if let Some(end) = find_matching_brace(bytes, brace) {
            out.push(Operation {
                kind,
                name,
                text: doc[kw_start..=end].to_string(),
                offset: kw_start,
            });
            i = end + 1;
        } else {
            break;
        }
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_whitespace(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => i += 1,
            b'#' => {
                // Comment to end of line.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            _ => break,
        }
    }
    i
}

/// Return the index of the matching `}` for the `{` at `open`. Honours
/// nesting and string literals (GraphQL strings use `"..."` or
/// `"""..."""` block strings).
fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(open), Some(&b'{'));
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'"' => {
                // Skip past string literal.
                let block = bytes.len() >= i + 3
                    && bytes[i + 1] == b'"'
                    && bytes[i + 2] == b'"';
                if block {
                    i += 3;
                    while i + 2 < bytes.len()
                        && !(bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
                    {
                        i += 1;
                    }
                    i += 2; // land on last `"`, outer loop +1 moves past.
                } else {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

/// Canonical GraphQL introspection query (abbreviated form that works
/// against every spec-conformant server).
pub fn introspection_query() -> &'static str {
    r#"query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { ...TypeRef }
        defaultValue
      }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { ...TypeRef }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type { ...TypeRef }
        defaultValue
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType { kind name }
    }
  }
}
"#
}

/// POST the introspection query to `url` with the supplied headers.
/// Returns the raw response for the UI to parse / display.
pub async fn run_introspection(
    url: &str,
    extra_headers: &[(String, String)],
    http: HttpClientConfig,
) -> Result<Response> {
    let mut req = Request::new("POST", url).with_context(|| format!("parse url {url}"))?;
    req.http_version = HttpVersion::Http11;
    req.headers
        .set_if_missing("Content-Type", "application/json");
    req.headers.set_if_missing("Accept", "application/json");
    for (k, v) in extra_headers {
        req.headers.set(k, v.clone());
    }
    let body = serde_json::json!({ "query": introspection_query(), "operationName": "IntrospectionQuery" });
    let serialized = serde_json::to_vec(&body)?;
    req.body = serialized;
    req.headers
        .set("Content-Length", req.body.len().to_string());
    let client = HttpClient::new(http);
    client.send(&req).await
}

// ---------------------------------------------------------------------------
// Schema shape (lightweight — just what the UI tree renders)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaView {
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
    pub types: Vec<SchemaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaType {
    pub kind: String,
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<SchemaField>,
    pub enum_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    pub type_label: String,
    pub args: Vec<SchemaArg>,
    pub description: Option<String>,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaArg {
    pub name: String,
    pub type_label: String,
    pub default_value: Option<String>,
}

/// Flatten an introspection response into the compact structure the
/// frontend tree uses. Accepts either the raw `__schema` object or a
/// wrapping `{ "data": { "__schema": … } }` envelope.
pub fn parse_schema(json: &Value) -> SchemaView {
    let root = json
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| json.get("__schema"))
        .cloned()
        .unwrap_or(Value::Null);
    let query_type = type_name(&root, "queryType");
    let mutation_type = type_name(&root, "mutationType");
    let subscription_type = type_name(&root, "subscriptionType");
    let types = root
        .get("types")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut mapped = Vec::with_capacity(types.len());
    for t in types {
        // Skip the introspection-internal types for a cleaner UI.
        let name = t
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.starts_with("__") {
            continue;
        }
        mapped.push(SchemaType {
            kind: t
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string(),
            name,
            description: t
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            fields: t
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().map(parse_field).collect())
                .unwrap_or_default(),
            enum_values: t
                .get("enumValues")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.get("name").and_then(|v| v.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    SchemaView {
        query_type,
        mutation_type,
        subscription_type,
        types: mapped,
    }
}

fn type_name(root: &Value, key: &str) -> Option<String> {
    root.get(key)
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn parse_field(v: &Value) -> SchemaField {
    SchemaField {
        name: v
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        type_label: render_type(v.get("type")),
        args: v
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|a| SchemaArg {
                        name: a
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        type_label: render_type(a.get("type")),
                        default_value: a
                            .get("defaultValue")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        description: v
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from),
        deprecated: v
            .get("isDeprecated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    }
}

fn render_type(t: Option<&Value>) -> String {
    let Some(t) = t else { return "Unknown".into() };
    let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let name = t.get("name").and_then(|v| v.as_str());
    match kind {
        "NON_NULL" => format!("{}!", render_type(t.get("ofType"))),
        "LIST" => format!("[{}]", render_type(t.get("ofType"))),
        _ => name.unwrap_or("Unknown").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpfree_core::headers::Headers;
    use burpfree_core::ids::TrafficId;
    use burpfree_core::traffic::{HttpVersion, Request, RequestSource, Transaction};

    fn make_tx(method: &str, url: &str, ct: Option<&str>, body: &[u8]) -> Transaction {
        let mut r = Request::new(method, url).unwrap();
        if let Some(c) = ct {
            r.headers.set("Content-Type", c);
        }
        r.body = body.to_vec();
        Transaction::new(r)
    }

    #[test]
    fn detects_endpoint_by_path() {
        let tx = make_tx("POST", "https://api.example.com/graphql", None, b"");
        assert!(looks_like_graphql(&tx));
    }

    #[test]
    fn detects_endpoint_by_body_shape() {
        let tx = make_tx(
            "POST",
            "https://api.example.com/data",
            Some("application/json"),
            br#"{"query":"{ users { id } }"}"#,
        );
        assert!(looks_like_graphql(&tx));
    }

    #[test]
    fn ignores_plain_json() {
        let tx = make_tx(
            "POST",
            "https://api.example.com/data",
            Some("application/json"),
            br#"{"name":"alice"}"#,
        );
        assert!(!looks_like_graphql(&tx));
    }

    #[test]
    fn parses_named_query() {
        let body = br#"{"query":"query GetUsers($limit: Int) { users(limit: $limit) { id name } }"}"#;
        let ops = parse_operations(body);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, OperationKind::Query);
        assert_eq!(ops[0].name.as_deref(), Some("GetUsers"));
        assert!(ops[0].text.contains("users(limit: $limit)"));
    }

    #[test]
    fn parses_mutation() {
        let body = br#"{"query":"mutation M { createUser(name: \"alice\") { id } }"}"#;
        let ops = parse_operations(body);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, OperationKind::Mutation);
        assert_eq!(ops[0].name.as_deref(), Some("M"));
    }

    #[test]
    fn parses_multiple_operations() {
        let doc = "query A { a } mutation B { b { c } }";
        let ops = parse_document(doc);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].kind, OperationKind::Query);
        assert_eq!(ops[0].name.as_deref(), Some("A"));
        assert_eq!(ops[1].kind, OperationKind::Mutation);
        assert_eq!(ops[1].name.as_deref(), Some("B"));
    }

    #[test]
    fn parses_anonymous_shorthand() {
        let doc = "{ me { id name } }";
        let ops = parse_document(doc);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, OperationKind::Anonymous);
        assert!(ops[0].name.is_none());
    }

    #[test]
    fn braces_inside_strings_do_not_break_matching() {
        let doc = r#"query X { field(input: "{not-a-brace}") { id } }"#;
        let ops = parse_document(doc);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].name.as_deref(), Some("X"));
    }

    #[test]
    fn parse_schema_handles_data_envelope() {
        let json = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "description": "A user",
                            "fields": [
                                {
                                    "name": "id",
                                    "description": null,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": { "kind": "SCALAR", "name": "ID" }
                                    },
                                    "args": [],
                                    "isDeprecated": false
                                },
                                {
                                    "name": "friends",
                                    "description": null,
                                    "type": {
                                        "kind": "LIST",
                                        "name": null,
                                        "ofType": {
                                            "kind": "NON_NULL",
                                            "name": null,
                                            "ofType": { "kind": "OBJECT", "name": "User" }
                                        }
                                    },
                                    "args": [
                                        {
                                            "name": "limit",
                                            "defaultValue": "10",
                                            "type": { "kind": "SCALAR", "name": "Int" }
                                        }
                                    ],
                                    "isDeprecated": false
                                }
                            ],
                            "enumValues": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "__Schema",
                            "fields": []
                        }
                    ]
                }
            }
        });
        let v = parse_schema(&json);
        assert_eq!(v.query_type.as_deref(), Some("Query"));
        assert_eq!(v.types.len(), 1, "introspection internal types are stripped");
        let user = &v.types[0];
        assert_eq!(user.name, "User");
        assert_eq!(user.fields.len(), 2);
        assert_eq!(user.fields[0].type_label, "ID!");
        assert_eq!(user.fields[1].type_label, "[User!]");
        assert_eq!(user.fields[1].args[0].name, "limit");
        assert_eq!(user.fields[1].args[0].default_value.as_deref(), Some("10"));
    }

    #[test]
    fn tx_with_pseudo_headers_still_recognised() {
        let mut r = Request {
            id: TrafficId::new(),
            method: "POST".into(),
            scheme: "https".into(),
            host: "api.example".into(),
            port: 443,
            path: "/graphql".into(),
            http_version: HttpVersion::Http11,
            headers: Headers::new(),
            body: b"{}".to_vec(),
            created_at_ms: 0,
            source: RequestSource::Manual,
            parent_id: None,
            annotation: String::new(),
            comment: String::new(),
        };
        r.headers.set("Content-Type", "application/graphql");
        assert!(looks_like_graphql(&Transaction::new(r)));
    }
}
