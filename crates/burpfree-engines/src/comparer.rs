//! Comparer: text diffing used by the UI's Comparer panel.
//!
//! Patience-style LCS diff. For long inputs the output is capped to a
//! configurable number of lines; UI can request fine-grained diff of a
//! specific window.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffOp {
    Equal,
    Insert,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    pub op: DiffOp,
    pub left_line: Option<usize>,
    pub right_line: Option<usize>,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub lines: Vec<DiffLine>,
    pub similarity: f32, // 0..1
    pub left_total: usize,
    pub right_total: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompareMode {
    /// Classic line-granularity diff.
    #[default]
    Line,
    /// Split both inputs by whitespace and diff token-by-token; the
    /// `text` of each DiffLine is a single word. Useful for spotting
    /// small reordering / mutation in otherwise similar responses.
    Word,
}

pub fn compare_text(a: &str, b: &str) -> DiffReport {
    compare_full(a, b, false, CompareMode::Line)
}

// ---------------------------------------------------------------------------
// Structural JSON diff
// ---------------------------------------------------------------------------

/// Kind of change at one JSONPath location. `Same` is recorded so the
/// operator sees the whole tree, not just the deltas — Burp's text diff
/// has the same semantics (equal rows are rendered dimmed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonDiffKind {
    Added,
    Removed,
    Changed,
    Same,
}

/// One row in the structural diff table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDiffEntry {
    /// JSONPath-ish selector: `$.user.name`, `$.items[0].id`.
    pub path: String,
    pub kind: JsonDiffKind,
    pub left: Option<serde_json::Value>,
    pub right: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDiffReport {
    pub entries: Vec<JsonDiffEntry>,
    pub similarity: f32,
    pub left_total: usize,
    pub right_total: usize,
    /// `Some(msg)` when the left side failed to parse as JSON. On any
    /// parse error `entries` is empty so the UI can show a dedicated
    /// error banner instead of a half-filled table.
    pub parse_error_left: Option<String>,
    pub parse_error_right: Option<String>,
    /// True when the walk hit the entry cap and short-circuited. The
    /// final `Added` entry's path marks the cut-off point.
    #[serde(default)]
    pub truncated: bool,
}

/// Entry-count ceiling — guards the UI from pathologically large
/// payloads (10k-entry user objects etc.) that would freeze the diff
/// table render.
const JSON_DIFF_ENTRY_CAP: usize = 5000;

/// Structural JSON diff. Parses both inputs, walks them recursively,
/// returns a flat ordered list of `JsonDiffEntry`. Objects iterate
/// the sorted union of keys so output order is deterministic; arrays
/// use positional alignment (index 0 to max(len)).
pub fn compare_json(a: &str, b: &str) -> JsonDiffReport {
    let left: Result<serde_json::Value, _> = serde_json::from_str(a);
    let right: Result<serde_json::Value, _> = serde_json::from_str(b);
    let left_err = left.as_ref().err().map(|e| e.to_string());
    let right_err = right.as_ref().err().map(|e| e.to_string());
    if left_err.is_some() || right_err.is_some() {
        return JsonDiffReport {
            entries: Vec::new(),
            similarity: 0.0,
            left_total: 0,
            right_total: 0,
            parse_error_left: left_err,
            parse_error_right: right_err,
            truncated: false,
        };
    }
    let lv = left.unwrap();
    let rv = right.unwrap();
    let mut entries = Vec::new();
    let mut truncated = false;
    walk_json("$", Some(&lv), Some(&rv), &mut entries, &mut truncated);
    let total = entries.len().max(1);
    let same = entries
        .iter()
        .filter(|e| e.kind == JsonDiffKind::Same)
        .count();
    JsonDiffReport {
        entries,
        similarity: same as f32 / total as f32,
        left_total: count_leaves(&lv),
        right_total: count_leaves(&rv),
        parse_error_left: None,
        parse_error_right: None,
        truncated,
    }
}

/// Depth-first recursive walk. Each node emits exactly one entry
/// — if both sides are objects or arrays, the parent emits a `Same`
/// for the container (so operators can collapse by path) and then
/// recurses into children.
fn walk_json(
    path: &str,
    left: Option<&serde_json::Value>,
    right: Option<&serde_json::Value>,
    out: &mut Vec<JsonDiffEntry>,
    truncated: &mut bool,
) {
    use serde_json::Value;
    if *truncated || out.len() >= JSON_DIFF_ENTRY_CAP {
        if !*truncated {
            out.push(JsonDiffEntry {
                path: format!("{path}... (truncated)"),
                kind: JsonDiffKind::Added,
                left: None,
                right: None,
            });
            *truncated = true;
        }
        return;
    }
    match (left, right) {
        (None, None) => {}
        (None, Some(r)) => {
            out.push(JsonDiffEntry {
                path: path.into(),
                kind: JsonDiffKind::Added,
                left: None,
                right: Some(r.clone()),
            });
        }
        (Some(l), None) => {
            out.push(JsonDiffEntry {
                path: path.into(),
                kind: JsonDiffKind::Removed,
                left: Some(l.clone()),
                right: None,
            });
        }
        (Some(l), Some(r)) => {
            match (l, r) {
                (Value::Object(lm), Value::Object(rm)) => {
                    // Record the container itself so collapsing by
                    // prefix works, then recurse.
                    out.push(JsonDiffEntry {
                        path: path.into(),
                        kind: JsonDiffKind::Same,
                        left: None,
                        right: None,
                    });
                    // Sorted key union — deterministic output.
                    let mut keys: std::collections::BTreeSet<&str> =
                        std::collections::BTreeSet::new();
                    for k in lm.keys() {
                        keys.insert(k.as_str());
                    }
                    for k in rm.keys() {
                        keys.insert(k.as_str());
                    }
                    for k in keys {
                        let child_path = format!("{path}.{k}");
                        walk_json(&child_path, lm.get(k), rm.get(k), out, truncated);
                    }
                }
                (Value::Array(la), Value::Array(ra)) => {
                    out.push(JsonDiffEntry {
                        path: path.into(),
                        kind: JsonDiffKind::Same,
                        left: None,
                        right: None,
                    });
                    let max = la.len().max(ra.len());
                    for i in 0..max {
                        let child_path = format!("{path}[{i}]");
                        walk_json(&child_path, la.get(i), ra.get(i), out, truncated);
                    }
                }
                _ => {
                    // Scalar / type-mismatch leaf.
                    let kind = if l == r {
                        JsonDiffKind::Same
                    } else {
                        JsonDiffKind::Changed
                    };
                    out.push(JsonDiffEntry {
                        path: path.into(),
                        kind,
                        left: Some(l.clone()),
                        right: Some(r.clone()),
                    });
                }
            }
        }
    }
}

/// Count scalar leaves recursively — used for `left_total` /
/// `right_total` so the UI can report "3 of 7 fields differ".
fn count_leaves(v: &serde_json::Value) -> usize {
    use serde_json::Value;
    match v {
        Value::Object(m) => m.values().map(count_leaves).sum::<usize>().max(1),
        Value::Array(a) => a.iter().map(count_leaves).sum::<usize>().max(1),
        _ => 1,
    }
}

pub fn compare_with_options(a: &str, b: &str, ignore_whitespace: bool) -> DiffReport {
    compare_full(a, b, ignore_whitespace, CompareMode::Line)
}

pub fn compare_full(
    a: &str,
    b: &str,
    ignore_whitespace: bool,
    mode: CompareMode,
) -> DiffReport {
    // Word mode: split by whitespace to produce the "lines" the diff
    // engine consumes; otherwise the per-line split.
    let split = |s: &str| -> Vec<String> {
        match mode {
            CompareMode::Line => s.lines().map(String::from).collect(),
            CompareMode::Word => s.split_whitespace().map(String::from).collect(),
        }
    };
    let left: Vec<String> = split(a);
    let right: Vec<String> = split(b);
    let la: Vec<String> = if ignore_whitespace {
        left.iter().map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")).collect()
    } else {
        left.clone()
    };
    let ra: Vec<String> = if ignore_whitespace {
        right.iter().map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")).collect()
    } else {
        right.clone()
    };
    let (ops, equal_count) = diff(&la, &ra);
    let mut lines = Vec::new();
    let mut li = 0usize;
    let mut ri = 0usize;
    for op in ops {
        match op {
            Edit::Equal => {
                lines.push(DiffLine {
                    op: DiffOp::Equal,
                    left_line: Some(li + 1),
                    right_line: Some(ri + 1),
                    text: left[li].clone(),
                });
                li += 1;
                ri += 1;
            }
            Edit::Delete => {
                lines.push(DiffLine {
                    op: DiffOp::Delete,
                    left_line: Some(li + 1),
                    right_line: None,
                    text: left[li].clone(),
                });
                li += 1;
            }
            Edit::Insert => {
                lines.push(DiffLine {
                    op: DiffOp::Insert,
                    left_line: None,
                    right_line: Some(ri + 1),
                    text: right[ri].clone(),
                });
                ri += 1;
            }
        }
    }
    let max_len = left.len().max(right.len()).max(1);
    DiffReport {
        lines,
        similarity: equal_count as f32 / max_len as f32,
        left_total: left.len(),
        right_total: right.len(),
    }
}

enum Edit {
    Equal,
    Insert,
    Delete,
}

fn diff(a: &[String], b: &[String]) -> (Vec<Edit>, usize) {
    let n = a.len();
    let m = b.len();
    // LCS DP table.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let mut ops = Vec::with_capacity(n + m);
    let mut i = n;
    let mut j = m;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops.push(Edit::Equal);
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            ops.push(Edit::Insert);
            j -= 1;
        } else {
            ops.push(Edit::Delete);
            i -= 1;
        }
    }
    ops.reverse();
    (ops, dp[n][m] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_full_similarity() {
        let r = compare_text("a\nb\nc", "a\nb\nc");
        assert_eq!(r.similarity, 1.0);
        assert!(r.lines.iter().all(|l| l.op == DiffOp::Equal));
    }

    #[test]
    fn insertions_and_deletions() {
        let a = "line1\nline2\nline3";
        let b = "line1\nchanged\nline3";
        let r = compare_text(a, b);
        let kinds: Vec<_> = r.lines.iter().map(|l| l.op).collect();
        assert!(kinds.contains(&DiffOp::Delete));
        assert!(kinds.contains(&DiffOp::Insert));
    }

    #[test]
    fn ignore_whitespace() {
        let r = compare_with_options("hello  world", "hello world", true);
        assert_eq!(r.similarity, 1.0);
    }

    #[test]
    fn word_mode_diffs_by_token() {
        let a = "the quick brown fox";
        let b = "the lazy brown fox";
        let r = compare_full(a, b, false, CompareMode::Word);
        // Four tokens on each side; one is replaced.
        assert_eq!(r.left_total, 4);
        assert_eq!(r.right_total, 4);
        let inserted: Vec<_> = r
            .lines
            .iter()
            .filter(|l| l.op == DiffOp::Insert)
            .map(|l| l.text.as_str())
            .collect();
        let deleted: Vec<_> = r
            .lines
            .iter()
            .filter(|l| l.op == DiffOp::Delete)
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(inserted, vec!["lazy"]);
        assert_eq!(deleted, vec!["quick"]);
    }

    #[test]
    fn word_mode_identical_similarity() {
        let r = compare_full("alpha beta gamma", "alpha  beta\ngamma", false, CompareMode::Word);
        assert_eq!(r.similarity, 1.0);
    }

    #[test]
    fn json_identical_full_similarity() {
        let a = r#"{"user":"alice","role":"admin","age":30}"#;
        let b = r#"{"age":30,"user":"alice","role":"admin"}"#;
        let r = compare_json(a, b);
        assert!(r.parse_error_left.is_none() && r.parse_error_right.is_none());
        // All leaf entries are Same; container row is also Same.
        assert!(r.entries.iter().all(|e| e.kind == JsonDiffKind::Same));
        // Similarity is 1.0 because every entry is Same.
        assert!((r.similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn json_added_removed_changed() {
        let a = r#"{"user":"alice","role":"admin","deleted":true}"#;
        let b = r#"{"user":"bob","role":"admin","added":"yes"}"#;
        let r = compare_json(a, b);
        // Pull each leaf change by path for a predictable assertion.
        let by_path: std::collections::HashMap<_, _> =
            r.entries.iter().map(|e| (e.path.clone(), e.kind)).collect();
        assert_eq!(by_path.get("$.user"), Some(&JsonDiffKind::Changed));
        assert_eq!(by_path.get("$.role"), Some(&JsonDiffKind::Same));
        assert_eq!(by_path.get("$.deleted"), Some(&JsonDiffKind::Removed));
        assert_eq!(by_path.get("$.added"), Some(&JsonDiffKind::Added));
        // Container row at the root is Same (both are objects).
        assert_eq!(by_path.get("$"), Some(&JsonDiffKind::Same));
    }

    #[test]
    fn json_arrays_positional_diff() {
        // Positional alignment: index 0 is Same, index 1 is Changed,
        // index 2 is Added (only present on the right).
        let a = r#"{"items":[1,2]}"#;
        let b = r#"{"items":[1,20,30]}"#;
        let r = compare_json(a, b);
        let by_path: std::collections::HashMap<_, _> =
            r.entries.iter().map(|e| (e.path.clone(), e.kind)).collect();
        assert_eq!(by_path.get("$.items[0]"), Some(&JsonDiffKind::Same));
        assert_eq!(by_path.get("$.items[1]"), Some(&JsonDiffKind::Changed));
        assert_eq!(by_path.get("$.items[2]"), Some(&JsonDiffKind::Added));
    }

    #[test]
    fn json_parse_error_surfaces_in_report() {
        let r = compare_json("{\"a\":1}", "{not json}");
        assert!(r.entries.is_empty());
        assert!(r.parse_error_left.is_none());
        assert!(r.parse_error_right.is_some());
        // Both sides broken → both errors land in the report.
        let r = compare_json("not json", "also not");
        assert!(r.parse_error_left.is_some());
        assert!(r.parse_error_right.is_some());
    }
}
