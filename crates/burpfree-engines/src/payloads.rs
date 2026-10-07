//! Payload providers for the Intruder-style attack engine.
//!
//! A [`PayloadProvider`] is a stateless description of a set of
//! payloads. Call [`PayloadProvider::iter`] to get a fresh iterator.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod library;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadProvider {
    List(SimpleListProvider),
    Numbers(NumbersProvider),
    File(FileProvider),
    Charset(CharsetProvider),
    /// Burp's "Null payloads" type — fire the same request N times
    /// with an empty substitution. Useful for sequential-POST style
    /// probes (session-ID brute, race-condition reruns, time-based
    /// counting) where the payload content itself doesn't matter.
    Null(NullProvider),
}

impl PayloadProvider {
    pub fn len(&self) -> usize {
        match self {
            Self::List(p) => p.len(),
            Self::Numbers(p) => p.len(),
            Self::File(p) => p.len(),
            Self::Charset(p) => p.len(),
            Self::Null(p) => p.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, i: usize) -> Option<String> {
        match self {
            Self::List(p) => p.get(i),
            Self::Numbers(p) => p.get(i),
            Self::File(p) => p.get(i),
            Self::Charset(p) => p.get(i),
            Self::Null(p) => p.get(i),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = String> + Send + '_> {
        match self {
            Self::List(p) => Box::new(p.items.iter().cloned()),
            Self::Numbers(p) => Box::new(p.clone().into_iter()),
            Self::File(p) => Box::new(p.lines.iter().cloned()),
            Self::Charset(p) => Box::new(p.clone().into_iter()),
            Self::Null(p) => Box::new(p.clone().into_iter()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimpleListProvider {
    pub items: Vec<String>,
}

impl SimpleListProvider {
    pub fn new(items: Vec<String>) -> Self {
        Self { items }
    }
    pub fn len(&self) -> usize { self.items.len() }
    pub fn is_empty(&self) -> bool { self.items.is_empty() }
    pub fn get(&self, i: usize) -> Option<String> { self.items.get(i).cloned() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumbersProvider {
    pub from: i64,
    pub to: i64,
    pub step: i64,
    #[serde(default)]
    pub pad_to: Option<usize>,
}

impl NumbersProvider {
    pub fn len(&self) -> usize {
        if self.step == 0 { return 0; }
        let diff = (self.to - self.from) / self.step;
        if diff < 0 { return 0; }
        (diff + 1) as usize
    }
    pub fn get(&self, i: usize) -> Option<String> {
        if i >= self.len() {
            return None;
        }
        let n = self.from + self.step * (i as i64);
        Some(match self.pad_to {
            Some(w) => format!("{:0>width$}", n, width = w),
            None => n.to_string(),
        })
    }
}

impl IntoIterator for NumbersProvider {
    type Item = String;
    type IntoIter = NumbersIter;
    fn into_iter(self) -> Self::IntoIter {
        NumbersIter { current: self.from, cfg: self, done: false }
    }
}

pub struct NumbersIter {
    current: i64,
    cfg: NumbersProvider,
    done: bool,
}

impl Iterator for NumbersIter {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.cfg.step == 0 {
            return None;
        }
        if (self.cfg.step > 0 && self.current > self.cfg.to)
            || (self.cfg.step < 0 && self.current < self.cfg.to)
        {
            return None;
        }
        let v = self.current;
        let next = v + self.cfg.step;
        self.current = next;
        if (self.cfg.step > 0 && v == self.cfg.to) || (self.cfg.step < 0 && v == self.cfg.to) {
            self.done = true;
        }
        Some(match self.cfg.pad_to {
            Some(w) => format!("{:0>width$}", v, width = w),
            None => v.to_string(),
        })
    }
}

/// Fire the same request `count` times. Each `get(i)` / iterator
/// element yields an empty string — the request template is
/// substituted with `""` which `apply_payloads` already handles
/// (leaves the marker position blank). Burp's "Null payloads"
/// equivalent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullProvider {
    pub count: usize,
}

impl NullProvider {
    pub fn new(count: usize) -> Self {
        Self { count }
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn get(&self, i: usize) -> Option<String> {
        if i < self.count {
            Some(String::new())
        } else {
            None
        }
    }
}

impl IntoIterator for NullProvider {
    type Item = String;
    type IntoIter = NullIter;
    fn into_iter(self) -> Self::IntoIter {
        NullIter {
            remaining: self.count,
        }
    }
}

pub struct NullIter {
    remaining: usize,
}

impl Iterator for NullIter {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(String::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProvider {
    pub path: PathBuf,
    #[serde(skip)]
    pub lines: Vec<String>,
}

impl FileProvider {
    pub fn load(path: PathBuf) -> Result<Self> {
        let f = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let r = BufReader::new(f);
        let mut lines = Vec::new();
        for line in r.lines() {
            let line = line?;
            if !line.is_empty() {
                lines.push(line);
            }
        }
        Ok(Self { path, lines })
    }
    pub fn len(&self) -> usize { self.lines.len() }
    pub fn get(&self, i: usize) -> Option<String> { self.lines.get(i).cloned() }
}

/// Combinations drawn from a character set of a given length (useful
/// for brute-forcing short tokens).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharsetProvider {
    pub charset: String,
    pub min_len: usize,
    pub max_len: usize,
}

impl CharsetProvider {
    pub fn len(&self) -> usize {
        let base = self.charset.chars().count();
        if base == 0 {
            return 0;
        }
        let mut total: usize = 0;
        for n in self.min_len..=self.max_len {
            if n == 0 { continue; }
            total = total.saturating_add(base.saturating_pow(n as u32));
        }
        total
    }
    pub fn get(&self, i: usize) -> Option<String> {
        self.clone().into_iter().nth(i)
    }
}

impl IntoIterator for CharsetProvider {
    type Item = String;
    type IntoIter = CharsetIter;
    fn into_iter(self) -> Self::IntoIter {
        let chars: Vec<char> = self.charset.chars().collect();
        CharsetIter {
            chars,
            min_len: self.min_len.max(1),
            max_len: self.max_len.max(self.min_len.max(1)),
            indices: Vec::new(),
            done: false,
        }
    }
}

pub struct CharsetIter {
    chars: Vec<char>,
    min_len: usize,
    max_len: usize,
    indices: Vec<usize>,
    done: bool,
}

impl Iterator for CharsetIter {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.chars.is_empty() {
            return None;
        }
        if self.indices.is_empty() {
            self.indices = vec![0; self.min_len];
            return Some(self.indices.iter().map(|&i| self.chars[i]).collect());
        }
        // increment like an odometer
        let base = self.chars.len();
        let mut i = self.indices.len() as isize - 1;
        loop {
            if i < 0 {
                // extend length
                let new_len = self.indices.len() + 1;
                if new_len > self.max_len {
                    self.done = true;
                    return None;
                }
                self.indices = vec![0; new_len];
                return Some(self.indices.iter().map(|&i| self.chars[i]).collect());
            }
            let ii = i as usize;
            self.indices[ii] += 1;
            if self.indices[ii] >= base {
                self.indices[ii] = 0;
                i -= 1;
            } else {
                break;
            }
        }
        Some(self.indices.iter().map(|&i| self.chars[i]).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn simple_list_iter() {
        let p = PayloadProvider::List(SimpleListProvider::new(vec!["a".into(), "b".into()]));
        let v: Vec<_> = p.iter().collect();
        assert_eq!(v, vec!["a".to_string(), "b".into()]);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn numbers_inclusive_range_pad() {
        let p = PayloadProvider::Numbers(NumbersProvider {
            from: 1, to: 3, step: 1, pad_to: Some(3),
        });
        let v: Vec<_> = p.iter().collect();
        assert_eq!(v, vec!["001".to_string(), "002".into(), "003".into()]);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn numbers_descending() {
        let p = PayloadProvider::Numbers(NumbersProvider {
            from: 5, to: 2, step: -1, pad_to: None,
        });
        let v: Vec<_> = p.iter().collect();
        assert_eq!(v, vec!["5", "4", "3", "2"]);
    }

    #[test]
    fn file_loader() {
        let mut tf = NamedTempFile::new().unwrap();
        writeln!(tf, "alpha").unwrap();
        writeln!(tf, "beta").unwrap();
        writeln!(tf, "").unwrap();
        writeln!(tf, "gamma").unwrap();
        let f = FileProvider::load(tf.path().to_path_buf()).unwrap();
        assert_eq!(f.lines, vec!["alpha".to_string(), "beta".into(), "gamma".into()]);
    }

    #[test]
    fn null_provider_yields_n_empty_strings() {
        let p = PayloadProvider::Null(NullProvider::new(3));
        assert_eq!(p.len(), 3);
        assert!(!p.is_empty());
        let v: Vec<_> = p.iter().collect();
        assert_eq!(v, vec!["".to_string(), "".into(), "".into()]);
        // Random-access path mirrors iterator.
        assert_eq!(p.get(0), Some(String::new()));
        assert_eq!(p.get(2), Some(String::new()));
        assert_eq!(p.get(3), None);

        // Zero-count is a legal (if useless) config — len/is_empty
        // should agree and the iterator should return nothing.
        let empty = PayloadProvider::Null(NullProvider::new(0));
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty.iter().count(), 0);
    }

    #[test]
    fn charset_len_two_three() {
        let p = CharsetProvider {
            charset: "ab".into(),
            min_len: 1,
            max_len: 2,
        };
        assert_eq!(p.len(), 2 + 4);
        let v: Vec<_> = PayloadProvider::Charset(p).iter().collect();
        assert_eq!(v, vec!["a", "b", "aa", "ab", "ba", "bb"]);
    }
}
