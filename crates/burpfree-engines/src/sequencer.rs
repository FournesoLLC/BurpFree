//! Sequencer-style token randomness analysis.
//!
//! Collects a bag of tokens (session IDs, CSRF tokens, API keys) and
//! reports basic statistics:
//!
//! * character-set used
//! * per-position character distribution
//! * byte-level entropy (Shannon)
//! * uniqueness
//! * mean / stddev length
//! * duplicate groups
//!
//! Statistical results are observations, **not** security conclusions.
//! The UI should present them with that caveat.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenAnalysis {
    pub count: usize,
    pub unique_count: usize,
    pub min_len: usize,
    pub max_len: usize,
    pub mean_len: f32,
    pub stddev_len: f32,
    pub character_set: Vec<char>,
    pub bits_per_char_estimate: f32,
    pub shannon_entropy_bytes: f32,
    pub per_position: Vec<PositionStats>,
    pub top_duplicates: Vec<DupGroup>,
    /// χ² statistic for byte frequencies versus a uniform-256
    /// distribution. Degrees of freedom = 255. A higher value means
    /// the byte histogram is further from uniform.
    #[serde(default)]
    pub chi_square_byte: f32,
    /// Degrees of freedom actually used (= distinct byte values seen - 1).
    /// Zero when every byte appears, otherwise strictly less than 255.
    #[serde(default)]
    pub chi_square_dof: u32,
    /// Wald-Wolfowitz runs-test z-score on byte parity (high / low
    /// half of the byte space). |z| ≤ 2 is roughly consistent with
    /// random bit flipping; larger magnitudes suggest clustering.
    #[serde(default)]
    pub runs_test_z: f32,
    /// Number of observed parity runs — the raw statistic the z-score
    /// is derived from.
    #[serde(default)]
    pub runs_observed: u32,
    /// Expected number of runs under the random-null hypothesis.
    #[serde(default)]
    pub runs_expected: f32,
    /// Count of samples with the high-bit set (byte ≥ 128). Reported
    /// so the UI can show the raw balance alongside the derived z.
    #[serde(default)]
    pub runs_high_count: u32,
    /// Count of samples with the high-bit unset.
    #[serde(default)]
    pub runs_low_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionStats {
    pub position: usize,
    pub distribution: BTreeMap<char, usize>,
    pub distinct_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DupGroup {
    pub token: String,
    pub count: usize,
}

pub fn analyze_tokens(tokens: &[String]) -> TokenAnalysis {
    let n = tokens.len();
    if n == 0 {
        return TokenAnalysis::default();
    }
    let mut lens: Vec<usize> = tokens.iter().map(|t| t.chars().count()).collect();
    let min_len = *lens.iter().min().unwrap_or(&0);
    let max_len = *lens.iter().max().unwrap_or(&0);
    let sum: usize = lens.iter().sum();
    let mean = sum as f32 / n as f32;
    let var: f32 = lens.iter().map(|l| (*l as f32 - mean).powi(2)).sum::<f32>() / n as f32;
    let stddev = var.sqrt();

    // Character set + byte entropy.
    let mut charset: std::collections::BTreeSet<char> = Default::default();
    let mut byte_counts = [0u64; 256];
    let mut total_bytes = 0u64;
    for t in tokens {
        for c in t.chars() {
            charset.insert(c);
        }
        for &b in t.as_bytes() {
            byte_counts[b as usize] += 1;
            total_bytes += 1;
        }
    }
    let char_set_vec: Vec<char> = charset.into_iter().collect();
    let bits_per_char_estimate = if char_set_vec.len() <= 1 {
        0.0
    } else {
        (char_set_vec.len() as f32).log2()
    };
    let mut shannon = 0.0f64;
    if total_bytes > 0 {
        for &c in &byte_counts {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total_bytes as f64;
            shannon -= p * p.log2();
        }
    }

    // Per-position stats up to the shortest token length.
    let positions = min_len;
    let mut per_position = Vec::with_capacity(positions);
    for pos in 0..positions {
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for t in tokens {
            if let Some(c) = t.chars().nth(pos) {
                *counts.entry(c).or_insert(0) += 1;
            }
        }
        per_position.push(PositionStats {
            position: pos,
            distinct_count: counts.len(),
            distribution: counts,
        });
    }

    // Duplicate groups.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for t in tokens {
        *counts.entry(t.clone()).or_insert(0) += 1;
    }
    let unique_count = counts.len();
    let mut dups: Vec<DupGroup> = counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(k, v)| DupGroup { token: k, count: v })
        .collect();
    dups.sort_by(|a, b| b.count.cmp(&a.count));
    dups.truncate(20);

    // Byte-level χ² against a uniform-256 distribution.
    let (chi_square_byte, chi_square_dof) = chi_square_uniform_256(&byte_counts, total_bytes);

    // Runs test over byte parity (high bit set vs clear). Walks every
    // byte in token-emission order; for well-mixed tokens we expect
    // roughly as many runs as a fair coin would produce.
    let (runs_observed, runs_expected, runs_z, hi, lo) = runs_test_parity(tokens);

    lens.sort();
    TokenAnalysis {
        count: n,
        unique_count,
        min_len,
        max_len,
        mean_len: mean,
        stddev_len: stddev,
        character_set: char_set_vec,
        bits_per_char_estimate,
        shannon_entropy_bytes: shannon as f32,
        per_position,
        top_duplicates: dups,
        chi_square_byte,
        chi_square_dof,
        runs_test_z: runs_z,
        runs_observed,
        runs_expected,
        runs_high_count: hi,
        runs_low_count: lo,
    }
}

fn chi_square_uniform_256(counts: &[u64; 256], total: u64) -> (f32, u32) {
    if total == 0 {
        return (0.0, 0);
    }
    let expected = total as f64 / 256.0;
    let mut chi = 0.0f64;
    let mut dof: u32 = 0;
    for &c in counts.iter() {
        if c == 0 {
            // We still factor the zero bucket into χ² (observed − expected)² / expected.
            chi += expected;
            continue;
        }
        dof += 1;
        let diff = c as f64 - expected;
        chi += diff * diff / expected;
    }
    (chi as f32, dof.saturating_sub(1))
}

fn runs_test_parity(tokens: &[String]) -> (u32, f32, f32, u32, u32) {
    let mut hi: u32 = 0;
    let mut lo: u32 = 0;
    let mut runs: u32 = 0;
    let mut prev: Option<bool> = None;
    for t in tokens {
        for &b in t.as_bytes() {
            let high = b >= 128;
            if high {
                hi += 1;
            } else {
                lo += 1;
            }
            match prev {
                None => {
                    runs = 1;
                    prev = Some(high);
                }
                Some(p) if p != high => {
                    runs += 1;
                    prev = Some(high);
                }
                _ => {}
            }
        }
    }
    let n1 = hi as f64;
    let n2 = lo as f64;
    let n = n1 + n2;
    if n < 2.0 || n1 == 0.0 || n2 == 0.0 {
        // Degenerate: all bytes on one side of the split. z = 0 is a
        // sentinel meaning "no useful signal from this test".
        return (runs, 0.0, 0.0, hi, lo);
    }
    let expected = 2.0 * n1 * n2 / n + 1.0;
    let var = (2.0 * n1 * n2 * (2.0 * n1 * n2 - n)) / (n * n * (n - 1.0));
    let std = var.sqrt();
    let z = if std > 0.0 {
        (runs as f64 - expected) / std
    } else {
        0.0
    };
    (runs, expected as f32, z as f32, hi, lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_entropy_hex() {
        let tokens: Vec<String> = (0..100).map(|_| burpfree_core::ids::random_token(16)).collect();
        let a = analyze_tokens(&tokens);
        assert_eq!(a.count, 100);
        assert_eq!(a.unique_count, 100);
        assert!(a.shannon_entropy_bytes > 3.5, "entropy: {}", a.shannon_entropy_bytes);
        assert_eq!(a.min_len, 32);
    }

    #[test]
    fn obvious_pattern_low_variance() {
        let tokens: Vec<String> = (0..10)
            .map(|i| format!("session-{:04}", i))
            .collect();
        let a = analyze_tokens(&tokens);
        assert_eq!(a.count, 10);
        // All start with "session-"; first few positions have a single
        // distinct value.
        assert_eq!(a.per_position[0].distinct_count, 1);
    }

    #[test]
    fn duplicate_detection() {
        let tokens = vec![
            "abc".to_string(),
            "abc".into(),
            "def".into(),
            "abc".into(),
        ];
        let a = analyze_tokens(&tokens);
        assert_eq!(a.top_duplicates.len(), 1);
        assert_eq!(a.top_duplicates[0].token, "abc");
        assert_eq!(a.top_duplicates[0].count, 3);
    }

    #[test]
    fn chi_square_detects_biased_distribution() {
        // Tokens made entirely of the character 'a' — one byte dominates.
        let biased: Vec<String> = (0..64).map(|_| "aaaaaaaaaaaaaaaa".to_string()).collect();
        let a = analyze_tokens(&biased);
        assert!(a.chi_square_byte > 100_000.0, "chi² should be huge: {}", a.chi_square_byte);

        // Hex tokens — spread across 16 nibble characters.
        let hex: Vec<String> = (0..64)
            .map(|_| burpfree_core::ids::random_token(32))
            .collect();
        let b = analyze_tokens(&hex);
        assert!(
            b.chi_square_byte < a.chi_square_byte,
            "hex should be closer to uniform than all-'a'"
        );
    }

    #[test]
    fn runs_test_z_near_zero_for_random_hex() {
        let hex: Vec<String> = (0..200)
            .map(|_| burpfree_core::ids::random_token(32))
            .collect();
        let a = analyze_tokens(&hex);
        // ASCII hex ('0'..='9', 'a'..='f') is always < 0x80, so every
        // byte is "low". The parity test is degenerate here and
        // reports z = 0 by design. The counts should still reflect it.
        assert_eq!(a.runs_high_count, 0);
        assert!(a.runs_low_count > 0);
        assert_eq!(a.runs_test_z, 0.0);
    }

    #[test]
    fn runs_test_z_signals_long_runs() {
        // 64 bytes of high followed by 64 bytes of low — 2 runs total,
        // when a fair coin would expect ~65. Z should be a very large
        // negative number.
        let highs = vec![0xFFu8; 64];
        let lows = vec![0x01u8; 64];
        let combined: Vec<u8> = highs.into_iter().chain(lows.into_iter()).collect();
        let token = String::from_utf8_lossy(&combined).to_string();
        let a = analyze_tokens(&[token]);
        assert!(
            a.runs_test_z < -3.0,
            "clustered z should be < -3, got {}",
            a.runs_test_z
        );
        assert_eq!(a.runs_observed, 2);
    }

    #[test]
    fn empty_input_safe() {
        let a = analyze_tokens(&[]);
        assert_eq!(a.count, 0);
        assert_eq!(a.chi_square_byte, 0.0);
        assert_eq!(a.runs_test_z, 0.0);
    }
}
