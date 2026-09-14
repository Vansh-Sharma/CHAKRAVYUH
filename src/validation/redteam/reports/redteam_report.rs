// Red Team OS — Red Team Report (D1)
//
// Aggregates evidence from red team runs into detection rate summaries,
// per-ring matrices, and identifies missed attacks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::validation::verification::{Evidence, Severity, Verdict};

/// A single cell in the ring detection matrix.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RingCell {
    /// Number of attacks blocked/detected.
    pub blocked: usize,
    /// Number of attacks missed (should have been blocked but weren't).
    pub missed: usize,
    /// Number of attacks that escaped (passed through without detection).
    pub escaped: usize,
}

impl RingCell {
    pub fn total(&self) -> usize {
        self.blocked + self.missed + self.escaped
    }

    pub fn detection_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 1.0;
        }
        self.blocked as f64 / total as f64
    }
}

/// 2D detection matrix: attack_category × ring → RingCell.
pub type RingDetectionMatrix = HashMap<String, HashMap<String, RingCell>>;

/// Per-mutation detection rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationEffectiveness {
    pub mutation_name: String,
    pub total: usize,
    pub detected: usize,
    pub detection_rate: f64,
}

/// Per-encoding detection rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingEffectiveness {
    pub encoding_name: String,
    pub total: usize,
    pub detected: usize,
    pub detection_rate: f64,
}

/// Comprehensive red team report summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamReportSummary {
    /// RFC 3339 generation timestamp.
    pub generated_at: String,
    /// Total evidence items analyzed.
    pub total_evidence: usize,
    /// Overall detection rate.
    pub overall_detection_rate: f64,
    /// Per-ring detection rates.
    pub detection_rate_per_ring: HashMap<String, f64>,
    /// Per-category detection rates.
    pub detection_rate_per_category: HashMap<String, f64>,
    /// Per-mutation detection rates.
    pub mutation_effectiveness: Vec<MutationEffectiveness>,
    /// Per-encoding detection rates.
    pub encoding_effectiveness: Vec<EncodingEffectiveness>,
    /// 2D matrix: category × ring → (blocked, missed, escaped).
    pub ring_matrix: RingDetectionMatrix,
    /// Severity distribution of misses.
    pub miss_severity_distribution: HashMap<String, usize>,
    /// Number of critical misses.
    pub critical_misses: usize,
}

/// Generate a comprehensive red team report from evidence.
pub fn generate_report(evidence: &[Evidence]) -> RedTeamReportSummary {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let total_evidence = evidence.len();

    let mut per_ring_blocked: HashMap<String, usize> = HashMap::new();
    let mut per_ring_total: HashMap<String, usize> = HashMap::new();
    let mut per_cat_blocked: HashMap<String, usize> = HashMap::new();
    let mut per_cat_total: HashMap<String, usize> = HashMap::new();
    let mut per_mutation: HashMap<String, (usize, usize)> = HashMap::new(); // (detected, total)
    let mut per_encoding: HashMap<String, (usize, usize)> = HashMap::new();
    let mut ring_matrix: RingDetectionMatrix = HashMap::new();
    let mut miss_severity: HashMap<String, usize> = HashMap::new();
    let mut critical_misses = 0usize;
    let mut total_blocked = 0usize;

    for ev in evidence {
        // Only count D1 evidence.
        if ev.phase != "D1" {
            continue;
        }

        let is_detected = ev.verdict == Verdict::Pass;
        let category = ev.attack_category.clone().unwrap_or_default();
        let mutation = ev.mutation_applied.clone().unwrap_or_else(|| "unknown".to_string());
        let encoding = ev.encoding_applied.clone().unwrap_or_else(|| "unknown".to_string());

        // Per-ring.
        for ring in &ev.rings {
            *per_ring_total.entry(ring.clone()).or_insert(0) += 1;
            if is_detected {
                *per_ring_blocked.entry(ring.clone()).or_insert(0) += 1;
                total_blocked += 1;
            }
        }

        // Per-category.
        *per_cat_total.entry(category.clone()).or_insert(0) += 1;
        if is_detected {
            *per_cat_blocked.entry(category.clone()).or_insert(0) += 1;
        }

        // Per-mutation.
        let (det, tot) = per_mutation.entry(mutation).or_insert((0, 0));
        *tot += 1;
        if is_detected {
            *det += 1;
        }

        // Per-encoding.
        let (det, tot) = per_encoding.entry(encoding).or_insert((0, 0));
        *tot += 1;
        if is_detected {
            *det += 1;
        }

        // Ring matrix.
        let cat_map = ring_matrix.entry(category.clone()).or_default();
        for ring in &ev.rings {
            let cell = cat_map.entry(ring.clone()).or_default();
            if is_detected {
                cell.blocked += 1;
            } else if ev.verdict == Verdict::Fail {
                cell.missed += 1;
                // Track severity of misses.
                let sev_key = format!("{:?}", ev.severity);
                *miss_severity.entry(sev_key).or_insert(0) += 1;
                if ev.severity == Severity::Critical {
                    critical_misses += 1;
                }
            } else {
                cell.escaped += 1;
            }
        }
    }

    // Compute detection rates.
    let detection_rate_per_ring: HashMap<String, f64> = per_ring_total
        .iter()
        .map(|(ring, total)| {
            let blocked = per_ring_blocked.get(ring).copied().unwrap_or(0);
            let rate = if *total > 0 { blocked as f64 / *total as f64 } else { 1.0 };
            (ring.clone(), rate)
        })
        .collect();

    let detection_rate_per_category: HashMap<String, f64> = per_cat_total
        .iter()
        .map(|(cat, total)| {
            let blocked = per_cat_blocked.get(cat).copied().unwrap_or(0);
            let rate = if *total > 0 { blocked as f64 / *total as f64 } else { 1.0 };
            (cat.clone(), rate)
        })
        .collect();

    let overall = if total_evidence > 0 {
        total_blocked as f64 / total_evidence as f64
    } else {
        1.0
    };

    let mut mutation_effectiveness: Vec<MutationEffectiveness> = per_mutation
        .into_iter()
        .map(|(name, (det, tot))| MutationEffectiveness {
            mutation_name: name,
            total: tot,
            detected: det,
            detection_rate: if tot > 0 { det as f64 / tot as f64 } else { 1.0 },
        })
        .collect();
    mutation_effectiveness.sort_by(|a, b| a.detection_rate.partial_cmp(&b.detection_rate).unwrap_or(std::cmp::Ordering::Equal));

    let mut encoding_effectiveness: Vec<EncodingEffectiveness> = per_encoding
        .into_iter()
        .map(|(name, (det, tot))| EncodingEffectiveness {
            encoding_name: name,
            total: tot,
            detected: det,
            detection_rate: if tot > 0 { det as f64 / tot as f64 } else { 1.0 },
        })
        .collect();
    encoding_effectiveness.sort_by(|a, b| a.detection_rate.partial_cmp(&b.detection_rate).unwrap_or(std::cmp::Ordering::Equal));

    RedTeamReportSummary {
        generated_at,
        total_evidence,
        overall_detection_rate: overall,
        detection_rate_per_ring,
        detection_rate_per_category,
        mutation_effectiveness,
        encoding_effectiveness,
        ring_matrix,
        miss_severity_distribution: miss_severity,
        critical_misses,
    }
}

/// Compute detection rate per ring from evidence.
pub fn detection_rate_per_ring(evidence: &[Evidence]) -> HashMap<String, f64> {
    let report = generate_report(evidence);
    report.detection_rate_per_ring
}

/// Find all missed attacks (should have been blocked but weren't).
pub fn missed_attacks(evidence: &[Evidence]) -> Vec<&Evidence> {
    evidence
        .iter()
        .filter(|ev| ev.phase == "D1" && ev.verdict == Verdict::Fail)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(passed: bool, ring: &str, category: &str, severity: Severity) -> Evidence {
        let _verdict = if passed { Verdict::Pass } else { Verdict::Fail };
        let mut ev = if passed {
            Evidence::pass(
                "run-1", "test", "D1", ring,
                serde_json::json!({"blocked": true}),
                serde_json::json!({"blocked": true}),
            )
        } else {
            Evidence::fail(
                "run-1", "test", "D1", ring,
                severity,
                serde_json::json!({"blocked": true}),
                serde_json::json!({"blocked": false}),
                "Attack missed",
            )
        };
        ev.rings = vec![ring.to_string()];
        ev.attack_category = Some(category.to_string());
        ev
    }

    #[test]
    fn report_with_mixed_results() {
        let evidence = vec![
            make_evidence(true, "shield", "PromptInjection", Severity::High),
            make_evidence(true, "shield", "PromptInjection", Severity::High),
            make_evidence(false, "shield", "Jailbreak", Severity::Critical),
            make_evidence(true, "threat", "PromptInjection", Severity::High),
        ];
        let report = generate_report(&evidence);
        assert_eq!(report.total_evidence, 4);
        assert!((report.overall_detection_rate - 0.75).abs() < 0.01);
        assert_eq!(report.critical_misses, 1);
    }

    #[test]
    fn detection_rate_per_ring_works() {
        let evidence = vec![
            make_evidence(true, "shield", "PromptInjection", Severity::High),
            make_evidence(false, "shield", "Jailbreak", Severity::High),
            make_evidence(true, "threat", "PromptInjection", Severity::High),
        ];
        let rates = detection_rate_per_ring(&evidence);
        assert!(rates.contains_key("shield"));
        assert!(rates.contains_key("threat"));
        assert!((rates["shield"] - 0.5).abs() < 0.01);
        assert!((rates["threat"] - 1.0).abs() < 0.01);
    }

    #[test]
    fn missed_attacks_filters_correctly() {
        let evidence = vec![
            make_evidence(true, "shield", "A", Severity::High),
            make_evidence(false, "shield", "B", Severity::Critical),
            make_evidence(false, "threat", "C", Severity::Medium),
            make_evidence(true, "threat", "D", Severity::High),
        ];
        let missed = missed_attacks(&evidence);
        assert_eq!(missed.len(), 2);
    }

    #[test]
    fn empty_evidence_report() {
        let report = generate_report(&[]);
        assert_eq!(report.total_evidence, 0);
        assert!((report.overall_detection_rate - 1.0).abs() < 0.01);
    }

    #[test]
    fn ring_matrix_populated() {
        let evidence = vec![
            make_evidence(true, "shield", "PromptInjection", Severity::High),
            make_evidence(false, "shield", "Jailbreak", Severity::High),
        ];
        let report = generate_report(&evidence);
        assert!(report.ring_matrix.contains_key("PromptInjection"));
        let shield_cell = report.ring_matrix["PromptInjection"].get("shield");
        assert!(shield_cell.is_some());
        assert_eq!(shield_cell.unwrap().blocked, 1);
    }
}
