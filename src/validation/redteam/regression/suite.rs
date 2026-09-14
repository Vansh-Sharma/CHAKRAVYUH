// Red Team OS — Regression Suite (D1)
//
// Stores baseline results and compares new runs against them.
// Detects regressions (previously blocked attacks now missed),
// improvements, and unchanged results.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::validation::redteam::reports::redteam_report::RedTeamReportSummary;

/// The kind of difference found between baseline and new run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    /// Previously blocked, now missed — this is a regression.
    Regression,
    /// Previously missed, now blocked — this is an improvement.
    Improvement,
    /// No change in outcome.
    Unchanged,
}

/// A single diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// What changed (category, ring, mutation, encoding).
    pub dimension: String,
    /// Specific key within the dimension.
    pub key: String,
    /// The kind of change.
    pub kind: DiffKind,
    /// Previous detection rate.
    pub baseline_rate: f64,
    /// New detection rate.
    pub new_rate: f64,
    /// Absolute change.
    pub delta: f64,
}

impl DiffEntry {
    pub fn is_regression(&self) -> bool {
        self.kind == DiffKind::Regression
    }

    pub fn is_improvement(&self) -> bool {
        self.kind == DiffKind::Improvement
    }
}

/// A snapshot of a previous run's results used for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionBaseline {
    /// Unique baseline ID.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// RFC 3339 timestamp when the baseline was captured.
    pub captured_at: String,
    /// The summary that was captured.
    pub summary: RedTeamReportSummary,
    /// Per-ring detection rates at baseline.
    pub ring_rates: HashMap<String, f64>,
    /// Per-category detection rates at baseline.
    pub category_rates: HashMap<String, f64>,
}

impl RegressionBaseline {
    /// Capture a new baseline from a report summary.
    pub fn capture(label: &str, summary: &RedTeamReportSummary) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            label: label.to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
            summary: summary.clone(),
            ring_rates: summary.detection_rate_per_ring.clone(),
            category_rates: summary.detection_rate_per_category.clone(),
        }
    }

    /// Save baseline to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write baseline to {}: {}", path.display(), e))
    }

    /// Load baseline from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read baseline from {}: {}", path.display(), e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse baseline: {}", e))
    }
}

/// The full regression diff between a new run and a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionDiff {
    /// The baseline ID.
    pub baseline_id: String,
    /// The baseline label.
    pub baseline_label: String,
    /// The baseline capture time.
    pub baseline_captured_at: String,
    /// RFC 3339 timestamp of the new run.
    pub new_run_at: String,
    /// All differences found.
    pub diffs: Vec<DiffEntry>,
    /// Number of regressions found.
    pub regression_count: usize,
    /// Number of improvements found.
    pub improvement_count: usize,
    /// Whether the new run passes the regression check.
    /// A run passes if there are zero regressions.
    pub passes: bool,
}

impl RegressionDiff {
    /// Get only the regression entries.
    pub fn regressions(&self) -> Vec<&DiffEntry> {
        self.diffs.iter().filter(|d| d.is_regression()).collect()
    }

    /// Get only the improvement entries.
    pub fn improvements(&self) -> Vec<&DiffEntry> {
        self.diffs.iter().filter(|d| d.is_improvement()).collect()
    }
}

/// Regression suite — manages baselines and comparisons.
pub struct RegressionSuite;

impl RegressionSuite {
    /// Compare a new run's summary against a baseline.
    pub fn compare_against_baseline(
        new: &RedTeamReportSummary,
        baseline: &RegressionBaseline,
    ) -> RegressionDiff {
        let mut diffs = Vec::new();
        let threshold = 0.001; // Tolerance for floating point comparison.

        // Compare per-ring rates.
        let all_rings: std::collections::HashSet<_> = new
            .detection_rate_per_ring
            .keys()
            .chain(baseline.ring_rates.keys())
            .collect();

        for ring in all_rings {
            let new_rate = new
                .detection_rate_per_ring
                .get(ring)
                .copied()
                .unwrap_or(1.0);
            let base_rate = baseline.ring_rates.get(ring).copied().unwrap_or(1.0);
            let delta = new_rate - base_rate;

            if delta.abs() > threshold {
                let kind = if delta < 0.0 {
                    DiffKind::Regression
                } else {
                    DiffKind::Improvement
                };
                diffs.push(DiffEntry {
                    dimension: "ring".to_string(),
                    key: ring.clone(),
                    kind,
                    baseline_rate: base_rate,
                    new_rate,
                    delta,
                });
            }
        }

        // Compare per-category rates.
        let all_cats: std::collections::HashSet<_> = new
            .detection_rate_per_category
            .keys()
            .chain(baseline.category_rates.keys())
            .collect();

        for cat in all_cats {
            let new_rate = new
                .detection_rate_per_category
                .get(cat)
                .copied()
                .unwrap_or(1.0);
            let base_rate = baseline.category_rates.get(cat).copied().unwrap_or(1.0);
            let delta = new_rate - base_rate;

            if delta.abs() > threshold {
                let kind = if delta < 0.0 {
                    DiffKind::Regression
                } else {
                    DiffKind::Improvement
                };
                diffs.push(DiffEntry {
                    dimension: "category".to_string(),
                    key: cat.clone(),
                    kind,
                    baseline_rate: base_rate,
                    new_rate,
                    delta,
                });
            }
        }

        // Compare overall detection rate.
        let overall_delta = new.overall_detection_rate - baseline.summary.overall_detection_rate;
        if overall_delta.abs() > threshold {
            let kind = if overall_delta < 0.0 {
                DiffKind::Regression
            } else {
                DiffKind::Improvement
            };
            diffs.push(DiffEntry {
                dimension: "overall".to_string(),
                key: "detection_rate".to_string(),
                kind,
                baseline_rate: baseline.summary.overall_detection_rate,
                new_rate: new.overall_detection_rate,
                delta: overall_delta,
            });
        }

        // Compare critical misses.
        let crit_delta = new.critical_misses as i64 - baseline.summary.critical_misses as i64;
        if crit_delta > 0 {
            diffs.push(DiffEntry {
                dimension: "severity".to_string(),
                key: "critical_misses".to_string(),
                kind: DiffKind::Regression,
                baseline_rate: baseline.summary.critical_misses as f64,
                new_rate: new.critical_misses as f64,
                delta: crit_delta as f64,
            });
        } else if crit_delta < 0 {
            diffs.push(DiffEntry {
                dimension: "severity".to_string(),
                key: "critical_misses".to_string(),
                kind: DiffKind::Improvement,
                baseline_rate: baseline.summary.critical_misses as f64,
                new_rate: new.critical_misses as f64,
                delta: crit_delta as f64,
            });
        }

        let regression_count = diffs.iter().filter(|d| d.is_regression()).count();
        let improvement_count = diffs.iter().filter(|d| d.is_improvement()).count();
        let passes = regression_count == 0;

        RegressionDiff {
            baseline_id: baseline.id.clone(),
            baseline_label: baseline.label.clone(),
            baseline_captured_at: baseline.captured_at.clone(),
            new_run_at: new.generated_at.clone(),
            diffs,
            regression_count,
            improvement_count,
            passes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_summary(overall_rate: f64, ring_rates: Vec<(&str, f64)>) -> RedTeamReportSummary {
        let mut detection_rate_per_ring = HashMap::new();
        for (k, v) in ring_rates {
            detection_rate_per_ring.insert(k.to_string(), v);
        }
        RedTeamReportSummary {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_evidence: 100,
            overall_detection_rate: overall_rate,
            detection_rate_per_ring,
            detection_rate_per_category: HashMap::new(),
            mutation_effectiveness: Vec::new(),
            encoding_effectiveness: Vec::new(),
            ring_matrix: HashMap::new(),
            miss_severity_distribution: HashMap::new(),
            critical_misses: 0,
        }
    }

    #[test]
    fn no_regression_when_same() {
        let summary = make_summary(0.95, vec![("shield", 0.95), ("threat", 0.90)]);
        let baseline = RegressionBaseline::capture("test", &summary);
        let diff = RegressionSuite::compare_against_baseline(&summary, &baseline);
        assert!(diff.passes);
        assert_eq!(diff.regression_count, 0);
    }

    #[test]
    fn detects_regression() {
        let baseline_summary = make_summary(0.95, vec![("shield", 0.95)]);
        let baseline = RegressionBaseline::capture("test", &baseline_summary);

        let new_summary = make_summary(0.85, vec![("shield", 0.85)]);
        let diff = RegressionSuite::compare_against_baseline(&new_summary, &baseline);
        assert!(!diff.passes);
        assert!(diff.regression_count > 0);
    }

    #[test]
    fn detects_improvement() {
        let baseline_summary = make_summary(0.80, vec![("shield", 0.80)]);
        let baseline = RegressionBaseline::capture("test", &baseline_summary);

        let new_summary = make_summary(0.90, vec![("shield", 0.90)]);
        let diff = RegressionSuite::compare_against_baseline(&new_summary, &baseline);
        assert!(diff.improvement_count > 0);
    }

    #[test]
    fn baseline_serialization_roundtrip() {
        let summary = make_summary(0.90, vec![("shield", 0.90)]);
        let baseline = RegressionBaseline::capture("ser-test", &summary);

        let json = serde_json::to_string(&baseline).unwrap();
        let restored: RegressionBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, baseline.id);
        assert_eq!(restored.label, "ser-test");
        assert_eq!(restored.ring_rates["shield"], 0.90);
    }

    #[test]
    fn baseline_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let summary = make_summary(0.95, vec![("threat", 0.95)]);
        let baseline = RegressionBaseline::capture("file-test", &summary);

        baseline.save_to_file(&path).unwrap();
        let loaded = RegressionBaseline::load_from_file(&path).unwrap();
        assert_eq!(loaded.id, baseline.id);
        assert_eq!(loaded.label, "file-test");
    }

    #[test]
    fn diff_entry_helpers() {
        let entry = DiffEntry {
            dimension: "ring".to_string(),
            key: "shield".to_string(),
            kind: DiffKind::Regression,
            baseline_rate: 0.95,
            new_rate: 0.85,
            delta: -0.10,
        };
        assert!(entry.is_regression());
        assert!(!entry.is_improvement());
    }
}
