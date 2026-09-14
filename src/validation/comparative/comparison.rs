// Comparative Research Lab — Comparison & Delta Analysis (D7)
//
// Compares benchmark results across versions, systems, and time.
// Produces structured comparison reports with deltas.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::benchmarks::{BenchmarkResult, Direction};

/// A single delta (change) between two benchmark results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    /// The metric name.
    pub metric: String,
    /// The old value.
    pub baseline: f64,
    /// The new value.
    pub current: f64,
    /// Absolute change.
    pub absolute: f64,
    /// Percentage change.
    pub pct_change: f64,
    /// Whether this is an improvement (respects direction).
    pub is_improvement: bool,
    /// Whether this is a regression.
    pub is_regression: bool,
    /// Whether the change is significant (> noise threshold).
    pub is_significant: bool,
}

impl Delta {
    pub fn new(metric: &str, baseline: f64, current: f64, direction: Direction) -> Self {
        let absolute = current - baseline;
        let pct_change = if baseline.abs() < 1e-9 {
            if current.abs() < 1e-9 {
                0.0
            } else {
                100.0
            }
        } else {
            (absolute / baseline.abs()) * 100.0
        };

        let is_improvement = match direction {
            Direction::HigherIsBetter => current > baseline,
            Direction::LowerIsBetter => current < baseline,
        };

        let is_regression = match direction {
            Direction::HigherIsBetter => current < baseline,
            Direction::LowerIsBetter => current > baseline,
        };

        // Significant if absolute change > 1% of baseline or > 0.01.
        let is_significant = pct_change.abs() > 1.0 || absolute.abs() > 0.01;

        Self {
            metric: metric.to_string(),
            baseline,
            current,
            absolute,
            pct_change,
            is_improvement,
            is_regression,
            is_significant,
        }
    }
}

/// A comparison between two benchmark runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// The baseline (old) run info.
    pub baseline_version: String,
    /// The current (new) run info.
    pub current_version: String,
    /// All deltas.
    pub deltas: Vec<Delta>,
    /// Summary of improvements and regressions.
    pub summary: ComparisonSummary,
    /// Per-category breakdown.
    pub category_breakdown: Vec<CategoryBreakdown>,
    /// RFC 3339 timestamp.
    pub timestamp: String,
}

impl ComparisonReport {
    /// Compare two sets of benchmark results.
    /// Results are matched by benchmark_id.
    pub fn compare(
        baseline: &[BenchmarkResult],
        current: &[BenchmarkResult],
        direction_map: &HashMap<String, Direction>,
    ) -> Self {
        let mut deltas = Vec::new();

        // Build a lookup for baseline results.
        let baseline_map: HashMap<String, &BenchmarkResult> = baseline
            .iter()
            .map(|r| (r.benchmark_id.clone(), r))
            .collect();

        for current_result in current {
            if let Some(baseline_result) = baseline_map.get(&current_result.benchmark_id) {
                for (metric_name, &current_value) in &current_result.metrics {
                    if let Some(&baseline_value) = baseline_result.metrics.get(metric_name) {
                        let direction = direction_map
                            .get(metric_name)
                            .copied()
                            .unwrap_or(Direction::HigherIsBetter);

                        deltas.push(Delta::new(
                            metric_name,
                            baseline_value,
                            current_value,
                            direction,
                        ));
                    }
                }
            }
        }

        let summary = ComparisonSummary::from_deltas(&deltas);
        let category_breakdown = CategoryBreakdown::from_deltas(&deltas, baseline, current);

        Self {
            baseline_version: baseline
                .first()
                .map(|r| r.version.clone())
                .unwrap_or_default(),
            current_version: current
                .first()
                .map(|r| r.version.clone())
                .unwrap_or_default(),
            deltas,
            summary,
            category_breakdown,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get only regressions.
    pub fn regressions(&self) -> Vec<&Delta> {
        self.deltas
            .iter()
            .filter(|d| d.is_regression && d.is_significant)
            .collect()
    }

    /// Get only improvements.
    pub fn improvements(&self) -> Vec<&Delta> {
        self.deltas
            .iter()
            .filter(|d| d.is_improvement && d.is_significant)
            .collect()
    }

    /// Export as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Text summary.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "=== Comparison: {} vs {} ===\n",
            self.baseline_version, self.current_version
        ));
        out.push_str(&format!(
            "Improvements: {}  Regressions: {}  Unchanged: {}\n",
            self.summary.improvements, self.summary.regressions, self.summary.unchanged
        ));

        if !self.regressions().is_empty() {
            out.push_str("\n--- Regressions ---\n");
            for r in self.regressions().iter().take(10) {
                out.push_str(&format!(
                    "  {} : {} -> {} ({:+.1}%)\n",
                    r.metric, r.baseline, r.current, r.pct_change
                ));
            }
        }

        if !self.improvements().is_empty() {
            out.push_str("\n--- Improvements ---\n");
            for i in self.improvements().iter().take(10) {
                out.push_str(&format!(
                    "  {} : {} -> {} ({:+.1}%)\n",
                    i.metric, i.baseline, i.current, i.pct_change
                ));
            }
        }

        out
    }
}

/// Summary of a comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub total_metrics: u64,
    pub improvements: u64,
    pub regressions: u64,
    pub unchanged: u64,
    pub avg_improvement_pct: f64,
    pub avg_regression_pct: f64,
}

impl ComparisonSummary {
    pub fn from_deltas(deltas: &[Delta]) -> Self {
        let total = deltas.len() as u64;
        let improvements = deltas
            .iter()
            .filter(|d| d.is_improvement && d.is_significant)
            .count() as u64;
        let regressions = deltas
            .iter()
            .filter(|d| d.is_regression && d.is_significant)
            .count() as u64;
        let unchanged = total - improvements - regressions;

        let imp_pcts: Vec<f64> = deltas
            .iter()
            .filter(|d| d.is_improvement)
            .map(|d| d.pct_change)
            .collect();
        let reg_pcts: Vec<f64> = deltas
            .iter()
            .filter(|d| d.is_regression)
            .map(|d| d.pct_change)
            .collect();

        let avg_improvement_pct = if imp_pcts.is_empty() {
            0.0
        } else {
            imp_pcts.iter().sum::<f64>() / imp_pcts.len() as f64
        };
        let avg_regression_pct = if reg_pcts.is_empty() {
            0.0
        } else {
            reg_pcts.iter().sum::<f64>() / reg_pcts.len() as f64
        };

        Self {
            total_metrics: total,
            improvements,
            regressions,
            unchanged,
            avg_improvement_pct,
            avg_regression_pct,
        }
    }
}

/// Per-category breakdown of comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub category: String,
    pub deltas: Vec<Delta>,
    pub has_regression: bool,
}

impl CategoryBreakdown {
    pub fn from_deltas(
        deltas: &[Delta],
        _baseline: &[BenchmarkResult],
        _current: &[BenchmarkResult],
    ) -> Vec<Self> {
        // Group deltas by a simple heuristic — use metric name prefix.
        let mut groups: HashMap<String, Vec<Delta>> = HashMap::new();
        for d in deltas {
            let cat = metric_to_category(&d.metric);
            groups.entry(cat).or_default().push(d.clone());
        }

        groups
            .into_iter()
            .map(|(category, deltas)| {
                let has_regression = deltas.iter().any(|d| d.is_regression && d.is_significant);
                CategoryBreakdown {
                    category,
                    deltas,
                    has_regression,
                }
            })
            .collect()
    }
}

/// A snapshot of benchmark results at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSnapshot {
    pub version: String,
    pub run_id: String,
    pub results: Vec<BenchmarkResult>,
    pub timestamp: String,
}

impl ComparisonSnapshot {
    pub fn new(version: &str, run_id: &str, results: Vec<BenchmarkResult>) -> Self {
        Self {
            version: version.to_string(),
            run_id: run_id.to_string(),
            results,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Map a metric name to a category string.
fn metric_to_category(metric: &str) -> String {
    if metric.contains("detection") || metric.contains("coverage") {
        "detection".to_string()
    } else if metric.contains("fp") || metric.contains("false_positive") {
        "false_positive".to_string()
    } else if metric.contains("latency") || metric.contains("p99") || metric.contains("p95") {
        "latency".to_string()
    } else if metric.contains("throughput") || metric.contains("rps") {
        "throughput".to_string()
    } else if metric.contains("drift") {
        "drift".to_string()
    } else if metric.contains("recovery") {
        "recovery".to_string()
    } else {
        "other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_higher_is_better() {
        let d = Delta::new("rate", 0.8, 0.9, Direction::HigherIsBetter);
        assert!(d.is_improvement);
        assert!(!d.is_regression);
        assert!((d.pct_change - 12.5).abs() < 0.1);
    }

    #[test]
    fn delta_lower_is_better() {
        let d = Delta::new("latency", 100.0, 80.0, Direction::LowerIsBetter);
        assert!(d.is_improvement);
        assert!(!d.is_regression);
    }

    #[test]
    fn delta_regression() {
        let d = Delta::new("rate", 0.9, 0.8, Direction::HigherIsBetter);
        assert!(d.is_regression);
        assert!(!d.is_improvement);
    }

    #[test]
    fn delta_significance() {
        let tiny = Delta::new("x", 100.0, 100.001, Direction::HigherIsBetter);
        assert!(!tiny.is_significant);

        let large = Delta::new("x", 100.0, 110.0, Direction::HigherIsBetter);
        assert!(large.is_significant);
    }

    #[test]
    fn comparison_report() {
        let mut direction_map = HashMap::new();
        direction_map.insert("rate".to_string(), Direction::HigherIsBetter);
        direction_map.insert("latency".to_string(), Direction::LowerIsBetter);

        let b1 = BenchmarkResult::new("bench-1", "cv", "1.0.0", "r1")
            .with_metric("rate", 0.85)
            .with_metric("latency", 500.0);
        let c1 = BenchmarkResult::new("bench-1", "cv", "2.0.0", "r2")
            .with_metric("rate", 0.92)
            .with_metric("latency", 450.0);

        let report = ComparisonReport::compare(&[b1], &[c1], &direction_map);
        assert_eq!(report.deltas.len(), 2);
        assert_eq!(report.summary.improvements, 2);
    }

    #[test]
    fn comparison_text() {
        let mut dm = HashMap::new();
        dm.insert("rate".to_string(), Direction::HigherIsBetter);
        let b = BenchmarkResult::new("b", "s", "1.0", "r").with_metric("rate", 0.8);
        let c = BenchmarkResult::new("b", "s", "2.0", "r").with_metric("rate", 0.9);
        let report = ComparisonReport::compare(&[b], &[c], &dm);
        let text = report.to_text();
        assert!(text.contains("1.0 vs 2.0"));
    }

    #[test]
    fn snapshot_creation() {
        let snap = ComparisonSnapshot::new("1.0.0", "run-1", Vec::new());
        assert_eq!(snap.version, "1.0.0");
    }
}
