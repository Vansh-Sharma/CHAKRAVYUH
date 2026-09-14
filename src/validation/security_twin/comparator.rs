// Security Twin — Comparator (D3)
//
// Compares twin predictions against real system outcomes.
// Produces discrepancies and accuracy metrics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{PredictionRecord, PredictionType};

/// A single discrepancy between prediction and reality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinDiscrepancy {
    /// The attack payload.
    pub payload: String,
    /// What the twin predicted.
    pub predicted: PredictionType,
    /// What the real system did.
    pub actual: PredictionType,
    /// Confidence the twin had.
    pub twin_confidence: f64,
    /// The type of discrepancy.
    pub discrepancy_type: DiscrepancyType,
    /// The predicted catch ring (if any).
    pub predicted_ring: Option<String>,
    /// The actual catch ring (if any).
    pub actual_ring: Option<String>,
    /// Attack category.
    pub attack_category: String,
}

/// The type of prediction error.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Twin predicted blocked, but real system allowed it.
    /// This is the MOST DANGEROUS — the twin gives false confidence.
    FalsePositive,
    /// Twin predicted allowed, but real system blocked it.
    /// Less dangerous but indicates the twin model is incomplete.
    FalseNegative,
    /// Twin predicted escalation, but real system did something else.
    WrongEscalation,
    /// Twin was uncertain, and it turned out to be an attack.
    MissedUncertain,
    /// Prediction and actual match — no discrepancy.
    None,
}

/// Result of comparing a batch of predictions against actuals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Total comparisons made.
    pub total: u64,
    /// Number of correct predictions.
    pub correct: u64,
    /// Prediction accuracy (correct / total).
    pub accuracy: f64,
    /// All discrepancies found.
    pub discrepancies: Vec<TwinDiscrepancy>,
    /// Per-category accuracy.
    pub category_accuracy: HashMap<String, f64>,
    /// Per-ring prediction accuracy.
    pub ring_accuracy: HashMap<String, f64>,
    /// Most dangerous discrepancies (false positives — twin said safe but wasn't).
    pub false_positives: Vec<TwinDiscrepancy>,
}

impl ComparisonResult {
    /// Compare a list of prediction records.
    pub fn from_records(records: &[PredictionRecord]) -> Self {
        let total = records.len() as u64;
        let correct = records.iter().filter(|r| r.correct).count() as u64;
        let accuracy = if total > 0 { correct as f64 / total as f64 } else { 1.0 };

        let mut discrepancies = Vec::new();
        let mut false_positives = Vec::new();
        let mut category_correct: HashMap<String, (u64, u64)> = HashMap::new();

        for record in records {
            if !record.correct {
                let disc_type = classify_discrepancy(record.predicted, record.actual);
                let disc = TwinDiscrepancy {
                    payload: record.attack_payload.clone(),
                    predicted: record.predicted,
                    actual: record.actual,
                    twin_confidence: record.confidence,
                    discrepancy_type: disc_type,
                    predicted_ring: None,
                    actual_ring: None,
                    attack_category: record.attack_category.clone(),
                };
                if disc_type == DiscrepancyType::FalsePositive {
                    false_positives.push(disc.clone());
                }
                discrepancies.push(disc);
            }

            let entry = category_correct
                .entry(record.attack_category.clone())
                .or_insert((0, 0));
            entry.1 += 1;
            if record.correct {
                entry.0 += 1;
            }
        }

        let category_accuracy: HashMap<String, f64> = category_correct
            .into_iter()
            .map(|(cat, (correct, total))| {
                let acc = if total > 0 { correct as f64 / total as f64 } else { 1.0 };
                (cat, acc)
            })
            .collect();

        Self {
            total,
            correct,
            accuracy,
            discrepancies,
            category_accuracy,
            ring_accuracy: HashMap::new(),
            false_positives,
        }
    }

    /// Get the most dangerous discrepancies (sorted by confidence descending).
    pub fn most_dangerous(&self, limit: usize) -> Vec<&TwinDiscrepancy> {
        let mut fps: Vec<_> = self.false_positives.iter().collect();
        fps.sort_by(|a, b| b.twin_confidence.partial_cmp(&a.twin_confidence).unwrap_or(std::cmp::Ordering::Equal));
        fps.truncate(limit);
        fps
    }

    /// Generate a human-readable summary.
    pub fn summary(&self) -> ComparisonSummary {
        ComparisonSummary {
            total_comparisons: self.total,
            accuracy_pct: self.accuracy * 100.0,
            discrepancy_count: self.discrepancies.len() as u64,
            false_positive_count: self.false_positives.len() as u64,
            worst_category: self.worst_category(),
            worst_category_accuracy: self.worst_category_accuracy(),
        }
    }

    fn worst_category(&self) -> String {
        self.category_accuracy
            .iter()
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(cat, _)| cat.clone())
            .unwrap_or_default()
    }

    fn worst_category_accuracy(&self) -> f64 {
        self.category_accuracy
            .values()
            .copied()
            .fold(1.0, f64::min)
    }
}

/// Human-readable comparison summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub total_comparisons: u64,
    pub accuracy_pct: f64,
    pub discrepancy_count: u64,
    pub false_positive_count: u64,
    pub worst_category: String,
    pub worst_category_accuracy: f64,
}

fn classify_discrepancy(predicted: PredictionType, actual: PredictionType) -> DiscrepancyType {
    match (predicted, actual) {
        (PredictionType::Blocked, PredictionType::Allowed) => DiscrepancyType::FalsePositive,
        (PredictionType::Allowed, PredictionType::Blocked) => DiscrepancyType::FalseNegative,
        (PredictionType::Escalated, _) | (_, PredictionType::Escalated) => DiscrepancyType::WrongEscalation,
        (PredictionType::Uncertain, PredictionType::Blocked) => DiscrepancyType::MissedUncertain,
        _ => DiscrepancyType::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(payload: &str, predicted: PredictionType, actual: PredictionType, cat: &str) -> PredictionRecord {
        PredictionRecord::new(payload, predicted, actual, 0.9, vec!["shield".to_string()], cat)
    }

    #[test]
    fn perfect_accuracy() {
        let records = vec![
            make_record("a", PredictionType::Blocked, PredictionType::Blocked, "sqli"),
            make_record("b", PredictionType::Allowed, PredictionType::Allowed, "xss"),
        ];
        let result = ComparisonResult::from_records(&records);
        assert_eq!(result.accuracy, 1.0);
        assert!(result.discrepancies.is_empty());
    }

    #[test]
    fn false_positive_detection() {
        let records = vec![
            make_record("sqli", PredictionType::Blocked, PredictionType::Allowed, "sqli"),
        ];
        let result = ComparisonResult::from_records(&records);
        assert_eq!(result.accuracy, 0.0);
        assert_eq!(result.false_positives.len(), 1);
        assert_eq!(result.false_positives[0].discrepancy_type, DiscrepancyType::FalsePositive);
    }

    #[test]
    fn category_accuracy() {
        let records = vec![
            make_record("a", PredictionType::Blocked, PredictionType::Blocked, "sqli"),
            make_record("b", PredictionType::Blocked, PredictionType::Allowed, "sqli"),
            make_record("c", PredictionType::Blocked, PredictionType::Blocked, "xss"),
        ];
        let result = ComparisonResult::from_records(&records);
        assert!((result.category_accuracy["sqli"] - 0.5).abs() < 0.01);
        assert!((result.category_accuracy["xss"] - 1.0).abs() < 0.01);
    }

    #[test]
    fn summary_output() {
        let records = vec![
            make_record("a", PredictionType::Blocked, PredictionType::Blocked, "sqli"),
            make_record("b", PredictionType::Blocked, PredictionType::Allowed, "sqli"),
        ];
        let result = ComparisonResult::from_records(&records);
        let summary = result.summary();
        assert!((summary.accuracy_pct - 50.0).abs() < 0.01);
        assert_eq!(summary.false_positive_count, 1);
    }

    #[test]
    fn most_dangerous_sorting() {
        let records = vec![
            make_record("low-conf-fp", PredictionType::Blocked, PredictionType::Allowed, "a"),
            make_record("high-conf-fp", PredictionType::Blocked, PredictionType::Allowed, "b"),
        ];
        let mut result = ComparisonResult::from_records(&records);
        // Set confidence values
        result.false_positives[0].twin_confidence = 0.3;
        result.false_positives[1].twin_confidence = 0.95;
        let dangerous = result.most_dangerous(1);
        assert_eq!(dangerous.len(), 1);
        assert!((dangerous[0].twin_confidence - 0.95).abs() < 0.01);
    }
}
