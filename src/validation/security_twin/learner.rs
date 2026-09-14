// Security Twin — Learner (D3)
//
// The learning loop takes comparison results and updates the twin model.
// It maintains a history of predictions and outcomes, identifies
// systematic errors, and produces learning records for model improvement.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{PredictionRecord, PredictionType};

/// A learning record — captures an insight from a prediction error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningRecord {
    /// Unique record ID.
    pub id: String,
    /// The type of learning insight.
    pub insight_type: InsightType,
    /// The attack category this relates to.
    pub attack_category: String,
    /// The ring(s) involved.
    pub rings: Vec<String>,
    /// Human-readable description of the insight.
    pub description: String,
    /// Suggested model adjustment.
    pub suggestion: String,
    /// Priority (higher = more important to fix).
    pub priority: u8,
    /// How many times this pattern has been seen.
    pub occurrence_count: u64,
    /// RFC 3339 timestamp.
    pub timestamp: String,
}

/// Type of learning insight.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InsightType {
    /// The twin model needs a new pattern for this attack category.
    MissingPattern,
    /// An existing pattern has wrong ring assignment.
    WrongRing,
    /// The confidence scoring is miscalibrated.
    ConfidenceMiscalibration,
    /// A ring threshold needs adjustment.
    ThresholdAdjustment,
    /// A new attack category needs to be added.
    NewCategory,
    /// The payload encoding is confusing the model.
    EncodingBlindSpot,
}

impl std::fmt::Display for InsightType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InsightType::MissingPattern => write!(f, "MISSING_PATTERN"),
            InsightType::WrongRing => write!(f, "WRONG_RING"),
            InsightType::ConfidenceMiscalibration => write!(f, "CONFIDENCE_MIS"),
            InsightType::ThresholdAdjustment => write!(f, "THRESHOLD_ADJ"),
            InsightType::NewCategory => write!(f, "NEW_CATEGORY"),
            InsightType::EncodingBlindSpot => write!(f, "ENCODING_BLIND"),
        }
    }
}

/// Stores learning records and computes model update suggestions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LearningStore {
    /// All learning records.
    pub records: Vec<LearningRecord>,
    /// Pattern counts per category (for identifying systematic errors).
    pub error_patterns: HashMap<String, u64>,
    /// Total predictions processed.
    pub total_processed: u64,
    /// Running accuracy.
    pub running_accuracy: f64,
}

impl LearningStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a batch of prediction records and extract learning insights.
    pub fn learn_from_records(&mut self, records: &[PredictionRecord]) -> Vec<LearningRecord> {
        let mut new_insights = Vec::new();

        for record in records {
            self.total_processed += 1;

            if record.correct {
                continue;
            }

            // Classify the error and create a learning record.
            let insight = self.classify_error(record);
            new_insights.push(insight);
        }

        // Update running accuracy.
        let total_correct = records.iter().filter(|r| r.correct).count();
        let batch_accuracy = if !records.is_empty() {
            total_correct as f64 / records.len() as f64
        } else {
            1.0
        };
        self.running_accuracy = if self.total_processed > 0 {
            // Exponential moving average.
            let alpha = 0.1;
            alpha * batch_accuracy + (1.0 - alpha) * self.running_accuracy
        } else {
            batch_accuracy
        };

        // Track error patterns.
        for record in records.iter().filter(|r| !r.correct) {
            *self
                .error_patterns
                .entry(record.attack_category.clone())
                .or_insert(0) += 1;
        }

        // Deduplicate insights (same category + type = merge).
        let deduped = self.deduplicate_insights(new_insights);
        self.records.extend(deduped.clone());
        deduped
    }

    /// Classify a prediction error into a specific insight type.
    fn classify_error(&self, record: &PredictionRecord) -> LearningRecord {
        let (insight_type, description, suggestion) = match (record.predicted, record.actual) {
            (PredictionType::Blocked, PredictionType::Allowed) => {
                // Twin said blocked, but system allowed — false confidence.
                // This could mean: ring threshold too low, pattern missing, or encoding bypass.
                let desc = format!(
                    "Twin predicted block for {} attack but system allowed it. \
                     Confidence was {:.2}. Twin may be overestimating ring sensitivity.",
                    record.attack_category, record.confidence
                );
                let suggestion = format!(
                    "Consider lowering {} ring threshold or adding new detection patterns \
                     for this attack variant.",
                    record
                        .rings
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("unknown")
                );
                (InsightType::ThresholdAdjustment, desc, suggestion)
            }
            (PredictionType::Allowed, PredictionType::Blocked) => {
                // Twin said allowed, but system blocked — missing pattern.
                let desc = format!(
                    "Twin predicted allow for {} attack but system blocked it. \
                     The twin model is missing this detection pattern.",
                    record.attack_category
                );
                let suggestion = format!(
                    "Add new detection pattern for {} category to the twin model. \
                     This is a coverage gap, not a threshold issue.",
                    record.attack_category
                );
                (InsightType::MissingPattern, desc, suggestion)
            }
            (PredictionType::Uncertain, PredictionType::Blocked) => (
                InsightType::ConfidenceMiscalibration,
                format!(
                    "Twin was uncertain but {} attack was actually blocked.",
                    record.attack_category
                ),
                "Review scoring function for this category.".to_string(),
            ),
            (PredictionType::Uncertain, PredictionType::Allowed) => (
                InsightType::MissingPattern,
                format!(
                    "Twin was uncertain and {} attack was not blocked — potential gap.",
                    record.attack_category
                ),
                "Add patterns for this attack category.".to_string(),
            ),
            (PredictionType::Escalated, _) => (
                InsightType::WrongRing,
                format!(
                    "Twin predicted escalation for {} attack but outcome was different.",
                    record.attack_category
                ),
                "Review escalation logic.".to_string(),
            ),
            (p, a) => (
                InsightType::MissingPattern,
                format!(
                    "Unhandled prediction mismatch: {:?} vs {:?} for {}.",
                    p, a, record.attack_category
                ),
                "Add handling for this case.".to_string(),
            ),
        };

        LearningRecord {
            id: uuid::Uuid::new_v4().to_string(),
            insight_type,
            attack_category: record.attack_category.clone(),
            rings: record.rings.clone(),
            description,
            suggestion,
            priority: if record.confidence > 0.8 { 1 } else { 3 },
            occurrence_count: 1,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Merge insights that have the same category + type.
    fn deduplicate_insights(&self, insights: Vec<LearningRecord>) -> Vec<LearningRecord> {
        let mut merged: HashMap<(String, InsightType), LearningRecord> = HashMap::new();
        for insight in insights {
            let key = (insight.attack_category.clone(), insight.insight_type);
            if let Some(existing) = merged.get_mut(&key) {
                existing.occurrence_count += insight.occurrence_count;
            } else {
                merged.insert(key, insight);
            }
        }
        merged.into_values().collect()
    }

    /// Get the top N most important learning insights.
    pub fn top_insights(&self, limit: usize) -> Vec<&LearningRecord> {
        let mut sorted: Vec<_> = self.records.iter().collect();
        sorted.sort_by_key(|r| r.priority);
        sorted.truncate(limit);
        sorted
    }

    /// Get error frequency per attack category.
    pub fn error_frequency(&self) -> Vec<(&String, &u64)> {
        let mut freq: Vec<_> = self.error_patterns.iter().collect();
        freq.sort_by(|a, b| b.1.cmp(a.1));
        freq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        payload: &str,
        predicted: PredictionType,
        actual: PredictionType,
        cat: &str,
    ) -> PredictionRecord {
        PredictionRecord::new(
            payload,
            predicted,
            actual,
            0.9,
            vec!["shield".to_string()],
            cat,
        )
    }

    #[test]
    fn learn_from_correct_predictions() {
        let mut store = LearningStore::new();
        let records = vec![
            record(
                "a",
                PredictionType::Blocked,
                PredictionType::Blocked,
                "sqli",
            ),
            record("b", PredictionType::Allowed, PredictionType::Allowed, "xss"),
        ];
        let insights = store.learn_from_records(&records);
        assert!(insights.is_empty());
        assert_eq!(store.total_processed, 2);
    }

    #[test]
    fn learn_from_false_positive() {
        let mut store = LearningStore::new();
        let records = vec![record(
            "sqli",
            PredictionType::Blocked,
            PredictionType::Allowed,
            "sqli",
        )];
        let insights = store.learn_from_records(&records);
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].insight_type, InsightType::ThresholdAdjustment);
    }

    #[test]
    fn learn_from_false_negative() {
        let mut store = LearningStore::new();
        let records = vec![record(
            "xss",
            PredictionType::Allowed,
            PredictionType::Blocked,
            "xss",
        )];
        let insights = store.learn_from_records(&records);
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].insight_type, InsightType::MissingPattern);
    }

    #[test]
    fn deduplication() {
        let mut store = LearningStore::new();
        let records = vec![
            record(
                "a",
                PredictionType::Blocked,
                PredictionType::Allowed,
                "sqli",
            ),
            record(
                "b",
                PredictionType::Blocked,
                PredictionType::Allowed,
                "sqli",
            ),
        ];
        let insights = store.learn_from_records(&records);
        // Two records of same category+type should be merged.
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].occurrence_count, 2);
    }

    #[test]
    fn error_frequency() {
        let mut store = LearningStore::new();
        let records = vec![
            record(
                "a",
                PredictionType::Blocked,
                PredictionType::Allowed,
                "sqli",
            ),
            record(
                "b",
                PredictionType::Blocked,
                PredictionType::Allowed,
                "sqli",
            ),
            record("c", PredictionType::Blocked, PredictionType::Allowed, "xss"),
        ];
        store.learn_from_records(&records);
        let freq = store.error_frequency();
        assert_eq!(freq[0].0, "sqli");
        assert_eq!(*freq[0].1, 2);
    }

    #[test]
    fn running_accuracy_updates() {
        let mut store = LearningStore::new();
        // All correct → accuracy should go up.
        let records = vec![
            record(
                "a",
                PredictionType::Blocked,
                PredictionType::Blocked,
                "sqli",
            ),
            record("b", PredictionType::Allowed, PredictionType::Allowed, "xss"),
        ];
        store.learn_from_records(&records);
        assert!(store.running_accuracy > 0.0);
    }
}
