// Keshav-Learn — Feedback Collector
//
// Collects decision feedback from operators, automated monitors, and
// cross-ring intelligence to feed the learning loop.
//
// Feedback types:
//   1. Operator feedback  — explicit approve/reject/override from admin
//   2. False positive report — a deny was incorrect (should have allowed)
//   3. False negative report — an allow was incorrect (should have denied)
//   4. Escalation outcome   — result of an escalation approval/denial
//
// The FeedbackCollector is the intake layer for Keshav-Learn. It stores
// feedback entries in memory (production would use persistent storage)
// and makes them available to ThresholdOptimizer and AnomalyProfiler.
//
// Latency Budget: <0.1ms per record (append-only)
// Thread Safety: RwLock-protected interior mutability

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Types of decision feedback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackType {
    /// Operator explicitly approved a decision.
    Approve,
    /// Operator explicitly rejected a decision.
    Reject,
    /// A Deny was a false positive (should have allowed).
    FalsePositive,
    /// An Allow was a false negative (should have denied).
    FalseNegative,
    /// An escalation was approved by the designated approver.
    EscalationApproved,
    /// An escalation was denied by the designated approver.
    EscalationDenied,
}

/// Severity classification of the feedback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackSeverity {
    /// Low impact — cosmetic or minor misclassification.
    Low,
    /// Medium impact — affected a legitimate request.
    Medium,
    /// High impact — security-relevant misclassification.
    High,
    /// Critical — system-wide policy gap or exploit path.
    Critical,
}

/// A single feedback entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    /// Unique feedback ID.
    pub feedback_id: String,
    /// The request ID this feedback refers to.
    pub request_id: String,
    /// Type of feedback.
    pub feedback_type: FeedbackType,
    /// Severity classification.
    pub severity: FeedbackSeverity,
    /// Which ring(s) the feedback targets (empty = all rings).
    pub target_rings: Vec<String>,
    /// Original decision that was fed back on.
    pub original_decision: String,
    /// Free-text explanation from the operator.
    pub explanation: String,
    /// Who submitted the feedback.
    pub submitted_by: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Whether this feedback has been processed by Learn.
    pub processed: bool,
}

/// Feedback Collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackCollectorConfig {
    /// Maximum number of feedback entries to retain in memory.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// How many unprocessed entries before triggering auto-optimize.
    #[serde(default = "default_auto_optimize_threshold")]
    pub auto_optimize_threshold: usize,
}

fn default_max_entries() -> usize { 10_000 }
fn default_auto_optimize_threshold() -> usize { 50 }

impl Default for FeedbackCollectorConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_entries(),
            auto_optimize_threshold: default_auto_optimize_threshold(),
        }
    }
}

/// The Feedback Collector — append-only intake for the learning loop.
pub struct FeedbackCollector {
    config: FeedbackCollectorConfig,
    entries: RwLock<Vec<FeedbackEntry>>,
    /// Index: request_id -> feedback entries (for fast lookup).
    by_request: RwLock<HashMap<String, Vec<usize>>>,
    /// Count of unprocessed entries.
    unprocessed_count: RwLock<usize>,
}

impl FeedbackCollector {
    pub fn new(config: FeedbackCollectorConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(Vec::new()),
            by_request: RwLock::new(HashMap::new()),
            unprocessed_count: RwLock::new(0),
        }
    }

    /// Submit a new feedback entry.
    pub fn submit(&self, entry: FeedbackEntry) {
        let request_id = entry.request_id.clone();
        let feedback_id = entry.feedback_id.clone();

        {
            let mut entries = self.entries.write().unwrap();
            let idx = entries.len();
            entries.push(entry);

            let mut by_request = self.by_request.write().unwrap();
            by_request.entry(request_id).or_default().push(idx);

            let mut count = self.unprocessed_count.write().unwrap();
            *count += 1;
        }

        tracing::debug!(
            feedback_id = %feedback_id,
            "feedback submitted to Keshav-Learn"
        );
    }

    /// Get all feedback entries.
    pub fn entries(&self) -> Vec<FeedbackEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Get feedback for a specific request.
    pub fn feedback_for_request(&self, request_id: &str) -> Vec<FeedbackEntry> {
        let by_request = self.by_request.read().unwrap();
        if let Some(indices) = by_request.get(request_id) {
            let entries = self.entries.read().unwrap();
            indices.iter().map(|&i| entries[i].clone()).collect()
        } else {
            vec![]
        }
    }

    /// Get unprocessed feedback count.
    pub fn unprocessed_count(&self) -> usize {
        *self.unprocessed_count.read().unwrap()
    }

    /// Whether auto-optimization should be triggered.
    pub fn should_auto_optimize(&self) -> bool {
        self.unprocessed_count() >= self.config.auto_optimize_threshold
    }

    /// Mark entries as processed.
    pub fn mark_processed(&self, up_to_count: usize) {
        let mut entries = self.entries.write().unwrap();
        let mut processed = 0;
        for entry in entries.iter_mut() {
            if !entry.processed && processed < up_to_count {
                entry.processed = true;
                processed += 1;
            }
        }
        let mut count = self.unprocessed_count.write().unwrap();
        *count = (*count).saturating_sub(processed);
    }

    /// Get summary statistics.
    pub fn stats(&self) -> FeedbackStats {
        let entries = self.entries.read().unwrap();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut false_positives = 0usize;
        let mut false_negatives = 0usize;

        for entry in entries.iter() {
            *by_type.entry(format!("{:?}", entry.feedback_type)).or_insert(0) += 1;
            *by_severity.entry(format!("{:?}", entry.severity)).or_insert(0) += 1;
            match entry.feedback_type {
                FeedbackType::FalsePositive => false_positives += 1,
                FeedbackType::FalseNegative => false_negatives += 1,
                _ => {}
            }
        }

        let total = entries.len();
        let misclassification_rate = if total > 0 {
            (false_positives + false_negatives) as f64 / total as f64
        } else {
            0.0
        };

        FeedbackStats {
            total_entries: total,
            unprocessed: *self.unprocessed_count.read().unwrap(),
            false_positives,
            false_negatives,
            misclassification_rate,
            by_type,
            by_severity,
        }
    }
}

impl Clone for FeedbackCollector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            entries: RwLock::new(self.entries.read().unwrap().clone()),
            by_request: RwLock::new(self.by_request.read().unwrap().clone()),
            unprocessed_count: RwLock::new(*self.unprocessed_count.read().unwrap()),
        }
    }
}

/// Feedback statistics summary.
#[derive(Debug, Clone, Serialize)]
pub struct FeedbackStats {
    pub total_entries: usize,
    pub unprocessed: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub misclassification_rate: f64,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_collector() -> FeedbackCollector {
        FeedbackCollector::new(FeedbackCollectorConfig::default())
    }

    fn make_entry(request_id: &str, ft: FeedbackType) -> FeedbackEntry {
        FeedbackEntry {
            feedback_id: uuid::Uuid::new_v4().to_string(),
            request_id: request_id.to_string(),
            feedback_type: ft,
            severity: FeedbackSeverity::Medium,
            target_rings: vec!["shield".to_string()],
            original_decision: "deny:WAF_SQL_INJECTION".to_string(),
            explanation: "test feedback".to_string(),
            submitted_by: "admin".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        }
    }

    #[test]
    fn submit_and_retrieve() {
        let c = make_collector();
        c.submit(make_entry("req-1", FeedbackType::FalsePositive));
        c.submit(make_entry("req-2", FeedbackType::Approve));
        assert_eq!(c.entries().len(), 2);
        assert_eq!(c.unprocessed_count(), 2);
    }

    #[test]
    fn feedback_for_specific_request() {
        let c = make_collector();
        c.submit(make_entry("req-1", FeedbackType::FalsePositive));
        c.submit(make_entry("req-1", FeedbackType::Reject));
        c.submit(make_entry("req-2", FeedbackType::Approve));
        assert_eq!(c.feedback_for_request("req-1").len(), 2);
        assert_eq!(c.feedback_for_request("req-2").len(), 1);
        assert_eq!(c.feedback_for_request("req-3").len(), 0);
    }

    #[test]
    fn auto_optimize_trigger() {
        let cfg = FeedbackCollectorConfig {
            auto_optimize_threshold: 3,
            ..Default::default()
        };
        let c = FeedbackCollector::new(cfg);
        assert!(!c.should_auto_optimize());
        c.submit(make_entry("r1", FeedbackType::FalsePositive));
        c.submit(make_entry("r2", FeedbackType::FalsePositive));
        c.submit(make_entry("r3", FeedbackType::FalsePositive));
        assert!(c.should_auto_optimize());
    }

    #[test]
    fn mark_processed() {
        let c = make_collector();
        c.submit(make_entry("r1", FeedbackType::FalsePositive));
        c.submit(make_entry("r2", FeedbackType::FalsePositive));
        c.mark_processed(1);
        assert_eq!(c.unprocessed_count(), 1);
    }

    #[test]
    fn stats_calculation() {
        let c = make_collector();
        c.submit(make_entry("r1", FeedbackType::FalsePositive));
        c.submit(make_entry("r2", FeedbackType::FalseNegative));
        c.submit(make_entry("r3", FeedbackType::Approve));
        let stats = c.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.false_positives, 1);
        assert_eq!(stats.false_negatives, 1);
        assert!((stats.misclassification_rate - 0.666).abs() < 0.01);
    }
}
