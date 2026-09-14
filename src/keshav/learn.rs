// Keshav-Learn — Adaptive Learning Layer (Phase 6)
//
// The learning brain of CHAKRAVYUH. Coordinates four subsystems:
//   1. FeedbackCollector — operator/approval feedback intake
//   2. ThresholdOptimizer — per-ring threshold tuning
//   3. AnomalyProfiler — behavioral anomaly detection
//   4. PatternStore — attack pattern persistence & recall
//
// ARCHITECTURAL GUARANTEE (Principle 1):
//   Keshav-Learn can NEVER override Keshav-Decide's Fallback Rules.
//   Learn can only adjust Policy Engine thresholds and provide advisory
//   signals. If Learn is disabled or fails, the system continues to
//   operate with static thresholds — no degradation in safety.
//
// Architecture Principle: Decide-without-Learn (Principle 1)
//   If Keshav-Learn is disabled, removed, or corrupt:
//   - Keshav-Decide still returns valid Decisions
//   - Keshav-Risk still returns valid RiskScores
//   - All rings still function independently
//   - The system degrades gracefully to Phase 5 behavior
//
// Learning loop:
//   1. Collect feedback from operators and automated monitors
//   2. Profile behavioral baselines for anomaly detection
//   3. Optimize ring thresholds based on feedback patterns
//   4. Store learned patterns for long-term recall
//   5. Provide learned signals to Keshav-Risk and Keshav-Decide
//
// Latency Budget: <1ms total overhead per request (for observe + assess)
// Thread Safety: All subsystems are internally synchronized

use std::sync::Arc;

use serde::Serialize;

use super::feedback_collector::{FeedbackCollector, FeedbackCollectorConfig, FeedbackEntry, FeedbackStats, FeedbackType, FeedbackSeverity};
use super::threshold_optimizer::{ThresholdOptimizer, ThresholdOptimizerConfig, OptimizationResult};
use super::anomaly_profiler::{AnomalyProfiler, AnomalyProfilerConfig, AnomalyAssessment, SourceId};
use super::pattern_store::{PatternStore, PatternStoreConfig, Pattern};

/// Keshav-Learn configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct LearnConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub feedback_collector: FeedbackCollectorConfig,

    #[serde(default)]
    pub threshold_optimizer: ThresholdOptimizerConfig,

    #[serde(default)]
    pub anomaly_profiler: AnomalyProfilerConfig,

    #[serde(default)]
    pub pattern_store: PatternStoreConfig,
}

fn default_enabled() -> bool { true }

impl Default for LearnConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            feedback_collector: FeedbackCollectorConfig::default(),
            threshold_optimizer: ThresholdOptimizerConfig::default(),
            anomaly_profiler: AnomalyProfilerConfig::default(),
            pattern_store: PatternStoreConfig::default(),
        }
    }
}

/// The overall learning status.
#[derive(Debug, Clone, Serialize)]
pub struct LearnStatus {
    pub enabled: bool,
    pub feedback_stats: FeedbackStats,
    pub unprocessed_feedback: usize,
    pub auto_optimize_pending: bool,
    pub profiles_count: usize,
    pub patterns_count: usize,
    pub threshold_count: usize,
    pub last_optimization: Option<OptimizationSummary>,
}

/// Summary of the last optimization pass.
#[derive(Debug, Clone, Serialize)]
pub struct OptimizationSummary {
    pub timestamp: String,
    pub adjustments_made: usize,
    pub rings_adjusted: Vec<String>,
}

/// Keshav-Learn — the adaptive learning coordinator.
///
/// This is the public face of the learning layer. It coordinates
/// all four subsystems and provides a unified interface for the
/// API layer and Keshav subsystems.
pub struct KeshavLearn {
    config: Arc<LearnConfig>,
    feedback: Arc<FeedbackCollector>,
    optimizer: Arc<ThresholdOptimizer>,
    profiler: Arc<AnomalyProfiler>,
    patterns: Arc<PatternStore>,
    last_optimization: std::sync::RwLock<Option<OptimizationSummary>>,
}

impl KeshavLearn {
    /// Create a new Keshav-Learn instance.
    pub fn new(config: LearnConfig) -> crate::Result<Self> {
        let feedback = Arc::new(FeedbackCollector::new(config.feedback_collector.clone()));
        let optimizer = Arc::new(ThresholdOptimizer::new(config.threshold_optimizer.clone()));
        let profiler = Arc::new(AnomalyProfiler::new(config.anomaly_profiler.clone()));
        let patterns = Arc::new(PatternStore::new(config.pattern_store.clone()));

        // Register default thresholds for all 9 rings.
        optimizer.register_ring("shield", 9.0, 6.0);
        optimizer.register_ring("threat", 9.0, 7.0);
        optimizer.register_ring("identity", 9.0, 6.0);
        optimizer.register_ring("memory", 9.0, 6.0);
        optimizer.register_ring("agent", 9.0, 6.0);
        optimizer.register_ring("execution", 9.0, 6.0);
        optimizer.register_ring("reasoning", 9.0, 6.0);
        optimizer.register_ring("governance", 9.0, 6.0);
        optimizer.register_ring("recovery_sec", 9.0, 6.0);

        Ok(Self {
            config: Arc::new(config),
            feedback,
            optimizer,
            profiler,
            patterns,
            last_optimization: std::sync::RwLock::new(None),
        })
    }

    /// Create a disabled instance (all operations are no-ops).
    pub fn disabled() -> crate::Result<Self> {
        Self::new(LearnConfig { enabled: false, ..Default::default() })
    }

    /// Whether learning is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    // ── Feedback Intake ──

    /// Submit operator feedback on a decision.
    pub fn submit_feedback(&self, entry: FeedbackEntry) {
        if !self.config.enabled {
            return;
        }
        self.feedback.submit(entry);
    }

    /// Submit a quick false-positive report.
    pub fn report_false_positive(
        &self,
        request_id: &str,
        ring_name: &str,
        original_decision: &str,
        explanation: &str,
        submitted_by: &str,
    ) {
        if !self.config.enabled {
            return;
        }
        self.feedback.submit(FeedbackEntry {
            feedback_id: uuid::Uuid::new_v4().to_string(),
            request_id: request_id.to_string(),
            feedback_type: FeedbackType::FalsePositive,
            severity: FeedbackSeverity::Medium,
            target_rings: vec![ring_name.to_string()],
            original_decision: original_decision.to_string(),
            explanation: explanation.to_string(),
            submitted_by: submitted_by.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        });
    }

    /// Submit a quick false-negative report.
    pub fn report_false_negative(
        &self,
        request_id: &str,
        ring_name: &str,
        original_decision: &str,
        explanation: &str,
        submitted_by: &str,
    ) {
        if !self.config.enabled {
            return;
        }
        self.feedback.submit(FeedbackEntry {
            feedback_id: uuid::Uuid::new_v4().to_string(),
            request_id: request_id.to_string(),
            feedback_type: FeedbackType::FalseNegative,
            severity: FeedbackSeverity::High,
            target_rings: vec![ring_name.to_string()],
            original_decision: original_decision.to_string(),
            explanation: explanation.to_string(),
            submitted_by: submitted_by.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        });
    }

    // ── Behavioral Profiling ──

    /// Observe a request for behavioral profiling.
    pub fn observe_request(
        &self,
        source_ip: &str,
        user_id: Option<&str>,
        agent_id: Option<&str>,
        denied: bool,
        prompt_length: usize,
        tool_name: Option<&str>,
    ) {
        if !self.config.enabled {
            return;
        }

        // Profile by IP (always).
        self.profiler.observe(&SourceId::Ip(source_ip.to_string()), denied, prompt_length, tool_name);

        // Profile by user if available.
        if let Some(uid) = user_id {
            self.profiler.observe(&SourceId::User(uid.to_string()), denied, prompt_length, tool_name);
        }

        // Profile by agent if available.
        if let Some(aid) = agent_id {
            self.profiler.observe(&SourceId::Agent(aid.to_string()), denied, prompt_length, tool_name);
        }
    }

    /// Assess anomaly for a source.
    pub fn assess_anomaly(&self, source_ip: &str) -> AnomalyAssessment {
        if !self.config.enabled {
            return AnomalyAssessment {
                source_key: format!("ip:{}", source_ip),
                anomaly_score: 0.0,
                dimensions: Default::default(),
                is_anomalous: false,
                summary: "learning disabled".to_string(),
            };
        }
        self.profiler.assess(&SourceId::Ip(source_ip.to_string()))
    }

    // ── Threshold Optimization ──

    /// Run an optimization pass. Called when auto-optimize threshold is reached.
    pub fn optimize_thresholds(&self) -> Vec<OptimizationResult> {
        if !self.config.enabled {
            return vec![];
        }

        let entries = self.feedback.entries();
        let unprocessed: Vec<_> = entries.iter().filter(|e| !e.processed).cloned().collect();

        let results = self.optimizer.optimize(&unprocessed);
        let processed_count = if results.is_empty() { 0 } else { unprocessed.len() };

        if processed_count > 0 {
            self.feedback.mark_processed(processed_count);

            let summary = OptimizationSummary {
                timestamp: chrono::Utc::now().to_rfc3339(),
                adjustments_made: results.len(),
                rings_adjusted: results.iter().map(|r| r.ring_name.clone()).collect(),
            };

            let mut last = self.last_optimization.write().unwrap();
            *last = Some(summary);
        }

        results
    }

    /// Get current deny threshold for a ring (learned or default).
    pub fn deny_threshold(&self, ring_name: &str) -> f64 {
        self.optimizer.deny_threshold(ring_name)
    }

    /// Get current challenge threshold for a ring (learned or default).
    pub fn challenge_threshold(&self, ring_name: &str) -> f64 {
        self.optimizer.challenge_threshold(ring_name)
    }

    /// Reset all learned thresholds to defaults.
    pub fn reset_thresholds(&self) {
        self.optimizer.reset_all();
        tracing::info!("Keshav-Learn: all thresholds reset to defaults");
    }

    // ── Pattern Store ──

    /// Add a pattern to the store.
    pub fn add_pattern(&self, pattern: Pattern) {
        if !self.config.enabled {
            return;
        }
        self.patterns.add(pattern);
    }

    /// Get a pattern by ID.
    pub fn get_pattern(&self, id: &str) -> Option<Pattern> {
        self.patterns.get(id)
    }

    /// Search patterns.
    pub fn search_patterns(&self, ring: Option<&str>, tags: &[&str]) -> Vec<Pattern> {
        self.patterns.search(ring, tags, None)
    }

    /// Record a pattern match.
    pub fn record_pattern_match(&self, pattern_id: &str, is_true_positive: bool) {
        self.patterns.record_match(pattern_id, is_true_positive);
    }

    /// Export patterns as JSON.
    pub fn export_patterns(&self) -> crate::Result<String> {
        self.patterns.export_json()
    }

    /// Import patterns from JSON.
    pub fn import_patterns(&self, json: &str) -> crate::Result<usize> {
        self.patterns.import_json(json)
    }

    // ── Status ──

    /// Get comprehensive learning status.
    pub fn status(&self) -> LearnStatus {
        LearnStatus {
            enabled: self.config.enabled,
            feedback_stats: self.feedback.stats(),
            unprocessed_feedback: self.feedback.unprocessed_count(),
            auto_optimize_pending: self.feedback.should_auto_optimize(),
            profiles_count: self.profiler.profile_count(),
            patterns_count: self.patterns.count(),
            threshold_count: self.optimizer.all_thresholds().len(),
            last_optimization: self.last_optimization.read().unwrap().clone(),
        }
    }

    /// Get subsystem references for direct access.
    pub fn feedback_collector(&self) -> &FeedbackCollector { &self.feedback }
    pub fn threshold_optimizer(&self) -> &ThresholdOptimizer { &self.optimizer }
    pub fn anomaly_profiler(&self) -> &AnomalyProfiler { &self.profiler }
    pub fn pattern_store(&self) -> &PatternStore { &self.patterns }
}

impl Clone for KeshavLearn {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            feedback: Arc::clone(&self.feedback),
            optimizer: Arc::clone(&self.optimizer),
            profiler: Arc::clone(&self.profiler),
            patterns: Arc::clone(&self.patterns),
            last_optimization: std::sync::RwLock::new(
                self.last_optimization.read().unwrap().clone()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keshav::pattern_store::{PatternType, PatternSource};

    fn make_learn() -> KeshavLearn {
        KeshavLearn::new(LearnConfig::default()).unwrap()
    }

    #[test]
    fn learn_enabled_by_default() {
        let learn = make_learn();
        assert!(learn.is_enabled());
    }

    #[test]
    fn disabled_instance_noops() {
        let learn = KeshavLearn::disabled().unwrap();
        assert!(!learn.is_enabled());

        // All operations should be no-ops.
        learn.report_false_positive("r1", "shield", "deny:x", "test", "admin");
        learn.observe_request("1.2.3.4", None, None, false, 50, None);
        assert_eq!(learn.feedback.stats().total_entries, 0);
        assert_eq!(learn.profiler.profile_count(), 0);
    }

    #[test]
    fn feedback_roundtrip() {
        let learn = make_learn();
        learn.report_false_positive("req-1", "shield", "deny:WAF", "benign", "admin");
        learn.report_false_negative("req-2", "threat", "allow", "malicious", "admin");
        let stats = learn.feedback.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.false_positives, 1);
        assert_eq!(stats.false_negatives, 1);
    }

    #[test]
    fn observe_and_assess() {
        let learn = make_learn();
        for _ in 0..10 {
            learn.observe_request("1.2.3.4", None, None, false, 50, Some("file_read"));
        }
        let assessment = learn.assess_anomaly("1.2.3.4");
        // With normal behavior, anomaly should be low.
        assert!(assessment.anomaly_score < 5.0);
    }

    #[test]
    fn threshold_defaults() {
        let learn = make_learn();
        assert_eq!(learn.deny_threshold("shield"), 9.0);
        assert_eq!(learn.challenge_threshold("shield"), 6.0);
        assert_eq!(learn.deny_threshold("threat"), 9.0);
    }

    #[test]
    fn pattern_add_and_search() {
        let learn = make_learn();
        learn.add_pattern(Pattern {
            id: "p1".to_string(),
            pattern_type: PatternType::Signature,
            name: "test pattern".to_string(),
            rings: vec!["threat".to_string()],
            pattern: "test".to_string(),
            priority: Default::default(),
            tags: vec!["jailbreak".to_string()],
            match_count: 0,
            true_positive_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_matched_at: None,
            active: true,
            confidence: 0.8,
            source: PatternSource::Manual,
        });
        assert_eq!(learn.patterns.count(), 1);
        let results = learn.search_patterns(Some("threat"), &["jailbreak"]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn status_report() {
        let learn = make_learn();
        let status = learn.status();
        assert!(status.enabled);
        assert_eq!(status.profiles_count, 0);
        assert_eq!(status.patterns_count, 0);
        assert_eq!(status.threshold_count, 9); // all 9 rings registered
    }

    #[test]
    fn reset_thresholds() {
        let learn = make_learn();
        // Submit enough FP feedback to trigger threshold change.
        for i in 0..10 {
            learn.report_false_positive(
                &format!("req-{}", i),
                "shield",
                "deny:WAF",
                "benign",
                "admin",
            );
        }
        learn.optimize_thresholds();
        let after_opt = learn.deny_threshold("shield");
        // Reset and verify back to default.
        learn.reset_thresholds();
        assert_eq!(learn.deny_threshold("shield"), 9.0);
        // The value after optimization may or may not have changed
        // depending on the optimization logic.
        let _ = after_opt;
    }

    #[test]
    fn clone_works() {
        let learn = make_learn();
        learn.report_false_positive("r1", "shield", "deny:x", "test", "admin");
        let cloned = learn.clone();
        assert_eq!(cloned.feedback.stats().total_entries, 1);
    }

    #[test]
    fn integration_full_loop() {
        let learn = make_learn();

        // 1. Observe behavior.
        for _ in 0..20 {
            learn.observe_request("10.0.0.1", Some("user-1"), None, false, 50, Some("file_read"));
        }

        // 2. Submit feedback.
        for i in 0..10 {
            learn.report_false_positive(
                &format!("req-fp-{}", i),
                "shield",
                "deny:WAF_PATTERN",
                "false positive — legitimate request",
                "admin",
            );
        }

        // 3. Add patterns.
        learn.add_pattern(Pattern {
            id: "learned-1".to_string(),
            pattern_type: PatternType::Learned,
            name: "Learned safe pattern".to_string(),
            rings: vec!["shield".to_string()],
            pattern: "safe_request_pattern".to_string(),
            priority: Default::default(),
            tags: vec!["learned".to_string()],
            match_count: 0,
            true_positive_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_matched_at: None,
            active: true,
            confidence: 0.5,
            source: PatternSource::Learned,
        });

        // 4. Run optimization.
        let results = learn.optimize_thresholds();

        // 5. Check status.
        let status = learn.status();
        assert!(status.enabled);
        assert_eq!(status.profiles_count, 2); // IP + User
        assert_eq!(status.patterns_count, 1);
        assert!(status.auto_optimize_pending == results.is_empty());
    }
}
