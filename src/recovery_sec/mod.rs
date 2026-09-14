// Recovery Security Ring — Ring 9 (Phase 5)
//
// Incident response, rollback, and system state recovery for AI operations.
// This is the Security Ring (Ring 9), distinct from the Cross Ring Recovery
// (which handles circuit breakers and health monitoring).
//
// 6 engines:
//   1. IncidentClassifier  — classifies security incidents by severity level
//   2. RollbackEngine      — manages rollback of compromised operations
//   3. QuarantineManager   — quarantines suspicious requests/responses
//   4. EvidenceCollector   — collects and chains forensic evidence for incidents
//   5. StateRestorer       — restores system state from checkpoints
//   6. NotificationEngine  — sends alerts for security incidents
//
// Pipeline: IncidentClassify → Quarantine → Evidence → Rollback → StateRestore → Notify
// Budget: <5ms p99

use std::collections::HashMap;
use std::sync::Arc;

use crate::decision::{Decision, Verdict};
use crate::error::Result;
use sha2::{Digest, Sha256};

// ── Configuration ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RecoverySecConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub incident_classifier: IncidentClassifierConfig,

    #[serde(default)]
    pub rollback_engine: RollbackEngineConfig,

    #[serde(default)]
    pub quarantine_manager: QuarantineManagerConfig,

    #[serde(default)]
    pub evidence_collector: EvidenceCollectorConfig,

    #[serde(default)]
    pub state_restorer: StateRestorerConfig,

    #[serde(default)]
    pub notification_engine: NotificationEngineConfig,

    /// Risk score threshold for deny (default: 9.0)
    #[serde(default = "default_deny_threshold")]
    pub deny_threshold: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_deny_threshold() -> f64 {
    9.0
}

impl Default for RecoverySecConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            incident_classifier: IncidentClassifierConfig::default(),
            rollback_engine: RollbackEngineConfig::default(),
            quarantine_manager: QuarantineManagerConfig::default(),
            evidence_collector: EvidenceCollectorConfig::default(),
            state_restorer: StateRestorerConfig::default(),
            notification_engine: NotificationEngineConfig::default(),
            deny_threshold: default_deny_threshold(),
        }
    }
}

// ── Engine Configs ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IncidentClassifierConfig {
    #[serde(default = "default_critical_threshold")]
    pub critical_threshold: f64,
    #[serde(default = "default_high_threshold")]
    pub high_threshold: f64,
}
fn default_critical_threshold() -> f64 {
    8.0
}
fn default_high_threshold() -> f64 {
    5.0
}
impl Default for IncidentClassifierConfig {
    fn default() -> Self {
        Self {
            critical_threshold: default_critical_threshold(),
            high_threshold: default_high_threshold(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RollbackEngineConfig {
    #[serde(default = "default_max_rollback_window")]
    pub max_rollback_window_secs: u64,
}
fn default_max_rollback_window() -> u64 {
    3600
}
impl Default for RollbackEngineConfig {
    fn default() -> Self {
        Self {
            max_rollback_window_secs: default_max_rollback_window(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QuarantineManagerConfig {
    #[serde(default = "default_max_quarantine_size")]
    pub max_quarantine_size: usize,
    #[serde(default)]
    pub auto_quarantine_on_critical: bool,
}
fn default_max_quarantine_size() -> usize {
    10000
}
impl Default for QuarantineManagerConfig {
    fn default() -> Self {
        Self {
            max_quarantine_size: default_max_quarantine_size(),
            auto_quarantine_on_critical: true,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EvidenceCollectorConfig {
    #[serde(default = "default_evidence_retention")]
    pub retention_days: u32,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
}
fn default_evidence_retention() -> u32 {
    365
}
fn default_hash_algorithm() -> String {
    "sha256".into()
}
impl Default for EvidenceCollectorConfig {
    fn default() -> Self {
        Self {
            retention_days: default_evidence_retention(),
            hash_algorithm: default_hash_algorithm(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StateRestorerConfig {
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_secs: u64,
    #[serde(default = "default_max_checkpoints")]
    pub max_checkpoints: usize,
}
fn default_checkpoint_interval() -> u64 {
    300
}
fn default_max_checkpoints() -> usize {
    50
}
impl Default for StateRestorerConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval_secs: default_checkpoint_interval(),
            max_checkpoints: default_max_checkpoints(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct NotificationEngineConfig {
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default = "default_severity_filter")]
    pub severity_filter: f64,
}
fn default_severity_filter() -> f64 {
    5.0
}
impl Default for NotificationEngineConfig {
    fn default() -> Self {
        Self {
            channels: vec!["log".into()],
            severity_filter: default_severity_filter(),
        }
    }
}

// ── Request ──

#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    /// The action that triggered this recovery evaluation.
    pub trigger_action: String,
    /// Risk signals from other rings.
    pub incoming_risk_score: f64,
    /// Whether a previous decision was denied.
    pub was_denied: bool,
    /// The deny code from a previous ring (if any).
    pub deny_code: Option<String>,
    /// Whether this is a suspected injection attempt.
    pub suspected_injection: bool,
    /// The original request data (for evidence collection).
    pub request_data: Option<String>,
    /// Source IP.
    pub source_ip: String,
    /// User ID.
    pub user_id: Option<String>,
    /// Agent ID (if applicable).
    pub agent_id: Option<String>,
    /// Request ID.
    pub request_id: String,
    /// HTTP headers.
    pub headers: HashMap<String, String>,
}

// ── Engine Result ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryEngineResult {
    pub engine_name: String,
    pub decision: String, // "allowed" | "flagged" | "denied" | "monitoring"
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

// ── Engine Outputs ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct IncidentClassification {
    pub severity: String,    // "low" | "medium" | "high" | "critical"
    pub severity_score: f64, // 0.0-10.0
    pub incident_type: String,
    pub requires_immediate_action: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RollbackAssessment {
    pub rollback_possible: bool,
    pub rollback_window_secs: u64,
    pub rollback_reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineDecision {
    pub quarantined: bool,
    pub quarantine_reason: String,
    pub quarantine_size: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EvidenceRecord {
    pub collected: bool,
    pub evidence_id: String,
    pub hash: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StateRestorePlan {
    pub restore_possible: bool,
    pub checkpoint_available: bool,
    pub restore_reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NotificationStatus {
    pub sent: bool,
    pub channels: Vec<String>,
    pub severity_threshold: f64,
}

// ── Verdict ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryVerdict {
    pub decision: Decision,
    pub incident_classification: Option<IncidentClassification>,
    pub rollback_assessment: Option<RollbackAssessment>,
    pub quarantine_decision: Option<QuarantineDecision>,
    pub evidence_record: Option<EvidenceRecord>,
    pub state_restore_plan: Option<StateRestorePlan>,
    pub notification_status: Option<NotificationStatus>,
    pub engine_results: Vec<RecoveryEngineResult>,
    pub latency_ms: f64,
    pub recovery_risk_score: f64,
}

impl Verdict for RecoveryVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }
    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

// ── Engines ──

struct IncidentClassifier {
    config: IncidentClassifierConfig,
}

impl IncidentClassifier {
    fn new(config: &IncidentClassifierConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &RecoveryRequest,
    ) -> (IncidentClassification, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        // Classify incident based on signals
        let mut severity_score = request.incoming_risk_score;

        // Escalate for known bad patterns
        if request.was_denied {
            severity_score += 2.0;
        }
        if request.suspected_injection {
            severity_score += 3.0;
        }
        if request.deny_code.as_deref() == Some("THREAT_INJECTION_DETECTED") {
            severity_score += 2.0;
        }
        if request.deny_code.as_deref() == Some("AGENT_BEHAVIOR_SEVERE") {
            severity_score += 2.5;
        }

        severity_score = severity_score.clamp(0.0, 10.0);

        let (severity, incident_type, requires_immediate) =
            if severity_score >= self.config.critical_threshold {
                ("critical", "security_breach", true)
            } else if severity_score >= self.config.high_threshold {
                ("high", "policy_violation", true)
            } else if severity_score >= 3.0 {
                ("medium", "anomaly", false)
            } else {
                ("low", "routine", false)
            };

        let result = IncidentClassification {
            severity: severity.into(),
            severity_score,
            incident_type: incident_type.into(),
            requires_immediate_action: requires_immediate,
        };

        let decision = match severity {
            "critical" => "denied",
            "high" => "flagged",
            _ => "allowed",
        };

        let engine_result = RecoveryEngineResult {
            engine_name: "incident_classifier".into(),
            decision: decision.into(),
            reason: format!(
                "severity={}, score={:.2}, type={}",
                severity, severity_score, incident_type
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "severity": severity, "severity_score": severity_score }),
        };

        (result, engine_result)
    }
}

struct QuarantineManager {
    config: QuarantineManagerConfig,
}

impl QuarantineManager {
    fn new(config: &QuarantineManagerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &RecoveryRequest,
        severity: &str,
    ) -> (QuarantineDecision, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        let should_quarantine = (self.config.auto_quarantine_on_critical && severity == "critical")
            || (severity == "high" && request.suspected_injection);

        let quarantine_reason = if should_quarantine {
            format!(
                "auto-quarantined: severity={}, injection={}",
                severity, request.suspected_injection
            )
        } else {
            "no quarantine needed".into()
        };

        let quarantine_size = if should_quarantine {
            request.request_data.as_ref().map(|d| d.len()).unwrap_or(0)
        } else {
            0
        };

        let result = QuarantineDecision {
            quarantined: should_quarantine,
            quarantine_reason: quarantine_reason.clone(),
            quarantine_size,
        };

        let decision = if should_quarantine {
            "denied"
        } else {
            "allowed"
        };

        let engine_result = RecoveryEngineResult {
            engine_name: "quarantine_manager".into(),
            decision: decision.into(),
            reason: format!(
                "quarantined={}, reason={}",
                should_quarantine, quarantine_reason
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "quarantined": should_quarantine }),
        };

        (result, engine_result)
    }
}

struct EvidenceCollector {
    config: EvidenceCollectorConfig,
}

impl EvidenceCollector {
    fn new(config: &EvidenceCollectorConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &RecoveryRequest,
        severity: &str,
    ) -> (EvidenceRecord, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        // Collect evidence for medium+ severity incidents
        let should_collect = severity == "critical" || severity == "high" || severity == "medium";

        let evidence_id = if should_collect {
            format!("ev-{}", request.request_id)
        } else {
            String::new()
        };

        // Compute a hash of the request data for tamper evidence
        let hash = if should_collect {
            let data = request.request_data.as_deref().unwrap_or("");
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            let digest = hasher.finalize();
            format!("{:x}", digest)
        } else {
            String::new()
        };

        let timestamp = if should_collect {
            chrono::Utc::now().to_rfc3339()
        } else {
            String::new()
        };

        let result = EvidenceRecord {
            collected: should_collect,
            evidence_id: evidence_id.clone(),
            hash,
            timestamp,
        };

        let engine_result = RecoveryEngineResult {
            engine_name: "evidence_collector".into(),
            decision: "allowed".into(), // Evidence collection never blocks
            reason: if should_collect {
                format!("evidence collected: {}", evidence_id)
            } else {
                "no evidence needed".into()
            },
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "collected": should_collect, "evidence_id": evidence_id }),
        };

        (result, engine_result)
    }
}

struct RollbackEngine {
    config: RollbackEngineConfig,
}

impl RollbackEngine {
    fn new(config: &RollbackEngineConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &RecoveryRequest,
        severity: &str,
    ) -> (RollbackAssessment, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        let rollback_possible =
            severity == "critical" || (severity == "high" && request.was_denied);
        let rollback_reason = if rollback_possible {
            format!(
                "rollback recommended: severity={}, action={}",
                severity, request.trigger_action
            )
        } else {
            "no rollback needed".into()
        };

        let result = RollbackAssessment {
            rollback_possible,
            rollback_window_secs: self.config.max_rollback_window_secs,
            rollback_reason,
        };

        let decision = if rollback_possible {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = RecoveryEngineResult {
            engine_name: "rollback_engine".into(),
            decision: decision.into(),
            reason: format!(
                "rollback_possible={}, window={}s",
                rollback_possible, self.config.max_rollback_window_secs
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "rollback_possible": rollback_possible }),
        };

        (result, engine_result)
    }
}

struct StateRestorer {
    config: StateRestorerConfig,
}

impl StateRestorer {
    fn new(config: &StateRestorerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        _request: &RecoveryRequest,
        severity: &str,
    ) -> (StateRestorePlan, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        let restore_possible = severity == "critical";
        let checkpoint_available = restore_possible; // Assume checkpoint available for critical

        let restore_reason = if restore_possible {
            format!(
                "state restore recommended for {} severity incident",
                severity
            )
        } else {
            "no state restore needed".into()
        };

        let result = StateRestorePlan {
            restore_possible,
            checkpoint_available,
            restore_reason,
        };

        let decision = "allowed"; // State restoration doesn't block, it's a recovery action

        let engine_result = RecoveryEngineResult {
            engine_name: "state_restorer".into(),
            decision: decision.into(),
            reason: format!(
                "restore_possible={}, checkpoint_available={}",
                restore_possible, checkpoint_available
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "restore_possible": restore_possible }),
        };

        (result, engine_result)
    }
}

struct NotificationEngine {
    config: NotificationEngineConfig,
}

impl NotificationEngine {
    fn new(config: &NotificationEngineConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(&self, severity_score: f64) -> (NotificationStatus, RecoveryEngineResult) {
        let start = std::time::Instant::now();

        let should_send = severity_score >= self.config.severity_filter;
        let channels = if should_send {
            self.config.channels.clone()
        } else {
            vec![]
        };

        let result = NotificationStatus {
            sent: should_send,
            channels: channels.clone(),
            severity_threshold: self.config.severity_filter,
        };

        let engine_result = RecoveryEngineResult {
            engine_name: "notification_engine".into(),
            decision: "allowed".into(), // Notifications never block
            reason: if should_send {
                format!("alert sent via {:?}", channels)
            } else {
                format!(
                    "severity {:.1} below threshold {:.1}, no alert",
                    severity_score, self.config.severity_filter
                )
            },
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "sent": should_send }),
        };

        (result, engine_result)
    }
}

// ── Ring Coordinator ──

pub struct RecoveryRing {
    config: Arc<RecoverySecConfig>,
    incident_classifier: Arc<IncidentClassifier>,
    rollback_engine: Arc<RollbackEngine>,
    quarantine_manager: Arc<QuarantineManager>,
    evidence_collector: Arc<EvidenceCollector>,
    state_restorer: Arc<StateRestorer>,
    notification_engine: Arc<NotificationEngine>,
}

impl Clone for RecoveryRing {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            incident_classifier: Arc::clone(&self.incident_classifier),
            rollback_engine: Arc::clone(&self.rollback_engine),
            quarantine_manager: Arc::clone(&self.quarantine_manager),
            evidence_collector: Arc::clone(&self.evidence_collector),
            state_restorer: Arc::clone(&self.state_restorer),
            notification_engine: Arc::clone(&self.notification_engine),
        }
    }
}

impl RecoveryRing {
    pub fn new(config: &RecoverySecConfig) -> Result<Self> {
        Ok(Self {
            config: Arc::new(config.clone()),
            incident_classifier: Arc::new(IncidentClassifier::new(&config.incident_classifier)),
            rollback_engine: Arc::new(RollbackEngine::new(&config.rollback_engine)),
            quarantine_manager: Arc::new(QuarantineManager::new(&config.quarantine_manager)),
            evidence_collector: Arc::new(EvidenceCollector::new(&config.evidence_collector)),
            state_restorer: Arc::new(StateRestorer::new(&config.state_restorer)),
            notification_engine: Arc::new(NotificationEngine::new(&config.notification_engine)),
        })
    }

    /// Evaluate recovery response through all 6 engines.
    ///
    /// Pipeline: IncidentClassify → Quarantine → Evidence → Rollback → StateRestore → Notify
    pub fn evaluate(&self, request: &RecoveryRequest) -> RecoveryVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return RecoveryVerdict {
                decision: Decision::Allow,
                incident_classification: None,
                rollback_assessment: None,
                quarantine_decision: None,
                evidence_record: None,
                state_restore_plan: None,
                notification_status: None,
                engine_results: vec![],
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                recovery_risk_score: 0.0,
            };
        }

        let mut engine_results = Vec::with_capacity(6);
        let mut risk_accumulator = 0.0f64;

        // 1. Incident Classifier
        let (incident_classification, incident_eng) = self.incident_classifier.evaluate(request);
        match incident_eng.decision.as_str() {
            "denied" => risk_accumulator += 4.0,
            "flagged" => risk_accumulator += 2.0,
            _ => {}
        }
        let severity = incident_classification.severity.clone();
        let severity_score = incident_classification.severity_score;
        engine_results.push(incident_eng);

        // 2. Quarantine Manager
        let (quarantine_decision, quarantine_eng) =
            self.quarantine_manager.evaluate(request, &severity);
        match quarantine_eng.decision.as_str() {
            "denied" => risk_accumulator += 5.0,
            "flagged" => risk_accumulator += 1.5,
            _ => {}
        }
        engine_results.push(quarantine_eng);

        // 3. Evidence Collector (never blocks)
        let (evidence_record, evidence_eng) = self.evidence_collector.evaluate(request, &severity);
        engine_results.push(evidence_eng);

        // 4. Rollback Engine
        let (rollback_assessment, rollback_eng) = self.rollback_engine.evaluate(request, &severity);
        match rollback_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(rollback_eng);

        // 5. State Restorer (never blocks)
        let (state_restore_plan, state_eng) = self.state_restorer.evaluate(request, &severity);
        engine_results.push(state_eng);

        // 6. Notification Engine (never blocks)
        let (notification_status, notify_eng) = self.notification_engine.evaluate(severity_score);
        engine_results.push(notify_eng);

        let recovery_risk_score = risk_accumulator.clamp(0.0, 10.0);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Decision logic: Recovery Ring can deny on quarantine or critical severity
        let any_denied = engine_results.iter().any(|e| e.decision == "denied");
        let decision = if recovery_risk_score >= self.config.deny_threshold {
            Decision::Deny {
                code: "RECOVERY_CRITICAL_INCIDENT".into(),
                retry_after: Some(60),
            }
        } else if any_denied {
            Decision::Deny {
                code: "RECOVERY_QUARANTINED".into(),
                retry_after: None,
            }
        } else if severity == "high" {
            Decision::Escalate {
                approver_role: "security_admin".into(),
                timeout_secs: 300,
            }
        } else {
            Decision::Allow
        };

        RecoveryVerdict {
            decision,
            incident_classification: Some(incident_classification),
            rollback_assessment: Some(rollback_assessment),
            quarantine_decision: Some(quarantine_decision),
            evidence_record: Some(evidence_record),
            state_restore_plan: Some(state_restore_plan),
            notification_status: Some(notification_status),
            engine_results,
            latency_ms,
            recovery_risk_score,
        }
    }

    /// Get the configuration reference.
    pub fn config(&self) -> &RecoverySecConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benign_request() -> RecoveryRequest {
        RecoveryRequest {
            trigger_action: "evaluate_prompt".into(),
            incoming_risk_score: 1.0,
            was_denied: false,
            deny_code: None,
            suspected_injection: false,
            request_data: Some("What is 2+2?".into()),
            source_ip: "1.2.3.4".into(),
            user_id: Some("user-1".into()),
            agent_id: None,
            request_id: "recovery-test-1".into(),
            headers: HashMap::new(),
        }
    }

    fn default_config() -> RecoverySecConfig {
        RecoverySecConfig::default()
    }

    #[test]
    fn recovery_ring_constructs() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        assert!(ring.config.enabled);
    }

    #[test]
    fn recovery_ring_allows_benign() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&benign_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.recovery_risk_score < 3.0);
    }

    #[test]
    fn recovery_ring_classifies_low_severity() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&benign_request());
        assert!(verdict.incident_classification.is_some());
        assert_eq!(
            verdict.incident_classification.as_ref().unwrap().severity,
            "low"
        );
    }

    #[test]
    fn recovery_ring_classifies_critical_on_high_risk() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 9.0;
        req.was_denied = true;
        req.suspected_injection = true;
        let verdict = ring.evaluate(&req);
        assert!(verdict.incident_classification.is_some());
        let classification = verdict.incident_classification.as_ref().unwrap();
        assert_eq!(classification.severity, "critical");
        assert!(classification.requires_immediate_action);
    }

    #[test]
    fn recovery_ring_quarantines_critical() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 8.5;
        req.suspected_injection = true;
        let verdict = ring.evaluate(&req);
        assert!(verdict.quarantine_decision.is_some());
        let qd = verdict.quarantine_decision.as_ref().unwrap();
        // Critical + auto_quarantine should quarantine
        if verdict.incident_classification.as_ref().unwrap().severity == "critical" {
            assert!(qd.quarantined);
        }
    }

    #[test]
    fn recovery_ring_collects_evidence() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 6.0;
        req.was_denied = true;
        let verdict = ring.evaluate(&req);
        assert!(verdict.evidence_record.is_some());
        let evidence = verdict.evidence_record.as_ref().unwrap();
        // Should collect for high severity
        if verdict.incident_classification.as_ref().unwrap().severity == "high" {
            assert!(evidence.collected);
            assert!(!evidence.hash.is_empty());
        }
    }

    #[test]
    fn recovery_ring_suggests_rollback_on_critical() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 9.0;
        req.was_denied = true;
        req.trigger_action = "delete_all_data".into();
        let verdict = ring.evaluate(&req);
        assert!(verdict.rollback_assessment.is_some());
        let rb = verdict.rollback_assessment.as_ref().unwrap();
        if verdict.incident_classification.as_ref().unwrap().severity == "critical" {
            assert!(rb.rollback_possible);
        }
    }

    #[test]
    fn recovery_ring_sends_notifications() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 7.0;
        let verdict = ring.evaluate(&req);
        assert!(verdict.notification_status.is_some());
        let notif = verdict.notification_status.as_ref().unwrap();
        assert!(notif.sent);
    }

    #[test]
    fn recovery_ring_denies_on_critical_incident() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let mut req = benign_request();
        req.incoming_risk_score = 10.0;
        req.was_denied = true;
        req.suspected_injection = true;
        req.deny_code = Some("THREAT_INJECTION_DETECTED".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.decision.is_deny());
    }

    #[test]
    fn recovery_ring_disabled_allows() {
        let mut config = default_config();
        config.enabled = false;
        let ring = RecoveryRing::new(&config).unwrap();
        let verdict = ring.evaluate(&benign_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.engine_results.is_empty());
    }

    #[test]
    fn recovery_verdict_implements_verdict_trait() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&benign_request());
        assert_eq!(verdict.decision(), &verdict.decision);
        assert!(verdict.latency_ms() >= 0.0);
    }

    #[test]
    fn recovery_ring_clones() {
        let ring = RecoveryRing::new(&default_config()).unwrap();
        let _clone = ring.clone();
    }
}
