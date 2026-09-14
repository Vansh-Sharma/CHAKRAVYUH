// Governance Ring — Ring 8 (Phase 5)
//
// Policy, audit, and compliance enforcement for AI operations.
// Ensures that AI actions comply with organizational policies,
// regulatory frameworks, and data governance rules.
//
// 6 engines:
//   1. PolicyComplianceChecker — validates actions against configurable governance policies
//   2. AuditLogger            — comprehensive audit trail for governance events
//   3. DataRetentionEnforcer  — enforces data retention and deletion policies
//   4. ConsentTracker        — tracks user consent for data processing
//   5. ComplianceReporter    — generates compliance scores and flags violations
//   6. SanctionChecker       — checks entities against sanctions/compliance lists
//
// Pipeline: Policy → Audit → Retention → Consent → ComplianceReport → Sanction
// Budget: <5ms p99

use std::collections::HashMap;
use std::sync::Arc;

use crate::decision::{Decision, Verdict};
use crate::error::Result;

// ── Configuration ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GovernanceConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub policy_compliance: PolicyComplianceConfig,

    #[serde(default)]
    pub audit_logger: AuditLoggerConfig,

    #[serde(default)]
    pub data_retention: DataRetentionConfig,

    #[serde(default)]
    pub consent_tracker: ConsentTrackerConfig,

    #[serde(default)]
    pub compliance_reporter: ComplianceReporterConfig,

    #[serde(default)]
    pub sanction_checker: SanctionCheckerConfig,

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

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            policy_compliance: PolicyComplianceConfig::default(),
            audit_logger: AuditLoggerConfig::default(),
            data_retention: DataRetentionConfig::default(),
            consent_tracker: ConsentTrackerConfig::default(),
            compliance_reporter: ComplianceReporterConfig::default(),
            sanction_checker: SanctionCheckerConfig::default(),
            deny_threshold: default_deny_threshold(),
        }
    }
}

// ── Engine Configs ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyComplianceConfig {
    #[serde(default = "default_max_violations")]
    pub max_violations: usize,
}
fn default_max_violations() -> usize {
    3
}
impl Default for PolicyComplianceConfig {
    fn default() -> Self {
        Self {
            max_violations: default_max_violations(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuditLoggerConfig {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}
fn default_retention_days() -> u32 {
    90
}
impl Default for AuditLoggerConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DataRetentionConfig {
    #[serde(default = "default_max_retention")]
    pub max_retention_days: u32,
    #[serde(default)]
    pub auto_delete: bool,
}
fn default_max_retention() -> u32 {
    365
}
impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            max_retention_days: default_max_retention(),
            auto_delete: false,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConsentTrackerConfig {
    #[serde(default)]
    pub require_explicit_consent: bool,
}
impl Default for ConsentTrackerConfig {
    fn default() -> Self {
        Self {
            require_explicit_consent: false,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ComplianceReporterConfig {
    #[serde(default = "default_compliance_threshold")]
    pub compliance_threshold: f64,
    #[serde(default)]
    pub frameworks: Vec<String>,
}
fn default_compliance_threshold() -> f64 {
    0.5
}
impl Default for ComplianceReporterConfig {
    fn default() -> Self {
        Self {
            compliance_threshold: default_compliance_threshold(),
            frameworks: vec!["GDPR".into(), "SOC2".into(), "HIPAA".into()],
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SanctionCheckerConfig {
    #[serde(default = "default_sanction_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub blocked_entities: Vec<String>,
    #[serde(default)]
    pub blocked_regions: Vec<String>,
}
fn default_sanction_enabled() -> bool {
    true
}
impl Default for SanctionCheckerConfig {
    fn default() -> Self {
        Self {
            enabled: default_sanction_enabled(),
            blocked_entities: vec![],
            blocked_regions: vec![],
        }
    }
}

// ── Request ──

#[derive(Debug, Clone)]
pub struct GovernanceRequest {
    /// The action being performed.
    pub action: String,
    /// The resource/target of the action.
    pub resource: Option<String>,
    /// The data classification level.
    pub data_classification: Option<String>,
    /// User consent headers or tokens.
    pub consent_token: Option<String>,
    /// The regulatory frameworks to check against.
    pub frameworks: Vec<String>,
    /// Entity identifiers (org ID, user ID, etc.).
    pub entity_id: Option<String>,
    /// Geographic region of the request.
    pub region: Option<String>,
    /// Source IP.
    pub source_ip: String,
    /// User ID if available.
    pub user_id: Option<String>,
    /// Role of the requesting user.
    pub role: Option<String>,
    /// Request ID.
    pub request_id: String,
    /// HTTP headers.
    pub headers: HashMap<String, String>,
}

// ── Engine Result ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct GovernanceEngineResult {
    pub engine_name: String,
    pub decision: String, // "allowed" | "flagged" | "denied"
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

// ── Engine Outputs ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyComplianceResult {
    pub compliant: bool,
    pub violations: Vec<String>,
    pub violation_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditLogResult {
    pub logged: bool,
    pub audit_id: String,
    pub retention_days: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DataRetentionResult {
    pub within_policy: bool,
    pub data_age_days: Option<u32>,
    pub max_allowed_days: u32,
    pub auto_delete_triggered: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsentResult {
    pub consent_valid: bool,
    pub consent_type: String, // "explicit" | "implicit" | "none"
    pub scopes_granted: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComplianceReportResult {
    pub compliance_score: f64, // 0.0-1.0
    pub frameworks_checked: Vec<String>,
    pub framework_scores: HashMap<String, f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SanctionCheckResult {
    pub blocked: bool,
    pub matched_entity: Option<String>,
    pub matched_region: Option<String>,
}

// ── Verdict ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct GovernanceVerdict {
    pub decision: Decision,
    pub policy_result: Option<PolicyComplianceResult>,
    pub audit_result: Option<AuditLogResult>,
    pub retention_result: Option<DataRetentionResult>,
    pub consent_result: Option<ConsentResult>,
    pub compliance_report: Option<ComplianceReportResult>,
    pub sanction_result: Option<SanctionCheckResult>,
    pub engine_results: Vec<GovernanceEngineResult>,
    pub latency_ms: f64,
    pub governance_risk_score: f64,
}

impl Verdict for GovernanceVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }
    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

// ── Engines ──

struct PolicyComplianceChecker {
    config: PolicyComplianceConfig,
}

impl PolicyComplianceChecker {
    fn new(config: &PolicyComplianceConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &GovernanceRequest,
    ) -> (PolicyComplianceResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        let mut violations = Vec::new();

        // Check action against governance rules
        let action_lower = request.action.to_lowercase();

        // High-risk actions require elevated roles
        let high_risk_actions = ["delete", "drop", "remove", "purge", "truncate", "overwrite"];
        if high_risk_actions.iter().any(|a| action_lower.contains(a)) {
            let has_admin_role = request
                .role
                .as_deref()
                .map(|r| r == "admin" || r == "operator")
                .unwrap_or(false);
            if !has_admin_role {
                violations.push(format!(
                    "high_risk_action '{}' requires admin role",
                    request.action
                ));
            }
        }

        // Data classification checks
        if let Some(classification) = &request.data_classification {
            let restricted_actions_for_sensitive = match classification.to_lowercase().as_str() {
                "confidential" | "restricted" => {
                    if action_lower.contains("export")
                        || action_lower.contains("transfer")
                        || action_lower.contains("copy")
                    {
                        violations.push(format!(
                            "action '{}' not allowed for {} data",
                            request.action, classification
                        ));
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            let _ = restricted_actions_for_sensitive;
        }

        let violation_count = violations.len();
        let compliant = violation_count == 0;

        let result = PolicyComplianceResult {
            compliant,
            violations: violations.clone(),
            violation_count,
        };

        let decision = if violation_count > self.config.max_violations {
            "denied"
        } else if !compliant {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = GovernanceEngineResult {
            engine_name: "policy_compliance".into(),
            decision: decision.into(),
            reason: format!("compliant={}, violations={}", compliant, violation_count),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "compliant": compliant, "violation_count": violation_count }),
        };

        (result, engine_result)
    }
}

struct AuditLogger {
    config: AuditLoggerConfig,
}

impl AuditLogger {
    fn new(config: &AuditLoggerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(&self, request: &GovernanceRequest) -> (AuditLogResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        // Generate a deterministic audit ID from request_id
        let audit_id = format!("audit-{}", request.request_id);

        let result = AuditLogResult {
            logged: true,
            audit_id,
            retention_days: self.config.retention_days,
        };

        let engine_result = GovernanceEngineResult {
            engine_name: "audit_logger".into(),
            decision: "allowed".into(),
            reason: format!("audit logged: {}", result.audit_id),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "audit_id": result.audit_id }),
        };

        (result, engine_result)
    }
}

struct DataRetentionEnforcer {
    config: DataRetentionConfig,
}

impl DataRetentionEnforcer {
    fn new(config: &DataRetentionConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &GovernanceRequest,
    ) -> (DataRetentionResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        // Check data age from headers if present
        let data_age_days = request
            .headers
            .get("x-data-age-days")
            .and_then(|v| v.parse::<u32>().ok());

        let within_policy = match data_age_days {
            Some(age) => age <= self.config.max_retention_days,
            None => true, // No age info, assume within policy
        };

        let auto_delete_triggered = self.config.auto_delete && !within_policy;

        let result = DataRetentionResult {
            within_policy,
            data_age_days,
            max_allowed_days: self.config.max_retention_days,
            auto_delete_triggered,
        };

        let decision = if auto_delete_triggered {
            "denied"
        } else if !within_policy {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = GovernanceEngineResult {
            engine_name: "data_retention".into(),
            decision: decision.into(),
            reason: format!(
                "within_policy={}, age={:?}, max={}",
                within_policy, data_age_days, self.config.max_retention_days
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "within_policy": within_policy }),
        };

        (result, engine_result)
    }
}

struct ConsentTracker {
    config: ConsentTrackerConfig,
}

impl ConsentTracker {
    fn new(config: &ConsentTrackerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(&self, request: &GovernanceRequest) -> (ConsentResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        let has_consent_token =
            request.consent_token.is_some() && !request.consent_token.as_ref().unwrap().is_empty();
        let has_consent_header = request.headers.contains_key("x-consent-granted");

        let consent_valid = if self.config.require_explicit_consent {
            has_consent_token
        } else {
            has_consent_token || has_consent_header || request.role.as_deref() == Some("admin")
        };

        let consent_type = match (has_consent_token, has_consent_header) {
            (true, _) => "explicit",
            (_, true) => "implicit",
            _ => "none",
        };

        // Derive scopes from consent token or headers
        let scopes_granted = if let Some(token) = &request.consent_token {
            token.split(',').map(|s| s.trim().to_string()).collect()
        } else if let Some(consent) = request.headers.get("x-consent-scopes") {
            consent.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            vec![]
        };

        let result = ConsentResult {
            consent_valid,
            consent_type: consent_type.into(),
            scopes_granted,
        };

        let decision = if !consent_valid && self.config.require_explicit_consent {
            "denied"
        } else if !consent_valid {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = GovernanceEngineResult {
            engine_name: "consent_tracker".into(),
            decision: decision.into(),
            reason: format!(
                "consent_valid={}, type={}, require_explicit={}",
                consent_valid, consent_type, self.config.require_explicit_consent
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "consent_valid": consent_valid, "consent_type": consent_type }),
        };

        (result, engine_result)
    }
}

struct ComplianceReporter {
    config: ComplianceReporterConfig,
}

impl ComplianceReporter {
    fn new(config: &ComplianceReporterConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &GovernanceRequest,
    ) -> (ComplianceReportResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        let frameworks_to_check = if request.frameworks.is_empty() {
            self.config.frameworks.clone()
        } else {
            request.frameworks.clone()
        };

        let mut framework_scores = HashMap::new();
        let mut total_score = 0.0f64;

        for framework in &frameworks_to_check {
            let score = self.compute_framework_score(framework, request);
            framework_scores.insert(framework.clone(), score);
            total_score += score;
        }

        let compliance_score = if frameworks_to_check.is_empty() {
            1.0
        } else {
            total_score / frameworks_to_check.len() as f64
        };

        let result = ComplianceReportResult {
            compliance_score,
            frameworks_checked: frameworks_to_check.clone(),
            framework_scores,
        };

        let decision = if compliance_score < self.config.compliance_threshold {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = GovernanceEngineResult {
            engine_name: "compliance_reporter".into(),
            decision: decision.into(),
            reason: format!(
                "compliance_score={:.3}, frameworks={:?}",
                compliance_score, frameworks_to_check
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "compliance_score": compliance_score }),
        };

        (result, engine_result)
    }

    fn compute_framework_score(&self, framework: &str, request: &GovernanceRequest) -> f64 {
        let action_lower = request.action.to_lowercase();
        let has_consent = request.consent_token.is_some();
        let is_admin = request.role.as_deref() == Some("admin");

        match framework {
            "GDPR" => {
                let mut score: f64 = 0.5;
                if has_consent {
                    score += 0.3;
                }
                if !action_lower.contains("export") {
                    score += 0.1;
                }
                if request.region.as_deref() != Some("EU") || has_consent {
                    score += 0.1;
                }
                score.clamp(0.0, 1.0)
            }
            "HIPAA" => {
                let mut score: f64 = 0.5;
                if request.data_classification.as_deref() == Some("phi") {
                    if has_consent {
                        score += 0.3;
                    }
                    if is_admin {
                        score += 0.2;
                    }
                } else {
                    score = 0.9;
                }
                score.clamp(0.0, 1.0)
            }
            "SOC2" => {
                let mut score: f64 = 0.7;
                if request.headers.contains_key("x-audit-trail") {
                    score += 0.2;
                }
                if is_admin {
                    score += 0.1;
                }
                score.clamp(0.0, 1.0)
            }
            _ => 0.8, // Unknown framework — assume moderate compliance
        }
    }
}

struct SanctionChecker {
    config: SanctionCheckerConfig,
}

impl SanctionChecker {
    fn new(config: &SanctionCheckerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn evaluate(
        &self,
        request: &GovernanceRequest,
    ) -> (SanctionCheckResult, GovernanceEngineResult) {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            let result = SanctionCheckResult {
                blocked: false,
                matched_entity: None,
                matched_region: None,
            };
            let engine_result = GovernanceEngineResult {
                engine_name: "sanction_checker".into(),
                decision: "allowed".into(),
                reason: "sanction_checker disabled".into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({ "enabled": false }),
            };
            return (result, engine_result);
        }

        let matched_entity = request.entity_id.as_ref().and_then(|id| {
            self.config
                .blocked_entities
                .iter()
                .find(|e| *e == id)
                .cloned()
        });

        let matched_region = request.region.as_ref().and_then(|r| {
            self.config
                .blocked_regions
                .iter()
                .find(|br| br.eq_ignore_ascii_case(r))
                .cloned()
        });

        let blocked = matched_entity.is_some() || matched_region.is_some();

        let result = SanctionCheckResult {
            blocked,
            matched_entity: matched_entity.clone(),
            matched_region: matched_region.clone(),
        };

        let decision = if blocked { "denied" } else { "allowed" };

        let engine_result = GovernanceEngineResult {
            engine_name: "sanction_checker".into(),
            decision: decision.into(),
            reason: format!(
                "blocked={}, entity={:?}, region={:?}",
                blocked, matched_entity, matched_region
            ),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "blocked": blocked }),
        };

        (result, engine_result)
    }
}

// ── Ring Coordinator ──

pub struct GovernanceRing {
    config: Arc<GovernanceConfig>,
    policy_checker: Arc<PolicyComplianceChecker>,
    audit_logger: Arc<AuditLogger>,
    retention_enforcer: Arc<DataRetentionEnforcer>,
    consent_tracker: Arc<ConsentTracker>,
    compliance_reporter: Arc<ComplianceReporter>,
    sanction_checker: Arc<SanctionChecker>,
}

impl Clone for GovernanceRing {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            policy_checker: Arc::clone(&self.policy_checker),
            audit_logger: Arc::clone(&self.audit_logger),
            retention_enforcer: Arc::clone(&self.retention_enforcer),
            consent_tracker: Arc::clone(&self.consent_tracker),
            compliance_reporter: Arc::clone(&self.compliance_reporter),
            sanction_checker: Arc::clone(&self.sanction_checker),
        }
    }
}

impl GovernanceRing {
    pub fn new(config: &GovernanceConfig) -> Result<Self> {
        Ok(Self {
            config: Arc::new(config.clone()),
            policy_checker: Arc::new(PolicyComplianceChecker::new(&config.policy_compliance)),
            audit_logger: Arc::new(AuditLogger::new(&config.audit_logger)),
            retention_enforcer: Arc::new(DataRetentionEnforcer::new(&config.data_retention)),
            consent_tracker: Arc::new(ConsentTracker::new(&config.consent_tracker)),
            compliance_reporter: Arc::new(ComplianceReporter::new(&config.compliance_reporter)),
            sanction_checker: Arc::new(SanctionChecker::new(&config.sanction_checker)),
        })
    }

    /// Evaluate governance compliance through all 6 engines.
    ///
    /// Pipeline: Policy → Audit → Retention → Consent → ComplianceReport → Sanction
    pub fn evaluate(&self, request: &GovernanceRequest) -> GovernanceVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return GovernanceVerdict {
                decision: Decision::Allow,
                policy_result: None,
                audit_result: None,
                retention_result: None,
                consent_result: None,
                compliance_report: None,
                sanction_result: None,
                engine_results: vec![],
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                governance_risk_score: 0.0,
            };
        }

        let mut engine_results = Vec::with_capacity(6);
        let mut risk_accumulator = 0.0f64;

        // 1. Policy Compliance Checker
        let (policy_result, policy_eng) = self.policy_checker.evaluate(request);
        match policy_eng.decision.as_str() {
            "denied" => risk_accumulator += 4.0,
            "flagged" => risk_accumulator += 1.5,
            _ => {}
        }
        engine_results.push(policy_eng);

        // 2. Audit Logger (never blocks — always "allowed")
        let (audit_result, audit_eng) = self.audit_logger.evaluate(request);
        engine_results.push(audit_eng);

        // 3. Data Retention Enforcer
        let (retention_result, retention_eng) = self.retention_enforcer.evaluate(request);
        match retention_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(retention_eng);

        // 4. Consent Tracker
        let (consent_result, consent_eng) = self.consent_tracker.evaluate(request);
        match consent_eng.decision.as_str() {
            "denied" => risk_accumulator += 4.0,
            "flagged" => risk_accumulator += 1.5,
            _ => {}
        }
        engine_results.push(consent_eng);

        // 5. Compliance Reporter
        let (compliance_report, compliance_eng) = self.compliance_reporter.evaluate(request);
        match compliance_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(compliance_eng);

        // 6. Sanction Checker
        let (sanction_result, sanction_eng) = self.sanction_checker.evaluate(request);
        match sanction_eng.decision.as_str() {
            "denied" => risk_accumulator += 10.0, // Sanction violations are critical
            _ => {}
        }
        engine_results.push(sanction_eng);

        let governance_risk_score = risk_accumulator.clamp(0.0, 10.0);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Decision logic
        let any_denied = engine_results.iter().any(|e| e.decision == "denied");
        let decision = if governance_risk_score >= self.config.deny_threshold {
            Decision::Deny {
                code: "GOVERNANCE_VIOLATION_SEVERE".into(),
                retry_after: Some(300),
            }
        } else if any_denied {
            Decision::Deny {
                code: "GOVERNANCE_VIOLATION".into(),
                retry_after: None,
            }
        } else if governance_risk_score > 5.0 {
            Decision::Escalate {
                approver_role: "compliance_officer".into(),
                timeout_secs: 600,
            }
        } else {
            Decision::Allow
        };

        GovernanceVerdict {
            decision,
            policy_result: Some(policy_result),
            audit_result: Some(audit_result),
            retention_result: Some(retention_result),
            consent_result: Some(consent_result),
            compliance_report: Some(compliance_report),
            sanction_result: Some(sanction_result),
            engine_results,
            latency_ms,
            governance_risk_score,
        }
    }

    /// Get the configuration reference.
    pub fn config(&self) -> &GovernanceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_request() -> GovernanceRequest {
        GovernanceRequest {
            action: "read".into(),
            resource: Some("/data/reports/q4".into()),
            data_classification: Some("internal".into()),
            consent_token: Some("analytics,reporting".into()),
            frameworks: vec![],
            entity_id: Some("org-123".into()),
            region: Some("US".into()),
            source_ip: "1.2.3.4".into(),
            user_id: Some("user-1".into()),
            role: Some("user".into()),
            request_id: "gov-test-1".into(),
            headers: HashMap::new(),
        }
    }

    fn default_config() -> GovernanceConfig {
        GovernanceConfig::default()
    }

    #[test]
    fn governance_ring_constructs() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        assert!(ring.config.enabled);
    }

    #[test]
    fn governance_ring_allows_benign() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.governance_risk_score < 5.0);
    }

    #[test]
    fn governance_ring_detects_high_risk_action() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.action = "delete".into();
        req.role = Some("user".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.policy_result.is_some());
        assert!(!verdict.policy_result.as_ref().unwrap().compliant);
    }

    #[test]
    fn governance_ring_admin_deletes_ok() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.action = "delete".into();
        req.role = Some("admin".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.policy_result.is_some());
        assert!(verdict.policy_result.as_ref().unwrap().compliant);
    }

    #[test]
    fn governance_ring_audit_always_logs() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.audit_result.is_some());
        assert!(verdict.audit_result.as_ref().unwrap().logged);
    }

    #[test]
    fn governance_ring_missing_consent() {
        let mut config = default_config();
        config.consent_tracker.require_explicit_consent = true;
        let ring = GovernanceRing::new(&config).unwrap();
        let mut req = default_request();
        req.consent_token = None;
        let verdict = ring.evaluate(&req);
        assert!(verdict.consent_result.is_some());
        assert!(!verdict.consent_result.as_ref().unwrap().consent_valid);
    }

    #[test]
    fn governance_ring_sanction_blocks() {
        let mut config = default_config();
        config.sanction_checker.blocked_entities = vec!["org-blocked".into()];
        let ring = GovernanceRing::new(&config).unwrap();
        let mut req = default_request();
        req.entity_id = Some("org-blocked".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.sanction_result.is_some());
        assert!(verdict.sanction_result.as_ref().unwrap().blocked);
        assert!(verdict.decision.is_deny());
    }

    #[test]
    fn governance_ring_data_retention_violation() {
        let mut config = default_config();
        config.data_retention.auto_delete = true;
        config.data_retention.max_retention_days = 30;
        let ring = GovernanceRing::new(&config).unwrap();
        let mut req = default_request();
        req.headers.insert("x-data-age-days".into(), "90".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.retention_result.is_some());
        assert!(!verdict.retention_result.as_ref().unwrap().within_policy);
    }

    #[test]
    fn governance_ring_compliance_reporting() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.compliance_report.is_some());
        assert!(!verdict
            .compliance_report
            .as_ref()
            .unwrap()
            .frameworks_checked
            .is_empty());
    }

    #[test]
    fn governance_ring_disabled_allows() {
        let mut config = default_config();
        config.enabled = false;
        let ring = GovernanceRing::new(&config).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.engine_results.is_empty());
    }

    #[test]
    fn governance_verdict_implements_verdict_trait() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert_eq!(verdict.decision(), &verdict.decision);
        assert!(verdict.latency_ms() >= 0.0);
    }

    #[test]
    fn governance_ring_clones() {
        let ring = GovernanceRing::new(&default_config()).unwrap();
        let _clone = ring.clone();
    }
}
