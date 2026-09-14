// Incident Response Automation — Coordinated response to security incidents.
//
// This module provides automated incident detection, classification,
// playbook execution, evidence collection, and reporting capabilities.
// It orchestrates the full incident lifecycle from detection through
// resolution and post-incident analysis.

pub mod evidence_chain;
pub mod playbook;
pub mod report_generator;
pub mod webhook_integration;

pub use evidence_chain::{
    ChainOfCustody, ChainVerificationResult, CustodyEntry, EvidenceCollector, EvidenceItem,
    EvidenceType,
};
pub use playbook::{
    Playbook, PlaybookAction, PlaybookContext, PlaybookEngine, PlaybookRegistry, PlaybookResult,
    PlaybookStep, StepFailurePolicy, TriggerCondition,
};
pub use report_generator::{
    EvidenceSummary, ExecutiveSummary, ImpactAnalysis, IncidentReport, OutputFormat,
    RemediationActions, ReportGenerator, RootCauseAnalysis, TimelineEntry,
};
pub use webhook_integration::{
    GenericPayload, JiraPayload, PagerDutyPayload, SlackPayload, WebhookEndpoint, WebhookEvent,
    WebhookPayload, WebhookRegistry, WebhookSender,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::decision::Decision;
use crate::error::{Error, Result};

// ── Configuration ──

/// Configuration for the incident response subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponseConfig {
    /// Whether incident response automation is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum number of playbooks that can run concurrently.
    #[serde(default = "default_max_concurrent_playbooks")]
    pub max_concurrent_playbooks: usize,

    /// Number of days to retain incident evidence.
    #[serde(default = "default_evidence_retention_days")]
    pub evidence_retention_days: u64,

    /// Timeout in milliseconds for outgoing webhook notifications.
    #[serde(default = "default_webhook_timeout_ms")]
    pub webhook_timeout_ms: u64,
}

fn default_enabled() -> bool {
    true
}
fn default_max_concurrent_playbooks() -> usize {
    10
}
fn default_evidence_retention_days() -> u64 {
    90
}
fn default_webhook_timeout_ms() -> u64 {
    5000
}

impl Default for IncidentResponseConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_concurrent_playbooks: default_max_concurrent_playbooks(),
            evidence_retention_days: default_evidence_retention_days(),
            webhook_timeout_ms: default_webhook_timeout_ms(),
        }
    }
}

// ── Incident Classification ─

/// Classification of a security incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentClassification {
    /// Unauthorized exfiltration of sensitive data.
    DataBreach,
    /// Access by an unauthorized entity.
    UnauthorizedAccess,
    /// Distributed denial-of-service attack.
    DDoS,
    /// Injection of malicious instructions via prompts.
    PromptInjection,
    /// Attempts to manipulate model behavior.
    ModelManipulation,
    /// Violation of security policy.
    PolicyViolation,
    /// Full or partial system compromise.
    SystemCompromise,
    /// Classification could not be determined.
    Unknown,
}

impl IncidentClassification {
    /// Returns a human-readable label for the classification.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DataBreach => "Data Breach",
            Self::UnauthorizedAccess => "Unauthorized Access",
            Self::DDoS => "DDoS Attack",
            Self::PromptInjection => "Prompt Injection",
            Self::ModelManipulation => "Model Manipulation",
            Self::PolicyViolation => "Policy Violation",
            Self::SystemCompromise => "System Compromise",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns the default severity for this classification.
    pub fn default_severity(&self) -> IncidentSeverity {
        match self {
            Self::DataBreach => IncidentSeverity::Critical,
            Self::UnauthorizedAccess => IncidentSeverity::High,
            Self::DDoS => IncidentSeverity::High,
            Self::PromptInjection => IncidentSeverity::Medium,
            Self::ModelManipulation => IncidentSeverity::High,
            Self::PolicyViolation => IncidentSeverity::Low,
            Self::SystemCompromise => IncidentSeverity::Critical,
            Self::Unknown => IncidentSeverity::Medium,
        }
    }
}

// ── Severity ──

/// Severity level of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    /// Numeric value for comparison (0 = Low, 3 = Critical).
    pub fn level(&self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── Incident ──

/// A security incident detected by the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Unique identifier for this incident.
    pub id: String,
    /// Classification of the incident type.
    pub classification: IncidentClassification,
    /// Severity level.
    pub severity: IncidentSeverity,
    /// Human-readable description of the incident.
    pub description: String,
    /// When the incident was detected.
    pub detected_at: DateTime<Utc>,
    /// Which CHAKRAVYUH ring detected it (1-9).
    pub source_ring: u8,
    /// Resources affected by this incident.
    pub affected_resources: Vec<String>,
    /// Additional key-value metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Incident {
    /// Create a new incident with the given classification and description.
    pub fn new(classification: IncidentClassification, description: &str, source_ring: u8) -> Self {
        let severity = classification.default_severity();
        Self {
            id: Uuid::new_v4().to_string(),
            classification,
            severity,
            description: description.to_string(),
            detected_at: Utc::now(),
            source_ring,
            affected_resources: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Builder-style setter for severity.
    pub fn with_severity(mut self, severity: IncidentSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Builder-style setter for affected resources.
    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.affected_resources = resources;
        self
    }

    /// Builder-style setter for metadata.
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    /// Returns the decision that should be applied based on incident severity.
    pub fn recommended_decision(&self) -> Decision {
        match self.severity {
            IncidentSeverity::Low | IncidentSeverity::Medium => Decision::Challenge {
                challenge_type: crate::decision::ChallengeType::Captcha,
            },
            IncidentSeverity::High => deny_high_severity(),
            IncidentSeverity::Critical => deny_critical(),
        }
    }
}

// Helper to construct denial decisions for severity-based recommendations.
fn deny_high_severity() -> Decision {
    Decision::Deny {
        code: "INCIDENT_HIGH_SEVERITY".to_string(),
        retry_after: Some(300),
    }
}
fn deny_critical() -> Decision {
    Decision::Deny {
        code: "INCIDENT_CRITICAL".to_string(),
        retry_after: None,
    }
}

// ── Orchestrator Status ──

/// Current status of the incident response orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorStatus {
    pub incidents_total: usize,
    pub incidents_active: usize,
    pub incidents_resolved: usize,
    pub playbooks_run_total: usize,
    pub playbooks_running: usize,
    pub evidence_items_collected: usize,
    pub webhooks_sent: usize,
    pub webhooks_failed: usize,
}

impl Default for OrchestratorStatus {
    fn default() -> Self {
        Self {
            incidents_total: 0,
            incidents_active: 0,
            incidents_resolved: 0,
            playbooks_run_total: 0,
            playbooks_running: 0,
            evidence_items_collected: 0,
            webhooks_sent: 0,
            webhooks_failed: 0,
        }
    }
}

// ── Incident Response Orchestrator ──

/// Main coordinator for incident response automation.
///
/// The orchestrator receives incidents, matches them to playbooks,
/// triggers evidence collection, sends webhook notifications, and
/// coordinates the full response lifecycle.
pub struct IncidentResponseOrchestrator {
    config: IncidentResponseConfig,
    incidents: Vec<Incident>,
    playbook_registry: playbook::PlaybookRegistry,
    evidence_collector: evidence_chain::EvidenceCollector,
    webhook_registry: webhook_integration::WebhookRegistry,
    report_generator: report_generator::ReportGenerator,
    status: OrchestratorStatus,
    active_playbooks: HashMap<String, playbook::PlaybookResult>,
}

impl IncidentResponseOrchestrator {
    /// Create a new incident response orchestrator.
    pub fn new(config: IncidentResponseConfig) -> Result<Self> {
        if !config.enabled {
            return Err(Error::EngineInit(
                "Incident response is disabled in configuration".to_string(),
            ));
        }
        Ok(Self {
            config,
            incidents: Vec::new(),
            playbook_registry: playbook::PlaybookRegistry::new(),
            evidence_collector: evidence_chain::EvidenceCollector::new(),
            webhook_registry: webhook_integration::WebhookRegistry::new(),
            report_generator: report_generator::ReportGenerator::new(),
            status: OrchestratorStatus::default(),
            active_playbooks: HashMap::new(),
        })
    }

    /// Handle a newly detected incident.
    ///
    /// This method classifies the incident, begins evidence collection,
    /// matches applicable playbooks, and triggers webhook notifications.
    pub fn handle_incident(&mut self, mut incident: Incident) -> Result<Incident> {
        if !self.config.enabled {
            return Err(Error::Evaluation(
                "Incident response is disabled".to_string(),
            ));
        }

        // Check concurrency limit
        if self.status.playbooks_running >= self.config.max_concurrent_playbooks {
            return Err(Error::Evaluation(format!(
                "Max concurrent playbooks ({}) reached",
                self.config.max_concurrent_playbooks
            )));
        }

        self.status.incidents_total += 1;
        self.status.incidents_active += 1;

        // Auto-classify severity if unknown
        if incident.classification == IncidentClassification::Unknown {
            incident.severity = IncidentSeverity::Medium;
        }

        // Collect initial evidence
        let _evidence_id = self
            .evidence_collector
            .collect(
                &incident.id,
                evidence_chain::EvidenceType::LogEntry,
                "Initial incident detection log",
                incident.description.as_bytes(),
            )
            .map_err(|e| Error::Other(format!("Evidence collection failed: {e}")))?;
        self.status.evidence_items_collected += 1;

        // Match and execute playbooks
        let matched = self
            .playbook_registry
            .find_by_trigger(&incident.classification, &incident.severity);

        for playbook in &matched {
            let context = playbook::PlaybookContext::from_incident(&incident);
            let result = playbook::PlaybookEngine::execute(playbook, context);
            self.status.playbooks_run_total += 1;
            if result.success {
                self.active_playbooks.insert(playbook.name.clone(), result);
            }
        }

        // Update running count based on active playbooks
        self.status.playbooks_running = self.active_playbooks.len();

        self.incidents.push(incident.clone());

        Ok(incident)
    }

    /// Get a list of currently active (running) playbooks.
    pub fn get_active_playbooks(&self) -> Vec<&str> {
        self.active_playbooks.keys().map(|s| s.as_str()).collect()
    }

    /// Generate a report for a specific incident.
    pub fn generate_report(&self, incident_id: &str, format: OutputFormat) -> Result<String> {
        let incident = self
            .incidents
            .iter()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| Error::Other(format!("Incident not found: {incident_id}")))?;

        let evidence_chain = self.evidence_collector.get_chain(incident_id);
        let evidence_chain: Vec<_> = if evidence_chain.is_empty() {
            Vec::new()
        } else {
            evidence_chain
        };

        let active_results: Vec<_> = self.active_playbooks.values().cloned().collect();

        let report =
            self.report_generator
                .generate(incident, &evidence_chain, &active_results, format)?;
        Ok(report)
    }

    /// Get the current status of the orchestrator.
    pub fn get_status(&self) -> &OrchestratorStatus {
        &self.status
    }

    /// Register a playbook with the orchestrator.
    pub fn register_playbook(&mut self, playbook: playbook::Playbook) {
        self.playbook_registry.register(playbook);
    }

    /// Register a webhook endpoint with the orchestrator.
    pub fn register_webhook(&mut self, endpoint: webhook_integration::WebhookEndpoint) {
        self.webhook_registry.register(endpoint);
    }

    /// Resolve an incident (mark as resolved).
    pub fn resolve_incident(&mut self, incident_id: &str) -> Result<()> {
        let incident = self
            .incidents
            .iter_mut()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| Error::Other(format!("Incident not found: {incident_id}")))?;
        incident.metadata.insert(
            "resolved_at".to_string(),
            serde_json::json!(Utc::now().to_rfc3339()),
        );
        self.status.incidents_active = self.status.incidents_active.saturating_sub(1);
        self.status.incidents_resolved += 1;
        Ok(())
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> IncidentResponseConfig {
        IncidentResponseConfig::default()
    }

    #[test]
    fn test_default_config() {
        let config = IncidentResponseConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_concurrent_playbooks, 10);
        assert_eq!(config.evidence_retention_days, 90);
        assert_eq!(config.webhook_timeout_ms, 5000);
    }

    #[test]
    fn test_config_deserialization() {
        let yaml = "enabled: false\nmax_concurrent_playbooks: 5\n";
        let config: IncidentResponseConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.max_concurrent_playbooks, 5);
        // Defaults should apply for missing fields
        assert_eq!(config.evidence_retention_days, 90);
    }

    #[test]
    fn test_incident_classification_label() {
        assert_eq!(IncidentClassification::DataBreach.label(), "Data Breach");
        assert_eq!(IncidentClassification::DDoS.label(), "DDoS Attack");
        assert_eq!(IncidentClassification::Unknown.label(), "Unknown");
    }

    #[test]
    fn test_incident_classification_default_severity() {
        assert_eq!(
            IncidentClassification::DataBreach.default_severity(),
            IncidentSeverity::Critical
        );
        assert_eq!(
            IncidentClassification::PolicyViolation.default_severity(),
            IncidentSeverity::Low
        );
        assert_eq!(
            IncidentClassification::PromptInjection.default_severity(),
            IncidentSeverity::Medium
        );
    }

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(
            IncidentClassification::DDoS,
            "High traffic detected from multiple sources",
            1,
        );
        assert!(!incident.id.is_empty());
        assert_eq!(incident.classification, IncidentClassification::DDoS);
        assert_eq!(incident.severity, IncidentSeverity::High);
        assert_eq!(incident.source_ring, 1);
        assert!(incident.affected_resources.is_empty());
        assert!(incident.metadata.is_empty());
    }

    #[test]
    fn test_incident_builder_pattern() {
        let incident = Incident::new(IncidentClassification::DataBreach, "PII leaked", 2)
            .with_severity(IncidentSeverity::Critical)
            .with_resources(vec!["user_db".to_string(), "api_gateway".to_string()])
            .with_metadata("source_ip", serde_json::json!("10.0.0.1"));

        assert_eq!(incident.severity, IncidentSeverity::Critical);
        assert_eq!(incident.affected_resources.len(), 2);
        assert_eq!(
            incident.metadata["source_ip"],
            serde_json::json!("10.0.0.1")
        );
    }

    #[test]
    fn test_severity_ordering() {
        assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
        assert!(IncidentSeverity::Medium < IncidentSeverity::High);
        assert!(IncidentSeverity::High < IncidentSeverity::Critical);
    }

    #[test]
    fn test_orchestrator_new() {
        let config = default_config();
        let orch = IncidentResponseOrchestrator::new(config);
        assert!(orch.is_ok());
        let orch = orch.unwrap();
        assert_eq!(orch.get_status().incidents_total, 0);
    }

    #[test]
    fn test_orchestrator_disabled() {
        let config = IncidentResponseConfig {
            enabled: false,
            ..default_config()
        };
        let result = IncidentResponseOrchestrator::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_incident() {
        let config = default_config();
        let mut orch = IncidentResponseOrchestrator::new(config).unwrap();
        let incident = Incident::new(
            IncidentClassification::PromptInjection,
            "Malicious prompt detected",
            3,
        );

        let result = orch.handle_incident(incident).unwrap();
        assert_eq!(
            result.classification,
            IncidentClassification::PromptInjection
        );
        assert_eq!(orch.get_status().incidents_total, 1);
        assert_eq!(orch.get_status().incidents_active, 1);
        assert!(orch.get_status().evidence_items_collected > 0);
    }

    #[test]
    fn test_resolve_incident() {
        let config = default_config();
        let mut orch = IncidentResponseOrchestrator::new(config).unwrap();
        let incident = Incident::new(
            IncidentClassification::PolicyViolation,
            "Rate limit exceeded",
            4,
        );
        let handled = orch.handle_incident(incident).unwrap();
        assert_eq!(orch.get_status().incidents_active, 1);

        orch.resolve_incident(&handled.id).unwrap();
        assert_eq!(orch.get_status().incidents_active, 0);
        assert_eq!(orch.get_status().incidents_resolved, 1);
    }

    #[test]
    fn test_resolve_nonexistent_incident() {
        let config = default_config();
        let mut orch = IncidentResponseOrchestrator::new(config).unwrap();
        let result = orch.resolve_incident("nonexistent-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_report_for_nonexistent() {
        let config = default_config();
        let orch = IncidentResponseOrchestrator::new(config).unwrap();
        let result = orch.generate_report("no-such-id", OutputFormat::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_active_playbooks_empty() {
        let config = default_config();
        let orch = IncidentResponseOrchestrator::new(config).unwrap();
        let active = orch.get_active_playbooks();
        assert!(active.is_empty());
    }

    #[test]
    fn test_incident_serialization() {
        let incident = Incident::new(IncidentClassification::DataBreach, "Test breach", 5)
            .with_severity(IncidentSeverity::Critical);

        let json = serde_json::to_string(&incident).unwrap();
        let deserialized: Incident = serde_json::from_str(&json).unwrap();
        assert_eq!(incident.id, deserialized.id);
        assert_eq!(incident.classification, deserialized.classification);
        assert_eq!(incident.severity, deserialized.severity);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", IncidentSeverity::Low), "low");
        assert_eq!(format!("{}", IncidentSeverity::Critical), "critical");
    }
}
