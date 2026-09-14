// Incident Report Generator — Comprehensive post-incident reporting.
//
// Generates structured reports from incident data, evidence chains,
// and playbook execution results. Supports JSON, plain text, and HTML
// output formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::evidence_chain::EvidenceItem;
use super::playbook::PlaybookResult;
use super::{Incident, IncidentClassification, IncidentSeverity};
use crate::error::{Error, Result};

// ── Output Format ──

/// Supported report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Text,
    Html,
}

// ── Report Sub-Structures ──

/// High-level summary for executive stakeholders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// One-paragraph overview of the incident.
    pub overview: String,
    /// Total duration from detection to resolution (seconds).
    pub total_duration_secs: Option<u64>,
    /// Final incident severity.
    pub severity: IncidentSeverity,
    /// Whether the incident was fully contained.
    pub contained: bool,
    /// Key metrics.
    pub key_metrics: Vec<String>,
}

/// A single entry in the incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Short description of what happened.
    pub event: String,
    /// Actor that performed the action (system, user, playbook).
    pub actor: String,
    /// Category of event.
    pub category: TimelineCategory,
}

/// Categories of timeline events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineCategory {
    Detection,
    Response,
    Containment,
    Evidence,
    Resolution,
    Notification,
}

/// Root cause analysis section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseAnalysis {
    /// Primary cause description.
    pub primary_cause: String,
    /// Contributing factors.
    pub contributing_factors: Vec<String>,
    /// Source ring where the issue originated.
    pub source_ring: u8,
    /// Recommended preventive measures.
    pub recommendations: Vec<String>,
}

/// Impact analysis section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    /// Number of affected resources.
    pub resources_affected: usize,
    /// List of affected resource names.
    pub affected_resources: Vec<String>,
    /// Estimated business impact level.
    pub business_impact: ImpactLevel,
    /// Data exposure assessment.
    pub data_exposure: DataExposureAssessment,
}

/// Business impact level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Data exposure assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExposureAssessment {
    /// Whether any data was exposed.
    pub exposed: bool,
    /// Types of data potentially exposed.
    pub data_types: Vec<String>,
    /// Number of records potentially affected.
    pub estimated_records: Option<u64>,
}

/// Remediation actions taken or recommended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationActions {
    /// Actions that were executed.
    pub executed: Vec<ActionItem>,
    /// Actions that are recommended but not yet executed.
    pub recommended: Vec<ActionItem>,
}

/// A single remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    pub description: String,
    pub status: ActionStatus,
    pub playbook: Option<String>,
}

/// Status of a remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Completed,
    InProgress,
    Pending,
    Skipped,
}

/// Summary of evidence collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Total number of evidence items.
    pub total_items: usize,
    /// Tamper-proof hash of the chain.
    pub chain_integrity_hash: Option<String>,
    /// Breakdown by evidence type.
    pub by_type: Vec<TypeBreakdown>,
}

/// Breakdown of evidence by type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeBreakdown {
    pub evidence_type: String,
    pub count: usize,
}

// ── Incident Report ──

/// A complete incident response report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    /// Report metadata.
    pub incident_id: String,
    pub classification: IncidentClassification,
    pub severity: IncidentSeverity,
    pub generated_at: DateTime<Utc>,
    pub format_version: String,
    /// Report sections.
    pub executive_summary: ExecutiveSummary,
    pub timeline: Vec<TimelineEntry>,
    pub root_cause_analysis: RootCauseAnalysis,
    pub impact_analysis: ImpactAnalysis,
    pub remediation_actions: RemediationActions,
    pub evidence_summary: EvidenceSummary,
}

// ── Report Generator ──

/// Generates incident response reports.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Create a new report generator.
    pub fn new() -> Self {
        Self
    }

    /// Generate a complete report for an incident.
    pub fn generate(
        &self,
        incident: &Incident,
        evidence: &[&EvidenceItem],
        playbook_results: &[PlaybookResult],
        format: OutputFormat,
    ) -> Result<String> {
        let summary = self.build_executive_summary(incident, playbook_results);
        let timeline = self.build_timeline(incident, evidence, playbook_results);
        let root_cause = self.analyze_root_cause(incident);
        let impact = self.assess_impact(incident);
        let remediation = self.build_remediation(incident, playbook_results);
        let evidence_summary = self.summarize_evidence(evidence);

        let report = IncidentReport {
            incident_id: incident.id.clone(),
            classification: incident.classification,
            severity: incident.severity,
            generated_at: Utc::now(),
            format_version: "1.0.0".to_string(),
            executive_summary: summary,
            timeline,
            root_cause_analysis: root_cause,
            impact_analysis: impact,
            remediation_actions: remediation,
            evidence_summary,
        };

        self.format_report(&report, format)
    }

    /// Build the executive summary section.
    pub fn build_executive_summary(
        &self,
        incident: &Incident,
        playbook_results: &[PlaybookResult],
    ) -> ExecutiveSummary {
        let all_success = playbook_results.iter().all(|r| r.success);
        let total_steps: usize = playbook_results.iter().map(|r| r.steps_completed).sum();

        let mut key_metrics = vec![
            format!("Classification: {}", incident.classification.label()),
            format!("Severity: {}", incident.severity),
            format!("Source Ring: {}", incident.source_ring),
            format!("Affected Resources: {}", incident.affected_resources.len()),
        ];
        if !playbook_results.is_empty() {
            key_metrics.push(format!(
                "Playbooks Executed: {} ({} successful)",
                playbook_results.len(),
                playbook_results.iter().filter(|r| r.success).count()
            ));
            key_metrics.push(format!("Total Steps Completed: {total_steps}"));
        }

        ExecutiveSummary {
            overview: incident.description.clone(),
            total_duration_secs: None,
            severity: incident.severity,
            contained: !playbook_results.is_empty() && all_success,
            key_metrics,
        }
    }

    /// Build the incident timeline.
    pub fn build_timeline(
        &self,
        incident: &Incident,
        evidence: &[&EvidenceItem],
        playbook_results: &[PlaybookResult],
    ) -> Vec<TimelineEntry> {
        let mut timeline = Vec::new();

        // Detection event
        timeline.push(TimelineEntry {
            timestamp: incident.detected_at,
            event: format!(
                "Incident {} detected: {}",
                incident.classification.label(),
                incident.description
            ),
            actor: "system".to_string(),
            category: TimelineCategory::Detection,
        });

        // Evidence collection events
        for item in evidence {
            timeline.push(TimelineEntry {
                timestamp: item.collected_at,
                event: format!(
                    "Evidence collected: {} ({})",
                    item.description,
                    item.evidence_type.label()
                ),
                actor: "evidence_collector".to_string(),
                category: TimelineCategory::Evidence,
            });
        }

        // Playbook execution events
        for result in playbook_results {
            timeline.push(TimelineEntry {
                timestamp: Utc::now(),
                event: format!(
                    "Playbook completed: {} steps done, {} failed, {}ms",
                    result.steps_completed, result.steps_failed, result.total_time_ms
                ),
                actor: "playbook_engine".to_string(),
                category: TimelineCategory::Response,
            });
        }

        // Sort by timestamp
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        timeline
    }

    /// Analyze the root cause of the incident.
    pub fn analyze_root_cause(&self, incident: &Incident) -> RootCauseAnalysis {
        let (primary_cause, factors) = match incident.classification {
            IncidentClassification::DataBreach => (
                "Unauthorized data exfiltration detected by security monitoring.".to_string(),
                vec![
                    "Possible insufficient access controls on sensitive data stores".to_string(),
                    "Detection triggered by anomaly in data access patterns".to_string(),
                ],
            ),
            IncidentClassification::PromptInjection => (
                "Malicious prompt injected into AI model input.".to_string(),
                vec![
                    "Input sanitization may be insufficient".to_string(),
                    "Model output guardrails bypassed".to_string(),
                ],
            ),
            IncidentClassification::DDoS => (
                "Distributed denial-of-service traffic pattern detected.".to_string(),
                vec![
                    "High request volume from distributed sources".to_string(),
                    "Rate limiting thresholds may need adjustment".to_string(),
                ],
            ),
            _ => (
                format!(
                    "{} incident detected in ring {}.",
                    incident.classification.label(),
                    incident.source_ring
                ),
                vec!["Further investigation required".to_string()],
            ),
        };

        RootCauseAnalysis {
            primary_cause,
            contributing_factors: factors,
            source_ring: incident.source_ring,
            recommendations: vec![
                "Review and update relevant security policies".to_string(),
                "Implement additional monitoring for similar patterns".to_string(),
                "Conduct post-incident review with stakeholders".to_string(),
            ],
        }
    }

    /// Assess the impact of the incident.
    pub fn assess_impact(&self, incident: &Incident) -> ImpactAnalysis {
        let business_impact = match incident.severity {
            IncidentSeverity::Critical => ImpactLevel::Critical,
            IncidentSeverity::High => ImpactLevel::High,
            IncidentSeverity::Medium => ImpactLevel::Medium,
            IncidentSeverity::Low => ImpactLevel::Low,
        };

        let exposed = matches!(
            incident.classification,
            IncidentClassification::DataBreach | IncidentClassification::SystemCompromise
        );

        ImpactAnalysis {
            resources_affected: incident.affected_resources.len(),
            affected_resources: incident.affected_resources.clone(),
            business_impact,
            data_exposure: DataExposureAssessment {
                exposed,
                data_types: if exposed {
                    vec!["PII".to_string(), "Credentials".to_string()]
                } else {
                    Vec::new()
                },
                estimated_records: if exposed { Some(0) } else { None },
            },
        }
    }

    /// Build remediation actions.
    fn build_remediation(
        &self,
        incident: &Incident,
        playbook_results: &[PlaybookResult],
    ) -> RemediationActions {
        let mut executed = Vec::new();
        let mut recommended = Vec::new();

        for result in playbook_results {
            executed.push(ActionItem {
                description: format!(
                    "Automated response playbook ({} steps, {}ms)",
                    result.steps_completed, result.total_time_ms
                ),
                status: if result.success {
                    ActionStatus::Completed
                } else {
                    ActionStatus::InProgress
                },
                playbook: None,
            });
        }

        // Add recommended actions based on classification
        match incident.classification {
            IncidentClassification::DataBreach => {
                recommended.push(ActionItem {
                    description: "Conduct full data audit".to_string(),
                    status: ActionStatus::Pending,
                    playbook: None,
                });
                recommended.push(ActionItem {
                    description: "Notify affected parties".to_string(),
                    status: ActionStatus::Pending,
                    playbook: None,
                });
            }
            IncidentClassification::PromptInjection => {
                recommended.push(ActionItem {
                    description: "Review and strengthen input validation".to_string(),
                    status: ActionStatus::Pending,
                    playbook: None,
                });
            }
            _ => {
                recommended.push(ActionItem {
                    description: "Review incident timeline and update policies".to_string(),
                    status: ActionStatus::Pending,
                    playbook: None,
                });
            }
        }

        RemediationActions {
            executed,
            recommended,
        }
    }

    /// Summarize evidence.
    fn summarize_evidence(&self, evidence: &[&EvidenceItem]) -> EvidenceSummary {
        let mut type_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for item in evidence {
            *type_counts
                .entry(item.evidence_type.label().to_string())
                .or_insert(0) += 1;
        }

        let mut by_type: Vec<TypeBreakdown> = type_counts
            .into_iter()
            .map(|(evidence_type, count)| TypeBreakdown {
                evidence_type,
                count,
            })
            .collect();
        by_type.sort_by(|a, b| b.count.cmp(&a.count));

        let chain_hash = evidence.last().map(|item| item.chain_hash.clone());

        EvidenceSummary {
            total_items: evidence.len(),
            chain_integrity_hash: chain_hash,
            by_type,
        }
    }

    /// Format a report in the specified output format.
    pub fn format_report(&self, report: &IncidentReport, format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => self.format_json(report),
            OutputFormat::Text => self.format_text(report),
            OutputFormat::Html => self.format_html(report),
        }
    }

    fn format_json(&self, report: &IncidentReport) -> Result<String> {
        serde_json::to_string_pretty(report).map_err(|e| Error::Serialization(e.to_string()))
    }

    fn format_text(&self, report: &IncidentReport) -> Result<String> {
        let mut out = String::new();
        out.push_str(&format!("=== INCIDENT RESPONSE REPORT ===\n"));
        out.push_str(&format!("Incident ID: {}\n", report.incident_id));
        out.push_str(&format!(
            "Classification: {}\n",
            report.classification.label()
        ));
        out.push_str(&format!("Severity: {}\n", report.severity));
        out.push_str(&format!("Generated: {}\n\n", report.generated_at));

        out.push_str("--- EXECUTIVE SUMMARY ---\n");
        out.push_str(&format!("{}\n", report.executive_summary.overview));
        out.push_str(&format!(
            "Contained: {}\n",
            report.executive_summary.contained
        ));
        for metric in &report.executive_summary.key_metrics {
            out.push_str(&format!("  - {metric}\n"));
        }
        out.push_str("\n");

        out.push_str("--- TIMELINE ---\n");
        for entry in &report.timeline {
            out.push_str(&format!(
                "  [{}] ({:?}) {}\n",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.category,
                entry.event
            ));
        }
        out.push_str("\n");

        out.push_str("--- ROOT CAUSE ANALYSIS ---\n");
        out.push_str(&format!(
            "Primary: {}\n",
            report.root_cause_analysis.primary_cause
        ));
        for factor in &report.root_cause_analysis.contributing_factors {
            out.push_str(&format!("  Factor: {factor}\n"));
        }
        out.push_str("\n");

        out.push_str(&format!(
            "--- IMPACT ---\nResources affected: {}\nBusiness impact: {:?}\nData exposed: {}\n\n",
            report.impact_analysis.resources_affected,
            report.impact_analysis.business_impact,
            report.impact_analysis.data_exposure.exposed
        ));

        out.push_str("--- REMEDIATION ---\n");
        for action in &report.remediation_actions.executed {
            out.push_str(&format!(
                "  [EXECUTED] {} ({:?})\n",
                action.description, action.status
            ));
        }
        for action in &report.remediation_actions.recommended {
            out.push_str(&format!(
                "  [RECOMMENDED] {} ({:?})\n",
                action.description, action.status
            ));
        }
        out.push_str("\n");

        out.push_str("--- EVIDENCE ---\n");
        out.push_str(&format!(
            "Total items: {}\n",
            report.evidence_summary.total_items
        ));
        if let Some(ref hash) = report.evidence_summary.chain_integrity_hash {
            out.push_str(&format!("Chain integrity: {hash}\n"));
        }

        Ok(out)
    }

    fn format_html(&self, report: &IncidentReport) -> Result<String> {
        let mut out = String::new();
        out.push_str("<!DOCTYPE html>\n<html><head>\n");
        out.push_str("<title>Incident Report</title>\n");
        out.push_str(
            "<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em;}",
        );
        out.push_str("h1{color:#c62828;}h2{color:#1565c0;border-bottom:1px solid #ddd;padding-bottom:0.3em;}");
        out.push_str(".metric{background:#f5f5f5;padding:0.5em;border-radius:4px;margin:0.3em 0;}");
        out.push_str(".severity-critical{color:#c62828;font-weight:bold;}");
        out.push_str(".severity-high{color:#e65100;}");
        out.push_str("table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:0.5em;text-align:left;}");
        out.push_str("th{background:#e3f2fd;}\n</style></head><body>\n");

        out.push_str(&format!(
            "<h1>Incident Report: {}</h1>\n",
            report.incident_id
        ));
        out.push_str(&format!(
            "<p><strong>Classification:</strong> {} | ",
            report.classification.label()
        ));
        out.push_str(&format!(
            "<strong>Severity:</strong> <span class=\"severity-{}\">{}</span> | ",
            format!("{:?}", report.severity).to_lowercase(),
            report.severity
        ));
        out.push_str(&format!(
            "<strong>Generated:</strong> {}</p>\n",
            report.generated_at
        ));

        out.push_str("<h2>Executive Summary</h2>\n");
        out.push_str(&format!("<p>{}</p>\n", report.executive_summary.overview));
        for metric in &report.executive_summary.key_metrics {
            out.push_str(&format!("<div class=\"metric\">{metric}</div>\n"));
        }

        out.push_str("<h2>Timeline</h2>\n<table>\n");
        out.push_str("<tr><th>Time</th><th>Category</th><th>Event</th></tr>\n");
        for entry in &report.timeline {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{:?}</td><td>{}</td></tr>\n",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                entry.category,
                entry.event
            ));
        }
        out.push_str("</table>\n");

        out.push_str("<h2>Root Cause Analysis</h2>\n");
        out.push_str(&format!(
            "<p><strong>Primary Cause:</strong> {}</p>\n",
            report.root_cause_analysis.primary_cause
        ));
        for factor in &report.root_cause_analysis.contributing_factors {
            out.push_str(&format!("<p>Contributing Factor: {factor}</p>\n"));
        }

        out.push_str("<h2>Impact</h2>\n");
        out.push_str(&format!(
            "<p>Resources affected: {}</p>\n",
            report.impact_analysis.resources_affected
        ));
        out.push_str(&format!(
            "<p>Business impact: {:?}</p>\n",
            report.impact_analysis.business_impact
        ));
        out.push_str(&format!(
            "<p>Data exposed: {}</p>\n",
            report.impact_analysis.data_exposure.exposed
        ));

        out.push_str("<h2>Remediation</h2>\n");
        for action in &report.remediation_actions.executed {
            out.push_str(&format!(
                "<p>[Executed] {} ({:?})</p>\n",
                action.description, action.status
            ));
        }
        for action in &report.remediation_actions.recommended {
            out.push_str(&format!(
                "<p>[Recommended] {} ({:?})</p>\n",
                action.description, action.status
            ));
        }

        out.push_str("<h2>Evidence</h2>\n");
        out.push_str(&format!(
            "<p>Total items: {}</p>\n",
            report.evidence_summary.total_items
        ));
        if let Some(ref hash) = report.evidence_summary.chain_integrity_hash {
            out.push_str(&format!(
                "<p>Chain integrity hash: <code>{hash}</code></p>\n"
            ));
        }

        out.push_str("</body></html>");
        Ok(out)
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident_response::evidence_chain::{EvidenceCollector, EvidenceType};

    fn make_incident(cls: IncidentClassification, sev: IncidentSeverity, ring: u8) -> Incident {
        Incident::new(cls, "test incident", ring)
            .with_severity(sev)
            .with_resources(vec!["resource-a".to_string()])
    }

    #[test]
    fn test_output_format_serialization() {
        assert_eq!(
            serde_json::to_string(&OutputFormat::Json).unwrap(),
            "\"json\""
        );
        assert_eq!(
            serde_json::to_string(&OutputFormat::Html).unwrap(),
            "\"html\""
        );
    }

    #[test]
    fn test_build_executive_summary() {
        let gen = ReportGenerator::new();
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let summary = gen.build_executive_summary(&incident, &[]);

        assert_eq!(summary.severity, IncidentSeverity::High);
        assert!(!summary.contained); // No playbooks, not contained by automation
        assert!(summary.overview.contains("test incident"));
        assert!(summary.key_metrics.iter().any(|m| m.contains("DDoS")));
    }

    #[test]
    fn test_build_timeline() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::DataBreach,
            IncidentSeverity::Critical,
            2,
        );
        let timeline = gen.build_timeline(&incident, &[], &[]);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].category, TimelineCategory::Detection);
    }

    #[test]
    fn test_analyze_root_cause() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::PromptInjection,
            IncidentSeverity::Medium,
            5,
        );
        let rca = gen.analyze_root_cause(&incident);

        assert!(rca.primary_cause.contains("prompt"));
        assert!(!rca.contributing_factors.is_empty());
        assert_eq!(rca.source_ring, 5);
        assert!(!rca.recommendations.is_empty());
    }

    #[test]
    fn test_assess_impact() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::DataBreach,
            IncidentSeverity::Critical,
            1,
        );
        let impact = gen.assess_impact(&incident);

        assert_eq!(impact.resources_affected, 1);
        assert_eq!(impact.business_impact, ImpactLevel::Critical);
        assert!(impact.data_exposure.exposed);
    }

    #[test]
    fn test_assess_impact_no_exposure() {
        let gen = ReportGenerator::new();
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let impact = gen.assess_impact(&incident);

        assert!(!impact.data_exposure.exposed);
        assert!(impact.data_exposure.data_types.is_empty());
    }

    #[test]
    fn test_format_json() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::PolicyViolation,
            IncidentSeverity::Low,
            3,
        );
        let result = gen
            .generate(&incident, &[], &[], OutputFormat::Json)
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["classification"], "policy_violation");
        assert_eq!(parsed["severity"], "low");
    }

    #[test]
    fn test_format_text() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::DataBreach,
            IncidentSeverity::High,
            1,
        );
        let result = gen
            .generate(&incident, &[], &[], OutputFormat::Text)
            .unwrap();

        assert!(result.contains("INCIDENT RESPONSE REPORT"));
        assert!(result.contains("Data Breach"));
        assert!(result.contains("EXECUTIVE SUMMARY"));
    }

    #[test]
    fn test_format_html() {
        let gen = ReportGenerator::new();
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::Medium, 1);
        let result = gen
            .generate(&incident, &[], &[], OutputFormat::Html)
            .unwrap();

        assert!(result.contains("<!DOCTYPE html>"));
        assert!(result.contains("<h1>Incident Report"));
        assert!(result.contains("DDoS Attack"));
        assert!(result.contains("</html>"));
    }

    #[test]
    fn test_generate_with_evidence() {
        let gen = ReportGenerator::new();
        let incident = make_incident(
            IncidentClassification::DataBreach,
            IncidentSeverity::Critical,
            2,
        );

        let mut collector = EvidenceCollector::new();
        collector
            .collect(&incident.id, EvidenceType::LogEntry, "Log", b"data")
            .unwrap();
        collector
            .collect(&incident.id, EvidenceType::NetworkCapture, "Net", b"data")
            .unwrap();
        let chain: Vec<_> = collector.get_chain(&incident.id);

        let result = gen
            .generate(&incident, &chain, &[], OutputFormat::Text)
            .unwrap();
        assert!(result.contains("Evidence collected"));
        assert!(result.contains("Total items: 2"));
    }

    #[test]
    fn test_generate_with_playbook_results() {
        let gen = ReportGenerator::new();
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);

        let pb_result = PlaybookResult {
            success: true,
            steps_completed: 3,
            steps_failed: 0,
            total_time_ms: 150,
            artifacts: std::collections::HashMap::new(),
            step_details: Vec::new(),
        };

        let result = gen
            .generate(&incident, &[], &[pb_result], OutputFormat::Text)
            .unwrap();
        assert!(result.contains("EXECUTED"));
        assert!(result.contains("Playbooks Executed: 1 (1 successful)"));
    }

    #[test]
    fn test_evidence_summary_by_type() {
        let gen = ReportGenerator::new();
        let incident = make_incident(IncidentClassification::Unknown, IncidentSeverity::Low, 1);

        let mut collector = EvidenceCollector::new();
        collector
            .collect(&incident.id, EvidenceType::LogEntry, "L1", b"a")
            .unwrap();
        collector
            .collect(&incident.id, EvidenceType::LogEntry, "L2", b"b")
            .unwrap();
        collector
            .collect(&incident.id, EvidenceType::ConversationLog, "C1", b"c")
            .unwrap();
        let chain: Vec<_> = collector.get_chain(&incident.id);

        let report_result = gen
            .generate(&incident, &chain, &[], OutputFormat::Json)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report_result).unwrap();
        let summary = &parsed["evidence_summary"];
        assert_eq!(summary["total_items"], 3);
    }
}
