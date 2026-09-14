// Soak Framework — Health Monitor (D6)
//
// Soak-specific health monitoring with continuous health checks,
// incident tracking, and uptime calculation.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::validation::verification::Severity;

/// A single health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Human-readable name of the health check.
    pub name: String,
    /// The subsystem being checked (e.g., "shield", "threat", "keshav").
    pub subsystem: String,
    /// Whether the check passed (healthy).
    pub healthy: bool,
    /// RFC 3339 timestamp of when the check was performed.
    pub last_checked: String,
    /// Response time in milliseconds.
    pub response_time_ms: u64,
    /// Additional details about the check result.
    pub details: String,
}

impl HealthCheck {
    /// Create a new health check result with the current timestamp.
    pub fn new(name: &str, subsystem: &str, healthy: bool, response_time_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            subsystem: subsystem.to_string(),
            healthy,
            last_checked: chrono::Utc::now().to_rfc3339(),
            response_time_ms,
            details: String::new(),
        }
    }

    /// Builder: set a custom timestamp.
    pub fn with_timestamp(mut self, ts: &str) -> Self {
        self.last_checked = ts.to_string();
        self
    }

    /// Builder: set details.
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = details.to_string();
        self
    }
}

/// A health incident — an unhealthy period that may or may not be resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIncident {
    /// Unique incident ID (UUID).
    pub id: String,
    /// Name of the health check that triggered this incident.
    pub check_name: String,
    /// Subsystem affected.
    pub subsystem: String,
    /// RFC 3339 timestamp when the incident started.
    pub started_at: String,
    /// RFC 3339 timestamp when the incident was resolved (if at all).
    pub resolved_at: Option<String>,
    /// Duration in milliseconds (only set when resolved).
    pub duration_ms: Option<u64>,
    /// Severity of the incident.
    pub severity: Severity,
    /// Human-readable description.
    pub description: String,
}

/// Summary of all incidents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    /// Total number of incidents recorded.
    pub total_incidents: u64,
    /// Number of currently open (unresolved) incidents.
    pub open_incidents: u64,
    /// Average duration of resolved incidents in milliseconds.
    pub avg_duration_ms: f64,
    /// Maximum duration of resolved incidents in milliseconds.
    pub max_duration_ms: u64,
    /// Incident count per subsystem.
    pub per_subsystem: HashMap<String, u64>,
}

/// Continuous health monitor for soak tests.
///
/// Tracks health checks over time, creates incidents when checks fail,
/// and resolves them when the subsystem becomes healthy again.
/// Computes uptime percentage and incident summaries.
pub struct SoakHealthMonitor {
    checks: Vec<HealthCheck>,
    incidents: Vec<HealthIncident>,
}

impl SoakHealthMonitor {
    /// Create a new health monitor.
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            incidents: Vec::new(),
        }
    }

    /// Record a health check result.
    ///
    /// If the check is unhealthy and there is no existing open incident
    /// for this check name, a new incident is created.
    /// If the check is healthy and there is an open incident, it is resolved.
    pub fn record_check(&mut self, check: HealthCheck) {
        info!(
            name = %check.name,
            subsystem = %check.subsystem,
            healthy = check.healthy,
            "Health check recorded"
        );

        if !check.healthy {
            // Check if there's already an open incident for this check.
            let has_open = self
                .incidents
                .iter()
                .any(|inc| inc.check_name == check.name && inc.resolved_at.is_none());
            if !has_open {
                let severity = Severity::High;
                let description = format!(
                    "Health check '{}' for subsystem '{}' failed: {}",
                    check.name, check.subsystem, check.details
                );
                warn!(
                    check_name = %check.name,
                    subsystem = %check.subsystem,
                    "New health incident created"
                );
                self.incidents.push(HealthIncident {
                    id: uuid::Uuid::new_v4().to_string(),
                    check_name: check.name.clone(),
                    subsystem: check.subsystem.clone(),
                    started_at: check.last_checked.clone(),
                    resolved_at: None,
                    duration_ms: None,
                    severity,
                    description,
                });
            }
        } else {
            // Resolve any open incident for this check.
            for inc in &mut self.incidents {
                if inc.check_name == check.name && inc.resolved_at.is_none() {
                    let started = match chrono::DateTime::parse_from_rfc3339(&inc.started_at) {
                        Ok(dt) => dt.timestamp_millis() as u64,
                        Err(_) => 0,
                    };
                    let resolved = match chrono::DateTime::parse_from_rfc3339(&check.last_checked) {
                        Ok(dt) => dt.timestamp_millis() as u64,
                        Err(_) => 0,
                    };
                    let duration = resolved.saturating_sub(started);
                    inc.resolved_at = Some(check.last_checked.clone());
                    inc.duration_ms = Some(duration);
                    info!(
                        incident_id = %inc.id,
                        duration_ms = duration,
                        "Health incident resolved"
                    );
                }
            }
        }

        self.checks.push(check);
    }

    /// Get all incidents (read-only).
    pub fn incidents(&self) -> &[HealthIncident] {
        &self.incidents
    }

    /// Get all open (unresolved) incidents.
    pub fn open_incidents(&self) -> Vec<&HealthIncident> {
        self.incidents
            .iter()
            .filter(|inc| inc.resolved_at.is_none())
            .collect()
    }

    /// Generate a summary of all incidents.
    pub fn incident_summary(&self) -> IncidentSummary {
        let total = self.incidents.len() as u64;
        let open = self.open_incidents().len() as u64;

        let resolved_durations: Vec<u64> = self
            .incidents
            .iter()
            .filter_map(|inc| inc.duration_ms)
            .collect();

        let avg_duration = if !resolved_durations.is_empty() {
            resolved_durations.iter().sum::<u64>() as f64 / resolved_durations.len() as f64
        } else {
            0.0
        };

        let max_duration = resolved_durations.iter().copied().max().unwrap_or(0);

        let mut per_subsystem: HashMap<String, u64> = HashMap::new();
        for inc in &self.incidents {
            *per_subsystem.entry(inc.subsystem.clone()).or_insert(0) += 1;
        }

        IncidentSummary {
            total_incidents: total,
            open_incidents: open,
            avg_duration_ms: avg_duration,
            max_duration_ms: max_duration,
            per_subsystem,
        }
    }

    /// Compute the uptime percentage across all health checks.
    ///
    /// Uptime = (healthy checks) / (total checks) * 100.
    /// Returns 100.0 if no checks have been recorded.
    pub fn uptime_pct(&self) -> f64 {
        if self.checks.is_empty() {
            return 100.0;
        }
        let healthy_count = self.checks.iter().filter(|c| c.healthy).count();
        (healthy_count as f64 / self.checks.len() as f64) * 100.0
    }

    /// Get the total number of health checks recorded.
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Get all health checks (read-only).
    pub fn checks(&self) -> &[HealthCheck] {
        &self.checks
    }
}

impl Default for SoakHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_incidents_when_all_healthy() {
        let mut monitor = SoakHealthMonitor::new();
        for _ in 0..5 {
            monitor.record_check(HealthCheck::new("db-ping", "storage", true, 5));
        }
        assert!(monitor.incidents().is_empty());
        assert!(monitor.open_incidents().is_empty());
        assert!((monitor.uptime_pct() - 100.0).abs() < 0.01);
    }

    #[test]
    fn incident_created_on_unhealthy() {
        let mut monitor = SoakHealthMonitor::new();
        monitor.record_check(
            HealthCheck::new("db-ping", "storage", false, 5000).with_details("Connection timeout"),
        );
        assert_eq!(monitor.incidents().len(), 1);
        assert_eq!(monitor.open_incidents().len(), 1);
        let inc = &monitor.incidents()[0];
        assert_eq!(inc.check_name, "db-ping");
        assert_eq!(inc.subsystem, "storage");
        assert!(inc.resolved_at.is_none());
        assert!(inc.duration_ms.is_none());
    }

    #[test]
    fn incident_resolved_on_recovery() {
        let mut monitor = SoakHealthMonitor::new();
        // Unhealthy.
        monitor.record_check(
            HealthCheck::new("api-check", "shield", false, 0)
                .with_timestamp("2025-01-01T00:00:00+00:00"),
        );
        // Healthy again 10 seconds later.
        monitor.record_check(
            HealthCheck::new("api-check", "shield", true, 5)
                .with_timestamp("2025-01-01T00:00:10+00:00"),
        );

        assert_eq!(monitor.incidents().len(), 1);
        let inc = &monitor.incidents()[0];
        assert!(inc.resolved_at.is_some());
        assert_eq!(inc.duration_ms, Some(10_000));
        assert!(monitor.open_incidents().is_empty());
    }

    #[test]
    fn uptime_calculation() {
        let mut monitor = SoakHealthMonitor::new();
        // 8 healthy, 2 unhealthy = 80% uptime.
        for _ in 0..8 {
            monitor.record_check(HealthCheck::new("check-a", "sub", true, 1));
        }
        for _ in 0..2 {
            monitor.record_check(HealthCheck::new("check-a", "sub", false, 5000));
        }
        let uptime = monitor.uptime_pct();
        assert!((uptime - 80.0).abs() < 0.01);
    }

    #[test]
    fn incident_summary_aggregation() {
        let mut monitor = SoakHealthMonitor::new();

        // Two failures for subsystem-a, one for subsystem-b.
        monitor.record_check(
            HealthCheck::new("a-check", "subsystem-a", false, 0)
                .with_timestamp("2025-01-01T00:00:00+00:00"),
        );
        monitor.record_check(
            HealthCheck::new("b-check", "subsystem-b", false, 0)
                .with_timestamp("2025-01-01T00:00:00+00:00"),
        );
        monitor.record_check(
            HealthCheck::new("a-check2", "subsystem-a", false, 0)
                .with_timestamp("2025-01-01T00:01:00+00:00"),
        );

        // Resolve the first one.
        monitor.record_check(
            HealthCheck::new("a-check", "subsystem-a", true, 5)
                .with_timestamp("2025-01-01T00:00:30+00:00"),
        );

        let summary = monitor.incident_summary();
        assert_eq!(summary.total_incidents, 3);
        assert_eq!(summary.open_incidents, 2); // a-check2 and b-check still open.
        assert_eq!(*summary.per_subsystem.get("subsystem-a").unwrap_or(&0), 2);
        assert_eq!(*summary.per_subsystem.get("subsystem-b").unwrap_or(&0), 1);
    }

    #[test]
    fn no_duplicate_incidents_for_same_check() {
        let mut monitor = SoakHealthMonitor::new();
        // Multiple unhealthy checks for the same name should only create one incident.
        monitor.record_check(HealthCheck::new("db", "storage", false, 0));
        monitor.record_check(HealthCheck::new("db", "storage", false, 0));
        monitor.record_check(HealthCheck::new("db", "storage", false, 0));
        assert_eq!(monitor.incidents().len(), 1);
        assert_eq!(monitor.open_incidents().len(), 1);
    }
}
