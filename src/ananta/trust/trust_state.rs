// Trust State — the current trust snapshot of the entire platform.
//
// Not a single score. A structured state that captures:
//   - Per-domain trust levels
//   - Overall trust score (weighted composite)
//   - Active alerts
//   - Trend direction (improving / degrading / stable)
//   - Last updated timestamp

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crate::ananta::TrendDirection;

/// A single domain's trust level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrust {
    /// Domain name (e.g., "decision", "policy", "learning").
    pub domain: String,
    /// Trust level 0.0 (fully untrusted) to 1.0 (fully trusted).
    pub level: f64,
    /// Trend direction.
    pub trend: TrendDirection,
    /// Number of observations that contributed to this level.
    pub observations: u64,
    /// Active alerts for this domain.
    pub alerts: Vec<TrustAlert>,
}

impl DomainTrust {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.into(),
            level: 1.0, // Start trusted.
            trend: TrendDirection::Stable,
            observations: 0,
            alerts: vec![],
        }
    }

    pub fn is_trusted(&self, threshold: f64) -> bool {
        self.level >= threshold
    }
}

/// A trust alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAlert {
    pub alert_type: AlertType,
    pub domain: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// Trust level dropped below threshold.
    TrustDegradation,
    /// Integrity check failed.
    IntegrityFailure,
    /// Decision drift detected.
    DecisionDrift,
    /// Policy changed unexpectedly.
    PolicyChange,
    /// Recovery action triggered.
    RecoveryTriggered,
    /// Anomaly detected in behavior.
    AnomalyDetected,
    /// Rate of something is abnormal.
    RateAnomaly,
    /// Configuration changed.
    ConfigChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// The platform-wide trust state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustState {
    /// Per-domain trust levels.
    pub domains: HashMap<String, DomainTrust>,
    /// Active alerts (across all domains).
    pub alerts: Vec<TrustAlert>,
    /// Last updated timestamp.
    pub last_updated: String,
    /// Number of attestation cycles completed.
    pub cycle_count: u64,
}

impl TrustState {
    pub fn new() -> Self {
        let mut domains = HashMap::new();
        // Initialize all 10 trust domains.
        for domain in TrustDomain::all() {
            domains.insert(domain.to_string(), DomainTrust::new(domain));
        }
        Self {
            domains,
            alerts: vec![],
            last_updated: chrono::Utc::now().to_rfc3339(),
            cycle_count: 0,
        }
    }

    /// Get trust level for a domain.
    pub fn domain_level(&self, domain: &str) -> f64 {
        self.domains.get(domain).map(|d| d.level).unwrap_or(1.0)
    }

    /// Set trust level for a domain.
    pub fn set_domain_level(&mut self, domain: &str, level: f64) {
        if let Some(d) = self.domains.get_mut(domain) {
            let old = d.level;
            d.level = level.clamp(0.0, 1.0);
            d.trend = if (d.level - old).abs() < 0.01 {
                TrendDirection::Stable
            } else if d.level > old {
                TrendDirection::Improving
            } else {
                TrendDirection::Degrading
            };
            d.observations += 1;
        }
    }

    /// Add an alert.
    pub fn add_alert(&mut self, alert: TrustAlert) {
        // Also add to the domain's alerts.
        if let Some(domain) = self.domains.get_mut(&alert.domain) {
            domain.alerts.push(alert.clone());
        }
        self.alerts.push(alert);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Clear alerts below a severity.
    pub fn clear_alerts_below(&mut self, min_severity: &AlertSeverity) {
        self.alerts.retain(|a| a.severity >= *min_severity);
        for domain in self.domains.values_mut() {
            domain.alerts.retain(|a| a.severity >= *min_severity);
        }
    }

    /// Compute overall trust score (weighted average of all domains).
    pub fn overall_score(&self) -> f64 {
        if self.domains.is_empty() {
            return 1.0;
        }

        let weights: HashMap<&str, f64> = TrustDomain::weights();
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        for (domain, dt) in &self.domains {
            let w = weights.get(domain.as_str()).copied().unwrap_or(1.0);
            weighted_sum += dt.level * w;
            total_weight += w;
        }

        if total_weight == 0.0 {
            return 1.0;
        }
        weighted_sum / total_weight
    }

    /// Record a cycle.
    pub fn record_cycle(&mut self) {
        self.cycle_count += 1;
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Count critical alerts.
    pub fn critical_count(&self) -> usize {
        self.alerts.iter().filter(|a| a.severity == AlertSeverity::Critical).count()
    }

    /// Summary.
    pub fn summary(&self) -> String {
        format!(
            "trust={:.3} domains={} alerts={} cycles={}",
            self.overall_score(),
            self.domains.len(),
            self.alerts.len(),
            self.cycle_count,
        )
    }
}

/// The 10 trust domains that ANANTA monitors.
pub struct TrustDomain;

impl TrustDomain {
    /// All 10 trust domains.
    pub fn all() -> &'static [&'static str] {
        &[
            "decision",       // Decision drift
            "policy",         // Policy drift
            "model",          // Model drift (ring behavior)
            "orchestration",  // Orchestration drift
            "learning",       // Learning drift
            "memory",         // Memory drift
            "configuration",  // Configuration drift
            "plugin",         // Plugin drift
            "runtime",        // Runtime drift
            "performance",    // Performance drift
            "trust",          // Trust drift (meta)
        ]
    }

    /// Weights for each domain (higher = more impact on overall score).
    pub fn weights() -> HashMap<&'static str, f64> {
        let mut w = HashMap::new();
        w.insert("decision", 2.0);
        w.insert("policy", 2.5);
        w.insert("orchestration", 2.0);
        w.insert("learning", 1.5);
        w.insert("configuration", 2.0);
        w.insert("runtime", 1.0);
        w.insert("trust", 3.0); // Meta-trust is most important.
        w.insert("model", 1.5);
        w.insert("memory", 1.0);
        w.insert("plugin", 1.0);
        w.insert("performance", 0.5);
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trust_state_all_domains() {
        let state = TrustState::new();
        assert_eq!(state.domains.len(), 11); // 10 + trust
        assert_eq!(state.overall_score(), 1.0);
    }

    #[test]
    fn set_domain_level_affects_overall() {
        let mut state = TrustState::new();
        state.set_domain_level("decision", 0.0);
        assert!(state.overall_score() < 1.0);
    }

    #[test]
    fn trend_detection() {
        let mut state = TrustState::new();
        state.set_domain_level("policy", 0.8);
        let domain = state.domains.get("policy").unwrap();
        assert_eq!(domain.trend, TrendDirection::Degrading);
    }

    #[test]
    fn add_and_clear_alerts() {
        let mut state = TrustState::new();
        state.add_alert(TrustAlert {
            alert_type: AlertType::IntegrityFailure,
            domain: "config".into(),
            message: "config tampered".into(),
            severity: AlertSeverity::Critical,
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: None,
        });
        assert_eq!(state.critical_count(), 1);

        state.clear_alerts_below(&AlertSeverity::Critical);
        assert_eq!(state.critical_count(), 1);

        state.clear_alerts_below(&AlertSeverity::Warning);
        assert_eq!(state.critical_count(), 1);
    }

    #[test]
    fn record_cycle() {
        let mut state = TrustState::new();
        state.record_cycle();
        state.record_cycle();
        assert_eq!(state.cycle_count, 2);
    }

    #[test]
    fn weights_sum_reasonable() {
        let weights = TrustDomain::weights();
        let total: f64 = weights.values().sum();
        // Should be in a reasonable range.
        assert!(total > 10.0 && total < 30.0);
    }
}
