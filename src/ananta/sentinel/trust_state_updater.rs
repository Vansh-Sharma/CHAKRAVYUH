// Trust State Updater — bridges Sentinel's drift alerts to TrustState.
//
// When Sentinel detects drift, this component updates the
// corresponding domain trust level in TrustState.

use crate::ananta::sentinel::drift::{DriftAlert, DriftType};
use crate::ananta::trust::trust_state::{
    AlertSeverity as TrustAlertSeverity, AlertType, TrustAlert, TrustState,
};

/// Maps drift alerts to trust state updates.
pub struct TrustStateUpdater {
    /// How much to reduce trust per alert (0.0-1.0).
    trust_reduction_per_alert: f64,
    /// Minimum trust level (floor).
    min_trust: f64,
    /// Recovery rate per cycle (how much trust recovers when no alerts).
    recovery_rate: f64,
}

impl TrustStateUpdater {
    pub fn new() -> Self {
        Self {
            trust_reduction_per_alert: 0.1,
            min_trust: 0.0,
            recovery_rate: 0.01,
        }
    }

    /// Process a drift alert and update trust state.
    pub fn process_alert(&self, state: &mut TrustState, alert: &DriftAlert) {
        let domain = self.drift_to_domain(&alert.drift_type);
        let current = state.domain_level(domain);

        // Reduce trust proportional to z-score severity.
        let reduction = self.trust_reduction_per_alert * (alert.z_score.abs() / 10.0).min(1.0);

        let new_level = (current - reduction).max(self.min_trust);
        state.set_domain_level(domain, new_level);

        // Add alert to trust state.
        let severity = match alert.severity {
            super::drift::AlertSeverity::Info => TrustAlertSeverity::Info,
            super::drift::AlertSeverity::Warning => TrustAlertSeverity::Warning,
            super::drift::AlertSeverity::Critical => TrustAlertSeverity::Critical,
        };

        state.add_alert(TrustAlert {
            alert_type: AlertType::DecisionDrift,
            domain: domain.into(),
            message: format!(
                "{} drift detected: z={:.2} value={:.4} (mean={:.4})",
                alert.drift_type, alert.z_score, alert.observed_value, alert.current_mean,
            ),
            severity,
            timestamp: alert.timestamp.clone(),
            data: Some(serde_json::to_value(alert).unwrap_or_default()),
        });
    }

    /// Apply recovery to all domains (call when no alerts in cycle).
    pub fn apply_recovery(&self, state: &mut TrustState) {
        let domains: Vec<String> = state.domains.keys().cloned().collect();
        for domain in domains {
            let current = state.domain_level(&domain);
            if current < 1.0 {
                let new_level = (current + self.recovery_rate).min(1.0);
                state.set_domain_level(&domain, new_level);
            }
        }
    }

    /// Map drift type to trust domain.
    fn drift_to_domain(&self, drift: &DriftType) -> &'static str {
        match drift {
            DriftType::Decision => "decision",
            DriftType::Policy => "policy",
            DriftType::Model => "model",
            DriftType::Orchestration => "orchestration",
            DriftType::Learning => "learning",
            DriftType::Memory => "memory",
            DriftType::Configuration => "configuration",
            DriftType::Plugin => "plugin",
            DriftType::Runtime => "runtime",
            DriftType::Trust => "trust",
        }
    }
}

impl Default for TrustStateUpdater {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::sentinel::drift::AlertSeverity;

    fn make_alert(dt: DriftType, z: f64) -> DriftAlert {
        DriftAlert {
            drift_type: dt,
            z_score: z,
            current_mean: 0.5,
            current_stddev: 0.1,
            observed_value: 0.9,
            context: String::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: if z > 6.0 {
                AlertSeverity::Critical
            } else {
                AlertSeverity::Warning
            },
        }
    }

    #[test]
    fn alert_reduces_trust() {
        let updater = TrustStateUpdater::new();
        let mut state = TrustState::new();
        let initial = state.domain_level("decision");

        updater.process_alert(&mut state, &make_alert(DriftType::Decision, 5.0));
        let after = state.domain_level("decision");
        assert!(after < initial);
    }

    #[test]
    fn recovery_increases_trust() {
        let updater = TrustStateUpdater::new();
        let mut state = TrustState::new();
        state.set_domain_level("policy", 0.5);

        updater.apply_recovery(&mut state);
        let after = state.domain_level("policy");
        assert!(after > 0.5);
    }

    #[test]
    fn trust_never_goes_below_min() {
        let updater = TrustStateUpdater::new();
        let mut state = TrustState::new();

        for _ in 0..100 {
            updater.process_alert(&mut state, &make_alert(DriftType::Decision, 10.0));
        }
        assert!(state.domain_level("decision") >= 0.0);
    }

    #[test]
    fn recovery_does_not_exceed_one() {
        let updater = TrustStateUpdater::new();
        let mut state = TrustState::new();
        state.set_domain_level("model", 0.99);

        updater.apply_recovery(&mut state);
        assert!(state.domain_level("model") <= 1.0);
    }
}
