// Alerting Engine — Rules-based alerting for the CHAKRAVYUH security gateway
//
// Provides:
//   - AlertCondition: Threshold, Anomaly, RateOfChange, Composite
//   - AnomalyDetector: Welford's online algorithm for running mean/std_dev,
//     z-score based anomaly detection
//   - AlertingEngine: rule management, evaluation, lifecycle
//   - DefaultAlertRules: built-in security rules
//
// No external crate dependencies — uses std + serde only.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────
// AlertSeverity
// ────────────────────────────────────────────────────────────────────

/// Severity level for alerts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    Info = 0,
    Warning = 1,
    Critical = 2,
    Emergency = 3,
}

impl AlertSeverity {
    /// Numeric value for comparison.
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }

    /// Short string label.
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
            AlertSeverity::Emergency => "emergency",
        }
    }
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ────────────────────────────────────────────────────────────────────
// AlertState
// ────────────────────────────────────────────────────────────────────

/// Lifecycle state of an alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertState {
    /// Alert has fired and is currently active.
    Active,
    /// Alert has been acknowledged by an operator.
    Acknowledged,
    /// Alert condition has resolved.
    Resolved,
    /// Alert is suppressed (e.g., maintenance mode).
    Suppressed,
}

impl AlertState {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertState::Active => "active",
            AlertState::Acknowledged => "acknowledged",
            AlertState::Resolved => "resolved",
            AlertState::Suppressed => "suppressed",
        }
    }
}

impl std::fmt::Display for AlertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ────────────────────────────────────────────────────────────────────
// ThresholdOperator
// ────────────────────────────────────────────────────────────────────

/// Comparison operator for threshold conditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThresholdOperator {
    Gt,  // >
    Gte, // >=
    Lt,  // <
    Lte, // <=
    Eq,  // ==
    Neq, // !=
}

impl ThresholdOperator {
    /// Evaluate this operator against two f64 values.
    pub fn evaluate(&self, actual: f64, threshold: f64) -> bool {
        match self {
            ThresholdOperator::Gt => actual > threshold,
            ThresholdOperator::Gte => actual >= threshold,
            ThresholdOperator::Lt => actual < threshold,
            ThresholdOperator::Lte => actual <= threshold,
            ThresholdOperator::Eq => (actual - threshold).abs() < 1e-9,
            ThresholdOperator::Neq => (actual - threshold).abs() >= 1e-9,
        }
    }

    /// String representation for display.
    pub fn as_str(&self) -> &'static str {
        match self {
            ThresholdOperator::Gt => ">",
            ThresholdOperator::Gte => ">=",
            ThresholdOperator::Lt => "<",
            ThresholdOperator::Lte => "<=",
            ThresholdOperator::Eq => "==",
            ThresholdOperator::Neq => "!=",
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// AlertCondition
// ────────────────────────────────────────────────────────────────────

/// Conditions that can trigger an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// Static threshold comparison.
    Threshold {
        metric_name: String,
        operator: ThresholdOperator,
        threshold: f64,
    },
    /// Anomaly detection using z-score deviation.
    Anomaly {
        metric_name: String,
        z_score_threshold: f64,
    },
    /// Rate of change: checks if metric delta exceeds threshold.
    RateOfChange {
        metric_name: String,
        operator: ThresholdOperator,
        rate_threshold: f64,
    },
    /// Composite condition: combines sub-conditions with AND/OR logic.
    Composite {
        rules: Vec<AlertCondition>,
        logic: CompositeLogic,
    },
}

/// Logic for combining composite conditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CompositeLogic {
    /// All sub-conditions must be true.
    And,
    /// Any sub-condition must be true.
    Or,
}

impl AlertCondition {
    /// Evaluate this condition against a metrics snapshot.
    pub fn evaluate(&self, metrics: &HashMap<String, f64>) -> bool {
        match self {
            AlertCondition::Threshold {
                metric_name,
                operator,
                threshold,
            } => {
                let actual = metrics.get(metric_name).copied().unwrap_or(0.0);
                operator.evaluate(actual, *threshold)
            }
            AlertCondition::Anomaly {
                metric_name,
                z_score_threshold,
            } => {
                // Anomaly evaluation requires historical data from the engine.
                // When called from the condition directly, we use a simple
                // deviation check: if the value is significantly different
                // from a baseline of 0, flag it.
                let actual = metrics.get(metric_name).copied().unwrap_or(0.0);
                actual.abs() > *z_score_threshold
            }
            AlertCondition::RateOfChange {
                metric_name,
                operator,
                rate_threshold,
            } => {
                // Rate of change needs previous value; return false if not
                // available in the snapshot (handled by the engine).
                let rate = metrics
                    .get(&format!("{}_rate", metric_name))
                    .copied()
                    .unwrap_or(0.0);
                operator.evaluate(rate, *rate_threshold)
            }
            AlertCondition::Composite { rules, logic } => {
                if rules.is_empty() {
                    return false;
                }
                match logic {
                    CompositeLogic::And => rules.iter().all(|r| r.evaluate(metrics)),
                    CompositeLogic::Or => rules.iter().any(|r| r.evaluate(metrics)),
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Alert
// ────────────────────────────────────────────────────────────────────

/// A fired alert with full lifecycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID.
    pub id: String,
    /// ID of the rule that triggered this alert.
    pub rule_id: String,
    /// Name of the rule.
    pub rule_name: String,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Current state.
    pub state: AlertState,
    /// Alert message (resolved from template).
    pub message: String,
    /// Metric values at the time the alert fired.
    pub metric_values: HashMap<String, f64>,
    /// Unix epoch timestamp when the alert was created.
    pub fired_at: f64,
    /// Unix epoch timestamp when the alert was acknowledged (if applicable).
    pub acknowledged_at: Option<f64>,
    /// Unix epoch timestamp when the alert was resolved (if applicable).
    pub resolved_at: Option<f64>,
}

impl Alert {
    /// Create a new active alert.
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        severity: AlertSeverity,
        message: &str,
        metric_values: HashMap<String, f64>,
    ) -> Self {
        Self {
            id: alert_id(),
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            severity,
            state: AlertState::Active,
            message: message.to_string(),
            metric_values,
            fired_at: unix_epoch_secs(),
            acknowledged_at: None,
            resolved_at: None,
        }
    }

    /// Acknowledge this alert.
    pub fn acknowledge(&mut self) {
        if self.state == AlertState::Active {
            self.state = AlertState::Acknowledged;
            self.acknowledged_at = Some(unix_epoch_secs());
        }
    }

    /// Resolve this alert.
    pub fn resolve(&mut self) {
        if self.state == AlertState::Active || self.state == AlertState::Acknowledged {
            self.state = AlertState::Resolved;
            self.resolved_at = Some(unix_epoch_secs());
        }
    }

    /// Suppress this alert.
    pub fn suppress(&mut self) {
        if self.state == AlertState::Active || self.state == AlertState::Acknowledged {
            self.state = AlertState::Suppressed;
        }
    }

    /// Whether this alert is still actionable.
    pub fn is_active(&self) -> bool {
        matches!(self.state, AlertState::Active | AlertState::Acknowledged)
    }
}

// ────────────────────────────────────────────────────────────────────
// AlertRule
// ────────────────────────────────────────────────────────────────────

/// A rule that can generate alerts when its condition is met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule ID.
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// The condition that triggers the alert.
    pub condition: AlertCondition,
    /// Alert severity when fired.
    pub severity: AlertSeverity,
    /// Message template (can include {metric_name} placeholders).
    pub message_template: String,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl AlertRule {
    /// Evaluate this rule against a metrics snapshot.
    pub fn evaluate(&self, metrics: &HashMap<String, f64>) -> bool {
        if !self.enabled {
            return false;
        }
        self.condition.evaluate(metrics)
    }

    /// Generate an alert message by substituting metric values into the template.
    pub fn render_message(&self, metrics: &HashMap<String, f64>) -> String {
        let mut msg = self.message_template.clone();
        for (key, value) in metrics {
            msg = msg.replace(&format!("{{{}}}", key), &format!("{:.4}", value));
        }
        // Also replace common placeholders
        msg = msg.replace("{severity}", self.severity.as_str());
        msg = msg.replace("{rule_name}", &self.name);
        msg
    }
}

// ────────────────────────────────────────────────────────────────────
// AnomalyDetector — Welford's online algorithm
// ────────────────────────────────────────────────────────────────────

/// Online anomaly detector using Welford's algorithm for running
/// mean and variance computation with z-score based detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetector {
    /// Running count of observations.
    count: u64,
    /// Running mean.
    mean: f64,
    /// Running M2 (sum of squared differences from mean).
    m2: f64,
    /// Z-score threshold for anomaly detection.
    z_threshold: f64,
    /// Historical values for rate-of-change computation (circular buffer).
    history: Vec<f64>,
    /// Maximum history size.
    max_history: usize,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with a given z-score threshold.
    /// Values with |z-score| > threshold are considered anomalous.
    pub fn new(z_threshold: f64) -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            z_threshold,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Create a new anomaly detector with a z-score threshold of 3.0 (standard).
    pub fn standard() -> Self {
        Self::new(3.0)
    }

    /// Create a new anomaly detector with a z-score threshold of 2.0 (sensitive).
    pub fn sensitive() -> Self {
        Self::new(2.0)
    }

    /// Update the detector with a new observation using Welford's algorithm.
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        // Update history buffer
        self.history.push(value);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Compute the current standard deviation.
    pub fn std_dev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let variance = self.m2 / (self.count - 1) as f64;
        variance.sqrt()
    }

    /// Compute the z-score of a new value.
    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd < 1e-12 {
            if (value - self.mean).abs() < 1e-12 {
                return 0.0;
            }
            return f64::INFINITY;
        }
        (value - self.mean).abs() / sd
    }

    /// Check if a value is anomalous based on the z-score threshold.
    pub fn is_anomalous(&self, value: f64) -> bool {
        self.z_score(value) > self.z_threshold
    }

    /// Compute the rate of change between the most recent two observations.
    pub fn rate_of_change(&self) -> f64 {
        if self.history.len() < 2 {
            return 0.0;
        }
        let len = self.history.len();
        let prev = self.history[len - 2];
        let curr = self.history[len - 1];
        curr - prev
    }

    /// Number of observations processed.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Current running mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Reset the detector.
    pub fn reset(&mut self) {
        self.count = 0;
        self.mean = 0.0;
        self.m2 = 0.0;
        self.history.clear();
    }
}

// ────────────────────────────────────────────────────────────────────
// MetricsSnapshot — input to rule evaluation
// ────────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of metric values for rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub values: HashMap<String, f64>,
    pub timestamp: f64,
}

impl MetricsSnapshot {
    /// Create an empty snapshot.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            timestamp: unix_epoch_secs(),
        }
    }

    /// Create a snapshot with the given values.
    pub fn from_map(values: HashMap<String, f64>) -> Self {
        Self {
            values,
            timestamp: unix_epoch_secs(),
        }
    }

    /// Get a metric value, defaulting to 0.0 if not present.
    pub fn get(&self, name: &str) -> f64 {
        self.values.get(name).copied().unwrap_or(0.0)
    }

    /// Set a metric value.
    pub fn set(&mut self, name: &str, value: f64) {
        self.values.insert(name.to_string(), value);
    }
}

impl Default for MetricsSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────
// AlertingEngine
// ────────────────────────────────────────────────────────────────────

/// The main alerting engine that manages rules, evaluates conditions,
/// and tracks alert lifecycles.
pub struct AlertingEngine {
    rules: std::sync::Mutex<Vec<AlertRule>>,
    active_alerts: std::sync::Mutex<Vec<Alert>>,
    resolved_alerts: std::sync::Mutex<Vec<Alert>>,
    anomaly_detectors: std::sync::Mutex<HashMap<String, AnomalyDetector>>,
    previous_metrics: std::sync::Mutex<HashMap<String, f64>>,
}

impl AlertingEngine {
    /// Create a new alerting engine.
    pub fn new() -> Self {
        Self {
            rules: std::sync::Mutex::new(Vec::new()),
            active_alerts: std::sync::Mutex::new(Vec::new()),
            resolved_alerts: std::sync::Mutex::new(Vec::new()),
            anomaly_detectors: std::sync::Mutex::new(HashMap::new()),
            previous_metrics: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Add a new alerting rule.
    pub fn add_rule(&self, rule: AlertRule) {
        if let Ok(mut rules) = self.rules.lock() {
            // Remove existing rule with the same ID
            rules.retain(|r| r.id != rule.id);
            rules.push(rule);
        }
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, rule_id: &str) -> bool {
        if let Ok(mut rules) = self.rules.lock() {
            let before = rules.len();
            rules.retain(|r| r.id != rule_id);
            rules.len() < before
        } else {
            false
        }
    }

    /// Get all registered rules.
    pub fn rules(&self) -> Vec<AlertRule> {
        self.rules.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Evaluate all rules against the given metrics snapshot.
    /// Returns a list of newly fired alerts.
    pub fn evaluate(&self, snapshot: &MetricsSnapshot) -> Vec<Alert> {
        let mut new_alerts = Vec::new();

        // First, update anomaly detectors for any Anomaly conditions
        if let Ok(mut detectors) = self.anomaly_detectors.lock() {
            if let Ok(rules) = self.rules.lock() {
                for rule in rules.iter() {
                    if let AlertCondition::Anomaly { metric_name, .. } = &rule.condition {
                        let value = snapshot.get(metric_name);
                        let detector = detectors
                            .entry(metric_name.clone())
                            .or_insert_with(AnomalyDetector::standard);
                        detector.update(value);
                        // Add the z-score to the snapshot values for condition evaluation
                        let z = detector.z_score(value);
                        // We store the z-score in the snapshot for the condition to use
                        // But since we can't mutate snapshot, we'll handle it in the condition check
                        let _ = snapshot;
                        // Re-evaluate with anomaly data
                        let is_anomalous = detector.is_anomalous(value);
                        if is_anomalous && rule.enabled {
                            let mut metric_values = snapshot.values.clone();
                            metric_values.insert(format!("{}_z_score", metric_name), z);
                            let message = rule.render_message(&metric_values);
                            let alert = Alert::new(
                                &rule.id,
                                &rule.name,
                                rule.severity,
                                &message,
                                metric_values,
                            );
                            new_alerts.push(alert);
                        }
                        continue;
                    }
                }
            }
        }

        // Evaluate non-anomaly rules
        if let Ok(rules) = self.rules.lock() {
            for rule in rules.iter() {
                // Skip anomaly conditions (already handled above)
                if matches!(rule.condition, AlertCondition::Anomaly { .. }) {
                    continue;
                }

                // Handle rate-of-change by computing rates
                let mut eval_values = snapshot.values.clone();
                if let AlertCondition::RateOfChange { metric_name, .. } = &rule.condition {
                    let current = snapshot.get(metric_name);
                    let rate = if let Ok(prev) = self.previous_metrics.lock() {
                        let prev_val = prev.get(metric_name).copied().unwrap_or(0.0);
                        current - prev_val
                    } else {
                        0.0
                    };
                    eval_values.insert(format!("{}_rate", metric_name), rate);
                }

                if rule.evaluate(&eval_values) {
                    // Check if we already have an active alert for this rule
                    let already_active = if let Ok(active) = self.active_alerts.lock() {
                        active.iter().any(|a| a.rule_id == rule.id && a.is_active())
                    } else {
                        false
                    };

                    if !already_active {
                        let message = rule.render_message(&eval_values);
                        let alert =
                            Alert::new(&rule.id, &rule.name, rule.severity, &message, eval_values);
                        new_alerts.push(alert);
                    }
                }
            }
        }

        // Store current metrics as previous for next evaluation
        if let Ok(mut prev) = self.previous_metrics.lock() {
            for (key, value) in &snapshot.values {
                prev.insert(key.clone(), *value);
            }
        }

        // Add new alerts to active list
        if !new_alerts.is_empty() {
            if let Ok(mut active) = self.active_alerts.lock() {
                active.extend(new_alerts.clone());
            }
        }

        // Auto-resolve alerts whose conditions are no longer met
        self.auto_resolve(snapshot);

        new_alerts
    }

    /// Acknowledge an alert by ID.
    pub fn acknowledge(&self, alert_id: &str) -> bool {
        if let Ok(mut active) = self.active_alerts.lock() {
            if let Some(alert) = active.iter_mut().find(|a| a.id == alert_id) {
                alert.acknowledge();
                return true;
            }
        }
        false
    }

    /// Resolve an alert by ID.
    pub fn resolve(&self, alert_id: &str) -> bool {
        let mut resolved_alert = None;
        if let Ok(mut active) = self.active_alerts.lock() {
            if let Some(alert) = active.iter_mut().find(|a| a.id == alert_id) {
                alert.resolve();
                resolved_alert = Some(alert.clone());
            }
        }
        if let Some(alert) = resolved_alert {
            if let Ok(mut active) = self.active_alerts.lock() {
                active.retain(|a| a.id != alert_id);
            }
            if let Ok(mut resolved) = self.resolved_alerts.lock() {
                resolved.push(alert);
            }
            return true;
        }
        false
    }

    /// Suppress an alert by ID.
    pub fn suppress(&self, alert_id: &str) -> bool {
        if let Ok(mut active) = self.active_alerts.lock() {
            if let Some(alert) = active.iter_mut().find(|a| a.id == alert_id) {
                alert.suppress();
                return true;
            }
        }
        false
    }

    /// Get all currently active (including acknowledged) alerts.
    pub fn active_alerts(&self) -> Vec<Alert> {
        self.active_alerts
            .lock()
            .map(|a| a.iter().filter(|al| al.is_active()).cloned().collect())
            .unwrap_or_default()
    }

    /// Get all resolved alerts.
    pub fn resolved_alerts(&self) -> Vec<Alert> {
        self.resolved_alerts
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Get total alert count (active + resolved).
    pub fn total_alerts(&self) -> usize {
        let active = self.active_alerts.lock().map(|a| a.len()).unwrap_or(0);
        let resolved = self.resolved_alerts.lock().map(|r| r.len()).unwrap_or(0);
        active + resolved
    }

    /// Auto-resolve alerts whose conditions are no longer met.
    fn auto_resolve(&self, snapshot: &MetricsSnapshot) {
        let to_resolve: Vec<String> = if let Ok(active) = self.active_alerts.lock() {
            let mut ids = Vec::new();
            for alert in active.iter() {
                if !alert.is_active() {
                    continue;
                }
                if let Ok(rules) = self.rules.lock() {
                    if let Some(rule) = rules.iter().find(|r| r.id == alert.rule_id) {
                        if !rule.evaluate(&snapshot.values) {
                            ids.push(alert.id.clone());
                        }
                    }
                }
            }
            ids
        } else {
            Vec::new()
        };

        for alert_id in to_resolve {
            let _ = self.resolve(&alert_id);
        }
    }

    /// Get the anomaly detector for a specific metric.
    pub fn anomaly_detector(&self, metric_name: &str) -> Option<(f64, f64, f64)> {
        self.anomaly_detectors.lock().ok().and_then(|dets| {
            dets.get(metric_name)
                .map(|d| (d.mean(), d.std_dev(), d.count() as f64))
        })
    }
}

impl Default for AlertingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────
// DefaultAlertRules — built-in security rules
// ────────────────────────────────────────────────────────────────────

/// Factory for built-in security alerting rules.
pub struct DefaultAlertRules;

impl DefaultAlertRules {
    /// Get the default set of security alerting rules.
    ///
    /// Returns 6 built-in rules:
    ///   1. High Error Rate (>5%)
    ///   2. High False Positive Rate (>20%)
    ///   3. Spike in Blocked Requests (rate > 100/sec)
    ///   4. Latency Anomaly on any ring (z-score > 3)
    ///   5. Elevated Deny Rate (>30%)
    ///   6. IP Block Anomaly (z-score > 3 on block rate)
    pub fn security_defaults() -> Vec<AlertRule> {
        vec![
            AlertRule {
                id: "high-error-rate".to_string(),
                name: "High Error Rate".to_string(),
                condition: AlertCondition::Threshold {
                    metric_name: "error_rate".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.05,
                },
                severity: AlertSeverity::Critical,
                message_template: "Error rate is {error_rate:.2%}, exceeding 5% threshold"
                    .to_string(),
                enabled: true,
            },
            AlertRule {
                id: "high-fp-rate".to_string(),
                name: "High False Positive Rate".to_string(),
                condition: AlertCondition::Threshold {
                    metric_name: "false_positive_rate".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.20,
                },
                severity: AlertSeverity::Warning,
                message_template:
                    "False positive rate is {false_positive_rate:.2%}, exceeding 20% threshold"
                        .to_string(),
                enabled: true,
            },
            AlertRule {
                id: "block-spike".to_string(),
                name: "Blocked Request Spike".to_string(),
                condition: AlertCondition::Threshold {
                    metric_name: "block_rate".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 100.0,
                },
                severity: AlertSeverity::Critical,
                message_template: "Block rate is {block_rate:.1f}/sec, exceeding 100/sec threshold"
                    .to_string(),
                enabled: true,
            },
            AlertRule {
                id: "latency-anomaly".to_string(),
                name: "Ring Latency Anomaly".to_string(),
                condition: AlertCondition::Anomaly {
                    metric_name: "avg_latency_ms".to_string(),
                    z_score_threshold: 3.0,
                },
                severity: AlertSeverity::Warning,
                message_template:
                    "Ring latency anomaly detected: z-score={avg_latency_ms_z_score:.2f}"
                        .to_string(),
                enabled: true,
            },
            AlertRule {
                id: "high-deny-rate".to_string(),
                name: "Elevated Deny Rate".to_string(),
                condition: AlertCondition::Threshold {
                    metric_name: "deny_rate".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.30,
                },
                severity: AlertSeverity::Warning,
                message_template: "Deny rate is {deny_rate:.2%}, exceeding 30% threshold"
                    .to_string(),
                enabled: true,
            },
            AlertRule {
                id: "ip-block-anomaly".to_string(),
                name: "IP Block Rate Anomaly".to_string(),
                condition: AlertCondition::Anomaly {
                    metric_name: "ip_block_rate".to_string(),
                    z_score_threshold: 3.0,
                },
                severity: AlertSeverity::Critical,
                message_template:
                    "IP block rate anomaly detected: z-score={ip_block_rate_z_score:.2f}"
                        .to_string(),
                enabled: true,
            },
        ]
    }
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Generate a unique alert ID.
fn alert_id() -> String {
    let seed = unix_epoch_secs();
    let hash = simple_hash(&format!("alert-{}", seed));
    format!("{:016x}", hash)
}

/// Get current Unix epoch in seconds as f64.
fn unix_epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Simple deterministic hash.
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AlertSeverity tests ──

    #[test]
    fn alert_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
        assert!(AlertSeverity::Critical < AlertSeverity::Emergency);
    }

    #[test]
    fn alert_severity_display() {
        assert_eq!(AlertSeverity::Info.to_string(), "info");
        assert_eq!(AlertSeverity::Emergency.to_string(), "emergency");
    }

    #[test]
    fn alert_severity_serde() {
        let s = AlertSeverity::Critical;
        let json = serde_json::to_string(&s).expect("serialize");
        let restored: AlertSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, AlertSeverity::Critical);
    }

    // ── AlertState tests ──

    #[test]
    fn alert_state_display() {
        assert_eq!(AlertState::Active.to_string(), "active");
        assert_eq!(AlertState::Resolved.to_string(), "resolved");
    }

    #[test]
    fn alert_state_serde() {
        let s = AlertState::Acknowledged;
        let json = serde_json::to_string(&s).expect("serialize");
        let restored: AlertState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, AlertState::Acknowledged);
    }

    // ── ThresholdOperator tests ──

    #[test]
    fn threshold_gt() {
        assert!(ThresholdOperator::Gt.evaluate(5.0, 3.0));
        assert!(!ThresholdOperator::Gt.evaluate(3.0, 5.0));
        assert!(!ThresholdOperator::Gt.evaluate(3.0, 3.0));
    }

    #[test]
    fn threshold_gte() {
        assert!(ThresholdOperator::Gte.evaluate(5.0, 3.0));
        assert!(ThresholdOperator::Gte.evaluate(3.0, 3.0));
        assert!(!ThresholdOperator::Gte.evaluate(2.9, 3.0));
    }

    #[test]
    fn threshold_lt() {
        assert!(ThresholdOperator::Lt.evaluate(1.0, 5.0));
        assert!(!ThresholdOperator::Lt.evaluate(5.0, 1.0));
    }

    #[test]
    fn threshold_lte() {
        assert!(ThresholdOperator::Lte.evaluate(3.0, 3.0));
        assert!(ThresholdOperator::Lte.evaluate(2.0, 3.0));
        assert!(!ThresholdOperator::Lte.evaluate(4.0, 3.0));
    }

    #[test]
    fn threshold_eq() {
        assert!(ThresholdOperator::Eq.evaluate(3.0, 3.0));
        assert!(!ThresholdOperator::Eq.evaluate(3.1, 3.0));
    }

    #[test]
    fn threshold_neq() {
        assert!(ThresholdOperator::Neq.evaluate(3.0, 4.0));
        assert!(!ThresholdOperator::Neq.evaluate(3.0, 3.0));
    }

    #[test]
    fn threshold_operator_display() {
        assert_eq!(ThresholdOperator::Gt.as_str(), ">");
        assert_eq!(ThresholdOperator::Gte.as_str(), ">=");
        assert_eq!(ThresholdOperator::Lte.as_str(), "<=");
    }

    // ── AlertCondition tests ──

    #[test]
    fn condition_threshold_true() {
        let cond = AlertCondition::Threshold {
            metric_name: "error_rate".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 0.05,
        };
        let mut metrics = HashMap::new();
        metrics.insert("error_rate".to_string(), 0.10);
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_threshold_false() {
        let cond = AlertCondition::Threshold {
            metric_name: "error_rate".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 0.05,
        };
        let mut metrics = HashMap::new();
        metrics.insert("error_rate".to_string(), 0.01);
        assert!(!cond.evaluate(&metrics));
    }

    #[test]
    fn condition_threshold_missing_metric() {
        let cond = AlertCondition::Threshold {
            metric_name: "missing".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 0.05,
        };
        let metrics = HashMap::new();
        // Missing metric defaults to 0.0
        assert!(!cond.evaluate(&metrics));
    }

    #[test]
    fn condition_anomaly_basic() {
        let cond = AlertCondition::Anomaly {
            metric_name: "latency".to_string(),
            z_score_threshold: 5.0,
        };
        let mut metrics = HashMap::new();
        metrics.insert("latency".to_string(), 10.0);
        // Direct evaluation: 10.0 > 5.0 → true
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_anomaly_low_value() {
        let cond = AlertCondition::Anomaly {
            metric_name: "latency".to_string(),
            z_score_threshold: 100.0,
        };
        let mut metrics = HashMap::new();
        metrics.insert("latency".to_string(), 10.0);
        assert!(!cond.evaluate(&metrics));
    }

    #[test]
    fn condition_rate_of_change() {
        let cond = AlertCondition::RateOfChange {
            metric_name: "requests".to_string(),
            operator: ThresholdOperator::Gt,
            rate_threshold: 50.0,
        };
        let mut metrics = HashMap::new();
        metrics.insert("requests_rate".to_string(), 100.0);
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_composite_and_all_true() {
        let cond = AlertCondition::Composite {
            rules: vec![
                AlertCondition::Threshold {
                    metric_name: "a".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.0,
                },
                AlertCondition::Threshold {
                    metric_name: "b".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.0,
                },
            ],
            logic: CompositeLogic::And,
        };
        let mut metrics = HashMap::new();
        metrics.insert("a".to_string(), 1.0);
        metrics.insert("b".to_string(), 1.0);
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_composite_and_partial() {
        let cond = AlertCondition::Composite {
            rules: vec![
                AlertCondition::Threshold {
                    metric_name: "a".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.0,
                },
                AlertCondition::Threshold {
                    metric_name: "b".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 10.0,
                },
            ],
            logic: CompositeLogic::And,
        };
        let mut metrics = HashMap::new();
        metrics.insert("a".to_string(), 1.0);
        metrics.insert("b".to_string(), 5.0); // not > 10
        assert!(!cond.evaluate(&metrics));
    }

    #[test]
    fn condition_composite_or_any_true() {
        let cond = AlertCondition::Composite {
            rules: vec![
                AlertCondition::Threshold {
                    metric_name: "a".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 10.0,
                },
                AlertCondition::Threshold {
                    metric_name: "b".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 10.0,
                },
            ],
            logic: CompositeLogic::Or,
        };
        let mut metrics = HashMap::new();
        metrics.insert("a".to_string(), 1.0);
        metrics.insert("b".to_string(), 15.0);
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_composite_empty() {
        let cond = AlertCondition::Composite {
            rules: vec![],
            logic: CompositeLogic::And,
        };
        let metrics = HashMap::new();
        assert!(!cond.evaluate(&metrics));
    }

    #[test]
    fn condition_nested_composite() {
        let cond = AlertCondition::Composite {
            rules: vec![
                AlertCondition::Composite {
                    rules: vec![AlertCondition::Threshold {
                        metric_name: "a".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.0,
                    }],
                    logic: CompositeLogic::Or,
                },
                AlertCondition::Threshold {
                    metric_name: "b".to_string(),
                    operator: ThresholdOperator::Gt,
                    threshold: 0.0,
                },
            ],
            logic: CompositeLogic::And,
        };
        let mut metrics = HashMap::new();
        metrics.insert("a".to_string(), 1.0);
        metrics.insert("b".to_string(), 1.0);
        assert!(cond.evaluate(&metrics));
    }

    #[test]
    fn condition_serde_roundtrip() {
        let cond = AlertCondition::Threshold {
            metric_name: "test".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 5.0,
        };
        let json = serde_json::to_string(&cond).expect("serialize");
        let restored: AlertCondition = serde_json::from_str(&json).expect("deserialize");
        match restored {
            AlertCondition::Threshold { metric_name, .. } => {
                assert_eq!(metric_name, "test");
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Alert tests ──

    #[test]
    fn alert_new() {
        let mut metrics = HashMap::new();
        metrics.insert("error_rate".to_string(), 0.10);
        let alert = Alert::new(
            "rule-1",
            "High Error Rate",
            AlertSeverity::Critical,
            "Error rate is 10%",
            metrics,
        );
        assert_eq!(alert.rule_id, "rule-1");
        assert_eq!(alert.state, AlertState::Active);
        assert!(alert.is_active());
        assert!(alert.acknowledged_at.is_none());
    }

    #[test]
    fn alert_acknowledge() {
        let mut alert = Alert::new("r1", "Test", AlertSeverity::Warning, "msg", HashMap::new());
        alert.acknowledge();
        assert_eq!(alert.state, AlertState::Acknowledged);
        assert!(alert.is_active());
        assert!(alert.acknowledged_at.is_some());
    }

    #[test]
    fn alert_resolve() {
        let mut alert = Alert::new("r1", "Test", AlertSeverity::Critical, "msg", HashMap::new());
        alert.resolve();
        assert_eq!(alert.state, AlertState::Resolved);
        assert!(!alert.is_active());
        assert!(alert.resolved_at.is_some());
    }

    #[test]
    fn alert_resolve_after_acknowledge() {
        let mut alert = Alert::new("r1", "Test", AlertSeverity::Warning, "msg", HashMap::new());
        alert.acknowledge();
        alert.resolve();
        assert_eq!(alert.state, AlertState::Resolved);
        assert!(!alert.is_active());
    }

    #[test]
    fn alert_suppress() {
        let mut alert = Alert::new("r1", "Test", AlertSeverity::Info, "msg", HashMap::new());
        alert.suppress();
        assert_eq!(alert.state, AlertState::Suppressed);
        assert!(!alert.is_active());
    }

    #[test]
    fn alert_acknowledge_already_resolved_noop() {
        let mut alert = Alert::new("r1", "Test", AlertSeverity::Info, "msg", HashMap::new());
        alert.resolve();
        alert.acknowledge(); // Should not change state
        assert_eq!(alert.state, AlertState::Resolved);
    }

    #[test]
    fn alert_serde_roundtrip() {
        let alert = Alert::new(
            "r1",
            "Test Alert",
            AlertSeverity::Critical,
            "test msg",
            HashMap::new(),
        );
        let json = serde_json::to_string(&alert).expect("serialize");
        let restored: Alert = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.rule_id, "r1");
        assert_eq!(restored.severity, AlertSeverity::Critical);
    }

    // ── AlertRule tests ──

    #[test]
    fn alert_rule_evaluate_true() {
        let rule = AlertRule {
            id: "test".to_string(),
            name: "Test Rule".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 5.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "x is high".to_string(),
            enabled: true,
        };
        let mut metrics = HashMap::new();
        metrics.insert("x".to_string(), 10.0);
        assert!(rule.evaluate(&metrics));
    }

    #[test]
    fn alert_rule_evaluate_disabled() {
        let rule = AlertRule {
            id: "test".to_string(),
            name: "Test Rule".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 5.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "x is high".to_string(),
            enabled: false,
        };
        let mut metrics = HashMap::new();
        metrics.insert("x".to_string(), 100.0);
        assert!(!rule.evaluate(&metrics));
    }

    #[test]
    fn alert_rule_render_message() {
        let rule = AlertRule {
            id: "test".to_string(),
            name: "Error Alert".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "error_rate".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.05,
            },
            severity: AlertSeverity::Critical,
            message_template: "Error rate is {error_rate}, severity: {severity}".to_string(),
            enabled: true,
        };
        let mut metrics = HashMap::new();
        metrics.insert("error_rate".to_string(), 0.10);
        let msg = rule.render_message(&metrics);
        assert!(msg.contains("0.1000"));
        assert!(msg.contains("critical"));
    }

    #[test]
    fn alert_rule_serde_roundtrip() {
        let rule = AlertRule {
            id: "test-rule".to_string(),
            name: "Test".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "m".to_string(),
                operator: ThresholdOperator::Lt,
                threshold: 1.0,
            },
            severity: AlertSeverity::Info,
            message_template: "msg".to_string(),
            enabled: true,
        };
        let json = serde_json::to_string(&rule).expect("serialize");
        let restored: AlertRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.id, "test-rule");
        assert_eq!(restored.severity, AlertSeverity::Info);
    }

    // ── AnomalyDetector tests ──

    #[test]
    fn anomaly_detector_new() {
        let det = AnomalyDetector::new(3.0);
        assert_eq!(det.count(), 0);
        assert_eq!(det.mean(), 0.0);
    }

    #[test]
    fn anomaly_detector_standard() {
        let det = AnomalyDetector::standard();
        assert_eq!(det.count(), 0);
    }

    #[test]
    fn welford_single_value() {
        let mut det = AnomalyDetector::new(3.0);
        det.update(10.0);
        assert_eq!(det.count(), 1);
        assert_eq!(det.mean(), 10.0);
        assert_eq!(det.std_dev(), 0.0); // need >= 2 values for std_dev
    }

    #[test]
    fn welford_two_values() {
        let mut det = AnomalyDetector::new(3.0);
        det.update(10.0);
        det.update(20.0);
        assert_eq!(det.count(), 2);
        assert_eq!(det.mean(), 15.0);
        // Variance = ((10-15)^2 + (20-15)^2) / (2-1) = 50, std_dev = sqrt(50)
        let expected_sd = 50.0_f64.sqrt();
        assert!(
            (det.std_dev() - expected_sd).abs() < 1e-9,
            "std_dev={}, expected={}",
            det.std_dev(),
            expected_sd
        );
    }

    #[test]
    fn welford_many_values_mean() {
        let mut det = AnomalyDetector::new(3.0);
        for v in [2.0, 4.0, 6.0, 8.0, 10.0] {
            det.update(v);
        }
        assert_eq!(det.mean(), 6.0);
    }

    #[test]
    fn welford_known_variance() {
        let mut det = AnomalyDetector::new(3.0);
        // Values: 2, 4, 4, 4, 5, 5, 7, 9
        // Mean = 40/8 = 5.0
        // Variance = ((2-5)^2 + (4-5)^2*3 + (5-5)^2*2 + (7-5)^2 + (9-5)^2) / 7
        //           = (9 + 3 + 0 + 4 + 16) / 7 = 32/7 ≈ 4.571
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            det.update(v);
        }
        assert_eq!(det.count(), 8);
        assert!(
            (det.mean() - 5.0).abs() < 1e-9,
            "mean={}, expected=5.0",
            det.mean()
        );
        let expected_var = 32.0 / 7.0;
        let actual_var = det.std_dev().powi(2);
        assert!(
            (actual_var - expected_var).abs() < 1e-9,
            "variance={}, expected={}",
            actual_var,
            expected_var
        );
    }

    #[test]
    fn anomaly_z_score_normal() {
        let mut det = AnomalyDetector::new(3.0);
        // Feed stable values
        for _ in 0..100 {
            det.update(10.0);
        }
        // A value close to the mean should have a low z-score
        let z = det.z_score(10.0);
        assert!(z < 1.0, "z-score should be near 0, got {}", z);
    }

    #[test]
    fn anomaly_z_score_anomalous() {
        let mut det = AnomalyDetector::new(3.0);
        // Feed stable values at 10.0
        for _ in 0..100 {
            det.update(10.0);
        }
        // An extreme outlier should have a high z-score
        let z = det.z_score(100.0);
        assert!(z > 3.0, "z-score should be > 3.0 for outlier, got {}", z);
    }

    #[test]
    fn anomaly_is_anomalous_false_for_normal() {
        let mut det = AnomalyDetector::new(3.0);
        for _ in 0..100 {
            det.update(10.0);
        }
        assert!(!det.is_anomalous(10.0));
    }

    #[test]
    fn anomaly_is_anomalous_true_for_outlier() {
        let mut det = AnomalyDetector::new(3.0);
        for _ in 0..100 {
            det.update(10.0);
        }
        assert!(det.is_anomalous(100.0));
    }

    #[test]
    fn anomaly_rate_of_change() {
        let mut det = AnomalyDetector::new(3.0);
        det.update(10.0);
        det.update(15.0);
        let rate = det.rate_of_change();
        assert_eq!(rate, 5.0);
    }

    #[test]
    fn anomaly_rate_of_change_insufficient() {
        let det = AnomalyDetector::new(3.0);
        assert_eq!(det.rate_of_change(), 0.0);
    }

    #[test]
    fn anomaly_reset() {
        let mut det = AnomalyDetector::new(3.0);
        det.update(10.0);
        det.update(20.0);
        assert_eq!(det.count(), 2);
        det.reset();
        assert_eq!(det.count(), 0);
        assert_eq!(det.mean(), 0.0);
    }

    #[test]
    fn anomaly_sensitive_detector() {
        let det = AnomalyDetector::sensitive();
        // Sensitive has z_threshold = 2.0
        let mut det = det;
        for _ in 0..100 {
            det.update(10.0);
        }
        // With threshold 2.0, a value of 30 might be anomalous
        // z-score = (30 - 10) / sd, where sd is very small for constant input
        // Actually sd=0 so z-score=0, let's add some variance
        let mut det2 = AnomalyDetector::sensitive();
        for v in [9.0, 10.0, 11.0, 9.5, 10.5, 9.0, 10.0, 11.0]
            .iter()
            .cycle()
            .take(100)
        {
            det2.update(*v);
        }
        let z = det2.z_score(20.0);
        assert!(
            z > 2.0,
            "sensitive z-score should detect anomaly, got {}",
            z
        );
    }

    // ── MetricsSnapshot tests ──

    #[test]
    fn snapshot_new() {
        let snap = MetricsSnapshot::new();
        assert!(snap.values.is_empty());
        assert_eq!(snap.get("anything"), 0.0);
    }

    #[test]
    fn snapshot_from_map() {
        let mut m = HashMap::new();
        m.insert("error_rate".to_string(), 0.05);
        let snap = MetricsSnapshot::from_map(m);
        assert_eq!(snap.get("error_rate"), 0.05);
    }

    #[test]
    fn snapshot_set_get() {
        let mut snap = MetricsSnapshot::new();
        snap.set("latency", 42.0);
        assert_eq!(snap.get("latency"), 42.0);
    }

    // ── AlertingEngine tests ──

    #[test]
    fn engine_new() {
        let engine = AlertingEngine::new();
        assert_eq!(engine.rules().len(), 0);
        assert_eq!(engine.active_alerts().len(), 0);
        assert_eq!(engine.total_alerts(), 0);
    }

    #[test]
    fn engine_add_remove_rule() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "Rule 1".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 5.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "x is high".to_string(),
            enabled: true,
        });
        assert_eq!(engine.rules().len(), 1);

        assert!(engine.remove_rule("r1"));
        assert_eq!(engine.rules().len(), 0);

        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn engine_evaluate_no_rules() {
        let engine = AlertingEngine::new();
        let snap = MetricsSnapshot::new();
        let alerts = engine.evaluate(&snap);
        assert!(alerts.is_empty());
    }

    #[test]
    fn engine_evaluate_threshold_fires() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "High Error".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "error_rate".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.05,
            },
            severity: AlertSeverity::Critical,
            message_template: "error rate high".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("error_rate", 0.10);
        let alerts = engine.evaluate(&snap);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "r1");
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn engine_evaluate_threshold_no_fire() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "High Error".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "error_rate".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.05,
            },
            severity: AlertSeverity::Critical,
            message_template: "error rate high".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("error_rate", 0.01);
        let alerts = engine.evaluate(&snap);
        assert!(alerts.is_empty());
    }

    #[test]
    fn engine_no_duplicate_active_alerts() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "High Error".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "error_rate".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.05,
            },
            severity: AlertSeverity::Critical,
            message_template: "error".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("error_rate", 0.10);

        let alerts1 = engine.evaluate(&snap);
        let alerts2 = engine.evaluate(&snap);

        assert_eq!(alerts1.len(), 1);
        assert_eq!(alerts2.len(), 0); // No duplicate
    }

    #[test]
    fn engine_auto_resolve() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "High Error".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "error_rate".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.05,
            },
            severity: AlertSeverity::Critical,
            message_template: "error".to_string(),
            enabled: true,
        });

        // Fire the alert
        let mut snap = MetricsSnapshot::new();
        snap.set("error_rate", 0.10);
        engine.evaluate(&snap);
        assert_eq!(engine.active_alerts().len(), 1);

        // Condition no longer met → auto-resolve
        let mut snap2 = MetricsSnapshot::new();
        snap2.set("error_rate", 0.01);
        engine.evaluate(&snap2);
        assert_eq!(engine.active_alerts().len(), 0);
        assert_eq!(engine.resolved_alerts().len(), 1);
    }

    #[test]
    fn engine_acknowledge_alert() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "Test".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "x".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("x", 1.0);
        engine.evaluate(&snap);

        let active = engine.active_alerts();
        assert!(engine.acknowledge(&active[0].id));
        let active_after = engine.active_alerts();
        assert_eq!(active_after[0].state, AlertState::Acknowledged);
    }

    #[test]
    fn engine_resolve_alert() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "Test".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "x".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("x", 1.0);
        engine.evaluate(&snap);

        let active = engine.active_alerts();
        assert!(engine.resolve(&active[0].id));
        assert!(engine.active_alerts().is_empty());
        assert_eq!(engine.resolved_alerts().len(), 1);
    }

    #[test]
    fn engine_suppress_alert() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "Test".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 0.0,
            },
            severity: AlertSeverity::Info,
            message_template: "x".to_string(),
            enabled: true,
        });

        let mut snap = MetricsSnapshot::new();
        snap.set("x", 1.0);
        engine.evaluate(&snap);

        let active = engine.active_alerts();
        assert!(engine.suppress(&active[0].id));
        // Suppressed alerts are not returned by active_alerts()
        assert!(engine.active_alerts().is_empty());
    }

    #[test]
    fn engine_add_rule_replaces() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "Old Rule".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 1.0,
            },
            severity: AlertSeverity::Warning,
            message_template: "old".to_string(),
            enabled: true,
        });
        engine.add_rule(AlertRule {
            id: "r1".to_string(),
            name: "New Rule".to_string(),
            condition: AlertCondition::Threshold {
                metric_name: "x".to_string(),
                operator: ThresholdOperator::Gt,
                threshold: 10.0,
            },
            severity: AlertSeverity::Critical,
            message_template: "new".to_string(),
            enabled: true,
        });
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].name, "New Rule");
    }

    // ── DefaultAlertRules tests ──

    #[test]
    fn default_rules_count() {
        let rules = DefaultAlertRules::security_defaults();
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn default_rules_all_enabled() {
        let rules = DefaultAlertRules::security_defaults();
        assert!(rules.iter().all(|r| r.enabled));
    }

    #[test]
    fn default_rules_unique_ids() {
        let rules = DefaultAlertRules::security_defaults();
        let ids: Vec<&String> = rules.iter().map(|r| &r.id).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().cloned().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn default_rules_have_names() {
        let rules = DefaultAlertRules::security_defaults();
        assert!(rules.iter().all(|r| !r.name.is_empty()));
    }

    #[test]
    fn default_rules_severities() {
        let rules = DefaultAlertRules::security_defaults();
        // Should have at least one Critical and one Warning
        let has_critical = rules.iter().any(|r| r.severity == AlertSeverity::Critical);
        let has_warning = rules.iter().any(|r| r.severity == AlertSeverity::Warning);
        assert!(has_critical);
        assert!(has_warning);
    }

    // ── AlertRule with composite condition in engine ──

    #[test]
    fn engine_composite_and_rule() {
        let engine = AlertingEngine::new();
        engine.add_rule(AlertRule {
            id: "composite".to_string(),
            name: "Composite AND".to_string(),
            condition: AlertCondition::Composite {
                rules: vec![
                    AlertCondition::Threshold {
                        metric_name: "error_rate".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.05,
                    },
                    AlertCondition::Threshold {
                        metric_name: "deny_rate".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.30,
                    },
                ],
                logic: CompositeLogic::And,
            },
            severity: AlertSeverity::Emergency,
            message_template: "Both conditions met".to_string(),
            enabled: true,
        });

        // Only one condition met → no alert
        let mut snap = MetricsSnapshot::new();
        snap.set("error_rate", 0.10);
        snap.set("deny_rate", 0.10);
        let alerts = engine.evaluate(&snap);
        assert!(alerts.is_empty());

        // Both conditions met → alert fires
        // Reset engine state for clean evaluation
        let engine2 = AlertingEngine::new();
        engine2.add_rule(AlertRule {
            id: "composite".to_string(),
            name: "Composite AND".to_string(),
            condition: AlertCondition::Composite {
                rules: vec![
                    AlertCondition::Threshold {
                        metric_name: "error_rate".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.05,
                    },
                    AlertCondition::Threshold {
                        metric_name: "deny_rate".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.30,
                    },
                ],
                logic: CompositeLogic::And,
            },
            severity: AlertSeverity::Emergency,
            message_template: "Both conditions met".to_string(),
            enabled: true,
        });
        let mut snap2 = MetricsSnapshot::new();
        snap2.set("error_rate", 0.10);
        snap2.set("deny_rate", 0.40);
        let alerts2 = engine2.evaluate(&snap2);
        assert_eq!(alerts2.len(), 1);
        assert_eq!(alerts2[0].severity, AlertSeverity::Emergency);
    }
}
