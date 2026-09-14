// ANANTA Health — Platform-wide Health Graph
//
// Health aggregates signals from all subsystems into a unified
// health graph. It provides:
//   - Per-component health scores
//   - Dependency-aware propagation (failure cascades)
//   - Anomaly prediction via trend analysis
//   - Overall platform health snapshot
//
// The health graph is a DAG: components depend on each other,
// and a failure in one affects its dependents.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::config::HealthConfig;

pub mod anomaly_prediction;
pub use anomaly_prediction::*;

pub mod health_correlation;
pub use health_correlation::*;

/// Health status levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Component is fully operational.
    Healthy,
    /// Component is degraded but functional.
    Degraded,
    /// Component is unhealthy and may fail.
    Unhealthy,
    /// Component has failed.
    Failed,
    /// Component status is unknown.
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl HealthStatus {
    /// Numeric score for aggregation (1.0 = healthy, 0.0 = failed).
    pub fn score(&self) -> f64 {
        match self {
            HealthStatus::Healthy => 1.0,
            HealthStatus::Degraded => 0.7,
            HealthStatus::Unhealthy => 0.3,
            HealthStatus::Failed => 0.0,
            HealthStatus::Unknown => 0.5,
        }
    }

    /// Worst status from a list.
    /// Returns the status with the lowest health score.
    pub fn worst(statuses: &[HealthStatus]) -> HealthStatus {
        statuses
            .iter()
            .min_by(|a, b| a.score().total_cmp(&b.score()))
            .cloned()
            .unwrap_or(HealthStatus::Unknown)
    }
}

/// A single health observation for a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthObservation {
    /// The component being observed.
    pub component: String,
    /// Current health status.
    pub status: HealthStatus,
    /// Numeric health score (0.0-1.0).
    pub score: f64,
    /// Optional message explaining the status.
    pub message: Option<String>,
    /// Timestamp of this observation.
    pub timestamp: String,
    /// Extra data.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl HealthObservation {
    pub fn new(component: &str, status: HealthStatus) -> Self {
        Self {
            component: component.into(),
            score: status.score(),
            status,
            message: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.into());
        self
    }
}

/// A dependency edge in the health graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The dependent component.
    pub from: String,
    /// The component it depends on.
    pub to: String,
    /// Dependency weight (how much the dependent is affected).
    pub weight: f64,
}

/// An anomaly prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPrediction {
    /// Component that may become unhealthy.
    pub component: String,
    /// Predicted status.
    pub predicted_status: HealthStatus,
    /// Confidence in the prediction (0.0-1.0).
    pub confidence: f64,
    /// Reasoning.
    pub reason: String,
    /// When the anomaly is predicted to occur (seconds from now).
    pub time_horizon_secs: u64,
    pub timestamp: String,
}

/// The platform health graph.
pub struct HealthGraph {
    config: HealthConfig,
    /// Current health observations per component.
    observations: HashMap<String, HealthObservation>,
    /// Dependency edges (from -> to means "from depends on to").
    dependencies: Vec<DependencyEdge>,
    /// Historical scores per component (for trend analysis).
    history: HashMap<String, Vec<f64>>,
    /// Max history length per component.
    max_history: usize,
}

impl HealthGraph {
    /// Create a new health graph.
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            observations: HashMap::new(),
            dependencies: vec![],
            history: HashMap::new(),
            max_history: 1000,
        }
    }

    /// Register a dependency relationship.
    pub fn add_dependency(&mut self, from: &str, to: &str, weight: f64) {
        let weight = weight.clamp(0.0, 1.0);
        self.dependencies.push(DependencyEdge {
            from: from.into(),
            to: to.into(),
            weight,
        });
    }

    /// Record a health observation for a component.
    pub fn observe(&mut self, observation: HealthObservation) {
        let component = observation.component.clone();
        // Store history.
        let entry = self.history.entry(component.clone()).or_default();
        entry.push(observation.score);
        if entry.len() > self.max_history {
            entry.remove(0);
        }
        self.observations.insert(component, observation);
    }

    /// Get the health score for a component.
    pub fn component_health(&self, component: &str) -> f64 {
        self.observations
            .get(component)
            .map(|o| o.score)
            .unwrap_or(1.0)
    }

    /// Get the health status for a component.
    pub fn component_status(&self, component: &str) -> HealthStatus {
        self.observations
            .get(component)
            .map(|o| o.status.clone())
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Compute the propagated health score for a component.
    ///
    /// This factors in the health of all dependencies.
    /// A component's effective health = its own health * dependency_factor.
    pub fn propagated_health(&self, component: &str) -> f64 {
        let own_health = self.component_health(component);

        // Find all dependencies of this component.
        let deps: Vec<&DependencyEdge> = self
            .dependencies
            .iter()
            .filter(|d| d.from == component)
            .collect();

        if deps.is_empty() {
            return own_health;
        }

        // Weighted average of dependency health, then multiply with own health.
        let mut total_weight = 0.0;
        let mut weighted_dep_health = 0.0;

        for dep in &deps {
            let dep_health = self.propagated_health(&dep.to);
            weighted_dep_health += dep_health * dep.weight;
            total_weight += dep.weight;
        }

        if total_weight == 0.0 {
            return own_health;
        }

        let dep_factor = weighted_dep_health / total_weight;
        own_health * (0.5 + 0.5 * dep_factor) // 50% own, 50% dependencies.
    }

    /// Compute overall platform health.
    pub fn overall_health(&self) -> f64 {
        if self.observations.is_empty() {
            return 1.0;
        }

        let components: Vec<String> = self.observations.keys().cloned().collect();
        let total: f64 = components.iter().map(|c| self.propagated_health(c)).sum();
        total / components.len() as f64
    }

    /// Get all observations.
    pub fn observations(&self) -> &HashMap<String, HealthObservation> {
        &self.observations
    }

    /// Get components that depend on a given component (reverse lookup).
    pub fn dependents(&self, component: &str) -> Vec<String> {
        self.dependencies
            .iter()
            .filter(|d| d.to == component)
            .map(|d| d.from.clone())
            .collect()
    }

    /// Predict anomalies based on trend analysis.
    ///
    /// Uses simple linear extrapolation on recent health scores.
    pub fn predict_anomalies(&self) -> Vec<AnomalyPrediction> {
        let mut predictions = vec![];

        for (component, history) in &self.history {
            if history.len() < 10 {
                continue; // Not enough data.
            }

            let recent: Vec<f64> = history.iter().rev().take(20).cloned().collect();
            let recent: Vec<f64> = recent.into_iter().rev().collect();

            if recent.len() < 2 {
                continue;
            }

            // Simple linear trend: slope = (last - first) / (n - 1).
            let first = recent.first().unwrap();
            let last = recent.last().unwrap();
            let slope = (last - first) / (recent.len() - 1) as f64;

            // Extrapolate to prediction window.
            let prediction_window = self.config.prediction_window_secs as f64;
            // Assume one observation per second (simplified).
            let predicted_value = last + slope * prediction_window * 0.1;

            if predicted_value < 0.5 {
                let predicted_status = if predicted_value < 0.2 {
                    HealthStatus::Failed
                } else {
                    HealthStatus::Unhealthy
                };

                let confidence = ((0.5 - predicted_value) * 2.0).clamp(0.1, 0.95);

                predictions.push(AnomalyPrediction {
                    component: component.clone(),
                    predicted_status,
                    confidence,
                    reason: format!(
                        "declining trend: slope={:.4}, current={:.3}, predicted={:.3}",
                        slope, last, predicted_value,
                    ),
                    time_horizon_secs: self.config.prediction_window_secs,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        predictions
    }

    /// Get the trend direction for a component.
    pub fn trend(&self, component: &str) -> TrendDirection {
        let history = match self.history.get(component) {
            Some(h) if h.len() >= 5 => h,
            _ => return TrendDirection::Unknown,
        };

        let recent: f64 = history.iter().rev().take(5).sum::<f64>() / 5.0;
        let older: f64 = history.iter().rev().skip(5).take(5).sum::<f64>()
            / 5.0_f64.min(history.len().saturating_sub(5).max(1) as f64);

        let diff = recent - older;
        if diff.abs() < 0.02 {
            TrendDirection::Stable
        } else if diff > 0.0 {
            TrendDirection::Improving
        } else {
            TrendDirection::Degrading
        }
    }

    /// Count components by status.
    pub fn status_counts(&self) -> HashMap<HealthStatus, usize> {
        let mut counts = HashMap::new();
        for obs in self.observations.values() {
            *counts.entry(obs.status.clone()).or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HealthConfig {
        HealthConfig::default()
    }

    #[test]
    fn new_graph_healthy() {
        let graph = HealthGraph::new(test_config());
        assert_eq!(graph.overall_health(), 1.0); // No components = fully healthy.
    }

    #[test]
    fn observe_component() {
        let mut graph = HealthGraph::new(test_config());
        graph.observe(HealthObservation::new("shield", HealthStatus::Healthy));
        assert_eq!(graph.component_health("shield"), 1.0);
    }

    #[test]
    fn dependency_propagation() {
        let mut graph = HealthGraph::new(test_config());
        // Decision depends on Policy.
        graph.add_dependency("decision", "policy", 0.8);
        graph.observe(HealthObservation::new("decision", HealthStatus::Healthy));
        graph.observe(HealthObservation::new("policy", HealthStatus::Failed));

        let propagated = graph.propagated_health("decision");
        assert!(propagated < 1.0); // Should be degraded due to failed dependency.
        assert!(propagated > 0.0); // But not zero — own health is good.
    }

    #[test]
    fn dependents_lookup() {
        let mut graph = HealthGraph::new(test_config());
        graph.add_dependency("a", "x", 1.0);
        graph.add_dependency("b", "x", 1.0);
        let deps = graph.dependents("x");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn status_counts() {
        let mut graph = HealthGraph::new(test_config());
        graph.observe(HealthObservation::new("a", HealthStatus::Healthy));
        graph.observe(HealthObservation::new("b", HealthStatus::Healthy));
        graph.observe(HealthObservation::new("c", HealthStatus::Failed));
        let counts = graph.status_counts();
        assert_eq!(counts.get(&HealthStatus::Healthy).copied().unwrap_or(0), 2);
        assert_eq!(counts.get(&HealthStatus::Failed).copied().unwrap_or(0), 1);
    }

    #[test]
    fn trend_analysis_stable() {
        let mut graph = HealthGraph::new(test_config());
        for _ in 0..20 {
            graph.observe(HealthObservation::new("stable", HealthStatus::Healthy));
        }
        assert_eq!(graph.trend("stable"), TrendDirection::Stable);
    }

    #[test]
    fn trend_analysis_degrading() {
        let mut graph = HealthGraph::new(test_config());
        // Simulate declining health.
        for i in 0..20 {
            let score = 1.0 - (i as f64 * 0.03);
            let status = if score > 0.7 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unhealthy
            };
            let mut obs = HealthObservation::new("declining", status);
            obs.score = score;
            graph.observe(obs);
        }
        assert_eq!(graph.trend("declining"), TrendDirection::Degrading);
    }

    #[test]
    fn anomaly_prediction_declining() {
        let mut graph = HealthGraph::new(HealthConfig {
            prediction_window_secs: 300,
            ..Default::default()
        });
        // Rapid decline.
        for i in 0..30 {
            let score = 1.0 - (i as f64 * 0.04);
            let status = if score > 0.7 {
                HealthStatus::Degraded
            } else if score > 0.3 {
                HealthStatus::Unhealthy
            } else {
                HealthStatus::Failed
            };
            let mut obs = HealthObservation::new("fast_decline", status);
            obs.score = score;
            graph.observe(obs);
        }
        let predictions = graph.predict_anomalies();
        assert!(!predictions.is_empty());
    }

    #[test]
    fn health_status_scores() {
        assert_eq!(HealthStatus::Healthy.score(), 1.0);
        assert_eq!(HealthStatus::Degraded.score(), 0.7);
        assert_eq!(HealthStatus::Unhealthy.score(), 0.3);
        assert_eq!(HealthStatus::Failed.score(), 0.0);
    }

    #[test]
    fn worst_status() {
        let statuses = vec![
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Failed,
        ];
        assert_eq!(HealthStatus::worst(&statuses), HealthStatus::Failed);
    }

    #[test]
    fn observation_serialization() {
        let obs = HealthObservation::new("test", HealthStatus::Healthy).with_message("all good");
        let json = serde_json::to_string(&obs).unwrap();
        let restored: HealthObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.component, "test");
        assert_eq!(restored.message, Some("all good".into()));
    }
}
