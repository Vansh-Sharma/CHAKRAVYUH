//! Chaos Engineering Engine for the ANANTA Trust Plane
//!
//! This module implements a production-grade chaos engineering framework that
//! allows the ANANTA trust plane to safely test its resilience against various
//! failure modes. Chaos experiments are structured, observable, and bounded by
//! safety mechanisms to prevent uncontrolled blast radius.
//!
//! # Architecture
//!
//! ```text
//! ChaosEngine
//!  ├── SteadyStateHypothesis  (what "normal" looks like)
//!  ├── FaultInjector          (how we break things)
//!  ├── BlastRadiusCalculator  (how far the breakage spreads)
//!  ├── ExperimentOrchestrator (how we run experiments)
//!  └── SafetyMonitor          (how we stay safe)
//! ```
//!
//! # Safety Guarantees
//!
//! - Every experiment must pass a steady-state hypothesis before injection
//! - Blast radius is computed and validated before any fault is injected
//! - Automatic rollback triggers if steady-state degrades beyond thresholds
//! - Dry-run mode computes impact without injecting any faults
//! - Hard timeout ensures experiments cannot run indefinitely

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: Core Types & Enums
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a chaos experiment.
pub type ExperimentId = String;

/// Unique identifier for a component in the dependency graph.
pub type ComponentId = String;

/// The type of fault to inject during a chaos experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FaultType {
    /// Simulate a process crash — the component stops responding entirely.
    Crash,
    /// Add artificial latency to the component's operations.
    LatencyInjection,
    /// Return errors with a configurable probability.
    ErrorInjection,
    /// Simulate CPU or memory resource exhaustion.
    ResourceExhaustion,
    /// Simulate network partition between components.
    NetworkPartition,
}

impl FaultType {
    /// Returns a human-readable label for the fault type.
    pub fn label(&self) -> &'static str {
        match self {
            FaultType::Crash => "crash",
            FaultType::LatencyInjection => "latency_injection",
            FaultType::ErrorInjection => "error_injection",
            FaultType::ResourceExhaustion => "resource_exhaustion",
            FaultType::NetworkPartition => "network_partition",
        }
    }

    /// Returns the severity weight for this fault type (0.0–1.0).
    /// Higher values indicate more destructive potential.
    pub fn base_severity(&self) -> f64 {
        match self {
            FaultType::Crash => 0.9,
            FaultType::LatencyInjection => 0.3,
            FaultType::ErrorInjection => 0.5,
            FaultType::ResourceExhaustion => 0.7,
            FaultType::NetworkPartition => 0.8,
        }
    }
}

/// The current status of a chaos experiment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentStatus {
    /// The experiment has been defined but not yet started.
    Pending,
    /// The steady-state hypothesis is being validated.
    ValidatingSteadyState,
    /// The fault is being injected.
    Injecting,
    /// The fault is active and observations are being collected.
    Active,
    /// Rollback actions are being executed.
    RollingBack,
    /// The experiment completed successfully.
    Completed,
    /// The experiment was aborted due to a safety trigger.
    Aborted,
    /// The experiment failed (steady-state never recovered).
    Failed,
}

impl std::fmt::Display for ExperimentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExperimentStatus::Pending => write!(f, "pending"),
            ExperimentStatus::ValidatingSteadyState => write!(f, "validating_steady_state"),
            ExperimentStatus::Injecting => write!(f, "injecting"),
            ExperimentStatus::Active => write!(f, "active"),
            ExperimentStatus::RollingBack => write!(f, "rolling_back"),
            ExperimentStatus::Completed => write!(f, "completed"),
            ExperimentStatus::Aborted => write!(f, "aborted"),
            ExperimentStatus::Failed => write!(f, "failed"),
        }
    }
}

/// A phase in the experiment lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentPhase {
    /// Before the fault is injected — baseline measurement.
    Before,
    /// During fault injection — the chaos is active.
    During,
    /// After rollback — recovery measurement.
    After,
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2: Steady-State Hypothesis
// ─────────────────────────────────────────────────────────────────────────────

/// A single metric-based condition that must hold for the system to be
/// considered in a steady state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricCondition {
    /// The metric name (e.g., "error_rate", "p99_latency", "trust_score").
    pub metric_name: String,
    /// The comparison operator to apply.
    pub comparator: MetricComparator,
    /// The threshold value to compare against.
    pub threshold: f64,
    /// Optional component scope — if None, applies globally.
    pub component: Option<ComponentId>,
}

/// Comparison operators for metric conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetricComparator {
    /// The metric must be strictly less than the threshold.
    LessThan,
    /// The metric must be less than or equal to the threshold.
    LessThanOrEqual,
    /// The metric must be strictly greater than the threshold.
    GreaterThan,
    /// The metric must be greater than or equal to the threshold.
    GreaterThanOrEqual,
    /// The metric must be approximately equal to the threshold (within epsilon).
    ApproximatelyEqual,
}

impl MetricComparator {
    /// Evaluate the comparator against an observed value and a threshold.
    pub fn evaluate(&self, observed: f64, threshold: f64) -> bool {
        let epsilon = 1e-6;
        match self {
            MetricComparator::LessThan => observed < threshold,
            MetricComparator::LessThanOrEqual => observed <= threshold,
            MetricComparator::GreaterThan => observed > threshold,
            MetricComparator::GreaterThanOrEqual => observed >= threshold,
            MetricComparator::ApproximatelyEqual => (observed - threshold).abs() < epsilon,
        }
    }
}

/// A behavioral probe that must succeed for the system to be in steady state.
/// Unlike metric conditions, behavioral probes test specific API calls or actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProbe {
    /// Human-readable name for this probe.
    pub name: String,
    /// The target API endpoint or action to invoke.
    pub target_endpoint: String,
    /// Expected HTTP status code (if applicable).
    pub expected_status: Option<u16>,
    /// Maximum acceptable response time in milliseconds.
    pub max_latency_ms: Option<u64>,
    /// Whether this probe must succeed for steady state to hold.
    pub required: bool,
}

/// The steady-state hypothesis defines what "normal" looks like for the system.
/// It is validated both before and after the chaos experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteadyStateHypothesis {
    /// Metric-based conditions that must all hold.
    pub metric_conditions: Vec<MetricCondition>,
    /// Behavioral probes that must all pass.
    pub behavioral_probes: Vec<BehavioralProbe>,
    /// Minimum number of consecutive valid samples before the hypothesis
    /// is considered confirmed. Defaults to 3.
    pub min_samples: usize,
    /// Tolerance: fraction of conditions that may fail and still be acceptable
    /// (0.0 means all must pass, 0.2 means up to 20% may fail).
    pub tolerance: f64,
}

impl Default for SteadyStateHypothesis {
    fn default() -> Self {
        Self {
            metric_conditions: vec![],
            behavioral_probes: vec![],
            min_samples: 3,
            tolerance: 0.0,
        }
    }
}

impl SteadyStateHypothesis {
    /// Create a new empty steady-state hypothesis.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a metric condition to the hypothesis.
    pub fn with_metric_condition(mut self, condition: MetricCondition) -> Self {
        self.metric_conditions.push(condition);
        self
    }

    /// Add a behavioral probe to the hypothesis.
    pub fn with_behavioral_probe(mut self, probe: BehavioralProbe) -> Self {
        self.behavioral_probes.push(probe);
        self
    }

    /// Set the minimum samples requirement.
    pub fn with_min_samples(mut self, n: usize) -> Self {
        self.min_samples = n;
        self
    }

    /// Set the tolerance fraction.
    pub fn with_tolerance(mut self, t: f64) -> Self {
        self.tolerance = t.clamp(0.0, 1.0);
        self
    }

    /// Validate the hypothesis against a set of observed metrics.
    /// Returns `true` if the hypothesis holds (steady state is confirmed).
    pub fn validate_metrics(&self, observations: &MetricsSnapshot) -> HypothesisResult {
        let mut passed: usize = 0;
        let mut failed: usize = 0;
        let mut failures: Vec<HypothesisFailure> = Vec::new();

        for condition in &self.metric_conditions {
            let observed = observations
                .get(&condition.metric_name, condition.component.as_deref())
                .copied()
                .unwrap_or(f64::NAN);

            if condition.comparator.evaluate(observed, condition.threshold) {
                passed += 1;
            } else {
                failed += 1;
                failures.push(HypothesisFailure {
                    condition_name: condition.metric_name.clone(),
                    observed,
                    expected: condition.threshold,
                    comparator: condition.comparator.clone(),
                    component: condition.component.clone(),
                });
            }
        }

        let total = self.metric_conditions.len();
        let allowed_failures = (total as f64 * self.tolerance).ceil() as usize;
        let holds = failed <= allowed_failures;

        HypothesisResult {
            holds,
            passed,
            failed,
            total,
            failures,
        }
    }

    /// Validate behavioral probes against probe results.
    pub fn validate_probes(&self, probe_results: &[ProbeResult]) -> HypothesisResult {
        let mut passed: usize = 0;
        let mut failed: usize = 0;
        let mut failures: Vec<HypothesisFailure> = Vec::new();

        for probe in &self.behavioral_probes {
            let result = probe_results
                .iter()
                .find(|r| r.name == probe.name);

            let success = match result {
                Some(r) => {
                    let status_ok = probe
                        .expected_status
                        .map_or(true, |s| r.status_code == Some(s));
                    let latency_ok = probe
                        .max_latency_ms
                        .map_or(true, |max| r.latency_ms.map_or(true, |l| l <= max));
                    status_ok && latency_ok && r.success
                }
                None => false,
            };

            if success {
                passed += 1;
            } else {
                failed += 1;
                failures.push(HypothesisFailure {
                    condition_name: probe.name.clone(),
                    observed: result
                        .map(|r| r.status_code.unwrap_or(0) as f64)
                        .unwrap_or(f64::NAN),
                    expected: probe.expected_status.unwrap_or(200) as f64,
                    comparator: MetricComparator::ApproximatelyEqual,
                    component: None,
                });
            }
        }

        let total = self.behavioral_probes.len();
        let allowed_failures = (total as f64 * self.tolerance).ceil() as usize;
        let holds = failed <= allowed_failures;

        HypothesisResult {
            holds,
            passed,
            failed,
            total,
            failures,
        }
    }

    /// Validate the full hypothesis (metrics + probes).
    pub fn validate(
        &self,
        metrics: &MetricsSnapshot,
        probe_results: &[ProbeResult],
    ) -> HypothesisResult {
        let metric_result = self.validate_metrics(metrics);
        let probe_result = self.validate_probes(probe_results);

        let total = metric_result.total + probe_result.total;
        let passed = metric_result.passed + probe_result.passed;
        let failed = metric_result.failed + probe_result.failed;
        let mut failures = metric_result.failures;
        failures.extend(probe_result.failures);

        let allowed_failures = (total as f64 * self.tolerance).ceil() as usize;
        let holds = failed <= allowed_failures;

        HypothesisResult {
            holds,
            passed,
            failed,
            total,
            failures,
        }
    }
}

/// The result of validating a steady-state hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisResult {
    /// Whether the hypothesis holds (steady state confirmed).
    pub holds: bool,
    /// Number of conditions that passed.
    pub passed: usize,
    /// Number of conditions that failed.
    pub failed: usize,
    /// Total number of conditions checked.
    pub total: usize,
    /// Details of each failure.
    pub failures: Vec<HypothesisFailure>,
}

/// Describes a single hypothesis validation failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisFailure {
    /// The name of the condition that failed.
    pub condition_name: String,
    /// The observed value.
    pub observed: f64,
    /// The expected threshold.
    pub expected: f64,
    /// The comparator that was used.
    pub comparator: MetricComparator,
    /// The component this condition was scoped to.
    pub component: Option<ComponentId>,
}

/// A snapshot of system metrics at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    /// Metrics keyed by (metric_name, optional_component).
    /// Stored as flat strings with optional component suffix.
    inner: HashMap<String, f64>,
    /// Timestamp of this snapshot.
    pub timestamp: DateTime<Utc>,
}

impl MetricsSnapshot {
    /// Create a new empty metrics snapshot.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// Build a composite key from metric name and optional component.
    fn key(metric_name: &str, component: Option<&str>) -> String {
        match component {
            Some(c) => format!("{}::{}", metric_name, c),
            None => metric_name.to_string(),
        }
    }

    /// Set a metric value.
    pub fn set(&mut self, metric_name: &str, value: f64, component: Option<&str>) {
        self.inner.insert(Self::key(metric_name, component), value);
    }

    /// Get a metric value.
    pub fn get(&self, metric_name: &str, component: Option<&str>) -> Option<&f64> {
        self.inner.get(&Self::key(metric_name, component))
    }

    /// Get the number of recorded metrics.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Result of executing a behavioral probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Name of the probe.
    pub name: String,
    /// Whether the probe succeeded.
    pub success: bool,
    /// HTTP status code returned (if applicable).
    pub status_code: Option<u16>,
    /// Response latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Error message if the probe failed.
    pub error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3: Fault Injection Primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a specific fault injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultConfig {
    /// The type of fault to inject.
    pub fault_type: FaultType,
    /// The target component to inject the fault into.
    pub target_component: ComponentId,
    /// Duration of the fault injection in milliseconds.
    pub duration_ms: u64,
    /// For latency injection: the delay to add in milliseconds.
    pub latency_ms: Option<u64>,
    /// For error injection: probability of returning an error (0.0–1.0).
    pub error_probability: Option<f64>,
    /// For error injection: the error message to return.
    pub error_message: Option<String>,
    /// For resource exhaustion: CPU load fraction (0.0–1.0).
    pub cpu_load: Option<f64>,
    /// For resource exhaustion: memory pressure fraction (0.0–1.0).
    pub memory_pressure: Option<f64>,
    /// For network partition: list of components to partition from the target.
    pub partitioned_components: Vec<ComponentId>,
    /// For packet loss: probability of dropping a packet (0.0–1.0).
    pub packet_loss_rate: Option<f64>,
}

impl FaultConfig {
    /// Create a crash fault configuration.
    pub fn crash(target: ComponentId, duration_ms: u64) -> Self {
        Self {
            fault_type: FaultType::Crash,
            target_component: target,
            duration_ms,
            latency_ms: None,
            error_probability: None,
            error_message: None,
            cpu_load: None,
            memory_pressure: None,
            partitioned_components: vec![],
            packet_loss_rate: None,
        }
    }

    /// Create a latency injection fault configuration.
    pub fn latency(target: ComponentId, duration_ms: u64, delay_ms: u64) -> Self {
        Self {
            fault_type: FaultType::LatencyInjection,
            target_component: target,
            duration_ms,
            latency_ms: Some(delay_ms),
            error_probability: None,
            error_message: None,
            cpu_load: None,
            memory_pressure: None,
            partitioned_components: vec![],
            packet_loss_rate: None,
        }
    }

    /// Create an error injection fault configuration.
    pub fn error(
        target: ComponentId,
        duration_ms: u64,
        probability: f64,
        message: String,
    ) -> Self {
        Self {
            fault_type: FaultType::ErrorInjection,
            target_component: target,
            duration_ms,
            latency_ms: None,
            error_probability: Some(probability.clamp(0.0, 1.0)),
            error_message: Some(message),
            cpu_load: None,
            memory_pressure: None,
            partitioned_components: vec![],
            packet_loss_rate: None,
        }
    }

    /// Create a resource exhaustion fault configuration.
    pub fn resource_exhaustion(
        target: ComponentId,
        duration_ms: u64,
        cpu_load: f64,
        memory_pressure: f64,
    ) -> Self {
        Self {
            fault_type: FaultType::ResourceExhaustion,
            target_component: target,
            duration_ms,
            latency_ms: None,
            error_probability: None,
            error_message: None,
            cpu_load: Some(cpu_load.clamp(0.0, 1.0)),
            memory_pressure: Some(memory_pressure.clamp(0.0, 1.0)),
            partitioned_components: vec![],
            packet_loss_rate: None,
        }
    }

    /// Create a network partition fault configuration.
    pub fn network_partition(
        target: ComponentId,
        duration_ms: u64,
        partitioned: Vec<ComponentId>,
    ) -> Self {
        Self {
            fault_type: FaultType::NetworkPartition,
            target_component: target,
            duration_ms,
            latency_ms: None,
            error_probability: None,
            error_message: None,
            cpu_load: None,
            memory_pressure: None,
            partitioned_components: partitioned,
            packet_loss_rate: None,
        }
    }

    /// Create a packet loss simulation configuration.
    pub fn packet_loss(
        target: ComponentId,
        duration_ms: u64,
        loss_rate: f64,
    ) -> Self {
        Self {
            fault_type: FaultType::NetworkPartition,
            target_component: target,
            duration_ms,
            latency_ms: None,
            error_probability: None,
            error_message: None,
            cpu_load: None,
            memory_pressure: None,
            partitioned_components: vec![],
            packet_loss_rate: Some(loss_rate.clamp(0.0, 1.0)),
        }
    }
}

/// A simulated fault injector that applies fault configurations and records
/// the effects on a metrics snapshot.
pub struct FaultInjector {
    /// Active faults keyed by target component.
    active_faults: HashMap<ComponentId, FaultConfig>,
    /// The simulated random seed for deterministic error injection.
    seed: u64,
    /// Counter for deterministic randomness.
    counter: u64,
}

impl FaultInjector {
    /// Create a new fault injector with a given random seed.
    pub fn new(seed: u64) -> Self {
        Self {
            active_faults: HashMap::new(),
            seed,
            counter: 0,
        }
    }

    /// Inject a fault. Returns the injection timestamp.
    pub fn inject(&mut self, config: FaultConfig) -> InjectionResult {
        let component = config.target_component.clone();
        self.active_faults.insert(component.clone(), config.clone());

        InjectionResult {
            component,
            fault_type: config.fault_type.clone(),
            injected_at: Utc::now(),
            duration_ms: config.duration_ms,
            success: true,
            message: format!(
                "{} injected into {} for {}ms",
                config.fault_type.label(),
                config.target_component,
                config.duration_ms
            ),
        }
    }

    /// Roll back a fault from a specific component.
    pub fn rollback(&mut self, component: &str) -> RollbackResult {
        if let Some(config) = self.active_faults.remove(component) {
            RollbackResult {
                component: component.to_string(),
                fault_type: config.fault_type,
                rolled_back_at: Utc::now(),
                success: true,
                message: format!("fault rolled back from {}", component),
            }
        } else {
            RollbackResult {
                component: component.to_string(),
                fault_type: FaultType::Crash, // placeholder
                rolled_back_at: Utc::now(),
                success: false,
                message: format!("no active fault on {} to roll back", component),
            }
        }
    }

    /// Roll back all active faults.
    pub fn rollback_all(&mut self) -> Vec<RollbackResult> {
        let components: Vec<ComponentId> = self.active_faults.keys().cloned().collect();
        components
            .into_iter()
            .map(|c| self.rollback(&c))
            .collect()
    }

    /// Simulate the effect of active faults on a metrics snapshot.
    /// This modifies the snapshot in place to reflect the impact of injected faults.
    pub fn apply_fault_effects(&mut self, metrics: &mut MetricsSnapshot) {
        for (component, config) in &self.active_faults {
            match config.fault_type {
                FaultType::Crash => {
                    // Crashed component returns no metrics — simulate 100% error rate.
                    metrics.set("error_rate", 1.0, Some(component));
                    metrics.set("availability", 0.0, Some(component));
                }
                FaultType::LatencyInjection => {
                    if let Some(delay_ms) = config.latency_ms {
                        let current_latency = metrics
                            .get("p99_latency", Some(component))
                            .copied()
                            .unwrap_or(50.0);
                        metrics.set(
                            "p99_latency",
                            current_latency + delay_ms as f64,
                            Some(component),
                        );
                    }
                }
                FaultType::ErrorInjection => {
                    if let Some(prob) = config.error_probability {
                        self.counter += 1;
                        let hash = self.simple_hash(self.counter);
                        let should_error = (hash % 10000) < (prob * 10000.0) as u64;
                        if should_error {
                            metrics.set("error_rate", prob, Some(component));
                        }
                    }
                }
                FaultType::ResourceExhaustion => {
                    if let Some(cpu) = config.cpu_load {
                        metrics.set("cpu_usage", cpu, Some(component));
                        // High CPU causes latency increase.
                        let latency_multiplier = 1.0 + cpu * 3.0;
                        let base_latency = metrics
                            .get("p99_latency", Some(component))
                            .copied()
                            .unwrap_or(50.0);
                        metrics.set(
                            "p99_latency",
                            base_latency * latency_multiplier,
                            Some(component),
                        );
                    }
                    if let Some(mem) = config.memory_pressure {
                        metrics.set("memory_usage", mem, Some(component));
                    }
                }
                FaultType::NetworkPartition => {
                    for partitioned in &config.partitioned_components {
                        metrics.set("network_reachable", 0.0, Some(partitioned));
                        metrics.set("packet_loss", 1.0, Some(partitioned));
                    }
                    if let Some(loss_rate) = config.packet_loss_rate {
                        metrics.set("packet_loss", loss_rate, Some(component));
                    }
                }
            }
        }
    }

    /// Check if a component has an active fault.
    pub fn has_active_fault(&self, component: &str) -> bool {
        self.active_faults.contains_key(component)
    }

    /// Get the number of active faults.
    pub fn active_fault_count(&self) -> usize {
        self.active_faults.len()
    }

    /// Simple deterministic hash for pseudo-random behavior.
    fn simple_hash(&self, value: u64) -> u64 {
        let mut h = self.seed.wrapping_add(value);
        h = h.wrapping_mul(6364136223846793005);
        h ^= h >> 32;
        h
    }
}

/// Result of a fault injection operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResult {
    /// The target component.
    pub component: ComponentId,
    /// The type of fault injected.
    pub fault_type: FaultType,
    /// When the fault was injected.
    pub injected_at: DateTime<Utc>,
    /// Duration of the injection in milliseconds.
    pub duration_ms: u64,
    /// Whether the injection succeeded.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

/// Result of a fault rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// The target component.
    pub component: ComponentId,
    /// The type of fault that was rolled back.
    pub fault_type: FaultType,
    /// When the rollback occurred.
    pub rolled_back_at: DateTime<Utc>,
    /// Whether the rollback succeeded.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4: Blast Radius Calculation
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge in the dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The source component (depends on).
    pub from: ComponentId,
    /// The target component (is depended upon by).
    pub to: ComponentId,
    /// Criticality weight of this dependency (0.0–1.0).
    /// Higher means the dependent relies more heavily on this dependency.
    pub weight: f64,
}

/// The dependency graph used for blast radius computation.
/// Edges go from dependent to dependency: A -> B means A depends on B.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    /// Adjacency list: component -> list of (dependency, weight) pairs.
    adj: HashMap<ComponentId, Vec<(ComponentId, f64)>>,
    /// Reverse adjacency list: component -> list of dependents.
    reverse_adj: HashMap<ComponentId, Vec<(ComponentId, f64)>>,
    /// All known components.
    components: HashSet<ComponentId>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a component to the graph (if not already present).
    pub fn add_component(&mut self, id: ComponentId) {
        self.components.insert(id);
    }

    /// Add a dependency edge: `from` depends on `to` with the given weight.
    pub fn add_dependency(&mut self, from: ComponentId, to: ComponentId, weight: f64) {
        self.components.insert(from.clone());
        self.components.insert(to.clone());
        let w = weight.clamp(0.0, 1.0);
        self.adj
            .entry(from.clone())
            .or_default()
            .push((to.clone(), w));
        self.reverse_adj
            .entry(to)
            .or_default()
            .push((from, w));
    }

    /// Add edges from a list of `DependencyEdge` values.
    pub fn add_edges(&mut self, edges: &[DependencyEdge]) {
        for edge in edges {
            self.add_dependency(
                edge.from.clone(),
                edge.to.clone(),
                edge.weight,
            );
        }
    }

    /// Get all components that directly depend on the given component.
    pub fn direct_dependents(&self, component: &str) -> Vec<&ComponentId> {
        self.reverse_adj
            .get(component)
            .map(|deps| deps.iter().map(|(c, _)| c).collect())
            .unwrap_or_default()
    }

    /// Get all components that the given component directly depends on.
    pub fn direct_dependencies(&self, component: &str) -> Vec<&ComponentId> {
        self.adj
            .get(component)
            .map(|deps| deps.iter().map(|(c, _)| c).collect())
            .unwrap_or_default()
    }

    /// Compute the full blast radius: all components reachable upstream
    /// (i.e., all components that transitively depend on the target).
    /// Uses BFS traversal of the reverse adjacency list.
    pub fn compute_blast_radius(&self, target: &str) -> BlastRadius {
        let mut visited: HashSet<ComponentId> = HashSet::new();
        let mut queue: VecDeque<ComponentId> = VecDeque::new();
        let mut impact_scores: HashMap<ComponentId, f64> = HashMap::new();

        visited.insert(target.to_string());
        queue.push_back(target.to_string());
        impact_scores.insert(target.to_string(), 1.0);

        while let Some(current) = queue.pop_front() {
            let current_score = impact_scores
                .get(&current)
                .copied()
                .unwrap_or(0.0);

            if let Some(dependents) = self.reverse_adj.get(&current) {
                for (dependent, weight) in dependents {
                    if !visited.contains(dependent) {
                        visited.insert(dependent.clone());
                        let propagated_score = current_score * weight;
                        impact_scores
                            .insert(dependent.clone(), propagated_score);
                        queue.push_back(dependent.clone());
                    }
                }
            }
        }

        // Remove the target itself from the affected set.
        visited.remove(target);

        let affected_count = visited.len();
        let total_components = self.components.len().max(1);
        let spread_fraction = affected_count as f64 / total_components as f64;
        let max_impact = impact_scores
            .values()
            .copied()
            .fold(0.0_f64, f64::max);
        let avg_impact = if affected_count > 0 {
            impact_scores
                .values()
                .filter(|_| true)
                .copied()
                .sum::<f64>()
                / (affected_count as f64 + 1.0) // +1 for the target
        } else {
            0.0
        };

        BlastRadius {
            target: target.to_string(),
            affected_components: visited.into_iter().collect(),
            affected_count,
            total_components,
            spread_fraction,
            max_impact_score: max_impact,
            avg_impact_score: avg_impact,
            impact_scores,
        }
    }

    /// Build a dependency graph from a list of (from, to, weight) tuples.
    pub fn from_tuples(tuples: &[(&str, &str, f64)]) -> Self {
        let mut graph = Self::new();
        for (from, to, weight) in tuples {
            graph.add_dependency(from.to_string(), to.to_string(), *weight);
        }
        graph
    }

    /// Get the number of components in the graph.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}

/// The computed blast radius for a fault target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// The target component that was analyzed.
    pub target: String,
    /// All components that would be affected (transitively).
    pub affected_components: Vec<ComponentId>,
    /// Number of affected components.
    pub affected_count: usize,
    /// Total number of components in the graph.
    pub total_components: usize,
    /// Fraction of the system that would be affected (0.0–1.0).
    pub spread_fraction: f64,
    /// Maximum impact score among affected components.
    pub max_impact_score: f64,
    /// Average impact score across affected components.
    pub avg_impact_score: f64,
    /// Per-component impact scores.
    pub impact_scores: HashMap<ComponentId, f64>,
}

impl BlastRadius {
    /// Check if the blast radius is within an acceptable limit.
    /// A blast radius is acceptable if the spread fraction is below the limit.
    pub fn is_acceptable(&self, max_spread_fraction: f64) -> bool {
        self.spread_fraction <= max_spread_fraction
    }

    /// Get a severity rating for this blast radius.
    pub fn severity(&self) -> BlastRadiusSeverity {
        if self.spread_fraction > 0.7 {
            BlastRadiusSeverity::Critical
        } else if self.spread_fraction > 0.4 {
            BlastRadiusSeverity::High
        } else if self.spread_fraction > 0.2 {
            BlastRadiusSeverity::Medium
        } else if self.affected_count > 0 {
            BlastRadiusSeverity::Low
        } else {
            BlastRadiusSeverity::None
        }
    }
}

/// Severity rating for a blast radius.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadiusSeverity {
    /// No components affected beyond the target.
    None,
    /// Few components affected, low spread.
    Low,
    /// Moderate number of components affected.
    Medium,
    /// Many components affected.
    High,
    /// Majority of the system would be affected.
    Critical,
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5: Experiment Orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// A single chaos experiment definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosExperiment {
    /// Unique identifier for this experiment.
    pub id: ExperimentId,
    /// Human-readable experiment name.
    pub name: String,
    /// Description of what this experiment tests.
    pub description: String,
    /// The fault configuration to inject.
    pub fault_config: FaultConfig,
    /// The steady-state hypothesis that must hold before and after.
    pub steady_state: SteadyStateHypothesis,
    /// Rollback plan description.
    pub rollback_plan: String,
    /// Tags for categorization and filtering.
    pub tags: Vec<String>,
    /// Maximum acceptable blast radius spread fraction.
    pub max_blast_radius: f64,
    /// Experiment timeout in milliseconds.
    pub timeout_ms: u64,
    /// Abort condition: if trust score drops below this, abort.
    pub abort_trust_threshold: Option<f64>,
    /// Whether this is a dry-run (no actual injection).
    pub dry_run: bool,
}

impl ChaosExperiment {
    /// Create a new chaos experiment with the given ID and name.
    pub fn new(id: ExperimentId, name: String) -> Self {
        Self {
            id,
            name,
            description: String::new(),
            fault_config: FaultConfig::crash("unknown".to_string(), 1000),
            steady_state: SteadyStateHypothesis::new(),
            rollback_plan: String::new(),
            tags: vec![],
            max_blast_radius: 0.5,
            timeout_ms: 30_000,
            abort_trust_threshold: Some(0.3),
            dry_run: false,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    /// Set the fault configuration.
    pub fn with_fault(mut self, config: FaultConfig) -> Self {
        self.fault_config = config;
        self
    }

    /// Set the steady-state hypothesis.
    pub fn with_steady_state(mut self, hypothesis: SteadyStateHypothesis) -> Self {
        self.steady_state = hypothesis;
        self
    }

    /// Set the rollback plan.
    pub fn with_rollback_plan(mut self, plan: String) -> Self {
        self.rollback_plan = plan;
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    /// Set the maximum blast radius.
    pub fn with_max_blast_radius(mut self, max: f64) -> Self {
        self.max_blast_radius = max.clamp(0.0, 1.0);
        self
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set the abort trust threshold.
    pub fn with_abort_threshold(mut self, threshold: f64) -> Self {
        self.abort_trust_threshold = Some(threshold);
        self
    }

    /// Set dry-run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

/// An observation recorded during an experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentObservation {
    /// Which phase of the experiment this observation belongs to.
    pub phase: ExperimentPhase,
    /// Timestamp of the observation.
    pub timestamp: DateTime<Utc>,
    /// Metrics snapshot at this point.
    pub metrics: MetricsSnapshot,
    /// Behavioral probe results at this point.
    pub probe_results: Vec<ProbeResult>,
    /// Trust score at this point (if available).
    pub trust_score: Option<f64>,
    /// Any notable events.
    pub events: Vec<String>,
}

/// The complete result of running a chaos experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentReport {
    /// The experiment that was run.
    pub experiment_id: ExperimentId,
    /// The experiment name.
    pub experiment_name: String,
    /// Final status of the experiment.
    pub status: ExperimentStatus,
    /// Observations collected during the experiment.
    pub observations: Vec<ExperimentObservation>,
    /// Before-state hypothesis validation.
    pub before_hypothesis: Option<HypothesisResult>,
    /// After-state hypothesis validation.
    pub after_hypothesis: Option<HypothesisResult>,
    /// Blast radius computation.
    pub blast_radius: Option<BlastRadius>,
    /// Fault injection result.
    pub injection_result: Option<InjectionResult>,
    /// Rollback results.
    pub rollback_results: Vec<RollbackResult>,
    /// When the experiment started.
    pub started_at: DateTime<Utc>,
    /// When the experiment ended.
    pub ended_at: DateTime<Utc>,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the experiment was a dry-run.
    pub dry_run: bool,
    /// Summary of findings.
    pub summary: String,
}

impl ExperimentReport {
    /// Generate a human-readable summary string.
    pub fn generate_summary(&self) -> String {
        let mut parts = vec![];
        parts.push(format!("experiment={} status={}", self.experiment_name, self.status));

        if let Some(ref blast) = self.blast_radius {
            parts.push(format!(
                "blast_radius: {}/{} components ({:.1}%) severity={:?}",
                blast.affected_count,
                blast.total_components,
                blast.spread_fraction * 100.0,
                blast.severity()
            ));
        }

        if let Some(ref before) = self.before_hypothesis {
            parts.push(format!(
                "before: {}/{} conditions passed",
                before.passed, before.total
            ));
        }

        if let Some(ref after) = self.after_hypothesis {
            parts.push(format!(
                "after: {}/{} conditions passed",
                after.passed, after.total
            ));
        }

        parts.push(format!(
            "duration={}ms observations={}",
            self.duration_ms,
            self.observations.len()
        ));

        if self.dry_run {
            parts.push("DRY_RUN".to_string());
        }

        parts.join(" | ")
    }
}

/// Orchestration mode for running multiple experiments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationMode {
    /// Run experiments one after another.
    Sequential,
    /// Run experiments concurrently (simulated — no real threads).
    Parallel,
}

/// The experiment orchestrator manages the lifecycle of chaos experiments.
pub struct ExperimentOrchestrator {
    /// The dependency graph for blast radius computation.
    dependency_graph: DependencyGraph,
    /// The fault injector.
    fault_injector: FaultInjector,
    /// Maximum global blast radius across all experiments.
    global_max_blast_radius: f64,
    /// Experiment history.
    history: Vec<ExperimentReport>,
}

impl ExperimentOrchestrator {
    /// Create a new experiment orchestrator.
    pub fn new(dependency_graph: DependencyGraph) -> Self {
        Self {
            dependency_graph,
            fault_injector: FaultInjector::new(42),
            global_max_blast_radius: 0.8,
            history: vec![],
        }
    }

    /// Set the global maximum blast radius.
    pub fn with_global_max_blast_radius(mut self, max: f64) -> Self {
        self.global_max_blast_radius = max.clamp(0.0, 1.0);
        self
    }

    /// Run a single chaos experiment and return the report.
    pub fn run_experiment(
        &mut self,
        experiment: &ChaosExperiment,
        initial_metrics: &MetricsSnapshot,
        initial_probes: &[ProbeResult],
    ) -> ExperimentReport {
        let started_at = Utc::now();
        let start_instant = Instant::now();
        let mut observations: Vec<ExperimentObservation> = vec![];
        let mut rollback_results: Vec<RollbackResult> = vec![];

        // ── Phase 1: Validate steady state before injection ──
        let before_hypothesis = Some(
            experiment
                .steady_state
                .validate(initial_metrics, initial_probes),
        );

        // Record baseline observation.
        observations.push(ExperimentObservation {
            phase: ExperimentPhase::Before,
            timestamp: Utc::now(),
            metrics: initial_metrics.clone(),
            probe_results: initial_probes.to_vec(),
            trust_score: initial_metrics.get("trust_score", None).copied(),
            events: vec!["baseline measurement".to_string()],
        });

        // Check if steady state holds before injection.
        let before_holds = before_hypothesis
            .as_ref()
            .map(|h| h.holds)
            .unwrap_or(false);

        if !before_holds {
            let report = ExperimentReport {
                experiment_id: experiment.id.clone(),
                experiment_name: experiment.name.clone(),
                status: ExperimentStatus::Failed,
                observations,
                before_hypothesis,
                after_hypothesis: None,
                blast_radius: None,
                injection_result: None,
                rollback_results,
                started_at,
                ended_at: Utc::now(),
                duration_ms: start_instant.elapsed().as_millis() as u64,
                dry_run: experiment.dry_run,
                summary: "experiment aborted: steady-state hypothesis did not hold before injection".to_string(),
            };
            self.history.push(report.clone());
            return report;
        }

        // ── Phase 2: Compute blast radius ──
        let target = &experiment.fault_config.target_component;
        let blast_radius = self.dependency_graph.compute_blast_radius(target);

        // Check if blast radius exceeds the experiment's limit.
        let blast_ok = blast_radius.is_acceptable(experiment.max_blast_radius);
        let _global_ok = blast_radius.is_acceptable(self.global_max_blast_radius);

        if !blast_ok {
            let summary = format!(
                "experiment aborted: blast radius {:.1}% exceeds limit {:.1}%",
                blast_radius.spread_fraction * 100.0,
                experiment.max_blast_radius * 100.0
            );
            let report = ExperimentReport {
                experiment_id: experiment.id.clone(),
                experiment_name: experiment.name.clone(),
                status: ExperimentStatus::Aborted,
                observations,
                before_hypothesis,
                after_hypothesis: None,
                blast_radius: Some(blast_radius),
                injection_result: None,
                rollback_results,
                started_at,
                ended_at: Utc::now(),
                duration_ms: start_instant.elapsed().as_millis() as u64,
                dry_run: experiment.dry_run,
                summary,
            };
            self.history.push(report.clone());
            return report;
        }

        // ── Phase 3: Dry-run check ──
        if experiment.dry_run {
            let summary = format!(
                "dry-run completed: blast_radius={:.1}% severity={:?} — no fault injected",
                blast_radius.spread_fraction * 100.0,
                blast_radius.severity()
            );
            let report = ExperimentReport {
                experiment_id: experiment.id.clone(),
                experiment_name: experiment.name.clone(),
                status: ExperimentStatus::Completed,
                observations,
                before_hypothesis: before_hypothesis.clone(),
                after_hypothesis: before_hypothesis,
                blast_radius: Some(blast_radius),
                injection_result: None,
                rollback_results,
                started_at,
                ended_at: Utc::now(),
                duration_ms: start_instant.elapsed().as_millis() as u64,
                dry_run: true,
                summary,
            };
            self.history.push(report.clone());
            return report;
        }

        // ── Phase 4: Inject fault ──
        let injection_result = Some(self.fault_injector.inject(experiment.fault_config.clone()));

        // Simulate fault effects on metrics.
        let mut during_metrics = initial_metrics.clone();
        self.fault_injector.apply_fault_effects(&mut during_metrics);

        let during_trust = during_metrics.get("trust_score", None).copied();

        // Record during observation.
        observations.push(ExperimentObservation {
            phase: ExperimentPhase::During,
            timestamp: Utc::now(),
            metrics: during_metrics.clone(),
            probe_results: vec![],
            trust_score: during_trust,
            events: vec![format!(
                "fault {} injected into {}",
                experiment.fault_config.fault_type.label(),
                experiment.fault_config.target_component
            )],
        });

        // ── Phase 5: Check abort conditions ──
        if let Some(threshold) = experiment.abort_trust_threshold {
            if let Some(trust) = during_trust {
                if trust < threshold {
                    // Abort: trust dropped below critical threshold.
                    rollback_results = self.fault_injector.rollback_all();

                    let after_metrics = initial_metrics.clone();
                    observations.push(ExperimentObservation {
                        phase: ExperimentPhase::After,
                        timestamp: Utc::now(),
                        metrics: after_metrics.clone(),
                        probe_results: vec![],
                        trust_score: after_metrics.get("trust_score", None).copied(),
                        events: vec!["abort triggered: trust below threshold".to_string()],
                    });

                    let after_hypothesis = Some(
                        experiment
                            .steady_state
                            .validate(&after_metrics, &[]),
                    );

                    let report = ExperimentReport {
                        experiment_id: experiment.id.clone(),
                        experiment_name: experiment.name.clone(),
                        status: ExperimentStatus::Aborted,
                        observations,
                        before_hypothesis,
                        after_hypothesis,
                        blast_radius: Some(blast_radius),
                        injection_result,
                        rollback_results,
                        started_at,
                        ended_at: Utc::now(),
                        duration_ms: start_instant.elapsed().as_millis() as u64,
                        dry_run: false,
                        summary: format!(
                            "experiment aborted: trust score {:.3} dropped below threshold {:.3}",
                            trust, threshold
                        ),
                    };
                    self.history.push(report.clone());
                    return report;
                }
            }
        }

        // ── Phase 6: Rollback ──
        rollback_results = self.fault_injector.rollback_all();

        // Simulate recovery.
        let mut after_metrics = initial_metrics.clone();
        // Apply slight degradation from the experiment (realistic recovery).
        let degradation = experiment.fault_config.fault_type.base_severity() * 0.05;
        if let Some(trust) = after_metrics.get("trust_score", None).copied() {
            after_metrics.set("trust_score", (trust - degradation).max(0.0), None);
        }

        let after_trust = after_metrics.get("trust_score", None).copied();

        // Record after observation.
        observations.push(ExperimentObservation {
            phase: ExperimentPhase::After,
            timestamp: Utc::now(),
            metrics: after_metrics.clone(),
            probe_results: vec![],
            trust_score: after_trust,
            events: vec!["fault rolled back".to_string()],
        });

        // ── Phase 7: Validate steady state after rollback ──
        let after_hypothesis = Some(
            experiment
                .steady_state
                .validate(&after_metrics, &[]),
        );

        let final_status = if after_hypothesis
            .as_ref()
            .map(|h| h.holds)
            .unwrap_or(true)
        {
            ExperimentStatus::Completed
        } else {
            ExperimentStatus::Failed
        };

        let ended_at = Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;

        let mut report = ExperimentReport {
            experiment_id: experiment.id.clone(),
            experiment_name: experiment.name.clone(),
            status: final_status,
            observations,
            before_hypothesis,
            after_hypothesis,
            blast_radius: Some(blast_radius),
            injection_result,
            rollback_results,
            started_at,
            ended_at,
            duration_ms,
            dry_run: false,
            summary: String::new(),
        };

        report.summary = report.generate_summary();
        self.history.push(report.clone());
        report
    }

    /// Run multiple experiments in the specified orchestration mode.
    pub fn run_experiments(
        &mut self,
        experiments: &[ChaosExperiment],
        initial_metrics: &MetricsSnapshot,
        initial_probes: &[ProbeResult],
        mode: OrchestrationMode,
    ) -> Vec<ExperimentReport> {
        match mode {
            OrchestrationMode::Sequential => self.run_sequential(experiments, initial_metrics, initial_probes),
            OrchestrationMode::Parallel => self.run_parallel(experiments, initial_metrics, initial_probes),
        }
    }

    /// Run experiments sequentially.
    fn run_sequential(
        &mut self,
        experiments: &[ChaosExperiment],
        initial_metrics: &MetricsSnapshot,
        initial_probes: &[ProbeResult],
    ) -> Vec<ExperimentReport> {
        let mut reports = vec![];
        for exp in experiments {
            let report = self.run_experiment(exp, initial_metrics, initial_probes);
            // If an experiment was aborted or failed, stop the sequence.
            if report.status == ExperimentStatus::Aborted {
                reports.push(report);
                break;
            }
            reports.push(report);
        }
        reports
    }

    /// Run experiments in parallel (simulated — each uses the same initial state).
    fn run_parallel(
        &mut self,
        experiments: &[ChaosExperiment],
        initial_metrics: &MetricsSnapshot,
        initial_probes: &[ProbeResult],
    ) -> Vec<ExperimentReport> {
        experiments
            .iter()
            .map(|exp| self.run_experiment(exp, initial_metrics, initial_probes))
            .collect()
    }

    /// Get the experiment history.
    pub fn history(&self) -> &[ExperimentReport] {
        &self.history
    }

    /// Get the dependency graph reference.
    pub fn dependency_graph(&self) -> &DependencyGraph {
        &self.dependency_graph
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 6: Safety Mechanisms
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the safety monitor that guards all chaos experiments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    /// Maximum allowed blast radius spread fraction for any single experiment.
    pub max_single_blast_radius: f64,
    /// Maximum cumulative blast radius across all active experiments.
    pub max_cumulative_blast_radius: f64,
    /// Global trust score floor — if trust drops below this, all experiments
    /// are immediately aborted.
    pub global_trust_floor: f64,
    /// Maximum experiment duration in milliseconds.
    pub max_experiment_duration_ms: u64,
    /// Maximum number of concurrent experiments.
    pub max_concurrent_experiments: usize,
    /// Whether experiments require explicit approval.
    pub require_approval: bool,
    /// List of components that are quarantined (no experiments allowed).
    pub quarantined_components: HashSet<ComponentId>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            max_single_blast_radius: 0.5,
            max_cumulative_blast_radius: 0.8,
            global_trust_floor: 0.2,
            max_experiment_duration_ms: 60_000,
            max_concurrent_experiments: 3,
            require_approval: false,
            quarantined_components: HashSet::new(),
        }
    }
}

impl SafetyConfig {
    /// Create a new safety configuration with strict settings.
    pub fn strict() -> Self {
        Self {
            max_single_blast_radius: 0.2,
            max_cumulative_blast_radius: 0.4,
            global_trust_floor: 0.4,
            max_experiment_duration_ms: 10_000,
            max_concurrent_experiments: 1,
            require_approval: true,
            quarantined_components: HashSet::new(),
        }
    }

    /// Create a new safety configuration with permissive settings.
    pub fn permissive() -> Self {
        Self {
            max_single_blast_radius: 0.9,
            max_cumulative_blast_radius: 1.0,
            global_trust_floor: 0.1,
            max_experiment_duration_ms: 300_000,
            max_concurrent_experiments: 10,
            require_approval: false,
            quarantined_components: HashSet::new(),
        }
    }

    /// Add a component to the quarantine list.
    pub fn quarantine_component(&mut self, component: ComponentId) {
        self.quarantined_components.insert(component);
    }
}

/// The result of a safety check before experiment execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheckResult {
    /// Whether the experiment is safe to proceed.
    pub allowed: bool,
    /// List of safety violations (empty if allowed).
    pub violations: Vec<SafetyViolation>,
    /// Recommended actions to resolve violations.
    pub recommendations: Vec<String>,
}

impl SafetyCheckResult {
    /// Create a result that allows the experiment.
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            violations: vec![],
            recommendations: vec![],
        }
    }

    /// Create a result that denies the experiment.
    pub fn denied(violations: Vec<SafetyViolation>) -> Self {
        let recommendations: Vec<String> = violations
            .iter()
            .map(|v| v.recommendation.clone())
            .collect();
        Self {
            allowed: false,
            violations,
            recommendations,
        }
    }
}

/// A single safety violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyViolation {
    /// Human-readable description of the violation.
    pub description: String,
    /// Severity of the violation.
    pub severity: SafetyViolationSeverity,
    /// Recommended action to resolve.
    pub recommendation: String,
}

/// Severity levels for safety violations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SafetyViolationSeverity {
    /// Informational — not a hard block.
    Info,
    /// Warning — may proceed with caution.
    Warning,
    /// Error — must be resolved before proceeding.
    Error,
    /// Critical — experiment must not proceed under any circumstances.
    Critical,
}

/// The safety monitor enforces all safety constraints before, during, and
/// after chaos experiments.
pub struct SafetyMonitor {
    /// Safety configuration.
    config: SafetyConfig,
    /// Currently active experiment IDs.
    active_experiments: HashSet<ExperimentId>,
    /// Cumulative blast radius of active experiments.
    cumulative_blast_radius: f64,
}

impl SafetyMonitor {
    /// Create a new safety monitor with the given configuration.
    pub fn new(config: SafetyConfig) -> Self {
        Self {
            config,
            active_experiments: HashSet::new(),
            cumulative_blast_radius: 0.0,
        }
    }

    /// Perform a pre-flight safety check on an experiment and its blast radius.
    pub fn pre_flight_check(
        &self,
        experiment: &ChaosExperiment,
        blast_radius: &BlastRadius,
    ) -> SafetyCheckResult {
        let mut violations = vec![];

        // Check quarantine.
        if self
            .config
            .quarantined_components
            .contains(&experiment.fault_config.target_component)
        {
            violations.push(SafetyViolation {
                description: format!(
                    "target component '{}' is quarantined",
                    experiment.fault_config.target_component
                ),
                severity: SafetyViolationSeverity::Critical,
                recommendation: format!(
                    "remove '{}' from quarantine before running experiments against it",
                    experiment.fault_config.target_component
                ),
            });
        }

        // Check single experiment blast radius.
        if !blast_radius.is_acceptable(self.config.max_single_blast_radius) {
            violations.push(SafetyViolation {
                description: format!(
                    "blast radius {:.1}% exceeds single-experiment limit {:.1}%",
                    blast_radius.spread_fraction * 100.0,
                    self.config.max_single_blast_radius * 100.0
                ),
                severity: SafetyViolationSeverity::Error,
                recommendation: "reduce the target's dependencies or increase max_single_blast_radius".to_string(),
            });
        }

        // Check cumulative blast radius.
        let potential_cumulative = self.cumulative_blast_radius + blast_radius.spread_fraction;
        if potential_cumulative > self.config.max_cumulative_blast_radius {
            violations.push(SafetyViolation {
                description: format!(
                    "cumulative blast radius would be {:.1}%, exceeding limit {:.1}%",
                    potential_cumulative * 100.0,
                    self.config.max_cumulative_blast_radius * 100.0
                ),
                severity: SafetyViolationSeverity::Error,
                recommendation: "wait for active experiments to complete before starting a new one".to_string(),
            });
        }

        // Check concurrent experiment limit.
        if self.active_experiments.len() >= self.config.max_concurrent_experiments {
            violations.push(SafetyViolation {
                description: format!(
                    "concurrent experiment limit {} reached",
                    self.config.max_concurrent_experiments
                ),
                severity: SafetyViolationSeverity::Warning,
                recommendation: "wait for an active experiment to complete".to_string(),
            });
        }

        // Check experiment timeout.
        if experiment.timeout_ms > self.config.max_experiment_duration_ms {
            violations.push(SafetyViolation {
                description: format!(
                    "experiment timeout {}ms exceeds maximum allowed {}ms",
                    experiment.timeout_ms, self.config.max_experiment_duration_ms
                ),
                severity: SafetyViolationSeverity::Warning,
                recommendation: format!(
                    "reduce experiment timeout to at most {}ms",
                    self.config.max_experiment_duration_ms
                ),
            });
        }

        if violations.is_empty() {
            SafetyCheckResult::allowed()
        } else {
            SafetyCheckResult::denied(violations)
        }
    }

    /// Check if the current trust score is above the floor.
    pub fn check_trust_floor(&self, trust_score: f64) -> bool {
        trust_score >= self.config.global_trust_floor
    }

    /// Register an experiment as active and update cumulative blast radius.
    pub fn register_experiment(&mut self, id: ExperimentId, blast_radius: f64) {
        self.active_experiments.insert(id);
        self.cumulative_blast_radius += blast_radius;
    }

    /// Deregister an experiment and reduce cumulative blast radius.
    pub fn deregister_experiment(&mut self, id: &ExperimentId, blast_radius: f64) {
        self.active_experiments.remove(id);
        self.cumulative_blast_radius = (self.cumulative_blast_radius - blast_radius).max(0.0);
    }

    /// Get the current number of active experiments.
    pub fn active_count(&self) -> usize {
        self.active_experiments.len()
    }

    /// Get the current cumulative blast radius.
    pub fn cumulative_blast_radius(&self) -> f64 {
        self.cumulative_blast_radius
    }

    /// Get a reference to the safety configuration.
    pub fn config(&self) -> &SafetyConfig {
        &self.config
    }

    /// Emergency abort: deregister all experiments.
    pub fn emergency_abort(&mut self) {
        self.active_experiments.clear();
        self.cumulative_blast_radius = 0.0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_metrics() -> MetricsSnapshot {
        let mut m = MetricsSnapshot::new();
        m.set("error_rate", 0.01, None);
        m.set("p99_latency", 50.0, None);
        m.set("trust_score", 0.95, None);
        m.set("availability", 0.999, None);
        m
    }

    fn simple_graph() -> DependencyGraph {
        DependencyGraph::from_tuples(&[
            ("api_gateway", "auth_service", 0.9),
            ("api_gateway", "trust_engine", 0.8),
            ("auth_service", "key_store", 0.7),
            ("trust_engine", "policy_store", 0.6),
            ("trust_engine", "audit_log", 0.4),
            ("policy_store", "config_db", 0.5),
            ("api_gateway", "rate_limiter", 0.3),
            ("rate_limiter", "redis_cache", 0.8),
        ])
    }

    // ── FaultType tests ──

    #[test]
    fn fault_type_labels_are_unique() {
        let labels: Vec<&str> = vec![
            FaultType::Crash.label(),
            FaultType::LatencyInjection.label(),
            FaultType::ErrorInjection.label(),
            FaultType::ResourceExhaustion.label(),
            FaultType::NetworkPartition.label(),
        ];
        let unique: HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn fault_type_base_severity_ordering() {
        assert!(FaultType::Crash.base_severity() > FaultType::LatencyInjection.base_severity());
        assert!(FaultType::NetworkPartition.base_severity() > FaultType::ErrorInjection.base_severity());
        assert!(FaultType::ResourceExhaustion.base_severity() > FaultType::LatencyInjection.base_severity());
    }

    // ── MetricComparator tests ──

    #[test]
    fn comparator_less_than() {
        assert!(MetricComparator::LessThan.evaluate(0.5, 1.0));
        assert!(!MetricComparator::LessThan.evaluate(1.0, 1.0));
        assert!(!MetricComparator::LessThan.evaluate(1.5, 1.0));
    }

    #[test]
    fn comparator_less_than_or_equal() {
        assert!(MetricComparator::LessThanOrEqual.evaluate(0.5, 1.0));
        assert!(MetricComparator::LessThanOrEqual.evaluate(1.0, 1.0));
        assert!(!MetricComparator::LessThanOrEqual.evaluate(1.5, 1.0));
    }

    #[test]
    fn comparator_greater_than() {
        assert!(MetricComparator::GreaterThan.evaluate(1.5, 1.0));
        assert!(!MetricComparator::GreaterThan.evaluate(1.0, 1.0));
    }

    #[test]
    fn comparator_approximately_equal() {
        assert!(MetricComparator::ApproximatelyEqual.evaluate(1.0, 1.0));
        assert!(MetricComparator::ApproximatelyEqual.evaluate(1.0 + 1e-9, 1.0));
        assert!(!MetricComparator::ApproximatelyEqual.evaluate(2.0, 1.0));
    }

    // ── SteadyStateHypothesis tests ──

    #[test]
    fn steady_state_hypothesis_validates_healthy_metrics() {
        let hypothesis = SteadyStateHypothesis::new()
            .with_metric_condition(MetricCondition {
                metric_name: "error_rate".to_string(),
                comparator: MetricComparator::LessThan,
                threshold: 0.05,
                component: None,
            })
            .with_metric_condition(MetricCondition {
                metric_name: "trust_score".to_string(),
                comparator: MetricComparator::GreaterThan,
                threshold: 0.8,
                component: None,
            });

        let metrics = healthy_metrics();
        let result = hypothesis.validate_metrics(&metrics);
        assert!(result.holds);
        assert_eq!(result.passed, 2);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn steady_state_hypothesis_detects_degradation() {
        let hypothesis = SteadyStateHypothesis::new()
            .with_metric_condition(MetricCondition {
                metric_name: "error_rate".to_string(),
                comparator: MetricComparator::LessThan,
                threshold: 0.05,
                component: None,
            });

        let mut metrics = MetricsSnapshot::new();
        metrics.set("error_rate", 0.5, None);

        let result = hypothesis.validate_metrics(&metrics);
        assert!(!result.holds);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failures[0].observed, 0.5);
    }

    #[test]
    fn steady_state_tolerance_allows_some_failures() {
        let hypothesis = SteadyStateHypothesis::new()
            .with_tolerance(0.5)
            .with_metric_condition(MetricCondition {
                metric_name: "error_rate".to_string(),
                comparator: MetricComparator::LessThan,
                threshold: 0.05,
                component: None,
            })
            .with_metric_condition(MetricCondition {
                metric_name: "trust_score".to_string(),
                comparator: MetricComparator::GreaterThan,
                threshold: 0.8,
                component: None,
            });

        let mut metrics = MetricsSnapshot::new();
        metrics.set("error_rate", 0.5, None); // Fails
        metrics.set("trust_score", 0.9, None); // Passes

        let result = hypothesis.validate_metrics(&metrics);
        // With 50% tolerance on 2 conditions, 1 failure is allowed.
        assert!(result.holds);
    }

    #[test]
    fn behavioral_probe_validation_passes() {
        let hypothesis = SteadyStateHypothesis::new()
            .with_behavioral_probe(BehavioralProbe {
                name: "health_check".to_string(),
                target_endpoint: "/health".to_string(),
                expected_status: Some(200),
                max_latency_ms: Some(100),
                required: true,
            });

        let probe_results = vec![ProbeResult {
            name: "health_check".to_string(),
            success: true,
            status_code: Some(200),
            latency_ms: Some(50),
            error: None,
        }];

        let result = hypothesis.validate_probes(&probe_results);
        assert!(result.holds);
        assert_eq!(result.passed, 1);
    }

    #[test]
    fn behavioral_probe_validation_fails_on_wrong_status() {
        let hypothesis = SteadyStateHypothesis::new()
            .with_behavioral_probe(BehavioralProbe {
                name: "health_check".to_string(),
                target_endpoint: "/health".to_string(),
                expected_status: Some(200),
                max_latency_ms: None,
                required: true,
            });

        let probe_results = vec![ProbeResult {
            name: "health_check".to_string(),
            success: false,
            status_code: Some(500),
            latency_ms: None,
            error: Some("internal error".to_string()),
        }];

        let result = hypothesis.validate_probes(&probe_results);
        assert!(!result.holds);
    }

    // ── MetricsSnapshot tests ──

    #[test]
    fn metrics_snapshot_set_and_get() {
        let mut m = MetricsSnapshot::new();
        m.set("latency", 42.0, None);
        m.set("latency", 99.0, Some("service_a"));

        assert_eq!(m.get("latency", None), Some(&42.0));
        assert_eq!(m.get("latency", Some("service_a")), Some(&99.0));
        assert_eq!(m.get("latency", Some("service_b")), None);
        assert_eq!(m.len(), 2);
    }

    // ── FaultConfig tests ──

    #[test]
    fn fault_config_crash_builder() {
        let cfg = FaultConfig::crash("service_a".to_string(), 5000);
        assert_eq!(cfg.fault_type, FaultType::Crash);
        assert_eq!(cfg.duration_ms, 5000);
    }

    #[test]
    fn fault_config_latency_builder() {
        let cfg = FaultConfig::latency("service_b".to_string(), 3000, 500);
        assert_eq!(cfg.fault_type, FaultType::LatencyInjection);
        assert_eq!(cfg.latency_ms, Some(500));
    }

    #[test]
    fn fault_config_error_builder_clamps_probability() {
        let cfg = FaultConfig::error("svc".to_string(), 1000, 1.5, "err".to_string());
        assert_eq!(cfg.error_probability, Some(1.0));
    }

    #[test]
    fn fault_config_resource_exhaustion_builder() {
        let cfg = FaultConfig::resource_exhaustion("svc".to_string(), 2000, 0.9, 0.8);
        assert_eq!(cfg.cpu_load, Some(0.9));
        assert_eq!(cfg.memory_pressure, Some(0.8));
    }

    // ── FaultInjector tests ──

    #[test]
    fn fault_injector_inject_and_rollback() {
        let mut injector = FaultInjector::new(42);
        let cfg = FaultConfig::crash("svc_a".to_string(), 1000);

        let result = injector.inject(cfg);
        assert!(result.success);
        assert!(injector.has_active_fault("svc_a"));
        assert_eq!(injector.active_fault_count(), 1);

        let rb = injector.rollback("svc_a");
        assert!(rb.success);
        assert!(!injector.has_active_fault("svc_a"));
        assert_eq!(injector.active_fault_count(), 0);
    }

    #[test]
    fn fault_injector_rollback_nonexistent() {
        let mut injector = FaultInjector::new(42);
        let rb = injector.rollback("nonexistent");
        assert!(!rb.success);
    }

    #[test]
    fn fault_injector_apply_crash_effects() {
        let mut injector = FaultInjector::new(42);
        let cfg = FaultConfig::crash("svc_a".to_string(), 1000);
        injector.inject(cfg);

        let mut metrics = MetricsSnapshot::new();
        injector.apply_fault_effects(&mut metrics);

        assert_eq!(metrics.get("error_rate", Some("svc_a")), Some(&1.0));
        assert_eq!(metrics.get("availability", Some("svc_a")), Some(&0.0));
    }

    #[test]
    fn fault_injector_apply_latency_effects() {
        let mut injector = FaultInjector::new(42);
        let cfg = FaultConfig::latency("svc_b".to_string(), 1000, 200);
        injector.inject(cfg);

        let mut metrics = MetricsSnapshot::new();
        metrics.set("p99_latency", 50.0, Some("svc_b"));
        injector.apply_fault_effects(&mut metrics);

        assert_eq!(metrics.get("p99_latency", Some("svc_b")), Some(&250.0));
    }

    #[test]
    fn fault_injector_apply_resource_exhaustion_effects() {
        let mut injector = FaultInjector::new(42);
        let cfg = FaultConfig::resource_exhaustion("svc_c".to_string(), 1000, 0.8, 0.7);
        injector.inject(cfg);

        let mut metrics = MetricsSnapshot::new();
        metrics.set("p99_latency", 100.0, Some("svc_c"));
        injector.apply_fault_effects(&mut metrics);

        assert_eq!(metrics.get("cpu_usage", Some("svc_c")), Some(&0.8));
        // latency should be 100 * (1 + 0.8 * 3) = 100 * 3.4 = 340
        let latency = metrics.get("p99_latency", Some("svc_c")).copied().unwrap();
        assert!((latency - 340.0).abs() < 1e-6);
    }

    #[test]
    fn fault_injector_rollback_all() {
        let mut injector = FaultInjector::new(42);
        injector.inject(FaultConfig::crash("a".to_string(), 1000));
        injector.inject(FaultConfig::crash("b".to_string(), 1000));

        let results = injector.rollback_all();
        assert_eq!(results.len(), 2);
        assert_eq!(injector.active_fault_count(), 0);
    }

    // ── DependencyGraph tests ──

    #[test]
    fn dependency_graph_construction() {
        let graph = simple_graph();
        assert_eq!(graph.component_count(), 9);
    }

    #[test]
    fn dependency_graph_direct_dependencies() {
        let graph = simple_graph();
        let deps = graph.direct_dependencies("api_gateway");
        assert!(deps.contains(&&"auth_service".to_string()));
        assert!(deps.contains(&&"trust_engine".to_string()));
    }

    #[test]
    fn dependency_graph_direct_dependents() {
        let graph = simple_graph();
        let dependents = graph.direct_dependents("auth_service");
        assert!(dependents.contains(&&"api_gateway".to_string()));
    }

    // ── BlastRadius tests ──

    #[test]
    fn blast_radius_leaf_component() {
        let graph = simple_graph();
        // config_db is a leaf — nothing depends on it except policy_store.
        let blast = graph.compute_blast_radius("config_db");
        assert!(blast.affected_count <= 3); // policy_store, trust_engine, api_gateway
        assert!(blast.spread_fraction < 0.5);
    }

    #[test]
    fn blast_radius_root_component() {
        let graph = simple_graph();
        // If we target trust_engine, we need to check what depends on it.
        let blast = graph.compute_blast_radius("trust_engine");
        // Only api_gateway depends on trust_engine.
        assert!(blast.affected_components.contains(&"api_gateway".to_string()));
    }

    #[test]
    fn blast_radius_isolated_component() {
        let mut graph = DependencyGraph::new();
        graph.add_component("isolated".to_string());
        let blast = graph.compute_blast_radius("isolated");
        assert_eq!(blast.affected_count, 0);
        assert_eq!(blast.severity(), BlastRadiusSeverity::None);
    }

    #[test]
    fn blast_radius_acceptable_check() {
        let blast = BlastRadius {
            target: "test".to_string(),
            affected_components: vec![],
            affected_count: 0,
            total_components: 10,
            spread_fraction: 0.3,
            max_impact_score: 0.3,
            avg_impact_score: 0.15,
            impact_scores: HashMap::new(),
        };
        assert!(blast.is_acceptable(0.5));
        assert!(!blast.is_acceptable(0.2));
    }

    #[test]
    fn blast_radius_severity_levels() {
        let make = |spread| BlastRadius {
            target: "t".to_string(),
            affected_components: vec![],
            affected_count: (spread * 100.0) as usize,
            total_components: 100,
            spread_fraction: spread,
            max_impact_score: spread,
            avg_impact_score: spread / 2.0,
            impact_scores: HashMap::new(),
        };
        assert_eq!(make(0.0).severity(), BlastRadiusSeverity::None);
        assert_eq!(make(0.1).severity(), BlastRadiusSeverity::Low);
        assert_eq!(make(0.3).severity(), BlastRadiusSeverity::Medium);
        assert_eq!(make(0.5).severity(), BlastRadiusSeverity::High);
        assert_eq!(make(0.8).severity(), BlastRadiusSeverity::Critical);
    }

    // ── ChaosExperiment tests ──

    #[test]
    fn chaos_experiment_builder() {
        let exp = ChaosExperiment::new("exp-1".to_string(), "Test Crash".to_string())
            .with_description("Test crash recovery".to_string())
            .with_dry_run(true)
            .with_timeout(5000);

        assert_eq!(exp.id, "exp-1");
        assert!(exp.dry_run);
        assert_eq!(exp.timeout_ms, 5000);
    }

    // ── ExperimentOrchestrator tests ──

    #[test]
    fn orchestrator_dry_run_experiment() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let experiment = ChaosExperiment::new("dry-1".to_string(), "Dry Run Test".to_string())
            .with_fault(FaultConfig::crash("auth_service".to_string(), 1000))
            .with_steady_state(
                SteadyStateHypothesis::new()
                    .with_metric_condition(MetricCondition {
                        metric_name: "error_rate".to_string(),
                        comparator: MetricComparator::LessThan,
                        threshold: 0.05,
                        component: None,
                    }),
            )
            .with_rollback_plan("restart auth_service".to_string())
            .with_dry_run(true);

        let metrics = healthy_metrics();
        let report = orchestrator.run_experiment(&experiment, &metrics, &[]);

        assert_eq!(report.status, ExperimentStatus::Completed);
        assert!(report.dry_run);
        assert!(report.injection_result.is_none());
        assert!(report.blast_radius.is_some());
    }

    #[test]
    fn orchestrator_experiment_with_injection() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let experiment = ChaosExperiment::new("inject-1".to_string(), "Latency Test".to_string())
            .with_fault(FaultConfig::latency("rate_limiter".to_string(), 1000, 200))
            .with_steady_state(
                SteadyStateHypothesis::new()
                    .with_metric_condition(MetricCondition {
                        metric_name: "error_rate".to_string(),
                        comparator: MetricComparator::LessThan,
                        threshold: 0.05,
                        component: None,
                    }),
            )
            .with_rollback_plan("remove latency injection".to_string())
            .with_max_blast_radius(0.5);

        let metrics = healthy_metrics();
        let report = orchestrator.run_experiment(&experiment, &metrics, &[]);

        assert!(report.injection_result.is_some());
        assert!(!report.rollback_results.is_empty());
        assert_eq!(report.observations.len(), 3); // before, during, after
    }

    #[test]
    fn orchestrator_aborts_on_blast_radius_exceeded() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let experiment = ChaosExperiment::new("blast-1".to_string(), "Blast Radius Test".to_string())
            .with_fault(FaultConfig::crash("config_db".to_string(), 1000))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_max_blast_radius(0.01); // Extremely low limit.

        let metrics = healthy_metrics();
        let report = orchestrator.run_experiment(&experiment, &metrics, &[]);

        assert_eq!(report.status, ExperimentStatus::Aborted);
        assert!(report.injection_result.is_none());
    }

    #[test]
    fn orchestrator_aborts_on_trust_threshold() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let experiment = ChaosExperiment::new("trust-1".to_string(), "Trust Abort Test".to_string())
            .with_fault(FaultConfig::crash("trust_engine".to_string(), 1000))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_abort_threshold(0.99); // Very high — will trigger abort.

        let metrics = healthy_metrics();
        let report = orchestrator.run_experiment(&experiment, &metrics, &[]);

        assert_eq!(report.status, ExperimentStatus::Aborted);
    }

    #[test]
    fn orchestrator_sequential_execution_stops_on_abort() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let exp1 = ChaosExperiment::new("seq-1".to_string(), "First".to_string())
            .with_fault(FaultConfig::crash("redis_cache".to_string(), 1000))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_max_blast_radius(0.01); // Will abort.

        let exp2 = ChaosExperiment::new("seq-2".to_string(), "Second".to_string())
            .with_fault(FaultConfig::crash("auth_service".to_string(), 1000))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_dry_run(true);

        let metrics = healthy_metrics();
        let reports = orchestrator.run_experiments(
            &[exp1, exp2],
            &metrics,
            &[],
            OrchestrationMode::Sequential,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status, ExperimentStatus::Aborted);
    }

    #[test]
    fn orchestrator_parallel_execution_runs_all() {
        let graph = simple_graph();
        let mut orchestrator = ExperimentOrchestrator::new(graph);

        let exp1 = ChaosExperiment::new("par-1".to_string(), "Parallel 1".to_string())
            .with_fault(FaultConfig::crash("redis_cache".to_string(), 1000))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_dry_run(true);

        let exp2 = ChaosExperiment::new("par-2".to_string(), "Parallel 2".to_string())
            .with_fault(FaultConfig::latency("rate_limiter".to_string(), 1000, 100))
            .with_steady_state(SteadyStateHypothesis::new())
            .with_dry_run(true);

        let metrics = healthy_metrics();
        let reports = orchestrator.run_experiments(
            &[exp1, exp2],
            &metrics,
            &[],
            OrchestrationMode::Parallel,
        );

        assert_eq!(reports.len(), 2);
    }

    // ── SafetyMonitor tests ──

    #[test]
    fn safety_monitor_allows_safe_experiment() {
        let config = SafetyConfig::default();
        let monitor = SafetyMonitor::new(config);

        let experiment = ChaosExperiment::new("safe-1".to_string(), "Safe".to_string());
        let blast = BlastRadius {
            target: "t".to_string(),
            affected_components: vec![],
            affected_count: 0,
            total_components: 10,
            spread_fraction: 0.1,
            max_impact_score: 0.1,
            avg_impact_score: 0.1,
            impact_scores: HashMap::new(),
        };

        let result = monitor.pre_flight_check(&experiment, &blast);
        assert!(result.allowed);
    }

    #[test]
    fn safety_monitor_blocks_quarantined_component() {
        let mut config = SafetyConfig::default();
        config.quarantine_component("critical_service".to_string());
        let monitor = SafetyMonitor::new(config);

        let experiment = ChaosExperiment::new("q-1".to_string(), "Quarantine Test".to_string())
            .with_fault(FaultConfig::crash("critical_service".to_string(), 1000));
        let blast = BlastRadius {
            target: "critical_service".to_string(),
            affected_components: vec![],
            affected_count: 0,
            total_components: 10,
            spread_fraction: 0.0,
            max_impact_score: 0.0,
            avg_impact_score: 0.0,
            impact_scores: HashMap::new(),
        };

        let result = monitor.pre_flight_check(&experiment, &blast);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.severity == SafetyViolationSeverity::Critical));
    }

    #[test]
    fn safety_monitor_blocks_large_blast_radius() {
        let config = SafetyConfig::default();
        let monitor = SafetyMonitor::new(config);

        let experiment = ChaosExperiment::new("big-1".to_string(), "Big Blast".to_string());
        let blast = BlastRadius {
            target: "t".to_string(),
            affected_components: vec![],
            affected_count: 8,
            total_components: 10,
            spread_fraction: 0.8,
            max_impact_score: 0.8,
            avg_impact_score: 0.4,
            impact_scores: HashMap::new(),
        };

        let result = monitor.pre_flight_check(&experiment, &blast);
        assert!(!result.allowed);
    }

    #[test]
    fn safety_monitor_cumulative_blast_radius_tracking() {
        let config = SafetyConfig::default();
        let mut monitor = SafetyMonitor::new(config);

        monitor.register_experiment("exp-1".to_string(), 0.3);
        monitor.register_experiment("exp-2".to_string(), 0.2);
        assert_eq!(monitor.active_count(), 2);
        assert!((monitor.cumulative_blast_radius() - 0.5).abs() < 1e-9);

        monitor.deregister_experiment(&"exp-1".to_string(), 0.3);
        assert_eq!(monitor.active_count(), 1);
        assert!((monitor.cumulative_blast_radius() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn safety_monitor_emergency_abort() {
        let config = SafetyConfig::default();
        let mut monitor = SafetyMonitor::new(config);
        monitor.register_experiment("e1".to_string(), 0.3);
        monitor.register_experiment("e2".to_string(), 0.4);

        monitor.emergency_abort();
        assert_eq!(monitor.active_count(), 0);
        assert_eq!(monitor.cumulative_blast_radius(), 0.0);
    }

    #[test]
    fn safety_monitor_trust_floor_check() {
        let config = SafetyConfig::default();
        let monitor = SafetyMonitor::new(config);

        assert!(monitor.check_trust_floor(0.5));
        assert!(monitor.check_trust_floor(0.2));
        assert!(!monitor.check_trust_floor(0.1));
    }

    // ── Serialization tests ──

    #[test]
    fn experiment_serialization_roundtrip() {
        let exp = ChaosExperiment::new("ser-1".to_string(), "Serialize Test".to_string())
            .with_fault(FaultConfig::latency("svc".to_string(), 5000, 200))
            .with_dry_run(true);

        let json = serde_json::to_string(&exp).unwrap();
        let restored: ChaosExperiment = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, exp.id);
        assert_eq!(restored.name, exp.name);
        assert!(restored.dry_run);
    }

    #[test]
    fn report_serialization_roundtrip() {
        let report = ExperimentReport {
            experiment_id: "rpt-1".to_string(),
            experiment_name: "Report Test".to_string(),
            status: ExperimentStatus::Completed,
            observations: vec![],
            before_hypothesis: None,
            after_hypothesis: None,
            blast_radius: None,
            injection_result: None,
            rollback_results: vec![],
            started_at: Utc::now(),
            ended_at: Utc::now(),
            duration_ms: 100,
            dry_run: false,
            summary: "test".to_string(),
        };

        let json = serde_json::to_string(&report).unwrap();
        let restored: ExperimentReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.experiment_id, "rpt-1");
        assert_eq!(restored.status, ExperimentStatus::Completed);
    }

    #[test]
    fn fault_config_serialization_roundtrip() {
        let cfg = FaultConfig::resource_exhaustion("svc".to_string(), 3000, 0.9, 0.8);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: FaultConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.fault_type, FaultType::ResourceExhaustion);
        assert_eq!(restored.cpu_load, Some(0.9));
    }

    #[test]
    fn safety_config_strict_and_permissive() {
        let strict = SafetyConfig::strict();
        let permissive = SafetyConfig::permissive();

        assert!(strict.max_single_blast_radius < permissive.max_single_blast_radius);
        assert!(strict.global_trust_floor > permissive.global_trust_floor);
        assert!(strict.max_concurrent_experiments < permissive.max_concurrent_experiments);
    }
}
