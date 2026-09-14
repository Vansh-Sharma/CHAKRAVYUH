// ANANTA Runtime — Lifecycle Management
//
// Manages the ANANTA plane's runtime state:
//   1. Startup sequence and initialization
//   2. Graceful shutdown
//   3. Component lifecycle tracking
//   4. Resource monitoring (memory, CPU approximation)
//   5. Uptime and performance metrics

pub mod runtime_wasm;
pub use runtime_wasm::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Runtime phase of ANANTA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    /// ANANTA has not started yet.
    Uninitialized,
    /// Currently initializing subsystems.
    Initializing,
    /// ANANTA is running and monitoring.
    Running,
    /// ANANTA is in the process of shutting down.
    ShuttingDown,
    /// ANANTA has fully stopped.
    Stopped,
    /// ANANTA encountered an error during startup.
    Failed,
}

impl std::fmt::Display for RuntimePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Component lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    NotStarted,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl std::fmt::Display for ComponentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Status of a single ANANTA component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component name (e.g., "sentinel", "phoenix", "audit").
    pub name: String,
    /// Current lifecycle state.
    pub state: ComponentState,
    /// When the component entered this state.
    pub since: String,
    /// Error message if failed.
    pub error: Option<String>,
    /// Number of restarts.
    pub restart_count: u64,
    /// Component-specific metrics.
    pub metrics: HashMap<String, f64>,
}

impl ComponentStatus {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            state: ComponentState::NotStarted,
            since: chrono::Utc::now().to_rfc3339(),
            error: None,
            restart_count: 0,
            metrics: HashMap::new(),
        }
    }

    pub fn set_state(&mut self, state: ComponentState) {
        self.state = state;
        self.since = chrono::Utc::now().to_rfc3339();
    }
}

/// Resource usage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Estimated memory usage in bytes (from the allocator).
    pub memory_bytes: u64,
    /// CPU time used by ANANTA tasks (microseconds).
    pub cpu_time_us: u64,
    /// Number of active tokio tasks.
    pub active_tasks: usize,
    /// Timestamp of this snapshot.
    pub timestamp: String,
}

impl ResourceUsage {
    pub fn now(active_tasks: usize) -> Self {
        Self {
            // Use a rough estimate. Real implementation would use
            // platform-specific APIs.
            memory_bytes: 0,
            cpu_time_us: 0,
            active_tasks,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// ANANTA runtime state.
pub struct RuntimeState {
    /// Current runtime phase.
    phase: RuntimePhase,
    /// When ANANTA started.
    started_at: Option<Instant>,
    /// When ANANTA entered the current phase.
    phase_entered_at: Instant,
    /// Per-component status.
    components: HashMap<String, ComponentStatus>,
    /// Resource usage history.
    resource_history: Vec<ResourceUsage>,
    /// Max resource history entries.
    max_resource_history: usize,
}

impl RuntimeState {
    /// Create a new runtime state.
    pub fn new() -> Self {
        Self {
            phase: RuntimePhase::Uninitialized,
            started_at: None,
            phase_entered_at: Instant::now(),
            components: HashMap::new(),
            resource_history: vec![],
            max_resource_history: 1000,
        }
    }

    /// Register a component.
    pub fn register_component(&mut self, name: &str) {
        self.components
            .insert(name.into(), ComponentStatus::new(name));
    }

    /// Set the runtime phase.
    pub fn set_phase(&mut self, phase: RuntimePhase) {
        let is_running = phase == RuntimePhase::Running;
        self.phase = phase;
        self.phase_entered_at = Instant::now();

        if is_running && self.started_at.is_none() {
            self.started_at = Some(Instant::now());
        }
    }

    /// Get the current phase.
    pub fn phase(&self) -> &RuntimePhase {
        &self.phase
    }

    /// Set a component's state.
    pub fn set_component_state(&mut self, name: &str, state: ComponentState) {
        if let Some(component) = self.components.get_mut(name) {
            if component.state == ComponentState::Running && state == ComponentState::Failed {
                component.restart_count += 1;
            }
            component.set_state(state);
        }
    }

    /// Set a component's error message.
    pub fn set_component_error(&mut self, name: &str, error: &str) {
        if let Some(component) = self.components.get_mut(name) {
            component.error = Some(error.into());
            component.set_state(ComponentState::Failed);
        }
    }

    /// Set a component metric.
    pub fn set_component_metric(&mut self, component: &str, key: &str, value: f64) {
        if let Some(comp) = self.components.get_mut(component) {
            comp.metrics.insert(key.into(), value);
        }
    }

    /// Get a component's status.
    pub fn component_status(&self, name: &str) -> Option<&ComponentStatus> {
        self.components.get(name)
    }

    /// Get all component statuses.
    pub fn component_statuses(&self) -> &HashMap<String, ComponentStatus> {
        &self.components
    }

    /// Record a resource usage snapshot.
    pub fn record_resource_usage(&mut self, usage: ResourceUsage) {
        self.resource_history.push(usage);
        if self.resource_history.len() > self.max_resource_history {
            self.resource_history.remove(0);
        }
    }

    /// Get the latest resource usage.
    pub fn latest_resource_usage(&self) -> Option<&ResourceUsage> {
        self.resource_history.last()
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> f64 {
        self.started_at
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Time in current phase (seconds).
    pub fn phase_duration_secs(&self) -> f64 {
        self.phase_entered_at.elapsed().as_secs_f64()
    }

    /// Check if all registered components are running.
    pub fn all_components_running(&self) -> bool {
        self.components
            .values()
            .all(|c| c.state == ComponentState::Running)
    }

    /// Count components by state.
    pub fn component_state_counts(&self) -> HashMap<ComponentState, usize> {
        let mut counts = HashMap::new();
        for comp in self.components.values() {
            *counts.entry(comp.state.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Get a summary of the runtime state.
    pub fn summary(&self) -> String {
        format!(
            "phase={} uptime={:.1}s components={}/{} running",
            self.phase,
            self.uptime_secs(),
            self.components
                .values()
                .filter(|c| c.state == ComponentState::Running)
                .count(),
            self.components.len(),
        )
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

/// ANANTA component names.
pub struct Components;

impl Components {
    pub const SENTINEL: &'static str = "sentinel";
    pub const PHOENIX: &'static str = "phoenix";
    pub const ANCHOR: &'static str = "anchor";
    pub const TRUST: &'static str = "trust";
    pub const ADAPTER: &'static str = "adapter";
    pub const HEALTH: &'static str = "health";
    pub const AUDIT: &'static str = "audit";
    pub const SIMULATION: &'static str = "simulation";
    pub const DISTRIBUTED: &'static str = "distributed";
    pub const SCHEDULER: &'static str = "scheduler";

    /// All component names.
    pub fn all() -> &'static [&'static str] {
        &[
            Self::SENTINEL,
            Self::PHOENIX,
            Self::ANCHOR,
            Self::TRUST,
            Self::ADAPTER,
            Self::HEALTH,
            Self::AUDIT,
            Self::SIMULATION,
            Self::DISTRIBUTED,
            Self::SCHEDULER,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_runtime_is_uninitialized() {
        let rt = RuntimeState::new();
        assert_eq!(rt.phase(), &RuntimePhase::Uninitialized);
        assert_eq!(rt.uptime_secs(), 0.0);
    }

    #[test]
    fn phase_transitions() {
        let mut rt = RuntimeState::new();
        rt.set_phase(RuntimePhase::Initializing);
        assert_eq!(rt.phase(), &RuntimePhase::Initializing);

        rt.set_phase(RuntimePhase::Running);
        assert!(rt.uptime_secs() >= 0.0);
        assert!(rt.uptime_secs() < 1.0);
    }

    #[test]
    fn register_and_track_components() {
        let mut rt = RuntimeState::new();
        rt.register_component(Components::SENTINEL);
        rt.register_component(Components::PHOENIX);

        rt.set_component_state(Components::SENTINEL, ComponentState::Running);
        rt.set_component_state(Components::PHOENIX, ComponentState::Running);

        assert!(rt.all_components_running());
    }

    #[test]
    fn component_failure_tracks_restarts() {
        let mut rt = RuntimeState::new();
        rt.register_component("test");
        rt.set_component_state("test", ComponentState::Running);

        // Fail it twice.
        rt.set_component_state("test", ComponentState::Failed);
        rt.set_component_state("test", ComponentState::Running);
        rt.set_component_state("test", ComponentState::Failed);

        assert_eq!(rt.component_status("test").unwrap().restart_count, 2);
    }

    #[test]
    fn component_error() {
        let mut rt = RuntimeState::new();
        rt.register_component("test");
        rt.set_component_error("test", "something broke");

        let status = rt.component_status("test").unwrap();
        assert_eq!(status.state, ComponentState::Failed);
        assert_eq!(status.error, Some("something broke".into()));
    }

    #[test]
    fn component_metrics() {
        let mut rt = RuntimeState::new();
        rt.register_component("sentinel");
        rt.set_component_metric("sentinel", "cycles_completed", 42.0);
        rt.set_component_metric("sentinel", "alerts_generated", 3.0);

        let status = rt.component_status("sentinel").unwrap();
        assert_eq!(status.metrics.get("cycles_completed"), Some(&42.0));
    }

    #[test]
    fn resource_tracking() {
        let mut rt = RuntimeState::new();
        rt.record_resource_usage(ResourceUsage::now(5));
        rt.record_resource_usage(ResourceUsage::now(8));

        let latest = rt.latest_resource_usage().unwrap();
        assert_eq!(latest.active_tasks, 8);
    }

    #[test]
    fn component_state_counts() {
        let mut rt = RuntimeState::new();
        rt.register_component("a");
        rt.register_component("b");
        rt.register_component("c");
        rt.set_component_state("a", ComponentState::Running);
        rt.set_component_state("b", ComponentState::Running);
        rt.set_component_state("c", ComponentState::Failed);

        let counts = rt.component_state_counts();
        assert_eq!(*counts.get(&ComponentState::Running).unwrap(), 2);
        assert_eq!(*counts.get(&ComponentState::Failed).unwrap(), 1);
    }

    #[test]
    fn all_components_constant() {
        let all = Components::all();
        assert!(all.len() >= 10);
        assert!(all.contains(&"sentinel"));
        assert!(all.contains(&"phoenix"));
    }

    #[test]
    fn summary_format() {
        let mut rt = RuntimeState::new();
        rt.register_component("sentinel");
        rt.set_phase(RuntimePhase::Running);
        rt.set_component_state("sentinel", ComponentState::Running);

        let summary = rt.summary();
        assert!(summary.contains("Running"));
        assert!(summary.contains("1/1"));
    }

    #[test]
    fn serialization() {
        let mut rt = RuntimeState::new();
        rt.register_component("sentinel");
        rt.set_phase(RuntimePhase::Running);
        rt.set_component_state("sentinel", ComponentState::Running);

        // Serialize component status.
        let status = rt.component_status("sentinel").unwrap();
        let json = serde_json::to_string(status).unwrap();
        let restored: ComponentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "sentinel");
    }
}
