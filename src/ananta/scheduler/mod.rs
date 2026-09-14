// ANANTA Scheduler — Background Task Scheduling
//
// ANANTA runs multiple periodic tasks:
//   - Sentinel attestation cycles
//   - Trust proof generation
//   - Health graph computation
//   - Audit log compaction
//   - Simulation runs
//   - Distributed heartbeats
//
// The scheduler manages these tasks with:
//   - Configurable intervals
//   - Jitter to prevent thundering herd
//   - Missed-task detection and recovery
//   - Task execution metrics

pub mod scheduler_priority;
pub use scheduler_priority::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a scheduled task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task is registered but not yet started.
    Idle,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
    /// Task was skipped (e.g., rate limited).
    Skipped,
    /// Task has been cancelled.
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A task execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskExecution {
    /// Task name.
    pub task_name: String,
    /// When this execution started.
    pub started_at: String,
    /// When this execution finished.
    pub finished_at: Option<String>,
    /// How long the execution took (ms).
    pub duration_ms: Option<u64>,
    /// Whether it succeeded.
    pub status: TaskStatus,
    /// Error message if failed.
    pub error: Option<String>,
}

/// A scheduled task definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// Unique task name.
    pub name: String,
    /// Interval between executions (ms).
    pub interval_ms: u64,
    /// Random jitter range (ms) to prevent synchronized execution.
    pub jitter_ms: u64,
    /// Current status.
    pub status: TaskStatus,
    /// Last execution record.
    pub last_execution: Option<TaskExecution>,
    /// Next scheduled execution time (ms since epoch).
    pub next_run_ms: u64,
    /// Total times this task has been executed.
    pub total_executions: u64,
    /// Total failures.
    pub total_failures: u64,
    /// Consecutive failures.
    pub consecutive_failures: u64,
    /// Whether the task is enabled.
    pub enabled: bool,
    /// Task description.
    pub description: String,
}

impl ScheduledTask {
    /// Create a new scheduled task.
    pub fn new(name: &str, interval_ms: u64, description: &str) -> Self {
        Self {
            name: name.into(),
            interval_ms,
            jitter_ms: 100, // Default 100ms jitter.
            status: TaskStatus::Idle,
            last_execution: None,
            next_run_ms: 0,
            total_executions: 0,
            total_failures: 0,
            consecutive_failures: 0,
            enabled: true,
            description: description.into(),
        }
    }

    /// Set jitter.
    pub fn with_jitter(mut self, jitter_ms: u64) -> Self {
        self.jitter_ms = jitter_ms;
        self
    }

    /// Calculate the actual interval with jitter applied.
    pub fn effective_interval(&self) -> u64 {
        if self.jitter_ms == 0 {
            return self.interval_ms;
        }
        let jitter: i64 = ((rand::random::<f64>() * 2.0 - 1.0) * self.jitter_ms as f64) as i64;
        (self.interval_ms as i64 + jitter).max(0) as u64
    }

    /// Record a successful execution.
    pub fn record_success(&mut self, duration_ms: u64) {
        self.status = TaskStatus::Completed;
        self.last_execution = Some(TaskExecution {
            task_name: self.name.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: Some(chrono::Utc::now().to_rfc3339()),
            duration_ms: Some(duration_ms),
            status: TaskStatus::Completed,
            error: None,
        });
        self.total_executions += 1;
        self.consecutive_failures = 0;
        self.update_next_run();
    }

    /// Record a failed execution.
    pub fn record_failure(&mut self, duration_ms: u64, error: &str) {
        self.status = TaskStatus::Failed;
        self.last_execution = Some(TaskExecution {
            task_name: self.name.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: Some(chrono::Utc::now().to_rfc3339()),
            duration_ms: Some(duration_ms),
            status: TaskStatus::Failed,
            error: Some(error.into()),
        });
        self.total_executions += 1;
        self.total_failures += 1;
        self.consecutive_failures += 1;
        self.update_next_run();
    }

    /// Record that the task was skipped.
    pub fn record_skipped(&mut self, reason: &str) {
        self.status = TaskStatus::Skipped;
        self.last_execution = Some(TaskExecution {
            task_name: self.name.clone(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: Some(chrono::Utc::now().to_rfc3339()),
            duration_ms: None,
            status: TaskStatus::Skipped,
            error: Some(reason.into()),
        });
        self.update_next_run();
    }

    /// Mark the task as currently running.
    pub fn mark_running(&mut self) {
        self.status = TaskStatus::Running;
    }

    /// Check if the task is due for execution.
    pub fn is_due(&self, now_ms: u64) -> bool {
        if !self.enabled {
            return false;
        }
        now_ms >= self.next_run_ms
    }

    /// Update the next run time.
    fn update_next_run(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.next_run_ms = now + self.effective_interval();
    }

    /// Compute the success rate (0.0-1.0).
    pub fn success_rate(&self) -> f64 {
        if self.total_executions == 0 {
            return 1.0;
        }
        let successes = self.total_executions - self.total_failures;
        successes as f64 / self.total_executions as f64
    }

    /// Enable or disable the task.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// The ANANTA task scheduler.
pub struct Scheduler {
    /// All registered tasks.
    tasks: HashMap<String, ScheduledTask>,
}

impl Scheduler {
    /// Create a new scheduler with default ANANTA tasks.
    pub fn new() -> Self {
        let mut scheduler = Self {
            tasks: HashMap::new(),
        };

        // Register default ANANTA tasks.
        scheduler.register(ScheduledTask::new(
            "attestation_cycle",
            1000,
            "Run a full integrity attestation cycle",
        ));
        scheduler.register(ScheduledTask::new(
            "trust_state_update",
            5000,
            "Compute and update trust state",
        ));
        scheduler.register(ScheduledTask::new(
            "trust_proof_generation",
            5000,
            "Generate cryptographic trust proof",
        ));
        scheduler.register(ScheduledTask::new(
            "health_graph_update",
            2000,
            "Recompute the health graph",
        ));
        scheduler.register(ScheduledTask::new(
            "drift_detection",
            1000,
            "Run drift detection on all 10 types",
        ));
        scheduler.register(ScheduledTask::new(
            "audit_compaction",
            300_000, // Every 5 minutes.
            "Compact audit log if needed",
        ));
        scheduler.register(ScheduledTask::new(
            "distributed_heartbeat",
            5000,
            "Send heartbeat to distributed peers",
        ));
        scheduler.register(ScheduledTask::new(
            "recovery_history_prune",
            3_600_000, // Every hour.
            "Prune old recovery history entries",
        ));

        scheduler
    }

    /// Register a task.
    pub fn register(&mut self, task: ScheduledTask) {
        self.tasks.insert(task.name.clone(), task);
    }

    /// Get a task by name.
    pub fn get(&self, name: &str) -> Option<&ScheduledTask> {
        self.tasks.get(name)
    }

    /// Get a mutable task by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut ScheduledTask> {
        self.tasks.get_mut(name)
    }

    /// Get all tasks that are currently due.
    pub fn due_tasks(&self) -> Vec<&ScheduledTask> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.tasks.values().filter(|t| t.is_due(now)).collect()
    }

    /// Get all task names.
    pub fn task_names(&self) -> Vec<String> {
        self.tasks.keys().cloned().collect()
    }

    /// Get all tasks.
    pub fn tasks(&self) -> &HashMap<String, ScheduledTask> {
        &self.tasks
    }

    /// Disable a task.
    pub fn disable(&mut self, name: &str) -> bool {
        if let Some(task) = self.tasks.get_mut(name) {
            task.set_enabled(false);
            true
        } else {
            false
        }
    }

    /// Enable a task.
    pub fn enable(&mut self, name: &str) -> bool {
        if let Some(task) = self.tasks.get_mut(name) {
            task.set_enabled(true);
            true
        } else {
            false
        }
    }

    /// Get a summary of all tasks.
    pub fn summary(&self) -> String {
        let total = self.tasks.len();
        let running = self
            .tasks
            .values()
            .filter(|t| t.status == TaskStatus::Running)
            .count();
        let failed = self
            .tasks
            .values()
            .filter(|t| t.consecutive_failures > 0)
            .count();
        format!(
            "scheduler: tasks={} running={} failed={}",
            total, running, failed,
        )
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_scheduler_has_default_tasks() {
        let scheduler = Scheduler::new();
        assert!(scheduler.get("attestation_cycle").is_some());
        assert!(scheduler.get("trust_state_update").is_some());
        assert!(scheduler.get("drift_detection").is_some());
    }

    #[test]
    fn register_custom_task() {
        let mut scheduler = Scheduler::new();
        scheduler.register(ScheduledTask::new("custom_task", 500, "A custom task"));
        assert!(scheduler.get("custom_task").is_some());
    }

    #[test]
    fn task_success_recording() {
        let mut task = ScheduledTask::new("test", 1000, "test task");
        task.record_success(50);
        assert_eq!(task.total_executions, 1);
        assert_eq!(task.total_failures, 0);
        assert_eq!(task.consecutive_failures, 0);
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.success_rate(), 1.0);
    }

    #[test]
    fn task_failure_recording() {
        let mut task = ScheduledTask::new("test", 1000, "test task");
        task.record_failure(10, "something went wrong");
        assert_eq!(task.total_executions, 1);
        assert_eq!(task.total_failures, 1);
        assert_eq!(task.consecutive_failures, 1);
        assert_eq!(task.success_rate(), 0.0);
    }

    #[test]
    fn task_success_rate() {
        let mut task = ScheduledTask::new("test", 1000, "test task");
        for _ in 0..7 {
            task.record_success(10);
        }
        for _ in 0..3 {
            task.record_failure(10, "fail");
        }
        assert!((task.success_rate() - 0.7).abs() < 0.01);
    }

    #[test]
    fn task_skip_recording() {
        let mut task = ScheduledTask::new("test", 1000, "test task");
        task.record_skipped("rate limited");
        assert_eq!(task.status, TaskStatus::Skipped);
        assert!(task.last_execution.is_some());
    }

    #[test]
    fn consecutive_failures_reset_on_success() {
        let mut task = ScheduledTask::new("test", 1000, "test task");
        task.record_failure(10, "fail");
        task.record_failure(10, "fail");
        assert_eq!(task.consecutive_failures, 2);
        task.record_success(10);
        assert_eq!(task.consecutive_failures, 0);
    }

    #[test]
    fn disable_and_enable() {
        let mut scheduler = Scheduler::new();
        assert!(scheduler.disable("attestation_cycle"));
        assert!(!scheduler.get("attestation_cycle").unwrap().enabled);
        assert!(scheduler.enable("attestation_cycle"));
        assert!(scheduler.get("attestation_cycle").unwrap().enabled);
    }

    #[test]
    fn disable_nonexistent() {
        let mut scheduler = Scheduler::new();
        assert!(!scheduler.disable("nonexistent"));
    }

    #[test]
    fn due_tasks_includes_enabled() {
        let mut scheduler = Scheduler::new();
        // Set next_run to 0 so it's always due.
        if let Some(task) = scheduler.get_mut("attestation_cycle") {
            task.next_run_ms = 0;
        }
        let due = scheduler.due_tasks();
        assert!(!due.is_empty());
    }

    #[test]
    fn due_tasks_excludes_disabled() {
        let mut scheduler = Scheduler::new();
        scheduler.disable("attestation_cycle");
        if let Some(task) = scheduler.get_mut("attestation_cycle") {
            task.next_run_ms = 0;
        }
        let due = scheduler.due_tasks();
        assert!(!due.iter().any(|t| t.name == "attestation_cycle"));
    }

    #[test]
    fn jitter_varies_interval() {
        let task = ScheduledTask::new("test", 1000, "test").with_jitter(200);
        let intervals: Vec<u64> = (0..100).map(|_| task.effective_interval()).collect();
        let min = *intervals.iter().min().unwrap();
        let max = *intervals.iter().max().unwrap();
        // With jitter, min and max should differ.
        assert!(max > min);
    }

    #[test]
    fn summary_format() {
        let scheduler = Scheduler::new();
        let summary = scheduler.summary();
        assert!(summary.contains("scheduler:"));
    }

    #[test]
    fn task_serialization() {
        let task = ScheduledTask::new("test", 1000, "test task");
        let json = serde_json::to_string(&task).unwrap();
        let restored: ScheduledTask = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "test");
        assert_eq!(restored.interval_ms, 1000);
    }

    #[test]
    fn execution_record_serialization() {
        let exec = TaskExecution {
            task_name: "test".into(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: Some(chrono::Utc::now().to_rfc3339()),
            duration_ms: Some(42),
            status: TaskStatus::Completed,
            error: None,
        };
        let json = serde_json::to_string(&exec).unwrap();
        let restored: TaskExecution = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.task_name, "test");
    }
}
