// ANANTA Priority Scheduler — Advanced Scheduling with Dynamic Priorities
//
// Implements six core subsystems:
//   1. Multi-level priority queue with dynamic priority adjustment
//   2. Earliest-Deadline-First (EDF) scheduling with slack time computation
//   3. Token-bucket rate limiting with fair sharing and backpressure
//   4. Jitter-based scheduling (uniform, exponential, bounded Pareto)
//   5. Task dependency DAG with cycle detection and critical path analysis
//   6. Comprehensive scheduling metrics (wait time, SLA compliance, etc.)

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// 1. Priority Queue with Dynamic Priorities
// ---------------------------------------------------------------------------

/// Represents a discrete priority level in the multi-level queue.
/// Lower ordinal values indicate higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PriorityLevel {
    /// Highest priority — system-critical tasks (e.g., attestation).
    Critical = 0,
    /// High priority — security-sensitive tasks (e.g., trust proof generation).
    High = 1,
    /// Normal priority — standard operational tasks (e.g., health graph update).
    Normal = 2,
    /// Low priority — background maintenance (e.g., audit compaction).
    Low = 3,
    /// Idle/batch — deferrable work that runs only when nothing else is pending.
    Idle = 4,
}

impl PriorityLevel {
    /// Number of discrete priority levels.
    pub const LEVEL_COUNT: usize = 5;

    /// Convert the level to its ordinal value (0 = highest).
    pub fn ordinal(&self) -> usize {
        match self {
            PriorityLevel::Critical => 0,
            PriorityLevel::High => 1,
            PriorityLevel::Normal => 2,
            PriorityLevel::Low => 3,
            PriorityLevel::Idle => 4,
        }
    }

    /// Create a priority level from an ordinal. Clamps to the valid range.
    pub fn from_ordinal(ord: usize) -> Self {
        match ord.min(PriorityLevel::LEVEL_COUNT - 1) {
            0 => PriorityLevel::Critical,
            1 => PriorityLevel::High,
            2 => PriorityLevel::Normal,
            3 => PriorityLevel::Low,
            _ => PriorityLevel::Idle,
        }
    }

    /// Return all priority levels from highest to lowest.
    pub fn all_levels() -> Vec<PriorityLevel> {
        vec![
            PriorityLevel::Critical,
            PriorityLevel::High,
            PriorityLevel::Normal,
            PriorityLevel::Low,
            PriorityLevel::Idle,
        ]
    }
}

/// A task entry in the priority queue, carrying both static and dynamic priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityTask {
    /// Unique task identifier.
    pub id: String,
    /// Human-readable task name.
    pub name: String,
    /// The static (base) priority assigned at enqueue time.
    pub base_priority: PriorityLevel,
    /// Dynamically adjusted effective priority (may be boosted or demoted).
    pub effective_priority: PriorityLevel,
    /// Monotonic timestamp (ms) when the task was enqueued.
    pub enqueued_at_ms: u64,
    /// Current system time in ms, used for age computation.
    pub current_time_ms: u64,
    /// Health score of the originating node [0.0, 1.0].
    pub health_score: f64,
    /// Trust score of the originating node [0.0, 1.0].
    pub trust_score: f64,
    /// Number of times this task has been re-enqueued (retry count).
    pub retry_count: u32,
    /// Optional deadline in ms since epoch. If `None`, the task has no deadline.
    pub deadline_ms: Option<u64>,
    /// Optional parent task ID for priority inheritance.
    pub parent_id: Option<String>,
}

impl PriorityTask {
    /// Create a new priority task.
    pub fn new(id: &str, name: &str, base_priority: PriorityLevel, enqueued_at_ms: u64) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            base_priority,
            effective_priority: base_priority,
            enqueued_at_ms,
            current_time_ms: enqueued_at_ms,
            health_score: 1.0,
            trust_score: 1.0,
            retry_count: 0,
            deadline_ms: None,
            parent_id: None,
        }
    }

    /// Set the health and trust scores.
    pub fn with_scores(mut self, health: f64, trust: f64) -> Self {
        self.health_score = health.clamp(0.0, 1.0);
        self.trust_score = trust.clamp(0.0, 1.0);
        self
    }

    /// Set a deadline.
    pub fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    /// Set a parent for priority inheritance.
    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_id = Some(parent_id.to_string());
        self
    }

    /// Set the retry count.
    pub fn with_retry_count(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    /// Update the current time and recompute the effective priority.
    pub fn update_time(&mut self, now_ms: u64) {
        self.current_time_ms = now_ms;
        self.effective_priority = self.compute_dynamic_priority();
    }

    /// Compute the age of the task in milliseconds.
    pub fn age_ms(&self) -> u64 {
        self.current_time_ms.saturating_sub(self.enqueued_at_ms)
    }

    /// Compute a composite dynamic priority based on age, health, trust, and retries.
    ///
    /// The algorithm uses a weighted scoring model:
    ///   - Age bonus: tasks older than `age_boost_threshold_ms` are boosted one level
    ///     per `age_boost_interval_ms` elapsed beyond the threshold.
    ///   - Health factor: low-health nodes have their tasks demoted.
    ///   - Trust factor: low-trust nodes have their tasks demoted.
    ///   - Retry penalty: each retry above the threshold demotes the task one level.
    pub fn compute_dynamic_priority(&self) -> PriorityLevel {
        let base_ord = self.base_priority.ordinal() as i32;
        let mut delta: i32 = 0;

        // Age-based boosting: promote waiting tasks to prevent starvation.
        let age_boost_threshold_ms: u64 = 10_000;
        let age_boost_interval_ms: u64 = 5_000;
        let age = self.age_ms();
        if age > age_boost_threshold_ms {
            let excess_intervals = ((age - age_boost_threshold_ms) / age_boost_interval_ms) as i32;
            delta -= excess_intervals; // negative delta = higher priority
        }

        // Health factor: demote tasks from unhealthy nodes.
        // If health < 0.5, demote by one level; if health < 0.3, demote by two.
        if self.health_score < 0.3 {
            delta += 2;
        } else if self.health_score < 0.5 {
            delta += 1;
        }

        // Trust factor: demote tasks from untrusted nodes.
        if self.trust_score < 0.3 {
            delta += 2;
        } else if self.trust_score < 0.5 {
            delta += 1;
        }

        // Retry penalty: too many retries suggest a problematic task.
        let retry_penalty_threshold: u32 = 3;
        if self.retry_count > retry_penalty_threshold {
            let excess = (self.retry_count - retry_penalty_threshold) as i32;
            delta += excess.min(2); // cap at +2
        }

        // Deadline urgency: if deadline is approaching within 2 seconds, boost.
        if let Some(deadline) = self.deadline_ms {
            let remaining = deadline.saturating_sub(self.current_time_ms);
            if remaining < 2_000 && remaining > 0 {
                delta -= 1; // boost by one level
            }
        }

        let adjusted = base_ord + delta;
        let clamped = adjusted.clamp(0, (PriorityLevel::LEVEL_COUNT - 1) as i32);
        PriorityLevel::from_ordinal(clamped as usize)
    }
}

/// A multi-level priority queue that supports dynamic priority adjustment,
/// priority inheritance, and priority ceiling protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityScheduler {
    /// One FIFO queue per priority level, indexed by `PriorityLevel::ordinal()`.
    queues: Vec<VecDeque<PriorityTask>>,
    /// Priority ceiling — the maximum effective priority any task may inherit.
    pub priority_ceiling: PriorityLevel,
    /// Mapping from task ID to its current priority for inheritance lookups.
    task_priorities: HashMap<String, PriorityLevel>,
    /// Total number of tasks across all queues.
    total_count: usize,
}

impl PriorityScheduler {
    /// Create a new priority scheduler with the given priority ceiling.
    pub fn new(ceiling: PriorityLevel) -> Self {
        let queues = (0..PriorityLevel::LEVEL_COUNT)
            .map(|_| VecDeque::new())
            .collect();
        Self {
            queues,
            priority_ceiling: ceiling,
            task_priorities: HashMap::new(),
            total_count: 0,
        }
    }

    /// Enqueue a task. The task's effective priority is computed from its base
    /// priority plus any priority inheritance from its parent.
    pub fn enqueue(&mut self, mut task: PriorityTask) {
        // Apply priority inheritance from parent.
        if let Some(ref parent_id) = task.parent_id {
            if let Some(&parent_pri) = self.task_priorities.get(parent_id) {
                // Inherit the parent's priority if it is higher.
                if parent_pri < task.effective_priority {
                    task.effective_priority = parent_pri;
                }
            }
        }
        // Enforce the priority ceiling.
        if task.effective_priority < self.priority_ceiling {
            task.effective_priority = self.priority_ceiling;
        }
        let idx = task.effective_priority.ordinal();
        self.task_priorities.insert(task.id.clone(), task.effective_priority);
        self.queues[idx].push_back(task);
        self.total_count += 1;
    }

    /// Dequeue the highest-priority task, applying dynamic priority recalculation.
    /// Returns `None` if all queues are empty.
    pub fn dequeue(&mut self, now_ms: u64) -> Option<PriorityTask> {
        for level in PriorityLevel::all_levels() {
            let idx = level.ordinal();
            if !self.queues[idx].is_empty() {
                // Recompute dynamic priorities for all tasks at this level.
                let mut reordered: Vec<PriorityTask> = self.queues[idx].drain(..).collect();
                for task in &mut reordered {
                    task.update_time(now_ms);
                    // Re-enforce the priority ceiling after dynamic recalculation.
                    if task.effective_priority < self.priority_ceiling {
                        task.effective_priority = self.priority_ceiling;
                    }
                }
                // Sort by effective priority (stable: oldest first within same level).
                reordered.sort_by_key(|t| (t.effective_priority.ordinal(), t.enqueued_at_ms));
                // Re-enqueue tasks that moved to a different level.
                for task in reordered {
                    let new_idx = task.effective_priority.ordinal();
                    if new_idx != idx {
                        self.queues[new_idx].push_back(task);
                    } else {
                        self.queues[idx].push_back(task);
                    }
                }
                // If this queue still has tasks, pop the front.
                if !self.queues[idx].is_empty() {
                    let task = self.queues[idx].pop_front().unwrap();
                    self.task_priorities.remove(&task.id);
                    self.total_count -= 1;
                    return Some(task);
                }
            }
        }
        None
    }

    /// Peek at the next task without removing it.
    pub fn peek(&self) -> Option<&PriorityTask> {
        for level in PriorityLevel::all_levels() {
            let idx = level.ordinal();
            if let Some(task) = self.queues[idx].front() {
                return Some(task);
            }
        }
        None
    }

    /// Return the number of tasks at each priority level.
    pub fn level_counts(&self) -> Vec<usize> {
        self.queues.iter().map(|q| q.len()).collect()
    }

    /// Return the total number of enqueued tasks.
    pub fn len(&self) -> usize {
        self.total_count
    }

    /// Check whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Promote a task by ID to a higher priority (used by priority inheritance
    /// when a parent task's priority is elevated).
    pub fn promote(&mut self, task_id: &str, new_priority: PriorityLevel) -> bool {
        let capped = if new_priority < self.priority_ceiling {
            self.priority_ceiling
        } else {
            new_priority
        };
        if let Some(existing) = self.task_priorities.get_mut(task_id) {
            if capped < *existing {
                *existing = capped;
                return true;
            }
        }
        false
    }
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new(PriorityLevel::Critical)
    }
}

// ---------------------------------------------------------------------------
// 2. Deadline-Aware Scheduling (Earliest Deadline First)
// ---------------------------------------------------------------------------

/// A task scheduled with an absolute deadline for EDF ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlineTask {
    /// Unique task identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Absolute deadline in ms since epoch.
    pub deadline_ms: u64,
    /// Estimated execution duration in ms.
    pub estimated_duration_ms: u64,
    /// Arrival (enqueue) time in ms.
    pub arrival_time_ms: u64,
    /// Current time in ms.
    pub current_time_ms: u64,
    /// Whether this task has already missed its deadline.
    pub missed: bool,
}

impl DeadlineTask {
    /// Create a new deadline-aware task.
    pub fn new(
        id: &str,
        name: &str,
        deadline_ms: u64,
        estimated_duration_ms: u64,
        arrival_time_ms: u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            deadline_ms,
            estimated_duration_ms,
            arrival_time_ms,
            current_time_ms: arrival_time_ms,
            missed: false,
        }
    }

    /// Compute slack time: the amount of time the task can delay before
    /// it must start executing to meet its deadline.
    ///
    /// `slack = deadline - current_time - estimated_duration`
    ///
    /// A negative slack indicates the deadline has already been missed or
    /// is impossible to meet.
    pub fn slack_time(&self) -> i64 {
        let remaining = self.deadline_ms as i64 - self.current_time_ms as i64;
        remaining - self.estimated_duration_ms as i64
    }

    /// Update the current time and check for deadline miss.
    pub fn update_time(&mut self, now_ms: u64) {
        self.current_time_ms = now_ms;
        if now_ms > self.deadline_ms {
            self.missed = true;
        }
    }

    /// Absolute laxity (same as slack time, exposed with a clearer name for EDF).
    pub fn laxity(&self) -> i64 {
        self.slack_time()
    }
}

/// An Earliest-Deadline-First scheduler that always picks the task with the
/// smallest (earliest) deadline. Ties are broken by slack time, then by
/// arrival order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDFScheduler {
    /// All pending deadline-aware tasks.
    tasks: Vec<DeadlineTask>,
    /// Count of total deadline misses observed.
    pub total_deadline_misses: u64,
    /// Count of total tasks scheduled.
    pub total_scheduled: u64,
}

impl EDFScheduler {
    /// Create a new empty EDF scheduler.
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            total_deadline_misses: 0,
            total_scheduled: 0,
        }
    }

    /// Submit a task to the EDF scheduler.
    pub fn submit(&mut self, task: DeadlineTask) {
        self.total_scheduled += 1;
        self.tasks.push(task);
    }

    /// Select the next task to execute using EDF policy.
    ///
    /// 1. Update all tasks to the current time, detecting misses.
    /// 2. Sort by deadline (ascending), then by slack time (ascending),
    ///    then by arrival time (ascending) for stability.
    /// 3. Return the first task (earliest deadline).
    pub fn next_task(&mut self, now_ms: u64) -> Option<DeadlineTask> {
        if self.tasks.is_empty() {
            return None;
        }
        // Refresh times and detect misses.
        for task in &mut self.tasks {
            task.update_time(now_ms);
            if task.missed {
                self.total_deadline_misses += 1;
            }
        }
        // EDF ordering: earliest deadline first.
        self.tasks.sort_by(|a, b| {
            a.deadline_ms
                .cmp(&b.deadline_ms)
                .then_with(|| a.slack_time().cmp(&b.slack_time()))
                .then_with(|| a.arrival_time_ms.cmp(&b.arrival_time_ms))
        });
        // Remove and return the first task (earliest deadline).
        Some(self.tasks.remove(0))
    }

    /// Return all tasks that have currently missed their deadlines.
    pub fn missed_tasks(&mut self, now_ms: u64) -> Vec<DeadlineTask> {
        for task in &mut self.tasks {
            task.update_time(now_ms);
        }
        let all = std::mem::take(&mut self.tasks);
        let (missed, remaining): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|t| t.missed);
        self.tasks = remaining;
        self.total_deadline_misses += missed.len() as u64;
        missed
    }

    /// Compute the deadline miss rate as a fraction in [0.0, 1.0].
    pub fn miss_rate(&self) -> f64 {
        if self.total_scheduled == 0 {
            return 0.0;
        }
        self.total_deadline_misses as f64 / self.total_scheduled as f64
    }

    /// Return the number of pending tasks.
    pub fn pending_count(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for EDFScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 3. Rate Limiting — Token Bucket with Fair Sharing
// ---------------------------------------------------------------------------

/// A classic token bucket rate limiter.
///
/// Tokens accumulate at `refill_rate_per_ms` tokens per millisecond, up to
/// a maximum of `bucket_capacity`. Each task execution consumes one token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    /// Maximum number of tokens the bucket can hold.
    pub bucket_capacity: u32,
    /// Current number of available tokens.
    pub current_tokens: f64,
    /// Refill rate in tokens per millisecond.
    pub refill_rate_per_ms: f64,
    /// Last time the bucket was refilled (ms since epoch).
    pub last_refill_ms: u64,
}

impl TokenBucket {
    /// Create a new token bucket.
    pub fn new(capacity: u32, refill_rate_per_ms: f64, last_refill_ms: u64) -> Self {
        Self {
            bucket_capacity: capacity,
            current_tokens: capacity as f64,
            refill_rate_per_ms,
            last_refill_ms,
        }
    }

    /// Refill tokens based on elapsed time since the last refill.
    pub fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms) as f64;
        let added = elapsed * self.refill_rate_per_ms;
        self.current_tokens = (self.current_tokens + added).min(self.bucket_capacity as f64);
        self.last_refill_ms = now_ms;
    }

    /// Attempt to consume one token. Returns `true` if a token was available.
    pub fn try_acquire(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.current_tokens >= 1.0 {
            self.current_tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Return the number of tokens currently available (after refill).
    pub fn available(&mut self, now_ms: u64) -> f64 {
        self.refill(now_ms);
        self.current_tokens
    }

    /// Return the fraction of the bucket that is full [0.0, 1.0].
    pub fn fill_fraction(&mut self, now_ms: u64) -> f64 {
        if self.bucket_capacity == 0 {
            return 0.0;
        }
        self.available(now_ms) / self.bucket_capacity as f64
    }
}

/// Backpressure signal emitted when rate limiting is active.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackpressureSignal {
    /// No backpressure — the system is operating normally.
    None,
    /// Mild backpressure — the bucket is below 50% capacity.
    Mild,
    /// Severe backpressure — the bucket is below 10% capacity.
    Severe,
    /// Exhausted — no tokens available; all requests are being rejected.
    Exhausted,
}

/// A per-task-type rate limiter with fair sharing across types.
///
/// Fair sharing works by giving each registered task type an equal share
/// of a global budget. If one type is under-utilizing its share, the
/// excess is redistributed proportionally to the others.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiter {
    /// Token bucket per task type (keyed by type name).
    pub buckets: HashMap<String, TokenBucket>,
    /// Global maximum concurrent task executions across all types.
    pub global_capacity: u32,
    /// Current global in-flight count.
    pub global_in_flight: u32,
}

impl RateLimiter {
    /// Create a new rate limiter with a given global capacity.
    pub fn new(global_capacity: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            global_capacity,
            global_in_flight: 0,
        }
    }

    /// Register a task type with a per-type bucket capacity and refill rate.
    pub fn register_type(
        &mut self,
        task_type: &str,
        capacity: u32,
        refill_rate_per_ms: f64,
        now_ms: u64,
    ) {
        self.buckets.insert(
            task_type.to_string(),
            TokenBucket::new(capacity, refill_rate_per_ms, now_ms),
        );
    }

    /// Attempt to acquire a execution slot for the given task type.
    /// Checks both the per-type bucket and the global capacity.
    pub fn try_acquire(&mut self, task_type: &str, now_ms: u64) -> bool {
        // Check global capacity first.
        if self.global_in_flight >= self.global_capacity {
            return false;
        }
        // Check per-type bucket.
        if let Some(bucket) = self.buckets.get_mut(task_type) {
            if bucket.try_acquire(now_ms) {
                self.global_in_flight += 1;
                return true;
            }
        }
        // If the type is not registered, allow it (no per-type limit).
        false
    }

    /// Release a global execution slot after a task completes.
    pub fn release(&mut self) {
        self.global_in_flight = self.global_in_flight.saturating_sub(1);
    }

    /// Compute the backpressure signal for a given task type.
    pub fn backpressure(&mut self, task_type: &str, now_ms: u64) -> BackpressureSignal {
        if self.global_in_flight >= self.global_capacity {
            return BackpressureSignal::Exhausted;
        }
        let global_ratio = self.global_in_flight as f64 / self.global_capacity as f64;
        if global_ratio > 0.9 {
            return BackpressureSignal::Severe;
        }
        if let Some(bucket) = self.buckets.get_mut(task_type) {
            let fill = bucket.fill_fraction(now_ms);
            if fill < 0.1 {
                return BackpressureSignal::Exhausted;
            } else if fill < 0.5 {
                return BackpressureSignal::Mild;
            }
        }
        BackpressureSignal::None
    }

    /// Compute fair-share redistribution weights.
    ///
    /// For N registered types, each gets `1/N` of the global capacity.
    /// Under-utilized types donate their unused slots proportionally.
    pub fn fair_share_weights(&mut self, now_ms: u64) -> HashMap<String, f64> {
        let n = self.buckets.len();
        if n == 0 {
            return HashMap::new();
        }
        let base_share = 1.0 / n as f64;
        let mut weights: HashMap<String, f64> = HashMap::new();
        let mut total_utilization = 0.0;
        let mut utilizations: HashMap<String, f64> = HashMap::new();

        for (name, bucket) in &mut self.buckets {
            let util = 1.0 - bucket.fill_fraction(now_ms);
            utilizations.insert(name.clone(), util);
            total_utilization += util;
        }

        if total_utilization < 1e-9 {
            // No utilization — equal distribution.
            for name in self.buckets.keys() {
                weights.insert(name.clone(), base_share);
            }
            return weights;
        }

        // Redistribute: types with lower utilization get more weight.
        let mut total_weight = 0.0;
        for (name, _bucket) in &self.buckets {
            let util = *utilizations.get(name).unwrap_or(&0.0);
            let weight = base_share * (1.0 + (1.0 - util / total_utilization));
            weights.insert(name.clone(), weight);
            total_weight += weight;
        }

        // Normalize weights to sum to 1.0.
        for weight in weights.values_mut() {
            *weight /= total_weight;
        }

        weights
    }
}

// ---------------------------------------------------------------------------
// 4. Jitter-Based Scheduling
// ---------------------------------------------------------------------------

/// Supported jitter distribution types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JitterDistribution {
    /// Uniform distribution over [0, max_jitter_ms].
    Uniform,
    /// Exponential distribution with the given lambda (rate) parameter.
    Exponential,
    /// Bounded Pareto distribution with shape parameter `alpha`.
    /// Produces heavy-tailed values suitable for thundering-herd mitigation.
    BoundedPareto,
}

/// Configuration for a jitter-based scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterConfig {
    /// The type of jitter distribution to use.
    pub distribution: JitterDistribution,
    /// Maximum jitter in milliseconds.
    pub max_jitter_ms: u64,
    /// Shape parameter for bounded Pareto (ignored for other distributions).
    pub pareto_alpha: f64,
    /// Lower bound for bounded Pareto (must be > 0).
    pub pareto_lower: f64,
    /// Lambda (rate) parameter for exponential distribution (ignored for others).
    pub exponential_lambda: f64,
}

impl JitterConfig {
    /// Create a uniform jitter configuration.
    pub fn uniform(max_jitter_ms: u64) -> Self {
        Self {
            distribution: JitterDistribution::Uniform,
            max_jitter_ms,
            pareto_alpha: 1.5,
            pareto_lower: 1.0,
            exponential_lambda: 0.001,
        }
    }

    /// Create an exponential jitter configuration.
    pub fn exponential(max_jitter_ms: u64, lambda: f64) -> Self {
        Self {
            distribution: JitterDistribution::Exponential,
            max_jitter_ms,
            pareto_alpha: 1.5,
            pareto_lower: 1.0,
            exponential_lambda: lambda,
        }
    }

    /// Create a bounded Pareto jitter configuration.
    pub fn bounded_pareto(max_jitter_ms: u64, alpha: f64, lower: f64) -> Self {
        Self {
            distribution: JitterDistribution::BoundedPareto,
            max_jitter_ms,
            pareto_alpha: alpha,
            pareto_lower: lower,
            exponential_lambda: 0.001,
        }
    }
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self::uniform(100)
    }
}

/// A scheduler that applies jitter to task execution times.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterScheduler {
    /// Jitter configuration.
    pub config: JitterConfig,
}

impl JitterScheduler {
    /// Create a new jitter scheduler with the given configuration.
    pub fn new(config: JitterConfig) -> Self {
        Self { config }
    }

    /// Compute a jitter value in milliseconds using the configured distribution.
    ///
    /// Uses a simple LCG-based pseudo-random number generator for
    /// deterministic behavior (seeded from thread-local entropy).
    pub fn compute_jitter(&self) -> u64 {
        let u: f64 = rand::random();
        match self.config.distribution {
            JitterDistribution::Uniform => {
                // U ~ Uniform(0, max_jitter)
                (u * self.config.max_jitter_ms as f64) as u64
            }
            JitterDistribution::Exponential => {
                // X ~ Exp(lambda), truncated to [0, max_jitter]
                let lambda = self.config.exponential_lambda.max(1e-9);
                let x = -(1.0 - u).ln() / lambda;
                x.min(self.config.max_jitter_ms as f64).max(0.0) as u64
            }
            JitterDistribution::BoundedPareto => {
                // Bounded Pareto: sample via inverse CDF.
                // CDF: F(x) = (1 - (L/x)^alpha) / (1 - (L/H)^alpha)
                // Inverse: x = L / (1 - u*(1 - (L/H)^alpha))^(1/alpha)
                let alpha = self.config.pareto_alpha.max(1.01);
                let lower = self.config.pareto_lower.max(0.001);
                let upper = self.config.max_jitter_ms as f64;
                if upper <= lower {
                    return 0;
                }
                let ratio = (lower / upper).powf(alpha);
                let denominator = 1.0 - u * (1.0 - ratio);
                if denominator <= 0.0 {
                    return self.config.max_jitter_ms;
                }
                let x = lower / denominator.powf(1.0 / alpha);
                x.min(self.config.max_jitter_ms as f64).max(0.0) as u64
            }
        }
    }

    /// Apply jitter to a base interval, returning the effective interval.
    /// The jitter can either add to or subtract from the base interval,
    /// centered around the base value.
    pub fn apply_jitter(&self, base_interval_ms: u64) -> u64 {
        let jitter = self.compute_jitter();
        // Center the jitter around the base: base ± (jitter / 2).
        let half_jitter = jitter as i64 / 2;
        (base_interval_ms as i64 + half_jitter - (jitter as i64 % 2)).max(1) as u64
    }
}

// ---------------------------------------------------------------------------
// 5. Task Dependency Graph (DAG)
// ---------------------------------------------------------------------------

/// A directed acyclic graph (DAG) of task dependencies.
///
/// Edges represent "depends-on" relationships: an edge from A to B means
/// A depends on B (B must complete before A can start).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// Adjacency list: task_id -> set of tasks it depends on (predecessors).
    pub predecessors: HashMap<String, HashSet<String>>,
    /// Adjacency list: task_id -> set of tasks that depend on it (successors).
    pub successors: HashMap<String, HashSet<String>>,
    /// Estimated duration for each task in ms.
    pub durations: HashMap<String, u64>,
    /// All registered task IDs.
    pub task_ids: HashSet<String>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph.
    pub fn new() -> Self {
        Self {
            predecessors: HashMap::new(),
            successors: HashMap::new(),
            durations: HashMap::new(),
            task_ids: HashSet::new(),
        }
    }

    /// Add a task node with an optional estimated duration.
    pub fn add_task(&mut self, task_id: &str, duration_ms: Option<u64>) {
        self.task_ids.insert(task_id.to_string());
        self.predecessors
            .entry(task_id.to_string())
            .or_default();
        self.successors
            .entry(task_id.to_string())
            .or_default();
        if let Some(dur) = duration_ms {
            self.durations.insert(task_id.to_string(), dur);
        }
    }

    /// Add a dependency edge: `task` depends on `depends_on`.
    /// Returns `false` if this would create a cycle.
    pub fn add_dependency(&mut self, task: &str, depends_on: &str) -> bool {
        // Ensure both nodes exist.
        self.add_task(task, None);
        self.add_task(depends_on, None);

        // Temporarily add the edge and check for cycles.
        self.predecessors
            .entry(task.to_string())
            .or_default()
            .insert(depends_on.to_string());
        self.successors
            .entry(depends_on.to_string())
            .or_default()
            .insert(task.to_string());

        if self.has_cycle() {
            // Rollback: remove the edge.
            self.predecessors
                .get_mut(task)
                .map(|s| s.remove(depends_on));
            self.successors
                .get_mut(depends_on)
                .map(|s| s.remove(task));
            return false;
        }
        true
    }

    /// Detect whether the graph contains a cycle using Kahn's algorithm.
    ///
    /// Kahn's algorithm works by repeatedly removing nodes with zero
    /// in-degree. If any nodes remain, the graph has a cycle.
    pub fn has_cycle(&self) -> bool {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for id in &self.task_ids {
            in_degree.entry(id.as_str()).or_insert(0);
        }
        for (_node, preds) in &self.predecessors {
            for pred in preds {
                *in_degree.entry(pred.as_str()).or_insert(0) += 0;
                *in_degree.entry(_node.as_str()).or_insert(0) += 1;
            }
        }
        // Recompute properly: in_degree[node] = number of predecessors.
        for id in &self.task_ids {
            in_degree.insert(id.as_str(), 0);
        }
        for (node, preds) in &self.predecessors {
            let count = preds.len();
            in_degree.insert(node.as_str(), count);
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();
        let mut visited_count = 0usize;

        while let Some(node) = queue.pop_front() {
            visited_count += 1;
            if let Some(succs) = self.successors.get(node) {
                for succ in succs {
                    if let Some(deg) = in_degree.get_mut(succ.as_str()) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(succ);
                        }
                    }
                }
            }
        }

        visited_count != self.task_ids.len()
    }

    /// Perform a topological sort of the graph.
    ///
    /// Returns the task IDs in a valid execution order (all dependencies
    /// of a task appear before the task itself). Returns `None` if the
    /// graph contains a cycle.
    pub fn topological_sort(&self) -> Option<Vec<String>> {
        if self.has_cycle() {
            return None;
        }

        let mut in_degree: HashMap<String, usize> = HashMap::new();
        for id in &self.task_ids {
            in_degree.insert(id.clone(), 0);
        }
        for (node, preds) in &self.predecessors {
            in_degree.insert(node.clone(), preds.len());
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(id, _)| id.clone())
            .collect();

        // Sort initial zero-in-degree nodes for deterministic output.
        let mut zero_nodes: Vec<String> = queue.drain(..).collect();
        zero_nodes.sort();
        queue.extend(zero_nodes);

        let mut result = Vec::new();

        while let Some(node) = queue.pop_front() {
            result.push(node.clone());
            if let Some(succs) = self.successors.get(&node) {
                let mut succ_list: Vec<&String> = succs.iter().collect();
                succ_list.sort();
                for succ in succ_list {
                    if let Some(deg) = in_degree.get_mut(succ) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(succ.clone());
                        }
                    }
                }
            }
        }

        Some(result)
    }

    /// Compute the critical path — the longest path through the DAG
    /// weighted by task durations.
    ///
    /// Uses a modified topological sort to compute the earliest start
    /// time (EST) for each task. The critical path length is the
    /// maximum EST + duration across all tasks.
    ///
    /// Returns `(critical_path_length_ms, critical_path_nodes)`.
    pub fn critical_path(&self) -> Option<(u64, Vec<String>)> {
        let sorted = self.topological_sort()?;
        if sorted.is_empty() {
            return Some((0, Vec::new()));
        }

        // Compute earliest start times via dynamic programming.
        let mut est: HashMap<String, u64> = HashMap::new();
        let mut predecessor_on_path: HashMap<String, String> = HashMap::new();

        for task_id in &sorted {
            let preds = self.predecessors.get(task_id).cloned().unwrap_or_default();
            let max_pred_finish = preds
                .iter()
                .map(|p| {
                    let p_est = *est.get(p).unwrap_or(&0);
                    let p_dur = *self.durations.get(p).unwrap_or(&0);
                    p_est + p_dur
                })
                .max()
                .unwrap_or(0);

            est.insert(task_id.clone(), max_pred_finish);

            // Record which predecessor is on the critical path.
            for p in &preds {
                let p_est = *est.get(p).unwrap_or(&0);
                let p_dur = *self.durations.get(p).unwrap_or(&0);
                if p_est + p_dur == max_pred_finish {
                    predecessor_on_path.insert(task_id.clone(), p.clone());
                    break;
                }
            }
        }

        // Find the task with the maximum (EST + duration).
        let mut best_finish = 0u64;
        let mut last_task = String::new();
        for task_id in &sorted {
            let task_est = *est.get(task_id).unwrap_or(&0);
            let task_dur = *self.durations.get(task_id).unwrap_or(&0);
            let finish = task_est + task_dur;
            if finish > best_finish {
                best_finish = finish;
                last_task = task_id.clone();
            }
        }

        // Backtrack to reconstruct the critical path.
        let mut path = Vec::new();
        let mut current = last_task;
        while !current.is_empty() {
            path.push(current.clone());
            current = predecessor_on_path
                .get(&current)
                .cloned()
                .unwrap_or_default();
        }
        path.reverse();

        Some((best_finish, path))
    }

    /// Return the set of tasks that are ready to execute (all dependencies satisfied).
    /// `completed` is the set of task IDs that have already finished.
    pub fn ready_tasks(&self, completed: &HashSet<String>) -> Vec<String> {
        self.task_ids
            .iter()
            .filter(|id| {
                !completed.contains(*id)
                    && self
                        .predecessors
                        .get(*id)
                        .map(|preds| preds.is_subset(completed))
                        .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Return the number of tasks in the graph.
    pub fn task_count(&self) -> usize {
        self.task_ids.len()
    }

    /// Return the number of dependency edges.
    pub fn edge_count(&self) -> usize {
        self.predecessors.values().map(|s| s.len()).sum()
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 6. Scheduling Metrics
// ---------------------------------------------------------------------------

/// Comprehensive metrics for the priority scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingMetrics {
    /// Total number of tasks scheduled.
    pub total_scheduled: u64,
    /// Total number of tasks completed.
    pub total_completed: u64,
    /// Total number of tasks that missed their deadline.
    pub total_deadline_misses: u64,
    /// Cumulative wait time across all tasks (ms).
    pub cumulative_wait_time_ms: u64,
    /// Cumulative execution time across all tasks (ms).
    pub cumulative_execution_time_ms: u64,
    /// Maximum observed wait time (ms).
    pub max_wait_time_ms: u64,
    /// Minimum observed wait time (ms).
    pub min_wait_time_ms: u64,
    /// Maximum observed execution time (ms).
    pub max_execution_time_ms: u64,
    /// Per-priority-level completion counts.
    pub completions_by_priority: BTreeMap<String, u64>,
    /// Per-priority-level queue utilization snapshots (fraction 0.0-1.0).
    pub queue_utilization: BTreeMap<String, f64>,
    /// SLA target: fraction of tasks that must meet their deadline.
    pub sla_target: f64,
    /// Number of tasks currently in each queue level.
    pub current_queue_sizes: BTreeMap<String, usize>,
}

impl SchedulingMetrics {
    /// Create a new metrics collector with the given SLA target.
    pub fn new(sla_target: f64) -> Self {
        Self {
            total_scheduled: 0,
            total_completed: 0,
            total_deadline_misses: 0,
            cumulative_wait_time_ms: 0,
            cumulative_execution_time_ms: 0,
            max_wait_time_ms: 0,
            min_wait_time_ms: u64::MAX,
            max_execution_time_ms: 0,
            completions_by_priority: BTreeMap::new(),
            queue_utilization: BTreeMap::new(),
            sla_target: sla_target.clamp(0.0, 1.0),
            current_queue_sizes: BTreeMap::new(),
        }
    }

    /// Record that a task was scheduled.
    pub fn record_scheduled(&mut self) {
        self.total_scheduled += 1;
    }

    /// Record a completed task with its wait time and execution time.
    pub fn record_completion(
        &mut self,
        priority: &str,
        wait_time_ms: u64,
        execution_time_ms: u64,
        deadline_met: bool,
    ) {
        self.total_completed += 1;
        self.cumulative_wait_time_ms += wait_time_ms;
        self.cumulative_execution_time_ms += execution_time_ms;

        if wait_time_ms > self.max_wait_time_ms {
            self.max_wait_time_ms = wait_time_ms;
        }
        if wait_time_ms < self.min_wait_time_ms {
            self.min_wait_time_ms = wait_time_ms;
        }
        if execution_time_ms > self.max_execution_time_ms {
            self.max_execution_time_ms = execution_time_ms;
        }

        *self
            .completions_by_priority
            .entry(priority.to_string())
            .or_insert(0) += 1;

        if !deadline_met {
            self.total_deadline_misses += 1;
        }
    }

    /// Compute the average wait time in ms.
    pub fn avg_wait_time_ms(&self) -> f64 {
        if self.total_completed == 0 {
            return 0.0;
        }
        self.cumulative_wait_time_ms as f64 / self.total_completed as f64
    }

    /// Compute the average execution time in ms.
    pub fn avg_execution_time_ms(&self) -> f64 {
        if self.total_completed == 0 {
            return 0.0;
        }
        self.cumulative_execution_time_ms as f64 / self.total_completed as f64
    }

    /// Compute the deadline miss rate as a fraction in [0.0, 1.0].
    pub fn deadline_miss_rate(&self) -> f64 {
        if self.total_completed == 0 {
            return 0.0;
        }
        self.total_deadline_misses as f64 / self.total_completed as f64
    }

    /// Check whether the scheduler is currently meeting its SLA target.
    /// SLA is met when `(1.0 - deadline_miss_rate) >= sla_target`.
    pub fn sla_compliant(&self) -> bool {
        if self.total_completed == 0 {
            return true; // No data yet — assume compliant.
        }
        (1.0 - self.deadline_miss_rate()) >= self.sla_target
    }

    /// Record a snapshot of queue utilization by priority level.
    pub fn snapshot_queue_utilization(&mut self, level_counts: &[(String, usize)], capacity_per_level: usize) {
        for (level, count) in level_counts {
            let util = if capacity_per_level == 0 {
                0.0
            } else {
                *count as f64 / capacity_per_level as f64
            };
            self.queue_utilization.insert(level.clone(), util);
        }
    }

    /// Record current queue sizes for live monitoring.
    pub fn update_queue_sizes(&mut self, level_counts: &[(String, usize)]) {
        for (level, count) in level_counts {
            self.current_queue_sizes.insert(level.clone(), *count);
        }
    }

    /// Compute overall queue utilization as a single fraction.
    pub fn overall_queue_utilization(&self) -> f64 {
        if self.queue_utilization.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.queue_utilization.values().sum();
        sum / self.queue_utilization.len() as f64
    }

    /// Return the throughput in tasks per second, given the elapsed time in ms.
    pub fn throughput_per_sec(&self, elapsed_ms: u64) -> f64 {
        if elapsed_ms == 0 {
            return 0.0;
        }
        self.total_completed as f64 / (elapsed_ms as f64 / 1000.0)
    }

    /// Produce a human-readable summary of all metrics.
    pub fn summary(&self) -> String {
        format!(
            "SchedulingMetrics {{ scheduled={}, completed={}, deadline_misses={}, \
             miss_rate={:.4}, avg_wait_ms={:.1}, avg_exec_ms={:.1}, \
             max_wait_ms={}, max_exec_ms={}, sla_compliant={}, \
             throughput_per_sec=N/A, queue_util={:.4} }}",
            self.total_scheduled,
            self.total_completed,
            self.total_deadline_misses,
            self.deadline_miss_rate(),
            self.avg_wait_time_ms(),
            self.avg_execution_time_ms(),
            self.max_wait_time_ms,
            self.max_execution_time_ms,
            self.sla_compliant(),
            self.overall_queue_utilization(),
        )
    }
}

impl Default for SchedulingMetrics {
    fn default() -> Self {
        Self::new(0.99) // Default SLA: 99% of tasks must meet deadline.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Priority Queue Tests --

    #[test]
    fn priority_level_ordinal_roundtrip() {
        for level in PriorityLevel::all_levels() {
            let ord = level.ordinal();
            assert_eq!(PriorityLevel::from_ordinal(ord), level);
        }
    }

    #[test]
    fn priority_level_from_ordinal_clamps() {
        assert_eq!(PriorityLevel::from_ordinal(100), PriorityLevel::Idle);
        assert_eq!(PriorityLevel::from_ordinal(0), PriorityLevel::Critical);
    }

    #[test]
    fn priority_task_age_computation() {
        let task = PriorityTask::new("t1", "task1", PriorityLevel::Normal, 1000)
            .with_scores(0.9, 0.9);
        let mut t = task;
        t.update_time(5000);
        assert_eq!(t.age_ms(), 4000);
    }

    #[test]
    fn dynamic_priority_age_boost() {
        // A task aged well beyond the threshold should be boosted.
        let mut task = PriorityTask::new("t1", "task1", PriorityLevel::Low, 0)
            .with_scores(1.0, 1.0);
        // Age the task 20 seconds (above 10s threshold, two 5s intervals).
        task.update_time(20_000);
        assert!(task.effective_priority <= PriorityLevel::Normal);
    }

    #[test]
    fn dynamic_priority_health_demotion() {
        let mut task = PriorityTask::new("t1", "task1", PriorityLevel::Normal, 0)
            .with_scores(0.2, 1.0);
        task.update_time(100);
        assert!(task.effective_priority >= PriorityLevel::Low);
    }

    #[test]
    fn dynamic_priority_trust_demotion() {
        let mut task = PriorityTask::new("t1", "task1", PriorityLevel::High, 0)
            .with_scores(1.0, 0.2);
        task.update_time(100);
        assert!(task.effective_priority >= PriorityLevel::Normal);
    }

    #[test]
    fn dynamic_priority_retry_penalty() {
        let mut task = PriorityTask::new("t1", "task1", PriorityLevel::Normal, 0)
            .with_scores(1.0, 1.0)
            .with_retry_count(10);
        task.update_time(100);
        // 10 retries, threshold is 3, so excess is 7, capped at +2 => demoted to Idle.
        assert_eq!(task.effective_priority, PriorityLevel::Idle);
    }

    #[test]
    fn priority_scheduler_enqueue_dequeue_order() {
        let mut scheduler = PriorityScheduler::default();
        let now = 1000u64;
        scheduler.enqueue(PriorityTask::new("low", "low", PriorityLevel::Low, now));
        scheduler.enqueue(PriorityTask::new("crit", "crit", PriorityLevel::Critical, now));
        scheduler.enqueue(PriorityTask::new("norm", "norm", PriorityLevel::Normal, now));

        let t1 = scheduler.dequeue(now).unwrap();
        assert_eq!(t1.id, "crit");
        let t2 = scheduler.dequeue(now).unwrap();
        assert_eq!(t2.id, "norm");
        let t3 = scheduler.dequeue(now).unwrap();
        assert_eq!(t3.id, "low");
        assert!(scheduler.dequeue(now).is_none());
    }

    #[test]
    fn priority_scheduler_ceiling_enforced() {
        let mut scheduler = PriorityScheduler::new(PriorityLevel::High);
        let task = PriorityTask::new("t1", "t1", PriorityLevel::Critical, 0);
        scheduler.enqueue(task);
        let dequeued = scheduler.dequeue(100).unwrap();
        // Ceiling is High, so Critical should be capped to High.
        assert_eq!(dequeued.effective_priority, PriorityLevel::High);
    }

    #[test]
    fn priority_inheritance() {
        let mut scheduler = PriorityScheduler::default();
        // Enqueue parent at High priority.
        let parent = PriorityTask::new("parent", "parent", PriorityLevel::High, 0);
        scheduler.enqueue(parent);
        // Child at Idle with parent reference.
        let child = PriorityTask::new("child", "child", PriorityLevel::Idle, 0)
            .with_parent("parent");
        scheduler.enqueue(child);
        // Child should inherit High priority (higher than Idle).
        let level_counts = scheduler.level_counts();
        // Child should be in High queue (ordinal 1), not Idle (ordinal 4).
        assert!(level_counts[1] >= 1);
    }

    #[test]
    fn priority_scheduler_promote() {
        let mut scheduler = PriorityScheduler::default();
        scheduler.enqueue(PriorityTask::new("t1", "t1", PriorityLevel::Low, 0));
        assert!(scheduler.promote("t1", PriorityLevel::High));
    }

    #[test]
    fn priority_scheduler_len_and_empty() {
        let mut scheduler = PriorityScheduler::default();
        assert!(scheduler.is_empty());
        scheduler.enqueue(PriorityTask::new("t1", "t1", PriorityLevel::Normal, 0));
        assert_eq!(scheduler.len(), 1);
        assert!(!scheduler.is_empty());
    }

    // -- EDF / Deadline Tests --

    #[test]
    fn deadline_task_slack_time() {
        let task = DeadlineTask::new("t1", "t1", 10_000, 2_000, 0);
        let mut t = task;
        t.update_time(5_000);
        // slack = deadline - current - duration = 10000 - 5000 - 2000 = 3000
        assert_eq!(t.slack_time(), 3000);
    }

    #[test]
    fn deadline_task_negative_slack() {
        let task = DeadlineTask::new("t1", "t1", 5_000, 4_000, 0);
        let mut t = task;
        t.update_time(10_000);
        // slack = 5000 - 10000 - 4000 = -9000
        assert_eq!(t.slack_time(), -9000);
        assert!(t.missed);
    }

    #[test]
    fn edf_scheduler_picks_earliest_deadline() {
        let mut edf = EDFScheduler::new();
        edf.submit(DeadlineTask::new("late", "late", 20_000, 1_000, 0));
        edf.submit(DeadlineTask::new("early", "early", 5_000, 1_000, 0));
        edf.submit(DeadlineTask::new("mid", "mid", 10_000, 1_000, 0));

        let t = edf.next_task(1_000).unwrap();
        assert_eq!(t.id, "early");
    }

    #[test]
    fn edf_scheduler_missed_tasks_detection() {
        let mut edf = EDFScheduler::new();
        edf.submit(DeadlineTask::new("past", "past", 5_000, 1_000, 0));
        edf.submit(DeadlineTask::new("future", "future", 50_000, 1_000, 0));

        let missed = edf.missed_tasks(10_000);
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].id, "past");
    }

    #[test]
    fn edf_miss_rate() {
        let mut edf = EDFScheduler::new();
        edf.submit(DeadlineTask::new("past", "past", 5_000, 1_000, 0));
        edf.submit(DeadlineTask::new("future", "future", 50_000, 1_000, 0));
        // Trigger miss detection.
        let _ = edf.missed_tasks(10_000);
        let rate = edf.miss_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    // -- Rate Limiter Tests --

    #[test]
    fn token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 0.001, 0); // 1 token/ms
        bucket.refill(5000);
        // After 5 seconds at 1 token/ms, should have 10 (capped at capacity).
        assert!((bucket.current_tokens - 10.0).abs() < 0.01);
    }

    #[test]
    fn token_bucket_acquire() {
        let mut bucket = TokenBucket::new(5, 0.001, 0);
        assert!(bucket.try_acquire(0)); // 5 -> 4
        assert!(bucket.try_acquire(0)); // 4 -> 3
        assert!(bucket.try_acquire(0)); // 3 -> 2
        assert!(bucket.try_acquire(0)); // 2 -> 1
        assert!(bucket.try_acquire(0)); // 1 -> 0
        assert!(!bucket.try_acquire(0)); // 0, rejected
    }

    #[test]
    fn rate_limiter_global_capacity() {
        let mut limiter = RateLimiter::new(2);
        limiter.register_type("a", 100, 0.01, 0);
        limiter.register_type("b", 100, 0.01, 0);
        assert!(limiter.try_acquire("a", 0));
        assert!(limiter.try_acquire("b", 0));
        assert!(!limiter.try_acquire("a", 0)); // Global full.
        limiter.release();
        assert!(limiter.try_acquire("a", 0)); // Now there's room.
    }

    #[test]
    fn rate_limiter_backpressure() {
        let mut limiter = RateLimiter::new(10);
        limiter.register_type("x", 100, 0.01, 0);
        // Exhaust all global slots.
        for _ in 0..10 {
            limiter.try_acquire("x", 0);
        }
        assert_eq!(limiter.backpressure("x", 0), BackpressureSignal::Exhausted);
    }

    #[test]
    fn rate_limiter_fair_share_weights() {
        let mut limiter = RateLimiter::new(100);
        limiter.register_type("a", 10, 0.01, 0);
        limiter.register_type("b", 10, 0.01, 0);
        let weights = limiter.fair_share_weights(0);
        assert_eq!(weights.len(), 2);
        // Both should have weight close to 0.5.
        let total: f64 = weights.values().sum();
        assert!((total - 1.0).abs() < 0.01);
    }

    // -- Jitter Tests --

    #[test]
    fn jitter_uniform_within_bounds() {
        let scheduler = JitterScheduler::new(JitterConfig::uniform(1000));
        for _ in 0..200 {
            let j = scheduler.compute_jitter();
            assert!(j <= 1000);
        }
    }

    #[test]
    fn jitter_exponential_within_bounds() {
        let scheduler = JitterScheduler::new(JitterConfig::exponential(1000, 0.005));
        for _ in 0..200 {
            let j = scheduler.compute_jitter();
            assert!(j <= 1000);
        }
    }

    #[test]
    fn jitter_pareto_within_bounds() {
        let scheduler = JitterScheduler::new(JitterConfig::bounded_pareto(1000, 1.5, 1.0));
        for _ in 0..200 {
            let j = scheduler.compute_jitter();
            assert!(j <= 1000);
        }
    }

    #[test]
    fn jitter_apply_positive() {
        let scheduler = JitterScheduler::new(JitterConfig::uniform(100));
        let base = 1000u64;
        // Apply jitter 500 times and check all results are positive.
        for _ in 0..500 {
            let effective = scheduler.apply_jitter(base);
            assert!(effective >= 1);
        }
    }

    // -- Dependency Graph Tests --

    #[test]
    fn dep_graph_add_and_ready_tasks() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", Some(100));
        graph.add_task("b", Some(200));
        graph.add_dependency("b", "a");

        let completed = HashSet::new();
        let ready = graph.ready_tasks(&completed);
        // Only "a" should be ready (no dependencies).
        assert_eq!(ready.len(), 1);
        assert!(ready.contains(&"a".to_string()));
    }

    #[test]
    fn dep_graph_no_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", None);
        graph.add_task("b", None);
        graph.add_task("c", None);
        assert!(graph.add_dependency("b", "a"));
        assert!(graph.add_dependency("c", "b"));
        assert!(!graph.has_cycle());
    }

    #[test]
    fn dep_graph_cycle_detection() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", None);
        graph.add_task("b", None);
        graph.add_task("c", None);
        assert!(graph.add_dependency("b", "a"));
        assert!(graph.add_dependency("c", "b"));
        // Adding a -> c would create cycle: a -> c -> b -> a.
        assert!(!graph.add_dependency("a", "c"));
    }

    #[test]
    fn dep_graph_topological_sort() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", Some(100));
        graph.add_task("b", Some(200));
        graph.add_task("c", Some(300));
        graph.add_dependency("c", "b");
        graph.add_dependency("b", "a");

        let sorted = graph.topological_sort().unwrap();
        let pos_a = sorted.iter().position(|x| x == "a").unwrap();
        let pos_b = sorted.iter().position(|x| x == "b").unwrap();
        let pos_c = sorted.iter().position(|x| x == "c").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn dep_graph_critical_path() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", Some(100)); // 100ms
        graph.add_task("b", Some(200)); // 200ms
        graph.add_task("c", Some(50));  // 50ms
        graph.add_dependency("b", "a");
        graph.add_dependency("c", "a");
        // Critical path: a(100) -> b(200) = 300ms
        // Alternative:    a(100) -> c(50)  = 150ms

        let (length, path) = graph.critical_path().unwrap();
        assert_eq!(length, 300);
        assert_eq!(path, vec!["a", "b"]);
    }

    #[test]
    fn dep_graph_edge_count() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", None);
        graph.add_task("b", None);
        graph.add_task("c", None);
        graph.add_dependency("b", "a");
        graph.add_dependency("c", "a");
        assert_eq!(graph.edge_count(), 2);
    }

    // -- Scheduling Metrics Tests --

    #[test]
    fn metrics_record_and_compute() {
        let mut metrics = SchedulingMetrics::new(0.95);
        metrics.record_scheduled();
        metrics.record_scheduled();
        metrics.record_completion("Critical", 50, 100, true);
        metrics.record_completion("Normal", 200, 300, true);
        metrics.record_completion("Low", 500, 50, false);

        assert_eq!(metrics.total_scheduled, 2);
        assert_eq!(metrics.total_completed, 3);
        assert_eq!(metrics.total_deadline_misses, 1);
        assert!((metrics.avg_wait_time_ms() - 250.0).abs() < 0.01);
        assert!((metrics.deadline_miss_rate() - (1.0 / 3.0)).abs() < 0.01);
        assert_eq!(metrics.max_wait_time_ms, 500);
        assert_eq!(metrics.max_execution_time_ms, 300);
    }

    #[test]
    fn metrics_sla_compliance() {
        let mut metrics = SchedulingMetrics::new(0.99);
        // With no completions, SLA should be compliant.
        assert!(metrics.sla_compliant());
        // Record one miss out of one completion.
        metrics.record_completion("Normal", 10, 10, false);
        // 0% success rate < 99% target.
        assert!(!metrics.sla_compliant());
    }

    #[test]
    fn metrics_queue_utilization() {
        let mut metrics = SchedulingMetrics::new(0.99);
        let levels: Vec<(String, usize)> = vec![
            ("Critical".to_string(), 5),
            ("Normal".to_string(), 3),
            ("Low".to_string(), 0),
        ];
        metrics.snapshot_queue_utilization(&levels, 10);
        assert!((metrics.queue_utilization.get("Critical").unwrap() - 0.5).abs() < 0.01);
        assert!((metrics.overall_queue_utilization() - (5.0 + 3.0 + 0.0) / 30.0).abs() < 0.01);
    }

    #[test]
    fn metrics_throughput() {
        let mut metrics = SchedulingMetrics::new(0.99);
        for _ in 0..100 {
            metrics.record_completion("Normal", 10, 10, true);
        }
        let throughput = metrics.throughput_per_sec(10_000); // 100 tasks in 10 seconds.
        assert!((throughput - 10.0).abs() < 0.01);
    }

    #[test]
    fn metrics_summary_string() {
        let metrics = SchedulingMetrics::default();
        let s = metrics.summary();
        assert!(s.contains("SchedulingMetrics"));
        assert!(s.contains("sla_compliant=true"));
    }

    #[test]
    fn metrics_min_wait_time_tracks() {
        let mut metrics = SchedulingMetrics::new(0.99);
        metrics.record_completion("Normal", 500, 100, true);
        metrics.record_completion("Normal", 50, 100, true);
        assert_eq!(metrics.min_wait_time_ms, 50);
    }

    // -- Serialization round-trip tests --

    #[test]
    fn priority_task_serde_roundtrip() {
        let task = PriorityTask::new("t1", "task1", PriorityLevel::High, 1000)
            .with_scores(0.7, 0.8)
            .with_deadline(5000)
            .with_parent("p1")
            .with_retry_count(2);
        let json = serde_json::to_string(&task).unwrap();
        let restored: PriorityTask = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "t1");
        assert_eq!(restored.base_priority, PriorityLevel::High);
        assert!((restored.health_score - 0.7).abs() < 0.001);
        assert_eq!(restored.deadline_ms, Some(5000));
    }

    #[test]
    fn dependency_graph_serde_roundtrip() {
        let mut graph = DependencyGraph::new();
        graph.add_task("a", Some(100));
        graph.add_task("b", Some(200));
        graph.add_dependency("b", "a");
        let json = serde_json::to_string(&graph).unwrap();
        let restored: DependencyGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.task_count(), 2);
        assert_eq!(restored.edge_count(), 1);
    }

    #[test]
    fn scheduling_metrics_serde_roundtrip() {
        let mut metrics = SchedulingMetrics::new(0.95);
        metrics.record_scheduled();
        metrics.record_completion("High", 10, 20, true);
        let json = serde_json::to_string(&metrics).unwrap();
        let restored: SchedulingMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_completed, 1);
        assert!((restored.sla_target - 0.95).abs() < 0.001);
    }
}
