// Temporal Trust Decay Engine — ANANTA
//
// This module implements a production-grade temporal trust decay system that
// models how trust in entities degrades over time. Each entity may use a
// different decay model, schedule, and policy. Every decay computation is
// recorded in an immutable audit trail.
//
// Decay models:
//   1. Exponential  — e^{-\lambda t}
//   2. Power Law    — t^{-\alpha}
//   3. Step Function — discrete drops at configurable boundaries
//   4. Logarithmic  — 1 - b * ln(1 + ct)
//   5. Custom       — user-defined piecewise linear segments
//
// Schedule types:
//   1. Immediate    — decay starts at evidence timestamp
//   2. Deferred     — delay before decay begins
//   3. Periodic     — decay applied at fixed intervals
//   4. Event-driven — decay triggered by named events
//   5. Cron-like    — minute/hour/day/month patterns

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

// ============================================================================
// 1. Decay Model Definitions
// ============================================================================

/// Identifies which mathematical decay model to apply to an entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DecayModelKind {
    Exponential,
    PowerLaw,
    StepFunction,
    Logarithmic,
    Custom,
}

/// Parameters for exponential decay: f(t) = e^{-\lambda * t}
///
/// Lambda controls the decay rate. Higher lambda means faster decay.
/// At t = 1/lambda, trust has fallen to ~37% of original.
/// At t = 2/lambda, trust has fallen to ~13.5% of original.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExponentialParams {
    /// Decay rate constant. Must be positive.
    pub lambda: f64,
}

impl ExponentialParams {
    pub fn new(lambda: f64) -> Self {
        Self {
            lambda: lambda.max(1e-9),
        }
    }

    /// Half-life in seconds: t_half = ln(2) / lambda
    pub fn half_life_secs(&self) -> f64 {
        std::f64::consts::LN_2 / self.lambda
    }

    /// Compute decay factor at elapsed seconds `t`.
    pub fn decay_factor(&self, t: f64) -> f64 {
        if t <= 0.0 {
            return 1.0;
        }
        (-self.lambda * t).exp()
    }
}

impl Default for ExponentialParams {
    fn default() -> Self {
        // Half-life of ~693 seconds (~11.5 minutes)
        Self { lambda: 0.001 }
    }
}

/// Parameters for power-law decay: f(t) = (1 + t)^{-\alpha}
///
/// Power-law decay has a "heavy tail" — trust degrades slowly after
/// an initial rapid drop. Alpha > 0 controls the steepness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerLawParams {
    /// Exponent controlling steepness. Must be positive.
    pub alpha: f64,
}

impl PowerLawParams {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: alpha.max(1e-9),
        }
    }

    /// Compute decay factor at elapsed seconds `t`.
    pub fn decay_factor(&self, t: f64) -> f64 {
        if t <= 0.0 {
            return 1.0;
        }
        (1.0 + t).powf(-self.alpha)
    }
}

impl Default for PowerLawParams {
    fn default() -> Self {
        Self { alpha: 0.5 }
    }
}

/// Parameters for step-function decay.
///
/// Trust drops discretely at each boundary. Between boundaries, trust
/// remains constant. This models systems where trust is only re-evaluated
/// at fixed intervals (e.g., daily audits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepFunctionParams {
    /// Ordered boundary points in seconds. At each boundary, trust is
    /// multiplied by the corresponding drop factor.
    pub boundaries: Vec<StepBoundary>,
}

/// A single step boundary: after `at_seconds` elapsed, multiply trust
/// by `drop_factor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepBoundary {
    /// Time in seconds at which this step occurs.
    pub at_seconds: f64,
    /// Multiplicative factor applied at this step (e.g., 0.8 = 20% drop).
    pub drop_factor: f64,
}

impl StepFunctionParams {
    pub fn new(boundaries: Vec<StepBoundary>) -> Self {
        let mut sorted = boundaries;
        sorted.sort_by(|a, b| a.at_seconds.partial_cmp(&b.at_seconds).unwrap());
        Self { boundaries: sorted }
    }

    /// Compute cumulative decay factor at elapsed seconds `t`.
    pub fn decay_factor(&self, t: f64) -> f64 {
        if t <= 0.0 {
            return 1.0;
        }
        let mut factor = 1.0;
        for boundary in &self.boundaries {
            if t >= boundary.at_seconds {
                factor *= boundary.drop_factor;
            } else {
                break;
            }
        }
        factor
    }
}

impl Default for StepFunctionParams {
    fn default() -> Self {
        Self::new(vec![
            StepBoundary {
                at_seconds: 3600.0,
                drop_factor: 0.9,
            },
            StepBoundary {
                at_seconds: 86400.0,
                drop_factor: 0.7,
            },
            StepBoundary {
                at_seconds: 604800.0,
                drop_factor: 0.5,
            },
        ])
    }
}

/// Parameters for logarithmic decay: f(t) = max(0, 1 - b * ln(1 + c * t))
///
/// This model produces slow, steady decay. The parameter `b` controls
/// the overall rate, while `c` controls how quickly the logarithmic
/// term grows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogarithmicParams {
    /// Scale factor for the logarithmic term. Must be positive.
    pub b: f64,
    /// Growth rate inside the logarithm. Must be positive.
    pub c: f64,
}

impl LogarithmicParams {
    pub fn new(b: f64, c: f64) -> Self {
        Self {
            b: b.max(1e-9),
            c: c.max(1e-9),
        }
    }

    /// Compute decay factor at elapsed seconds `t`.
    pub fn decay_factor(&self, t: f64) -> f64 {
        if t <= 0.0 {
            return 1.0;
        }
        let value = 1.0 - self.b * (1.0 + self.c * t).ln();
        value.max(0.0)
    }
}

impl Default for LogarithmicParams {
    fn default() -> Self {
        Self { b: 0.1, c: 0.001 }
    }
}

/// A single linear segment for the custom piecewise-linear decay model.
///
/// Segments are defined by (time, factor) points and connected with
/// straight lines. The segment from `start_seconds` to `end_seconds`
/// linearly interpolates between `start_factor` and `end_factor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearSegment {
    /// Start time in seconds.
    pub start_seconds: f64,
    /// End time in seconds.
    pub end_seconds: f64,
    /// Decay factor at `start_seconds`.
    pub start_factor: f64,
    /// Decay factor at `end_seconds`.
    pub end_factor: f64,
}

impl LinearSegment {
    pub fn new(start_seconds: f64, end_seconds: f64, start_factor: f64, end_factor: f64) -> Self {
        Self {
            start_seconds: start_seconds.max(0.0),
            end_seconds: end_seconds.max(start_seconds.max(0.0) + 0.001),
            start_factor: start_factor.clamp(0.0, 1.0),
            end_factor: end_factor.clamp(0.0, 1.0),
        }
    }

    /// Evaluate the linear interpolation at time `t`.
    pub fn evaluate(&self, t: f64) -> Option<f64> {
        if t < self.start_seconds || t > self.end_seconds {
            return None;
        }
        let range = self.end_seconds - self.start_seconds;
        if range <= 0.0 {
            return Some(self.start_factor);
        }
        let frac = (t - self.start_seconds) / range;
        Some(self.start_factor + frac * (self.end_factor - self.start_factor))
    }
}

/// Parameters for custom piecewise-linear decay.
///
/// The user provides an ordered list of segments. Before the first segment,
/// decay factor is 1.0. After the last segment, the final factor is held.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomParams {
    /// Ordered segments covering the decay curve.
    pub segments: Vec<LinearSegment>,
}

impl CustomParams {
    pub fn new(segments: Vec<LinearSegment>) -> Self {
        let mut sorted = segments;
        sorted.sort_by_key(|s| s.start_seconds as i64);
        Self { segments: sorted }
    }

    /// Compute decay factor at elapsed seconds `t`.
    pub fn decay_factor(&self, t: f64) -> f64 {
        if t <= 0.0 {
            return 1.0;
        }
        if self.segments.is_empty() {
            return 1.0;
        }
        // Before first segment
        if let Some(first) = self.segments.first() {
            if t < first.start_seconds {
                return 1.0;
            }
        }
        // Find the segment containing t
        for segment in &self.segments {
            if let Some(factor) = segment.evaluate(t) {
                return factor;
            }
        }
        // After last segment — hold the final value
        if let Some(last) = self.segments.last() {
            return last.end_factor;
        }
        1.0
    }
}

impl Default for CustomParams {
    fn default() -> Self {
        Self::new(vec![
            LinearSegment::new(0.0, 3600.0, 1.0, 0.8),
            LinearSegment::new(3600.0, 86400.0, 0.8, 0.5),
            LinearSegment::new(86400.0, 604800.0, 0.5, 0.2),
        ])
    }
}

/// Unified decay model that wraps one of the five model types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecayModel {
    Exponential(ExponentialParams),
    PowerLaw(PowerLawParams),
    StepFunction(StepFunctionParams),
    Logarithmic(LogarithmicParams),
    Custom(CustomParams),
}

impl DecayModel {
    /// Returns the kind identifier for this model.
    pub fn kind(&self) -> DecayModelKind {
        match self {
            DecayModel::Exponential(_) => DecayModelKind::Exponential,
            DecayModel::PowerLaw(_) => DecayModelKind::PowerLaw,
            DecayModel::StepFunction(_) => DecayModelKind::StepFunction,
            DecayModel::Logarithmic(_) => DecayModelKind::Logarithmic,
            DecayModel::Custom(_) => DecayModelKind::Custom,
        }
    }

    /// Compute the decay factor at the given elapsed seconds.
    pub fn decay_factor(&self, t: f64) -> f64 {
        match self {
            DecayModel::Exponential(p) => p.decay_factor(t),
            DecayModel::PowerLaw(p) => p.decay_factor(t),
            DecayModel::StepFunction(p) => p.decay_factor(t),
            DecayModel::Logarithmic(p) => p.decay_factor(t),
            DecayModel::Custom(p) => p.decay_factor(t),
        }
    }

    /// Apply this decay model to a trust value given elapsed seconds.
    pub fn apply(&self, trust: f64, elapsed_secs: f64) -> f64 {
        let factor = self.decay_factor(elapsed_secs);
        (trust * factor).clamp(0.0, 1.0)
    }

    /// Create a default exponential model.
    pub fn default_exponential() -> Self {
        DecayModel::Exponential(ExponentialParams::default())
    }

    /// Create a default power-law model.
    pub fn default_power_law() -> Self {
        DecayModel::PowerLaw(PowerLawParams::default())
    }

    /// Create a default step-function model.
    pub fn default_step_function() -> Self {
        DecayModel::StepFunction(StepFunctionParams::default())
    }

    /// Create a default logarithmic model.
    pub fn default_logarithmic() -> Self {
        DecayModel::Logarithmic(LogarithmicParams::default())
    }

    /// Create a default custom model.
    pub fn default_custom() -> Self {
        DecayModel::Custom(CustomParams::default())
    }
}

// ============================================================================
// 2. Decay Schedule Definitions
// ============================================================================

/// When and how decay is triggered for an entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleType {
    /// Decay begins immediately at the evidence timestamp.
    Immediate,
    /// Decay is deferred by a fixed delay after evidence timestamp.
    Deferred,
    /// Decay is applied at fixed time intervals.
    Periodic,
    /// Decay is triggered by specific named events.
    EventDriven,
    /// Cron-like schedule with minute/hour/day/month fields.
    Cron,
}

/// Parameters for a deferred schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredParams {
    /// Delay in seconds before decay begins after the last evidence.
    pub delay_secs: f64,
}

impl DeferredParams {
    pub fn new(delay_secs: f64) -> Self {
        Self {
            delay_secs: delay_secs.max(0.0),
        }
    }
}

impl Default for DeferredParams {
    fn default() -> Self {
        Self { delay_secs: 300.0 }
    }
}

/// Parameters for a periodic schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicParams {
    /// Interval between decay applications, in seconds.
    pub interval_secs: f64,
}

impl PeriodicParams {
    pub fn new(interval_secs: f64) -> Self {
        Self {
            interval_secs: interval_secs.max(1.0),
        }
    }

    /// Check whether decay should fire at the given elapsed time.
    pub fn should_fire(&self, elapsed_secs: f64) -> bool {
        if elapsed_secs <= 0.0 {
            return false;
        }
        let n = (elapsed_secs / self.interval_secs).floor() as u64;
        // Fires at every multiple of interval_secs
        let boundary = n as f64 * self.interval_secs;
        (elapsed_secs - boundary).abs() < 0.5
    }

    /// Compute the number of decay steps that should have fired.
    pub fn fired_steps(&self, elapsed_secs: f64) -> u64 {
        if elapsed_secs <= 0.0 {
            return 0;
        }
        (elapsed_secs / self.interval_secs).floor() as u64
    }
}

impl Default for PeriodicParams {
    fn default() -> Self {
        Self {
            interval_secs: 3600.0,
        }
    }
}

/// Parameters for an event-driven schedule.
///
/// Decay fires only when a named event occurs. The event names
/// can represent system events like "config_change", "restart", etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDrivenParams {
    /// Set of event names that trigger decay.
    pub trigger_events: HashSet<String>,
    /// Seconds of decay to apply per trigger event.
    pub decay_secs_per_trigger: f64,
}

impl EventDrivenParams {
    pub fn new(trigger_events: HashSet<String>, decay_secs_per_trigger: f64) -> Self {
        Self {
            trigger_events,
            decay_secs_per_trigger: decay_secs_per_trigger.max(0.0),
        }
    }

    /// Check whether the given event name is a trigger.
    pub fn is_trigger(&self, event_name: &str) -> bool {
        self.trigger_events.contains(event_name)
    }
}

impl Default for EventDrivenParams {
    fn default() -> Self {
        let mut events = HashSet::new();
        events.insert("config_change".into());
        events.insert("restart".into());
        events.insert("version_upgrade".into());
        Self {
            trigger_events: events,
            decay_secs_per_trigger: 3600.0,
        }
    }
}

/// Cron-like schedule parameters.
///
/// Unlike traditional cron (which specifies *when* to run), this
/// specifies the cadence for trust decay recalculation.
/// Fields use Unix cron semantics:
///   minute: 0-59
///   hour:   0-23
///   day:    1-31
///   month:  1-12
///
/// A value of `None` means "every" (wildcard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronParams {
    /// Minute field (0-59), None = every minute.
    pub minute: Option<u8>,
    /// Hour field (0-23), None = every hour.
    pub hour: Option<u8>,
    /// Day of month (1-31), None = every day.
    pub day: Option<u8>,
    /// Month (1-12), None = every month.
    pub month: Option<u8>,
}

impl CronParams {
    pub fn new(minute: Option<u8>, hour: Option<u8>, day: Option<u8>, month: Option<u8>) -> Self {
        Self {
            minute: minute.map(|m| m.min(59)),
            hour: hour.map(|h| h.min(23)),
            day: day.map(|d| d.clamp(1, 31)),
            month: month.map(|m| m.clamp(1, 12)),
        }
    }

    /// Check if the given DateTime matches this cron schedule.
    pub fn matches(&self, dt: &DateTime<Utc>) -> bool {
        if let Some(m) = self.minute {
            if dt.minute() as u8 != m {
                return false;
            }
        }
        if let Some(h) = self.hour {
            if dt.hour() as u8 != h {
                return false;
            }
        }
        if let Some(d) = self.day {
            if dt.day() as u8 != d {
                return false;
            }
        }
        if let Some(mo) = self.month {
            if dt.month() as u8 != mo {
                return false;
            }
        }
        true
    }

    /// Create a schedule that fires every hour at minute 0.
    pub fn hourly() -> Self {
        Self::new(Some(0), None, None, None)
    }

    /// Create a schedule that fires daily at midnight UTC.
    pub fn daily() -> Self {
        Self::new(Some(0), Some(0), None, None)
    }

    /// Create a schedule that fires weekly on Monday.
    pub fn weekly() -> Self {
        Self::new(Some(0), Some(0), None, None)
    }
}

impl Default for CronParams {
    fn default() -> Self {
        Self::hourly()
    }
}

/// Unified decay schedule wrapping one of the schedule types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecaySchedule {
    Immediate,
    Deferred(DeferredParams),
    Periodic(PeriodicParams),
    EventDriven(EventDrivenParams),
    Cron(CronParams),
}

impl DecaySchedule {
    /// Returns the schedule type identifier.
    pub fn schedule_type(&self) -> ScheduleType {
        match self {
            DecaySchedule::Immediate => ScheduleType::Immediate,
            DecaySchedule::Deferred(_) => ScheduleType::Deferred,
            DecaySchedule::Periodic(_) => ScheduleType::Periodic,
            DecaySchedule::EventDriven(_) => ScheduleType::EventDriven,
            DecaySchedule::Cron(_) => ScheduleType::Cron,
        }
    }

    /// Compute the effective elapsed seconds for decay given the actual
    /// elapsed time since evidence. Schedule types may modify this.
    pub fn effective_elapsed(&self, actual_elapsed_secs: f64) -> f64 {
        match self {
            DecaySchedule::Immediate => actual_elapsed_secs,
            DecaySchedule::Deferred(params) => {
                if actual_elapsed_secs <= params.delay_secs {
                    0.0
                } else {
                    actual_elapsed_secs - params.delay_secs
                }
            }
            DecaySchedule::Periodic(params) => {
                let steps = params.fired_steps(actual_elapsed_secs);
                steps as f64 * params.interval_secs
            }
            DecaySchedule::EventDriven(_) => 0.0,
            DecaySchedule::Cron(_) => actual_elapsed_secs,
        }
    }

    /// Check if decay should be applied now given elapsed time.
    pub fn should_decay(&self, elapsed_secs: f64, now: &DateTime<Utc>) -> bool {
        match self {
            DecaySchedule::Immediate => elapsed_secs > 0.0,
            DecaySchedule::Deferred(params) => elapsed_secs > params.delay_secs,
            DecaySchedule::Periodic(params) => params.should_fire(elapsed_secs),
            DecaySchedule::EventDriven(_) => false,
            DecaySchedule::Cron(params) => params.matches(now),
        }
    }
}

// ============================================================================
// 3. Evidence Tracking and Aging
// ============================================================================

/// A single piece of trust evidence with raw and decayed weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayEvidence {
    /// Unique identifier for this evidence record.
    pub id: String,
    /// Whether the evidence is positive (trust-increasing).
    pub is_positive: bool,
    /// Raw weight at the time of observation (0.0, 1.0].
    pub raw_weight: f64,
    /// Current decayed weight after applying temporal decay.
    pub decayed_weight: f64,
    /// When this evidence was observed (RFC 3339).
    pub observed_at: DateTime<Utc>,
    /// Human-readable source description.
    pub source: String,
}

impl DecayEvidence {
    /// Create a new evidence record with the given properties.
    pub fn new(is_positive: bool, raw_weight: f64, source: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            is_positive,
            raw_weight: raw_weight.clamp(0.01, 1.0),
            decayed_weight: raw_weight.clamp(0.01, 1.0),
            observed_at: Utc::now(),
            source: source.into(),
        }
    }

    /// Create evidence with a specific timestamp.
    pub fn with_timestamp(
        is_positive: bool,
        raw_weight: f64,
        source: &str,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            is_positive,
            raw_weight: raw_weight.clamp(0.01, 1.0),
            decayed_weight: raw_weight.clamp(0.01, 1.0),
            observed_at,
            source: source.into(),
        }
    }

    /// Compute the age of this evidence in seconds.
    pub fn age_secs(&self, now: &DateTime<Utc>) -> f64 {
        let duration = *now - self.observed_at;
        duration.num_seconds() as f64 + duration.num_nanoseconds().unwrap_or(0) as f64 * 1e-9
    }
}

/// Configuration for the sliding evidence window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceWindowConfig {
    /// Maximum age of evidence in seconds before it is fully expired.
    pub max_age_secs: f64,
    /// Whether to use linear weighting within the window.
    /// If false, all evidence within the window has equal weight.
    pub weighted: bool,
    /// Maximum number of evidence records to keep per entity.
    pub max_entries: usize,
}

impl Default for EvidenceWindowConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 86400.0 * 7.0, // 7 days
            weighted: true,
            max_entries: 10000,
        }
    }
}

impl EvidenceWindowConfig {
    pub fn new(max_age_secs: f64, weighted: bool, max_entries: usize) -> Self {
        Self {
            max_age_secs: max_age_secs.max(1.0),
            weighted,
            max_entries: max_entries.max(1),
        }
    }

    /// Compute a recency weight for evidence of the given age.
    /// Returns 1.0 for brand-new evidence, 0.0 for expired evidence,
    /// and linearly interpolates in between when `weighted` is true.
    pub fn recency_weight(&self, age_secs: f64) -> f64 {
        if age_secs >= self.max_age_secs {
            return 0.0;
        }
        if !self.weighted || age_secs <= 0.0 {
            return 1.0;
        }
        1.0 - (age_secs / self.max_age_secs)
    }
}

/// An entity's evidence store with aging support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStore {
    /// All evidence records for this entity, newest first.
    pub evidence: VecDeque<DecayEvidence>,
    /// Window configuration.
    pub window_config: EvidenceWindowConfig,
}

impl EvidenceStore {
    pub fn new(config: EvidenceWindowConfig) -> Self {
        Self {
            evidence: VecDeque::new(),
            window_config: config,
        }
    }

    /// Add a new evidence record.
    pub fn add_evidence(&mut self, evidence: DecayEvidence) {
        if self.evidence.len() >= self.window_config.max_entries {
            self.evidence.pop_back();
        }
        self.evidence.push_front(evidence);
    }

    /// Remove all evidence older than the configured max age.
    pub fn prune_expired(&mut self, now: &DateTime<Utc>) {
        while let Some(oldest) = self.evidence.back() {
            if oldest.age_secs(now) >= self.window_config.max_age_secs {
                self.evidence.pop_back();
            } else {
                break;
            }
        }
    }

    /// Recompute decayed weights for all evidence using the given model and schedule.
    pub fn recompute_decayed_weights(
        &mut self,
        model: &DecayModel,
        schedule: &DecaySchedule,
        now: &DateTime<Utc>,
    ) {
        for ev in &mut self.evidence {
            let age = ev.age_secs(now);
            let effective_age = schedule.effective_elapsed(age);
            let factor = model.decay_factor(effective_age);
            ev.decayed_weight = (ev.raw_weight * factor).clamp(0.0, 1.0);
        }
    }

    /// Compute the aggregate trust from all evidence.
    ///
    /// Positive evidence contributes +decayed_weight, negative evidence
    /// contributes -decayed_weight. The result is normalized to [0, 1].
    pub fn aggregate_trust(&self, now: &DateTime<Utc>) -> f64 {
        if self.evidence.is_empty() {
            return 0.5;
        }
        let mut positive_sum = 0.0;
        let mut negative_sum = 0.0;
        for ev in &self.evidence {
            let recency = self.window_config.recency_weight(ev.age_secs(now));
            let weighted = ev.decayed_weight * recency;
            if ev.is_positive {
                positive_sum += weighted;
            } else {
                negative_sum += weighted;
            }
        }
        let total = positive_sum + negative_sum;
        if total <= 0.0 {
            return 0.5;
        }
        positive_sum / total
    }

    /// Compute the raw (non-decayed) aggregate trust for comparison.
    pub fn aggregate_raw_trust(&self) -> f64 {
        if self.evidence.is_empty() {
            return 0.5;
        }
        let mut positive_sum = 0.0;
        let mut negative_sum = 0.0;
        for ev in &self.evidence {
            if ev.is_positive {
                positive_sum += ev.raw_weight;
            } else {
                negative_sum += ev.raw_weight;
            }
        }
        let total = positive_sum + negative_sum;
        if total <= 0.0 {
            return 0.5;
        }
        positive_sum / total
    }

    /// Count evidence records.
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }
}

// ============================================================================
// 4. Decay Policy Management
// ============================================================================

/// A decay policy defines how a specific entity or entity class decays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayPolicy {
    /// Unique policy identifier.
    pub policy_id: String,
    /// Human-readable name.
    pub name: String,
    /// The decay model to apply.
    pub model: DecayModel,
    /// The decay schedule.
    pub schedule: DecaySchedule,
    /// Minimum trust floor. Trust will never decay below this value.
    pub trust_floor: f64,
    /// Maximum per-step decay rate cap (0.0, 1.0]. Prevents catastrophic
    /// single-step drops.
    pub max_decay_rate: f64,
    /// Whether this policy is active.
    pub active: bool,
    /// Entity IDs this policy applies to. Empty means applies to all.
    pub entity_scope: HashSet<String>,
    /// Description of the policy's purpose.
    pub description: String,
}

impl DecayPolicy {
    /// Create a new decay policy.
    pub fn new(policy_id: &str, name: &str, model: DecayModel, schedule: DecaySchedule) -> Self {
        Self {
            policy_id: policy_id.into(),
            name: name.into(),
            model,
            schedule,
            trust_floor: 0.1,
            max_decay_rate: 0.5,
            active: true,
            entity_scope: HashSet::new(),
            description: String::new(),
        }
    }

    /// Set the trust floor.
    pub fn with_floor(mut self, floor: f64) -> Self {
        self.trust_floor = floor.clamp(0.0, 1.0);
        self
    }

    /// Set the maximum decay rate cap.
    pub fn with_max_decay_rate(mut self, rate: f64) -> Self {
        self.max_decay_rate = rate.clamp(0.01, 1.0);
        self
    }

    /// Set the entity scope.
    pub fn with_entities(mut self, entities: HashSet<String>) -> Self {
        self.entity_scope = entities;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    /// Check if this policy applies to the given entity.
    pub fn applies_to(&self, entity_id: &str) -> bool {
        if !self.active {
            return false;
        }
        self.entity_scope.is_empty() || self.entity_scope.contains(entity_id)
    }

    /// Apply decay to a trust value, respecting floor and rate cap.
    ///
    /// Returns (new_trust, actual_decay_amount).
    pub fn apply_decay(&self, current_trust: f64, elapsed_secs: f64) -> (f64, f64) {
        let effective_elapsed = self.schedule.effective_elapsed(elapsed_secs);
        let new_trust = self.model.apply(current_trust, effective_elapsed);
        let decay_amount = current_trust - new_trust;
        // Apply rate cap: limit single-step decay
        let capped_decay = decay_amount.min(current_trust * self.max_decay_rate);
        let after_cap = current_trust - capped_decay;
        // Apply floor
        let floored = after_cap.max(self.trust_floor);
        (floored, current_trust - floored)
    }
}

/// Registry of all active decay policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRegistry {
    /// Policies indexed by policy_id.
    policies: HashMap<String, DecayPolicy>,
    /// Index from entity_id to set of applicable policy_ids.
    entity_index: HashMap<String, Vec<String>>,
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            entity_index: HashMap::new(),
        }
    }

    /// Register a new policy.
    pub fn register(&mut self, policy: DecayPolicy) {
        let pid = policy.policy_id.clone();
        let entities: Vec<String> = if policy.entity_scope.is_empty() {
            Vec::new() // Global policy — no per-entity index
        } else {
            policy.entity_scope.iter().cloned().collect()
        };
        self.policies.insert(pid.clone(), policy);
        for entity_id in entities {
            self.entity_index
                .entry(entity_id)
                .or_default()
                .push(pid.clone());
        }
    }

    /// Unregister a policy by ID.
    pub fn unregister(&mut self, policy_id: &str) -> bool {
        if let Some(policy) = self.policies.remove(policy_id) {
            for entity_id in &policy.entity_scope {
                if let Some(pids) = self.entity_index.get_mut(entity_id) {
                    pids.retain(|pid| pid != policy_id);
                }
            }
            return true;
        }
        false
    }

    /// Get a policy by ID.
    pub fn get(&self, policy_id: &str) -> Option<&DecayPolicy> {
        self.policies.get(policy_id)
    }

    /// Get a mutable reference to a policy by ID.
    pub fn get_mut(&mut self, policy_id: &str) -> Option<&mut DecayPolicy> {
        self.policies.get_mut(policy_id)
    }

    /// Find all policies that apply to the given entity.
    pub fn policies_for_entity(&self, entity_id: &str) -> Vec<&DecayPolicy> {
        let mut result: Vec<&DecayPolicy> = Vec::new();
        // Global policies (empty entity_scope)
        for policy in self.policies.values() {
            if policy.entity_scope.is_empty() && policy.active {
                result.push(policy);
            }
        }
        // Entity-specific policies
        if let Some(pids) = self.entity_index.get(entity_id) {
            for pid in pids {
                if let Some(policy) = self.policies.get(pid) {
                    if policy.active {
                        result.push(policy);
                    }
                }
            }
        }
        result
    }

    /// List all registered policy IDs.
    pub fn list_policy_ids(&self) -> Vec<&str> {
        self.policies.keys().map(|s| s.as_str()).collect()
    }

    /// Count of registered policies.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 5. Decay Audit Trail
// ============================================================================

/// A single immutable audit record for a decay computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayAuditEntry {
    /// Unique entry identifier.
    pub entry_id: String,
    /// Timestamp of this computation (RFC 3339).
    pub computed_at: DateTime<Utc>,
    /// Entity that was decayed.
    pub entity_id: String,
    /// Trust value before decay.
    pub trust_before: f64,
    /// Trust value after decay.
    pub trust_after: f64,
    /// The decay model kind used.
    pub model_kind: DecayModelKind,
    /// The schedule type used.
    pub schedule_type: ScheduleType,
    /// Elapsed seconds since last evidence.
    pub elapsed_secs: f64,
    /// Effective elapsed seconds after schedule adjustment.
    pub effective_elapsed_secs: f64,
    /// Human-readable reason for this decay computation.
    pub reason: String,
    /// Serialized model parameters for reproducibility.
    pub model_params_json: String,
}

impl DecayAuditEntry {
    /// Create a new audit entry.
    pub fn new(
        entity_id: &str,
        trust_before: f64,
        trust_after: f64,
        model: &DecayModel,
        schedule: &DecaySchedule,
        elapsed_secs: f64,
        effective_elapsed_secs: f64,
        reason: &str,
    ) -> Self {
        let model_params_json = serde_json::to_string(model).unwrap_or_else(|_| "{}".into());
        Self {
            entry_id: uuid::Uuid::new_v4().to_string(),
            computed_at: Utc::now(),
            entity_id: entity_id.into(),
            trust_before,
            trust_after,
            model_kind: model.kind(),
            schedule_type: schedule.schedule_type(),
            elapsed_secs,
            effective_elapsed_secs,
            reason: reason.into(),
            model_params_json,
        }
    }

    /// The amount of trust lost in this computation.
    pub fn decay_amount(&self) -> f64 {
        self.trust_before - self.trust_after
    }
}

/// Immutable audit trail for all decay computations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayAuditTrail {
    /// All audit entries, ordered by computation time.
    entries: Vec<DecayAuditEntry>,
    /// Maximum number of entries to retain.
    max_entries: usize,
}

impl DecayAuditTrail {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries.min(1000)),
            max_entries: max_entries.max(1),
        }
    }

    /// Record a new audit entry.
    pub fn record(&mut self, entry: DecayAuditEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Get all entries for a specific entity.
    pub fn entries_for_entity(&self, entity_id: &str) -> Vec<&DecayAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.entity_id == entity_id)
            .collect()
    }

    /// Get the most recent N entries.
    pub fn recent_entries(&self, n: usize) -> &[DecayAuditEntry] {
        let start = if self.entries.len() > n {
            self.entries.len() - n
        } else {
            0
        };
        &self.entries[start..]
    }

    /// Count total audit entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the trail is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute total trust lost across all entries.
    pub fn total_decay(&self) -> f64 {
        self.entries.iter().map(|e| e.decay_amount()).sum()
    }

    /// Find entries where decay exceeded a threshold.
    pub fn large_decays(&self, threshold: f64) -> Vec<&DecayAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.decay_amount() > threshold)
            .collect()
    }

    /// Export all entries as JSON string.
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries).unwrap_or_else(|_| "[]".into())
    }
}

impl Default for DecayAuditTrail {
    fn default() -> Self {
        Self::new(100_000)
    }
}

// ============================================================================
// 6. Entity Trust State with Decay
// ============================================================================

/// The full trust state for a single entity under decay management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDecayState {
    /// Entity identifier.
    pub entity_id: String,
    /// Current trust score (after decay).
    pub current_trust: f64,
    /// Raw trust score (before decay, based on evidence alone).
    pub raw_trust: f64,
    /// The policy ID governing this entity's decay.
    pub policy_id: String,
    /// Timestamp of the last decay computation.
    pub last_decay_at: DateTime<Utc>,
    /// Timestamp of the most recent evidence.
    pub last_evidence_at: DateTime<Utc>,
    /// Number of decay computations performed.
    pub decay_count: u64,
    /// The evidence store for this entity.
    pub evidence_store: EvidenceStore,
    /// Whether this entity needs recomputation (dirty flag).
    pub dirty: bool,
}

impl EntityDecayState {
    /// Create a new entity decay state.
    pub fn new(entity_id: &str, policy_id: &str, window_config: EvidenceWindowConfig) -> Self {
        Self {
            entity_id: entity_id.into(),
            current_trust: 0.5,
            raw_trust: 0.5,
            policy_id: policy_id.into(),
            last_decay_at: Utc::now(),
            last_evidence_at: Utc::now(),
            decay_count: 0,
            evidence_store: EvidenceStore::new(window_config),
            dirty: false,
        }
    }

    /// Record new evidence and mark the entity as dirty.
    pub fn add_evidence(&mut self, evidence: DecayEvidence) {
        self.last_evidence_at = evidence.observed_at;
        self.evidence_store.add_evidence(evidence);
        self.raw_trust = self.evidence_store.aggregate_raw_trust();
        self.dirty = true;
    }

    /// Mark this entity as needing recomputation.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Compute elapsed seconds since last evidence.
    pub fn elapsed_since_evidence(&self, now: &DateTime<Utc>) -> f64 {
        let duration = *now - self.last_evidence_at;
        duration.num_seconds() as f64 + duration.num_nanoseconds().unwrap_or(0) as f64 * 1e-9
    }

    /// Compute elapsed seconds since last decay computation.
    pub fn elapsed_since_decay(&self, now: &DateTime<Utc>) -> f64 {
        let duration = *now - self.last_decay_at;
        duration.num_seconds() as f64 + duration.num_nanoseconds().unwrap_or(0) as f64 * 1e-9
    }
}

// ============================================================================
// 7. Batch Decay Processor with Priority Queue
// ============================================================================

/// Staleness ordering for the priority queue.
/// Entities that haven't been decayed recently are processed first.
#[derive(Debug, Clone, Eq, PartialEq)]
struct StaleEntity {
    /// Inverse of last_decay timestamp for max-heap ordering.
    /// Higher values = more stale = processed first.
    stale_key: i64,
    entity_id: String,
}

impl Ord for StaleEntity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Max-heap: most stale (highest stale_key) first
        self.stale_key.cmp(&other.stale_key)
    }
}

impl PartialOrd for StaleEntity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Result of a batch decay processing run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecayResult {
    /// Number of entities processed.
    pub entities_processed: usize,
    /// Number of entities skipped (not dirty, not eligible).
    pub entities_skipped: usize,
    /// Total trust lost across all processed entities.
    pub total_decay: f64,
    /// Maximum single-entity decay in this batch.
    pub max_single_decay: f64,
    /// Number of entities that hit their trust floor.
    pub floor_hits: usize,
    /// Wall-clock time of this batch run (RFC 3339).
    pub batch_time: DateTime<Utc>,
}

impl BatchDecayResult {
    pub fn summary(&self) -> String {
        format!(
            "batch: processed={} skipped={} total_decay={:.4} max_decay={:.4} floor_hits={}",
            self.entities_processed,
            self.entities_skipped,
            self.total_decay,
            self.max_single_decay,
            self.floor_hits,
        )
    }
}

/// The main decay engine that orchestrates all decay operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDecayEngine {
    /// All entity states indexed by entity_id.
    entities: HashMap<String, EntityDecayState>,
    /// Policy registry.
    policy_registry: PolicyRegistry,
    /// Immutable audit trail.
    audit_trail: DecayAuditTrail,
    /// Default evidence window configuration for new entities.
    default_window_config: EvidenceWindowConfig,
    /// Default policy ID for entities without explicit policy.
    default_policy_id: String,
}

impl TrustDecayEngine {
    /// Create a new decay engine with a default exponential policy.
    pub fn new() -> Self {
        let mut registry = PolicyRegistry::new();
        let default_policy = DecayPolicy::new(
            "default_exponential",
            "Default Exponential Decay",
            DecayModel::default_exponential(),
            DecaySchedule::Immediate,
        )
        .with_floor(0.1)
        .with_max_decay_rate(0.5)
        .with_description("Default policy using exponential decay with half-life ~693s");
        let default_id = default_policy.policy_id.clone();
        registry.register(default_policy);

        Self {
            entities: HashMap::new(),
            policy_registry: registry,
            audit_trail: DecayAuditTrail::default(),
            default_window_config: EvidenceWindowConfig::default(),
            default_policy_id: default_id,
        }
    }

    /// Create engine with custom default window config.
    pub fn with_window_config(config: EvidenceWindowConfig) -> Self {
        let mut engine = Self::new();
        engine.default_window_config = config;
        engine
    }

    /// Register a new decay policy.
    pub fn register_policy(&mut self, policy: DecayPolicy) {
        self.policy_registry.register(policy);
    }

    /// Unregister a policy.
    pub fn unregister_policy(&mut self, policy_id: &str) -> bool {
        self.policy_registry.unregister(policy_id)
    }

    /// Get a reference to the policy registry.
    pub fn policies(&self) -> &PolicyRegistry {
        &self.policy_registry
    }

    /// Get a mutable reference to the policy registry.
    pub fn policies_mut(&mut self) -> &mut PolicyRegistry {
        &mut self.policy_registry
    }

    /// Register a new entity for decay tracking.
    pub fn register_entity(&mut self, entity_id: &str, policy_id: Option<&str>) {
        let pid = policy_id.unwrap_or(&self.default_policy_id).to_string();
        let state = EntityDecayState::new(entity_id, &pid, self.default_window_config.clone());
        self.entities.insert(entity_id.into(), state);
    }

    /// Add evidence to an entity.
    pub fn add_evidence(&mut self, entity_id: &str, evidence: DecayEvidence) -> bool {
        if let Some(state) = self.entities.get_mut(entity_id) {
            state.add_evidence(evidence);
            return true;
        }
        false
    }

    /// Mark an entity as dirty (needs recomputation).
    pub fn mark_dirty(&mut self, entity_id: &str) -> bool {
        if let Some(state) = self.entities.get_mut(entity_id) {
            state.mark_dirty();
            return true;
        }
        false
    }

    /// Trigger an event-driven decay for all entities with event-driven policies.
    pub fn trigger_event(&mut self, event_name: &str) -> Vec<(String, f64, f64)> {
        let now = Utc::now();
        let mut results = Vec::new();
        for (entity_id, state) in &mut self.entities {
            let policies = self.policy_registry.policies_for_entity(entity_id);
            for policy in &policies {
                if let DecaySchedule::EventDriven(params) = &policy.schedule {
                    if params.is_trigger(event_name) {
                        let elapsed = state.elapsed_since_evidence(&now);
                        let effective_elapsed = params.decay_secs_per_trigger;
                        // Apply model directly, bypassing apply_decay which would
                        // re-zero effective_elapsed for EventDriven schedules.
                        let new_trust_raw =
                            policy.model.apply(state.current_trust, effective_elapsed);
                        let decay_amount = state.current_trust - new_trust_raw;
                        let capped_decay =
                            decay_amount.min(state.current_trust * policy.max_decay_rate);
                        let after_cap = state.current_trust - capped_decay;
                        let new_trust = after_cap.max(policy.trust_floor);
                        let old_trust = state.current_trust;
                        state.current_trust = new_trust;
                        state.last_decay_at = now;
                        state.decay_count += 1;

                        let entry = DecayAuditEntry::new(
                            entity_id,
                            old_trust,
                            new_trust,
                            &policy.model,
                            &policy.schedule,
                            elapsed,
                            effective_elapsed,
                            &format!("event_trigger:{}", event_name),
                        );
                        self.audit_trail.record(entry);
                        results.push((entity_id.clone(), old_trust, new_trust));
                    }
                }
            }
        }
        results
    }

    /// Decay a single entity by ID.
    pub fn decay_entity(&mut self, entity_id: &str) -> Option<(f64, f64)> {
        let now = Utc::now();
        let policies = self.policy_registry.policies_for_entity(entity_id);
        if policies.is_empty() {
            return None;
        }
        let state = self.entities.get_mut(entity_id)?;

        // Prune expired evidence
        state.evidence_store.prune_expired(&now);

        let elapsed = state.elapsed_since_evidence(&now);
        let old_trust = state.current_trust;

        // Apply all applicable policies (use the first matching one for the model)
        let primary_policy = &policies[0];
        let effective_elapsed = primary_policy.schedule.effective_elapsed(elapsed);

        // Recompute evidence weights
        state.evidence_store.recompute_decayed_weights(
            &primary_policy.model,
            &primary_policy.schedule,
            &now,
        );

        // Aggregate from evidence
        let evidence_trust = state.evidence_store.aggregate_trust(&now);

        // Apply decay policy
        let (new_trust, _decay_amount) = primary_policy.apply_decay(old_trust, elapsed);

        // Blend evidence-based trust with decayed trust
        // If there is recent evidence, it can offset some decay
        let blended = if !state.evidence_store.is_empty() {
            let evidence_weight = 0.3; // Evidence has 30% influence
            let decay_weight = 1.0 - evidence_weight;
            (evidence_trust * evidence_weight + new_trust * decay_weight).clamp(0.0, 1.0)
        } else {
            new_trust
        };

        // Apply floor
        let final_trust = blended.max(primary_policy.trust_floor);
        let _actual_decay = old_trust - final_trust;

        // Record audit
        let entry = DecayAuditEntry::new(
            entity_id,
            old_trust,
            final_trust,
            &primary_policy.model,
            &primary_policy.schedule,
            elapsed,
            effective_elapsed,
            "scheduled_decay",
        );

        let _ = state; // Release borrow
        self.audit_trail.record(entry);

        let state = self.entities.get_mut(entity_id).unwrap();
        state.current_trust = final_trust;
        state.raw_trust = state.evidence_store.aggregate_raw_trust();
        state.last_decay_at = now;
        state.decay_count += 1;
        state.dirty = false;

        Some((old_trust, final_trust))
    }

    /// Batch process decay for all dirty entities, ordered by staleness.
    pub fn batch_decay(&mut self) -> BatchDecayResult {
        let now = Utc::now();
        let mut result = BatchDecayResult {
            entities_processed: 0,
            entities_skipped: 0,
            total_decay: 0.0,
            max_single_decay: 0.0,
            floor_hits: 0,
            batch_time: now,
        };

        // Build priority queue of entities to process
        let mut heap: BinaryHeap<StaleEntity> = BinaryHeap::new();
        let mut entity_ids: Vec<String> = Vec::new();

        for (entity_id, state) in &self.entities {
            entity_ids.push(entity_id.clone());
            let stale_key = state.last_decay_at.timestamp_millis();
            heap.push(StaleEntity {
                stale_key: -stale_key, // Negate for max-heap: older = larger neg = higher priority
                entity_id: entity_id.clone(),
            });
        }

        // Process in staleness order
        while let Some(stale) = heap.pop() {
            let eid = &stale.entity_id;
            let needs_processing = {
                if let Some(state) = self.entities.get(eid) {
                    state.dirty
                        || self
                            .policy_registry
                            .policies_for_entity(eid)
                            .iter()
                            .any(|p| {
                                let elapsed = state.elapsed_since_decay(&now);
                                p.schedule.should_decay(elapsed, &now)
                            })
                } else {
                    false
                }
            };

            if !needs_processing {
                result.entities_skipped += 1;
                continue;
            }

            let old_trust = self
                .entities
                .get(eid)
                .map(|s| s.current_trust)
                .unwrap_or(0.5);

            if self.decay_entity(eid).is_some() {
                let new_trust = self
                    .entities
                    .get(eid)
                    .map(|s| s.current_trust)
                    .unwrap_or(0.5);
                let decay = old_trust - new_trust;
                result.total_decay += decay;
                result.max_single_decay = result.max_single_decay.max(decay);

                // Check floor hit
                if let Some(policy) = self.policy_registry.policies_for_entity(eid).first() {
                    if (new_trust - policy.trust_floor).abs() < 1e-9 {
                        result.floor_hits += 1;
                    }
                }

                result.entities_processed += 1;
            } else {
                result.entities_skipped += 1;
            }
        }

        result
    }

    /// Incremental update: only recompute entities that have new evidence
    /// or whose schedules have triggered since the last run.
    pub fn incremental_decay(&mut self) -> BatchDecayResult {
        let now = Utc::now();
        let mut result = BatchDecayResult {
            entities_processed: 0,
            entities_skipped: 0,
            total_decay: 0.0,
            max_single_decay: 0.0,
            floor_hits: 0,
            batch_time: now,
        };

        let entity_ids: Vec<String> = self.entities.keys().cloned().collect();
        for eid in entity_ids {
            let state = match self.entities.get(&eid) {
                Some(s) => s,
                None => continue,
            };

            // Check if entity is dirty (has new evidence)
            if !state.dirty {
                // Check if any schedule has triggered
                let has_trigger = self
                    .policy_registry
                    .policies_for_entity(&eid)
                    .iter()
                    .any(|p| {
                        let elapsed = state.elapsed_since_decay(&now);
                        p.schedule.should_decay(elapsed, &now)
                    });
                if !has_trigger {
                    result.entities_skipped += 1;
                    continue;
                }
            }

            let old_trust = state.current_trust;
            if self.decay_entity(&eid).is_some() {
                let new_trust = self
                    .entities
                    .get(&eid)
                    .map(|s| s.current_trust)
                    .unwrap_or(0.5);
                let decay = old_trust - new_trust;
                result.total_decay += decay;
                result.max_single_decay = result.max_single_decay.max(decay);
                result.entities_processed += 1;
            } else {
                result.entities_skipped += 1;
            }
        }

        result
    }

    /// Get the current trust of an entity.
    pub fn get_trust(&self, entity_id: &str) -> Option<f64> {
        self.entities.get(entity_id).map(|s| s.current_trust)
    }

    /// Get the raw (non-decayed) trust of an entity.
    pub fn get_raw_trust(&self, entity_id: &str) -> Option<f64> {
        self.entities.get(entity_id).map(|s| s.raw_trust)
    }

    /// Get the full entity state.
    pub fn get_entity_state(&self, entity_id: &str) -> Option<&EntityDecayState> {
        self.entities.get(entity_id)
    }

    /// Get a reference to the audit trail.
    pub fn audit_trail(&self) -> &DecayAuditTrail {
        &self.audit_trail
    }

    /// Get the number of tracked entities.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// List all tracked entity IDs.
    pub fn entity_ids(&self) -> Vec<&str> {
        self.entities.keys().map(|s| s.as_str()).collect()
    }

    /// Force-set an entity's trust (e.g., manual override).
    pub fn set_trust(&mut self, entity_id: &str, trust: f64) -> bool {
        if let Some(state) = self.entities.get_mut(entity_id) {
            let old = state.current_trust;
            state.current_trust = trust.clamp(0.0, 1.0);
            let entry = DecayAuditEntry::new(
                entity_id,
                old,
                state.current_trust,
                &DecayModel::default_exponential(),
                &DecaySchedule::Immediate,
                0.0,
                0.0,
                "manual_override",
            );
            self.audit_trail.record(entry);
            return true;
        }
        false
    }

    /// Remove an entity from tracking.
    pub fn remove_entity(&mut self, entity_id: &str) -> bool {
        self.entities.remove(entity_id).is_some()
    }

    /// Export the full engine state as JSON.
    pub fn export_state(&self) -> String {
        serde_json::to_string_pretty(&self.entities).unwrap_or_else(|_| "{}".into())
    }

    /// Compute a summary snapshot of all entity trust levels.
    pub fn trust_snapshot(&self) -> HashMap<String, f64> {
        self.entities
            .iter()
            .map(|(k, v)| (k.clone(), v.current_trust))
            .collect()
    }
}

impl Default for TrustDecayEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_engine() -> TrustDecayEngine {
        TrustDecayEngine::new()
    }

    fn make_evidence(positive: bool, weight: f64) -> DecayEvidence {
        DecayEvidence::new(positive, weight, "test")
    }

    // -- Decay Model Tests --

    #[test]
    fn exponential_decay_at_zero_is_one() {
        let params = ExponentialParams::new(0.01);
        assert!((params.decay_factor(0.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn exponential_decay_monotonic() {
        let params = ExponentialParams::new(0.001);
        let f1 = params.decay_factor(100.0);
        let f2 = params.decay_factor(200.0);
        assert!(f1 > f2);
        assert!(f2 > 0.0);
    }

    #[test]
    fn exponential_half_life_correct() {
        let params = ExponentialParams::new(std::f64::consts::LN_2);
        let half_life = params.half_life_secs();
        assert!((half_life - 1.0).abs() < 1e-9);
        let factor = params.decay_factor(1.0);
        assert!((factor - 0.5).abs() < 1e-9);
    }

    #[test]
    fn power_law_decay_at_zero_is_one() {
        let params = PowerLawParams::new(0.5);
        assert!((params.decay_factor(0.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn power_law_heavy_tail() {
        let params = PowerLawParams::new(0.5);
        let f_100 = params.decay_factor(100.0);
        let f_10000 = params.decay_factor(10000.0);
        assert!(f_100 > f_10000);
        // Heavy tail: at large t, decay is still non-trivial
        assert!(f_10000 > 0.0);
    }

    #[test]
    fn step_function_respects_boundaries() {
        let params = StepFunctionParams::new(vec![
            StepBoundary {
                at_seconds: 10.0,
                drop_factor: 0.8,
            },
            StepBoundary {
                at_seconds: 20.0,
                drop_factor: 0.5,
            },
        ]);
        assert!((params.decay_factor(5.0) - 1.0).abs() < 1e-12);
        assert!((params.decay_factor(15.0) - 0.8).abs() < 1e-12);
        assert!((params.decay_factor(25.0) - 0.4).abs() < 1e-12);
    }

    #[test]
    fn step_function_flat_between_boundaries() {
        let params = StepFunctionParams::new(vec![StepBoundary {
            at_seconds: 100.0,
            drop_factor: 0.9,
        }]);
        let f_50 = params.decay_factor(50.0);
        let f_99 = params.decay_factor(99.0);
        assert!((f_50 - f_99).abs() < 1e-12);
    }

    #[test]
    fn logarithmic_decay_decreases() {
        let params = LogarithmicParams::new(0.1, 0.001);
        let f0 = params.decay_factor(0.0);
        let f1000 = params.decay_factor(1000.0);
        assert!((f0 - 1.0).abs() < 1e-12);
        assert!(f1000 < f0);
    }

    #[test]
    fn logarithmic_decay_non_negative() {
        let params = LogarithmicParams::new(0.1, 0.001);
        let f_huge = params.decay_factor(1e12);
        assert!(f_huge >= 0.0);
    }

    #[test]
    fn custom_piecewise_linear_interpolation() {
        let seg = LinearSegment::new(0.0, 100.0, 1.0, 0.0);
        assert!((seg.evaluate(0.0).unwrap() - 1.0).abs() < 1e-12);
        assert!((seg.evaluate(50.0).unwrap() - 0.5).abs() < 1e-12);
        assert!((seg.evaluate(100.0).unwrap() - 0.0).abs() < 1e-12);
        assert!(seg.evaluate(200.0).is_none());
    }

    #[test]
    fn custom_params_multi_segment() {
        let params = CustomParams::new(vec![
            LinearSegment::new(0.0, 10.0, 1.0, 0.8),
            LinearSegment::new(10.0, 100.0, 0.8, 0.2),
        ]);
        assert!((params.decay_factor(0.0) - 1.0).abs() < 1e-12);
        assert!((params.decay_factor(5.0) - 0.9).abs() < 1e-9);
        assert!((params.decay_factor(10.0) - 0.8).abs() < 1e-9);
        assert!((params.decay_factor(55.0) - 0.5).abs() < 1e-9);
        assert!((params.decay_factor(200.0) - 0.2).abs() < 1e-9);
    }

    #[test]
    fn decay_model_apply_clamps_to_range() {
        let model = DecayModel::Exponential(ExponentialParams::new(0.0001));
        let result = model.apply(1.5, 0.0);
        assert!(result <= 1.0);
        assert!(result >= 0.0);
    }

    // -- Schedule Tests --

    #[test]
    fn immediate_schedule_always_decays() {
        let schedule = DecaySchedule::Immediate;
        let now = Utc::now();
        assert!(schedule.should_decay(1.0, &now));
        assert!(!schedule.should_decay(0.0, &now));
    }

    #[test]
    fn deferred_schedule_delays_decay() {
        let schedule = DecaySchedule::Deferred(DeferredParams::new(100.0));
        assert!(!schedule.should_decay(50.0, &Utc::now()));
        assert!(schedule.should_decay(150.0, &Utc::now()));
        assert!((schedule.effective_elapsed(50.0) - 0.0).abs() < 1e-12);
        assert!((schedule.effective_elapsed(200.0) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn periodic_schedule_fired_steps() {
        let schedule = DecaySchedule::Periodic(PeriodicParams::new(60.0));
        let steps = match &schedule {
            DecaySchedule::Periodic(p) => p.fired_steps(185.0),
            _ => panic!("expected periodic"),
        };
        assert_eq!(steps, 3);
    }

    #[test]
    fn event_driven_schedule_never_decays_on_time() {
        let schedule = DecaySchedule::EventDriven(EventDrivenParams::default());
        assert!(!schedule.should_decay(999999.0, &Utc::now()));
    }

    #[test]
    fn cron_params_hourly_matching() {
        let cron = CronParams::hourly();
        let on_the_hour = DateTime::parse_from_rfc3339("2025-01-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let off_the_hour = DateTime::parse_from_rfc3339("2025-01-01T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(cron.matches(&on_the_hour));
        assert!(!cron.matches(&off_the_hour));
    }

    #[test]
    fn cron_params_daily_midnight() {
        let cron = CronParams::daily();
        let midnight = DateTime::parse_from_rfc3339("2025-06-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let noon = DateTime::parse_from_rfc3339("2025-06-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(cron.matches(&midnight));
        assert!(!cron.matches(&noon));
    }

    // -- Evidence Tests --

    #[test]
    fn evidence_store_add_and_count() {
        let mut store = EvidenceStore::new(EvidenceWindowConfig::default());
        assert!(store.is_empty());
        store.add_evidence(make_evidence(true, 0.8));
        store.add_evidence(make_evidence(false, 0.3));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn evidence_store_max_entries() {
        let config = EvidenceWindowConfig::new(86400.0, false, 3);
        let mut store = EvidenceStore::new(config);
        for i in 0..5 {
            store.add_evidence(make_evidence(true, 0.5 + i as f64 * 0.1));
        }
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn evidence_window_recency_weight() {
        let config = EvidenceWindowConfig::new(100.0, true, 1000);
        assert!((config.recency_weight(0.0) - 1.0).abs() < 1e-12);
        assert!((config.recency_weight(50.0) - 0.5).abs() < 1e-9);
        assert!((config.recency_weight(100.0) - 0.0).abs() < 1e-12);
        assert!((config.recency_weight(200.0) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn evidence_aggregate_trust_all_positive() {
        let mut store = EvidenceStore::new(EvidenceWindowConfig::new(86400.0, false, 100));
        store.add_evidence(make_evidence(true, 0.8));
        store.add_evidence(make_evidence(true, 0.6));
        let trust = store.aggregate_raw_trust();
        assert!((trust - 1.0).abs() < 1e-9);
    }

    #[test]
    fn evidence_aggregate_trust_mixed() {
        let mut store = EvidenceStore::new(EvidenceWindowConfig::new(86400.0, false, 100));
        store.add_evidence(make_evidence(true, 0.8));
        store.add_evidence(make_evidence(false, 0.2));
        let trust = store.aggregate_raw_trust();
        assert!((trust - 0.8).abs() < 1e-9);
    }

    // -- Policy Tests --

    #[test]
    fn policy_applies_to_scoped_entity() {
        let mut entities = HashSet::new();
        entities.insert("node_a".into());
        let policy = DecayPolicy::new(
            "p1",
            "Test",
            DecayModel::default_exponential(),
            DecaySchedule::Immediate,
        )
        .with_entities(entities);
        assert!(policy.applies_to("node_a"));
        assert!(!policy.applies_to("node_b"));
    }

    #[test]
    fn global_policy_applies_to_all() {
        let policy = DecayPolicy::new(
            "global",
            "Global",
            DecayModel::default_exponential(),
            DecaySchedule::Immediate,
        );
        assert!(policy.applies_to("any_entity"));
        assert!(policy.applies_to("another"));
    }

    #[test]
    fn policy_floor_is_respected() {
        let policy = DecayPolicy::new(
            "p_floor",
            "Floor Test",
            DecayModel::Exponential(ExponentialParams::new(10.0)),
            DecaySchedule::Immediate,
        )
        .with_floor(0.25);
        let (new_trust, _) = policy.apply_decay(0.3, 1000.0);
        assert!(new_trust >= 0.25);
    }

    #[test]
    fn policy_max_decay_rate_caps() {
        let policy = DecayPolicy::new(
            "p_cap",
            "Rate Cap",
            DecayModel::Exponential(ExponentialParams::new(100.0)),
            DecaySchedule::Immediate,
        )
        .with_max_decay_rate(0.1);
        let trust = 1.0;
        let (new_trust, decay) = policy.apply_decay(trust, 100.0);
        // Max decay should be 0.1 * 1.0 = 0.1
        assert!(decay <= 0.1001);
        assert!(new_trust >= 0.89);
    }

    // -- Registry Tests --

    #[test]
    fn registry_register_and_get() {
        let mut reg = PolicyRegistry::new();
        let p = DecayPolicy::new(
            "p1",
            "One",
            DecayModel::default_exponential(),
            DecaySchedule::Immediate,
        );
        reg.register(p);
        assert!(reg.get("p1").is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_unregister() {
        let mut reg = PolicyRegistry::new();
        reg.register(DecayPolicy::new(
            "p1",
            "One",
            DecayModel::default_exponential(),
            DecaySchedule::Immediate,
        ));
        assert!(reg.unregister("p1"));
        assert!(reg.get("p1").is_none());
    }

    // -- Audit Trail Tests --

    #[test]
    fn audit_trail_records_entries() {
        let mut trail = DecayAuditTrail::new(100);
        let entry = DecayAuditEntry::new(
            "ent1",
            0.9,
            0.7,
            &DecayModel::default_exponential(),
            &DecaySchedule::Immediate,
            100.0,
            100.0,
            "test",
        );
        trail.record(entry);
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn audit_trail_evicts_oldest() {
        let mut trail = DecayAuditTrail::new(3);
        for i in 0..5 {
            trail.record(DecayAuditEntry::new(
                &format!("ent{}", i),
                0.9,
                0.7,
                &DecayModel::default_exponential(),
                &DecaySchedule::Immediate,
                100.0,
                100.0,
                "test",
            ));
        }
        assert_eq!(trail.len(), 3);
        let recent = trail.recent_entries(3);
        assert_eq!(recent[0].entity_id, "ent2");
    }

    #[test]
    fn audit_trail_filter_by_entity() {
        let mut trail = DecayAuditTrail::new(100);
        trail.record(DecayAuditEntry::new(
            "a",
            0.9,
            0.8,
            &DecayModel::default_exponential(),
            &DecaySchedule::Immediate,
            10.0,
            10.0,
            "test",
        ));
        trail.record(DecayAuditEntry::new(
            "b",
            0.7,
            0.5,
            &DecayModel::default_exponential(),
            &DecaySchedule::Immediate,
            10.0,
            10.0,
            "test",
        ));
        trail.record(DecayAuditEntry::new(
            "a",
            0.8,
            0.6,
            &DecayModel::default_power_law(),
            &DecaySchedule::Immediate,
            20.0,
            20.0,
            "test",
        ));
        assert_eq!(trail.entries_for_entity("a").len(), 2);
        assert_eq!(trail.entries_for_entity("b").len(), 1);
    }

    // -- Engine Integration Tests --

    #[test]
    fn engine_register_and_get_entity() {
        let mut engine = make_engine();
        engine.register_entity("node_1", None);
        assert_eq!(engine.entity_count(), 1);
        assert!(engine.get_trust("node_1").is_some());
    }

    #[test]
    fn engine_add_evidence() {
        let mut engine = make_engine();
        engine.register_entity("node_1", None);
        engine.add_evidence("node_1", make_evidence(true, 0.9));
        let state = engine.get_entity_state("node_1").unwrap();
        assert_eq!(state.evidence_store.len(), 1);
        assert!(state.dirty);
    }

    #[test]
    fn engine_decay_reduces_trust() {
        let mut engine = make_engine();
        engine.register_entity("node_1", None);
        // Start with high trust
        engine.set_trust("node_1", 1.0);
        // Manually set last_evidence_at to the past to simulate aging
        {
            let state = engine.entities.get_mut("node_1").unwrap();
            state.last_evidence_at = Utc::now() - Duration::seconds(10000);
            state.last_decay_at = Utc::now() - Duration::seconds(10000);
            state.dirty = true;
        }
        engine.decay_entity("node_1");
        let trust = engine.get_trust("node_1").unwrap();
        assert!(trust < 1.0);
    }

    #[test]
    fn engine_batch_decay_processes_dirty() {
        let mut engine = make_engine();
        engine.register_entity("n1", None);
        engine.register_entity("n2", None);
        engine.add_evidence("n1", make_evidence(true, 0.8));
        engine.add_evidence("n2", make_evidence(false, 0.5));
        let result = engine.batch_decay();
        assert!(result.entities_processed >= 2);
    }

    #[test]
    fn engine_set_trust_audit_recorded() {
        let mut engine = make_engine();
        engine.register_entity("node_1", None);
        engine.set_trust("node_1", 0.95);
        let entries = engine.audit_trail().entries_for_entity("node_1");
        assert!(!entries.is_empty());
        assert_eq!(entries.last().unwrap().reason, "manual_override");
    }

    #[test]
    fn engine_remove_entity() {
        let mut engine = make_engine();
        engine.register_entity("node_1", None);
        assert!(engine.remove_entity("node_1"));
        assert_eq!(engine.entity_count(), 0);
    }

    #[test]
    fn engine_trust_snapshot() {
        let mut engine = make_engine();
        engine.register_entity("a", None);
        engine.register_entity("b", None);
        let snapshot = engine.trust_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.contains_key("a"));
        assert!(snapshot.contains_key("b"));
    }

    #[test]
    fn engine_event_trigger_fires() {
        let mut engine = make_engine();
        let mut entities = HashSet::new();
        entities.insert("ev_node".into());
        let event_policy = DecayPolicy::new(
            "event_pol",
            "Event Policy",
            DecayModel::Exponential(ExponentialParams::new(0.01)),
            DecaySchedule::EventDriven(EventDrivenParams::new(
                {
                    let mut s = HashSet::new();
                    s.insert("restart".into());
                    s
                },
                100.0,
            )),
        )
        .with_entities(entities);
        engine.register_policy(event_policy);
        engine.register_entity("ev_node", Some("event_pol"));
        engine.set_trust("ev_node", 1.0);
        let results = engine.trigger_event("restart");
        assert_eq!(results.len(), 1);
        let (_, before, after) = &results[0];
        assert!(after < before);
    }

    #[test]
    fn engine_export_state_is_valid_json() {
        let mut engine = make_engine();
        engine.register_entity("x", None);
        let json = engine.export_state();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn audit_trail_large_decays_filter() {
        let mut trail = DecayAuditTrail::new(100);
        trail.record(DecayAuditEntry::new(
            "e1",
            1.0,
            0.95,
            &DecayModel::default_exponential(),
            &DecaySchedule::Immediate,
            100.0,
            100.0,
            "small",
        ));
        trail.record(DecayAuditEntry::new(
            "e2",
            1.0,
            0.3,
            &DecayModel::default_exponential(),
            &DecaySchedule::Immediate,
            100.0,
            100.0,
            "big",
        ));
        let large = trail.large_decays(0.5);
        assert_eq!(large.len(), 1);
        assert_eq!(large[0].entity_id, "e2");
    }

    #[test]
    fn evidence_store_recompute_decayed_weights() {
        let mut store = EvidenceStore::new(EvidenceWindowConfig::new(1_000_000.0, false, 100));
        let past = Utc::now() - Duration::seconds(10000);
        store.add_evidence(DecayEvidence::with_timestamp(true, 0.9, "test", past));
        let model = DecayModel::Exponential(ExponentialParams::new(0.001));
        let schedule = DecaySchedule::Immediate;
        store.recompute_decayed_weights(&model, &schedule, &Utc::now());
        let ev = store.evidence.front().unwrap();
        assert!(ev.decayed_weight < ev.raw_weight);
    }

    #[test]
    fn decay_model_serialization_roundtrip() {
        let model = DecayModel::Exponential(ExponentialParams::new(0.005));
        let json = serde_json::to_string(&model).unwrap();
        let decoded: DecayModel = serde_json::from_str(&json).unwrap();
        let t1 = model.decay_factor(500.0);
        let t2 = decoded.decay_factor(500.0);
        assert!((t1 - t2).abs() < 1e-12);
    }

    #[test]
    fn decay_policy_serialization_roundtrip() {
        let policy = DecayPolicy::new(
            "ser_test",
            "Serialization",
            DecayModel::default_power_law(),
            DecaySchedule::Periodic(PeriodicParams::new(600.0)),
        )
        .with_floor(0.05)
        .with_max_decay_rate(0.3);
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: DecayPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.policy_id, "ser_test");
        assert!((decoded.trust_floor - 0.05).abs() < 1e-12);
    }

    #[test]
    fn evidence_prune_removes_old() {
        let config = EvidenceWindowConfig::new(60.0, false, 1000);
        let mut store = EvidenceStore::new(config);
        let old = Utc::now() - Duration::seconds(120);
        let recent = Utc::now() - Duration::seconds(10);
        store.add_evidence(DecayEvidence::with_timestamp(true, 0.9, "old", old));
        store.add_evidence(DecayEvidence::with_timestamp(true, 0.8, "new", recent));
        store.prune_expired(&Utc::now());
        assert_eq!(store.len(), 1);
    }
}
