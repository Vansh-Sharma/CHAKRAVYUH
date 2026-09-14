#![deny(unsafe_code)]

// Trust Propagation Bridge
//
// Connects BayesianTrustEngine to AnantaPlane.
//
// Problem: AnantaPlane updates TrustState (simple EMA) on drift/integrity.
// The BayesianTrustEngine exists but is never called from AnantaPlane.
//
// This module:
//   1. Syncs TrustState domains into BayesianTrustEngine nodes
//   2. Converts drift/integrity events into TrustEvidence
//   3. Runs Bayesian propagation after each OVAPH cycle
//   4. Reconciles Bayesian posteriors back into TrustState levels
//   5. Provides a unified trust query interface

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::ananta::sentinel::drift::{AlertSeverity as DriftAlertSeverity, DriftAlert};
use crate::ananta::trust::trust_engine::{BayesianTrustEngine, PropagationResult, TrustEvidence};
use crate::ananta::trust::trust_state::TrustState;

// ---------------------------------------------------------------------------
// Section 1: TrustEvent
// ---------------------------------------------------------------------------

/// The origin of a trust-affecting event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TrustEventSource {
    /// A drift alert was raised by the sentinel.
    DriftAlert,
    /// An integrity check passed or failed.
    IntegrityCheck,
    /// A health observation was recorded.
    HealthObservation,
    /// A recovery action completed.
    RecoveryResult,
    /// An attestation cycle finished.
    AttestationCycle,
    /// A manual trust override was applied.
    ManualOverride,
}

impl std::fmt::Display for TrustEventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriftAlert => write!(f, "drift_alert"),
            Self::IntegrityCheck => write!(f, "integrity_check"),
            Self::HealthObservation => write!(f, "health_observation"),
            Self::RecoveryResult => write!(f, "recovery_result"),
            Self::AttestationCycle => write!(f, "attestation_cycle"),
            Self::ManualOverride => write!(f, "manual_override"),
        }
    }
}

impl Default for TrustEventSource {
    fn default() -> Self {
        Self::HealthObservation
    }
}

/// A single trust-affecting event to be propagated into the Bayesian engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// Where this event originated.
    pub source: TrustEventSource,
    /// Which trust domain this event affects (e.g., "decision", "policy").
    pub domain: String,
    /// Whether this event increases trust (true) or decreases it (false).
    pub is_positive: bool,
    /// How much weight to assign to this event (0.0, 1.0].
    pub weight: f64,
    /// Human-readable description.
    pub description: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
}

impl TrustEvent {
    /// Create a new trust event.
    pub fn new(
        source: TrustEventSource,
        domain: &str,
        is_positive: bool,
        weight: f64,
        description: &str,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            source,
            domain: domain.to_string(),
            is_positive,
            weight: weight.clamp(0.01, 1.0),
            description: description.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a positive trust event.
    pub fn positive(domain: &str, source: TrustEventSource, description: &str) -> Self {
        Self::new(source, domain, true, 0.5, description)
    }

    /// Create a negative trust event.
    pub fn negative(domain: &str, source: TrustEventSource, description: &str) -> Self {
        Self::new(source, domain, false, 0.5, description)
    }
}

// ---------------------------------------------------------------------------
// Section 2: EventToEvidenceConverter
// ---------------------------------------------------------------------------

/// Converts domain events (drift alerts, integrity results, health observations)
/// into [`TrustEvent`]s that the bridge can process.
///
/// The converter maintains a per-source default weight map so that different
/// event origins have appropriately calibrated impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventToEvidenceConverter {
    /// Default weight for each event source type.
    weight_map: HashMap<TrustEventSource, f64>,
    /// The sentinel node used as the "from" side of Bayesian edges.
    sentinel_node: String,
}

impl Default for EventToEvidenceConverter {
    fn default() -> Self {
        let mut weight_map = HashMap::new();
        weight_map.insert(TrustEventSource::DriftAlert, 0.8);
        weight_map.insert(TrustEventSource::IntegrityCheck, 0.9);
        weight_map.insert(TrustEventSource::HealthObservation, 0.4);
        weight_map.insert(TrustEventSource::RecoveryResult, 0.7);
        weight_map.insert(TrustEventSource::AttestationCycle, 0.6);
        weight_map.insert(TrustEventSource::ManualOverride, 1.0);
        Self {
            weight_map,
            sentinel_node: "ananta_plane".to_string(),
        }
    }
}

impl EventToEvidenceConverter {
    /// Create a new converter with default weights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a converter with a custom sentinel node.
    pub fn with_sentinel(sentinel_node: &str) -> Self {
        Self {
            sentinel_node: sentinel_node.to_string(),
            ..Self::default()
        }
    }

    /// Configure the default weight for a given event source.
    pub fn configure_weight(&mut self, source: TrustEventSource, weight: f64) {
        self.weight_map.insert(source, weight.clamp(0.01, 1.0));
    }

    /// Get the default weight for a source.
    pub fn get_weight(&self, source: &TrustEventSource) -> f64 {
        self.weight_map.get(source).copied().unwrap_or(0.5)
    }

    /// Get the sentinel node name.
    pub fn sentinel_node(&self) -> &str {
        &self.sentinel_node
    }

    /// Convert a [`TrustEvent`] into a [`TrustEvidence`] suitable for the
    /// Bayesian engine, and return the (from, to) edge key.
    pub fn convert(&self, event: &TrustEvent) -> (String, String, TrustEvidence) {
        let from = self.sentinel_node.clone();
        let to = event.domain.clone();
        let evidence = TrustEvidence {
            is_positive: event.is_positive,
            weight: event.weight,
            timestamp: event.timestamp.clone(),
            source: format!("{}:{}", event.source, event.event_id),
        };
        debug!(
            from = %from,
            to = %to,
            is_positive = evidence.is_positive,
            weight = evidence.weight,
            "converted TrustEvent to TrustEvidence"
        );
        (from, to, evidence)
    }

    /// Convert a [`DriftAlert`] into a [`TrustEvent`].
    ///
    /// Drift alerts are always negative (they signal degradation).
    /// The weight is scaled by the z-score magnitude and the alert severity.
    pub fn convert_drift_alert(&self, alert: &DriftAlert) -> TrustEvent {
        let domain = format!("{:?}", alert.drift_type).to_lowercase();
        let base_weight = self
            .weight_map
            .get(&TrustEventSource::DriftAlert)
            .copied()
            .unwrap_or(0.8);
        // Scale weight by z-score magnitude (clamped to [0.01, 1.0]).
        let z_scale = (alert.z_score.abs() / 5.0).min(1.0).max(0.1);
        let severity_multiplier = match alert.severity {
            DriftAlertSeverity::Critical => 1.0,
            DriftAlertSeverity::Warning => 0.7,
            DriftAlertSeverity::Info => 0.3,
        };
        let weight = (base_weight * z_scale * severity_multiplier).clamp(0.01, 1.0);

        let description = format!(
            "drift detected: type={:?} z={:.2} context={}",
            alert.drift_type, alert.z_score, alert.context
        );

        TrustEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            source: TrustEventSource::DriftAlert,
            domain,
            is_positive: false,
            weight,
            description,
            timestamp: alert.timestamp.clone(),
        }
    }

    /// Convert an integrity check result into a [`TrustEvent`].
    ///
    /// Parameters:
    /// - `domain`: the trust domain this integrity check covers
    /// - `passed`: whether the integrity check passed
    /// - `detail`: human-readable detail string
    pub fn convert_integrity_result(&self, domain: &str, passed: bool, detail: &str) -> TrustEvent {
        let base_weight = self
            .weight_map
            .get(&TrustEventSource::IntegrityCheck)
            .copied()
            .unwrap_or(0.9);
        TrustEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            source: TrustEventSource::IntegrityCheck,
            domain: domain.to_string(),
            is_positive: passed,
            weight: base_weight,
            description: format!(
                "integrity check {} for {}: {}",
                if passed { "passed" } else { "FAILED" },
                domain,
                detail
            ),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Convert a health observation into a [`TrustEvent`].
    ///
    /// Parameters:
    /// - `domain`: the trust domain
    /// - `is_healthy`: whether the observation indicates health
    /// - `health_score`: a 0.0-1.0 health score
    /// - `detail`: human-readable detail
    pub fn convert_health_observation(
        &self,
        domain: &str,
        is_healthy: bool,
        health_score: f64,
        detail: &str,
    ) -> TrustEvent {
        let base_weight = self
            .weight_map
            .get(&TrustEventSource::HealthObservation)
            .copied()
            .unwrap_or(0.4);
        // Weight scales with how far from neutral the health score is.
        let distance_from_neutral = (health_score - 0.5).abs() * 2.0;
        let weight = (base_weight * (0.5 + 0.5 * distance_from_neutral)).clamp(0.01, 1.0);

        TrustEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            source: TrustEventSource::HealthObservation,
            domain: domain.to_string(),
            is_positive: is_healthy,
            weight,
            description: format!(
                "health observation for {}: score={:.3} {}",
                domain, health_score, detail
            ),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Section 3: TrustStateSynchronizer
// ---------------------------------------------------------------------------

/// Result of a synchronization operation between TrustState and the Bayesian engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Number of domains that were synced.
    pub domains_synced: usize,
    /// Number of evidence records added.
    pub evidence_added: usize,
    /// Number of propagation iterations run.
    pub propagation_iterations: u32,
    /// Per-domain trust changes.
    pub trust_changes: Vec<TrustChange>,
    /// Wall-clock duration of the sync in milliseconds.
    pub duration_ms: f64,
}

impl Default for SyncResult {
    fn default() -> Self {
        Self {
            domains_synced: 0,
            evidence_added: 0,
            propagation_iterations: 0,
            trust_changes: vec![],
            duration_ms: 0.0,
        }
    }
}

/// A single domain trust change recorded during synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChange {
    /// The domain name.
    pub domain: String,
    /// Trust level before the change.
    pub old_level: f64,
    /// Trust level after the change.
    pub new_level: f64,
    /// The signed delta (new - old).
    pub delta: f64,
    /// What caused the change (e.g., "bayesian_posterior", "reconciliation").
    pub source: String,
}

/// Bidirectional synchronizer between the simple [`TrustState`] and the
/// probabilistic [`BayesianTrustEngine`].
///
/// The synchronizer:
///   - Pushes TrustState domain levels into the Bayesian engine as seed evidence
///   - Pulls Bayesian posteriors back into TrustState domain levels
///   - Reconciles both directions using a weighted blend factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStateSynchronizer {
    /// PageRank-style damping factor for propagation convergence.
    pub damping: f64,
    /// Convergence threshold for propagation.
    pub convergence_threshold: f64,
    /// Maximum iterations for propagation.
    pub max_propagation_iterations: u32,
    /// How much the Bayesian posterior influences TrustState (0.0 = pure EMA, 1.0 = pure Bayesian).
    pub reconciliation_factor: f64,
    /// The sentinel node used as the "from" side of Bayesian edges.
    sentinel_node: String,
}

impl Default for TrustStateSynchronizer {
    fn default() -> Self {
        Self {
            damping: 0.85,
            convergence_threshold: 1e-6,
            max_propagation_iterations: 100,
            reconciliation_factor: 0.3,
            sentinel_node: "ananta_plane".to_string(),
        }
    }
}

impl TrustStateSynchronizer {
    /// Create a new synchronizer with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom reconciliation factor.
    pub fn with_reconciliation_factor(factor: f64) -> Self {
        Self {
            reconciliation_factor: factor.clamp(0.0, 1.0),
            ..Self::default()
        }
    }

    /// Create with a custom sentinel node.
    pub fn with_sentinel(sentinel_node: &str) -> Self {
        Self {
            sentinel_node: sentinel_node.to_string(),
            ..Self::default()
        }
    }

    /// Get the sentinel node name.
    pub fn sentinel_node(&self) -> &str {
        &self.sentinel_node
    }

    /// Sync TrustState domain levels INTO the BayesianTrustEngine.
    ///
    /// For each domain in TrustState, this records an initial positive
    /// evidence proportional to the domain's trust level. This seeds the
    /// Bayesian engine with the current EMA-based state.
    ///
    /// The evidence weight is scaled: a domain at level 1.0 gets weight 1.0,
    /// a domain at level 0.5 gets weight 0.5. This encodes the existing
    /// trust level as a single positive observation.
    pub fn sync_to_engine(
        &self,
        state: &TrustState,
        engine: &mut BayesianTrustEngine,
    ) -> SyncResult {
        let start = std::time::Instant::now();
        let mut domains_synced = 0usize;
        let mut evidence_added = 0usize;

        for (domain_name, domain_trust) in &state.domains {
            let level = domain_trust.level;
            // Record positive evidence with weight equal to the trust level.
            // This encodes "we observed level amount of trustworthiness".
            let weight = level.clamp(0.01, 1.0);
            engine.record_evidence(
                &self.sentinel_node,
                domain_name,
                true,
                weight,
                &format!("sync_to_engine:{}", domain_name),
            );
            domains_synced += 1;
            evidence_added += 1;

            debug!(
                domain = %domain_name,
                level = level,
                weight = weight,
                "synced domain to Bayesian engine"
            );
        }

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        info!(
            domains_synced = domains_synced,
            duration_ms = duration_ms,
            "sync_to_engine complete"
        );

        SyncResult {
            domains_synced,
            evidence_added,
            propagation_iterations: 0,
            trust_changes: vec![],
            duration_ms,
        }
    }

    /// Sync BayesianTrustEngine posteriors BACK into TrustState.
    ///
    /// For each edge in the engine that matches a known domain, this reads
    /// the posterior mean and updates the corresponding domain level in
    /// TrustState.
    ///
    /// The propagation is run first to get the latest node-level trust values.
    pub fn sync_from_engine(
        &self,
        engine: &mut BayesianTrustEngine,
        state: &mut TrustState,
    ) -> SyncResult {
        let start = std::time::Instant::now();
        let mut trust_changes = vec![];

        // Run propagation to get updated node trust values.
        let prop_result = engine.propagate();
        let iterations = prop_result.iterations;

        // For each domain in TrustState, check if there's a corresponding
        // propagated trust value.
        for (domain_name, domain_trust) in &mut state.domains {
            let new_level = prop_result.get(domain_name);
            if new_level > 0.0 {
                let old_level = domain_trust.level;
                if (new_level - old_level).abs() > 1e-9 {
                    trust_changes.push(TrustChange {
                        domain: domain_name.clone(),
                        old_level,
                        new_level,
                        delta: new_level - old_level,
                        source: "bayesian_posterior".to_string(),
                    });
                    // Inline set_domain_level to avoid borrow conflict.
                    let clamped = new_level.clamp(0.0, 1.0);
                    domain_trust.trend = if (clamped - domain_trust.level).abs() < 0.01 {
                        crate::ananta::trust::trust_state::TrendDirection::Stable
                    } else if clamped > domain_trust.level {
                        crate::ananta::trust::trust_state::TrendDirection::Improving
                    } else {
                        crate::ananta::trust::trust_state::TrendDirection::Degrading
                    };
                    domain_trust.level = clamped;
                    domain_trust.observations += 1;
                }
            }
        }

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        info!(
            changes = trust_changes.len(),
            iterations = iterations,
            duration_ms = duration_ms,
            "sync_from_engine complete"
        );

        SyncResult {
            domains_synced: state.domains.len(),
            evidence_added: 0,
            propagation_iterations: iterations,
            trust_changes,
            duration_ms,
        }
    }

    /// Reconcile TrustState and BayesianTrustEngine in both directions.
    ///
    /// This is the primary synchronization method used after each OVAPH cycle:
    ///   1. Push current TrustState levels into the engine (seed evidence)
    ///   2. Run Bayesian propagation
    ///   3. Pull posteriors back
    ///   4. Blend: new_level = (1 - r) * simple_level + r * bayesian_level
    ///      where r is the reconciliation_factor
    pub fn reconcile(
        &self,
        state: &mut TrustState,
        engine: &mut BayesianTrustEngine,
    ) -> SyncResult {
        let start = std::time::Instant::now();
        let mut trust_changes = vec![];

        // Step 1: Push current state into engine.
        let to_result = self.sync_to_engine(state, engine);
        let evidence_added = to_result.evidence_added;
        let domains_synced = to_result.domains_synced;

        // Step 2: Run propagation.
        let prop_result = engine.propagate();
        let iterations = prop_result.iterations;

        // Step 3 & 4: Pull posteriors and blend.
        for (domain_name, domain_trust) in &mut state.domains {
            let bayesian_level = prop_result.get(domain_name);
            if bayesian_level <= 0.0 {
                // No Bayesian data for this domain yet.
                continue;
            }
            let simple_level = domain_trust.level;
            let blended = (1.0 - self.reconciliation_factor) * simple_level
                + self.reconciliation_factor * bayesian_level;
            let new_level = blended.clamp(0.0, 1.0);

            if (new_level - simple_level).abs() > 1e-9 {
                trust_changes.push(TrustChange {
                    domain: domain_name.clone(),
                    old_level: simple_level,
                    new_level,
                    delta: new_level - simple_level,
                    source: "reconciliation".to_string(),
                });
                // Inline set_domain_level to avoid borrow conflict.
                let clamped = new_level.clamp(0.0, 1.0);
                domain_trust.trend = if (clamped - domain_trust.level).abs() < 0.01 {
                    crate::ananta::trust::trust_state::TrendDirection::Stable
                } else if clamped > domain_trust.level {
                    crate::ananta::trust::trust_state::TrendDirection::Improving
                } else {
                    crate::ananta::trust::trust_state::TrendDirection::Degrading
                };
                domain_trust.level = clamped;
                domain_trust.observations += 1;
            }
        }

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        info!(
            changes = trust_changes.len(),
            iterations = iterations,
            domains_synced = domains_synced,
            evidence_added = evidence_added,
            duration_ms = duration_ms,
            "reconciliation complete"
        );

        SyncResult {
            domains_synced,
            evidence_added,
            propagation_iterations: iterations,
            trust_changes,
            duration_ms,
        }
    }

    /// Apply a single trust event to the Bayesian engine.
    ///
    /// Converts the event into evidence and records it on the appropriate
    /// edge (sentinel_node -> domain).
    pub fn apply_event(
        &self,
        engine: &mut BayesianTrustEngine,
        event: &TrustEvent,
    ) -> Result<String, String> {
        if event.domain.is_empty() {
            return Err("domain must not be empty".to_string());
        }
        if event.weight < 0.01 {
            return Err("weight must be >= 0.01".to_string());
        }

        let evidence_id = event.event_id.clone();
        engine.record_evidence(
            &self.sentinel_node,
            &event.domain,
            event.is_positive,
            event.weight,
            &format!("event:{}", event.event_id),
        );

        debug!(
            event_id = %event.event_id,
            domain = %event.domain,
            is_positive = event.is_positive,
            weight = event.weight,
            "applied event to Bayesian engine"
        );

        Ok(evidence_id)
    }

    /// Run a convergence check: iterate propagation until convergence or
    /// max iterations, returning the final result.
    pub fn run_convergence_propagation(
        &self,
        engine: &mut BayesianTrustEngine,
    ) -> Result<PropagationResult, String> {
        let result = engine.propagate();
        debug!(
            iterations = result.iterations,
            converged = result.converged,
            max_delta = result.final_max_delta,
            "propagation convergence check"
        );
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Section 4: TrustPropagationOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the full trust propagation pipeline:
///   event collection → evidence conversion → Bayesian update → propagation → reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPropagationOrchestrator {
    /// The bidirectional synchronizer.
    pub synchronizer: TrustStateSynchronizer,
    /// The event-to-evidence converter.
    pub converter: EventToEvidenceConverter,
    /// Events queued for processing.
    pending_events: Vec<TrustEvent>,
    /// Maximum number of events to buffer before forcing a flush.
    pub max_pending_events: usize,
}

impl Default for TrustPropagationOrchestrator {
    fn default() -> Self {
        Self {
            synchronizer: TrustStateSynchronizer::default(),
            converter: EventToEvidenceConverter::default(),
            pending_events: vec![],
            max_pending_events: 1000,
        }
    }
}

impl TrustPropagationOrchestrator {
    /// Create a new orchestrator with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom reconciliation factor.
    pub fn with_reconciliation_factor(factor: f64) -> Self {
        Self {
            synchronizer: TrustStateSynchronizer::with_reconciliation_factor(factor),
            converter: EventToEvidenceConverter::default(),
            pending_events: vec![],
            max_pending_events: 1000,
        }
    }

    /// Submit a single trust event for processing.
    pub fn submit_event(&mut self, event: TrustEvent) -> Result<(), String> {
        if self.pending_events.len() >= self.max_pending_events {
            return Err(format!(
                "pending event buffer full (max={})",
                self.max_pending_events
            ));
        }
        debug!(
            event_id = %event.event_id,
            domain = %event.domain,
            "submitted trust event"
        );
        self.pending_events.push(event);
        Ok(())
    }

    /// Submit multiple trust events at once.
    pub fn submit_events(&mut self, events: Vec<TrustEvent>) -> Result<usize, String> {
        let available = self
            .max_pending_events
            .saturating_sub(self.pending_events.len());
        let total = events.len();
        if total > available {
            let accepted = total.min(available);
            let batch: Vec<TrustEvent> = events.into_iter().take(accepted).collect();
            self.pending_events.extend(batch);
            return Err(format!(
                "only {}/{} events accepted (buffer near capacity)",
                accepted, total
            ));
        }
        self.pending_events.extend(events);
        Ok(total)
    }

    /// Process all pending events: convert to evidence and add to the engine.
    pub fn process_pending(
        &mut self,
        engine: &mut BayesianTrustEngine,
    ) -> Result<ProcessPendingResult, String> {
        let events_to_process = std::mem::take(&mut self.pending_events);
        if events_to_process.is_empty() {
            return Ok(ProcessPendingResult {
                events_processed: 0,
                evidence_added: 0,
                errors: vec![],
            });
        }

        let mut evidence_added = 0usize;
        let mut errors = vec![];

        for event in &events_to_process {
            let (from, to, evidence) = self.converter.convert(event);
            if from.is_empty() || to.is_empty() {
                errors.push(format!(
                    "event {} has empty from/to: from={}, to={}",
                    event.event_id, from, to
                ));
                continue;
            }
            engine.record_evidence(
                &from,
                &to,
                evidence.is_positive,
                evidence.weight,
                &evidence.source,
            );
            evidence_added += 1;
        }

        info!(
            events_processed = events_to_process.len(),
            evidence_added = evidence_added,
            errors = errors.len(),
            "processed pending events"
        );

        Ok(ProcessPendingResult {
            events_processed: events_to_process.len(),
            evidence_added,
            errors,
        })
    }

    /// Run a full propagation cycle: process events → propagate → reconcile.
    ///
    /// This is the main entry point called after each OVAPH cycle.
    pub fn run_propagation_cycle(
        &mut self,
        engine: &mut BayesianTrustEngine,
        state: &mut TrustState,
    ) -> Result<PropagationCycleResult, String> {
        info!("starting trust propagation cycle");

        // Step 1: Process all pending events.
        let pending_result = self.process_pending(engine)?;

        // Step 2: Run Bayesian propagation.
        let prop_result = engine.propagate();

        // Step 3: Reconcile posteriors back into TrustState.
        let sync_result = self.synchronizer.reconcile(state, engine);

        info!(
            events_processed = pending_result.events_processed,
            evidence_added = pending_result.evidence_added,
            propagation_iterations = prop_result.iterations,
            propagation_converged = prop_result.converged,
            domains_changed = sync_result.trust_changes.len(),
            "trust propagation cycle complete"
        );

        Ok(PropagationCycleResult {
            pending_result,
            propagation_result: prop_result,
            sync_result,
        })
    }

    /// Get the number of events currently pending.
    pub fn get_pending_count(&self) -> usize {
        self.pending_events.len()
    }

    /// Clear all pending events without processing them.
    pub fn clear_pending(&mut self) {
        let count = self.pending_events.len();
        self.pending_events.clear();
        if count > 0 {
            warn!(cleared = count, "cleared pending events without processing");
        }
    }
}

/// Result of processing pending events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPendingResult {
    /// Total events that were in the queue.
    pub events_processed: usize,
    /// How many were successfully converted to evidence.
    pub evidence_added: usize,
    /// Any errors encountered during processing.
    pub errors: Vec<String>,
}

/// Result of a full propagation cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationCycleResult {
    /// Result of processing the pending event queue.
    pub pending_result: ProcessPendingResult,
    /// Result of the Bayesian propagation.
    pub propagation_result: PropagationResult,
    /// Result of reconciling back to TrustState.
    pub sync_result: SyncResult,
}

// ---------------------------------------------------------------------------
// Section 5: UnifiedTrustQuery
// ---------------------------------------------------------------------------

/// A unified snapshot comparing the simple TrustState and Bayesian engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedTrustSnapshot {
    /// When this snapshot was taken.
    pub timestamp: String,
    /// Domain levels from TrustState (simple EMA).
    pub simple_domains: HashMap<String, f64>,
    /// Domain levels from Bayesian engine posterior means.
    pub bayesian_nodes: HashMap<String, f64>,
    /// Overall simple trust score (weighted average).
    pub overall_simple: f64,
    /// Overall Bayesian trust score (weighted average).
    pub overall_bayesian: f64,
    /// Agreement score: 1.0 = perfect agreement, 0.0 = maximum divergence.
    pub agreement_score: f64,
    /// Per-domain divergence report.
    pub divergence_report: Vec<TrustDivergence>,
}

/// Per-domain divergence between simple and Bayesian trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDivergence {
    /// Domain name.
    pub domain: String,
    /// Simple (EMA) trust level.
    pub simple_level: f64,
    /// Bayesian posterior trust level.
    pub bayesian_level: f64,
    /// Absolute divergence (|simple - bayesian|).
    pub divergence: f64,
    /// Severity classification.
    pub severity: DivergenceSeverity,
}

/// Severity of trust divergence between the two models.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceSeverity {
    /// No meaningful divergence (< 0.05).
    None,
    /// Low divergence (0.05 - 0.15).
    Low,
    /// Medium divergence (0.15 - 0.30).
    Medium,
    /// High divergence (0.30 - 0.50).
    High,
    /// Critical divergence (> 0.50).
    Critical,
}

impl DivergenceSeverity {
    /// Classify a divergence value into a severity level.
    pub fn from_divergence(d: f64) -> Self {
        let d = d.abs();
        if d < 0.05 {
            Self::None
        } else if d < 0.15 {
            Self::Low
        } else if d < 0.30 {
            Self::Medium
        } else if d < 0.50 {
            Self::High
        } else {
            Self::Critical
        }
    }
}

impl UnifiedTrustSnapshot {
    /// Compute a unified trust snapshot by comparing TrustState and the
    /// Bayesian engine.
    ///
    /// The Bayesian engine is propagated first to get fresh node-level values.
    pub fn compute(simple: &TrustState, engine: &mut BayesianTrustEngine) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Collect simple domain levels.
        let simple_domains: HashMap<String, f64> = simple
            .domains
            .iter()
            .map(|(k, v)| (k.clone(), v.level))
            .collect();

        // Propagate and collect Bayesian node levels.
        let prop_result = engine.propagate();
        let bayesian_nodes: HashMap<String, f64> = prop_result
            .node_trust
            .into_iter()
            .filter(|(k, _)| !k.starts_with("_internal_"))
            .collect();

        // Compute overall scores as unweighted averages of available domains.
        let all_domains: std::collections::HashSet<&String> =
            simple_domains.keys().chain(bayesian_nodes.keys()).collect();

        let (mut simple_sum, mut bayesian_sum, mut count) = (0.0, 0.0, 0usize);
        for domain in &all_domains {
            let s = simple_domains.get(*domain).copied().unwrap_or(0.5);
            let b = bayesian_nodes.get(*domain).copied().unwrap_or(0.5);
            simple_sum += s;
            bayesian_sum += b;
            count += 1;
        }
        let overall_simple = if count > 0 {
            simple_sum / count as f64
        } else {
            1.0
        };
        let overall_bayesian = if count > 0 {
            bayesian_sum / count as f64
        } else {
            1.0
        };

        // Build divergence report.
        let mut divergence_report: Vec<TrustDivergence> = vec![];
        for domain in &all_domains {
            let s = simple_domains.get(*domain).copied().unwrap_or(0.5);
            let b = bayesian_nodes.get(*domain).copied().unwrap_or(0.5);
            let divergence = (s - b).abs();
            divergence_report.push(TrustDivergence {
                domain: (*domain).clone(),
                simple_level: s,
                bayesian_level: b,
                divergence,
                severity: DivergenceSeverity::from_divergence(divergence),
            });
        }
        // Sort by divergence descending.
        divergence_report.sort_by(|a, b| {
            b.divergence
                .partial_cmp(&a.divergence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Agreement score: 1.0 - mean divergence.
        let mean_divergence = if count > 0 {
            divergence_report.iter().map(|d| d.divergence).sum::<f64>() / count as f64
        } else {
            0.0
        };
        let agreement_score = (1.0 - mean_divergence).clamp(0.0, 1.0);

        UnifiedTrustSnapshot {
            timestamp,
            simple_domains,
            bayesian_nodes,
            overall_simple,
            overall_bayesian,
            agreement_score,
            divergence_report,
        }
    }

    /// Get all domains where divergence exceeds a threshold.
    pub fn divergent_domains(&self, min_divergence: f64) -> Vec<&TrustDivergence> {
        self.divergence_report
            .iter()
            .filter(|d| d.divergence >= min_divergence)
            .collect()
    }

    /// Get the most divergent domain, if any.
    pub fn most_divergent(&self) -> Option<&TrustDivergence> {
        self.divergence_report.first()
    }

    /// Generate a human-readable agreement summary.
    pub fn agreement_summary(&self) -> String {
        let divergent_count = self
            .divergence_report
            .iter()
            .filter(|d| d.severity != DivergenceSeverity::None)
            .count();
        let critical_count = self
            .divergence_report
            .iter()
            .filter(|d| d.severity == DivergenceSeverity::Critical)
            .count();

        let most = match self.most_divergent() {
            Some(d) => format!(" | most_divergent: {} ({:.3})", d.domain, d.divergence),
            None => String::new(),
        };

        format!(
            "agreement={:.3} simple={:.3} bayesian={:.3} \
             divergent_domains={} critical={}",
            self.agreement_score,
            self.overall_simple,
            self.overall_bayesian,
            divergent_count,
            critical_count,
        ) + &most
    }
}

// ---------------------------------------------------------------------------
// Section 6: Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::sentinel::drift::DriftType;

    // ── A. TrustEvent (4 tests) ──────────────────────────────────────────

    mod test_trust_event {
        use super::*;

        #[test]
        fn test_new_creates_event_with_defaults() {
            let event = TrustEvent::new(
                TrustEventSource::DriftAlert,
                "decision",
                false,
                0.8,
                "drift detected",
            );
            assert_eq!(event.domain, "decision");
            assert!(!event.is_positive);
            assert!((event.weight - 0.8).abs() < 1e-9);
            assert!(!event.event_id.is_empty());
            assert!(!event.timestamp.is_empty());
        }

        #[test]
        fn test_positive_helper() {
            let event = TrustEvent::positive(
                "policy",
                TrustEventSource::AttestationCycle,
                "attestation passed",
            );
            assert!(event.is_positive);
            assert_eq!(event.domain, "policy");
            assert_eq!(event.source, TrustEventSource::AttestationCycle);
        }

        #[test]
        fn test_negative_helper() {
            let event = TrustEvent::negative(
                "model",
                TrustEventSource::IntegrityCheck,
                "integrity failed",
            );
            assert!(!event.is_positive);
            assert_eq!(event.domain, "model");
        }

        #[test]
        fn test_all_source_types() {
            let sources = vec![
                TrustEventSource::DriftAlert,
                TrustEventSource::IntegrityCheck,
                TrustEventSource::HealthObservation,
                TrustEventSource::RecoveryResult,
                TrustEventSource::AttestationCycle,
                TrustEventSource::ManualOverride,
            ];
            for source in sources {
                let event = TrustEvent::new(source.clone(), "test", true, 0.5, "test");
                assert_eq!(event.source, source);
                // Verify Display impl doesn't panic.
                let _display = format!("{}", source);
            }
        }
    }

    // ── B. EventToEvidenceConverter (5 tests) ────────────────────────────

    mod test_converter {
        use super::*;

        #[test]
        fn test_convert_positive_event() {
            let converter = EventToEvidenceConverter::new();
            let event =
                TrustEvent::positive("decision", TrustEventSource::HealthObservation, "healthy");
            let (from, to, evidence) = converter.convert(&event);
            assert_eq!(from, "ananta_plane");
            assert_eq!(to, "decision");
            assert!(evidence.is_positive);
        }

        #[test]
        fn test_convert_negative_event() {
            let converter = EventToEvidenceConverter::new();
            let event = TrustEvent::negative("policy", TrustEventSource::DriftAlert, "drift!");
            let (_, _, evidence) = converter.convert(&event);
            assert!(!evidence.is_positive);
        }

        #[test]
        fn test_weight_map_configuration() {
            let mut converter = EventToEvidenceConverter::new();
            converter.configure_weight(TrustEventSource::ManualOverride, 0.95);
            assert!((converter.get_weight(&TrustEventSource::ManualOverride) - 0.95).abs() < 1e-9);
            // Default weight for DriftAlert.
            assert!((converter.get_weight(&TrustEventSource::DriftAlert) - 0.8).abs() < 1e-9);
        }

        #[test]
        fn test_convert_drift_alert() {
            let converter = EventToEvidenceConverter::new();
            let alert = DriftAlert {
                drift_type: DriftType::Decision,
                z_score: 3.5,
                current_mean: 0.8,
                current_stddev: 0.1,
                observed_value: 0.3,
                context: "ring-0".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: DriftAlertSeverity::Critical,
            };
            let event = converter.convert_drift_alert(&alert);
            assert_eq!(event.source, TrustEventSource::DriftAlert);
            assert!(!event.is_positive);
            assert_eq!(event.domain, "decision");
            assert!(event.weight > 0.0);
        }

        #[test]
        fn test_convert_integrity_result() {
            let converter = EventToEvidenceConverter::new();
            let passed = converter.convert_integrity_result("memory", true, "hash match");
            assert!(passed.is_positive);
            assert_eq!(passed.domain, "memory");

            let failed = converter.convert_integrity_result("runtime", false, "hash mismatch");
            assert!(!failed.is_positive);
            assert_eq!(failed.domain, "runtime");
        }
    }

    // ── C. TrustStateSynchronizer (8 tests) ─────────────────────────────

    mod test_synchronizer {
        use super::*;

        #[test]
        fn test_sync_to_engine_seeds_all_domains() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            let result = sync.sync_to_engine(&state, &mut engine);
            assert_eq!(result.domains_synced, state.domains.len());
            assert_eq!(result.evidence_added, state.domains.len());
            // Engine should now have edges.
            assert!(engine.edge_count() > 0);
        }

        #[test]
        fn test_sync_from_engine_updates_state() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // First sync state to engine so there are edges.
            sync.sync_to_engine(&state, &mut engine);

            // Now add strong negative evidence to drive a domain down.
            for _ in 0..20 {
                engine.record_evidence("ananta_plane", "decision", false, 1.0, "test_negative");
            }

            let result = sync.sync_from_engine(&mut engine, &mut state);
            assert!(result.propagation_iterations > 0);
            // The decision domain should have changed.
            let changed: Vec<_> = result
                .trust_changes
                .iter()
                .filter(|c| c.domain == "decision")
                .collect();
            assert!(!changed.is_empty(), "decision domain should have changed");
        }

        #[test]
        fn test_reconcile_blends_both_models() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::with_reconciliation_factor(0.5);

            // Drive a domain down in the simple state.
            state.set_domain_level("policy", 0.2);

            // Add positive evidence in the engine.
            for _ in 0..20 {
                engine.record_evidence("ananta_plane", "policy", true, 1.0, "test_positive");
            }

            let result = sync.reconcile(&mut state, &mut engine);
            let policy_change = result.trust_changes.iter().find(|c| c.domain == "policy");
            assert!(
                policy_change.is_some(),
                "policy domain should have a trust change after reconciliation"
            );
            let change = policy_change.unwrap();
            // With 50% reconciliation, new level should be between 0.2 and the Bayesian value.
            assert!(
                change.new_level > 0.2,
                "blended level should be higher than 0.2, got {:.4}",
                change.new_level
            );
            assert!(
                change.new_level < 1.0,
                "blended level should be less than 1.0, got {:.4}",
                change.new_level
            );
        }

        #[test]
        fn test_apply_event_success() {
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();
            let event =
                TrustEvent::positive("decision", TrustEventSource::HealthObservation, "healthy");
            let result = sync.apply_event(&mut engine, &event);
            assert!(result.is_ok());
            assert!(engine.edge_count() > 0);
        }

        #[test]
        fn test_apply_event_rejects_empty_domain() {
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();
            let event = TrustEvent::new(TrustEventSource::HealthObservation, "", true, 0.5, "test");
            let result = sync.apply_event(&mut engine, &event);
            assert!(result.is_err());
        }

        #[test]
        fn test_convergence_propagation() {
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Seed some edges.
            engine.record_evidence("a", "b", true, 0.8, "test");
            engine.record_evidence("b", "c", true, 0.6, "test");

            let result = sync.run_convergence_propagation(&mut engine);
            assert!(result.is_ok());
            let prop = result.unwrap();
            assert!(prop.iterations > 0);
        }

        #[test]
        fn test_trust_changes_tracked() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Seed engine.
            sync.sync_to_engine(&state, &mut engine);

            // Add evidence to shift a domain.
            for _ in 0..10 {
                engine.record_evidence("ananta_plane", "trust", false, 1.0, "stress");
            }

            let result = sync.sync_from_engine(&mut engine, &mut state);
            assert!(
                !result.trust_changes.is_empty(),
                "should track trust changes"
            );
        }

        #[test]
        fn test_empty_state_sync() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Sync should succeed even with a fresh engine.
            let result = sync.sync_to_engine(&state, &mut engine);
            assert!(result.domains_synced > 0);
        }
    }

    // ── D. TrustPropagationOrchestrator (6 tests) ───────────────────────

    mod test_orchestrator {
        use super::*;

        #[test]
        fn test_new_orchestrator() {
            let orch = TrustPropagationOrchestrator::new();
            assert_eq!(orch.get_pending_count(), 0);
            assert_eq!(orch.max_pending_events, 1000);
        }

        #[test]
        fn test_submit_event() {
            let mut orch = TrustPropagationOrchestrator::new();
            let event = TrustEvent::positive("decision", TrustEventSource::HealthObservation, "ok");
            let result = orch.submit_event(event);
            assert!(result.is_ok());
            assert_eq!(orch.get_pending_count(), 1);
        }

        #[test]
        fn test_process_pending() {
            let mut orch = TrustPropagationOrchestrator::new();
            let mut engine = BayesianTrustEngine::new();

            orch.submit_event(TrustEvent::positive(
                "decision",
                TrustEventSource::HealthObservation,
                "ok",
            ))
            .unwrap();
            orch.submit_event(TrustEvent::negative(
                "policy",
                TrustEventSource::DriftAlert,
                "drift",
            ))
            .unwrap();

            let result = orch.process_pending(&mut engine);
            assert!(result.is_ok());
            let pr = result.unwrap();
            assert_eq!(pr.events_processed, 2);
            assert_eq!(pr.evidence_added, 2);
            assert_eq!(orch.get_pending_count(), 0);
        }

        #[test]
        fn test_full_cycle() {
            let mut orch = TrustPropagationOrchestrator::new();
            let mut engine = BayesianTrustEngine::new();
            let mut state = TrustState::new();

            // Submit some events.
            orch.submit_event(TrustEvent::negative(
                "decision",
                TrustEventSource::DriftAlert,
                "drift detected",
            ))
            .unwrap();
            orch.submit_event(TrustEvent::positive(
                "policy",
                TrustEventSource::AttestationCycle,
                "attestation ok",
            ))
            .unwrap();

            let result = orch.run_propagation_cycle(&mut engine, &mut state);
            assert!(result.is_ok());
            let cycle = result.unwrap();
            assert_eq!(cycle.pending_result.events_processed, 2);
            assert!(cycle.propagation_result.iterations > 0);
        }

        #[test]
        fn test_max_pending_enforced() {
            let mut orch = TrustPropagationOrchestrator {
                max_pending_events: 2,
                ..TrustPropagationOrchestrator::default()
            };

            orch.submit_event(TrustEvent::positive(
                "a",
                TrustEventSource::HealthObservation,
                "ok",
            ))
            .unwrap();
            orch.submit_event(TrustEvent::positive(
                "b",
                TrustEventSource::HealthObservation,
                "ok",
            ))
            .unwrap();

            let result = orch.submit_event(TrustEvent::positive(
                "c",
                TrustEventSource::HealthObservation,
                "ok",
            ));
            assert!(result.is_err());
        }

        #[test]
        fn test_clear_pending() {
            let mut orch = TrustPropagationOrchestrator::new();
            orch.submit_event(TrustEvent::positive(
                "a",
                TrustEventSource::HealthObservation,
                "ok",
            ))
            .unwrap();
            orch.submit_event(TrustEvent::positive(
                "b",
                TrustEventSource::HealthObservation,
                "ok",
            ))
            .unwrap();
            assert_eq!(orch.get_pending_count(), 2);

            orch.clear_pending();
            assert_eq!(orch.get_pending_count(), 0);
        }
    }

    // ── E. UnifiedTrustQuery (6 tests) ──────────────────────────────────

    mod test_unified_query {
        use super::*;

        #[test]
        fn test_compute_snapshot() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Seed engine.
            sync.sync_to_engine(&state, &mut engine);

            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);
            assert!(!snapshot.timestamp.is_empty());
            assert!(!snapshot.simple_domains.is_empty());
            assert!(snapshot.overall_simple > 0.0);
        }

        #[test]
        fn test_agreement_score_range() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            sync.sync_to_engine(&state, &mut engine);
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);

            assert!(
                snapshot.agreement_score >= 0.0 && snapshot.agreement_score <= 1.0,
                "agreement_score should be in [0, 1], got {:.4}",
                snapshot.agreement_score
            );
        }

        #[test]
        fn test_divergent_domains_filters() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Drive the engine's decision domain far from the simple state.
            for _ in 0..50 {
                engine.record_evidence("ananta_plane", "decision", false, 1.0, "stress");
            }

            sync.sync_to_engine(&state, &mut engine);
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);

            let divergent = snapshot.divergent_domains(0.1);
            // At minimum, decision should show some divergence.
            assert!(
                divergent.iter().any(|d| d.domain == "decision"),
                "decision should be in divergent domains"
            );
        }

        #[test]
        fn test_most_divergent_returns_highest() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Create strong divergence in one domain.
            for _ in 0..50 {
                engine.record_evidence("ananta_plane", "trust", false, 1.0, "heavy");
            }

            sync.sync_to_engine(&state, &mut engine);
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);

            let most = snapshot.most_divergent();
            assert!(most.is_some());
            let m = most.unwrap();
            // The most divergent should be >= all others.
            for d in &snapshot.divergence_report {
                assert!(m.divergence >= d.divergence - 1e-9);
            }
        }

        #[test]
        fn test_agreement_summary_does_not_panic() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);
            let summary = snapshot.agreement_summary();
            assert!(!summary.is_empty());
        }

        #[test]
        fn test_empty_state_snapshot() {
            let state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            // Don't seed the engine — it should handle empty gracefully.
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);
            assert!(!snapshot.simple_domains.is_empty());
            // Bayesian nodes may be empty but overall should be valid.
            assert!(snapshot.overall_simple >= 0.0);
        }
    }

    // ── F. Integration (6 tests) ─────────────────────────────────────────

    mod test_integration {
        use super::*;

        #[test]
        fn test_event_to_propagation_flow() {
            // End-to-end: event → converter → engine → propagation.
            let converter = EventToEvidenceConverter::new();
            let mut engine = BayesianTrustEngine::new();
            let _sync = TrustStateSynchronizer::new();

            let event = TrustEvent::negative(
                "decision",
                TrustEventSource::DriftAlert,
                "drift detected in ring-0",
            );

            let (from, to, evidence) = converter.convert(&event);
            engine.record_evidence(
                &from,
                &to,
                evidence.is_positive,
                evidence.weight,
                &evidence.source,
            );

            let result = engine.propagate();
            assert!(result.iterations > 0);
            assert!(result.node_trust.contains_key("decision"));
        }

        #[test]
        fn test_multi_domain_sync() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::new();

            // Set different levels for different domains.
            state.set_domain_level("decision", 0.3);
            state.set_domain_level("policy", 0.9);
            state.set_domain_level("trust", 0.1);

            let result = sync.sync_to_engine(&state, &mut engine);
            assert_eq!(result.domains_synced, state.domains.len());

            // Verify edges exist for the modified domains.
            assert!(
                engine.trust_score("ananta_plane", "decision").is_some(),
                "decision edge should exist"
            );
            assert!(
                engine.trust_score("ananta_plane", "policy").is_some(),
                "policy edge should exist"
            );
            assert!(
                engine.trust_score("ananta_plane", "trust").is_some(),
                "trust edge should exist"
            );
        }

        #[test]
        fn test_divergent_detection_integration() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::with_reconciliation_factor(0.0);
            let _converter = EventToEvidenceConverter::new();

            // Drive decision down in simple state.
            state.set_domain_level("decision", 0.1);

            // Seed engine with high trust for decision.
            for _ in 0..30 {
                engine.record_evidence("ananta_plane", "decision", true, 1.0, "positive");
            }

            // Sync (with 0 reconciliation so state stays at 0.1).
            sync.reconcile(&mut state, &mut engine);

            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);
            let divergent = snapshot.divergent_domains(0.1);
            assert!(
                divergent.iter().any(|d| d.domain == "decision"),
                "decision should diverge significantly"
            );
        }

        #[test]
        fn test_high_volume_events() {
            let mut orch = TrustPropagationOrchestrator::new();
            let mut engine = BayesianTrustEngine::new();
            let mut state = TrustState::new();

            // Submit 200 events.
            let domains = ["decision", "policy", "model", "orchestration", "trust"];
            for i in 0..200 {
                let domain = domains[i % domains.len()];
                let is_positive = i % 3 != 0; // 2/3 positive
                let event = TrustEvent::new(
                    if is_positive {
                        TrustEventSource::HealthObservation
                    } else {
                        TrustEventSource::DriftAlert
                    },
                    domain,
                    is_positive,
                    0.5,
                    &format!("event-{}", i),
                );
                orch.submit_event(event).unwrap();
            }

            let result = orch.run_propagation_cycle(&mut engine, &mut state);
            assert!(result.is_ok());
            let cycle = result.unwrap();
            assert_eq!(cycle.pending_result.events_processed, 200);
            assert_eq!(cycle.pending_result.evidence_added, 200);
            assert_eq!(orch.get_pending_count(), 0);
        }

        #[test]
        fn test_reconciliation_stability() {
            // Run multiple cycles and verify trust doesn't explode.
            let mut orch = TrustPropagationOrchestrator::with_reconciliation_factor(0.2);
            let mut engine = BayesianTrustEngine::new();
            let mut state = TrustState::new();

            for cycle in 0..10 {
                let is_positive = cycle % 2 == 0;
                orch.submit_event(TrustEvent::new(
                    TrustEventSource::HealthObservation,
                    "decision",
                    is_positive,
                    0.5,
                    &format!("cycle-{}", cycle),
                ))
                .unwrap();

                let result = orch.run_propagation_cycle(&mut engine, &mut state);
                assert!(
                    result.is_ok(),
                    "cycle {} should succeed: {:?}",
                    cycle,
                    result.err()
                );
            }

            // All levels should still be in [0, 1].
            for (domain, dt) in &state.domains {
                assert!(
                    dt.level >= 0.0 && dt.level <= 1.0,
                    "{} level out of range: {:.4}",
                    domain,
                    dt.level
                );
            }
        }

        #[test]
        fn test_full_ovaph_simulation() {
            // Simulate a complete OVAPH cycle with drift, integrity, and health events.
            let converter = EventToEvidenceConverter::new();
            let mut orch = TrustPropagationOrchestrator::new();
            let mut engine = BayesianTrustEngine::new();
            let mut state = TrustState::new();

            // 1. A drift alert fires.
            let drift_alert = DriftAlert {
                drift_type: DriftType::Decision,
                z_score: 4.2,
                current_mean: 0.85,
                current_stddev: 0.08,
                observed_value: 0.4,
                context: "ring-0-policy-v3".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: DriftAlertSeverity::Critical,
            };
            let drift_event = converter.convert_drift_alert(&drift_alert);
            orch.submit_event(drift_event).unwrap();

            // 2. An integrity check fails.
            let integrity_event = converter.convert_integrity_result(
                "configuration",
                false,
                "config file hash mismatch",
            );
            orch.submit_event(integrity_event).unwrap();

            // 3. Some health observations.
            let health_event = converter.convert_health_observation(
                "runtime",
                true,
                0.92,
                "all services responding",
            );
            orch.submit_event(health_event).unwrap();

            // 4. A recovery succeeds.
            let recovery_event = TrustEvent::positive(
                "decision",
                TrustEventSource::RecoveryResult,
                "drift corrected via policy rollback",
            );
            orch.submit_event(recovery_event).unwrap();

            // 5. Run the full cycle.
            let result = orch.run_propagation_cycle(&mut engine, &mut state);
            assert!(result.is_ok());
            let cycle = result.unwrap();

            assert_eq!(cycle.pending_result.events_processed, 4);
            assert_eq!(cycle.pending_result.evidence_added, 4);
            assert!(cycle.propagation_result.iterations > 0);

            // 6. Take a unified snapshot.
            let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);
            assert!(!snapshot.timestamp.is_empty());
            assert!(snapshot.agreement_score >= 0.0 && snapshot.agreement_score <= 1.0);

            let summary = snapshot.agreement_summary();
            assert!(!summary.is_empty());

            // Decision and configuration should show some impact.
            assert!(
                snapshot
                    .divergence_report
                    .iter()
                    .any(|d| d.domain == "decision"),
                "decision should be in divergence report"
            );
        }
    }

    // ── Additional edge-case tests ───────────────────────────────────────

    mod test_edge_cases {
        use super::*;

        #[test]
        fn test_weight_clamping_on_event_creation() {
            let event = TrustEvent::new(
                TrustEventSource::HealthObservation,
                "test",
                true,
                5.0, // Exceeds max
                "overweight",
            );
            assert!(
                event.weight <= 1.0,
                "weight should be clamped to 1.0, got {}",
                event.weight
            );
        }

        #[test]
        fn test_weight_clamping_zero() {
            let event = TrustEvent::new(
                TrustEventSource::HealthObservation,
                "test",
                true,
                0.0, // Below minimum
                "underweight",
            );
            assert!(
                event.weight >= 0.01,
                "weight should be clamped to 0.01, got {}",
                event.weight
            );
        }

        #[test]
        fn test_empty_pending_process() {
            let mut orch = TrustPropagationOrchestrator::new();
            let mut engine = BayesianTrustEngine::new();
            let result = orch.process_pending(&mut engine);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().events_processed, 0);
        }

        #[test]
        fn test_submit_events_partial_accept() {
            let mut orch = TrustPropagationOrchestrator {
                max_pending_events: 2,
                ..TrustPropagationOrchestrator::default()
            };

            let events = vec![
                TrustEvent::positive("a", TrustEventSource::HealthObservation, "ok"),
                TrustEvent::positive("b", TrustEventSource::HealthObservation, "ok"),
                TrustEvent::positive("c", TrustEventSource::HealthObservation, "ok"),
                TrustEvent::positive("d", TrustEventSource::HealthObservation, "ok"),
            ];

            let result = orch.submit_events(events);
            // Should accept 2 out of 4 (0 already pending + max 2).
            assert!(result.is_err());
        }

        #[test]
        fn test_sync_result_default() {
            let result = SyncResult::default();
            assert_eq!(result.domains_synced, 0);
            assert_eq!(result.evidence_added, 0);
            assert_eq!(result.propagation_iterations, 0);
            assert!(result.trust_changes.is_empty());
        }

        #[test]
        fn test_divergence_severity_classification() {
            assert_eq!(
                DivergenceSeverity::from_divergence(0.01),
                DivergenceSeverity::None
            );
            assert_eq!(
                DivergenceSeverity::from_divergence(0.10),
                DivergenceSeverity::Low
            );
            assert_eq!(
                DivergenceSeverity::from_divergence(0.20),
                DivergenceSeverity::Medium
            );
            assert_eq!(
                DivergenceSeverity::from_divergence(0.40),
                DivergenceSeverity::High
            );
            assert_eq!(
                DivergenceSeverity::from_divergence(0.60),
                DivergenceSeverity::Critical
            );
        }

        #[test]
        fn test_serialization_round_trip() {
            let event = TrustEvent::new(
                TrustEventSource::DriftAlert,
                "decision",
                false,
                0.75,
                "serialization test",
            );
            let json = serde_json::to_string(&event)
                .map_err(|e| e.to_string())
                .unwrap();
            let deserialized: TrustEvent = serde_json::from_str(&json)
                .map_err(|e| e.to_string())
                .unwrap();
            assert_eq!(deserialized.event_id, event.event_id);
            assert_eq!(deserialized.domain, event.domain);
            assert_eq!(deserialized.source, event.source);
        }

        #[test]
        fn test_convert_health_observation_weight_scaling() {
            let converter = EventToEvidenceConverter::new();

            // High health score (far from neutral) should have higher weight.
            let high = converter.convert_health_observation("test", true, 0.95, "excellent");
            let low = converter.convert_health_observation("test", true, 0.6, "marginal");

            assert!(
                high.weight > low.weight,
                "high health ({:.3}) should have more weight ({:.3}) than marginal ({:.3})",
                0.95,
                high.weight,
                low.weight
            );
        }

        #[test]
        fn test_drift_alert_severity_scaling() {
            let converter = EventToEvidenceConverter::new();

            let critical = DriftAlert {
                drift_type: DriftType::Policy,
                z_score: 5.0,
                current_mean: 0.8,
                current_stddev: 0.1,
                observed_value: 0.2,
                context: "test".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: DriftAlertSeverity::Critical,
            };

            let info = DriftAlert {
                drift_type: DriftType::Policy,
                z_score: 2.5,
                current_mean: 0.8,
                current_stddev: 0.1,
                observed_value: 0.5,
                context: "test".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: DriftAlertSeverity::Info,
            };

            let crit_event = converter.convert_drift_alert(&critical);
            let info_event = converter.convert_drift_alert(&info);

            assert!(
                crit_event.weight > info_event.weight,
                "critical drift should have higher weight than info"
            );
        }

        #[test]
        fn test_reconciliation_factor_zero_keeps_simple() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::with_reconciliation_factor(0.0);

            state.set_domain_level("decision", 0.3);

            // Add lots of positive evidence.
            for _ in 0..50 {
                engine.record_evidence("ananta_plane", "decision", true, 1.0, "positive");
            }

            sync.reconcile(&mut state, &mut engine);

            // With factor 0.0, decision should stay at 0.3.
            let level = state.domain_level("decision");
            assert!(
                (level - 0.3).abs() < 1e-9,
                "with factor 0.0, level should stay at 0.3, got {:.4}",
                level
            );
        }

        #[test]
        fn test_reconciliation_factor_one_uses_bayesian() {
            let mut state = TrustState::new();
            let mut engine = BayesianTrustEngine::new();
            let sync = TrustStateSynchronizer::with_reconciliation_factor(1.0);

            state.set_domain_level("decision", 0.9);

            // Add lots of negative evidence.
            for _ in 0..50 {
                engine.record_evidence("ananta_plane", "decision", false, 1.0, "negative");
            }

            sync.reconcile(&mut state, &mut engine);

            // With factor 1.0, decision should move toward the Bayesian posterior (low).
            let level = state.domain_level("decision");
            assert!(
                level < 0.8,
                "with factor 1.0, level should drop significantly, got {:.4}",
                level
            );
        }
    }
}
