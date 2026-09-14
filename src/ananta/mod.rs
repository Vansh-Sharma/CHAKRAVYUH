// ═══════════════════════════════════════════════════════════════
// ANANTA — Autonomous Trust Plane
//
// "The protector of the protector."
//
// ANANTA is NOT a ring. It is a supervisory plane that exists
// above and outside the 9 defense rings and Keshav Core.
//
// It answers: "Can the security system itself still be trusted?"
//
// Subsystems:
//   1. Crypto       — hashing, signing, Merkle trees, encryption
//   2. Anchor       — root of trust, attestation, manifest, keys
//   3. Trust        — trust engine, trust graph, trust proofs
//   4. Sentinel     — continuous integrity verification, drift detection
//   5. Phoenix      — autonomous recovery intelligence
//   6. Adapter      — adaptive security orchestration
//   7. Health       — platform-wide health graph
//   8. Audit        — immutable audit log
//   9. Simulation   — security twin, attack/recovery simulators
//  10. Distributed  — consensus, quorum, federation
//  11. Runtime      — component status, resource tracking
//  12. Scheduler    — background task scheduling with jitter
//  13. State        — snapshots, diffing, versioning
//
// CRITICAL DESIGN CONSTRAINTS:
//   - ANANTA never depends on Keshav (no circular dependency)
//   - ANANTA has its own config file (ananta.yaml)
//   - ANANTA's hot-path impact is ZERO (background tasks only)
//   - ANANTA is optional (system works without it in degraded mode)
//
// Background loops (all independent, all zero hot-path impact):
//   Loop 1: Attestation   — periodic integrity checks → signed report → trust chain
//   Loop 2: Trust Proof   — cryptographic proof of platform trust
//   Loop 3: Sentinel      — 10-type drift detection → trust state updates
//   Loop 4: Phoenix       — autonomous recovery when trust degrades
//   Loop 5: Health        — DAG health graph + anomaly prediction
//   Loop 6: Adapter       — adaptive pipeline reconfiguration (opt-in)
//
// ═══════════════════════════════════════════════════════════════

pub mod config;
pub mod config_validator;
pub mod crypto;
pub mod anchor;
pub mod trust;
pub mod sentinel;
pub mod phoenix;
pub mod adapter;
pub mod health;
pub mod audit;
pub mod simulation;
pub mod distributed;
pub mod runtime;
pub mod scheduler;
pub mod state;
pub mod ovaph_loop;
#[cfg(test)]
pub mod integration_tests;
#[cfg(test)]
pub mod benchmarks;

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};

use serde::{Deserialize, Serialize};

/// Canonical trend direction used across all ANANTA subsystems.
///
/// Unifies the various `TrendDirection` enums that were previously
/// defined independently in health, trust, sentinel, and validation modules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// Values are improving over time.
    Improving,
    /// Values are relatively stable.
    Stable,
    /// Values are degrading over time.
    Degrading,
    /// Insufficient data to determine a trend.
    Unknown,
}

use anchor::{IntegrityChecker, KeyManager, Manifest, SecureStore, TrustChain};
use sentinel::drift::{DriftDetector, DriftObservation};
use sentinel::TrustStateUpdater;
use phoenix::planner::RecoveryPlanner;
use phoenix::RecoveryHistory;
use health::HealthGraph;
use audit::{AuditLog, AuditCategory, AuditSeverity};
use adapter::Adapter;
use trust::trust_proof::TrustProof;


// Re-export key types for external use.
pub use config::AnantaConfig;
pub use anchor::AttestationReport;
pub use trust::TrustState;
pub use sentinel::drift::{DriftType, DriftAlert};
pub use phoenix::strategies::{RecoveryAction, RecoveryStrategy, RecoveryResult};
pub use health::{HealthGraph as AnantaHealthGraph, HealthStatus, AnomalyPrediction};
pub use audit::AuditLog as AnantaAuditLog;
pub use ovaph_loop::{OvaphLoop, OvaphConfig, OvaphCycleReport};

/// The ANANTA Autonomous Trust Plane.
///
/// This is the top-level orchestrator that owns ALL subsystems.
/// It is created at startup, runs 6 independent background loops,
/// and provides trust state / attestation / proof APIs.
///
/// Architecture:
///   AnantaPlane owns all subsystem state behind Arc<RwLock<>>.
///   Each background loop is an independent tokio::spawn task.
///   Loops communicate through shared trust_state and audit log.
///   Zero hot-path impact — all work is async background.
pub struct AnantaPlane {
    config: AnantaConfig,

    // ── Anchor: Root of Trust ──
    manifest: Arc<RwLock<Manifest>>,
    key_manager: Arc<RwLock<KeyManager>>,
    integrity_checker: Arc<RwLock<IntegrityChecker>>,
    secure_store: Arc<RwLock<SecureStore>>,

    // ── Trust Engine ──
    trust_state: Arc<RwLock<TrustState>>,

    // ── Trust Chains (append-only, tamper-evident) ──
    attestation_chain: Arc<RwLock<TrustChain>>,
    recovery_chain: Arc<RwLock<TrustChain>>,

    // ── Sentinel: Drift Detection ──
    drift_detector: Arc<Mutex<DriftDetector>>,
    trust_state_updater: TrustStateUpdater,

    // ── Phoenix: Recovery ──
    recovery_planner: Arc<Mutex<RecoveryPlanner>>,
    recovery_history: Arc<Mutex<RecoveryHistory>>,

    // ── Health: Platform Health Graph ──
    health_graph: Arc<Mutex<HealthGraph>>,

    // ── Audit: Immutable Log ──
    audit_log: Arc<Mutex<AuditLog>>,

    // ── Adapter: Adaptive Orchestration ──
    adapter: Arc<Mutex<Adapter>>,

    // ── Attestation State ──
    latest_attestation: Arc<RwLock<Option<AttestationReport>>>,
    latest_trust_proof: Arc<RwLock<Option<TrustProof>>>,
    consecutive_passes: Arc<std::sync::atomic::AtomicU64>,
    consecutive_failures: Arc<std::sync::atomic::AtomicU64>,

    // ── OVAPH Loop (Phase B) ──
    ovaph_loop: Arc<Mutex<OvaphLoop>>,
    latest_ovaph_report: Arc<RwLock<Option<OvaphCycleReport>>>,

    // ── Lifecycle ──
    shutdown: Arc<tokio::sync::Notify>,
    /// Set to true once start() has been called.
    started: Arc<std::sync::atomic::AtomicBool>,
}

impl AnantaPlane {
    // ── Construction ──

    /// Create and initialize ANANTA.
    ///
    /// This does NOT start background tasks. Call `start()` separately.
    /// All subsystems are initialized but dormant.
    pub fn new(config: AnantaConfig) -> Result<Self, String> {
        // Validate config — warnings only, never fatal.
        let warnings = config.validate();
        for w in &warnings {
            tracing::warn!(
                field = %w.field,
                severity = ?w.severity,
                message = %w.message,
                "ananta config warning"
            );
        }

        // ── Initialize Anchor subsystem ──
        let manifest = Arc::new(RwLock::new(Manifest::new(config.crypto.hash_algorithm.clone())));
        let key_manager = Arc::new(RwLock::new(KeyManager::new("ananta-boot-key")));
        let integrity_checker = Arc::new(RwLock::new(
            IntegrityChecker::new(config.crypto.hash_algorithm.clone()),
        ));
        let secure_store = Arc::new(RwLock::new(
            SecureStore::new("ananta-secure", &config.state_path)?,
        ));

        // ── Initialize Trust subsystem ──
        let trust_state = Arc::new(RwLock::new(TrustState::new()));

        // ── Initialize Trust Chains ──
        let attestation_chain = Arc::new(RwLock::new(
            TrustChain::new(config.crypto.hash_algorithm.clone()),
        ));
        let recovery_chain = Arc::new(RwLock::new(
            TrustChain::new(config.crypto.hash_algorithm.clone()),
        ));

        // ── Initialize Sentinel ──
        let drift_detector = Arc::new(Mutex::new(DriftDetector::new(
            config.sentinel.drift_sigma_threshold,
            config.sentinel.drift_window_size,
        )));
        let trust_state_updater = TrustStateUpdater::new();

        // ── Initialize Phoenix ──
        let recovery_planner = Arc::new(Mutex::new(RecoveryPlanner::new(config.phoenix.clone())));
        let recovery_history = Arc::new(Mutex::new(
            RecoveryHistory::new(config.crypto.hash_algorithm.clone()),
        ));

        // ── Initialize Health ──
        let health_graph = Arc::new(Mutex::new(HealthGraph::new(config.health.clone())));

        // ── Initialize Audit ──
        let audit_log = Arc::new(Mutex::new(AuditLog::new(
            config.audit.clone(),
            config.crypto.hash_algorithm.clone(),
        )));

        // ── Initialize Adapter ──
        let adapter = Arc::new(Mutex::new(Adapter::new(config.adapter.clone())));

        // ── Initialize OVAPH Loop (Phase B) ──
        let ovaph_config = OvaphConfig {
            enabled: config.enabled,
            heal_autonomous: config.phoenix.autonomous,
            ..OvaphConfig::default()
        };
        let ovaph_loop = Arc::new(Mutex::new(OvaphLoop::new(ovaph_config)));

        Ok(Self {
            config,
            manifest,
            key_manager,
            integrity_checker,
            secure_store,
            trust_state,
            attestation_chain,
            recovery_chain,
            drift_detector,
            trust_state_updater,
            recovery_planner,
            recovery_history,
            health_graph,
            audit_log,
            adapter,
            latest_attestation: Arc::new(RwLock::new(None)),
            latest_trust_proof: Arc::new(RwLock::new(None)),
            consecutive_passes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            consecutive_failures: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ovaph_loop,
            latest_ovaph_report: Arc::new(RwLock::new(None)),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    // ── Public Query API ──

    /// Get the current trust state snapshot.
    pub async fn trust_state(&self) -> TrustState {
        self.trust_state.read().await.clone()
    }

    /// Get the latest attestation report.
    pub async fn latest_attestation(&self) -> Option<AttestationReport> {
        self.latest_attestation.read().await.clone()
    }

    /// Get the latest trust proof.
    pub async fn latest_trust_proof(&self) -> Option<TrustProof> {
        self.latest_trust_proof.read().await.clone()
    }

    /// Get overall platform health score.
    pub async fn overall_health(&self) -> f64 {
        let graph = self.health_graph.lock().await;
        graph.overall_health()
    }

    /// Get trust state summary string.
    pub async fn trust_summary(&self) -> String {
        let state = self.trust_state.read().await;
        state.summary()
    }

    /// Get consecutive attestation pass count.
    pub fn consecutive_passes(&self) -> u64 {
        self.consecutive_passes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get consecutive attestation failure count.
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the latest OVAPH cycle report.
    pub async fn latest_ovaph_report(&self) -> Option<OvaphCycleReport> {
        self.latest_ovaph_report.read().await.clone()
    }

    /// Get OVAPH loop metrics.
    pub async fn ovaph_metrics(&self) -> ovaph_loop::OvaphMetrics {
        let loop_ = self.ovaph_loop.lock().await;
        loop_.metrics().clone().expect("ovaph metrics should be available")
    }

    /// Run a single OVAPH cycle (Observe → Verify → Attest → Heal → Prove).
    ///
    /// This is the Phase B unified trust verification loop. It collects
    /// observations from all subsystems, runs verification, generates
    /// attestation, triggers healing if needed, and produces a trust proof.
    pub async fn run_ovaph_cycle(&self) -> Result<OvaphCycleReport, String> {
        let cycle_start = std::time::Instant::now();
        let trust_before = {
            let state = self.trust_state.read().await;
            state.overall_score()
        };

        // ── Stage O: Observe ──
        let observation = ovaph_loop::OvaphObservation::new();
        let mut observation = observation;
        {
            let mut obs_builder = observation;
            // Collect drift stats for all types.
            let detector = self.drift_detector.lock().await;
            for dt in DriftType::all() {
                if let Some((mean, stddev, count)) = detector.stats(dt) {
                    let snapshot = ovaph_loop::DriftSnapshot {
                        drift_type: format!("{:?}", dt),
                        current_mean: mean,
                        current_stddev: stddev,
                        sample_count: count as u64,
                        last_z_score: 0.0, // Not directly available from stats.
                    };
                    obs_builder.drift_snapshots.push(snapshot);
                }
            }
            observation = obs_builder;
        }
        // Collect health.
        {
            let graph = self.health_graph.lock().await;
            let overall = graph.overall_health();
            let health_snap = ovaph_loop::HealthSnapshot::new(overall);
            // Count degraded/failed.
            let mut degraded = 0u32;
            let mut failed = 0u32;
            // (HealthGraph doesn't expose per-component iteration in the simple API,
            //  so we use the overall score and note 0 for component counts here.)
            let _ = (&mut degraded, &mut failed); // acknowledge
            observation.health_snapshot = health_snap;
        }

        // ── Stage V: Verify ──
        let verification = {
            let loop_ = self.ovaph_loop.lock().await;
            let (_, v) = loop_.run_verify(&observation).await;
            v
        };

        // ── Stage A: Attest ──
        let attestation_result = match self.run_attestation_cycle().await {
            Ok(report) => ovaph_loop::OvaphAttestationResult {
                attestation_passed: report.integrity.passed,
                trust_level: report.trust_level,
                failed_components: report.integrity.failed_components().into_iter().map(|s| s.to_string()).collect(),
                attestation_id: uuid::Uuid::new_v4().to_string(),
                chain_length_after: self.attestation_chain.read().await.len() as u64,
            },
            Err(e) => {
                tracing::error!(error = %e, "OVAPH attestation stage failed");
                ovaph_loop::OvaphAttestationResult::failed(&e)
            }
        };

        // ── Stage H: Heal ──
        let healing_result = {
            let loop_ = self.ovaph_loop.lock().await;
            let (_, h) = loop_.run_heal(&verification).await;
            h
        };

        // ── Stage P: Prove ──
        let proof_result = match self.run_trust_proof_generation().await {
            Ok(proof) => ovaph_loop::OvaphProofResult {
                proof_generated: true,
                trust_score: proof.trust_score,
                proof_id: Some(proof.proof_id),
                all_domains_passed: proof.all_passed,
                chain_verified: self.attestation_chain.read().await.verify().is_none(),
            },
            Err(_) => ovaph_loop::OvaphProofResult {
                proof_generated: false,
                trust_score: 0.0,
                proof_id: None,
                all_domains_passed: false,
                chain_verified: false,
            },
        };

        // ── Assemble cycle report ──
        let trust_after = {
            let state = self.trust_state.read().await;
            state.overall_score()
        };

        let observation_stage = ovaph_loop::StageResult::completed(
            ovaph_loop::OvaphStage::Observe,
            cycle_start.elapsed().as_millis() as u64,
            observation.drift_snapshots.len(),
        );
        let verify_stage = ovaph_loop::StageResult::completed(
            ovaph_loop::OvaphStage::Verify,
            0,
            verification.signals.len(),
        );
        let attest_stage = ovaph_loop::StageResult::completed(
            ovaph_loop::OvaphStage::Attest,
            0,
            if attestation_result.attestation_passed { 1 } else { 0 },
        );
        let heal_stage = ovaph_loop::StageResult::completed(
            ovaph_loop::OvaphStage::Heal,
            0,
            healing_result.actions_executed,
        );
        let prove_stage = ovaph_loop::StageResult::completed(
            ovaph_loop::OvaphStage::Prove,
            0,
            if proof_result.proof_generated { 1 } else { 0 },
        );
        let stages = vec![observation_stage, verify_stage, attest_stage, heal_stage, prove_stage];
        let total_duration_ms = std::cmp::max(1, cycle_start.elapsed().as_millis() as u64);

        let report = OvaphCycleReport {
            cycle_id: ovaph_loop::OvaphCycleId {
                cycle_number: 0,
                started_at: chrono::Utc::now().to_rfc3339(),
                cycle_id: uuid::Uuid::new_v4().to_string(),
            },
            cycle_number: 0, // Will be set by the loop internally.
            stages,
            total_duration_ms,
            trust_before,
            trust_after,
            recovery_actions_taken: healing_result.actions_executed,
            attestation_passed: attestation_result.attestation_passed,
            trust_proof_generated: proof_result.proof_generated,
            overall_outcome: ovaph_loop::CycleOutcome::AllCompleted,
        };

        // Record cycle in OVAPH loop metrics.
        {
            let mut loop_ = self.ovaph_loop.lock().await;
            // Access the internal metrics mutex directly to record this cycle.
            if let Ok(mut metrics_guard) = loop_.metrics_lock() {
                metrics_guard.record_cycle(&report);
            };
        }

        // Store latest report.
        {
            let mut latest = self.latest_ovaph_report.write().await;
            *latest = Some(report.clone());
        }

        // Audit the OVAPH cycle.
        {
            let mut log = self.audit_log.lock().await;
            log.append(
                AuditCategory::Lifecycle,
                if attestation_result.attestation_passed { AuditSeverity::Info } else { AuditSeverity::Warning },
                &format!(
                    "OVAPH cycle complete: trust={:.3}→{:.3} attest={} heal_actions={} proof={}",
                    trust_before, trust_after,
                    attestation_result.attestation_passed,
                    healing_result.actions_executed,
                    proof_result.proof_generated,
                ),
            );
        }

        tracing::info!(
            trust_before = %trust_before,
            trust_after = %trust_after,
            attest = attestation_result.attestation_passed,
            heal_actions = healing_result.actions_executed,
            proof = proof_result.proof_generated,
            "OVAPH cycle complete"
        );

        Ok(report)
    }

    // ── Integrity Provider Registration ──

    /// Register an integrity data provider for a domain.
    ///
    /// Call this BEFORE `start()`. The provider is a function that
    /// returns the current state bytes to hash and compare against
    /// the manifest.
    ///
    /// Example domains: Binary, Config, Policy, AnantaConfig, RingConfig("shield")
    pub async fn register_integrity_provider(
        &self,
        domain: anchor::integrity::IntegrityDomain,
        provider: impl Fn() -> Vec<u8> + 'static + Send + Sync,
    ) {
        let mut checker = self.integrity_checker.write().await;
        let domain_display = domain.clone();
        checker.register_provider(domain, provider);
        tracing::debug!(domain = %domain_display, "integrity provider registered");
    }

    /// Add a trusted hash to the manifest.
    ///
    /// This is how the system records what "trusted" looks like.
    /// ANANTA will then verify live data against these hashes.
    pub async fn add_manifest_entry(&self, key: &str, data: &[u8]) {
        use crate::ananta::crypto::hashing::hash_bytes;
        let mut manifest = self.manifest.write().await;
        let digest = hash_bytes(data, &self.config.crypto.hash_algorithm);
        let hex = digest.hex.clone();
        manifest.insert(key.to_string(), digest);
        tracing::debug!(key = %key, hash = %hex, "manifest entry added");
    }

    // ── Drift Observation Feed ──

    /// Feed an observation into the drift detector.
    ///
    /// This is how rings / Keshav report metrics to ANANTA.
    /// For example, Keshav reports the decision allow/deny ratio,
    /// each ring reports its latency, etc.
    pub async fn observe_drift(&self, observation: DriftObservation) {
        let mut detector = self.drift_detector.lock().await;
        if let Some(alert) = detector.observe(observation) {
            drop(detector);
            // Process the alert: update trust state + audit.
            self.handle_drift_alert(alert).await;
        }
    }

    /// Feed a health observation for a component.
    pub async fn observe_health(&self, obs: health::HealthObservation) {
        let mut graph = self.health_graph.lock().await;
        graph.observe(obs);
    }

    /// Add a dependency edge to the health graph.
    pub async fn add_health_dependency(&self, from: &str, to: &str, weight: f64) {
        let mut graph = self.health_graph.lock().await;
        graph.add_dependency(from, to, weight);
    }

    // ── Core Loop Implementations ──

    /// Run a single attestation cycle: integrity check → signed report → trust chain.
    async fn run_attestation_cycle(&self) -> Result<AttestationReport, String> {
        // 1. Snapshot integrity against manifest.
        let manifest = self.manifest.read().await;
        let checker = self.integrity_checker.read().await;
        let snapshot = checker.snapshot(&manifest);
        drop(manifest);
        drop(checker);

        let passes = self.consecutive_passes.load(std::sync::atomic::Ordering::Relaxed);
        let failures = self.consecutive_failures.load(std::sync::atomic::Ordering::Relaxed);

        // 2. Build attestation report.
        let mut report = AttestationReport::from_snapshot(snapshot, passes, failures);

        // 3. Sign the attestation.
        {
            let km = self.key_manager.read().await;
            if let Some(key) = km.get_key(&anchor::KeyPurpose::Attestation) {
                report.sign(key);
            }
        }

        // 4. Update consecutive counters.
        if report.integrity.passed {
            self.consecutive_passes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.consecutive_failures.store(0, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.consecutive_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.consecutive_passes.store(0, std::sync::atomic::Ordering::Relaxed);
        }

        // 5. Store latest report.
        {
            let mut latest = self.latest_attestation.write().await;
            *latest = Some(report.clone());
        }

        // 6. Append to attestation trust chain.
        {
            let mut chain = self.attestation_chain.write().await;
            chain.append(
                "attestation",
                serde_json::json!({
                    "trust_level": report.trust_level,
                    "passed": report.integrity.passed,
                    "merkle_root": report.integrity.merkle_root.hex,
                    "failed_components": report.integrity.failed_components(),
                }),
            );
        }

        // 7. Update trust state from integrity results.
        {
            let mut state = self.trust_state.write().await;
            for result in &report.integrity.results {
                if !result.passed {
                    // Integrity failure → reduce trust for that component's domain.
                    let domain = self.component_to_trust_domain(&result.component);
                    let current = state.domain_level(domain);
                    let new_level = (current - 0.15).max(0.0);
                    state.set_domain_level(domain, new_level);

                    state.add_alert(trust::trust_state::TrustAlert {
                        alert_type: trust::trust_state::AlertType::IntegrityFailure,
                        domain: domain.to_string(),
                        message: format!(
                            "integrity check failed: {} (expected={}, actual={})",
                            result.component,
                            result.expected.as_ref().map(|e| &e.hex[..12]).unwrap_or("none"),
                            &result.actual.hex[..12],
                        ),
                        severity: trust::trust_state::AlertSeverity::Critical,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        data: None,
                    });
                }
            }
            state.record_cycle();
        }

        // 8. Audit the attestation.
        {
            let mut log = self.audit_log.lock().await;
            let severity = if report.integrity.passed {
                AuditSeverity::Info
            } else {
                AuditSeverity::Error
            };
            log.append(
                AuditCategory::Integrity,
                severity,
                &format!(
                    "attestation cycle: trust={:.3} passed={} failed={}",
                    report.trust_level,
                    report.integrity.passed,
                    report.integrity.failed_count,
                ),
            );
        }

        // 9. Update health graph from integrity results.
        {
            let mut graph = self.health_graph.lock().await;
            for result in &report.integrity.results {
                let status = if result.passed {
                    health::HealthStatus::Healthy
                } else {
                    health::HealthStatus::Failed
                };
                let mut obs = health::HealthObservation::new(&result.component, status);
                obs.score = if result.passed { 1.0 } else { 0.0 };
                graph.observe(obs);
            }
        }

        tracing::info!(
            trust = %report.trust_level,
            passed = report.integrity.passed,
            domains = report.integrity.results.len(),
            "{}",
            report.summary(),
        );

        Ok(report)
    }

    /// Generate a Trust Proof — the cryptographic evidence of platform trust.
    async fn run_trust_proof_generation(&self) -> Result<TrustProof, String> {
        let state = self.trust_state.read().await;
        let attestation = self.latest_attestation.read().await;
        let attestation_chain = self.attestation_chain.read().await;

        // TrustProof::generate requires attestation + key_pair.
        // If no attestation yet, skip.
        let attestation = match attestation.as_ref() {
            Some(a) => a,
            None => return Err("no attestation available for trust proof".into()),
        };

        // Get the signing key.
        let key_pair = {
            let km = self.key_manager.read().await;
            match km.get_key(&anchor::KeyPurpose::Attestation) {
                Some(kp) => kp.clone(),
                None => return Err("no attestation key available".into()),
            }
        };

        let chain_head = attestation_chain.latest()
            .map(|l| l.hash.clone())
            .unwrap_or_default();

        let proof = TrustProof::generate(
            attestation,
            &state,
            &chain_head,
            &key_pair,
        );

        // Store.
        {
            let mut latest = self.latest_trust_proof.write().await;
            *latest = Some(proof.clone());
        }

        // Audit.
        {
            let mut log = self.audit_log.lock().await;
            log.append(
                AuditCategory::Trust,
                AuditSeverity::Info,
                &format!(
                    "trust proof generated: score={:.3} all_passed={} proof_id={}",
                    proof.trust_score,
                    proof.all_passed,
                    proof.proof_id,
                ),
            );
        }

        tracing::debug!(
            proof_id = %proof.proof_id,
            score = %proof.trust_score,
            "trust proof generated"
        );

        Ok(proof)
    }

    /// Run a single drift detection cycle.
    ///
    /// This doesn't feed observations — those come from `observe_drift()`.
    /// Instead, it:
    ///   1. Applies recovery to trust state (if no alerts recently)
    ///   2. Records the trust state cycle
    async fn run_drift_cycle(&self) {
        // Apply trust recovery when no alerts are firing.
        {
            let mut state = self.trust_state.write().await;
            self.trust_state_updater.apply_recovery(&mut state);
        }
    }

    /// Handle a drift alert: update trust state, audit, and trigger Phoenix if needed.
    async fn handle_drift_alert(&self, alert: sentinel::drift::DriftAlert) {
        tracing::warn!(
            drift_type = %alert.drift_type,
            z_score = %alert.z_score,
            context = %alert.context,
            "drift detected"
        );

        // 1. Update trust state from drift alert.
        {
            let mut state = self.trust_state.write().await;
            self.trust_state_updater.process_alert(&mut state, &alert);
        }

        // 2. Audit the drift.
        {
            let mut log = self.audit_log.lock().await;
            let mut data = std::collections::HashMap::new();
            data.insert("z_score".into(), serde_json::json!(alert.z_score));
            data.insert("drift_type".into(), serde_json::json!(format!("{}", alert.drift_type)));
            data.insert("observed".into(), serde_json::json!(alert.observed_value));
            data.insert("mean".into(), serde_json::json!(alert.current_mean));

            let severity = match alert.severity {
                sentinel::drift::AlertSeverity::Info => AuditSeverity::Info,
                sentinel::drift::AlertSeverity::Warning => AuditSeverity::Warning,
                sentinel::drift::AlertSeverity::Critical => AuditSeverity::Critical,
            };

            log.append_with_data(
                AuditCategory::Drift,
                severity,
                &alert.summary(),
                data,
            );
        }

        // 3. Update health graph from drift.
        {
            let mut graph = self.health_graph.lock().await;
            let status = match alert.severity {
                sentinel::drift::AlertSeverity::Info => health::HealthStatus::Degraded,
                sentinel::drift::AlertSeverity::Warning => health::HealthStatus::Unhealthy,
                sentinel::drift::AlertSeverity::Critical => health::HealthStatus::Failed,
            };
            let mut obs = health::HealthObservation::new(
                &format!("drift:{}", alert.drift_type),
                status,
            );
            obs.score = (1.0 - (alert.z_score.abs() / 20.0)).max(0.0);
            graph.observe(obs);
        }

        // 4. Trigger Phoenix recovery if autonomous mode is on.
        if self.config.phoenix.autonomous {
            self.trigger_phoenix_recovery(&alert).await;
        }
    }

    /// Trigger Phoenix recovery planning for a drift alert.
    async fn trigger_phoenix_recovery(&self, alert: &sentinel::drift::DriftAlert) {
        let domain = self.drift_type_to_domain(&alert.drift_type);
        let trust_level = {
            let state = self.trust_state.read().await;
            state.domain_level(domain)
        };
        let failures = self.consecutive_failures.load(std::sync::atomic::Ordering::Relaxed);

        let plan = {
            let mut planner = self.recovery_planner.lock().await;
            let history = self.recovery_history.lock().await;
            planner.plan(domain, trust_level, alert.z_score, failures, &history)
        };

        if plan.actions.is_empty() {
            tracing::debug!(
                domain = %domain,
                rationale = %plan.rationale,
                "phoenix: no action needed"
            );
            return;
        }

        tracing::warn!(
            domain = %domain,
            actions = plan.actions.len(),
            rationale = %plan.rationale,
            "phoenix: recovery plan generated"
        );

        // Audit the recovery plan.
        {
            let mut log = self.audit_log.lock().await;
            log.append(
                AuditCategory::Recovery,
                AuditSeverity::Warning,
                &format!(
                    "recovery plan: domain={} actions={} rationale={}",
                    domain,
                    plan.actions.len(),
                    plan.rationale,
                ),
            );
        }

        // Execute planned actions and record results.
        for planned in &plan.actions {
            let result = self.execute_recovery_action(&planned.action).await;

            // Record in recovery history.
            {
                let mut history = self.recovery_history.lock().await;
                history.record(&planned.action, &result);
            }

            // Append to recovery trust chain.
            {
                let mut chain = self.recovery_chain.write().await;
                chain.append(
                    &format!("recovery:{:?}", planned.action.strategy),
                    serde_json::json!({
                        "action_id": planned.action.action_id,
                        "strategy": format!("{}", planned.action.strategy),
                        "target": planned.action.target,
                        "outcome": format!("{}", result.outcome),
                        "confidence": planned.action.confidence,
                    }),
                );
            }

            // Audit the result.
            {
                let mut log = self.audit_log.lock().await;
                let sev = match result.outcome {
                    phoenix::RecoveryOutcome::Success => AuditSeverity::Info,
                    phoenix::RecoveryOutcome::Failed => AuditSeverity::Error,
                    phoenix::RecoveryOutcome::Escalated => AuditSeverity::Critical,
                    phoenix::RecoveryOutcome::Skipped => AuditSeverity::Info,
                };
                log.append(
                    AuditCategory::Recovery,
                    sev,
                    &format!(
                        "recovery executed: strategy={:?} target={} outcome={}",
                        result.action.strategy,
                        result.action.target,
                        result.outcome,
                    ),
                );
            }
        }
    }

    /// Execute a single recovery action.
    ///
    /// In a full implementation, this would interface with the
    /// actual ring/subsystem lifecycle. For now, it simulates the
    /// action and records the result.
    async fn execute_recovery_action(&self, action: &RecoveryAction) -> RecoveryResult {
        let start = std::time::Instant::now();

        tracing::info!(
            strategy = %action.strategy,
            target = %action.target,
            confidence = %action.confidence,
            "executing recovery action"
        );

        // Simulate recovery execution.
        // In production, this would:
        //   - Restart: send SIGTERM/SIGKILL to the ring process
        //   - Rollback: reload config/policy from last-known-good
        //   - Quarantine: update routing to skip the component
        //   - Escalate: send alert to operations channel
        //   - ReloadPolicy: re-read policy file
        //   - ResetThresholds: reset KeshavLearn state
        match action.strategy {
            RecoveryStrategy::Escalate => {
                RecoveryResult::failed(
                    action.clone(),
                    "escalated to human operator — awaiting response",
                    start.elapsed().as_secs_f64() * 1000.0,
                )
            }
            RecoveryStrategy::Observe => {
                RecoveryResult::success(
                    action.clone(),
                    "observation mode — monitoring frequency increased",
                    start.elapsed().as_secs_f64() * 1000.0,
                )
            }
            _ => {
                // Simulate success with probability based on confidence.
                if rand::random::<f64>() < action.confidence {
                    RecoveryResult::success(
                        action.clone(),
                        &format!("{:?} completed for {}", action.strategy, action.target),
                        start.elapsed().as_secs_f64() * 1000.0,
                    )
                } else {
                    RecoveryResult::failed(
                        action.clone(),
                        &format!("{:?} failed for {}", action.strategy, action.target),
                        start.elapsed().as_secs_f64() * 1000.0,
                    )
                }
            }
        }
    }

    /// Run a single health graph cycle: predict anomalies + audit.
    async fn run_health_cycle(&self) {
        let predictions = {
            let graph = self.health_graph.lock().await;
            graph.predict_anomalies()
        };

        if !predictions.is_empty() {
            for pred in &predictions {
                tracing::warn!(
                    component = %pred.component,
                    predicted_status = %pred.predicted_status,
                    confidence = %pred.confidence,
                    reason = %pred.reason,
                    "anomaly predicted"
                );

                // Audit prediction.
                let mut log = self.audit_log.lock().await;
                log.append(
                    AuditCategory::Health,
                    AuditSeverity::Warning,
                    &format!(
                        "anomaly predicted: component={} status={} confidence={:.2} reason={}",
                        pred.component, pred.predicted_status, pred.confidence, pred.reason,
                    ),
                );
            }
        }

        // Update trust state from health graph.
        {
            let graph = self.health_graph.lock().await;
            let overall = graph.overall_health();
            let mut state = self.trust_state.write().await;
            // Health contributes to the runtime domain trust.
            let current_runtime = state.domain_level("runtime");
            let new_runtime = (current_runtime * 0.7 + overall * 0.3).clamp(0.0, 1.0);
            state.set_domain_level("runtime", new_runtime);
        }
    }

    /// Run a single adapter evaluation cycle.
    async fn run_adapter_cycle(&self) {
        let trust_state = self.trust_state.read().await;
        let proposals = {
            let mut adapter = self.adapter.lock().await;
            adapter.evaluate(&trust_state)
        };

        for proposal in &proposals {
            tracing::info!(
                proposal_id = %proposal.proposal_id,
                target = %proposal.target,
                rationale = %proposal.rationale,
                "adaptation proposed"
            );

            // Audit.
            let mut log = self.audit_log.lock().await;
            log.append(
                AuditCategory::Adaptation,
                if proposal.parameter_changes.len() > 1 {
                    AuditSeverity::Warning
                } else {
                    AuditSeverity::Info
                },
                &format!(
                    "adapter proposal: target={} changes={} rationale={}",
                    proposal.target,
                    proposal.parameter_changes.len(),
                    proposal.rationale,
                ),
            );
        }
    }

    // ── Background Task Orchestrator ──

    /// Start ALL ANANTA background loops.
    ///
    /// Spawns 6 independent tokio tasks:
    ///   1. Attestation loop  (sentinel.check_interval_ms)
    ///   2. Trust Proof loop (trust_proof.generation_interval_ms)
    ///   3. Drift cycle loop  (sentinel.trust_state_interval_ms)
    ///   4. Phoenix loop     (runs on drift alerts, no separate timer)
    ///   5. Health loop       (health.computation_interval_ms)
    ///   6. Adapter loop      (every 10s, if enabled)
    ///
    /// Returns a JoinHandle for the supervisor task.
    /// Call `shutdown()` to stop all loops.
    pub fn start(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        if self.started.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!("ANANTA start() called twice — ignoring");
            return tokio::spawn(async {});
        }

        let plane = Arc::clone(self);
        let config = self.config.clone();

        tokio::spawn(async move {
            if !config.enabled {
                tracing::info!("ANANTA disabled — running without trust plane");
                return;
            }

            tracing::info!(
                attestation_ms = config.sentinel.check_interval_ms,
                proof_ms = config.trust_proof.generation_interval_ms,
                drift_ms = config.sentinel.trust_state_interval_ms,
                health_ms = config.health.computation_interval_ms,
                adapter_enabled = config.adapter.enabled,
                phoenix_autonomous = config.phoenix.autonomous,
                "ANANTA trust plane starting — 6 background loops"
            );

            // Audit startup.
            {
                let mut log = plane.audit_log.lock().await;
                log.append(
                    AuditCategory::Lifecycle,
                    AuditSeverity::Info,
                    "ANANTA trust plane started",
                );
            }

            // Run initial attestation immediately.
            match plane.run_attestation_cycle().await {
                Ok(report) => tracing::info!(
                    trust = %report.trust_level,
                    "ANANTA initial attestation complete"
                ),
                Err(e) => tracing::error!(error = %e, "ANANTA initial attestation failed"),
            }

            // ── Loop 1: Attestation ──
            let attestation_plane = Arc::clone(&plane);
            let attestation_interval = config.sentinel.check_interval_ms;
            let attestation_shutdown = plane.shutdown.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(attestation_interval),
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match attestation_plane.run_attestation_cycle().await {
                                Ok(_) => {},
                                Err(e) => tracing::error!(error = %e, "attestation cycle error"),
                            }
                        }
                        _ = attestation_shutdown.notified() => {
                            tracing::info!("attestation loop shutting down");
                            break;
                        }
                    }
                }
            });

            // ── Loop 2: Trust Proof Generation ──
            if config.trust_proof.enabled {
                let proof_plane = Arc::clone(&plane);
                let proof_interval = config.trust_proof.generation_interval_ms;
                let proof_shutdown = plane.shutdown.clone();
                tokio::spawn(async move {
                    // Wait for first attestation to complete.
                    tokio::time::sleep(std::time::Duration::from_millis(
                        attestation_interval,
                    )).await;

                    let mut interval = tokio::time::interval(
                        std::time::Duration::from_millis(proof_interval),
                    );
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                match proof_plane.run_trust_proof_generation().await {
                                    Ok(_) => {},
                                    Err(e) => tracing::error!(error = %e, "trust proof generation error"),
                                }
                            }
                            _ = proof_shutdown.notified() => {
                                tracing::info!("trust proof loop shutting down");
                                break;
                            }
                        }
                    }
                });
            }

            // ── Loop 3: Drift Detection Cycle ──
            let drift_plane = Arc::clone(&plane);
            let drift_interval = config.sentinel.trust_state_interval_ms;
            let drift_shutdown = plane.shutdown.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(drift_interval),
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            drift_plane.run_drift_cycle().await;
                        }
                        _ = drift_shutdown.notified() => {
                            tracing::info!("drift cycle loop shutting down");
                            break;
                        }
                    }
                }
            });

            // ── Loop 4: Phoenix is event-driven (triggered by drift alerts) ──
            // No separate timer needed — Phoenix runs inside handle_drift_alert().
            tracing::debug!(
                autonomous = config.phoenix.autonomous,
                "phoenix recovery: event-driven via drift alerts"
            );

            // ── Loop 5: Health Graph ──
            if config.health.enabled {
                let health_plane = Arc::clone(&plane);
                let health_interval = config.health.computation_interval_ms;
                let health_shutdown = plane.shutdown.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(
                        std::time::Duration::from_millis(health_interval),
                    );
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                health_plane.run_health_cycle().await;
                            }
                            _ = health_shutdown.notified() => {
                                tracing::info!("health loop shutting down");
                                break;
                            }
                        }
                    }
                });
            }

            // ── Loop 6: Adapter (opt-in, runs every 10s) ──
            if config.adapter.enabled {
                let adapter_plane = Arc::clone(&plane);
                let adapter_shutdown = plane.shutdown.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(
                        std::time::Duration::from_secs(10),
                    );
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                adapter_plane.run_adapter_cycle().await;
                            }
                            _ = adapter_shutdown.notified() => {
                                tracing::info!("adapter loop shutting down");
                                break;
                            }
                        }
                    }
                });
            }

            // ── Loop 7: OVAPH Unified Cycle (Phase B, runs every 30s) ──
            let ovaph_plane = Arc::clone(&plane);
            let ovaph_shutdown = plane.shutdown.clone();
            tokio::spawn(async move {
                // Wait for initial attestation to complete first.
                tokio::time::sleep(std::time::Duration::from_millis(
                    config.sentinel.check_interval_ms,
                )).await;

                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(30),
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match ovaph_plane.run_ovaph_cycle().await {
                                Ok(report) => tracing::debug!(
                                    cycle_id = %report.cycle_id,
                                    outcome = ?report.overall_outcome,
                                    "OVAPH cycle completed"
                                ),
                                Err(e) => tracing::error!(error = %e, "OVAPH cycle error"),
                            }
                        }
                        _ = ovaph_shutdown.notified() => {
                            tracing::info!("OVAPH loop shutting down");
                            break;
                        }
                    }
                }
            });

            // Supervisor: keep alive until shutdown.
            plane.shutdown.notified().await;

            // Final audit.
            {
                let mut log = plane.audit_log.lock().await;
                log.append(
                    AuditCategory::Lifecycle,
                    AuditSeverity::Info,
                    "ANANTA trust plane shutting down",
                );
            }

            tracing::info!("ANANTA trust plane stopped");
        })
    }

    /// Signal graceful shutdown of all background loops.
    pub async fn shutdown(&self) {
        tracing::info!("ANANTA shutdown signal sent");
        self.shutdown.notify_waiters();
    }

    /// Check if ANANTA has been started.
    pub fn is_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::Relaxed)
    }

    // ── Helpers ──

    /// Map a component name from integrity results to a trust domain.
    fn component_to_trust_domain(&self, component: &str) -> &'static str {
        match component {
            "binary" => "runtime",
            "config" => "configuration",
            "policy" => "policy",
            "ananta_config" => "configuration",
            c if c.starts_with("ring_config:") => {
                let ring_name = c.strip_prefix("ring_config:").unwrap_or("");
                match ring_name {
                    "shield" | "threat" | "identity" => "decision",
                    "agent" | "memory" | "execution" => "model",
                    "reasoning" | "governance" => "learning",
                    "recovery" => "orchestration",
                    _ => "configuration",
                }
            }
            _ => "runtime",
        }
    }

    /// Map a drift type to its trust domain string.
    fn drift_type_to_domain(&self, dt: &DriftType) -> &'static str {
        match dt {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel::drift::DriftObservation;

    fn test_config() -> AnantaConfig {
        AnantaConfig {
            enabled: true,
            state_path: format!("/tmp/ananta_test_{}", std::process::id()).into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn ananta_creates_with_all_subsystems() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        let state = plane.trust_state().await;
        // 11 trust domains initialized.
        assert_eq!(state.domains.len(), 11);
        assert!(state.overall_score() >= 0.0);
        assert!(!plane.is_started());
    }

    #[tokio::test]
    async fn attestation_cycle_runs() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        let report = plane.run_attestation_cycle().await.unwrap();
        // No providers registered, so results are empty (not failed).
        assert!(report.integrity.results.is_empty() || report.integrity.passed);
    }

    #[tokio::test]
    async fn consecutive_counters_update() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        plane.run_attestation_cycle().await.unwrap();
        assert!(plane.consecutive_passes() >= 1);
        assert_eq!(plane.consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn latest_attestation_available() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        assert!(plane.latest_attestation().await.is_none());
        plane.run_attestation_cycle().await.unwrap();
        assert!(plane.latest_attestation().await.is_some());
    }

    #[tokio::test]
    async fn trust_chain_grows_on_attestation() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        plane.run_attestation_cycle().await.unwrap();
        plane.run_attestation_cycle().await.unwrap();
        let chain = plane.attestation_chain.read().await;
        assert_eq!(chain.len(), 2);
        assert!(chain.verify().is_none());
    }

    #[tokio::test]
    async fn trust_proof_generated() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        plane.run_attestation_cycle().await.unwrap();
        let proof = plane.run_trust_proof_generation().await.unwrap();
        assert!(!proof.proof_id.is_empty());
        assert!(plane.latest_trust_proof().await.is_some());
    }

    #[tokio::test]
    async fn drift_observation_updates_trust() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        // Feed stable data to establish baseline.
        for _ in 0..50 {
            plane.observe_drift(DriftObservation {
                drift_type: DriftType::Decision,
                value: 0.85,
                context: "test".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }).await;
        }

        let before = plane.trust_state().await.domain_level("decision");

        // Feed anomalous value.
        plane.observe_drift(DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.10,
            context: "test".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }).await;

        let after = plane.trust_state().await.domain_level("decision");
        assert!(after < before, "drift should reduce trust: before={} after={}", before, after);
    }

    #[tokio::test]
    async fn health_observation_and_overall() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        let health = plane.overall_health().await;
        assert!(health > 0.0);
    }

    #[tokio::test]
    async fn register_integrity_provider_works() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        // Register a provider and a manifest entry.
        plane.register_integrity_provider(
            anchor::integrity::IntegrityDomain::Config,
            || b"known_good_config".to_vec(),
        ).await;

        plane.add_manifest_entry("config", b"known_good_config").await;

        // Run attestation — should pass.
        let report = plane.run_attestation_cycle().await.unwrap();
        let config_result = report.integrity.results.iter()
            .find(|r| r.component == "config");
        assert!(config_result.is_some());
        assert!(config_result.unwrap().passed);
    }

    #[tokio::test]
    async fn integrity_failure_detected() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        plane.register_integrity_provider(
            anchor::integrity::IntegrityDomain::Config,
            || b"tampered_config".to_vec(),
        ).await;

        // Manifest says "known_good" but provider returns "tampered".
        plane.add_manifest_entry("config", b"known_good_config").await;

        let report = plane.run_attestation_cycle().await.unwrap();
        assert!(!report.integrity.passed);
    }

    #[tokio::test]
    async fn start_sets_flag() {
        let config = AnantaConfig {
            enabled: false, // Don't actually start loops for test.
            state_path: format!("/tmp/ananta_test_{}", std::process::id()).into(),
            ..Default::default()
        };
        let plane = Arc::new(AnantaPlane::new(config).unwrap());
        assert!(!plane.is_started());

        let handle = plane.start();
        // Give it a moment to set the flag.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(plane.is_started());

        plane.shutdown().await;
        let _ = handle.await;
    }

    #[tokio::test]
    async fn config_warnings_work() {
        let mut config = test_config();
        config.sentinel.check_interval_ms = 50;
        let warnings = config.validate();
        assert!(!warnings.is_empty());
    }

    #[tokio::test]
    async fn recovery_history_records_actions() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        let action = phoenix::strategies::RecoveryAction::new(
            RecoveryStrategy::Restart,
            "shield",
            "test recovery",
        );

        let result = plane.execute_recovery_action(&action).await;
        {
            let mut history = plane.recovery_history.lock().await;
            history.record(&action, &result);
        }

        let history = plane.recovery_history.lock().await;
        assert_eq!(history.total_actions(), 1);
    }

    #[tokio::test]
    async fn trust_summary_string() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        let summary = plane.trust_summary().await;
        assert!(summary.contains("trust="));
    }

    #[tokio::test]
    async fn ovaph_cycle_runs() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        let report = plane.run_ovaph_cycle().await;
        assert!(report.is_ok(), "OVAPH cycle should succeed: {:?}", report.err());
        let report = report.unwrap();
        assert!(!report.cycle_id.cycle_id.is_empty());
        assert!(report.trust_before >= 0.0);
        assert!(report.trust_after >= 0.0);
    }

    #[tokio::test]
    async fn ovaph_report_available() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        assert!(plane.latest_ovaph_report().await.is_none());
        let _ = plane.run_ovaph_cycle().await;
        assert!(plane.latest_ovaph_report().await.is_some());
    }

    #[tokio::test]
    async fn ovaph_metrics_accessible() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();
        let metrics = plane.ovaph_metrics().await;
        assert_eq!(metrics.total_cycles, 0);
        let _ = plane.run_ovaph_cycle().await;
        let metrics = plane.ovaph_metrics().await;
        assert!(metrics.total_cycles >= 1);
    }

    #[tokio::test]
    async fn ovaph_with_integrity_failure() {
        let config = test_config();
        let plane = AnantaPlane::new(config).unwrap();

        // Register a provider that returns tampered data.
        plane.register_integrity_provider(
            anchor::integrity::IntegrityDomain::Config,
            || b"tampered".to_vec(),
        ).await;
        plane.add_manifest_entry("config", b"known_good").await;

        let report = plane.run_ovaph_cycle().await.unwrap();
        assert!(!report.attestation_passed);
    }
}
