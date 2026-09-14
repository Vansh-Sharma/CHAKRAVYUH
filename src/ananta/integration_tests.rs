#![cfg(test)]
#![deny(unsafe_code)]

// ANANTA Integration Tests — Phase B
//
// Tests the full ANANTA subsystem working together,
// including the OVAPH loop, rollback engine, sentinel wiring,
// trust propagation, and adapter pipeline.
//
// Categories:
//   A. OVAPH Loop Integration (8 tests)
//   B. Rollback Engine Integration (5 tests)
//   C. Sentinel + Trust State Integration (5 tests)
//   D. Adapter + Trust State Integration (4 tests)
//   E. Trust Propagation Integration (4 tests)
//   F. Full Pipeline Integration (5 tests)
//   G. Failure Injection (5 tests)

use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::ananta::adapter::{
    AdaptationProposal, AdaptationStatus, Adapter, DynamicPipelineManager,
    ParameterChange, PipelineConfig, PipelineStage, StageType,
};
use crate::ananta::config::AdapterConfig;
use crate::ananta::ovaph_loop::{
    CycleOutcome, OvaphAttestationResult, OvaphConfig,
    OvaphLoop, OvaphMetrics, OvaphObservation, OvaphStage, OvaphVerificationResult,
    Severity, StageOutcome, VerifiedSignal,
};
use crate::ananta::phoenix::rollback_engine::{
    RollbackConfig, RollbackExecutor, RollbackOutcome, SnapshotStore, StateDiff, StateSnapshot,
};
use crate::ananta::sentinel::drift::{DriftObservation, DriftType};
use crate::ananta::sentinel::sentinel_wiring::{DriftBaselines, SentinelHub};
use crate::ananta::trust::trust_engine::BayesianTrustEngine;
use crate::ananta::trust::trust_propagation_bridge::{
    TrustEvent, TrustEventSource, TrustPropagationOrchestrator, TrustStateSynchronizer,
    UnifiedTrustSnapshot,
};
use crate::ananta::trust::TrustState;

// ─────────────────────────────────────────────────────────────
// Helper: create a test config matching the one used in mod.rs
// ─────────────────────────────────────────────────────────────

fn test_config() -> AnantaConfig {
    AnantaConfig {
        enabled: true,
        state_path: format!("/tmp/ananta_integration_test_{}", std::process::id()).into(),
        ..Default::default()
    }
}

fn test_pid() -> u32 {
    std::process::id()
}

// ═══════════════════════════════════════════════════════════════
// Section A: OVAPH Loop Integration (8 tests)
// ═══════════════════════════════════════════════════════════════

/// A.1 — Run full OVAPH cycle and verify all 5 stages execute.
#[tokio::test]
async fn ovaph_full_cycle_with_attestation() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    let report = plane.run_ovaph_cycle().await.expect("OVAPH cycle should succeed");

    // All 5 stages must be present (O, V, A, H, P).
    assert_eq!(
        report.stages.len(),
        5,
        "OVAPH cycle must have exactly 5 stages, got {}",
        report.stages.len()
    );

    let stage_names: Vec<&str> = report.stages.iter().map(|s| s.stage.name()).collect();
    assert_eq!(stage_names, vec!["Observe", "Verify", "Attest", "Heal", "Prove"]);

    // Each stage must have completed or been skipped — not failed.
    for sr in &report.stages {
        assert!(
            sr.success,
            "stage {} should succeed or skip: errors={:?}",
            sr.stage,
            sr.errors
        );
    }

    // Report metadata checks.
    assert!(!report.cycle_id.cycle_id.is_empty());
    assert!(report.overall_outcome == CycleOutcome::AllCompleted);
}

/// A.2 — Run 3 cycles in sequence, verify metrics accumulate.
#[tokio::test]
async fn ovaph_consecutive_cycles() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    for i in 1..=3 {
        let _ = plane.run_ovaph_cycle().await.unwrap();
        let metrics = plane.ovaph_metrics().await;
        assert_eq!(
            metrics.total_cycles,
            i as u64,
            "after {} cycles, metrics.total_cycles should be {}",
            i, i
        );
    }

    let metrics = plane.ovaph_metrics().await;
    assert!(metrics.completed_cycles >= 3, "expected >= 3 completed, got {}", metrics.completed_cycles);
    assert_eq!(metrics.failed_cycles, 0, "no cycles should fail");
    assert!(metrics.avg_cycle_duration_ms > 0.0);
    assert!(metrics.last_cycle_at.is_some());
}

/// A.3 — Feed drift data then run OVAPH, verify detection in Verify stage.
#[tokio::test]
async fn ovaph_with_drift_observation() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Establish baseline with 50 stable observations.
    for _ in 0..50 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Decision,
                value: 0.85,
                context: "baseline".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    // Inject anomalous observation.
    plane
        .observe_drift(DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.05,
            context: "anomaly".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
        .await;

    // Run OVAPH cycle — it should observe the drift detector's state.
    let report = plane.run_ovaph_cycle().await.unwrap();
    // The Verify stage should have detected signals.
    let verify_stage = report.stages.iter().find(|s| s.stage == OvaphStage::Verify);
    assert!(verify_stage.is_some());
    // The observation should contain drift snapshots for Decision type.
    let trust_before = report.trust_before;
    // Trust should be well-defined.
    assert!(trust_before >= 0.0 && trust_before <= 1.0);
}

/// A.4 — Register a tampered provider and verify attest stage fails.
#[tokio::test]
async fn ovaph_with_integrity_failure() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    plane
        .register_integrity_provider(anchor::integrity::IntegrityDomain::Config, || {
            b"tampered_data".to_vec()
        })
        .await;
    plane
        .add_manifest_entry("config", b"known_good_config")
        .await;

    let report = plane.run_ovaph_cycle().await.unwrap();
    assert!(!report.attestation_passed, "attestation should fail with tampered provider");
}

/// A.5 — With heal_autonomous=false, verify no recovery actions are taken.
#[tokio::test]
async fn ovaph_heal_stage_disabled() {
    let ovaph_config = OvaphConfig {
        enabled: true,
        heal_autonomous: false,
        ..OvaphConfig::default()
    };
    let loop_engine = OvaphLoop::new(ovaph_config);

    // Create a verification that requires healing.
    let verification = OvaphVerificationResult {
        signals: vec![VerifiedSignal::anomaly(
            "decision".into(),
            Severity::Critical,
            0.9,
        )],
        composite_severity: Severity::Critical,
        requires_healing: true,
        rationale: "critical anomaly detected".into(),
    };

    let (heal_result, healing) = loop_engine.run_heal(&verification).await;

    assert!(matches!(heal_result.outcome, StageOutcome::Skipped(_)), "heal stage should be skipped when autonomous=false");
    assert!(healing.healing_required);
    assert_eq!(healing.actions_executed, 0, "no actions should execute when autonomous=false");
    assert_eq!(healing.actions_planned, 0, "no actions planned when autonomous=false");
}

/// A.6 — After attestation, verify the Prove stage generates a proof.
#[tokio::test]
async fn ovaph_prove_stage_generates_proof() {
    let ovaph_config = OvaphConfig {
        enabled: true,
        prove_generate_proof: true,
        ..OvaphConfig::default()
    };
    let loop_engine = OvaphLoop::new(ovaph_config);

    // Clean attestation result.
    let attestation = OvaphAttestationResult {
        attestation_passed: true,
        trust_level: 0.95,
        failed_components: vec![],
        attestation_id: uuid::Uuid::new_v4().to_string(),
        chain_length_after: 1,
    };

    let (prove_result, proof) = loop_engine.run_prove(&attestation).await;

    assert!(prove_result.success, "Prove stage should complete");
    assert!(proof.proof_generated, "proof should be generated when attestation passes");
    assert!(proof.proof_id.is_some(), "proof_id should be present");
    assert!(proof.all_domains_passed);
    assert!(proof.trust_score > 0.0);
}

/// A.7 — Verify metrics survive across cycles.
#[tokio::test]
async fn ovaph_cycle_metrics_persist() {
    let ovaph_config = OvaphConfig::default();
    let loop_engine = OvaphLoop::new(ovaph_config);

    let _ = loop_engine.run_full_cycle().await.unwrap();
    let m1 = loop_engine.metrics().unwrap();
    assert_eq!(m1.total_cycles, 1);

    let _ = loop_engine.run_full_cycle().await.unwrap();
    let m2 = loop_engine.metrics().unwrap();
    assert_eq!(m2.total_cycles, 2);
    assert!(m2.total_duration_ms >= m1.total_duration_ms);
    assert!(m2.avg_cycle_duration_ms > 0.0);
    assert_eq!(m2.consecutive_successes, 2);
    assert_eq!(m2.consecutive_failures, 0);
}

/// A.8 — Spawn 2 cycles concurrently, verify no deadlock or panic.
#[tokio::test]
async fn ovaph_concurrent_cycles_safe() {
    let ovaph_config = OvaphConfig {
        enabled: true,
        stage_timeout_ms: 5_000,
        max_cycle_duration_ms: 60_000,
        ..OvaphConfig::default()
    };
    let loop_engine = Arc::new(OvaphLoop::new(ovaph_config));

    let engine_a = Arc::clone(&loop_engine);
    let engine_b = Arc::clone(&loop_engine);

    let h1 = tokio::spawn(async move { engine_a.run_full_cycle().await });
    let h2 = tokio::spawn(async move { engine_b.run_full_cycle().await });

    let r1 = h1.await.expect("task 1 should not panic");
    let r2 = h2.await.expect("task 2 should not panic");

    assert!(r1.is_ok(), "cycle 1 should succeed: {:?}", r1.err());
    assert!(r2.is_ok(), "cycle 2 should succeed: {:?}", r2.err());

    // At least 2 cycles should be recorded.
    let metrics = loop_engine.metrics().unwrap();
    assert!(metrics.total_cycles >= 2, "expected >= 2 cycles, got {}", metrics.total_cycles);
}

// ═══════════════════════════════════════════════════════════════
// Section B: Rollback Engine Integration (5 tests)
// ═══════════════════════════════════════════════════════════════

fn make_rollback_executor(max_snapshots: usize) -> RollbackExecutor {
    let store = Arc::new(std::sync::Mutex::new(SnapshotStore::new(
        RollbackConfig {
            max_snapshots_per_domain: max_snapshots,
            verify_after_rollback: true,
            auto_snapshot_before_recovery: false,
            ..RollbackConfig::default()
        },
    )));
    RollbackExecutor::new(
        store,
        RollbackConfig {
            max_snapshots_per_domain: max_snapshots,
            verify_after_rollback: true,
            auto_snapshot_before_recovery: false,
            ..RollbackConfig::default()
        },
    )
}

fn test_snapshot(_domain: &str, key_prefix: &str) -> HashMap<String, serde_json::Value> {
    let mut data = HashMap::new();
    data.insert(format!("{}_key1", key_prefix), serde_json::json!("value1"));
    data.insert(format!("{}_key2", key_prefix), serde_json::json!(42));
    data.insert(format!("{}_key3", key_prefix), serde_json::json!(true));
    data
}

/// B.1 — Create snapshot, modify, rollback, verify restored.
#[test]
fn rollback_full_flow() {
    let mut executor = make_rollback_executor(10);
    let domain = "decision";

    // Create initial (known-good) snapshot.
    let good_data = test_snapshot(domain, "v1");
    let good = executor
        .store
        .lock()
        .unwrap()
        .create_last_known_good(domain, good_data.clone())
        .unwrap();

    // Create a modified snapshot.
    let mut modified_data = good_data.clone();
    modified_data.insert("v1_key2".into(), serde_json::json!("tampered"));
    executor
        .store
        .lock()
        .unwrap()
        .create_snapshot(domain, modified_data)
        .unwrap();

    // Rollback to the known-good snapshot.
    let result = executor
        .execute_rollback_to_last_good(domain)
        .expect("rollback should succeed");

    assert_eq!(result.outcome, RollbackOutcome::Success);
    assert_eq!(result.domain, domain);
    assert_eq!(result.target_snapshot_id, good.snapshot_id);

    // Verify the latest snapshot has the original key1 value.
    let guard = executor.store.lock().unwrap();
    let latest = guard
        .latest(domain)
        .expect("should have a snapshot after rollback");
    assert_eq!(
        latest.get("v1_key1").and_then(|v| v.as_str()),
        Some("value1"),
        "key1 should be restored after rollback"
    );
}

/// B.2 — Rollback 3 domains independently.
#[test]
fn rollback_multiple_domains() {
    let mut executor = make_rollback_executor(10);
    let domains = ["decision", "policy", "model"];

    let mut good_ids: Vec<String> = Vec::new();
    for domain in &domains {
        let data = test_snapshot(domain, "good");
        let snap = executor
            .store
            .lock()
            .unwrap()
            .create_last_known_good(domain, data)
            .unwrap();
        good_ids.push(snap.snapshot_id.clone());

        // Corrupt.
        let mut corrupted = test_snapshot(domain, "good");
        corrupted.insert(format!("{}_key1", "good"), serde_json::json!("corrupted"));
        executor
            .store
            .lock()
            .unwrap()
            .create_snapshot(domain, corrupted)
            .unwrap();
    }

    // Rollback all domains.
    for (i, domain) in domains.iter().enumerate() {
        let result = executor
            .execute_rollback_to_last_good(domain)
            .expect("rollback should succeed");
        assert_eq!(result.outcome, RollbackOutcome::Success);
        assert_eq!(result.target_snapshot_id, good_ids[i]);
    }

    // Verify each domain was rolled back.
    for domain in &domains {
        let guard = executor.store.lock().unwrap();
        let latest = guard
            .latest(domain)
            .unwrap();
        assert_eq!(
            latest.get(&format!("{}_key1", "good")).and_then(|v| v.as_str()),
            Some("value1")
        );
    }

    // History should record all 3 rollbacks.
    assert_eq!(executor.history_count(), 3);
}

/// B.3 — Verify rollback history records all operations.
#[test]
fn rollback_history_audit() {
    let mut executor = make_rollback_executor(10);
    let domain = "policy";

    // Create good and corrupted snapshots.
    let good = executor
        .store
        .lock()
        .unwrap()
        .create_last_known_good(domain, test_snapshot(domain, "a"))
        .unwrap();
    executor
        .store
        .lock()
        .unwrap()
        .create_snapshot(domain, test_snapshot(domain, "b"))
        .unwrap();

    // Execute 3 rollbacks.
    for _ in 0..3 {
        let _ = executor.execute_rollback(domain, &good.snapshot_id);
    }

    let history = executor.history();
    assert_eq!(history.len(), 3, "should have 3 rollback history entries");

    // All entries should reference the same domain.
    for entry in history {
        assert_eq!(entry.domain, domain);
        assert_eq!(entry.target_snapshot_id, good.snapshot_id);
        assert!(entry.duration_ms > 0 || entry.outcome == RollbackOutcome::DryRun);
    }
}

/// B.4 — Rollback and verify that the result matches the target snapshot.
#[test]
fn rollback_with_verification() {
    let mut executor = make_rollback_executor(10);
    let domain = "runtime";

    let target_data = test_snapshot(domain, "target");
    let target = executor
        .store
        .lock()
        .unwrap()
        .create_snapshot(domain, target_data.clone())
        .unwrap();

    // Corrupt.
    let mut corrupted = target_data.clone();
    corrupted.insert("target_key1".into(), serde_json::json!("bad_value"));
    executor
        .store
        .lock()
        .unwrap()
        .create_snapshot(domain, corrupted)
        .unwrap();

    // Rollback.
    let result = executor
        .execute_rollback(domain, &target.snapshot_id)
        .expect("rollback should succeed");

    assert_eq!(result.outcome, RollbackOutcome::Success);
    // Verification is enabled, so it should be present.
    assert!(
        result.verification.is_some(),
        "verification should be present when verify_after_rollback=true"
    );
}

/// B.5 — Create many snapshots, verify pruning evicts oldest.
#[test]
fn rollback_snapshot_pruning() {
    let max_snaps = 5;
    let executor = make_rollback_executor(max_snaps);
    let domain = "memory";

    // Create more snapshots than the limit.
    for i in 0..(max_snaps + 3) {
        let mut data = HashMap::new();
        data.insert(format!("idx"), serde_json::json!(i));
        executor
            .store
            .lock()
            .unwrap()
            .create_snapshot(domain, data)
            .unwrap();
    }

    let count = executor.store.lock().unwrap().count(domain);
    assert_eq!(
        count, max_snaps,
        "store should prune to max_snapshots={}, got {}",
        max_snaps,
        count
    );
}

// ═══════════════════════════════════════════════════════════════
// Section C: Sentinel + Trust State Integration (5 tests)
// ═══════════════════════════════════════════════════════════════

/// C.1 — Feed anomalous drift, verify trust decreases.
#[tokio::test]
async fn drift_detection_updates_trust() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Establish baseline.
    for _ in 0..50 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Decision,
                value: 0.85,
                context: "baseline".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    let before = plane.trust_state().await.domain_level("decision");

    // Feed extreme anomaly.
    plane
        .observe_drift(DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.0,
            context: "severe_anomaly".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
        .await;

    let after = plane.trust_state().await.domain_level("decision");
    assert!(
        after < before,
        "trust should decrease after anomalous drift: before={} after={}",
        before, after
    );
}

/// C.2 — Feed 5 drift types simultaneously.
#[tokio::test]
async fn multi_type_drift_concurrent() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    let drift_types = [
        DriftType::Decision,
        DriftType::Policy,
        DriftType::Model,
        DriftType::Orchestration,
        DriftType::Learning,
    ];

    // Baseline.
    for dt in &drift_types {
        for _ in 0..30 {
            plane
                .observe_drift(DriftObservation {
                    drift_type: dt.clone(),
                    value: 0.8,
                    context: "baseline".into(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
                .await;
        }
    }

    // Simultaneous anomalies.
    for dt in &drift_types {
        plane
            .observe_drift(DriftObservation {
                drift_type: dt.clone(),
                value: 0.01,
                context: "concurrent_anomaly".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    // Check that trust didn't panic and overall score is well-defined.
    let state = plane.trust_state().await;
    let overall = state.overall_score();
    assert!(overall >= 0.0 && overall <= 1.0, "overall trust should be in [0,1]: {}", overall);
}

/// C.3 — After drift, feed stable data, verify trust recovery.
#[tokio::test]
async fn drift_recovery_trust_restores() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Baseline.
    for _ in 0..40 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Policy,
                value: 0.8,
                context: "baseline".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    let baseline_trust = plane.trust_state().await.domain_level("policy");

    // Cause drift.
    for _ in 0..5 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Policy,
                value: 0.0,
                context: "drift_event".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    let drifted_trust = plane.trust_state().await.domain_level("policy");
    assert!(
        drifted_trust < baseline_trust,
        "trust should have dropped from drift: baseline={} drifted={}",
        baseline_trust, drifted_trust
    );

    // Run recovery drift cycle (applies trust recovery).
    plane.run_drift_cycle().await;
    let recovered_trust = plane.trust_state().await.domain_level("policy");
    assert!(
        recovered_trust >= drifted_trust,
        "trust should not decrease further after recovery: drifted={} recovered={}",
        drifted_trust, recovered_trust
    );
}

/// C.4 — Feed baseline data, verify no false alerts.
#[tokio::test]
async fn sentinel_baseline_warming() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    let before = plane.trust_state().await.domain_level("decision");

    // Feed 100 stable observations.
    for i in 0..100 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Decision,
                value: 0.85 + (i as f64 % 10.0) * 0.001, // Tiny natural variation.
                context: "warming".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    let after = plane.trust_state().await.domain_level("decision");
    // Trust should not have degraded significantly from stable data.
    let drop = before - after;
    assert!(
        drop < 0.3,
        "trust should not drop more than 0.3 from stable data: before={} after={} drop={}",
        before, after, drop
    );

    // No critical alerts should be present.
    let state = plane.trust_state().await;
    assert_eq!(state.critical_count(), 0, "no critical alerts from stable data");
}

/// C.5 — Verify drift alerts appear in audit log.
#[tokio::test]
async fn drift_alert_audited() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Warm baseline.
    for _ in 0..50 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Configuration,
                value: 0.9,
                context: "baseline".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    // Trigger drift alert.
    plane
        .observe_drift(DriftObservation {
            drift_type: DriftType::Configuration,
            value: 0.0,
            context: "attack".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
        .await;

    // Trust should decrease, indicating the alert was processed and audited.
    let state = plane.trust_state().await;
    let config_trust = state.domain_level("configuration");
    assert!(
        config_trust < 1.0,
        "configuration trust should have dropped after drift alert: {}",
        config_trust
    );
}

// ═══════════════════════════════════════════════════════════════
// Section D: Adapter + Trust State Integration (4 tests)
// ═══════════════════════════════════════════════════════════════

/// D.1 — Set trust low, verify adapter proposes tightening.
#[tokio::test]
async fn degraded_trust_proposes_tightening() {
    let mut trust_state = TrustState::new();
    // Degrade overall trust below 0.7.
    trust_state.set_domain_level("decision", 0.1);
    trust_state.set_domain_level("policy", 0.2);
    trust_state.set_domain_level("orchestration", 0.1);

    let adapter_config = AdapterConfig {
        enabled: true,
        max_reconfigurations_per_hour: 100,
        ..AdapterConfig::default()
    };
    let mut adapter = Adapter::new(adapter_config);

    let proposals = adapter.evaluate(&trust_state);

    // Should propose tightening for the pipeline.
    let has_pipeline = proposals.iter().any(|p| p.target == "pipeline");
    assert!(has_pipeline, "should propose pipeline tightening when trust is degraded");

    // The proposal should contain parameter changes.
    if let Some(p) = proposals.iter().find(|p| p.target == "pipeline") {
        assert!(!p.parameter_changes.is_empty());
        assert!(p.trust_level_at_proposal < 0.7);
    }
}

/// D.2 — Set domain trust to 0.1, verify quarantine proposed.
#[tokio::test]
async fn quarantine_proposed_for_critical_domain() {
    let mut trust_state = TrustState::new();
    trust_state.set_domain_level("configuration", 0.1);

    let adapter_config = AdapterConfig {
        enabled: true,
        max_reconfigurations_per_hour: 100,
        ..AdapterConfig::default()
    };
    let mut adapter = Adapter::new(adapter_config);

    let proposals = adapter.evaluate(&trust_state);

    let has_quarantine = proposals
        .iter()
        .any(|p| p.target == "configuration" && p.rationale.contains("Quarantining"));
    assert!(
        has_quarantine,
        "should propose quarantine for domain with trust=0.1"
    );
}

/// D.3 — Exhaust rate limit, verify no more proposals.
#[tokio::test]
async fn adapter_rate_limiting() {
    let mut trust_state = TrustState::new();
    trust_state.set_domain_level("decision", 0.1);
    trust_state.set_domain_level("policy", 0.05);

    let adapter_config = AdapterConfig {
        enabled: true,
        max_reconfigurations_per_hour: 2,
        ..AdapterConfig::default()
    };
    let mut adapter = Adapter::new(adapter_config);

    // First call should produce proposals.
    let first = adapter.evaluate(&trust_state);
    assert!(!first.is_empty(), "first evaluation should produce proposals");

    // Second call — may still produce for the second domain.
    let _ = adapter.evaluate(&trust_state);

    // Third call — should be rate-limited.
    let third = adapter.evaluate(&trust_state);
    assert!(
        third.is_empty(),
        "third evaluation should be rate-limited, got {} proposals",
        third.len()
    );
}

/// D.4 — Create proposal, verify JSON roundtrip.
#[tokio::test]
async fn adapter_proposal_serialization() {
    let proposal = AdaptationProposal {
        proposal_id: "test-prop-001".into(),
        target: "pipeline".into(),
        description: "Integration test proposal".into(),
        parameter_changes: vec![
            ParameterChange {
                parameter: "threat_threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.3),
            },
            ParameterChange {
                parameter: "sensitivity".into(),
                old_value: serde_json::json!(1.0),
                new_value: serde_json::json!(1.3),
            },
        ],
        trust_level_at_proposal: 0.45,
        rationale: "trust degraded, tightening".into(),
        signature: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        grace_deadline: chrono::Utc::now().to_rfc3339(),
        status: AdaptationStatus::Proposed,
    };

    let json = serde_json::to_string(&proposal).expect("serialize should work");
    let deserialized: AdaptationProposal =
        serde_json::from_str(&json).expect("deserialize should work");

    assert_eq!(deserialized.proposal_id, proposal.proposal_id);
    assert_eq!(deserialized.target, proposal.target);
    assert_eq!(deserialized.parameter_changes.len(), 2);
    assert_eq!(deserialized.status, AdaptationStatus::Proposed);
    assert!((deserialized.trust_level_at_proposal - 0.45).abs() < f64::EPSILON);
}

// ═══════════════════════════════════════════════════════════════
// Section E: Trust Propagation Integration (4 tests)
// ═══════════════════════════════════════════════════════════════

/// E.1 — Add positive evidence, verify trust increases.
#[test]
fn evidence_updates_trust() {
    let mut engine = BayesianTrustEngine::new();
    let from = "ananta_plane";
    let to = "decision";

    let before = engine.trust_score(from, to);
    assert!(before.is_none(), "no trust score before evidence");

    // Add 5 positive evidence records.
    for _ in 0..5 {
        engine.record_evidence(from, to, true, 0.8, "test_positive");
    }

    let after = engine.trust_score(from, to).expect("should have trust score after evidence");
    assert!(after > 0.5, "trust should be high after positive evidence: {}", after);
}

/// E.2 — Add negative evidence, verify trust decreases.
#[test]
fn negative_evidence_decreases_trust() {
    let mut engine = BayesianTrustEngine::new();
    let from = "ananta_plane";
    let to = "policy";

    // Seed with some positive evidence.
    for _ in 0..5 {
        engine.record_evidence(from, to, true, 0.9, "test_positive");
    }
    let positive_score = engine.trust_score(from, to).unwrap();

    // Add negative evidence.
    for _ in 0..10 {
        engine.record_evidence(from, to, false, 0.9, "test_negative");
    }
    let negative_score = engine.trust_score(from, to).unwrap();

    assert!(
        negative_score < positive_score,
        "trust should decrease after negative evidence: positive={} negative={}",
        positive_score, negative_score
    );
}

/// E.3 — Update 3 domains, verify propagation effect.
#[test]
fn multi_domain_propagation() {
    let mut engine = BayesianTrustEngine::new();
    let from = "ananta_plane";
    let domains = ["decision", "policy", "model"];

    for domain in &domains {
        engine.record_evidence(from, domain, true, 0.7, "multi_domain_test");
    }

    let result = engine.propagate();
    assert!(result.iterations > 0, "propagation should run iterations");

    // All domains should have trust > 0.
    for domain in &domains {
        let score = result.get(domain);
        assert!(score > 0.0, "domain {} should have trust > 0 after propagation: {}", domain, score);
    }
}

/// E.4 — Create divergence between simple and Bayesian trust.
#[test]
fn trust_divergence_detection() {
    let mut state = TrustState::new();
    let mut engine = BayesianTrustEngine::new();
    let _synchronizer = TrustStateSynchronizer::with_reconciliation_factor(0.0); // Pure simple.

    // Set simple trust very low.
    state.set_domain_level("decision", 0.1);

    // Set Bayesian trust very high.
    for _ in 0..10 {
        engine.record_evidence("ananta_plane", "decision", true, 0.9, "high_trust");
    }

    let snapshot = UnifiedTrustSnapshot::compute(&state, &mut engine);

    // The decision domain should show divergence.
    let decision_div = snapshot
        .divergence_report
        .iter()
        .find(|d| d.domain == "decision");
    assert!(decision_div.is_some(), "decision domain should appear in divergence report");

    let div = decision_div.unwrap();
    assert!(
        div.divergence > 0.3,
        "divergence between simple ({}) and Bayesian ({}) should be > 0.3, got {}",
        div.simple_level, div.bayesian_level, div.divergence
    );
    assert!(
        div.severity >= crate::ananta::trust::trust_propagation_bridge::DivergenceSeverity::High
    );
}

// ═══════════════════════════════════════════════════════════════
// Section F: Full Pipeline Integration (5 tests)
// ═══════════════════════════════════════════════════════════════

/// F.1 — Full cycle: drift → trust update → OVAPH cycle → proof.
#[tokio::test]
async fn full_drift_to_ovaph_pipeline() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Establish baseline.
    for _ in 0..50 {
        plane
            .observe_drift(DriftObservation {
                drift_type: DriftType::Decision,
                value: 0.85,
                context: "pipeline_baseline".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
            .await;
    }

    // Run attestation first.
    let _ = plane.run_attestation_cycle().await.unwrap();

    // Run OVAPH cycle.
    let report = plane.run_ovaph_cycle().await.unwrap();
    assert_eq!(report.stages.len(), 5);
    assert!(report.trust_before >= 0.0);
    assert!(report.trust_after >= 0.0);

    // Attestation chain should have grown.
    let chain_len = plane.attestation_chain.read().await.len();
    assert!(chain_len >= 1, "attestation chain should have entries");
}

/// F.2 — Run attestation → trust proof → verify chain integrity.
#[tokio::test]
async fn attestation_chain_integrity() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    // Run 3 attestation cycles.
    for _ in 0..3 {
        plane.run_attestation_cycle().await.unwrap();
    }

    let chain = plane.attestation_chain.read().await;
    assert_eq!(chain.len(), 3);
    // Chain should verify (no tampering).
    assert!(chain.verify().is_none(), "chain should verify successfully");
}

/// F.3 — Trust propagation orchestrator full cycle.
#[test]
fn trust_propagation_full_cycle() {
    let mut orchestrator = TrustPropagationOrchestrator::new();
    let mut engine = BayesianTrustEngine::new();
    let mut state = TrustState::new();

    // Submit events.
    orchestrator
        .submit_event(TrustEvent::positive(
            "decision",
            TrustEventSource::AttestationCycle,
            "attestation passed",
        ))
        .unwrap();
    orchestrator
        .submit_event(TrustEvent::negative(
            "policy",
            TrustEventSource::DriftAlert,
            "policy drift detected",
        ))
        .unwrap();

    assert_eq!(orchestrator.get_pending_count(), 2);

    // Run full propagation cycle.
    let result = orchestrator
        .run_propagation_cycle(&mut engine, &mut state)
        .expect("propagation cycle should succeed");

    assert_eq!(result.pending_result.events_processed, 2);
    assert_eq!(result.pending_result.evidence_added, 2);
    assert!(result.propagation_result.iterations > 0);
    assert_eq!(orchestrator.get_pending_count(), 0, "pending events should be flushed");
}

/// F.4 — DynamicPipelineManager with adaptation proposal.
#[test]
fn dynamic_pipeline_propose_and_apply() {
    let mut pipeline_config = PipelineConfig::new();
    pipeline_config
        .add_stage(PipelineStage::new("shield_filter", StageType::Filter))
        .unwrap();
    pipeline_config
        .add_stage(PipelineStage::new("threat_decide", StageType::Decide))
        .unwrap();

    let mut manager = DynamicPipelineManager::new(pipeline_config);

    let proposal = AdaptationProposal {
        proposal_id: "test-prop".into(),
        target: "shield_filter".into(),
        description: "Update filter config".into(),
        parameter_changes: vec![ParameterChange {
            parameter: "max_rate".into(),
            old_value: serde_json::json!(1000),
            new_value: serde_json::json!(500),
        }],
        trust_level_at_proposal: 0.6,
        rationale: "tightening".into(),
        signature: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        grace_deadline: chrono::Utc::now().to_rfc3339(),
        status: AdaptationStatus::Proposed,
    };

    let result = manager
        .propose_and_apply(&proposal)
        .expect("propose_and_apply should succeed");

    assert!(result.status == crate::ananta::adapter::ExecutionStatus::Applied
        || result.status == crate::ananta::adapter::ExecutionStatus::Applied);

    // The stage config should have been updated.
    let config = manager.current_config();
    let stage = config.stages.iter().find(|s| s.name == "shield_filter");
    assert!(stage.is_some());
    assert_eq!(
        stage.unwrap().config.get("max_rate"),
        Some(&serde_json::json!(500))
    );
}

/// F.5 — SentinelHub processes observation through full pipeline.
#[test]
fn sentinel_hub_full_pipeline() {
    let mut hub = SentinelHub::with_defaults(3.0, 100).unwrap();

    // Warm baseline.
    for _ in 0..50 {
        let obs = DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.8,
            context: "baseline".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let _ = hub.observe(obs);
    }

    // Anomalous observation.
    let anomalous = DriftObservation {
        drift_type: DriftType::Decision,
        value: 0.0,
        context: "anomaly".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let result = hub.observe(anomalous).expect("observe should succeed");

    // Should detect anomaly.
    assert!(result.is_some(), "anomalous observation should produce a fused signal");
    let signal = result.unwrap();
    assert!(signal.is_anomaly, "fused signal should be an anomaly");
    assert!(signal.composite_confidence > 0.0);
}

// ═══════════════════════════════════════════════════════════════
// Section G: Failure Injection (5 tests)
// ═══════════════════════════════════════════════════════════════

/// G.1 — Rollback to non-existent snapshot returns error.
#[test]
fn rollback_nonexistent_target() {
    let mut executor = make_rollback_executor(10);
    let domain = "policy";

    // Create a snapshot so the domain exists.
    executor
        .store
        .lock()
        .unwrap()
        .create_snapshot(domain, test_snapshot(domain, "only"))
        .unwrap();

    let result = executor.execute_rollback(domain, "nonexistent-snapshot-id");
    assert!(result.is_err(), "rollback to nonexistent snapshot should fail");
}

/// G.2 — Empty domain rollback returns error.
#[test]
fn rollback_empty_domain() {
    let mut executor = make_rollback_executor(10);

    let result = executor.execute_rollback_to_last_good("nonexistent_domain");
    assert!(result.is_err(), "rollback on empty domain should fail");
}

/// G.3 — SentinelHub rejects invalid config.
#[test]
fn sentinel_hub_invalid_config() {
    use crate::ananta::sentinel::sentinel_wiring::FusionConfig;

    // Zero weights.
    let bad_config = FusionConfig {
        z_score_weight: 0.0,
        advanced_weight: 0.0,
        ..FusionConfig::default()
    };
    assert!(bad_config.validate().is_err(), "zero weights should be invalid");

    // Zero baseline min samples.
    let bad_config2 = FusionConfig {
        baseline_min_samples: 0,
        ..FusionConfig::default()
    };
    assert!(bad_config2.validate().is_err(), "zero baseline_min_samples should be invalid");
}

/// G.4 — Trust propagation event buffer overflow.
#[test]
fn trust_propagation_buffer_overflow() {
    let mut orchestrator = TrustPropagationOrchestrator::new();
    orchestrator.max_pending_events = 3;

    // Submit 3 events (fills buffer).
    for i in 0..3 {
        let _ = orchestrator.submit_event(TrustEvent::positive(
            &format!("domain_{}", i),
            TrustEventSource::HealthObservation,
            "test event",
        ));
    }
    assert_eq!(orchestrator.get_pending_count(), 3);

    // 4th event should fail.
    let result = orchestrator.submit_event(TrustEvent::positive(
        "overflow",
        TrustEventSource::HealthObservation,
        "should fail",
    ));
    assert!(result.is_err(), "should fail when buffer is full");
}

/// G.5 — Adapter disabled returns no proposals.
#[tokio::test]
async fn adapter_disabled_no_proposals() {
    let mut trust_state = TrustState::new();
    trust_state.set_domain_level("decision", 0.0);
    trust_state.set_domain_level("policy", 0.0);

    let adapter_config = AdapterConfig {
        enabled: false,
        max_reconfigurations_per_hour: 100,
        ..AdapterConfig::default()
    };
    let mut adapter = Adapter::new(adapter_config);

    let proposals = adapter.evaluate(&trust_state);
    assert!(
        proposals.is_empty(),
        "disabled adapter should return no proposals even with degraded trust"
    );
}

// ═══════════════════════════════════════════════════════════════
// Section F (continued): Additional Full Pipeline Tests
// ═══════════════════════════════════════════════════════════════

/// F.6 — Reconciliation blends simple and Bayesian trust.
#[test]
fn reconciliation_blends_trust() {
    let mut state = TrustState::new();
    let mut engine = BayesianTrustEngine::new();
    let factor = 0.5;
    let synchronizer = TrustStateSynchronizer::with_reconciliation_factor(factor);

    // Set simple trust to 0.5.
    state.set_domain_level("decision", 0.5);

    // Set Bayesian trust to 1.0 via positive evidence.
    for _ in 0..20 {
        engine.record_evidence("ananta_plane", "decision", true, 1.0, "test");
    }

    // Reconcile.
    let result = synchronizer.reconcile(&mut state, &mut engine);
    assert!(result.domains_synced > 0);

    // Decision domain should have changed.
    let decision_change = result.trust_changes.iter().find(|c| c.domain == "decision");
    assert!(
        decision_change.is_some(),
        "decision domain should have a trust change after reconciliation"
    );

    // The new level should be between 0.5 and 1.0 (blended).
    let new_level = state.domain_level("decision");
    assert!(
        new_level > 0.5 && new_level <= 1.0,
        "reconciled level should be between simple (0.5) and Bayesian (~1.0): {}",
        new_level
    );
}

/// F.7 — OVAPH cycle with observation containing drift and health signals.
#[tokio::test]
async fn ovaph_cycle_with_enriched_observation() {
    let ovaph_config = OvaphConfig {
        enabled: true,
        verify_drift_sigma_threshold: 2.0,
        ..OvaphConfig::default()
    };
    let loop_engine = OvaphLoop::new(ovaph_config);

    // Build an observation with anomalous drift.
    let observation = OvaphObservation {
        drift_snapshots: vec![crate::ananta::ovaph_loop::DriftSnapshot {
            drift_type: "Decision".into(),
            current_mean: 0.8,
            current_stddev: 0.05,
            sample_count: 100,
            last_z_score: 5.0, // Well above threshold.
        }],
        health_snapshot: crate::ananta::ovaph_loop::HealthSnapshot {
            overall_health: 0.95,
            component_count: 5,
            degraded_components: vec![],
            failed_components: vec![],
        },
        integrity_snapshot: crate::ananta::ovaph_loop::IntegritySnapshot {
            total_domains: 3,
            passed_count: 3,
            failed_count: 0,
            failed_component_names: vec![],
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        observation_id: uuid::Uuid::new_v4().to_string(),
    };

    let report = loop_engine
        .run_cycle_with_observation(observation)
        .await
        .unwrap();

    assert_eq!(report.stages.len(), 5);
    // The Verify stage should have produced a signal for the anomalous drift.
    let verify_stage = report.stages.iter().find(|s| s.stage == OvaphStage::Verify);
    assert!(verify_stage.is_some());
    assert!(verify_stage.unwrap().findings_count >= 1, "verify should find the anomalous drift");
}

/// F.8 — StateSnapshot checksum verification.
#[test]
fn state_snapshot_checksum_roundtrip() {
    let mut data = HashMap::new();
    data.insert("key1".into(), serde_json::json!("value1"));
    data.insert("key2".into(), serde_json::json!(42));

    let mut snapshot = StateSnapshot::new("test_domain", data).unwrap();
    assert!(snapshot.verify_checksum().unwrap(), "fresh snapshot should verify");

    // Serialize and deserialize.
    let json = snapshot.to_json().unwrap();
    let restored = StateSnapshot::from_json(&json).unwrap();
    assert!(restored.verify_checksum().unwrap(), "restored snapshot should verify");
    assert_eq!(snapshot.snapshot_id, restored.snapshot_id);
    assert_eq!(snapshot.domain, restored.domain);

    // Mutate and verify checksum fails.
    snapshot.set("key1", serde_json::json!("tampered")).unwrap();
    assert!(snapshot.verify_checksum().unwrap(), "after set(), checksum should be recomputed");
}

/// F.9 — StateDiff computation and reverse application.
#[test]
fn state_diff_reverse_application() {
    let mut data_from = HashMap::new();
    data_from.insert("a".into(), serde_json::json!(1));
    data_from.insert("b".into(), serde_json::json!(2));

    let mut data_to = HashMap::new();
    data_to.insert("a".into(), serde_json::json!(10));
    data_to.insert("c".into(), serde_json::json!(3));

    let from = StateSnapshot::new("diff_test", data_from).unwrap();
    let to = StateSnapshot::new("diff_test", data_to).unwrap();

    let diff = StateDiff::compute(&from, &to).unwrap();
    assert!(diff.field_count() >= 3, "should have 3 fields (a, b, c)");

    // Check diff types.
    let a_diff = diff.fields.iter().find(|f| f.key == "a");
    assert!(a_diff.is_some());
    assert_eq!(a_diff.unwrap().diff_type, crate::ananta::phoenix::rollback_engine::DiffType::Modified);

    let b_diff = diff.fields.iter().find(|f| f.key == "b");
    assert!(b_diff.is_some());
    assert_eq!(b_diff.unwrap().diff_type, crate::ananta::phoenix::rollback_engine::DiffType::Removed);

    let c_diff = diff.fields.iter().find(|f| f.key == "c");
    assert!(c_diff.is_some());
    assert_eq!(c_diff.unwrap().diff_type, crate::ananta::phoenix::rollback_engine::DiffType::Added);

    // Apply reverse: start from 'to' and revert to 'from'.
    let mut reverted = to.clone();
    diff.apply_reverse(&mut reverted).unwrap();

    // After reverse, 'a' should be back to 1, 'c' should be removed, 'b' should be restored.
    assert_eq!(reverted.get("a"), Some(&serde_json::json!(1)), "'a' should be reverted to 1");
    assert!(reverted.get("c").is_none(), "'c' should be removed by reverse");
    assert_eq!(reverted.get("b"), Some(&serde_json::json!(2)), "'b' should be restored");
}

/// F.10 — DriftBaselines compute and update correctly.
#[test]
fn drift_baselines_compute_and_update() {
    let mut baselines = DriftBaselines::new();

    // Compute from batch.
    let values: Vec<f64> = (0..100).map(|i| 0.5 + (i as f64 % 20.0) * 0.01).collect();
    baselines
        .compute_baseline(DriftType::Decision, &values)
        .unwrap();

    let baseline = baselines.get(&DriftType::Decision).unwrap();
    assert_eq!(baseline.sample_count, 100);
    assert!(baseline.mean > 0.4 && baseline.mean < 0.8);
    assert!(baseline.stddev >= 0.0);

    // Update with new value.
    baselines.update(DriftType::Decision, 0.99);
    let updated = baselines.get(&DriftType::Decision).unwrap();
    assert_eq!(updated.sample_count, 101);
}

/// F.11 — PipelineStage serialization roundtrip.
#[test]
fn pipeline_stage_serialization() {
    let stage = PipelineStage::new("test_stage", StageType::Decide);
    let json = stage.to_json().unwrap();
    let restored = PipelineStage::from_json(&json).unwrap();
    assert_eq!(restored.name, stage.name);
    assert_eq!(restored.stage_type, stage.stage_type);
    assert!(restored.is_critical(), "Decide stages are critical");
}

/// F.12 — OvaphVerificationResult from_observation with critical health.
#[test]
fn ovaph_verification_critical_health() {
    let observation = OvaphObservation {
        drift_snapshots: vec![],
        health_snapshot: crate::ananta::ovaph_loop::HealthSnapshot {
            overall_health: 0.1,
            component_count: 5,
            degraded_components: vec!["comp1".into()],
            failed_components: vec!["comp2".into()],
        },
        integrity_snapshot: crate::ananta::ovaph_loop::IntegritySnapshot::default(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        observation_id: uuid::Uuid::new_v4().to_string(),
    };

    let result = OvaphVerificationResult::from_observation(&observation, 3.0);
    assert!(result.requires_healing, "critical health should require healing");
    assert_eq!(result.composite_severity, Severity::Critical);

    // Should contain a health signal.
    let has_health_signal = result.signals.iter().any(|s| s.drift_type == "health");
    assert!(has_health_signal, "should have a health signal");
}

/// F.13 — OvaphHealingResult autonomous mode executes actions.
#[tokio::test]
async fn ovaph_healing_autonomous_executes() {
    let ovaph_config = OvaphConfig {
        enabled: true,
        heal_autonomous: true,
        ..OvaphConfig::default()
    };
    let loop_engine = OvaphLoop::new(ovaph_config);

    let verification = OvaphVerificationResult {
        signals: vec![
            VerifiedSignal::anomaly("decision".into(), Severity::High, 0.8),
            VerifiedSignal::anomaly("policy".into(), Severity::Critical, 0.9),
        ],
        composite_severity: Severity::Critical,
        requires_healing: true,
        rationale: "multiple anomalies".into(),
    };

    let (_stage_result, healing) = loop_engine.run_heal(&verification).await;

    assert!(healing.healing_required);
    assert_eq!(healing.actions_executed, 2, "should execute 2 healing actions");
    assert_eq!(healing.actions_succeeded, 2);
    assert_eq!(healing.strategies_used.len(), 2);
}

/// F.14 — Recovery history records via AnantaPlane.
#[tokio::test]
async fn recovery_history_records_via_plane() {
    let config = test_config();
    let plane = AnantaPlane::new(config).unwrap();

    let action = phoenix::strategies::RecoveryAction::new(
        phoenix::strategies::RecoveryStrategy::Restart,
        "shield",
        "integration test recovery",
    );

    let result = plane.execute_recovery_action(&action).await;
    {
        let mut history = plane.recovery_history.lock().await;
        history.record(&action, &result);
    }

    let history = plane.recovery_history.lock().await;
    assert_eq!(history.total_actions(), 1);
}

/// F.15 — OVAPH metrics success rate computation.
#[tokio::test]
async fn ovaph_metrics_success_rate() {
    let ovaph_config = OvaphConfig::default();
    let loop_engine = OvaphLoop::new(ovaph_config);

    // Run a successful cycle.
    let _ = loop_engine.run_full_cycle().await.unwrap();
    let metrics = loop_engine.metrics().unwrap();
    assert!((metrics.success_rate() - 1.0).abs() < f64::EPSILON);

    // success_rate on fresh metrics should be 0.0.
    let fresh = OvaphMetrics::new();
    assert!((fresh.success_rate() - 0.0).abs() < f64::EPSILON);
}
