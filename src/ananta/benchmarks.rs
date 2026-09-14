// ═══════════════════════════════════════════════════════════════
// ANANTA Benchmarks — Phase B
//
// Criterion benchmarks for all ANANTA subsystems including
// Phase B additions.
//
// Categories:
//   A. OVAPH Loop          (4 benches)
//   B. Sentinel             (3 benches)
//   C. Trust Engine        (3 benches)
//   D. Phoenix Rollback    (3 benches)
//   E. Adapter Pipeline    (3 benches)
//   F. Anchor/Crypto       (3 benches)
//   G. Full Pipeline       (2 benches)
//
// Total: 21 bench functions across 7 groups.
// ═══════════════════════════════════════════════════════════════

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ananta::adapter::{
    AdaptationProposal, AdaptationStatus, Adapter, ParameterChange, PipelineConfig,
    PipelineExecutor, PipelineStage, PipelineValidator, StageType,
};
use crate::ananta::anchor::integrity::IntegrityDomain;
use crate::ananta::anchor::{IntegrityChecker, Manifest, TrustChain};
use crate::ananta::config::{AdapterConfig, AnantaConfig, HashAlgorithm};
use crate::ananta::ovaph_loop::{
    CycleOutcome, DriftSnapshot, HealthSnapshot, IntegritySnapshot as OvaphIntegritySnapshot,
    OvaphConfig, OvaphCycleId, OvaphCycleReport, OvaphLoop, OvaphMetrics, OvaphObservation,
    OvaphStage, StageResult,
};
use crate::ananta::phoenix::rollback_engine::{
    RollbackConfig, RollbackExecutor, SnapshotStore, StateDiff, StateSnapshot,
};
use crate::ananta::sentinel::sentinel_wiring::{DriftBaselines, FusionConfig, SentinelHub};
use crate::ananta::sentinel::{DriftDetector, DriftObservation, DriftType};
use crate::ananta::trust::trust_engine::BayesianTrustEngine;
use crate::ananta::trust::TrustState;

// ═══════════════════════════════════════════════════════════════
// Helper factories
// ═══════════════════════════════════════════════════════════════

/// Build an OvaphConfig with all stages enabled for benchmarking.
fn bench_ovaph_config() -> OvaphConfig {
    OvaphConfig {
        enabled: true,
        interval_ms: 30_000,
        observe_baseline_observations: 5,
        verify_drift_sigma_threshold: 3.0,
        attest_sign_reports: false,
        heal_autonomous: false,
        prove_generate_proof: false,
        max_cycle_duration_ms: 60_000,
        stage_timeout_ms: 10_000,
    }
}

/// Build a sample OvaphObservation with drift snapshots.
fn bench_observation() -> OvaphObservation {
    let drift_snapshots: Vec<DriftSnapshot> = DriftType::all()
        .iter()
        .map(|dt| DriftSnapshot {
            drift_type: format!("{:?}", dt),
            current_mean: 0.85,
            current_stddev: 0.03,
            sample_count: 100,
            last_z_score: 0.5,
        })
        .collect();
    OvaphObservation {
        drift_snapshots,
        health_snapshot: HealthSnapshot {
            overall_health: 0.95,
            component_count: 10,
            degraded_components: vec![],
            failed_components: vec![],
        },
        integrity_snapshot: OvaphIntegritySnapshot {
            total_domains: 7,
            passed_count: 7,
            failed_count: 0,
            failed_component_names: vec![],
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        observation_id: uuid::Uuid::new_v4().to_string(),
    }
}

/// Build a DriftObservation for a given drift type and value.
fn bench_drift_obs(dt: DriftType, value: f64) -> DriftObservation {
    DriftObservation {
        drift_type: dt,
        value,
        context: "bench".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

/// Build a DriftBaselines instance.
fn bench_baselines() -> DriftBaselines {
    DriftBaselines::new()
}

/// Build a FusionConfig with low thresholds so fusion fires easily.
fn bench_fusion_config() -> FusionConfig {
    FusionConfig {
        require_both_detectors: false,
        advanced_methods: vec!["ks".to_string()],
        baseline_min_samples: 5,
        correlation_window_seconds: 60,
        z_score_weight: 0.6,
        advanced_weight: 0.4,
    }
}

/// Build a sample AnantaConfig for AnantaPlane benchmarks.
fn bench_ananta_config() -> AnantaConfig {
    let mut config = AnantaConfig::default();
    config.state_path = std::env::temp_dir()
        .join("ananta_bench")
        .to_string_lossy()
        .to_string();
    config
}

/// Build a HashMap of sample data for snapshots.
fn bench_snapshot_data(size: usize) -> HashMap<String, serde_json::Value> {
    let mut data = HashMap::new();
    for i in 0..size {
        data.insert(
            format!("key_{}", i),
            serde_json::json!({
                "value": i as f64,
                "enabled": true,
                "tags": ["a", "b", "c"],
            }),
        );
    }
    data
}

/// Build a PipelineConfig with several stages.
fn bench_pipeline_config() -> PipelineConfig {
    let mut config = PipelineConfig::new();
    for i in 0..5 {
        config
            .add_stage(PipelineStage::new(
                &format!("stage_{}", i),
                StageType::Filter,
            ))
            .unwrap();
    }
    config
}

/// Build an AdaptationProposal for pipeline benchmarks.
fn bench_proposal() -> AdaptationProposal {
    AdaptationProposal {
        proposal_id: uuid::Uuid::new_v4().to_string(),
        target: "pipeline".to_string(),
        description: "Benchmark adaptation".to_string(),
        parameter_changes: vec![ParameterChange {
            parameter: "threat_threshold".to_string(),
            old_value: serde_json::json!(0.5),
            new_value: serde_json::json!(0.4),
        }],
        trust_level_at_proposal: 0.85,
        rationale: "Benchmark proposal".to_string(),
        signature: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        grace_deadline: chrono::Utc::now().to_rfc3339(),
        status: AdaptationStatus::Proposed,
    }
}

// ═══════════════════════════════════════════════════════════════
// Group A: OVAPH Loop — 4 benches
// ═══════════════════════════════════════════════════════════════

/// A1: Run a full OVAPH cycle through all five stages.
fn bench_ovaph_single_cycle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = bench_ovaph_config();

    c.bench_function("ovaph/single_cycle", |b| {
        b.to_async(&rt).iter_with_setup(
            || OvaphLoop::new(config.clone()),
            |loop_| async move {
                let result = loop_.run_full_cycle().await;
                black_box(&result);
            },
        );
    });
}

/// A2: Run only the Observe stage with a populated observation.
fn bench_ovaph_observe_stage(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = bench_ovaph_config();
    let observation = bench_observation();

    c.bench_function("ovaph/observe_stage", |b| {
        b.to_async(&rt).iter_with_setup(
            || (OvaphLoop::new(config.clone()), observation.clone()),
            |(loop_, obs)| async move {
                let (result, _) = loop_.run_observe(obs).await;
                black_box(&result);
            },
        );
    });
}

/// A3: Run only the Verify stage with a sample observation.
fn bench_ovaph_verify_stage(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = bench_ovaph_config();
    let observation = bench_observation();

    c.bench_function("ovaph/verify_stage", |b| {
        b.to_async(&rt).iter_with_setup(
            || (OvaphLoop::new(config.clone()), observation.clone()),
            |(loop_, obs)| async move {
                let (result, _) = loop_.run_verify(&obs).await;
                black_box(&result);
            },
        );
    });
}

/// A4: Record 1000 synthetic cycle reports into OvaphMetrics.
fn bench_ovaph_metrics_record(c: &mut Criterion) {
    c.bench_function("ovaph/metrics_record_1000", |b| {
        b.iter_with_setup(
            || {
                // Pre-build 1000 synthetic reports.
                let mut reports = Vec::with_capacity(1000);
                for i in 0..1000 {
                    reports.push(OvaphCycleReport {
                        cycle_id: OvaphCycleId {
                            cycle_number: i,
                            started_at: chrono::Utc::now().to_rfc3339(),
                            cycle_id: uuid::Uuid::new_v4().to_string(),
                        },
                        cycle_number: i,
                        stages: OvaphStage::all()
                            .iter()
                            .map(|&s| StageResult::completed(s, 10, 0))
                            .collect(),
                        total_duration_ms: 50,
                        trust_before: 0.95,
                        trust_after: 0.96,
                        recovery_actions_taken: 0,
                        attestation_passed: true,
                        trust_proof_generated: true,
                        overall_outcome: CycleOutcome::AllCompleted,
                    });
                }
                reports
            },
            |reports| {
                let mut metrics = OvaphMetrics::new();
                for report in &reports {
                    metrics.record_cycle(report);
                }
                black_box(&metrics);
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group B: Sentinel — 3 benches
// ═══════════════════════════════════════════════════════════════

/// B1: Feed 1000 observations across all drift types to DriftDetector.
fn bench_drift_detector_observe(c: &mut Criterion) {
    let drift_types = DriftType::all().to_vec();
    let observations: Vec<DriftObservation> = (0..1000)
        .map(|i| {
            let dt = &drift_types[i % drift_types.len()];
            bench_drift_obs(dt.clone(), 0.85 + (i as f64 * 0.0001))
        })
        .collect();

    c.bench_function("sentinel/drift_detector_observe_1000", |b| {
        b.iter_with_setup(
            || DriftDetector::new(3.0, 100),
            |mut detector| {
                for obs in &observations {
                    let result = detector.observe(obs.clone());
                    black_box(&result);
                }
                black_box(&detector);
            },
        );
    });
}

/// B2: Update DriftBaselines 1000 times across all drift types.
fn bench_drift_detector_baseline(c: &mut Criterion) {
    let drift_types = DriftType::all().to_vec();
    let values: Vec<(DriftType, f64)> = (0..1000)
        .map(|i| {
            let dt = drift_types[i % drift_types.len()].clone();
            (dt, 0.85 + (i as f64 * 0.0002 - 0.1))
        })
        .collect();

    c.bench_function("sentinel/drift_baseline_update_1000", |b| {
        b.iter_with_setup(
            || bench_baselines(),
            |mut baselines| {
                for (dt, val) in &values {
                    baselines.update(dt.clone(), *val);
                }
                black_box(&baselines);
            },
        );
    });
}

/// B3: Process 1000 observations through SentinelHub (simple + advanced fusion).
fn bench_sentinel_hub_fuse(c: &mut Criterion) {
    let drift_types = DriftType::all().to_vec();
    let observations: Vec<DriftObservation> = (0..1000)
        .map(|i| {
            let dt = &drift_types[i % drift_types.len()];
            bench_drift_obs(dt.clone(), 0.85 + (i as f64 * 0.001 - 0.5))
        })
        .collect();

    let fusion_config = bench_fusion_config();

    c.bench_function("sentinel/hub_fuse_1000", |b| {
        b.iter_with_setup(
            || SentinelHub::new(3.0, 100, fusion_config.clone(), 50).unwrap(),
            |mut hub| {
                for obs in &observations {
                    let result = hub.observe(obs.clone());
                    black_box(&result);
                }
                black_box(&hub);
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group C: Trust Engine — 3 benches
// ═══════════════════════════════════════════════════════════════

/// C1: Add 1000 evidence records to a BayesianTrustEngine via record_evidence.
fn bench_bayesian_add_evidence(c: &mut Criterion) {
    c.bench_function("trust/bayesian_add_evidence_1000", |b| {
        b.iter_with_setup(
            || BayesianTrustEngine::new(),
            |mut engine| {
                for i in 0..1000 {
                    let is_positive = i % 3 != 0;
                    let source = if is_positive {
                        "bench_positive"
                    } else {
                        "bench_negative"
                    };
                    engine.record_evidence("node_a", "node_b", is_positive, 0.8, source);
                }
                black_box(&engine);
            },
        );
    });
}

/// C2: Propagate trust on a 10-node graph 100 times.
fn bench_bayesian_propagate(c: &mut Criterion) {
    c.bench_function("trust/bayesian_propagate_10node_100x", |b| {
        b.iter_with_setup(
            || {
                let mut engine = BayesianTrustEngine::new();
                // Build a 10-node ring graph with edges.
                let nodes: Vec<String> = (0..10).map(|i| format!("node_{}", i)).collect();
                for i in 0..10 {
                    let from = &nodes[i];
                    let to = &nodes[(i + 1) % 10];
                    engine.record_evidence(from, to, true, 1.0, "init");
                    engine.record_evidence(from, to, false, 0.2, "init_neg");
                }
                engine
            },
            |mut engine| {
                for _ in 0..100 {
                    let result = engine.propagate();
                    black_box(&result);
                }
            },
        );
    });
}

/// C3: Set 1000 domain levels on TrustState.
fn bench_trust_state_domain_updates(c: &mut Criterion) {
    let domains: Vec<String> = (0..20).map(|i| format!("domain_{}", i)).collect();

    c.bench_function("trust/domain_updates_1000", |b| {
        b.iter_with_setup(
            || TrustState::new(),
            |mut state| {
                for i in 0..1000 {
                    let domain = &domains[i % domains.len()];
                    let level = 0.5 + (i as f64 % 1.0) * 0.5;
                    state.set_domain_level(domain, level);
                }
                black_box(&state);
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group D: Phoenix Rollback — 3 benches
// ═══════════════════════════════════════════════════════════════

/// D1: Create 100 StateSnapshots with SHA-256 checksum computation.
fn bench_rollback_create_snapshot(c: &mut Criterion) {
    c.bench_function("phoenix/create_snapshot_100", |b| {
        b.iter_with_setup(
            || bench_snapshot_data(20),
            |data| {
                let mut snapshots = Vec::with_capacity(100);
                for i in 0..100 {
                    let mut modified = data.clone();
                    modified.insert(format!("cycle_{}", i), serde_json::json!(i));
                    let snapshot =
                        StateSnapshot::new(&format!("domain_{}", i % 5), modified).unwrap();
                    snapshots.push(snapshot);
                }
                black_box(&snapshots);
            },
        );
    });
}

/// D2: Execute 100 rollbacks via RollbackExecutor.
fn bench_rollback_execute(c: &mut Criterion) {
    c.bench_function("phoenix/rollback_execute_100", |b| {
        b.iter_with_setup(
            || {
                // Pre-build a store with snapshots and get the executor.
                let store = Arc::new(Mutex::new(SnapshotStore::with_defaults()));
                // Populate with snapshots.
                {
                    let mut store_guard = store.lock().unwrap();
                    for i in 0..5 {
                        let data = bench_snapshot_data(10);
                        store_guard
                            .create_snapshot(&format!("domain_{}", i), data)
                            .unwrap();
                    }
                }
                let executor = RollbackExecutor::new(store, RollbackConfig::default());
                executor
            },
            |mut executor| {
                // Execute rollbacks across all 5 domains.
                for i in 0..5 {
                    let domain = format!("domain_{}", i);
                    // Get the snapshot ID from the store.
                    let store = executor.store.lock().unwrap();
                    if let Some(snap) = store.latest(&domain) {
                        let target_id = snap.snapshot_id.clone();
                        drop(store);
                        let result = executor.execute_rollback(&domain, &target_id);
                        black_box(&result);
                    }
                }
                // Do this 20 times to get 100 total rollbacks.
                for _round in 1..20 {
                    for i in 0..5 {
                        let domain = format!("domain_{}", i);
                        let store = executor.store.lock().unwrap();
                        if let Some(snap) = store.latest(&domain) {
                            let target_id = snap.snapshot_id.clone();
                            drop(store);
                            let result = executor.execute_rollback(&domain, &target_id);
                            black_box(&result);
                        }
                    }
                }
            },
        );
    });
}

/// D3: Compute 100 diffs between pairs of snapshots.
fn bench_state_diff_compute(c: &mut Criterion) {
    c.bench_function("phoenix/state_diff_compute_100", |b| {
        b.iter_with_setup(
            || {
                // Pre-build snapshot pairs for diffing.
                let mut pairs = Vec::with_capacity(100);
                for _i in 0..100 {
                    let mut from_data = bench_snapshot_data(15);
                    from_data.insert("version".to_string(), serde_json::json!(1));
                    let from = StateSnapshot::new("bench", from_data).unwrap();

                    let mut to_data = bench_snapshot_data(15);
                    to_data.insert("version".to_string(), serde_json::json!(2));
                    to_data.insert("new_field".to_string(), serde_json::json!("added"));
                    // Remove one key to create a Removed diff.
                    to_data.remove("key_0");
                    let to = StateSnapshot::new("bench", to_data).unwrap();

                    pairs.push((from, to));
                }
                pairs
            },
            |pairs| {
                for (from, to) in &pairs {
                    let diff = StateDiff::compute(from, to).unwrap();
                    black_box(&diff);
                }
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group E: Adapter Pipeline — 3 benches
// ═══════════════════════════════════════════════════════════════

/// E1: Evaluate 100 trust states through the Adapter.
fn bench_adapter_evaluate(c: &mut Criterion) {
    let adapter_config = AdapterConfig {
        enabled: true,
        max_reconfigurations_per_hour: 1000,
        require_signed_changes: false,
        adaptation_grace_period_ms: 300_000,
    };

    c.bench_function("adapter/evaluate_100", |b| {
        b.iter_with_setup(
            || {
                // Pre-build 100 degraded trust states.
                let mut states = Vec::with_capacity(100);
                for i in 0..100 {
                    let mut state = TrustState::new();
                    // Create a degraded state that triggers proposals.
                    let level = 0.3 + (i as f64 % 0.4);
                    state.set_domain_level("decision", level);
                    state.set_domain_level("policy", 0.1 + (i as f64 % 0.3));
                    states.push(state);
                }
                states
            },
            |states| {
                let mut adapter = Adapter::new(adapter_config.clone());
                for state in &states {
                    let proposals = adapter.evaluate(state);
                    black_box(&proposals);
                }
            },
        );
    });
}

/// E2: Validate 100 pipeline configurations through PipelineValidator.
fn bench_pipeline_validate(c: &mut Criterion) {
    c.bench_function("adapter/pipeline_validate_100", |b| {
        b.iter_with_setup(
            || {
                // Pre-build 100 pipeline configs.
                let mut configs = Vec::with_capacity(100);
                for i in 0..100 {
                    let mut config = PipelineConfig::new();
                    let stages_count = 1 + (i % 8); // Vary stage count 1-8
                    for j in 0..stages_count {
                        let stage_type = match j % 5 {
                            0 => StageType::Filter,
                            1 => StageType::Transform,
                            2 => StageType::Enrich,
                            3 => StageType::Decide,
                            _ => StageType::Act,
                        };
                        config
                            .add_stage(PipelineStage::new(&format!("stage_{}", j), stage_type))
                            .unwrap();
                    }
                    configs.push(config);
                }
                configs
            },
            |configs| {
                let validator = PipelineValidator::new();
                for config in &configs {
                    let result = validator.validate(config);
                    black_box(&result);
                }
            },
        );
    });
}

/// E3: Apply 100 adaptations through PipelineExecutor.
fn bench_pipeline_apply_adaptation(c: &mut Criterion) {
    c.bench_function("adapter/apply_adaptation_100", |b| {
        b.iter_with_setup(
            || {
                // Pre-build 100 proposals.
                let proposals: Vec<AdaptationProposal> = (0..100)
                    .map(|i| AdaptationProposal {
                        proposal_id: uuid::Uuid::new_v4().to_string(),
                        target: "pipeline".to_string(),
                        description: format!("Adaptation {}", i),
                        parameter_changes: vec![ParameterChange {
                            parameter: "sensitivity".to_string(),
                            old_value: serde_json::json!(1.0),
                            new_value: serde_json::json!(1.0 + i as f64 * 0.01),
                        }],
                        trust_level_at_proposal: 0.85,
                        rationale: "Benchmark".to_string(),
                        signature: None,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        grace_deadline: chrono::Utc::now().to_rfc3339(),
                        status: AdaptationStatus::Proposed,
                    })
                    .collect();
                proposals
            },
            |proposals| {
                let mut executor = PipelineExecutor::new();
                let mut config = bench_pipeline_config();
                for proposal in &proposals {
                    let result = executor.apply_adaptation(&mut config, proposal);
                    black_box(&result);
                }
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group F: Anchor/Crypto — 3 benches
// ═══════════════════════════════════════════════════════════════

/// F1: Append 1000 links to a TrustChain.
fn bench_trust_chain_append(c: &mut Criterion) {
    c.bench_function("anchor/trust_chain_append_1000", |b| {
        b.iter_with_setup(
            || TrustChain::new(HashAlgorithm::Sha256),
            |mut chain| {
                for i in 0..1000 {
                    let link = chain.append(
                        "attestation",
                        serde_json::json!({
                            "cycle": i,
                            "trust": 0.95,
                            "passed": true,
                        }),
                    );
                    black_box(link);
                }
                black_box(&chain);
            },
        );
    });
}

/// F2: Verify a 1000-link TrustChain's integrity.
fn bench_trust_chain_verify(c: &mut Criterion) {
    c.bench_function("anchor/trust_chain_verify_1000", |b| {
        b.iter_with_setup(
            || {
                // Build a 1000-link chain.
                let mut chain = TrustChain::new(HashAlgorithm::Sha256);
                for i in 0..1000 {
                    chain.append(
                        "attestation",
                        serde_json::json!({
                            "cycle": i,
                            "trust": 0.95,
                        }),
                    );
                }
                chain
            },
            |chain| {
                let result = chain.verify();
                black_box(&result);
            },
        );
    });
}

/// F3: Snapshot 100 integrity domains through IntegrityChecker.
fn bench_integrity_snapshot(c: &mut Criterion) {
    c.bench_function("anchor/integrity_snapshot_100", |b| {
        b.iter_with_setup(
            || {
                // Build an IntegrityChecker with 7 registered providers.
                let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
                let domains = vec![
                    IntegrityDomain::Binary,
                    IntegrityDomain::Config,
                    IntegrityDomain::Policy,
                    IntegrityDomain::AnantaConfig,
                    IntegrityDomain::Runtime,
                    IntegrityDomain::Modules,
                    IntegrityDomain::RingConfig("ring_0".to_string()),
                ];
                for domain in domains {
                    let data_bytes = vec![0u8; 256];
                    checker.register_provider(domain, move || data_bytes.clone());
                }
                let manifest = Manifest::new(HashAlgorithm::Sha256);
                (checker, manifest)
            },
            |(checker, manifest)| {
                for _ in 0..100 {
                    let snapshot = checker.snapshot(&manifest);
                    black_box(&snapshot);
                }
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Group G: Full Pipeline — 2 benches
// ═══════════════════════════════════════════════════════════════

/// G1: Run a full OVAPH cycle on the AnantaPlane (all subsystems together).
fn bench_full_ovaph_with_plane(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("pipeline/full_ovaph_with_plane", |b| {
        b.to_async(&rt).iter_with_setup(
            || {
                let config = bench_ananta_config();
                let plane = crate::ananta::AnantaPlane::new(config).unwrap();
                plane
            },
            |plane| async move {
                let result = plane.run_ovaph_cycle().await;
                black_box(&result);
            },
        );
    });
}

/// G2: Create AnantaPlane 100 times (measures full construction cost).
fn bench_ananta_plane_creation(c: &mut Criterion) {
    c.bench_function("pipeline/ananta_plane_creation_100", |b| {
        b.iter_with_setup(
            || bench_ananta_config(),
            |config| {
                // Use block_on for each creation since AnantaPlane::new is sync.
                for _ in 0..100 {
                    let result = crate::ananta::AnantaPlane::new(config.clone());
                    black_box(&result);
                }
            },
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// Criterion group registration
// ═══════════════════════════════════════════════════════════════

fn ovaph_benches(c: &mut Criterion) {
    bench_ovaph_single_cycle(c);
    bench_ovaph_observe_stage(c);
    bench_ovaph_verify_stage(c);
    bench_ovaph_metrics_record(c);
}

fn sentinel_benches(c: &mut Criterion) {
    bench_drift_detector_observe(c);
    bench_drift_detector_baseline(c);
    bench_sentinel_hub_fuse(c);
}

fn trust_benches(c: &mut Criterion) {
    bench_bayesian_add_evidence(c);
    bench_bayesian_propagate(c);
    bench_trust_state_domain_updates(c);
}

fn phoenix_benches(c: &mut Criterion) {
    bench_rollback_create_snapshot(c);
    bench_rollback_execute(c);
    bench_state_diff_compute(c);
}

fn adapter_benches(c: &mut Criterion) {
    bench_adapter_evaluate(c);
    bench_pipeline_validate(c);
    bench_pipeline_apply_adaptation(c);
}

fn anchor_benches(c: &mut Criterion) {
    bench_trust_chain_append(c);
    bench_trust_chain_verify(c);
    bench_integrity_snapshot(c);
}

fn pipeline_benches(c: &mut Criterion) {
    bench_full_ovaph_with_plane(c);
    bench_ananta_plane_creation(c);
}

criterion_group!(
    benches,
    ovaph_benches,
    sentinel_benches,
    trust_benches,
    phoenix_benches,
    adapter_benches,
    anchor_benches,
    pipeline_benches,
);

criterion_main!(benches);
