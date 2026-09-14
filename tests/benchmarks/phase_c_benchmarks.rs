// Phase C — Comprehensive Performance Benchmarks for CHAKRAVYUH
//
// Covers 6 hot-path categories:
//   1. Keshav Decision Pipeline (full 9-ring evaluate)
//   2. Policy VM Execution
//   3. ANANTA Crypto
//   4. Cross-Ring Message Passing
//   5. Storage Operations
//   6. ANANTA Trust Engine
//
// Run with: cargo bench --bench phase_c_benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;

use chakravyuh::{
    agent::AgentRing,
    ananta::{
        config::HashAlgorithm as AnantaHashAlgorithm,
        crypto::{
            encryption::{decrypt, encrypt},
            hashing::hash_bytes,
            merkle::MerkleTree,
            signing::{sign, verify, KeyPair},
            threshold::{
                lagrange_interpolate_at_zero, PartialSignature, ShamirScheme, ThresholdSigner,
            },
        },
        trust::trust_decay::TrustDecayEngine,
        trust::trust_engine::BayesianTrustEngine,
    },
    cross_ring::{CrossRingMessage, CrossRingNetwork, CrossRingType},
    execution::ExecutionRing,
    governance::GovernanceRing,
    identity::IdentityRing,
    keshav::{
        decide::KeshavDecide,
        executor::{PipelineContext, PipelineExecutor},
        orchestrate::{KeshavOrchestrate, RequestType},
        policy_engine::{Policy, PolicyEngine},
        risk::KeshavRisk,
        AllRingVerdicts,
    },
    memory::MemoryRing,
    policy_compiler::{PolicyCompiler, PolicyCompilerConfig, PolicyInput},
    reasoning::ReasoningRing,
    shield::{ShieldRequest, ShieldRing},
    storage::{CachedStore, MemoryStore, Store},
    threat::ThreatRing,
    Config,
};

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn make_shield_request(prompt: &str) -> ShieldRequest {
    ShieldRequest {
        source_ip: "1.2.3.4".into(),
        user_agent: Some("bench/1.0".into()),
        api_key: Some("bench-key".into()),
        user_id: Some("bench-user".into()),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        headers: Default::default(),
        body: serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": prompt}]
        }),
    }
}

fn make_pipeline_executor() -> PipelineExecutor {
    let config: Config = Config::default_yaml().parse().unwrap();
    let config = Arc::new(config);
    PipelineExecutor {
        shield: ShieldRing::new(config.clone()).unwrap(),
        threat: ThreatRing::new(Arc::new(config.threat.clone())).unwrap(),
        identity: IdentityRing::new(&config.identity).unwrap(),
        memory: MemoryRing::new(&config.memory).unwrap(),
        agent: AgentRing::new(&config.agent).unwrap(),
        execution: ExecutionRing::new(&config.execution).unwrap(),
        reasoning: ReasoningRing::new(&config.reasoning).unwrap(),
        governance: GovernanceRing::new(&config.governance).unwrap(),
        decide: KeshavDecide::with_defaults().unwrap(),
        risk: KeshavRisk::new(config.keshav.risk.clone()),
    }
}

fn make_simple_prompt_context() -> PipelineContext {
    PipelineContext {
        shield_request: make_shield_request("What is the capital of France?"),
        request_id: uuid::Uuid::new_v4().to_string(),
        prompt_text: "What is the capital of France?".into(),
        tool_call: None,
    }
}

fn make_tool_call_context() -> PipelineContext {
    PipelineContext {
        shield_request: make_shield_request("Please run the deploy script"),
        request_id: uuid::Uuid::new_v4().to_string(),
        prompt_text: "Please run the deploy script".into(),
        tool_call: Some(chakravyuh::ToolCallContext {
            tool_name: "bash".into(),
            parameters: serde_json::json!({"command": "./deploy.sh"}),
            agent_id: Some("agent-42".into()),
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Keshav Decision Pipeline
// ═══════════════════════════════════════════════════════════════════════

fn bench_pipeline_simple_prompt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let executor = Arc::new(make_pipeline_executor());
    let orch = KeshavOrchestrate::with_defaults();
    let plan = Arc::new(orch.plan(RequestType::SimplePrompt, false));

    let mut group = c.benchmark_group("keshav/pipeline_executor");
    group.throughput(Throughput::Elements(1));
    group.bench_function("simple_prompt", |b| {
        b.to_async(&rt).iter(|| {
            let ctx = make_simple_prompt_context();
            let executor = executor.clone();
            let plan = plan.clone();
            async move {
                let result = executor.execute(black_box(&plan), black_box(&ctx)).await;
                black_box(result);
            }
        });
    });
    group.finish();
}

fn bench_pipeline_tool_call(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let executor = Arc::new(make_pipeline_executor());
    let orch = KeshavOrchestrate::with_defaults();
    let plan = Arc::new(orch.plan(RequestType::SimplePrompt, true)); // has_tool_call overrides to ToolCall

    let mut group = c.benchmark_group("keshav/pipeline_executor");
    group.throughput(Throughput::Elements(1));
    group.bench_function("tool_call", |b| {
        b.to_async(&rt).iter(|| {
            let ctx = make_tool_call_context();
            let executor = executor.clone();
            let plan = plan.clone();
            async move {
                let result = executor.execute(black_box(&plan), black_box(&ctx)).await;
                black_box(result);
            }
        });
    });
    group.finish();
}

fn bench_keshav_decide_evaluate(c: &mut Criterion) {
    let decide = KeshavDecide::with_defaults().unwrap();
    let config: Config = Config::default_yaml().parse().unwrap();
    let config = Arc::new(config);
    let shield = ShieldRing::new(config.clone()).unwrap();
    let threat = ThreatRing::new(Arc::new(config.threat.clone())).unwrap();
    let req = make_shield_request("Hello, world");

    let shield_verdict = shield.evaluate(&req);
    let threat_verdict = threat.evaluate(&req);

    let mut group = c.benchmark_group("keshav/decide");
    group.throughput(Throughput::Elements(1));
    group.bench_function("evaluate_shield_only", |b| {
        b.iter(|| {
            let record =
                decide.evaluate(black_box(&shield_verdict), None, "bench-req-1", "1.2.3.4");
            black_box(record);
        });
    });
    group.bench_function("evaluate_with_threat", |b| {
        b.iter(|| {
            let record = decide.evaluate(
                black_box(&shield_verdict),
                Some(black_box(&threat_verdict)),
                "bench-req-2",
                "1.2.3.4",
            );
            black_box(record);
        });
    });
    group.finish();
}

fn bench_keshav_decide_evaluate_all(c: &mut Criterion) {
    let decide = KeshavDecide::with_defaults().unwrap();
    let config: Config = Config::default_yaml().parse().unwrap();
    let config = Arc::new(config);
    let shield = ShieldRing::new(config.clone()).unwrap();
    let threat = ThreatRing::new(Arc::new(config.threat.clone())).unwrap();
    let req = make_shield_request("Hello, world");

    let shield_verdict = shield.evaluate(&req);
    let threat_verdict = threat.evaluate(&req);

    // Create minimal optional verdicts for all rings
    let identity_verdict = chakravyuh::identity::IdentityVerdict {
        decision: chakravyuh::Decision::Allow,
        identity_profile: None,
        role: None,
        trust_result: None,
        anomaly_result: None,
        engine_results: vec![],
        latency_ms: 0.5,
        identity_risk_score: 0.1,
    };
    let memory_verdict = chakravyuh::memory::MemoryVerdict {
        decision: chakravyuh::Decision::Allow,
        pii_findings: None,
        conversation_state: None,
        rag_verdict: None,
        provenance_verdict: None,
        access_verdict: None,
        engine_results: vec![],
        latency_ms: 0.3,
        memory_risk_score: 0.0,
    };
    let agent_verdict = chakravyuh::agent::AgentVerdict {
        decision: chakravyuh::Decision::Allow,
        agent_type: None,
        effective_permissions: vec![],
        scope_verdict: None,
        behavior_analysis: None,
        chain_risk: None,
        engine_results: vec![],
        latency_ms: 0.4,
        behavior_risk_score: 0.1,
    };
    let execution_verdict = chakravyuh::execution::ExecutionVerdict {
        decision: chakravyuh::Decision::Allow,
        engine_results: vec![],
        sandbox_config: None,
        approval_request: None,
        latency_ms: 0.2,
    };

    let mut group = c.benchmark_group("keshav/decide");
    group.throughput(Throughput::Elements(1));
    group.bench_function("evaluate_all_full_9ring", |b| {
        b.iter(|| {
            let record = decide.evaluate_all(
                black_box(&shield_verdict),
                Some(black_box(&threat_verdict)),
                Some(black_box(&identity_verdict)),
                Some(black_box(&memory_verdict)),
                Some(black_box(&agent_verdict)),
                Some(black_box(&execution_verdict)),
                "bench-req-full",
                "1.2.3.4",
            );
            black_box(record);
        });
    });
    group.finish();
}

fn bench_policy_engine_evaluate_all(c: &mut Criterion) {
    let engine = PolicyEngine::new(Policy::default());

    let shield_verdict = chakravyuh::shield::ShieldVerdict {
        decision: chakravyuh::Decision::Allow,
        engine_results: vec![],
        latency_ms: 0.5,
    };
    let threat_verdict = chakravyuh::threat::ThreatVerdict {
        decision: chakravyuh::Decision::Allow,
        engine_results: vec![],
        composite_score: 0.1,
        confidence: 0.9,
        matched_signatures: vec![],
        latency_ms: 1.0,
    };
    let identity_verdict = chakravyuh::identity::IdentityVerdict {
        decision: chakravyuh::Decision::Allow,
        identity_profile: None,
        role: None,
        trust_result: None,
        anomaly_result: None,
        engine_results: vec![],
        latency_ms: 0.5,
        identity_risk_score: 0.1,
    };
    let memory_verdict = chakravyuh::memory::MemoryVerdict {
        decision: chakravyuh::Decision::Allow,
        pii_findings: None,
        conversation_state: None,
        rag_verdict: None,
        provenance_verdict: None,
        access_verdict: None,
        engine_results: vec![],
        latency_ms: 0.3,
        memory_risk_score: 0.0,
    };
    let agent_verdict = chakravyuh::agent::AgentVerdict {
        decision: chakravyuh::Decision::Allow,
        agent_type: None,
        effective_permissions: vec![],
        scope_verdict: None,
        behavior_analysis: None,
        chain_risk: None,
        engine_results: vec![],
        latency_ms: 0.4,
        behavior_risk_score: 0.1,
    };
    let execution_verdict = chakravyuh::execution::ExecutionVerdict {
        decision: chakravyuh::Decision::Allow,
        engine_results: vec![],
        sandbox_config: None,
        approval_request: None,
        latency_ms: 0.2,
    };

    let all_verdicts = AllRingVerdicts {
        shield: &shield_verdict,
        threat: Some(&threat_verdict),
        identity: Some(&identity_verdict),
        memory: Some(&memory_verdict),
        agent: Some(&agent_verdict),
        execution: Some(&execution_verdict),
        reasoning: None,
        governance: None,
        recovery: None,
    };
    let risk = chakravyuh::RiskScore::default();

    let mut group = c.benchmark_group("keshav/policy_engine");
    group.throughput(Throughput::Elements(1));
    group.bench_function("evaluate_all_rings", |b| {
        b.iter(|| {
            let result = engine.evaluate_all(black_box(&all_verdicts), black_box(&risk));
            black_box(result);
        });
    });
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Policy VM Execution
// ═══════════════════════════════════════════════════════════════════════

fn bench_policy_vm_execution(c: &mut Criterion) {
    // Build policies of varying sizes by repeating rules
    let small_policy = build_vm_policy(10);
    let medium_policy = build_vm_policy(50);
    let large_policy = build_vm_policy(200);

    let mut compiler = PolicyCompiler::new(PolicyCompilerConfig::default()).unwrap();
    let compiled_small = compiler.compile_yaml(&small_policy).unwrap();
    let compiled_medium = compiler.compile_yaml(&medium_policy).unwrap();
    let compiled_large = compiler.compile_yaml(&large_policy).unwrap();

    let input = PolicyInput::new("bench-req", "1.2.3.4", "Hello, world");

    let mut group = c.benchmark_group("policy_vm/execute");
    group.throughput(Throughput::Elements(1));
    for (name, compiled) in [
        ("10_instructions", &compiled_small),
        ("50_instructions", &compiled_medium),
        ("200_instructions", &compiled_large),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), compiled, |b, prog| {
            b.iter(|| {
                let result = compiler.execute(prog, black_box(&input));
                let _ = black_box(result);
            });
        });
    }
    group.finish();
}

fn bench_policy_compiler_compile(c: &mut Criterion) {
    let policy_yaml = build_vm_policy(50);

    let mut group = c.benchmark_group("policy_compiler");
    group.throughput(Throughput::Elements(1));
    group.bench_function("compile_yaml_50_rules", |b| {
        b.iter(|| {
            let mut compiler = PolicyCompiler::new(PolicyCompilerConfig::default()).unwrap();
            let result = compiler.compile_yaml(black_box(&policy_yaml));
            let _ = black_box(result);
        });
    });
    group.finish();
}

/// Build a YAML policy with the given number of deny rules.
fn build_vm_policy(num_rules: usize) -> String {
    let mut rules = String::new();
    for i in 0..num_rules {
        rules.push_str(&format!(
            r#"  - name: "rule_{}"
    action: "deny"
    condition: 'payload.contains("pattern_{}")'
    enabled: true
    risk_weight: 0.1
"#,
            i, i
        ));
    }
    format!(
        r#"version: "1.0"
name: "bench-policy"
rules:
{}"#,
        rules
    )
}

// ═══════════════════════════════════════════════════════════════════════
// 3. ANANTA Crypto
// ═══════════════════════════════════════════════════════════════════════

fn bench_hashing(c: &mut Criterion) {
    let data_1kb = vec![0xABu8; 1024];
    let data_10kb = vec![0xCDu8; 10 * 1024];
    let data_100kb = vec![0xEFu8; 100 * 1024];

    let algos = [
        ("sha256", AnantaHashAlgorithm::Sha256),
        ("sha384", AnantaHashAlgorithm::Sha384),
        ("sha512", AnantaHashAlgorithm::Sha512),
        ("blake3", AnantaHashAlgorithm::Blake3),
    ];
    let sizes = [
        ("1kb", &data_1kb[..]),
        ("10kb", &data_10kb[..]),
        ("100kb", &data_100kb[..]),
    ];

    let mut group = c.benchmark_group("ananta/crypto/hashing");
    for (algo_name, algo) in &algos {
        for (size_name, data) in &sizes {
            let _label = format!("{}/{}", algo_name, size_name);
            group.throughput(Throughput::Bytes(data.len() as u64));
            group.bench_with_input(BenchmarkId::new(*algo_name, size_name), data, |b, d| {
                b.iter(|| {
                    let digest = hash_bytes(black_box(d), black_box(algo));
                    black_box(digest);
                });
            });
        }
    }
    group.finish();
}

fn bench_sign_verify(c: &mut Criterion) {
    let key_pair = KeyPair::generate_ed25519("bench-key");
    let data_1kb = vec![0xABu8; 1024];
    let data_10kb = vec![0xCDu8; 10 * 1024];

    let mut group = c.benchmark_group("ananta/crypto/sign_verify");
    for (name, data) in [("1kb", &data_1kb[..]), ("10kb", &data_10kb[..])] {
        let sig = sign(&key_pair, data);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("sign", name), &sig, |b, _sig| {
            b.iter(|| {
                let s = sign(black_box(&key_pair), black_box(data));
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("verify", name), data, |b, d| {
            b.iter(|| {
                let ok = verify(
                    black_box(key_pair.public_key()),
                    black_box(key_pair.algorithm()),
                    black_box(&sig),
                    black_box(d),
                );
                black_box(ok);
            });
        });
    }
    group.finish();
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let password = "bench-encryption-key";
    let data_1kb = vec![0xABu8; 1024];
    let data_10kb = vec![0xCDu8; 10 * 1024];

    let mut group = c.benchmark_group("ananta/crypto/encrypt_decrypt");
    for (name, data) in [("1kb", &data_1kb[..]), ("10kb", &data_10kb[..])] {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", name), data, |b, d| {
            b.iter(|| {
                let result = encrypt(black_box(password), black_box(d));
                let _ = black_box(result);
            });
        });

        // Pre-compute an encrypted payload for decryption benchmark
        let encrypted = encrypt(password, data).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", name), &encrypted, |b, enc| {
            b.iter(|| {
                let result = decrypt(black_box(password), black_box(enc));
                let _ = black_box(result);
            });
        });
    }
    group.finish();
}

fn bench_merkle_tree(c: &mut Criterion) {
    let algo = AnantaHashAlgorithm::Sha256;
    let leaf_counts = [10usize, 100, 1000];

    let mut group = c.benchmark_group("ananta/crypto/merkle");
    for count in &leaf_counts {
        let leaves: Vec<Vec<u8>> = (0..*count)
            .map(|i| format!("leaf-data-{}", i).into_bytes())
            .collect();
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::new("from_leaves", count),
            &leaf_refs,
            |b, refs| {
                b.iter(|| {
                    let tree = MerkleTree::from_data(refs.as_slice(), black_box(&algo));
                    black_box(tree);
                });
            },
        );

        // Build tree once for proof gen + verify
        let tree = MerkleTree::from_data(&leaf_refs, &algo);
        group.bench_with_input(
            BenchmarkId::new("proof_generation", count),
            &tree,
            |b, t| {
                b.iter(|| {
                    // Generate proof for the last leaf
                    let proof = t.proof(black_box(t.leaves.len() - 1));
                    black_box(proof);
                });
            },
        );

        let proof = tree.proof(tree.leaves.len() - 1).unwrap();
        group.bench_with_input(
            BenchmarkId::new("proof_verification", count),
            &proof,
            |b, p| {
                b.iter(|| {
                    let ok = MerkleTree::verify_proof(black_box(p), black_box(&algo));
                    black_box(ok);
                });
            },
        );
    }
    group.finish();
}

fn bench_lagrange_interpolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ananta/crypto/lagrange");

    // (3,5) Shamir scheme
    let scheme_3_5 = ShamirScheme::new(3, 5);
    let shares_3_5 = scheme_3_5.split(42_000_000);
    let points_3_5: Vec<(u64, u64)> = shares_3_5.iter().map(|s| (s.index, s.value)).collect();

    group.bench_function("(3,5)_5_shares", |b| {
        b.iter(|| {
            let result = lagrange_interpolate_at_zero(black_box(&points_3_5));
            black_box(result);
        });
    });

    // (5,7) Shamir scheme
    let scheme_5_7 = ShamirScheme::new(5, 7);
    let shares_5_7 = scheme_5_7.split(42_000_000);
    let points_5_7: Vec<(u64, u64)> = shares_5_7.iter().map(|s| (s.index, s.value)).collect();

    group.bench_function("(5,7)_7_shares", |b| {
        b.iter(|| {
            let result = lagrange_interpolate_at_zero(black_box(&points_5_7));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_threshold_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ananta/crypto/threshold_signing");

    // (3,5) threshold signing setup
    let private_key = 123_456_789u64;
    let (signers_3_5, pubkey_3_5) = ThresholdSigner::setup(private_key, 3, 5);
    let message = b"bench threshold signing message payload";

    // Pre-compute partial signatures
    let partials_3_5: Vec<PartialSignature> = signers_3_5
        .iter()
        .take(3)
        .map(|s| s.sign_partial(message))
        .collect();

    group.bench_function("(3,5)_partial_sign_3", |b| {
        b.iter(|| {
            let partials: Vec<PartialSignature> = signers_3_5
                .iter()
                .take(3)
                .map(|s| s.sign_partial(black_box(message)))
                .collect();
            black_box(partials);
        });
    });

    group.bench_function("(3,5)_combine_3", |b| {
        b.iter(|| {
            let sig = ThresholdSigner::combine_signatures(black_box(&partials_3_5), 3);
            black_box(sig);
        });
    });

    let full_sig = ThresholdSigner::combine_signatures(&partials_3_5, 3);
    group.bench_function("(3,5)_verify", |b| {
        b.iter(|| {
            let ok = pubkey_3_5.verify(black_box(message), black_box(&full_sig));
            black_box(ok);
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Cross-Ring Message Passing
// ═══════════════════════════════════════════════════════════════════════

fn bench_cross_ring_send_recv(c: &mut Criterion) {
    let network =
        CrossRingNetwork::new(&chakravyuh::cross_ring::CrossRingConfig::default()).unwrap();

    let mut group = c.benchmark_group("cross_ring/send_recv");
    group.throughput(Throughput::Elements(1));
    group.bench_function("send_command", |b| {
        b.iter(|| {
            let msg = CrossRingMessage::new(
                CrossRingType::Command,
                "keshav",
                "shield",
                "policy_update",
                serde_json::json!({"action": "reload"}),
            );
            let result = network.send_command(msg);
            let _ = black_box(result);
        });
    });
    group.bench_function("recv_command", |b| {
        // Pre-send a message so recv has something
        let msg = CrossRingMessage::new(
            CrossRingType::Command,
            "keshav",
            "shield",
            "policy_update",
            serde_json::json!({"action": "reload"}),
        );
        let _ = network.send_command(msg);
        b.iter(|| {
            let result = network.recv_command();
            let _ = black_box(result);
            // Re-send for next iteration
            let msg = CrossRingMessage::new(
                CrossRingType::Command,
                "keshav",
                "shield",
                "policy_update",
                serde_json::json!({"action": "reload"}),
            );
            let _ = network.send_command(msg);
        });
    });
    group.finish();
}

fn bench_cross_ring_broadcast(c: &mut Criterion) {
    let network =
        CrossRingNetwork::new(&chakravyuh::cross_ring::CrossRingConfig::default()).unwrap();
    let destinations = [
        "shield",
        "threat",
        "identity",
        "memory",
        "agent",
        "execution",
        "reasoning",
        "governance",
        "recovery",
    ];

    let mut group = c.benchmark_group("cross_ring/broadcast");
    group.throughput(Throughput::Elements(destinations.len() as u64));
    group.bench_function("broadcast_to_9_rings", |b| {
        b.iter(|| {
            let msg = CrossRingMessage::new(
                CrossRingType::Communication,
                "keshav",
                "broadcast",
                "system_alert",
                serde_json::json!({"level": "high", "message": "security scan initiated"}),
            );
            let result = network.broadcast(msg);
            let _ = black_box(result);
        });
    });
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Storage Operations
// ═══════════════════════════════════════════════════════════════════════

fn bench_memory_store(c: &mut Criterion) {
    let store = MemoryStore::new();
    let small_value = vec![0xABu8; 100];
    let large_value = vec![0xCDu8; 10 * 1024];

    let mut group = c.benchmark_group("storage/memory_store");

    group.bench_function("set_100b", |b| {
        b.iter(|| {
            let ok = store.set(black_box("bench-key-small"), black_box(&small_value));
            black_box(ok);
        });
    });
    group.bench_function("set_10kb", |b| {
        b.iter(|| {
            let ok = store.set(black_box("bench-key-large"), black_box(&large_value));
            black_box(ok);
        });
    });

    // Pre-populate for get benchmarks
    store.set("bench-key-small", &small_value);
    store.set("bench-key-large", &large_value);

    group.bench_function("get_100b", |b| {
        b.iter(|| {
            let result = store.get(black_box("bench-key-small"));
            black_box(result);
        });
    });
    group.bench_function("get_10kb", |b| {
        b.iter(|| {
            let result = store.get(black_box("bench-key-large"));
            black_box(result);
        });
    });

    group.bench_function("delete", |b| {
        b.iter(|| {
            store.set("bench-key-del", &small_value);
            let ok = store.delete(black_box("bench-key-del"));
            black_box(ok);
        });
    });

    group.finish();
}

fn bench_cached_store(c: &mut Criterion) {
    let inner = MemoryStore::new();
    let cached = CachedStore::new(inner, 1000);
    let value = vec![0xABu8; 100];

    // Pre-populate for cache hit
    cached.set("cache-hit-key", &value);

    let mut group = c.benchmark_group("storage/cached_store");
    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            let result = cached.get(black_box("cache-hit-key"));
            black_box(result);
        });
    });
    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            let result = cached.get(black_box("never-seen-key"));
            black_box(result);
        });
    });
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 6. ANANTA Trust Engine
// ═══════════════════════════════════════════════════════════════════════

fn bench_bayesian_trust_update(c: &mut Criterion) {
    let mut engine = BayesianTrustEngine::new();

    let mut group = c.benchmark_group("ananta/trust/bayesian");
    group.bench_function("update_trust_single_evidence", |b| {
        b.iter(|| {
            engine.record_evidence(
                black_box("shield"),
                black_box("threat"),
                black_box(true),
                1.0,
                "benchmark",
            );
        });
    });
    group.finish();
}

fn bench_trust_decay_batch(c: &mut Criterion) {
    let mut engine = TrustDecayEngine::new();
    // Register 100 entities with some evidence
    for i in 0..100u32 {
        let entity_id = format!("entity-{}", i);
        engine.register_entity(&entity_id, None);
        engine.add_evidence(
            &entity_id,
            chakravyuh::ananta::trust::trust_decay::DecayEvidence::new(true, 1.0, "bench"),
        );
    }

    let mut group = c.benchmark_group("ananta/trust/decay");
    group.throughput(Throughput::Elements(100));
    group.bench_function("batch_decay_100_entities", |b| {
        b.iter(|| {
            // Re-register entities and add evidence to ensure dirty state
            for i in 0..100u32 {
                let entity_id = format!("entity-{}", i);
                engine.mark_dirty(&entity_id);
            }
            let result = engine.batch_decay();
            black_box(result);
        });
    });
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// Criterion groups
// ═══════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    // 1. Keshav Decision Pipeline
    bench_pipeline_simple_prompt,
    bench_pipeline_tool_call,
    bench_keshav_decide_evaluate,
    bench_keshav_decide_evaluate_all,
    bench_policy_engine_evaluate_all,
    // 2. Policy VM Execution
    bench_policy_vm_execution,
    bench_policy_compiler_compile,
    // 3. ANANTA Crypto
    bench_hashing,
    bench_sign_verify,
    bench_encrypt_decrypt,
    bench_merkle_tree,
    bench_lagrange_interpolation,
    bench_threshold_signing,
    // 4. Cross-Ring Message Passing
    bench_cross_ring_send_recv,
    bench_cross_ring_broadcast,
    // 5. Storage Operations
    bench_memory_store,
    bench_cached_store,
    // 6. ANANTA Trust Engine
    bench_bayesian_trust_update,
    bench_trust_decay_batch,
);

criterion_main!(benches);
