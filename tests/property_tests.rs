// CHAKRAVYUH Property-Based Tests
//
// Comprehensive proptest suite covering all 10 invariant categories
// across the 9-ring security architecture.

use chakravyuh::{
    ananta::{
        config::HashAlgorithm,
        crypto::{
            encryption::{decrypt, encrypt},
            hashing::{constant_time_eq, hash_bytes, hash_combined},
            lagrange_interpolate_at_zero,
            merkle::MerkleTree,
            signing::{sign, verify, KeyPair},
            ShamirScheme,
        },
        ovaph_loop::OvaphStage,
    },
    cross_ring::{CrossRingMessage, CrossRingType, MessagePriority},
    identity::{IdentityConfig, IdentityRequest, IdentityRing},
    infra::{AuditConfig, AuditTrail},
    keshav::{
        feedback_collector::{
            FeedbackCollector, FeedbackCollectorConfig, FeedbackEntry, FeedbackSeverity,
            FeedbackType,
        },
        risk::{ContextSignals, KeshavRisk, RiskSignals},
    },
    policy_compiler::bytecode::{BytecodeProgram, Constant, Instruction, OpCode},
    policy_compiler::vm::PolicyVM,
    shield::{ShieldRequest, ShieldRing},
    storage::{MemoryStore, Store},
    Config, Decision,
};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

fn test_config() -> Config {
    let yaml = Config::default_yaml();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(tmp.as_file_mut(), yaml.as_bytes()).unwrap();
    Config::from_file(tmp.path()).unwrap()
}

fn make_shield_request(prompt: &str) -> ShieldRequest {
    ShieldRequest {
        source_ip: "192.168.1.1".into(),
        user_agent: Some("test/1.0".into()),
        api_key: None,
        user_id: None,
        method: "POST".into(),
        path: "/v1/chat".into(),
        headers: HashMap::new(),
        body: serde_json::json!({"prompt": prompt}),
    }
}

/// Construct a minimal valid Decision::Challenge via JSON deserialization.
/// ChallengeType is in a private module, so we use serde to construct it.
fn make_challenge_decision() -> Decision {
    serde_json::from_value(serde_json::json!({"type": "challenge", "challenge_type": "javascript"}))
        .unwrap()
}

// ─────────────────────────────────────────────────────────────────────
// 1. Decision Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// ShieldRing::evaluate always returns a valid ShieldVerdict with a
    /// well-formed Decision (one of Allow/Deny/Challenge/Escalate).
    #[test]
    fn prop_shield_evaluate_returns_valid_decision(
        prompt in ".*{0,500}",
    ) {
        let config = test_config();
        let shield = ShieldRing::new(Arc::new(config)).unwrap();
        let req = make_shield_request(&prompt);
        let verdict = shield.evaluate(&req);

        // The decision must match one of the four known variants.
        let is_valid = matches!(
            verdict.decision,
            Decision::Allow
                | Decision::Deny { .. }
                | Decision::Challenge { .. }
                | Decision::Escalate { .. }
        );
        prop_assert!(is_valid, "decision must be a valid variant");
    }

    /// is_allow() and is_deny() are always mutually exclusive.
    #[test]
    fn prop_decision_allow_deny_mutually_exclusive(
        code in ".{0,50}",
        role in ".{0,50}",
        timeout in 0u64..300u64,
    ) {
        let challenge = make_challenge_decision();
        let mut decisions = vec![
            &Decision::Allow as &Decision,
            &challenge as &Decision,
        ];
        let deny = Decision::Deny { code: code.clone(), retry_after: None };
        let escalate = Decision::Escalate { approver_role: role.clone(), timeout_secs: timeout };
        decisions.push(&deny);
        decisions.push(&escalate);
        for d in &decisions {
            prop_assert!(
                !(d.is_allow() && d.is_deny()),
                "is_allow and is_deny must never both be true"
            );
        }
    }

    /// Decision::http_status() always returns a valid HTTP status code (100-599).
    #[test]
    fn prop_http_status_in_valid_range(
        code in ".{0,50}",
        role in ".{0,50}",
        timeout in 0u64..300u64,
    ) {
        let challenge = make_challenge_decision();
        let mut decisions = vec![
            &Decision::Allow as &Decision,
            &challenge as &Decision,
        ];
        let deny = Decision::Deny { code: code.clone(), retry_after: None };
        let escalate = Decision::Escalate { approver_role: role.clone(), timeout_secs: timeout };
        decisions.push(&deny);
        decisions.push(&escalate);
        for d in &decisions {
            let status = d.http_status();
            prop_assert!(
                (100..=599).contains(&status),
                "http_status {} out of range 100-599",
                status
            );
        }
    }

    /// ShieldVerdict latency_ms is always non-negative.
    #[test]
    fn prop_shield_verdict_latency_non_negative(
        prompt in ".*{0,500}",
    ) {
        let config = test_config();
        let shield = ShieldRing::new(Arc::new(config)).unwrap();
        let req = make_shield_request(&prompt);
        let verdict = shield.evaluate(&req);
        prop_assert!(
            verdict.latency_ms >= 0.0,
            "latency_ms must be >= 0, got {}",
            verdict.latency_ms
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 2. Risk Score Bounds
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// All RiskScore fields returned by KeshavRisk::evaluate are finite f64 values.
    #[test]
    fn prop_risk_score_fields_are_finite(
        threat in proptest::option::of(0.0f64..20.0f64),
        identity in proptest::option::of(0.0f64..20.0f64),
        agent in proptest::option::of(0.0f64..20.0f64),
        memory in proptest::option::of(0.0f64..20.0f64),
        execution in proptest::option::of(0.0f64..20.0f64),
        reasoning in proptest::option::of(0.0f64..20.0f64),
        governance in proptest::option::of(0.0f64..20.0f64),
        recovery in proptest::option::of(0.0f64..20.0f64),
        ctx_tod in 0.0f64..2.0f64,
        ctx_rate in 0.0f64..2.0f64,
        ctx_rep in 0.0f64..2.0f64,
    ) {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: threat,
            identity_score: identity,
            agent_score: agent,
            memory_score: memory,
            execution_score: execution,
            reasoning_score: reasoning,
            governance_score: governance,
            recovery_score: recovery,
            context: ContextSignals {
                time_of_day_risk: ctx_tod,
                rate_anomaly: ctx_rate,
                source_reputation: ctx_rep,
            },
        };
        let score = risk.evaluate(&signals);

        for (name, val) in [
            ("overall", score.overall),
            ("threat", score.threat),
            ("identity", score.identity),
            ("behavior", score.behavior),
            ("memory", score.memory),
            ("execution", score.execution),
            ("context", score.context),
            ("confidence", score.confidence),
        ] {
            prop_assert!(val.is_finite(), "{}.is_finite() failed, got {}", name, val);
            prop_assert!(!val.is_nan(), "{} must not be NaN", name);
        }
    }

    /// ContextSignals::to_score() returns a value in [0.0, 10.0].
    #[test]
    fn prop_context_signals_to_score_bounded(
        tod in 0.0f64..5.0f64,
        rate in 0.0f64..5.0f64,
        rep in -2.0f64..5.0f64,
    ) {
        let ctx = ContextSignals {
            time_of_day_risk: tod,
            rate_anomaly: rate,
            source_reputation: rep,
        };
        let s = ctx.to_score();
        prop_assert!(s >= 0.0, "context score must be >= 0, got {}", s);
        prop_assert!(s <= 10.0, "context score must be <= 10, got {}", s);
        prop_assert!(s.is_finite(), "context score must be finite, got {}", s);
    }

    /// KeshavRisk::evaluate overall is clamped to [0, 10].
    #[test]
    fn prop_risk_overall_clamped(
        threat in proptest::option::of(proptest::num::f64::NORMAL),
        identity in proptest::option::of(proptest::num::f64::NORMAL),
    ) {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: threat,
            identity_score: identity,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let score = risk.evaluate(&signals);
        prop_assert!(score.overall >= 0.0 && score.overall <= 10.0,
            "overall must be in [0, 10], got {}", score.overall);
    }

    /// RiskScore confidence is always in (0, 1].
    #[test]
    fn prop_risk_confidence_bounded(
        threat in proptest::option::of(0.0f64..10.0f64),
    ) {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: threat,
            identity_score: None,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let score = risk.evaluate(&signals);
        prop_assert!(score.confidence > 0.0 && score.confidence <= 1.0,
            "confidence must be in (0, 1], got {}", score.confidence);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 3. Trust Score Bounds
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// Identity trust scores from TrustAccumulator are always in [0.0, 1.0].
    #[test]
    fn prop_identity_trust_score_in_range(
        ip in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
    ) {
        let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
        let mut headers = HashMap::new();
        headers.insert("authorization".into(), "Bearer sk-test-key-16chars-min".into());
        let request = IdentityRequest {
            source_ip: ip,
            user_agent: Some("test-agent/1.0".into()),
            api_key: Some("sk-test-key-16chars-min".into()),
            was_denied: false,
            request_id: "prop-test".into(),
            headers,
        };
        let verdict = ring.evaluate(&request);
        if let Some(trust) = &verdict.trust_result {
            prop_assert!(
                trust.trust_score >= 0.0 && trust.trust_score <= 1.0,
                "trust_score out of [0,1]: {}",
                trust.trust_score
            );
        }
    }

    /// ANANTA trust state domain levels are always in [0.0, 1.0] after set.
    #[test]
    fn prop_ananta_domain_levels_clamped(
        level in proptest::num::f64::NORMAL,
    ) {
        use chakravyuh::ananta::trust::TrustState;
        let mut state = TrustState::new();
        state.set_domain_level("decision", level);
        let actual = state.domain_level("decision");
        prop_assert!(
            (0.0..=1.0).contains(&actual),
            "domain level must be in [0,1], got {}",
            actual
        );
    }

    /// ANANTA overall trust score is always in [0.0, 1.0].
    #[test]
    fn prop_ananta_overall_score_bounded(
        decision_level in 0.0f64..1.0f64,
        policy_level in 0.0f64..1.0f64,
    ) {
        use chakravyuh::ananta::trust::TrustState;
        let mut state = TrustState::new();
        state.set_domain_level("decision", decision_level);
        state.set_domain_level("policy", policy_level);
        let overall = state.overall_score();
        prop_assert!(
            (0.0..=1.0).contains(&overall),
            "overall score must be in [0,1], got {}",
            overall
        );
    }

    /// Trust state domain levels remain bounded after multiple updates.
    #[test]
    fn prop_trust_state_bounded_after_updates(
        levels in proptest::collection::vec(proptest::num::f64::NORMAL, 1..20),
    ) {
        use chakravyuh::ananta::trust::TrustState;
        let mut state = TrustState::new();
        for (i, &level) in levels.iter().enumerate() {
            let domain = format!("domain_{}", i % 5);
            state.set_domain_level(&domain, level);
        }
        for (name, dt) in &state.domains {
            prop_assert!(dt.level >= 0.0 && dt.level <= 1.0,
                "domain {} level {} out of [0,1]", name, dt.level);
        }
        let overall = state.overall_score();
        prop_assert!((0.0..=1.0).contains(&overall),
            "overall score {} out of [0,1]", overall);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 4. Crypto Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// hash_bytes is deterministic: same input always produces same output.
    #[test]
    fn prop_hash_bytes_deterministic(
        data in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
    ) {
        let algo = HashAlgorithm::Sha256;
        let a = hash_bytes(&data, &algo);
        let b = hash_bytes(&data, &algo);
        prop_assert_eq!(a.bytes, b.bytes);
    }

    /// hash_bytes produces the correct length per algorithm.
    #[test]
    fn prop_hash_bytes_correct_length(
        data in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        algo_idx in 0usize..4usize,
    ) {
        let algos = [
            (HashAlgorithm::Sha256, 32usize),
            (HashAlgorithm::Sha384, 48usize),
            (HashAlgorithm::Sha512, 64usize),
            (HashAlgorithm::Blake3, 32usize),
        ];
        let (ref algo, expected_len) = algos[algo_idx];
        let digest = hash_bytes(&data, algo);
        prop_assert_eq!(digest.bytes.len(), expected_len,
            "expected {} bytes for {:?}, got {}",
            expected_len, algo, digest.bytes.len());
    }

    /// constant_time_eq returns true for identical inputs.
    #[test]
    fn prop_constant_time_eq_identical(
        data in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
    ) {
        prop_assert!(constant_time_eq(&data, &data));
    }

    /// constant_time_eq returns false for different inputs of same length.
    #[test]
    fn prop_constant_time_eq_different_same_len(
        mut a in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
    ) {
        a[0] = a[0].wrapping_add(1);
        let mut b = a.clone();
        b[0] = b[0].wrapping_add(2);
        if a != b {
            prop_assert!(!constant_time_eq(&a, &b));
        }
    }

    /// Ed25519 sign+verify roundtrip succeeds.
    #[test]
    fn prop_ed25519_sign_verify_roundtrip(
        data in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
    ) {
        let kp = KeyPair::generate_ed25519("prop-test");
        let sig = sign(&kp, &data);
        prop_assert!(
            verify(kp.public_key(), &kp.algorithm, &sig, &data),
            "Ed25519 sign+verify roundtrip failed"
        );
    }

    /// Ed25519 verify rejects tampered data.
    #[test]
    fn prop_ed25519_rejects_tampered_data(
        data in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
    ) {
        let kp = KeyPair::generate_ed25519("prop-test");
        let sig = sign(&kp, &data);
        let mut tampered = data.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        prop_assert!(
            !verify(kp.public_key(), &kp.algorithm, &sig, &tampered),
            "Ed25519 verify should reject tampered data"
        );
    }

    /// HMAC-SHA256 sign+verify roundtrip.
    #[test]
    fn prop_hmac_sign_verify_roundtrip(
        data in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
    ) {
        let kp = KeyPair::generate_hmac_sha256("prop-hmac");
        let sig = sign(&kp, &data);
        prop_assert!(
            verify(kp.public_key(), &kp.algorithm, &sig, &data),
            "HMAC-SHA256 sign+verify roundtrip failed"
        );
    }

    /// Encryption roundtrip: encrypt then decrypt produces original plaintext.
    #[test]
    fn prop_encryption_roundtrip(
        password in ".{4,64}",
        plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..1024),
    ) {
        let encrypted = encrypt(&password, &plaintext).unwrap();
        let decrypted = decrypt(&password, &encrypted).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Encryption rejects wrong password.
    #[test]
    fn prop_encryption_rejects_wrong_password(
        password in ".{4,64}",
        wrong in ".{4,64}",
        plaintext in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
    ) {
        proptest::prop_assume!(password != wrong);
        let encrypted = encrypt(&password, &plaintext).unwrap();
        let result = decrypt(&wrong, &encrypted);
        prop_assert!(result.is_err(),
            "decrypt with wrong password should fail");
    }

    /// hash_combined is deterministic.
    #[test]
    fn prop_hash_combined_deterministic(
        a in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
        b in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
    ) {
        let algo = &HashAlgorithm::Sha256;
        let h1 = hash_combined(&[&a, &b], algo);
        let h2 = hash_combined(&[&a, &b], algo);
        prop_assert_eq!(h1.bytes, h2.bytes);
    }

    /// hash_combined order matters: [a, b] != [b, a].
    #[test]
    fn prop_hash_combined_order_matters(
        a in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        b in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
    ) {
        let algo = &HashAlgorithm::Sha256;
        proptest::prop_assume!(a != b);
        let h1 = hash_combined(&[&a, &b], algo);
        let h2 = hash_combined(&[&b, &a], algo);
        prop_assert_ne!(h1.bytes, h2.bytes,
            "hash_combined should be order-dependent");
    }

    /// MerkleTree::verify_proof returns true for proofs generated by the tree.
    #[test]
    fn prop_merkle_proof_verifies(
        items in proptest::collection::vec(
            proptest::collection::vec(proptest::num::u8::ANY, 1..64),
            2..20
        ),
    ) {
        let data_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_data(&data_refs, &HashAlgorithm::Sha256);
        for i in 0..tree.leaves.len() {
            let proof = tree.proof(i).expect("proof should exist");
            prop_assert!(
                MerkleTree::verify_proof(&proof, &HashAlgorithm::Sha256),
                "Merkle proof for index {} failed to verify", i
            );
        }
    }

    /// MerkleTree::verify_proof returns false for tampered leaf hashes.
    #[test]
    fn prop_merkle_proof_detects_tampered_leaf(
        items in proptest::collection::vec(
            proptest::collection::vec(proptest::num::u8::ANY, 1..64),
            2..10
        ),
    ) {
        let data_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_data(&data_refs, &HashAlgorithm::Sha256);
        let mut proof = tree.proof(0).expect("proof should exist");
        proof.leaf_hash = hash_bytes(b"TAMPERED_DATA", &HashAlgorithm::Sha256);
        prop_assert!(
            !MerkleTree::verify_proof(&proof, &HashAlgorithm::Sha256),
            "Merkle proof should detect tampered leaf hash"
        );
    }

    /// MerkleTree::verify_proof returns false for tampered sibling hashes.
    #[test]
    fn prop_merkle_proof_detects_tampered_siblings(
        items in proptest::collection::vec(
            proptest::collection::vec(proptest::num::u8::ANY, 1..64),
            3..10
        ),
    ) {
        let data_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_data(&data_refs, &HashAlgorithm::Sha256);
        let idx = if tree.leaves.len() > 1 { 1 } else { 0 };
        let mut proof = tree.proof(idx).expect("proof should exist");
        if !proof.path.is_empty() {
            proof.path[0].0 = hash_bytes(b"TAMPERED_SIBLING", &HashAlgorithm::Sha256);
            prop_assert!(
                !MerkleTree::verify_proof(&proof, &HashAlgorithm::Sha256),
                "Merkle proof should detect tampered sibling"
            );
        }
    }

    /// MerkleTree is deterministic: same data produces same root.
    #[test]
    fn prop_merkle_tree_deterministic(
        items in proptest::collection::vec(
            proptest::collection::vec(proptest::num::u8::ANY, 1..64),
            1..20
        ),
    ) {
        let data_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let t1 = MerkleTree::from_data(&data_refs, &HashAlgorithm::Sha256);
        let t2 = MerkleTree::from_data(&data_refs, &HashAlgorithm::Sha256);
        prop_assert_eq!(t1.root.bytes, t2.root.bytes);
    }

    /// BLAKE3 Merkle proofs verify correctly.
    #[test]
    fn prop_merkle_blake3_proof(
        items in proptest::collection::vec(
            proptest::collection::vec(proptest::num::u8::ANY, 1..64),
            2..15
        ),
    ) {
        let data_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_data(&data_refs, &HashAlgorithm::Blake3);
        if !tree.leaves.is_empty() {
            let proof = tree.proof(0).expect("proof should exist");
            prop_assert!(MerkleTree::verify_proof(&proof, &HashAlgorithm::Blake3));
        }
    }

    /// Shamir with threshold t shares can reconstruct the secret.
    #[test]
    fn prop_shamir_reconstruct_with_threshold(
        secret in 1u64..2_147_483_646u64,
        threshold in 2usize..5usize,
        num_shares in 3usize..8usize,
    ) {
        let n = threshold.max(num_shares);
        let scheme = ShamirScheme::new(threshold, n);
        let shares = scheme.split(secret);
        let shares_for_recon: Vec<(u64, u64)> = shares[..threshold]
            .iter()
            .map(|s| (s.index, s.value))
            .collect();
        let reconstructed = lagrange_interpolate_at_zero(&shares_for_recon);
        prop_assert_eq!(reconstructed, secret,
            "Shamir reconstruction failed: expected {}, got {}",
            secret, reconstructed);
    }

    /// Shamir with fewer than threshold shares cannot reconstruct the secret.
    #[test]
    fn prop_shamir_fewer_shares_wrong_secret(
        secret in 1u64..2_147_483_646u64,
        threshold in 3usize..6usize,
    ) {
        let n = threshold + 2;
        let scheme = ShamirScheme::new(threshold, n);
        let shares = scheme.split(secret);
        let insufficient: Vec<(u64, u64)> = shares[..(threshold - 1)]
            .iter()
            .map(|s| (s.index, s.value))
            .collect();
        let reconstructed = lagrange_interpolate_at_zero(&insufficient);
        prop_assert_ne!(reconstructed, secret,
            "Shamir with fewer shares should NOT reconstruct secret: got {}",
            reconstructed);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 5. Policy VM Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// PolicyVM::execute returns a VMResult (never panics) for any valid program.
    #[test]
    fn prop_vm_execute_never_panics(
        push_val in proptest::num::f64::NORMAL,
    ) {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(push_val.abs() % 100.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c).with_source(1, "prop"));
        prog.emit(Instruction::new(OpCode::Halt).with_source(2, "prop"));
        prog.max_stack_size = 16;
        prog.rule_count = 1;

        let vm = PolicyVM::new();
        let env = HashMap::new();
        // Should not panic, even if it returns an error.
        let _result = vm.execute(&prog, &env);
    }

    /// VMResult::instructions_executed is > 0 for non-empty programs.
    #[test]
    fn prop_vm_non_empty_program_has_steps(
        push_val in proptest::num::f64::NORMAL,
    ) {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(push_val.abs() % 100.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c).with_source(1, "prop"));
        prog.emit(Instruction::new(OpCode::Halt).with_source(2, "prop"));
        prog.max_stack_size = 16;
        prog.rule_count = 1;

        let vm = PolicyVM::new();
        let env = HashMap::new();
        let result = vm.execute(&prog, &env).unwrap();
        prop_assert!(result.instructions_executed > 0,
            "non-empty program should execute at least 1 instruction, got {}",
            result.instructions_executed);
    }

    /// All valid OpCode enum variants map to known opcodes (no invalid opcodes
    /// can be constructed through the enum).
    #[test]
    fn prop_opcode_from_byte_always_valid(
        byte in 0u8..=255u8,
    ) {
        let opcode = OpCode::from_byte(byte);
        prop_assert!(!opcode.mnemonic().is_empty(),
            "OpCode::from_byte({}) should have a non-empty mnemonic", byte);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 6. OVAPH State Machine
// ─────────────────────────────────────────────────────────────────────

#[test]
fn ovaph_all_returns_exactly_five_stages() {
    assert_eq!(OvaphStage::all().len(), 5);
}

proptest! {
    /// OvaphStage::next() always returns the next stage in sequence.
    #[test]
    fn prop_ovaph_next_cycles(
        start_idx in 0usize..5usize,
        steps in 1usize..20usize,
    ) {
        let all = OvaphStage::all();
        let mut stage = all[start_idx % all.len()];
        for _ in 0..steps {
            stage = stage.next();
        }
        let expected = all[(start_idx + steps) % 5];
        prop_assert_eq!(stage, expected);
    }

    /// OvaphStage::name() returns a non-empty string for every stage.
    #[test]
    fn prop_ovaph_name_non_empty(
        idx in 0usize..5usize,
    ) {
        let stage = OvaphStage::all()[idx];
        prop_assert!(!stage.name().is_empty(),
            "OvaphStage name should not be empty");
    }

    /// OvaphStage::duration_hint_ms() returns a positive value for every stage.
    #[test]
    fn prop_ovaph_duration_hint_positive(
        idx in 0usize..5usize,
    ) {
        let stage = OvaphStage::all()[idx];
        prop_assert!(stage.duration_hint_ms() > 0,
            "duration_hint_ms should be positive, got {}",
            stage.duration_hint_ms());
    }

    /// OVAPH full cycle returns to start.
    #[test]
    fn prop_ovaph_full_cycle(
        start_idx in 0usize..5usize,
    ) {
        let all = OvaphStage::all();
        let mut stage = all[start_idx];
        for _ in 0..5 {
            stage = stage.next();
        }
        prop_assert_eq!(stage, all[start_idx],
            "5 applications of next() should return to start");
    }
}

// ─────────────────────────────────────────────────────────────────────
// 7. Cross-Ring Message Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// CrossRingMessage::validate_direction() works for all CrossRingType combinations.
    #[test]
    fn prop_cross_ring_validate_direction_no_panic(
        ring_type_idx in 0usize..5usize,
        source in ".{1,20}",
        destination in ".{1,20}",
    ) {
        let types = [
            CrossRingType::Command,
            CrossRingType::Intel,
            CrossRingType::Control,
            CrossRingType::Communication,
            CrossRingType::Recovery,
        ];
        let ring_type = types[ring_type_idx].clone();
        let msg = CrossRingMessage::new(
            ring_type, &source, &destination, "test_type",
            serde_json::json!({}),
        );
        // Should never panic, just returns Ok or Err.
        let _ = msg.validate_direction();
    }

    /// MessagePriority serialization roundtrip.
    #[test]
    fn prop_message_priority_ordering_serialization_roundtrip(
        priority_idx in 0usize..4usize,
    ) {
        let priorities = [
            MessagePriority::Low,
            MessagePriority::Normal,
            MessagePriority::High,
            MessagePriority::Critical,
        ];
        let p = priorities[priority_idx].clone();
        let json = serde_json::to_string(&p).unwrap();
        let p2: MessagePriority = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(p, p2);
    }

    /// CrossRingMessage serialization roundtrip.
    #[test]
    fn prop_cross_ring_message_serialization_roundtrip(
        source in "[a-z]{1,10}",
        dest in "[a-z]{1,10}",
        msg_type in "[a-z_]{1,20}",
    ) {
        let msg = CrossRingMessage::new(
            CrossRingType::Intel, &source, &dest, &msg_type,
            serde_json::json!({"key": "value"}),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: CrossRingMessage = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(msg.source, msg2.source);
        prop_assert_eq!(msg.destination, msg2.destination);
        prop_assert_eq!(msg.msg_type, msg2.msg_type);
        prop_assert_eq!(msg.cross_ring_type, msg2.cross_ring_type);
    }
}

#[test]
fn message_priority_ordering() {
    assert!(MessagePriority::Low < MessagePriority::Normal);
    assert!(MessagePriority::Normal < MessagePriority::High);
    assert!(MessagePriority::High < MessagePriority::Critical);
}

// ─────────────────────────────────────────────────────────────────────
// 8. Storage Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// MemoryStore::set + MemoryStore::get roundtrip preserves data.
    #[test]
    fn prop_memory_store_set_get_roundtrip(
        key in ".{1,100}",
        value in proptest::collection::vec(proptest::num::u8::ANY, 0..1024),
    ) {
        let store = MemoryStore::new();
        store.set(&key, &value);
        let retrieved = store.get(&key).expect("key should exist after set");
        prop_assert_eq!(retrieved, value);
    }

    /// MemoryStore::delete removes data (subsequent get returns None).
    #[test]
    fn prop_memory_store_delete_removes(
        key in ".{1,100}",
        value in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
    ) {
        let store = MemoryStore::new();
        store.set(&key, &value);
        prop_assert!(store.delete(&key), "delete should return true for existing key");
        prop_assert!(store.get(&key).is_none(),
            "get should return None after delete");
    }

    /// MemoryStore::keys with prefix returns only keys starting with that prefix.
    #[test]
    fn prop_memory_store_keys_prefix(
        prefix in "[a-z]{1,5}",
        suffix1 in "[a-z]{1,5}",
        suffix2 in "[a-z]{1,5}",
        value in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
    ) {
        let store = MemoryStore::new();
        let key_with_prefix = format!("{}:{}", prefix, suffix1);
        let key_without_prefix = format!("_noprefix:{}", suffix2);
        store.set(&key_with_prefix, &value);
        store.set(&key_without_prefix, &value);

        let matching = store.keys(&prefix);
        for k in &matching {
            prop_assert!(k.starts_with(&prefix),
                "key {:?} should start with prefix {:?}", k, prefix);
        }
        prop_assert!(matching.contains(&key_with_prefix),
            "matching keys should contain the key with prefix");
        prop_assert!(!matching.contains(&key_without_prefix),
            "matching keys should NOT contain the key without prefix");
    }

    /// MemoryStore set overwrites previous value.
    #[test]
    fn prop_memory_store_overwrite(
        key in ".{1,50}",
        v1 in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
        v2 in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
    ) {
        let store = MemoryStore::new();
        store.set(&key, &v1);
        store.set(&key, &v2);
        let retrieved = store.get(&key).unwrap();
        prop_assert_eq!(retrieved, v2, "second set should overwrite first");
    }

    /// MemoryStore delete of non-existent key returns false.
    #[test]
    fn prop_memory_store_delete_nonexistent(
        key in ".{1,50}",
    ) {
        let store = MemoryStore::new();
        prop_assert!(!store.delete(&key),
            "delete of non-existent key should return false");
    }
}

// ─────────────────────────────────────────────────────────────────────
// 9. Audit Chain Integrity
// ─────────────────────────────────────────────────────────────────────

#[test]
fn audit_verify_chain_empty_trail() {
    let trail = AuditTrail::new(AuditConfig::default());
    let (valid, total, tampered) = trail.verify_chain();
    assert!(valid, "empty audit trail should verify as valid");
    assert_eq!(total, 0);
    assert_eq!(tampered, 0);
}

proptest! {
    /// AuditTrail::verify_chain returns true after recording entries.
    #[test]
    fn prop_audit_chain_valid_after_appends(
        entries in proptest::collection::vec(
            proptest::string::string_regex("[a-z]{1,10}").unwrap(),
            1..20
        ),
    ) {
        let trail = AuditTrail::new(AuditConfig::default());
        for (i, trace_id) in entries.iter().enumerate() {
            trail.append(
                trace_id,
                &format!(r#"{{"seq":{}}}"#, i),
                &format!("10.0.0.{}", i % 256),
                "/v1/evaluate",
            );
        }
        let (valid, total, tampered) = trail.verify_chain();
        prop_assert!(valid,
            "audit chain should be valid after {} appends, tampered={}",
            total, tampered);
        prop_assert_eq!(total, entries.len());
        prop_assert_eq!(tampered, 0);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 10. Config Roundtrip
// ─────────────────────────────────────────────────────────────────────

#[test]
fn config_default_yaml_roundtrip() {
    let yaml = Config::default_yaml();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(tmp.as_file_mut(), yaml.as_bytes()).unwrap();
    let config =
        Config::from_file(tmp.path()).expect("default_yaml should parse into a valid Config");
    assert!(config.shield.enabled, "shield should be enabled by default");
}

proptest! {
    /// Config parsed from a valid YAML string is a valid Config.
    #[test]
    fn prop_config_from_str_parses(
        _yaml in "shield:\n  enabled: true\n"
    ) {
        let config: Config = "shield:\n  enabled: true\n".parse().unwrap();
        prop_assert!(config.shield.enabled);
    }

    /// Decision serialization roundtrip for all variants.
    #[test]
    fn prop_decision_serialization_roundtrip(
        code in ".{0,30}",
        role in ".{0,30}",
        timeout in 0u64..600u64,
    ) {
        let decisions = vec![
            Decision::Allow,
            Decision::Deny { code: code.clone(), retry_after: Some(30) },
            make_challenge_decision(),
            Decision::Escalate { approver_role: role.clone(), timeout_secs: timeout },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).unwrap();
            let d2: Decision = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&d2).unwrap();
            prop_assert_eq!(json, json2,
                "Decision serialization roundtrip failed");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// 11. Feedback Collector Invariants
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// FeedbackCollector submit and retrieve roundtrip.
    #[test]
    fn prop_feedback_submit_retrieve(
        request_id in "[a-z0-9]{1,20}",
        explanation in ".{0,200}",
    ) {
        let collector = FeedbackCollector::new(FeedbackCollectorConfig::default());
        let entry = FeedbackEntry {
            feedback_id: uuid::Uuid::new_v4().to_string(),
            request_id: request_id.clone(),
            feedback_type: FeedbackType::FalsePositive,
            severity: FeedbackSeverity::High,
            target_rings: vec!["shield".into()],
            original_decision: "deny:WAF_SQL_INJECTION".into(),
            explanation,
            submitted_by: "admin".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        };
        collector.submit(entry);
        let retrieved = collector.feedback_for_request(&request_id);
        prop_assert_eq!(retrieved.len(), 1);
    }

    /// FeedbackCollector unprocessed count matches.
    #[test]
    fn prop_feedback_unprocessed_count(
        count in 1usize..10usize,
    ) {
        let collector = FeedbackCollector::new(FeedbackCollectorConfig::default());
        for i in 0..count {
            let entry = FeedbackEntry {
                feedback_id: uuid::Uuid::new_v4().to_string(),
                request_id: format!("req-{}", i),
                feedback_type: FeedbackType::Approve,
                severity: FeedbackSeverity::Low,
                target_rings: vec![],
                original_decision: "allow".into(),
                explanation: String::new(),
                submitted_by: "system".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                processed: false,
            };
            collector.submit(entry);
        }
        prop_assert_eq!(collector.unprocessed_count(), count);
    }

    /// KeshavRisk is deterministic: same signals produce same score.
    #[test]
    fn prop_keshav_risk_deterministic(
        threat in proptest::option::of(0.0f64..10.0f64),
        identity in proptest::option::of(0.0f64..10.0f64),
    ) {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: threat,
            identity_score: identity,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let s1 = risk.evaluate(&signals);
        let s2 = risk.evaluate(&signals);
        prop_assert_eq!(s1.overall, s2.overall);
        prop_assert_eq!(s1.confidence, s2.confidence);
    }
}
