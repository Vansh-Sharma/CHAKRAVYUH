# ANANTA — Autonomous Trust Plane

> **Source**: `src/ananta/`
> **Config**: `configs/ananta.example.yaml` (independent from Keshav)
> **Cross-References**: [Architecture](./ARCHITECTURE.md) · [Sentinel](./SENTINEL.md) · [Phoenix](./PHOENIX.md) · [Trust Engine](./TRUST_ENGINE.md) · [OVAPH Loop](./OVAPH.md)

---

## 1. Overview

ANANTA is NOT a ring. It is a supervisory plane that exists **above and outside** the 9 defense rings and Keshav Core. It answers the question:

> **"Can the security system itself still be trusted?"**

The name ANANTA ("The Infinite One") reflects its role as the ever-present guardian of the guardian. It monitors, verifies, and autonomously recovers the security system without ever impacting the hot path.

### Critical Design Constraints

| Constraint | Implementation |
|-----------|---------------|
| ANANTA never depends on Keshav | No imports from `src/keshav/` |
| Independent configuration | Separate `ananta.yaml`; `AnantaConfig::from_yaml()` |
| Zero hot-path impact | All work is async background (`tokio::spawn`) |
| Optional | System works without it in degraded mode |
| Separate state directory | `state_path` must be on different mount point |

---

## 2. 13 Subsystems Across 18 Modules

```mermaid
graph TB
    subgraph ANANTA_PLANE["ANANTA Autonomous Trust Plane — src/ananta/"]
        direction TB
        subgraph FOUNDATION["Foundation Layer"]
            Crypto["<b>crypto/</b> (4 modules)<br/>hashing · signing · merkle · encryption · threshold"]
            Anchor["<b>anchor/</b> (6 modules)<br/>attestation · integrity · key_manager · manifest<br/>secure_enclave · secure_store · trust_chain"]
        end

        subgraph INTELLIGENCE["Intelligence Layer"]
            Trust["<b>trust/</b> (6 modules)<br/>engine · graph · state · proof · decay · propagation"]
            Sentinel["<b>sentinel/</b> (4 modules)<br/>drift · drift_analyzer · sentinel_wiring · trust_state_updater"]
            Phoenix["<b>phoenix/</b> (5 modules)<br/>strategies · rollback_engine · recovery_simulator<br/>planner · recovery_history"]
        end

        subgraph PLATFORM["Platform Layer"]
            Health["<b>health/</b> (3 modules)<br/>health_correlation · anomaly_prediction"]
            Audit["<b>audit/</b> (4 modules)<br/>immutable_log · evidence · audit_compliance"]
            Sim["<b>simulation/</b> (2 modules)<br/>scenario_runner · chaos_engine"]
            Dist["<b>distributed/</b> (4 modules)<br/>consensus · gossip · partition_detector · adaptive_routing"]
            Runtime["<b>runtime/</b> (2 modules)<br/>runtime_wasm"]
            Sched["<b>scheduler/</b> (2 modules)<br/>scheduler_priority"]
            State["<b>state/</b> (1 module)<br/>state_sync"]
        end

        subgraph ADAPTIVE["Adaptive Layer"]
            Adapter["<b>adapter/</b> (4 modules)<br/>policy_executor · orchestration_validator<br/>dynamic_pipeline"]
        end
    end

    Crypto --> Anchor
    Sentinel --> Trust
    Phoenix --> Sentinel
    Trust --> Crypto
    Trust --> Anchor
    Adapter --> Trust

    style FOUNDATION fill:#2c3e50,color:#fff
    style INTELLIGENCE fill:#e67e22,color:#fff
    style PLATFORM fill:#27ae60,color:#fff
    style ADAPTIVE fill:#8e44ad,color:#fff
```

---

## 3. Independent Configuration

> **Source**: `src/ananta/config.rs`

ANANTA loads from a separate `ananta.yaml` file. It cannot trust Keshav's config because ANANTA's job is to protect Keshav.

### Top-Level Structure

```rust
pub struct AnantaConfig {
    pub enabled: bool,                          // Master switch
    pub sentinel: SentinelConfig,               // Drift detection
    pub phoenix: PhoenixConfig,                 // Recovery
    pub anchor: AnchorConfig,                   // Root of trust
    pub adapter: AdapterConfig,                 // Adaptive orchestration
    pub trust_proof: TrustProofConfig,          // Trust proof generation
    pub health: HealthConfig,                   // Health graph
    pub audit: AuditConfig,                     // Immutable audit
    pub distributed: DistributedConfig,         // Multi-node
    pub state_path: String,                     // Separate from Keshav
    pub crypto: CryptoConfig,                   // Algorithm suite
}
```

### Configuration Validation

The `AnantaConfig::validate()` method returns `Vec<ConfigWarning>` for questionable values:

| Field | Warning | Severity |
|-------|---------|----------|
| `sentinel.check_interval_ms < 100` | Excessive CPU usage | Warning |
| `trust_proof.generation_interval_ms < 1000` | Performance impact | Warning |
| `phoenix.max_recovery_actions_per_hour > 100` | Instability indicator | Info |
| `distributed.quorum_size < 2` | No fault tolerance | Warning |

### Subsystem Config Defaults

| Subsystem | Key Defaults |
|-----------|-------------|
| **Sentinel** | `check_interval_ms: 1000`, `drift_window_size: 1000`, `drift_sigma_threshold: 3.0`, `enable_full_drift_detection: true` |
| **Phoenix** | `autonomous: true`, `max_recovery_actions_per_hour: 20`, `recovery_cooldown_ms: 30000`, `action_confidence_threshold: 0.85` |
| **Anchor** | `verify_runtime_integrity: true`, `key_rotation_hours: 720`, `encrypted_store: true` |
| **Adapter** | `enabled: false` (opt-in safety), `require_signed_changes: true`, `adaptation_grace_period_ms: 300000` |
| **Trust Proof** | `enabled: true`, `generation_interval_ms: 5000`, `retention_count: 1000` |
| **Health** | `enabled: true`, `computation_interval_ms: 2000`, `prediction_window_secs: 300` |
| **Audit** | `enabled: true`, `max_entries_before_compaction: 100000`, `chained_entries: true` |
| **Crypto** | `hash_algorithm: Sha256`, `kdf_iterations: 100000` |

---

## 4. Background Loops

ANANTA runs 6 independent background loops. All are `tokio::spawn` tasks with zero hot-path impact.

```mermaid
flowchart TB
    subgraph Loops["ANANTA Background Loops (all independent)"]
        L1["<b>Loop 1: Attestation</b><br/>Periodic integrity checks →<br/>signed report → trust chain"]
        L2["<b>Loop 2: Trust Proof</b><br/>Cryptographic proof of<br/>platform trust"]
        L3["<b>Loop 3: Sentinel</b><br/>10-type drift detection →<br/>trust state updates"]
        L4["<b>Loop 4: Phoenix</b><br/>Autonomous recovery when<br/>trust degrades"]
        L5["<b>Loop 5: Health</b><br/>DAG health graph +<br/>anomaly prediction"]
        L6["<b>Loop 6: Adapter</b><br/>Adaptive pipeline<br/>reconfiguration (opt-in)"]
    end

    L1 --> TC["Trust Chain (append-only)"]
    L2 --> TP["TrustProof (cryptographic)"]
    L3 --> TS["TrustState"]
    L4 --> TC
    L5 --> TS
    L6 --> TS

    style Loops fill:#f39c12,color:#fff
```

---

## 5. AnantaPlane — Top-Level Orchestrator

> **Source**: `src/ananta/mod.rs`

The `AnantaPlane` struct owns all subsystem state behind `Arc<RwLock<>>`. Each background loop is an independent tokio task. Loops communicate through shared `trust_state` and audit log.

```rust
pub struct AnantaPlane {
    config: AnantaConfig,

    // Anchor: Root of Trust
    manifest: Arc<RwLock<Manifest>>,
    key_manager: Arc<RwLock<KeyManager>>,
    integrity_checker: Arc<RwLock<IntegrityChecker>>,
    secure_store: Arc<RwLock<SecureStore>>,

    // Trust Engine
    trust_state: Arc<RwLock<TrustState>>,

    // Trust Chains (append-only, tamper-evident)
    attestation_chain: Arc<RwLock<TrustChain>>,
    recovery_chain: Arc<RwLock<TrustChain>>,
    // ... additional subsystems
}
```

---

## 6. Startup Flow

```mermaid
sequenceDiagram
    participant Main as main.rs
    participant AP as AnantaPlane
    participant Anchor as Anchor
    participant Sentinel as Sentinel
    participant Phoenix as Phoenix
    participant Trust as Trust Engine
    participant OVAPH as OVAPH Loop

    Main->>AP: new(config)
    AP->>Anchor: initialize manifest, keys, integrity checker
    AP->>Trust: initialize TrustState with 11 domains
    AP->>Sentinel: start drift detector (10 types, Welford)
    AP->>Phoenix: initialize recovery planner + history

    Note over AP: Load ananta.yaml
    AP->>AP: validate config → ConfigWarning[]

    Note over AP: Spawn 6 background loops
    AP->>AP: tokio::spawn(attestation_loop)
    AP->>AP: tokio::spawn(trust_proof_loop)
    AP->>AP: tokio::spawn(sentinel_loop)
    AP->>AP: tokio::spawn(phoenix_loop)
    AP->>AP: tokio::spawn(health_loop)
    AP->>AP: tokio::spawn(adapter_loop)

    opt OVAPH enabled
        AP->>OVAPH: new(config.ovaph)
        AP->>AP: tokio::spawn(ovaph_loop)
    end

    Note over Main: ANANTA runs in background.
    Note over Main: Zero impact on request hot-path.
```

---

## 7. Crypto Subsystem

> **Source**: `src/ananta/crypto/`

Provides the cryptographic primitives used across all ANANTA subsystems:

| Module | Purpose |
|--------|---------|
| `hashing.rs` | Hash functions (SHA-256/384/512, BLAKE3) via `hash_combined()` → `HashDigest` |
| `signing.rs` | Ed25519 key generation, signing, verification (`KeyPair`, `Signature`) |
| `merkle.rs` | Merkle tree construction and verification |
| `encryption.rs` | AES-256-GCM encryption/decryption |
| `threshold.rs` | Threshold cryptography (multi-party signing) |

The hash algorithm is configurable via `CryptoConfig.hash_algorithm`:

```rust
pub enum HashAlgorithm {
    Sha256,    // Default
    Sha384,
    Sha512,
    Blake3,
}
```

---

## 8. Anchor — Root of Trust

> **Source**: `src/ananta/anchor/`

Anchor is the cryptographic root of trust for the entire ANANTA plane.

| Module | Purpose |
|--------|---------|
| `manifest.rs` | Immutable manifest of trusted binary/config hashes |
| `attestation.rs` | `AttestationReport` — signed integrity snapshot |
| `integrity.rs` | Runtime integrity verification (hash policies, configs) |
| `key_manager.rs` | Key generation, rotation, storage |
| `secure_enclave.rs` | Secure enclave abstraction (TPM/TEE) |
| `secure_store.rs` | Encrypted on-disk key/value store |
| `trust_chain.rs` | Append-only, tamper-evident chain of attestations |

Key rotation interval: 720 hours (30 days) by default.

---

## 9. Health Subsystem

> **Source**: `src/ananta/health/`

| Module | Purpose |
|--------|---------|
| `health_correlation.rs` | DAG-based health graph with dependency correlation |
| `anomaly_prediction.rs` | Look-ahead anomaly prediction (default 300s window) |

The health graph computes a composite platform-wide health score considering inter-component dependencies.

---

## 10. Audit Subsystem

> **Source**: `src/ananta/audit/`

ANANTA maintains its own immutable audit trail, **separate** from Keshav's DecisionLogger.

| Module | Purpose |
|--------|---------|
| `immutable_log.rs` | Append-only audit log (separate from Keshav's) |
| `evidence.rs` | Evidence chain for forensic analysis |
| `audit_compliance.rs` | Compliance report generation |

Features:
- Cryptographic chaining of entries (tamper evidence)
- Compaction at 100,000 entries
- `AuditCategory` and `AuditSeverity` classification

---

## 11. Simulation Subsystem

> **Source**: `src/ananta/simulation/`

| Module | Purpose |
|--------|---------|
| `scenario_runner.rs` | Security twin scenario execution |
| `chaos_engine.rs` | Fault injection and chaos testing |

The simulation subsystem enables "what-if" analysis: run failure scenarios against a virtual model of the system before they occur in production.

---

## 12. Distributed Subsystem

> **Source**: `src/ananta/distributed/`

| Module | Purpose |
|--------|---------|
| `consensus.rs` | Multi-node trust consensus |
| `gossip.rs` | Gossip protocol for state propagation |
| `partition_detector.rs` | Network partition detection |
| `adaptive_routing.rs` | Adaptive message routing |

Distributed mode is **disabled by default**. When enabled, requires `quorum_size >= 2` for fault tolerance.

---

## 13. Adapter — Adaptive Security Orchestration

> **Source**: `src/ananta/adapter/`

| Module | Purpose |
|--------|---------|
| `policy_executor.rs` | Execute adapted policies |
| `orchestration_validator.rs` | Validate pipeline changes |
| `dynamic_pipeline.rs` | Runtime pipeline reconfiguration |

**Disabled by default** — must be explicitly opted in. Requires cryptographic signing for all pipeline changes. Has a 5-minute grace period before adapted pipelines are reverted if no improvement is detected.

---

## 14. Scheduler

> **Source**: `src/ananta/scheduler/`

Background task scheduling with jitter to prevent thundering herd. Provides priority-based scheduling for all 6 ANANTA background loops.

---

## 15. Trend Direction

All ANANTA subsystems share a canonical `TrendDirection` enum:

```rust
pub enum TrendDirection {
    Improving,   // Values improving over time
    Stable,      // Relatively stable
    Degrading,   // Values degrading
    Unknown,     // Insufficient data
}
```
