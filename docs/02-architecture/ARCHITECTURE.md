# CHAKRAVYUH OS — System Architecture

> **Version**: Current (see `env!("CARGO_PKG_VERSION")` in source)
> **Last Updated**: Auto-generated from source
> **Cross-References**: [Keshav Core](./KESHAV.md) · [ANANTA](./ANANTA.md) · [Sentinel](./SENTINEL.md) · [Phoenix](./PHOENIX.md) · [Trust Engine](./TRUST_ENGINE.md) · [OVAPH Loop](./OVAPH.md)

---

## 1. Overview

CHAKRAVYUH OS is a layered AI security operating system built in Rust. It protects LLM-powered applications through 9 concentric defense rings, a central decision brain (Keshav Core), 5 cross-ring communication channels, and an autonomous trust plane (ANANTA) that verifies the security system itself.

The name "Chakravyuh" comes from the ancient Indian military formation — concentric, impenetrable layers. Each ring is independently functional; the system is designed so that the failure of any ring or subsystem never results in a security bypass.

---

## 2. High-Level Data Flow

```mermaid
flowchart TB
    Client(["Client Request"]) --> Shield["<b>Shield Ring</b><br/>Ring 1 · WAF / Rate Limit / Geo"]
    Shield --> |"Verdict"| Keshav["<b>Keshav Core</b><br/>Decide · Risk · Learn · Orchestrate"]

    Threat["<b>Threat Ring</b><br/>Ring 3 · 6 Engines"] --> |"Verdict"| Keshav
    Identity["<b>Identity Ring</b><br/>Ring 2 · 4 Engines"] --> |"Verdict"| Keshav
    Memory["<b>Memory Ring</b><br/>Ring 5"] --> |"Verdict"| Keshav
    Agent["<b>Agent Ring</b><br/>Ring 4"] --> |"Verdict"| Keshav
    Execution["<b>Execution Ring</b><br/>Ring 6 · Sandbox"] --> |"Verdict"| Keshav
    Reasoning["<b>Reasoning Ring</b><br/>Ring 7"] --> |"Verdict"| Keshav
    Governance["<b>Governance Ring</b><br/>Ring 8"] --> |"Verdict"| Keshav
    Recovery["<b>Recovery Ring</b><br/>Ring 9"] --> |"Verdict"| Keshav

    Keshav --> |"Decision"| Decision["<b>DecisionRecord</b><br/>Allow / Deny / Challenge / Escalate"]
    Decision --> Client

    ANANTA["<b>ANANTA Trust Plane</b><br/>Zero hot-path impact"] -.-> |"Supervises"| Shield
    ANANTA -.-> |"Supervises"| Threat
    ANANTA -.-> |"Supervises"| Keshav

    style Keshav fill:#4a90d9,color:#fff
    style ANANTA fill:#e67e22,color:#fff,stroke-dasharray: 5 5
```

---

## 3. The 9 Defense Rings

Each ring is an independently testable module under `src/`. Rings produce a verdict (`Allow`, `Deny`, `Challenge`, `Escalate`) for each request. Keshav Core combines all verdicts into a final decision.

| # | Ring | Module | Purpose | Key Engines/Components |
|---|------|--------|---------|------------------------|
| 1 | **Shield** | `src/shield/` | First line of defense | WAF Engine, Rate Limiter, Geo Fencer, Bot Detector, DoS Protector, Input Validator |
| 2 | **Identity** | `src/identity/` | Who is asking? | SessionIdentity, RoleResolver, TrustAccumulator, IdentityAnomaly |
| 3 | **Threat** | `src/threat/` | What are they asking? | ObfuscationDecoder, PatternMatcher, SemanticClassifier, JailbreakDetector, ConfidenceScorer, AttackLibrary |
| 4 | **Agent** | `src/agent/` | Is the agent behaving? | BehaviorMonitor, CapabilityGuard, PermissionEnforcer, ToolChainingDetector |
| 5 | **Memory** | `src/memory/` | Is memory access safe? | ContextGuard, RAGPoisonDetector, PIIExtractor, ConversationTracker |
| 6 | **Execution** | `src/execution/` | Is the tool call safe? | SandboxExecutor, SSRFProtector, ParameterValidator, ToolAllowlist |
| 7 | **Reasoning** | `src/reasoning/` | Is reasoning sound? | Reasoning risk assessment |
| 8 | **Governance** | `src/governance/` | Policy compliance | GovernanceVerdict generation |
| 9 | **Recovery** | `src/recovery_sec/` | Recovery security | RecoveryVerdict generation |

### Ring Ordering

Rings are identified by the `RingId` enum in `src/keshav/orchestrate.rs`:

```rust
pub enum RingId {
    Shield,      // Ring 1
    Identity,    // Ring 2
    Threat,      // Ring 3
    Agent,       // Ring 4
    Memory,      // Ring 5
    Execution,   // Ring 6
    Reasoning,   // Ring 7
    Governance,  // Ring 8
    Recovery,    // Ring 9
}
```

---

## 4. Keshav Core — The Decision Brain

> **Deep Dive**: [KESHAV.md](./KESHAV.md)

Keshav is the central nervous system. It contains four subsystems:

| Subsystem | Source File | Phase | Latency Budget |
|-----------|-------------|-------|----------------|
| **Decide** | `src/keshav/decide.rs` | 2 | < 1ms |
| **Risk** | `src/keshav/risk.rs` | 3 | < 0.5ms p99 |
| **Learn** | `src/keshav/learn.rs` | 6 | < 1ms overhead |
| **Orchestrate** | `src/keshav/orchestrate.rs` | 3 | < 1ms overhead |

Supporting modules:

- `policy_engine.rs` — YAML rule evaluation, first-match-wins, default deny
- `policy_manager.rs` — Hot-reload policies at runtime (RwLock-protected)
- `decision_logger.rs` — Append-only JSON+CSV audit log (SOC 2, ISO 27001)
- `fallback_rules.rs` — Hardcoded Fail Secure rules (cannot be modified)
- `threshold_optimizer.rs` — Per-ring threshold tuning from feedback
- `anomaly_profiler.rs` — Behavioral anomaly detection by IP/user/agent
- `pattern_store.rs` — Attack pattern persistence and recall
- `feedback_collector.rs` — Operator feedback intake (FP/FN reports)
- `executor.rs` — Pipeline execution coordinator

### Core Principle: Decide-without-Learn

> **Principle 1**: Decide MUST work without Learn, without Risk, and without any ring. If all rings are disabled or fail to initialize, Decide still returns a valid Decision using its Fallback Rules.

> **Principle 2** (Fail Secure): If ANY ring returned Deny, the system denies. The system never fails open.

---

## 5. The 5 Cross Rings

> **Source**: `src/cross_ring/`

Cross rings are communication channels between the defense rings and Keshav. Each has directional semantics enforced at the message level.

```mermaid
flowchart LR
    Keshav["<b>Keshav Core</b>"] 
    RingA["Ring A"]
    RingB["Ring B"]
    System["System-wide"]
    Recovery["Independent Path"]

    Keshav -->|"top-down"| RingA
    RingA <-->|"peer-to-peer"| RingB
    RingB -->|"arbitration"| Keshav
    Keshav -->|"broadcast"| System
    Recovery -.->|"no restrictions"| Keshav

    subgraph Cross Rings
        CR1["<b>Command Ring</b><br/>Keshav → Rings"]
        CR2["<b>Intel Ring</b><br/>Ring ↔ Ring"]
        CR3["<b>Control Ring</b><br/>Rings → Keshav"]
        CR4["<b>Communication Ring</b><br/>Broadcast"]
        CR5["<b>Recovery Ring</b><br/>Independent"]
    end
```

| Cross Ring | Direction | Source | Transport |
|-----------|-----------|--------|-----------|
| **Command** | Keshav → Rings (top-down) | `command_ring.rs` | `InProcessTransport` (mpsc) |
| **Intel** | Ring ↔ Ring (peer-to-peer) | `intel_ring.rs` | `InProcessTransport` (multi-subscriber) |
| **Control** | Rings → Keshav (arbitration) | `control_ring.rs` | `InProcessTransport` (mpsc) |
| **Communication** | System-wide broadcast | `communication_ring.rs` | `BroadcastTransport` (fan-out) |
| **Recovery** | Independent path | `recovery_ring.rs` | `InProcessTransport` (mpsc) |

### Cross Ring Message Structure

Every message is a `CrossRingMessage` (defined in `src/cross_ring/message.rs`):

```rust
pub struct CrossRingMessage {
    pub message_id: String,           // UUID v4
    pub timestamp: String,            // ISO 8601
    pub source: String,               // "keshav" or ring name
    pub destination: String,          // ring name, "keshav", or "broadcast"
    pub cross_ring_type: CrossRingType,
    pub msg_type: String,             // e.g., "policy_update", "attack_pattern"
    pub payload: serde_json::Value,
    pub priority: MessagePriority,    // Low / Normal / High / Critical
    pub version: String,              // Keshav version
}
```

Directional validation is enforced by `CrossRingMessage::validate_direction()`:

- **Command**: `source` must be `"keshav"`
- **Control**: `destination` must be `"keshav"`
- **Intel**: `source` must NOT be `"keshav"` (Keshav subscribes but doesn't publish)
- **Communication**: `destination` must be `"broadcast"`
- **Recovery**: No directional restrictions

### Transport Layer

The `RingTransport` trait (`src/cross_ring/transport.rs`) abstracts the communication backend:

| Implementation | Use Case |
|---------------|----------|
| `InProcessTransport` | Default, single-process (bounded mpsc channels) |
| `BroadcastTransport` | Communication Ring (fan-out with history replay) |
| `GrpcTransport` | Production distributed (gRPC + TLS + mTLS) |
| `NatsTransport` | Distributed pub/sub (NATS JetStream) |
| `RedisTransport` | Distributed (Redis Streams) |

---

## 6. ANANTA — Autonomous Trust Plane

> **Deep Dive**: [ANANTA.md](./ANANTA.md)

ANANTA is NOT a ring. It is a supervisory plane that exists above and outside the 9 defense rings and Keshav Core. It answers: **"Can the security system itself still be trusted?"**

### Critical Design Constraints

1. ANANTA never depends on Keshav (no circular dependency)
2. ANANTA has its own config file (`ananta.yaml`) — it cannot trust Keshav's config
3. ANANTA's hot-path impact is **ZERO** (all background tasks only)
4. ANANTA is optional (system works without it in degraded mode)

### 13 Subsystems across 18 Modules

```mermaid
graph TB
    subgraph ANANTA["ANANTA Autonomous Trust Plane"]
        Crypto["<b>Crypto</b><br/>hash · sign · Merkle · encrypt"]
        Anchor["<b>Anchor</b><br/>root of trust · attestation"]
        Trust["<b>Trust</b><br/>engine · graph · proofs · decay"]
        Sentinel["<b>Sentinel</b><br/>drift detection · integrity"]
        Phoenix["<b>Phoenix</b><br/>recovery · rollback · simulate"]
        Adapter["<b>Adapter</b><br/>adaptive orchestration"]
        Health["<b>Health</b><br/>DAG health · anomaly prediction"]
        Audit["<b>Audit</b><br/>immutable log · evidence"]
        Sim["<b>Simulation</b><br/>security twin · chaos"]
        Dist["<b>Distributed</b><br/>consensus · gossip · quorum"]
        Runtime["<b>Runtime</b><br/>component status"]
        Sched["<b>Scheduler</b><br/>background tasks"]
        State["<b>State</b><br/>snapshots · diffing"]
        OVAPH["<b>OVAPH Loop</b><br/>Observe→Verify→Attest→Heal→Prove"]
    end

    style ANANTA fill:#f39c12,color:#fff
    style OVAPH fill:#e74c3c,color:#fff
```

---

## 7. Policy Compiler

> **Source**: `src/policy_compiler/`

The Policy Compiler transforms human-readable YAML policy definitions into bytecode for the Policy VM:

```mermaid
flowchart LR
    YAML["YAML Policy"] --> Compiler["Policy Compiler<br/>tokenizer → parser → AST"]
    Compiler --> CodeGen["Code Generator<br/>constant folding · dead code elimination"]
    CodeGen --> Bytecode["BytecodeProgram"]
    Bytecode --> VM["Policy VM<br/>stack-based execution"]
    VM --> Decision["Decision"]

    Compiler --> Versioning["Versioning<br/>policy version tracking"]
```

Modules:

| Module | Purpose |
|--------|---------|
| `compiler.rs` | YAML → AST → bytecode compilation with optimizer |
| `vm.rs` | Stack-based bytecode VM for policy evaluation |
| `bytecode.rs` | `OpCode`, `Instruction`, `Constant`, `BytecodeProgram` |
| `versioning.rs` | Policy version tracking and change detection |

---

## 8. Request Lifecycle — End to End

```mermaid
sequenceDiagram
    participant C as Client
    participant O as Keshav-Orchestrate
    participant S as Shield Ring
    participant T as Threat Ring
    participant I as Identity Ring
    participant D as Keshav-Decide
    participant L as Decision Logger

    C->>O: POST /v1/evaluate
    O->>O: plan(request_type, has_tool_call)
    O-->>O: OrchestrationPlan { parallel_batch, sequential_batch }

    par Parallel Evaluation
        O->>S: evaluate(request)
        S-->>O: ShieldVerdict
    and
        O->>T: evaluate(request)
        T-->>O: ThreatVerdict
    and
        O->>I: evaluate(request)
        I-->>O: IdentityVerdict
    end

    Note over O: Sequential deps: Agent after Threat, Execution after Agent

    O->>D: evaluate_all(all_ring_verdicts, risk_score)
    D->>D: Policy Engine (first-match-wins)
    alt Policy matched
        D-->>O: (Decision, policy_name, reasoning)
    else No match
        D->>D: Fallback Rules (deny-on-any-ring-deny)
        D-->>O: (Decision, "fallback", reasoning)
    end

    D->>L: log(DecisionRecord)
    D-->>C: DecisionRecord { final_decision, risk_score, reasoning }
```

---

## 9. Module Dependency Graph

```mermaid
graph TD
    main["main.rs"] --> lib["lib.rs"]
    lib --> keshav["src/keshav/"]
    lib --> shield["src/shield/"]
    lib --> threat["src/threat/"]
    lib --> identity["src/identity/"]
    lib --> agent["src/agent/"]
    lib --> memory["src/memory/"]
    lib --> execution["src/execution/"]
    lib --> reasoning["src/reasoning/"]
    lib --> governance["src/governance/"]
    lib --> recovery_sec["src/recovery_sec/"]
    lib --> cross_ring["src/cross_ring/"]
    lib --> ananta["src/ananta/"]
    lib --> policy_compiler["src/policy_compiler/"]
    lib --> config["src/config.rs"]
    lib --> decision["src/decision.rs"]

    keshav --> decision
    keshav --> shield
    keshav --> threat
    keshav --> identity
    keshav --> memory
    keshav --> agent
    keshav --> execution

    ananta --> ananta_crypto["ananta/crypto/"]
    ananta --> ananta_anchor["ananta/anchor/"]
    ananta --> ananta_trust["ananta/trust/"]
    ananta --> ananta_sentinel["ananta/sentinel/"]
    ananta --> ananta_phoenix["ananta/phoenix/"]
    ananta --> ananta_health["ananta/health/"]
    ananta --> ananta_audit["ananta/audit/"]

    ananta_crypto --> ananta_anchor
    ananta_sentinel --> ananta_trust
    ananta_phoenix --> ananta_sentinel
    ananta_trust --> ananta_crypto

    style keshav fill:#4a90d9,color:#fff
    style ananta fill:#e67e22,color:#fff
    style cross_ring fill:#27ae60,color:#fff
```

---

## 10. Ring Interaction Diagram

```mermaid
graph LR
    subgraph Parallel Batch
        S["Shield"]
        T["Threat"]
        Id["Identity"]
        M["Memory"]
        Re["Reasoning"]
        Go["Governance"]
    end

    subgraph Sequential Batch
        Ag["Agent<br/><i>after Threat Allow</i>"]
        Ex["Execution<br/><i>after Agent Allow</i>"]
    end

    T -->|"AllowOnly"| Ag
    Ag -->|"AllowOnly"| Ex

    subgraph Keshav Core
        D["Decide"]
        R["Risk"]
        L["Learn"]
    end

    S --> D
    T --> D
    Id --> D
    M --> D
    Ag --> D
    Ex --> D
    Re --> D
    Go --> D
    R --> D
    L -.->|"advisory only"| D

    style Keshav Core fill:#4a90d9,color:#fff
```

---

## 11. Configuration

CHAKRAVYUH uses two independent configuration files:

| Config File | Format | Controls |
|------------|--------|----------|
| `config.yaml` | YAML | Keshav Core, all 9 rings, API settings |
| `ananta.yaml` | YAML | ANANTA Trust Plane (independent) |

ANANTA's config is deliberately separate — since ANANTA protects Keshav, it cannot trust Keshav's configuration.

### Example Config Paths

- Main config: `configs/config.example.yaml`
- ANANTA config: `configs/ananta.example.yaml`

---

## 12. Threat Ring Engine Pipeline

The Threat Ring (`src/threat/`) runs 6 engines in sequence:

```mermaid
flowchart LR
    Input["Input Text"] --> OD["<b>ObfuscationDecoder</b><br/>URL/Base64/Hex/Leetspeak"]
    OD --> PM["<b>PatternMatcher</b><br/>Regex + AttackLibrary"]
    PM --> SC["<b>SemanticClassifier</b><br/>Intent classification"]
    SC --> JB["<b>JailbreakDetector</b><br/>Multi-turn JB detection"]
    JB --> CS["<b>ConfidenceScorer</b><br/>Composite score + confidence"]
    CS --> Output["ThreatVerdict"]

    AL["<b>AttackLibrary</b><br/>data/threat/attack_library.json"] -.-> PM
```

---

## 13. Identity Ring Engine Pipeline

```mermaid
flowchart LR
    Input["Session Data"] --> SI["<b>SessionIdentity</b><br/>Principal resolution"]
    SI --> RR["<b>RoleResolver</b><br/>Role → permission mapping"]
    RR --> TA["<b>TrustAccumulator</b><br/>Composite trust score"]
    TA --> IA["<b>IdentityAnomaly</b><br/>Anomaly detection"]
    IA --> Output["IdentityVerdict"]
```

---

## 14. Key Architectural Guarantees

| Guarantee | Mechanism | Source |
|-----------|-----------|--------|
| **Never fail open** | Fallback Rules are hardcoded; deny-on-any-ring-deny | `fallback_rules.rs` |
| **Decide without Learn** | Learn can only advise, never override Fallback Rules | `learn.rs` |
| **Zero ANANTA hot-path impact** | ANANTA runs as background tokio tasks only | `ananta/mod.rs` |
| **Independent ANANTA config** | Separate `ananta.yaml`, cannot depend on Keshav config | `ananta/config.rs` |
| **Append-only audit** | DecisionLogger, ANANTA AuditLog — records cannot be modified | `decision_logger.rs`, `ananta/audit/` |
| **Hot-reload policies** | PolicyManager uses RwLock for atomic swap; failure preserves old policy | `policy_manager.rs` |
| **Directional cross rings** | `validate_direction()` enforces message flow rules | `cross_ring/message.rs` |
| **Statistical drift detection** | Welford's online algorithm, not threshold-based alerting | `ananta/sentinel/drift.rs` |

---

## 15. Source Tree Layout

```
src/
├── main.rs                    # Binary entry point
├── lib.rs                     # Library root
├── config.rs                  # Main configuration
├── decision.rs                # Decision, DecisionRecord, RiskScore
├── error.rs                   # Error types
├── keshav/                    # Keshav Core — Central Decision Brain
├── cross_ring/                # 5 Cross Rings (Command, Intel, Control, Communication, Recovery)
├── shield/                    # Ring 1 — Shield (WAF, rate limit, geo, bot, DoS)
├── identity/                  # Ring 2 — Identity (session, role, trust, anomaly)
├── threat/                    # Ring 3 — Threat (6 engines)
├── agent/                     # Ring 4 — Agent (behavior, capability, permission)
├── memory/                    # Ring 5 — Memory (context, RAG, PII, conversation)
├── execution/                 # Ring 6 — Execution (sandbox, SSRF, parameter)
├── reasoning/                 # Ring 7 — Reasoning
├── governance/                # Ring 8 — Governance
├── recovery_sec/              # Ring 9 — Recovery Security
├── ananta/                    # ANANTA — Autonomous Trust Plane (13 subsystems)
├── policy_compiler/           # YAML → Bytecode compiler + VM
├── validation/                # Testing, verification, benchmarks, red team
├── storage/                   # Memory + Redis stores
├── observability/              # Metrics, OpenTelemetry, alerting
├── incident_response/         # Playbooks, webhooks, evidence chains
├── federated/                 # Federated learning, differential privacy
├── twin/                      # Digital twin engine
├── plugin/                    # WASM plugin runtime
├── tenant/                    # Multi-tenancy
├── cli/                       # CLI commands
└── api/                       # API handlers
```
