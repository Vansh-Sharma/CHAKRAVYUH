# Changelog

All notable changes to CHAKRAVYUH are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

---

## [1.0.0] - FROZEN

**Status: API surface frozen.** See `docs/API_STABILITY.md` for the stability guarantee.
No breaking changes will be made within the 1.0.x series.

### Added

- **All 9 Security Rings** fully implemented and tested:
  - Shield Ring (6 engines), Identity Ring (4 engines), Threat Ring (6 engines),
    Agent Ring (6 engines), Memory Ring (6 engines), Execution Ring (6 engines),
    Reasoning Ring, Governance Ring, Recovery Ring
- **5 Cross Rings**: Command, Intel, Control, Communication, Recovery
- **Keshav Core**: Decide, Risk, Learn, Orchestrate, Policy Engine, Pattern Store,
  Threshold Optimizer, Anomaly Profiler, Feedback Collector
- **ANANTA Trust Plane**: Shadow, Pulse, Guard, Evolve, Void subsystems plus
  Trust Engine, Sentinel, Scheduler, Crypto (BLAKE3/SHA-256/Ed25519/AES-256-GCM),
  OVAPH continuous validation loop
- **Policy Compiler**: YAML → bytecode VM with versioned policies
- **Plugin System**: WASM-based runtime with marketplace API
- **Storage Backends**: In-memory (default) + Redis (optional feature)
- **Phase D Security Validation Platform**: red team framework, soak testing,
  chaos engineering, 16 fuzz targets, formal verification, security twin,
  comparative benchmarks, ANANTA-specific verification
- **3,200+ tests** (unit, integration, property-based, OWASP LLM01 benchmark)
- **OWASP LLM01 benchmark**: 529 attack patterns, 100% detection, 0% false positives,
  0.74ms p99
- `cargo audit` passes with **0 vulnerabilities**

### Hardened

- `h2` pinned to >= 0.4.16 (RUSTSEC-2026-0258)
- `maxminddb` upgraded to 0.27 (RUSTSEC-2025-0132)
- `notify` upgraded to 8.0 (eliminated `instant` transitive dependency)
- `axum-server` 0.8 TLS path reviewed — no `rustls-pemfile` dependency

---

## [0.9.0]

### Added

- ANANTA Trust Plane (Shadow, Pulse, Guard, Evolve, Void)
- Policy Compiler with bytecode VM and versioned policy execution
- WASM Plugin System with plugin API and marketplace support
- Pluggable Storage backends (in-memory + Redis)
- Multi-tenant support with quota management and policy isolation
- Federated threat intelligence sync with differential privacy
- Security digital twin for scenario simulation
- gRPC service definitions (`proto/chakravyuh.proto`)

---

## [0.8.0]

### Added

- Memory Ring (ContextGuard, PIIExtractor, ConversationTracker, RAGPoisonDetector,
  ProvenanceValidator, MemoryAccessControl)
- Agent Ring (AgentPolicy, PermissionEnforcer, AgentScope, CapabilityGuard,
  BehaviorMonitor, ToolChainingDetector)
- Keshav-Learn: ML-based risk scoring and anomaly detection
- Keshav-Orchestrate: ring coordination with static routing
- Threshold Optimizer, Anomaly Profiler, Feedback Collector, Pattern Store

---

## [0.7.0]

### Added

- Identity Ring (SessionIdentity, RoleResolver, TrustAccumulator, IdentityAnomaly)
- Execution Ring (ToolAllowlist, ParameterValidator, SandboxExecutor,
  ApprovalWorkflow, ActionLogger, SSRFProtector)
- Keshav-Risk: composite risk scoring with 6 weighted signals
- All 5 Cross Rings (Command, Intel, Control, Communication, Recovery)
- Multi-tenant context and role-based access control

---

## [0.6.0]

### Added

- Threat Ring (ObfuscationDecoder, PatternMatcher, SemanticClassifier,
  JailbreakDetector, ConfidenceScorer, AttackLibrary v3)
- Keshav-Decide: rule-based policy engine with YAML configuration
- Policy Engine with default-deny semantics
- Decision Logger with JSON/CSV export
- Fallback Rules (Fail Secure principle)

---

## [0.5.0]

### Added

- Shield Ring (InputValidator, RateLimiter, DoSProtector, GeoFencer,
  BotDetector, WAFEngine)
- HTTP API (`/v1/evaluate`, `/health`, `/version`)
- CLI with 14 subcommands
- Reverse proxy mode (`/v1/proxy`) for OpenAI-compatible upstreams
- Project scaffolding, CI pipeline, and documentation foundation
