# CHAKRAVYUH v1.0.0 — Frozen Public API Surface

> **FROZEN** as of Phase A (Core Freeze).  
> Date: 2026-08-05  
> Version: 1.0.0  
> License: Apache-2.0  
>  
> This document is the canonical record of every `pub` type, function, trait, and method
> in the CHAKRAVYUH codebase. No signature may change, no public type may be added or
> removed, without following the deprecation discipline defined in `API_STABILITY.md`.

---

## Table of Contents

1. [Root Types](#root-types)
2. [Shield Ring](#shield-ring)
3. [Identity Ring](#identity-ring)
4. [Threat Ring](#threat-ring)
5. [Execution Ring](#execution-ring)
6. [Agent Ring](#agent-ring)
7. [Memory Ring](#memory-ring)
8. [Reasoning Ring](#reasoning-ring)
9. [Governance Ring](#governance-ring)
10. [Recovery Ring](#recovery-sec-ring)
11. [Keshav (Decision Brain)](#keshav-decision-brain)
12. [ANANTA (Trust Plane)](#ananta-trust-plane)
13. [Cross-Ring Network](#cross-ring-network)
14. [Storage Layer](#storage-layer)
15. [Infrastructure](#infrastructure)
16. [Policy Compiler](#policy-compiler)
17. [Incident Response](#incident-response)
18. [Federated Module](#federated-module)
19. [Tenant Module](#tenant-module)
20. [Plugin System](#plugin-system)
21. [Security Twin](#security-twin)
22. [Observability](#observability)
23. [CLI](#cli)
24. [API / gRPC](#api--grpc)
25. [Summary Statistics](#summary-statistics)

---

## Root Types

### `chakravyuh`

#### pub structs

- `Chakravyuh { pub storage: Box<dyn Store>, pub policy_manager: PolicyManager, pub shutdown: ShutdownState, pub audit: AuditTrail, pub api_key_manager: ApiKeyManager, ... }`

#### impl Chakravyuh

- `fn new(config: Config) -> Result<Self>`
- `fn serve(self, addr: &str) -> Result<()>`
- `fn config(&self) -> &Config`
- `fn agent(&self) -> &AgentRing`
- `fn memory(&self) -> &MemoryRing`
- `fn reasoning(&self) -> &ReasoningRing`
- `fn governance(&self) -> &GovernanceRing`
- `fn recovery_sec(&self) -> &RecoveryRing`
- `fn identity(&self) -> &IdentityRing`
- `fn execution(&self) -> &ExecutionRing`
- `fn risk(&self) -> &KeshavRisk`
- `fn learn(&self) -> &KeshavLearn`
- `fn orchestrate(&self) -> &KeshavOrchestrate`
- `fn cross_ring(&self) -> &CrossRingNetwork`
- `fn storage(&self) -> &dyn Store`
- `fn policy_manager(&self) -> &PolicyManager`
- `fn shutdown(&self) -> &ShutdownState`
- `fn ananta(&self) -> Option<&AnantaPlane>`

---

### `chakravyuh::error`

#### pub enums

- `Error` — `ConfigLoad(String)` | `ConfigParse(String)` | `EngineInit(String)` | `RateLimiterStorage(String)` | `Evaluation(String)` | `Serialization(String)` | `Io(std::io::Error)` | `Other(String)`

---

### `chakravyuh::config`

#### pub structs

- `Config { pub server: ServerConfig, pub shield: ShieldConfig, pub upstream: Option<UpstreamConfig>, pub threat: ThreatConfig, pub identity: IdentityConfig, pub agent: AgentConfig, pub memory: MemoryConfig, pub execution: ExecutionConfig, pub reasoning: ReasoningConfig, pub governance: GovernanceConfig, pub recovery_sec: RecoverySecConfig, pub keshav: KeshavConfig, pub cross_ring: CrossRingConfig, pub storage: StorageConfig, pub grpc: GrpcConfig, pub logging: LoggingConfig, pub config_watcher: ConfigWatcherConfig, pub audit: AuditConfig, pub api_keys: ApiKeyConfig, pub ananta_config_path: Option<String> }`
- `UpstreamConfig { pub url: String, pub api_key: String, pub timeout_secs: u64, pub forward_client_auth: bool }`
- `ServerConfig { pub bind: String, pub workers: usize, pub tls: Option<TlsConfig> }`
- `TlsConfig { pub cert_path: String, pub key_path: String }`
- `ShieldConfig { pub enabled: bool, pub input_validator: InputValidatorConfig, pub rate_limiter: RateLimiterConfig, pub dos_protector: DosProtectorConfig, pub geo_fencer: GeoFencerConfig, pub bot_detector: BotDetectorConfig, pub waf: WafConfig }`
- `LoggingConfig { pub level: String, pub format: String }`

#### impl Config

- `fn from_file<P: AsRef<Path>>(path: P) -> Result<Self>`
- `fn default_yaml() -> &'static str`

---

### `chakravyuh::decision`

#### pub enums

- `Decision` — `Allow` | `Deny { code: String, retry_after: Option<u32> }` | `Challenge { challenge_type: ChallengeType }` | `Escalate { approver_role: String, timeout_secs: u64 }`
- `ChallengeType` — `Javascript` | `Captcha` | `TwoFactor` | `EmailVerification`

#### pub structs

- `RiskScore { pub overall: f64, pub threat: f64, pub identity: f64, pub behavior: f64, pub memory: f64, pub execution: f64, pub context: f64, pub confidence: f64 }`
- `DecisionRecord { pub request_id: String, pub timestamp: String, pub source: DecisionSource, pub risk_score: RiskScore, pub rings_evaluated: Vec<u8>, pub ring_verdicts: serde_json::Value, pub policy_applied: Option<String>, pub final_decision: Decision, pub reasoning: String, pub latency_ms: f64, pub keshav_version: String, pub policy_version: String }`
- `DecisionSource { pub ip: String, pub user_id: Option<String>, pub agent_id: Option<String>, pub api_key: Option<String> }`

#### pub traits

- `Verdict` — `fn decision(&self) -> &Decision;` `fn latency_ms(&self) -> f64;`

#### impl Decision

- `fn is_allow(&self) -> bool`
- `fn is_deny(&self) -> bool`
- `fn http_status(&self) -> u16`

---

## Shield Ring

### `chakravyuh::shield`

#### pub structs

- `ShieldRing { ... }` (private fields)
- `ShieldRequest { pub source_ip: String, pub user_agent: Option<String>, pub api_key: Option<String>, pub user_id: Option<String>, pub method: String, pub path: String, pub headers: HashMap<String, String>, pub body: serde_json::Value }`
- `ShieldVerdict { pub decision: Decision, pub engine_results: Vec<EngineResult>, pub latency_ms: f64 }`
- `EngineResult { pub engine_name: String, pub decision: Decision, pub reason: String, pub latency_ms: f64, pub metadata: serde_json::Value }`

#### impl ShieldRing

- `fn new(config: Arc<Config>) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> ShieldVerdict`

#### impl ShieldRequest

- `fn prompt_text(&self) -> Option<String>`

---

### `chakravyuh::shield::input_validator`

#### pub structs

- `InputValidatorConfig { pub enabled: bool, pub max_prompt_length: usize, pub max_tokens: usize, pub max_messages: usize, pub required_fields: Vec<String> }`
- `InputValidator { ... }` (private fields)

#### impl InputValidator

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

### `chakravyuh::shield::rate_limiter`

#### pub structs

- `RateLimiterConfig { pub enabled: bool, pub backend: String, pub redis_url: Option<String>, pub limits: RateLimits }`
- `RateLimits { pub per_ip: String, pub per_api_key: String, pub per_user: String }`
- `RateLimiter { ... }` (private fields)

#### impl RateLimiter

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn with_storage(shield_config: &ShieldConfig, storage: Arc<dyn RateLimitStorage>) -> Self`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

### `chakravyuh::shield::rate_limiter_storage`

#### pub structs

- `Bucket { pub tokens: f64, pub last_refill: Instant }`
- `MemoryStorage { ... }` (private fields)

#### pub traits

- `RateLimitStorage: Send + Sync + std::fmt::Debug` — `fn try_consume(&self, key: &str, capacity: f64, refill_per_sec: f64) -> bool;` `fn bucket_count(&self) -> usize { 0 }`

#### impl Bucket

- `fn new(capacity: f64) -> Self`
- `fn refill(&mut self, capacity: f64, refill_per_sec: f64)`
- `fn try_consume(&mut self, capacity: f64, refill_per_sec: f64) -> bool`

#### impl MemoryStorage

- `fn new() -> Self`

#### pub fns

- `fn build_storage(backend: &str, redis_url: Option<&str>) -> Result<Box<dyn RateLimitStorage>, String>`

---

### `chakravyuh::shield::dos_protector`

#### pub structs

- `DosProtectorConfig { pub enabled: bool, pub baseline_window: u64, pub threshold_sigma: f64, pub block_duration: u64, pub min_requests: usize, pub hard_limit_per_min: usize }`
- `DosProtector { ... }` (private fields)

#### impl DosProtector

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

### `chakravyuh::shield::geo_fencer`

#### pub structs

- `GeoFencerConfig { pub enabled: bool, pub mode: String, pub countries: Vec<String>, pub default_on_lookup_fail: String, pub db_path: String }`
- `GeoFencer { ... }` (private fields)

#### impl GeoFencer

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

### `chakravyuh::shield::bot_detector`

#### pub structs

- `BotDetectorConfig { pub enabled: bool, pub challenge_unknown: bool, pub good_bots: Vec<String>, pub bad_bots: Vec<String> }`
- `BotDetector { ... }` (private fields)

#### impl BotDetector

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

### `chakravyuh::shield::waf_engine`

#### pub structs

- `WafConfig { pub enabled: bool, pub sanitize: bool, pub custom_rules: Vec<CustomRule> }`
- `CustomRule { pub name: String, pub pattern: String, pub action: String }`
- `WafEngine { ... }` (private fields)

#### impl WafEngine

- `fn new(shield_config: &ShieldConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> EngineResult`

---

## Identity Ring

### `chakravyuh::identity`

#### pub structs

- `IdentityConfig { pub enabled: bool, pub session_identity: SessionIdentityConfig, pub role_resolver: RoleResolverConfig, pub trust_accumulator: TrustAccumulatorConfig, pub identity_anomaly: IdentityAnomalyConfig, pub challenge_threshold: f64, pub deny_threshold: f64 }`
- `IdentityRequest { pub source_ip: String, pub user_agent: Option<String>, pub api_key: Option<String>, pub was_denied: bool, pub request_id: String, pub headers: HashMap<String, String> }`
- `IdentityEngineResult { pub engine_name: String, pub decision: String, pub reason: String, pub latency_ms: f64, pub metadata: serde_json::Value }`
- `IdentityVerdict { pub decision: Decision, pub identity_profile: Option<IdentityProfile>, pub role: Option<Role>, pub trust_result: Option<TrustResult>, pub anomaly_result: Option<AnomalyResult>, pub engine_results: Vec<IdentityEngineResult>, pub latency_ms: f64, pub identity_risk_score: f64 }`
- `IdentityRing { ... }` (private fields)

#### impl IdentityRing

- `fn new(config: &IdentityConfig) -> Result<Self>`
- `fn evaluate(&self, request: &IdentityRequest) -> IdentityVerdict`
- `fn trust_accumulator(&self) -> &TrustAccumulator`
- `fn identity_anomaly(&self) -> &IdentityAnomaly`
- `fn config(&self) -> &IdentityConfig`

---

### `chakravyuh::identity::session_identity`

#### pub structs

- `SessionIdentityConfig { ... }`
- `IdentityProfile { pub identity_type: IdentityType, ... }`
- `SessionIdentity { ... }`
- `IdentityResult { pub valid: bool, pub reason: String, pub profile: IdentityProfile, pub latency_ms: f64 }`

#### pub enums

- `IdentityType` — `Anonymous` | `ApiKey` | `Jwt` | `Session` | `MTLS` | `Internal` | `Unknown`

#### impl SessionIdentity

- `fn new(config: &SessionIdentityConfig) -> Self`
- `fn evaluate(&self, api_key: Option<&str>, headers: &HashMap<String, String>) -> IdentityResult`

---

### `chakravyuh::identity::role_resolver`

#### pub structs

- `RoleResolverConfig { ... }`
- `RoleResolver { ... }`
- `RoleResult { pub role: Role, pub permissions: Vec<Permission>, pub reason: String }`

#### pub enums

- `Role` — `Admin` | `User` | `Service` | `Anonymous`
- `Permission` — `Read` | `Write` | `Execute` | `Admin` | `ManageUsers`

#### impl Role

- `fn level(&self) -> u8`

#### impl RoleResolver

- `fn new(config: &RoleResolverConfig) -> Self`
- `fn evaluate(&self, profile: &IdentityProfile) -> RoleResult`

---

### `chakravyuh::identity::trust_accumulator`

#### pub structs

- `TrustAccumulatorConfig { ... }`
- `TrustAccumulator { ... }`
- `TrustResult { pub trust_score: f64, pub reason: String, pub factors: serde_json::Value, pub request_count: usize }`

#### impl TrustAccumulator

- `fn new(config: &TrustAccumulatorConfig) -> Self`
- `fn evaluate(&self, profile: &IdentityProfile, role: &Role, source_ip: &str, user_agent: Option<&str>, was_denied: bool) -> TrustResult`
- `fn get_trust(&self, principal_id: &str) -> Option<f64>`
- `fn tracked_count(&self) -> usize`
- `fn reset(&self)`

---

### `chakravyuh::identity::identity_anomaly`

#### pub structs

- `IdentityAnomalyConfig { ... }`
- `Anomaly { pub anomaly_type: AnomalyType, pub score: f64, pub description: String, pub metadata: serde_json::Value }`
- `AnomalyResult { pub anomalies: Vec<Anomaly>, pub composite_score: f64, pub is_severe: bool, pub summary: String }`
- `IdentityAnomaly { ... }`

#### pub enums

- `AnomalyType` — `IpHop` | `ImpossibleTravel` | `VelocityAnomaly` | `CredentialAbuse` | `PrivilegeEscalation`

#### impl IdentityAnomaly

- `fn new(config: &IdentityAnomalyConfig) -> Self`
- `fn evaluate(&self, profile: &IdentityProfile, role: &Role, source_ip: &str, user_agent: Option<&str>, trust: &TrustResult) -> AnomalyResult`
- `fn reset(&self)`

---

## Threat Ring

### `chakravyuh::threat`

#### pub structs

- `ThreatConfig { pub enabled: bool, pub pattern_matcher: PatternMatcherConfig, pub semantic_classifier: SemanticClassifierConfig, pub jailbreak_detector: JailbreakDetectorConfig, pub deny_threshold: f64, pub challenge_threshold: f64 }`
- `PatternMatcherConfig { pub enabled: bool }`
- `SemanticClassifierConfig { pub enabled: bool }`
- `JailbreakDetectorConfig { pub enabled: bool }`
- `ThreatRing { ... }` (private fields)
- `ThreatEngineResult { pub engine_name: String, pub score: f64, pub confidence: f64, pub signals: Vec<String>, pub reason: String, pub latency_ms: f64 }`
- `ThreatVerdict { pub decision: Decision, pub engine_results: Vec<ThreatEngineResult>, pub composite_score: f64, pub confidence: f64, pub matched_signatures: Vec<String>, pub latency_ms: f64 }`

#### impl ThreatRing

- `fn new(config: Arc<ThreatConfig>) -> Result<Self>`
- `fn evaluate(&self, request: &ShieldRequest) -> ThreatVerdict`
- `fn attack_library(&self) -> &AttackLibrary`

---

### `chakravyuh::threat::attack_library`

#### pub structs

- `AttackSignature { pub id: String, pub name: String, pub attack_type: AttackType, pub patterns: Vec<String>, pub severity: String, pub description: String, pub enabled: bool }`
- `SignatureMatch { pub signature_id: String, pub signature_name: String, pub attack_type: String, pub matched_pattern: String, pub severity: String, pub start_pos: usize, pub end_pos: usize, pub score: f64 }`
- `AttackLibrary { ... }` (private fields)

#### pub enums

- `AttackType` — `PromptInjection` | `Jailbreak` | `PersonaHijack` | `InstructionOverride` | `DataExfiltration` | `Obfuscation`
- `MatchKind` — `Exact` | `Regex` | `Fuzzy`

#### impl AttackType

- `fn label(&self) -> &'static str`

#### impl AttackLibrary

- `fn load_default() -> Self`
- `fn from_json(json: &str) -> Result<Self, String>`
- `fn version(&self) -> &str`
- `fn signatures(&self) -> &[AttackSignature]`
- `fn scan(&self, prompt_lower: &str) -> Vec<SignatureMatch>`

---

### `chakravyuh::threat::confidence_scorer`

#### pub structs

- `ScoredResult { pub composite_score: f64, pub confidence: f64, pub matched_signatures: Vec<String> }`
- `ConfidenceScorer;`

#### impl ConfidenceScorer

- `fn new() -> Self`
- `fn score(&self, engine_results: &[ThreatEngineResult]) -> ScoredResult`

---

### `chakravyuh::threat::jailbreak_detector`

#### impl JailbreakDetector

- `fn new(config: &JailbreakDetectorConfig, attack_library: Arc<AttackLibrary>) -> Result<Self>`
- `fn evaluate(&self, _prompt: &str, prompt_lower: &str) -> ThreatEngineResult`

---

### `chakravyuh::threat::obfuscation_decoder`

#### impl ObfuscationDecoder

- `fn new() -> Self`
- `fn decode_into(&self, prompt: &str, prompt_lower: &mut String) -> ThreatEngineResult`

---

### `chakravyuh::threat::pattern_matcher`

#### impl PatternMatcher

- `fn new(config: &PatternMatcherConfig, attack_library: Arc<AttackLibrary>) -> Result<Self>`
- `fn evaluate(&self, _prompt: &str, prompt_lower: &str) -> ThreatEngineResult`

---

### `chakravyuh::threat::semantic_classifier`

#### impl SemanticClassifier

- `fn new(config: &SemanticClassifierConfig) -> Result<Self>`
- `fn evaluate(&self, _prompt: &str, prompt_lower: &str) -> ThreatEngineResult`

---

## Execution Ring

### `chakravyuh::execution`

#### pub structs

- `ExecutionConfig { pub enabled: bool, pub tool_allowlist: ToolAllowlistConfig, pub parameter_validator: ParameterValidatorConfig, pub sandbox_executor: SandboxExecutorConfig, pub approval_workflow: ApprovalWorkflowConfig, pub action_logger: ActionLoggerConfig, pub ssrf_protector: SsrfProtectorConfig }`
- `ToolCall { pub tool_name: String, pub parameters: serde_json::Value, pub request_id: String, pub source_ip: String, pub agent_id: Option<String>, pub user_id: Option<String> }`
- `ExecutionEngineResult { pub engine_name: String, pub decision: Decision, pub reason: String, pub latency_ms: f64 }`
- `ExecutionVerdict { pub decision: Decision, pub engine_results: Vec<ExecutionEngineResult>, pub sandbox_config: Option<SandboxConfig>, pub approval_request: Option<ApprovalRequest>, pub latency_ms: f64 }`
- `ExecutionRing { ... }` (private fields)

#### impl ExecutionRing

- `fn new(config: &ExecutionConfig) -> Result<Self>`
- `fn evaluate(&self, call: &ToolCall) -> ExecutionVerdict`
- `fn action_logger(&self) -> &ActionLogger`

---

### `chakravyuh::execution::tool_allowlist`

#### pub structs

- `ToolEntry { pub name: String, pub description: String, pub risk_level: String, pub max_calls_per_request: usize, pub allowed_params: Vec<String> }`
- `ToolAllowlistConfig { pub enabled: bool, pub tools: Vec<ToolEntry>, pub default_max_calls: usize }`
- `ToolAllowlistResult { pub decision: Decision, pub reason: String, pub latency_ms: f64 }`
- `ToolAllowlist { ... }` (private fields)

#### impl ToolAllowlist

- `fn new(config: &ToolAllowlistConfig) -> Result<Self>`
- `fn evaluate(&self, tool_name: &str, request_id: &str) -> ToolAllowlistResult`
- `fn reset_request(&self, request_id: &str)`
- `fn tools(&self) -> &[ToolEntry]`

---

### `chakravyuh::execution::parameter_validator`

#### pub structs

- `ToolParameterSchema { pub tool_name: String, pub schema: ParameterSchema }`
- `ParameterSchema { pub properties: HashMap<String, PropertySpec>, pub required: Vec<String> }`
- `PropertySpec { pub property_type: PropertyType, pub description: String, pub constraints: serde_json::Value }`
- `ParameterValidatorResult { pub decision: Decision, pub reason: String, pub errors: Vec<String>, pub latency_ms: f64 }`
- `ParameterValidatorConfig { pub enabled: bool, pub schemas: Vec<ToolParameterSchema>, pub strict_mode: bool }`

#### pub enums

- `PropertyType` — `String` | `Number` | `Boolean` | `Array` | `Object`

#### impl ParameterValidator

- `fn new(config: &ParameterValidatorConfig) -> Result<Self>`
- `fn evaluate(&self, tool_name: &str, params: &serde_json::Value) -> ParameterValidatorResult`

---

### `chakravyuh::execution::sandbox_executor`

#### pub structs

- `SandboxExecutorConfig { pub enabled: bool, pub default_mode: SandboxMode, pub timeout_ms: u64, pub memory_limit_mb: usize, pub allowed_network: bool }`
- `SandboxConfig { pub mode: SandboxMode, pub timeout_ms: u64, pub memory_limit_mb: usize, pub allowed_network: bool }`
- `SandboxExecutorResult { pub sandbox_config: SandboxConfig, pub latency_ms: f64 }`

#### pub enums

- `SandboxMode` — `None` | `Standard` | `Restricted` | `NetworkIsolated` | `Full`

#### impl SandboxExecutor

- `fn new(config: &SandboxExecutorConfig) -> Result<Self>`
- `fn evaluate(&self, tool_name: &str) -> SandboxExecutorResult`

---

### `chakravyuh::execution::approval_workflow`

#### pub structs

- `ApprovalRequest { pub request_id: String, pub tool_name: String, pub parameters: serde_json::Value, pub required_approver_role: String, pub timeout_secs: u64, pub reason: String }`
- `ApprovalWorkflowResult { pub approval_required: Option<ApprovalRequest>, pub reason: String, pub latency_ms: f64 }`
- `ApprovalWorkflowConfig { pub enabled: bool, pub rules: Vec<ApprovalRule>, pub default_timeout_secs: u64 }`
- `ApprovalRule { pub tool_pattern: String, pub required_role: String, pub conditions: ApprovalConditions, pub fallback: ApprovalFallback }`
- `ApprovalConditions { pub require_high_risk: bool, pub risk_threshold: f64, pub max_parameter_size: usize }`

#### pub enums

- `ApprovalFallback` — `Deny` | `Allow` | `Challenge`

#### impl ApprovalWorkflow

- `fn new(config: &ApprovalWorkflowConfig) -> Result<Self>`
- `fn evaluate(&self, tool_name: &str, request_id: &str, params: &serde_json::Value) -> ApprovalWorkflowResult`

---

### `chakravyuh::execution::action_logger`

#### pub structs

- `ActionLogEntry { pub request_id: String, pub tool_name: String, pub parameters: serde_json::Value, pub decision: String, pub source_ip: String, pub latency_ms: f64, pub timestamp: String, pub hash: String, pub prev_hash: String }`
- `ActionLoggerConfig { pub enabled: bool, pub max_entries: usize }`

#### impl ActionLogger

- `fn new(config: &ActionLoggerConfig) -> Result<Self>`
- `fn in_memory() -> Self`
- `fn log(&self, request_id: &str, tool_name: &str, params: &serde_json::Value, decision: &str, source_ip: &str, latency_ms: f64)`
- `fn entries(&self) -> Vec<ActionLogEntry>`
- `fn export_json(&self) -> Result<String>`
- `fn export_csv(&self) -> Result<String>`
- `fn verify_chain(&self) -> bool`
- `fn encode(bytes: impl AsRef<[u8]>) -> String`

---

### `chakravyuh::execution::ssrf_protector`

#### pub structs

- `SsrfProtectorConfig { pub enabled: bool, pub blocked_cidrs: Vec<String>, pub allow_localhost: bool, pub allow_private_networks: bool, pub allow_link_local: bool, pub max_redirects: usize }`
- `SsrfProtectorResult { pub decision: Decision, pub reason: String, pub is_internal: bool, pub latency_ms: f64 }`

#### impl SsrfProtector

- `fn new(config: &SsrfProtectorConfig) -> Result<Self>`
- `fn evaluate(&self, target: &str) -> SsrfProtectorResult`

---

## Agent Ring

### `chakravyuh::agent`

#### pub structs

- `AgentConfig { pub enabled: bool, pub permission_enforcer: PermissionEnforcerConfig, pub behavior_monitor: BehaviorMonitorConfig, pub tool_chaining_detector: ToolChainingDetectorConfig, pub agent_policy: AgentPolicyConfig, pub agent_scope: AgentScopeConfig, pub capability_guard: CapabilityGuardConfig }`
- `AgentRequest { pub agent_id: String, pub agent_type: AgentType, pub action: String, pub tools: Vec<String>, pub source_ip: String, pub target: Option<String>, pub context: serde_json::Value }`
- `AgentEngineResult { pub engine_name: String, pub decision: String, pub reason: String, pub risk_score: f64, pub latency_ms: f64, pub metadata: serde_json::Value }`
- `AgentVerdict { pub decision: Decision, pub engine_results: Vec<AgentEngineResult>, pub agent_risk_score: f64, pub latency_ms: f64 }`
- `AgentRing { ... }` (private fields)

#### impl AgentRing

- `fn new(config: &AgentConfig) -> Result<Self>`
- `fn evaluate(&self, request: &AgentRequest) -> AgentVerdict`

---

### `chakravyuh::agent::agent_policy`

#### pub enums

- `AgentType` — `Autonomous` | `SemiAutonomous` | `HumanInTheLoop`

#### pub structs

- `AgentPolicyConfig { pub enabled: bool, pub policies: HashMap<String, serde_json::Value> }`
- `AgentPolicyResult { pub allowed: bool, pub reason: String }`

#### impl AgentPolicy

- `fn new(config: &AgentPolicyConfig) -> Self`
- `fn evaluate(&self, agent_type: &AgentType, agent_id: &str) -> AgentPolicyResult`

---

### `chakravyuh::agent::agent_scope`

#### pub enums

- `AgentScopeType` — `Global` | `Tenant` | `User` | `Session` | `Request`

#### pub structs

- `AgentScopeConfig { pub default_scope: AgentScopeType }`
- `ScopeVerdict { pub in_scope: bool, pub effective_scope: AgentScopeType, pub reason: String }`

#### impl AgentScope

- `fn new(config: &AgentScopeConfig) -> Self`
- `fn evaluate(&self, scope: &AgentScopeType, action: &str, target: &Option<String>) -> ScopeVerdict`

---

### `chakravyuh::agent::behavior_monitor`

#### pub structs

- `BehaviorMonitorConfig { pub enabled: bool, pub max_history: usize, pub anomaly_threshold: f64 }`
- `BehaviorAnalysis { pub is_anomalous: bool, pub anomaly_score: f64, pub deviation_factors: Vec<String>, pub history_size: usize }`

#### impl BehaviorMonitor

- `fn new(config: &BehaviorMonitorConfig) -> Self`
- `fn evaluate(&self, agent_id: &str, _action: &str, tools: &[String], _source_ip: &str) -> BehaviorAnalysis`

---

### `chakravyuh::agent::capability_guard`

#### pub enums

- `Capability` — `Read` | `Write` | `Execute` | `Network` | `FileSystem` | `Admin` | `Privileged`

#### pub structs

- `CapabilityGuardConfig { pub enabled: bool, pub max_capabilities: usize, pub blocked_capabilities: Vec<Capability> }`
- `CapabilityGuardResult { pub allowed: bool, pub blocked_capabilities: Vec<Capability>, pub reason: String }`

#### impl CapabilityGuard

- `fn new(config: &CapabilityGuardConfig) -> Self`
- `fn evaluate(&self, agent_type: &AgentType, tools: &[String]) -> CapabilityGuardResult`

---

### `chakravyuh::agent::permission_enforcer`

#### pub enums

- `Permission` — `ReadData` | `WriteData` | `ExecuteTool` | `ManageAgent` | `AdminAccess`

#### pub structs

- `PermissionEnforcerConfig { pub enabled: bool, pub role_permissions: HashMap<String, Vec<Permission>> }`
- `PermissionResult { pub allowed: bool, pub granted_permissions: Vec<Permission>, pub denied_permissions: Vec<Permission>, pub reason: String }`

#### impl PermissionEnforcer

- `fn new(config: &PermissionEnforcerConfig) -> Self`
- `fn evaluate(&self, agent_type: &AgentType, action: &str, tools: &[String]) -> PermissionResult`

---

### `chakravyuh::agent::tool_chaining_detector`

#### pub structs

- `ChainPattern { pub tool_sequence: Vec<String>, pub max_chain_length: usize, pub risk_score: f64 }`
- `ChainRisk { pub is_risky: bool, pub risk_score: f64, pub matched_pattern: Option<ChainPattern>, pub reason: String }`
- `ToolChainingDetectorConfig { pub enabled: bool, pub risky_patterns: Vec<ChainPattern>, pub default_max_chain: usize }`

#### impl ToolChainingDetector

- `fn new(config: &ToolChainingDetectorConfig) -> Self`
- `fn evaluate(&self, tools: &[String]) -> ChainRisk`

---

## Memory Ring

### `chakravyuh::memory`

#### pub structs

- `MemoryConfig { pub enabled: bool, pub conversation_tracker: ConversationTrackerConfig, pub rag_poison_detector: RAGPoisonDetectorConfig, pub pii_extractor: PIIExtractorConfig, pub provenance_validator: ProvenanceValidatorConfig, pub memory_access_control: MemoryAccessControlConfig, pub context_guard: ContextGuardConfig }`
- `MemoryRequest { pub request_id: String, pub conversation_id: Option<String>, pub user_id: Option<String>, pub query: String, pub context: serde_json::Value }`
- `MemoryEngineResult { pub engine_name: String, pub score: f64, pub reason: String, pub latency_ms: f64 }`
- `MemoryVerdict { pub decision: Decision, pub engine_results: Vec<MemoryEngineResult>, pub memory_risk_score: f64, pub latency_ms: f64 }`
- `MemoryRing { ... }` (private fields)

#### impl MemoryRing

- `fn new(config: &MemoryConfig) -> Result<Self>`
- `fn evaluate(&self, request: &MemoryRequest) -> MemoryVerdict`

---

### `chakravyuh::memory::conversation_tracker`

#### impl ConversationTracker

- `fn new(config: &ConversationTrackerConfig) -> Self`
- `fn track(&self, conversation_id: &str, user_id: &str, role: &str, content: &str) -> ConversationState`
- `fn get_state(&self, conversation_id: &str) -> Option<ConversationState>`

---

### `chakravyuh::memory::rag_poison_detector`

#### impl RAGPoisonDetector

- `fn new(config: &RAGPoisonDetectorConfig) -> Self`
- `fn evaluate(&self, document: &str, source: &str) -> RAGVerdict`

---

### `chakravyuh::memory::pii_extractor`

#### pub enums

- `PIIType` — `Email` | `Phone` | `SSN` | `CreditCard` | `Address` | `Name` | `IpAddress` | `Custom(String)`

#### impl PIIExtractor

- `fn new(config: &PIIExtractorConfig) -> Self`
- `fn scan(&self, text: &str) -> Vec<PIIFinding>`
- `fn redact(&self, text: &str) -> String`

---

### `chakravyuh::memory::provenance_validator`

#### impl ProvenanceValidator

- `fn new(config: &ProvenanceValidatorConfig) -> Self`
- `fn validate(&self, entry: &MemoryEntry) -> ProvenanceVerdict`

---

### `chakravyuh::memory::memory_access_control`

#### pub enums

- `AccessControlAction` — `Allow` | `Deny` | `Redact`

#### impl MemoryAccessControl

- `fn new(config: &MemoryAccessControlConfig) -> Self`
- `fn check(&self, user_id: &str, memory_key: &str, action: AccessControlAction) -> AccessVerdict`

---

### `chakravyuh::memory::context_guard`

#### impl ContextGuard

- `fn new(config: &ContextGuardConfig) -> Self`
- `fn evaluate(&self, conversation_history: &[serde_json::Value], query: &str) -> ContextGuardResult`

---

## Reasoning Ring

### `chakravyuh::reasoning`

#### pub structs

- `ReasoningConfig { pub enabled: bool, pub coherence_checker: CoherenceCheckerConfig, pub hallucination_detector: HallucinationDetectorConfig, pub depth_analyzer: DepthAnalyzerConfig, pub bias_detector: BiasDetectorConfig, pub step_validator: StepValidatorConfig, pub output_consistency: OutputConsistencyConfig }`
- `ReasoningRequest { pub prompt: String, pub response: String, pub conversation_history: Vec<serde_json::Value>, pub context: serde_json::Value }`
- `ReasoningEngineResult { pub engine_name: String, pub score: f64, pub reason: String, pub latency_ms: f64 }`
- `ReasoningVerdict { pub decision: Decision, pub reasoning_score: f64, pub engine_results: Vec<ReasoningEngineResult>, pub latency_ms: f64 }`
- `ReasoningRing { ... }` (private fields)

#### impl ReasoningRing

- `fn new(config: &ReasoningConfig) -> Result<Self>`
- `fn evaluate(&self, request: &ReasoningRequest) -> ReasoningVerdict`
- `fn config(&self) -> &ReasoningConfig`

---

## Governance Ring

### `chakravyuh::governance`

#### pub structs

- `GovernanceConfig { pub enabled: bool, pub policy_compliance: PolicyComplianceConfig, pub audit_logger: AuditLoggerConfig, pub data_retention: DataRetentionConfig, pub consent_tracker: ConsentTrackerConfig, pub compliance_reporter: ComplianceReporterConfig, pub sanction_checker: SanctionCheckerConfig, pub deny_threshold: f64 }`
- `GovernanceRequest { pub agent_id: String, pub action: String, pub target: Option<String>, pub data_types: Vec<String>, pub user_consent: bool, pub entity_id: Option<String>, pub context: serde_json::Value }`
- `GovernanceEngineResult { pub engine_name: String, pub passed: bool, pub score: f64, pub details: serde_json::Value, pub reason: String, pub latency_ms: f64 }`
- `GovernanceVerdict { pub decision: Decision, pub governance_score: f64, pub engine_results: Vec<GovernanceEngineResult>, pub compliance_score: f64, pub violations: Vec<String>, pub consent_required: bool, pub latency_ms: f64 }`
- `GovernanceRing { ... }` (private fields)

#### impl GovernanceRing

- `fn new(config: &GovernanceConfig) -> Result<Self>`
- `fn evaluate(&self, request: &GovernanceRequest) -> GovernanceVerdict`
- `fn config(&self) -> &GovernanceConfig`

---

## Recovery Sec Ring

### `chakravyuh::recovery_sec`

#### pub structs

- `RecoverySecConfig { pub enabled: bool, pub incident_classifier: IncidentClassifierConfig, pub rollback_engine: RollbackEngineConfig, pub quarantine_manager: QuarantineManagerConfig, pub evidence_collector: EvidenceCollectorConfig, pub state_restorer: StateRestorerConfig, pub notification_engine: NotificationEngineConfig }`
- `RecoveryRequest { pub incident_id: String, pub incident_type: String, pub severity: String, pub affected_rings: Vec<String>, pub context: serde_json::Value }`
- `RecoveryEngineResult { pub engine_name: String, pub action: String, pub success: bool, pub details: serde_json::Value, pub reason: String, pub latency_ms: f64 }`
- `RecoveryVerdict { pub decision: Decision, pub recovery_actions: Vec<String>, pub engine_results: Vec<RecoveryEngineResult>, pub recovery_score: f64, pub latency_ms: f64 }`
- `RecoveryRing { ... }` (private fields)

#### impl RecoveryRing

- `fn new(config: &RecoverySecConfig) -> Result<Self>`
- `fn evaluate(&self, request: &RecoveryRequest) -> RecoveryVerdict`
- `fn config(&self) -> &RecoverySecConfig`

---

## Keshav (Decision Brain)

### `chakravyuh::keshav`

#### pub structs

- `KeshavConfig { enabled: bool, policy_path: Option<String>, risk: RiskConfig, orchestrate: OrchestrateConfig, learn: LearnConfig }`
- `KeshavCore { ... }` (private fields)
- `AllRingVerdicts<'a> { shield: &'a ShieldVerdict, threat: Option<&'a ThreatVerdict>, identity: Option<&'a IdentityVerdict>, memory: Option<&'a MemoryVerdict>, agent: Option<&'a AgentVerdict>, execution: Option<&'a ExecutionVerdict>, reasoning: Option<&'a ReasoningVerdict>, governance: Option<&'a GovernanceVerdict>, recovery: Option<&'a RecoveryVerdict> }`

#### impl KeshavCore

- `fn new(_config: &KeshavConfig) -> crate::Result<Self>`

---

### `chakravyuh::keshav::decide`

#### impl KeshavDecide

- `fn new(policy: Policy, decision_logger: Arc<DecisionLogger>) -> crate::Result<Self>`
- `fn with_defaults() -> crate::Result<Self>`
- `fn evaluate(&self, shield_verdict: &ShieldVerdict, threat_verdict: Option<&ThreatVerdict>, request_id: &str, source_ip: &str) -> DecisionRecord`
- `fn evaluate_all(&self, shield_verdict: &ShieldVerdict, threat_verdict: Option<&ThreatVerdict>, identity_verdict: Option<&IdentityVerdict>, memory_verdict: Option<&MemoryVerdict>, agent_verdict: Option<&AgentVerdict>, execution_verdict: Option<&ExecutionVerdict>, request_id: &str, source_ip: &str) -> DecisionRecord`
- `fn logger(&self) -> &DecisionLogger`

---

### `chakravyuh::keshav::risk`

#### pub structs

- `RiskConfig { w_threat: f64, w_identity: f64, w_behavior: f64, w_memory: f64, w_execution: f64, w_reasoning: f64, w_governance: f64, w_recovery: f64, w_context: f64 }`
- `RiskSignals { threat_score: Option<f64>, identity_score: Option<f64>, agent_score: Option<f64>, memory_score: Option<f64>, execution_score: Option<f64>, reasoning_score: Option<f64>, governance_score: Option<f64>, recovery_score: Option<f64>, context: ContextSignals }`
- `ContextSignals { time_of_day_risk: f64, rate_anomaly: f64, source_reputation: f64 }`

#### impl KeshavRisk

- `fn new(config: RiskConfig) -> Self`
- `fn with_defaults() -> Self`
- `fn evaluate(&self, signals: &RiskSignals) -> RiskScore`
- `fn config(&self) -> &RiskConfig`

#### impl ContextSignals

- `fn to_score(&self) -> f64`

#### pub fns

- `fn threat_to_risk_score(composite_score: f64) -> f64`
- `fn execution_to_risk_score(decision: &crate::decision::Decision) -> f64`

---

### `chakravyuh::keshav::orchestrate`

#### pub structs

- `OrchestrateConfig { enabled: bool, routing: Vec<RoutingRule> }`
- `RoutingRule { request_type: RequestType, rings: Vec<RingId>, parallel: bool, sequential_deps: Vec<SequentialDep> }`
- `SequentialDep { ring: RingId, depends_on: RingId, condition: DepCondition }`
- `OrchestrationPlan { request_type: RequestType, parallel_batch: Vec<RingId>, sequential_batch: Vec<(RingId, RingId, DepCondition)>, total_rings: usize }`
- `PipelineContext { shield_request: ShieldRequest, request_id: String, prompt_text: String, tool_call: Option<ToolCallContext> }`
- `ToolCallContext { tool_name: String, parameters: serde_json::Value, agent_id: Option<String> }`
- `PipelineResult { shield_verdict: ShieldVerdict, threat_verdict: Option<ThreatVerdict>, identity_verdict: Option<IdentityVerdict>, memory_verdict: Option<MemoryVerdict>, agent_verdict: Option<AgentVerdict>, execution_verdict: Option<ExecutionVerdict>, reasoning_verdict: Option<ReasoningVerdict>, governance_verdict: Option<GovernanceVerdict>, risk_score: RiskScore, decision_record: DecisionRecord }`
- `PipelineExecutor { pub shield: ShieldRing, pub threat: ThreatRing, pub identity: IdentityRing, pub memory: MemoryRing, pub agent: AgentRing, pub execution: ExecutionRing, pub reasoning: ReasoningRing, pub governance: GovernanceRing, pub decide: KeshavDecide, pub risk: KeshavRisk }`

#### pub enums

- `RequestType` — `HealthCheck` | `SimplePrompt` | `ToolCall` | `AuthRequest` | `AdminOperation` | `Unknown`
- `RingId` — `Shield` | `Identity` | `Threat` | `Agent` | `Memory` | `Execution` | `Reasoning` | `Governance` | `Recovery`
- `DepCondition` — `AllowOnly` | `DenyOnly` | `Always`

#### impl KeshavOrchestrate

- `fn new(config: OrchestrateConfig) -> Self`
- `fn with_defaults() -> Self`
- `fn plan(&self, request_type: RequestType, has_tool_call: bool) -> OrchestrationPlan`
- `fn config(&self) -> &OrchestrateConfig`

#### impl PipelineResult

- `fn shape_full_response(&self) -> serde_json::Value`

#### impl PipelineExecutor

- `fn execute(&self, plan: &OrchestrationPlan, ctx: &PipelineContext) -> PipelineResult` (async)

---

### `chakravyuh::keshav::policy_engine`

#### pub structs

- `Policy { version: String, rules: Vec<PolicyRule> }`
- `PolicyRule { name: String, condition: RuleCondition, action: RuleAction, reason: String }`
- `PolicyEngine { ... }` (private fields)
- `PolicyManager { ... }` (private fields)
- `PolicyInfo { version: String, rule_count: usize, rules: Vec<String>, policy_path: Option<String> }`

#### pub enums

- `RuleCondition` — `ShieldDeny` | `ThreatDeny` | `ThreatChallenge` | `IdentityDeny` | `IdentityChallenge` | `MemoryDeny` | `MemoryChallenge` | `AgentDeny` | `ExecutionDeny` | `AllRingsAllow` | `RiskAbove(f64)`
- `RuleAction` — `PassThrough` | `Allow` | `Deny(String)` | `Challenge` | `Escalate`

#### impl PolicyEngine

- `fn new(policy: Policy) -> Self`
- `fn policy(&self) -> &Policy`
- `fn evaluate(&self, shield: &ShieldVerdict, threat: Option<&ThreatVerdict>, risk: &RiskScore) -> Option<(Decision, Option<String>, String)>`
- `fn evaluate_all(&self, all: &AllRingVerdicts<'_>, risk: &RiskScore) -> Option<(Decision, Option<String>, String)>`

#### impl PolicyManager

- `fn new(policy: Policy, policy_path: Option<String>) -> Self`
- `fn with_defaults() -> Self`
- `fn evaluate_all(&self, all: &AllRingVerdicts<'_>, risk: &RiskScore) -> Option<(Decision, Option<String>, String)>`
- `fn policy_version(&self) -> String`
- `fn rule_count(&self) -> usize`
- `fn reload_from_file(&self) -> Result<String, String>`
- `fn reload_from_yaml(&self, yaml: &str) -> Result<String, String>`
- `fn export_policy_yaml(&self) -> String`
- `fn policy_info(&self) -> PolicyInfo`

---

### `chakravyuh::keshav::decision_logger`

#### pub structs

- `DecisionLogEntry { record: DecisionRecord, logged_at: String, seq: u64 }`
- `DecisionLogger { ... }` (private fields)

#### impl DecisionLogger

- `fn in_memory() -> Self`
- `fn with_capacity(max_entries: usize) -> Self`
- `fn log(&self, record: &DecisionRecord) -> Result<(), String>`
- `fn entries(&self) -> Vec<DecisionLogEntry>`
- `fn len(&self) -> usize`
- `fn is_empty(&self) -> bool`
- `fn export_json(&self) -> Result<String, String>`
- `fn export_csv(&self) -> Result<String, String>`

---

### `chakravyuh::keshav::fallback_rules`

#### impl FallbackRules

- `fn new() -> Self`
- `fn evaluate(&self, shield: &ShieldVerdict, threat: Option<&ThreatVerdict>) -> (Decision, String)`
- `fn evaluate_all(&self, all: &AllRingVerdicts<'_>) -> (Decision, String)`

---

### `chakravyuh::keshav::learn`

#### pub structs

- `LearnConfig { enabled: bool, feedback_collector: FeedbackCollectorConfig, threshold_optimizer: ThresholdOptimizerConfig, anomaly_profiler: AnomalyProfilerConfig, pattern_store: PatternStoreConfig }`
- `LearnStatus { enabled: bool, feedback_stats: FeedbackStats, unprocessed_feedback: usize, auto_optimize_pending: bool, profiles_count: usize, patterns_count: usize, threshold_count: usize, last_optimization: Option<OptimizationSummary> }`
- `OptimizationSummary { timestamp: String, adjustments_made: usize, rings_adjusted: Vec<String> }`
- `KeshavLearn { ... }` (private fields)

#### impl KeshavLearn

- `fn new(config: LearnConfig) -> crate::Result<Self>`
- `fn disabled() -> crate::Result<Self>`
- `fn is_enabled(&self) -> bool`
- `fn submit_feedback(&self, entry: FeedbackEntry)`
- `fn report_false_positive(&self, request_id: &str, ring_name: &str, original_decision: &str, explanation: &str, submitted_by: &str)`
- `fn report_false_negative(&self, request_id: &str, ring_name: &str, original_decision: &str, explanation: &str, submitted_by: &str)`
- `fn observe_request(&self, source_ip: &str, user_id: Option<&str>, agent_id: Option<&str>, denied: bool, prompt_length: usize, tool_name: Option<&str>)`
- `fn assess_anomaly(&self, source_ip: &str) -> AnomalyAssessment`
- `fn optimize_thresholds(&self) -> Vec<OptimizationResult>`
- `fn deny_threshold(&self, ring_name: &str) -> f64`
- `fn challenge_threshold(&self, ring_name: &str) -> f64`
- `fn reset_thresholds(&self)`
- `fn add_pattern(&self, pattern: Pattern)`
- `fn get_pattern(&self, id: &str) -> Option<Pattern>`
- `fn search_patterns(&self, ring: Option<&str>, tags: &[&str]) -> Vec<Pattern>`
- `fn record_pattern_match(&self, pattern_id: &str, is_true_positive: bool)`
- `fn export_patterns(&self) -> crate::Result<String>`
- `fn import_patterns(&self, json: &str) -> crate::Result<usize>`
- `fn status(&self) -> LearnStatus`
- `fn feedback_collector(&self) -> &FeedbackCollector`
- `fn threshold_optimizer(&self) -> &ThresholdOptimizer`
- `fn anomaly_profiler(&self) -> &AnomalyProfiler`
- `fn pattern_store(&self) -> &PatternStore`

---

### `chakravyuh::keshav::feedback_collector`

#### pub structs

- `FeedbackEntry { feedback_id: String, request_id: String, feedback_type: FeedbackType, severity: FeedbackSeverity, target_rings: Vec<String>, original_decision: String, explanation: String, submitted_by: String, timestamp: String, processed: bool }`
- `FeedbackCollectorConfig { max_entries: usize, auto_optimize_threshold: usize }`
- `FeedbackStats { total_entries: usize, unprocessed: usize, false_positives: usize, false_negatives: usize, misclassification_rate: f64, by_type: HashMap<String, usize>, by_severity: HashMap<String, usize> }`

#### pub enums

- `FeedbackType` — `Approve` | `Reject` | `FalsePositive` | `FalseNegative` | `EscalationApproved` | `EscalationDenied`
- `FeedbackSeverity` — `Low` | `Medium` | `High` | `Critical`

#### impl FeedbackCollector

- `fn new(config: FeedbackCollectorConfig) -> Self`
- `fn submit(&self, entry: FeedbackEntry)`
- `fn entries(&self) -> Vec<FeedbackEntry>`
- `fn feedback_for_request(&self, request_id: &str) -> Vec<FeedbackEntry>`
- `fn unprocessed_count(&self) -> usize`
- `fn should_auto_optimize(&self) -> bool`
- `fn mark_processed(&self, up_to_count: usize)`
- `fn stats(&self) -> FeedbackStats`

---

### `chakravyuh::keshav::threshold_optimizer`

#### pub structs

- `ThresholdState { deny_threshold: f64, challenge_threshold: f64, default_deny_threshold: f64, default_challenge_threshold: f64, adjustment_count: u64, total_adjustment: f64, feedback_count: u64 }`
- `ThresholdOptimizerConfig { step_size: f64, min_feedback_for_adjustment: usize, max_adjustments_per_pass: usize }`
- `OptimizationResult { ring_name: String, old_deny: f64, new_deny: f64, old_challenge: f64, new_challenge: f64, direction: OptimizationDirection, reason: String, confidence: f64 }`

#### pub enums

- `OptimizationDirection` — `Raised` | `Lowered` | `Unchanged`

#### impl ThresholdOptimizer

- `fn new(config: ThresholdOptimizerConfig) -> Self`
- `fn register_ring(&self, ring_name: &str, default_deny: f64, default_challenge: f64)`
- `fn deny_threshold(&self, ring_name: &str) -> f64`
- `fn challenge_threshold(&self, ring_name: &str) -> f64`
- `fn all_thresholds(&self) -> HashMap<String, ThresholdState>`
- `fn optimize(&self, feedback: &[FeedbackEntry]) -> Vec<OptimizationResult>`
- `fn reset(&self, ring_name: &str) -> bool`
- `fn reset_all(&self)`

#### impl ThresholdState

- `fn new(default_deny: f64, default_challenge: f64) -> Self`

---

### `chakravyuh::keshav::anomaly_profiler`

#### pub structs

- `BehavioralMetrics { request_count: u64, deny_count: u64, unique_tools: usize, total_prompt_length: u64, total_prompt_length_sq: u64, unique_prompts: u64, last_seen_secs: i64, first_seen_secs: i64, hourly_distribution: [u64; 24] }`
- `AnomalyAssessment { source_key: String, anomaly_score: f64, dimensions: AnomalyDimensions, is_anomalous: bool, summary: String }`
- `AnomalyDimensions { request_rate_zscore: f64, deny_rate_zscore: f64, tool_diversity_zscore: f64, prompt_entropy_zscore: f64, temporal_zscore: f64 }`
- `AnomalyProfilerConfig { zscore_threshold: f64, max_profiles: usize, min_requests_for_profile: u64, decay_factor: f64 }`

#### pub enums

- `SourceId` — `Ip(String)` | `User(String)` | `Agent(String)` | `ApiKey(String)`

#### impl AnomalyProfiler

- `fn new(config: AnomalyProfilerConfig) -> Self`
- `fn observe(&self, source: &SourceId, denied: bool, prompt_length: usize, tool_name: Option<&str>)`
- `fn assess(&self, source: &SourceId) -> AnomalyAssessment`
- `fn profile(&self, source: &SourceId) -> Option<BehavioralMetrics>`
- `fn profile_count(&self) -> usize`
- `fn global_metrics(&self) -> BehavioralMetrics`
- `fn prune(&self, max_age_secs: i64) -> usize`

#### impl BehavioralMetrics

- `fn deny_rate(&self) -> f64`
- `fn avg_prompt_length(&self) -> f64`
- `fn prompt_length_stddev(&self) -> f64`
- `fn peak_hour(&self) -> u8`

---

### `chakravyuh::keshav::pattern_store`

#### pub structs

- `Pattern { id: String, pattern_type: PatternType, name: String, rings: Vec<String>, pattern: String, priority: PatternPriority, tags: Vec<String>, match_count: u64, true_positive_count: u64, created_at: String, last_matched_at: Option<String>, active: bool, confidence: f64, source: PatternSource }`
- `PatternPriority { level: u8, weight: f64 }`
- `PatternStoreConfig { max_patterns: usize, min_confidence_for_activation: f64, min_matches_for_confidence: u64 }`
- `PatternStoreStats { total_patterns: usize, active_patterns: usize, total_matches: u64, overall_precision: f64, by_type: HashMap<String, usize>, by_source: HashMap<String, usize> }`

#### pub enums

- `PatternType` — `Signature` | `Behavioral` | `Threshold` | `FeedbackRule` | `Learned`
- `PatternSource` — `Manual` | `Learned` | `Imported` | `CrossRing`

#### impl PatternStore

- `fn new(config: PatternStoreConfig) -> Self`
- `fn with_store(config: PatternStoreConfig, store: Arc<dyn Store>) -> Self`
- `fn add(&self, pattern: Pattern)`
- `fn get(&self, id: &str) -> Option<Pattern>`
- `fn remove(&self, id: &str) -> bool`
- `fn search(&self, ring: Option<&str>, tags: &[&str], pattern_type: Option<PatternType>) -> Vec<Pattern>`
- `fn record_match(&self, pattern_id: &str, is_true_positive: bool)`
- `fn export_json(&self) -> crate::Result<String>`
- `fn import_json(&self, json: &str) -> crate::Result<usize>`
- `fn stats(&self) -> PatternStoreStats`
- `fn count(&self) -> usize`

#### impl Pattern

- `fn precision(&self) -> f64`
- `fn record_match(&mut self, is_true_positive: bool)`

---

## ANANTA (Trust Plane)

### `chakravyuh::ananta`

#### pub structs

- `AnantaConfig { pub enabled: bool, pub sentinel: SentinelConfig, pub phoenix: PhoenixConfig, pub anchor: AnchorConfig, pub adapter: AdapterConfig, pub trust_proof: TrustProofConfig, pub health: HealthConfig, pub audit: AuditConfig, pub distributed: DistributedConfig, pub state_path: String, pub crypto: CryptoConfig }`
- `SentinelConfig { check_interval_ms: u64, drift_window_size: usize, drift_sigma_threshold: f64, enable_full_drift_detection: bool, trust_state_interval_ms: u64 }`
- `PhoenixConfig { autonomous: bool, max_recovery_actions_per_hour: u32, recovery_cooldown_ms: u64, history_retention_hours: u64, action_confidence_threshold: f64 }`
- `AnchorConfig { enable_hardware_root: bool, manifest_path: String, verify_runtime_integrity: bool, key_rotation_hours: u64, encrypted_store: bool }`
- `AdapterConfig { enabled: bool, max_reconfigurations_per_hour: u32, require_signed_changes: bool, adaptation_grace_period_ms: u64 }`
- `TrustProofConfig { enabled: bool, generation_interval_ms: u64, retention_count: usize, include_runtime_hashes: bool }`
- `HealthConfig { enabled: bool, computation_interval_ms: u64, prediction_window_secs: u64 }`
- `AuditConfig { enabled: bool, max_entries_before_compaction: usize, chained_entries: bool }`
- `DistributedConfig { enabled: bool, quorum_size: u8, node_id: Option<String>, peers: Vec<String> }`
- `CryptoConfig { hash_algorithm: HashAlgorithm, kdf_iterations: u32 }`
- `ConfigWarning { field: String, message: String, severity: WarningSeverity }`
- `AnantaPlane { ... }` (private fields — all Arc<RwLock<>> internals)

#### pub enums

- `HashAlgorithm` — `Sha256` | `Sha384` | `Sha512` | `Blake3`
- `WarningSeverity` — `Info` | `Warning` | `Critical`

#### impl AnantaConfig

- `fn from_yaml(yaml: &str) -> Result<Self, String>`
- `fn default_yaml() -> String`
- `fn validate(&self) -> Vec<ConfigWarning>`

#### impl AnantaPlane

- `fn new(config: AnantaConfig) -> Result<Self, String>`
- `fn consecutive_passes(&self) -> u64`
- `fn consecutive_failures(&self) -> u64`
- `fn start(self: &Arc<Self>) -> tokio::task::JoinHandle<()>` (async — starts all 7 background loops)
- `fn is_started(&self) -> bool`
- `fn run_ovaph_cycle(&self) -> OvaphCycleReport`
- `fn latest_ovaph_report(&self) -> Option<OvaphCycleReport>`
- `fn ovaph_metrics(&self) -> Option<OvaphMetrics>`
- `fn trust_state(&self) -> Option<TrustSnapshot>`
- `fn attestation(&self) -> Option<AttestationReport>`
- `fn health(&self) -> Option<HealthSnapshot>`
- `fn audit_entries(&self, query: &AuditQuery) -> Vec<AuditEntry>`

---

### `chakravyuh::ananta::ovaph_loop`

#### pub structs

- `OvaphConfig { pub observe_interval_ms: u64, pub verify_timeout_ms: u64, pub attest_include_integrity: bool, pub heal_dry_run: bool, pub prove_include_attestation: bool }`
- `OvaphCycleReport { pub cycle_id: u64, pub timestamp: String, pub stages_completed: Vec<OvaphStage>, pub observations: OvaphObservation, pub verification: OvaphVerificationResult, pub attestation: OvaphAttestationResult, pub healing: OvaphHealingResult, pub proof: OvaphProofResult, pub total_duration_ms: f64, pub success: bool }`
- `OvaphMetrics { pub total_cycles: u64, pub successful_cycles: u64, pub failed_cycles: u64, pub avg_cycle_duration_ms: f64, pub last_cycle_timestamp: Option<String> }`
- `OvaphLoop { ... }` (private fields)

#### pub enums

- `OvaphStage` — `Observe` | `Verify` | `Attest` | `Heal` | `Prove`

#### impl OvaphStage

- `fn all() -> &'static [OvaphStage]`
- `fn next(&self) -> OvaphStage`
- `fn duration_hint_ms(&self) -> u64`
- `fn name(&self) -> &'static str`

#### impl OvaphLoop

- `fn new(config: OvaphConfig) -> Self`
- `fn run_cycle(&mut self, ...) -> OvaphCycleReport`
- `fn metrics(&self) -> &OvaphMetrics`

---

### `chakravyuh::ananta::crypto`

#### pub structs

- `Signature { algorithm: SignAlgorithm, bytes: Vec<u8>, key_id: String }`
- `KeyPair { key_id: String, algorithm: SignAlgorithm, public_key: Vec<u8>, secret_key: Vec<u8> }`
- `HashDigest { bytes: Vec<u8>, algorithm: HashAlgorithm }`
- `MerkleTree { ... }` (private fields)
- `MerkleProof { leaf_index: usize, leaf_hash: String, siblings: Vec<String>, root_hash: String }`
- `EncryptedPayload { nonce: [u8; 12], ciphertext: Vec<u8>, salt: Vec<u8>, algorithm: EncryptionAlgorithm }`
- `Encryptor { ... }` (private fields)
- `Decryptor { ... }` (private fields)

#### pub enums

- `SignAlgorithm` — `Ed25519` | `HmacSha256`
- `EncryptionAlgorithm` — `Aes256Gcm`
- `CryptoError` — `EncryptionFailed` | `DecryptionFailed` | `InvalidPayload` | `KeyDerivationFailed`

#### pub fns (crypto::threshold)

- `fn mod_add(a: u64, b: u64) -> u64`
- `fn mod_sub(a: u64, b: u64) -> u64`
- `fn mod_mul(a: u64, b: u64) -> u64`
- `fn mod_pow(base: u64, exp: u64) -> u64`
- `fn mod_inverse(a: u64) -> Option<u64>`
- `fn mod_div(a: u64, b: u64) -> Option<u64>`
- `fn mod_neg(a: u64) -> u64`
- `fn lagrange_interpolate_at_zero(shares: &[(u64, u64)]) -> u64`
- `fn lagrange_basis_coeff(x_i: u64, all_x: &[u64]) -> u64`
- `fn eval_poly(coeffs: &[u64], x: u64) -> u64`
- `fn run_dkg(participant_ids: &[u64], threshold: usize) -> DKGResult`
- `fn execute_key_refresh(current_shares: &[(u64, u64)], participant_ids: &[u64], threshold: usize) -> Result<Vec<RefreshedShare>, KeyRefreshError>`
- `fn verify_refresh_preserves_secret(original_shares: &[(u64, u64)], refreshed: &[RefreshedShare], threshold: usize) -> bool`
- `fn random_polynomial(degree: usize, secret: u64) -> Vec<u64>`
- `fn poly_add(a: &[u64], b: &[u64]) -> Vec<u64>`

#### pub fns (crypto::hashing)

- `fn hash(data: &str, algorithm: &HashAlgorithm) -> HashDigest`
- `fn hash_bytes(data: &[u8], algorithm: &HashAlgorithm) -> HashDigest`
- `fn hash_combined(data: &[&[u8]], algorithm: &HashAlgorithm) -> HashDigest`
- `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool`

#### pub fns (crypto::signing)

- `fn sign(key_pair: &KeyPair, data: &[u8]) -> Signature`
- `fn verify(public_key: &[u8], data: &[u8], signature: &Signature) -> bool`

#### pub fns (crypto::encryption)

- `fn encrypt(password: &str, plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError>`
- `fn decrypt(password: &str, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError>`

#### impl MerkleTree

- `fn from_leaves(hashes: Vec<String>, algorithm: &HashAlgorithm) -> Self`
- `fn root(&self) -> &str`
- `fn proof(&self, leaf_index: usize) -> MerkleProof`

#### impl MerkleProof (associated)

- `fn verify_proof(proof: &MerkleProof, algorithm: &HashAlgorithm) -> bool`

---

### `chakravyuh::ananta::anchor`

#### pub structs

- `AttestationReport { timestamp: String, platform_hash: String, integrity_results: Vec<IntegrityResult>, trust_level: f64, signed: bool, signature: Option<Signature> }`
- `IntegrityResult { component: String, passed: bool, expected: HashDigest, actual: HashDigest, duration_ms: f64 }`
- `IntegritySnapshot { timestamp: String, results: Vec<IntegrityResult>, merkle_root: HashDigest }`
- `KeyMetadata { key_id: String, purpose: KeyPurpose, created_at: String, rotated_at: Option<String>, algorithm: String }`
- `ManifestEntry { hash: HashDigest, added_at: String }`
- `EnclaveConfig { ... }` (many pub fields)
- `SealedData { id: String, encrypted: Vec<u8>, iv: [u8; 12], created_at: DateTime<Utc>, expires_at: Option<DateTime<Utc>>, tags: Vec<String>, aad: Vec<u8> }`
- `AttestationNonce { bytes: Vec<u8> }`
- `AttestationKey { enclave_identity: String, generation: u64, key: KeyPair }`
- `EnclaveQuote { body: Vec<u8>, signature: HashDigest, nonce_hash: HashDigest }`
- `AttestationResult { verified: bool, trust_level: f64, details: String }`
- `AttestationCheckResult { valid: bool, identity_match: bool, measurement_verified: bool, trust_level: f64, issues: Vec<String> }`
- `MeasurementEntry { name: String, measurement_type: MeasurementType, hash: HashDigest, description: Option<String>, registered_at: DateTime<Utc> }`
- `DerivedKey { id: String, key: Vec<u8>, algorithm: String, created_at: DateTime<Utc>, expires_at: DateTime<Utc>, purpose: String }`
- `EnclaveHealthSnapshot { is_initialized: bool, state: EnclaveState, measurement_count: usize, sealed_object_count: usize, key_count: usize, last_attestation: Option<DateTime<Utc>> }`
- `TrustChainLink { index: u64, event_type: String, data: serde_json::Value, timestamp: String, hash: String, previous_hash: String, signature: Option<String> }`

#### pub enums

- `KeyPurpose` — `Attestation` | `Signing` | `Encryption` | `Sealing`
- `IntegrityDomain` — `Policy` | `Config` | `Binary` | `Runtime` | `Manifest` | `Secrets`
- `EnclaveState` — `Uninitialized` | `Operational` | `Compromised` | `Error`
- `MeasurementType` — `Code` | `Data` | `Config` | `Key`
- `MeasurementPolicy` — `AllowList` | `DenyList` | `Open`
- `EnclaveError` — `NotInitialized` | `AlreadyInitialized` | `Compromised` | `SealingFailed` | `UnsealingFailed` | `AttestationFailed` | `KeyDerivationFailed` | `MeasurementFailed` | `MeasurementDenied` | `Expired` | `NotFound` | `InvalidInput` | `HardwareUnavailable`

#### pub fns (anchor::secure_enclave)

- `fn sha256_digest(data: &[u8]) -> HashDigest`
- `fn hmac_sha256(key: &[u8], message: &[u8]) -> HashDigest`
- `fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> HashDigest`
- `fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, EnclaveError>`
- `fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, EnclaveError>`

---

### `chakravyuh::ananta::trust`

#### pub structs

- `DomainTrust { level: f64, trend: TrendDirection, last_updated: String }`
- `TrustAlert { domain: String, alert_type: AlertType, severity: AlertSeverity, message: String, timestamp: String }`
- `TrustNode { id: String, node_type: NodeType, trust_score: f64, metadata: HashMap<String, String> }`
- `TrustEdge { from: String, to: String, weight: f64, positive_count: u64, negative_count: u64, last_event: String, last_updated: String }`
- `TrustProof { timestamp: String, trust_state: HashMap<String, f64>, attestation_hash: String, platform_hash: String, integrity_hash: String, signature: Option<Signature>, cycle_count: u64 }`
- `DomainTrustEntry { domain: String, level: f64, trend: String }`
- `TrustEvent { ... }`, `EventToEvidenceConverter { ... }`, `SyncResult { ... }`, `TrustChange { ... }`
- `TrustStateSynchronizer { ... }`, `TrustPropagationOrchestrator { ... }`
- `UnifiedTrustSnapshot { ... }`, `TrustDivergence { ... }`

#### pub enums

- `TrendDirection` — `Improving` | `Stable` | `Degrading`
- `AlertType` — `DriftDetected` | `IntegrityViolation` | `TrustDrop` | `RecoveryExecuted` | `AnomalyPredicted`
- `AlertSeverity` — `Info` | `Warning` | `Critical`
- `NodeType` — `Component` | `Service` | `Node` | `External`
- `DecayFunction` — `Exponential` | `Linear` | `Step`
- `TrustEventSource` — `Sentinel` | `IntegrityCheck` | `HealthObservation` | `RecoveryResult` | `ManualOverride` | `DecaySchedule`
- `DivergenceSeverity` — `Negligible` | `Low` | `Medium` | `High` | `Critical`

---

### `chakravyuh::ananta::sentinel`

#### pub structs

- `DriftObservation { drift_type: DriftType, value: f64, source: String, timestamp: String }`
- `DriftAlert { drift_type: DriftType, severity: AlertSeverity, value: f64, expected: f64, sigma: f64, message: String, timestamp: String }`
- `ReferenceBaseline`, `DriftBaselines`, `FusedDriftSignal`, `FusionConfig`
- `SentinelHub`, `CorrelatedAlert`, `SentinelVerificationBridge`

#### pub enums

- `DriftType` — `Latency` | `ErrorRate` | `Throughput` | `MemoryUsage` | `CpuUsage` | `SignatureCount` | `RequestPattern` | `ResponseSize` | `ConnectionCount` | `Custom`
- `AlertSeverity` — `Info` | `Warning` | `Critical`
- `DriftSeverity` — `Low` | `Medium` | `High` | `Critical`
- `DriftPattern` — `Sudden` | `Gradual` | `Recurring` | `Seasonal` | `NoDrift`
- `TrendDirection` — `Increasing` | `Decreasing` | `Stable` | `Volatile`
- `CorrelationType` — `Causal` | `Coincidental` | `Inverse` | `Unknown`

#### pub fns

- `fn correlate_signals(signals: &[&FusedDriftSignal]) -> Vec<CorrelatedAlert>`

---

### `chakravyuh::ananta::phoenix`

#### pub structs

- `RecoveryAction { strategy: RecoveryStrategy, target: String, reason: String, confidence: f64, priority: u8, trigger: String }`
- `RecoveryResult { action: RecoveryAction, outcome: RecoveryOutcome, message: String, duration_ms: f64, timestamp: String }`
- `RecoveryPlan { actions: Vec<PlannedAction>, estimated_duration_ms: u64, confidence: f64 }`
- `PlannedAction { action: RecoveryAction, delay_ms: u64 }`
- `StateSnapshot { ... }`, `StateDiff { ... }`, `RollbackConfig`, `SnapshotStore`, `RollbackResult`, `RollbackExecutor`, `VerificationResult`, `RollbackCandidate`, `RollbackPlanner`

#### pub enums

- `RecoveryStrategy` — `RestartComponent` | `ReloadConfig` | `RollbackState` | `Failover` | `ScaleUpDown` | `DisableFeature` | `RotateKeys` | `FullReset`
- `RecoveryOutcome` — `Success` | `Failed`
- `DiffType` — `Added` | `Removed` | `Modified` | `TypeChanged`
- `RollbackOutcome` — `Success` | `Failed` | `Partial` | `Timeout` | `DryRun`

---

### `chakravyuh::ananta::adapter`

#### pub structs

- `AdaptationProposal { id, description, changes, status, trust_before, trust_after, created_at, applied_at, confidence }`
- `ParameterChange { path, old_value, new_value, reason }`

#### pub enums

- `AdaptationStatus` — `Proposed` | `Applied` | `Reverted` | `Expired`

---

### `chakravyuh::ananta::health`

#### pub structs

- `HealthObservation`, `DependencyEdge`, `AnomalyPrediction`, `HealthGraph`

#### pub enums

- `HealthStatus` — `Healthy` | `Degraded` | `Critical` | `Unknown`

---

### `chakravyuh::ananta::audit`

#### pub structs

- `AuditEntry`, `AuditQuery`, `AuditLog`
- `Evidence`, `WalEntry`, `MerkleCheckpoint`

#### pub enums

- `AuditCategory` — `Integrity` | `Drift` | `Recovery` | `Trust` | `Configuration` | `Access` | `Anomaly`
- `AuditSeverity` — `Info` | `Warning` | `Error` | `Critical`
- `OverflowPolicy` — `OverwriteOldest` | `RejectNew`

---

### `chakravyuh::ananta::simulation`

#### pub structs

- `ThreatScenario`, `ThreatEvent`, `SimulationResult`, `SecurityTwin`, `SimulationEngine`

#### pub enums

- `ThreatEventType` — `DriftInjection` | `IntegrityFailure` | `TrustDegradation` | `CascadeFailure`

---

### `chakravyuh::ananta::distributed`

#### pub structs

- `Node`, `Vote`, `ConsensusResult`, `FederationLink`, `DistributedManager`
- `PhiAccrualDetector`, `PartitionInfo`, `HeartbeatSample`

#### pub enums

- `NodeStatus` — `Active` | `Suspect` | `Dead` | `Joining`
- `NodeRole` — `Leader` | `Follower` | `Voter` | `Observer`
- `VoteDecision` — `Approve` | `Reject` | `Abstain`
- `ConsensusDecision` — `Approved` | `Rejected` | `Timeout` | `NoQuorum`
- `FederationStatus` — `Connected` | `Disconnected` | `Syncing`

#### pub fns

- `fn ln_gamma(x: f64) -> f64`
- `fn gamma_func(x: f64) -> f64`
- `fn regularized_gamma_p(a: f64, x: f64) -> f64`
- `fn normal_cdf(z: f64) -> f64`

---

### `chakravyuh::ananta::runtime`

#### pub structs

- `ComponentStatus`, `ResourceUsage`, `RuntimeState`, `Components`

#### pub enums

- `RuntimePhase` — `Initializing` | `Running` | `Degraded` | `ShuttingDown`
- `ComponentState` — `Starting` | `Running` | `Stopped` | `Error`

---

### `chakravyuh::ananta::scheduler`

#### pub structs

- `TaskExecution`, `ScheduledTask`, `Scheduler`

#### pub enums

- `TaskStatus` — `Pending` | `Running` | `Success` | `Failed` | `Skipped` | `Disabled`

---

### `chakravyuh::ananta::state`

#### pub structs

- `StateSnapshot`, `SnapshotMetadata`, `StateDiff`, `DomainChange`, `StateManager`

---

## Cross-Ring Network

### `chakravyuh::cross_ring`

#### pub structs

- `CrossRingConfig { pub enabled: bool, pub command: CommandRingConfig, pub intel: IntelRingConfig, pub control: ControlRingConfig, pub recovery: RecoveryRingConfig, pub buffer_size: usize }`
- `CrossRingNetwork { ... }` (private fields)
- `RingHealthSnapshot { ... }`
- `RecoveryEvent { ... }`
- `DegradedAssessment { ... }`

#### pub enums

- `CrossRingType` — `Command` | `Intel` | `Control` | `Recovery`
- `MessagePriority` — `Low` | `Normal` | `High` | `Critical`
- `RecoveryAction` — `None` | `CircuitBreak` | `DegradeMode` | `FailOpen` | `Escalate`
- `CircuitState` — `Closed` | `Open` | `HalfOpen`

#### impl CrossRingMessage

- `fn new(msg_type: CrossRingType, from: &str, to: &str, subject: &str, payload: serde_json::Value) -> Self`
- `fn high_priority(msg_type: CrossRingType, from: &str, to: &str, subject: &str, payload: serde_json::Value) -> Self`
- `fn validate_direction(&self) -> Result<(), String>`

#### impl CrossRingNetwork

- `fn new(config: &CrossRingConfig) -> Result<Self>`
- `fn send_command(&self, msg: CrossRingMessage) -> Result<()>`
- `fn recv_command(&self) -> Option<CrossRingMessage>`
- `fn publish_intel(&self, msg: CrossRingMessage) -> Result<()>`
- `fn recv_intel(&self) -> Option<CrossRingMessage>`
- `fn escalate(&self, msg: CrossRingMessage) -> Result<()>`
- `fn recv_escalation(&self) -> Option<CrossRingMessage>`
- `fn broadcast(&self, msg: CrossRingMessage) -> Result<()>`
- `fn record_ring_success(&self, ring_name: &str, latency_ms: f64)`
- `fn record_ring_failure(&self, ring_name: &str)`
- `fn ring_should_allow(&self, ring_name: &str) -> bool`
- `fn assess_degraded_mode(&self, known_rings: &[&str]) -> DegradedAssessment`
- `fn ring_health(&self, known_rings: &[&str]) -> Vec<RingHealthSnapshot>`
- `fn recovery_events(&self) -> Vec<RecoveryEvent>`
- `fn command_ring(&self) -> &CommandRing`
- `fn intel_ring(&self) -> &IntelRing`
- `fn control_ring(&self) -> &ControlRing`
- `fn recovery_ring(&self) -> &RecoveryRing`
- `fn drain_all(&self)`

---

## Storage Layer

### `chakravyuh::storage`

#### pub traits

- `Store: Send + Sync` — `fn get(&self, key: &str) -> Option<Vec<u8>>;` `fn set(&self, key: &str, value: &[u8]) -> bool;` `fn delete(&self, key: &str) -> bool;` `fn exists(&self, key: &str) -> bool { ... };` `fn keys(&self, prefix: &str) -> Vec<String>;` `fn health_check(&self) -> StoreHealth;`

#### pub structs

- `StoreHealth { pub backend: String, pub reachable: bool, pub latency_ms: f64, pub detail: String }`
- `StorageConfig { pub backend: String, pub redis_url: String, pub redis_prefix: String, pub timeout_ms: u64 }`
- `CachedStore<S: Store> { ... }` (private fields)
- `MemoryStore { ... }` (private fields)

#### impl CachedStore

- `fn new(l2: S, max_cache_entries: usize) -> Self`

#### impl MemoryStore

- `fn new() -> Self`

#### pub fns

- `fn create_store(config: &StorageConfig) -> Box<dyn Store>`

---

## Infrastructure

### `chakravyuh::infra`

#### pub structs

- `ShutdownState { ... }` (private fields)
- `SystemHealth { pub version: String, pub uptime_secs: u64, pub rings: Vec<RingHealth>, pub store: StoreHealthReport, pub config_hash: String }`
- `RingHealth { pub name: String, pub healthy: bool, pub latency_ms: f64, pub error_rate: f64 }`
- `AuditEntry { pub id: String, pub timestamp: String, pub action: String, pub actor: String, pub target: String, pub result: String, pub details: serde_json::Value, pub prev_hash: String, pub hash: String }`
- `AuditTrail { ... }` (private fields)
- `ApiKeyMeta { pub name: String, pub created_at: String, pub permissions: Vec<Permission>, pub rate_limit: Option<u32>, pub metadata: serde_json::Value }`
- `ApiKeyManager { ... }` (private fields)
- `ApiKeyInfo { pub id: String, pub name: String, pub key_hash: String, pub permissions: Vec<Permission>, pub rate_limit: Option<u32>, pub created_at: String, pub last_used: Option<String> }`
- `TraceContext { pub trace_id: String, pub span_id: String, pub parent_id: Option<String>, pub start: Instant }`
- `Span { pub name: String, pub trace_id: String, pub span_id: String, pub parent_id: Option<String>, pub start: Instant, pub end: Instant, pub duration_ms: f64, pub metadata: serde_json::Value }`
- `TraceStats { pub total_traces: usize, pub recent_count: usize, pub avg_latency_ms: f64 }`

#### pub enums

- `Permission` — `Read` | `Write` | `Admin`

#### impl ShutdownState

- `fn new(grace_period_secs: u64) -> Self`
- `fn initiate(&self)`
- `fn notified(&self) -> tokio::sync::broadcast::Receiver<()>`
- `fn is_shutting_down(&self) -> bool`

#### impl ApiKeyManager

- `fn new(config: ApiKeyConfig) -> Self`
- `fn create(&self, name: String, permissions: Vec<Permission>, rate_limit: Option<u32>) -> Result<(String, String)>`
- `fn authenticate(&self, key: &str, required: Permission) -> AuthResult`
- `fn revoke(&self, id: &str) -> bool`
- `fn list(&self) -> Vec<ApiKeyInfo>`

#### impl AuditTrail

- `fn new(config: AuditConfig) -> Self`
- `fn record(&self, action: &str, actor: &str, target: &str, result: &str, details: serde_json::Value)`
- `fn entries(&self) -> Vec<AuditEntry>`
- `fn verify_chain(&self) -> bool`

#### impl TraceContext

- `fn new() -> Self`

#### pub fns

- `fn is_alive() -> bool`
- `fn is_ready() -> bool`
- `fn record_request(ring: &str, ok: bool, latency_ms: f64)`
- `fn request_counts() -> (u64, u64)`
- `fn record_endpoint(endpoint: &str)`
- `fn record_decision(decision: &str)`
- `fn record_ring_eval(ring: &str)`
- `fn record_latency(latency_ms: f64)`
- `fn metrics_text() -> String`
- `fn extract_trace_id(headers: &axum::http::HeaderMap) -> Option<String>`
- `fn record_trace(ctx: &TraceContext)`
- `fn recent_traces() -> Vec<Span>`
- `fn trace_stats() -> TraceStats`
- `fn spawn_config_watcher(config: &ConfigWatcherConfig, policy_path: std::path::PathBuf, manager: Arc<PolicyManager>) -> Option<ConfigWatcherHandle>`

---

## Policy Compiler

### `chakravyuh::policy_compiler`

#### pub structs

- `PolicyCompilerConfig { ... }`
- `PolicyInput { pub source: String, pub format: String }`
- `PolicyOutput { pub success: bool, pub bytecode: Option<BytecodeProgram>, pub ast: Option<Vec<ASTNode>>, pub errors: Vec<String>, pub warnings: Vec<String>, pub compilation_time_ms: f64 }`
- `CompiledPolicy { pub program: BytecodeProgram, pub version: String, pub source_hash: String, pub compiled_at: String }`
- `ReloadResult { pub success: bool, pub old_version: String, pub new_version: String, pub error: Option<String> }`
- `PolicyCompiler { ... }` (private fields)
- `PolicyCompilerEngine { ... }` (private fields)
- `Instruction { ... }`
- `BytecodeProgram { ... }`
- `VMConfig { ... }`
- `VMResult { pub success: bool, pub decision: String, pub score: f64, pub reason: String, pub steps: usize }`
- `PolicyVM { ... }` (private fields)
- `PolicyVersion { pub major: u32, pub minor: u32, pub patch: u32 }`
- `VersionDiff { pub from: PolicyVersion, pub to: PolicyVersion, pub changes: Vec<String> }`
- `VersionedPolicy { ... }`
- `PolicyVersionStore { ... }` (private fields)

#### pub enums

- `ASTNode` — `Rule { ... }` | `Condition { ... }` | `Action { ... }` | `BinaryOp { ... }` | `UnaryOp { ... }` | `Literal { ... }` | `Identifier(String)` | `Block(Vec<ASTNode>)`
- `BinOp` — `And` | `Or` | `Xor` | `Eq` | `Neq` | `Gt` | `Lt` | `Gte` | `Lte` | `Add` | `Sub`
- `UnOp` — `Not` | `Negate`
- `OpCode` — `Nop` | `LoadConst` | `LoadVar` | `StoreVar` | `Jump` | `JumpIfFalse` | `Call` | `Return` | `Halt` | `Compare` | `Add` | `Subtract` | `ScoreAdd` | `DecisionAllow` | `DecisionDeny` | `DecisionChallenge`
- `Constant` — `Integer(i64)` | `Float(f64)` | `String(String)` | `Boolean(bool)`
- `Value` — `Integer(i64)` | `Float(f64)` | `String(String)` | `Boolean(bool)` | `Decision(String)` | `Unit`

#### impl PolicyCompiler

- `fn new(config: PolicyCompilerConfig) -> Self`
- `fn compile(&self, input: &PolicyInput) -> PolicyOutput`
- `fn compile_and_load(&self, input: &PolicyInput) -> Result<CompiledPolicy, String>`
- `fn reload(&mut self, input: &PolicyInput) -> ReloadResult`

#### impl PolicyCompilerEngine

- `fn new() -> Self`
- `fn compile(&self, source: &str) -> Result<BytecodeProgram, String>`

#### impl PolicyVM

- `fn new(config: VMConfig, program: BytecodeProgram) -> Self`
- `fn execute(&self, context: &serde_json::Value) -> VMResult`

#### impl PolicyVersionStore

- `fn new() -> Self`
- `fn store(&self, policy: VersionedPolicy)`
- `fn latest(&self) -> Option<VersionedPolicy>`
- `fn get(&self, version: &PolicyVersion) -> Option<VersionedPolicy>`
- `fn history(&self) -> Vec<VersionedPolicy>`
- `fn diff(&self, from: &PolicyVersion, to: &PolicyVersion) -> Option<VersionDiff>`

---

## Incident Response

### `chakravyuh::incident_response`

#### pub structs

- `Incident { pub id: String, pub classification: IncidentClassification, pub severity: IncidentSeverity, ... }`
- `OrchestratorStatus { ... }`
- `IncidentResponseOrchestrator { ... }` (private fields)
- `EvidenceItem { ... }`, `ChainOfCustody { ... }`, `EvidenceCollector { ... }` (private fields)
- `PlaybookStep { ... }`, `PlaybookContext { ... }`, `Playbook { ... }` (private fields), `PlaybookRegistry { ... }` (private fields)
- `IncidentReport { ... }`, `ReportGenerator;`
- `WebhookEndpoint { ... }`, `WebhookEvent { ... }`, `WebhookRegistry { ... }` (private fields)

#### pub enums

- `IncidentClassification` — `SecurityBreach` | `DataLeak` | `UnauthorizedAccess` | `ServiceDisruption` | `ComplianceViolation` | `Unknown`
- `IncidentSeverity` — `Critical` | `High` | `Medium` | `Low` | `Info`
- `EvidenceType` — `Log` | `Screenshot` | `NetworkCapture` | `MemoryDump` | `ConfigSnapshot` | `UserStatement`
- `PlaybookAction` — `BlockIp` | `RevokeKey` | `NotifyTeam` | `Escalate` | `Quarantine` | `Custom { action: String, params: serde_json::Value }`
- `StepFailurePolicy` — `Abort` | `Continue` | `Skip`
- `OutputFormat` — `Json` | `Html` | `Markdown` | `Pdf`
- `TimelineCategory` — `Detection` | `Triage` | `Containment` | `Eradication` | `Recovery` | `PostIncident`
- `ImpactLevel` — `Critical` | `High` | `Medium` | `Low` | `Minimal`
- `ActionStatus` — `Pending` | `InProgress` | `Completed` | `Failed` | `Skipped`
- `WebhookEventType` — `IncidentCreated` | `IncidentUpdated` | `AlertTriggered` | `IncidentResolved`

#### pub traits

- `WebhookPayload` — `fn to_json(&self) -> serde_json::Value;` `fn content_type(&self) -> &str;`

#### impl IncidentResponseOrchestrator

- `fn new(config: &IncidentResponseConfig) -> Self`
- `fn handle_incident(&self, incident: &Incident) -> Result<Incident>`
- `fn status(&self) -> OrchestratorStatus`

#### impl EvidenceCollector

- `fn new() -> Self`
- `fn collect(&self, evidence_type: EvidenceType, data: Vec<u8>, collector: &str) -> EvidenceItem`
- `fn chain(&self) -> ChainOfCustody`
- `fn verify_chain(&self) -> ChainVerificationResult`

#### impl PlaybookEngine

- `fn execute(&self, playbook: &Playbook, context: &PlaybookContext) -> PlaybookResult`

#### impl PlaybookRegistry

- `fn new() -> Self`
- `fn register(&self, playbook: Playbook) -> Result<(), String>`
- `fn get(&self, name: &str) -> Option<&Playbook>`
- `fn trigger(&self, incident_type: &str, context: &PlaybookContext) -> Vec<PlaybookResult>`

#### impl ReportGenerator

- `fn generate(&self, incident: &Incident, format: OutputFormat) -> Result<IncidentReport, String>`

#### impl WebhookRegistry

- `fn new() -> Self`
- `fn register(&self, endpoint: WebhookEndpoint)`
- `fn notify(&self, event: &WebhookEvent) -> Vec<WebhookSendResult>`

---

## Federated Module

### `chakravyuh::federated`

#### pub structs

- `FederatedConfig { ... }`, `FederatedVerdict { ... }`, `FederatedOrchestrator { ... }` (private fields)
- `ModelVersion { ... }`, `ModelCheckpoint { ... }`, `ModelDiff { ... }`, `FederatedModelManager { ... }` (private fields)
- `ModelUpdate { ... }`, `GlobalModel { ... }`, `FedAvgAggregator { ... }` (private fields)
- `DifferentialPrivacyEngine { ... }` (private fields), `PrivacyReport { ... }`
- `ThreatSignature { ... }`, `SyncRequest { ... }`, `SyncResponse { ... }`, `ThreatSignatureSync { ... }` (private fields)

#### impl FederatedOrchestrator

- `fn new(config: &FederatedConfig) -> Self`
- `fn contribute(&self, update: ModelUpdate) -> Result<AggregationMetadata>`
- `fn get_global_model(&self) -> GlobalModel`
- `fn sync_threats(&self) -> SyncResponse`

#### impl FederatedModelManager

- `fn new() -> Self`
- `fn register_checkpoint(&self, checkpoint: ModelCheckpoint) -> CheckpointId`
- `fn get_checkpoint(&self, id: &CheckpointId) -> Option<ModelCheckpoint>`
- `fn latest(&self) -> Option<CheckpointSummary>`
- `fn diff(&self, v1: &str, v2: &str) -> Option<ModelDiff>`
- `fn stats(&self) -> RegistryStats`

#### impl FedAvgAggregator

- `fn new(config: &AggregationConfig) -> Self`
- `fn aggregate(&self, updates: &[ModelUpdate]) -> GlobalModel`

#### impl DifferentialPrivacyEngine

- `fn new(config: &DifferentialPrivacyConfig) -> Self`
- `fn add_noise(&self, weights: &mut [f64]) -> PrivacyReport`
- `fn privacy_budget(&self) -> f64`
- `fn reset_budget(&self)`

#### impl ThreatSignatureSync

- `fn new(config: &ThreatSyncConfig) -> Self`
- `fn sync(&self, request: SyncRequest) -> SyncResponse`
- `fn diff(&self, local: &[ThreatSignature], remote: &[ThreatSignature]) -> Vec<SignatureDiff>`

---

## Tenant Module

### `chakravyuh::tenant`

#### pub structs

- `Tenant { pub id: TenantId, pub name: String, pub tier: TenantTier, ... }`
- `TenantId(pub String)`
- `TenantContext { ... }` (private fields)
- `TenantPolicyEngine { ... }` (private fields)
- `QuotaEnforcer { ... }` (private fields)

#### pub enums

- `TenantTier` — `Free` | `Basic` | `Professional` | `Enterprise`
- `TenantRuleAction` — `Allow` | `Deny` | `Log` | `Transform`

#### impl TenantId

- `fn new(id: String) -> Result<Self, TenantIdParseError>`
- `fn as_str(&self) -> &str`

#### impl TenantContext

- `fn new(tenant_id: TenantId) -> Self`
- `fn tenant_id(&self) -> &TenantId`
- `fn with_isolation_level(...) -> Self`

#### impl TenantContextExtractor

- `fn extract(headers: &axum::http::HeaderMap) -> Option<TenantContext>`

#### impl TenantPolicyEngine

- `fn new(config: &TenantPolicyConfig) -> Self`
- `fn evaluate(&self, tenant: &Tenant, request: &str) -> TenantPolicyDecision`
- `fn add_rule(&self, rule: TenantCustomRule)`

#### impl QuotaEnforcer

- `fn new() -> Self`
- `fn check(&self, tenant_id: &TenantId, resource: &str) -> QuotaCheckResult`
- `fn record_usage(&self, tenant_id: &TenantId, resource: &str, amount: u64)`
- `fn get_usage(&self, tenant_id: &TenantId) -> QuotaUsageSnapshot`
- `fn set_quota(&self, tenant_id: &TenantId, resource: &str, quota: ResourceQuota)`

---

## Plugin System

### `chakravyuh::plugin`

#### pub structs

- `PluginApi { ... }` (private fields), `PluginInput { ... }`, `PluginOutput { ... }`
- `PluginRegistry { ... }` (private fields), `PluginManager { ... }` (private fields)
- `WasmRuntime { ... }` (private fields)

#### pub enums

- `HostFunction` — `GetConfig` | `Log` | `EmitMetric` | `GetDecision` | `ReportViolation`
- `PluginDecision` — `Allow` | `Deny` | `NoOp`
- `PluginPermission` — `ReadState` | `WriteState` | `Network` | `FileSystem` | `EmitEvents`
- `PluginStatus` — `Loaded` | `Unloaded` | `Failed(String)`
- `WasmOpcode` — ... (opcode enum)
- `SandboxViolation` — `StackOverflow` | `StackUnderflow` | `InvalidMemoryAccess` | `InvalidOpcode` | `CallDepthExceeded` | `OutOfFuel`

#### impl PluginApi

- `fn new(config: &PluginApiConfig) -> Self`
- `fn execute(&self, input: &PluginInput) -> Result<PluginOutput>`

#### impl PluginRegistry

- `fn new() -> Self`
- `fn register(&self, manifest: PluginManifest, wasm_bytes: Vec<u8>) -> Result<(), String>`
- `fn get(&self, name: &str) -> Option<PluginInfo>`
- `fn list(&self) -> Vec<PluginInfo>`

#### impl PluginManager

- `fn new(config: &PluginConfig) -> Self`
- `fn load_plugin(&self, name: &str, wasm_bytes: Vec<u8>) -> Result<(), String>`
- `fn execute(&self, plugin_name: &str, input: &PluginInput) -> Result<PluginOutput>`
- `fn list_plugins(&self) -> Vec<PluginInfo>`
- `fn unload_plugin(&self, name: &str) -> Result<(), String>`

#### impl WasmRuntime

- `fn new(config: &WasmRuntimeConfig) -> Self`
- `fn load(&self, wasm_bytes: &[u8]) -> Result<WasmModule>`
- `fn execute(&self, module: &WasmModule, function: &str, args: &[WasmValue]) -> Result<Vec<WasmValue>>`

---

## Security Twin

### `chakravyuh::twin`

#### pub structs

- `SecurityTwinService { ... }` (private fields)
- `StateSnapshot { pub timestamp: String, pub ring_health: HashMap<String, f64>, pub risk_trend: Vec<f64>, pub active_incidents: usize, pub config_hash: String }`
- `TwinState { pub snapshots: Vec<StateSnapshot>, pub current_scenario: Option<String> }`
- `Scenario { pub id: String, pub name: String, pub description: String, pub scenario_type: ScenarioType, pub steps: Vec<serde_json::Value>, pub expected_outcome: ScenarioOutcome, pub metadata: serde_json::Value }`
- `ScenarioResult { pub scenario_id: String, pub outcome: ScenarioOutcome, pub metrics: ScenarioMetrics, pub details: serde_json::Value }`

#### pub enums

- `ScenarioType` — `Attack` | `Failure` | `Recovery` | `Load` | `Compliance`
- `ScenarioOutcome` — `Pass` | `Fail` | `Error`

#### impl SecurityTwinService

- `fn new() -> Self`
- `fn run_scenario(&self, scenario: &Scenario) -> ScenarioResult`
- `fn run_all_scenarios(&self) -> Vec<ScenarioResult>`
- `fn get_state(&self) -> &TwinState`
- `fn take_snapshot(&self) -> StateSnapshot`

---

## Observability

### `chakravyuh::observability`

#### pub structs

- `DashboardSnapshot { ... }`, `Alert { ... }`, `AlertRule { ... }`, `AnomalyDetector { ... }`
- `MetricsSnapshot { ... }`, `AlertingEngine { ... }`, `OtelExporter { ... }`
- `SpanBuilder { ... }`, `MetricBuilder { ... }`, `ReservoirHistogram { ... }`
- `SecurityMetricsCollector { ... }`

#### impl SecurityDashboardAggregator

- `fn new() -> Self`
- `fn snapshot(&self) -> DashboardSnapshot`

#### impl AlertingEngine

- `fn new(config: &ObservabilityConfig) -> Self`
- `fn evaluate(&self, metrics: &MetricsSnapshot) -> Vec<Alert>`

#### impl AnomalyDetector

- `fn detect(&self, point: f64, history: &[f64]) -> Option<f64>`

#### impl OtelExporter

- `fn new(config: &OtelConfig) -> Self`
- `fn export_batch(&self, batch: &OtelBatch) -> Result<(), String>`

#### impl SecurityMetricsCollector

- `fn new() -> Self`
- `fn record_ring_latency(ring: &str, latency_ms: f64)`
- `fn record_decision(decision: &str)`
- `fn record_ip_block(ip: &str)`
- `fn get_ring_latency_stats(ring: &str) -> Option<RingLatencyStats>`
- `fn get_decision_distribution() -> DecisionDistribution`

---

## CLI

### `chakravyuh::cli`

#### pub structs

- `Cli { pub config: PathBuf, ... }`
- `CliResult { pub success: bool, pub output: String, pub duration_ms: u64 }`
- `CliOrchestrator { ... }` (private fields)

#### pub enums

- `Commands` — `Serve` | `Validate` | `Test` | `Version` | `Config` | `Policy` | `Evaluate` | `TestSuite` | `Keys` | `Audit` | `Status` | `Completions`
- `CliCommand` — `Config(ConfigCommand)` | `Policy(PolicyCommand)` | `Evaluate(EvaluateCommand)` | `Test(TestCommand)` | `Keys(KeysCommand)` | `Audit(AuditCommand)` | `Status(StatusCommand)` | `Benchmark` | `SimulateAttack` | `AnantaStatus`
- `OutputFormat` — `Text` | `Json` | `Table`
- `ExitCode` — `Ok` | `Error` | `UsageError` | `ConfigError` | `Partial`

#### impl CliOrchestrator

- `fn new(config: CliConfig) -> Self`
- `fn with_defaults() -> Self`
- `fn execute(&self, command: CliCommand) -> CliResult`
- `fn parse_command(args: &[String]) -> Result<CliCommand>`

#### pub fns

- `fn check_status(config: &AnantaStatusConfig) -> AnantaStatusReport`
- `fn format_status(report: &AnantaStatusReport, format: OutputFormat) -> String`
- `fn run_benchmark(config: &BenchmarkConfig) -> BenchmarkReport`
- `fn format_report(report: &BenchmarkReport, format: OutputFormat) -> String`

---

## API / gRPC

### `chakravyuh::api`

#### pub structs

- `ApiState { ... }` (private fields)
- `UpstreamClient { ... }` (private fields)

#### impl UpstreamClient

- `fn new(config: UpstreamConfig) -> Self`

#### pub fns

- `fn build_router(...) -> axum::Router`

---

### `chakravyuh::grpc`

#### pub structs

- `GrpcConfig { pub enabled: bool, pub bind: String }`
- `ChakravyuhGrpcService { ... }` (private fields)

#### impl ChakravyuhGrpcService

- `fn new(state: Arc<ApiState>) -> Self`

---

## Summary Statistics

| Category | Count |
|---|---|
| `.rs` files scanned | 130+ |
| `pub struct` declarations | ~310 |
| `pub enum` declarations | ~120 |
| `pub trait` declarations | 5 (`Verdict`, `RateLimitStorage`, `Store`, `WebhookPayload`, + trait objects) |
| `pub fn` (free functions) | ~60 |
| `impl` blocks with `pub fn` methods | ~400+ |
| Ring types (top-level) | 9: Shield, Identity, Threat, Agent, Memory, Execution, Reasoning, Governance, RecoverySec |
| Cross-cutting | CrossRingNetwork, Storage, Infra, CLI, API, gRPC, Plugin, Tenant, Federated, Twin, IncidentResponse, Observability, PolicyCompiler |
| Keshav subsystems | Decide, Risk, Orchestrate, Learn (FeedbackCollector, ThresholdOptimizer, AnomalyProfiler, PatternStore), PolicyEngine, PolicyManager, DecisionLogger, FallbackRules |
| ANANTA subsystems | Crypto (Signing, Hashing, Merkle, Encryption, Threshold), Anchor (Integrity, KeyManager, Manifest, SecureStore, SecureEnclave, TrustChain, Attestation), Trust (State, Graph, Engine, Decay, Proof, PropagationBridge), Sentinel (Drift, DriftAnalyzer, SentinelWiring, TrustStateUpdater), Phoenix (Strategies, Planner, RecoverySimulator, RecoveryHistory, RollbackEngine), Adapter, Health, Audit, Distributed, Runtime, Scheduler, State, Simulation, OvaphLoop |
| Background loops | 7 (Sentinel, Phoenix, Trust Proof, Health, Audit, Distributed, OVAPH) |
| `unsafe` blocks | **0** (#![deny(unsafe_code)] enforced) |

---

*This document is auto-generated during Phase A (Core Freeze) and serves as the
immutable API contract for CHAKRAVYUH v1.0.0. Any deviation requires a formal
RFC through the process defined in `API_STABILITY.md`.*