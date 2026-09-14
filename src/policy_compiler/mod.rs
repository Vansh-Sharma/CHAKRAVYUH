// Real-Time Policy Compiler — main module for CHAKRAVYUH.
//
// This module compiles YAML-based security policies into a bytecode VM
// representation for fast runtime evaluation. It provides:
//
//   1. PolicyCompilerConfig  — configuration for the compiler subsystem
//   2. PolicyCompiler        — main entry point for compilation and execution
//   3. CompiledPolicy        — compiled bytecode artifact
//   4. PolicyInput/Output    — request/response types for evaluation
//   5. ReloadResult          — result of a hot-reload operation
//
// Submodules:
//   - bytecode: instruction set, program representation, serialization
//   - vm: stack-based virtual machine for bytecode execution
//   - compiler: YAML-to-bytecode compiler with tokenizer, parser, codegen, optimizer
//   - versioning: semver policy versioning, history, diff, rollback

pub mod bytecode;
pub mod compiler;
pub mod versioning;
pub mod vm;

pub use bytecode::{BytecodeProgram, Constant, Instruction, OpCode};
pub use compiler::{ASTNode, PolicyCompilerEngine, YamlPolicy};
pub use versioning::{PolicyVersion, PolicyVersionStore, VersionDiff, VersionedPolicy};
pub use vm::{VMConfig, VMResult, Value};

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::decision::Decision;
use crate::error::{Error, Result};

// ── PolicyCompilerConfig ───────────────────────────────────────────────

/// Configuration for the policy compiler subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCompilerConfig {
    /// Whether the policy compiler is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Maximum number of compiled policies to cache in memory.
    #[serde(default = "default_bytecode_cache_size")]
    pub bytecode_cache_size: usize,
    /// Maximum size (in bytes) of a YAML policy source before rejection.
    #[serde(default = "default_max_policy_size")]
    pub max_policy_size: usize,
    /// Whether to watch for policy file changes and hot-reload.
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
    /// Number of threads to use for parallel policy compilation.
    #[serde(default = "default_compilation_threads")]
    pub compilation_threads: usize,
}

fn default_enabled() -> bool {
    true
}

fn default_bytecode_cache_size() -> usize {
    64
}

fn default_max_policy_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_hot_reload() -> bool {
    false
}

fn default_compilation_threads() -> usize {
    1
}

impl Default for PolicyCompilerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bytecode_cache_size: default_bytecode_cache_size(),
            max_policy_size: default_max_policy_size(),
            hot_reload: default_hot_reload(),
            compilation_threads: default_compilation_threads(),
        }
    }
}

// ── PolicyInput ────────────────────────────────────────────────────────

/// Input to a policy evaluation.
///
/// Represents a request or event that needs to be evaluated against
/// a compiled security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    /// Unique request identifier.
    pub request_id: String,
    /// Source IP address of the request.
    pub source_ip: String,
    /// User identifier (if authenticated).
    pub user_id: String,
    /// Agent identifier (if applicable).
    pub agent_id: String,
    /// Request payload (e.g., prompt, query, command).
    pub payload: String,
    /// HTTP headers or equivalent metadata.
    pub headers: HashMap<String, String>,
    /// Additional key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl PolicyInput {
    /// Create a new policy input with required fields.
    pub fn new(request_id: &str, source_ip: &str, payload: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            source_ip: source_ip.to_string(),
            user_id: String::new(),
            agent_id: String::new(),
            payload: payload.to_string(),
            headers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the user_id.
    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = user_id.to_string();
        self
    }

    /// Add a header.
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Convert the PolicyInput into a VM environment HashMap.
    pub fn to_vm_env(&self) -> HashMap<String, vm::Value> {
        let mut env = HashMap::new();
        env.insert(
            "request_id".to_string(),
            vm::Value::String(self.request_id.clone()),
        );
        env.insert(
            "source_ip".to_string(),
            vm::Value::String(self.source_ip.clone()),
        );
        env.insert(
            "user_id".to_string(),
            vm::Value::String(self.user_id.clone()),
        );
        env.insert(
            "agent_id".to_string(),
            vm::Value::String(self.agent_id.clone()),
        );
        env.insert(
            "payload".to_string(),
            vm::Value::String(self.payload.clone()),
        );

        // Convert headers to a flat representation.
        for (k, v) in &self.headers {
            env.insert(format!("header.{}", k), vm::Value::String(v.clone()));
        }

        // Convert metadata.
        for (k, v) in &self.metadata {
            env.insert(format!("meta.{}", k), vm::Value::String(v.clone()));
        }

        env
    }
}

// ── PolicyOutput ───────────────────────────────────────────────────────

/// Output of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutput {
    /// The security decision.
    pub decision: Decision,
    /// Computed risk score (0.0 to 1.0).
    pub risk_score: f64,
    /// Names of rules that matched during evaluation.
    pub rules_matched: Vec<String>,
    /// Execution time in nanoseconds.
    pub execution_time_ns: u64,
    /// Policy version that produced this decision.
    pub policy_version: String,
}

impl PolicyOutput {
    /// Create a new policy output.
    pub fn new(
        decision: Decision,
        risk_score: f64,
        rules_matched: Vec<String>,
        execution_time_ns: u64,
        policy_version: String,
    ) -> Self {
        Self {
            decision,
            risk_score,
            rules_matched,
            execution_time_ns,
            policy_version,
        }
    }
}

// ── CompiledPolicy ─────────────────────────────────────────────────────

/// A compiled policy artifact ready for execution.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// The compiled bytecode program.
    pub bytecode: BytecodeProgram,
    /// Policy version string.
    pub version: String,
    /// Hash of the source YAML (for change detection).
    pub source_hash: String,
    /// Timestamp when this policy was compiled.
    pub compiled_at: u64,
    /// Number of rules in this policy.
    pub rule_count: u32,
    /// Serialized bytecode bytes (for caching / storage).
    pub bytecode_bytes: Vec<u8>,
}

impl CompiledPolicy {
    /// Create a new compiled policy from a BytecodeProgram.
    pub fn from_program(program: BytecodeProgram, version: String, source_hash: String) -> Self {
        let rule_count = program.rule_count;
        let bytecode_bytes = program.to_bytes();
        Self {
            bytecode: program,
            version,
            source_hash,
            compiled_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            rule_count,
            bytecode_bytes,
        }
    }
}

// ── ReloadResult ─────────────────────────────────────────────────────────

/// Result of a hot-reload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResult {
    /// The version that was active before the reload.
    pub old_version: String,
    /// The new version after the reload.
    pub new_version: String,
    /// Number of rules that changed (added + removed).
    pub rules_changed: u32,
    /// Whether the bytecode signature changed.
    pub signatures_changed: bool,
    /// Time taken for the reload in nanoseconds.
    pub reload_time_ns: u64,
}

// ── PolicyCompiler ─────────────────────────────────────────────────────

/// The main policy compiler — orchestrates compilation and execution.
///
/// Provides a high-level API for:
///   - Compiling YAML policies to CompiledPolicy artifacts
///   - Executing compiled policies against PolicyInput
///   - Hot-reloading policies at runtime
pub struct PolicyCompiler {
    /// Compiler configuration.
    config: PolicyCompilerConfig,
    /// The inner compiler engine (YAML → bytecode).
    engine: PolicyCompilerEngine,
    /// The bytecode VM for execution.
    vm: vm::PolicyVM,
    /// Currently active compiled policy (if any).
    current_policy: Option<CompiledPolicy>,
    /// Version history store.
    version_store: PolicyVersionStore,
    /// Next version to assign.
    next_version: PolicyVersion,
}

impl PolicyCompiler {
    /// Create a new PolicyCompiler with the given configuration.
    pub fn new(config: PolicyCompilerConfig) -> Result<Self> {
        if config.compilation_threads == 0 {
            return Err(Error::ConfigLoad("compilation_threads must be >= 1".into()));
        }

        let vm_config = vm::VMConfig::default();
        let vm = vm::PolicyVM::with_config(vm_config);
        let version_store = PolicyVersionStore::new(config.bytecode_cache_size);

        Ok(Self {
            config,
            engine: PolicyCompilerEngine::new(),
            vm,
            current_policy: None,
            version_store,
            next_version: PolicyVersion::new(1, 0, 0),
        })
    }

    /// Compile a YAML policy string into a CompiledPolicy.
    pub fn compile_yaml(&mut self, yaml_str: &str) -> Result<CompiledPolicy> {
        // Check policy size.
        if yaml_str.len() > self.config.max_policy_size {
            return Err(Error::Evaluation(format!(
                "policy size {} exceeds maximum {} bytes",
                yaml_str.len(),
                self.config.max_policy_size
            )));
        }

        // Parse the YAML to get the version info.
        let policy = self.engine.parse_yaml(yaml_str)?;

        // Override version if the policy specifies one.
        if let Ok(pv) = PolicyVersion::parse(&policy.version) {
            self.next_version = pv;
        }

        // Compile to bytecode.
        let program = self.engine.compile(&policy)?;

        // Compute source hash.
        let source_hash = format!("{:016x}", hash_bytes(yaml_str.as_bytes()));

        // Create the compiled policy.
        let version_str = self.next_version.to_string();
        let compiled =
            CompiledPolicy::from_program(program, version_str.clone(), source_hash.clone());

        // Store in version history.
        let parent = self
            .current_policy
            .as_ref()
            .map(|p| PolicyVersion::parse(&p.version).unwrap_or(PolicyVersion::new(0, 0, 0)));

        let versioned = VersionedPolicy::new(
            self.next_version.clone(),
            format!("{:016x}", hash_bytes(&compiled.bytecode_bytes)),
            source_hash.clone(),
            compiled.compiled_at,
            parent,
            compiled.bytecode_bytes.clone(),
            compiled.rule_count,
        );

        let _ = self.version_store.store(versioned);

        // Advance to next version.
        self.next_version = self.next_version.bump_minor();

        // Set as current policy.
        self.current_policy = Some(compiled.clone());

        Ok(compiled)
    }

    /// Execute a compiled policy against the given input.
    pub fn execute(&self, policy: &CompiledPolicy, input: &PolicyInput) -> Result<PolicyOutput> {
        let start = Instant::now();

        let env = input.to_vm_env();

        // Execute the bytecode program on the VM.
        let vm_result = self
            .vm
            .execute(&policy.bytecode, &env)
            .map_err(|e| Error::Evaluation(e))?;

        let elapsed = start.elapsed().as_nanos() as u64;

        Ok(PolicyOutput::new(
            vm_result.decision,
            vm_result.risk_score,
            vm_result.rules_matched,
            elapsed,
            policy.version.clone(),
        ))
    }

    /// Execute the current active policy against the given input.
    pub fn execute_current(&self, input: &PolicyInput) -> Result<PolicyOutput> {
        let policy = self
            .current_policy
            .as_ref()
            .ok_or_else(|| Error::Evaluation("no policy currently loaded".into()))?;
        self.execute(policy, input)
    }

    /// Hot-reload a new YAML policy, replacing the current one.
    ///
    /// Returns a ReloadResult with diff information.
    pub fn hot_reload(&mut self, yaml_str: &str) -> Result<ReloadResult> {
        let start = Instant::now();

        let old_version = self
            .current_policy
            .as_ref()
            .map(|p| p.version.clone())
            .unwrap_or_else(|| "none".to_string());

        let old_hash = self
            .current_policy
            .as_ref()
            .map(|p| p.source_hash.clone())
            .unwrap_or_default();

        // Save old rule count BEFORE compile_yaml overwrites self.current_policy.
        let old_rule_count = self
            .current_policy
            .as_ref()
            .map(|p| p.rule_count)
            .unwrap_or(0);

        // Compile the new policy.
        let new_policy = self.compile_yaml(yaml_str)?;

        let reload_time = start.elapsed().as_nanos() as u64;

        let signatures_changed = old_hash != new_policy.source_hash;
        let rules_changed = if old_rule_count > new_policy.rule_count {
            old_rule_count - new_policy.rule_count
        } else {
            new_policy.rule_count - old_rule_count
        };

        Ok(ReloadResult {
            old_version,
            new_version: new_policy.version,
            rules_changed,
            signatures_changed,
            reload_time_ns: reload_time,
        })
    }

    /// Get the currently active compiled policy.
    pub fn current_policy(&self) -> Option<&CompiledPolicy> {
        self.current_policy.as_ref()
    }

    /// Get a reference to the version store.
    pub fn version_store(&self) -> &PolicyVersionStore {
        &self.version_store
    }

    /// Get a mutable reference to the version store.
    pub fn version_store_mut(&mut self) -> &mut PolicyVersionStore {
        &mut self.version_store
    }

    /// Get the compiler configuration.
    pub fn config(&self) -> &PolicyCompilerConfig {
        &self.config
    }
}

// ── Helper ─────────────────────────────────────────────────────────────

/// Simple hash function for bytes (FNV-1a inspired).
fn hash_bytes(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_POLICY: &str = r#"
version: "1.0"
name: "test-security-policy"
rules:
  - name: "block_sql_injection"
    action: "deny"
    condition: 'payload.contains("SELECT")'
    enabled: true
    risk_weight: 0.3
  - name: "block_high_risk"
    action: "deny"
    condition: "risk_score > 0.8"
    enabled: true
    risk_weight: 0.5
  - name: "allow_known_users"
    action: "allow"
    condition: 'user_id == "admin"'
    enabled: true
"#;

    fn test_config() -> PolicyCompilerConfig {
        PolicyCompilerConfig {
            enabled: true,
            bytecode_cache_size: 10,
            max_policy_size: 10 * 1024 * 1024,
            hot_reload: false,
            compilation_threads: 1,
        }
    }

    #[test]
    fn config_defaults() {
        let config = PolicyCompilerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.bytecode_cache_size, 64);
        assert_eq!(config.max_policy_size, 10 * 1024 * 1024);
        assert!(!config.hot_reload);
        assert_eq!(config.compilation_threads, 1);
    }

    #[test]
    fn compiler_new() {
        let compiler = PolicyCompiler::new(test_config()).unwrap();
        assert!(compiler.current_policy().is_none());
        assert_eq!(compiler.version_store().len(), 0);
    }

    #[test]
    fn compiler_new_zero_threads_fails() {
        let config = PolicyCompilerConfig {
            compilation_threads: 0,
            ..test_config()
        };
        let result = PolicyCompiler::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn compile_yaml_policy() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        let compiled = compiler.compile_yaml(SAMPLE_POLICY).unwrap();
        assert!(!compiled.version.is_empty());
        assert_eq!(compiled.rule_count, 3);
        assert!(compiled.bytecode.instruction_count() > 0);
        assert!(compiler.current_policy().is_some());
    }

    #[test]
    fn compile_oversized_policy_fails() {
        let mut compiler = PolicyCompiler::new(PolicyCompilerConfig {
            max_policy_size: 10, // very small
            ..test_config()
        })
        .unwrap();

        let result = compiler.compile_yaml(SAMPLE_POLICY);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn execute_deny_sql_injection() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        let compiled = compiler.compile_yaml(SAMPLE_POLICY).unwrap();

        let input =
            PolicyInput::new("req-001", "192.168.1.1", "SELECT * FROM users").with_user("unknown");

        let output = compiler.execute(&compiled, &input).unwrap();
        assert!(output.decision.is_deny());
        assert!(output.execution_time_ns > 0);
        assert!(!output.policy_version.is_empty());
    }

    #[test]
    fn execute_deny_high_risk() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        let compiled = compiler.compile_yaml(SAMPLE_POLICY).unwrap();

        // Directly execute via VM with risk_score set high.
        let mut env = HashMap::new();
        env.insert("risk_score".to_string(), vm::Value::Number(0.9));
        env.insert("payload".to_string(), vm::Value::String("hello".into()));
        env.insert("user_id".to_string(), vm::Value::String("guest".into()));

        let result = compiler.vm.execute(&compiled.bytecode, &env).unwrap();
        assert!(result.decision.is_deny());
    }

    #[test]
    fn execute_allow_safe_request() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        let compiled = compiler.compile_yaml(SAMPLE_POLICY).unwrap();

        // Safe request with no SQL injection, low risk, non-admin user.
        let mut env = HashMap::new();
        env.insert("risk_score".to_string(), vm::Value::Number(0.1));
        env.insert(
            "payload".to_string(),
            vm::Value::String("hello world".into()),
        );
        env.insert("user_id".to_string(), vm::Value::String("guest".into()));

        let result = compiler.vm.execute(&compiled.bytecode, &env).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn policy_input_to_vm_env() {
        let input = PolicyInput::new("req-123", "10.0.0.1", "test payload")
            .with_user("alice")
            .with_header("X-Request-Id", "abc");

        let env = input.to_vm_env();
        assert_eq!(env.get("request_id").unwrap().to_string(), "\"req-123\"");
        assert_eq!(env.get("source_ip").unwrap().to_string(), "\"10.0.0.1\"");
        assert_eq!(env.get("payload").unwrap().to_string(), "\"test payload\"");
        assert_eq!(env.get("user_id").unwrap().to_string(), "\"alice\"");
    }

    #[test]
    fn hot_reload_policy() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        compiler.compile_yaml(SAMPLE_POLICY).unwrap();

        let new_yaml = r#"
version: "2.0"
name: "updated-policy"
rules:
  - name: "new_rule"
    action: "deny"
    condition: 'payload.contains("malware")'
    enabled: true
"#;

        let result = compiler.hot_reload(new_yaml).unwrap();
        assert_eq!(result.old_version, "1.0.0");
        assert!(result.signatures_changed);
        assert!(result.rules_changed > 0);
        assert!(result.reload_time_ns > 0);
    }

    #[test]
    fn version_store_tracks_compiles() {
        let mut compiler = PolicyCompiler::new(test_config()).unwrap();
        compiler.compile_yaml(SAMPLE_POLICY).unwrap();
        assert_eq!(compiler.version_store().len(), 1);
        assert!(compiler.version_store().latest().is_some());
    }

    #[test]
    fn policy_output_serialization() {
        let output = PolicyOutput::new(
            Decision::Deny {
                code: "TEST".to_string(),
                retry_after: Some(60),
            },
            0.85,
            vec!["rule_1".to_string()],
            12345,
            "1.0.0".to_string(),
        );

        let json = serde_json::to_string(&output).unwrap();
        let deserialized: PolicyOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.risk_score, 0.85);
        assert_eq!(deserialized.policy_version, "1.0.0");
        assert!(deserialized.decision.is_deny());
    }

    #[test]
    fn compiled_policy_from_program() {
        let program = BytecodeProgram::new();
        let compiled = CompiledPolicy::from_program(program, "1.0.0".into(), "hash123".into());
        assert_eq!(compiled.version, "1.0.0");
        assert_eq!(compiled.source_hash, "hash123");
        assert!(!compiled.bytecode_bytes.is_empty());
        assert!(compiled.compiled_at > 0);
    }

    #[test]
    fn reload_result_serialization() {
        let result = ReloadResult {
            old_version: "1.0.0".into(),
            new_version: "2.0.0".into(),
            rules_changed: 3,
            signatures_changed: true,
            reload_time_ns: 5000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ReloadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.old_version, "1.0.0");
        assert_eq!(deserialized.new_version, "2.0.0");
        assert!(deserialized.signatures_changed);
    }
}
