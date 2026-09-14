// Plugin API — Sandboxed execution interface for CHAKRAVYUH plugins.
//
// Provides input/output validation, host function dispatch, timeout
// enforcement, and structured result types for plugin execution.

use super::wasm_runtime::{SandboxViolation, WasmRuntime, WasmValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the plugin execution API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginApiConfig {
    /// Maximum input payload in bytes (default: 64 KB).
    pub max_input_bytes: usize,
    /// Maximum output payload in bytes (default: 1 MB).
    pub max_output_bytes: usize,
    /// Maximum execution time per call in milliseconds (default: 50).
    pub max_execution_ms: u64,
    /// Host functions the plugin is allowed to call.
    pub allowed_host_functions: Vec<String>,
}

impl Default for PluginApiConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_output_bytes: 1024 * 1024,
            max_execution_ms: 50,
            allowed_host_functions: vec![
                "log".to_string(),
                "get_config".to_string(),
                "emit_metric".to_string(),
                "get_request_header".to_string(),
                "report_decision".to_string(),
                "get_current_time".to_string(),
            ],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host functions
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the built-in host functions a plugin may invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostFunction {
    Log,
    GetConfig,
    EmitMetric,
    GetRequestHeader,
    ReportDecision,
    GetCurrentTime,
}

impl HostFunction {
    /// Convert to the string name used for allowlist checking.
    pub fn as_str(&self) -> &str {
        match self {
            HostFunction::Log => "log",
            HostFunction::GetConfig => "get_config",
            HostFunction::EmitMetric => "emit_metric",
            HostFunction::GetRequestHeader => "get_request_header",
            HostFunction::ReportDecision => "report_decision",
            HostFunction::GetCurrentTime => "get_current_time",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output
// ─────────────────────────────────────────────────────────────────────────────

/// Data passed to a plugin for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    pub request_id: String,
    pub prompt_text: String,
    pub source_ip: String,
    pub headers: HashMap<String, String>,
    pub risk_score: f64,
    pub ring_name: String,
}

impl PluginInput {
    /// Build a serialized byte representation for WASM consumption.
    pub fn serialize(&self) -> Vec<u8> {
        format!(
            "req:{}\nprompt:{}\nip:{}\nrisk:{}\nring:{}\n",
            self.request_id, self.prompt_text, self.source_ip, self.risk_score, self.ring_name
        )
        .into_bytes()
    }

    /// Total byte size of the serialized input.
    pub fn serialized_size(&self) -> usize {
        self.serialize().len()
    }
}

/// The decision a plugin can return.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PluginDecision {
    Allow,
    Deny(String),
    Challenge(String),
    NoOp,
}

impl std::fmt::Display for PluginDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginDecision::Allow => write!(f, "allow"),
            PluginDecision::Deny(reason) => write!(f, "deny: {}", reason),
            PluginDecision::Challenge(challenge) => write!(f, "challenge: {}", challenge),
            PluginDecision::NoOp => write!(f, "noop"),
        }
    }
}

/// A metric event emitted by a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricEvent {
    pub name: String,
    pub value: f64,
    pub timestamp: String,
    pub labels: HashMap<String, String>,
}

impl MetricEvent {
    pub fn new(name: &str, value: f64) -> Self {
        Self {
            name: name.to_string(),
            value,
            timestamp: chrono::Utc::now().to_rfc3339(),
            labels: HashMap::new(),
        }
    }

    pub fn with_label(mut self, key: &str, val: &str) -> Self {
        self.labels.insert(key.to_string(), val.to_string());
        self
    }
}

/// Output produced by a plugin after execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub decision: PluginDecision,
    pub confidence: f64,
    pub reason: String,
    pub metrics_emitted: Vec<MetricEvent>,
    pub execution_time_ms: f64,
    pub memory_used_bytes: u64,
}

impl PluginOutput {
    pub fn new(decision: PluginDecision, confidence: f64, reason: &str) -> Self {
        Self {
            decision,
            confidence,
            reason: reason.to_string(),
            metrics_emitted: Vec::new(),
            execution_time_ms: 0.0,
            memory_used_bytes: 0,
        }
    }

    pub fn allow(reason: &str) -> Self {
        Self::new(PluginDecision::Allow, 1.0, reason)
    }

    pub fn deny(reason: &str) -> Self {
        Self::new(PluginDecision::Deny(reason.to_string()), 1.0, reason)
    }

    pub fn noop(reason: &str) -> Self {
        Self::new(PluginDecision::NoOp, 0.0, reason)
    }

    pub fn with_metric(mut self, metric: MetricEvent) -> Self {
        self.metrics_emitted.push(metric);
        self
    }

    pub fn with_execution_time(mut self, ms: f64) -> Self {
        self.execution_time_ms = ms;
        self
    }

    pub fn with_memory_used(mut self, bytes: u64) -> Self {
        self.memory_used_bytes = bytes;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a sandboxed plugin execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxResult {
    Success(PluginOutput),
    SandboxViolation(SandboxViolation),
    ExecutionError(String),
    Timeout,
}

impl SandboxResult {
    /// Extract the PluginOutput, or return an error string.
    pub fn into_output(self) -> std::result::Result<PluginOutput, String> {
        match self {
            SandboxResult::Success(output) => Ok(output),
            SandboxResult::SandboxViolation(v) => Err(format!("sandbox violation: {}", v)),
            SandboxResult::ExecutionError(e) => Err(format!("execution error: {}", e)),
            SandboxResult::Timeout => Err("execution timed out".to_string()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginApi
// ─────────────────────────────────────────────────────────────────────────────

/// Sandboxed execution API for plugins.
#[derive(Debug)]
pub struct PluginApi {
    config: PluginApiConfig,
    pub runtime: WasmRuntime,
    host_functions: Vec<HostFunction>,
}

impl PluginApi {
    pub fn new(config: PluginApiConfig, runtime: WasmRuntime) -> Self {
        Self {
            config,
            runtime,
            host_functions: Vec::new(),
        }
    }

    /// Execute a plugin function and return a SandboxResult.
    pub fn execute(
        &mut self,
        plugin_name: &str,
        func_name: &str,
        input: &PluginInput,
    ) -> SandboxResult {
        // Validate input size.
        if let Err(e) = self.validate_input(input) {
            return SandboxResult::ExecutionError(e);
        }

        let _serialized = input.serialize();
        let risk_i32 = (input.risk_score * 100.0) as i32;

        // Map risk score to a WASM value argument.
        let wasm_args = vec![WasmValue::I32(risk_i32)];

        let start = Instant::now();
        let result = self.runtime.call(plugin_name, func_name, wasm_args);
        let elapsed = start.elapsed();

        // Timeout check.
        if elapsed.as_millis() as u64 > self.config.max_execution_ms {
            return SandboxResult::Timeout;
        }

        match result {
            Ok(wasm_val) => {
                let decision = self.wasm_value_to_decision(&wasm_val, &input);
                let output = PluginOutput::new(
                    decision.clone(),
                    0.8,
                    &format!(
                        "plugin {} evaluated, wasm returned {}",
                        plugin_name, wasm_val
                    ),
                )
                .with_execution_time(elapsed.as_secs_f64() * 1000.0)
                .with_memory_used(self.runtime.fuel_consumed());
                SandboxResult::Success(output)
            }
            Err(e) => {
                if e.contains("fuel exhausted") {
                    SandboxResult::SandboxViolation(SandboxViolation::FuelExhausted)
                } else if e.contains("out of memory") {
                    SandboxResult::SandboxViolation(SandboxViolation::OutOfMemory)
                } else if e.contains("stack overflow") {
                    SandboxResult::SandboxViolation(SandboxViolation::StackOverflow)
                } else if e.contains("invalid") {
                    SandboxResult::SandboxViolation(SandboxViolation::InvalidAccess)
                } else {
                    SandboxResult::ExecutionError(e)
                }
            }
        }
    }

    /// Validate the input against size limits.
    pub fn validate_input(&self, input: &PluginInput) -> std::result::Result<(), String> {
        let size = input.serialized_size();
        if size > self.config.max_input_bytes {
            return Err(format!(
                "input size {} exceeds limit {}",
                size, self.config.max_input_bytes
            ));
        }
        Ok(())
    }

    /// Register a host function that plugins may call.
    pub fn register_host_function(&mut self, hf: HostFunction) {
        let name = hf.as_str().to_string();
        if !self.config.allowed_host_functions.contains(&name) {
            self.config.allowed_host_functions.push(name);
        }
        self.host_functions.push(hf);
    }

    /// List all registered host function names.
    pub fn list_host_functions(&self) -> Vec<&str> {
        self.host_functions.iter().map(|hf| hf.as_str()).collect()
    }

    /// Map a WASM return value to a PluginDecision.
    fn wasm_value_to_decision(&self, val: &WasmValue, input: &PluginInput) -> PluginDecision {
        let risk_threshold = 50i32; // 0.5 risk score mapped to i32
        match val {
            WasmValue::I32(v) => {
                if *v >= risk_threshold {
                    PluginDecision::Deny(format!(
                        "risk score {} exceeds threshold",
                        input.risk_score
                    ))
                } else {
                    PluginDecision::Allow
                }
            }
            WasmValue::I64(v) => {
                if *v >= risk_threshold as i64 {
                    PluginDecision::Deny(format!(
                        "risk score {} exceeds threshold",
                        input.risk_score
                    ))
                } else {
                    PluginDecision::Allow
                }
            }
            _ => PluginDecision::NoOp,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::wasm_runtime::{WasmFunction, WasmModule, WasmOpcode, WasmRuntimeConfig};

    fn make_api() -> PluginApi {
        let runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        PluginApi::new(PluginApiConfig::default(), runtime)
    }

    fn make_api_with_module() -> PluginApi {
        let mut runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        // Simple module: evaluate function returns param 0 (risk score as i32)
        let func = WasmFunction::new("evaluate", vec![WasmOpcode::LocalGet(0), WasmOpcode::End])
            .with_param(WasmValue::I32(0));
        let module = WasmModule::new("test-plugin")
            .with_function(func)
            .with_export("evaluate")
            .with_memory(vec![0u8; 4096]);
        runtime.load_module(module).unwrap();
        PluginApi::new(PluginApiConfig::default(), runtime)
    }

    fn make_input(risk: f64) -> PluginInput {
        PluginInput {
            request_id: "req-001".to_string(),
            prompt_text: "hello world".to_string(),
            source_ip: "10.0.0.1".to_string(),
            headers: HashMap::new(),
            risk_score: risk,
            ring_name: "threat".to_string(),
        }
    }

    // ── Config tests ──

    #[test]
    fn test_api_config_defaults() {
        let cfg = PluginApiConfig::default();
        assert_eq!(cfg.max_input_bytes, 64 * 1024);
        assert_eq!(cfg.max_output_bytes, 1024 * 1024);
        assert_eq!(cfg.max_execution_ms, 50);
        assert!(!cfg.allowed_host_functions.is_empty());
    }

    // ── HostFunction tests ──

    #[test]
    fn test_host_function_names() {
        assert_eq!(HostFunction::Log.as_str(), "log");
        assert_eq!(HostFunction::GetConfig.as_str(), "get_config");
        assert_eq!(HostFunction::EmitMetric.as_str(), "emit_metric");
        assert_eq!(
            HostFunction::GetRequestHeader.as_str(),
            "get_request_header"
        );
        assert_eq!(HostFunction::ReportDecision.as_str(), "report_decision");
        assert_eq!(HostFunction::GetCurrentTime.as_str(), "get_current_time");
    }

    // ── PluginInput tests ──

    #[test]
    fn test_plugin_input_serialize() {
        let input = make_input(0.5);
        let bytes = input.serialize();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("req-001"));
        assert!(text.contains("hello world"));
        assert!(text.contains("10.0.0.1"));
    }

    #[test]
    fn test_plugin_input_serialized_size() {
        let input = make_input(0.5);
        assert!(input.serialized_size() > 0);
    }

    // ── PluginDecision tests ──

    #[test]
    fn test_decision_display() {
        assert_eq!(format!("{}", PluginDecision::Allow), "allow");
        assert_eq!(format!("{}", PluginDecision::NoOp), "noop");
        assert!(format!("{}", PluginDecision::Deny("err".to_string())).contains("deny"));
    }

    #[test]
    fn test_decision_equality() {
        assert_eq!(PluginDecision::Allow, PluginDecision::Allow);
        assert_eq!(PluginDecision::NoOp, PluginDecision::NoOp);
        assert_ne!(PluginDecision::Allow, PluginDecision::NoOp);
    }

    // ── MetricEvent tests ──

    #[test]
    fn test_metric_event_new() {
        let m = MetricEvent::new("latency_ms", 42.0);
        assert_eq!(m.name, "latency_ms");
        assert_eq!(m.value, 42.0);
        assert!(!m.timestamp.is_empty());
    }

    #[test]
    fn test_metric_event_with_label() {
        let m = MetricEvent::new("requests", 100.0).with_label("ring", "shield");
        assert_eq!(m.labels.get("ring").unwrap(), "shield");
    }

    // ── PluginOutput tests ──

    #[test]
    fn test_output_constructors() {
        let allow = PluginOutput::allow("ok");
        assert_eq!(allow.decision, PluginDecision::Allow);
        assert_eq!(allow.confidence, 1.0);

        let deny = PluginOutput::deny("blocked");
        assert!(matches!(deny.decision, PluginDecision::Deny(_)));

        let noop = PluginOutput::noop("nothing");
        assert_eq!(noop.decision, PluginDecision::NoOp);
    }

    #[test]
    fn test_output_with_metric() {
        let out = PluginOutput::allow("ok").with_metric(MetricEvent::new("eval", 1.0));
        assert_eq!(out.metrics_emitted.len(), 1);
    }

    #[test]
    fn test_output_with_execution_time() {
        let out = PluginOutput::allow("ok").with_execution_time(12.5);
        assert_eq!(out.execution_time_ms, 12.5);
    }

    #[test]
    fn test_output_with_memory_used() {
        let out = PluginOutput::allow("ok").with_memory_used(4096);
        assert_eq!(out.memory_used_bytes, 4096);
    }

    // ── SandboxResult tests ──

    #[test]
    fn test_sandbox_result_success() {
        let r = SandboxResult::Success(PluginOutput::allow("ok"));
        let out = r.into_output().unwrap();
        assert_eq!(out.decision, PluginDecision::Allow);
    }

    #[test]
    fn test_sandbox_result_violation() {
        let r = SandboxResult::SandboxViolation(SandboxViolation::FuelExhausted);
        assert!(r.into_output().is_err());
    }

    #[test]
    fn test_sandbox_result_timeout() {
        let r = SandboxResult::Timeout;
        let err = r.into_output().unwrap_err();
        assert!(err.contains("timed out"));
    }

    #[test]
    fn test_sandbox_result_execution_error() {
        let r = SandboxResult::ExecutionError("oops".to_string());
        let err = r.into_output().unwrap_err();
        assert!(err.contains("oops"));
    }

    // ── PluginApi execution tests ──

    #[test]
    fn test_execute_low_risk() {
        let mut api = make_api_with_module();
        let input = make_input(0.2); // low risk -> i32(20) < 50 -> Allow
        let result = api.execute("test-plugin", "evaluate", &input);
        let output = result.into_output().unwrap();
        assert_eq!(output.decision, PluginDecision::Allow);
    }

    #[test]
    fn test_execute_high_risk() {
        let mut api = make_api_with_module();
        let input = make_input(0.8); // high risk -> i32(80) >= 50 -> Deny
        let result = api.execute("test-plugin", "evaluate", &input);
        let output = result.into_output().unwrap();
        assert!(matches!(output.decision, PluginDecision::Deny(_)));
    }

    #[test]
    fn test_execute_records_time() {
        let mut api = make_api_with_module();
        let input = make_input(0.3);
        let result = api.execute("test-plugin", "evaluate", &input);
        let output = result.into_output().unwrap();
        assert!(output.execution_time_ms >= 0.0);
    }

    #[test]
    fn test_validate_input_within_limits() {
        let api = make_api();
        let input = make_input(0.5);
        assert!(api.validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_input_exceeds_limit() {
        let config = PluginApiConfig {
            max_input_bytes: 10,
            ..Default::default()
        };
        let runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        let api = PluginApi::new(config, runtime);
        let input = make_input(0.5);
        assert!(api.validate_input(&input).is_err());
    }

    #[test]
    fn test_register_host_function() {
        let mut api = make_api();
        api.register_host_function(HostFunction::Log);
        let funcs = api.list_host_functions();
        assert!(funcs.contains(&"log"));
    }

    #[test]
    fn test_register_host_function_adds_to_allowed() {
        let config = PluginApiConfig {
            allowed_host_functions: vec![],
            ..Default::default()
        };
        let runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        let mut api = PluginApi::new(config, runtime);
        api.register_host_function(HostFunction::Log);
        assert!(api
            .config
            .allowed_host_functions
            .contains(&"log".to_string()));
    }

    #[test]
    fn test_execute_nonexistent_plugin() {
        let mut api = make_api();
        let input = make_input(0.5);
        let result = api.execute("ghost", "evaluate", &input);
        assert!(result.into_output().is_err());
    }
}
