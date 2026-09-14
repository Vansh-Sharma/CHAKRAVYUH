// Sandbox Executor — Engine 3 of the Execution Ring
//
// Configures sandbox environments for risky tool calls.
// In the MVP, this engine produces SandboxConfig — it does NOT
// execute tools itself. The host application reads the config
// and applies sandboxing (chroot, container, seccomp, etc.).
//
// Latency Budget: N/A (config generation only, <0.1ms)

use serde::{Deserialize, Serialize};

/// Sandbox mode for a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// No sandboxing required (safe tool).
    None,
    /// Filesystem isolation (chroot / restricted path).
    Filesystem,
    /// Full container isolation (network + fs + process).
    Container,
    /// Network sandbox only (restrict outbound connections).
    Network,
}

/// Sandbox configuration produced by this engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub mode: SandboxMode,
    /// Allowed filesystem paths (for Filesystem mode).
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Blocked network ranges (for Network/Container mode).
    #[serde(default)]
    pub blocked_networks: Vec<String>,
    /// Maximum execution time in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Maximum memory in MB.
    #[serde(default = "default_memory")]
    pub max_memory_mb: u64,
    /// Whether network access is allowed.
    #[serde(default = "default_true")]
    pub network_allowed: bool,
    /// Whether environment variables are stripped.
    #[serde(default = "default_true")]
    pub strip_env: bool,
}

fn default_timeout() -> u64 {
    30
}
fn default_memory() -> u64 {
    256
}
fn default_true() -> bool {
    true
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::None,
            allowed_paths: vec![],
            blocked_networks: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "169.254.0.0/16".into(),
                "127.0.0.0/8".into(),
            ],
            timeout_secs: default_timeout(),
            max_memory_mb: default_memory(),
            network_allowed: true,
            strip_env: true,
        }
    }
}

/// Configuration for the Sandbox Executor engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Default sandbox config for tools not explicitly configured.
    #[serde(default)]
    pub default_config: SandboxConfig,
    /// Per-tool sandbox overrides.
    #[serde(default)]
    pub tool_overrides: std::collections::HashMap<String, SandboxConfig>,
    /// Risky tools that always get full container sandbox.
    #[serde(default)]
    pub always_sandbox_tools: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

impl Default for SandboxExecutorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            default_config: SandboxConfig::default(),
            tool_overrides: std::collections::HashMap::new(),
            always_sandbox_tools: vec![
                "shell_exec".into(),
                "code_execution".into(),
                "file_write".into(),
            ],
        }
    }
}

/// Result of sandbox configuration.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxExecutorResult {
    pub sandbox_config: SandboxConfig,
    pub reason: String,
    pub tool_name: String,
    pub latency_ms: f64,
}

/// The Sandbox Executor engine.
///
/// Produces sandbox configuration for tool calls. Does NOT execute
/// the tool — the host application reads SandboxConfig and applies it.
#[derive(Clone)]
pub struct SandboxExecutor {
    config: SandboxExecutorConfig,
}

impl SandboxExecutor {
    pub fn new(config: &SandboxExecutorConfig) -> crate::Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Get the sandbox configuration for a tool call.
    pub fn evaluate(&self, tool_name: &str) -> SandboxExecutorResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return SandboxExecutorResult {
                sandbox_config: SandboxConfig {
                    mode: SandboxMode::None,
                    ..Default::default()
                },
                reason: "sandbox_executor engine disabled".into(),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check tool-specific overrides first.
        if let Some(override_cfg) = self.config.tool_overrides.get(tool_name) {
            return SandboxExecutorResult {
                sandbox_config: override_cfg.clone(),
                reason: format!("tool '{}' uses override sandbox config", tool_name),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check if tool always gets full sandbox.
        if self
            .config
            .always_sandbox_tools
            .contains(&tool_name.to_string())
        {
            let mut cfg = SandboxConfig::default();
            cfg.mode = SandboxMode::Container;
            cfg.network_allowed = false;
            cfg.strip_env = true;
            return SandboxExecutorResult {
                sandbox_config: cfg,
                reason: format!(
                    "tool '{}' is in always_sandbox_tools; applying container sandbox",
                    tool_name
                ),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        SandboxExecutorResult {
            sandbox_config: self.config.default_config.clone(),
            reason: format!("tool '{}' uses default sandbox config", tool_name),
            tool_name: tool_name.into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_sandbox_gets_container() {
        let engine = SandboxExecutor::new(&SandboxExecutorConfig::default()).unwrap();
        let result = engine.evaluate("shell_exec");
        assert_eq!(result.sandbox_config.mode, SandboxMode::Container);
        assert!(!result.sandbox_config.network_allowed);
    }

    #[test]
    fn safe_tool_gets_none() {
        let engine = SandboxExecutor::new(&SandboxExecutorConfig::default()).unwrap();
        let result = engine.evaluate("calculator");
        assert_eq!(result.sandbox_config.mode, SandboxMode::None);
    }

    #[test]
    fn override_takes_precedence() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(
            "web_search".into(),
            SandboxConfig {
                mode: SandboxMode::Network,
                network_allowed: true,
                ..Default::default()
            },
        );
        let config = SandboxExecutorConfig {
            tool_overrides: overrides,
            ..Default::default()
        };
        let engine = SandboxExecutor::new(&config).unwrap();
        let result = engine.evaluate("web_search");
        assert_eq!(result.sandbox_config.mode, SandboxMode::Network);
    }

    #[test]
    fn disabled_returns_none() {
        let config = SandboxExecutorConfig {
            enabled: false,
            ..Default::default()
        };
        let engine = SandboxExecutor::new(&config).unwrap();
        let result = engine.evaluate("shell_exec");
        assert_eq!(result.sandbox_config.mode, SandboxMode::None);
    }
}
