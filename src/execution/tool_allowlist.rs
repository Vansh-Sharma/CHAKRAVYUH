// Tool Allowlist — Engine 1 of the Execution Ring
//
// Only pre-approved tools can be called by AI agents.
// Each tool has a configurable max_calls_per_request limit.
// Tools not on the allowlist are automatically blocked.
//
// Latency Budget: <0.2ms p99

use serde::{Deserialize, Serialize};

/// Configuration for a single tool in the allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_calls")]
    pub max_calls_per_request: u32,
}

fn default_true() -> bool {
    true
}
fn default_max_calls() -> u32 {
    5
}

/// Configuration for the Tool Allowlist engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAllowlistConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub tools: Vec<ToolEntry>,
}

fn default_enabled() -> bool {
    true
}

impl Default for ToolAllowlistConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            tools: vec![
                ToolEntry {
                    name: "web_search".into(),
                    enabled: true,
                    max_calls_per_request: 5,
                },
                ToolEntry {
                    name: "calculator".into(),
                    enabled: true,
                    max_calls_per_request: 10,
                },
                ToolEntry {
                    name: "file_read".into(),
                    enabled: true,
                    max_calls_per_request: 3,
                },
            ],
        }
    }
}

/// Result of a tool allowlist check.
#[derive(Debug, Clone, Serialize)]
pub struct ToolAllowlistResult {
    pub decision: crate::decision::Decision,
    pub reason: String,
    pub tool_name: String,
    pub latency_ms: f64,
}

/// The Tool Allowlist engine.
///
/// Checks whether a tool call is on the configured allowlist.
/// Tools not in the list are denied. Disabled tools are denied.
/// Calls exceeding max_calls_per_request are denied.
pub struct ToolAllowlist {
    config: ToolAllowlistConfig,
    /// Tracks call counts per tool per request (keyed by request_id).
    call_counts:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, u32>>>,
}

impl Clone for ToolAllowlist {
    fn clone(&self) -> Self {
        // Note: call counts are NOT cloned across instances — each
        // clone gets a fresh counter. This is intentional for the
        // API layer where each request handler clones the engine.
        Self {
            config: self.config.clone(),
            call_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl ToolAllowlist {
    pub fn new(config: &ToolAllowlistConfig) -> crate::Result<Self> {
        Ok(Self {
            config: config.clone(),
            call_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Check if a tool call is allowed.
    ///
    /// If the tool is on the allowlist, enabled, and within the call limit, returns Allow.
    /// Otherwise returns Deny with a specific reason.
    pub fn evaluate(&self, tool_name: &str, request_id: &str) -> ToolAllowlistResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ToolAllowlistResult {
                decision: crate::decision::Decision::Allow,
                reason: "tool_allowlist engine disabled".into(),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Find the tool in the allowlist.
        let entry = self.config.tools.iter().find(|t| t.name == tool_name);

        match entry {
            None => {
                // Tool not on allowlist — deny (Principle 2: Fail Secure).
                ToolAllowlistResult {
                    decision: crate::decision::Decision::Deny {
                        code: "EXEC_TOOL_NOT_ALLOWLISTED".into(),
                        retry_after: None,
                    },
                    reason: format!(
                        "tool '{}' is not on the allowlist; configure it in execution.tools",
                        tool_name
                    ),
                    tool_name: tool_name.into(),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                }
            }
            Some(entry) => {
                if !entry.enabled {
                    ToolAllowlistResult {
                        decision: crate::decision::Decision::Deny {
                            code: "EXEC_TOOL_DISABLED".into(),
                            retry_after: None,
                        },
                        reason: format!("tool '{}' is disabled in configuration", tool_name),
                        tool_name: tool_name.into(),
                        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }
                } else {
                    // Check call count.
                    let mut counts = self.call_counts.lock().unwrap();
                    let req_counts = counts.entry(request_id.to_string()).or_default();
                    let current = req_counts.entry(tool_name.to_string()).or_insert(0);
                    *current += 1;

                    if *current > entry.max_calls_per_request {
                        ToolAllowlistResult {
                            decision: crate::decision::Decision::Deny {
                                code: "EXEC_TOOL_RATE_EXCEEDED".into(),
                                retry_after: None,
                            },
                            reason: format!(
                                "tool '{}' exceeded max_calls_per_request ({})",
                                tool_name, entry.max_calls_per_request
                            ),
                            tool_name: tool_name.into(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                        }
                    } else {
                        ToolAllowlistResult {
                            decision: crate::decision::Decision::Allow,
                            reason: format!(
                                "tool '{}' is allowlisted (call {}/{})",
                                tool_name, *current, entry.max_calls_per_request
                            ),
                            tool_name: tool_name.into(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                        }
                    }
                }
            }
        }
    }

    /// Reset call counts for a request (called after the request completes).
    pub fn reset_request(&self, request_id: &str) {
        let mut counts = self.call_counts.lock().unwrap();
        counts.remove(request_id);
    }

    /// Get the list of configured tools.
    pub fn tools(&self) -> &[ToolEntry] {
        &self.config.tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ToolAllowlistConfig {
        ToolAllowlistConfig::default()
    }

    #[test]
    fn allow_known_enabled_tool() {
        let engine = ToolAllowlist::new(&default_config()).unwrap();
        let result = engine.evaluate("web_search", "req-1");
        assert!(result.decision.is_allow());
        assert!(result.reason.contains("web_search"));
    }

    #[test]
    fn deny_unknown_tool() {
        let engine = ToolAllowlist::new(&default_config()).unwrap();
        let result = engine.evaluate("rm -rf", "req-1");
        assert!(result.decision.is_deny());
        assert!(result.reason.contains("not on the allowlist"));
    }

    #[test]
    fn enforce_max_calls() {
        let config = ToolAllowlistConfig {
            tools: vec![ToolEntry {
                name: "calculator".into(),
                enabled: true,
                max_calls_per_request: 2,
            }],
            ..Default::default()
        };
        let engine = ToolAllowlist::new(&config).unwrap();

        assert!(engine.evaluate("calculator", "req-x").decision.is_allow());
        assert!(engine.evaluate("calculator", "req-x").decision.is_allow());
        assert!(engine.evaluate("calculator", "req-x").decision.is_deny());
    }

    #[test]
    fn reset_clears_counts() {
        let engine = ToolAllowlist::new(&default_config()).unwrap();
        assert!(engine.evaluate("web_search", "req-r").decision.is_allow());
        engine.reset_request("req-r");
        // After reset, counter starts over at 1 (not 2).
        assert!(engine.evaluate("web_search", "req-r").decision.is_allow());
    }

    #[test]
    fn different_requests_independent() {
        let engine = ToolAllowlist::new(&default_config()).unwrap();
        assert!(engine.evaluate("web_search", "req-a").decision.is_allow());
        assert!(engine.evaluate("web_search", "req-b").decision.is_allow());
    }
}
