// CapabilityGuard — controls what capabilities an agent can access.

use std::collections::HashMap;
use super::agent_policy::AgentType;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq, Hash)]
pub enum Capability {
    CodeExecution, FileWrite, NetworkAccess, ApiCalls, MemoryAccess,
    ShellAccess, EmailSend, DatabaseAccess, FileDelete,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CapabilityGuardConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Per-agent-type capability policy overrides.
    #[serde(default)]
    pub capability_policy: HashMap<String, Vec<String>>,
}

fn default_enabled() -> bool { true }

impl Default for CapabilityGuardConfig {
    fn default() -> Self { Self { enabled: default_enabled(), capability_policy: HashMap::new() } }
}

pub struct CapabilityGuardResult {
    pub allowed: bool,
    pub granted: Vec<Capability>,
    pub denied_capabilities: Vec<String>,
    pub reason: String,
}

fn type_capabilities(agent_type: &AgentType) -> Vec<Capability> {
    match agent_type {
        AgentType::Coder => vec![Capability::CodeExecution, Capability::FileWrite, Capability::FileDelete],
        AgentType::Researcher => vec![Capability::NetworkAccess, Capability::ApiCalls],
        AgentType::Assistant => vec![Capability::MemoryAccess],
        AgentType::Analyst => vec![Capability::NetworkAccess, Capability::ApiCalls, Capability::DatabaseAccess],
        AgentType::Custom(_) => vec![],
    }
}

fn parse_capability(s: &str) -> Option<Capability> {
    match s.to_lowercase().as_str() {
        "code_execution" | "code" => Some(Capability::CodeExecution),
        "file_write" | "write" => Some(Capability::FileWrite),
        "network_access" | "network" => Some(Capability::NetworkAccess),
        "api_calls" | "api" => Some(Capability::ApiCalls),
        "memory_access" | "memory" => Some(Capability::MemoryAccess),
        "shell_access" | "shell" => Some(Capability::ShellAccess),
        "email_send" | "email" => Some(Capability::EmailSend),
        "database_access" | "database" => Some(Capability::DatabaseAccess),
        "file_delete" | "delete" => Some(Capability::FileDelete),
        _ => None,
    }
}

fn tool_to_capability(tool: &str) -> Vec<Capability> {
    let t = tool.to_lowercase();
    let mut caps = Vec::new();
    if t.contains("code_exec") || t.contains("python") || t.contains("node") { caps.push(Capability::CodeExecution); }
    if t.contains("file_write") || t.contains("create_file") || t.contains("save") { caps.push(Capability::FileWrite); }
    if t.contains("file_delete") || t.contains("remove") { caps.push(Capability::FileDelete); }
    if t.contains("http") || t.contains("curl") || t.contains("fetch") || t.contains("network") { caps.push(Capability::NetworkAccess); }
    if t.contains("api_call") || t.contains("rest") { caps.push(Capability::ApiCalls); }
    if t.contains("memory") || t.contains("rag") { caps.push(Capability::MemoryAccess); }
    if t.contains("shell") || t.contains("bash") || t.contains("cmd") { caps.push(Capability::ShellAccess); }
    if t.contains("email") || t.contains("smtp") { caps.push(Capability::EmailSend); }
    if t.contains("sql") || t.contains("db") || t.contains("database") { caps.push(Capability::DatabaseAccess); }
    caps
}

pub struct CapabilityGuard { config: CapabilityGuardConfig }

impl CapabilityGuard {
    pub fn new(config: &CapabilityGuardConfig) -> Self { Self { config: config.clone() } }

    pub fn evaluate(&self, agent_type: &AgentType, tools: &[String]) -> CapabilityGuardResult {
        if !self.config.enabled {
            return CapabilityGuardResult { allowed: true, granted: vec![], denied_capabilities: vec![], reason: "capability guard disabled".into() };
        }

        let type_key = match agent_type {
            AgentType::Custom(s) => s.clone(),
            other => format!("{:?}", other).to_lowercase(),
        };

        let granted: Vec<Capability> = if let Some(policy) = self.config.capability_policy.get(&type_key) {
            policy.iter().filter_map(|c| parse_capability(c)).collect()
        } else {
            type_capabilities(agent_type)
        };

        let granted_set: std::collections::HashSet<_> = granted.iter().collect();
        let mut required_caps = Vec::new();
        for tool in tools {
            for cap in tool_to_capability(tool) {
                if !granted_set.contains(&cap) && !required_caps.contains(&cap) {
                    required_caps.push(cap);
                }
            }
        }

        let denied: Vec<String> = required_caps.iter().map(|c| format!("{:?}", c)).collect();
        let allowed = denied.is_empty();
        let reason = if allowed { "all required capabilities granted".into() } else { format!("denied capabilities: {}", denied.join(", ")) };

        CapabilityGuardResult { allowed, granted, denied_capabilities: denied, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guard() -> CapabilityGuard { CapabilityGuard::new(&CapabilityGuardConfig::default()) }

    #[test]
    fn coder_has_code_execution() {
        let g = default_guard();
        let r = g.evaluate(&AgentType::Coder, &["code_execution".into()]);
        assert!(r.allowed);
    }

    #[test]
    fn assistant_lacks_code_execution() {
        let g = default_guard();
        let r = g.evaluate(&AgentType::Assistant, &["code_execution".into()]);
        assert!(!r.allowed);
        assert!(r.denied_capabilities.contains(&"CodeExecution".to_string()));
    }

    #[test]
    fn researcher_has_network() {
        let g = default_guard();
        let r = g.evaluate(&AgentType::Researcher, &["http_request".into()]);
        assert!(r.allowed);
    }

    #[test]
    fn custom_empty_no_capabilities() {
        let g = default_guard();
        let r = g.evaluate(&AgentType::Custom("empty".into()), &["shell_exec".into()]);
        assert!(!r.allowed);
    }

    #[test]
    fn multiple_tools_checked() {
        let g = default_guard();
        let r = g.evaluate(&AgentType::Assistant, &["shell_exec".into(), "code_execution".into()]);
        assert!(!r.allowed);
        assert!(r.denied_capabilities.len() >= 2);
    }
}
