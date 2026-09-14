// PermissionEnforcer — checks action permissions per agent type.

use super::agent_policy::AgentType;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Execute,
    NetworkAccess,
    FileSystem,
    ApiCall,
    MemoryRead,
    MemoryWrite,
    ToolUse,
    CodeExecution,
    EmailSend,
    FileDelete,
    AdminAccess,
    ShellAccess,
    DatabaseAccess,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PermissionEnforcerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Per-agent-type permission overrides.
    #[serde(default)]
    pub permission_overrides: HashMap<String, Vec<String>>,
}

fn default_enabled() -> bool {
    true
}

impl Default for PermissionEnforcerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            permission_overrides: HashMap::new(),
        }
    }
}

pub struct PermissionResult {
    pub allowed: bool,
    pub effective_permissions: Vec<Permission>,
    pub denied_permissions: Vec<String>,
    pub reason: String,
}

fn type_permissions(agent_type: &AgentType) -> Vec<Permission> {
    match agent_type {
        AgentType::Coder => vec![
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::FileSystem,
            Permission::ApiCall,
            Permission::ToolUse,
            Permission::CodeExecution,
        ],
        AgentType::Researcher => vec![
            Permission::Read,
            Permission::NetworkAccess,
            Permission::ApiCall,
            Permission::MemoryRead,
            Permission::ToolUse,
        ],
        AgentType::Assistant => vec![
            Permission::Read,
            Permission::MemoryRead,
            Permission::ToolUse,
        ],
        AgentType::Analyst => vec![
            Permission::Read,
            Permission::NetworkAccess,
            Permission::ApiCall,
            Permission::MemoryRead,
            Permission::DatabaseAccess,
            Permission::ToolUse,
        ],
        AgentType::Custom(_) => vec![],
    }
}

fn parse_permission(s: &str) -> Option<Permission> {
    match s.to_lowercase().as_str() {
        "read" => Some(Permission::Read),
        "write" => Some(Permission::Write),
        "execute" => Some(Permission::Execute),
        "network_access" | "network" => Some(Permission::NetworkAccess),
        "filesystem" | "file_system" => Some(Permission::FileSystem),
        "api_call" | "api" => Some(Permission::ApiCall),
        "memory_read" => Some(Permission::MemoryRead),
        "memory_write" => Some(Permission::MemoryWrite),
        "tool_use" | "tool" => Some(Permission::ToolUse),
        "code_execution" | "code" => Some(Permission::CodeExecution),
        "email_send" | "email" => Some(Permission::EmailSend),
        "file_delete" => Some(Permission::FileDelete),
        "admin_access" | "admin" => Some(Permission::AdminAccess),
        "shell_access" | "shell" => Some(Permission::ShellAccess),
        "database_access" | "database" => Some(Permission::DatabaseAccess),
        _ => None,
    }
}

fn action_required_permissions(action: &str, tools: &[String]) -> Vec<Permission> {
    let mut perms = Vec::new();
    let action_lower = action.to_lowercase();

    if action_lower.contains("execute_code")
        || action_lower.contains("run_code")
        || action_lower.contains("compile")
    {
        perms.push(Permission::CodeExecution);
    }
    if action_lower.contains("network_call")
        || action_lower.contains("http_request")
        || action_lower.contains("fetch")
    {
        perms.push(Permission::NetworkAccess);
    }
    if action_lower.contains("read_file")
        || action_lower.contains("get_file")
        || action_lower.contains("list_dir")
    {
        perms.push(Permission::Read);
        perms.push(Permission::FileSystem);
    }
    if action_lower.contains("write_file")
        || action_lower.contains("create_file")
        || action_lower.contains("save")
    {
        perms.push(Permission::Write);
        perms.push(Permission::FileSystem);
    }
    if action_lower.contains("delete_file") || action_lower.contains("remove") {
        perms.push(Permission::FileDelete);
        perms.push(Permission::FileSystem);
    }
    if action_lower.contains("send_email") || action_lower.contains("email") {
        perms.push(Permission::EmailSend);
    }
    if action_lower.contains("db_query")
        || action_lower.contains("sql")
        || action_lower.contains("database")
    {
        perms.push(Permission::DatabaseAccess);
    }
    if action_lower.contains("shell")
        || action_lower.contains("bash")
        || action_lower.contains("cmd")
    {
        perms.push(Permission::ShellAccess);
    }
    if action_lower.contains("admin") || action_lower.contains("config") {
        perms.push(Permission::AdminAccess);
    }

    for tool in tools {
        let tl = tool.to_lowercase();
        if tl.contains("shell") || tl.contains("bash") {
            perms.push(Permission::ShellAccess);
        }
        if tl.contains("code_exec") || tl.contains("python") || tl.contains("node") {
            perms.push(Permission::CodeExecution);
        }
        if tl.contains("email") || tl.contains("smtp") {
            perms.push(Permission::EmailSend);
        }
        if tl.contains("sql") || tl.contains("db_") {
            perms.push(Permission::DatabaseAccess);
        }
        if tl.contains("http") || tl.contains("curl") || tl.contains("fetch") {
            perms.push(Permission::NetworkAccess);
        }
        if tl.contains("write") || tl.contains("create") {
            perms.push(Permission::Write);
        }
        if tl.contains("delete") || tl.contains("remove") {
            perms.push(Permission::FileDelete);
        }
    }

    perms.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
    perms.dedup();
    perms
}

pub struct PermissionEnforcer {
    config: PermissionEnforcerConfig,
}

impl PermissionEnforcer {
    pub fn new(config: &PermissionEnforcerConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn evaluate(
        &self,
        agent_type: &AgentType,
        action: &str,
        tools: &[String],
    ) -> PermissionResult {
        if !self.config.enabled {
            return PermissionResult {
                allowed: true,
                effective_permissions: vec![],
                denied_permissions: vec![],
                reason: "permission enforcer disabled".into(),
            };
        }

        let type_key = match agent_type {
            AgentType::Custom(s) => s.clone(),
            other => format!("{:?}", other).to_lowercase(),
        };

        let granted: Vec<Permission> =
            if let Some(overrides) = self.config.permission_overrides.get(&type_key) {
                overrides
                    .iter()
                    .filter_map(|p| parse_permission(p))
                    .collect()
            } else {
                type_permissions(agent_type)
            };

        let required = action_required_permissions(action, tools);
        let granted_set: std::collections::HashSet<_> = granted.iter().collect();
        let denied: Vec<String> = required
            .iter()
            .filter(|p| !granted_set.contains(p))
            .map(|p| format!("{:?}", p))
            .collect();

        let allowed = denied.is_empty();
        let reason = if allowed {
            "all required permissions granted".into()
        } else {
            format!("missing permissions: {}", denied.join(", "))
        };

        PermissionResult {
            allowed,
            effective_permissions: granted,
            denied_permissions: denied,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_enforcer() -> PermissionEnforcer {
        PermissionEnforcer::new(&PermissionEnforcerConfig::default())
    }

    #[test]
    fn coder_can_execute_code() {
        let e = default_enforcer();
        let r = e.evaluate(&AgentType::Coder, "execute_code", &[]);
        assert!(r.allowed);
    }

    #[test]
    fn assistant_cannot_execute_code() {
        let e = default_enforcer();
        let r = e.evaluate(&AgentType::Assistant, "execute_code", &[]);
        assert!(!r.allowed);
        assert!(r.denied_permissions.contains(&"CodeExecution".to_string()));
    }

    #[test]
    fn researcher_can_network_call() {
        let e = default_enforcer();
        let r = e.evaluate(&AgentType::Researcher, "network_call", &[]);
        assert!(r.allowed);
    }

    #[test]
    fn tool_permissions_checked() {
        let e = default_enforcer();
        let r = e.evaluate(&AgentType::Assistant, "action", &["shell_exec".into()]);
        assert!(!r.allowed);
        assert!(r.denied_permissions.contains(&"ShellAccess".to_string()));
    }

    #[test]
    fn disabled_allows_all() {
        let e = PermissionEnforcer::new(&PermissionEnforcerConfig {
            enabled: false,
            ..Default::default()
        });
        let r = e.evaluate(
            &AgentType::Assistant,
            "execute_code",
            &["shell_exec".to_string()],
        );
        assert!(r.allowed);
    }
}
