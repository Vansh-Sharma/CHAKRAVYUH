// MemoryAccessControl — role-based memory operation permissions.
//
// Enforces: admin=full, operator=read+write, user=read, service=read+write, anonymous=none.

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MemoryAccessControlConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool { true }

impl Default for MemoryAccessControlConfig {
    fn default() -> Self { Self { enabled: default_enabled() } }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessVerdict {
    pub role: String,
    pub allowed_actions: Vec<AccessControlAction>,
    pub denied: bool,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub enum AccessControlAction {
    Read,
    Write,
    Delete,
    Admin,
}

/// Permission sets per role.
fn role_permissions(role: &str) -> Vec<AccessControlAction> {
    match role.to_lowercase().as_str() {
        "admin" => vec![AccessControlAction::Read, AccessControlAction::Write, AccessControlAction::Delete, AccessControlAction::Admin],
        "operator" | "service" => vec![AccessControlAction::Read, AccessControlAction::Write],
        "auditor" => vec![AccessControlAction::Read],
        "user" => vec![AccessControlAction::Read],
        _ => vec![],  // anonymous — no access
    }
}

pub struct MemoryAccessControl {
    config: MemoryAccessControlConfig,
}

impl MemoryAccessControl {
    pub fn new(config: &MemoryAccessControlConfig) -> Self {
        Self { config: config.clone() }
    }

    pub fn evaluate(&self, role: &str, entry_count: usize) -> AccessVerdict {
        if !self.config.enabled {
            return AccessVerdict { role: role.into(), allowed_actions: vec![AccessControlAction::Read, AccessControlAction::Write, AccessControlAction::Delete, AccessControlAction::Admin], denied: false, reason: "memory access control disabled".into() };
        }

        let allowed = role_permissions(role);
        let denied = allowed.is_empty() && entry_count > 0;

        let reason = if denied {
            format!("role '{}' has no memory access permissions", role)
        } else {
            format!("role '{}' has {} permissions: {:?}", role, allowed.len(), allowed)
        };

        AccessVerdict { role: role.into(), allowed_actions: allowed, denied, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_full_access() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("admin", 5);
        assert!(!v.denied);
        assert_eq!(v.allowed_actions.len(), 4);
    }

    #[test]
    fn user_read_only() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("user", 5);
        assert!(!v.denied);
        assert!(v.allowed_actions.contains(&AccessControlAction::Read));
        assert!(!v.allowed_actions.contains(&AccessControlAction::Write));
    }

    #[test]
    fn anonymous_denied() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("anonymous", 5);
        assert!(v.denied);
        assert!(v.allowed_actions.is_empty());
    }

    #[test]
    fn unknown_role_denied() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("hacker", 3);
        assert!(v.denied);
    }

    #[test]
    fn no_entries_allowed() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("anonymous", 0);
        assert!(!v.denied); // No entries = nothing to deny
    }

    #[test]
    fn service_write_access() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig::default());
        let v = ac.evaluate("service", 3);
        assert!(!v.denied);
        assert!(v.allowed_actions.contains(&AccessControlAction::Write));
    }

    #[test]
    fn disabled_allows_all() {
        let ac = MemoryAccessControl::new(&MemoryAccessControlConfig { enabled: false });
        let v = ac.evaluate("anonymous", 10);
        assert!(!v.denied);
    }
}
