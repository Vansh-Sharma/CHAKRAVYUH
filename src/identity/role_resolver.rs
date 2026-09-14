// RoleResolver Engine — RBAC/ABAC Role Mapping
//
// Maps identity profiles to roles and permission sets.
// Supports both Role-Based Access Control (RBAC) and
// Attribute-Based Access Control (ABAC) via policy rules.
//
// Role hierarchy (default):
//   admin     → full access to all resources
//   operator  → read + write, no system config
//   auditor   → read-only, access to logs/decisions
//   user      → standard API access
//   service   → machine-to-machine, limited endpoints
//   anonymous → public endpoints only
//
// Permissions can be extended via config rules.
//
// Latency Budget: <0.05ms per evaluation

use crate::identity::session_identity::{IdentityProfile, IdentityType};

/// Supported roles in the CHAKRAVYUH access model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full system access — all endpoints, all operations.
    Admin,
    /// Read + write, no system configuration changes.
    Operator,
    /// Read-only with access to logs, decisions, and audit trails.
    Auditor,
    /// Standard API user — chat completions, basic endpoints.
    User,
    /// Machine-to-machine service account with limited endpoint access.
    Service,
    /// Unauthenticated — public endpoints only.
    Anonymous,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Operator => write!(f, "operator"),
            Self::Auditor => write!(f, "auditor"),
            Self::User => write!(f, "user"),
            Self::Service => write!(f, "service"),
            Self::Anonymous => write!(f, "anonymous"),
        }
    }
}

impl Role {
    /// The numeric privilege level (higher = more privilege).
    pub fn level(&self) -> u8 {
        match self {
            Self::Admin => 100,
            Self::Operator => 80,
            Self::Auditor => 60,
            Self::User => 40,
            Self::Service => 30,
            Self::Anonymous => 10,
        }
    }
}

/// A permission that can be granted to a role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    /// Read access to resources.
    Read,
    /// Write/create access.
    Write,
    /// Delete access.
    Delete,
    /// Execute tool calls / API operations.
    Execute,
    /// Access to system configuration.
    Configure,
    /// Access to decision logs and audit trails.
    Audit,
    /// Access to /health and /version endpoints.
    Health,
    /// Use /v1/chat/completions (standard LLM access).
    Chat,
    /// Use /v1/evaluate.
    Evaluate,
    /// Use /v1/proxy.
    Proxy,
    /// Admin operations (user management, policy changes).
    AdminOps,
}

/// RoleResolver engine configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RoleResolverConfig {
    /// Whether this engine is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Custom role mappings: identity claim → role.
    /// Format: "role:admin" or "scope:admin" → Role::Admin
    #[serde(default)]
    pub claim_to_role: std::collections::HashMap<String, String>,

    /// API key → role mapping (key prefix → role).
    /// Example: "sk-admin-" → "admin"
    #[serde(default)]
    pub api_key_prefix_roles: std::collections::HashMap<String, String>,

    /// Role permission overrides.
    /// Format: role_name → [permission, ...]
    #[serde(default)]
    pub role_permissions: std::collections::HashMap<String, Vec<String>>,
}

fn default_enabled() -> bool {
    true
}

impl Default for RoleResolverConfig {
    fn default() -> Self {
        let mut claim_to_role = std::collections::HashMap::new();
        claim_to_role.insert("role:admin".into(), "admin".into());
        claim_to_role.insert("role:operator".into(), "operator".into());
        claim_to_role.insert("role:auditor".into(), "auditor".into());

        let mut api_key_prefix_roles = std::collections::HashMap::new();
        api_key_prefix_roles.insert("sk-admin-".into(), "admin".into());
        api_key_prefix_roles.insert("sk-op-".into(), "operator".into());
        api_key_prefix_roles.insert("sk-audit-".into(), "auditor".into());
        api_key_prefix_roles.insert("sk-svc-".into(), "service".into());

        Self {
            enabled: default_enabled(),
            claim_to_role,
            api_key_prefix_roles,
            role_permissions: std::collections::HashMap::new(),
        }
    }
}

/// Result of role resolution.
#[derive(Debug, Clone)]
pub struct RoleResult {
    /// The resolved role.
    pub role: Role,
    /// The set of permissions granted to this role.
    pub permissions: std::collections::HashSet<Permission>,
    /// How the role was determined.
    pub resolution_method: String,
    /// Whether the role resolution was successful.
    pub valid: bool,
    pub reason: String,
}

/// The RoleResolver engine.
///
/// Determines the role and permission set for each identity.
/// Resolution priority:
///   1. JWT claims (role:xxx, scope:admin)
///   2. API key prefix mapping
///   3. Identity type defaults
pub struct RoleResolver {
    config: RoleResolverConfig,
    /// Default permissions per role (hardcoded baseline).
    default_permissions: std::collections::HashMap<Role, Vec<Permission>>,
}

impl RoleResolver {
    pub fn new(config: &RoleResolverConfig) -> Self {
        let mut default_permissions = std::collections::HashMap::new();
        default_permissions.insert(
            Role::Admin,
            vec![
                Permission::Read,
                Permission::Write,
                Permission::Delete,
                Permission::Execute,
                Permission::Configure,
                Permission::Audit,
                Permission::Health,
                Permission::Chat,
                Permission::Evaluate,
                Permission::Proxy,
                Permission::AdminOps,
            ],
        );
        default_permissions.insert(
            Role::Operator,
            vec![
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Audit,
                Permission::Health,
                Permission::Chat,
                Permission::Evaluate,
                Permission::Proxy,
            ],
        );
        default_permissions.insert(
            Role::Auditor,
            vec![
                Permission::Read,
                Permission::Audit,
                Permission::Health,
                Permission::Evaluate,
            ],
        );
        default_permissions.insert(
            Role::User,
            vec![
                Permission::Read,
                Permission::Execute,
                Permission::Health,
                Permission::Chat,
                Permission::Evaluate,
                Permission::Proxy,
            ],
        );
        default_permissions.insert(
            Role::Service,
            vec![
                Permission::Read,
                Permission::Execute,
                Permission::Health,
                Permission::Chat,
            ],
        );
        default_permissions.insert(Role::Anonymous, vec![Permission::Health]);

        Self {
            config: config.clone(),
            default_permissions,
        }
    }

    /// Resolve the role and permissions for an identity profile.
    pub fn evaluate(&self, profile: &IdentityProfile) -> RoleResult {
        if !self.config.enabled {
            return RoleResult {
                role: Role::Anonymous,
                permissions: self.permissions_for(&Role::Anonymous),
                resolution_method: "disabled".into(),
                valid: true,
                reason: "role_resolver engine disabled".into(),
            };
        }

        // Priority 1: Check JWT claims for explicit role.
        if profile.identity_type == IdentityType::Jwt {
            for claim in &profile.claims {
                if let Some(role) = self.config.claim_to_role.get(claim) {
                    if let Some(r) = Self::parse_role(role) {
                        return RoleResult {
                            role: r.clone(),
                            permissions: self.permissions_for(&r),
                            resolution_method: format!("jwt_claim:{}", claim),
                            valid: true,
                            reason: format!("role '{}' from JWT claim '{}'", role, claim),
                        };
                    }
                }
            }
        }

        // Priority 2: Check API key prefix mapping.
        if profile.identity_type == IdentityType::ApiKey {
            for (prefix, role_name) in &self.config.api_key_prefix_roles {
                if profile.credential_ref.starts_with(prefix) {
                    if let Some(r) = Self::parse_role(role_name) {
                        return RoleResult {
                            role: r.clone(),
                            permissions: self.permissions_for(&r),
                            resolution_method: format!("api_key_prefix:{}", prefix),
                            valid: true,
                            reason: format!(
                                "role '{}' from API key prefix '{}'",
                                role_name, prefix
                            ),
                        };
                    }
                }
            }
        }

        // Priority 3: Default by identity type.
        let role = match profile.identity_type {
            IdentityType::Internal => Role::Admin,
            IdentityType::Mtls => Role::Operator,
            IdentityType::Jwt => Role::User,
            IdentityType::Session => Role::User,
            IdentityType::ApiKey => Role::User,
            IdentityType::Anonymous => Role::Anonymous,
        };

        RoleResult {
            role: role.clone(),
            permissions: self.permissions_for(&role),
            resolution_method: format!("identity_type_default:{}", profile.identity_type),
            valid: true,
            reason: format!(
                "role '{}' from identity type '{}'",
                role, profile.identity_type
            ),
        }
    }

    /// Get the permission set for a role (default + config overrides).
    fn permissions_for(&self, role: &Role) -> std::collections::HashSet<Permission> {
        let mut perms: std::collections::HashSet<Permission> = self
            .default_permissions
            .get(role)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Apply config overrides.
        if let Some(override_perms) = self.config.role_permissions.get(&role.to_string()) {
            for p_str in override_perms {
                if let Some(p) = Self::parse_permission(p_str) {
                    perms.insert(p);
                }
            }
        }

        perms
    }

    fn parse_role(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "auditor" => Some(Role::Auditor),
            "user" => Some(Role::User),
            "service" => Some(Role::Service),
            "anonymous" => Some(Role::Anonymous),
            _ => None,
        }
    }

    fn parse_permission(s: &str) -> Option<Permission> {
        match s {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "delete" => Some(Permission::Delete),
            "execute" => Some(Permission::Execute),
            "configure" => Some(Permission::Configure),
            "audit" => Some(Permission::Audit),
            "health" => Some(Permission::Health),
            "chat" => Some(Permission::Chat),
            "evaluate" => Some(Permission::Evaluate),
            "proxy" => Some(Permission::Proxy),
            "admin_ops" => Some(Permission::AdminOps),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::session_identity::IdentityType;

    fn default_engine() -> RoleResolver {
        RoleResolver::new(&RoleResolverConfig::default())
    }

    fn anon_profile() -> IdentityProfile {
        IdentityProfile::default()
    }

    fn api_key_profile(key: &str) -> IdentityProfile {
        IdentityProfile {
            identity_type: IdentityType::ApiKey,
            principal_id: format!("key:{}", key),
            credential_ref: key.to_string(),
            trust_base: 0.5,
            claims: vec![],
            format_valid: true,
        }
    }

    fn jwt_profile(claims: Vec<String>) -> IdentityProfile {
        IdentityProfile {
            identity_type: IdentityType::Jwt,
            principal_id: "jwt:user-42".into(),
            credential_ref: "token".into(),
            trust_base: 0.7,
            claims,
            format_valid: true,
        }
    }

    #[test]
    fn anonymous_gets_anonymous_role() {
        let engine = default_engine();
        let result = engine.evaluate(&anon_profile());
        assert_eq!(result.role, Role::Anonymous);
        assert!(result.permissions.contains(&Permission::Health));
        assert!(!result.permissions.contains(&Permission::Chat));
    }

    #[test]
    fn api_key_gets_user_role() {
        let engine = default_engine();
        let result = engine.evaluate(&api_key_profile("sk-regular-key-1234567890"));
        assert_eq!(result.role, Role::User);
        assert!(result.permissions.contains(&Permission::Chat));
        assert!(result.permissions.contains(&Permission::Execute));
    }

    #[test]
    fn api_key_admin_prefix() {
        let engine = default_engine();
        let result = engine.evaluate(&api_key_profile("sk-admin-supersecretkey12345"));
        assert_eq!(result.role, Role::Admin);
        assert!(result.permissions.contains(&Permission::Configure));
        assert!(result.permissions.contains(&Permission::AdminOps));
    }

    #[test]
    fn api_key_service_prefix() {
        let engine = default_engine();
        let result = engine.evaluate(&api_key_profile("sk-svc-backend-service-key"));
        assert_eq!(result.role, Role::Service);
        assert!(!result.permissions.contains(&Permission::Evaluate));
    }

    #[test]
    fn jwt_with_admin_claim() {
        let engine = default_engine();
        let result = engine.evaluate(&jwt_profile(vec!["role:admin".into()]));
        assert_eq!(result.role, Role::Admin);
        assert_eq!(result.resolution_method, "jwt_claim:role:admin");
    }

    #[test]
    fn jwt_with_auditor_claim() {
        let engine = default_engine();
        let result = engine.evaluate(&jwt_profile(vec!["role:auditor".into()]));
        assert_eq!(result.role, Role::Auditor);
        assert!(result.permissions.contains(&Permission::Audit));
        assert!(!result.permissions.contains(&Permission::Write));
    }

    #[test]
    fn jwt_without_role_claim_falls_to_default() {
        let engine = default_engine();
        let result = engine.evaluate(&jwt_profile(vec!["sub:user-42".into()]));
        assert_eq!(result.role, Role::User);
    }

    #[test]
    fn internal_identity_gets_admin() {
        let engine = default_engine();
        let profile = IdentityProfile {
            identity_type: IdentityType::Internal,
            principal_id: "keshav".into(),
            credential_ref: "keshav".into(),
            trust_base: 1.0,
            claims: vec!["internal".into()],
            format_valid: true,
        };
        let result = engine.evaluate(&profile);
        assert_eq!(result.role, Role::Admin);
    }

    #[test]
    fn mtls_gets_operator() {
        let engine = default_engine();
        let profile = IdentityProfile {
            identity_type: IdentityType::Mtls,
            principal_id: "cert:abc123".into(),
            credential_ref: "fingerprint".into(),
            trust_base: 0.9,
            claims: vec!["mtls".into()],
            format_valid: true,
        };
        let result = engine.evaluate(&profile);
        assert_eq!(result.role, Role::Operator);
    }

    #[test]
    fn disabled_engine_returns_anonymous() {
        let engine = RoleResolver::new(&RoleResolverConfig {
            enabled: false,
            ..Default::default()
        });
        let profile = api_key_profile("sk-admin-key12345678901234");
        let result = engine.evaluate(&profile);
        assert_eq!(result.role, Role::Anonymous);
    }

    #[test]
    fn admin_has_all_permissions() {
        let engine = default_engine();
        let result = engine.evaluate(&jwt_profile(vec!["role:admin".into()]));
        assert_eq!(result.permissions.len(), 11);
    }

    #[test]
    fn role_levels_order() {
        assert!(Role::Admin.level() > Role::Operator.level());
        assert!(Role::Operator.level() > Role::Auditor.level());
        assert!(Role::Auditor.level() > Role::User.level());
        assert!(Role::User.level() > Role::Service.level());
        assert!(Role::Service.level() > Role::Anonymous.level());
    }
}
