// Dynamic Policy Reload (Phase 7)
//
// Hot-reloads the PolicyEngine from a YAML policy file at runtime.
// Supports:
//   - File-based reload (load from policy_path in config)
//   - Admin API endpoint to trigger reload (POST /v1/policy/reload)
//   - Runtime policy swap without restart
//   - Policy versioning and change detection
//
// Thread Safety: RwLock-protected interior mutability.
// Architectural Guarantee: A reload failure never affects the current
// running policy — the old policy continues to serve requests.

use std::sync::RwLock;

use crate::keshav::policy_engine::{Policy, PolicyEngine};

/// Manages the runtime PolicyEngine with hot-reload capability.
pub struct PolicyManager {
    engine: RwLock<PolicyEngine>,
    policy_path: Option<String>,
    /// The currently loaded policy (for version tracking).
    current_policy: RwLock<Policy>,
}

impl PolicyManager {
    /// Create a new PolicyManager with the given initial policy.
    pub fn new(policy: Policy, policy_path: Option<String>) -> Self {
        let engine = PolicyEngine::new(policy.clone());
        Self {
            engine: RwLock::new(engine),
            policy_path,
            current_policy: RwLock::new(policy),
        }
    }

    /// Create with the default policy (v2.0.0).
    pub fn with_defaults() -> Self {
        Self::new(Policy::default(), None)
    }

    /// Evaluate all ring verdicts against the current policy.
    pub fn evaluate_all(
        &self,
        all: &crate::keshav::decide::AllRingVerdicts<'_>,
        risk: &crate::decision::RiskScore,
    ) -> Option<(crate::decision::Decision, Option<String>, String)> {
        let engine = self.engine.read().unwrap();
        engine.evaluate_all(all, risk)
    }

    /// Get a reference to the current policy version.
    pub fn policy_version(&self) -> String {
        let policy = self.current_policy.read().unwrap();
        policy.version.clone()
    }

    /// Get the number of rules in the current policy.
    pub fn rule_count(&self) -> usize {
        let policy = self.current_policy.read().unwrap();
        policy.rules.len()
    }

    /// Reload the policy from the configured file path.
    /// Returns Ok with the new version on success, Err on failure.
    /// On failure, the old policy continues to serve requests.
    pub fn reload_from_file(&self) -> Result<String, String> {
        let path = self
            .policy_path
            .as_ref()
            .ok_or_else(|| "no policy_path configured".to_string())?;

        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read policy file: {}", e))?;

        let policy: Policy = serde_yaml::from_str(&content)
            .map_err(|e| format!("failed to parse policy YAML: {}", e))?;

        self.swap_policy(policy)
    }

    /// Reload policy from a YAML string (for API-based reload).
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<String, String> {
        let policy: Policy = serde_yaml::from_str(yaml)
            .map_err(|e| format!("failed to parse policy YAML: {}", e))?;

        self.swap_policy(policy)
    }

    /// Swap in a new policy atomically.
    fn swap_policy(&self, policy: Policy) -> Result<String, String> {
        let new_version = policy.version.clone();

        // Validate the policy has at least one rule.
        if policy.rules.is_empty() {
            return Err("policy has zero rules — rejected".into());
        }

        let new_engine = PolicyEngine::new(policy.clone());

        // Atomic swap: write lock ensures no concurrent reads.
        {
            let mut engine = self.engine.write().unwrap();
            *engine = new_engine;
        }
        {
            let mut current = self.current_policy.write().unwrap();
            *current = policy;
        }

        tracing::info!(
            version = %new_version,
            rules = self.rule_count(),
            "policy reloaded successfully"
        );

        Ok(new_version)
    }

    /// Get the current policy as YAML.
    pub fn export_policy_yaml(&self) -> String {
        let policy = self.current_policy.read().unwrap();
        serde_yaml::to_string(&*policy).unwrap_or_else(|_| "export failed".into())
    }

    /// Get current policy info for API responses.
    pub fn policy_info(&self) -> PolicyInfo {
        let policy = self.current_policy.read().unwrap();
        PolicyInfo {
            version: policy.version.clone(),
            rule_count: policy.rules.len(),
            rules: policy.rules.iter().map(|r| r.name.clone()).collect(),
            policy_path: self.policy_path.clone(),
        }
    }
}

impl Clone for PolicyManager {
    fn clone(&self) -> Self {
        Self {
            engine: RwLock::new(self.engine.read().unwrap().clone_safe()),
            policy_path: self.policy_path.clone(),
            current_policy: RwLock::new(self.current_policy.read().unwrap().clone()),
        }
    }
}

impl PolicyEngine {
    /// Clone the engine (needed for PolicyManager Clone).
    fn clone_safe(&self) -> Self {
        Self::new(self.policy().clone())
    }
}

/// Policy information for API responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyInfo {
    pub version: String,
    pub rule_count: usize,
    pub rules: Vec<String>,
    pub policy_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Decision, RiskScore};
    use crate::shield::ShieldVerdict;

    fn shield_allow() -> crate::shield::ShieldVerdict {
        ShieldVerdict {
            decision: Decision::Allow,
            engine_results: vec![],
            latency_ms: 0.5,
        }
    }

    fn make_all_verdicts() -> crate::keshav::decide::AllRingVerdicts<'static> {
        static SHIELD: std::sync::OnceLock<crate::shield::ShieldVerdict> =
            std::sync::OnceLock::new();
        let shield = SHIELD.get_or_init(|| crate::shield::ShieldVerdict {
            decision: Decision::Allow,
            engine_results: vec![],
            latency_ms: 0.5,
        });
        crate::keshav::decide::AllRingVerdicts {
            shield,
            threat: None,
            identity: None,
            memory: None,
            agent: None,
            execution: None,
            reasoning: None,
            governance: None,
            recovery: None,
        }
    }

    #[test]
    fn default_policy_allows() {
        let pm = PolicyManager::with_defaults();
        let result = pm.evaluate_all(&make_all_verdicts(), &RiskScore::default());
        assert!(result.is_some());
        let (decision, name, _) = result.unwrap();
        assert!(decision.is_allow());
        assert_eq!(name.as_deref(), Some("allow_default"));
    }

    #[test]
    fn policy_version_tracked() {
        let pm = PolicyManager::with_defaults();
        assert_eq!(pm.policy_version(), "2.0.0");
        assert!(pm.rule_count() > 0);
    }

    #[test]
    fn reload_from_yaml_string() {
        let pm = PolicyManager::with_defaults();
        let yaml = r#"
version: "3.0.0-test"
rules:
  - name: always_allow
    condition: all_rings_allow
    action: allow
    reason: test policy
"#;
        let version = pm.reload_from_yaml(yaml).unwrap();
        assert_eq!(version, "3.0.0-test");
        assert_eq!(pm.policy_version(), "3.0.0-test");
        assert_eq!(pm.rule_count(), 1);
    }

    #[test]
    fn empty_policy_rejected() {
        let pm = PolicyManager::with_defaults();
        let yaml = r#"
version: "bad"
rules: []
"#;
        let result = pm.reload_from_yaml(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("zero rules"));
        // Old policy should still be active.
        assert_eq!(pm.policy_version(), "2.0.0");
    }

    #[test]
    fn reload_failure_preserves_old() {
        let pm = PolicyManager::with_defaults();
        let bad_yaml = "not valid yaml {{";
        let result = pm.reload_from_yaml(bad_yaml);
        assert!(result.is_err());
        assert_eq!(pm.policy_version(), "2.0.0");
    }

    #[test]
    fn export_policy_yaml() {
        let pm = PolicyManager::with_defaults();
        let yaml = pm.export_policy_yaml();
        assert!(yaml.contains("version:"));
        assert!(yaml.contains("2.0.0"));
    }

    #[test]
    fn policy_info() {
        let pm = PolicyManager::with_defaults();
        let info = pm.policy_info();
        assert_eq!(info.version, "2.0.0");
        assert!(info.rule_count > 0);
        assert!(info.rules.contains(&"allow_default".to_string()));
    }

    #[test]
    fn reload_from_file_nonexistent() {
        let pm = PolicyManager::new(Policy::default(), Some("/nonexistent/path.yaml".into()));
        let result = pm.reload_from_file();
        assert!(result.is_err());
    }

    #[test]
    fn clone_preserves_state() {
        let pm = PolicyManager::with_defaults();
        let cloned = pm.clone();
        assert_eq!(cloned.policy_version(), pm.policy_version());
    }
}
