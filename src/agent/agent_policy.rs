// AgentPolicy — defines what an agent CAN and CANNOT do per agent type.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AgentType {
    Coder,
    Researcher,
    Assistant,
    Analyst,
    Custom(String),
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AgentPolicyConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Custom agent policies: agent_type -> list of allowed capabilities.
    #[serde(default)]
    pub custom_policies: HashMap<String, Vec<String>>,
}

fn default_enabled() -> bool {
    true
}

impl Default for AgentPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            custom_policies: HashMap::new(),
        }
    }
}

pub struct AgentPolicyResult {
    pub allowed: bool,
    pub reason: String,
    pub risk_score: f64,
}

pub struct AgentPolicy {
    config: AgentPolicyConfig,
    known_agents: Mutex<HashMap<String, u64>>,
}

impl AgentPolicy {
    pub fn new(config: &AgentPolicyConfig) -> Self {
        Self {
            config: config.clone(),
            known_agents: Mutex::new(HashMap::new()),
        }
    }

    pub fn evaluate(&self, agent_type: &AgentType, agent_id: &str) -> AgentPolicyResult {
        if !self.config.enabled {
            return AgentPolicyResult {
                allowed: true,
                reason: "agent policy disabled".into(),
                risk_score: 0.0,
            };
        }

        // Check if agent is known.
        let is_known = {
            let mut agents = self.known_agents.lock().unwrap();
            let count = agents.entry(agent_id.to_string()).or_insert(0);
            *count += 1;
            *count > 1
        };

        // Custom policies override defaults.
        let type_key = match agent_type {
            AgentType::Custom(s) => s.clone(),
            other => format!("{:?}", other).to_lowercase(),
        };
        if let Some(policy) = self.config.custom_policies.get(&type_key) {
            if policy.is_empty() {
                return AgentPolicyResult {
                    allowed: false,
                    reason: format!("agent type {:?} has no allowed capabilities", agent_type),
                    risk_score: 5.0,
                };
            }
            return AgentPolicyResult {
                allowed: true,
                reason: format!("{:?} policy: {} capabilities", agent_type, policy.len()),
                risk_score: 0.0,
            };
        }

        // Default policies per type — all known types are allowed.
        if !is_known {
            return AgentPolicyResult {
                allowed: true,
                reason: format!("first encounter with agent {:?}, monitoring", agent_type),
                risk_score: 1.0,
            };
        }

        AgentPolicyResult {
            allowed: true,
            reason: format!("{:?} agent within policy", agent_type),
            risk_score: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> AgentPolicy {
        AgentPolicy::new(&AgentPolicyConfig::default())
    }

    #[test]
    fn known_agent_allowed() {
        let p = default_policy();
        let r = p.evaluate(&AgentType::Coder, "agent-1");
        assert!(r.allowed);
    }

    #[test]
    fn unknown_agent_mild_risk() {
        let p = default_policy();
        let r = p.evaluate(&AgentType::Coder, "brand-new-agent");
        assert!(r.allowed);
        assert!(r.risk_score > 0.0);
    }

    #[test]
    fn second_seen_normal() {
        let p = default_policy();
        p.evaluate(&AgentType::Coder, "agent-x");
        let r = p.evaluate(&AgentType::Coder, "agent-x");
        assert_eq!(r.risk_score, 0.0);
    }

    #[test]
    fn custom_empty_policy_denied() {
        let mut cfg = AgentPolicyConfig::default();
        cfg.custom_policies.insert("restricted".into(), vec![]);
        let p = AgentPolicy::new(&cfg);
        let r = p.evaluate(&AgentType::Custom("restricted".into()), "agent-1");
        assert!(!r.allowed);
    }

    #[test]
    fn disabled_allows_all() {
        let p = AgentPolicy::new(&AgentPolicyConfig {
            enabled: false,
            ..Default::default()
        });
        let r = p.evaluate(&AgentType::Custom("anything".into()), "x");
        assert!(r.allowed);
    }
}
