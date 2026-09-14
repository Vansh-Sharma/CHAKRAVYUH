// BehaviorMonitor — tracks agent behavior over time, detects anomalies.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BehaviorMonitorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
    /// Risk threshold for anomaly (default: 3.0).
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Action count for baseline (default: 10).
    #[serde(default = "default_baseline_actions")]
    pub baseline_actions: u32,
}

fn default_enabled() -> bool { true }
fn default_max_agents() -> usize { 5_000 }
fn default_anomaly_threshold() -> f64 { 3.0 }
fn default_baseline_actions() -> u32 { 10 }

impl Default for BehaviorMonitorConfig {
    fn default() -> Self {
        Self { enabled: default_enabled(), max_agents: default_max_agents(), anomaly_threshold: default_anomaly_threshold(), baseline_actions: default_baseline_actions() }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BehaviorAnalysis {
    pub risk_score: f64,
    pub action_count: u32,
    pub tool_frequency: HashMap<String, u32>,
    pub summary: String,
    pub anomaly_detected: bool,
}

#[derive(Debug, Clone)]
struct AgentBehavior {
    action_count: u32,
    tool_usage: HashMap<String, u32>,
    unique_tools: std::collections::HashSet<String>,
    last_action: std::time::Instant,
}

pub struct BehaviorMonitor {
    config: BehaviorMonitorConfig,
    state: Mutex<HashMap<String, AgentBehavior>>,
}

impl BehaviorMonitor {
    pub fn new(config: &BehaviorMonitorConfig) -> Self {
        Self { config: config.clone(), state: Mutex::new(HashMap::new()) }
    }

    pub fn evaluate(&self, agent_id: &str, _action: &str, tools: &[String], _source_ip: &str) -> BehaviorAnalysis {
        if !self.config.enabled {
            return BehaviorAnalysis { risk_score: 0.0, action_count: 0, tool_frequency: HashMap::new(), summary: "behavior monitor disabled".into(), anomaly_detected: false };
        }

        let mut state = self.state.lock().unwrap();

        // Evict if over limit.
        if state.len() >= self.config.max_agents && !state.contains_key(agent_id) {
            let oldest = state.keys().next().cloned();
            if let Some(k) = oldest { state.remove(&k); }
        }

        let behavior = state.entry(agent_id.to_string()).or_insert_with(|| AgentBehavior {
            action_count: 0, tool_usage: HashMap::new(), unique_tools: std::collections::HashSet::new(),
            last_action: std::time::Instant::now(),
        });

        behavior.action_count += 1;
        for tool in tools {
            *behavior.tool_usage.entry(tool.clone()).or_insert(0) += 1;
            behavior.unique_tools.insert(tool.clone());
        }
        behavior.last_action = std::time::Instant::now();

        let action_count = behavior.action_count;
        let mut risk_score = 0.0f64;

        // Check for excessive action rate.
        if action_count > self.config.baseline_actions {
            let ratio = action_count as f64 / self.config.baseline_actions as f64;
            if ratio > self.config.anomaly_threshold {
                risk_score += (ratio - self.config.anomaly_threshold) * 2.0;
            }
        }

        // Check for tool diversity (too many unique tools = suspicious).
        if behavior.unique_tools.len() > 8 {
            risk_score += (behavior.unique_tools.len() - 8) as f64 * 0.3;
        }

        // Check for single-tool obsession (one tool > 80% of usage).
        let total_tool_uses: u32 = behavior.tool_usage.values().sum();
        if total_tool_uses > 5 {
            for (_tool, count) in &behavior.tool_usage {
                if *count as f64 / total_tool_uses as f64 > 0.8 && *count > 10 {
                    risk_score += 2.0;
                }
            }
        }

        let anomaly_detected = risk_score > self.config.anomaly_threshold;
        let summary = if anomaly_detected {
            format!("anomalous behavior: {} actions, {} unique tools (risk={:.1})", action_count, behavior.unique_tools.len(), risk_score)
        } else {
            format!("normal behavior: {} actions, {} unique tools", action_count, behavior.unique_tools.len())
        };

        let tool_frequency = behavior.tool_usage.clone();
        BehaviorAnalysis { risk_score: risk_score.clamp(0.0, 10.0), action_count, tool_frequency, summary, anomaly_detected }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_monitor() -> BehaviorMonitor { BehaviorMonitor::new(&BehaviorMonitorConfig::default()) }

    fn make_tools(names: &[&str]) -> Vec<String> { names.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn normal_behavior_low_risk() {
        let m = default_monitor();
        let a = m.evaluate("agent-1", "read_file", &make_tools(&["file_read"]), "1.2.3.4");
        assert!(a.risk_score < 1.0);
    }

    #[test]
    fn excessive_actions_detected() {
        let m = default_monitor();
        for _ in 0..50 {
            m.evaluate("agent-x", "action", &make_tools(&["tool"]), "1.2.3.4");
        }
        let a = m.evaluate("agent-x", "action", &make_tools(&["tool"]), "1.2.3.4");
        assert!(a.anomaly_detected);
        assert!(a.action_count > 50);
    }

    #[test]
    fn too_many_unique_tools() {
        let m = default_monitor();
        let many_tools: Vec<String> = (0..15).map(|i| format!("tool_{}", i)).collect();
        m.evaluate("agent-y", "action", &many_tools, "1.2.3.4");
        let a = m.evaluate("agent-y", "action", &many_tools, "1.2.3.4");
        assert!(a.risk_score > 0.0);
    }

    #[test]
    fn single_tool_obsession() {
        let m = default_monitor();
        for _ in 0..20 {
            m.evaluate("agent-z", "action", &make_tools(&["shell_exec"]), "1.2.3.4");
        }
        let a = m.evaluate("agent-z", "action", &make_tools(&["shell_exec"]), "1.2.3.4");
        assert!(a.risk_score > 1.0);
    }

    #[test]
    fn disabled_no_tracking() {
        let m = BehaviorMonitor::new(&BehaviorMonitorConfig { enabled: false, ..Default::default() });
        let a = m.evaluate("agent-1", "action", &[], "1.2.3.4");
        assert_eq!(a.risk_score, 0.0);
    }
}
