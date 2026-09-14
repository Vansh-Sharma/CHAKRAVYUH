// ToolChainingDetector — detects potentially dangerous tool sequences.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainPattern {
    pub name: String,
    pub sequence: Vec<String>,
    pub risk_weight: f64,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainRisk {
    pub risk_score: f64,
    pub chains_detected: Vec<String>,
    pub matched_patterns: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ToolChainingDetectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_patterns_enabled")]
    pub default_patterns_enabled: bool,
    #[serde(default)]
    pub custom_patterns: Vec<ChainPattern>,
}

fn default_enabled() -> bool { true }
fn default_patterns_enabled() -> bool { true }

impl Default for ToolChainingDetectorConfig {
    fn default() -> Self { Self { enabled: default_enabled(), default_patterns_enabled: default_patterns_enabled(), custom_patterns: vec![] } }
}

fn default_dangerous_chains() -> Vec<ChainPattern> {
    vec![
        ChainPattern { name: "Data Exfiltration".into(), sequence: vec!["file_read".into(), "email_send".into()], risk_weight: 8.0, description: "Reading files then emailing them — potential data exfiltration".into() },
        ChainPattern { name: "C2 Communication".into(), sequence: vec!["code_exec".into(), "network_call".into()], risk_weight: 9.0, description: "Executing code then making network calls — potential C2".into() },
        ChainPattern { name: "Database Theft".into(), sequence: vec!["db_dump".into(), "external_transmit".into()], risk_weight: 9.0, description: "Dumping database then transmitting externally".into() },
        ChainPattern { name: "Memory Exfiltration".into(), sequence: vec!["memory_read".into(), "api_call".into()], risk_weight: 7.0, description: "Reading memory then making API calls — data exfiltration".into() },
        ChainPattern { name: "Persistence Install".into(), sequence: vec!["file_write".into(), "execute".into()], risk_weight: 7.0, description: "Writing then executing — persistence".into() },
        ChainPattern { name: "Reverse Shell".into(), sequence: vec!["shell_access".into(), "network_call".into()], risk_weight: 9.0, description: "Shell access then network — reverse shell".into() },
    ]
}

/// Normalize tool names for pattern matching.
fn normalize_tool(tool: &str) -> String {
    let t = tool.to_lowercase();
    if t.contains("file_read") || t.contains("read_file") { return "file_read".into(); }
    if t.contains("email_send") || t.contains("send_email") { return "email_send".into(); }
    if t.contains("code_exec") || t.contains("execute_code") { return "code_exec".into(); }
    if t.contains("network_call") || t.contains("http_request") || t.contains("fetch") { return "network_call".into(); }
    if t.contains("db_dump") || t.contains("sql_dump") { return "db_dump".into(); }
    if t.contains("external_transmit") || t.contains("upload") { return "external_transmit".into(); }
    if t.contains("memory_read") || t.contains("rag_query") { return "memory_read".into(); }
    if t.contains("api_call") || t.contains("rest") { return "api_call".into(); }
    if t.contains("file_write") || t.contains("create_file") || t.contains("save") { return "file_write".into(); }
    if t.contains("execute") || t.contains("run") { return "execute".into(); }
    if t.contains("shell_access") || t.contains("bash") || t.contains("cmd") { return "shell_access".into(); }
    t
}

/// Check if pattern sequence is a subsequence of the tools list.
fn is_subsequence(pattern: &[String], tools: &[String]) -> bool {
    let mut pat_idx = 0;
    for tool in tools {
        if pat_idx < pattern.len() && tool == &pattern[pat_idx] {
            pat_idx += 1;
        }
    }
    pat_idx == pattern.len()
}

pub struct ToolChainingDetector {
    config: ToolChainingDetectorConfig,
    patterns: Vec<ChainPattern>,
}

impl ToolChainingDetector {
    pub fn new(config: &ToolChainingDetectorConfig) -> Self {
        let mut patterns = Vec::new();
        if config.default_patterns_enabled {
            patterns.extend(default_dangerous_chains());
        }
        patterns.extend(config.custom_patterns.clone());
        Self { config: config.clone(), patterns }
    }

    pub fn evaluate(&self, tools: &[String]) -> ChainRisk {
        if !self.config.enabled {
            return ChainRisk { risk_score: 0.0, chains_detected: vec![], matched_patterns: vec![], summary: "tool chaining detector disabled".into() };
        }

        if tools.len() < 2 {
            return ChainRisk { risk_score: 0.0, chains_detected: vec![], matched_patterns: vec![], summary: "insufficient tools for chain analysis".into() };
        }

        let normalized: Vec<String> = tools.iter().map(|t| normalize_tool(t)).collect();
        let mut chains_detected = Vec::new();
        let mut matched_patterns = Vec::new();
        let mut max_risk = 0.0f64;

        for pattern in &self.patterns {
            if is_subsequence(&pattern.sequence, &normalized) {
                chains_detected.push(pattern.name.clone());
                matched_patterns.push(format!("{} ({:.0} risk)", pattern.name, pattern.risk_weight));
                max_risk = max_risk.max(pattern.risk_weight);
            }
        }

        let risk_score = max_risk.clamp(0.0, 10.0);
        let summary = if chains_detected.is_empty() {
            "no dangerous tool chains detected".into()
        } else {
            format!("dangerous chains: {} (max risk: {:.0})", chains_detected.join(", "), max_risk)
        };

        ChainRisk { risk_score, chains_detected, matched_patterns, summary }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_detector() -> ToolChainingDetector { ToolChainingDetector::new(&ToolChainingDetectorConfig::default()) }

    #[test]
    fn safe_tools_no_risk() {
        let d = default_detector();
        let r = d.evaluate(&["file_read".into(), "code_execution".into()]);
        assert_eq!(r.risk_score, 0.0);
    }

    #[test]
    fn data_exfiltration_detected() {
        let d = default_detector();
        let r = d.evaluate(&["file_read".into(), "email_send".into()]);
        assert!(r.risk_score > 5.0);
        assert!(r.chains_detected.contains(&"Data Exfiltration".to_string()));
    }

    #[test]
    fn reverse_shell_detected() {
        let d = default_detector();
        let r = d.evaluate(&["shell_access".into(), "network_call".into()]);
        assert!(r.risk_score > 5.0);
    }

    #[test]
    fn partial_chain_in_longer_sequence() {
        let d = default_detector();
        let r = d.evaluate(&["file_read".into(), "some_tool".into(), "email_send".into()]);
        assert!(r.risk_score > 0.0); // Subsequence match should still work
    }

    #[test]
    fn single_tool_no_chain() {
        let d = default_detector();
        let r = d.evaluate(&["shell_access".into()]);
        assert_eq!(r.risk_score, 0.0);
    }

    #[test]
    fn disabled_no_detection() {
        let d = ToolChainingDetector::new(&ToolChainingDetectorConfig { enabled: false, ..Default::default() });
        let r = d.evaluate(&["shell_access".into(), "network_call".into()]);
        assert_eq!(r.risk_score, 0.0);
    }
}
