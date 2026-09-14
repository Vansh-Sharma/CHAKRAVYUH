// Action Logger — Engine 5 of the Execution Ring
//
// Full audit trail of every tool call.
// Append-only log (WAL pattern). Tamper-evident via hash chaining.
// Exportable in JSON and CSV formats.
//
// Latency Budget: <1ms p99 (write to log)

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Configuration for the Action Logger engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLoggerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Maximum number of entries to keep in memory (default: 10000).
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Whether to include full parameters in the log.
    #[serde(default = "default_true")]
    pub log_full_params: bool,
}

fn default_enabled() -> bool {
    true
}
fn default_max_entries() -> usize {
    10_000
}
fn default_true() -> bool {
    true
}

impl Default for ActionLoggerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_entries: default_max_entries(),
            log_full_params: default_true(),
        }
    }
}

/// A single action log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {
    pub log_id: u64,
    pub timestamp: String, // ISO 8601
    pub request_id: String,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub decision: String, // "allowed", "blocked", "sandboxed", "approval_required"
    pub sandbox_mode: Option<String>,
    pub approval_request: Option<String>,
    pub approver: Option<String>,
    pub source_ip: String,
    pub latency_ms: f64,
    /// SHA-256 hash of this entry + previous entry's hash (tamper-evident chain).
    pub chain_hash: String,
}

/// The Action Logger engine.
///
/// Records every tool call as an append-only audit trail.
/// Uses hash chaining for tamper evidence.
pub struct ActionLogger {
    config: ActionLoggerConfig,
    entries: Arc<Mutex<Vec<ActionLogEntry>>>,
    /// Running hash of the chain (SHA-256).
    prev_hash: Arc<Mutex<String>>,
}

impl Clone for ActionLogger {
    fn clone(&self) -> Self {
        // Cloned loggers share the same entries/prev_hash via Arc.
        Self {
            config: self.config.clone(),
            entries: Arc::clone(&self.entries),
            prev_hash: Arc::clone(&self.prev_hash),
        }
    }
}

impl ActionLogger {
    pub fn new(config: &ActionLoggerConfig) -> crate::Result<Self> {
        Ok(Self {
            config: config.clone(),
            entries: Arc::new(Mutex::new(Vec::new())),
            prev_hash: Arc::new(Mutex::new("genesis".into())),
        })
    }

    /// Create an in-memory action logger (for testing).
    pub fn in_memory() -> Self {
        Self::new(&ActionLoggerConfig::default()).unwrap()
    }

    /// Log a tool call action.
    pub fn log(
        &self,
        request_id: &str,
        tool_name: &str,
        parameters: &serde_json::Value,
        decision: &str,
        source_ip: &str,
        latency_ms: f64,
    ) {
        if !self.config.enabled {
            return;
        }

        let params = if self.config.log_full_params {
            parameters.clone()
        } else {
            serde_json::json!({"_redacted": true})
        };

        let log_id = {
            let entries = self.entries.lock().unwrap();
            entries.len() as u64
        };

        let chain_hash = {
            let prev = self.prev_hash.lock().unwrap();
            compute_chain_hash(log_id, &prev.clone(), request_id, tool_name, decision)
        };

        let entry = ActionLogEntry {
            log_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.into(),
            agent_id: None,
            user_id: None,
            tool_name: tool_name.into(),
            parameters: params,
            decision: decision.into(),
            sandbox_mode: None,
            approval_request: None,
            approver: None,
            source_ip: source_ip.into(),
            latency_ms,
            chain_hash,
        };

        let mut prev_hash = self.prev_hash.lock().unwrap();
        let mut entries = self.entries.lock().unwrap();

        // Evict oldest entries if over max.
        if entries.len() >= self.config.max_entries {
            let drain_count = entries.len() - self.config.max_entries + 1;
            entries.drain(0..drain_count);
        }

        *prev_hash = entry.chain_hash.clone();
        entries.push(entry);
    }

    /// Get all log entries.
    pub fn entries(&self) -> Vec<ActionLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Export all entries as JSON.
    pub fn export_json(&self) -> crate::Result<String> {
        let entries = self.entries.lock().unwrap();
        serde_json::to_string_pretty(&*entries)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Export all entries as CSV.
    pub fn export_csv(&self) -> crate::Result<String> {
        let entries = self.entries.lock().unwrap();
        let mut wtr = csv::Writer::from_writer(vec![]);
        for entry in entries.iter() {
            wtr.serialize(entry)
                .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
        }
        let data = wtr.into_inner()
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
        String::from_utf8(data)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Verify chain integrity (all hashes link correctly).
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        let mut prev = "genesis".to_string();
        for entry in entries.iter() {
            let expected = compute_chain_hash(
                entry.log_id,
                &prev,
                &entry.request_id,
                &entry.tool_name,
                &entry.decision,
            );
            if entry.chain_hash != expected {
                return false;
            }
            prev = entry.chain_hash.clone();
        }
        true
    }
}

/// Compute the chain hash: SHA-256(prev_hash + log_id + request_id + tool_name + decision).
fn compute_chain_hash(
    log_id: u64,
    prev_hash: &str,
    request_id: &str,
    tool_name: &str,
    decision: &str,
) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(log_id.to_le_bytes());
    hasher.update(request_id.as_bytes());
    hasher.update(tool_name.as_bytes());
    hasher.update(decision.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// Small hex encode helper (we don't want to add the hex crate just for this).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_and_retrieve() {
        let logger = ActionLogger::in_memory();
        logger.log(
            "req-1", "web_search",
            &serde_json::json!({"query": "test"}),
            "allowed", "1.2.3.4", 0.5,
        );
        let entries = logger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "web_search");
        assert_eq!(entries[0].decision, "allowed");
    }

    #[test]
    fn chain_integrity() {
        let logger = ActionLogger::in_memory();
        for i in 0..10 {
            logger.log(
                &format!("req-{}", i), "tool",
                &serde_json::json!({"i": i}),
                "allowed", "1.2.3.4", 0.1,
            );
        }
        assert!(logger.verify_chain());
    }

    #[test]
    fn max_entries_eviction() {
        let config = ActionLoggerConfig {
            max_entries: 5,
            ..Default::default()
        };
        let logger = ActionLogger::new(&config).unwrap();
        for i in 0..10 {
            logger.log(
                &format!("req-{}", i), "tool",
                &serde_json::json!({}),
                "allowed", "1.2.3.4", 0.1,
            );
        }
        let entries = logger.entries();
        assert!(entries.len() <= 5);
    }

    #[test]
    fn export_json_works() {
        let logger = ActionLogger::in_memory();
        logger.log("req-1", "tool", &serde_json::json!({}), "allowed", "1.2.3.4", 0.1);
        let json = logger.export_json().unwrap();
        assert!(json.contains("req-1"));
    }
}
