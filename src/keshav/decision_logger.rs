// Decision Logger — append-only audit log for every decision.
//
// Every call to `KeshavDecide::evaluate()` produces a `DecisionRecord`
// that is logged here. The log is append-only — records cannot be
// modified or deleted. This is the audit trail required for
// compliance (SOC 2, ISO 27001, etc.).
//
// Backends:
//   - In-memory (default): VecDeque, bounded to max_entries.
//     Lost on restart. Used for testing and dev.
//   - File (future): append to a JSONL file. Phase 3.
//   - SQLite (future): structured query. Phase 5.
//   - Network sink (future): ship to SIEM/Splunk/Datadog. Phase 5.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::decision::DecisionRecord;

/// Maximum number of entries to keep in-memory by default.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

pub struct DecisionLogger {
    entries: Mutex<VecDeque<DecisionLogEntry>>,
    max_entries: usize,
}

/// A logged decision record + metadata about when it was logged.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecisionLogEntry {
    pub record: DecisionRecord,
    pub logged_at: String, // ISO 8601
    pub seq: u64,          // sequence number
}

impl DecisionLogger {
    /// Create an in-memory logger with the default capacity.
    pub fn in_memory() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Create an in-memory logger with a custom capacity.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_entries.min(100_000))),
            max_entries,
        }
    }

    /// Append a decision record to the log.
    pub fn log(&self, record: &DecisionRecord) -> Result<(), String> {
        let mut entries = self.entries.lock().map_err(|e| e.to_string())?;

        let seq = entries.len() as u64;
        let entry = DecisionLogEntry {
            record: record.clone(),
            logged_at: chrono::Utc::now().to_rfc3339(),
            seq,
        };

        // Enforce capacity — drop oldest entries.
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(entry);
        Ok(())
    }

    /// Get a snapshot of all logged entries (newest first).
    pub fn entries(&self) -> Vec<DecisionLogEntry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.iter().rev().cloned().collect()
    }

    /// Number of logged entries.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.len()
    }

    /// True if no entries have been logged.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export all entries as JSON (array).
    pub fn export_json(&self) -> Result<String, String> {
        let entries = self.entries();
        serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())
    }

    /// Export all entries as CSV.
    ///
    /// Columns: seq, logged_at, request_id, timestamp, source_ip,
    /// final_decision, policy_applied, latency_ms, rings_evaluated
    pub fn export_csv(&self) -> Result<String, String> {
        let entries = self.entries();

        let mut wtr = csv::Writer::from_writer(vec![]);
        // Write header.
        wtr.write_record([
            "seq",
            "logged_at",
            "request_id",
            "timestamp",
            "source_ip",
            "final_decision",
            "policy_applied",
            "latency_ms",
            "rings_evaluated",
        ])
        .map_err(|e| e.to_string())?;

        for entry in entries {
            let decision_str = format!("{:?}", entry.record.final_decision);
            let rings_str = entry
                .record
                .rings_evaluated
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(",");

            wtr.write_record(&[
                entry.seq.to_string(),
                entry.logged_at,
                entry.record.request_id,
                entry.record.timestamp,
                entry.record.source.ip,
                decision_str,
                entry.record.policy_applied.unwrap_or_default(),
                format!("{:.3}", entry.record.latency_ms),
                rings_str,
            ])
            .map_err(|e| e.to_string())?;
        }

        let bytes = wtr.into_inner().map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Decision, DecisionRecord, DecisionSource, RiskScore};

    fn make_record(id: &str, decision: Decision) -> DecisionRecord {
        DecisionRecord {
            request_id: id.into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            source: DecisionSource {
                ip: "1.2.3.4".into(),
                user_id: None,
                agent_id: None,
                api_key: None,
            },
            risk_score: RiskScore::default(),
            rings_evaluated: vec![1],
            ring_verdicts: serde_json::json!({}),
            policy_applied: Some("default".into()),
            final_decision: decision,
            reasoning: "test".into(),
            latency_ms: 0.5,
            keshav_version: "0.0.1".into(),
            policy_version: "1.0.0".into(),
        }
    }

    #[test]
    fn log_appends_entries() {
        let logger = DecisionLogger::in_memory();
        assert!(logger.is_empty());

        logger.log(&make_record("r1", Decision::Allow)).unwrap();
        logger.log(&make_record("r2", Decision::Allow)).unwrap();
        assert_eq!(logger.len(), 2);
    }

    #[test]
    fn entries_are_newest_first() {
        let logger = DecisionLogger::in_memory();
        logger.log(&make_record("r1", Decision::Allow)).unwrap();
        logger.log(&make_record("r2", Decision::Allow)).unwrap();

        let entries = logger.entries();
        assert_eq!(entries[0].record.request_id, "r2");
        assert_eq!(entries[1].record.request_id, "r1");
    }

    #[test]
    fn capacity_evicts_oldest() {
        let logger = DecisionLogger::with_capacity(3);
        for i in 0..5 {
            logger
                .log(&make_record(&format!("r{}", i), Decision::Allow))
                .unwrap();
        }
        assert_eq!(logger.len(), 3);
        // Oldest (r0, r1) should have been evicted.
        let entries = logger.entries();
        assert_eq!(entries[2].record.request_id, "r2");
        assert_eq!(entries[0].record.request_id, "r4");
    }

    #[test]
    fn export_json_produces_valid_json() {
        let logger = DecisionLogger::in_memory();
        logger.log(&make_record("r1", Decision::Allow)).unwrap();
        let json = logger.export_json().unwrap();
        assert!(json.contains("\"request_id\": \"r1\""));
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn export_csv_produces_header_and_rows() {
        let logger = DecisionLogger::in_memory();
        logger.log(&make_record("r1", Decision::Allow)).unwrap();
        logger
            .log(&make_record(
                "r2",
                Decision::Deny {
                    code: "X".into(),
                    retry_after: None,
                },
            ))
            .unwrap();
        let csv = logger.export_csv().unwrap();
        assert!(csv.starts_with("seq,logged_at,request_id"));
        assert!(csv.contains("r1"));
        assert!(csv.contains("r2"));
    }
}
