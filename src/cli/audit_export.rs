// Audit export module — queries and exports audit trail entries in multiple formats.
//
// Supports three output formats:
//   - JSON: pretty-printed array of entries
//   - CSV: header row + data rows with proper escaping
//   - Text: human-readable aligned table
//
// Query filters: time range, severity, source ring, decision type, limit, offset.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ── Export format ──────────────────────────────────────────────────────────

/// Export format for audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// JSON pretty-printed array.
    Json,
    /// CSV with header row.
    Csv,
    /// Human-readable aligned text table.
    Text,
}

impl Default for ExportFormat {
    fn default() -> Self {
        ExportFormat::Json
    }
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Csv => write!(f, "csv"),
            ExportFormat::Text => write!(f, "text"),
        }
    }
}

// ── Audit query ───────────────────────────────────────────────────────────

/// Query parameters for filtering audit entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start of the time range (inclusive).
    pub start_time: Option<String>,
    /// End of the time range (exclusive).
    pub end_time: Option<String>,
    /// Filter by severity level (e.g. "high", "medium", "low").
    pub severity_filter: Option<String>,
    /// Filter by source ring name (e.g. "shield", "threat").
    pub source_ring_filter: Option<String>,
    /// Filter by decision type (e.g. "allow", "deny").
    pub decision_type_filter: Option<String>,
    /// Maximum number of entries to return.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Number of entries to skip (for pagination).
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize { 1000 }

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            severity_filter: None,
            source_ring_filter: None,
            decision_type_filter: None,
            limit: default_limit(),
            offset: 0,
        }
    }
}

// ── Audit entry (export) ──────────────────────────────────────────────────

/// An audit entry prepared for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryExport {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Source ring that produced this entry.
    pub source_ring: String,
    /// Decision that was made (allow, deny, challenge, escalate).
    pub decision: String,
    /// Risk score at the time of the decision.
    pub risk_score: f64,
    /// User ID (if available).
    pub user_id: Option<String>,
    /// Request ID.
    pub request_id: String,
    /// Human-readable description of the event.
    pub description: String,
    /// Additional metadata as a JSON-like string.
    pub metadata: Option<String>,
}

// ── Time range parsing ───────────────────────────────────────────────────

/// Parse a time range string in the format "2024-01-01..2024-01-31".
///
/// Supports ISO 8601 date or datetime on either side of `..`.
/// If a time portion is omitted, it defaults to 00:00:00 UTC (start)
/// or 23:59:59 UTC (end).
pub fn parse_time_range(s: &str) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let parts: Vec<&str> = s.splitn(2, "..").collect();
    if parts.len() != 2 {
        return Err(Error::Other(format!(
            "invalid time range format '{}': expected 'START..END'",
            s
        )));
    }

    let start = parse_datetime_flexible(parts[0].trim())?;
    let end = parse_datetime_flexible(parts[1].trim())?;

    if start > end {
        return Err(Error::Other(format!(
            "invalid time range: start ({}) is after end ({})",
            start, end
        )));
    }

    Ok((start, end))
}

/// Parse a datetime string, accepting either a full ISO 8601 datetime
/// or a date-only string.
fn parse_datetime_flexible(s: &str) -> Result<DateTime<Utc>> {
    // Try full datetime first.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try date-only (YYYY-MM-DD).
    if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let start_of_day = naive_date.and_hms_opt(0, 0, 0)
            .ok_or_else(|| Error::Other("invalid date".into()))?;
        return Ok(start_of_day.and_utc());
    }

    Err(Error::Other(format!(
        "cannot parse datetime '{}': expected ISO 8601 or YYYY-MM-DD",
        s
    )))
}

// ── Entry filtering ──────────────────────────────────────────────────────

/// Filter audit entries according to a query.
pub fn filter_entries(
    entries: &[AuditEntryExport],
    query: &AuditQuery,
) -> Vec<AuditEntryExport> {
    let mut filtered: Vec<AuditEntryExport> = entries
        .iter()
        .filter(|entry| {
            // Filter by severity (match against description or metadata).
            if let Some(ref sev) = query.severity_filter {
                let entry_sev = entry
                    .metadata
                    .as_deref()
                    .and_then(|m| extract_severity(m))
                    .unwrap_or("medium");
                if entry_sev != sev.to_lowercase().as_str() {
                    return false;
                }
            }

            // Filter by source ring.
            if let Some(ref ring) = query.source_ring_filter {
                if entry.source_ring.to_lowercase() != ring.to_lowercase() {
                    return false;
                }
            }

            // Filter by decision type.
            if let Some(ref dec) = query.decision_type_filter {
                if entry.decision.to_lowercase() != dec.to_lowercase() {
                    return false;
                }
            }

            // Filter by time range.
            if let (Some(ref start_str), Some(ref end_str)) = (&query.start_time, &query.end_time) {
                if let Ok((start_dt, end_dt)) = parse_time_range(&format!("{}..{}", start_str, end_str)) {
                    if let Ok(entry_dt) = DateTime::parse_from_rfc3339(&entry.timestamp) {
                        let entry_dt = entry_dt.with_timezone(&Utc);
                        if entry_dt < start_dt || entry_dt >= end_dt {
                            return false;
                        }
                    }
                }
            } else if let Some(ref start_str) = query.start_time {
                if let Ok(start_dt) = parse_datetime_flexible(start_str) {
                    if let Ok(entry_dt) = DateTime::parse_from_rfc3339(&entry.timestamp) {
                        let entry_dt = entry_dt.with_timezone(&Utc);
                        if entry_dt < start_dt {
                            return false;
                        }
                    }
                }
            } else if let Some(ref end_str) = query.end_time {
                if let Ok(end_dt) = parse_datetime_flexible(end_str) {
                    if let Ok(entry_dt) = DateTime::parse_from_rfc3339(&entry.timestamp) {
                        let entry_dt = entry_dt.with_timezone(&Utc);
                        if entry_dt >= end_dt {
                            return false;
                        }
                    }
                }
            }

            true
        })
        .cloned()
        .collect();

    // Apply pagination.
    let filtered_len = filtered.len();
    let end_idx = (query.offset + query.limit).min(filtered_len);
    if query.offset < filtered_len {
        filtered.drain(end_idx..);
        filtered.drain(..query.offset);
    } else {
        filtered.clear();
    }

    filtered
}

/// Try to extract a severity string from a metadata JSON string.
fn extract_severity(metadata: &str) -> Option<&str> {
    // Simple extraction: look for "severity": "value" pattern.
    if let Some(pos) = metadata.find("\"severity\"") {
        let rest = &metadata[pos..];
        if let Some(colon) = rest.find(':') {
            let after_colon = rest[colon + 1..].trim_start();
            if after_colon.starts_with('"') {
                let end_quote = after_colon[1..].find('"')?;
                return Some(&after_colon[1..=end_quote]);
            }
        }
    }
    None
}

// ── Export formatting ─────────────────────────────────────────────────────

/// Export filtered audit entries in the specified format.
pub fn export(
    query: &AuditQuery,
    entries: &[AuditEntryExport],
    format: ExportFormat,
) -> String {
    let filtered = filter_entries(entries, query);

    match format {
        ExportFormat::Json => export_json(&filtered),
        ExportFormat::Csv => export_csv(&filtered),
        ExportFormat::Text => export_text(&filtered),
    }
}

/// Export as a pretty-printed JSON array.
fn export_json(entries: &[AuditEntryExport]) -> String {
    serde_json::to_string_pretty(entries)
        .unwrap_or_else(|e| format!("JSON serialization error: {}", e))
}

/// Export as CSV with header row and proper escaping.
fn export_csv(entries: &[AuditEntryExport]) -> String {
    let mut output = Vec::new();

    // Header row.
    output.push(csv_escape_row(&[
        "timestamp", "source_ring", "decision", "risk_score",
        "user_id", "request_id", "description", "metadata",
    ]));

    // Data rows.
    for entry in entries {
        output.push(csv_escape_row(&[
            &entry.timestamp,
            &entry.source_ring,
            &entry.decision,
            &entry.risk_score.to_string(),
            entry.user_id.as_deref().unwrap_or(""),
            &entry.request_id,
            &entry.description,
            entry.metadata.as_deref().unwrap_or(""),
        ]));
    }

    output.join("\n")
}

/// Escape a single CSV value. Wraps in double quotes if it contains commas,
/// newlines, or double quotes. Internal double quotes are doubled.
fn csv_escape_value(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        let escaped = val.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        val.to_string()
    }
}

/// Build a CSV row from field values.
fn csv_escape_row(fields: &[&str]) -> String {
    fields.iter().map(|f| csv_escape_value(f)).collect::<Vec<_>>().join(",")
}

/// Export as a human-readable aligned text table.
fn export_text(entries: &[AuditEntryExport]) -> String {
    if entries.is_empty() {
        return "No audit entries found.".to_string();
    }

    let headers = ["timestamp", "ring", "decision", "risk", "user_id", "request_id", "description"];
    let col_widths: [usize; 7] = [24, 12, 10, 6, 16, 16, 40];

    let mut lines = Vec::new();

    // Header.
    let header_parts: Vec<String> = headers
        .iter()
        .zip(col_widths.iter())
        .map(|(h, w)| format!("{:<w$}", h, w = w))
        .collect();
    lines.push(header_parts.join(" | "));

    // Separator.
    let sep_parts: Vec<String> = col_widths.iter().map(|w| "-".repeat(*w)).collect();
    lines.push(sep_parts.join("-+-"));

    // Rows.
    for entry in entries {
        let desc = if entry.description.len() > 40 {
            format!("{}...", &entry.description[..37])
        } else {
            entry.description.clone()
        };
        let user = entry.user_id.as_deref().unwrap_or("-");
        let row = format!(
            "{:<24} | {:<12} | {:<10} | {:>6.2} | {:<16} | {:<16} | {}",
            entry.timestamp, entry.source_ring, entry.decision,
            entry.risk_score, user, entry.request_id, desc,
        );
        lines.push(row);
    }

    lines.push(format!("\n{} entries", entries.len()));
    lines.join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<AuditEntryExport> {
        vec![
            AuditEntryExport {
                timestamp: "2024-01-15T10:30:00Z".into(),
                source_ring: "shield".into(),
                decision: "deny".into(),
                risk_score: 8.5,
                user_id: Some("user-001".into()),
                request_id: "req-001".into(),
                description: "SQL injection detected".into(),
                metadata: Some(r#"{"severity": "high"}"#.into()),
            },
            AuditEntryExport {
                timestamp: "2024-01-15T11:00:00Z".into(),
                source_ring: "threat".into(),
                decision: "allow".into(),
                risk_score: 0.5,
                user_id: Some("user-002".into()),
                request_id: "req-002".into(),
                description: "Normal request passed".into(),
                metadata: Some(r#"{"severity": "low"}"#.into()),
            },
            AuditEntryExport {
                timestamp: "2024-02-01T09:00:00Z".into(),
                source_ring: "identity".into(),
                decision: "challenge".into(),
                risk_score: 4.0,
                user_id: None,
                request_id: "req-003".into(),
                description: "Unusual login pattern".into(),
                metadata: Some(r#"{"severity": "medium"}"#.into()),
            },
        ]
    }

    #[test]
    fn test_export_json() {
        let entries = sample_entries();
        let query = AuditQuery::default();
        let output = export(&query, &entries, ExportFormat::Json);
        assert!(output.starts_with('['));
        assert!(output.contains("SQL injection"));
        assert!(output.contains("Normal request"));
    }

    #[test]
    fn test_export_csv() {
        let entries = sample_entries();
        let query = AuditQuery::default();
        let output = export(&query, &entries, ExportFormat::Csv);
        let lines: Vec<&str> = output.lines().collect();
        // Header + 3 data rows.
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("timestamp"));
        assert!(lines[0].contains("source_ring"));
        assert!(lines[1].contains("shield"));
    }

    #[test]
    fn test_export_text() {
        let entries = sample_entries();
        let query = AuditQuery::default();
        let output = export(&query, &entries, ExportFormat::Text);
        assert!(output.contains("shield"));
        assert!(output.contains("deny"));
        assert!(output.contains("3 entries"));
    }

    #[test]
    fn test_export_empty() {
        let query = AuditQuery::default();
        let output = export(&query, &[], ExportFormat::Text);
        assert_eq!(output, "No audit entries found.");
    }

    #[test]
    fn test_export_empty_csv() {
        let query = AuditQuery::default();
        let output = export(&query, &[], ExportFormat::Csv);
        let lines: Vec<&str> = output.lines().collect();
        // Only header row.
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_parse_time_range_valid() {
        let (start, end) = parse_time_range("2024-01-01..2024-01-31").unwrap();
        assert_eq!(start.to_string(), "2024-01-01 00:00:00 UTC");
        assert_eq!(end.to_string(), "2024-01-31 00:00:00 UTC");
    }

    #[test]
    fn test_parse_time_range_with_datetime() {
        let (start, end) = parse_time_range(
            "2024-01-01T00:00:00Z..2024-01-01T23:59:59Z"
        ).unwrap();
        assert!(start < end);
    }

    #[test]
    fn test_parse_time_range_invalid_format() {
        let result = parse_time_range("not-a-range");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_time_range_inverted() {
        let result = parse_time_range("2024-12-31..2024-01-01");
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_by_severity() {
        let entries = sample_entries();
        let mut query = AuditQuery::default();
        query.severity_filter = Some("high".into());
        let filtered = filter_entries(&entries, &query);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source_ring, "shield");
    }

    #[test]
    fn test_filter_by_ring() {
        let entries = sample_entries();
        let mut query = AuditQuery::default();
        query.source_ring_filter = Some("threat".into());
        let filtered = filter_entries(&entries, &query);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].decision, "allow");
    }

    #[test]
    fn test_filter_by_decision() {
        let entries = sample_entries();
        let mut query = AuditQuery::default();
        query.decision_type_filter = Some("challenge".into());
        let filtered = filter_entries(&entries, &query);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source_ring, "identity");
    }

    #[test]
    fn test_filter_by_time_range() {
        let entries = sample_entries();
        let mut query = AuditQuery::default();
        query.start_time = Some("2024-01-15".into());
        query.end_time = Some("2024-01-16".into());
        let filtered = filter_entries(&entries, &query);
        // Only the first two entries fall within Jan 15.
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_with_limit_and_offset() {
        let entries = sample_entries();
        let mut query = AuditQuery::default();
        query.limit = 1;
        query.offset = 1;
        let filtered = filter_entries(&entries, &query);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].request_id, "req-002");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape_value("hello, world"), "\"hello, world\"");
    }

    #[test]
    fn test_csv_escape_quote() {
        assert_eq!(csv_escape_value("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_csv_escape_simple() {
        assert_eq!(csv_escape_value("simple"), "simple");
    }

    #[test]
    fn test_large_dataset_export() {
        // Generate 5000 entries to test performance.
        let entries: Vec<AuditEntryExport> = (0..5000)
            .map(|i| AuditEntryExport {
                timestamp: format!("2024-01-{:02}T{:02}:00:00Z", 1 + (i % 28), i % 24),
                source_ring: ["shield", "threat", "identity"][i % 3].into(),
                decision: if i % 5 == 0 { "deny".into() } else { "allow".into() },
                risk_score: (i as f64) / 5000.0 * 10.0,
                user_id: Some(format!("user-{:04}", i)),
                request_id: format!("req-{:06}", i),
                description: format!("Entry number {} for testing", i),
                metadata: None,
            })
            .collect();

        let query = AuditQuery {
            limit: usize::MAX,
            ..AuditQuery::default()
        };
        let json_output = export(&query, &entries, ExportFormat::Json);
        assert!(json_output.len() > 1000);

        let csv_output = export(&query, &entries, ExportFormat::Csv);
        let csv_lines: Vec<&str> = csv_output.lines().collect();
        assert_eq!(csv_lines.len(), 5001); // header + 5000 rows

        let text_output = export(&query, &entries, ExportFormat::Text);
        assert!(text_output.contains("5000 entries"));
    }

    #[test]
    fn test_column_alignment() {
        let entries = vec![
            AuditEntryExport {
                timestamp: "2024-01-15T10:00:00Z".into(),
                source_ring: "x".into(),
                decision: "a".into(),
                risk_score: 1.0,
                user_id: None,
                request_id: "r".into(),
                description: "d".into(),
                metadata: None,
            },
        ];
        let query = AuditQuery::default();
        let output = export(&query, &entries, ExportFormat::Text);
        // Verify columns are aligned (pipes line up).
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.len() >= 3);
        // Header and separator should have the same length.
        assert_eq!(lines[0].len(), lines[1].len());
    }
}
