// CLI: `chakravyuh audit` subcommands
//
// Provides audit trail inspection and management:
//   - verify    — verify the integrity of the audit chain
//   - tail      — show the most recent audit entries
//   - search    — search audit entries by criteria
//   - export    — export audit entries to JSON or JSONL
//   - stats     — show audit statistics

use std::path::PathBuf;

use clap::Subcommand;
use serde_json::Value;

use crate::cli::utils::{self, Color, ExitCode, StatusIndicator};
use crate::infra::audit::{AuditConfig, AuditTrail};
use crate::storage::{create_store, StorageConfig};

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Verify the integrity of the audit hash chain
    Verify {
        /// Endpoint URL of a running CHAKRAVYUH instance
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Admin API key
        #[arg(short, long)]
        api_key: Option<String>,
    },

    /// Show the most recent audit entries
    Tail {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        count: usize,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json", "jsonl"])]
        format: String,
        /// Endpoint URL of a running CHAKRAVYUH instance
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },

    /// Search audit entries by criteria
    Search {
        /// Filter by source IP (substring match)
        #[arg(long)]
        source_ip: Option<String>,
        /// Filter by request path (substring match)
        #[arg(long)]
        path: Option<String>,
        /// Filter by decision (allow, deny, challenge)
        #[arg(long)]
        decision: Option<String>,
        /// Maximum entries to return
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },

    /// Export audit entries to a file
    Export {
        /// Output file path
        output: PathBuf,
        /// Output format
        #[arg(long, default_value = "jsonl", value_parser = ["jsonl", "json"])]
        format: String,
        /// Maximum entries to export
        #[arg(long, default_value = "1000")]
        limit: usize,
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },

    /// Show audit trail statistics
    Stats {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },
}

/// Execute an audit subcommand. Returns the exit code.
pub async fn run(cmd: AuditCommand) -> ExitCode {
    match cmd {
        AuditCommand::Verify { endpoint, api_key } => {
            cmd_verify(&endpoint, api_key.as_deref()).await
        }
        AuditCommand::Tail {
            count,
            format,
            endpoint,
        } => cmd_tail(count, &format, &endpoint).await,
        AuditCommand::Search {
            source_ip,
            path,
            decision,
            limit,
            format,
            endpoint,
        } => {
            cmd_search(
                source_ip.as_deref(),
                path.as_deref(),
                decision.as_deref(),
                limit,
                &format,
                &endpoint,
            )
            .await
        }
        AuditCommand::Export {
            output,
            format,
            limit,
            endpoint,
        } => cmd_export(&output, &format, limit, &endpoint).await,
        AuditCommand::Stats { endpoint } => cmd_stats(&endpoint).await,
    }
}

// ── verify ─────────────────────────────────────────────────────────────

async fn cmd_verify(endpoint: &str, api_key: Option<&str>) -> ExitCode {
    utils::section("Audit Chain Verification");
    utils::kv("Endpoint", endpoint);

    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/v1/audit/verify", endpoint));
    if let Some(key) = api_key {
        req = req.header("authorization", format!("Bearer {}", key));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                let valid = body.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
                let total = body
                    .get("total_entries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let broken = body.get("broken_at").and_then(|v| v.as_u64());

                utils::kv("Total Entries", &total.to_string());

                if valid {
                    println!("{} Chain integrity verified", StatusIndicator::ok(""));
                    ExitCode::Ok
                } else {
                    println!("{} Chain integrity BROKEN", StatusIndicator::fail(""));
                    if let Some(seq) = broken {
                        utils::kv("Broken At Sequence", &seq.to_string());
                    }
                    ExitCode::GeneralError
                }
            } else {
                eprintln!("{} Failed to parse response", StatusIndicator::fail(""));
                ExitCode::GeneralError
            }
        }
        Ok(resp) => {
            eprintln!(
                "{} Server returned {}",
                StatusIndicator::fail(""),
                resp.status()
            );
            if resp.status().as_u16() == 404 {
                eprintln!(
                    "  {} Audit endpoint not available. Is audit enabled in config?",
                    StatusIndicator::warn("")
                );
            }
            ExitCode::ConnectionError
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            ExitCode::ConnectionError
        }
    }
}

// ── tail ────────────────────────────────────────────────────────────────

async fn cmd_tail(count: usize, format: &str, endpoint: &str) -> ExitCode {
    utils::section("Recent Audit Entries");
    utils::kv("Endpoint", endpoint);
    utils::kv("Count", &count.to_string());

    let client = reqwest::Client::new();
    let url = format!("{}/v1/audit?limit={}", endpoint, count);

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                let entries = body
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .cloned()
                    .unwrap_or_default();

                if entries.is_empty() {
                    println!("  {}", Color::dim("No audit entries found"));
                    return ExitCode::Ok;
                }

                if format == "json" {
                    println!("{}", serde_json::to_string_pretty(&entries).unwrap());
                } else if format == "jsonl" {
                    for entry in &entries {
                        println!("{}", serde_json::to_string(entry).unwrap());
                    }
                } else {
                    for entry in &entries {
                        let seq = entry
                            .get("seq")
                            .and_then(|v| Some(v.to_string()))
                            .unwrap_or_default();
                        let ts = entry
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let ip = entry
                            .get("source_ip")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let path = entry.get("path").and_then(|v| v.as_str()).unwrap_or("-");
                        let decision = entry
                            .get("decision_json")
                            .and_then(|d| d.get("final_decision"))
                            .and_then(|d| d.get("type"))
                            .and_then(|d| d.as_str())
                            .unwrap_or("?");

                        let decision_color = match decision {
                            "allow" => Color::green(decision),
                            "deny" => Color::red(decision),
                            _ => Color::yellow(decision),
                        };

                        println!(
                            "  {} {} {:<15} {:<6} {} {}",
                            Color::dim(&format!("#{:<6}", seq)),
                            Color::dim(ts),
                            ip,
                            decision_color,
                            path,
                            Color::dim(&format!(
                                "hash={}...",
                                entry
                                    .get("hash")
                                    .and_then(|h| h.as_str())
                                    .unwrap_or("?")
                                    .chars()
                                    .take(8)
                                    .collect::<String>()
                            ))
                        );
                    }
                }

                println!("\n  {} entries shown", entries.len());
                ExitCode::Ok
            } else {
                eprintln!("{} Failed to parse response", StatusIndicator::fail(""));
                ExitCode::GeneralError
            }
        }
        Ok(resp) => {
            eprintln!(
                "{} Server returned {}",
                StatusIndicator::fail(""),
                resp.status()
            );
            ExitCode::ConnectionError
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            ExitCode::ConnectionError
        }
    }
}

// ── search ─────────────────────────────────────────────────────────────

async fn cmd_search(
    source_ip: Option<&str>,
    path: Option<&str>,
    decision: Option<&str>,
    limit: usize,
    format: &str,
    endpoint: &str,
) -> ExitCode {
    utils::section("Audit Search");
    utils::kv("Endpoint", endpoint);

    let mut params = vec![("limit", limit.to_string())];
    if let Some(ip) = source_ip {
        params.push(("source_ip", ip.to_string()));
    }
    if let Some(p) = path {
        params.push(("path", p.to_string()));
    }
    if let Some(d) = decision {
        params.push(("decision", d.to_string()));
    }

    let client = reqwest::Client::new();
    let req = client
        .get(format!("{}/v1/audit/search", endpoint))
        .query(&params);

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                if format == "json" {
                    println!("{}", serde_json::to_string_pretty(&body).unwrap());
                } else {
                    let entries = body
                        .get("entries")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = body.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
                    println!("  Found {} entries (showing {})", total, entries.len());
                    for entry in &entries {
                        println!("  {}", serde_json::to_string(entry).unwrap());
                    }
                }
                ExitCode::Ok
            } else {
                eprintln!("{} Parse error", StatusIndicator::fail(""));
                ExitCode::GeneralError
            }
        }
        Ok(resp) => {
            eprintln!(
                "{} Server returned {}",
                StatusIndicator::fail(""),
                resp.status()
            );
            ExitCode::ConnectionError
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            ExitCode::ConnectionError
        }
    }
}

// ── export ─────────────────────────────────────────────────────────────

async fn cmd_export(output: &PathBuf, format: &str, limit: usize, endpoint: &str) -> ExitCode {
    utils::section("Audit Export");
    utils::kv("Endpoint", endpoint);
    utils::kv("Output", &output.display().to_string());
    utils::kv("Format", format);
    utils::kv("Limit", &limit.to_string());

    let client = reqwest::Client::new();
    let url = format!("{}/v1/audit?limit={}&format={}", endpoint, limit, format);

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await.unwrap_or_default();

            // If JSON format, wrap in array.
            let content = if format == "json" {
                // Server might return raw entries; try to pretty-print.
                match serde_json::from_str::<Value>(&text) {
                    Ok(v) => serde_json::to_string_pretty(&v).unwrap_or(text),
                    Err(_) => text,
                }
            } else {
                text
            };

            match std::fs::write(output, &content) {
                Ok(()) => {
                    println!(
                        "{} Exported to {}",
                        StatusIndicator::ok(""),
                        output.display()
                    );
                    ExitCode::Ok
                }
                Err(e) => {
                    eprintln!("{} Write failed: {}", StatusIndicator::fail(""), e);
                    ExitCode::GeneralError
                }
            }
        }
        Ok(resp) => {
            eprintln!(
                "{} Server returned {}",
                StatusIndicator::fail(""),
                resp.status()
            );
            ExitCode::ConnectionError
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            ExitCode::ConnectionError
        }
    }
}

// ── stats ───────────────────────────────────────────────────────────────

async fn cmd_stats(endpoint: &str) -> ExitCode {
    utils::section("Audit Statistics");
    utils::kv("Endpoint", endpoint);

    let client = reqwest::Client::new();

    // Try to get audit stats from the metrics or a dedicated endpoint.
    let url = format!("{}/v1/audit/stats", endpoint);

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
                return ExitCode::Ok;
            }
        }
        _ => {}
    }

    // Fallback: try to get summary from the audit list endpoint.
    let fallback_url = format!("{}/v1/audit?limit=1", endpoint);
    match client.get(&fallback_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                let total = body.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
                utils::kv("Total Entries", &total.to_string());
                println!(
                    "\n{} No dedicated stats endpoint available.",
                    StatusIndicator::warn("")
                );
                println!("  Use `chakravyuh audit tail --format json` for detailed analysis.");
                return ExitCode::Ok;
            }
        }
        _ => {}
    }

    eprintln!(
        "{} Could not reach audit endpoint",
        StatusIndicator::fail("")
    );
    ExitCode::ConnectionError
}

// ── Local audit verification (offline, using in-memory audit) ─────────

/// Verify an audit chain from a local store (for offline analysis).
pub fn verify_local_chain(store_config: &StorageConfig, audit_config: &AuditConfig) -> ExitCode {
    let store = create_store(store_config);
    let _audit = AuditTrail::new(audit_config.clone());

    // Get total entries.
    let keys = store.keys("chakravyuh:audit:entry:");
    let total = keys.len();

    utils::section("Local Audit Chain Verification");
    utils::kv("Storage Backend", &store_config.backend);
    utils::kv("Total Entries", &total.to_string());

    if total == 0 {
        println!("\n  {} No entries to verify", Color::dim("(empty)"));
        return ExitCode::Ok;
    }

    // Check head pointer.
    let head = store.get("chakravyuh:audit:head");
    match head {
        Some(head_bytes) => {
            let head_seq = String::from_utf8_lossy(&head_bytes);
            utils::kv("Chain Head", &head_seq);
        }
        None => {
            eprintln!("{} No chain head found", StatusIndicator::fail(""));
            return ExitCode::GeneralError;
        }
    }

    // Verify store health.
    let health = store.health_check();
    utils::kv(
        "Store Reachable",
        if health.reachable { "yes" } else { "no" },
    );

    if health.reachable {
        println!(
            "\n{} Store is reachable, {} entries indexed",
            StatusIndicator::ok(""),
            total
        );
        ExitCode::Ok
    } else {
        eprintln!("\n{} Store is not reachable", StatusIndicator::fail(""));
        ExitCode::GeneralError
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_connection_error() {
        // Should get a connection error for non-running instance.
        let code = run(AuditCommand::Verify {
            endpoint: "http://127.0.0.1:1".to_string(),
            api_key: None,
        })
        .await;
        assert_eq!(code, ExitCode::ConnectionError);
    }

    #[tokio::test]
    async fn test_stats_connection_error() {
        let code = run(AuditCommand::Stats {
            endpoint: "http://127.0.0.1:1".to_string(),
        })
        .await;
        assert_eq!(code, ExitCode::ConnectionError);
    }

    #[test]
    fn test_local_verify_empty() {
        let store_config = StorageConfig::default();
        let audit_config = AuditConfig::default();
        let code = verify_local_chain(&store_config, &audit_config);
        assert_eq!(code, ExitCode::Ok);
    }
}
