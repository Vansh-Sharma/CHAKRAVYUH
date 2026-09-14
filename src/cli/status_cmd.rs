// CLI: `chakravyuh status` subcommands
//
// Provides status and health checking for running instances:
//   - health     — check liveness/readiness of a running instance
//   - rings      — show per-ring health and statistics
//   - storage    — check storage backend health
//   - info       — show comprehensive system info

use std::time::Duration;

use clap::Subcommand;
use serde_json::Value;

use crate::cli::utils::{self, Color, ExitCode, StatusIndicator};

#[derive(Subcommand, Debug)]
pub enum StatusCommand {
    /// Check health of a running CHAKRAVYUH instance
    Health {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Check readiness (requires all rings healthy)
        #[arg(long)]
        ready: bool,
        /// Timeout in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,
    },

    /// Show per-ring health and statistics
    Rings {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },

    /// Check storage backend health
    Storage {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
    },

    /// Show comprehensive system information
    Info {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },
}

/// Execute a status subcommand. Returns the exit code.
pub async fn run(cmd: StatusCommand) -> ExitCode {
    match cmd {
        StatusCommand::Health {
            endpoint,
            ready,
            timeout,
        } => cmd_health(&endpoint, ready, timeout).await,
        StatusCommand::Rings { endpoint, format } => cmd_rings(&endpoint, &format).await,
        StatusCommand::Storage { endpoint } => cmd_storage(&endpoint).await,
        StatusCommand::Info { endpoint, format } => cmd_info(&endpoint, &format).await,
    }
}

// ── health ─────────────────────────────────────────────────────────────

async fn cmd_health(endpoint: &str, ready: bool, timeout_secs: u64) -> ExitCode {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let path = if ready { "/health/ready" } else { "/health" };
    let url = format!("{}{}", endpoint, path);

    let label = if ready { "Readiness" } else { "Liveness" };

    utils::section(&format!("{} Check", label));
    utils::kv("Endpoint", endpoint);
    utils::kv("Path", path);

    let start = std::time::Instant::now();

    match client.get(&url).send().await {
        Ok(resp) => {
            let latency = start.elapsed();
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or_default();

            utils::kv("HTTP Status", &status.to_string());
            utils::kv("Latency", &utils::format_duration(latency));

            if status.is_success() {
                let version = body
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let uptime = body
                    .get("uptime_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                utils::kv("Version", &Color::cyan(version));
                utils::kv("Uptime", &format_human_uptime(uptime));

                if ready {
                    // Show ring health summary.
                    if let Some(rings) = body.get("rings").and_then(|r| r.as_array()) {
                        let mut all_healthy = true;
                        for ring in rings {
                            let name = ring.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                            let healthy = ring
                                .get("healthy")
                                .and_then(|h| h.as_bool())
                                .unwrap_or(false);
                            let enabled = ring
                                .get("enabled")
                                .and_then(|e| e.as_bool())
                                .unwrap_or(false);

                            if !enabled {
                                continue;
                            }
                            if !healthy {
                                all_healthy = false;
                            }

                            let status_str = if healthy {
                                StatusIndicator::ok("")
                            } else {
                                all_healthy = false;
                                StatusIndicator::fail("")
                            };

                            utils::kv(&format!("Ring: {}", name), &status_str);
                        }

                        if !all_healthy {
                            println!("\n{} Some rings are unhealthy", StatusIndicator::warn(""));
                            return ExitCode::PartialFailure;
                        }
                    }
                }

                println!(
                    "\n{} Instance is {}",
                    StatusIndicator::ok(""),
                    if ready { "ready" } else { "alive" }
                );
                ExitCode::Ok
            } else {
                eprintln!(
                    "\n{} Instance returned {}",
                    StatusIndicator::fail(""),
                    status
                );
                if ready && status.as_u16() == 503 {
                    eprintln!(
                        "  {} System is not ready (rings may be initializing or unhealthy)",
                        StatusIndicator::warn("")
                    );
                }
                ExitCode::ConnectionError
            }
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            if e.is_timeout() {
                eprintln!(
                    "  {} Timed out after {}s",
                    StatusIndicator::warn(""),
                    timeout_secs
                );
            } else if e.is_connect() {
                eprintln!(
                    "  {} Is CHAKRAVYUH running at {}?",
                    StatusIndicator::warn(""),
                    endpoint
                );
            }
            ExitCode::ConnectionError
        }
    }
}

// ── rings ───────────────────────────────────────────────────────────────

async fn cmd_rings(endpoint: &str, format: &str) -> ExitCode {
    utils::section("Ring Health");

    let client = reqwest::Client::new();

    // Get readiness probe which includes ring health.
    let url = format!("{}/health/ready", endpoint);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                let rings = body
                    .get("rings")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default();

                if rings.is_empty() {
                    println!("  {} No ring health data available", Color::dim("(empty)"));
                    return ExitCode::Ok;
                }

                if format == "json" {
                    println!("{}", serde_json::to_string_pretty(&rings).unwrap());
                } else {
                    let mut rows: Vec<Vec<String>> = Vec::new();
                    for ring in &rings {
                        let name = ring
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("?")
                            .to_string();
                        let enabled = ring
                            .get("enabled")
                            .and_then(|e| e.as_bool())
                            .unwrap_or(false);
                        let healthy = ring
                            .get("healthy")
                            .and_then(|h| h.as_bool())
                            .unwrap_or(false);
                        let evals = ring
                            .get("total_evaluations")
                            .and_then(|e| e.as_u64())
                            .unwrap_or(0);
                        let errors = ring
                            .get("total_errors")
                            .and_then(|e| e.as_u64())
                            .unwrap_or(0);
                        let error_rate = ring
                            .get("error_rate")
                            .and_then(|e| e.as_f64())
                            .unwrap_or(0.0);

                        let status = if !enabled {
                            Color::dim("disabled").to_string()
                        } else if healthy {
                            Color::green("healthy").to_string()
                        } else {
                            Color::red("UNHEALTHY").to_string()
                        };

                        rows.push(vec![
                            name,
                            if enabled {
                                "yes".to_string()
                            } else {
                                "no".to_string()
                            },
                            status,
                            evals.to_string(),
                            errors.to_string(),
                            format!("{:.2}%", error_rate * 100.0),
                        ]);
                    }

                    utils::print_table(
                        &[
                            "Ring",
                            "Enabled",
                            "Status",
                            "Evaluations",
                            "Errors",
                            "Error Rate",
                        ],
                        &rows,
                    );
                }

                return ExitCode::Ok;
            }
        }
        _ => {}
    }

    // Try the recovery endpoint which also has ring health.
    let recovery_url = format!("{}/v1/recovery", endpoint);
    match client.get(&recovery_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
                return ExitCode::Ok;
            }
        }
        _ => {}
    }

    eprintln!(
        "{} Could not retrieve ring health",
        StatusIndicator::fail("")
    );
    ExitCode::ConnectionError
}

// ── storage ─────────────────────────────────────────────────────────────

async fn cmd_storage(endpoint: &str) -> ExitCode {
    utils::section("Storage Health");

    let client = reqwest::Client::new();
    let url = format!("{}/v1/storage/health", endpoint);

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<Value>().await {
                let backend = body.get("backend").and_then(|b| b.as_str()).unwrap_or("?");
                let reachable = body
                    .get("reachable")
                    .and_then(|r| r.as_bool())
                    .unwrap_or(false);
                let latency = body
                    .get("latency_ms")
                    .and_then(|l| l.as_f64())
                    .unwrap_or(0.0);
                let detail = body.get("detail").and_then(|d| d.as_str()).unwrap_or("");

                utils::kv("Backend", &Color::cyan(backend));
                let reachable_str = if reachable {
                    Color::green("yes")
                } else {
                    Color::red("no")
                };
                utils::kv("Reachable", &reachable_str);
                utils::kv("Latency", &format!("{:.3} ms", latency));
                if !detail.is_empty() {
                    utils::kv("Detail", detail);
                }

                if reachable {
                    println!("\n{} Storage is healthy", StatusIndicator::ok(""));
                    ExitCode::Ok
                } else {
                    println!("\n{} Storage is NOT reachable", StatusIndicator::fail(""));
                    ExitCode::PartialFailure
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
            ExitCode::ConnectionError
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            ExitCode::ConnectionError
        }
    }
}

// ── info ────────────────────────────────────────────────────────────────

async fn cmd_info(endpoint: &str, format: &str) -> ExitCode {
    utils::section("System Information");

    let client = reqwest::Client::new();

    // Collect info from multiple endpoints.
    let mut all_info = serde_json::Map::new();

    // Health endpoint.
    if let Ok(resp) = client.get(format!("{}/health", endpoint)).send().await {
        if let Ok(body) = resp.json::<Value>().await {
            all_info.insert("health".to_string(), body);
        }
    }

    // Version endpoint.
    if let Ok(resp) = client.get(format!("{}/version", endpoint)).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<Value>().await {
                all_info.insert("version".to_string(), body);
            }
        }
    }

    // Storage health.
    if let Ok(resp) = client
        .get(format!("{}/v1/storage/health", endpoint))
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<Value>().await {
                all_info.insert("storage".to_string(), body);
            }
        }
    }

    // Recovery/ring health.
    if let Ok(resp) = client.get(format!("{}/v1/recovery", endpoint)).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<Value>().await {
                all_info.insert("recovery".to_string(), body);
            }
        }
    }

    if all_info.is_empty() {
        eprintln!("{} No endpoints reachable", StatusIndicator::fail(""));
        return ExitCode::ConnectionError;
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&all_info).unwrap());
    } else {
        // Print structured text info.
        if let Some(health) = all_info.get("health") {
            if let Some(version) = health.get("version").and_then(|v| v.as_str()) {
                utils::kv("Version", &Color::cyan(version));
            }
            if let Some(uptime) = health.get("uptime_secs").and_then(|u| u.as_u64()) {
                utils::kv("Uptime", &format_human_uptime(uptime));
            }
            if let Some(total) = health.get("total_requests").and_then(|t| t.as_u64()) {
                utils::kv("Total Requests", &total.to_string());
            }
            if let Some(errors) = health.get("total_errors").and_then(|e| e.as_u64()) {
                utils::kv("Total Errors", &Color::red(&errors.to_string()));
            }
            if let Some(rate) = health.get("error_rate").and_then(|r| r.as_f64()) {
                utils::kv("Error Rate", &format!("{:.2}%", rate * 100.0));
            }
        }

        if let Some(storage) = all_info.get("storage") {
            if let Some(backend) = storage.get("backend").and_then(|b| b.as_str()) {
                utils::kv("Storage", backend);
            }
            if let Some(reachable) = storage.get("reachable").and_then(|r| r.as_bool()) {
                utils::kv(
                    "Storage Status",
                    if reachable { "healthy" } else { "unreachable" },
                );
            }
        }

        // Show which endpoints were reached.
        let reached = all_info.keys().cloned().collect::<Vec<_>>();
        utils::kv("Endpoints Reached", &reached.join(", "));
    }

    ExitCode::Ok
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Format uptime in human-readable form.
fn format_human_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_human_uptime() {
        assert_eq!(format_human_uptime(30), "30s");
        assert_eq!(format_human_uptime(90), "1m 30s");
        assert_eq!(format_human_uptime(3700), "1h 1m");
        assert_eq!(format_human_uptime(90061), "1d 1h");
    }

    #[tokio::test]
    async fn test_health_connection_error() {
        let code = run(StatusCommand::Health {
            endpoint: "http://127.0.0.1:1".to_string(),
            ready: false,
            timeout: 2,
        })
        .await;
        assert_eq!(code, ExitCode::ConnectionError);
    }

    #[tokio::test]
    async fn test_storage_connection_error() {
        let code = run(StatusCommand::Storage {
            endpoint: "http://127.0.0.1:1".to_string(),
        })
        .await;
        assert_eq!(code, ExitCode::ConnectionError);
    }

    #[tokio::test]
    async fn test_info_connection_error() {
        let code = run(StatusCommand::Info {
            endpoint: "http://127.0.0.1:1".to_string(),
            format: "text".to_string(),
        })
        .await;
        assert_eq!(code, ExitCode::ConnectionError);
    }
}
