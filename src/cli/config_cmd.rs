// CLI: `chakravyuh config` subcommands
//
// Provides offline configuration management:
//   - validate   — parse and validate a YAML config file
//   - show       — display a parsed config in structured form
//   - defaults   — print the default example configuration
//   - diff       — compare two config files and report differences

use std::path::PathBuf;

use clap::Subcommand;

use crate::cli::utils::{self, Color, ExitCode};
use crate::Config;

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Validate a configuration file
    Validate {
        /// Path to the YAML configuration file
        config: PathBuf,
        /// Show detailed validation results including all parsed sections
        #[arg(long)]
        verbose: bool,
    },

    /// Display the parsed configuration in structured form
    Show {
        /// Path to the YAML configuration file
        config: PathBuf,
        /// Output format: "text" or "json"
        #[arg(long, default_value = "text")]
        format: String,
        /// Show only a specific section (e.g., "shield", "threat", "keshav")
        section: Option<String>,
    },

    /// Print the default example configuration
    Defaults {
        /// Output format: "yaml" or "json"
        #[arg(long, default_value = "yaml")]
        format: String,
        /// Write to file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Compare two configuration files and show differences
    Diff {
        /// Path to the first (baseline) configuration
        base: PathBuf,
        /// Path to the second (modified) configuration
        modified: PathBuf,
    },
}

/// Execute a config subcommand. Returns the exit code.
pub async fn run(cmd: ConfigCommand) -> ExitCode {
    match cmd {
        ConfigCommand::Validate { config, verbose } => cmd_validate(&config, verbose),
        ConfigCommand::Show {
            config,
            format,
            section,
        } => cmd_show(&config, &format, section.as_deref()),
        ConfigCommand::Defaults { format, output } => cmd_defaults(&format, output),
        ConfigCommand::Diff { base, modified } => cmd_diff(&base, &modified),
    }
}

// ── validate ────────────────────────────────────────────────────────────

fn cmd_validate(path: &PathBuf, verbose: bool) -> ExitCode {
    utils::section("Config Validation");
    utils::kv("File", &path.display().to_string());

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} {}",
                utils::StatusIndicator::fail(&format!("Cannot read file: {}", e)),
                ""
            );
            return ExitCode::ConfigError;
        }
    };

    utils::kv("Size", &utils::format_size(content.len()));

    let config: Result<Config, _> = content.parse();
    match config {
        Ok(cfg) => {
            println!("{} Configuration is valid", utils::StatusIndicator::ok(""));

            if verbose {
                utils::sub_section("Parsed Sections");
                utils::kv(
                    "Shield Ring",
                    if cfg.shield.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Threat Ring",
                    if cfg.threat.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Identity Ring",
                    if cfg.identity.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Agent Ring",
                    if cfg.agent.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Memory Ring",
                    if cfg.memory.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Execution Ring",
                    if cfg.execution.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Reasoning Ring",
                    if cfg.reasoning.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Governance Ring",
                    if cfg.governance.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Recovery Ring",
                    if cfg.recovery_sec.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Keshav Core",
                    if cfg.keshav.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Cross-Ring",
                    if cfg.cross_ring.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv("Storage Backend", &cfg.storage.backend);
                utils::kv(
                    "gRPC Server",
                    if cfg.grpc.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Audit Trail",
                    if cfg.audit.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "API Keys",
                    if cfg.api_keys.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                utils::kv(
                    "Config Watcher",
                    if cfg.config_watcher.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );

                if let Some(ref ananta) = cfg.ananta_config_path {
                    utils::kv("ANANTA Config", ananta);
                } else {
                    let label = Color::dim("(none — degraded mode)");
                    utils::kv("ANANTA Config", &label);
                }

                if let Some(ref upstream) = cfg.upstream {
                    utils::sub_section("Upstream Configuration");
                    utils::kv("URL", &upstream.url);
                    utils::kv("Timeout", &format!("{}s", upstream.timeout_secs));
                    utils::kv(
                        "Forward Client Auth",
                        if upstream.forward_client_auth {
                            "yes"
                        } else {
                            "no"
                        },
                    );
                    utils::kv(
                        "API Key Set",
                        if upstream.api_key.is_empty() {
                            "no"
                        } else {
                            "yes (masked)"
                        },
                    );
                }
            }

            ExitCode::Ok
        }
        Err(e) => {
            eprintln!(
                "{} Configuration invalid: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            ExitCode::ConfigError
        }
    }
}

// ── show ────────────────────────────────────────────────────────────────

fn cmd_show(path: &PathBuf, format: &str, section: Option<&str>) -> ExitCode {
    let config = match Config::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", utils::StatusIndicator::fail(""), e);
            return ExitCode::ConfigError;
        }
    };

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&config).unwrap_or_else(|e| e.to_string());
            println!("{}", json);
        }
        _ => {
            utils::section("CHAKRAVYUH Configuration");

            if let Some(sec) = section {
                show_section(&config, sec);
            } else {
                show_section(&config, "server");
                show_section(&config, "shield");
                show_section(&config, "threat");
                show_section(&config, "identity");
                show_section(&config, "agent");
                show_section(&config, "memory");
                show_section(&config, "execution");
                show_section(&config, "keshav");
                show_section(&config, "cross_ring");
                show_section(&config, "storage");
                show_section(&config, "governance");
                show_section(&config, "reasoning");
                show_section(&config, "recovery_sec");
            }
        }
    }

    ExitCode::Ok
}

fn show_section(config: &Config, section: &str) {
    match section {
        "server" => {
            utils::sub_section("Server");
            utils::kv("Bind Address", &config.server.bind);
            utils::kv("Workers", &config.server.workers.to_string());
            if let Some(ref tls) = config.server.tls {
                utils::kv("TLS Cert", &tls.cert_path);
                utils::kv("TLS Key", &tls.key_path);
            }
        }
        "shield" => {
            utils::sub_section("Shield Ring (Ring 1 — Perimeter Defense)");
            utils::kv("Enabled", if config.shield.enabled { "yes" } else { "no" });
            utils::kv(
                "Input Validator",
                if config.shield.input_validator.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "Rate Limiter",
                if config.shield.rate_limiter.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "DoS Protector",
                if config.shield.dos_protector.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "Geo Fencer",
                if config.shield.geo_fencer.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "Bot Detector",
                if config.shield.bot_detector.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "WAF Engine",
                if config.shield.waf.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
        }
        "threat" => {
            utils::sub_section("Threat Ring (Ring 3 — Cognitive Threat Detection)");
            utils::kv("Enabled", if config.threat.enabled { "yes" } else { "no" });
            utils::kv("Deny Threshold", &config.threat.deny_threshold.to_string());
            utils::kv(
                "Challenge Threshold",
                &config.threat.challenge_threshold.to_string(),
            );
            utils::kv(
                "Pattern Matcher",
                if config.threat.pattern_matcher.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "Semantic Classifier",
                if config.threat.semantic_classifier.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
            utils::kv(
                "Jailbreak Detector",
                if config.threat.jailbreak_detector.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            );
        }
        "identity" => {
            utils::sub_section("Identity Ring (Ring 2 — Auth, AuthZ & Trust)");
            utils::kv(
                "Enabled",
                if config.identity.enabled { "yes" } else { "no" },
            );
        }
        "agent" => {
            utils::sub_section("Agent Ring (Ring 4 — Agent Policy & Behavior)");
            utils::kv("Enabled", if config.agent.enabled { "yes" } else { "no" });
        }
        "memory" => {
            utils::sub_section("Memory Ring (Ring 5 — Context Integrity)");
            utils::kv("Enabled", if config.memory.enabled { "yes" } else { "no" });
        }
        "execution" => {
            utils::sub_section("Execution Ring (Ring 6 — Tool Call Firewall)");
            utils::kv(
                "Enabled",
                if config.execution.enabled {
                    "yes"
                } else {
                    "no"
                },
            );
        }
        "keshav" => {
            utils::sub_section("Keshav Core — Central Decision Brain");
            utils::kv("Enabled", if config.keshav.enabled { "yes" } else { "no" });
            if let Some(ref path) = config.keshav.policy_path {
                utils::kv("Policy Path", path);
            }
        }
        "cross_ring" => {
            utils::sub_section("Cross-Ring Network");
            utils::kv(
                "Enabled",
                if config.cross_ring.enabled {
                    "yes"
                } else {
                    "no"
                },
            );
            utils::kv(
                "Command Buffer",
                &config.cross_ring.command.buffer_size.to_string(),
            );
            utils::kv(
                "Intel Buffer",
                &config.cross_ring.intel.buffer_size.to_string(),
            );
            utils::kv(
                "Control Buffer",
                &config.cross_ring.control.buffer_size.to_string(),
            );
            utils::kv(
                "Recovery Threshold",
                &config.cross_ring.recovery.failure_threshold.to_string(),
            );
        }
        "storage" => {
            utils::sub_section("Storage Backend");
            utils::kv("Backend", &config.storage.backend);
            if config.storage.backend == "redis" {
                utils::kv("Redis URL", &config.storage.redis_url);
            }
        }
        "governance" => {
            utils::sub_section("Governance Ring (Ring 8 — Policy & Compliance)");
            utils::kv(
                "Enabled",
                if config.governance.enabled {
                    "yes"
                } else {
                    "no"
                },
            );
        }
        "reasoning" => {
            utils::sub_section("Reasoning Ring (Ring 7 — CoT Integrity)");
            utils::kv(
                "Enabled",
                if config.reasoning.enabled {
                    "yes"
                } else {
                    "no"
                },
            );
        }
        "recovery_sec" => {
            utils::sub_section("Recovery Security Ring (Ring 9)");
            utils::kv(
                "Enabled",
                if config.recovery_sec.enabled {
                    "yes"
                } else {
                    "no"
                },
            );
        }
        _ => {
            utils::kv("Section", &format!("unknown section: {}", section));
        }
    }
}

// ── defaults ────────────────────────────────────────────────────────────

fn cmd_defaults(format: &str, output: Option<PathBuf>) -> ExitCode {
    let yaml = Config::default_yaml();

    let content = match format {
        "json" => {
            // Parse YAML then serialize to JSON.
            let config: Config = yaml.parse().unwrap_or_default();
            serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string())
        }
        _ => yaml.to_string(),
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &content) {
                eprintln!(
                    "{} Failed to write: {}",
                    utils::StatusIndicator::fail(""),
                    e
                );
                return ExitCode::GeneralError;
            }
            println!(
                "{} Default config written to {}",
                utils::StatusIndicator::ok(""),
                path.display()
            );
        }
        None => {
            println!("{}", content);
        }
    }

    ExitCode::Ok
}

// ── diff ────────────────────────────────────────────────────────────────

fn cmd_diff(base_path: &PathBuf, modified_path: &PathBuf) -> ExitCode {
    utils::section("Configuration Diff");

    let base_content = match std::fs::read_to_string(base_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Cannot read base: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::ConfigError;
        }
    };

    let modified_content = match std::fs::read_to_string(modified_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Cannot read modified: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::ConfigError;
        }
    };

    let base: Config = match base_content.parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Base config invalid: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::ConfigError;
        }
    };

    let modified: Config = match modified_content.parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Modified config invalid: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::ConfigError;
        }
    };

    utils::kv("Base", &base_path.display().to_string());
    utils::kv("Modified", &modified_path.display().to_string());

    let mut differences = Vec::new();

    // Compare key boolean flags.
    if base.shield.enabled != modified.shield.enabled {
        differences.push((
            "shield.enabled",
            base.shield.enabled.to_string(),
            modified.shield.enabled.to_string(),
        ));
    }
    if base.threat.enabled != modified.threat.enabled {
        differences.push((
            "threat.enabled",
            base.threat.enabled.to_string(),
            modified.threat.enabled.to_string(),
        ));
    }
    if base.identity.enabled != modified.identity.enabled {
        differences.push((
            "identity.enabled",
            base.identity.enabled.to_string(),
            modified.identity.enabled.to_string(),
        ));
    }
    if base.agent.enabled != modified.agent.enabled {
        differences.push((
            "agent.enabled",
            base.agent.enabled.to_string(),
            modified.agent.enabled.to_string(),
        ));
    }
    if base.memory.enabled != modified.memory.enabled {
        differences.push((
            "memory.enabled",
            base.memory.enabled.to_string(),
            modified.memory.enabled.to_string(),
        ));
    }
    if base.execution.enabled != modified.execution.enabled {
        differences.push((
            "execution.enabled",
            base.execution.enabled.to_string(),
            modified.execution.enabled.to_string(),
        ));
    }
    if base.threat.deny_threshold != modified.threat.deny_threshold {
        differences.push((
            "threat.deny_threshold",
            base.threat.deny_threshold.to_string(),
            modified.threat.deny_threshold.to_string(),
        ));
    }
    if base.storage.backend != modified.storage.backend {
        differences.push((
            "storage.backend",
            base.storage.backend.clone(),
            modified.storage.backend.clone(),
        ));
    }
    if base.server.bind != modified.server.bind {
        differences.push((
            "server.bind",
            base.server.bind.clone(),
            modified.server.bind.clone(),
        ));
    }

    if differences.is_empty() {
        println!("{} No differences found", utils::StatusIndicator::ok(""));
    } else {
        println!("\n{} differences found:\n", differences.len());
        utils::print_table(
            &["Key", "Base", "Modified"],
            &differences
                .iter()
                .map(|(k, b, m)| vec![k.to_string(), b.to_string(), m.to_string()])
                .collect::<Vec<_>>(),
        );
    }

    ExitCode::Ok
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[tokio::test]
    async fn test_validate_ok() {
        let f = write_temp("shield:\n  enabled: true\n");
        let code = run(ConfigCommand::Validate {
            config: f.path().to_path_buf(),
            verbose: false,
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }

    #[tokio::test]
    async fn test_validate_invalid() {
        let f = write_temp("invalid: [yaml: broken");
        let code = run(ConfigCommand::Validate {
            config: f.path().to_path_buf(),
            verbose: false,
        })
        .await;
        assert_eq!(code, ExitCode::ConfigError);
    }

    #[tokio::test]
    async fn test_defaults() {
        let code = run(ConfigCommand::Defaults {
            format: "yaml".to_string(),
            output: None,
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }

    #[tokio::test]
    async fn test_defaults_write() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("config.yaml");
        let code = run(ConfigCommand::Defaults {
            format: "yaml".to_string(),
            output: Some(out.clone()),
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
        assert!(out.exists());
    }
}
