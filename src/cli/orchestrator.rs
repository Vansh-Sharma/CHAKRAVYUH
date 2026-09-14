// CLI Orchestrator — programmatic command routing for the CHAKRAVYUH CLI tool module.
//
// This module provides a library-level API (not a binary CLI) that a binary
// `main.rs` can call. It defines the command enum, output format, result type,
// and a simple string-based command parser (no external CLI crate).
//
// Commands:
//   - policy validate  — dry-run policy validation
//   - bench            — benchmark all rings
//   - audit export     — export audit trail
//   - ananta status    — trust plane health dashboard
//   - simulate attack  — run attack scenarios from twin

use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::error::{Error, Result};

use super::ananta_status::{self, AnantaStatusConfig};
use super::audit_export::{self, AuditEntryExport, AuditQuery, ExportFormat as AuditExportFormat};
use super::benchmark::{self, BenchmarkConfig};
use super::policy_validate;
use super::simulate_attack::{self, SimulateAttackConfig};

// ── Output format ─────────────────────────────────────────────────────────

/// Output format for CLI results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON output.
    Json,
    /// Human-readable plain text.
    Text,
    /// Aligned table (text-based).
    Table,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Text
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "text" => Ok(OutputFormat::Text),
            "table" => Ok(OutputFormat::Table),
            _ => Err(Error::Other(format!("unknown output format: {}", s))),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Table => write!(f, "table"),
        }
    }
}

// ── CLI command enum ──────────────────────────────────────────────────────

/// A CLI command to be executed by the orchestrator.
#[derive(Debug, Clone)]
pub enum CliCommand {
    /// `cv policy validate <file>` — dry-run policy validation.
    PolicyValidate {
        /// Path to the YAML policy file.
        file_path: String,
    },

    /// `cv bench [options]` — benchmark suite for all rings.
    Bench {
        /// Benchmark configuration overrides.
        config: BenchmarkConfig,
    },

    /// `cv audit export [filters]` — export audit trail.
    AuditExport {
        /// Query filters for the audit export.
        query: AuditQuery,
        /// Pre-loaded audit entries (in real usage, these come from the store).
        entries: Vec<AuditEntryExport>,
        /// Output format.
        format: AuditExportFormat,
    },

    /// `cv ananta status [options]` — trust plane health dashboard.
    AnantaStatus {
        /// Configuration for the ANANTA status check.
        config: AnantaStatusConfig,
    },

    /// `cv simulate attack [options]` — run attack scenarios from twin.
    SimulateAttack {
        /// Configuration for the attack simulation.
        config: SimulateAttackConfig,
    },
}

// ── CLI result ────────────────────────────────────────────────────────────

/// The result of executing a CLI command.
#[derive(Debug, Clone)]
pub struct CliResult {
    /// Whether the command succeeded.
    pub success: bool,
    /// Formatted output string.
    pub output: String,
    /// Output format used.
    pub format: OutputFormat,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

impl CliResult {
    /// Create a successful result.
    pub fn ok(output: String, format: OutputFormat, duration_ms: u64) -> Self {
        Self {
            success: true,
            output,
            format,
            duration_ms,
        }
    }

    /// Create a failure result.
    pub fn err(output: String, format: OutputFormat, duration_ms: u64) -> Self {
        Self {
            success: false,
            output,
            format,
            duration_ms,
        }
    }

    /// Convert to a JSON value.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "success": self.success,
            "output": self.output,
            "format": self.format.to_string(),
            "duration_ms": self.duration_ms,
        })
    }
}

// ── CLI configuration ─────────────────────────────────────────────────────

/// Configuration for the CLI orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Default output format for commands.
    #[serde(default = "default_output_format")]
    pub default_format: OutputFormat,

    /// Whether to show verbose output.
    #[serde(default)]
    pub verbose: bool,

    /// Optional path to an ANANTA config file.
    pub ananta_config_path: Option<String>,
}

fn default_output_format() -> OutputFormat {
    OutputFormat::Text
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            default_format: default_output_format(),
            verbose: false,
            ananta_config_path: None,
        }
    }
}

// ── CLI orchestrator ──────────────────────────────────────────────────────

/// Routes CLI commands to the appropriate handler.
///
/// This is the central dispatcher for the programmatic CLI API.
/// It parses commands and delegates to the corresponding module.
pub struct CliOrchestrator {
    /// Orchestrator configuration.
    config: CliConfig,
}

impl CliOrchestrator {
    /// Create a new orchestrator with the given configuration.
    pub fn new(config: CliConfig) -> Self {
        Self { config }
    }

    /// Create an orchestrator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CliConfig::default())
    }

    /// Execute a CLI command and return the result.
    pub fn execute(&self, command: CliCommand) -> CliResult {
        let start = Instant::now();
        let format = self.config.default_format;

        let result = match command {
            CliCommand::PolicyValidate { file_path } => {
                self.exec_policy_validate(&file_path, format)
            }
            CliCommand::Bench { config } => self.exec_bench(&config, format),
            CliCommand::AuditExport {
                query,
                entries,
                format: export_fmt,
            } => self.exec_audit_export(&query, &entries, export_fmt, format),
            CliCommand::AnantaStatus { config } => self.exec_ananta_status(&config, format),
            CliCommand::SimulateAttack { config } => self.exec_simulate_attack(&config, format),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(output) => CliResult::ok(output, format, duration_ms),
            Err(output) => CliResult::err(output, format, duration_ms),
        }
    }

    /// Parse command-line arguments into a CliCommand.
    ///
    /// Uses simple string matching (no external CLI crate needed).
    ///
    /// # Arguments
    /// * `args` - Command-line arguments (typically `std::env::args().skip(1).collect()`)
    ///
    /// # Examples
    ///
    /// ```
    /// use chakravyuh::cli::orchestrator::{CliOrchestrator, CliCommand};
    ///
    /// // Parse: chakravyuh policy validate policy.yaml
    /// let args = vec!["policy".to_string(), "validate".to_string(), "policy.yaml".to_string()];
    /// let cmd = chakravyuh::cli::orchestrator::CliOrchestrator::parse_command(&args).unwrap();
    ///
    /// // Verify we got back a PolicyValidate command with the right file path.
    /// match cmd {
    ///     CliCommand::PolicyValidate { file_path } => {
    ///         assert_eq!(file_path, "policy.yaml");
    ///     }
    ///     other => panic!("expected PolicyValidate, got {:?}", other),
    /// }
    /// ```
    pub fn parse_command(args: &[String]) -> Result<CliCommand> {
        if args.is_empty() {
            return Err(Error::Other("no command provided".into()));
        }

        match args[0].as_str() {
            "policy" => parse_policy_command(&args[1..]),
            "bench" => parse_bench_command(&args[1..]),
            "audit" => parse_audit_command(&args[1..]),
            "ananta" => parse_ananta_command(&args[1..]),
            "simulate" => parse_simulate_command(&args[1..]),
            other => Err(Error::Other(format!("unknown command: {}", other))),
        }
    }

    // ── Command handlers ──────────────────────────────────────────────────

    fn exec_policy_validate(
        &self,
        file_path: &str,
        format: OutputFormat,
    ) -> std::result::Result<String, String> {
        let yaml_str = std::fs::read_to_string(file_path)
            .map_err(|e| format!("failed to read file '{}': {}", file_path, e))?;

        let result = policy_validate::PolicyValidator::validate_yaml(&yaml_str);

        let output = match format {
            OutputFormat::Json => serde_json::to_string_pretty(&result)
                .map_err(|e| format!("serialization failed: {}", e))?,
            OutputFormat::Text | OutputFormat::Table => format_validation_result(&result),
        };

        Ok(output)
    }

    fn exec_bench(
        &self,
        config: &BenchmarkConfig,
        format: OutputFormat,
    ) -> std::result::Result<String, String> {
        let report = benchmark::run_benchmark(config);
        let output = benchmark::format_report(&report, format);
        Ok(output)
    }

    fn exec_audit_export(
        &self,
        query: &AuditQuery,
        entries: &[AuditEntryExport],
        export_fmt: AuditExportFormat,
        _format: OutputFormat,
    ) -> std::result::Result<String, String> {
        let output = audit_export::export(query, entries, export_fmt);
        Ok(output)
    }

    fn exec_ananta_status(
        &self,
        config: &AnantaStatusConfig,
        format: OutputFormat,
    ) -> std::result::Result<String, String> {
        let report = ananta_status::check_status(config);
        let output = ananta_status::format_status(&report, format);
        Ok(output)
    }

    fn exec_simulate_attack(
        &self,
        config: &SimulateAttackConfig,
        format: OutputFormat,
    ) -> std::result::Result<String, String> {
        let result = simulate_attack::run_simulation(config);
        let output = simulate_attack::format_results(&result, format);
        Ok(output)
    }
}

// ── Subcommand parsers ───────────────────────────────────────────────────

fn parse_policy_command(args: &[String]) -> Result<CliCommand> {
    if args.is_empty() {
        return Err(Error::Other("policy subcommand required (validate)".into()));
    }
    match args[0].as_str() {
        "validate" => {
            if args.len() < 2 {
                return Err(Error::Other("policy validate requires a file path".into()));
            }
            Ok(CliCommand::PolicyValidate {
                file_path: args[1].clone(),
            })
        }
        other => Err(Error::Other(format!(
            "unknown policy subcommand: {} (expected: validate)",
            other
        ))),
    }
}

fn parse_bench_command(args: &[String]) -> Result<CliCommand> {
    let mut config = BenchmarkConfig::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--warmup" => {
                i += 1;
                if i >= args.len() {
                    return Err(Error::Other("--warmup requires a value".into()));
                }
                config.warmup_iterations = args[i]
                    .parse()
                    .map_err(|e| Error::Other(format!("invalid warmup value: {}", e)))?;
            }
            "--iterations" | "-n" => {
                i += 1;
                if i >= args.len() {
                    return Err(Error::Other("--iterations requires a value".into()));
                }
                config.measure_iterations = args[i]
                    .parse()
                    .map_err(|e| Error::Other(format!("invalid iterations value: {}", e)))?;
            }
            "--ring" => {
                i += 1;
                if i >= args.len() {
                    return Err(Error::Other("--ring requires a value".into()));
                }
                config.ring_filter = Some(args[i].clone());
            }
            other => {
                return Err(Error::Other(format!("unknown bench option: {}", other)));
            }
        }
        i += 1;
    }
    Ok(CliCommand::Bench { config })
}

fn parse_audit_command(args: &[String]) -> Result<CliCommand> {
    if args.is_empty() {
        return Err(Error::Other("audit subcommand required (export)".into()));
    }
    match args[0].as_str() {
        "export" => {
            let mut query = AuditQuery::default();
            let mut format = AuditExportFormat::Json;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--format" | "-f" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--format requires a value".into()));
                        }
                        format = match args[i].to_lowercase().as_str() {
                            "json" => AuditExportFormat::Json,
                            "csv" => AuditExportFormat::Csv,
                            "text" => AuditExportFormat::Text,
                            _ => return Err(Error::Other(format!("unknown format: {}", args[i]))),
                        };
                    }
                    "--limit" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--limit requires a value".into()));
                        }
                        query.limit = args[i]
                            .parse()
                            .map_err(|e| Error::Other(format!("invalid limit: {}", e)))?;
                    }
                    "--severity" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--severity requires a value".into()));
                        }
                        query.severity_filter = Some(args[i].clone());
                    }
                    "--ring" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--ring requires a value".into()));
                        }
                        query.source_ring_filter = Some(args[i].clone());
                    }
                    other => {
                        return Err(Error::Other(format!(
                            "unknown audit export option: {}",
                            other
                        )));
                    }
                }
                i += 1;
            }
            Ok(CliCommand::AuditExport {
                query,
                entries: vec![],
                format,
            })
        }
        other => Err(Error::Other(format!(
            "unknown audit subcommand: {} (expected: export)",
            other
        ))),
    }
}

fn parse_ananta_command(args: &[String]) -> Result<CliCommand> {
    if args.is_empty() {
        return Err(Error::Other("ananta subcommand required (status)".into()));
    }
    match args[0].as_str() {
        "status" => {
            let mut config = AnantaStatusConfig::default();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--verbose" | "-v" => {
                        config.verbose = true;
                    }
                    "--config" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--config requires a path".into()));
                        }
                        config.ananta_config_path = Some(args[i].clone());
                    }
                    other => {
                        return Err(Error::Other(format!(
                            "unknown ananta status option: {}",
                            other
                        )));
                    }
                }
                i += 1;
            }
            Ok(CliCommand::AnantaStatus { config })
        }
        other => Err(Error::Other(format!(
            "unknown ananta subcommand: {} (expected: status)",
            other
        ))),
    }
}

fn parse_simulate_command(args: &[String]) -> Result<CliCommand> {
    if args.is_empty() {
        return Err(Error::Other("simulate subcommand required (attack)".into()));
    }
    match args[0].as_str() {
        "attack" => {
            let mut config = SimulateAttackConfig::default();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--scenario" | "-s" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--scenario requires a name".into()));
                        }
                        config.scenario_filter = Some(args[i].clone());
                    }
                    "--iterations" | "-n" => {
                        i += 1;
                        if i >= args.len() {
                            return Err(Error::Other("--iterations requires a value".into()));
                        }
                        config.iterations = args[i]
                            .parse()
                            .map_err(|e| Error::Other(format!("invalid iterations: {}", e)))?;
                    }
                    other => {
                        return Err(Error::Other(format!(
                            "unknown simulate attack option: {}",
                            other
                        )));
                    }
                }
                i += 1;
            }
            Ok(CliCommand::SimulateAttack { config })
        }
        other => Err(Error::Other(format!(
            "unknown simulate subcommand: {} (expected: attack)",
            other
        ))),
    }
}

// ── Formatting helpers ───────────────────────────────────────────────────

/// Format a validation result as human-readable text.
fn format_validation_result(result: &policy_validate::ValidationResult) -> String {
    let mut lines = Vec::new();

    if result.is_valid {
        lines.push("Validation PASSED".to_string());
    } else {
        lines.push("Validation FAILED".to_string());
    }

    lines.push(format!("Policy version: {}", result.stats.policy_version));
    lines.push(format!("Rule count: {}", result.stats.rule_count));

    if !result.errors.is_empty() {
        lines.push(String::new());
        lines.push(format!("Errors ({}):", result.errors.len()));
        for issue in &result.errors {
            lines.push(format!(
                "  [{}] {} @ {}",
                issue.severity, issue.message, issue.location
            ));
            if let Some(ref suggestion) = issue.suggestion {
                lines.push(format!("    Suggestion: {}", suggestion));
            }
        }
    }

    if !result.warnings.is_empty() {
        lines.push(String::new());
        lines.push(format!("Warnings ({}):", result.warnings.len()));
        for issue in &result.warnings {
            lines.push(format!(
                "  [{}] {} @ {}",
                issue.severity, issue.message, issue.location
            ));
        }
    }

    lines.join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_policy_validate() {
        let args = vec!["policy".into(), "validate".into(), "policy.yaml".into()];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::PolicyValidate { file_path } => {
                assert_eq!(file_path, "policy.yaml");
            }
            _ => panic!("expected PolicyValidate command"),
        }
    }

    #[test]
    fn test_parse_bench_defaults() {
        let args = vec!["bench".into()];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::Bench { config } => {
                assert_eq!(config.warmup_iterations, 100);
                assert_eq!(config.measure_iterations, 1000);
                assert!(config.ring_filter.is_none());
            }
            _ => panic!("expected Bench command"),
        }
    }

    #[test]
    fn test_parse_bench_with_options() {
        let args = vec![
            "bench".into(),
            "--warmup".into(),
            "50".into(),
            "--iterations".into(),
            "500".into(),
            "--ring".into(),
            "shield".into(),
        ];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::Bench { config } => {
                assert_eq!(config.warmup_iterations, 50);
                assert_eq!(config.measure_iterations, 500);
                assert_eq!(config.ring_filter.as_deref(), Some("shield"));
            }
            _ => panic!("expected Bench command"),
        }
    }

    #[test]
    fn test_parse_audit_export() {
        let args = vec![
            "audit".into(),
            "export".into(),
            "--format".into(),
            "csv".into(),
            "--limit".into(),
            "100".into(),
        ];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::AuditExport { format, query, .. } => {
                assert_eq!(format, AuditExportFormat::Csv);
                assert_eq!(query.limit, 100);
            }
            _ => panic!("expected AuditExport command"),
        }
    }

    #[test]
    fn test_parse_ananta_status() {
        let args = vec!["ananta".into(), "status".into(), "--verbose".into()];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::AnantaStatus { config } => {
                assert!(config.verbose);
            }
            _ => panic!("expected AnantaStatus command"),
        }
    }

    #[test]
    fn test_parse_simulate_attack() {
        let args = vec![
            "simulate".into(),
            "attack".into(),
            "--scenario".into(),
            "prompt_injection".into(),
            "--iterations".into(),
            "10".into(),
        ];
        let cmd = CliOrchestrator::parse_command(&args).unwrap();
        match cmd {
            CliCommand::SimulateAttack { config } => {
                assert_eq!(config.scenario_filter.as_deref(), Some("prompt_injection"));
                assert_eq!(config.iterations, 10);
            }
            _ => panic!("expected SimulateAttack command"),
        }
    }

    #[test]
    fn test_parse_empty_args_returns_error() {
        let result = CliOrchestrator::parse_command(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_command_returns_error() {
        let args = vec!["unknown".into()];
        let result = CliOrchestrator::parse_command(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_config_defaults() {
        let config = CliConfig::default();
        assert_eq!(config.default_format, OutputFormat::Text);
        assert!(!config.verbose);
        assert!(config.ananta_config_path.is_none());
    }

    #[test]
    fn test_cli_result_ok() {
        let r = CliResult::ok("hello".into(), OutputFormat::Text, 5);
        assert!(r.success);
        assert_eq!(r.duration_ms, 5);
    }

    #[test]
    fn test_cli_result_err() {
        let r = CliResult::err("fail".into(), OutputFormat::Json, 1);
        assert!(!r.success);
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!(
            "table".parse::<OutputFormat>().unwrap(),
            OutputFormat::Table
        );
        assert!("yaml".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Text.to_string(), "text");
        assert_eq!(OutputFormat::Table.to_string(), "table");
    }

    #[test]
    fn test_cli_result_to_json() {
        let r = CliResult::ok("output".into(), OutputFormat::Json, 42);
        let v = r.to_json_value();
        assert_eq!(v["success"], true);
        assert_eq!(v["duration_ms"], 42);
    }
}
