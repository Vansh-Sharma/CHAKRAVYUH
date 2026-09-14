// CLI Tool Module — comprehensive command-line interface for CHAKRAVYUH.
//
// This module provides a rich set of offline and online commands for:
//   - Configuration management (validate, show, diff, defaults)
//   - Policy compilation and inspection (compile, inspect, version, bytecode)
//   - Prompt evaluation against Shield + Threat rings (prompt, scan, batch)
//   - Security test suites (shield, threat, compliance, quick smoke test)
//   - API key management (generate, verify, info, list, revoke)
//   - Audit trail management (verify, tail, search, export, stats)
//   - Status and health checking (health, rings, storage, info)
//
// Architecture:
//   The CLI uses the chakravyuh library directly for offline operations
//   (config parsing, policy compilation, ring evaluation) and makes HTTP
//   requests to a running instance for online operations (audit, status,
//   key management).
//
// Usage:
//   chakravyuh config validate config.yaml
//   chakravyuh policy compile policy.yaml
//   chakravyuh evaluate prompt "Ignore previous instructions"
//   chakravyuh test shield --attacks attacks.jsonl
//   chakravyuh status health --endpoint http://localhost:8443

pub mod ananta_status;
pub mod audit_cmd;
pub mod audit_export;
pub mod benchmark;
pub mod config_cmd;
pub mod evaluate_cmd;
pub mod keys_cmd;
pub mod orchestrator;
pub mod policy_cmd;
pub mod policy_validate;
pub mod simulate_attack;
pub mod status_cmd;
pub mod test_cmd;
pub mod utils;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::cli::utils::print_banner;

/// CHAKRAVYUH CLI — Security operations for autonomous AI.
///
/// The CLI provides both offline operations (config validation, policy
/// compilation, prompt evaluation) and online operations (status checks,
/// audit trail, key management) against a running CHAKRAVYUH instance.
#[derive(Parser, Debug)]
#[command(
    name = "chakravyuh",
    version,
    about = "CHAKRAVYUH — Open-source security operating system for autonomous AI",
    long_about = None,
    propagate_version = true,
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Cli {
    /// Path to configuration file (used by some subcommands)
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/chakravyuh/config.yaml"
    )]
    pub config: PathBuf,

    /// Suppress colored output
    #[arg(long, global = true, env = "NO_COLOR")]
    pub no_color: bool,

    /// Output format override (text or json)
    #[arg(long, global = true, default_value = "text", value_parser = ["text", "json"])]
    pub output_format: String,

    /// Show detailed output
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level CLI commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: config_cmd::ConfigCommand,
    },

    /// Policy compilation and management
    Policy {
        #[command(subcommand)]
        command: policy_cmd::PolicyCommand,
    },

    /// Evaluate prompts against security rings
    Evaluate {
        #[command(subcommand)]
        command: evaluate_cmd::EvaluateCommand,
    },

    /// Run security test suites
    Test {
        #[command(subcommand)]
        command: test_cmd::TestCommand,
    },

    /// API key management
    Keys {
        #[command(subcommand)]
        command: keys_cmd::KeysCommand,
    },

    /// Audit trail management
    Audit {
        #[command(subcommand)]
        command: audit_cmd::AuditCommand,
    },

    /// Status and health checking
    Status {
        #[command(subcommand)]
        command: status_cmd::StatusCommand,
    },

    /// Print version and build information
    Version,

    /// Print the default example configuration
    Defaults,

    /// Generate shell completion scripts
    #[command(hide = true)]
    Completions {
        /// Shell type (bash, zsh, fish, powershell, elvish)
        shell: Shell,
    },
}

/// Run the CLI and return the exit code.
pub async fn run() -> ExitCode {
    let cli = Cli::parse();

    // Apply NO_COLOR override.
    if cli.no_color {
        std::env::set_var("NO_COLOR", "1");
    }

    match cli.command {
        Commands::Config { command } => config_cmd::run(command).await,
        Commands::Policy { command } => policy_cmd::run(command).await,
        Commands::Evaluate { command } => evaluate_cmd::run(command).await,
        Commands::Test { command } => test_cmd::run(command).await,
        Commands::Keys { command } => keys_cmd::run(command).await,
        Commands::Audit { command } => audit_cmd::run(command).await,
        Commands::Status { command } => status_cmd::run(command).await,
        Commands::Version => cmd_version(),
        Commands::Defaults => cmd_defaults(),
        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "chakravyuh",
                &mut std::io::stdout(),
            );
            ExitCode::Ok
        }
    }
}

/// Run the CLI with the banner printed.
pub async fn run_with_banner() -> ExitCode {
    print_banner();
    run().await
}

// ── Simple top-level commands ───────────────────────────────────────────

fn cmd_version() -> ExitCode {
    print_banner();
    let version = env!("CARGO_PKG_VERSION");
    let profile = std::env::var("BUILD_PROFILE").unwrap_or_else(|_| "debug".into());
    let rust_version = format!("rustc {}", std::env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into()));

    utils::sub_section("Build Information");
    utils::kv("Version", version);
    utils::kv("Profile", &profile);
    utils::kv("Rust", &rust_version);
    utils::kv("Target", std::env::consts::ARCH);
    utils::kv("OS", std::env::consts::OS);
    utils::kv("License", "Apache-2.0");

    ExitCode::Ok
}

fn cmd_defaults() -> ExitCode {
    let yaml = crate::Config::default_yaml();
    println!("{}", yaml);
    ExitCode::Ok
}

/// Get the CLI exit code for use in main().
impl ExitCode {
    /// Convert to a process exit code.
    pub fn to_process_code(self) -> i32 {
        self.code()
    }
}

// ── Re-exports for convenience ──────────────────────────────────────────

pub use utils::ExitCode;

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parse() {
        let cli = Cli::try_parse_from(["chakravyuh", "version"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_config_validate() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "config",
            "validate",
            "config.yaml",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_policy_compile() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "policy",
            "compile",
            "policy.yaml",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_evaluate_prompt() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "evaluate",
            "prompt",
            "What is 2+2?",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_test_shield() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "test",
            "shield",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_keys_generate() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "keys",
            "generate",
            "--name",
            "test-key",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_status_health() {
        let cli = Cli::try_parse_from([
            "chakravyuh",
            "status",
            "health",
            "--endpoint",
            "http://localhost:8443",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_parse_no_subcommand_fails() {
        let cli = Cli::try_parse_from(["chakravyuh"]);
        assert!(cli.is_err());
    }

    #[test]
    fn test_cli_command_factory() {
        // Verify the command tree renders without panicking.
        let _ = Cli::command().render_help();
    }

    #[test]
    fn test_defaults_command() {
        assert_eq!(cmd_defaults(), ExitCode::Ok);
    }

    #[test]
    fn test_version_command() {
        assert_eq!(cmd_version(), ExitCode::Ok);
    }
}
