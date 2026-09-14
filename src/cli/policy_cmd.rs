// CLI: `chakravyuh policy` subcommands
//
// Provides offline policy compilation, inspection, and version management:
//   - compile    — compile a YAML policy to bytecode
//   - inspect    — inspect compiled policy bytecode (disassembly)
//   - version    — show policy version history and diff
//   - bytecode   — dump raw bytecode in hex or instruction form

use std::path::PathBuf;

use clap::Subcommand;

use crate::cli::utils::{self, Color, ExitCode};
use crate::policy_compiler::{PolicyCompiler, PolicyCompilerConfig, PolicyInput, VersionDiff};

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Compile a YAML security policy to bytecode
    Compile {
        /// Path to the YAML policy file
        policy: PathBuf,
        /// Output format for the compilation report
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
        /// Save compiled bytecode to file
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Disassemble and inspect a compiled policy
    Inspect {
        /// Path to the YAML policy file to compile and inspect
        policy: PathBuf,
        /// Show VM execution trace (evaluate with sample input)
        #[arg(long)]
        trace: bool,
    },

    /// Show policy version history and differences
    Version {
        /// Path to the first policy file
        base: PathBuf,
        /// Path to the second policy file (for diff)
        modified: Option<PathBuf>,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },

    /// Dump raw bytecode instructions
    Bytecode {
        /// Path to the YAML policy file
        policy: PathBuf,
        /// Output format: "hex" for raw bytes, "asm" for disassembly
        #[arg(long, default_value = "asm", value_parser = ["hex", "asm"])]
        format: String,
        /// Save bytecode bytes to file (hex format)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Execute a policy subcommand. Returns the exit code.
pub async fn run(cmd: PolicyCommand) -> ExitCode {
    match cmd {
        PolicyCommand::Compile {
            policy,
            format,
            output,
        } => cmd_compile(&policy, &format, output),
        PolicyCommand::Inspect { policy, trace } => cmd_inspect(&policy, trace),
        PolicyCommand::Version {
            base,
            modified,
            format,
        } => cmd_version(&base, modified.as_ref(), &format),
        PolicyCommand::Bytecode {
            policy,
            format,
            output,
        } => cmd_bytecode(&policy, &format, output),
    }
}

// ── compile ─────────────────────────────────────────────────────────────

fn cmd_compile(path: &PathBuf, format: &str, output: Option<PathBuf>) -> ExitCode {
    let yaml = match read_policy_file(path) {
        Ok(y) => y,
        Err(e) => return e,
    };

    let mut compiler = make_compiler();

    utils::section("Policy Compilation");
    utils::kv("Source", &path.display().to_string());
    utils::kv("Size", &utils::format_size(yaml.len()));

    let compiled = match compiler.compile_yaml(&yaml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Compilation failed: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::PolicyError;
        }
    };

    println!(
        "{} Policy compiled successfully",
        utils::StatusIndicator::ok("")
    );
    utils::sub_section("Compilation Result");
    utils::kv("Version", &compiled.version);
    utils::kv("Source Hash", &compiled.source_hash);
    utils::kv("Rule Count", &compiled.rule_count.to_string());
    utils::kv(
        "Instructions",
        &compiled.bytecode.instruction_count().to_string(),
    );
    utils::kv("Constants", &compiled.bytecode.constant_count().to_string());
    utils::kv(
        "Bytecode Size",
        &utils::format_size(compiled.bytecode_bytes.len()),
    );

    let store = compiler.version_store();
    utils::kv("Versions in Store", &store.len().to_string());

    if let Some(latest) = store.latest() {
        utils::kv("Latest Version", &latest.version.to_string());
        utils::kv("Latest Bytecode Hash", &latest.bytecode_hash);
    }

    // Save bytecode if requested.
    if let Some(ref out_path) = output {
        use std::io::Write;
        let mut file = match std::fs::File::create(out_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "{} Cannot create output file: {}",
                    utils::StatusIndicator::fail(""),
                    e
                );
                return ExitCode::GeneralError;
            }
        };
        if let Err(e) = file.write_all(&compiled.bytecode_bytes) {
            eprintln!("{} Write failed: {}", utils::StatusIndicator::fail(""), e);
            return ExitCode::GeneralError;
        }
        println!(
            "\n{} Bytecode written to {}",
            utils::StatusIndicator::ok(""),
            out_path.display()
        );
    }

    if format == "json" {
        let summary = serde_json::json!({
            "version": compiled.version,
            "source_hash": compiled.source_hash,
            "rule_count": compiled.rule_count,
            "instruction_count": compiled.bytecode.instruction_count(),
            "constant_count": compiled.bytecode.constant_count(),
            "bytecode_size": compiled.bytecode_bytes.len(),
        });
        println!("\n{}", serde_json::to_string_pretty(&summary).unwrap());
        println!(
            "\n{}",
            serde_json::to_string_pretty(&output.as_ref().map(|p| p.display().to_string()))
                .unwrap()
        );
    }

    ExitCode::Ok
}

// ── inspect ─────────────────────────────────────────────────────────────

fn cmd_inspect(path: &PathBuf, trace: bool) -> ExitCode {
    let yaml = match read_policy_file(path) {
        Ok(y) => y,
        Err(e) => return e,
    };

    let mut compiler = make_compiler();

    utils::section("Policy Inspection");

    let compiled = match compiler.compile_yaml(&yaml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Compilation failed: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::PolicyError;
        }
    };

    // Disassemble the bytecode.
    utils::sub_section("Disassembly");
    let program = &compiled.bytecode;

    println!("  {:<6} {:<10} {:<6} {}", "IDX", "OPCODE", "ARG", "DETAIL");
    println!("  {}", "-".repeat(60));

    for (i, instr) in program.instructions.iter().enumerate() {
        let detail = if let Some(ci) = instr.operand {
            match program.constant_pool.get(ci as usize) {
                Some(c) => format!("const[{}]={}", ci, c),
                None => format!("const[{}]=?", ci),
            }
        } else {
            "-".to_string()
        };
        println!(
            "  {:<6} {:<10} {:<6} {}",
            i,
            format!("{:?}", instr.opcode),
            instr.operand.unwrap_or(0),
            detail
        );
    }

    // Show constants table.
    if program.constant_count() > 0 {
        utils::sub_section("Constants Table");
        for (i, constant) in program.constant_pool.iter().enumerate() {
            println!("  [{}] {}", i, constant);
        }
    }

    // Optional: trace with sample input.
    if trace {
        utils::sub_section("Execution Trace (sample input)");
        let input = PolicyInput::new(
            "cli-trace-001",
            "192.168.1.1",
            "SELECT * FROM users WHERE 1=1",
        )
        .with_user("test_user");

        match compiler.execute(&compiled, &input) {
            Ok(output) => {
                utils::kv("Decision", &format!("{:?}", output.decision));
                utils::kv("Risk Score", &output.risk_score.to_string());
                utils::kv("Rules Matched", &output.rules_matched.join(", "));
                utils::kv("Policy Version", &output.policy_version);
                utils::kv(
                    "Execution Time",
                    &utils::format_duration(std::time::Duration::from_nanos(
                        output.execution_time_ns,
                    )),
                );
            }
            Err(e) => {
                eprintln!(
                    "  {} Execution error: {}",
                    utils::StatusIndicator::fail(""),
                    e
                );
            }
        }
    }

    ExitCode::Ok
}

// ── version ─────────────────────────────────────────────────────────────

fn cmd_version(base_path: &PathBuf, modified_path: Option<&PathBuf>, format: &str) -> ExitCode {
    let base_yaml = match read_policy_file(base_path) {
        Ok(y) => y,
        Err(e) => return e,
    };

    let mut compiler = make_compiler();

    utils::section("Policy Versioning");

    // Compile base.
    let base = match compiler.compile_yaml(&base_yaml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Base compile failed: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::PolicyError;
        }
    };

    utils::kv("Base Version", &base.version);
    utils::kv("Base Hash", &base.source_hash);
    utils::kv("Base Rules", &base.rule_count.to_string());

    if let Some(mod_path) = modified_path {
        let mod_yaml = match read_policy_file(mod_path) {
            Ok(y) => y,
            Err(e) => return e,
        };

        // Hot-reload to get diff info.
        let reload_result = match compiler.hot_reload(&mod_yaml) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{} Modified compile failed: {}",
                    utils::StatusIndicator::fail(""),
                    e
                );
                return ExitCode::PolicyError;
            }
        };

        utils::sub_section("Hot-Reload Diff");
        utils::kv("Old Version", &reload_result.old_version);
        utils::kv("New Version", &reload_result.new_version);
        utils::kv("Rules Changed", &reload_result.rules_changed.to_string());
        utils::kv(
            "Signatures Changed",
            &reload_result.signatures_changed.to_string(),
        );
        utils::kv(
            "Reload Time",
            &utils::format_duration(std::time::Duration::from_nanos(
                reload_result.reload_time_ns,
            )),
        );

        // Show version store history.
        let store = compiler.version_store();
        utils::sub_section("Version History");
        for v in store.list_versions() {
            let marker = if *v == reload_result.new_version {
                Color::green(" << current")
            } else {
                String::new()
            };
            if let Some(policy) = store.get(v) {
                utils::kv(
                    &format!("v{}{}", v, marker),
                    &format!(
                        "rules={}, bytecode_hash={}...",
                        policy.rule_count,
                        &policy.bytecode_hash[..8.min(policy.bytecode_hash.len())]
                    ),
                );
            }
        }

        if format == "json" {
            let diff = VersionDiff {
                old_version: reload_result.old_version,
                new_version: reload_result.new_version,
                rules_added: reload_result.rules_changed,
                rules_removed: 0,
                bytecode_changed: reload_result.signatures_changed,
                source_changed: false,
                added_rule_names: vec![],
                removed_rule_names: vec![],
            };
            println!("\n{}", serde_json::to_string_pretty(&diff).unwrap());
        }
    } else {
        // Single policy: show version store.
        let store = compiler.version_store();
        utils::kv("Versions in Store", &store.len().to_string());
        if let Some(latest) = store.latest() {
            utils::kv("Latest", &latest.version.to_string());
        }
    }

    ExitCode::Ok
}

// ── bytecode ────────────────────────────────────────────────────────────

fn cmd_bytecode(path: &PathBuf, format: &str, output: Option<PathBuf>) -> ExitCode {
    let yaml = match read_policy_file(path) {
        Ok(y) => y,
        Err(e) => return e,
    };

    let mut compiler = make_compiler();

    utils::section("Bytecode Dump");

    let compiled = match compiler.compile_yaml(&yaml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Compilation failed: {}",
                utils::StatusIndicator::fail(""),
                e
            );
            return ExitCode::PolicyError;
        }
    };

    let bytes = &compiled.bytecode_bytes;
    utils::kv("Total Bytes", &bytes.len().to_string());

    match format {
        "hex" => {
            // Print in 16-byte rows.
            for (i, chunk) in bytes.chunks(16).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if *b >= 0x20 && *b < 0x7f {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("  {:04x}: {:<48} |{}|", i * 16, hex.join(" "), ascii);
            }
        }
        _ => {
            // ASM format — just the disassembly (same as inspect but more compact).
            for (i, instr) in compiled.bytecode.instructions.iter().enumerate() {
                let arg_str = if instr.operand.unwrap_or(0) != 0 {
                    format!(" {}", instr.operand.unwrap_or(0))
                } else {
                    String::new()
                };
                let const_str = if let Some(ci) = instr.operand {
                    format!(" [c{}]", ci)
                } else {
                    String::new()
                };
                println!("  {:04x}: {:?}{}{}", i, instr.opcode, arg_str, const_str);
            }
        }
    }

    // Save raw bytes if requested.
    if let Some(out_path) = output {
        use std::io::Write;
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let mut file = match std::fs::File::create(&out_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{} Cannot create: {}", utils::StatusIndicator::fail(""), e);
                return ExitCode::GeneralError;
            }
        };
        if let Err(e) = file.write_all(hex_str.as_bytes()) {
            eprintln!("{} Write failed: {}", utils::StatusIndicator::fail(""), e);
            return ExitCode::GeneralError;
        }
        println!(
            "\n{} Hex dump written to {}",
            utils::StatusIndicator::ok(""),
            out_path.display()
        );
    }

    ExitCode::Ok
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_compiler() -> PolicyCompiler {
    let config = PolicyCompilerConfig {
        enabled: true,
        bytecode_cache_size: 64,
        max_policy_size: 10 * 1024 * 1024,
        hot_reload: false,
        compilation_threads: 1,
    };
    PolicyCompiler::new(config).expect("compiler init")
}

fn read_policy_file(path: &PathBuf) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|e| {
        eprintln!(
            "{} Cannot read policy: {}",
            utils::StatusIndicator::fail(""),
            e
        );
        ExitCode::GeneralError
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SAMPLE_POLICY: &str = r#"
version: "1.0"
name: "test-policy"
rules:
  - name: "block_sql_injection"
    action: "deny"
    condition: 'payload.contains("SELECT")'
    enabled: true
    risk_weight: 0.3
  - name: "allow_admin"
    action: "allow"
    condition: 'user_id == "admin"'
    enabled: true
"#;

    fn write_temp_policy(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[tokio::test]
    async fn test_compile_ok() {
        let f = write_temp_policy(SAMPLE_POLICY);
        let code = run(PolicyCommand::Compile {
            policy: f.path().to_path_buf(),
            format: "text".to_string(),
            output: None,
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }

    #[tokio::test]
    async fn test_compile_missing_file() {
        let code = run(PolicyCommand::Compile {
            policy: PathBuf::from("/nonexistent/policy.yaml"),
            format: "text".to_string(),
            output: None,
        })
        .await;
        assert_eq!(code, ExitCode::GeneralError);
    }

    #[tokio::test]
    async fn test_inspect() {
        let f = write_temp_policy(SAMPLE_POLICY);
        let code = run(PolicyCommand::Inspect {
            policy: f.path().to_path_buf(),
            trace: false,
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }

    #[tokio::test]
    async fn test_bytecode_hex() {
        let f = write_temp_policy(SAMPLE_POLICY);
        let code = run(PolicyCommand::Bytecode {
            policy: f.path().to_path_buf(),
            format: "hex".to_string(),
            output: None,
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }

    #[tokio::test]
    async fn test_version_single() {
        let f = write_temp_policy(SAMPLE_POLICY);
        let code = run(PolicyCommand::Version {
            base: f.path().to_path_buf(),
            modified: None,
            format: "text".to_string(),
        })
        .await;
        assert_eq!(code, ExitCode::Ok);
    }
}
