// CLI: `chakravyuh keys` subcommands
//
// Provides API key management:
//   - generate  — generate a new HMAC-SHA256 signed API key
//   - verify    — verify a key's signature and check permissions
//   - list      — list stored API keys (requires running instance)
//   - revoke    — revoke an API key (requires running instance)
//   - info      — decode and display key metadata

use clap::Subcommand;

use crate::cli::utils::{self, Color, ExitCode, StatusIndicator};
use crate::infra::api_keys::{ApiKeyConfig, ApiKeyManager, Permission};

#[derive(Subcommand, Debug)]
pub enum KeysCommand {
    /// Generate a new HMAC-SHA256 signed API key
    Generate {
        /// Key name (human-readable label)
        #[arg(long, default_value = "cli-generated")]
        name: String,
        /// Description for the key
        #[arg(long)]
        description: Option<String>,
        /// Permissions to grant (comma-separated: evaluate,proxy,execute,decisions,learn,policy,metrics,admin)
        #[arg(long, default_value = "evaluate")]
        permissions: String,
        /// Master secret for signing (or set CHAKRAVYUH_MASTER_SECRET env var)
        #[arg(long)]
        secret: Option<String>,
        /// Days until expiration (0 = never expires)
        #[arg(long, default_value = "90")]
        expires_days: u64,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },

    /// Verify a key's signature against the master secret
    Verify {
        /// The full key string (key_id:signature) or just the key_id
        key: String,
        /// Master secret for verification
        #[arg(long)]
        secret: Option<String>,
        /// Method + path + body to verify against
        #[arg(long)]
        request_body: Option<String>,
    },

    /// Display key information and metadata
    Info {
        /// The key string to decode
        key: String,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },

    /// List API keys from a running CHAKRAVYUH instance
    List {
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Admin API key for authentication
        #[arg(short, long)]
        api_key: Option<String>,
    },

    /// Revoke an API key on a running CHAKRAVYUH instance
    Revoke {
        /// Key ID to revoke
        key_id: String,
        /// Endpoint URL
        #[arg(short, long, default_value = "http://localhost:8443")]
        endpoint: String,
        /// Admin API key for authentication
        #[arg(short, long)]
        api_key: Option<String>,
    },
}

/// Execute a keys subcommand. Returns the exit code.
pub async fn run(cmd: KeysCommand) -> ExitCode {
    match cmd {
        KeysCommand::Generate {
            name,
            description,
            permissions,
            secret,
            expires_days,
            format,
        } => cmd_generate(
            &name,
            description.as_deref(),
            &permissions,
            secret.as_deref(),
            expires_days,
            &format,
        ),
        KeysCommand::Verify {
            key,
            secret,
            request_body,
        } => cmd_verify(&key, secret.as_deref(), request_body.as_deref()),
        KeysCommand::Info { key, format } => cmd_info(&key, &format),
        KeysCommand::List { endpoint, api_key } => cmd_list(&endpoint, api_key.as_deref()).await,
        KeysCommand::Revoke {
            key_id,
            endpoint,
            api_key,
        } => cmd_revoke(&key_id, &endpoint, api_key.as_deref()).await,
    }
}

// ── generate ────────────────────────────────────────────────────────────

fn cmd_generate(
    name: &str,
    description: Option<&str>,
    permissions_str: &str,
    secret: Option<&str>,
    expires_days: u64,
    format: &str,
) -> ExitCode {
    let master_secret = secret
        .map(|s| s.to_string())
        .or_else(|| std::env::var("CHAKRAVYUH_MASTER_SECRET").ok())
        .unwrap_or_default();

    if master_secret.is_empty() {
        eprintln!(
            "{} Master secret required. Use --secret or CHAKRAVYUH_MASTER_SECRET env var",
            StatusIndicator::fail("")
        );
        return ExitCode::ConfigError;
    }

    let permissions = parse_permissions(permissions_str);
    if permissions.is_empty() {
        eprintln!(
            "{} No valid permissions specified",
            StatusIndicator::fail("")
        );
        return ExitCode::ConfigError;
    }

    let config = ApiKeyConfig {
        enabled: true,
        master_secret,
        timestamp_tolerance_secs: 300,
        require_for_v1: false,
    };

    let manager = ApiKeyManager::new(config);

    let desc = description.unwrap_or("Generated via chakravyuh CLI");

    let key_info = match manager.create_key(name, permissions.clone(), None, "cli", desc, 0) {
        Ok((key_id, secret_key)) => (key_id, secret_key, desc.to_string()),
        Err(e) => {
            eprintln!("{} Key generation failed: {}", StatusIndicator::fail(""), e);
            return ExitCode::GeneralError;
        }
    };

    let (key_id, secret_key, description) = key_info;

    // Compute expiration.
    let expires_at = if expires_days > 0 {
        let now = chrono::Utc::now();
        Some((now + chrono::Duration::days(expires_days as i64)).to_rfc3339())
    } else {
        None
    };

    if format == "json" {
        let output = serde_json::json!({
            "key_id": key_id,
            "name": name,
            "description": description,
            "permissions": permissions.iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>(),
            "expires_at": expires_at,
            "secret_key": &secret_key,
            "warning": "Save the secret key now. It cannot be retrieved again."
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        utils::section("API Key Generated");
        utils::kv("Key ID", &Color::cyan(&key_id));
        utils::kv("Name", name);
        utils::kv("Description", &description);
        utils::kv(
            "Permissions",
            &permissions
                .iter()
                .map(|p| format!("{:?}", p))
                .collect::<Vec<_>>()
                .join(", "),
        );
        utils::kv("Expires At", expires_at.as_deref().unwrap_or("never"));
        println!();
        // Print the secret key with a warning.
        println!(
            "  {}",
            Color::yellow("Save this secret key now. It cannot be retrieved again:")
        );
        println!("  {}", Color::bold(&secret_key));
        println!();
        println!("  {}", Color::dim("To authenticate, send:"));
        println!(
            "  {}",
            Color::dim(&format!("  Authorization: Bearer {}:{{signature}}", key_id))
        );
    }

    ExitCode::Ok
}

// ── verify ──────────────────────────────────────────────────────────────

fn cmd_verify(key: &str, secret: Option<&str>, _request_body: Option<&str>) -> ExitCode {
    let master_secret = secret
        .map(|s| s.to_string())
        .or_else(|| std::env::var("CHAKRAVYUH_MASTER_SECRET").ok())
        .unwrap_or_default();

    if master_secret.is_empty() {
        eprintln!("{} Master secret required", StatusIndicator::fail(""));
        return ExitCode::ConfigError;
    }

    let config = ApiKeyConfig {
        enabled: true,
        master_secret,
        timestamp_tolerance_secs: 300,
        require_for_v1: false,
    };

    let manager = ApiKeyManager::new(config);

    utils::section("API Key Verification");

    // Parse the key string.
    let (key_id, signature) = if key.contains(':') {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (key.to_string(), String::new())
    };

    utils::kv("Key ID", &key_id);
    utils::kv(
        "Has Signature",
        if signature.is_empty() { "no" } else { "yes" },
    );

    // Attempt to look up the key.
    match manager.list_keys().iter().find(|k| k.key_id == key_id) {
        Some(info) => {
            utils::kv("Status", &Color::green("found"));
            utils::kv("Name", &info.name);
            utils::kv("Created", &info.created_at);
            utils::kv("Permissions", &format!("{:?}", info.permissions));
        }
        None => {
            utils::kv("Status", &Color::red("not found"));
            println!(
                "\n{} Key '{}' is not registered in the manager",
                StatusIndicator::fail(""),
                key_id
            );
            return ExitCode::GeneralError;
        }
    }

    ExitCode::Ok
}

// ── info ────────────────────────────────────────────────────────────────

fn cmd_info(key: &str, format: &str) -> ExitCode {
    // Parse the key.
    let (key_id, has_sig) = if key.contains(':') {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        (parts[0].to_string(), true)
    } else {
        (key.to_string(), false)
    };

    let output = serde_json::json!({
        "key_id": key_id,
        "has_signature": has_sig,
        "prefix_type": infer_key_prefix(&key_id),
    });

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        utils::section("Key Information");
        utils::kv("Key ID", &Color::cyan(&key_id));
        utils::kv("Has Signature", if has_sig { "yes" } else { "no" });
        utils::kv("Inferred Type", infer_key_prefix(&key_id));
    }

    ExitCode::Ok
}

// ── list ────────────────────────────────────────────────────────────────

async fn cmd_list(endpoint: &str, api_key: Option<&str>) -> ExitCode {
    utils::section("API Keys");
    utils::kv("Endpoint", endpoint);

    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/v1/keys", endpoint));
    if let Some(key) = api_key {
        req = req.header("authorization", format!("Bearer {}", key));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
                return ExitCode::Ok;
            }
        }
        Ok(resp) => {
            eprintln!(
                "{} Server returned {}",
                StatusIndicator::fail(""),
                resp.status()
            );
            return ExitCode::ConnectionError;
        }
        Err(e) => {
            eprintln!("{} Connection failed: {}", StatusIndicator::fail(""), e);
            return ExitCode::ConnectionError;
        }
    }
    ExitCode::Ok
}

// ── revoke ──────────────────────────────────────────────────────────────

async fn cmd_revoke(key_id: &str, endpoint: &str, api_key: Option<&str>) -> ExitCode {
    utils::section("Revoke API Key");
    utils::kv("Key ID", key_id);
    utils::kv("Endpoint", endpoint);

    let client = reqwest::Client::new();
    let mut req = client.delete(format!("{}/v1/keys/{}", endpoint, key_id));
    if let Some(key) = api_key {
        req = req.header("authorization", format!("Bearer {}", key));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            println!(
                "{} Key '{}' revoked successfully",
                StatusIndicator::ok(""),
                key_id
            );
            ExitCode::Ok
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

// ── Helpers ─────────────────────────────────────────────────────────────

/// Parse a comma-separated permissions string into a Vec<Permission>.
fn parse_permissions(s: &str) -> Vec<Permission> {
    s.split(',')
        .filter_map(|p| match p.trim().to_lowercase().as_str() {
            "evaluate" => Some(Permission::Evaluate),
            "proxy" => Some(Permission::Proxy),
            "execute" => Some(Permission::Execute),
            "decisions" => Some(Permission::Decisions),
            "learn" => Some(Permission::Learn),
            "policy" => Some(Permission::Policy),
            "metrics" => Some(Permission::Metrics),
            "admin" => Some(Permission::Admin),
            _ => None,
        })
        .collect()
}

/// Infer the type of key from its ID prefix.
fn infer_key_prefix(key_id: &str) -> &'static str {
    if key_id.starts_with("ak_live_") {
        "live"
    } else if key_id.starts_with("ak_test_") {
        "test"
    } else if key_id.starts_with("sk-admin-") {
        "admin (Keshav)"
    } else if key_id.starts_with("sk-op-") {
        "operator (Keshav)"
    } else if key_id.starts_with("sk-audit-") {
        "auditor (Keshav)"
    } else if key_id.starts_with("sk-svc-") {
        "service (Keshav)"
    } else {
        "unknown"
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_permissions() {
        let perms = parse_permissions("evaluate,proxy,admin");
        assert_eq!(perms.len(), 3);
        assert!(perms.contains(&Permission::Evaluate));
        assert!(perms.contains(&Permission::Proxy));
        assert!(perms.contains(&Permission::Admin));
    }

    #[test]
    fn test_parse_permissions_invalid() {
        let perms = parse_permissions("invalid,also_bad");
        assert!(perms.is_empty());
    }

    #[test]
    fn test_infer_key_prefix() {
        assert_eq!(infer_key_prefix("ak_live_abc123"), "live");
        assert_eq!(infer_key_prefix("ak_test_xyz"), "test");
        assert_eq!(infer_key_prefix("sk-admin-key1"), "admin (Keshav)");
        assert_eq!(infer_key_prefix("unknown-prefix"), "unknown");
    }

    #[test]
    fn test_info_no_secret() {
        let code = tokio::runtime::Runtime::new().unwrap().block_on(async {
            run(KeysCommand::Info {
                key: "ak_live_test123".to_string(),
                format: "text".to_string(),
            })
            .await
        });
        assert_eq!(code, ExitCode::Ok);
    }
}
