// Configuration types for CHAKRAVYUH.
//
// Configuration is loaded from YAML files. The structure mirrors
// the architecture: top-level config has shield, threat, execution,
// keshav, cross_ring sections.

use std::path::Path;

use crate::shield::{
    bot_detector::BotDetectorConfig, dos_protector::DosProtectorConfig,
    geo_fencer::GeoFencerConfig, input_validator::InputValidatorConfig,
    rate_limiter::RateLimiterConfig, waf_engine::WafConfig,
};
use crate::Result;

use crate::grpc::GrpcConfig;
use crate::infra::{ApiKeyConfig, AuditConfig, ConfigWatcherConfig};

/// Top-level CHAKRAVYUH configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub shield: ShieldConfig,

    /// Upstream LLM API configuration for the /v1/proxy endpoint.
    /// When set, /v1/proxy evaluates the Shield Ring, then forwards
    /// the request to this upstream and returns its response.
    /// When unset, /v1/proxy returns the verdict without forwarding.
    #[serde(default)]
    pub upstream: Option<UpstreamConfig>,

    // Phase 2+ (stubs for now — not yet implemented)
    #[serde(default)]
    pub threat: crate::threat::ThreatConfig,

    #[serde(default)]
    pub identity: crate::identity::IdentityConfig,

    #[serde(default)]
    pub agent: crate::agent::AgentConfig,

    #[serde(default)]
    pub memory: crate::memory::MemoryConfig,

    #[serde(default)]
    pub execution: crate::execution::ExecutionConfig,

    #[serde(default)]
    pub reasoning: crate::reasoning::ReasoningConfig,

    #[serde(default)]
    pub governance: crate::governance::GovernanceConfig,

    #[serde(default)]
    pub recovery_sec: crate::recovery_sec::RecoverySecConfig,

    #[serde(default)]
    pub keshav: crate::keshav::KeshavConfig,

    #[serde(default)]
    pub cross_ring: crate::cross_ring::CrossRingConfig,

    #[serde(default)]
    pub storage: crate::storage::StorageConfig,

    #[serde(default)]
    pub grpc: GrpcConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    // Phase 9: Production hardening configs.
    #[serde(default)]
    pub config_watcher: ConfigWatcherConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub api_keys: ApiKeyConfig,

    /// Optional path to ANANTA's independent config file.
    ///
    /// ANANTA has its OWN config file (ananta.yaml) — it never trusts
    /// or depends on Keshav's configuration. This field tells Chakravyuh
    /// where to find it. When unset, ANANTA is not started.
    ///
    /// Example: "/etc/chakravyuh/ananta.yaml"
    #[serde(default)]
    pub ananta_config_path: Option<String>,
}

/// Upstream LLM API configuration.
///
/// CHAKRAVYUH is an OpenAI-compatible reverse proxy. Set `url` to your
/// LLM provider's chat completions endpoint (e.g.,
/// `https://api.openai.com/v1/chat/completions`). The `api_key` will be
/// sent as `Authorization: Bearer <key>` to the upstream.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UpstreamConfig {
    /// Full URL of the upstream chat completions endpoint.
    /// Example: https://api.openai.com/v1/chat/completions
    pub url: String,

    /// API key for the upstream. Sent as `Authorization: Bearer <key>`.
    /// Can also be set via the CHAKRAVYUH_UPSTREAM_API_KEY environment
    /// variable (takes precedence over this field).
    #[serde(default)]
    pub api_key: String,

    /// Request timeout in seconds (default: 60).
    #[serde(default = "default_upstream_timeout")]
    pub timeout_secs: u64,

    /// If true, the client's Authorization header is forwarded to the
    /// upstream instead of using `api_key`. Useful when each client has
    /// its own upstream credentials.
    #[serde(default)]
    pub forward_client_auth: bool,
}

fn default_upstream_timeout() -> u64 {
    60
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind: String,

    #[serde(default = "default_workers")]
    pub workers: usize,

    /// Optional built-in TLS termination.
    ///
    /// When set and CHAKRAVYUH is built with the `tls` cargo feature,
    /// the server listens with HTTPS using rustls. When unset, or when
    /// the `tls` feature is off, the server listens with plain HTTP —
    /// operators are expected to terminate TLS at a reverse proxy
    /// (nginx, Caddy, AWS ALB, etc.).
    ///
    /// Example YAML:
    ///   server:
    ///     bind: 0.0.0.0:8443
    ///     tls:
    ///       cert_path: /etc/chakravyuh/tls/fullchain.pem
    ///       key_path: /etc/chakravyuh/tls/privkey.pem
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Built-in TLS termination configuration (rustls).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain (fullchain.pem).
    pub cert_path: String,

    /// Path to the PEM-encoded private key (privkey.pem).
    pub key_path: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:8443".into()
}
fn default_workers() -> usize {
    4
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind_addr(),
            workers: default_workers(),
            tls: None,
        }
    }
}

/// Shield Ring configuration (aggregates all 6 engines).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct ShieldConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub input_validator: InputValidatorConfig,

    #[serde(default)]
    pub rate_limiter: RateLimiterConfig,

    #[serde(default)]
    pub dos_protector: DosProtectorConfig,

    #[serde(default)]
    pub geo_fencer: GeoFencerConfig,

    #[serde(default)]
    pub bot_detector: BotDetectorConfig,

    #[serde(default)]
    pub waf: WafConfig,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default)]
    pub format: String, // "json" or "text"
}

fn default_log_level() -> String {
    "info".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: "text".into(),
        }
    }
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            crate::error::Error::ConfigLoad(format!(
                "Failed to read config from {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;
        let cfg: Config = content.parse()?;
        Ok(cfg)
    }

    /// Get the default configuration as a string (for documentation).
    pub fn default_yaml() -> &'static str {
        include_str!("../configs/config.example.yaml")
    }
}

impl std::str::FromStr for Config {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(s)
            .map_err(|e| crate::error::Error::ConfigParse(format!("YAML parse error: {}", e)))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let yaml = Config::default_yaml();
        let config: Config = yaml.parse().expect("Default config should parse");
        assert!(config.shield.enabled);
    }

    #[test]
    fn test_minimal_config() {
        let yaml = r#"
shield:
  enabled: true
"#;
        let config: Config = yaml.parse().expect("Minimal config should parse");
        assert!(config.shield.enabled);
    }
}
