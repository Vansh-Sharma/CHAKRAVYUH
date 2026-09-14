// ANANTA Configuration — independent from Keshav.
//
// CRITICAL: ANANTA has its own config file and does NOT depend on
// Keshav's configuration. This is a first-class design constraint.
// ANANTA protects Keshav, so it cannot trust Keshav's config.

use serde::{Deserialize, Serialize};

/// ANANTA plane configuration.
///
/// Loaded from a separate `ananta.yaml` file, never from the main
/// CHAKRAVYUH config. This ensures ANANTA's trust verification
/// cannot be compromised by manipulating the main config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnantaConfig {
    /// Master enable switch. When false, ANANTA does not run.
    /// The system operates in degraded mode (no trust plane).
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Sentinel configuration.
    #[serde(default)]
    pub sentinel: SentinelConfig,

    /// Phoenix (recovery) configuration.
    #[serde(default)]
    pub phoenix: PhoenixConfig,

    /// Anchor (root of trust) configuration.
    #[serde(default)]
    pub anchor: AnchorConfig,

    /// Adapter (adaptive orchestration) configuration.
    #[serde(default)]
    pub adapter: AdapterConfig,

    /// Trust Proof Engine configuration.
    #[serde(default)]
    pub trust_proof: TrustProofConfig,

    /// Health Model configuration.
    #[serde(default)]
    pub health: HealthConfig,

    /// Audit configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Distributed configuration.
    #[serde(default)]
    pub distributed: DistributedConfig,

    /// Path to ANANTA's own secure state directory.
    /// Must be on a different mount point from Keshav's data.
    #[serde(default = "default_state_path")]
    pub state_path: String,

    /// Cryptographic algorithm suite.
    #[serde(default)]
    pub crypto: CryptoConfig,
}

fn default_enabled() -> bool { true }
fn default_state_path() -> String { "./ananta_state".into() }

impl Default for AnantaConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            sentinel: SentinelConfig::default(),
            phoenix: PhoenixConfig::default(),
            anchor: AnchorConfig::default(),
            adapter: AdapterConfig::default(),
            trust_proof: TrustProofConfig::default(),
            health: HealthConfig::default(),
            audit: AuditConfig::default(),
            distributed: DistributedConfig::default(),
            state_path: default_state_path(),
            crypto: CryptoConfig::default(),
        }
    }
}

impl AnantaConfig {
    /// Parse from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("ananta config parse error: {}", e))
    }

    /// Default YAML configuration for documentation / bootstrapping.
    pub fn default_yaml() -> String {
        serde_yaml::to_string(&Self::default()).unwrap_or_default()
    }

    /// Validate the configuration. Returns warnings for questionable values.
    pub fn validate(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();

        if self.sentinel.check_interval_ms < 100 {
            warnings.push(ConfigWarning {
                field: "sentinel.check_interval_ms".into(),
                message: "interval < 100ms may cause excessive CPU usage".into(),
                severity: WarningSeverity::Warning,
            });
        }

        if self.trust_proof.generation_interval_ms < 1000 {
            warnings.push(ConfigWarning {
                field: "trust_proof.generation_interval_ms".into(),
                message: "trust proof generation < 1s may impact performance".into(),
                severity: WarningSeverity::Warning,
            });
        }

        if self.phoenix.max_recovery_actions_per_hour > 100 {
            warnings.push(ConfigWarning {
                field: "phoenix.max_recovery_actions_per_hour".into(),
                message: "high recovery action rate may indicate instability".into(),
                severity: WarningSeverity::Info,
            });
        }

        if self.distributed.enabled && self.distributed.quorum_size < 2 {
            warnings.push(ConfigWarning {
                field: "distributed.quorum_size".into(),
                message: "quorum_size < 2 provides no fault tolerance".into(),
                severity: WarningSeverity::Warning,
            });
        }

        warnings
    }
}

// ── Subsystem Configs ──

/// Sentinel: continuous integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// How often (ms) Sentinel runs a full integrity check cycle.
    #[serde(default = "default_check_interval")]
    pub check_interval_ms: u64,

    /// Size of the sliding window for drift detection (number of observations).
    #[serde(default = "default_window_size")]
    pub drift_window_size: usize,

    /// Number of standard deviations before a metric is considered drifting.
    #[serde(default = "default_drift_threshold")]
    pub drift_sigma_threshold: f64,

    /// Enable 10-type drift detection.
    #[serde(default = "default_true")]
    pub enable_full_drift_detection: bool,

    /// Trust State computation interval (ms).
    #[serde(default = "default_trust_state_interval")]
    pub trust_state_interval_ms: u64,
}

fn default_check_interval() -> u64 { 1000 }
fn default_window_size() -> usize { 1000 }
fn default_drift_threshold() -> f64 { 3.0 }
fn default_true() -> bool { true }
fn default_trust_state_interval() -> u64 { 5000 }

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: default_check_interval(),
            drift_window_size: default_window_size(),
            drift_sigma_threshold: default_drift_threshold(),
            enable_full_drift_detection: default_true(),
            trust_state_interval_ms: default_trust_state_interval(),
        }
    }
}

/// Phoenix: autonomous recovery intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoenixConfig {
    /// Enable autonomous recovery (otherwise Phoenix only recommends).
    #[serde(default = "default_true")]
    pub autonomous: bool,

    /// Max recovery actions per hour (rate limit to prevent recovery loops).
    #[serde(default = "default_max_recovery")]
    pub max_recovery_actions_per_hour: u32,

    /// Cooldown between recovery actions (ms).
    #[serde(default = "default_cooldown")]
    pub recovery_cooldown_ms: u64,

    /// How far back to keep recovery history (hours).
    #[serde(default = "default_history_hours")]
    pub history_retention_hours: u64,

    /// Confidence threshold before Phoenix acts (0.0-1.0).
    /// Higher = more cautious, fewer false-positive recoveries.
    #[serde(default = "default_action_confidence")]
    pub action_confidence_threshold: f64,
}

fn default_max_recovery() -> u32 { 20 }
fn default_cooldown() -> u64 { 30_000 }
fn default_history_hours() -> u64 { 168 } // 7 days
fn default_action_confidence() -> f64 { 0.85 }

impl Default for PhoenixConfig {
    fn default() -> Self {
        Self {
            autonomous: default_true(),
            max_recovery_actions_per_hour: default_max_recovery(),
            recovery_cooldown_ms: default_cooldown(),
            history_retention_hours: default_history_hours(),
            action_confidence_threshold: default_action_confidence(),
        }
    }
}

/// Anchor: root of trust and cryptographic attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorConfig {
    /// Enable hardware root of trust (TPM/TEE) if available.
    #[serde(default)]
    pub enable_hardware_root: bool,

    /// Path to the immutable manifest (hashes of all trusted binaries/configs).
    #[serde(default = "default_manifest_path")]
    pub manifest_path: String,

    /// Enable runtime integrity verification (hash policies, configs in-memory).
    #[serde(default = "default_true")]
    pub verify_runtime_integrity: bool,

    /// Key rotation interval (hours).
    #[serde(default = "default_key_rotation")]
    pub key_rotation_hours: u64,

    /// Store secrets in encrypted on-disk store.
    #[serde(default = "default_true")]
    pub encrypted_store: bool,
}

fn default_manifest_path() -> String { "./ananta_state/manifest.json".into() }
fn default_key_rotation() -> u64 { 720 } // 30 days

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            enable_hardware_root: false,
            manifest_path: default_manifest_path(),
            verify_runtime_integrity: true,
            key_rotation_hours: default_key_rotation(),
            encrypted_store: true,
        }
    }
}

/// Adapter: adaptive security orchestration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Enable adaptive pipeline reconfiguration.
    #[serde(default)]
    pub enabled: bool,

    /// Max pipeline reconfigurations per hour.
    #[serde(default = "default_max_reconfig")]
    pub max_reconfigurations_per_hour: u32,

    /// Require cryptographic signing for all pipeline changes.
    #[serde(default = "default_true")]
    pub require_signed_changes: bool,

    /// Grace period (ms) before an adapted pipeline is reverted if
    /// no improvement is detected.
    #[serde(default = "default_grace_period")]
    pub adaptation_grace_period_ms: u64,
}

fn default_max_reconfig() -> u32 { 10 }
fn default_grace_period() -> u64 { 300_000 } // 5 min

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_reconfigurations_per_hour: default_max_reconfig(),
            require_signed_changes: true,
            adaptation_grace_period_ms: default_grace_period(),
        }
    }
}

/// Trust Proof Engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustProofConfig {
    /// Enable trust proof generation.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How often (ms) to generate a new trust proof.
    #[serde(default = "default_proof_interval")]
    pub generation_interval_ms: u64,

    /// Number of proofs to retain for audit.
    #[serde(default = "default_proof_retention")]
    pub retention_count: usize,

    /// Include runtime memory state hashes in proof (more expensive).
    #[serde(default)]
    pub include_runtime_hashes: bool,
}

fn default_proof_interval() -> u64 { 5000 }
fn default_proof_retention() -> usize { 1000 }

impl Default for TrustProofConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            generation_interval_ms: default_proof_interval(),
            retention_count: default_proof_retention(),
            include_runtime_hashes: false,
        }
    }
}

/// Health Model configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Enable platform-wide health graph.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Health graph computation interval (ms).
    #[serde(default = "default_health_interval")]
    pub computation_interval_ms: u64,

    /// Anomaly prediction look-ahead window (seconds).
    #[serde(default = "default_prediction_window")]
    pub prediction_window_secs: u64,
}

fn default_health_interval() -> u64 { 2000 }
fn default_prediction_window() -> u64 { 300 } // 5 min

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            computation_interval_ms: default_health_interval(),
            prediction_window_secs: default_prediction_window(),
        }
    }
}

/// Audit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable ANANTA's own immutable audit trail (separate from Keshav's).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Max audit entries before compaction.
    #[serde(default = "default_max_entries")]
    pub max_entries_before_compaction: usize,

    /// Enable cryptographic chaining of audit entries (tamper evidence).
    #[serde(default = "default_true")]
    pub chained_entries: bool,
}

fn default_max_entries() -> usize { 100_000 }

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries_before_compaction: default_max_entries(),
            chained_entries: true,
        }
    }
}

/// Distributed configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedConfig {
    /// Enable distributed ANANTA (multi-node consensus).
    #[serde(default)]
    pub enabled: bool,

    /// Quorum size for trust decisions.
    #[serde(default = "default_quorum")]
    pub quorum_size: u8,

    /// Node ID for this instance.
    pub node_id: Option<String>,

    /// Peer addresses for cluster communication.
    #[serde(default)]
    pub peers: Vec<String>,
}

fn default_quorum() -> u8 { 3 }

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            quorum_size: default_quorum(),
            node_id: None,
            peers: vec![],
        }
    }
}

/// Cryptographic configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Hash algorithm for integrity verification.
    #[serde(default = "default_hash_algo")]
    pub hash_algorithm: HashAlgorithm,

    /// Key derivation iterations.
    #[serde(default = "default_kdf_iterations")]
    pub kdf_iterations: u32,
}

fn default_hash_algo() -> HashAlgorithm { HashAlgorithm::Sha256 }
fn default_kdf_iterations() -> u32 { 100_000 }

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: default_hash_algo(),
            kdf_iterations: default_kdf_iterations(),
        }
    }
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Blake3,
}

/// A configuration validation warning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigWarning {
    pub field: String,
    pub message: String,
    pub severity: WarningSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    Info,
    Warning,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let yaml = AnantaConfig::default_yaml();
        let config = AnantaConfig::from_yaml(&yaml).expect("default yaml parses");
        assert!(config.enabled);
        assert!(config.sentinel.enable_full_drift_detection);
        assert!(config.phoenix.autonomous);
        assert!(!config.adapter.enabled); // disabled by default (safety)
        assert!(config.trust_proof.enabled);
    }

    #[test]
    fn validation_catches_low_intervals() {
        let mut config = AnantaConfig::default();
        config.sentinel.check_interval_ms = 50;
        let warnings = config.validate();
        assert!(warnings.iter().any(|w| w.field == "sentinel.check_interval_ms"));
    }

    #[test]
    fn validation_catches_low_quorum() {
        let mut config = AnantaConfig::default();
        config.distributed.enabled = true;
        config.distributed.quorum_size = 1;
        let warnings = config.validate();
        assert!(warnings.iter().any(|w| w.field == "distributed.quorum_size"));
    }

    #[test]
    fn hash_algorithm_serialization() {
        let yaml = r#"{ hash_algorithm: blake3 }"#;
        let config: CryptoConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hash_algorithm, HashAlgorithm::Blake3);
    }
}
