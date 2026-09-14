// Integrity verification — the core of Anchor.
//
// Checks:
//   1. Binary integrity (hash of running binary vs manifest)
//   2. Config integrity (hash of loaded configs vs manifest)
//   3. Policy integrity (hash of active policy vs manifest)
//   4. Runtime integrity (hash of in-memory state structures)
//   5. Plugin/module integrity (hash of loaded .rs source hashes)

use crate::ananta::anchor::manifest::Manifest;
use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::{hash_bytes, HashDigest};
use crate::ananta::crypto::merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Result of an integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    /// What was checked.
    pub component: String,
    /// Expected hash (from manifest).
    pub expected: Option<HashDigest>,
    /// Actual hash (computed now).
    pub actual: HashDigest,
    /// Whether the check passed.
    pub passed: bool,
    /// Time taken to compute.
    pub check_duration_ms: f64,
}

impl IntegrityResult {
    pub fn failed(
        component: &str,
        expected: &HashDigest,
        actual: HashDigest,
        duration_ms: f64,
    ) -> Self {
        Self {
            component: component.into(),
            expected: Some(expected.clone()),
            actual,
            passed: false,
            check_duration_ms: duration_ms,
        }
    }

    pub fn passed(component: &str, actual: HashDigest, duration_ms: f64) -> Self {
        Self {
            component: component.into(),
            expected: None,
            actual,
            passed: true,
            check_duration_ms: duration_ms,
        }
    }
}

/// What integrity domains to check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntegrityDomain {
    /// The CHAKRAVYUH binary itself.
    Binary,
    /// Keshav configuration (main config).
    Config,
    /// Active security policy.
    Policy,
    /// ANANTA's own configuration.
    AnantaConfig,
    /// Individual ring configurations.
    RingConfig(String),
    /// Runtime state snapshot.
    Runtime,
    /// Loaded modules/plugins.
    Modules,
}

impl std::fmt::Display for IntegrityDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityDomain::Binary => write!(f, "binary"),
            IntegrityDomain::Config => write!(f, "config"),
            IntegrityDomain::Policy => write!(f, "policy"),
            IntegrityDomain::AnantaConfig => write!(f, "ananta_config"),
            IntegrityDomain::RingConfig(name) => write!(f, "ring_config:{}", name),
            IntegrityDomain::Runtime => write!(f, "runtime"),
            IntegrityDomain::Modules => write!(f, "modules"),
        }
    }
}

/// Performs integrity checks against the manifest.
///
/// The IntegrityChecker is the workhorse of Anchor.
/// It hashes live data and compares against the immutable manifest.
pub struct IntegrityChecker {
    algorithm: HashAlgorithm,
    /// Live data providers — functions that return current state to hash.
    /// Bounded by Send + Sync so IntegrityChecker can be used inside
    /// Arc<RwLock<_>> and moved across tokio tasks.
    providers: HashMap<IntegrityDomain, Box<dyn Fn() -> Vec<u8> + Send + Sync>>,
}

impl IntegrityChecker {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            providers: HashMap::new(),
        }
    }

    /// Register a data provider for a domain.
    /// The provider returns raw bytes that will be hashed.
    pub fn register_provider(
        &mut self,
        domain: IntegrityDomain,
        provider: impl Fn() -> Vec<u8> + Send + Sync + 'static,
    ) {
        self.providers.insert(domain, Box::new(provider));
    }

    /// Check a single domain against the manifest.
    pub fn check_domain(&self, domain: &IntegrityDomain, manifest: &Manifest) -> IntegrityResult {
        let start = Instant::now();

        let data = match self.providers.get(domain) {
            Some(provider) => provider(),
            None => {
                return IntegrityResult::passed(
                    &domain.to_string(),
                    hash_bytes(b"no_provider_registered", &self.algorithm),
                    start.elapsed().as_secs_f64() * 1000.0,
                )
            }
        };

        let actual = hash_bytes(&data, &self.algorithm);
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        let key = domain.to_string();
        if let Some(expected) = manifest.get(&key) {
            IntegrityResult {
                component: key,
                expected: Some(expected.clone()),
                passed: expected.bytes == actual.bytes,
                actual,
                check_duration_ms: duration_ms,
            }
        } else {
            // No manifest entry — record but don't fail.
            IntegrityResult::passed(&key, actual, duration_ms)
        }
    }

    /// Check all registered domains against the manifest.
    pub fn check_all(&self, manifest: &Manifest) -> Vec<IntegrityResult> {
        let mut results = Vec::new();

        // Check all registered providers.
        for domain in self.providers.keys() {
            results.push(self.check_domain(domain, manifest));
        }

        // Also check manifest entries that have no provider.
        for key in manifest
            .entries()
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>()
        {
            let domain_str = key.as_str();
            let has_provider = self.providers.keys().any(|d| d.to_string() == domain_str);
            if !has_provider {
                let expected = manifest.get(&key).unwrap();
                results.push(IntegrityResult {
                    component: key.clone(),
                    expected: Some(expected.clone()),
                    actual: hash_bytes(b"no_provider", &self.algorithm),
                    passed: false,
                    check_duration_ms: 0.0,
                });
            }
        }

        results
    }

    /// Compute the Merkle root of all domain hashes.
    /// This is a single hash that represents the integrity of the entire platform.
    pub fn platform_merkle_root(&self, manifest: &Manifest) -> HashDigest {
        let results = self.check_all(manifest);
        let data: Vec<&[u8]> = results.iter().map(|r| r.actual.bytes.as_slice()).collect();
        let tree = MerkleTree::from_data(&data, &self.algorithm);
        tree.root
    }

    /// Generate a comprehensive integrity snapshot.
    pub fn snapshot(&self, manifest: &Manifest) -> IntegritySnapshot {
        let results = self.check_all(manifest);
        let merkle_root = self.platform_merkle_root(manifest);
        let passed = results.iter().all(|r| r.passed);
        let failed_count = results.iter().filter(|r| !r.passed).count();
        let total_check_ms: f64 = results.iter().map(|r| r.check_duration_ms).sum();

        IntegritySnapshot {
            timestamp: chrono::Utc::now().to_rfc3339(),
            merkle_root,
            results,
            passed,
            failed_count,
            total_check_ms,
        }
    }
}

/// A point-in-time integrity snapshot of the entire platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegritySnapshot {
    pub timestamp: String,
    pub merkle_root: HashDigest,
    pub results: Vec<IntegrityResult>,
    pub passed: bool,
    pub failed_count: usize,
    pub total_check_ms: f64,
}

impl IntegritySnapshot {
    /// Summarize the snapshot.
    pub fn summary(&self) -> String {
        if self.passed {
            format!(
                "OK — {} domains verified in {:.1}ms",
                self.results.len(),
                self.total_check_ms
            )
        } else {
            format!(
                "FAILED — {}/{} domains failed in {:.1}ms",
                self.failed_count,
                self.results.len(),
                self.total_check_ms
            )
        }
    }

    /// Get the list of failed components.
    pub fn failed_components(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.component.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest() -> Manifest {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert(
            "config".into(),
            crate::ananta::crypto::hash("valid_config_data", &HashAlgorithm::Sha256),
        );
        m.insert(
            "policy".into(),
            crate::ananta::crypto::hash("valid_policy_data", &HashAlgorithm::Sha256),
        );
        m
    }

    #[test]
    fn check_domain_passes() {
        let manifest = test_manifest();
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        checker.register_provider(IntegrityDomain::Config, || b"valid_config_data".to_vec());

        let result = checker.check_domain(&IntegrityDomain::Config, &manifest);
        assert!(result.passed);
    }

    #[test]
    fn check_domain_detects_tampering() {
        let manifest = test_manifest();
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        checker.register_provider(IntegrityDomain::Config, || b"tampered_config_data".to_vec());

        let result = checker.check_domain(&IntegrityDomain::Config, &manifest);
        assert!(!result.passed);
    }

    #[test]
    fn check_all_covers_providers_and_manifest() {
        let manifest = test_manifest();
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        checker.register_provider(IntegrityDomain::Config, || b"valid_config_data".to_vec());
        // Policy has no provider.

        let results = checker.check_all(&manifest);
        assert!(results.len() >= 2); // config (from provider) + policy (from manifest)
    }

    #[test]
    fn snapshot_summary() {
        let manifest = test_manifest();
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        checker.register_provider(IntegrityDomain::Config, || b"valid_config_data".to_vec());

        let snapshot = checker.snapshot(&manifest);
        assert!(snapshot.merkle_root.bytes.len() == 32);
        // Policy has no provider so it'll fail.
        assert!(!snapshot.passed);
    }

    #[test]
    fn platform_merkle_root_deterministic() {
        let manifest = test_manifest();
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        checker.register_provider(IntegrityDomain::Config, || b"valid_config_data".to_vec());

        let r1 = checker.platform_merkle_root(&manifest);
        let r2 = checker.platform_merkle_root(&manifest);
        assert_eq!(r1.bytes, r2.bytes);
    }
}
