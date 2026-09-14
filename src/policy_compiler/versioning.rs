// Policy Versioning — semver management, version store, diff, and rollback.
//
// Provides semantic versioning for compiled policies, a history store
// for tracking versions, diff computation between versions, and
// rollback capability to restore previous policy states.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── PolicyVersion (semver) ────────────────────────────────────────────

/// Semantic version for policy artifacts.
///
/// Follows the MAJOR.MINOR.PATCH convention:
///   - MAJOR: breaking changes to rule semantics or bytecode format
///   - MINOR: new rules, non-breaking changes
///   - PATCH: bug fixes, metadata changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PolicyVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PolicyVersion {
    /// Create a new policy version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a version string "MAJOR.MINOR.PATCH".
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(format!(
                "invalid version '{}': expected MAJOR.MINOR.PATCH",
                s
            ));
        }
        let major = parts[0]
            .parse::<u32>()
            .map_err(|e| format!("invalid major version '{}': {}", parts[0], e))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|e| format!("invalid minor version '{}': {}", parts[1], e))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|e| format!("invalid patch version '{}': {}", parts[2], e))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// Bump the major version.
    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    /// Bump the minor version.
    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    /// Bump the patch version.
    pub fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }

    /// Returns true if this is a pre-release version (any component is 0 and others exist).
    pub fn is_prerelease(&self) -> bool {
        self.major == 0
    }
}

impl std::fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl std::str::FromStr for PolicyVersion {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl PartialOrd for PolicyVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PolicyVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

// ── VersionedPolicy ────────────────────────────────────────────────────

/// A compiled policy with version metadata and hashes.
#[derive(Debug, Clone)]
pub struct VersionedPolicy {
    /// Semantic version of this policy.
    pub version: PolicyVersion,
    /// Hash of the compiled bytecode (for integrity checks).
    pub bytecode_hash: String,
    /// Hash of the source YAML policy.
    pub source_yaml_hash: String,
    /// Timestamp when this version was compiled.
    pub compiled_at: u64,
    /// Parent version (None for the initial version).
    pub parent_version: Option<PolicyVersion>,
    /// Serialized bytecode (compressed for storage).
    pub bytecode_bytes: Vec<u8>,
    /// Rule count in this version.
    pub rule_count: u32,
}

impl VersionedPolicy {
    /// Create a new versioned policy.
    pub fn new(
        version: PolicyVersion,
        bytecode_hash: String,
        source_yaml_hash: String,
        compiled_at: u64,
        parent_version: Option<PolicyVersion>,
        bytecode_bytes: Vec<u8>,
        rule_count: u32,
    ) -> Self {
        Self {
            version,
            bytecode_hash,
            source_yaml_hash,
            compiled_at,
            parent_version,
            bytecode_bytes,
            rule_count,
        }
    }
}

// ── Version Diff ───────────────────────────────────────────────────────

/// Describes the differences between two policy versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    /// Old version.
    pub old_version: String,
    /// New version.
    pub new_version: String,
    /// Whether the bytecode hash changed.
    pub bytecode_changed: bool,
    /// Whether the source YAML changed.
    pub source_changed: bool,
    /// Number of rules added.
    pub rules_added: u32,
    /// Number of rules removed.
    pub rules_removed: u32,
    /// Names of added rules.
    pub added_rule_names: Vec<String>,
    /// Names of removed rules.
    pub removed_rule_names: Vec<String>,
}

impl VersionDiff {
    /// Returns true if this diff represents no changes.
    pub fn is_empty(&self) -> bool {
        !self.bytecode_changed
            && !self.source_changed
            && self.rules_added == 0
            && self.rules_removed == 0
    }
}

// ── PolicyVersionStore ─────────────────────────────────────────────────

/// In-memory store for policy version history.
///
/// Tracks compiled policies across versions, supports diff computation
/// and rollback to previous versions.
#[derive(Debug, Clone, Default)]
pub struct PolicyVersionStore {
    /// All stored versions, keyed by version string.
    versions: HashMap<String, VersionedPolicy>,
    /// Ordered list of version strings (insertion order).
    version_order: Vec<String>,
    /// Maximum number of versions to retain.
    max_versions: usize,
}

impl PolicyVersionStore {
    /// Create a new version store with the given capacity.
    pub fn new(max_versions: usize) -> Self {
        Self {
            versions: HashMap::new(),
            version_order: Vec::new(),
            max_versions,
        }
    }

    /// Store a new versioned policy.
    ///
    /// Returns the version string that was stored. If the store is at capacity,
    /// the oldest version is evicted.
    pub fn store(&mut self, policy: VersionedPolicy) -> String {
        let key = policy.version.to_string();

        // Evict oldest versions if at capacity.
        while self.version_order.len() >= self.max_versions {
            let oldest = self.version_order.remove(0);
            self.versions.remove(&oldest);
        }

        self.versions.insert(key.clone(), policy);
        self.version_order.push(key.clone());

        key
    }

    /// Retrieve a versioned policy by version string.
    pub fn get(&self, version: &str) -> Option<&VersionedPolicy> {
        self.versions.get(version)
    }

    /// Retrieve the latest (most recent) versioned policy.
    pub fn latest(&self) -> Option<&VersionedPolicy> {
        self.version_order
            .last()
            .and_then(|key| self.versions.get(key))
    }

    /// Retrieve the latest version string.
    pub fn latest_version(&self) -> Option<&str> {
        self.version_order.last().map(|s| s.as_str())
    }

    /// Number of stored versions.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Compute a diff between two versions.
    pub fn diff(&self, old_version: &str, new_version: &str) -> Result<VersionDiff, String> {
        let old = self
            .versions
            .get(old_version)
            .ok_or_else(|| format!("version '{}' not found", old_version))?;
        let new = self
            .versions
            .get(new_version)
            .ok_or_else(|| format!("version '{}' not found", new_version))?;

        let bytecode_changed = old.bytecode_hash != new.bytecode_hash;
        let source_changed = old.source_yaml_hash != new.source_yaml_hash;

        // Rule count diff (we don't have rule names in VersionedPolicy,
        // so we approximate with count difference).
        let new_count = new.rule_count as i32;
        let old_count = old.rule_count as i32;

        let (added, removed) = if new_count >= old_count {
            ((new_count - old_count) as u32, 0)
        } else {
            (0, (old_count - new_count) as u32)
        };

        Ok(VersionDiff {
            old_version: old_version.to_string(),
            new_version: new_version.to_string(),
            bytecode_changed,
            source_changed,
            rules_added: added,
            rules_removed: removed,
            added_rule_names: Vec::new(), // Would need rule name tracking
            removed_rule_names: Vec::new(),
        })
    }

    /// Compute diff between the latest version and the previous version.
    pub fn latest_diff(&self) -> Result<VersionDiff, String> {
        if self.version_order.len() < 2 {
            return Err("need at least 2 versions for a diff".into());
        }
        let n = self.version_order.len();
        self.diff(&self.version_order[n - 2], &self.version_order[n - 1])
    }

    /// Rollback to a specific version by returning its bytecode.
    ///
    /// Does not remove newer versions — they remain in history.
    pub fn rollback(&self, version: &str) -> Result<&VersionedPolicy, String> {
        self.versions
            .get(version)
            .ok_or_else(|| format!("version '{}' not found for rollback", version))
    }

    /// List all version strings in chronological order.
    pub fn list_versions(&self) -> &[String] {
        &self.version_order
    }

    /// Clear all stored versions.
    pub fn clear(&mut self) {
        self.versions.clear();
        self.version_order.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse() {
        let v = PolicyVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn version_parse_invalid() {
        assert!(PolicyVersion::parse("1.2").is_err());
        assert!(PolicyVersion::parse("1.2.3.4").is_err());
        assert!(PolicyVersion::parse("abc.def.ghi").is_err());
    }

    #[test]
    fn version_display() {
        let v = PolicyVersion::new(2, 5, 1);
        assert_eq!(format!("{}", v), "2.5.1");
    }

    #[test]
    fn version_from_str() {
        let v: PolicyVersion = "3.14.0".parse().unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 14);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn version_ordering() {
        let v100 = PolicyVersion::new(1, 0, 0);
        let v110 = PolicyVersion::new(1, 1, 0);
        let v101 = PolicyVersion::new(1, 0, 1);
        let v200 = PolicyVersion::new(2, 0, 0);

        assert!(v100 < v101);
        assert!(v101 < v110);
        assert!(v110 < v200);
        assert!(v200 > v100);
    }

    #[test]
    fn version_equality() {
        let a = PolicyVersion::parse("1.2.3").unwrap();
        let b = PolicyVersion::parse("1.2.3").unwrap();
        let c = PolicyVersion::parse("1.2.4").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn version_bump_major() {
        let v = PolicyVersion::new(1, 2, 3);
        let bumped = v.bump_major();
        assert_eq!(bumped, PolicyVersion::new(2, 0, 0));
    }

    #[test]
    fn version_bump_minor() {
        let v = PolicyVersion::new(1, 2, 3);
        let bumped = v.bump_minor();
        assert_eq!(bumped, PolicyVersion::new(1, 3, 0));
    }

    #[test]
    fn version_bump_patch() {
        let v = PolicyVersion::new(1, 2, 3);
        let bumped = v.bump_patch();
        assert_eq!(bumped, PolicyVersion::new(1, 2, 4));
    }

    #[test]
    fn version_prerelease() {
        let pre = PolicyVersion::new(0, 1, 0);
        let release = PolicyVersion::new(1, 0, 0);
        assert!(pre.is_prerelease());
        assert!(!release.is_prerelease());
    }

    #[test]
    fn store_store_and_retrieve() {
        let mut store = PolicyVersionStore::new(10);
        let policy = VersionedPolicy::new(
            PolicyVersion::new(1, 0, 0),
            "hash1".into(),
            "yaml_hash1".into(),
            1000,
            None,
            vec![0x01, 0x02, 0x03],
            5,
        );
        let key = store.store(policy);
        assert_eq!(key, "1.0.0");

        let retrieved = store.get("1.0.0").unwrap();
        assert_eq!(retrieved.bytecode_hash, "hash1");
        assert_eq!(retrieved.rule_count, 5);
    }

    #[test]
    fn store_latest() {
        let mut store = PolicyVersionStore::new(10);
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 0, 0),
            "h1".into(),
            "y1".into(),
            1,
            None,
            vec![],
            1,
        ));
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 1, 0),
            "h2".into(),
            "y2".into(),
            2,
            Some(PolicyVersion::new(1, 0, 0)),
            vec![0x01],
            2,
        ));

        let latest = store.latest().unwrap();
        assert_eq!(latest.version, PolicyVersion::new(1, 1, 0));
        assert_eq!(store.latest_version(), Some("1.1.0"));
    }

    #[test]
    fn store_eviction() {
        let mut store = PolicyVersionStore::new(2);
        store.store(make_versioned("0.1.0", "h1"));
        store.store(make_versioned("0.2.0", "h2"));
        store.store(make_versioned("0.3.0", "h3"));

        // Oldest should be evicted.
        assert!(store.get("0.1.0").is_none());
        assert!(store.get("0.2.0").is_some());
        assert!(store.get("0.3.0").is_some());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_diff() {
        let mut store = PolicyVersionStore::new(10);
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 0, 0),
            "hash_a".into(),
            "yaml_a".into(),
            1,
            None,
            vec![],
            3,
        ));
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 1, 0),
            "hash_b".into(),
            "yaml_b".into(),
            2,
            Some(PolicyVersion::new(1, 0, 0)),
            vec![0x01],
            5,
        ));

        let diff = store.diff("1.0.0", "1.1.0").unwrap();
        assert!(diff.bytecode_changed);
        assert!(diff.source_changed);
        assert_eq!(diff.rules_added, 2);
        assert_eq!(diff.rules_removed, 0);
    }

    #[test]
    fn store_diff_empty() {
        let mut store = PolicyVersionStore::new(10);
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 0, 0),
            "hash".into(),
            "yaml".into(),
            1,
            None,
            vec![],
            3,
        ));
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 0, 1),
            "hash".into(),
            "yaml".into(),
            2,
            Some(PolicyVersion::new(1, 0, 0)),
            vec![],
            3,
        ));

        let diff = store.diff("1.0.0", "1.0.1").unwrap();
        assert!(!diff.bytecode_changed);
        assert!(!diff.source_changed);
        assert!(diff.is_empty());
    }

    #[test]
    fn store_rollback() {
        let mut store = PolicyVersionStore::new(10);
        store.store(VersionedPolicy::new(
            PolicyVersion::new(1, 0, 0),
            "old_hash".into(),
            "old_yaml".into(),
            1,
            None,
            vec![0xAA, 0xBB],
            3,
        ));
        store.store(VersionedPolicy::new(
            PolicyVersion::new(2, 0, 0),
            "new_hash".into(),
            "new_yaml".into(),
            2,
            Some(PolicyVersion::new(1, 0, 0)),
            vec![0xCC, 0xDD],
            7,
        ));

        let rolled_back = store.rollback("1.0.0").unwrap();
        assert_eq!(rolled_back.bytecode_hash, "old_hash");
        assert_eq!(rolled_back.bytecode_bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn store_rollback_not_found() {
        let store = PolicyVersionStore::new(10);
        let result = store.rollback("99.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn store_list_versions() {
        let mut store = PolicyVersionStore::new(10);
        store.store(make_versioned("1.0.0", "h1"));
        store.store(make_versioned("1.1.0", "h2"));
        store.store(make_versioned("2.0.0", "h3"));

        let versions = store.list_versions();
        assert_eq!(versions, &["1.0.0", "1.1.0", "2.0.0"]);
    }

    #[test]
    fn store_clear() {
        let mut store = PolicyVersionStore::new(10);
        store.store(make_versioned("1.0.0", "h1"));
        store.store(make_versioned("1.1.0", "h2"));
        assert_eq!(store.len(), 2);

        store.clear();
        assert!(store.is_empty());
        assert!(store.latest().is_none());
    }

    #[test]
    fn store_diff_not_enough_versions() {
        let store = PolicyVersionStore::new(10);
        let result = store.latest_diff();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 2"));
    }

    #[test]
    fn store_latest_diff_success() {
        let mut store = PolicyVersionStore::new(10);
        store.store(make_versioned("1.0.0", "hash_a"));
        store.store(make_versioned("1.1.0", "hash_b"));

        let diff = store.latest_diff().unwrap();
        assert_eq!(diff.old_version, "1.0.0");
        assert_eq!(diff.new_version, "1.1.0");
        assert!(diff.bytecode_changed);
    }

    // ── Helper ────────────────────────────────────────────────────

    fn make_versioned(ver: &str, hash: &str) -> VersionedPolicy {
        let v = PolicyVersion::parse(ver).unwrap();
        VersionedPolicy::new(
            v,
            hash.to_string(),
            format!("yaml_{}", hash),
            0,
            None,
            vec![],
            0,
        )
    }
}
