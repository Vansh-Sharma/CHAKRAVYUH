// Plugin Marketplace — Manifest, signing, versioning, dependency
// resolution, permission validation, search, and hot-reload for CHAKRAVYUH plugins.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// Version
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic version: MAJOR.MINOR.PATCH.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parse "1.2.3" into a Version.
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(format!(
                "invalid version '{}': expected MAJOR.MINOR.PATCH",
                s
            ));
        }
        let major = parts[0]
            .parse::<u32>()
            .map_err(|e| format!("invalid major '{}': {}", parts[0], e))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|e| format!("invalid minor '{}': {}", parts[1], e))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|e| format!("invalid patch '{}': {}", parts[2], e))?;
        Ok(Version {
            major,
            minor,
            patch,
        })
    }

    /// Check compatibility: same major version.
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                std::cmp::Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginPermission
// ─────────────────────────────────────────────────────────────────────────────

/// Permissions a plugin can request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginPermission {
    ReadRequest,
    WriteDecision,
    AccessHeaders,
    EmitMetrics,
    AccessConfig,
    NetworkAccess,
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginDependency
// ─────────────────────────────────────────────────────────────────────────────

/// A dependency on another plugin with a version requirement string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub name: String,
    pub version_req: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginManifest
// ─────────────────────────────────────────────────────────────────────────────

/// Full manifest describing a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: Version,
    pub display_name: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub ring_target: String,
    pub hook_point: String,
    pub wasm_bytes_hash: String,
    pub config_schema: HashMap<String, String>,
    pub dependencies: Vec<PluginDependency>,
    pub permissions: Vec<PluginPermission>,
    pub checksum: String,
    pub created_at: String,
    pub updated_at: String,
}

impl PluginManifest {
    pub fn new(name: &str, version: Version) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            name: name.to_string(),
            version,
            display_name: name.to_string(),
            description: String::new(),
            author: String::new(),
            license: "Apache-2.0".to_string(),
            ring_target: String::new(),
            hook_point: "pre-evaluate".to_string(),
            wasm_bytes_hash: String::new(),
            config_schema: HashMap::new(),
            dependencies: Vec::new(),
            permissions: Vec::new(),
            checksum: String::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = name.to_string();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_ring_target(mut self, ring: &str) -> Self {
        self.ring_target = ring.to_string();
        self
    }

    pub fn with_hook_point(mut self, hook: &str) -> Self {
        self.hook_point = hook.to_string();
        self
    }

    pub fn with_dependency(mut self, dep: PluginDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    pub fn with_permission(mut self, perm: PluginPermission) -> Self {
        self.permissions.push(perm);
        self
    }

    pub fn with_checksum(mut self, cksum: &str) -> Self {
        self.checksum = cksum.to_string();
        self
    }

    pub fn with_config_schema(mut self, key: &str, val: &str) -> Self {
        self.config_schema.insert(key.to_string(), val.to_string());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginSignature
// ─────────────────────────────────────────────────────────────────────────────

/// Simulated plugin signature for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSignature {
    pub public_key: String,
    pub signature: String,
    pub algorithm: String,
}

impl PluginSignature {
    pub fn new(public_key: &str, signature: &str) -> Self {
        Self {
            public_key: public_key.to_string(),
            signature: signature.to_string(),
            algorithm: "ed25519".to_string(),
        }
    }

    /// Simulated verification: checks that public_key and signature are non-empty.
    pub fn verify(&self) -> bool {
        !self.public_key.is_empty() && !self.signature.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisteredPlugin
// ─────────────────────────────────────────────────────────────────────────────

/// A plugin stored in the registry.
#[derive(Debug, Clone)]
pub struct RegisteredPlugin {
    pub manifest: PluginManifest,
    pub signature: PluginSignature,
    pub wasm_bytes: Vec<u8>,
    pub loaded_at: String,
    pub hot_reload_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Summary struct for plugin listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: Version,
    pub display_name: String,
    pub description: String,
    pub ring_target: String,
    pub hook_point: String,
    pub is_loaded: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// ReloadResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a hot-reload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResult {
    pub success: bool,
    pub old_version: Option<Version>,
    pub new_version: Version,
    pub reason: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry for plugins with dependency resolution, permission
/// validation, and search.
#[derive(Debug)]
pub struct PluginRegistry {
    plugins: HashMap<String, RegisteredPlugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a new plugin.
    pub fn register(
        &mut self,
        manifest: PluginManifest,
        signature: PluginSignature,
        wasm_bytes: Vec<u8>,
    ) -> std::result::Result<(), String> {
        if !signature.verify() {
            return Err("signature verification failed".to_string());
        }
        let name = manifest.name.clone();
        let now = chrono::Utc::now().to_rfc3339();
        self.plugins.insert(
            name,
            RegisteredPlugin {
                manifest,
                signature,
                wasm_bytes,
                loaded_at: now,
                hot_reload_count: 0,
            },
        );
        Ok(())
    }

    /// Unregister a plugin by name.
    pub fn unregister(&mut self, name: &str) -> std::result::Result<(), String> {
        if self.plugins.remove(name).is_some() {
            Ok(())
        } else {
            Err(format!("plugin '{}' not found in registry", name))
        }
    }

    /// Get a registered plugin by name.
    pub fn get(&self, name: &str) -> Option<&RegisteredPlugin> {
        self.plugins.get(name)
    }

    /// List all registered plugins as PluginInfo.
    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .values()
            .map(|p| PluginInfo {
                name: p.manifest.name.clone(),
                version: p.manifest.version.clone(),
                display_name: p.manifest.display_name.clone(),
                description: p.manifest.description.clone(),
                ring_target: p.manifest.ring_target.clone(),
                hook_point: p.manifest.hook_point.clone(),
                is_loaded: true,
            })
            .collect()
    }

    /// Check if a newer version is available for the given plugin.
    pub fn check_update(&self, name: &str, new_version: &Version) -> std::result::Result<bool, String> {
        let plugin = self
            .plugins
            .get(name)
            .ok_or_else(|| format!("plugin '{}' not found", name))?;
        Ok(new_version > &plugin.manifest.version)
    }

    /// Resolve dependencies using DFS with cycle detection.
    /// Returns the ordered list of plugin names to load.
    pub fn resolve_dependencies(&self, root: &str) -> std::result::Result<Vec<String>, String> {
        let mut order = Vec::new();
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        self.dfs(root, &mut visiting, &mut visited, &mut order)?;
        Ok(order)
    }

    fn dfs(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) -> std::result::Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if visiting.contains(name) {
            return Err(format!("circular dependency detected involving '{}'", name));
        }
        if !self.plugins.contains_key(name) {
            return Err(format!("dependency '{}' not found in registry", name));
        }
        visiting.insert(name.to_string());

        let plugin = &self.plugins[name];
        for dep in &plugin.manifest.dependencies {
            self.dfs(&dep.name, visiting, visited, order)?;
        }

        visiting.remove(name);
        visited.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    /// Validate that a plugin has the required permissions.
    pub fn validate_permissions(
        &self,
        name: &str,
        required: &[PluginPermission],
    ) -> std::result::Result<bool, String> {
        let plugin = self
            .plugins
            .get(name)
            .ok_or_else(|| format!("plugin '{}' not found", name))?;
        let has_all = required
            .iter()
            .all(|perm| plugin.manifest.permissions.contains(perm));
        Ok(has_all)
    }

    /// Search plugins by name substring or ring target.
    pub fn search(&self, query: &str) -> Vec<PluginInfo> {
        let query_lower = query.to_lowercase();
        self.plugins
            .values()
            .filter(|p| {
                p.manifest.name.to_lowercase().contains(&query_lower)
                    || p.manifest.display_name.to_lowercase().contains(&query_lower)
                    || p.manifest.ring_target.to_lowercase().contains(&query_lower)
            })
            .map(|p| PluginInfo {
                name: p.manifest.name.clone(),
                version: p.manifest.version.clone(),
                display_name: p.manifest.display_name.clone(),
                description: p.manifest.description.clone(),
                ring_target: p.manifest.ring_target.clone(),
                hook_point: p.manifest.hook_point.clone(),
                is_loaded: true,
            })
            .collect()
    }

    /// Get the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HotReloadManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages hot-reload of registered plugins.
#[derive(Debug)]
pub struct HotReloadManager {
    registry: Arc<RwLock<PluginRegistry>>,
    reload_count: std::sync::atomic::AtomicU64,
    last_reload: std::sync::RwLock<Option<std::time::Instant>>,
}

impl HotReloadManager {
    pub fn new(registry: Arc<RwLock<PluginRegistry>>) -> Self {
        Self {
            registry,
            reload_count: std::sync::atomic::AtomicU64::new(0),
            last_reload: std::sync::RwLock::new(None),
        }
    }

    /// Hot-reload a single plugin by name. Increments its patch version.
    pub fn reload(&self, name: &str) -> std::result::Result<ReloadResult, String> {
        let mut reg = self
            .registry
            .write()
            .map_err(|_| "registry lock poisoned".to_string())?;

        let plugin = reg
            .plugins
            .get_mut(name)
            .ok_or_else(|| format!("plugin '{}' not found for reload", name))?;

        let old_version = Some(plugin.manifest.version.clone());
        plugin.manifest.version = Version::new(
            plugin.manifest.version.major,
            plugin.manifest.version.minor,
            plugin.manifest.version.patch + 1,
        );
        plugin.manifest.updated_at = chrono::Utc::now().to_rfc3339();
        plugin.hot_reload_count += 1;
        let new_version = plugin.manifest.version.clone();

        drop(reg);

        self.reload_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut last) = self.last_reload.write() {
            *last = Some(std::time::Instant::now());
        }

        Ok(ReloadResult {
            success: true,
            old_version,
            new_version,
            reason: "patch version bumped".to_string(),
        })
    }

    /// Hot-reload all registered plugins.
    pub fn reload_all(&self) -> std::result::Result<Vec<ReloadResult>, String> {
        let names: Vec<String> = {
            let reg = self
                .registry
                .read()
                .map_err(|_| "registry lock poisoned".to_string())?;
            reg.plugins.keys().cloned().collect()
        };

        let mut results = Vec::new();
        for name in &names {
            match self.reload(name) {
                Ok(r) => results.push(r),
                Err(e) => results.push(ReloadResult {
                    success: false,
                    old_version: None,
                    new_version: Version::new(0, 0, 0),
                    reason: e,
                }),
            }
        }
        Ok(results)
    }

    /// Get the time of the last reload, if any.
    pub fn last_reload(&self) -> Option<std::time::Instant> {
        self.last_reload.read().ok()?.clone()
    }

    /// Get the total number of reloads performed.
    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest(name: &str, version: &str) -> PluginManifest {
        PluginManifest::new(name, Version::parse(version).unwrap())
            .with_description(format!("{} plugin", name).as_str())
    }

    fn make_signature() -> PluginSignature {
        PluginSignature::new("test-key", "test-sig")
    }

    fn make_registry_with_plugins() -> PluginRegistry {
        let mut reg = PluginRegistry::new();
        reg.register(make_manifest("core-lib", "1.0.0"), make_signature(), vec![])
            .unwrap();
        reg.register(
            make_manifest("shield-plugin", "2.1.0")
                .with_dependency(PluginDependency {
                    name: "core-lib".to_string(),
                    version_req: ">=1.0.0".to_string(),
                }),
            make_signature(),
            vec![],
        )
        .unwrap();
        reg
    }

    // ── Version tests ──

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_parse_invalid() {
        assert!(Version::parse("1.2").is_err());
        assert!(Version::parse("a.b.c").is_err());
        assert!(Version::parse("1.2.3.4").is_err());
        assert!(Version::parse("").is_err());
    }

    #[test]
    fn test_version_display() {
        assert_eq!(format!("{}", Version::new(3, 14, 159)), "3.14.159");
    }

    #[test]
    fn test_version_ord() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);
        let v4 = Version::new(1, 0, 1);
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v4);
        assert!(v4 < v2);
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 5, 0);
        let v3 = Version::new(2, 0, 0);
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    // ── Signature tests ──

    #[test]
    fn test_signature_verify_valid() {
        let sig = PluginSignature::new("pk", "sig");
        assert!(sig.verify());
    }

    #[test]
    fn test_signature_verify_empty_key() {
        let sig = PluginSignature::new("", "sig");
        assert!(!sig.verify());
    }

    #[test]
    fn test_signature_verify_empty_sig() {
        let sig = PluginSignature::new("pk", "");
        assert!(!sig.verify());
    }

    // ── Registry tests ──

    #[test]
    fn test_register_and_get() {
        let mut reg = PluginRegistry::new();
        let manifest = make_manifest("test", "1.0.0");
        reg.register(manifest, make_signature(), vec![]).unwrap();
        let plugin = reg.get("test").unwrap();
        assert_eq!(plugin.manifest.name, "test");
    }

    #[test]
    fn test_register_invalid_signature() {
        let mut reg = PluginRegistry::new();
        let manifest = make_manifest("test", "1.0.0");
        let sig = PluginSignature::new("", "");
        let result = reg.register(manifest, sig, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unregister() {
        let mut reg = PluginRegistry::new();
        reg.register(make_manifest("test", "1.0.0"), make_signature(), vec![])
            .unwrap();
        assert_eq!(reg.len(), 1);
        reg.unregister("test").unwrap();
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_unregister_not_found() {
        let mut reg = PluginRegistry::new();
        let result = reg.unregister("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_plugins() {
        let reg = make_registry_with_plugins();
        let list = reg.list();
        assert_eq!(list.len(), 2);
        let names: Vec<&str> = list.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"core-lib"));
        assert!(names.contains(&"shield-plugin"));
    }

    #[test]
    fn test_check_update() {
        let reg = make_registry_with_plugins();
        assert!(reg.check_update("core-lib", &Version::new(1, 1, 0)).unwrap());
        assert!(!reg.check_update("core-lib", &Version::new(0, 9, 0)).unwrap());
    }

    #[test]
    fn test_resolve_dependencies() {
        let reg = make_registry_with_plugins();
        let order = reg.resolve_dependencies("shield-plugin").unwrap();
        assert_eq!(order.len(), 2);
        // core-lib must come before shield-plugin (topological order).
        let core_idx = order.iter().position(|n| n == "core-lib").unwrap();
        let shield_idx = order.iter().position(|n| n == "shield-plugin").unwrap();
        assert!(core_idx < shield_idx);
    }

    #[test]
    fn test_resolve_dependencies_cycle() {
        let mut reg = PluginRegistry::new();
        reg.register(
            make_manifest("a", "1.0.0")
                .with_dependency(PluginDependency {
                    name: "b".to_string(),
                    version_req: "*".to_string(),
                }),
            make_signature(),
            vec![],
        )
        .unwrap();
        reg.register(
            make_manifest("b", "1.0.0")
                .with_dependency(PluginDependency {
                    name: "a".to_string(),
                    version_req: "*".to_string(),
                }),
            make_signature(),
            vec![],
        )
        .unwrap();
        let result = reg.resolve_dependencies("a");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("circular"));
    }

    #[test]
    fn test_validate_permissions() {
        let mut reg = PluginRegistry::new();
        let manifest = make_manifest("secured", "1.0.0")
            .with_permission(PluginPermission::ReadRequest)
            .with_permission(PluginPermission::EmitMetrics);
        reg.register(manifest, make_signature(), vec![]).unwrap();

        assert!(reg
            .validate_permissions(
                "secured",
                &[PluginPermission::ReadRequest],
            )
            .unwrap());
        assert!(!reg
            .validate_permissions(
                "secured",
                &[PluginPermission::NetworkAccess],
            )
            .unwrap());
    }

    #[test]
    fn test_search_by_name() {
        let reg = make_registry_with_plugins();
        let results = reg.search("shield");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "shield-plugin");
    }

    #[test]
    fn test_search_by_ring() {
        let mut reg = PluginRegistry::new();
        reg.register(
            make_manifest("p1", "1.0.0").with_ring_target("threat"),
            make_signature(),
            vec![],
        )
        .unwrap();
        reg.register(
            make_manifest("p2", "1.0.0").with_ring_target("shield"),
            make_signature(),
            vec![],
        )
        .unwrap();
        let results = reg.search("threat");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "p1");
    }

    // ── HotReloadManager tests ──

    #[test]
    fn test_hot_reload_single() {
        let reg = Arc::new(RwLock::new(make_registry_with_plugins()));
        let mgr = HotReloadManager::new(reg);
        let result = mgr.reload("core-lib").unwrap();
        assert!(result.success);
        assert_eq!(result.old_version, Some(Version::new(1, 0, 0)));
        assert_eq!(result.new_version, Version::new(1, 0, 1));
    }

    #[test]
    fn test_hot_reload_not_found() {
        let reg = Arc::new(RwLock::new(PluginRegistry::new()));
        let mgr = HotReloadManager::new(reg);
        let result = mgr.reload("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn test_hot_reload_all() {
        let reg = Arc::new(RwLock::new(make_registry_with_plugins()));
        let mgr = HotReloadManager::new(reg);
        let results = mgr.reload_all().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_reload_count() {
        let reg = Arc::new(RwLock::new(make_registry_with_plugins()));
        let mgr = HotReloadManager::new(reg);
        assert_eq!(mgr.reload_count(), 0);
        let _ = mgr.reload("core-lib");
        assert_eq!(mgr.reload_count(), 1);
        let _ = mgr.reload("shield-plugin");
        assert_eq!(mgr.reload_count(), 2);
    }

    #[test]
    fn test_last_reload() {
        let reg = Arc::new(RwLock::new(make_registry_with_plugins()));
        let mgr = HotReloadManager::new(reg);
        assert!(mgr.last_reload().is_none());
        let _ = mgr.reload("core-lib");
        assert!(mgr.last_reload().is_some());
    }

    // ── Manifest builder tests ──

    #[test]
    fn test_manifest_builder() {
        let m = PluginManifest::new("test-plugin", Version::new(2, 0, 0))
            .with_display_name("Test Plugin")
            .with_description("A test")
            .with_author("VINOMOID")
            .with_ring_target("threat")
            .with_hook_point("post-evaluate")
            .with_permission(PluginPermission::ReadRequest)
            .with_config_schema("threshold", "f64")
            .with_checksum("abc123");
        assert_eq!(m.name, "test-plugin");
        assert_eq!(m.version, Version::new(2, 0, 0));
        assert_eq!(m.display_name, "Test Plugin");
        assert_eq!(m.author, "VINOMOID");
        assert_eq!(m.ring_target, "threat");
        assert_eq!(m.hook_point, "post-evaluate");
        assert_eq!(m.permissions.len(), 1);
        assert_eq!(m.config_schema.get("threshold").unwrap(), "f64");
        assert_eq!(m.checksum, "abc123");
    }

    #[test]
    fn test_plugin_permission_equality() {
        assert_eq!(PluginPermission::ReadRequest, PluginPermission::ReadRequest);
        assert_ne!(PluginPermission::ReadRequest, PluginPermission::NetworkAccess);
    }

    #[test]
    fn test_registry_len_and_is_empty() {
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        reg.register(make_manifest("a", "1.0.0"), make_signature(), vec![])
            .unwrap();
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_plugin_info_fields() {
        let info = PluginInfo {
            name: "p".to_string(),
            version: Version::new(1, 2, 3),
            display_name: "P".to_string(),
            description: "desc".to_string(),
            ring_target: String::new(),
            hook_point: "pre".to_string(),
            is_loaded: true,
        };
        assert_eq!(info.name, "p");
        assert_eq!(info.version, Version::new(1, 2, 3));
        assert!(info.is_loaded);
    }
}
