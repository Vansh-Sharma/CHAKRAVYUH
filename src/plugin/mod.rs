// Plugin/Extension System — WASM-based runtime, plugin API, marketplace, hot-reload.
//
// Simulates WASM execution for custom ring engines without real WASM dependency.
// Provides a central PluginManager that coordinates loading, execution, and lifecycle.

pub mod plugin_api;
pub mod plugin_marketplace;
pub mod wasm_runtime;

pub use plugin_api::*;
pub use plugin_marketplace::*;
pub use wasm_runtime::*;

use crate::error::{Error, Result};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────
// PluginConfig
// ─────────────────────────────────────────────────────────────────────

/// Top-level configuration for the plugin system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub max_plugins: usize,
    pub auto_reload: bool,
    pub plugin_dir: String,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_plugins: 50,
            auto_reload: false,
            plugin_dir: "./plugins".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// LoadedPlugin
// ─────────────────────────────────────────────────────────────────────

/// Internal representation of a loaded plugin.
pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub wasm_bytes: Vec<u8>,
    pub loaded_at: String,
    pub is_active: bool,
    pub execution_count: AtomicU64,
}

impl LoadedPlugin {
    pub fn new(manifest: PluginManifest, wasm_bytes: Vec<u8>) -> Self {
        Self {
            manifest,
            wasm_bytes,
            loaded_at: chrono::Utc::now().to_rfc3339(),
            is_active: true,
            execution_count: AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("name", &self.manifest.name)
            .field("version", &self.manifest.version)
            .field("is_active", &self.is_active)
            .field(
                "execution_count",
                &self.execution_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────
// PluginStatus
// ─────────────────────────────────────────────────────────────────────

/// Runtime status snapshot of a loaded plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStatus {
    pub name: String,
    pub version: Version,
    pub is_active: bool,
    pub execution_count: u64,
    pub memory_used: u64,
    pub last_executed: String,
}

// ─────────────────────────────────────────────────────────────────────
// PluginManager
// ─────────────────────────────────────────────────────────────────────

/// Central coordinator for the plugin system.
#[derive(Debug)]
pub struct PluginManager {
    plugins: RwLock<HashMap<String, LoadedPlugin>>,
    runtime: RwLock<WasmRuntime>,
    marketplace: Arc<RwLock<PluginRegistry>>,
    api: RwLock<PluginApi>,
    hot_reload: HotReloadManager,
    last_execution: RwLock<HashMap<String, Instant>>,
    max_plugins: usize,
}

impl PluginManager {
    /// Create a new PluginManager with the given configuration.
    pub fn new(config: PluginConfig) -> Self {
        let max_plugins = config.max_plugins;
        let runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        let api_runtime = WasmRuntime::new(WasmRuntimeConfig::default());
        let api = PluginApi::new(PluginApiConfig::default(), api_runtime);
        let marketplace = Arc::new(RwLock::new(PluginRegistry::new()));
        let hot_reload = HotReloadManager::new(marketplace.clone());

        Self {
            plugins: RwLock::new(HashMap::new()),
            runtime: RwLock::new(runtime),
            marketplace,
            api: RwLock::new(api),
            hot_reload,
            last_execution: RwLock::new(HashMap::new()),
            max_plugins,
        }
    }

    /// Load a plugin from its manifest. Returns the plugin ID (name string).
    pub fn load_plugin(&self, manifest: PluginManifest) -> Result<String> {
        let name = manifest.name.clone();

        {
            let plugins = self
                .plugins
                .read()
                .map_err(|_| Error::Other("lock poisoned".to_string()))?;
            if plugins.len() >= self.max_plugins {
                return Err(Error::Other(format!(
                    "max plugins ({}) reached",
                    self.max_plugins
                )));
            }
            if plugins.contains_key(&name) {
                return Err(Error::Other(format!("plugin '{}' already loaded", name)));
            }
        }

        // Build a simple evaluate function that returns param 0.
        let func = WasmFunction::new("evaluate", vec![WasmOpcode::LocalGet(0), WasmOpcode::End])
            .with_param(WasmValue::I32(0));

        let module = WasmModule::new(&name)
            .with_function(func)
            .with_export("evaluate")
            .with_memory(vec![0u8; 4096])
            .with_version(&manifest.version.to_string());

        {
            let mut rt = self
                .runtime
                .write()
                .map_err(|_| Error::Other("runtime lock poisoned".to_string()))?;
            rt.load_module(module)
                .map_err(|e| Error::Other(format!("failed to load WASM module: {}", e)))?;
        }

        // Also register in API runtime for execution.
        {
            let mut api = self
                .api
                .write()
                .map_err(|_| Error::Other("api lock poisoned".to_string()))?;
            let api_func =
                WasmFunction::new("evaluate", vec![WasmOpcode::LocalGet(0), WasmOpcode::End])
                    .with_param(WasmValue::I32(0));
            let api_module = WasmModule::new(&name)
                .with_function(api_func)
                .with_export("evaluate")
                .with_memory(vec![0u8; 4096]);
            api.runtime
                .load_module(api_module)
                .map_err(|e| Error::Other(format!("failed to load API module: {}", e)))?;
        }

        let loaded = LoadedPlugin::new(manifest.clone(), Vec::new());
        {
            let mut plugins = self
                .plugins
                .write()
                .map_err(|_| Error::Other("lock poisoned".to_string()))?;
            plugins.insert(name.clone(), loaded);
        }

        // Register in marketplace registry.
        if let Ok(mut reg) = self.marketplace.write() {
            let sig = plugin_marketplace::PluginSignature::new("default", &format!("sig-{}", name));
            let _ = reg.register(manifest, sig, vec![]);
        }

        tracing::info!(plugin = %name, "plugin loaded");
        Ok(name)
    }

    /// Unload a plugin by ID (name).
    pub fn unload_plugin(&self, id: &str) -> Result<()> {
        let removed = {
            let mut plugins = self
                .plugins
                .write()
                .map_err(|_| Error::Other("lock poisoned".to_string()))?;
            plugins.remove(id).is_some()
        };
        if removed {
            if let Ok(mut reg) = self.marketplace.write() {
                let _ = reg.unregister(id);
            }
            if let Ok(mut last) = self.last_execution.write() {
                last.remove(id);
            }
            tracing::info!(plugin = %id, "plugin unloaded");
            Ok(())
        } else {
            Err(Error::Other(format!("plugin '{}' not found", id)))
        }
    }

    /// Execute a loaded plugin with the given input.
    pub fn execute_plugin(&self, id: &str, input: &PluginInput) -> Result<PluginOutput> {
        {
            let plugins = self
                .plugins
                .read()
                .map_err(|_| Error::Other("lock poisoned".to_string()))?;
            if !plugins.contains_key(id) {
                return Err(Error::Other(format!("plugin '{}' not found", id)));
            }
            // Bump execution count atomically.
            if let Some(p) = plugins.get(id) {
                p.execution_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut api = self
            .api
            .write()
            .map_err(|_| Error::Other("api lock poisoned".to_string()))?;
        let sandbox_result = api.execute(id, "evaluate", input);

        // Record last execution time.
        if let Ok(mut last) = self.last_execution.write() {
            last.insert(id.to_string(), Instant::now());
        }

        sandbox_result.into_output().map_err(|e| Error::Other(e))
    }

    /// List all loaded plugins.
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        match self.plugins.read() {
            Ok(plugins) => plugins
                .values()
                .map(|p| PluginInfo {
                    name: p.manifest.name.clone(),
                    version: p.manifest.version.clone(),
                    display_name: p.manifest.display_name.clone(),
                    description: p.manifest.description.clone(),
                    ring_target: p.manifest.ring_target.clone(),
                    hook_point: p.manifest.hook_point.clone(),
                    is_loaded: p.is_active,
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Hot-reload a plugin by ID.
    pub fn hot_reload(&self, id: &str) -> Result<()> {
        self.hot_reload.reload(id).map_err(|e| Error::Other(e))?;

        if let Ok(mut plugins) = self.plugins.write() {
            if let Some(plugin) = plugins.get_mut(id) {
                plugin.manifest.version = Version::new(
                    plugin.manifest.version.major,
                    plugin.manifest.version.minor,
                    plugin.manifest.version.patch + 1,
                );
            }
        }

        tracing::info!(plugin = %id, "plugin hot-reloaded");
        Ok(())
    }

    /// Get the status of a loaded plugin.
    pub fn plugin_status(&self, id: &str) -> Option<PluginStatus> {
        let plugins = self.plugins.read().ok()?;
        let plugin = plugins.get(id)?;

        let last_exec = self
            .last_execution
            .read()
            .ok()
            .and_then(|m| m.get(id).map(|i| format!("{}s ago", i.elapsed().as_secs())))
            .unwrap_or_else(|| "never".to_string());

        Some(PluginStatus {
            name: plugin.manifest.name.clone(),
            version: plugin.manifest.version.clone(),
            is_active: plugin.is_active,
            execution_count: plugin.execution_count.load(Ordering::Relaxed),
            memory_used: 4096,
            last_executed: last_exec,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_manager() -> PluginManager {
        PluginManager::new(PluginConfig::default())
    }

    fn make_manifest(name: &str, version: &str) -> PluginManifest {
        PluginManifest::new(name, Version::parse(version).unwrap())
    }

    fn make_input() -> PluginInput {
        PluginInput {
            request_id: "req-test".to_string(),
            prompt_text: "test prompt".to_string(),
            source_ip: "192.168.1.1".to_string(),
            headers: HashMap::new(),
            risk_score: 0.3,
            ring_name: "threat".to_string(),
        }
    }

    #[test]
    fn test_plugin_config_defaults() {
        let cfg = PluginConfig::default();
        assert_eq!(cfg.max_plugins, 50);
        assert!(!cfg.auto_reload);
        assert_eq!(cfg.plugin_dir, "./plugins");
        assert!(cfg.enabled);
    }

    #[test]
    fn test_load_and_list_plugin() {
        let mgr = make_manager();
        let manifest = make_manifest("test-plugin", "1.0.0");
        let id = mgr.load_plugin(manifest).unwrap();
        assert_eq!(id, "test-plugin");

        let list = mgr.list_plugins();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-plugin");
    }

    #[test]
    fn test_load_duplicate_plugin() {
        let mgr = make_manager();
        let _ = mgr.load_plugin(make_manifest("dup", "1.0.0"));
        let result = mgr.load_plugin(make_manifest("dup", "1.1.0"));
        assert!(result.is_err());
    }

    #[test]
    fn test_unload_plugin() {
        let mgr = make_manager();
        let id = mgr
            .load_plugin(make_manifest("unload-me", "1.0.0"))
            .unwrap();
        assert_eq!(mgr.list_plugins().len(), 1);
        mgr.unload_plugin(&id).unwrap();
        assert_eq!(mgr.list_plugins().len(), 0);
    }

    #[test]
    fn test_unload_nonexistent_plugin() {
        let mgr = make_manager();
        let result = mgr.unload_plugin("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_plugin() {
        let mgr = make_manager();
        let id = mgr
            .load_plugin(make_manifest("exec-plug", "1.0.0"))
            .unwrap();
        let input = make_input();
        let output = mgr.execute_plugin(&id, &input).unwrap();
        assert!(matches!(
            output.decision,
            PluginDecision::Allow | PluginDecision::NoOp
        ));
    }

    #[test]
    fn test_plugin_status() {
        let mgr = make_manager();
        let id = mgr
            .load_plugin(make_manifest("status-plug", "1.0.0"))
            .unwrap();
        let status = mgr.plugin_status(&id).unwrap();
        assert_eq!(status.name, "status-plug");
        assert!(status.is_active);
        assert_eq!(status.execution_count, 0);

        let _ = mgr.execute_plugin(&id, &make_input());
        let status2 = mgr.plugin_status(&id).unwrap();
        assert_eq!(status2.execution_count, 1);
    }

    #[test]
    fn test_plugin_status_nonexistent() {
        let mgr = make_manager();
        assert!(mgr.plugin_status("ghost").is_none());
    }

    #[test]
    fn test_hot_reload_plugin() {
        let mgr = make_manager();
        let id = mgr
            .load_plugin(make_manifest("reload-plug", "1.0.0"))
            .unwrap();
        mgr.hot_reload(&id).unwrap();
        let status = mgr.plugin_status(&id).unwrap();
        assert_eq!(status.version, Version::new(1, 0, 1));
    }
}
