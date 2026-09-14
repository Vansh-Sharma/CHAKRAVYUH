// Config File Watcher (Phase 9)
//
// Watches a policy file for changes and triggers automatic hot-reload.
// Uses the `notify` crate for cross-platform file system events.
//
// Architecture:
//   - Runs as a background tokio task
//   - Debounces rapid file changes (500ms window)
//   - Calls the PolicyManager's reload_from_file() on change
//   - Logs all reload events for audit trail
//   - Stops gracefully on shutdown signal
//
// The watcher is OPTIONAL. If it fails to start (e.g., file doesn't exist),
// the system continues without auto-reload. Manual reload via API still works.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::keshav::policy_manager::PolicyManager;

/// Configuration for the config file watcher.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConfigWatcherConfig {
    /// Enable the config file watcher.
    #[serde(default)]
    pub enabled: bool,

    /// Debounce interval in milliseconds.
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
}

fn default_debounce_ms() -> u64 {
    500
}

impl Default for ConfigWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            debounce_ms: default_debounce_ms(),
        }
    }
}

/// A handle to the running config watcher task.
/// Dropping this handle does NOT stop the watcher; use `shutdown()` to stop.
pub struct ConfigWatcherHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl ConfigWatcherHandle {
    /// Stop the config watcher.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Spawn the config file watcher as a background task.
///
/// Watches `policy_path` for file modifications and calls
/// `policy_manager.reload_from_file()` on each change (debounced).
///
/// Returns a handle that can be used to shut down the watcher.
pub fn spawn_config_watcher(
    config: &ConfigWatcherConfig,
    policy_path: Option<String>,
    policy_manager: Arc<PolicyManager>,
) -> Option<ConfigWatcherHandle> {
    if !config.enabled {
        tracing::info!("config_watcher: disabled (set config_watcher.enabled: true to enable)");
        return None;
    }

    let path = match policy_path {
        Some(ref p) if !p.is_empty() => {
            let pb = PathBuf::from(p);
            if pb.exists() {
                pb
            } else {
                tracing::warn!(path = %p, "config_watcher: policy path does not exist, watcher not started");
                return None;
            }
        }
        _ => {
            tracing::info!("config_watcher: no policy_path configured, watcher not started");
            return None;
        }
    };

    let debounce = Duration::from_millis(config.debounce_ms);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);

    // Create the notify watcher.
    let mut watcher = match RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = event_tx.blocking_send(event);
            }
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "config_watcher: failed to create file watcher");
            return None;
        }
    };

    if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
        tracing::warn!(path = %path.display(), error = %e, "config_watcher: failed to watch file");
        return None;
    }

    tracing::info!(path = %path.display(), debounce_ms = config.debounce_ms, "config_watcher: watching policy file");

    // Spawn the background task.
    tokio::spawn(async move {
        let mut last_reload = std::time::Instant::now()
            .checked_sub(debounce)
            .unwrap_or_else(std::time::Instant::now);

        loop {
            tokio::select! {
                // File change event.
                Some(event) = event_rx.recv() => {
                    let now = std::time::Instant::now();
                    if now.duration_since(last_reload) < debounce {
                        tracing::trace!(
                            path = ?event.paths,
                            "config_watcher: debouncing rapid change"
                        );
                        continue;
                    }

                    // Only react to modify/create events.
                    match event.kind {
                        EventKind::Modify(_)
                        | EventKind::Create(_) => {
                            match policy_manager.reload_from_file() {
                                Ok(version) => {
                                    tracing::info!(
                                        version = %version,
                                        path = ?event.paths,
                                        "config_watcher: policy reloaded from file change"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "config_watcher: auto-reload failed (will retry on next change)"
                                    );
                                }
                            }
                            last_reload = now;
                        }
                        _ => {
                            tracing::trace!(kind = ?event.kind, "config_watcher: ignoring non-modify event");
                        }
                    }
                }

                // Shutdown signal.
                _ = &mut shutdown_rx => {
                    tracing::info!("config_watcher: shutting down");
                    break;
                }
            }
        }

        // Drop the watcher to stop watching.
        drop(watcher);
    });

    Some(ConfigWatcherHandle { shutdown_tx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ConfigWatcherConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.debounce_ms, 500);
    }

    #[test]
    fn config_parses_yaml() {
        let yaml = r#"enabled: true
debounce_ms: 1000
"#;
        let cfg: ConfigWatcherConfig = serde_yaml::from_str(yaml).expect("parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.debounce_ms, 1000);
    }

    #[test]
    fn watcher_disabled_returns_none() {
        let cfg = ConfigWatcherConfig::default();
        let pm = Arc::new(PolicyManager::new(
            crate::keshav::policy_engine::Policy::default(),
            None,
        ));
        let result = spawn_config_watcher(&cfg, None, pm);
        assert!(result.is_none());
    }
}
