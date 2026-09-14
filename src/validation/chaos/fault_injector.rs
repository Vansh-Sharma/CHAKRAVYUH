// Chaos Framework — Fault Injector (D4)
//
// Responsible for injecting faults into the system and tracking what was
// changed so it can be rolled back. Each injection records the original
// state for later restoration.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use super::fault_types::{FaultInjection, FaultTarget, FaultType};

/// A fault that is currently active in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveFault {
    /// The injection ID that was returned when this fault was injected.
    pub injection_id: String,
    /// The fault specification.
    pub fault: FaultType,
    /// RFC 3339 timestamp when the fault was injected.
    pub injected_at: String,
    /// Whether this fault is still active.
    pub active: bool,
    /// A snapshot of what was changed so it can be rolled back.
    pub rollback_snapshot: FaultSnapshot,
}

/// Snapshot of system state before a fault was injected, enabling rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultSnapshot {
    /// The target that was modified.
    pub target: String,
    /// What was changed: field name → original value.
    pub original_values: HashMap<String, serde_json::Value>,
    /// Whether network was affected (for network faults).
    pub network_affected: bool,
    /// For state corruption: the original field values before corruption.
    pub corrupted_fields: Vec<String>,
}

/// The fault injector manages injecting and releasing faults.
///
/// In a real system this would interact with ring subsystems. Here it
/// simulates the injection by recording what *would* be changed and
/// producing observable effects that the health monitor can track.
pub struct FaultInjector {
    active_faults: Vec<ActiveFault>,
    /// Simulated state store: target → (field → value).
    simulated_state: HashMap<String, HashMap<String, serde_json::Value>>,
    /// Simulated network partitions: "from→to" → true.
    simulated_partitions: HashMap<String, bool>,
    /// Counter for generating injection IDs.
    injection_counter: u64,
}

impl FaultInjector {
    /// Create a new fault injector.
    pub fn new() -> Self {
        Self {
            active_faults: Vec::new(),
            simulated_state: HashMap::new(),
            simulated_partitions: HashMap::new(),
            injection_counter: 0,
        }
    }

    /// Inject a fault into the system.
    ///
    /// Returns the injection ID for later release.
    /// Records what was changed so it can be rolled back.
    pub fn inject(&mut self, fault: &FaultInjection) -> Result<String, String> {
        self.injection_counter += 1;
        let injection_id = format!("inj-{:06}", self.injection_counter);
        let injected_at = chrono::Utc::now().to_rfc3339();

        let snapshot = self.apply_fault(&fault.fault)?;

        let active = ActiveFault {
            injection_id: injection_id.clone(),
            fault: fault.fault.clone(),
            injected_at: injected_at.clone(),
            active: true,
            rollback_snapshot: snapshot,
        };

        self.active_faults.push(active);
        info!(
            injection_id = %injection_id,
            fault_name = %fault.name,
            "Fault injected"
        );

        Ok(injection_id)
    }

    /// Release a previously injected fault by injection_id.
    ///
    /// Restores the system to its pre-injection state.
    pub fn release(&mut self, injection_id: &str) -> Result<(), String> {
        let idx = self
            .active_faults
            .iter()
            .position(|f| f.injection_id == injection_id && f.active)
            .ok_or_else(|| format!("No active fault with id: {}", injection_id))?;

        // Clone needed data to avoid borrow conflicts.
        let fault_clone = self.active_faults[idx].fault.clone();
        let snapshot_clone = self.active_faults[idx].rollback_snapshot.clone();
        self.rollback_fault(&fault_clone, &snapshot_clone)?;
        self.active_faults[idx].active = false;

        info!(injection_id = %injection_id, "Fault released");
        Ok(())
    }

    /// Release all active faults.
    pub fn release_all(&mut self) {
        // Collect what needs rolling back first to avoid borrow conflicts.
        let to_rollback: Vec<(FaultType, FaultSnapshot)> = self
            .active_faults
            .iter()
            .filter(|f| f.active)
            .map(|f| (f.fault.clone(), f.rollback_snapshot.clone()))
            .collect();

        for (fault, snapshot) in to_rollback {
            let _ = self.rollback_fault(&fault, &snapshot);
        }

        for fault in &mut self.active_faults {
            fault.active = false;
        }

        info!(count = self.active_faults.len(), "All faults released");
    }

    /// Get a reference to all active faults.
    pub fn active_faults(&self) -> &[ActiveFault] {
        &self.active_faults
    }

    /// Get the number of currently active faults.
    pub fn active_count(&self) -> usize {
        self.active_faults.iter().filter(|f| f.active).count()
    }

    /// Check if a specific target has any active faults.
    pub fn has_active_fault(&self, target: &FaultTarget) -> bool {
        self.active_faults.iter().any(|f| {
            f.active && f.fault.primary_target() == Some(target)
        })
    }

    /// Check if a network path is currently partitioned.
    pub fn is_partitioned(&self, from: &FaultTarget, to: &FaultTarget) -> bool {
        let key = format!("{}→{}", from.label(), to.label());
        self.simulated_partitions.get(&key).copied().unwrap_or(false)
    }

    /// Get the simulated (possibly corrupted) state of a target.
    pub fn simulated_state(&self, target: &str) -> Option<&HashMap<String, serde_json::Value>> {
        self.simulated_state.get(target)
    }

    // --- Internal fault application ---

    fn apply_fault(&mut self, fault: &FaultType) -> Result<FaultSnapshot, String> {
        match fault {
            FaultType::StateCorruption { target, fields } => {
                self.apply_state_corruption(target, fields)
            }
            FaultType::StateLoss { target } => {
                self.apply_state_loss(target)
            }
            FaultType::NetworkPartition { from, to } => {
                self.apply_network_partition(from, to)
            }
            FaultType::NetworkLatency { from, to, .. } => {
                // Record the partition key as "latency" rather than full partition.
                let key = format!("{}→{}", from.label(), to.label());
                let snapshot = FaultSnapshot {
                    target: format!("{}→{}", from.label(), to.label()),
                    original_values: HashMap::new(),
                    network_affected: true,
                    corrupted_fields: Vec::new(),
                };
                self.simulated_partitions.insert(key, true);
                Ok(snapshot)
            }
            FaultType::NetworkLoss { from, to, .. } => {
                self.apply_network_partition(from, to)
            }
            FaultType::RingCrash { target } => {
                // Simulate by marking the target's state as crashed.
                let target_key = target.label().to_string();
                let entry = self
                    .simulated_state
                    .entry(target_key.clone())
                    .or_default();
                let original = entry
                    .get("status")
                    .cloned()
                    .unwrap_or(serde_json::json!("healthy"));
                entry.insert("status".to_string(), serde_json::json!("crashed"));
                let mut orig = HashMap::new();
                orig.insert("status".to_string(), original);
                Ok(FaultSnapshot {
                    target: target_key,
                    original_values: orig,
                    network_affected: false,
                    corrupted_fields: Vec::new(),
                })
            }
            FaultType::RingHang { target, .. }
            | FaultType::RingSlow { target, .. }
            | FaultType::RingError { target, .. } => {
                let target_key = target.label().to_string();
                Ok(FaultSnapshot {
                    target: target_key,
                    original_values: HashMap::new(),
                    network_affected: false,
                    corrupted_fields: Vec::new(),
                })
            }
            FaultType::MemoryPressure { .. } | FaultType::CpuSpike { .. } => {
                Ok(FaultSnapshot {
                    target: "system".to_string(),
                    original_values: HashMap::new(),
                    network_affected: false,
                    corrupted_fields: Vec::new(),
                })
            }
            FaultType::OvaphLoopDisruption { phase } => Ok(FaultSnapshot {
                target: format!("ovaph:{}", phase),
                original_values: HashMap::new(),
                network_affected: false,
                corrupted_fields: Vec::new(),
            }),
            FaultType::TrustChainCorruption { depth } => Ok(FaultSnapshot {
                target: format!("trust_chain:depth={}", depth),
                original_values: HashMap::new(),
                network_affected: false,
                corrupted_fields: vec![format!("chain_depth_{}", depth)],
            }),
            FaultType::DriftInjection { subsystem, .. } => Ok(FaultSnapshot {
                target: subsystem.clone(),
                original_values: HashMap::new(),
                network_affected: false,
                corrupted_fields: vec![format!("{}_drift", subsystem)],
            }),
            FaultType::AttestationFailure { reason } => {
                warn!(reason = %reason, "Simulating attestation failure");
                Ok(FaultSnapshot {
                    target: "attestation".to_string(),
                    original_values: HashMap::new(),
                    network_affected: false,
                    corrupted_fields: Vec::new(),
                })
            }
        }
    }

    fn apply_state_corruption(
        &mut self,
        target: &FaultTarget,
        fields: &[String],
    ) -> Result<FaultSnapshot, String> {
        let target_key = target.label().to_string();
        let entry = self
            .simulated_state
            .entry(target_key.clone())
            .or_default();

        let mut original_values = HashMap::new();
        for field in fields {
            let original = entry
                .get(field)
                .cloned()
                .unwrap_or(serde_json::json!(null));
            original_values.insert(field.clone(), original);
            // Corrupt: set to a recognizable corrupt value.
            entry.insert(field.clone(), serde_json::json!(format!("__CORRUPTED_{}", field)));
        }

        Ok(FaultSnapshot {
            target: target_key,
            original_values,
            network_affected: false,
            corrupted_fields: fields.to_vec(),
        })
    }

    fn apply_state_loss(&mut self, target: &FaultTarget) -> Result<FaultSnapshot, String> {
        let target_key = target.label().to_string();
        let original = self.simulated_state.remove(&target_key).unwrap_or_default();
        let original_values: HashMap<String, serde_json::Value> = original;

        Ok(FaultSnapshot {
            target: target_key,
            original_values,
            network_affected: false,
            corrupted_fields: Vec::new(),
        })
    }

    fn apply_network_partition(
        &mut self,
        from: &FaultTarget,
        to: &FaultTarget,
    ) -> Result<FaultSnapshot, String> {
        let key = format!("{}→{}", from.label(), to.label());
        self.simulated_partitions.insert(key.clone(), true);
        Ok(FaultSnapshot {
            target: key,
            original_values: HashMap::new(),
            network_affected: true,
            corrupted_fields: Vec::new(),
        })
    }

    // --- Rollback ---

    fn rollback_fault(
        &mut self,
        fault: &FaultType,
        snapshot: &FaultSnapshot,
    ) -> Result<(), String> {
        // Restore corrupted state fields.
        if !snapshot.original_values.is_empty() {
            let entry = self
                .simulated_state
                .entry(snapshot.target.clone())
                .or_default();
            for (field, value) in &snapshot.original_values {
                entry.insert(field.clone(), value.clone());
            }
        }

        // Remove network partitions.
        if snapshot.network_affected {
            self.simulated_partitions.remove(&snapshot.target);
        }

        // For state loss: restore the original values (even if empty, recreate the entry).
        if matches!(fault, FaultType::StateLoss { .. }) {
            let entry = self
                .simulated_state
                .entry(snapshot.target.clone())
                .or_default();
            for (field, value) in &snapshot.original_values {
                entry.insert(field.clone(), value.clone());
            }
        }

        // For ring crash: restore status.
        if let FaultType::RingCrash { .. } = fault {
            if let Some(status) = snapshot.original_values.get("status") {
                let entry = self
                    .simulated_state
                    .entry(snapshot.target.clone())
                    .or_default();
                entry.insert("status".to_string(), status.clone());
            }
        }

        Ok(())
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::verification::Severity;

    fn make_fault(id: &str, fault: FaultType) -> FaultInjection {
        FaultInjection::new(id, fault, "test", "test fault").severity(Severity::Medium)
    }

    #[test]
    fn inject_and_release_ring_crash() {
        let mut injector = FaultInjector::new();
        let fi = make_fault(
            "crash-1",
            FaultType::RingCrash {
                target: FaultTarget::Shield,
            },
        );
        let id = injector.inject(&fi).unwrap();
        assert_eq!(injector.active_count(), 1);
        assert!(injector.has_active_fault(&FaultTarget::Shield));

        injector.release(&id).unwrap();
        assert_eq!(injector.active_count(), 0);
        assert!(!injector.has_active_fault(&FaultTarget::Shield));
    }

    #[test]
    fn inject_state_corruption_and_rollback() {
        let mut injector = FaultInjector::new();
        let fi = make_fault(
            "corrupt-1",
            FaultType::StateCorruption {
                target: FaultTarget::Memory,
                fields: vec!["context".to_string(), "pii_cache".to_string()],
            },
        );
        let id = injector.inject(&fi).unwrap();

        // Check the state is corrupted.
        let state = injector.simulated_state("memory").unwrap();
        assert_eq!(
            state.get("context").unwrap(),
            &serde_json::json!("__CORRUPTED_context")
        );

        injector.release(&id).unwrap();

        // After rollback, values should be restored to null (original).
        let state = injector.simulated_state("memory").unwrap();
        assert_eq!(state.get("context").unwrap(), &serde_json::json!(null));
    }

    #[test]
    fn inject_network_partition() {
        let mut injector = FaultInjector::new();
        let fi = make_fault(
            "partition-1",
            FaultType::NetworkPartition {
                from: FaultTarget::Shield,
                to: FaultTarget::Threat,
            },
        );
        let id = injector.inject(&fi).unwrap();

        assert!(injector.is_partitioned(&FaultTarget::Shield, &FaultTarget::Threat));
        assert!(!injector.is_partitioned(&FaultTarget::Threat, &FaultTarget::Shield));

        injector.release(&id).unwrap();
        assert!(!injector.is_partitioned(&FaultTarget::Shield, &FaultTarget::Threat));
    }

    #[test]
    fn release_nonexistent_returns_error() {
        let mut injector = FaultInjector::new();
        let result = injector.release("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn release_all_clears_everything() {
        let mut injector = FaultInjector::new();
        let _ = injector
            .inject(&make_fault(
                "a",
                FaultType::RingCrash {
                    target: FaultTarget::Agent,
                },
            ))
            .unwrap();
        let _ = injector
            .inject(&make_fault(
                "b",
                FaultType::RingHang {
                    target: FaultTarget::Execution,
                    duration_ms: 5000,
                },
            ))
            .unwrap();

        assert_eq!(injector.active_count(), 2);
        injector.release_all();
        assert_eq!(injector.active_count(), 0);
    }

    #[test]
    fn state_loss_clears_state() {
        let mut injector = FaultInjector::new();
        let fi = make_fault(
            "loss-1",
            FaultType::StateLoss {
                target: FaultTarget::Reasoning,
            },
        );
        let id = injector.inject(&fi).unwrap();
        // State should be empty after loss.
        assert!(injector.simulated_state("reasoning").is_none());

        injector.release(&id).unwrap();
        // After rollback, empty state is restored.
        assert!(injector.simulated_state("reasoning").is_some());
    }
}
