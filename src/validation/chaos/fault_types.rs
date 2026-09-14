// Chaos Framework — Fault Types (D4)
//
// Defines all fault types that can be injected into the CHAKRAVYUH system.
// Organized into categories: ring faults, state faults, network faults,
// resource faults, and ANANTA-specific faults.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::validation::verification::Severity;

/// Target subsystems that faults can be directed at.
/// Covers all nine rings plus ANANTA subsystems and cross-cutting concerns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FaultTarget {
    Shield,
    Threat,
    Execution,
    Agent,
    Memory,
    Reasoning,
    Governance,
    RecoverySec,
    Identity,
    AnantaSentinel,
    AnantaPhoenix,
    AnantaVault,
    AnantaAdapter,
    KeshavDecide,
    KeshavLearn,
    KeshavRisk,
    CrossRingNetwork,
    Storage,
}

impl FaultTarget {
    /// Human-readable label for display and reports.
    pub fn label(&self) -> &'static str {
        match self {
            FaultTarget::Shield => "shield",
            FaultTarget::Threat => "threat",
            FaultTarget::Execution => "execution",
            FaultTarget::Agent => "agent",
            FaultTarget::Memory => "memory",
            FaultTarget::Reasoning => "reasoning",
            FaultTarget::Governance => "governance",
            FaultTarget::RecoverySec => "recovery_sec",
            FaultTarget::Identity => "identity",
            FaultTarget::AnantaSentinel => "ananta_sentinel",
            FaultTarget::AnantaPhoenix => "ananta_phoenix",
            FaultTarget::AnantaVault => "ananta_vault",
            FaultTarget::AnantaAdapter => "ananta_adapter",
            FaultTarget::KeshavDecide => "keshav_decide",
            FaultTarget::KeshavLearn => "keshav_learn",
            FaultTarget::KeshavRisk => "keshav_risk",
            FaultTarget::CrossRingNetwork => "cross_ring_network",
            FaultTarget::Storage => "storage",
        }
    }

    /// Category grouping for reporting.
    pub fn category(&self) -> &'static str {
        match self {
            FaultTarget::Shield
            | FaultTarget::Threat
            | FaultTarget::Execution
            | FaultTarget::Agent
            | FaultTarget::Memory
            | FaultTarget::Reasoning
            | FaultTarget::Governance
            | FaultTarget::RecoverySec
            | FaultTarget::Identity => "ring",
            FaultTarget::AnantaSentinel
            | FaultTarget::AnantaPhoenix
            | FaultTarget::AnantaVault
            | FaultTarget::AnantaAdapter => "ananta",
            FaultTarget::KeshavDecide
            | FaultTarget::KeshavLearn
            | FaultTarget::KeshavRisk => "keshav",
            FaultTarget::CrossRingNetwork => "network",
            FaultTarget::Storage => "infra",
        }
    }
}

impl std::fmt::Display for FaultTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// All fault types organized into categories.
///
/// - **Ring faults**: crash, hang, slow, error — simulate ring-level failures.
/// - **State faults**: corruption, loss — simulate data integrity issues.
/// - **Network faults**: partition, latency, loss — simulate network issues.
/// - **Resource faults**: memory pressure, CPU spike — simulate resource exhaustion.
/// - **ANANTA-specific**: OVAph loop disruption, trust chain corruption,
///   drift injection, attestation failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FaultType {
    // --- Ring faults ---
    /// The target ring crashes and becomes unavailable.
    RingCrash { target: FaultTarget },
    /// The target ring hangs for the specified duration.
    RingHang {
        target: FaultTarget,
        duration_ms: u64,
    },
    /// The target ring responds slowly with added latency.
    RingSlow {
        target: FaultTarget,
        latency_ms: u64,
    },
    /// The target ring returns errors at a given rate (0.0–1.0).
    RingError {
        target: FaultTarget,
        error_rate: f64,
    },

    // --- State faults ---
    /// Specific fields in the target's state are corrupted.
    StateCorruption {
        target: FaultTarget,
        fields: Vec<String>,
    },
    /// The target loses all its state.
    StateLoss { target: FaultTarget },

    // --- Network faults ---
    /// Network communication from one target to another is severed.
    NetworkPartition {
        from: FaultTarget,
        to: FaultTarget,
    },
    /// Network communication from one target to another is delayed.
    NetworkLatency {
        from: FaultTarget,
        to: FaultTarget,
        latency_ms: u64,
    },
    /// Network communication from one target to another is lost at a rate.
    NetworkLoss {
        from: FaultTarget,
        to: FaultTarget,
        loss_rate: f64,
    },

    // --- Resource faults ---
    /// Simulate memory pressure by allocating the given megabytes.
    MemoryPressure { megabytes: u64 },
    /// Simulate a CPU spike for the given duration.
    CpuSpike { duration_ms: u64 },

    // --- ANANTA-specific faults ---
    /// Disrupt a specific phase of the OVAph (Observe–Verify–Act–Prove–Heal) loop.
    OvaphLoopDisruption { phase: String },
    /// Corrupt the trust chain to a given depth.
    TrustChainCorruption { depth: u32 },
    /// Inject drift into a subsystem with a given magnitude.
    DriftInjection {
        subsystem: String,
        magnitude: f64,
    },
    /// Force an attestation failure with a reason.
    AttestationFailure { reason: String },
}

impl FaultType {
    /// The primary target affected by this fault.
    pub fn primary_target(&self) -> Option<&FaultTarget> {
        match self {
            FaultType::RingCrash { target }
            | FaultType::RingHang { target, .. }
            | FaultType::RingSlow { target, .. }
            | FaultType::RingError { target, .. }
            | FaultType::StateCorruption { target, .. }
            | FaultType::StateLoss { target } => Some(target),
            FaultType::NetworkPartition { from, .. }
            | FaultType::NetworkLatency { from, .. }
            | FaultType::NetworkLoss { from, .. } => Some(from),
            FaultType::MemoryPressure { .. }
            | FaultType::CpuSpike { .. }
            | FaultType::OvaphLoopDisruption { .. }
            | FaultType::TrustChainCorruption { .. }
            | FaultType::DriftInjection { .. }
            | FaultType::AttestationFailure { .. } => None,
        }
    }

    /// Short category label for grouping.
    pub fn category(&self) -> &'static str {
        match self {
            FaultType::RingCrash { .. }
            | FaultType::RingHang { .. }
            | FaultType::RingSlow { .. }
            | FaultType::RingError { .. } => "ring",
            FaultType::StateCorruption { .. } | FaultType::StateLoss { .. } => "state",
            FaultType::NetworkPartition { .. }
            | FaultType::NetworkLatency { .. }
            | FaultType::NetworkLoss { .. } => "network",
            FaultType::MemoryPressure { .. } | FaultType::CpuSpike { .. } => "resource",
            FaultType::OvaphLoopDisruption { .. }
            | FaultType::TrustChainCorruption { .. }
            | FaultType::DriftInjection { .. }
            | FaultType::AttestationFailure { .. } => "ananta",
        }
    }
}

/// A planned fault injection with metadata.
///
/// Describes what fault to inject, which target, the expected behavior
/// when the system is healthy, and the severity if recovery fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultInjection {
    /// Unique identifier for this injection.
    pub id: String,
    /// The fault type to inject.
    pub fault: FaultType,
    /// Human-readable name.
    pub name: String,
    /// Detailed description of the fault scenario.
    pub description: String,
    /// What the system SHOULD do when this fault is active.
    pub expected_behavior: String,
    /// Severity if the system fails to recover.
    pub severity: Severity,
    /// Tags for filtering and grouping.
    pub tags: Vec<String>,
}

impl FaultInjection {
    /// Create a new fault injection with required fields.
    pub fn new(id: &str, fault: FaultType, name: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            fault,
            name: name.to_string(),
            description: description.to_string(),
            expected_behavior: String::new(),
            severity: Severity::default(),
            tags: Vec::new(),
        }
    }

    /// Builder: set expected behavior.
    pub fn expected_behavior(mut self, behavior: &str) -> Self {
        self.expected_behavior = behavior.to_string();
        self
    }

    /// Builder: set severity.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Builder: add a tag.
    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Builder: set all tags.
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_target_label_and_category() {
        assert_eq!(FaultTarget::Shield.label(), "shield");
        assert_eq!(FaultTarget::Shield.category(), "ring");
        assert_eq!(FaultTarget::AnantaSentinel.category(), "ananta");
        assert_eq!(FaultTarget::KeshavDecide.category(), "keshav");
        assert_eq!(FaultTarget::CrossRingNetwork.category(), "network");
        assert_eq!(FaultTarget::Storage.category(), "infra");
    }

    #[test]
    fn fault_type_category() {
        let crash = FaultType::RingCrash {
            target: FaultTarget::Shield,
        };
        assert_eq!(crash.category(), "ring");

        let corruption = FaultType::StateCorruption {
            target: FaultTarget::Memory,
            fields: vec!["context".to_string()],
        };
        assert_eq!(corruption.category(), "state");

        let partition = FaultType::NetworkPartition {
            from: FaultTarget::Shield,
            to: FaultTarget::Threat,
        };
        assert_eq!(partition.category(), "network");

        let mem = FaultType::MemoryPressure { megabytes: 512 };
        assert_eq!(mem.category(), "resource");

        let drift = FaultType::DriftInjection {
            subsystem: "sentinel".to_string(),
            magnitude: 0.75,
        };
        assert_eq!(drift.category(), "ananta");
    }

    #[test]
    fn fault_type_primary_target() {
        let crash = FaultType::RingCrash {
            target: FaultTarget::Agent,
        };
        assert_eq!(crash.primary_target(), Some(&FaultTarget::Agent));

        let partition = FaultType::NetworkPartition {
            from: FaultTarget::Shield,
            to: FaultTarget::Threat,
        };
        assert_eq!(partition.primary_target(), Some(&FaultTarget::Shield));

        let mem = FaultType::MemoryPressure { megabytes: 256 };
        assert_eq!(mem.primary_target(), None);
    }

    #[test]
    fn fault_injection_builder() {
        let fi = FaultInjection::new(
            "fi-001",
            FaultType::RingCrash {
                target: FaultTarget::Governance,
            },
            "governance crash",
            "Simulate governance ring crash",
        )
        .expected_behavior("System should fall back to safe defaults")
        .severity(Severity::Critical)
        .tag("ring-fault")
        .tag("governance");

        assert_eq!(fi.id, "fi-001");
        assert!(!fi.expected_behavior.is_empty());
        assert_eq!(fi.severity, Severity::Critical);
        assert_eq!(fi.tags.len(), 2);
    }

    #[test]
    fn fault_injection_serialization_roundtrip() {
        let fi = FaultInjection::new(
            "fi-ser",
            FaultType::TrustChainCorruption { depth: 3 },
            "trust chain corrupt",
            "Corrupt trust chain at depth 3",
        )
        .severity(Severity::High);

        let json = serde_json::to_string(&fi).map_err(|e| e.to_string());
        assert!(json.is_ok());
        let restored: Result<FaultInjection, _> =
            serde_json::from_str(&json.unwrap()).map_err(|e| e.to_string());
        assert!(restored.is_ok());
        let restored = restored.unwrap();
        assert_eq!(restored.id, fi.id);
        assert_eq!(restored.severity, Severity::High);
    }

    #[test]
    fn all_fault_targets_count() {
        // Verify we have 18 targets (9 rings + 4 ANANTA + 3 Keshav + 2 infra).
        let all = vec![
            FaultTarget::Shield,
            FaultTarget::Threat,
            FaultTarget::Execution,
            FaultTarget::Agent,
            FaultTarget::Memory,
            FaultTarget::Reasoning,
            FaultTarget::Governance,
            FaultTarget::RecoverySec,
            FaultTarget::Identity,
            FaultTarget::AnantaSentinel,
            FaultTarget::AnantaPhoenix,
            FaultTarget::AnantaVault,
            FaultTarget::AnantaAdapter,
            FaultTarget::KeshavDecide,
            FaultTarget::KeshavLearn,
            FaultTarget::KeshavRisk,
            FaultTarget::CrossRingNetwork,
            FaultTarget::Storage,
        ];
        assert_eq!(all.len(), 18);
    }
}
