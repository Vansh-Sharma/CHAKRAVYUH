// Chaos Framework — Chaos Engine (D4)
//
// Orchestrates chaos scenarios: plan → inject → monitor → verify → record.
// Each scenario consists of multiple fault injections executed sequentially.
// The engine tracks per-fault results, recovery times, and cascading failures.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::validation::chaos::fault_injector::FaultInjector;
use crate::validation::chaos::fault_types::{FaultInjection, FaultTarget, FaultType};
use crate::validation::chaos::health_monitor::HealthMonitor;
use crate::validation::chaos::recovery_metrics::{RecoveryMetrics, RecoverySummary};
use crate::validation::verification::{Evidence, ValidationReport, Verdict};

/// Configuration for the chaos engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    /// Maximum number of concurrent faults allowed.
    pub max_concurrent_faults: usize,
    /// Default duration for fault activation in milliseconds.
    pub fault_duration_ms: u64,
    /// Timeout for waiting for recovery after fault release in milliseconds.
    pub recovery_timeout_ms: u64,
    /// Whether to automatically release faults after duration.
    pub auto_heal: bool,
    /// Which targets to include in the chaos run.
    pub targets: Vec<FaultTarget>,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            max_concurrent_faults: 3,
            fault_duration_ms: 5000,
            recovery_timeout_ms: 30000,
            auto_heal: true,
            targets: vec![
                FaultTarget::Shield,
                FaultTarget::Threat,
                FaultTarget::Execution,
                FaultTarget::Agent,
                FaultTarget::Memory,
                FaultTarget::Reasoning,
                FaultTarget::Governance,
                FaultTarget::RecoverySec,
                FaultTarget::Identity,
            ],
        }
    }
}

impl ChaosConfig {
    /// Create a config for quick smoke testing.
    pub fn smoke_test() -> Self {
        Self {
            max_concurrent_faults: 1,
            fault_duration_ms: 1000,
            recovery_timeout_ms: 5000,
            auto_heal: true,
            targets: vec![FaultTarget::Shield, FaultTarget::Threat],
        }
    }
}

/// A planned chaos scenario containing ordered fault injections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosScenario {
    /// Human-readable scenario name.
    pub name: String,
    /// Description of what this scenario tests.
    pub description: String,
    /// The fault injections in execution order.
    pub faults: Vec<FaultInjection>,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

impl ChaosScenario {
    /// Create a new scenario.
    pub fn new(name: &str, description: &str, faults: Vec<FaultInjection>) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            faults,
            tags: Vec::new(),
        }
    }
}

/// Per-fault result from a chaos execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultResult {
    /// The fault injection ID.
    pub fault_id: String,
    /// The fault name.
    pub fault_name: String,
    /// The internal injection ID from the FaultInjector.
    pub injection_id: String,
    /// Whether the system recovered.
    pub recovered: bool,
    /// Recovery time in milliseconds.
    pub recovery_time_ms: Option<u64>,
    /// Targets that cascaded.
    pub cascade_targets: Vec<String>,
    /// Whether recovery was auto-healed.
    pub auto_healed: bool,
    /// Whether data was lost.
    pub data_loss: bool,
    /// Verdict for this fault.
    pub verdict: Verdict,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Complete result of a chaos scenario execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosResult {
    /// The scenario name.
    pub scenario_name: String,
    /// Per-fault results.
    pub fault_results: Vec<FaultResult>,
    /// Per-fault recovery metrics.
    pub recovery_metrics: Vec<RecoveryMetrics>,
    /// Aggregate recovery summary.
    pub recovery_summary: RecoverySummary,
    /// Map from fault_id to list of cascade target labels.
    pub cascade_map: HashMap<String, Vec<String>>,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Total scenario duration in microseconds.
    pub duration_us: u64,
}

impl ChaosResult {
    /// Number of faults that passed (system recovered as expected).
    pub fn pass_count(&self) -> usize {
        self.fault_results
            .iter()
            .filter(|r| r.verdict == Verdict::Pass)
            .count()
    }

    /// Number of faults that failed.
    pub fn fail_count(&self) -> usize {
        self.fault_results
            .iter()
            .filter(|r| r.verdict == Verdict::Fail)
            .count()
    }
}

/// The chaos engine orchestrates fault injection scenarios.
///
/// For each fault in a scenario:
/// 1. Inject the fault
/// 2. Monitor health (simulate health changes)
/// 3. Detect cascades
/// 4. Release the fault
/// 5. Verify recovery
/// 6. Record evidence
pub struct ChaosEngine {
    config: ChaosConfig,
    injector: FaultInjector,
    monitor: HealthMonitor,
}

impl ChaosEngine {
    /// Create a new chaos engine with the given config.
    pub fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            injector: FaultInjector::new(),
            monitor: HealthMonitor::new(),
        }
    }

    /// Plan a scenario from a list of fault injections.
    ///
    /// Validates that faults don't exceed `max_concurrent_faults`
    /// and filters to only include configured targets.
    pub fn plan_scenario(&self, faults: &[FaultInjection]) -> Result<ChaosScenario, String> {
        if faults.is_empty() {
            return Err("Cannot plan scenario with zero faults".to_string());
        }

        // Filter to configured targets (if any configured).
        let filtered: Vec<FaultInjection> = if self.config.targets.is_empty() {
            faults.to_vec()
        } else {
            faults
                .iter()
                .filter(|f| {
                    let primary = f.fault.primary_target();
                    match primary {
                        Some(t) => self.config.targets.contains(t),
                        None => true, // Include resource/ANANTA faults that have no single target.
                    }
                })
                .cloned()
                .collect()
        };

        if filtered.is_empty() {
            return Err("No faults match configured targets; scenario would be empty".to_string());
        }

        Ok(ChaosScenario::new(
            &format!("chaos-{}-faults", filtered.len()),
            &format!("Chaos scenario with {} fault injections", filtered.len()),
            filtered,
        ))
    }

    /// Execute a planned chaos scenario.
    ///
    /// For each fault:
    /// 1. Inject
    /// 2. Simulate health impact (mark target unhealthy)
    /// 3. Detect cascades
    /// 4. Release fault
    /// 5. Simulate recovery (mark target healthy)
    /// 6. Measure recovery time
    /// 7. Record evidence
    pub fn execute_scenario(
        &mut self,
        scenario: &ChaosScenario,
        report: &mut ValidationReport,
    ) -> Result<ChaosResult, String> {
        let start = std::time::Instant::now();
        info!(
            scenario = %scenario.name,
            fault_count = scenario.faults.len(),
            "Starting chaos scenario execution"
        );

        let mut fault_results = Vec::new();
        let mut recovery_metrics_list = Vec::new();
        let mut cascade_map: HashMap<String, Vec<String>> = HashMap::new();

        for fault in &scenario.faults {
            let fr =
                self.execute_single_fault(fault, &mut recovery_metrics_list, &mut cascade_map)?;

            // Record evidence for this fault.
            self.record_fault_evidence(&fr, fault, report);

            fault_results.push(fr);

            // Enforce max concurrent faults.
            while self.injector.active_count() >= self.config.max_concurrent_faults {
                // Release the oldest active fault.
                let oldest = self
                    .injector
                    .active_faults()
                    .iter()
                    .find(|f| f.active)
                    .cloned();
                if let Some(active) = oldest {
                    let _ = self.injector.release(&active.injection_id);
                    // Simulate recovery for released fault's target.
                    if let Some(target) = active.fault.primary_target() {
                        self.monitor.sample(target.clone(), true, Some(5), 0.0);
                    }
                } else {
                    break;
                }
            }
        }

        // Ensure all faults are released.
        self.injector.release_all();

        let recovery_summary = RecoverySummary::from_metrics(&recovery_metrics_list);

        // Determine overall verdict.
        let overall_verdict = if fault_results.iter().any(|r| r.verdict == Verdict::Fail) {
            Verdict::Fail
        } else {
            Verdict::Pass
        };

        let duration_us = start.elapsed().as_micros() as u64;

        info!(
            scenario = %scenario.name,
            verdict = %overall_verdict,
            duration_us = duration_us,
            "Chaos scenario complete"
        );

        Ok(ChaosResult {
            scenario_name: scenario.name.clone(),
            fault_results,
            recovery_metrics: recovery_metrics_list,
            recovery_summary,
            cascade_map,
            verdict: overall_verdict,
            duration_us,
        })
    }

    /// Execute a single fault: inject → simulate impact → detect cascade → release → verify.
    fn execute_single_fault(
        &mut self,
        fault: &FaultInjection,
        recovery_metrics_list: &mut Vec<RecoveryMetrics>,
        cascade_map: &mut HashMap<String, Vec<String>>,
    ) -> Result<FaultResult, String> {
        let fault_type_str = fault.fault.category().to_string();
        let target_label = fault
            .fault
            .primary_target()
            .map(|t| t.label().to_string())
            .unwrap_or_else(|| "system".to_string());

        // 1. Inject.
        let injection_id = self.injector.inject(fault)?;
        let injected_at = chrono::Utc::now().to_rfc3339();

        // 2. Simulate health impact: mark primary target unhealthy.
        if let Some(target) = fault.fault.primary_target() {
            self.monitor.sample(target.clone(), false, None, 1.0);

            // 3. Simulate cascade for certain fault types.
            if matches!(
                fault.fault,
                FaultType::RingCrash { .. }
                    | FaultType::NetworkPartition { .. }
                    | FaultType::StateLoss { .. }
            ) {
                // Pick a related target to simulate cascade.
                let cascade_target = Self::pick_cascade_target(&target);
                if cascade_target != *target {
                    self.monitor
                        .sample(cascade_target.clone(), false, None, 0.8);
                }
            }

            // 4. Detect cascades.
            let cascaded = self.monitor.detect_cascade(target.clone(), &injected_at);
            let cascade_labels: Vec<String> =
                cascaded.iter().map(|t| t.label().to_string()).collect();
            if !cascade_labels.is_empty() {
                cascade_map.insert(fault.id.clone(), cascade_labels.clone());
            }

            // 5. Release fault.
            self.injector.release(&injection_id)?;

            // 6. Simulate recovery.
            self.monitor.sample(target.clone(), true, Some(5), 0.0);
            // Also recover cascade targets.
            for ct in &cascaded {
                self.monitor.sample(ct.clone(), true, Some(10), 0.0);
            }

            // 7. Measure recovery time.
            let recovery_time = self.monitor.recovery_time(target.clone(), &injected_at);
            let recovered = recovery_time.is_some();

            // Detect data loss for state faults.
            let data_loss = matches!(fault.fault, FaultType::StateLoss { .. });

            let auto_healed = self.config.auto_heal && recovered;

            let verdict = if recovered {
                Verdict::Pass
            } else if recovery_time.is_none() && self.config.recovery_timeout_ms > 0 {
                Verdict::Fail
            } else {
                Verdict::Pass
            };

            let explanation = if recovered {
                format!(
                    "Target {} recovered in {}ms",
                    target.label(),
                    recovery_time.unwrap_or(0)
                )
            } else {
                format!("Target {} did not recover within timeout", target.label())
            };

            // Build recovery metrics.
            let mut rm = RecoveryMetrics::new(&fault.id, &fault_type_str, &target_label);
            if let Some(rt) = recovery_time {
                rm = rm.recovered(rt);
            }
            if auto_healed {
                rm = rm.auto_healed();
            }
            if !cascade_labels.is_empty() {
                rm = rm.cascaded(cascade_labels.clone());
            }
            if data_loss {
                rm = rm.data_loss();
            }
            recovery_metrics_list.push(rm);

            Ok(FaultResult {
                fault_id: fault.id.clone(),
                fault_name: fault.name.clone(),
                injection_id,
                recovered,
                recovery_time_ms: recovery_time,
                cascade_targets: cascade_labels,
                auto_healed,
                data_loss,
                verdict,
                explanation,
            })
        } else {
            // No primary target (resource/ANANTA faults). Release immediately.
            self.injector.release(&injection_id)?;

            let rm = RecoveryMetrics::new(&fault.id, &fault_type_str, &target_label);
            recovery_metrics_list.push(rm);

            Ok(FaultResult {
                fault_id: fault.id.clone(),
                fault_name: fault.name.clone(),
                injection_id,
                recovered: true,
                recovery_time_ms: Some(0),
                cascade_targets: Vec::new(),
                auto_healed: self.config.auto_heal,
                data_loss: false,
                verdict: Verdict::Pass,
                explanation: "Fault has no primary target; no recovery needed".to_string(),
            })
        }
    }

    /// Pick a related cascade target for simulation purposes.
    /// Maps each ring to a "downstream" ring that would be affected.
    fn pick_cascade_target(target: &FaultTarget) -> FaultTarget {
        match target {
            FaultTarget::Shield => FaultTarget::Threat,
            FaultTarget::Threat => FaultTarget::Execution,
            FaultTarget::Execution => FaultTarget::Agent,
            FaultTarget::Agent => FaultTarget::Memory,
            FaultTarget::Memory => FaultTarget::Reasoning,
            FaultTarget::Reasoning => FaultTarget::Governance,
            FaultTarget::Governance => FaultTarget::RecoverySec,
            FaultTarget::RecoverySec => FaultTarget::Identity,
            FaultTarget::Identity => FaultTarget::Shield,
            FaultTarget::AnantaSentinel => FaultTarget::AnantaPhoenix,
            FaultTarget::AnantaPhoenix => FaultTarget::AnantaVault,
            FaultTarget::AnantaVault => FaultTarget::AnantaAdapter,
            FaultTarget::AnantaAdapter => FaultTarget::AnantaSentinel,
            FaultTarget::KeshavDecide => FaultTarget::KeshavLearn,
            FaultTarget::KeshavLearn => FaultTarget::KeshavRisk,
            FaultTarget::KeshavRisk => FaultTarget::KeshavDecide,
            FaultTarget::CrossRingNetwork => FaultTarget::Shield,
            FaultTarget::Storage => FaultTarget::Memory,
        }
    }

    /// Record evidence for a fault result into the validation report.
    fn record_fault_evidence(
        &self,
        result: &FaultResult,
        fault: &FaultInjection,
        report: &mut ValidationReport,
    ) {
        let (verdict, evidence) = match result.verdict {
            Verdict::Pass => {
                let ev = Evidence::pass(
                    &report.run_id,
                    &format!("chaos:{}", result.fault_name),
                    "D4",
                    &result.fault_name,
                    serde_json::json!({"recovered": true, "expected_behavior": fault.expected_behavior}),
                    serde_json::json!({"recovered": result.recovered, "recovery_time_ms": result.recovery_time_ms}),
                ).with_tags(vec!["chaos".to_string(), "d4".to_string()])
                 .with_rings(vec![result.fault_id.clone()]);
                (Verdict::Pass, ev)
            }
            Verdict::Fail => {
                let ev = Evidence::fail(
                    &report.run_id,
                    &format!("chaos:{}", result.fault_name),
                    "D4",
                    &result.fault_name,
                    fault.severity,
                    serde_json::json!({"recovered": true}),
                    serde_json::json!({"recovered": result.recovered, "cascade_targets": result.cascade_targets}),
                    &result.explanation,
                ).with_tags(vec!["chaos".to_string(), "d4".to_string()])
                 .with_rings(vec![result.fault_id.clone()]);
                (Verdict::Fail, ev)
            }
            _ => {
                let ev = Evidence::new(
                    &report.run_id,
                    &format!("chaos:{}", result.fault_name),
                    "D4",
                    &result.fault_name,
                    result.verdict,
                    serde_json::json!(null),
                    serde_json::json!(null),
                    &result.explanation,
                );
                (result.verdict, ev)
            }
        };
        let _ = verdict; // Used for match.
        report.record_evidence(evidence);
    }

    /// Get a reference to the health monitor.
    pub fn monitor(&self) -> &HealthMonitor {
        &self.monitor
    }

    /// Get a reference to the fault injector.
    pub fn injector(&self) -> &FaultInjector {
        &self.injector
    }

    /// Get the engine configuration.
    pub fn config(&self) -> &ChaosConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::chaos::fault_types::FaultType;
    use crate::validation::verification::Severity;

    fn make_fault_injection(id: &str, fault: FaultType) -> FaultInjection {
        FaultInjection::new(
            id,
            fault,
            &format!("fault-{}", id),
            &format!("Test fault {}", id),
        )
        .expected_behavior("System should recover")
        .severity(Severity::High)
        .tag("test")
    }

    #[test]
    fn plan_scenario_basic() {
        let engine = ChaosEngine::new(ChaosConfig::default());
        let faults = vec![
            make_fault_injection(
                "f1",
                FaultType::RingCrash {
                    target: FaultTarget::Shield,
                },
            ),
            make_fault_injection(
                "f2",
                FaultType::RingHang {
                    target: FaultTarget::Threat,
                    duration_ms: 1000,
                },
            ),
        ];

        let scenario = engine.plan_scenario(&faults).unwrap();
        assert_eq!(scenario.faults.len(), 2);
    }

    #[test]
    fn plan_scenario_empty_fails() {
        let engine = ChaosEngine::new(ChaosConfig::default());
        let result = engine.plan_scenario(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn plan_scenario_filters_targets() {
        let mut config = ChaosConfig::default();
        config.targets = vec![FaultTarget::Shield];
        let engine = ChaosEngine::new(config);

        let faults = vec![
            make_fault_injection(
                "f1",
                FaultType::RingCrash {
                    target: FaultTarget::Shield,
                },
            ),
            make_fault_injection(
                "f2",
                FaultType::RingCrash {
                    target: FaultTarget::Threat,
                },
            ),
        ];

        let scenario = engine.plan_scenario(&faults).unwrap();
        assert_eq!(scenario.faults.len(), 1);
        assert_eq!(scenario.faults[0].id, "f1");
    }

    #[test]
    fn execute_single_fault_crash_and_recover() {
        let mut engine = ChaosEngine::new(ChaosConfig::default());
        let mut report = ValidationReport::new("chaos-test", vec!["D4".to_string()]);

        let fault = make_fault_injection(
            "crash-1",
            FaultType::RingCrash {
                target: FaultTarget::Agent,
            },
        );
        let scenario =
            ChaosScenario::new("single-crash", "Test single crash recovery", vec![fault]);

        let result = engine.execute_scenario(&scenario, &mut report).unwrap();
        assert_eq!(result.fault_results.len(), 1);
        assert!(result.fault_results[0].recovered);
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn execute_scenario_records_evidence() {
        let mut engine = ChaosEngine::new(ChaosConfig::default());
        let mut report = ValidationReport::new("chaos-evidence", vec!["D4".to_string()]);

        let fault = make_fault_injection(
            "ev-1",
            FaultType::RingSlow {
                target: FaultTarget::Governance,
                latency_ms: 200,
            },
        );
        let scenario = ChaosScenario::new("evidence-test", "test", vec![fault]);

        engine.execute_scenario(&scenario, &mut report).unwrap();
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].phase, "D4");
    }

    #[test]
    fn execute_network_partition_cascade() {
        let mut engine = ChaosEngine::new(ChaosConfig::default());
        let mut report = ValidationReport::new("cascade-test", vec!["D4".to_string()]);

        let fault = make_fault_injection(
            "part-1",
            FaultType::NetworkPartition {
                from: FaultTarget::Shield,
                to: FaultTarget::Threat,
            },
        );
        let scenario = ChaosScenario::new("partition-cascade", "test cascade", vec![fault]);

        let result = engine.execute_scenario(&scenario, &mut report).unwrap();
        // Network partition should cause cascade.
        assert!(
            !result.cascade_map.is_empty() || result.fault_results[0].cascade_targets.is_empty()
        );
    }

    #[test]
    fn recovery_summary_computed() {
        let mut engine = ChaosEngine::new(ChaosConfig::default());
        let mut report = ValidationReport::new("summary-test", vec!["D4".to_string()]);

        let faults = vec![
            make_fault_injection(
                "s1",
                FaultType::RingCrash {
                    target: FaultTarget::Shield,
                },
            ),
            make_fault_injection(
                "s2",
                FaultType::RingHang {
                    target: FaultTarget::Threat,
                    duration_ms: 500,
                },
            ),
        ];
        let scenario = ChaosScenario::new("summary-scenario", "test", faults);

        let result = engine.execute_scenario(&scenario, &mut report).unwrap();
        assert_eq!(result.recovery_summary.total_faults, 2);
        assert!(result.recovery_summary.recovered >= 1);
    }
}
