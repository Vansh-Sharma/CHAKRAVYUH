// Keshav-Orchestrate — Ring Coordination (Basic)
//
// Phase 3 version: Static routing rules. Determines which rings
// evaluate each request. Shields and Threat can run in parallel.
// Execution depends on Threat verdict (don't sandbox an already-blocked request).
//
// Phase 6 version: Dynamic ring selection with ML optimization.
//
// Latency Budget: <1ms overhead

use serde::{Deserialize, Serialize};

/// Keshav-Orchestrate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrateConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Static routing rules for request types.
    #[serde(default)]
    pub routing: Vec<RoutingRule>,
}

fn default_enabled() -> bool {
    true
}

impl Default for OrchestrateConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            routing: vec![
                RoutingRule {
                    request_type: RequestType::HealthCheck,
                    rings: vec![],
                    parallel: false,
                    sequential_deps: vec![],
                },
                RoutingRule {
                    request_type: RequestType::SimplePrompt,
                    // Cognitive rings in parallel + Reasoning + Governance
                    rings: vec![RingId::Shield, RingId::Threat, RingId::Identity, RingId::Memory, RingId::Reasoning, RingId::Governance],
                    parallel: true,
                    sequential_deps: vec![],
                },
                RoutingRule {
                    request_type: RequestType::ToolCall,
                    // All 9 rings: cognitive + tool rings + Reasoning + Governance + Recovery
                    rings: vec![RingId::Shield, RingId::Threat, RingId::Identity, RingId::Memory, RingId::Agent, RingId::Execution, RingId::Reasoning, RingId::Governance, RingId::Recovery],
                    parallel: true,
                    sequential_deps: vec![
                        SequentialDep {
                            ring: RingId::Agent,
                            depends_on: RingId::Threat,
                            condition: DepCondition::AllowOnly,
                        },
                        SequentialDep {
                            ring: RingId::Execution,
                            depends_on: RingId::Agent,
                            condition: DepCondition::AllowOnly,
                        },
                    ],
                },
                RoutingRule {
                    request_type: RequestType::AuthRequest,
                    rings: vec![RingId::Shield, RingId::Identity],
                    parallel: false,
                    sequential_deps: vec![
                        SequentialDep {
                            ring: RingId::Identity,
                            depends_on: RingId::Shield,
                            condition: DepCondition::AllowOnly,
                        },
                    ],
                },
                RoutingRule {
                    request_type: RequestType::AdminOperation,
                    rings: vec![RingId::Shield, RingId::Identity],
                    parallel: false,
                    sequential_deps: vec![
                        SequentialDep {
                            ring: RingId::Identity,
                            depends_on: RingId::Shield,
                            condition: DepCondition::AllowOnly,
                        },
                    ],
                },
                RoutingRule {
                    request_type: RequestType::Unknown,
                    // Fail Secure: all 9 available rings
                    rings: vec![RingId::Shield, RingId::Threat, RingId::Identity, RingId::Memory, RingId::Agent, RingId::Execution, RingId::Reasoning, RingId::Governance, RingId::Recovery],
                    parallel: true,
                    sequential_deps: vec![
                        SequentialDep {
                            ring: RingId::Agent,
                            depends_on: RingId::Threat,
                            condition: DepCondition::AllowOnly,
                        },
                        SequentialDep {
                            ring: RingId::Execution,
                            depends_on: RingId::Agent,
                            condition: DepCondition::AllowOnly,
                        },
                    ],
                },
            ],
        }
    }
}

/// Types of incoming requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    /// Health check — no rings needed.
    HealthCheck,
    /// Simple prompt (read-only) — Shield + Threat.
    SimplePrompt,
    /// Tool call — Shield + Threat + Execution.
    ToolCall,
    /// Authentication request — Shield only.
    AuthRequest,
    /// Admin operation — Shield only (Governance in Phase 5).
    AdminOperation,
    /// Unknown — all available rings (Fail Secure).
    Unknown,
}

/// Ring identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RingId {
    Shield,   // Ring 1
    Identity, // Ring 2 (Phase 4)
    Threat,   // Ring 3
    Agent,    // Ring 4 (Phase 4)
    Memory,   // Ring 5 (Phase 4)
    Execution,// Ring 6
    Reasoning,// Ring 7 (Phase 5)
    Governance,// Ring 8 (Phase 5)
    Recovery, // Ring 9 (Phase 5)
}

/// A static routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub request_type: RequestType,
    pub rings: Vec<RingId>,
    #[serde(default)]
    pub parallel: bool,
    #[serde(default)]
    pub sequential_deps: Vec<SequentialDep>,
}

/// A sequential dependency between rings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequentialDep {
    /// The ring that depends on another.
    pub ring: RingId,
    /// The ring this depends on.
    pub depends_on: RingId,
    /// Condition under which the dependent ring should evaluate.
    #[serde(default)]
    pub condition: DepCondition,
}

/// Condition for sequential dependency evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DepCondition {
    /// Only evaluate if the dependency returned Allow.
    AllowOnly,
    /// Only evaluate if the dependency returned Deny.
    DenyOnly,
    /// Always evaluate regardless of dependency result.
    Always,
}

impl Default for DepCondition {
    fn default() -> Self {
        DepCondition::AllowOnly
    }
}

/// The result of orchestration — which rings to run and how.
#[derive(Debug, Clone, Serialize)]
pub struct OrchestrationPlan {
    pub request_type: RequestType,
    /// Rings to evaluate in parallel (batch 1).
    pub parallel_batch: Vec<RingId>,
    /// Rings to evaluate sequentially after parallel batch (batch 2).
    /// Each entry has its dependency condition.
    pub sequential_batch: Vec<(RingId, RingId, DepCondition)>,
    /// Total expected rings in this evaluation.
    pub total_rings: usize,
}

/// Keshav-Orchestrate — determines which rings evaluate each request.
///
/// Phase 3 version: Static rules. Phase 6: Dynamic ML-based.
#[derive(Clone)]
pub struct KeshavOrchestrate {
    config: OrchestrateConfig,
}

impl KeshavOrchestrate {
    pub fn new(config: OrchestrateConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(OrchestrateConfig::default())
    }

    /// Classify a request and produce an orchestration plan.
    pub fn plan(
        &self,
        request_type: RequestType,
        has_tool_call: bool,
    ) -> OrchestrationPlan {
        if !self.config.enabled {
            return OrchestrationPlan {
                request_type,
                parallel_batch: vec![RingId::Shield, RingId::Threat, RingId::Execution],
                sequential_batch: vec![],
                total_rings: 3,
            };
        }

        // Override: if there's a tool call, always use ToolCall routing.
        let effective_type = if has_tool_call {
            RequestType::ToolCall
        } else {
            request_type
        };

        // Find matching rule.
        let rule = self
            .config
            .routing
            .iter()
            .find(|r| r.request_type == effective_type);

        let (parallel, sequential) = match rule {
            Some(r) => {
                // Split rings into parallel and sequential based on deps.
                let dep_rings: std::collections::HashSet<&RingId> =
                    r.sequential_deps.iter().map(|d| &d.ring).collect();
                let parallel_batch: Vec<RingId> = r
                    .rings
                    .iter()
                    .filter(|ring| !dep_rings.contains(ring))
                    .cloned()
                    .collect();
                let sequential_batch: Vec<(RingId, RingId, DepCondition)> = r
                    .sequential_deps
                    .iter()
                    .map(|d| (d.ring.clone(), d.depends_on.clone(), d.condition.clone()))
                    .collect();
                (parallel_batch, sequential_batch)
            }
            None => {
                // Unknown rule — all available rings (Fail Secure).
                (
                    vec![RingId::Shield, RingId::Threat],
                    vec![(RingId::Execution, RingId::Threat, DepCondition::AllowOnly)],
                )
            }
        };

        let total = parallel.len() + sequential.len();

        OrchestrationPlan {
            request_type: effective_type,
            parallel_batch: parallel,
            sequential_batch: sequential,
            total_rings: total,
        }
    }

    /// Get the configuration (for introspection).
    pub fn config(&self) -> &OrchestrateConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_no_rings() {
        let orch = KeshavOrchestrate::with_defaults();
        let plan = orch.plan(RequestType::HealthCheck, false);
        assert!(plan.parallel_batch.is_empty());
        assert_eq!(plan.total_rings, 0);
    }

    #[test]
    fn simple_prompt_shield_threat_parallel() {
        let orch = KeshavOrchestrate::with_defaults();
        let plan = orch.plan(RequestType::SimplePrompt, false);
        assert!(plan.parallel_batch.contains(&RingId::Shield));
        assert!(plan.parallel_batch.contains(&RingId::Threat));
        // Phase 4+: SimplePrompt routes Identity + Memory + Reasoning + Governance
        assert!(plan.parallel_batch.contains(&RingId::Identity));
        assert!(plan.parallel_batch.contains(&RingId::Memory));
        assert!(plan.parallel_batch.contains(&RingId::Reasoning));
        assert!(plan.parallel_batch.contains(&RingId::Governance));
        assert_eq!(plan.total_rings, 6);
    }

    #[test]
    fn tool_call_includes_execution_sequential() {
        let orch = KeshavOrchestrate::with_defaults();
        let plan = orch.plan(RequestType::SimplePrompt, true); // has_tool_call overrides
        assert!(plan.parallel_batch.contains(&RingId::Shield));
        assert!(plan.parallel_batch.contains(&RingId::Threat));
        assert!(!plan.sequential_batch.is_empty());
        // Phase 4: Execution depends on Agent (not Threat directly).
        let exec_dep = plan.sequential_batch.iter().find(|(r, _, _)| *r == RingId::Execution);
        assert!(exec_dep.is_some());
        assert_eq!(exec_dep.unwrap().1, RingId::Agent);
        // Agent depends on Threat.
        let agent_dep = plan.sequential_batch.iter().find(|(r, _, _)| *r == RingId::Agent);
        assert!(agent_dep.is_some());
        assert_eq!(agent_dep.unwrap().1, RingId::Threat);
    }

    #[test]
    fn unknown_fails_secure() {
        let orch = KeshavOrchestrate::with_defaults();
        let plan = orch.plan(RequestType::Unknown, false);
        assert!(plan.parallel_batch.contains(&RingId::Shield));
        assert!(plan.parallel_batch.contains(&RingId::Threat));
        // Should have Execution as sequential dep.
        assert!(!plan.sequential_batch.is_empty());
    }

    #[test]
    fn disabled_runs_all_rings() {
        let orch = KeshavOrchestrate::new(OrchestrateConfig { enabled: false, ..Default::default() });
        let plan = orch.plan(RequestType::HealthCheck, false);
        assert_eq!(plan.total_rings, 3); // All 3 rings despite health check
    }
}
