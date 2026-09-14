// ANANTA Evidence Correlation & Attack Chain Reconstruction
//
// This module transforms raw audit entries into a correlated evidence graph,
// reconstructs attack chains via backward-chaining, maps evidence to the
// MITRE ATT&CK framework, fuses conflicting evidence using Dempster-Shafer
// theory, and reconstructs temporal timelines with gap and burst detection.
//
// Design principles:
//   - Every correlation is scored and explorable.
//   - Attack chains are ranked by severity, density, and temporal coherence.
//   - MITRE mapping is first-class, not an afterthought.
//   - Dempster-Shafer fusion handles uncertainty rigorously.
//   - Timeline analysis surfaces temporal attack patterns.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::AuditCategory;

// ═══════════════════════════════════════════════════════════════════════════
// §1. Core Evidence Types
// ═══════════════════════════════════════════════════════════════════════════

/// Severity level for evidence items, mirroring the audit severity but
/// extended with a numeric score for ranking and fusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSeverity {
    /// Low-priority informational evidence.
    Low,
    /// Moderate-priority evidence warranting investigation.
    Medium,
    /// High-priority evidence indicating likely malicious activity.
    High,
    /// Critical evidence confirming an active intrusion.
    Critical,
}

impl EvidenceSeverity {
    /// Convert severity to a numeric score in [0.0, 1.0].
    pub fn score(&self) -> f64 {
        match self {
            EvidenceSeverity::Low => 0.25,
            EvidenceSeverity::Medium => 0.5,
            EvidenceSeverity::High => 0.75,
            EvidenceSeverity::Critical => 1.0,
        }
    }

    /// Parse from a numeric score, clamping to the nearest level.
    pub fn from_score(s: f64) -> Self {
        if s >= 0.875 {
            EvidenceSeverity::Critical
        } else if s >= 0.625 {
            EvidenceSeverity::High
        } else if s >= 0.375 {
            EvidenceSeverity::Medium
        } else {
            EvidenceSeverity::Low
        }
    }
}

/// A single piece of evidence extracted from the audit trail or external
/// observability sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceNode {
    /// Unique identifier for this evidence item.
    pub id: String,
    /// Human-readable description of what was observed.
    pub description: String,
    /// The ANANTA audit category this evidence originates from.
    pub category: AuditCategory,
    /// Severity assessment of this evidence.
    pub severity: EvidenceSeverity,
    /// When this evidence was observed (UTC, RFC 3339).
    pub observed_at: DateTime<Utc>,
    /// Set of entity identifiers involved (hosts, users, IPs, processes, etc.).
    pub entities: HashSet<String>,
    /// Arbitrary key-value metadata for structured enrichment.
    pub metadata: HashMap<String, serde_json::Value>,
    /// Confidence in this evidence being accurate [0.0, 1.0].
    pub confidence: f64,
    /// Whether this evidence has been marked as part of an attack chain.
    pub chained: bool,
}

impl EvidenceNode {
    /// Create a new evidence node with the given parameters.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        category: AuditCategory,
        severity: EvidenceSeverity,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            category,
            severity,
            observed_at,
            entities: HashSet::new(),
            metadata: HashMap::new(),
            confidence: 1.0,
            chained: false,
        }
    }

    /// Add an entity to this evidence node.
    pub fn with_entity(mut self, entity: impl Into<String>) -> Self {
        self.entities.insert(entity.into());
        self
    }

    /// Set the confidence level.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Insert a metadata key-value pair.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §2. Evidence Correlation Graph
// ═══════════════════════════════════════════════════════════════════════════

/// A directed edge in the evidence correlation graph. The edge runs from
/// `source` to `target`, with `weight` representing the strength of
/// correlation (0.0 = unrelated, 1.0 = strongly correlated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEdge {
    /// ID of the source evidence node.
    pub source: String,
    /// ID of the target evidence node.
    pub target: String,
    /// Combined correlation weight in [0.0, 1.0].
    pub weight: f64,
    /// Individual component scores that compose the weight.
    pub components: CorrelationComponents,
}

/// Decomposed correlation components for explainability.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorrelationComponents {
    /// Temporal proximity score based on exponential decay.
    pub temporal: f64,
    /// Entity overlap score based on Jaccard similarity.
    pub entity_overlap: f64,
    /// Category co-occurrence bonus.
    pub category_cooccurrence: f64,
}

impl CorrelationComponents {
    /// Compute the combined weight as a weighted average of components.
    pub fn combined(&self) -> f64 {
        // Weights: temporal 40%, entity overlap 40%, category 20%
        (self.temporal * 0.4) + (self.entity_overlap * 0.4) + (self.category_cooccurrence * 0.2)
    }
}

/// A directed acyclic graph (DAG) of evidence nodes connected by weighted
/// correlation edges. Used as the foundational data structure for attack
/// chain reconstruction and timeline analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraph {
    /// All evidence nodes indexed by ID.
    pub nodes: HashMap<String, EvidenceNode>,
    /// All correlation edges.
    pub edges: Vec<CorrelationEdge>,
    /// Half-life in seconds for temporal decay. Default: 300 (5 minutes).
    pub temporal_half_life_secs: f64,
    /// Minimum weight threshold to include an edge in the graph.
    pub min_weight_threshold: f64,
    /// Category co-occurrence matrix: (cat_a, cat_b) -> bonus score.
    #[serde(skip)]
    pub category_affinity: HashMap<(AuditCategory, AuditCategory), f64>,
}

impl Default for EvidenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceGraph {
    /// Create a new empty evidence graph with default parameters.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            temporal_half_life_secs: 300.0,
            min_weight_threshold: 0.1,
            category_affinity: Self::default_category_affinity(),
        }
    }

    /// Build the default category affinity matrix. Categories that commonly
    /// appear together in attack patterns receive higher affinity scores.
    fn default_category_affinity() -> HashMap<(AuditCategory, AuditCategory), f64> {
        let mut m = HashMap::new();
        let pairs: &[(&[AuditCategory], f64)] = &[
            (&[AuditCategory::Drift, AuditCategory::Trust], 0.7),
            (&[AuditCategory::Drift, AuditCategory::Integrity], 0.8),
            (&[AuditCategory::Integrity, AuditCategory::Trust], 0.6),
            (&[AuditCategory::KeyManagement, AuditCategory::Trust], 0.5),
            (&[AuditCategory::Configuration, AuditCategory::Drift], 0.6),
            (
                &[AuditCategory::Configuration, AuditCategory::KeyManagement],
                0.5,
            ),
            (&[AuditCategory::Health, AuditCategory::Trust], 0.4),
            (
                &[AuditCategory::Adaptation, AuditCategory::Configuration],
                0.5,
            ),
            (&[AuditCategory::Recovery, AuditCategory::Trust], 0.6),
            (&[AuditCategory::Recovery, AuditCategory::Integrity], 0.7),
            (&[AuditCategory::Consensus, AuditCategory::Trust], 0.4),
            (
                &[AuditCategory::Lifecycle, AuditCategory::Configuration],
                0.3,
            ),
        ];
        for (cats, score) in pairs {
            let key_ab = (cats[0].clone(), cats[1].clone());
            let key_ba = (cats[1].clone(), cats[0].clone());
            m.insert(key_ab, *score);
            m.insert(key_ba, *score);
        }
        m
    }

    /// Insert an evidence node into the graph.
    pub fn add_node(&mut self, node: EvidenceNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Compute the temporal proximity score between two evidence nodes using
    /// exponential decay: `score = exp(-lambda * delta_t)` where
    /// `lambda = ln(2) / half_life`.
    pub fn temporal_score(&self, a: &EvidenceNode, b: &EvidenceNode) -> f64 {
        let delta = (a.observed_at - b.observed_at).num_seconds().abs() as f64;
        if delta == 0.0 {
            return 1.0;
        }
        let lambda = std::f64::consts::LN_2 / self.temporal_half_life_secs;
        (-lambda * delta).exp()
    }

    /// Compute the Jaccard similarity between the entity sets of two
    /// evidence nodes: `|A ∩ B| / |A ∪ B|`.
    pub fn entity_jaccard(&self, a: &EvidenceNode, b: &EvidenceNode) -> f64 {
        if a.entities.is_empty() && b.entities.is_empty() {
            return 0.0;
        }
        let intersection = a.entities.intersection(&b.entities).count();
        let union = a.entities.union(&b.entities).count();
        intersection as f64 / union as f64
    }

    /// Look up the category co-occurrence affinity between two categories.
    fn category_affinity_score(&self, a: &AuditCategory, b: &AuditCategory) -> f64 {
        *self
            .category_affinity
            .get(&(a.clone(), b.clone()))
            .unwrap_or(&0.0)
    }

    /// Compute all correlation edges for the current set of nodes.
    /// An edge is created if the combined weight exceeds `min_weight_threshold`.
    /// Edges are directed from earlier to later evidence (chronological).
    pub fn compute_edges(&mut self) {
        self.edges.clear();
        let node_list: Vec<&EvidenceNode> = self.nodes.values().collect();
        let n = node_list.len();

        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let a = node_list[i];
                let b = node_list[j];

                // Only create edge from earlier to later.
                if a.observed_at >= b.observed_at {
                    continue;
                }

                let temporal = self.temporal_score(a, b);
                let entity_overlap = self.entity_jaccard(a, b);
                let cat_score = self.category_affinity_score(&a.category, &b.category);

                let components = CorrelationComponents {
                    temporal,
                    entity_overlap,
                    category_cooccurrence: cat_score,
                };

                let weight = components.combined();
                if weight >= self.min_weight_threshold {
                    self.edges.push(CorrelationEdge {
                        source: a.id.clone(),
                        target: b.id.clone(),
                        weight,
                        components,
                    });
                }
            }
        }
    }

    /// Get all nodes that have an incoming edge to the given node.
    pub fn predecessors(&self, node_id: &str) -> Vec<&CorrelationEdge> {
        self.edges.iter().filter(|e| e.target == node_id).collect()
    }

    /// Get all nodes that have an outgoing edge from the given node.
    pub fn successors(&self, node_id: &str) -> Vec<&CorrelationEdge> {
        self.edges.iter().filter(|e| e.source == node_id).collect()
    }

    /// Return the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §3. MITRE ATT&CK Framework Mapping
// ═══════════════════════════════════════════════════════════════════════════

/// The 14 MITRE ATT&CK Enterprise tactics, ordered roughly by kill-chain
/// progression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub enum MitreTactic {
    /// Tactic TA00XX: The adversary is trying to get into your network.
    InitialAccess,
    /// Tactic TA0002: The adversary is trying to run malicious code.
    Execution,
    /// Tactic TA0003: The adversary is trying to maintain their foothold.
    Persistence,
    /// Tactic TA0004: The adversary is trying to gain higher-level permissions.
    PrivilegeEscalation,
    /// Tactic TA0005: The adversary is trying to avoid being detected.
    DefenseEvasion,
    /// Tactic TA0006: The adversary is trying to steal account names and passwords.
    CredentialAccess,
    /// Tactic TA0007: The adversary is trying to figure out your environment.
    Discovery,
    /// Tactic TA0008: The adversary is trying to move through your environment.
    LateralMovement,
    /// Tactic TA0009: The adversary is trying to gather data of interest.
    Collection,
    /// Tactic TA0010: The adversary is trying to steal data.
    Exfiltration,
    /// Tactic TA0011: The adversary is trying to communicate with compromised
    /// systems to control them.
    CommandAndControl,
    /// Tactic TA0040: The adversary is trying to manipulate, interrupt, or
    /// destroy your systems and data.
    Impact,
}

impl MitreTactic {
    /// Return the MITRE tactic ID string.
    pub fn tactic_id(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Impact => "TA0040",
        }
    }

    /// Return a human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Impact => "Impact",
        }
    }

    /// Return the ordinal position of this tactic in the kill chain
    /// (0-based), used for temporal coherence scoring.
    pub fn kill_chain_order(&self) -> usize {
        match self {
            MitreTactic::InitialAccess => 0,
            MitreTactic::Execution => 1,
            MitreTactic::Persistence => 2,
            MitreTactic::PrivilegeEscalation => 3,
            MitreTactic::DefenseEvasion => 4,
            MitreTactic::CredentialAccess => 5,
            MitreTactic::Discovery => 6,
            MitreTactic::LateralMovement => 7,
            MitreTactic::Collection => 8,
            MitreTactic::Exfiltration => 9,
            MitreTactic::CommandAndControl => 10,
            MitreTactic::Impact => 11,
        }
    }

    /// Return all 12 tactics in kill-chain order.
    pub fn all() -> Vec<MitreTactic> {
        vec![
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::Exfiltration,
            MitreTactic::CommandAndControl,
            MitreTactic::Impact,
        ]
    }
}

/// A specific MITRE ATT&CK technique with its ID and name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MitreTechnique {
    /// MITRE technique ID, e.g. "T1059".
    pub technique_id: String,
    /// Human-readable technique name.
    pub name: String,
    /// The parent tactic this technique belongs to.
    pub tactic: MitreTactic,
}

impl MitreTechnique {
    /// Create a new MITRE technique reference.
    pub fn new(
        technique_id: impl Into<String>,
        name: impl Into<String>,
        tactic: MitreTactic,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            name: name.into(),
            tactic,
        }
    }
}

/// Mapping from ANANTA audit categories to plausible MITRE ATT&CK
/// techniques. Each category maps to one or more techniques with a
/// confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryMitreMapping {
    /// The ANANTA audit category.
    pub category: AuditCategory,
    /// Mapped techniques with confidence scores.
    pub techniques: Vec<(MitreTechnique, f64)>,
}

/// The MITRE ATT&CK mapper: takes evidence nodes and produces ranked
/// tactic/technique hypotheses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapper {
    /// Mapping table from audit categories to MITRE techniques.
    mappings: Vec<CategoryMitreMapping>,
    /// Cache of category -> techniques for fast lookup.
    #[serde(skip)]
    lookup: HashMap<AuditCategory, Vec<(MitreTechnique, f64)>>,
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreMapper {
    /// Create a new MITRE mapper with the default built-in mapping table.
    pub fn new() -> Self {
        let mappings = Self::build_default_mappings();
        let lookup = mappings
            .iter()
            .map(|m| (m.category.clone(), m.techniques.clone()))
            .collect();
        Self { mappings, lookup }
    }

    /// Construct the default ANANTA-category-to-MITRE mapping table.
    /// These mappings represent the analyst's knowledge of which ANANTA
    /// events correspond to which ATT&CK techniques.
    fn build_default_mappings() -> Vec<CategoryMitreMapping> {
        vec![
            CategoryMitreMapping {
                category: AuditCategory::Trust,
                techniques: vec![
                    (
                        MitreTechnique::new("T1078", "Valid Accounts", MitreTactic::InitialAccess),
                        0.7,
                    ),
                    (
                        MitreTechnique::new(
                            "T1550",
                            "Use Alternate Authentication Material",
                            MitreTactic::LateralMovement,
                        ),
                        0.5,
                    ),
                    (
                        MitreTechnique::new(
                            "T1133",
                            "External Remote Services",
                            MitreTactic::InitialAccess,
                        ),
                        0.6,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Drift,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1059",
                            "Command and Scripting Interpreter",
                            MitreTactic::Execution,
                        ),
                        0.8,
                    ),
                    (
                        MitreTechnique::new(
                            "T1112",
                            "Modify Registry",
                            MitreTactic::DefenseEvasion,
                        ),
                        0.6,
                    ),
                    (
                        MitreTechnique::new(
                            "T1547",
                            "Boot or Logon Autostart Execution",
                            MitreTactic::Persistence,
                        ),
                        0.5,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Integrity,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1486",
                            "Data Encrypted for Impact",
                            MitreTactic::Impact,
                        ),
                        0.8,
                    ),
                    (
                        MitreTechnique::new("T1565", "Data Manipulation", MitreTactic::Impact),
                        0.7,
                    ),
                    (
                        MitreTechnique::new(
                            "T1070",
                            "Indicator Removal",
                            MitreTactic::DefenseEvasion,
                        ),
                        0.6,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Configuration,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1578",
                            "Modify Cloud Compute Infrastructure",
                            MitreTactic::Persistence,
                        ),
                        0.7,
                    ),
                    (
                        MitreTechnique::new(
                            "T1562",
                            "Impair Defenses",
                            MitreTactic::DefenseEvasion,
                        ),
                        0.8,
                    ),
                    (
                        MitreTechnique::new(
                            "T1078.004",
                            "Cloud Account",
                            MitreTactic::InitialAccess,
                        ),
                        0.5,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::KeyManagement,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1552",
                            "Unsecured Credentials",
                            MitreTactic::CredentialAccess,
                        ),
                        0.9,
                    ),
                    (
                        MitreTechnique::new(
                            "T1555",
                            "Credentials from Password Stores",
                            MitreTactic::CredentialAccess,
                        ),
                        0.7,
                    ),
                    (
                        MitreTechnique::new(
                            "T1606",
                            "Forge Web Credentials",
                            MitreTactic::CredentialAccess,
                        ),
                        0.6,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Adaptation,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1027",
                            "Obfuscated Files or Information",
                            MitreTactic::DefenseEvasion,
                        ),
                        0.6,
                    ),
                    (
                        MitreTechnique::new(
                            "T1567",
                            "Exfiltration Over Web Service",
                            MitreTactic::Exfiltration,
                        ),
                        0.5,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Recovery,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1490",
                            "Inhibit System Recovery",
                            MitreTactic::Impact,
                        ),
                        0.8,
                    ),
                    (
                        MitreTechnique::new("T1489", "Service Stop", MitreTactic::Impact),
                        0.6,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Health,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1498",
                            "Network Denial of Service",
                            MitreTactic::Impact,
                        ),
                        0.6,
                    ),
                    (
                        MitreTechnique::new(
                            "T1499",
                            "Endpoint Denial of Service",
                            MitreTactic::Impact,
                        ),
                        0.6,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Consensus,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T0882",
                            "Compromised Host Software",
                            MitreTactic::CommandAndControl,
                        ),
                        0.4,
                    ),
                    (
                        MitreTechnique::new(
                            "T1053",
                            "Scheduled Task/Job",
                            MitreTactic::Persistence,
                        ),
                        0.3,
                    ),
                ],
            },
            CategoryMitreMapping {
                category: AuditCategory::Lifecycle,
                techniques: vec![
                    (
                        MitreTechnique::new(
                            "T1543",
                            "Create or Modify System Process",
                            MitreTactic::Persistence,
                        ),
                        0.5,
                    ),
                    (
                        MitreTechnique::new("T1036", "Masquerading", MitreTactic::DefenseEvasion),
                        0.4,
                    ),
                ],
            },
        ]
    }

    /// Given a collection of evidence nodes, return a ranked list of
    /// (tactic, aggregate_score) pairs. The score aggregates evidence
    /// confidence, severity, and mapping confidence.
    pub fn likely_tactics(&self, nodes: &[EvidenceNode]) -> Vec<(MitreTactic, f64)> {
        let mut tactic_scores: HashMap<MitreTactic, f64> = HashMap::new();
        for node in nodes {
            if let Some(techniques) = self.lookup.get(&node.category) {
                for (technique, mapping_conf) in techniques {
                    let entry = tactic_scores.entry(technique.tactic.clone()).or_insert(0.0);
                    *entry += node.severity.score() * node.confidence * mapping_conf;
                }
            }
        }
        // Normalize scores to [0, 1] range.
        let max_score = tactic_scores.values().copied().fold(0.0_f64, f64::max);
        if max_score > 0.0 {
            for v in tactic_scores.values_mut() {
                *v /= max_score;
            }
        }
        let mut ranked: Vec<_> = tactic_scores.into_iter().collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Given a collection of evidence nodes, return the top-K techniques
    /// ranked by aggregate evidence-weighted confidence.
    pub fn likely_techniques(
        &self,
        nodes: &[EvidenceNode],
        top_k: usize,
    ) -> Vec<(MitreTechnique, f64)> {
        let mut technique_scores: HashMap<String, (MitreTechnique, f64)> = HashMap::new();
        for node in nodes {
            if let Some(techniques) = self.lookup.get(&node.category) {
                for (technique, mapping_conf) in techniques {
                    let key = technique.technique_id.clone();
                    let score = node.severity.score() * node.confidence * mapping_conf;
                    let entry = technique_scores
                        .entry(key)
                        .or_insert((technique.clone(), 0.0));
                    entry.1 += score;
                }
            }
        }
        let mut ranked: Vec<_> = technique_scores.into_values().collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.truncate(top_k);
        ranked
    }

    /// Map a single evidence node to its most likely MITRE technique.
    pub fn map_node(&self, node: &EvidenceNode) -> Vec<(MitreTechnique, f64)> {
        self.lookup
            .get(&node.category)
            .map(|techniques| {
                techniques
                    .iter()
                    .map(|(t, c)| (t.clone(), c * node.confidence * node.severity.score()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §4. Attack Chain Reconstruction
// ═══════════════════════════════════════════════════════════════════════════

/// A reconstructed attack chain: an ordered sequence of evidence nodes
/// that form a plausible attack narrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Ordered list of evidence node IDs forming the chain.
    pub node_ids: Vec<String>,
    /// Aggregate score for this chain (higher = more plausible).
    pub score: f64,
    /// Decomposed scoring components.
    pub score_breakdown: ChainScoreBreakdown,
    /// The MITRE tactics this chain touches, in order.
    pub tactics_touched: Vec<MitreTactic>,
    /// Total wall-clock duration of the chain.
    pub duration: Duration,
}

/// Scoring components for an attack chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainScoreBreakdown {
    /// Sum of severity scores across all nodes in the chain.
    pub total_severity: f64,
    /// Number of evidence nodes per unit time (nodes/minute).
    pub evidence_density: f64,
    /// How well the chain follows a monotonic MITRE kill-chain order.
    pub temporal_coherence: f64,
    /// Average correlation weight along the chain edges.
    pub avg_edge_weight: f64,
}

impl AttackChain {
    /// Compute the overall chain score from its components.
    /// Formula: 0.35 * severity + 0.25 * density + 0.25 * coherence + 0.15 * edge_weight
    pub fn compute_score(breakdown: &ChainScoreBreakdown) -> f64 {
        (breakdown.total_severity * 0.35)
            + (breakdown.evidence_density * 0.25)
            + (breakdown.temporal_coherence * 0.25)
            + (breakdown.avg_edge_weight * 0.15)
    }
}

/// The attack chain reconstructor: backward-chains from high-severity
/// evidence through the correlation graph to find plausible attack paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReconstructor {
    /// The evidence correlation graph.
    pub graph: EvidenceGraph,
    /// The MITRE mapper for tactic annotation.
    pub mapper: MitreMapper,
    /// Minimum chain length to consider.
    pub min_chain_length: usize,
    /// Maximum chain length (prevents combinatorial explosion).
    pub max_chain_length: usize,
    /// Maximum number of chains to return.
    pub top_k: usize,
    /// Minimum severity to use as a chain seed.
    pub seed_min_severity: EvidenceSeverity,
}

impl Default for ChainReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainReconstructor {
    /// Create a new chain reconstructor with default parameters.
    pub fn new() -> Self {
        Self {
            graph: EvidenceGraph::new(),
            mapper: MitreMapper::new(),
            min_chain_length: 2,
            max_chain_length: 20,
            top_k: 10,
            seed_min_severity: EvidenceSeverity::High,
        }
    }

    /// Reconstruct attack chains from the current graph state.
    /// Returns the top-K chains ranked by score.
    pub fn reconstruct(&mut self) -> Vec<AttackChain> {
        // Ensure edges are computed.
        self.graph.compute_edges();

        // Identify seed nodes: those at or above the minimum severity.
        let seeds: Vec<String> = self
            .graph
            .nodes
            .values()
            .filter(|n| n.severity >= self.seed_min_severity)
            .map(|n| n.id.clone())
            .collect();

        // Build predecessor index for fast backward traversal.
        let pred_index: HashMap<String, Vec<usize>> = {
            let mut idx: HashMap<String, Vec<usize>> = HashMap::new();
            for (i, edge) in self.graph.edges.iter().enumerate() {
                idx.entry(edge.target.clone()).or_default().push(i);
            }
            idx
        };

        // Backward-chain from each seed using BFS with pruning.
        let mut all_chains: Vec<AttackChain> = Vec::new();

        for seed in &seeds {
            let mut queue: VecDeque<Vec<String>> = VecDeque::new();
            queue.push_back(vec![seed.clone()]);

            while let Some(chain) = queue.pop_front() {
                let last = chain.last().unwrap();

                // Get predecessors of the last node.
                if let Some(pred_edges) = pred_index.get(last) {
                    let mut extended = false;
                    for &edge_idx in pred_edges {
                        let edge = &self.graph.edges[edge_idx];
                        // Prevent cycles.
                        if chain.contains(&edge.source) {
                            continue;
                        }
                        // Prune by max length.
                        if chain.len() >= self.max_chain_length {
                            continue;
                        }
                        let mut new_chain = chain.clone();
                        new_chain.push(edge.source.clone());
                        queue.push_back(new_chain);
                        extended = true;
                    }
                    // If no extensions and chain meets minimum length, score it.
                    if !extended && chain.len() >= self.min_chain_length {
                        if let Some(scored) = self.score_chain(&chain) {
                            all_chains.push(scored);
                        }
                    }
                } else if chain.len() >= self.min_chain_length {
                    if let Some(scored) = self.score_chain(&chain) {
                        all_chains.push(scored);
                    }
                }
            }
        }

        // Sort by score descending, deduplicate, take top-K.
        all_chains.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all_chains.truncate(self.top_k);

        // Mark nodes as chained.
        for chain in &all_chains {
            for nid in &chain.node_ids {
                if let Some(node) = self.graph.nodes.get_mut(nid) {
                    node.chained = true;
                }
            }
        }

        all_chains
    }

    /// Score a candidate chain. Returns `None` if the chain cannot be
    /// scored (e.g., a node is missing from the graph).
    fn score_chain(&self, chain: &[String]) -> Option<AttackChain> {
        let nodes: Vec<&EvidenceNode> = chain
            .iter()
            .map(|id| self.graph.nodes.get(id))
            .collect::<Option<Vec<_>>>()?;

        // Total severity: sum of severity scores.
        let total_severity: f64 = nodes.iter().map(|n| n.severity.score()).sum();
        let max_possible_severity = nodes.len() as f64;
        let normalized_severity = if max_possible_severity > 0.0 {
            total_severity / max_possible_severity
        } else {
            0.0
        };

        // Evidence density: nodes per minute.
        let duration_secs = if nodes.len() >= 2 {
            let first_t = nodes.first().unwrap().observed_at;
            let last_t = nodes.last().unwrap().observed_at;
            (last_t - first_t).num_seconds().unsigned_abs() as f64
        } else {
            1.0
        };
        let duration_mins = duration_secs / 60.0;
        let density = nodes.len() as f64 / duration_mins.max(0.01);
        let normalized_density = (density / 10.0).min(1.0); // Cap at 10 nodes/min.

        // Temporal coherence: check that MITRE tactic ordering is
        // monotonically non-decreasing along the chain.
        let tactic_orders: Vec<usize> = nodes
            .iter()
            .map(|n| {
                let tactics = self.mapper.likely_tactics(&[(*n).clone()]);
                tactics
                    .first()
                    .map(|(t, _)| t.kill_chain_order())
                    .unwrap_or(0)
            })
            .collect();
        let monotonic_violations = tactic_orders.windows(2).filter(|w| w[1] < w[0]).count();
        let max_violations = tactic_orders.len().saturating_sub(1);
        let temporal_coherence = if max_violations > 0 {
            1.0 - (monotonic_violations as f64 / max_violations as f64)
        } else {
            1.0
        };

        // Average edge weight along consecutive pairs.
        let edge_weights: Vec<f64> = chain
            .windows(2)
            .filter_map(|w| {
                self.graph
                    .edges
                    .iter()
                    .find(|e| e.source == w[1] && e.target == w[0])
                    .map(|e| e.weight)
            })
            .collect();
        let avg_edge_weight = if !edge_weights.is_empty() {
            edge_weights.iter().sum::<f64>() / edge_weights.len() as f64
        } else {
            0.0
        };

        let breakdown = ChainScoreBreakdown {
            total_severity: normalized_severity,
            evidence_density: normalized_density,
            temporal_coherence,
            avg_edge_weight,
        };

        let score = AttackChain::compute_score(&breakdown);

        // Collect tactics touched.
        let tactics_touched: Vec<MitreTactic> = nodes
            .iter()
            .filter_map(|n| {
                let tactics = self.mapper.likely_tactics(&[(*n).clone()]);
                tactics.first().map(|(t, _)| t.clone())
            })
            .collect();

        let duration = Duration::seconds(duration_secs as i64);

        Some(AttackChain {
            node_ids: chain.to_vec(),
            score,
            score_breakdown: breakdown,
            tactics_touched,
            duration,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §5. Evidence Fusion (Dempster-Shafer Theory)
// ═══════════════════════════════════════════════════════════════════════════

/// A Dempster-Shafer basic probability assignment (mass function) over
/// the frame of discernment {"attack", "benign", "unknown"}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MassFunction {
    /// Probability mass assigned to "attack" hypothesis.
    pub attack: f64,
    /// Probability mass assigned to "benign" hypothesis.
    pub benign: f64,
    /// Probability mass assigned to the full frame (ignorance/uncertainty).
    pub unknown: f64,
}

impl MassFunction {
    /// Create a new mass function. Values are normalized if they do not
    /// sum to 1.0.
    pub fn new(attack: f64, benign: f64, unknown: f64) -> Self {
        let total = attack + benign + unknown;
        if total > 0.0 {
            Self {
                attack: attack / total,
                benign: benign / total,
                unknown: unknown / total,
            }
        } else {
            // Uniform prior if all zeros.
            Self {
                attack: 1.0 / 3.0,
                benign: 1.0 / 3.0,
                unknown: 1.0 / 3.0,
            }
        }
    }

    /// Create a mass function expressing full ignorance.
    pub fn ignorance() -> Self {
        Self {
            attack: 0.0,
            benign: 0.0,
            unknown: 1.0,
        }
    }

    /// Create a mass function strongly favoring the attack hypothesis.
    pub fn attack_prior(confidence: f64) -> Self {
        Self::new(confidence, 0.0, 1.0 - confidence)
    }

    /// Create a mass function strongly favoring the benign hypothesis.
    pub fn benign_prior(confidence: f64) -> Self {
        Self::new(0.0, confidence, 1.0 - confidence)
    }

    /// Dempster's combination rule for two mass functions.
    /// Computes `m12(A) = (1/K) * Σ m1(X) * m2(Y)` for all X ∩ Y = A,
    /// where K is the degree of conflict.
    ///
    /// Frame: Θ = {a=attack, b=benign, θ=unknown}
    /// Focal sets: {a}, {b}, {a,b} (a,b are singletons, {a,b}=θ is unknown)
    ///
    /// Conflict K = m1(a)*m2(b) + m1(b)*m2(a)
    pub fn combine(&self, other: &MassFunction) -> MassFunction {
        // Compute conflict K.
        let conflict = (self.attack * other.benign) + (self.benign * other.attack);

        if conflict >= 1.0 {
            // Total conflict: fall back to weighted average.
            return self.weighted_average(other, 0.5);
        }

        let one_minus_k = 1.0 - conflict;

        // m12(a) = (m1(a)*m2(a) + m1(a)*m2(θ) + m1(θ)*m2(a)) / (1-K)
        let attack = (self.attack * other.attack
            + self.attack * other.unknown
            + self.unknown * other.attack)
            / one_minus_k;

        // m12(b) = (m1(b)*m2(b) + m1(b)*m2(θ) + m1(θ)*m2(b)) / (1-K)
        let benign = (self.benign * other.benign
            + self.benign * other.unknown
            + self.unknown * other.benign)
            / one_minus_k;

        // m12(θ) = m1(θ)*m2(θ) / (1-K)
        let unknown = (self.unknown * other.unknown) / one_minus_k;

        MassFunction {
            attack: attack.clamp(0.0, 1.0),
            benign: benign.clamp(0.0, 1.0),
            unknown: unknown.clamp(0.0, 1.0),
        }
    }

    /// Combine multiple mass functions iteratively using Dempster's rule.
    /// Falls back to weighted averaging for any pair with total conflict.
    pub fn combine_many(masses: &[MassFunction]) -> MassFunction {
        if masses.is_empty() {
            return MassFunction::ignorance();
        }
        let mut result = masses[0].clone();
        for m in masses.iter().skip(1) {
            result = result.combine(m);
        }
        result
    }

    /// Weighted average fusion for complementary (non-conflicting) evidence.
    /// `alpha` is the weight for `self`, `1-alpha` for `other`.
    pub fn weighted_average(&self, other: &MassFunction, alpha: f64) -> MassFunction {
        let beta = 1.0 - alpha;
        MassFunction {
            attack: (self.attack * alpha + other.attack * beta).clamp(0.0, 1.0),
            benign: (self.benign * alpha + other.benign * beta).clamp(0.0, 1.0),
            unknown: (self.unknown * alpha + other.unknown * beta).clamp(0.0, 1.0),
        }
    }

    /// Compute the belief (lower probability) for the "attack" hypothesis.
    /// Bel(a) = m(a) (since {a} has no proper subsets in our frame).
    pub fn belief_attack(&self) -> f64 {
        self.attack
    }

    /// Compute the plausibility (upper probability) for the "attack" hypothesis.
    /// Pl(a) = 1 - Bel(¬a) = 1 - m(b).
    pub fn plausibility_attack(&self) -> f64 {
        1.0 - self.benign
    }

    /// Compute the degree of conflict between two mass functions.
    pub fn conflict(&self, other: &MassFunction) -> f64 {
        (self.attack * other.benign) + (self.benign * other.attack)
    }

    /// Decision: return "attack" if belief exceeds threshold, "benign" if
    /// plausibility of attack is below threshold, else "uncertain".
    pub fn decision(&self, attack_threshold: f64) -> FusionDecision {
        if self.belief_attack() >= attack_threshold {
            FusionDecision::Attack
        } else if self.plausibility_attack() < attack_threshold {
            FusionDecision::Benign
        } else {
            FusionDecision::Uncertain
        }
    }

    /// Derive a mass function from an evidence node's severity and confidence.
    pub fn from_evidence(node: &EvidenceNode) -> Self {
        let severity_mass = node.severity.score() * node.confidence;
        let remaining = 1.0 - severity_mass;
        // Allocate remaining mass proportionally between benign and unknown.
        Self {
            attack: severity_mass,
            benign: remaining * 0.3,
            unknown: remaining * 0.7,
        }
    }
}

/// The outcome of evidence fusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FusionDecision {
    /// Evidence supports the attack hypothesis.
    Attack,
    /// Evidence supports the benign hypothesis.
    Benign,
    /// Insufficient evidence to decide.
    Uncertain,
}

/// An evidence fusion engine that combines mass functions from multiple
/// evidence nodes and resolves conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFusionEngine {
    /// Threshold above which the belief in "attack" triggers an attack
    /// decision. Default: 0.6.
    pub attack_threshold: f64,
    /// Mass functions accumulated so far, keyed by evidence ID.
    pub masses: HashMap<String, MassFunction>,
    /// The combined mass function after the last `fuse()` call.
    pub combined: MassFunction,
}

impl Default for EvidenceFusionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceFusionEngine {
    /// Create a new fusion engine with default parameters.
    pub fn new() -> Self {
        Self {
            attack_threshold: 0.6,
            masses: HashMap::new(),
            combined: MassFunction::ignorance(),
        }
    }

    /// Add an evidence node's mass function to the engine.
    pub fn add_evidence(&mut self, node: &EvidenceNode) {
        let mass = MassFunction::from_evidence(node);
        self.masses.insert(node.id.clone(), mass);
    }

    /// Fuse all accumulated evidence using Dempster-Shafer combination.
    /// Falls back to weighted averaging for highly conflicting pairs.
    pub fn fuse(&mut self) -> FusionResult {
        let mass_vec: Vec<MassFunction> = self.masses.values().cloned().collect();

        // First pass: check overall pairwise conflict.
        let mut total_conflict = 0.0;
        let pair_count = if mass_vec.len() >= 2 {
            mass_vec.len() * (mass_vec.len() - 1) / 2
        } else {
            0
        };

        if pair_count > 0 {
            for i in 0..mass_vec.len() {
                for j in (i + 1)..mass_vec.len() {
                    total_conflict += mass_vec[i].conflict(&mass_vec[j]);
                }
            }
            total_conflict /= pair_count as f64;
        }

        // If average conflict is high, use weighted averaging instead.
        self.combined = if total_conflict > 0.8 {
            // High conflict: use weighted averaging with equal weights.
            let mut avg_attack = 0.0;
            let mut avg_benign = 0.0;
            let mut avg_unknown = 0.0;
            let n = mass_vec.len() as f64;
            for m in &mass_vec {
                avg_attack += m.attack / n;
                avg_benign += m.benign / n;
                avg_unknown += m.unknown / n;
            }
            MassFunction {
                attack: avg_attack,
                benign: avg_benign,
                unknown: avg_unknown,
            }
        } else {
            MassFunction::combine_many(&mass_vec)
        };

        let decision = self.combined.decision(self.attack_threshold);

        FusionResult {
            combined: self.combined.clone(),
            decision,
            average_pairwise_conflict: total_conflict,
            evidence_count: mass_vec.len(),
            conflict_resolution: if total_conflict > 0.8 {
                ConflictResolution::WeightedAverage
            } else {
                ConflictResolution::DempsterShafer
            },
        }
    }

    /// Reset all accumulated evidence.
    pub fn reset(&mut self) {
        self.masses.clear();
        self.combined = MassFunction::ignorance();
    }
}

/// The result of an evidence fusion operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionResult {
    /// The combined mass function after fusion.
    pub combined: MassFunction,
    /// The final decision based on the combined evidence.
    pub decision: FusionDecision,
    /// Average pairwise conflict across all evidence pairs.
    pub average_pairwise_conflict: f64,
    /// Number of evidence items fused.
    pub evidence_count: usize,
    /// Which fusion strategy was used.
    pub conflict_resolution: ConflictResolution,
}

/// The conflict resolution strategy that was applied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// Standard Dempster-Shafer combination was used.
    DempsterShafer,
    /// Weighted averaging was used due to high conflict.
    WeightedAverage,
}

// ═══════════════════════════════════════════════════════════════════════════
// §6. Timeline Reconstruction
// ═══════════════════════════════════════════════════════════════════════════

/// A single event on the reconstructed timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// The evidence node ID this event represents.
    pub evidence_id: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Severity of the event.
    pub severity: EvidenceSeverity,
    /// Human-readable description.
    pub description: String,
    /// The ANANTA audit category.
    pub category: AuditCategory,
    /// Whether this event is part of a detected temporal gap.
    pub in_gap: bool,
    /// Whether this event is part of a detected burst.
    pub in_burst: bool,
}

/// A detected temporal gap between consecutive events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalGap {
    /// The evidence ID of the event just before the gap.
    pub before_id: String,
    /// The evidence ID of the event just after the gap.
    pub after_id: String,
    /// Duration of the gap.
    pub duration: Duration,
    /// Start time of the gap.
    pub start: DateTime<Utc>,
    /// End time of the gap.
    pub end: DateTime<Utc>,
    /// How many standard deviations this gap exceeds the mean inter-event
    /// time. Higher = more anomalous.
    pub anomaly_score: f64,
}

/// A detected burst: a cluster of events occurring unusually close together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstPattern {
    /// Ordered evidence IDs in this burst.
    pub evidence_ids: Vec<String>,
    /// Start time of the burst.
    pub start: DateTime<Utc>,
    /// End time of the burst.
    pub end: DateTime<Utc>,
    /// Total duration of the burst.
    pub duration: Duration,
    /// Number of events in the burst.
    pub event_count: usize,
    /// Events per second within this burst.
    pub rate: f64,
}

/// The reconstructed timeline of evidence events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTimeline {
    /// Chronologically ordered timeline events.
    pub events: Vec<TimelineEvent>,
    /// Detected temporal gaps (anomalous pauses in activity).
    pub gaps: Vec<TemporalGap>,
    /// Detected burst patterns (anomalous spikes in activity).
    pub bursts: Vec<BurstPattern>,
    /// Gap detection threshold in standard deviations. Default: 2.0.
    pub gap_threshold_stddev: f64,
    /// Burst detection window in seconds. Events within this window
    /// are considered part of the same potential burst. Default: 10.0.
    pub burst_window_secs: f64,
    /// Minimum number of events to constitute a burst. Default: 3.
    pub burst_min_events: usize,
}

impl Default for EvidenceTimeline {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceTimeline {
    /// Create a new empty timeline with default detection parameters.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            gaps: Vec::new(),
            bursts: Vec::new(),
            gap_threshold_stddev: 2.0,
            burst_window_secs: 10.0,
            burst_min_events: 3,
        }
    }

    /// Build a timeline from a slice of evidence nodes. Nodes are sorted
    /// chronologically, then gap and burst detection is performed.
    pub fn from_evidence(nodes: &[EvidenceNode]) -> Self {
        let mut timeline = Self::new();

        // Sort nodes chronologically.
        let mut sorted: Vec<&EvidenceNode> = nodes.iter().collect();
        sorted.sort_by_key(|n| n.observed_at);

        for node in sorted {
            timeline.events.push(TimelineEvent {
                evidence_id: node.id.clone(),
                timestamp: node.observed_at,
                severity: node.severity.clone(),
                description: node.description.clone(),
                category: node.category.clone(),
                in_gap: false,
                in_burst: false,
            });
        }

        if timeline.events.len() >= 2 {
            timeline.detect_gaps();
            timeline.detect_bursts();
        }

        timeline
    }

    /// Detect temporal gaps: inter-event intervals that exceed the mean
    /// by more than `gap_threshold_stddev` standard deviations.
    pub fn detect_gaps(&mut self) {
        self.gaps.clear();

        if self.events.len() < 2 {
            return;
        }

        // Compute inter-event durations.
        let intervals: Vec<f64> = self
            .events
            .windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_seconds().abs() as f64)
            .collect();

        // Compute median and median absolute deviation (MAD) for robust
        // outlier detection. Mean+stddev is skewed by a single large gap.
        let mut sorted_intervals = intervals.clone();
        sorted_intervals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = sorted_intervals[sorted_intervals.len() / 2];

        let mut abs_devs: Vec<f64> = intervals.iter().map(|x| (x - median).abs()).collect();
        abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mad = abs_devs[abs_devs.len() / 2];

        let threshold = if mad > 0.0 {
            median + self.gap_threshold_stddev * mad
        } else {
            median * 3.0 // Fallback: 3x median.
        };

        for (i, &interval) in intervals.iter().enumerate() {
            if interval > threshold {
                let before = &self.events[i];
                let after = &self.events[i + 1];
                let anomaly_score = if mad > 0.0 {
                    (interval - median) / mad
                } else {
                    0.0
                };

                self.gaps.push(TemporalGap {
                    before_id: before.evidence_id.clone(),
                    after_id: after.evidence_id.clone(),
                    duration: Duration::seconds(interval as i64),
                    start: before.timestamp,
                    end: after.timestamp,
                    anomaly_score,
                });

                // Mark events as being in a gap.
                self.events[i].in_gap = true;
                self.events[i + 1].in_gap = true;
            }
        }
    }

    /// Detect burst patterns: consecutive events within `burst_window_secs`
    /// that total at least `burst_min_events` events.
    pub fn detect_bursts(&mut self) {
        self.bursts.clear();

        if self.events.len() < self.burst_min_events {
            return;
        }

        let mut burst_start: Option<usize> = None;
        let mut current_burst_ids: Vec<String> = Vec::new();

        for i in 1..self.events.len() {
            let interval = (self.events[i].timestamp - self.events[i - 1].timestamp)
                .num_seconds()
                .abs() as f64;

            if interval <= self.burst_window_secs {
                if burst_start.is_none() {
                    burst_start = Some(i - 1);
                    current_burst_ids.push(self.events[i - 1].evidence_id.clone());
                }
                current_burst_ids.push(self.events[i].evidence_id.clone());
            } else {
                // End of potential burst.
                if current_burst_ids.len() >= self.burst_min_events {
                    if let Some(start_idx) = burst_start {
                        let end_idx = start_idx + current_burst_ids.len() - 1;
                        let start_time = self.events[start_idx].timestamp;
                        let end_time = self.events[end_idx].timestamp;
                        let duration_secs =
                            (end_time - start_time).num_seconds().unsigned_abs() as f64;

                        self.bursts.push(BurstPattern {
                            evidence_ids: current_burst_ids.clone(),
                            start: start_time,
                            end: end_time,
                            duration: Duration::seconds(duration_secs as i64),
                            event_count: current_burst_ids.len(),
                            rate: if duration_secs > 0.0 {
                                current_burst_ids.len() as f64 / duration_secs
                            } else {
                                current_burst_ids.len() as f64
                            },
                        });

                        // Mark events as being in a burst.
                        for j in start_idx..=end_idx {
                            if j < self.events.len() {
                                self.events[j].in_burst = true;
                            }
                        }
                    }
                }
                burst_start = None;
                current_burst_ids.clear();
            }
        }

        // Handle burst that extends to the end of the timeline.
        if current_burst_ids.len() >= self.burst_min_events {
            if let Some(start_idx) = burst_start {
                let end_idx = (start_idx + current_burst_ids.len()).saturating_sub(1);
                let start_time = self.events[start_idx].timestamp;
                let end_time = self.events[end_idx.min(self.events.len() - 1)].timestamp;
                let duration_secs = (end_time - start_time).num_seconds().unsigned_abs() as f64;

                self.bursts.push(BurstPattern {
                    evidence_ids: current_burst_ids,
                    start: start_time,
                    end: end_time,
                    duration: Duration::seconds(duration_secs as i64),
                    event_count: end_idx - start_idx + 1,
                    rate: if duration_secs > 0.0 {
                        (end_idx - start_idx + 1) as f64 / duration_secs
                    } else {
                        (end_idx - start_idx + 1) as f64
                    },
                });
            }
        }
    }

    /// Return the total wall-clock span of the timeline.
    pub fn total_span(&self) -> Duration {
        if self.events.len() < 2 {
            return Duration::zero();
        }
        let first = self.events.first().unwrap().timestamp;
        let last = self.events.last().unwrap().timestamp;
        last - first
    }

    /// Return the mean inter-event interval in seconds.
    pub fn mean_interval_secs(&self) -> f64 {
        if self.events.len() < 2 {
            return 0.0;
        }
        let total: f64 = self
            .events
            .windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_seconds().abs() as f64)
            .sum();
        total / (self.events.len() - 1) as f64
    }

    /// Get all events within a time range.
    pub fn events_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §7. Integrated Evidence Correlator
// ═══════════════════════════════════════════════════════════════════════════

/// Top-level evidence correlator that integrates the graph, chain
/// reconstruction, MITRE mapping, fusion, and timeline analysis into
/// a single cohesive analysis pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCorrelator {
    /// The correlation graph.
    pub graph: EvidenceGraph,
    /// The chain reconstructor.
    pub reconstructor: ChainReconstructor,
    /// The MITRE mapper.
    pub mapper: MitreMapper,
    /// The evidence fusion engine.
    pub fusion: EvidenceFusionEngine,
    /// The reconstructed timeline.
    pub timeline: EvidenceTimeline,
}

impl Default for EvidenceCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceCorrelator {
    /// Create a new evidence correlator with default sub-components.
    pub fn new() -> Self {
        Self {
            graph: EvidenceGraph::new(),
            reconstructor: ChainReconstructor::new(),
            mapper: MitreMapper::new(),
            fusion: EvidenceFusionEngine::new(),
            timeline: EvidenceTimeline::new(),
        }
    }

    /// Ingest a batch of evidence nodes, run the full analysis pipeline,
    /// and return a comprehensive correlation report.
    pub fn analyze(&mut self, nodes: Vec<EvidenceNode>) -> CorrelationReport {
        // Reset state.
        self.graph.nodes.clear();
        self.graph.edges.clear();
        self.fusion.reset();

        // Populate graph and fusion engine.
        for node in &nodes {
            self.graph.add_node(node.clone());
            self.fusion.add_evidence(node);
        }

        // Compute correlation edges.
        self.graph.compute_edges();

        // Run attack chain reconstruction.
        self.reconstructor.graph = self.graph.clone();
        self.reconstructor.mapper = self.mapper.clone();
        let chains = self.reconstructor.reconstruct();

        // Update graph with chain markings from reconstructor.
        self.graph = self.reconstructor.graph.clone();

        // Run evidence fusion.
        let fusion_result = self.fusion.fuse();

        // Build timeline.
        self.timeline = EvidenceTimeline::from_evidence(&nodes);

        // Compute MITRE tactic rankings.
        let tactics = self.mapper.likely_tactics(&nodes);
        let techniques = self.mapper.likely_techniques(&nodes, 10);

        CorrelationReport {
            total_evidence: nodes.len(),
            graph_node_count: self.graph.node_count(),
            graph_edge_count: self.graph.edge_count(),
            attack_chains: chains,
            top_tactics: tactics,
            top_techniques: techniques,
            fusion: fusion_result,
            timeline_gaps: self.timeline.gaps.len(),
            timeline_bursts: self.timeline.bursts.len(),
            timeline_span_secs: self.timeline.total_span().num_seconds().unsigned_abs() as u64,
        }
    }
}

/// A comprehensive correlation report produced by the evidence correlator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    /// Total number of evidence items analyzed.
    pub total_evidence: usize,
    /// Number of nodes in the correlation graph.
    pub graph_node_count: usize,
    /// Number of edges in the correlation graph.
    pub graph_edge_count: usize,
    /// Reconstructed attack chains, ranked by score.
    pub attack_chains: Vec<AttackChain>,
    /// Top MITRE tactics ranked by evidence support.
    pub top_tactics: Vec<(MitreTactic, f64)>,
    /// Top MITRE techniques ranked by evidence support.
    pub top_techniques: Vec<(MitreTechnique, f64)>,
    /// Evidence fusion result.
    pub fusion: FusionResult,
    /// Number of temporal gaps detected.
    pub timeline_gaps: usize,
    /// Number of burst patterns detected.
    pub timeline_bursts: usize,
    /// Total timeline span in seconds.
    pub timeline_span_secs: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// §8. Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a basic evidence node for testing.
    fn make_node(
        id: &str,
        category: AuditCategory,
        severity: EvidenceSeverity,
        offset_secs: i64,
    ) -> EvidenceNode {
        EvidenceNode::new(
            id,
            format!("test evidence {}", id),
            category,
            severity,
            Utc::now() + Duration::seconds(offset_secs),
        )
        .with_entity("host-01")
        .with_confidence(0.9)
    }

    // ── EvidenceSeverity ────────────────────────────────────────────────

    #[test]
    fn severity_score_increases_monotonically() {
        assert!(EvidenceSeverity::Low.score() < EvidenceSeverity::Medium.score());
        assert!(EvidenceSeverity::Medium.score() < EvidenceSeverity::High.score());
        assert!(EvidenceSeverity::High.score() < EvidenceSeverity::Critical.score());
    }

    #[test]
    fn severity_from_score_round_trips() {
        for sev in [
            EvidenceSeverity::Low,
            EvidenceSeverity::Medium,
            EvidenceSeverity::High,
            EvidenceSeverity::Critical,
        ] {
            assert_eq!(EvidenceSeverity::from_score(sev.score()), sev);
        }
    }

    // ── EvidenceNode ────────────────────────────────────────────────────

    #[test]
    fn evidence_node_builder() {
        let node = make_node("n1", AuditCategory::Drift, EvidenceSeverity::High, 0);
        assert_eq!(node.id, "n1");
        assert_eq!(node.category, AuditCategory::Drift);
        assert!(node.entities.contains("host-01"));
        assert!((node.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn evidence_node_serialization_roundtrip() {
        let node = make_node(
            "n-ser",
            AuditCategory::Trust,
            EvidenceSeverity::Critical,
            100,
        );
        let json = serde_json::to_string(&node).expect("serialize");
        let back: EvidenceNode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.id, node.id);
        assert_eq!(back.severity, node.severity);
        assert_eq!(back.category, node.category);
    }

    // ── EvidenceGraph ───────────────────────────────────────────────────

    #[test]
    fn graph_temporal_score_same_time() {
        let g = EvidenceGraph::new();
        let a = make_node("a", AuditCategory::Drift, EvidenceSeverity::High, 0);
        let b = make_node("b", AuditCategory::Trust, EvidenceSeverity::High, 0);
        assert!((g.temporal_score(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn graph_temporal_score_decays() {
        let g = EvidenceGraph::new();
        let a = make_node("a", AuditCategory::Drift, EvidenceSeverity::High, 0);
        let b = make_node("b", AuditCategory::Trust, EvidenceSeverity::High, 600);
        let score = g.temporal_score(&a, &b);
        assert!(score < 1.0);
        assert!(score > 0.0);
    }

    #[test]
    fn graph_jaccard_identical_entities() {
        let g = EvidenceGraph::new();
        let a =
            make_node("a", AuditCategory::Drift, EvidenceSeverity::High, 0).with_entity("user-1");
        let b =
            make_node("b", AuditCategory::Trust, EvidenceSeverity::High, 10).with_entity("user-1");
        assert!((g.entity_jaccard(&a, &b) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn graph_jaccard_empty_entities() {
        let g = EvidenceGraph::new();
        let a = EvidenceNode::new(
            "a",
            "desc",
            AuditCategory::Drift,
            EvidenceSeverity::High,
            Utc::now(),
        );
        let b = EvidenceNode::new(
            "b",
            "desc",
            AuditCategory::Trust,
            EvidenceSeverity::High,
            Utc::now(),
        );
        assert!((g.entity_jaccard(&a, &b)).abs() < f64::EPSILON);
    }

    #[test]
    fn graph_compute_edges_filters_by_threshold() {
        let mut g = EvidenceGraph::new();
        g.min_weight_threshold = 0.9; // Very high threshold.
        g.add_node(make_node(
            "a",
            AuditCategory::Drift,
            EvidenceSeverity::High,
            0,
        ));
        g.add_node(make_node(
            "b",
            AuditCategory::Trust,
            EvidenceSeverity::High,
            6000,
        ));
        g.compute_edges();
        // With a 6000-second gap and 0.9 threshold, should have zero edges.
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn graph_predecessors_and_successors() {
        let mut g = EvidenceGraph::new();
        g.add_node(make_node(
            "a",
            AuditCategory::Drift,
            EvidenceSeverity::High,
            0,
        ));
        g.add_node(make_node(
            "b",
            AuditCategory::Trust,
            EvidenceSeverity::High,
            5,
        ));
        g.compute_edges();
        let preds_of_b = g.predecessors("b");
        let succs_of_a = g.successors("a");
        // Both should find the a->b edge (or not if below threshold).
        assert_eq!(preds_of_b.len(), succs_of_a.len());
    }

    // ── MITRE ATT&CK ────────────────────────────────────────────────────

    #[test]
    fn mitre_tactic_ids_unique() {
        let tactics = MitreTactic::all();
        let ids: HashSet<_> = tactics.iter().map(|t| t.tactic_id()).collect();
        assert_eq!(ids.len(), tactics.len());
    }

    #[test]
    fn mitre_kill_chain_order_monotonic() {
        let tactics = MitreTactic::all();
        for w in tactics.windows(2) {
            assert!(w[0].kill_chain_order() < w[1].kill_chain_order());
        }
    }

    #[test]
    fn mitre_mapper_returns_tactics() {
        let mapper = MitreMapper::new();
        let nodes = vec![
            make_node("e1", AuditCategory::Drift, EvidenceSeverity::High, 0),
            make_node(
                "e2",
                AuditCategory::Integrity,
                EvidenceSeverity::Critical,
                10,
            ),
        ];
        let tactics = mapper.likely_tactics(&nodes);
        assert!(!tactics.is_empty());
        // Scores should be descending.
        for w in tactics.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn mitre_mapper_techniques_limited_by_top_k() {
        let mapper = MitreMapper::new();
        let nodes = vec![make_node(
            "e1",
            AuditCategory::Drift,
            EvidenceSeverity::High,
            0,
        )];
        let techniques = mapper.likely_techniques(&nodes, 2);
        assert!(techniques.len() <= 2);
    }

    #[test]
    fn mitre_map_single_node() {
        let mapper = MitreMapper::new();
        let node = make_node(
            "e1",
            AuditCategory::KeyManagement,
            EvidenceSeverity::Critical,
            0,
        );
        let mapped = mapper.map_node(&node);
        assert!(!mapped.is_empty());
        // KeyManagement should map to CredentialAccess tactics.
        let has_cred_access = mapped
            .iter()
            .any(|(t, _)| t.tactic == MitreTactic::CredentialAccess);
        assert!(has_cred_access);
    }

    // ── Dempster-Shafer Fusion ──────────────────────────────────────────

    #[test]
    fn mass_function_normalizes() {
        let m = MassFunction::new(0.5, 0.3, 0.3);
        let total = m.attack + m.benign + m.unknown;
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn mass_function_ignorance() {
        let m = MassFunction::ignorance();
        assert!((m.unknown - 1.0).abs() < f64::EPSILON);
        assert!((m.attack).abs() < f64::EPSILON);
    }

    #[test]
    fn mass_function_all_zeros_becomes_uniform() {
        let m = MassFunction::new(0.0, 0.0, 0.0);
        assert!((m.attack - 1.0 / 3.0).abs() < 1e-10);
        assert!((m.benign - 1.0 / 3.0).abs() < 1e-10);
        assert!((m.unknown - 1.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn dempster_combine_agreeing_evidence() {
        let m1 = MassFunction::attack_prior(0.7);
        let m2 = MassFunction::attack_prior(0.8);
        let combined = m1.combine(&m2);
        // Both favor attack, so combined attack belief should increase.
        assert!(combined.attack > m1.attack);
        assert!(combined.attack > m2.attack);
    }

    #[test]
    fn dempster_combine_conflicting_falls_back() {
        let m1 = MassFunction::attack_prior(1.0);
        let m2 = MassFunction::benign_prior(1.0);
        // Total conflict: should fall back to weighted average.
        let combined = m1.combine(&m2);
        // Should not panic; result should be valid mass function.
        let total = combined.attack + combined.benign + combined.unknown;
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn weighted_average_basic() {
        let m1 = MassFunction::attack_prior(0.8);
        let m2 = MassFunction::benign_prior(0.8);
        let avg = m1.weighted_average(&m2, 0.5);
        assert!((avg.attack - 0.4).abs() < 1e-10);
        assert!((avg.benign - 0.4).abs() < 1e-10);
    }

    #[test]
    fn belief_and_plausibility() {
        let m = MassFunction::new(0.6, 0.1, 0.3);
        assert!((m.belief_attack() - 0.6).abs() < f64::EPSILON);
        assert!((m.plausibility_attack() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn fusion_decision_attack() {
        let m = MassFunction::attack_prior(0.9);
        assert_eq!(m.decision(0.6), FusionDecision::Attack);
    }

    #[test]
    fn fusion_decision_benign() {
        let m = MassFunction::benign_prior(0.9);
        assert_eq!(m.decision(0.6), FusionDecision::Benign);
    }

    #[test]
    fn fusion_engine_full_pipeline() {
        let mut engine = EvidenceFusionEngine::new();
        engine.add_evidence(&make_node(
            "e1",
            AuditCategory::Drift,
            EvidenceSeverity::Critical,
            0,
        ));
        engine.add_evidence(&make_node(
            "e2",
            AuditCategory::Integrity,
            EvidenceSeverity::High,
            10,
        ));
        let result = engine.fuse();
        assert_eq!(result.evidence_count, 2);
        // High-severity evidence should push toward Attack decision.
        assert!(result.combined.attack > 0.0);
    }

    #[test]
    fn mass_function_from_evidence() {
        let node = make_node("e1", AuditCategory::Drift, EvidenceSeverity::Critical, 0)
            .with_confidence(1.0);
        let m = MassFunction::from_evidence(&node);
        // Critical severity * 1.0 confidence = 1.0 attack mass.
        assert!((m.attack - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn combine_many_empty_returns_ignorance() {
        let result = MassFunction::combine_many(&[]);
        assert!((result.unknown - 1.0).abs() < f64::EPSILON);
    }

    // ── Timeline ────────────────────────────────────────────────────────

    #[test]
    fn timeline_sorts_chronologically() {
        let nodes = vec![
            make_node("c", AuditCategory::Drift, EvidenceSeverity::High, 200),
            make_node("a", AuditCategory::Trust, EvidenceSeverity::Medium, 0),
            make_node("b", AuditCategory::Integrity, EvidenceSeverity::Low, 100),
        ];
        let timeline = EvidenceTimeline::from_evidence(&nodes);
        assert_eq!(timeline.events[0].evidence_id, "a");
        assert_eq!(timeline.events[1].evidence_id, "b");
        assert_eq!(timeline.events[2].evidence_id, "c");
    }

    #[test]
    fn timeline_gap_detection() {
        let nodes = vec![
            make_node("a", AuditCategory::Trust, EvidenceSeverity::Low, 0),
            make_node("b", AuditCategory::Trust, EvidenceSeverity::Low, 1),
            make_node("c", AuditCategory::Trust, EvidenceSeverity::Low, 2),
            make_node("d", AuditCategory::Trust, EvidenceSeverity::Low, 10000), // Big gap.
            make_node("e", AuditCategory::Trust, EvidenceSeverity::Low, 10001),
        ];
        let timeline = EvidenceTimeline::from_evidence(&nodes);
        // Should detect at least one gap around the 10000-second jump.
        assert!(timeline.gaps.len() >= 1);
    }

    #[test]
    fn timeline_burst_detection() {
        let nodes = vec![
            make_node("a", AuditCategory::Drift, EvidenceSeverity::High, 0),
            make_node("b", AuditCategory::Drift, EvidenceSeverity::High, 1),
            make_node("c", AuditCategory::Drift, EvidenceSeverity::High, 2),
            make_node("d", AuditCategory::Drift, EvidenceSeverity::High, 3),
            make_node("e", AuditCategory::Drift, EvidenceSeverity::Low, 600), // Outside burst window.
        ];
        let mut timeline = EvidenceTimeline::from_evidence(&nodes);
        timeline.burst_window_secs = 5.0;
        timeline.detect_bursts();
        // Should detect the first 4 events as a burst.
        assert_eq!(timeline.bursts.len(), 1);
        assert_eq!(timeline.bursts[0].event_count, 4);
    }

    #[test]
    fn timeline_mean_interval() {
        let nodes = vec![
            make_node("a", AuditCategory::Trust, EvidenceSeverity::Low, 0),
            make_node("b", AuditCategory::Trust, EvidenceSeverity::Low, 10),
            make_node("c", AuditCategory::Trust, EvidenceSeverity::Low, 30),
        ];
        let timeline = EvidenceTimeline::from_evidence(&nodes);
        // Intervals: 10, 20 → mean = 15.
        assert!((timeline.mean_interval_secs() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn timeline_events_in_range() {
        let nodes = vec![
            make_node("a", AuditCategory::Trust, EvidenceSeverity::Low, 0),
            make_node("b", AuditCategory::Trust, EvidenceSeverity::Low, 50),
            make_node("c", AuditCategory::Trust, EvidenceSeverity::Low, 100),
        ];
        let timeline = EvidenceTimeline::from_evidence(&nodes);
        let start = timeline.events[0].timestamp + Duration::seconds(5);
        let end = timeline.events[2].timestamp - Duration::seconds(5);
        let in_range = timeline.events_in_range(start, end);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].evidence_id, "b");
    }

    // ── Attack Chain Reconstruction ─────────────────────────────────────

    #[test]
    fn chain_reconstruction_finds_chains() {
        let mut reconstructor = ChainReconstructor::new();
        reconstructor.seed_min_severity = EvidenceSeverity::Medium;
        reconstructor.min_chain_length = 2;

        let shared_entity = "host-01";
        reconstructor.graph.add_node(
            make_node("e1", AuditCategory::Drift, EvidenceSeverity::High, 0)
                .with_entity(shared_entity),
        );
        reconstructor.graph.add_node(
            make_node(
                "e2",
                AuditCategory::Integrity,
                EvidenceSeverity::Critical,
                10,
            )
            .with_entity(shared_entity),
        );
        reconstructor.graph.add_node(
            make_node("e3", AuditCategory::Trust, EvidenceSeverity::Medium, 20)
                .with_entity(shared_entity),
        );

        let chains = reconstructor.reconstruct();
        // Should find at least one chain.
        assert!(!chains.is_empty());
        // All chains should have at least 2 nodes.
        for chain in &chains {
            assert!(chain.node_ids.len() >= 2);
        }
    }

    #[test]
    fn chain_scores_are_valid() {
        for chain in &dummy_chains() {
            assert!(chain.score >= 0.0);
            assert!(chain.score <= 1.0);
        }
    }

    #[test]
    fn chain_duration_computed() {
        let chains = dummy_chains();
        for chain in &chains {
            assert!(chain.duration.num_seconds() >= 0);
        }
    }

    // ── Integration: EvidenceCorrelator ─────────────────────────────────

    #[test]
    fn correlator_full_analysis() {
        let mut correlator = EvidenceCorrelator::new();
        let nodes = vec![
            make_node("e1", AuditCategory::Drift, EvidenceSeverity::High, 0)
                .with_entity("host-01")
                .with_entity("user-admin"),
            make_node(
                "e2",
                AuditCategory::Integrity,
                EvidenceSeverity::Critical,
                5,
            )
            .with_entity("host-01"),
            make_node(
                "e3",
                AuditCategory::KeyManagement,
                EvidenceSeverity::High,
                15,
            )
            .with_entity("host-01")
            .with_entity("user-admin"),
            make_node(
                "e4",
                AuditCategory::Configuration,
                EvidenceSeverity::Medium,
                100,
            )
            .with_entity("host-02"),
            make_node(
                "e5",
                AuditCategory::Recovery,
                EvidenceSeverity::Critical,
                110,
            )
            .with_entity("host-02"),
        ];
        let report = correlator.analyze(nodes);
        assert_eq!(report.total_evidence, 5);
        assert!(report.graph_node_count > 0);
        assert!(!report.top_tactics.is_empty());
        assert!(report.fusion.evidence_count > 0);
    }

    #[test]
    fn correlator_serialization_roundtrip() {
        let mut correlator = EvidenceCorrelator::new();
        let nodes = vec![make_node(
            "e1",
            AuditCategory::Drift,
            EvidenceSeverity::High,
            0,
        )];
        correlator.analyze(nodes);
        let json = serde_json::to_string(&correlator).expect("serialize");
        let back: EvidenceCorrelator = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.graph.node_count(), correlator.graph.node_count());
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Produce a small set of dummy chains for scoring tests.
    fn dummy_chains() -> Vec<AttackChain> {
        vec![AttackChain {
            node_ids: vec!["a".into(), "b".into(), "c".into()],
            score: 0.85,
            score_breakdown: ChainScoreBreakdown {
                total_severity: 0.9,
                evidence_density: 0.7,
                temporal_coherence: 0.95,
                avg_edge_weight: 0.8,
            },
            tactics_touched: vec![
                MitreTactic::InitialAccess,
                MitreTactic::Execution,
                MitreTactic::Impact,
            ],
            duration: Duration::seconds(120),
        }]
    }
}
