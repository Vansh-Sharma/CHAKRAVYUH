// Reasoning Ring — Ring 7 (Phase 5)
//
// Chain-of-thought integrity validation for AI reasoning processes.
// Ensures that agent reasoning is coherent, unbiased, grounded, and consistent.
//
// 6 engines:
//   1. CoherenceChecker    — validates logical coherence and detects contradictions
//   2. HallucinationDetector — detects fabricated claims and implausible references
//   3. DepthAnalyzer      — checks reasoning depth vs task complexity
//   4. BiasDetector        — detects cognitive biases in reasoning patterns
//   5. StepValidator       — validates each step in a reasoning chain
//   6. OutputConsistencyChecker — checks final output alignment with stated reasoning
//
// Pipeline: Coherence → Hallucination → Depth → Bias → Step → OutputConsistency
// Budget: <5ms p99

use std::collections::HashMap;
use std::sync::Arc;

use crate::decision::{Decision, Verdict};
use crate::error::Result;

// ── Configuration ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReasoningConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub coherence_checker: CoherenceCheckerConfig,

    #[serde(default)]
    pub hallucination_detector: HallucinationDetectorConfig,

    #[serde(default)]
    pub depth_analyzer: DepthAnalyzerConfig,

    #[serde(default)]
    pub bias_detector: BiasDetectorConfig,

    #[serde(default)]
    pub step_validator: StepValidatorConfig,

    #[serde(default)]
    pub output_consistency: OutputConsistencyConfig,

    /// Risk score threshold for deny (default: 9.0)
    #[serde(default = "default_deny_threshold")]
    pub deny_threshold: f64,
}

fn default_enabled() -> bool { true }
fn default_deny_threshold() -> f64 { 9.0 }

impl Default for ReasoningConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            coherence_checker: CoherenceCheckerConfig::default(),
            hallucination_detector: HallucinationDetectorConfig::default(),
            depth_analyzer: DepthAnalyzerConfig::default(),
            bias_detector: BiasDetectorConfig::default(),
            step_validator: StepValidatorConfig::default(),
            output_consistency: OutputConsistencyConfig::default(),
            deny_threshold: default_deny_threshold(),
        }
    }
}

// ── Engine Configs ──

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CoherenceCheckerConfig {
    #[serde(default = "default_min_coherence")]
    pub min_coherence_score: f64,
}
fn default_min_coherence() -> f64 { 0.3 }
impl Default for CoherenceCheckerConfig {
    fn default() -> Self { Self { min_coherence_score: default_min_coherence() } }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HallucinationDetectorConfig {
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f64,
}
fn default_sensitivity() -> f64 { 0.7 }
impl Default for HallucinationDetectorConfig {
    fn default() -> Self { Self { sensitivity: default_sensitivity() } }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DepthAnalyzerConfig {
    #[serde(default = "default_min_depth")]
    pub min_depth_ratio: f64,
}
fn default_min_depth() -> f64 { 0.2 }
impl Default for DepthAnalyzerConfig {
    fn default() -> Self { Self { min_depth_ratio: default_min_depth() } }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BiasDetectorConfig {
    #[serde(default = "default_bias_threshold")]
    pub bias_threshold: f64,
}
fn default_bias_threshold() -> f64 { 0.6 }
impl Default for BiasDetectorConfig {
    fn default() -> Self { Self { bias_threshold: default_bias_threshold() } }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StepValidatorConfig {
    #[serde(default = "default_max_invalid_steps")]
    pub max_invalid_steps: usize,
}
fn default_max_invalid_steps() -> usize { 2 }
impl Default for StepValidatorConfig {
    fn default() -> Self { Self { max_invalid_steps: default_max_invalid_steps() } }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OutputConsistencyConfig {
    #[serde(default = "default_min_consistency")]
    pub min_consistency: f64,
}
fn default_min_consistency() -> f64 { 0.4 }
impl Default for OutputConsistencyConfig {
    fn default() -> Self { Self { min_consistency: default_min_consistency() } }
}

// ── Request ──

/// Input to the Reasoning Ring evaluation.
#[derive(Debug, Clone)]
pub struct ReasoningRequest {
    /// The reasoning text / chain-of-thought to evaluate.
    pub reasoning_text: String,
    /// The final output/conclusion produced by the model.
    pub output_text: Option<String>,
    /// The original prompt/task description.
    pub task_description: Option<String>,
    /// Individual reasoning steps (if available from structured output).
    pub reasoning_steps: Vec<String>,
    /// Source IP for attribution.
    pub source_ip: String,
    /// User ID if available.
    pub user_id: Option<String>,
    /// Request ID for traceability.
    pub request_id: String,
    /// HTTP headers.
    pub headers: HashMap<String, String>,
}

// ── Engine Result ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReasoningEngineResult {
    pub engine_name: String,
    pub decision: String, // "allowed" | "flagged" | "denied"
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

// ── Engine Outputs ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoherenceResult {
    pub coherence_score: f64,      // 0.0-1.0
    pub contradictions_detected: usize,
    pub non_sequiturs: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HallucinationResult {
    pub hallucination_score: f64,  // 0.0-1.0
    pub implausible_claims: Vec<String>,
    pub fabricated_references: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DepthResult {
    pub depth_score: f64,          // 0.0-1.0
    pub reasoning_length: usize,
    pub complexity_estimate: f64,
    pub depth_assessment: String,  // "shallow" | "adequate" | "deep"
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BiasResult {
    pub bias_score: f64,           // 0.0-1.0
    pub detected_biases: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StepValidationResult {
    pub invalid_steps: usize,
    pub total_steps: usize,
    pub step_scores: Vec<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OutputConsistencyResult {
    pub consistency_score: f64,   // 0.0-1.0
    pub mismatches: Vec<String>,
}

// ── Verdict ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReasoningVerdict {
    pub decision: Decision,
    pub coherence_result: Option<CoherenceResult>,
    pub hallucination_result: Option<HallucinationResult>,
    pub depth_result: Option<DepthResult>,
    pub bias_result: Option<BiasResult>,
    pub step_result: Option<StepValidationResult>,
    pub consistency_result: Option<OutputConsistencyResult>,
    pub engine_results: Vec<ReasoningEngineResult>,
    pub latency_ms: f64,
    pub reasoning_risk_score: f64,
}

impl Verdict for ReasoningVerdict {
    fn decision(&self) -> &Decision { &self.decision }
    fn latency_ms(&self) -> f64 { self.latency_ms }
}

// ── Engines ──

struct CoherenceChecker {
    config: CoherenceCheckerConfig,
}

impl CoherenceChecker {
    fn new(config: &CoherenceCheckerConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, text: &str) -> (CoherenceResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();
        let text_lower = text.to_lowercase();

        // Detect contradictions: opposing statements in close proximity
        let contradiction_patterns = [
            ("however", "but also"),
            ("although", "despite being"),
            ("on the other hand", "therefore"),
            ("conversely", "clearly"),
            ("while it is true", "it is false"),
            ("not", "not not"), // double negative as proxy
        ];

        let mut contradictions = 0usize;
        let mut non_sequiturs = 0usize;

        for (a, b) in &contradiction_patterns {
            // Count how many times both patterns appear within a window
            let a_count = text_lower.matches(a).count();
            let b_count = text_lower.matches(b).count();
            if a_count > 0 && b_count > 0 {
                contradictions += 1;
            }
        }

        // Detect non-sequiturs: abrupt topic shifts (sentences that don't connect)
        let sentences: Vec<&str> = text.split(&['.', '!', '?'][..])
            .filter(|s| s.trim().len() > 5)
            .collect();
        for window in sentences.windows(2) {
            let words_a: std::collections::HashSet<String> = window[0].split_whitespace().map(|w| w.to_lowercase()).collect();
            let words_b: std::collections::HashSet<String> = window[1].split_whitespace().map(|w| w.to_lowercase()).collect();
            let overlap = words_a.intersection(&words_b).count();
            let jaccard = if words_a.is_empty() || words_b.is_empty() {
                1.0
            } else {
                overlap as f64 / (words_a.len() + words_b.len() - overlap) as f64
            };
            if jaccard < 0.01 && words_a.len() > 3 && words_b.len() > 3 {
                non_sequiturs += 1;
            }
        }

        let total_issues = contradictions + non_sequiturs;
        let coherence_score = if sentences.is_empty() {
            1.0
        } else {
            (1.0 - (total_issues as f64 / (sentences.len() as f64 * 0.3).max(1.0))).clamp(0.0, 1.0)
        };

        let result = CoherenceResult {
            coherence_score,
            contradictions_detected: contradictions,
            non_sequiturs,
        };

        let decision = if coherence_score < self.config.min_coherence_score {
            "denied"
        } else if coherence_score < self.config.min_coherence_score * 2.0 {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "coherence_checker".into(),
            decision: decision.into(),
            reason: format!("coherence_score={:.3}, contradictions={}, non_sequiturs={}", coherence_score, contradictions, non_sequiturs),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "coherence_score": coherence_score }),
        };

        (result, engine_result)
    }
}

struct HallucinationDetector {
    config: HallucinationDetectorConfig,
}

impl HallucinationDetector {
    fn new(config: &HallucinationDetectorConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, text: &str) -> (HallucinationResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();
        let text_lower = text.to_lowercase();

        // Patterns that suggest hallucination or fabrication
        let hallucination_patterns = [
            "according to my knowledge",
            "i'm not entirely sure, but",
            "i believe that",
            "it's possible that",
            "as far as i can tell",
            "i might be wrong, but",
            "i recall that",
            "studies have shown that",  // vague citation without reference
            "research indicates that", // vague citation
            "experts agree that",      // appeal to unnamed authority
        ];

        let mut implausible_claims = Vec::new();
        let mut fabricated_references = Vec::new();

        for pattern in &hallucination_patterns {
            if text_lower.contains(pattern) {
                implausible_claims.push(pattern.to_string());
            }
        }

        // Detect fabricated references: patterns like "Smith (2023)" without context
        let ref_pattern = regex::Regex::new(r"[A-Z][a-z]+ \(\d{4}\)").ok();
        if let Some(re) = &ref_pattern {
            for cap in re.find_iter(text) {
                // If there's no explicit citation list, these might be fabricated
                if !text_lower.contains("references") && !text_lower.contains("citations") {
                    fabricated_references.push(cap.as_str().to_string());
                }
            }
        }

        let total_signals = implausible_claims.len() + fabricated_references.len();
        let hallucination_score = (total_signals as f64 * self.config.sensitivity / 10.0).clamp(0.0, 1.0);

        let result = HallucinationResult {
            hallucination_score,
            implausible_claims: implausible_claims.clone(),
            fabricated_references: fabricated_references.clone(),
        };

        let decision = if hallucination_score > 0.8 {
            "denied"
        } else if hallucination_score > 0.4 {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "hallucination_detector".into(),
            decision: decision.into(),
            reason: format!("hallucination_score={:.3}, claims={}, refs={}", hallucination_score, implausible_claims.len(), fabricated_references.len()),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "hallucination_score": hallucination_score }),
        };

        (result, engine_result)
    }
}

struct DepthAnalyzer {
    config: DepthAnalyzerConfig,
}

impl DepthAnalyzer {
    fn new(config: &DepthAnalyzerConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, text: &str, task: Option<&str>) -> (DepthResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();

        let word_count = text.split_whitespace().count();
        let sentence_count = text.split(&['.', '!', '?'][..]).filter(|s| !s.trim().is_empty()).count();

        // Estimate complexity based on task description
        let complexity_estimate = match task {
            Some(t) if t.contains("explain") || t.contains("analyze") || t.contains("compare") => 0.7,
            Some(t) if t.contains("why") || t.contains("how") || t.contains("what if") => 0.6,
            Some(t) if t.contains("list") || t.contains("name") => 0.3,
            Some(t) if t.contains("yes") || t.contains("no") => 0.1,
            Some(_) => 0.5,
            None => 0.5,
        };

        // Expected minimum words based on complexity
        let expected_words = (complexity_estimate * 200.0) as usize;
        let depth_ratio = if expected_words == 0 {
            1.0
        } else {
            (word_count as f64 / expected_words as f64).clamp(0.0, 2.0)
        };

        let depth_score = depth_ratio.clamp(0.0, 1.0);
        let depth_assessment = if depth_score >= 0.7 { "deep" } else if depth_score >= self.config.min_depth_ratio { "adequate" } else { "shallow" };

        let result = DepthResult {
            depth_score,
            reasoning_length: word_count,
            complexity_estimate,
            depth_assessment: depth_assessment.into(),
        };

        let decision = if depth_score < self.config.min_depth_ratio {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "depth_analyzer".into(),
            decision: decision.into(),
            reason: format!("depth_score={:.3}, words={}, sentences={}, complexity={:.2}, assessment={}", depth_score, word_count, sentence_count, complexity_estimate, depth_assessment),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "depth_score": depth_score }),
        };

        (result, engine_result)
    }
}

struct BiasDetector {
    config: BiasDetectorConfig,
}

impl BiasDetector {
    fn new(config: &BiasDetectorConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, text: &str) -> (BiasResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();
        let text_lower = text.to_lowercase();

        // Known cognitive bias patterns
        let bias_patterns: &[(&str, &str)] = &[
            ("confirmation_bias", "this confirms my belief that"),
            ("anchoring_bias", "as we all know"),
            ("authority_bias", "experts say"),
            ("bandwagon_bias", "everyone agrees"),
            ("false_dilemma", "either"),
            ("hasty_generalization", "always"),
            ("straw_man", "you're saying that"),
            ("emotional_appeal", "think about the children"),
            ("circular_reasoning", "because it is"),
            ("appeal_to_nature", "naturally"),
        ];

        let mut detected_biases = Vec::new();
        for (bias_name, pattern) in bias_patterns {
            if text_lower.contains(pattern) {
                detected_biases.push(bias_name.to_string());
            }
        }

        let bias_score = (detected_biases.len() as f64 / bias_patterns.len() as f64).clamp(0.0, 1.0);

        let result = BiasResult {
            bias_score,
            detected_biases: detected_biases.clone(),
        };

        let decision = if bias_score > self.config.bias_threshold {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "bias_detector".into(),
            decision: decision.into(),
            reason: format!("bias_score={:.3}, biases={:?}", bias_score, detected_biases),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "bias_score": bias_score }),
        };

        (result, engine_result)
    }
}

struct StepValidator {
    config: StepValidatorConfig,
}

impl StepValidator {
    fn new(config: &StepValidatorConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, steps: &[String]) -> (StepValidationResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();
        let _total_steps = steps.len().max(1);

        // Validate each step: check for empty steps, very short steps, or contradictory steps
        let mut step_scores = Vec::new();
        let mut invalid_steps = 0usize;

        for (i, step) in steps.iter().enumerate() {
            let trimmed = step.trim();
            let score = if trimmed.is_empty() {
                0.0
            } else if trimmed.len() < 10 {
                0.3
            } else {
                // Check for step connectives (therefore, because, so, thus)
                let has_connective = trimmed.contains("therefore")
                    || trimmed.contains("because")
                    || trimmed.contains("thus")
                    || trimmed.contains("so")
                    || trimmed.contains("hence")
                    || trimmed.contains("consequently")
                    || trimmed.contains("as a result");

                if has_connective || i == 0 {
                    0.9 // First step or well-connected step
                } else {
                    0.6 // Step without clear connective
                }
            };

            step_scores.push(score);
            if score < 0.3 {
                invalid_steps += 1;
            }
        }

        let result = StepValidationResult {
            invalid_steps,
            total_steps: steps.len(),
            step_scores,
        };

        let decision = if invalid_steps > self.config.max_invalid_steps {
            "denied"
        } else if invalid_steps > 0 {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "step_validator".into(),
            decision: decision.into(),
            reason: format!("invalid_steps={}/{}, total_steps={}", invalid_steps, self.config.max_invalid_steps, steps.len()),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "invalid_steps": invalid_steps, "total_steps": steps.len() }),
        };

        (result, engine_result)
    }
}

struct OutputConsistencyChecker {
    config: OutputConsistencyConfig,
}

impl OutputConsistencyChecker {
    fn new(config: &OutputConsistencyConfig) -> Self { Self { config: config.clone() } }

    fn evaluate(&self, reasoning: &str, output: Option<&str>) -> (OutputConsistencyResult, ReasoningEngineResult) {
        let start = std::time::Instant::now();

        let result = match output {
            Some(out) if !out.is_empty() => {
                let reasoning_words: std::collections::HashSet<&str> = reasoning.split_whitespace().collect();
                let output_words: std::collections::HashSet<&str> = out.split_whitespace().collect();

                // Jaccard similarity between reasoning and output vocabulary
                let overlap = reasoning_words.intersection(&output_words).count();
                let union = reasoning_words.union(&output_words).count();
                let consistency_score = if union == 0 { 1.0 } else { overlap as f64 / union as f64 };

                // Also check for explicit contradictions
                let reasoning_lower = reasoning.to_lowercase();
                let output_lower = out.to_lowercase();
                let mut mismatches = Vec::new();

                // Check for negated conclusions
                for conclusion_word in &["yes", "true", "correct", "valid", "confirmed"] {
                    if reasoning_lower.contains(conclusion_word) && output_lower.contains(&format!("not {}", conclusion_word)) {
                        mismatches.push(format!("conclusion contradiction: {}", conclusion_word));
                    }
                }

                OutputConsistencyResult {
                    consistency_score: consistency_score.clamp(0.0, 1.0),
                    mismatches,
                }
            }
            _ => OutputConsistencyResult {
                consistency_score: 1.0, // No output to compare, assume consistent
                mismatches: vec![],
            },
        };

        let has_mismatches = !result.mismatches.is_empty();
        let decision = if has_mismatches || result.consistency_score < self.config.min_consistency {
            "flagged"
        } else {
            "allowed"
        };

        let engine_result = ReasoningEngineResult {
            engine_name: "output_consistency".into(),
            decision: decision.into(),
            reason: format!("consistency={:.3}, mismatches={}", result.consistency_score, result.mismatches.len()),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({ "consistency_score": result.consistency_score }),
        };

        (result, engine_result)
    }
}

// ── Ring Coordinator ──

pub struct ReasoningRing {
    config: Arc<ReasoningConfig>,
    coherence_checker: Arc<CoherenceChecker>,
    hallucination_detector: Arc<HallucinationDetector>,
    depth_analyzer: Arc<DepthAnalyzer>,
    bias_detector: Arc<BiasDetector>,
    step_validator: Arc<StepValidator>,
    output_consistency: Arc<OutputConsistencyChecker>,
}

impl Clone for ReasoningRing {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            coherence_checker: Arc::clone(&self.coherence_checker),
            hallucination_detector: Arc::clone(&self.hallucination_detector),
            depth_analyzer: Arc::clone(&self.depth_analyzer),
            bias_detector: Arc::clone(&self.bias_detector),
            step_validator: Arc::clone(&self.step_validator),
            output_consistency: Arc::clone(&self.output_consistency),
        }
    }
}

impl ReasoningRing {
    pub fn new(config: &ReasoningConfig) -> Result<Self> {
        Ok(Self {
            config: Arc::new(config.clone()),
            coherence_checker: Arc::new(CoherenceChecker::new(&config.coherence_checker)),
            hallucination_detector: Arc::new(HallucinationDetector::new(&config.hallucination_detector)),
            depth_analyzer: Arc::new(DepthAnalyzer::new(&config.depth_analyzer)),
            bias_detector: Arc::new(BiasDetector::new(&config.bias_detector)),
            step_validator: Arc::new(StepValidator::new(&config.step_validator)),
            output_consistency: Arc::new(OutputConsistencyChecker::new(&config.output_consistency)),
        })
    }

    /// Evaluate reasoning integrity through all 6 engines.
    ///
    /// Pipeline: Coherence → Hallucination → Depth → Bias → Step → OutputConsistency
    /// Risk accumulation: each flagged/denied engine adds to reasoning_risk_score.
    pub fn evaluate(&self, request: &ReasoningRequest) -> ReasoningVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ReasoningVerdict {
                decision: Decision::Allow,
                coherence_result: None,
                hallucination_result: None,
                depth_result: None,
                bias_result: None,
                step_result: None,
                consistency_result: None,
                engine_results: vec![],
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                reasoning_risk_score: 0.0,
            };
        }

        let mut engine_results = Vec::with_capacity(6);
        let mut risk_accumulator = 0.0f64;

        // 1. Coherence Checker
        let (coherence_result, coherence_eng) = self.coherence_checker.evaluate(&request.reasoning_text);
        match coherence_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(coherence_eng);

        // 2. Hallucination Detector
        let (hallucination_result, hallucination_eng) = self.hallucination_detector.evaluate(&request.reasoning_text);
        match hallucination_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(hallucination_eng);

        // 3. Depth Analyzer
        let (depth_result, depth_eng) = self.depth_analyzer.evaluate(&request.reasoning_text, request.task_description.as_deref());
        match depth_eng.decision.as_str() {
            "denied" => risk_accumulator += 2.0,
            "flagged" => risk_accumulator += 0.5,
            _ => {}
        }
        engine_results.push(depth_eng);

        // 4. Bias Detector
        let (bias_result, bias_eng) = self.bias_detector.evaluate(&request.reasoning_text);
        match bias_eng.decision.as_str() {
            "denied" => risk_accumulator += 2.5,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(bias_eng);

        // 5. Step Validator
        let (step_result, step_eng) = self.step_validator.evaluate(&request.reasoning_steps);
        match step_eng.decision.as_str() {
            "denied" => risk_accumulator += 3.0,
            "flagged" => risk_accumulator += 1.0,
            _ => {}
        }
        engine_results.push(step_eng);

        // 6. Output Consistency Checker
        let (consistency_result, consistency_eng) = self.output_consistency.evaluate(
            &request.reasoning_text,
            request.output_text.as_deref(),
        );
        match consistency_eng.decision.as_str() {
            "denied" => risk_accumulator += 2.0,
            "flagged" => risk_accumulator += 0.5,
            _ => {}
        }
        engine_results.push(consistency_eng);

        let reasoning_risk_score = risk_accumulator.clamp(0.0, 10.0);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Decision logic
        let any_denied = engine_results.iter().any(|e| e.decision == "denied");
        let decision = if reasoning_risk_score >= self.config.deny_threshold {
            Decision::Deny {
                code: "REASONING_INTEGRITY_SEVERE".into(),
                retry_after: Some(60),
            }
        } else if any_denied {
            Decision::Challenge {
                challenge_type: crate::decision::ChallengeType::TwoFactor,
            }
        } else if reasoning_risk_score > 5.0 {
            Decision::Escalate {
                approver_role: "admin".into(),
                timeout_secs: 300,
            }
        } else {
            Decision::Allow
        };

        ReasoningVerdict {
            decision,
            coherence_result: Some(coherence_result),
            hallucination_result: Some(hallucination_result),
            depth_result: Some(depth_result),
            bias_result: Some(bias_result),
            step_result: Some(step_result),
            consistency_result: Some(consistency_result),
            engine_results,
            latency_ms,
            reasoning_risk_score,
        }
    }

    /// Get the configuration reference.
    pub fn config(&self) -> &ReasoningConfig { &self.config }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_request() -> ReasoningRequest {
        ReasoningRequest {
            reasoning_text: "First, we analyze the problem statement to understand the requirements. The available data indicates that X leads to Y through a causal relationship. Based on this causal relationship, we can therefore conclude Z. This conclusion is supported by the initial problem analysis.".into(),
            output_text: Some("The conclusion is Z, based on the causal relationship between X and Y.".into()),
            task_description: Some("analyze the data".into()),
            reasoning_steps: vec![
                "Analyze the problem statement to understand requirements".into(),
                "Review the data indicating X leads to Y through a causal relationship".into(),
                "Conclude Z based on the causal relationship between X and Y".into(),
            ],
            source_ip: "1.2.3.4".into(),
            user_id: None,
            request_id: "test-1".into(),
            headers: HashMap::new(),
        }
    }

    fn default_config() -> ReasoningConfig { ReasoningConfig::default() }

    #[test]
    fn reasoning_ring_constructs() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        assert!(ring.config.enabled);
    }

    #[test]
    fn reasoning_ring_allows_benign() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.reasoning_risk_score < 5.0);
    }

    #[test]
    fn reasoning_ring_detects_contradictions() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.reasoning_text = "However this is true. But also it is false. Although it is correct. Despite being wrong. On the other hand, clearly it is. While it is true, it is false.".into();
        let verdict = ring.evaluate(&req);
        assert!(verdict.coherence_result.is_some());
        assert!(verdict.coherence_result.as_ref().unwrap().contradictions_detected > 0);
    }

    #[test]
    fn reasoning_ring_detects_hallucination_patterns() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.reasoning_text = "According to my knowledge, I believe that studies have shown that experts agree that research indicates that as far as I can tell.".into();
        let verdict = ring.evaluate(&req);
        assert!(verdict.hallucination_result.is_some());
        assert!(verdict.hallucination_result.as_ref().unwrap().implausible_claims.len() > 0);
    }

    #[test]
    fn reasoning_ring_detects_shallow_reasoning() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.reasoning_text = "Yes.".into();
        req.task_description = Some("explain why the economy crashed in 2008".into());
        let verdict = ring.evaluate(&req);
        assert!(verdict.depth_result.is_some());
        assert_eq!(verdict.depth_result.as_ref().unwrap().depth_assessment, "shallow");
    }

    #[test]
    fn reasoning_ring_detects_bias() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.reasoning_text = "As we all know, everyone agrees that experts say this is always the case. Either you accept it or you're wrong.".into();
        let verdict = ring.evaluate(&req);
        assert!(verdict.bias_result.is_some());
        assert!(verdict.bias_result.as_ref().unwrap().detected_biases.len() > 0);
    }

    #[test]
    fn reasoning_ring_validates_steps() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let mut req = default_request();
        req.reasoning_steps = vec!["".into(), "ok".into(), "".into(), "".into()];
        let verdict = ring.evaluate(&req);
        assert!(verdict.step_result.is_some());
        assert!(verdict.step_result.as_ref().unwrap().invalid_steps > 0);
    }

    #[test]
    fn reasoning_ring_disabled_allows() {
        let mut config = default_config();
        config.enabled = false;
        let ring = ReasoningRing::new(&config).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert!(verdict.decision.is_allow());
        assert!(verdict.engine_results.is_empty());
    }

    #[test]
    fn reasoning_verdict_implements_verdict_trait() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let verdict = ring.evaluate(&default_request());
        assert_eq!(verdict.decision(), &verdict.decision);
        assert!(verdict.latency_ms() >= 0.0);
    }

    #[test]
    fn reasoning_ring_clones() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let _clone = ring.clone();
    }

    #[test]
    fn reasoning_ring_empty_input() {
        let ring = ReasoningRing::new(&default_config()).unwrap();
        let req = ReasoningRequest {
            reasoning_text: String::new(),
            output_text: None,
            task_description: None,
            reasoning_steps: vec![],
            source_ip: "0.0.0.0".into(),
            user_id: None,
            request_id: "empty".into(),
            headers: HashMap::new(),
        };
        let verdict = ring.evaluate(&req);
        // Empty input should be handled gracefully (not panic)
        assert!(verdict.latency_ms() >= 0.0);
    }
}
