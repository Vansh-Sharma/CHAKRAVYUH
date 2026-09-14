// Confidence Scorer — Threat Ring Engine #4
//
// Aggregates per-engine results into a single composite threat score
// and a confidence value. The composite score is what the Threat Ring
// maps to a Decision via `deny_threshold` / `challenge_threshold`.
//
// Scoring algorithm (weighted average with quorum):
//
//   1. Each engine reports (score, confidence).
//   2. Weights: pattern_matcher=0.40, semantic_classifier=0.30,
//      jailbreak_detector=0.30. (Pattern matcher gets highest weight
//      because it has the lowest false-positive rate.)
//   3. Composite score = sum(score_i * weight_i * confidence_i) /
//                        sum(weight_i * confidence_i)
//   4. Composite confidence = min(confidence_i) — we are only as
//      confident as the least-confident engine that fired.
//   5. Quorum rule: if only ONE engine fired (the others scored 0),
//      we apply a 0.85 multiplier to the composite score to reflect
//      reduced certainty. Single-engine fires are more likely to be
//      false positives.
//
// Latency Budget: <0.1ms (pure arithmetic)

use crate::threat::ThreatEngineResult;

pub struct ConfidenceScorer;

impl ConfidenceScorer {
    pub fn new() -> Self {
        Self
    }

    pub fn score(&self, engine_results: &[ThreatEngineResult]) -> ScoredResult {
        if engine_results.is_empty() {
            return ScoredResult::default();
        }

        // Engine weights — lookup by engine_name.
        let weight_of = |name: &str| -> f64 {
            match name {
                "pattern_matcher" => 0.40,
                "semantic_classifier" => 0.30,
                "jailbreak_detector" => 0.30,
                _ => 0.10,
            }
        };

        let mut numerator = 0.0_f64;
        let mut denominator = 0.0_f64;
        let mut engines_fired = 0;
        let mut max_confidence = 0.0_f64;
        let mut matched_signatures: Vec<String> = Vec::new();

        for r in engine_results {
            if r.score > 0.0 {
                engines_fired += 1;
                if r.confidence > max_confidence {
                    max_confidence = r.confidence;
                }
                // Collect signals (signature IDs).
                for s in &r.signals {
                    matched_signatures.push(s.clone());
                }

                // Only fired engines contribute to numerator/denominator.
                let w = weight_of(&r.engine_name);
                numerator += r.score * w * r.confidence;
                denominator += w * r.confidence;
            }
        }

        if denominator == 0.0 || engines_fired == 0 {
            // No engines fired → confident it's safe.
            return ScoredResult {
                composite_score: 0.0,
                confidence: 1.0,
                matched_signatures: vec![],
            };
        }

        let mut composite = numerator / denominator;

        // Quorum rule: single-engine fires get a 0.85 confidence haircut.
        if engines_fired == 1 {
            composite *= 0.85;
        }

        // Confidence in the composite:
        // - Single engine: its own confidence, haircut by 0.85.
        // - Multiple engines: max confidence among fired, boosted by 0.05.
        let confidence = if engines_fired == 1 {
            max_confidence * 0.85
        } else {
            (max_confidence + 0.05).min(1.0)
        };

        ScoredResult {
            composite_score: composite,
            confidence,
            matched_signatures,
        }
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScoredResult {
    pub composite_score: f64,
    pub confidence: f64,
    pub matched_signatures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(name: &str, score: f64, confidence: f64, signals: Vec<&str>) -> ThreatEngineResult {
        ThreatEngineResult {
            engine_name: name.into(),
            score,
            confidence,
            signals: signals.into_iter().map(String::from).collect(),
            reason: format!("test {}", name),
            latency_ms: 0.1,
        }
    }

    #[test]
    fn empty_engines_returns_zero() {
        let s = ConfidenceScorer::new().score(&[]);
        assert_eq!(s.composite_score, 0.0);
        assert_eq!(s.confidence, 0.0);
    }

    #[test]
    fn all_zero_scores_returns_confident_safe() {
        let s = ConfidenceScorer::new().score(&[
            engine("pattern_matcher", 0.0, 0.9, vec![]),
            engine("semantic_classifier", 0.0, 0.7, vec![]),
            engine("jailbreak_detector", 0.0, 0.85, vec![]),
        ]);
        assert_eq!(s.composite_score, 0.0);
        assert_eq!(s.confidence, 1.0); // confident it's safe
    }

    #[test]
    fn single_engine_fire_gets_haircut() {
        let s = ConfidenceScorer::new().score(&[
            engine("pattern_matcher", 0.9, 0.9, vec!["PI-001"]),
            engine("semantic_classifier", 0.0, 0.7, vec![]),
            engine("jailbreak_detector", 0.0, 0.85, vec![]),
        ]);
        // Only pattern_matcher fired:
        // numerator = 0.9 * 0.40 * 0.9 = 0.324
        // denominator = 0.40 * 0.9 = 0.36
        // Raw composite = 0.324 / 0.36 = 0.9
        // Haircut (single engine): 0.9 * 0.85 = 0.765
        assert!(
            (s.composite_score - 0.765).abs() < 0.001,
            "expected 0.765, got {}",
            s.composite_score
        );
        // Confidence: 0.9 * 0.85 = 0.765
        assert!(
            (s.confidence - 0.765).abs() < 0.001,
            "expected 0.765, got {}",
            s.confidence
        );
    }

    #[test]
    fn multi_engine_fire_no_haircut() {
        let s = ConfidenceScorer::new().score(&[
            engine("pattern_matcher", 0.95, 0.9, vec!["JB-DAN-001"]),
            engine("semantic_classifier", 0.8, 0.7, vec!["persona_shift"]),
            engine("jailbreak_detector", 0.99, 0.95, vec!["JB:DAN"]),
        ]);
        // All three fired:
        // numerator = 0.95*0.40*0.9 + 0.8*0.30*0.7 + 0.99*0.30*0.95
        //           = 0.342 + 0.168 + 0.28215 = 0.79215
        // denominator = 0.40*0.9 + 0.30*0.7 + 0.30*0.95 = 0.36 + 0.21 + 0.285 = 0.855
        // composite = 0.79215 / 0.855 = 0.9268...
        assert!(
            s.composite_score > 0.85,
            "expected high composite, got {}",
            s.composite_score
        );
        // Confidence: max(0.9, 0.7, 0.95) + 0.05 = 1.0
        assert!(
            s.confidence > 0.95,
            "expected boosted confidence, got {}",
            s.confidence
        );
        assert_eq!(s.matched_signatures.len(), 3);
    }

    #[test]
    fn high_score_engine_dominates() {
        let s = ConfidenceScorer::new().score(&[
            engine("pattern_matcher", 0.0, 0.9, vec![]),
            engine("semantic_classifier", 0.3, 0.7, vec!["authority_claim"]),
            engine("jailbreak_detector", 0.0, 0.85, vec![]),
        ]);
        // Only semantic fired with score 0.3:
        // numerator = 0.3 * 0.30 * 0.7 = 0.063
        // denominator = 0.30 * 0.7 = 0.21
        // Raw composite = 0.063 / 0.21 = 0.3
        // Haircut: 0.3 * 0.85 = 0.255
        assert!(
            (s.composite_score - 0.255).abs() < 0.001,
            "expected 0.255, got {}",
            s.composite_score
        );
    }
}
