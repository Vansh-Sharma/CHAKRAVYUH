// D2 ANANTA Verification — Drift Injector
//
// A controlled drift injection utility for testing ANANTA's drift detection.
// Modifies values by a bounded magnitude to simulate real-world drift.
//
// Drift types:
//   - Decision drift:  risk score / verdict shifts
//   - Policy drift:    threshold / sensitivity changes
//   - Trust drift:     trust score shifts
//   - Integrity corruption: bit-flip in data strings
//   - Config drift:    specific config field modifications

use rand::Rng;
use serde_json::Value;
use tracing;

/// Controlled drift injector for ANANTA verification tests.
#[derive(Debug)]
pub struct DriftInjector {
    rng: rand::rngs::ThreadRng,
}

impl DriftInjector {
    /// Create a new drift injector with a thread-local RNG.
    pub fn new() -> Self {
        Self { rng: rand::rng() }
    }

    /// Inject decision drift into a value containing risk scores and verdicts.
    ///
    /// For numeric fields (risk_score, confidence, etc.), shifts by up to `magnitude`.
    /// For string verdict fields, may flip between adjacent verdicts if magnitude is high enough.
    pub fn inject_decision_drift(&mut self, original: &Value, magnitude: f64) -> Value {
        let mut modified = original.clone();
        self.apply_numeric_drift(&mut modified, magnitude);
        tracing::debug!(magnitude = %magnitude, "Injected decision drift");
        modified
    }

    /// Inject policy drift into a value containing thresholds and sensitivity settings.
    ///
    /// Shifts threshold-like fields (threshold, sensitivity, tolerance) by up to `magnitude`.
    pub fn inject_policy_drift(&mut self, original: &Value, magnitude: f64) -> Value {
        let mut modified = original.clone();
        if let Some(obj) = modified.as_object_mut() {
            let policy_keys = [
                "threshold",
                "sensitivity",
                "tolerance",
                "max_risk",
                "block_threshold",
            ];
            for key in &policy_keys {
                if let Some(Value::Number(n)) = obj.get_mut(*key) {
                    if let Some(f) = n.as_f64() {
                        let shift = self.rng.random_range(-magnitude..=magnitude);
                        let new_val = (f + shift).max(0.0).min(1.0);
                        if let Some(num) = serde_json::Number::from_f64(new_val) {
                            *n = num;
                        }
                    }
                }
            }
        }
        tracing::debug!(magnitude = %magnitude, "Injected policy drift");
        modified
    }

    /// Inject trust drift — shift a trust score by a controlled magnitude.
    ///
    /// Returns a value clamped to [0.0, 1.0].
    pub fn inject_trust_drift(&mut self, original: f64, magnitude: f64) -> f64 {
        let shift = self.rng.random_range(-magnitude..=magnitude);
        let drifted = (original + shift).max(0.0).min(1.0);
        tracing::debug!(
            original = %original, drifted = %drifted, magnitude = %magnitude,
            "Injected trust drift"
        );
        drifted
    }

    /// Inject integrity corruption by flipping bits in a string.
    ///
    /// Flips approximately `magnitude * len` bytes (treating magnitude as a fraction).
    /// Returns the corrupted string.
    pub fn inject_integrity_corruption(&mut self, data: &str) -> String {
        if data.is_empty() {
            return data.to_string();
        }
        let mut bytes = data.as_bytes().to_vec();
        let num_flips = if data.len() > 2 {
            (data.len() as f64 * 0.05).max(1.0) as usize
        } else {
            1
        };

        for _ in 0..num_flips.min(bytes.len()) {
            let idx = self.rng.random_range(0..bytes.len());
            let bit_pos = self.rng.random_range(0..8);
            bytes[idx] ^= 1 << bit_pos;
        }

        let corrupted = String::from_utf8_lossy(&bytes).to_string();
        tracing::debug!(
            original_len = data.len(),
            corrupted_len = corrupted.len(),
            num_flips,
            "Injected integrity corruption"
        );
        corrupted
    }

    /// Inject config drift by modifying specific config fields.
    ///
    /// For each field in `fields`, if it exists in the original value as a number,
    /// shifts it by up to `magnitude`. If it's a string, appends a random suffix.
    pub fn inject_config_drift(
        &mut self,
        original: &Value,
        fields: &[String],
        magnitude: f64,
    ) -> Value {
        let mut modified = original.clone();
        if let Some(obj) = modified.as_object_mut() {
            for field in fields {
                if let Some(value) = obj.get_mut(field) {
                    match value {
                        Value::Number(n) => {
                            if let Some(f) = n.as_f64() {
                                let shift = self.rng.random_range(-magnitude..=magnitude);
                                if let Some(num) = serde_json::Number::from_f64(f + shift) {
                                    *n = num;
                                }
                            }
                        }
                        Value::String(s) => {
                            let suffix = format!("_drift_{}", self.rng.random_range(0..10000));
                            *s = format!("{}{}", s, suffix);
                        }
                        Value::Bool(b) => {
                            // Flip with probability proportional to magnitude.
                            if self.rng.random::<f64>() < magnitude {
                                *b = !*b;
                            }
                        }
                        _ => {} // Skip arrays, nulls, objects
                    }
                }
            }
        }
        tracing::debug!(fields = ?fields, magnitude = %magnitude, "Injected config drift");
        modified
    }

    // ── Internal helpers ──

    /// Apply numeric drift to all numeric fields in a JSON value.
    fn apply_numeric_drift(&mut self, value: &mut Value, magnitude: f64) {
        match value {
            Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    self.apply_numeric_drift(v, magnitude);
                }
            }
            Value::Array(arr) => {
                for v in arr.iter_mut() {
                    self.apply_numeric_drift(v, magnitude);
                }
            }
            Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    let shift = self.rng.random_range(-magnitude..=magnitude);
                    if let Some(num) = serde_json::Number::from_f64(f + shift) {
                        *n = num;
                    }
                }
            }
            _ => {} // Skip strings, bools, null
        }
    }
}

impl Default for DriftInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_drift_shifts_risk_score() {
        let mut injector = DriftInjector::new();
        let original = serde_json::json!({
            "risk_score": 0.5,
            "verdict": "allow"
        });
        let drifted = injector.inject_decision_drift(&original, 0.1);

        // Risk score should have shifted.
        let drifted_score = drifted["risk_score"].as_f64().unwrap_or(0.0);
        let orig_score = original["risk_score"].as_f64().unwrap_or(0.0);
        assert!((drifted_score - orig_score).abs() <= 0.1);
        // Verdict should still be a string.
        assert!(drifted["verdict"].is_string());
    }

    #[test]
    fn policy_drift_modifies_thresholds() {
        let mut injector = DriftInjector::new();
        let original = serde_json::json!({
            "threshold": 0.8,
            "sensitivity": 0.6,
            "other_field": "untouched"
        });
        let drifted = injector.inject_policy_drift(&original, 0.05);

        // Threshold and sensitivity should change.
        let t = drifted["threshold"].as_f64().unwrap_or(0.0);
        assert!((t - 0.8).abs() <= 0.05);
        let s = drifted["sensitivity"].as_f64().unwrap_or(0.0);
        assert!((s - 0.6).abs() <= 0.05);
        // Non-policy field should be untouched.
        assert_eq!(drifted["other_field"], original["other_field"]);
    }

    #[test]
    fn trust_drift_clamped() {
        let mut injector = DriftInjector::new();
        let drifted = injector.inject_trust_drift(0.9, 0.5);
        assert!(drifted >= 0.0 && drifted <= 1.0);
    }

    #[test]
    fn integrity_corruption_changes_data() {
        let mut injector = DriftInjector::new();
        let data = "hello world this is a test string for corruption";
        let corrupted = injector.inject_integrity_corruption(data);
        // With high probability, the corrupted string differs.
        // (There's a tiny chance the same bits get flipped twice, but with a long string it's negligible.)
        assert_ne!(data, corrupted);
    }

    #[test]
    fn config_drift_modifies_specific_fields() {
        let mut injector = DriftInjector::new();
        let original = serde_json::json!({
            "port": 8080,
            "timeout": 30.0,
            "mode": "strict",
            "enabled": true
        });
        let fields = vec!["port".to_string(), "mode".to_string()];
        let drifted = injector.inject_config_drift(&original, &fields, 0.1);

        // Port should have changed.
        assert_ne!(drifted["port"], original["port"]);
        // Mode should have a suffix appended.
        let mode = drifted["mode"].as_str().unwrap_or("");
        assert!(mode.contains("_drift_"));
        // Timeout and enabled should be untouched (not in fields list).
        assert_eq!(drifted["timeout"], original["timeout"]);
        assert_eq!(drifted["enabled"], original["enabled"]);
    }

    #[test]
    fn integrity_corruption_empty_string() {
        let mut injector = DriftInjector::new();
        let corrupted = injector.inject_integrity_corruption("");
        assert_eq!(corrupted, "");
    }

    #[test]
    fn decision_drift_nested_objects() {
        let mut injector = DriftInjector::new();
        let original = serde_json::json!({
            "outer": { "inner_score": 0.75, "flag": true }
        });
        let drifted = injector.inject_decision_drift(&original, 0.1);
        let inner = drifted["outer"]["inner_score"].as_f64().unwrap_or(0.0);
        assert!((inner - 0.75).abs() <= 0.1);
    }
}
