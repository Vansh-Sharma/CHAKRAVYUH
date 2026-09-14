// ContextGuard — validates context length, depth, token limits
//
// Prevents context window overflow attacks and excessive conversation depth.

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ContextGuardConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Max context length in characters (default: 128000).
    #[serde(default = "default_max_context")]
    pub max_context_length: usize,
    /// Max turns in a conversation (default: 100).
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    /// Max prompt length in characters (default: 64000).
    #[serde(default = "default_max_prompt")]
    pub max_prompt_length: usize,
    /// Warning threshold (percentage of max, default: 0.8).
    #[serde(default = "default_warning_threshold")]
    pub warning_threshold: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_max_context() -> usize {
    128_000
}
fn default_max_turns() -> u32 {
    100
}
fn default_max_prompt() -> usize {
    64_000
}
fn default_warning_threshold() -> f64 {
    0.8
}

impl Default for ContextGuardConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_context_length: default_max_context(),
            max_turns: default_max_turns(),
            max_prompt_length: default_max_prompt(),
            warning_threshold: default_warning_threshold(),
        }
    }
}

pub struct ContextGuardResult {
    pub valid: bool,
    pub reason: String,
    pub context_length: usize,
    pub turn_count: u32,
    pub max_context: usize,
    pub max_turns: u32,
    pub latency_ms: f64,
}

/// Detects excessive repetition in the prompt (context flood attack).
/// Checks if any substring of length 4-50 is repeated 5+ times consecutively.
fn has_excessive_repetition(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    // Check substrings of length 4 to 20 (beyond that, the check is too expensive).
    for sub_len in 4..=20.min(len / 5) {
        for start in 0..=(len.saturating_sub(sub_len * 5)) {
            let sub = &chars[start..start + sub_len];
            let mut repeat_count = 0usize;
            let mut pos = start;
            while pos + sub_len <= len && &chars[pos..pos + sub_len] == sub {
                repeat_count += 1;
                pos += sub_len;
            }
            if repeat_count >= 5 {
                return true;
            }
        }
    }
    false
}

pub struct ContextGuard {
    config: ContextGuardConfig,
}

impl ContextGuard {
    pub fn new(config: &ContextGuardConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn evaluate(
        &self,
        prompt: &str,
        context_length: usize,
        turn_count: u32,
    ) -> ContextGuardResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ContextGuardResult {
                valid: true,
                reason: "context guard disabled".into(),
                context_length,
                turn_count,
                max_context: self.config.max_context_length,
                max_turns: self.config.max_turns,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check prompt length.
        if prompt.len() > self.config.max_prompt_length {
            return ContextGuardResult {
                valid: false,
                reason: format!(
                    "prompt exceeds max length ({} > {})",
                    prompt.len(),
                    self.config.max_prompt_length
                ),
                context_length,
                turn_count,
                max_context: self.config.max_context_length,
                max_turns: self.config.max_turns,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check context length.
        if context_length > self.config.max_context_length {
            return ContextGuardResult {
                valid: false,
                reason: format!(
                    "context exceeds max length ({} > {})",
                    context_length, self.config.max_context_length
                ),
                context_length,
                turn_count,
                max_context: self.config.max_context_length,
                max_turns: self.config.max_turns,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check turn count.
        if turn_count > self.config.max_turns {
            return ContextGuardResult {
                valid: false,
                reason: format!(
                    "turn count exceeds max ({} > {})",
                    turn_count, self.config.max_turns
                ),
                context_length,
                turn_count,
                max_context: self.config.max_context_length,
                max_turns: self.config.max_turns,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check for repetition attacks.
        if has_excessive_repetition(prompt) {
            return ContextGuardResult {
                valid: false,
                reason: "excessive repetition detected — possible context flood attack".into(),
                context_length,
                turn_count,
                max_context: self.config.max_context_length,
                max_turns: self.config.max_turns,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Warning threshold check (soft — valid but flagged).
        let usage_ratio = context_length as f64 / self.config.max_context_length as f64;
        let reason = if usage_ratio > self.config.warning_threshold {
            format!(
                "context usage at {:.0}% ({}/{})",
                usage_ratio * 100.0,
                context_length,
                self.config.max_context_length
            )
        } else {
            "context within limits".into()
        };

        ContextGuardResult {
            valid: true,
            reason,
            context_length,
            turn_count,
            max_context: self.config.max_context_length,
            max_turns: self.config.max_turns,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guard() -> ContextGuard {
        ContextGuard::new(&ContextGuardConfig::default())
    }

    #[test]
    fn normal_prompt_passes() {
        let g = default_guard();
        let r = g.evaluate("Hello, how are you?", 50, 1);
        assert!(r.valid);
    }

    #[test]
    fn oversized_context_fails() {
        let g = default_guard();
        let r = g.evaluate("test", 200_000, 1);
        assert!(!r.valid);
        assert!(r.reason.contains("exceeds max"));
    }

    #[test]
    fn too_many_turns_fails() {
        let g = default_guard();
        let r = g.evaluate("test", 100, 500);
        assert!(!r.valid);
        assert!(r.reason.contains("turn count"));
    }

    #[test]
    fn repetition_detected() {
        let g = default_guard();
        let repeated = "ignore this ".repeat(100);
        let r = g.evaluate(&repeated, repeated.len(), 1);
        assert!(!r.valid);
        assert!(r.reason.contains("repetition"));
    }

    #[test]
    fn disabled_allows_all() {
        let g = ContextGuard::new(&ContextGuardConfig {
            enabled: false,
            ..Default::default()
        });
        let r = g.evaluate("test", 999_999, 9999);
        assert!(r.valid);
    }

    #[test]
    fn oversized_prompt_fails() {
        let g = default_guard();
        let long_prompt = "x".repeat(70_000);
        let r = g.evaluate(&long_prompt, long_prompt.len(), 1);
        assert!(!r.valid);
        assert!(r.reason.contains("prompt exceeds"));
    }
}
