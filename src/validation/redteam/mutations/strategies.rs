// Red Team OS — Mutation Strategies (D1)
//
// Mutation strategies transform attack payloads to test detection robustness.
// Each strategy takes a payload string and returns a mutated version.

use serde::{Deserialize, Serialize};

/// Trait for mutation strategies.
pub trait MutationStrategy {
    /// Human-readable name of this mutation.
    fn name(&self) -> &str;

    /// Apply this mutation to a payload string.
    fn apply(&self, payload: &str) -> String;
}

// ─── Identity (no-op mutation) ─────────────────────────────────────────

/// No-op mutation — returns the payload unchanged. Used as a baseline.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityMutation;

impl MutationStrategy for IdentityMutation {
    fn name(&self) -> &str { "identity" }
    fn apply(&self, payload: &str) -> String { payload.to_string() }
}

// ─── 1. Case Variation ──────────────────────────────────────────────────

/// Randomly varies the case of alphabetic characters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaseVariationMutation;

impl MutationStrategy for CaseVariationMutation {
    fn name(&self) -> &str { "case_variation" }

    fn apply(&self, payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c.is_ascii_alphabetic() && i % 3 == 0 {
                    c.to_ascii_uppercase()
                } else if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .collect()
    }
}

// ─── 2. Unicode Homoglyph ───────────────────────────────────────────────

/// Replaces ASCII characters with visually similar Unicode homoglyphs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnicodeHomoglyphMutation;

impl MutationStrategy for UnicodeHomoglyphMutation {
    fn name(&self) -> &str { "unicode_homoglyph" }

    fn apply(&self, payload: &str) -> String {
        let homoglyphs: &[(&str, &str)] = &[
            ("a", "\u{0430}"), ("e", "\u{0435}"), ("o", "\u{043E}"),
            ("p", "\u{0440}"), ("c", "\u{0441}"), ("x", "\u{0445}"),
            ("y", "\u{0443}"), ("H", "\u{041D}"), ("i", "\u{0456}"),
            ("j", "\u{0458}"),
        ];
        let mut result = payload.to_string();
        for (ascii, unicode) in homoglyphs {
            // Only replace first occurrence to keep it subtle.
            if let Some(idx) = result.find(ascii) {
                result = format!("{}{}{}", &result[..idx], unicode, &result[idx + ascii.len()..]);
            }
        }
        result
    }
}

// ─── 3. Whitespace Injection ────────────────────────────────────────────

/// Inserts zero-width or unusual whitespace between characters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitespaceInjectionMutation;

impl MutationStrategy for WhitespaceInjectionMutation {
    fn name(&self) -> &str { "whitespace_injection" }

    fn apply(&self, payload: &str) -> String {
        let words: Vec<&str> = payload.split_whitespace().collect();
        words.join("\u{200B}") // Zero-width space between words
    }
}

// ─── 4. Comment Injection ───────────────────────────────────────────────

/// Injects HTML/XML-style comments within words.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommentInjectionMutation;

impl MutationStrategy for CommentInjectionMutation {
    fn name(&self) -> &str { "comment_injection" }

    fn apply(&self, payload: &str) -> String {
        let words: Vec<String> = payload.split_whitespace()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 && w.len() > 3 {
                    let mid = w.len() / 2;
                    format!("{}<!---->{}", &w[..mid], &w[mid..])
                } else {
                    w.to_string()
                }
            })
            .collect();
        words.join(" ")
    }
}

// ─── 5. Null Byte Injection ─────────────────────────────────────────────

/// Injects null bytes between words to confuse string processing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NullByteMutation;

impl MutationStrategy for NullByteMutation {
    fn name(&self) -> &str { "null_byte" }

    fn apply(&self, payload: &str) -> String {
        payload.split_whitespace().collect::<Vec<_>>().join("\x00")
    }
}

// ─── 6. Zero-Width Characters ───────────────────────────────────────────

/// Appends zero-width characters that are invisible but change the string.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZeroWidthMutation;

impl MutationStrategy for ZeroWidthMutation {
    fn name(&self) -> &str { "zero_width" }

    fn apply(&self, payload: &str) -> String {
        // Zero-width joiner (U+200D) and zero-width non-joiner (U+200C)
        let zwc = "\u{200D}\u{200C}\u{200B}";
        format!("{}{}", payload, zwc)
    }
}

// ─── 7. HTML Entity Encoding ────────────────────────────────────────────

/// Encodes key characters as HTML entities.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HtmlEntityMutation;

impl MutationStrategy for HtmlEntityMutation {
    fn name(&self) -> &str { "html_entity" }

    fn apply(&self, payload: &str) -> String {
        payload
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
}

// ─── 8. Double URL Encoding ─────────────────────────────────────────────

/// Applies URL encoding twice to obfuscate the payload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DoubleUrlEncodeMutation;

impl MutationStrategy for DoubleUrlEncodeMutation {
    fn name(&self) -> &str { "double_url_encode" }

    fn apply(&self, payload: &str) -> String {
        let once: String = payload
            .bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                    vec![b]
                } else {
                    format!("%{:02X}", b).into_bytes()
                }
            })
            .map(|b| b as char)
            .collect();
        // Second pass
        once.bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || b == b'%' {
                    vec![b]
                } else {
                    format!("%{:02X}", b).into_bytes()
                }
            })
            .map(|b| b as char)
            .collect()
    }
}

// ─── 9. Unicode Normalize Trick ─────────────────────────────────────────

/// Uses Unicode normalization tricks (fullwidth characters).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnicodeNormalizeMutation;

impl MutationStrategy for UnicodeNormalizeMutation {
    fn name(&self) -> &str { "unicode_normalize" }

    fn apply(&self, payload: &str) -> String {
        payload
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    // Map a-z to fullwidth U+FF41–U+FF5A
                    let offset = c as u32 - 'a' as u32;
                    char::from_u32(0xFF41 + offset).unwrap_or(c)
                } else if c.is_ascii_uppercase() {
                    let offset = c as u32 - 'A' as u32;
                    char::from_u32(0xFF21 + offset).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect()
    }
}

// ─── 10. Token Splitting ────────────────────────────────────────────────

/// Splits tokens with invisible separators to evade pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenSplittingMutation;

impl MutationStrategy for TokenSplittingMutation {
    fn name(&self) -> &str { "token_splitting" }

    fn apply(&self, payload: &str) -> String {
        // Insert a soft hyphen (U+00AD) after every 3rd character
        payload
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let mut v = vec![c];
                if i > 0 && i % 3 == 0 {
                    v.push('\u{00AD}'); // soft hyphen
                }
                v
            })
            .collect()
    }
}

/// Returns all built-in mutation strategies.
pub fn all_strategies() -> Vec<Box<dyn MutationStrategy>> {
    vec![
        Box::new(IdentityMutation),
        Box::new(CaseVariationMutation),
        Box::new(UnicodeHomoglyphMutation),
        Box::new(WhitespaceInjectionMutation),
        Box::new(CommentInjectionMutation),
        Box::new(NullByteMutation),
        Box::new(ZeroWidthMutation),
        Box::new(HtmlEntityMutation),
        Box::new(DoubleUrlEncodeMutation),
        Box::new(UnicodeNormalizeMutation),
        Box::new(TokenSplittingMutation),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_returns_same() {
        let m = IdentityMutation;
        assert_eq!(m.apply("hello world"), "hello world");
    }

    #[test]
    fn case_variation_changes_case() {
        let m = CaseVariationMutation;
        let result = m.apply("HELLO world");
        assert_ne!(result, "HELLO world");
    }

    #[test]
    fn whitespace_injection_adds_zws() {
        let m = WhitespaceInjectionMutation;
        let result = m.apply("hello world");
        assert!(result.contains('\u{200B}'));
    }

    #[test]
    fn null_byte_injection() {
        let m = NullByteMutation;
        let result = m.apply("a b c");
        assert!(result.contains('\x00'));
    }

    #[test]
    fn unicode_normalize_produces_fullwidth() {
        let m = UnicodeNormalizeMutation;
        let result = m.apply("abc");
        assert_ne!(result, "abc");
        assert!(result.chars().any(|c| c > '\u{FF00}'));
    }

    #[test]
    fn html_entity_encodes_special() {
        let m = HtmlEntityMutation;
        let result = m.apply("<script>alert('xss')</script>");
        assert!(result.contains("&lt;"));
        assert!(result.contains("&gt;"));
    }

    #[test]
    fn token_splitting_adds_soft_hyphen() {
        let m = TokenSplittingMutation;
        let result = m.apply("abcdef");
        assert!(result.contains('\u{00AD}'));
    }

    #[test]
    fn all_strategies_count() {
        let strats = all_strategies();
        assert_eq!(strats.len(), 11); // 10 real + 1 identity
    }

    #[test]
    fn each_strategy_has_name() {
        for s in all_strategies() {
            assert!(!s.name().is_empty());
            let result = s.apply("test payload");
            assert!(!result.is_empty());
        }
    }
}
