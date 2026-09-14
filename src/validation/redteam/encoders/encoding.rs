// Red Team OS — Encoding Strategies (D1)
//
// Encoding strategies fully encode a payload into a different representation.
// Unlike mutations (which subtly alter), encoders transform the entire payload.

use serde::{Deserialize, Serialize};

/// Trait for encoding strategies.
pub trait Encoder {
    /// Human-readable name.
    fn name(&self) -> &str;

    /// Encode the payload. Returns an error if encoding fails.
    fn encode(&self, payload: &str) -> Result<String, String>;
}

// ─── Identity (no-op encoder) ──────────────────────────────────────────

/// No-op encoder — returns the payload unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityEncoder;

impl Encoder for IdentityEncoder {
    fn name(&self) -> &str {
        "identity"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        Ok(payload.to_string())
    }
}

// ─── 1. Base64 Encoding ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Base64Encoder;

impl Encoder for Base64Encoder {
    fn name(&self) -> &str {
        "base64"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        Ok(engine.encode(payload.as_bytes()))
    }
}

// ─── 2. URL Encoding ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UrlEncoder;

impl Encoder for UrlEncoder {
    fn name(&self) -> &str {
        "url_encoding"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        let encoded: String = payload
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
        Ok(encoded)
    }
}

// ─── 3. Hex Encoding ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HexEncoder;

impl Encoder for HexEncoder {
    fn name(&self) -> &str {
        "hex_encoding"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        Ok(hex::encode(payload.as_bytes()))
    }
}

// ─── 4. HTML Entity Encoding ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HtmlEntityEncoder;

impl Encoder for HtmlEntityEncoder {
    fn name(&self) -> &str {
        "html_entity_encoding"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        let encoded: String = payload
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    format!("&#{};", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect();
        Ok(encoded)
    }
}

// ─── 5. Unicode Escape Encoding ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnicodeEscapeEncoder;

impl Encoder for UnicodeEscapeEncoder {
    fn name(&self) -> &str {
        "unicode_escape"
    }
    fn encode(&self, payload: &str) -> Result<String, String> {
        let encoded: String = payload
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    format!("\\u{:04x}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect();
        Ok(encoded)
    }
}

/// Returns all built-in encoders.
pub fn all_encoders() -> Vec<Box<dyn Encoder>> {
    vec![
        Box::new(IdentityEncoder),
        Box::new(Base64Encoder),
        Box::new(UrlEncoder),
        Box::new(HexEncoder),
        Box::new(HtmlEntityEncoder),
        Box::new(UnicodeEscapeEncoder),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_encoder() {
        let e = IdentityEncoder;
        assert_eq!(e.encode("hello").unwrap(), "hello");
    }

    #[test]
    fn base64_roundtrip() {
        let e = Base64Encoder;
        let encoded = e.encode("hello world").unwrap();
        assert_ne!(encoded, "hello world");
        // Verify it's valid base64
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded = engine.decode(&encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn url_encoder_special_chars() {
        let e = UrlEncoder;
        let encoded = e.encode("hello world<script>").unwrap();
        assert!(encoded.contains("%20"));
        assert!(encoded.contains("%3C"));
    }

    #[test]
    fn hex_encoder() {
        let e = HexEncoder;
        let encoded = e.encode("AB").unwrap();
        assert_eq!(encoded, "4142");
    }

    #[test]
    fn html_entity_encoder() {
        let e = HtmlEntityEncoder;
        let encoded = e.encode("<A>").unwrap();
        assert!(encoded.contains("&#60;"));
        assert!(encoded.contains("&#65;"));
    }

    #[test]
    fn unicode_escape_encoder() {
        let e = UnicodeEscapeEncoder;
        let encoded = e.encode("hi").unwrap();
        assert_eq!(encoded, "\\u0068\\u0069");
    }

    #[test]
    fn all_encoders_count() {
        let encs = all_encoders();
        assert_eq!(encs.len(), 6); // 5 real + 1 identity
    }

    #[test]
    fn all_encoders_produce_output() {
        for enc in all_encoders() {
            let result = enc.encode("test");
            assert!(result.is_ok(), "Encoder {} failed", enc.name());
            assert!(!result.unwrap().is_empty());
        }
    }
}
