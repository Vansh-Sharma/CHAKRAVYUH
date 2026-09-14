/// Authentication handling for the CHAKRAVYUH SDK.
///
/// Supports Bearer JWT and API key authentication using `ck_live_*` (production)
/// and `ck_test_*` (sandbox) token formats.

use std::fmt;

/// A validated API key or Bearer token.
///
/// The key is validated at construction time to ensure it follows the
/// expected format (`ck_live_*` or `ck_test_*`).
#[derive(Debug, Clone)]
pub struct ApiKey {
    token: String,
}

impl ApiKey {
    /// Create a new API key from a string.
    ///
    /// The key must start with `ck_live_` or `ck_test_`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not match the expected format.
    ///
    /// # Examples
    ///
    /// ```
    /// use chakravyuh::auth::ApiKey;
    ///
    /// let key = ApiKey::new("ck_live_xxxxxxxxx")?;
    /// assert_eq!(key.as_str(), "ck_live_xxxxxxxxx");
    /// # Ok::<(), chakravyuh::ChakravyuhError>(())
    /// ```
    pub fn new(key: impl Into<String>) -> Result<Self, crate::ChakravyuhError> {
        let token = key.into();
        let trimmed = token.trim();
        if !trimmed.starts_with("ck_live_") && !trimmed.starts_with("ck_test_") {
            return Err(crate::ChakravyuhError::Unauthorized(format!(
                "Invalid API key format. Expected 'ck_live_*' or 'ck_test_*', got: '{}'",
                &trimmed[..trimmed.len().min(12)]
            )));
        }
        Ok(Self {
            token: trimmed.to_string(),
        })
    }

    /// Returns the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Returns `true` if this is a production (live) key.
    pub fn is_live(&self) -> bool {
        self.token.starts_with("ck_live_")
    }

    /// Returns `true` if this is a test/sandbox key.
    pub fn is_test(&self) -> bool {
        self.token.starts_with("ck_test_")
    }

    /// Returns the Bearer authorization header value.
    pub(crate) fn bearer_value(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mask the key for safe display.
        let prefix = &self.token[..8.min(self.token.len())];
        write!(f, "{}...", prefix)
    }
}

impl std::hash::Hash for ApiKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.token.hash(state);
    }
}

impl PartialEq for ApiKey {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
    }
}

impl Eq for ApiKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_live_key() {
        let key = ApiKey::new("ck_live_abc123xyz").unwrap();
        assert!(key.is_live());
        assert!(!key.is_test());
        assert_eq!(key.as_str(), "ck_live_abc123xyz");
    }

    #[test]
    fn test_valid_test_key() {
        let key = ApiKey::new("ck_test_abc123").unwrap();
        assert!(key.is_test());
        assert!(!key.is_live());
    }

    #[test]
    fn test_invalid_key() {
        let result = ApiKey::new("invalid_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_trimmed() {
        let key = ApiKey::new("  ck_live_abc  ").unwrap();
        assert_eq!(key.as_str(), "ck_live_abc");
    }

    #[test]
    fn test_bearer_value() {
        let key = ApiKey::new("ck_live_abc").unwrap();
        assert_eq!(key.bearer_value(), "Bearer ck_live_abc");
    }

    #[test]
    fn test_display_masked() {
        let key = ApiKey::new("ck_live_abc123xyz").unwrap();
        let display = format!("{key}");
        assert!(display.ends_with("..."));
        assert!(!display.contains("abc123xyz"));
    }
}