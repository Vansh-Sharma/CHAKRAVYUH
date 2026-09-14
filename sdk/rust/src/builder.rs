/// Builder for constructing a [`Chakravyuh`](crate::Chakravyuh) client.

use std::time::Duration;

use crate::auth::ApiKey;

/// Builder for constructing a [`Chakravyuh`](crate::Chakravyuh) client instance.
///
/// Use [`Chakravyuh::builder()`](crate::Chakravyuh::builder) to obtain a new builder.
///
/// # Examples
///
/// ```
/// use chakravyuh::Chakravyuh;
///
/// let ck = Chakravyuh::builder()
///     .api_key("ck_live_xxxxxxxxx")?
///     .base_url("https://api.chakravyuh.ai")
///     .timeout(30)
///     .build()?;
/// # Ok::<(), chakravyuh::ChakravyuhError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ChakravyuhBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout_secs: Option<u64>,
}

impl Default for ChakravyuhBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChakravyuhBuilder {
    /// Create a new builder with default settings.
    pub(crate) fn new() -> Self {
        Self {
            api_key: None,
            base_url: Some("https://api.vinomoid.com".to_string()),
            timeout_secs: Some(30),
        }
    }

    /// Set the API key.
    ///
    /// The key must follow the format `ck_live_*` (production) or `ck_test_*` (sandbox).
    ///
    /// # Errors
    ///
    /// Returns [`ChakravyuhError::Unauthorized`] if the key format is invalid.
    pub fn api_key(mut self, key: impl Into<String>) -> Result<Self, crate::ChakravyuhError> {
        // Validate the key format early.
        let _validated = ApiKey::new(key.into())?;
        self.api_key = Some(_validated.as_str().to_string());
        Ok(self)
    }

    /// Set the base URL for the API.
    ///
    /// Defaults to `https://api.vinomoid.com`.
    ///
    /// Use `http://localhost:9090` for local development.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the request timeout in seconds.
    ///
    /// Defaults to 30 seconds.
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    /// Build the [`Chakravyuh`](crate::Chakravyuh) client.
    ///
    /// # Errors
    ///
    /// Returns an error if the API key is not set.
    pub fn build(self) -> Result<crate::Chakravyuh, crate::ChakravyuhError> {
        let key_str = self.api_key.ok_or_else(|| {
            crate::ChakravyuhError::Unauthorized(
                "API key is required. Call .api_key() before .build().".to_string(),
            )
        })?;

        let api_key = ApiKey::new(key_str)?;
        let base_url = self
            .base_url
            .unwrap_or_else(|| "https://api.vinomoid.com".to_string());
        let timeout = Duration::from_secs(self.timeout_secs.unwrap_or(30));

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .build()
            .map_err(|e| crate::ChakravyuhError::Network(format!(
                "Failed to create HTTP client: {e}"
            )))?;

        Ok(crate::Chakravyuh {
            http,
            api_key,
            base_url: base_url.trim_end_matches('/').to_string(),
            timeout_secs: timeout.as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let b = ChakravyuhBuilder::new();
        assert!(b.api_key.is_none());
        assert_eq!(b.base_url.as_deref(), Some("https://api.vinomoid.com"));
        assert_eq!(b.timeout_secs, Some(30));
    }

    #[test]
    fn test_builder_custom() {
        let b = ChakravyuhBuilder::new()
            .api_key("ck_live_abc123")
            .unwrap()
            .base_url("http://localhost:9090")
            .timeout(60);
        assert_eq!(b.api_key.as_deref(), Some("ck_live_abc123"));
        assert_eq!(b.base_url.as_deref(), Some("http://localhost:9090"));
        assert_eq!(b.timeout_secs, Some(60));
    }

    #[test]
    fn test_builder_invalid_key() {
        let result = ChakravyuhBuilder::new().api_key("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_build_fails_without_key() {
        let result = ChakravyuhBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_build_success() {
        let result = ChakravyuhBuilder::new()
            .api_key("ck_live_abc")
            .unwrap()
            .base_url("http://localhost:9090")
            .build();
        assert!(result.is_ok());
        let ck = result.unwrap();
        assert_eq!(ck.api_key.as_str(), "ck_live_abc");
        assert_eq!(ck.base_url, "http://localhost:9090");
    }

    #[test]
    fn test_base_url_trailing_slash_stripped() {
        let ck = ChakravyuhBuilder::new()
            .api_key("ck_live_abc")
            .unwrap()
            .base_url("https://api.vinomoid.com/")
            .build()
            .unwrap();
        assert_eq!(ck.base_url, "https://api.vinomoid.com");
    }
}