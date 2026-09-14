/// Protect endpoint implementation.

use crate::client::HttpClient;
use crate::errors::ChakravyuhError;
use crate::models::{ProtectRequest, ProtectResponse, WithHeaders};

/// Optional parameters for the protect call.
#[derive(Debug, Clone, Default)]
pub struct ProtectOptions {
    /// Idempotency key for exactly-once processing.
    pub idempotency_key: Option<String>,
    /// Correlation ID for distributed tracing.
    pub correlation_id: Option<String>,
}

impl ProtectOptions {
    /// Create new empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the idempotency key.
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Set the correlation ID.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }
}

/// Execute a protect request.
pub(crate) async fn execute_protect(
    client: &HttpClient,
    request: ProtectRequest,
    options: Option<ProtectOptions>,
) -> Result<WithHeaders<ProtectResponse>, ChakravyuhError> {
    let opts = options.unwrap_or_default();
    client
        .post_with_headers(
            "/v1/protect",
            &request,
            opts.idempotency_key.as_deref(),
            opts.correlation_id.as_deref(),
        )
        .await
}
