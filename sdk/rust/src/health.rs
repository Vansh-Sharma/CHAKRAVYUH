/// Health endpoint implementation.

use crate::client::HttpClient;
use crate::errors::ChakravyuhError;
use crate::models::{HealthResponse, WithHeaders};

/// Execute a health check request.
///
/// Note: The `/v1/health` endpoint does not require authentication per the API spec,
/// but we include the Authorization header anyway for consistency with the other calls.
pub(crate) async fn execute_health(
    client: &HttpClient,
) -> Result<WithHeaders<HealthResponse>, ChakravyuhError> {
    client.get("/v1/health", "").await
}