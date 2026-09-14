/// Audit endpoint implementation.

use crate::client::HttpClient;
use crate::errors::ChakravyuhError;
use crate::models::{AuditListResponse, AuditQuery, WithHeaders};

/// Optional parameters for the audit call.
#[derive(Debug, Clone, Default)]
pub struct AuditOptions {
    /// Correlation ID for distributed tracing.
    pub correlation_id: Option<String>,
}

impl AuditOptions {
    /// Create new empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the correlation ID.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }
}

/// Execute an audit list request.
pub(crate) async fn execute_audit(
    client: &HttpClient,
    query: &AuditQuery,
) -> Result<WithHeaders<AuditListResponse>, ChakravyuhError> {
    let qs = query.to_query();
    client.get("/v1/audit", &qs).await
}