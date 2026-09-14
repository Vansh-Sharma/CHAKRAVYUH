/// Internal HTTP execution layer.

use crate::auth::ApiKey;
use crate::errors::{api_error_from_status, ChakravyuhError};
use crate::models::{ErrorResponse, WithHeaders};

/// Internal client for executing authenticated HTTP requests against the
/// CHAKRAVYUH OS REST Gateway.
#[derive(Debug, Clone)]
pub(crate) struct HttpClient {
    /// The underlying `reqwest` client.
    pub http: reqwest::Client,
    /// Base URL of the API (trailing slash stripped).
    pub base_url: String,
    /// Authenticated API key.
    pub api_key: ApiKey,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl HttpClient {
    /// Execute an authenticated GET request.
    pub async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &str,
    ) -> Result<WithHeaders<T>, ChakravyuhError> {
        let url = format!("{}{}{query}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.api_key.bearer_value())
            .header("Accept", "application/json")
            .header("User-Agent", self::user_agent())
            .send()
            .await?;

        self.extract(resp).await
    }

    /// Execute an authenticated POST request with a JSON body.
    pub async fn post<
        B: serde::Serialize,
        T: serde::de::DeserializeOwned,
    >(
        &self,
        path: &str,
        body: &B,
    ) -> Result<WithHeaders<T>, ChakravyuhError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", self.api_key.bearer_value())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", self::user_agent())
            .json(body)
            .send()
            .await?;

        self.extract(resp).await
    }

    /// Execute an authenticated POST request with optional idempotency and correlation headers.
    pub async fn post_with_headers<
        B: serde::Serialize,
        T: serde::de::DeserializeOwned,
    >(
        &self,
        path: &str,
        body: &B,
        idempotency_key: Option<&str>,
        correlation_id: Option<&str>,
    ) -> Result<WithHeaders<T>, ChakravyuhError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .http
            .post(&url)
            .header("Authorization", self.api_key.bearer_value())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", self::user_agent())
            .json(body);

        if let Some(key) = idempotency_key {
            req = req.header("Idempotency-Key", key);
        }
        if let Some(cid) = correlation_id {
            req = req.header("X-Correlation-Id", cid);
        }

        let resp = req.send().await?;
        self.extract(resp).await
    }

    /// Extract a successful response or convert an error.
    async fn extract<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<WithHeaders<T>, ChakravyuhError> {
        let status = resp.status().as_u16();
        let request_id = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let audit_trace_id = resp
            .headers()
            .get("x-audit-trace-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if resp.status().is_success() {
            let data: T = resp.json().await?;
            Ok(WithHeaders {
                data,
                request_id,
                audit_trace_id,
            })
        } else {
            // Try to parse the error body.
            let body_text = resp.text().await.unwrap_or_default();
            if let Ok(error_resp) = serde_json::from_str::<ErrorResponse>(&body_text) {
                let err = api_error_from_status(status, &error_resp.error);
                Err(err)
            } else {
                // Fallback for non-JSON error bodies.
                Err(ChakravyuhError::Api {
                    code: "unknown_error".to_string(),
                    message: body_text,
                    request_id: request_id.unwrap_or_default(),
                })
            }
        }
    }
}

fn user_agent() -> &'static str {
    concat!(
        "chakravyuh-rust-sdk/",
        env!("CARGO_PKG_VERSION"),
        " (rust/",
        env!("CARGO_PKG_RUST_VERSION"),
        ")"
    )
}
