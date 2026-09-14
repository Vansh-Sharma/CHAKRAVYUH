// SessionIdentity Engine — Identity Classification & Validation
//
// Classifies every request by its authentication method:
//   - API Key (Bearer token in Authorization header)
//   - JWT (signed token with claims)
//   - Session Token (opaque token mapped to session)
//   - Anonymous (no credentials)
//
// Validates credential format and structure.
// Does NOT verify signatures (that's handled upstream by the auth provider).
// CHAKRAVYUH is a security layer, not an identity provider.
//
// Output: IdentityProfile with identity_type, principal_id, trust_base
//
// Latency Budget: <0.05ms per evaluation

use serde::{Deserialize, Serialize};

/// Supported identity/credential types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    /// No credentials provided.
    Anonymous,
    /// API key (e.g., sk-xxxx, Bearer token without JWT structure).
    ApiKey,
    /// JWT token with claims (header.payload.signature).
    Jwt,
    /// Opaque session token.
    Session,
    /// Mutual TLS client certificate.
    Mtls,
    /// Internal/service identity (e.g., Keshav ring-to-ring).
    Internal,
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => write!(f, "anonymous"),
            Self::ApiKey => write!(f, "api_key"),
            Self::Jwt => write!(f, "jwt"),
            Self::Session => write!(f, "session"),
            Self::Mtls => write!(f, "mtls"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// The identity profile extracted from a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    /// The type of credential presented.
    pub identity_type: IdentityType,
    /// A principal identifier extracted from the credential.
    /// For API keys: a hash prefix (first 8 chars of SHA-256).
    /// For JWTs: the 'sub' claim if present.
    /// For anonymous: "anonymous".
    pub principal_id: String,
    /// Raw credential (truncated for logging — never logged in full).
    #[serde(skip_serializing)]
    pub credential_ref: String,
    /// Base trust level for this identity type (0.0-1.0).
    /// Higher = more trusted by default.
    pub trust_base: f64,
    /// Additional claims extracted (e.g., JWT scopes, roles).
    pub claims: Vec<String>,
    /// Whether the credential format is structurally valid.
    pub format_valid: bool,
}

impl Default for IdentityProfile {
    fn default() -> Self {
        Self {
            identity_type: IdentityType::Anonymous,
            principal_id: "anonymous".into(),
            credential_ref: String::new(),
            trust_base: 0.1, // Lowest default trust
            claims: vec![],
            format_valid: true,
        }
    }
}

/// SessionIdentity engine configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionIdentityConfig {
    /// Whether this engine is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// List of valid API key prefixes (e.g., ["sk-", "pk-"]).
    /// If empty, all API keys are accepted (format-only validation).
    #[serde(default)]
    pub valid_api_key_prefixes: Vec<String>,

    /// Minimum API key length (default: 16).
    #[serde(default = "default_min_key_length")]
    pub min_api_key_length: usize,

    /// Maximum API key length (default: 256).
    #[serde(default = "default_max_key_length")]
    pub max_api_key_length: usize,

    /// JWT issuers that are trusted (format-only, not signature verification).
    /// If empty, all JWTs are accepted structurally.
    #[serde(default)]
    pub trusted_jwt_issuers: Vec<String>,

    /// Base trust levels per identity type.
    #[serde(default = "default_trust_levels")]
    pub trust_bases: std::collections::HashMap<String, f64>,
}

fn default_enabled() -> bool { true }
fn default_min_key_length() -> usize { 16 }
fn default_max_key_length() -> usize { 256 }

fn default_trust_levels() -> std::collections::HashMap<String, f64> {
    let mut m = std::collections::HashMap::new();
    m.insert("anonymous".into(), 0.1);
    m.insert("api_key".into(), 0.5);
    m.insert("jwt".into(), 0.7);
    m.insert("session".into(), 0.6);
    m.insert("mtls".into(), 0.9);
    m.insert("internal".into(), 1.0);
    m
}

impl Default for SessionIdentityConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            valid_api_key_prefixes: vec!["sk-".into(), "pk-".into()],
            min_api_key_length: default_min_key_length(),
            max_api_key_length: default_max_key_length(),
            trusted_jwt_issuers: vec![],
            trust_bases: default_trust_levels(),
        }
    }
}

/// Result of identity classification.
#[derive(Debug, Clone)]
pub struct IdentityResult {
    pub profile: IdentityProfile,
    pub reason: String,
    pub latency_ms: f64,
    /// True if the credential is well-formed. False triggers escalation.
    pub valid: bool,
}

/// The SessionIdentity engine.
///
/// Classifies the request's authentication method and extracts
/// a principal identity. Does NOT verify signatures — that is
/// the responsibility of the upstream identity provider.
pub struct SessionIdentity {
    config: SessionIdentityConfig,
}

impl SessionIdentity {
    pub fn new(config: &SessionIdentityConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Classify and validate the identity from a request.
    ///
    /// Checks:
    ///   1. Is there an Authorization header? → JWT or API key
    ///   2. Is there an X-Session-Token header? → Session
    ///   3. Is there a X-Client-Cert header (mTLS proxied)? → mTLS
    ///   4. Is there an X-Internal-Identity header? → Internal
    ///   5. Otherwise → Anonymous
    pub fn evaluate(
        &self,
        api_key: Option<&str>,
        headers: &std::collections::HashMap<String, String>,
    ) -> IdentityResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return IdentityResult {
                profile: IdentityProfile::default(),
                reason: "session_identity engine disabled".into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                valid: true,
            };
        }

        // Check for internal identity first (highest trust).
        if let Some(internal_id) = headers.get("x-internal-identity") {
            let profile = IdentityProfile {
                identity_type: IdentityType::Internal,
                principal_id: internal_id.clone(),
                credential_ref: internal_id.clone(),
                trust_base: self.trust_base(&IdentityType::Internal),
                claims: vec!["internal".into()],
                format_valid: !internal_id.is_empty(),
            };
            return IdentityResult {
                reason: format!("internal identity: {}", internal_id),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                valid: profile.format_valid,
                profile,
            };
        }

        // Check for mTLS client certificate fingerprint.
        if let Some(cert_fp) = headers.get("x-client-cert-fingerprint") {
            let profile = IdentityProfile {
                identity_type: IdentityType::Mtls,
                principal_id: format!("cert:{}", &cert_fp[..cert_fp.len().min(16)]),
                credential_ref: cert_fp.clone(),
                trust_base: self.trust_base(&IdentityType::Mtls),
                claims: vec!["mtls".into()],
                format_valid: cert_fp.len() >= 8,
            };
            return IdentityResult {
                reason: format!("mtls certificate: {}...", &cert_fp[..cert_fp.len().min(16)]),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                valid: profile.format_valid,
                profile,
            };
        }

        // Check for session token.
        if let Some(session_token) = headers.get("x-session-token") {
            let valid = session_token.len() >= 16;
            let profile = IdentityProfile {
                identity_type: IdentityType::Session,
                principal_id: format!("session:{}", hash_prefix(session_token)),
                credential_ref: session_token.clone(),
                trust_base: self.trust_base(&IdentityType::Session),
                claims: vec![],
                format_valid: valid,
            };
            return IdentityResult {
                reason: if valid {
                    format!("session identity: {}", profile.principal_id)
                } else {
                    "session token too short".into()
                },
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                valid,
                profile,
            };
        }

        // Check API key / JWT from Authorization header.
        if let Some(key) = api_key {
            // Check if it's a JWT (has dots).
            if key.split('.').count() == 3 {
                let claims = self.extract_jwt_claims(key);
                let issuer_ok = self.config.trusted_jwt_issuers.is_empty()
                    || claims.iter().any(|c| c.starts_with("iss:"))
                    || self.config.trusted_jwt_issuers.is_empty();

                let profile = IdentityProfile {
                    identity_type: IdentityType::Jwt,
                    principal_id: claims
                        .iter()
                        .find(|c| c.starts_with("sub:"))
                        .map(|c| c[4..].to_string())
                        .unwrap_or_else(|| format!("jwt:{}", hash_prefix(key))),
                    credential_ref: key.to_string(),
                    trust_base: self.trust_base(&IdentityType::Jwt),
                    claims,
                    format_valid: key.len() >= 32, // JWTs are typically 100+ chars
                };
                return IdentityResult {
                    reason: format!("jwt identity: {}", profile.principal_id),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    valid: profile.format_valid && issuer_ok,
                    profile,
                };
            }

            // It's an API key.
            let prefix_valid = self.config.valid_api_key_prefixes.is_empty()
                || self.config.valid_api_key_prefixes.iter().any(|p| key.starts_with(p));
            let length_valid = key.len() >= self.config.min_api_key_length
                && key.len() <= self.config.max_api_key_length;

            let valid = prefix_valid && length_valid;
            let profile = IdentityProfile {
                identity_type: IdentityType::ApiKey,
                principal_id: format!("key:{}", hash_prefix(key)),
                credential_ref: key.to_string(),
                trust_base: self.trust_base(&IdentityType::ApiKey),
                claims: vec![],
                format_valid: valid,
            };
            return IdentityResult {
                reason: if valid {
                    format!("api key identity: {}", profile.principal_id)
                } else if !prefix_valid {
                    format!("api key prefix not recognized: {:?}", self.config.valid_api_key_prefixes)
                } else {
                    format!(
                        "api key length {} outside range [{}, {}]",
                        key.len(),
                        self.config.min_api_key_length,
                        self.config.max_api_key_length
                    )
                },
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                valid,
                profile,
            };
        }

        // Anonymous — no credentials.
        IdentityResult {
            profile: IdentityProfile::default(),
            reason: "anonymous — no credentials presented".into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            valid: true, // Anonymous is valid (but low trust).
        }
    }

    /// Extract basic claims from a JWT token (without verification).
    ///
    /// This is format-only parsing. CHAKRAVYUH does NOT verify JWT signatures.
    /// Signature verification is done by the upstream identity provider.
    fn extract_jwt_claims(&self, token: &str) -> Vec<String> {
        let mut claims = vec![];
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return claims;
        }

        // Decode the payload (second part).
        let payload = parts.get(1).unwrap();
        let decoded = match base64_decode_urlsafe(payload) {
            Some(d) => d,
            None => return claims,
        };

        // Parse as JSON and extract common claims.
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded) {
            if let Some(sub) = json.get("sub").and_then(|v| v.as_str()) {
                claims.push(format!("sub:{}", sub));
            }
            if let Some(iss) = json.get("iss").and_then(|v| v.as_str()) {
                claims.push(format!("iss:{}", iss));
            }
            if let Some(aud) = json.get("aud").and_then(|v| v.as_str()) {
                claims.push(format!("aud:{}", aud));
            }
            if let Some(scope) = json.get("scope").and_then(|v| v.as_str()) {
                for s in scope.split_whitespace() {
                    claims.push(format!("scope:{}", s));
                }
            }
            if let Some(roles) = json.get("roles").and_then(|v| v.as_array()) {
                for role in roles {
                    if let Some(r) = role.as_str() {
                        claims.push(format!("role:{}", r));
                    }
                }
            }
            if let Some(exp) = json.get("exp").and_then(|v| v.as_i64()) {
                let now = chrono::Utc::now().timestamp();
                if exp < now {
                    claims.push("expired:true".into());
                }
            }
        }

        claims
    }

    /// Get the base trust level for an identity type.
    fn trust_base(&self, identity_type: &IdentityType) -> f64 {
        self.config
            .trust_bases
            .get(&identity_type.to_string())
            .copied()
            .unwrap_or(0.1)
    }
}

/// Simple URL-safe base64 decode (no external dep).
fn base64_decode_urlsafe(input: &str) -> Option<String> {
    // Replace URL-safe characters.
    let s = input.replace('-', "+").replace('_', "/");
    // Add padding.
    let padding = match s.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    // Rust base64 crate can handle this, but we use a simple approach.
    // For JWT payload decoding, we only need the JSON part.
    use base64::Engine;
    let decoded = {
        // Use the base64 crate already in Cargo.toml.
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        match engine.decode(input) {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(_) => {
                // Try with standard engine as fallback.
                let engine = base64::engine::general_purpose::STANDARD;
                engine.decode(&format!("{}{}", s, padding))
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            }
        }
    };
    decoded
}

/// Compute a SHA-256 hash prefix for display/logging.
fn hash_prefix(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    // Return first 8 hex characters.
    hash[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn default_engine() -> SessionIdentity {
        SessionIdentity::new(&SessionIdentityConfig::default())
    }

    fn headers_from(pairs: Vec<(&str, &str)>) -> std::collections::HashMap<String, String> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn anonymous_no_credentials() {
        let engine = default_engine();
        let result = engine.evaluate(None, &std::collections::HashMap::new());
        assert_eq!(result.profile.identity_type, IdentityType::Anonymous);
        assert_eq!(result.profile.principal_id, "anonymous");
        assert!(result.valid);
    }

    #[test]
    fn api_key_recognized() {
        let engine = default_engine();
        let result = engine.evaluate(Some("sk-live-abcdefghij1234567890"), &std::collections::HashMap::new());
        assert_eq!(result.profile.identity_type, IdentityType::ApiKey);
        assert!(result.profile.principal_id.starts_with("key:"));
        assert!(result.valid);
    }

    #[test]
    fn api_key_short_rejected() {
        let engine = default_engine();
        let result = engine.evaluate(Some("sk-short"), &std::collections::HashMap::new());
        assert_eq!(result.profile.identity_type, IdentityType::ApiKey);
        assert!(!result.valid);
        assert!(result.reason.contains("length"));
    }

    #[test]
    fn api_key_bad_prefix_rejected() {
        let engine = SessionIdentity::new(&SessionIdentityConfig {
            valid_api_key_prefixes: vec!["sk-".into()],
            ..Default::default()
        });
        let result = engine.evaluate(Some("xx-some-long-key-12345678"), &std::collections::HashMap::new());
        assert!(!result.valid);
        assert!(result.reason.contains("prefix"));
    }

    #[test]
    fn jwt_detected() {
        let engine = default_engine();
        // A minimal valid-format JWT.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"user-42","iss":"auth.example.com"}"#);
        let signature = "signature";
        let jwt = format!("{}.{}.{}", header, payload, signature);

        let result = engine.evaluate(Some(&jwt), &std::collections::HashMap::new());
        assert_eq!(result.profile.identity_type, IdentityType::Jwt);
        assert_eq!(result.profile.principal_id, "user-42");
        assert!(result.profile.claims.iter().any(|c| c == "sub:user-42"));
        assert!(result.profile.claims.iter().any(|c| c == "iss:auth.example.com"));
        assert!(result.valid);
    }

    #[test]
    fn jwt_with_roles() {
        let engine = default_engine();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","roles":["admin","auditor"]}"#);
        let jwt = format!("{}.{}.{}", header, payload, "sig");

        let result = engine.evaluate(Some(&jwt), &std::collections::HashMap::new());
        assert!(result.profile.claims.iter().any(|c| c == "role:admin"));
        assert!(result.profile.claims.iter().any(|c| c == "role:auditor"));
    }

    #[test]
    fn session_token_detected() {
        let engine = default_engine();
        let headers = headers_from(vec![("x-session-token", "sess_abcdefghij12345678901234")]);
        let result = engine.evaluate(None, &headers);
        assert_eq!(result.profile.identity_type, IdentityType::Session);
        assert!(result.profile.principal_id.starts_with("session:"));
        assert!(result.valid);
    }

    #[test]
    fn session_token_short_rejected() {
        let engine = default_engine();
        let headers = headers_from(vec![("x-session-token", "short")]);
        let result = engine.evaluate(None, &headers);
        assert!(!result.valid);
    }

    #[test]
    fn internal_identity_highest_trust() {
        let engine = default_engine();
        let headers = headers_from(vec![("x-internal-identity", "keshav-core")]);
        let result = engine.evaluate(None, &headers);
        assert_eq!(result.profile.identity_type, IdentityType::Internal);
        assert_eq!(result.profile.trust_base, 1.0);
        assert!(result.valid);
    }

    #[test]
    fn internal_empty_rejected() {
        let engine = default_engine();
        let headers = headers_from(vec![("x-internal-identity", "")]);
        let result = engine.evaluate(None, &headers);
        assert!(!result.valid);
    }

    #[test]
    fn mtls_detected() {
        let engine = default_engine();
        let headers = headers_from(vec![("x-client-cert-fingerprint", "a1b2c3d4e5f6a1b2c3d4e5f6")]);
        let result = engine.evaluate(None, &headers);
        assert_eq!(result.profile.identity_type, IdentityType::Mtls);
        assert!(result.valid);
    }

    #[test]
    fn disabled_engine_allows_anonymous() {
        let engine = SessionIdentity::new(&SessionIdentityConfig { enabled: false, ..Default::default() });
        let result = engine.evaluate(Some("sk-test-1234567890123456"), &std::collections::HashMap::new());
        assert_eq!(result.profile.identity_type, IdentityType::Anonymous);
        assert!(result.valid);
    }

    #[test]
    fn trust_levels_configurable() {
        let engine = SessionIdentity::new(&SessionIdentityConfig {
            trust_bases: {
                let mut m = std::collections::HashMap::new();
                m.insert("api_key".into(), 0.9);
                m
            },
            ..Default::default()
        });
        let result = engine.evaluate(Some("sk-custom-high-trust-key"), &std::collections::HashMap::new());
        assert!((result.profile.trust_base - 0.9).abs() < 0.01);
    }

    #[test]
    fn expired_jwt_detected() {
        let engine = default_engine();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        // exp = 0 (Jan 1 1970 — always expired).
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"user","exp":0}"#);
        let jwt = format!("{}.{}.{}", header, payload, "sig");

        let result = engine.evaluate(Some(&jwt), &std::collections::HashMap::new());
        assert!(result.profile.claims.iter().any(|c| c == "expired:true"));
    }
}
