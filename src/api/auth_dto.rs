// Phase 13.0 — Authentication DTOs
//
// Wire-format types for the auth endpoints:
//   POST /v1/auth/signup
//   POST /v1/auth/login
//   POST /v1/auth/refresh
//   POST /v1/auth/logout
//   GET  /v1/auth/me

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── POST /v1/auth/signup ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

impl SignupRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.email.trim().is_empty() || !self.email.contains('@') {
            return Err("email must be a valid email address".into());
        }
        if self.password.len() < 8 {
            return Err("password must be at least 8 characters".into());
        }
        Ok(())
    }
}

// ── POST /v1/auth/login ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// ── POST /v1/auth/refresh ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ── POST /v1/auth/logout ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct LogoutRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

// ── Shared response types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserPublic,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
}

impl From<crate::identity::platform::User> for UserPublic {
    fn from(u: crate::identity::platform::User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            name: u.name,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LogoutResponse {
    pub logged_out: bool,
}

// ── GET /v1/auth/me ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MeResponse {
    pub user: UserPublic,
    pub organizations: Vec<OrgSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgSummary {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub role: String,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_validates_email() {
        let req = SignupRequest {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
            name: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn signup_validates_short_password() {
        let req = SignupRequest {
            email: "alice@example.com".to_string(),
            password: "short".to_string(),
            name: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn signup_accepts_valid_input() {
        let req = SignupRequest {
            email: "alice@example.com".to_string(),
            password: "password123".to_string(),
            name: Some("Alice".to_string()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn signup_deserializes_without_name() {
        let json = r#"{"email":"bob@example.com","password":"password123"}"#;
        let req: SignupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "bob@example.com");
        assert!(req.name.is_none());
    }
}
