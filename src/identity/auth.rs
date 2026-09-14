// Phase 13.0 — Authentication service
//
// Argon2id password hashing + JWT (HS256) issue/verify + refresh tokens.
// This is the auth layer that sits on top of PlatformStore.
//
// Security properties:
//   - Passwords are hashed with Argon2id (memory-hard, OWASP recommended)
//   - JWTs are signed with HS256 using a server secret
//   - Refresh tokens are SHA-256 hashed at rest (never stored plaintext)
//   - Token comparison uses constant-time equality
//   - Access tokens expire in 15 minutes
//   - Refresh tokens expire in 7 days

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::platform::{hash_refresh_token, PlatformStore};

// ── JWT Claims ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: String,
    /// Issued at (unix timestamp).
    pub iat: u64,
    /// Expiration (unix timestamp).
    pub exp: u64,
    /// Issuer.
    pub iss: String,
    /// Email (for display).
    pub email: String,
    /// JWT ID — unique per token issuance. Ensures that two tokens
    /// issued for the same user within the same second are not
    /// byte-identical (which would break refresh-token rotation tests
    /// and let revoked tokens be replayed by accident).
    pub jti: String,
}

/// JWT configuration.
#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            // In production, this MUST be loaded from env var or secret manager.
            secret: "dev_secret_change_me_in_production".to_string(),
            issuer: "chakravyuh".to_string(),
            access_token_ttl_secs: 15 * 60,           // 15 minutes
            refresh_token_ttl_secs: 7 * 24 * 60 * 60, // 7 days
        }
    }
}

// ── Auth Service ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuthService {
    config: JwtConfig,
    store: PlatformStore,
}

/// Result of a successful login.
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64, // seconds until access_token expires
    pub user_id: Uuid,
    pub email: String,
}

/// Errors returned by AuthService.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user already exists")]
    UserExists,
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("user not found")]
    UserNotFound,
    #[error("password hashing error: {0}")]
    HashError(String),
    #[error("jwt error: {0}")]
    JwtError(String),
}

impl AuthService {
    pub fn new(config: JwtConfig, store: PlatformStore) -> Self {
        Self { config, store }
    }

    // ── Password Hashing (Argon2id) ──

    /// Hash a password using Argon2id with a random salt.
    pub fn hash_password(password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::HashError(e.to_string()))?;
        Ok(hash.to_string())
    }

    /// Verify a password against a stored Argon2id hash.
    /// Uses constant-time comparison internally.
    pub fn verify_password(password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    // ── Signup ──

    pub fn signup(
        &self,
        email: &str,
        password: &str,
        name: Option<&str>,
    ) -> Result<(TokenPair, crate::identity::platform::User), AuthError> {
        // Validate inputs.
        if email.trim().is_empty() || !email.contains('@') {
            return Err(AuthError::InvalidCredentials);
        }
        if password.len() < 8 {
            return Err(AuthError::InvalidCredentials);
        }

        // Check for existing user.
        if self.store.get_user_by_email(email).is_some() {
            return Err(AuthError::UserExists);
        }

        // Hash the password.
        let password_hash = Self::hash_password(password)?;

        // Create the user.
        let user = self.store.create_user(email, &password_hash, name);

        // Issue tokens.
        let tokens = self.issue_tokens(user.id, user.email.clone())?;

        Ok((tokens, user))
    }

    // ── Login ──

    pub fn login(&self, email: &str, password: &str) -> Result<TokenPair, AuthError> {
        let user = self
            .store
            .get_user_by_email(email)
            .ok_or(AuthError::InvalidCredentials)?;

        if !Self::verify_password(password, &user.password_hash) {
            return Err(AuthError::InvalidCredentials);
        }

        self.issue_tokens(user.id, user.email.clone())
    }

    // ── Token Issuance ──

    fn issue_tokens(&self, user_id: Uuid, email: String) -> Result<TokenPair, AuthError> {
        let now = Utc::now();
        let access_exp = now + Duration::seconds(self.config.access_token_ttl_secs);
        let refresh_exp = now + Duration::seconds(self.config.refresh_token_ttl_secs);

        // Build access token claims.
        let claims = Claims {
            sub: user_id.to_string(),
            iat: now.timestamp() as u64,
            exp: access_exp.timestamp() as u64,
            iss: self.config.issuer.clone(),
            email: email.clone(),
            jti: Uuid::new_v4().to_string(),
        };

        // Sign the JWT.
        let access_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.secret.as_bytes()),
        )
        .map_err(|e| AuthError::JwtError(e.to_string()))?;

        // Generate refresh token (random opaque string).
        let refresh_token = generate_refresh_token();
        let refresh_hash = hash_refresh_token(&refresh_token);

        // Store the refresh token.
        self.store
            .store_refresh_token(&refresh_hash, user_id, None, refresh_exp);

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_ttl_secs,
            user_id,
            email,
        })
    }

    // ── Token Verification ──

    pub fn verify_access_token(&self, token: &str) -> Result<Claims, AuthError> {
        let token = token.strip_prefix("Bearer ").unwrap_or(token);

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                AuthError::TokenExpired
            } else {
                AuthError::InvalidToken
            }
        })?;

        Ok(data.claims)
    }

    // ── Refresh ──

    pub fn refresh(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let hash = hash_refresh_token(refresh_token);

        let stored = self
            .store
            .verify_refresh_token(&hash)
            .ok_or(AuthError::InvalidToken)?;

        // Rotate: revoke the old refresh token.
        self.store.revoke_refresh_token(&hash);

        // Issue new tokens.
        let user = self
            .store
            .get_user_by_id(stored.user_id)
            .ok_or(AuthError::UserNotFound)?;

        self.issue_tokens(user.id, user.email)
    }

    // ── Logout ──

    pub fn logout(&self, refresh_token: Option<&str>) -> bool {
        if let Some(token) = refresh_token {
            let hash = hash_refresh_token(token);
            return self.store.revoke_refresh_token(&hash);
        }
        false
    }

    // ── Get current user from JWT ──

    pub fn get_user_from_token(
        &self,
        token: &str,
    ) -> Result<crate::identity::platform::User, AuthError> {
        let claims = self.verify_access_token(token)?;
        let user_id: Uuid = claims.sub.parse().map_err(|_| AuthError::InvalidToken)?;
        self.store
            .get_user_by_id(user_id)
            .ok_or(AuthError::UserNotFound)
    }
}

/// Generate a random 32-byte refresh token (base64-encoded).
fn generate_refresh_token() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> AuthService {
        AuthService::new(JwtConfig::default(), PlatformStore::new())
    }

    #[test]
    fn hash_and_verify_password() {
        let hash = AuthService::hash_password("my_password_123").unwrap();
        assert!(AuthService::verify_password("my_password_123", &hash));
        assert!(!AuthService::verify_password("wrong_password", &hash));
    }

    #[test]
    fn signup_creates_user_and_returns_tokens() {
        let svc = test_service();
        let (tokens, user) = svc
            .signup("alice@example.com", "password123", Some("Alice"))
            .unwrap();

        assert_eq!(user.email, "alice@example.com");
        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.expires_in, 15 * 60);
        assert_eq!(tokens.email, "alice@example.com");
    }

    #[test]
    fn signup_rejects_short_password() {
        let svc = test_service();
        let result = svc.signup("bob@example.com", "short", None);
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn signup_rejects_invalid_email() {
        let svc = test_service();
        let result = svc.signup("not-an-email", "password123", None);
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn signup_rejects_duplicate_email() {
        let svc = test_service();
        svc.signup("carol@example.com", "password123", None)
            .unwrap();
        let result = svc.signup("carol@example.com", "different_password", None);
        assert!(matches!(result, Err(AuthError::UserExists)));
    }

    #[test]
    fn login_returns_tokens() {
        let svc = test_service();
        svc.signup("dave@example.com", "password123", None).unwrap();

        let tokens = svc.login("dave@example.com", "password123").unwrap();
        assert!(!tokens.access_token.is_empty());
    }

    #[test]
    fn login_wrong_password_fails() {
        let svc = test_service();
        svc.signup("eve@example.com", "password123", None).unwrap();

        let result = svc.login("eve@example.com", "wrong_password");
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn login_nonexistent_user_fails() {
        let svc = test_service();
        let result = svc.login("ghost@example.com", "password123");
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn verify_access_token_decodes_claims() {
        let svc = test_service();
        let (tokens, _user) = svc
            .signup("frank@example.com", "password123", None)
            .unwrap();

        let claims = svc.verify_access_token(&tokens.access_token).unwrap();
        assert_eq!(claims.email, "frank@example.com");
        assert_eq!(claims.iss, "chakravyuh");
    }

    #[test]
    fn verify_access_token_rejects_garbage() {
        let svc = test_service();
        let result = svc.verify_access_token("not.a.jwt");
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn refresh_rotates_tokens() {
        let svc = test_service();
        let (tokens, _user) = svc
            .signup("grace@example.com", "password123", None)
            .unwrap();

        // Refresh should work.
        let new_tokens = svc.refresh(&tokens.refresh_token).unwrap();
        assert_ne!(tokens.access_token, new_tokens.access_token);
        assert_ne!(tokens.refresh_token, new_tokens.refresh_token);

        // Old refresh token should be revoked.
        let result = svc.refresh(&tokens.refresh_token);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn logout_revokes_refresh_token() {
        let svc = test_service();
        let (tokens, _user) = svc
            .signup("heidi@example.com", "password123", None)
            .unwrap();

        assert!(svc.logout(Some(&tokens.refresh_token)));

        // Token can no longer be used for refresh.
        let result = svc.refresh(&tokens.refresh_token);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn get_user_from_token_returns_user() {
        let svc = test_service();
        let (tokens, user) = svc.signup("ivan@example.com", "password123", None).unwrap();

        let fetched = svc.get_user_from_token(&tokens.access_token).unwrap();
        assert_eq!(fetched.id, user.id);
        assert_eq!(fetched.email, user.email);
    }
}
