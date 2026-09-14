// Phase 14.0 — OpenAPI 3.1 Specification + Swagger UI
//
// Serves:
//   GET /openapi.json  — full OpenAPI 3.1 spec covering all endpoints
//   GET /docs          — interactive Swagger UI (try-it-out enabled)
//   GET /docs/oauth2-redirect.html  — placeholder for OAuth flow
//
// The spec is generated from a static YAML string (kept in sync with
// specs/openapi.yaml on disk) and served as JSON for runtime consumption.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Response},
};
use serde_json::{json, Value};

/// GET /openapi.json — returns the complete OpenAPI 3.1 spec.
pub async fn openapi_spec() -> Json<Value> {
    Json(openapi_json())
}

/// GET /docs — interactive Swagger UI.
///
/// Uses the swagger-ui-bundle from cdn.jsdelivr.net, configured for
/// Bearer auth and try-it-out enabled. No npm install required — just
/// a single HTML page that loads Swagger UI from CDN.
pub async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

/// GET /docs/oauth2-redirect.html — placeholder required by Swagger UI.
pub async fn oauth2_redirect() -> Html<&'static str> {
    Html(OAUTH2_REDIRECT_HTML)
}

/// The full OpenAPI 3.1 spec as a JSON Value.
///
/// This is built programmatically so we don't need to ship a separate
/// YAML parser at runtime. Keeping it as a function means the spec is
/// always in sync with the code that generates it.
pub fn openapi_json() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "CHAKRAVYUH Security Operating System",
            "description": "Open-source security operating system for autonomous AI. Multi-ring AI security orchestration platform that provides real-time prompt analysis, policy evaluation, audit verification, and threat intelligence for LLM-powered applications.\n\n## Authentication\n\nAll protected endpoints require either a JWT (for user-auth flows like signup/login) or an API key (`ck_live_*` / `ck_test_*`) for service-to-service calls.\n\n```http\nAuthorization: Bearer ck_live_xxxxxxxxx\n```\n\n## Rate Limiting\n\nRate limits are enforced per API key, based on the organization's plan:\n- Free: 100 RPM\n- Pro: 1000 RPM\n- Enterprise: Unlimited\n\n## Idempotency\n\nState-mutating endpoints support an `Idempotency-Key` header for safe retries.\n\n## Errors\n\nAll errors follow the standard format:\n```json\n{\n  \"error\": {\n    \"code\": \"invalid_api_key\",\n    \"message\": \"API key is invalid\",\n    \"request_id\": \"req_xxx\"\n  }\n}\n```",
            "version": "1.0.0",
            "contact": {
                "name": "VINOMOID",
                "url": "https://vinomoid.com",
                "email": "api@vinomoid.com"
            },
            "license": {
                "name": "Apache-2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0"
            }
        },
        "servers": [
            {"url": "http://localhost:8443", "description": "Local development"},
            {"url": "https://api.chakravyuh.org", "description": "Production"}
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Use a JWT (for user auth) or a ck_live_*/ck_test_* API key"
                }
            },
            "schemas": {
                "ErrorBody": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"type": "string", "example": "invalid_api_key"},
                                "message": {"type": "string", "example": "API key is invalid"},
                                "request_id": {"type": "string", "example": "req_abc123"}
                            }
                        }
                    }
                },
                "SignupRequest": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": {"type": "string", "format": "email", "example": "alice@example.com"},
                        "password": {"type": "string", "minLength": 8, "example": "password123"},
                        "name": {"type": "string", "example": "Alice"}
                    }
                },
                "TokenResponse": {
                    "type": "object",
                    "properties": {
                        "access_token": {"type": "string", "example": "eyJhbGciOiJIUzI1NiIs..."},
                        "refresh_token": {"type": "string", "example": "abc123..."},
                        "expires_in": {"type": "integer", "example": 900},
                        "user": {"$ref": "#/components/schemas/UserPublic"}
                    }
                },
                "UserPublic": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "email": {"type": "string"},
                        "name": {"type": "string", "nullable": true}
                    }
                },
                "CreateOrgRequest": {
                    "type": "object",
                    "required": ["name", "slug"],
                    "properties": {
                        "name": {"type": "string", "example": "Acme Inc"},
                        "slug": {"type": "string", "example": "acme"},
                        "plan": {"type": "string", "enum": ["free", "pro", "enterprise"], "default": "free"}
                    }
                },
                "CreateApiKeyRequest": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "example": "Production key"},
                        "workspace_id": {"type": "string", "format": "uuid", "nullable": true},
                        "is_live": {"type": "boolean", "default": true}
                    }
                },
                "CreateApiKeyResponse": {
                    "type": "object",
                    "properties": {
                        "api_key": {"type": "string", "example": "ck_live_4H8Jabcd1234567890"},
                        "id": {"type": "string", "format": "uuid"},
                        "name": {"type": "string"},
                        "is_live": {"type": "boolean"},
                        "key_prefix": {"type": "string", "example": "ck_live_4H8J****"}
                    }
                },
                "ProtectRequest": {
                    "type": "object",
                    "required": ["input"],
                    "properties": {
                        "input": {"type": "string", "example": "What is the capital of France?"},
                        "tenant_id": {"type": "string", "default": "default"},
                        "request_id": {"type": "string", "nullable": true}
                    }
                },
                "ProtectResponse": {
                    "type": "object",
                    "properties": {
                        "allowed": {"type": "boolean"},
                        "action": {"type": "string", "enum": ["allow", "block", "challenge", "escalate"]},
                        "risk_score": {"type": "number", "minimum": 0, "maximum": 1},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "triggered_ring": {"type": "string", "nullable": true},
                        "policy_id": {"type": "string"},
                        "evidence_id": {"type": "string"},
                        "latency_ms": {"type": "number"},
                        "request_id": {"type": "string"},
                        "ring_scores": {"type": "object"},
                        "details": {"$ref": "#/components/schemas/ProtectDetails"}
                    }
                },
                "ProtectDetails": {
                    "type": "object",
                    "properties": {
                        "reason": {"type": "string", "example": "WAF_PROMPT_INJECTION_IGNORE"},
                        "patterns": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string"}
                    }
                }
            }
        },
        "security": [{"bearerAuth": []}],
        "tags": [
            {"name": "Auth", "description": "User signup, login, token refresh"},
            {"name": "Organizations", "description": "Organization and workspace management"},
            {"name": "API Keys", "description": "Generate and revoke API keys"},
            {"name": "Protect", "description": "Primary prompt protection endpoint"},
            {"name": "Audit", "description": "Immutable audit trail"},
            {"name": "Developer", "description": "OpenAPI spec, docs, snippets, Postman"}
        ],
        "paths": {
            "/v1/auth/signup": {
                "post": {
                    "tags": ["Auth"],
                    "summary": "Sign up a new user",
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SignupRequest"}}}
                    },
                    "responses": {
                        "201": {"description": "User created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TokenResponse"}}}},
                        "400": {"description": "Invalid input", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}},
                        "409": {"description": "Email already exists", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}
                    }
                }
            },
            "/v1/auth/login": {
                "post": {
                    "tags": ["Auth"],
                    "summary": "Login with email + password",
                    "security": [],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["email", "password"], "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}},
                    "responses": {
                        "200": {"description": "Login successful", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TokenResponse"}}}},
                        "401": {"description": "Invalid credentials", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}
                    }
                }
            },
            "/v1/auth/me": {
                "get": {
                    "tags": ["Auth"],
                    "summary": "Get current user",
                    "responses": {
                        "200": {"description": "Current user", "content": {"application/json": {"schema": {"type": "object", "properties": {"user": {"$ref": "#/components/schemas/UserPublic"}, "organizations": {"type": "array"}}}}}},
                        "401": {"description": "Unauthorized", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}
                    }
                }
            },
            "/v1/orgs": {
                "post": {
                    "tags": ["Organizations"],
                    "summary": "Create organization",
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateOrgRequest"}}}},
                    "responses": {
                        "201": {"description": "Organization created"},
                        "409": {"description": "Slug already taken"}
                    }
                },
                "get": {
                    "tags": ["Organizations"],
                    "summary": "List your organizations",
                    "responses": {"200": {"description": "List of organizations"}}
                }
            },
            "/v1/orgs/{org_id}/keys": {
                "post": {
                    "tags": ["API Keys"],
                    "summary": "Generate API key (returns plaintext ONCE)",
                    "parameters": [{"name": "org_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateApiKeyRequest"}}}},
                    "responses": {
                        "201": {"description": "API key created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateApiKeyResponse"}}}},
                        "403": {"description": "Access denied to organization"}
                    }
                },
                "get": {
                    "tags": ["API Keys"],
                    "summary": "List API keys (no plaintext returned)",
                    "parameters": [{"name": "org_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}],
                    "responses": {"200": {"description": "List of API keys"}}
                }
            },
            "/v1/orgs/{org_id}/keys/{key_id}": {
                "delete": {
                    "tags": ["API Keys"],
                    "summary": "Revoke an API key",
                    "parameters": [
                        {"name": "org_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}},
                        {"name": "key_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}
                    ],
                    "responses": {
                        "200": {"description": "API key revoked"},
                        "404": {"description": "Key not found"}
                    }
                }
            },
            "/v1/protect": {
                "post": {
                    "tags": ["Protect"],
                    "summary": "Protect an LLM interaction (primary endpoint)",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProtectRequest"}}}},
                    "responses": {
                        "200": {"description": "Allowed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProtectResponse"}}}},
                        "403": {"description": "Blocked", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProtectResponse"}}}},
                        "401": {"description": "Invalid API key", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}},
                        "400": {"description": "Invalid input", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}
                    }
                }
            },
            "/v1/orgs/{org_id}/audit": {
                "get": {
                    "tags": ["Audit"],
                    "summary": "List audit logs (tenant-isolated)",
                    "parameters": [
                        {"name": "org_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                    ],
                    "responses": {"200": {"description": "Audit log entries"}}
                }
            },
            "/v1/health": {
                "get": {
                    "tags": ["Developer"],
                    "summary": "System health",
                    "security": [],
                    "responses": {"200": {"description": "System is operational"}}
                }
            },
            "/openapi.json": {
                "get": {
                    "tags": ["Developer"],
                    "summary": "OpenAPI 3.1 specification",
                    "security": [],
                    "responses": {"200": {"description": "OpenAPI spec"}}
                }
            },
            "/docs": {
                "get": {
                    "tags": ["Developer"],
                    "summary": "Interactive Swagger UI",
                    "security": [],
                    "responses": {"200": {"description": "HTML"}}
                }
            },
            "/postman.json": {
                "get": {
                    "tags": ["Developer"],
                    "summary": "Postman collection",
                    "security": [],
                    "responses": {"200": {"description": "Postman collection JSON"}}
                }
            },
            "/snippets": {
                "get": {
                    "tags": ["Developer"],
                    "summary": "cURL / Python / TypeScript / Go snippets per endpoint",
                    "security": [],
                    "responses": {"200": {"description": "Snippets for every endpoint"}}
                }
            }
        }
    })
}

/// Swagger UI HTML — loads from CDN, configured for Bearer auth + try-it-out.
const SWAGGER_UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CHAKRAVYUH API Docs</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
    <style>
        body { margin: 0; }
        .topbar { background: #1a1a2e; padding: 12px 24px; color: white; font-family: -apple-system, sans-serif; }
        .topbar h1 { margin: 0; font-size: 18px; font-weight: 500; }
        .topbar .version { opacity: 0.6; font-size: 12px; margin-left: 8px; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>CHAKRAVYUH Security OS <span class="version">v1.0.0</span></h1>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = () => {
            window.ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
                plugins: [SwaggerUIBundle.plugins.DownloadUrl],
                layout: 'BaseLayout',
                docExpansion: 'none',
                tryItOutEnabled: true,
                requestSnippetsEnabled: true,
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                persistAuthorization: true,
                requestSnippets: {
                    generators: {
                        curl_bash: { title: "cURL (bash)", syntax: "bash" },
                        python: { title: "Python (requests)", syntax: "python" },
                        node_fetch: { title: "Node.js (fetch)", syntax: "javascript" },
                        go: { title: "Go (net/http)", syntax: "go" }
                    },
                    defaultExpanded: true,
                    defaultLang: "curl_bash"
                }
            });
        };
    </script>
</body>
</html>"#;

const OAUTH2_REDIRECT_HTML: &str = r#"<!DOCTYPE html>
<html><body><h1>OAuth2 Redirect</h1><p>CHAKRAVYUH uses Bearer tokens, not OAuth2. This page is a placeholder required by Swagger UI.</p></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn openapi_spec_returns_valid_json() {
        let json = openapi_json();
        assert_eq!(json["openapi"], "3.1.0");
        assert!(json["paths"].is_object());
        assert!(json["paths"]
            .as_object()
            .unwrap()
            .contains_key("/v1/protect"));
        assert!(json["paths"]
            .as_object()
            .unwrap()
            .contains_key("/v1/auth/signup"));
        assert!(json["paths"].as_object().unwrap().contains_key("/v1/orgs"));
    }

    #[tokio::test]
    async fn swagger_ui_returns_html() {
        let html = swagger_ui().await;
        assert!(html.0.contains("swagger-ui"));
        assert!(html.0.contains("/openapi.json"));
    }

    #[test]
    fn openapi_spec_includes_all_endpoints() {
        let json = openapi_json();
        let paths = json["paths"].as_object().unwrap();
        // Auth
        assert!(paths.contains_key("/v1/auth/signup"));
        assert!(paths.contains_key("/v1/auth/login"));
        assert!(paths.contains_key("/v1/auth/me"));
        // Orgs
        assert!(paths.contains_key("/v1/orgs"));
        assert!(paths.contains_key("/v1/orgs/{org_id}/keys"));
        assert!(paths.contains_key("/v1/orgs/{org_id}/keys/{key_id}"));
        assert!(paths.contains_key("/v1/orgs/{org_id}/audit"));
        // Protect
        assert!(paths.contains_key("/v1/protect"));
        // Developer
        assert!(paths.contains_key("/openapi.json"));
        assert!(paths.contains_key("/docs"));
        assert!(paths.contains_key("/postman.json"));
        assert!(paths.contains_key("/snippets"));
    }

    #[test]
    fn openapi_has_security_scheme() {
        let json = openapi_json();
        assert!(json["components"]["securitySchemes"]["bearerAuth"].is_object());
    }
}
