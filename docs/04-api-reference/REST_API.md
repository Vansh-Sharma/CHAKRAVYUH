# CHAKRAVYUH REST API Reference

> **Base URL**: `http://localhost:8443` (configurable via `server.bind`)
> **Content-Type**: `application/json` for all request/response bodies
> **Source IP**: `X-Real-IP` > first `X-Forwarded-For` > `0.0.0.0` fallback

---

## Health & Diagnostics

### GET /health

Basic liveness check returning uptime and version. No authentication required.

```bash
curl -s http://localhost:8443/health | jq .
```

```json
{"status": "ok", "uptime_secs": 3642, "version": "1.0.0"}
```

Does **not** check ring health — use `/health/ready` for that.

---

### GET /health/ready

Kubernetes readiness probe. Returns `200` only when all rings are healthy and error rates are below thresholds. Returns `503` when not ready.

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/health/ready
```

---

### GET /health/live

Kubernetes liveness probe. Returns `200` if the process is alive.

---

### GET /version

Returns version, build profile, and license.

```bash
curl -s http://localhost:8443/version | jq .
```

```json
{"version": "1.0.0", "build": "release", "license": "Apache-2.0", "repo": "https://github.com/vinomoid/chakravyuh"}
```

---

### GET /metrics

Prometheus-format metrics. Per-ring counters, latency histograms, decision counts. Not authenticated by default — protect with network policy.

---

## Core Evaluation Pipeline

### POST /v1/evaluate

Evaluate a chat completion request through: **Shield → Threat → Identity → Memory → Keshav**.

**Request** (OpenAI-compatible; extra fields passed through unchanged)

```json
{
  "model": "gpt-4",
  "messages": [{"role": "user", "content": "What is the capital of France?"}]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | `string` | No* | LLM model identifier |
| `messages` | `array` | No* | Chat messages |

> *Missing fields are caught by Shield `input_validator` with a `MISSING_REQUIRED_FIELD` verdict rather than a generic 400.

**Response** `200` (allow) or `403` (deny/challenge/escalate)

```json
{
  "decision": {"type": "allow"},
  "risk_score": {
    "overall": 0.02, "threat": 0.0, "identity": 0.0, "behavior": 0.0,
    "memory": 0.0, "execution": 0.0, "context": 0.0, "confidence": 0.95
  },
  "ring_results": {
    "shield": {"decision": "allow", "latency_ms": 0.12},
    "threat": {"decision": "allow", "composite_score": 0.01, "latency_ms": 0.45},
    "identity": {"decision": "allow", "identity_risk_score": 0.0, "latency_ms": 0.08},
    "memory": {"decision": "allow", "memory_risk_score": 0.0, "latency_ms": 0.03}
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "latency_ms": 0.68
}
```

**Decision types**: `allow` (200) | `deny` with `code` + `retry_after` (403) | `challenge` with `challenge_type` (403) | `escalate` with `approver_role` + `timeout_secs` (403)

**Errors**: 403 — ring denial | 429 — rate limit exceeded

```bash
curl -s -X POST http://localhost:8443/v1/evaluate \
  -H "Content-Type: application/json" -H "X-Real-IP: 203.0.113.50" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}' | jq .
```

**Security Notes**: When `api_keys.require_for_v1` is `true`, HMAC-SHA256 authentication is enforced.

---

### POST /v1/proxy

Evaluate and forward to upstream LLM API. Pipeline: **Shield → Threat → Identity → Memory → Reasoning → Governance → Keshav**. Requires `upstream` config section.

**Request**: Same as `/v1/evaluate` (any JSON body forwarded as-is).

**On deny (403)**: Same decision JSON as `/v1/evaluate`.

**On allow**: Upstream response body with injected response headers:

| Header | Description |
|--------|-------------|
| `x-chakravyuh-decision` | Final pipeline verdict |
| `x-chakravyuh-shield-latency-ms` | Shield processing time |
| `x-chakravyuh-upstream-latency-ms` | Upstream response time |
| `x-chakravyuh-risk-score` | Composite risk score |
| `x-chakravyuh-request-id` | Unique request UUID |

**Errors**: 403 — pipeline denial | 502 — upstream failed

```bash
curl -s -X POST http://localhost:8443/v1/proxy \
  -H "Content-Type: application/json" -H "X-Real-IP: 10.0.0.1" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Explain quantum computing"}]}' -D -
```

**Security Notes**: When `forward_client_auth` is `false` (default), CHAKRAVYUH replaces the `Authorization` header with `upstream.api_key`. Client keys never reach upstream. Override key via `CHAKRAVYUH_UPSTREAM_API_KEY` env var.

---

### POST /v1/execute

Evaluate a tool call: **Shield → Threat → Identity → Memory → Agent → Execution → Keshav**.

```json
{"tool_name": "web_search", "parameters": {"query": "security vulns"}, "agent_id": "agent-001"}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_name` | `string` | Yes | Tool being called |
| `parameters` | `object` | No | Call parameters (default `{}`) |
| `agent_id` | `string` | No | Calling agent identifier |
| `request_id` | `string` | No | Custom ID (UUID generated if omitted) |

**Response**: Same shape as `/v1/evaluate` with additional `agent` and `execution` in `ring_results`. HTTP 200 only if shield, agent, and execution all allow.

```bash
curl -s -X POST http://localhost:8443/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"file_read","parameters":{"path":"/data/report.txt"}}' | jq .
```

**Security Notes**: Triggers Agent Ring (policy, scope, capability) and Execution Ring (allowlist, sandbox, SSRF, approval). Non-allowlisted tools are denied.

---

## Decision Audit

### GET /v1/decisions

List recent decision records (newest first).

**Query**: `?limit=100&offset=0&decision=deny`

```bash
curl -s "http://localhost:8443/v1/decisions?limit=10&decision=deny" | jq .
```

```json
{"count": 42, "decisions": [{"request_id": "...", "final_decision": {"type": "allow"}, "risk_score": {"overall": 0.01}}]}
```

---

### GET /v1/decisions/export

Export all decisions. **Query**: `?format=json` (default) or `?format=csv`

```bash
curl -s http://localhost:8443/v1/decisions/export?format=csv -o decisions.csv
```

CSV returns `Content-Disposition: attachment; filename="chakravyuh_decisions.csv"`.

---

## Learning System

### GET /v1/learn/status

Learning subsystem status: feedback stats, pattern counts, anomaly profiler state.

```bash
curl -s http://localhost:8443/v1/learn/status | jq .
```

```json
{
  "enabled": true,
  "feedback": {"total": 150, "false_positives": 12, "false_negatives": 3, "approved": 130, "rejected": 5},
  "unprocessed_feedback": 0, "auto_optimize_pending": false,
  "profiles_count": 5, "patterns_count": 340, "thresholds_count": 8
}
```

---

### POST /v1/learn/optimize

Trigger manual threshold optimization from collected feedback.

```bash
curl -s -X POST http://localhost:8443/v1/learn/optimize | jq .
```

```json
{"status": "optimization_started", "feedback_analyzed": 150, "thresholds_adjusted": 3}
```

---

### POST /v1/learn/feedback

Submit decision feedback. **Valid `feedback` values**: `false_positive`, `false_negative`, `approve`, `reject`, `escalation_approved`, `escalation_denied`.

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "feedback": "false_positive",
  "ring": "threat",
  "original_decision": "deny",
  "explanation": "Legitimate security research prompt",
  "submitted_by": "admin"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | `string` | Yes | Request ID of the decision |
| `feedback` | `string` | Yes | Feedback type (see above) |
| `ring` | `string` | No | Ring that made the decision |
| `original_decision` | `string` | Yes | Original decision type |
| `explanation` | `string` | Yes | Human-readable reason |
| `submitted_by` | `string` | Yes | Submitter identifier |
| `severity` | `string` | No | Severity classification |

**Errors**: 400 — invalid `feedback` type | 404 — `request_id` not found

```bash
curl -s -X POST http://localhost:8443/v1/learn/feedback \
  -H "Content-Type: application/json" \
  -d '{"request_id":"550e8400","feedback":"false_positive","original_decision":"deny","explanation":"Benign prompt","submitted_by":"sec-team"}' | jq .
```

---

### GET /v1/learn/thresholds

View current learned threshold values.

```json
{"thresholds": {"threat.deny_threshold": 0.60, "threat.challenge_threshold": 0.30, "identity.anomaly.challenge_threshold": 6.0}}
```

---

### POST /v1/learn/thresholds/reset

Reset all learned thresholds to configured defaults.

```json
{"status": "thresholds_reset", "reset_count": 4}
```

---

### GET /v1/learn/patterns

Pattern store statistics with category breakdown.

```json
{"total_patterns": 340, "categories": {"prompt_injection": 85, "jailbreak": 62, "sqli": 48}}
```

---

### GET /v1/learn/patterns/export

Export full pattern store as JSON array.

---

### POST /v1/learn/patterns/import

Import patterns from a JSON array body.

```bash
curl -s -X POST http://localhost:8443/v1/learn/patterns/import -H "Content-Type: application/json" -d @patterns.json | jq .
```

---

## Policy Management

### GET /v1/policy/info

Current policy version, rule count, compilation status.

```json
{"version": "2025-01-15T10:00:00Z", "rules_count": 42, "compiled": true}
```

---

### GET /v1/policy/export

Export active policy as YAML (`application/yaml`).

```bash
curl -s http://localhost:8443/v1/policy/export > policy.yaml
```

---

### POST /v1/policy/reload

Hot-reload policy from disk without restart.

```json
{"status": "reloaded", "previous_version": "...", "new_version": "..."}
```

---

## Infrastructure

### GET /v1/recovery

Ring health, circuit breaker state, degraded/lockdown status, recent recovery events.

```bash
curl -s http://localhost:8443/v1/recovery | jq .
```

```json
{
  "degraded": false, "lockdown": false, "action": "Normal", "rings_down": 0,
  "rings": [{"name": "shield", "state": "Closed", "healthy": true, "slow": false,
    "total_requests": 15000, "total_failures": 12, "error_rate": "0.001", "avg_latency_ms": "0.15"}],
  "recent_recovery_events": [{"event_type": "circuit_opened", "ring": "threat",
    "from": "Closed", "to": "Open", "reason": "error_rate_exceeded", "action": "degraded_mode"}]
}
```

---

### GET /v1/storage/health

Storage backend health (memory or Redis).

```json
{"backend": "redis", "healthy": true, "latency_ms": 1.2, "connected": true}
```

---

## ANANTA Trust Plane (Optional)

Available only when `ananta_config_path` is set.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/ananta/trust` | GET | Trust state and scores |
| `/v1/ananta/attestation` | GET | Attestation report |
| `/v1/ananta/proof` | GET | Trust proof data |
| `/v1/ananta/health` | GET | ANANTA subsystem health |

---

## Error Response Format

All errors use a consistent shape: `{"error": "type", "detail": "context"}`

| Code | Meaning |
|------|----------|
| 200 | Success |
| 400 | Malformed request body |
| 403 | Denied by security pipeline |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
| 502 | Upstream forwarding failed |
| 503 | Service not ready |
