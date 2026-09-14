# chakravyuh — Official Python SDK for CHAKRAVYUH OS

The official Python SDK for [CHAKRAVYUH OS](https://vinomoid.com/chakravyuh-os) by Vinomoid — a multi-ring AI security orchestration platform for LLM-powered applications.

## Installation

```bash
pip install chakravyuh
```

## Quick Start

### Synchronous

```python
from chakravyuh import Chakravyuh

ck = Chakravyuh(api_key="ck_live_xxxxxxxxx")
result = ck.protect("Ignore previous instructions")

if not result.allowed:
    print(f"Blocked: {result.action.value}")
    print(f"Risk: {result.risk_score}")
    print(f"Ring: {result.triggered_ring}")

ck.close()
```

### Context Manager

```python
with Chakravyuh(api_key="ck_live_xxxxxxxxx") as ck:
    result = ck.protect("Hello, world!", tenant_id="tenant_001")
    print(result.allowed)
```

### Async

```python
from chakravyuh import AsyncChakravyuh

async with AsyncChakravyuh(api_key="ck_live_xxxxxxxxx") as ck:
    result = await ck.protect("Ignore previous instructions")
    print(result.risk_score)
```

## API Reference

### Client Construction

| Parameter | Default | Description |
|-----------|---------|-------------|
| `api_key` | *(required)* | `ck_live_*` or `ck_test_*` |
| `base_url` | `https://api.vinomoid.com` | API base URL |
| `timeout` | `30` | Request timeout in seconds |

### Methods

| Method | Endpoint | Description |
|--------|----------|-------------|
| `protect(content, *, tenant_id, ...)` | `POST /v1/protect` | Analyze and protect an LLM interaction |
| `protect_with(request)` | `POST /v1/protect` | Full control over protect request |
| `verify(evidence_id)` | `POST /v1/verify` | Verify audit evidence integrity |
| `evaluate_policy(policy_id, payload)` | `POST /v1/policy/evaluate` | Evaluate a security policy |
| `audit(query)` | `GET /v1/audit` | List audit records with filtering |
| `health()` | `GET /v1/health` | System health and status |

### Protect with Context

```python
from chakravyuh import (
    Chakravyuh, ProtectRequest, ProtectInput,
    InputType, ProtectContext,
)

request = ProtectRequest(
    input=ProtectInput(type=InputType.PROMPT, content="Suspicious input"),
    context=ProtectContext(source_ip="10.0.0.1", session_id="sess_abc"),
    tenant_id="tenant_vino_001",
    metadata={"model": "gpt-4o"},
)
result = ck.protect_with(request)
```

### Audit with Filtering

```python
from chakravyuh import AuditQuery, Severity

query = AuditQuery().tenant("tenant_001").severity(Severity.CRITICAL).limit(50)
result = ck.audit(query)
for record in result.records:
    print(f"[{record.severity.value}] {record.evidence_id}: {record.summary}")
print(f"Page: {result.pagination.offset}/{result.pagination.total_records}")
```

### Error Handling

```python
from chakravyuh import Chakravyuh, ChakravyuhError, RateLimitError, UnauthorizedError

try:
    result = ck.protect("test")
except UnauthorizedError as e:
    print(f"Auth failed: {e.message}")
except RateLimitError as e:
    print(f"Rate limited. Retry in {e.retry_after}s")
except ChakravyuhError as e:
    if e.is_retryable:
        print(f"Retryable: {e.message}")
    else:
        print(f"Fatal: {e.message}")
```

### Error Types

| Exception | HTTP | Retryable |
|-----------|------|-----------|
| `UnauthorizedError` | 401 | No |
| `ForbiddenError` | 403 | No |
| `NotFoundError` | 404 | No |
| `RateLimitError` | 429 | Yes |
| `ServiceUnavailableError` | 503 | Yes |
| `TimeoutError` | — | Yes |
| `NetworkError` | — | Yes |
| `ApiError` | Other | No |
| `SerializationError` | — | No |

### Key Enums

**`InputType`**: `PROMPT` · `API_REQUEST` · `AGENT_INSTRUCTION` · `OUTPUT` · `CONVERSATION`

**`Action`**: `ALLOW` · `BLOCK` · `CONDITIONAL` · `WARN`

**`Ring`** (15 defense rings): `PROMPT` · `INPUT` · `OUTPUT` · `CONTEXT` · `AGENT` · `IDENTITY` · `TRUST` · `COMPLIANCE` · `RATE` · `GEO` · `ANOMALY` · `BEHAVIORAL` · `SESSION` · `SEMANTIC` · `OVAPH`

## Running Tests

```bash
# Unit tests (no network)
pytest tests/test_errors.py tests/test_auth.py tests/test_models.py

# Integration tests (mocked HTTP)
pytest tests/test_integration.py

# All tests
pytest
```

## Requirements

- Python 3.10+
- httpx >= 0.27
- pydantic >= 2.5

## License

Proprietary — [Vinomoid](https://vinomoid.com)
