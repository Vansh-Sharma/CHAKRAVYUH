# Python SDK — CHAKRAVYUH OS v1.0.0

> **Status: Planned (not yet implemented).**
> This document describes an interim HTTP-based workaround using the standard
> `requests` library against the REST API exposed by the Rust binary.
> Source: [`src/lib.rs`](../../src/lib.rs) · License: Apache-2.0

## Purpose

A native `chakravyuh` Python package is on the roadmap. Until it ships, Python
services interact with CHAKRAVYUH by calling the HTTP API that `cv.serve()`
exposes. The examples below cover the most common operations.

---

## Prerequisites

```bash
pip install requests
```

Start the CHAKRAVYUH daemon (see [Rust SDK](./RUST_SDK.md) for setup):

```bash
chakravyuh serve --addr 0.0.0.0:9090
```

---

## Evaluate a Request

```python
import requests

BASE = "http://127.0.0.1:9090"

resp = requests.post(
    f"{BASE}/v1/evaluate",
    json={
        "request": {
            "method": "POST",
            "path": "/api/transfer",
            "headers": {"authorization": "Bearer <token>"},
            "source_ip": "10.0.1.5",
        }
    },
    headers={"X-API-Key": "<your-api-key>"},
)
resp.raise_for_status()
data = resp.json()

print("Decision:", data["decision"])
print("Risk:", data["risk_score"]["overall"])
```

## Proxy a Request

The `/v1/proxy` endpoint evaluates the request and, if the decision is `Allow`,
forwards it to the configured upstream automatically:

```python
resp = requests.post(
    f"{BASE}/v1/proxy",
    json={
        "method": "GET",
        "path": "/api/data",
        "headers": {"authorization": "Bearer <token>"},
        "body": "",
        "source_ip": "10.0.1.5",
    },
    headers={"X-API-Key": "<your-api-key>"},
)
print(resp.status_code, resp.text)
```

## Export Decisions

```python
resp = requests.get(
    f"{BASE}/v1/decisions/export",
    params={"format": "json", "limit": 100},
    headers={"X-API-Key": "<your-api-key>"},
)
records = resp.json()
for r in records:
    print(r["decision"], r["risk_score"]["overall"])
```

## Error Handling (Interim Pattern)

```python
try:
    resp.raise_for_status()
except requests.exceptions.HTTPError as e:
    if e.response is not None and e.response.status_code == 429:
        retry = e.response.headers.get("Retry-After")
        print(f"Rate-limited; retry after {retry}s")
    else:
        raise
except requests.exceptions.ConnectionError:
    print("CHAKRAVYUH daemon is unreachable")
```

---

## Planned SDK Shape

When implemented, the Python SDK is expected to expose:

- A synchronous `ChakravyuhClient(base_url, api_key)` class.
- An async `AsyncChakravyuhClient` variant using `httpx`.
- Typed dataclasses mirroring `Decision`, `RiskScore`, and `DecisionRecord`.
- Helpers for interpreting `Decision` variants (`Allow`, `Deny`, `Challenge`, `Escalate`)
  and their associated payloads (`code`, `retry_after`, `challenge_type`,
  `approver_role`, `timeout_secs`).

---

## Cross-References

- [Rust SDK](./RUST_SDK.md) — native library with all accessor methods
- [API Reference](../04-api/README.md) — full HTTP route specification
- [GitHub Repository](https://github.com/vinomoid/chakravyuh)