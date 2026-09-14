# TypeScript SDK — CHAKRAVYUH OS v1.0.0

> **Status: Planned (not yet implemented).**
> This document describes an interim HTTP-based workaround using the native
> `fetch` API against the REST API exposed by the Rust binary.
> Source: [`src/lib.rs`](../../src/lib.rs) · License: Apache-2.0

## Purpose

A native `@vinomoid/chakravyuh` npm package is planned. Until it ships,
TypeScript and JavaScript services interact with CHAKRAVYUH by calling the
HTTP API directly. The examples below use `fetch` and work in Node 18+,
Deno, Cloudflare Workers, and all modern browsers.

---

## Prerequisites

Start the CHAKRAVYUH daemon (see [Rust SDK](./RUST_SDK.md) for setup):

```bash
chakravyuh serve --addr 0.0.0.0:9090
```

---

## Evaluate a Request

```typescript
const BASE = "http://127.0.0.1:9090";

interface EvaluateResponse {
  decision: "Allow" | "Deny" | "Challenge" | "Escalate";
  risk_score: { overall: number; threat: number; identity: number };
}

async function evaluate(path: string, method = "GET") {
  const res = await fetch(`${BASE}/v1/evaluate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": "<your-api-key>",
    },
    body: JSON.stringify({
      request: {
        method,
        path,
        headers: { authorization: "Bearer <token>" },
        source_ip: "10.0.2.10",
      },
    }),
  });

  if (!res.ok) throw new Error(`evaluate failed: ${res.status}`);
  return (await res.json()) as EvaluateResponse;
}

const result = await evaluate("/api/users");
console.log("Decision:", result.decision);
console.log("Risk:", result.risk_score.overall);
```

## Proxy a Request

The `/v1/proxy` endpoint evaluates the request and, on `Allow`, forwards it
to the configured upstream:

```typescript
async function proxy(path: string) {
  const res = await fetch(`${BASE}/v1/proxy`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": "<your-api-key>",
    },
    body: JSON.stringify({
      method: "GET",
      path,
      headers: { authorization: "Bearer <token>" },
      body: "",
      source_ip: "10.0.2.10",
    }),
  });

  console.log(res.status, await res.text());
}

await proxy("/api/data");
```

## Error Handling (Interim Pattern)

```typescript
async function safeEvaluate(path: string) {
  try {
    return await evaluate(path);
  } catch (err) {
    if (err instanceof TypeError) {
      console.error("CHAKRAVYUH daemon is unreachable");
    }
    throw err;
  }
}
```

---

## Planned SDK Shape

When implemented, the TypeScript SDK is expected to provide:

- A `ChakravyuhClient` class with `evaluate()`, `proxy()`, and `health()` methods.
- Full TypeScript types for `Decision`, `RiskScore`, and `DecisionRecord` exported
  from the package, including discriminated unions matching the Rust enum variants
  (`Deny` with `code`/`retry_after`, `Challenge` with `challenge_type`, `Escalate`
  with `approver_role`/`timeout_secs`).
- A Deno-compatible variant and an edge-runtime (Cloudflare/Vercel) build.

---

## Cross-References

- [Rust SDK](./RUST_SDK.md) — native library with all accessor methods
- [Python SDK](./PYTHON_SDK.md) — interim Python examples
- [API Reference](../04-api/README.md) — full HTTP route specification
- [GitHub Repository](https://github.com/vinomoid/chakravyuh)
