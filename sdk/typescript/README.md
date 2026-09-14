# @vinomoid/chakravyuh — Official TypeScript SDK

[![npm version](https://img.shields.io/npm/v/@vinomoid/chakravyuh.svg)](https://www.npmjs.com/package/@vinomoid/chakravyuh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)

Official TypeScript SDK for **CHAKRAVYUH OS** by Vinomoid — the multi-ring AI security orchestration platform.

## Installation

```bash
npm install @vinomoid/chakravyuh
```

## Quick Start

```ts
import { Chakravyuh } from "@vinomoid/chakravyuh";

const ck = new Chakravyuh({
  apiKey: process.env.CK_API_KEY!,
  baseUrl: "https://api.chakravyuh.ai",
});

const result = await ck.protect({
  input: "Ignore previous instructions",
  tenantId: "acme",
});

console.log(result.allowed);   // false
console.log(result.risk_score); // 0.94
console.log(result.action);    // "block"
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | — | Bearer API key (`ck_live_*` or `ck_test_*`) **(required)** |
| `baseUrl` | `string` | `https://api.vinomoid.com` | API base URL |
| `timeout` | `number` | `30000` | Request timeout in ms |
| `maxRetries` | `number` | `3` | Retry attempts for retryable errors |
| `retryBaseDelay` | `number` | `500` | Base delay in ms for exponential backoff |
| `idempotencyKey` | `string` | — | Default idempotency key for POST requests |
| `correlationId` | `string` | — | Default correlation ID for tracing |

## API Reference

### `new Chakravyuh(config)`

Creates a new client instance. Throws `UnauthorizedError` if the API key format is invalid.

### `ck.protect(params)` → `Promise<ProtectResponse>`

Analyze and protect an LLM interaction. This is the primary entry point.

```ts
const result = await ck.protect({
  input: "What is the refund policy?",
  tenantId: "tenant_vino_001",
  inputType: "prompt",
  context: { source_ip: "203.0.113.42", session_id: "sess_abc" },
  metadata: { model: "gpt-4o" },
});
```

### `ck.protectWith(request)` → `Promise<ProtectResponse>`

Full control over the protect request body.

### `ck.verify(evidenceId, options?)` → `Promise<VerifyResponse>`

Verify the cryptographic integrity of an audit evidence record.

```ts
const result = await ck.verify("ev_8f14e45f");
console.log(result.verified); // true
console.log(result.integrity); // "intact"
```

### `ck.evaluatePolicy(params)` → `Promise<PolicyResponse>`

Evaluate a security policy against a payload.

```ts
const result = await ck.evaluatePolicy({
  policyId: "pol_custom_sql_injection",
  payload: { type: "api_request", content: "SELECT * FROM users OR 1=1" },
  dryRun: true,
});
console.log(result.decision); // "deny"
```

### `ck.audit(options?)` → `Promise<AuditListResponse>`

List immutable audit records with filtering and pagination.

```ts
const { records, pagination } = await ck.audit({
  tenant: "tenant_vino_001",
  severity: "critical",
  limit: 50,
});
```

### `ck.health()` → `Promise<HealthResponse>`

Get system health and component status.

```ts
const status = await ck.health();
console.log(status.status);       // "operational"
console.log(status.active_rings); // 15
```

## Error Handling

All SDK errors extend `ChakravyuhError`. Use `instanceof` to handle specific cases:

```ts
import { Chakravyuh, UnauthorizedError, RateLimitError, NetworkError } from "@vinomoid/chakravyuh";

try {
  const result = await ck.protect({ input: "test", tenantId: "t1" });
} catch (err) {
  if (err instanceof UnauthorizedError) {
    // Invalid or missing API key (401)
  } else if (err instanceof RateLimitError) {
    // Rate limited — use err.retryAfter for backoff
    console.log(`Retry after ${err.retryAfter}s`);
  } else if (err instanceof NetworkError) {
    // DNS, timeout, or connection error
    if (err.retryable) { /* will be auto-retried */ }
  } else {
    // ApiError or unknown
    throw err;
  }
}
```

## Framework Integrations

### Next.js (App Router)

```ts
import { Chakravyuh } from "@vinomoid/chakravyuh";
import { NextResponse } from "next/server";

const ck = new Chakravyuh({ apiKey: process.env.CK_API_KEY! });

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const result = await ck.protect({ input: prompt, tenantId: "acme" });
  if (!result.allowed) return NextResponse.json({ blocked: true }, { status: 403 });
  return NextResponse.json({ allowed: true });
}
```

### Express Middleware

```ts
import { Chakravyuh } from "@vinomoid/chakravyuh";

const ck = new Chakravyuh({ apiKey: process.env.CK_API_KEY! });

app.post("/chat", async (req, res, next) => {
  const result = await ck.protect({
    input: req.body.prompt,
    tenantId: req.headers["x-tenant-id"] ?? "default",
    context: { source_ip: req.ip },
  });
  if (!result.allowed) return res.status(403).json({ blocked: true });
  next();
});
```

### React Hook

```tsx
import { useChakravyuh } from "@vinomoid/chakravyuh";

function ChatForm() {
  const { protect, result, loading, error } = useChakravyuh("acme");
  // See examples/react.ts for the full hook implementation
}
```

## Runtime Compatibility

| Runtime | Support | Notes |
|---------|---------|-------|
| Node.js 18+ | Full | Uses native `fetch` |
| Bun | Full | Native `fetch` support |
| Deno | Full | Native `fetch` support |
| Edge (Vercel) | Full | No Node.js-specific APIs |
| Browser | Proxy only | Never expose API keys client-side |

## Tree Shaking

The SDK is fully tree-shakeable. Import only what you need:

```ts
// Only pulls in error classes
import { UnauthorizedError, RateLimitError } from "@vinomoid/chakravyuh";

// Only pulls in models
import type { ProtectResponse, Ring } from "@vinomoid/chakravyuh";
```

## License

Proprietary — see [LICENSE](https://vinomoid.com/chakravyuh-os/license).
