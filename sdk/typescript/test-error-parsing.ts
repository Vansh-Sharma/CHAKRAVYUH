/**
 * Local smoke test — verifies errorFromResponse correctly parses a 403
 * with a ProtectResponse body and attaches it to ForbiddenError.response.
 *
 * Run: npx tsx test-error-parsing.ts
 *
 * This does NOT require a running server — it tests the SDK's error
 * parsing logic in isolation.
 */

import { ForbiddenError, errorFromResponse } from "./src/errors";
import type { ProtectResponse } from "./src/models";

// Simulate the exact body the Rust server returns on 403 from /v1/protect
// (from src/api/dto.rs ProtectResponse + ProtectDetails)
const server403Body: ProtectResponse = {
  allowed: false,
  action: "block",
  risk_score: 0.0,
  confidence: 0.11,
  triggered_ring: "shield",
  policy_id: "pol_default_v1",
  evidence_id: "ev_abc12345",
  latency_ms: 6.5,
  request_id: "req_xyz789",
  ring_scores: { prompt: 0.0, input: 0.0 },
  details: {
    reason: "WAF_PROMPT_INJECTION_IGNORE",
    recommendation: "Review and sanitize input before processing",
  },
};

console.log("=== Testing errorFromResponse(403, ProtectResponse body) ===\n");

const err = errorFromResponse(403, server403Body);

console.log(`Error type:      ${err.constructor.name}`);
console.log(`Is ForbiddenError: ${err instanceof ForbiddenError}`);
console.log(`Error message:   ${err.message}`);
console.log(`Error code:      ${err.code}`);
console.log(`Error requestId: ${err.requestId}`);
console.log("");

if (err instanceof ForbiddenError && err.response) {
  const resp = err.response;
  console.log("ForbiddenError.response populated:");
  console.log(`  action:       ${resp.action}`);
  console.log(`  ring:         ${resp.triggered_ring}`);
  console.log(`  reason:       ${resp.details?.reason}`);
  console.log(`  risk_score:   ${resp.risk_score}`);
  console.log(`  confidence:   ${resp.confidence}`);
  console.log(`  evidence_id:  ${resp.evidence_id}`);
  console.log(`  request_id:   ${resp.request_id}`);
  console.log("");

  // Verify spec expectations
  const checks: Array<[string, boolean]> = [
    ["err is ForbiddenError", err instanceof ForbiddenError],
    ["err.response is populated", err.response !== undefined],
    ["err.response.action is 'block'", resp.action === "block"],
    ["err.response.triggered_ring is 'shield'", resp.triggered_ring === "shield"],
    ["err.response.details.reason is WAF_PROMPT_INJECTION_IGNORE", resp.details?.reason === "WAF_PROMPT_INJECTION_IGNORE"],
    ["err.response.evidence_id is ev_abc12345", resp.evidence_id === "ev_abc12345"],
    ["err.response.request_id is req_xyz789", resp.request_id === "req_xyz789"],
  ];

  console.log("=== Spec checks ===");
  let allPassed = true;
  for (const [name, ok] of checks) {
    const status = ok ? "✓" : "✗";
    console.log(`  ${status} ${name}`);
    if (!ok) allPassed = false;
  }

  console.log("");
  if (allPassed) {
    console.log("✓ All checks passed — TypeScript SDK parses 403 correctly");
  } else {
    console.log("✗ Some checks failed");
    process.exit(1);
  }
} else {
  console.log("✗ FAILED — ForbiddenError.response is not populated");
  process.exit(1);
}
