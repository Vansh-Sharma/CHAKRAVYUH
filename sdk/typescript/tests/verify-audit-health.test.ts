/**
 * Tests for verify, audit, and health methods.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Chakravyuh, NetworkError } from "../src/index";

describe("Chakravyuh.verify", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = originalFetch; });

  it("verifies evidence integrity", async () => {
    const mockResponse = {
      verified: true,
      integrity: "intact",
      timestamp: "2026-08-22T10:30:00Z",
      chain_position: 47821,
      hash: { algorithm: "sha256", value: "a3f2b91c..." },
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      arrayBuffer: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(mockResponse)).buffer),
    } as Response);

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123" });
    const result = await ck.verify("ev_8f14e45f");

    expect(result.verified).toBe(true);
    expect(result.integrity).toBe("intact");
    expect(result.chain_position).toBe(47821);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("reports tampered evidence", async () => {
    const mockResponse = {
      verified: false,
      integrity: "corrupted",
      timestamp: "2026-08-22T10:30:00Z",
      chain_position: 47821,
      details: {
        expected_hash: "a3f2b91c...",
        actual_hash: "ffff0000...",
        divergence_at: "byte 2",
      },
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      arrayBuffer: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(mockResponse)).buffer),
    } as Response);

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123" });
    const result = await ck.verify("ev_a3f2b91c");

    expect(result.verified).toBe(false);
    expect(result.integrity).toBe("corrupted");
    expect(result.details?.divergence_at).toBe("byte 2");
  });
});

describe("Chakravyuh.audit", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = originalFetch; });

  it("returns paginated audit records", async () => {
    const mockResponse = {
      records: [
        {
          evidence_id: "ev_8f14e45f",
          timestamp: "2026-08-22T10:15:33Z",
          tenant_id: "tenant_vino_001",
          action: "block",
          severity: "critical",
          risk_score: 0.94,
          triggered_ring: "prompt",
          policy_id: "pol_default_v1",
          input_type: "prompt",
          input_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb924",
          summary: "Prompt injection attempt blocked",
          chain_position: 47820,
          chain_hash: "a1b2c3d4e5f6...",
        },
      ],
      pagination: {
        total_records: 1847,
        limit: 20,
        offset: 0,
        has_more: true,
        next_offset: 20,
      },
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      arrayBuffer: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(mockResponse)).buffer),
    } as Response);

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123" });
    const result = await ck.audit({ tenant: "tenant_vino_001", limit: 20 });

    expect(result.records).toHaveLength(1);
    expect(result.pagination.total_records).toBe(1847);
    expect(result.records[0]?.evidence_id).toBe("ev_8f14e45f");

    // Verify query params in URL
    const call = vi.mocked(fetch).mock.calls[0]!;
    expect(call[0]).toContain("tenant=tenant_vino_001");
    expect(call[0]).toContain("limit=20");
  });
});

describe("Chakravyuh.health", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = originalFetch; });

  it("returns health status", async () => {
    const mockResponse = {
      status: "operational",
      version: "1.0.0",
      uptime_seconds: 86400,
      active_rings: 15,
      latency: { p50_ms: 2.1, p95_ms: 5.3, p99_ms: 12.7 },
      build: {
        version: "1.0.0",
        commit: "a3f2b91c",
        target: "x86_64-unknown-linux-gnu",
        profile: "release",
        rustc: "1.82.0",
        built_at: "2026-08-21T18:00:00Z",
      },
      components: {
        keshav_orchestrator: "healthy",
        ananta_engine: "healthy",
        sentinel: "healthy",
        phoenix: "healthy",
        trust_engine: "healthy",
        identity: "healthy",
        policy_compiler: "healthy",
        audit_engine: "healthy",
        ovaph: "healthy",
      },
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      arrayBuffer: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(mockResponse)).buffer),
    } as Response);

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123" });
    const result = await ck.health();

    expect(result.status).toBe("operational");
    expect(result.active_rings).toBe(15);
    expect(result.components.ananta_engine).toBe("healthy");
  });
});

describe("Chakravyuh.evaluatePolicy", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = originalFetch; });

  it("evaluates policy and returns decision", async () => {
    const mockResponse = {
      decision: "deny",
      matched_rules: [
        {
          rule_id: "rule_sql_injection_001",
          rule_name: "SQL Injection Pattern Match",
          ring: "input",
          severity: "critical",
          pattern: "OR 1=1",
          confidence: 0.98,
        },
      ],
      severity: "critical",
      explanation:
        'The input contains a classic SQL injection pattern ("OR 1=1").',
      recommendation: "Reject the request and log the incident",
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      arrayBuffer: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(mockResponse)).buffer),
    } as Response);

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123" });
    const result = await ck.evaluatePolicy({
      policyId: "pol_custom_sql_injection",
      payload: {
        type: "api_request",
        content: "SELECT * FROM users WHERE id = 1 OR 1=1",
      },
      dryRun: true,
    });

    expect(result.decision).toBe("deny");
    expect(result.matched_rules).toHaveLength(1);
    expect(result.matched_rules[0]?.rule_id).toBe("rule_sql_injection_001");
  });
});

describe("Network error handling", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = originalFetch; });

  it("wraps fetch errors as NetworkError", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    const ck = new Chakravyuh({ apiKey: "ck_test_abc123", maxRetries: 0 });

    await expect(ck.health()).rejects.toThrow(NetworkError);
  });
});
