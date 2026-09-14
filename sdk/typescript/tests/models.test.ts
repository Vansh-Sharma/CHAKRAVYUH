/**
 * Compile-time model validation tests.
 * These verify that the types are correctly shaped at the type level.
 */
import { describe, it, expect } from "vitest";
import type {
  ProtectRequest,
  ProtectResponse,
  VerifyRequest,
  VerifyResponse,
  PolicyRequest,
  PolicyResponse,
  AuditRecord,
  AuditListResponse,
  HealthResponse,
  AuditQuery,
  ChakravyuhConfig,
  InputType,
  Action,
  Ring,
  Severity,
} from "../src/models";

describe("Model type smoke tests", () => {
  it("ProtectRequest compiles correctly", () => {
    const req: ProtectRequest = {
      input: {
        type: "prompt" as InputType,
        content: "test",
      },
      tenant_id: "tenant_1",
      context: {
        source_ip: "1.2.3.4",
        session_id: "sess_1",
      },
      metadata: { model: "gpt-4o" },
    };
    expect(req.input.type).toBe("prompt");
    expect(req.tenant_id).toBe("tenant_1");
  });

  it("ProtectResponse compiles correctly", () => {
    const res: ProtectResponse = {
      allowed: true,
      action: "allow" as Action,
      risk_score: 0.12,
      confidence: 0.97,
      triggered_ring: null,
      policy_id: "pol_1",
      evidence_id: "ev_1",
      latency_ms: 3.42,
      ring_scores: {
        prompt: 0.05,
        input: 0.08,
      },
      details: {
        reason: "Test reason",
        patterns: ["pattern1"],
      },
    };
    expect(res.allowed).toBe(true);
    expect(res.triggered_ring).toBeNull();
  });

  it("VerifyRequest compiles correctly", () => {
    const req: VerifyRequest = {
      evidence_id: "ev_1",
      hash: {
        algorithm: "sha256",
        value: "abc123",
      },
    };
    expect(req.evidence_id).toBe("ev_1");
  });

  it("PolicyRequest compiles correctly", () => {
    const req: PolicyRequest = {
      policy_id: "pol_1",
      request_payload: {
        type: "prompt" as InputType,
        content: "test",
      },
      dry_run: true,
    };
    expect(req.dry_run).toBe(true);
  });

  it("AuditQuery compiles correctly", () => {
    const q: AuditQuery = {
      tenant: "t1",
      limit: 50,
      offset: 0,
      severity: "critical" as Severity,
    };
    expect(q.limit).toBe(50);
  });

  it("HealthResponse compiles correctly", () => {
    const h: HealthResponse = {
      status: "operational",
      version: "1.0.0",
      uptime_seconds: 86400,
      active_rings: 15,
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
    expect(h.active_rings).toBe(15);
  });
});
