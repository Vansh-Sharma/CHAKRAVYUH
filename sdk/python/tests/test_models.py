"""Unit tests for Pydantic models (serialization/deserialization)."""

from datetime import datetime, timezone

import pytest

from chakravyuh.models import (
    Action,
    AuditListResponse,
    AuditQuery,
    AuditRecord,
    BuildInfo,
    BuildProfile,
    ComponentHealth,
    ComponentsHealth,
    DegradedReason,
    GeoInfo,
    HashAlgorithm,
    HashSpec,
    HealthResponse,
    InputType,
    IntegrityStatus,
    LatencyStats,
    MatchedRule,
    Pagination,
    PolicyDecision,
    PolicyResponse,
    ProtectContext,
    ProtectDetails,
    ProtectInput,
    ProtectRequest,
    ProtectResponse,
    Ring,
    Severity,
    SystemStatus,
    VerifyDetails,
    VerifyRequest,
    VerifyResponse,
)


class TestProtectRequest:
    def test_prompt_convenience(self):
        req = ProtectRequest.prompt("t1", "Hello world")
        assert req.input.type == InputType.PROMPT
        assert req.input.content == "Hello world"
        assert req.tenant_id == "t1"
        assert req.context is None

    def test_prompt_with_context(self):
        ctx = ProtectContext(source_ip="10.0.0.1", session_id="sess_abc")
        req = ProtectRequest.prompt("t1", "test", context=ctx)
        assert req.context is not None
        assert req.context.source_ip == "10.0.0.1"

    def test_prompt_with_metadata(self):
        req = ProtectRequest.prompt("t1", "test", metadata={"model": "gpt-4o"})
        assert req.metadata == {"model": "gpt-4o"}

    def test_model_dump_excludes_none(self):
        req = ProtectRequest.prompt("t1", "test")
        d = req.model_dump(mode="json", exclude_none=True)
        assert "context" not in d
        assert "metadata" not in d
        assert "tools" not in d.get("input", {})


class TestProtectResponse:
    def test_deserialize_allowed(self):
        data = {
            "allowed": True,
            "action": "allow",
            "risk_score": 0.12,
            "confidence": 0.97,
            "triggered_ring": None,
            "policy_id": "pol_v1",
            "evidence_id": "ev_123",
            "latency_ms": 3.42,
            "ring_scores": {"prompt": 0.05, "input": 0.08},
        }
        resp = ProtectResponse(**data)
        assert resp.allowed
        assert resp.action == Action.ALLOW
        assert resp.triggered_ring is None
        assert len(resp.ring_scores) == 2

    def test_deserialize_blocked(self):
        data = {
            "allowed": False,
            "action": "block",
            "risk_score": 0.94,
            "confidence": 0.99,
            "triggered_ring": "prompt",
            "policy_id": "pol_v1",
            "evidence_id": "ev_456",
            "latency_ms": 4.18,
            "ring_scores": {"prompt": 0.96},
            "details": {
                "reason": "Prompt injection",
                "patterns": ["instruction_override"],
            },
        }
        resp = ProtectResponse(**data)
        assert not resp.allowed
        assert resp.action == Action.BLOCK
        assert resp.triggered_ring == Ring.PROMPT
        assert resp.details is not None
        assert resp.details.patterns == ["instruction_override"]


class TestVerifyResponse:
    def test_intact(self):
        data = {
            "verified": True,
            "integrity": "intact",
            "timestamp": "2026-08-22T10:30:00Z",
            "chain_position": 47821,
            "hash": {"algorithm": "sha256", "value": "abc123"},
        }
        resp = VerifyResponse(**data)
        assert resp.verified
        assert resp.integrity == IntegrityStatus.INTACT

    def test_corrupted(self):
        data = {
            "verified": False,
            "integrity": "corrupted",
            "timestamp": "2026-08-22T10:30:00Z",
            "chain_position": 47821,
            "details": {
                "expected_hash": "abc",
                "actual_hash": "fff",
                "divergence_at": "byte 2",
            },
        }
        resp = VerifyResponse(**data)
        assert resp.integrity == IntegrityStatus.CORRUPTED


class TestPolicyResponse:
    def test_deny(self):
        data = {
            "decision": "deny",
            "matched_rules": [
                {
                    "rule_id": "r1",
                    "rule_name": "SQL Injection",
                    "ring": "input",
                    "severity": "critical",
                    "confidence": 0.98,
                    "pattern": "OR 1=1",
                }
            ],
            "severity": "critical",
            "explanation": "SQL injection detected",
            "recommendation": "Reject",
        }
        resp = PolicyResponse(**data)
        assert resp.decision == PolicyDecision.DENY
        assert len(resp.matched_rules) == 1
        assert resp.matched_rules[0].ring == Ring.INPUT

    def test_allow_empty_rules(self):
        data = {
            "decision": "allow",
            "matched_rules": [],
            "severity": "none",
            "explanation": "All clear",
        }
        resp = PolicyResponse(**data)
        assert resp.decision == PolicyDecision.ALLOW
        assert len(resp.matched_rules) == 0


class TestHealthResponse:
    def test_operational(self):
        data = {
            "status": "operational",
            "version": "1.0.0",
            "uptime_seconds": 86400,
            "active_rings": 15,
            "latency": {"p50_ms": 2.1, "p95_ms": 5.3, "p99_ms": 12.7},
            "build": {
                "version": "1.0.0",
                "commit": "a3f2b91c",
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "rustc": "1.82.0",
                "built_at": "2026-08-21T18:00:00Z",
            },
            "components": {
                "keshav_orchestrator": "healthy",
                "ananta_engine": "healthy",
                "sentinel": "healthy",
                "phoenix": "healthy",
                "trust_engine": "healthy",
                "identity": "healthy",
                "policy_compiler": "healthy",
                "audit_engine": "healthy",
                "ovaph": "healthy",
            },
        }
        resp = HealthResponse(**data)
        assert resp.status == SystemStatus.OPERATIONAL
        assert resp.active_rings == 15
        assert resp.components.ananta_engine == ComponentHealth.HEALTHY
        assert len(resp.degraded_reasons) == 0


class TestAuditQuery:
    def test_empty(self):
        q = AuditQuery()
        assert q.query_string == ""

    def test_tenant_and_limit(self):
        q = AuditQuery().tenant("t1").limit(50)
        qs = q.query_string
        assert "tenant=t1" in qs
        assert "limit=50" in qs

    def test_limit_capped(self):
        q = AuditQuery().limit(500)
        assert "limit=100" in q.query_string

    def test_all_params(self):
        from datetime import datetime, timezone
        q = (
            AuditQuery()
            .tenant("t1")
            .severity(Severity.HIGH)
            .offset(100)
            .limit(20)
        )
        qs = q.query_string
        assert "tenant=t1" in qs
        assert "severity=high" in qs
        assert "offset=100" in qs


class TestRingEnum:
    def test_all_15_rings(self):
        expected = {
            Ring.PROMPT, Ring.INPUT, Ring.OUTPUT, Ring.CONTEXT, Ring.AGENT,
            Ring.IDENTITY, Ring.TRUST, Ring.COMPLIANCE, Ring.RATE, Ring.GEO,
            Ring.ANOMALY, Ring.BEHAVIORAL, Ring.SESSION, Ring.SEMANTIC, Ring.OVAPH,
        }
        assert len(Ring) == 15
        assert set(Ring) == expected


class TestAuditListResponse:
    def test_deserialize(self):
        data = {
            "records": [
                {
                    "evidence_id": "ev_001",
                    "timestamp": "2026-08-22T10:15:33Z",
                    "tenant_id": "t1",
                    "action": "block",
                    "severity": "critical",
                    "risk_score": 0.94,
                    "policy_id": "pol_v1",
                    "chain_position": 100,
                    "chain_hash": "abc",
                }
            ],
            "pagination": {
                "total_records": 1,
                "limit": 20,
                "offset": 0,
                "has_more": False,
            },
        }
        resp = AuditListResponse(**data)
        assert len(resp.records) == 1
        assert resp.records[0].evidence_id == "ev_001"
        assert not resp.pagination.has_more
