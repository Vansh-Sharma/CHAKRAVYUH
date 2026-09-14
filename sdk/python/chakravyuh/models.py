"""Pydantic v2 models matching the CHAKRAVYUH OS OpenAPI 3.1.0 contract.

Every model mirrors a schema in the official API specification.
All models use ``alias_generators`` to produce ``snake_case`` JSON keys.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


# ═══════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════


class InputType(str, Enum):
    """The type of input being protected."""

    PROMPT = "prompt"
    API_REQUEST = "api_request"
    AGENT_INSTRUCTION = "agent_instruction"
    OUTPUT = "output"
    CONVERSATION = "conversation"


class Action(str, Enum):
    """Action taken by the orchestrator.

    The REST API returns ``"allow"`` for allowed requests and ``"deny"``
    for blocked requests (per the Phase 14 contract). The legacy
    ``"block"`` value is still accepted as an alias for ``DENY`` so
    older server builds don't break the SDK.
    """

    ALLOW = "allow"
    DENY = "deny"
    # Aliases kept for backward compatibility with older server builds.
    BLOCK = "block"
    CONDITIONAL = "conditional"
    WARN = "warn"


# Wire values that normalize to DENY. Older server builds returned
# "block" instead of "deny" — both must map to Action.DENY so callers
# can write `if result.action == Action.DENY:` regardless of server version.
_ACTION_ALIASES: dict[str, Action] = {
    "allow": Action.ALLOW,
    "deny": Action.DENY,
    "block": Action.DENY,  # legacy alias
    "conditional": Action.CONDITIONAL,
    "warn": Action.WARN,
}


class Ring(str, Enum):
    """Defense ring that produced a trigger (15 rings)."""

    PROMPT = "prompt"
    INPUT = "input"
    OUTPUT = "output"
    CONTEXT = "context"
    AGENT = "agent"
    IDENTITY = "identity"
    TRUST = "trust"
    COMPLIANCE = "compliance"
    RATE = "rate"
    GEO = "geo"
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    SESSION = "session"
    SEMANTIC = "semantic"
    OVAPH = "ovaph"


class Severity(str, Enum):
    """Severity classification."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntegrityStatus(str, Enum):
    """Integrity verification result."""

    INTACT = "intact"
    CORRUPTED = "corrupted"
    UNKNOWN = "unknown"


class PolicyDecision(str, Enum):
    """Policy evaluation decision."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


class HashAlgorithm(str, Enum):
    """Hash algorithm for evidence verification."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class SignatureAlgorithm(str, Enum):
    """Signature algorithm for evidence verification."""

    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa_p256"
    RSA_PSS = "rsa_pss"


class ComponentHealth(str, Enum):
    """Component health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class SystemStatus(str, Enum):
    """Overall system health status.

    The server may return ``"operational"`` (current contract) or ``"ok"``
    (legacy/compatibility form). Both normalize to :attr:`OPERATIONAL`.
    Case-insensitive on input.
    """

    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


# Map of accepted wire strings → canonical enum value.
# Used by the field validator on HealthResponse so callers can pass
# either "ok" or "operational" interchangeably.
_STATUS_ALIASES: dict[str, SystemStatus] = {
    "ok": SystemStatus.OPERATIONAL,
    "operational": SystemStatus.OPERATIONAL,
    "degraded": SystemStatus.DEGRADED,
    "unavailable": SystemStatus.UNAVAILABLE,
}


class BuildProfile(str, Enum):
    """Build profile."""

    DEBUG = "debug"
    RELEASE = "release"


class StepUpType(str, Enum):
    """Step-up verification type."""

    MFA = "mfa"
    CAPTCHA = "captcha"
    MANUAL_REVIEW = "manual_review"


# ═══════════════════════════════════════════════════════════════════
# Shared Types
# ═══════════════════════════════════════════════════════════════════


class ToolDef(BaseModel):
    """A tool definition available to an agent."""

    name: str
    description: str | None = None
    parameters: dict[str, Any] | None = None


class GeoInfo(BaseModel):
    """Geolocation data for geo-ring evaluation."""

    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    is_vpn: bool | None = None


class HashSpec(BaseModel):
    """Hash specification for evidence verification."""

    algorithm: HashAlgorithm
    value: str


class SignatureSpec(BaseModel):
    """Signature specification for evidence verification."""

    algorithm: SignatureAlgorithm
    value: str


class StepUpRequired(BaseModel):
    """Step-up authentication requirement."""

    type: str
    challenge: str


class ProtectDetails(BaseModel):
    """Additional decision context (when action is not ``allow``)."""

    reason: str | None = None
    patterns: list[str] = Field(default_factory=list)
    recommendation: str | None = None
    step_up_required: StepUpRequired | None = None


# ═══════════════════════════════════════════════════════════════════
# Protect Types
# ═══════════════════════════════════════════════════════════════════


class ProtectInput(BaseModel):
    """The input to be analyzed by the protect endpoint."""

    type: InputType
    content: str
    content_type: str | None = None
    tools: list[ToolDef] = Field(default_factory=list)


class ProtectContext(BaseModel):
    """Contextual metadata about the request environment."""

    source_ip: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    endpoint: str | None = None
    method: str | None = None
    agent_id: str | None = None
    chain_depth: int | None = None
    geo: GeoInfo | None = None


class ProtectRequest(BaseModel):
    """Request body for ``POST /v1/protect``."""

    input: ProtectInput
    context: ProtectContext | None = None
    tenant_id: str
    metadata: dict[str, Any] | None = None

    @classmethod
    def prompt(cls, tenant_id: str, content: str, **kwargs: Any) -> ProtectRequest:
        """Convenience constructor for a simple prompt protection request.

        Args:
            tenant_id: Tenant identifier.
            content: The prompt text to analyze.
            **kwargs: Forwarded to the constructor (e.g. ``context``, ``metadata``).
        """
        return cls(
            input=ProtectInput(type=InputType.PROMPT, content=content),
            tenant_id=tenant_id,
            **kwargs,
        )


class ProtectResponse(BaseModel):
    """Response from ``POST /v1/protect``.

    Accepts the server's actual wire format and exposes the spec
    contract fields. The server returns:

    ```json
    {
      "allowed": false,
      "action": "block",
      "risk_score": 0.0,
      "confidence": 0.11,
      "triggered_ring": "shield",
      "policy_id": "pol_default_v1",
      "evidence_id": "ev_abc12345",
      "latency_ms": 6.5,
      "ring_scores": {...},
      "details": {"reason": "WAF_PROMPT_INJECTION_IGNORE", ...},
      "request_id": "req_xyz789"
    }
    ```

    The SDK exposes:
    - ``action`` normalized to ``Action.DENY`` (legacy ``"block"`` maps to DENY)
    - ``ring`` (mapped from server's ``triggered_ring``)
    - ``reason`` (mapped from server's ``details.reason``)
    """

    allowed: bool
    action: Action
    risk_score: float
    confidence: float
    latency_ms: float
    request_id: str
    evidence_id: str
    # Normalized fields — populated by the model_validator from the
    # server's wire-format keys (triggered_ring, details.reason).
    ring: str | None = None
    reason: str | None = None

    model_config = {"extra": "allow"}

    @model_validator(mode="before")
    @classmethod
    def _normalize_wire_fields(cls, data: Any) -> Any:
        """Map the server's wire-format keys to the spec contract.

        - ``triggered_ring`` → ``ring``
        - ``details.reason`` → ``reason``
        - ``action: "block"`` → ``action: "deny"`` (via _ACTION_ALIASES)
        - ``policy_id`` made optional (server always returns it, spec doesn't require it)
        """
        if not isinstance(data, dict):
            return data

        normalized = dict(data)

        # Map triggered_ring → ring (server uses triggered_ring, spec uses ring)
        if "triggered_ring" in normalized and "ring" not in normalized:
            tr = normalized.get("triggered_ring")
            if tr is not None:
                normalized["ring"] = tr

        # Map details.reason → reason (server nests reason under details)
        details = normalized.get("details")
        if isinstance(details, dict) and "reason" not in normalized:
            d_reason = details.get("reason")
            if d_reason is not None:
                normalized["reason"] = d_reason

        # Normalize action: "block" → "deny" (legacy → spec)
        act = normalized.get("action")
        if isinstance(act, str):
            mapped = _ACTION_ALIASES.get(act.lower())
            if mapped is not None:
                normalized["action"] = mapped.value  # store as string, field_validator will convert

        return normalized

    @field_validator("action", mode="before")
    @classmethod
    def _normalize_action(cls, v: object) -> object:
        """Normalize legacy ``"block"`` → ``Action.DENY``."""
        if isinstance(v, Action):
            return v
        if isinstance(v, str):
            mapped = _ACTION_ALIASES.get(v.lower())
            if mapped is not None:
                return mapped
        return v


# ═══════════════════════════════════════════════════════════════════
# Verify Types
# ═══════════════════════════════════════════════════════════════════


class VerifyDetails(BaseModel):
    """Verification failure details."""

    expected_hash: str
    actual_hash: str
    divergence_at: str


class VerifyRequest(BaseModel):
    """Request body for ``POST /v1/verify``."""

    evidence_id: str
    hash: HashSpec | None = None
    signature: SignatureSpec | None = None


class VerifyResponse(BaseModel):
    """Response from ``POST /v1/verify``."""

    verified: bool
    integrity: IntegrityStatus
    timestamp: datetime
    chain_position: int
    hash: HashSpec | None = None
    details: VerifyDetails | None = None


# ═══════════════════════════════════════════════════════════════════
# Policy Types
# ═══════════════════════════════════════════════════════════════════


class MatchedRule(BaseModel):
    """A rule that matched during policy evaluation."""

    rule_id: str
    rule_name: str
    ring: Ring
    severity: Severity
    pattern: str | None = None
    details: str | None = None
    confidence: float


class PolicyRequest(BaseModel):
    """Request body for ``POST /v1/policy/evaluate``."""

    policy_id: str
    request_payload: ProtectInput
    dry_run: bool | None = None


class PolicyResponse(BaseModel):
    """Response from ``POST /v1/policy/evaluate``."""

    decision: PolicyDecision
    matched_rules: list[MatchedRule] = Field(default_factory=list)
    severity: Severity
    explanation: str
    recommendation: str | None = None


# ═══════════════════════════════════════════════════════════════════
# Audit Types
# ═══════════════════════════════════════════════════════════════════


class AuditRecord(BaseModel):
    """A single immutable audit record."""

    evidence_id: str
    timestamp: datetime
    tenant_id: str
    action: Action
    severity: Severity
    risk_score: float
    triggered_ring: Ring | None = None
    policy_id: str
    input_type: str | None = None
    input_hash: str | None = None
    summary: str | None = None
    details: dict[str, Any] | None = None
    chain_position: int
    chain_hash: str


class Pagination(BaseModel):
    """Pagination metadata for audit listing."""

    total_records: int
    limit: int
    offset: int
    has_more: bool
    next_offset: int | None = None


class AuditListResponse(BaseModel):
    """Response from ``GET /v1/audit``."""

    records: list[AuditRecord]
    pagination: Pagination


class AuditQuery:
    """Builder for audit list query parameters.

    Examples:
        >>> q = AuditQuery().tenant("t1").severity(Severity.CRITICAL).limit(50)
    """

    def __init__(
        self,
        *,
        tenant: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        severity: Severity | None = None,
        action: Action | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> None:
        self._params: dict[str, str] = {}
        if tenant is not None:
            self._params["tenant"] = tenant
        if limit is not None:
            self._params["limit"] = str(min(limit, 100))
        if offset is not None:
            self._params["offset"] = str(offset)
        if severity is not None:
            self._params["severity"] = severity.value
        if action is not None:
            self._params["action"] = action.value
        if from_time is not None:
            self._params["from"] = from_time.isoformat()
        if to_time is not None:
            self._params["to"] = to_time.isoformat()

    def tenant(self, value: str) -> AuditQuery:
        self._params["tenant"] = value
        return self

    def limit(self, value: int) -> AuditQuery:
        self._params["limit"] = str(min(value, 100))
        return self

    def offset(self, value: int) -> AuditQuery:
        self._params["offset"] = str(value)
        return self

    def severity(self, value: Severity) -> AuditQuery:
        self._params["severity"] = value.value
        return self

    def action(self, value: Action) -> AuditQuery:
        self._params["action"] = value.value
        return self

    def from_time(self, value: datetime) -> AuditQuery:
        self._params["from"] = value.isoformat()
        return self

    def to_time(self, value: datetime) -> AuditQuery:
        self._params["to"] = value.isoformat()
        return self

    @property
    def query_string(self) -> str:
        """URL-encoded query string (without leading ``?``)."""
        from urllib.parse import urlencode

        return urlencode(self._params)


# ═══════════════════════════════════════════════════════════════════
# Health Types
# ═══════════════════════════════════════════════════════════════════


class LatencyStats(BaseModel):
    """Request latency percentiles."""

    p50_ms: float
    p95_ms: float
    p99_ms: float


class BuildInfo(BaseModel):
    """Build metadata compiled into the binary."""

    version: str
    commit: str
    target: str
    profile: BuildProfile
    rustc: str
    built_at: datetime


class DegradedReason(BaseModel):
    """Reason for degraded system status."""

    component: str
    issue: str


class ComponentsHealth(BaseModel):
    """Health status of each subsystem."""

    keshav_orchestrator: ComponentHealth
    ananta_engine: ComponentHealth
    sentinel: ComponentHealth
    phoenix: ComponentHealth
    trust_engine: ComponentHealth
    identity: ComponentHealth
    policy_compiler: ComponentHealth
    audit_engine: ComponentHealth
    ovaph: ComponentHealth


class HealthResponse(BaseModel):
    """Response from ``GET /v1/health``.

    Tolerant of both the current contract (``status: "operational"``,
    ``uptime_seconds``, ``active_rings``, ``build``, ``components``) and
    the legacy form (``status: "ok"``, ``uptime_secs``, no build info).
    Missing optional fields fall back to sensible defaults.
    """

    status: SystemStatus
    version: str
    uptime_seconds: int = 0
    active_rings: int = 0
    latency: LatencyStats | None = None
    build: BuildInfo | None = None
    components: ComponentsHealth | None = None
    degraded_reasons: list[DegradedReason] = Field(default_factory=list)

    model_config = {"extra": "allow"}

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_keys(cls, data: Any) -> Any:
        """Map legacy field names to current names so both server
        versions (``uptime_secs`` and ``uptime_seconds``) parse cleanly.
        """
        if isinstance(data, dict):
            if "uptime_secs" in data and "uptime_seconds" not in data:
                data = {**data, "uptime_seconds": data["uptime_secs"]}
                data.pop("uptime_secs", None)
        return data

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, v: object) -> object:
        """Accept ``"ok"``, ``"operational"``, or any case-insensitive
        variant — the server may return either form, both map to
        :attr:`SystemStatus.OPERATIONAL`.
        """
        if isinstance(v, SystemStatus):
            return v
        if isinstance(v, str):
            mapped = _STATUS_ALIASES.get(v.lower())
            if mapped is not None:
                return mapped
        return v


# ═══════════════════════════════════════════════════════════════════
# Error Types
# ═══════════════════════════════════════════════════════════════════


class ApiErrorBody(BaseModel):
    """Structured error body from the API."""

    code: str
    message: str
    request_id: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    """Top-level error response wrapper."""

    error: ApiErrorBody
