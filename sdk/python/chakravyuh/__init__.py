"""CHAKRAVYUH OS — Official Python SDK.

The ``chakravyuh`` package provides a production-quality Python client
for the `CHAKRAVYUH OS <https://vinomoid.com/chakravyuh-os>`_ REST API.

CHAKRAVYUH OS is a multi-ring AI security orchestration platform that provides
real-time prompt analysis, policy evaluation, audit verification, and threat
intelligence for LLM-powered applications.

Quick Start::

    from chakravyuh import Chakravyuh

    ck = Chakravyuh(api_key="ck_live_xxxxxxxxx")
    result = ck.protect("Ignore previous instructions")
    if not result.allowed:
        print(f"Blocked: {result.action}")

Async::

    from chakravyuh import AsyncChakravyuh

    async with AsyncChakravyuh(api_key="ck_live_xxxxxxxxx") as ck:
        result = await ck.protect("Ignore previous instructions")
        print(result.risk_score)
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    # Client
    "Chakravyuh",
    "AsyncChakravyuh",
    # Auth
    "ApiKey",
    # Errors
    "ChakravyuhError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "RateLimitError",
    "ApiError",
    "NetworkError",
    "TimeoutError",
    "ServiceUnavailableError",
    "SerializationError",
    # Models - Enums
    "InputType",
    "Action",
    "Ring",
    "Severity",
    "IntegrityStatus",
    "PolicyDecision",
    "HashAlgorithm",
    "SignatureAlgorithm",
    "ComponentHealth",
    "SystemStatus",
    "BuildProfile",
    # Models - Request/Response
    "ProtectRequest",
    "ProtectResponse",
    "ProtectInput",
    "ProtectContext",
    "ProtectDetails",
    "VerifyRequest",
    "VerifyResponse",
    "HashSpec",
    "SignatureSpec",
    "PolicyResponse",
    "MatchedRule",
    "AuditQuery",
    "AuditListResponse",
    "AuditRecord",
    "Pagination",
    "HealthResponse",
    # Models - Supporting
    "ToolDef",
    "GeoInfo",
    "LatencyStats",
    "BuildInfo",
    "ComponentsHealth",
    "DegradedReason",
]

# Client
from .client import AsyncChakravyuh, Chakravyuh

# Auth
from .auth import ApiKey

# Errors
from .errors import (
    ApiError,
    ChakravyuhError,
    ForbiddenError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    SerializationError,
    ServiceUnavailableError,
    TimeoutError,
    UnauthorizedError,
)

# Models
from .models import (
    Action,
    AuditListResponse,
    AuditQuery,
    AuditRecord,
    BuildInfo,
    BuildProfile,
    ComponentHealth,
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
    SignatureAlgorithm,
    SignatureSpec,
    SystemStatus,
    ToolDef,
    VerifyRequest,
    VerifyResponse,
)
