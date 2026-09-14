"""CHAKRAVYUH OS client — sync and async.

The main entry point is the :class:`Chakravyuh` class.

Examples:
    >>> ck = Chakravyuh(api_key="ck_live_xxxxxxxxx")
    >>> result = ck.protect("Ignore previous instructions")
    >>> print(result.allowed)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal, overload

import httpx

from .auth import ApiKey
from .errors import (
    NetworkError as _NetworkError,
    SerializationError as _SerializationError,
    ServiceUnavailableError,
    TimeoutError as _TimeoutError,
    UnauthorizedError,
    error_from_response,
)
from .models import (
    Action,
    AuditListResponse,
    AuditQuery,
    HashSpec,
    HealthResponse,
    InputType,
    PolicyResponse,
    ProtectInput,
    ProtectRequest,
    ProtectResponse,
    Severity,
    VerifyRequest,
    VerifyResponse,
)

if TYPE_CHECKING:
    pass

__all__ = ["Chakravyuh", "AsyncChakravyuh"]

_DEFAULT_BASE_URL = "https://api.vinomoid.com"
_DEFAULT_TIMEOUT = 30.0
_USER_AGENT = "chakravyuh-python-sdk/1.0.0"


class _BaseClient:
    """Shared logic for sync and async clients."""

    __slots__ = ("_api_key", "_base_url", "_timeout")

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = ApiKey(api_key)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def api_key(self) -> ApiKey:
        """The validated API key."""
        return self._api_key

    @property
    def base_url(self) -> str:
        """The configured API base URL."""
        return self._base_url

    @property
    def is_live(self) -> bool:
        """Whether this client uses a production API key."""
        return self._api_key.is_live

    @property
    def is_test(self) -> bool:
        """Whether this client uses a sandbox API key."""
        return self._api_key.is_test

    def _common_headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key.bearer,
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }

    # ------------------------------------------------------------------
    # Response handling (shared)
    # ------------------------------------------------------------------

    def _parse_response(self, status: int, body_bytes: bytes, headers: Any) -> Any:  # noqa: ANN401
        """Parse a successful response or raise the appropriate error."""
        try:
            data = json.loads(body_bytes)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _SerializationError(
                f"Failed to decode response: {exc}"
            ) from exc

        if status >= 400:
            retry_after = None
            if status == 429:
                ra = headers.get("retry-after") if headers else None
                if ra is not None:
                    retry_after = int(ra)
            raise error_from_response(status, data, retry_after=retry_after)

        return data


class Chakravyuh(_BaseClient):
    """Synchronous CHAKRAVYUH OS client.

    Args:
        api_key: Bearer API key (``ck_live_*`` or ``ck_test_*``).
        base_url: API base URL. Defaults to ``https://api.vinomoid.com``.
        timeout: Request timeout in seconds. Defaults to 30.

    Raises:
        UnauthorizedError: If the API key format is invalid.

    Examples:
        >>> ck = Chakravyuh(api_key="ck_live_xxxxxxxxx")
        >>> result = ck.protect("Hello, world!")
        >>> print(result.allowed, result.risk_score)
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(api_key=api_key, base_url=base_url, timeout=timeout)
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            headers=self._common_headers(),
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> Chakravyuh:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ----------------------------------------------------------------
    # POST /v1/protect
    # ----------------------------------------------------------------

    def protect(
        self,
        content: str,
        *,
        tenant_id: str = "default",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        input_type: InputType = InputType.PROMPT,
        content_type: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> ProtectResponse:
        """Analyze and protect an LLM interaction.

        Args:
            content: The prompt or content to analyze.
            tenant_id: Tenant identifier for multi-tenant isolation.
            context: Optional request context (source_ip, session_id, etc.).
            metadata: Optional key-value metadata for policy evaluation.
            input_type: Type of input. Defaults to ``InputType.PROMPT``.
            content_type: MIME type. Defaults to ``text/plain``.
            tools: Tool definitions (only for ``AGENT_INSTRUCTION``).

        Returns:
            A :class:`ProtectResponse` with the protection decision.

        Raises:
            ChakravyuhError: On API errors.
        """
        from .models import ProtectContext, ToolDef

        input_obj = ProtectInput(
            type=input_type,
            content=content,
            content_type=content_type,
            tools=[ToolDef(**t) for t in (tools or [])],
        )

        ctx = None
        if context:
            ctx = ProtectContext(**context)

        request = ProtectRequest(
            input=input_obj,
            context=ctx,
            tenant_id=tenant_id,
            metadata=metadata,
        )

        data = self._post("/v1/protect", request)
        return ProtectResponse(**data)

    def protect_with(self, request: ProtectRequest) -> ProtectResponse:
        """Protect with a full :class:`ProtectRequest` for maximum control.

        Args:
            request: A complete :class:`ProtectRequest`.

        Returns:
            A :class:`ProtectResponse`.
        """
        data = self._post("/v1/protect", request)
        return ProtectResponse(**data)

    # ----------------------------------------------------------------
    # POST /v1/verify
    # ----------------------------------------------------------------

    def verify(
        self,
        evidence_id: str,
        *,
        hash: HashSpec | None = None,
    ) -> VerifyResponse:
        """Verify the cryptographic integrity of an audit evidence record.

        Args:
            evidence_id: The ID of the audit evidence record to verify.
            hash: Optional hash specification to verify against.

        Returns:
            A :class:`VerifyResponse` with verification status.
        """
        request = VerifyRequest(evidence_id=evidence_id, hash=hash)
        data = self._post("/v1/verify", request)
        return VerifyResponse(**data)

    # ----------------------------------------------------------------
    # POST /v1/policy/evaluate
    # ----------------------------------------------------------------

    def evaluate_policy(
        self,
        policy_id: str,
        payload: ProtectInput,
        *,
        dry_run: bool = False,
    ) -> PolicyResponse:
        """Evaluate a security policy against a payload.

        Args:
            policy_id: ID of the security policy to evaluate.
            payload: The input to evaluate.
            dry_run: If True, evaluates without creating audit records.

        Returns:
            A :class:`PolicyResponse` with the decision.
        """
        from .models import PolicyRequest

        request = PolicyRequest(
            policy_id=policy_id,
            request_payload=payload,
            dry_run=dry_run,
        )
        data = self._post("/v1/policy/evaluate", request)
        return PolicyResponse(**data)

    # ----------------------------------------------------------------
    # GET /v1/audit
    # ----------------------------------------------------------------

    def audit(self, query: AuditQuery | None = None) -> AuditListResponse:
        """List immutable audit records.

        Args:
            query: Optional :class:`AuditQuery` for filtering and pagination.
                   Defaults to first 20 records.

        Returns:
            An :class:`AuditListResponse` with records and pagination.
        """
        qs = query.query_string if query else ""
        path = f"/v1/audit?{qs}" if qs else "/v1/audit"
        data = self._get(path)
        return AuditListResponse(**data)

    # ----------------------------------------------------------------
    # GET /v1/health
    # ----------------------------------------------------------------

    def health(self) -> HealthResponse:
        """Get system health and status.

        Returns:
            A :class:`HealthResponse` with component health and latency stats.
        """
        data = self._get("/v1/health")
        return HealthResponse(**data)

    # ----------------------------------------------------------------
    # Internal HTTP helpers
    # ----------------------------------------------------------------

    def _get(self, path: str) -> dict[str, Any]:
        try:
            resp = self._client.get(path)
            return self._parse_response(
                resp.status_code, resp.content, resp.headers
            )
        except httpx.TimeoutException as exc:
            raise _TimeoutError(
                f"Request timed out after {self._timeout}s",
                timeout_secs=self._timeout,
            ) from exc
        except httpx.ConnectError as exc:
            raise _NetworkError(f"Connection error: {exc}") from exc
        except httpx.HTTPError as exc:
            raise _NetworkError(str(exc)) from exc

    def _post(self, path: str, body: Any) -> dict[str, Any]:
        try:
            resp = self._client.post(
                path,
                json=body.model_dump(mode="json", exclude_none=True),
                headers={"Content-Type": "application/json"},
            )
            return self._parse_response(
                resp.status_code, resp.content, resp.headers
            )
        except httpx.TimeoutException as exc:
            raise _TimeoutError(
                f"Request timed out after {self._timeout}s",
                timeout_secs=self._timeout,
            ) from exc
        except httpx.ConnectError as exc:
            raise _NetworkError(f"Connection error: {exc}") from exc
        except httpx.HTTPError as exc:
            raise _NetworkError(str(exc)) from exc


class AsyncChakravyuh(_BaseClient):
    """Asynchronous CHAKRAVYUH OS client.

    Args:
        api_key: Bearer API key (``ck_live_*`` or ``ck_test_*``).
        base_url: API base URL. Defaults to ``https://api.vinomoid.com``.
        timeout: Request timeout in seconds. Defaults to 30.

    Raises:
        UnauthorizedError: If the API key format is invalid.

    Examples:
        >>> async with AsyncChakravyuh(api_key="ck_live_xxxxxxxxx") as ck:
        ...     result = await ck.protect("Hello, world!")
        ...     print(result.allowed)
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(api_key=api_key, base_url=base_url, timeout=timeout)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers=self._common_headers(),
        )

    async def close(self) -> None:
        """Close the underlying async HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncChakravyuh:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ----------------------------------------------------------------
    # POST /v1/protect
    # ----------------------------------------------------------------

    async def protect(
        self,
        content: str,
        *,
        tenant_id: str = "default",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        input_type: InputType = InputType.PROMPT,
        content_type: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> ProtectResponse:
        """Analyze and protect an LLM interaction (async)."""
        from .models import ProtectContext, ToolDef

        input_obj = ProtectInput(
            type=input_type,
            content=content,
            content_type=content_type,
            tools=[ToolDef(**t) for t in (tools or [])],
        )
        ctx = ProtectContext(**context) if context else None
        request = ProtectRequest(
            input=input_obj, context=ctx, tenant_id=tenant_id, metadata=metadata
        )
        data = await self._post("/v1/protect", request)
        return ProtectResponse(**data)

    async def protect_with(self, request: ProtectRequest) -> ProtectResponse:
        """Protect with a full :class:`ProtectRequest` (async)."""
        data = await self._post("/v1/protect", request)
        return ProtectResponse(**data)

    # ----------------------------------------------------------------
    # POST /v1/verify
    # ----------------------------------------------------------------

    async def verify(
        self,
        evidence_id: str,
        *,
        hash: HashSpec | None = None,
    ) -> VerifyResponse:
        """Verify audit evidence integrity (async)."""
        request = VerifyRequest(evidence_id=evidence_id, hash=hash)
        data = await self._post("/v1/verify", request)
        return VerifyResponse(**data)

    # ----------------------------------------------------------------
    # POST /v1/policy/evaluate
    # ----------------------------------------------------------------

    async def evaluate_policy(
        self,
        policy_id: str,
        payload: ProtectInput,
        *,
        dry_run: bool = False,
    ) -> PolicyResponse:
        """Evaluate a security policy (async)."""
        from .models import PolicyRequest

        request = PolicyRequest(
            policy_id=policy_id, request_payload=payload, dry_run=dry_run
        )
        data = await self._post("/v1/policy/evaluate", request)
        return PolicyResponse(**data)

    # ----------------------------------------------------------------
    # GET /v1/audit
    # ----------------------------------------------------------------

    async def audit(self, query: AuditQuery | None = None) -> AuditListResponse:
        """List audit records (async)."""
        qs = query.query_string if query else ""
        path = f"/v1/audit?{qs}" if qs else "/v1/audit"
        data = await self._get(path)
        return AuditListResponse(**data)

    # ----------------------------------------------------------------
    # GET /v1/health
    # ----------------------------------------------------------------

    async def health(self) -> HealthResponse:
        """Get system health (async)."""
        data = await self._get("/v1/health")
        return HealthResponse(**data)

    # ----------------------------------------------------------------
    # Internal HTTP helpers
    # ----------------------------------------------------------------

    async def _get(self, path: str) -> dict[str, Any]:
        try:
            resp = await self._client.get(path)
            return self._parse_response(
                resp.status_code, resp.content, resp.headers
            )
        except httpx.TimeoutException as exc:
            raise _TimeoutError(
                f"Request timed out after {self._timeout}s",
                timeout_secs=self._timeout,
            ) from exc
        except httpx.ConnectError as exc:
            raise _NetworkError(f"Connection error: {exc}") from exc
        except httpx.HTTPError as exc:
            raise _NetworkError(str(exc)) from exc

    async def _post(self, path: str, body: Any) -> dict[str, Any]:
        try:
            resp = await self._client.post(
                path,
                json=body.model_dump(mode="json", exclude_none=True),
                headers={"Content-Type": "application/json"},
            )
            return self._parse_response(
                resp.status_code, resp.content, resp.headers
            )
        except httpx.TimeoutException as exc:
            raise _TimeoutError(
                f"Request timed out after {self._timeout}s",
                timeout_secs=self._timeout,
            ) from exc
        except httpx.ConnectError as exc:
            raise _NetworkError(f"Connection error: {exc}") from exc
        except httpx.HTTPError as exc:
            raise _NetworkError(str(exc)) from exc
