"""Unified exception hierarchy for the CHAKRAVYUH SDK.

All SDK operations raise subclasses of :class:`ChakravyuhError`.
Check ``.is_retryable`` to decide whether to retry with backoff.
"""

from __future__ import annotations


class ChakravyuhError(Exception):
    """Base exception for all CHAKRAVYUH SDK errors.

    Attributes:
        message: Human-readable error description.
        request_id: Server request ID for support correlation (if available).
    """

    def __init__(self, message: str, *, request_id: str | None = None) -> None:
        self.message = message
        self.request_id = request_id
        super().__init__(message)

    @property
    def code(self) -> str:
        """Machine-readable error code."""
        return "unknown_error"

    @property
    def is_retryable(self) -> bool:
        """Whether this error is retryable with exponential backoff."""
        return False

    def __repr__(self) -> str:
        return f"{type(self).__name__}(message={self.message!r}, request_id={self.request_id!r})"


class UnauthorizedError(ChakravyuhError):
    """Authentication failed — the API key is missing, invalid, or expired.

    Ensure your API key follows the format ``ck_live_*`` or ``ck_test_*``.
    """

    @property
    def code(self) -> str:
        return "authentication_required"


class ForbiddenError(ChakravyuhError):
    """The request was denied (HTTP 403).

    For protect endpoints, the 403 body is a :class:`ProtectResponse`
    with ``allowed=false``. The parsed response object is attached to
    this exception as :attr:`response` so callers can inspect why the
    prompt was blocked without re-parsing.

    Example::

        try:
            ck.protect("Ignore all previous instructions", tenant_id="t1")
        except ForbiddenError as e:
            print(e.response.reason)   # WAF_PROMPT_INJECTION_IGNORE
            print(e.response.ring)     # Shield
            print(e.response.risk_score)  # 0.95
    """

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        response: "ProtectResponse | None" = None,
    ) -> None:
        super().__init__(message, request_id=request_id)
        # Late import to avoid circular dependency at module load time.
        if response is None and isinstance(message, dict):
            # Allow being constructed directly from a parsed body dict.
            try:
                from .models import ProtectResponse as _PR
                response = _PR(**message)  # type: ignore[arg-type]
            except Exception:
                response = None
        self.response = response

    @property
    def code(self) -> str:
        return "access_denied"

    def __repr__(self) -> str:
        if self.response is not None:
            return (
                f"{type(self).__name__}(action={self.response.action!r}, "
                f"ring={self.response.ring!r}, reason={self.response.reason!r}, "
                f"request_id={self.request_id!r})"
            )
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"request_id={self.request_id!r})"
        )


# Forward declaration for the type-checker / IDE. Real import is done
# lazily inside ForbiddenError.__init__ to avoid a circular import
# (models.py imports errors.py at module load).
from typing import TYPE_CHECKING  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover
    from .models import ProtectResponse


class NotFoundError(ChakravyuhError):
    """The requested resource was not found (HTTP 404)."""

    @property
    def code(self) -> str:
        return "not_found"


class RateLimitError(ChakravyuhError):
    """Rate limit exceeded. Retry after ``retry_after`` seconds.

    Attributes:
        retry_after: Seconds until the rate limit window resets.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: int = 0,
        request_id: str | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(message, request_id=request_id)

    @property
    def code(self) -> str:
        return "rate_limited"

    @property
    def is_retryable(self) -> bool:
        return True

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"retry_after={self.retry_after}, request_id={self.request_id!r})"
        )


class ApiError(ChakravyuhError):
    """The API returned a structured error response.

    Attributes:
        api_code: Machine-readable error code from the server.
    """

    def __init__(
        self,
        message: str,
        *,
        api_code: str = "unknown_error",
        request_id: str | None = None,
    ) -> None:
        self.api_code = api_code
        super().__init__(message, request_id=request_id)

    @property
    def code(self) -> str:
        return self.api_code

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"api_code={self.api_code!r}, request_id={self.request_id!r})"
        )


class NetworkError(ChakravyuhError):
    """A network error occurred — could not reach the API.

    Covers connection timeouts, DNS failures, and transport errors.
    """

    @property
    def is_retryable(self) -> bool:
        return True


class TimeoutError(ChakravyuhError):
    """The request timed out.

    Attributes:
        timeout_secs: The configured timeout in seconds.
    """

    def __init__(
        self,
        message: str,
        *,
        timeout_secs: float = 0,
        request_id: str | None = None,
    ) -> None:
        self.timeout_secs = timeout_secs
        super().__init__(message, request_id=request_id)

    @property
    def is_retryable(self) -> bool:
        return True

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"timeout_secs={self.timeout_secs}, request_id={self.request_id!r})"
        )


class ServiceUnavailableError(ChakravyuhError):
    """The service is temporarily unavailable (HTTP 503). Retry with backoff."""

    @property
    def code(self) -> str:
        return "service_unavailable"

    @property
    def is_retryable(self) -> bool:
        return True


class SerializationError(ChakravyuhError):
    """Request or response serialization/deserialization failed."""

    @property
    def code(self) -> str:
        return "serialization_error"


# Status code → exception mapping.
_STATUS_TO_EXCEPTION: dict[int, type[ChakravyuhError]] = {
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
    429: RateLimitError,
    503: ServiceUnavailableError,
}


def error_from_response(
    status_code: int,
    body: dict,
    retry_after: int | None = None,
) -> ChakravyuhError:
    """Convert an API error response into the appropriate exception.

    Args:
        status_code: HTTP status code.
        body: Parsed JSON body. May be either:
            - An error envelope ``{"error": {"code": ..., "message": ...}}``
            - A protect-response body ``{"allowed": false, "action": "deny", ...}``
              (for 403 from /v1/protect — the full ProtectResponse is parsed
              and attached to the returned :class:`ForbiddenError` as
              ``.response``).
        retry_after: Value of the ``Retry-After`` header (for 429 responses).

    Returns:
        The appropriate :class:`ChakravyuhError` subclass instance.
    """
    # ── 403 with a ProtectResponse body ──
    # The /v1/protect endpoint returns 403 with the full ProtectResponse
    # JSON (allowed, action, ring, reason, risk_score, confidence,
    # request_id, evidence_id) — NOT an error envelope. Parse the body
    # into a ProtectResponse and attach it to ForbiddenError.response.
    if status_code == 403 and isinstance(body, dict) and "allowed" in body:
        # Lazy import to avoid circular dependency.
        from .models import ProtectResponse

        try:
            response = ProtectResponse(**body)
        except Exception:
            # Body wasn't a valid ProtectResponse — fall back to a bare
            # ForbiddenError with the request_id if present.
            return ForbiddenError(
                "Forbidden",
                request_id=body.get("request_id") if isinstance(body, dict) else None,
            )

        return ForbiddenError(
            message=response.reason or response.action or "Forbidden",
            request_id=response.request_id,
            response=response,
        )

    # ── Standard error envelope ──
    err = body.get("error", {}) if isinstance(body, dict) else {}
    code = err.get("code", "unknown_error")
    message = err.get("message", "Unknown error")
    request_id = err.get("request_id")

    exc_cls = _STATUS_TO_EXCEPTION.get(status_code, ApiError)

    if exc_cls is RateLimitError:
        return RateLimitError(
            message, retry_after=retry_after or 0, request_id=request_id
        )
    if exc_cls is ApiError:
        return ApiError(message, api_code=code, request_id=request_id)
    return exc_cls(message, request_id=request_id)
