"""Unit tests for the error hierarchy."""

from chakravyuh.errors import (
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
    error_from_response,
)


class TestErrorHierarchy:
    def test_unauthorized(self):
        err = UnauthorizedError("bad key")
        assert err.code == "authentication_required"
        assert not err.is_retryable
        assert err.request_id is None

    def test_forbidden(self):
        err = ForbiddenError("no access")
        assert err.code == "access_denied"
        assert not err.is_retryable

    def test_not_found(self):
        err = NotFoundError("missing")
        assert err.code == "not_found"

    def test_rate_limit(self):
        err = RateLimitError("slow down", retry_after=30, request_id="req_1")
        assert err.code == "rate_limited"
        assert err.is_retryable
        assert err.retry_after == 30
        assert err.request_id == "req_1"

    def test_api_error(self):
        err = ApiError("fail", api_code="custom_error", request_id="req_2")
        assert err.code == "custom_error"
        assert err.request_id == "req_2"
        assert not err.is_retryable

    def test_network_error_retryable(self):
        assert NetworkError("conn fail").is_retryable

    def test_timeout_error_retryable(self):
        err = TimeoutError("slow", timeout_secs=10)
        assert err.is_retryable
        assert err.timeout_secs == 10

    def test_service_unavailable_retryable(self):
        assert ServiceUnavailableError("down").is_retryable

    def test_serialization_error(self):
        assert not SerializationError("json fail").is_retryable

    def test_repr(self):
        err = RateLimitError("rl", retry_after=5, request_id="r1")
        r = repr(err)
        assert "RateLimitError" in r
        assert "r1" in r


class TestErrorFromResponse:
    def test_401(self):
        body = {"error": {"code": "auth", "message": "bad", "request_id": "r1"}}
        err = error_from_response(401, body)
        assert isinstance(err, UnauthorizedError)

    def test_403(self):
        body = {"error": {"code": "denied", "message": "no", "request_id": "r2"}}
        err = error_from_response(403, body)
        assert isinstance(err, ForbiddenError)

    def test_404(self):
        body = {"error": {"code": "missing", "message": "gone", "request_id": "r3"}}
        err = error_from_response(404, body)
        assert isinstance(err, NotFoundError)

    def test_429(self):
        body = {"error": {"code": "rl", "message": "slow", "request_id": "r4"}}
        err = error_from_response(429, body, retry_after=30)
        assert isinstance(err, RateLimitError)
        assert err.retry_after == 30

    def test_500(self):
        body = {"error": {"code": "internal", "message": "oops", "request_id": "r5"}}
        err = error_from_response(500, body)
        assert isinstance(err, ApiError)
        assert err.api_code == "internal"

    def test_missing_error_key(self):
        body = {}
        err = error_from_response(500, body)
        assert isinstance(err, ApiError)
