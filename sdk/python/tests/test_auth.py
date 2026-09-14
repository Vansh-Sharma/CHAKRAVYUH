"""Unit tests for API key validation."""

import pytest

from chakravyuh.auth import ApiKey
from chakravyuh.errors import UnauthorizedError


class TestApiKey:
    def test_valid_live_key(self):
        k = ApiKey("ck_live_abc123xyz")
        assert k.is_live
        assert not k.is_test
        assert k.token == "ck_live_abc123xyz"
        assert k.bearer == "Bearer ck_live_abc123xyz"

    def test_valid_test_key(self):
        k = ApiKey("ck_test_abc123")
        assert k.is_test
        assert not k.is_live

    def test_invalid_key(self):
        with pytest.raises(UnauthorizedError):
            ApiKey("invalid_key")

    def test_empty_key(self):
        with pytest.raises(UnauthorizedError):
            ApiKey("")

    def test_whitespace_trimmed(self):
        k = ApiKey("  ck_live_abc  ")
        assert k.token == "ck_live_abc"

    def test_equality(self):
        a = ApiKey("ck_live_abc")
        b = ApiKey("ck_live_abc")
        assert a == b
        assert hash(a) == hash(b)

    def test_inequality(self):
        a = ApiKey("ck_live_abc")
        b = ApiKey("ck_live_xyz")
        assert a != b

    def test_repr_masked(self):
        k = ApiKey("ck_live_abcdef123456")
        r = repr(k)
        assert r.startswith("ApiKey(ck_live_abc")
        assert "..." in r
        assert "123456" not in r
