"""API key validation and authorization header handling.

Supports ``ck_live_*`` (production) and ``ck_test_*`` (sandbox) token formats.
"""

from __future__ import annotations

import re

from .errors import UnauthorizedError

_KEY_PATTERN = re.compile(r"^(ck_live_|ck_test_)\S+$")


class ApiKey:
    """A validated API key for CHAKRAVYUH OS.

    The key must start with ``ck_live_`` or ``ck_test_``.

    Args:
        key: The raw API key string.

    Raises:
        UnauthorizedError: If the key does not match the required format.

    Examples:
        >>> k = ApiKey("ck_live_xxxxxxxxx")
        >>> k.is_live
        True
        >>> k.bearer
        'Bearer ck_live_xxxxxxxxx'
    """

    __slots__ = ("_key",)

    def __init__(self, key: str) -> None:
        stripped = key.strip()
        if not _KEY_PATTERN.match(stripped):
            raise UnauthorizedError(
                f"Invalid API key format. Expected 'ck_live_*' or 'ck_test_*'."
            )
        self._key = stripped

    @property
    def token(self) -> str:
        """The raw token string."""
        return self._key

    @property
    def bearer(self) -> str:
        """The ``Authorization`` header value (``Bearer ck_live_...``)."""
        return f"Bearer {self._key}"

    @property
    def is_live(self) -> bool:
        """``True`` if this is a production (live) key."""
        return self._key.startswith("ck_live_")

    @property
    def is_test(self) -> bool:
        """``True`` if this is a sandbox/test key."""
        return self._key.startswith("ck_test_")

    def __repr__(self) -> str:
        prefix = self._key[:12]
        return f"ApiKey({prefix}...)"

    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ApiKey):
            return self._key == other._key
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._key)
