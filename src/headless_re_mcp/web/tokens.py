"""Constant-time credential comparison for the web console's auth checks."""

from __future__ import annotations

import secrets

__all__ = ["tokens_match"]


def tokens_match(provided: str, expected: str) -> bool:
    """Compare two tokens in constant time, tolerating non-ASCII input.

    ``secrets.compare_digest`` raises ``TypeError`` the moment a ``str`` operand
    holds any non-ASCII character, so a request whose ``?token=`` value, Bearer
    header, or bootstrap cookie contained one turned the promised clean 401 into
    an uncaught 500 with a logged incident. The cookie path makes that worse: it
    runs from the cookie-promotion middleware on every request, so one malformed
    cookie 500s the whole console rather than a single call.

    Comparing the UTF-8 encodings keeps the timing guarantee (``compare_digest``
    on ``bytes`` has no such restriction) while treating a credential that could
    never have been minted here as simply wrong.
    """
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
