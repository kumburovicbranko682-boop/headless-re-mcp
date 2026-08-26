"""Recursive credential redaction shared across persistent and public payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|private[_-]?key|access[_-]?key|authorization|token|secret"
    r"|password|passwd|credential|providerApiKeys)",
    re.I,
)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
MAX_DEPTH = 250


def is_secret_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY.search(key))


def _could_hold_a_credential(value: Any, _depth: int = 0) -> bool:
    """Return whether a value under a secret-looking key can contain text."""
    if _depth >= MAX_DEPTH:
        return True
    if isinstance(value, (bool, int, float)):
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_could_hold_a_credential(item, _depth + 1) for item in value)
    return True


def redact(value: Any, *, mask: str = "***REDACTED***", _depth: int = 0) -> Any:
    """Recursively mask credential fields and bearer values.

    Key names are matched instead of secret-looking values because reverse
    engineering results legitimately contain credentials found in the target.
    Numeric metadata tokens remain visible.
    """
    if _depth >= MAX_DEPTH:
        return {"redaction_depth_exceeded": True, "depth": MAX_DEPTH}
    if isinstance(value, Mapping):
        return {
            str(key): mask
            if is_secret_key(key) and _could_hold_a_credential(item)
            else redact(item, mask=mask, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item, mask=mask, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return _BEARER.sub(f"Bearer {mask}", value)
    return value


def masked_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "********"
    return f"{value[:2]}…{value[-2:]}"
