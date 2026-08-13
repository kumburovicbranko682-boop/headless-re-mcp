"""Recursive secret redaction shared by provider, API, audit and SSE paths."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_SECRET_KEY = re.compile(r"(?:api[_-]?key|authorization|token|secret|password|providerApiKeys)", re.I)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")


def is_secret_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY.search(key))


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "***REDACTED***" if is_secret_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer ***REDACTED***", value)
    return value


def masked_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "********"
    return f"{value[:2]}…{value[-2:]}"
