"""Recursive secret redaction shared by provider, API, audit and SSE paths.

This also runs over tool results, which is what keeps it narrow. The results
carry what the analysis found in the target: strings, dumps, symbol names. A
credential hardcoded in a sample is the deliverable, not a leak, so matching
secret-looking *values* would destroy the finding the run was started to
produce. Only key names are matched, and only names that belong to
configuration rather than to anything a binary could be described with --
"cookie" is deliberately absent, because ``__security_cookie`` is a real symbol
in almost every Windows binary.
"""

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
