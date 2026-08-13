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
MAX_DEPTH = 250


def is_secret_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY.search(key))


def _could_hold_a_credential(value: Any, _depth: int = 0) -> bool:
    """A credential is text. A metadata token is a number.

    "token" matches the same way "cookie" would have, and a .NET metadata token
    is exactly the sort of thing a binary is described with. Measured against
    real payloads: dotnet.il returned call_tokens as ***REDACTED***, so the
    agent could not follow a single call; the token column of an enumerate
    listing went the same way, as did metadata_token and the token_handle of a
    thread. Nothing said the values had been suppressed rather than missing.

    Checking the value rather than narrowing the key keeps every string token
    masked, which is the shape an actual credential arrives in.
    """
    if _depth >= MAX_DEPTH:
        # This walks the value on its own, so redact's depth counter does not
        # cover it: a secret key holding a list nested three thousand deep
        # raised RecursionError here while the same list under an ordinary key
        # was fine. Too deep to inspect means masked, which is the safe answer
        # for a value already sitting under a credential's name.
        return True
    if isinstance(value, (bool, int, float)):
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_could_hold_a_credential(item, _depth + 1) for item in value)
    return True


def redact(value: Any, *, _depth: int = 0) -> Any:
    if _depth >= MAX_DEPTH:
        # This walks every tool argument and every tool result, and it recurses.
        # Python gives up at 1000 frames, and a structure 2000 deep encoded in
        # 14 KB -- comfortably inside the argument size bound -- raised
        # RecursionError from inside the store transaction, failing the run with
        # nothing to explain it. Real payloads are nowhere near: the whole
        # 263-tool schema export is 12 deep and a detection report is 7.
        return {"redaction_depth_exceeded": True, "depth": MAX_DEPTH}
    if isinstance(value, Mapping):
        return {
            str(key): "***REDACTED***"
            if is_secret_key(key) and _could_hold_a_credential(item)
            else redact(item, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer ***REDACTED***", value)
    return value


def masked_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "********"
    return f"{value[:2]}…{value[-2:]}"
