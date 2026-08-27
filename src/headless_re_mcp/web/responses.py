"""A JSONResponse that degrades instead of 500ing on hostile-influenced content.

Starlette renders with ensure_ascii=False, allow_nan=False and then encodes to
UTF-8, all inside JSONResponse.__init__. Two values that reach route payloads
from outside break that render: an unpaired surrogate (json.loads accepts a
lone \\ud800 escape, so backend JSON parses pass one through from a hostile
binary's strings) raises UnicodeEncodeError, and a non-finite float from a
backend's JSON raises ValueError. Either way the endpoint 500s over one bad
value in an otherwise good payload, which for the console means a dead panel
instead of a '?' in a string field.
"""

from __future__ import annotations

import math
from typing import Any

from starlette.responses import JSONResponse as _StarletteJSONResponse

# Payloads are ok/data/error/meta envelopes, nowhere near this deep. The cap
# only exists so that the one-off repair walk cannot itself recurse away on a
# pathological structure whose render failed for depth in the first place.
_MAX_REPAIR_DEPTH = 64


def _repaired(value: Any, depth: int = 0) -> Any:
    """The JSON-compliant twin of value: finite floats, UTF-8 encodable text."""
    if depth >= _MAX_REPAIR_DEPTH:
        return None
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return value.encode("utf-8", "replace").decode("utf-8")
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {
            (_repaired(key, depth + 1) if isinstance(key, str) else key): _repaired(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_repaired(item, depth + 1) for item in value]
    return value


class JSONResponse(_StarletteJSONResponse):
    def render(self, content: Any) -> bytes:
        try:
            return super().render(content)
        except (UnicodeEncodeError, ValueError, RecursionError):
            return super().render(_repaired(content))
