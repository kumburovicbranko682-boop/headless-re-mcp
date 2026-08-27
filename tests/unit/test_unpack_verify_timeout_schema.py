"""``unpack.verify`` must advertise the deadline the service actually enforces.

The tool's ``timeout`` only bounds the optional DIE rescan: the service runs it
through ``_detection_timeout``, which raises for anything over
``MAX_WORKFLOW_TIMEOUT`` (300s). The ``open_ida`` reopen it once claimed to need
a wider ceiling for runs on ``open_static``'s own timeout, not this parameter.
The schema nonetheless advertised ``le=600``, so an in-schema ``timeout=400``
passed MCP validation only to be refused downstream as "timeout must be greater
than 0 and at most 300 seconds" -- a ceiling the caller was never told about.
Pin the advertised maximum to the enforced one so the two cannot drift apart
again, matching the sibling external-unpacker tools that share the gate.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.service import _detection_timeout
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools


def _timeout_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["timeout"]


def test_unpack_verify_schema_ceiling_matches_the_enforced_detection_cap() -> None:
    schema = _timeout_schema("unpack.verify")
    assert schema.get("type") == "number"
    assert schema.get("exclusiveMinimum") == 0
    assert schema.get("maximum") == MAX_WORKFLOW_TIMEOUT == 300.0


def test_detection_timeout_rejects_just_past_the_advertised_ceiling() -> None:
    """The value the schema advertises as the maximum must be accepted and one
    step past it refused, or the schema is lying about the deadline again."""
    assert _detection_timeout(300.0) == 300.0
    with pytest.raises(ValueError):
        _detection_timeout(300.0001)
    with pytest.raises(ValueError):
        _detection_timeout(600.0)
