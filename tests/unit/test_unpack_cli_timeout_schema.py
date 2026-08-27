"""The external-unpacker CLI tools must advertise the deadline the service enforces.

``unpack.xvlkc.unpack`` / ``unpack.vmp.dump`` / ``unpack.scylla.rebuild`` all run
their ``timeout`` through ``_detection_timeout``, which raises for anything over
``MAX_WORKFLOW_TIMEOUT`` (300s). The schemas used to advertise ``le=600``, so an
in-schema ``timeout=400`` passed MCP validation only to be refused downstream as
"timeout must be greater than 0 and at most 300 seconds" -- a ceiling the caller
was never told about. Pin the advertised maximum to the enforced one so the two
cannot drift apart again.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.service import _detection_timeout
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools

_DETECTION_CAPPED = ("unpack.xvlkc.unpack", "unpack.vmp.dump", "unpack.scylla.rebuild")


def _timeout_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["timeout"]


@pytest.mark.parametrize("name", _DETECTION_CAPPED)
def test_the_schema_ceiling_matches_the_enforced_detection_cap(name: str) -> None:
    schema = _timeout_schema(name)
    assert schema.get("type") == "number"
    assert schema.get("exclusiveMinimum") == 0
    assert schema.get("maximum") == MAX_WORKFLOW_TIMEOUT == 300.0


def test_detection_timeout_rejects_just_past_the_advertised_ceiling() -> None:
    """The value the schema now advertises as the maximum must be accepted, and
    one step past it refused -- otherwise the schema is lying again."""
    assert _detection_timeout(300.0) == 300.0
    with pytest.raises(ValueError):
        _detection_timeout(300.0001)
    with pytest.raises(ValueError):
        _detection_timeout(600.0)
