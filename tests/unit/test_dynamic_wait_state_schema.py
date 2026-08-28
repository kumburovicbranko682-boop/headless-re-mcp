"""dynamic.wait must advertise its state parameter as the debugger-state enum.

``AnalysisService.dynamic_wait`` rejects any state outside
``{"idle", "running", "paused"}`` with a ``ValueError``. The tool declared the
parameter a bare ``str``, so the schema promised "any string": an agent asking
to wait for ``"stopped"`` or ``"suspended"`` passed schema validation and only
learned the value was wrong after the request reached the service, and the three
real states were never visible in the schema. Pinning it to a ``Literal`` turns
the schema into an enum, refusing bad values before dispatch.
"""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.dynamic import WaitState, build_dynamic_tools


def _wait_schema() -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_dynamic_tools(object())  # type: ignore[arg-type]
        if binding.name == "dynamic.wait"
    )
    return input_schema_for(handler)


def _service_wait_states() -> set[str]:
    """The exact allowlist AnalysisService.dynamic_wait enforces, from source."""
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service.py"
    ).read_text(encoding="utf-8")
    match = re.search(r"if state not in \{([^}]*)\}", source)
    assert match, "could not find the dynamic_wait state guard in service.py"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def test_dynamic_wait_state_schema_matches_the_service_allowlist() -> None:
    schema = _wait_schema()
    state = schema["properties"]["state"]  # type: ignore[index]
    # Required (no default), so it is a plain enum rather than an anyOf-with-null.
    assert "state" in schema["required"]  # type: ignore[operator]
    assert set(state["enum"]) == _service_wait_states()  # type: ignore[index]


def test_wait_state_literal_is_the_service_allowlist() -> None:
    from typing import get_args

    # The Literal the tool publishes and the set the service enforces agree, so a
    # future change to one without the other is caught here.
    assert set(get_args(WaitState)) == _service_wait_states()
