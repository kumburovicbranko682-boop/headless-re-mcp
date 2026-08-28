"""web.wait must advertise its DOM-state allow-list in the tool schema.

The four Playwright wait states (visible / hidden / attached / detached) live in
the backend's ``_WAIT_STATES``, which re-validates for the agent and OpenAI
transports that call handlers directly and skip the pydantic schema. But the
tool param was a bare ``str``, so the MCP schema advertised no allow-list: a
client could not offer the choices and a bad state only failed after a browser
worker was already claimed -- unlike frida.hook.template and workspace.mode.set,
whose enums are pinned in the schema. The param now carries the same
``Field(pattern=...)`` constraint, and this ties that pattern to the backend's
allow-list so the two cannot drift: a state added to one must be added to the
other.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.backends.web.client import _WAIT_STATES
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.web import build_web_tools


def test_web_wait_state_schema_matches_the_backend_allow_list() -> None:
    handler = next(
        binding.handler
        for binding in build_web_tools(cast(Any, object()))
        if binding.name == "web.wait"
    )
    state = input_schema_for(handler)["properties"]["state"]

    # The schema advertises exactly the backend's allow-list, in order, so an MCP
    # client rejects an unknown state up front instead of spending a worker on a
    # wait that the backend would only refuse after attaching.
    assert state.get("pattern") == "^(" + "|".join(_WAIT_STATES) + ")$"
    # The default must itself satisfy the advertised pattern.
    assert state.get("default") in _WAIT_STATES
