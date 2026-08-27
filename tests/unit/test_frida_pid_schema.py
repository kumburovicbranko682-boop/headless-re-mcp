"""frida Java tools must refuse a negative pid at the schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _pid_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["pid"]


def test_frida_java_schema_refuses_a_negative_pid() -> None:
    """Every sibling paginated/id integer (apk.*, web.*, proxy.*, device.*) is
    Field-bounded; these two declared pid as a bare int. pid=0 is the "use the
    session's last authorized pid" sentinel, so the floor is 0, not 1. The
    backend already rejects pid<=0, but that leaves the boundary to run only on
    the agent/OpenAI paths -- the MCP schema should refuse it the way the other
    tools do, as invalid_params, rather than passing a negative pid through to a
    backend permission check.
    """
    for name in ("frida.java.classes", "frida.java.methods"):
        pid = _pid_schema(name)
        assert pid.get("type") == "integer"
        assert pid.get("minimum") == 0
        assert "maximum" not in pid
