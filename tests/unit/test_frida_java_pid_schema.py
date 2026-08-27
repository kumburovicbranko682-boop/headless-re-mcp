"""frida.java.* must refuse a negative pid at the tool schema.

The repo-wide "bound the numeric argument at the schema, not one dispatch
later" pass reached every paged tool and the native region/import caps. The
two Java enumeration tools were the last frida arguments left unbounded: pid
was a plain int with default 0. The service reads 0 as "use the session's most
recently spawned/attached pid" and forwards any other value to the frida
client, whose _authorize rejects `pid <= 0` with invalid_params and a pid
outside the authorized set with permission_denied -- but only after the tool is
already dispatched to the backend. Pin the floor to 0 (which keeps the sentinel
valid) so a negative pid is refused at the MCP edge, matching every sibling
numeric argument.
"""

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


def test_frida_java_tools_refuse_a_negative_pid() -> None:
    """Both Java enumeration tools carry pid minimum 0 and no upper bound."""
    for name in ("frida.java.classes", "frida.java.methods"):
        pid = _pid_schema(name)
        assert pid.get("type") == "integer"
        assert pid.get("minimum") == 0
        assert "maximum" not in pid
