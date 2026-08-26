"""Cursor calls tools with underscores; the alias must resolve without clashing.

Cursor sends ``static_functions`` where the catalog registers
``static.functions``. install_cursor_underscore_aliases resolves that at
get_tool time without adding a second ListTools entry. It builds the
underscore->dotted map with a plain dict, so two dotted names that collapse to
the same underscore form would silently shadow each other -- the OpenAI bridge
guards that class of collision, this path does not. The catalog has multi-dot
names (breakpoints.condition.set), so the collision is not hypothetical; pin
that the shipped surface stays collision-free, and pin the resolution itself.
"""

from __future__ import annotations

from collections import defaultdict

from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandTransport
from headless_re_mcp.mcp.adapter import install_cursor_underscore_aliases


def test_no_two_shipped_tool_names_collapse_to_the_same_underscore_form() -> None:
    buckets: dict[str, list[str]] = defaultdict(list)
    for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP):
        buckets[spec.name.replace(".", "_")].append(spec.name)
    collisions = {form: names for form, names in buckets.items() if len(names) > 1}
    assert not collisions, (
        "dotted tool names collide once dots become underscores, so the Cursor "
        f"alias would silently shadow one: {collisions}"
    )


class _FakeToolManager:
    """Minimal stand-in for FastMCP's tool manager: a name->tool dict."""

    def __init__(self, names: list[str]) -> None:
        self._tools = {name: f"tool:{name}" for name in names}

    def get_tool(self, name: str) -> object | None:
        return self._tools.get(name)


class _FakeServer:
    def __init__(self, names: list[str]) -> None:
        self._tool_manager = _FakeToolManager(names)


def test_an_underscore_call_resolves_to_the_dotted_tool() -> None:
    server = _FakeServer(["static.functions", "breakpoints.condition.set", "doctor"])
    install_cursor_underscore_aliases(server)  # type: ignore[arg-type]
    get = server._tool_manager.get_tool

    # The dotted name still resolves directly.
    assert get("static.functions") == "tool:static.functions"
    # The underscore form Cursor sends now resolves to the same tool...
    assert get("static_functions") == "tool:static.functions"
    # ...including multi-segment names.
    assert get("breakpoints_condition_set") == "tool:breakpoints.condition.set"
    # A name with no dot needs no alias and is unaffected.
    assert get("doctor") == "tool:doctor"
    # A genuinely unknown name is still unresolved (no accidental catch-all).
    assert get("nope_not_here") is None


def test_installing_aliases_is_a_noop_when_no_name_has_a_dot() -> None:
    server = _FakeServer(["doctor", "healthz"])
    install_cursor_underscore_aliases(server)  # type: ignore[arg-type]
    # With nothing to alias, get_tool is left as the original bound method
    # rather than being replaced by the aliasing closure. (Bound methods are
    # fresh objects each access, so compare the underlying function.)
    resolver = server._tool_manager.get_tool
    assert getattr(resolver, "__func__", None) is _FakeToolManager.get_tool
    assert resolver("doctor") == "tool:doctor"
