"""The tool-registration path fails loud when bindings drift from the catalog.

Every backend surface -- the Android (``apk``/``device``/``frida``), web
(``web``/``js``/``wasm``/``proxy``) and radare2/Ghidra tools alongside the PE
ones -- is registered through :func:`bind_all_tools`, which cross-checks the
handlers each factory produces against the single ``CommandCatalog``. Two
invariants keep that surface honest: no name may be bound twice, and the bound
set must equal the catalog's declared MCP set. If either slipped, a tool could
silently shadow another or a declared tool could ship with no handler. These
tests pin both guards, plus the per-builder duplicate check the factories rely
on, so a refactor cannot quietly remove them.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from headless_re_mcp.mcp.adapter import register_bound_tools
from headless_re_mcp.tools import assembly
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def _fake_analysis() -> Any:
    # bind_all_tools only reads settings.local_full_access before the guards.
    return SimpleNamespace(settings=SimpleNamespace(local_full_access=False))


def _handler(**_kwargs: Any) -> dict[str, Any]:
    return {}


def test_tool_set_builder_refuses_a_duplicate_name() -> None:
    builder = ToolSetBuilder()

    @builder.tool(name="apk.open")
    def first() -> dict[str, Any]:
        return {}

    with pytest.raises(ValueError, match="duplicate tool binding: apk.open"):

        @builder.tool(name="apk.open")
        def second() -> dict[str, Any]:
            return {}


def test_bind_all_tools_rejects_two_factories_claiming_one_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _colliding(_analysis: Any) -> tuple[BoundTool, ...]:
        return (BoundTool("web.open", _handler), BoundTool("web.open", _handler))

    monkeypatch.setattr(assembly, "TOOL_FACTORIES", (_colliding,))
    with pytest.raises(ValueError, match="duplicate protocol-independent tool binding"):
        bind_all_tools(_fake_analysis(), CommandCatalog())


def test_bind_all_tools_rejects_a_binding_the_catalog_never_declared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _phantom(_analysis: Any) -> tuple[BoundTool, ...]:
        return (BoundTool("phantom.tool", _handler),)

    monkeypatch.setattr(assembly, "TOOL_FACTORIES", (_phantom,))
    with pytest.raises(ValueError, match="tool binding mismatch") as info:
        bind_all_tools(_fake_analysis(), CommandCatalog())
    message = str(info.value)
    # The undeclared name is named as extra, and the real catalog names it missed.
    assert "phantom.tool" in message
    assert "extra=" in message and "missing=" in message


def test_register_bound_tools_refuses_a_command_the_catalog_keeps_off_mcp() -> None:
    """A transport declaration is a promise, not a comment.

    The catalog can declare a command agent-only (or CLI-only); if the MCP
    adapter registered it anyway, the surface an operator audited via the
    catalog and the surface a client can actually call would quietly diverge.
    Registration must stop at the first such name rather than ship it.
    """

    def handler() -> dict[str, Any]:
        """Agent-only probe."""
        return {"ok": True, "data": {}, "error": None, "meta": {}}

    catalog = CommandCatalog(
        [
            CommandSpec(
                name="agent.only",
                service_method="agent_only",
                transports=frozenset({CommandTransport.AGENT}),
                effects=frozenset({ToolEffect.READ_ONLY}),
            )
        ]
    )
    with pytest.raises(ValueError, match="not exposed over MCP: agent.only"):
        register_bound_tools(
            FastMCP(name="probe"),
            [BoundTool("agent.only", handler)],
            catalog=catalog,
        )
