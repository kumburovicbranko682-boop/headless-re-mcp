"""Read-only deployments must actually refuse writes.

`local_full_access` was written by setup and loaded into Settings but never read
by anything, so a deployment that asked to be read-only still exposed the full
write surface. These pin the enforcement so the setting cannot go inert again.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.commands import CommandCatalog, CommandSpec, CommandTransport
from headless_re_mcp.mcp.adapter import register_tool
from headless_re_mcp.tools.catalog import ToolEffect


def _catalog(effects: frozenset[ToolEffect]) -> CommandCatalog:
    return CommandCatalog(
        [
            CommandSpec(
                name="probe.act",
                service_method="probe_act",
                transports=frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
                effects=effects,
            )
        ]
    )


def _register(catalog: CommandCatalog, calls: list[str]) -> None:
    def handler(value: str = "x") -> dict[str, Any]:
        """Probe."""
        calls.append(value)
        return {"ok": True, "data": {"value": value}, "error": None, "meta": {}}

    register_tool(FastMCP(name="probe"), handler, name="probe.act", catalog=catalog)


def test_a_write_tool_is_refused_when_the_deployment_is_read_only() -> None:
    catalog = _catalog(frozenset({ToolEffect.STATE_CHANGE}))
    calls: list[str] = []
    _register(catalog, calls)
    catalog.write_allowed = False

    spec = catalog.get("probe.act")
    assert spec is not None and spec.handler is not None
    result = spec.handler(value="boom")

    assert calls == [], "the handler ran despite the deployment being read-only"
    assert result["ok"] is False
    assert result["error"]["code"] == "write_disabled"
    assert result["error"]["details"]["setting"] == "local_full_access"
    # A refusal has to be an ordinary envelope, or clients see a transport fault
    # instead of a reason they can act on.
    assert set(result) == {"ok", "data", "error", "meta"}


def test_a_file_write_tool_is_refused_too() -> None:
    catalog = _catalog(frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE}))
    calls: list[str] = []
    _register(catalog, calls)
    catalog.write_allowed = False

    spec = catalog.get("probe.act")
    assert spec is not None and spec.handler is not None

    assert spec.handler()["error"]["code"] == "write_disabled"
    assert calls == []


def test_a_read_only_tool_still_runs_in_a_read_only_deployment() -> None:
    catalog = _catalog(frozenset({ToolEffect.READ_ONLY}))
    calls: list[str] = []
    _register(catalog, calls)
    catalog.write_allowed = False

    spec = catalog.get("probe.act")
    assert spec is not None and spec.handler is not None
    result = spec.handler(value="ok")

    # Read-only mode restricts writes; blocking reads would make it useless.
    assert result["ok"] is True
    assert calls == ["ok"]


def test_writes_run_normally_when_full_access_is_allowed() -> None:
    catalog = _catalog(frozenset({ToolEffect.STATE_CHANGE}))
    calls: list[str] = []
    _register(catalog, calls)

    spec = catalog.get("probe.act")
    assert spec is not None and spec.handler is not None

    assert spec.handler(value="go")["ok"] is True
    assert calls == ["go"]


def test_the_guard_is_applied_by_the_catalog_so_every_transport_gets_it() -> None:
    catalog = _catalog(frozenset({ToolEffect.STATE_CHANGE}))
    calls: list[str] = []

    def handler(value: str = "x") -> dict[str, Any]:
        """Probe."""
        calls.append(value)
        return {"ok": True, "data": None, "error": None, "meta": {}}

    # bind_handler is what the agent route and the OpenAI bridge use; guarding
    # only inside the MCP adapter left those two writable in a read-only setup.
    spec = catalog.bind_handler(
        "probe.act", handler, input_schema={"properties": {}}, description="Probe."
    )
    catalog.write_allowed = False

    assert spec.handler is not None
    assert spec.handler()["error"]["code"] == "write_disabled"
    assert calls == []


def test_the_policy_is_read_per_call_not_frozen_at_registration() -> None:
    catalog = _catalog(frozenset({ToolEffect.STATE_CHANGE}))
    calls: list[str] = []
    _register(catalog, calls)

    spec = catalog.get("probe.act")
    assert spec is not None and spec.handler is not None
    assert spec.handler(value="first")["ok"] is True
    catalog.write_allowed = False

    # Binding the decision at registration would leave a running server stuck
    # with whatever the config said at startup.
    assert spec.handler(value="second")["ok"] is False
    assert calls == ["first"]
