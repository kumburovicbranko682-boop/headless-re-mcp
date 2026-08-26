"""Read-only deployments must actually refuse writes.

`local_full_access` was written by setup and loaded into Settings but never read
by anything, so a deployment that asked to be read-only still exposed the full
write surface. These pin the enforcement so the setting cannot go inert again.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from headless_re_mcp.config import Settings
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


def _loaded_full_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    env: str | None,
    config_value: object = "unset",
) -> bool:
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    if env is None:
        monkeypatch.delenv("HEADLESS_RE_LOCAL_FULL_ACCESS", raising=False)
    else:
        monkeypatch.setenv("HEADLESS_RE_LOCAL_FULL_ACCESS", env)
    if config_value == "unset":
        return Settings.load(tmp_path / "missing-config.json").local_full_access
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"local_full_access": config_value}), encoding="utf-8")
    return Settings.load(config).local_full_access


def test_read_only_is_the_opt_in_and_full_access_is_the_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The switch that flips a deployment read-only is the env/JSON parse itself.

    The guard above reads catalog.write_allowed, which bind_all_tools copies
    from Settings.local_full_access. If a falsy env string failed to parse to
    False the whole write surface would quietly reopen, so pin the parse: no
    configuration is full access, and only the falsy tokens turn writes off.
    """
    assert _loaded_full_access(monkeypatch, tmp_path, env=None) is True


@pytest.mark.parametrize("falsy", ["0", "false", "False", "no", "off", "  OFF  "])
def test_a_falsy_switch_makes_the_deployment_read_only(
    falsy: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _loaded_full_access(monkeypatch, tmp_path, env=falsy) is False


@pytest.mark.parametrize("truthy", ["1", "true", "yes", "on", "enabled"])
def test_a_truthy_switch_keeps_full_access(
    truthy: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert _loaded_full_access(monkeypatch, tmp_path, env=truthy) is True


def test_a_json_key_can_request_read_only_and_env_overrides_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A JSON config alone can select read-only.
    assert _loaded_full_access(monkeypatch, tmp_path, env=None, config_value=False) is False
    # Env wins over JSON in both directions.
    assert _loaded_full_access(monkeypatch, tmp_path, env="1", config_value=False) is True
    assert _loaded_full_access(monkeypatch, tmp_path, env="off", config_value=True) is False
