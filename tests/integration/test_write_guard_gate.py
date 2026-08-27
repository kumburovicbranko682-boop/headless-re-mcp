"""Write-effect guard gate: a read-only deployment refuses every write over MCP.

Every tool carries an explicit effects policy (read-only / state-change /
file-write) and ``local_full_access=0`` is the switch that turns a deployment
read-only. The contract this gate pins, end to end through a real
``headless_re_mcp serve`` process:

* every advertised write tool answers ``write_disabled`` -- not a subset, not
  a sample, all of them, across every backend family (session, static,
  dynamic, unpack, apk, device, web, proxy, frida, r2, ghidra, windbg, ...);
* the refusal is an ordinary error envelope naming the tool and the setting,
  so a caller learns why instead of watching tools vanish: the read-only
  server advertises exactly the same tool surface as the full-access one;
* the guard answers before the handler runs -- a fully valid ``session.create``
  against a real committed PE is refused and leaves no session behind;
* read tools keep answering in read-only mode, and flipping the one setting
  makes the very same write calls succeed.

Pure Python end to end: no analysis backend is consulted because the guard
refuses (or the sqlite ledger answers) before any backend would be reached.
Runs on every platform.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.tools.catalog import CommandCatalog, CommandTransport

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

# Families that must appear among the refused tools, so a regression that
# quietly drops one backend's tools from the write policy cannot pass.
_EXPECTED_WRITE_FAMILIES = frozenset(
    {
        "session",
        "knowledge",
        "report",
        "artifacts",
        "batch",
        "static",
        "dynamic",
        "patches",
        "unpack",
        "trace",
        "workflow",
        "apk",
        "device",
        "web",
        "proxy",
        "frida",
        "r2",
        "ghidra",
        "windbg",
        "ui",
    }
)


@asynccontextmanager
async def _mcp_client(artifact_root: Path, *, full_access: bool) -> AsyncIterator[ClientSession]:
    """A real MCP stdio server whose whole state lives under ``artifact_root``."""
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    env["HEADLESS_RE_LOCAL_FULL_ACCESS"] = "1" if full_access else "0"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


async def _call(client: ClientSession, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await client.call_tool(tool, arguments)
    payload = getattr(result, "structuredContent", None)
    assert isinstance(payload, dict), f"{tool} left the error envelope: {result.content!r}"
    return payload


def _synthesize_value(name: str, schema: dict[str, Any], defs: dict[str, Any]) -> Any:
    """A value that satisfies the advertised JSON schema for one property.

    The guard answers before any handler runs, so the values never need to
    make semantic sense -- they only have to get past protocol validation so
    the refusal (not a validation error) is what comes back.
    """
    if "$ref" in schema:
        target = defs.get(str(schema["$ref"]).rsplit("/", 1)[-1], {})
        properties = target.get("properties", {})
        required = list(target.get("required", []))
        if not required and properties:
            # Selector-style models accept any one of their fields but not none.
            required = [next(iter(properties))]
        return {key: _synthesize_value(key, properties.get(key, {}), defs) for key in required}
    if "enum" in schema:
        return schema["enum"][0]
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            if option.get("type") != "null":
                return _synthesize_value(name, option, defs)
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((entry for entry in kind if entry != "null"), "string")
    if kind == "string":
        pattern = schema.get("pattern", "")
        alternatives = re.fullmatch(r"\^\((\w+)(?:\|\w+)*\)\$", pattern)
        if alternatives:
            return alternatives.group(1)
        hex_run = re.fullmatch(r"\^\[0-9a-fA-F\]\{(\d+)\}\$", pattern)
        if hex_run:
            return "f" * int(hex_run.group(1))
        length = max(schema.get("minLength", 1), 32 if "session" in name else 1)
        return ("f" if "session" in name else "x") * length
    if kind in {"integer", "number"}:
        value = 1
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            value = minimum
        if maximum is not None and value > maximum:
            value = maximum
        return value
    if kind == "boolean":
        return False
    if kind == "array":
        item = schema.get("items", {})
        return [_synthesize_value(name, item, defs)] * int(schema.get("minItems", 0))
    if kind == "object":
        return {}
    return "x"


def _synthesize_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.get("$defs", {})
    properties = schema.get("properties", {})
    return {
        name: _synthesize_value(name, properties.get(name, {}), defs)
        for name in schema.get("required", [])
    }


def _mcp_tool_names(catalog: CommandCatalog) -> set[str]:
    return {spec.name for spec in catalog.for_transport(CommandTransport.MCP)}


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_read_only_mode_refuses_every_advertised_write_tool(tmp_path: Path) -> None:
    """All write tools stay discoverable and every one of them is refused."""
    catalog = CommandCatalog()
    async with _mcp_client(tmp_path / "readonly", full_access=False) as client:
        listed = await client.list_tools()
        tools = {tool.name: tool for tool in listed.tools}

        # Read-only mode hides nothing: the advertised surface is exactly the
        # catalog's MCP transport. Refusal-at-call-time, not disappearance.
        assert set(tools) == _mcp_tool_names(catalog)

        write_names = sorted(catalog.write_names(CommandTransport.MCP))
        assert len(write_names) >= 100, "write policy shrank suspiciously"
        for name in write_names:
            arguments = _synthesize_arguments(tools[name].inputSchema or {})
            payload = await _call(client, name, arguments)
            assert payload["ok"] is False, f"{name} executed in read-only mode: {payload}"
            error = payload["error"]
            assert error["code"] == "write_disabled", (name, error)
            assert error["details"] == {"tool": name, "setting": "local_full_access"}, name
            assert error["retryable"] is False, name
            assert "read-only" in error["message"], name

        families = {name.split(".", 1)[0] for name in write_names}
        missing = _EXPECTED_WRITE_FAMILIES - families
        assert not missing, f"write policy no longer covers: {sorted(missing)}"


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_refusal_precedes_execution_and_reads_stay_served(tmp_path: Path) -> None:
    """A fully valid write is refused before it runs; read tools keep working."""
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    async with _mcp_client(tmp_path / "readonly", full_access=False) as client:
        # Nothing wrong with the arguments: the binary exists and would open.
        refused = await _call(client, "session.create", {"binary": str(_PE_FIXTURE)})
        assert refused["ok"] is False
        assert refused["error"]["code"] == "write_disabled"

        # ...and the refusal left no trace: the session ledger is still empty.
        sessions = await _call(client, "session.list", {})
        assert sessions["ok"] is True, sessions
        assert sessions["data"]["sessions"] == []
        assert sessions["data"]["total"] == 0

        # The read surface answers normally rather than the server going dark.
        capabilities = await _call(client, "capabilities.search", {})
        assert capabilities["ok"] is True, capabilities
        assert capabilities["data"]["count"] >= 1

        metrics = await _call(client, "meta.metrics", {"limit": 5})
        assert metrics["ok"] is True, metrics


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_full_access_toggle_allows_the_same_write_path(tmp_path: Path) -> None:
    """Flipping local_full_access is the only difference: same calls succeed."""
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    catalog = CommandCatalog()
    async with _mcp_client(tmp_path / "full", full_access=True) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == _mcp_tool_names(catalog)

        created = await _call(client, "session.create", {"binary": str(_PE_FIXTURE)})
        assert created["ok"] is True, created
        session_id = str(created["data"]["session"]["id"])

        recorded = await _call(
            client,
            "knowledge.record",
            {
                "session_id": session_id,
                "kind": "function",
                "key": "write-guard-gate",
                "value": {"observed": "writes flow when the deployment allows them"},
            },
        )
        assert recorded["ok"] is True, recorded

        report = await _call(client, "report.generate", {"session_id": session_id})
        assert report["ok"] is True, report

        closed = await _call(client, "session.close", {"session_id": session_id})
        assert closed["ok"] is True, closed
