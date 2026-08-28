from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject


def _session_id(data: JsonObject | None) -> str:
    assert data is not None
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _require_ida_gate_binary() -> str:
    """Return the gate binary, or skip when either precondition is missing.

    The binary path and IDA are independent: conftest's _default_ida_gate_binary
    points HEADLESS_RE_IDA_GATE_BINARY at the native fixture whenever that fixture
    exists (built for the r2/other gates), which says nothing about whether IDA is
    installed. Guarding on the path alone let these two gates proceed to
    static.open on any machine that has the fixtures but no IDA, where the service
    returns backend_unavailable ("IDA home is not configured") and the round trip
    fails -- a missing backend read as a failure, the skip-as-failure inversion
    this suite forbids.
    """
    binary = os.environ.get("HEADLESS_RE_IDA_GATE_BINARY")
    if not binary:
        pytest.skip("HEADLESS_RE_IDA_GATE_BINARY is not configured")
    if Settings.load().ida_home is None:
        pytest.skip("IDA home is not configured — idalib Gate not run (skip != pass)")
    return binary


@pytest.mark.integration
@pytest.mark.headless
def test_mcp_static_idalib_session_round_trip() -> None:
    binary = _require_ida_gate_binary()

    service = AnalysisService(Settings.load())
    created = service.create_session(binary)
    assert created.ok, created.model_dump(mode="json")
    session_id = _session_id(created.data)
    try:
        opened = service.open_static(session_id)
        assert opened.ok, opened.model_dump(mode="json")

        functions = service.static_functions(session_id, limit=10)
        assert functions.ok, functions.model_dump(mode="json")
        assert functions.data is not None
        assert functions.data["items"]

        strings = service.static_strings(session_id, limit=10)
        assert strings.ok, strings.model_dump(mode="json")
        assert strings.data is not None
        assert strings.data["items"]

        decompiled = service.static_decompile(session_id)
        assert decompiled.ok, decompiled.model_dump(mode="json")
        assert decompiled.data is not None
        assert decompiled.data["code"]
    finally:
        closed = service.close_session(session_id)
        assert closed.ok, closed.model_dump(mode="json")


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict)
    return content


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_mcp_stdio_protocol_round_trip() -> None:
    binary = _require_ida_gate_binary()

    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=os.environ.copy(),
        cwd=project_root,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = await client.list_tools()
        assert "static.functions" in {tool.name for tool in tools.tools}

        created = _structured(
            await client.call_tool("session.create", {"binary": binary})
        )
        assert created["ok"] is True
        session_id = _session_id(created["data"])
        try:
            opened = _structured(
                await client.call_tool("static.open", {"session_id": session_id})
            )
            assert opened["ok"] is True

            functions = _structured(
                await client.call_tool(
                    "static.functions",
                    {"session_id": session_id, "limit": 5},
                )
            )
            assert functions["ok"] is True
            assert functions["data"]["items"]

            decompiled = _structured(
                await client.call_tool(
                    "static.decompile", {"session_id": session_id}
                )
            )
            assert decompiled["ok"] is True
            assert decompiled["data"]["code"]
        finally:
            closed = _structured(
                await client.call_tool(
                    "session.close", {"session_id": session_id}
                )
            )
            assert closed["ok"] is True
