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


@pytest.mark.integration
@pytest.mark.headless
def test_mcp_static_idalib_session_round_trip() -> None:
    binary = os.environ.get("HEADLESS_RE_IDA_GATE_BINARY")
    if not binary:
        pytest.skip("HEADLESS_RE_IDA_GATE_BINARY is not configured")

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
    binary = os.environ.get("HEADLESS_RE_IDA_GATE_BINARY")
    if not binary:
        pytest.skip("HEADLESS_RE_IDA_GATE_BINARY is not configured")

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
