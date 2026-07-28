from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DYNAMIC_TOOLS = frozenset(
    {
        "dynamic.open",
        "dynamic.state",
        "dynamic.events",
        "dynamic.wait",
        "dynamic.launch",
        "dynamic.attach",
        "dynamic.stop",
        "dynamic.pause",
        "dynamic.resume",
        "dynamic.step_into",
        "dynamic.step_over",
        "dynamic.registers.read",
        "dynamic.registers.write",
        "dynamic.memory.read",
        "dynamic.memory.write",
        "dynamic.modules",
        "dynamic.breakpoints",
        "dynamic.breakpoint.set",
        "dynamic.breakpoint.remove",
        "workflow.status",
        "workflow.events.consume",
    }
)


def _configured_fixture(variable: str, architecture: Architecture) -> Path:
    if not os.environ.get(variable):
        pytest.skip(f"{variable} is not configured")
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture is not built: {fixture}")
    return fixture


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict)
    return content


async def _call(
    client: ClientSession,
    tool: str,
    arguments: JsonObject,
) -> JsonObject:
    result = _structured(await client.call_tool(tool, arguments))
    assert result["ok"] is True, result
    data = result.get("data")
    assert isinstance(data, dict)
    return data


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("variable", "architecture", "instruction_pointer", "accumulator"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86, "eip", "eax"),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64, "rip", "rax"),
    ],
)
async def test_mcp_stdio_dynamic_round_trip(
    variable: str,
    architecture: Architecture,
    instruction_pointer: str,
    accumulator: str,
) -> None:
    fixture = _configured_fixture(variable, architecture)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=os.environ.copy(),
        cwd=_PROJECT_ROOT,
    )

    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = await client.list_tools()
        tool_names = {tool.name for tool in tools.tools}
        assert tool_names >= _DYNAMIC_TOOLS
        assert "dynamic.command" not in tool_names

        created = await _call(client, "session.create", {"binary": str(fixture)})
        session = created["session"]
        assert isinstance(session, dict)
        session_id = str(session["id"])
        try:
            opened = await _call(client, "dynamic.open", {"session_id": session_id})
            backend = opened["backend"]
            assert isinstance(backend, dict)
            assert backend["architecture"] == architecture.value

            state = await _call(client, "dynamic.state", {"session_id": session_id})
            assert state["state"] == "idle"
            initial_events = await _call(
                client,
                "dynamic.events",
                {"session_id": session_id, "limit": 1},
            )
            assert initial_events["events"] == []
            assert initial_events["next_cursor"] == 0
            launched = await _call(
                client,
                "dynamic.launch",
                {
                    "session_id": session_id,
                    "arguments": "--debug-wait",
                    "timeout": 30.0,
                },
            )
            assert launched["state"]["state"] == "paused"

            initial_workflow_data = await _call(
                client,
                "workflow.status",
                {"session_id": session_id},
            )
            initial_workflow = initial_workflow_data["workflow"]
            assert isinstance(initial_workflow, dict)
            workflow_id = str(initial_workflow["id"])
            initial_workflow_state = initial_workflow["state"]
            assert isinstance(initial_workflow_state, dict)
            assert initial_workflow_state["cursor"] == 0

            first_events = await _call(
                client,
                "dynamic.events",
                {"session_id": session_id, "limit": 1, "timeout": 5.0},
            )
            assert first_events["cursor"] == 0
            assert first_events["count"] == 1
            assert first_events["next_cursor"] > 0
            assert first_events["has_more"] is True
            first_cursor = int(first_events["next_cursor"])
            workflow_after_dynamic_data = await _call(
                client,
                "workflow.status",
                {"session_id": session_id},
            )
            workflow_after_dynamic = workflow_after_dynamic_data["workflow"]
            assert isinstance(workflow_after_dynamic, dict)
            assert workflow_after_dynamic["id"] == workflow_id
            workflow_after_dynamic_state = workflow_after_dynamic["state"]
            assert isinstance(workflow_after_dynamic_state, dict)
            assert workflow_after_dynamic_state["cursor"] == first_cursor

            second_events = await _call(
                client,
                "workflow.events.consume",
                {"session_id": session_id, "limit": 2},
            )
            assert second_events["cursor"] == first_cursor
            assert second_events["next_cursor"] > first_cursor
            workflow_after_consume_data = await _call(
                client,
                "workflow.status",
                {"session_id": session_id},
            )
            workflow_after_consume = workflow_after_consume_data["workflow"]
            assert isinstance(workflow_after_consume, dict)
            assert workflow_after_consume["id"] == workflow_id
            workflow_after_consume_state = workflow_after_consume["state"]
            assert isinstance(workflow_after_consume_state, dict)
            assert workflow_after_consume_state["cursor"] == second_events["next_cursor"]

            register_result = await _call(
                client,
                "dynamic.registers.read",
                {"session_id": session_id},
            )
            registers = register_result["registers"]
            assert isinstance(registers, dict)
            ip = int(registers[instruction_pointer])
            original_register = int(registers[accumulator])
            changed_register = original_register ^ 1
            await _call(
                client,
                "dynamic.registers.write",
                {
                    "session_id": session_id,
                    "name": accumulator,
                    "value": changed_register,
                },
            )
            register_result = await _call(
                client,
                "dynamic.registers.read",
                {"session_id": session_id},
            )
            assert register_result["registers"][accumulator] == changed_register
            await _call(
                client,
                "dynamic.registers.write",
                {
                    "session_id": session_id,
                    "name": accumulator,
                    "value": original_register,
                },
            )

            memory = await _call(
                client,
                "dynamic.memory.read",
                {"session_id": session_id, "address": ip, "size": 1},
            )
            original_memory = str(memory["data"])
            changed_memory = f"{int(original_memory, 16) ^ 1:02x}"
            await _call(
                client,
                "dynamic.memory.write",
                {"session_id": session_id, "address": ip, "data": changed_memory},
            )
            memory = await _call(
                client,
                "dynamic.memory.read",
                {"session_id": session_id, "address": ip, "size": 1},
            )
            assert memory["data"] == changed_memory
            await _call(
                client,
                "dynamic.memory.write",
                {"session_id": session_id, "address": ip, "data": original_memory},
            )

            modules = await _call(
                client,
                "dynamic.modules",
                {"session_id": session_id},
            )
            assert modules["count"] > 0

            await _call(
                client,
                "dynamic.breakpoint.set",
                {"session_id": session_id, "address": ip},
            )
            breakpoints = await _call(
                client,
                "dynamic.breakpoints",
                {"session_id": session_id},
            )
            assert ip in {
                int(item["address"])
                for item in breakpoints["breakpoints"]
                if isinstance(item, dict)
            }
            await _call(
                client,
                "dynamic.breakpoint.remove",
                {"session_id": session_id, "address": ip},
            )

            stepped = await _call(
                client,
                "dynamic.step_into",
                {"session_id": session_id, "timeout": 30.0},
            )
            assert stepped["state"]["state"] == "paused"
            await _call(
                client,
                "dynamic.resume",
                {"session_id": session_id, "timeout": 30.0},
            )
            paused = await _call(
                client,
                "dynamic.pause",
                {"session_id": session_id, "timeout": 30.0},
            )
            assert paused["state"]["state"] == "paused"

            stopped = await _call(
                client,
                "dynamic.stop",
                {"session_id": session_id, "timeout": 30.0},
            )
            assert stopped["state"]["state"] == "idle"

            raw_event_groups = [first_events["events"], second_events["events"]]
            event_cursor = int(second_events["next_cursor"])
            for _ in range(16):
                batch = await _call(
                    client,
                    "dynamic.events",
                    {"session_id": session_id, "limit": 256},
                )
                assert int(batch["cursor"]) == event_cursor
                raw_event_groups.append(batch["events"])
                event_cursor = int(batch["next_cursor"])
                if batch["has_more"] is False:
                    break
            else:
                raise AssertionError("MCP event stream did not drain within the bound")

            events = [
                event
                for group in raw_event_groups
                if isinstance(group, list)
                for event in group
                if isinstance(event, dict)
            ]
            sequences = [int(event["sequence"]) for event in events]
            assert sequences == sorted(set(sequences))
            assert all(event["source"] == "x64dbg.plugin_callback" for event in events)
            kinds = {str(event["kind"]) for event in events}
            assert {
                "debug.init",
                "process.created",
                "module.loaded",
                "debug.paused",
                "debug.resumed",
                "debug.stopping",
                "debug.stopped",
            } <= kinds
        finally:
            closed = await _call(
                client,
                "session.close",
                {"session_id": session_id},
            )
            closed_session = closed["session"]
            assert isinstance(closed_session, dict)
            assert closed_session["state"] == "closed"