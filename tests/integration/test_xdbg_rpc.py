from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.events import DebugEvent
from headless_re_mcp.core.models import Architecture

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_REQUIRED_CAPABILITIES = frozenset(
    {
        "debug.state",
        "debug.launch",
        "debug.stop",
        "debug.pause",
        "debug.resume",
        "debug.step_into",
        "debug.step_over",
        "registers.read",
        "registers.write",
        "memory.read",
        "memory.write",
        "modules.list",
        "events.read",
        "breakpoints.list",
        "breakpoints.set",
        "breakpoints.remove",
    }
)


def _configured_paths(variable: str, architecture: Architecture) -> tuple[Path, Path]:
    executable = os.environ.get(variable)
    if not executable:
        pytest.skip(f"{variable} is not configured")
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture is not built: {fixture}")
    return Path(executable), fixture


def _entry_point(binary: Path, module_base: int) -> int:
    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    entry_rva = int.from_bytes(image[optional_header + 16 : optional_header + 20], "little")
    assert entry_rva > 0
    return module_base + entry_rva


def _fixture_module(modules: list[object], fixture: Path) -> dict[str, object]:
    fixture_name = fixture.name.casefold()
    for raw in modules:
        assert isinstance(raw, dict)
        path = str(raw.get("path", ""))
        name = str(raw.get("name", ""))
        if Path(path).name.casefold() == fixture_name or name.casefold() == fixture_name:
            return raw
    raise AssertionError(f"fixture module missing from {modules!r}")


def _event_values(batch: dict[str, object]) -> list[dict[str, object]]:
    raw_events = batch.get("events")
    assert isinstance(raw_events, list)
    events: list[dict[str, object]] = []
    for raw in raw_events:
        assert isinstance(raw, dict)
        events.append(raw)
    sequences = [int(event["sequence"]) for event in events]
    assert sequences == sorted(set(sequences))
    assert all(event.get("source") == "x64dbg.plugin_callback" for event in events)
    assert int(batch["count"]) == len(events)
    if sequences:
        assert int(batch["next_cursor"]) == sequences[-1]
    return events


def _drain_events(client: XdbgClient, cursor: int) -> tuple[list[DebugEvent], int]:
    events: list[DebugEvent] = []
    while True:
        batch = client.read_events(cursor, limit=256, timeout=30.0)
        assert batch.cursor == cursor
        events.extend(batch.events)
        cursor = batch.next_cursor
        if not batch.has_more:
            return events, cursor


def _resume_until_idle(client: XdbgClient, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    transition_kinds = frozenset({"debug.resumed", "debug.stopped"})
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("debuggee did not reach idle within the test bound")
        marker = client.read_events(
            0,
            limit=1,
            timeout=min(5.0, remaining),
        )
        client.request("debug.resume", timeout=min(30.0, remaining))
        state = client.wait_for_state(
            {"paused", "idle"},
            timeout=min(30.0, remaining),
            after_event_sequence=marker.latest_sequence,
            transition_event_kinds=transition_kinds,
        )
        if state["state"] == "idle":
            return


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture", "instruction_pointer", "accumulator"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86, "eip", "eax"),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64, "rip", "rax"),
    ],
)
def test_xdbg_rpc_full_dynamic_round_trip(
    variable: str,
    architecture: Architecture,
    instruction_pointer: str,
    accumulator: str,
) -> None:
    executable, fixture = _configured_paths(variable, architecture)
    client = XdbgClient(executable, architecture)
    runtime_directory = client.runtime_directory

    try:
        assert client.capabilities >= _REQUIRED_CAPABILITIES
        assert client.metadata["architecture"] == architecture.value
        assert client.request("debug.state")["state"] == "idle"

        initial_events = client.request("events.read", {"cursor": 0, "limit": 256})
        assert _event_values(initial_events) == []
        assert initial_events["next_cursor"] == 0
        assert initial_events["latest_sequence"] == 0
        assert initial_events["dropped"] == 0
        assert initial_events["dropped_total"] == 0
        assert initial_events["capacity"] == 1024
        for params in ({"limit": 0}, {"limit": 257}, {"cursor": 1}):
            with pytest.raises(XdbgRpcError) as exc_info:
                client.request("events.read", params)
            assert exc_info.value.code in {"invalid_params", "invalid_cursor"}

        client.request(
            "debug.launch",
            {"path": str(fixture.resolve()), "arguments": "--debug-wait"},
            timeout=30,
        )
        client.wait_for_state({"paused"}, timeout=30)

        launch_events = client.request("events.read", {"cursor": 0, "limit": 256})
        launch_values = _event_values(launch_events)
        launch_kinds = {str(event["kind"]) for event in launch_values}
        assert launch_events["dropped"] == 0
        assert {"debug.init", "process.created", "module.loaded", "debug.paused"} <= launch_kinds
        event_cursor = int(launch_events["next_cursor"])

        register_result = client.request("registers.read")
        registers = register_result["registers"]
        assert isinstance(registers, dict)
        ip = int(registers[instruction_pointer])
        original_register = int(registers[accumulator])
        changed_register = original_register ^ 1
        client.request(
            "registers.write",
            {"name": accumulator, "value": changed_register},
        )
        assert client.request("registers.read")["registers"][accumulator] == changed_register
        client.request(
            "registers.write",
            {"name": accumulator, "value": original_register},
        )
        assert client.request("registers.read")["registers"][accumulator] == original_register

        original_memory = str(client.request("memory.read", {"address": ip, "size": 1})["data"])
        changed_memory = f"{int(original_memory, 16) ^ 1:02x}"
        client.request("memory.write", {"address": ip, "data": changed_memory})
        assert client.request("memory.read", {"address": ip, "size": 1})["data"] == changed_memory
        client.request("memory.write", {"address": ip, "data": original_memory})
        assert client.request("memory.read", {"address": ip, "size": 1})["data"] == original_memory

        module_result = client.request("modules.list")
        raw_modules = module_result["modules"]
        assert isinstance(raw_modules, list)
        module = _fixture_module(raw_modules, fixture)
        breakpoint_address = _entry_point(fixture, int(module["base"]))

        client.request("breakpoints.set", {"address": breakpoint_address})
        breakpoint_result = client.request("breakpoints.list")
        raw_breakpoints = breakpoint_result["breakpoints"]
        assert isinstance(raw_breakpoints, list)
        assert breakpoint_address in {
            int(item["address"]) for item in raw_breakpoints if isinstance(item, dict)
        }
        client.request("breakpoints.remove", {"address": breakpoint_address})
        breakpoint_result = client.request("breakpoints.list")
        raw_breakpoints = breakpoint_result["breakpoints"]
        assert isinstance(raw_breakpoints, list)
        assert breakpoint_address not in {
            int(item["address"]) for item in raw_breakpoints if isinstance(item, dict)
        }

        client.request("debug.step_into")
        assert client.wait_for_state({"paused", "idle"}, timeout=30)["state"] == "paused"
        client.request("debug.step_over")
        assert client.wait_for_state({"paused", "idle"}, timeout=30)["state"] == "paused"

        client.request("debug.resume")
        pause_result = client.request("debug.pause")
        assert pause_result["state"] in {"running", "paused"}
        assert client.wait_for_state({"paused"}, timeout=30)["state"] == "paused"
        assert client.request("debug.pause")["state"] == "paused"

        client.request("debug.stop")
        assert client.wait_for_state({"idle"}, timeout=30)["state"] == "idle"

        final_events = client.request(
            "events.read", {"cursor": event_cursor, "limit": 256}
        )
        final_values = _event_values(final_events)
        final_kinds = {str(event["kind"]) for event in final_values}
        assert final_events["dropped"] == 0
        assert {"debug.resumed", "debug.paused", "debug.stopping", "debug.stopped"} <= final_kinds
        empty_events = client.request(
            "events.read",
            {"cursor": int(final_events["next_cursor"]), "limit": 256},
        )
        assert _event_values(empty_events) == []
        assert empty_events["has_more"] is False
        assert not client.analyzer_windows
    finally:
        client.close()

    assert client.exit_code == 0
    assert not runtime_directory.exists()
    assert not client.analyzer_windows


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_xdbg_event_overflow_module_lifecycle_and_close_race(
    variable: str,
    architecture: Architecture,
) -> None:
    executable, fixture = _configured_paths(variable, architecture)
    event_fixture = fixture.with_name("event_fixture.dll")
    assert event_fixture.is_file()
    client = XdbgClient(executable, architecture)
    runtime_directory = client.runtime_directory
    closed = False

    try:
        initial = client.read_events(0, limit=256)
        assert initial.events == ()
        assert initial.next_cursor == 0

        client.request(
            "debug.launch",
            {"path": str(fixture.resolve()), "arguments": "--module-cycle"},
            timeout=30,
        )
        client.wait_for_state({"paused"}, timeout=30)
        _resume_until_idle(client, timeout=60)
        lifecycle_events, cursor = _drain_events(client, 0)

        loaded = [
            event
            for event in lifecycle_events
            if event.kind == "module.loaded"
            and str(event.data.get("name", "")).casefold() == event_fixture.name.casefold()
        ]
        assert loaded
        loaded_bases = {int(event.data["base"]) for event in loaded if "base" in event.data}
        assert loaded_bases
        assert any(
            event.kind == "module.unloaded"
            and int(event.data.get("base", -1)) in loaded_bases
            for event in lifecycle_events
        )

        client.request(
            "debug.launch",
            {
                "path": str(fixture.resolve()),
                "arguments": "--event-stress 540",
            },
            timeout=30,
        )
        client.wait_for_state({"paused"}, timeout=30)
        baseline = cursor
        _resume_until_idle(client, timeout=120)

        first = client.read_events(baseline, limit=256, timeout=30.0)
        assert first.capacity == 1024
        assert first.dropped > 0
        assert first.dropped_total == first.latest_sequence - first.capacity
        assert first.oldest_sequence == first.latest_sequence - first.capacity + 1
        assert first.dropped == first.oldest_sequence - baseline - 1
        retained = list(first.events)
        cursor = first.next_cursor
        has_more = first.has_more
        while has_more:
            batch = client.read_events(cursor, limit=256, timeout=30.0)
            assert batch.dropped == 0
            retained.extend(batch.events)
            cursor = batch.next_cursor
            has_more = batch.has_more

        assert len(retained) == first.capacity
        sequences = [event.sequence for event in retained]
        assert sequences == list(range(first.oldest_sequence, first.latest_sequence + 1))
        retained_kinds = {event.kind for event in retained}
        assert {"thread.created", "thread.exited", "debug.stopped"} <= retained_kinds

        client.request(
            "debug.launch",
            {
                "path": str(fixture.resolve()),
                "arguments": "--event-stress 2048",
            },
            timeout=30,
        )
        client.wait_for_state({"paused"}, timeout=30)
        client.request("debug.resume")
        client.close(timeout=30)
        closed = True
    finally:
        if not closed:
            client.close(timeout=30)

    assert client.exit_code == 0
    assert not runtime_directory.exists()
    assert not client.analyzer_windows