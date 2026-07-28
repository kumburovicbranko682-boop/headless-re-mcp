"""M9 Gate: real x86/x64 conditional-breakpoint true/false stop semantics."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient
from headless_re_mcp.core.events import DebugEvent
from headless_re_mcp.core.models import Architecture

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_RUN_TRANSITIONS = frozenset({"debug.paused", "debug.stopped"})


def _configured_paths(variable: str, architecture: Architecture) -> tuple[Path, Path]:
    executable = os.environ.get(variable)
    if not executable:
        fallback = (
            _PROJECT_ROOT
            / "artifacts"
            / f"x64dbg-{architecture.value}"
            / "Release"
            / "headless.exe"
        )
        if fallback.is_file():
            executable = str(fallback)
        else:
            pytest.skip(f"{variable} is not configured")
    path = Path(executable)
    if not path.is_file():
        pytest.skip(f"{variable} missing: {path}")
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture is not built: {fixture}")
    return path, fixture


def _entry_point(binary: Path, module_base: int) -> int:
    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    entry_rva = int.from_bytes(image[optional_header + 16 : optional_header + 20], "little")
    assert entry_rva > 0
    return module_base + entry_rva


def _fixture_module(modules: object, fixture: Path) -> dict[str, object]:
    assert isinstance(modules, list)
    fixture_name = fixture.name.casefold()
    for raw in modules:
        assert isinstance(raw, dict)
        path = str(raw.get("path", ""))
        name = str(raw.get("name", ""))
        if Path(path).name.casefold() == fixture_name or name.casefold() == fixture_name:
            return raw
    raise AssertionError(f"fixture module missing from {modules!r}")


def _drain_events(
    client: XdbgClient,
    cursor: int,
) -> tuple[tuple[DebugEvent, ...], int]:
    events: list[DebugEvent] = []
    while True:
        batch = client.read_events(cursor, limit=256, timeout=10.0)
        assert batch.dropped == 0, "conditional-breakpoint evidence was dropped"
        events.extend(batch.events)
        cursor = batch.next_cursor
        if not batch.has_more:
            return tuple(events), cursor


def _target_hits(events: tuple[DebugEvent, ...], address: int) -> list[DebugEvent]:
    return [
        event
        for event in events
        if event.kind == "breakpoint.hit" and int(event.data.get("address", -1)) == address
    ]


def _launch_at_initial_pause(
    client: XdbgClient,
    fixture: Path,
) -> int:
    client.request("debug.launch", {"path": str(fixture.resolve())}, timeout=30)
    initial = client.wait_for_state({"paused"}, timeout=30)
    assert initial["state"] == "paused"

    modules = client.request("modules.list")["modules"]
    module = _fixture_module(modules, fixture)
    target = _entry_point(fixture, int(module["base"]))
    client.request("breakpoints.set", {"address": target})
    return target


def _exercise_false_condition(
    executable: Path,
    fixture: Path,
    architecture: Architecture,
) -> None:
    client = XdbgClient(executable, architecture)
    runtime_directory = client.runtime_directory

    try:
        target = _launch_at_initial_pause(client, fixture)
        conditioned = client.breakpoints_condition_set(target, "0")
        assert conditioned == {
            "address": target,
            "type": "software",
            "expression": "0",
        }
        assert client.breakpoints_condition_get(target)["expression"] == "0"

        _, marker = _drain_events(client, 0)
        client.request("debug.resume")
        outcome = client.wait_for_state(
            {"paused", "idle"},
            timeout=30,
            after_event_sequence=marker,
            transition_event_kinds=_RUN_TRANSITIONS,
        )
        assert outcome["state"] == "idle", (
            f"false condition stopped at the fixture entry point {target:#x}"
        )

        events, _ = _drain_events(client, marker)
        hits = _target_hits(events, target)
        assert len(hits) == 1, "fixture entry was not executed exactly once"
        assert not any(event.kind == "debug.paused" for event in events), (
            "condition '0' emitted a post-resume pause"
        )
        exits = [event for event in events if event.kind == "process.exited"]
        assert len(exits) == 1
        assert int(exits[0].data["exit_code"]) == 0
        assert any(event.kind == "debug.stopped" for event in events)
    finally:
        client.close()

    assert client.exit_code == 0
    assert not runtime_directory.exists()
    assert not client.analyzer_windows


def _exercise_true_condition(
    executable: Path,
    fixture: Path,
    architecture: Architecture,
    instruction_pointer: str,
) -> None:
    client = XdbgClient(executable, architecture)
    runtime_directory = client.runtime_directory

    try:
        target = _launch_at_initial_pause(client, fixture)
        conditioned = client.breakpoints_condition_set(target, "1")
        assert conditioned == {
            "address": target,
            "type": "software",
            "expression": "1",
        }
        assert client.breakpoints_condition_get(target)["expression"] == "1"

        _, marker = _drain_events(client, 0)
        client.request("debug.resume")
        outcome = client.wait_for_state(
            {"paused", "idle"},
            timeout=30,
            after_event_sequence=marker,
            transition_event_kinds=_RUN_TRANSITIONS,
        )
        assert outcome["state"] == "paused", (
            f"true condition did not stop at the fixture entry point {target:#x}"
        )

        registers = client.request("registers.read")["registers"]
        assert isinstance(registers, dict)
        assert int(registers[instruction_pointer]) == target

        events, _ = _drain_events(client, marker)
        hits = _target_hits(events, target)
        assert len(hits) == 1
        pauses = [event for event in events if event.kind == "debug.paused"]
        assert len(pauses) == 1
        assert hits[0].sequence < pauses[0].sequence

        client.request("debug.stop")
        stopped = client.wait_for_state({"idle"}, timeout=30)
        assert stopped["state"] == "idle"
    finally:
        client.close()

    assert client.exit_code == 0
    assert not runtime_directory.exists()
    assert not client.analyzer_windows


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture", "instruction_pointer"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86, "eip"),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64, "rip"),
    ],
)
def test_m9_condition_breakpoint_true_false_gate(
    variable: str,
    architecture: Architecture,
    instruction_pointer: str,
) -> None:
    if os.name != "nt":
        pytest.skip("M9 conditional-breakpoint gate requires Windows")
    executable, fixture = _configured_paths(variable, architecture)

    _exercise_false_condition(executable, fixture, architecture)
    _exercise_true_condition(executable, fixture, architecture, instruction_pointer)
