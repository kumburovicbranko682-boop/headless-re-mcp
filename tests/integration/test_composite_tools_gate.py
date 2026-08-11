"""Gate: agent-facing composite tools against a real IDA + x64dbg backend.

These tools were built against fakes, so this gate is the only place that proves
the real RPC actually rebases breakpoints, stops where we asked, and hands back
Microsoft x64 argument registers. Skips when a backend or fixture is missing;
a skip is not a pass.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _data(result: Result[JsonObject]) -> JsonObject:

    assert result.ok, result.model_dump(mode="json")
    assert result.data is not None
    return result.data


def _object(value: object) -> JsonObject:

    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def _entry_rva(binary: Path) -> int:

    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    rva = int.from_bytes(image[optional_header + 16 : optional_header + 20], "little")
    assert rva > 0
    return rva


def _main_module(modules: JsonObject, fixture: Path) -> JsonObject:

    entries = modules.get("modules")
    assert isinstance(entries, list)
    expected = fixture.name.casefold()
    for raw in entries:
        item = _object(raw)
        if Path(str(item.get("path", ""))).name.casefold() == expected:
            return item
        if str(item.get("name", "")).casefold() == expected:
            return item
    raise AssertionError(f"fixture module missing from runtime modules: {fixture.name}")


@pytest.fixture(scope="module")


def settings() -> Settings:

    loaded = Settings.load()
    executable = loaded.x64dbg_headless_x64
    if executable is None or not executable.is_file():
        pytest.skip("x64 headless executable is not configured")
    if loaded.ida_home is None or not loaded.ida_home.is_dir():
        pytest.skip("IDA home is not configured")
    return loaded


@pytest.fixture(scope="module")


def fixture_binary() -> Path:

    binary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not binary.is_file():
        pytest.skip(f"fixture is not built: {binary}")
    return binary


def test_composite_tools_drive_a_real_debuggee(
    settings: Settings,
    fixture_binary: Path,
) -> None:

    service = AnalysisService(settings)
    session_id = str(_object(_data(service.create_session(str(fixture_binary)))["session"])["id"])
    try:
        static_backend = _object(_data(service.open_static(session_id))["backend"])
        _data(service.open_dynamic(session_id))
        launched = _data(
            service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0)
        )
        assert _object(launched["state"])["state"] == "paused"
        module = _main_module(_data(service.dynamic_modules(session_id)), fixture_binary)
        runtime_base = int(module["base"])
        static_base = int(static_backend["image_base"])
        entry_rva = _entry_rva(fixture_binary)
        assert runtime_base != static_base, "fixture was not relocated; rebasing is untested"
        static_entry = static_base + entry_rva
        runtime_entry = runtime_base + entry_rva
        # 1) One resolver, three coordinate systems, one runtime answer.
        from_static = _data(
            service.resolve_runtime_address(session_id, static_entry, source="static")
        )
        assert from_static["runtime_address"] == runtime_entry
        assert from_static["static_address"] == static_entry
        assert from_static["rva"] == entry_rva
        from_rva = _data(service.resolve_runtime_address(session_id, entry_rva, source="rva"))
        assert from_rva["runtime_address"] == runtime_entry
        from_runtime = _data(
            service.resolve_runtime_address(session_id, runtime_entry, source="runtime")
        )
        assert from_runtime["static_address"] == static_entry
        # 2) A static address must arm the rebased runtime address, not itself.
        _data(service.dynamic_breakpoint_set(session_id, static_entry, address_space="static"))
        listed = _data(service.dynamic_breakpoints(session_id))
        addresses = {
            int(_object(item)["address"])
            for item in (listed.get("breakpoints") or [])
        }
        assert runtime_entry in addresses
        assert static_entry not in addresses
        _data(service.dynamic_breakpoint_remove(session_id, runtime_entry))
        # 3) Real API-argument capture at a real stop.
        traced = _data(
            service.trace_api_arguments(
                session_id,
                address=runtime_entry,
                max_hits=1,
                timeout=60.0,
            )
        )
        assert traced["hit_count"] == 1, traced
        assert traced["convention"] == "microsoft_x64_integer_registers"
        hit = _object(traced["hits"][0])
        assert hit["instruction_pointer"] == runtime_entry
        sources = [_object(item)["source"] for item in hit["arguments"]]
        assert sources == ["rcx", "rdx", "r8", "r9"]
        assert all(_object(item)["value"] is not None for item in hit["arguments"])
        # 4) Relaunch, then let the composite workflow do everything in one call.
        _data(service.dynamic_stop(session_id, timeout=60.0))
        relaunched = _data(
            service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0)
        )
        assert _object(relaunched["state"])["state"] == "paused"
        module = _main_module(_data(service.dynamic_modules(session_id)), fixture_binary)
        runtime_entry = int(module["base"]) + entry_rva
        static_entry = static_base + entry_rva
        analyzed = _data(
            service.analyze_function_dynamic(session_id, static_entry, timeout=60.0)
        )
        assert _object(analyzed["function"])["runtime_address"] == runtime_entry
        execution = _object(analyzed["execution"])
        assert execution["resumed"] is True
        assert execution["instruction_pointer"] == runtime_entry
        assert execution["stopped_at_breakpoint"] is True
        assert _object(analyzed["breakpoint"])["address"] == runtime_entry
        assert "decompiled" in _object(analyzed["static"])
        # 5) Nothing died, so recovery must keep both live backends untouched.
        recovered = _data(service.session_recover(session_id))
        assert recovered["replaced"] is False
        assert recovered["kept"] == 2
        assert recovered["recovered"] == 0
        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()


@pytest.fixture(scope="module")

def x86_settings() -> Settings:

    loaded = Settings.load()
    executable = loaded.x64dbg_headless_x86
    if executable is None or not executable.is_file():
        pytest.skip("x86 headless executable is not configured")
    return loaded


@pytest.fixture(scope="module")

def x86_fixture() -> Path:

    binary = _PROJECT_ROOT / "artifacts" / "fixtures-x86" / "headless_fixture.exe"
    if not binary.is_file():
        pytest.skip(f"fixture is not built: {binary}")
    return binary


def test_trace_api_arguments_reads_the_x86_stack(
    x86_settings: Settings,
    x86_fixture: Path,
) -> None:

    """x86 has no argument registers, so the stack path must work for real."""
    service = AnalysisService(x86_settings)
    session_id = str(
        _object(_data(service.create_session(str(x86_fixture)))["session"])["id"]
    )
    try:
        _data(service.open_dynamic(session_id))
        _data(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        module = _main_module(_data(service.dynamic_modules(session_id)), x86_fixture)
        runtime_entry = int(module["base"]) + _entry_rva(x86_fixture)
        traced = _data(
            service.trace_api_arguments(
                session_id,
                address=runtime_entry,
                max_hits=1,
                argument_count=3,
                timeout=60.0,
            )
        )
        assert traced["architecture"] == "x86"
        assert traced["convention"] == "x86_stack_arguments"
        assert traced["hit_count"] == 1, traced
        hit = _object(traced["hits"][0])
        # Proves _instruction_pointer resolves eip, not just rip.
        assert hit["instruction_pointer"] == runtime_entry
        arguments = [_object(item) for item in hit["arguments"]]
        assert [item["source"] for item in arguments] == [
            "[esp+0x4]",
            "[esp+0x8]",
            "[esp+0xc]",
        ]
        assert all(isinstance(item["value"], int) for item in arguments), arguments
        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()


def _dynamic_client(service: AnalysisService, session_id: str) -> object:
    runtime = service._runtime_owner.get(session_id, BackendKind.X64DBG)
    assert runtime is not None
    return runtime.worker


def _drop_connection(client: object) -> None:
    """Leave the client exactly as a transport fault does: worker up, pipe gone."""
    transport = client._transport  # type: ignore[attr-defined]
    assert transport is not None
    transport.close()
    client._transport = None  # type: ignore[attr-defined]
    assert client.transport_connected is False  # type: ignore[attr-defined]


def test_a_dropped_connection_heals_without_losing_the_debuggee(
    settings: Settings,
    fixture_binary: Path,
) -> None:
    """A lost pipe must not end the session; the worker still owns the debuggee."""
    service = AnalysisService(settings)
    session_id = str(
        _object(_data(service.create_session(str(fixture_binary)))["session"])["id"]
    )
    try:
        _data(service.open_dynamic(session_id))
        _data(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        before = _data(service.dynamic_state(session_id))
        debugger_pid = int(str(before["debugger_pid"]))
        # Without this the pid comparison below would pass on two missing values.
        assert isinstance(before["debuggee_pid"], int) and before["debuggee_pid"] > 0
        client = _dynamic_client(service, session_id)

        _drop_connection(client)
        after = _data(service.dynamic_state(session_id))

        assert client.transport_connected is True  # type: ignore[attr-defined]
        # Healed in place rather than restarted: a restart would hand back a new
        # debugger and drop the process being debugged.
        assert int(str(after["debugger_pid"])) == debugger_pid
        assert after["debuggee_pid"] == before["debuggee_pid"]
        assert after["state"] == before["state"]
        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()


def test_a_dropped_connection_repairs_itself_with_nobody_watching(
    settings: Settings,
    fixture_binary: Path,
) -> None:
    """Nothing may need to be called for a live session to come back."""
    service = AnalysisService(settings)
    session_id = str(
        _object(_data(service.create_session(str(fixture_binary)))["session"])["id"]
    )
    try:
        _data(service.open_dynamic(session_id))
        _data(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        client = _dynamic_client(service, session_id)
        _drop_connection(client)

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if client.transport_connected:  # type: ignore[attr-defined]
                break
            time.sleep(0.1)
        else:
            raise AssertionError("the connection was never repaired on its own")

        # Recovering the connection is only worth anything if calls work again.
        assert _data(service.dynamic_state(session_id))["debuggee_pid"]
        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()


def test_session_recover_reconnects_a_live_backend_in_place(
    settings: Settings,
    fixture_binary: Path,
) -> None:
    """Explicit recovery must repair a dropped pipe, not report nothing to do."""
    service = AnalysisService(settings)
    session_id = str(
        _object(_data(service.create_session(str(fixture_binary)))["session"])["id"]
    )
    try:
        _data(service.open_dynamic(session_id))
        _data(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        debuggee_pid = _data(service.dynamic_state(session_id))["debuggee_pid"]
        assert isinstance(debuggee_pid, int) and debuggee_pid > 0
        _drop_connection(_dynamic_client(service, session_id))

        recovered = _data(service.session_recover(session_id, ["x64dbg"]))

        assert recovered["replaced"] is False
        assert recovered["recovered"] == 1, recovered
        assert recovered["failed"] == 0, recovered
        assert recovered["backends"][0]["action"] == "reconnected"
        assert _data(service.dynamic_state(session_id))["debuggee_pid"] == debuggee_pid
        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()


def test_session_recover_rebuilds_after_a_real_worker_kill(
    settings: Settings,
    fixture_binary: Path,
) -> None:
    """Kill the real debugger process; recovery must hand back a working session."""
    service = AnalysisService(settings)
    session_id = str(
        _object(_data(service.create_session(str(fixture_binary)))["session"])["id"]
    )
    replacement: str | None = None
    try:
        _data(service.open_static(session_id))
        _data(service.open_dynamic(session_id))
        _data(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        debugger_pid = int(str(_data(service.dynamic_state(session_id))["debugger_pid"]))
        assert debugger_pid > 0
        # /T also takes the debuggee down, since x64dbg owns it.
        subprocess.run(
            ["taskkill", "/PID", str(debugger_pid), "/T", "/F"],
            check=True,
            capture_output=True,
        )
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if not service.dynamic_state(session_id).ok:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("the service never noticed the killed worker")
        recovered = _data(service.session_recover(session_id))
        assert recovered["failed"] == 0, recovered
        assert recovered["recovered"] >= 1, recovered
        # Depending on how the death is detected the session may survive (the
        # backend is reopened in place) or be rebuilt; both are real recoveries,
        # so assert the outcome rather than the mechanism.
        target = str(recovered["session_id"])
        if recovered["replaced"]:
            assert recovered["previous_session_id"] == session_id
            assert target != session_id
            replacement = target
        else:
            assert target == session_id
        # A recovered session is only useful if it can debug again.
        relaunched = _data(
            service.dynamic_launch(target, arguments="--debug-wait", timeout=60.0)
        )
        assert _object(relaunched["state"])["state"] == "paused"
        _data(service.dynamic_stop(target, timeout=60.0))
    finally:
        if replacement is not None:
            service.close_session(replacement)
        service.close_session(session_id)
        service.close_all()


def test_batch_opens_parallel_ida_sessions_and_reports(
    settings: Settings,
    fixture_binary: Path,
) -> None:

    second = fixture_binary.parent / "console_fixture.exe"
    if not second.is_file():
        pytest.skip(f"fixture is not built: {second}")
    service = AnalysisService(settings)
    try:
        # Two real idalib backends at once: the parallel claim, actually exercised.
        batch = _data(
            service.batch_analyze(
                [str(fixture_binary), str(second)],
                max_workers=2,
                open_static=True,
            )
        )
        assert batch["count"] == 2
        assert batch["succeeded"] == 2, batch
        sessions = [str(_object(item)["session_id"]) for item in batch["entries"]]
        assert len(set(sessions)) == 2
        target = sessions[0]
        _data(service.static_functions(target, limit=1))
        _data(
            service.knowledge_record(target, "api", "CreateFileW", {"module": "kernel32"})
        )
        _data(service.knowledge_record(target, "function", "entry", {"note": "gate"}))
        # Same key twice must update rather than duplicate.
        _data(service.knowledge_record(target, "function", "entry", {"note": "gate2"}))
        api_only = _data(service.knowledge_query(target, kind="api"))
        assert api_only["total"] == 1
        everything = _data(service.knowledge_query(target))
        assert everything["total"] == 2
        report = _data(service.report_generate(target, title="Gate report"))
        path = Path(str(report["path"]))
        assert path.is_file()
        markdown = path.read_text(encoding="utf-8")
        assert markdown.startswith("# Gate report")
        assert "CreateFileW" in markdown
        assert "gate2" in markdown
        assert report["findings"] == 2
    finally:
        service.close_all()
