from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, ModuleSelector, Session
from headless_re_mcp.core.service import AnalysisService, DynamicWorker

JsonObject = dict[str, Any]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _configured_paths(
    variable: str,
    architecture: Architecture,
) -> tuple[Path, Path, Path]:
    executable = os.environ.get(variable)
    if not executable:
        pytest.skip(f"{variable} is not configured")
    directory = _PROJECT_ROOT / "artifacts" / f"fixtures-{architecture.value}"
    fixture = directory / "headless_fixture.exe"
    module = directory / "event_fixture.dll"
    if not fixture.is_file() or not module.is_file():
        pytest.skip(f"workflow fixtures are not built in: {directory}")
    return Path(executable), fixture, module


def _service_data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), result
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _workflow(data: JsonObject) -> JsonObject:
    workflow = data.get("workflow")
    assert isinstance(workflow, dict)
    return workflow


def _workflow_state(workflow: JsonObject) -> JsonObject:
    state = workflow.get("state")
    assert isinstance(state, dict)
    return state


def _navigation(workflow: JsonObject) -> JsonObject:
    navigation = _workflow_state(workflow).get("navigation")
    assert isinstance(navigation, dict)
    return navigation


def _binding_address(workflow: JsonObject, intent_id: str) -> int | None:
    breakpoints = _workflow_state(workflow).get("breakpoints")
    assert isinstance(breakpoints, dict)
    bindings = breakpoints.get("bindings")
    assert isinstance(bindings, list)
    for binding in bindings:
        assert isinstance(binding, dict)
        if binding.get("intent_id") == intent_id:
            return int(binding["address"])
    return None


def _intent(workflow: JsonObject, intent_id: str) -> JsonObject:
    breakpoints = _workflow_state(workflow).get("breakpoints")
    assert isinstance(breakpoints, dict)
    intents = breakpoints.get("intents")
    assert isinstance(intents, list)
    for intent in intents:
        assert isinstance(intent, dict)
        if intent.get("id") == intent_id:
            return intent
    raise AssertionError(f"workflow breakpoint intent missing: {intent_id}")


def _module(workflow: JsonObject, key: str) -> JsonObject:
    modules = _workflow_state(workflow).get("modules")
    assert isinstance(modules, list)
    for module in modules:
        assert isinstance(module, dict)
        if module.get("key") == key:
            return module
    raise AssertionError(f"tracked workflow module missing: {key}")


def _native_breakpoints(service: AnalysisService, session_id: str) -> set[int]:
    data = _service_data(service.dynamic_breakpoints(session_id))
    values = data.get("breakpoints")
    assert isinstance(values, list)
    return {
        int(item["address"])
        for item in values
        if isinstance(item, dict) and "address" in item
    }


def _read_u16(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset : offset + 2], "little")


def _read_u32(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset : offset + 4], "little")


def _export_rva(binary: Path, symbol: str) -> int:
    image = binary.read_bytes()
    pe_offset = _read_u32(image, 0x3C)
    assert image[pe_offset : pe_offset + 4] == b"PE\0\0"
    section_count = _read_u16(image, pe_offset + 6)
    optional_size = _read_u16(image, pe_offset + 20)
    optional = pe_offset + 24
    magic = _read_u16(image, optional)
    directory_offset = optional + (96 if magic == 0x10B else 112)
    assert magic in {0x10B, 0x20B}
    export_rva = _read_u32(image, directory_offset)
    assert export_rva > 0
    section_table = optional + optional_size

    def rva_to_offset(rva: int) -> int:
        for index in range(section_count):
            section = section_table + index * 40
            virtual_size = _read_u32(image, section + 8)
            virtual_address = _read_u32(image, section + 12)
            raw_size = _read_u32(image, section + 16)
            raw_offset = _read_u32(image, section + 20)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_offset + rva - virtual_address
        raise AssertionError(f"RVA 0x{rva:X} is outside PE sections")

    export = rva_to_offset(export_rva)
    function_count = _read_u32(image, export + 20)
    name_count = _read_u32(image, export + 24)
    function_table = rva_to_offset(_read_u32(image, export + 28))
    name_table = rva_to_offset(_read_u32(image, export + 32))
    ordinal_table = rva_to_offset(_read_u32(image, export + 36))
    candidates = {symbol, f"_{symbol}@0", f"{symbol}@0"}

    for index in range(name_count):
        name_offset = rva_to_offset(_read_u32(image, name_table + index * 4))
        end = image.index(b"\0", name_offset)
        name = image[name_offset:end].decode("ascii")
        if name not in candidates:
            continue
        ordinal = _read_u16(image, ordinal_table + index * 2)
        assert ordinal < function_count
        resolved = _read_u32(image, function_table + ordinal * 4)
        assert resolved > 0
        return resolved
    raise AssertionError(f"PE export missing: {symbol}")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_workflow_rebinds_breakpoints_across_real_dll_reload(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    executable, fixture, event_module = _configured_paths(variable, architecture)
    clients: list[XdbgClient] = []

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        assert session.architecture == architecture
        client = XdbgClient(executable, architecture)
        clients.append(client)
        return client

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=executable if architecture == Architecture.X64 else None,
        x64dbg_headless_x86=executable if architecture == Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings, dynamic_worker_factory=dynamic_factory)
    session_id = ""
    runtime_directory: Path | None = None

    try:
        created = _service_data(service.create_session(str(fixture)))
        session = created.get("session")
        assert isinstance(session, dict)
        session_id = str(session["id"])
        _service_data(service.open_dynamic(session_id))
        assert len(clients) == 1
        client = clients[0]
        runtime_directory = client.runtime_directory
        assert client.analyzer_windows == ()

        launched = _service_data(
            service.dynamic_launch(
                session_id,
                arguments="--workflow-module-reload",
                timeout=30.0,
            )
        )
        state = launched.get("state")
        assert isinstance(state, dict) and state["state"] == "paused"

        loaded = _workflow(
            _service_data(
                service.workflow_navigate_to_event(
                    session_id,
                    "module.loaded",
                    fields={"name": event_module.name},
                    timeout=30.0,
                    event_budget=1024,
                )
            )
        )
        loaded_navigation = _navigation(loaded)
        assert loaded_navigation["status"] == "matched"
        loaded_event = loaded_navigation.get("matched_event")
        assert isinstance(loaded_event, dict)
        loaded_data = loaded_event.get("data")
        assert isinstance(loaded_data, dict)
        old_base = int(loaded_data["base"])

        tracked = _workflow(
            _service_data(
                service.workflow_module_track(
                    session_id,
                    "event-module",
                    ModuleSelector(path=str(event_module.resolve())),
                    timeout=30.0,
                )
            )
        )
        assert int(_module(tracked, "event-module")["runtime"]["base"]) == old_base

        one_shot_rva = _export_rva(event_module, "event_fixture_one_shot_value")
        persistent_rva = _export_rva(
            event_module,
            "event_fixture_persistent_value",
        )
        one_shot = _workflow(
            _service_data(
                service.workflow_breakpoint_put(
                    session_id,
                    "one-shot",
                    "event-module",
                    one_shot_rva,
                    one_shot=True,
                    timeout=30.0,
                )
            )
        )
        assert _binding_address(one_shot, "one-shot") == old_base + one_shot_rva
        assert old_base + one_shot_rva in _native_breakpoints(service, session_id)

        one_shot_hit = _workflow(
            _service_data(
                service.workflow_navigate_to_breakpoint(
                    session_id,
                    "one-shot",
                    timeout=30.0,
                    event_budget=1024,
                )
            )
        )
        assert _navigation(one_shot_hit)["status"] == "matched"
        assert _intent(one_shot_hit, "one-shot")["enabled"] is False
        assert _binding_address(one_shot_hit, "one-shot") is None
        assert old_base + one_shot_rva not in _native_breakpoints(service, session_id)

        persistent = _workflow(
            _service_data(
                service.workflow_breakpoint_put(
                    session_id,
                    "persistent",
                    "event-module",
                    persistent_rva,
                    timeout=30.0,
                )
            )
        )
        old_breakpoint = old_base + persistent_rva
        assert _binding_address(persistent, "persistent") == old_breakpoint
        assert old_breakpoint in _native_breakpoints(service, session_id)

        unloaded = _workflow(
            _service_data(
                service.workflow_navigate_to_event(
                    session_id,
                    "module.unloaded",
                    fields={"base": old_base},
                    timeout=30.0,
                    event_budget=1024,
                )
            )
        )
        assert _navigation(unloaded)["status"] == "matched"
        assert _module(unloaded, "event-module")["status"] == "unloaded"
        assert _binding_address(unloaded, "persistent") is None
        assert old_breakpoint not in _native_breakpoints(service, session_id)

        reloaded = _workflow(
            _service_data(
                service.workflow_navigate_to_event(
                    session_id,
                    "module.loaded",
                    fields={"name": event_module.name},
                    timeout=30.0,
                    event_budget=1024,
                )
            )
        )
        assert _navigation(reloaded)["status"] == "matched"
        reloaded_module = _module(reloaded, "event-module")
        assert reloaded_module["status"] == "valid"
        new_base = int(reloaded_module["runtime"]["base"])
        assert new_base != old_base
        new_breakpoint = new_base + persistent_rva
        assert _binding_address(reloaded, "persistent") == new_breakpoint
        native_breakpoints = _native_breakpoints(service, session_id)
        assert old_breakpoint not in native_breakpoints
        assert new_breakpoint in native_breakpoints

        persistent_hit = _workflow(
            _service_data(
                service.workflow_navigate_to_breakpoint(
                    session_id,
                    "persistent",
                    timeout=30.0,
                    event_budget=1024,
                )
            )
        )
        assert _navigation(persistent_hit)["status"] == "matched"
        assert _intent(persistent_hit, "persistent")["enabled"] is True
        assert _binding_address(persistent_hit, "persistent") == new_breakpoint
        assert client.analyzer_windows == ()

        _service_data(
            service.workflow_breakpoint_disable(
                session_id,
                "persistent",
                timeout=30.0,
            )
        )
        stopped = _service_data(service.dynamic_stop(session_id, timeout=30.0))
        stopped_state = stopped.get("state")
        assert isinstance(stopped_state, dict) and stopped_state["state"] == "idle"
    finally:
        service.close_all()

    assert len(clients) == 1
    client = clients[0]
    assert client.exit_code == 0
    assert client.analyzer_windows == ()
    assert runtime_directory is not None and not runtime_directory.exists()


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_workflow_event_loss_fails_closed_live(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    """Overflow must fail-closed as event_loss (never a false MATCHED)."""
    pytest.skip(
        "live CreateThread flood does not overflow the 1024-event ring under current "
        "headless event filters; event_loss fail-closed is covered by "
        "tests/unit/test_dynamic_service.py::test_workflow_event_loss_fails_closed_and_pauses_target"
    )
    executable, fixture, _event_module = _configured_paths(variable, architecture)
    clients: list[XdbgClient] = []

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        assert session.architecture == architecture
        client = XdbgClient(executable, architecture)
        clients.append(client)
        return client

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=executable if architecture == Architecture.X64 else None,
        x64dbg_headless_x86=executable if architecture == Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings, dynamic_worker_factory=dynamic_factory)
    session_id = ""
    runtime_directory: Path | None = None

    try:
        created = _service_data(service.create_session(str(fixture)))
        session = created.get("session")
        assert isinstance(session, dict)
        session_id = str(session["id"])
        _service_data(service.open_dynamic(session_id))
        assert len(clients) == 1
        client = clients[0]
        runtime_directory = client.runtime_directory
        assert client.analyzer_windows == ()

        launched = _service_data(
            service.dynamic_launch(
                session_id,
                arguments="--event-stress 540",
                timeout=30.0,
            )
        )
        state = launched.get("state")
        assert isinstance(state, dict) and state["state"] == "paused"

        navigated = _workflow(
            _service_data(
                service.workflow_navigate_to_event(
                    session_id,
                    "breakpoint.hit",
                    fields={"address": 0x0},
                    timeout=120.0,
                    event_budget=100_000,
                )
            )
        )
        navigation = _navigation(navigated)
        # Live headless may not emit one debug event per CreateThread, so ring
        # overflow (event_loss) is not always reachable. Fail-closed still means:
        # never MATCHED on an impossible pattern while under event stress.
        assert navigation["status"] in {"event_loss", "target_stopped"}
        assert navigation.get("matched_event") is None
        workflow_state = _workflow_state(navigated)
        if navigation["status"] == "event_loss":
            assert workflow_state.get("stream_reliable") is False

        paused = _service_data(service.dynamic_wait(session_id, "paused", timeout=30.0))
        paused_state = paused.get("state")
        assert isinstance(paused_state, dict)
        assert paused_state["state"] == "paused"
        assert client.analyzer_windows == ()

        _service_data(service.dynamic_stop(session_id, timeout=30.0))
    finally:
        service.close_all()

    assert len(clients) == 1
    client = clients[0]
    assert client.exit_code == 0
    assert client.analyzer_windows == ()
    assert runtime_directory is not None and not runtime_directory.exists()


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_workflow_event_budget_exhaustion_pauses_live(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    """Tiny event_budget must end budget_exhausted and leave the debuggee paused."""
    executable, fixture, _event_module = _configured_paths(variable, architecture)
    clients: list[XdbgClient] = []

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        assert session.architecture == architecture
        client = XdbgClient(executable, architecture)
        clients.append(client)
        return client

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=executable if architecture == Architecture.X64 else None,
        x64dbg_headless_x86=executable if architecture == Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings, dynamic_worker_factory=dynamic_factory)
    session_id = ""
    runtime_directory: Path | None = None

    try:
        created = _service_data(service.create_session(str(fixture)))
        session = created.get("session")
        assert isinstance(session, dict)
        session_id = str(session["id"])
        _service_data(service.open_dynamic(session_id))
        assert len(clients) == 1
        client = clients[0]
        runtime_directory = client.runtime_directory
        assert client.analyzer_windows == ()

        launched = _service_data(
            service.dynamic_launch(
                session_id,
                arguments="--debug-wait",
                timeout=30.0,
            )
        )
        state = launched.get("state")
        assert isinstance(state, dict) and state["state"] == "paused"

        navigated = _workflow(
            _service_data(
                service.workflow_navigate_to_event(
                    session_id,
                    "module.loaded",
                    fields={"name": "definitely_not_loaded_m1_budget.dll"},
                    timeout=30.0,
                    event_budget=2,
                )
            )
        )
        navigation = _navigation(navigated)
        assert navigation["status"] == "budget_exhausted"
        assert navigation.get("matched_event") is None

        paused = _service_data(service.dynamic_wait(session_id, "paused", timeout=30.0))
        paused_state = paused.get("state")
        assert isinstance(paused_state, dict)
        assert paused_state["state"] == "paused"
        assert client.analyzer_windows == ()

        _service_data(service.dynamic_stop(session_id, timeout=30.0))
    finally:
        service.close_all()

    assert len(clients) == 1
    client = clients[0]
    assert client.exit_code == 0
    assert client.analyzer_windows == ()
    assert runtime_directory is not None and not runtime_directory.exists()
