"""Live Gate: dump after module unload must fail closed (M4.5)."""

from __future__ import annotations

import os
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, Session
from headless_re_mcp.core.service import AnalysisService, DynamicWorker

JsonObject = dict[str, Any]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _service_data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), result
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _matching_module(catalog: JsonObject, module_path: Path) -> JsonObject | None:
    name = module_path.name.casefold()
    for raw in catalog.get("modules") or []:
        assert isinstance(raw, dict)
        path = str(raw.get("path", ""))
        mod_name = str(raw.get("name", ""))
        if Path(path).name.casefold() == name or mod_name.casefold() == name:
            return raw
    return None


def _module_event_seen(
    batch: JsonObject,
    *,
    kind: str,
    module_path: Path,
    runtime_base: int | None = None,
) -> bool:
    name = module_path.name.casefold()
    for event in batch.get("events") or []:
        if not isinstance(event, dict) or event.get("kind") != kind:
            continue
        data = event.get("data") or {}
        if not isinstance(data, dict):
            continue
        event_name = str(data.get("name", "")).casefold()
        event_path = str(data.get("path", "")).casefold()
        base = int(data.get("base") or 0)
        if runtime_base is not None and base == runtime_base:
            return True
        if event_name == name or Path(event_path).name.casefold() == name:
            return True
    return False


def _pause_after_module_event(
    service: AnalysisService,
    session_id: str,
    module_path: Path,
    *,
    kind: str,
    runtime_base: int | None = None,
) -> JsonObject:
    resumed = _service_data(service.dynamic_resume(session_id))
    assert resumed["state"] in {"running", "paused"}
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        batch = _service_data(service.dynamic_events(session_id, limit=256, timeout=2.0))
        if _module_event_seen(
            batch, kind=kind, module_path=module_path, runtime_base=runtime_base
        ):
            paused = _service_data(service.dynamic_pause(session_id, timeout=30.0))
            assert paused["state"]["state"] == "paused"
            return _service_data(service.module_catalog(session_id))
        state = _service_data(service.dynamic_state(session_id))
        if state["state"] == "idle":
            break
        if state["state"] == "paused":
            resumed = _service_data(service.dynamic_resume(session_id))
            assert resumed["state"] in {"running", "paused"}
        time.sleep(0.05)
    raise AssertionError(f"{kind} was not observed for {module_path.name}")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_dump_after_unload_fails_closed(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    executable = os.environ.get(variable)
    if not executable:
        pytest.skip(f"{variable} is not configured")
    fixture = (
        _PROJECT_ROOT / f"artifacts/fixtures-{architecture.value}/headless_fixture.exe"
    )
    event_fixture = fixture.with_name("event_fixture.dll")
    if not fixture.is_file() or not event_fixture.is_file():
        pytest.skip("headless/event fixtures are not built")

    clients: list[XdbgClient] = []

    def factory(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        client = XdbgClient(Path(executable), architecture)
        clients.append(client)
        return client

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=Path(executable) if architecture is Architecture.X64 else None,
        x64dbg_headless_x86=Path(executable) if architecture is Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings, dynamic_worker_factory=factory)
    session_id = ""
    client: XdbgClient | None = None
    try:
        created = _service_data(service.create_session(str(fixture)))
        session_id = str(created["session"]["id"])
        _service_data(service.open_dynamic(session_id))
        client = clients[0]
        launch = _service_data(
            service.dynamic_launch(
                session_id,
                arguments="--module-lifecycle-windows",
                timeout=30.0,
            )
        )
        state = launch.get("state")
        assert isinstance(state, dict) and state["state"] == "paused"

        loaded_catalog = _pause_after_module_event(
            service,
            session_id,
            event_fixture,
            kind="module.loaded",
        )
        loaded = _matching_module(loaded_catalog, event_fixture)
        assert loaded is not None
        loaded_base = int(loaded["base"])

        unloaded_catalog = _pause_after_module_event(
            service,
            session_id,
            event_fixture,
            kind="module.unloaded",
            runtime_base=loaded_base,
        )
        assert _matching_module(unloaded_catalog, event_fixture) is None

        dumped = service.modules_dump(session_id, loaded_base, size=0x1000)
        assert not dumped.ok and dumped.error is not None
        assert dumped.error.code in {
            "module_not_found",
            "module_unloaded_during_dump",
        }
        assert client.analyzer_windows == ()
    finally:
        if session_id:
            with suppress(Exception):
                service.dynamic_stop(session_id)
            with suppress(Exception):
                service.close_session(session_id)
