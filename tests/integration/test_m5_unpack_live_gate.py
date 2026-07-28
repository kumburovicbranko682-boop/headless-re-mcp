"""M5 live Gate: full unpack orchestration on real backends.

Covers:
1. UPX route via ``unpack.start`` → ``verified`` (M5→M3), dual arch fixtures.
2. Dynamic route via confirm_oep → dump → IAT → pe.rebuild → verify, with
   phase/timeline/artifact assertions and active-session replace guard.
"""

from __future__ import annotations

import json
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, Session
from headless_re_mcp.core.service import AnalysisService, DynamicWorker
from headless_re_mcp.detection.pe import scan_pe
from headless_re_mcp.unpack.session import UnpackPhase, create_unpack_session, transition

JsonObject = dict[str, Any]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _service_data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), result
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _upx_exe() -> Path:
    configured = os.environ.get("HEADLESS_RE_UPX")
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
        pytest.skip(f"HEADLESS_RE_UPX missing: {path}")
    settings = Settings.load()
    if settings.upx is not None and settings.upx.is_file():
        return settings.upx
    fallback = _PROJECT_ROOT / "artifacts" / "tools" / "upx-5.2.0" / "upx.exe"
    if fallback.is_file():
        return fallback
    pytest.skip("official UPX CLI not configured")


def _upx_fixture(architecture: Architecture) -> Path:
    candidates = (
        _PROJECT_ROOT
        / "artifacts"
        / "fixtures-upx"
        / f"console_fixture-{architecture.value}-upx.exe",
        _PROJECT_ROOT / "fixtures" / "upx" / f"console_fixture-{architecture.value}.upx.exe",
    )
    for path in candidates:
        if path.is_file():
            return path
    pytest.skip(f"UPX fixture missing for {architecture.value}: {candidates[0]}")


def _headless_paths(
    variable: str,
    architecture: Architecture,
) -> tuple[Path, Path]:
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


def _entry_point_rva(binary: Path) -> int:
    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional = pe_offset + 24
    return int.from_bytes(image[optional + 16 : optional + 20], "little")


def _fixture_module(modules: list[object], fixture: Path) -> JsonObject:
    name = fixture.name.casefold()
    for raw in modules:
        assert isinstance(raw, dict)
        path = str(raw.get("path", ""))
        mod_name = str(raw.get("name", ""))
        if Path(path).name.casefold() == name or mod_name.casefold() == name:
            return raw
    raise AssertionError(f"fixture module missing from {modules!r}")


def _assert_session_ledger(settings: Settings, session_id: str, *, min_events: int) -> JsonObject:
    directory = (
        settings.artifact_root.expanduser().resolve() / "unpack" / session_id / "session"
    )
    state_path = directory / "state.json"
    timeline_path = directory / "timeline.jsonl"
    assert state_path.is_file(), state_path
    assert timeline_path.is_file(), timeline_path
    snapshot = json.loads(state_path.read_text(encoding="utf-8"))
    assert isinstance(snapshot, dict)
    assert snapshot.get("claims_universal_unpack") is False
    lines = [line for line in timeline_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= min_events
    return snapshot


@pytest.mark.integration
@pytest.mark.parametrize("architecture", [Architecture.X64, Architecture.X86])
def test_m5_upx_route_live_orchestration(tmp_path: Path, architecture: Architecture) -> None:
    upx = _upx_exe()
    fixture = _upx_fixture(architecture)
    before = fixture.read_bytes()
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=Settings.load().diec,
    )
    service = AnalysisService(settings)
    created = _service_data(service.create_session(str(fixture)))
    session_id = str(created["session"]["id"])

    started = _service_data(
        service.unpack_start(
            session_id,
            use_die=settings.diec is not None,
            execute_upx=True,
            open_ida=False,
            timeout=120.0,
        )
    )
    assert started["claims_universal_unpack"] is False
    unpack = started["unpack"]
    assert isinstance(unpack, dict)
    assert unpack["route"] == "upx"
    assert unpack["phase"] == "verified"
    events = [item["event"] for item in unpack.get("timeline") or []]
    assert "upx_test_ok" in events
    assert "upx_unpacked" in events

    artifacts = unpack.get("artifacts") or []
    assert any(item.get("kind") == "upx_unpacked" for item in artifacts)
    assert fixture.read_bytes() == before

    snapshot = _assert_session_ledger(settings, session_id, min_events=2)
    assert snapshot["phase"] == "verified"

    refused = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "unpack_already_active"

    replaced = _service_data(
        service.unpack_start(
            session_id,
            use_die=settings.diec is not None,
            execute_upx=True,
            open_ida=False,
            replace=True,
            timeout=120.0,
        )
    )
    assert replaced["unpack"]["phase"] == "verified"
    assert fixture.read_bytes() == before


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_m5_dynamic_full_orchestration_live(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    executable, fixture = _headless_paths(variable, architecture)
    os.environ[variable] = str(executable)
    clients: list[XdbgClient] = []

    def dynamic_factory(session: Session, settings: Settings) -> DynamicWorker:
        del settings
        assert session.architecture == architecture
        client = XdbgClient(executable, architecture)
        clients.append(client)
        return client

    loaded = Settings.load()
    diec = loaded.diec
    if diec is None:
        env_diec = os.environ.get("HEADLESS_RE_DIEC")
        if env_diec:
            diec = Path(env_diec)
    settings = Settings(
        ida_home=loaded.ida_home,
        x64dbg_source=None,
        x64dbg_headless_x64=executable if architecture is Architecture.X64 else None,
        x64dbg_headless_x86=executable if architecture is Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )
    if settings.ida_home is None:
        pytest.skip("IDA home is not configured (required for M5 verify open_ida)")
    if settings.diec is None or not settings.diec.is_file():
        pytest.skip("HEADLESS_RE_DIEC is not configured (required for M5 verify DIE)")

    service = AnalysisService(settings, dynamic_worker_factory=dynamic_factory)
    session_id = ""
    client: XdbgClient | None = None
    try:
        created = _service_data(service.create_session(str(fixture)))
        session = created["session"]
        assert isinstance(session, dict)
        session_id = str(session["id"])
        _service_data(service.open_dynamic(session_id))
        assert len(clients) == 1
        client = clients[0]
        assert client.analyzer_windows == ()

        launched = _service_data(
            service.dynamic_launch(session_id, arguments="--debug-wait", timeout=30.0)
        )
        state = launched.get("state")
        assert isinstance(state, dict) and state["state"] == "paused"

        modules = _service_data(service.dynamic_modules(session_id))
        module = _fixture_module(list(modules.get("modules") or []), fixture)
        base = int(module["base"])
        oep_rva = _entry_point_rva(fixture)

        started = _service_data(
            service.unpack_start(session_id, execute_upx=False, timeout=120.0)
        )
        unpack = started.get("unpack")
        phase = unpack.get("phase") if isinstance(unpack, dict) else None
        # Unpacked fixture often routes to none; force generic_dynamic for orchestration.
        if phase not in {"running", "oep_candidate"}:
            forced = create_unpack_session(
                session_id,
                route="generic_dynamic",
                timeout_seconds=120.0,
                input_sha256=str(session.get("sha256", "")),
            )
            forced = transition(
                forced,
                UnpackPhase.RUNNING,
                event="awaiting_runtime",
                message="M5 live gate forced running for dynamic orchestration",
            )
            service._store_unpack_session(forced)
        else:
            assert phase in {"running", "oep_candidate"}

        cancelled_probe = _service_data(
            service.unpack_cancel(session_id, reason="m5 gate cancel probe")
        )
        assert cancelled_probe["unpack"]["phase"] == "cancelled"
        assert cancelled_probe["safe_rollback"] is False
        assert cancelled_probe["claims_universal_unpack"] is False

        # Restart after terminal cancel (no replace flag required).
        restarted = _service_data(
            service.unpack_start(session_id, execute_upx=False, timeout=120.0)
        )
        unpack = restarted.get("unpack")
        phase = unpack.get("phase") if isinstance(unpack, dict) else None
        if phase not in {"running", "oep_candidate"}:
            forced = create_unpack_session(
                session_id,
                route="generic_dynamic",
                timeout_seconds=120.0,
                input_sha256=str(session.get("sha256", "")),
            )
            forced = transition(
                forced,
                UnpackPhase.RUNNING,
                event="awaiting_runtime",
                message="M5 live gate forced running after cancel",
            )
            service._store_unpack_session(forced)

        confirmed = _service_data(
            service.unpack_confirm_oep(
                session_id,
                oep_rva=oep_rva,
                module_base=base,
                auto_dump=True,
                dump_timeout=60.0,
            )
        )
        assert confirmed["auto_dump"] is True
        assert confirmed["claims_universal_unpack"] is False
        dump = confirmed.get("dump")
        assert isinstance(dump, dict)
        dump_path = Path(str(dump["output_path"]))
        assert dump_path.is_file()
        status = _service_data(service.unpack_status(session_id))
        assert status["unpack"]["phase"] == "dumped"

        scanned = _service_data(service.unpack_iat_scan(session_id, base))
        assert scanned["confirmed"] is False
        candidates = scanned.get("candidates")
        assert isinstance(candidates, list) and candidates
        candidate = candidates[0]
        assert isinstance(candidate, dict)
        iat_va = int(candidate["iat_va"])
        iat_size = int(candidate["size"])

        validated = _service_data(
            service.unpack_iat_validate(
                session_id,
                iat_va=iat_va,
                size=iat_size,
                oep_rva=oep_rva,
                module_base=base,
            )
        )
        assert validated["confirmed"] is True

        rebuilt = _service_data(
            service.unpack_pe_rebuild(
                session_id,
                str(dump_path),
                entry_point_rva=oep_rva,
                iat_va=iat_va,
                iat_size=iat_size,
            )
        )
        assert rebuilt["claims_universal_unpack"] is False
        out_path = Path(str(rebuilt["output_path"]))
        assert out_path.is_file()
        status = _service_data(service.unpack_status(session_id))
        assert status["unpack"]["phase"] == "imports_rebuilt"

        _service_data(service.open_static(session_id))
        verified = _service_data(
            service.unpack_verify(
                session_id,
                str(out_path),
                use_die=True,
                open_ida=True,
                baseline_session_id=session_id,
            )
        )
        assert verified["claims_universal_unpack"] is False
        die = verified.get("die")
        assert isinstance(die, dict) and die.get("status") == "completed"
        ida = verified.get("ida")
        assert isinstance(ida, dict) and ida.get("static_open_ok") is True
        pe = scan_pe(out_path)
        assert pe.architecture == architecture.value

        status = _service_data(service.unpack_status(session_id))
        assert status["unpack"]["phase"] in {"verified", "reanalyzed"}
        snapshot = _assert_session_ledger(settings, session_id, min_events=4)
        assert snapshot["phase"] in {"verified", "reanalyzed", "imports_rebuilt", "dumped"}

        assert client.analyzer_windows == ()
        child_id = str(ida.get("session_id") or "")
        if child_id:
            with suppress(Exception):
                service.close_session(child_id)
    finally:
        if session_id:
            with suppress(Exception):
                service.dynamic_stop(session_id)
            with suppress(Exception):
                service.close_session(session_id)
        if client is not None:
            assert client.analyzer_windows == ()
