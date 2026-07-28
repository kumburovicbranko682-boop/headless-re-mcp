"""Live Gate: dump → IAT scan/validate → pe.rebuild → verify on real headless."""

from __future__ import annotations

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

JsonObject = dict[str, Any]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _configured_paths(
    variable: str,
    architecture: Architecture,
) -> tuple[Path, Path]:
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


def _service_data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), result
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


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


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_unpack_live_dump_iat_rebuild_verify(
    tmp_path: Path,
    variable: str,
    architecture: Architecture,
) -> None:
    executable, fixture = _configured_paths(variable, architecture)
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
        x64dbg_headless_x64=executable if architecture == Architecture.X64 else None,
        x64dbg_headless_x86=executable if architecture == Architecture.X86 else None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )
    if settings.ida_home is None:
        pytest.skip("IDA home is not configured (required for M4 verify open_ida)")
    if settings.diec is None or not settings.diec.is_file():
        pytest.skip("HEADLESS_RE_DIEC is not configured (required for M4 verify DIE)")
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

        # Capability: rebuilt headless should advertise pe.headers.runtime.
        assert "pe.headers.runtime" in client.capabilities

        modules = _service_data(service.dynamic_modules(session_id))
        module = _fixture_module(list(modules.get("modules") or []), fixture)
        base = int(module["base"])
        size = int(module.get("size") or 0)
        assert base > 0 and size > 0
        oep_rva = _entry_point_rva(fixture)

        started = _service_data(
            service.unpack_start(
                session_id,
                execute_upx=False,
                timeout=120.0,
            )
        )
        # Unpacked fixture often has no packer route; force RUNNING for dump/IAT Gate.
        from headless_re_mcp.unpack.session import (
            UnpackPhase,
            create_unpack_session,
            transition,
        )

        unpack = started.get("unpack")
        phase = unpack.get("phase") if isinstance(unpack, dict) else None
        if phase not in {"running", "oep_candidate"}:
            state = create_unpack_session(
                session_id,
                route="generic_dynamic",
                timeout_seconds=120.0,
                input_sha256=str(session.get("sha256", "")),
            )
            state = transition(
                state,
                UnpackPhase.RUNNING,
                event="awaiting_runtime",
                message="live gate forced running for dump/IAT path",
            )
            service._store_unpack_session(state)
        else:
            assert phase in {"running", "oep_candidate"}

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
        dump = confirmed.get("dump")
        assert isinstance(dump, dict)
        dump_path = str(dump["output_path"])
        assert Path(dump_path).is_file()
        headers = dump.get("headers")
        if isinstance(headers, dict):
            # Prefer native path after rebuild; fallback is still acceptable if advertised.
            source = headers.get("source")
            assert source in {None, "native", "pe.headers.runtime", "memory.read_fallback"} or (
                "source" not in headers
            )

        scanned = _service_data(service.unpack_iat_scan(session_id, base))
        assert scanned["confirmed"] is False
        assert scanned.get("blind_selection", False) is False
        candidates = scanned.get("candidates")
        assert isinstance(candidates, list) and candidates

        candidate = candidates[0]
        assert isinstance(candidate, dict)
        iat_va = int(candidate["iat_va"])
        iat_size = int(candidate["size"])
        # Negative: nonsense IAT must not be confirmed / must not claim universal unpack.
        bad_result = service.unpack_iat_validate(
            session_id,
            iat_va=base + 0x10,
            size=0x10,
            oep_rva=0xDEAD,
            module_base=base,
        )
        if bad_result.ok and isinstance(bad_result.data, dict):
            bad = bad_result.data
            assert bad["claims_universal_unpack"] is False
            assert bad["confirmed"] is False
            assert float(bad.get("confidence") or 0.0) < 0.5
            assert any("forwarded" in str(item).lower() for item in bad.get("unfixed") or [])
        else:
            assert bad_result.error is not None
            assert bad_result.error.code  # structured failure is an acceptable negative

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
                dump_path,
                entry_point_rva=oep_rva,
                iat_va=iat_va,
                iat_size=iat_size,
            )
        )
        assert rebuilt["claims_universal_unpack"] is False
        report = rebuilt.get("report") or {}
        assert isinstance(report, dict)
        assert report.get("claims_universal_unpack") is False
        assert any("checksum" in str(item).lower() for item in report.get("unfixed") or [])
        out_path = Path(str(rebuilt["output_path"]))
        assert out_path.is_file()
        assert str(settings.artifact_root.resolve()) in str(out_path.resolve())

        # Completion path: parser + DIE + optional IDA reopen.
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
        assert isinstance(verified.get("unfixed"), list)
        die = verified.get("die")
        assert isinstance(die, dict) and die.get("status") == "completed"
        ida = verified.get("ida")
        assert isinstance(ida, dict) and ida.get("static_open_ok") is True
        pe = scan_pe(out_path)
        assert pe.architecture == architecture.value

        status = _service_data(service.unpack_status(session_id))
        phase = status["unpack"]["phase"]
        assert phase in {"imports_rebuilt", "verified", "reanalyzed", "dumped"}

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
