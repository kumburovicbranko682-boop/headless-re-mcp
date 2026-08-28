"""Backend-wrapper coverage for core/service_ext.py.

The optional-backend methods (radare2, Ghidra, Frida, WinDbg) all wrap an
external tool client that is absent on a hosted runner, so their success tails,
mid-call session-close guards, and typed-error arms never ran. Here the clients
are faked and the debuggee-pid seam is stubbed so every arm runs on Linux,
reusing the mixin harness from test_service_ext_artifacts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_service_ext_artifacts import _Service

import headless_re_mcp.core.service_ext as service_ext
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.core.models import Result, SessionState


class _FakeTool:
    """A stand-in tool client: every method returns data or raises/hooks."""

    def __init__(
        self,
        *_args: Any,
        data: dict[str, Any] | None = None,
        error: BaseException | None = None,
        on_call: Any = None,
        **_kwargs: Any,
    ) -> None:
        self._data = data if data is not None else {"tool": "ok"}
        self._error = error
        self._on_call = on_call

    def _act(self) -> dict[str, Any]:
        if self._on_call is not None:
            self._on_call()
        if self._error is not None:
            raise self._error
        return dict(self._data)

    def __getattr__(self, _name: str) -> Any:
        return lambda *a, **k: self._act()


def _install(
    monkeypatch: pytest.MonkeyPatch, name: str, tool: _FakeTool
) -> None:
    monkeypatch.setattr(service_ext, name, lambda *a, **k: tool)


def _with_pid(service: _Service, pid: int = 4321) -> None:
    service.dynamic_state = lambda _sid, **_k: Result(  # type: ignore[attr-defined]
        ok=True, data={"debuggee_pid": pid}
    )


# --- radare2 ---


def test_r2_open_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "R2Client", _FakeTool(data={"opened": True}))

    result = service.r2_open("sid")

    assert result.ok and result.data is not None
    assert result.data["opened"] is True


def test_r2_disasm_and_xrefs_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "R2Client", _FakeTool(data={"listing": []}))

    assert service.r2_disasm("sid", 0x401000).ok
    assert service.r2_xrefs("sid", 0x401000).ok


def test_r2_request_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "R2Client", _FakeTool(data={"info": {}}))

    assert service.r2_info("sid").ok


def test_r2_maps_a_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "R2Client", _FakeTool(error=R2Error("r2_failed", "no r2")))

    result = service.r2_open("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "r2_failed"


def test_r2_disasm_refuses_a_session_closed_mid_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()

    def _close() -> None:
        service.registry.transition("sid", SessionState.FAILED)

    _install(monkeypatch, "R2Client", _FakeTool(on_call=_close))

    result = service.r2_disasm("sid", 0x401000)

    assert not result.ok and result.error is not None


def test_r2_xrefs_refuses_a_session_closed_mid_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(
        monkeypatch,
        "R2Client",
        _FakeTool(on_call=lambda: service.registry.transition("sid", SessionState.FAILED)),
    )

    assert not service.r2_xrefs("sid", 0x401000).ok


def test_r2_request_refuses_a_session_closed_mid_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(
        monkeypatch,
        "R2Client",
        _FakeTool(on_call=lambda: service.registry.transition("sid", SessionState.FAILED)),
    )

    assert not service.r2_functions("sid").ok


# --- Ghidra ---


def test_ghidra_analyze_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "GhidraClient", _FakeTool(data={"analyzed": True}))

    result = service.ghidra_analyze("sid")

    assert result.ok and result.data is not None
    assert result.data["analyzed"] is True


def test_ghidra_export_registers_an_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    export = tmp_path / "functions.json"
    export.write_bytes(b'{"functions": []}')
    _install(monkeypatch, "GhidraClient", _FakeTool(data={"export_path": str(export)}))

    result = service.ghidra_functions("sid")

    assert result.ok and result.data is not None
    assert "artifact_id" in result.data


def test_ghidra_symbols_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "GhidraClient", _FakeTool(data={"symbols": []}))

    assert service.ghidra_symbols("sid").ok


def test_ghidra_xrefs_requires_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "GhidraClient", _FakeTool())

    result = service.ghidra_xrefs("sid", address=None)  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_ghidra_decompile_requires_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "GhidraClient", _FakeTool())

    result = service.ghidra_decompile("sid", address=None)  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_ghidra_export_rejects_an_unknown_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(monkeypatch, "GhidraClient", _FakeTool())

    result = service_ext._ghidra_export(service, "sid", "bogus")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_ghidra_maps_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _install(
        monkeypatch, "GhidraClient", _FakeTool(error=GhidraError("ghidra_failed", "no ghidra"))
    )

    result = service.ghidra_analyze("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "ghidra_failed"


# --- Frida ---


def test_frida_attach_modules_exports_read_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _with_pid(service)
    _install(monkeypatch, "FridaClient", _FakeTool(data={"count": 2}))

    assert service.frida_attach("sid").ok
    assert service.frida_modules("sid").ok
    assert service.frida_exports("sid", "kernel32.dll").ok
    assert service.frida_memory_read("sid", 0x1000, 16).ok


def test_frida_maps_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _with_pid(service)
    _install(monkeypatch, "FridaClient", _FakeTool(error=FridaError("frida_failed", "no frida")))

    result = service.frida_attach("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "frida_failed"


def test_require_debuggee_pid_refuses_when_no_pid(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.dynamic_state = lambda _sid, **_k: Result(  # type: ignore[attr-defined]
        ok=True, data={"debuggee_pid": None}
    )

    result = service.frida_attach("sid")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_state"


# --- WinDbg (client seam faked so the Windows-only gate is bypassed) ---


def test_windbg_dump_reads_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    _install(monkeypatch, "_windbg_client", _FakeTool(data={"lines": []}))

    assert service.windbg_threads(str(tmp_path / "d.dmp")).ok
    assert service.windbg_modules(str(tmp_path / "d.dmp")).ok
    assert service.windbg_disasm(str(tmp_path / "d.dmp"), 0x1000).ok


def test_windbg_dump_read_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    _install(monkeypatch, "_windbg_client", _FakeTool(error=RuntimeError("cdb crashed")))

    for result in (
        service.windbg_open_dump(str(tmp_path / "d.dmp")),
        service.windbg_threads(str(tmp_path / "d.dmp")),
        service.windbg_modules(str(tmp_path / "d.dmp")),
        service.windbg_disasm(str(tmp_path / "d.dmp"), 0x1000),
    ):
        assert not result.ok and result.error is not None


def test_windbg_live_probes_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    _with_pid(service)
    _install(monkeypatch, "_windbg_client", _FakeTool(data={"live": True}))

    assert service.windbg_attach("sid").ok
    assert service.windbg_live_threads("sid").ok
    assert service.windbg_live_modules("sid").ok
    assert service.windbg_live_disasm("sid", 0x1000).ok


# --- batch_analyze protocol guard and ui.drive_to_breakpoint binding guard ---


def test_batch_analyze_flags_a_missing_session_object(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.create_session = lambda _path: Result(
        ok=True, data={"session": "not-a-dict"}
    )

    result = service.batch_analyze(["only.exe"], max_workers=1)

    assert result.ok and result.data is not None
    entry = result.data["entries"][0]
    assert entry["ok"] is False
    assert entry["error"]["code"] == "rpc_protocol_error"


def test_ui_drive_to_breakpoint_reports_a_missing_binding(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.pe_session()
    service.workflow_status = lambda _sid: Result(ok=True, data={})

    result = service.ui_drive_to_breakpoint("sid", "bp-missing")

    assert not result.ok and result.error is not None
