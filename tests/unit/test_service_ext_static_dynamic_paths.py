"""Success and error-translation paths of the non-PE service methods.

``service_ext`` wires the cross-platform static/dynamic backends -- radare2,
Ghidra and Frida -- into ``AnalysisService``. The closed-session guards are
pinned elsewhere (``test_r2_closed_session`` and friends); what those leave
untested is the ordinary case: a call that runs the fake backend, records the
backend and a timeline entry, and returns ``_success`` -- and the two failure
translations every one of these methods shares, where a backend's own error
type becomes an ``XdbgRpcError`` carrying its code and an unexpected exception
becomes a generic failure. Each backend is faked at its ``service_ext`` import
site, so these run without radare2, Ghidra, Frida or a debuggee on the box.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import (
    _ghidra_export,
    _require_debuggee_pid,
)


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = svc.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    svc._session_id = created.data["session"]["id"]  # type: ignore[attr-defined]
    try:
        yield svc
    finally:
        svc.close_all()


def _sid(service: Any) -> str:
    return str(service._session_id)


# ---------------------------------------------------------------------------
# radare2: open / disasm / xrefs / whitelist request.
# ---------------------------------------------------------------------------
class _FakeR2:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        return {"opened": True, "binary": str(binary), "info": "arch x86", "note": "ok"}

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"address": address, "count": count, "ops": []}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        return {"address": address, "xrefs": []}

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"raw": "ok", "commands": commands}


def test_r2_open_success_records_backend_and_returns_data(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client", lambda *a, **k: _FakeR2()
    )
    result = service.r2_open(_sid(service))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["opened"] is True
    assert result.data["binary"].endswith("sample.exe")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("r2_open", ()),
        ("r2_disasm", (0x1000,)),
        ("r2_xrefs", (0x1000,)),
        ("r2_info", ()),
    ],
)
def test_r2_methods_translate_r2error_to_its_code(
    service: Any, monkeypatch: pytest.MonkeyPatch, method: str, args: tuple[Any, ...]
) -> None:
    class _Boom(_FakeR2):
        def _raise(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            raise R2Error("r2_unavailable", "radare2 not installed")

        open = disasm = xrefs = run = _raise  # type: ignore[assignment]

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client", lambda *a, **k: _Boom()
    )
    result = getattr(service, method)(_sid(service), *args)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "r2_unavailable"


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("r2_open", ()),
        ("r2_disasm", (0x1000,)),
        ("r2_xrefs", (0x1000,)),
        ("r2_info", ()),
    ],
)
def test_r2_methods_translate_an_unexpected_error(
    service: Any, monkeypatch: pytest.MonkeyPatch, method: str, args: tuple[Any, ...]
) -> None:
    class _Boom(_FakeR2):
        def _raise(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            raise RuntimeError("segfault in the pipe")

        open = disasm = xrefs = run = _raise  # type: ignore[assignment]

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client", lambda *a, **k: _Boom()
    )
    result = getattr(service, method)(_sid(service), *args)
    assert result.ok is False
    assert result.error is not None


def test_r2_disasm_and_xrefs_and_info_succeed(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client", lambda *a, **k: _FakeR2()
    )
    session_id = _sid(service)
    assert service.r2_disasm(session_id, 0x2000, count=4).ok
    assert service.r2_xrefs(session_id, 0x2000).ok
    info = service.r2_info(session_id)
    assert info.ok, info.error
    assert info.data is not None
    assert info.data["commands"] == ["i"]


# ---------------------------------------------------------------------------
# Ghidra: analyze and the export modes, including artifact recording.
# ---------------------------------------------------------------------------
class _FakeGhidra:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def analyze_binary(
        self, binary: Path, project: Path, *, timeout: float = 120.0
    ) -> dict[str, Any]:
        return {"analyzed": True, "binary": str(binary)}

    def functions(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"functions": [], "count": 0}

    def symbols(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"symbols": [], "count": 0}

    def xrefs(
        self,
        binary: Path,
        project: Path,
        address: str | int,
        *,
        limit: int = 256,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        return {"address": address, "xrefs": []}

    def decompile(
        self, binary: Path, project: Path, address: str | int, *, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"address": address, "code": "int main(){}"}


def test_ghidra_analyze_success_records_backend(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient", lambda *a, **k: _FakeGhidra()
    )
    result = service.ghidra_analyze(_sid(service))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["analyzed"] is True


def test_ghidra_analyze_translates_ghidraerror(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeGhidra):
        def analyze_binary(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise GhidraError("capability_unavailable", "ghidra not found")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient", lambda *a, **k: _Boom()
    )
    result = service.ghidra_analyze(_sid(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_ghidra_export_modes_all_run(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient", lambda *a, **k: _FakeGhidra()
    )
    session_id = _sid(service)
    assert service.ghidra_functions(session_id, limit=8).ok
    assert service.ghidra_symbols(session_id, limit=8).ok
    assert service.ghidra_xrefs(session_id, "0x401000", limit=8).ok
    assert service.ghidra_decompile(session_id, "0x401000").ok


def test_ghidra_export_records_an_artifact_when_a_file_is_written(
    service: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A decompilation that lands a file on disk is registered as an artifact.

    The whole-program export is the one big enough to persist, so the method
    hashes it and attaches an artifact id -- the branch a fake that returns
    only in-memory data never reaches.
    """
    export_file = tmp_path / "decompiled.c"
    export_file.write_text("int main(void){return 0;}\n", encoding="utf-8")

    class _Exporting(_FakeGhidra):
        def decompile(self, *a: Any, **k: Any) -> dict[str, Any]:
            return {"code": "...", "export_path": str(export_file)}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient", lambda *a, **k: _Exporting()
    )
    result = service.ghidra_decompile(_sid(service), "0x401000")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_ghidra_export_rejects_an_unknown_mode(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient", lambda *a, **k: _FakeGhidra()
    )
    result = _ghidra_export(service, _sid(service), "not-a-mode")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


# ---------------------------------------------------------------------------
# Frida process attach: needs a debuggee pid, faked here.
# ---------------------------------------------------------------------------
class _FakeFridaProc:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
        return {"attached": True, "pid": pid}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
        return {"modules": [], "count": 0, "pid": pid}

    def exports(
        self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
    ) -> dict[str, Any]:
        return {"exports": [], "count": 0, "module": module_name}

    def memory_read(
        self, pid: int, address: int, size: int, *, allowed_pid: int
    ) -> dict[str, Any]:
        return {"address": address, "size": size, "bytes": ""}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        return {"template": template, "pid": pid, "resident": False}


@pytest.fixture
def _frida_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *a, **k: _FakeFridaProc(),
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._require_debuggee_pid",
        lambda service, session_id: 4242,
    )


def test_frida_attach_success(service: Any, _frida_pid: None) -> None:
    result = service.frida_attach(_sid(service))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pid"] == 4242
    assert result.data["attached"] is True


def test_frida_modules_and_exports_and_memory_read_succeed(
    service: Any, _frida_pid: None
) -> None:
    session_id = _sid(service)
    assert service.frida_modules(session_id, limit=8).ok
    assert service.frida_exports(session_id, "libc.so", limit=8).ok
    read = service.frida_memory_read(session_id, 0x1000, 16)
    assert read.ok, read.error
    assert read.data is not None
    assert read.data["size"] == 16


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("frida_attach", ()),
        ("frida_modules", ()),
        ("frida_exports", ("libc.so",)),
        ("frida_memory_read", (0x1000, 16)),
    ],
)
def test_frida_process_methods_translate_fridaerror(
    service: Any,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    args: tuple[Any, ...],
) -> None:
    class _Boom(_FakeFridaProc):
        def _raise(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            raise FridaError("frida_unavailable", "frida not installed")

        attach = modules = exports = memory_read = _raise  # type: ignore[assignment]

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _Boom()
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._require_debuggee_pid",
        lambda service, session_id: 4242,
    )
    result = getattr(service, method)(_sid(service), *args)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "frida_unavailable"


def test_frida_hook_template_uses_the_debuggee_pid_when_not_device_bound(
    service: Any, _frida_pid: None
) -> None:
    """With no authorised device pids, hook.template falls back to the debuggee.

    A device-connected (APK/web) session hooks its authorised device pid; a
    plain session with an active debuggee takes the ``_require_debuggee_pid``
    branch instead. This session has no ``frida_authorized`` metadata, so it is
    the latter.
    """
    result = service.frida_hook_template(_sid(service), template="noop")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pid"] == 4242
    assert result.data["template"] == "noop"


def test_frida_hook_template_translates_fridaerror(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeFridaProc):
        def hook_template(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise FridaError("frida_rpc_error", "script load failed")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _Boom()
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._require_debuggee_pid",
        lambda service, session_id: 4242,
    )
    result = service.frida_hook_template(_sid(service), template="noop")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "frida_rpc_error"


def test_frida_attach_translates_an_unexpected_error(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeFridaProc):
        def attach(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise RuntimeError("usb stack died")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _Boom()
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._require_debuggee_pid",
        lambda service, session_id: 4242,
    )
    result = service.frida_attach(_sid(service))
    assert result.ok is False
    assert result.error is not None


# ---------------------------------------------------------------------------
# _require_debuggee_pid: the two guard branches and the happy return.
# ---------------------------------------------------------------------------
def test_require_debuggee_pid_rejects_an_unreadable_state() -> None:
    fake = SimpleNamespace(
        dynamic_state=lambda session_id: SimpleNamespace(ok=False, data=None)
    )
    with pytest.raises(Exception) as caught:
        _require_debuggee_pid(fake, "s1")
    assert getattr(caught.value, "code", None) == "invalid_state"


def test_require_debuggee_pid_rejects_when_no_debuggee_is_active() -> None:
    fake = SimpleNamespace(
        dynamic_state=lambda session_id: SimpleNamespace(ok=True, data={"debuggee_pid": 0})
    )
    with pytest.raises(Exception) as caught:
        _require_debuggee_pid(fake, "s1")
    assert getattr(caught.value, "code", None) == "invalid_state"


def test_require_debuggee_pid_returns_the_active_pid() -> None:
    fake = SimpleNamespace(
        dynamic_state=lambda session_id: SimpleNamespace(
            ok=True, data={"debuggee_pid": 1337}
        )
    )
    assert _require_debuggee_pid(fake, "s1") == 1337
