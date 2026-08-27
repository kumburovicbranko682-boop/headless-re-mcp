"""Service-layer paths for the portable (r2 / ghidra) analysis surface.

r2 and ghidra are the cross-format backends; their session wrappers live in the
grab-bag ``service_ext`` mixin rather than a dedicated module, and were only
exercised end to end. This covers them directly: the state gate before and
after the backend runs, the close-mid-run rollback, backend/timeline recording,
export-artifact registration, and the ``R2Error`` / ``GhidraError`` mapping.

The clients are faked in the module namespace, so no r2 or ghidra install is
touched; frida/windbg live methods in the same mixin belong to the native
debugger track and are covered elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_ext as service_ext
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.core.models import Result, Session, SessionState, TargetKind
from headless_re_mcp.core.service_ext import ExtAnalysisMixin, _ghidra_export


class _Repo:
    def __init__(self) -> None:
        self.backends: list[tuple[str, str, dict[str, Any]]] = []
        self.timeline: list[tuple[str, str, str, dict[str, Any]]] = []
        self.artifacts: list[dict[str, Any]] = []

    def record_backend(self, session_id: str, kind: str, **fields: Any) -> None:
        self.backends.append((session_id, kind, fields))

    def append_timeline(self, session_id: str, event: str, message: str, **details: Any) -> None:
        self.timeline.append((session_id, event, message, details))

    def register_artifact(self, **fields: Any) -> dict[str, Any]:
        self.artifacts.append(fields)
        return {"id": f"art-{len(self.artifacts)}"}


class _SeqRegistry:
    """A registry whose get() walks a fixed list of states across calls.

    Each portable method reads the session twice -- once to gate, once to
    verify it did not close while the backend ran -- so a two-element list can
    drive both the healthy path and the close-mid-run rollback.
    """

    def __init__(self, session: Session, states: list[SessionState]) -> None:
        self._session = session
        self._states = states
        self._i = 0

    def get(self, session_id: str) -> Session:
        state = self._states[min(self._i, len(self._states) - 1)]
        self._i += 1
        return self._session.model_copy(update={"state": state})


class _Host(ExtAnalysisMixin):
    def __init__(self, registry: _SeqRegistry, settings: Any, repo: _Repo) -> None:
        self.registry = registry
        self.settings = settings
        self.repository = repo


def _make_host(
    tmp_path: Path, states: list[SessionState] | None = None
) -> tuple[_Host, _Repo]:
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    session = Session(
        target=TargetKind.PE,
        binary=binary,
        locator=str(binary),
        state=SessionState.READY,
    )
    registry = _SeqRegistry(session, states or [SessionState.READY, SessionState.READY])
    settings = SimpleNamespace(r2=None, ghidra_home=None, artifact_root=tmp_path)
    repo = _Repo()
    return _Host(registry, settings, repo), repo


# --- fake backends --------------------------------------------------------


class _OkR2:
    def __init__(self, exe: Any = None) -> None:
        pass

    def open(self, binary: Path, timeout: float = 30.0) -> dict[str, Any]:
        return {"note": "one-shot open"}

    def run(self, binary: Path, commands: list[str], timeout: float = 30.0) -> dict[str, Any]:
        return {"raw": "[]", "commands": list(commands), "parsed": True}

    def disasm(
        self, binary: Path, address: int, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"raw": "nop", "address": address, "count": count}

    def xrefs(self, binary: Path, address: int, timeout: float = 30.0) -> dict[str, Any]:
        return {"raw": "", "address": address, "items": []}


class _BadR2:
    def __init__(self, exe: Any = None) -> None:
        pass

    def open(self, binary: Path, timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("capability_unavailable", "no r2 on PATH")

    def run(self, binary: Path, commands: list[str], timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 exited nonzero")

    def disasm(
        self, binary: Path, address: int, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        raise R2Error("invalid_params", "bad address")

    def xrefs(self, binary: Path, address: int, timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 exited nonzero")


class _OkGhidra:
    def __init__(self, home: Any = None) -> None:
        pass

    def analyze_binary(self, binary: Path, project: Path, timeout: float = 120.0) -> dict[str, Any]:
        return {"analyzed": True}

    def functions(
        self, binary: Path, project: Path, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"items": [], "count": 0}

    def symbols(
        self, binary: Path, project: Path, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"items": [], "count": 0}

    def xrefs(
        self,
        binary: Path,
        project: Path,
        address: str | int,
        limit: int = 256,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        return {"items": [], "address": address}

    def decompile(
        self, binary: Path, project: Path, address: str | int, timeout: float = 180.0
    ) -> dict[str, Any]:
        return {"decompilation": "int main(){}"}


class _BadGhidra:
    def __init__(self, home: Any = None) -> None:
        pass

    def analyze_binary(self, binary: Path, project: Path, timeout: float = 120.0) -> dict[str, Any]:
        raise GhidraError("capability_unavailable", "no ghidra home")

    def functions(
        self, binary: Path, project: Path, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        raise GhidraError("backend_error", "analyzeHeadless failed")

    def symbols(
        self, binary: Path, project: Path, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        raise GhidraError("backend_error", "analyzeHeadless failed")

    def xrefs(
        self,
        binary: Path,
        project: Path,
        address: str | int,
        limit: int = 256,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        raise GhidraError("backend_error", "analyzeHeadless failed")

    def decompile(
        self, binary: Path, project: Path, address: str | int, timeout: float = 180.0
    ) -> dict[str, Any]:
        raise GhidraError("backend_error", "analyzeHeadless failed")


# --- capabilities.describe -------------------------------------------------


def test_capabilities_describe_returns_a_found_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "describe_capability", lambda cid, settings: {"id": cid})

    result = host.capabilities_describe("static.functions")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["capability"]["id"] == "static.functions"


def test_capabilities_describe_reports_a_missing_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "describe_capability", lambda cid, settings: None)

    result = host.capabilities_describe("nope")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


# --- r2 surface ------------------------------------------------------------

_R2_CALLS: list[tuple[str, Callable[[_Host], Result[Any]]]] = [
    ("r2_open", lambda h: h.r2_open("sid")),
    ("r2_info", lambda h: h.r2_info("sid")),
    ("r2_functions", lambda h: h.r2_functions("sid")),
    ("r2_strings", lambda h: h.r2_strings("sid")),
    ("r2_imports", lambda h: h.r2_imports("sid")),
    ("r2_exports", lambda h: h.r2_exports("sid")),
    ("r2_disasm", lambda h: h.r2_disasm("sid", 0x401000)),
    ("r2_xrefs", lambda h: h.r2_xrefs("sid", 0x401000)),
]


@pytest.mark.parametrize("name,call", _R2_CALLS, ids=[n for n, _ in _R2_CALLS])
def test_r2_method_returns_the_backend_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "R2Client", _OkR2)

    result = call(host)

    assert result.ok, result.error
    assert result.meta.get("backend") == "radare2"


@pytest.mark.parametrize("name,call", _R2_CALLS, ids=[n for n, _ in _R2_CALLS])
def test_r2_method_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "R2Client", _BadR2)

    result = call(host)

    assert not result.ok
    assert result.error is not None
    assert result.error.code in {"capability_unavailable", "backend_error", "invalid_params"}


@pytest.mark.parametrize("name,call", _R2_CALLS, ids=[n for n, _ in _R2_CALLS])
def test_r2_method_is_refused_on_a_failed_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path, states=[SessionState.FAILED])
    monkeypatch.setattr(service_ext, "R2Client", _OkR2)

    result = call(host)

    assert not result.ok


@pytest.mark.parametrize("name,call", _R2_CALLS, ids=[n for n, _ in _R2_CALLS])
def test_r2_method_rolls_back_when_the_session_closes_midway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path, states=[SessionState.READY, SessionState.CLOSED])
    monkeypatch.setattr(service_ext, "R2Client", _OkR2)

    result = call(host)

    assert not result.ok


def test_r2_open_records_the_backend_and_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, repo = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "R2Client", _OkR2)

    host.r2_open("sid")

    assert repo.backends and repo.backends[0][1] == "radare2"
    assert any(event == "r2.open" for _sid, event, _msg, _d in repo.timeline)


# --- ghidra surface --------------------------------------------------------

_GHIDRA_CALLS: list[tuple[str, Callable[[_Host], Result[Any]]]] = [
    ("ghidra_analyze", lambda h: h.ghidra_analyze("sid")),
    ("ghidra_functions", lambda h: h.ghidra_functions("sid")),
    ("ghidra_symbols", lambda h: h.ghidra_symbols("sid")),
    ("ghidra_xrefs", lambda h: h.ghidra_xrefs("sid", 0x401000)),
    ("ghidra_decompile", lambda h: h.ghidra_decompile("sid", 0x401000)),
]


@pytest.mark.parametrize("name,call", _GHIDRA_CALLS, ids=[n for n, _ in _GHIDRA_CALLS])
def test_ghidra_method_returns_the_backend_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = call(host)

    assert result.ok, result.error
    assert result.meta.get("backend") == "ghidra"


@pytest.mark.parametrize("name,call", _GHIDRA_CALLS, ids=[n for n, _ in _GHIDRA_CALLS])
def test_ghidra_method_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "GhidraClient", _BadGhidra)

    result = call(host)

    assert not result.ok
    assert result.error is not None
    assert result.error.code in {"capability_unavailable", "backend_error"}


@pytest.mark.parametrize("name,call", _GHIDRA_CALLS, ids=[n for n, _ in _GHIDRA_CALLS])
def test_ghidra_method_is_refused_on_a_failed_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path, states=[SessionState.FAILED])
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = call(host)

    assert not result.ok


@pytest.mark.parametrize("name,call", _GHIDRA_CALLS, ids=[n for n, _ in _GHIDRA_CALLS])
def test_ghidra_method_rolls_back_when_the_session_closes_midway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, call: Callable[[_Host], Result[Any]]
) -> None:
    host, _ = _make_host(tmp_path, states=[SessionState.READY, SessionState.CLOSED])
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = call(host)

    assert not result.ok


def test_ghidra_xrefs_requires_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = host.ghidra_xrefs("sid", address=None)  # type: ignore[arg-type]

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_ghidra_decompile_requires_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = host.ghidra_decompile("sid", address=None)  # type: ignore[arg-type]

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_ghidra_export_registers_a_written_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, repo = _make_host(tmp_path)
    export = tmp_path / "decomp.c"
    export.write_text("int main(){return 0;}\n", encoding="utf-8")

    class _Exporting(_OkGhidra):
        def decompile(
            self, binary: Path, project: Path, address: str | int, timeout: float = 180.0
        ) -> dict[str, Any]:
            return {"decompilation": "int main(){}", "export_path": str(export)}

    monkeypatch.setattr(service_ext, "GhidraClient", _Exporting)

    result = host.ghidra_decompile("sid", 0x401000)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"] == "art-1"
    assert repo.artifacts and repo.artifacts[0]["kind"] == "ghidra_decompile"


def test_ghidra_export_rejects_an_unknown_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, _ = _make_host(tmp_path)
    monkeypatch.setattr(service_ext, "GhidraClient", _OkGhidra)

    result = _ghidra_export(host, "sid", "not-a-mode")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"
