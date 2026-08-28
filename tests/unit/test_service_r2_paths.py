"""Success and error-envelope coverage for the radare2 service methods.

``core/service_ext`` exposes ``r2_open``, ``r2_disasm``, ``r2_xrefs`` and the
whitelist-command helper ``_r2_request`` (behind ``r2_info`` / ``r2_functions``
/ ``r2_strings`` / ``r2_imports`` / ``r2_exports``). The closed-session gate in
``test_r2_closed_session`` only reaches the pre-run state check and ``r2_open``'s
mid-run re-check, so each method's happy path (record backend + timeline +
``_success`` envelope), the ``R2Error`` -> structured-envelope mapping, the
unexpected-error arm, and ``_r2_request``'s own mid-run re-check were never run.

radare2 is a portable, non-PE backend, so these fake ``R2Client`` and drive the
service directly the way the r2 closed-session gate already does.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeR2:
    """Records each call and returns a fixed payload for the happy path."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        self.calls.append(("open", timeout))
        return {"opened": True, "binary": str(binary), "info": "arch=x86", "note": "fake"}

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        self.calls.append(("disasm", address, count))
        return {"raw": "pdj", "address": address, "count": count}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        self.calls.append(("xrefs", address))
        return {"raw": "axj", "address": address}

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        self.calls.append(("run", tuple(commands)))
        return {"raw": "info", "commands": list(commands)}


class _BoomR2:
    """Every op raises the same R2Error so the envelope mapping is uniform."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise R2Error("process_failed", "r2 exited non-zero", stderr="boom")

        return _fn


class _CrashR2:
    """Raises a bare RuntimeError to reach the unexpected-error arm."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("r2 wrapper blew up")

        return _fn


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _pe_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _patch_r2(monkeypatch: Any, factory: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.core.service_ext.R2Client", factory)


# --------------------------------------------------------------------------- #
# r2_open                                                                      #
# --------------------------------------------------------------------------- #
def test_r2_open_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_open(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["opened"] is True
        assert result.meta["backend"] == "radare2"
        assert ("open", 30.0) in fake.calls
    finally:
        service.close_all()


def test_r2_open_maps_an_r2_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_r2(monkeypatch, _BoomR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_open(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
        assert result.error.details.get("stderr") == "boom"
    finally:
        service.close_all()


def test_r2_open_wraps_an_unexpected_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_r2(monkeypatch, _CrashR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_open(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# r2_disasm / r2_xrefs                                                         #
# --------------------------------------------------------------------------- #
def test_r2_disasm_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_disasm(session_id, 0x1000, count=8)
        assert result.ok, result.error
        assert result.data is not None and result.data["address"] == 0x1000
        assert result.data["count"] == 8
        assert result.meta["backend"] == "radare2"
        assert ("disasm", 0x1000, 8) in fake.calls
    finally:
        service.close_all()


def test_r2_disasm_maps_an_r2_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_r2(monkeypatch, _BoomR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_disasm(session_id, 0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
    finally:
        service.close_all()


def test_r2_xrefs_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_xrefs(session_id, 0x2000)
        assert result.ok, result.error
        assert result.data is not None and result.data["address"] == 0x2000
        assert result.meta["backend"] == "radare2"
        assert ("xrefs", 0x2000) in fake.calls
    finally:
        service.close_all()


def test_r2_xrefs_maps_an_r2_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_r2(monkeypatch, _BoomR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_xrefs(session_id, 0x2000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# _r2_request (r2_info / r2_functions / ...)                                   #
# --------------------------------------------------------------------------- #
def test_r2_info_runs_a_whitelist_command(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_info(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["commands"] == ["i"]
        assert result.meta["backend"] == "radare2"
    finally:
        service.close_all()


def test_r2_functions_maps_an_r2_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_r2(monkeypatch, _BoomR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.r2_functions(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "commands"),
    [("r2_strings", ["izj"]), ("r2_imports", ["iij"]), ("r2_exports", ["iEj"])],
)
def test_r2_whitelist_readouts_run_their_command(
    tmp_path: Path, monkeypatch: Any, method: str, commands: list[str]
) -> None:
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = getattr(service, method)(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["commands"] == commands
        assert result.meta["backend"] == "radare2"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# r2_disasm / r2_xrefs state guards and unexpected-error arm                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method", ["r2_disasm", "r2_xrefs"])
def test_r2_address_ops_reject_a_closed_session(
    tmp_path: Path, monkeypatch: Any, method: str
) -> None:
    """The retained-CLOSED invariant the open/functions gate pins holds here too."""
    fake = _FakeR2()
    _patch_r2(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        result = getattr(service, method)(session_id, 0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert fake.calls == []  # never reached the backend
    finally:
        service.close_all()


@pytest.mark.parametrize("method", ["r2_disasm", "r2_xrefs"])
def test_r2_address_ops_do_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any, method: str
) -> None:
    service = _service(tmp_path)
    holder: dict[str, str] = {}

    class _CloseThenRun(_FakeR2):
        def disasm(
            self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
        ) -> dict[str, Any]:
            service.close_session(holder["session_id"])
            return super().disasm(binary, address, count=count, timeout=timeout)

        def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
            service.close_session(holder["session_id"])
            return super().xrefs(binary, address, timeout=timeout)

    _patch_r2(monkeypatch, lambda *a, **k: _CloseThenRun())
    try:
        holder["session_id"] = _pe_session(service, tmp_path)
        result = getattr(service, method)(holder["session_id"], 0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "args"), [("r2_disasm", (0x1000,)), ("r2_xrefs", (0x1000,))]
)
def test_r2_address_ops_wrap_an_unexpected_error(
    tmp_path: Path, monkeypatch: Any, method: str, args: tuple[int, ...]
) -> None:
    _patch_r2(monkeypatch, _CrashR2)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = getattr(service, method)(session_id, *args)
        assert result.ok is False and result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


def test_r2_request_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close during the whitelist run must fail, not record radare2 on a dead session."""
    service = _service(tmp_path)
    holder: dict[str, str] = {}

    class _CloseThenRun(_FakeR2):
        def run(
            self, binary: Path, commands: list[str], *, timeout: float = 30.0
        ) -> dict[str, Any]:
            service.close_session(holder["session_id"])
            return super().run(binary, commands, timeout=timeout)

    _patch_r2(monkeypatch, lambda *a, **k: _CloseThenRun())
    try:
        holder["session_id"] = _pe_session(service, tmp_path)
        result = service.r2_info(holder["session_id"])
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()
