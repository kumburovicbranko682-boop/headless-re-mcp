"""Cover device.* helpers and the capture-size guards that only fire on a
successful pull/screenshot: the artifact pruner's empty/short-circuit arms, the
oversized-file refusal, the unexpected-error envelope, and the screenshot/pull
paths that delete and refuse an over-limit capture.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_device as sd
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


# --- module-level helpers -----------------------------------------------------


def test_prune_device_artifacts_ignores_a_missing_directory(tmp_path: Path) -> None:
    # iterdir on a path that does not exist raises OSError and is swallowed.
    sd.prune_device_artifacts(tmp_path / "not-there")


def test_prune_device_artifacts_keeps_an_underfull_directory(tmp_path: Path) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    (directory / "a.png").write_bytes(b"x")
    sd.prune_device_artifacts(directory, keep=32)
    assert (directory / "a.png").is_file()


def test_refuse_oversized_device_file_ignores_a_missing_file(tmp_path: Path) -> None:
    assert sd.refuse_oversized_device_file(tmp_path / "gone.bin") is None


def test_refuse_oversized_device_file_deletes_and_refuses_a_large_capture(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "big.bin"
    capture.write_bytes(b"0123456789ABCDEF")
    refused = sd.refuse_oversized_device_file(capture, limit=4)
    assert refused is not None
    assert refused.ok is False
    assert refused.error is not None
    assert refused.error.code == "output_too_large"
    assert not capture.exists()


def test_backend_builds_a_default_when_none_is_owned(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        service._adb_backend = object()  # type: ignore[assignment]
        backend = service._backend()
        assert backend is not None
    finally:
        service.close_all()


# --- _adb_wrap unexpected error -----------------------------------------------


class _FakeBackend:
    def __init__(self, *, screenshot_to: Path | None = None, pull_to: Path | None = None) -> None:
        self.screenshot_to = screenshot_to
        self.pull_to = pull_to

    def boom(self, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("adbutils blew up")

    def screenshot(self, *, serial: str, out_path: Path) -> dict[str, Any]:
        out_path.write_bytes(b"PNGDATA")
        return {"serial": serial, "path": str(out_path)}

    def pull(self, *, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
        local_path.write_bytes(b"PULLDATA")
        return {"serial": serial, "path": str(local_path)}


def test_adb_wrap_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeBackend()
    monkeypatch.setattr(service, "_backend", lambda: fake)
    try:
        result = service._adb_wrap("boom")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


# --- screenshot / pull oversized capture --------------------------------------


def _oversized_result() -> Result[dict[str, Any]]:
    return Result[dict[str, Any]](
        ok=False,
        error=RpcError(code="output_too_large", message="too big"),
    )


def test_device_screenshot_refuses_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeBackend()
    monkeypatch.setattr(service, "_backend", lambda: fake)
    monkeypatch.setattr(sd, "refuse_oversized_device_file", lambda path: _oversized_result())
    try:
        result = service.device_screenshot("emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "output_too_large"
    finally:
        service.close_all()


def test_device_pull_refuses_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeBackend()
    monkeypatch.setattr(service, "_backend", lambda: fake)
    monkeypatch.setattr(sd, "refuse_oversized_device_file", lambda path: _oversized_result())
    try:
        result = service.device_pull("emulator-5554", "/data/local/tmp/file.bin")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "output_too_large"
    finally:
        service.close_all()


def test_device_screenshot_keeps_a_reasonable_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeBackend()
    monkeypatch.setattr(service, "_backend", lambda: fake)
    try:
        result = service.device_screenshot("emulator-5554")
        assert result.ok is True
        assert result.data is not None
    finally:
        service.close_all()
