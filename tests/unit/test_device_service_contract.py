"""Service-layer contract for the device.* ADB surface.

test_device_connect_honesty.py pins the one subtle bit of device_connect (a
refused TCP connect is not an ok envelope); test_device_artifacts.py pins the
retention math. What was left is the plumbing every device.* method shares: the
_adb_wrap envelope (success, structured AdbError, and the generic fallback), the
backend accessor's construct-on-demand fallback, and the capture-size guard that
screenshot/pull run after a transfer -- delete an over-limit file, prune the
capture directory, and answer output_too_large.

All of it is device-free: a fake backend (never a real adb) decides what each
op returns or raises, and the oversize guard is forced by stubbing
refuse_oversized_device_file so no 64 MiB file has to be written. The pure guard
itself is pinned directly with an explicit small limit.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.core import service_device
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    refuse_oversized_device_file,
)


class _FakeBackend:
    def __init__(
        self,
        *,
        connect_result: dict[str, Any] | None = None,
        connect_error: BaseException | None = None,
        capture_error: BaseException | None = None,
    ) -> None:
        self._connect_result = connect_result
        self._connect_error = connect_error
        self._capture_error = capture_error

    def list_devices(self) -> dict[str, Any]:
        return {"devices": [], "count": 0}

    def connect(self, host: str, port: int) -> dict[str, Any]:
        if self._connect_error is not None:
            raise self._connect_error
        return self._connect_result or {"endpoint": f"{host}:{port}", "connected": True}

    def screenshot(self, serial: str, out_path: Path) -> dict[str, Any]:
        del serial
        if self._capture_error is not None:
            raise self._capture_error
        Path(out_path).write_bytes(b"PNG")
        return {"path": str(out_path), "size": 3}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
        del serial
        if self._capture_error is not None:
            raise self._capture_error
        Path(local_path).write_bytes(b"data")
        return {"remote": remote_path, "local": str(local_path), "size": 4}

    def boom(self) -> dict[str, Any]:
        raise RuntimeError("kaboom")


class _RecordingBackend:
    """Records (op, kwargs) for whatever method the wrapper calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def _call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((name, kwargs))
            return {"op": name}

        return _call


class _Harness(DeviceAnalysisMixin):
    def __init__(self, backend: Any, artifact_root: Path) -> None:
        self.settings = SimpleNamespace(adb=None, artifact_root=artifact_root)
        self._fake = backend

    def _backend(self) -> Any:  # type: ignore[override]
        return self._fake


# --- refuse_oversized_device_file (pure guard) ----------------------------


def test_refuse_oversized_device_file_missing_path_is_none(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "gone.bin", limit=10) is None


def test_refuse_oversized_device_file_under_limit_is_none(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"hi")
    assert refuse_oversized_device_file(small, limit=10) is None
    assert small.exists()


def test_refuse_oversized_device_file_deletes_and_reports_over_limit(tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"0123456789ABCDEF")
    result = refuse_oversized_device_file(big, limit=8)
    assert result is not None
    assert result.ok is False
    assert result.error is not None and result.error.code == "output_too_large"
    assert not big.exists()  # the over-limit capture is reclaimed


# --- _backend construct-on-demand -----------------------------------------


def test_backend_constructs_a_backend_when_none_is_owned() -> None:
    class _Bare(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(adb=None)

    assert isinstance(_Bare()._backend(), AdbBackend)


# --- _adb_wrap envelope ---------------------------------------------------


def test_adb_wrap_returns_success_for_a_dict(tmp_path: Path) -> None:
    result = _Harness(_FakeBackend(), tmp_path).device_list()
    assert result.ok and result.data is not None
    assert result.data["count"] == 0


def test_adb_wrap_maps_a_generic_exception_to_internal(tmp_path: Path) -> None:
    # A non-AdbError from the backend falls to the generic branch and becomes
    # internal_error rather than escaping the service.
    result = _Harness(_FakeBackend(), tmp_path)._adb_wrap("boom")
    assert result.ok is False
    assert result.error is not None and result.error.code == "internal_error"


# --- device_connect failure passthrough -----------------------------------


def test_device_connect_returns_a_backend_failure_unchanged(tmp_path: Path) -> None:
    # When the backend itself raises, device_connect returns that failure
    # directly; the connected-false honesty check only runs on an ok result.
    backend = _FakeBackend(connect_error=AdbError("backend_error", "refused"))
    result = _Harness(backend, tmp_path).device_connect("127.0.0.1", 5555)
    assert result.ok is False
    assert result.error is not None and result.error.code == "backend_error"


# --- device_screenshot / device_pull oversize guard -----------------------


def _force_oversize(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(_out: Path) -> Result[dict[str, Any]]:
        return Result[dict[str, Any]](
            ok=False,
            error=RpcError(code="output_too_large", message="too big", details={}),
        )

    monkeypatch.setattr(service_device, "refuse_oversized_device_file", _fail)


def test_device_screenshot_success_prunes_and_returns(tmp_path: Path) -> None:
    result = _Harness(_FakeBackend(), tmp_path).device_screenshot("emulator-5554")
    assert result.ok and result.data is not None
    assert Path(result.data["path"]).exists()


def test_device_screenshot_over_limit_prunes_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_oversize(monkeypatch)
    result = _Harness(_FakeBackend(), tmp_path).device_screenshot("emulator-5554")
    assert result.ok is False
    assert result.error is not None and result.error.code == "output_too_large"


def test_device_pull_success_prunes_and_returns(tmp_path: Path) -> None:
    result = _Harness(_FakeBackend(), tmp_path).device_pull("emulator-5554", "/sdcard/x.txt")
    assert result.ok and result.data is not None
    assert Path(result.data["local"]).exists()


def test_device_pull_over_limit_prunes_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_oversize(monkeypatch)
    result = _Harness(_FakeBackend(), tmp_path).device_pull("emulator-5554", "/sdcard/x.txt")
    assert result.ok is False
    assert result.error is not None and result.error.code == "output_too_large"


def test_device_screenshot_failure_still_prunes_and_passes_through(tmp_path: Path) -> None:
    # A failed capture (backend raised) skips the size guard but still prunes
    # the directory before returning the failure.
    backend = _FakeBackend(capture_error=AdbError("backend_error", "no framebuffer"))
    result = _Harness(backend, tmp_path).device_screenshot("emulator-5554")
    assert result.ok is False
    assert result.error is not None and result.error.code == "backend_error"


def test_device_pull_failure_still_prunes_and_passes_through(tmp_path: Path) -> None:
    backend = _FakeBackend(capture_error=AdbError("not_found", "missing remote"))
    result = _Harness(backend, tmp_path).device_pull("emulator-5554", "/sdcard/x.txt")
    assert result.ok is False
    assert result.error is not None and result.error.code == "not_found"


# --- wrapper methods forward the right op and kwargs ----------------------


@pytest.mark.parametrize(
    ("call", "op", "expected"),
    [
        (lambda h: h.device_info("s"), "info", {"serial": "s"}),
        (lambda h: h.device_properties("s"), "properties", {"serial": "s", "limit": 500}),
        (
            lambda h: h.device_packages("s"),
            "packages",
            {"serial": "s", "third_party_only": False, "limit": 500},
        ),
        (
            lambda h: h.device_install("s", "/a.apk"),
            "install",
            {"serial": "s", "apk_path": "/a.apk", "reinstall": True},
        ),
        (
            lambda h: h.device_uninstall("s", "com.x"),
            "uninstall",
            {"serial": "s", "package": "com.x"},
        ),
        (lambda h: h.device_launch("s", "com.x"), "launch", {"serial": "s", "package": "com.x"}),
        (
            lambda h: h.device_force_stop("s", "com.x"),
            "force_stop",
            {"serial": "s", "package": "com.x"},
        ),
        (lambda h: h.device_current_activity("s"), "current_activity", {"serial": "s"}),
        (lambda h: h.device_logcat("s"), "logcat", {"serial": "s", "lines": 200}),
        (
            lambda h: h.device_push("s", "/l", "/r"),
            "push",
            {"serial": "s", "local_path": "/l", "remote_path": "/r"},
        ),
        (
            lambda h: h.device_forward("s", "tcp:1", "tcp:2"),
            "forward",
            {"serial": "s", "local": "tcp:1", "remote": "tcp:2"},
        ),
    ],
)
def test_wrapper_methods_forward_the_op_and_kwargs(
    tmp_path: Path, call: Any, op: str, expected: dict[str, Any]
) -> None:
    backend = _RecordingBackend()
    result = call(_Harness(backend, tmp_path))
    assert result.ok
    assert backend.calls == [(op, expected)]
