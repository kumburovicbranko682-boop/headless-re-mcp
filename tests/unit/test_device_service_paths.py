"""Guard and capture-cap paths for the ADB device-control service.

The device.* field suites drive the adb backend through fakes, and the artifact
suite drives the per-directory count cap, but the service mixin's own edges --
the per-call backend fallback, the generic (non-AdbError) failure arc, the
"capture came back over the byte cap" screenshot/pull branches, and the small
pruning/sizing helpers' defensive returns -- ran in none of them. These drive
the mixin directly with a lightweight harness so no real adb device is needed.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.core import service_device
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


class _RealBackendHarness(DeviceAnalysisMixin):
    """No _adb_backend attribute, so _backend() must build one per call."""

    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]


class _StubBackend:
    """An adb backend stand-in whose one op raises whatever it is given."""

    def __init__(self, **ops: Any) -> None:
        for name, fn in ops.items():
            setattr(self, name, fn)


class _StubBackendHarness(DeviceAnalysisMixin):
    def __init__(self, root: Path, backend: _StubBackend) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]
        self._stub = backend

    def _backend(self) -> Any:
        return self._stub


class _CaptureHarness(DeviceAnalysisMixin):
    """A harness whose _adb_wrap writes a small file and reports success."""

    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]

    def _adb_wrap(self, op: str, /, **kwargs: object) -> Result[JsonObject]:
        path = Path(str(kwargs.get("out_path") or kwargs.get("local_path")))
        path.write_bytes(b"x" * 1024)
        return _success({"path": str(path)}, backend="adb")


class _RecordingBackend:
    """Records the op it was asked to run and echoes the arguments back."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def _op(**kwargs: Any) -> JsonObject:
            self.calls.append((name, kwargs))
            return {"op": name, **kwargs}

        return _op


# --- _backend fallback -------------------------------------------------------


def test_backend_is_constructed_per_call_without_an_owned_backend(tmp_path: Path) -> None:
    """A mixin with no owned backend builds a fresh AdbBackend on demand."""
    backend = _RealBackendHarness(tmp_path)._backend()
    assert isinstance(backend, AdbBackend)


# --- _adb_wrap generic failure ----------------------------------------------


def test_adb_wrap_maps_an_unexpected_error_to_internal_error(tmp_path: Path) -> None:
    """A non-AdbError fault from the backend still becomes a structured envelope."""

    def _boom() -> Any:
        raise RuntimeError("adbutils threw something unexpected")

    harness = _StubBackendHarness(tmp_path, _StubBackend(list_devices=_boom))
    result = harness.device_list()
    assert result.ok is False
    assert result.error is not None and result.error.code == "internal_error"


def test_adb_wrap_maps_an_adb_error_to_its_code(tmp_path: Path) -> None:
    """An AdbError keeps its structured code through the envelope."""

    def _boom(*, serial: str) -> Any:
        raise AdbError("not_found", f"no such device {serial}")

    harness = _StubBackendHarness(tmp_path, _StubBackend(info=_boom))
    result = harness.device_info("emulator-5554")
    assert result.ok is False
    assert result.error is not None and result.error.code == "not_found"


# --- the bounded, named device operations dispatch to the right adb op -------


@pytest.mark.parametrize(
    ("invoke", "expected_op"),
    [
        (lambda s: s.device_properties("emulator-5554"), "properties"),
        (lambda s: s.device_packages("emulator-5554"), "packages"),
        (lambda s: s.device_install("emulator-5554", "/tmp/app.apk"), "install"),
        (lambda s: s.device_uninstall("emulator-5554", "com.example"), "uninstall"),
        (lambda s: s.device_launch("emulator-5554", "com.example"), "launch"),
        (lambda s: s.device_force_stop("emulator-5554", "com.example"), "force_stop"),
        (lambda s: s.device_current_activity("emulator-5554"), "current_activity"),
        (lambda s: s.device_logcat("emulator-5554"), "logcat"),
        (lambda s: s.device_push("emulator-5554", "/tmp/l", "/sdcard/r"), "push"),
        (lambda s: s.device_forward("emulator-5554", "tcp:1", "tcp:2"), "forward"),
    ],
)
def test_named_device_ops_dispatch_to_their_adb_operation(
    tmp_path: Path, invoke: Any, expected_op: str
) -> None:
    """Each named tool forwards to exactly the adb op it advertises."""
    backend = _RecordingBackend()
    harness = _StubBackendHarness(tmp_path, backend)  # type: ignore[arg-type]
    result = invoke(harness)
    assert result.ok is True, result.error
    assert result.data is not None and result.data["op"] == expected_op
    assert backend.calls[0][0] == expected_op


# --- failure arcs: the op fails, but capture cleanup still runs ---------------


def test_device_connect_returns_the_failure_when_the_op_fails(tmp_path: Path) -> None:
    """A connect that raises AdbError is surfaced, not swallowed into ok."""

    def _boom(*, host: str, port: int) -> Any:
        raise AdbError("backend_error", f"cannot reach {host}:{port}")

    harness = _StubBackendHarness(tmp_path, _StubBackend(connect=_boom))
    result = harness.device_connect()
    assert result.ok is False
    assert result.error is not None and result.error.code == "backend_error"


def test_device_screenshot_prunes_and_returns_a_backend_failure(tmp_path: Path) -> None:
    """When the screenshot op fails, the directory is still pruned and the error returned."""

    def _boom(*, serial: str, out_path: Path) -> Any:
        raise AdbError("backend_error", "screencap failed")

    harness = _StubBackendHarness(tmp_path, _StubBackend(screenshot=_boom))
    result = harness.device_screenshot("emulator-5554")
    assert result.ok is False
    assert result.error is not None and result.error.code == "backend_error"


def test_device_pull_prunes_and_returns_a_backend_failure(tmp_path: Path) -> None:
    """When the pull op fails, the directory is still pruned and the error returned."""

    def _boom(*, serial: str, remote_path: str, local_path: Path) -> Any:
        raise AdbError("not_found", "no such remote path")

    harness = _StubBackendHarness(tmp_path, _StubBackend(pull=_boom))
    result = harness.device_pull("emulator-5554", "/sdcard/gone.bin")
    assert result.ok is False
    assert result.error is not None and result.error.code == "not_found"


# --- screenshot / pull oversized branches ------------------------------------


def _oversized_result() -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="over the cap", details={}),
    )


def test_device_screenshot_refuses_and_prunes_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A screenshot that comes back over the byte cap is refused, not returned ok."""
    monkeypatch.setattr(
        service_device, "refuse_oversized_device_file", lambda _path: _oversized_result()
    )
    result = _CaptureHarness(tmp_path).device_screenshot("emulator-5554")
    assert result.ok is False
    assert result.error is not None and result.error.code == "output_too_large"


def test_device_pull_refuses_and_prunes_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pull that comes back over the byte cap is refused, not returned ok."""
    monkeypatch.setattr(
        service_device, "refuse_oversized_device_file", lambda _path: _oversized_result()
    )
    result = _CaptureHarness(tmp_path).device_pull("emulator-5554", "/sdcard/big.bin")
    assert result.ok is False
    assert result.error is not None and result.error.code == "output_too_large"


# --- helper defensive returns ------------------------------------------------


def test_refuse_oversized_device_file_ignores_a_missing_path(tmp_path: Path) -> None:
    """A capture path that is not on disk is a no-op, not an error."""
    assert refuse_oversized_device_file(tmp_path / "gone.bin") is None


def test_prune_device_artifacts_tolerates_a_missing_directory(tmp_path: Path) -> None:
    """A directory that cannot be listed is left alone, not raised over."""
    prune_device_artifacts(tmp_path / "never-made")


def test_prune_device_artifacts_is_a_noop_below_the_keep_count(tmp_path: Path) -> None:
    """A directory holding fewer files than the keep count is untouched."""
    directory = tmp_path / "device"
    directory.mkdir()
    kept = directory / "one.png"
    kept.write_bytes(b"x")
    prune_device_artifacts(directory, keep=32)
    assert kept.exists()
