"""Guard and error branches of the ADB device-control service surface.

The existing device tests pin the directory-count/byte caps, the portable pull
suffix and the connect honesty. This file fills in the branches those step
over: the artifact pruner's unreadable-directory and under-cap early returns
and its per-file stat failure, the oversize check's stat failure, the backend
accessor constructing a backend when none is owned, the ``_adb_wrap`` catch-all
for an unexpected error, and the oversized-capture refuse-and-prune arcs on
device.screenshot and device.pull. Each test pins one branch; no real adb runs.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.core import service_device as sd
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


class _Harness(DeviceAnalysisMixin):
    """A mixin host whose _adb_wrap writes a stand-in capture, as adb would."""

    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root)

    def _adb_wrap(self, op: str, /, **kwargs: object) -> Result[JsonObject]:  # type: ignore[override]
        path = Path(str(kwargs.get("out_path") or kwargs.get("local_path")))
        path.write_bytes(b"x" * 4096)
        return _success({"path": str(path)}, backend="adb")


# ---------------------------------------------------------------------------
# prune_device_artifacts.
# ---------------------------------------------------------------------------
def test_prune_ignores_an_unreadable_directory(tmp_path: Path) -> None:
    """A directory that cannot be listed is left alone, not raised through."""
    prune_device_artifacts(tmp_path / "absent", keep=32)


def test_prune_keeps_everything_under_the_cap(tmp_path: Path) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    (directory / "a.png").write_bytes(b"x")
    prune_device_artifacts(directory, keep=32)
    assert (directory / "a.png").exists()


def test_prune_survives_a_per_file_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file whose mtime probe fails sorts as oldest instead of crashing.

    The listing's is_file() stat succeeds; the sort-key stat then fails, so the
    key falls back to 0 and the file is treated as the oldest capture.
    """
    directory = tmp_path / "device"
    directory.mkdir()
    for i in range(3):
        (directory / f"s{i}.png").write_bytes(b"x")
    real_stat = Path.stat
    calls: dict[str, int] = {}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "s1.png":
            calls[self.name] = calls.get(self.name, 0) + 1
            if calls[self.name] >= 2:
                raise OSError("stat denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    prune_device_artifacts(directory, keep=1)
    assert len(list(directory.iterdir())) == 1


# ---------------------------------------------------------------------------
# refuse_oversized_device_file.
# ---------------------------------------------------------------------------
def test_refuse_returns_none_when_stat_fails(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "absent.bin", limit=10) is None


# ---------------------------------------------------------------------------
# _backend / _adb_wrap.
# ---------------------------------------------------------------------------
def test_backend_constructs_one_when_none_is_owned(tmp_path: Path) -> None:
    class _Host(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(artifact_root=tmp_path, adb=None)

    backend = _Host()._backend()
    assert isinstance(backend, AdbBackend)


def test_adb_wrap_maps_an_adb_error_to_a_structured_failure(tmp_path: Path) -> None:
    class _Boom:
        def list_devices(self, **kwargs: Any) -> Any:
            raise AdbError("backend_error", "adb server unreachable", endpoint="127.0.0.1:5037")

    class _Host(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(artifact_root=tmp_path)

        def _backend(self) -> Any:  # type: ignore[override]
            return _Boom()

    result = _Host().device_list()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


class _Recorder:
    """A stand-in backend that records the op it was called with."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def method(**kwargs: Any) -> JsonObject:
            self.calls.append((name, kwargs))
            target = kwargs.get("out_path") or kwargs.get("local_path")
            if target is not None:
                Path(str(target)).write_bytes(b"x" * 16)
            if name == "connect":
                return {"connected": True, "endpoint": "127.0.0.1:5555"}
            return {"ok": True}

        return method


def test_every_device_method_forwards_to_its_backend_op(tmp_path: Path) -> None:
    """Each device.* surface method maps to exactly one named backend op."""
    recorder = _Recorder()

    class _Host(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(artifact_root=tmp_path)

        def _backend(self) -> Any:  # type: ignore[override]
            return recorder

    host = _Host()
    assert host.device_connect().ok is True
    assert host.device_info("s").ok is True
    assert host.device_properties("s").ok is True
    assert host.device_packages("s").ok is True
    assert host.device_install("s", "/tmp/a.apk").ok is True
    assert host.device_uninstall("s", "com.x").ok is True
    assert host.device_launch("s", "com.x").ok is True
    assert host.device_force_stop("s", "com.x").ok is True
    assert host.device_current_activity("s").ok is True
    assert host.device_logcat("s").ok is True
    assert host.device_screenshot("s").ok is True
    assert host.device_pull("s", "/sdcard/a.txt").ok is True
    assert host.device_push("s", "/tmp/a", "/sdcard/a").ok is True
    assert host.device_forward("s", "tcp:1", "tcp:2").ok is True

    ops = [name for name, _ in recorder.calls]
    assert ops == [
        "connect",
        "info",
        "properties",
        "packages",
        "install",
        "uninstall",
        "launch",
        "force_stop",
        "current_activity",
        "logcat",
        "screenshot",
        "pull",
        "push",
        "forward",
    ]


def test_failed_device_ops_return_the_failure_and_still_prune(tmp_path: Path) -> None:
    """When the adb op fails, connect/screenshot/pull surface the failure.

    screenshot and pull still run their directory prune on the failure path so a
    half-written capture cannot accumulate.
    """

    class _Fail:
        def __getattr__(self, name: str) -> Any:
            def method(**kwargs: Any) -> Any:
                raise AdbError("backend_error", f"{name} failed")

            return method

    class _Host(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(artifact_root=tmp_path)

        def _backend(self) -> Any:  # type: ignore[override]
            return _Fail()

    host = _Host()
    assert host.device_connect().ok is False
    assert host.device_screenshot("s").ok is False
    assert host.device_pull("s", "/sdcard/a.txt").ok is False


def test_adb_wrap_wraps_an_unexpected_error(tmp_path: Path) -> None:
    """A non-AdbError from the backend is caught, not leaked as an internal fault."""

    class _Boom:
        def list_devices(self, **kwargs: Any) -> Any:
            raise ValueError("kaboom")

    class _Host(DeviceAnalysisMixin):
        def __init__(self) -> None:
            self.settings = SimpleNamespace(artifact_root=tmp_path)

        def _backend(self) -> Any:  # type: ignore[override]
            return _Boom()

    result = _Host().device_list()
    assert result.ok is False
    assert result.error is not None


# ---------------------------------------------------------------------------
# oversized-capture refuse-and-prune arcs.
# ---------------------------------------------------------------------------
def _oversized_sentinel() -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="too big", details={}),
    )


def test_screenshot_refuses_and_prunes_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = _oversized_sentinel()
    monkeypatch.setattr(sd, "refuse_oversized_device_file", lambda path: sentinel)
    result = _Harness(tmp_path).device_screenshot("emulator-5554")
    assert result is sentinel
    assert (tmp_path / "device").is_dir()


def test_pull_refuses_and_prunes_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = _oversized_sentinel()
    monkeypatch.setattr(sd, "refuse_oversized_device_file", lambda path: sentinel)
    result = _Harness(tmp_path).device_pull("emulator-5554", "/sdcard/big.bin")
    assert result is sentinel
    assert (tmp_path / "device").is_dir()
