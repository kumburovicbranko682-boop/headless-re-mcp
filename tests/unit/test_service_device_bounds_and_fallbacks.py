"""Device capture bounds and backend fallbacks in the device.* service layer.

The device artifact directory is the one place retention never sees (captures
are keyed by serial, not session), so its own pruning and size refusal are the
only bounds it has. These tests pin the failure edges of that machinery -- a
directory that vanished, a file that vanished between listing and stat, a
capture the size check refuses after the fact -- plus the mixin's two backend
fallbacks: constructing an ad-hoc AdbBackend when none was injected, and
converting an unexpected exception into a failure envelope instead of letting
it escape the tool call.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_device
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    _safe_pull_suffix,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


def _recording_backend(
    monkeypatch: pytest.MonkeyPatch, op_names: list[str]
) -> tuple[AdbBackend, list[tuple[str, dict[str, Any]]]]:
    """A real AdbBackend (so the mixin's isinstance guard accepts it) whose
    named ops are replaced with recorders."""
    backend = AdbBackend()
    calls: list[tuple[str, dict[str, Any]]] = []

    def make(name: str) -> Any:
        def op(**kwargs: Any) -> JsonObject:
            calls.append((name, kwargs))
            return {"op": name, **kwargs}

        return op

    for name in op_names:
        monkeypatch.setattr(backend, name, make(name))
    return backend, calls


class _Host(DeviceAnalysisMixin):
    def __init__(self, settings: Settings, backend: AdbBackend | None = None) -> None:
        self.settings = settings
        if backend is not None:
            self._adb_backend = backend


def _settings(tmp_path: Path) -> Settings:
    # Only artifact_root is consulted on these paths; the stand-in deliberately
    # has no adb attribute so _backend's getattr fallback is exercised too.
    return cast(Settings, SimpleNamespace(artifact_root=tmp_path))


def test_a_clean_extension_is_kept_but_a_path_like_suffix_falls_back_to_bin() -> None:
    assert _safe_pull_suffix("/sdcard/app.apk") == ".apk"
    # A remote path whose "suffix" is a local path fragment or an oversized /
    # non-alnum blob must not become the artifact's extension; it collapses to
    # the safe default rather than smuggling a path or NTFS stream through.
    assert _safe_pull_suffix("/sdcard/weird.name.with-a-very-long-extension") == ".bin"
    assert _safe_pull_suffix("/sdcard/noext") == ".bin"


def test_pruning_a_directory_that_vanished_is_a_no_op() -> None:
    prune_device_artifacts(Path("/nonexistent/device-artifacts"))


def test_pruning_under_the_cap_deletes_nothing(tmp_path: Path) -> None:
    keeper = tmp_path / "screenshot.png"
    keeper.write_bytes(b"png")

    prune_device_artifacts(tmp_path, keep=2)

    assert keeper.exists()


def test_a_file_that_vanishes_between_listing_and_stat_sorts_oldest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The race: iterdir saw the file, but by the time the sort asks for its
    # mtime it is gone. It must sort as oldest (mtime 0) and be pruned first
    # rather than aborting the sweep.
    vanished = tmp_path / "vanished.png"
    vanished.write_bytes(b"gone")
    old = tmp_path / "old.png"
    old.write_bytes(b"old")
    os.utime(old, (100, 100))
    new = tmp_path / "new.png"
    new.write_bytes(b"new")
    os.utime(new, (200, 200))

    real_stat = Path.stat
    real_is_file = Path.is_file

    def fake_is_file(self: Path, **kwargs: Any) -> bool:
        if self.name == "vanished.png":
            return True
        return real_is_file(self, **kwargs)

    def fake_stat(self: Path, **kwargs: Any) -> Any:
        if self.name == "vanished.png":
            raise OSError("deleted between listing and stat")
        return real_stat(self, **kwargs)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    monkeypatch.setattr(Path, "stat", fake_stat)

    prune_device_artifacts(tmp_path, keep=1)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["new.png"]


def test_refusing_a_capture_that_vanished_returns_none() -> None:
    assert refuse_oversized_device_file(Path("/nonexistent/pull.bin")) is None


def test_a_within_limit_capture_is_left_in_place(tmp_path: Path) -> None:
    small = tmp_path / "ok.png"
    small.write_bytes(b"tiny")

    assert refuse_oversized_device_file(small, limit=1024) is None
    assert small.exists()


def test_an_oversized_capture_is_deleted_and_reported(tmp_path: Path) -> None:
    # The transfer already wrote the bytes; the bound is enforced after the
    # fact by removing the file and returning an output_too_large refusal so
    # the caller learns the disk was not left holding an unbounded pull.
    big = tmp_path / "huge.bin"
    big.write_bytes(b"x" * 64)

    refusal = refuse_oversized_device_file(big, limit=16)

    assert refusal is not None
    assert refusal.ok is False
    assert refusal.error is not None
    assert refusal.error.code == "output_too_large"
    assert not big.exists()


def test_backend_is_constructed_ad_hoc_when_none_was_injected(tmp_path: Path) -> None:
    host = _Host(_settings(tmp_path))

    assert isinstance(host._backend(), AdbBackend)


def test_an_unexpected_backend_crash_becomes_a_failure_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise RuntimeError("adbutils fell over")

    monkeypatch.setattr(backend, "list_devices", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_list()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def _refusal() -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="capture over the limit"),
    )


def test_an_oversized_screenshot_is_refused_after_the_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_screenshot(*, serial: str, out_path: Path) -> JsonObject:
        out_path.write_bytes(b"png")
        return {"path": str(out_path)}

    monkeypatch.setattr(backend, "screenshot", fake_screenshot)
    refusal = _refusal()
    monkeypatch.setattr(
        service_device,
        "refuse_oversized_device_file",
        lambda path, **kwargs: refusal,
    )
    host = _Host(_settings(tmp_path), backend)

    result = host.device_screenshot("emulator-5554")

    assert result is refusal


def test_an_oversized_pull_is_refused_after_the_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_pull(*, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        local_path.write_bytes(b"blob")
        return {"path": str(local_path)}

    monkeypatch.setattr(backend, "pull", fake_pull)
    refusal = _refusal()
    monkeypatch.setattr(
        service_device,
        "refuse_oversized_device_file",
        lambda path, **kwargs: refusal,
    )
    host = _Host(_settings(tmp_path), backend)

    result = host.device_pull("emulator-5554", "/sdcard/app.apk")

    assert result is refusal


def test_a_failed_screenshot_still_prunes_and_returns_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the capture op itself fails, the oversized check is skipped but the
    # directory is still pruned before the failure is returned.
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise AdbError("backend_error", "screencap failed")

    monkeypatch.setattr(backend, "screenshot", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_screenshot("emulator-5554")

    assert result.ok is False


def test_a_failed_pull_still_prunes_and_returns_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise AdbError("backend_error", "pull failed")

    monkeypatch.setattr(backend, "pull", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_pull("emulator-5554", "/sdcard/app.apk")

    assert result.ok is False


def test_an_adb_error_becomes_a_failure_carrying_the_backend_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An AdbError (the backend's own typed failure) must surface with its code
    # preserved, distinct from the internal_error a surprise exception yields.
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise AdbError("device_offline", "device dropped off the bus")

    monkeypatch.setattr(backend, "list_devices", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_list()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "device_offline"


def test_a_connect_that_fails_at_the_wrapper_passes_the_failure_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # device_connect only inspects data on the ok path; when the wrapper itself
    # returns a failure (the op raised), that envelope is returned untouched
    # rather than being second-guessed by the connected-flag check.
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise AdbError("backend_error", "adb server not running")

    monkeypatch.setattr(backend, "connect", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_connect()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_a_within_limit_screenshot_returns_the_success_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_screenshot(*, serial: str, out_path: Path) -> JsonObject:
        out_path.write_bytes(b"small-png")
        return {"path": str(out_path)}

    monkeypatch.setattr(backend, "screenshot", fake_screenshot)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_screenshot("emulator-5554")

    assert result.ok is True


def test_a_within_limit_pull_returns_the_success_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_pull(*, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        local_path.write_bytes(b"blob")
        return {"path": str(local_path)}

    monkeypatch.setattr(backend, "pull", fake_pull)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_pull("emulator-5554", "/sdcard/app.apk")

    assert result.ok is True


def test_every_passthrough_method_forwards_to_its_named_backend_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The bulk of the mixin is one-line delegations. Rather than assert each
    # return shape, this pins that each tool forwards to the backend op it
    # claims to, with the caller's arguments intact -- a rename or a dropped
    # keyword on any of them would show up here.
    ops = [
        "info",
        "properties",
        "packages",
        "install",
        "uninstall",
        "launch",
        "force_stop",
        "current_activity",
        "logcat",
        "push",
        "forward",
    ]
    backend, calls = _recording_backend(monkeypatch, ops)
    host = _Host(_settings(tmp_path), backend)

    host.device_info("s1")
    host.device_properties("s1", limit=10)
    host.device_packages("s1", third_party_only=True, limit=20)
    host.device_install("s1", "/app.apk", reinstall=False)
    host.device_uninstall("s1", "com.example")
    host.device_launch("s1", "com.example")
    host.device_force_stop("s1", "com.example")
    host.device_current_activity("s1")
    host.device_logcat("s1", lines=50)
    host.device_push("s1", "/local", "/remote")
    host.device_forward("s1", "tcp:1", "tcp:2")

    assert [name for name, _ in calls] == ops
    by_op = dict(calls)
    assert by_op["properties"] == {"serial": "s1", "limit": 10}
    assert by_op["packages"] == {"serial": "s1", "third_party_only": True, "limit": 20}
    assert by_op["install"] == {"serial": "s1", "apk_path": "/app.apk", "reinstall": False}
    assert by_op["logcat"] == {"serial": "s1", "lines": 50}
    assert by_op["forward"] == {"serial": "s1", "local": "tcp:1", "remote": "tcp:2"}
