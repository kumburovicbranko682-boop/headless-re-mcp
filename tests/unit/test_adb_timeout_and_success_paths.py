"""ADB timeout contracts, capability detection, and the paths the error suite skips.

``test_adb_client_paths`` pins the ``backend_error`` mapping of each operation;
this covers the symmetric ``timeout`` branch (a stalled device answers timeout,
not backend_error, so an agent knows to retry rather than give up), the
adbutils-missing capability guard, the screenshot success path and the pull/push
size ceilings, plus the framework-id skip in package extraction and the forward
reservation surviving a failed re-forward of a key this process already holds.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _apk_package_name,
    _pids_for_package,
    _pm_path,
)

_TIMEOUT = "adb timed out after 8s"


class _ShellDev:
    def __init__(self, handler: Any) -> None:
        self._handler = handler

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        cmd = " ".join(args) if isinstance(args, list) else str(args)
        return self._handler(cmd)


def _backend_with(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.x"/>')
    return path


# ---------------------------------------------------------------------------
# module helpers: the remaining parse edges
# ---------------------------------------------------------------------------
def test_apk_package_name_skips_framework_ids(tmp_path: Path) -> None:
    # Bytes that fail utf-8 (0xff) and decode in utf-16-le to a marker followed
    # by a framework id (skipped) and then the real application id.
    def u16(text: str) -> bytes:
        return text.encode("utf-16-le")

    payload = (
        b"\xff\xfe"
        + u16("package")
        + b"\x20\x00"
        + u16("android.app")
        + b"\x20\x00"
        + u16("com.example.real")
    )
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", payload)
    assert _apk_package_name(apk) == "com.example.real"


def test_pm_path_ignores_a_non_package_line() -> None:
    dev = _ShellDev(lambda cmd: "some unrelated line\nanother\n")
    assert _pm_path(dev, "com.x") is None


def test_pids_for_package_ps_line_without_a_pid_contributes_nothing() -> None:
    def not_found_then_ps(cmd: str) -> str:
        if cmd.startswith("pidof"):
            return "not found"
        # Matches the package but the first three columns hold no pid.
        return "u0_a1 user com.x running\n"

    assert _pids_for_package(_ShellDev(not_found_then_ps), "com.x") == []


def test_pids_for_package_caps_the_ps_scan_at_sixteen() -> None:
    def not_found_then_ps(cmd: str) -> str:
        if cmd.startswith("pidof"):
            return "not found"
        return "".join(f"u0 {1000 + i} 1 com.x\n" for i in range(20))

    pids = _pids_for_package(_ShellDev(not_found_then_ps), "com.x")
    assert pids is not None and len(pids) == 16


def test_backend_degrades_when_adbutils_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    assert backend.available is False
    assert backend._adbutils is None


# ---------------------------------------------------------------------------
# _client / list_devices AdbError passthrough
# ---------------------------------------------------------------------------
def test_client_passes_through_a_structured_adb_error() -> None:
    backend = AdbBackend()
    backend._available = True

    def raises_adb(host: str, port: int, socket_timeout: float | None = None) -> None:
        raise AdbError("capability_unavailable", "already structured")

    backend._adbutils = type("m", (), {"AdbClient": staticmethod(raises_adb)})()
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_list_devices_times_out_and_passes_through_adb_error() -> None:
    backend = AdbBackend()
    backend._available = True

    class _TimeoutClient:
        def list(self) -> list[Any]:
            raise RuntimeError(_TIMEOUT)

    backend._client = lambda **kw: _TimeoutClient()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as timed:
        backend.list_devices()
    assert timed.value.code == "timeout"

    class _AdbErrClient:
        def list(self) -> list[Any]:
            raise AdbError("invalid_state", "server restarting")

    backend._client = lambda **kw: _AdbErrClient()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as passed:
        backend.list_devices()
    assert passed.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# per-operation timeout branch (a stalled device is timeout, not backend_error)
# ---------------------------------------------------------------------------
def test_install_times_out(tmp_path: Path) -> None:
    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kw: Any) -> None:
            raise RuntimeError(_TIMEOUT)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).install("emulator-5554", str(_real_apk(tmp_path / "a.apk")))
    assert caught.value.code == "timeout"


def test_uninstall_times_out() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError(_TIMEOUT)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.x")
    assert caught.value.code == "timeout"


def test_current_activity_times_out() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError(_TIMEOUT)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "timeout"


def test_screenshot_times_out(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            raise RuntimeError(_TIMEOUT)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).screenshot("emulator-5554", tmp_path / "s.png")
    assert caught.value.code == "timeout"


def test_pull_times_out(tmp_path: Path) -> None:
    class _Sync:
        def stat(self, remote: str, timeout: float | None = None) -> Any:
            raise RuntimeError("stat unsupported")

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            raise RuntimeError(_TIMEOUT)

    class _Dev:
        sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).pull("emulator-5554", "/sdcard/x", tmp_path / "o.bin")
    assert caught.value.code == "timeout"


def test_push_times_out(tmp_path: Path) -> None:
    local = tmp_path / "f.bin"
    local.write_bytes(b"hi")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError(_TIMEOUT)

    class _Dev:
        sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).push("emulator-5554", str(local), "/sdcard/x")
    assert caught.value.code == "timeout"


def test_ensure_frida_server_push_times_out(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError(_TIMEOUT)

    class _Dev:
        sync = _Sync()

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""  # frida-server not visible in ps

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "timeout"


# ---------------------------------------------------------------------------
# screenshot success + pull/push size ceilings
# ---------------------------------------------------------------------------
def test_screenshot_success_reports_size(tmp_path: Path) -> None:
    out = tmp_path / "shot.png"

    class _Image:
        def save(self, dest: str) -> None:
            Path(dest).write_bytes(b"\x89PNG\r\n\x1a\n" + b"pixels")

    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            return _Image()

    payload = _backend_with(_Dev()).screenshot("emulator-5554", out)
    assert payload["size"] == out.stat().st_size
    assert out.is_file()


def test_pull_refuses_a_file_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)

    def write_big(remote: str, local: str) -> None:
        Path(local).write_bytes(b"way too big")

    class _Sync:
        def stat(self, remote: str, timeout: float | None = None) -> Any:
            raise RuntimeError("stat unsupported")  # skip the pre-stat cap check

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            write_big(remote, local)

    class _Dev:
        sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).pull("emulator-5554", "/sdcard/x", tmp_path / "o.bin")
    assert caught.value.code == "too_large"


def test_push_maps_a_local_stat_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = tmp_path / "f.bin"
    local.write_bytes(b"hi")
    real_stat = Path.stat

    def guarded_stat(self: Path, *a: Any, **k: Any) -> Any:
        if self == local:
            raise OSError("stat blew up")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "stat", guarded_stat)
    backend = AdbBackend()
    backend._available = True
    with pytest.raises(AdbError) as caught:
        backend.push("emulator-5554", str(local), "/sdcard/x")
    assert caught.value.code == "backend_error"
    assert "cannot stat" in caught.value.message


# ---------------------------------------------------------------------------
# forward: a failed re-forward of a held key keeps the reservation
# ---------------------------------------------------------------------------
def test_forward_keeps_a_held_reservation_when_the_reforward_errors() -> None:
    key = ("emulator-5554", "tcp:8080")

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", _TIMEOUT)

    backend = _backend_with(_Dev())
    backend._forwards.append(key)  # this process already holds the slot
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:8080", "tcp:8080")
    assert caught.value.code == "timeout"
    # The pre-existing reservation must survive a failed re-forward.
    assert key in backend._forwards


def test_forward_keeps_a_held_reservation_on_a_backend_error() -> None:
    key = ("emulator-5554", "tcp:9090")

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("cannot bind")

    backend = _backend_with(_Dev())
    backend._forwards.append(key)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9090", "tcp:9090")
    assert caught.value.code == "backend_error"
    assert key in backend._forwards
