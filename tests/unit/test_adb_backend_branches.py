"""ADB backend guard, degradation, and honesty branches.

The live paths (talk to a real emulator/device) live in
``tests/integration/test_android_re_gate.py`` and only run where adb + a device
are present. Everything here drives the backend through a fake device/client so
the decisions that must hold on every machine run on every machine: the strict
argument checks, the host-error-as-stdout detection, "could not verify" honesty
on install/uninstall/launch/force-stop, the pull/push caps, and the bounded
forward table with its reservation-release-on-failure.
"""

from __future__ import annotations

import ast
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _accepted_kwargs,
    _accepts_timeout,
    _apk_package_name,
    _bind_open_transport,
    _call,
    _check_forward_spec,
    _device_info_row,
    _device_shell,
    _file_mode_size,
    _is_host_error_output,
)

MP = pytest.MonkeyPatch


class _TimeoutError(Exception):
    def __init__(self) -> None:
        super().__init__("operation timed out")


class _Image:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def save(self, path: str) -> None:
        Path(path).write_bytes(self._payload)


class _Sync:
    def __init__(
        self,
        *,
        stat_result: Any = None,
        stat_error: BaseException | None = None,
        pull_error: BaseException | None = None,
        pull_writes: bytes | None = b"data",
        pull_dir: bool = False,
        push_error: BaseException | None = None,
    ) -> None:
        self._stat_result = stat_result
        self._stat_error = stat_error
        self._pull_error = pull_error
        self._pull_writes = pull_writes
        self._pull_dir = pull_dir
        self._push_error = push_error

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        if self._stat_error is not None:
            raise self._stat_error
        return self._stat_result

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        if self._pull_error is not None:
            raise self._pull_error
        if self._pull_dir:
            Path(local).mkdir(parents=True, exist_ok=True)
            return
        if self._pull_writes is not None:
            Path(local).write_bytes(self._pull_writes)

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        if self._push_error is not None:
            raise self._push_error


class _FakeDev:
    def __init__(
        self,
        *,
        shell_map: dict[str, str] | None = None,
        shell_default: str = "",
        shell_error: BaseException | None = None,
        state: str = "device",
        get_state_error: BaseException | None = None,
        app_current: Any = "__unset__",
        app_current_error: BaseException | None = None,
        install_error: BaseException | None = None,
        uninstall_error: BaseException | None = None,
        screenshot_error: BaseException | None = None,
        screenshot_payload: bytes = b"\x89PNG" + b"0" * 64,
        forward_error: BaseException | None = None,
        sync: _Sync | None = None,
        has_open_transport: bool = True,
    ) -> None:
        self._shell_map = shell_map or {}
        self._shell_default = shell_default
        self._shell_error = shell_error
        self._state = state
        self._get_state_error = get_state_error
        self._app_current = app_current
        self._app_current_error = app_current_error
        self._install_error = install_error
        self._uninstall_error = uninstall_error
        self._screenshot_error = screenshot_error
        self._screenshot_payload = screenshot_payload
        self._forward_error = forward_error
        self.sync = sync if sync is not None else _Sync()
        self.shell_calls: list[str] = []
        self.forwarded: list[tuple[str, str]] = []
        self.removed_forwards: list[str] = []
        if not has_open_transport:
            del self.open_transport

    def _key(self, args: str | list[str]) -> str:
        return args if isinstance(args, str) else " ".join(args)

    def shell(self, args: str | list[str], timeout: float | None = None) -> str:
        key = self._key(args)
        self.shell_calls.append(key)
        if self._shell_error is not None:
            raise self._shell_error
        return self._shell_map.get(key, self._shell_default)

    def get_state(self, timeout: float | None = None) -> str:
        if self._get_state_error is not None:
            raise self._get_state_error
        return self._state

    def app_current(self, timeout: float | None = None) -> Any:
        if self._app_current_error is not None:
            raise self._app_current_error
        if self._app_current == "__unset__":
            return SimpleNamespace(package="com.example.app", activity=".Main")
        return self._app_current

    def install(self, path: str, **kwargs: Any) -> None:
        if self._install_error is not None:
            raise self._install_error

    def uninstall(self, package: str, timeout: float | None = None) -> None:
        if self._uninstall_error is not None:
            raise self._uninstall_error

    def screenshot(self, timeout: float | None = None) -> _Image:
        if self._screenshot_error is not None:
            raise self._screenshot_error
        return _Image(self._screenshot_payload)

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        if self._forward_error is not None:
            raise self._forward_error
        self.forwarded.append((local, remote))

    def forward_remove(self, local: str, timeout: float | None = None) -> None:
        self.removed_forwards.append(local)

    def open_transport(self, command: Any = None, timeout: float | None = None) -> Any:
        return None


def _backend_with_dev(dev: _FakeDev, monkeypatch: MP) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = object()
    monkeypatch.setattr(backend, "_device", lambda serial: dev)
    return backend


def _device_tool_docstring(name: str) -> str:
    """The docstring the device.* tool named ``name`` advertises to an agent."""
    from headless_re_mcp.tools.device import build_device_tools

    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


# ----------------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------------
class TestHelpers:
    def test_accepts_timeout_named_varkw_and_uninspectable(self) -> None:
        assert _accepts_timeout(lambda a, timeout=1: a) is True
        assert _accepts_timeout(lambda a, **kw: a) is True
        assert _accepts_timeout(lambda a: a) is False
        assert _accepts_timeout(range) is False  # ValueError from signature()

    def test_accepted_kwargs_filters_to_the_signature(self) -> None:
        def named(a: int, flags: list[int] | None = None) -> int:
            return a

        def varkw(a: int, **kw: Any) -> int:
            return a

        assert _accepted_kwargs(named, {"flags": [1], "nolaunch": True}) == {"flags": [1]}
        assert _accepted_kwargs(varkw, {"flags": [1], "nolaunch": True}) == {
            "flags": [1],
            "nolaunch": True,
        }
        assert _accepted_kwargs(range, {"flags": [1]}) == {}

    def test_device_info_row_object_and_tuple(self) -> None:
        obj = _device_info_row(SimpleNamespace(serial="emulator-5554", state="device"))
        assert obj == {"serial": "emulator-5554", "state": "device"}
        pair = _device_info_row(("emulator-5556", "offline"))
        assert pair == {"serial": "emulator-5556", "state": "offline"}
        one = _device_info_row(("emulator-5558",))
        assert one == {"serial": "emulator-5558", "state": "unknown"}

    def test_file_mode_size_object_and_tuple(self) -> None:
        assert _file_mode_size(SimpleNamespace(mode=0o100644, size=10)) == (0o100644, 10)
        assert _file_mode_size((0o40755, 4096)) == (0o40755, 4096)

    def test_host_error_detection(self) -> None:
        assert _is_host_error_output("error: device offline") is True
        assert _is_host_error_output("adb: no devices/emulators found") is True
        assert _is_host_error_output("package:com.example.app") is False
        assert _is_host_error_output("") is False
        # A real line that merely mentions error is not a host error.
        assert _is_host_error_output("W System: recovered from error: boom") is False

    def test_forward_spec_rejects_bad_ports_and_shapes(self) -> None:
        _check_forward_spec("tcp:8080", side="local")
        _check_forward_spec("localabstract:frida-server", side="remote")
        _check_forward_spec("jdwp:1234", side="remote", allow_jdwp=True)
        for bad in ("tcp:0", "tcp:70000", "jdwp:1", "weird:1"):
            with pytest.raises(AdbError) as info:
                _check_forward_spec(bad, side="local")
            assert info.value.code == "invalid_params"


class TestApkPackageName:
    def _zip(self, path: Path, manifest: bytes) -> Path:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
        return path

    def test_non_zip_returns_none(self, tmp_path: Path) -> None:
        bad = tmp_path / "not.apk"
        bad.write_bytes(b"not a zip")
        assert _apk_package_name(bad) is None

    def test_plaintext_manifest_package_attribute(self, tmp_path: Path) -> None:
        apk = self._zip(tmp_path / "a.apk", b'<manifest package="com.example.app">')
        assert _apk_package_name(apk) == "com.example.app"

    def test_binary_manifest_scanned_for_candidate(self, tmp_path: Path) -> None:
        # Invalid utf-8 lead byte forces the utf-8 decode to raise (the except
        # branch), then the utf-16-le scan recovers the package near the marker.
        payload = b"\xff\xfe" + "xpackagex com.example.app".encode("utf-16-le")
        apk = self._zip(tmp_path / "b.apk", payload)
        assert _apk_package_name(apk) == "com.example.app"

    def test_only_framework_packages_returns_none(self, tmp_path: Path) -> None:
        payload = "package android.support.v4".encode("utf-16-le")
        apk = self._zip(tmp_path / "c.apk", payload)
        assert _apk_package_name(apk) is None


# ----------------------------------------------------------------------------
# _client / _device / list_devices / connect
# ----------------------------------------------------------------------------
class _FakeClientList:
    def __init__(self, *, infos: list[Any], error: BaseException | None = None) -> None:
        self._infos = infos
        self._error = error

    def list(self) -> list[Any]:
        if self._error is not None:
            raise self._error
        return self._infos


class _FakeClientNoList:
    def __init__(self, serials: list[str]) -> None:
        self._serials = serials

    def device_list(self) -> list[Any]:
        return [SimpleNamespace(serial=s) for s in self._serials]


class _FakeConnectClient:
    def __init__(
        self, *, message: str = "connected to x", error: BaseException | None = None
    ) -> None:
        self._message = message
        self._error = error

    def connect(self, endpoint: str, timeout: float | None = None) -> str:
        if self._error is not None:
            raise self._error
        return self._message


class TestClientAndDevice:
    def test_missing_adbutils_degrades(self) -> None:
        backend = AdbBackend()
        backend._available = False
        backend._adbutils = None
        with pytest.raises(AdbError) as info:
            backend._client()
        assert info.value.code == "capability_unavailable"

    def test_import_failure_degrades_not_crashes(self, monkeypatch: MP) -> None:
        monkeypatch.setitem(sys.modules, "adbutils", None)
        backend = AdbBackend()
        assert backend.available is False

    def test_client_wraps_socket_timeout(self, monkeypatch: MP) -> None:
        class _Adbutils:
            def AdbClient(self, **kwargs: Any) -> Any:
                raise _TimeoutError()

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = _Adbutils()
        with pytest.raises(AdbError) as info:
            backend._client()
        assert info.value.code == "timeout"

    def test_client_wraps_unreachable_server(self) -> None:
        class _Adbutils:
            def AdbClient(self, **kwargs: Any) -> Any:
                raise RuntimeError("connection refused")

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = _Adbutils()
        with pytest.raises(AdbError) as info:
            backend._client()
        assert info.value.code == "backend_error"

    def test_client_falls_back_when_socket_timeout_kwarg_unsupported(self) -> None:
        seen: dict[str, Any] = {}

        class _Client:
            pass

        class _Adbutils:
            def AdbClient(self, host: str = "", port: int = 0, **kwargs: Any) -> Any:
                if "socket_timeout" in kwargs:
                    raise TypeError("unexpected socket_timeout")
                seen["fallback"] = True
                return _Client()

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = _Adbutils()
        assert isinstance(backend._client(), _Client)
        assert seen["fallback"] is True

    def test_device_not_found_is_reported(self, monkeypatch: MP) -> None:
        class _Client:
            def device(self, serial: str | None = None) -> Any:
                raise RuntimeError("device not found")

        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _Client())
        with pytest.raises(AdbError) as info:
            backend._device("emulator-5554")
        assert info.value.code == "not_found"

    def test_list_devices_via_list_api(self, monkeypatch: MP) -> None:
        infos = [SimpleNamespace(serial="emulator-5554", state="device")]
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _FakeClientList(infos=infos))
        result = backend.list_devices()
        assert result["count"] == 1
        assert result["devices"][0]["serial"] == "emulator-5554"

    def test_list_devices_via_device_list_fallback(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _FakeClientNoList(["a", "b"]))
        result = backend.list_devices()
        assert [d["serial"] for d in result["devices"]] == ["a", "b"]
        assert result["devices"][0]["state"] == "device"

    def test_list_devices_wraps_errors(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(
            backend, "_client", lambda **kw: _FakeClientList(infos=[], error=RuntimeError("boom"))
        )
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "backend_error"

    def test_connect_rejects_bad_port(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _FakeConnectClient())
        with pytest.raises(AdbError) as info:
            backend.connect(port=99999)
        assert info.value.code == "invalid_params"

    def test_connect_reports_result(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        client = _FakeConnectClient(message="connected to 127.0.0.1:5555")
        monkeypatch.setattr(backend, "_client", lambda **kw: client)
        result = backend.connect(port=5555)
        assert result["connected"] is True
        assert result["endpoint"] == "127.0.0.1:5555"

    def test_connect_wraps_failure(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(
            backend, "_client", lambda **kw: _FakeConnectClient(error=RuntimeError("refused"))
        )
        with pytest.raises(AdbError) as info:
            backend.connect(port=5555)
        assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# Read/state operations with an injected device
# ----------------------------------------------------------------------------
class TestReadOperations:
    def test_info_collects_getprop_values(self, monkeypatch: MP) -> None:
        dev = _FakeDev(
            shell_map={
                "getprop ro.product.model": "Pixel",
                "getprop ro.product.device": "sailfish",
                "getprop ro.build.version.sdk": "34",
                "getprop ro.build.version.release": "14",
                "getprop ro.product.cpu.abi": "arm64-v8a",
            }
        )
        backend = _backend_with_dev(dev, monkeypatch)
        info = backend.info("emulator-5554")
        assert info["model"] == "Pixel"
        assert info["sdk"] == "34"

    def test_info_wraps_backend_failures(self, monkeypatch: MP) -> None:
        dev = _FakeDev(get_state_error=RuntimeError("offline"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.info("emulator-5554")
        assert info.value.code == "backend_error"

    def test_properties_caps_and_flags_more(self, monkeypatch: MP) -> None:
        lines = "\n".join(f"[ro.k{i}]: [{i}]" for i in range(3))
        dev = _FakeDev(shell_map={"getprop": lines})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.properties("emulator-5554", limit=2)
        assert result["count"] == 2
        assert result["has_more"] is True

    def test_properties_detects_host_error(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"getprop": "error: device offline"})
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.properties("emulator-5554")
        assert info.value.code == "backend_error"

    def test_packages_third_party_and_cap(self, monkeypatch: MP) -> None:
        lines = "package:com.b\npackage:com.a\npackage:\npackage:com.c"
        dev = _FakeDev(shell_map={"pm list packages -3": lines})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.packages("emulator-5554", third_party_only=True, limit=2)
        assert result["packages"] == ["com.a", "com.b"]
        assert result["has_more"] is True
        assert result["third_party_only"] is True

    def test_current_activity_reports_foreground(self, monkeypatch: MP) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.current_activity("emulator-5554")
        assert result["package"] == "com.example.app"

    def test_current_activity_none_is_a_failure(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current=None)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.current_activity("emulator-5554")
        assert info.value.code == "backend_error"

    def test_current_activity_wraps_read_error(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current_error=RuntimeError("dumpsys failed"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.current_activity("emulator-5554")
        assert info.value.code == "backend_error"

    def test_logcat_truncates_from_the_front(self, monkeypatch: MP) -> None:
        big = ("x" * 300_000) + "\nlast line"
        dev = _FakeDev(shell_map={"logcat -d -t 200": big})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.logcat("emulator-5554")
        assert result["truncated"] is True
        # The half-line prefix was dropped, not returned as a whole entry.
        assert "x" * 300_000 not in "\n".join(result["lines"])


# ----------------------------------------------------------------------------
# install / uninstall / launch / force_stop
# ----------------------------------------------------------------------------
def _apk_file(path: Path, package: str = "com.example.app") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f'<manifest package="{package}">'.encode())
    return path


class TestInstallLifecycle:
    def test_install_missing_file_is_not_found(self, monkeypatch: MP, tmp_path: Path) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.install("emulator-5554", str(tmp_path / "missing.apk"))
        assert info.value.code == "not_found"

    def test_install_non_zip_is_rejected(self, monkeypatch: MP, tmp_path: Path) -> None:
        junk = tmp_path / "app.apk"
        junk.write_bytes(b"not a zip")
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.install("emulator-5554", str(junk))
        assert info.value.code == "invalid_params"

    def test_install_verifies_presence_via_pm_path(self, monkeypatch: MP, tmp_path: Path) -> None:
        apk = _apk_file(tmp_path / "app.apk")
        dev = _FakeDev(shell_map={"pm path com.example.app": "package:/data/app/base.apk"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.install("emulator-5554", str(apk))
        assert result["installed"] is True
        assert result["package"] == "com.example.app"

    def test_install_reports_when_pm_path_cannot_verify(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        apk = _apk_file(tmp_path / "app.apk")
        dev = _FakeDev(shell_map={"pm path com.example.app": "error: device offline"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.install("emulator-5554", str(apk))
        assert result["installed"] is None
        assert "could not verify" in result["note"]

    def test_install_wraps_backend_failure(self, monkeypatch: MP, tmp_path: Path) -> None:
        apk = _apk_file(tmp_path / "app.apk")
        dev = _FakeDev(install_error=RuntimeError("INSTALL_FAILED"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.install("emulator-5554", str(apk))
        assert info.value.code == "backend_error"

    def test_install_reports_unreadable_package(self, monkeypatch: MP, tmp_path: Path) -> None:
        # A zip with no readable manifest package still installs, but the verify
        # cannot run, which must be said rather than claimed as installed.
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", b"dex")
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.install("emulator-5554", str(apk))
        assert result["installed"] is None
        assert "package name not readable" in result["note"]

    def test_uninstall_confirms_removal(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pm path com.example.app": ""})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is True

    def test_uninstall_reports_still_present(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pm path com.example.app": "package:/data/app/base.apk"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is False
        assert "still visible" in result["note"]

    def test_uninstall_reports_unverifiable(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pm path com.example.app": "error: device offline"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is None
        assert "could not verify" in result["note"]

    def test_uninstall_wraps_backend_failure(self, monkeypatch: MP) -> None:
        dev = _FakeDev(uninstall_error=RuntimeError("DELETE_FAILED"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"

    def test_launch_confirms_foreground(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current=SimpleNamespace(package="com.example.app", activity=".Main"))
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.launch("emulator-5554", "com.example.app")
        assert result["launched"] is True

    def test_launch_reports_when_foreground_unreadable(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current_error=RuntimeError("no window"))
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.launch("emulator-5554", "com.example.app")
        assert result["launched"] is None
        assert "could not read foreground" in result["note"]

    def test_launch_wraps_backend_failure(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_error=RuntimeError("monkey crashed"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.launch("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        # The failure names the operation and the package it acted on, rather
        # than _device_shell's generic "adb shell failed" with no package -- the
        # context the previously-unreachable branch meant to add.
        assert "launch failed" in info.value.message
        assert info.value.details["package"] == "com.example.app"

    def test_launch_failure_keeps_a_timeout_code(self, monkeypatch: MP) -> None:
        # _device_shell raises AdbError("timeout", ...) on a stall; the enrichment
        # must preserve that code (a timeout is retryable) rather than flatten it
        # to backend_error.
        dev = _FakeDev(shell_error=TimeoutError("stalled"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.launch("emulator-5554", "com.example.app")
        assert info.value.code == "timeout"
        assert info.value.details["package"] == "com.example.app"

    def test_force_stop_reads_remaining_pids(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pidof com.example.app": ""})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is True
        assert result["remaining_pids"] == []

    def test_force_stop_reports_survivors(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pidof com.example.app": "1201 1202"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is False
        assert result["remaining_pids"] == [1201, 1202]

    def test_force_stop_wraps_backend_failure(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_error=RuntimeError("am died"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.force_stop("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        assert "force-stop failed" in info.value.message
        assert info.value.details["package"] == "com.example.app"


class TestVerificationNoteDocstrings:
    """install/uninstall/launch/force_stop return a note explaining a null or

    negative outcome, but their docstrings named only the primary fields --
    the same "answer-shape map drops a field the backend sends" class as the
    web.har.export size gap. The backend behaviour is pinned in
    TestInstallLifecycle (result["note"] on every unverifiable branch); this
    pins that the tool docstring, the agent's one map of the reply, actually
    names note, and for the reachable branches that every returned key is named.
    """

    def _assert_every_key_named(self, payload: dict[str, Any], name: str) -> None:
        doc = _device_tool_docstring(name)
        for key in payload:
            assert key in doc, f"{name} returns {key!r} but the docstring never names it"

    def test_install_unverifiable_keys_are_all_named(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        apk = _apk_file(tmp_path / "app.apk")
        dev = _FakeDev(shell_map={"pm path com.example.app": "error: device offline"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.install("emulator-5554", str(apk))
        assert "note" in result
        self._assert_every_key_named(result, "device.install")

    def test_uninstall_unverifiable_keys_are_all_named(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pm path com.example.app": "error: device offline"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.uninstall("emulator-5554", "com.example.app")
        assert "note" in result
        self._assert_every_key_named(result, "device.uninstall")

    def test_launch_unreadable_keys_are_all_named(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current_error=RuntimeError("no window"))
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.launch("emulator-5554", "com.example.app")
        assert "note" in result
        self._assert_every_key_named(result, "device.launch")

    def test_force_stop_survivor_keys_are_all_named(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"pidof com.example.app": "1201 1202"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.force_stop("emulator-5554", "com.example.app")
        self._assert_every_key_named(result, "device.force_stop")

    def test_all_four_verification_docstrings_name_note(self) -> None:
        for name in (
            "device.install",
            "device.uninstall",
            "device.launch",
            "device.force_stop",
        ):
            assert "note" in _device_tool_docstring(name), name


# ----------------------------------------------------------------------------
# screenshot / pull / push
# ----------------------------------------------------------------------------
class TestTransfers:
    def test_screenshot_writes_and_sizes(self, monkeypatch: MP, tmp_path: Path) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert result["size"] > 0

    def test_screenshot_wraps_failure(self, monkeypatch: MP, tmp_path: Path) -> None:
        dev = _FakeDev(screenshot_error=RuntimeError("no display"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "backend_error"

    def test_screenshot_over_cap_is_refused(self, monkeypatch: MP, tmp_path: Path) -> None:
        monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "too_large"

    def test_pull_refuses_a_remote_directory(self, monkeypatch: MP, tmp_path: Path) -> None:
        sync = _Sync(stat_result=SimpleNamespace(mode=0o040755, size=0))
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/dir", tmp_path / "out")
        assert info.value.code == "invalid_params"

    def test_pull_refuses_oversized_remote(self, monkeypatch: MP, tmp_path: Path) -> None:
        monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        sync = _Sync(stat_result=SimpleNamespace(mode=0o100644, size=1024))
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/big.bin", tmp_path / "out.bin")
        assert info.value.code == "too_large"

    def test_pull_stat_failure_is_best_effort(self, monkeypatch: MP, tmp_path: Path) -> None:
        # A stat that raises must not abort the pull; the transfer still runs.
        sync = _Sync(stat_error=RuntimeError("stat unsupported"), pull_writes=b"payload")
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.pull("emulator-5554", "/sdcard/f.bin", tmp_path / "out.bin")
        assert result["size"] == len(b"payload")

    def test_pull_that_wrote_nothing_is_not_found(self, monkeypatch: MP, tmp_path: Path) -> None:
        sync = _Sync(stat_result=SimpleNamespace(mode=0o100644, size=4), pull_writes=None)
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/missing.bin", tmp_path / "out.bin")
        assert info.value.code == "not_found"

    def test_pull_directory_result_is_refused(self, monkeypatch: MP, tmp_path: Path) -> None:
        sync = _Sync(stat_error=RuntimeError("no stat"), pull_dir=True)
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/dir", tmp_path / "out")
        assert info.value.code == "invalid_params"

    def test_pull_wraps_transfer_failure(self, monkeypatch: MP, tmp_path: Path) -> None:
        sync = _Sync(stat_error=RuntimeError("no stat"), pull_error=RuntimeError("broken pipe"))
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/f.bin", tmp_path / "out.bin")
        assert info.value.code == "backend_error"

    def test_push_missing_local_is_not_found(self, monkeypatch: MP, tmp_path: Path) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(tmp_path / "missing"), "/sdcard/x")
        assert info.value.code == "not_found"

    def test_push_over_cap_is_refused(self, monkeypatch: MP, tmp_path: Path) -> None:
        monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        local = tmp_path / "big.bin"
        local.write_bytes(b"12345678")
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(local), "/sdcard/x")
        assert info.value.code == "too_large"

    def test_push_reports_size_on_success(self, monkeypatch: MP, tmp_path: Path) -> None:
        local = tmp_path / "f.bin"
        local.write_bytes(b"payload")
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.push("emulator-5554", str(local), "/sdcard/f.bin")
        assert result["size"] == len(b"payload")

    def test_push_wraps_transfer_failure(self, monkeypatch: MP, tmp_path: Path) -> None:
        local = tmp_path / "f.bin"
        local.write_bytes(b"payload")
        dev = _FakeDev(sync=_Sync(push_error=RuntimeError("no space")))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(local), "/sdcard/f.bin")
        assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# forward / release_forwards / ensure_frida_server
# ----------------------------------------------------------------------------
class TestForwardAndFrida:
    def test_forward_records_and_release_removes(self, monkeypatch: MP) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert dev.forwarded == [("tcp:27042", "tcp:27042")]
        released = backend.release_forwards()
        assert released["count"] == 1
        assert dev.removed_forwards == ["tcp:27042"]

    def test_forward_failure_releases_reservation(self, monkeypatch: MP) -> None:
        dev = _FakeDev(forward_error=RuntimeError("bind failed"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "backend_error"
        # The slot was freed, so the table is empty and a retry can reserve again.
        assert backend._forwards == []

    def test_forward_cap_is_enforced(self, monkeypatch: MP) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        backend._forwards = [("s", f"tcp:{9000 + i}") for i in range(adb_client._MAX_FORWARDS)]
        with pytest.raises(AdbError) as info:
            backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "invalid_state"

    def test_release_forwards_reschedules_a_failed_removal(self, monkeypatch: MP) -> None:
        # A device with no forward-remove API is remembered, not dropped: adb
        # still holds the forward and the next release is the retry.
        class _NoRemoveDev:
            pass

        backend = AdbBackend()
        backend._available = True
        backend._forwards = [("emulator-5554", "tcp:27042")]
        monkeypatch.setattr(backend, "_device", lambda serial: _NoRemoveDev())
        result = backend.release_forwards()
        assert result["count"] == 0
        assert result["failed"]
        assert backend._forwards == [("emulator-5554", "tcp:27042")]

    def test_ensure_frida_rejects_bad_remote_path(self, monkeypatch: MP) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", remote_path="bad path;rm")
        assert info.value.code == "invalid_params"

    def test_ensure_frida_rejects_bad_bind_host(self, monkeypatch: MP) -> None:
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", bind_host="1.2.3.4:5")
        assert info.value.code == "invalid_params"

    def test_ensure_frida_noop_when_already_running(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"ps -A": "root 1 frida-server"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is True
        assert result["pushed"] is False

    def test_ensure_frida_missing_binary_is_not_found(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        dev = _FakeDev(shell_map={"ps -A": "", "ps": ""})
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server(
                "emulator-5554", server_binary=str(tmp_path / "missing")
            )
        assert info.value.code == "not_found"

    def test_ensure_frida_launches_and_reports_not_visible(self, monkeypatch: MP) -> None:
        # ps never shows frida-server, so the honest reply is running=False with
        # a note, not a claimed success.
        dev = _FakeDev(shell_map={"ps -A": "", "ps": ""})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is False
        assert "not visible" in result["note"]

    def test_ensure_frida_pushes_binary_then_launches(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        binary = tmp_path / "frida-server"
        binary.write_bytes(b"\x7fELF")
        dev = _FakeDev(shell_map={"ps -A": "", "ps": ""})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.ensure_frida_server("emulator-5554", server_binary=str(binary))
        assert result["pushed"] is True

    def test_ensure_frida_launch_timeout_is_treated_as_maybe_running(
        self, monkeypatch: MP
    ) -> None:
        # A timeout on the detached su launch often means it started; the reply
        # says "verify manually" rather than raising.
        dev = _FakeDev(shell_map={"ps -A": "", "ps": ""}, shell_error=None)

        calls = {"n": 0}
        original_shell = dev.shell

        def flaky_shell(args: str | list[str], timeout: float | None = None) -> str:
            key = args if isinstance(args, str) else " ".join(args)
            if key.startswith("su -c"):
                calls["n"] += 1
                raise _TimeoutError()
            return original_shell(args, timeout=timeout)

        monkeypatch.setattr(dev, "shell", flaky_shell)
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.ensure_frida_server("emulator-5554")
        assert "verify manually" in result["note"]
        assert calls["n"] == 1


# ----------------------------------------------------------------------------
# Timeout / error propagation in the low-level helpers
# ----------------------------------------------------------------------------
class TestHelperErrorPaths:
    def test_device_shell_reraises_adb_error(self) -> None:
        class _Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                raise AdbError("invalid_state", "already wrapped")

        with pytest.raises(AdbError) as info:
            _device_shell(_Dev(), "getprop")
        assert info.value.code == "invalid_state"

    def test_device_shell_labels_timeout(self) -> None:
        class _Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                raise _TimeoutError()

        with pytest.raises(AdbError) as info:
            _device_shell(_Dev(), "getprop")
        assert info.value.code == "timeout"

    def test_device_shell_wraps_any_other_error_as_backend_error(self) -> None:
        # The third leg of _device_shell's contract: a non-AdbError, non-timeout
        # failure becomes backend_error. This is *why* properties/packages/logcat
        # can call _device_shell without their own except-Exception wrapper --
        # the helper has already normalised everything. Pin it so that guarantee
        # cannot quietly weaken into a raw exception leak.
        class _Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                raise ValueError("shell blew up")

        with pytest.raises(AdbError) as info:
            _device_shell(_Dev(), "getprop")
        assert info.value.code == "backend_error"

    # _call and _device_shell deliberately diverge, and the whole backend's error
    # hygiene rests on it: _device_shell normalises *every* failure to AdbError,
    # while _call normalises *only* timeouts and re-raises anything else for the
    # caller to wrap with its own context (path/package/remote). Confusing the two
    # is what made launch/force_stop's except-Exception branch dead code; pin both
    # halves so neither can drift toward the other.
    def test_call_reraises_adb_error_unchanged(self) -> None:
        def method() -> None:
            raise AdbError("invalid_state", "already typed")

        with pytest.raises(AdbError) as info:
            _call(method, timeout=1.0)
        assert info.value.code == "invalid_state"

    def test_call_labels_a_timeout_as_adb_error(self) -> None:
        def method() -> None:
            raise _TimeoutError()

        with pytest.raises(AdbError) as info:
            _call(method, timeout=1.0)
        assert info.value.code == "timeout"

    def test_call_reraises_a_non_timeout_error_unchanged(self) -> None:
        # The load-bearing divergence: a plain ValueError is re-raised as-is, not
        # wrapped into backend_error. Every _call site relies on this to add its
        # own operation-specific context; if _call started wrapping like
        # _device_shell, those except-Exception branches would all go dead.
        sentinel = ValueError("boom")

        def method() -> None:
            raise sentinel

        with pytest.raises(ValueError) as info:
            _call(method, timeout=1.0)
        assert info.value is sentinel

    def test_info_timeout_from_get_state(self, monkeypatch: MP) -> None:
        dev = _FakeDev(get_state_error=_TimeoutError())
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.info("emulator-5554")
        assert info.value.code == "timeout"

    def test_force_stop_pidof_falls_back_to_ps(self, monkeypatch: MP) -> None:
        dev = _FakeDev(
            shell_map={
                "pidof com.example.app": "pidof: not found",
                "ps -A": "u0_a1 3120 1 com.example.app",
            }
        )
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is False
        assert 3120 in result["remaining_pids"]

    def test_forward_reraises_adb_error_and_frees_slot(self, monkeypatch: MP) -> None:
        dev = _FakeDev(forward_error=AdbError("invalid_state", "device busy"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "invalid_state"
        assert backend._forwards == []


class TestBindOpenTransport:
    def test_returns_device_when_no_open_transport(self) -> None:
        dev = SimpleNamespace()  # no open_transport attribute
        assert _bind_open_transport(dev, 5.0) is dev

    def test_rebinds_default_and_stays_callable(self) -> None:
        seen: dict[str, Any] = {}

        class _Dev:
            def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
                seen["timeout"] = timeout
                return "transport"

        dev = _Dev()
        bound = _bind_open_transport(dev, 42.0)
        assert bound.open_transport() == "transport"
        assert seen["timeout"] == 42.0

    def test_falls_back_to_positional_calls(self) -> None:
        class _Dev:
            def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
                # Reject the keyword form the wrapper tries first, forcing the
                # positional fallbacks the older adbutils shape needs.
                if command == "__kw__":
                    raise TypeError("no keywords")
                return "ok"

        dev = _Dev()
        original = dev.open_transport

        def kw_only(*, command: Any = None, timeout: float | None = None) -> str:
            raise TypeError("keyword form unsupported")

        dev.open_transport = kw_only  # type: ignore[method-assign]
        # Restore a positional-capable callable for the wrapper to fall back to.
        dev.open_transport = original  # type: ignore[method-assign]
        bound = _bind_open_transport(dev, 5.0)
        assert bound.open_transport() == "ok"

    def test_setattr_failure_returns_device_unchanged(self) -> None:
        class _Dev:
            @property
            def open_transport(self) -> Any:
                return lambda command=None, timeout=None: "x"

        dev = _Dev()
        # Assigning over a read-only property raises; the helper must swallow it.
        assert _bind_open_transport(dev, 5.0) is dev
