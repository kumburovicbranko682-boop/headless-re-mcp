"""AdbBackend helper and error-envelope paths a live adb server never reaches.

The device read-out, transfer and forward-bookkeeping suites cover the happy and
verify paths through an injected fake device. This file drives the surrounding
plumbing: the timeout/backend_error mapping in the shell and call wrappers, the
open_transport deadline shim, the AdbClient/device construction guards, the
UTF-16 manifest fallback, and the frida-server bring-up -- all of which only run
against a real adbutils and are otherwise dark.
"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _accepted_kwargs,
    _accepts_timeout,
    _apk_package_name,
    _bind_open_transport,
    _call,
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _pids_for_package,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


def _backend(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# --------------------------------------------------------------------------
# signature-driven helpers.
# --------------------------------------------------------------------------
def test_accepts_timeout_false_when_a_callable_has_no_signature() -> None:
    assert _accepts_timeout(range) is False


def test_accepted_kwargs_variants() -> None:
    def named(a: int, timeout: float | None = None) -> None: ...

    def var(**kwargs: Any) -> None: ...

    assert _accepted_kwargs(named, {"timeout": 1, "nope": 2}) == {"timeout": 1}
    assert _accepted_kwargs(var, {"timeout": 1, "nope": 2}) == {"timeout": 1, "nope": 2}
    # range has no introspectable signature -> nothing accepted.
    assert _accepted_kwargs(range, {"timeout": 1}) == {}


# --------------------------------------------------------------------------
# _device_shell / _call error mapping.
# --------------------------------------------------------------------------
class _ShellDev:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def shell(self, args: Any, timeout: float | None = None) -> str:
        raise self._exc


def test_device_shell_maps_a_timeout() -> None:
    with pytest.raises(AdbError) as info:
        _device_shell(_ShellDev(TimeoutError("timed out")), "getprop")
    assert info.value.code == "timeout"


def test_device_shell_maps_a_generic_failure_to_backend_error() -> None:
    with pytest.raises(AdbError) as info:
        _device_shell(_ShellDev(ValueError("broken pipe")), "getprop")
    assert info.value.code == "backend_error"


def test_device_shell_reraises_an_adb_error_unchanged() -> None:
    original = AdbError("invalid_state", "already known")
    with pytest.raises(AdbError) as info:
        _device_shell(_ShellDev(original), "getprop")
    assert info.value is original


def test_call_maps_a_timeout_when_a_deadline_was_requested() -> None:
    def method() -> None:
        raise TimeoutError("adb stalled")

    with pytest.raises(AdbError) as info:
        _call(method, timeout=5.0)
    assert info.value.code == "timeout"


def test_call_reraises_a_non_timeout_exception() -> None:
    def method() -> None:
        raise ValueError("not a timeout")

    with pytest.raises(ValueError):
        _call(method, timeout=5.0)


def test_call_reraises_an_adb_error() -> None:
    original = AdbError("permission_denied", "nope")

    def method() -> None:
        raise original

    with pytest.raises(AdbError) as info:
        _call(method, timeout=5.0)
    assert info.value is original


# --------------------------------------------------------------------------
# _frida_server_visible.
# --------------------------------------------------------------------------
class _PsDev:
    def __init__(self, ps_a: str, ps: str = "", raises: bool = False) -> None:
        self._ps_a = ps_a
        self._ps = ps
        self._raises = raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        if self._raises:
            raise RuntimeError("device gone")
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        return self._ps_a if tokens == ("ps", "-A") else self._ps


def test_frida_server_visible_true_from_ps_a() -> None:
    assert _frida_server_visible(_PsDev("root frida-server\n")) is True


def test_frida_server_visible_falls_back_to_ps() -> None:
    assert _frida_server_visible(_PsDev("init\n", "root frida-server\n")) is True


def test_frida_server_visible_is_none_on_error() -> None:
    assert _frida_server_visible(_PsDev("", raises=True)) is None


# --------------------------------------------------------------------------
# _bind_open_transport.
# --------------------------------------------------------------------------
def test_bind_open_transport_returns_dev_without_the_method() -> None:
    dev = SimpleNamespace(open_transport=None)
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_prefers_keyword_form() -> None:
    seen: list[tuple[str, Any, Any]] = []

    class _Dev:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            seen.append(("kw", command, timeout))
            return "t"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "t"
    assert seen == [("kw", None, 5.0)]


def test_bind_open_transport_falls_back_to_positional() -> None:
    seen: list[Any] = []

    class _Dev:
        def open_transport(self, *args: Any) -> str:
            seen.append(args)
            return "t"

    dev = _bind_open_transport(_Dev(), 7.0)
    assert dev.open_transport() == "t"
    assert seen == [(None, 7.0)]


def test_bind_open_transport_falls_back_to_command_only() -> None:
    seen: list[Any] = []

    class _Dev:
        def open_transport(self, command: Any = None) -> str:
            seen.append(command)
            return "t"

    dev = _bind_open_transport(_Dev(), 9.0)
    assert dev.open_transport() == "t"
    assert seen == [None]


def test_bind_open_transport_tolerates_a_read_only_attribute() -> None:
    class _Dev:
        __slots__ = ()

        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            return "t"

    dev = _Dev()
    # __slots__ makes the attribute assignment raise; the shim must return the
    # device unchanged rather than propagate that.
    assert _bind_open_transport(dev, 5.0) is dev


# --------------------------------------------------------------------------
# _file_mode_size / _apk_package_name / _pids_for_package.
# --------------------------------------------------------------------------
def test_file_mode_size_reads_a_tuple_row() -> None:
    assert _file_mode_size((0o100644, 4096)) == (0o100644, 4096)


def _binary_manifest_apk(tmp_path: Path, text16: str, name: str = "app.apk") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", text16.encode("utf-16-le"))
    return path


def test_apk_package_name_reads_a_utf16_manifest(tmp_path: Path) -> None:
    # A non-ASCII char makes the UTF-8 decode raise, so the reader takes the
    # UTF-16 fallback; the "package" marker then anchors the candidate scan.
    apk = _binary_manifest_apk(tmp_path, "\u00e9 package com.example.app")
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_skips_framework_ids(tmp_path: Path) -> None:
    apk = _binary_manifest_apk(
        tmp_path, "\u00e9 package android.permission.INTERNET com.example.app"
    )
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_returns_none_without_a_candidate(tmp_path: Path) -> None:
    apk = _binary_manifest_apk(tmp_path, "\u00e9 package noDotsHere")
    assert _apk_package_name(apk) is None


class _PidsDev:
    def __init__(self, pidof: str, ps: str = "", ps_raises: bool = False) -> None:
        self._pidof = pidof
        self._ps = ps
        self._ps_raises = ps_raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:1] == ("pidof",):
            return self._pidof
        if self._ps_raises:
            raise RuntimeError("ps gone")
        return self._ps


def test_pids_for_package_returns_none_when_the_ps_fallback_fails() -> None:
    dev = _PidsDev("pidof: not found", ps_raises=True)
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_returns_none_on_unparseable_output() -> None:
    dev = _PidsDev("weird output with no pids")
    assert _pids_for_package(dev, "com.example.app") is None


# --------------------------------------------------------------------------
# _client / _device construction guards.
# --------------------------------------------------------------------------
def _backend_with_adbutils(adb_client: Any, *, adb_path: Path | None = None) -> AdbBackend:
    backend = AdbBackend(adb_path)
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    return backend


def test_client_reports_capability_unavailable_without_adbutils() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    with pytest.raises(AdbError) as info:
        backend._client()
    assert info.value.code == "capability_unavailable"


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    made: list[dict[str, Any]] = []

    def adb_client(*, host: str, port: int) -> str:
        made.append({"host": host, "port": port})
        return "client"

    backend = _backend_with_adbutils(adb_client)
    assert backend._client() == "client"
    assert made == [{"host": "127.0.0.1", "port": 5037}]


def test_client_maps_a_timeout() -> None:
    def adb_client(**_: Any) -> str:
        raise TimeoutError("adb slow")

    with pytest.raises(AdbError) as info:
        _backend_with_adbutils(adb_client)._client()
    assert info.value.code == "timeout"


def test_client_maps_a_generic_failure_to_backend_error() -> None:
    def adb_client(**_: Any) -> str:
        raise RuntimeError("no server")

    with pytest.raises(AdbError) as info:
        _backend_with_adbutils(adb_client)._client()
    assert info.value.code == "backend_error"


def test_client_sets_the_adb_path_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    adb_path = tmp_path / "adb"
    adb_path.write_text("#!/bin/sh\n")

    def adb_client(**_: Any) -> str:
        return "client"

    backend = _backend_with_adbutils(adb_client, adb_path=adb_path)
    assert backend._client() == "client"
    import os

    assert os.environ["ADBUTILS_ADB_PATH"] == str(adb_path)


def test_device_maps_a_timeout() -> None:
    class _Client:
        def device(self, serial: str) -> Any:
            raise TimeoutError("transport wait")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **_: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend._device("emulator-5554")
    assert info.value.code == "timeout"


def test_device_maps_an_unknown_device_to_not_found() -> None:
    class _Client:
        def device(self, serial: str) -> Any:
            raise RuntimeError("device not found")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **_: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend._device("emulator-5554")
    assert info.value.code == "not_found"


# --------------------------------------------------------------------------
# per-method backend_error / verify branches.
# --------------------------------------------------------------------------
def test_info_wraps_a_read_failure_as_backend_error() -> None:
    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            raise RuntimeError("offline")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).info("emulator-5554")
    assert info.value.code == "backend_error"


def test_install_wraps_a_device_failure_as_backend_error(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.app"/>')

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).install("emulator-5554", str(apk))
    assert info.value.code == "backend_error"


class _LaunchDev:
    def __init__(self, *, foreground: str | None, shell_raises: bool = False,
                 current_raises: bool = False) -> None:
        self._foreground = foreground
        self._shell_raises = shell_raises
        self._current_raises = current_raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        if self._shell_raises:
            raise RuntimeError("monkey missing")
        return ""

    def app_current(self, timeout: float | None = None) -> Any:
        if self._current_raises:
            raise RuntimeError("dumpsys failed")
        return SimpleNamespace(package=self._foreground)


def test_launch_confirms_the_foreground_package() -> None:
    payload = _backend(_LaunchDev(foreground="com.example.app")).launch(
        "emulator-5554", "com.example.app"
    )
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_launch_is_null_when_the_foreground_cannot_be_read() -> None:
    payload = _backend(_LaunchDev(foreground=None, current_raises=True)).launch(
        "emulator-5554", "com.example.app"
    )
    assert payload["launched"] is None
    assert "note" in payload


def test_launch_wraps_a_monkey_failure() -> None:
    with pytest.raises(AdbError) as info:
        _backend(_LaunchDev(foreground=None, shell_raises=True)).launch(
            "emulator-5554", "com.example.app"
        )
    assert info.value.code == "backend_error"


def test_current_activity_wraps_a_read_failure() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys failed")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).current_activity("emulator-5554")
    assert info.value.code == "backend_error"


class _Image:
    def __init__(self, nbytes: int) -> None:
        self._nbytes = nbytes

    def save(self, path: str) -> None:
        with open(path, "wb") as handle:
            handle.truncate(self._nbytes)


class _ShotDev:
    def __init__(self, image: Any = None, raises: bool = False) -> None:
        self._image = image
        self._raises = raises

    def screenshot(self, timeout: float | None = None) -> Any:
        if self._raises:
            raise RuntimeError("screencap failed")
        return self._image


def test_screenshot_returns_the_saved_size(tmp_path: Path) -> None:
    payload = _backend(_ShotDev(_Image(16))).screenshot("emulator-5554", tmp_path / "s.png")
    assert payload["size"] == 16
    assert Path(payload["path"]).is_file()


def test_screenshot_refuses_an_image_over_the_cap(tmp_path: Path) -> None:
    big = _ShotDev(_Image(UNREGISTERED_CAPTURE_MAX_BYTES + 1))
    with pytest.raises(AdbError) as info:
        _backend(big).screenshot("emulator-5554", tmp_path / "big.png")
    assert info.value.code == "too_large"


def test_screenshot_wraps_a_capture_failure(tmp_path: Path) -> None:
    with pytest.raises(AdbError) as info:
        _backend(_ShotDev(raises=True)).screenshot("emulator-5554", tmp_path / "s.png")
    assert info.value.code == "backend_error"


class _PullDev:
    def __init__(self, *, stat_raises: bool = False, pull_raises: bool = False) -> None:
        self._stat_raises = stat_raises
        self._pull_raises = pull_raises
        self.sync = self

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        if self._stat_raises:
            raise RuntimeError("no stat")
        return SimpleNamespace(mode=stat.S_IFREG | 0o644, size=4)

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        if self._pull_raises:
            raise RuntimeError("pull broke")
        Path(local).write_bytes(b"data")


def test_pull_survives_a_best_effort_stat_failure(tmp_path: Path) -> None:
    payload = _backend(_PullDev(stat_raises=True)).pull(
        "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
    )
    assert payload["size"] == 4


def test_pull_wraps_a_transfer_failure(tmp_path: Path) -> None:
    with pytest.raises(AdbError) as info:
        _backend(_PullDev(pull_raises=True)).pull(
            "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
        )
    assert info.value.code == "backend_error"


def test_push_wraps_a_transfer_failure(tmp_path: Path) -> None:
    local = tmp_path / "small.bin"
    local.write_bytes(b"hello")

    class _Dev:
        def __init__(self) -> None:
            self.sync = self

        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("push broke")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).push("emulator-5554", str(local), "/sdcard/small.bin")
    assert info.value.code == "backend_error"


# --------------------------------------------------------------------------
# ensure_frida_server bring-up.
# --------------------------------------------------------------------------
class _FridaDev:
    def __init__(
        self,
        *,
        running: bool = False,
        visible_after_launch: bool = True,
        su_raises: bool = False,
        push_raises: bool = False,
    ) -> None:
        self.running = running
        self._visible_after_launch = visible_after_launch
        self._su_raises = su_raises
        self._push_raises = push_raises
        self.sync = self
        self.pushed: list[tuple[str, str]] = []

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        if self._push_raises:
            raise RuntimeError("push refused")
        self.pushed.append((local, remote))

    def shell(self, args: Any, timeout: float | None = None) -> str:
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:1] == ("ps",):
            return "root frida-server\n" if self.running else "init\n"
        text = args if isinstance(args, str) else " ".join(args)
        if text.startswith("su -c"):
            if self._su_raises:
                raise RuntimeError("su blocked")
            if self._visible_after_launch:
                self.running = True
            return ""
        return ""


def test_ensure_frida_server_is_a_noop_when_already_running() -> None:
    payload = _backend(_FridaDev(running=True)).ensure_frida_server("emulator-5554")
    assert payload["running"] is True
    assert payload["pushed"] is False


def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server(
            "emulator-5554", remote_path="not-absolute; rm -rf /"
        )
    assert info.value.code == "invalid_params"


def test_ensure_frida_server_rejects_a_bad_bind_host() -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server("emulator-5554", bind_host="1.2.3.4:evil")
    assert info.value.code == "invalid_params"


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert info.value.code == "not_found"


def test_ensure_frida_server_pushes_and_launches(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev()
    payload = _backend(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert payload["running"] is True
    assert payload["pushed"] is True
    assert dev.pushed


def test_ensure_frida_server_notes_a_launch_that_did_not_return() -> None:
    payload = _backend(_FridaDev(su_raises=True)).ensure_frida_server("emulator-5554")
    assert payload["pushed"] is False
    assert "verify manually" in payload["note"]


def test_ensure_frida_server_notes_when_not_visible_after_launch() -> None:
    payload = _backend(_FridaDev(visible_after_launch=False)).ensure_frida_server(
        "emulator-5554"
    )
    assert payload["running"] is False
    assert "not visible" in payload["note"]


def test_ensure_frida_server_wraps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev(push_raises=True)).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert info.value.code == "backend_error"


# --------------------------------------------------------------------------
# import success, client/device reraise, list_devices, connect, and the
# AdbError-reraise arcs that keep an already-structured error unchanged.
# --------------------------------------------------------------------------
def test_available_with_a_fake_adbutils_module(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    monkeypatch.setitem(sys.modules, "adbutils", types.ModuleType("adbutils"))
    assert AdbBackend().available is True


def test_client_reraises_an_adb_error() -> None:
    original = AdbError("invalid_state", "client boom")

    def adb_client(**_: Any) -> str:
        raise original

    with pytest.raises(AdbError) as info:
        _backend_with_adbutils(adb_client)._client()
    assert info.value is original


def _backend_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **_: client  # type: ignore[method-assign]
    return backend


def test_device_reraises_an_adb_error() -> None:
    original = AdbError("permission_denied", "device boom")

    class _Client:
        def device(self, serial: str) -> Any:
            raise original

    with pytest.raises(AdbError) as info:
        _backend_client(_Client())._device("emulator-5554")
    assert info.value is original


def test_device_wraps_the_transport_on_success() -> None:
    marker = SimpleNamespace(open_transport=lambda command=None, timeout=None: "t")

    class _Client:
        def device(self, serial: str) -> Any:
            return marker

    dev = _backend_client(_Client())._device("emulator-5554")
    assert dev is marker


class _ListClient:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def list(self) -> Any:
        raise self._exc


def test_list_devices_reraises_an_adb_error() -> None:
    original = AdbError("capability_unavailable", "no adb")
    with pytest.raises(AdbError) as info:
        _backend_client(_ListClient(original)).list_devices()
    assert info.value is original


def test_list_devices_maps_a_timeout() -> None:
    with pytest.raises(AdbError) as info:
        _backend_client(_ListClient(TimeoutError("slow"))).list_devices()
    assert info.value.code == "timeout"


def test_list_devices_maps_a_generic_failure() -> None:
    with pytest.raises(AdbError) as info:
        _backend_client(_ListClient(RuntimeError("boom"))).list_devices()
    assert info.value.code == "backend_error"


class _ConnectClient:
    def __init__(self, message: str = "connected to x", raises: bool = False) -> None:
        self._message = message
        self._raises = raises

    def connect(self, endpoint: str, timeout: float | None = None) -> str:
        if self._raises:
            raise RuntimeError("connection refused")
        return self._message


def test_connect_rejects_an_out_of_range_port() -> None:
    with pytest.raises(AdbError) as info:
        _backend_client(_ConnectClient()).connect(port=70000)
    assert info.value.code == "invalid_params"


def test_connect_wraps_a_refused_endpoint() -> None:
    with pytest.raises(AdbError) as info:
        _backend_client(_ConnectClient(raises=True)).connect(host="127.0.0.1", port=5555)
    assert info.value.code == "backend_error"


def test_connect_reports_a_successful_endpoint() -> None:
    payload = _backend_client(_ConnectClient("already connected")).connect(port=5555)
    assert payload["connected"] is True


def test_properties_skips_lines_that_are_not_key_value_pairs() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "garbage without brackets\n[ro.build.version.sdk]: [34]\n"

    payload = _backend(_Dev()).properties("emulator-5554")
    assert payload["properties"] == {"ro.build.version.sdk": "34"}


def test_packages_skips_an_empty_name() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "package:\npackage:com.example.app\n"

    payload = _backend(_Dev()).packages("emulator-5554")
    assert payload["packages"] == ["com.example.app"]


def test_info_reraises_an_adb_error() -> None:
    original = AdbError("timeout", "state read timed out")

    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            raise original

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).info("emulator-5554")
    assert info.value is original


def test_uninstall_wraps_a_device_failure() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError("DELETE_FAILED_INTERNAL_ERROR")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert info.value.code == "backend_error"


def test_current_activity_reraises_an_adb_error() -> None:
    original = AdbError("timeout", "dumpsys timed out")

    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise original

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).current_activity("emulator-5554")
    assert info.value is original


def test_pull_refuses_a_directory_that_lands_locally(tmp_path: Path) -> None:
    class _Dev:
        def __init__(self) -> None:
            self.sync = self

        def stat(self, remote: str, timeout: float | None = None) -> Any:
            return SimpleNamespace(mode=stat.S_IFREG | 0o644, size=4)

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            Path(local).mkdir()

    dest = tmp_path / "pulled"
    with pytest.raises(AdbError) as info:
        _backend(_Dev()).pull("emulator-5554", "/sdcard/x", dest)
    assert info.value.code == "invalid_params"
    assert not dest.exists()


def test_pull_refuses_a_file_that_exceeds_the_cap_after_transfer(tmp_path: Path) -> None:
    class _Dev:
        def __init__(self) -> None:
            self.sync = self

        def stat(self, remote: str, timeout: float | None = None) -> Any:
            raise RuntimeError("no stat")

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            with open(local, "wb") as handle:
                handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).pull("emulator-5554", "/sdcard/big", tmp_path / "big.bin")
    assert info.value.code == "too_large"


def test_forward_reraises_an_adb_error() -> None:
    original = AdbError("backend_error", "forward refused by adb")

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise original

    backend = _backend(_Dev())
    with pytest.raises(AdbError) as info:
        backend.forward("emulator-5554", "tcp:9000", "tcp:9000")
    assert info.value is original
    # The reserved slot must not leak when the forward fails.
    assert backend._forwards == []
