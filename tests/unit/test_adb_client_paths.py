"""ADB backend paths the readout/lifecycle suites do not reach.

These exercise the module-level helpers (timeout introspection, host-error
detection, package-id extraction, pid parsing), the ``_client`` / ``_device``
construction and its hang-ceiling wrapper, the frida-server bootstrap, and the
per-operation ``backend_error`` mapping. The theme is honesty under a stalled or
version-skewed device: a probe that cannot run must surface as timeout or a
structured error, never as an empty-but-successful result.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
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
    _device_info_row,
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _is_host_error_output,
    _is_timeout,
    _pids_for_package,
    _pm_path,
)


# ---------------------------------------------------------------------------
# timeout / kwargs introspection
# ---------------------------------------------------------------------------
def test_accepts_timeout_named_varkw_and_uninspectable() -> None:
    def named(x: int, timeout: float = 1.0) -> None:
        del x, timeout

    def varkw(x: int, **kw: object) -> None:
        del x, kw

    def plain(x: int) -> None:
        del x

    assert _accepts_timeout(named) is True
    assert _accepts_timeout(varkw) is True  # **kwargs can carry timeout
    assert _accepts_timeout(plain) is False
    # range has no introspectable signature -> False rather than raise.
    assert _accepts_timeout(range) is False


def test_accepted_kwargs_filters_to_the_signature() -> None:
    def named(a: int, b: int = 0) -> None:
        del a, b

    def varkw(a: int, **kw: object) -> None:
        del a, kw

    assert _accepted_kwargs(named, {"b": 1, "c": 2}) == {"b": 1}
    assert _accepted_kwargs(varkw, {"b": 1, "c": 2}) == {"b": 1, "c": 2}
    assert _accepted_kwargs(range, {"b": 1}) == {}


def test_is_timeout_and_host_error_detection() -> None:
    assert _is_timeout(RuntimeError("adb timed out")) is True
    assert _is_timeout(RuntimeError("refused")) is False
    assert _is_host_error_output("error: device offline\nadb: no device") is True
    assert _is_host_error_output("") is False
    # A real logcat line that merely mentions error is not a host error.
    assert _is_host_error_output("08-28 I/App: recovered from error") is False


# ---------------------------------------------------------------------------
# _device_shell / _call error mapping
# ---------------------------------------------------------------------------
class _ShellDev:
    """A device whose shell() delegates to a handler keyed on the command."""

    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.sync: Any = None

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        cmd = " ".join(args) if isinstance(args, list) else str(args)
        return self._handler(cmd)


def test_device_shell_maps_timeout_and_backend_error() -> None:
    def timeout_handler(cmd: str) -> str:
        raise RuntimeError("operation timed out")

    with pytest.raises(AdbError) as timed:
        _device_shell(_ShellDev(timeout_handler), "getprop")
    assert timed.value.code == "timeout"

    def refused_handler(cmd: str) -> str:
        raise RuntimeError("connection refused")

    with pytest.raises(AdbError) as failed:
        _device_shell(_ShellDev(refused_handler), "getprop")
    assert failed.value.code == "backend_error"


def test_device_shell_passes_through_an_adb_error() -> None:
    def handler(cmd: str) -> str:
        raise AdbError("invalid_params", "already structured")

    with pytest.raises(AdbError) as caught:
        _device_shell(_ShellDev(handler), "getprop")
    assert caught.value.code == "invalid_params"


def test_call_forwards_timeout_and_maps_deadline() -> None:
    seen: dict[str, Any] = {}

    def method(value: int, timeout: float | None = None) -> int:
        seen["timeout"] = timeout
        return value

    assert _call(method, 5, timeout=3.0) == 5
    assert seen["timeout"] == 3.0

    def slow(value: int, timeout: float | None = None) -> int:
        raise RuntimeError("timed out")

    with pytest.raises(AdbError) as caught:
        _call(slow, 1, timeout=2.0)
    assert caught.value.code == "timeout"


def test_call_passes_through_adb_error_and_reraises_non_timeout() -> None:
    def structured(value: int, timeout: float | None = None) -> int:
        raise AdbError("not_found", "gone")

    with pytest.raises(AdbError) as adb:
        _call(structured, 1, timeout=2.0)
    assert adb.value.code == "not_found"

    def other(value: int, timeout: float | None = None) -> int:
        raise ValueError("some other failure")

    with pytest.raises(ValueError):
        _call(other, 1, timeout=2.0)


# ---------------------------------------------------------------------------
# _frida_server_visible
# ---------------------------------------------------------------------------
def test_frida_server_visible_true_on_ps_a_then_ps_then_none() -> None:
    seen = _ShellDev(lambda cmd: "root 900 frida-server\n")
    assert _frida_server_visible(seen) is True

    def ps_fallback(cmd: str) -> str:
        return "" if cmd == "ps -A" else "u0 frida-server"

    assert _frida_server_visible(_ShellDev(ps_fallback)) is True

    def boom(cmd: str) -> str:
        raise RuntimeError("device offline")

    assert _frida_server_visible(_ShellDev(boom)) is None


# ---------------------------------------------------------------------------
# _bind_open_transport
# ---------------------------------------------------------------------------
def test_bind_open_transport_noop_without_the_method() -> None:
    dev = object()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_falls_back_through_positional_forms() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Dev:
        def open_transport(self, command: Any = None) -> str:
            # Only accepts a single positional command; kwargs and (cmd, timeout)
            # both raise TypeError, driving the wrapper's fallbacks.
            calls.append((command,))
            return "transport"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport("cmd") == "transport"
    assert calls == [("cmd",)]


def test_bind_open_transport_returns_dev_when_it_cannot_install() -> None:
    class _Slots:
        __slots__ = ()

        def open_transport(self, command: Any = None, timeout: float | None = None) -> None:
            del command, timeout

    dev = _Slots()
    # Assigning the wrapper raises (no __dict__); the original dev is returned.
    assert _bind_open_transport(dev, 5.0) is dev


# ---------------------------------------------------------------------------
# _device_info_row / _file_mode_size tuple shapes
# ---------------------------------------------------------------------------
def test_device_info_row_reads_objects_and_tuples() -> None:
    from types import SimpleNamespace

    row = _device_info_row(SimpleNamespace(serial="abc", state="device"))
    assert row == {"serial": "abc", "state": "device"}
    # A bare (serial, state) tuple is read positionally.
    assert _device_info_row(("emulator-5554", "offline")) == {
        "serial": "emulator-5554",
        "state": "offline",
    }
    # Missing state defaults to unknown.
    assert _device_info_row(("only-serial",))["state"] == "unknown"


def test_file_mode_size_reads_objects_and_tuples() -> None:
    from types import SimpleNamespace

    assert _file_mode_size(SimpleNamespace(mode=0o100644, size=10)) == (0o100644, 10)
    assert _file_mode_size((0o40755, 4096)) == (0o40755, 4096)


# ---------------------------------------------------------------------------
# _apk_package_name
# ---------------------------------------------------------------------------
def test_apk_package_name_from_utf8_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.app"/>')
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_from_binary_axml(tmp_path: Path) -> None:
    apk = tmp_path / "b.apk"
    # Bytes that fail utf-8 decode (0xff) but decode in utf-16-le to a string
    # containing a "package" marker followed by a clean package id.
    payload = (
        b"\xff\xfe"
        + "package".encode("utf-16-le")
        + b"\x20\x00"
        + "com.example.app".encode("utf-16-le")
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", payload)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_none_without_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "c.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"\x00")
    assert _apk_package_name(apk) is None


# ---------------------------------------------------------------------------
# _pm_path / _pids_for_package
# ---------------------------------------------------------------------------
def test_pm_path_reads_package_line_host_error_and_absence() -> None:
    dev = _ShellDev(lambda cmd: "package:/data/app/com.x/base.apk")
    assert _pm_path(dev, "com.x") == "/data/app/com.x/base.apk"

    host = _ShellDev(lambda cmd: "error: device offline")
    with pytest.raises(AdbError) as caught:
        _pm_path(host, "com.x")
    assert caught.value.code == "backend_error"

    absent = _ShellDev(lambda cmd: "")
    assert _pm_path(absent, "com.x") is None


def test_pids_for_package_digits_empty_and_ps_fallback() -> None:
    assert _pids_for_package(_ShellDev(lambda cmd: "123 456"), "com.x") == [123, 456]
    assert _pids_for_package(_ShellDev(lambda cmd: ""), "com.x") == []
    # A non-digit, non-"not found" reply means pidof produced nothing usable.
    assert _pids_for_package(_ShellDev(lambda cmd: "garbage"), "com.x") is None

    def not_found_then_ps(cmd: str) -> str:
        if cmd.startswith("pidof"):
            return "pidof: not found"
        return "u0_a1 1500 1000 com.x\n"

    assert _pids_for_package(_ShellDev(not_found_then_ps), "com.x") == [1500]


def test_pids_for_package_returns_none_when_a_probe_raises() -> None:
    def pidof_fails(cmd: str) -> str:
        raise AdbError("timeout", "adb timed out after 8s")

    assert _pids_for_package(_ShellDev(pidof_fails), "com.x") is None

    def not_found_then_ps_fails(cmd: str) -> str:
        if cmd.startswith("pidof"):
            return "not found"
        raise AdbError("timeout", "adb timed out after 8s")

    assert _pids_for_package(_ShellDev(not_found_then_ps_fails), "com.x") is None


# ---------------------------------------------------------------------------
# _client / _device
# ---------------------------------------------------------------------------
def test_client_reports_capability_unavailable() -> None:
    backend = AdbBackend()
    backend._available = False
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_constructs_with_and_without_socket_timeout() -> None:
    class _WithTimeout:
        def __init__(self, host: str, port: int, socket_timeout: float | None = None) -> None:
            self.socket_timeout = socket_timeout

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = type("m", (), {"AdbClient": _WithTimeout})()
    client = backend._client(socket_timeout=12.0)
    assert client.socket_timeout == 12.0

    class _NoTimeout:
        def __init__(self, host: str, port: int) -> None:
            self.host = host

    backend._adbutils = type("m", (), {"AdbClient": _NoTimeout})()
    fallback = backend._client()
    assert fallback.host == "127.0.0.1"


def test_client_maps_timeout_and_backend_error() -> None:
    backend = AdbBackend()
    backend._available = True

    def timeout_client(host: str, port: int, socket_timeout: float | None = None) -> None:
        raise RuntimeError("adb timed out")

    backend._adbutils = type("m", (), {"AdbClient": staticmethod(timeout_client)})()
    with pytest.raises(AdbError) as timed:
        backend._client()
    assert timed.value.code == "timeout"

    def broken_client(host: str, port: int, socket_timeout: float | None = None) -> None:
        raise RuntimeError("no adb server")

    backend._adbutils = type("m", (), {"AdbClient": staticmethod(broken_client)})()
    with pytest.raises(AdbError) as failed:
        backend._client()
    assert failed.value.code == "backend_error"


def test_client_sets_the_adb_path_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)

    class _Client:
        def __init__(self, host: str, port: int, socket_timeout: float | None = None) -> None:
            pass

    backend = AdbBackend()
    backend._available = True
    backend._adb_path = Path("/opt/platform-tools/adb")
    backend._adbutils = type("m", (), {"AdbClient": _Client})()
    backend._client()
    assert os.environ.get("ADBUTILS_ADB_PATH") == "/opt/platform-tools/adb"


def test_device_maps_not_found_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = AdbBackend()
    backend._available = True

    class _Client:
        def __init__(self, fail: str) -> None:
            self._fail = fail

        def device(self, serial: str) -> Any:
            if self._fail == "timeout":
                raise RuntimeError("adb timed out")
            raise RuntimeError("device offline")

    backend._client = lambda **kw: _Client("timeout")  # type: ignore[method-assign]
    with pytest.raises(AdbError) as timed:
        backend._device("emulator-5554")
    assert timed.value.code == "timeout"

    backend._client = lambda **kw: _Client("offline")  # type: ignore[method-assign]
    with pytest.raises(AdbError) as missing:
        backend._device("emulator-5554")
    assert missing.value.code == "not_found"


def test_device_returns_the_bound_device() -> None:
    backend = AdbBackend()
    backend._available = True
    dev = object()

    class _Client:
        def device(self, serial: str) -> Any:
            assert serial == "emulator-5554"
            return dev

    backend._client = lambda **kw: _Client()  # type: ignore[method-assign]
    assert backend._device("emulator-5554") is dev


# ---------------------------------------------------------------------------
# method-level backend_error / verification branches
# ---------------------------------------------------------------------------
def _backend_with(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_list_devices_maps_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = AdbBackend()
    backend._available = True

    class _Client:
        def list(self) -> list[Any]:
            raise RuntimeError("adb server down")

    backend._client = lambda **kw: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "backend_error"


def test_connect_rejects_bad_port_and_maps_failure() -> None:
    backend = AdbBackend()
    backend._available = True

    class _Client:
        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            raise RuntimeError("no route to host")

    backend._client = lambda **kw: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as bad_port:
        backend.connect("127.0.0.1", 99999)
    assert bad_port.value.code == "invalid_params"

    with pytest.raises(AdbError) as failed:
        backend.connect("127.0.0.1", 5555)
    assert failed.value.code == "backend_error"


class _MethodDev:
    """Configurable device for the per-method error branches."""

    def __init__(self, handler: Any) -> None:
        self._handler = handler

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        cmd = " ".join(args) if isinstance(args, list) else str(args)
        return self._handler(cmd)


def test_info_maps_a_getprop_failure() -> None:
    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            raise RuntimeError("device stalled")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "value"

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_info_passes_through_a_structured_adb_error() -> None:
    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            raise AdbError("timeout", "adb timed out after 8s")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "value"

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).info("emulator-5554")
    assert caught.value.code == "timeout"


def test_launch_passes_through_a_shell_error() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("monkey crashed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).launch("emulator-5554", "com.x")
    # _device_shell already mapped it to a structured error; launch re-raises it.
    assert caught.value.code == "backend_error"


def test_force_stop_passes_through_a_shell_error() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("am crashed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).force_stop("emulator-5554", "com.x")
    assert caught.value.code == "backend_error"


def test_properties_skips_non_matching_lines() -> None:
    dev = _MethodDev(lambda cmd: "[ro.a]: [1]\ngarbage line\n[ro.b]: [2]\n")
    payload = _backend_with(dev).properties("emulator-5554")
    assert payload["properties"] == {"ro.a": "1", "ro.b": "2"}
    assert payload["count"] == 2


def test_packages_skips_empty_and_non_package_lines() -> None:
    dev = _MethodDev(lambda cmd: "package:com.a\nnoise\npackage:\npackage:com.b\n")
    payload = _backend_with(dev).packages("emulator-5554")
    assert payload["packages"] == ["com.a", "com.b"]


def test_install_maps_a_transfer_failure(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.x"/>')

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kw: Any) -> None:
            raise RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_uninstall_maps_a_failure() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError("DELETE_FAILED_INTERNAL_ERROR")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.x")
    assert caught.value.code == "backend_error"


def test_launch_reports_when_foreground_cannot_be_read() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "Events injected: 1"

        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys unavailable")

    payload = _backend_with(_Dev()).launch("emulator-5554", "com.x")
    assert payload["launched"] is None
    assert "could not read foreground" in payload["note"]


def test_current_activity_maps_a_read_failure() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys crashed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_force_stop_reports_when_pids_cannot_be_read() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            cmd = " ".join(args) if isinstance(args, list) else str(args)
            if cmd.startswith("am force-stop"):
                return ""
            raise AdbError("timeout", "adb timed out after 8s")

    payload = _backend_with(_Dev()).force_stop("emulator-5554", "com.x")
    assert payload["stopped"] is None
    assert "could not read process list" in payload["note"]


def test_screenshot_maps_a_capture_failure(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            raise RuntimeError("no framebuffer")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).screenshot("emulator-5554", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# pull sync branches
# ---------------------------------------------------------------------------
class _PullSync:
    def __init__(self, *, stat_raises: bool = False, pull: Any = None) -> None:
        self._stat_raises = stat_raises
        self._pull = pull

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        if self._stat_raises:
            raise RuntimeError("stat unsupported")
        raise AssertionError("unexpected stat call")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        if self._pull is not None:
            self._pull(remote, local)


def test_pull_proceeds_when_stat_is_unavailable(tmp_path: Path) -> None:
    def write(remote: str, local: str) -> None:
        Path(local).write_bytes(b"payload")

    class _Dev:
        sync = _PullSync(stat_raises=True, pull=write)

    local = tmp_path / "out.bin"
    payload = _backend_with(_Dev()).pull("emulator-5554", "/sdcard/x.bin", local)
    assert payload["size"] == 7


def test_pull_maps_a_transfer_failure(tmp_path: Path) -> None:
    def boom(remote: str, local: str) -> None:
        raise RuntimeError("permission denied")

    class _Dev:
        sync = _PullSync(stat_raises=True, pull=boom)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).pull("emulator-5554", "/sdcard/x.bin", tmp_path / "o.bin")
    assert caught.value.code == "backend_error"


def test_pull_refuses_a_directory_that_lands_locally(tmp_path: Path) -> None:
    def make_dir(remote: str, local: str) -> None:
        Path(local).mkdir()

    class _Dev:
        sync = _PullSync(stat_raises=True, pull=make_dir)

    local = tmp_path / "tree"
    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).pull("emulator-5554", "/sdcard/dir", local)
    assert caught.value.code == "invalid_params"
    assert not local.exists()  # the mistaken tree is cleaned up


def test_pull_reports_when_nothing_was_written(tmp_path: Path) -> None:
    class _Dev:
        sync = _PullSync(stat_raises=True, pull=lambda remote, local: None)

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).pull("emulator-5554", "/sdcard/ghost", tmp_path / "ghost.bin")
    assert caught.value.code == "not_found"


def test_push_maps_a_transfer_failure(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"hi")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("no space left on device")

    class _Dev:
        sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).push("emulator-5554", str(small), "/sdcard/x")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# ensure_frida_server
# ---------------------------------------------------------------------------
def test_ensure_frida_server_validates_remote_path() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", remote_path="relative/path"
        )
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_pushes_and_reports_running(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    state = {"phase": 0}

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            state["pushed"] = (local, remote)

    class _Dev:
        sync = _Sync()

        def shell(self, args: Any, timeout: float | None = None) -> str:
            cmd = " ".join(args) if isinstance(args, list) else str(args)
            if cmd.startswith("ps"):
                # Not visible before launch; visible after the su -c line runs.
                return "frida-server" if state["phase"] >= 1 else ""
            if cmd.startswith("su -c"):
                state["phase"] = 1
                return ""
            return ""

    payload = _backend_with(_Dev()).ensure_frida_server(
        "emulator-5554", server_binary=str(binary), port=27042
    )
    assert payload["running"] is True
    assert payload["pushed"] is True
    assert state["pushed"][1] == "/data/local/tmp/frida-server"


def test_ensure_frida_server_maps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("read-only filesystem")

    class _Dev:
        sync = _Sync()

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""  # not visible

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "backend_error"


def test_ensure_frida_server_notes_a_launch_that_could_not_be_confirmed() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            cmd = " ".join(args) if isinstance(args, list) else str(args)
            if cmd.startswith("su -c"):
                raise RuntimeError("su timed out")
            return ""  # never visible

    payload = _backend_with(_Dev()).ensure_frida_server("emulator-5554")
    # A launch that cannot be confirmed is reported honestly, not as running.
    assert payload["running"] in (None, False)
    assert "verify manually" in payload["note"]


def test_ensure_frida_server_reports_a_missing_binary(tmp_path: Path) -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""  # not visible

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert caught.value.code == "not_found"


# ---------------------------------------------------------------------------
# forward: AdbError from the bind releases the reserved slot
# ---------------------------------------------------------------------------
def test_forward_releases_the_slot_on_an_adb_error() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "adb timed out after 30s")

    backend = _backend_with(_Dev())
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "timeout"
    # The reserved slot must not survive a failed bind.
    assert backend._forwards == []
