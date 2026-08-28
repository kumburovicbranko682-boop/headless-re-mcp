"""Guard, error and verify branches of the ADB (adbutils) backend.

The existing adb tests pin the honest paging / tri-state read-outs on a scripted
device. This file fills in the branches those happy-path fakes step over: the
timeout-vs-backend translation every adbutils call funnels through, the
availability and transport guards, the APK package sniffing, and the
install/uninstall/pull/push/forward cleanup that has to hold when the device or
the local file is wrong. Each test pins one branch.

No adbutils, adb server or device is required: every device / client / sync
object is a stand-in returning or raising exactly what the real one would at the
seam under test, which is where the client's own translation logic lives.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adbmod
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
    _pids_for_package,
    _pm_path,
)


class _ScriptedDev:
    """A device whose ``shell`` answers by the command's leading tokens."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], str],
        *,
        raise_for: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        self._responses = responses
        self._raise_for = set(raise_for)
        self.calls: list[list[str] | str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens in self._raise_for:
            raise RuntimeError("device stalled")
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def _backend_with(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# ---------------------------------------------------------------------------
# Module helpers: signature probes and translation.
# ---------------------------------------------------------------------------
def test_accepts_timeout_reads_the_signature() -> None:
    def named(a: int, timeout: float = 0.0) -> int:
        return a

    def varkw(a: int, **kwargs: Any) -> int:
        return a

    def plain(a: int) -> int:
        return a

    assert _accepts_timeout(named) is True
    assert _accepts_timeout(varkw) is True
    assert _accepts_timeout(plain) is False
    # An uninspectable callable is treated as not accepting timeout.
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_filters_to_the_signature() -> None:
    def named(a: int, nolaunch: bool = False) -> int:
        return a

    def varkw(a: int, **kwargs: Any) -> int:
        return a

    extra = {"nolaunch": True, "uninstall": False, "flags": []}
    assert _accepted_kwargs(named, extra) == {"nolaunch": True}
    assert _accepted_kwargs(varkw, extra) == extra
    # An uninspectable callable gets nothing rather than raising later.
    assert _accepted_kwargs(object(), extra) == {}


def test_device_shell_reraises_an_adb_error() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("timeout", "already structured")

    with pytest.raises(AdbError) as caught:
        _device_shell(_Dev(), "getprop")
    assert caught.value.code == "timeout"


def test_call_reraises_adb_error_and_maps_timeouts() -> None:
    def raises_adb(**kwargs: Any) -> None:
        raise AdbError("invalid_params", "structured")

    with pytest.raises(AdbError) as structured:
        _call(raises_adb, timeout=1.0)
    assert structured.value.code == "invalid_params"

    def raises_timeout(**kwargs: Any) -> None:
        raise RuntimeError("operation timed out")

    with pytest.raises(AdbError) as timed:
        _call(raises_timeout, timeout=1.0)
    assert timed.value.code == "timeout"


def test_frida_server_visible_reads_ps_fallback_and_swallows_errors() -> None:
    # ps -A shows nothing, ps shows the server: the fallback answer is used.
    seen_in_ps = _ScriptedDev({("ps",): "1 frida-server", ("ps", "-A"): "1 init"})
    assert _frida_server_visible(seen_in_ps) is True

    # A device that errors on the probe yields None, not a false negative.
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("offline")

    assert _frida_server_visible(_Dev()) is None


def test_file_mode_size_reads_a_tuple_shape() -> None:
    assert _file_mode_size((0o40000, 512)) == (0o40000, 512)


# ---------------------------------------------------------------------------
# _bind_open_transport.
# ---------------------------------------------------------------------------
def test_bind_open_transport_passes_through_without_the_method() -> None:
    dev = object()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_falls_back_across_signatures() -> None:
    """Older adbutils open_transport takes only ``command``.

    The wrapper tries the kwarg form, then positional, then bare command, so a
    device on any of those signatures still gets a bounded transport.
    """
    calls: list[tuple[Any, ...]] = []

    class _Dev:
        def open_transport(self, command: Any = None) -> str:
            calls.append((command,))
            return "transport"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "transport"


def test_bind_open_transport_returns_dev_when_it_cannot_rebind() -> None:
    """A device that refuses attribute assignment keeps its own method."""

    class _Dev:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "readonly"

    dev = _Dev()
    assert _bind_open_transport(dev, 5.0) is dev


# ---------------------------------------------------------------------------
# _apk_package_name.
# ---------------------------------------------------------------------------
def _apk_with_manifest(tmp_path: Path, manifest: bytes, name: str = "app.apk") -> Path:
    apk = tmp_path / name
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    return apk


def test_apk_package_name_reads_a_plain_text_manifest(tmp_path: Path) -> None:
    apk = _apk_with_manifest(tmp_path, b'<manifest package="com.example.app">')
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_falls_back_to_utf16_and_skips_framework_ids(
    tmp_path: Path,
) -> None:
    """A binary AXML that is not utf-8 is scanned as utf-16, framework ids aside.

    A real binary manifest fails the utf-8 decode, so the reader drops to a
    utf-16 scan around the ``package`` marker and skips the android.* strings
    that always appear before the app's own id.
    """
    body = "package android.support com.example.myapp".encode("utf-16-le")
    apk = _apk_with_manifest(tmp_path, b"\xff\xff" + body)
    assert _apk_package_name(apk) == "com.example.myapp"


def test_apk_package_name_is_none_without_a_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "empty.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    assert _apk_package_name(apk) is None


# ---------------------------------------------------------------------------
# _pids_for_package.
# ---------------------------------------------------------------------------
def test_pids_for_package_returns_none_when_ps_fallback_fails() -> None:
    dev = _ScriptedDev(
        {("pidof",): "pidof: not found"},
        raise_for=(("ps", "-A"),),
    )
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_caps_the_ps_fallback_scan() -> None:
    rows = "\n".join(f"u0_a{i} {1000 + i} 1 0 0 x 0 S com.example.app" for i in range(20))
    dev = _ScriptedDev({("pidof",): "not found", ("ps", "-A"): rows})
    pids = _pids_for_package(dev, "com.example.app")
    assert pids is not None
    assert len(pids) == 16


def test_pids_for_package_none_when_pidof_has_no_digits() -> None:
    dev = _ScriptedDev({("pidof",): "garbage-no-numbers"})
    assert _pids_for_package(dev, "com.example.app") is None


# ---------------------------------------------------------------------------
# __init__ / _client / _device.
# ---------------------------------------------------------------------------
def test_backend_without_adbutils_reports_unavailable(monkeypatch: Any) -> None:
    import builtins

    real_import = builtins.__import__

    def deny(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "adbutils":
            raise ImportError("no adbutils")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny)
    backend = AdbBackend()
    assert backend.available is False
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    """Older adbutils AdbClient has no socket_timeout kwarg.

    The client tries the timeout-bounded constructor first and falls back to the
    plain one on TypeError rather than failing outright on an older adbutils.
    """
    attempts: list[str] = []

    class _Adbutils:
        @staticmethod
        def AdbClient(host: str, port: int) -> str:
            attempts.append(host)
            return "client"

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _Adbutils()
    assert backend._client() == "client"
    assert attempts == ["127.0.0.1"]


def test_client_translates_timeout_and_backend_failures() -> None:
    class _Timeout:
        @staticmethod
        def AdbClient(host: str, port: int, socket_timeout: float) -> str:
            raise RuntimeError("connection timed out")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _Timeout()
    with pytest.raises(AdbError) as timed:
        backend._client()
    assert timed.value.code == "timeout"

    class _Broken:
        @staticmethod
        def AdbClient(host: str, port: int, socket_timeout: float) -> str:
            raise RuntimeError("no adb server")

    backend._adbutils = _Broken()
    with pytest.raises(AdbError) as broke:
        backend._client()
    assert broke.value.code == "backend_error"


def test_device_translates_lookup_failures() -> None:
    class _Client:
        def __init__(self, exc: Exception) -> None:
            self._exc = exc

        def device(self, serial: str) -> Any:
            raise self._exc

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client(RuntimeError("timed out"))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as timed:
        backend._device("emulator-5554")
    assert timed.value.code == "timeout"

    backend._client = lambda **kwargs: _Client(RuntimeError("no device"))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as missing:
        backend._device("emulator-5554")
    assert missing.value.code == "not_found"


def test_client_passes_through_a_structured_failure() -> None:
    """An AdbError from the constructor is re-raised, not rewrapped."""

    class _Adbutils:
        @staticmethod
        def AdbClient(host: str, port: int, socket_timeout: float) -> str:
            raise AdbError("capability_unavailable", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _Adbutils()
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_device_passes_through_a_structured_failure() -> None:
    class _Client:
        def device(self, serial: str) -> Any:
            raise AdbError("not_found", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend._device("emulator-5554")
    assert caught.value.code == "not_found"


def test_device_binds_the_transport_on_success() -> None:
    class _Dev:
        serial = "emulator-5554"

    class _Client:
        def device(self, serial: str) -> _Dev:
            return _Dev()

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client()  # type: ignore[method-assign]
    dev = backend._device("emulator-5554")
    assert isinstance(dev, _Dev)


# ---------------------------------------------------------------------------
# list_devices / connect.
# ---------------------------------------------------------------------------
def test_list_devices_translates_failures() -> None:
    class _Client:
        def __init__(self, exc: Exception) -> None:
            self._exc = exc

        def list(self) -> Any:
            raise self._exc

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client(RuntimeError("timed out"))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as timed:
        backend.list_devices()
    assert timed.value.code == "timeout"

    backend._client = lambda **kwargs: _Client(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as broke:
        backend.list_devices()
    assert broke.value.code == "backend_error"


def test_list_devices_passes_through_a_structured_failure() -> None:
    class _Client:
        def list(self) -> Any:
            raise AdbError("timeout", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "timeout"


def test_connect_rejects_a_bad_port_and_wraps_failures() -> None:
    class _Client:
        def connect(self, endpoint: str, timeout: float = 0.0) -> str:
            raise RuntimeError("refused")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: _Client()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as bad_port:
        backend.connect("127.0.0.1", 99999)
    assert bad_port.value.code == "invalid_params"

    with pytest.raises(AdbError) as failed:
        backend.connect("127.0.0.1", 5555)
    assert failed.value.code == "backend_error"


# ---------------------------------------------------------------------------
# info / properties / packages read-out guards.
# ---------------------------------------------------------------------------
def test_info_wraps_a_structured_and_an_unstructured_failure() -> None:
    # A shell that raises becomes AdbError inside _device_shell and re-raises.
    class _StateOk:
        def get_state(self, timeout: float | None = None) -> str:
            return "device"

        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("getprop stalled")

    with pytest.raises(AdbError) as structured:
        _backend_with(_StateOk()).info("emulator-5554")
    assert structured.value.code == "backend_error"


def test_properties_skips_lines_that_are_not_property_rows() -> None:
    dump = "not a property line\n[ro.name]: [pixel]\ngarbage"
    dev = _ScriptedDev({("getprop",): dump})
    payload = _backend_with(dev).properties("emulator-5554")
    assert payload["properties"] == {"ro.name": "pixel"}


def test_packages_skips_blank_and_non_package_lines() -> None:
    listing = "not-a-package\npackage:\npackage:com.example.app"
    dev = _ScriptedDev({("pm", "list", "packages"): listing})
    payload = _backend_with(dev).packages("emulator-5554")
    assert payload["packages"] == ["com.example.app"]


# ---------------------------------------------------------------------------
# install / uninstall / launch / force_stop / current_activity errors.
# ---------------------------------------------------------------------------
def test_install_wraps_a_backend_failure(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="com.example.app">')

    class _Dev:
        def install(self, path: str, **kwargs: Any) -> None:
            raise RuntimeError("INSTALL_FAILED")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_uninstall_wraps_a_backend_failure() -> None:
    class _Dev:
        def uninstall(self, package: str, **kwargs: Any) -> None:
            raise RuntimeError("DELETE_FAILED")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_launch_wraps_a_failure_and_notes_an_unreadable_foreground() -> None:
    class _Raises:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("monkey failed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Raises()).launch("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"

    class _NoForeground:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys stalled")

    payload = _backend_with(_NoForeground()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "note" in payload


def test_force_stop_wraps_a_backend_failure() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("am failed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).force_stop("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_current_activity_wraps_a_failure() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys stalled")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# screenshot / pull / push.
# ---------------------------------------------------------------------------
def test_screenshot_saves_and_reports_size(tmp_path: Path) -> None:
    class _Image:
        def save(self, path: str) -> None:
            Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

    class _Dev:
        def screenshot(self, **kwargs: Any) -> _Image:
            return _Image()

    out = tmp_path / "shots" / "s.png"
    payload = _backend_with(_Dev()).screenshot("emulator-5554", out)
    assert payload["size"] > 0
    assert Path(payload["path"]).is_file()


def test_screenshot_wraps_a_capture_failure(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, **kwargs: Any) -> Any:
            raise RuntimeError("capture failed")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).screenshot("emulator-5554", tmp_path / "s.png")
    assert caught.value.code == "backend_error"


class _Sync:
    def __init__(self, *, stat_result: Any = None, stat_raises: bool = False,
                 pull_action: Any = None, push_action: Any = None) -> None:
        self._stat_result = stat_result
        self._stat_raises = stat_raises
        self._pull_action = pull_action
        self._push_action = push_action

    def stat(self, remote: str, **kwargs: Any) -> Any:
        if self._stat_raises:
            raise RuntimeError("stat failed")
        return self._stat_result

    def pull(self, remote: str, local: str, **kwargs: Any) -> None:
        if self._pull_action is not None:
            self._pull_action(local)

    def push(self, local: str, remote: str, **kwargs: Any) -> None:
        if self._push_action is not None:
            self._push_action()


def test_pull_over_cap_after_transfer_is_too_large(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A pulled file bigger than the cap is refused after the transfer.

    The pre-stat probe is best-effort, so the real size is only known once the
    bytes land; a file over the cap must surface too_large rather than a size
    that lies about what fits.
    """
    monkeypatch.setattr(adbmod, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)

    def write_big(local: str) -> None:
        Path(local).write_bytes(b"x" * 64)

    dev = type("_D", (), {"sync": _Sync(stat_raises=True, pull_action=write_big)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/f", tmp_path / "out.bin")
    assert caught.value.code == "too_large"


def test_pull_refuses_a_directory_result(tmp_path: Path) -> None:
    def make_dir(local: str) -> None:
        Path(local).mkdir(parents=True, exist_ok=True)

    dev = type("_D", (), {"sync": _Sync(stat_raises=True, pull_action=make_dir)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/dir", tmp_path / "out")
    assert caught.value.code == "invalid_params"


def test_pull_wraps_a_transfer_failure(tmp_path: Path) -> None:
    def boom(local: str) -> None:
        raise RuntimeError("transfer reset")

    dev = type("_D", (), {"sync": _Sync(stat_raises=True, pull_action=boom)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/f", tmp_path / "out.bin")
    assert caught.value.code == "backend_error"


def test_push_reports_a_missing_local_file(tmp_path: Path) -> None:
    dev = type("_D", (), {"sync": _Sync()})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).push("emulator-5554", str(tmp_path / "absent"), "/sdcard/f")
    assert caught.value.code == "not_found"


def test_push_wraps_a_transfer_failure(tmp_path: Path) -> None:
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")

    def boom() -> None:
        raise RuntimeError("push reset")

    dev = type("_D", (), {"sync": _Sync(push_action=boom)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).push("emulator-5554", str(local), "/sdcard/f")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# ensure_frida_server.
# ---------------------------------------------------------------------------
def test_ensure_frida_server_validates_remote_path() -> None:
    dev = _ScriptedDev({})
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).ensure_frida_server("emulator-5554", remote_path="../escape")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_reports_an_already_running_server() -> None:
    dev = _ScriptedDev({("ps", "-A"): "1 frida-server"})
    payload = _backend_with(dev).ensure_frida_server("emulator-5554")
    assert payload["running"] is True
    assert payload["pushed"] is False


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _ScriptedDev({("ps", "-A"): "1 init"})
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert caught.value.code == "not_found"


def test_ensure_frida_server_notes_a_launch_that_could_not_be_confirmed() -> None:
    """A su launch that errors is reported with a note, not raised.

    A blocking su often means the launch fired but the shell never returned, so
    the reply carries a manual-verify note rather than turning a likely success
    into a failure.
    """

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("su prompt")

    payload = _backend_with(_Dev()).ensure_frida_server("emulator-5554")
    assert payload["pushed"] is False
    assert "note" in payload


def test_ensure_frida_server_confirms_a_freshly_launched_server() -> None:
    """Once the launch command runs, a follow-up ps that sees the server wins."""

    class _StatefulDev:
        def __init__(self) -> None:
            self.launched = False

        def shell(self, args: Any, timeout: float | None = None) -> str:
            text = args if isinstance(args, str) else " ".join(args)
            if text.startswith("su -c"):
                self.launched = True
                return ""
            if "ps" in text.split():
                return "1 frida-server" if self.launched else "1 init"
            return ""

    payload = _backend_with(_StatefulDev()).ensure_frida_server("emulator-5554")
    assert payload["running"] is True


# ---------------------------------------------------------------------------
# forward: reservation cleanup on failure.
# ---------------------------------------------------------------------------
def test_forward_releases_the_reservation_when_the_call_fails() -> None:
    """A failed forward frees its tracked slot so a retry is not blocked.

    The slot is reserved before the adb call, so a failure has to give it back
    or a long-lived agent leaks slots until the cap locks it out.
    """

    class _Dev:
        def forward(self, local: str, remote: str, **kwargs: Any) -> None:
            raise RuntimeError("bind failed")

    backend = _backend_with(_Dev())
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9000", "tcp:9000")
    assert caught.value.code == "backend_error"
    assert backend._forwards == []


def test_forward_releases_the_reservation_on_a_structured_failure() -> None:
    """A structured adb failure frees the slot the same way a raw one does."""

    class _Dev:
        def forward(self, local: str, remote: str, **kwargs: Any) -> None:
            raise AdbError("timeout", "adb timed out")

    backend = _backend_with(_Dev())
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9000", "tcp:9000")
    assert caught.value.code == "timeout"
    assert backend._forwards == []


def test_forward_keeps_a_preexisting_reservation_on_failure() -> None:
    """A retry of an already-tracked forward must not drop the original slot.

    The slot is only freed by the caller that reserved it; a second attempt on a
    key already present did not reserve, so a failure leaves the first
    reservation intact rather than releasing a slot it does not own.
    """

    class _Dev:
        def forward(self, local: str, remote: str, **kwargs: Any) -> None:
            raise RuntimeError("bind failed")

    backend = _backend_with(_Dev())
    key = ("emulator-5554", "tcp:9000")
    backend._forwards.append(key)
    with pytest.raises(AdbError):
        backend.forward("emulator-5554", "tcp:9000", "tcp:9000")
    assert backend._forwards == [key]


def test_forward_leaves_a_preexisting_reservation_on_a_structured_failure() -> None:
    """A structured failure on a retry also leaves the original slot untouched."""

    class _Dev:
        def forward(self, local: str, remote: str, **kwargs: Any) -> None:
            raise AdbError("timeout", "adb timed out")

    backend = _backend_with(_Dev())
    key = ("emulator-5554", "tcp:9000")
    backend._forwards.append(key)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9000", "tcp:9000")
    assert caught.value.code == "timeout"
    assert backend._forwards == [key]


# ---------------------------------------------------------------------------
# _device_info_row / _pm_path: read-out shapes exercised outside the happy path.
# ---------------------------------------------------------------------------
def test_device_info_row_reads_object_and_tuple_shapes() -> None:
    """A device row comes from attributes, else a positional tuple.

    adbutils' list() has returned both an object with serial/state and a bare
    tuple across versions; a one-tuple names only the serial and leaves the
    state unknown rather than borrowing a neighbour's value.
    """

    class _Info:
        serial = "emulator-5554"
        state = "device"

    assert _device_info_row(_Info()) == {"serial": "emulator-5554", "state": "device"}
    assert _device_info_row(("abc", "offline")) == {"serial": "abc", "state": "offline"}
    assert _device_info_row(("abc",)) == {"serial": "abc", "state": "unknown"}


def test_pm_path_reads_the_package_line() -> None:
    dev = _ScriptedDev({("pm", "path"): "package:/data/app/base.apk"})
    assert _pm_path(dev, "com.example.app") == "/data/app/base.apk"


def test_pm_path_is_none_when_no_package_line_is_present() -> None:
    dev = _ScriptedDev({("pm", "path"): "some noise\nother line"})
    assert _pm_path(dev, "com.example.app") is None


def test_pm_path_raises_on_a_host_error_reply() -> None:
    """An adb host-error line answered as stdout is a failure, not "absent".

    pm path returning only ``adb: device offline`` must raise so install /
    uninstall report "could not verify" rather than reading the missing
    package: line as a definitive not-installed.
    """
    dev = _ScriptedDev({("pm", "path"): "adb: device offline"})
    with pytest.raises(AdbError) as caught:
        _pm_path(dev, "com.example.app")
    assert caught.value.code == "backend_error"


def test_pids_for_package_ps_row_without_a_pid_is_skipped() -> None:
    """A ps row whose first columns hold no digit contributes no pid.

    The scan reads a pid from the first three columns; a malformed row with no
    numeric column there is skipped rather than fabricating a pid from the
    package name that also appears on the line.
    """
    rows = "aaa bbb ccc com.example.app\nu0_a1 2001 1 0 0 x 0 S com.example.app"
    dev = _ScriptedDev({("pidof",): "not found", ("ps", "-A"): rows})
    assert _pids_for_package(dev, "com.example.app") == [2001]


# ---------------------------------------------------------------------------
# _client env wiring / info unstructured failure / properties cap.
# ---------------------------------------------------------------------------
def test_client_exports_the_adb_path_to_the_environment(monkeypatch: Any) -> None:
    """A configured adb_path is published so adbutils can find and spawn adb."""
    import os

    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)

    class _Adbutils:
        @staticmethod
        def AdbClient(host: str, port: int, socket_timeout: float) -> str:
            return "client"

    backend = AdbBackend(adb_path=Path("/opt/adb"))
    backend._available = True
    backend._adbutils = _Adbutils()
    assert backend._client() == "client"
    assert os.environ["ADBUTILS_ADB_PATH"] == "/opt/adb"


def test_info_wraps_an_unstructured_state_failure() -> None:
    """A non-timeout error from get_state becomes a structured backend_error.

    get_state raising a plain error (not an AdbError, not a timeout) must not
    escape info() as a bare exception; it is wrapped so the caller always sees
    the structured shape.
    """

    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            raise ValueError("weird state")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "x"

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_properties_caps_at_the_requested_limit() -> None:
    dump = "[ro.a]: [1]\n[ro.b]: [2]"
    dev = _ScriptedDev({("getprop",): dump})
    payload = _backend_with(dev).properties("emulator-5554", limit=1)
    assert payload["has_more"] is True
    assert payload["count"] == 1


# ---------------------------------------------------------------------------
# Structured-failure pass-through: install / uninstall / screenshot / pull /
# push already re-raise AdbError without rewrapping it as backend_error.
# ---------------------------------------------------------------------------
def test_install_passes_through_a_structured_failure(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="com.example.app">')

    class _Dev:
        def install(self, path: str, **kwargs: Any) -> None:
            raise AdbError("timeout", "adb timed out")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "timeout"


def test_uninstall_passes_through_a_structured_failure() -> None:
    class _Dev:
        def uninstall(self, package: str, **kwargs: Any) -> None:
            raise AdbError("timeout", "adb timed out")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "timeout"


def test_launch_reports_a_foreground_match() -> None:
    """A monkey launch whose foreground equals the package reads as launched."""

    class _Current:
        package = "com.example.app"
        activity = ".Main"

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

        def app_current(self, timeout: float | None = None) -> Any:
            return _Current()

    payload = _backend_with(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_current_activity_returns_the_foreground() -> None:
    class _Current:
        package = "com.example.app"
        activity = ".Main"

    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            return _Current()

    payload = _backend_with(_Dev()).current_activity("emulator-5554")
    assert payload == {"package": "com.example.app", "activity": ".Main"}


def test_current_activity_rejects_an_empty_foreground() -> None:
    """app_current answering with no package is a failed read, not an empty one.

    dumpsys can return an object with package None; reporting that as a
    successful empty foreground let an agent treat a failed read as "nothing in
    front", so it is raised instead.
    """

    class _Current:
        package = None
        activity = None

    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            return _Current()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_passes_through_a_structured_failure() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise AdbError("timeout", "adb timed out")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "timeout"


def test_screenshot_passes_through_a_structured_failure(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, **kwargs: Any) -> Any:
            raise AdbError("timeout", "adb timed out")

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).screenshot("emulator-5554", tmp_path / "s.png")
    assert caught.value.code == "timeout"


def test_screenshot_over_the_cap_is_refused(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(adbmod, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)

    class _Image:
        def save(self, path: str) -> None:
            Path(path).write_bytes(b"x" * 64)

    class _Dev:
        def screenshot(self, **kwargs: Any) -> _Image:
            return _Image()

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).screenshot("emulator-5554", tmp_path / "s.png")
    assert caught.value.code == "too_large"


def test_pull_without_a_sync_surface_fails_cleanly(tmp_path: Path) -> None:
    """A device with no sync API is refused, not crashed with AttributeError."""
    dev = type("_D", (), {})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/f", tmp_path / "out.bin")
    assert caught.value.code == "backend_error"


def test_pull_passes_through_a_structured_failure(tmp_path: Path) -> None:
    def boom(local: str) -> None:
        raise AdbError("timeout", "adb timed out")

    dev = type("_D", (), {"sync": _Sync(stat_raises=True, pull_action=boom)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/f", tmp_path / "out.bin")
    assert caught.value.code == "timeout"


def test_pull_reports_a_missing_local_result(tmp_path: Path) -> None:
    """A clean pull that wrote nothing means the remote path was absent.

    Older adbutils does not raise when the remote path does not exist, and the
    pre-stat probe is best-effort, so a pull that leaves no local file is
    surfaced as not_found rather than a size-0 success.
    """
    dev = type("_D", (), {"sync": _Sync(stat_raises=True)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).pull("emulator-5554", "/sdcard/absent", tmp_path / "out.bin")
    assert caught.value.code == "not_found"


def test_push_wraps_a_local_stat_failure(tmp_path: Path, monkeypatch: Any) -> None:
    """A local file that passes is_file but fails stat is a structured error.

    The size cap needs the file's size; if the stat that reads it fails (a race,
    a permission flip between the is_file check and the read) the push reports a
    structured backend_error rather than letting the OSError escape.
    """
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")
    real_stat = Path.stat
    seen = {"count": 0}

    def flaky(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == local:
            seen["count"] += 1
            if seen["count"] >= 2:
                raise OSError("stat denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky)
    dev = type("_D", (), {"sync": _Sync()})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).push("emulator-5554", str(local), "/sdcard/f")
    assert caught.value.code == "backend_error"


def test_push_passes_through_a_structured_failure(tmp_path: Path) -> None:
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")

    def boom() -> None:
        raise AdbError("timeout", "adb timed out")

    dev = type("_D", (), {"sync": _Sync(push_action=boom)})()
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).push("emulator-5554", str(local), "/sdcard/f")
    assert caught.value.code == "timeout"


# ---------------------------------------------------------------------------
# ensure_frida_server: bind-host guard, push path, and the not-visible reply.
# ---------------------------------------------------------------------------
def test_ensure_frida_server_rejects_a_bad_bind_host() -> None:
    dev = _ScriptedDev({})
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).ensure_frida_server("emulator-5554", bind_host="1.2.3.4:9")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_pushes_then_confirms(tmp_path: Path) -> None:
    """A supplied binary is pushed, made executable, launched, then confirmed."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    class _Dev:
        def __init__(self) -> None:
            self.launched = False
            self.sync = _Sync()

        def shell(self, args: Any, timeout: float | None = None) -> str:
            text = args if isinstance(args, str) else " ".join(args)
            if text.startswith("su -c"):
                self.launched = True
                return ""
            if "ps" in text.split():
                return "1 frida-server" if self.launched else "1 init"
            return ""

    payload = _backend_with(_Dev()).ensure_frida_server(
        "emulator-5554", server_binary=str(binary)
    )
    assert payload["running"] is True
    assert payload["pushed"] is True


def test_ensure_frida_server_wraps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    def boom() -> None:
        raise RuntimeError("push reset")

    class _Dev:
        def __init__(self) -> None:
            self.sync = _Sync(push_action=boom)

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "1 init"

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "backend_error"


def test_ensure_frida_server_passes_through_a_structured_push_failure(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    def boom() -> None:
        raise AdbError("timeout", "adb timed out")

    class _Dev:
        def __init__(self) -> None:
            self.sync = _Sync(push_action=boom)

        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "1 init"

    with pytest.raises(AdbError) as caught:
        _backend_with(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "timeout"


def test_ensure_frida_server_reports_a_launch_that_never_appeared() -> None:
    """A launch that returns but never shows in ps is reported, not asserted up.

    The command coming back cleanly does not prove the server started, so a
    follow-up ps that still does not see it yields running=False with a note
    rather than a false running=True.
    """

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "1 init"

    payload = _backend_with(_Dev()).ensure_frida_server("emulator-5554")
    assert payload["running"] is False
    assert payload["pushed"] is False
    assert "note" in payload
