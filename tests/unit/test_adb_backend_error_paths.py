"""AdbBackend guard, error-mapping and honesty branches.

The device read-outs, transfers and forward bookkeeping are pinned in their own
files with fake devices. What is covered here is the surface those tests do not
reach: the module-level shims that flatten adbutils' version drift, and the
per-method error contract -- every operation must turn a backend fault into a
structured ``AdbError`` with a specific code (``timeout``, ``backend_error``,
``not_found``, ``invalid_params``, ``capability_unavailable``) rather than
letting an adbutils exception escape, and every verify-and-report method must
stay honest (null, not a guessed true/false) when its follow-up probe cannot
run. All of it runs against injected fakes -- no adbutils, no emulator.
"""

from __future__ import annotations

import stat
import sys
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
    _pids_for_package,
    _pm_path,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


# --------------------------------------------------------------------------
# module-level shims
# --------------------------------------------------------------------------
def test_accepts_timeout_reads_the_signature() -> None:
    """A method taking ``timeout`` or ``**kwargs`` accepts it; a plain one does not."""

    def takes_timeout(a: int, timeout: float | None = None) -> None: ...
    def takes_kwargs(a: int, **kwargs: Any) -> None: ...
    def takes_neither(a: int) -> None: ...

    assert _accepts_timeout(takes_timeout) is True
    assert _accepts_timeout(takes_kwargs) is True
    assert _accepts_timeout(takes_neither) is False


def test_accepts_timeout_is_false_when_the_signature_is_unreadable() -> None:
    """A C builtin whose signature inspect cannot read is treated as not accepting it.

    Passing ``timeout=`` to such a call would raise TypeError from the body; the
    shim must answer False so the caller drops the kwarg instead.
    """
    assert _accepts_timeout(range) is False


def test_accepted_kwargs_filters_to_what_the_method_names() -> None:
    """Only the kwargs the method actually declares survive when it has no **kwargs."""

    def limited(self: Any, path: str, nolaunch: bool = False) -> None: ...

    kept = _accepted_kwargs(limited, {"nolaunch": True, "uninstall": False, "flags": []})
    assert kept == {"nolaunch": True}


def test_accepted_kwargs_passes_everything_through_a_var_keyword() -> None:
    def wide(self: Any, **kwargs: Any) -> None: ...

    extra = {"nolaunch": True, "flags": ["-r"]}
    assert _accepted_kwargs(wide, extra) == extra


def test_accepted_kwargs_is_empty_when_the_signature_is_unreadable() -> None:
    assert _accepted_kwargs(range, {"timeout": 1}) == {}


def test_device_shell_re_raises_an_adb_error_unchanged() -> None:
    """A shell that already failed with a structured error is not re-wrapped."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("permission_denied", "needs root")

    with pytest.raises(AdbError) as caught:
        _device_shell(_Dev(), "id")
    assert caught.value.code == "permission_denied"


def test_device_shell_maps_a_timeout_and_a_generic_failure() -> None:
    class _Timeout:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise TimeoutError("the device stalled")

    class _Broken:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("transport closed")

    with pytest.raises(AdbError) as timed:
        _device_shell(_Timeout(), "id")
    assert timed.value.code == "timeout"
    with pytest.raises(AdbError) as broke:
        _device_shell(_Broken(), "id")
    assert broke.value.code == "backend_error"


def test_call_re_raises_a_non_timeout_exception_untouched() -> None:
    """_call only maps timeouts; anything else propagates for the caller to wrap."""

    def boom() -> None:
        raise RuntimeError("some adbutils fault")

    with pytest.raises(RuntimeError):
        _call(boom, timeout=1.0)


def test_call_maps_a_timeout_when_a_deadline_was_asked_for() -> None:
    def slow() -> None:
        raise TimeoutError("timed out")

    with pytest.raises(AdbError) as caught:
        _call(slow, timeout=1.0)
    assert caught.value.code == "timeout"


def test_frida_server_visible_is_none_when_the_probe_cannot_run() -> None:
    """A ps read that throws is 'unknown', not a confident 'not running'."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("device offline")

    assert _frida_server_visible(_Dev()) is None


def test_bind_open_transport_leaves_a_device_without_the_method_alone() -> None:
    class _NoTransport:
        pass

    dev = _NoTransport()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_rebinds_and_forwards_the_deadline() -> None:
    calls: list[tuple[Any, float | None]] = []

    class _Dev:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            calls.append((command, timeout))
            return "transport"

    dev = _bind_open_transport(_Dev(), 12.5)
    assert dev.open_transport("cmd") == "transport"
    assert calls == [("cmd", 12.5)]


def test_bind_open_transport_falls_back_when_keywords_are_rejected() -> None:
    """A positional-only open_transport still gets the deadline via the fallbacks."""
    seen: list[tuple[Any, ...]] = []

    class _KwHostile:
        def open_transport(self, command: Any = None, timeout: float | None = None, /) -> str:
            seen.append((command, timeout))
            return "ok"

    dev = _bind_open_transport(_KwHostile(), 3.0)
    assert dev.open_transport("cmd") == "ok"
    assert seen == [("cmd", 3.0)]


def test_bind_open_transport_falls_back_to_a_lone_positional() -> None:
    seen: list[Any] = []

    class _OneArg:
        def open_transport(self, command: Any = None, /) -> str:
            seen.append(command)
            return "ok"

    dev = _bind_open_transport(_OneArg(), 3.0)
    assert dev.open_transport("cmd") == "ok"
    assert seen == ["cmd"]


def test_bind_open_transport_keeps_the_device_when_rebinding_is_refused() -> None:
    """A device that will not accept the attribute is returned unchanged, not crashed."""

    class _ReadOnly:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "t"

    dev = _ReadOnly()
    assert _bind_open_transport(dev, 5.0) is dev


def test_device_info_row_reads_a_tuple_pair_and_a_bare_serial() -> None:
    assert _device_info_row(("emulator-5554", "device")) == {
        "serial": "emulator-5554",
        "state": "device",
    }
    # A one-element tuple has a serial but no state, which reads as unknown.
    assert _device_info_row(("emulator-5554",)) == {
        "serial": "emulator-5554",
        "state": "unknown",
    }


def test_file_mode_size_reads_a_tuple_pair() -> None:
    mode, size = _file_mode_size((stat.S_IFREG | 0o644, 123))
    assert mode == stat.S_IFREG | 0o644
    assert size == 123


# --------------------------------------------------------------------------
# _apk_package_name binary-manifest fallback
# --------------------------------------------------------------------------
def test_apk_package_name_reads_a_binary_manifest_after_utf8_fails(tmp_path: Path) -> None:
    """A binary AXML that is not valid UTF-8 falls back to a UTF-16 window scan.

    The scan starts at the 'package' marker, skips android.* framework names,
    and returns the first real package candidate.
    """
    import zipfile

    text = "package android.permission.INTERNET com.example.app"
    # A leading U+FFFF makes the whole blob invalid UTF-8 so the fast path raises,
    # while decoding cleanly as UTF-16LE for the fallback window scan.
    manifest = b"\xff\xff" + text.encode("utf-16-le")
    apk = tmp_path / "binary.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_is_none_when_only_framework_names_appear(tmp_path: Path) -> None:
    """A manifest whose only candidates are android.* yields no package id."""
    import zipfile

    text = "package android.permission.INTERNET com.android.systemui"
    manifest = b"\xff\xff" + text.encode("utf-16-le")
    apk = tmp_path / "framework.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    assert _apk_package_name(apk) is None


# --------------------------------------------------------------------------
# _pm_path / _pids_for_package parsing branches
# --------------------------------------------------------------------------
def test_pm_path_skips_noise_before_the_package_line() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "some warning line\npackage:/data/app/base.apk"

    assert _pm_path(_Dev(), "com.example.app") == "/data/app/base.apk"


def test_pids_for_package_returns_none_when_pidof_is_pure_noise() -> None:
    """A pidof that answers text but no digits (and no missing-binary marker) is unknown."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "weird output with no numbers"

    assert _pids_for_package(_Dev(), "com.example.app") is None


def test_pids_for_package_is_none_when_the_ps_fallback_fails() -> None:
    """pidof missing plus a ps that throws leaves the pid list unknown, not empty."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
            if tokens[:1] == ("pidof",):
                return "pidof: not found"
            raise AdbError("timeout", "ps stalled")

    assert _pids_for_package(_Dev(), "com.example.app") is None


def test_pids_for_package_caps_the_ps_fallback_at_sixteen() -> None:
    """The ps-table fallback stops after 16 matching rows rather than scanning forever."""
    rows = "\n".join(f"u0_a{i} {1000 + i} 1 0 0 S com.example.app" for i in range(20))

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
            if tokens[:1] == ("pidof",):
                return "pidof: not found"
            return rows

    pids = _pids_for_package(_Dev(), "com.example.app")
    assert pids is not None
    assert len(pids) == 16


# --------------------------------------------------------------------------
# helpers for backend-level tests
# --------------------------------------------------------------------------
def _backend_with_device(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _backend_with_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: client  # type: ignore[method-assign]
    return backend


# --------------------------------------------------------------------------
# __init__ / _client / _device
# --------------------------------------------------------------------------
def test_missing_adbutils_degrades_to_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checkout without adbutils is usable-but-degraded, not a crashing import."""
    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    assert backend.available is False


def test_client_refuses_when_adbutils_is_unavailable() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_sets_the_adb_path_env_and_builds_a_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A configured adb path is exported so adbutils can find and spawn the server."""
    built: list[dict[str, Any]] = []

    class _FakeAdbutils:
        def AdbClient(self, **kwargs: Any) -> str:
            built.append(kwargs)
            return "client"

    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    backend = AdbBackend(adb_path=tmp_path / "adb")
    backend._available = True
    backend._adbutils = _FakeAdbutils()
    import os

    assert backend._client() == "client"
    assert os.environ["ADBUTILS_ADB_PATH"] == str(tmp_path / "adb")
    assert built and built[0]["host"] == "127.0.0.1"


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    """An older AdbClient without socket_timeout is retried without the kwarg."""

    class _OldAdbutils:
        def AdbClient(self, **kwargs: Any) -> str:
            if "socket_timeout" in kwargs:
                raise TypeError("unexpected keyword argument 'socket_timeout'")
            return "old-client"

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _OldAdbutils()
    assert backend._client() == "old-client"


def test_client_re_raises_a_structured_error() -> None:
    class _StructuredFault:
        def AdbClient(self, **kwargs: Any) -> str:
            raise AdbError("capability_unavailable", "no adb")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _StructuredFault()
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_maps_an_unreachable_server_and_a_timeout() -> None:
    class _Unreachable:
        def AdbClient(self, **kwargs: Any) -> str:
            raise RuntimeError("connection refused")

    class _Slow:
        def AdbClient(self, **kwargs: Any) -> str:
            raise TimeoutError("timed out")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = _Unreachable()
    with pytest.raises(AdbError) as unreachable:
        backend._client()
    assert unreachable.value.code == "backend_error"

    backend._adbutils = _Slow()
    with pytest.raises(AdbError) as slow:
        backend._client()
    assert slow.value.code == "timeout"


def test_device_maps_a_missing_device_and_a_timeout() -> None:
    class _NotFoundClient:
        def device(self, serial: str) -> Any:
            raise RuntimeError("device not connected")

    class _TimeoutClient:
        def device(self, serial: str) -> Any:
            raise TimeoutError("transport timed out")

    backend = _backend_with_client(_NotFoundClient())
    with pytest.raises(AdbError) as missing:
        backend._device("emulator-5554")
    assert missing.value.code == "not_found"

    backend = _backend_with_client(_TimeoutClient())
    with pytest.raises(AdbError) as slow:
        backend._device("emulator-5554")
    assert slow.value.code == "timeout"


def test_device_re_raises_a_structured_error() -> None:
    class _Client:
        def device(self, serial: str) -> Any:
            raise AdbError("invalid_params", "bad serial")

    with pytest.raises(AdbError) as caught:
        _backend_with_client(_Client())._device("emulator-5554")
    assert caught.value.code == "invalid_params"


def test_device_returns_a_bound_transport_on_success() -> None:
    class _Dev:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            return "t"

    dev = _Dev()

    class _Client:
        def device(self, serial: str) -> Any:
            return dev

    backend = _backend_with_client(_Client())
    assert backend._device("emulator-5554") is dev


# --------------------------------------------------------------------------
# list_devices / connect error contracts
# --------------------------------------------------------------------------
def test_list_devices_maps_a_backend_failure_and_a_timeout() -> None:
    class _Broken:
        def list(self) -> list[Any]:
            raise RuntimeError("adb server died")

    class _Slow:
        def list(self) -> list[Any]:
            raise TimeoutError("timed out")

    with pytest.raises(AdbError) as broke:
        _backend_with_client(_Broken()).list_devices()
    assert broke.value.code == "backend_error"

    with pytest.raises(AdbError) as slow:
        _backend_with_client(_Slow()).list_devices()
    assert slow.value.code == "timeout"


def test_list_devices_re_raises_a_structured_error() -> None:
    class _Client:
        def list(self) -> list[Any]:
            raise AdbError("capability_unavailable", "no adb")

    with pytest.raises(AdbError) as caught:
        _backend_with_client(_Client()).list_devices()
    assert caught.value.code == "capability_unavailable"


def test_connect_rejects_a_port_out_of_range() -> None:
    class _Client:
        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            return "connected"

    backend = _backend_with_client(_Client())
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 70000)
    assert caught.value.code == "invalid_params"


def test_connect_reports_the_endpoint_and_success_flag() -> None:
    class _Client:
        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            return f"connected to {endpoint}"

    payload = _backend_with_client(_Client()).connect("127.0.0.1", 5555)
    assert payload["endpoint"] == "127.0.0.1:5555"
    assert payload["connected"] is True


def test_connect_maps_a_backend_failure() -> None:
    class _Client:
        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            raise RuntimeError("no route to host")

    with pytest.raises(AdbError) as caught:
        _backend_with_client(_Client()).connect("10.0.0.9", 5555)
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# info / properties / packages honesty
# --------------------------------------------------------------------------
class _ScriptedDev:
    def __init__(
        self,
        responses: dict[tuple[str, ...], str],
        *,
        raise_for: tuple[tuple[str, ...], ...] = (),
        state: str = "device",
    ) -> None:
        self._responses = responses
        self._raise_for = set(raise_for)
        self._state = state
        self.calls: list[Any] = []

    def get_state(self, timeout: float | None = None) -> str:
        return self._state

    def shell(self, args: Any, timeout: float | None = None) -> str:
        self.calls.append(args)
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens in self._raise_for:
            raise RuntimeError("device stalled")
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def test_info_reports_the_getprop_read_out() -> None:
    dev = _ScriptedDev(
        {
            ("getprop", "ro.product.model"): "Pixel",
            ("getprop", "ro.build.version.sdk"): "34",
        }
    )
    payload = _backend_with_device(dev).info("emulator-5554")
    assert payload["state"] == "device"
    assert payload["model"] == "Pixel"
    assert payload["sdk"] == "34"


def test_info_maps_a_shell_failure_to_backend_error() -> None:
    dev = _ScriptedDev({}, raise_for=(("getprop", "ro.product.model"),))
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_info_maps_a_get_state_failure_to_backend_error() -> None:
    """A non-structured fault from get_state is wrapped, not leaked."""

    class _Dev(_ScriptedDev):
        def get_state(self, timeout: float | None = None) -> str:
            raise RuntimeError("transport closed")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev({})).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_properties_pages_and_skips_unparseable_lines() -> None:
    dump = "not a property line\n[ro.a]: [1]\n[ro.b]: [2]\n[ro.c]: [3]"
    dev = _ScriptedDev({("getprop",): dump})
    payload = _backend_with_device(dev).properties("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_properties_returns_a_complete_read_within_the_cap() -> None:
    dump = "[ro.a]: [1]\n[ro.b]: [2]"
    dev = _ScriptedDev({("getprop",): dump})
    payload = _backend_with_device(dev).properties("emulator-5554", limit=500)
    assert payload["has_more"] is False
    assert payload["properties"] == {"ro.a": "1", "ro.b": "2"}


def test_properties_rejects_a_host_error_dump() -> None:
    dev = _ScriptedDev({("getprop",): "error: device offline"})
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).properties("emulator-5554")
    assert caught.value.code == "backend_error"


def test_packages_skips_noise_and_empty_names() -> None:
    listing = "junk line\npackage:\npackage:com.a\npackage:com.b"
    dev = _ScriptedDev({("pm", "list", "packages"): listing})
    payload = _backend_with_device(dev).packages("emulator-5554")
    assert payload["packages"] == ["com.a", "com.b"]


def test_packages_rejects_a_host_error_dump() -> None:
    dev = _ScriptedDev({("pm", "list", "packages"): "adb: device offline"})
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).packages("emulator-5554")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# install / uninstall / force_stop error mapping
# --------------------------------------------------------------------------
def test_install_maps_a_transfer_failure(tmp_path: Path) -> None:
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="com.example.app"/>')

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_install_re_raises_a_structured_transfer_error(tmp_path: Path) -> None:
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b'<manifest package="com.example.app"/>')

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise AdbError("timeout", "install stalled")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "timeout"


def test_uninstall_maps_a_backend_failure() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError("DELETE_FAILED_INTERNAL_ERROR")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_uninstall_re_raises_a_structured_error() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "uninstall stalled")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "timeout"


def test_force_stop_maps_a_shell_failure() -> None:
    dev = _ScriptedDev({}, raise_for=(("am", "force-stop", "com.example.app"),))
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).force_stop("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# launch honesty
# --------------------------------------------------------------------------
class _Foreground:
    def __init__(self, package: str | None, activity: str | None = ".Main") -> None:
        self.package = package
        self.activity = activity


def test_launch_confirms_a_foreground_package() -> None:
    class _Dev(_ScriptedDev):
        def app_current(self, timeout: float | None = None) -> Any:
            return _Foreground("com.example.app")

    dev = _Dev({})
    payload = _backend_with_device(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_launch_maps_a_monkey_failure() -> None:
    dev = _ScriptedDev(
        {}, raise_for=(("monkey", "-p", "com.example.app", "-c",
                        "android.intent.category.LAUNCHER", "1"),)
    )
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).launch("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_launch_is_null_when_the_foreground_cannot_be_read() -> None:
    """monkey running is not proof the app is up; an unreadable foreground is null."""

    class _Dev(_ScriptedDev):
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys failed")

    dev = _Dev({})
    payload = _backend_with_device(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "note" in payload


# --------------------------------------------------------------------------
# current_activity honesty
# --------------------------------------------------------------------------
def test_current_activity_returns_the_foreground() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            return _Foreground("com.example.app", ".MainActivity")

    payload = _backend_with_device(_Dev()).current_activity("emulator-5554")
    assert payload == {"package": "com.example.app", "activity": ".MainActivity"}


def test_current_activity_re_raises_a_structured_error() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise AdbError("permission_denied", "blocked")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "permission_denied"


def test_current_activity_maps_a_generic_failure() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys stalled")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_refuses_an_empty_foreground() -> None:
    """app_current answering None must not read as an empty-but-successful foreground."""

    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            return _Foreground(None, None)

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# screenshot cap and failure
# --------------------------------------------------------------------------
class _Image:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def save(self, path: str) -> None:
        Path(path).write_bytes(self._payload)


def test_screenshot_writes_and_reports_the_size(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            return _Image(b"PNGDATA")

    out = tmp_path / "shot.png"
    payload = _backend_with_device(_Dev()).screenshot("emulator-5554", out)
    assert payload["size"] == len(b"PNGDATA")
    assert out.read_bytes() == b"PNGDATA"


def test_screenshot_refuses_a_capture_over_the_cap(tmp_path: Path) -> None:
    class _SparseImage:
        def save(self, path: str) -> None:
            with open(path, "wb") as handle:
                handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _SparseImage:
            return _SparseImage()

    out = tmp_path / "big.png"
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).screenshot("emulator-5554", out)
    assert caught.value.code == "too_large"


def test_screenshot_maps_a_capture_failure(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            raise RuntimeError("screencap failed")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).screenshot("emulator-5554", tmp_path / "x.png")
    assert caught.value.code == "backend_error"


def test_screenshot_re_raises_a_structured_error(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            raise AdbError("timeout", "screencap stalled")

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).screenshot("emulator-5554", tmp_path / "x.png")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# pull branches
# --------------------------------------------------------------------------
class _PullSync:
    def __init__(self, *, stat_raises: bool = False, on_pull: Any = None) -> None:
        self._stat_raises = stat_raises
        self._on_pull = on_pull

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        if self._stat_raises:
            raise RuntimeError("stat unsupported")
        raise RuntimeError("stat unsupported")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        if self._on_pull is not None:
            self._on_pull(local)


class _PullDev:
    def __init__(self, sync: _PullSync) -> None:
        self.sync = sync


def test_pull_proceeds_when_the_stat_probe_is_unavailable(tmp_path: Path) -> None:
    """An older sync that cannot stat still pulls; the size is read from the file."""
    sync = _PullSync(stat_raises=True, on_pull=lambda local: Path(local).write_bytes(b"data"))
    local = tmp_path / "ok.bin"
    payload = _backend_with_device(_PullDev(sync)).pull("emulator-5554", "/sdcard/ok.bin", local)
    assert payload["size"] == 4


def test_pull_maps_a_transfer_failure(tmp_path: Path) -> None:
    def _raise(local: str) -> None:
        raise RuntimeError("remote read error")

    sync = _PullSync(on_pull=_raise)
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_PullDev(sync)).pull(
            "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
        )
    assert caught.value.code == "backend_error"


def test_pull_refuses_when_the_transfer_left_a_directory(tmp_path: Path) -> None:
    """adb sync writing a tree where a file was asked for is refused and cleaned up."""

    def _make_dir(local: str) -> None:
        Path(local).mkdir()

    sync = _PullSync(on_pull=_make_dir)
    local = tmp_path / "pulled"
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_PullDev(sync)).pull("emulator-5554", "/sdcard/dir", local)
    assert caught.value.code == "invalid_params"
    assert not local.exists()


def test_pull_refuses_a_pulled_file_over_the_cap(tmp_path: Path) -> None:
    def _make_big(local: str) -> None:
        with open(local, "wb") as handle:
            handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    sync = _PullSync(on_pull=_make_big)
    local = tmp_path / "big.bin"
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_PullDev(sync)).pull("emulator-5554", "/sdcard/big.bin", local)
    assert caught.value.code == "too_large"


def test_pull_maps_a_device_without_a_sync_channel(tmp_path: Path) -> None:
    """A device exposing no sync API fails as backend_error, not an AttributeError."""

    class _NoSync:
        pass

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_NoSync()).pull(
            "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
        )
    assert caught.value.code == "backend_error"


def test_pull_re_raises_a_structured_transfer_error(tmp_path: Path) -> None:
    def _raise(local: str) -> None:
        raise AdbError("timeout", "pull stalled")

    sync = _PullSync(on_pull=_raise)
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_PullDev(sync)).pull(
            "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
        )
    assert caught.value.code == "timeout"


def test_pull_reports_not_found_when_nothing_was_written(tmp_path: Path) -> None:
    """adb sync can report a clean pull yet write nothing; that is not an empty file."""
    sync = _PullSync(on_pull=lambda local: None)
    local = tmp_path / "ghost.bin"
    with pytest.raises(AdbError) as caught:
        _backend_with_device(_PullDev(sync)).pull("emulator-5554", "/sdcard/ghost.bin", local)
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# push failure
# --------------------------------------------------------------------------
def test_push_maps_a_transfer_failure(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"hello")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("no space left on device")

    class _Dev:
        def __init__(self) -> None:
            self.sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).push("emulator-5554", str(small), "/sdcard/small.bin")
    assert caught.value.code == "backend_error"


def test_push_re_raises_a_structured_error(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"hi")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "push stalled")

    class _Dev:
        def __init__(self) -> None:
            self.sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).push("emulator-5554", str(small), "/sdcard/small.bin")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# ensure_frida_server
# --------------------------------------------------------------------------
def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    dev = _ScriptedDev({})
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).ensure_frida_server("emulator-5554", remote_path="not-absolute")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_rejects_a_bad_bind_host() -> None:
    dev = _ScriptedDev({})
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).ensure_frida_server("emulator-5554", bind_host="bad host!")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_is_a_noop_when_already_running() -> None:
    dev = _ScriptedDev({("ps", "-A"): "root 1 frida-server"})
    payload = _backend_with_device(dev).ensure_frida_server("emulator-5554")
    assert payload["running"] is True
    assert payload["pushed"] is False


def test_ensure_frida_server_maps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("read-only filesystem")

    class _Dev(_ScriptedDev):
        def __init__(self) -> None:
            super().__init__({("ps", "-A"): ""})
            self.sync = _Sync()

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "backend_error"


def test_ensure_frida_server_re_raises_a_structured_push_error(tmp_path: Path) -> None:
    """A chmod that fails as a structured error after the push is not re-wrapped."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            return None

    class _Dev(_ScriptedDev):
        def __init__(self) -> None:
            super().__init__({("ps", "-A"): ""})
            self.sync = _Sync()

        def shell(self, args: Any, timeout: float | None = None) -> str:
            tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
            if tokens[:1] == ("chmod",):
                raise AdbError("permission_denied", "chmod refused")
            return ""

    with pytest.raises(AdbError) as caught:
        _backend_with_device(_Dev()).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert caught.value.code == "permission_denied"


def test_ensure_frida_server_confirms_a_launch_that_became_visible() -> None:
    """When ps shows frida-server after the su launch, running is a measured True."""

    class _Dev(_ScriptedDev):
        def __init__(self) -> None:
            super().__init__({})
            self._launched = False

        def shell(self, args: Any, timeout: float | None = None) -> str:
            text = args if isinstance(args, str) else " ".join(args)
            if text.startswith("su -c"):
                self._launched = True
                return ""
            if text.startswith("ps"):
                return "root 1 frida-server" if self._launched else ""
            return ""

    payload = _backend_with_device(_Dev()).ensure_frida_server("emulator-5554")
    assert payload["running"] is True
    assert payload["pushed"] is False


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _ScriptedDev({("ps", "-A"): ""})
    with pytest.raises(AdbError) as caught:
        _backend_with_device(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "missing")
        )
    assert caught.value.code == "not_found"


def test_ensure_frida_server_pushes_then_reports_unverified(tmp_path: Path) -> None:
    """A push that lands but leaves frida-server invisible in ps is reported, not faked."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    pushed: list[tuple[str, str]] = []

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            pushed.append((local, remote))

    class _Dev(_ScriptedDev):
        def __init__(self) -> None:
            super().__init__({("ps", "-A"): "", ("ps",): ""})
            self.sync = _Sync()

    payload = _backend_with_device(_Dev()).ensure_frida_server(
        "emulator-5554", server_binary=str(binary)
    )
    assert payload["pushed"] is True
    assert payload["running"] is False
    assert "note" in payload
    assert pushed


def test_ensure_frida_server_notes_a_launch_that_stalled() -> None:
    """A su launch that times out often means it started; the reply says verify manually."""

    class _Dev(_ScriptedDev):
        def shell(self, args: Any, timeout: float | None = None) -> str:
            text = args if isinstance(args, str) else " ".join(args)
            if text.startswith("su -c"):
                raise RuntimeError("su prompt timed out")
            return ""

    payload = _backend_with_device(_Dev({})).ensure_frida_server("emulator-5554")
    assert "note" in payload
    assert payload["pushed"] is False


# --------------------------------------------------------------------------
# forward error contract
# --------------------------------------------------------------------------
def test_forward_releases_the_slot_on_a_structured_error() -> None:
    """An AdbError from the bind must not leave the reserved slot behind."""

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("permission_denied", "cannot bind")

    backend = _backend_with_device(_Dev())
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "permission_denied"
    assert backend._forwards == []


def test_forward_failure_on_a_held_slot_leaves_it_in_place() -> None:
    """A generic failure re-forwarding a held key does not drop the existing slot."""

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("adb refused")

    backend = _backend_with_device(_Dev())
    backend._forwards = [("emulator-5554", "tcp:5000")]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "backend_error"
    # The slot was already held (not reserved by this call), so it stays.
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


def test_forward_structured_error_on_a_held_slot_leaves_it_in_place() -> None:
    """An AdbError re-forwarding a held key keeps the slot it did not reserve."""

    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("permission_denied", "cannot bind")

    backend = _backend_with_device(_Dev())
    backend._forwards = [("emulator-5554", "tcp:5000")]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "permission_denied"
    assert backend._forwards == [("emulator-5554", "tcp:5000")]
