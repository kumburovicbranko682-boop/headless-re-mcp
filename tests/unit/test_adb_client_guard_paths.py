"""AdbBackend guard paths that live off the happy read-out routes.

The device read-outs, transfers, and forward bookkeeping are pinned elsewhere;
this file drives the edges those tests do not reach -- the module-level shims
that let one code path serve several adbutils vintages (``_accepts_timeout``,
``_accepted_kwargs``, ``_bind_open_transport``), the signal-shaping helpers
(``_apk_package_name``, ``_pm_path``, ``_pids_for_package``, ``_file_mode_size``,
``_device_info_row``), the ``_client`` / ``_device`` construction that reaches
the adb server, and every method's error contract: the ``except AdbError:
raise`` passthroughs, the timeout mapping, and the tri-state notes a caller
reads when a follow-up probe could not run. adbutils is not installed, so each
path runs against an injected fake exactly where the real logic lives.
"""

from __future__ import annotations

import stat
import sys
import types
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
    _device_info_row,
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _pids_for_package,
    _pm_path,
)


class _RaisingTimeout(Exception):
    """A timeout-flavoured error adbutils raises without deriving TimeoutError."""


def _backend_with(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# --------------------------------------------------------------------------
# _accepts_timeout / _accepted_kwargs
# --------------------------------------------------------------------------


def test_accepts_timeout_is_false_when_the_signature_cannot_be_read() -> None:
    """A target whose signature ``inspect`` refuses reads as "no timeout".

    ``signature`` raises ``TypeError`` for a non-callable; the shim must treat
    that as "cannot pass timeout" rather than propagating the error into the
    call site that only wanted to know whether the kwarg is safe.
    """
    assert _accepts_timeout(123) is False


def test_accepted_kwargs_is_empty_when_the_signature_cannot_be_read() -> None:
    """A signature that cannot be introspected yields no forwarded kwargs."""
    assert _accepted_kwargs(123, {"timeout": 1}) == {}


def test_accepted_kwargs_keeps_only_named_parameters() -> None:
    """Without ``**kwargs`` the shim forwards only the keys the func declares."""

    def target(alpha: int, beta: int) -> None:  # pragma: no cover - shape only
        del alpha, beta

    assert _accepted_kwargs(target, {"alpha": 1, "gamma": 2}) == {"alpha": 1}


# --------------------------------------------------------------------------
# _device_shell / _call
# --------------------------------------------------------------------------


def test_device_shell_passes_an_adberror_through_untouched() -> None:
    """An AdbError from the underlying shell is re-raised, not re-wrapped."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise AdbError("invalid_params", "already structured")

    with pytest.raises(AdbError) as excinfo:
        _device_shell(_Dev(), "getprop")
    assert excinfo.value.code == "invalid_params"


def test_call_passes_an_adberror_through_untouched() -> None:
    """An AdbError raised inside the invoked method is re-raised verbatim."""

    def method() -> None:
        raise AdbError("permission_denied", "already structured")

    with pytest.raises(AdbError) as excinfo:
        _call(method, timeout=5.0)
    assert excinfo.value.code == "permission_denied"


def test_call_maps_a_timeout_error_when_a_deadline_was_requested() -> None:
    """A timeout-named failure with a deadline becomes an AdbError timeout."""

    def method() -> None:
        raise _RaisingTimeout("timed out waiting for device")

    with pytest.raises(AdbError) as excinfo:
        _call(method, timeout=8.0)
    assert excinfo.value.code == "timeout"


def test_call_reraises_a_non_timeout_error_unwrapped() -> None:
    """A plain failure propagates as itself so an outer handler can shape it."""

    def method() -> None:
        raise RuntimeError("adb server said no")

    with pytest.raises(RuntimeError):
        _call(method, timeout=8.0)


# --------------------------------------------------------------------------
# _frida_server_visible
# --------------------------------------------------------------------------


def test_frida_server_visible_returns_none_when_the_probe_fails() -> None:
    """A shell that fails leaves visibility unknown (None), not a false False.

    Reporting False for a device whose process list could not be read would let
    ensure_frida_server push and relaunch a server that is in fact already
    running; the tri-state must stay None so the caller knows the probe failed.
    """

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise RuntimeError("device offline")

    assert _frida_server_visible(_Dev()) is None


# --------------------------------------------------------------------------
# _bind_open_transport
# --------------------------------------------------------------------------


def test_bind_open_transport_returns_the_device_without_a_transport_hook() -> None:
    """A device with no ``open_transport`` is returned untouched."""
    dev = SimpleNamespace()
    assert _bind_open_transport(dev, 30.0) is dev


def test_bind_open_transport_falls_back_through_older_call_shapes() -> None:
    """The wrapper degrades keyword -> positional-2 -> positional-1 on TypeError.

    Older adbutils' ``open_transport`` does not accept the keyword form, and
    older still drops the timeout argument entirely; the installed wrapper must
    keep trying narrower signatures rather than surfacing the TypeError.
    """
    seen: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def original(*args: Any, **kwargs: Any) -> str:
        seen.append((args, kwargs))
        if kwargs or len(args) == 2:
            raise TypeError("unsupported signature")
        return "connected"

    dev = SimpleNamespace(open_transport=original)
    bound = _bind_open_transport(dev, 30.0)
    assert bound.open_transport() == "connected"
    # keyword form, then positional-2, then the bare positional-1 that succeeds.
    assert len(seen) == 3


def test_bind_open_transport_first_call_shape_succeeds() -> None:
    """When the modern keyword form works the wrapper returns it directly."""
    calls: list[dict[str, Any]] = []

    def original(command: Any = None, timeout: float | None = None) -> str:
        calls.append({"command": command, "timeout": timeout})
        return "ok"

    dev = SimpleNamespace(open_transport=original)
    bound = _bind_open_transport(dev, 42.0)
    assert bound.open_transport() == "ok"
    assert calls == [{"command": None, "timeout": 42.0}]


def test_bind_open_transport_returns_device_when_the_hook_cannot_be_set() -> None:
    """A read-only ``open_transport`` attribute is left as-is, not forced."""

    class _ReadOnly:
        @property
        def open_transport(self) -> Any:
            return lambda *a, **k: None

    dev = _ReadOnly()
    assert _bind_open_transport(dev, 30.0) is dev


# --------------------------------------------------------------------------
# _device_info_row / _file_mode_size
# --------------------------------------------------------------------------


def test_device_info_row_reads_a_single_element_tuple() -> None:
    """A one-item ``(serial,)`` row keeps the serial and defaults the state."""
    assert _device_info_row(("emulator-5554",)) == {
        "serial": "emulator-5554",
        "state": "unknown",
    }


def test_file_mode_size_reads_a_tuple_stat_row() -> None:
    """A ``(mode, size)`` tuple stat is read positionally."""
    mode, size = _file_mode_size((stat.S_IFREG | 0o644, 4096))
    assert mode == stat.S_IFREG | 0o644
    assert size == 4096


# --------------------------------------------------------------------------
# _apk_package_name
# --------------------------------------------------------------------------


def test_apk_package_name_reads_a_binary_manifest_via_utf16(tmp_path: Path) -> None:
    """A binary AXML manifest yields the package id through the utf-16 scan.

    A real AndroidManifest.xml stores strings as UTF-16LE, so the utf-8 attempt
    both fails to decode (a non-ASCII byte makes it invalid) and finds no
    ``package="..."`` literal; the fallback walks the utf-16 text, skips the
    framework ``android.*`` names, and returns the first real package token.
    """
    manifest = "package \u00e9 android.support com.example.app".encode("utf-16-le")
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_is_none_when_no_token_is_a_real_package(tmp_path: Path) -> None:
    """A manifest with only framework names yields no id rather than a guess."""
    manifest = "android.foo com.android.bar".encode("utf-16-le")
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    assert _apk_package_name(apk) is None


# --------------------------------------------------------------------------
# _pm_path
# --------------------------------------------------------------------------


def test_pm_path_skips_noise_before_the_package_line() -> None:
    """A leading non-``package:`` line is stepped over, not misread."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "junk banner line\npackage:/data/app/com.example/base.apk"

    assert _pm_path(_Dev(), "com.example.app") == "/data/app/com.example/base.apk"


def test_pm_path_is_none_when_no_package_line_is_present() -> None:
    """Output without a ``package:`` line reads as "not installed" (None)."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "some unrelated output"

    assert _pm_path(_Dev(), "com.example.app") is None


# --------------------------------------------------------------------------
# _pids_for_package
# --------------------------------------------------------------------------


def _pidof_dev(pidof: str, ps: str | None = None, *, ps_raises: bool = False) -> Any:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del timeout
            tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
            if tokens[:1] == ("pidof",):
                return pidof
            if tokens[:1] == ("ps",):
                if ps_raises:
                    raise AdbError("timeout", "ps stalled")
                return ps or ""
            return ""

    return _Dev()


def test_pids_for_package_returns_none_when_the_ps_fallback_fails() -> None:
    """A missing-pidof device whose ps fallback errors reports unknown (None)."""
    dev = _pidof_dev("/system/bin/sh: pidof: not found", ps_raises=True)
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_skips_rows_without_a_numeric_column() -> None:
    """A matching ps row with no numeric field in its first columns is skipped."""
    ps = "USER NAME STATE com.example.app\n"
    dev = _pidof_dev("pidof: not found", ps=ps)
    assert _pids_for_package(dev, "com.example.app") == []


def test_pids_for_package_caps_the_ps_scan_at_sixteen_rows() -> None:
    """The ps fallback stops collecting after sixteen matching processes."""
    rows = "\n".join(f"u0_a12 {1000 + i} 1 com.example.app" for i in range(20))
    dev = _pidof_dev("pidof: not found", ps=rows)
    pids = _pids_for_package(dev, "com.example.app")
    assert pids is not None
    assert len(pids) == 16


def test_pids_for_package_is_none_when_pidof_output_has_no_digits() -> None:
    """A pidof reply that is neither empty, a miss, nor numeric is unknown."""
    dev = _pidof_dev("weird non-numeric reply")
    assert _pids_for_package(dev, "com.example.app") is None


# --------------------------------------------------------------------------
# __init__ / _client / _device
# --------------------------------------------------------------------------


def test_init_marks_available_when_adbutils_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present adbutils module flips the backend to available at construction."""
    fake = types.ModuleType("adbutils")
    monkeypatch.setitem(sys.modules, "adbutils", fake)
    backend = AdbBackend()
    assert backend.available is True
    assert backend._adbutils is fake


class _FakeAdbClient:
    def __init__(self, host: str, port: int, socket_timeout: float | None = None) -> None:
        if socket_timeout is not None:
            # Model an older adbutils AdbClient that lacks socket_timeout.
            raise TypeError("unexpected keyword argument 'socket_timeout'")
        self.host = host
        self.port = port


def _backend_with_adbutils(adbclient: Any, *, adb_path: Path | None = None) -> AdbBackend:
    backend = AdbBackend(adb_path=adb_path)
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=adbclient)
    return backend


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    """An AdbClient without ``socket_timeout`` is retried without the kwarg."""
    backend = _backend_with_adbutils(_FakeAdbClient)
    client = backend._client()
    assert isinstance(client, _FakeAdbClient)
    assert client.host == "127.0.0.1"


def test_client_sets_the_adb_path_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A configured adb path is exported for adbutils to find the executable."""
    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\n", encoding="utf-8")
    backend = _backend_with_adbutils(_FakeAdbClient, adb_path=adb)
    backend._client()
    import os

    assert os.environ["ADBUTILS_ADB_PATH"] == str(adb)


def test_client_maps_a_timeout_reaching_the_server() -> None:
    """A timeout constructing the client is reported as an AdbError timeout."""

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise _RaisingTimeout("adb server handshake timed out")

    backend = _backend_with_adbutils(_Client)
    with pytest.raises(AdbError) as excinfo:
        backend._client()
    assert excinfo.value.code == "timeout"


def test_client_maps_a_generic_failure_to_backend_error() -> None:
    """A non-timeout failure reaching adb is a backend_error, not a crash."""

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("connection refused")

    backend = _backend_with_adbutils(_Client)
    with pytest.raises(AdbError) as excinfo:
        backend._client()
    assert excinfo.value.code == "backend_error"


def test_client_passes_an_adberror_through() -> None:
    """An AdbError raised while constructing the client is re-raised verbatim."""

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise AdbError("capability_unavailable", "already structured")

    backend = _backend_with_adbutils(_Client)
    with pytest.raises(AdbError) as excinfo:
        backend._client()
    assert excinfo.value.code == "capability_unavailable"


def test_device_binds_the_transport_ceiling_on_success() -> None:
    """A resolved device is returned with its transport deadline installed."""
    dev = SimpleNamespace(open_transport=lambda command=None, timeout=None: "ok")
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda socket_timeout=0.0: SimpleNamespace(  # type: ignore[method-assign, misc]
        device=lambda serial: dev
    )
    resolved = backend._device("emulator-5554")
    assert resolved is dev


def test_device_maps_a_lookup_timeout() -> None:
    """A timeout resolving the device is an AdbError timeout."""

    def device(serial: str) -> Any:
        raise _RaisingTimeout("device lookup timed out")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda socket_timeout=0.0: SimpleNamespace(device=device)  # type: ignore[method-assign, misc]
    with pytest.raises(AdbError) as excinfo:
        backend._device("emulator-5554")
    assert excinfo.value.code == "timeout"


def test_device_maps_a_generic_lookup_failure_to_not_found() -> None:
    """A non-timeout lookup failure reports the device as not found."""

    def device(serial: str) -> Any:
        raise RuntimeError("no such device")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda socket_timeout=0.0: SimpleNamespace(device=device)  # type: ignore[method-assign, misc]
    with pytest.raises(AdbError) as excinfo:
        backend._device("emulator-5554")
    assert excinfo.value.code == "not_found"


def test_device_passes_an_adberror_through() -> None:
    """An AdbError from the device lookup is re-raised, not re-mapped."""

    def device(serial: str) -> Any:
        raise AdbError("invalid_params", "already structured")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda socket_timeout=0.0: SimpleNamespace(device=device)  # type: ignore[method-assign, misc]
    with pytest.raises(AdbError) as excinfo:
        backend._device("emulator-5554")
    assert excinfo.value.code == "invalid_params"


# --------------------------------------------------------------------------
# list_devices / connect
# --------------------------------------------------------------------------


def _backend_with_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda socket_timeout=0.0: client  # type: ignore[method-assign, misc]
    return backend


def test_list_devices_passes_an_adberror_through() -> None:
    """An AdbError from the lister is re-raised, not wrapped as backend_error."""

    def lister() -> Any:
        raise AdbError("permission_denied", "adb unauthorized")

    backend = _backend_with_client(SimpleNamespace(list=lister))
    with pytest.raises(AdbError) as excinfo:
        backend.list_devices()
    assert excinfo.value.code == "permission_denied"


def test_list_devices_maps_a_timeout() -> None:
    """A timeout listing devices becomes an AdbError timeout."""

    def lister() -> Any:
        raise _RaisingTimeout("list timed out")

    backend = _backend_with_client(SimpleNamespace(list=lister))
    with pytest.raises(AdbError) as excinfo:
        backend.list_devices()
    assert excinfo.value.code == "timeout"


def test_list_devices_maps_a_generic_failure() -> None:
    """A non-timeout listing failure is reported as backend_error."""

    def lister() -> Any:
        raise RuntimeError("adb server died")

    backend = _backend_with_client(SimpleNamespace(list=lister))
    with pytest.raises(AdbError) as excinfo:
        backend.list_devices()
    assert excinfo.value.code == "backend_error"


def test_connect_rejects_a_port_out_of_range() -> None:
    """A port outside 1..65535 is refused before any endpoint is built."""
    backend = _backend_with_client(SimpleNamespace(connect=lambda *a, **k: "ok"))
    with pytest.raises(AdbError) as excinfo:
        backend.connect(port=99999)
    assert excinfo.value.code == "invalid_params"


def test_connect_maps_a_failure_to_backend_error() -> None:
    """A connect that raises surfaces as backend_error with the endpoint."""

    def connect(endpoint: str, timeout: float | None = None) -> str:
        raise RuntimeError("no route to host")

    backend = _backend_with_client(SimpleNamespace(connect=connect))
    with pytest.raises(AdbError) as excinfo:
        backend.connect(host="10.0.0.5", port=5555)
    assert excinfo.value.code == "backend_error"
    assert excinfo.value.details["endpoint"] == "10.0.0.5:5555"


# --------------------------------------------------------------------------
# info / properties / packages
# --------------------------------------------------------------------------


def test_info_passes_an_adberror_through() -> None:
    """An AdbError from ``get_state`` is re-raised, not re-wrapped."""

    def get_state(timeout: float | None = None) -> str:
        raise AdbError("timeout", "get_state stalled")

    dev = SimpleNamespace(get_state=get_state, shell=lambda *a, **k: "")
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).info("emulator-5554")
    assert excinfo.value.code == "timeout"


def test_info_maps_a_generic_read_failure() -> None:
    """A non-AdbError failure reading device info becomes backend_error."""

    def get_state(timeout: float | None = None) -> str:
        raise RuntimeError("state read failed")

    dev = SimpleNamespace(get_state=get_state, shell=lambda *a, **k: "")
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).info("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_properties_skips_lines_that_do_not_match_the_pattern() -> None:
    """A non ``[key]: [value]`` line is stepped over, not counted."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "not a getprop line\n[ro.build]: [123]"

    payload = _backend_with(_Dev()).properties("emulator-5554")
    assert payload["properties"] == {"ro.build": "123"}
    assert payload["count"] == 1


def test_packages_skips_non_package_lines_and_empty_names() -> None:
    """A banner line and an empty ``package:`` name are both filtered out."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "List of packages:\npackage:\npackage:com.example.app"

    payload = _backend_with(_Dev()).packages("emulator-5554")
    assert payload["packages"] == ["com.example.app"]
    assert payload["count"] == 1


# --------------------------------------------------------------------------
# install / uninstall error contracts
# --------------------------------------------------------------------------


def _apk(path: Path, package: str = "com.example.app") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f'<manifest package="{package}"/>')
    return path


def test_install_passes_an_adberror_through(tmp_path: Path) -> None:
    """An AdbError from ``dev.install`` is re-raised unchanged."""

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise AdbError("timeout", "install stalled")

    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).install("emulator-5554", str(_apk(tmp_path / "a.apk")))
    assert excinfo.value.code == "timeout"


def test_install_maps_a_generic_failure(tmp_path: Path) -> None:
    """A non-AdbError install failure becomes backend_error with the path."""

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE")

    apk = _apk(tmp_path / "a.apk")
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).install("emulator-5554", str(apk))
    assert excinfo.value.code == "backend_error"
    assert excinfo.value.details["path"] == str(apk)


def test_install_notes_when_pm_path_reports_the_package_missing(tmp_path: Path) -> None:
    """A clean install whose pm path shows nothing is installed False with a note."""

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            del path, timeout, kwargs

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

    payload = _backend_with(_Dev()).install("emulator-5554", str(_apk(tmp_path / "a.apk")))
    assert payload["installed"] is False
    assert "not visible" in payload["note"]


def test_uninstall_passes_an_adberror_through() -> None:
    """An AdbError from ``dev.uninstall`` is re-raised unchanged."""

    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise AdbError("permission_denied", "not allowed")

    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert excinfo.value.code == "permission_denied"


def test_uninstall_maps_a_generic_failure() -> None:
    """A non-AdbError uninstall failure becomes backend_error with the package."""

    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError("DELETE_FAILED_INTERNAL_ERROR")

    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert excinfo.value.code == "backend_error"


# --------------------------------------------------------------------------
# launch / force_stop / current_activity
# --------------------------------------------------------------------------


def test_launch_passes_an_adberror_through() -> None:
    """An AdbError from the monkey shell is re-raised unchanged."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("timeout", "monkey stalled")

    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).launch("emulator-5554", "com.example.app")
    assert excinfo.value.code == "timeout"


def test_launch_maps_a_generic_shell_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-AdbError escaping the shell shim is shaped into backend_error."""

    def boom(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("adb transport broke mid-shell")

    monkeypatch.setattr(adb_client, "_device_shell", boom)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(SimpleNamespace()).launch("emulator-5554", "com.example.app")
    assert excinfo.value.code == "backend_error"


def test_launch_notes_when_the_foreground_cannot_be_read() -> None:
    """monkey running but app_current failing leaves launched null with a note."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

        def app_current(self, timeout: float | None = None) -> Any:
            raise RuntimeError("dumpsys unavailable")

    payload = _backend_with(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "could not read foreground" in payload["note"]


def test_force_stop_passes_an_adberror_through() -> None:
    """An AdbError from the force-stop shell is re-raised unchanged."""

    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("timeout", "force-stop stalled")

    with pytest.raises(AdbError) as excinfo:
        _backend_with(_Dev()).force_stop("emulator-5554", "com.example.app")
    assert excinfo.value.code == "timeout"


def test_force_stop_maps_a_generic_shell_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-AdbError escaping the shell shim is shaped into backend_error."""

    def boom(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("adb transport broke mid-shell")

    monkeypatch.setattr(adb_client, "_device_shell", boom)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(SimpleNamespace()).force_stop("emulator-5554", "com.example.app")
    assert excinfo.value.code == "backend_error"


def test_current_activity_passes_an_adberror_through() -> None:
    """An AdbError from ``app_current`` is re-raised unchanged."""

    def app_current(timeout: float | None = None) -> Any:
        raise AdbError("timeout", "app_current stalled")

    dev = SimpleNamespace(app_current=app_current)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).current_activity("emulator-5554")
    assert excinfo.value.code == "timeout"


def test_current_activity_maps_a_generic_failure() -> None:
    """A non-AdbError failure reading the activity becomes backend_error."""

    def app_current(timeout: float | None = None) -> Any:
        raise RuntimeError("dumpsys broke")

    dev = SimpleNamespace(app_current=app_current)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).current_activity("emulator-5554")
    assert excinfo.value.code == "backend_error"


# --------------------------------------------------------------------------
# screenshot
# --------------------------------------------------------------------------


class _Image:
    def __init__(self, payload: bytes = b"PNGDATA") -> None:
        self._payload = payload

    def save(self, path: str) -> None:
        Path(path).write_bytes(self._payload)


def test_screenshot_passes_an_adberror_through(tmp_path: Path) -> None:
    """An AdbError capturing the screen is re-raised unchanged."""

    def screenshot(timeout: float | None = None) -> Any:
        raise AdbError("timeout", "screencap stalled")

    dev = SimpleNamespace(screenshot=screenshot)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).screenshot("emulator-5554", tmp_path / "shot.png")
    assert excinfo.value.code == "timeout"


def test_screenshot_maps_a_generic_failure(tmp_path: Path) -> None:
    """A non-AdbError capture failure becomes backend_error."""

    def screenshot(timeout: float | None = None) -> Any:
        raise RuntimeError("no framebuffer")

    dev = SimpleNamespace(screenshot=screenshot)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).screenshot("emulator-5554", tmp_path / "shot.png")
    assert excinfo.value.code == "backend_error"


def test_screenshot_returns_the_saved_size(tmp_path: Path) -> None:
    """A captured image within the cap reports its on-disk byte size."""
    dev = SimpleNamespace(screenshot=lambda timeout=None: _Image(b"PNGDATA"))
    out = tmp_path / "nested" / "shot.png"
    payload = _backend_with(dev).screenshot("emulator-5554", out)
    assert payload["size"] == len(b"PNGDATA")
    assert payload["path"] == str(out)
    assert out.read_bytes() == b"PNGDATA"


# --------------------------------------------------------------------------
# pull
# --------------------------------------------------------------------------


class _PullSync:
    def __init__(self, *, pull: Any = None, stat_result: Any = None) -> None:
        self._pull = pull
        self._stat = stat_result

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        if isinstance(self._stat, BaseException):
            raise self._stat
        return self._stat

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del timeout
        if self._pull is not None:
            self._pull(remote, local)


def test_pull_reports_backend_error_when_there_is_no_sync_channel(tmp_path: Path) -> None:
    """A device with no ``sync`` cannot pull, surfacing as backend_error.

    The pre-stat size guard is skipped when there is no sync channel, and the
    transfer itself then has nothing to call, so the operation fails cleanly
    rather than reporting a phantom success.
    """
    dev = SimpleNamespace(sync=None)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert excinfo.value.code == "backend_error"


def test_pull_continues_when_the_pre_stat_probe_fails(tmp_path: Path) -> None:
    """A stat that raises leaves the size unknown but does not abort the pull."""
    sync = _PullSync(
        stat_result=RuntimeError("stat unsupported"),
        pull=lambda remote, local: Path(local).write_bytes(b"payload"),
    )
    dev = SimpleNamespace(sync=sync)
    out = tmp_path / "out.bin"
    payload = _backend_with(dev).pull("emulator-5554", "/sdcard/x", out)
    assert payload["size"] == len(b"payload")


def test_pull_passes_an_adberror_from_the_transfer_through(tmp_path: Path) -> None:
    """An AdbError raised by the transfer is re-raised unchanged."""

    def raise_adb(remote: str, local: str) -> None:
        raise AdbError("permission_denied", "cannot read remote")

    sync = _PullSync(stat_result=None, pull=raise_adb)
    dev = SimpleNamespace(sync=sync)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert excinfo.value.code == "permission_denied"


def test_pull_refuses_and_removes_a_directory_written_by_the_transfer(
    tmp_path: Path,
) -> None:
    """A transfer that writes a directory is refused and the tree is removed.

    Older adbutils can materialise a directory when the remote turns out to be
    one after the best-effort stat; keeping it would smuggle a tree past the
    single-file capture budget, so it is deleted and reported invalid_params.
    """

    def make_dir(remote: str, local: str) -> None:
        Path(local).mkdir(parents=True, exist_ok=True)

    sync = _PullSync(stat_result=None, pull=make_dir)
    dev = SimpleNamespace(sync=sync)
    out = tmp_path / "pulled"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/dir", out)
    assert excinfo.value.code == "invalid_params"
    assert not out.exists()


def test_pull_refuses_a_file_that_exceeds_the_cap_after_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pulled file measured over the cap is rejected as too_large."""

    def write_small(remote: str, local: str) -> None:
        Path(local).write_bytes(b"data")

    sync = _PullSync(stat_result=None, pull=write_small)
    dev = SimpleNamespace(sync=sync)
    monkeypatch.setattr(
        adb_client,
        "capped_file_size",
        lambda path, cap: (cap + 1, True),
    )
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/big.bin", tmp_path / "out.bin")
    assert excinfo.value.code == "too_large"


# --------------------------------------------------------------------------
# push
# --------------------------------------------------------------------------


def test_push_reports_a_stat_failure_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local file whose stat raises after the is_file check is backend_error."""
    local = tmp_path / "src.bin"
    local.write_bytes(b"payload")

    def raising_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "stat", raising_stat)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(SimpleNamespace()).push("emulator-5554", str(local), "/sdcard/x")
    assert excinfo.value.code == "backend_error"


def test_push_passes_an_adberror_from_the_transfer_through(tmp_path: Path) -> None:
    """An AdbError from the push transfer is re-raised unchanged."""
    local = tmp_path / "src.bin"
    local.write_bytes(b"payload")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("permission_denied", "read-only remote")

    dev = SimpleNamespace(sync=_Sync())
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(local), "/sdcard/x")
    assert excinfo.value.code == "permission_denied"


def test_push_maps_a_generic_transfer_failure(tmp_path: Path) -> None:
    """A non-AdbError push failure becomes backend_error with the remote path."""
    local = tmp_path / "src.bin"
    local.write_bytes(b"payload")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("no space left on device")

    dev = SimpleNamespace(sync=_Sync())
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(local), "/sdcard/x")
    assert excinfo.value.code == "backend_error"
    assert excinfo.value.details["remote"] == "/sdcard/x"


# --------------------------------------------------------------------------
# ensure_frida_server
# --------------------------------------------------------------------------


class _FridaDev:
    """A device whose ps output flips to show frida-server once it is launched."""

    def __init__(self, *, launch_raises: bool = False, push_error: Exception | None = None) -> None:
        self.launched = False
        self.pushed = False
        self.chmodded = False
        self._launch_raises = launch_raises
        self._push_error = push_error
        self.sync = self

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        if self._push_error is not None:
            raise self._push_error
        self.pushed = True

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        text = " ".join(args) if isinstance(args, list) else str(args)
        if text.startswith("su -c"):
            if self._launch_raises:
                raise RuntimeError("su prompt hung")
            self.launched = True
            return ""
        if "chmod" in text:
            self.chmodded = True
            return ""
        if text.startswith("ps"):
            return "1234 frida-server\n" if self.launched else ""
        return ""


def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    """A remote_path that is not an absolute clean path is refused."""
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_FridaDev()).ensure_frida_server("emulator-5554", remote_path="not-absolute")
    assert excinfo.value.code == "invalid_params"


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    """A server_binary path that is not a file is refused before any push."""
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_FridaDev()).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "nope")
        )
    assert excinfo.value.code == "not_found"


def test_ensure_frida_server_pushes_and_confirms_it_is_running(tmp_path: Path) -> None:
    """A pushed binary that launches and appears in ps reports running/pushed."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev()
    payload = _backend_with(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert payload == {"running": True, "pushed": True, "port": 27042}
    assert dev.pushed is True
    assert dev.chmodded is True


def test_ensure_frida_server_passes_an_adberror_from_the_push_through(tmp_path: Path) -> None:
    """An AdbError while pushing the binary is re-raised unchanged."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev(push_error=AdbError("permission_denied", "read-only tmp"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert excinfo.value.code == "permission_denied"


def test_ensure_frida_server_maps_a_generic_push_failure(tmp_path: Path) -> None:
    """A non-AdbError push failure becomes backend_error."""
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev(push_error=RuntimeError("adb transfer broke"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert excinfo.value.code == "backend_error"


def test_ensure_frida_server_notes_when_the_launch_shell_fails() -> None:
    """A launch that raises returns a manual-verify note, not an exception.

    A su launch that times out often means frida-server did start (the shell
    just did not return), so the reply carries the post-launch visibility probe
    and a note rather than failing the whole call.
    """
    payload = _backend_with(_FridaDev(launch_raises=True)).ensure_frida_server("emulator-5554")
    assert payload["pushed"] is False
    assert "verify manually" in payload["note"]


# --------------------------------------------------------------------------
# forward error/cleanup paths
# --------------------------------------------------------------------------


def test_forward_releases_the_slot_when_the_call_raises_adberror() -> None:
    """An AdbError from forward frees the reserved slot before re-raising."""

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        raise AdbError("timeout", "forward stalled")

    dev = SimpleNamespace(forward=forward)
    backend = _backend_with(dev)
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "timeout"
    assert backend._forwards == []


def test_forward_leaves_an_unreserved_slot_alone_on_adberror() -> None:
    """An AdbError retrying an already-tracked forward leaves its slot intact."""

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        raise AdbError("timeout", "forward stalled")

    dev = SimpleNamespace(forward=forward)
    backend = _backend_with(dev)
    backend._forwards.append(("emulator-5554", "tcp:5000"))
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "timeout"
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


def test_forward_tolerates_the_slot_vanishing_on_adberror() -> None:
    """A concurrent release removing the slot mid-AdbError is handled cleanly."""
    backend = _backend_with(SimpleNamespace())

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        backend._forwards.clear()
        raise AdbError("timeout", "forward stalled")

    backend._device = lambda serial: SimpleNamespace(forward=forward)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "timeout"
    assert backend._forwards == []


def test_forward_frees_the_slot_and_wraps_a_generic_failure() -> None:
    """A generic forward failure frees the reserved slot and maps to backend_error."""

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        raise RuntimeError("bind refused")

    dev = SimpleNamespace(forward=forward)
    backend = _backend_with(dev)
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "backend_error"
    assert backend._forwards == []


def test_forward_does_not_touch_a_slot_it_did_not_reserve() -> None:
    """A retry of an already-tracked forward that fails leaves the slot intact."""

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        raise RuntimeError("bind refused")

    dev = SimpleNamespace(forward=forward)
    backend = _backend_with(dev)
    backend._forwards.append(("emulator-5554", "tcp:5000"))
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "backend_error"
    # The pre-existing reservation is left in place, not removed by the retry.
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


def test_forward_tolerates_the_slot_vanishing_during_a_failure() -> None:
    """A concurrent release removing the slot mid-failure is handled, not crashed.

    The failure cleanup guards the removal with a membership check so a slot the
    reservation created but a parallel release_forwards already dropped does not
    raise a second error while the first is being reported.
    """
    backend = _backend_with(SimpleNamespace())

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        backend._forwards.clear()
        raise RuntimeError("bind refused")

    backend._device = lambda serial: SimpleNamespace(forward=forward)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as excinfo:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert excinfo.value.code == "backend_error"
    assert backend._forwards == []


# --------------------------------------------------------------------------
# release_forwards
# --------------------------------------------------------------------------


def test_release_forwards_deduplicates_when_retrying_a_failed_pair() -> None:
    """Two tracked copies of the same failing forward re-queue only once.

    A device with no forward-remove API cannot drop the forward, so each held
    pair is re-queued for the next close_all; duplicate held entries must not
    accumulate two copies of the same pair on retry.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: SimpleNamespace()  # type: ignore[method-assign]
    backend._forwards = [
        ("emulator-5554", "tcp:5000"),
        ("emulator-5554", "tcp:5000"),
    ]
    result = backend.release_forwards()
    assert result["count"] == 0
    assert len(result["failed"]) == 2
    # Both failures name the same pair, but it is re-queued exactly once.
    assert backend._forwards == [("emulator-5554", "tcp:5000")]
