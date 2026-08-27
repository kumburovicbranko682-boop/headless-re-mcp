"""Every AdbBackend path must turn a raw adbutils failure into a structured error.

The happy paths and the argument validators are pinned by the other adb test
modules; what is exercised here is the seam that the rest of the surface trusts:
each capability wraps adbutils' broad exceptions into an ``AdbError`` with a
stable code (``timeout`` / ``not_found`` / ``backend_error`` /
``capability_unavailable``) rather than letting a bare ``RuntimeError`` escape as
an opaque ``internal_error``. A ``timeout``-named exception must map to the
retryable ``timeout`` code, an ``AdbError`` raised by an inner helper must pass
through unchanged, and the pure shims (`_apk_package_name`, `_pids_for_package`,
`_bind_open_transport`, ...) must degrade the same hostile shapes without
raising. These branches only run through the live adbutils backend, so they are
driven here with injected fakes -- no adbutils, no emulator.
"""

from __future__ import annotations

import builtins
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb
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


def _backend(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _backend_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: client  # type: ignore[method-assign]
    return backend


# --------------------------------------------------------------------------
# Signature-introspection shims: a callable whose signature cannot be read
# --------------------------------------------------------------------------


def test_accepts_timeout_is_false_when_the_signature_cannot_be_read() -> None:
    # signature(range) raises ValueError ("no signature for builtin type").
    assert _accepts_timeout(range) is False


def test_accepted_kwargs_is_empty_when_the_signature_cannot_be_read() -> None:
    assert _accepted_kwargs(range, {"timeout": 1}) == {}


def test_accepted_kwargs_keeps_only_parameters_the_callable_names() -> None:
    def target(a: int, timeout: float = 0.0) -> None:
        del a, timeout

    assert _accepted_kwargs(target, {"timeout": 5, "flags": ["-r"]}) == {"timeout": 5}


# --------------------------------------------------------------------------
# _device_shell / _call error mapping
# --------------------------------------------------------------------------


def test_device_shell_passes_an_adberror_through_unchanged() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise AdbError("invalid_params", "already structured")

    with pytest.raises(AdbError) as caught:
        _device_shell(_Dev(), "ps")
    assert caught.value.code == "invalid_params"


def test_call_passes_an_adberror_through_unchanged() -> None:
    def method() -> None:
        raise AdbError("not_found", "missing")

    with pytest.raises(AdbError) as caught:
        _call(method, timeout=5.0)
    assert caught.value.code == "not_found"


def test_call_maps_a_timeout_named_exception_to_the_timeout_code() -> None:
    def method(timeout: float | None = None) -> None:
        del timeout
        raise TimeoutError("adb read timed out")

    with pytest.raises(AdbError) as caught:
        _call(method, timeout=3.0)
    assert caught.value.code == "timeout"


def test_call_reraises_a_non_timeout_exception_untouched_without_a_deadline() -> None:
    def method() -> None:
        raise RuntimeError("some other failure")

    with pytest.raises(RuntimeError):
        _call(method, timeout=None)


# --------------------------------------------------------------------------
# _frida_server_visible: a probe that raises reads as "unknown", never True
# --------------------------------------------------------------------------


def test_frida_server_visible_returns_none_when_the_probe_raises() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise RuntimeError("device offline")

    assert _frida_server_visible(_Dev()) is None


# --------------------------------------------------------------------------
# _bind_open_transport: the deadline shim and its call-shape fallbacks
# --------------------------------------------------------------------------


def test_bind_open_transport_returns_the_device_untouched_without_the_method() -> None:
    dev = SimpleNamespace(serial="x")
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_keyword_shape_is_used_first() -> None:
    calls: list[str] = []

    class _Dev:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            del command, timeout
            calls.append("kw")
            return "kw"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "kw"
    assert calls == ["kw"]


def test_bind_open_transport_falls_back_to_positional_two_arg() -> None:
    class _Dev:
        # Only positional args: the keyword form raises TypeError, the two-arg
        # positional call succeeds.
        def open_transport(self, a: Any = None, b: Any = None) -> str:
            return "positional"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "positional"


def test_bind_open_transport_falls_back_to_command_only() -> None:
    class _Dev:
        # Accepts exactly one positional: both the keyword form and the two-arg
        # positional form raise TypeError, leaving the command-only call.
        def open_transport(self, command: Any) -> str:
            return "command-only"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "command-only"


def test_bind_open_transport_returns_the_device_when_the_attribute_is_read_only() -> None:
    class _Dev:
        @property
        def open_transport(self) -> Any:
            return lambda **kwargs: None

    dev = _Dev()
    # Assigning over the read-only property raises AttributeError; the shim must
    # swallow it and hand back the device rather than crash the whole call.
    assert _bind_open_transport(dev, 5.0) is dev


# --------------------------------------------------------------------------
# Row/shape shims for odd adbutils return types
# --------------------------------------------------------------------------


def test_device_info_row_reads_a_single_element_tuple_as_unknown_state() -> None:
    assert _device_info_row(("emulator-5554",)) == {
        "serial": "emulator-5554",
        "state": "unknown",
    }


def test_file_mode_size_reads_a_tuple_pair() -> None:
    assert _file_mode_size((stat.S_IFDIR | 0o755, 4096)) == (stat.S_IFDIR | 0o755, 4096)


# --------------------------------------------------------------------------
# _apk_package_name: hostile / binary AndroidManifest shapes
# --------------------------------------------------------------------------


def _apk_with_manifest_bytes(path: Path, raw: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", raw)


def test_apk_package_name_recovers_from_a_binary_manifest(tmp_path: Path) -> None:
    """A non-UTF-8 binary AXML still yields the id via the UTF-16 window scan.

    The leading 0xff makes the UTF-8 decode raise (exercising the swallow), and
    the UTF-16 window skips the framework ``android.*`` token before returning
    the real application id.
    """
    raw = b"\xff\xfe" + "package\x00android.intent.action\x00com.example.myapp".encode(
        "utf-16-le"
    )
    apk = tmp_path / "binary.apk"
    _apk_with_manifest_bytes(apk, raw)
    assert _apk_package_name(apk) == "com.example.myapp"


def test_apk_package_name_is_none_when_nothing_parses(tmp_path: Path) -> None:
    apk = tmp_path / "empty.apk"
    _apk_with_manifest_bytes(apk, b"\x00\x01\x02\x03")
    assert _apk_package_name(apk) is None


# --------------------------------------------------------------------------
# _pm_path: skips non-package lines; _pids_for_package hostile shapes
# --------------------------------------------------------------------------


def test_pm_path_skips_noise_before_the_package_line() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "some noise\npackage:/data/app/com.x/base.apk\n"

    assert _pm_path(_Dev(), "com.x") == "/data/app/com.x/base.apk"


class _PidsDev:
    """Routes pidof / ps by the argv the caller passes."""

    def __init__(self, *, pidof: str, ps: str | None = None, ps_raises: bool = False) -> None:
        self._pidof = pidof
        self._ps = ps or ""
        self._ps_raises = ps_raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:1] == ("pidof",):
            return self._pidof
        if self._ps_raises:
            raise AdbError("timeout", "ps timed out")
        return self._ps


def test_pids_for_package_returns_none_when_the_ps_fallback_fails() -> None:
    dev = _PidsDev(pidof="pidof: not found", ps_raises=True)
    assert _pids_for_package(dev, "com.x") is None


def test_pids_for_package_caps_the_ps_fallback_scan() -> None:
    lines = "\n".join(f"u0_a{i} {1000 + i} 2 com.x proc" for i in range(20))
    dev = _PidsDev(pidof="not found", ps=lines)
    pids = _pids_for_package(dev, "com.x")
    assert pids is not None
    assert len(pids) == 16


def test_pids_for_package_is_none_when_pidof_answers_without_a_number() -> None:
    dev = _PidsDev(pidof="weird-response-without-digits")
    assert _pids_for_package(dev, "com.x") is None


# --------------------------------------------------------------------------
# __init__ / _client availability and construction failures
# --------------------------------------------------------------------------


def test_missing_adbutils_at_import_degrades_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "adbutils":
            raise ImportError("no adbutils here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    backend = AdbBackend()
    assert backend.available is False


def test_client_reports_capability_unavailable_when_adbutils_is_absent() -> None:
    backend = AdbBackend()
    backend._available = False
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "capability_unavailable"


def test_client_sets_the_adb_path_env_and_builds_a_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()

    def adb_client(**kwargs: Any) -> Any:
        assert kwargs["host"] == "127.0.0.1"
        return sentinel

    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    backend = AdbBackend(adb_path=Path("/opt/platform-tools/adb"))
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    backend._available = True
    import os

    assert backend._client() is sentinel
    assert os.environ["ADBUTILS_ADB_PATH"] == "/opt/platform-tools/adb"


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    calls: list[dict[str, Any]] = []

    def adb_client(**kwargs: Any) -> str:
        calls.append(kwargs)
        if "socket_timeout" in kwargs:
            raise TypeError("old adbutils has no socket_timeout")
        return "client"

    backend = AdbBackend()
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    backend._available = True
    assert backend._client() == "client"
    assert len(calls) == 2


def test_client_maps_a_timeout_to_the_timeout_code() -> None:
    def adb_client(**kwargs: Any) -> None:
        raise TimeoutError("cannot reach server")

    backend = AdbBackend()
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    backend._available = True
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "timeout"


def test_client_maps_any_other_failure_to_backend_error() -> None:
    def adb_client(**kwargs: Any) -> None:
        raise RuntimeError("connection refused")

    backend = AdbBackend()
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    backend._available = True
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# _device: resolve, bind, and its failure mapping
# --------------------------------------------------------------------------


def test_device_binds_the_transport_deadline_on_success() -> None:
    dev = SimpleNamespace(serial="emulator-5554")
    client = SimpleNamespace(device=lambda serial: dev)
    backend = _backend_client(client)
    resolved = backend._device("emulator-5554")
    assert resolved is dev


def test_device_maps_a_timeout_to_the_timeout_code() -> None:
    def device(serial: str) -> None:
        raise TimeoutError("transport timed out")

    backend = _backend_client(SimpleNamespace(device=device))
    with pytest.raises(AdbError) as caught:
        backend._device("emulator-5554")
    assert caught.value.code == "timeout"


def test_device_maps_any_other_failure_to_not_found() -> None:
    def device(serial: str) -> None:
        raise RuntimeError("device 'emulator-5554' not found")

    backend = _backend_client(SimpleNamespace(device=device))
    with pytest.raises(AdbError) as caught:
        backend._device("emulator-5554")
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# list_devices / connect / info: adbutils exceptions become structured errors
# --------------------------------------------------------------------------


def _client_whose_list_raises(exc: BaseException) -> Any:
    def lister() -> list[Any]:
        raise exc

    return SimpleNamespace(list=lister)


def test_list_devices_maps_a_timeout() -> None:
    backend = _backend_client(_client_whose_list_raises(TimeoutError("stalled")))
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "timeout"


def test_list_devices_maps_any_other_failure_to_backend_error() -> None:
    backend = _backend_client(_client_whose_list_raises(RuntimeError("boom")))
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "backend_error"


def test_list_devices_passes_an_adberror_through() -> None:
    backend = _backend_client(_client_whose_list_raises(AdbError("timeout", "already mapped")))
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "timeout"


def test_connect_maps_a_failure_to_backend_error() -> None:
    def connect(endpoint: str, timeout: float | None = None) -> str:
        raise RuntimeError("cannot connect")

    backend = _backend_client(SimpleNamespace(connect=connect))
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 5555)
    assert caught.value.code == "backend_error"


def test_info_maps_a_get_state_failure_to_backend_error() -> None:
    class _Dev:
        def get_state(self) -> str:
            raise RuntimeError("adb offline")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_info_passes_an_adberror_through() -> None:
    class _Dev:
        def get_state(self) -> str:
            raise AdbError("timeout", "already mapped")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).info("emulator-5554")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# properties / packages: line filtering
# --------------------------------------------------------------------------


def test_properties_skips_lines_that_are_not_prop_records() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "this is not a prop line\n[ro.name]: [pixel]\n"

    payload = _backend(_Dev()).properties("emulator-5554")
    assert payload["properties"] == {"ro.name": "pixel"}


def test_packages_skips_noise_and_empty_names() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "junk header\npackage:\npackage:com.a\n"

    payload = _backend(_Dev()).packages("emulator-5554")
    assert payload["packages"] == ["com.a"]


# --------------------------------------------------------------------------
# install / uninstall / launch / force_stop / current_activity error envelopes
# --------------------------------------------------------------------------


def _valid_apk(path: Path, package: str = "com.example.app") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f'<manifest package="{package}"/>')
    return path


def test_install_maps_a_device_failure_to_backend_error(tmp_path: Path) -> None:
    apk = _valid_apk(tmp_path / "app.apk")

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise RuntimeError("pm install failed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_uninstall_maps_a_device_failure_to_backend_error() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise RuntimeError("pm uninstall failed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_launch_maps_a_monkey_failure_to_backend_error() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("monkey crashed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).launch("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_launch_reports_null_when_the_foreground_cannot_be_read() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

        def app_current(self) -> Any:
            raise RuntimeError("dumpsys unavailable")

    payload = _backend(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "note" in payload


def test_force_stop_maps_a_failure_to_backend_error() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("am crashed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).force_stop("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_current_activity_maps_a_failure_to_backend_error() -> None:
    class _Dev:
        def app_current(self) -> Any:
            raise RuntimeError("dumpsys crashed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_passes_an_adberror_through() -> None:
    class _Dev:
        def app_current(self) -> Any:
            raise AdbError("timeout", "already mapped")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# screenshot: success, capture-cap, and failure envelope
# --------------------------------------------------------------------------


class _Image:
    def __init__(self, nbytes: int) -> None:
        self._n = nbytes

    def save(self, path: str) -> None:
        with open(path, "wb") as handle:
            handle.truncate(self._n)


def test_screenshot_returns_the_size_on_success(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            return _Image(64)

    out = tmp_path / "shots" / "screen.png"
    payload = _backend(_Dev()).screenshot("emulator-5554", out)
    assert payload["size"] == 64
    assert out.exists()


def test_screenshot_refuses_an_image_over_the_capture_cap(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            return _Image(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "big.png")
    assert caught.value.code == "too_large"


def test_screenshot_maps_a_failure_to_backend_error(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            raise RuntimeError("screencap failed")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# pull: the stat-skip path, directory refusal, cap, and failure envelope
# --------------------------------------------------------------------------


def test_pull_maps_a_missing_sync_channel_to_backend_error(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=None)
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert caught.value.code == "backend_error"


class _StatlessSync:
    """A sync channel whose stat probe raises so pull proceeds unbounded-by-stat."""

    def __init__(self, on_pull: Any) -> None:
        self._on_pull = on_pull

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        raise RuntimeError("stat unsupported")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        self._on_pull(local)


def test_pull_succeeds_when_the_pre_stat_probe_is_unavailable(tmp_path: Path) -> None:
    sync = _StatlessSync(lambda local: Path(local).write_bytes(b"hello"))
    out = tmp_path / "out.bin"
    payload = _backend(SimpleNamespace(sync=sync)).pull("emulator-5554", "/sdcard/x", out)
    assert payload["size"] == 5


def test_pull_refuses_and_removes_a_pulled_directory(tmp_path: Path) -> None:
    sync = _StatlessSync(lambda local: Path(local).mkdir())
    out = tmp_path / "pulled_tree"
    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=sync)).pull("emulator-5554", "/sdcard/dir", out)
    assert caught.value.code == "invalid_params"
    assert not out.exists()


def test_pull_refuses_a_landed_file_over_the_cap(tmp_path: Path) -> None:
    def over_cap(local: str) -> None:
        with open(local, "wb") as handle:
            handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    sync = _StatlessSync(over_cap)
    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=sync)).pull("emulator-5554", "/sdcard/big", tmp_path / "big")
    assert caught.value.code == "too_large"


def test_pull_passes_an_adberror_from_the_transfer_through(tmp_path: Path) -> None:
    def raise_adb(local: str) -> None:
        raise AdbError("timeout", "sync timed out")

    sync = _StatlessSync(raise_adb)
    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=sync)).pull("emulator-5554", "/sdcard/x", tmp_path / "out")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# push: stat failure and transfer failure envelopes
# --------------------------------------------------------------------------


def test_push_maps_a_stat_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FakePath:
        def __init__(self, value: str) -> None:
            self._value = str(value)

        def expanduser(self) -> _FakePath:
            return self

        def is_file(self) -> bool:
            return True

        def stat(self) -> Any:
            raise OSError("stat refused")

        def __str__(self) -> str:
            return self._value

    monkeypatch.setattr(adb, "Path", _FakePath)
    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=None)).push("emulator-5554", "/local/x", "/sdcard/x")
    assert caught.value.code == "backend_error"


def test_push_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    local = tmp_path / "small.bin"
    local.write_bytes(b"hi")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("sync push failed")

    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=_Sync())).push("emulator-5554", str(local), "/sdcard/x")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# ensure_frida_server: binary resolution, push, launch note, visibility
# --------------------------------------------------------------------------


class _FridaDev:
    def __init__(
        self,
        *,
        ps_before: str = "",
        ps_after: str = "",
        push_raises: bool = False,
        push_adberror: bool = False,
        launch_raises: bool = False,
    ) -> None:
        self._ps_before = ps_before
        self._ps_after = ps_after
        self._launched = False

        class _Sync:
            def push(self, local: str, remote: str, timeout: float | None = None) -> None:
                if push_adberror:
                    raise AdbError("timeout", "push timed out")
                if push_raises:
                    raise RuntimeError("push refused")

        self.sync = _Sync()
        self._launch_raises = launch_raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        text = args if isinstance(args, str) else " ".join(args)
        if "su -c" in text:
            self._launched = True
            if self._launch_raises:
                raise RuntimeError("su blocked")
            return ""
        if text.startswith("ps"):
            return self._ps_after if self._launched else self._ps_before
        return ""


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _FridaDev(ps_before="")
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert caught.value.code == "not_found"


def test_ensure_frida_server_pushes_and_confirms_it_running(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev(ps_before="", ps_after="root 999 frida-server\n")
    payload = _backend(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert payload["running"] is True
    assert payload["pushed"] is True


def test_ensure_frida_server_maps_a_push_failure_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev(ps_before="", push_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert caught.value.code == "backend_error"


def test_ensure_frida_server_returns_a_note_when_the_launch_raises() -> None:
    dev = _FridaDev(ps_before="", launch_raises=True)
    payload = _backend(dev).ensure_frida_server("emulator-5554")
    assert "note" in payload
    assert payload["pushed"] is False


def test_ensure_frida_server_notes_when_it_cannot_confirm_the_process() -> None:
    # Launch returns cleanly but ps never shows the process.
    dev = _FridaDev(ps_before="", ps_after="")
    payload = _backend(dev).ensure_frida_server("emulator-5554")
    assert payload["running"] in (None, False)
    assert "note" in payload


# --------------------------------------------------------------------------
# forward: the reserved-slot cleanup on the two failure shapes
# --------------------------------------------------------------------------


def test_forward_releases_the_reserved_slot_on_an_adberror() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "forward timed out")

    backend = _backend(_Dev())
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "timeout"
    assert backend._forwards == []


def test_forward_failure_on_a_held_slot_keeps_the_slot() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise RuntimeError("bind refused")

    backend = _backend(_Dev())
    # Pre-hold the slot so the failing call does not own the reservation: the
    # generic-failure cleanup must leave the already-held slot in place.
    backend._forwards = [("emulator-5554", "tcp:5000")]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "backend_error"
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


def test_forward_adberror_on_a_held_slot_keeps_the_slot() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "forward timed out")

    backend = _backend(_Dev())
    backend._forwards = [("emulator-5554", "tcp:5000")]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "timeout"
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


# --------------------------------------------------------------------------
# Remaining envelope / success branches
# --------------------------------------------------------------------------


def test_device_shell_maps_a_timeout_named_exception() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise TimeoutError("shell timed out")

    with pytest.raises(AdbError) as caught:
        _device_shell(_Dev(), "ps")
    assert caught.value.code == "timeout"


def test_pids_for_package_returns_none_when_pidof_itself_fails() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("timeout", "pidof timed out")

    assert _pids_for_package(_Dev(), "com.x") is None


def test_pids_for_package_is_empty_when_pidof_answers_nothing() -> None:
    assert _pids_for_package(_PidsDev(pidof=""), "com.x") == []


def test_pids_for_package_reads_pidof_numbers_directly() -> None:
    assert _pids_for_package(_PidsDev(pidof="4321 8765"), "com.x") == [4321, 8765]


def test_pids_for_package_skips_foreign_and_digitless_ps_lines() -> None:
    lines = "\n".join(
        [
            "a line that never mentions the target",
            "u0_a1 nodigit abc com.x proc",
            "u0_a2 4242 2 com.x proc",
        ]
    )
    assert _pids_for_package(_PidsDev(pidof="not found", ps=lines), "com.x") == [4242]


def test_client_passes_an_adberror_through() -> None:
    def adb_client(**kwargs: Any) -> None:
        raise AdbError("timeout", "already mapped")

    backend = AdbBackend()
    backend._adbutils = SimpleNamespace(AdbClient=adb_client)
    backend._available = True
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "timeout"


def test_device_passes_an_adberror_through() -> None:
    def device(serial: str) -> None:
        raise AdbError("timeout", "already mapped")

    backend = _backend_client(SimpleNamespace(device=device))
    with pytest.raises(AdbError) as caught:
        backend._device("emulator-5554")
    assert caught.value.code == "timeout"


def test_connect_reports_a_successful_endpoint() -> None:
    def connect(endpoint: str, timeout: float | None = None) -> str:
        return f"connected to {endpoint}"

    payload = _backend_client(SimpleNamespace(connect=connect)).connect("127.0.0.1", 5555)
    assert payload["connected"] is True
    assert payload["endpoint"] == "127.0.0.1:5555"


def test_packages_flags_the_overflow_at_the_limit() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "package:com.a\npackage:com.b\n"

    payload = _backend(_Dev()).packages("emulator-5554", limit=1)
    assert payload["count"] == 1
    assert payload["has_more"] is True


def test_install_passes_an_adberror_through(tmp_path: Path) -> None:
    apk = _valid_apk(tmp_path / "app.apk")

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            raise AdbError("timeout", "already mapped")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).install("emulator-5554", str(apk))
    assert caught.value.code == "timeout"


def test_uninstall_passes_an_adberror_through() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "already mapped")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "timeout"


def test_launch_confirms_the_foreground_package() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

        def app_current(self) -> Any:
            return SimpleNamespace(package="com.example.app", activity=".Main")

    payload = _backend(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_force_stop_confirms_no_remaining_pids() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ""

    payload = _backend(_Dev()).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is True
    assert payload["remaining_pids"] == []


def test_force_stop_notes_when_the_process_list_cannot_be_read() -> None:
    class _Dev:
        def __init__(self) -> None:
            self._first = True

        def shell(self, args: Any, timeout: float | None = None) -> str:
            tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
            if tokens[:1] == ("pidof",):
                raise AdbError("timeout", "pidof timed out")
            if tokens[:1] == ("ps",):
                raise AdbError("timeout", "ps timed out")
            return ""

    payload = _backend(_Dev()).force_stop("emulator-5554", "com.example.app")
    assert payload["stopped"] is None
    assert "note" in payload


def test_current_activity_returns_the_foreground() -> None:
    class _Dev:
        def app_current(self) -> Any:
            return SimpleNamespace(package="com.example.app", activity=".Main")

    payload = _backend(_Dev()).current_activity("emulator-5554")
    assert payload == {"package": "com.example.app", "activity": ".Main"}


def test_current_activity_refuses_an_empty_foreground() -> None:
    class _Dev:
        def app_current(self) -> Any:
            return SimpleNamespace(package=None, activity=None)

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_logcat_trims_the_partial_leading_line_when_truncated() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return ("x" * 100 + "\n") * 3000

    payload = _backend(_Dev()).logcat("emulator-5554", lines=5000)
    assert payload["truncated"] is True
    # The oldest bytes were dropped mid-line; the kept lines are whole.
    assert all(line == "x" * 100 for line in payload["lines"])


def test_screenshot_passes_an_adberror_through(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            raise AdbError("timeout", "already mapped")

    with pytest.raises(AdbError) as caught:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "shot.png")
    assert caught.value.code == "timeout"


def test_push_passes_an_adberror_from_the_transfer_through(tmp_path: Path) -> None:
    local = tmp_path / "small.bin"
    local.write_bytes(b"hi")

    class _Sync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "sync push timed out")

    with pytest.raises(AdbError) as caught:
        _backend(SimpleNamespace(sync=_Sync())).push("emulator-5554", str(local), "/sdcard/x")
    assert caught.value.code == "timeout"


def test_ensure_frida_server_is_a_noop_when_already_running() -> None:
    dev = _FridaDev(ps_before="root 5 frida-server\n")
    payload = _backend(dev).ensure_frida_server("emulator-5554")
    assert payload == {"running": True, "pushed": False, "port": 27042}


def test_ensure_frida_server_passes_a_push_adberror_through(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    dev = _FridaDev(ps_before="", push_adberror=True)
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert caught.value.code == "timeout"
