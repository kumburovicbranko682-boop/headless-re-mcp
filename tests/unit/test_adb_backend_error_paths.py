"""AdbBackend module helpers and method guard/error/honesty branches.

The existing adb tests pin the happy shapes of list/forward/transfer/readout.
What is covered here is the machinery and the honest failures around them:

* the pure helpers -- serial/package/forward validation, the timeout/kwargs
  signature probes, the host-error detector, the APK package-name sniffer, the
  pid parser, and the open_transport rebinder;
* the capability/timeout mapping in ``_client`` / ``_device``;
* the per-method error contract -- a backend fault becomes a structured
  ``AdbError`` (backend_error / timeout / not_found / too_large /
  invalid_params / invalid_state), and an unverifiable probe answers with a
  labelled ``None`` rather than a false success.

adbutils is never imported; a fake module and fake device objects drive every
path, so the CI quality job (no ``android`` extra) sees identical behaviour.
"""

from __future__ import annotations

import stat
import types
import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.adb.client as adb
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


# --------------------------------------------------------------------------
# validation helpers
# --------------------------------------------------------------------------
def test_check_serial_and_package_accept_and_refuse() -> None:
    assert adb._check_serial(" emulator-5554 ") == "emulator-5554"
    assert adb._check_serial("127.0.0.1:5555") == "127.0.0.1:5555"
    with pytest.raises(AdbError) as bad:
        adb._check_serial("bad serial!")
    assert bad.value.code == "invalid_params"

    assert adb._check_package(" com.example.app ") == "com.example.app"
    with pytest.raises(AdbError):
        adb._check_package("nodots")


def test_require_apk_zip_refuses_a_non_zip(tmp_path: Path) -> None:
    plain = tmp_path / "not.apk"
    plain.write_bytes(b"this is not a zip")
    with pytest.raises(AdbError) as caught:
        adb._require_apk_zip(plain)
    assert caught.value.code == "invalid_params"

    real = tmp_path / "real.apk"
    with zipfile.ZipFile(real, "w") as zf:
        zf.writestr("AndroidManifest.xml", "x")
    adb._require_apk_zip(real)  # does not raise


def test_check_forward_spec_ranges_and_shapes() -> None:
    adb._check_forward_spec("tcp:5555", side="local")
    adb._check_forward_spec("localabstract:foo", side="local")
    adb._check_forward_spec("jdwp:123", side="remote", allow_jdwp=True)
    with pytest.raises(AdbError):
        adb._check_forward_spec("tcp:70000", side="local")
    with pytest.raises(AdbError):
        adb._check_forward_spec("tcp:0", side="remote")
    with pytest.raises(AdbError):
        adb._check_forward_spec("weird", side="local")


def test_is_timeout_and_signature_probes() -> None:
    assert adb._is_timeout(TimeoutError("x")) is True
    assert adb._is_timeout(RuntimeError("op timed out")) is True
    assert adb._is_timeout(RuntimeError("nope")) is False

    def named(a: int, timeout: float = 1.0) -> None: ...
    def kwargs(a: int, **rest: Any) -> None: ...
    def neither(a: int) -> None: ...

    assert adb._accepts_timeout(named) is True
    assert adb._accepts_timeout(kwargs) is True  # **kwargs is accepted too
    assert adb._accepts_timeout(neither) is False
    assert adb._accepts_timeout(range) is False  # unreadable C signature


def test_accepted_kwargs_filters_or_passes_through() -> None:
    def specific(a: int, nolaunch: bool = False) -> None: ...
    def var(a: int, **rest: Any) -> None: ...

    assert adb._accepted_kwargs(specific, {"nolaunch": True, "flags": []}) == {"nolaunch": True}
    assert adb._accepted_kwargs(var, {"nolaunch": True, "flags": []}) == {
        "nolaunch": True,
        "flags": [],
    }
    assert adb._accepted_kwargs(range, {"nolaunch": True}) == {}


def test_is_host_error_output_reads_only_error_lines_as_failure() -> None:
    assert adb._is_host_error_output("error: device offline") is True
    assert adb._is_host_error_output("adb: no devices") is True
    assert adb._is_host_error_output("") is False
    # A real result line beside an error line is still a result.
    assert adb._is_host_error_output("package:com.x\nerror: warn") is False


# --------------------------------------------------------------------------
# _device_shell / _call deadline mapping
# --------------------------------------------------------------------------
class _Shell:
    def __init__(self, responder: Any) -> None:
        self._responder = responder

    def __call__(self, args: Any, timeout: float | None = None) -> Any:
        return self._responder(args)


def test_device_shell_maps_timeout_and_generic_and_reraises_adberror() -> None:
    def _boom_timeout(args: Any) -> str:
        raise RuntimeError("read timed out")

    dev = type("D", (), {"shell": _Shell(_boom_timeout)})()
    with pytest.raises(AdbError) as timed:
        adb._device_shell(dev, "getprop")
    assert timed.value.code == "timeout"

    def _boom(args: Any) -> str:
        raise RuntimeError("broken pipe")

    dev = type("D", (), {"shell": _Shell(_boom)})()
    with pytest.raises(AdbError) as generic:
        adb._device_shell(dev, "getprop")
    assert generic.value.code == "backend_error"

    def _reraise(args: Any) -> str:
        raise AdbError("invalid_state", "already mapped")

    dev = type("D", (), {"shell": _Shell(_reraise)})()
    with pytest.raises(AdbError) as passed:
        adb._device_shell(dev, "getprop")
    assert passed.value.code == "invalid_state"


def test_call_maps_timeout_and_reraises_other_errors() -> None:
    def timed(*, timeout: float | None = None) -> None:
        raise RuntimeError("connection timed out")

    with pytest.raises(AdbError) as caught:
        adb._call(timed, timeout=5.0)
    assert caught.value.code == "timeout"

    def other() -> None:
        raise ValueError("not a timeout")

    # No timeout passed and not a timeout error -> the original propagates.
    with pytest.raises(ValueError):
        adb._call(other)


def test_frida_server_visible_is_none_on_probe_failure() -> None:
    def _boom(args: Any) -> str:
        raise RuntimeError("device offline")

    dev = type("D", (), {"shell": _Shell(_boom)})()
    assert adb._frida_server_visible(dev) is None

    dev = type("D", (), {"shell": _Shell(lambda args: "root 123 frida-server")})()
    assert adb._frida_server_visible(dev) is True


# --------------------------------------------------------------------------
# _bind_open_transport
# --------------------------------------------------------------------------
def test_bind_open_transport_leaves_a_non_callable_alone() -> None:
    dev = type("D", (), {"open_transport": None})()
    assert adb._bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_rebinds_with_a_default_timeout() -> None:
    seen: dict[str, Any] = {}

    class _Dev:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            seen["command"] = command
            seen["timeout"] = timeout
            return "transport"

    dev = _Dev()
    bound = adb._bind_open_transport(dev, 42.0)
    assert bound is dev
    assert dev.open_transport() == "transport"
    assert seen["timeout"] == 42.0


def test_bind_open_transport_tolerates_a_read_only_attribute() -> None:
    class _Dev:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "x"

    dev = _Dev()
    # Assigning to the property raises; the helper swallows it and returns dev.
    assert adb._bind_open_transport(dev, 5.0) is dev


# --------------------------------------------------------------------------
# row/mode/size parsers
# --------------------------------------------------------------------------
def test_device_info_row_reads_objects_and_tuples() -> None:
    obj = type("I", (), {"serial": "emulator-5554", "state": "device"})()
    assert adb._device_info_row(obj) == {"serial": "emulator-5554", "state": "device"}
    assert adb._device_info_row(("serial-only",)) == {"serial": "serial-only", "state": "unknown"}
    assert adb._device_info_row(("s", "offline")) == {"serial": "s", "state": "offline"}


def test_file_mode_size_reads_objects_and_tuples() -> None:
    obj = type("F", (), {"mode": 0o100644, "size": 10})()
    assert adb._file_mode_size(obj) == (0o100644, 10)
    assert adb._file_mode_size((0o40755, 4096)) == (0o40755, 4096)


# --------------------------------------------------------------------------
# _apk_package_name
# --------------------------------------------------------------------------
def test_apk_package_name_reads_utf8_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", 'package="com.example.app" x')
    assert adb._apk_package_name(apk) == "com.example.app"


def test_apk_package_name_is_none_for_a_non_zip(tmp_path: Path) -> None:
    junk = tmp_path / "x.apk"
    junk.write_bytes(b"not a zip")
    assert adb._apk_package_name(junk) is None


def test_apk_package_name_scans_binary_and_skips_framework_ids(tmp_path: Path) -> None:
    apk = tmp_path / "bin.apk"
    # A binary AXML stores its strings UTF-16LE with no package="..." attribute,
    # so it falls through to the UTF-16 text scan, which skips android.* /
    # com.android.* framework identifiers.
    blob = "package\x00android.app.Activity\x00com.vendor.realapp".encode("utf-16-le")
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", blob)
    assert adb._apk_package_name(apk) == "com.vendor.realapp"


# --------------------------------------------------------------------------
# _pm_path / _pids_for_package
# --------------------------------------------------------------------------
def test_pm_path_reads_a_package_line_and_raises_on_host_error() -> None:
    dev = type("D", (), {"shell": _Shell(lambda args: "package:/data/app/base.apk")})()
    assert adb._pm_path(dev, "com.x") == "/data/app/base.apk"

    dev = type("D", (), {"shell": _Shell(lambda args: "")})()
    assert adb._pm_path(dev, "com.x") is None

    dev = type("D", (), {"shell": _Shell(lambda args: "error: device offline")})()
    with pytest.raises(AdbError) as caught:
        adb._pm_path(dev, "com.x")
    assert caught.value.code == "backend_error"


def test_pids_for_package_direct_ps_fallback_and_empty() -> None:
    dev = type("D", (), {"shell": _Shell(lambda args: "123 456")})()
    assert adb._pids_for_package(dev, "com.x") == [123, 456]

    dev = type("D", (), {"shell": _Shell(lambda args: "")})()
    assert adb._pids_for_package(dev, "com.x") == []

    # pidof says "not found" -> fall back to a ps -A scan for the package.
    def _responder(args: Any) -> str:
        if isinstance(args, list) and args and args[0] == "pidof":
            return "pidof: not found"
        return "u0_a1 555 999 com.x\n"

    dev = type("D", (), {"shell": _Shell(_responder)})()
    assert adb._pids_for_package(dev, "com.x") == [555]


def test_pids_for_package_is_none_when_the_probe_cannot_run() -> None:
    def _boom(args: Any) -> str:
        raise AdbError("timeout", "adb timed out")

    dev = type("D", (), {"shell": _Shell(_boom)})()
    assert adb._pids_for_package(dev, "com.x") is None


# --------------------------------------------------------------------------
# backend construction + _client / _device
# --------------------------------------------------------------------------
def test_backend_without_adbutils_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    assert backend.available is False
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


class _FakeClient:
    def __init__(self, *, device: Any = None, connect_result: str = "connected") -> None:
        self._device = device
        self._connect_result = connect_result

    def device(self, serial: str) -> Any:
        return self._device

    def connect(self, endpoint: str, timeout: float = 10.0) -> str:
        return self._connect_result


def _available_backend() -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = object()
    return backend


def test_client_falls_back_when_socket_timeout_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _Adbutils:
        def AdbClient(self, **kwargs: Any) -> str:
            calls.append(kwargs)
            if "socket_timeout" in kwargs:
                raise TypeError("no socket_timeout")
            return "client"

    backend = _available_backend()
    backend._adbutils = _Adbutils()
    assert backend._client() == "client"
    assert len(calls) == 2 and "socket_timeout" not in calls[-1]


def test_client_maps_server_errors_and_timeouts() -> None:
    class _TimeoutAdbutils:
        def AdbClient(self, **kwargs: Any) -> str:
            raise RuntimeError("server connect timed out")

    backend = _available_backend()
    backend._adbutils = _TimeoutAdbutils()
    with pytest.raises(AdbError) as timed:
        backend._client()
    assert timed.value.code == "timeout"

    class _BoomAdbutils:
        def AdbClient(self, **kwargs: Any) -> str:
            raise RuntimeError("connection refused")

    backend._adbutils = _BoomAdbutils()
    with pytest.raises(AdbError) as generic:
        backend._client()
    assert generic.value.code == "backend_error"


def test_device_maps_missing_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _available_backend()

    class _Client:
        def device(self, serial: str) -> Any:
            raise RuntimeError("device not found")

    monkeypatch.setattr(AdbBackend, "_client", lambda self, *, socket_timeout=0: _Client())
    with pytest.raises(AdbError) as missing:
        backend._device("emulator-5554")
    assert missing.value.code == "not_found"

    class _TimeoutClient:
        def device(self, serial: str) -> Any:
            raise RuntimeError("transport timed out")

    monkeypatch.setattr(
        AdbBackend, "_client", lambda self, *, socket_timeout=0: _TimeoutClient()
    )
    with pytest.raises(AdbError) as timed:
        backend._device("emulator-5554")
    assert timed.value.code == "timeout"


# --------------------------------------------------------------------------
# device-method error contracts (via a fake device)
# --------------------------------------------------------------------------
def _backend_with_device(monkeypatch: pytest.MonkeyPatch, dev: Any) -> AdbBackend:
    backend = _available_backend()
    monkeypatch.setattr(AdbBackend, "_device", lambda self, serial: dev)
    return backend


def _shell_dev(responder: Any, **extra: Any) -> Any:
    # Instance attributes, not class attributes: a plain function stored on a
    # class becomes a bound method (and would receive the device as ``self``),
    # so the fake device is built on a namespace whose callables are called
    # exactly as adbutils' own methods are.
    dev = types.SimpleNamespace()
    dev.shell = _Shell(responder)
    for key, value in extra.items():
        setattr(dev, key, value)
    return dev


def test_list_devices_uses_list_then_device_list_and_maps_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _available_backend()

    class _Client:
        def list(self) -> list[Any]:
            return [type("I", (), {"serial": "emulator-5554", "state": "device"})()]

    monkeypatch.setattr(AdbBackend, "_client", lambda self, *, socket_timeout=0: _Client())
    payload = backend.list_devices()
    assert payload["count"] == 1 and payload["devices"][0]["serial"] == "emulator-5554"

    class _Boom:
        list = None

        def device_list(self) -> list[Any]:
            raise RuntimeError("adb list timed out")

    monkeypatch.setattr(AdbBackend, "_client", lambda self, *, socket_timeout=0: _Boom())
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "timeout"


def test_connect_rejects_bad_ports_and_maps_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _available_backend()
    monkeypatch.setattr(
        AdbBackend, "_client", lambda self, *, socket_timeout=0: _FakeClient()
    )
    with pytest.raises(AdbError) as bad:
        backend.connect("127.0.0.1", 70000)
    assert bad.value.code == "invalid_params"

    class _Boom:
        def connect(self, endpoint: str, timeout: float = 10.0) -> str:
            raise RuntimeError("refused")

    monkeypatch.setattr(AdbBackend, "_client", lambda self, *, socket_timeout=0: _Boom())
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 5555)
    assert caught.value.code == "backend_error"


def test_connect_reports_connected_state(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _available_backend()
    monkeypatch.setattr(
        AdbBackend,
        "_client",
        lambda self, *, socket_timeout=0: _FakeClient(connect_result="already connected"),
    )
    payload = backend.connect("127.0.0.1", 5555)
    assert payload["connected"] is True and payload["endpoint"] == "127.0.0.1:5555"


def test_info_maps_a_shell_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(args: Any) -> str:
        raise RuntimeError("getprop broke")

    dev = _shell_dev(_boom, get_state=lambda timeout=None: "device")
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_properties_pages_and_rejects_host_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "[ro.a]: [1]\n[ro.b]: [2]\n[ro.c]: [3]\n"
    backend = _backend_with_device(monkeypatch, _shell_dev(lambda args: text))
    payload = backend.properties("emulator-5554", limit=2)
    assert payload["count"] == 2 and payload["has_more"] is True

    backend = _backend_with_device(
        monkeypatch, _shell_dev(lambda args: "error: device offline")
    )
    with pytest.raises(AdbError) as caught:
        backend.properties("emulator-5554")
    assert caught.value.code == "backend_error"


def test_packages_skips_noise_and_rejects_host_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "package:com.b\npackage:\nnoise\npackage:com.a\n"
    backend = _backend_with_device(monkeypatch, _shell_dev(lambda args: text))
    payload = backend.packages("emulator-5554")
    assert payload["packages"] == ["com.a", "com.b"]

    backend = _backend_with_device(monkeypatch, _shell_dev(lambda args: "adb: no device"))
    with pytest.raises(AdbError) as caught:
        backend.packages("emulator-5554")
    assert caught.value.code == "backend_error"


def test_install_missing_file_and_transfer_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _available_backend()
    with pytest.raises(AdbError) as missing:
        backend.install("emulator-5554", str(tmp_path / "nope.apk"))
    assert missing.value.code == "not_found"

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", 'package="com.example.app"')

    def _install(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("pm install failed")

    dev = _shell_dev(lambda args: "", install=_install)
    backend2 = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend2.install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_install_verifies_a_visible_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", 'package="com.example.app"')

    def _responder(args: Any) -> str:
        if isinstance(args, list) and args[:2] == ["pm", "path"]:
            return "package:/data/app/com.example.app/base.apk"
        return ""

    dev = _shell_dev(_responder, install=lambda *a, **k: None)
    backend = _backend_with_device(monkeypatch, dev)
    result = backend.install("emulator-5554", str(apk))
    assert result["installed"] is True and result["package"] == "com.example.app"


def test_install_reports_unverifiable_when_pm_path_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", 'package="com.example.app"')

    def _responder(args: Any) -> str:
        if isinstance(args, list) and args[:2] == ["pm", "path"]:
            return "error: device offline"
        return ""

    dev = _shell_dev(_responder, install=lambda *a, **k: None)
    backend = _backend_with_device(monkeypatch, dev)
    result = backend.install("emulator-5554", str(apk))
    assert result["installed"] is None and "could not verify" in result["note"]


def test_uninstall_maps_failure_and_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("uninstall broke")

    dev = _shell_dev(lambda args: "", uninstall=_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.uninstall("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"

    # A clean uninstall whose pm path is now empty reports uninstalled True.
    dev = _shell_dev(lambda args: "", uninstall=lambda *a, **k: None)
    backend = _backend_with_device(monkeypatch, dev)
    result = backend.uninstall("emulator-5554", "com.example.app")
    assert result["uninstalled"] is True


def test_launch_confirms_and_reports_unreadable_foreground(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = type("C", (), {"package": "com.example.app", "activity": ".Main"})()
    dev = _shell_dev(lambda args: "", app_current=lambda timeout=None: current)
    backend = _backend_with_device(monkeypatch, dev)
    assert backend.launch("emulator-5554", "com.example.app")["launched"] is True

    def _boom(timeout: float | None = None) -> Any:
        raise RuntimeError("dumpsys failed")

    dev = _shell_dev(lambda args: "", app_current=_boom)
    backend = _backend_with_device(monkeypatch, dev)
    result = backend.launch("emulator-5554", "com.example.app")
    assert result["launched"] is None and "could not read foreground" in result["note"]


def test_force_stop_maps_failure_and_reports_remaining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _responder(args: Any) -> str:
        if isinstance(args, list) and args[:1] == ["am"]:
            return ""
        return ""  # pidof -> empty -> no pids

    dev = _shell_dev(_responder)
    backend = _backend_with_device(monkeypatch, dev)
    result = backend.force_stop("emulator-5554", "com.example.app")
    assert result["stopped"] is True and result["remaining_pids"] == []

    def _boom(args: Any) -> str:
        if isinstance(args, list) and args[:1] == ["am"]:
            raise RuntimeError("am broke")
        return ""

    dev = _shell_dev(_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.force_stop("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_current_activity_returns_and_refuses_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    current = type("C", (), {"package": "com.example.app", "activity": ".Main"})()
    dev = _shell_dev(lambda args: "", app_current=lambda timeout=None: current)
    backend = _backend_with_device(monkeypatch, dev)
    assert backend.current_activity("emulator-5554")["package"] == "com.example.app"

    dev = _shell_dev(lambda args: "", app_current=lambda timeout=None: None)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_maps_a_read_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(timeout: float | None = None) -> Any:
        raise RuntimeError("app_current broke")

    dev = _shell_dev(lambda args: "", app_current=_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_logcat_trims_and_rejects_host_error(monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "line1\nline2\nline3\n")
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.logcat("emulator-5554", lines=2)
    assert payload["count"] == 2 and payload["lines"] == ["line2", "line3"]

    dev = _shell_dev(lambda args: "error: offline")
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.logcat("emulator-5554")
    assert caught.value.code == "backend_error"


class _Image:
    def __init__(self, size: int) -> None:
        self._size = size

    def save(self, path: str) -> None:
        Path(path).write_bytes(b"x" * self._size)


def test_screenshot_writes_size_and_maps_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dev = _shell_dev(lambda args: "", screenshot=lambda timeout=None: _Image(10))
    backend = _backend_with_device(monkeypatch, dev)
    out = tmp_path / "shots" / "s.png"
    payload = backend.screenshot("emulator-5554", out)
    assert payload["size"] == 10 and out.exists()

    def _boom(timeout: float | None = None) -> Any:
        raise RuntimeError("screencap broke")

    dev = _shell_dev(lambda args: "", screenshot=_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.screenshot("emulator-5554", tmp_path / "s2.png")
    assert caught.value.code == "backend_error"


class _Sync:
    def __init__(self, *, stat_info: Any = None, pull_writes: bytes | None = None,
                 pull_error: Exception | None = None, push_error: Exception | None = None) -> None:
        self._stat = stat_info
        self._pull_writes = pull_writes
        self._pull_error = pull_error
        self._push_error = push_error

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        if self._stat is None:
            raise RuntimeError("no stat")
        return self._stat

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        if self._pull_error is not None:
            raise self._pull_error
        if self._pull_writes is not None:
            Path(local).write_bytes(self._pull_writes)

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        if self._push_error is not None:
            raise self._push_error


def test_pull_reports_not_found_when_nothing_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dev = _shell_dev(lambda args: "", sync=_Sync(pull_writes=None))
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.pull("emulator-5554", "/sdcard/x", tmp_path / "out" / "x")
    assert caught.value.code == "not_found"


def test_pull_refuses_a_directory_by_stat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dir_info = type("S", (), {"mode": stat.S_IFDIR | 0o755, "size": 0})()
    dev = _shell_dev(lambda args: "", sync=_Sync(stat_info=dir_info))
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.pull("emulator-5554", "/sdcard/dir", tmp_path / "out" / "d")
    assert caught.value.code == "invalid_params"


def test_pull_maps_a_transfer_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "", sync=_Sync(pull_error=RuntimeError("pull broke")))
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.pull("emulator-5554", "/sdcard/x", tmp_path / "out" / "x")
    assert caught.value.code == "backend_error"


def test_pull_succeeds_and_reports_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "", sync=_Sync(pull_writes=b"hello"))
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.pull("emulator-5554", "/sdcard/x", tmp_path / "out" / "x")
    assert payload["size"] == 5


def test_push_validates_local_file_and_maps_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _available_backend()
    with pytest.raises(AdbError) as missing:
        backend.push("emulator-5554", str(tmp_path / "nope"), "/sdcard/x")
    assert missing.value.code == "not_found"

    local = tmp_path / "f.bin"
    local.write_bytes(b"data")
    dev = _shell_dev(lambda args: "", sync=_Sync(push_error=RuntimeError("push broke")))
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.push("emulator-5554", str(local), "/sdcard/x")
    assert caught.value.code == "backend_error"

    dev = _shell_dev(lambda args: "", sync=_Sync())
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.push("emulator-5554", str(local), "/sdcard/x")
    assert payload["size"] == 4


# --------------------------------------------------------------------------
# ensure_frida_server
# --------------------------------------------------------------------------
def test_ensure_frida_server_rejects_bad_paths_and_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "")
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as bad_path:
        backend.ensure_frida_server("emulator-5554", remote_path="relative/path")
    assert bad_path.value.code == "invalid_params"
    with pytest.raises(AdbError) as bad_host:
        backend.ensure_frida_server("emulator-5554", bind_host="bad host!")
    assert bad_host.value.code == "invalid_params"


def test_ensure_frida_server_noop_when_already_running(monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "root 1 frida-server")
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.ensure_frida_server("emulator-5554")
    assert payload["running"] is True and payload["pushed"] is False


def test_ensure_frida_server_rejects_a_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dev = _shell_dev(lambda args: "")  # not running
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "nope")
        )
    assert caught.value.code == "not_found"


def test_ensure_frida_server_reports_not_visible_after_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ps never shows frida-server, so the launch is reported unverified.
    dev = _shell_dev(lambda args: "")
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.ensure_frida_server("emulator-5554")
    assert payload["running"] is False and "not visible" in payload["note"]


def test_ensure_frida_server_pushes_the_binary_then_confirms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")

    class _State:
        launched = False

        def __call__(self, args: Any) -> str:
            text = args if isinstance(args, str) else " ".join(args)
            if text.startswith("su -c"):
                self.launched = True
                return ""
            if text.startswith("ps"):
                # Only reports running once the launch command has been issued.
                return "root 1 frida-server" if self.launched else ""
            return ""

    pushed: list[tuple[str, str]] = []
    sync = types.SimpleNamespace(
        push=lambda local, remote, timeout=None: pushed.append((local, remote))
    )
    dev = _shell_dev(_State(), sync=sync)
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert payload["running"] is True and payload["pushed"] is True
    assert pushed and pushed[0][1] == "/data/local/tmp/frida-server"


# --------------------------------------------------------------------------
# forward / release_forwards
# --------------------------------------------------------------------------
def test_forward_releases_slot_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("bind refused")

    dev = _shell_dev(lambda args: "", forward=_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5555", "tcp:27042")
    assert caught.value.code == "backend_error"
    # The reserved slot was handed back so the cap is not leaked.
    assert backend._forwards == []


def test_forward_reraises_a_mapped_adberror_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _adb_boom(*args: Any, **kwargs: Any) -> None:
        raise AdbError("invalid_state", "already forwarded")

    dev = _shell_dev(lambda args: "", forward=_adb_boom)
    backend = _backend_with_device(monkeypatch, dev)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5555", "tcp:27042")
    assert caught.value.code == "invalid_state"
    assert backend._forwards == []


def test_forward_succeeds_and_records_the_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    dev = _shell_dev(lambda args: "", forward=lambda *a, **k: None)
    backend = _backend_with_device(monkeypatch, dev)
    payload = backend.forward("emulator-5554", "tcp:5555", "tcp:27042")
    assert payload == {"local": "tcp:5555", "remote": "tcp:27042"}
    assert ("emulator-5554", "tcp:5555") in backend._forwards


def test_release_forwards_removes_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    removed_calls: list[str] = []

    def _remove(local: str, timeout: float | None = None) -> None:
        removed_calls.append(local)

    dev = _shell_dev(lambda args: "", forward_remove=_remove)
    backend = _backend_with_device(monkeypatch, dev)
    backend._forwards = [("emulator-5554", "tcp:5555")]
    payload = backend.release_forwards()
    assert payload["count"] == 1 and removed_calls == ["tcp:5555"]
    assert backend._forwards == []


def test_release_forwards_retries_a_device_with_no_remove_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dev = _shell_dev(lambda args: "")  # neither forward_remove nor remove_forward
    backend = _backend_with_device(monkeypatch, dev)
    backend._forwards = [("emulator-5554", "tcp:5555")]
    payload = backend.release_forwards()
    assert payload["count"] == 0 and len(payload["failed"]) == 1
    # The un-removable forward is kept for the next close_all to retry.
    assert backend._forwards == [("emulator-5554", "tcp:5555")]
