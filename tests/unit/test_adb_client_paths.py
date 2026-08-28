"""Error and edge arms of the ADB backend, driven by injected fakes.

adbutils is optional and not installed here, so the existing suite exercises
the read-out parsing with a scripted device but leaves most of the backend's
failure translation unrun: the signature-probing helpers, ``_device_shell``
and ``_call`` error mapping, the ``open_transport`` timeout shim, the
``_client`` / ``_device`` construction arms, and the except/verify branches
of every device operation. These drive those arms directly with fake
adbutils modules and fake devices -- no emulator, no adb server -- exactly
where the real error handling lives.
"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path
from typing import Any, cast

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
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _is_host_error_output,
    _is_timeout,
    _pids_for_package,
)

# --------------------------------------------------------------------------- #
# Signature-probing helpers
# --------------------------------------------------------------------------- #


def test_accepts_timeout_detects_explicit_and_varkw_params() -> None:
    def explicit(args: Any, timeout: float | None = None) -> None: ...
    def varkw(args: Any, **kwargs: Any) -> None: ...
    def neither(args: Any) -> None: ...

    assert _accepts_timeout(explicit) is True
    assert _accepts_timeout(varkw) is True
    assert _accepts_timeout(neither) is False


def test_accepts_timeout_is_false_when_the_signature_is_opaque() -> None:
    # A non-introspectable object makes signature() raise; the helper must
    # answer False rather than propagate, so the caller falls back to a
    # timeout-less call instead of crashing.
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_passes_all_for_varkw_and_filters_otherwise() -> None:
    def varkw(**kwargs: Any) -> None: ...
    def narrow(nolaunch: bool = False) -> None: ...

    assert _accepted_kwargs(varkw, {"a": 1, "b": 2}) == {"a": 1, "b": 2}
    assert _accepted_kwargs(narrow, {"nolaunch": True, "flags": []}) == {"nolaunch": True}


def test_accepted_kwargs_is_empty_when_the_signature_is_opaque() -> None:
    assert _accepted_kwargs(object(), {"a": 1}) == {}


def test_is_timeout_reads_type_name_and_message() -> None:
    assert _is_timeout(TimeoutError("x")) is True
    assert _is_timeout(RuntimeError("the call timed out")) is True
    assert _is_timeout(RuntimeError("device offline")) is False


def test_is_host_error_output_only_flags_all_error_lines() -> None:
    assert _is_host_error_output("error: device offline\nadb: no such device") is True
    assert _is_host_error_output("  \n  ") is False  # blank only
    assert _is_host_error_output("error: x\nreal log line") is False


# --------------------------------------------------------------------------- #
# _device_shell / _call error translation
# --------------------------------------------------------------------------- #


class _ShellDev:
    def __init__(self, behaviour: Any, *, accepts_timeout: bool = True) -> None:
        self._behaviour = behaviour
        if accepts_timeout:
            self.shell = self._shell_timeout
        else:
            self.shell = self._shell_plain  # type: ignore[assignment]

    def _run(self) -> str:
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return str(self._behaviour)

    def _shell_timeout(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._run()

    def _shell_plain(self, args: Any) -> str:
        del args
        return self._run()


def test_device_shell_passes_and_returns_when_supported() -> None:
    assert _device_shell(_ShellDev("output-text"), "getprop") == "output-text"


def test_device_shell_works_without_a_timeout_parameter() -> None:
    # Older adbutils: shell() has no timeout kw, so the ternary must call it
    # without one instead of hitting a TypeError.
    assert _device_shell(_ShellDev("v", accepts_timeout=False), "getprop") == "v"


def test_device_shell_reraises_an_adberror_unchanged() -> None:
    original = AdbError("invalid_params", "bad")
    with pytest.raises(AdbError) as exc:
        _device_shell(_ShellDev(original), "x")
    assert exc.value is original


def test_device_shell_maps_a_timeout_to_a_timeout_error() -> None:
    with pytest.raises(AdbError) as exc:
        _device_shell(_ShellDev(TimeoutError("stalled")), "x", timeout=3.0)
    assert exc.value.code == "timeout"


def test_device_shell_maps_a_generic_failure_to_backend_error() -> None:
    with pytest.raises(AdbError) as exc:
        _device_shell(_ShellDev(RuntimeError("broken pipe")), "x")
    assert exc.value.code == "backend_error"


def test_call_passes_timeout_only_when_accepted_and_maps_timeout() -> None:
    def with_timeout(value: int, timeout: float | None = None) -> tuple[int, float | None]:
        return value, timeout

    assert _call(with_timeout, 5, timeout=2.0) == (5, 2.0)

    def stalls(timeout: float | None = None) -> None:
        raise TimeoutError("gone")

    with pytest.raises(AdbError) as exc:
        _call(stalls, timeout=1.0)
    assert exc.value.code == "timeout"


def test_call_reraises_adberror_and_non_timeout_errors() -> None:
    original = AdbError("not_found", "x")

    def raises_adb() -> None:
        raise original

    with pytest.raises(AdbError) as exc:
        _call(raises_adb, timeout=1.0)
    assert exc.value is original

    def raises_value() -> None:
        raise ValueError("plain")

    with pytest.raises(ValueError):
        _call(raises_value, timeout=1.0)


# --------------------------------------------------------------------------- #
# _frida_server_visible / _bind_open_transport / _file_mode_size
# --------------------------------------------------------------------------- #


def test_frida_server_visible_true_from_ps_a() -> None:
    dev = _ShellDev("root 1 frida-server -l 127.0.0.1")
    assert _frida_server_visible(dev) is True


def test_frida_server_visible_none_when_the_probe_fails() -> None:
    dev = _ShellDev(RuntimeError("device gone"))
    assert _frida_server_visible(dev) is None


def test_bind_open_transport_returns_the_device_without_the_method() -> None:
    dev = object()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_falls_back_through_older_signatures() -> None:
    class _OldTransport:
        def __init__(self) -> None:
            self.got: Any = "unset"

        def open_transport(self, command: Any) -> str:
            # Accepts only one positional, so the kwargs and 2-arg attempts
            # both raise TypeError before this succeeds.
            self.got = command
            return "transport"

    dev = _OldTransport()
    _bind_open_transport(dev, 9.0)
    # The binder replaced the instance method with a zero-arg closure.
    assert dev.open_transport() == "transport"  # type: ignore[call-arg]
    assert dev.got is None


def test_bind_open_transport_survives_an_unassignable_method() -> None:
    class _Frozen:
        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            return "t"

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "open_transport":
                raise AttributeError("read only")
            super().__setattr__(name, value)

    dev = _Frozen()
    assert _bind_open_transport(dev, 5.0) is dev


def test_file_mode_size_reads_attributes_then_tuples() -> None:
    from types import SimpleNamespace

    mode, size = _file_mode_size(SimpleNamespace(mode=stat.S_IFREG, size=42))
    assert (mode, size) == (stat.S_IFREG, 42)
    assert _file_mode_size((stat.S_IFDIR, 7)) == (stat.S_IFDIR, 7)


# --------------------------------------------------------------------------- #
# _apk_package_name / _pids_for_package
# --------------------------------------------------------------------------- #


def _zip_with_manifest(path: Path, manifest: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    return path


def test_apk_package_name_falls_back_to_the_utf16_scan(tmp_path: Path) -> None:
    # A binary AXML manifest is not valid UTF-8 and has no package="..."
    # attribute; the UTF-16 scan must skip android.* framework ids and return
    # the real application id.
    text = "namespace package android.intent.action.MAIN pad com.example.app tail"
    manifest = b"\xff\xff" + text.encode("utf-16-le")
    apk = _zip_with_manifest(tmp_path / "app.apk", manifest)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_reads_a_utf8_string_pool(tmp_path: Path) -> None:
    # A binary AXML whose string pool is UTF-8 (aapt2's UTF8_FLAG), not UTF-16:
    # the package bytes are UTF-8, so the UTF-16 scan sees only garbage. The
    # leading non-UTF-8 bytes keep the strict text path from matching, exactly
    # as a real binary AXML header would. The UTF-8 fallback scan must still
    # skip android.* framework ids and return the real application id.
    text = "namespace package android.intent.action.MAIN pad com.example.app tail"
    manifest = b"\xff\xff" + text.encode("utf-8")
    apk = _zip_with_manifest(tmp_path / "app.apk", manifest)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_is_none_for_a_manifestless_zip(tmp_path: Path) -> None:
    apk = tmp_path / "empty.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    assert _apk_package_name(apk) is None


class _PidsDev:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = args if isinstance(args, list) else str(args).split()
        head = tokens[0]
        value = self._responses[head]
        if isinstance(value, Exception):
            raise value
        return str(value)


def test_pids_for_package_returns_none_when_ps_fallback_fails() -> None:
    dev = _PidsDev({"pidof": "pidof: not found", "ps": AdbError("timeout", "stalled")})
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_bounds_the_ps_fallback_to_sixteen() -> None:
    rows = "\n".join(f"u0_a{i} {1000 + i} 1 com.example.app" for i in range(25))
    dev = _PidsDev({"pidof": "pidof: not found", "ps": rows})
    pids = _pids_for_package(dev, "com.example.app")
    assert pids is not None
    assert len(pids) == 16


def test_pids_for_package_is_none_for_unparseable_nonempty_output() -> None:
    dev = _PidsDev({"pidof": "weird output without any numbers"})
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_ignores_a_sibling_package_in_the_ps_fallback() -> None:
    """The ps -A fallback must match the NAME column, not a whole-line substring.

    com.example.apple contains com.example.app as a substring; the old test
    attributed the sibling's pid to the target, so force_stop reported the app
    still running after it had been stopped. A same-app child process
    (com.example.app:svc) is still the target -- force-stop kills it too -- so
    it stays. Pinning the exact pid set is what makes this non-vacuous: a
    substring match would return all three pids and fail here.
    """
    ps_table = "\n".join(
        [
            "USER   PID  PPID VSZ RSS WCHAN ADDR S NAME",
            "u0_a10 4321 1 0 0 ffff 0 S com.example.app",
            "u0_a11 4322 1 0 0 ffff 0 S com.example.app:svc",
            "u0_a12 9999 1 0 0 ffff 0 S com.example.apple",
        ]
    )
    dev = _PidsDev({"pidof": "pidof: not found", "ps": ps_table})
    assert _pids_for_package(dev, "com.example.app") == [4321, 4322]


# --------------------------------------------------------------------------- #
# _client / _device construction arms (fake adbutils module)
# --------------------------------------------------------------------------- #


def _module_with(client_cls: type) -> Any:
    module = type("FakeAdbutils", (), {})
    module.AdbClient = client_cls  # type: ignore[attr-defined]
    return module


def _backend_with_adbutils(client_cls: type, *, adb_path: Path | None = None) -> AdbBackend:
    backend = AdbBackend(adb_path=adb_path)
    backend._available = True
    backend._adbutils = _module_with(client_cls)
    return backend


def test_client_is_unavailable_without_adbutils() -> None:
    backend = AdbBackend()  # real import failed: not installed
    backend._available = False
    with pytest.raises(AdbError) as exc:
        backend._client()
    assert exc.value.code == "capability_unavailable"


def test_client_sets_the_adb_path_env_and_falls_back_on_typeerror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    seen: dict[str, Any] = {}

    class _Client:
        def __init__(self, host: str, port: int) -> None:
            # No socket_timeout kw: the first construction raises TypeError and
            # the backend retries without it.
            seen["host"] = host
            seen["port"] = port

    adb_path = tmp_path / "platform-tools" / "adb"
    backend = _backend_with_adbutils(_Client, adb_path=adb_path)
    client = backend._client()
    assert isinstance(client, _Client)
    import os

    assert os.environ["ADBUTILS_ADB_PATH"] == str(adb_path)


def test_client_maps_a_timeout_and_a_generic_error() -> None:
    class _TimeoutClient:
        def __init__(self, **kwargs: Any) -> None:
            raise TimeoutError("no server")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_TimeoutClient)._client()
    assert exc.value.code == "timeout"

    class _BrokenClient:
        def __init__(self, **kwargs: Any) -> None:
            raise RuntimeError("connection refused")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_BrokenClient)._client()
    assert exc.value.code == "backend_error"


def test_device_maps_a_lookup_failure_to_not_found() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def device(self, serial: str) -> Any:
            raise RuntimeError("device offline")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client)._device("emulator-5554")
    assert exc.value.code == "not_found"


def test_device_maps_a_timeout_to_timeout() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def device(self, serial: str) -> Any:
            raise TimeoutError("transport stalled")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client)._device("emulator-5554")
    assert exc.value.code == "timeout"


def test_client_reraises_an_adberror_from_construction() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            raise AdbError("invalid_state", "already claimed")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client)._client()
    assert exc.value.code == "invalid_state"


def test_device_reraises_an_adberror_from_lookup() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def device(self, serial: str) -> Any:
            raise AdbError("capability_unavailable", "no transport")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client)._device("emulator-5554")
    assert exc.value.code == "capability_unavailable"


def test_device_returns_the_resolved_device_on_success() -> None:
    sentinel = object()

    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def device(self, serial: str) -> Any:
            return sentinel

    # No open_transport on the sentinel, so _bind_open_transport returns it as-is.
    assert _backend_with_adbutils(_Client)._device("emulator-5554") is sentinel


def test_list_devices_maps_a_timeout_and_a_generic_failure() -> None:
    class _TimeoutClient:
        def __init__(self, **kwargs: Any) -> None: ...

        def list(self) -> Any:
            raise TimeoutError("adb list stalled")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_TimeoutClient).list_devices()
    assert exc.value.code == "timeout"

    class _BrokenClient:
        def __init__(self, **kwargs: Any) -> None: ...

        def list(self) -> Any:
            raise RuntimeError("adb server died")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_BrokenClient).list_devices()
    assert exc.value.code == "backend_error"


def test_list_devices_reraises_an_adberror_from_the_lister() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def list(self) -> Any:
            raise AdbError("timeout", "adb timed out")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client).list_devices()
    assert exc.value.code == "timeout"


def test_connect_rejects_an_out_of_range_port() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client).connect("127.0.0.1", 0)
    assert exc.value.code == "invalid_params"


def test_connect_maps_a_raised_connect_to_backend_error() -> None:
    class _Client:
        def __init__(self, **kwargs: Any) -> None: ...

        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            raise RuntimeError("no route to host")

    with pytest.raises(AdbError) as exc:
        _backend_with_adbutils(_Client).connect("127.0.0.1", 5555)
    assert exc.value.code == "backend_error"


# --------------------------------------------------------------------------- #
# Device operations: verify/except arms via an injected device
# --------------------------------------------------------------------------- #


def _backend_with_dev(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


class _OpDev:
    """A device whose behaviours are supplied per attribute for op tests."""

    def __init__(self, **behaviours: Any) -> None:
        self._behaviours = behaviours

    def _resolve(self, name: str, default: Any = "") -> Any:
        value = self._behaviours.get(name, default)
        if isinstance(value, Exception):
            raise value
        return value

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = args if isinstance(args, list) else str(args).split()
        table = self._behaviours.get("shell", {})
        for matcher, output in table.items():
            if tuple(tokens[: len(matcher)]) == matcher:
                if isinstance(output, Exception):
                    raise output
                return str(output)
        return ""

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return cast(str, self._resolve("get_state", "device"))

    def app_current(self, timeout: float | None = None) -> Any:
        del timeout
        return self._resolve("app_current", None)

    def install(self, path: str, **kwargs: Any) -> Any:
        del path, kwargs
        return self._resolve("install", None)

    def uninstall(self, package: str, **kwargs: Any) -> Any:
        del package, kwargs
        return self._resolve("uninstall", None)


def test_info_maps_an_unexpected_read_failure_to_backend_error() -> None:
    dev = _OpDev(get_state=ValueError("boom"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).info("emulator-5554")
    assert exc.value.code == "backend_error"


def test_info_reraises_an_adberror_from_a_probe() -> None:
    dev = _OpDev(get_state=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).info("emulator-5554")
    assert exc.value.code == "timeout"


def test_properties_skips_lines_that_do_not_match_the_getprop_shape() -> None:
    dev = _OpDev(shell={("getprop",): "junk line\n[ro.product.model]: [Pixel]"})
    payload = _backend_with_dev(dev).properties("emulator-5554")
    assert payload["properties"] == {"ro.product.model": "Pixel"}


def test_packages_skips_non_package_and_empty_lines() -> None:
    listing = "not-a-package\npackage:\npackage:com.real.app"
    dev = _OpDev(shell={("pm", "list", "packages"): listing})
    payload = _backend_with_dev(dev).packages("emulator-5554")
    assert payload["packages"] == ["com.real.app"]


def test_install_reraises_an_adberror_from_the_transfer(tmp_path: Path) -> None:
    apk = _zip_with_manifest(tmp_path / "app.apk", b"<manifest/>")
    dev = _OpDev(install=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).install("emulator-5554", str(apk))
    assert exc.value.code == "timeout"


def test_uninstall_reraises_an_adberror() -> None:
    dev = _OpDev(uninstall=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).uninstall("emulator-5554", "com.example.app")
    assert exc.value.code == "timeout"


def test_force_stop_reraises_an_adberror_from_the_shell() -> None:
    dev = _OpDev(shell={("am", "force-stop"): AdbError("timeout", "adb timed out")})
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).force_stop("emulator-5554", "com.example.app")
    assert exc.value.code == "timeout"


def test_current_activity_reraises_an_adberror() -> None:
    dev = _OpDev(app_current=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).current_activity("emulator-5554")
    assert exc.value.code == "timeout"


def test_info_returns_the_property_fields_on_success() -> None:
    dev = _OpDev(
        shell={
            ("getprop", "ro.product.model"): "Pixel",
            ("getprop", "ro.product.device"): "sailfish",
            ("getprop", "ro.build.version.sdk"): "30",
            ("getprop", "ro.build.version.release"): "11",
            ("getprop", "ro.product.cpu.abi"): "arm64-v8a",
        }
    )
    payload = _backend_with_dev(dev).info("emulator-5554")
    assert payload["model"] == "Pixel"
    assert payload["abi"] == "arm64-v8a"
    assert payload["state"] == "device"


def test_launch_reports_the_foreground_and_handles_a_read_failure() -> None:
    from types import SimpleNamespace

    ok = _OpDev(app_current=SimpleNamespace(package="com.example.app"))
    payload = _backend_with_dev(ok).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"

    unreadable = _OpDev(app_current=RuntimeError("dumpsys failed"))
    note = _backend_with_dev(unreadable).launch("emulator-5554", "com.example.app")
    assert note["launched"] is None
    assert "note" in note


def test_launch_maps_a_monkey_failure_to_backend_error() -> None:
    dev = _OpDev(shell={("monkey",): RuntimeError("no activity")})
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).launch("emulator-5554", "com.example.app")
    assert exc.value.code == "backend_error"


def test_install_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    apk = _zip_with_manifest(tmp_path / "app.apk", b"<manifest/>")
    dev = _OpDev(install=RuntimeError("pm install failed"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).install("emulator-5554", str(apk))
    assert exc.value.code == "backend_error"


def test_uninstall_maps_a_failure_to_backend_error() -> None:
    dev = _OpDev(uninstall=RuntimeError("pm uninstall failed"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).uninstall("emulator-5554", "com.example.app")
    assert exc.value.code == "backend_error"


def test_current_activity_maps_a_failure_to_backend_error() -> None:
    dev = _OpDev(app_current=RuntimeError("dumpsys failed"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).current_activity("emulator-5554")
    assert exc.value.code == "backend_error"


# --------------------------------------------------------------------------- #
# screenshot / pull / push transfer arms
# --------------------------------------------------------------------------- #


class _Image:
    def __init__(self, data: bytes = b"PNGDATA") -> None:
        self._data = data

    def save(self, path: str) -> None:
        Path(path).write_bytes(self._data)


class _ScreenshotDev:
    def __init__(self, behaviour: Any) -> None:
        self._behaviour = behaviour

    def screenshot(self, timeout: float | None = None) -> Any:
        del timeout
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return self._behaviour


def test_screenshot_saves_and_reports_the_size(tmp_path: Path) -> None:
    dev = _ScreenshotDev(_Image(b"a-real-png"))
    out = tmp_path / "shots" / "cap.png"
    payload = _backend_with_dev(dev).screenshot("emulator-5554", out)
    assert payload["size"] == len(b"a-real-png")
    assert Path(payload["path"]).read_bytes() == b"a-real-png"


def test_screenshot_maps_a_capture_failure_to_backend_error(tmp_path: Path) -> None:
    dev = _ScreenshotDev(RuntimeError("screencap died"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).screenshot("emulator-5554", tmp_path / "x.png")
    assert exc.value.code == "backend_error"


def test_screenshot_reraises_an_adberror_from_capture(tmp_path: Path) -> None:
    dev = _ScreenshotDev(AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).screenshot("emulator-5554", tmp_path / "x.png")
    assert exc.value.code == "timeout"


def test_screenshot_refuses_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adb, "capped_file_size", lambda path, cap: (cap + 1, True))
    dev = _ScreenshotDev(_Image(b"small"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).screenshot("emulator-5554", tmp_path / "big.png")
    assert exc.value.code == "too_large"


class _Sync:
    def __init__(
        self,
        *,
        stat_result: Any = None,
        stat_error: Exception | None = None,
        on_pull: Any = None,
        pull_error: Exception | None = None,
        push_error: Exception | None = None,
    ) -> None:
        self._stat_result = stat_result
        self._stat_error = stat_error
        self._on_pull = on_pull
        self._pull_error = pull_error
        self._push_error = push_error

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        if self._stat_error is not None:
            raise self._stat_error
        return self._stat_result

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        if self._pull_error is not None:
            raise self._pull_error
        if self._on_pull is not None:
            self._on_pull(Path(local))

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        if self._push_error is not None:
            raise self._push_error


class _TransferDev:
    def __init__(self, sync: _Sync) -> None:
        self.sync = sync


def test_pull_tolerates_a_failing_stat_probe_then_succeeds(tmp_path: Path) -> None:
    sync = _Sync(
        stat_error=RuntimeError("stat unsupported"),
        on_pull=lambda local: local.write_bytes(b"payload"),
    )
    out = tmp_path / "pulled.bin"
    payload = _backend_with_dev(_TransferDev(sync)).pull("emulator-5554", "/sdcard/x", out)
    assert payload["size"] == len(b"payload")


def test_pull_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    sync = _Sync(pull_error=RuntimeError("sync broke"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).pull(
            "emulator-5554", "/sdcard/x", tmp_path / "out.bin"
        )
    assert exc.value.code == "backend_error"


def test_pull_reraises_an_adberror_from_the_transfer(tmp_path: Path) -> None:
    sync = _Sync(pull_error=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).pull(
            "emulator-5554", "/sdcard/x", tmp_path / "out.bin"
        )
    assert exc.value.code == "timeout"


def test_pull_refuses_when_the_result_is_a_directory(tmp_path: Path) -> None:
    def _make_dir(local: Path) -> None:
        local.mkdir(parents=True, exist_ok=True)

    sync = _Sync(on_pull=_make_dir)
    out = tmp_path / "asdir"
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).pull("emulator-5554", "/sdcard/dir", out)
    assert exc.value.code == "invalid_params"
    assert not out.exists()  # the stray directory was removed


def test_pull_reports_not_found_when_nothing_was_written(tmp_path: Path) -> None:
    sync = _Sync(on_pull=lambda local: None)  # a clean pull that writes nothing
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).pull(
            "emulator-5554", "/sdcard/missing", tmp_path / "out.bin"
        )
    assert exc.value.code == "not_found"


def test_pull_refuses_a_file_over_the_cap_after_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adb, "capped_file_size", lambda path, cap: (cap + 1, True))
    sync = _Sync(on_pull=lambda local: local.write_bytes(b"x"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).pull(
            "emulator-5554", "/sdcard/x", tmp_path / "out.bin"
        )
    assert exc.value.code == "too_large"


def test_push_maps_a_stat_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = tmp_path / "local.bin"
    local.write_bytes(b"data")
    real_stat = Path.stat
    calls = {"n": 0}

    def boom(self: Path, *args: Any, **kwargs: Any) -> Any:
        # is_file() stats first and must succeed; the explicit size stat that
        # follows is the one whose failure this test exercises.
        if self == local:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("stat failed")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", boom)
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(_Sync())).push("emulator-5554", str(local), "/sdcard/x")
    assert exc.value.code == "backend_error"


def test_push_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    local = tmp_path / "local.bin"
    local.write_bytes(b"data")
    sync = _Sync(push_error=RuntimeError("sync push broke"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).push("emulator-5554", str(local), "/sdcard/x")
    assert exc.value.code == "backend_error"


def test_push_reraises_an_adberror_from_the_transfer(tmp_path: Path) -> None:
    local = tmp_path / "local.bin"
    local.write_bytes(b"data")
    sync = _Sync(push_error=AdbError("timeout", "adb timed out"))
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(_TransferDev(sync)).push("emulator-5554", str(local), "/sdcard/x")
    assert exc.value.code == "timeout"


# --------------------------------------------------------------------------- #
# ensure_frida_server / forward
# --------------------------------------------------------------------------- #


class _FridaDev:
    def __init__(self, shell_table: dict[tuple[str, ...], Any], sync: Any = None) -> None:
        self._table = shell_table
        self.sync = sync
        self.chmod_seen = False

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = args if isinstance(args, list) else str(args).split()
        if tokens[:1] == ["chmod"]:
            self.chmod_seen = True
            return ""
        for matcher, output in self._table.items():
            if tuple(tokens[: len(matcher)]) == matcher:
                if isinstance(output, Exception):
                    raise output
                return str(output)
        return ""


def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    dev = _FridaDev({})
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).ensure_frida_server("emulator-5554", remote_path="../etc/passwd")
    assert exc.value.code == "invalid_params"


def test_ensure_frida_server_is_a_no_op_when_already_running() -> None:
    dev = _FridaDev({("ps", "-A"): "root 1 frida-server -l 127.0.0.1:27042"})
    payload = _backend_with_dev(dev).ensure_frida_server("emulator-5554")
    assert payload == {"running": True, "pushed": False, "port": 27042}


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _FridaDev({("ps", "-A"): "", ("ps",): ""})
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert exc.value.code == "not_found"


def test_ensure_frida_server_pushes_and_reports_visibility(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF-ish")
    # Not visible before the push, visible after the launch command runs.
    state = {"visible": False}

    class _StatefulFrida(_FridaDev):
        def shell(self, args: Any, timeout: float | None = None) -> str:
            tokens = args if isinstance(args, list) else str(args).split()
            if isinstance(args, str) and "su -c" in args:
                state["visible"] = True
                return ""
            if tokens[:2] == ["ps", "-A"]:
                return "root 1 frida-server -l" if state["visible"] else ""
            return super().shell(args, timeout)

    dev = _StatefulFrida({}, sync=_Sync())
    payload = _backend_with_dev(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert payload["running"] is True
    assert payload["pushed"] is True
    assert dev.chmod_seen is True


def test_ensure_frida_server_maps_a_push_failure_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF-ish")
    dev = _FridaDev(
        {("ps", "-A"): "", ("ps",): ""},
        sync=_Sync(push_error=RuntimeError("sync push refused")),
    )
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert exc.value.code == "backend_error"


def test_ensure_frida_server_reraises_an_adberror_from_the_push(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF-ish")
    dev = _FridaDev(
        {("ps", "-A"): "", ("ps",): ""},
        sync=_Sync(push_error=AdbError("timeout", "adb timed out")),
    )
    with pytest.raises(AdbError) as exc:
        _backend_with_dev(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert exc.value.code == "timeout"


def test_ensure_frida_server_notes_a_launch_that_left_nothing_visible(
    tmp_path: Path,
) -> None:
    dev = _FridaDev({("ps", "-A"): "", ("ps",): ""}, sync=_Sync())
    payload = _backend_with_dev(dev).ensure_frida_server("emulator-5554")
    assert payload["running"] in (False, None)
    assert "note" in payload


def test_ensure_frida_server_notes_a_launch_that_timed_out() -> None:
    class _LaunchTimeoutDev(_FridaDev):
        def shell(self, args: Any, timeout: float | None = None) -> str:
            if isinstance(args, str) and "su -c" in args:
                raise TimeoutError("su prompt hung")
            return super().shell(args, timeout)

    dev = _LaunchTimeoutDev({("ps", "-A"): "", ("ps",): ""})
    payload = _backend_with_dev(dev).ensure_frida_server("emulator-5554")
    assert "note" in payload
    assert "verify manually" in payload["note"]


class _ForwardDev:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error
        self.calls: list[tuple[str, str]] = []

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        self.calls.append((local, remote))
        if self._error is not None:
            raise self._error


def test_forward_releases_the_slot_when_the_backend_raises_adberror() -> None:
    dev = _ForwardDev(error=AdbError("backend_error", "forward refused"))
    backend = _backend_with_dev(dev)
    with pytest.raises(AdbError):
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    # The reserved slot must not leak after the failure.
    assert backend._forwards == []


def test_forward_wraps_and_releases_the_slot_on_a_generic_failure() -> None:
    dev = _ForwardDev(error=RuntimeError("adb forward broke"))
    backend = _backend_with_dev(dev)
    with pytest.raises(AdbError) as exc:
        backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert exc.value.code == "backend_error"
    assert backend._forwards == []


def test_forward_records_a_successful_slot() -> None:
    dev = _ForwardDev()
    backend = _backend_with_dev(dev)
    payload = backend.forward("emulator-5554", "tcp:5000", "tcp:6000")
    assert payload == {"local": "tcp:5000", "remote": "tcp:6000"}
    assert backend._forwards == [("emulator-5554", "tcp:5000")]
