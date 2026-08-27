"""Helper and backend error/guard paths for the ADB backend.

The higher-level honesty contracts (install/uninstall tri-state, pull/push
caps, forward bookkeeping, manifest bounds) are pinned in the other
``test_adb_*`` files with injected fake devices. This file fills in the layers
those tests skip past: the signature-probing helpers (``_accepts_timeout`` /
``_accepted_kwargs``), the timeout/backend-error conversions in ``_device_shell``
and ``_call``, the ``open_transport`` deadline shim, the best-effort package and
pid readers, and the ``except`` arms of the client/device/list and per-command
methods. A fake ``adbutils`` module stands in for the optional dependency so the
client-construction paths run without it.
"""

from __future__ import annotations

import sys
import types
import zipfile
from inspect import Parameter, signature
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_mod
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

# ---------------------------------------------------------------------------
# _accepts_timeout / _accepted_kwargs
# ---------------------------------------------------------------------------


def test_accepts_timeout_handles_named_varkw_and_unintrospectable() -> None:
    def named(a: int, timeout: float = 0.0) -> None:
        del a, timeout

    def varkw(a: int, **kwargs: object) -> None:
        del a, kwargs

    def neither(a: int) -> None:
        del a

    assert _accepts_timeout(named) is True
    # adbutils methods often take **kwargs; passing timeout there is accepted.
    assert _accepts_timeout(varkw) is True
    assert _accepts_timeout(neither) is False
    # A non-callable makes inspect.signature raise; that becomes False.
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_filters_or_passes_by_signature() -> None:
    def named(path: str, nolaunch: bool = False) -> None:
        del path, nolaunch

    def varkw(path: str, **kwargs: object) -> None:
        del path, kwargs

    extra = {"nolaunch": True, "flags": ["-r"], "uninstall": False}
    # Only the named parameter survives the filter.
    assert _accepted_kwargs(named, extra) == {"nolaunch": True}
    # **kwargs takes everything.
    assert _accepted_kwargs(varkw, extra) == extra
    # Unintrospectable -> nothing is forwarded.
    assert _accepted_kwargs(object(), extra) == {}
    assert any(
        p.kind is Parameter.VAR_KEYWORD
        for p in signature(varkw).parameters.values()
    )


# ---------------------------------------------------------------------------
# _device_shell
# ---------------------------------------------------------------------------


class _ShellDev:
    def __init__(self, handler: Any) -> None:
        self._handler = handler

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        return self._handler(args)


def test_device_shell_reraises_adb_error_unchanged() -> None:
    def _boom(args: Any) -> str:
        raise AdbError("invalid_state", "already flagged")

    with pytest.raises(AdbError) as caught:
        _device_shell(_ShellDev(_boom), "ps")
    assert caught.value.code == "invalid_state"


def test_device_shell_maps_timeout_and_generic_failures() -> None:
    def _timeout(args: Any) -> str:
        raise RuntimeError("connection timed out")

    def _generic(args: Any) -> str:
        raise RuntimeError("broken pipe")

    with pytest.raises(AdbError) as t:
        _device_shell(_ShellDev(_timeout), "ps")
    assert t.value.code == "timeout"
    with pytest.raises(AdbError) as g:
        _device_shell(_ShellDev(_generic), "ps")
    assert g.value.code == "backend_error"


def test_device_shell_uses_the_no_timeout_form_when_unsupported() -> None:
    class _OldDev:
        def shell(self, args: Any) -> str:  # no timeout parameter
            return f"ran:{args}"

    assert _device_shell(_OldDev(), "getprop") == "ran:getprop"


# ---------------------------------------------------------------------------
# _call
# ---------------------------------------------------------------------------


def test_call_forwards_timeout_only_when_the_method_accepts_it() -> None:
    seen: dict[str, Any] = {}

    def with_timeout(a: int, timeout: float | None = None) -> str:
        seen["timeout"] = timeout
        return "ok"

    def without_timeout(a: int) -> str:
        seen["called"] = True
        return "ok"

    assert _call(with_timeout, 1, timeout=5.0) == "ok"
    assert seen["timeout"] == 5.0
    assert _call(without_timeout, 1, timeout=5.0) == "ok"
    assert seen["called"] is True


def test_call_reraises_adb_error_and_maps_timeout() -> None:
    def adb(a: int, timeout: float | None = None) -> None:
        raise AdbError("permission_denied", "no")

    def timeout(a: int, timeout: float | None = None) -> None:
        raise RuntimeError("op timed out")

    def generic(a: int) -> None:
        raise RuntimeError("plain failure")

    with pytest.raises(AdbError) as a:
        _call(adb, 1, timeout=5.0)
    assert a.value.code == "permission_denied"
    with pytest.raises(AdbError) as t:
        _call(timeout, 1, timeout=5.0)
    assert t.value.code == "timeout"
    # timeout=None: a generic error is passed through untranslated.
    with pytest.raises(RuntimeError):
        _call(generic, 1)


# ---------------------------------------------------------------------------
# _frida_server_visible
# ---------------------------------------------------------------------------


def test_frida_server_visible_true_false_and_probe_failure() -> None:
    class _PsA:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            return "root 123 frida-server\n"

    class _PsFallback:
        def __init__(self) -> None:
            self.calls = 0

        def shell(self, args: Any, timeout: float | None = None) -> str:
            self.calls += 1
            return "" if self.calls == 1 else "u0_a1 frida-server"

    class _Broken:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("device offline")

    assert _frida_server_visible(_PsA()) is True
    assert _frida_server_visible(_PsFallback()) is True
    assert _frida_server_visible(_Broken()) is None


# ---------------------------------------------------------------------------
# _bind_open_transport
# ---------------------------------------------------------------------------


def test_bind_open_transport_no_op_without_the_method() -> None:
    dev = types.SimpleNamespace()
    assert _bind_open_transport(dev, 1.0) is dev


def test_bind_open_transport_falls_back_through_arg_shapes() -> None:
    class _Dev:
        def open_transport(self, command: Any = None) -> str:  # only 1 positional
            return f"transport:{command}"

    dev = _Dev()
    _bind_open_transport(dev, 2.0)
    # The wrapper tries kwargs, then positional+timeout, then bare positional.
    assert dev.open_transport() == "transport:None"  # type: ignore[call-arg]


def test_bind_open_transport_returns_dev_when_assignment_is_blocked() -> None:
    class _ReadOnly:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "t"

    dev = _ReadOnly()
    assert _bind_open_transport(dev, 1.0) is dev


# ---------------------------------------------------------------------------
# _apk_package_name UTF-16 fallback
# ---------------------------------------------------------------------------


def test_apk_package_name_recovers_from_a_utf16_manifest(tmp_path: Path) -> None:
    # 0x00A9 makes the raw bytes invalid UTF-8, forcing the UTF-16 fallback; the
    # android.* candidate ahead of the real id must be skipped.
    text = "\u00a9 xx package android.app.Thing com.example.app tail"
    apk = tmp_path / "u16.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", text.encode("utf-16-le"))
    assert _apk_package_name(apk) == "com.example.app"


# ---------------------------------------------------------------------------
# _pids_for_package
# ---------------------------------------------------------------------------


class _PidDev:
    def __init__(self, handler: Any) -> None:
        self._handler = handler

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        return self._handler(args)


def test_pids_for_package_parses_pidof_digits() -> None:
    dev = _PidDev(lambda args: "1000 1001 1002")
    assert _pids_for_package(dev, "com.example.app") == [1000, 1001, 1002]


def test_pids_for_package_returns_none_when_pidof_output_has_no_pids() -> None:
    dev = _PidDev(lambda args: "weird non-numeric line")
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_falls_back_to_ps_and_caps_at_sixteen() -> None:
    def _handler(args: Any) -> str:
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:1] == ("pidof",):
            return "pidof: not found"
        rows = [f"{100 + i} u0 com.example.app svc" for i in range(20)]
        return "\n".join(rows)

    pids = _pids_for_package(_PidDev(_handler), "com.example.app")
    assert pids is not None
    assert len(pids) == 16


def test_pids_for_package_returns_none_when_ps_probe_errors() -> None:
    def _handler(args: Any) -> str:
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:1] == ("pidof",):
            return "not found"
        raise AdbError("timeout", "ps stalled")

    assert _pids_for_package(_PidDev(_handler), "com.example.app") is None


# ---------------------------------------------------------------------------
# _file_mode_size
# ---------------------------------------------------------------------------


def test_file_mode_size_reads_attrs_and_tuples() -> None:
    obj = types.SimpleNamespace(mode=0o100644, size=42)
    assert _file_mode_size(obj) == (0o100644, 42)
    assert _file_mode_size([0o40755, 7]) == (0o40755, 7)


# ---------------------------------------------------------------------------
# _client / _device construction
# ---------------------------------------------------------------------------


def _backend_with_adbutils(adbutils: Any, *, adb_path: Path | None = None) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = adbutils
    backend._adb_path = adb_path
    return backend


def test_client_refuses_when_adbutils_is_missing() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_sets_the_adb_path_env_and_builds_a_client(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    made: dict[str, Any] = {}

    class _AdbClient:
        def __init__(self, host: str, port: int, socket_timeout: float) -> None:
            made["socket_timeout"] = socket_timeout

    backend = _backend_with_adbutils(
        types.SimpleNamespace(AdbClient=_AdbClient), adb_path=tmp_path / "adb"
    )
    backend._client(socket_timeout=3.0)
    import os

    assert os.environ["ADBUTILS_ADB_PATH"] == str(tmp_path / "adb")
    assert made["socket_timeout"] == 3.0


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    class _AdbClient:
        def __init__(self, host: str, port: int) -> None:  # no socket_timeout
            self.host = host

    backend = _backend_with_adbutils(types.SimpleNamespace(AdbClient=_AdbClient))
    assert backend._client() is not None


def test_client_maps_timeout_and_backend_failures() -> None:
    class _TimeoutClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("adb server timed out")

    class _BrokenClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("connection refused")

    with pytest.raises(AdbError) as t:
        _backend_with_adbutils(types.SimpleNamespace(AdbClient=_TimeoutClient))._client()
    assert t.value.code == "timeout"
    with pytest.raises(AdbError) as b:
        _backend_with_adbutils(types.SimpleNamespace(AdbClient=_BrokenClient))._client()
    assert b.value.code == "backend_error"


def test_device_resolves_and_converts_failures(monkeypatch: Any) -> None:
    class _Client:
        def __init__(self, outcome: str) -> None:
            self._outcome = outcome

        def device(self, serial: str) -> Any:
            if self._outcome == "ok":
                return types.SimpleNamespace(serial=serial)
            if self._outcome == "adberr":
                raise AdbError("invalid_params", "bad serial")
            if self._outcome == "timeout":
                raise RuntimeError("device wait timed out")
            raise RuntimeError("no devices")

    backend = AdbBackend()
    backend._available = True

    backend._client = lambda **kw: _Client("ok")  # type: ignore[method-assign]
    assert backend._device("emulator-5554").serial == "emulator-5554"

    backend._client = lambda **kw: _Client("adberr")  # type: ignore[method-assign]
    with pytest.raises(AdbError) as a:
        backend._device("emulator-5554")
    assert a.value.code == "invalid_params"

    backend._client = lambda **kw: _Client("timeout")  # type: ignore[method-assign]
    with pytest.raises(AdbError) as t:
        backend._device("emulator-5554")
    assert t.value.code == "timeout"

    backend._client = lambda **kw: _Client("missing")  # type: ignore[method-assign]
    with pytest.raises(AdbError) as m:
        backend._device("emulator-5554")
    assert m.value.code == "not_found"


# ---------------------------------------------------------------------------
# list_devices / connect
# ---------------------------------------------------------------------------


def _backend_with_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kw: client  # type: ignore[method-assign]
    return backend


def test_list_devices_uses_device_list_when_there_is_no_list_method() -> None:
    class _Client:
        def device_list(self) -> list[Any]:
            return [types.SimpleNamespace(serial="emulator-5554")]

    payload = _backend_with_client(_Client()).list_devices()
    assert payload["devices"] == [{"serial": "emulator-5554", "state": "device"}]
    assert payload["count"] == 1


def test_list_devices_maps_a_failure_to_backend_error() -> None:
    class _Client:
        def list(self) -> list[Any]:
            raise RuntimeError("adb server gone")

    with pytest.raises(AdbError) as caught:
        _backend_with_client(_Client()).list_devices()
    assert caught.value.code == "backend_error"


def test_connect_rejects_a_bad_port() -> None:
    backend = _backend_with_client(types.SimpleNamespace())
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 70000)
    assert caught.value.code == "invalid_params"


def test_connect_reports_connected_and_wraps_failures() -> None:
    class _OkClient:
        def connect(self, endpoint: str, timeout: float = 0.0) -> str:
            return f"connected to {endpoint}"

    class _BadClient:
        def connect(self, endpoint: str, timeout: float = 0.0) -> str:
            raise RuntimeError("host unreachable")

    ok = _backend_with_client(_OkClient()).connect("127.0.0.1", 5555)
    assert ok["connected"] is True
    with pytest.raises(AdbError) as caught:
        _backend_with_client(_BadClient()).connect("127.0.0.1", 5555)
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# Per-command error/guard paths with an injected device
# ---------------------------------------------------------------------------


def _backend_dev(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


class _CmdDev:
    """Configurable device: each capability is a callable or a default."""

    def __init__(self, **handlers: Any) -> None:
        self._h = handlers
        if "sync" in handlers:
            self.sync = handlers["sync"]

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        handler = self._h.get("shell")
        return handler(args) if handler else ""

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        handler = self._h.get("get_state")
        return handler() if handler else "device"

    def app_current(self, timeout: float | None = None) -> Any:
        del timeout
        handler = self._h.get("app_current")
        if handler:
            return handler()
        return types.SimpleNamespace(package="com.example.app", activity=".Main")

    def screenshot(self, timeout: float | None = None) -> Any:
        del timeout
        handler = self._h.get("screenshot")
        return handler() if handler else None

    def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> Any:
        del timeout, kwargs
        handler = self._h.get("install")
        return handler(path) if handler else None

    def uninstall(self, package: str, timeout: float | None = None) -> Any:
        del timeout
        handler = self._h.get("uninstall")
        return handler(package) if handler else None

    def forward(self, local: str, remote: str, timeout: float | None = None) -> Any:
        del timeout
        handler = self._h.get("forward")
        return handler(local, remote) if handler else None


def test_info_wraps_a_getprop_failure(monkeypatch: Any) -> None:
    def _state() -> str:
        raise RuntimeError("dumpsys blew up")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(get_state=_state)).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_properties_skips_lines_that_do_not_match() -> None:
    text = "garbage line\n[ro.product.model]: [Pixel]\nanother junk"
    payload = _backend_dev(_CmdDev(shell=lambda args: text)).properties("emulator-5554")
    assert payload["properties"] == {"ro.product.model": "Pixel"}
    assert payload["count"] == 1


def test_packages_skips_non_package_and_empty_lines() -> None:
    text = "junk\npackage:\npackage:com.example.app\n"
    payload = _backend_dev(_CmdDev(shell=lambda args: text)).packages("emulator-5554")
    assert payload["packages"] == ["com.example.app"]


def test_install_wraps_a_device_install_failure(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.app"/>')

    def _install(path: str) -> None:
        raise RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(install=_install)).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_uninstall_wraps_a_device_uninstall_failure() -> None:
    def _uninstall(package: str) -> None:
        raise RuntimeError("DELETE_FAILED_INTERNAL_ERROR")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(uninstall=_uninstall)).uninstall(
            "emulator-5554", "com.example.app"
        )
    assert caught.value.code == "backend_error"


def test_launch_reraises_a_shell_adb_error() -> None:
    def _shell(args: Any) -> str:
        raise AdbError("timeout", "monkey stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(shell=_shell)).launch("emulator-5554", "com.example.app")
    assert caught.value.code == "timeout"


def test_launch_returns_null_when_foreground_read_fails() -> None:
    def _app_current() -> Any:
        raise RuntimeError("cannot read foreground")

    payload = _backend_dev(_CmdDev(app_current=_app_current)).launch(
        "emulator-5554", "com.example.app"
    )
    assert payload["launched"] is None
    assert "note" in payload


def test_force_stop_reraises_a_shell_adb_error() -> None:
    def _shell(args: Any) -> str:
        raise AdbError("backend_error", "am failed")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(shell=_shell)).force_stop("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"


def test_current_activity_wraps_a_generic_failure() -> None:
    def _app_current() -> Any:
        raise RuntimeError("dumpsys timeout window")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(app_current=_app_current)).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_reraises_an_adb_error() -> None:
    def _app_current() -> Any:
        raise AdbError("timeout", "app_current stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(app_current=_app_current)).current_activity("emulator-5554")
    assert caught.value.code == "timeout"


def test_screenshot_wraps_a_capture_failure(tmp_path: Path) -> None:
    def _screenshot() -> Any:
        raise RuntimeError("screencap failed")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(screenshot=_screenshot)).screenshot(
            "emulator-5554", tmp_path / "shot.png"
        )
    assert caught.value.code == "backend_error"


def test_screenshot_saves_and_reports_size(tmp_path: Path) -> None:
    class _Image:
        def save(self, path: str) -> None:
            Path(path).write_bytes(b"\x89PNG fake")

    payload = _backend_dev(_CmdDev(screenshot=lambda: _Image())).screenshot(
        "emulator-5554", tmp_path / "shot.png"
    )
    assert payload["size"] == len(b"\x89PNG fake")
    assert Path(payload["path"]).exists()


def test_screenshot_refuses_an_oversized_capture(tmp_path: Path, monkeypatch: Any) -> None:
    class _Image:
        def save(self, path: str) -> None:
            Path(path).write_bytes(b"x")

    monkeypatch.setattr(adb_mod, "capped_file_size", lambda path, cap: (cap + 1, True))
    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(screenshot=lambda: _Image())).screenshot(
            "emulator-5554", tmp_path / "shot.png"
        )
    assert caught.value.code == "too_large"


# ---------------------------------------------------------------------------
# pull / push error arms
# ---------------------------------------------------------------------------


class _Sync:
    def __init__(self, *, stat_raises: bool = False, pull_writes: bytes | None = b"data",
                 pull_raises: bool = False, push_raises: bool = False) -> None:
        self._stat_raises = stat_raises
        self._pull_writes = pull_writes
        self._pull_raises = pull_raises
        self._push_raises = push_raises

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        if self._stat_raises:
            raise RuntimeError("stat unsupported")
        return types.SimpleNamespace(mode=0o100644, size=4)

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        if self._pull_raises:
            raise RuntimeError("pull broke")
        if self._pull_writes is not None:
            Path(local).write_bytes(self._pull_writes)

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        if self._push_raises:
            raise RuntimeError("push broke")


def test_pull_tolerates_a_stat_probe_failure_then_transfers(tmp_path: Path) -> None:
    dev = _CmdDev(sync=_Sync(stat_raises=True, pull_writes=b"ok"))
    payload = _backend_dev(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert payload["size"] == 2


def test_pull_wraps_a_transfer_failure(tmp_path: Path) -> None:
    dev = _CmdDev(sync=_Sync(stat_raises=True, pull_raises=True))
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert caught.value.code == "backend_error"


def test_pull_reports_not_found_when_nothing_was_written(tmp_path: Path) -> None:
    dev = _CmdDev(sync=_Sync(stat_raises=True, pull_writes=None))
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).pull("emulator-5554", "/sdcard/missing", tmp_path / "out.bin")
    assert caught.value.code == "not_found"


def test_pull_refuses_a_pulled_file_over_the_cap(tmp_path: Path, monkeypatch: Any) -> None:
    dev = _CmdDev(sync=_Sync(stat_raises=True, pull_writes=b"data"))
    monkeypatch.setattr(adb_mod, "capped_file_size", lambda path, cap: (cap + 1, True))
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert caught.value.code == "too_large"


def test_push_wraps_a_transfer_failure(tmp_path: Path) -> None:
    local = tmp_path / "f.bin"
    local.write_bytes(b"hi")
    dev = _CmdDev(sync=_Sync(push_raises=True))
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).push("emulator-5554", str(local), "/sdcard/f.bin")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# ensure_frida_server
# ---------------------------------------------------------------------------


def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    dev = _CmdDev(shell=lambda args: "")
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).ensure_frida_server("emulator-5554", remote_path="relative/path")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_reports_a_missing_binary(tmp_path: Path) -> None:
    dev = _CmdDev(shell=lambda args: "")  # ps has no frida-server -> not visible
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "nope")
        )
    assert caught.value.code == "not_found"


def test_ensure_frida_server_wraps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    dev = _CmdDev(shell=lambda args: "", sync=_Sync(push_raises=True))
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert caught.value.code == "backend_error"


def test_ensure_frida_server_reports_visible_after_launch() -> None:
    class _Dev:
        def __init__(self) -> None:
            self.calls = 0

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del timeout
            self.calls += 1
            # First two probes (ps -A, ps) before launch: not visible. After the
            # su -c launch, the process shows up.
            return "frida-server" if self.calls > 3 else ""

    payload = _backend_dev(_Dev()).ensure_frida_server("emulator-5554")
    assert payload["running"] is True


def test_ensure_frida_server_returns_a_note_when_launch_stalls() -> None:
    class _Dev:
        def __init__(self) -> None:
            self.calls = 0

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del timeout
            self.calls += 1
            text = str(args)
            if "su -c" in text:
                raise RuntimeError("su prompt timed out")
            return ""

    payload = _backend_dev(_Dev()).ensure_frida_server("emulator-5554")
    assert "note" in payload
    assert payload["running"] in (None, False)


# ---------------------------------------------------------------------------
# forward error arms (reservation rollback)
# ---------------------------------------------------------------------------


def test_forward_rolls_back_the_reservation_on_an_adb_error() -> None:
    def _forward(local: str, remote: str) -> None:
        raise AdbError("invalid_state", "port busy")

    backend = _backend_dev(_CmdDev(forward=_forward))
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5555", "tcp:27042")
    assert caught.value.code == "invalid_state"
    # The failed reservation must not linger and leak a forward slot.
    assert backend._forwards == []


def test_forward_wraps_a_generic_failure_and_rolls_back() -> None:
    def _forward(local: str, remote: str) -> None:
        raise RuntimeError("adb forward refused")

    backend = _backend_dev(_CmdDev(forward=_forward))
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5555", "tcp:27042")
    assert caught.value.code == "backend_error"
    assert backend._forwards == []


def test_constructor_reports_available_when_adbutils_imports(monkeypatch: Any) -> None:
    monkeypatch.setitem(sys.modules, "adbutils", types.ModuleType("adbutils"))
    backend = AdbBackend()
    assert backend.available is True
    assert backend._adbutils is sys.modules["adbutils"]


def test_client_reraises_an_adb_error_from_construction() -> None:
    class _AdbClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise AdbError("permission_denied", "adb refused")

    with pytest.raises(AdbError) as caught:
        _backend_with_adbutils(types.SimpleNamespace(AdbClient=_AdbClient))._client()
    assert caught.value.code == "permission_denied"


def test_list_devices_reraises_adb_error_and_maps_timeout() -> None:
    class _AdbErr:
        def list(self) -> list[Any]:
            raise AdbError("invalid_state", "server busy")

    class _Timeout:
        def list(self) -> list[Any]:
            raise RuntimeError("list timed out")

    with pytest.raises(AdbError) as a:
        _backend_with_client(_AdbErr()).list_devices()
    assert a.value.code == "invalid_state"
    with pytest.raises(AdbError) as t:
        _backend_with_client(_Timeout()).list_devices()
    assert t.value.code == "timeout"


def test_info_reraises_an_adb_error_from_get_state() -> None:
    def _state() -> str:
        raise AdbError("timeout", "get_state stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(get_state=_state)).info("emulator-5554")
    assert caught.value.code == "timeout"


def test_properties_reports_has_more_when_the_page_fills() -> None:
    text = "[a]: [1]\n[b]: [2]"
    payload = _backend_dev(_CmdDev(shell=lambda args: text)).properties(
        "emulator-5554", limit=1
    )
    assert payload["count"] == 1
    assert payload["has_more"] is True


def test_install_reraises_an_adb_error_from_the_device(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.app"/>')

    def _install(path: str) -> None:
        raise AdbError("timeout", "install stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(install=_install)).install("emulator-5554", str(apk))
    assert caught.value.code == "timeout"


def test_uninstall_reraises_an_adb_error_from_the_device() -> None:
    def _uninstall(package: str) -> None:
        raise AdbError("timeout", "uninstall stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(uninstall=_uninstall)).uninstall(
            "emulator-5554", "com.example.app"
        )
    assert caught.value.code == "timeout"


def test_launch_confirms_the_foreground_package() -> None:
    payload = _backend_dev(_CmdDev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_current_activity_returns_package_and_activity() -> None:
    payload = _backend_dev(_CmdDev()).current_activity("emulator-5554")
    assert payload["package"] == "com.example.app"
    assert payload["activity"] == ".Main"


def test_current_activity_rejects_an_empty_foreground() -> None:
    def _app_current() -> Any:
        return types.SimpleNamespace(package=None, activity=None)

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(app_current=_app_current)).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_screenshot_reraises_an_adb_error(tmp_path: Path) -> None:
    def _screenshot() -> Any:
        raise AdbError("timeout", "screencap stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(screenshot=_screenshot)).screenshot(
            "emulator-5554", tmp_path / "shot.png"
        )
    assert caught.value.code == "timeout"


def test_pull_without_a_sync_channel_reports_backend_error(tmp_path: Path) -> None:
    # A device object with no sync channel: the transfer cannot run, so it is a
    # backend error rather than a silent empty pull.
    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev()).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert caught.value.code == "backend_error"


def test_pull_reraises_an_adb_error_from_the_transfer(tmp_path: Path) -> None:
    class _Sync2:
        def stat(self, remote: str, timeout: float | None = None) -> Any:
            raise RuntimeError("no stat")

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "pull stalled")

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(sync=_Sync2())).pull(
            "emulator-5554", "/sdcard/x", tmp_path / "out.bin"
        )
    assert caught.value.code == "timeout"


def test_pull_refuses_when_the_transfer_wrote_a_directory(tmp_path: Path) -> None:
    class _DirSync:
        def stat(self, remote: str, timeout: float | None = None) -> Any:
            raise RuntimeError("no stat")

        def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
            Path(local).mkdir()

    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(sync=_DirSync())).pull(
            "emulator-5554", "/sdcard/dir", tmp_path / "out"
        )
    assert caught.value.code == "invalid_params"


def test_push_reraises_an_adb_error_from_the_transfer(tmp_path: Path) -> None:
    class _Sync2:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "push stalled")

    local = tmp_path / "f.bin"
    local.write_bytes(b"hi")
    with pytest.raises(AdbError) as caught:
        _backend_dev(_CmdDev(sync=_Sync2())).push(
            "emulator-5554", str(local), "/sdcard/f.bin"
        )
    assert caught.value.code == "timeout"


def test_ensure_frida_server_is_a_no_op_when_already_running() -> None:
    dev = _CmdDev(shell=lambda args: "root 10 frida-server")
    payload = _backend_dev(dev).ensure_frida_server("emulator-5554")
    assert payload == {"running": True, "pushed": False, "port": 27042}


def test_ensure_frida_server_pushes_a_binary_then_reports(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")

    class _PushSync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            del local, remote, timeout

    dev = _CmdDev(shell=lambda args: "", sync=_PushSync())
    payload = _backend_dev(dev).ensure_frida_server(
        "emulator-5554", server_binary=str(binary)
    )
    assert payload["pushed"] is True
    assert payload["running"] in (None, False)


def test_ensure_frida_server_reraises_an_adb_error_from_push(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")

    class _AdbErrSync:
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            raise AdbError("timeout", "push stalled")

    dev = _CmdDev(shell=lambda args: "", sync=_AdbErrSync())
    with pytest.raises(AdbError) as caught:
        _backend_dev(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert caught.value.code == "timeout"


def test_module_error_is_a_runtime_error() -> None:
    assert issubclass(adb_mod.AdbError, RuntimeError)
