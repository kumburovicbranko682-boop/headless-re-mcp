"""Guard, error and version-fallback branches of the ADB (adbutils) backend.

The existing adb tests pin the honest read-outs (logcat truncation, package
paging, install/uninstall tri-states, pull/push caps). This file fills the
error and helper branches around them: the timeout/signature shims tolerate an
uninspectable callable, ``_client``/``_device`` map an unreachable adb server
to the right structured error, every device operation wraps a backend failure
rather than leaking it, ``pull`` refuses a directory or an empty transfer and
bounds its size, ``ensure_frida_server`` validates its inputs and reports what
it could confirm, and ``forward`` frees its reserved slot when the bind fails.
adbutils is never imported: a fake device (and, for the wiring, a fake adbutils
module) stands in, exactly like the sibling suites.
"""

from __future__ import annotations

import sys
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
    _device_info_row,
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _pids_for_package,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


class _ScriptedDev:
    """A device whose ``shell`` answers by the command's leading tokens."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], str] | None = None,
        *,
        raise_for: dict[tuple[str, ...], BaseException] | None = None,
        sync: Any = None,
    ) -> None:
        self._responses = responses or {}
        self._raise_for = raise_for or {}
        self.sync = sync
        self.calls: list[list[str] | str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        for matcher, exc in self._raise_for.items():
            if tokens[: len(matcher)] == matcher:
                raise exc
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def _backend(dev: Any = None) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    if dev is not None:
        backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# ============================================================================
# Timeout / signature shims tolerate an uninspectable callable.
# ============================================================================
def test_accepts_timeout_is_false_when_a_signature_cannot_be_read() -> None:
    # A non-callable has no inspectable signature; the shim must not raise.
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_is_empty_when_a_signature_cannot_be_read() -> None:
    assert _accepted_kwargs(object(), {"timeout": 1}) == {}


def test_accepted_kwargs_keeps_only_the_named_parameters() -> None:
    def target(alpha: int, beta: int) -> None:
        del alpha, beta

    assert _accepted_kwargs(target, {"beta": 2, "gamma": 3}) == {"beta": 2}


# ============================================================================
# _device_shell / _call error mapping.
# ============================================================================
def test_device_shell_reraises_an_adb_error_unchanged() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise AdbError("invalid_state", "already structured")

    with pytest.raises(AdbError) as info:
        _device_shell(_Dev(), "getprop")
    assert info.value.code == "invalid_state"


def test_call_reraises_an_adb_error_unchanged() -> None:
    def method() -> None:
        raise AdbError("invalid_state", "already structured")

    with pytest.raises(AdbError) as info:
        _call(method, timeout=1.0)
    assert info.value.code == "invalid_state"


def test_call_maps_a_timeout_named_exception() -> None:
    def method(timeout: float | None = None) -> None:
        del timeout
        raise RuntimeError("operation timed out")

    with pytest.raises(AdbError) as info:
        _call(method, timeout=1.0)
    assert info.value.code == "timeout"


# ============================================================================
# Small helpers.
# ============================================================================
def test_frida_server_visible_is_none_when_the_probe_fails() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            raise RuntimeError("device stalled")

    assert _frida_server_visible(_Dev()) is None


def test_bind_open_transport_ignores_a_device_without_the_api() -> None:
    dev = SimpleNamespace(open_transport=None)
    assert _bind_open_transport(dev, 1.0) is dev


def test_bind_open_transport_falls_back_through_the_call_forms() -> None:
    seen: list[tuple[Any, ...]] = []

    class _Dev:
        def open_transport(self, *args: Any, **kwargs: Any) -> str:
            if kwargs:
                raise TypeError("no keyword form")
            if len(args) > 1:
                raise TypeError("no two-positional form")
            seen.append(args)
            return "transport"

    dev = _bind_open_transport(_Dev(), 2.0)
    assert dev.open_transport() == "transport"
    assert seen  # the bare single-argument form was reached


def test_bind_open_transport_returns_the_device_when_it_cannot_rebind() -> None:
    class _Dev:
        @property
        def open_transport(self) -> Any:
            return lambda command=None, timeout=None: "t"

    dev = _Dev()
    # The property has no setter, so the rebind is swallowed and dev is returned.
    assert _bind_open_transport(dev, 1.0) is dev


def test_device_info_row_reads_a_single_element_tuple() -> None:
    assert _device_info_row(("emulator-5554",)) == {
        "serial": "emulator-5554",
        "state": "unknown",
    }


def test_file_mode_size_reads_a_two_element_tuple() -> None:
    assert _file_mode_size((0o40755, 4096)) == (0o40755, 4096)


def test_apk_package_name_reads_utf16_when_utf8_decoding_fails(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    text = "x package android.intent.category.LAUNCHER com.example.app"
    with zipfile.ZipFile(apk, "w") as archive:
        # A leading 0xff 0xfe makes the UTF-8 decode raise, forcing the UTF-16
        # fallback; the marker scan then skips the android.* candidate.
        archive.writestr("AndroidManifest.xml", b"\xff\xfe" + text.encode("utf-16-le"))
    assert _apk_package_name(apk) == "com.example.app"


# ============================================================================
# _pids_for_package fallback and bounds.
# ============================================================================
def test_pids_for_package_returns_none_when_the_ps_fallback_fails() -> None:
    dev = _ScriptedDev(
        {("pidof",): "/system/bin/sh: pidof: not found"},
        raise_for={("ps", "-A"): AdbError("timeout", "stalled")},
    )
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_bounds_the_ps_scan_and_skips_pidless_rows() -> None:
    rows = ["user extra com.example.app"]  # a matching row with no numeric pid
    rows += [f"u0 {1000 + index} 1 com.example.app" for index in range(20)]
    dev = _ScriptedDev(
        {
            ("pidof",): "pidof: not found",
            ("ps", "-A"): "\n".join(rows),
        }
    )
    pids = _pids_for_package(dev, "com.example.app")
    assert pids is not None
    assert len(pids) == 16  # the scan stops at the 16-pid ceiling


def test_pids_for_package_returns_none_when_pidof_names_no_pid() -> None:
    dev = _ScriptedDev({("pidof",): "weird-output-with-no-digits"})
    assert _pids_for_package(dev, "com.example.app") is None


# ============================================================================
# Construction, _client, _device wiring (a fake adbutils module).
# ============================================================================
def test_backend_without_adbutils_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    assert backend.available is False


def test_client_reports_capability_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    with pytest.raises(AdbError) as info:
        backend._client()
    assert info.value.code == "capability_unavailable"


def test_client_sets_the_adb_path_and_falls_back_without_socket_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    def factory(host: str, port: int, socket_timeout: float | None = None) -> str:
        if socket_timeout is not None:
            raise TypeError("older adbutils has no socket_timeout")
        return f"{host}:{port}"

    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=factory)
    backend._adb_path = tmp_path / "adb"
    assert backend._client() == "127.0.0.1:5037"
    assert os.environ["ADBUTILS_ADB_PATH"] == str(tmp_path / "adb")


def test_client_maps_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch

    def factory(**kwargs: Any) -> str:
        del kwargs
        raise RuntimeError("connection timed out")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=factory)
    with pytest.raises(AdbError) as info:
        backend._client()
    assert info.value.code == "timeout"


def test_client_maps_an_unreachable_server() -> None:
    def factory(**kwargs: Any) -> str:
        del kwargs
        raise RuntimeError("connection refused")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=factory)
    with pytest.raises(AdbError) as info:
        backend._client()
    assert info.value.code == "backend_error"


def test_device_binds_the_transport_on_success() -> None:
    dev = SimpleNamespace(open_transport=None)
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(device=lambda serial: dev)  # type: ignore[method-assign]
    assert backend._device("emulator-5554") is dev


def test_device_maps_a_not_found() -> None:
    def device(serial: str) -> Any:
        del serial
        raise RuntimeError("device offline")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(device=device)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend._device("emulator-5554")
    assert info.value.code == "not_found"


def test_device_maps_a_timeout() -> None:
    def device(serial: str) -> Any:
        del serial
        raise RuntimeError("transport timed out")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(device=device)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend._device("emulator-5554")
    assert info.value.code == "timeout"


# ============================================================================
# list_devices / connect error mapping.
# ============================================================================
def test_list_devices_maps_a_backend_error() -> None:
    def lister() -> list[Any]:
        raise RuntimeError("adb server gone")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(list=lister)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.list_devices()
    assert info.value.code == "backend_error"


def test_list_devices_maps_a_timeout() -> None:
    def lister() -> list[Any]:
        raise RuntimeError("list timed out")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(list=lister)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.list_devices()
    assert info.value.code == "timeout"


def test_connect_rejects_a_port_out_of_range() -> None:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.connect(port=70000)
    assert info.value.code == "invalid_params"


def test_connect_maps_a_backend_error() -> None:
    def connect(endpoint: str, timeout: float | None = None) -> str:
        del endpoint, timeout
        raise RuntimeError("connection refused")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(connect=connect)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.connect(port=5555)
    assert info.value.code == "backend_error"


# ============================================================================
# info / properties / packages parsing.
# ============================================================================
def test_info_maps_a_backend_error() -> None:
    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            del timeout
            raise RuntimeError("adb dead")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).info("emulator-5554")
    assert info.value.code == "backend_error"


def test_properties_skips_lines_that_are_not_key_values() -> None:
    dev = _ScriptedDev({("getprop",): "[ro.a]: [1]\ngarbage line\n[ro.b]: [2]"})
    payload = _backend(dev).properties("emulator-5554")
    assert payload["properties"] == {"ro.a": "1", "ro.b": "2"}


def test_packages_skips_non_package_and_empty_names() -> None:
    listing = "not a package line\npackage:\npackage:com.a"
    dev = _ScriptedDev({("pm", "list", "packages"): listing})
    payload = _backend(dev).packages("emulator-5554")
    assert payload["packages"] == ["com.a"]


# ============================================================================
# install / uninstall verification and error mapping.
# ============================================================================
def _apk_with_package(path: Path, package: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f'<manifest package="{package}"/>')


def test_install_maps_a_backend_error(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            del path, timeout, kwargs
            raise RuntimeError("pm install failed")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).install("emulator-5554", str(apk))
    assert info.value.code == "backend_error"


def test_install_is_false_when_pm_path_lists_no_package(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            del path, timeout, kwargs

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return "unrelated diagnostic line\n"

    payload = _backend(_Dev()).install("emulator-5554", str(apk))
    assert payload["installed"] is False


def test_uninstall_maps_a_backend_error() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            del package, timeout
            raise RuntimeError("pm uninstall failed")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert info.value.code == "backend_error"


# ============================================================================
# launch / force_stop / current_activity / screenshot.
# ============================================================================
def test_launch_maps_a_shell_error() -> None:
    dev = _ScriptedDev(raise_for={("monkey",): RuntimeError("no monkey")})
    with pytest.raises(AdbError) as info:
        _backend(dev).launch("emulator-5554", "com.example.app")
    assert info.value.code == "backend_error"


def test_launch_notes_when_the_foreground_cannot_be_read() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            raise RuntimeError("dumpsys failed")

    payload = _backend(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "note" in payload


def test_force_stop_maps_a_shell_error() -> None:
    dev = _ScriptedDev(raise_for={("am", "force-stop"): RuntimeError("boom")})
    with pytest.raises(AdbError) as info:
        _backend(dev).force_stop("emulator-5554", "com.example.app")
    assert info.value.code == "backend_error"


def test_current_activity_maps_a_backend_error() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            raise RuntimeError("dumpsys failed")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).current_activity("emulator-5554")
    assert info.value.code == "backend_error"


def test_screenshot_saves_and_reports_its_size(tmp_path: Path) -> None:
    class _Image:
        def save(self, path: str) -> None:
            Path(path).write_bytes(b"PNGDATA")

    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            del timeout
            return _Image()

    out = tmp_path / "shot.png"
    payload = _backend(_Dev()).screenshot("emulator-5554", out)
    assert payload["size"] == 7
    assert out.read_bytes() == b"PNGDATA"


def test_screenshot_maps_a_capture_error(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            del timeout
            raise RuntimeError("no framebuffer")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "x.png")
    assert info.value.code == "backend_error"


# ============================================================================
# pull edge cases.
# ============================================================================
class _PullSync:
    def __init__(self, *, action: str) -> None:
        self._action = action

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        raise RuntimeError("stat unavailable")  # best-effort probe fails

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        target = Path(local)
        if self._action == "write":
            target.write_bytes(b"data")
        elif self._action == "dir":
            target.mkdir()
        elif self._action == "nothing":
            return
        elif self._action == "oversize":
            with target.open("wb") as handle:
                handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)


def test_pull_proceeds_when_the_stat_probe_is_unavailable(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=_PullSync(action="write"))
    payload = _backend(dev).pull("emulator-5554", "/sdcard/ok.bin", tmp_path / "ok.bin")
    assert payload["size"] == 4


def test_pull_maps_a_backend_error_without_a_sync_channel(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=None)
    with pytest.raises(AdbError) as info:
        _backend(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert info.value.code == "backend_error"


def test_pull_refuses_a_pulled_directory(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=_PullSync(action="dir"))
    with pytest.raises(AdbError) as info:
        _backend(dev).pull("emulator-5554", "/sdcard/d", tmp_path / "out_dir")
    assert info.value.code == "invalid_params"


def test_pull_reports_not_found_when_nothing_was_written(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=_PullSync(action="nothing"))
    with pytest.raises(AdbError) as info:
        _backend(dev).pull("emulator-5554", "/sdcard/gone", tmp_path / "out.bin")
    assert info.value.code == "not_found"


def test_pull_refuses_a_file_over_the_cap_after_transfer(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=_PullSync(action="oversize"))
    with pytest.raises(AdbError) as info:
        _backend(dev).pull("emulator-5554", "/sdcard/big", tmp_path / "big.bin")
    assert info.value.code == "too_large"


# ============================================================================
# push edge cases.
# ============================================================================
def test_push_maps_a_local_stat_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local = tmp_path / "s.bin"
    local.write_bytes(b"hi")
    real_stat = Path.stat
    seen = {"count": 0}

    def fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == local:
            seen["count"] += 1
            if seen["count"] >= 2:  # is_file() stats once; the explicit stat() is next
                raise OSError("stat vanished")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    backend = _backend(SimpleNamespace(sync=SimpleNamespace()))
    with pytest.raises(AdbError) as info:
        backend.push("emulator-5554", str(local), "/sdcard/s")
    assert info.value.code == "backend_error"


def test_push_maps_a_backend_error(tmp_path: Path) -> None:
    local = tmp_path / "s.bin"
    local.write_bytes(b"hi")

    class _PushSync:
        def push(self, local_path: str, remote: str, timeout: float | None = None) -> None:
            del local_path, remote, timeout
            raise RuntimeError("transfer failed")

    dev = SimpleNamespace(sync=_PushSync())
    with pytest.raises(AdbError) as info:
        _backend(dev).push("emulator-5554", str(local), "/sdcard/s")
    assert info.value.code == "backend_error"


# ============================================================================
# ensure_frida_server.
# ============================================================================
class _FridaDev:
    def __init__(
        self,
        *,
        visible_before: bool = False,
        visible_after: bool = True,
        push_raises: bool = False,
        launch_raises: bool = False,
    ) -> None:
        self._visible_before = visible_before
        self._visible_after = visible_after
        self._push_raises = push_raises
        self._launch_raises = launch_raises
        self._launched = False
        self.sync = self

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        if self._push_raises:
            raise RuntimeError("push failed")

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        text = args if isinstance(args, str) else " ".join(args)
        if text.startswith("su -c"):
            if self._launch_raises:
                raise RuntimeError("su timed out")
            self._launched = True
            return ""
        if text.startswith("ps"):
            visible = self._visible_after if self._launched else self._visible_before
            return "frida-server\n" if visible else "init\n"
        return ""


def test_ensure_frida_rejects_a_bad_remote_path() -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server("emulator-5554", remote_path="bad path")
    assert info.value.code == "invalid_params"


def test_ensure_frida_rejects_a_missing_server_binary(tmp_path: Path) -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert info.value.code == "not_found"


def test_ensure_frida_pushes_and_reports_running(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    payload = _backend(_FridaDev(visible_after=True)).ensure_frida_server(
        "emulator-5554", server_binary=str(binary)
    )
    assert payload["running"] is True
    assert payload["pushed"] is True


def test_ensure_frida_maps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev(push_raises=True)).ensure_frida_server(
            "emulator-5554", server_binary=str(binary)
        )
    assert info.value.code == "backend_error"


def test_ensure_frida_notes_when_launch_cannot_be_confirmed() -> None:
    payload = _backend(_FridaDev(launch_raises=True)).ensure_frida_server("emulator-5554")
    assert payload["pushed"] is False
    assert "note" in payload


# ============================================================================
# forward slot release and release_forwards retry.
# ============================================================================
def test_forward_releases_the_slot_on_an_adb_error() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            del local, remote, timeout
            raise AdbError("timeout", "bind stalled")

    backend = _backend(_Dev())
    with pytest.raises(AdbError) as info:
        backend.forward("emulator-5554", "tcp:8000", "tcp:9000")
    assert info.value.code == "timeout"
    assert backend._forwards == []


def test_forward_maps_a_backend_error_and_releases_the_slot() -> None:
    class _Dev:
        def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
            del local, remote, timeout
            raise RuntimeError("bind refused")

    backend = _backend(_Dev())
    with pytest.raises(AdbError) as info:
        backend.forward("emulator-5554", "tcp:8000", "tcp:9000")
    assert info.value.code == "backend_error"
    assert backend._forwards == []


def test_release_forwards_re_adds_failures_without_duplicating() -> None:
    class _Dev:
        forward_remove = None  # no remover API -> the removal fails and is retried

    backend = _backend(_Dev())
    # Two identical held forwards: the retry re-add must not duplicate the key.
    backend._forwards = [("emulator-5554", "tcp:8000"), ("emulator-5554", "tcp:8000")]
    result = backend.release_forwards()
    assert result["count"] == 0
    assert result["failed"]
    assert backend._forwards == [("emulator-5554", "tcp:8000")]


# ============================================================================
# Functional branches: paging, foreground reads, capture cap.
# ============================================================================
def test_properties_reports_has_more_past_the_limit() -> None:
    dev = _ScriptedDev({("getprop",): "[a]: [1]\n[b]: [2]\n[c]: [3]"})
    payload = _backend(dev).properties("emulator-5554", limit=2)
    assert payload["has_more"] is True
    assert payload["count"] == 2


def test_launch_confirms_the_foreground_package() -> None:
    class _Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            return SimpleNamespace(package="com.example.app", activity=".Main")

    payload = _backend(_Dev()).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["foreground"] == "com.example.app"


def test_current_activity_reports_the_foreground() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            return SimpleNamespace(package="com.example.app", activity=".Main")

    payload = _backend(_Dev()).current_activity("emulator-5554")
    assert payload == {"package": "com.example.app", "activity": ".Main"}


def test_current_activity_rejects_an_empty_foreground() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            return SimpleNamespace(package=None, activity=None)

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).current_activity("emulator-5554")
    assert info.value.code == "backend_error"


def test_screenshot_refuses_an_image_over_the_cap(tmp_path: Path) -> None:
    class _Image:
        def save(self, path: str) -> None:
            with Path(path).open("wb") as handle:
                handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    class _Dev:
        def screenshot(self, timeout: float | None = None) -> _Image:
            del timeout
            return _Image()

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "big.png")
    assert info.value.code == "too_large"


def test_ensure_frida_rejects_a_bad_bind_host() -> None:
    with pytest.raises(AdbError) as info:
        _backend(_FridaDev()).ensure_frida_server("emulator-5554", bind_host="1.2.3.4:5")
    assert info.value.code == "invalid_params"


def test_ensure_frida_is_a_noop_when_already_running() -> None:
    payload = _backend(_FridaDev(visible_before=True)).ensure_frida_server("emulator-5554")
    assert payload == {"running": True, "pushed": False, "port": 27042}


def test_ensure_frida_notes_when_the_server_is_not_visible_after_launch() -> None:
    payload = _backend(_FridaDev(visible_after=False)).ensure_frida_server("emulator-5554")
    assert payload["running"] is False
    assert "note" in payload


# ============================================================================
# Structured errors pass through the operation wrappers unwrapped.
# ============================================================================
def test_client_reraises_an_adb_error() -> None:
    def factory(**kwargs: Any) -> str:
        del kwargs
        raise AdbError("invalid_state", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=factory)
    with pytest.raises(AdbError) as info:
        backend._client()
    assert info.value.code == "invalid_state"


def test_device_reraises_an_adb_error() -> None:
    def device(serial: str) -> Any:
        del serial
        raise AdbError("invalid_state", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(device=device)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend._device("emulator-5554")
    assert info.value.code == "invalid_state"


def test_list_devices_reraises_an_adb_error() -> None:
    def lister() -> list[Any]:
        raise AdbError("invalid_state", "structured")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(list=lister)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as info:
        backend.list_devices()
    assert info.value.code == "invalid_state"


def test_info_reraises_an_adb_error() -> None:
    class _Dev:
        def get_state(self, timeout: float | None = None) -> str:
            del timeout
            raise AdbError("timeout", "structured")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).info("emulator-5554")
    assert info.value.code == "timeout"


def test_install_reraises_an_adb_error(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")

    class _Dev:
        def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
            del path, timeout, kwargs
            raise AdbError("timeout", "structured")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).install("emulator-5554", str(apk))
    assert info.value.code == "timeout"


def test_uninstall_reraises_an_adb_error() -> None:
    class _Dev:
        def uninstall(self, package: str, timeout: float | None = None) -> None:
            del package, timeout
            raise AdbError("timeout", "structured")

        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return ""

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).uninstall("emulator-5554", "com.example.app")
    assert info.value.code == "timeout"


def test_current_activity_reraises_an_adb_error() -> None:
    class _Dev:
        def app_current(self, timeout: float | None = None) -> Any:
            del timeout
            raise AdbError("timeout", "structured")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).current_activity("emulator-5554")
    assert info.value.code == "timeout"


def test_screenshot_reraises_an_adb_error(tmp_path: Path) -> None:
    class _Dev:
        def screenshot(self, timeout: float | None = None) -> Any:
            del timeout
            raise AdbError("timeout", "structured")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).screenshot("emulator-5554", tmp_path / "x.png")
    assert info.value.code == "timeout"


class _AdbErrorPullSync:
    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        raise RuntimeError("stat unavailable")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, local, timeout
        raise AdbError("timeout", "structured")


def test_pull_reraises_an_adb_error(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=_AdbErrorPullSync())
    with pytest.raises(AdbError) as info:
        _backend(dev).pull("emulator-5554", "/sdcard/x", tmp_path / "out.bin")
    assert info.value.code == "timeout"


def test_push_reraises_an_adb_error(tmp_path: Path) -> None:
    local = tmp_path / "s.bin"
    local.write_bytes(b"hi")

    class _PushSync:
        def push(self, local_path: str, remote: str, timeout: float | None = None) -> None:
            del local_path, remote, timeout
            raise AdbError("timeout", "structured")

    dev = SimpleNamespace(sync=_PushSync())
    with pytest.raises(AdbError) as info:
        _backend(dev).push("emulator-5554", str(local), "/sdcard/s")
    assert info.value.code == "timeout"


def test_ensure_frida_reraises_an_adb_error_on_push(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")

    class _Dev(_FridaDev):
        def push(self, local: str, remote: str, timeout: float | None = None) -> None:
            del local, remote, timeout
            raise AdbError("timeout", "structured")

    with pytest.raises(AdbError) as info:
        _backend(_Dev()).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert info.value.code == "timeout"
