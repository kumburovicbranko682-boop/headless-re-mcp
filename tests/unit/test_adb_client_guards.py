"""Helper-level and per-method guards of the ADB device backend.

The paginating read-outs are pinned in ``test_adb_device_readouts.py``; this
covers the parsing and honesty helpers underneath them (host-error detection,
APK package sniffing, pid resolution, timeout-aware invocation) and the error
branches each device method maps to a structured ``AdbError``. All of it runs
against injected fakes -- no adbutils, no emulator -- because that is exactly
where the honesty lives: a stalled shell must become a ``timeout``/``backend_error``
envelope, and a probe that cannot run must leave a tri-state ``null`` rather than
a false success.
"""

from __future__ import annotations

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
    _check_forward_spec,
    _device_info_row,
    _device_shell,
    _file_mode_size,
    _frida_server_visible,
    _is_host_error_output,
    _pids_for_package,
    _pm_path,
    _require_apk_zip,
)


class _ShellDev:
    """A fake adbutils device whose ``shell`` answers by the command's tokens."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], Any] | None = None,
        *,
        raise_for: tuple[tuple[str, ...], ...] = (),
        **attrs: Any,
    ) -> None:
        self._responses = responses or {}
        self._raise_for = set(raise_for)
        self.calls: list[Any] = []
        for key, value in attrs.items():
            setattr(self, key, value)

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens in self._raise_for:
            raise RuntimeError("device stalled")
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                if isinstance(output, Exception):
                    raise output
                return str(output)
        return ""


def _backend(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# ---------------------------------------------------------------------------
# timeout-aware invocation helpers
# ---------------------------------------------------------------------------
def test_accepts_timeout_covers_named_varkw_and_uninspectable() -> None:
    def named(timeout: float = 0.0) -> None: ...
    def varkw(**kwargs: Any) -> None: ...
    def neither(x: int) -> None: ...

    assert _accepts_timeout(named) is True
    assert _accepts_timeout(varkw) is True
    assert _accepts_timeout(neither) is False
    # A non-introspectable callable is treated as not accepting a timeout.
    assert _accepts_timeout(object()) is False


def test_accepted_kwargs_filters_to_the_named_parameters() -> None:
    def only_flags(flags: list[str]) -> None: ...
    def anything(**kwargs: Any) -> None: ...

    assert _accepted_kwargs(only_flags, {"flags": ["-r"], "nolaunch": True}) == {"flags": ["-r"]}
    assert _accepted_kwargs(anything, {"a": 1, "b": 2}) == {"a": 1, "b": 2}
    assert _accepted_kwargs(object(), {"a": 1}) == {}


def test_device_shell_maps_timeout_and_backend_errors() -> None:
    passthrough = _ShellDev()
    assert _device_shell(passthrough, "echo") == ""

    class _Timeout:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("operation timed out")

    with pytest.raises(AdbError) as timed:
        _device_shell(_Timeout(), "getprop")
    assert timed.value.code == "timeout"

    class _Broken:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("adb transport gone")

    with pytest.raises(AdbError) as broke:
        _device_shell(_Broken(), "getprop")
    assert broke.value.code == "backend_error"


def test_device_shell_passes_through_an_adb_error() -> None:
    class _Raiser:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise AdbError("invalid_params", "already structured")

    with pytest.raises(AdbError) as caught:
        _device_shell(_Raiser(), "x")
    assert caught.value.code == "invalid_params"


def test_call_forwards_timeout_and_maps_a_timeout_error() -> None:
    def slow(timeout: float | None = None) -> str:
        raise RuntimeError("timed out")

    with pytest.raises(AdbError) as caught:
        _call(slow, timeout=5.0)
    assert caught.value.code == "timeout"

    def structured(timeout: float | None = None) -> str:
        raise AdbError("not_found", "device gone")

    with pytest.raises(AdbError) as passed:
        _call(structured, timeout=5.0)
    assert passed.value.code == "not_found"


# ---------------------------------------------------------------------------
# frida-server probe
# ---------------------------------------------------------------------------
def test_frida_server_visible_reads_the_process_table() -> None:
    up = _ShellDev({("ps", "-A"): "1 root frida-server\n2 root init"})
    assert _frida_server_visible(up) is True

    fallback = _ShellDev({("ps", "-A"): "no match", ("ps",): "frida-server here"})
    assert _frida_server_visible(fallback) is True

    class _Dead:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("offline")

    # An unreadable process table is null (unknown), not a definite "not running".
    assert _frida_server_visible(_Dead()) is None


# ---------------------------------------------------------------------------
# open_transport rebinding
# ---------------------------------------------------------------------------
def test_bind_open_transport_leaves_a_device_without_the_method() -> None:
    dev = SimpleNamespace()
    assert _bind_open_transport(dev, 5.0) is dev


def test_bind_open_transport_falls_back_across_signatures() -> None:
    seen: list[tuple[Any, ...]] = []

    class _Dev:
        def open_transport(self, command: Any = None) -> str:
            # Only the positional single-arg form works; the kw and two-arg
            # forms raise TypeError, exercising both fallbacks.
            seen.append((command,))
            return "transport"

    dev = _bind_open_transport(_Dev(), 5.0)
    assert dev.open_transport() == "transport"
    assert seen == [(None,)]


def test_bind_open_transport_returns_device_when_binding_is_refused() -> None:
    class _Frozen:
        __slots__ = ()

        def open_transport(self, command: Any = None, timeout: float | None = None) -> str:
            return "x"

    frozen = _Frozen()
    # __slots__ makes the attribute assignment raise; the original is returned.
    assert _bind_open_transport(frozen, 5.0) is frozen


# ---------------------------------------------------------------------------
# small parsers
# ---------------------------------------------------------------------------
def test_device_info_row_reads_objects_and_tuples() -> None:
    obj = _device_info_row(SimpleNamespace(serial="emulator-5554", state="device"))
    assert obj == {"serial": "emulator-5554", "state": "device"}
    tup = _device_info_row(("emulator-5556", "offline"))
    assert tup == {"serial": "emulator-5556", "state": "offline"}
    assert _device_info_row(SimpleNamespace())["state"] == "unknown"


def test_file_mode_size_reads_objects_and_tuples() -> None:
    assert _file_mode_size(SimpleNamespace(mode=0o100644, size=42)) == (0o100644, 42)
    assert _file_mode_size((0o40755, 0)) == (0o40755, 0)


def test_is_host_error_output_distinguishes_errors_from_real_output() -> None:
    assert _is_host_error_output("adb: device offline") is True
    assert _is_host_error_output("error: no devices/emulators found") is True
    assert _is_host_error_output("") is False
    # A real logcat line that merely mentions "error" is not a host error.
    assert _is_host_error_output("10-01 12:00:00 E/App: an error happened") is False


# ---------------------------------------------------------------------------
# APK package sniffing
# ---------------------------------------------------------------------------
def _apk_with_manifest(path: Path, manifest: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    return path


def test_require_apk_zip_refuses_a_non_archive(tmp_path: Path) -> None:
    junk = tmp_path / "not.apk"
    junk.write_bytes(b"not a zip")
    with pytest.raises(AdbError) as caught:
        _require_apk_zip(junk)
    assert caught.value.code == "invalid_params"


def test_apk_package_name_reads_a_plain_text_manifest(tmp_path: Path) -> None:
    apk = _apk_with_manifest(
        tmp_path / "a.apk", b'<manifest package="com.example.app"></manifest>'
    )
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_falls_back_to_utf16_scan(tmp_path: Path) -> None:
    manifest = "junk package com.example.legit end".encode("utf-16-le")
    apk = _apk_with_manifest(tmp_path / "b.apk", manifest)
    assert _apk_package_name(apk) == "com.example.legit"


def test_apk_package_name_returns_none_without_a_package(tmp_path: Path) -> None:
    apk = _apk_with_manifest(tmp_path / "c.apk", "no ids here".encode("utf-16-le"))
    assert _apk_package_name(apk) is None


def test_apk_package_name_returns_none_for_a_broken_archive(tmp_path: Path) -> None:
    empty = tmp_path / "d.apk"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("other.txt", b"x")
    assert _apk_package_name(empty) is None


# ---------------------------------------------------------------------------
# pm path / pidof honesty
# ---------------------------------------------------------------------------
def test_pm_path_returns_the_apk_path_or_none() -> None:
    found = _ShellDev({("pm", "path"): "package:/data/app/com.x/base.apk"})
    assert _pm_path(found, "com.x") == "/data/app/com.x/base.apk"
    absent = _ShellDev({("pm", "path"): ""})
    assert _pm_path(absent, "com.x") is None


def test_pm_path_raises_on_a_host_error() -> None:
    dead = _ShellDev({("pm", "path"): "adb: device offline"})
    with pytest.raises(AdbError) as caught:
        _pm_path(dead, "com.x")
    assert caught.value.code == "backend_error"


def test_pids_for_package_parses_pidof_and_falls_back_to_ps() -> None:
    numeric = _ShellDev({("pidof",): "111 222"})
    assert _pids_for_package(numeric, "com.x") == [111, 222]

    empty = _ShellDev({("pidof",): ""})
    assert _pids_for_package(empty, "com.x") == []

    fallback = _ShellDev(
        {
            ("pidof",): "/system/bin/sh: pidof: not found",
            ("ps", "-A"): "u0 4321 1 0 0 x S com.x\n",
        }
    )
    assert _pids_for_package(fallback, "com.x") == [4321]


def test_pids_for_package_is_null_when_pidof_cannot_run() -> None:
    class _Dead:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            raise RuntimeError("timed out")

    assert _pids_for_package(_Dead(), "com.x") is None


# ---------------------------------------------------------------------------
# forward spec validation
# ---------------------------------------------------------------------------
def test_check_forward_spec_accepts_valid_and_refuses_invalid() -> None:
    _check_forward_spec("tcp:8080", side="local")
    _check_forward_spec("localabstract:foo", side="local")
    _check_forward_spec("jdwp:1234", side="remote", allow_jdwp=True)
    for bad in ("tcp:0", "tcp:70000", "jdwp:1", "weird:1", "tcp:abc"):
        with pytest.raises(AdbError) as caught:
            _check_forward_spec(bad, side="local")
        assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# capability gating and connect
# ---------------------------------------------------------------------------
def test_client_without_adbutils_is_capability_unavailable() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_connect_rejects_a_bad_port_and_maps_failures() -> None:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(  # type: ignore[method-assign]
        connect=lambda endpoint, timeout=0.0: "connected to " + endpoint
    )
    with pytest.raises(AdbError) as bad_port:
        backend.connect(port=99999)
    assert bad_port.value.code == "invalid_params"

    payload = backend.connect(host="127.0.0.1", port=5555)
    assert payload["connected"] is True
    assert payload["endpoint"] == "127.0.0.1:5555"

    backend._client = lambda **kwargs: SimpleNamespace(  # type: ignore[method-assign]
        connect=lambda endpoint, timeout=0.0: (_ for _ in ()).throw(RuntimeError("refused"))
    )
    with pytest.raises(AdbError) as failed:
        backend.connect(port=5555)
    assert failed.value.code == "backend_error"


# ---------------------------------------------------------------------------
# per-method error / honesty branches
# ---------------------------------------------------------------------------
def test_info_maps_a_shell_failure_to_backend_error() -> None:
    dev = _ShellDev(
        {("getprop",): "x"},
        get_state=lambda timeout=None: "device",
        raise_for=(("getprop", "ro.product.model"),),
    )
    with pytest.raises(AdbError) as caught:
        _backend(dev).info("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_is_honest_when_the_foreground_is_unreadable() -> None:
    dev = _ShellDev(app_current=lambda timeout=None: SimpleNamespace(package=None, activity=None))
    with pytest.raises(AdbError) as caught:
        _backend(dev).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"


def test_current_activity_returns_the_foreground_package() -> None:
    dev = _ShellDev(
        app_current=lambda timeout=None: SimpleNamespace(package="com.x", activity=".Main")
    )
    payload = _backend(dev).current_activity("emulator-5554")
    assert payload == {"package": "com.x", "activity": ".Main"}


def test_launch_notes_when_the_foreground_cannot_be_read() -> None:
    def boom(timeout: float | None = None) -> Any:
        raise RuntimeError("dumpsys unavailable")

    dev = _ShellDev({("monkey",): ""}, app_current=boom)
    payload = _backend(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert "note" in payload


def test_install_rejects_a_missing_or_non_apk(tmp_path: Path) -> None:
    backend = _backend(_ShellDev())
    with pytest.raises(AdbError) as missing:
        backend.install("emulator-5554", str(tmp_path / "absent.apk"))
    assert missing.value.code == "not_found"

    junk = tmp_path / "fake.apk"
    junk.write_bytes(b"not a zip")
    with pytest.raises(AdbError) as non_apk:
        backend.install("emulator-5554", str(junk))
    assert non_apk.value.code == "invalid_params"


def test_install_verifies_the_package_after_a_successful_transfer(tmp_path: Path) -> None:
    apk = _apk_with_manifest(
        tmp_path / "app.apk", b'<manifest package="com.example.app"></manifest>'
    )
    dev = _ShellDev(
        {("pm", "path"): "package:/data/app/com.example.app/base.apk"},
        install=lambda path, **kwargs: None,
    )
    payload = _backend(dev).install("emulator-5554", str(apk))
    assert payload["installed"] is True
    assert payload["package"] == "com.example.app"


def test_install_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    apk = _apk_with_manifest(
        tmp_path / "app.apk", b'<manifest package="com.example.app"></manifest>'
    )

    def explode(path: str, **kwargs: Any) -> None:
        raise RuntimeError("adb: failed to copy")

    dev = _ShellDev(install=explode)
    with pytest.raises(AdbError) as caught:
        _backend(dev).install("emulator-5554", str(apk))
    assert caught.value.code == "backend_error"


def test_uninstall_reports_a_lingering_package(tmp_path: Path) -> None:
    dev = _ShellDev(
        {("pm", "path"): "package:/data/app/com.x/base.apk"},
        uninstall=lambda pkg, **kwargs: None,
    )
    payload = _backend(dev).uninstall("emulator-5554", "com.example.app")
    assert payload["uninstalled"] is False
    assert "note" in payload


def test_push_validates_the_local_file(tmp_path: Path) -> None:
    backend = _backend(_ShellDev())
    with pytest.raises(AdbError) as missing:
        backend.push("emulator-5554", str(tmp_path / "gone.bin"), "/data/local/tmp/x")
    assert missing.value.code == "not_found"


def test_push_transfers_and_reports_the_size(tmp_path: Path) -> None:
    local = tmp_path / "payload.bin"
    local.write_bytes(b"12345")
    dev = _ShellDev(sync=SimpleNamespace(push=lambda src, dst, timeout=None: None))
    payload = _backend(dev).push("emulator-5554", str(local), "/data/local/tmp/x")
    assert payload["size"] == 5
    assert payload["remote"] == "/data/local/tmp/x"


def test_ensure_frida_server_validates_paths_and_short_circuits_when_running() -> None:
    running = _ShellDev({("ps", "-A"): "1 root frida-server"})
    payload = _backend(running).ensure_frida_server("emulator-5554")
    assert payload == {"running": True, "pushed": False, "port": 27042}

    backend = _backend(_ShellDev())
    with pytest.raises(AdbError) as bad_path:
        backend.ensure_frida_server("emulator-5554", remote_path="../etc/passwd")
    assert bad_path.value.code == "invalid_params"

    with pytest.raises(AdbError) as bad_host:
        backend.ensure_frida_server("emulator-5554", bind_host="1.2.3.4:evil")
    assert bad_host.value.code == "invalid_params"


def test_forward_enforces_the_slot_cap() -> None:
    dev = _ShellDev(forward=lambda local, remote, timeout=None: None)
    backend = _backend(dev)
    backend._forwards = [("emulator-5554", f"tcp:{9000 + i}") for i in range(32)]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9999", "tcp:27042")
    assert caught.value.code == "invalid_state"


def test_release_forwards_reports_devices_without_a_remove_api() -> None:
    backend = AdbBackend()
    backend._available = True
    backend._forwards = [("emulator-5554", "tcp:9000")]
    backend._device = lambda serial: SimpleNamespace()  # type: ignore[method-assign]
    result = backend.release_forwards()
    assert result["count"] == 0
    assert result["failed"][0]["local"] == "tcp:9000"
    # The forward is retained for the next attempt rather than forgotten.
    assert ("emulator-5554", "tcp:9000") in backend._forwards


def test_forward_happy_path_reserves_and_binds_the_slot() -> None:
    bound: list[tuple[str, str]] = []
    dev = _ShellDev(
        forward=lambda local, remote, timeout=None: bound.append((local, remote))
    )
    backend = _backend(dev)
    payload = backend.forward("emulator-5554", "tcp:9999", "tcp:27042")
    assert payload == {"local": "tcp:9999", "remote": "tcp:27042"}
    assert bound == [("tcp:9999", "tcp:27042")]
    assert ("emulator-5554", "tcp:9999") in backend._forwards


def test_forward_releases_its_reservation_when_the_bind_fails() -> None:
    def boom(local: str, remote: str, timeout: float | None = None) -> None:
        raise RuntimeError("cannot bind")

    dev = _ShellDev(forward=boom)
    backend = _backend(dev)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:9999", "tcp:27042")
    assert caught.value.code == "backend_error"
    # A failed bind must not leak the slot, or the cap fills with dead entries.
    assert ("emulator-5554", "tcp:9999") not in backend._forwards


# ---------------------------------------------------------------------------
# list_devices fallback, screenshot, pull
# ---------------------------------------------------------------------------
def test_list_devices_falls_back_to_device_list_without_a_list_api() -> None:
    client = SimpleNamespace(
        device_list=lambda: [SimpleNamespace(serial="emulator-5554"), SimpleNamespace(serial="")]
    )
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: client  # type: ignore[method-assign]
    payload = backend.list_devices()
    assert payload["count"] == 2
    assert payload["devices"][0] == {"serial": "emulator-5554", "state": "device"}


def test_list_devices_maps_a_backend_failure() -> None:
    def boom() -> Any:
        raise RuntimeError("adb server gone")

    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: SimpleNamespace(list=boom)  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "backend_error"


class _Image:
    """A minimal PIL-like screenshot that records where it was saved."""

    def __init__(self, blob: bytes) -> None:
        self._blob = blob
        self.saved_to: str | None = None

    def save(self, path: str) -> None:
        self.saved_to = path
        Path(path).write_bytes(self._blob)


def test_screenshot_saves_and_reports_the_size(tmp_path: Path) -> None:
    dev = _ShellDev(screenshot=lambda timeout=None: _Image(b"PNGDATA"))
    out = tmp_path / "shots" / "screen.png"
    payload = _backend(dev).screenshot("emulator-5554", out)
    assert payload["size"] == len(b"PNGDATA")
    assert payload["serial"] == "emulator-5554"
    assert out.read_bytes() == b"PNGDATA"


def test_screenshot_maps_a_capture_failure() -> None:
    def boom(timeout: float | None = None) -> Any:
        raise RuntimeError("no framebuffer")

    dev = _ShellDev(screenshot=boom)
    with pytest.raises(AdbError) as caught:
        _backend(dev).screenshot("emulator-5554", Path("/tmp/does-not-matter.png"))
    assert caught.value.code == "backend_error"


def test_pull_refuses_a_remote_directory(tmp_path: Path) -> None:
    import stat as _stat

    sync = SimpleNamespace(
        stat=lambda remote, timeout=None: SimpleNamespace(mode=_stat.S_IFDIR | 0o755, size=0),
        pull=lambda remote, local, timeout=None: None,
    )
    dev = _ShellDev(sync=sync)
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull("emulator-5554", "/data/local/tmp", tmp_path / "out.bin")
    assert caught.value.code == "invalid_params"


def test_pull_transfers_and_reports_the_size(tmp_path: Path) -> None:
    def pull(remote: str, local: str, timeout: float | None = None) -> None:
        Path(local).write_bytes(b"pulled-bytes")

    sync = SimpleNamespace(
        stat=lambda remote, timeout=None: SimpleNamespace(mode=0o100644, size=12),
        pull=pull,
    )
    dev = _ShellDev(sync=sync)
    out = tmp_path / "out" / "file.bin"
    payload = _backend(dev).pull("emulator-5554", "/data/local/tmp/file.bin", out)
    assert payload["size"] == len(b"pulled-bytes")
    assert out.read_bytes() == b"pulled-bytes"


def test_pull_is_honest_when_no_local_file_is_written(tmp_path: Path) -> None:
    # adb sync can report a clean pull yet write nothing for a missing remote.
    sync = SimpleNamespace(
        stat=lambda remote, timeout=None: SimpleNamespace(mode=0o100644, size=0),
        pull=lambda remote, local, timeout=None: None,
    )
    dev = _ShellDev(sync=sync)
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull("emulator-5554", "/data/local/tmp/gone", tmp_path / "out.bin")
    assert caught.value.code == "not_found"


def test_ensure_frida_server_pushes_the_binary_then_launches(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    pushed: list[tuple[str, str]] = []
    dev = _ShellDev(
        {("ps", "-A"): "1 root init"},  # never visible: push + launch both run
        sync=SimpleNamespace(
            push=lambda src, dst, timeout=None: pushed.append((src, dst))
        ),
    )
    payload = _backend(dev).ensure_frida_server(
        "emulator-5554", server_binary=str(binary)
    )
    assert pushed == [(str(binary), "/data/local/tmp/frida-server")]
    assert payload["pushed"] is True
    # ps still shows nothing after the launch, so the honest reply flags that.
    assert payload["running"] in (False, None)
    assert "note" in payload


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _ShellDev({("ps", "-A"): "1 root init"})
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "absent")
        )
    assert caught.value.code == "not_found"
