"""Device-free coverage for the AdbBackend operation methods.

The parser and compat-shim tests pin the module-level helpers; what was left
uncovered is the orchestration each public method wraps around them -- resolve
the device, run one or two shell/sync calls, and shape the result or map the
failure onto the structured error contract. None of that needs a phone: every
method takes its device from ``_device`` (or its client from ``_client``), so
replacing those with fakes drives the same code a live device would, including
the branches a real gate can only reach by breaking a device on purpose
(install rollback, a pull that lands a directory, a forward that fails after
its slot was reserved, frida-server that never becomes visible).

These fakes speak only the adbutils surface the client actually calls
(``shell`` with an optional ``timeout``, ``sync.stat/pull/push``,
``get_state``, ``app_current``, ``install``, ``uninstall``, ``screenshot``,
``forward``/``forward_remove``), so a signature drift in the client shows up
here as a wrong call, not a silent pass.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

SERIAL = "emulator-5554"


def _backend(dev: Any = None) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace()
    if dev is not None:
        backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _returns(value: Any) -> Any:
    def f(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return value

    return f


def _raises(exc: BaseException) -> Any:
    def f(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise exc

    return f


def _sheller(shell_map: dict[Any, Any]) -> Any:
    def shell(args: Any, timeout: float | None = None) -> str:
        del timeout
        key = tuple(args) if isinstance(args, list) else args
        if key not in shell_map:
            raise KeyError(f"unexpected shell: {key!r}")
        value = shell_map[key]
        if isinstance(value, BaseException):
            raise value
        return str(value)

    return shell


# --- __init__ degradation --------------------------------------------------


def test_construction_degrades_without_adbutils(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "adbutils", None)
    backend = AdbBackend()
    assert backend.available is False
    assert backend._adbutils is None


# --- _client ---------------------------------------------------------------


def test_client_raises_when_unavailable() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "capability_unavailable"


def test_client_builds_with_socket_timeout() -> None:
    seen: dict[str, Any] = {}

    class _AC:
        def __init__(self, host: str, port: int, socket_timeout: float | None = None) -> None:
            seen.update(host=host, port=port, socket_timeout=socket_timeout)

    backend = _backend()
    backend._adbutils = SimpleNamespace(AdbClient=_AC)
    client = backend._client(socket_timeout=12.0)
    assert isinstance(client, _AC)
    assert seen == {"host": "127.0.0.1", "port": 5037, "socket_timeout": 12.0}


def test_client_falls_back_when_socket_timeout_is_unsupported() -> None:
    seen: dict[str, Any] = {}

    class _AC:
        def __init__(self, host: str, port: int) -> None:  # no socket_timeout kwarg
            seen.update(host=host, port=port)

    backend = _backend()
    backend._adbutils = SimpleNamespace(AdbClient=_AC)
    client = backend._client()
    assert isinstance(client, _AC)
    assert seen == {"host": "127.0.0.1", "port": 5037}


def test_client_exports_the_adb_path_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADBUTILS_ADB_PATH", raising=False)

    class _AC:
        def __init__(self, host: str, port: int, socket_timeout: float | None = None) -> None:
            del host, port, socket_timeout

    backend = AdbBackend(adb_path=Path("/opt/tools/adb"))
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=_AC)
    backend._client()
    import os

    assert os.environ["ADBUTILS_ADB_PATH"] == "/opt/tools/adb"


def test_client_maps_a_stall_to_timeout() -> None:
    backend = _backend()
    backend._adbutils = SimpleNamespace(AdbClient=_raises(TimeoutError("connect timed out")))
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "timeout"


def test_client_maps_a_generic_failure_to_backend_error() -> None:
    backend = _backend()
    backend._adbutils = SimpleNamespace(AdbClient=_raises(RuntimeError("no server")))
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "backend_error"
    assert "cannot reach adb server" in caught.value.message


# --- _device ---------------------------------------------------------------


def test_device_resolves_and_returns_the_handle() -> None:
    dev = SimpleNamespace(serial=SERIAL)  # no open_transport -> bind is a no-op
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(device=lambda serial: dev)  # type: ignore[method-assign]
    assert backend._device(SERIAL) is dev


def test_device_maps_a_lookup_failure_to_not_found() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        device=_raises(RuntimeError("no device"))
    )
    with pytest.raises(AdbError) as caught:
        backend._device(SERIAL)
    assert caught.value.code == "not_found"


def test_device_maps_a_stall_to_timeout() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        device=_raises(TimeoutError("transport timed out"))
    )
    with pytest.raises(AdbError) as caught:
        backend._device(SERIAL)
    assert caught.value.code == "timeout"


# --- list_devices ----------------------------------------------------------


def test_list_devices_uses_the_modern_list_api() -> None:
    infos = [
        SimpleNamespace(serial="a", state="device"),
        SimpleNamespace(serial="b", state="offline"),
    ]
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(list=lambda: infos)  # type: ignore[method-assign]
    data = backend.list_devices()
    assert data["count"] == 2
    assert {d["serial"] for d in data["devices"]} == {"a", "b"}


def test_list_devices_falls_back_to_device_list() -> None:
    devices = [SimpleNamespace(serial="a"), SimpleNamespace(serial="b")]
    # No `list` attribute at all forces the device_list() branch.
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(device_list=lambda: devices)  # type: ignore[method-assign]
    data = backend.list_devices()
    assert data["count"] == 2
    assert all(d["state"] == "device" for d in data["devices"])


def test_list_devices_maps_a_failure_to_backend_error() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        device_list=_raises(RuntimeError("adb died"))
    )
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "backend_error"


def test_list_devices_maps_a_stall_to_timeout() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(list=_raises(TimeoutError("timed out")))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "timeout"


# --- connect ---------------------------------------------------------------


def test_connect_rejects_a_bad_port() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 70000)
    assert caught.value.code == "invalid_params"


def test_connect_reports_a_successful_result() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        connect=lambda endpoint, timeout=None: "connected to 127.0.0.1:5555"
    )
    data = backend.connect("127.0.0.1", 5555)
    assert data["endpoint"] == "127.0.0.1:5555"
    assert data["connected"] is True


def test_connect_maps_a_failure_to_backend_error() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        connect=_raises(RuntimeError("refused"))
    )
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 5555)
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "127.0.0.1:5555"


# --- info ------------------------------------------------------------------


def test_info_reads_getprop_values() -> None:
    dev = SimpleNamespace(
        get_state=_returns("device"),
        shell=_sheller(
            {
                "getprop ro.product.model": "Pixel 7",
                "getprop ro.product.device": "panther",
                "getprop ro.build.version.sdk": "34",
                "getprop ro.build.version.release": "14",
                "getprop ro.product.cpu.abi": "arm64-v8a",
            }
        ),
    )
    data = _backend(dev).info(SERIAL)
    assert data["serial"] == SERIAL
    assert data["model"] == "Pixel 7"
    assert data["abi"] == "arm64-v8a"


def test_info_maps_an_unexpected_failure_to_backend_error() -> None:
    dev = SimpleNamespace(get_state=_raises(RuntimeError("boom")), shell=_sheller({}))
    with pytest.raises(AdbError) as caught:
        _backend(dev).info(SERIAL)
    assert caught.value.code == "backend_error"


# --- properties ------------------------------------------------------------


def test_properties_parses_bracketed_lines_and_skips_junk() -> None:
    raw = "[ro.product.model]: [Pixel]\nnot a property line\n[ro.build.id]: [UP1A]\n"
    dev = SimpleNamespace(shell=_sheller({"getprop": raw}))
    data = _backend(dev).properties(SERIAL)
    assert data["properties"] == {"ro.product.model": "Pixel", "ro.build.id": "UP1A"}
    assert data["has_more"] is False


def test_properties_flags_has_more_at_the_cap() -> None:
    raw = "".join(f"[p{i}]: [v{i}]\n" for i in range(10))
    dev = SimpleNamespace(shell=_sheller({"getprop": raw}))
    data = _backend(dev).properties(SERIAL, limit=3)
    assert data["count"] == 3
    assert data["has_more"] is True


# --- packages --------------------------------------------------------------


def test_packages_reads_and_sorts_ignoring_blank_and_non_package_lines() -> None:
    raw = "junk\npackage:com.b.app\npackage:\npackage:com.a.app\n"
    dev = SimpleNamespace(shell=_sheller({"pm list packages": raw}))
    data = _backend(dev).packages(SERIAL)
    assert data["packages"] == ["com.a.app", "com.b.app"]
    assert data["third_party_only"] is False


def test_packages_third_party_flag_flows_to_the_command_and_result() -> None:
    dev = SimpleNamespace(shell=_sheller({"pm list packages -3": "package:com.x.app\n"}))
    data = _backend(dev).packages(SERIAL, third_party_only=True)
    assert data["packages"] == ["com.x.app"]
    assert data["third_party_only"] is True


def test_packages_flags_has_more_at_the_cap() -> None:
    raw = "".join(f"package:com.app{i}\n" for i in range(10))
    dev = SimpleNamespace(shell=_sheller({"pm list packages": raw}))
    data = _backend(dev).packages(SERIAL, limit=3)
    assert data["count"] == 3
    assert data["has_more"] is True


# --- install ---------------------------------------------------------------


def test_install_rejects_a_missing_apk() -> None:
    dev = SimpleNamespace(install=_returns(None))
    with pytest.raises(AdbError) as caught:
        _backend(dev).install(SERIAL, "/no/such.apk")
    assert caught.value.code == "not_found"


def test_install_maps_a_failure_to_backend_error(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    dev = SimpleNamespace(install=_raises(RuntimeError("INSTALL_FAILED")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).install(SERIAL, str(apk))
    assert caught.value.code == "backend_error"


def test_install_notes_when_the_package_name_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(adb_client, "_apk_package_name", lambda path: None)
    dev = SimpleNamespace(install=_returns(None))
    data = _backend(dev).install(SERIAL, str(apk))
    assert data["installed"] is None
    assert "package name not readable" in data["note"]


def test_install_notes_when_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(adb_client, "_apk_package_name", lambda path: "com.example.app")
    dev = SimpleNamespace(
        install=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): RuntimeError("offline")}),
    )
    data = _backend(dev).install(SERIAL, str(apk))
    assert data["installed"] is None
    assert data["package"] == "com.example.app"
    assert "could not verify" in data["note"]


def test_install_confirms_a_visible_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(adb_client, "_apk_package_name", lambda path: "com.example.app")
    dev = SimpleNamespace(
        install=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): "package:/data/app/base.apk\n"}),
    )
    data = _backend(dev).install(SERIAL, str(apk))
    assert data["installed"] is True
    assert data["package"] == "com.example.app"


def test_install_notes_when_the_package_is_not_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(adb_client, "_apk_package_name", lambda path: "com.example.app")
    dev = SimpleNamespace(
        install=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): "Unknown package\n"}),
    )
    data = _backend(dev).install(SERIAL, str(apk))
    assert data["installed"] is False
    assert "not visible to pm path" in data["note"]


# --- uninstall -------------------------------------------------------------


def test_uninstall_maps_a_failure_to_backend_error() -> None:
    dev = SimpleNamespace(uninstall=_raises(RuntimeError("DELETE_FAILED")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).uninstall(SERIAL, "com.example.app")
    assert caught.value.code == "backend_error"


def test_uninstall_notes_when_verification_fails() -> None:
    dev = SimpleNamespace(
        uninstall=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): RuntimeError("offline")}),
    )
    data = _backend(dev).uninstall(SERIAL, "com.example.app")
    assert data["uninstalled"] is None
    assert "could not verify" in data["note"]


def test_uninstall_confirms_removal_when_pm_path_is_empty() -> None:
    dev = SimpleNamespace(
        uninstall=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): "Unknown package\n"}),
    )
    data = _backend(dev).uninstall(SERIAL, "com.example.app")
    assert data["uninstalled"] is True


def test_uninstall_notes_when_the_package_is_still_present() -> None:
    dev = SimpleNamespace(
        uninstall=_returns(None),
        shell=_sheller({("pm", "path", "com.example.app"): "package:/data/app/base.apk\n"}),
    )
    data = _backend(dev).uninstall(SERIAL, "com.example.app")
    assert data["uninstalled"] is False
    assert "still visible" in data["note"]


# --- launch ----------------------------------------------------------------


_MONKEY = ["monkey", "-p", "com.example.app", "-c", "android.intent.category.LAUNCHER", "1"]


def test_launch_maps_a_monkey_failure_to_backend_error() -> None:
    dev = SimpleNamespace(shell=_sheller({tuple(_MONKEY): RuntimeError("no activities")}))
    with pytest.raises(AdbError) as caught:
        _backend(dev).launch(SERIAL, "com.example.app")
    assert caught.value.code == "backend_error"


def test_launch_notes_when_the_foreground_cannot_be_read() -> None:
    dev = SimpleNamespace(
        shell=_sheller({tuple(_MONKEY): ""}),
        app_current=_raises(RuntimeError("no window")),
    )
    data = _backend(dev).launch(SERIAL, "com.example.app")
    assert data["launched"] is None
    assert "could not read foreground" in data["note"]


def test_launch_confirms_the_foreground_package() -> None:
    dev = SimpleNamespace(
        shell=_sheller({tuple(_MONKEY): ""}),
        app_current=_returns(SimpleNamespace(package="com.example.app")),
    )
    data = _backend(dev).launch(SERIAL, "com.example.app")
    assert data["launched"] is True
    assert data["foreground"] == "com.example.app"


# --- force_stop ------------------------------------------------------------


_FORCE_STOP = ("am", "force-stop", "com.example.app")


def test_force_stop_maps_a_failure_to_backend_error() -> None:
    dev = SimpleNamespace(shell=_sheller({_FORCE_STOP: RuntimeError("no such user")}))
    with pytest.raises(AdbError) as caught:
        _backend(dev).force_stop(SERIAL, "com.example.app")
    assert caught.value.code == "backend_error"


def test_force_stop_notes_when_the_process_list_is_unreadable() -> None:
    dev = SimpleNamespace(
        shell=_sheller(
            {
                _FORCE_STOP: "",
                ("pidof", "com.example.app"): RuntimeError("offline"),
            }
        )
    )
    data = _backend(dev).force_stop(SERIAL, "com.example.app")
    assert data["stopped"] is None
    assert "could not read process list" in data["note"]


def test_force_stop_confirms_no_remaining_pids() -> None:
    dev = SimpleNamespace(
        shell=_sheller({_FORCE_STOP: "", ("pidof", "com.example.app"): ""})
    )
    data = _backend(dev).force_stop(SERIAL, "com.example.app")
    assert data["stopped"] is True
    assert data["remaining_pids"] == []


# --- current_activity ------------------------------------------------------


def test_current_activity_shapes_the_reply() -> None:
    dev = SimpleNamespace(
        app_current=_returns(SimpleNamespace(package="com.x", activity="com.x.Main"))
    )
    data = _backend(dev).current_activity(SERIAL)
    assert data == {"package": "com.x", "activity": "com.x.Main"}


def test_current_activity_maps_a_failure_to_backend_error() -> None:
    dev = SimpleNamespace(app_current=_raises(RuntimeError("no window")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).current_activity(SERIAL)
    assert caught.value.code == "backend_error"


# --- logcat ----------------------------------------------------------------


def test_logcat_returns_the_tail_lines() -> None:
    dev = SimpleNamespace(shell=_sheller({("logcat", "-d", "-t", "200"): "a\nb\nc\n"}))
    data = _backend(dev).logcat(SERIAL)
    assert data["lines"] == ["a", "b", "c"]
    assert data["truncated"] is False


def test_logcat_truncates_an_oversized_dump() -> None:
    blob = "x" * (adb_client._MAX_LOGCAT_CHARS + 50)
    dev = SimpleNamespace(shell=_sheller({("logcat", "-d", "-t", "200"): blob}))
    data = _backend(dev).logcat(SERIAL)
    assert data["truncated"] is True


# --- screenshot ------------------------------------------------------------


class _Image:
    def __init__(self, payload: bytes = b"PNGDATA") -> None:
        self._payload = payload

    def save(self, path: str) -> None:
        Path(path).write_bytes(self._payload)


def test_screenshot_saves_and_reports_the_size(tmp_path: Path) -> None:
    dev = SimpleNamespace(screenshot=_returns(_Image(b"PNG")))
    out = tmp_path / "shots" / "cap.png"
    data = _backend(dev).screenshot(SERIAL, out)
    assert out.read_bytes() == b"PNG"
    assert data["size"] == 3


def test_screenshot_maps_a_failure_to_backend_error(tmp_path: Path) -> None:
    dev = SimpleNamespace(screenshot=_raises(RuntimeError("no framebuffer")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).screenshot(SERIAL, tmp_path / "cap.png")
    assert caught.value.code == "backend_error"


def test_screenshot_refuses_an_over_cap_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adb_client, "capped_file_size", lambda path, cap: (cap + 1, True))
    dev = SimpleNamespace(screenshot=_returns(_Image(b"PNG")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).screenshot(SERIAL, tmp_path / "cap.png")
    assert caught.value.code == "too_large"


# --- pull ------------------------------------------------------------------


def _pull_writes(payload: bytes = b"data") -> Any:
    def pull(remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        Path(local).write_bytes(payload)

    return pull


def test_pull_transfers_a_small_file_that_stat_approved(tmp_path: Path) -> None:
    # stat succeeds, reports a small regular file (neither directory nor
    # over-cap), so the transfer runs and reports the on-disk size.
    info = SimpleNamespace(mode=stat.S_IFREG | 0o644, size=4)
    dev = SimpleNamespace(sync=SimpleNamespace(stat=_returns(info), pull=_pull_writes(b"data")))
    out = tmp_path / "pulled.bin"
    data = _backend(dev).pull(SERIAL, "/sdcard/x", out)
    assert data["size"] == 4


def test_pull_stat_error_is_tolerated_then_transfers(tmp_path: Path) -> None:
    # stat is best-effort: if it errors, the pull still runs and its own size
    # check catches an oversize file.
    dev = SimpleNamespace(
        sync=SimpleNamespace(stat=_raises(RuntimeError("no stat")), pull=_pull_writes(b"hi"))
    )
    out = tmp_path / "pulled.bin"
    data = _backend(dev).pull(SERIAL, "/sdcard/x", out)
    assert data["size"] == 2


def test_pull_refuses_a_remote_directory(tmp_path: Path) -> None:
    info = SimpleNamespace(mode=stat.S_IFDIR | 0o755, size=0)
    dev = SimpleNamespace(sync=SimpleNamespace(stat=_returns(info), pull=_pull_writes()))
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/dir", tmp_path / "x")
    assert caught.value.code == "invalid_params"


def test_pull_refuses_an_over_cap_remote_by_stat(tmp_path: Path) -> None:
    over = adb_client.UNREGISTERED_CAPTURE_MAX_BYTES + 1
    info = SimpleNamespace(mode=stat.S_IFREG | 0o644, size=over)
    dev = SimpleNamespace(sync=SimpleNamespace(stat=_returns(info), pull=_pull_writes()))
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/huge", tmp_path / "x")
    assert caught.value.code == "too_large"


def test_pull_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    sync = SimpleNamespace(stat=_raises(OSError()), pull=_raises(RuntimeError("io")))
    dev = SimpleNamespace(sync=sync)
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/x", tmp_path / "x")
    assert caught.value.code == "backend_error"


def test_pull_refuses_when_the_transfer_lands_a_directory(tmp_path: Path) -> None:
    def pull(remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        Path(local).mkdir(parents=True, exist_ok=True)

    dev = SimpleNamespace(sync=SimpleNamespace(stat=_raises(OSError()), pull=pull))
    out = tmp_path / "landed"
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/x", out)
    assert caught.value.code == "invalid_params"
    assert not out.exists()  # the stray directory was cleaned up


def test_pull_refuses_an_over_cap_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adb_client, "capped_file_size", lambda path, cap: (cap + 1, True))
    dev = SimpleNamespace(sync=SimpleNamespace(stat=_raises(OSError()), pull=_pull_writes(b"x")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/x", tmp_path / "x")
    assert caught.value.code == "too_large"


# --- push ------------------------------------------------------------------


def test_push_rejects_a_missing_local_file(tmp_path: Path) -> None:
    dev = SimpleNamespace(sync=SimpleNamespace(push=_returns(None)))
    with pytest.raises(AdbError) as caught:
        _backend(dev).push(SERIAL, str(tmp_path / "gone.bin"), "/sdcard/x")
    assert caught.value.code == "not_found"


def test_push_maps_a_stat_error_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "stat", _raises(OSError("stat failed")))
    dev = SimpleNamespace(sync=SimpleNamespace(push=_returns(None)))
    with pytest.raises(AdbError) as caught:
        _backend(dev).push(SERIAL, str(src), "/sdcard/x")
    assert caught.value.code == "backend_error"
    assert "cannot stat local file" in caught.value.message


def test_push_refuses_an_over_cap_local_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    src = tmp_path / "big.bin"
    src.write_bytes(b"12345")
    dev = SimpleNamespace(sync=SimpleNamespace(push=_returns(None)))
    with pytest.raises(AdbError) as caught:
        _backend(dev).push(SERIAL, str(src), "/sdcard/x")
    assert caught.value.code == "too_large"


def test_push_transfers_and_reports_the_size(tmp_path: Path) -> None:
    src = tmp_path / "f.bin"
    src.write_bytes(b"hello")
    recorded: list[tuple[str, str]] = []

    def push(local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        recorded.append((local, remote))

    dev = SimpleNamespace(sync=SimpleNamespace(push=push))
    data = _backend(dev).push(SERIAL, str(src), "/sdcard/x")
    assert data["size"] == 5
    assert recorded == [(str(src), "/sdcard/x")]


def test_push_maps_a_transfer_failure_to_backend_error(tmp_path: Path) -> None:
    src = tmp_path / "f.bin"
    src.write_bytes(b"hello")
    dev = SimpleNamespace(sync=SimpleNamespace(push=_raises(RuntimeError("io"))))
    with pytest.raises(AdbError) as caught:
        _backend(dev).push(SERIAL, str(src), "/sdcard/x")
    assert caught.value.code == "backend_error"


# --- ensure_frida_server ---------------------------------------------------


class _FridaDev:
    """A device whose ps output flips to show frida-server after the su launch."""

    def __init__(
        self,
        *,
        visible_before: bool = False,
        visible_after: bool = False,
        launch_error: BaseException | None = None,
        push_error: BaseException | None = None,
    ) -> None:
        self._before = visible_before
        self._after = visible_after
        self._launch_error = launch_error
        self._push_error = push_error
        self._launched = False
        self.pushed: list[tuple[str, str]] = []
        self.sync = SimpleNamespace(push=self._push)

    def _push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        if self._push_error is not None:
            raise self._push_error
        self.pushed.append((local, remote))

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        text = args if isinstance(args, str) else " ".join(args)
        if text.startswith("su -c"):
            self._launched = True
            if self._launch_error is not None:
                raise self._launch_error
            return ""
        if isinstance(args, list) and args[:1] == ["chmod"]:
            return ""
        if text in ("ps -A", "ps"):
            present = self._after if self._launched else self._before
            return "u0 900 1 frida-server\n" if present else "root 1 0 init\n"
        raise KeyError(text)


def test_ensure_frida_server_rejects_a_bad_remote_path() -> None:
    dev = _FridaDev()
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(SERIAL, remote_path="has space")
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_short_circuits_when_already_running() -> None:
    dev = _FridaDev(visible_before=True)
    data = _backend(dev).ensure_frida_server(SERIAL)
    assert data == {"running": True, "pushed": False, "port": 27042}


def test_ensure_frida_server_rejects_a_missing_binary(tmp_path: Path) -> None:
    dev = _FridaDev(visible_before=False)
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(SERIAL, server_binary=str(tmp_path / "missing"))
    assert caught.value.code == "not_found"


def test_ensure_frida_server_pushes_launches_and_confirms(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    dev = _FridaDev(visible_before=False, visible_after=True)
    data = _backend(dev).ensure_frida_server(SERIAL, server_binary=str(binary))
    assert data["running"] is True
    assert data["pushed"] is True
    assert dev.pushed == [(str(binary), "/data/local/tmp/frida-server")]


def test_ensure_frida_server_maps_a_push_failure(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    dev = _FridaDev(visible_before=False, push_error=RuntimeError("read-only fs"))
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(SERIAL, server_binary=str(binary))
    assert caught.value.code == "backend_error"
    assert "failed to push frida-server" in caught.value.message


def test_ensure_frida_server_notes_a_launch_that_stalls() -> None:
    dev = _FridaDev(visible_before=False, launch_error=RuntimeError("su timed out"))
    data = _backend(dev).ensure_frida_server(SERIAL)
    assert "launch attempted" in data["note"]


def test_ensure_frida_server_notes_when_never_visible() -> None:
    dev = _FridaDev(visible_before=False, visible_after=False)
    data = _backend(dev).ensure_frida_server(SERIAL)
    assert data["running"] is False
    assert "not visible in ps" in data["note"]


# --- forward ---------------------------------------------------------------


def test_forward_rejects_a_bad_local_spec() -> None:
    with pytest.raises(AdbError) as caught:
        _backend().forward(SERIAL, "not-a-spec", "tcp:1234")
    assert caught.value.code == "invalid_params"
    assert "local" in caught.value.details


def test_forward_rejects_a_bad_remote_spec() -> None:
    with pytest.raises(AdbError) as caught:
        _backend().forward(SERIAL, "tcp:1234", "not-a-spec")
    assert caught.value.code == "invalid_params"
    assert "remote" in caught.value.details


def test_forward_refuses_when_the_slot_cap_is_reached() -> None:
    dev = SimpleNamespace(forward=_returns(None))
    backend = _backend(dev)
    backend._forwards = [(SERIAL, f"tcp:{5000 + i}") for i in range(adb_client._MAX_FORWARDS)]
    with pytest.raises(AdbError) as caught:
        backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert caught.value.code == "invalid_state"


def test_forward_records_the_reservation_on_success() -> None:
    recorded: list[tuple[str, str]] = []

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        recorded.append((local, remote))

    dev = SimpleNamespace(forward=forward)
    backend = _backend(dev)
    data = backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert data == {"local": "tcp:9999", "remote": "tcp:1234"}
    assert (SERIAL, "tcp:9999") in backend._forwards
    assert recorded == [("tcp:9999", "tcp:1234")]


def test_forward_rolls_back_the_reservation_on_an_adb_error() -> None:
    dev = SimpleNamespace(forward=_raises(AdbError("timeout", "stalled")))
    backend = _backend(dev)
    with pytest.raises(AdbError) as caught:
        backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert caught.value.code == "timeout"
    assert (SERIAL, "tcp:9999") not in backend._forwards


def test_forward_rolls_back_and_wraps_a_generic_error() -> None:
    dev = SimpleNamespace(forward=_raises(RuntimeError("boom")))
    backend = _backend(dev)
    with pytest.raises(AdbError) as caught:
        backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert caught.value.code == "backend_error"
    assert (SERIAL, "tcp:9999") not in backend._forwards


def test_forward_reissues_an_already_reserved_slot() -> None:
    recorded: list[tuple[str, str]] = []

    def forward(local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        recorded.append((local, remote))

    dev = SimpleNamespace(forward=forward)
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:9999")]  # already reserved
    data = backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert data == {"local": "tcp:9999", "remote": "tcp:1234"}
    assert recorded == [("tcp:9999", "tcp:1234")]
    # Re-issuing must not double the reservation.
    assert backend._forwards.count((SERIAL, "tcp:9999")) == 1


def test_forward_reissue_failure_keeps_the_pre_existing_slot() -> None:
    # The slot was not reserved by this call, so a failure must not drop it.
    dev = SimpleNamespace(forward=_raises(AdbError("timeout", "stalled")))
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:9999")]
    with pytest.raises(AdbError) as caught:
        backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert caught.value.code == "timeout"
    assert (SERIAL, "tcp:9999") in backend._forwards


def test_forward_reissue_generic_failure_keeps_the_pre_existing_slot() -> None:
    dev = SimpleNamespace(forward=_raises(RuntimeError("boom")))
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:9999")]
    with pytest.raises(AdbError) as caught:
        backend.forward(SERIAL, "tcp:9999", "tcp:1234")
    assert caught.value.code == "backend_error"
    assert (SERIAL, "tcp:9999") in backend._forwards


# --- structured errors pass through unchanged -----------------------------
#
# Each operation wraps its device call in `except AdbError: raise` before the
# generic `except Exception -> backend_error`. That ordering is the contract:
# a helper that already produced a structured code (a timeout, a not_found)
# must reach the caller with that code intact, not be flattened to
# backend_error. These pin that passthrough for every such method.


def test_client_passes_through_a_structured_error() -> None:
    backend = _backend()
    backend._adbutils = SimpleNamespace(AdbClient=_raises(AdbError("invalid_state", "busy")))
    with pytest.raises(AdbError) as caught:
        backend._client()
    assert caught.value.code == "invalid_state"


def test_device_passes_through_the_serial_check_error() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(device=_returns(None))  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend._device("bad serial with spaces!")
    assert caught.value.code == "invalid_params"


def test_list_devices_passes_through_a_structured_error() -> None:
    backend = _backend()
    backend._client = lambda **kw: SimpleNamespace(  # type: ignore[method-assign]
        list=_raises(AdbError("invalid_state", "busy"))
    )
    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "invalid_state"


def test_info_passes_through_a_structured_error() -> None:
    dev = SimpleNamespace(get_state=_raises(AdbError("timeout", "stalled")), shell=_sheller({}))
    with pytest.raises(AdbError) as caught:
        _backend(dev).info(SERIAL)
    assert caught.value.code == "timeout"


def test_install_passes_through_a_structured_error(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    dev = SimpleNamespace(install=_raises(AdbError("timeout", "stalled")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).install(SERIAL, str(apk))
    assert caught.value.code == "timeout"


def test_uninstall_passes_through_a_structured_error() -> None:
    dev = SimpleNamespace(uninstall=_raises(AdbError("timeout", "stalled")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).uninstall(SERIAL, "com.example.app")
    assert caught.value.code == "timeout"


def test_current_activity_passes_through_a_structured_error() -> None:
    dev = SimpleNamespace(app_current=_raises(AdbError("timeout", "stalled")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).current_activity(SERIAL)
    assert caught.value.code == "timeout"


def test_screenshot_passes_through_a_structured_error(tmp_path: Path) -> None:
    dev = SimpleNamespace(screenshot=_raises(AdbError("timeout", "stalled")))
    with pytest.raises(AdbError) as caught:
        _backend(dev).screenshot(SERIAL, tmp_path / "cap.png")
    assert caught.value.code == "timeout"


def test_pull_passes_through_a_structured_error(tmp_path: Path) -> None:
    sync = SimpleNamespace(stat=_raises(OSError()), pull=_raises(AdbError("timeout", "stalled")))
    dev = SimpleNamespace(sync=sync)
    with pytest.raises(AdbError) as caught:
        _backend(dev).pull(SERIAL, "/sdcard/x", tmp_path / "x")
    assert caught.value.code == "timeout"


def test_push_passes_through_a_structured_error(tmp_path: Path) -> None:
    src = tmp_path / "f.bin"
    src.write_bytes(b"hello")
    dev = SimpleNamespace(sync=SimpleNamespace(push=_raises(AdbError("timeout", "stalled"))))
    with pytest.raises(AdbError) as caught:
        _backend(dev).push(SERIAL, str(src), "/sdcard/x")
    assert caught.value.code == "timeout"


def test_ensure_frida_server_passes_through_a_structured_push_error(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"ELF")
    dev = _FridaDev(visible_before=False, push_error=AdbError("timeout", "stalled"))
    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(SERIAL, server_binary=str(binary))
    assert caught.value.code == "timeout"


# --- release_forwards ------------------------------------------------------


def test_release_forwards_removes_each_held_forward() -> None:
    removed: list[str] = []
    dev = SimpleNamespace(forward_remove=lambda local, timeout=None: removed.append(local))
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:5001"), (SERIAL, "tcp:5002")]
    data = backend.release_forwards()
    assert data["count"] == 2
    assert removed == ["tcp:5001", "tcp:5002"]
    assert backend._forwards == []


def test_release_forwards_retains_forwards_without_a_remove_api() -> None:
    dev = SimpleNamespace()  # no forward_remove / remove_forward
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:5001")]
    data = backend.release_forwards()
    assert data["count"] == 0
    assert data["failed"][0]["error"] == "device has no forward-remove API"
    # Not dropped: adb still holds it, so the next close_all retries.
    assert (SERIAL, "tcp:5001") in backend._forwards


def test_release_forwards_retains_a_forward_when_removal_raises() -> None:
    dev = SimpleNamespace(forward_remove=_raises(RuntimeError("offline")))
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:5001")]
    data = backend.release_forwards()
    assert data["count"] == 0
    assert (SERIAL, "tcp:5001") in backend._forwards


def test_release_forwards_deduplicates_the_retry_set() -> None:
    # A duplicate key that both fail exercises the "already re-added" skip in
    # the retry loop; the forward is retained exactly once.
    dev = SimpleNamespace()  # no remove API -> both entries fail and retry
    backend = _backend(dev)
    backend._forwards = [(SERIAL, "tcp:5001"), (SERIAL, "tcp:5001")]
    backend.release_forwards()
    assert backend._forwards.count((SERIAL, "tcp:5001")) == 1
