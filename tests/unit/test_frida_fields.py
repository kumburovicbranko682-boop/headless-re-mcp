"""frida tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
import time
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.tools.frida import build_frida_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Exports:
    def modules(self, limit: int = 64) -> list[dict[str, Any]]:
        del limit
        return [
            {"name": f"m{index}", "base": "0x1", "size": 1, "path": ""}
            for index in range(25)
        ]


class _Script:
    exports_sync = _Exports()

    def load(self) -> None:
        return None


class _Session:
    def create_script(self, source: str) -> _Script:
        return _Script()

    def detach(self) -> None:
        return None


class _Frida:
    def attach(self, pid: int) -> _Session:
        return _Session()


def test_frida_modules_says_when_the_page_is_not_the_whole_list() -> None:
    """The catalog named count and total and stopped there.

    Measured: 25 modules, limit 10 -> count 10, total 25, has_more True.
    An overnight pass that treated the page as complete because has_more
    was unnamed had no field to notice the rest.
    """
    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["modules"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.modules")
    assert "has_more" in doc


def test_frida_modules_does_not_hide_a_failed_detach() -> None:
    """A returned module page must not conceal its still-attached session."""

    class _LeakedSession(_Session):
        def detach(self) -> None:
            raise RuntimeError("detach refused")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid: _LeakedSession()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.modules(9, allowed_pid=9)

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 9


class _ExportApi:
    def exports(self, name: str, count: int) -> dict[str, Any]:
        return {
            "found": True,
            "module": name,
            "base": "0x1",
            "exports": [
                {"name": f"e{index}", "address": "0x2", "type": "function"}
                for index in range(int(count))
            ],
        }


class _ExportScript:
    exports_sync = _ExportApi()

    def load(self) -> None:
        return None


class _ExportSession:
    def create_script(self, source: str) -> _ExportScript:
        return _ExportScript()

    def detach(self) -> None:
        return None


class _ExportFrida:
    def attach(self, pid: int) -> _ExportSession:
        return _ExportSession()


def test_frida_exports_says_when_the_page_is_not_the_whole_table() -> None:
    """The catalog named found, module, base and exports, and stopped there.

    Measured: 11 exports requested for a page of 10 -> count 10, has_more
    True. An overnight pass that treated exports as the whole table had no
    field to notice the rest.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ExportFrida()
    payload = client.exports(1, "ntdll.dll", allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert len(payload["exports"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.exports")
    assert "has_more" in doc


def test_frida_exports_does_not_hide_a_failed_detach() -> None:
    """A returned export page must not conceal its still-attached session."""

    class _LeakedSession(_ExportSession):
        def detach(self) -> None:
            raise RuntimeError("detach refused")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid: _LeakedSession()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.exports(11, "ntdll.dll", allowed_pid=11)

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 11


def test_frida_memory_read_does_not_hide_a_failed_detach() -> None:
    """Returned bytes must not conceal their still-attached native session."""

    class _ReadApi:
        def read(self, address: int, size: int) -> bytes:
            del address, size
            return b"\x90"

    class _ReadScript:
        exports_sync = _ReadApi()

        def load(self) -> None:
            return None

    class _LeakedSession:
        def create_script(self, source: str) -> _ReadScript:
            del source
            return _ReadScript()

        def detach(self) -> None:
            raise RuntimeError("detach refused")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid: _LeakedSession()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.memory_read(13, 0x1000, 1, allowed_pid=13)

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 13


class _Dev:
    def __init__(self, ident: str, name: str, kind: str) -> None:
        self.id = ident
        self.name = name
        self.type = kind


class _DeviceFrida:
    def enumerate_devices(self) -> list[_Dev]:
        return [
            _Dev("local", "Local System", "local"),
            _Dev("usb", "Pixel", "usb"),
        ]


def test_frida_devices_puts_the_list_in_devices_not_items() -> None:
    """The catalog never named the list field.

    Measured: two devices -> count 2, field is devices not items or
    enumerations. Looking for items after a successful call reads as Frida
    seeing none.
    """
    client = FridaClient()
    client._available = True
    client._frida = _DeviceFrida()
    payload = client.enumerate_devices()
    assert "items" not in payload
    assert "enumerations" not in payload
    assert payload["count"] == 2
    assert len(payload["devices"]) == 2
    assert payload["devices"][0]["id"] == "local"
    assert payload["devices"][0]["type"] == "local"
    doc = _tool_docstring("frida.devices")
    assert "Answers with devices" in doc
    assert "count" in doc

class _App:
    def __init__(self, index: int) -> None:
        self.identifier = f"com.app{index}"
        self.name = f"App{index}"
        self.pid = 0


class _Device:
    def enumerate_applications(self) -> list[_App]:
        return [_App(index) for index in range(25)]


def test_frida_applications_puts_the_list_in_applications_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 25 apps, limit 10 -> count 10, total 25, has_more True, field
    is applications not apps or packages. Looking for those after a
    successful call reads as an empty device, and a full page with no
    has_more reads as every installed app.
    """
    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    payload = client.applications("usb", limit=10)
    assert "apps" not in payload
    assert "packages" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["applications"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.applications")
    assert "Answers with applications" in doc
    assert "has_more" in doc

class _JavaApi:
    def classes(self, name_filter: str, count: int) -> list[str]:
        return [f"c{index}" for index in range(int(count))]

    def methods(self, class_name: str, count: int) -> list[str]:
        return [f"m{index}" for index in range(int(count))]


class _JavaScript:
    exports_sync = _JavaApi()

    def load(self) -> None:
        return None


class _JavaSession:
    def create_script(self, source: str) -> _JavaScript:
        return _JavaScript()

    def detach(self) -> None:
        return None


class _JavaDevice:
    def attach(self, pid: int) -> _JavaSession:
        return _JavaSession()


def test_frida_java_classes_puts_the_list_in_classes_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 11 classes requested for a page of 10 -> count 10, has_more
    True, field is classes. Looking for class_list after a successful call
    reads as no classes, and a full page with no has_more reads as every
    loaded class.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _JavaDevice()  # type: ignore[method-assign]
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="classes", limit=10
    )
    assert "class_list" not in payload
    assert payload["count"] == 10
    assert len(payload["classes"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.java.classes")
    assert "Answers with classes" in doc
    assert "has_more" in doc

def test_frida_java_methods_puts_the_list_in_methods_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 11 methods requested for a page of 10 -> count 10, has_more
    True, field is methods. Looking for method_list after a successful call
    reads as no methods, and a full page with no has_more reads as every
    declared method.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _JavaDevice()  # type: ignore[method-assign]
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Foo", limit=10
    )
    assert "method_list" not in payload
    assert payload["class_name"] == "Foo"
    assert payload["count"] == 10
    assert len(payload["methods"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.java.methods")
    assert "Answers with methods" in doc
    assert "has_more" in doc


def test_frida_java_enumeration_does_not_hide_a_failed_detach() -> None:
    """Returned Java classes must not conceal an attached device session."""

    class _LeakedSession(_JavaSession):
        def detach(self) -> None:
            raise RuntimeError("detach refused")

    class _LeakedDevice:
        def attach(self, pid: int) -> _LeakedSession:
            del pid
            return _LeakedSession()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _LeakedDevice()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 19, allowed_pids={19}, mode="classes")

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 19


class _SpawnDevice:
    def spawn(self, argv: list[str]) -> int:
        return 4242

    def resume(self, pid: int) -> None:
        return None


def test_frida_spawn_names_pid_not_process_id() -> None:
    """The catalog said spawn and never named the pid field.

    Measured: package com.example.app -> pid 4242, package, device usb.
    There is no process_id or spawned field. Looking for process_id after a
    successful spawn reads as a launch that returned no process.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _SpawnDevice()  # type: ignore[method-assign]
    payload = client.spawn("usb", "com.example.app")
    assert "process_id" not in payload
    assert "spawned" not in payload
    assert payload["pid"] == 4242
    assert payload["package"] == "com.example.app"
    assert payload["device"] == "usb"


def test_frida_spawn_refuses_a_path_or_bare_name() -> None:
    from headless_re_mcp.backends.frida.client import FridaError

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _SpawnDevice()  # type: ignore[method-assign]
    for package in (r"C:\Windows\notepad.exe", "/system/bin/sh", "notapackage"):
        with pytest.raises(FridaError) as caught:
            client.spawn("usb", package)
        assert caught.value.code == "invalid_params"
    doc = _tool_docstring("frida.spawn")
    assert "Answers with pid" in doc
    assert "There is no process_id" in doc


def test_frida_spawn_times_out_and_kills_the_probe_process() -> None:
    """device.spawn / resume with no deadline parked a worker forever.

    Measured: resume that never returned left the spawned pid running and the
    caller blocked. The probe now kills that pid and raises timeout.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 4242

        def resume(self, pid: int) -> None:
            del pid
            time.sleep(10)

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app", timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert killed == [4242]


def test_frida_spawn_timeout_reports_a_probe_process_that_cannot_be_killed() -> None:
    """A timed-out resume must disclose its one failed kill attempt."""
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 4242

        def resume(self, pid: int) -> None:
            del pid
            time.sleep(1)

        def kill(self, pid: int) -> None:
            killed.append(pid)
            raise RuntimeError("kill refused")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app", timeout=0.1)

    assert caught.value.code == "frida_spawn_cleanup_failed"
    assert caught.value.details["pid"] == 4242
    assert caught.value.details["kill_error"] == "RuntimeError: kill refused"
    assert killed == [4242]


def test_frida_spawn_kills_a_process_that_arrives_after_timeout() -> None:
    """A native spawn completing 100ms late must not resume an untracked pid."""
    killed = Event()
    resumed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            time.sleep(0.15)
            return 4242

        def resume(self, pid: int) -> None:
            resumed.append(pid)

        def kill(self, pid: int) -> None:
            assert pid == 4242
            killed.set()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app", timeout=0.05)

    assert caught.value.code == "timeout"
    assert killed.wait(0.5), "late spawned process remained alive after timeout"
    assert resumed == []


def test_frida_spawn_reports_a_process_that_cannot_be_killed_after_resume_failure() -> None:
    """One failed rollback must not claim its spawned pid was killed."""

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 4242

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume refused")

        def kill(self, pid: int) -> None:
            del pid
            raise RuntimeError("kill refused")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "frida_spawn_cleanup_failed"
    assert caught.value.details["pid"] == 4242
    assert caught.value.details["resume_error"] == "RuntimeError: resume refused"
    assert caught.value.details["kill_error"] == "RuntimeError: kill refused"


def test_frida_java_perform_times_out_and_detaches_the_probe() -> None:
    """Java.perform on a non-JIT process used to occupy the worker forever.

    Measured: exports_sync.classes that never returned left the session
    attached. The probe now detaches and raises timeout.
    """
    state = {"detached": False}

    class _HangApi:
        def classes(self, name_filter: str, count: int) -> list[str]:
            del name_filter, count
            time.sleep(10)
            return []

    class _HangScript:
        exports_sync = _HangApi()

        def load(self) -> None:
            return None

    class _HangSession:
        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            state["detached"] = True

    class _HangDevice:
        def attach(self, pid: int) -> _HangSession:
            del pid
            return _HangSession()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _HangDevice()  # type: ignore[method-assign]
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes", timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert state["detached"] is True


def test_frida_java_timeout_does_not_hide_a_failed_detach() -> None:
    """A timed-out Java probe must disclose its one retained native session."""
    detach_attempts: list[int] = []

    class _HangApi:
        def classes(self, name_filter: str, count: int) -> list[str]:
            del name_filter, count
            time.sleep(1)
            return []

    class _HangScript:
        exports_sync = _HangApi()

        def load(self) -> None:
            return None

    class _LeakedSession:
        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            detach_attempts.append(1)
            raise RuntimeError("detach refused")

    class _Device:
        def attach(self, pid: int) -> _LeakedSession:
            del pid
            return _LeakedSession()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(
            None,
            29,
            allowed_pids={29},
            mode="classes",
            timeout=0.1,
        )

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 29
    assert caught.value.details["detach_error"] == "RuntimeError: detach refused"
    assert detach_attempts == [1]


def test_frida_device_connect_names_connected_and_device(monkeypatch: Any) -> None:
    """The catalog said bind a device and never named the payload.

    Measured against the USB path: connected True and device holding the
    resolved id/name/type, not the usb alias. There is no top-level
    device_id or ok field. Looking for device_id after a successful
    connect reads as a bind that returned no device.
    """
    from headless_re_mcp.core.service_frida import FridaDeviceMixin
    from headless_re_mcp.core.session import SessionRegistry

    class _UsbDevice:
        id = "ABCD1234"
        name = "Pixel 8"
        type = "usb"

    class _Client:
        def _resolve_device(self, device_id: str) -> _UsbDevice:
            assert device_id == "usb"
            return _UsbDevice()

    class _Repo:
        def record_backend(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def append_timeline(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class _Service(FridaDeviceMixin):
        def __init__(self) -> None:
            self.registry = SessionRegistry()
            self.repository = _Repo()

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service = _Service()
    session = service.registry.create("https://example.invalid")
    result = service.frida_device_connect(session.id, device_id="usb")
    assert result.ok
    assert result.data is not None
    assert "device_id" not in result.data
    assert "ok" not in result.data
    assert result.data["connected"] is True
    assert result.data["device"] == {
        "id": "ABCD1234",
        "name": "Pixel 8",
        "type": "usb",
    }
    auth = service.registry.get(session.id).metadata["frida_authorized"]
    assert auth["device_id"] == "ABCD1234"
    doc = _tool_docstring("frida.device.connect")
    assert "Answers with connected" in doc
    assert "There is no top-level device_id" in doc

def test_frida_server_ensure_description_names_running_not_ok() -> None:
    """The catalog said start frida-server and never named the success field.

    Measured against AdbBackend.ensure_frida_server: every return carries
    running, pushed and port, plus note when the process is not visible.
    There is no ok, started or server field. Envelope success with running
    false means the process is not visible. Looking for started after a
    successful call when the server was already up (running true, pushed
    false) reads as a failed start, so the agent pushes and launches again.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    source = Path(AdbBackend.ensure_frida_server.__code__.co_filename).read_text(
        encoding="utf-8"
    )
    start = source.index("def ensure_frida_server")
    chunk = source[start : source.index("\n    def forward(", start)]
    returned = chunk[chunk.index("if visible:") :]
    assert '"running"' in returned
    assert '"pushed"' in returned
    assert '"port"' in returned
    assert '"ok"' not in returned
    assert '"started"' not in returned
    described = _tool_docstring("frida.server.ensure")
    assert "Answers with running" in described
    assert "pushed" in described
    assert "no ok field" in described


def test_add_remote_device_reuses_a_device_already_registered() -> None:
    """Re-adding the same endpoint used to churn the device manager."""

    class _Device:
        id = "10.0.0.1:27042"
        name = "remote"
        type = "remote"

    class _Manager:
        def __init__(self) -> None:
            self.added = 0

        def get_device(self, endpoint: str, timeout: int = 1) -> _Device:
            del endpoint, timeout
            return _Device()

        def add_remote_device(self, endpoint: str) -> _Device:
            del endpoint
            self.added += 1
            return _Device()

    class _Frida:
        def __init__(self) -> None:
            self.manager = _Manager()

        def get_device_manager(self) -> _Manager:
            return self.manager

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    first = client.add_remote_device("10.0.0.1:27042")
    second = client.add_remote_device("10.0.0.1:27042")
    assert first["id"] == "10.0.0.1:27042"
    assert second["id"] == "10.0.0.1:27042"
    assert client._frida.manager.added == 0
