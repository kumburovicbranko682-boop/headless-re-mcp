"""frida tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import FridaClient
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
    def modules(self) -> list[dict[str, Any]]:
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
    doc = _tool_docstring("frida.spawn")
    assert "Answers with pid" in doc
    assert "There is no process_id" in doc


def test_frida_device_connect_names_connected_and_device() -> None:
    """The catalog said bind a device and never named the payload.

    Measured against the service return: connected True and device holding
    the device info. There is no top-level device_id or ok field. Looking
    for device_id after a successful connect reads as a bind that returned
    no device.
    """
    from headless_re_mcp.core.service_frida import FridaDeviceMixin

    source = inspect.getsource(FridaDeviceMixin.frida_device_connect)
    assert '{"connected": True, "device": info}' in source
    assert '"ok"' not in source
    doc = _tool_docstring("frida.device.connect")
    assert "Answers with connected" in doc
    assert "There is no top-level device_id" in doc
