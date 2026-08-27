"""device.info must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakeDev:
    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return "device"

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        mapping = {
            "getprop ro.product.model": "Pixel",
            "getprop ro.product.device": "oriole",
            "getprop ro.build.version.sdk": "34",
            "getprop ro.build.version.release": "14",
            "getprop ro.product.cpu.abi": "arm64-v8a",
        }
        return mapping.get(args, "")


def test_device_info_names_sdk_and_abi_not_android_version() -> None:
    """The catalog said SDK and ABI; those are not field names.

    Measured against AdbBackend.info: serial, state, model, device, sdk,
    release, abi. There is no SDK, ABI, android_version or version field.
    Looking for android_version after a successful call reads as a device
    with no OS version.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    payload = backend.info("emulator-5554")
    assert payload == {
        "serial": "emulator-5554",
        "state": "device",
        "model": "Pixel",
        "device": "oriole",
        "sdk": "34",
        "release": "14",
        "abi": "arm64-v8a",
    }
    assert "SDK" not in payload
    assert "ABI" not in payload
    assert "android_version" not in payload
    assert "version" not in payload
    doc = _tool_docstring("device.info")
    assert "Answers with serial" in doc
    assert "sdk" in doc
    assert "abi" in doc
    assert "no SDK" in doc
    assert "android_version" in doc


class _OfflineDev:
    """A device whose getprop returns the adb host's error line as stdout."""

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return "offline"

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return "error: device offline"


class _UnsetPropDev:
    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return "device"

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        # A real device that simply has none of these identity props set:
        # getprop answers with an empty line, not an error.
        return ""


def test_device_info_treats_a_host_error_getprop_as_a_failure() -> None:
    """An offline device must not report "error: device offline" as its model.

    adbutils' shell can return the adb host's own error line as stdout without
    raising, so a raw getprop would surface it as the model/abi value. info()
    now guards each read like properties()/packages(): a host-error dump is a
    backend_error, not a phantom device identity.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _OfflineDev()  # type: ignore[method-assign]
    with pytest.raises(AdbError) as excinfo:
        backend.info("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_device_info_keeps_an_unset_property_as_empty_not_an_error() -> None:
    """An unset property is a real empty string, not a host error.

    getprop for a property that is not set answers with a blank line; that must
    stay "" rather than being mistaken for the offline case and raising.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _UnsetPropDev()  # type: ignore[method-assign]
    payload = backend.info("emulator-5554")
    assert payload["state"] == "device"
    assert payload["model"] == ""
    assert payload["abi"] == ""
