"""device.info must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend
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
        "truncated": False,
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


class _HugeInfoDev:
    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return "device"

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        mapping = {
            "getprop ro.product.model": "M" * (5 * 1024),
            "getprop ro.product.device": "oriole",
            "getprop ro.build.version.sdk": "34",
            "getprop ro.build.version.release": "14",
            "getprop ro.product.cpu.abi": "arm64-v8a",
        }
        return mapping.get(args, "")


def test_device_info_clips_a_hostile_getprop_value_and_flags_it() -> None:
    """info() reads the same device-controlled getprop surface as properties().

    A rooted device can setprop ro.product.model to a huge value. Measured:
    a 5 KiB model is clipped to the per-value byte cap, the reply sets
    truncated, and the real values beside it are untouched.
    """
    from headless_re_mcp.backends.adb.client import _MAX_PROP_VALUE_BYTES

    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _HugeInfoDev()  # type: ignore[method-assign]
    payload = backend.info("emulator-5554")
    assert payload["truncated"] is True
    assert len(payload["model"].encode("utf-8")) == _MAX_PROP_VALUE_BYTES
    assert payload["device"] == "oriole"
    assert payload["abi"] == "arm64-v8a"
    assert "truncated" in _tool_docstring("device.info")
