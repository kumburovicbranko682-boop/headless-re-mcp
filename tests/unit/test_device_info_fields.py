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


_GETPROP_DUMP = "\n".join(
    (
        "[ro.product.model]: [Pixel]",
        "[ro.product.device]: [oriole]",
        "[ro.build.version.sdk]: [34]",
        "[ro.build.version.release]: [14]",
        "[ro.product.cpu.abi]: [arm64-v8a]",
        "[persist.some.other.prop]: [ignored]",
    )
)


class _FakeDev:
    def __init__(self) -> None:
        self.shell_calls: list[str] = []

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return "device"

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.shell_calls.append(str(args))
        # info reads one getprop dump, not one getprop per key.
        return _GETPROP_DUMP if args == "getprop" else ""


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


def test_device_info_reads_one_getprop_dump_not_a_call_per_key() -> None:
    """info used to issue five getprop round-trips, one per identity key.

    Each was a separate point that could time out and a separate latency on a
    remote transport. It now reads a single getprop dump (plus the transport
    get_state), parses the five identity keys from it, and ignores the rest.
    """
    dev = _FakeDev()
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    payload = backend.info("emulator-5554")
    assert dev.shell_calls == ["getprop"]
    assert payload["model"] == "Pixel"
    assert payload["abi"] == "arm64-v8a"
    doc = _tool_docstring("device.info")
    assert "Answers with serial" in doc
    assert "sdk" in doc
    assert "abi" in doc
    assert "no SDK" in doc
    assert "android_version" in doc
