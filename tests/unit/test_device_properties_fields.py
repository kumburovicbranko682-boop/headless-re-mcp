"""device.properties must name the map and say when it was cut."""

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
    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return "\n".join(f"[ro.prop.{index}]: [{index}]" for index in range(600))


class _HugePropDev:
    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        big = "v" * (5 * 1024)
        return f"[ro.big]: [{big}]\n[ro.small]: [ok]"


class _HugePackageDev:
    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        big = "a" * (5 * 1024)
        return f"package:com.example.app\npackage:{big}"


def test_a_capped_property_list_says_has_more() -> None:
    """The catalog said key/value pairs and never named the payload.

    Measured against AdbBackend.properties with 600 getprop lines and
    limit 500: properties has 500 keys, count 500, has_more True. There
    is no props or items field. Looking for props after a successful
    call reads as an empty getprop; ignoring has_more treats the page
    as the whole device.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    payload = backend.properties("emulator-5554", limit=500)
    assert "props" not in payload
    assert "items" not in payload
    assert payload["count"] == 500
    assert len(payload["properties"]) == 500
    assert payload["has_more"] is True
    # An ordinary getprop dump fits every value, so nothing is clipped.
    assert payload["truncated"] is False
    doc = _tool_docstring("device.properties")
    assert "Answers with properties" in doc
    assert "has_more" in doc
    assert "count" in doc


def test_properties_clips_a_hostile_value_and_flags_it() -> None:
    """A rooted app can setprop a multi-megabyte value.

    The list is count-capped, but each value is device-controlled. Measured:
    a 5 KiB value is clipped to the per-value byte cap, the reply sets
    truncated, and a normal value beside it is untouched.
    """
    from headless_re_mcp.backends.adb.client import _MAX_PROP_VALUE_BYTES

    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _HugePropDev()  # type: ignore[method-assign]
    payload = backend.properties("emulator-5554", limit=500)
    assert payload["truncated"] is True
    assert len(payload["properties"]["ro.big"].encode("utf-8")) == _MAX_PROP_VALUE_BYTES
    assert payload["properties"]["ro.small"] == "ok"
    assert "truncated" in _tool_docstring("device.properties")


def test_packages_clips_a_hostile_name_and_flags_it() -> None:
    """pm list packages is device-controlled, so a name can be pathological.

    Measured: a 5 KiB package name is clipped to the per-value byte cap, the
    reply sets truncated, and a real package name is returned intact.
    """
    from headless_re_mcp.backends.adb.client import _MAX_PROP_VALUE_BYTES

    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _HugePackageDev()  # type: ignore[method-assign]
    payload = backend.packages("emulator-5554", limit=500)
    assert payload["truncated"] is True
    assert any(
        len(name.encode("utf-8")) == _MAX_PROP_VALUE_BYTES for name in payload["packages"]
    )
    assert "com.example.app" in payload["packages"]
    assert "truncated" in _tool_docstring("device.packages")
