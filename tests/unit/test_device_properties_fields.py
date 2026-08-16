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
    doc = _tool_docstring("device.properties")
    assert "Answers with properties" in doc
    assert "has_more" in doc
    assert "count" in doc
