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


class _SmallDev:
    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        # Emitted key order is deliberately not sorted, to prove the reader
        # imposes its own stable order rather than paging getprop's line order.
        return "\n".join(f"[k.{n}]: [{n}]" for n in (3, 1, 4, 0, 2))


def _small_backend() -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _SmallDev()  # type: ignore[method-assign]
    return backend


def test_properties_offset_pages_a_stable_sorted_key_order() -> None:
    """offset must reach getprop keys past the cap, over one sorted order.

    Keys past the limit were unreachable behind has_more, and capping in
    getprop's line order returned an arbitrary subset. Paging offset=0 then
    offset=3 over five keys emitted out of order returns disjoint, contiguous
    slices of the sorted order (k.0..k.4) that cover them all, with has_more
    false only on the page that reaches the end.
    """
    backend = _small_backend()

    first = backend.properties("emulator-5554", offset=0, limit=3)
    assert list(first["properties"]) == ["k.0", "k.1", "k.2"]
    assert first["total"] == 5
    assert first["offset"] == 0
    assert first["count"] == 3
    assert first["has_more"] is True

    second = backend.properties("emulator-5554", offset=3, limit=3)
    assert list(second["properties"]) == ["k.3", "k.4"]
    assert second["total"] == 5
    assert second["offset"] == 3
    assert second["has_more"] is False

    past = backend.properties("emulator-5554", offset=99, limit=3)
    assert past["properties"] == {}
    assert past["count"] == 0
    assert past["has_more"] is False
