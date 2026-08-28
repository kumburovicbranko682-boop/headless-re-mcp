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


class _ReverseKeyDev:
    """getprop output whose keys arrive in reverse-alphabetical order."""

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return "\n".join(f"[ro.k.{letter}]: [{letter}]" for letter in ("e", "d", "c", "b", "a"))


def test_a_capped_property_map_is_the_alphabetical_key_prefix() -> None:
    """A capped map must be the alphabetically first keys, not an arbitrary
    getprop-order slice: only then can a caller tell 'this key is absent within
    the page' from 'this key may sit past the cap'. Keys arrive reversed, so a
    cap-then-slice would keep ro.k.e/d/c; requiring ro.k.a/b/c pins sort-before-
    cap for properties the same way packages does."""
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _ReverseKeyDev()  # type: ignore[method-assign]
    payload = backend.properties("emulator-5554", limit=3)
    assert payload["has_more"] is True
    assert payload["count"] == 3
    assert payload["total"] == 5
    assert payload["offset"] == 0
    assert list(payload["properties"]) == ["ro.k.a", "ro.k.b", "ro.k.c"]


def test_offset_pages_the_property_tail_that_a_capped_first_page_hides() -> None:
    """Same reachability contract as packages: getprop lists every property, so
    a key sorting past the cap must be reachable by offset, not merely flagged
    by has_more. Keys arrive reversed; the first page is the alphabetical head,
    and offset reaches the tail so 'sorts within a reachable page and absent =>
    unset' holds for the whole map, not just the head."""
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _ReverseKeyDev()  # type: ignore[method-assign]

    head = backend.properties("emulator-5554", limit=2)
    assert list(head["properties"]) == ["ro.k.a", "ro.k.b"]
    assert head["offset"] == 0
    assert head["total"] == 5
    assert head["has_more"] is True

    tail = backend.properties("emulator-5554", limit=2, offset=4)
    assert list(tail["properties"]) == ["ro.k.e"]
    assert tail["offset"] == 4
    assert tail["count"] == 1
    assert tail["has_more"] is False

    # A negative offset floors to 0 rather than slicing from the sorted tail;
    # a past-end offset yields an empty map, not an error.
    floored = backend.properties("emulator-5554", limit=1, offset=-3)
    assert list(floored["properties"]) == ["ro.k.a"]
    assert floored["offset"] == 0
    past_end = backend.properties("emulator-5554", offset=99)
    assert past_end["properties"] == {}
    assert past_end["count"] == 0
    assert past_end["total"] == 5
    assert past_end["has_more"] is False
