"""device.services must parse `service list` honestly and stay bounded.

`service list` prints one row per registered binder service as
`<index> <name>: [<interface>]` under a `Found N services:` header. The parser
has to keep a service that publishes no interface (`[]`) rather than drop it,
report the device's own count as reported_total, cap the list with has_more,
and treat an adb host-error line as a failure, not an empty registry.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


class _FakeDev:
    def __init__(self, text: str) -> None:
        self._text = text

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._text


def _backend_returning(text: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(text)  # type: ignore[method-assign]
    return backend


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


def test_services_parses_name_interface_and_keeps_empty_interface() -> None:
    """A service with no published interface ([]) is kept with an empty string.

    Measured intent: names and interfaces are split at ': [', dotted names
    survive, sorting is by name, reported_total mirrors the Found N header, and
    a service printing [] comes back with interface "" rather than vanishing.
    """
    text = "\n".join(
        [
            "Found 3 services:",
            "0\tactivity: [android.app.IActivityManager]",
            "1\tmedia.audio_flinger: [android.media.IAudioFlinger]",
            "2\tempty: []",
        ]
    )
    payload = _backend_returning(text).services("emulator-5554")

    assert "items" not in payload
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert payload["reported_total"] == 3
    assert payload["services"] == [
        {"name": "activity", "interface": "android.app.IActivityManager"},
        {"name": "empty", "interface": ""},
        {"name": "media.audio_flinger", "interface": "android.media.IAudioFlinger"},
    ]

    doc = _tool_docstring("device.services")
    assert "services" in doc
    assert "interface" in doc
    assert "has_more" in doc
    assert "reported_total" in doc


def test_services_caps_and_discloses_has_more() -> None:
    """A list that fills the cap reports has_more and keeps reported_total."""
    lines = ["Found 600 services:"]
    lines += [f"{index}\tsvc{index:04d}: [i.face.I{index}]" for index in range(600)]
    payload = _backend_returning("\n".join(lines)).services("emulator-5554", limit=500)

    assert payload["count"] == 500
    assert len(payload["services"]) == 500
    assert payload["has_more"] is True
    assert payload["reported_total"] == 600


def test_services_host_error_is_failure_not_empty_registry() -> None:
    """An adb host-error line raises rather than reading as zero services."""
    with pytest.raises(AdbError) as excinfo:
        _backend_returning("error: device offline").services("emulator-5554")
    assert excinfo.value.code == "backend_error"
