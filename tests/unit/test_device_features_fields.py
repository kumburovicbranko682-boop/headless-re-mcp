"""device.features must name the list, keep versioned entries, and bound it.

`pm list features` prints one `feature:<name>` line per device capability,
including versioned entries such as `feature:reqGlEsVersion=196610`. The parser
keeps the token after `feature:` verbatim (so the versioned name=value entries
survive), sorts and caps the list with has_more, and treats an adb host-error
line as a failure rather than an empty feature set.
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


def test_features_parses_and_keeps_versioned_entries() -> None:
    """The token after feature: is kept verbatim, including name=value, sorted.

    Measured intent: plain features and the versioned reqGlEsVersion=196610 both
    appear, non-feature noise lines are ignored, the list is sorted, and the
    field is features (not items) with count and has_more.
    """
    text = "\n".join(
        [
            "feature:android.hardware.telephony",
            "feature:android.software.webview",
            "feature:android.hardware.bluetooth",
            "feature:reqGlEsVersion=196610",
            "",
            "not a feature line",
        ]
    )
    payload = _backend_returning(text).features("emulator-5554")

    assert "items" not in payload
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert payload["features"] == [
        "android.hardware.bluetooth",
        "android.hardware.telephony",
        "android.software.webview",
        "reqGlEsVersion=196610",
    ]

    doc = _tool_docstring("device.features")
    assert "features" in doc
    assert "has_more" in doc
    assert "count" in doc


def test_features_caps_and_discloses_has_more() -> None:
    """A list that fills the cap reports has_more."""
    text = "\n".join(f"feature:android.test.f{index:04d}" for index in range(600))
    payload = _backend_returning(text).features("emulator-5554", limit=500)
    assert payload["count"] == 500
    assert len(payload["features"]) == 500
    assert payload["has_more"] is True


def test_features_host_error_is_failure_not_empty() -> None:
    """An adb host-error line raises rather than reading as zero features."""
    with pytest.raises(AdbError) as excinfo:
        _backend_returning("error: device offline").features("emulator-5554")
    assert excinfo.value.code == "backend_error"
