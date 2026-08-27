"""device.settings must read the Settings provider honestly and stay bounded.

Each `settings list <namespace>` prints `key=value` lines; the three namespaces
come back as separate maps. The parser has to split only on the first `=`,
report a namespace the device refuses under unavailable (not as empty), fail
only when every namespace fails, and cap the total entry count with has_more.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


class _FakeDev:
    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        text = str(args)
        for namespace, response in self._responses.items():
            if text.endswith(namespace):
                return response
        return ""


def _backend_returning(responses: dict[str, str]) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(responses)  # type: ignore[method-assign]
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


def test_settings_parses_three_namespaces_and_splits_on_first_equals() -> None:
    """Namespaces map separately; a value containing '=' survives the split.

    Measured intent: global/secure/system each become their own key/value map,
    policy_control=immersive.full=* keeps the whole value after the first '=',
    count is the total across namespaces, and nothing is reported unavailable.
    """
    payload = _backend_returning(
        {
            "global": "http_proxy=10.0.2.2:8080\nadb_enabled=1\npolicy_control=immersive.full=*",
            "secure": "install_non_market_apps=1\ndevelopment_settings_enabled=1",
            "system": "screen_brightness=120",
        }
    ).settings("emulator-5554")

    assert "props" not in payload
    assert payload["count"] == 6
    assert payload["has_more"] is False
    assert "unavailable" not in payload
    assert payload["settings"]["global"] == {
        "http_proxy": "10.0.2.2:8080",
        "adb_enabled": "1",
        "policy_control": "immersive.full=*",
    }
    assert payload["settings"]["secure"] == {
        "install_non_market_apps": "1",
        "development_settings_enabled": "1",
    }
    assert payload["settings"]["system"] == {"screen_brightness": "120"}

    doc = _tool_docstring("device.settings")
    assert "settings" in doc
    assert "unavailable" in doc
    assert "has_more" in doc
    assert "count" in doc


def test_settings_refused_namespace_is_unavailable_not_empty() -> None:
    """A namespace answered with an adb error line is reported, not read as empty."""
    payload = _backend_returning(
        {
            "global": "adb_enabled=1",
            "secure": "error: permission denial",
            "system": "screen_off_timeout=60000",
        }
    ).settings("emulator-5554")

    assert set(payload["settings"]) == {"global", "system"}
    assert payload["unavailable"] == ["secure"]
    assert payload["count"] == 2


def test_settings_all_namespaces_failing_is_an_error() -> None:
    """When every namespace fails the call raises rather than returning empty."""
    with pytest.raises(AdbError) as excinfo:
        _backend_returning(
            {
                "global": "error: closed",
                "secure": "adb: device offline",
                "system": "error: closed",
            }
        ).settings("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_settings_caps_total_and_discloses_has_more() -> None:
    """Filling the cap in the first namespace sets has_more and skips the rest."""
    big = "\n".join(f"k{index:04d}={index}" for index in range(600))
    payload = _backend_returning(
        {"global": big, "secure": "s=1", "system": "t=1"}
    ).settings("emulator-5554", limit=500)

    assert payload["count"] == 500
    assert len(payload["settings"]["global"]) == 500
    assert "secure" not in payload["settings"]
    assert payload["has_more"] is True
