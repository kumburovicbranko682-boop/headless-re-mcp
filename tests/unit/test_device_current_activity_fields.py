"""device.current_activity must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

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


class _Current:
    package = "com.example.app"
    activity = "com.example.app.MainActivity"


class _FakeDev:
    def app_current(self, timeout: float | None = None) -> _Current:
        del timeout
        return _Current()


def test_device_current_activity_names_package_and_activity() -> None:
    """The tool said package and activity but never named the payload keys.

    Measured against AdbBackend.current_activity: package and activity only.
    There is no foreground, current, component or app field. Looking for
    foreground after a successful call reads as a device with no UI.
    """
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    payload = backend.current_activity("emulator-5554")
    assert payload == {
        "package": "com.example.app",
        "activity": "com.example.app.MainActivity",
    }
    assert "foreground" not in payload
    assert "current" not in payload
    assert "component" not in payload
    assert "app" not in payload
    doc = " ".join(_tool_docstring("device.current_activity").split())
    assert "Answers with package and activity" in doc
    assert "There is no foreground" in doc
    assert "component" in doc