"""device.* verdict tools must document the note that explains a null result.

install/uninstall/launch/force_stop each answer with a boolean verdict that is
null when adb returned but the outcome could not be confirmed. The reason for
that null (or a negative) rides in a ``note`` field. A description that names
only the boolean leaves an agent with a null it cannot interpret, so the four
docstrings must name note and the backend must actually emit it.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import headless_re_mcp.backends.adb.client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_SERIAL = "127.0.0.1:5555"
_PACKAGE = "com.example.app"


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
    """A device that returns from every adb call but reveals no outcome."""

    def shell(self, args: Any, timeout: float | None = None) -> str:
        return ""

    def app_current(self, timeout: float | None = None) -> Any:
        raise RuntimeError("cannot read foreground")

    def uninstall(self, package: str, timeout: float | None = None) -> str:
        return ""

    def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> str:
        return ""


def _backend(monkeypatch: Any) -> AdbBackend:
    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", lambda serial: _FakeDev())
    return backend


def test_install_reports_note_when_the_package_id_is_unreadable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not really an apk")
    backend = _backend(monkeypatch)
    monkeypatch.setattr(adb_client, "_apk_package_name", lambda path: None)
    payload = backend.install(_SERIAL, str(apk))
    assert payload["installed"] is None
    assert "package" not in payload
    assert payload["note"]
    doc = _tool_docstring("device.install")
    assert "note" in doc


def test_uninstall_reports_note_when_it_cannot_verify(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch)

    def cannot_check(dev: Any, package: str) -> str:
        raise AdbError("backend_error", "pm path failed")

    monkeypatch.setattr(adb_client, "_pm_path", cannot_check)
    payload = backend.uninstall(_SERIAL, _PACKAGE)
    assert payload["uninstalled"] is None
    assert payload["package"] == _PACKAGE
    assert payload["note"]
    doc = _tool_docstring("device.uninstall")
    assert "note" in doc


def test_launch_reports_note_and_no_foreground_when_it_cannot_read(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch)
    payload = backend.launch(_SERIAL, _PACKAGE)
    assert payload["launched"] is None
    assert "foreground" not in payload
    assert payload["package"] == _PACKAGE
    assert payload["note"]
    doc = _tool_docstring("device.launch")
    assert "note" in doc


def test_force_stop_reports_note_and_no_pids_when_it_cannot_read(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch)
    monkeypatch.setattr(adb_client, "_pids_for_package", lambda dev, package: None)
    payload = backend.force_stop(_SERIAL, _PACKAGE)
    assert payload["stopped"] is None
    assert "remaining_pids" not in payload
    assert payload["package"] == _PACKAGE
    assert payload["note"]
    doc = _tool_docstring("device.force_stop")
    assert "note" in doc
