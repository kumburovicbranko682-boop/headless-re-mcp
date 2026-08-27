"""frida.attach.app authorizes a running app's pid without relaunching it.

frida.spawn is the only way a device session could authorize a pid, and spawn
restarts the app from scratch -- there was no way to hook an app already running
(e.g. after a manual login). attach resolves the live pid of a named package
from the device's application listing and adds it to the session's authorized
set, the same bounded target model as spawn, so frida.java.* and
frida.hook.template can then target it.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.core.service_frida import FridaDeviceMixin
from headless_re_mcp.core.session import SessionRegistry
from headless_re_mcp.tools.frida import build_frida_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Repo:
    def record_backend(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def append_timeline(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


class _Service(FridaDeviceMixin):
    def __init__(self) -> None:
        self.registry = SessionRegistry()
        self.repository = _Repo()


class _RecordingFrida:
    """A fake FridaClient returning a fixed application listing."""

    def __init__(self, applications: list[dict[str, Any]]) -> None:
        self._applications = applications
        self.calls: list[dict[str, Any]] = []

    def applications(self, device_id: object, *, limit: int) -> dict[str, Any]:
        self.calls.append({"device_id": device_id, "limit": limit})
        return {
            "applications": list(self._applications),
            "count": len(self._applications),
            "total": len(self._applications),
            "has_more": False,
        }


def _connected_service(
    monkeypatch: Any, applications: list[dict[str, Any]]
) -> tuple[_Service, str, _RecordingFrida]:
    fake = _RecordingFrida(applications)
    monkeypatch.setattr("headless_re_mcp.core.service_frida.FridaClient", lambda: fake)
    service = _Service()
    session = service.registry.create("https://example.invalid")
    service.registry.update_metadata(
        session.id,
        {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}},
    )
    return service, session.id, fake


def test_a_running_app_is_authorized_by_its_live_pid(monkeypatch: Any) -> None:
    """Measured: com.example.app running at pid 5678 -> authorized, not relaunched."""
    service, session_id, fake = _connected_service(
        monkeypatch,
        [
            {"identifier": "com.other.app", "name": "Other", "pid": 0},
            {"identifier": "com.example.app", "name": "Example", "pid": 5678},
        ],
    )
    result = service.frida_attach_app(session_id, "com.example.app")
    assert result.ok
    assert result.data is not None
    assert result.data["package"] == "com.example.app"
    assert result.data["pid"] == 5678
    assert result.data["device"] == "usb"
    # There is no spawned/attached field to misread as a relaunch.
    assert "spawned" not in result.data
    assert "attached" not in result.data
    # The pid joins the session's authorized set so java/hook can target it.
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == [5678]
    assert auth["packages"] == ["com.example.app"]
    # It resolved from a single bounded application scan, not a spawn.
    assert fake.calls == [{"device_id": "usb", "limit": 1000}]


def test_an_installed_but_not_running_app_is_told_to_launch_or_spawn(
    monkeypatch: Any,
) -> None:
    """Measured: pid 0 (installed, not running) -> invalid_state, nothing authorized.

    The message points at both ways forward -- device.launch to start it, or
    frida.spawn to relaunch -- rather than the frida.java 'call frida.spawn
    first' error, which would hide that the app is already installed.
    """
    service, session_id, _fake = _connected_service(
        monkeypatch,
        [{"identifier": "com.example.app", "name": "Example", "pid": 0}],
    )
    result = service.frida_attach_app(session_id, "com.example.app")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"
    assert "not running" in result.error.message
    assert "frida.spawn" in result.error.message
    assert "device.launch" in result.error.message
    # A failed attach must not authorize anything.
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == []


def test_an_uninstalled_package_is_treated_as_not_running(monkeypatch: Any) -> None:
    """A package absent from the listing is not running, so attach refuses it."""
    service, session_id, _fake = _connected_service(
        monkeypatch,
        [{"identifier": "com.other.app", "name": "Other", "pid": 111}],
    )
    result = service.frida_attach_app(session_id, "com.example.app")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == []


def test_attach_without_a_connected_device_is_refused(monkeypatch: Any) -> None:
    """Attach requires frida.device.connect first, the same guard as spawn."""
    fake = _RecordingFrida([])
    monkeypatch.setattr("headless_re_mcp.core.service_frida.FridaClient", lambda: fake)
    service = _Service()
    session = service.registry.create("https://example.invalid")
    result = service.frida_attach_app(session.id, "com.example.app")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"
    assert "frida.device.connect" in result.error.message
    # No device means no application scan was ever attempted.
    assert fake.calls == []


def test_a_blank_package_is_rejected_before_scanning(monkeypatch: Any) -> None:
    service, session_id, fake = _connected_service(monkeypatch, [])
    result = service.frida_attach_app(session_id, "   ")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert fake.calls == []


def test_a_malformed_package_is_rejected_like_spawn(monkeypatch: Any) -> None:
    """A path or bare name is invalid_params up front, not a 'not running' scan.

    attach shares frida.spawn's package contract, so an agent that hands it a
    pulled file path gets the same "must be an Android package id" refusal
    instead of a misleading suggestion to launch or spawn it -- and no device
    enumeration is spent on input that can never name a running package.
    """
    for bad in (r"C:\Windows\notepad.exe", "/system/bin/sh", "notapackage"):
        service, session_id, fake = _connected_service(
            monkeypatch,
            [{"identifier": "com.example.app", "name": "Example", "pid": 5678}],
        )
        result = service.frida_attach_app(session_id, bad)
        assert not result.ok, bad
        assert result.error is not None
        assert result.error.code == "invalid_params", bad
        assert "Android package id" in result.error.message
        assert fake.calls == [], bad


def test_the_tool_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("frida.attach.app")
    assert "Answers with package, pid and device" in doc
    assert "There is no spawned" in doc
