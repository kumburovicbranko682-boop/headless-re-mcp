"""frida.processes lists running processes on the session's frida device.

frida.applications lists what is *installed*; frida.processes lists what is
*running* via frida's own enumerate_processes, so an app id (or a non-app system
process) becomes an attachable target -- the pid frida.attach and the
frida.*_device hooks consume directly. These cover the {pid, name} shaping, the
pid sort, the name_filter (which reaches a target past the cap), the has_more
accounting, the enumerate-failure path, service routing, and the read-only class.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
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


class _ProcInfo:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.name = name


def _procs_client(procs: list[_ProcInfo]) -> FridaClient:
    class _ProcDev:
        def enumerate_processes(self) -> list[_ProcInfo]:
            return procs

    client = FridaClient()
    client._resolve_device = lambda device_id: _ProcDev()  # type: ignore[method-assign]
    return client


def test_frida_processes_lists_pid_and_name_sorted_by_pid() -> None:
    client = _procs_client(
        [
            _ProcInfo(4242, "com.example.app"),
            _ProcInfo(1, "init"),
            _ProcInfo(317, "surfaceflinger"),
        ]
    )
    out = client.processes("usb")
    assert out["count"] == 3
    assert out["total"] == 3
    assert out["has_more"] is False
    # Ascending pid so the capped page is stable across calls.
    assert [row["pid"] for row in out["processes"]] == [1, 317, 4242]
    assert out["processes"][0] == {"pid": 1, "name": "init"}


def test_frida_processes_name_filter_is_case_insensitive() -> None:
    client = _procs_client(
        [
            _ProcInfo(1, "init"),
            _ProcInfo(10, "com.example.app"),
            _ProcInfo(11, "com.example.app:svc"),
            _ProcInfo(12, "surfaceflinger"),
        ]
    )
    out = client.processes("usb", name_filter="COM.EXAMPLE")
    assert {row["name"] for row in out["processes"]} == {
        "com.example.app",
        "com.example.app:svc",
    }
    assert out["total"] == 2


def test_frida_processes_filter_reaches_a_process_past_the_cap() -> None:
    procs = [_ProcInfo(index, f"proc{index}") for index in range(50)]
    procs.append(_ProcInfo(9999, "needle"))
    out = _procs_client(procs).processes("usb", limit=1, name_filter="needle")
    assert [row["name"] for row in out["processes"]] == ["needle"]
    assert out["total"] == 1
    assert out["has_more"] is False


def test_frida_processes_has_more_when_the_cap_is_hit() -> None:
    procs = [_ProcInfo(index, f"proc{index}") for index in range(20)]
    out = _procs_client(procs).processes("usb", limit=10)
    assert out["count"] == 10
    assert out["total"] == 20
    assert out["has_more"] is True


def test_frida_processes_enumerate_failure_is_backend_error() -> None:
    class _BoomDev:
        def enumerate_processes(self) -> list[_ProcInfo]:
            raise RuntimeError("frida-server is not running")

    client = FridaClient()
    client._resolve_device = lambda device_id: _BoomDev()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as info:
        client.processes("usb")
    assert info.value.code == "backend_error"


def test_service_frida_processes_routes_through_auth_to_the_client(
    monkeypatch: Any,
) -> None:
    from headless_re_mcp.core import service_frida
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        calls: list[Any] = []

        class _FakeClient:
            def processes(
                self, device_id: str | None, *, limit: int, name_filter: str
            ) -> dict[str, Any]:
                calls.append((device_id, limit, name_filter))
                return {
                    "processes": [{"pid": 1, "name": "init"}],
                    "count": 1,
                    "total": 1,
                    "has_more": False,
                }

        monkeypatch.setattr(service_frida, "FridaClient", _FakeClient)
        monkeypatch.setattr(
            service, "_frida_auth", lambda session_id: {"device_id": "usb"}
        )
        result = service.frida_processes("s", limit=50, name_filter="init")
        assert result.ok and result.data is not None
        assert result.data["processes"][0]["name"] == "init"
        assert calls == [("usb", 50, "init")]
    finally:
        service.close_all()


def test_frida_processes_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("frida.processes").split())
    assert "frida.applications" in doc
    assert "frida.attach" in doc
    assert "name_filter" in doc
    assert "Read-only" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "frida.processes" in _READ_ONLY_NAMES
