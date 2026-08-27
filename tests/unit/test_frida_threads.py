"""frida.threads maps enumerateThreads and says when a page is not the whole list.

The frida native runtime cannot run in CI, so the mapping is exercised through
the same API mock the modules/exports tests use, and the RPC script content is
guarded statically the way the memory.read test does.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import _ENUM_SCRIPT, FridaClient
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


class _ThreadsApi:
    def threads(self, limit: int) -> dict[str, Any]:
        del limit
        return {
            "threads": [
                {"id": 1000 + index, "state": "running", "pc": "0x1", "sp": "0x2"}
                for index in range(25)
            ],
            "total": 25,
        }


class _ThreadsScript:
    exports_sync = _ThreadsApi()

    def load(self) -> None:
        return None


class _ThreadsSession:
    def create_script(self, source: str) -> _ThreadsScript:
        del source
        return _ThreadsScript()

    def detach(self) -> None:
        return None


class _ThreadsFrida:
    def attach(self, pid: int) -> _ThreadsSession:
        del pid
        return _ThreadsSession()


def _client() -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _ThreadsFrida()
    return client


def test_frida_threads_puts_the_list_in_threads_and_says_when_it_stopped() -> None:
    """Measured shape: 25 threads, limit 10 -> count 10, total 25, has_more True.

    The field is threads, not items or enumerations, and each row keeps id,
    state, pc and sp. A full page with has_more unnamed would read as every
    thread in the process.
    """
    payload = _client().threads(1, allowed_pid=1, limit=10)
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["threads"]) == 10
    assert payload["has_more"] is True
    first = payload["threads"][0]
    assert first["id"] == 1000
    assert first["state"] == "running"
    assert first["pc"] == "0x1"
    assert first["sp"] == "0x2"
    doc = _tool_docstring("frida.threads")
    assert "Answers with threads" in doc
    assert "has_more" in doc
    assert "pc" in doc


class _ThreadsNoContextApi:
    """A thread whose context could not be read comes back with empty pc/sp."""

    def threads(self, limit: int) -> dict[str, Any]:
        del limit
        return {"threads": [{"id": 7, "state": "waiting", "pc": "", "sp": ""}], "total": 1}


def test_frida_threads_keeps_a_context_less_thread_with_empty_pc_sp() -> None:
    client = FridaClient()
    client._available = True
    client._frida = type(
        "_F",
        (),
        {
            "attach": lambda self, pid: type(
                "_S",
                (),
                {
                    "create_script": lambda self, source: type(
                        "_Sc",
                        (),
                        {"exports_sync": _ThreadsNoContextApi(), "load": lambda self: None},
                    )(),
                    "detach": lambda self: None,
                },
            )()
        },
    )()
    payload = client.threads(1, allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["has_more"] is False
    assert payload["threads"][0] == {"id": 7, "state": "waiting", "pc": "", "sp": ""}


def test_threads_rpc_uses_process_enumerate_threads() -> None:
    """The RPC must call the real enumerator and read cross-arch pc/sp aliases."""
    assert "threads: function" in _ENUM_SCRIPT
    assert "Process.enumerateThreads()" in _ENUM_SCRIPT
    assert "t.context.pc.toString()" in _ENUM_SCRIPT
    assert "t.context.sp.toString()" in _ENUM_SCRIPT
