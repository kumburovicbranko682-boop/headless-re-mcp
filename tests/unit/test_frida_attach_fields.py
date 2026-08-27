"""frida.attach must name the probe fields it actually returns."""

from __future__ import annotations

import ast
import time
from pathlib import Path

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


def _attach_return() -> str:
    source = Path(FridaClient.attach.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def attach(self, pid: int")
    chunk = source[start : source.index("def modules(", start)]
    return chunk[chunk.rindex("return {") :]


def test_frida_attach_answers_with_pid_not_session() -> None:
    """The catalog said probe-attach and never named the object.

    Measured: FridaClient.attach returns pid, attached, device and note.
    There is no session, handle or session_id. Looking for session after
    success retries the probe against a debuggee that already handled it.
    """
    returned = _attach_return()
    assert '"pid": pid' in returned
    assert '"attached": True' in returned
    assert '"device": "local"' in returned
    assert '"note":' in returned
    assert '"session"' not in returned
    assert '"handle"' not in returned
    assert '"session_id"' not in returned
    described = _tool_docstring("frida.attach")
    assert "Answers with pid" in described
    assert "attached" in described
    assert "device" in described
    assert "note" in described
    assert "no session" in described


def test_frida_attach_times_out_instead_of_parking_the_worker() -> None:
    """frida.attach on a paused debuggee used to block the caller forever.

    Measured: a mock attach that never returns held the thread until the
    process was killed. The probe now has a deadline and raises the timeout
    envelope rather than occupying a worker.
    """

    class _Frida:
        def attach(self, pid: int) -> object:
            del pid
            time.sleep(10)
            raise AssertionError("attach should have been abandoned")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1, timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"


def test_frida_attach_does_not_report_success_when_detach_fails() -> None:
    """A probe that stays attached is a leak, not attached=true.

    The immediate detach is the whole contract of a probe attach: the session
    must not outlive the call. When detach fails the session is still resident
    in the target, so report the failure rather than a clean probe.
    """

    class _Session:
        def detach(self) -> None:
            raise RuntimeError("native session is still attached")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, timeout: _Session()  # type: ignore[method-assign]

    with pytest.raises(FridaError) as caught:
        client.attach(7, allowed_pid=7, timeout=0.2)

    assert caught.value.code == "frida_detach_failed"
    assert caught.value.details["pid"] == 7
