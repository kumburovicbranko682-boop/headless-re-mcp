"""Coverage for the installed excepthook bodies and the explicit-loop asyncio arm.

The existing suite installs the hooks and drives real threads/loops; these tests
reach the remaining branches by grabbing the installed hook callables and calling
them directly (delegated KeyboardInterrupt, synthesized exceptions, unraisable
objects) with the process-wide hook state saved and restored around each case.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.error_boundary as boundary


@pytest.fixture
def incident_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    logger = logging.getLogger("headless_re_mcp.incidents")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    monkeypatch.setattr(boundary, "_LOG_PATH", None)
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))
    return tmp_path / "incidents.log"


@pytest.fixture
def restore_hooks() -> object:
    saved = (sys.excepthook, threading.excepthook, sys.unraisablehook)
    try:
        yield
    finally:
        sys.excepthook, threading.excepthook, sys.unraisablehook = saved


def test_install_asyncio_handler_accepts_an_explicit_loop(incident_log: Path) -> None:
    loop = asyncio.new_event_loop()
    try:
        boundary.install_asyncio_exception_handler(loop)
        loop.call_exception_handler({"exception": RuntimeError("explicit-loop failure")})
    finally:
        loop.close()
    assert "asyncio" in incident_log.read_text(encoding="utf-8")


def test_sys_excepthook_delegates_keyboard_interrupt_and_reports_others(
    incident_log: Path,
    restore_hooks: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    boundary.install_global_exception_hooks("hook-test")
    hook = sys.excepthook

    hook(KeyboardInterrupt, KeyboardInterrupt(), None)
    assert "KeyboardInterrupt" in capsys.readouterr().err

    hook(RuntimeError, RuntimeError("token=sekret boom"), None)
    err = capsys.readouterr().err
    envelope = json.loads(err.strip().splitlines()[-1])
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "uncaught_exception"
    assert "sekret" not in err
    assert "hook-test" in incident_log.read_text(encoding="utf-8")


def test_thread_hook_synthesizes_a_missing_exception(
    incident_log: Path, restore_hooks: object
) -> None:
    boundary.install_global_exception_hooks("hook-test")
    thread_hook = threading.excepthook
    args = SimpleNamespace(
        exc_type=RuntimeError,
        exc_value=None,
        exc_traceback=None,
        thread=SimpleNamespace(name="ghost-worker"),
    )
    thread_hook(args)  # type: ignore[arg-type]
    logged = incident_log.read_text(encoding="utf-8")
    assert "thread:ghost-worker" in logged


def test_unraisable_hook_handles_present_and_missing_exceptions(
    incident_log: Path, restore_hooks: object
) -> None:
    boundary.install_global_exception_hooks("hook-test")
    unraisable_hook = sys.unraisablehook

    unraisable_hook(
        SimpleNamespace(
            exc_value=RuntimeError("finalizer blew up"),
            err_msg=None,
            object="widget",
        )
    )
    unraisable_hook(
        SimpleNamespace(
            exc_value=None,
            err_msg="destructor noise",
            object="gadget",
        )
    )
    logged = incident_log.read_text(encoding="utf-8")
    assert "unraisable:widget" in logged
    assert "finalizer blew up" in logged
    assert "destructor noise" in logged
