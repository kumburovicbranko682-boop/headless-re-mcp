"""The process/thread/unraisable/asyncio hook branches of error_boundary.

test_error_boundary pins the tool/CLI/web envelopes, the redactor and the
background-thread and asyncio happy paths. This file reaches the hook arms
those step over: the sys excepthook's KeyboardInterrupt vs regular split, the
thread hook synthesizing an exception when none is supplied, the unraisable
hook's non-exception fallback, and installing the asyncio handler against an
explicit loop rather than the running one. Each test installs the real hooks,
drives one arm, and restores the interpreter hooks afterwards.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from collections.abc import Iterator
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
def restore_hooks() -> Iterator[None]:
    saved = (sys.excepthook, threading.excepthook, sys.unraisablehook)
    try:
        yield
    finally:
        sys.excepthook, threading.excepthook, sys.unraisablehook = saved


def test_asyncio_handler_accepts_an_explicit_loop(incident_log: Path) -> None:
    """Passing a loop installs the handler on it without needing a running loop."""
    loop = asyncio.new_event_loop()
    try:
        boundary.install_asyncio_exception_handler(loop)
        assert loop.get_exception_handler() is not None
        loop.call_exception_handler({"exception": RuntimeError("provider refused api_key=sk-x")})
    finally:
        loop.close()
    logged = incident_log.read_text(encoding="utf-8")
    assert "asyncio" in logged
    assert "sk-x" not in logged
    assert "[REDACTED]" in logged


def test_sys_excepthook_splits_keyboard_interrupt_from_regular_errors(
    incident_log: Path, restore_hooks: None, capsys: pytest.CaptureFixture[str]
) -> None:
    boundary.install_global_exception_hooks("test-process")
    hook = sys.excepthook

    hook(KeyboardInterrupt, KeyboardInterrupt(), None)
    hook(ValueError, ValueError("boom api_key=sk-secret"), None)

    err = capsys.readouterr().err
    assert "uncaught_exception" in err
    assert "sk-secret" not in err
    assert "[REDACTED]" in err
    assert incident_log.is_file()


def test_thread_hook_synthesizes_an_exception_when_none_is_given(
    incident_log: Path, restore_hooks: None
) -> None:
    boundary.install_global_exception_hooks("test-process")
    args = SimpleNamespace(
        exc_type=RuntimeError, exc_value=None, exc_traceback=None, thread=None
    )
    threading.excepthook(args)  # type: ignore[arg-type]
    logged = incident_log.read_text(encoding="utf-8")
    assert "thread:unknown" in logged
    assert "thread exception hook received no exception" in logged


def test_unraisable_hook_handles_missing_and_present_exceptions(
    incident_log: Path, restore_hooks: None
) -> None:
    boundary.install_global_exception_hooks("test-process")

    sys.unraisablehook(  # type: ignore[arg-type]
        SimpleNamespace(exc_value=None, err_msg="gc could not finalize", object="widget")
    )
    sys.unraisablehook(  # type: ignore[arg-type]
        SimpleNamespace(exc_value=ValueError("late boom"), err_msg=None, object="other")
    )

    logged = incident_log.read_text(encoding="utf-8")
    assert "unraisable:widget" in logged
    assert "gc could not finalize" in logged
    assert "unraisable:other" in logged
