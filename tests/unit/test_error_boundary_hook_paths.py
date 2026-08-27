"""Coverage for the process/thread/unraisable/asyncio hook bodies.

``test_error_boundary.py`` exercises the tool, CLI, web and background-thread
boundaries end to end. This file drives the remaining hook internals directly:
the ``sys.excepthook`` arm (both the KeyboardInterrupt passthrough and the
scrubbed envelope it prints), the thread hook synthesizing an exception when the
loop hands it none, the unraisable hook for both a real exception and an
err_msg-only report, and the asyncio installer's explicit-loop branch. The
process-wide hooks are snapshotted with monkeypatch so installing them here
cannot leak into other tests.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import types
from pathlib import Path

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
def installed_hooks(incident_log: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install the global hooks with the originals snapshotted for restoration.

    ``monkeypatch.setattr`` records the current hook before install overwrites
    it, so teardown puts pytest's own hooks back and the install cannot bleed
    into unrelated tests.
    """
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    boundary.install_global_exception_hooks("test-process")
    return incident_log


# --------------------------------------------------------------------------- #
# sys.excepthook                                                              #
# --------------------------------------------------------------------------- #
def test_process_excepthook_prints_a_scrubbed_envelope(
    installed_hooks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = installed_hooks
    # A runtime value, not a source literal: the traceback frame shows the
    # f-string source (``password={secret}``), so only a scrubbed message could
    # leak the value into the envelope or the log.
    secret = "sk-live-" + "DEADBEEFcafe"
    try:
        raise RuntimeError(f"process boom password={secret}")
    except RuntimeError as exc:
        sys.excepthook(type(exc), exc, exc.__traceback__)

    captured = capsys.readouterr()
    envelope = json.loads(captured.err.strip().splitlines()[-1])
    assert envelope["error"]["code"] == "uncaught_exception"
    assert secret not in captured.err
    assert "[REDACTED]" in envelope["error"]["message"]
    logged = log.read_text(encoding="utf-8")
    assert "test-process" in logged
    assert secret not in logged


def test_process_excepthook_delegates_keyboard_interrupt(
    installed_hooks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ctrl-C is not an incident; it is handed to the default hook untouched."""
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    captured = capsys.readouterr()
    assert "KeyboardInterrupt" in captured.err
    # The default hook does not emit our JSON envelope for an interrupt.
    assert "uncaught_exception" not in captured.err
    assert not installed_hooks.exists()


# --------------------------------------------------------------------------- #
# threading.excepthook                                                        #
# --------------------------------------------------------------------------- #
def test_thread_hook_synthesizes_an_exception_when_none_is_given(
    installed_hooks: Path,
) -> None:
    """A thread hook fired with no exception object still records an incident."""
    args = threading.ExceptHookArgs((RuntimeError, None, None, threading.current_thread()))
    threading.excepthook(args)
    logged = installed_hooks.read_text(encoding="utf-8")
    assert "thread exception hook received no exception" in logged


# --------------------------------------------------------------------------- #
# sys.unraisablehook                                                          #
# --------------------------------------------------------------------------- #
def test_unraisable_hook_records_a_real_exception(installed_hooks: Path) -> None:
    args = types.SimpleNamespace(
        exc_type=ValueError,
        exc_value=ValueError("finalizer failed token=hunter2"),
        exc_traceback=None,
        err_msg=None,
        object="doomed-object",
    )
    sys.unraisablehook(args)
    logged = installed_hooks.read_text(encoding="utf-8")
    assert "unraisable:doomed-object" in logged
    assert "hunter2" not in logged


def test_unraisable_hook_synthesizes_when_there_is_no_exception(
    installed_hooks: Path,
) -> None:
    args = types.SimpleNamespace(
        exc_type=None,
        exc_value=None,
        exc_traceback=None,
        err_msg="gc could not finalize an object",
        object=None,
    )
    sys.unraisablehook(args)
    logged = installed_hooks.read_text(encoding="utf-8")
    assert "gc could not finalize an object" in logged


# --------------------------------------------------------------------------- #
# install_asyncio_exception_handler with an explicit loop                     #
# --------------------------------------------------------------------------- #
def test_asyncio_handler_accepts_an_explicit_loop(incident_log: Path) -> None:
    """Passing a loop skips the get_running_loop lookup and installs on it."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        boundary.install_asyncio_exception_handler(loop)
        handler = loop.get_exception_handler()
        assert handler is not None
        handler(loop, {"exception": RuntimeError("explicit-loop failure")})
    finally:
        loop.close()

    logged = incident_log.read_text(encoding="utf-8")
    assert "explicit-loop failure" in logged
    assert "asyncio" in logged
