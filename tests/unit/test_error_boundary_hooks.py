"""Direct coverage for the process/thread/unraisable/asyncio hook bodies.

test_error_boundary.py installs these hooks and proves the *effects* that flow
through a real thread or event loop, but the hook closures themselves -- the
sys.excepthook envelope, its KeyboardInterrupt passthrough, and the two
synthesise-an-exception fallbacks in the thread and unraisable hooks -- are
never invoked directly, so their branches went unverified. This file calls
each installed hook by hand with the awkward inputs the interpreter really
hands them (a KeyboardInterrupt, an args struct with no exception object) and
pins what they record and print.
"""

from __future__ import annotations

import asyncio
import json
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
    """install_global_exception_hooks mutates interpreter-wide hooks; put them back."""
    saved = (sys.excepthook, threading.excepthook, sys.unraisablehook)
    try:
        yield
    finally:
        sys.excepthook, threading.excepthook, sys.unraisablehook = saved


def test_sys_excepthook_prints_a_scrubbed_envelope_for_an_uncaught_exception(
    incident_log: Path, restore_hooks: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The installed excepthook must emit one machine-readable, secret-free line."""
    boundary.install_global_exception_hooks("test-process")

    sys.excepthook(
        RuntimeError,
        RuntimeError("crashed with api_key=sk-DEADBEEFsecret"),
        None,
    )

    captured = capsys.readouterr()
    envelope = json.loads(captured.err.strip().splitlines()[-1])
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "uncaught_exception"
    assert "sk-DEADBEEFsecret" not in captured.err
    assert "[REDACTED]" in envelope["error"]["message"]
    assert envelope["error"]["details"]["incident_id"]
    logged = incident_log.read_text(encoding="utf-8")
    assert "sk-DEADBEEFsecret" not in logged
    assert "[REDACTED]" in logged


def test_sys_excepthook_delegates_keyboard_interrupt_to_the_default(
    incident_log: Path, restore_hooks: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C must reach the stock handler, not become an incident envelope."""
    boundary.install_global_exception_hooks("test-process")
    seen: list[type[BaseException]] = []
    monkeypatch.setattr(sys, "__excepthook__", lambda exc_type, exc, tb: seen.append(exc_type))

    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)

    assert seen == [KeyboardInterrupt]
    assert not incident_log.exists(), "a Ctrl-C must not be recorded as an incident"


def test_thread_hook_synthesizes_an_exception_when_none_is_supplied(
    incident_log: Path, restore_hooks: None
) -> None:
    """threading can hand the hook an args struct whose exc_value is None."""
    boundary.install_global_exception_hooks("test-process")

    threading.excepthook(
        SimpleNamespace(  # type: ignore[arg-type]  # hook only reads a few attributes
            exc_type=None,
            exc_value=None,
            exc_traceback=None,
            thread=SimpleNamespace(name="orphan-worker"),
        )
    )

    logged = incident_log.read_text(encoding="utf-8")
    assert "thread:orphan-worker" in logged
    assert "received no exception" in logged


def test_unraisable_hook_synthesizes_from_err_msg_and_scrubs_the_object(
    incident_log: Path, restore_hooks: None
) -> None:
    """An unraisable with no exception object still leaves a redacted incident.

    __del__ failures arrive here with exc_value possibly None and the offending
    object's repr in ``object``; both the synthesised message and that repr can
    carry a runtime secret, so both must be scrubbed before they hit the log.
    """
    boundary.install_global_exception_hooks("test-process")

    sys.unraisablehook(
        SimpleNamespace(
            exc_value=None,
            err_msg="finalizer failed with token=sk-DEADBEEFsecret",
            object="<Conn password=sk-OTHERsecret>",
            exc_traceback=None,
        )
    )

    logged = incident_log.read_text(encoding="utf-8")
    assert "unraisable:" in logged
    assert "sk-DEADBEEFsecret" not in logged
    assert "sk-OTHERsecret" not in logged
    assert "[REDACTED]" in logged


def test_unraisable_hook_records_a_real_exception_object_directly(
    incident_log: Path, restore_hooks: None
) -> None:
    """When the args already carry a BaseException, it is recorded as-is."""
    boundary.install_global_exception_hooks("test-process")

    sys.unraisablehook(
        SimpleNamespace(
            exc_value=ValueError("finalizer raised ValueError"),
            err_msg="Exception ignored in",
            object="<Widget>",
            exc_traceback=None,
        )
    )

    logged = incident_log.read_text(encoding="utf-8")
    assert "unraisable:" in logged
    assert "ValueError" in logged


def test_installing_the_asyncio_hook_with_an_explicit_loop_targets_that_loop() -> None:
    """Passing a loop skips the get_running_loop lookup and binds that loop."""
    loop = asyncio.new_event_loop()
    try:
        assert loop.get_exception_handler() is None
        boundary.install_asyncio_exception_handler(loop)
        assert loop.get_exception_handler() is not None
    finally:
        loop.close()
