"""The installed process hooks themselves: sys, thread, unraisable, asyncio."""

from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.error_boundary as boundary


@pytest.fixture
def hook_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fresh incident log plus automatic restore of every global hook."""
    logger = logging.getLogger("headless_re_mcp.incidents")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    monkeypatch.setattr(boundary, "_LOG_PATH", None)
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))
    # Re-setting the current values makes monkeypatch restore them on teardown,
    # so install_global_exception_hooks cannot leak into other tests.
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    return tmp_path / "incidents.log"


def test_keyboard_interrupt_is_passed_to_the_default_hook(
    hook_sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C must keep its normal exit behaviour, not become an incident."""
    boundary.install_global_exception_hooks("test-proc")
    seen: list[type[BaseException]] = []
    monkeypatch.setattr(sys, "__excepthook__", lambda exc_type, exc, tb: seen.append(exc_type))

    interrupt = KeyboardInterrupt()
    sys.excepthook(KeyboardInterrupt, interrupt, None)

    assert seen == [KeyboardInterrupt]
    assert not hook_sandbox.exists()


def test_an_uncaught_exception_prints_a_redacted_json_envelope(
    hook_sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    boundary.install_global_exception_hooks("test-proc")

    crash = RuntimeError("boom token=hunter2")
    sys.excepthook(RuntimeError, crash, None)

    envelope = json.loads(capsys.readouterr().err.strip())
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "uncaught_exception"
    assert "hunter2" not in envelope["error"]["message"]
    assert "[REDACTED]" in envelope["error"]["message"]
    assert envelope["error"]["details"]["context"] == "test-proc"
    assert "hunter2" not in hook_sandbox.read_text(encoding="utf-8")


def test_a_thread_hook_with_no_exception_still_records_an_incident(
    hook_sandbox: Path,
) -> None:
    boundary.install_global_exception_hooks("test-proc")

    args = SimpleNamespace(
        exc_type=RuntimeError,
        exc_value=None,
        exc_traceback=None,
        thread=SimpleNamespace(name="worker-9"),
    )
    threading.excepthook(args)  # type: ignore[arg-type]

    logged = hook_sandbox.read_text(encoding="utf-8")
    assert "context=thread:worker-9" in logged
    assert "thread exception hook received no exception" in logged


def test_the_unraisable_hook_records_real_and_synthesized_exceptions(
    hook_sandbox: Path,
) -> None:
    boundary.install_global_exception_hooks("test-proc")

    real = SimpleNamespace(
        exc_value=ValueError("del failed token=hunter2"),
        err_msg=None,
        object="<Finalizer token=hunter2>",
    )
    sys.unraisablehook(real)
    synthesized = SimpleNamespace(exc_value=None, err_msg="gc lost the exception", object="<gc>")
    sys.unraisablehook(synthesized)

    logged = hook_sandbox.read_text(encoding="utf-8")
    assert "del failed" in logged
    assert "gc lost the exception" in logged
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_an_explicit_loop_gets_the_asyncio_handler_installed(
    hook_sandbox: Path,
) -> None:
    installed: list[Any] = []
    loop = SimpleNamespace(set_exception_handler=installed.append)

    boundary.install_asyncio_exception_handler(loop)  # type: ignore[arg-type]

    assert len(installed) == 1
    installed[0](loop, {"exception": RuntimeError("unawaited token=hunter2")})
    logged = hook_sandbox.read_text(encoding="utf-8")
    assert "unawaited" in logged
    assert "hunter2" not in logged
