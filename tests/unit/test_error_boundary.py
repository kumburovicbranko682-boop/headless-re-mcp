from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

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


def test_tool_exception_returns_ai_envelope_and_logs(
    incident_log: Path,
) -> None:
    def boom(*, token: str) -> dict[str, object]:
        raise RuntimeError(f"broken token={token}")

    guarded = boundary.guard_tool_handler(boom, tool_name="test.boom")
    result = guarded(token="top-secret")
    assert result["ok"] is False
    assert result["error"]["code"] == "internal_error"  # type: ignore[index]
    encoded = json.dumps(result)
    assert "top-secret" not in encoded
    assert "incident_id" in encoded
    assert incident_log.is_file()
    logged = incident_log.read_text(encoding="utf-8")
    assert "test.boom" in logged
    assert "top-secret" not in logged
    assert "[REDACTED]" in logged


@pytest.mark.parametrize(
    "marker",
    [
        "api_key=sk-DEADBEEFsecret",
        "api-key: sk-DEADBEEFsecret",
        "apikey = sk-DEADBEEFsecret",
        "token=sk-DEADBEEFsecret",
        "TOKEN: sk-DEADBEEFsecret",
        "secret=sk-DEADBEEFsecret",
        "Password=sk-DEADBEEFsecret",
        "Authorization: Bearer sk-DEADBEEFsecret",
        # Keywords the structured redactor already masks; the inline scrubber
        # guards higher-exposure channels (on-disk log, 500 body) and must
        # cover the same set or a payload-safe secret leaks when it lands in a
        # message instead.
        "private_key=sk-DEADBEEFsecret",
        "private-key: sk-DEADBEEFsecret",
        "access_key=sk-DEADBEEFsecret",
        "passwd=sk-DEADBEEFsecret",
        "credential: sk-DEADBEEFsecret",
    ],
)
def test_every_sensitive_keyword_form_is_redacted(marker: str) -> None:
    """The redactor guards incident logs and envelopes; the keyword set is the guard.

    ``record_exception`` and the envelope both run messages through this regex,
    so if an edit drops a keyword or a separator the matching secret starts
    reaching disk in the clear. Pin the whole matrix -- every keyword, both
    ``:``/``=`` separators, the bearer header, and case-insensitivity -- and
    keep it aligned with the structured redactor's key set in redaction.py.
    """
    redacted = boundary._redact_text(f"connect failed while sending {marker} to host")

    assert "sk-DEADBEEFsecret" not in redacted
    assert "[REDACTED]" in redacted


def test_redaction_leaves_ordinary_diagnostics_intact() -> None:
    """Over-redaction would blind an operator; only secret keywords are touched."""
    text = "read 4096 bytes at offset=1234 for session id=abc (retryable=false)"

    assert boundary._redact_text(text) == text


def test_a_bearer_secret_never_reaches_the_envelope_or_the_log(
    incident_log: Path,
) -> None:
    """A runtime bearer token in a failure message is scrubbed in envelope and log.

    The secret arrives as a value (not a source literal, which the traceback
    would show regardless), which is how a real credential reaches an error, and
    must survive neither the caller-facing envelope nor the on-disk incident log.
    """

    def call_api(*, authorization: str) -> dict[str, object]:
        raise RuntimeError(f"upstream rejected {authorization}")

    guarded = boundary.guard_tool_handler(call_api, tool_name="net.call")
    result = guarded(authorization="Authorization: Bearer sk-DEADBEEFsecret")

    assert result["ok"] is False
    encoded = json.dumps(result)
    assert "sk-DEADBEEFsecret" not in encoded
    assert "[REDACTED]" in encoded
    logged = incident_log.read_text(encoding="utf-8")
    assert "sk-DEADBEEFsecret" not in logged
    assert "[REDACTED]" in logged


def test_tool_system_exit_cannot_terminate_server(incident_log: Path) -> None:
    def exits() -> dict[str, object]:
        raise SystemExit(9)

    result = boundary.guard_tool_handler(exits, tool_name="test.exit")()
    assert result["ok"] is False
    assert result["error"]["code"] == "internal_error"  # type: ignore[index]
    assert "SystemExit" in result["error"]["message"]  # type: ignore[index]
    assert incident_log.is_file()


def test_web_exception_returns_json_instead_of_crashing(incident_log: Path) -> None:
    app = FastAPI()
    boundary.register_fastapi_exception_boundary(app)

    @app.get("/boom")
    def boom() -> None:
        raise LookupError("web exploded")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
    assert response.status_code == 500
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error"]["code"] == "internal_error"
    assert payload["error"]["details"]["incident_id"]
    assert incident_log.is_file()


def test_a_web_handler_secret_is_scrubbed_from_the_500_body_and_log(
    incident_log: Path,
) -> None:
    """A raise carrying a runtime credential must not leak it over HTTP.

    The tool-level envelope is tested for this; the FastAPI boundary walks the
    same exception_envelope path, but nothing asserted the HTTP 500 body itself
    is scrubbed. Model the realistic case -- a secret interpolated into the
    message at runtime -- and require it absent from both the response and the
    incident log.
    """
    app = FastAPI()
    boundary.register_fastapi_exception_boundary(app)
    secret = "sk-live-" + "abcdef0123456789"

    @app.get("/leak")
    def leak() -> None:
        raise RuntimeError(f"upstream rejected Authorization: Bearer {secret}")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/leak")

    assert response.status_code == 500
    body = response.text
    assert secret not in body
    assert "REDACTED" in response.json()["error"]["message"]
    assert secret not in incident_log.read_text(encoding="utf-8")


def test_the_boundary_still_answers_when_its_own_log_cannot_be_opened(
    incident_log: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A volume with no space must not turn one failure into two.

    Every caller of record_exception is already handling a failure: except
    blocks, the three excepthooks, the asyncio handler, and the scheduler loop.
    A second exception thrown from inside the recorder escapes all of them, and
    in the scheduler that ends the task for good while HTTP carries on
    answering 200 -- the outage with no symptom anyone is watching.
    """

    def full_disk(*args: object, **kwargs: object) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(boundary, "attach_rotating_handler", full_disk)

    incident = boundary.record_exception(RuntimeError("original failure"), context="probe")

    assert incident["incident_id"], "the caller still needs an id to report"
    assert incident["message"] == "original failure", "the original failure must survive"
    assert incident["log_path"] is None, "an unwritten log must not be claimed as written"

    def boom() -> dict[str, object]:
        raise RuntimeError("broken")

    result = boundary.guard_tool_handler(boom, tool_name="test.boom")()
    assert result["ok"] is False
    assert result["error"]["code"] == "internal_error"  # type: ignore[index]


def test_startup_survives_a_log_file_it_cannot_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process that cannot write its logs must still start.

    resolve_log_dir says exactly that, and then the handler was built eagerly,
    so an unopenable path raised out of the first entry point that installed the
    hooks. The supervisor restarts a process that exits during startup, which
    turns one unwritable file into a crash loop and takes the service down for
    as long as the volume stays full.
    """
    (tmp_path / "incidents.log").mkdir()
    logger = logging.getLogger("headless_re_mcp.incidents")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    monkeypatch.setattr(boundary, "_LOG_PATH", None)
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))

    path = boundary.install_global_exception_hooks("test-process")

    assert path == (tmp_path / "incidents.log").resolve()
    incident = boundary.record_exception(RuntimeError("still works"), context="probe")
    assert incident["incident_id"], "the boundary must keep answering"


def test_run_cli_safely_turns_failures_into_exit_codes_not_tracebacks(
    incident_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI boundary: 0 passes through, Ctrl-C is 130, a crash is 1 + envelope.

    An AI caller drives these CLIs and parses stderr, so a crash must come out
    as one machine-readable envelope line (with secrets scrubbed), never a raw
    traceback, and the exit codes are the contract scripts branch on.
    """
    assert boundary.run_cli_safely(lambda: 0, context="cli-test") == 0

    def interrupted() -> int:
        raise KeyboardInterrupt

    assert boundary.run_cli_safely(interrupted, context="cli-test") == 130

    def explodes() -> int:
        credential = "hunter2"
        raise RuntimeError(f"backend rejected password={credential}")

    code = boundary.run_cli_safely(explodes, context="cli-test")
    captured = capsys.readouterr()

    assert code == 1
    assert "Traceback" not in captured.err
    assert "hunter2" not in captured.err
    envelope = json.loads(captured.err.strip().splitlines()[-1])
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "internal_error"
    assert "[REDACTED]" in envelope["error"]["message"]


def test_background_thread_exception_is_logged(incident_log: Path) -> None:
    boundary.install_global_exception_hooks("test-process")

    def boom() -> None:
        raise RuntimeError("thread exploded")

    thread = threading.Thread(target=boom, name="failing-worker")
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    logged = incident_log.read_text(encoding="utf-8")
    assert "thread:failing-worker" in logged
    assert "thread exploded" in logged


def test_the_asyncio_hook_logs_unawaited_failures_and_scrubs_secrets(
    incident_log: Path,
) -> None:
    """A task nobody awaited must leave a redacted incident, not vanish.

    The loop reports never-retrieved failures through its exception handler;
    ours must write the incident (scrubbed by the same redactor as every other
    boundary) and, when the loop hands over a context with no exception object
    at all -- callback errors do this -- synthesize one from the message
    rather than dropping the report.
    """
    import asyncio

    secret = "sk-live-" + "cafef00d0123"

    async def scenario() -> None:
        boundary.install_asyncio_exception_handler()
        loop = asyncio.get_running_loop()
        loop.call_exception_handler(
            {"exception": RuntimeError(f"provider refused api_key={secret}")}
        )
        loop.call_exception_handler({"message": "callback dropped mid-flight"})

    asyncio.run(scenario())

    logged = incident_log.read_text(encoding="utf-8")
    assert "asyncio" in logged
    assert secret not in logged
    assert "[REDACTED]" in logged
    assert "callback dropped mid-flight" in logged


def test_installing_the_asyncio_hook_outside_a_loop_is_a_quiet_no_op() -> None:
    """install_global_exception_hooks runs before any loop exists; it must not raise."""
    boundary.install_asyncio_exception_handler()


def test_the_asyncio_hook_accepts_an_explicit_loop() -> None:
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        boundary.install_asyncio_exception_handler(loop)
        assert loop.get_exception_handler() is not None
    finally:
        loop.close()


@pytest.fixture
def restored_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)


def test_the_process_hook_prints_an_envelope_and_forwards_ctrl_c(
    incident_log: Path,
    restored_hooks: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys

    boundary.install_global_exception_hooks("proc-test")

    sys.excepthook(RuntimeError, RuntimeError("password=hunter2 went bang"), None)
    err = capsys.readouterr().err
    payload = json.loads(err.strip().splitlines()[-1])
    assert payload["error"]["code"] == "uncaught_exception"
    assert "hunter2" not in err
    assert "[REDACTED]" in payload["error"]["message"]

    forwarded: list[tuple[object, ...]] = []
    monkeypatch.setattr(sys, "__excepthook__", lambda *args: forwarded.append(args))
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    assert forwarded and forwarded[0][0] is KeyboardInterrupt
    assert "uncaught_exception" not in capsys.readouterr().err


def test_the_thread_hook_synthesizes_a_missing_exception(
    incident_log: Path, restored_hooks: None
) -> None:
    from types import SimpleNamespace
    from typing import Any, cast

    boundary.install_global_exception_hooks("proc-test")

    args = SimpleNamespace(exc_value=None, exc_traceback=None, thread=None)
    threading.excepthook(cast(Any, args))

    logged = incident_log.read_text(encoding="utf-8")
    assert "thread:unknown" in logged
    assert "received no exception" in logged


def test_the_unraisable_hook_logs_real_and_synthesized_failures(
    incident_log: Path, restored_hooks: None
) -> None:
    import sys
    from types import SimpleNamespace
    from typing import Any, cast

    boundary.install_global_exception_hooks("proc-test")

    sys.unraisablehook(
        cast(Any, SimpleNamespace(exc_value=ValueError("del exploded"), object="finalizer"))
    )
    sys.unraisablehook(
        cast(Any, SimpleNamespace(exc_value=None, err_msg="gc dropped it", object="thing"))
    )

    logged = incident_log.read_text(encoding="utf-8")
    assert "unraisable:finalizer" in logged
    assert "del exploded" in logged
    assert "gc dropped it" in logged
