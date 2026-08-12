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
