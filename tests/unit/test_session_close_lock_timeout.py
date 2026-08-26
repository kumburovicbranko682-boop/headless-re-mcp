"""Session teardown must not wait forever behind a hung backend call."""

from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

from pytest import MonkeyPatch

import headless_re_mcp.core.service as service_module
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService, _BackendRuntime


def test_close_session_times_out_waiting_for_a_busy_runtime(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """One permanently held request lock must not permanently hold close."""

    class _Worker:
        def __init__(self) -> None:
            self.closed = False
            self.terminated = False

        def close(self, *, timeout: float = 15.0) -> None:
            del timeout
            self.closed = True

        def terminate(self) -> None:
            self.terminated = True

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    worker = _Worker()
    runtime = _BackendRuntime(worker=worker)  # type: ignore[arg-type]
    service._runtime_owner.begin_open(session_id, BackendKind.IDA)
    service._runtime_owner.put(session_id, BackendKind.IDA, runtime)
    monkeypatch.setattr(
        service_module,
        "_RUNTIME_CLOSE_LOCK_TIMEOUT_S",
        0.05,
        raising=False,
    )

    runtime.lock.acquire()
    results: list[Any] = []
    close_thread = threading.Thread(
        target=lambda: results.append(service.close_session(session_id)),
        daemon=True,
    )
    close_thread.start()
    close_thread.join(timeout=0.25)
    returned_within_bound = not close_thread.is_alive()
    runtime.lock.release()
    close_thread.join(timeout=2.0)

    assert returned_within_bound, "session.close remained blocked behind the runtime lock"
    assert len(results) == 1
    result = results[0]
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_close_timeout"
    assert worker.closed is False
    assert worker.terminated is True
