from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# fastapi and the web app it powers are the optional ``web`` extra. Skip this
# module (rather than erroring out the whole tests/unit collection) when it is
# absent, matching the skip-!=-pass contract the backend gates follow.
TestClient = pytest.importorskip(
    "fastapi.testclient", reason="fastapi (web extra) not installed (skip != pass)"
).TestClient
create_app = pytest.importorskip("headless_re_mcp.web.app").create_app


def test_rejected_missions_do_not_leave_unbounded_empty_threads(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    """Validate a mission before creating the inbox that would own it.

    An 8,001-character objective is rejected by the store, but the route used
    to create its thread first. Twelve failed requests therefore left twelve
    empty threads, and empty threads are deliberately retained as inboxes, so
    retries could grow the database indefinitely without queuing any work.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        responses = [
            client.post(
                "/api/agent/missions",
                headers=headers,
                json={"objective": "x" * 8_001},
            )
            for _ in range(12)
        ]
        threads = client.get("/api/agent/threads", headers=headers).json()["threads"]

    assert {response.status_code for response in responses} == {400}
    assert threads == [], f"12 rejected missions leaked {len(threads)} retained threads"
