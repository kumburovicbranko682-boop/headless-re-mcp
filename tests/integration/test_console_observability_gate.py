"""Console observability gate: the operator's live view is real, over real HTTP.

The serve-web HTTP gate proves boot, auth, probes, and the session lifecycle.
What it does not touch is the part of the console an operator actually watches
and pulls evidence from:

* the live monitor -- ``GET /api/sessions/{id}/monitor`` one-shot and the
  ``/monitor/stream`` Server-Sent-Events feed the browser's EventSource
  consumes (token in the query string, because EventSource cannot set
  headers), streaming bounded frames and closing with an ``end`` event;
* the artifact plane -- ``GET /api/artifacts`` and
  ``GET /api/artifacts/{id}/file``, which must hand back the *actual bytes* of
  a generated report and 404 on anything else;
* the audit read surface -- ``GET /api/audit`` showing what was done to the
  session, honestly attributed;
* the generic write proxy -- ``POST /api/write/{action}``, which must demand
  ``confirm``, refuse unknown actions, and really execute an allowed one.

Everything runs against a real ``python -m headless_re_mcp serve-web`` process
with isolated config and artifact roots, driving the committed PE fixture.
Pure Python, any platform: session.create only classifies and binds.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_TOKEN = "console-observability-gate-" + "y" * 20
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextmanager
def _serve_web(tmp_root: Path) -> Iterator[str]:
    config_home = tmp_root / "config"
    (config_home / "headless-re-mcp").mkdir(parents=True, exist_ok=True)
    (config_home / "headless-re-mcp" / "web_token.json").write_text(
        json.dumps({"token": _TOKEN}), encoding="utf-8"
    )
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_root / "artifacts")
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "headless_re_mcp", "serve-web", "--port", str(port)],
        cwd=str(_PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + _BOOT_TIMEOUT_S
        while True:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise AssertionError(f"serve-web exited during boot:\n{output}")
            try:
                if httpx.get(f"{base_url}/healthz", timeout=2.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert time.monotonic() < deadline, "serve-web never became healthy"
            time.sleep(0.2)
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15.0)


@contextmanager
def _console(tmp_path: Path) -> Iterator[httpx.Client]:
    with (
        _serve_web(tmp_path) as base_url,
        httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {_TOKEN}"},
            timeout=30.0,
        ) as client,
    ):
        yield client


def _open_session(http: httpx.Client) -> str:
    created = http.post("/api/sessions", json={"binary": str(_PE_FIXTURE)})
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["ok"] is True, body
    return str(body["data"]["session"]["id"])


def _sse_events(response: httpx.Response) -> Iterator[tuple[str, dict[str, Any]]]:
    event_type: str | None = None
    for line in response.iter_lines():
        if line.startswith("event:"):
            event_type = line[6:].strip()
        elif line.startswith("data:") and event_type is not None:
            yield event_type, json.loads(line[5:].strip())
            event_type = None


@pytest.mark.integration
@pytest.mark.headless
def test_monitor_serves_snapshots_and_a_bounded_sse_feed(tmp_path: Path) -> None:
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    with _console(tmp_path) as http:
        session_id = _open_session(http)
        report = http.post(
            f"/api/sessions/{session_id}/report", json={"title": "Monitor gate"}
        ).json()
        assert report["ok"] is True
        artifact_id = report["data"]["artifact_id"]

        # One-shot snapshot: the frame reflects what actually happened.
        snapshot = http.get(f"/api/sessions/{session_id}/monitor").json()
        assert snapshot["ok"] is True
        frame = snapshot["data"]
        assert frame["session_id"] == session_id
        timeline_events = [entry["event"] for entry in frame["timeline"]["items"]]
        assert timeline_events, "monitor frame carried no timeline"
        listed = frame["artifacts"]["items"]
        assert artifact_id in {item["id"] for item in listed}

        # Live feed, authenticated the way EventSource has to: token in the
        # query string. Bounded frames, then a clean end event.
        frames: list[dict[str, Any]] = []
        ended = False
        with http.stream(
            "GET",
            f"/api/sessions/{session_id}/monitor/stream",
            params={"token": _TOKEN, "interval_ms": 250, "max_frames": 3},
            headers={"Authorization": ""},
        ) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            for event_type, payload in _sse_events(response):
                if event_type == "monitor":
                    frames.append(payload)
                elif event_type == "end":
                    ended = True
        assert ended, "stream never sent its end event"
        assert len(frames) == 3
        for item in frames:
            assert item["ok"] is True
            assert item["data"]["session_id"] == session_id
        # The live frames see the same artifact the snapshot saw.
        assert artifact_id in {entry["id"] for entry in frames[-1]["data"]["artifacts"]["items"]}

        # A vanished session yields an honest error frame, not a fake dashboard.
        missing = http.get("/api/sessions/does-not-exist/monitor").json()
        assert missing["ok"] is False
        assert missing["data"]["error"]["code"]

        # And without any token the stream endpoint refuses outright.
        bare = httpx.get(f"{http.base_url}/api/sessions/{session_id}/monitor/stream", timeout=10.0)
        assert bare.status_code == 401


@pytest.mark.integration
@pytest.mark.headless
def test_artifact_bytes_and_audit_come_back_over_http(tmp_path: Path) -> None:
    assert _PE_FIXTURE.is_file()
    with _console(tmp_path) as http:
        session_id = _open_session(http)
        report = http.post(
            f"/api/sessions/{session_id}/report", json={"title": "Evidence pull"}
        ).json()
        artifact_id = report["data"]["artifact_id"]
        markdown = report["data"]["markdown"]

        listing = http.get("/api/artifacts", params={"session_id": session_id}).json()
        assert listing["ok"] is True
        match = [item for item in listing["data"]["artifacts"] if item["id"] == artifact_id]
        assert match and match[0]["kind"] == "report_markdown"

        # The download is the artifact's actual bytes, not a rendering of them.
        download = http.get(f"/api/artifacts/{artifact_id}/file")
        assert download.status_code == 200
        assert download.text == markdown
        assert "Evidence pull" in download.text

        assert http.get("/api/artifacts/nope/file").status_code == 404

        # The audit trail attributes the real operations to the real session.
        audit = http.get("/api/audit", params={"session_id": session_id}).json()
        assert audit["ok"] is True
        entries = audit["data"]["entries"]
        assert entries, "audit trail is empty after two writes"
        assert all(entry["session_id"] == session_id for entry in entries)
        actions = {entry["action"] for entry in entries}
        assert "session.create" in actions, actions
        assert all(entry["ok"] for entry in entries)


@pytest.mark.integration
@pytest.mark.headless
def test_generic_write_proxy_demands_confirmation_and_executes(tmp_path: Path) -> None:
    with _console(tmp_path) as http:
        # No confirm, no execution -- and the refusal names the missing piece.
        refused = http.post("/api/write/artifacts.gc", json={"max_total_bytes": 1 << 29})
        assert refused.status_code == 400
        assert refused.json()["detail"] == "confirm_required"

        # Unknown or non-web actions are rejected before any dispatch.
        unknown = http.post("/api/write/no.such.tool", json={"confirm": True})
        assert unknown.status_code == 400
        assert unknown.json()["detail"] == "unknown_or_disallowed_write"

        # Bad parameters are a 400, not a crash.
        bad = http.post("/api/write/artifacts.gc", json={"confirm": True, "max_total_bytes": 0})
        assert bad.status_code == 400

        # A confirmed, well-formed write really executes.
        done = http.post(
            "/api/write/artifacts.gc", json={"confirm": True, "max_total_bytes": 1 << 29}
        )
        assert done.status_code == 200, done.text
        assert done.json()["ok"] is True
