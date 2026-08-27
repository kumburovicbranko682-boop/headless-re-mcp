"""Agent control plane over real HTTP: run start, SSE stream, tool dispatch, approval.

The Agent workbench story rests on four HTTP claims that only unit tests
guarded so far: ``POST /api/agent/runs`` starts a run that really drives the
provider loop; ``GET /api/agent/runs/{id}/events`` streams the run's life as
Server-Sent Events; a write tool proposed by the LLM is dispatched against the
real ``AnalysisService`` when autonomy allows it (leaving an auditable
``approval.auto`` event); and in ``request`` mode the very same call parks as
``approval.required`` until a human approves or rejects it over HTTP.

This gate boots a real ``python -m headless_re_mcp serve-web`` process in an
isolated config home and points its provider at a local fake OpenAI server
that speaks the chat-completions SSE dialect: first round proposes a
``session.create`` tool call on a committed PE fixture, second round (once a
``tool`` role message appears in the conversation) answers with final text.
No real LLM, no network beyond loopback; pure Python.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets as _secrets
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

_TERMINAL = {"completed", "failed", "rejected", "cancelled"}


class _FakeOpenAI:
    """Chat-completions SSE fake: propose session.create, then answer text."""

    def __init__(self, binary: str) -> None:
        self.binary = binary
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path.endswith("/models"):
                    body = json.dumps({"data": [{"id": "fake-model"}]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length) or b"{}")
                messages = request.get("messages") or []
                saw_tool_result = any(
                    isinstance(m, dict) and m.get("role") == "tool" for m in messages
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if saw_tool_result:
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {"content": "Sample opened. Analysis complete."},
                                    "finish_reason": None,
                                }
                            ]
                        },
                        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                    ]
                else:
                    arguments = json.dumps({"binary": outer.binary})
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_open",
                                                "function": {
                                                    "name": "session.create",
                                                    "arguments": arguments,
                                                },
                                            }
                                        ]
                                    },
                                    "finish_reason": None,
                                }
                            ]
                        },
                        {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
                    ]
                for chunk in chunks:
                    payload = json.dumps(chunk, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

        # HTTP/1.0 framing: the body ends when the connection closes, so the
        # fake never has to speak chunked transfer encoding.
        Handler.protocol_version = "HTTP/1.0"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@dataclass
class _Console:
    base: str
    headers: dict[str, str]
    client: httpx.Client


@contextlib.contextmanager
def _console(tmp_path: Path) -> Iterator[_Console]:
    config_home = tmp_path / "config-home"
    app_dir = config_home / "headless-re-mcp"
    app_dir.mkdir(parents=True)
    token = _secrets.token_urlsafe(32)
    (app_dir / "web_token.json").write_text(json.dumps({"token": token}), encoding="utf-8")

    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "headless_re_mcp",
            "serve-web",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        cwd=_PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    headers = {"Authorization": f"Bearer {token}"}
    client = httpx.Client(timeout=30.0)
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise AssertionError(f"serve-web exited early:\n{output}")
            try:
                if client.get(f"{base}/healthz").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.monotonic() > deadline:
                raise AssertionError("serve-web did not become healthy in 60s")
            time.sleep(0.2)
        yield _Console(base=base, headers=headers, client=client)
    finally:
        client.close()
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)


def _configure_provider(console: _Console, base_url: str) -> None:
    saved = console.client.put(
        f"{console.base}/api/providers/gate",
        headers=console.headers,
        json={"base_url": base_url, "model": "fake-model", "api_key": "secret-key-123"},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["ok"] is True


def _set_autonomy(console: _Console, mode: str) -> dict[str, Any]:
    response = console.client.put(
        f"{console.base}/api/agent/autonomy", headers=console.headers, json={"mode": mode}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == mode
    return body


def _start_run(console: _Console, prompt: str) -> tuple[str, str]:
    thread = console.client.post(
        f"{console.base}/api/agent/threads", headers=console.headers, json={"title": "gate"}
    )
    assert thread.status_code == 201, thread.text
    thread_id = thread.json()["thread"]["id"]
    run = console.client.post(
        f"{console.base}/api/agent/runs",
        headers=console.headers,
        json={"thread_id": thread_id, "message": prompt},
    )
    assert run.status_code == 202, run.text
    return thread_id, run.json()["run_id"]


def _event_history(console: _Console, run_id: str) -> list[dict[str, Any]]:
    response = console.client.get(
        f"{console.base}/api/agent/runs/{run_id}/events/history", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return response.json()["events"]


def _wait_for_event(
    console: _Console, run_id: str, event_type: str, timeout: float = 30.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in _event_history(console, run_id):
            if event["type"] == event_type:
                return event
        time.sleep(0.2)
    raise AssertionError(f"never saw {event_type} for run {run_id}")


def _wait_terminal(console: _Console, run_id: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = console.client.get(
            f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
        )
        assert response.status_code == 200, response.text
        run = response.json()["run"]
        if run["status"] in _TERMINAL:
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal status")


@pytest.mark.integration
def test_agent_run_streams_real_tool_dispatch_over_sse(tmp_path: Path) -> None:
    fake = _FakeOpenAI(str(_FIXTURE))
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")

            thread_id, run_id = _start_run(console, "Open the sample and report.")

            # Consume the live SSE stream to its natural end: the endpoint
            # closes by itself once the run is terminal and drained.
            frames: list[tuple[str, dict[str, Any]]] = []
            with console.client.stream(
                "GET",
                f"{console.base}/api/agent/runs/{run_id}/events",
                headers=console.headers,
                timeout=60.0,
            ) as stream:
                assert stream.status_code == 200
                current_type = ""
                for line in stream.iter_lines():
                    if line.startswith("event:"):
                        current_type = line.split(":", 1)[1].strip()
                    elif line.startswith("data:") and current_type not in ("", "heartbeat"):
                        frames.append((current_type, json.loads(line.split(":", 1)[1])))

            types = [frame_type for frame_type, _ in frames]
            assert "tool.proposed" in types
            assert "approval.auto" in types, types
            assert "approval.required" not in types
            assert "tool.started" in types
            assert "tool.completed" in types
            assert types[-1] == "run.completed", types

            by_type = dict(reversed(frames))
            proposed = by_type["tool.proposed"]["data"]
            assert proposed["name"] == "session.create"
            assert len(proposed["args_sha256"]) == 64
            completed_tool = by_type["tool.completed"]["data"]
            assert completed_tool["ok"] is True

            run = _wait_terminal(console, run_id)
            assert run["status"] == "completed"

            # The dispatch was real: the console now holds an analysis session
            # for exactly the fixture the fake told the agent to open.
            sessions = console.client.get(
                f"{console.base}/api/sessions", headers=console.headers
            ).json()
            assert sessions["ok"] is True
            binaries = [item.get("binary") for item in sessions["data"]["sessions"]]
            assert str(_FIXTURE) in binaries, binaries

            # And the thread carries the full exchange: user, tool result,
            # assistant final text.
            detail = console.client.get(
                f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
            ).json()
            roles = [message["role"] for message in detail["messages"]]
            assert "user" in roles and "tool" in roles and "assistant" in roles
            final = [m for m in detail["messages"] if m["role"] == "assistant"][-1]
            assert "Analysis complete" in final["content"]
    finally:
        fake.close()


@pytest.mark.integration
def test_agent_write_parks_for_human_approval_over_http(tmp_path: Path) -> None:
    fake = _FakeOpenAI(str(_FIXTURE))
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            body = _set_autonomy(console, "request")
            assert body["auto_executable_write_count"] == 0

            # Approve path: the run parks, a human approves over HTTP, the run
            # then finishes normally.
            _, run_id = _start_run(console, "Open the sample.")
            required = _wait_for_event(console, run_id, "approval.required")
            call = required["data"]
            assert call["name"] == "session.create"

            parked = console.client.get(
                f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
            ).json()["run"]
            assert parked["status"] == "awaiting_approval"

            # A stale or mismatched digest must be refused before it approves
            # anything.
            mismatch = console.client.post(
                f"{console.base}/api/agent/runs/{run_id}/tool-calls/{call['tool_call_id']}/approve",
                headers=console.headers,
                json={"args_sha256": "0" * 64},
            )
            assert mismatch.status_code == 409, mismatch.text

            approved = console.client.post(
                f"{console.base}/api/agent/runs/{run_id}/tool-calls/{call['tool_call_id']}/approve",
                headers=console.headers,
                json={"args_sha256": call["args_sha256"]},
            )
            assert approved.status_code == 200, approved.text

            run = _wait_terminal(console, run_id)
            assert run["status"] == "completed"
            types = [event["type"] for event in _event_history(console, run_id)]
            assert "approval.required" in types
            assert "approval.approved" in types
            assert "approval.auto" not in types

            # Reject path: a fresh thread parks the same way, and a human
            # rejection terminates the run as rejected with no dispatch.
            _, rejected_run = _start_run(console, "Open the sample again.")
            required = _wait_for_event(console, rejected_run, "approval.required")
            call = required["data"]
            rejected = console.client.post(
                f"{console.base}/api/agent/runs/{rejected_run}/tool-calls/{call['tool_call_id']}/reject",
                headers=console.headers,
                json={"args_sha256": call["args_sha256"]},
            )
            assert rejected.status_code == 200, rejected.text

            run = _wait_terminal(console, rejected_run)
            assert run["status"] == "rejected"
            types = [event["type"] for event in _event_history(console, rejected_run)]
            assert "run.rejected" in types
            assert "tool.started" not in types
    finally:
        fake.close()


@pytest.mark.integration
def test_provider_control_plane_masks_secrets_and_probes_models(tmp_path: Path) -> None:
    fake = _FakeOpenAI(str(_FIXTURE))
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)

            listing = console.client.get(f"{console.base}/api/providers", headers=console.headers)
            assert listing.status_code == 200
            assert listing.json()["ok"] is True
            # The saved key must never come back over the wire.
            assert "secret-key-123" not in listing.text

            probed = console.client.post(
                f"{console.base}/api/providers/gate/models", headers=console.headers
            )
            assert probed.status_code == 200, probed.text
            assert probed.json()["models"] == ["fake-model"]

            # A dead endpoint fails as a diagnosable 502, not a hang or a 200.
            dead = console.client.put(
                f"{console.base}/api/providers/dead",
                headers=console.headers,
                json={"base_url": "http://127.0.0.1:9/v1", "model": "x", "make_current": False},
            )
            assert dead.status_code == 200, dead.text
            failed = console.client.post(
                f"{console.base}/api/providers/dead/models", headers=console.headers
            )
            assert failed.status_code == 502
            assert failed.json()["detail"].startswith("provider_probe_failed:")

            # The control plane is not anonymous.
            anonymous = console.client.get(f"{console.base}/api/providers")
            assert anonymous.status_code == 401
    finally:
        fake.close()
