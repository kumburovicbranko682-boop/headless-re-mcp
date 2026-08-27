"""Mission resilience over real HTTP: spent bounds continue, cancel reaches the run.

Two scheduler claims carry the mission mechanism and had no end-to-end proof:

* a run that spends its tool-round budget has used a bound, not broken -- the
  mission it belongs to is re-queued and finished by a later run, instead of
  dying on run one with the rest of its budget unspent (which is the exact
  objective missions exist for);
* cancelling a mission reaches down into its in-flight run: the scheduler must
  stop the run it started, not merely flag the mission row, or a runaway
  objective keeps holding its provider connection and its tool session.

The provider is a local fake OpenAI: while the continuation contract says
"Run 1", it proposes a cheap read-only tool call every round until the
orchestrator's 24-round bound trips (the wrap-up round offers no tools and
gets plain text); once the contract says "Run 2" it opens with the completion
marker. The cancel test uses a provider that stalls mid-stream. No real LLM,
loopback only, pure Python.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets as _secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from headless_re_mcp.agent.models import (
    MISSION_COMPLETE_MARKER,
    RUN_ROUNDS_EXHAUSTED,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MISSION_TERMINAL = {"completed", "failed", "exhausted", "cancelled"}
_RUN_TERMINAL = {"completed", "failed", "rejected", "cancelled", "interrupted"}
_ATTEMPT = re.compile(r"Run (\d+) of at most (\d+)")


def _sse(chunks: list[dict[str, Any]]) -> bytes:
    body = b"".join(f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks)
    return body + b"data: [DONE]\n\n"


def _text_chunks(text: str) -> list[dict[str, Any]]:
    return [
        {"choices": [{"delta": {"content": text}, "finish_reason": None}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
    ]


class _RoundBurnerOpenAI:
    """Run 1: a tool call every round until the bound; Run 2: the marker."""

    def __init__(self) -> None:
        outer = self
        self.tool_rounds_served = 0

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length) or b"{}")
                attempt = 0
                for message in request.get("messages") or []:
                    if not isinstance(message, dict) or message.get("role") != "user":
                        continue
                    match = _ATTEMPT.search(str(message.get("content") or ""))
                    if match:
                        attempt = int(match.group(1))
                tools_offered = bool(request.get("tools"))

                if attempt >= 2:
                    chunks = _text_chunks(f"{MISSION_COMPLETE_MARKER}: finished on run 2.")
                elif not tools_offered:
                    # The wrap-up round: the orchestrator offers no tools and
                    # asks for a summary before filing the bound as spent.
                    chunks = _text_chunks("Out of rounds; summary of progress so far.")
                else:
                    outer.tool_rounds_served += 1
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": f"call_{uuid.uuid4().hex[:8]}",
                                                "function": {
                                                    "name": "meta.metrics",
                                                    "arguments": "{}",
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
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(_sse(chunks))

        Handler.protocol_version = "HTTP/1.0"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _StallingOpenAI:
    def __init__(self) -> None:
        self.request_started = threading.Event()
        self._release = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                chunk = {"choices": [{"delta": {"content": "..."}, "finish_reason": None}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.flush()
                outer.request_started.set()
                outer._release.wait(timeout=120)

        Handler.protocol_version = "HTTP/1.0"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._release.set()
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
        yield _Console(base=base, headers={"Authorization": f"Bearer {token}"}, client=client)
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
        json={"base_url": base_url, "model": "fake-model", "api_key": "k"},
    )
    assert saved.status_code == 200, saved.text


def _queue_mission(console: _Console, objective: str, *, max_runs: int) -> dict[str, Any]:
    created = console.client.post(
        f"{console.base}/api/agent/missions",
        headers=console.headers,
        json={"objective": objective, "max_runs": max_runs},
    )
    assert created.status_code == 201, created.text
    return created.json()["mission"]


def _get_mission(console: _Console, mission_id: str) -> dict[str, Any]:
    response = console.client.get(
        f"{console.base}/api/agent/missions/{mission_id}", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return response.json()["mission"]


def _wait_mission_terminal(
    console: _Console, mission_id: str, timeout: float = 120.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        mission = _get_mission(console, mission_id)
        if mission["status"] in _MISSION_TERMINAL:
            return mission
        time.sleep(0.3)
    raise AssertionError(f"mission {mission_id} never reached a terminal status")


def _wait_first_run_id(console: _Console, mission_id: str, timeout: float = 30.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        mission = _get_mission(console, mission_id)
        if mission["last_run_id"]:
            return str(mission["last_run_id"])
        time.sleep(0.1)
    raise AssertionError(f"mission {mission_id} never started a run")


def _wait_run_terminal(console: _Console, run_id: str, timeout: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = console.client.get(
            f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
        )
        assert response.status_code == 200, response.text
        run = response.json()["run"]
        if run["status"] in _RUN_TERMINAL:
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal status")


@pytest.mark.integration
def test_a_run_that_spends_its_rounds_does_not_kill_the_mission(tmp_path: Path) -> None:
    fake = _RoundBurnerOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)

            mission = _queue_mission(console, "Burn run one, finish on run two.", max_runs=3)
            first_run_id = _wait_first_run_id(console, mission["id"])

            # Run 1 ends by spending its bound: filed failed with the budget
            # ending, after really serving a tool call per round.
            first_run = _wait_run_terminal(console, first_run_id, timeout=90.0)
            assert first_run["status"] == "failed", first_run
            assert RUN_ROUNDS_EXHAUSTED in (first_run["error"] or ""), first_run
            assert fake.tool_rounds_served >= 24, fake.tool_rounds_served

            # The mission survives the spent bound and completes on run 2.
            done = _wait_mission_terminal(console, mission["id"])
            assert done["status"] == "completed", done
            assert done["runs_used"] == 2, done
            assert done["last_run_id"] != first_run_id

            second_run = _wait_run_terminal(console, str(done["last_run_id"]))
            assert second_run["status"] == "completed", second_run
    finally:
        fake.close()


@pytest.mark.integration
def test_cancelling_a_mission_stops_its_inflight_run(tmp_path: Path) -> None:
    fake = _StallingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)

            mission = _queue_mission(console, "An objective nobody wants anymore.", max_runs=4)
            run_id = _wait_first_run_id(console, mission["id"])
            assert fake.request_started.wait(timeout=15), "provider never saw the request"

            cancelled = console.client.post(
                f"{console.base}/api/agent/missions/{mission['id']}/cancel",
                headers=console.headers,
            )
            assert cancelled.status_code == 202, cancelled.text

            # The cancel reached the run the scheduler had started, not just
            # the mission row.
            run = _wait_run_terminal(console, run_id)
            assert run["status"] == "cancelled", run
            done = _wait_mission_terminal(console, mission["id"])
            assert done["status"] == "cancelled", done

            history = console.client.get(
                f"{console.base}/api/agent/runs/{run_id}/events/history",
                headers=console.headers,
            ).json()["events"]
            assert "run.cancelled" in [event["type"] for event in history]

            # The scheduler survives the cancellation and keeps scheduling.
            listing = console.client.get(
                f"{console.base}/api/agent/missions", headers=console.headers
            ).json()
            assert listing["scheduler_running"] is True

            # Cancelling an unknown mission is an honest 404.
            missing = console.client.post(
                f"{console.base}/api/agent/missions/does-not-exist/cancel",
                headers=console.headers,
            )
            assert missing.status_code == 404
    finally:
        fake.close()
