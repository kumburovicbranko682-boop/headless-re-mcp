"""A SIGKILL mid-run is survived: runs are filed honestly, missions resume.

Unattended operation means the console will eventually die without warning --
an OOM kill, a host reboot, a supervisor giving up -- while a run is streaming
from the provider. Two things must then be true or the deployment needs a
human. The dead run must be *filed*, not left in ``streaming`` forever, so
the operator reading the record sees ``interrupted: service_restarted``
rather than a run that lies about still working. And a mission whose run was
killed must go back to the queue and be finished by the next process, because
the run died, not the objective.

Both properties live in ``recover_after_restart``, which only the process
taking ownership of the database calls. This gate proves them across a real
process boundary: boot ``serve-web``, hold a run mid-stream against a
stalling fake provider, ``SIGKILL -9`` the console so nothing gets to clean
up, boot a second console over the same state directory, and read what the
survivor says happened. No real LLM, loopback only, pure Python.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets as _secrets
import signal
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

from headless_re_mcp.agent.models import MISSION_COMPLETE_MARKER

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TERMINAL = {"completed", "failed", "rejected", "cancelled", "interrupted"}
_MISSION_TERMINAL = {"completed", "failed", "exhausted", "cancelled"}

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="kills the console with SIGKILL, a POSIX signal"
)


class _CrashOpenAI:
    """Stall the first request forever; answer every later one immediately.

    The first caller is the process this gate is about to kill: it must be
    held mid-stream so the kill lands while the run is genuinely in flight.
    Later callers are the surviving process, which needs real answers.
    Keyed on a POST counter, not the transcript -- the killed conversation
    never finished, so its shape proves nothing about which process is asking.
    """

    def __init__(self, *, final_text: str) -> None:
        outer = self
        self.first_post_streaming = threading.Event()
        self._posts = 0
        self._lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                with outer._lock:
                    outer._posts += 1
                    first = outer._posts == 1
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if first:
                    chunk = {
                        "choices": [{"delta": {"content": "Working..."}, "finish_reason": None}]
                    }
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                    self.wfile.flush()
                    outer.first_post_streaming.set()
                    # Keepalives instead of a bare sleep so the handler notices
                    # the client dying (the kill) and exits quietly.
                    for _ in range(120):
                        time.sleep(0.5)
                        try:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                        except OSError:
                            return
                    return
                chunks: tuple[dict[str, Any], ...] = (
                    {"choices": [{"delta": {"content": outer.final_text}, "finish_reason": None}]},
                    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                )
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

        Handler.protocol_version = "HTTP/1.0"
        self.final_text = final_text
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        # A handler killed mid-write is this gate working as intended, not an
        # error worth a traceback on the test's stderr.
        self._server.handle_error = lambda *_args: None  # type: ignore[method-assign]
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
    process: subprocess.Popen[str]

    def kill9(self) -> None:
        """Die the way a crash does: no signal handler, no cleanup, no flush."""
        self.process.send_signal(signal.SIGKILL)
        self.process.wait(timeout=15)


@contextlib.contextmanager
def _boot(tmp_path: Path) -> Iterator[_Console]:
    """Boot a console over ``tmp_path``; state persists across boots."""
    config_home = tmp_path / "config-home"
    app_dir = config_home / "headless-re-mcp"
    token_file = app_dir / "web_token.json"
    if token_file.exists():
        token = json.loads(token_file.read_text(encoding="utf-8"))["token"]
    else:
        app_dir.mkdir(parents=True)
        token = _secrets.token_urlsafe(32)
        token_file.write_text(json.dumps({"token": token}), encoding="utf-8")

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
        yield _Console(
            base=base, headers={"Authorization": f"Bearer {token}"}, client=client, process=process
        )
    finally:
        client.close()
        if process.poll() is None:
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


def _get_run(console: _Console, run_id: str) -> dict[str, Any]:
    response = console.client.get(
        f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return dict(response.json()["run"])


def _wait_run(console: _Console, run_id: str, status: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = _get_run(console, run_id)
        if run["status"] == status:
            return run
        assert run["status"] not in _TERMINAL - {status}, run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached {status}")


def _wait_terminal(console: _Console, run_id: str, timeout: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = _get_run(console, run_id)
        if run["status"] in _TERMINAL:
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal status")


def _history(console: _Console, run_id: str) -> list[dict[str, Any]]:
    response = console.client.get(
        f"{console.base}/api/agent/runs/{run_id}/events/history", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return list(response.json()["events"])


def _get_mission(console: _Console, mission_id: str) -> dict[str, Any]:
    response = console.client.get(
        f"{console.base}/api/agent/missions/{mission_id}", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return dict(response.json()["mission"])


@pytest.mark.integration
def test_a_run_killed_mid_stream_is_filed_as_interrupted_on_reboot(tmp_path: Path) -> None:
    fake = _CrashOpenAI(final_text="Done.")
    try:
        with _boot(tmp_path) as first:
            _configure_provider(first, fake.base_url)
            thread = first.client.post(
                f"{first.base}/api/agent/threads", headers=first.headers, json={"title": "crash"}
            )
            thread_id = thread.json()["thread"]["id"]
            started = first.client.post(
                f"{first.base}/api/agent/runs",
                headers=first.headers,
                json={"thread_id": thread_id, "message": "analyse the sample"},
            )
            assert started.status_code == 202, started.text
            run_id = str(started.json()["run_id"])

            # The kill must land while the provider stream is genuinely open.
            assert fake.first_post_streaming.wait(30), "the run never reached the provider"
            _wait_run(first, run_id, "streaming")
            first.kill9()

        with _boot(tmp_path) as second:
            # The dead run is filed, not left claiming to work forever.
            run = _get_run(second, run_id)
            assert run["status"] == "interrupted", run
            assert run["error"] == "service_restarted", run

            # The record says so too, in the run's own event trail.
            events = _history(second, run_id)
            failed = [event for event in events if event["type"] == "run.failed"]
            assert failed, f"no run.failed event on record: {[e['type'] for e in events]}"
            assert failed[-1]["data"]["status"] == "interrupted"
            assert failed[-1]["data"]["error"] == "service_restarted"

            # The survivor is a working console, on the same thread: a fresh
            # run against the same provider profile completes normally.
            retried = second.client.post(
                f"{second.base}/api/agent/runs",
                headers=second.headers,
                json={"thread_id": thread_id, "message": "try again"},
            )
            assert retried.status_code == 202, retried.text
            retry = _wait_terminal(second, str(retried.json()["run_id"]))
            assert retry["status"] == "completed", retry
    finally:
        fake.close()


@pytest.mark.integration
def test_a_mission_whose_run_was_killed_resumes_and_completes(tmp_path: Path) -> None:
    fake = _CrashOpenAI(final_text=f"{MISSION_COMPLETE_MARKER}: objective met.")
    try:
        with _boot(tmp_path) as first:
            _configure_provider(first, fake.base_url)
            created = first.client.post(
                f"{first.base}/api/agent/missions",
                headers=first.headers,
                json={"objective": "Finish the analysis without a human.", "max_runs": 4},
            )
            assert created.status_code == 201, created.text
            mission_id = str(created.json()["mission"]["id"])

            # Hold the mission's first run mid-stream, then note which run it is.
            assert fake.first_post_streaming.wait(60), "the mission never reached the provider"
            deadline = time.monotonic() + 30
            killed_run_id: str | None = None
            while time.monotonic() < deadline:
                mission = _get_mission(first, mission_id)
                if mission["status"] == "running" and mission["last_run_id"]:
                    killed_run_id = str(mission["last_run_id"])
                    break
                time.sleep(0.2)
            assert killed_run_id is not None, "mission never exposed its in-flight run"
            first.kill9()

        with _boot(tmp_path) as second:
            # The run died; the objective did not. The next process claims the
            # requeued mission and finishes it with no human in the loop.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                mission = _get_mission(second, mission_id)
                if mission["status"] in _MISSION_TERMINAL:
                    break
                time.sleep(0.3)
            assert mission["status"] == "completed", mission

            # The killed run is on record as interrupted, and the completion
            # came from a different, later run inside the same budget.
            killed = _get_run(second, killed_run_id)
            assert killed["status"] == "interrupted", killed
            assert killed["error"] == "service_restarted", killed
            assert mission["last_run_id"] != killed_run_id
            assert 2 <= int(mission["runs_used"]) <= int(mission["max_runs"])
            final_run = _get_run(second, str(mission["last_run_id"]))
            assert final_run["status"] == "completed", final_run
    finally:
        fake.close()
