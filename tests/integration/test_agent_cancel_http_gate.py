"""Cancel an in-flight agent run over real HTTP, plus the thread data plane.

A run that cannot be stopped is a liability the moment a provider stalls: the
operator's only lever is ``POST /api/agent/runs/{id}/cancel``, and it has to
work while the provider connection is still open and streaming nothing. This
gate points a real ``serve-web`` process at a fake OpenAI server that sends
one text delta and then deliberately hangs, cancels the run over HTTP, and
proves the terminal state is ``cancelled`` (event ``run.cancelled``), that no
tool was ever dispatched, and that no analysis session appeared as a side
effect. Unknown run ids answer 404, and a second cancel of a terminal run is
harmless.

The second test pins the thread data plane the console UI depends on: create,
list, message-size and empty-message guardrails (413 / 400), transcript
readback, and deletion that really forgets the thread.

No real LLM, loopback only, pure Python.
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
_TERMINAL = {"completed", "failed", "rejected", "cancelled"}


class _StallingOpenAI:
    """Sends one SSE text delta, then holds the stream open without finishing."""

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
                chunk = {"choices": [{"delta": {"content": "Thinking"}, "finish_reason": None}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.flush()
                outer.request_started.set()
                # Hold the response open; the run can only end via cancel.
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
def test_cancel_stops_an_inflight_run_over_http(tmp_path: Path) -> None:
    fake = _StallingOpenAI()
    try:
        with _console(tmp_path) as console:
            saved = console.client.put(
                f"{console.base}/api/providers/gate",
                headers=console.headers,
                json={"base_url": fake.base_url, "model": "fake-model", "api_key": "k"},
            )
            assert saved.status_code == 200, saved.text

            thread = console.client.post(
                f"{console.base}/api/agent/threads", headers=console.headers, json={"title": "c"}
            )
            thread_id = thread.json()["thread"]["id"]
            run = console.client.post(
                f"{console.base}/api/agent/runs",
                headers=console.headers,
                json={"thread_id": thread_id, "message": "go"},
            )
            assert run.status_code == 202, run.text
            run_id = run.json()["run_id"]

            # The provider is genuinely mid-stream before we pull the lever.
            assert fake.request_started.wait(timeout=15), "provider never saw the request"

            cancelled = console.client.post(
                f"{console.base}/api/agent/runs/{run_id}/cancel", headers=console.headers
            )
            assert cancelled.status_code == 202, cancelled.text
            assert cancelled.json()["run"]["cancel_requested"] is True

            final = _wait_terminal(console, run_id)
            assert final["status"] == "cancelled"

            history = console.client.get(
                f"{console.base}/api/agent/runs/{run_id}/events/history",
                headers=console.headers,
            ).json()["events"]
            types = [event["type"] for event in history]
            assert "run.cancelled" in types
            # The run died mid-provider-stream: nothing was ever dispatched.
            assert not any(t.startswith("tool.") for t in types), types

            # And no side effects leaked into the analysis plane.
            sessions = console.client.get(
                f"{console.base}/api/sessions", headers=console.headers
            ).json()
            assert sessions["data"]["sessions"] == []

            # Cancel is idempotent on a terminal run and honest about unknowns.
            again = console.client.post(
                f"{console.base}/api/agent/runs/{run_id}/cancel", headers=console.headers
            )
            assert again.status_code == 202
            missing = console.client.post(
                f"{console.base}/api/agent/runs/does-not-exist/cancel", headers=console.headers
            )
            assert missing.status_code == 404
    finally:
        fake.close()


@pytest.mark.integration
def test_thread_data_plane_lifecycle_over_http(tmp_path: Path) -> None:
    with _console(tmp_path) as console:
        created = console.client.post(
            f"{console.base}/api/agent/threads",
            headers=console.headers,
            json={"title": "lifecycle"},
        )
        assert created.status_code == 201, created.text
        thread_id = created.json()["thread"]["id"]

        listed = console.client.get(f"{console.base}/api/agent/threads", headers=console.headers)
        assert thread_id in [item["id"] for item in listed.json()["threads"]]

        # Guardrails: an empty message is a 400, an oversized one a 413.
        empty = console.client.post(
            f"{console.base}/api/agent/threads/{thread_id}/messages",
            headers=console.headers,
            json={"content": "   "},
        )
        assert empty.status_code == 400
        oversized = console.client.post(
            f"{console.base}/api/agent/threads/{thread_id}/messages",
            headers=console.headers,
            json={"content": "x" * (1_048_576 + 1)},
        )
        assert oversized.status_code == 413

        posted = console.client.post(
            f"{console.base}/api/agent/threads/{thread_id}/messages",
            headers=console.headers,
            json={"content": "hello agent"},
        )
        assert posted.status_code == 201, posted.text

        detail = console.client.get(
            f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
        ).json()
        contents = [message["content"] for message in detail["messages"]]
        assert contents == ["hello agent"]

        deleted = console.client.delete(
            f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
        )
        assert deleted.status_code == 200

        gone = console.client.get(
            f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
        )
        assert gone.status_code == 404
        again = console.client.delete(
            f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
        )
        assert again.status_code == 404

        # Messages to a deleted thread are refused, not silently re-created.
        orphan = console.client.post(
            f"{console.base}/api/agent/threads/{thread_id}/messages",
            headers=console.headers,
            json={"content": "ghost"},
        )
        assert orphan.status_code == 404
