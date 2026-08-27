"""Provider backoff under a real run: retried, refused, and never replayed.

Rate limits and 5xx are routine on hosted inference. The unattended story
depends on three claims about how a run meets them, all made by
``RetryingProvider`` and none proven end to end until now:

* a transient fault (503) before any output costs seconds, not the run -- the
  same request is retried below the run and the run still completes;
* a non-transient refusal (401) fails the run immediately, with exactly one
  request on the wire, because retrying a bad credential just burns budget;
* once the stream has produced output, a mid-stream disconnect is never
  replayed -- a resent request could duplicate output or re-issue tool calls,
  so the run fails instead, again with exactly one request on the wire.

Each test boots a real ``serve-web`` process against a local fake OpenAI whose
failure mode is scripted, and reads the outcome back over HTTP. No real LLM,
loopback only, pure Python.
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


class _ScriptedOpenAI:
    """Fake chat-completions endpoint with a scripted failure mode.

    mode "retryable": first POST answers 503, later POSTs stream a completion.
    mode "refused": every POST answers 401.
    mode "midstream_abort": stream one text delta over chunked framing, then
    drop the connection without finishing the body.
    """

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.post_count = 0
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def _sse_body(self, text: str) -> bytes:
                chunks = [
                    {"choices": [{"delta": {"content": text}, "finish_reason": None}]},
                    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                ]
                body = b"".join(f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks)
                return body + b"data: [DONE]\n\n"

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                with outer._lock:
                    outer.post_count += 1
                    seen = outer.post_count

                if outer.mode == "refused" or (outer.mode == "retryable" and seen == 1):
                    status = 401 if outer.mode == "refused" else 503
                    body = json.dumps({"error": {"message": "scripted fault"}}).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if outer.mode == "midstream_abort":
                    # HTTP/1.1 chunked framing so a dropped connection is a
                    # protocol error the client must surface, not a normal end
                    # of body.
                    self.protocol_version = "HTTP/1.1"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    delta = {
                        "choices": [{"delta": {"content": "partial out"}, "finish_reason": None}]
                    }
                    payload = f"data: {json.dumps(delta)}\n\n".encode()
                    self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    self.wfile.flush()
                    # Vanish without the terminating zero-length chunk.
                    self.close_connection = True
                    with contextlib.suppress(OSError):
                        self.connection.shutdown(socket.SHUT_RDWR)
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(self._sse_body("Recovered. Analysis complete."))

        Handler.protocol_version = "HTTP/1.0"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
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


def _run_against(console: _Console, base_url: str) -> str:
    saved = console.client.put(
        f"{console.base}/api/providers/gate",
        headers=console.headers,
        json={"base_url": base_url, "model": "fake-model", "api_key": "k"},
    )
    assert saved.status_code == 200, saved.text
    thread = console.client.post(
        f"{console.base}/api/agent/threads", headers=console.headers, json={"title": "b"}
    )
    thread_id = thread.json()["thread"]["id"]
    run = console.client.post(
        f"{console.base}/api/agent/runs",
        headers=console.headers,
        json={"thread_id": thread_id, "message": "go"},
    )
    assert run.status_code == 202, run.text
    return str(run.json()["run_id"])


def _wait_terminal(console: _Console, run_id: str, timeout: float = 45.0) -> dict[str, Any]:
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
def test_transient_503_is_retried_below_the_run(tmp_path: Path) -> None:
    fake = _ScriptedOpenAI("retryable")
    try:
        with _console(tmp_path) as console:
            run_id = _run_against(console, fake.base_url)
            run = _wait_terminal(console, run_id)
            # The outage cost a backoff, not the run.
            assert run["status"] == "completed", run
            assert fake.post_count == 2, fake.post_count
    finally:
        fake.close()


@pytest.mark.integration
def test_non_retryable_401_fails_the_run_after_one_request(tmp_path: Path) -> None:
    fake = _ScriptedOpenAI("refused")
    try:
        with _console(tmp_path) as console:
            run_id = _run_against(console, fake.base_url)
            run = _wait_terminal(console, run_id)
            assert run["status"] == "failed", run
            assert run["error"], run
            # A refused credential is not retried: one request, then the verdict.
            assert fake.post_count == 1, fake.post_count
    finally:
        fake.close()


@pytest.mark.integration
def test_midstream_disconnect_is_never_replayed(tmp_path: Path) -> None:
    fake = _ScriptedOpenAI("midstream_abort")
    try:
        with _console(tmp_path) as console:
            run_id = _run_against(console, fake.base_url)
            run = _wait_terminal(console, run_id)
            # Output already reached the caller, so a replay could duplicate it
            # or re-issue tool calls: the run must fail instead.
            assert run["status"] == "failed", run
            assert run["error"], run
            assert fake.post_count == 1, fake.post_count
    finally:
        fake.close()
