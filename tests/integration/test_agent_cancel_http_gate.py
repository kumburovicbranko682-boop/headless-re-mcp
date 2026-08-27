"""Agent cancellation & thread lifecycle gate, over the real serve-web process.

Cancelling a run mid-flight is a concurrency property, not a CRUD call: the
server has to interrupt a task that is blocked reading the provider's stream,
land the run in a terminal ``cancelled`` state, say so on the event stream, and
leave no half-done side effect behind. That is exactly the kind of thing that
passes in a unit test with a fake task and breaks against a real event loop and
a real HTTP client, so this gate proves it end to end:

* a run is started against a provider that deliberately stalls (a loopback
  server that opens the SSE response and then never finishes it), so the run is
  genuinely in-flight when ``POST /api/agent/runs/{id}/cancel`` arrives;
* the run reaches terminal ``cancelled``, the SSE feed carries ``run.cancelled``
  and then closes, and no analysis session was ever opened because the stalled
  turn never produced a tool call.

The same real server also anchors the workbench's data plane, which needs no
model at all: thread create, message append with byte-limit rejection, the
aggregated thread read, and delete-then-404.

Pure Python, any platform.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TOKEN = "agent-cancel-gate-" + "z" * 24
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _StallingOpenAI:
    """A chat-completions server that opens the stream and then hangs.

    It sends one assistant delta so the run is unmistakably streaming, then
    holds the connection without ever finishing -- the run stays in-flight
    until the server cancels it out from under the blocked read.
    """

    def __init__(self) -> None:
        self.hits = 0
        self._lock = threading.Lock()
        server_self = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                del args

            def do_POST(self) -> None:  # noqa: N802 - stdlib name
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                with server_self._lock:
                    server_self.hits += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                opening = 'data: {"choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n'
                try:
                    self.wfile.write(opening.encode())
                    self.wfile.flush()
                    # Hang, but stay responsive to teardown. Never send [DONE].
                    for _ in range(600):
                        time.sleep(0.1)
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _StallingOpenAI:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10.0)


@contextmanager
def _serve_web(tmp_root: Path, *, provider_base_url: str | None = None) -> Iterator[str]:
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
    if provider_base_url is not None:
        provider_config = tmp_root / "providers.json"
        provider_config.write_text(
            json.dumps(
                {
                    "current": "default",
                    "profiles": {
                        "default": {
                            "id": "default",
                            "base_url": provider_base_url,
                            "model": "fake-model",
                            "api_key": "loopback-key",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        env["HEADLESS_RE_PROVIDER_CONFIG"] = str(provider_config)
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


def _event_types(http: httpx.Client, run_id: str) -> list[str]:
    history = http.get(f"/api/agent/runs/{run_id}/events/history").json()
    return [event["type"] for event in history["events"]]


def _wait_until(predicate: Any, *, timeout: float = 30.0, interval: float = 0.1) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError("condition not met in time")


@pytest.mark.integration
@pytest.mark.headless
def test_cancel_stops_an_inflight_run_over_http(tmp_path: Path) -> None:
    with _StallingOpenAI() as fake:
        provider_base_url = f"http://127.0.0.1:{fake.port}"
        with (
            _serve_web(tmp_path, provider_base_url=provider_base_url) as base_url,
            httpx.Client(
                base_url=base_url, headers={"Authorization": f"Bearer {_TOKEN}"}, timeout=30.0
            ) as http,
        ):
            thread_id = http.post("/api/agent/threads", json={"title": "cancel"}).json()["thread"][
                "id"
            ]
            run_id = http.post(
                "/api/agent/runs", json={"thread_id": thread_id, "message": "hang please"}
            ).json()["run_id"]

            # The run is genuinely in-flight: streaming, model contacted, not
            # terminal, waiting on the provider that will never answer.
            _wait_until(lambda: "llm.started" in _event_types(http, run_id))
            live = http.get(f"/api/agent/runs/{run_id}").json()["run"]
            assert live["status"] in {"streaming", "queued"}
            assert fake.hits == 1

            cancelled = http.post(f"/api/agent/runs/{run_id}/cancel")
            assert cancelled.status_code == 202, cancelled.text

            # It lands terminal-cancelled, and the event stream says so and ends.
            _wait_until(
                lambda: http.get(f"/api/agent/runs/{run_id}").json()["run"]["status"] == "cancelled"
            )
            frames: list[str] = []
            ended = False
            with http.stream("GET", f"/api/agent/runs/{run_id}/events") as response:
                assert response.status_code == 200
                event_type: str | None = None
                for line in response.iter_lines():
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                        frames.append(event_type)
                    if event_type == "run.cancelled":
                        ended = True
            assert "run.cancelled" in frames
            assert ended

            # Nothing was half-built: the stalled turn produced no tool call, so
            # no analysis session exists.
            sessions = http.get("/api/sessions").json()["data"]["sessions"]
            assert sessions == []

            # Cancelling an already-terminal run is a no-op, not an error.
            again = http.post(f"/api/agent/runs/{run_id}/cancel")
            assert again.status_code == 202
            assert http.get(f"/api/agent/runs/{run_id}").json()["run"]["status"] == "cancelled"


@pytest.mark.integration
@pytest.mark.headless
def test_thread_data_plane_lifecycle_over_http(tmp_path: Path) -> None:
    with (
        _serve_web(tmp_path) as base_url,
        httpx.Client(
            base_url=base_url, headers={"Authorization": f"Bearer {_TOKEN}"}, timeout=30.0
        ) as http,
    ):
        created = http.post("/api/agent/threads", json={"title": "workbench"})
        assert created.status_code == 201
        thread_id = created.json()["thread"]["id"]

        first = http.post(
            f"/api/agent/threads/{thread_id}/messages", json={"content": "first note"}
        )
        assert first.status_code == 201
        assert first.json()["message"]["role"] == "user"

        # An empty message is rejected, not stored.
        empty = http.post(f"/api/agent/threads/{thread_id}/messages", json={"content": "   "})
        assert empty.status_code == 400

        # A wildly oversized message is refused with 413, not silently truncated
        # or crashed.
        huge = http.post(
            f"/api/agent/threads/{thread_id}/messages",
            json={"content": "x" * (5 * 1024 * 1024)},
        )
        assert huge.status_code == 413

        # The aggregated read returns the thread and exactly the stored message.
        aggregate = http.get(f"/api/agent/threads/{thread_id}").json()
        assert aggregate["ok"] is True
        assert aggregate["thread"]["id"] == thread_id
        contents = [message["content"] for message in aggregate["messages"]]
        assert contents == ["first note"]

        # It shows up in the listing, then delete removes it for good.
        listed = http.get("/api/agent/threads").json()["threads"]
        assert thread_id in {item["id"] for item in listed}

        deleted = http.delete(f"/api/agent/threads/{thread_id}")
        assert deleted.status_code == 200 and deleted.json()["ok"] is True
        assert http.get(f"/api/agent/threads/{thread_id}").status_code == 404
        assert http.delete(f"/api/agent/threads/{thread_id}").status_code == 404

        # Messaging a thread that never existed is a clean 404.
        assert (
            http.post("/api/agent/threads/ghost/messages", json={"content": "hi"}).status_code
            == 404
        )
