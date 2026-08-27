"""Agent HTTP/SSE gate: the conversation workbench works front to back over HTTP.

The agent loop and the mission scheduler are proven end to end in process with
an injected fake provider, and the serve-web console is proven over real HTTP
for the non-agent surface. The one seam neither covers is the agent control
plane a browser actually talks to: ``POST /api/agent/runs`` and the
``GET /api/agent/runs/{id}/events`` Server-Sent-Events stream, with the *real*
``OpenAICompatibleProvider`` making a real network call.

This gate closes it. A tiny fake OpenAI-compatible chat-completions server runs
in the test process and speaks the streaming SSE shape the provider parses; a
real ``python -m headless_re_mcp serve-web`` process is pointed at it through
the provider config file. Then, entirely over HTTP:

* a thread is created, a run is started with a user message, and the run's
  events are consumed from the real SSE endpoint -- correct ``event:``/``data:``
  framing, in sequence order;
* the model's streamed ``session.create`` tool call is dispatched through the
  real catalog against the committed PE fixture: the stream carries
  ``tool.proposed``/``approval.auto``/``tool.completed(ok=True)`` and ends with
  ``run.completed``;
* the effect is real -- ``GET /api/sessions`` afterwards shows the one bound PE
  session the run opened.

Pure Python end to end: the "LLM" is a local socket the test controls, and no
analysis backend is opened (session.create only classifies and binds).
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
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_TOKEN = "agent-http-sse-gate-" + "x" * 24
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _sse(chunks: list[dict[str, Any]]) -> bytes:
    body = "".join(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n" for chunk in chunks)
    return (body + "data: [DONE]\n\n").encode("utf-8")


class _FakeOpenAI:
    """A loopback chat-completions server: one tool call, then a final answer.

    Request one streams a ``session.create`` tool call for the fixture; every
    later request (the loop's next turn, after the tool result is fed back)
    streams a plain final answer with no tools, ending the run.
    """

    def __init__(self, binary: str) -> None:
        self.binary = binary
        self.calls = 0
        self._lock = threading.Lock()
        server_self = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # noqa: D401 - silence
                del args

            def do_POST(self) -> None:  # noqa: N802 - stdlib name
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                with server_self._lock:
                    server_self.calls += 1
                    first = server_self.calls == 1
                if first:
                    payload = _sse(
                        [
                            {"choices": [{"index": 0, "delta": {"role": "assistant"}}]},
                            {
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "id": "call_open",
                                                    "type": "function",
                                                    "function": {
                                                        "name": "session.create",
                                                        "arguments": json.dumps(
                                                            {"binary": server_self.binary}
                                                        ),
                                                    },
                                                }
                                            ]
                                        },
                                        "finish_reason": None,
                                    }
                                ]
                            },
                            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
                        ]
                    )
                else:
                    payload = _sse(
                        [
                            {
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": "Sample opened. Analysis complete."},
                                        "finish_reason": None,
                                    }
                                ]
                            },
                            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                        ]
                    )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _FakeOpenAI:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10.0)


def _write_provider_config(path: Path, base_url: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "current": "default",
                "profiles": {
                    "default": {
                        "id": "default",
                        "base_url": base_url,
                        "model": "fake-model",
                        "api_key": "loopback-key",
                    }
                },
            }
        ),
        encoding="utf-8",
    )


@contextmanager
def _serve_web(tmp_root: Path, provider_base_url: str) -> Iterator[str]:
    config_home = tmp_root / "config"
    (config_home / "headless-re-mcp").mkdir(parents=True, exist_ok=True)
    (config_home / "headless-re-mcp" / "web_token.json").write_text(
        json.dumps({"token": _TOKEN}), encoding="utf-8"
    )
    provider_config = tmp_root / "providers.json"
    _write_provider_config(provider_config, provider_base_url)

    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_root / "artifacts")
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_PROVIDER_CONFIG"] = str(provider_config)
    # Full access, so the model's session.create runs unattended.
    env["HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS"] = "state_change,file_write"
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


def _consume_sse(client: httpx.Client, path: str, *, timeout: float = 40.0) -> list[dict[str, Any]]:
    """Read one run's SSE stream to its close, returning parsed events in order."""
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    with client.stream("GET", path, timeout=timeout) as response:
        assert response.status_code == 200, response.status_code
        assert response.headers["content-type"].startswith("text/event-stream")
        event_type: str | None = None
        seq: int | None = None
        for line in response.iter_lines():
            if time.monotonic() > deadline:
                raise AssertionError("SSE stream did not close in time")
            if line.startswith("id:"):
                seq = int(line[3:].strip())
            elif line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
                if event_type in {None, "heartbeat"}:
                    continue
                dumped = json.loads(data)
                # The SSE data frame is the whole event.dump(); the event's own
                # payload is its inner "data" field.
                events.append(
                    {
                        "seq": dumped.get("seq", seq),
                        "type": event_type or dumped.get("type"),
                        "data": dumped.get("data", {}),
                    }
                )
    return events


@pytest.mark.integration
@pytest.mark.headless
def test_agent_run_streams_real_tool_dispatch_over_sse(tmp_path: Path) -> None:
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    with _FakeOpenAI(str(_PE_FIXTURE)) as fake:
        provider_base_url = f"http://127.0.0.1:{fake.port}"
        with (
            _serve_web(tmp_path, provider_base_url) as base_url,
            httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {_TOKEN}"}) as http,
        ):
            created = http.post("/api/agent/threads", json={"title": "sse gate"})
            assert created.status_code == 201, created.text
            thread_id = created.json()["thread"]["id"]

            started = http.post(
                "/api/agent/runs",
                json={"thread_id": thread_id, "message": "Open the sample."},
            )
            assert started.status_code == 202, started.text
            run_id = started.json()["run_id"]

            events = _consume_sse(http, f"/api/agent/runs/{run_id}/events")

            # The stream is ordered and framed, and reaches a clean completion.
            seqs = [event["seq"] for event in events if event["seq"] is not None]
            assert seqs == sorted(seqs)
            types = [event["type"] for event in events]
            assert "llm.started" in types
            assert types[-1] == "run.completed"
            assert events[-1]["data"]["status"] == "completed"

            proposed = [event for event in events if event["type"] == "tool.proposed"]
            assert [event["data"]["name"] for event in proposed] == ["session.create"]
            auto = [event for event in events if event["type"] == "approval.auto"]
            assert auto and auto[0]["data"]["name"] == "session.create"
            assert not any(event["type"] == "approval.required" for event in events)
            completed = [
                event
                for event in events
                if event["type"] == "tool.completed" and event["data"].get("ok")
            ]
            assert [event["data"]["name"] for event in completed] == ["session.create"]

            # The dispatched tool really opened a session in the service.
            sessions = http.get("/api/sessions").json()
            assert sessions["ok"] is True
            assert len(sessions["data"]["sessions"]) == 1
            assert sessions["data"]["sessions"][0]["target"] == "pe"

            # The run reached a terminal, completed state through the run API too.
            run = http.get(f"/api/agent/runs/{run_id}").json()
            assert run["run"]["status"] == "completed"

            # The fake model was actually consulted twice: tool round, then wrap-up.
            assert fake.calls >= 2

            # The non-streaming history endpoint agrees with the live stream.
            history = http.get(f"/api/agent/runs/{run_id}/events/history").json()
            assert [event["type"] for event in history["events"]][-1] == "run.completed"
