"""Context stays bounded on the wire while the record stays complete.

A long unattended thread dies in one of two ways if context is unmanaged: the
request to the provider grows until the API rejects it, or the compactor cuts
carelessly and ships a tool message with no preceding tool_calls -- an
OpenAI-compatible endpoint 400s on that, and the scheduler reads a provider
400 as the mission failing. The compactor has unit proof; what had none is
the wiring: that a real run through ``serve-web`` actually compacts what it
sends, keeps the system prompt and the current task, says out loud that it
omitted history, and never turns compaction into amnesia in the *persisted*
thread, which must keep every message.

The second case guards the other bound: a model that runs away mid-call can
emit megabytes of tool arguments. Those are refused as ``arguments_too_large``
rather than truncated -- a truncated argument is a different command than the
one the model gave -- and the refusal goes back as an ordinary tool result so
the run continues instead of failing. The runaway payload must not be
persisted anywhere: not proposed, not in events, not in the transcript.

No real LLM, loopback only, pure Python. The fake provider records exactly
what reached the wire, which is the one place these properties are testable.
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

# The orchestrator's wire budget: profile threshold (default 75%) of 120,000
# characters. Fillers of 25,000 characters make roughly three of them fit.
_WIRE_BUDGET = 90_000
_FILLER_CHARS = 25_000
_FILLER_COUNT = 6
_TASK_CANARY = "TASK-CANARY-7777 summarize the findings so far"

# Just over the orchestrator's 262,144-byte argument bound, and distinctive
# enough that one substring search proves it was never persisted.
_ARG_CANARY = "ARGCANARY-" + "A" * 300_000


def _filler(index: int) -> str:
    return f"FILLER-{index:04d} " + "x" * _FILLER_CHARS


class _RecordingOpenAI:
    """Answer plain text, remembering every request body that reached the wire."""

    def __init__(self) -> None:
        outer = self
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length) or b"{}")
                with outer._lock:
                    outer.requests.append(request)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for chunk in (
                    {"choices": [{"delta": {"content": "Done."}, "finish_reason": None}]},
                    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                ):
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

        Handler.protocol_version = "HTTP/1.0"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _RunawayArgsOpenAI:
    """Propose one tool call with oversized arguments, then answer text.

    Counter-based rather than transcript-based on purpose: the oversized
    assistant turn is itself too large to survive compaction, so the second
    request may not show the tool result -- and a transcript-keyed fake would
    loop forever re-proposing the same runaway call.
    """

    def __init__(self) -> None:
        outer = self
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
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_runaway",
                                                "function": {
                                                    "name": "session.create",
                                                    "arguments": json.dumps(
                                                        {
                                                            "binary": "/tmp/x.bin",
                                                            "note": _ARG_CANARY,
                                                        }
                                                    ),
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
                else:
                    chunks = [
                        {"choices": [{"delta": {"content": "Done."}, "finish_reason": None}]},
                        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                    ]
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

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


def _configure_provider(console: _Console, base_url: str) -> None:
    saved = console.client.put(
        f"{console.base}/api/providers/gate",
        headers=console.headers,
        json={"base_url": base_url, "model": "fake-model", "api_key": "k"},
    )
    assert saved.status_code == 200, saved.text


def _set_autonomy(console: _Console, mode: str) -> None:
    response = console.client.put(
        f"{console.base}/api/agent/autonomy", headers=console.headers, json={"mode": mode}
    )
    assert response.status_code == 200, response.text


def _new_thread(console: _Console, title: str) -> str:
    thread = console.client.post(
        f"{console.base}/api/agent/threads", headers=console.headers, json={"title": title}
    )
    assert thread.status_code in (200, 201), thread.text
    return str(thread.json()["thread"]["id"])


def _start_run(console: _Console, thread_id: str, message: str) -> str:
    run = console.client.post(
        f"{console.base}/api/agent/runs",
        headers=console.headers,
        json={"thread_id": thread_id, "message": message},
    )
    assert run.status_code == 202, run.text
    return str(run.json()["run_id"])


def _history(console: _Console, run_id: str) -> list[dict[str, Any]]:
    response = console.client.get(
        f"{console.base}/api/agent/runs/{run_id}/events/history", headers=console.headers
    )
    assert response.status_code == 200, response.text
    return list(response.json()["events"])


def _wait_terminal(console: _Console, run_id: str, timeout: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = console.client.get(
            f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
        ).json()["run"]
        if run["status"] in _TERMINAL:
            return dict(run)
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal status")


def _thread_messages(console: _Console, thread_id: str) -> list[dict[str, Any]]:
    detail = console.client.get(
        f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
    )
    assert detail.status_code == 200, detail.text
    return list(detail.json()["messages"])


def _message_size(item: dict[str, Any]) -> int:
    return len(json.dumps(item, ensure_ascii=False, default=str, separators=(",", ":")))


@pytest.mark.integration
def test_oversized_history_is_compacted_on_the_wire_but_kept_in_the_record(tmp_path: Path) -> None:
    fake = _RecordingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")
            thread_id = _new_thread(console, "long thread")

            # Grow the thread well past the wire budget through the public
            # data plane, exactly as weeks of prior turns would.
            for index in range(_FILLER_COUNT):
                added = console.client.post(
                    f"{console.base}/api/agent/threads/{thread_id}/messages",
                    headers=console.headers,
                    json={"content": _filler(index)},
                )
                assert added.status_code == 201, added.text

            run_id = _start_run(console, thread_id, _TASK_CANARY)
            run = _wait_terminal(console, run_id)
            assert run["status"] == "completed", run

            assert fake.requests, "the provider never saw a request"
            messages = fake.requests[-1]["messages"]

            # The system prompt survives compaction and stays first.
            assert messages[0]["role"] == "system"
            assert "compacted" not in str(messages[0].get("content", ""))

            # Compaction announces itself instead of silently rewriting
            # history: the model is told messages were omitted and reminded
            # that tool output is untrusted.
            notice = messages[1]
            assert notice["role"] == "system"
            assert "compacted" in notice["content"]
            assert "omitted" in notice["content"]
            assert "untrusted" in notice["content"]

            # The wire request respects the budget the profile configured.
            total = sum(_message_size(item) for item in messages)
            assert total <= _WIRE_BUDGET, f"wire request is {total} chars, over {_WIRE_BUDGET}"

            wire = json.dumps(messages, ensure_ascii=False)
            # The current task is the one thing the model cannot proceed
            # without; the oldest history is what pays for it.
            assert _TASK_CANARY in wire
            assert "FILLER-0000" not in wire
            # A compacted tail must never start with an orphaned tool reply:
            # providers 400 on that, which would kill the run.
            non_system = [m for m in messages if m.get("role") != "system"]
            assert non_system and non_system[0]["role"] != "tool"

            # Compaction bounds the wire, not the record: the persisted
            # thread still carries every filler in full.
            stored = _thread_messages(console, thread_id)
            stored_blob = json.dumps(stored, ensure_ascii=False)
            for index in range(_FILLER_COUNT):
                assert f"FILLER-{index:04d}" in stored_blob
            assert any(
                message["role"] == "assistant" and "Done." in message["content"]
                for message in stored
            )
    finally:
        fake.close()


@pytest.mark.integration
def test_runaway_arguments_are_refused_not_truncated_and_never_persisted(tmp_path: Path) -> None:
    fake = _RunawayArgsOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")
            thread_id = _new_thread(console, "runaway")
            run_id = _start_run(console, thread_id, "open the sample")

            # The refusal is a correctable tool result, not a run failure:
            # the model reads it, answers, and the run completes.
            run = _wait_terminal(console, run_id)
            assert run["status"] == "completed", run

            events = _history(console, run_id)
            completed = [
                event
                for event in events
                if event["type"] == "tool.completed"
                and event["data"].get("tool_call_id") == "call_runaway"
            ]
            assert completed, "the runaway call left no tool.completed event"
            assert completed[0]["data"]["ok"] is False
            assert completed[0]["data"]["error"] == "arguments_too_large"

            # Refused before proposal: the runaway payload never became a
            # persisted tool-call row, so there is no tool.proposed for it.
            assert not any(
                event["type"] == "tool.proposed"
                and event["data"].get("tool_call_id") == "call_runaway"
                for event in events
            )

            # Refused, not truncated-and-executed: no session was created.
            sessions = console.client.get(
                f"{console.base}/api/sessions", headers=console.headers
            ).json()
            listed = sessions.get("sessions", sessions.get("items", []))
            assert listed == [], f"a session exists, so the runaway call ran: {listed}"

            # The megabyte payload is nowhere on record -- events and the
            # thread transcript both stay clean of it.
            assert "ARGCANARY" not in json.dumps(events, ensure_ascii=False)
            transcript = json.dumps(_thread_messages(console, thread_id), ensure_ascii=False)
            assert "ARGCANARY" not in transcript
            # ...while the refusal itself is on record for the operator.
            assert "arguments_too_large" in transcript
    finally:
        fake.close()
