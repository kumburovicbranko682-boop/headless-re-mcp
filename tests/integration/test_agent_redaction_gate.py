"""Secrets in agent events are redacted on the wire, over real HTTP+SSE.

An agent's event stream is the audit trail: an operator watches it live and
reads it back later. Reverse-engineering arguments and tool results routinely
carry credentials -- a key the model was told to try, an ``Authorization``
header pasted into a hint -- and the orchestrator redacts them by key name
(and masks bearer values inside strings) before an event ever leaves the
process. That redaction is security-load-bearing and had no end-to-end proof:
this gate drives a real ``serve-web`` process with a fake LLM that proposes a
tool call whose arguments are stuffed with canary secrets, then asserts the
``tool.proposed`` / ``approval.required`` events -- both on the live SSE feed
and in the persisted history -- carry masks, and that no canary cleartext
appears anywhere in the run's events or the thread transcript.

The args hash the approval flow checks is taken over the *raw* arguments, so
redaction does not weaken it: the request-mode test approves using the hash the
redacted event advertised and the call still dispatches. No real LLM, loopback
only, pure Python.
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
_MASK = "***REDACTED***"
_TERMINAL = {"completed", "failed", "rejected", "cancelled"}

# Canary secret values. Distinctive enough that a single substring search
# proves nothing echoed them, keyed under names the redactor must catch.
_CANARIES = {
    "LEAKCANARY-APIKEY-1111",
    "LEAKCANARY-PASSWORD-2222",
    "LEAKCANARY-TOKEN-3333",
    "LEAKCANARY-BEARER-4444",
}
_SECRET_ARGUMENTS = {
    "binary": "/tmp/does-not-need-to-exist.bin",
    "api_key": "LEAKCANARY-APIKEY-1111",
    "password": "LEAKCANARY-PASSWORD-2222",
    "session_token": "LEAKCANARY-TOKEN-3333",
    "hint": "authenticate with Authorization: Bearer LEAKCANARY-BEARER-4444",
}


class _SecretProposingOpenAI:
    """Propose a tool call carrying secrets; answer text once a tool ran."""

    def __init__(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                return

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
                        {"choices": [{"delta": {"content": "Done."}, "finish_reason": None}]},
                        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                    ]
                else:
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_secret",
                                                "function": {
                                                    "name": "session.create",
                                                    "arguments": json.dumps(_SECRET_ARGUMENTS),
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


def _start_run(console: _Console) -> str:
    thread = console.client.post(
        f"{console.base}/api/agent/threads", headers=console.headers, json={"title": "redact"}
    )
    thread_id = thread.json()["thread"]["id"]
    run = console.client.post(
        f"{console.base}/api/agent/runs",
        headers=console.headers,
        json={"thread_id": thread_id, "message": "try the secret"},
    )
    assert run.status_code == 202, run.text
    return thread_id, str(run.json()["run_id"])


def _history(console: _Console, run_id: str) -> list[dict[str, Any]]:
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
        for event in _history(console, run_id):
            if event["type"] == event_type:
                return event
        time.sleep(0.2)
    raise AssertionError(f"never saw {event_type} for run {run_id}")


def _wait_terminal(console: _Console, run_id: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = console.client.get(
            f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
        ).json()["run"]
        if run["status"] in _TERMINAL:
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal status")


def _assert_arguments_masked(arguments: dict[str, Any]) -> None:
    assert arguments["api_key"] == _MASK, arguments
    assert arguments["password"] == _MASK, arguments
    assert arguments["session_token"] == _MASK, arguments
    # A bearer value embedded in an otherwise-visible string is masked in place.
    assert "LEAKCANARY-BEARER-4444" not in arguments["hint"], arguments
    assert _MASK in arguments["hint"], arguments
    # A non-secret argument is left intact so the trail stays useful.
    assert arguments["binary"] == _SECRET_ARGUMENTS["binary"], arguments


def _assert_no_canary_anywhere(console: _Console, run_id: str, thread_id: str) -> None:
    events_blob = json.dumps(_history(console, run_id), ensure_ascii=False)
    detail = console.client.get(
        f"{console.base}/api/agent/threads/{thread_id}", headers=console.headers
    ).json()
    thread_blob = json.dumps(detail, ensure_ascii=False)
    for canary in _CANARIES:
        assert canary not in events_blob, f"{canary} leaked into events"
        assert canary not in thread_blob, f"{canary} leaked into thread transcript"


@pytest.mark.integration
def test_secret_arguments_are_masked_in_the_live_sse_and_history(tmp_path: Path) -> None:
    fake = _SecretProposingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")
            thread_id, run_id = _start_run(console)

            # Read the whole run off the live SSE feed.
            proposed_seen: dict[str, Any] | None = None
            with console.client.stream(
                "GET",
                f"{console.base}/api/agent/runs/{run_id}/events",
                headers=console.headers,
                timeout=60.0,
            ) as stream:
                assert stream.status_code == 200
                current = ""
                for line in stream.iter_lines():
                    if line.startswith("event:"):
                        current = line.split(":", 1)[1].strip()
                    elif line.startswith("data:") and current == "tool.proposed":
                        proposed_seen = json.loads(line.split(":", 1)[1])

            assert proposed_seen is not None, "tool.proposed never arrived on the SSE feed"
            live_args = proposed_seen["data"]["arguments"]
            _assert_arguments_masked(live_args)
            # The hash is over raw args, so it is a real 64-hex digest even
            # though the streamed arguments are masked.
            assert len(proposed_seen["data"]["args_sha256"]) == 64

            # The persisted history redacts identically, and nothing leaked.
            history_proposed = _wait_for_event(console, run_id, "tool.proposed")
            _assert_arguments_masked(history_proposed["data"]["arguments"])
            _wait_terminal(console, run_id)
            _assert_no_canary_anywhere(console, run_id, thread_id)
    finally:
        fake.close()


@pytest.mark.integration
def test_approval_card_is_redacted_yet_its_hash_still_authorizes(tmp_path: Path) -> None:
    fake = _SecretProposingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "request")
            thread_id, run_id = _start_run(console)

            required = _wait_for_event(console, run_id, "approval.required")
            card = required["data"]
            # The human-facing approval card is redacted too.
            _assert_arguments_masked(card["arguments"])

            # Approving with the hash the redacted card advertised still works:
            # redaction never touched the digest, which is over the raw args.
            approved = console.client.post(
                f"{console.base}/api/agent/runs/{run_id}/tool-calls/{card['tool_call_id']}/approve",
                headers=console.headers,
                json={"args_sha256": card["args_sha256"]},
            )
            assert approved.status_code == 200, approved.text
            # The approve response echoes the tool call, also redacted.
            echoed = approved.json()["tool_call"]["arguments"]
            _assert_arguments_masked(echoed)

            _wait_terminal(console, run_id)
            types = [event["type"] for event in _history(console, run_id)]
            assert "approval.approved" in types
            assert "tool.started" in types
            _assert_no_canary_anywhere(console, run_id, thread_id)
    finally:
        fake.close()
