"""What the console's focus and persona controls do reaches the LLM's wire.

Two console controls decide what the agent actually is, and both are only
useful if they reach the provider request itself -- not the UI, not the
catalog, the bytes sent to the model:

* the workspace profile (full/pe/android/web) trims which tools the agent is
  *offered*. A pe-focused run must not be handed apk.* or web.* tools it could
  misapply, and every profile must keep the core session.* surface. The
  trimming is read live per run, so switching focus in the console re-shapes
  the next run without a restart.
* the selected persona *is* the system prompt -- but the desktop and stealth
  safety rules are appended to whatever the persona says, so a custom persona
  cannot silently drop the rule that stops the agent claiming a GUI is open,
  or the one governing packed-sample handling and what stays behind approval.

Both were unit-proven against the helpers; neither was proven end to end,
where the console's HTTP controls meet the bytes on the wire. This gate drives
a real serve-web with a fake provider that records every request, flips the
profile and the persona through the public API, and reads back what the model
was sent. No real LLM, loopback only, pure Python.
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

# Fragments copied from the orchestrator's non-overridable safety rules. If the
# wording there changes, this gate should fail until it is re-read -- these are
# the sentences whose survival it is guarding.
_DESKTOP_RULE_FRAGMENT = "Do not tell the user the GUI is open until that snapshot lists windows."
_STEALTH_RULE_FRAGMENT = "patches.apply and static.bytes.patch are not."

_CUSTOM_PERSONA_BODY = (
    "CUSTOMPERSONA-CANARY. You are a terse assistant. Answer in one line. "
    "This persona deliberately omits every safety rule to prove they are "
    "appended anyway."
)


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

    def take_last(self) -> dict[str, Any]:
        with self._lock:
            assert self.requests, "the provider never saw a request"
            return self.requests[-1]

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()

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


def _set_profile(console: _Console, profile: str) -> None:
    response = console.client.post(
        f"{console.base}/api/workspace/mode", headers=console.headers, json={"profile": profile}
    )
    assert response.status_code == 200, response.text


def _run_to_completion(console: _Console, message: str) -> None:
    thread = console.client.post(
        f"{console.base}/api/agent/threads", headers=console.headers, json={"title": "wire"}
    )
    thread_id = thread.json()["thread"]["id"]
    run = console.client.post(
        f"{console.base}/api/agent/runs",
        headers=console.headers,
        json={"thread_id": thread_id, "message": message},
    )
    assert run.status_code == 202, run.text
    run_id = str(run.json()["run_id"])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = console.client.get(
            f"{console.base}/api/agent/runs/{run_id}", headers=console.headers
        ).json()["run"]["status"]
        if status in _TERMINAL:
            assert status == "completed", status
            return
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never completed")


def _tool_names(request: dict[str, Any]) -> set[str]:
    tools = request.get("tools") or []
    names: set[str] = set()
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.add(function["name"])
    return names


def _system_prompt(request: dict[str, Any]) -> str:
    for message in request.get("messages") or []:
        if isinstance(message, dict) and message.get("role") == "system":
            return str(message.get("content") or "")
    raise AssertionError("no system message on the wire")


@pytest.mark.integration
def test_workspace_profile_trims_the_tools_the_agent_is_offered(tmp_path: Path) -> None:
    fake = _RecordingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")

            # Full: every domain is on the wire.
            _set_profile(console, "full")
            _run_to_completion(console, "full run")
            full = _tool_names(fake.take_last())
            assert any(name.startswith("apk.") for name in full)
            assert any(name.startswith("web.") for name in full)
            assert any(name.startswith("session.") for name in full)

            # Web focus: android tools go, web tools and the shared proxy stay,
            # core session tools stay.
            fake.reset()
            _set_profile(console, "web")
            _run_to_completion(console, "web run")
            web = _tool_names(fake.take_last())
            assert not any(name.startswith("apk.") for name in web)
            assert any(name.startswith("web.") for name in web)
            assert any(name.startswith("js.") for name in web)
            assert any(name.startswith("session.") for name in web)
            assert web < full, "web profile must be a strict subset of full"

            # PE focus: android and web and the shared proxy all go; core stays.
            fake.reset()
            _set_profile(console, "pe")
            _run_to_completion(console, "pe run")
            pe = _tool_names(fake.take_last())
            for prefix in ("apk.", "device.", "web.", "js.", "wasm.", "proxy."):
                assert not any(name.startswith(prefix) for name in pe), prefix
            assert any(name.startswith("session.") for name in pe)
            assert pe < web, "pe profile must be a strict subset of web"
    finally:
        fake.close()


@pytest.mark.integration
def test_custom_persona_is_the_prompt_but_safety_rules_are_appended(tmp_path: Path) -> None:
    fake = _RecordingOpenAI()
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)
            _set_autonomy(console, "full_access")

            # Import a persona that deliberately contains none of the safety
            # rules, then select it -- both over the public API.
            imported = console.client.post(
                f"{console.base}/api/agent/personas/import",
                headers=console.headers,
                json={"title": "Terse", "content": _CUSTOM_PERSONA_BODY},
            )
            assert imported.status_code == 200, imported.text
            persona_id = next(
                item["id"] for item in imported.json()["personas"] if item["title"] == "Terse"
            )
            selected = console.client.post(
                f"{console.base}/api/agent/personas/select",
                headers=console.headers,
                json={"id": persona_id},
            )
            assert selected.status_code == 200, selected.text

            _run_to_completion(console, "persona run")
            prompt = _system_prompt(fake.take_last())

            # The persona body is the prompt.
            assert "CUSTOMPERSONA-CANARY" in prompt
            # ...yet the safety rules a custom persona omitted are appended
            # regardless. These are the sentences the console cannot let a
            # persona silently drop.
            assert _DESKTOP_RULE_FRAGMENT in prompt
            assert _STEALTH_RULE_FRAGMENT in prompt
    finally:
        fake.close()
