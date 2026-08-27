"""Unattended mission plane over real HTTP: isolation rotation, fail-closed, honesty.

The README's unattended story names six mechanisms; three of them meet here and
had no end-to-end proof: the mission scheduler that feeds an objective bounded
runs, the isolation hook that rolls the machine back at each sample boundary,
and the budget bookkeeping that files an unmet objective honestly instead of
pretending. This gate drives all three through a real ``serve-web`` process:

* a mission that needs two runs completes unattended -- and the isolation
  command ran exactly once, before the first run, never between the runs of
  the same mission (rolling back mid-mission would destroy the state the next
  run needs);
* when the isolation command fails and is required, the mission fails closed
  with zero runs started, because continuing would analyse a new sample on a
  dirty machine;
* a mission whose budget runs out is filed ``exhausted`` with "objective not
  met", not silently completed and not mislabelled as failed.

The provider is a local fake OpenAI that reads the continuation contract
("Run N of at most M") out of the last user message: run 1 reports progress,
run 2 opens with the completion marker. No real LLM, loopback only, pure
Python.
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
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from headless_re_mcp.agent.models import MISSION_COMPLETE_MARKER

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MISSION_TERMINAL = {"completed", "failed", "exhausted", "cancelled"}
_ATTEMPT = re.compile(r"Run (\d+) of at most (\d+)")


class _MissionOpenAI:
    """Answer by the continuation contract: progress until the final attempt."""

    def __init__(self, *, complete_on_attempt: int) -> None:
        outer = self

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
                if attempt >= outer.complete_on_attempt:
                    text = f"{MISSION_COMPLETE_MARKER}: objective met."
                else:
                    text = "Progress made this run. Next step: continue the analysis."
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                chunks = [
                    {"choices": [{"delta": {"content": text}, "finish_reason": None}]},
                    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
                ]
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

        Handler.protocol_version = "HTTP/1.0"
        self.complete_on_attempt = complete_on_attempt
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
def _console(tmp_path: Path, *, config: dict[str, Any] | None = None) -> Iterator[_Console]:
    config_home = tmp_path / "config-home"
    app_dir = config_home / "headless-re-mcp"
    app_dir.mkdir(parents=True)
    token = _secrets.token_urlsafe(32)
    (app_dir / "web_token.json").write_text(json.dumps({"token": token}), encoding="utf-8")
    if config:
        (app_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")

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


def _wait_mission_terminal(
    console: _Console, mission_id: str, timeout: float = 90.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = console.client.get(
            f"{console.base}/api/agent/missions/{mission_id}", headers=console.headers
        )
        assert response.status_code == 200, response.text
        mission = response.json()["mission"]
        if mission["status"] in _MISSION_TERMINAL:
            return mission
        time.sleep(0.3)
    raise AssertionError(f"mission {mission_id} never reached a terminal status")


def _rotation_script(tmp_path: Path, *, exit_code: int = 0) -> tuple[Path, Path]:
    marker = tmp_path / "rotations.log"
    script = tmp_path / "rotate.py"
    script.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(marker)!r}).open('a').write('rotated\\n')\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    return script, marker


@pytest.mark.integration
def test_mission_completes_unattended_with_one_rotation_per_sample(tmp_path: Path) -> None:
    script, marker = _rotation_script(tmp_path)
    fake = _MissionOpenAI(complete_on_attempt=2)
    try:
        with _console(
            tmp_path,
            config={"isolation_command": [sys.executable, str(script)], "isolation_required": True},
        ) as console:
            _configure_provider(console, fake.base_url)

            mission = _queue_mission(console, "Analyse the sample across runs.", max_runs=4)
            done = _wait_mission_terminal(console, mission["id"])

            assert done["status"] == "completed", done
            assert done["runs_used"] == 2, done
            assert done["last_run_id"], done

            # The isolation step ran exactly once -- at the sample boundary,
            # never between the runs of the same mission.
            assert marker.read_text(encoding="utf-8").splitlines() == ["rotated"]

            # The thread shows the continuation contract carrying the work
            # across bounded runs, and a final reply opening with the marker.
            detail = console.client.get(
                f"{console.base}/api/agent/threads/{mission['thread_id']}",
                headers=console.headers,
            ).json()
            user_texts = [m["content"] for m in detail["messages"] if m["role"] == "user"]
            assert any("Run 1 of at most 4" in text for text in user_texts)
            assert any("Run 2 of at most 4" in text for text in user_texts)
            finals = [m["content"] for m in detail["messages"] if m["role"] == "assistant"]
            assert finals and finals[-1].startswith(MISSION_COMPLETE_MARKER)
    finally:
        fake.close()


@pytest.mark.integration
def test_required_isolation_failure_fails_the_mission_closed(tmp_path: Path) -> None:
    script, marker = _rotation_script(tmp_path, exit_code=2)
    fake = _MissionOpenAI(complete_on_attempt=1)
    try:
        with _console(
            tmp_path,
            config={"isolation_command": [sys.executable, str(script)], "isolation_required": True},
        ) as console:
            _configure_provider(console, fake.base_url)

            mission = _queue_mission(console, "Analyse a sample on a dirty machine.", max_runs=4)
            done = _wait_mission_terminal(console, mission["id"])

            # Continuing would analyse a new sample on a machine the previous
            # one touched: the mission must fail before any run starts.
            assert done["status"] == "failed", done
            assert "isolation step failed" in (done["error"] or ""), done
            assert done["runs_used"] == 0, done
            assert not done["last_run_id"], done
            # The command genuinely ran (and reported its failure).
            assert marker.read_text(encoding="utf-8").splitlines() == ["rotated"]
    finally:
        fake.close()


@pytest.mark.integration
def test_spent_budget_is_filed_as_exhausted_not_completed(tmp_path: Path) -> None:
    # The provider never opens with the marker, so the objective is never met.
    fake = _MissionOpenAI(complete_on_attempt=99)
    try:
        with _console(tmp_path) as console:
            _configure_provider(console, fake.base_url)

            mission = _queue_mission(console, "An objective the model never finishes.", max_runs=1)
            done = _wait_mission_terminal(console, mission["id"])

            assert done["status"] == "exhausted", done
            assert "objective not met within 1 runs" in (done["error"] or ""), done
            assert done["runs_used"] == 1, done

            # Honest bookkeeping over HTTP: the missions listing shows the same
            # terminal state and a live scheduler.
            listing = console.client.get(
                f"{console.base}/api/agent/missions", headers=console.headers
            ).json()
            assert listing["scheduler_running"] is True
            by_id = {item["id"]: item for item in listing["missions"]}
            assert by_id[mission["id"]]["status"] == "exhausted"
    finally:
        fake.close()
