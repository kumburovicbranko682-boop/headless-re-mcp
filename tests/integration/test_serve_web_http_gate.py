"""serve-web gate: the operator console boots and serves over real HTTP.

Every existing web-console test drives the ASGI app in process through
Starlette's TestClient, which skips the parts an operator actually depends
on: the ``python -m headless_re_mcp serve-web`` CLI path, the uvicorn boot,
a real TCP port, real request sources for the loopback guard, and the
process shutdown. This gate spawns the real thing and pins:

* the door: unauthenticated and wrongly-authenticated API calls get 401,
  ``/`` without a token gets the 401 hint page, ``?token=`` serves the SPA
  and plants the HttpOnly bootstrap cookie, and that cookie alone (no Bearer,
  no query token -- the SPA strips it from the URL) authenticates API calls;
* the probes: ``/healthz`` answers liveness with build info including the
  platform support level, ``/readyz`` answers 200 with passing store and
  artifact-root checks, ``/metrics`` serves a Prometheus exposition -- all
  three without credentials, as a supervisor would call them;
* the work: a full analysis session lifecycle -- create against the committed
  PE fixture, list, get, report, timeline, close -- over plain HTTP with a
  Bearer token, every response a structured envelope.

Pure Python end to end (uvicorn + fastapi from the web extra); no analysis
backend is opened. The token file and all state live in isolated temp
directories seeded through the same config-home mechanism the product uses.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_TOKEN = "serve-web-http-gate-" + "x" * 24
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _seed_token(config_home: Path) -> None:
    token_dir = config_home / "headless-re-mcp"
    token_dir.mkdir(parents=True, exist_ok=True)
    (token_dir / "web_token.json").write_text(json.dumps({"token": _TOKEN}), encoding="utf-8")


@contextmanager
def _serve_web(tmp_root: Path) -> Iterator[str]:
    """A real serve-web process; yields its base URL, guarantees teardown."""
    config_home = tmp_root / "config"
    _seed_token(config_home)
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_root / "artifacts")
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
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


def _envelope(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, (response.status_code, response.text)
    payload = response.json()
    assert payload["ok"] is True, payload
    return payload


@pytest.mark.integration
@pytest.mark.headless
def test_serve_web_guards_the_door_and_answers_probes(tmp_path: Path) -> None:
    with _serve_web(tmp_path) as base_url, httpx.Client(base_url=base_url) as http:
        # Probes answer without credentials, the way a supervisor calls them.
        health = http.get("/healthz")
        assert health.status_code == 200
        body = health.json()
        assert body["ok"] is True
        assert body["service"] == "headless-re-mcp-web"
        assert body["build"]["version"]
        assert body["build"]["support_level"] in {"full", "core"}
        if sys.platform.startswith("linux"):
            assert body["build"]["support_level"] == "core"

        ready = http.get("/readyz")
        assert ready.status_code == 200, ready.text
        readiness = ready.json()
        assert readiness["ok"] is True
        assert readiness["data"]["ready"] is True
        checks = {check["name"]: check["ok"] for check in readiness["data"]["checks"]}
        assert checks == {"store": True, "artifact_root": True}

        metrics = http.get("/metrics")
        assert metrics.status_code == 200
        assert metrics.headers["content-type"].startswith("text/plain")
        assert "headless_re" in metrics.text

        # The door: no token, wrong token, right token.
        assert http.get("/api/meta").status_code == 401
        wrong = http.get("/api/meta", headers={"Authorization": "Bearer nope-" + "x" * 24})
        assert wrong.status_code == 401
        meta = _envelope(http.get("/api/meta", headers={"Authorization": f"Bearer {_TOKEN}"}))
        assert meta["loopback_only"] is True
        assert str(tmp_path) in meta["artifact_root"]

        # The SPA: 401 hint page without a token, HTML plus bootstrap cookie
        # with one, and the HttpOnly cookie alone then authenticates the API
        # (the SPA strips ?token= from the URL after first load).
        bare = http.get("/")
        assert bare.status_code == 401
        assert "token" in bare.text
        page = http.get("/", params={"token": _TOKEN})
        assert page.status_code == 200
        assert "<!doctype" in page.text.lower()
        cookie = page.cookies.get("headless_re_bootstrap")
        assert cookie, "bootstrap cookie was not planted"
        via_cookie = httpx.get(
            f"{base_url}/api/sessions", cookies={"headless_re_bootstrap": cookie}
        )
        assert via_cookie.status_code == 200
        assert via_cookie.json()["ok"] is True


@pytest.mark.integration
@pytest.mark.headless
def test_serve_web_drives_an_analysis_session_over_http(tmp_path: Path) -> None:
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    with (
        _serve_web(tmp_path) as base_url,
        httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {_TOKEN}"}) as http,
    ):
        empty = _envelope(http.get("/api/sessions"))
        assert empty["data"]["sessions"] == []

        created = _envelope(http.post("/api/sessions", json={"binary": str(_PE_FIXTURE)}))
        session = created["data"]["session"]
        session_id = str(session["id"])
        assert session["target"] == "pe"

        listed = _envelope(http.get("/api/sessions"))
        assert [item["id"] for item in listed["data"]["sessions"]] == [session_id]

        fetched = _envelope(http.get(f"/api/sessions/{session_id}"))
        assert fetched["data"]["session"]["id"] == session_id

        report = _envelope(
            http.post(f"/api/sessions/{session_id}/report", json={"title": "HTTP gate"})
        )
        assert report["data"]["artifact_id"]
        assert "HTTP gate" in report["data"]["markdown"]

        timeline = _envelope(http.get(f"/api/sessions/{session_id}/timeline"))
        events = [entry["event"] for entry in timeline["data"]["events"]]
        assert "session.created" in events

        closed = _envelope(http.post(f"/api/sessions/{session_id}/close"))
        assert closed["ok"] is True

        unclean = _envelope(http.get("/api/sessions/unclean"))
        assert unclean["data"]["sessions"] == []
