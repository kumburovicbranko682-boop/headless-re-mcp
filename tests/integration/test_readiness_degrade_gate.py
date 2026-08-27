"""Readiness degrades honestly and recovers, while liveness never wavers.

``/healthz`` and ``/readyz`` answer different questions on purpose: liveness
proves the process serves HTTP and deliberately touches nothing else, so a
slow or broken backend can never talk a supervisor into a restart loop;
readiness actually writes a probe file under the artifact root and reports
503 the moment new work would fail. That split is what an unattended
deployment stands on -- the supervisor restarts on liveness, the load
director drains on readiness -- and the happy path alone proves none of it.

This gate boots a real ``serve-web`` process, then takes the artifact root's
write permission away out from under it. It asserts ``/readyz`` flips to 503
with the ``artifact_root`` check named as the failure, that ``/healthz``
keeps answering 200 throughout, and that ``/metrics`` keeps serving scrapes
with the ``headless_re_ready`` gauge dropping to 0 -- degradation must be
observable, not an outage of the observer. Restoring the permission flips
``/readyz`` back to 200 with no restart, proving the probes re-check reality
on every call instead of latching. Loopback only, pure Python, no real
backends.
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
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="degrades the artifact root via POSIX directory permissions"
)


@dataclass
class _Console:
    base: str
    headers: dict[str, str]
    client: httpx.Client
    artifact_root: Path


@contextlib.contextmanager
def _console(tmp_path: Path) -> Iterator[_Console]:
    config_home = tmp_path / "config-home"
    app_dir = config_home / "headless-re-mcp"
    app_dir.mkdir(parents=True)
    token = _secrets.token_urlsafe(32)
    (app_dir / "web_token.json").write_text(json.dumps({"token": token}), encoding="utf-8")

    artifact_root = tmp_path / "artifacts"
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)

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
            base=base,
            headers={"Authorization": f"Bearer {token}"},
            client=client,
            artifact_root=artifact_root,
        )
    finally:
        # Whatever the test did to the directory, put it back so shutdown and
        # tmp_path cleanup never trip over a read-only tree.
        with contextlib.suppress(OSError):
            os.chmod(artifact_root, 0o700)
        client.close()
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)


def _readyz(console: _Console) -> tuple[int, dict[str, Any]]:
    response = console.client.get(f"{console.base}/readyz")
    payload = response.json()
    assert isinstance(payload, dict)
    return response.status_code, payload


def _check(payload: dict[str, Any], name: str) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {
        item["name"]: item for item in payload.get("data", {}).get("checks", [])
    }
    assert name in checks, f"readyz payload lists no {name!r} check: {sorted(checks)}"
    return checks[name]


def _ready_gauge(exposition: str) -> float:
    match = re.search(r"^headless_re_ready (\S+)$", exposition, re.MULTILINE)
    assert match, "exposition carries no headless_re_ready sample"
    return float(match.group(1))


def _wait_readyz(console: _Console, status: int, *, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    code, payload = _readyz(console)
    while code != status:
        assert time.monotonic() < deadline, (
            f"/readyz never reached {status}; last answer {code}: {json.dumps(payload)[:500]}"
        )
        time.sleep(0.3)
        code, payload = _readyz(console)
    return payload


def test_readiness_degrades_to_503_and_recovers_while_liveness_holds(tmp_path: Path) -> None:
    with _console(tmp_path) as console:
        # Healthy baseline: both checks pass, the gauge reads 1, and the
        # payload names the platform honestly so a fleet dashboard can trust it.
        payload = _wait_readyz(console, 200)
        assert payload["ok"] is True
        assert payload["data"]["ready"] is True
        assert _check(payload, "artifact_root")["ok"] is True
        assert _check(payload, "store")["ok"] is True
        assert payload["data"]["platform"]["system"] == "Linux"

        healthy_metrics = console.client.get(f"{console.base}/metrics")
        assert healthy_metrics.status_code == 200
        assert _ready_gauge(healthy_metrics.text) == 1.0

        # Take the artifact root's write bit away under the running process.
        # The probe creates a fresh file per call, so this is exactly the
        # failure a full or remounted-read-only volume produces.
        os.chmod(console.artifact_root, 0o500)
        try:
            degraded = _wait_readyz(console, 503)
            assert degraded["data"]["ready"] is False
            failed = _check(degraded, "artifact_root")
            assert failed["ok"] is False
            assert failed["detail"], "a failing check must say why"

            # Liveness is a different question and must keep answering 200:
            # this is the property that stops a supervisor restart loop.
            health = console.client.get(f"{console.base}/healthz")
            assert health.status_code == 200
            assert health.json()["ok"] is True

            # The scrape endpoint stays up too -- degradation is a signal to
            # publish, not a reason the publisher goes dark.
            degraded_metrics = console.client.get(f"{console.base}/metrics")
            assert degraded_metrics.status_code == 200
            assert _ready_gauge(degraded_metrics.text) == 0.0
        finally:
            os.chmod(console.artifact_root, 0o700)

        # Same process, no restart: the probe re-checks reality per call, so
        # readiness returns as soon as the directory does.
        recovered = _wait_readyz(console, 200)
        assert recovered["data"]["ready"] is True
        assert _check(recovered, "artifact_root")["ok"] is True
        assert _ready_gauge(console.client.get(f"{console.base}/metrics").text) == 1.0


def test_metrics_exposition_is_well_formed_prometheus(tmp_path: Path) -> None:
    with _console(tmp_path) as console:
        response = console.client.get(f"{console.base}/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain; version=0.0.4")

        text = response.text
        assert text.endswith("\n"), "exposition must end with a newline"

        # Every non-comment line must be `name{labels} value` with a finite
        # float value; a scraper drops the whole document over one bad line.
        sample_pattern = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$")
        families: dict[str, str] = {}
        samples: list[str] = []
        for line in text.splitlines():
            if not line:
                continue
            if line.startswith("# HELP ") or line.startswith("# TYPE "):
                kind, _, rest = line[2:].partition(" ")
                name = rest.split(" ", 1)[0]
                assert name.startswith("headless_re_"), line
                if kind == "TYPE":
                    families[name] = rest.split(" ", 2)[1]
                continue
            match = sample_pattern.match(line)
            assert match, f"malformed sample line: {line!r}"
            float(match.group(3))
            samples.append(match.group(1))

        # The always-on families a fleet dashboard is built around.
        assert families.get("headless_re_build_info") == "gauge"
        assert families.get("headless_re_ready") == "gauge"
        assert "headless_re_build_info" in samples
        assert "headless_re_ready" in samples

        # Build labels name the running interpreter so a scrape can attribute
        # a regression to the environment that produced it.
        build_line = next(
            line for line in text.splitlines() if line.startswith("headless_re_build_info")
        )
        assert f'python="{sys.version_info.major}.{sys.version_info.minor}' in build_line

        # Every sample belongs to a declared family: HELP/TYPE are not
        # decoration, they are the contract TYPE-checking scrapers enforce.
        assert set(samples) <= set(families), sorted(set(samples) - set(families))
