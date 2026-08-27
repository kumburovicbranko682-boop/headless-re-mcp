"""Console configuration & persona control plane, over the real serve-web process.

Two operator-facing control planes the console exposes get no end-to-end
coverage today, even though both are pure Python and drive real state:

* **Personas** are the agent's system prompt. Listing the built-ins, selecting
  one, importing a custom markdown persona (which becomes current), and
  deleting it -- plus the guards that refuse an empty import and refuse to
  delete a built-in -- is the whole surface an operator uses to steer the
  agent, and it persists to disk next to the console data.
* **MCP export** is the console's version of ``config generate``: it discovers
  local backends and hands back client-shaped MCP JSON (Cursor / VS Code /
  Claude Desktop / raw stdio) that the operator pastes into their host, and can
  persist those files under the config directory. It must never bundle IDA and
  never claim universal unpack.

This gate drives both over a real ``serve-web`` process with isolated config
and artifact roots. Pure Python, any platform.
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

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TOKEN = "console-config-persona-gate-" + "w" * 18
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextmanager
def _console(tmp_root: Path) -> Iterator[tuple[httpx.Client, Path]]:
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
        with httpx.Client(
            base_url=base_url, headers={"Authorization": f"Bearer {_TOKEN}"}, timeout=30.0
        ) as client:
            yield client, config_home / "headless-re-mcp"
    finally:
        process.terminate()
        try:
            process.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15.0)


@pytest.mark.integration
@pytest.mark.headless
def test_persona_control_plane_over_http(tmp_path: Path) -> None:
    with _console(tmp_path) as (http, _config_dir):
        listing = http.get("/api/agent/personas").json()
        assert listing["ok"] is True
        by_id = {item["id"]: item for item in listing["personas"]}
        assert "default" in by_id
        # Exactly one persona is marked current, and it is a built-in.
        current_items = [item for item in listing["personas"] if item["current"]]
        assert len(current_items) == 1
        assert current_items[0]["builtin"] is True
        assert listing["current"] == current_items[0]["id"]

        # Selecting the default pins it; an unknown id is a clean 404.
        selected = http.post("/api/agent/personas/select", json={"id": "default"})
        assert selected.status_code == 200
        assert selected.json()["current"] == "default"
        assert http.post("/api/agent/personas/select", json={"id": "ghost"}).status_code == 404
        assert http.post("/api/agent/personas/select", json={}).status_code == 400

        # Importing a markdown persona creates it and makes it current.
        imported = http.post(
            "/api/agent/personas/import",
            json={"title": "Recon Specialist", "content": "Focus on imports and strings first."},
        )
        assert imported.status_code == 200, imported.text
        new_id = imported.json()["current"]
        assert new_id not in {"default", "seagull"}
        new_by_id = {item["id"]: item for item in imported.json()["personas"]}
        assert new_by_id[new_id]["builtin"] is False
        assert new_by_id[new_id]["current"] is True

        # It survives a fresh read (persisted to disk, not just in memory).
        reread = {item["id"]: item for item in http.get("/api/agent/personas").json()["personas"]}
        assert new_id in reread

        # Guards: empty import and built-in deletion are refused, not honoured.
        assert (
            http.post(
                "/api/agent/personas/import", json={"title": "blank", "content": "   "}
            ).status_code
            == 400
        )
        assert (
            http.request("DELETE", "/api/agent/personas/default").status_code == 400
        )  # persona_builtin
        assert http.request("DELETE", "/api/agent/personas/ghost").status_code == 404

        # Deleting the custom persona removes it and resets current to a built-in.
        deleted = http.request("DELETE", f"/api/agent/personas/{new_id}")
        assert deleted.status_code == 200, deleted.text
        after = deleted.json()
        assert new_id not in {item["id"] for item in after["personas"]}
        assert after["current"] in {"default", "seagull"}
        assert {item["id"] for item in after["personas"] if item["current"]} == {after["current"]}


@pytest.mark.integration
@pytest.mark.headless
def test_mcp_export_over_http(tmp_path: Path) -> None:
    with _console(tmp_path) as (http, config_dir):
        # Client-shaped export: a Cursor snippet wraps the stdio server.
        cursor = http.get("/api/mcp/export", params={"client": "cursor"}).json()
        assert cursor["never_bundle_ida"] is True
        assert cursor["claims_universal_unpack"] is False
        assert cursor["client"] == "cursor"
        server = cursor["config"]["mcpServers"]["headless-re-mcp"]
        assert Path(server["command"]).exists()
        assert "serve" in server["args"]

        # Raw stdio export hands back the same server block directly.
        stdio = http.get("/api/mcp/export", params={"client": "stdio"}).json()
        assert stdio["config"]["args"][-1] == "serve"
        assert stdio["stdio"]["args"] == stdio["config"]["args"]

        # "all" carries stdio plus every example wrapper.
        everything = http.get("/api/mcp/export", params={"client": "all"}).json()
        assert set(everything["examples"]) == {"cursor", "vscode", "claude_desktop"}
        assert everything["stdio"]["args"][-1] == "serve"

        # An unknown client is rejected before doing any work.
        assert http.get("/api/mcp/export", params={"client": "emacs"}).status_code == 400

        # No IDA license or secret rides along in the exported JSON.
        assert "api_key" not in json.dumps(everything).lower()

        # POST demands confirmation; a confirmed persist writes real files.
        assert http.post("/api/mcp/export", json={}).status_code == 400
        persisted = http.post("/api/mcp/export", json={"confirm": True, "persist": True})
        assert persisted.status_code == 200, persisted.text
        body = persisted.json()
        assert body["persisted"] is True
        written = body["written"]
        assert "bundle" in written
        bundle_path = Path(written["bundle"])
        assert bundle_path.is_file()
        assert bundle_path.parent == config_dir
        # The persisted bundle is valid JSON describing the stdio server.
        saved = json.loads(bundle_path.read_text(encoding="utf-8"))
        assert saved["stdio"]["args"][-1] == "serve"
