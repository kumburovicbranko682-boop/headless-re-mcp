"""Operator first-touch CLI, proven end to end: doctor honesty + a bootable bundle.

``doctor`` and ``config generate`` are the first two commands a new operator
runs; everything else depends on trusting them. ``doctor`` must tell the truth
about this host -- on Linux the Windows-only backends are
``unsupported_on_platform``, never a misleading ``missing``, and ``--strict``
must exit by the same readiness the JSON report printed. ``config generate``
must emit a secrets-free MCP server block that is not merely well-shaped but
actually boots: this gate launches the generated command line as a real MCP
stdio server, completes the handshake, and lists tools.

Both commands run as real subprocesses (``python -m headless_re_mcp ...``) in
an isolated config/artifact environment. Pure Python; runs on any platform and
asserts per-platform honesty rather than assuming one OS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ON_WINDOWS = sys.platform.startswith("win")

_STATUS_VALUES = {"ready", "detected", "missing", "blocked", "unsupported_on_platform"}
_WINDOWS_ONLY_PROBES = {"x64dbg_headless_binaries", "win32_ui", "windbg"}


def _isolated_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    config_home = tmp_path / "config-home"
    config_home.mkdir(parents=True, exist_ok=True)
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return env


def _cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "headless_re_mcp", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=_PROJECT_ROOT,
        timeout=180,
        check=False,
    )


@pytest.mark.integration
def test_doctor_json_reports_this_platform_honestly(tmp_path: Path) -> None:
    env = _isolated_env(tmp_path)

    result = _cli(["doctor", "--json"], env)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)

    # Contract shape: readiness, platform block, and every probe accounted for.
    assert isinstance(report["ready"], bool)
    probes = {probe["name"]: probe for probe in report["probes"]}
    assert len(probes) == len(report["probes"]), "probe names must be unique"
    for probe in report["probes"]:
        assert probe["status"] in _STATUS_VALUES, probe
        assert isinstance(probe["required"], bool)
    required_flagged = {name for name, probe in probes.items() if probe["required"]}
    assert required_flagged == set(report["required_probes"])

    if _ON_WINDOWS:
        assert report["platform"]["support_level"] == "full"
        for name in _WINDOWS_ONLY_PROBES:
            assert probes[name]["status"] != "unsupported_on_platform", probes[name]
    else:
        # Linux core: only platform+python are required, the platform block
        # says core, and the Windows-only backends are honestly unsupported
        # rather than pretending they could be installed here.
        assert report["platform"]["support_level"] == "core"
        assert set(report["required_probes"]) == {"platform", "python"}
        assert report["ready"] is True
        for name in _WINDOWS_ONLY_PROBES:
            assert probes[name]["status"] == "unsupported_on_platform", probes[name]
            assert probes[name]["required"] is False

    # --strict must exit by the same readiness the JSON report printed.
    strict = _cli(["doctor", "--strict"], env)
    assert strict.returncode == (0 if report["ready"] else 1), strict.stdout


@pytest.mark.integration
@pytest.mark.asyncio
async def test_config_generate_bundle_is_secrets_free_and_actually_boots(
    tmp_path: Path,
) -> None:
    env = _isolated_env(tmp_path)
    output = tmp_path / "bundle.json"

    result = _cli(["config", "generate", "--output", str(output)], env)
    text = output.read_text(encoding="utf-8")
    bundle = json.loads(text)

    if not bundle.get("ok"):
        # On a host whose doctor is not ready (e.g. Windows without IDA) the
        # command must fail closed with the doctor verdict, then --skip-doctor
        # still yields a bootable bundle.
        assert result.returncode == 1
        assert bundle["error"]["code"] == "doctor_not_ready"
        result = _cli(["config", "generate", "--skip-doctor", "--output", str(output)], env)
        text = output.read_text(encoding="utf-8")
        bundle = json.loads(text)

    assert result.returncode == 0, result.stderr
    assert bundle["ok"] is True

    server = bundle["stdio"]
    assert Path(server["command"]).exists()
    assert server["args"][:2] == ["-m", "headless_re_mcp"]
    assert server["args"][-1] == "serve"
    if "--config" in server["args"]:
        # The pinned config path lives in the isolated config home, not in the
        # operator's real profile.
        pinned = Path(server["args"][server["args"].index("--config") + 1])
        assert str(pinned).startswith(env["XDG_CONFIG_HOME"]), pinned

    # Secrets-free: no api keys anywhere, and env carries only the config
    # pointer -- never tokens or licenses.
    assert "api_key" not in text.lower()
    assert set(server["env"]) <= {"HEADLESS_RE_CONFIG"}

    # The copy-paste examples all wrap the very same server block.
    examples = bundle["examples"]
    assert examples["cursor"]["mcpServers"]["headless-re-mcp"] == server
    assert examples["claude_desktop"]["mcpServers"]["headless-re-mcp"] == server
    vscode = examples["vscode"]["servers"]["headless-re-mcp"]
    assert vscode["type"] == "stdio"
    assert vscode["command"] == server["command"]
    assert vscode["args"] == server["args"]

    # The bundle is not just well-shaped: the generated command line boots a
    # real MCP server that completes the handshake and advertises tools.
    child_env = {**env, **{k: str(v) for k, v in server["env"].items()}}
    params = StdioServerParameters(
        command=server["command"],
        args=server["args"],
        env=child_env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        listed = await client.list_tools()
        names = {tool.name for tool in listed.tools}
        assert "session.create" in names
        assert "capabilities.search" in names
        assert len(names) > 100
