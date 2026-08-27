"""Operator first-contact CLI gate: doctor tells the truth, config generate works.

``doctor`` and ``config generate`` are the first two commands a new operator
runs, and both make promises the rest of the deployment rests on: doctor's
platform verdict decides whether an install is "ready", and the generated
bundle is what gets pasted into an MCP host. Their unit tests exercise the
functions; nothing yet holds the actual CLI subprocess to its contract.

This gate runs the real CLI and pins:

* ``doctor --json`` reports the platform support level honestly -- ``core`` on
  Linux, ``full`` on Windows -- with the platform-correct required-probe set,
  and every Windows-only backend on a non-Windows host says
  ``unsupported_on_platform`` (never "ready", never a fake "missing" that a
  reader would try to install); ``--strict`` exits 0 on a box whose required
  probes are ready;
* ``config generate`` emits a secrets-free bundle whose stdio block is not
  merely well-shaped: the gate boots the exact command+args the bundle
  prescribes and completes a real MCP initialize/list_tools handshake over
  stdio, so what the operator pastes into Cursor is proven runnable.

Pure Python end to end; runs on any supported platform.
"""

from __future__ import annotations

import asyncio
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

_WINDOWS_ONLY_PROBES = {
    "x64dbg_source",
    "x64dbg_headless_binaries",
    "x64dbg_scyllahide",
    "native_toolchain",
    "win32_ui",
    "hidden_desktop",
    "exeinfope",
    "xvlkc",
    "vmp_dumper",
    "scylla",
    "windbg",
}


def _isolated_env(tmp_path: Path) -> dict[str, str]:
    config_home = tmp_path / "config"
    config_home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    return env


def _cli(args: list[str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "headless_re_mcp", *args],
        cwd=str(_PROJECT_ROOT),
        env=_isolated_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=180.0,
    )


@pytest.mark.integration
@pytest.mark.headless
def test_doctor_json_reports_this_platform_honestly(tmp_path: Path) -> None:
    result = _cli(["doctor", "--json"], tmp_path)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)

    expected_level = "full" if _ON_WINDOWS else "core"
    assert report["platform"]["support_level"] == expected_level
    assert report["platform"]["status"] == "ready"

    expected_required = (
        {"platform", "python", "ida_idalib", "x64dbg_headless_binaries"}
        if _ON_WINDOWS
        else {"platform", "python"}
    )
    assert set(report["required_probes"]) == expected_required

    by_name = {probe["name"]: probe for probe in report["probes"]}
    # The probe list is complete enough to answer the required question at all.
    assert expected_required.issubset(by_name)
    for name in ("platform", "python"):
        assert by_name[name]["status"] == "ready", by_name[name]
        assert by_name[name]["required"] is True
    assert report["ready"] is True

    if not _ON_WINDOWS:
        # Windows-only capability is declared unsupported -- not "missing", which
        # would send the reader off to install something that cannot exist here,
        # and never "ready", which would be a lie.
        for name in _WINDOWS_ONLY_PROBES:
            probe = by_name[name]
            assert probe["status"] == "unsupported_on_platform", probe
            assert probe["required"] is False

    # Strict mode agrees: required probes are ready, so the gate passes.
    strict = _cli(["doctor", "--json", "--strict"], tmp_path)
    assert strict.returncode == 0, strict.stdout[-2000:]


async def _handshake_tool_count(server: dict[str, object], tmp_path: Path) -> int:
    params = StdioServerParameters(
        command=str(server["command"]),
        args=[str(item) for item in server["args"]],  # type: ignore[union-attr]
        env=_isolated_env(tmp_path),
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        return len(tools.tools)


@pytest.mark.integration
@pytest.mark.headless
def test_config_generate_bundle_is_secrets_free_and_actually_boots(tmp_path: Path) -> None:
    output = tmp_path / "bundle.json"
    result = _cli(["config", "generate", "--output", str(output)], tmp_path)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]

    text = output.read_text(encoding="utf-8")
    bundle = json.loads(text)
    assert bundle["ok"] is True

    server = bundle["stdio"]
    assert Path(server["command"]).exists(), server["command"]
    # The bundle pins the (isolated) default config path explicitly, so the MCP
    # host runs with the same config the operator would edit.
    default_config = (
        Path(_isolated_env(tmp_path)["XDG_CONFIG_HOME"]) / "headless-re-mcp" / "config.json"
        if not _ON_WINDOWS
        else Path(_isolated_env(tmp_path)["APPDATA"]) / "headless-re-mcp" / "config.json"
    ).resolve()
    assert server["args"] == ["-m", "headless_re_mcp", "--config", str(default_config), "serve"]
    assert server["env"] == {"HEADLESS_RE_CONFIG": str(default_config)}
    # No secret material rides along in what gets pasted into an MCP host: the
    # only env the server block carries is the config-file pointer.
    assert "api_key" not in text.lower()
    assert set(server["env"]) == {"HEADLESS_RE_CONFIG"}

    # The examples are copy-paste blocks wrapping that same server.
    cursor_example = bundle["examples"]["cursor"]["mcpServers"]["headless-re-mcp"]
    assert cursor_example["command"] == server["command"]

    # The strongest claim: the emitted command really is an MCP server. Boot
    # exactly what the bundle says and complete a live handshake over stdio.
    tool_count = asyncio.run(_handshake_tool_count(server, tmp_path))
    assert tool_count > 100, f"advertised only {tool_count} tools"

    # A pinned config path is threaded through argv and env, resolved.
    config_file = tmp_path / "operator-config.json"
    config_file.write_text("{}", encoding="utf-8")
    pinned_out = tmp_path / "pinned.json"
    pinned = _cli(
        [
            "config",
            "generate",
            "--config-path",
            str(config_file),
            "--no-examples",
            "--output",
            str(pinned_out),
        ],
        tmp_path,
    )
    assert pinned.returncode == 0
    pinned_bundle = json.loads(pinned_out.read_text(encoding="utf-8"))
    resolved = str(config_file.resolve())
    assert pinned_bundle["stdio"]["args"] == [
        "-m",
        "headless_re_mcp",
        "--config",
        resolved,
        "serve",
    ]
    assert pinned_bundle["stdio"]["env"] == {"HEADLESS_RE_CONFIG": resolved}
    assert "examples" not in pinned_bundle
