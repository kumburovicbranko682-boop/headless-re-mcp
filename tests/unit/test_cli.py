from __future__ import annotations

import json
from pathlib import Path

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.backends.x64dbg.gate import XdbgHeadlessGateResult
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture


def _settings(tmp_path: Path, *, configured: bool) -> Settings:
    x86 = tmp_path / "headless-x86.exe" if configured else None
    x64 = tmp_path / "headless-x64.exe" if configured else None
    if x86 is not None:
        x86.touch()
    if x64 is not None:
        x64.touch()
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=x86,
        artifact_root=tmp_path / "artifacts",
    )


def test_gate_xdbg_cli_reports_missing_executables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path, configured=False)
    monkeypatch.setattr(cli_module.Settings, "load", lambda _path=None: settings)
    monkeypatch.setattr(cli_module, "is_windows_host", lambda: True)

    exit_code = cli_module.main(["gate-xdbg", "--architecture", "all"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["ok"] is False
    assert {item["architecture"] for item in payload["results"]} == {"x86", "x64"}


def test_gate_xdbg_cli_runs_requested_architectures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path, configured=True)
    monkeypatch.setattr(cli_module.Settings, "load", lambda _path=None: settings)
    monkeypatch.setattr(cli_module, "is_windows_host", lambda: True)
    calls: list[tuple[Architecture, float]] = []

    def fake_gate(
        executable: Path,
        architecture: Architecture,
        *,
        timeout: float,
    ) -> XdbgHeadlessGateResult:
        calls.append((architecture, timeout))
        return XdbgHeadlessGateResult(
            ok=True,
            architecture=architecture,
            executable=str(executable),
            exit_code=0,
            stdout="[headless] entering command loop...",
            stderr="",
            analyzer_windows=(),
            command_loop_seen=True,
        )

    monkeypatch.setattr(cli_module, "run_command_loop_gate", fake_gate)

    exit_code = cli_module.main(
        ["gate-xdbg", "--architecture", "all", "--timeout", "2.5"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert set(calls) == {
        (Architecture.X86, 2.5),
        (Architecture.X64, 2.5),
    }