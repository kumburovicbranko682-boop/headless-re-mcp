"""run_idalib_gate is driven with a faked worker so its body runs off Windows.

The only other test for this function starts a real descendant process to prove
the timeout kills the whole tree, and it is Win32-only, so on any other platform
the launcher, the analyzer-window gate, the exit-code handling and the timeout
branch never execute. These tests fake the subprocess and the window probe so the
gate's decision logic -- ok requires a zero exit, an ok payload and no analyzer
window -- is exercised directly, along with the timeout path's killed-pid report.
"""

from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida import gate as gate_mod
from headless_re_mcp.backends.ida.gate import HeadlessGateResult, _last_json_line, run_idalib_gate
from headless_re_mcp.config import Settings


class _FakePopen:
    def __init__(
        self,
        cmd: list[str],
        *,
        stdout: str = "",
        returncode: int = 0,
        timeout_first: bool = False,
        **_: Any,
    ) -> None:
        self.cmd = cmd
        self.pid = 4321
        self._stdout = stdout
        self.returncode = returncode
        self._timeout_first = timeout_first
        self._calls = 0

    def communicate(self, timeout: float = 0.0) -> tuple[str, str]:
        self._calls += 1
        if self._timeout_first and self._calls == 1:
            raise subprocess.TimeoutExpired(cmd=self.cmd, timeout=timeout)
        return self._stdout, "worker-stderr"

    def kill(self) -> None:
        pass


def _run_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    stdout: str,
    returncode: int = 0,
    windows: tuple[str, ...] = (),
    timeout_first: bool = False,
    decompile: bool = True,
) -> tuple[HeadlessGateResult, list[str]]:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    fake_ida = tmp_path / "IDA"
    fake_ida.mkdir()
    settings = replace(Settings.load(), ida_home=fake_ida)

    captured: dict[str, list[str]] = {}

    def fake_popen(cmd: list[str], **kwargs: Any) -> _FakePopen:
        captured["cmd"] = cmd
        return _FakePopen(
            cmd, stdout=stdout, returncode=returncode, timeout_first=timeout_first
        )

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(gate_mod, "describe_process_windows", lambda pid: set(windows))
    monkeypatch.setattr(gate_mod, "terminate_process_tree", lambda proc: [proc.pid, 9999])

    result = run_idalib_gate(binary, settings, timeout=0.3, decompile=decompile)
    return result, captured["cmd"]


def test_gate_ok_requires_zero_exit_ok_payload_and_no_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _ = _run_gate(monkeypatch, tmp_path, stdout='{"ok": true, "id": "1"}\n')
    assert result.ok is True
    assert result.exit_code == 0
    assert result.backend == "ida"
    assert result.payload == {"ok": True, "id": "1"}
    assert result.analyzer_windows == ()
    assert result.stderr == "worker-stderr"


def test_gate_not_ok_when_worker_payload_is_not_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _ = _run_gate(monkeypatch, tmp_path, stdout='{"ok": false}\n')
    assert result.ok is False
    assert result.exit_code == 0


def test_gate_not_ok_when_an_analyzer_window_appeared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A visible analyzer window means the run was not truly headless."""
    result, _ = _run_gate(
        monkeypatch, tmp_path, stdout='{"ok": true}\n', windows=("Analyzer",)
    )
    assert result.ok is False
    assert result.analyzer_windows == ("Analyzer",)


def test_gate_not_ok_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _ = _run_gate(monkeypatch, tmp_path, stdout='{"ok": true}\n', returncode=3)
    assert result.ok is False
    assert result.exit_code == 3


def test_gate_reports_error_when_worker_emits_no_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _ = _run_gate(monkeypatch, tmp_path, stdout="garbage\n")
    assert result.ok is False
    assert result.payload == {"error": "worker returned no JSON object"}


def test_gate_passes_no_decompile_flag_before_the_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, cmd = _run_gate(monkeypatch, tmp_path, stdout='{"ok": true}\n', decompile=False)
    assert "--no-decompile" in cmd
    assert cmd.index("--no-decompile") < len(cmd) - 1  # the binary path is last


def test_gate_timeout_reports_killed_pids_and_drains_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A timeout terminates the tree, reports the killed pids and exits -1."""
    result, _ = _run_gate(
        monkeypatch, tmp_path, stdout='{"ok": true}\n', timeout_first=True
    )
    assert result.ok is False
    assert result.exit_code == -1
    assert "timed out" in result.payload["error"]
    assert result.payload["killed_pids"] == [4321, 9999]
    assert result.to_dict()["payload"]["killed_pids"] == [4321, 9999]


def test_gate_raises_when_ida_home_is_unset(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    settings = replace(Settings.load(), ida_home=None)
    with pytest.raises(RuntimeError, match="IDA home is not configured"):
        run_idalib_gate(binary, settings)


def test_last_json_line_skips_a_non_object_with_nothing_after_it() -> None:
    """A line that parses to a non-object JSON value is skipped, not returned."""
    assert _last_json_line("garbage\n[1, 2, 3]\n") == {
        "error": "worker returned no JSON object"
    }
