"""Unit coverage for the idalib gate runner using a faked worker process."""

from __future__ import annotations

import subprocess
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida import gate as gate_mod
from headless_re_mcp.backends.ida.gate import (
    HeadlessGateResult,
    _last_json_line,
    run_idalib_gate,
)
from headless_re_mcp.config import Settings


class _FakeProcess:
    def __init__(
        self,
        stdout: str = "",
        stderr: str = "",
        returncode: int | None = 0,
        *,
        timeout_runs: int = 0,
        delay: float = 0.0,
    ) -> None:
        self.pid = 4242
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._timeout_runs = timeout_runs
        self._delay = delay

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        if self._delay:
            time.sleep(self._delay)
        if self._timeout_runs > 0:
            self._timeout_runs -= 1
            raise subprocess.TimeoutExpired(cmd="gate", timeout=timeout or 0.0)
        return self._stdout, self._stderr


def _settings(tmp_path: Path) -> Settings:
    ida_home = tmp_path / "IDA"
    ida_home.mkdir(exist_ok=True)
    return replace(Settings.load(), ida_home=ida_home)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
    *,
    windows: list[str] | None = None,
) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def fake_popen(command: list[str], **kwargs: Any) -> _FakeProcess:
        seen["command"] = command
        seen["env"] = kwargs.get("env")
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(gate_mod, "describe_process_windows", lambda pid: list(windows or []))
    monkeypatch.setattr(gate_mod, "terminate_process_tree", lambda proc: [proc.pid, proc.pid + 1])
    return seen


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return binary


def test_gate_refuses_to_run_without_an_ida_home(tmp_path: Path) -> None:
    settings = replace(Settings.load(), ida_home=None)
    with pytest.raises(RuntimeError, match="IDA home is not configured"):
        run_idalib_gate(_binary(tmp_path), settings)


def test_gate_reports_a_clean_worker_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    process = _FakeProcess(stdout='noise\n{"ok": true, "functions": 3}\n')
    seen = _install(monkeypatch, process)

    result = run_idalib_gate(_binary(tmp_path), settings, timeout=5.0)

    assert result.ok is True
    assert result.payload == {"ok": True, "functions": 3}
    assert result.exit_code == 0
    assert result.analyzer_windows == ()
    assert "--no-decompile" not in seen["command"]
    assert seen["env"]["PATH"].startswith(str(settings.ida_home))
    assert result.to_dict()["backend"] == "ida"
    assert result.to_dict()["analyzer_windows"] == []


def test_gate_passes_the_no_decompile_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install(monkeypatch, _FakeProcess(stdout='{"ok": true}\n'))

    run_idalib_gate(_binary(tmp_path), _settings(tmp_path), decompile=False)

    assert "--no-decompile" in seen["command"]


def test_gate_fails_when_the_worker_shows_a_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess(stdout='{"ok": true}\n', delay=0.05)
    _install(monkeypatch, process, windows=["IDA: licence"])
    monkeypatch.setattr(gate_mod, "_WINDOW_POLL_INTERVAL", 0.01)

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=5.0)

    assert result.ok is False
    assert result.analyzer_windows == ("IDA: licence",)


def test_gate_fails_on_a_nonzero_worker_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _FakeProcess(stdout="no json here\n", returncode=3))

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path))

    assert result.ok is False
    assert result.exit_code == 3
    assert result.payload == {"error": "worker returned no JSON object"}


def test_gate_normalizes_a_missing_return_code_to_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _FakeProcess(stdout='{"ok": false}\n', returncode=None))

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path))

    assert result.ok is False
    assert result.exit_code == 0


def test_gate_timeout_kills_the_tree_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess(stdout="partial", stderr="late", timeout_runs=1)
    _install(monkeypatch, process)

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=0.01)

    assert result.ok is False
    assert result.exit_code == -1
    assert "timed out after 0.01" in result.payload["error"]
    assert result.payload["killed_pids"] == [4242, 4243]
    assert (result.stdout, result.stderr) == ("partial", "late")


def test_gate_timeout_tolerates_an_undrainable_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess(timeout_runs=2)
    _install(monkeypatch, process)

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=0.01)

    assert result.ok is False
    assert (result.stdout, result.stderr) == ("", "")


def test_last_json_line_takes_the_newest_object() -> None:
    text = '{"first": 1}\nnot json\n[1, 2]\n{"second": 2}\n'
    assert _last_json_line(text) == {"second": 2}


def test_last_json_line_skips_non_object_json() -> None:
    assert _last_json_line('{"kept": true}\n[1]\n"str"\n') == {"kept": True}


def test_last_json_line_reports_a_silent_worker() -> None:
    assert _last_json_line("") == {"error": "worker returned no JSON object"}


def test_result_to_dict_round_trips_every_field() -> None:
    result = HeadlessGateResult(
        ok=True,
        backend="ida",
        payload={"ok": True},
        exit_code=0,
        stdout="out",
        stderr="err",
        analyzer_windows=("a",),
    )
    assert result.to_dict() == {
        "ok": True,
        "backend": "ida",
        "payload": {"ok": True},
        "exit_code": 0,
        "stdout": "out",
        "stderr": "err",
        "analyzer_windows": ["a"],
    }
