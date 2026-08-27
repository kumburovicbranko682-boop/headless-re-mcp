"""Driver-side coverage for ``run_idalib_gate`` that does not need IDA or Win32.

The one existing gate test (``test_ida_gate_timeout``) is Win32-only and skips
everywhere else, so the launcher's own logic -- building the worker command,
draining stdout/stderr, classifying the run from the worker's last JSON line,
and the timeout kill -- went untested on Linux. None of that is Windows
specific: ``describe_process_windows`` returns an empty set off Windows and
``terminate_process_tree`` walks /proc, so the worker command is replaced with
a small stand-in Python process and the whole path runs here.
"""

from __future__ import annotations

import sys
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


def _run_with_script(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    script: str,
    *,
    timeout: float = 30.0,
    decompile: bool = True,
) -> HeadlessGateResult:
    """Run the gate against a stand-in worker that executes ``script``."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    ida_home = tmp_path / "IDA"
    ida_home.mkdir()
    settings = replace(Settings.load(), ida_home=ida_home)

    real_popen = gate_mod.subprocess.Popen

    def fake_popen(cmd: list[str], **kwargs: Any) -> Any:
        # Ignore the real worker command (it would import IDA) and run the
        # stand-in with the launcher's own pipe/env/creationflags kwargs.
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(gate_mod.subprocess, "Popen", fake_popen)
    return run_idalib_gate(binary, settings, timeout=timeout, decompile=decompile)


def test_a_missing_ida_home_is_refused_before_launching() -> None:
    settings = replace(Settings.load(), ida_home=None)
    with pytest.raises(RuntimeError, match="IDA home is not configured"):
        run_idalib_gate(Path("whatever.exe"), settings)


def test_a_clean_worker_run_is_reported_ok(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """returncode 0 + ``ok`` true + no analyzer windows means ok."""
    result = _run_with_script(
        monkeypatch,
        tmp_path,
        'import json; print(json.dumps({"ok": True, "functions": 3}))',
    )
    assert result.ok is True
    assert result.backend == "ida"
    assert result.exit_code == 0
    assert result.payload["functions"] == 3
    assert result.analyzer_windows == ()
    assert result.stderr == ""


def test_a_worker_that_fails_is_not_reported_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-zero exit is carried through and never counts as ok.

    Runs with ``decompile=False`` so the no-decompile arm of the command
    builder is exercised too (harmless here since the command is replaced).
    """
    result = _run_with_script(
        monkeypatch,
        tmp_path,
        'import json, sys; print(json.dumps({"ok": False, "error": "nope"})); sys.exit(2)',
        decompile=False,
    )
    assert result.ok is False
    assert result.exit_code == 2
    assert result.payload["error"] == "nope"


def test_a_worker_ok_flag_is_required_even_on_a_clean_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _run_with_script(
        monkeypatch,
        tmp_path,
        'import json; print(json.dumps({"ok": False}))',
    )
    assert result.exit_code == 0
    assert result.ok is False


def test_worker_output_without_a_json_object_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Plain text and a bare JSON array both fail to yield a result object."""
    result = _run_with_script(
        monkeypatch,
        tmp_path,
        'print("[1, 2, 3]"); print("plain progress text")',
    )
    assert result.ok is False
    assert result.payload == {"error": "worker returned no JSON object"}


def test_a_hung_worker_is_killed_and_reported_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """communicate() timing out kills the process tree and returns exit -1.

    The stand-in sleeps well past the deadline; the launcher must not hang on
    it (the whole point of the tree kill) and must surface the timeout as a
    non-ok result carrying the pids it killed.
    """
    result = _run_with_script(
        monkeypatch,
        tmp_path,
        "import time; time.sleep(30)",
        timeout=0.5,
    )
    assert result.ok is False
    assert result.exit_code == -1
    assert result.payload["error"].startswith("idalib gate timed out")
    assert isinstance(result.payload["killed_pids"], list)
    assert len(result.payload["killed_pids"]) >= 1


def test_result_to_dict_is_a_plain_serializable_mapping() -> None:
    result = HeadlessGateResult(
        ok=True,
        backend="ida",
        payload={"ok": True},
        exit_code=0,
        stdout="out",
        stderr="err",
        analyzer_windows=("0x1:Cls:Title",),
    )
    assert result.to_dict() == {
        "ok": True,
        "backend": "ida",
        "payload": {"ok": True},
        "exit_code": 0,
        "stdout": "out",
        "stderr": "err",
        "analyzer_windows": ["0x1:Cls:Title"],
    }


def test_last_json_line_prefers_the_final_object_and_skips_noise() -> None:
    text = '{"ok": false}\nprogress: 40%\n{"ok": true, "n": 9}\n'
    assert _last_json_line(text) == {"ok": True, "n": 9}


def test_last_json_line_reports_when_there_is_no_object() -> None:
    assert _last_json_line("no json here\n") == {"error": "worker returned no JSON object"}
