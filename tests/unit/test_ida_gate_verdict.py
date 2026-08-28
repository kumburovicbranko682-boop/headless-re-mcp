"""The idalib gate's verdict logic, driven end to end without IDA.

``run_idalib_gate`` launches ``sys.executable -m ...gate_worker`` and turns the
worker's last JSON line, exit code and any observed analyzer windows into one
verdict. Its only test asserts Win32 descendant enumeration and skips off
Windows, so none of this ran on a hosted platform. Swapping ``sys.executable``
for a tiny shell script drives the real machinery -- Popen, the window-monitor
thread, communicate, the timeout kill of the worker tree -- and pins the
verdict contract: a clean JSON ``ok`` passes, a missing JSON object or a
non-zero exit refuses, and a hung worker is killed and reported, not waited on.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.ida.gate import (
    HeadlessGateResult,
    _last_json_line,
    run_idalib_gate,
)
from headless_re_mcp.config import Settings

posix_only = pytest.mark.skipif(os.name == "nt", reason="the fake worker is a /bin/sh script")


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=tmp_path / "ida",
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _fake_worker(tmp_path: Path, body: str) -> Path:
    """Replace the gate's worker interpreter with a shell script."""
    script = tmp_path / "fake_python"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return script


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ fake")
    return path


def test_a_missing_ida_home_is_refused_before_any_launch(tmp_path: Path) -> None:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    with pytest.raises(RuntimeError, match="IDA home"):
        run_idalib_gate(_binary(tmp_path), settings, timeout=5)


@posix_only
def test_a_clean_json_verdict_passes_and_sees_the_ida_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The worker prints preamble noise, its PATH (which must have ida_home
    # prepended), then the verdict object the gate must pick out.
    script = _fake_worker(
        tmp_path,
        'echo "ida preamble noise"\necho "$PATH" >&2\necho \'{"ok": true, "functions": 3}\'\n',
    )
    monkeypatch.setattr(sys, "executable", str(script))

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=10, decompile=False)

    assert result.ok is True
    assert result.exit_code == 0
    assert result.payload["functions"] == 3
    assert result.analyzer_windows == ()
    assert str(tmp_path / "ida") in result.stderr
    assert result.to_dict()["payload"]["ok"] is True


@posix_only
def test_a_worker_that_prints_no_json_object_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _fake_worker(tmp_path, 'echo "analysis went fine, promise"\n')
    monkeypatch.setattr(sys, "executable", str(script))

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=10)

    assert result.ok is False
    assert result.exit_code == 0
    assert result.payload == {"error": "worker returned no JSON object"}


@posix_only
def test_a_nonzero_exit_refuses_even_with_an_ok_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The worker crashed after printing success: the exit code wins.
    script = _fake_worker(tmp_path, "echo '{\"ok\": true}'\nexit 3\n")
    monkeypatch.setattr(sys, "executable", str(script))

    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=10)

    assert result.ok is False
    assert result.exit_code == 3
    assert result.payload == {"ok": True}


@posix_only
def test_a_hung_worker_is_killed_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _fake_worker(tmp_path, "sleep 60\n")
    monkeypatch.setattr(sys, "executable", str(script))

    started = time.monotonic()
    result = run_idalib_gate(_binary(tmp_path), _settings(tmp_path), timeout=0.5)
    elapsed = time.monotonic() - started

    assert result.ok is False
    assert result.exit_code == -1
    assert "timed out" in result.payload["error"]
    assert isinstance(result.payload["killed_pids"], list)
    # The gate returned promptly after the kill, not after the worker's sleep.
    assert elapsed < 15


def test_last_json_line_takes_the_last_object_and_skips_noise() -> None:
    text = "\n".join(
        [
            "loading type libraries...",
            "[1, 2, 3]",  # valid JSON but not an object
            '{"ok": false, "stage": "early"}',
            '{"ok": true, "stage": "final"}',
        ]
    )
    assert _last_json_line(text) == {"ok": True, "stage": "final"}
    assert _last_json_line("") == {"error": "worker returned no JSON object"}
    assert _last_json_line("not json at all") == {"error": "worker returned no JSON object"}
    # A trailing non-object JSON line (array) is skipped so the last object wins.
    assert _last_json_line('{"ok": true}\n[1, 2, 3]') == {"ok": True}


def test_gate_result_to_dict_lists_windows() -> None:
    result = HeadlessGateResult(
        ok=False,
        backend="ida",
        payload={"error": "x"},
        exit_code=2,
        stdout="",
        stderr="",
        analyzer_windows=("0x1:IdaWindow:About",),
    )
    dumped = result.to_dict()
    assert dumped["analyzer_windows"] == ["0x1:IdaWindow:About"]
    assert dumped["exit_code"] == 2
