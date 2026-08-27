"""The debugger gates must not keep unbounded child output in memory.

Both gates used bare ``communicate()``, which keeps every byte the child
writes: the idalib gate runs idalib against the sample under analysis for up
to 300 s, so a hostile sample that makes idalib flood diagnostics ballooned
the gate's memory without limit. ``drain_capped`` keeps the head of each
stream under a hard cap. These tests shrink the cap and flood from a fake
child to prove the bound, that a verdict printed early still lands, that a
sample's invalid UTF-8 no longer crashes the idalib gate mid-read, and that
the stdin command feed and timeout tree-kill survived the rewrite.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import drain_capped
from headless_re_mcp.backends.ida import gate as ida_gate_mod
from headless_re_mcp.backends.ida.gate import run_idalib_gate
from headless_re_mcp.backends.x64dbg import gate as xdbg_gate_mod
from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture

_CAP = 64 * 1024
_FLOOD_CHARS = 4 * _CAP


def _patch_first_popen(monkeypatch: Any, module: Any, script: str) -> None:
    """Replace the gate's child with a fake script, keeping the gate's kwargs."""
    real_popen = subprocess.Popen
    seen = {"first": True}

    def fake_popen(cmd: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        if seen["first"]:
            seen["first"] = False
            return real_popen([sys.executable, "-c", script], **kwargs)
        return real_popen(cmd, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)


def _ida_settings(tmp_path: Path) -> tuple[Path, Settings]:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    fake_ida = tmp_path / "IDA"
    fake_ida.mkdir()
    return binary, replace(Settings.load(), ida_home=fake_ida)


def test_idalib_gate_flood_is_capped_and_fails_closed(tmp_path: Path, monkeypatch: Any) -> None:
    """A worker flooding stdout past the cap is truncated, not accumulated.

    The verdict JSON is the last line, so a flood that pushes it past the cap
    must read as "worker returned no JSON object" with the truncation named --
    not as a success and not as gigabytes held in memory.
    """
    binary, settings = _ida_settings(tmp_path)
    monkeypatch.setattr(ida_gate_mod, "_GATE_MAX_OUTPUT", _CAP)
    script = (
        "import sys\n"
        f"sys.stdout.write('A' * {_FLOOD_CHARS})\n"
        "sys.stdout.write('\\n{\"ok\": true}\\n')\n"
    )
    _patch_first_popen(monkeypatch, ida_gate_mod, script)

    result = run_idalib_gate(binary, settings, timeout=30.0)

    assert result.ok is False
    assert len(result.stdout) <= _CAP
    assert result.payload["stdout_truncated"] is True
    assert result.payload["error"] == "worker returned no JSON object"


def test_idalib_gate_survives_invalid_utf8_from_sample(tmp_path: Path, monkeypatch: Any) -> None:
    """Bytes echoed from a hostile sample must not crash the gate mid-read.

    The idalib gate opened its pipes with text=True and strict decoding, so a
    single invalid UTF-8 sequence raised UnicodeDecodeError out of the drain
    (the x64dbg gate already passed errors="replace").
    """
    binary, settings = _ida_settings(tmp_path)
    script = (
        "import sys\n"
        "sys.stdout.buffer.write(b'\\xff\\xfe garbage from sample\\n')\n"
        "sys.stdout.buffer.write(b'{\"ok\": true}\\n')\n"
    )
    _patch_first_popen(monkeypatch, ida_gate_mod, script)

    result = run_idalib_gate(binary, settings, timeout=30.0)

    assert result.payload.get("ok") is True
    assert "\ufffd" in result.stdout


def test_xdbg_gate_flood_is_capped_and_early_marker_still_counts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The stdin command feed works and a later flood cannot grow memory.

    The fake executable blocks on stdin until the gate's "state\\nexit\\n"
    arrives (proving input delivery), prints the command-loop marker, then
    floods. Head-keep means the early marker still yields ok=True while the
    flood is dropped past the cap and reported as truncated.
    """
    exe = tmp_path / "headless.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(xdbg_gate_mod, "detect_pe_architecture", lambda path: Architecture.X64)
    monkeypatch.setattr(xdbg_gate_mod, "_GATE_MAX_OUTPUT", _CAP)
    script = (
        "import sys\n"
        "commands = sys.stdin.read()\n"
        "assert 'exit' in commands\n"
        "sys.stdout.write('[headless] entering command loop\\n')\n"
        f"sys.stdout.write('B' * {_FLOOD_CHARS})\n"
    )
    _patch_first_popen(monkeypatch, xdbg_gate_mod, script)

    result = run_command_loop_gate(exe, Architecture.X64, timeout=30.0)

    assert result.ok is True
    assert result.command_loop_seen is True
    assert len(result.stdout) <= _CAP
    assert result.stdout_truncated is True
    assert result.stderr_truncated is False


def test_drain_capped_timeout_kills_and_returns_partial_output() -> None:
    """A child that outruns its deadline is killed, keeping what it printed."""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys, time\nprint('early diagnostics', flush=True)\ntime.sleep(60)\n",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    io = drain_capped(process, timeout=1.0)
    elapsed = time.monotonic() - started

    assert io.timed_out is True
    assert io.killed, "the timed-out child must be in the killed list"
    assert "early diagnostics" in io.stdout
    assert elapsed < 15.0, f"timeout cleanup hung for {elapsed:.1f}s"
    assert process.poll() is not None
