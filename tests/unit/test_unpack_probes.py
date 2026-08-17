"""Doctor leftover unpacker probes used subprocess.run; a launcher left children."""

from __future__ import annotations

import inspect
import os
import time
from contextlib import suppress
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.de4dot import probe_de4dot_version
from headless_re_mcp.dotnet.net_reactor_slayer import probe_net_reactor_slayer
from headless_re_mcp.unpack.scylla import probe_scylla
from headless_re_mcp.unpack.vmp_dumper import probe_vmp_dumper
from headless_re_mcp.unpack.xvlkc import probe_xvlkc


def _launcher(tmp_path: Path, name: str) -> tuple[Path, Path]:
    marker = tmp_path / f"{name}.pid"
    launcher = tmp_path / name
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"Path({str(marker)!r}).write_text(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    return launcher, marker


def _kill_child(marker: Path) -> None:
    if marker.is_file():
        with suppress(OSError, ValueError):
            os.kill(int(marker.read_text()), 9)


def test_the_leftover_probes_bind_what_they_start() -> None:
    for fn in (
        probe_xvlkc,
        probe_scylla,
        probe_vmp_dumper,
        probe_net_reactor_slayer,
        probe_de4dot_version,
    ):
        assert "run_bounded" in inspect.getsource(fn)


def test_a_probe_that_finishes_still_reports_the_banner(tmp_path: Path) -> None:
    if os.name == "nt":
        exe = tmp_path / "xvlkc.cmd"
        exe.write_text("@echo xvlkc usage unpack input\n", encoding="utf-8")
    else:
        exe = tmp_path / "xvlkc"
        exe.write_text(
            "#!/usr/bin/env python3\nprint('xvlkc usage unpack input')\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)
    ok, text = probe_xvlkc(exe, timeout=2.0)
    assert ok is True
    assert "xvlkc" in text.casefold()


def test_a_real_xvlkc_timeout_returns_instead_of_waiting_out_the_child(
    tmp_path: Path,
) -> None:
    """Doctor and unpack.cli start these probes. Killing only the launcher leaves the tool.

    Measured against a launcher that starts a sleeper: a 1s deadline returned
    in 1.002s and the child was still running.
    """
    if os.name == "nt":
        pytest.skip("probe argv is the file itself; a shebang launcher is POSIX")
    launcher, marker = _launcher(tmp_path, "xvlkc")
    started = time.monotonic()
    try:
        ok, text = probe_xvlkc(launcher, timeout=0.8)
        elapsed = time.monotonic() - started
        assert ok is False
        assert text == ""
        assert elapsed < 10.0
    finally:
        _kill_child(marker)


def test_scylla_still_counts_a_start_that_never_exits_as_ready(tmp_path: Path) -> None:
    """GUI Scylla often never exits; that is not the same as available.

    The tree still has to be bound. Measured: 1.002s, ok=False,
    text=timeout_after_start, child gone.
    """
    if os.name == "nt":
        pytest.skip("probe argv is the file itself; a shebang launcher is POSIX")
    launcher, marker = _launcher(tmp_path, "scylla")
    started = time.monotonic()
    try:
        ok, text = probe_scylla(launcher, timeout=0.8)
        elapsed = time.monotonic() - started
        assert ok is False
        assert text == "timeout_after_start"
        assert elapsed < 10.0
    finally:
        _kill_child(marker)


def test_de4dot_does_not_call_a_hung_binary_ready(tmp_path: Path) -> None:
    """Three argv variants, each timing out, used to return True with empty text.

    Measured: 3.006s for a 1s deadline, ok=True, child still running. Doctor
    then reported the optional deobfuscator READY.
    """
    if os.name == "nt":
        pytest.skip("probe argv is the file itself; a shebang launcher is POSIX")
    launcher, marker = _launcher(tmp_path, "de4dot")
    started = time.monotonic()
    try:
        ok, text = probe_de4dot_version(launcher, timeout=0.8)
        elapsed = time.monotonic() - started
        assert ok is False
        assert text == ""
        assert elapsed < 10.0
    finally:
        _kill_child(marker)
