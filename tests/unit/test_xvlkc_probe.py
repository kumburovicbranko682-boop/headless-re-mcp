"""XVLKC capability probe must not leave what a launcher started."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from headless_re_mcp.unpack.xvlkc import probe_xvlkc


def _alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _launcher(tmp_path: Path) -> tuple[Path, Path]:
    body = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "Path(__file__).with_suffix('.child').write_text(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n"
    )
    script = tmp_path / "xvlkc_launcher.py"
    marker = script.with_suffix(".child")
    if os.name == "nt":
        script.write_text(body, encoding="utf-8")
        wrapper = tmp_path / "xvlkc.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper, marker
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return script, marker


def test_a_timeout_kills_what_the_probe_started(tmp_path: Path) -> None:
    """Measured: 0.5s timeout returned False while the child was still alive."""
    stub, marker = _launcher(tmp_path)
    child = 0
    try:
        ok, output = probe_xvlkc(stub, timeout=0.5)
        assert ok is False
        assert output == ""

        deadline = time.monotonic() + 3.0
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.is_file(), "the launcher never reported the child it started"
        child = int(marker.read_text().strip())
        while _alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _alive(child) is False, "the launcher's child outlived the probe"
    finally:
        if child and _alive(child):
            os.kill(child, 9)


def test_a_probe_that_prints_usage_is_ready(tmp_path: Path) -> None:
    if os.name == "nt":
        stub = tmp_path / "xvlkc.cmd"
        stub.write_text("@echo off\r\necho XVLKC usage\r\n", encoding="utf-8")
    else:
        stub = tmp_path / "xvlkc"
        stub.write_text(
            "#!/usr/bin/env python3\nimport sys\nprint('XVLKC usage')\nsys.exit(0)\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
    ok, output = probe_xvlkc(stub, timeout=5.0)
    assert ok is True
    assert "usage" in output.casefold()
