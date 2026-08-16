"""Native setup helpers: pip install must not hang the host."""

from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path

import pytest


def _load_bootstrap():
    root = Path(__file__).resolve().parents[2]
    path = root / "src" / "headless_re_mcp" / "native_app" / "bootstrap.py"
    spec = importlib.util.spec_from_file_location("headless_re_mcp_native_bootstrap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pip_install_editable_does_not_wait_forever(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """subprocess.run used to install with no deadline.

    Measured: run() was invoked with no timeout; a 0.8s sleep held
    pip_install_editable 0.8s. A wedged pip held setup forever.
    """
    boot = _load_bootstrap()
    monkeypatch.setattr(boot, "_PIP_INSTALL_TIMEOUT", 0.4)
    pid_path = tmp_path / "child.pid"
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    fake_python = tmp_path / "python"
    fake_python.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys\n"
        "if '-m' in sys.argv and 'pip' in sys.argv:\n"
        f"    child = subprocess.Popen([sys.executable, {str(sleeper)!r}])\n"
        f"    open({str(pid_path)!r}, 'a').write(str(child.pid) + '\\n')\n"
        "    import time; time.sleep(30)\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    monkeypatch.setattr(boot.sys, "executable", str(fake_python))
    t0 = time.monotonic()
    code = boot.pip_install_editable(tmp_path)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert code == 124
    assert pid_path.is_file()
    pids = [int(line) for line in pid_path.read_text().split() if line.strip()]
    assert pids
    deadline = time.monotonic() + 2.0
    alive = set(pids)
    while time.monotonic() < deadline and alive:
        remaining = set()
        for pid in alive:
            try:
                os.kill(pid, 0)
            except OSError:
                continue
            remaining.add(pid)
        alive = remaining
        if alive:
            time.sleep(0.05)
    assert alive == set(), f"pip install left orphans {sorted(alive)}"
