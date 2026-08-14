"""configure_ida must not report a failed idalib activation as success."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import activate_idalib, configure_ida


def test_failed_idalib_activation_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The installer treats ok as whether IDA is usable.

    Measured: activate_idalib returned ok=False and configure_ida still answered
    ok=True, saved=True. setup.py then skips InstallError and the supervised
    service starts; every later static.open fails for the rest of the night.
    """
    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    config_path = tmp_path / "user-config.json"

    monkeypatch.setattr(
        setup_mod,
        "activate_idalib",
        lambda home: {
            "ok": False,
            "code": "activation_failed",
            "message": "idalib did not activate",
        },
    )

    result = configure_ida(ida_home=fake_ida, activate=True, config_path=config_path)

    assert result["saved"] is True
    assert result["activation"]["ok"] is False
    assert result["ok"] is False, (
        f"activation failed but configure_ida answered ok={result.get('ok')!r}"
    )


def test_skipping_activation_still_reports_the_saved_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Saving the path without activating is a real success."""
    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    config_path = tmp_path / "user-config.json"
    monkeypatch.setattr(
        setup_mod,
        "activate_idalib",
        lambda home: (_ for _ in ()).throw(AssertionError("must not activate")),
    )
    result = configure_ida(ida_home=fake_ida, activate=False, config_path=config_path)
    assert result["ok"] is True
    assert result["saved"] is True
    assert result["activation"] is None


_LAUNCHER = (
    "import os, subprocess, sys, time\n"
    "flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0\n"
    "child = subprocess.Popen([sys.executable, '-c', "
    "'import time\\nwhile True: time.sleep(0.2)'], creationflags=flags)\n"
    "print(child.pid, flush=True)\n"
    "while True: time.sleep(0.2)\n"
)


def _pid_is_alive(pid: int) -> bool:
    import ctypes
    import os

    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def test_activation_timeout_kills_the_process_the_script_started(
    tmp_path: Path,
) -> None:
    """subprocess.run killed the script and then drained with no deadline.

    The child inherits the pipes, so that drain never sees EOF. Measured
    against this launcher: returning at all, with both pids dead, in under
    ten seconds is the bound; a hang here is the old behaviour.
    """
    import os
    import time

    if os.name != "nt":
        pytest.skip("descendant enumeration here is Win32 (skip != pass)")

    fake_ida = tmp_path / "IDA Professional 9.9"
    script_dir = fake_ida / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    (script_dir / "py-activate-idalib.py").write_text(_LAUNCHER, encoding="utf-8")

    started = time.monotonic()
    result = activate_idalib(fake_ida, timeout=0.8)
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"activation timeout hung for {elapsed:.1f}s"
    assert result["ok"] is False
    assert result["code"] == "timeout"
    killed = result["killed_pids"]
    assert len(killed) >= 2
    for pid in killed:
        assert _pid_is_alive(int(pid)) is False

