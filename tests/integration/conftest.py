"""Bridge config.json into the environment variables the gates read.

Most gates decide whether to run by looking only at ``HEADLESS_RE_*`` environment
variables, so a machine configured through ``config.json`` skipped them even with
every backend installed. Exporting the resolved settings keeps "skip != pass"
meaningful: a skip should mean the backend is genuinely missing, not that the
configuration lives in a file instead of the environment.

Existing environment variables always win, so a caller can still force a gate to
skip or point it somewhere else.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# One integration run per machine. idalib opens a binary in place, so a sample
# has exactly one database and a second process asking for it is refused --
# measured with two runs of this suite against the same fixtures, most opens
# failed and the failures landed on whichever gates happened to overlap.
# The path is inside the checkout so two runs of the same tree agree on it
# without either being configured.
_GATE_LOCK = _PROJECT_ROOT / ".pytest-integration.lock"
_LOCK_WAIT_S = 1800.0
_LOCK_POLL_S = 2.0
# Held as a lease rather than a pid: os.kill(pid, 0) returns normally for a dead
# process on Windows, so it cannot tell a crashed holder from a live one. The
# holder touches the file while it runs and a lock nobody has touched recently
# is abandoned, which needs nothing from the operating system either way.
_LEASE_REFRESH_S = 10.0
_LEASE_STALE_S = 60.0
_WINDOWS_ONLY_MODULES = frozenset(
    {
        "test_address_sync.py",
        "test_composite_tools_gate.py",
        "test_crackme_serial_e2e_gate.py",
        "test_exeinfope_gate.py",
        "test_hidden_desktop_gate.py",
        "test_m4_unload_dump_gate.py",
        "test_m5_unpack_live_gate.py",
        "test_m9_condition_breakpoint_gate.py",
        "test_m9_dynamic_ext_gate.py",
        "test_m9_target_exit_fail_closed_gate.py",
        "test_m9_trace_quota_artifact_gate.py",
        "test_m10_ui_backends_gate.py",
        "test_m10_ui_drive_breakpoint_gate.py",
        "test_m10_ui_drive_gate.py",
        "test_m10_ui_interact_gate.py",
        "test_m10_ui_pid_gate.py",
        "test_m11_frida_live_gate.py",
        "test_m11_windbg_live_gate.py",
        "test_m12_persist_gate.py",
        "test_mcp_dynamic_xdbg.py",
        "test_unpack_live_gate.py",
        "test_workflow_xdbg.py",
        "test_xdbg_headless_gate.py",
        "test_xdbg_rpc.py",
    }
)

_PATH_SETTINGS = {
    "HEADLESS_RE_X64DBG_HEADLESS_X64": "x64dbg_headless_x64",
    "HEADLESS_RE_X64DBG_HEADLESS_X86": "x64dbg_headless_x86",
    "HEADLESS_RE_X64DBG_SOURCE": "x64dbg_source",
    "HEADLESS_RE_IDA_HOME": "ida_home",
    "HEADLESS_RE_DIEC": "diec",
    "HEADLESS_RE_EXEINFOPE": "exeinfope",
    "HEADLESS_RE_UPX": "upx",
    "HEADLESS_RE_DE4DOT": "de4dot",
    "HEADLESS_RE_NET_REACTOR_SLAYER": "net_reactor_slayer",
    "HEADLESS_RE_XVLKC": "xvlkc",
    "HEADLESS_RE_VMP_DUMPER": "vmp_dumper",
    "HEADLESS_RE_SCYLLA": "scylla",
    "HEADLESS_RE_R2": "r2",
    "HEADLESS_RE_GHIDRA_HOME": "ghidra_home",
    "HEADLESS_RE_CDB": "cdb",
}


def _default_ida_gate_binary() -> None:
    """Give the idalib gates a target instead of skipping for want of a path."""
    if os.environ.get("HEADLESS_RE_IDA_GATE_BINARY"):
        return
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if fixture.is_file():
        os.environ["HEADLESS_RE_IDA_GATE_BINARY"] = str(fixture)


def pytest_configure() -> None:
    try:
        settings = Settings.load()
    except Exception:  # noqa: BLE001 - never block collection on config problems
        return
    for variable, attribute in _PATH_SETTINGS.items():
        if os.environ.get(variable):
            continue
        value = getattr(settings, attribute, None)
        if value:
            os.environ[variable] = str(value)
    _default_ida_gate_binary()


def _lease_is_stale(lock: Path) -> bool:
    """True when nobody has touched the lock recently enough to still hold it."""
    try:
        return (time.time() - lock.stat().st_mtime) > _LEASE_STALE_S
    except OSError:
        return True  # gone between the failed create and this call


def _acquire_gate_lock() -> bool:
    """Take the lock, or give up waiting and say so."""
    deadline = time.monotonic() + _LOCK_WAIT_S
    while True:
        try:
            handle = os.open(_GATE_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if _lease_is_stale(_GATE_LOCK):
                with suppress(OSError):
                    _GATE_LOCK.unlink()
                continue
            if time.monotonic() >= deadline:
                # Run anyway rather than fail for a reason nobody caused. The
                # collisions this avoids are visible in the report; a suite that
                # never ran is not.
                print(f"\n[gate-lock] still held after {_LOCK_WAIT_S:g}s, running anyway")
                return False
            time.sleep(_LOCK_POLL_S)
            continue
        except OSError:
            return False  # cannot create it at all, which is not a reason to refuse
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps({"pid": os.getpid(), "started_at": time.time()}))
        return True


@pytest.fixture(scope="session", autouse=True)
def _one_integration_run_at_a_time() -> Iterator[None]:
    """Serialise whole suites, because they contend for the same IDA databases.

    idalib opens a binary in place, so two runs over the same fixtures refuse
    each other instead of queueing. The failures land on whichever gates
    happened to overlap, so they move between runs and read as flake rather
    than as a collision.

    Waiting is bounded and the lease expires on its own: this must never be the
    reason a suite does not finish.
    """
    held = _acquire_gate_lock()
    stop = threading.Event()

    def keep_alive() -> None:
        # A crashed run cannot clean up after itself, so holding is something
        # the holder has to keep doing rather than something it declares once.
        while not stop.wait(_LEASE_REFRESH_S):
            try:
                os.utime(_GATE_LOCK, None)
            except OSError:
                return

    keeper: threading.Thread | None = None
    if held:
        keeper = threading.Thread(target=keep_alive, name="gate-lock-lease", daemon=True)
        keeper.start()
    try:
        yield
    finally:
        stop.set()
        if keeper is not None:
            keeper.join(timeout=_LEASE_REFRESH_S + 5.0)
        if held:
            with suppress(OSError):
                _GATE_LOCK.unlink()


def _hidden_desktop_is_on() -> bool:
    override = os.environ.get("HEADLESS_RE_HIDDEN_DESKTOP")
    if override is not None:
        return override.strip().lower() in {"1", "true", "yes", "on"}
    try:
        return bool(Settings.load().hidden_desktop)
    except Exception:  # noqa: BLE001 - never block collection on config problems
        return False


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip window-driving gates when the session runs on a hidden desktop.

    Those gates enumerate and click windows on the desktop the test process
    owns. Under hidden_desktop the debuggee's windows are on a separate Win32
    desktop object, so the gates find nothing and fail with "window not
    observed" -- which reads like a broken debugger rather than a
    configuration that put the windows somewhere else.

    It matters because hidden_desktop is what an unattended deployment runs,
    so the suite was unrunnable in its own production configuration without
    nine confusing failures. A skip that names the variable says which of the
    two the operator is looking at.
    """
    if os.name != "nt":
        windows_skip = pytest.mark.skip(
            reason=(
                "Windows-only integration gate: requires x64dbg/WinDbg/Win32 UI "
                "or a Windows-native fixture"
            )
        )
        for item in items:
            if Path(str(item.path)).name in _WINDOWS_ONLY_MODULES:
                item.add_marker(pytest.mark.windows_only)
                item.add_marker(windows_skip)

    if not _hidden_desktop_is_on():
        return
    skip = pytest.mark.skip(
        reason="HEADLESS_RE_HIDDEN_DESKTOP is on; this gate drives windows on the "
        "visible desktop. Unset it to run these."
    )
    for item in items:
        if "visible_desktop" in item.keywords:
            item.add_marker(skip)
