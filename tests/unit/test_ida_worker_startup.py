"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import _DATABASE_IN_USE, _open_database_error


def test_a_database_held_elsewhere_is_named_and_marked_retryable() -> None:
    """Code 4 was reported as a bare number and as permanent.

    Measured with two processes cycling one fixture, 40 of 50 opens failed this
    way, and none did when the same cycles ran one after another. batch.analyze
    opens up to eight static sessions at once, so the collision is something the
    surface invites rather than an accident.
    """
    error = _open_database_error(_DATABASE_IN_USE, Path(r"C:\samples\packed.exe"))

    assert "packed.exe" in str(error), "the caller has to know which sample"
    assert "already open in another process" in str(error)
    assert getattr(error, "retryable", False) is True


def test_any_other_open_failure_keeps_its_code_and_stays_permanent() -> None:
    """Only the one condition proven transient is described as transient."""
    error = _open_database_error(1, Path("sample.exe"))

    assert "code 1" in str(error), "an unclassified failure must still name its code"
    assert getattr(error, "retryable", False) is False


def test_the_worker_envelope_carries_retryable_through_to_the_client() -> None:
    """The flag is only useful if it survives the hop out of the worker."""
    payload = {
        "code": "worker_start_failed",
        "message": "RuntimeError: the IDA database for packed.exe is already open",
        "details": {},
        "retryable": True,
    }

    parsed = IdaWorkerError.from_payload(payload)

    assert parsed.code == "worker_start_failed"
    assert parsed.retryable is True


def test_terminating_ida_kills_the_whole_process_tree(tmp_path: Path) -> None:
    """IDA terminate used to kill only the launcher; the child stayed."""
    import os
    import subprocess
    import sys
    import time
    from contextlib import suppress

    from headless_re_mcp.backends.ida.client import IdaWorkerClient

    script = tmp_path / "sleeper.py"
    script.write_text(
        "import subprocess, sys\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "print(c.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    parent = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        text=True,
    )
    child_pid = int(parent.stdout.readline().strip())

    def _alive(pid: int) -> bool:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                return fh.read().split()[2] != "Z"
        except FileNotFoundError:
            return False

    assert _alive(parent.pid)
    assert _alive(child_pid)

    client = object.__new__(IdaWorkerClient)
    client._process = parent
    client._closed = False
    client.terminate()
    time.sleep(0.2)
    assert parent.poll() is not None
    assert not _alive(child_pid), f"child {child_pid} still alive after IDA terminate"
    with suppress(OSError):
        os.kill(child_pid, 9)
