"""A verbose tool used to dump its whole stdout into the service process."""

from __future__ import annotations

import sys

from headless_re_mcp.backends.common.bounded_run import run_bounded


class TestRunBoundedDoesNotKeepTheWholeStream:
    """communicate() used to hold every byte until the caller sliced.

    Measured: 20 MiB stdout, run_bounded returned 20 MiB, RSS +38 MiB --
    so a verbose JVM log became a process-lifetime leak before Ghidra or
    r2 applied their own caps.
    """

    def test_a_large_stdout_is_capped_and_counted(self) -> None:
        payload = 2 * 1024 * 1024
        cap = 64 * 1024
        completed = run_bounded(
            [sys.executable, "-c", f"import sys; sys.stdout.buffer.write(b'x' * {payload})"],
            timeout=10.0,
            max_output=cap,
        )
        assert len(completed.stdout) == cap
        assert completed.stdout_bytes == payload
        assert completed.truncated is True
        assert completed.stdout == b"x" * cap

    def test_a_short_stdout_is_kept_whole(self) -> None:
        completed = run_bounded(
            [sys.executable, "-c", "import sys; print('done'); sys.exit(3)"],
            timeout=10.0,
            max_output=64 * 1024,
        )
        assert completed.returncode == 3
        assert completed.stdout.strip() == b"done"
        assert completed.truncated is False
        assert completed.stdout_bytes == len(completed.stdout)
