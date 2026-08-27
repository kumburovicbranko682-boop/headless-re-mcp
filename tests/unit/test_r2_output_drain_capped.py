"""r2.run must say when output_bytes is only a floor, not the true size.

run() bounds r2's stdout twice: run_bounded reads at most an 8 MiB drain buffer,
then run() keeps the first 1 MiB as `raw`. The 1 MiB cut is reported via
truncated/output_bytes/returned_bytes. But when r2 emits more than the 8 MiB
drain buffer, completed.stdout is that buffer and completed.stdout_truncated is
set -- so output_bytes (len of what we captured) is a floor, not the total.
Without a signal, a caller reads the 8 MiB cap as the whole output. These pin
that run() now flags that case as output_bytes_capped, and only that case.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import _MAX_OUTPUT, R2Client


def _run_with(monkeypatch: pytest.MonkeyPatch, completed: Completed) -> None:
    monkeypatch.setattr(r2_client, "run_bounded", lambda *a, **k: completed)


def test_output_bytes_is_flagged_as_a_floor_when_the_drain_buffer_was_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run_with(
        monkeypatch,
        Completed(
            returncode=0,
            stdout=b"X" * (_MAX_OUTPUT + 40),
            stderr=b"",
            stdout_truncated=True,
        ),
    )
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)

    payload = R2Client(Path(sys.executable)).run(binary, ["i"])

    assert payload["truncated"] is True
    assert payload["output_bytes_capped"] is True
    # output_bytes stays what we captured; the flag says it is a lower bound.
    assert payload["output_bytes"] == _MAX_OUTPUT + 40
    assert payload["returned_bytes"] == _MAX_OUTPUT


def test_no_floor_flag_when_output_fits_the_drain_buffer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordinary 1 MiB cut (drain buffer not exceeded) must not gain the flag."""
    _run_with(
        monkeypatch,
        Completed(
            returncode=0,
            stdout=b"X" * (_MAX_OUTPUT + 40),
            stderr=b"",
            stdout_truncated=False,
        ),
    )
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)

    payload = R2Client(Path(sys.executable)).run(binary, ["i"])

    assert payload["truncated"] is True
    assert "output_bytes_capped" not in payload
    assert payload["output_bytes"] == _MAX_OUTPUT + 40
