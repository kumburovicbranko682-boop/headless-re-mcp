"""r2.run used to hide the stream cap behind len(stdout)."""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.r2.client as r2_mod
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client


class TestR2RunReportsTheStreamCap:
    """The 1 MiB run_bounded keep used to look like the listing ended.

    Measured: 5000000-byte stdout, keep 1 MiB, no truncated -- so a
    caller reading raw thinks radare2 printed only the retained prefix.
    """

    def test_the_true_log_length_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "t.exe"
        binary.write_bytes(b"MZ")
        stub = tmp_path / "r2"
        stub.write_bytes(b"")
        monkeypatch.setattr(
            r2_mod,
            "run_bounded",
            lambda *args, **kwargs: Completed(
                0, b"A" * 1_000_000, b"", stdout_bytes=5_000_000, truncated=True
            ),
        )
        result = R2Client(stub).run(binary, ["i"])
        assert result["truncated"] is True
        assert result["output_bytes"] == 5_000_000
        assert result["returned_bytes"] == 1_000_000
        assert len(result["raw"]) == 1_000_000
