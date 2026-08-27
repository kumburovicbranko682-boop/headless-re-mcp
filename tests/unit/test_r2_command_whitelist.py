from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


@pytest.mark.parametrize(
    "command",
    [
        "pdj 1 @ 0;!echo escaped",
        "pdj 1 @ 0\n!echo escaped",
        "pdj 1 @ 0|!echo escaped",
        "pdj 1 @ `!echo escaped`",
        "axj @ 0 && !echo escaped",
        "axtj @ 0 && !echo escaped",
        "axtj",
        "axtj 0x1000",
        "axffj @ 0 && !echo escaped",
        "axffj",
        "axffj 0x1000",
        "i anything",
        "pdj 513 @ 0",
    ],
)
def test_r2_whitelist_rejects_composed_commands_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, [command])

    assert launched == []


def test_r2_whitelist_keeps_bounded_disasm_and_xref_forms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(
        binary,
        ["pdj 32 @ 4198400", "axj @ 0x401000", "axtj @ 0x401150", "axffj @ 0x4011b0"],
    )

    assert result["commands"] == [
        "pdj 32 @ 4198400",
        "axj @ 0x401000",
        "axtj @ 0x401150",
        "axffj @ 0x4011b0",
    ]
    assert len(launched) == 1
