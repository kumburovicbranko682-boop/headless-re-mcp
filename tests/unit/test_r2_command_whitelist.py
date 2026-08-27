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
    result = client.run(binary, ["pdj 32 @ 4198400", "axj @ 0x401000"])

    assert result["commands"] == ["pdj 32 @ 4198400", "axj @ 0x401000"]
    assert len(launched) == 1


def test_r2_xrefs_uses_the_address_scoped_axtj_not_the_global_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """r2.xrefs must query axtj @ addr (refs *to* addr), never bare axj.

    axj ignores the seek and dumps the binary's whole ref table, so the old
    command made the address argument a no-op. Pin the scoped form here so a
    revert cannot silently reintroduce the global dump.
    """
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    client.xrefs(binary, 0x401000)

    assert len(launched) == 1
    script = launched[0][launched[0].index("-c") + 1]
    assert "axtj @ 4198400" in script, script
    assert "axj @" not in script, script


def test_r2_whitelist_admits_scoped_axtj_and_axfj(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    # Both scoped ref forms are read-only and allow-listed.
    assert client.run(binary, ["axtj @ 0x401000"])["commands"] == ["axtj @ 0x401000"]
    assert client.run(binary, ["axfj @ 0x401000"])["commands"] == ["axfj @ 0x401000"]
    # A composed axtj is still rejected before launch.
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, ["axtj @ 0 ; !echo escaped"])
