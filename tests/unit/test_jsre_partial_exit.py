"""webcrack/wabt must say when they exited non-zero but still produced output.

Both CLIs are on the "return what we got" path: ``_run`` only fails hard when
the exit is non-zero *and* nothing came back, so a partial run (webcrack emits
what it managed; wasm2wat/wasm-objdump bail on a later section after writing
earlier ones) otherwise looked identical to a clean pass. These pin the
``tool_failed`` flag -- the same one jadx raises for its partial decompiles -- on
deobfuscate/unpack_bundle/wat/info with a mocked ``_run``; no real tool needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, WasmClient


def _make_input(tmp_path: Path) -> Path:
    src = tmp_path / "input.bin"
    src.write_text("payload", encoding="utf-8")
    return src


def test_deobfuscate_flags_a_nonzero_exit_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        return "deobfuscated();", "1 warning emitted", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    result = client.deobfuscate(_make_input(tmp_path))
    assert result["code"] == "deobfuscated();"
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1
    assert result["stderr"] == "1 warning emitted"


def test_deobfuscate_clean_run_has_no_tool_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        return "clean();", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    result = client.deobfuscate(_make_input(tmp_path))
    assert result["code"] == "clean();"
    assert "tool_failed" not in result
    assert "exit_code" not in result


def test_unpack_bundle_flags_a_nonzero_exit_that_still_wrote_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        out_dir = Path(cmd[cmd.index("-o") + 1])
        (out_dir / "deobfuscated.js").write_text("x", encoding="utf-8")
        return "", "bundle only partly unpacked", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    result = client.unpack_bundle(_make_input(tmp_path), tmp_path / "out")
    # Files landed, so it is not a hard failure -- but the caller must learn the
    # unpack was partial rather than read the file list as complete.
    assert result["file_count"] == 1
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1
    assert result["stderr"] == "bundle only partly unpacked"


def test_wat_flags_a_nonzero_exit_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        return "(module)", "error: unknown section, stopped early", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = WasmClient()
    client._wasm2wat = Path("/bin/true")
    result = client.wat(_make_input(tmp_path))
    assert result["wat"] == "(module)"
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1


def test_info_flags_a_nonzero_exit_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        return "Sections:\n Type", "error: truncated Code section", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = WasmClient()
    client._objdump = Path("/bin/true")
    result = client.info(_make_input(tmp_path))
    assert "Sections" in result["objdump"]
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1


def test_wat_clean_run_has_no_tool_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        return "(module (func))", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = WasmClient()
    client._wasm2wat = Path("/bin/true")
    result = client.wat(_make_input(tmp_path))
    assert "module" in result["wat"]
    assert "tool_failed" not in result
