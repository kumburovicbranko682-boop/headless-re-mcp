"""js.unpack_bundle must hand webcrack a directory it can create itself.

webcrack creates its ``-o`` directory and refuses to run if it already exists,
even when empty ("output directory already exists", exit 1). The client used to
``mkdir(exist_ok=True)`` that directory before launching webcrack, so every
unpack aborted and the capability never once succeeded with the real tool. These
tests pin the corrected contract with a stand-in that mimics webcrack's
refuse-if-exists behaviour, so a re-introduced pre-creation fails here instead of
only in the (tool-gated) live gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError


def _webcrack_like(existed_when_run: list[bool]):
    """A fake _run that behaves like webcrack: refuse a pre-existing -o dir."""

    def fake_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
        del timeout, maximum
        out_dir = Path(cmd[cmd.index("-o") + 1])
        existed_when_run.append(out_dir.exists())
        if out_dir.exists():
            return "", "output directory already exists\n", 1
        out_dir.mkdir(parents=True)
        (out_dir / "deobfuscated.js").write_text("x = 1;\n", encoding="utf-8")
        return "", "", 0

    return fake_run


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "app.js"
    bundle.write_text("const a = 1;\n", encoding="utf-8")
    return bundle


def test_target_directory_is_absent_when_webcrack_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The -o directory must not exist yet, or webcrack refuses to run."""
    seen: list[bool] = []
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like(seen))
    client = JsClient(executable=Path("/bin/true"))

    result = client.unpack_bundle(_bundle(tmp_path), tmp_path / "out", limit=10)

    assert seen == [False], "webcrack saw a pre-existing -o directory"
    assert "tool_failed" not in result
    assert result["file_count"] == 1
    assert result["files"] == ["deobfuscated.js"]


def test_a_leftover_empty_directory_is_cleared_so_a_retry_can_proceed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty tree from a failed run must not permanently block reuse."""
    seen: list[bool] = []
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like(seen))
    client = JsClient(executable=Path("/bin/true"))
    out = tmp_path / "out"
    out.mkdir()

    result = client.unpack_bundle(_bundle(tmp_path), out, limit=10)

    assert seen == [False], "the empty leftover directory was not cleared"
    assert "tool_failed" not in result
    assert result["file_count"] == 1


def test_a_non_empty_directory_is_left_for_webcrack_and_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Files an analyst placed in the target survive: no delete, no overwrite."""
    seen: list[bool] = []
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like(seen))
    client = JsClient(executable=Path("/bin/true"))
    out = tmp_path / "out"
    out.mkdir()
    sentinel = out / "analyst.txt"
    sentinel.write_text("keep me", encoding="utf-8")

    result = client.unpack_bundle(_bundle(tmp_path), out, limit=10)

    # webcrack saw the populated directory and refused; the client did not
    # pre-empt that by deleting it.
    assert seen == [True]
    assert sentinel.read_text(encoding="utf-8") == "keep me"
    assert result["tool_failed"] is True
    assert result["exit_code"] == 1


def test_unpack_raises_when_webcrack_refuses_and_nothing_is_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal that leaves no readable output is surfaced as a backend error."""

    def refuse(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
        del cmd, timeout, maximum
        return "", "output directory already exists\n", 1

    monkeypatch.setattr(jsre_client, "_run", refuse)
    client = JsClient(executable=Path("/bin/true"))

    with pytest.raises(JsReError) as excinfo:
        client.unpack_bundle(_bundle(tmp_path), tmp_path / "out", limit=10)
    assert excinfo.value.code == "backend_error"
