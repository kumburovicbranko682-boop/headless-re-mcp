"""js.unpack_bundle must not pre-create webcrack's output directory.

webcrack creates its ``-o`` directory itself and aborts with "output directory
already exists" if it is already there -- even when empty. The client used to
run ``out_dir.mkdir(parents=True, exist_ok=True)`` right before launching
webcrack, so every unpack failed and the whole bundle-splitting capability
never once produced a file. These tests pin the corrected contract:

* a fresh (non-existent) target is handed to webcrack untouched;
* a leftover *empty* directory from a failed run is cleared so a retry works;
* a *non-empty* directory is left intact -- webcrack refuses it and the client
  never silently overwrites files an analyst placed there.

They drive the real ``unpack_bundle`` with a stand-in for ``_run`` that behaves
like webcrack: it fails when the directory already exists and is non-empty, and
otherwise creates the directory and writes a module -- so a regression that
re-adds the ``mkdir`` turns the fresh-path test red.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError


def _webcrack_like(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
    """Mimic webcrack's -o contract: refuse an existing non-empty dir."""
    del timeout, maximum
    out_dir = Path(cmd[cmd.index("-o") + 1])
    if out_dir.exists() and any(out_dir.iterdir()):
        return "", "output directory already exists", 1
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "deobfuscated.js").write_text("console.log(1);\n", encoding="utf-8")
    return "", "", 0


def _client() -> JsClient:
    # A real path so the "webcrack configured" guard passes; _run is patched.
    return JsClient(executable=Path("/bin/true"))


def test_fresh_target_is_created_by_the_tool_not_pre_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression guard: pre-creating out_dir made webcrack abort."""
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like)
    bundle = tmp_path / "app.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out = tmp_path / "unpacked"
    assert not out.exists()

    payload = _client().unpack_bundle(bundle, out, offset=0, limit=10)

    assert "tool_failed" not in payload
    assert payload["file_count"] == 1
    assert payload["files"] == ["deobfuscated.js"]
    assert (out / "deobfuscated.js").is_file()


def test_a_leftover_empty_directory_is_cleared_so_a_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like)
    bundle = tmp_path / "app.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out = tmp_path / "unpacked"
    out.mkdir()  # an earlier run created it then failed before writing anything
    assert out.is_dir() and not any(out.iterdir())

    payload = _client().unpack_bundle(bundle, out, offset=0, limit=10)

    assert "tool_failed" not in payload
    assert payload["file_count"] == 1
    assert (out / "deobfuscated.js").is_file()


def test_a_non_empty_directory_is_left_for_the_tool_to_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never clobber an analyst's files: a non-empty target is preserved."""
    monkeypatch.setattr(jsre_client, "_run", _webcrack_like)
    bundle = tmp_path / "app.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out = tmp_path / "unpacked"
    out.mkdir()
    keep = out / "analyst-notes.txt"
    keep.write_text("do not delete", encoding="utf-8")

    payload = _client().unpack_bundle(bundle, out, offset=0, limit=10)

    # webcrack refused; the client surfaces that rather than overwriting.
    assert payload["tool_failed"] is True
    assert payload["exit_code"] == 1
    assert keep.read_text(encoding="utf-8") == "do not delete"


def test_a_non_empty_dir_with_no_output_and_no_files_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the tool fails and nothing is listable, it is a hard error.

    A refusal on a directory holding only a non-listing artefact (an empty
    subdir) leaves the listing empty *and* the exit nonzero, which must raise
    rather than return a hollow success.
    """

    def always_refuse(
        cmd: list[str], *, timeout: float, maximum: float = 0.0
    ) -> tuple[str, str, int]:
        del cmd, timeout, maximum
        return "", "output directory already exists", 1

    monkeypatch.setattr(jsre_client, "_run", always_refuse)
    bundle = tmp_path / "app.js"
    bundle.write_text("var a=1;", encoding="utf-8")
    out = tmp_path / "unpacked"
    out.mkdir()
    (out / "sub").mkdir()  # only a directory, so the file listing stays empty

    with pytest.raises(JsReError) as caught:
        _client().unpack_bundle(bundle, out, offset=0, limit=10)
    assert caught.value.code == "backend_error"
