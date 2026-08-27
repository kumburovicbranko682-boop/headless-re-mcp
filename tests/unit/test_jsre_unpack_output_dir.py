"""js.unpack_bundle must hand webcrack a directory it can create itself.

webcrack owns its ``-o`` directory: it creates it and aborts with "output
directory already exists" if the path is already there, even when the directory
is empty. unpack_bundle used to ``mkdir(out_dir, exist_ok=True)`` before
launching webcrack, so the tool bailed every single time and the bundle-unpack
capability never worked. These pin the fix: ensure only the parent exists, leave
the target for webcrack to create, and clear an empty leftover from a re-used
path (while leaving a non-empty directory for webcrack to refuse rather than
silently overwriting an analyst's files).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre.client import JsClient


def _webcrack_that_refuses_existing_dirs(cmd: list[str], **_kwargs: Any) -> Completed:
    """Stand in for the real webcrack: refuse an existing -o, else write output."""
    target = Path(cmd[cmd.index("-o") + 1])
    if target.exists():
        return Completed(1, b"", b"output directory already exists")
    target.mkdir(parents=True)
    (target / "deobfuscated.js").write_text("// clean", encoding="utf-8")
    return Completed(0, b"", b"")


def test_unpack_bundle_does_not_precreate_the_output_dir(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    # The parent does not exist yet either: the client must create the parent but
    # not the target directory webcrack insists on creating.
    out = tmp_path / "jsre" / "unpack-abc123"

    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        _webcrack_that_refuses_existing_dirs,
    ):
        payload = JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    assert payload["file_count"] == 1
    assert payload["files"] == ["deobfuscated.js"]
    assert "tool_failed" not in payload
    assert Path(payload["output_dir"]) == out


def test_unpack_bundle_clears_an_empty_leftover_output_dir(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "unpack-reused"
    out.mkdir()  # an empty directory left by a prior aborted run

    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        _webcrack_that_refuses_existing_dirs,
    ):
        payload = JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    assert payload["files"] == ["deobfuscated.js"]
    assert "tool_failed" not in payload


def test_unpack_bundle_leaves_a_nonempty_output_dir_for_webcrack_to_refuse(
    tmp_path: Path,
) -> None:
    """A directory with files is not cleared: webcrack's refusal must stand.

    Clearing it would let the client silently overwrite whatever an analyst had
    already put there. So a non-empty target is left in place; webcrack aborts,
    and because the pre-existing files make the listing non-empty the client
    surfaces that abort as tool_failed rather than raising.
    """
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "unpack-has-files"
    out.mkdir()
    (out / "keep.js").write_text("do not clobber", encoding="utf-8")

    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        _webcrack_that_refuses_existing_dirs,
    ):
        payload = JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    # The analyst's file is untouched and webcrack's abort is surfaced honestly.
    assert (out / "keep.js").read_text(encoding="utf-8") == "do not clobber"
    assert payload["tool_failed"] is True
    assert payload["exit_code"] == 1
