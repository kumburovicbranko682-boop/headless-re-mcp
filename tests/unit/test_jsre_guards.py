"""jsre guards: the unpack hard-failure line, wabt resolution, and shared helpers.

webcrack and wabt both exit non-zero on partial work while still producing
usable output, so the adapter only fails hard when nothing landed -- the same
partial-vs-hard rule the deobfuscate/wat/info paths follow, but on the
unpack_bundle branch, which the paging tests only ever drove with a clean exit.
The rest cover the shared input/resolution helpers that decide whether a tool is
launched at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
)


def _bundle(tmp_path: Path) -> Path:
    path = tmp_path / "app.js"
    path.write_text("bundle", encoding="utf-8")
    return path


def test_unpack_bundle_fails_hard_only_when_nothing_landed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero webcrack exit that wrote no files is a real failure.

    webcrack exits non-zero for benign reasons, so the adapter cannot treat exit
    code alone as failure -- but an exit that also produced no output is a
    genuine backend_error, carrying the exit code and bounded stderr, rather than
    an empty success the caller reads as "this bundle unpacked to nothing".
    """
    def fake_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
        del cmd, timeout, maximum
        return "", "boom", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as caught:
        client.unpack_bundle(_bundle(tmp_path), tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_unpack_bundle_keeps_a_partial_tree_despite_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero exit that still emitted files is kept, flagged, not discarded.

    This is the other half of the guard: when webcrack chokes on some modules but
    writes the rest, throwing away the whole tree would lose real work. The files
    are returned and the non-zero exit is surfaced so the partial run is not read
    as a clean one.
    """
    def fake_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
        del timeout, maximum
        out_dir = Path(cmd[cmd.index("-o") + 1])
        (out_dir / "mod.js").write_text("x", encoding="utf-8")
        return "", "partial", 1

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    result = client.unpack_bundle(_bundle(tmp_path), tmp_path / "out")
    assert result["file_count"] == 1
    assert result["exit_code"] == 1
    assert result["tool_failed"] is True


def test_resolve_wabt_tool_finds_a_tool_under_the_bin_directory(tmp_path: Path) -> None:
    """A wabt path pointing at the install root resolves the tool under bin/.

    Operators point HEADLESS_RE_WABT at either the exact binary or the unpacked
    wabt directory; the latter keeps its tools in bin/, so the resolver must fall
    back there rather than reporting wabt unavailable for a perfectly good
    install.
    """
    exe = "wasm2wat.exe" if jsre_client.os.name == "nt" else "wasm2wat"
    tool = tmp_path / "wabt" / "bin" / exe
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"")
    assert _resolve_wabt_tool(tmp_path / "wabt", "wasm2wat") == tool


def test_require_existing_file_reports_a_missing_input_as_not_found(tmp_path: Path) -> None:
    """A path that is not a file is refused up front, before any child launch.

    Handing a nonexistent path to the subprocess would bind the child on input
    it can never read; the guard reports not_found naming the resolved path
    instead.
    """
    missing = tmp_path / "gone.js"
    with pytest.raises(JsReError) as caught:
        _require_existing_file(missing, missing="input file not found")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_looks_like_wasm_is_false_when_the_path_cannot_be_read(tmp_path: Path) -> None:
    """An unreadable path is not a module, and the magic check must not raise.

    _looks_like_wasm gates wat/info; if opening the path raises (a directory,
    a vanished file, a permissions fault) it has to answer False so the caller
    reports a clean invalid_params, not an internal_error from the probe itself.
    """
    directory = tmp_path / "adir"
    directory.mkdir()
    assert _looks_like_wasm(directory) is False


def test_capped_file_listing_caps_names_independently_of_the_total(tmp_path: Path) -> None:
    """The name list is capped separately from the count, and says it truncated.

    With more files than the name cap but fewer than the hard count cap, the walk
    lists cap names, still counts them all, and reports has_more -- so a caller
    paging the list knows there is more than the page shows.
    """
    for index in range(4):
        (tmp_path / f"m{index}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(tmp_path, cap=2)
    assert len(names) == 2
    assert total == 4
    assert has_more is True


def test_capped_file_listing_ignores_a_missing_root_and_glob_directories(
    tmp_path: Path,
) -> None:
    """A missing root lists nothing, and a directory matching the walk is skipped.

    unpack summarises even when webcrack wrote nothing, so a missing output root
    must answer empty rather than raise; and a subdirectory (rglob('*') yields
    directories too) must not be counted as an extracted file.
    """
    assert _capped_file_listing(tmp_path / "absent", cap=10) == ([], 0, False)
    (tmp_path / "real.js").write_text("x", encoding="utf-8")
    (tmp_path / "subdir").mkdir()
    names, total, has_more = _capped_file_listing(tmp_path, cap=10)
    assert names == ["real.js"]
    assert total == 1
    assert has_more is False
