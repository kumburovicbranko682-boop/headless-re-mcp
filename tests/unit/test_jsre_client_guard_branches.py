"""Guard, listing and discovery branches of the webcrack / wabt adapter.

The existing jsre tests pin the non-zero-exit signalling, the unpack listing
schema and the input caps. This file fills in the branches those step over:
the capped file listing (non-dir root, directory entries, both ceilings), the
missing / unstatable input guards, the wasm-magic probe on an unreadable path,
the bounded-run timeout and launch-failure translation, the no-output failure
wraps on unpack_bundle / wasm.wat / wasm.info, and the wabt ``bin/`` fallback.
Each test pins one branch; nothing real is spawned -- ``run_bounded`` or the
module-level ``_run`` is faked at the seam.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.jsre import client as jsremod
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
)

_WABT_EXE_SUFFIX = ".exe" if os.name == "nt" else ""


def _wabt_dir(tmp_path: Path) -> Path:
    wabt = tmp_path / "wabt"
    wabt.mkdir()
    (wabt / f"wasm2wat{_WABT_EXE_SUFFIX}").write_text("x", encoding="utf-8")
    (wabt / f"wasm-objdump{_WABT_EXE_SUFFIX}").write_text("x", encoding="utf-8")
    return wabt


def _wasm(tmp_path: Path) -> Path:
    path = tmp_path / "module.wasm"
    path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return path


# ---------------------------------------------------------------------------
# _capped_file_listing.
# ---------------------------------------------------------------------------
def test_capped_listing_returns_empty_for_a_non_dir_root(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "absent", cap=10) == ([], 0, False)


def test_capped_listing_counts_files_not_directories(tmp_path: Path) -> None:
    root = tmp_path / "r"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "chunk.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(root, cap=10)
    assert names == [str(Path("sub") / "chunk.js")]
    assert total == 1
    assert has_more is False


def test_capped_listing_marks_names_beyond_the_cap(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    for i in range(3):
        (root / f"m{i}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(root, cap=2)
    assert len(names) == 2
    assert total == 3
    assert has_more is True


def test_capped_listing_stops_at_the_counted_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsremod, "_MAX_COUNTED_FILES", 2)
    root = tmp_path / "r"
    root.mkdir()
    for i in range(3):
        (root / f"m{i}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(root, cap=100)
    assert total == 2
    assert has_more is True


# ---------------------------------------------------------------------------
# input guards.
# ---------------------------------------------------------------------------
def test_require_existing_file_reports_a_missing_input(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / "absent.js", missing="input file not found")
    assert caught.value.code == "not_found"


def test_require_existing_file_wraps_an_unstatable_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that passes is_file but fails stat is a structured backend error.

    The first stat (inside is_file) succeeds and the size probe's stat fails,
    modelling the file vanishing or a permission flip between the two calls.
    """
    target = tmp_path / "input.js"
    target.write_text("x", encoding="utf-8")
    real_stat = Path.stat
    seen = {"count": 0}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "input.js":
            seen["count"] += 1
            if seen["count"] > 1:
                raise OSError("stat denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    with pytest.raises(JsReError) as caught:
        _require_existing_file(target, missing="input file not found")
    assert caught.value.code == "backend_error"
    assert "input unreadable" in caught.value.message


def test_looks_like_wasm_is_false_for_an_unreadable_path(tmp_path: Path) -> None:
    assert _looks_like_wasm(tmp_path / "absent.wasm") is False


# ---------------------------------------------------------------------------
# _run translation.
# ---------------------------------------------------------------------------
def test_run_reports_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [99])

    monkeypatch.setattr(jsremod, "run_bounded", fake_run)
    with pytest.raises(JsReError) as caught:
        jsremod._run(["webcrack", "app.js"], timeout=5.0)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [99]


def test_run_wraps_a_launch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("not executable")

    monkeypatch.setattr(jsremod, "run_bounded", fake_run)
    with pytest.raises(JsReError) as caught:
        jsremod._run(["webcrack", "app.js"], timeout=5.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch webcrack" in caught.value.message


# ---------------------------------------------------------------------------
# no-output failures.
# ---------------------------------------------------------------------------
def test_unpack_bundle_fails_when_nothing_was_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = tmp_path / "webcrack"
    tool.write_text("x", encoding="utf-8")
    src = tmp_path / "bundle.js"
    src.write_text("x", encoding="utf-8")
    monkeypatch.setattr(jsremod, "_run", lambda cmd, **k: ("", "fatal: bad bundle", 1))
    with pytest.raises(JsReError) as caught:
        JsClient(tool).unpack_bundle(src, tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "webcrack unpack failed"
    assert caught.value.details["exit_code"] == 1


def test_wat_fails_when_wasm2wat_printed_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = WasmClient(wabt=_wabt_dir(tmp_path))
    monkeypatch.setattr(jsremod, "_run", lambda cmd, **k: ("", "parse error", 1))
    with pytest.raises(JsReError) as caught:
        client.wat(_wasm(tmp_path))
    assert caught.value.code == "backend_error"
    assert caught.value.message == "wasm2wat failed"


def test_info_fails_when_objdump_printed_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = WasmClient(wabt=_wabt_dir(tmp_path))
    monkeypatch.setattr(jsremod, "_run", lambda cmd, **k: ("", "section error", 1))
    with pytest.raises(JsReError) as caught:
        client.info(_wasm(tmp_path))
    assert caught.value.code == "backend_error"
    assert caught.value.message == "wasm-objdump failed"


# ---------------------------------------------------------------------------
# wabt discovery.
# ---------------------------------------------------------------------------
def test_resolve_wabt_tool_falls_back_to_the_bin_directory(tmp_path: Path) -> None:
    wabt = tmp_path / "wabt"
    (wabt / "bin").mkdir(parents=True)
    exe = wabt / "bin" / f"wasm2wat{_WABT_EXE_SUFFIX}"
    exe.write_text("x", encoding="utf-8")
    assert _resolve_wabt_tool(wabt, "wasm2wat") == exe
