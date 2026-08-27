"""Pure jsre listing/guard helpers, pinned without webcrack or wabt.

Three helpers shape what the JS/WASM line reports or admits, yet had thin or no
direct coverage:

* ``_capped_file_listing`` bounds ``js.unpack_bundle``'s directory listing on
  two axes -- the returned name count (``cap``) and the total files walked
  (``_MAX_COUNTED_FILES``) -- and its ``has_more`` flag is how an agent learns
  the listing was clipped. A listing that filled the cap yet reported
  ``has_more`` false would tell the agent it saw every unpacked file.
* ``_looks_like_wasm`` sniffs the four-byte magic; the magic yes/no cases are
  pinned elsewhere, but the unreadable-path branch (which must be False, not a
  crash) was not.
* ``_require_existing_file`` is the size/existence guard every jsre tool runs
  before handing the file to a child process.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as jsre
from headless_re_mcp.backends.common.bounded_run import InvalidTimeout, TimedOut
from headless_re_mcp.backends.jsre.client import (
    JsReError,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _run,
)


def test_listing_returns_sorted_relative_names_within_the_cap(tmp_path: Path) -> None:
    for name in ("b.js", "a.js", "c.js"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(tmp_path, cap=10)
    assert names == ["a.js", "b.js", "c.js"]
    assert total == 3
    assert has_more is False


def test_listing_caps_the_names_but_counts_all_and_flags_has_more(tmp_path: Path) -> None:
    """More files than the name cap: total still counts them all and has_more
    fires, so a caller knows the returned names are a clipped view."""
    for index in range(5):
        (tmp_path / f"f{index}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(tmp_path, cap=2)
    assert len(names) == 2
    assert names == sorted(names)
    assert total == 5
    assert has_more is True


def test_listing_of_a_non_directory_is_empty(tmp_path: Path) -> None:
    regular = tmp_path / "file.bin"
    regular.write_text("x", encoding="utf-8")
    assert _capped_file_listing(regular, cap=10) == ([], 0, False)


def test_listing_of_a_missing_root_is_empty(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "does-not-exist", cap=10) == ([], 0, False)


def test_listing_counts_only_files_and_reports_nested_paths(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.js").write_text("x", encoding="utf-8")
    (tmp_path / "top.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(tmp_path, cap=10)
    # The "sub" directory itself is not counted; both files are, nested one by
    # its path relative to the root.
    assert total == 2
    assert set(names) == {"top.js", str(Path("sub") / "nested.js")}
    assert has_more is False


def test_listing_stops_and_flags_has_more_at_the_walk_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the total hits _MAX_COUNTED_FILES the walk stops -- total never runs
    past the ceiling, and has_more says there was more to count."""
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_COUNTED_FILES", 2)
    for index in range(4):
        (tmp_path / f"f{index}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(tmp_path, cap=10)
    assert total == 2
    assert has_more is True


def test_looks_like_wasm_is_false_for_an_unreadable_path(tmp_path: Path) -> None:
    """A directory cannot be opened as a file: the OSError must read as
    not-wasm, not escape as a crash."""
    directory = tmp_path / "a-directory"
    directory.mkdir()
    assert _looks_like_wasm(directory) is False


def test_require_existing_file_refuses_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        _require_existing_file(tmp_path / "nope.js", missing="input not found")
    assert info.value.code == "not_found"


def test_require_existing_file_returns_a_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "in.js"
    target.write_text("var a=1;", encoding="utf-8")
    assert _require_existing_file(target, missing="m") == target.expanduser()


def test_require_existing_file_refuses_an_oversized_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file past the byte cap is refused up front with the measured size and
    the cap, rather than being streamed into the child process."""
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 4)
    target = tmp_path / "big.js"
    target.write_bytes(b"x" * 100)
    with pytest.raises(JsReError) as info:
        _require_existing_file(target, missing="m")
    assert info.value.code == "too_large"
    assert info.value.details["size"] == 100
    assert info.value.details["max_file_size"] == 4


def test_run_maps_an_invalid_timeout_to_invalid_params(monkeypatch: pytest.MonkeyPatch) -> None:
    def _bad_clamp(timeout: float, *, maximum: float) -> float:
        raise InvalidTimeout("timeout must be positive")

    monkeypatch.setattr(jsre, "clamp_cli_timeout", _bad_clamp)
    with pytest.raises(JsReError) as info:
        _run(["webcrack", "x"], timeout=-1)
    assert info.value.code == "invalid_params"


def test_run_maps_a_deadline_to_timeout_and_carries_the_killed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A node child that outran its deadline surfaces as a timeout, and the pids
    the launcher had to kill travel back so the failure is not silent."""
    monkeypatch.setattr(jsre, "clamp_cli_timeout", lambda timeout, *, maximum: timeout)

    def _times_out(cmd: list[str], *, timeout: float, creationflags: int = 0) -> object:
        raise TimedOut(timeout, [4321])

    monkeypatch.setattr(jsre, "run_bounded", _times_out)
    with pytest.raises(JsReError) as info:
        _run(["webcrack", "x"], timeout=5)
    assert info.value.code == "timeout"
    assert info.value.details["killed_pids"] == [4321]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing/unlaunchable binary is a backend_error, not an uncaught OSError."""
    monkeypatch.setattr(jsre, "clamp_cli_timeout", lambda timeout, *, maximum: timeout)

    def _cannot_launch(cmd: list[str], *, timeout: float, creationflags: int = 0) -> object:
        raise OSError("No such file or directory")

    monkeypatch.setattr(jsre, "run_bounded", _cannot_launch)
    with pytest.raises(JsReError) as info:
        _run(["missing-binary"], timeout=5)
    assert info.value.code == "backend_error"
