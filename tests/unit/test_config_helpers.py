"""Configuration helpers must degrade to safe defaults, never raise on load.

These cover the platform-specific discovery branches (idalib names, IDA/x64dbg
install probing) and the tolerant parsers (``_as_int``/``_as_command``) that
turn an operator typo or a stale path into a fallback rather than a failed
server start. The host tools are absent, so filesystem layouts are synthesised
under ``tmp_path`` and ``os.name``/``sys.platform`` are pinned per case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.config as config
from headless_re_mcp.config import (
    _as_command,
    _as_int,
    _ida_config_home,
    discover_x64dbg_headless,
    discover_x64dbg_source,
    find_ida_executable,
    ida_library_names,
    list_ida_install_candidates,
    update_config_values,
    validate_ida_home,
)

# --------------------------------------------------------------------------
# idalib runtime names per platform
# --------------------------------------------------------------------------


def test_ida_library_names_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "nt")
    assert ida_library_names() == ("idalib.dll",)


def test_ida_library_names_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    monkeypatch.setattr("headless_re_mcp.config.sys.platform", "darwin")
    assert ida_library_names() == ("libidalib.dylib", "idalib.dylib")


def test_ida_library_names_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    monkeypatch.setattr("headless_re_mcp.config.sys.platform", "linux")
    assert ida_library_names() == ("libidalib.so", "idalib.so")


# --------------------------------------------------------------------------
# IDA executable / install discovery
# --------------------------------------------------------------------------


def test_find_ida_executable_returns_a_present_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    (tmp_path / "ida").write_text("#!/bin/sh\n", encoding="utf-8")
    assert find_ida_executable(tmp_path) == tmp_path / "ida"


def test_find_ida_executable_returns_none_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    assert find_ida_executable(tmp_path) is None


def test_list_ida_install_candidates_scans_linux_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    monkeypatch.setattr("headless_re_mcp.config.sys.platform", "linux")
    # No config-home candidate; discovery falls back to /opt and the home root.
    monkeypatch.setattr(config, "_ida_config_home", lambda: None)

    home = tmp_path / "home"
    usable = home / "idapro-9.1"
    usable.mkdir(parents=True)
    (usable / "libidalib.so").write_text("", encoding="utf-8")
    # A same-root install without the runtime must be ignored, not returned.
    (home / "ida-8.4").mkdir()

    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))

    candidates = list_ida_install_candidates()

    assert usable.resolve() in candidates
    assert (home / "ida-8.4").resolve() not in candidates


def test_list_ida_install_candidates_skips_missing_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    monkeypatch.setattr("headless_re_mcp.config.sys.platform", "linux")
    monkeypatch.setattr(config, "_ida_config_home", lambda: None)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "nonexistent"))

    candidates = list_ida_install_candidates()

    assert isinstance(candidates, list)
    assert all(tmp_path not in candidate.parents for candidate in candidates)


# --------------------------------------------------------------------------
# validate_ida_home
# --------------------------------------------------------------------------


def test_validate_ida_home_rejects_an_empty_path() -> None:
    result = validate_ida_home("")
    assert result["ok"] is False and result["code"] == "empty_path"


def test_validate_ida_home_rejects_a_non_directory(tmp_path: Path) -> None:
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    result = validate_ida_home(target)
    assert result["ok"] is False and result["code"] == "not_a_directory"


def test_validate_ida_home_reports_missing_idalib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    monkeypatch.setattr("headless_re_mcp.config.sys.platform", "linux")
    result = validate_ida_home(tmp_path)
    assert result["ok"] is False and result["code"] == "idalib_missing"


# --------------------------------------------------------------------------
# x64dbg discovery
# --------------------------------------------------------------------------


def test_discover_x64dbg_source_finds_cwd_upstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    headless = tmp_path / "upstream" / "x64dbg" / "src" / "headless" / "headless.cpp"
    headless.parent.mkdir(parents=True)
    headless.write_text("int main(){}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert discover_x64dbg_source() == (tmp_path / "upstream" / "x64dbg").resolve()


def test_discover_x64dbg_headless_rejects_unknown_architecture() -> None:
    assert discover_x64dbg_headless("arm64") is None


# --------------------------------------------------------------------------
# _ida_config_home (Windows-only)
# --------------------------------------------------------------------------


def test_ida_config_home_is_none_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "posix")
    assert _ida_config_home() is None


def test_ida_config_home_needs_appdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.config.os.name", "nt")
    monkeypatch.delenv("APPDATA", raising=False)
    assert _ida_config_home() is None


# --------------------------------------------------------------------------
# update_config_values
# --------------------------------------------------------------------------


def test_update_config_values_writes_and_merges(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    update_config_values({"ida_home": tmp_path / "ida"}, config_path=path)
    reopened = update_config_values({"ida_home": None, "profile": "pe"}, config_path=path)
    assert reopened == path
    assert path.is_file()


def test_update_config_values_wraps_a_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")

    def boom(_path: Path) -> dict[str, object]:
        raise OSError("permission denied")

    monkeypatch.setattr(config, "_read_json_object", boom)
    with pytest.raises(OSError, match="could not read existing config"):
        update_config_values({"profile": "pe"}, config_path=path)


# --------------------------------------------------------------------------
# tolerant scalar/command parsers
# --------------------------------------------------------------------------


def test_as_command_splits_a_string_default() -> None:
    assert _as_command(None, "pwsh -NoProfile") == ("pwsh", "-NoProfile")


def test_as_command_returns_empty_for_an_unusable_default() -> None:
    assert _as_command(None, 123) == ()


def test_as_command_reads_a_list_default() -> None:
    assert _as_command(None, ["a", "", "b"]) == ("a", "b")


def test_as_int_falls_back_on_unreadable_values() -> None:
    assert _as_int("not-a-number", "also-bad", fallback=7) == 7


def test_as_int_reads_a_valid_value() -> None:
    assert _as_int("42", None) == 42
