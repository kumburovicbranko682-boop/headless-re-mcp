"""Tool discovery and validation edges in ``config.py``.

These helpers decide which external binaries the server will load and execute
(idalib, x64dbg headless), so their guard rails matter: a wrong directory must
be rejected with a structured reason instead of being handed to a loader, and
discovery must only accept installs that actually carry the platform-native
runtime. Everything here is exercised against temp directories with the host
platform pinned via monkeypatch, so the same assertions run on every OS.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from headless_re_mcp import config
from headless_re_mcp.config import (
    _as_command,
    _as_float,
    _as_int,
    discover_ida_home,
    discover_x64dbg_headless,
    discover_x64dbg_source,
    find_ida_executable,
    ida_library_names,
    list_ida_install_candidates,
    update_config_values,
    validate_ida_home,
)


class _OsProxy:
    """A stand-in ``os`` module with a pinned ``name``.

    Patching ``os.name`` globally is not an option: since Python 3.12
    ``Path()`` dispatches on it at call time, so the whole test would suddenly
    build WindowsPath objects on Linux. The proxy pins what ``config`` reads
    and forwards everything else (``environ`` and friends) to the real module.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)


class _SysProxy:
    def __init__(self, platform: str) -> None:
        self.platform = platform

    def __getattr__(self, attr: str) -> object:
        return getattr(sys, attr)


def _pin_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "os", _OsProxy("nt"))


def _pin_posix(monkeypatch: pytest.MonkeyPatch, platform: str = "linux") -> None:
    monkeypatch.setattr(config, "os", _OsProxy("posix"))
    monkeypatch.setattr(config, "sys", _SysProxy(platform))


# ---------------------------------------------------------------------------
# idalib runtime names per host
# ---------------------------------------------------------------------------


def test_ida_library_names_follow_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_windows(monkeypatch)
    assert ida_library_names() == ("idalib.dll",)
    _pin_posix(monkeypatch, platform="darwin")
    assert ida_library_names() == ("libidalib.dylib", "idalib.dylib")
    _pin_posix(monkeypatch, platform="linux")
    assert ida_library_names() == ("libidalib.so", "idalib.so")


def test_find_ida_executable_reports_the_gui_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pin_posix(monkeypatch)
    assert find_ida_executable(tmp_path) is None
    gui = tmp_path / "ida64"
    gui.write_bytes(b"elf")
    assert find_ida_executable(tmp_path) == gui


# ---------------------------------------------------------------------------
# install discovery: only directories with the native runtime count
# ---------------------------------------------------------------------------


def test_windows_discovery_scans_program_files_and_dedupes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pin_windows(monkeypatch)
    # Both roots point at the same tree, so every install is seen twice and
    # must be reported once.
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    usable = tmp_path / "IDA Professional 9.1"
    usable.mkdir()
    (usable / "idalib.dll").write_bytes(b"dll")
    legacy = tmp_path / "Hex-Rays" / "IDA Pro 9.0"
    legacy.mkdir(parents=True)
    (legacy / "idalib.dll").write_bytes(b"dll")
    # An install without the runtime is a GUI-only layout and must not win.
    hollow = tmp_path / "IDA Professional 9.2"
    hollow.mkdir()
    found = list_ida_install_candidates()
    assert found == [usable.resolve(), legacy.resolve()]
    assert discover_ida_home() == usable.resolve()


def test_posix_discovery_scans_the_home_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pin_posix(monkeypatch)
    home = tmp_path / "home"
    install = home / "idapro-9.1"
    install.mkdir(parents=True)
    (install / "libidalib.so").write_bytes(b"so")
    empty = home / "ida-9.0"
    empty.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    found = list_ida_install_candidates()
    assert install.resolve() in found
    assert empty.resolve() not in found
    # A vanished home directory is skipped, not an error.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "gone"))
    assert install.resolve() not in list_ida_install_candidates()


def test_registered_windows_install_is_honoured_when_it_has_the_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pin_windows(monkeypatch)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "nowhere"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nowhere-x86"))
    install = tmp_path / "registered"
    install.mkdir()
    (install / "idalib.dll").write_bytes(b"dll")
    appdata = tmp_path / "appdata"
    registration = appdata / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    registration.parent.mkdir(parents=True)
    registration.write_text(
        json.dumps({"Paths": {"ida-install-dir": str(install)}}), encoding="utf-8"
    )
    monkeypatch.setenv("APPDATA", str(appdata))
    assert list_ida_install_candidates() == [install.resolve()]


def test_corrupt_windows_registration_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pin_windows(monkeypatch)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "nowhere"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nowhere-x86"))
    appdata = tmp_path / "appdata"
    registration = appdata / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    registration.parent.mkdir(parents=True)
    registration.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(appdata))
    # A corrupt registration file falls through to (empty) filesystem scan.
    assert list_ida_install_candidates() == []
    assert discover_ida_home() is None


def test_registered_install_without_the_runtime_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The registry says "IDA lives here" but the directory has no idalib:
    # a GUI-only install must not be handed to the idalib loader.
    _pin_windows(monkeypatch)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "nowhere"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nowhere-x86"))
    hollow = tmp_path / "gui-only"
    hollow.mkdir()
    appdata = tmp_path / "appdata"
    registration = appdata / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    registration.parent.mkdir(parents=True)
    registration.write_text(
        json.dumps({"Paths": {"ida-install-dir": str(hollow)}}), encoding="utf-8"
    )
    monkeypatch.setenv("APPDATA", str(appdata))
    assert list_ida_install_candidates() == []


# ---------------------------------------------------------------------------
# validate_ida_home: user-supplied paths get a structured verdict
# ---------------------------------------------------------------------------


def test_validate_ida_home_verdicts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _pin_posix(monkeypatch)
    assert validate_ida_home("")["code"] == "empty_path"
    missing = validate_ida_home(tmp_path / "nope")
    assert missing["code"] == "not_a_directory"
    hollow = validate_ida_home(tmp_path)
    assert hollow["ok"] is False
    assert hollow["code"] == "idalib_missing"
    # The verdict tells the operator what filename would have satisfied it.
    assert "libidalib.so" in hollow["expected_idalib_names"]
    (tmp_path / "libidalib.so").write_bytes(b"so")
    good = validate_ida_home(tmp_path)
    assert good["ok"] is True
    assert good["idalib"] == str(tmp_path / "libidalib.so")


# ---------------------------------------------------------------------------
# update_config_values: unreadable existing config fails loudly
# ---------------------------------------------------------------------------


def test_update_config_values_names_the_unreadable_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")

    def _denied(_path: Path) -> dict[str, object]:
        raise OSError("permission denied")

    monkeypatch.setattr(config, "_read_json_object", _denied)
    with pytest.raises(OSError, match="could not read existing config"):
        update_config_values({"key": "value"}, config_path=path)
    # The failed merge must not have clobbered the file.
    assert path.read_text(encoding="utf-8") == "{}"


# ---------------------------------------------------------------------------
# x64dbg discovery
# ---------------------------------------------------------------------------


def test_x64dbg_source_is_found_by_its_headless_entrypoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "upstream" / "x64dbg"
    entry = source / "src" / "headless" / "headless.cpp"
    entry.parent.mkdir(parents=True)
    entry.write_text("// entry", encoding="utf-8")
    monkeypatch.setattr(Path, "cwd", staticmethod(lambda: tmp_path))
    assert discover_x64dbg_source() == source.resolve()


def test_x64dbg_headless_refuses_an_unknown_architecture() -> None:
    assert discover_x64dbg_headless("arm64") is None
    assert discover_x64dbg_headless("") is None


def test_x64dbg_headless_is_found_under_the_packaged_layout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "external" / "x64dbg-x64" / "headless.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"mz")
    monkeypatch.setattr(config, "repo_root", lambda: tmp_path)
    # Architecture matching is case/space tolerant because it comes from
    # session metadata, not operator input.
    assert discover_x64dbg_headless(" X64 ") == binary.resolve()
    assert discover_x64dbg_headless("x86") is None


# ---------------------------------------------------------------------------
# tolerant setting readers
# ---------------------------------------------------------------------------


def test_as_command_splits_defaults_like_an_operator_would() -> None:
    # A JSON-string default is argv-split, an array default is already argv
    # (blank fragments dropped), and no configuration means no command.
    # Backslash handling is deliberately host-specific in _split_command, so
    # the fixture command stays slash-free to assert the same thing everywhere.
    assert _as_command(None, "pwsh -File revert.ps1") == ("pwsh", "-File", "revert.ps1")
    assert _as_command(None, ["pwsh", "", "-File"]) == ("pwsh", "-File")
    assert _as_command(None, None) == ()
    # An explicit env value always wins over the default.
    assert _as_command("echo ok", "pwsh -File revert.ps1") == ("echo", "ok")


def test_numeric_settings_fall_back_instead_of_crashing_startup() -> None:
    assert _as_float("not-a-number", "also-bad", fallback=1.5) == 1.5
    assert _as_float(None, "2.5") == 2.5
    # Negative durations are clamped, not honoured.
    assert _as_float("-3", None) == 0.0
    assert _as_int("not-a-number", "also-bad", fallback=7) == 7
    assert _as_int(None, "12") == 12
    assert _as_int("-5", None) == 0


def test_an_unresolvable_tilde_tool_path_keeps_its_literal_value() -> None:
    """expanduser raises RuntimeError for ~nosuchuser; startup must survive it."""
    kept = config._optional_path("~nosuchuser-headless-re/ida")

    assert kept == Path("~nosuchuser-headless-re/ida")
    assert kept.is_dir() is False


def test_an_embedded_nul_tool_path_keeps_its_literal_value() -> None:
    """resolve raises ValueError for a NUL byte; existence checks answer False."""
    kept = config._optional_path("ida\x00home")

    assert kept == Path("ida\x00home")
    assert kept.is_file() is False


def test_settings_load_survives_a_tilde_tool_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One bad optional tool path must not stop the whole server from starting."""
    monkeypatch.setenv("HEADLESS_RE_IDA_HOME", "~nosuchuser-headless-re/ida")

    settings = config.Settings.load(config_path=tmp_path / "config.json")

    assert settings.ida_home == Path("~nosuchuser-headless-re/ida")


def test_settings_load_names_an_unexpandable_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The artifact root gets created, so a bad tilde must refuse loudly by name."""
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", "~nosuchuser-headless-re/artifacts")

    with pytest.raises(ValueError, match="artifact_root"):
        config.Settings.load(config_path=tmp_path / "config.json")


def test_validate_ida_home_answers_a_tilde_path_with_a_structured_reply() -> None:
    checked = validate_ida_home("~nosuchuser-headless-re/ida")

    assert checked["ok"] is False
    assert checked["code"] == "not_a_directory"
