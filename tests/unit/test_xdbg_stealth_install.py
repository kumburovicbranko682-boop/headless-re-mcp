"""Install/seed and candidate-mapping guard coverage for ScyllaHide stealth.

``test_xdbg_stealth.py`` covers apply/inspect happy paths through the service.
This file pins the pure edges that run identically on Linux: candidate
mapping skips, ini read fallbacks, apply-profile section/seed invariants,
``install_from_extracted_tree`` (success, nested lookup, missing files,
existing ini), and the ``summarize_settings`` invalid-default fallback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.stealth import (
    DEFAULT_PROFILE_ID,
    StealthError,
    StealthLayout,
    apply_profile,
    install_from_extracted_tree,
    layout_for_headless,
    profile_from_candidates,
    read_current_section,
    summarize_settings,
)
from headless_re_mcp.core.models import Architecture

_PLUGIN_NAME = "ScyllaHideX64DBGPlugin.dp64"
_HOOK_NAME = "HookLibraryx64.dll"


def _layout(tmp_path: Path, *, with_plugin: bool = False) -> StealthLayout:
    root = tmp_path / "x64dbg"
    (root / "plugins").mkdir(parents=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    if with_plugin:
        layout.plugin.write_bytes(b"plugin")
        layout.hook_library.write_bytes(b"hook")
    return layout


def test_profile_from_candidates_skips_non_dict_and_unfloatable_confidence() -> None:
    non_dict: list[Any] = ["not-a-dict", 42]
    assert profile_from_candidates(non_dict) is None
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "VMProtect 3.x", "confidence": "high"}]
        )
        == "vmp"
    )


def test_read_current_section_missing_file_returns_none(tmp_path: Path) -> None:
    assert read_current_section(tmp_path / "absent.ini") is None


def test_read_current_section_without_settings_returns_none(tmp_path: Path) -> None:
    ini = tmp_path / "no_settings.ini"
    ini.write_text("[Other]\nkey=value\n", encoding="utf-8")
    assert read_current_section(ini) is None


def test_read_current_section_reads_configured_profile(tmp_path: Path) -> None:
    ini = tmp_path / "ok.ini"
    ini.write_text("[SETTINGS]\nCurrentProfile=Basic\n", encoding="utf-8")
    assert read_current_section(ini) == "Basic"


def test_apply_profile_rejects_ini_missing_target_section(tmp_path: Path) -> None:
    layout = _layout(tmp_path, with_plugin=True)
    layout.ini.write_text(
        "[SETTINGS]\nCurrentProfile=Basic\n[Basic]\nDLLNormal=1\n", encoding="utf-8"
    )
    with pytest.raises(StealthError) as excinfo:
        apply_profile(layout, "vmp", require_plugin=True)
    assert excinfo.value.code == "invalid_params"


def test_apply_profile_seeds_missing_settings_without_clobbering(tmp_path: Path) -> None:
    layout = _layout(tmp_path, with_plugin=True)
    layout.ini.write_text("[VMProtect x86/x64]\nDLLNormal=9\n", encoding="utf-8")

    applied = apply_profile(layout, "vmp", require_plugin=True)

    assert applied["section"] == "VMProtect x86/x64"
    text = layout.ini.read_text(encoding="utf-8")
    assert "DLLNormal=9" in text
    assert "CurrentProfile=VMProtect x86/x64" in text
    assert read_current_section(layout.ini) == "VMProtect x86/x64"


def test_install_from_extracted_tree_copies_direct_and_nested_then_seeds(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    source = tmp_path / "extracted"
    (source).mkdir()
    (source / _PLUGIN_NAME).write_bytes(b"plugin-bytes")
    nested = source / "x64" / "release"
    nested.mkdir(parents=True)
    (nested / _HOOK_NAME).write_bytes(b"hook-bytes")

    result = install_from_extracted_tree(source, layout, seed_ini=True)

    assert layout.plugin.read_bytes() == b"plugin-bytes"
    assert layout.hook_library.read_bytes() == b"hook-bytes"
    assert layout.ini.is_file()
    assert result["plugin_present"] is True
    ini_text = layout.ini.read_text(encoding="utf-8")
    assert "AutostartServer=0" in ini_text
    assert "ServerPort=0" in ini_text


def test_install_from_extracted_tree_copies_existing_ini(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    source = tmp_path / "extracted"
    source.mkdir()
    (source / _PLUGIN_NAME).write_bytes(b"plugin")
    (source / _HOOK_NAME).write_bytes(b"hook")
    (source / "scylla_hide.ini").write_text(
        "[SETTINGS]\nCurrentProfile=Basic\n[Basic]\nDLLNormal=1\nAutostartServer=1\n",
        encoding="utf-8",
    )

    install_from_extracted_tree(source, layout, seed_ini=True)

    assert layout.ini.is_file()
    ini_text = layout.ini.read_text(encoding="utf-8")
    assert "AutostartServer=0" in ini_text
    assert "AutostartServer=1" not in ini_text


def test_install_from_extracted_tree_skips_seed_when_disabled(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    source = tmp_path / "extracted"
    source.mkdir()
    (source / _PLUGIN_NAME).write_bytes(b"plugin")
    (source / _HOOK_NAME).write_bytes(b"hook")

    result = install_from_extracted_tree(source, layout, seed_ini=False)

    assert layout.plugin.is_file()
    assert layout.hook_library.is_file()
    assert not layout.ini.is_file()
    assert result["ini_present"] is False


def test_install_from_extracted_tree_missing_files_fails_closed(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    source = tmp_path / "empty"
    source.mkdir()

    with pytest.raises(StealthError) as excinfo:
        install_from_extracted_tree(source, layout)

    assert excinfo.value.code == "plugin_missing"
    assert excinfo.value.details["found_plugin"] is False
    assert excinfo.value.details["found_hook_library"] is False


def test_summarize_settings_falls_back_on_invalid_default(tmp_path: Path) -> None:
    layout = _layout(tmp_path, with_plugin=True)

    summary = summarize_settings(
        enabled=True,
        default_profile="not-a-profile",
        layouts={Architecture.X64: layout},
    )

    assert summary["enabled"] is True
    assert summary["default_profile"] == DEFAULT_PROFILE_ID
    assert summary["architectures"]["x64"]["plugin_present"] is True
