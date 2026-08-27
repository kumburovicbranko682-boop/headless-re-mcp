"""Regression: the ScyllaHide ini reader must survive UTF-16, its native format.

``read_current_section`` / ``_load_or_seed`` read the ini as UTF-8 and *mean*
to fall back to UTF-16 -- the encoding ScyllaHide itself writes. But
``configparser.read`` only swallows ``OSError`` while a UTF-16 file decoded as
UTF-8 raises ``UnicodeDecodeError``, so the fallback was dead code: the first
real ScyllaHide ini (UTF-16, BOM-prefixed) crashed status/inspect/apply with an
unhandled decode error instead of reporting the current profile.

``test_xdbg_stealth_install.py`` already covers the UTF-8 install/seed/candidate
edges; this file pins only the UTF-16 paths that used to raise, including the
install path's security-relevant quieting of the inject server on a UTF-16 tree.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.x64dbg.stealth import (
    StealthLayout,
    apply_profile,
    install_from_extracted_tree,
    layout_for_headless,
    read_current_section,
)
from headless_re_mcp.core.models import Architecture

_PLUGIN = "ScyllaHideX64DBGPlugin.dp64"
_HOOK = "HookLibraryx64.dll"

# A ScyllaHide ini as the tool ships it: UTF-16 and with the inject server on.
_UTF16_INI = (
    "[SETTINGS]\n"
    "CurrentProfile=Themida x86/x64\n"
    "[Themida x86/x64]\n"
    "DLLNormal=1\n"
    "AutostartServer=1\n"
    "ServerPort=1337\n"
)


def _fresh_layout(tmp_path: Path) -> StealthLayout:
    root = tmp_path / "x64dbg-x64"
    (root / "plugins").mkdir(parents=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    return layout


def test_read_current_section_reads_a_utf16_scyllahide_ini(tmp_path: Path) -> None:
    ini = tmp_path / "scylla_hide.ini"
    ini.write_text(_UTF16_INI, encoding="utf-16")
    # Before the fix this raised UnicodeDecodeError instead of returning.
    assert read_current_section(ini) == "Themida x86/x64"


def test_apply_profile_over_a_utf16_ini_succeeds_and_quiets_server(tmp_path: Path) -> None:
    """apply_profile loads the ini via _load_or_seed, which had the same bug."""
    layout = _fresh_layout(tmp_path)
    layout.plugin.write_bytes(b"plugin")
    layout.hook_library.write_bytes(b"hook")
    layout.ini.write_text(_UTF16_INI, encoding="utf-16")

    # "themida" is the one section this minimal tool ini carries, so applying it
    # exercises the UTF-16 load path without tripping the unrelated
    # "no such section" guard.
    result = apply_profile(layout, "themida", require_plugin=True)

    assert result["section"] == "Themida x86/x64"
    assert read_current_section(layout.ini) == "Themida x86/x64"
    text = layout.ini.read_text(encoding="utf-8")
    assert "AutostartServer=0" in text and "ServerPort=0" in text
    assert "AutostartServer=1" not in text and "1337" not in text


def test_install_from_a_utf16_tree_quiets_the_inject_server(tmp_path: Path) -> None:
    """Installing a tree whose ini is UTF-16 must still disarm the listen port."""
    source = tmp_path / "extracted"
    source.mkdir()
    (source / _PLUGIN).write_bytes(b"plugin-bytes")
    (source / _HOOK).write_bytes(b"hook-bytes")
    (source / "scylla_hide.ini").write_text(_UTF16_INI, encoding="utf-16")

    layout = _fresh_layout(tmp_path)
    result = install_from_extracted_tree(source, layout)

    assert result["plugin_present"] is True
    assert layout.plugin.read_bytes() == b"plugin-bytes"
    text = layout.ini.read_text(encoding="utf-8")
    assert "AutostartServer=0" in text and "ServerPort=0" in text
    assert "1337" not in text
