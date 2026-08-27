"""Ghidra launcher discovery must match the host, not just the first file found.

A real Ghidra install ships both ``support/analyzeHeadless`` (POSIX shell) and
``support/analyzeHeadless.bat`` (Windows) side by side. Discovery used to list
the ``.bat`` first, so on Linux it returned the batch file -- not +x, not a
POSIX executable -- and a correct install failed to launch with Errno 13 while
Doctor, sharing this probe, still reported Ghidra ready. These pin the fix on
both platforms by faking a full install and toggling ``os.name``; they need no
real Ghidra on the box.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.ghidra.client import _find_analyze_headless


def _full_install(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def test_posix_picks_the_shell_launcher_not_the_windows_bat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _full_install(tmp_path)
    monkeypatch.setattr(ghidra_client.os, "name", "posix")
    found = _find_analyze_headless(home)
    assert found == home / "support" / "analyzeHeadless"
    assert not str(found).endswith(".bat")


def test_windows_picks_the_bat_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _full_install(tmp_path)
    monkeypatch.setattr(ghidra_client.os, "name", "nt")
    found = _find_analyze_headless(home)
    assert found == home / "support" / "analyzeHeadless.bat"


def test_posix_falls_back_to_bat_when_only_bat_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A .bat-only tree (as the other unit fakes build) must still be found."""
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr(ghidra_client.os, "name", "posix")
    assert _find_analyze_headless(home) == support / "analyzeHeadless.bat"
