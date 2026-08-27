"""Wiring a configured Ghidra extension (ghidra-wasm-plugin) into place.

analyzeHeadless only loads extensions from ``<home>/Ghidra/Extensions/<name>``.
``HEADLESS_RE_GHIDRA_WASM_PLUGIN`` points at an extracted extension dir that may
live anywhere, so the client copies it in before the headless run -- otherwise
the setting does nothing and a .wasm imports with no WebAssembly loader. These
pin the copy: it lands in the right place, is idempotent (copy-if-absent), never
touches a non-extension dir, skips a plugin already installed in place, and
degrades to None (never raises) when the install tree is not writable.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def _fake_plugin(tmp_path: Path, name: str = "ghidra-wasm-plugin") -> Path:
    plugin = tmp_path / "unpacked" / name
    (plugin / "lib").mkdir(parents=True)
    (plugin / "Module.manifest").write_text("", encoding="utf-8")
    (plugin / "lib" / "plugin.jar").write_bytes(b"jar")
    return plugin


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "mod.wasm"
    path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return path


def test_install_copies_extension_into_ghidra_extensions(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    plugin = _fake_plugin(tmp_path)
    dest = ghidra_client._install_extension(home, plugin)
    expected = home.resolve() / "Ghidra" / "Extensions" / "ghidra-wasm-plugin"
    assert dest == expected
    assert (expected / "Module.manifest").is_file()
    assert (expected / "lib" / "plugin.jar").read_bytes() == b"jar"


def test_install_is_idempotent_and_does_not_overwrite(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    plugin = _fake_plugin(tmp_path)
    dest = ghidra_client._install_extension(home, plugin)
    assert dest is not None
    # A marker written into the installed copy must survive a second install:
    # the helper is copy-if-absent, not copy-over.
    marker = dest / "marker.txt"
    marker.write_text("keep", encoding="utf-8")
    again = ghidra_client._install_extension(home, plugin)
    assert again == dest
    assert marker.read_text(encoding="utf-8") == "keep"


def test_install_noop_for_a_non_extension_dir(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    not_plugin = tmp_path / "random"
    not_plugin.mkdir()
    (not_plugin / "readme.txt").write_text("x", encoding="utf-8")
    assert ghidra_client._install_extension(home, not_plugin) is None
    # A dir with no Module.manifest is rejected before any Extensions/ is made.
    assert not (home / "Ghidra" / "Extensions").exists()


def test_install_noop_without_home_or_plugin(tmp_path: Path) -> None:
    assert ghidra_client._install_extension(None, _fake_plugin(tmp_path)) is None
    assert ghidra_client._install_extension(_fake_home(tmp_path), None) is None


def test_install_skips_when_plugin_is_already_installed_in_place(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    in_place = home / "Ghidra" / "Extensions" / "ghidra-wasm-plugin"
    in_place.mkdir(parents=True)
    (in_place / "Module.manifest").write_text("", encoding="utf-8")
    (in_place / "keep.txt").write_text("keep", encoding="utf-8")
    dest = ghidra_client._install_extension(home, in_place)
    assert dest == in_place.resolve()
    # Pointing the setting at the install copy must not recurse or clobber it.
    assert (in_place / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_install_degrades_to_none_when_copy_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _fake_home(tmp_path)
    plugin = _fake_plugin(tmp_path)

    def boom(src: Any, dst: Any, *args: Any, **kwargs: Any) -> Any:
        raise OSError("read-only file system")

    # The client calls shutil.copytree by module reference, so patching the
    # shutil module reaches it.
    monkeypatch.setattr(shutil, "copytree", boom)
    assert ghidra_client._install_extension(home, plugin) is None
    # No half-copied extension left behind.
    assert not (home / "Ghidra" / "Extensions" / "ghidra-wasm-plugin").exists()


def test_run_headless_installs_the_configured_plugin_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A headless export must drop the plugin in first, so the loader exists."""
    home = _fake_home(tmp_path)
    plugin = _fake_plugin(tmp_path)
    client = ghidra_client.GhidraClient(home=home, wasm_plugin=plugin)
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")

    installed_when_launched: list[bool] = []
    dest = home.resolve() / "Ghidra" / "Extensions" / "ghidra-wasm-plugin"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        installed_when_launched.append((dest / "Module.manifest").is_file())
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client.functions(_binary(tmp_path), tmp_path / "project")

    assert installed_when_launched == [True]
    assert (dest / "lib" / "plugin.jar").read_bytes() == b"jar"
