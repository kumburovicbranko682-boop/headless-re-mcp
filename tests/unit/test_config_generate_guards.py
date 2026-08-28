"""Guard/branch coverage for the MCP client config generator.

``test_config_generate.py`` covers secret scrubbing and the happy embed/export
paths against real Settings. These pin the remaining branches: path-existence
guards, the importability probe swallowing spec errors, the PYTHONPATH resolver
corners, the config-path-absent branches in env/server building,
``merge_live_settings`` with no live overlay, and the export skipping a
non-dict example payload while persisting.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

import headless_re_mcp.config_generate as config_generate
from headless_re_mcp.config import Settings
from headless_re_mcp.config_generate import (
    _package_importable,
    _path_exists,
    build_discovered_env,
    build_stdio_server_config,
    merge_live_settings,
    resolve_pythonpath_for_mcp,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def test_path_exists_is_false_for_none() -> None:
    assert _path_exists(None) is False


def test_path_exists_is_false_when_probe_raises_oserror() -> None:
    class _Boom:
        def exists(self) -> bool:
            raise OSError("device gone")

    assert _path_exists(cast(Path, _Boom())) is False


def test_package_importable_swallows_find_spec_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    def _boom(name: str) -> object:
        raise ValueError("bad module name")

    monkeypatch.setattr(importlib.util, "find_spec", _boom)
    assert _package_importable() is False


def test_resolve_pythonpath_is_none_when_repo_src_has_no_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(config_generate, "repo_root", lambda: tmp_path)
    assert resolve_pythonpath_for_mcp() is None


def test_resolve_pythonpath_returns_src_when_package_not_importable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "src" / "headless_re_mcp").mkdir(parents=True)
    monkeypatch.setattr(config_generate, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(config_generate, "_package_importable", lambda: False)
    assert resolve_pythonpath_for_mcp() == str((tmp_path / "src").resolve())


def test_build_discovered_env_omits_config_when_no_path_is_known(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(config_generate, "default_config_path", lambda: None)
    env, inventory = build_discovered_env(_settings(tmp_path), config_path=None)
    assert "HEADLESS_RE_CONFIG" not in env
    assert all(item["key"] != "HEADLESS_RE_CONFIG" for item in inventory)


def test_build_discovered_env_skips_pythonpath_when_disabled(tmp_path: Path) -> None:
    env, _ = build_discovered_env(
        _settings(tmp_path), config_path=tmp_path / "config.json", include_pythonpath=False
    )
    assert "PYTHONPATH" not in env


def test_build_discovered_env_omits_pythonpath_when_unresolvable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(config_generate, "resolve_pythonpath_for_mcp", lambda: None)
    env, _ = build_discovered_env(
        _settings(tmp_path), config_path=tmp_path / "config.json", include_pythonpath=True
    )
    assert "PYTHONPATH" not in env


def test_stdio_config_embed_without_a_config_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(config_generate, "default_config_path", lambda: None)
    server = build_stdio_server_config(
        settings=_settings(tmp_path), embed_discovered_env=True, config_path=None
    )
    assert "--config" not in server["args"]
    assert server["args"][-1] == "serve"


def test_stdio_config_without_embed_or_config_path() -> None:
    server = build_stdio_server_config()
    assert "--config" not in server["args"]
    assert server["env"] == {}


def test_merge_live_settings_returns_fresh_when_live_is_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fresh = _settings(tmp_path)
    monkeypatch.setattr(
        Settings,
        "load",
        classmethod(lambda cls, config_path=None: fresh),
    )
    assert merge_live_settings(None) is fresh


def test_export_persist_skips_a_non_dict_example_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_bundle = {
        "ok": True,
        "stdio": {"command": "python", "args": ["-m", "x", "serve"], "env": {}},
        "examples": {
            "cursor": {"mcpServers": {}},
            "vscode": "not-a-dict",  # not a dict -> skipped on persist
            "claude_desktop": {"mcpServers": {}},
        },
        "notes": [],
        "env_inventory": [],
        "embedded_env_keys": [],
        "doctor": None,
        "doctor_ready": None,
    }
    monkeypatch.setattr(config_generate, "generate_config_bundle", lambda *a, **k: fake_bundle)

    export = config_generate.export_mcp_environment(
        _settings(tmp_path),
        config_path=tmp_path / "config.json",
        persist=True,
        output_dir=tmp_path / "out",
        refresh_discovery=False,
    )

    written = export["written"]
    assert "cursor" in written
    assert "claude_desktop" in written
    assert "vscode" not in written
    assert (tmp_path / "out" / "mcp.cursor.json").is_file()
    assert not (tmp_path / "out" / "mcp.vscode.json").exists()


def test_export_without_persist_writes_no_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_bundle = {
        "ok": True,
        "stdio": {"command": "python", "args": ["-m", "x", "serve"], "env": {}},
        "examples": {"cursor": {"mcpServers": {}}},
        "notes": [],
    }
    monkeypatch.setattr(config_generate, "generate_config_bundle", lambda *a, **k: fake_bundle)

    export = config_generate.export_mcp_environment(
        _settings(tmp_path),
        config_path=tmp_path / "config.json",
        persist=False,
        refresh_discovery=False,
    )

    assert export["ok"] is True
    assert export["written"] == {}
