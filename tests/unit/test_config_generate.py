from __future__ import annotations

import json
from pathlib import Path

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.config_generate import (
    build_stdio_server_config,
    generate_config_bundle,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def test_stdio_config_has_no_secret_fields(tmp_path: Path) -> None:
    server = build_stdio_server_config(
        python_path=Path(tmp_path / "python.exe"),
        config_path=tmp_path / "config.json",
    )
    blob = json.dumps(server)
    assert "token" not in blob.casefold()
    assert "license" not in blob.casefold()
    assert server["args"][:2] == ["-m", "headless_re_mcp"]
    assert "serve" in server["args"]


def test_generate_skips_doctor_when_requested(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    bundle = generate_config_bundle(
        settings,
        python_path=Path("python"),
        config_path=tmp_path / "config.json",
        run_doctor_check=False,
        include_examples=True,
    )
    assert bundle["ok"] is True
    assert "cursor" in bundle["examples"]
    assert "vscode" in bundle["examples"]
    assert "claude_desktop" in bundle["examples"]


def test_embed_discovered_env_uses_real_paths(tmp_path: Path) -> None:
    from headless_re_mcp.config_generate import export_mcp_environment

    headless = tmp_path / "headless.exe"
    headless.write_bytes(b"MZ")
    ida = tmp_path / "IDA"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    settings = Settings(
        ida_home=ida,
        x64dbg_source=None,
        x64dbg_headless_x64=headless,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "artifacts").mkdir()
    export = export_mcp_environment(
        settings,
        python_path=tmp_path / "python.exe",
        config_path=tmp_path / "config.json",
        persist=True,
        output_dir=tmp_path / "out",
    )
    assert export["ok"] is True
    env = export["stdio"]["env"]
    assert env["HEADLESS_RE_X64DBG_HEADLESS_X64"] == str(headless.resolve())
    assert env["HEADLESS_RE_IDA_HOME"] == str(ida.resolve())
    assert "HEADLESS_RE_CONFIG" in env
    cursor = export["examples"]["cursor"]["mcpServers"]["headless-re-mcp"]
    assert cursor["env"]["HEADLESS_RE_IDA_HOME"] == str(ida.resolve())
    assert (tmp_path / "out" / "mcp.cursor.json").is_file()
    assert "rpc_token" not in json.dumps(export["stdio"]).casefold()


def test_cli_config_generate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(cli_module.Settings, "load", lambda _path=None: settings)
    code = cli_module.main(
        ["config", "generate", "--skip-doctor", "--no-examples", "--python", "python"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert "examples" not in payload
