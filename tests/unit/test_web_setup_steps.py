"""Hermetic coverage for the web install-wizard steps.

The HTTP-level tests in ``test_web_console.py`` drive a few happy-path steps,
and ``test_web_setup_ida.py`` pins the IDA activation contract on Windows. The
remaining branches -- idalib activation off Windows, the x64dbg tree sync, the
runtime/doctor/finalize probes, MCP generation, and the step dispatcher's
error arms -- were untested, leaving ``web/setup.py`` at 43%.

Every step here runs against redirected config/data/repo paths so nothing
touches the real user config or the checked-out tree.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp import config as config_mod
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import (
    activate_idalib,
    configure_ida,
    run_setup_step,
)


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    cfg = tmp_path / "config.json"
    data = tmp_path / "data"
    root = tmp_path / "repo"
    data.mkdir()
    root.mkdir()
    for module, name in (
        (config_mod, "default_config_path"),
        (config_mod, "default_data_path"),
        (setup_mod, "default_config_path"),
        (setup_mod, "default_data_path"),
    ):
        target = cfg if name == "default_config_path" else data
        monkeypatch.setattr(module, name, lambda t=target: t)
    monkeypatch.setattr(setup_mod, "repo_root", lambda: root)
    return SimpleNamespace(cfg=cfg, data=data, root=root, tmp=tmp_path)


def _settings(tmp_path: Path, **over: Any) -> Settings:
    base = replace(
        Settings.load(config_path=tmp_path / "does-not-exist.json"),
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **over) if over else base


# --------------------------------------------------------------------------- #
# _no_window_flags                                                            #
# --------------------------------------------------------------------------- #
def test_no_window_flags_are_zero_off_windows() -> None:
    assert setup_mod._no_window_flags() == 0


def test_no_window_flags_ask_for_a_hidden_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    assert setup_mod._no_window_flags() == 0x08000000


# --------------------------------------------------------------------------- #
# activate_idalib                                                             #
# --------------------------------------------------------------------------- #
def _ida_with_activation_script(tmp_path: Path) -> Path:
    ida = tmp_path / "IDA Professional 9.9"
    script_dir = ida / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    (script_dir / "py-activate-idalib.py").write_text("print('ok')\n", encoding="utf-8")
    return ida


def test_activate_idalib_reports_a_missing_script(tmp_path: Path) -> None:
    ida = tmp_path / "IDA"
    ida.mkdir()
    result = activate_idalib(ida)
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"


def test_activate_idalib_reports_success_on_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida = _ida_with_activation_script(tmp_path)
    monkeypatch.setattr(
        setup_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=0, stdout=b"activated", stderr=b""),
    )
    result = activate_idalib(ida)
    assert result["ok"] is True
    assert result["code"] == "activated"
    assert result["exit_code"] == 0


def test_activate_idalib_flags_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida = _ida_with_activation_script(tmp_path)
    monkeypatch.setattr(
        setup_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=3, stdout=b"", stderr=b"boom"),
    )
    result = activate_idalib(ida)
    assert result["ok"] is False
    assert result["code"] == "activation_exit_nonzero"
    assert result["exit_code"] == 3


def test_activate_idalib_reports_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ida = _ida_with_activation_script(tmp_path)

    def hang(*_a: Any, **_k: Any) -> Completed:
        raise TimedOut(timeout=1.5, killed=[123, 456])

    monkeypatch.setattr(setup_mod, "run_bounded", hang)
    result = activate_idalib(ida)
    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert result["killed_pids"] == [123, 456]


def test_activate_idalib_reports_a_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida = _ida_with_activation_script(tmp_path)

    def boom(*_a: Any, **_k: Any) -> Completed:
        raise OSError("could not spawn python")

    monkeypatch.setattr(setup_mod, "run_bounded", boom)
    result = activate_idalib(ida)
    assert result["ok"] is False
    assert result["code"] == "activation_failed"


# --------------------------------------------------------------------------- #
# configure_ida validation failure                                            #
# --------------------------------------------------------------------------- #
def test_configure_ida_refuses_an_invalid_home(tmp_path: Path) -> None:
    result = configure_ida(
        ida_home=tmp_path / "not-an-ida-dir",
        activate=False,
        config_path=tmp_path / "config.json",
    )
    assert result["ok"] is False
    assert result["saved"] is False
    assert result["validation"]["ok"] is False


# --------------------------------------------------------------------------- #
# _step_environment web-extra probe                                           #
# --------------------------------------------------------------------------- #
def test_environment_step_flags_a_missing_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With fastapi unimportable, the step reports the web extra as absent."""
    monkeypatch.setitem(sys.modules, "fastapi", None)
    result = setup_mod._step_environment(_settings(tmp_path))
    assert result["web_extra"]["ok"] is False
    assert result["web_extra"]["error"]
    assert result["ok"] is False


# --------------------------------------------------------------------------- #
# _sync_one_arch and the sync step                                            #
# --------------------------------------------------------------------------- #
def test_sync_reports_an_already_present_binary(isolated: SimpleNamespace) -> None:
    dst = isolated.root / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")
    result = setup_mod._sync_one_arch("x64")
    assert result["already_present"] is True
    assert result["ok"] is True


def test_sync_discovers_an_existing_binary_without_copying(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = isolated.tmp / "elsewhere" / "headless.exe"
    found.parent.mkdir(parents=True)
    found.write_bytes(b"MZ")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: found)
    result = setup_mod._sync_one_arch("x86")
    assert result["ok"] is True
    assert result["note"] == "discovered_existing"
    assert result["copied"] is False


def test_sync_reports_missing_source_when_nothing_is_found(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: None)
    result = setup_mod._sync_one_arch("x64")
    assert result["ok"] is False
    assert result["message"] == "source Release/headless.exe missing"


def test_sync_copies_the_release_tree_over_a_stale_destination(
    isolated: SimpleNamespace,
) -> None:
    src = isolated.root / "artifacts" / "x64dbg-x64" / "Release"
    (src / "plugins").mkdir(parents=True)
    (src / "headless.exe").write_bytes(b"MZ-new")
    (src / "plugins" / "helper.dll").write_bytes(b"dll")
    dst = isolated.root / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / ".gitkeep").write_bytes(b"")
    (dst / "stale.txt").write_bytes(b"old")
    (dst / "stale_dir").mkdir()

    result = setup_mod._sync_one_arch("x64")

    assert result["copied"] is True
    assert result["ok"] is True
    assert (dst / "headless.exe").read_bytes() == b"MZ-new"
    assert (dst / "plugins" / "helper.dll").is_file()
    assert (dst / ".gitkeep").is_file()  # preserved
    assert not (dst / "stale.txt").exists()  # cleaned
    assert not (dst / "stale_dir").exists()


def test_sync_step_aggregates_both_arches(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    dst = isolated.root / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: None)
    result = setup_mod._step_sync_x64dbg(_settings(isolated.tmp))
    assert result["step"] == "sync_x64dbg"
    assert result["ok"] is True  # x64 already present
    assert len(result["items"]) == 2


# --------------------------------------------------------------------------- #
# _step_probe_runtimes                                                        #
# --------------------------------------------------------------------------- #
def test_probe_runtimes_reports_present_and_absent_paths(
    isolated: SimpleNamespace,
) -> None:
    x64 = isolated.tmp / "headless-x64.exe"
    x64.write_bytes(b"MZ")
    ida = isolated.tmp / "IDA"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    settings = _settings(
        isolated.tmp,
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=None,
        ida_home=ida,
    )
    result = setup_mod._step_probe_runtimes(settings)
    checks = {c["id"]: c for c in result["checks"]}
    assert checks["x64dbg_x64"]["ok"] is True
    assert checks["x64dbg_x86"]["ok"] is False
    assert checks["ida_home"]["ok"] is True
    assert result["ok"] is False  # x86 missing


# --------------------------------------------------------------------------- #
# _step_persist_defaults                                                      #
# --------------------------------------------------------------------------- #
def test_persist_defaults_writes_the_discovered_paths(
    isolated: SimpleNamespace,
) -> None:
    x64 = isolated.tmp / "hx64.exe"
    x86 = isolated.tmp / "hx86.exe"
    ida = isolated.tmp / "IDA"
    for p in (x64, x86):
        p.write_bytes(b"MZ")
    ida.mkdir()
    settings = _settings(
        isolated.tmp,
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=x86,
        ida_home=ida,
    )
    result = setup_mod._step_persist_defaults(settings)
    assert result["ok"] is True
    assert result["config_path"] == str(isolated.cfg)
    assert "ida_home" in result["written_keys"]
    assert "x64dbg_headless_x64" in result["written_keys"]
    assert "x64dbg_headless_x86" in result["written_keys"]
    assert isolated.cfg.is_file()


# --------------------------------------------------------------------------- #
# _step_doctor and _step_finalize                                             #
# --------------------------------------------------------------------------- #
def test_doctor_step_summarizes_probe_statuses(isolated: SimpleNamespace) -> None:
    result = setup_mod._step_doctor(_settings(isolated.tmp))
    assert result["step"] == "doctor"
    assert "ready" in result["summary"]
    assert result["core_total"] >= 1
    assert isinstance(result["probes"], list)


def test_finalize_step_lists_next_commands(isolated: SimpleNamespace) -> None:
    result = setup_mod._step_finalize(_settings(isolated.tmp))
    assert result["step"] == "finalize"
    assert "python start_web.py" in result["next_commands"]
    assert "missing_core" in result


# --------------------------------------------------------------------------- #
# _step_generate_mcp                                                          #
# --------------------------------------------------------------------------- #
def test_generate_mcp_extracts_the_cursor_snippet(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = {
        "ok": True,
        "written": {"bundle": "/tmp/bundle.json"},
        "examples": {"cursor": {"mcpServers": {"headless-re": {"command": "python"}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "doctor_ready": False,
        "stdio": {"command": "python"},
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda *a, **k: export,
    )
    result = setup_mod._step_generate_mcp(_settings(isolated.tmp))
    assert result["ok"] is True
    assert result["output"] == "/tmp/bundle.json"
    assert result["cursor_snippet"] == export["examples"]["cursor"]
    assert result["server_keys"] == ["headless-re"]


def test_generate_mcp_tolerates_missing_examples(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda *a, **k: {"ok": True, "written": {}},
    )
    result = setup_mod._step_generate_mcp(_settings(isolated.tmp))
    assert result["has_examples"] is False
    assert result["cursor_snippet"] is None
    assert result["server_keys"] == []


# --------------------------------------------------------------------------- #
# run_setup_step dispatch                                                     #
# --------------------------------------------------------------------------- #
def test_run_setup_step_rejects_an_unknown_step(isolated: SimpleNamespace) -> None:
    result = run_setup_step(_settings(isolated.tmp), "not-a-step")
    assert result["ok"] is False
    assert result["code"] == "unknown_step"


def test_run_setup_step_configure_ida_is_probe_only_without_a_path(
    isolated: SimpleNamespace,
) -> None:
    result = run_setup_step(_settings(isolated.tmp), "configure_ida")
    assert result["step"] == "configure_ida"
    assert result["skipped"] is True


def test_run_setup_step_configure_ida_routes_to_configure(
    isolated: SimpleNamespace,
) -> None:
    ida = isolated.tmp / "IDA Professional 9.9"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    result = run_setup_step(
        _settings(isolated.tmp), "configure_ida", ida_home=str(ida), activate=False
    )
    assert result["step"] == "configure_ida"
    assert result["saved"] is True


@pytest.mark.parametrize(
    "step",
    ["environment", "sync_x64dbg", "probe_runtimes", "doctor", "persist_defaults", "finalize"],
)
def test_run_setup_step_routes_each_named_step(isolated: SimpleNamespace, step: str) -> None:
    result = run_setup_step(_settings(isolated.tmp), step)
    assert result["step"] == step


def test_run_setup_step_routes_generate_mcp(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda *a, **k: {"ok": True, "written": {"bundle": "/tmp/b.json"}},
    )
    result = run_setup_step(_settings(isolated.tmp), "generate_mcp")
    assert result["step"] == "generate_mcp"
    assert result["ok"] is True
