"""The install-wizard steps: honest per-step results over faked collaborators.

test_web_setup_ida pins configure_ida's activation honesty; these cover the
rest of the wizard -- each step answers its own structured result, the x64dbg
sync copies without touching anything outside the repo tree it was pointed
at, activation failures name timeout and launch errors, and the dispatcher
routes every declared step while refusing names it does not know.
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

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import (
    SETUP_STEPS,
    _no_window_flags,
    _step_doctor,
    _step_environment,
    _step_finalize,
    _step_generate_mcp,
    _step_persist_defaults,
    _step_probe_runtimes,
    _step_sync_x64dbg,
    _sync_one_arch,
    activate_idalib,
    run_setup_step,
)

JsonObject = dict[str, Any]


def _settings(tmp_path: Path) -> Settings:
    return replace(Settings.load(), artifact_root=tmp_path / "artifacts")


def test_no_window_flags_by_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert _no_window_flags() == 0
    monkeypatch.setattr(os, "name", "nt")
    expected = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert _no_window_flags() == expected


def test_activate_idalib_names_a_missing_script(tmp_path: Path) -> None:
    result = activate_idalib(tmp_path / "IDA Professional 9.9")
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"
    assert result["script"].endswith("py-activate-idalib.py")


def _fake_ida_with_script(tmp_path: Path) -> Path:
    home = tmp_path / "IDA Professional 9.9"
    script_dir = home / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('hi')\n", encoding="utf-8")
    return home


def test_activate_idalib_reports_timeout_and_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _fake_ida_with_script(tmp_path)

    def _timed_out(command: list[str], **kwargs: Any) -> Any:
        raise TimedOut(2.0, [111, 222])

    monkeypatch.setattr(setup_mod, "run_bounded", _timed_out)
    result = activate_idalib(home, timeout=2.0)
    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert result["killed_pids"] == [111, 222]
    assert "2s" in result["message"]

    def _unlaunchable(command: list[str], **kwargs: Any) -> Any:
        raise PermissionError("not executable")

    monkeypatch.setattr(setup_mod, "run_bounded", _unlaunchable)
    result = activate_idalib(home)
    assert result["ok"] is False
    assert result["code"] == "activation_failed"
    assert "not executable" in result["message"]


def test_configure_ida_refuses_an_invalid_home_without_saving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod,
        "update_config_values",
        lambda *args, **kwargs: pytest.fail("a failed validation must not write config"),
    )
    result = setup_mod.configure_ida(ida_home=tmp_path / "not-an-ida-install")
    assert result["ok"] is False
    assert result["saved"] is False
    assert result["validation"]["ok"] is False
    assert result["activation"] is None


def test_step_environment_reports_a_missing_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fastapi being importable is what the wizard itself runs on; a broken
    install must be named in the step, not crash it."""
    monkeypatch.setitem(sys.modules, "fastapi", None)
    result = _step_environment(_settings(tmp_path))
    assert result["ok"] is False
    assert result["web_extra"]["ok"] is False
    assert "fastapi" in result["web_extra"]["error"]


def test_sync_one_arch_prefers_what_is_already_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")
    result = _sync_one_arch("x64")
    assert result["already_present"] is True
    assert result["ok"] is True
    assert result["copied"] is False


def test_sync_one_arch_falls_back_to_discovery_then_reports_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    elsewhere = tmp_path / "elsewhere" / "headless.exe"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_bytes(b"MZ")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: elsewhere)
    result = _sync_one_arch("x64")
    assert result["ok"] is True
    assert result["copied"] is False
    assert result["note"] == "discovered_existing"
    assert result["headless"] == str(elsewhere)

    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)
    result = _sync_one_arch("x64")
    assert result["ok"] is False
    assert result["message"] == "source Release/headless.exe missing"


def test_sync_one_arch_replaces_stale_content_but_keeps_gitkeep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    src = tmp_path / "artifacts" / "x64dbg-x86" / "Release"
    src.mkdir(parents=True)
    (src / "headless.exe").write_bytes(b"MZ")
    (src / "plugin.dll").write_bytes(b"MZ")
    (src / "plugins").mkdir()
    (src / "plugins" / "hook.dll").write_bytes(b"MZ")

    dst = tmp_path / "external" / "x64dbg-x86"
    dst.mkdir(parents=True)
    (dst / ".gitkeep").write_text("", encoding="utf-8")
    (dst / "stale.dll").write_bytes(b"old")
    (dst / "stale-dir").mkdir()
    (dst / "stale-dir" / "junk.bin").write_bytes(b"old")

    result = _sync_one_arch("x86")
    assert result["copied"] is True
    assert result["ok"] is True
    assert (dst / "headless.exe").read_bytes() == b"MZ"
    assert (dst / "plugins" / "hook.dll").is_file()
    assert (dst / ".gitkeep").exists()
    assert not (dst / "stale.dll").exists()
    assert not (dst / "stale-dir").exists()


def test_step_sync_x64dbg_is_ok_when_either_arch_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")
    result = _step_sync_x64dbg(_settings(tmp_path))
    assert result["step"] == "sync_x64dbg"
    assert result["ok"] is True
    assert [item["arch"] for item in result["items"]] == ["x64", "x86"]
    assert result["items"][1]["ok"] is False


def test_step_probe_runtimes_prefers_refreshed_paths_and_checks_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "x64" / "headless.exe"
    x64.parent.mkdir(parents=True)
    x64.write_bytes(b"MZ")
    ida_home = tmp_path / "ida"
    ida_home.mkdir()
    refreshed = SimpleNamespace(x64dbg_headless_x64=x64, x64dbg_headless_x86=None, ida_home=None)
    monkeypatch.setattr(setup_mod, "Settings", SimpleNamespace(load=lambda **kwargs: refreshed))
    monkeypatch.setattr(setup_mod, "find_idalib_library", lambda home: home / "libida.so")
    stale = SimpleNamespace(
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=tmp_path / "gone" / "headless.exe",
        ida_home=ida_home,
    )
    result = _step_probe_runtimes(stale)  # type: ignore[arg-type]
    checks = {check["id"]: check for check in result["checks"]}
    # The freshly discovered x64 wins; the stale x86 fallback fails is_file.
    assert checks["x64dbg_x64"]["ok"] is True
    assert checks["x64dbg_x86"]["ok"] is False
    # ida_home falls back to the caller's settings and finds the library.
    assert checks["ida_home"]["ok"] is True
    # Step ok keys on the x64dbg pair only; ida never blocks the wizard here.
    assert result["ok"] is False


def _probe(name: str, status: str) -> SimpleNamespace:
    return SimpleNamespace(to_dict=lambda: {"name": name, "status": status, "summary": name})


def test_step_doctor_counts_core_probes_and_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SimpleNamespace(
        ready=False,
        probes=[
            _probe("python", "ready"),
            _probe("ida_idalib", "missing"),
            _probe("x64dbg_headless_binaries", "ready"),
            _probe("frida", "detected"),
            _probe("network", "blocked"),
        ],
    )
    monkeypatch.setattr(setup_mod, "run_doctor", lambda settings: report)
    result = _step_doctor(_settings(tmp_path))
    assert result["ok"] is False
    assert result["core_total"] == 3
    assert result["core_ready_count"] == 2
    assert result["summary"] == {"ready": 2, "missing": 1, "blocked": 1, "detected": 1}


def test_step_persist_defaults_writes_the_discovered_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, Any] = {}

    def _capture(updates: dict[str, Any], **kwargs: Any) -> Path:
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", _capture)
    settings = replace(
        _settings(tmp_path),
        ida_home=tmp_path / "ida",
        x64dbg_headless_x64=tmp_path / "x64.exe",
        x64dbg_headless_x86=tmp_path / "x86.exe",
    )
    result = _step_persist_defaults(settings)
    assert result["ok"] is True
    assert result["config_path"] == str(tmp_path / "config.json")
    assert written["ida_home"] == str(tmp_path / "ida")
    assert written["x64dbg_headless_x64"] == str(tmp_path / "x64.exe")
    assert written["x64dbg_headless_x86"] == str(tmp_path / "x86.exe")
    assert written["local_full_access"] is True
    assert set(result["written_keys"]) == set(written.keys())


def test_step_generate_mcp_maps_the_export_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = {
        "ok": True,
        "written": {"bundle": str(tmp_path / "mcp.json")},
        "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "doctor_ready": True,
        "stdio": {"command": "python"},
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist: export,
    )
    result = _step_generate_mcp(_settings(tmp_path))
    assert result["ok"] is True
    assert result["output"] == str(tmp_path / "mcp.json")
    assert result["server_keys"] == ["headless-re"]
    assert result["cursor_snippet"] == {"mcpServers": {"headless-re": {}}}


def test_step_finalize_tolerates_only_a_missing_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod, "setup_status", lambda settings: {"config_path": "c", "ida_home": None}
    )
    snapshots = iter(
        [
            {"missing_core": [{"id": "ida_home"}]},
            {"missing_core": [{"id": "x64dbg_headless_x64"}]},
        ]
    )
    monkeypatch.setattr(setup_mod, "build_deps_snapshot", lambda settings: next(snapshots))
    settings = _settings(tmp_path)
    assert _step_finalize(settings)["ok"] is True
    assert _step_finalize(settings)["ok"] is False


def test_run_setup_step_routes_every_declared_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    routed: list[str] = []

    def _stub(name: str) -> Any:
        def _run(settings: Settings) -> JsonObject:
            routed.append(name)
            return {"step": name}

        return _run

    for step in SETUP_STEPS:
        if step == "configure_ida":
            continue
        monkeypatch.setattr(setup_mod, f"_step_{step}", _stub(step))
    settings = _settings(tmp_path)
    for step in SETUP_STEPS:
        if step == "configure_ida":
            continue
        assert run_setup_step(settings, step) == {"step": step}
    assert routed == [step for step in SETUP_STEPS if step != "configure_ida"]


def test_run_setup_step_configure_ida_probes_when_no_path_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "list_ida_install_candidates", lambda: [])
    settings = replace(_settings(tmp_path), ida_home=None)
    result = run_setup_step(settings, "configure_ida")
    assert result["ok"] is False
    assert result["skipped"] is True
    assert result["ida_home"] is None

    monkeypatch.setattr(
        setup_mod,
        "configure_ida",
        lambda *, ida_home, activate: {"ok": True, "saved": True},
    )
    result = run_setup_step(settings, "configure_ida", ida_home=str(tmp_path / "ida"))
    assert result == {"step": "configure_ida", "ok": True, "saved": True}


def test_run_setup_step_refuses_unknown_and_undispatched_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    result = run_setup_step(settings, "  bogus ")
    assert result == {
        "ok": False,
        "step": "bogus",
        "code": "unknown_step",
        "message": "unknown setup step",
    }
    # A step added to SETUP_STEPS without a dispatcher answers unknown_step
    # instead of crashing the wizard.
    monkeypatch.setattr(setup_mod, "SETUP_STEPS", (*SETUP_STEPS, "future_step"))
    result = run_setup_step(settings, "future_step")
    assert result == {"ok": False, "step": "future_step", "code": "unknown_step"}
