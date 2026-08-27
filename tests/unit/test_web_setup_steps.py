"""Web install-wizard steps: dispatch, guards, and side-effect isolation.

Every collaborator that would touch the real config, copy runtime trees, or
launch a JVM/IDA activator is monkeypatched, so the wizard's step routing and
each step's result shape run without an IDA install, an x64dbg build, or a
browser toolchain present.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.web import setup as setup_mod


def _settings(tmp_path: Path) -> Settings:
    return replace(Settings.load(), artifact_root=tmp_path / "artifacts")


# --- activate_idalib --------------------------------------------------------


def test_activate_idalib_reports_a_missing_script(tmp_path: Path) -> None:
    result = setup_mod.activate_idalib(tmp_path / "IDA")
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"


def _script(tmp_path: Path) -> Path:
    home = tmp_path / "IDA"
    (home / "idalib" / "python").mkdir(parents=True)
    (home / "idalib" / "python" / "py-activate-idalib.py").write_text("x", encoding="utf-8")
    return home


def test_activate_idalib_maps_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _script(tmp_path)

    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(1.5, [111, 222])

    monkeypatch.setattr(setup_mod, "run_bounded", _timeout)
    result = setup_mod.activate_idalib(home)
    assert result["ok"] is False and result["code"] == "timeout"
    assert result["killed_pids"] == [111, 222]


def test_activate_idalib_maps_a_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _script(tmp_path)
    monkeypatch.setattr(
        setup_mod, "run_bounded", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )
    result = setup_mod.activate_idalib(home)
    assert result["ok"] is False and result["code"] == "activation_failed"


def test_activate_idalib_reports_success_and_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _script(tmp_path)
    monkeypatch.setattr(setup_mod, "run_bounded", lambda *a, **k: Completed(0, b"done", b""))
    ok = setup_mod.activate_idalib(home)
    assert ok["ok"] is True and ok["code"] == "activated"

    monkeypatch.setattr(setup_mod, "run_bounded", lambda *a, **k: Completed(2, b"", b"bad"))
    failed = setup_mod.activate_idalib(home)
    assert failed["ok"] is False and failed["code"] == "activation_exit_nonzero"
    assert failed["exit_code"] == 2


# --- configure_ida ----------------------------------------------------------


def test_configure_ida_returns_early_on_a_bad_home(tmp_path: Path) -> None:
    result = setup_mod.configure_ida(
        ida_home=tmp_path / "not-really-ida", config_path=tmp_path / "cfg.json"
    )
    assert result["ok"] is False and result["saved"] is False
    assert result["activation"] is None


def test_configure_ida_saves_and_activates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    home = tmp_path / "IDA"
    home.mkdir()
    monkeypatch.setattr(
        setup_mod, "validate_ida_home", lambda h: {"ok": True, "path": str(home)}
    )
    monkeypatch.setattr(
        setup_mod, "update_config_values", lambda values, config_path=None: tmp_path / "cfg.json"
    )
    monkeypatch.setattr(setup_mod, "activate_idalib", lambda h: {"ok": True, "code": "activated"})
    monkeypatch.setattr(
        setup_mod,
        "probe_ida",
        lambda settings: SimpleNamespace(
            name="ida_idalib",
            status=SimpleNamespace(value="ready"),
            summary="ok",
            remediation="",
            details={},
        ),
    )
    result = setup_mod.configure_ida(ida_home=home, activate=True)
    assert result["ok"] is True and result["saved"] is True
    assert result["activation"]["ok"] is True
    assert result["probe"]["status"] == "ready"


# --- environment ------------------------------------------------------------


def test_step_environment_reports_missing_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A None entry in sys.modules makes ``import fastapi`` raise ImportError,
    # which is exactly the "web extra not installed" branch.
    monkeypatch.setitem(sys.modules, "fastapi", None)
    result = setup_mod._step_environment(_settings(tmp_path))
    assert result["web_extra"]["ok"] is False
    assert result["web_extra"]["error"]


def test_step_environment_ok_when_web_extra_present(tmp_path: Path) -> None:
    result = setup_mod._step_environment(_settings(tmp_path))
    assert result["step"] == "environment"
    assert result["web_extra"]["ok"] is True


# --- sync x64dbg ------------------------------------------------------------


def _repo(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: root)


def test_sync_one_arch_reports_an_already_present_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(monkeypatch, tmp_path)
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_text("bin", encoding="utf-8")
    result = setup_mod._sync_one_arch("x64")
    assert result["already_present"] is True and result["ok"] is True


def test_sync_one_arch_discovers_an_existing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(monkeypatch, tmp_path)
    found = tmp_path / "elsewhere" / "headless.exe"
    found.parent.mkdir(parents=True)
    found.write_text("bin", encoding="utf-8")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: found)
    result = setup_mod._sync_one_arch("x86")
    assert result["ok"] is True and result["note"] == "discovered_existing"


def test_sync_one_arch_reports_a_missing_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(monkeypatch, tmp_path)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)
    result = setup_mod._sync_one_arch("x64")
    assert result["ok"] is False
    assert result["message"] == "source Release/headless.exe missing"


def test_sync_one_arch_copies_the_release_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(monkeypatch, tmp_path)
    src = tmp_path / "artifacts" / "x64dbg-x64" / "Release"
    src.mkdir(parents=True)
    (src / "headless.exe").write_text("bin", encoding="utf-8")
    (src / "plugins").mkdir()
    (src / "plugins" / "p.dp64").write_text("plug", encoding="utf-8")
    # A pre-existing destination with junk to be cleared, keeping .gitkeep.
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / ".gitkeep").write_text("", encoding="utf-8")
    (dst / "stale.txt").write_text("old", encoding="utf-8")
    (dst / "stale_dir").mkdir()
    result = setup_mod._sync_one_arch("x64")
    assert result["copied"] is True and result["ok"] is True
    assert (dst / "headless.exe").is_file()
    assert (dst / "plugins" / "p.dp64").is_file()
    assert (dst / ".gitkeep").is_file()
    assert not (dst / "stale.txt").exists()
    assert not (dst / "stale_dir").exists()


def test_step_sync_x64dbg_aggregates_both_arches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(monkeypatch, tmp_path)
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_text("bin", encoding="utf-8")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)
    result = setup_mod._step_sync_x64dbg(_settings(tmp_path))
    assert result["step"] == "sync_x64dbg"
    assert result["ok"] is True and len(result["items"]) == 2


# --- probe runtimes ---------------------------------------------------------


def test_step_probe_runtimes_checks_configured_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "hx64.exe"
    x64.write_text("bin", encoding="utf-8")
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    settings = replace(
        _settings(tmp_path),
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=None,
        ida_home=ida_dir,
    )
    # Freshly reloaded settings must not shadow the ones under test.
    monkeypatch.setattr(setup_mod.Settings, "load", classmethod(lambda cls, **k: settings))
    monkeypatch.setattr(setup_mod, "find_idalib_library", lambda home: None)
    result = setup_mod._step_probe_runtimes(settings)
    checks = {c["id"]: c for c in result["checks"]}
    assert checks["x64dbg_x64"]["ok"] is True
    assert checks["x64dbg_x86"]["ok"] is False
    assert checks["ida_home"]["ok"] is False


# --- doctor / persist / generate / finalize --------------------------------


def test_step_doctor_summarizes_probes(tmp_path: Path) -> None:
    result = setup_mod._step_doctor(_settings(tmp_path))
    assert result["step"] == "doctor"
    assert "probes" in result and isinstance(result["summary"], dict)
    assert result["core_total"] >= 1


def test_step_persist_defaults_writes_optional_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved: list[tuple[dict[str, Any], Any]] = []

    def _fake_update(values: dict[str, Any], config_path: Any = None) -> Path:
        saved.append((values, config_path))
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", _fake_update)
    settings = replace(
        _settings(tmp_path),
        ida_home=tmp_path / "ida",
        x64dbg_headless_x64=tmp_path / "hx64.exe",
        x64dbg_headless_x86=tmp_path / "hx86.exe",
    )
    result = setup_mod._step_persist_defaults(settings)
    assert result["ok"] is True
    written = set(result["written_keys"])
    assert {"ida_home", "x64dbg_headless_x64", "x64dbg_headless_x86"} <= written
    assert saved  # update_config_values was invoked


def test_step_persist_defaults_omits_absent_optional_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod, "update_config_values", lambda values, config_path=None: tmp_path / "config.json"
    )
    settings = replace(
        _settings(tmp_path),
        ida_home=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
    )
    result = setup_mod._step_persist_defaults(settings)
    written = set(result["written_keys"])
    assert not ({"ida_home", "x64dbg_headless_x64", "x64dbg_headless_x86"} & written)


def test_step_generate_mcp_shapes_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_export = {
        "ok": True,
        "written": {"bundle": str(tmp_path / "mcp.json")},
        "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "env_inventory": [],
        "doctor_ready": True,
        "stdio": {"ok": True},
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist=True: fake_export,
    )
    result = setup_mod._step_generate_mcp(_settings(tmp_path))
    assert result["ok"] is True and result["step"] == "generate_mcp"
    assert result["server_keys"] == ["headless-re"]
    assert result["cursor_snippet"] == {"mcpServers": {"headless-re": {}}}


def test_step_finalize_reports_missing_core(tmp_path: Path) -> None:
    result = setup_mod._step_finalize(_settings(tmp_path))
    assert result["step"] == "finalize"
    assert "missing_core" in result
    assert "python -m headless_re_mcp doctor" in result["next_commands"]


# --- run_setup_step dispatch ------------------------------------------------


def test_run_setup_step_rejects_an_unknown_step(tmp_path: Path) -> None:
    result = setup_mod.run_setup_step(_settings(tmp_path), "nonsense")
    assert result["ok"] is False and result["code"] == "unknown_step"


def test_run_setup_step_configure_ida_probe_only_when_no_home(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), ida_home=None)
    result = setup_mod.run_setup_step(settings, "configure_ida")
    assert result["step"] == "configure_ida"
    assert result["skipped"] is True
    assert result["ok"] is False  # no ida_home configured


def test_run_setup_step_configure_ida_delegates_with_a_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod,
        "configure_ida",
        lambda *, ida_home, activate: {"ok": True, "saved": True, "ida_home": ida_home},
    )
    result = setup_mod.run_setup_step(
        _settings(tmp_path), "configure_ida", ida_home="/opt/ida", activate=False
    )
    assert result["step"] == "configure_ida" and result["ok"] is True


def test_run_setup_step_routes_each_known_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    routed: list[str] = []

    for step in ("environment", "sync_x64dbg", "probe_runtimes", "doctor", "persist_defaults",
                 "generate_mcp", "finalize"):
        monkeypatch.setattr(
            setup_mod,
            f"_step_{step}",
            lambda s, _step=step: {"ok": True, "step": _step, "routed": True},
        )
    for step in ("environment", "sync_x64dbg", "probe_runtimes", "doctor", "persist_defaults",
                 "generate_mcp", "finalize"):
        result = setup_mod.run_setup_step(settings, step)
        assert result.get("routed") is True and result["step"] == step
        routed.append(step)
    assert len(routed) == 7
