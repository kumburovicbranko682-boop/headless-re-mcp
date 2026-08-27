"""Install-wizard step paths without touching the real user config.

Every write seam (update_config_values, export_mcp_environment, run_bounded)
and every discovery seam (repo_root, Settings.load, run_doctor, deps snapshot)
is replaced in the setup module namespace, so the wizard's step logic runs for
real while the host machine stays untouched.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.config_generate as config_generate
import headless_re_mcp.web.setup as setup_mod
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.doctor import ProbeStatus
from headless_re_mcp.web.setup import (
    SETUP_STEPS,
    _no_window_flags,
    _step_doctor,
    _step_finalize,
    _step_generate_mcp,
    _step_persist_defaults,
    _step_probe_runtimes,
    _step_sync_x64dbg,
    _sync_one_arch,
    activate_idalib,
    configure_ida,
    run_setup_step,
    setup_status,
)

JsonObject = dict[str, Any]


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides) if overrides else base


def test_no_window_flags_follow_the_host_os(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup_mod.os, "name", "posix")
    assert _no_window_flags() == 0

    monkeypatch.setattr(setup_mod.os, "name", "nt")
    monkeypatch.setattr(
        setup_mod.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False
    )
    assert _no_window_flags() == 0x08000000


def test_setup_status_summarizes_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = SimpleNamespace(
        name="ida_idalib",
        status=ProbeStatus.MISSING,
        summary="not configured",
        remediation="set ida_home",
        details={},
    )
    monkeypatch.setattr(setup_mod, "probe_ida", lambda settings: probe)
    monkeypatch.setattr(
        setup_mod, "build_deps_snapshot", lambda settings: {"counts": {"missing": 1}}
    )
    monkeypatch.setattr(setup_mod, "list_ida_install_candidates", lambda: [])
    monkeypatch.delenv("HEADLESS_RE_IDA_HOME", raising=False)

    status = setup_status(_settings(tmp_path, ida_home=tmp_path / "ida"))

    assert status["ok"] is True
    assert status["ida_home"] == str(tmp_path / "ida")
    assert status["env_override"] is False
    assert status["x64dbg_headless_x64"] is None
    assert status["probe"]["status"] == "missing"
    assert status["deps_counts"] == {"missing": 1}
    assert status["steps"] == list(SETUP_STEPS)


def test_activation_without_the_script_is_refused(tmp_path: Path) -> None:
    result = activate_idalib(tmp_path)

    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"
    assert result["script"].endswith("py-activate-idalib.py")


def _ida_home_with_script(tmp_path: Path) -> Path:
    home = tmp_path / "ida"
    script_dir = home / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('hi')\n", encoding="utf-8")
    return home


def test_a_timed_out_activation_reports_the_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timing_out(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        raise TimedOut(timeout=5.0, killed=[42])

    monkeypatch.setattr(setup_mod, "run_bounded", timing_out)

    result = activate_idalib(_ida_home_with_script(tmp_path))

    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert result["killed_pids"] == [42]


def test_an_unlaunchable_activation_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unlaunchable(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        raise OSError("exec format error")

    monkeypatch.setattr(setup_mod, "run_bounded", unlaunchable)

    result = activate_idalib(_ida_home_with_script(tmp_path))

    assert result["ok"] is False
    assert result["code"] == "activation_failed"
    assert "exec format error" in result["message"]


@pytest.mark.parametrize(
    ("exit_code", "ok", "code"),
    [(0, True, "activated"), (2, False, "activation_exit_nonzero")],
)
def test_activation_reports_the_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    ok: bool,
    code: str,
) -> None:
    monkeypatch.setattr(
        setup_mod,
        "run_bounded",
        lambda cmd, **kwargs: Completed(exit_code, b"out", b"err"),
    )

    result = activate_idalib(_ida_home_with_script(tmp_path))

    assert result["ok"] is ok
    assert result["code"] == code
    assert result["exit_code"] == exit_code
    assert result["stdout"] == "out"


def test_configure_ida_does_not_save_an_invalid_home(tmp_path: Path) -> None:
    result = configure_ida(
        ida_home=tmp_path / "not-an-ida", config_path=tmp_path / "config.json"
    )

    assert result["ok"] is False
    assert result["saved"] is False
    assert result["validation"]["ok"] is False
    assert result["activation"] is None


def test_environment_step_reports_a_broken_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "fastapi", None)

    result = setup_mod._step_environment(_settings(tmp_path))

    assert result["ok"] is False
    assert result["web_extra"]["ok"] is False
    assert "fastapi" in result["web_extra"]["error"]


def test_environment_step_passes_on_this_host(tmp_path: Path) -> None:
    result = setup_mod._step_environment(_settings(tmp_path))

    assert result["ok"] is True
    assert result["python"]["ok"] is True
    assert result["web_extra"] == {"ok": True, "error": None}


def _fake_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(setup_mod, "repo_root", lambda: root)
    return root


def test_sync_skips_when_the_destination_is_already_populated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _fake_repo(tmp_path, monkeypatch)
    dst = root / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")

    result = _sync_one_arch("x64")

    assert result["ok"] is True
    assert result["already_present"] is True
    assert result["copied"] is False


def test_sync_falls_back_to_a_discovered_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_repo(tmp_path, monkeypatch)
    elsewhere = tmp_path / "elsewhere" / "headless.exe"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_bytes(b"MZ")
    monkeypatch.setattr(
        setup_mod, "discover_x64dbg_headless", lambda arch: elsewhere
    )

    result = _sync_one_arch("x64")

    assert result["ok"] is True
    assert result["copied"] is False
    assert result["note"] == "discovered_existing"
    assert result["headless"] == str(elsewhere)


def test_sync_reports_a_missing_source_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_repo(tmp_path, monkeypatch)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)

    result = _sync_one_arch("x86")

    assert result["ok"] is False
    assert result["message"] == "source Release/headless.exe missing"


def test_sync_replaces_stale_destination_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _fake_repo(tmp_path, monkeypatch)
    src = root / "artifacts" / "x64dbg-x64" / "Release"
    (src / "plugins").mkdir(parents=True)
    (src / "headless.exe").write_bytes(b"MZ new")
    (src / "plugins" / "stealth.dll").write_bytes(b"MZ plugin")
    dst = root / "external" / "x64dbg-x64"
    (dst / "old-dir").mkdir(parents=True)
    (dst / "old-dir" / "junk.bin").write_bytes(b"junk")
    (dst / "old-file.dll").write_bytes(b"stale")
    (dst / ".gitkeep").write_bytes(b"")

    result = _sync_one_arch("x64")

    assert result["ok"] is True
    assert result["copied"] is True
    assert (dst / "headless.exe").read_bytes() == b"MZ new"
    assert (dst / "plugins" / "stealth.dll").is_file()
    assert not (dst / "old-dir").exists()
    assert not (dst / "old-file.dll").exists()
    assert (dst / ".gitkeep").exists()


def test_sync_step_needs_only_one_arch_to_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = {"x64": True, "x86": False}
    monkeypatch.setattr(
        setup_mod, "_sync_one_arch", lambda arch: {"arch": arch, "ok": outcomes[arch]}
    )

    result = _step_sync_x64dbg(_settings(tmp_path))

    assert result["ok"] is True
    assert [item["arch"] for item in result["items"]] == ["x64", "x86"]


def test_probe_runtimes_prefers_freshly_discovered_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "x64" / "headless.exe"
    x64.parent.mkdir()
    x64.write_bytes(b"MZ")
    ida = tmp_path / "ida"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    refreshed = _settings(
        tmp_path, x64dbg_headless_x64=x64, x64dbg_headless_x86=None, ida_home=ida
    )
    monkeypatch.setattr(
        setup_mod.Settings, "load", staticmethod(lambda config_path=None: refreshed)
    )
    stale_x86 = tmp_path / "gone" / "headless.exe"
    stale = _settings(tmp_path, x64dbg_headless_x86=stale_x86)

    result = _step_probe_runtimes(stale)

    checks = {check["id"]: check for check in result["checks"]}
    assert checks["x64dbg_x64"]["ok"] is True
    assert checks["x64dbg_x86"]["ok"] is False
    assert checks["x64dbg_x86"]["path"] == str(stale_x86)
    assert checks["ida_home"]["ok"] is True
    assert result["ok"] is False


def test_probe_runtimes_without_any_paths_reports_them_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = _settings(tmp_path)
    monkeypatch.setattr(
        setup_mod.Settings, "load", staticmethod(lambda config_path=None: empty)
    )

    result = _step_probe_runtimes(empty)

    assert result["ok"] is False
    assert all(check["ok"] is False for check in result["checks"])
    assert all(check["path"] is None for check in result["checks"])


class _FakeProbe:
    def __init__(self, name: str, status: str) -> None:
        self._payload = {"name": name, "status": status}

    def to_dict(self) -> JsonObject:
        return dict(self._payload)


def test_doctor_step_counts_core_probes_and_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SimpleNamespace(
        ready=False,
        probes=[
            _FakeProbe("python", "ready"),
            _FakeProbe("ida_idalib", "missing"),
            _FakeProbe("x64dbg_headless_binaries", "ready"),
            _FakeProbe("upx", "blocked"),
            _FakeProbe("radare2", "detected"),
        ],
    )
    monkeypatch.setattr(setup_mod, "run_doctor", lambda settings: report)

    result = _step_doctor(_settings(tmp_path))

    assert result["ok"] is False
    assert result["core_total"] == 3
    assert result["core_ready_count"] == 2
    assert result["summary"] == {"ready": 2, "missing": 1, "blocked": 1, "detected": 1}


def test_persist_defaults_writes_every_discovered_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_update(updates: dict[str, Any], **kwargs: Any) -> Path:
        captured.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)
    settings = _settings(
        tmp_path,
        ida_home=tmp_path / "ida",
        x64dbg_headless_x64=tmp_path / "x64.exe",
        x64dbg_headless_x86=tmp_path / "x86.exe",
    )

    result = _step_persist_defaults(settings)

    assert result["ok"] is True
    assert captured["ida_home"] == str(tmp_path / "ida")
    assert captured["x64dbg_headless_x64"] == str(tmp_path / "x64.exe")
    assert captured["x64dbg_headless_x86"] == str(tmp_path / "x86.exe")
    assert captured["local_full_access"] is True
    assert "ida_home" in result["written_keys"]


def test_persist_defaults_omits_paths_that_were_never_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_update(updates: dict[str, Any], **kwargs: Any) -> Path:
        captured.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)

    result = _step_persist_defaults(_settings(tmp_path))

    assert result["ok"] is True
    assert "ida_home" not in captured
    assert "x64dbg_headless_x64" not in captured
    assert "x64dbg_headless_x86" not in captured
    assert captured["http_host"] == "127.0.0.1"


def test_generate_mcp_surfaces_the_bundle_and_cursor_snippet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = {
        "ok": True,
        "written": {"bundle": str(tmp_path / "mcp.json")},
        "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "env_inventory": [{"key": "HEADLESS_RE_IDA_HOME"}],
        "doctor_ready": True,
        "stdio": {"command": "python"},
    }
    monkeypatch.setattr(
        config_generate, "export_mcp_environment", lambda settings, persist: export
    )

    result = _step_generate_mcp(_settings(tmp_path))

    assert result["ok"] is True
    assert result["output"] == str(tmp_path / "mcp.json")
    assert result["has_examples"] is True
    assert result["server_keys"] == ["headless-re"]
    assert result["cursor_snippet"] == {"mcpServers": {"headless-re": {}}}


def test_generate_mcp_tolerates_an_empty_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        config_generate, "export_mcp_environment", lambda settings, persist: {}
    )

    result = _step_generate_mcp(_settings(tmp_path))

    assert result["ok"] is True
    assert result["output"] is None
    assert result["has_examples"] is False
    assert result["server_keys"] == []
    assert result["cursor_snippet"] is None


def _finalize_with_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_core: list[JsonObject]
) -> JsonObject:
    monkeypatch.setattr(
        setup_mod,
        "setup_status",
        lambda settings: {
            "ida_home": None,
            "x64dbg_headless_x64": None,
            "x64dbg_headless_x86": None,
            "config_path": str(tmp_path / "config.json"),
        },
    )
    monkeypatch.setattr(
        setup_mod,
        "build_deps_snapshot",
        lambda settings: {"missing_core": missing_core},
    )
    return _step_finalize(_settings(tmp_path))


def test_finalize_is_ok_when_nothing_core_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _finalize_with_missing(tmp_path, monkeypatch, [])

    assert result["ok"] is True
    assert result["missing_core"] == []
    assert "python start_web.py" in result["next_commands"]


def test_finalize_tolerates_only_a_missing_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _finalize_with_missing(tmp_path, monkeypatch, [{"id": "ida_home"}])

    assert result["ok"] is True


def test_finalize_fails_on_other_missing_core_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _finalize_with_missing(
        tmp_path, monkeypatch, [{"id": "x64dbg_x64"}, {"id": "ida_home"}]
    )

    assert result["ok"] is False


def test_run_setup_step_rejects_an_unknown_step(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "  bogus  ")

    assert result == {
        "ok": False,
        "step": "bogus",
        "code": "unknown_step",
        "message": "unknown setup step",
    }


def test_run_setup_step_dispatches_every_named_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for step in SETUP_STEPS:
        if step == "configure_ida":
            continue
        monkeypatch.setattr(
            setup_mod, f"_step_{step}", lambda settings, step=step: {"step": step}
        )

    settings = _settings(tmp_path)
    for step in SETUP_STEPS:
        if step == "configure_ida":
            continue
        assert run_setup_step(settings, step) == {"step": step}


def test_run_setup_step_probes_configure_ida_when_no_path_is_given(
    tmp_path: Path,
) -> None:
    ida = tmp_path / "ida"
    ida.mkdir()
    settings = _settings(tmp_path, ida_home=ida)

    result = run_setup_step(settings, "configure_ida")

    assert result["ok"] is True
    assert result["skipped"] is True
    assert result["ida_home"] == str(ida)

    without = run_setup_step(_settings(tmp_path), "configure_ida")
    assert without["ok"] is False
    assert without["ida_home"] is None


def test_run_setup_step_configures_ida_when_a_path_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_configure(*, ida_home: str, activate: bool) -> JsonObject:
        seen["ida_home"] = ida_home
        seen["activate"] = activate
        return {"ok": True, "saved": True}

    monkeypatch.setattr(setup_mod, "configure_ida", fake_configure)

    result = run_setup_step(
        _settings(tmp_path), "configure_ida", ida_home="/opt/ida", activate=False
    )

    assert result == {"step": "configure_ida", "ok": True, "saved": True}
    assert seen == {"ida_home": "/opt/ida", "activate": False}


def test_run_setup_step_refuses_a_listed_step_it_cannot_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The final fallthrough guards a SETUP_STEPS entry with no dispatcher."""
    monkeypatch.setattr(setup_mod, "SETUP_STEPS", ("mystery",))

    result = run_setup_step(_settings(tmp_path), "mystery")

    assert result == {"ok": False, "step": "mystery", "code": "unknown_step"}
