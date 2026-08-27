"""Install-wizard steps in web/setup.py: status, activation, sync, dispatch.

Everything here is cross-platform orchestration: external effects (probe_ida,
run_doctor, run_bounded, update_config_values, export_mcp_environment) are
monkeypatched so each step's ok/shape logic is exercised deterministically.
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
from headless_re_mcp.doctor import ProbeStatus
from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import (
    SETUP_STEPS,
    activate_idalib,
    configure_ida,
    run_setup_step,
    setup_status,
)


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides) if overrides else base


def _fake_probe(status: ProbeStatus = ProbeStatus.MISSING) -> SimpleNamespace:
    return SimpleNamespace(
        name="ida_idalib",
        status=status,
        summary="idalib summary",
        remediation="install IDA",
        details={"hint": 1},
    )


# ---------------------------------------------------------------------------
# _no_window_flags / setup_status
# ---------------------------------------------------------------------------


def test_no_window_flags_covers_both_platform_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert setup_mod._no_window_flags() == 0
    monkeypatch.setattr(os, "name", "nt")
    expected = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert setup_mod._no_window_flags() == expected


def test_setup_status_reports_probe_paths_and_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "probe_ida", lambda s: _fake_probe())
    monkeypatch.setattr(setup_mod, "build_deps_snapshot", lambda s: {"counts": {"missing": 2}})
    monkeypatch.setenv("HEADLESS_RE_IDA_HOME", str(tmp_path))
    ida_home = tmp_path / "ida"
    x64 = tmp_path / "headless64.exe"

    status = setup_status(_settings(tmp_path, ida_home=ida_home, x64dbg_headless_x64=x64))

    assert status["ok"] is True
    assert status["steps"] == list(SETUP_STEPS)
    assert status["ida_home"] == str(ida_home)
    assert status["x64dbg_headless_x64"] == str(x64)
    assert status["x64dbg_headless_x86"] is None
    assert status["env_override"] is True
    assert status["probe"]["status"] == "missing"
    assert status["probe"]["message"] == "idalib summary"
    assert status["deps_counts"] == {"missing": 2}
    assert status["never_bundle_ida"] is True
    assert status["claims_universal_unpack"] is False


# ---------------------------------------------------------------------------
# activate_idalib
# ---------------------------------------------------------------------------


def _make_activation_script(tmp_path: Path) -> Path:
    ida_home = tmp_path / "ida"
    script_dir = ida_home / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('hi')\n", "utf-8")
    return ida_home


def test_activate_idalib_reports_a_missing_script(tmp_path: Path) -> None:
    result = activate_idalib(tmp_path / "ida")
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"
    assert result["script"].endswith("py-activate-idalib.py")


def test_activate_idalib_success_decodes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida_home = _make_activation_script(tmp_path)
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], *, timeout: float, creationflags: int) -> Any:
        captured["command"] = command
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout=b"activated!", stderr=b"warn")

    monkeypatch.setattr(setup_mod, "run_bounded", fake_run)

    result = activate_idalib(ida_home, timeout=33.0)

    assert result["ok"] is True
    assert result["code"] == "activated"
    assert result["exit_code"] == 0
    assert result["stdout"] == "activated!"
    assert result["stderr"] == "warn"
    assert result["python"] == sys.executable
    assert captured["timeout"] == 33.0
    assert captured["command"][0] == sys.executable
    assert "--ida-install-dir" in captured["command"]


def test_activate_idalib_nonzero_exit_is_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida_home = _make_activation_script(tmp_path)
    monkeypatch.setattr(
        setup_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(returncode=3, stdout=b"", stderr=b"boom"),
    )
    result = activate_idalib(ida_home)
    assert result["ok"] is False
    assert result["code"] == "activation_exit_nonzero"
    assert result["exit_code"] == 3


def test_activate_idalib_timeout_reports_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida_home = _make_activation_script(tmp_path)

    def raise_timeout(*a: Any, **k: Any) -> Any:
        raise TimedOut(timeout=1.5, killed=[11, 22])

    monkeypatch.setattr(setup_mod, "run_bounded", raise_timeout)
    result = activate_idalib(ida_home)
    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert result["timeout"] == 1.5
    assert result["killed_pids"] == [11, 22]
    assert "1.5s" in result["message"]


def test_activate_idalib_oserror_reports_activation_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ida_home = _make_activation_script(tmp_path)

    def raise_oserror(*a: Any, **k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(setup_mod, "run_bounded", raise_oserror)
    result = activate_idalib(ida_home)
    assert result["ok"] is False
    assert result["code"] == "activation_failed"
    assert result["message"] == "exec format error"


def test_configure_ida_rejects_a_failed_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        setup_mod,
        "validate_ida_home",
        lambda home: {"ok": False, "message": "not an IDA install"},
    )
    result = configure_ida(ida_home="/nope", activate=True)
    assert result == {
        "ok": False,
        "saved": False,
        "validation": {"ok": False, "message": "not an IDA install"},
        "activation": None,
    }


# ---------------------------------------------------------------------------
# _step_environment
# ---------------------------------------------------------------------------


def test_step_environment_reports_python_and_web_extra(tmp_path: Path) -> None:
    result = setup_mod._step_environment(_settings(tmp_path))
    assert result["step"] == "environment"
    assert result["python"]["ok"] is True
    assert result["web_extra"] == {"ok": True, "error": None}
    assert result["ok"] is True
    assert result["paths"]["artifact_root"] == str(tmp_path / "artifacts")
    assert result["claims_universal_unpack"] is False


def test_step_environment_reports_a_missing_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # None in sys.modules makes "import fastapi" raise ImportError.
    monkeypatch.setitem(sys.modules, "fastapi", None)
    result = setup_mod._step_environment(_settings(tmp_path))
    assert result["ok"] is False
    assert result["web_extra"]["ok"] is False
    assert "fastapi" in result["web_extra"]["error"]


# ---------------------------------------------------------------------------
# _sync_one_arch / _step_sync_x64dbg
# ---------------------------------------------------------------------------


def test_sync_one_arch_short_circuits_when_already_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / "headless.exe").write_bytes(b"MZ")

    result = setup_mod._sync_one_arch("x64")

    assert result["already_present"] is True
    assert result["ok"] is True
    assert result["copied"] is False
    assert result["headless"] == str((dst / "headless.exe").resolve())


def test_sync_one_arch_falls_back_to_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    found = tmp_path / "elsewhere" / "headless.exe"
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: found)

    result = setup_mod._sync_one_arch("x86")

    assert result["ok"] is True
    assert result["copied"] is False
    assert result["headless"] == str(found)
    assert result["note"] == "discovered_existing"


def test_sync_one_arch_reports_a_missing_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)

    result = setup_mod._sync_one_arch("x64")

    assert result["ok"] is False
    assert result["copied"] is False
    assert result["message"] == "source Release/headless.exe missing"


def test_sync_one_arch_copies_the_release_tree_and_clears_stale_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    src = tmp_path / "artifacts" / "x64dbg-x64" / "Release"
    (src / "plugins").mkdir(parents=True)
    (src / "headless.exe").write_bytes(b"MZ new")
    (src / "plugins" / "helper.dll").write_bytes(b"dll")
    dst = tmp_path / "external" / "x64dbg-x64"
    (dst / "stale-dir").mkdir(parents=True)
    (dst / ".gitkeep").write_bytes(b"")
    (dst / "stale.dll").write_bytes(b"old")

    result = setup_mod._sync_one_arch("x64")

    assert result["copied"] is True
    assert result["ok"] is True
    assert (dst / "headless.exe").read_bytes() == b"MZ new"
    assert (dst / "plugins" / "helper.dll").read_bytes() == b"dll"
    assert (dst / ".gitkeep").exists()
    assert not (dst / "stale.dll").exists()
    assert not (dst / "stale-dir").exists()


def test_step_sync_x64dbg_is_ok_when_any_arch_synced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod, "_sync_one_arch", lambda arch: {"arch": arch, "ok": arch == "x64"}
    )
    result = setup_mod._step_sync_x64dbg(_settings(tmp_path))
    assert result["ok"] is True
    assert [item["arch"] for item in result["items"]] == ["x64", "x86"]
    assert result["never_bundle_ida"] is True

    monkeypatch.setattr(setup_mod, "_sync_one_arch", lambda arch: {"arch": arch, "ok": False})
    assert setup_mod._step_sync_x64dbg(_settings(tmp_path))["ok"] is False


# ---------------------------------------------------------------------------
# _step_probe_runtimes
# ---------------------------------------------------------------------------


def test_step_probe_runtimes_prefers_refreshed_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "x64" / "headless.exe"
    x64.parent.mkdir()
    x64.write_bytes(b"MZ")
    ida = tmp_path / "ida"
    ida.mkdir()
    refreshed = SimpleNamespace(x64dbg_headless_x64=x64, x64dbg_headless_x86=None, ida_home=ida)
    monkeypatch.setattr(setup_mod, "Settings", SimpleNamespace(load=lambda: refreshed))
    monkeypatch.setattr(setup_mod, "find_idalib_library", lambda home: home / "libida.so")
    # x86 falls back to the passed-in settings; that file is missing.
    settings = _settings(tmp_path, x64dbg_headless_x86=tmp_path / "missing86.exe")

    result = setup_mod._step_probe_runtimes(settings)

    checks = {c["id"]: c for c in result["checks"]}
    assert checks["x64dbg_x64"]["ok"] is True
    assert checks["x64dbg_x86"]["ok"] is False
    assert checks["x64dbg_x86"]["path"] == str(tmp_path / "missing86.exe")
    assert checks["ida_home"]["ok"] is True
    assert checks["ida_home"]["never_bundle"] is True
    assert result["ok"] is False  # x86 binary missing blocks the step
    assert result["settings_reloaded"] is True


def test_step_probe_runtimes_is_ok_with_both_x64dbg_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "headless64.exe"
    x86 = tmp_path / "headless86.exe"
    x64.write_bytes(b"MZ")
    x86.write_bytes(b"MZ")
    refreshed = SimpleNamespace(x64dbg_headless_x64=x64, x64dbg_headless_x86=x86, ida_home=None)
    monkeypatch.setattr(setup_mod, "Settings", SimpleNamespace(load=lambda: refreshed))
    result = setup_mod._step_probe_runtimes(_settings(tmp_path))
    assert result["ok"] is True
    checks = {c["id"]: c for c in result["checks"]}
    assert checks["ida_home"] == {
        "id": "ida_home",
        "ok": False,
        "path": None,
        "packable": False,
        "never_bundle": True,
    }


# ---------------------------------------------------------------------------
# _step_doctor
# ---------------------------------------------------------------------------


class _FakeProbeReportEntry:
    def __init__(self, name: str, status: ProbeStatus) -> None:
        self._payload = {"name": name, "status": status}

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


def test_step_doctor_counts_core_and_summary_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SimpleNamespace(
        ready=False,
        probes=[
            _FakeProbeReportEntry("python", ProbeStatus.READY),
            _FakeProbeReportEntry("ida_idalib", ProbeStatus.MISSING),
            _FakeProbeReportEntry("x64dbg_headless_binaries", ProbeStatus.READY),
            _FakeProbeReportEntry("frida", ProbeStatus.DETECTED),
            _FakeProbeReportEntry("proxy", ProbeStatus.BLOCKED),
        ],
    )
    monkeypatch.setattr(setup_mod, "run_doctor", lambda s: report)

    result = setup_mod._step_doctor(_settings(tmp_path))

    assert result["ok"] is False
    assert result["ready"] is False
    assert result["core_ready_count"] == 2
    assert result["core_total"] == 3
    assert result["summary"] == {
        "ready": 2,
        "missing": 1,
        "blocked": 1,
        "detected": 1,
    }


# ---------------------------------------------------------------------------
# _step_persist_defaults
# ---------------------------------------------------------------------------


def test_step_persist_defaults_writes_known_paths_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, Any] = {}

    def fake_update(updates: dict[str, Any]) -> Path:
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)
    settings = _settings(
        tmp_path,
        ida_home=tmp_path / "ida",
        x64dbg_headless_x64=tmp_path / "headless64.exe",
    )

    result = setup_mod._step_persist_defaults(settings)

    assert result["ok"] is True
    assert result["config_path"] == str(tmp_path / "config.json")
    assert "x64dbg_headless_x86" not in written
    assert written["ida_home"] == str(tmp_path / "ida")
    assert written["x64dbg_headless_x64"] == str(tmp_path / "headless64.exe")
    assert written["local_full_access"] is True
    assert written["hidden_desktop"] is True
    assert result["written_keys"] == sorted(written.keys())


def test_step_persist_defaults_skips_unset_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, Any] = {}

    def fake_update(updates: dict[str, Any]) -> Path:
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)
    settings = _settings(tmp_path, x64dbg_headless_x86=tmp_path / "headless86.exe")

    result = setup_mod._step_persist_defaults(settings)

    assert result["ok"] is True
    assert "ida_home" not in written
    assert "x64dbg_headless_x64" not in written
    assert written["x64dbg_headless_x86"] == str(tmp_path / "headless86.exe")


# ---------------------------------------------------------------------------
# _step_generate_mcp
# ---------------------------------------------------------------------------


def test_step_generate_mcp_extracts_the_cursor_snippet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = {
        "ok": True,
        "written": {"bundle": str(tmp_path / "mcp.json")},
        "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "env_inventory": [{"key": "PYTHONPATH"}],
        "doctor_ready": True,
        "stdio": {"command": "python"},
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist: export,
    )

    result = setup_mod._step_generate_mcp(_settings(tmp_path))

    assert result["ok"] is True
    assert result["output"] == str(tmp_path / "mcp.json")
    assert result["has_examples"] is True
    assert result["cursor_snippet"] == {"mcpServers": {"headless-re": {}}}
    assert result["server_keys"] == ["headless-re"]
    assert result["embedded_env_keys"] == ["HEADLESS_RE_IDA_HOME"]


def test_step_generate_mcp_tolerates_an_empty_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist: {"ok": False},
    )
    result = setup_mod._step_generate_mcp(_settings(tmp_path))
    assert result["ok"] is False
    assert result["output"] is None
    assert result["has_examples"] is False
    assert result["cursor_snippet"] is None
    assert result["server_keys"] == []


# ---------------------------------------------------------------------------
# _step_finalize
# ---------------------------------------------------------------------------


def _patch_finalize_deps(
    monkeypatch: pytest.MonkeyPatch, missing_core: list[dict[str, Any]]
) -> None:
    monkeypatch.setattr(setup_mod, "probe_ida", lambda s: _fake_probe())
    monkeypatch.setattr(
        setup_mod,
        "build_deps_snapshot",
        lambda s: {"counts": {}, "missing_core": missing_core},
    )


def test_step_finalize_is_ok_when_only_ida_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_finalize_deps(monkeypatch, [{"id": "ida_home"}])
    result = setup_mod._step_finalize(_settings(tmp_path))
    assert result["ok"] is True
    assert result["missing_core"] == [{"id": "ida_home"}]
    assert "python start_web.py" in result["next_commands"]


def test_step_finalize_fails_when_a_core_runtime_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_finalize_deps(monkeypatch, [{"id": "ida_home"}, {"id": "x64dbg_headless_x64"}])
    result = setup_mod._step_finalize(_settings(tmp_path))
    assert result["ok"] is False


def test_step_finalize_is_ok_with_nothing_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_finalize_deps(monkeypatch, [])
    result = setup_mod._step_finalize(_settings(tmp_path))
    assert result["ok"] is True
    assert result["claims_universal_unpack"] is False


# ---------------------------------------------------------------------------
# run_setup_step dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("step", "func_name"),
    [
        ("environment", "_step_environment"),
        ("sync_x64dbg", "_step_sync_x64dbg"),
        ("probe_runtimes", "_step_probe_runtimes"),
        ("doctor", "_step_doctor"),
        ("persist_defaults", "_step_persist_defaults"),
        ("generate_mcp", "_step_generate_mcp"),
        ("finalize", "_step_finalize"),
    ],
)
def test_run_setup_step_dispatches_each_named_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str, func_name: str
) -> None:
    marker = {"ok": True, "step": step, "marker": True}
    monkeypatch.setattr(setup_mod, func_name, lambda s: marker)
    assert run_setup_step(_settings(tmp_path), f"  {step} ") is marker


def test_run_setup_step_rejects_an_unknown_step(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "bogus")
    assert result == {
        "ok": False,
        "step": "bogus",
        "code": "unknown_step",
        "message": "unknown setup step",
    }
    assert run_setup_step(_settings(tmp_path), "")["code"] == "unknown_step"


def test_run_setup_step_configure_ida_probes_when_path_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "list_ida_install_candidates", lambda: [])

    absent = run_setup_step(_settings(tmp_path), "configure_ida")
    assert absent["ok"] is False
    assert absent["skipped"] is True
    assert absent["ida_home"] is None

    configured = run_setup_step(_settings(tmp_path, ida_home=tmp_path / "ida"), "configure_ida")
    assert configured["ok"] is True
    assert configured["ida_home"] == str(tmp_path / "ida")


def test_run_setup_step_configure_ida_delegates_with_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_configure(*, ida_home: str, activate: bool) -> dict[str, Any]:
        captured["ida_home"] = ida_home
        captured["activate"] = activate
        return {"ok": True, "saved": True}

    monkeypatch.setattr(setup_mod, "configure_ida", fake_configure)

    result = run_setup_step(
        _settings(tmp_path), "configure_ida", ida_home="/opt/ida", activate=False
    )

    assert result == {"step": "configure_ida", "ok": True, "saved": True}
    assert captured == {"ida_home": "/opt/ida", "activate": False}
