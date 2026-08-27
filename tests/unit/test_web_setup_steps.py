"""Coverage for the web install-wizard steps in headless_re_mcp.web.setup.

These exercise the Linux-reachable branches the IDA-focused suite leaves alone:
the per-step dispatch in ``run_setup_step``, the x64dbg tree sync
(``_sync_one_arch``), and the activation failure returns. Every external touch
(config writes, doctor, MCP export, IDA library discovery) is stubbed so the
wizard logic is what is under test, not the host it runs on.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import (
    _sync_one_arch,
    activate_idalib,
    configure_ida,
    run_setup_step,
)


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "ida_home": None,
        "x64dbg_source": None,
        "x64dbg_headless_x64": None,
        "x64dbg_headless_x86": None,
        "artifact_root": tmp_path / "artifacts",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


# --- activate_idalib -------------------------------------------------------


def test_activation_reports_a_missing_script_rather_than_launching(tmp_path: Path) -> None:
    home = tmp_path / "ida"
    (home / "idalib" / "python").mkdir(parents=True)
    result = activate_idalib(home)
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"
    assert result["script"].endswith("py-activate-idalib.py")


def test_activation_maps_a_launch_oserror_to_activation_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script_dir = tmp_path / "ida" / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('x')\n", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> object:
        raise OSError("cannot execute python")

    monkeypatch.setattr(setup_mod, "run_bounded", boom)
    result = activate_idalib(tmp_path / "ida")
    assert result["ok"] is False
    assert result["code"] == "activation_failed"
    assert "cannot execute python" in result["message"]


def test_activation_timeout_surfaces_the_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script_dir = tmp_path / "ida" / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('x')\n", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> object:
        raise TimedOut(0.5, [4321, 8765])

    monkeypatch.setattr(setup_mod, "run_bounded", boom)
    result = activate_idalib(tmp_path / "ida", timeout=0.5)
    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert result["timeout"] == 0.5
    assert result["killed_pids"] == [4321, 8765]


def test_activation_success_reports_exit_code_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script_dir = tmp_path / "ida" / "idalib" / "python"
    script_dir.mkdir(parents=True)
    (script_dir / "py-activate-idalib.py").write_text("print('x')\n", encoding="utf-8")

    class _Completed:
        returncode = 0
        stdout = b"activated fine"
        stderr = b""

    monkeypatch.setattr(setup_mod, "run_bounded", lambda *a, **k: _Completed())
    result = activate_idalib(tmp_path / "ida")
    assert result["ok"] is True
    assert result["code"] == "activated"
    assert result["exit_code"] == 0
    assert result["stdout"] == "activated fine"


# --- setup_status ----------------------------------------------------------


def test_setup_status_reports_paths_probe_and_dependency_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = SimpleNamespace(
        name="ida_idalib",
        status=SimpleNamespace(value="missing"),
        summary="idalib runtime not found",
        remediation="install IDA 9.x",
        details={"looked_in": []},
    )
    monkeypatch.setattr(setup_mod, "probe_ida", lambda _s: probe)
    monkeypatch.setattr(
        setup_mod, "build_deps_snapshot", lambda _s: {"counts": {"ready": 3}}
    )
    status = setup_mod.setup_status(
        _settings(
            tmp_path,
            ida_home=tmp_path / "ida",
            x64dbg_headless_x64=tmp_path / "hx64.exe",
        )
    )
    assert status["ok"] is True
    assert status["ida_home"] == str(tmp_path / "ida")
    assert status["x64dbg_headless_x64"] == str(tmp_path / "hx64.exe")
    assert status["x64dbg_headless_x86"] is None
    assert status["probe"]["status"] == "missing"
    assert status["probe"]["message"] == status["probe"]["summary"]
    assert status["deps_counts"] == {"ready": 3}
    assert status["steps"] == list(setup_mod.SETUP_STEPS)


# --- configure_ida ---------------------------------------------------------


def test_configure_ida_reports_validation_failure_without_saving(tmp_path: Path) -> None:
    result = configure_ida(
        ida_home=tmp_path / "does-not-exist",
        activate=False,
        config_path=tmp_path / "config.json",
    )
    assert result["ok"] is False
    assert result["saved"] is False
    assert result["activation"] is None
    assert result["validation"]["ok"] is False


# --- _sync_one_arch --------------------------------------------------------


def test_sync_reports_an_already_present_binary_without_copying(
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


def test_sync_falls_back_to_a_discovered_binary_when_source_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    found = tmp_path / "runtime" / "headless.exe"
    found.parent.mkdir(parents=True)
    found.write_bytes(b"MZ")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: found)
    result = _sync_one_arch("x86")
    assert result["ok"] is True
    assert result["copied"] is False
    assert result["note"] == "discovered_existing"
    assert result["headless"] == str(found)


def test_sync_reports_a_missing_source_when_nothing_is_discoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: None)
    result = _sync_one_arch("x64")
    assert result["ok"] is False
    assert result["copied"] is False
    assert "missing" in result["message"]


def test_sync_copies_the_release_tree_and_clears_stale_destination_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    src = tmp_path / "artifacts" / "x64dbg-x64" / "Release"
    src.mkdir(parents=True)
    (src / "headless.exe").write_bytes(b"MZ")
    (src / "plugin.dll").write_bytes(b"..")
    (src / "sub").mkdir()
    (src / "sub" / "note.txt").write_text("keep me", encoding="utf-8")

    dst = tmp_path / "external" / "x64dbg-x64"
    dst.mkdir(parents=True)
    (dst / ".gitkeep").write_text("", encoding="utf-8")  # preserved
    (dst / "stale.txt").write_text("old", encoding="utf-8")  # cleared
    (dst / "oldsub").mkdir()  # cleared

    result = _sync_one_arch("x64")

    assert result["copied"] is True
    assert result["ok"] is True
    assert (dst / "headless.exe").is_file()
    assert (dst / "plugin.dll").is_file()
    assert (dst / "sub" / "note.txt").read_text(encoding="utf-8") == "keep me"
    assert (dst / ".gitkeep").exists()
    assert not (dst / "stale.txt").exists()
    assert not (dst / "oldsub").exists()


# --- run_setup_step dispatch ----------------------------------------------


def test_unknown_step_is_reported_not_raised(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "not-a-real-step")
    assert result["ok"] is False
    assert result["code"] == "unknown_step"


def test_environment_step_reports_python_and_platform(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "environment")
    assert result["step"] == "environment"
    assert result["python"]["ok"] is True
    assert result["platform"]["system"]
    assert result["web_extra"]["ok"] is True


def test_environment_step_flags_a_missing_web_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A None entry in sys.modules makes the import statement raise ImportError,
    # which is exactly the "web extra not installed" case the step must report.
    monkeypatch.setitem(sys.modules, "fastapi", None)
    result = run_setup_step(_settings(tmp_path), "environment")
    assert result["web_extra"]["ok"] is False
    assert result["web_extra"]["error"]
    assert result["ok"] is False


def test_sync_step_runs_both_arches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda _arch: None)
    result = run_setup_step(_settings(tmp_path), "sync_x64dbg")
    assert result["step"] == "sync_x64dbg"
    assert result["ok"] is False
    assert [item["arch"] for item in result["items"]] == ["x64", "x86"]


def test_probe_runtimes_prefers_reloaded_paths_then_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reloaded = _settings(tmp_path)  # nothing configured on disk
    monkeypatch.setattr(
        Settings,
        "load",
        staticmethod(lambda config_path=None: reloaded),
    )
    monkeypatch.setattr(setup_mod, "find_idalib_library", lambda home: home / "libida.so")
    x64 = tmp_path / "headless-x64.exe"
    x64.write_bytes(b"MZ")
    x86 = tmp_path / "headless-x86.exe"
    x86.write_bytes(b"MZ")
    ida = tmp_path / "ida"
    ida.mkdir()
    passed = _settings(
        tmp_path, x64dbg_headless_x64=x64, x64dbg_headless_x86=x86, ida_home=ida
    )
    result = run_setup_step(passed, "probe_runtimes")
    assert result["settings_reloaded"] is True
    by_id = {check["id"]: check for check in result["checks"]}
    assert by_id["x64dbg_x64"]["ok"] is True
    assert by_id["x64dbg_x86"]["ok"] is True
    assert by_id["ida_home"]["ok"] is True
    assert result["ok"] is True


def test_probe_runtimes_marks_ida_missing_when_no_runtime_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reloaded = _settings(tmp_path)
    monkeypatch.setattr(
        Settings,
        "load",
        staticmethod(lambda config_path=None: reloaded),
    )
    monkeypatch.setattr(setup_mod, "find_idalib_library", lambda home: None)
    ida = tmp_path / "ida"
    ida.mkdir()
    result = run_setup_step(_settings(tmp_path, ida_home=ida), "probe_runtimes")
    by_id = {check["id"]: check for check in result["checks"]}
    assert by_id["ida_home"]["ok"] is False
    # ok is judged on the x64dbg checks only; both are absent here.
    assert result["ok"] is False


class _FakeProbe:
    def __init__(self, name: str, status: str) -> None:
        self._payload = {"name": name, "status": status}

    def to_dict(self) -> dict[str, object]:
        return dict(self._payload)


class _FakeDoctorReport:
    def __init__(self, ready: bool, probes: list[_FakeProbe]) -> None:
        self.ready = ready
        self.probes = probes


def test_doctor_step_counts_core_and_summarises_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probes = [
        _FakeProbe("python", "ready"),
        _FakeProbe("ida_idalib", "missing"),
        _FakeProbe("x64dbg_headless_binaries", "ready"),
        _FakeProbe("diec", "detected"),
        _FakeProbe("cdb", "blocked"),
    ]
    monkeypatch.setattr(
        setup_mod, "run_doctor", lambda _s: _FakeDoctorReport(False, probes)
    )
    result = run_setup_step(_settings(tmp_path), "doctor")
    assert result["step"] == "doctor"
    assert result["ready"] is False
    assert result["core_total"] == 3
    assert result["core_ready_count"] == 2
    assert result["summary"] == {
        "ready": 2,
        "missing": 1,
        "blocked": 1,
        "detected": 1,
    }


def test_persist_defaults_writes_optional_tool_paths_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: dict[str, object] = {}

    def fake_update(updates: dict[str, object], *, config_path: Path | None = None) -> Path:
        recorded.update(updates)
        return tmp_path / "written-config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)
    ida = tmp_path / "ida"
    ida.mkdir()
    x64 = tmp_path / "x64.exe"
    x64.write_bytes(b"MZ")
    x86 = tmp_path / "x86.exe"
    x86.write_bytes(b"MZ")
    passed = _settings(
        tmp_path, ida_home=ida, x64dbg_headless_x64=x64, x64dbg_headless_x86=x86
    )
    result = run_setup_step(passed, "persist_defaults")
    assert result["ok"] is True
    assert result["config_path"] == str(tmp_path / "written-config.json")
    assert "ida_home" in result["written_keys"]
    assert "x64dbg_headless_x64" in result["written_keys"]
    assert recorded["ida_home"] == str(ida)
    assert recorded["local_full_access"] is True


def test_persist_defaults_omits_optional_paths_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: dict[str, object] = {}

    def fake_update(updates: dict[str, object], *, config_path: Path | None = None) -> Path:
        recorded.update(updates)
        return tmp_path / "written-config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", fake_update)
    result = run_setup_step(_settings(tmp_path), "persist_defaults")
    assert result["ok"] is True
    assert "ida_home" not in result["written_keys"]
    assert "x64dbg_headless_x64" not in result["written_keys"]
    assert recorded["http_host"] == "127.0.0.1"


def test_generate_mcp_step_surfaces_bundle_and_cursor_servers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import headless_re_mcp.config_generate as config_generate

    export = {
        "ok": True,
        "written": {"bundle": "/tmp/mcp-bundle.json"},
        "examples": {"cursor": {"mcpServers": {"headless-re": {"command": "python"}}}},
        "embedded_env_keys": ["HEADLESS_RE_IDA_HOME"],
        "env_inventory": [{"key": "HEADLESS_RE_IDA_HOME"}],
        "doctor_ready": True,
        "stdio": {"command": "python"},
    }
    monkeypatch.setattr(
        config_generate, "export_mcp_environment", lambda _s, persist=True: export
    )
    result = run_setup_step(_settings(tmp_path), "generate_mcp")
    assert result["ok"] is True
    assert result["output"] == "/tmp/mcp-bundle.json"
    assert result["has_examples"] is True
    assert result["server_keys"] == ["headless-re"]
    assert result["embedded_env_keys"] == ["HEADLESS_RE_IDA_HOME"]


def test_finalize_step_is_ready_when_no_core_dependency_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        setup_mod,
        "setup_status",
        lambda _s: {
            "ida_home": "/opt/ida",
            "x64dbg_headless_x64": "/opt/x64",
            "x64dbg_headless_x86": "/opt/x86",
            "config_path": "/opt/config.json",
        },
    )
    monkeypatch.setattr(setup_mod, "build_deps_snapshot", lambda _s: {"missing_core": []})
    result = run_setup_step(_settings(tmp_path), "finalize")
    assert result["ok"] is True
    assert result["ida_home"] == "/opt/ida"
    assert "python start_web.py" in result["next_commands"]


def test_finalize_step_treats_a_missing_ida_home_as_acceptable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "setup_status", lambda _s: {})
    monkeypatch.setattr(
        setup_mod,
        "build_deps_snapshot",
        lambda _s: {"missing_core": [{"id": "ida_home"}]},
    )
    result = run_setup_step(_settings(tmp_path), "finalize")
    assert result["ok"] is True


def test_finalize_step_blocks_on_a_missing_non_ida_core_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup_mod, "setup_status", lambda _s: {})
    monkeypatch.setattr(
        setup_mod,
        "build_deps_snapshot",
        lambda _s: {"missing_core": [{"id": "x64dbg_headless_x64"}]},
    )
    result = run_setup_step(_settings(tmp_path), "finalize")
    assert result["ok"] is False


def test_configure_ida_step_soft_probes_when_no_path_is_given(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "configure_ida", ida_home=None)
    assert result["step"] == "configure_ida"
    assert result["skipped"] is True
    assert result["ok"] is False  # nothing configured yet
    assert result["ida_home"] is None


def test_configure_ida_step_dispatches_to_configure_ida(tmp_path: Path) -> None:
    result = run_setup_step(
        _settings(tmp_path), "configure_ida", ida_home=str(tmp_path / "missing-ida")
    )
    assert result["step"] == "configure_ida"
    assert result["ok"] is False
    assert result["validation"]["ok"] is False
