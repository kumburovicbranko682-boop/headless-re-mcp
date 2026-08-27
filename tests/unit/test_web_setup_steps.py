"""The install wizard's step results, driven through run_setup_step.

These steps are the first-run path: what they answer decides whether the
installer proceeds, retries, or stops. The existing tests pin the
configure_ida activation gate; everything else -- activation error mapping,
the x64dbg sync copy/discover/missing shapes, runtime probing, the config
write-through, MCP export shaping, doctor counting and the finalize gate --
ran on no hosted platform. External effects (config writes, doctor, MCP
export, binary discovery) are cut at the module seams the way the installer
tests do; the activation subprocess paths run a real script.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.doctor import ProbeStatus
from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import (
    SETUP_STEPS,
    activate_idalib,
    run_setup_step,
    setup_status,
)


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(settings, **overrides) if overrides else settings


def _fake_ida(tmp_path: Path, *, with_script: str | None = None) -> Path:
    home = tmp_path / "IDA Professional 9.9"
    home.mkdir(parents=True, exist_ok=True)
    (home / ida_library_names()[0]).write_bytes(b"MZ")
    if with_script is not None:
        script_dir = home / "idalib" / "python"
        script_dir.mkdir(parents=True, exist_ok=True)
        (script_dir / "py-activate-idalib.py").write_text(
            with_script, encoding="utf-8"
        )
    return home


def test_setup_status_reports_paths_and_the_probe(tmp_path: Path) -> None:
    status = setup_status(_settings(tmp_path))
    assert status["ok"] is True
    assert status["steps"] == list(SETUP_STEPS)
    assert status["ida_home"] is None
    assert status["never_bundle_ida"] is True
    assert status["probe"]["name"] == "ida_idalib"


def test_activation_without_the_script_is_refused_by_name(tmp_path: Path) -> None:
    home = _fake_ida(tmp_path)
    result = activate_idalib(home)
    assert result["ok"] is False
    assert result["code"] == "activation_script_missing"
    assert "py-activate-idalib.py" in result["script"]


def test_activation_success_and_nonzero_exit_are_distinguished(tmp_path: Path) -> None:
    ok_home = _fake_ida(tmp_path / "ok", with_script="print('activated')\n")
    result = activate_idalib(ok_home, timeout=60)
    assert result["ok"] is True
    assert result["code"] == "activated"
    assert "activated" in result["stdout"]

    bad_home = _fake_ida(
        tmp_path / "bad",
        with_script="import sys\nprint('boom', file=sys.stderr)\nsys.exit(2)\n",
    )
    result = activate_idalib(bad_home, timeout=60)
    assert result["ok"] is False
    assert result["code"] == "activation_exit_nonzero"
    assert result["exit_code"] == 2
    assert "boom" in result["stderr"]


def test_activation_timeout_is_reported_not_waited_out(tmp_path: Path) -> None:
    home = _fake_ida(
        tmp_path, with_script="import time\nwhile True: time.sleep(0.2)\n"
    )
    started = time.monotonic()
    result = activate_idalib(home, timeout=0.5)
    elapsed = time.monotonic() - started

    assert elapsed < 15, f"activation timeout took {elapsed:.1f}s to return"
    assert result["ok"] is False
    assert result["code"] == "timeout"
    assert isinstance(result["killed_pids"], list)


def test_activation_launch_failure_maps_to_activation_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _fake_ida(tmp_path, with_script="print('never runs')\n")

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise OSError("exec format error")

    monkeypatch.setattr(setup_mod, "run_bounded", refuse)
    result = activate_idalib(home)
    assert result["ok"] is False
    assert result["code"] == "activation_failed"
    assert "exec format error" in result["message"]


@pytest.mark.parametrize("step", ["bogus", "", "  "])
def test_unknown_steps_are_named_and_refused(tmp_path: Path, step: str) -> None:
    result = run_setup_step(_settings(tmp_path), step)
    assert result["ok"] is False
    assert result["code"] == "unknown_step"


def test_configure_ida_without_a_path_is_a_probe_not_a_write(tmp_path: Path) -> None:
    # No ida_home given: the step reports current state and must not save.
    result = run_setup_step(_settings(tmp_path), "configure_ida")
    assert result["skipped"] is True
    assert result["ok"] is False  # nothing configured yet

    configured = _settings(tmp_path, ida_home=tmp_path / "ida")
    result = run_setup_step(configured, "configure_ida")
    assert result["skipped"] is True
    assert result["ok"] is True


def test_environment_step_answers_ready_on_a_test_host(tmp_path: Path) -> None:
    result = run_setup_step(_settings(tmp_path), "environment")
    # The test host is by construction 3.11+ with the web extra installed.
    assert result["ok"] is True
    assert result["python"]["ok"] is True
    assert result["web_extra"]["ok"] is True
    assert result["paths"]["artifact_root"] == str(tmp_path / "artifacts")


def _repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(setup_mod, "repo_root", lambda: root)
    return root


def test_sync_reports_already_present_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path, monkeypatch)
    for arch in ("x64", "x86"):
        dst = root / "external" / f"x64dbg-{arch}"
        dst.mkdir(parents=True)
        (dst / "headless.exe").write_bytes(b"MZ")

    result = run_setup_step(_settings(tmp_path), "sync_x64dbg")
    assert result["ok"] is True
    assert all(item["already_present"] for item in result["items"])
    assert all(not item["copied"] for item in result["items"])


def test_sync_falls_back_to_discovery_without_copying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(tmp_path, monkeypatch)
    found = tmp_path / "elsewhere" / "headless.exe"
    found.parent.mkdir()
    found.write_bytes(b"MZ")
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: found)

    result = run_setup_step(_settings(tmp_path), "sync_x64dbg")
    assert result["ok"] is True
    for item in result["items"]:
        assert item["note"] == "discovered_existing"
        assert item["copied"] is False


def test_sync_names_the_missing_source_instead_of_half_succeeding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repo(tmp_path, monkeypatch)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)

    result = run_setup_step(_settings(tmp_path), "sync_x64dbg")
    assert result["ok"] is False
    for item in result["items"]:
        assert item["message"] == "source Release/headless.exe missing"


def test_sync_copies_the_release_and_clears_stale_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path, monkeypatch)
    monkeypatch.setattr(setup_mod, "discover_x64dbg_headless", lambda arch: None)
    for arch in ("x64", "x86"):
        src = root / "artifacts" / f"x64dbg-{arch}" / "Release"
        (src / "plugins").mkdir(parents=True)
        (src / "headless.exe").write_bytes(b"MZ new")
        (src / "plugins" / "dbg.dll").write_bytes(b"MZ plugin")
        dst = root / "external" / f"x64dbg-{arch}"
        dst.mkdir(parents=True)
        (dst / ".gitkeep").write_text("")
        (dst / "stale.dll").write_bytes(b"old")
        (dst / "stale_dir").mkdir()

    result = run_setup_step(_settings(tmp_path), "sync_x64dbg")
    assert result["ok"] is True
    for arch, item in zip(("x64", "x86"), result["items"], strict=True):
        assert item["copied"] is True and item["ok"] is True
        dst = root / "external" / f"x64dbg-{arch}"
        assert (dst / "headless.exe").read_bytes() == b"MZ new"
        assert (dst / "plugins" / "dbg.dll").is_file()
        assert (dst / ".gitkeep").is_file(), "the placeholder must survive"
        assert not (dst / "stale.dll").exists()
        assert not (dst / "stale_dir").exists()


def test_probe_runtimes_requires_both_debuggers_but_not_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    x64 = tmp_path / "x64" / "headless.exe"
    x64.parent.mkdir()
    x64.write_bytes(b"MZ")
    ida_without_lib = tmp_path / "ida-empty"
    ida_without_lib.mkdir()
    refreshed = _settings(
        tmp_path,
        ida_home=ida_without_lib,
        x64dbg_headless_x64=x64,
        x64dbg_headless_x86=tmp_path / "missing" / "headless.exe",
    )
    monkeypatch.setattr(
        setup_mod,
        "Settings",
        SimpleNamespace(load=lambda config_path=None: refreshed),
    )

    result = run_setup_step(_settings(tmp_path), "probe_runtimes")
    by_id = {check["id"]: check for check in result["checks"]}
    assert by_id["x64dbg_x64"]["ok"] is True
    assert by_id["x64dbg_x86"]["ok"] is False
    assert by_id["ida_home"]["ok"] is False  # dir exists but holds no idalib
    assert by_id["ida_home"]["never_bundle"] is True
    # Overall verdict tracks the debuggers only; IDA stays optional here.
    assert result["ok"] is False


def test_persist_defaults_writes_only_known_keys_through_the_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, Any] = {}

    def capture(updates: dict[str, Any], config_path: Path | None = None) -> Path:
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(setup_mod, "update_config_values", capture)
    settings = _settings(
        tmp_path,
        ida_home=tmp_path / "ida",
        x64dbg_headless_x64=tmp_path / "x64.exe",
    )

    result = run_setup_step(settings, "persist_defaults")
    assert result["ok"] is True
    assert written["local_full_access"] is True
    assert written["ida_home"] == str(tmp_path / "ida")
    assert "x64dbg_headless_x86" not in written  # unset stays unwritten
    assert result["written_keys"] == sorted(written.keys())


def test_generate_mcp_step_extracts_the_cursor_snippet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = {
        "ok": True,
        "written": {"bundle": str(tmp_path / "mcp.json")},
        "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
        "doctor_ready": False,
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist: export,
    )

    result = run_setup_step(_settings(tmp_path), "generate_mcp")
    assert result["ok"] is True
    assert result["output"] == str(tmp_path / "mcp.json")
    assert result["server_keys"] == ["headless-re"]
    assert result["doctor_ready"] is False


def test_doctor_step_counts_statuses_from_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def probe(name: str, status: ProbeStatus) -> SimpleNamespace:
        return SimpleNamespace(
            to_dict=lambda: {"name": name, "status": status.value}
        )

    report = SimpleNamespace(
        ready=False,
        probes=[
            probe("python", ProbeStatus.READY),
            probe("ida_idalib", ProbeStatus.MISSING),
            probe("x64dbg_headless_binaries", ProbeStatus.BLOCKED),
            probe("platform", ProbeStatus.DETECTED),
        ],
    )
    monkeypatch.setattr(setup_mod, "run_doctor", lambda settings: report)

    result = run_setup_step(_settings(tmp_path), "doctor")
    assert result["ok"] is False
    assert result["summary"] == {
        "ready": 1,
        "missing": 1,
        "blocked": 1,
        "detected": 1,
    }
    # Of the three core probes present, only python is ready.
    assert result["core_ready_count"] == 1
    assert result["core_total"] == 3


def test_finalize_gates_on_missing_core_except_optional_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    snapshots = [{"missing_core": [{"id": "ida_home"}]}]

    monkeypatch.setattr(
        setup_mod, "build_deps_snapshot", lambda s: snapshots[0]
    )
    result = run_setup_step(settings, "finalize")
    assert result["ok"] is True, "IDA alone missing must not block finalize"
    assert result["missing_core"] == [{"id": "ida_home"}]

    snapshots[0] = {"missing_core": [{"id": "x64dbg_headless_x64"}]}
    result = run_setup_step(settings, "finalize")
    assert result["ok"] is False
    assert "python start_web.py" in result["next_commands"]
