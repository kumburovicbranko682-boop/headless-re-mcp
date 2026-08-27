"""Coverage for the first-run configuration bootstrap (``native_app.bootstrap``).

The module wires the CLI/GUI setup flow over lazily imported config and setup
helpers. Tests patch those helpers on their real modules (the imports bind at
call time) and drive the interactive path with scripted ``input``/``print``,
so path resolution, the IDA re-check, and the end-to-end wizard run for real
without touching the operator's config or Qt.
"""

from __future__ import annotations

import builtins
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.config as config
import headless_re_mcp.config_generate as config_generate
import headless_re_mcp.doctor as doctor_module
import headless_re_mcp.web.setup as web_setup
from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.native_app import bootstrap


@pytest.fixture(autouse=True)
def _preserve_process_state() -> Any:
    """``ensure_repo_on_path`` chdirs and edits sys.path; undo both."""
    cwd = os.getcwd()
    path = list(sys.path)
    try:
        yield
    finally:
        os.chdir(cwd)
        sys.path[:] = path


def _fake_settings(**overrides: Any) -> SimpleNamespace:
    base = {
        "ida_home": Path("/opt/ida"),
        "x64dbg_headless_x64": Path("/opt/x64/headless.exe"),
        "x64dbg_headless_x86": Path("/opt/x86/headless.exe"),
        "upx": Path("/opt/upx"),
        "diec": Path("/opt/diec"),
        "r2": Path("/opt/r2"),
        "cdb": Path("/opt/cdb"),
        "ghidra_home": Path("/opt/ghidra"),
        "de4dot": Path("/opt/de4dot"),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _pin_settings(monkeypatch: pytest.MonkeyPatch, settings: SimpleNamespace) -> None:
    monkeypatch.setattr(config.Settings, "load", staticmethod(lambda **kwargs: settings))


# ---------------------------------------------------------------------------
# ensure_repo_on_path
# ---------------------------------------------------------------------------


def test_ensure_repo_on_path_uses_the_source_tree() -> None:
    root = bootstrap.ensure_repo_on_path()
    assert (root / "src" / "headless_re_mcp").is_dir()
    assert str(root / "src") in sys.path
    assert Path(os.getcwd()) == root


def test_ensure_repo_on_path_falls_back_to_repo_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A __file__ whose parents[3] is not a checkout forces the fallback.
    fake_file = tmp_path / "site" / "pkg" / "native_app" / "bootstrap.py"
    fake_file.parent.mkdir(parents=True)
    monkeypatch.setattr(bootstrap, "__file__", str(fake_file))

    checkout = tmp_path / "checkout"
    (checkout / "src").mkdir(parents=True)
    monkeypatch.setattr(config, "repo_root", lambda: checkout)

    root = bootstrap.ensure_repo_on_path()

    assert root == checkout
    assert str(checkout / "src") in sys.path
    assert Path(os.getcwd()) == checkout


def test_ensure_repo_on_path_tolerates_a_missing_src_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_file = tmp_path / "site" / "pkg" / "native_app" / "bootstrap.py"
    fake_file.parent.mkdir(parents=True)
    monkeypatch.setattr(bootstrap, "__file__", str(fake_file))

    checkout = tmp_path / "checkout"
    checkout.mkdir()  # no src/ underneath
    monkeypatch.setattr(config, "repo_root", lambda: checkout)

    root = bootstrap.ensure_repo_on_path()

    assert root == checkout
    assert str(checkout / "src") not in sys.path, "a missing src dir is not added to the path"


# ---------------------------------------------------------------------------
# discover_defaults
# ---------------------------------------------------------------------------


def test_discover_defaults_prefers_probes_over_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(config, "discover_ida_home", lambda: Path("/probed/ida"))
    monkeypatch.setattr(
        config,
        "discover_x64dbg_headless",
        lambda arch: Path(f"/probed/{arch}.exe"),
    )
    monkeypatch.setattr(config, "list_ida_install_candidates", lambda: [Path("/c1")])

    defaults = bootstrap.discover_defaults()

    assert defaults["ida_home"] == Path("/probed/ida"), "a live probe wins over the stored value"
    assert defaults["x64dbg_headless_x64"] == Path("/probed/x64.exe")
    assert defaults["ida_candidates"] == [Path("/c1")]
    assert defaults["cdb"] == Path("/opt/cdb"), "unprobed tools fall back to settings"


def test_discover_defaults_falls_back_when_probes_are_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(config, "discover_ida_home", lambda: None)
    monkeypatch.setattr(config, "discover_x64dbg_headless", lambda arch: None)
    monkeypatch.setattr(config, "list_ida_install_candidates", lambda: [])

    defaults = bootstrap.discover_defaults()

    assert defaults["ida_home"] == Path("/opt/ida")
    assert defaults["x64dbg_headless_x86"] == Path("/opt/x86/headless.exe")


# ---------------------------------------------------------------------------
# apply_paths
# ---------------------------------------------------------------------------


def test_apply_paths_writes_cleaned_config_and_activates_ida(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    written: dict[str, Any] = {}

    def fake_update(values: dict[str, Any]) -> Path:
        written.update(values)
        return config_path

    activation_calls: list[dict[str, Any]] = []

    def fake_configure_ida(**kwargs: Any) -> dict[str, Any]:
        activation_calls.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr(config, "update_config_values", fake_update)
    monkeypatch.setattr(config, "default_config_path", lambda: tmp_path / "default.json")
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(web_setup, "configure_ida", fake_configure_ida)

    result = bootstrap.apply_paths(
        {"ida_home": str(tmp_path / "ida"), "upx": None, "r2": ""},
        activate_ida=True,
    )

    assert result["ok"] is True
    assert result["config_path"] == str(config_path)
    assert written["local_full_access"] is True and written["http_port"] == 8765
    assert isinstance(written["ida_home"], Path), "provided paths are resolved to Path"
    assert "upx" not in written and "r2" not in written, "None/empty values are dropped"
    assert activation_calls and activation_calls[0]["activate"] is True
    assert result["activation"] == {"ok": True}


def test_apply_paths_skips_activation_without_ida(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "update_config_values", lambda values: tmp_path / "c.json")
    monkeypatch.setattr(config, "default_config_path", lambda: tmp_path / "d.json")
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(
        web_setup,
        "configure_ida",
        lambda **kwargs: pytest.fail("configure_ida must not run without an ida_home"),
    )

    result = bootstrap.apply_paths({"upx": str(tmp_path / "upx")}, activate_ida=True)

    assert result["activation"] is None


# ---------------------------------------------------------------------------
# sync_and_probe / export_mcp_files / run_doctor_summary
# ---------------------------------------------------------------------------


def test_sync_and_probe_runs_each_step(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    seen: list[str] = []

    def fake_run_setup_step(settings: Any, step: str) -> dict[str, Any]:
        seen.append(step)
        return {"ok": True, "step": step}

    monkeypatch.setattr(web_setup, "run_setup_step", fake_run_setup_step)

    results = bootstrap.sync_and_probe()

    assert seen == ["sync_x64dbg", "probe_runtimes", "persist_defaults"]
    assert [item["step"] for item in results] == seen


def test_export_mcp_files_writes_cursor_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(config, "default_config_path", lambda: tmp_path / "default.json")
    monkeypatch.setattr(
        config_generate,
        "export_mcp_environment",
        lambda settings, persist, config_path: {
            "ok": True,
            "written": {"env": "x"},
            "examples": {"cursor": {"mcpServers": {"headless-re": {}}}},
            "doctor_ready": True,
        },
    )

    result = bootstrap.export_mcp_files(tmp_path)

    cursor_file = tmp_path / ".cursor" / "mcp.json"
    assert cursor_file.is_file()
    assert result["cursor_mcp"] == str(cursor_file)
    assert result["cursor_payload"] == {"mcpServers": {"headless-re": {}}}
    assert result["doctor_ready"] is True


def test_export_mcp_files_without_cursor_example_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(config, "default_config_path", lambda: tmp_path / "default.json")
    monkeypatch.setattr(
        config_generate,
        "export_mcp_environment",
        lambda settings, persist, config_path: {"ok": False, "examples": {}},
    )

    result = bootstrap.export_mcp_files(tmp_path)

    assert result["cursor_mcp"] is None and result["cursor_payload"] is None
    assert not (tmp_path / ".cursor").exists()


def test_run_doctor_summary_flattens_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch, _fake_settings())
    report = SimpleNamespace(
        ready=True,
        probes=[
            SimpleNamespace(name="ida", status=SimpleNamespace(value="ok"), summary="found"),
            SimpleNamespace(name="cdb", status=SimpleNamespace(value="warn"), summary="missing"),
        ],
    )
    monkeypatch.setattr(doctor_module, "run_doctor", lambda settings: report)

    summary = bootstrap.run_doctor_summary()

    assert summary["ready"] is True
    assert summary["probes"][0] == {"name": "ida", "status": "ok", "summary": "found"}
    assert summary["probes"][1]["status"] == "warn"


# ---------------------------------------------------------------------------
# pip_install_editable / process launchers / stop_owned_process
# ---------------------------------------------------------------------------


def test_pip_install_editable_returns_the_process_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_bounded(cmd: list[str], **kwargs: Any) -> Any:
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bootstrap, "run_bounded", fake_run_bounded)

    code = bootstrap.pip_install_editable(tmp_path, extras=".[dev]")

    assert code == 0
    assert captured["cmd"] == [sys.executable, "-m", "pip", "install", "-e", ".[dev]"]
    assert captured["cwd"] == str(tmp_path)


def test_pip_install_editable_reports_124_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_bounded(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(1.0, [])

    monkeypatch.setattr(bootstrap, "run_bounded", fake_run_bounded)

    assert bootstrap.pip_install_editable(tmp_path) == 124


@pytest.mark.parametrize(
    ("launcher", "expected_subcommand"),
    [
        (lambda: bootstrap.start_mcp_serve(), "serve"),
        (lambda: bootstrap.start_web_console(), "serve-web"),
    ],
)
def test_launchers_spawn_the_expected_subcommand(
    monkeypatch: pytest.MonkeyPatch,
    launcher: Any,
    expected_subcommand: str,
) -> None:
    calls: dict[str, Any] = {}

    def fake_popen(cmd: list[str], **kwargs: Any) -> Any:
        calls["cmd"] = cmd
        calls["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(pid=4321)

    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: Path("/repo"))
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    process = launcher()

    assert process.pid == 4321
    assert calls["cmd"] == [sys.executable, "-m", "headless_re_mcp", expected_subcommand]
    assert calls["cwd"] == "/repo"


def test_stop_owned_process_terminates_a_live_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[Any] = []
    monkeypatch.setattr(
        bootstrap,
        "terminate_process_tree",
        lambda proc, wait_s: terminated.append((proc, wait_s)),
    )

    live = SimpleNamespace(poll=lambda: None)
    bootstrap.stop_owned_process(live, wait_s=2.0)  # type: ignore[arg-type]
    assert terminated == [(live, 2.0)]

    terminated.clear()
    bootstrap.stop_owned_process(None)
    bootstrap.stop_owned_process(SimpleNamespace(poll=lambda: 0))  # type: ignore[arg-type]
    assert terminated == [], "a dead or absent child needs no termination"


# ---------------------------------------------------------------------------
# Interactive prompt helpers.
# ---------------------------------------------------------------------------


def _scripted_input(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    queue = list(answers)
    monkeypatch.setattr(builtins, "input", lambda prompt="": queue.pop(0))


def test_ask_returns_default_on_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _scripted_input(monkeypatch, ["", "typed"])
    assert bootstrap._ask("q", default="fallback") == "fallback"
    assert bootstrap._ask("q", default="fallback") == "typed"


def test_ask_yes_parses_affirmatives(monkeypatch: pytest.MonkeyPatch) -> None:
    _scripted_input(monkeypatch, ["", "y", "是", "n"])
    assert bootstrap._ask_yes("go", default=True) is True
    assert bootstrap._ask_yes("go") is True
    assert bootstrap._ask_yes("go") is True
    assert bootstrap._ask_yes("go", default=True) is False


def test_resolve_path_rejects_skip_tokens_and_bad_kinds(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert bootstrap._resolve_path("  ", expect="dir") is None
    assert bootstrap._resolve_path("skip", expect="dir") is None

    a_dir = tmp_path / "d"
    a_dir.mkdir()
    a_file = tmp_path / "f.txt"
    a_file.write_text("x", encoding="utf-8")

    assert bootstrap._resolve_path(f'"{a_dir}"', expect="dir") == a_dir.resolve()
    assert bootstrap._resolve_path(str(a_file), expect="file") == a_file.resolve()

    assert bootstrap._resolve_path(str(a_file), expect="dir") is None
    assert bootstrap._resolve_path(str(a_dir), expect="file") is None
    assert "不是目录" in capsys.readouterr().out


def test_resolve_path_reports_an_unresolvable_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def boom(self: Path) -> Path:
        raise OSError("no such thing")

    monkeypatch.setattr(Path, "resolve", boom)

    assert bootstrap._resolve_path("/whatever", expect="dir") is None
    assert "无法解析" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _ask_path_cli
# ---------------------------------------------------------------------------


def test_ask_path_cli_non_interactive_returns_detected(tmp_path: Path) -> None:
    detected = tmp_path
    assert (
        bootstrap._ask_path_cli(
            "UPX", expect="dir", detected=detected, required=False, non_interactive=True
        )
        == detected
    )


def test_ask_path_cli_non_interactive_missing_required_aborts() -> None:
    with pytest.raises(SystemExit):
        bootstrap._ask_path_cli(
            "IDA", expect="dir", detected=None, required=True, non_interactive=True
        )


def test_ask_path_cli_interactive_accepts_detected_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scripted_input(monkeypatch, [""])
    result = bootstrap._ask_path_cli(
        "UPX", expect="dir", detected=tmp_path, required=False, non_interactive=False
    )
    assert result == tmp_path


def test_ask_path_cli_required_skip_loops_until_a_path_is_given(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "x64"
    target.mkdir()
    # First a skip (rejected because required with no detected), then the path.
    _scripted_input(monkeypatch, ["-", str(target)])

    result = bootstrap._ask_path_cli(
        "x64dbg", expect="dir", detected=None, required=True, non_interactive=False
    )

    assert result == target.resolve()


def test_ask_path_cli_skip_with_a_detected_value_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scripted_input(monkeypatch, ["-"])
    result = bootstrap._ask_path_cli(
        "UPX", expect="dir", detected=tmp_path, required=False, non_interactive=False
    )
    assert result is None, "an explicit skip drops even a detected optional path"


def test_ask_path_cli_optional_invalid_path_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scripted_input(monkeypatch, [str(tmp_path / "missing")])
    result = bootstrap._ask_path_cli(
        "UPX", expect="file", detected=None, required=False, non_interactive=False
    )
    assert result is None


def test_ask_path_cli_required_invalid_path_loops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = tmp_path / "tool.exe"
    good.write_text("x", encoding="utf-8")
    _scripted_input(monkeypatch, [str(tmp_path / "missing.exe"), str(good)])
    result = bootstrap._ask_path_cli(
        "cdb", expect="file", detected=None, required=True, non_interactive=False
    )
    assert result == good.resolve()


def test_ask_path_cli_ida_validation_pass_returns_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    monkeypatch.setattr(config, "validate_ida_home", lambda path: {"ok": True})
    _scripted_input(monkeypatch, [str(ida_dir)])

    result = bootstrap._ask_path_cli(
        "IDA Professional", expect="dir", detected=None, required=True, non_interactive=False
    )

    assert result == ida_dir.resolve()


def test_ask_path_cli_ida_validation_can_be_overridden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    monkeypatch.setattr(
        config, "validate_ida_home", lambda path: {"ok": False, "message": "no idalib"}
    )
    # Decline the override once (loops), then accept it.
    inputs = iter([str(ida_dir), str(ida_dir)])
    yes = iter([False, True])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda prompt, default=False: next(yes))

    result = bootstrap._ask_path_cli(
        "IDA Professional", expect="dir", detected=None, required=True, non_interactive=False
    )

    assert result == ida_dir.resolve(), "the operator may keep a path idalib validation dislikes"


# ---------------------------------------------------------------------------
# run_cli_setup end to end.
# ---------------------------------------------------------------------------


def _stub_cli_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    ready: bool,
) -> dict[str, Any]:
    recorded: dict[str, Any] = {"pip": 0, "applied": None}

    def fake_pip(root: Any) -> int:
        recorded["pip"] += 1
        return 0

    def fake_apply(updates: dict[str, Any], activate_ida: bool) -> dict[str, Any]:
        recorded["applied"] = (updates, activate_ida)
        return {"config_path": str(tmp_path / "config.json")}

    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: tmp_path)
    monkeypatch.setattr(bootstrap, "pip_install_editable", fake_pip)
    monkeypatch.setattr(
        bootstrap,
        "discover_defaults",
        lambda: {
            "ida_home": tmp_path / "ida",
            "x64dbg_headless_x64": tmp_path / "x64.exe",
            "x64dbg_headless_x86": tmp_path / "x86.exe",
            "upx": None,
            "diec": None,
            "r2": None,
            "cdb": None,
        },
    )
    monkeypatch.setattr(
        bootstrap,
        "_ask_path_cli",
        lambda title, *, expect, detected, required, non_interactive: detected,
    )
    monkeypatch.setattr(bootstrap, "apply_paths", fake_apply)
    monkeypatch.setattr(
        bootstrap, "sync_and_probe", lambda: [{"ok": True, "step": "probe_runtimes"}]
    )
    monkeypatch.setattr(
        bootstrap,
        "export_mcp_files",
        lambda root: {
            "cursor_mcp": str(tmp_path / ".cursor" / "mcp.json"),
            "cursor_payload": {"mcpServers": {}},
        },
    )
    monkeypatch.setattr(
        bootstrap,
        "run_doctor_summary",
        lambda: {
            "ready": ready,
            "probes": [{"name": "ida", "status": "ok" if ready else "fail", "summary": "s"}],
        },
    )
    return recorded


def test_run_cli_setup_non_interactive_reports_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _stub_cli_pipeline(monkeypatch, tmp_path, ready=True)

    code = bootstrap.run_cli_setup(non_interactive=True)

    assert code == 0
    assert recorded["pip"] == 1, "non-interactive still runs the pip step"
    updates, activate = recorded["applied"]
    assert activate is True and updates["ida_home"] == tmp_path / "ida"


def test_run_cli_setup_returns_two_when_doctor_not_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _stub_cli_pipeline(monkeypatch, tmp_path, ready=False)

    code = bootstrap.run_cli_setup(non_interactive=True, skip_pip=True)

    assert code == 2
    assert recorded["pip"] == 0, "skip_pip must bypass the install"


def test_run_cli_setup_interactive_declines_pip_and_optional_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _stub_cli_pipeline(monkeypatch, tmp_path, ready=True)
    # No cursor file and a non-dict payload exercise the export-skip branches.
    monkeypatch.setattr(
        bootstrap,
        "export_mcp_files",
        lambda root: {"cursor_mcp": None, "cursor_payload": None},
    )
    # Every yes/no prompt is declined: no pip, no optional tools.
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda prompt, default=False: False)

    asked_titles: list[str] = []

    def fake_ask_path(
        title: str, *, expect: str, detected: Any, required: bool, non_interactive: bool
    ) -> Any:
        asked_titles.append(title)
        return detected

    monkeypatch.setattr(bootstrap, "_ask_path_cli", fake_ask_path)

    code = bootstrap.run_cli_setup(non_interactive=False)

    assert code == 0
    assert recorded["pip"] == 0, "declining the pip prompt must skip the install"
    assert not any("UPX" in title for title in asked_titles), "optional tools were declined"
