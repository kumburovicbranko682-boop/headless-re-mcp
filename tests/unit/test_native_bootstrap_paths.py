"""Full-surface coverage for ``native_app.bootstrap``.

The module is the first-run wizard shared by the CLI and the native GUI: it
discovers tool paths, writes user config, exports MCP files, runs doctor, and
drives an interactive prompt loop. Every collaborator is a lazily imported
function (``config``, ``web.setup``, ``config_generate``, ``doctor``) or an
external process, so these tests stub each collaborator and script ``input`` to
walk the discovery, apply, prompt, and orchestration paths without touching the
real filesystem or spawning anything.
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

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.native_app import bootstrap


def _fake_settings(**over: Any) -> SimpleNamespace:
    base = dict(
        ida_home=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        upx=None,
        diec=None,
        r2=None,
        cdb=None,
        ghidra_home=None,
        de4dot=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_settings(monkeypatch: pytest.MonkeyPatch, settings: SimpleNamespace) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config.Settings",
        SimpleNamespace(load=lambda config_path=None: settings),
    )


class _Input:
    """Scripted ``input`` returning queued answers in order."""

    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return self._answers.pop(0)


# ---------------------------------------------------------------------------
# ensure_repo_on_path


def test_ensure_repo_on_path_uses_real_src(monkeypatch: pytest.MonkeyPatch) -> None:
    chdirs: list[str] = []
    monkeypatch.setattr(os, "chdir", lambda p: chdirs.append(str(p)))
    monkeypatch.setattr(sys, "path", [])  # force the insert branch
    root = bootstrap.ensure_repo_on_path()
    assert (root / "src" / "headless_re_mcp").is_dir()
    assert str(root / "src") in sys.path
    assert chdirs == [str(root)]


def test_ensure_repo_on_path_falls_back_to_repo_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "src" / "headless_re_mcp").mkdir(parents=True)
    real_is_dir = Path.is_dir

    def is_dir(self: Path) -> bool:
        if self.as_posix().endswith("src/headless_re_mcp") and not str(self).startswith(
            str(tmp_path)
        ):
            return False  # force the packaged-install fallback
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr("headless_re_mcp.config.repo_root", lambda: tmp_path)
    monkeypatch.setattr(os, "chdir", lambda p: None)
    monkeypatch.setattr(sys, "path", [])
    root = bootstrap.ensure_repo_on_path()
    assert root == tmp_path
    assert str(tmp_path / "src") in sys.path


def test_ensure_repo_on_path_skips_insert_when_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "src" / "headless_re_mcp").mkdir(parents=True)
    real_is_dir = Path.is_dir

    def is_dir(self: Path) -> bool:
        if self.as_posix().endswith("src/headless_re_mcp") and not str(self).startswith(
            str(tmp_path)
        ):
            return False
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr("headless_re_mcp.config.repo_root", lambda: tmp_path)
    monkeypatch.setattr(os, "chdir", lambda p: None)
    monkeypatch.setattr(sys, "path", [str(tmp_path / "src")])  # already present
    bootstrap.ensure_repo_on_path()
    assert sys.path.count(str(tmp_path / "src")) == 1  # not inserted a second time


def test_ensure_repo_on_path_without_src_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_is_dir = Path.is_dir

    def is_dir(self: Path) -> bool:
        if self.as_posix().endswith("src/headless_re_mcp") and not str(self).startswith(
            str(tmp_path)
        ):
            return False
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr("headless_re_mcp.config.repo_root", lambda: tmp_path)  # no src subtree
    monkeypatch.setattr(os, "chdir", lambda p: None)
    before = list(sys.path)
    monkeypatch.setattr(sys, "path", before)
    root = bootstrap.ensure_repo_on_path()
    assert root == tmp_path
    assert str(tmp_path / "src") not in sys.path


# ---------------------------------------------------------------------------
# discover_defaults


def test_discover_defaults_prefers_discovery_over_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _fake_settings(ida_home=Path("/set/ida"), upx=Path("/set/upx"))
    _patch_settings(monkeypatch, settings)
    monkeypatch.setattr("headless_re_mcp.config.discover_ida_home", lambda: Path("/found/ida"))
    monkeypatch.setattr("headless_re_mcp.config.list_ida_install_candidates", lambda: [Path("/c")])

    def dis_x64(arch: str) -> Path | None:
        return Path("/found/x64") if arch == "x64" else None

    monkeypatch.setattr("headless_re_mcp.config.discover_x64dbg_headless", dis_x64)
    out = bootstrap.discover_defaults()
    assert out["ida_home"] == Path("/found/ida")  # discovery wins
    assert out["ida_candidates"] == [Path("/c")]
    assert out["x64dbg_headless_x64"] == Path("/found/x64")
    assert out["x64dbg_headless_x86"] is None  # falls back to settings (None)
    assert out["upx"] == Path("/set/upx")  # settings-only key


def test_discover_defaults_falls_back_to_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _fake_settings(ida_home=Path("/set/ida"), x64dbg_headless_x86=Path("/set/x86"))
    _patch_settings(monkeypatch, settings)
    monkeypatch.setattr("headless_re_mcp.config.discover_ida_home", lambda: None)
    monkeypatch.setattr("headless_re_mcp.config.list_ida_install_candidates", lambda: [])
    monkeypatch.setattr("headless_re_mcp.config.discover_x64dbg_headless", lambda arch: None)
    out = bootstrap.discover_defaults()
    assert out["ida_home"] == Path("/set/ida")
    assert out["x64dbg_headless_x86"] == Path("/set/x86")


# ---------------------------------------------------------------------------
# apply_paths


def _patch_apply(
    monkeypatch: pytest.MonkeyPatch, config_path: Path, settings: SimpleNamespace
) -> list[Any]:
    configure_calls: list[Any] = []
    monkeypatch.setattr("headless_re_mcp.config.update_config_values", lambda cleaned: config_path)
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: Path("/default/config.json")
    )
    monkeypatch.setattr(
        "headless_re_mcp.config.Settings",
        SimpleNamespace(load=lambda config_path=None: settings),
    )

    def fake_configure(**kw: Any) -> dict[str, Any]:
        configure_calls.append(kw)
        return {"activated": True}

    monkeypatch.setattr("headless_re_mcp.web.setup.configure_ida", fake_configure)
    return configure_calls


def test_apply_paths_activates_ida(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    calls = _patch_apply(monkeypatch, config_path, _fake_settings())
    result = bootstrap.apply_paths(
        {"ida_home": str(tmp_path), "upx": None, "diec": ""},
        activate_ida=True,
    )
    assert result["ok"] is True
    assert result["config_path"] == str(config_path)
    assert result["activation"] == {"activated": True}
    assert "upx" not in result["written"]  # None skipped
    assert "diec" not in result["written"]  # "" skipped
    assert calls and calls[0]["activate"] is True


def test_apply_paths_without_activation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    calls = _patch_apply(monkeypatch, config_path, _fake_settings())
    result = bootstrap.apply_paths({"ida_home": str(tmp_path)}, activate_ida=False)
    assert result["activation"] is None
    assert calls == []


# ---------------------------------------------------------------------------
# sync_and_probe


def test_sync_and_probe_runs_each_step(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_settings(monkeypatch, _fake_settings())
    seen: list[str] = []

    def run_step(settings: Any, step: str) -> dict[str, Any]:
        seen.append(step)
        return {"ok": True, "step": step}

    monkeypatch.setattr("headless_re_mcp.web.setup.run_setup_step", run_step)
    out = bootstrap.sync_and_probe()
    assert seen == ["sync_x64dbg", "probe_runtimes", "persist_defaults"]
    assert all(item["ok"] for item in out)


# ---------------------------------------------------------------------------
# export_mcp_files


def test_export_mcp_files_writes_cursor_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    export = {
        "ok": True,
        "written": {"a": "b"},
        "examples": {"cursor": {"mcpServers": {"x": {}}}},
        "doctor_ready": True,
    }
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist, config_path: export,
    )
    out = bootstrap.export_mcp_files(tmp_path)
    written = tmp_path / ".cursor" / "mcp.json"
    assert out["ok"] is True
    assert out["cursor_mcp"] == str(written)
    assert written.is_file()
    assert out["cursor_payload"] == {"mcpServers": {"x": {}}}
    assert out["doctor_ready"] is True


def test_export_mcp_files_without_cursor_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_settings(monkeypatch, _fake_settings())
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    export = {"ok": False, "examples": "not-a-dict"}
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist, config_path: export,
    )
    out = bootstrap.export_mcp_files(tmp_path)
    assert out["ok"] is False
    assert out["cursor_mcp"] is None
    assert out["cursor_payload"] is None
    assert not (tmp_path / ".cursor").exists()


# ---------------------------------------------------------------------------
# run_doctor_summary


def test_run_doctor_summary_maps_report(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_settings(monkeypatch, _fake_settings())
    report = SimpleNamespace(
        ready=True,
        probes=[
            SimpleNamespace(name="ida", status=SimpleNamespace(value="ok"), summary="found"),
            SimpleNamespace(name="upx", status=SimpleNamespace(value="warn"), summary="missing"),
        ],
    )
    monkeypatch.setattr("headless_re_mcp.doctor.run_doctor", lambda settings: report)
    out = bootstrap.run_doctor_summary()
    assert out["ready"] is True
    assert out["probes"][0] == {"name": "ida", "status": "ok", "summary": "found"}
    assert out["probes"][1]["status"] == "warn"


# ---------------------------------------------------------------------------
# pip_install_editable


def test_pip_install_editable_returns_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def fake_bounded(cmd: list[str], **kwargs: Any) -> Any:
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bootstrap, "run_bounded", fake_bounded)
    code = bootstrap.pip_install_editable(tmp_path, ".[dev]")
    assert code == 0
    assert captured["cmd"][-1] == ".[dev]"
    assert captured["cwd"] == str(tmp_path)


def test_pip_install_editable_timeout_returns_124(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(0.8, [])

    monkeypatch.setattr(bootstrap, "run_bounded", boom)
    assert bootstrap.pip_install_editable(tmp_path) == 124


# ---------------------------------------------------------------------------
# start_mcp_serve / start_web_console


def test_start_mcp_serve_spawns_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: dict[str, Any] = {}
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: tmp_path)
    monkeypatch.setattr(bootstrap, "no_window_popen_kwargs", lambda: {"close_fds": True})

    def fake_popen(cmd: list[str], **kwargs: Any) -> str:
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return "proc"

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result: Any = bootstrap.start_mcp_serve()
    assert result == "proc"
    assert calls["cmd"][-1] == "serve"
    assert calls["kwargs"]["cwd"] == str(tmp_path)
    assert calls["kwargs"]["close_fds"] is True


def test_start_web_console_spawns_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: dict[str, Any] = {}
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: tmp_path)
    monkeypatch.setattr(bootstrap, "no_window_popen_kwargs", lambda: {})

    def fake_popen(cmd: list[str], **kwargs: Any) -> str:
        calls["cmd"] = cmd
        return "web"

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result: Any = bootstrap.start_web_console()
    assert result == "web"
    assert calls["cmd"][-1] == "serve-web"


# ---------------------------------------------------------------------------
# stop_owned_process


def test_stop_owned_process_noop_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        bootstrap, "terminate_process_tree", lambda *a, **k: called.__setitem__("n", 1)
    )
    bootstrap.stop_owned_process(None)
    assert called["n"] == 0


def test_stop_owned_process_noop_when_already_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        bootstrap, "terminate_process_tree", lambda *a, **k: called.__setitem__("n", 1)
    )
    proc = SimpleNamespace(poll=lambda: 0)
    bootstrap.stop_owned_process(proc)  # type: ignore[arg-type]
    assert called["n"] == 0


def test_stop_owned_process_terminates_live_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        bootstrap,
        "terminate_process_tree",
        lambda proc, wait_s: seen.update(proc=proc, wait_s=wait_s),
    )
    proc = SimpleNamespace(poll=lambda: None)
    bootstrap.stop_owned_process(proc, wait_s=3.0)  # type: ignore[arg-type]
    assert seen["proc"] is proc
    assert seen["wait_s"] == 3.0


# ---------------------------------------------------------------------------
# _ask / _ask_yes


def test_ask_returns_default_on_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input(""))
    assert bootstrap._ask("prompt", default="fallback") == "fallback"


def test_ask_returns_typed_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input("  typed  "))
    assert bootstrap._ask("prompt") == "typed"


def test_ask_yes_default_when_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input(""))
    assert bootstrap._ask_yes("go?", default=True) is True


def test_ask_yes_parses_affirmative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input("是"))
    assert bootstrap._ask_yes("go?") is True


def test_ask_yes_parses_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input("nope"))
    assert bootstrap._ask_yes("go?", default=True) is False


# ---------------------------------------------------------------------------
# _resolve_path


def test_resolve_path_skip_tokens_return_none() -> None:
    assert bootstrap._resolve_path("", expect="dir") is None
    assert bootstrap._resolve_path("skip", expect="dir") is None
    assert bootstrap._resolve_path("无", expect="file") is None


def test_resolve_path_reports_unresolvable(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    def boom(self: Path, *a: Any, **k: Any) -> Path:
        raise OSError("bad path")

    monkeypatch.setattr(Path, "resolve", boom)
    assert bootstrap._resolve_path("whatever", expect="dir") is None
    assert "无法解析" in capsys.readouterr().out


def test_resolve_path_rejects_non_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    target = tmp_path / "afile.txt"
    target.write_text("x")
    assert bootstrap._resolve_path(str(target), expect="dir") is None
    assert "不是目录" in capsys.readouterr().out


def test_resolve_path_rejects_missing_file(tmp_path: Path, capsys: Any) -> None:
    missing = tmp_path / "nope.exe"
    assert bootstrap._resolve_path(str(missing), expect="file") is None
    assert "文件不存在" in capsys.readouterr().out


def test_resolve_path_accepts_valid_dir(tmp_path: Path) -> None:
    assert bootstrap._resolve_path(f'"{tmp_path}"', expect="dir") == tmp_path.resolve()


# ---------------------------------------------------------------------------
# _ask_path_cli


def test_ask_path_cli_non_interactive_requires_detected() -> None:
    with pytest.raises(SystemExit):
        bootstrap._ask_path_cli(
            "IDA", expect="dir", detected=None, required=True, non_interactive=True
        )


def test_ask_path_cli_non_interactive_returns_detected(tmp_path: Path) -> None:
    got = bootstrap._ask_path_cli(
        "UPX", expect="dir", detected=tmp_path, required=False, non_interactive=True
    )
    assert got == tmp_path


def test_ask_path_cli_blank_keeps_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(builtins, "input", _Input(""))
    # Blank input resolves to the detected default path.
    got = bootstrap._ask_path_cli(
        "UPX", expect="dir", detected=tmp_path, required=False, non_interactive=False
    )
    assert got == tmp_path.resolve()


def test_ask_path_cli_skip_required_then_resolve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # First a skip token while required with no detected -> reprompt; then a real dir.
    monkeypatch.setattr(builtins, "input", _Input("-", str(tmp_path)))
    got = bootstrap._ask_path_cli(
        "x64dbg", expect="dir", detected=None, required=True, non_interactive=False
    )
    assert got == tmp_path.resolve()


def test_ask_path_cli_skip_optional_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "input", _Input("skip"))
    got = bootstrap._ask_path_cli(
        "UPX", expect="file", detected=None, required=False, non_interactive=False
    )
    assert got is None


def test_ask_path_cli_unresolvable_optional_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A path that does not exist for expect=file -> _resolve_path None -> not required -> None.
    monkeypatch.setattr(builtins, "input", _Input(str(tmp_path / "missing.exe")))
    got = bootstrap._ask_path_cli(
        "cdb", expect="file", detected=None, required=False, non_interactive=False
    )
    assert got is None


def test_ask_path_cli_unresolvable_required_reprompts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    good = tmp_path / "real.exe"
    good.write_text("x")
    monkeypatch.setattr(builtins, "input", _Input(str(tmp_path / "missing.exe"), str(good)))
    got = bootstrap._ask_path_cli(
        "x64dbg", expect="file", detected=None, required=True, non_interactive=False
    )
    assert got == good.resolve()


def test_ask_path_cli_ida_validation_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(builtins, "input", _Input(str(tmp_path)))
    monkeypatch.setattr("headless_re_mcp.config.validate_ida_home", lambda p: {"ok": True})
    got = bootstrap._ask_path_cli(
        "IDA Professional", expect="dir", detected=None, required=True, non_interactive=False
    )
    assert got == tmp_path.resolve()


def test_ask_path_cli_ida_validation_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Validation fails, operator confirms using it anyway.
    monkeypatch.setattr(builtins, "input", _Input(str(tmp_path)))
    monkeypatch.setattr(
        "headless_re_mcp.config.validate_ida_home",
        lambda p: {"ok": False, "message": "no idalib"},
    )
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda *a, **k: True)
    got = bootstrap._ask_path_cli(
        "IDA Professional", expect="dir", detected=None, required=True, non_interactive=False
    )
    assert got == tmp_path.resolve()


def test_ask_path_cli_ida_validation_declined_reprompts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setattr(builtins, "input", _Input(str(tmp_path), str(other)))
    validations = iter([{"ok": False, "message": "bad"}, {"ok": True}])
    monkeypatch.setattr("headless_re_mcp.config.validate_ida_home", lambda p: next(validations))
    # Decline the first (bad) path, then the second validates clean.
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda *a, **k: False)
    got = bootstrap._ask_path_cli(
        "IDA Professional", expect="dir", detected=None, required=True, non_interactive=False
    )
    assert got == other.resolve()


# ---------------------------------------------------------------------------
# run_cli_setup


def _stub_orchestration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    doctor_ready: bool,
    cursor_mcp: str | None = "/tmp/mcp.json",
    cursor_payload: Any = None,
) -> dict[str, Any]:
    log: dict[str, Any] = {"pip": 0, "path_calls": []}
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: tmp_path)

    def fake_pip(root: Path) -> int:
        log["pip"] += 1
        return 0

    monkeypatch.setattr(bootstrap, "pip_install_editable", fake_pip)
    monkeypatch.setattr(
        bootstrap,
        "discover_defaults",
        lambda: {
            "ida_home": tmp_path,
            "x64dbg_headless_x64": tmp_path / "x64.exe",
            "x64dbg_headless_x86": tmp_path / "x86.exe",
            "upx": None,
            "diec": None,
            "r2": None,
            "cdb": None,
        },
    )

    def fake_path_cli(title: str, **kw: Any) -> Any:
        log["path_calls"].append(title)
        return kw.get("detected")

    monkeypatch.setattr(bootstrap, "_ask_path_cli", fake_path_cli)
    monkeypatch.setattr(
        bootstrap, "apply_paths", lambda updates, activate_ida: {"config_path": "/cfg"}
    )
    monkeypatch.setattr(bootstrap, "sync_and_probe", lambda: [{"ok": True, "step": "sync_x64dbg"}])
    monkeypatch.setattr(
        bootstrap,
        "export_mcp_files",
        lambda root: {"cursor_mcp": cursor_mcp, "cursor_payload": cursor_payload},
    )
    monkeypatch.setattr(
        bootstrap,
        "run_doctor_summary",
        lambda: {
            "ready": doctor_ready,
            "probes": [{"name": "ida", "status": "ok", "summary": "ready"}],
        },
    )
    return log


def test_run_cli_setup_non_interactive_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = _stub_orchestration(
        monkeypatch, tmp_path, doctor_ready=True, cursor_payload={"mcpServers": {}}
    )
    code = bootstrap.run_cli_setup(non_interactive=True)
    assert code == 0
    assert log["pip"] == 1  # pip ran (not skipped, non-interactive)
    # 3 required paths + 4 optional tools all prompted in non-interactive mode.
    assert len(log["path_calls"]) == 7


def test_run_cli_setup_not_ready_returns_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_orchestration(monkeypatch, tmp_path, doctor_ready=False, cursor_mcp=None)
    code = bootstrap.run_cli_setup(non_interactive=True, activate_ida=False)
    assert code == 2


def test_run_cli_setup_skip_pip_and_interactive_prompts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = _stub_orchestration(monkeypatch, tmp_path, doctor_ready=True)
    # Interactive: decline the optional-tools prompt; skip_pip avoids the pip question.
    answers = iter([False])
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda *a, **k: next(answers))
    code = bootstrap.run_cli_setup(skip_pip=True, non_interactive=False)
    assert code == 0
    assert log["pip"] == 0  # pip skipped
    assert len(log["path_calls"]) == 3  # optional tools declined -> only required paths


def test_run_cli_setup_interactive_runs_pip_when_confirmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = _stub_orchestration(monkeypatch, tmp_path, doctor_ready=True)
    # Confirm pip, then confirm optional tools.
    answers = iter([True, True])
    monkeypatch.setattr(bootstrap, "_ask_yes", lambda *a, **k: next(answers))
    code = bootstrap.run_cli_setup(skip_pip=False, non_interactive=False)
    assert code == 0
    assert log["pip"] == 1
    assert len(log["path_calls"]) == 7
