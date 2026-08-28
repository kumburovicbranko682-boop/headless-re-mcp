"""Launcher guard clauses and the Windows single-instance lock branch.

The loopback refusal and the clean-shutdown session release are covered in
test_web_launch.py; this file drives the remaining run_web early exits (bad
host, busy/exhausted port, second-console refusal), the launch banner, and the
msvcrt arm of _claim_artifact_root that never runs on the Linux CI host.
"""

from __future__ import annotations

import os
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.web import app as web_app


class _OsProxy:
    """A stand-in ``os`` module with a pinned ``name``.

    Patching the global ``os.name`` would poison ``pathlib.Path`` on Python
    3.11, where ``Path()`` picks WindowsPath (uninstantiable on POSIX) from
    ``os.name``; a failing test would then crash pytest's own failure
    reporting. The proxy pins what ``web_app`` reads and forwards the
    rest to the real module.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)


_CHOOSE = "headless_re_mcp.web.launch_util.choose_bind_port"


def _settings(tmp_path: Path) -> Settings:
    return replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


def test_run_web_refuses_a_host_that_is_not_an_ip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = web_app.run_web(_settings(tmp_path), host="not-an-ip")
    assert code == 2
    assert "主机不是合法 IP" in capsys.readouterr().out


def test_run_web_reports_a_busy_preferred_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (8765, "busy"))
    code = web_app.run_web(_settings(tmp_path), auto_port=False)
    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_run_web_reports_an_exhausted_port_span(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (8765, "exhausted"))
    code = web_app.run_web(_settings(tmp_path))
    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_run_web_refuses_a_second_console_on_the_same_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (8765, "preferred"))
    settings = _settings(tmp_path)
    held = web_app._claim_artifact_root(settings.artifact_root)
    assert held is not None
    try:
        code = web_app.run_web(settings)
    finally:
        os.close(held)
    assert code == 78
    assert "另一个控制台已在使用同一制品目录" in capsys.readouterr().out


def test_run_web_prints_the_launch_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (18888, "fallback"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    # Keep the token file out of the real user config directory.
    monkeypatch.setattr(
        "headless_re_mcp.web.auth.default_config_path",
        lambda: tmp_path / "config" / "config.json",
    )

    code = web_app.run_web(_settings(tmp_path), quiet_banner=False)

    assert code == 0
    out = capsys.readouterr().out
    assert "自动改用 18888" in out
    assert "监控台已启动" in out
    assert "Token 文件" in out


def test_run_web_banner_omits_the_fallback_line_on_the_preferred_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (8765, "preferred"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(
        "headless_re_mcp.web.auth.default_config_path",
        lambda: tmp_path / "config" / "config.json",
    )

    code = web_app.run_web(_settings(tmp_path), quiet_banner=False)

    assert code == 0
    out = capsys.readouterr().out
    assert "监控台已启动" in out
    assert "自动改用" not in out


def test_run_web_releases_the_root_lock_when_startup_fails_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_CHOOSE, lambda *a, **k: (8765, "preferred"))

    def _boom(_settings_arg: Settings | None = None) -> tuple[str, Path]:
        raise RuntimeError("token store unavailable")

    # Fail before the service is constructed: the finally must still release the
    # single-instance lock even though there is no session to close.
    monkeypatch.setattr(web_app, "ensure_web_token", _boom)
    settings = _settings(tmp_path)

    with pytest.raises(RuntimeError, match="token store unavailable"):
        web_app.run_web(settings)

    # The lock is free again: a replacement console can claim the same root.
    reclaimed = web_app._claim_artifact_root(settings.artifact_root)
    assert reclaimed is not None
    os.close(reclaimed)


def test_claim_artifact_root_takes_the_windows_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, int, int]] = []

    fake_msvcrt = types.ModuleType("msvcrt")

    def _locking(fd: int, mode: int, nbytes: int) -> None:
        calls.append((fd, mode, nbytes))

    fake_msvcrt.LK_NBLCK = 3  # type: ignore[attr-defined]
    fake_msvcrt.locking = _locking  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(web_app, "os", _OsProxy("nt"))

    handle = web_app._claim_artifact_root(tmp_path)
    try:
        assert handle is not None
        assert calls and calls[0][1] == 3
    finally:
        if handle is not None:
            os.close(handle)
