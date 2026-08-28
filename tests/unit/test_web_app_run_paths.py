"""run_web return-code and banner coverage.

The loopback launcher already has tests for the non-loopback refusal and for a
clean quiet shutdown. These cover the remaining arms: an unparseable host, the
busy and exhausted port outcomes, the single-instance refusal (root already
locked), and the non-quiet startup banner on a fallback port. choose_bind_port,
the root claim, and uvicorn.run are stubbed so nothing binds or serves.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings

# web.app imports fastapi (the optional ``web`` extra); skip this module
# cleanly when the extra is absent instead of erroring out the whole
# tests/unit collection (skip != pass).
web_app = pytest.importorskip(
    "headless_re_mcp.web.app", reason="fastapi (web extra) not installed (skip != pass)"
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


def test_run_web_rejects_unparseable_host(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = web_app.run_web(_settings(tmp_path), host="not-an-ip", port=8765)
    assert code == 2
    assert "不是合法 IP" in capsys.readouterr().out


def test_run_web_reports_busy_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "busy"),
    )
    code = web_app.run_web(_settings(tmp_path), host="127.0.0.1", port=8765, auto_port=False)
    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_run_web_reports_exhausted_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "exhausted"),
    )
    code = web_app.run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_run_web_refuses_when_root_already_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "preferred"),
    )
    monkeypatch.setattr(web_app, "_claim_artifact_root", lambda root: None)
    code = web_app.run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 78
    assert "另一个控制台已在使用" in capsys.readouterr().out


def test_run_web_prints_fallback_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred + 1, "fallback"),
    )
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    code = web_app.run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 0
    out = capsys.readouterr().out
    assert "自动改用" in out
    assert "监控台已启动" in out


def test_run_web_releases_root_lock_after_normal_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "preferred"),
    )
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    settings = _settings(tmp_path)
    assert web_app.run_web(settings, host="127.0.0.1", port=8765, quiet_banner=True) == 0
    released = web_app._claim_artifact_root(settings.artifact_root)
    assert released is not None
    os.close(released)
