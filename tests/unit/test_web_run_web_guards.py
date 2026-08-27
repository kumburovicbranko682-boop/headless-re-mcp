"""run_web refuses to serve on bad input and returns supervisor-legible codes.

run_web is the loopback console launcher. A supervisor reads its exit code to
decide whether to restart: 2/3 mean a configuration the operator must fix, and
78 (EX_CONFIG) means a correct invocation against a setup that cannot work, so
the child should stay down rather than be restarted into the same refusal.
These pin those codes -- and the loopback-only bind, which is a security
boundary -- against the launcher, not just the helpers it leans on.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.web import app as web_app
from headless_re_mcp.web.app import run_web


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


def test_run_web_refuses_a_host_that_is_not_an_ip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A hostname (rather than a literal address) never reaches the socket layer:
    # it cannot be proven loopback, so the launcher rejects it up front.
    code = run_web(_settings(tmp_path), host="not-an-ip")
    assert code == 2
    assert "不是合法 IP" in capsys.readouterr().out


def test_run_web_reports_a_busy_preferred_port_without_auto_fallback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Occupy an ephemeral port, then demand exactly it with auto-fallback off.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    busy_port = sock.getsockname()[1]
    try:
        code = run_web(
            _settings(tmp_path),
            host="127.0.0.1",
            port=busy_port,
            auto_port=False,
        )
    finally:
        sock.close()
    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_run_web_reports_an_exhausted_port_span(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: Any
) -> None:
    def all_busy(*_args: object, **_kwargs: object) -> tuple[int, str]:
        return 8765, "exhausted"

    # run_web imports choose_bind_port from launch_util at call time.
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port", all_busy
    )
    code = run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_run_web_refuses_when_the_artifact_root_is_already_held(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: Any
) -> None:
    # Make the port selection succeed deterministically so the run reaches the
    # single-console lock, which is the behaviour under test.
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_args, **_kwargs: (8765, "preferred"),
    )
    settings = _settings(tmp_path)
    held = web_app._claim_artifact_root(settings.artifact_root)
    assert held is not None, "the first console must take the root"
    try:
        code = run_web(settings, host="127.0.0.1", port=8765)
    finally:
        os.close(held)
    # EX_CONFIG: a correct invocation that cannot work, so the supervisor keeps
    # the second console down instead of restarting it into the same refusal.
    assert code == 78
    assert "另一个控制台已在使用同一制品目录" in capsys.readouterr().out
