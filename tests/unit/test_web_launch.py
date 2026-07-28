from __future__ import annotations

import socket
from pathlib import Path

import pytest

from headless_re_mcp.web.launch_util import choose_bind_port, port_is_free, probe_our_healthz


def test_port_is_free_and_choose_fallback() -> None:
    # Bind an ephemeral port to force it busy, then ask chooser to skip it.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    busy_port = sock.getsockname()[1]
    try:
        assert port_is_free("127.0.0.1", busy_port) is False
        chosen, reason = choose_bind_port("127.0.0.1", busy_port, span=20, auto=True)
        assert reason == "fallback"
        assert chosen != busy_port
        assert port_is_free("127.0.0.1", chosen) is True
        busy_only, reason2 = choose_bind_port("127.0.0.1", busy_port, span=1, auto=False)
        assert busy_only == busy_port
        assert reason2 == "busy"
    finally:
        sock.close()


def test_choose_preferred_when_free() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    probe = sock.getsockname()[1]
    sock.close()
    # After close, port should be choosable as preferred.
    chosen, reason = choose_bind_port("127.0.0.1", probe, span=5, auto=True)
    assert chosen == probe
    assert reason == "preferred"


def test_probe_our_healthz_none_on_closed_port() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    assert probe_our_healthz("127.0.0.1", port, timeout=0.2) is None


def test_run_web_chinese_refuse_non_loopback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.web.app import run_web

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    code = run_web(settings, host="0.0.0.0", port=8765)
    assert code == 2
    out = capsys.readouterr().out
    assert "拒绝绑定" in out
