"""An unknown session_id answers session_not_found on every non-PE track.

``SessionNotFound`` is a distinct error type on purpose: it is the one signal
that tells an unattended caller which mistyped or lost a session id to recreate
the session rather than to wait. Several non-PE service methods reached their
backend before resolving the session, so the backend's "no active page" /
"proxy not running" / "no active debuggee" -- all reported as ``invalid_state``
-- leaked out for an id that never existed. To a caller that reads as "the
session exists but is busy", which sends it into a wait/retry loop for a state
that can never arrive.

``web.screenshot``, ``r2.*`` and ``ghidra.*`` already resolved the session
first. This pins that the stragglers now do too -- ``web.navigate`` /
``console`` / ``network.list`` / ``scripts`` / ``wasm.list`` / ``dom.snapshot``,
``proxy.flows`` / ``replay`` / ``status`` and ``frida.attach`` / ``modules`` /
``exports`` / ``memory.read`` -- while a session that *does* exist but has no
live backend still answers ``invalid_state``, so the fix did not paper over the
genuine wrong-state case.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService

UNKNOWN = "session-that-never-existed-0000"

# (service method, extra positional args after session_id) for the tools that
# used to leak the backend's invalid_state for an id that never existed.
_PREVIOUSLY_LEAKY: tuple[tuple[str, tuple[Any, ...]], ...] = (
    ("web_navigate", ("http://example.invalid/",)),
    ("web_console", ()),
    ("web_network_list", ()),
    ("web_scripts", ()),
    ("web_wasm_list", ()),
    ("web_dom_snapshot", ()),
    ("proxy_flows", ()),
    ("proxy_replay", ("flow-1",)),
    ("proxy_status", ()),
    ("frida_attach", ()),
    ("frida_modules", ()),
    ("frida_exports", ("libc.so",)),
    ("frida_memory_read", (0x1000, 16)),
)


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


@pytest.mark.parametrize(
    "method,args", _PREVIOUSLY_LEAKY, ids=[name for name, _ in _PREVIOUSLY_LEAKY]
)
def test_unknown_session_is_not_found_not_invalid_state(
    service: AnalysisService, method: str, args: tuple[Any, ...]
) -> None:
    result = getattr(service, method)(UNKNOWN, *args)
    assert result.ok is False and result.error is not None
    assert result.error.code == "session_not_found", (
        f"{method} answered {result.error.code!r} for a session id that never existed; a "
        "caller reads invalid_state as 'exists but busy' and waits instead of recreating it"
    )


def test_the_leaky_surface_is_not_empty() -> None:
    """Guard against a rename quietly emptying the parametrised list above."""
    assert len(_PREVIOUSLY_LEAKY) >= 13


class _NoPageWeb:
    """A web backend that is reachable but has no page for the session."""

    def navigate(self, session_id: str, url: str, timeout: float = 30.0) -> dict[str, Any]:
        raise WebError("invalid_state", "no active page for this session")

    def close_all(self) -> None:
        return None


class _IdleProxy:
    """A proxy backend that is reachable but not running for the session."""

    def flows(self, session_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        raise ProxyError("invalid_state", "proxy is not running for this session")

    def close_all(self) -> None:
        return None


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_web_real_session_without_a_page_still_invalid_state(tmp_path: Path) -> None:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    svc._web_backend = _NoPageWeb()  # type: ignore[assignment]
    try:
        sid = _web_session(svc)
        result = svc.web_navigate(sid, "http://example.com/")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state", (
            "a session that exists but has no page must keep answering invalid_state; "
            "the not-found fix must not swallow the genuine wrong-state case"
        )
        # A retained CLOSED session still resolves in the registry, so it too must
        # reach the backend and get invalid_state -- not not_found.
        svc.registry._sessions[sid].state = SessionState.CLOSED
        closed = svc.web_navigate(sid, "http://example.com/")
        assert closed.ok is False and closed.error is not None
        assert closed.error.code == "invalid_state"
    finally:
        svc.close_all()


def test_proxy_real_session_that_is_idle_still_invalid_state(tmp_path: Path) -> None:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    svc._proxy_backend = _IdleProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(svc)
        result = svc.proxy_flows(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        svc.close_all()


def test_frida_real_session_without_a_debuggee_still_invalid_state(tmp_path: Path) -> None:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        sid = _web_session(svc)
        # No debuggee has ever been attached to this session, so _require_debuggee_pid
        # reaches its own invalid_state check after resolving the session.
        result = svc.frida_modules(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        svc.close_all()
