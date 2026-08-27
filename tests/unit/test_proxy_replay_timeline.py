"""proxy.replay must leave the same session-timeline trail its siblings do.

proxy.start, proxy.stop, proxy.export_har and proxy.ca.install_android each
append a timeline entry, but proxy.replay -- the state-changing call that
re-sends a captured request to the upstream, a real mutating network action --
went through the generic _proxy_wrap and recorded nothing. A session timeline
that omits replays cannot show the session touched the network beyond its own
passive capture: an auditor saw the proxy start and export a HAR with no record
that a captured login or purchase had been fired at the server a second time.

A replay that fails records nothing, the same as every other tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeProxy:
    """ProxyBackend stand-in: replay echoes the flow id, or raises."""

    def __init__(self, *, error: ProxyError | None = None) -> None:
        self.replayed: list[str] = []
        self._error = error

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        self.replayed.append(flow_id)
        if self._error is not None:
            raise self._error
        return {"replayed": True, "flow_id": flow_id}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _replay_events(service: AnalysisService, session_id: str) -> list[JsonObject]:
    listed = service.timeline_list(session_id)
    assert listed.ok and listed.data is not None, listed.error
    return [e for e in listed.data["events"] if e.get("event") == "proxy.replay"]


def test_replay_records_the_flow_on_the_timeline(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeProxy()
        service._proxy_backend = fake  # type: ignore[assignment]

        result = service.proxy_replay(session_id, "flow-42")
        assert result.ok, result.error
        assert fake.replayed == ["flow-42"]

        events = _replay_events(service, session_id)
        assert len(events) == 1, events
        entry = events[0]
        assert entry["message"] == "proxy flow replayed"
        assert entry["details"]["flow_id"] == "flow-42"
    finally:
        service.close_all()


def test_a_failed_replay_records_nothing(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeProxy(error=ProxyError("not_found", "no such flow"))
        service._proxy_backend = fake  # type: ignore[assignment]

        result = service.proxy_replay(session_id, "missing")
        assert not result.ok
        assert result.error is not None

        assert _replay_events(service, session_id) == [], (
            "a replay that failed must not leave a 'proxy flow replayed' entry"
        )
    finally:
        service.close_all()
