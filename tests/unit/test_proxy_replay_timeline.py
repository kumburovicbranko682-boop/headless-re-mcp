"""proxy.replay must leave a mark in the session timeline.

proxy.replay is classed as a state change (tools/catalog.py): it re-sends a
captured request to the live server, an outbound side-effecting action. Its
state-changing siblings -- proxy.start, proxy.stop, proxy.export_har,
proxy.ca.install_android -- each append a timeline entry, but replay went
through the read-shaped _proxy_wrap and recorded nothing, so timeline.list could
show that a proxy ran and was stopped yet never that flows were replayed against
the target. These pin that a successful replay records a proxy.replay entry
naming the flow, and that a failed replay -- like its siblings, which timeline
only on success -- leaves no misleading "replayed" mark.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProxy:
    """A ProxyBackend stand-in for the one call proxy_replay makes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = False

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        self.calls.append((session_id, flow_id))
        if self.fail:
            raise ProxyError("not_found", "unknown flow id", flow_id=flow_id)
        return {"replayed": True, "flow_id": flow_id}

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


def _open_session(tmp_path: Path) -> tuple[AnalysisService, str, _FakeProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def _timeline_events(service: AnalysisService, session_id: str) -> list[JsonObject]:
    result = service.timeline_list(session_id)
    assert result.ok and result.data is not None, result.error
    return list(result.data["events"])


def test_proxy_replay_records_a_timeline_entry(tmp_path: Path) -> None:
    service, session_id, _fake = _open_session(tmp_path)
    try:
        result = service.proxy_replay(session_id, "flow-7")
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["replayed"] is True

        replays = [e for e in _timeline_events(service, session_id) if e["event"] == "proxy.replay"]
        assert len(replays) == 1
        assert replays[0]["details"] == {"flow_id": "flow-7"}
    finally:
        service.close_all()


def test_a_failed_proxy_replay_leaves_no_timeline_entry(tmp_path: Path) -> None:
    service, session_id, fake = _open_session(tmp_path)
    try:
        fake.fail = True
        result = service.proxy_replay(session_id, "flow-7")
        assert result.ok is False
        assert result.error is not None

        events = _timeline_events(service, session_id)
        assert [e for e in events if e["event"] == "proxy.replay"] == []
    finally:
        service.close_all()
