"""Every proxy service method turns an unexpected backend fault into a clean
failure envelope instead of letting it escape the worker.

Each proxy wrapper catches ``ProxyError`` first (mapped to its own code) and then
a final ``BaseException``, which routes an *unexpected* fault -- a bug, or an
adbutils/mitmproxy internal error, anything that is not a ``ProxyError`` -- through
the canonical envelope as ``internal_error`` rather than crashing the RPC loop.
The ProxyError arms and the happy paths are exercised in test_proxy_service_lifecycle
and test_proxy_flow_get_artifact; these pin the catch-all arms of ``proxy.stop``,
``proxy.replay`` and the read-shaped ``_proxy_wrap`` (``status`` / ``flows``), plus
``proxy.flow_get``'s ProxyError mapping and its skip of a malformed (non-dict)
part -- all at the service layer with a fault-injecting fake backend, where the
fail-closed envelope and the timeline bookkeeping live.
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


class _FaultProxy:
    """A ProxyBackend stand-in whose reads/mutations raise on demand.

    Each `*_exc` slot, when set, is raised by the matching method; `flow_get`
    can instead return a chosen payload so the malformed-part branch is reachable.
    """

    def __init__(self) -> None:
        self.stop_exc: BaseException | None = None
        self.replay_exc: BaseException | None = None
        self.status_exc: BaseException | None = None
        self.flow_get_exc: BaseException | None = None
        self.flow_get_result: JsonObject | None = None

    def stop(self, session_id: str) -> JsonObject:
        if self.stop_exc is not None:
            raise self.stop_exc
        return {"stopped": True}

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        if self.replay_exc is not None:
            raise self.replay_exc
        return {"replayed": True, "flow_id": flow_id}

    def status(self, session_id: str) -> JsonObject:
        if self.status_exc is not None:
            raise self.status_exc
        return {"running": False}

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        if self.flow_get_exc is not None:
            raise self.flow_get_exc
        assert self.flow_get_result is not None
        return self.flow_get_result

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


def _open(tmp_path: Path) -> tuple[AnalysisService, str, _FaultProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FaultProxy()
    service._proxy_backend = fake  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def _timeline(service: AnalysisService, session_id: str) -> list[JsonObject]:
    result = service.timeline_list(session_id)
    assert result.ok and result.data is not None, result.error
    return list(result.data["events"])


def test_proxy_stop_unexpected_backend_fault_is_internal_error(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        fake.stop_exc = RuntimeError("mitmproxy internals blew up")
        result = service.proxy_stop(session_id)
        assert result.ok is False
        assert result.error is not None
        # Not a ProxyError, so it must be caught by the final BaseException arm
        # and filed as internal_error -- never allowed to escape the worker.
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


def test_proxy_replay_unexpected_backend_fault_is_internal_error(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        fake.replay_exc = RuntimeError("replay thread crashed")
        result = service.proxy_replay(session_id, "flow-1")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
        # A crashed replay is not a replay: it must leave no "replayed" mark that
        # would tell timeline.list a flow was re-sent against the target.
        assert [e for e in _timeline(service, session_id) if e["event"] == "proxy.replay"] == []
    finally:
        service.close_all()


def test_proxy_status_unexpected_backend_fault_is_internal_error(tmp_path: Path) -> None:
    # proxy.status routes through the read-shaped _proxy_wrap; its BaseException
    # arm is the fail-closed backstop for every pure-read proxy method.
    service, session_id, fake = _open(tmp_path)
    try:
        fake.status_exc = RuntimeError("recorder lock deadlocked")
        result = service.proxy_status(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


def test_proxy_flow_get_maps_a_proxy_error_to_its_code(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        fake.flow_get_exc = ProxyError("not_found", "unknown flow id", flow_id="ghost")
        result = service.proxy_flow_get(session_id, "ghost")
        assert result.ok is False
        assert result.error is not None
        # A ProxyError keeps its own code (via _as_rpc), not internal_error.
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_flow_get_skips_a_non_dict_part_without_crashing(tmp_path: Path) -> None:
    """A part that is not a dict is skipped, not indexed into.

    flow_get normally hands back ``request`` / ``response`` maps, but the service
    must not assume it: a null or non-dict part (a shape the backend could take
    for a flow with no response, or an older payload) has no body_path to register
    and must be passed through untouched rather than crashing the registration
    loop. Pins the ``if not isinstance(part, dict): continue`` guard.
    """
    service, session_id, fake = _open(tmp_path)
    try:
        fake.flow_get_result = {
            "id": "flow-9",
            "request": None,
            "response": "not-a-dict",
        }
        result = service.proxy_flow_get(session_id, "flow-9")
        assert result.ok is True, result.error
        assert result.data is not None
        # Both malformed parts came back exactly as given -- untouched, no crash.
        assert result.data["request"] is None
        assert result.data["response"] == "not-a-dict"
    finally:
        service.close_all()
