"""Guard clauses, failure arms, and capture registration of the proxy mixin.

The proxy control surface mediates a MITM interception backend shared by the
Web and Android workflows. Every arm here must answer with a structured
envelope rather than a traceback, a session that dies mid-start must have its
proxy torn down again, and each spilled flow body must be registered as its own
reclaimable artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_proxy import ProxyAnalysisMixin
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]


class _ScriptedProxy:
    """ProxyBackend double: records calls, answers from a script, raises on cue."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.replies: dict[str, JsonObject] = {}
        self.raises: dict[str, BaseException] = {}
        self.on_start: Any = None
        self.ca_cert: Path | None = None
        self.flow_bodies: dict[str, str] = {}

    def _answer(self, op: str, *args: Any, **kwargs: Any) -> JsonObject:
        self.calls.append((op, args, kwargs))
        exc = self.raises.get(op)
        if exc is not None:
            raise exc
        return dict(self.replies.get(op, {"op": op}))

    def called(self, op: str) -> bool:
        return any(name == op for name, _, _ in self.calls)

    def start(self, session_id: str, *, host: str = "127.0.0.1", port: int = 8080) -> JsonObject:
        if self.on_start is not None:
            self.on_start()
        return self._answer("start", session_id, host=host, port=port)

    def stop(self, session_id: str) -> JsonObject:
        return self._answer("stop", session_id)

    def status(self, session_id: str) -> JsonObject:
        return self._answer("status", session_id)

    def flows(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        return self._answer("flows", session_id, offset=offset, limit=limit)

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        reply = self._answer("flow_get", session_id, flow_id, artifact_dir)
        for part_key, filename in (("request", "req.bin"), ("response", "resp.bin")):
            body = self.flow_bodies.get(part_key)
            if body is None:
                continue
            path = artifact_dir / filename
            path.write_bytes(body.encode("utf-8"))
            reply.setdefault(part_key, {})["body_path"] = str(path)
        return reply

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        return self._answer("replay", session_id, flow_id)

    def export_har(self, session_id: str, out: Path) -> JsonObject:
        reply = self._answer("export_har", session_id, str(out))
        out.write_text("{}", encoding="utf-8")
        return reply

    def ca_cert_path(self) -> Path | None:
        self.calls.append(("ca_cert_path", (), {}))
        return self.ca_cert


class _ScriptedAdb(AdbBackend):
    """AdbBackend double; a plain fake would fail the mixin's construction path."""

    def __init__(self) -> None:
        super().__init__(None)
        self.pushes: list[tuple[str, str, str]] = []
        self.raises: BaseException | None = None
        self.on_push: Any = None

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        if self.raises is not None:
            raise self.raises
        self.pushes.append((serial, local_path, remote_path))
        if self.on_push is not None:
            self.on_push()
        return {"pushed": remote_path}


class _Service(ProxyAnalysisMixin):
    def __init__(self, artifact_root: Path) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
        self.registry = SessionRegistry()
        self.repository = InMemoryAnalysisRepository(artifact_root)
        self.fake = _ScriptedProxy()
        self._proxy_backend = cast(ProxyBackend, self.fake)

    def web_session(self, session_id: str = "proxysid") -> str:
        self.registry.adopt(
            Session(id=session_id, target=TargetKind.WEB, locator="https://example.test/")
        )
        return session_id

    def timeline_events(self, session_id: str) -> list[str]:
        listing = self.repository.list_timeline(session_id)
        return [str(item["event"]) for item in listing["events"]]


def test_start_records_the_backend_and_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["start"] = {"endpoint": "127.0.0.1:8080", "running": True}

    result = service.proxy_start(sid, host="0.0.0.0", port=9090)

    assert result.ok and result.data is not None
    assert result.data["endpoint"] == "127.0.0.1:8080"
    _, args, kwargs = service.fake.calls[0]
    assert args == (sid,)
    assert kwargs == {"host": "0.0.0.0", "port": 9090}
    backends = service.repository.list_backends(sid)
    assert [item["kind"] for item in backends] == ["proxy"]
    assert backends[0]["endpoint"] == "127.0.0.1:8080"
    assert "proxy.start" in service.timeline_events(sid)


def test_start_refuses_a_session_already_in_a_terminal_state(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.registry.transition(sid, SessionState.FAILED)

    result = service.proxy_start(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert not service.fake.called("start")


def test_start_maps_a_backend_bind_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["start"] = ProxyError("port_in_use", "8080 is taken", port=8080)

    result = service.proxy_start(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "port_in_use"
    assert result.error.details["port"] == 8080
    assert service.repository.list_backends(sid) == []


def test_start_stops_the_proxy_when_the_session_dies_mid_start(tmp_path: Path) -> None:
    """A close racing proxy.start must not leave a bound port nothing can stop."""
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.on_start = lambda: service.registry.transition(sid, SessionState.FAILED)

    result = service.proxy_start(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert service.fake.called("stop")
    assert service.repository.list_backends(sid) == []


def test_start_maps_an_unexpected_error(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["start"] = InvalidStateTransition("registry interrupted")

    result = service.proxy_start(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_stop_appends_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.proxy_stop(sid)

    assert result.ok
    assert "proxy.stop" in service.timeline_events(sid)


def test_stop_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["stop"] = ProxyError("not_running", "no proxy for this session")
    refused = service.proxy_stop(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "not_running"

    service.fake.raises["stop"] = InvalidStateTransition("interrupted")
    broken = service.proxy_stop(sid)
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_status_and_flows_pass_paging_through_the_wrapper(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    assert service.proxy_status(sid).ok
    assert service.proxy_flows(sid, offset=5, limit=9).ok
    assert service.proxy_replay(sid, "flow-1").ok

    assert service.fake.calls == [
        ("status", (sid,), {}),
        ("flows", (sid,), {"offset": 5, "limit": 9}),
        ("replay", (sid, "flow-1"), {}),
    ]


def test_flows_maps_a_backend_refusal(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["flows"] = ProxyError("not_running", "no proxy for this session")

    result = service.proxy_flows(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "not_running"


def test_flow_get_registers_both_spilled_bodies_under_distinct_kinds(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.flow_bodies = {"request": "POST payload", "response": "200 payload"}

    result = service.proxy_flow_get(sid, "flow-1")

    assert result.ok and result.data is not None
    request_artifact = result.data["request"]["artifact_id"]
    response_artifact = result.data["response"]["artifact_id"]
    assert request_artifact != response_artifact
    described_request = service.repository.describe_artifact(str(request_artifact))
    described_response = service.repository.describe_artifact(str(response_artifact))
    assert described_request is not None
    assert described_request["kind"] == "proxy_flow_request_body"
    assert described_response is not None
    assert described_response["kind"] == "proxy_flow_response_body"


def test_flow_get_skips_a_part_that_is_not_an_object_or_has_no_body(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["flow_get"] = {
        "request": "not-an-object",
        "response": {"status": 204},
    }

    result = service.proxy_flow_get(sid, "flow-1")

    assert result.ok and result.data is not None
    assert result.data["request"] == "not-an-object"
    assert "artifact_id" not in result.data["response"]
    assert service.repository.list_artifacts(sid)["total"] == 0


def test_flow_get_reports_a_registration_failure_on_the_part(tmp_path: Path) -> None:
    """A body that cannot be registered still travels, annotated, never as an id."""
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.flow_bodies = {"request": "payload"}

    def refuse_registration(**fields: Any) -> JsonObject:
        raise ValueError("registration refused")

    service.record_artifact = refuse_registration  # type: ignore[attr-defined]
    result = service.proxy_flow_get(sid, "flow-1")

    assert result.ok and result.data is not None
    assert "artifact_id" not in result.data["request"]
    assert "registration refused" in result.data["request"]["artifact_error"]


def test_flow_get_leaves_a_part_alone_when_its_body_file_is_gone(tmp_path: Path) -> None:
    """A body_path that points at nothing registers no artifact and no error."""
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["flow_get"] = {
        "request": {"body_path": str(tmp_path / "vanished.bin")},
    }

    result = service.proxy_flow_get(sid, "flow-1")

    assert result.ok and result.data is not None
    assert "artifact_id" not in result.data["request"]
    assert "artifact_error" not in result.data["request"]
    assert service.repository.list_artifacts(sid)["total"] == 0


def test_flow_get_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["flow_get"] = ProxyError("flow_not_found", "unknown flow id")
    refused = service.proxy_flow_get(sid, "flow-404")
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "flow_not_found"

    service.fake.raises["flow_get"] = InvalidStateTransition("interrupted")
    broken = service.proxy_flow_get(sid, "flow-1")
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_flow_get_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.web_session()

    result = service.proxy_flow_get("..", "flow-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_export_har_registers_the_capture_and_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.proxy_export_har(sid)

    assert result.ok and result.data is not None
    described = service.repository.describe_artifact(str(result.data["artifact_id"]))
    assert described is not None
    assert described["kind"] == "proxy_har"
    assert "proxy.export_har" in service.timeline_events(sid)


def test_export_har_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["export_har"] = ProxyError("not_running", "no proxy for this session")
    refused = service.proxy_export_har(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "not_running"

    service.fake.raises["export_har"] = InvalidStateTransition("interrupted")
    broken = service.proxy_export_har(sid)
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_ca_install_pushes_the_generated_cert_to_the_device(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----", encoding="utf-8")
    service.fake.ca_cert = cert
    adb = _ScriptedAdb()
    service._adb_backend = adb  # type: ignore[attr-defined]

    result = service.proxy_ca_install_android(sid, "emulator-1")

    assert result.ok and result.data is not None
    assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
    assert adb.pushes == [("emulator-1", str(cert), "/data/local/tmp/mitmproxy-ca-cert.pem")]
    assert "proxy.ca.install_android" in service.timeline_events(sid)


def test_ca_install_refuses_a_session_that_dies_after_the_push(tmp_path: Path) -> None:
    """A close racing the push must surface as invalid_request, not success."""
    service = _Service(tmp_path)
    sid = service.web_session()
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----", encoding="utf-8")
    service.fake.ca_cert = cert
    adb = _ScriptedAdb()
    adb.on_push = lambda: service.registry.transition(sid, SessionState.FAILED)
    service._adb_backend = adb  # type: ignore[attr-defined]

    result = service.proxy_ca_install_android(sid, "emulator-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert adb.pushes  # the push did happen before the session died
    assert "proxy.ca.install_android" not in service.timeline_events(sid)


def test_ca_install_refuses_a_terminal_session(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.registry.transition(sid, SessionState.FAILED)

    result = service.proxy_ca_install_android(sid, "emulator-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert not service.fake.called("ca_cert_path")


def test_ca_install_reports_a_missing_ca_as_not_found(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.ca_cert = None

    result = service.proxy_ca_install_android(sid, "emulator-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "not_found"


def test_ca_install_maps_an_adb_push_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----", encoding="utf-8")
    service.fake.ca_cert = cert
    adb = _ScriptedAdb()
    adb.raises = AdbError("device_not_found", "no such serial", serial="emulator-1")
    service._adb_backend = adb  # type: ignore[attr-defined]

    result = service.proxy_ca_install_android(sid, "emulator-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "device_not_found"


def test_the_shared_wrapper_maps_an_unexpected_error(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["status"] = InvalidStateTransition("interrupted")

    result = service.proxy_status(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
