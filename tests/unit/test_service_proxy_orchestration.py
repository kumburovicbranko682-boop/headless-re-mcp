"""The proxy service mixin must translate every backend outcome into an envelope.

``ProxyAnalysisMixin`` is the seam between the mitmproxy/adb backends and the
tool surface: it gates on session state, records backends/timeline/artifacts,
and turns a ``ProxyError`` / ``AdbError`` into a retryable-aware ``XdbgRpcError``
while letting anything else through as a plain failure. None of that needs a
real proxy, so these drive the mixin through ``AnalysisService`` with fake
backends:

* ``proxy_start`` records a started proxy, and unwinds it (best-effort stop)
  when the session is torn down mid-launch, plus the ``ProxyError`` mapping,
* ``proxy_stop`` / ``proxy_status`` / ``proxy_flows`` / ``proxy_replay`` report
  success and both failure envelopes (mapped ProxyError vs. bare exception),
* ``proxy_flow_get`` registers request/response body spills (and threads an
  ``artifact_error`` when registration fails), skipping non-dict / body-less
  parts,
* ``proxy_export_har`` registers the HAR it wrote, and
* ``proxy_ca_install_android`` refuses without a generated CA, pushes the cert
  through adb, and maps an ``AdbError``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeProxy:
    """A mitmproxy stand-in whose every method is scriptable per test."""

    def __init__(self) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.cert: Path | None = None
        self.raise_on: dict[str, BaseException] = {}
        self.start_hook: Any = None
        self.flow_get_result: JsonObject = {}

    def _maybe_raise(self, op: str) -> None:
        if op in self.raise_on:
            raise self.raise_on[op]

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> JsonObject:
        self._maybe_raise("start")
        self.started.append(session_id)
        if self.start_hook is not None:
            self.start_hook(session_id)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def stop(self, session_id: str) -> JsonObject:
        self._maybe_raise("stop")
        self.stopped.append(session_id)
        return {"stopped": True}

    def status(self, session_id: str) -> JsonObject:
        self._maybe_raise("status")
        return {"running": True}

    def flows(self, session_id: str, offset: int = 0, limit: int = 100) -> JsonObject:
        self._maybe_raise("flows")
        return {"flows": [], "offset": offset, "limit": limit}

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        self._maybe_raise("replay")
        return {"replayed": flow_id}

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        self._maybe_raise("flow_get")
        return dict(self.flow_get_result)

    def export_har(self, session_id: str, out: Path) -> JsonObject:
        self._maybe_raise("export_har")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out), "entry_count": 0}

    def ca_cert_path(self) -> Path | None:
        return self.cert

    def close_all(self) -> None:
        self.started.clear()


class _FakeAdb:
    def __init__(self) -> None:
        self.pushes: list[tuple[str, str, str]] = []
        self.raise_on_push: BaseException | None = None
        self.push_hook: Any = None

    def push(self, serial: str, local: str, remote: str) -> JsonObject:
        if self.raise_on_push is not None:
            raise self.raise_on_push
        self.pushes.append((serial, local, remote))
        if self.push_hook is not None:
            self.push_hook()
        return {"pushed": True}


@pytest.fixture
def proxy_env(tmp_path: Path) -> Iterator[tuple[AnalysisService, _FakeProxy, str]]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    proxy = _FakeProxy()
    service._proxy_backend = proxy  # type: ignore[assignment]
    try:
        created = service.create_session("https://example.com/app", target="web")
        assert created.ok, created.error
        assert created.data is not None
        session_id = str(created.data["session"]["id"])
        yield service, proxy, session_id
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# proxy_start
# --------------------------------------------------------------------------


def test_proxy_start_records_a_started_proxy(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    result = service.proxy_start(session_id, port=18080)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["endpoint"] == "127.0.0.1:18080"
    assert proxy.started == [session_id]
    backends = service.repository.list_backends(session_id)
    assert any(b["kind"] == "proxy" for b in backends)


def test_proxy_start_unwinds_when_the_session_closes_mid_launch(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env

    def close_during_start(sid: str) -> None:
        service.close_session(sid)

    proxy.start_hook = close_during_start
    result = service.proxy_start(session_id, port=18081)
    assert result.ok is False
    assert result.error is not None
    # The proxy was started, so the racing teardown must have stopped it again.
    assert proxy.started == [session_id]
    assert session_id in proxy.stopped


def test_proxy_start_maps_a_backend_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["start"] = ProxyError("timeout", "mitmproxy not listening")
    result = service.proxy_start(session_id, port=18082)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


# --------------------------------------------------------------------------
# proxy_stop / status / flows / replay (the _proxy_wrap siblings)
# --------------------------------------------------------------------------


def test_proxy_stop_reports_success(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    result = service.proxy_stop(session_id)
    assert result.ok, result.error
    assert proxy.stopped == [session_id]


def test_proxy_stop_maps_a_backend_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["stop"] = ProxyError("backend_error", "shutdown refused")
    result = service.proxy_stop(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"
    assert result.error.retryable is False


def test_proxy_stop_surfaces_an_unexpected_exception(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["stop"] = RuntimeError("mitmdump crashed")
    result = service.proxy_stop(session_id)
    assert result.ok is False
    assert result.error is not None


def test_proxy_status_and_flows_and_replay_report_success(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, _, session_id = proxy_env
    assert service.proxy_status(session_id).ok
    flows = service.proxy_flows(session_id, offset=5, limit=20)
    assert flows.ok and flows.data is not None
    assert flows.data["offset"] == 5 and flows.data["limit"] == 20
    replay = service.proxy_replay(session_id, "flow-1")
    assert replay.ok and replay.data is not None
    assert replay.data["replayed"] == "flow-1"


def test_proxy_wrap_maps_a_backend_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["status"] = ProxyError("invalid_state", "proxy not running")
    result = service.proxy_status(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_proxy_wrap_surfaces_an_unexpected_exception(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["flows"] = ValueError("bad cursor")
    result = service.proxy_flows(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# proxy_flow_get -- body-spill registration
# --------------------------------------------------------------------------


def test_proxy_flow_get_registers_both_body_spills(
    proxy_env: tuple[AnalysisService, _FakeProxy, str], tmp_path: Path
) -> None:
    service, proxy, session_id = proxy_env
    req_body = tmp_path / "req.bin"
    resp_body = tmp_path / "resp.bin"
    req_body.write_bytes(b"request-bytes")
    resp_body.write_bytes(b"response-bytes")
    proxy.flow_get_result = {
        "request": {"body_path": str(req_body)},
        "response": {"body_path": str(resp_body)},
    }
    result = service.proxy_flow_get(session_id, "flow-1")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["request"]["artifact_id"]
    assert result.data["response"]["artifact_id"]


def test_proxy_flow_get_skips_non_dict_and_bodyless_parts(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.flow_get_result = {
        "request": None,
        "response": {"body_path": ""},
    }
    result = service.proxy_flow_get(session_id, "flow-2")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data["response"]


def test_proxy_flow_get_threads_a_registration_failure(
    proxy_env: tuple[AnalysisService, _FakeProxy, str], tmp_path: Path
) -> None:
    service, proxy, session_id = proxy_env
    body = tmp_path / "resp.bin"
    body.write_bytes(b"response-bytes")
    proxy.flow_get_result = {"response": {"body_path": str(body)}}

    def explode(**_: object) -> JsonObject:
        raise RuntimeError("repository is down")

    service.record_artifact = explode  # type: ignore[method-assign]
    result = service.proxy_flow_get(session_id, "flow-3")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data["response"]
    assert "repository is down" in result.data["response"]["artifact_error"]


def test_proxy_flow_get_leaves_an_unregisterable_body_untouched(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.flow_get_result = {"response": {"body_path": "/nonexistent/does-not-exist.bin"}}
    result = service.proxy_flow_get(session_id, "flow-x")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data["response"]
    assert "artifact_error" not in result.data["response"]


def test_proxy_flow_get_maps_a_backend_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["flow_get"] = ProxyError("not_found", "no such flow")
    result = service.proxy_flow_get(session_id, "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_flow_get_surfaces_an_unexpected_exception(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["flow_get"] = KeyError("body")
    result = service.proxy_flow_get(session_id, "boom")
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# proxy_export_har
# --------------------------------------------------------------------------


def test_proxy_export_har_registers_the_written_file(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, _, session_id = proxy_env
    result = service.proxy_export_har(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_proxy_export_har_maps_a_backend_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["export_har"] = ProxyError("backend_error", "har write failed")
    result = service.proxy_export_har(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_proxy_export_har_surfaces_an_unexpected_exception(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.raise_on["export_har"] = OSError("disk full")
    result = service.proxy_export_har(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# proxy_ca_install_android
# --------------------------------------------------------------------------


def test_ca_install_refuses_without_a_generated_ca(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    proxy.cert = None
    result = service.proxy_ca_install_android(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_ca_install_refuses_on_a_closed_session(
    proxy_env: tuple[AnalysisService, _FakeProxy, str],
) -> None:
    service, proxy, session_id = proxy_env
    closed = service.close_session(session_id)
    assert closed.ok, closed.error
    result = service.proxy_ca_install_android(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None


def test_ca_install_aborts_if_the_session_closes_during_push(
    proxy_env: tuple[AnalysisService, _FakeProxy, str], tmp_path: Path
) -> None:
    service, proxy, session_id = proxy_env
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    proxy.cert = cert
    adb = _FakeAdb()
    adb.push_hook = lambda: service.close_session(session_id)
    service._adb_backend = adb  # type: ignore[assignment]
    result = service.proxy_ca_install_android(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    # The cert reached the device even though the racing teardown aborted the call.
    assert adb.pushes == [
        ("emulator-5554", str(cert), "/data/local/tmp/mitmproxy-ca-cert.pem")
    ]


def test_ca_install_pushes_the_cert_through_adb(
    proxy_env: tuple[AnalysisService, _FakeProxy, str], tmp_path: Path
) -> None:
    service, proxy, session_id = proxy_env
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    proxy.cert = cert
    adb = _FakeAdb()
    service._adb_backend = adb  # type: ignore[assignment]
    result = service.proxy_ca_install_android(session_id, "emulator-5554")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
    assert adb.pushes == [
        ("emulator-5554", str(cert), "/data/local/tmp/mitmproxy-ca-cert.pem")
    ]


def test_ca_install_maps_an_adb_error(
    proxy_env: tuple[AnalysisService, _FakeProxy, str], tmp_path: Path
) -> None:
    service, proxy, session_id = proxy_env
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    proxy.cert = cert
    adb = _FakeAdb()
    adb.raise_on_push = AdbError("timeout", "adb push timed out")
    service._adb_backend = adb  # type: ignore[assignment]
    result = service.proxy_ca_install_android(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True
