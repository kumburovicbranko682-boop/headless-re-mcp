"""HTTP(S) interception service methods (mitmproxy), shared by Web and Android.

One proxy per session. The CA-install helper pushes the mitmproxy root
certificate onto a rooted device/emulator so its TLS can be inspected; it is
best-effort and returns guidance rather than raising when root is unavailable.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, SessionState
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _record_backend, _register_capture, _timeline_append
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]


def _as_rpc(exc: ProxyError | AdbError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class ProxyAnalysisMixin:
    settings: Settings
    registry: SessionRegistry
    # Owned by AnalysisService for the same reason as the web backend: lazily
    # creating it from a worker thread races, and the losing thread's proxy
    # would keep a bound port that nothing can ever stop.
    _proxy_backend: ProxyBackend

    @property
    def _proxy(self) -> ProxyBackend:
        return self._proxy_backend

    def _proxy_artifact_dir(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ProxyError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve() / "proxy" / session_id
        root.mkdir(parents=True, exist_ok=True)
        return root

    def proxy_start(
        self, session_id: str, host: str = "127.0.0.1", port: int = 8080
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"proxy.start cannot run in {session.state.value} state"
                )
            data = self._proxy.start(session_id, host=host, port=port)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"proxy.start cannot run in {session.state.value} state"
                    )
            except BaseException:
                with suppress(BaseException):
                    self._proxy.stop(session_id)
                raise
            _record_backend(self, session_id, "proxy", endpoint=data.get("endpoint"))
            _timeline_append(self, session_id, "proxy.start", "mitmproxy started", port=port)
            return _success(data, session_id=session_id, backend="proxy")
        except ProxyError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def proxy_stop(self, session_id: str) -> Result[JsonObject]:
        try:
            data = self._proxy.stop(session_id)
            _timeline_append(self, session_id, "proxy.stop", "mitmproxy stopped")
            return _success(data, session_id=session_id, backend="proxy")
        except ProxyError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def proxy_status(self, session_id: str) -> Result[JsonObject]:
        return self._proxy_wrap(session_id, "status", session_id)

    def proxy_flows(self, session_id: str, offset: int = 0, limit: int = 100) -> Result[JsonObject]:
        return self._proxy_wrap(session_id, "flows", session_id, offset=offset, limit=limit)

    def proxy_flow_get(self, session_id: str, flow_id: str) -> Result[JsonObject]:
        try:
            data = self._proxy.flow_get(session_id, flow_id, self._proxy_artifact_dir(session_id))
            return _success(data, session_id=session_id, backend="proxy")
        except ProxyError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def proxy_replay(self, session_id: str, flow_id: str) -> Result[JsonObject]:
        return self._proxy_wrap(session_id, "replay", session_id, flow_id)

    def proxy_export_har(self, session_id: str) -> Result[JsonObject]:
        try:
            out = self._proxy_artifact_dir(session_id) / f"capture-{uuid4().hex}.har"
            data = self._proxy.export_har(session_id, out)
            data = _register_capture(
                self, session_id, out, kind="proxy_har", source="proxy.export_har", payload=data
            )
            _timeline_append(self, session_id, "proxy.export_har", "proxy HAR exported")
            return _success(data, session_id=session_id, backend="proxy")
        except ProxyError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def proxy_ca_install_android(self, session_id: str, serial: str) -> Result[JsonObject]:
        try:
            self.registry.get(session_id)
            cert = self._proxy.ca_cert_path()
            if cert is None:
                raise ProxyError(
                    "not_found",
                    "mitmproxy CA not found; start the proxy once to generate ~/.mitmproxy",
                )
            backend = getattr(self, "_adb_backend", None) or AdbBackend(
                getattr(self.settings, "adb", None)
            )
            remote_tmp = "/data/local/tmp/mitmproxy-ca-cert.pem"
            backend.push(serial, str(cert), remote_tmp)
            data = {
                "pushed_to": remote_tmp,
                "note": (
                    "Pushed CA to device tmp. Installing as a system-trusted cert "
                    "requires root and remounting /system; use frida.server.ensure "
                    "flows or a rooted image. As a user cert, import via Settings."
                ),
            }
            _timeline_append(
                self, session_id, "proxy.ca.install_android", "CA pushed to device", serial=serial
            )
            return _success(data, session_id=session_id, backend="proxy")
        except (ProxyError, AdbError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _proxy_wrap(
        self, session_id: str, op: str, /, *args: Any, **kwargs: Any
    ) -> Result[JsonObject]:
        try:
            method = getattr(self._proxy, op)
            data = method(*args, **kwargs)
            return _success(data, session_id=session_id, backend="proxy")
        except ProxyError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
