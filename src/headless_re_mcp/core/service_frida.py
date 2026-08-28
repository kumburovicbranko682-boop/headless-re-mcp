"""Device-aware Frida service methods (USB / emulator / remote).

The local single-pid rule is preserved for PE sessions. Device operations use a
per-session authorization record kept in session metadata: a session must first
connect a device, then every pid it touches must have been produced by a spawn
or attach it performed. This is the same "explicit, bounded target" boundary as
the local path, generalised rather than removed.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, SessionState
from headless_re_mcp.core.results import _failure, _success, backend_error_as_rpc
from headless_re_mcp.core.service_ext import (
    _ensure_repository,
    _record_backend,
    _timeline_append,
)
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]
_AUTH_KEY = "frida_authorized"
# Authorizations for processes that are long gone are dead weight; keep only a
# recent window so a session that spawns repeatedly cannot grow without bound.
_MAX_AUTHORIZED = 64


def _as_rpc(exc: FridaError | AdbError) -> XdbgRpcError:
    return backend_error_as_rpc(exc)


class FridaDeviceMixin:
    """frida.* device operations attached to APK/web sessions."""

    settings: Settings
    registry: SessionRegistry

    def _require_open_session(self, session_id: str, tool: str) -> Any:
        session = self.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"{tool} cannot run in {session.state.value} state"
            )
        return session

    def _frida_auth(self, session_id: str) -> JsonObject:
        session = self._require_open_session(session_id, "frida")
        auth = session.metadata.get(_AUTH_KEY)
        if not isinstance(auth, dict):
            raise FridaError(
                "invalid_state",
                "connect a frida device for this session first (frida.device.connect)",
            )
        return auth

    def _save_auth(self, session_id: str, auth: JsonObject) -> None:
        self.registry.update_metadata(session_id, {_AUTH_KEY: auth})

    def _audit_frida(
        self,
        session_id: str,
        action: str,
        result: Result[JsonObject],
        params: JsonObject,
        *fields: str,
    ) -> None:
        """Record a frida device mutation in the durable audit log, best-effort.

        frida.spawn and frida.server.ensure change the target device the same
        way device.launch / device.install do -- spawn launches a process under
        instrumentation, server.ensure pushes and starts a frida-server binary
        -- so they belong in the same audit trail those adb-path mutations
        already write to. They are session-scoped, so unlike device.* they also
        own a timeline entry; but the timeline is trimmed with the session,
        while this line survives cross-session, which is exactly why ui.drive
        audits alongside its own timeline entry rather than instead of it. Pure
        enumerations (devices, applications, java.*) read and mutate nothing, so
        they are not audited. Best-effort -- the process is already spawned or
        the server already running, so a failed audit write must not turn that
        into a failed tool call -- and it copies only structural result fields
        (pids, ports, running/pushed booleans) which carry no secrets; the store
        redacts regardless. A failed call is still recorded, with its error
        code, the way ui.drive audits both outcomes.
        """
        if result.ok and isinstance(result.data, dict):
            summary: JsonObject = {name: result.data.get(name) for name in fields}
        else:
            summary = {}
            if result.error is not None:
                summary["code"] = result.error.code
        with suppress(Exception):
            _ensure_repository(self).append_audit(
                session_id=session_id,
                action=action,
                params_summary=params,
                ok=result.ok,
                result_summary=summary,
            )

    def frida_devices(self) -> Result[JsonObject]:
        try:
            data = FridaClient().enumerate_devices()
            return _success(data, backend="frida")
        except FridaError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def frida_device_connect(
        self, session_id: str, device_id: str = "usb", endpoint: str = ""
    ) -> Result[JsonObject]:
        try:
            self._require_open_session(session_id, "frida.device.connect")
            client = FridaClient()
            if endpoint.strip():
                info = client.add_remote_device(endpoint.strip())
                resolved_id = str(info.get("id") or endpoint.strip())
            else:
                device = client._resolve_device(device_id)
                resolved_id = str(getattr(device, "id", "") or device_id)
                info = {
                    "id": resolved_id,
                    "name": str(getattr(device, "name", "")),
                    "type": str(getattr(device, "type", "")),
                }
            self._require_open_session(session_id, "frida.device.connect")
            self._save_auth(session_id, {"device_id": resolved_id, "pids": [], "packages": []})
            _record_backend(self, session_id, "frida", endpoint=resolved_id)
            _timeline_append(
                self,
                session_id,
                "frida.device.connect",
                "frida device connected",
                device=resolved_id,
            )
            return _success(
                {"connected": True, "device": info}, session_id=session_id, backend="frida"
            )
        except (FridaError, AdbError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_server_ensure(
        self,
        session_id: str,
        serial: str,
        server_binary: str = "",
        port: int = 27042,
        bind_host: str = "127.0.0.1",
    ) -> Result[JsonObject]:
        try:
            self._require_open_session(session_id, "frida.server.ensure")
            backend = getattr(self, "_adb_backend", None) or AdbBackend(
                getattr(self.settings, "adb", None)
            )
            binary = server_binary.strip() or (
                str(self.settings.frida_server)
                if getattr(self.settings, "frida_server", None)
                else None
            )
            data = backend.ensure_frida_server(
                serial, server_binary=binary, port=port, bind_host=bind_host
            )
            self._require_open_session(session_id, "frida.server.ensure")
            _timeline_append(
                self, session_id, "frida.server.ensure", "frida-server ensured", serial=serial
            )
            result: Result[JsonObject] = _success(data, session_id=session_id, backend="frida")
        except (FridaError, AdbError) as exc:
            result = _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            result = _failure(exc, session_id=session_id)
        self._audit_frida(
            session_id,
            "frida.server.ensure",
            result,
            {"serial": serial, "port": port},
            "running",
            "pushed",
            "port",
        )
        return result

    def frida_applications(
        self, session_id: str, offset: int = 0, limit: int = 256
    ) -> Result[JsonObject]:
        try:
            auth = self._frida_auth(session_id)
            data = FridaClient().applications(
                auth.get("device_id"), offset=offset, limit=limit
            )
            return _success(data, session_id=session_id, backend="frida")
        except (FridaError, AdbError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def frida_spawn(self, session_id: str, package: str) -> Result[JsonObject]:
        try:
            auth = self._frida_auth(session_id)
            data = FridaClient().spawn(auth.get("device_id"), package)
            # A close arriving mid-spawn would otherwise report ok=True and
            # write the freshly spawned pid onto a session that no longer
            # exists -- the same "mutate a closed session" defect that
            # frida.device.connect and frida.server.ensure re-check for. The
            # spawned process is on the device either way; refusing here at
            # least keeps a dead session from being recorded as owning it.
            self._require_open_session(session_id, "frida.spawn")
            pid = int(data["pid"])
            auth = dict(auth)
            auth["pids"] = _append_recent(auth.get("pids"), pid)
            auth["packages"] = _append_recent(auth.get("packages"), package.strip())
            self._save_auth(session_id, auth)
            _timeline_append(
                self, session_id, "frida.spawn", "frida spawned package", package=package, pid=pid
            )
            result: Result[JsonObject] = _success(data, session_id=session_id, backend="frida")
        except (FridaError, AdbError) as exc:
            result = _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            result = _failure(exc, session_id=session_id)
        self._audit_frida(session_id, "frida.spawn", result, {"package": package}, "pid")
        return result

    def frida_java_classes(
        self, session_id: str, name_filter: str = "", limit: int = 200, pid: int = 0
    ) -> Result[JsonObject]:
        return self._java(session_id, "classes", name_filter=name_filter, limit=limit, pid=pid)

    def frida_java_methods(
        self, session_id: str, class_name: str, limit: int = 200, pid: int = 0
    ) -> Result[JsonObject]:
        return self._java(session_id, "methods", class_name=class_name, limit=limit, pid=pid)

    def _java(
        self,
        session_id: str,
        mode: str,
        *,
        class_name: str | None = None,
        name_filter: str | None = None,
        limit: int = 200,
        pid: int = 0,
    ) -> Result[JsonObject]:
        try:
            auth = self._frida_auth(session_id)
            target_pid = int(pid) if pid else _last_pid(auth)
            data = FridaClient().java_enumerate(
                auth.get("device_id"),
                target_pid,
                allowed_pids=auth.get("pids", []),
                mode=mode,
                class_name=class_name,
                name_filter=name_filter,
                limit=limit,
            )
            return _success(data, session_id=session_id, backend="frida")
        except (FridaError, AdbError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)


def _append_recent(existing: Any, value: Any, *, limit: int = _MAX_AUTHORIZED) -> list[Any]:
    """Append preserving recency, de-duplicated and bounded.

    Recency matters: the Java tools default to the most recently spawned pid, so
    a sorted set would silently target the highest pid instead of the app the
    caller just launched. The bound keeps a long-lived session from accumulating
    authorizations for processes that are long gone.
    """
    items = [item for item in (existing or []) if item != value]
    items.append(value)
    return items[-limit:]


def _last_pid(auth: JsonObject) -> int:
    pids = auth.get("pids") or []
    if not pids:
        raise FridaError("invalid_state", "no spawned/attached pid; call frida.spawn first")
    return int(pids[-1])
