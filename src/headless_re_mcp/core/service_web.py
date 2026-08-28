"""Browser dynamic-analysis service methods (CDP via Playwright).

A single WebBackend holds one browser per web session for this service. Web
sessions are bound to their session id, and large payloads (bodies, scripts,
HAR) spill to the session artifact area rather than inflating a tool result.
"""

from __future__ import annotations

import json
from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.common.har import HarParseError, summarize_har
from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import HAR_INSPECT_MAX_BYTES
from headless_re_mcp.core.models import Result, SessionState, TargetKind
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _record_backend, _register_capture, _timeline_append
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]


def _as_rpc(exc: WebError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class WebAnalysisMixin:
    settings: Settings
    registry: SessionRegistry
    # Constructed once by AnalysisService rather than lazily here: tool calls run
    # on a shared worker pool, and two concurrent first-calls would each build a
    # backend, leaving whichever lost the race holding a browser that nothing
    # tracks and nothing ever closes.
    _web_backend: WebBackend

    @property
    def _web(self) -> WebBackend:
        return self._web_backend

    def _web_artifact_dir(self, session_id: str) -> Path:
        from headless_re_mcp.core.service import _is_safe_session_segment

        if not _is_safe_session_segment(session_id):
            raise WebError("invalid_params", "invalid session id")
        self.registry.get(session_id)
        root = self.settings.artifact_root.expanduser().resolve() / "web" / session_id
        root.mkdir(parents=True, exist_ok=True)
        return root

    def web_status(self, session_id: str) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            data = dict(self._web.status(session_id))
            data["locator"] = session.locator
            data["state"] = session.state.value
            data["target"] = session.target.value
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_preview(self, session_id: str) -> Result[JsonObject]:
        """Overwrite a stable inspect PNG; not registered as an artifact."""
        try:
            out = self._web_artifact_dir(session_id) / "preview.png"
            data = self._web.screenshot(session_id, out, full_page=False)
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_open(
        self, session_id: str, url: str = "", headless: bool = True, timeout: float = 30.0
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"web.open cannot run in {session.state.value} state"
                )
            target = url.strip() or (session.locator or "")
            if session.target is not TargetKind.WEB and not target:
                raise WebError("invalid_params", "a url is required for a non-web session")
            data = self._web.open(session_id, target, headless=headless, timeout=timeout)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"web.open cannot run in {session.state.value} state"
                    )
            except BaseException:
                with suppress(BaseException):
                    self._web.close(session_id)
                raise
            _record_backend(self, session_id, "web", endpoint=data.get("url"))
            _timeline_append(self, session_id, "web.open", "browser opened", url=data.get("url"))
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_navigate(self, session_id: str, url: str, timeout: float = 30.0) -> Result[JsonObject]:
        return self._web_wrap(session_id, "navigate", session_id, url, timeout=timeout)

    def web_close(self, session_id: str) -> Result[JsonObject]:
        try:
            data = self._web.close(session_id)
            _timeline_append(self, session_id, "web.close", "browser closed")
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_network_list(
        self, session_id: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        return self._web_wrap(session_id, "network_list", session_id, offset=offset, limit=limit)

    def web_network_get(self, session_id: str, request_id: str) -> Result[JsonObject]:
        try:
            data = self._web.network_get(session_id, request_id, self._web_artifact_dir(session_id))
            spill = data.get("body_path")
            if isinstance(spill, str):
                data = _register_capture(
                    self,
                    session_id,
                    Path(spill),
                    kind="web_response_body",
                    source="web.network.get",
                    payload=data,
                )
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_console(self, session_id: str, limit: int = 200) -> Result[JsonObject]:
        return self._web_wrap(session_id, "console", session_id, limit=limit)

    def web_scripts(
        self,
        session_id: str,
        wasm_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._web_wrap(
            session_id,
            "scripts",
            session_id,
            wasm_only=wasm_only,
            offset=offset,
            limit=limit,
        )

    def web_wasm_list(
        self, session_id: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        return self._web_wrap(
            session_id,
            "scripts",
            session_id,
            wasm_only=True,
            offset=offset,
            limit=limit,
        )

    def web_script_source(self, session_id: str, script_id: str) -> Result[JsonObject]:
        try:
            data = self._web.script_source(
                session_id, script_id, self._web_artifact_dir(session_id)
            )
            spill = data.get("source_path")
            if isinstance(spill, str):
                data = _register_capture(
                    self,
                    session_id,
                    Path(spill),
                    kind="web_script_source",
                    source="web.script.source",
                    payload=data,
                )
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_dom_snapshot(self, session_id: str) -> Result[JsonObject]:
        return self._web_wrap(session_id, "dom_snapshot", session_id)

    def web_screenshot(self, session_id: str, full_page: bool = False) -> Result[JsonObject]:
        try:
            out = self._web_artifact_dir(session_id) / f"screenshot-{uuid4().hex}.png"
            data = self._web.screenshot(session_id, out, full_page=full_page)
            data = _register_capture(
                self, session_id, out, kind="web_screenshot", source="web.screenshot", payload=data
            )
            _timeline_append(self, session_id, "web.screenshot", "browser screenshot")
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_har_export(self, session_id: str) -> Result[JsonObject]:
        try:
            out = self._web_artifact_dir(session_id) / f"capture-{uuid4().hex}.har"
            data = self._web.har_export(session_id, out)
            data = _register_capture(
                self, session_id, out, kind="web_har", source="web.har.export", payload=data
            )
            _timeline_append(self, session_id, "web.har.export", "browser HAR exported")
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def web_har_inspect(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        host: str | None = None,
        method: str | None = None,
        status: int | None = None,
    ) -> Result[JsonObject]:
        """Read a session's .har file offline and summarise its network log.

        The counterpart to web.har.export/proxy.export_har: no browser, no
        proxy, no CLI -- just the .har the session is bound to. It makes a
        .har a first-class target to open and query, closing the round trip
        those exporters opened. Bad input is a precise envelope, never an
        internal fault: a file that is not JSON or not a HAR 1.2 log is
        invalid_params, one over the size cap is too_large, and a session
        with no local file (a live web session on a remote URL) is
        target_mismatch from require_binary.
        """
        try:
            session = self.registry.get(session_id)
            path = session.require_binary()
            try:
                size = path.stat().st_size
            except OSError as exc:
                raise XdbgRpcError(
                    "backend_error", f"HAR file unreadable: {exc}", details={"path": str(path)}
                ) from exc
            if size > HAR_INSPECT_MAX_BYTES:
                raise XdbgRpcError(
                    "too_large",
                    f"HAR file is {size} bytes, over the {HAR_INSPECT_MAX_BYTES}-byte limit",
                    details={"path": str(path), "size": size, "max_bytes": HAR_INSPECT_MAX_BYTES},
                )
            try:
                document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError, UnicodeError) as exc:
                raise XdbgRpcError(
                    "invalid_params", f"not a readable HAR file: {exc}", details={"path": str(path)}
                ) from exc
            try:
                data = summarize_har(
                    document,
                    offset=offset,
                    limit=limit,
                    host=host,
                    method=method,
                    status=status,
                )
            except HarParseError as exc:
                raise XdbgRpcError(
                    "invalid_params", str(exc), details={"path": str(path)}
                ) from exc
            return _success(data, session_id=session_id, backend="har")
        except XdbgRpcError as exc:
            return _failure(exc, session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _web_wrap(
        self, session_id: str, op: str, /, *args: Any, **kwargs: Any
    ) -> Result[JsonObject]:
        try:
            method = getattr(self._web, op)
            data = method(*args, **kwargs)
            return _success(data, session_id=session_id, backend="web")
        except WebError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
