"""Chrome DevTools Protocol driving via Playwright's sync API.

One browser per web session, driven through a CDP session so network, console,
scripts and WASM modules can be inspected with DevTools fidelity. Playwright is
optional and its browsers must be installed; a missing dependency degrades to
``capability_unavailable``. There is deliberately no arbitrary-JS ``evaluate``
tool, mirroring the debugger surface's refusal to offer ``dynamic.command``.

The sync API is used because tool handlers run on worker threads with no running
event loop (the MCP adapter offloads blocking work), which is exactly where the
sync API is supported. It is greenlet-based and thread-affine, so every call for
a session is funnelled onto that session's own thread -- see ``_Runner``.
"""

from __future__ import annotations

import contextlib
import queue
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, TypeVar

JsonObject = dict[str, Any]
T = TypeVar("T")

_MAX_REQUESTS = 3000
_MAX_CONSOLE = 2000
_MAX_SCRIPTS = 2000
_MAX_INLINE_BODY = 200_000
# Playwright enforces its own timeouts inside the driver process, so they stop
# existing the moment the driver does. This is the outer bound that keeps a call
# from parking a worker thread forever when that happens.
_CALL_TIMEOUT = 60.0


class WebError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class _Runner:
    """Own one thread and run every Playwright call for one session on it.

    The sync API is greenlet-based and its objects cannot be touched from a
    thread other than the one that created them: doing so raises "Cannot switch
    to a different thread" from deep inside playwright. Tool calls arrive on a
    shared worker pool, so which thread services ``web.dom_snapshot`` has
    nothing to do with which one serviced ``web.open`` -- the pool reuses an
    idle worker, so it appears to work until concurrency spreads the calls out.

    Waits are bounded here too. Playwright's own timeouts live in the driver
    process, so a driver that dies takes them with it and the caller blocks for
    good; a wedged runner is marked and refuses further work rather than
    queueing the whole session behind a call that will never return.
    """

    def __init__(self, name: str) -> None:
        self._queue: queue.SimpleQueue[tuple[Callable[[], Any], Future[Any]] | None] = (
            queue.SimpleQueue()
        )
        self._wedged = False
        self._closed = False
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)
        self._thread.start()

    @property
    def wedged(self) -> bool:
        return self._wedged

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            work, future = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(work())
            except BaseException as exc:  # noqa: BLE001 - handed to the caller
                future.set_exception(exc)

    def call(self, work: Callable[[], T], *, timeout: float = _CALL_TIMEOUT) -> T:
        if self._closed:
            raise WebError("invalid_state", "web session is closed")
        if self._wedged:
            raise WebError(
                "backend_error",
                "browser is unresponsive and this session cannot be used; call web.close",
            )
        future: Future[T] = Future()
        self._queue.put((work, future))
        try:
            return future.result(timeout=timeout)
        except FutureTimeout as exc:
            # The thread stays blocked in playwright and cannot be interrupted.
            # It is a daemon, so it costs the process a thread and nothing else,
            # and the session it belongs to is now unusable by definition.
            self._wedged = True
            raise WebError("timeout", f"browser did not respond within {timeout:g}s") from exc

    def shutdown(self) -> None:
        self._closed = True
        self._queue.put(None)


class _WebSession:
    """Live browser objects plus bounded telemetry buffers for one session."""

    def __init__(self, playwright: Any, browser: Any, context: Any, page: Any, cdp: Any) -> None:
        self.playwright = playwright
        self.browser = browser
        self.context = context
        self.page = page
        self.cdp = cdp
        self.requests: OrderedDict[str, JsonObject] = OrderedDict()
        self.console: deque[JsonObject] = deque(maxlen=_MAX_CONSOLE)
        # Bounded like the other two: scriptParsed fires for every script a page
        # parses, so a long-lived tab (or one that eval()s) would otherwise grow
        # this dictionary for as long as the session is open.
        self.scripts: OrderedDict[str, JsonObject] = OrderedDict()
        # How many entries the rings dropped. The lists look complete once they
        # sit at the cap; without this an overnight page that eval()s reports
        # "2000 scripts" as if that were all it ever parsed.
        self.requests_evicted = 0
        self.scripts_evicted = 0
        self.console_evicted = 0
        self.lock = threading.RLock()
        # Set right after construction: the runner is what built these objects,
        # and it is the only thread allowed to touch them again.
        self.runner: _Runner | None = None

    def remember_request(self, info: JsonObject) -> None:
        with self.lock:
            self.requests[str(info.get("requestId"))] = info
            while len(self.requests) > _MAX_REQUESTS:
                self.requests.popitem(last=False)
                self.requests_evicted += 1

    def remember_script(self, info: JsonObject) -> None:
        with self.lock:
            self.scripts[str(info.get("scriptId"))] = info
            while len(self.scripts) > _MAX_SCRIPTS:
                self.scripts.popitem(last=False)
                self.scripts_evicted += 1

    def remember_console(self, entry: JsonObject) -> None:
        with self.lock:
            if self.console.maxlen is not None and len(self.console) >= self.console.maxlen:
                self.console_evicted += 1
            self.console.append(entry)

    def close(self) -> None:
        for closer in (self.context.close, self.browser.close, self.playwright.stop):
            with contextlib.suppress(Exception):  # teardown is best-effort
                closer()


class WebBackend:
    """Manages one browser per session id (process-lifetime state)."""

    def __init__(self) -> None:
        self._sessions: dict[str, _WebSession] = {}
        self._lock = threading.RLock()
        self._available: bool | None = None

    def _check_available(self) -> None:
        if self._available is None:
            try:
                import playwright.sync_api  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        if not self._available:
            raise WebError("capability_unavailable", "playwright is not installed")

    def _get(self, session_id: str) -> _WebSession:
        with self._lock:
            handle = self._sessions.get(session_id)
        if handle is None:
            raise WebError(
                "invalid_state", "web session not open; call web.open first", session_id=session_id
            )
        return handle

    def _runner(self, handle: _WebSession) -> _Runner:
        runner = handle.runner
        if runner is None:
            raise WebError("invalid_state", "web session has no browser thread")
        return runner

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self._check_available()
        from playwright.sync_api import sync_playwright

        with self._lock:
            if session_id in self._sessions:
                raise WebError("invalid_state", "web session already open", session_id=session_id)

        runner = _Runner(f"playwright-{session_id[:8]}")

        def build() -> tuple[_WebSession, JsonObject]:
            pw = sync_playwright().start()
            try:
                browser = pw.chromium.launch(headless=headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                cdp = context.new_cdp_session(page)
                handle = _WebSession(pw, browser, context, page, cdp)
                self._wire_events(handle)
                if url:
                    page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
                # Summarised here rather than by a second call: between the two,
                # a browser exists that no session yet refers to, and a failure
                # in that window would leave it with nothing able to close it.
                summary = {
                    "opened": True,
                    "url": page.url,
                    "title": _safe_title(page),
                    "headless": headless,
                }
            except Exception as exc:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    pw.stop()
                raise WebError("backend_error", f"failed to open browser: {exc}", url=url) from exc
            return handle, summary

        try:
            # Launching a browser is the slowest thing here, so it gets the
            # caller's navigation budget plus room for the launch itself.
            handle, summary = runner.call(build, timeout=timeout + 30.0)
        except BaseException:
            runner.shutdown()
            raise
        handle.runner = runner
        with self._lock:
            self._sessions[session_id] = handle
        return summary

    def _wire_events(self, handle: _WebSession) -> None:
        cdp = handle.cdp
        cdp.send("Network.enable")
        cdp.send("Runtime.enable")
        cdp.send("Debugger.enable")
        cdp.send("Page.enable")

        def on_request(params: JsonObject) -> None:
            req = params.get("request") or {}
            handle.remember_request(
                {
                    "requestId": params.get("requestId"),
                    "url": req.get("url"),
                    "method": req.get("method"),
                    "resourceType": params.get("type"),
                    "status": None,
                    "mimeType": None,
                }
            )

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = resp.get("mimeType")

        def on_script(params: JsonObject) -> None:
            handle.remember_script(
                {
                    "scriptId": params.get("scriptId"),
                    "url": params.get("url"),
                    "language": params.get("scriptLanguage", "JavaScript"),
                }
            )

        def on_console(params: JsonObject) -> None:
            parts: list[str] = []
            for argument in params.get("args") or []:
                if not isinstance(argument, dict):
                    continue
                if "value" in argument:
                    parts.append(str(argument["value"]))
                elif argument.get("description"):
                    parts.append(str(argument["description"]))
                else:
                    parts.append(str(argument.get("type", "")))
            handle.remember_console(
                {"type": str(params.get("type") or "log"), "text": " ".join(parts)}
            )

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                handle.page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"navigation failed: {exc}", url=url) from exc
            return {"url": handle.page.url, "title": _safe_title(handle.page)}

        return self._runner(handle).call(work, timeout=timeout + 10.0)

    def close(self, session_id: str) -> JsonObject:
        with self._lock:
            handle = self._sessions.pop(session_id, None)
        if handle is None:
            return {"closed": False, "note": "no web session was open"}
        runner = handle.runner
        if runner is None:
            handle.close()
            return {"closed": True}
        clean = True
        if not runner.wedged:
            # Teardown talks to the browser, so it belongs on the same thread as
            # everything else. Bounded, because close is the recovery path: it
            # has to reclaim the session even when the browser is beyond saving.
            with contextlib.suppress(WebError):
                runner.call(handle.close, timeout=20.0)
        if runner.wedged:
            clean = False
        runner.shutdown()
        return {"closed": True, "clean": clean}

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
        window = items[offset : offset + limit]
        evicted = handle.requests_evicted
        # truncated means the ring dropped older requests. has_more means this
        # page is not the whole current ring. Measured: 500 live requests and
        # limit=100 came back as total=500, truncated=False, no has_more, so
        # an agent that follows the tool text treats the page as complete.
        return {
            "requests": window,
            "count": len(window),
            "total": len(items),
            "offset": offset,
            "evicted": evicted,
            "truncated": evicted > 0,
            "has_more": offset + len(window) < len(items),
        }

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.requests.get(request_id)
        if entry is None:
            raise WebError("not_found", "unknown request id", request_id=request_id)
        body = ""
        base64_encoded = False
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Network.getResponseBody", {"requestId": request_id})
            )
            body = resp.get("body", "")
            base64_encoded = bool(resp.get("base64Encoded"))
        except Exception as exc:  # noqa: BLE001
            return {**entry, "body_error": str(exc)}
        result = dict(entry)
        if len(body) > _MAX_INLINE_BODY:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out = artifact_dir / f"body-{request_id.replace('.', '_')}.bin"
            out.write_text(body, encoding="utf-8", errors="replace")
            result["body_path"] = str(out)
            result["body_truncated"] = True
            result["body"] = body[:_MAX_INLINE_BODY]
        else:
            result["body"] = body
            result["body_truncated"] = False
        result["base64_encoded"] = base64_encoded
        return result

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        handle = self._get(session_id)
        cap = max(1, int(limit))
        with handle.lock:
            items = list(handle.console)
            evicted = handle.console_evicted
        window = items[-cap:]
        # Measured: 500 live lines and limit=200 came back as count=200,
        # truncated=False, evicted=0, and no total or has_more.
        return {
            "console": window,
            "count": len(window),
            "total": len(items),
            "evicted": evicted,
            "truncated": evicted > 0,
            "has_more": len(items) > cap,
        }

    def scripts(self, session_id: str, *, wasm_only: bool = False) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            values = list(handle.scripts.values())
            evicted = handle.scripts_evicted
        if wasm_only:
            values = [s for s in values if str(s.get("language")).lower() == "webassembly"]
        return {
            "scripts": values,
            "count": len(values),
            "evicted": evicted,
            "truncated": evicted > 0,
        }

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Debugger.getScriptSource", {"scriptId": script_id})
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError(
                "not_found", f"cannot fetch script source: {exc}", script_id=script_id
            ) from exc
        source = resp.get("scriptSource", "")
        result: JsonObject = {"scriptId": script_id, "bytes": len(source)}
        if len(source) > _MAX_INLINE_BODY:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out = artifact_dir / f"script-{script_id}.js"
            out.write_text(source, encoding="utf-8", errors="replace")
            result["source_path"] = str(out)
            result["truncated"] = True
            result["source"] = source[:_MAX_INLINE_BODY]
        else:
            result["source"] = source
            result["truncated"] = False
        return result

    def dom_snapshot(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                html = handle.page.content()
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            return {
                "url": handle.page.url,
                "title": _safe_title(handle.page),
                "html": html[:_MAX_INLINE_BODY],
                "truncated": len(html) > _MAX_INLINE_BODY,
            }

        return self._runner(handle).call(work)

    def screenshot(self, session_id: str, out_path: Path, *, full_page: bool = False) -> JsonObject:
        handle = self._get(session_id)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        def work() -> JsonObject:
            try:
                handle.page.screenshot(path=str(out_path), full_page=full_page)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"screenshot failed: {exc}") from exc
            # Measured: a screenshot whose playwright call wrote nothing still
            # came back as a path. The caller then reads a capture that is not
            # on disk.
            if not out_path.is_file():
                raise WebError(
                    "backend_error",
                    "screenshot did not write an image",
                    path=str(out_path),
                )
            return {"path": str(out_path)}

        return self._runner(handle).call(work)

    def har_export(self, session_id: str, out_path: Path) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entries = [
                {
                    "request": {"method": e.get("method"), "url": e.get("url")},
                    "response": {
                        "status": e.get("status") or 0,
                        "content": {"mimeType": e.get("mimeType") or ""},
                    },
                    "_resourceType": e.get("resourceType"),
                }
                for e in handle.requests.values()
            ]
        import json

        har = {
            "log": {"version": "1.2", "creator": {"name": "headless-re-mcp"}, "entries": entries}
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
        return {"path": str(out_path), "entry_count": len(entries)}

    def close_all(self) -> None:
        with self._lock:
            session_ids = list(self._sessions)
        for session_id in session_ids:
            with contextlib.suppress(WebError):
                self.close(session_id)


def _safe_title(page: Any) -> str:
    try:
        return str(page.title())
    except Exception:  # noqa: BLE001
        return ""
