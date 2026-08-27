"""In-process HTTP(S) interception via a threaded mitmproxy DumpMaster.

One proxy per session. mitmproxy runs its own asyncio loop, so it lives on a
dedicated thread; a bounded addon records flows into a ring buffer that the
read tools query. mitmproxy is optional and the API differs across versions, so
startup is defensive and a missing module degrades to ``capability_unavailable``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES

JsonObject = dict[str, Any]
_MAX_FLOWS = 2000
_REPLAY_WAIT_S = 15.0
# The ring is count-capped, but each slot can still hold a multi-megabyte
# request or response. Two thousand of those is the overnight OOM the count
# cap was supposed to prevent.
_MAX_STORED_BODY = 2 * 1024 * 1024
_MAX_RETAINED_BYTES = 64 * 1024 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
# A body at or below this stays inline in the reply; anything larger spills to an
# artifact so a single fetch cannot return a multi-megabyte string.
_MAX_INLINE_BODY = 200_000
_OMITTED_BODY = object()
# WebSocket message capture is bounded on every axis: per-message content, the
# ring length per socket, the number of sockets tracked, and total bytes held.
# mitmproxy keeps every frame on flow.websocket.messages forever, so a chatty
# socket we retain would be the same overnight OOM the body caps guard against.
_MAX_WS_STORED_MSG = 8 * 1024
_MAX_WS_MESSAGES = 500
_MAX_WS_FLOWS = 64
_MAX_WS_RETAINED_BYTES = 16 * 1024 * 1024
_MITM_WS_TAIL = 4
# proxy.stats returns the top hosts and content types rather than every one; a
# capture can touch hundreds of distinct hosts (ad/analytics fan-out), and the
# point of the summary is triage, not a second full listing.
_MAX_STATS_HOSTS = 50
_MAX_STATS_CONTENT_TYPES = 50


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _flow_matches(
    summary: JsonObject,
    method: str | None,
    host: str | None,
    url_contains: str | None,
    status: int | None,
) -> bool:
    """Whether a flow summary passes the (already-non-None) filters.

    method is an exact, case-insensitive match (GET is not POST); host and
    url_contains are case-insensitive substrings (so ``api.example.com`` matches
    ``example.com`` and a path fragment matches its URL); status is an exact
    integer, and a flow with no status yet (a failed or in-flight request) never
    matches a status filter rather than matching everything.
    """
    if method is not None and str(summary.get("method", "")).upper() != method.upper():
        return False
    if host is not None and host.casefold() not in str(summary.get("host", "")).casefold():
        return False
    if url_contains is not None:
        url = str(summary.get("url", "")).casefold()
        if url_contains.casefold() not in url:
            return False
    if status is not None:
        flow_status = summary.get("status")
        if not isinstance(flow_status, int) or flow_status != status:
            return False
    return True


def _shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel and await every remaining task, then close the loop.

    Transports (including the proxy's listening socket) are only closed when the
    tasks owning them are allowed to unwind, so this is what actually frees the
    port rather than merely dropping the loop's reference to it.
    """
    try:
        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        loop.close()


# mitmproxy's ``ctx`` is a plain module global that ``Master.__init__`` resets
# *before* the new master's addons have registered their options. Two masters
# in one process therefore race: a running master's hooks can land on the
# half-built foreign Options and crash ("No such option: rfile"). Holding this
# lock from construction until the running-hook chain has completed keeps the
# hazard windows from overlapping. Steady-state cross-reads remain (ctx points
# at the newest master), but by then every Options is fully registered and the
# schemas are identical, so reads cannot crash.
_START_SERIALIZER = threading.Lock()

# DumpMaster bundles addons that implement mitmdump's *CLI* semantics; run in
# process they can each kill a healthy capture:
#   - keepserving / readfilestdin read ``ctx.options.rfile`` in running(),
#     which is the crash site of the ctx race above,
#   - errorcheck installs a process-wide ERROR-level root logging handler and
#     ``sys.exit(1)``s the master when *any* component of the process logs an
#     error during its startup window -- including a different master or an
#     unrelated failing tool.
# None of them serve an embedded proxy: we never set rfile or the replay
# options, and startup failure is already surfaced by the readiness probe.
_DUMP_CLI_ADDONS = ("keepserving", "readfilestdin", "errorcheck")


def _strip_dump_cli_addons(master: Any) -> None:
    """Remove DumpMaster's CLI-only addons; see ``_DUMP_CLI_ADDONS`` for why."""
    for name in _DUMP_CLI_ADDONS:
        addon = None
        with contextlib.suppress(Exception):
            addon = master.addons.get(name)
        if addon is None:
            continue
        with contextlib.suppress(Exception):
            master.addons.remove(addon)
        # errorcheck installs its root-logger handler in its constructor and
        # normally detaches it inside Master.run(); once the addon is removed
        # that never runs, and a stale handler would buffer every ERROR record
        # in the process for the rest of its lifetime.
        finish = getattr(addon, "finish", None)
        if callable(finish):
            with contextlib.suppress(Exception):
                finish()


class _RunningSignal:
    """Addon that reports when the master's running-hook chain has completed.

    Appended after every other addon, so mitmproxy invokes it last: once set,
    all earlier running() hooks -- the ones that read the shared ``ctx`` -- have
    already run. ``start()`` holds ``_START_SERIALIZER`` until this fires, which
    is what actually closes the cross-master ctx race.
    """

    def __init__(self) -> None:
        self.reached = threading.Event()

    def running(self) -> None:
        self.reached.set()


def _close_proxy_servers(
    master: Any, loop: asyncio.AbstractEventLoop, timeout: float = 10.0
) -> None:
    """Stop mitmproxy's proxy servers so the listening socket is released.

    mitmproxy has no ``Done`` hook that closes the proxy server, and closing the
    event loop does not close the socket the server opened: run in process,
    ``stop()`` would report success while the port stayed bound and the next
    capture could never rebind it. Reconfiguring the server set to empty is
    mitmproxy's own teardown path -- the one a mode change already takes -- and
    it actually frees the port. Best-effort and version-guarded: a master or
    ``servers`` object this does not recognise falls through to the loop unwind,
    which is no worse than before.
    """
    proxyserver = None
    with contextlib.suppress(Exception):
        proxyserver = master.addons.get("proxyserver")
    servers = getattr(proxyserver, "servers", None)
    update = getattr(servers, "update", None)
    if update is None or not loop.is_running():
        return

    async def _teardown() -> None:
        await update([])

    with contextlib.suppress(Exception):
        future = asyncio.run_coroutine_threadsafe(_teardown(), loop)
        future.result(timeout=timeout)


def _message_body(message: Any) -> bytes:
    """The content-encoding-decoded body of a mitmproxy request/response.

    ``raw_content`` is the on-the-wire body, which for a gzip/br/deflate/zstd
    response stays compressed -- returning it means an analyst reading a
    captured API response gets compressed bytes, not the JSON. ``get_content``
    applies the Content-Encoding decode (and ``strict=False`` hands back the
    raw bytes rather than raising when the encoding is unknown or the stream is
    truncated), which is what mitmproxy's own views show. A message with no
    body (a GET, a bodiless response) or one that fails outright yields ``b""``
    so the caller never has to guard.
    """
    if message is None:
        return b""
    getter = getattr(message, "get_content", None)
    if getter is not None:
        try:
            decoded = getter(strict=False)
            if isinstance(decoded, bytes | bytearray):
                return bytes(decoded)
        except Exception:  # noqa: BLE001 - fall back to the raw bytes below
            pass
    try:
        return message.raw_content or b""
    except Exception:  # noqa: BLE001 - a malformed capture must not crash the read
        return b""


def _content_encoding(message: Any) -> str:
    """The Content-Encoding a message arrived with (``""`` when identity/none)."""
    headers = getattr(message, "headers", None)
    if headers is None:
        return ""
    try:
        value = headers.get("content-encoding", "") or ""
    except Exception:  # noqa: BLE001 - odd header containers must not crash the read
        return ""
    value = str(value).strip()
    return "" if value.lower() in ("", "identity") else value


def _headers_contain(message: Any, needle: str) -> bool:
    """Whether any header ``name: value`` of a mitmproxy message holds the needle.

    ``needle`` is already casefolded. A missing or odd header container yields
    False rather than raising, so a search over the capture never crashes on one
    malformed flow.
    """
    headers = getattr(message, "headers", None)
    if headers is None:
        return False
    try:
        items = list(headers.items())
    except Exception:  # noqa: BLE001 - odd header containers must not break the scan
        return False
    return any(needle in f"{key}: {value}".casefold() for key, value in items)


def _attach_body(section: JsonObject, body: bytes, artifact_dir: Path, *, prefix: str) -> None:
    """Put a captured body on a flow section, inline when small, spilled when big."""
    if len(body) > _MAX_INLINE_BODY:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        out = artifact_dir / f"{prefix}-{uuid4().hex}.bin"
        out.write_bytes(body)
        section["body_path"] = str(out)
    else:
        section["body"] = body.decode("utf-8", errors="replace")


def _port_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
    """True when something is listening and accepting on host:port."""
    with contextlib.suppress(OSError), socket.socket() as probe:
        probe.settimeout(timeout)
        return probe.connect_ex((host, port)) == 0
    return False


def _port_bindable(host: str, port: int) -> bool:
    """True when a listener could take host:port right now.

    ``_port_accepts`` answers a different question -- whether somebody is
    serving -- and says "free" for a port held by a socket that is not
    accepting: one whose backlog is full, one bound without ``listen``, one
    behind a filter. Believing it there means mitmproxy is started on a port it
    cannot bind, and the caller waits out the whole readiness timeout for an
    answer that was available immediately.
    """
    with contextlib.suppress(OSError), socket.socket() as probe:
        # Match what asyncio will do when it binds for real, so this probe never
        # refuses a port the server itself would have taken.
        if os.name != "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    return False


def _uninstall_master_logging(
    master: Any, loop: asyncio.AbstractEventLoop | None = None
) -> None:
    """Detach the root-logger handler mitmproxy installs in ``Master.__init__``.

    mitmproxy removes it in ``Master.done()``, which only runs after a normal
    ``run()``; a startup that fails never gets there. What is left behind is
    worse than a lost object: the handler stays on the root logger holding the
    master, its addons and every captured flow, and each later log record from
    anywhere in the process is dispatched into an event loop that is closed.
    """
    if master is None and loop is None:
        return
    handler = getattr(master, "_legacy_log_events", None)
    if handler is not None:
        with contextlib.suppress(Exception):
            handler.uninstall()
    root = logging.getLogger()
    for candidate in list(root.handlers):
        owner = getattr(candidate, "master", None)
        if owner is None:
            continue
        # By loop as well as by identity: a constructor that raises after
        # installing the handler leaves a master nothing else can reach.
        if owner is master or (loop is not None and getattr(owner, "event_loop", None) is loop):
            with contextlib.suppress(Exception):
                root.removeHandler(candidate)


def _content_len(part: Any) -> int:
    if part is None:
        return 0
    content = getattr(part, "raw_content", None)
    if not content:
        return 0
    try:
        return len(content)
    except TypeError:
        return 0


def _encoded_len(value: object) -> int:
    try:
        return len(str(value).encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return _MAX_STORED_BODY + 1


def _headers_len(part: Any) -> int:
    headers = getattr(part, "headers", None)
    if headers is None:
        return 0
    try:
        try:
            items = headers.items(multi=True)
        except TypeError:
            items = headers.items()
        total = 0
        for key, value in items:
            total += _encoded_len(key) + _encoded_len(value)
            if total > _MAX_STORED_BODY:
                break
        return total
    except Exception:  # noqa: BLE001
        return 0


def _flow_stored_bytes(flow: Any) -> int:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    total = _content_len(request) + _content_len(response)
    for value in (
        getattr(request, "method", ""),
        getattr(request, "pretty_url", ""),
        getattr(request, "host", ""),
    ):
        total += _encoded_len(value)
    return total + _headers_len(request) + _headers_len(response)


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _har_flow_headers(message: Any) -> list[JsonObject]:
    """A captured message's headers as HAR's name/value array (empty when none).

    ``items(multi=True)`` preserves duplicate header lines -- several
    ``Set-Cookie`` / ``Cache-Control`` values are exactly the sort of thing an
    analyst reading a captured session needs -- and falls back to ``items()``
    for a plain-dict stand-in. A missing or odd header container yields ``[]``
    rather than raising, so one malformed flow cannot fail the whole export.
    """
    headers = getattr(message, "headers", None)
    if headers is None:
        return []
    try:
        try:
            items = list(headers.items(multi=True))
        except TypeError:
            items = list(headers.items())
    except Exception:  # noqa: BLE001 - odd header containers must not break the export
        return []
    return [{"name": str(name), "value": str(value)} for name, value in items]


def _har_query_string(url: str) -> list[JsonObject]:
    """The URL's query as HAR's name/value array; a bad URL yields an empty one."""
    try:
        query = urlsplit(url).query
    except (ValueError, TypeError):
        return []
    return [
        {"name": name, "value": value}
        for name, value in parse_qsl(query, keep_blank_values=True)
    ]


def _har_started(message: Any) -> str:
    """A flow's start time as an ISO 8601 stamp, falling back to now.

    HAR entries require a ``startedDateTime``; mitmproxy records the request's
    wall-clock start on ``timestamp_start``. A flow with none (or a stand-in
    without the field) gets the current time so the entry stays valid.
    """
    ts = getattr(message, "timestamp_start", None)
    if isinstance(ts, int | float) and ts > 0:
        with contextlib.suppress(OverflowError, OSError, ValueError):
            return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()
    return datetime.now(UTC).isoformat()


def _har_time_ms(request: Any, response: Any) -> float:
    """Round-trip time in milliseconds from request start to response end.

    Zero when either timestamp is missing, so the ``time``/``timings`` fields
    are always present and non-negative as HAR 1.2 requires.
    """
    start = getattr(request, "timestamp_start", None)
    end = getattr(response, "timestamp_end", None)
    if end is None:
        end = getattr(response, "timestamp_start", None)
    if isinstance(start, int | float) and isinstance(end, int | float) and end >= start:
        return max(0.0, (float(end) - float(start)) * 1000.0)
    return 0.0


class _FlowRecorder:
    """A mitmproxy addon that snapshots finished flows into a ring buffer.

    Written from mitmproxy's event-loop thread and read from MCP worker threads,
    so every access takes the lock. Both containers are bounded and evicted in
    lockstep: the summaries are small, but ``_raw`` holds whole flow objects
    including bodies, so letting it grow with the capture is how an unattended
    run runs the host out of memory overnight.
    """

    def __init__(self, capacity: int = _MAX_FLOWS) -> None:
        self._capacity = max(1, capacity)
        self.flows: deque[JsonObject] = deque(maxlen=self._capacity)
        self._seq = 0
        self._raw: OrderedDict[str, Any] = OrderedDict()
        self._raw_sizes: dict[str, int] = {}
        self._retained_bytes = 0
        self._ws: OrderedDict[str, deque[JsonObject]] = OrderedDict()
        self._ws_bytes = 0
        self._lock = threading.RLock()

    @staticmethod
    def _ws_msg_bytes(record: JsonObject) -> int:
        return len(str(record.get("text", "")).encode("utf-8", errors="ignore"))

    def _drop_ws(self, flow_id: str) -> None:
        bucket = self._ws.pop(flow_id, None)
        if bucket is None:
            return
        for record in bucket:
            self._ws_bytes -= self._ws_msg_bytes(record)

    def _omit_retained(self, flow_id: str) -> None:
        retained = self._raw.get(flow_id)
        if retained is None or retained is _OMITTED_BODY:
            return
        self._raw[flow_id] = _OMITTED_BODY
        self._retained_bytes -= self._raw_sizes.pop(flow_id, 0)
        for summary in reversed(self.flows):
            if summary.get("id") == flow_id:
                summary["body_omitted"] = True
                break

    def _retain_raw(self, flow_id: str, flow: Any) -> bool:
        """Store one flow for flow_get within the memory budget; return omitted.

        The caller holds the lock. Evicts oldest raw flows and omits bodies to
        stay under _MAX_RETAINED_BYTES and the ring capacity. Shared by
        response() and error() so the two entry points can never disagree about
        the accounting.
        """
        stored_bytes = _flow_stored_bytes(flow)
        omitted = stored_bytes > _MAX_STORED_BODY
        self._raw.pop(flow_id, None)
        self._retained_bytes -= self._raw_sizes.pop(flow_id, 0)
        if not omitted:
            for retained_id, retained in list(self._raw.items()):
                if self._retained_bytes + stored_bytes <= _MAX_RETAINED_BYTES:
                    break
                if retained is not _OMITTED_BODY:
                    self._omit_retained(retained_id)
            omitted = self._retained_bytes + stored_bytes > _MAX_RETAINED_BYTES
        self._raw[flow_id] = _OMITTED_BODY if omitted else flow
        if not omitted:
            self._raw_sizes[flow_id] = stored_bytes
            self._retained_bytes += stored_bytes
        # Evict oldest raw flows in lockstep with the summary ring so the two
        # views can never disagree about which flows are retrievable.
        while len(self._raw) > self._capacity:
            evicted_id, _ = self._raw.popitem(last=False)
            self._retained_bytes -= self._raw_sizes.pop(evicted_id, 0)
            self._drop_ws(evicted_id)
        return omitted

    def response(self, flow: Any) -> None:  # mitmproxy calls this on each response
        req = flow.request
        resp = flow.response
        method, method_truncated = _bounded_metadata(req.method, _MAX_METADATA_BYTES)
        url, url_truncated = _bounded_metadata(req.pretty_url, _MAX_URL_BYTES)
        host, host_truncated = _bounded_metadata(req.host, _MAX_METADATA_BYTES)
        content_type, type_truncated = _bounded_metadata(
            resp.headers.get("content-type", "") if resp else "",
            _MAX_METADATA_BYTES,
        )
        with self._lock:
            self._seq += 1
            flow_id = str(getattr(flow, "id", None) or self._seq)
            omitted = self._retain_raw(flow_id, flow)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": getattr(resp, "status_code", None),
                "content_type": content_type,
            }
            # Flag flows that carried a request payload so a scan of the list
            # can point flow_get at the ones whose request body is the target,
            # mirroring the web line's has_request_body hint.
            if _content_len(req) > 0:
                entry["has_request_body"] = True
            if omitted:
                entry["body_omitted"] = True
            if method_truncated or url_truncated or host_truncated or type_truncated:
                entry["metadata_truncated"] = True
            self.flows.append(entry)

    def error(self, flow: Any) -> None:  # mitmproxy calls this when a flow errors
        # A request whose upstream fails (connection refused, DNS failure, reset,
        # a TLS handshake that ssl_insecure cannot save) never reaches
        # response(), so without this the flow is invisible -- the capture looks
        # empty even though a request was attempted, and the failure reason is
        # lost. Record it as a failed flow carrying the error message, mirroring
        # the web line's Network.loadingFailed handling.
        req = getattr(flow, "request", None)
        if req is None:
            return
        err = getattr(flow, "error", None)
        message, msg_truncated = _bounded_metadata(
            str(getattr(err, "msg", "") or "connection error"), _MAX_METADATA_BYTES
        )
        method, method_truncated = _bounded_metadata(
            getattr(req, "method", ""), _MAX_METADATA_BYTES
        )
        url, url_truncated = _bounded_metadata(getattr(req, "pretty_url", ""), _MAX_URL_BYTES)
        host, host_truncated = _bounded_metadata(getattr(req, "host", ""), _MAX_METADATA_BYTES)
        with self._lock:
            flow_id = str(getattr(flow, "id", None) or "")
            # If response() already recorded this flow, just annotate it rather
            # than adding a second row for the same request.
            if flow_id:
                for summary in reversed(self.flows):
                    if summary.get("id") == flow_id:
                        summary["failed"] = True
                        summary["error"] = message
                        return
            self._seq += 1
            if not flow_id:
                flow_id = str(self._seq)
            omitted = self._retain_raw(flow_id, flow)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": None,
                "content_type": "",
                "failed": True,
                "error": message,
            }
            if _content_len(req) > 0:
                entry["has_request_body"] = True
            if omitted:
                entry["body_omitted"] = True
            if method_truncated or url_truncated or host_truncated or msg_truncated:
                entry["metadata_truncated"] = True
            self.flows.append(entry)

    def websocket_message(self, flow: Any) -> None:  # mitmproxy calls this per frame
        ws = getattr(flow, "websocket", None)
        messages = getattr(ws, "messages", None) if ws is not None else None
        if not messages:
            return
        msg = messages[-1]
        content = bytes(getattr(msg, "content", b"") or b"")
        size = len(content)
        stored = content[:_MAX_WS_STORED_MSG]
        try:
            text = stored.decode("utf-8")
            binary = False
        except UnicodeDecodeError:
            text = stored.decode("utf-8", errors="replace")
            binary = True
        record: JsonObject = {
            "from_client": bool(getattr(msg, "from_client", False)),
            "size": size,
            "text": text,
            "truncated": size > len(stored),
        }
        if binary:
            record["binary"] = True
        with self._lock:
            flow_id = str(getattr(flow, "id", None) or "")
            if not flow_id:
                return
            bucket = self._ws.get(flow_id)
            if bucket is None:
                bucket = deque(maxlen=_MAX_WS_MESSAGES)
                self._ws[flow_id] = bucket
            else:
                self._ws.move_to_end(flow_id)
            if bucket.maxlen is not None and len(bucket) == bucket.maxlen:
                self._ws_bytes -= self._ws_msg_bytes(bucket[0])
            bucket.append(record)
            self._ws_bytes += self._ws_msg_bytes(record)
            for summary in reversed(self.flows):
                if summary.get("id") == flow_id:
                    summary["is_websocket"] = True
                    summary["websocket_messages"] = int(summary.get("websocket_messages", 0)) + 1
                    break
            while self._ws_bytes > _MAX_WS_RETAINED_BYTES and self._ws:
                oldest_id = next(iter(self._ws))
                oldest = self._ws[oldest_id]
                if oldest:
                    self._ws_bytes -= self._ws_msg_bytes(oldest.popleft())
                if not oldest:
                    self._ws.pop(oldest_id, None)
            while len(self._ws) > _MAX_WS_FLOWS:
                _, dropped = self._ws.popitem(last=False)
                for stale in dropped:
                    self._ws_bytes -= self._ws_msg_bytes(stale)
        # mitmproxy retains every frame on the flow forever; since we hold that
        # flow object, trim its list to a short tail so the capture we keep does
        # not grow without bound behind our own accounting.
        with contextlib.suppress(Exception):
            extra = len(messages) - _MITM_WS_TAIL
            if extra > 0:
                del messages[:extra]

    def snapshot(self) -> list[JsonObject]:
        with self._lock:
            return list(self.flows)

    def clear(self) -> int:
        """Drop every recorded flow and reset the sequence and byte accounting.

        Returns how many flow summaries were discarded. The seq counter is reset
        to 0 so ``dropped`` is measured from the post-clear baseline rather than
        reporting a phantom eviction gap. This does not touch the running proxy
        (it keeps listening, and the CA stays installed); only the capture the
        recorder holds is emptied.
        """
        with self._lock:
            discarded = len(self.flows)
            self.flows.clear()
            self._seq = 0
            self._raw.clear()
            self._raw_sizes.clear()
            self._retained_bytes = 0
            self._ws.clear()
            self._ws_bytes = 0
            return discarded

    def raw(self, flow_id: str) -> Any | None:
        with self._lock:
            return self._raw.get(flow_id)

    def websocket(self, flow_id: str) -> JsonObject | None:
        with self._lock:
            bucket = self._ws.get(flow_id)
            if bucket is None:
                return None
            messages = list(bucket)
            total = len(messages)
            for summary in self.flows:
                if summary.get("id") == flow_id:
                    total = int(summary.get("websocket_messages", total))
                    break
            return {
                "messages": messages,
                "returned": len(messages),
                "message_count": total,
                "truncated": total > len(messages),
            }

    def count(self) -> int:
        with self._lock:
            return len(self.flows)

    def retained_bytes(self) -> int:
        with self._lock:
            return self._retained_bytes


class _ProxyInstance:
    def __init__(self, host: str, port: int, ssl_insecure: bool = False) -> None:
        self.host = host
        self.port = port
        self.ssl_insecure = ssl_insecure
        self.recorder = _FlowRecorder()
        self._running_signal = _RunningSignal()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any = None
        self._started = threading.Event()
        self._error: BaseException | None = None

    def start(self, timeout: float = 15.0) -> None:
        """Return only once the proxy is actually accepting connections.

        Reaching mitmproxy's run() is not the same as having bound the port: a
        busy port fails a moment later, and reporting "running" for a proxy that
        is about to die is how an unattended capture silently records nothing.

        Serialized process-wide: mitmproxy's ctx globals make a master's
        construction-to-running window hazardous to every other master (see
        ``_START_SERIALIZER``), and ``setup_servers`` reads the *shared*
        ``ctx.options.mode`` -- two masters starting at once can bind each
        other's port. Starts are quick, so the serialization is invisible.
        """
        with _START_SERIALIZER:
            self._locked_start(timeout)

    def _locked_start(self, timeout: float) -> None:
        # Refuse up front if the port is already taken -- typically a proxy this
        # service leaked on a previous run. Without this the readiness probe
        # below would see the foreign listener and call it success, which is the
        # same lie in a different disguise. Both questions have to be asked: a
        # holder that never accepts is invisible to the connect probe.
        if _port_accepts(self.host, self.port) or not _port_bindable(self.host, self.port):
            raise ProxyError(
                "invalid_state",
                "port is already in use; stop the existing listener first",
                host=self.host,
                port=self.port,
            )
        self._thread = threading.Thread(
            target=self._run, name=f"mitmproxy-{self.port}", daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if self._error is not None:
                raise ProxyError("backend_error", f"mitmproxy failed to start: {self._error}")
            if not self._thread.is_alive():
                raise ProxyError("backend_error", "mitmproxy exited during startup")
            # Both conditions, not just the port: the socket accepts as soon as
            # setup_servers finishes, but the running-hook chain -- the part
            # that reads the shared ctx -- runs after that, and the start lock
            # must be held until it has completed.
            if self._running_signal.reached.is_set() and _port_accepts(self.host, self.port):
                return
            time.sleep(0.05)
        self.stop()
        raise ProxyError(
            "timeout", "mitmproxy did not begin listening in time", port=self.port
        )

    def _run(self) -> None:
        loop: asyncio.AbstractEventLoop | None = None
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            opts = options.Options(listen_host=self.host, listen_port=self.port)
            # Only the constructor may disagree about kwargs across mitmproxy
            # versions. Catching TypeError around run() too would treat a bug
            # inside a running proxy as a signature mismatch and start a second
            # DumpMaster on the same port.
            try:
                master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            except TypeError:
                master = DumpMaster(opts)
            _strip_dump_cli_addons(master)
            if self.ssl_insecure:
                # Do not verify the upstream server's TLS certificate. RE targets
                # routinely use self-signed, private-CA or pinned certificates,
                # and mitmproxy's default verification turns those into a 502 with
                # no flow recorded at all -- the analyst sees an empty capture.
                # Set after construction: ssl_insecure is only registered once the
                # TLS addon has loaded, which DumpMaster() does.
                master.options.update(ssl_insecure=True)
            # The signal goes in last so its running() fires after every other
            # addon's: that is what makes it mean "the hazard window is over".
            master.addons.add(self.recorder, self._running_signal)
            self._master = master
            self._started.set()
            loop.run_until_complete(master.run())
        except BaseException as exc:  # noqa: BLE001 - report to the starting thread
            self._error = exc
            self._started.set()
        finally:
            # Closing the loop outright abandons mitmproxy's still-pending
            # accept task, which leaves the listening socket open at the OS
            # level: stop() would appear to work while the port stayed bound
            # and the next capture could never start. Unwind the tasks first.
            if loop is not None:
                with contextlib.suppress(Exception):
                    _shutdown_loop(loop)
            _uninstall_master_logging(self._master, loop)

    def stop(self) -> None:
        master = self._master
        loop = self._loop
        if master is not None and loop is not None:
            # Release the listening socket before unwinding the master: neither
            # Master.done() nor closing the loop closes the proxy server, so
            # without this the port stays bound until the whole process exits.
            _close_proxy_servers(master, loop)
            with contextlib.suppress(Exception):
                loop.call_soon_threadsafe(master.shutdown)
        if self._thread is not None:
            self._thread.join(timeout=10.0)
        # Also here, not only in the thread's own unwind: a thread that is wedged
        # never runs its finally, and a stale handler is the one piece of a dead
        # proxy that keeps costing the whole process something.
        _uninstall_master_logging(master)
        self._master = None
        self._loop = None


class ProxyBackend:
    def __init__(self) -> None:
        self._instances: dict[str, _ProxyInstance] = {}
        self._lock = threading.RLock()
        self._available: bool | None = None

    def _check_available(self) -> None:
        if self._available is None:
            try:
                import mitmproxy  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        if not self._available:
            raise ProxyError("capability_unavailable", "mitmproxy is not installed")

    def _get(self, session_id: str) -> _ProxyInstance:
        with self._lock:
            inst = self._instances.get(session_id)
        if inst is None:
            raise ProxyError("invalid_state", "no proxy running for this session; call proxy.start")
        return inst

    def start(
        self,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        ssl_insecure: bool = False,
    ) -> JsonObject:
        self._check_available()
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ProxyError("invalid_params", "port must be 1..65535", port=port)
        with self._lock:
            if session_id in self._instances:
                raise ProxyError("invalid_state", "proxy already running for this session")
            for owner, existing in self._instances.items():
                if existing.host == host and existing.port == port:
                    raise ProxyError(
                        "invalid_state",
                        "port is already reserved by another session",
                        host=host,
                        port=port,
                        owner_session_id=owner,
                    )
            # Reserve before listen: two workers racing start() used to each
            # bind a port, and only the last write to this dict was tracked.
            inst = _ProxyInstance(host, port, ssl_insecure=ssl_insecure)
            self._instances[session_id] = inst
        try:
            inst.start()
        except BaseException:
            with self._lock:
                if self._instances.get(session_id) is inst:
                    self._instances.pop(session_id, None)
            with contextlib.suppress(Exception):
                inst.stop()
            raise
        with self._lock:
            if self._instances.get(session_id) is inst:
                return {
                    "running": True,
                    "host": host,
                    "port": port,
                    "endpoint": f"{host}:{port}",
                    "ssl_insecure": ssl_insecure,
                }
        with contextlib.suppress(Exception):
            inst.stop()
        raise ProxyError("invalid_state", "proxy was stopped while starting")

    def stop(self, session_id: str) -> JsonObject:
        with self._lock:
            inst = self._instances.pop(session_id, None)
        if inst is None:
            return {"stopped": False, "note": "no proxy was running"}
        inst.stop()
        return {"stopped": True}

    def status(self, session_id: str) -> JsonObject:
        with self._lock:
            inst = self._instances.get(session_id)
        if inst is None:
            return {"running": False}
        return {
            "running": True,
            "host": inst.host,
            "port": inst.port,
            "flow_count": inst.recorder.count(),
            "retained_max": _MAX_FLOWS,
            "retained_bytes": inst.recorder.retained_bytes(),
            "retained_bytes_max": _MAX_RETAINED_BYTES,
        }

    def clear(self, session_id: str) -> JsonObject:
        """Empty the capture ring without stopping the proxy.

        The proxy keeps running (same port, CA still installed); only the flows
        recorded so far are dropped. This is the triage move: clear the noise,
        reproduce the one action you care about, then read a clean capture --
        instead of paging past everything or stop/starting and losing the port
        and CA setup. Answers with cleared (how many flow summaries were
        discarded) and running true.
        """
        inst = self._get(session_id)
        cleared = inst.recorder.clear()
        return {"cleared": cleared, "running": True}

    def stats(self, session_id: str) -> JsonObject:
        """Aggregate the whole capture into a triage summary.

        proxy.flows is a paged listing; on a capture of hundreds of flows a
        caller had to walk every page to learn what hosts, methods, statuses and
        content types are present before it could sensibly filter. This folds the
        ring once into counts: by method, by status class (2xx/4xx/...), the top
        hosts and content types (capped, with the distinct totals so a trimmed
        list is visible), and how many flows failed, upgraded to WebSocket or
        carried a request body. dropped mirrors proxy.flows: the ring evictions
        the summary can no longer see.
        """
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        total = len(items)
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - total)
        by_method: dict[str, int] = {}
        by_status_class: dict[str, int] = {}
        host_counts: dict[str, int] = {}
        content_counts: dict[str, int] = {}
        failed = websockets = with_request_body = no_status = 0
        for summary in items:
            method = (str(summary.get("method", "") or "").upper()) or "UNKNOWN"
            by_method[method] = by_method.get(method, 0) + 1
            status = summary.get("status")
            if isinstance(status, int):
                cls = f"{status // 100}xx"
                by_status_class[cls] = by_status_class.get(cls, 0) + 1
            else:
                no_status += 1
            host = str(summary.get("host", "") or "")
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1
            # Drop the ``; charset=...`` parameter so the same media type is one
            # bucket, not several.
            ctype = str(summary.get("content_type", "") or "").split(";")[0].strip().lower()
            if ctype:
                content_counts[ctype] = content_counts.get(ctype, 0) + 1
            if summary.get("failed"):
                failed += 1
            if summary.get("is_websocket"):
                websockets += 1
            if summary.get("has_request_body"):
                with_request_body += 1

        def _top(counts: dict[str, int], key: str, cap: int) -> list[JsonObject]:
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            return [{key: name, "count": count} for name, count in ranked[:cap]]

        return {
            "total": total,
            "dropped": dropped,
            "by_method": by_method,
            "by_status_class": by_status_class,
            "top_hosts": _top(host_counts, "host", _MAX_STATS_HOSTS),
            "host_count": len(host_counts),
            "top_content_types": _top(content_counts, "content_type", _MAX_STATS_CONTENT_TYPES),
            "content_type_count": len(content_counts),
            "failed": failed,
            "websockets": websockets,
            "with_request_body": with_request_body,
            "no_status": no_status,
        }

    def search(
        self,
        session_id: str,
        query: str,
        *,
        limit: int = 100,
        include_bodies: bool = True,
    ) -> JsonObject:
        """Grep the whole capture for a case-insensitive substring.

        proxy.flows and proxy.stats find a flow by its metadata; neither can
        answer "which request or response actually contains this token / this
        endpoint / this error string?" without pulling every flow with flow.get
        and reading it by hand. This folds that scan into one call: it walks the
        capture and, per flow, reports where the needle hit -- url,
        request_headers, response_headers, request_body, response_body, or
        websocket. Bodies are the content-encoding-decoded payloads (the same
        bytes flow.get returns, so a gzip'd JSON response is searched decoded,
        not compressed); a body that was not retained (over the cap, or evicted)
        is simply skipped, and include_bodies=false restricts the scan to
        url/headers/frames for a cheaper metadata-only pass.
        """
        if not query or not query.strip():
            raise ProxyError("invalid_params", "query is required")
        needle = query.casefold()
        inst = self._get(session_id)
        summaries = inst.recorder.snapshot()
        dropped = 0
        if summaries:
            dropped = max(0, int(summaries[-1].get("seq") or 0) - len(summaries))
        cap = max(1, min(int(limit), 1000))
        matches: list[JsonObject] = []
        total = 0
        bodies_scanned = 0
        bodies_omitted = 0
        for summary in summaries:
            flow_id = str(summary.get("id"))
            where: list[str] = []
            if needle in str(summary.get("url", "")).casefold():
                where.append("url")
            raw = inst.recorder.raw(flow_id)
            if raw is _OMITTED_BODY:
                bodies_omitted += 1
            elif raw is not None:
                req = getattr(raw, "request", None)
                resp = getattr(raw, "response", None)
                if _headers_contain(req, needle):
                    where.append("request_headers")
                if _headers_contain(resp, needle):
                    where.append("response_headers")
                if include_bodies:
                    bodies_scanned += 1
                    if needle in _message_body(req).decode("utf-8", "replace").casefold():
                        where.append("request_body")
                    if needle in _message_body(resp).decode("utf-8", "replace").casefold():
                        where.append("response_body")
            websocket = inst.recorder.websocket(flow_id)
            if websocket is not None and any(
                needle in str(msg.get("text", "")).casefold()
                for msg in websocket.get("messages", [])
            ):
                where.append("websocket")
            if not where:
                continue
            total += 1
            if len(matches) < cap:
                matches.append(
                    {
                        "id": flow_id,
                        "seq": summary.get("seq"),
                        "method": summary.get("method"),
                        "url": summary.get("url"),
                        "host": summary.get("host"),
                        "status": summary.get("status"),
                        "where": where,
                    }
                )
        return {
            "query": query,
            "matches": matches,
            "count": len(matches),
            "total": total,
            "scanned": len(summaries),
            "bodies_scanned": bodies_scanned,
            "bodies_omitted": bodies_omitted,
            "include_bodies": include_bodies,
            "truncated": total > len(matches),
            "dropped": dropped,
        }

    def flows(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        method: str | None = None,
        host: str | None = None,
        url_contains: str | None = None,
        status: int | None = None,
    ) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        # ``dropped`` is the ring-eviction count for the whole capture, so it is
        # measured against every recorded flow -- before any filter narrows the
        # view -- otherwise a filtered page would misreport how much history the
        # ring has already lost.
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        unfiltered_total = len(items)
        filtered = any(v is not None for v in (method, host, url_contains, status))
        if filtered:
            # Narrow before paginating so the pagination fields describe the
            # result set the caller is actually walking. Finding one request
            # among thousands otherwise meant paging the whole log by hand.
            items = [
                summary
                for summary in items
                if _flow_matches(summary, method, host, url_contains, status)
            ]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        result: JsonObject = {
            "flows": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
        }
        if filtered:
            # total already reports the matched count; unfiltered_total keeps the
            # size of the whole capture visible so a small match is not read as a
            # small capture.
            result["filtered"] = True
            result["unfiltered_total"] = unfiltered_total
        return result

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        inst = self._get(session_id)
        flow = inst.recorder.raw(flow_id)
        if flow is None:
            raise ProxyError(
                "not_found",
                "unknown flow id (it may have been evicted from the capture ring)",
                flow_id=flow_id,
            )
        if flow is _OMITTED_BODY:
            raise ProxyError(
                "too_large",
                "flow body was not retained",
                flow_id=flow_id,
            )
        req = flow.request
        resp = flow.response
        req_body = _message_body(req)
        resp_body = _message_body(resp)
        result: JsonObject = {
            "id": flow_id,
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "headers": dict(req.headers),
                "size": len(req_body),
            },
            "response": {
                "status": getattr(resp, "status_code", None),
                "headers": dict(resp.headers) if resp else {},
                "size": len(resp_body),
            },
        }
        # size is the decoded length; note the wire encoding so a caller knows
        # the body was decompressed (and that size != the Content-Length header).
        req_encoding = _content_encoding(req)
        if req_encoding:
            result["request"]["content_encoding"] = req_encoding
        resp_encoding = _content_encoding(resp)
        if resp_encoding:
            result["response"]["content_encoding"] = resp_encoding
        # The request body is often the point of the capture (POST params, a
        # JSON payload, credentials); it used to be dropped, leaving only the
        # response. Both are now returned, inline when small and spilled to an
        # artifact when large, symmetrically.
        _attach_body(result["request"], req_body, artifact_dir, prefix="flow-req")
        _attach_body(result["response"], resp_body, artifact_dir, prefix="flow")
        # A WebSocket upgrade's payload is not in the 101 response -- it is the
        # frames that follow, captured separately. Surface them so an analyst
        # sees the actual duplex traffic, not just the handshake.
        websocket = inst.recorder.websocket(flow_id)
        if websocket is not None:
            result["websocket"] = websocket
        # An errored flow has a request but no response; surface the failure so
        # flow_get on it reads as "the upstream failed", not "the response was
        # empty".
        error = getattr(flow, "error", None)
        error_msg = getattr(error, "msg", None) if error is not None else None
        if error_msg:
            result["failed"] = True
            result["error"] = str(error_msg)[:2000]
        return result

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        inst = self._get(session_id)
        flow = inst.recorder.raw(flow_id)
        master = inst._master
        if flow is None:
            raise ProxyError("not_found", "unknown flow id", flow_id=flow_id)
        if flow is _OMITTED_BODY:
            raise ProxyError(
                "too_large",
                "flow body was not retained; cannot replay",
                flow_id=flow_id,
            )
        if master is None or inst._loop is None:
            raise ProxyError("invalid_state", "proxy is not running")
        try:
            new_flow = flow.copy()
            done: concurrent.futures.Future[Any] = concurrent.futures.Future()

            def _run() -> None:
                try:
                    master.commands.call("replay.client", [new_flow])
                except Exception as exc:  # noqa: BLE001
                    if not done.done():
                        done.set_exception(exc)
                    return
                if not done.done():
                    done.set_result(True)

            inst._loop.call_soon_threadsafe(_run)
            done.result(timeout=_REPLAY_WAIT_S)
        except concurrent.futures.TimeoutError as exc:
            raise ProxyError(
                "timeout", "replay did not complete", flow_id=flow_id
            ) from exc
        except ProxyError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ProxyError("backend_error", f"replay failed: {exc}", flow_id=flow_id) from exc
        return {"replayed": True, "flow_id": flow_id}

    def export_har(self, session_id: str, out_path: Path) -> JsonObject:
        """Serialise the capture as a conformant HAR 1.2 log.

        The old export named only each flow's method/url/status/mimeType, which
        is not valid HAR 1.2 -- the viewers this feeds (DevTools Import HAR, HAR
        Analyzer, har-validator) reject an entry with no startedDateTime,
        timings, cookies, headers or queryString, so the file was effectively
        unusable. The proxy already retains the whole flow, so this now emits
        conformant entries: request/response headers (the auth, cookie,
        content-type and CORS lines an analyst actually reads, with duplicates
        preserved), the parsed query string, real per-flow timings and start
        times, and the decoded response size. Bodies are not inlined -- a
        capture can hold megabytes per flow -- so ``response.content`` carries
        the size and mimeType and ``proxy.flow.get`` remains the way to read a
        body. A failed upstream flow is emitted with status 0 and an ``_error``
        note rather than dropped. Oldest entries are trimmed to fit the capture
        cap, mirroring the web HAR export.
        """
        import json

        inst = self._get(session_id)
        entries: list[JsonObject] = []
        for summary in inst.recorder.snapshot():
            flow_id = str(summary.get("id"))
            url = str(summary.get("url") or "")
            method = str(summary.get("method") or "")
            status = summary.get("status")
            content_type = str(summary.get("content_type") or "")
            raw = inst.recorder.raw(flow_id)
            req_obj = resp_obj = None
            if raw is not None and raw is not _OMITTED_BODY:
                req_obj = getattr(raw, "request", None)
                resp_obj = getattr(raw, "response", None)
            resp_body_len = len(_message_body(resp_obj)) if resp_obj is not None else 0
            req_body_len = _content_len(req_obj)
            time_ms = _har_time_ms(req_obj, resp_obj)
            entry: JsonObject = {
                "startedDateTime": _har_started(req_obj),
                "time": time_ms,
                "request": {
                    "method": method,
                    "url": url,
                    "httpVersion": str(getattr(req_obj, "http_version", "") or "HTTP/1.1"),
                    "cookies": [],
                    "headers": _har_flow_headers(req_obj),
                    "queryString": _har_query_string(url),
                    "headersSize": -1,
                    "bodySize": req_body_len if req_body_len else -1,
                },
                "response": {
                    "status": status if isinstance(status, int) else 0,
                    "statusText": str(getattr(resp_obj, "reason", "") or ""),
                    "httpVersion": str(getattr(resp_obj, "http_version", "") or "HTTP/1.1"),
                    "cookies": [],
                    "headers": _har_flow_headers(resp_obj),
                    "content": {"size": resp_body_len, "mimeType": content_type},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": resp_body_len if resp_body_len else -1,
                },
                "cache": {},
                "timings": {"send": 0, "wait": time_ms, "receive": 0},
            }
            if summary.get("failed"):
                entry["response"]["_error"] = str(summary.get("error") or "")
            entries.append(entry)
        har: JsonObject = {
            "log": {"version": "1.2", "creator": {"name": "headless-re-mcp"}, "entries": entries}
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(har, ensure_ascii=False)
        truncated = False
        encoded = text.encode("utf-8")
        # Drop oldest entries until the file fits the capture cap, exactly as the
        # web HAR export does, so one huge capture cannot write an unbounded file.
        while entries and len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            drop = max(1, len(entries) // 8)
            del entries[:drop]
            har["log"]["entries"] = entries
            text = json.dumps(har, ensure_ascii=False)
            encoded = text.encode("utf-8")
            truncated = True
        if len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise ProxyError(
                "too_large",
                "HAR export exceeds capture cap",
                size=len(encoded),
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        out_path.write_text(text, encoding="utf-8")
        return {
            "path": str(out_path),
            "entry_count": len(entries),
            "truncated": truncated,
            "size": len(encoded),
        }

    def ca_cert_path(self) -> Path | None:
        for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
            candidate = Path.home() / ".mitmproxy" / name
            if candidate.is_file():
                return candidate
        return None

    def close_all(self) -> None:
        with self._lock:
            instances = list(self._instances.values())
            self._instances.clear()
        for inst in instances:
            inst.stop()
