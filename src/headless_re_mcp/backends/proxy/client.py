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
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from headless_re_mcp.backends.common.har import har_entry, serialize_har
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES

JsonObject = dict[str, Any]
_MAX_FLOWS = 2000
_REPLAY_WAIT_S = 15.0
_SERVER_STOP_WAIT_S = 10.0
# The ring is count-capped, but each slot can still hold a multi-megabyte
# request or response. Two thousand of those is the overnight OOM the count
# cap was supposed to prevent.
_MAX_STORED_BODY = 2 * 1024 * 1024
_MAX_RETAINED_BYTES = 64 * 1024 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
# A body at or under this stays inline as text; anything larger, or anything
# that is not valid UTF-8, spills to a file so the caller never receives a
# lossy decode masquerading as the real bytes.
_MAX_INLINE_BODY = 200_000
# flow.get returns headers inline. The body is already spilled/capped, but the
# header map was dumped whole, so a chatty or hostile server (thousands of
# headers, a multi-kilobyte Set-Cookie) could return an unbounded blob into the
# tool response. Bound it in count, per-value and total size like the rest.
_MAX_FLOW_HEADERS = 100
_MAX_HEADER_VALUE_BYTES = 4 * 1024
_MAX_FLOW_HEADERS_TOTAL_BYTES = 64 * 1024
_OMITTED_BODY = object()
# proxy.stats top-N ceiling: a capture can touch thousands of hosts, so the
# ranked host/content-type lists are capped even when the caller asks for more.
_MAX_TOP_STATS = 50


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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


def _drain_proxy_servers(master: Any, loop: asyncio.AbstractEventLoop) -> None:
    """Close mitmproxy's listening servers, and wait until they are down.

    ``Master.done()`` stopped tearing down the proxyserver's listeners on the
    road to mitmproxy 12 -- mitmdump never noticed because the whole process
    exits right after ``run()`` returns. Embedded in a long-lived service,
    ``shutdown()`` alone therefore leaves the OS socket accepting forever:
    stop() reports "stopped" and joins a thread that exits cleanly, yet the
    port stays bound until the process dies, so no later capture can ever bind
    it again. Draining ``Servers.update([])`` on the proxy loop is the
    documented way to stop every listener, and it awaits their close.
    """
    try:
        addon = master.addons.get("proxyserver")
        update = getattr(getattr(addon, "servers", None), "update", None)
        if update is None:
            return
        future = asyncio.run_coroutine_threadsafe(update([]), loop)
    except Exception:  # noqa: BLE001 - the addon surface varies across versions
        return
    with contextlib.suppress(Exception):
        future.result(timeout=_SERVER_STOP_WAIT_S)


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


def _raw_body(part: Any) -> bytes:
    """The raw bytes of a request/response, or empty when there is no body.

    mitmproxy decodes ``raw_content`` lazily and can raise while doing so; a
    failure there is not a reason to fail the whole fetch, so it reads as an
    empty body the same way a bodyless message does.
    """
    if part is None:
        return b""
    try:
        content = part.raw_content
    except Exception:  # noqa: BLE001 - a decode failure is an empty body here
        return b""
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    return b""


def _emit_body(raw: bytes, artifact_dir: Path) -> JsonObject:
    """Describe one message body without ever handing back a lossy decode.

    Text within the inline cap comes back as ``body``; a larger body, or one
    that is not valid UTF-8, spills to a ``.bin`` artifact and comes back as
    ``body_path`` with ``spill_reason`` so a caller can tell "too big to inline"
    from "not text" and never mistakes replacement characters for real bytes.
    """
    out: JsonObject = {"size": len(raw)}
    if not raw:
        out["body"] = ""
        return out
    too_large = len(raw) > _MAX_INLINE_BODY
    if not too_large:
        try:
            out["body"] = raw.decode("utf-8")
            return out
        except UnicodeDecodeError:
            pass
    artifact_dir.mkdir(parents=True, exist_ok=True)
    dest = artifact_dir / f"flow-{uuid4().hex}.bin"
    dest.write_bytes(raw)
    out["body_path"] = str(dest)
    out["spill_reason"] = "too_large" if too_large else "binary"
    return out


def _bounded_headers(part: Any) -> tuple[dict[str, str], bool]:
    """Header map for flow.get, bounded in count, per-value and total size.

    mitmproxy keeps whole headers on the retained flow, so a hostile or chatty
    server could otherwise put megabytes of them inline in the tool response.
    Duplicate names collapse to the last value, matching the previous
    ``dict(headers)``; the returned flag says when anything was dropped so a
    reader does not mistake a bounded map for the whole header set.
    """
    headers = getattr(part, "headers", None)
    if headers is None:
        return {}, False
    try:
        try:
            items = list(headers.items(multi=True))
        except TypeError:
            items = list(headers.items())
    except Exception:  # noqa: BLE001
        return {}, True
    out: dict[str, str] = {}
    truncated = False
    total = 0
    for key, value in items:
        name = str(key)
        if name not in out and len(out) >= _MAX_FLOW_HEADERS:
            truncated = True
            break
        text, cut = _bounded_metadata(value, _MAX_HEADER_VALUE_BYTES)
        truncated = truncated or cut
        entry_bytes = len(name.encode("utf-8", errors="replace")) + len(
            text.encode("utf-8", errors="replace")
        )
        if total + entry_bytes > _MAX_FLOW_HEADERS_TOTAL_BYTES:
            truncated = True
            break
        total += entry_bytes
        out[name] = text
    return out, truncated


def summarize_flows(
    items: list[JsonObject], *, dropped: int = 0, top: int = 10
) -> JsonObject:
    """Fold a flow snapshot into the aggregate a capture triage reads first.

    Pure over the summary rows the recorder already produces (id/method/url/
    host/status/content_type/response_size, plus error/body_omitted), so it
    needs no proxy instance and stays testable in isolation. content_type is
    normalised to the bare media type (the ``; charset=...`` tail is dropped)
    and host is taken as recorded; both ranked lists are capped at ``top``.
    """
    top = max(1, min(int(top), _MAX_TOP_STATS))
    methods: Counter[str] = Counter()
    status_classes: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    errors = 0
    body_omitted = 0
    total_response_bytes = 0
    for row in items:
        methods[str(row.get("method") or "").upper() or "?"] += 1
        status = row.get("status")
        if isinstance(status, int):
            status_classes[f"{status // 100}xx"] += 1
        else:
            # An errored or still-pending flow carries a null status; it is a
            # class of its own, not folded into any numeric bucket.
            status_classes["none"] += 1
        host = str(row.get("host") or "")
        if host:
            hosts[host] += 1
        ctype = str(row.get("content_type") or "").split(";", 1)[0].strip().lower()
        if ctype:
            content_types[ctype] += 1
        if row.get("error"):
            errors += 1
        if row.get("body_omitted"):
            body_omitted += 1
        size = row.get("response_size")
        if isinstance(size, int) and size > 0:
            total_response_bytes += size

    def _ranked(counter: Counter[str]) -> list[tuple[str, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:top]

    return {
        "total": len(items),
        "dropped": dropped,
        "methods": dict(sorted(methods.items(), key=lambda kv: (-kv[1], kv[0]))),
        "status_classes": dict(sorted(status_classes.items())),
        "top_hosts": [{"host": h, "count": c} for h, c in _ranked(hosts)],
        "host_count": len(hosts),
        "top_content_types": [
            {"content_type": t, "count": c} for t, c in _ranked(content_types)
        ],
        "content_type_count": len(content_types),
        "errors": errors,
        "body_omitted": body_omitted,
        "total_response_bytes": total_response_bytes,
    }


# proxy.search ceilings: a capture holds up to _MAX_FLOWS rows, so the result
# list is capped, and each match snippet is bounded so a hit inside a big body
# does not drag the whole body into the response.
_MAX_SEARCH_RESULTS = 1000
_SEARCH_SNIPPET_CHARS = 80
_SEARCH_SNIPPET_MAX = 400
# proxy.endpoints result cap: distinct endpoints are bounded by the flow ring,
# but the returned page is still capped like every other list.
_MAX_ENDPOINTS_PAGE = 1000
# proxy.cookies caps: a response can carry many Set-Cookie headers and each
# value can be a long token, so the header scan, each value, and the inventory
# are all bounded.
_MAX_COOKIE_HEADER_SCAN = 400
_MAX_COOKIE_VALUE_CHARS = 4096
_MAX_COOKIE_INVENTORY = 1000
# proxy.security_headers: the response headers whose absence is the finding,
# mapped to the short key the tool reports. Values and the document inventory
# are bounded so a chatty capture cannot blow the response.
_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": "csp",
    "strict-transport-security": "hsts",
    "x-frame-options": "x_frame_options",
    "x-content-type-options": "x_content_type_options",
    "referrer-policy": "referrer_policy",
    "permissions-policy": "permissions_policy",
    "cross-origin-opener-policy": "coop",
    "cross-origin-embedder-policy": "coep",
    "cross-origin-resource-policy": "corp",
}
_MAX_SEC_HEADER_VALUE_CHARS = 4096
_MAX_SEC_DOCUMENTS = 1000


def _cookie_header_pairs(part: Any) -> list[tuple[str, str]]:
    """Every (lowercased name, value) header on a message, bounded in count.

    Unlike _bounded_headers this keeps duplicates, because a response commonly
    carries several Set-Cookie headers that collapsing to a dict would lose.
    """
    headers = getattr(part, "headers", None)
    if headers is None:
        return []
    try:
        try:
            items = list(headers.items(multi=True))
        except TypeError:
            items = list(headers.items())
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for key, value in items[:_MAX_COOKIE_HEADER_SCAN]:
        out.append((str(key).lower(), str(value)))
    return out


def _parse_set_cookie(value: str) -> tuple[str, str, dict[str, Any]] | None:
    """Split one Set-Cookie value into (name, value, attributes)."""
    segments = value.split(";")
    first = segments[0].strip()
    if "=" not in first:
        return None
    name, _, cval = first.partition("=")
    name = name.strip()
    if not name:
        return None
    attrs: dict[str, Any] = {}
    for segment in segments[1:]:
        segment = segment.strip()
        if not segment:
            continue
        if "=" in segment:
            key, _, val = segment.partition("=")
            attrs[key.strip().lower()] = val.strip()
        else:
            attrs[segment.lower()] = True
    return name, cval.strip(), attrs


def _parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Split a request Cookie header into its name=value pairs."""
    pairs: list[tuple[str, str]] = []
    for segment in value.split(";"):
        segment = segment.strip()
        if "=" in segment:
            key, _, val = segment.partition("=")
            pairs.append((key.strip(), val.strip()))
    return pairs


def _blank_cookie(name: str, domain: str) -> JsonObject:
    return {
        "name": name,
        "domain": domain,
        "value": "",
        "path": None,
        "http_only": False,
        "secure": False,
        "same_site": None,
        "set_count": 0,
        "sent_count": 0,
    }


def fold_cookies(
    rows: list[JsonObject], raw_lookup: Any, *, limit: int = 200
) -> JsonObject:
    """Fold Set-Cookie (responses) and Cookie (requests) into a distinct inventory.

    Pure over the recorder's two views. Set-Cookie carries the security
    attributes (Domain/Path/HttpOnly/Secure/SameSite); the request Cookie header
    only proves a name was sent back. Cookies are keyed by (name, domain), so
    the same name on two hosts stays distinct. A flow whose headers were evicted
    (body_omitted) contributes nothing and is counted in body_unavailable.
    """
    inventory: dict[tuple[str, str], JsonObject] = {}
    body_unavailable = 0
    for row in rows:
        host = str(row.get("host") or "")
        flow_id = str(row.get("id") or "")
        raw = raw_lookup(flow_id) if flow_id else None
        if raw is _OMITTED_BODY:
            body_unavailable += 1
            continue
        if raw is None:
            continue
        resp = getattr(raw, "response", None)
        if resp is not None:
            for name_lower, value in _cookie_header_pairs(resp):
                if name_lower != "set-cookie":
                    continue
                parsed = _parse_set_cookie(value)
                if parsed is None:
                    continue
                cname, cval, attrs = parsed
                domain = str(attrs.get("domain") or host)
                entry = inventory.setdefault((cname, domain), _blank_cookie(cname, domain))
                entry["value"] = cval[:_MAX_COOKIE_VALUE_CHARS]
                entry["set_count"] += 1
                entry["http_only"] = entry["http_only"] or ("httponly" in attrs)
                entry["secure"] = entry["secure"] or ("secure" in attrs)
                same_site = attrs.get("samesite")
                if isinstance(same_site, str):
                    entry["same_site"] = same_site
                path = attrs.get("path")
                if isinstance(path, str):
                    entry["path"] = path
        req = getattr(raw, "request", None)
        if req is not None:
            for name_lower, value in _cookie_header_pairs(req):
                if name_lower != "cookie":
                    continue
                for cname, cval in _parse_cookie_header(value):
                    entry = inventory.setdefault((cname, host), _blank_cookie(cname, host))
                    if not entry["value"]:
                        entry["value"] = cval[:_MAX_COOKIE_VALUE_CHARS]
                    entry["sent_count"] += 1

    cookies = list(inventory.values())
    for entry in cookies:
        sources: list[str] = []
        if entry["set_count"]:
            sources.append("set-cookie")
        if entry["sent_count"]:
            sources.append("cookie")
        entry["sources"] = sources
    cookies.sort(
        key=lambda e: (
            -(int(e["set_count"]) + int(e["sent_count"])),
            str(e["name"]),
            str(e["domain"]),
        )
    )
    cap = max(1, min(int(limit), _MAX_COOKIE_INVENTORY))
    window = cookies[:cap]
    return {
        "cookies": window,
        "count": len(window),
        "total": len(cookies),
        "truncated": len(window) < len(cookies),
        "body_unavailable": body_unavailable,
    }


def fold_security_headers(
    rows: list[JsonObject], raw_lookup: Any, *, limit: int = 200
) -> JsonObject:
    """Audit each served document's response security headers.

    Pure over the recorder's two views (summary rows plus the flow_id -> raw
    lookup). A document is any response typed text/html, plus any response that
    carries at least one tracked security header; each is folded by (host, path)
    -- the query string dropped -- and reports which of the tracked headers
    (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, COOP/COEP/CORP) are present and which are missing. The
    finding is usually the absence: a page served with no CSP and no HSTS. A
    flow whose body (and thus headers) was evicted contributes nothing and, when
    it looked like a document, is counted in body_unavailable.
    """
    docs: dict[tuple[str, str], JsonObject] = {}
    body_unavailable = 0
    for row in rows:
        content_type = str(row.get("content_type") or "")
        is_html = "html" in content_type.lower()
        flow_id = str(row.get("id") or "")
        raw = raw_lookup(flow_id) if flow_id else None
        if raw is _OMITTED_BODY:
            if is_html:
                body_unavailable += 1
            continue
        found: dict[str, str] = {}
        if raw is not None:
            resp = getattr(raw, "response", None)
            if resp is not None:
                for name_lower, value in _cookie_header_pairs(resp):
                    mapped = _SECURITY_HEADERS.get(name_lower)
                    if mapped is None:
                        continue
                    if mapped in found:
                        # CSP and the like can legitimately repeat; keep them joined
                        # rather than letting the last win.
                        joined = found[mapped] + ", " + value
                        found[mapped] = joined[:_MAX_SEC_HEADER_VALUE_CHARS]
                    else:
                        found[mapped] = value[:_MAX_SEC_HEADER_VALUE_CHARS]
        # A non-document response with no security header at all is noise here.
        if not is_html and not found:
            continue
        host = str(row.get("host") or "")
        url = str(row.get("url") or "")
        path = "/"
        if url:
            parts = urlsplit(url)
            if not host:
                host = parts.netloc
            path = parts.path or "/"
        key = (host, path)
        doc = docs.get(key)
        if doc is None:
            doc = {
                "host": host,
                "path": path,
                "status": row.get("status"),
                "content_type": content_type,
                "headers": {},
            }
            docs[key] = doc
        headers: dict[str, str] = doc["headers"]
        for name, value in found.items():
            headers.setdefault(name, value)

    tracked = sorted(_SECURITY_HEADERS.values())
    missing_counts: dict[str, int] = dict.fromkeys(tracked, 0)
    documents: list[JsonObject] = []
    for doc in docs.values():
        headers = doc["headers"]
        doc["present"] = sorted(headers.keys())
        missing = [name for name in tracked if name not in headers]
        doc["missing"] = missing
        for name in missing:
            missing_counts[name] += 1
        documents.append(doc)

    cap = max(1, min(int(limit), _MAX_SEC_DOCUMENTS))
    window = documents[:cap]
    return {
        "documents": window,
        "count": len(window),
        "total": len(documents),
        "truncated": len(window) < len(documents),
        "body_unavailable": body_unavailable,
        "tracked_headers": tracked,
        "missing_counts": missing_counts,
    }


def fold_endpoints(rows: list[JsonObject], *, limit: int = 100) -> JsonObject:
    """Fold a flow snapshot into distinct (method, host, path) endpoints.

    Pure over the recorder's summary rows. The query string is stripped so
    ``/search?q=a`` and ``/search?q=b`` collapse to one endpoint -- the view an
    API map wants -- and each endpoint aggregates its hit count, the distinct
    status codes seen, and how many of its flows errored. Ranked by hits.
    """
    buckets: dict[tuple[str, str, str], JsonObject] = {}
    for row in rows:
        method = str(row.get("method") or "").upper() or "?"
        url = str(row.get("url") or "")
        host = str(row.get("host") or "")
        path = "/"
        if url:
            parts = urlsplit(url)
            if not host:
                host = parts.netloc
            path = parts.path or "/"
        key = (method, host, path)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "method": method,
                "host": host,
                "path": path,
                "hits": 0,
                "_statuses": set(),
                "errors": 0,
            }
            buckets[key] = bucket
        bucket["hits"] += 1
        status = row.get("status")
        if isinstance(status, int):
            bucket["_statuses"].add(status)
        if row.get("error"):
            bucket["errors"] += 1

    endpoints: list[JsonObject] = []
    for bucket in buckets.values():
        statuses = bucket.pop("_statuses")
        bucket["statuses"] = sorted(statuses)
        endpoints.append(bucket)
    endpoints.sort(
        key=lambda e: (-e["hits"], str(e["host"]), str(e["path"]), str(e["method"]))
    )
    cap = max(1, min(int(limit), _MAX_ENDPOINTS_PAGE))
    window = endpoints[:cap]
    return {
        "endpoints": window,
        "count": len(window),
        "total": len(endpoints),
        "truncated": len(window) < len(endpoints),
        "total_flows": len(rows),
    }


def fold_hosts(rows: list[JsonObject], *, limit: int = 100) -> JsonObject:
    """Fold a flow snapshot into distinct hosts: who did this app talk to.

    Coarser than fold_endpoints (which keys on method+path): this is the one-look
    contacted-hosts inventory. Each host aggregates its hit count, the schemes
    seen (so a host reached over cleartext http stands out), the methods and
    distinct status codes, how many flows errored, and the first/last capture
    sequence numbers so first contact is visible. Ranked by hits.
    """
    buckets: dict[str, JsonObject] = {}
    for row in rows:
        url = str(row.get("url") or "")
        host = str(row.get("host") or "")
        scheme = ""
        if url:
            parts = urlsplit(url)
            if not host:
                host = parts.netloc
            scheme = parts.scheme
        if not host:
            host = "?"
        bucket = buckets.get(host)
        if bucket is None:
            bucket = {
                "host": host,
                "hits": 0,
                "_schemes": set(),
                "_methods": set(),
                "_statuses": set(),
                "errors": 0,
                "first_seq": None,
                "last_seq": None,
            }
            buckets[host] = bucket
        bucket["hits"] += 1
        if scheme:
            bucket["_schemes"].add(scheme)
        method = str(row.get("method") or "").upper()
        if method:
            bucket["_methods"].add(method)
        status = row.get("status")
        if isinstance(status, int):
            bucket["_statuses"].add(status)
        if row.get("error"):
            bucket["errors"] += 1
        seq = row.get("seq")
        if isinstance(seq, int):
            if bucket["first_seq"] is None or seq < bucket["first_seq"]:
                bucket["first_seq"] = seq
            if bucket["last_seq"] is None or seq > bucket["last_seq"]:
                bucket["last_seq"] = seq

    hosts: list[JsonObject] = []
    for bucket in buckets.values():
        schemes = bucket.pop("_schemes")
        bucket["schemes"] = sorted(schemes)
        bucket["secure"] = "https" in schemes
        bucket["cleartext"] = "http" in schemes
        bucket["methods"] = sorted(bucket.pop("_methods"))
        bucket["statuses"] = sorted(bucket.pop("_statuses"))
        hosts.append(bucket)
    hosts.sort(key=lambda h: (-h["hits"], str(h["host"])))
    cap = max(1, min(int(limit), _MAX_ENDPOINTS_PAGE))
    window = hosts[:cap]
    return {
        "hosts": window,
        "count": len(window),
        "total": len(hosts),
        "truncated": len(window) < len(hosts),
        "total_flows": len(rows),
    }


def _headers_text(headers: dict[str, str]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in headers.items())


def _flow_search_fields(raw: Any) -> dict[str, str]:
    """The searchable text of a retained flow, keyed by where it came from.

    Reuses the same bounded header read and lazy-decode body read as flow.get,
    so a body that mitmproxy cannot decode simply contributes nothing rather
    than raising.
    """
    req = getattr(raw, "request", None)
    resp = getattr(raw, "response", None)
    fields: dict[str, str] = {}
    req_headers, _ = _bounded_headers(req)
    if req_headers:
        fields["request_headers"] = _headers_text(req_headers)
    if resp is not None:
        resp_headers, _ = _bounded_headers(resp)
        if resp_headers:
            fields["response_headers"] = _headers_text(resp_headers)
    req_body = _raw_body(req)
    if req_body:
        fields["request_body"] = req_body.decode("utf-8", errors="replace")
    resp_body = _raw_body(resp)
    if resp_body:
        fields["response_body"] = resp_body.decode("utf-8", errors="replace")
    return fields


def _search_snippet(text: str, index: int, needle_len: int) -> str:
    """A bounded window around a match, with ellipses when it was clipped."""
    start = max(0, index - _SEARCH_SNIPPET_CHARS)
    end = min(len(text), index + needle_len + _SEARCH_SNIPPET_CHARS)
    window = text[start:end]
    if len(window) > _SEARCH_SNIPPET_MAX:
        window = window[:_SEARCH_SNIPPET_MAX]
        end = start + _SEARCH_SNIPPET_MAX
    prefix = "\u2026" if start > 0 else ""
    suffix = "\u2026" if end < len(text) else ""
    return f"{prefix}{window}{suffix}"


def search_flows(
    rows: list[JsonObject],
    raw_lookup: Any,
    query: str,
    *,
    limit: int = 100,
    case_sensitive: bool = False,
) -> JsonObject:
    """Scan a capture for a substring across url/host/headers/bodies.

    Pure over the recorder's two views (the summary rows plus a flow_id ->
    raw-flow lookup), so it needs no live proxy and stays testable. url and host
    come from the summary row and are always searchable; headers and bodies come
    from the retained raw flow, so a flow whose body was evicted (body_omitted)
    can only match on url/host and is counted in body_unavailable. matched_in
    names every field that hit; snippets carries a bounded window for the
    header/body hits.
    """
    cap = max(1, min(int(limit), _MAX_SEARCH_RESULTS))
    needle = query if case_sensitive else query.lower()

    def _hay(text: str) -> str:
        return text if case_sensitive else text.lower()

    matches: list[JsonObject] = []
    body_unavailable = 0
    truncated = False
    for row in rows:
        matched_in: list[str] = []
        snippets: dict[str, str] = {}
        for field in ("url", "host"):
            value = str(row.get(field) or "")
            if value and needle in _hay(value):
                matched_in.append(field)

        flow_id = str(row.get("id") or "")
        raw = raw_lookup(flow_id) if flow_id else None
        if raw is _OMITTED_BODY:
            body_unavailable += 1
        elif raw is not None:
            for field, text in _flow_search_fields(raw).items():
                idx = _hay(text).find(needle)
                if idx != -1:
                    matched_in.append(field)
                    snippets[field] = _search_snippet(text, idx, len(query))

        if not matched_in:
            continue
        entry: JsonObject = {
            key: row.get(key)
            for key in ("id", "method", "url", "host", "status")
            if key in row
        }
        entry["matched_in"] = sorted(set(matched_in))
        if snippets:
            entry["snippets"] = snippets
        matches.append(entry)
        if len(matches) >= cap:
            truncated = True
            break

    return {
        "query": query,
        "matches": matches,
        "count": len(matches),
        "scanned": len(rows),
        "truncated": truncated,
        "body_unavailable": body_unavailable,
        "case_sensitive": bool(case_sensitive),
    }


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
        self._lock = threading.RLock()

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

    def response(self, flow: Any) -> None:  # mitmproxy calls this on each response
        self._record(flow)

    def error(self, flow: Any) -> None:  # mitmproxy calls this when a flow errors
        # A flow that never produced a response -- TLS handshake refused,
        # upstream unreachable, connection reset mid-request -- otherwise
        # vanishes: only `response` was wired, so the capture silently dropped
        # every failed request. That is the opposite of what an RE session
        # wants, where "this host refused the handshake" is often the finding.
        # Record it, marked with error/error_msg, so it is captured like any
        # other flow but stays distinguishable from a completed one (which
        # always carries a numeric status; an errored flow's status is null).
        err = getattr(flow, "error", None)
        message = str(getattr(err, "msg", None) or err or "flow error")
        self._record(flow, error_msg=message)

    def _record(self, flow: Any, *, error_msg: str | None = None) -> None:
        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)
        stored_bytes = _flow_stored_bytes(flow)
        omitted = stored_bytes > _MAX_STORED_BODY
        method, method_truncated = _bounded_metadata(
            getattr(req, "method", ""), _MAX_METADATA_BYTES
        )
        url, url_truncated = _bounded_metadata(
            getattr(req, "pretty_url", ""), _MAX_URL_BYTES
        )
        host, host_truncated = _bounded_metadata(
            getattr(req, "host", ""), _MAX_METADATA_BYTES
        )
        content_type, type_truncated = _bounded_metadata(
            resp.headers.get("content-type", "") if resp else "",
            _MAX_METADATA_BYTES,
        )
        # The decoded response body length is known here, before the flow may be
        # dropped from the retain ring, so the summary keeps it even for a flow
        # whose body was not retained -- and the HAR export can report a real
        # content size instead of the -1 "unknown" sentinel.
        response_size = _content_len(resp)
        error_text, error_truncated = _bounded_metadata(error_msg, _MAX_METADATA_BYTES)
        with self._lock:
            self._seq += 1
            flow_id = str(getattr(flow, "id", None) or self._seq)
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
            # Evict oldest raw flows in lockstep with the summary ring so the
            # two views can never disagree about which flows are retrievable.
            while len(self._raw) > self._capacity:
                evicted_id, _ = self._raw.popitem(last=False)
                self._retained_bytes -= self._raw_sizes.pop(evicted_id, 0)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": getattr(resp, "status_code", None),
                "content_type": content_type,
                "response_size": response_size,
            }
            if omitted:
                entry["body_omitted"] = True
            if error_msg is not None:
                entry["error"] = True
                entry["error_msg"] = error_text
            if (
                method_truncated
                or url_truncated
                or host_truncated
                or type_truncated
                or error_truncated
            ):
                entry["metadata_truncated"] = True
            self.flows.append(entry)

    def snapshot(self) -> list[JsonObject]:
        with self._lock:
            return list(self.flows)

    def raw(self, flow_id: str) -> Any | None:
        with self._lock:
            return self._raw.get(flow_id)

    def count(self) -> int:
        with self._lock:
            return len(self.flows)

    def retained_bytes(self) -> int:
        with self._lock:
            return self._retained_bytes

    def clear(self) -> int:
        """Drop every captured flow and reset the sequence, keeping the ring live.

        Returns the number of flow summaries that were held. ``_seq`` is reset so
        the next capture window starts at 1 and the dropped accounting (seq minus
        retained) stays honest instead of reporting the pre-clear gap forever.
        """
        with self._lock:
            cleared = len(self.flows)
            self.flows.clear()
            self._raw.clear()
            self._raw_sizes.clear()
            self._retained_bytes = 0
            self._seq = 0
            return cleared


class _ProxyInstance:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.recorder = _FlowRecorder()
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
        """
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
            if _port_accepts(self.host, self.port):
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
            master.addons.add(self.recorder)
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
        thread = self._thread
        if master is not None and loop is not None:
            # Draining needs a loop that is still serving; a dead thread means
            # the servers are already unwinding (or leaked beyond reach), and
            # waiting on its loop would stall stop() for the whole timeout.
            if thread is not None and thread.is_alive():
                _drain_proxy_servers(master, loop)
            with contextlib.suppress(Exception):
                loop.call_soon_threadsafe(master.shutdown)
        if thread is not None:
            thread.join(timeout=10.0)
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

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> JsonObject:
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
            inst = _ProxyInstance(host, port)
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

    def flows(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        return {
            "flows": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
        }

    def stats(self, session_id: str, *, top: int = 10) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        return summarize_flows(items, dropped=dropped, top=top)

    def clear(self, session_id: str) -> JsonObject:
        inst = self._get(session_id)
        cleared = inst.recorder.clear()
        return {"cleared": cleared, "running": True}

    def endpoints(self, session_id: str, *, limit: int = 100) -> JsonObject:
        inst = self._get(session_id)
        return fold_endpoints(inst.recorder.snapshot(), limit=limit)

    def hosts(self, session_id: str, *, limit: int = 100) -> JsonObject:
        inst = self._get(session_id)
        return fold_hosts(inst.recorder.snapshot(), limit=limit)

    def cookies(self, session_id: str, *, limit: int = 200) -> JsonObject:
        inst = self._get(session_id)
        return fold_cookies(inst.recorder.snapshot(), inst.recorder.raw, limit=limit)

    def security_headers(self, session_id: str, *, limit: int = 200) -> JsonObject:
        inst = self._get(session_id)
        return fold_security_headers(
            inst.recorder.snapshot(), inst.recorder.raw, limit=limit
        )

    def search(
        self,
        session_id: str,
        query: str,
        *,
        limit: int = 100,
        case_sensitive: bool = False,
    ) -> JsonObject:
        inst = self._get(session_id)
        rows = inst.recorder.snapshot()
        return search_flows(
            rows,
            inst.recorder.raw,
            query,
            limit=limit,
            case_sensitive=case_sensitive,
        )

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
        method, method_cut = _bounded_metadata(req.method, _MAX_METADATA_BYTES)
        url, url_cut = _bounded_metadata(req.pretty_url, _MAX_URL_BYTES)
        req_headers, req_headers_cut = _bounded_headers(req)
        resp_headers, resp_headers_cut = _bounded_headers(resp) if resp else ({}, False)
        request: JsonObject = {"method": method, "url": url, "headers": req_headers}
        if method_cut or url_cut or req_headers_cut:
            request["metadata_truncated"] = True
        # The request body is what an agent reverse-engineering an API most
        # wants to see -- what was actually POSTed -- and used to be dropped
        # entirely, leaving only the response.
        request.update(_emit_body(_raw_body(req), artifact_dir))
        response: JsonObject = {
            "status": getattr(resp, "status_code", None),
            "headers": resp_headers,
        }
        if resp_headers_cut:
            response["metadata_truncated"] = True
        response.update(_emit_body(_raw_body(resp), artifact_dir))
        return {"id": flow_id, "request": request, "response": response}

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
        inst = self._get(session_id)
        entries = [
            har_entry(
                method=f.get("method"),
                url=f.get("url"),
                status=f.get("status"),
                mime_type=f.get("content_type") or "",
                response_body_size=f.get("response_size"),
            )
            for f in inst.recorder.snapshot()
        ]
        # Bounded like web.har.export: the flow ring holds up to 2000 rows whose
        # URLs alone can be 16 KiB each, so an unbounded write would drop a
        # multi-megabyte artifact the retention walker never budgeted for.
        serialized = serialize_har(entries, max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES)
        if serialized.size > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise ProxyError(
                "too_large",
                "HAR export exceeds capture cap",
                size=serialized.size,
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized.text, encoding="utf-8")
        return {
            "path": str(out_path),
            "entry_count": serialized.entry_count,
            "truncated": serialized.truncated,
            "size": serialized.size,
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
