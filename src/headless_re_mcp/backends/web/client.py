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

import base64
import contextlib
import queue
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urljoin
from uuid import uuid4

from headless_re_mcp.backends.jsre.js_sourcemap import (
    SourceMapError,
    decode_data_uri,
    extract_source,
    find_source_mapping_url,
    flatten_sources,
    is_remote_url,
    list_sources,
    parse_source_map,
)
from headless_re_mcp.backends.jsre.js_strings import extract_endpoints as extract_js_endpoints
from headless_re_mcp.backends.jsre.js_strings import extract_secrets as extract_js_secrets
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size
from headless_re_mcp.core.process_tree import process_image_path, terminate_pid_tree

JsonObject = dict[str, Any]
T = TypeVar("T")

_MAX_REQUESTS = 3000
_MAX_CONSOLE = 2000
_MAX_SCRIPTS = 2000
# web.secrets fetches and scans the source of the page's parsed scripts (the JS
# js.secrets detectors, reused). A page can parse thousands of scripts and one
# can be multi-megabyte, so the number fetched, each source read, and the total
# scanned are bounded, and the distinct-finding set is capped -- scan_capped when
# any ceiling is hit. The whole batch runs in one runner call, so it gets a
# wider timeout than a single CDP read.
_MAX_WEB_SECRET_SCRIPTS = 200
_MAX_WEB_SECRET_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_WEB_SECRET_SCAN_BYTES = 64 * 1024 * 1024
_MAX_WEB_SECRET_FINDINGS = 20000
_WEB_SECRET_SCAN_TIMEOUT = 120.0
# web.endpoints scans the same parsed-script sources for URLs/API paths (the JS
# js.endpoints detectors, reused) with the same ceilings as web.secrets, plus a
# cap on the distinct-host summary (hosts_truncated when over).
_MAX_WEB_ENDPOINT_SCRIPTS = 200
_MAX_WEB_ENDPOINT_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_WEB_ENDPOINT_SCAN_BYTES = 64 * 1024 * 1024
_MAX_WEB_ENDPOINT_FINDINGS = 20000
_MAX_WEB_ENDPOINT_HOSTS = 512
_WEB_ENDPOINT_SCAN_TIMEOUT = 120.0
# web.script.sourcemap recovers a live script's original sources from its source
# map (the js_sourcemap parser, reused). Unlike file-based js.sourcemap, an
# external .map is fetched by the browser (page context, so cookies/CORS apply);
# the fetched text and one extracted source are both bounded, and the whole
# resolve+fetch+parse runs in one runner call under this timeout.
_MAX_WEB_SOURCEMAP_FETCH_BYTES = 8 * 1024 * 1024
_MAX_WEB_SOURCEMAP_PAGE = 2000
_MAX_WEB_SOURCEMAP_CONTENT = 2 * 1024 * 1024
_WEB_SOURCEMAP_TIMEOUT = 30.0
# Fetches the map in the page's own context so a same-origin or CORS-permitted
# .map behind auth is reachable; the body is sliced in-page so a huge map does
# not cross the bridge whole.
_WEB_SOURCEMAP_FETCH_JS = """
async ({url, max}) => {
  try {
    const resp = await fetch(url, {credentials: 'include'});
    if (!resp.ok) return {ok: false, status: resp.status};
    const text = await resp.text();
    return {ok: true, text: text.length > max ? text.slice(0, max) : text, len: text.length};
  } catch (e) {
    return {ok: false, error: String((e && e.message) || e)};
  }
}
"""
# web.frames flattens Page.getFrameTree; a hostile page can insert or deeply
# nest many iframes, so cap the tree walked (frames_truncated when hit) and page
# the flattened list the same way the other web reads do.
_MAX_FRAMES = 1024
_MAX_FRAMES_PAGE = 1000
_MAX_INLINE_BODY = 200_000
_MAX_CONSOLE_TEXT = 8 * 1024
# CDP caps console previews at a handful of members; bound our own render too.
_MAX_PREVIEW_PROPS = 50
# An uncaught error's call chain: keep the top frames so a deep or recursive
# stack cannot bloat the console ring, and flatten (no async parent walk).
_MAX_STACK_FRAMES = 32
# Inline copy of a request body kept on the ring for har.export. Small on
# purpose -- the on-demand web.network.get path fetches the full body -- so
# 3000 retained requests cannot each pin a large payload in memory.
_MAX_POST_DATA = 8 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
# Response/request headers are kept per ring entry; bound the count, each field
# and the per-side total so a header-heavy page cannot bloat the request ring.
_MAX_HEADERS = 100
_MAX_HEADER_TEXT = 8 * 1024
_MAX_HEADERS_BYTES = 16 * 1024
# web.cookies reads the whole jar via CDP; a hostile page can set thousands of
# cookies with large values, so cap the universe collected and clip each value.
_MAX_COOKIES = 1000
_MAX_COOKIE_VALUE = 4 * 1024
# web.storage reads localStorage/sessionStorage through a fixed in-page snippet
# (the dom_snapshot pattern, not caller-supplied JS). A hostile page can fill
# either store with many large entries, so cap the count collected in-browser
# and clip each value; localStorage values (base64 blobs, JSON config) run
# larger than cookies, hence the wider value clip.
_MAX_STORAGE_ITEMS = 1000
_MAX_STORAGE_VALUE = 8 * 1024
# A fixed reader: the caller chooses only the area (local/session), never code.
# Bounds are applied in-browser so a store with millions of keys or a
# multi-megabyte value never serialises whole into this process.
_STORAGE_JS = """
(args) => {
  let store;
  try {
    store = args.area === 'session' ? window.sessionStorage : window.localStorage;
    void store.length;
  } catch (e) {
    return { unavailable: true, origin: (location && location.origin) || '' };
  }
  const items = [];
  let over = false;
  const total = store.length;
  for (let i = 0; i < total; i++) {
    if (items.length >= args.maxItems) { over = true; break; }
    const key = store.key(i);
    let value = store.getItem(key);
    if (typeof value !== 'string') value = (value == null) ? '' : String(value);
    const clipped = value.length > args.maxValue;
    items.push({
      key: String(key),
      value: clipped ? value.slice(0, args.maxValue) : value,
      value_truncated: clipped,
    });
  }
  return { origin: (location && location.origin) || '', items, total, over };
}
"""
# web.indexed_db reads IndexedDB through a fixed in-page snippet (the web.storage
# pattern, not caller-supplied JS). IndexedDB is databases -> object stores ->
# records, and a hostile (or just large) origin can hold many of each, so every
# level is bounded in-browser: the databases opened, the stores scanned across
# them, the records read per store and in total, and each serialised value. A
# highly compressible or deeply nested value cannot serialise whole into this
# process because the value clip is applied in the page.
_MAX_IDB_DATABASES = 50
_MAX_IDB_STORES = 200
_MAX_IDB_RECORDS = 5000
_MAX_IDB_RECORDS_PER_STORE = 500
_MAX_IDB_VALUE = 8 * 1024
_MAX_IDB_PAGE = 1000
# A fixed reader: the caller chooses only which records to keep (filters/paging),
# never code. It walks indexedDB.databases() -> each db's object stores -> a
# bounded slice of each store's records, JSON-serialising values with a replacer
# that renders the non-JSON structured-clone types (ArrayBuffer/typed array/Blob/
# Date/bigint) as short placeholders rather than throwing or emitting `{}`. Every
# open/transaction/read is wrapped so one unreadable database or store degrades
# to empty instead of failing the whole snapshot.
_INDEXED_DB_JS = """
(args) => {
  const origin = (location && location.origin) || '';
  if (!self.indexedDB || typeof indexedDB.databases !== 'function') {
    return { unavailable: true, origin };
  }
  const openDb = (name) => new Promise((resolve) => {
    let req;
    try { req = indexedDB.open(name); } catch (e) { resolve(null); return; }
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  });
  const readStore = (db, storeName, maxPerStore) => new Promise((resolve) => {
    let store;
    try {
      store = db.transaction(storeName, 'readonly').objectStore(storeName);
    } catch (e) { resolve({ keys: [], values: [] }); return; }
    let kReq, vReq;
    try {
      kReq = store.getAllKeys(undefined, maxPerStore);
      vReq = store.getAll(undefined, maxPerStore);
    } catch (e) { resolve({ keys: [], values: [] }); return; }
    let keys = [], values = [], done = 0;
    const finish = () => { done++; if (done >= 2) resolve({ keys, values }); };
    kReq.onsuccess = () => { keys = kReq.result || []; finish(); };
    kReq.onerror = () => finish();
    vReq.onsuccess = () => { values = vReq.result || []; finish(); };
    vReq.onerror = () => finish();
  });
  const serialize = (v, maxValue) => {
    let s;
    try {
      s = JSON.stringify(v, (k, val) => {
        if (val instanceof ArrayBuffer) return '[ArrayBuffer ' + val.byteLength + ']';
        if (ArrayBuffer.isView(val)) {
          const n = (val.constructor && val.constructor.name) || 'TypedArray';
          return '[' + n + ' ' + (val.byteLength || 0) + ']';
        }
        if (typeof Blob !== 'undefined' && val instanceof Blob) return '[Blob ' + val.size + ']';
        if (val instanceof Date) return val.toISOString();
        if (typeof val === 'bigint') return val.toString();
        return val;
      });
    } catch (e) {
      try { s = String(v); } catch (e2) { s = '[unserializable]'; }
    }
    if (typeof s !== 'string') s = (s == null) ? '' : String(s);
    const clipped = s.length > maxValue;
    return { value: clipped ? s.slice(0, maxValue) : s, truncated: clipped };
  };
  const run = async () => {
    let dbList;
    try {
      dbList = await indexedDB.databases();
    } catch (e) { return { unavailable: true, origin }; }
    if (!Array.isArray(dbList)) dbList = [];
    const databases = [];
    const records = [];
    let over = false;
    let storesScanned = 0;
    for (let i = 0; i < dbList.length; i++) {
      if (databases.length >= args.maxDatabases) { over = true; break; }
      const meta = dbList[i] || {};
      const dbName = String(meta.name == null ? '' : meta.name);
      const version = (typeof meta.version === 'number') ? meta.version : null;
      const db = await openDb(dbName);
      if (!db) {
        databases.push({ name: dbName, version, stores: [], error: true });
        continue;
      }
      let storeNames = [];
      try {
        storeNames = Array.prototype.slice.call(db.objectStoreNames);
      } catch (e) { storeNames = []; }
      const shownStores = [];
      let storesOver = false;
      for (let j = 0; j < storeNames.length; j++) {
        if (storesScanned >= args.maxStores) { over = true; storesOver = true; break; }
        const sName = String(storeNames[j]);
        shownStores.push(sName);
        storesScanned++;
        if (records.length >= args.maxRecords) { over = true; continue; }
        const res = await readStore(db, sName, args.maxRecordsPerStore);
        const n = Math.max(res.keys.length, res.values.length);
        if (n >= args.maxRecordsPerStore) over = true;
        for (let r = 0; r < n; r++) {
          if (records.length >= args.maxRecords) { over = true; break; }
          let keyStr;
          try {
            keyStr = (res.keys[r] == null) ? '' : String(res.keys[r]);
          } catch (e) { keyStr = ''; }
          const ser = serialize(res.values[r], args.maxValue);
          records.push({
            database: dbName, store: sName, key: keyStr,
            value: ser.value, value_truncated: ser.truncated,
          });
        }
      }
      try { db.close(); } catch (e) {}
      const row = { name: dbName, version, stores: shownStores };
      if (storesOver) row.stores_over = true;
      databases.push(row);
    }
    return { origin, databases, records, over, unavailable: false };
  };
  return run();
}
"""
# Header lists live on the ring entry but are stripped from network.list.
_NETWORK_HEADER_KEYS = frozenset({"request_headers", "response_headers"})
# Ring-only capture detail that no network.* view should surface directly: the
# inline POST body exists solely to feed har.export (network.get fetches the
# full request_body on demand, network.list is a lean index), so strip it from
# both outputs rather than leak a redundant 8 KiB preview onto every row.
_NETWORK_INTERNAL_KEYS = frozenset({"post_data", "post_data_truncated"})
# Playwright enforces its own timeouts inside the driver process, so they stop
# existing the moment the driver does. This is the outer bound that keeps a call
# from parking a worker thread forever when that happens.
_CALL_TIMEOUT = 60.0
# web.open / web.navigate bound timeout at le=120.0 in the MCP schema, but the
# agent transport calls handlers directly (catalog.invoke -> handler) with no
# pydantic validation. Left unclamped, page.goto would wait timeout*1000 ms and
# the runner future timeout+30 s, so an unattended navigation to a hanging page
# could park a browser worker far past the schema ceiling. Worse, a non-positive
# timeout -- which gt=0 forbids but the agent transport skips -- reaches
# page.goto as timeout=0, which Playwright reads as "no timeout" (an unbounded
# wait). Clamp to the schema ceiling and fall back to the schema default for a
# non-positive value, the way the Frida and subprocess backends clamp.
_MAX_NAV_TIMEOUT_S = 120.0
_DEFAULT_NAV_TIMEOUT_S = 30.0
# Each open() holds a live Chromium (its own process tree and hundreds of MB).
# Without a ceiling an agent loop -- or a caller that forgets web.close -- can
# fork browsers until the host is starved; the adb backend caps concurrent
# forwards for the same reason. A refused open is invalid_state, not a crash.
_MAX_WEB_SESSIONS = 8
_OPENING = object()


class WebError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _cdp_headers(headers: object) -> list[JsonObject]:
    """CDP's header object as a bounded, order-preserving name/value list.

    CDP hands headers over as a plain object, and where a name repeats it joins
    the values with newlines -- Set-Cookie above all, which must never be folded
    into one string (RFC 6265, and an Expires date carries its own comma). Split
    on the newline so each value stays its own entry, the same fidelity
    proxy.flow.get keeps. Count and total bytes are capped because these live on
    a per-request ring entry retained for up to _MAX_REQUESTS requests, so a
    header-flooding page cannot grow the buffer without bound.
    """
    if not isinstance(headers, dict):
        return []
    out: list[JsonObject] = []
    total = 0
    for raw_name, raw_value in headers.items():
        name, _ = _bounded_metadata(raw_name, _MAX_HEADER_TEXT)
        for piece in str(raw_value).split("\n"):
            value, _ = _bounded_metadata(piece, _MAX_HEADER_TEXT)
            out.append({"name": name, "value": value})
            total += len(name) + len(value)
            if len(out) >= _MAX_HEADERS or total >= _MAX_HEADERS_BYTES:
                return out
    return out


def _bounded_nav_timeout(timeout: float) -> float:
    """Cap a navigation timeout at the schema ceiling; see _MAX_NAV_TIMEOUT_S."""
    value = float(timeout)
    if value <= 0:
        return _DEFAULT_NAV_TIMEOUT_S
    return min(value, _MAX_NAV_TIMEOUT_S)


_NAVIGABLE_SCHEMES = ("http://", "https://", "data:")


def _require_navigable_scheme(url: str) -> None:
    """Refuse to point the browser at a local-file or browser-internals scheme.

    ``web.open`` / ``web.navigate`` drive a real Chromium, so an unrestricted
    navigation target is a read primitive: ``file:///etc/passwd`` serves
    arbitrary disk contents, ``chrome://`` / ``view-source:`` / ``filesystem:``
    expose browser internals, and the agent could then lift any of it back out
    through ``web.dom.snapshot`` or ``web.script.source``. This surface
    deliberately omits an arbitrary-JS ``evaluate`` for the same class of reason.

    Allowed are the schemes a web target actually speaks -- ``http://`` and
    ``https://`` -- plus ``data:``, which is inline caller-supplied content on an
    opaque origin with no path to the local disk or a privileged page (and which
    the hermetic browser tests use so they need no network). Everything else
    (``file:``, ``chrome:``, ``about:``, ``javascript:``, a bare path with no
    scheme) is refused before it reaches ``page.goto``. The check runs on the
    agent-supplied string directly because the transport calls handlers with no
    pydantic validation.
    """
    if not url.strip().lower().startswith(_NAVIGABLE_SCHEMES):
        raise WebError(
            "invalid_params",
            "web navigation is limited to http://, https:// and data: URLs",
            url=url,
        )


def _looks_like_missing_browser(exc: BaseException) -> bool:
    """Whether a launch failure is really "no browser installed", not a crash.

    ``pip install playwright`` never downloads Chromium: the module imports and
    ``_check_available`` passes, and only ``chromium.launch()`` fails, with a
    message that tells the caller to run ``playwright install``. That is a
    missing optional capability -- the same as an absent androguard or jadx --
    so it deserves the ``capability_unavailable`` contract the rest of the
    surface uses, not a ``backend_error`` that reads as a runtime fault.
    """
    text = str(exc).casefold()
    return "executable doesn't exist" in text or "playwright install" in text


def _looks_like_nav_timeout(exc: BaseException) -> bool:
    """Whether a goto failure is really a navigation timeout, not a load error.

    ``page.goto`` raises Playwright's own ``TimeoutError`` when the page does not
    reach the wait state within its deadline -- a transient, retry-worthy stall,
    the same class the runner's wall-clock deadline already reports as
    ``timeout``. Left in the generic ``except`` it became a non-retryable
    ``backend_error``, so an unattended caller honouring ``retryable`` gave up on
    a slow page that a second navigation might well have loaded. Match the type
    by name (robust across Playwright versions and message wording) with the
    message shape as a fallback, so a real load error (DNS, connection refused)
    still reads as ``backend_error``.
    """
    if type(exc).__name__ == "TimeoutError":
        return True
    text = str(exc).casefold()
    return "timeout" in text and "exceeded" in text


def _render_console_preview(preview: JsonObject) -> str:
    """Render a CDP ObjectPreview as a compact ``{k: v}`` / ``[v, ...]`` string.

    ``console.log({id: 42, token: "x"})`` arrives as a RemoteObject with no
    primitive ``value`` -- only ``type: "object"`` and a ``description`` of
    "Object", which on its own throws away the logged payload (config, tokens)
    an analyst is reading the console for. CDP does ship the members in
    ``preview.properties``; fold them back into the DevTools-style rendering so
    the values survive. String members are quoted to keep them distinct from
    numbers, and an overflowed preview ends in an ellipsis.
    """
    props = preview.get("properties")
    if not isinstance(props, list):
        return str(preview.get("description") or preview.get("type") or "")
    is_array = preview.get("subtype") == "array"
    parts: list[str] = []
    for prop in props[:_MAX_PREVIEW_PROPS]:
        if not isinstance(prop, dict):
            continue
        value = prop.get("value", "")
        text = value if isinstance(value, str) else str(value)
        if prop.get("type") == "string":
            text = f'"{text}"'
        parts.append(text if is_array else f"{prop.get('name', '')}: {text}")
    if preview.get("overflow"):
        parts.append("…")
    body = ", ".join(parts)
    return f"[{body}]" if is_array else f"{{{body}}}"


def _clip_console_text(params: JsonObject) -> tuple[str, bool]:
    """Join console args, stopping at ``_MAX_CONSOLE_TEXT``.

    A page that ``console.log``s a whole document would otherwise store that
    string in the ring for as long as the session lives. Slice each argument
    before joining so the huge original is not copied into the buffer.
    """
    parts: list[str] = []
    remaining = _MAX_CONSOLE_TEXT
    truncated = False
    for argument in params.get("args") or []:
        if remaining <= 0:
            truncated = True
            break
        if not isinstance(argument, dict):
            continue
        if "value" in argument:
            raw = argument["value"]
        elif isinstance(argument.get("preview"), dict):
            raw = _render_console_preview(argument["preview"])
        elif argument.get("description"):
            raw = argument["description"]
        else:
            raw = argument.get("type", "")
        piece = raw if isinstance(raw, str) else str(raw)
        if parts:
            if remaining <= 1:
                truncated = True
                break
            remaining -= 1
        if len(piece) > remaining:
            piece = piece[:remaining]
            remaining = 0
            truncated = True
        else:
            remaining -= len(piece)
        parts.append(piece)
        if truncated:
            break
    return " ".join(parts), truncated


def _console_call_site(params: JsonObject) -> tuple[str, int | None]:
    """The top stack frame of a ``consoleAPICalled`` event: (url, line) or ("", None).

    ``consoleAPICalled`` carries a ``stackTrace`` whose first ``callFrame`` is
    where the ``console.*`` ran, so a logged line can be pivoted back to its
    script location -- exactly the anonymous/dynamic scripts ``web.scripts``
    flags. This mirrors the throw-site (url/line) already attached to uncaught
    exceptions. CDP line numbers are 0-based; they are surfaced as reported
    (matching Debugger.scriptParsed) rather than silently shifted. A missing or
    oddly shaped stack degrades to no location rather than breaking capture.
    """
    stack = params.get("stackTrace")
    if not isinstance(stack, dict):
        return "", None
    frames = stack.get("callFrames")
    if not isinstance(frames, list) or not frames:
        return "", None
    top = frames[0]
    if not isinstance(top, dict):
        return "", None
    url, _ = _bounded_metadata(top.get("url"), _MAX_URL_BYTES)
    line = top.get("lineNumber")
    return url, line if isinstance(line, int) else None


def _stack_frames(stack: object) -> list[JsonObject]:
    """A bounded ``[{function, url, line}]`` list from a CDP ``stackTrace``.

    ``exceptionDetails.stackTrace.callFrames`` is the chain of calls that led to
    an uncaught error -- the functions involved, not just the throw site the
    entry already carries -- which is the first thing an analyst reads to place
    the failure. Only the top ``_MAX_STACK_FRAMES`` are kept, each field
    bounded; line numbers are surfaced 0-based as CDP reports them (matching the
    throw site and ``Debugger.scriptParsed``). An anonymous frame keeps its
    empty ``function``. A missing or oddly shaped stack yields ``[]`` rather
    than breaking capture; the async ``parent`` chain is deliberately not walked
    so the list stays flat and bounded.
    """
    if not isinstance(stack, dict):
        return []
    frames = stack.get("callFrames")
    if not isinstance(frames, list):
        return []
    out: list[JsonObject] = []
    for frame in frames[:_MAX_STACK_FRAMES]:
        if not isinstance(frame, dict):
            continue
        function, _ = _bounded_metadata(frame.get("functionName"), _MAX_METADATA_BYTES)
        url, _ = _bounded_metadata(frame.get("url"), _MAX_URL_BYTES)
        line = frame.get("lineNumber")
        out.append(
            {
                "function": function,
                "url": url,
                "line": line if isinstance(line, int) else None,
            }
        )
    return out


def _clip_exception_text(params: JsonObject) -> tuple[str, bool]:
    """Render a ``Runtime.exceptionThrown`` payload into one console-style line.

    Uncaught errors and unhandled promise rejections arrive on this event, not
    ``consoleAPICalled``, so without handling it the console buffer misses
    exactly the failures an analyst watches for. DevTools shows the ``text``
    header ("Uncaught", "Uncaught (in promise)") followed by the exception's
    ``description`` -- an ``Error`` carries its whole "Error: msg\\n    at ..."
    stack -- or, for a thrown primitive, its ``value``. Clipped to the same
    per-message cap as every other console line so a page throwing a megabyte
    string cannot pin it in the ring.
    """
    details = params.get("exceptionDetails")
    if not isinstance(details, dict):
        return "", False
    parts: list[str] = []
    head = details.get("text")
    if isinstance(head, str) and head:
        parts.append(head)
    exc = details.get("exception")
    if isinstance(exc, dict):
        desc = exc.get("description")
        if isinstance(desc, str) and desc:
            parts.append(desc)
        elif "value" in exc:
            value = exc.get("value")
            parts.append(value if isinstance(value, str) else str(value))
    message = " ".join(parts)
    if len(message) > _MAX_CONSOLE_TEXT:
        return message[:_MAX_CONSOLE_TEXT], True
    return message, False


def _spill_text(
    text: str,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
    truncate: bool = False,
) -> tuple[str, Path | None, bool]:
    """Inline a prefix, spill the rest, or refuse when the capture cap is hit.

    CDP already delivered the whole payload. Writing it to the session artifact
    dir still fills the disk before retention runs: a single media response is
    enough. Returns ``(inline, spill_path_or_none, truncated)``.

    ``truncate`` turns the over-cap case from a refusal into a bounded degrade:
    a snapshot keeps the capture cap's worth (cut on a byte boundary, so a
    trailing multibyte char may be clipped) and reports truncation, rather than
    failing the whole call the way a response body or script source -- which the
    caller asked for in full -- should when it cannot be delivered whole.
    """
    payload = text.encode("utf-8", errors="replace")
    forced = False
    if len(payload) > UNREGISTERED_CAPTURE_MAX_BYTES:
        if not truncate:
            raise WebError(
                "too_large",
                f"{kind} exceeds capture cap",
                size=len(payload),
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        payload = payload[:UNREGISTERED_CAPTURE_MAX_BYTES]
        forced = True
    size = len(payload)
    if size <= _MAX_INLINE_BODY and not forced:
        return text, None, False
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise WebError("invalid_params", f"invalid {kind} artifact filename")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    out = artifact_dir / filename
    out.write_bytes(payload)
    written, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
    if over:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=written,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    preview = payload[:_MAX_INLINE_BODY].decode("utf-8", errors="ignore")
    return preview, out, True


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
        with contextlib.suppress(Exception):
            self._queue.put(None)
        self._thread.join(timeout=2.0)


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
        self.requests_dropped = 0
        self.console_dropped = 0
        # Bounded like the other two: scriptParsed fires for every script a page
        # parses, so a long-lived tab (or one that eval()s) would otherwise grow
        # this dictionary for as long as the session is open.
        self.scripts: OrderedDict[str, JsonObject] = OrderedDict()
        self.scripts_dropped = 0
        self.lock = threading.RLock()
        # Set right after construction: the runner is what built these objects,
        # and it is the only thread allowed to touch them again.
        self.runner: _Runner | None = None
        # Node driver that owns Chromium. Playwright does not expose a PID;
        # close from another thread cannot talk to the objects, so this is
        # what a wedged session has to kill.
        self.driver_pid: int | None = None

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

    def status(self, session_id: str) -> JsonObject:
        """Cheap page identity; never launches a browser."""
        with self._lock:
            handle = self._sessions.get(session_id)
        if handle is None:
            return {"open": False}
        if type(handle) is object:
            return {"open": False, "opening": True}
        if not isinstance(handle, _WebSession):
            return {"open": False}

        def work() -> JsonObject:
            return {
                "open": True,
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }

        return self._runner(handle).call(work)

    def _get(self, session_id: str) -> _WebSession:
        with self._lock:
            handle = self._sessions.get(session_id)
        if not isinstance(handle, _WebSession):
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
        timeout = _bounded_nav_timeout(timeout)
        # An empty url means "open a blank browser"; only a real destination is
        # held to the scheme allowlist, and it is checked before a browser is
        # ever launched so a refused target costs nothing.
        if url:
            _require_navigable_scheme(url)

        with self._lock:
            if session_id in self._sessions:
                raise WebError("invalid_state", "web session already open", session_id=session_id)
            # Bound the live browser count before reserving a slot, so a refused
            # open never starts a Chromium. The reservation (opening token or a
            # live handle) is what counts, so a launch in flight already holds
            # its slot and cannot be double-spent by a racing open.
            if len(self._sessions) >= _MAX_WEB_SESSIONS:
                raise WebError(
                    "invalid_state",
                    "too many open web sessions; close one before opening another",
                    cap=_MAX_WEB_SESSIONS,
                    held=len(self._sessions),
                )
            # Per-open token, not the shared _OPENING sentinel: close() pops
            # the reservation, and a second open() must not look like the
            # first launch still owns the slot.
            opening = object()
            self._sessions[session_id] = opening  # type: ignore[assignment]

        from playwright.sync_api import sync_playwright

        runner = _Runner(f"playwright-{session_id[:8]}")
        # Filled as soon as the node driver exists, so a timeout in launch or
        # goto can still kill the tree from this thread.
        pid_box: list[int] = []

        def build() -> tuple[_WebSession, JsonObject]:
            pw = sync_playwright().start()
            pid = _playwright_driver_pid(pw)
            if isinstance(pid, int) and pid > 0:
                pid_box.append(pid)
            try:
                browser = pw.chromium.launch(headless=headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                cdp = context.new_cdp_session(page)
                handle = _WebSession(pw, browser, context, page, cdp)
                handle.driver_pid = pid
                self._wire_events(handle)
                if url:
                    page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
                # Summarised here rather than by a second call: between the two,
                # a browser exists that no session yet refers to, and a failure
                # in that window would leave it with nothing able to close it.
                summary = {
                    "opened": True,
                    "url": _bounded_metadata(page.url, _MAX_URL_BYTES)[0],
                    "title": _safe_title(page),
                    "headless": headless,
                }
            except Exception as exc:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    pw.stop()
                if _looks_like_missing_browser(exc):
                    raise WebError(
                        "capability_unavailable",
                        "playwright is installed but its browser is not; "
                        "run 'playwright install chromium'",
                    ) from exc
                if url and _looks_like_nav_timeout(exc):
                    raise WebError(
                        "timeout",
                        f"navigation to {url} did not complete within {timeout:g}s",
                        url=url,
                    ) from exc
                raise WebError("backend_error", f"failed to open browser: {exc}", url=url) from exc
            return handle, summary

        try:
            # Launching a browser is the slowest thing here, so it gets the
            # caller's navigation budget plus room for the launch itself.
            handle, summary = runner.call(build, timeout=timeout + 30.0)
        except BaseException:
            runner.shutdown()
            for pid in pid_box:
                _reap_driver_pid(pid)
            with self._lock:
                if self._sessions.get(session_id) is opening:
                    self._sessions.pop(session_id, None)
            raise
        handle.runner = runner
        with self._lock:
            if self._sessions.get(session_id) is not opening:
                runner.shutdown()
                _reap_web_session(handle)
                raise WebError("invalid_state", "web session was closed while opening")
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
            url, url_truncated = _bounded_metadata(req.get("url"), _MAX_URL_BYTES)
            method, method_truncated = _bounded_metadata(
                req.get("method"), _MAX_METADATA_BYTES
            )
            resource_type, type_truncated = _bounded_metadata(
                params.get("type"), _MAX_METADATA_BYTES
            )
            wall_time = params.get("wallTime")
            entry: JsonObject = {
                "requestId": params.get("requestId"),
                "url": url,
                "method": method,
                "resourceType": resource_type,
                "status": None,
                "mimeType": None,
                # CDP wallTime is an epoch time; keep it so a HAR export can place
                # the request in real time instead of all at the export instant.
                "started_at": float(wall_time) if isinstance(wall_time, (int, float)) else None,
            }
            if url_truncated or method_truncated or type_truncated:
                entry["metadata_truncated"] = True
            # The request headers CDP reported at send time (auth, cookies, the
            # custom API headers analysis is after). Kept off network.list -- see
            # its projection -- and surfaced by network.get / har.export.
            entry["request_headers"] = _cdp_headers(req.get("headers"))
            # The page's POST payload (the request body -- JSON, form creds, a
            # signed blob) is what an API/protocol analyst most wants. CDP inlines
            # it here for a small body, so keep a bounded copy on the ring: it
            # lets har.export emit request.postData without a per-request CDP
            # round-trip. A large body is not inlined by CDP (only hasPostData is
            # set); it must be pulled on demand by web.network.get. Flag which
            # rows have one either way so the caller knows there is a body.
            post = req.get("postData")
            if isinstance(post, str) and post:
                entry["post_data"] = post[:_MAX_POST_DATA]
                if len(post) > _MAX_POST_DATA:
                    entry["post_data_truncated"] = True
            if req.get("hasPostData"):
                entry["has_post_data"] = True
            with handle.lock:
                handle.requests[str(params.get("requestId"))] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    handle.requests.popitem(last=False)
                    handle.requests_dropped += 1

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            mime_type, mime_truncated = _bounded_metadata(
                resp.get("mimeType"), _MAX_METADATA_BYTES
            )
            remote_ip, ip_truncated = _bounded_metadata(
                resp.get("remoteIPAddress"), _MAX_METADATA_BYTES
            )
            remote_port = resp.get("remotePort")
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = mime_type
                    # Set-Cookie, CSP, CORS, cache and content-type -- the
                    # response side an analyst reads. CDP folds repeats with
                    # newlines; _cdp_headers unfolds them so each survives.
                    entry["response_headers"] = _cdp_headers(resp.get("headers"))
                    # The server IP:port the request actually reached -- the C2
                    # or CDN host behind the domain, an infrastructure pivot a
                    # URL alone does not give. Absent for cached and data:
                    # responses, which never open a connection.
                    if remote_ip:
                        entry["remote_ip"] = remote_ip
                    if isinstance(remote_port, int) and not isinstance(remote_port, bool):
                        entry["remote_port"] = remote_port
                    if mime_truncated or ip_truncated:
                        entry["metadata_truncated"] = True

        def on_loading_failed(params: JsonObject) -> None:
            # A request that never gets a response -- blocked by CSP/CORS/mixed
            # content, aborted, or a net::ERR_* transport failure -- arrives on
            # loadingFailed, not responseReceived. Without it a failed load sits
            # in the ring at status None, indistinguishable from one still in
            # flight, so a reader could not tell a blocked endpoint (exactly what
            # an analyst hunts for) from a slow one. Mark the entry in place with
            # why it failed, mirroring how on_response fills status.
            error_text, error_truncated = _bounded_metadata(
                params.get("errorText"), _MAX_METADATA_BYTES
            )
            blocked, blocked_truncated = _bounded_metadata(
                params.get("blockedReason"), _MAX_METADATA_BYTES
            )
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is None:
                    return
                entry["failed"] = True
                if error_text:
                    entry["error_text"] = error_text
                if blocked:
                    entry["blocked_reason"] = blocked
                if isinstance(params.get("canceled"), bool):
                    entry["canceled"] = params["canceled"]
                if error_truncated or blocked_truncated:
                    entry["metadata_truncated"] = True

        def on_script(params: JsonObject) -> None:
            url, url_truncated = _bounded_metadata(params.get("url"), _MAX_URL_BYTES)
            language, language_truncated = _bounded_metadata(
                params.get("scriptLanguage", "JavaScript"), _MAX_METADATA_BYTES
            )
            entry: JsonObject = {
                "scriptId": params.get("scriptId"),
                "url": url,
                "language": language,
            }
            # CDP attaches a stackTrace only to a script compiled at runtime --
            # eval, new Function, or a document.write-injected <script>. Such a
            # script carries an empty url, so on the list it is indistinguishable
            # from any other anonymous one, yet for RE it is the most interesting:
            # a packer's real payload is exactly what lands here. Flag it so a
            # caller can point web.script.source at the generated code rather than
            # guess among blank-url rows.
            if params.get("stackTrace"):
                entry["dynamic"] = True
            # The script's character length (when CDP reported it) lets a caller
            # tell which anonymous script is the big generated blob worth pulling.
            length = params.get("length")
            if isinstance(length, int) and length >= 0:
                entry["length"] = length
            if url_truncated or language_truncated:
                entry["metadata_truncated"] = True
            with handle.lock:
                handle.scripts[str(params.get("scriptId"))] = entry
                while len(handle.scripts) > _MAX_SCRIPTS:
                    handle.scripts.popitem(last=False)
                    handle.scripts_dropped += 1

        def record_console(entry: JsonObject) -> None:
            with handle.lock:
                if (
                    handle.console.maxlen is not None
                    and len(handle.console) == handle.console.maxlen
                ):
                    handle.console_dropped += 1
                handle.console.append(entry)

        def on_console(params: JsonObject) -> None:
            text, text_truncated = _clip_console_text(params)
            entry: JsonObject = {
                "type": str(params.get("type") or "log"),
                "text": text,
            }
            if text_truncated:
                entry["text_truncated"] = True
            # Attach the call site (url/line) from the message's stack, the same
            # way a thrown exception carries its throw site, so a logged line can
            # be traced to the script that emitted it.
            url, line = _console_call_site(params)
            if url:
                entry["url"] = url
            if line is not None:
                entry["line"] = line
            record_console(entry)

        def on_exception(params: JsonObject) -> None:
            # Uncaught errors and unhandled promise rejections come over
            # exceptionThrown, not consoleAPICalled; folding them into the same
            # ring is what makes the buffer match what DevTools shows. Typed
            # "error" and flagged uncaught so a caller can tell a thrown failure
            # from a console.error the page chose to emit, with the throw site
            # (url/line) attached when CDP reported one.
            text, text_truncated = _clip_exception_text(params)
            entry: JsonObject = {
                "type": "error",
                "text": text or "Uncaught (exception)",
                "uncaught": True,
            }
            if text_truncated:
                entry["text_truncated"] = True
            details = params.get("exceptionDetails")
            if isinstance(details, dict):
                url, _ = _bounded_metadata(details.get("url"), _MAX_URL_BYTES)
                if url:
                    entry["url"] = url
                line = details.get("lineNumber")
                if isinstance(line, int):
                    entry["line"] = line
                # The call chain that led here (functions, not just the throw
                # site) is the first thing read to place an uncaught error.
                stack = _stack_frames(details.get("stackTrace"))
                if stack:
                    entry["stack"] = stack
            record_console(entry)

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.loadingFailed", on_loading_failed)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)
        cdp.on("Runtime.exceptionThrown", on_exception)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        _require_navigable_scheme(url)
        handle = self._get(session_id)
        timeout = _bounded_nav_timeout(timeout)

        def work() -> JsonObject:
            try:
                handle.page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
            except Exception as exc:  # noqa: BLE001
                if _looks_like_nav_timeout(exc):
                    raise WebError(
                        "timeout",
                        f"navigation to {url} did not complete within {timeout:g}s",
                        url=url,
                    ) from exc
                raise WebError("backend_error", f"navigation failed: {exc}", url=url) from exc
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }

        return self._runner(handle).call(work, timeout=timeout + 10.0)

    def close(self, session_id: str) -> JsonObject:
        with self._lock:
            handle = self._sessions.pop(session_id, None)
        if handle is None:
            return {"closed": False, "note": "no web session was open"}
        # Opening reservations are bare object() tokens. Anything else is a
        # live handle (or a test double) and must be torn down.
        if type(handle) is object:
            return {"closed": True, "note": "open was aborted"}
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
            # Playwright objects cannot be touched from this thread, and a
            # wedged runner will never run handle.close. The node driver is
            # what still holds Chromium; killing it is the only close that
            # works from here.
            _reap_web_session(handle)
        runner.shutdown()
        return {"closed": True, "clean": clean}

    def network_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        url_filter: str = "",
        type_filter: str = "",
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        # A case-insensitive URL substring filter, applied before paging, so a
        # single endpoint (/api/, a host, a .json) is reachable on a page that
        # captured hundreds of requests instead of only by walking every page.
        # total then reports the match count; dropped stays the ring's eviction
        # count, which the filter does not change.
        needle = url_filter.strip().lower() if isinstance(url_filter, str) else ""
        if needle:
            items = [item for item in items if needle in str(item.get("url", "")).lower()]
        # A resourceType exact match (case-insensitive), the way to pull the API
        # traffic (XHR/Fetch) out of a capture otherwise buried under Image/
        # Script/Stylesheet rows. Combines with url_filter -- both must pass --
        # and, like it, runs before paging so total is the match count.
        wanted_type = type_filter.strip().lower() if isinstance(type_filter, str) else ""
        if wanted_type:
            items = [
                item
                for item in items
                if str(item.get("resourceType", "") or "").lower() == wanted_type
            ]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        # Headers ride on the ring entry so network.get and har.export can reach
        # them, but a list of up to 1000 rows must stay a lean index -- strip
        # them, and the har.export-only inline body, so the summary is not
        # dominated by every row's headers or POST payload.
        omit = _NETWORK_HEADER_KEYS | _NETWORK_INTERNAL_KEYS
        window = [
            {k: v for k, v in item.items() if k not in omit}
            for item in items[start : start + cap]
        ]
        return {
            "requests": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
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
        except WebError:
            # A session-level fault -- the runner timing out (which wedges the
            # session), an already-wedged runner, or a closed session -- is not a
            # per-body condition: every later call fails too. Swallowed into
            # ``body_error`` it read as a successful metadata fetch, so an
            # unattended caller kept hitting a browser it had no way to learn was
            # dead. Let it propagate with its own code (``timeout`` is retryable),
            # exactly as web.script_source already does; only a genuine per-body
            # CDP failure (no such resource, body already evicted) below stays a
            # soft ``body_error`` with the entry metadata intact.
            raise
        except Exception as exc:  # noqa: BLE001
            projected = {k: v for k, v in entry.items() if k not in _NETWORK_INTERNAL_KEYS}
            return {**projected, "body_error": str(exc)}
        if not isinstance(body, str):
            body = str(body)
        inline, spill, cut = _spill_text(
            body,
            artifact_dir=artifact_dir,
            filename=f"body-{uuid4().hex}.bin",
            kind="response body",
        )
        # The inline POST body is a har.export-only ring detail; network.get
        # returns the full request_body via _attach_request_body below, so drop
        # the redundant preview rather than ship two request-body fields.
        result = {k: v for k, v in entry.items() if k not in _NETWORK_INTERNAL_KEYS}
        result["body"] = inline
        result["body_truncated"] = cut
        if spill is not None:
            result["body_path"] = str(spill)
        result["base64_encoded"] = base64_encoded
        if entry.get("has_post_data"):
            self._attach_request_body(handle, request_id, artifact_dir, result)
        return result

    def _attach_request_body(
        self,
        handle: _WebSession,
        request_id: str,
        artifact_dir: Path,
        result: JsonObject,
    ) -> None:
        """Pull the request's POST body and spill it beside the response body.

        Symmetric with proxy.flow.get, which already exposes request.body. A
        session-level fault propagates the way the response-body fetch does; a
        per-body condition (CDP has no post data retained, or a body over the
        capture cap) is a soft request_body_error so the response the caller
        already got is not lost.
        """
        try:
            post = self._runner(handle).call(
                lambda: handle.cdp.send(
                    "Network.getRequestPostData", {"requestId": request_id}
                )
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001
            result["request_body_error"] = str(exc)
            return
        raw = post.get("postData", "") if isinstance(post, dict) else ""
        if not isinstance(raw, str):
            raw = str(raw)
        try:
            inline, spill, cut = _spill_text(
                raw,
                artifact_dir=artifact_dir,
                filename=f"request-body-{uuid4().hex}.bin",
                kind="request body",
            )
        except WebError as exc:
            result["request_body_error"] = exc.message
            return
        result["request_body"] = inline
        result["request_body_truncated"] = cut
        if spill is not None:
            result["request_body_path"] = str(spill)

    def console(
        self, session_id: str, *, limit: int = 200, type_filter: str = ""
    ) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        # An exact, case-insensitive type match (log/info/warning/error/...),
        # applied before the tail, so the failures an analyst watches for
        # (error, warning, and the uncaught throws folded in as error) can be
        # pulled out of a console the page has flooded with log lines. has_more
        # then reflects older matching messages; dropped stays the ring's
        # eviction count.
        wanted = type_filter.strip().lower() if isinstance(type_filter, str) else ""
        if wanted:
            held = [entry for entry in held if str(entry.get("type", "")).lower() == wanted]
        page = held[-capped:]
        return {
            "console": page,
            "count": len(page),
            "has_more": len(held) > capped,
            "dropped": dropped,
        }

    @staticmethod
    def _project_cookie(cookie: dict[str, Any]) -> JsonObject:
        """Project a CDP cookie into a bounded, JSON-safe row.

        The value is the analysis target (session/auth tokens) so it is kept,
        but clipped to _MAX_COOKIE_VALUE; name/domain/path are bounded like other
        metadata. httpOnly is the whole reason a JS-only tool cannot see these,
        so it, secure, session and sameSite are surfaced verbatim.
        """
        value, value_over = _bounded_metadata(cookie.get("value"), _MAX_COOKIE_VALUE)
        row: JsonObject = {
            "name": _bounded_metadata(cookie.get("name"), _MAX_METADATA_BYTES)[0],
            "value": value,
            "domain": _bounded_metadata(cookie.get("domain"), _MAX_METADATA_BYTES)[0],
            "path": _bounded_metadata(cookie.get("path"), _MAX_METADATA_BYTES)[0],
            "http_only": bool(cookie.get("httpOnly")),
            "secure": bool(cookie.get("secure")),
            "session": bool(cookie.get("session")),
        }
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and not isinstance(expires, bool):
            row["expires"] = float(expires)
        size = cookie.get("size")
        if isinstance(size, int) and not isinstance(size, bool):
            row["size"] = size
        same_site = cookie.get("sameSite")
        if isinstance(same_site, str) and same_site:
            row["same_site"] = _bounded_metadata(same_site, _MAX_METADATA_BYTES)[0]
        if value_over:
            row["value_truncated"] = True
        return row

    def cookies(
        self, session_id: str, *, offset: int = 0, limit: int = 200, domain_filter: str = ""
    ) -> JsonObject:
        handle = self._get(session_id)
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Network.getAllCookies")
            )
        except WebError:
            # Session-level fault (wedged/timed-out/closed runner) propagates
            # with its own code, as the other CDP reads do.
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError("backend_error", f"cannot read cookies: {exc}") from exc
        raw = resp.get("cookies") if isinstance(resp, dict) else None
        rows = raw if isinstance(raw, list) else []
        # Bound the universe first: a hostile page can set an unbounded number of
        # cookies, and collection_truncated tells the caller the jar was larger.
        universe_over = len(rows) > _MAX_COOKIES
        projected = [self._project_cookie(c) for c in rows[:_MAX_COOKIES] if isinstance(c, dict)]
        # A case-insensitive substring on the cookie domain, applied before
        # paging, isolates the app's own cookies from the third-party trackers a
        # real page accretes; total then reflects the matching set.
        needle = domain_filter.strip().lower() if isinstance(domain_filter, str) else ""
        if needle:
            projected = [c for c in projected if needle in str(c.get("domain", "")).lower()]
        total = len(projected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_COOKIES))
        window = projected[start : start + cap]
        return {
            "cookies": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "collection_truncated": universe_over,
        }

    def storage(
        self,
        session_id: str,
        *,
        kind: str = "local",
        offset: int = 0,
        limit: int = 200,
        key_filter: str = "",
    ) -> JsonObject:
        """Read localStorage/sessionStorage for the top document's origin.

        The Web Storage companion to :meth:`cookies`: SPAs keep JWT/refresh
        tokens and app config here, and neither the request-header capture nor a
        page's own document.cookie reaches it. Read through a fixed in-page
        snippet (like dom_snapshot) so the caller supplies no code, only the
        area. A data:/about:blank page has an opaque origin with no storage and
        is reported as invalid_state rather than an empty jar.
        """
        handle = self._get(session_id)
        area = (kind or "").strip().lower()
        if area not in ("local", "session"):
            raise WebError("invalid_params", "kind must be 'local' or 'session'", kind=kind)

        def work() -> JsonObject:
            try:
                raw = handle.page.evaluate(
                    _STORAGE_JS,
                    {"area": area, "maxItems": _MAX_STORAGE_ITEMS, "maxValue": _MAX_STORAGE_VALUE},
                )
            except WebError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cannot read {area} storage: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "storage read returned no object")
            origin = _bounded_metadata(raw.get("origin"), _MAX_METADATA_BYTES)[0]
            if raw.get("unavailable"):
                raise WebError(
                    "invalid_state",
                    "web storage is unavailable for this origin (data:/about:blank "
                    "pages have none); navigate to an http(s) page first",
                    origin=origin,
                )
            raw_items = raw.get("items")
            items = raw_items if isinstance(raw_items, list) else []
            rows: list[JsonObject] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                value, value_over = _bounded_metadata(item.get("value"), _MAX_STORAGE_VALUE)
                row: JsonObject = {
                    "key": _bounded_metadata(item.get("key"), _MAX_METADATA_BYTES)[0],
                    "value": value,
                }
                if value_over or bool(item.get("value_truncated")):
                    row["value_truncated"] = True
                rows.append(row)
            # A case-insensitive substring on the key, applied before paging, so
            # one entry (an auth token, a feature flag) is reachable without
            # walking every page; total then reflects the matching set, while
            # collection_truncated stays the in-browser universe cap.
            needle = key_filter.strip().lower() if isinstance(key_filter, str) else ""
            if needle:
                rows = [row for row in rows if needle in str(row.get("key", "")).lower()]
            total = len(rows)
            start = max(0, int(offset))
            cap = max(1, min(int(limit), _MAX_STORAGE_ITEMS))
            window = rows[start : start + cap]
            return {
                "kind": area,
                "origin": origin,
                "storage": window,
                "count": len(window),
                "total": total,
                "offset": start,
                "has_more": start + len(window) < total,
                "collection_truncated": bool(raw.get("over")),
            }

        return self._runner(handle).call(work)

    def indexed_db(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 200,
        database_filter: str = "",
        store_filter: str = "",
        key_filter: str = "",
    ) -> JsonObject:
        """Read IndexedDB for the top document's origin: databases, stores, records.

        The third Web-storage surface, after cookies() and storage(): a modern SPA
        keeps auth tokens, cached API responses and user data in IndexedDB, not
        cookies or localStorage, and no Set-Cookie capture, document.cookie read
        or Web Storage read reaches it. Read through a fixed in-page snippet (like
        storage(), no caller code), and only for the top document's origin. Two
        things come back: ``databases`` is the structure -- one row per database
        with its object-store names -- and ``records`` is a flat, paged list of
        the actual entries ({database, store, key, value}). Values are
        JSON-serialised in the page (ArrayBuffer/Blob/typed-array/Date rendered as
        short placeholders) and clipped, with value_truncated when long. Every
        level is bounded in-browser and collection_truncated is set when any cap
        truncated the walk. A data:/about:blank page (or a browser without
        indexedDB.databases) has none and is reported invalid_state rather than an
        empty result.
        """
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                raw = handle.page.evaluate(
                    _INDEXED_DB_JS,
                    {
                        "maxDatabases": _MAX_IDB_DATABASES,
                        "maxStores": _MAX_IDB_STORES,
                        "maxRecords": _MAX_IDB_RECORDS,
                        "maxRecordsPerStore": _MAX_IDB_RECORDS_PER_STORE,
                        "maxValue": _MAX_IDB_VALUE,
                    },
                )
            except WebError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cannot read IndexedDB: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "IndexedDB read returned no object")
            origin = _bounded_metadata(raw.get("origin"), _MAX_METADATA_BYTES)[0]
            if raw.get("unavailable"):
                raise WebError(
                    "invalid_state",
                    "IndexedDB is unavailable for this origin (data:/about:blank pages "
                    "have none, and the browser must expose indexedDB.databases); "
                    "navigate to an http(s) page first",
                    origin=origin,
                )
            # Structure summary: one row per database with its store names. Kept
            # whole (not narrowed by the record filters) so the caller always sees
            # what exists, the way proxy.hosts summarises alongside the flows.
            raw_dbs = raw.get("databases")
            db_entries = raw_dbs if isinstance(raw_dbs, list) else []
            databases: list[JsonObject] = []
            for entry in db_entries[:_MAX_IDB_DATABASES]:
                if not isinstance(entry, dict):
                    continue
                raw_stores = entry.get("stores")
                store_names = [
                    _bounded_metadata(name, _MAX_METADATA_BYTES)[0]
                    for name in (raw_stores if isinstance(raw_stores, list) else [])
                ]
                version = entry.get("version")
                db_row: JsonObject = {
                    "name": _bounded_metadata(entry.get("name"), _MAX_METADATA_BYTES)[0],
                    "version": version if isinstance(version, int) and not isinstance(version, bool)
                    else None,
                    "stores": store_names,
                }
                if entry.get("stores_over"):
                    db_row["stores_truncated"] = True
                if entry.get("error"):
                    db_row["error"] = True
                databases.append(db_row)
            # Flat record list, filtered and paged on the Python side.
            raw_records = raw.get("records")
            rec_entries = raw_records if isinstance(raw_records, list) else []
            rows: list[JsonObject] = []
            for item in rec_entries:
                if not isinstance(item, dict):
                    continue
                value, value_over = _bounded_metadata(item.get("value"), _MAX_IDB_VALUE)
                row: JsonObject = {
                    "database": _bounded_metadata(item.get("database"), _MAX_METADATA_BYTES)[0],
                    "store": _bounded_metadata(item.get("store"), _MAX_METADATA_BYTES)[0],
                    "key": _bounded_metadata(item.get("key"), _MAX_METADATA_BYTES)[0],
                    "value": value,
                }
                if value_over or bool(item.get("value_truncated")):
                    row["value_truncated"] = True
                rows.append(row)
            # Case-insensitive substring filters applied before paging so total is
            # the matching set: database/store isolate one app's data from the
            # noise a page accretes, key finds a single record.
            db_needle = database_filter.strip().lower() if isinstance(database_filter, str) else ""
            if db_needle:
                rows = [r for r in rows if db_needle in str(r.get("database", "")).lower()]
            store_needle = store_filter.strip().lower() if isinstance(store_filter, str) else ""
            if store_needle:
                rows = [r for r in rows if store_needle in str(r.get("store", "")).lower()]
            key_needle = key_filter.strip().lower() if isinstance(key_filter, str) else ""
            if key_needle:
                rows = [r for r in rows if key_needle in str(r.get("key", "")).lower()]
            total = len(rows)
            start = max(0, int(offset))
            cap = max(1, min(int(limit), _MAX_IDB_PAGE))
            window = rows[start : start + cap]
            return {
                "origin": origin,
                "databases": databases,
                "records": window,
                "count": len(window),
                "total": total,
                "offset": start,
                "has_more": start + len(window) < total,
                "collection_truncated": bool(raw.get("over")),
            }

        return self._runner(handle).call(work)

    def frames(
        self, session_id: str, *, offset: int = 0, limit: int = 200, url_filter: str = ""
    ) -> JsonObject:
        """Flatten Page.getFrameTree into one row per frame (main + iframes).

        web.cookies and web.storage only reach the top document's origin, and
        dom_snapshot is the top document's HTML; this reveals the iframes those
        tools do not see -- the cross-origin auth/payment/CAPTCHA/ad frames whose
        own origin, storage and cookies are a separate boundary -- so their
        security_origin becomes a pivot. The tree is walked breadth-first, so the
        main frame leads and each child follows its parent; the collection is
        bounded (frames_truncated when a hostile page nests past the cap).
        """
        handle = self._get(session_id)
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Page.getFrameTree")
            )
        except WebError:
            # Session-level fault (wedged/timed-out/closed runner) keeps its own
            # code, as the other CDP reads do.
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError("backend_error", f"cannot read frame tree: {exc}") from exc
        tree = resp.get("frameTree") if isinstance(resp, dict) else None
        rows: list[JsonObject] = []
        collection_over = False
        # Breadth-first over the frame tree: the main frame is depth 0, and every
        # child records its parent's frame id so the nesting is reconstructable
        # from a flat list. A depth-first recursion could blow the stack on a
        # pathologically nested page; a queue with an explicit cap cannot.
        queue: list[tuple[Any, int, str]] = []
        if isinstance(tree, dict):
            queue.append((tree, 0, ""))
        while queue:
            node, depth, parent_id = queue.pop(0)
            if not isinstance(node, dict):
                continue
            frame_obj = node.get("frame")
            frame = frame_obj if isinstance(frame_obj, dict) else {}
            if len(rows) >= _MAX_FRAMES:
                collection_over = True
                break
            frame_id = _bounded_metadata(frame.get("id"), _MAX_METADATA_BYTES)[0]
            row: JsonObject = {
                "frame_id": frame_id,
                "url": _bounded_metadata(frame.get("url"), _MAX_URL_BYTES)[0],
                "security_origin": _bounded_metadata(
                    frame.get("securityOrigin"), _MAX_URL_BYTES
                )[0],
                "depth": depth,
                "is_main": depth == 0,
            }
            if parent_id:
                row["parent_id"] = parent_id
            name = _bounded_metadata(frame.get("name"), _MAX_METADATA_BYTES)[0]
            if name:
                row["name"] = name
            mime = _bounded_metadata(frame.get("mimeType"), _MAX_METADATA_BYTES)[0]
            if mime:
                row["mime_type"] = mime
            rows.append(row)
            children = node.get("childFrames")
            if isinstance(children, list):
                for child in children:
                    queue.append((child, depth + 1, frame_id))
        # A case-insensitive substring on the frame url, applied before paging so
        # total is the match count -- the way to find one embedded origin among
        # the many trackers a real page pulls in.
        needle = url_filter.strip().lower() if isinstance(url_filter, str) else ""
        if needle:
            rows = [row for row in rows if needle in str(row.get("url", "")).lower()]
        total = len(rows)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_FRAMES_PAGE))
        window = rows[start : start + cap]
        return {
            "frames": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "frames_truncated": collection_over,
        }

    def scripts(
        self,
        session_id: str,
        *,
        wasm_only: bool = False,
        dynamic_only: bool = False,
        offset: int = 0,
        limit: int = 100,
        url_filter: str = "",
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            values = list(handle.scripts.values())
        if wasm_only:
            values = [s for s in values if str(s.get("language")).lower() == "webassembly"]
        # Runtime-generated scripts (eval / new Function / document.write) carry
        # dynamic=True and usually a blank url, so a url_filter cannot reach them
        # -- yet they are where a packer's unpacked payload lands. dynamic_only
        # isolates exactly those, applied before paging so total is their count.
        if dynamic_only:
            values = [s for s in values if s.get("dynamic")]
        # A case-insensitive url substring filter, applied before paging, so one
        # script is reachable on a page that parsed hundreds instead of only by
        # walking every page; total then reports the match count.
        needle = url_filter.strip().lower() if isinstance(url_filter, str) else ""
        if needle:
            values = [s for s in values if needle in str(s.get("url", "")).lower()]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = values[start : start + cap]
        return {
            "scripts": window,
            "count": len(window),
            "total": len(values),
            "offset": start,
            "has_more": start + len(window) < len(values),
            "dropped": handle.scripts_dropped,
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
        if not isinstance(source, str):
            source = str(source)
        inline, spill, cut = _spill_text(
            source,
            artifact_dir=artifact_dir,
            filename=f"script-{uuid4().hex}.js",
            kind="script source",
        )
        result: JsonObject = {
            "scriptId": script_id,
            "bytes": len(source.encode("utf-8", errors="replace")),
            "source": inline,
            "truncated": cut,
        }
        if spill is not None:
            result["source_path"] = str(spill)
        return result

    def script_sourcemap(
        self,
        session_id: str,
        script_id: str,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        extract: str = "",
    ) -> JsonObject:
        """Recover a live script's original sources from its source map.

        The dynamic counterpart to js.sourcemap: on a running page the .map is
        usually served, not on disk, so this fetches the script's source over CDP,
        reads its trailing sourceMappingURL, and -- for an external map -- fetches
        it in the page's own context (cookies/CORS apply) before parsing with the
        shared js_sourcemap parser. An inline data: URI is decoded directly. List
        mode (extract empty) and extract mode mirror js.sourcemap; a script with no
        sourceMappingURL comes back has_source_map False rather than as an error,
        so the caller can sweep web.scripts cheaply.
        """
        handle = self._get(session_id)
        wanted = str(script_id)
        with handle.lock:
            script = next(
                (s for s in handle.scripts.values() if str(s.get("scriptId")) == wanted),
                None,
            )
        script_url = str(script.get("url", "")) if script else ""

        def work() -> JsonObject:
            try:
                resp = handle.cdp.send("Debugger.getScriptSource", {"scriptId": wanted})
            except WebError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise WebError(
                    "not_found", f"cannot fetch script source: {exc}", script_id=wanted
                ) from exc
            source = resp.get("scriptSource", "") if isinstance(resp, dict) else ""
            if not isinstance(source, str):
                source = str(source)
            url_out = _bounded_metadata(script_url, _MAX_URL_BYTES)[0]
            mapping_url = find_source_mapping_url(source)
            if mapping_url is None:
                return {
                    "script_id": wanted,
                    "script_url": url_out,
                    "has_source_map": False,
                    "sources": [],
                    "count": 0,
                    "total": 0,
                    "offset": max(0, int(offset)),
                    "has_more": False,
                    "sources_total": 0,
                    "with_content": 0,
                }
            map_text, origin, resolved_url = self._resolve_map_text(
                handle, mapping_url, script_url
            )
            try:
                data = parse_source_map(map_text)
                sources, contents, meta = flatten_sources(data)
            except SourceMapError as exc:
                raise WebError(exc.code, exc.message, script_id=wanted) from exc
            if extract:
                result = extract_source(
                    sources, contents, meta, origin, extract,
                    content_cap=_MAX_WEB_SOURCEMAP_CONTENT,
                )
            else:
                result = list_sources(
                    sources, contents, meta, origin,
                    offset=offset, limit=limit, name_filter=name_filter,
                    page_cap=_MAX_WEB_SOURCEMAP_PAGE,
                )
            result["script_id"] = wanted
            result["script_url"] = url_out
            result["has_source_map"] = True
            result["source_map_url"] = resolved_url
            return result

        return self._runner(handle).call(work, timeout=_WEB_SOURCEMAP_TIMEOUT)

    def _resolve_map_text(
        self, handle: Any, mapping_url: str, script_url: str
    ) -> tuple[str, str, str]:
        """Return (map_json_text, origin, resolved_url) for a sourceMappingURL.

        An inline data: URI is decoded locally; anything else is resolved against
        the script's URL and fetched in the page context. Runs on the runner
        thread (the caller's work()), so page.evaluate is legal here.
        """
        if mapping_url.startswith("data:"):
            try:
                decoded = decode_data_uri(
                    mapping_url, max_bytes=_MAX_WEB_SOURCEMAP_FETCH_BYTES
                )
            except SourceMapError as exc:
                raise WebError(exc.code, exc.message) from exc
            return decoded, "inline", "data:"
        abs_url = mapping_url
        if not is_remote_url(mapping_url):
            if not script_url:
                raise WebError(
                    "invalid_state",
                    "source map is a relative reference but the script has no "
                    "URL to resolve against",
                    source_mapping_url=mapping_url,
                )
            abs_url = urljoin(script_url, mapping_url)
        elif mapping_url.startswith("//") and script_url:
            abs_url = urljoin(script_url, mapping_url)
        try:
            fetched = handle.page.evaluate(
                _WEB_SOURCEMAP_FETCH_JS,
                {"url": abs_url, "max": _MAX_WEB_SOURCEMAP_FETCH_BYTES},
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError("backend_error", f"cannot fetch source map: {exc}", url=abs_url) from exc
        if not isinstance(fetched, dict) or not fetched.get("ok"):
            if isinstance(fetched, dict) and fetched.get("status") is not None:
                detail = f"HTTP {fetched.get('status')}"
            elif isinstance(fetched, dict) and fetched.get("error"):
                detail = str(fetched.get("error"))
            else:
                detail = "unknown error"
            raise WebError(
                "backend_error", f"source map fetch failed: {detail}", url=abs_url
            )
        text = fetched.get("text")
        if not isinstance(text, str):
            text = str(text) if text is not None else ""
        return text, f"external:{abs_url}", abs_url

    def secrets(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        name_filter: str = "",
        include_generic: bool = False,
        url_filter: str = "",
        dynamic_only: bool = False,
    ) -> JsonObject:
        """Scan the live page's parsed scripts for embedded credentials.

        The dynamic-page counterpart to js.secrets: that scans a file at rest,
        this fetches the source of the scripts the running page actually parsed --
        including the runtime/eval/new-Function scripts (dynamic=True) a packer
        unpacks in memory and never writes to disk, which no static pass sees --
        and runs the same detector table over each (via the shared JS lexer, so
        \\x/\\u-escaped keys are decoded and quotes in comments/regex are not
        mistaken for strings). Findings are deduplicated across scripts by
        (detector, value): each row is {detector, value (clipped, value_truncated
        when long), count (occurrences across the page), first_script ({script_id,
        url} -- the script to hand web.script.source)}. Answers also carry
        detectors (the distinct set present), scanned_scripts (how many sources
        were fetched and scanned), scripts_dropped (ring eviction of the parsed-
        script list) and scan_capped (the script count, per-source byte, total
        scan-byte or distinct-finding ceiling was hit). url_filter and dynamic_only
        pre-narrow which scripts are scanned (dynamic_only isolates the eval/packer
        payloads); WASM scripts are skipped (use wasm.secrets). name_filter then
        keeps only findings whose detector or value contains that substring
        (case-insensitive), applied before paging so total is the match count.
        include_generic adds a high-entropy catch-all for a literal no specific
        detector claimed.
        """
        handle = self._get(session_id)
        with handle.lock:
            script_list = list(handle.scripts.values())
            dropped = handle.scripts_dropped
        if dynamic_only:
            script_list = [s for s in script_list if s.get("dynamic")]
        url_needle = url_filter.strip().lower() if isinstance(url_filter, str) else ""
        if url_needle:
            script_list = [s for s in script_list if url_needle in str(s.get("url", "")).lower()]
        # getScriptSource on a wasm script returns WAT, not JS; that is wasm.secrets'
        # job, so only JavaScript sources are scanned here.
        script_list = [
            s for s in script_list if str(s.get("language", "")).lower() != "webassembly"
        ]

        def work() -> JsonObject:
            aggregates: dict[tuple[str, str], JsonObject] = {}
            scanned_bytes = 0
            scanned_scripts = 0
            scan_capped = False
            stop = False
            for script in script_list:
                if scanned_scripts >= _MAX_WEB_SECRET_SCRIPTS:
                    scan_capped = True
                    break
                script_id = str(script.get("scriptId"))
                try:
                    resp = handle.cdp.send(
                        "Debugger.getScriptSource", {"scriptId": script_id}
                    )
                except Exception:  # noqa: BLE001
                    # A script the engine already discarded (or otherwise refuses)
                    # is skipped rather than failing the whole scan.
                    continue
                source = resp.get("scriptSource", "") if isinstance(resp, dict) else ""
                if not isinstance(source, str):
                    source = str(source)
                source = source[:_MAX_WEB_SECRET_SOURCE_BYTES]
                scanned_bytes += len(source)
                scanned_scripts += 1
                url = _bounded_metadata(script.get("url"), _MAX_URL_BYTES)[0]
                per, _detectors, per_capped = extract_js_secrets(
                    source, include_generic=include_generic
                )
                if per_capped:
                    scan_capped = True
                for finding in per:
                    key = (str(finding["detector"]), str(finding["value"]))
                    current = aggregates.get(key)
                    if current is None:
                        if len(aggregates) >= _MAX_WEB_SECRET_FINDINGS:
                            scan_capped = True
                            stop = True
                            break
                        row: JsonObject = {
                            "detector": finding["detector"],
                            "value": finding["value"],
                            "count": int(finding["count"]),
                            "first_script": {"script_id": script_id, "url": url},
                        }
                        if finding.get("value_truncated"):
                            row["value_truncated"] = True
                        aggregates[key] = row
                    else:
                        current["count"] = int(current["count"]) + int(finding["count"])
                if stop:
                    break
                if scanned_bytes >= _MAX_WEB_SECRET_SCAN_BYTES:
                    scan_capped = True
                    break

            needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
            secrets = list(aggregates.values())
            if needle:
                secrets = [
                    s
                    for s in secrets
                    if needle in str(s["detector"]).lower() or needle in str(s["value"]).lower()
                ]
            secrets.sort(key=lambda s: (str(s["detector"]), -int(s["count"]), str(s["value"])))
            detectors = sorted({str(s["detector"]) for s in secrets})
            start = max(0, int(offset))
            cap = max(1, min(int(limit), 1000))
            window = secrets[start : start + cap]
            return {
                "secrets": window,
                "count": len(window),
                "total": len(secrets),
                "offset": start,
                "has_more": start + len(window) < len(secrets),
                "detectors": detectors,
                "scanned_scripts": scanned_scripts,
                "scripts_dropped": dropped,
                "scan_capped": scan_capped,
            }

        return self._runner(handle).call(work, timeout=_WEB_SECRET_SCAN_TIMEOUT)

    def endpoints(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        name_filter: str = "",
        include_paths: bool = True,
        url_filter: str = "",
        dynamic_only: bool = False,
    ) -> JsonObject:
        """Extract the network endpoints baked into the live page's scripts.

        The dynamic-page counterpart to js.endpoints, and the static complement to
        web.network.list: that shows the endpoints the page actually hit, this
        fetches the source of every script the running page parsed -- including the
        runtime/eval/new-Function scripts (dynamic=True) a packer unpacks in memory
        and never writes to disk -- and pulls the scheme'd URLs (http/https/ws/wss/
        ftp) and, when include_paths is set, the request paths ('/api/...') out of
        each via the shared JS lexer (so \\x/\\u-escaped URLs are decoded and quotes
        in comments/regex are not mistaken for strings). This surfaces the
        configured-but-not-yet-called endpoints -- feature-gated, admin, or
        lazy-chunk backends -- that never appear in the network log. Endpoints are
        deduplicated across scripts by value: each row is {value, kind (url|path),
        scheme, host, count (occurrences across the page), first_script
        ({script_id, url}, the script to hand web.script.source)}. Answers also
        carry hosts (the distinct host set of the URL endpoints, hosts_truncated
        when capped), scanned_scripts, scripts_dropped and scan_capped (a script-
        count, per-source-byte, total-scan-byte or distinct-endpoint ceiling was
        hit). url_filter and dynamic_only pre-narrow which scripts are scanned;
        WASM scripts are skipped. name_filter then keeps only endpoints whose value
        or host contains that substring (case-insensitive), applied before the host
        summary and paging so total is the match count.
        """
        handle = self._get(session_id)
        with handle.lock:
            script_list = list(handle.scripts.values())
            dropped = handle.scripts_dropped
        if dynamic_only:
            script_list = [s for s in script_list if s.get("dynamic")]
        url_needle = url_filter.strip().lower() if isinstance(url_filter, str) else ""
        if url_needle:
            script_list = [s for s in script_list if url_needle in str(s.get("url", "")).lower()]
        script_list = [
            s for s in script_list if str(s.get("language", "")).lower() != "webassembly"
        ]

        def work() -> JsonObject:
            aggregates: dict[str, JsonObject] = {}
            scanned_bytes = 0
            scanned_scripts = 0
            scan_capped = False
            stop = False
            for script in script_list:
                if scanned_scripts >= _MAX_WEB_ENDPOINT_SCRIPTS:
                    scan_capped = True
                    break
                script_id = str(script.get("scriptId"))
                try:
                    resp = handle.cdp.send(
                        "Debugger.getScriptSource", {"scriptId": script_id}
                    )
                except Exception:  # noqa: BLE001
                    continue
                source = resp.get("scriptSource", "") if isinstance(resp, dict) else ""
                if not isinstance(source, str):
                    source = str(source)
                source = source[:_MAX_WEB_ENDPOINT_SOURCE_BYTES]
                scanned_bytes += len(source)
                scanned_scripts += 1
                url = _bounded_metadata(script.get("url"), _MAX_URL_BYTES)[0]
                per, _hosts, _hosts_trunc, per_capped = extract_js_endpoints(
                    source, include_paths=include_paths
                )
                if per_capped:
                    scan_capped = True
                for finding in per:
                    value = str(finding["value"])
                    current = aggregates.get(value)
                    if current is None:
                        if len(aggregates) >= _MAX_WEB_ENDPOINT_FINDINGS:
                            scan_capped = True
                            stop = True
                            break
                        aggregates[value] = {
                            "value": finding["value"],
                            "kind": finding["kind"],
                            "scheme": finding["scheme"],
                            "host": finding["host"],
                            "count": int(finding["count"]),
                            "first_script": {"script_id": script_id, "url": url},
                        }
                    else:
                        current["count"] = int(current["count"]) + int(finding["count"])
                if stop:
                    break
                if scanned_bytes >= _MAX_WEB_ENDPOINT_SCAN_BYTES:
                    scan_capped = True
                    break

            needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
            endpoints = list(aggregates.values())
            if needle:
                endpoints = [
                    e
                    for e in endpoints
                    if needle in str(e["value"]).lower() or needle in str(e["host"]).lower()
                ]
            endpoints.sort(key=lambda e: (-int(e["count"]), str(e["value"])))
            all_hosts = sorted({str(e["host"]) for e in endpoints if e.get("host")})
            hosts_truncated = len(all_hosts) > _MAX_WEB_ENDPOINT_HOSTS
            host_list = all_hosts[:_MAX_WEB_ENDPOINT_HOSTS]
            start = max(0, int(offset))
            cap = max(1, min(int(limit), 1000))
            window = endpoints[start : start + cap]
            return {
                "endpoints": window,
                "count": len(window),
                "total": len(endpoints),
                "offset": start,
                "has_more": start + len(window) < len(endpoints),
                "hosts": host_list,
                "hosts_truncated": hosts_truncated,
                "scanned_scripts": scanned_scripts,
                "scripts_dropped": dropped,
                "scan_capped": scan_capped,
            }

        return self._runner(handle).call(work, timeout=_WEB_ENDPOINT_SCAN_TIMEOUT)

    def wasm_get(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        """Write a live WebAssembly module's raw bytes to a .wasm artifact.

        web.wasm.list surfaces the modules but the only way to read one was
        Debugger.getScriptSource, which for wasm returns the engine's textual
        disassembly, not the binary -- so the module could not be fed to the
        wasm.wat / wasm.info tools that exist to analyse it. This pulls the
        bytecode (Debugger.getWasmBytecode) and, being binary, always spills to
        a file rather than inlining. Session-level faults propagate with their
        own code, as script_source does; a missing/evicted module is not_found.
        """
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.scripts.get(script_id)
        if entry is None:
            raise WebError("not_found", "unknown script id", script_id=script_id)
        if str(entry.get("language", "")).lower() != "webassembly":
            raise WebError(
                "invalid_params",
                "script is not a WebAssembly module; see language on web.wasm.list",
                script_id=script_id,
            )
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Debugger.getWasmBytecode", {"scriptId": script_id})
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError(
                "not_found", f"cannot fetch wasm bytecode: {exc}", script_id=script_id
            ) from exc
        encoded = resp.get("bytecode", "") if isinstance(resp, dict) else ""
        try:
            payload = base64.b64decode(encoded or "", validate=False)
        except (ValueError, TypeError) as exc:
            raise WebError(
                "backend_error", f"invalid wasm bytecode: {exc}", script_id=script_id
            ) from exc
        if len(payload) > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise WebError(
                "too_large",
                "wasm module exceeds capture cap",
                size=len(payload),
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
                script_id=script_id,
            )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        out = artifact_dir / f"wasm-{uuid4().hex}.wasm"
        out.write_bytes(payload)
        return {
            "scriptId": script_id,
            "url": entry.get("url"),
            "bytes": len(payload),
            "wasm_path": str(out),
        }

    def dom_snapshot(self, session_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        # Clip in the browser at the spill ceiling, not the 200 KB inline cap:
        # a DOM between the two used to come back cut with no way to recover the
        # rest, unlike script.source / network.get which spill the full payload
        # to an artifact. Bounding the transfer here keeps a huge SPA from
        # serialising unbounded into memory; _spill_text then inlines a prefix
        # and writes the full (up to the cap) DOM to dom_path.
        cap = UNREGISTERED_CAPTURE_MAX_BYTES

        def work() -> JsonObject:
            try:
                clipped = handle.page.evaluate(
                    """(cap) => {
                        const html = document.documentElement
                          ? document.documentElement.outerHTML
                          : (document.body ? document.body.outerHTML : "");
                        const text = typeof html === "string" ? html : "";
                        return {
                          html: text.length > cap ? text.slice(0, cap) : text,
                          over: text.length > cap
                        };
                    }""",
                    cap,
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            if not isinstance(clipped, dict):
                raise WebError("backend_error", "dom snapshot returned no document")
            html = clipped.get("html")
            text = html if isinstance(html, str) else ""
            inline, spill, cut = _spill_text(
                text,
                artifact_dir=artifact_dir,
                filename=f"dom-{uuid4().hex}.html",
                kind="dom snapshot",
                truncate=True,
            )
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "html": inline,
                "truncated": cut or bool(clipped.get("over")),
            }
            if spill is not None:
                result["dom_path"] = str(spill)
            return result

        return self._runner(handle).call(work)

    def screenshot(self, session_id: str, out_path: Path, *, full_page: bool = False) -> JsonObject:
        handle = self._get(session_id)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        def work() -> JsonObject:
            try:
                handle.page.screenshot(path=str(out_path), full_page=full_page)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"screenshot failed: {exc}") from exc
            size, over = capped_file_size(out_path, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
            if over:
                raise WebError(
                    "too_large",
                    "screenshot exceeds capture cap",
                    size=size,
                    cap=UNREGISTERED_CAPTURE_MAX_BYTES,
                )
            return {"path": str(out_path), "size": size}

        return self._runner(handle).call(work)

    def har_export(self, session_id: str, out_path: Path) -> JsonObject:
        from headless_re_mcp.backends.common.har import (
            har_document,
            har_entry,
            header_value,
            post_data,
        )

        handle = self._get(session_id)
        with handle.lock:
            entries = [
                har_entry(
                    started_at=e.get("started_at"),
                    method=e.get("method"),
                    url=e.get("url"),
                    status=e.get("status"),
                    mime_type=e.get("mimeType"),
                    request_headers=e.get("request_headers"),
                    response_headers=e.get("response_headers"),
                    # The inline body CDP handed us at send time, typed by the
                    # request's own content-type header, so a viewer shows the
                    # POST payload instead of an empty Request tab.
                    request_post_data=post_data(
                        e.get("post_data"),
                        header_value(e.get("request_headers"), "content-type"),
                    ),
                    # The server IP the response actually came from, so the HAR
                    # entry's serverIPAddress names the C2/CDN host, not just the
                    # domain in the URL.
                    server_ip=str(e.get("remote_ip") or ""),
                    extra={"_resourceType": e.get("resourceType")},
                )
                for e in handle.requests.values()
            ]
        import json

        har = har_document(entries)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(har, ensure_ascii=False)
        truncated = False
        encoded = text.encode("utf-8")
        while entries and len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            drop = max(1, len(entries) // 8)
            del entries[-drop:]
            har["log"]["entries"] = entries
            text = json.dumps(har, ensure_ascii=False)
            encoded = text.encode("utf-8")
            truncated = True
        if len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise WebError(
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

    def close_all(self) -> None:
        with self._lock:
            session_ids = list(self._sessions)
        for session_id in session_ids:
            with contextlib.suppress(WebError):
                self.close(session_id)


def _safe_title(page: Any) -> str:
    try:
        return _bounded_metadata(page.title(), _MAX_METADATA_BYTES)[0]
    except Exception:  # noqa: BLE001
        return ""


def _playwright_driver_pid(playwright: Any) -> int | None:
    """PID of the node driver that owns Chromium.

    Playwright does not publish this. The private chain is the only handle a
    wedged session has left, because the objects themselves cannot be touched
    from any thread other than the one that created them.
    """
    current: Any = playwright
    for attr in ("_impl_obj", "_connection", "_transport", "_proc"):
        current = getattr(current, attr, None)
        if current is None:
            return None
    pid = getattr(current, "pid", None)
    return pid if isinstance(pid, int) and pid > 0 else None


_DRIVER_IMAGE_MARKERS = ("node", "chromium", "chrome", "playwright")


def _reap_driver_pid(pid: int | None) -> None:
    if not isinstance(pid, int) or pid <= 0:
        return
    image = (process_image_path(pid) or "").casefold()
    if not image or not any(marker in image for marker in _DRIVER_IMAGE_MARKERS):
        return
    terminate_pid_tree(pid)


def _reap_web_session(handle: _WebSession) -> None:
    _reap_driver_pid(getattr(handle, "driver_pid", None))
