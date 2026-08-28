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
import binascii
import contextlib
import queue
import threading
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit
from uuid import uuid4

from headless_re_mcp.backends.common.har import har_entry, serialize_har
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size
from headless_re_mcp.core.process_tree import process_image_path, terminate_pid_tree

JsonObject = dict[str, Any]
T = TypeVar("T")

_MAX_REQUESTS = 3000
_MAX_CONSOLE = 2000
_MAX_SCRIPTS = 2000
_MAX_INLINE_BODY = 200_000
_MAX_CONSOLE_TEXT = 8 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
# web.network.stats top-N ceiling: a page can touch hundreds of hosts, so the
# ranked host/mime lists are capped even when the caller asks for more.
_MAX_TOP_STATS = 50
# web.storage caps: a page can stuff thousands of keys or a multi-megabyte value
# into Web Storage, so both the key list and each value are bounded.
_MAX_STORAGE_KEYS = 500
_MAX_STORAGE_VALUE_CHARS = 8192
# web.cookies caps: a context can hold a large jar and each value can be a long
# signed token, so both the list and each value are bounded.
_MAX_COOKIES = 500
_MAX_COOKIE_VALUE_CHARS = 4096
# web.forms caps: a page can carry many forms with many fields each; bound the
# form list, the fields per form, and each captured (hidden/submit) value.
_MAX_FORMS = 200
_MAX_FORM_FIELDS = 100
_MAX_FIELD_VALUE_CHARS = 2048
# web.meta caps: a page head can carry hundreds of meta/link tags (og:*, twitter:*,
# preconnect); bound both lists and each meta content string.
_MAX_META_TAGS = 300
_MAX_META_LINKS = 200
_MAX_META_CONTENT_CHARS = 2048
# web.links caps: a content-heavy page can carry thousands of anchors and
# subresources; bound the anchor list, the subresource list and the origin roll-up.
_MAX_ANCHORS = 500
_MAX_SUB_RESOURCES = 500
_MAX_LINK_ORIGINS = 200
# web.frames cap: an ad-heavy page can nest hundreds of iframes; bound the list.
_MAX_FRAMES = 200
# web.performance cap: a resource-heavy page reports thousands of Resource Timing
# entries; bound the slowest-first list the tool returns.
_MAX_PERF_RESOURCES = 100
# web.dom.query caps: a broad selector can match thousands of nodes; bound the
# element list, the attributes per element, and each captured value/text/html.
_MAX_DOM_QUERY = 100
_MAX_DOM_ATTRS = 50
_MAX_DOM_ATTR_CHARS = 1024
_MAX_DOM_TEXT = 2048
_MAX_DOM_HTML = 512
# web.network.headers captures the request/response header maps per request.
# Bound the header count, each value, and the whole map so a hostile response
# cannot balloon the per-request entry held in the ring.
_MAX_HEADERS = 100
_MAX_HEADER_VALUE_BYTES = 2048
_MAX_HEADER_MAP_BYTES = 16 * 1024
# CDP already caps the inline postData it hands out; bound it again so one large
# upload cannot bloat the per-request buffer that lives in the ring.
_MAX_POST_BODY_BYTES = 64 * 1024
# Playwright enforces its own timeouts inside the driver process, so they stop
# existing the moment the driver does. This is the outer bound that keeps a call
# from parking a worker thread forever when that happens.
_CALL_TIMEOUT = 60.0
# Ceiling for a caller-supplied navigation timeout, matching the web.open /
# web.navigate tool schema (``0 < timeout <= 120``). See ``_bound_nav_timeout``.
_MAX_NAV_TIMEOUT_S = 120.0
_OPENING = object()


class WebError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _bound_nav_timeout(timeout: float) -> float:
    """Clamp a caller navigation timeout at the backend boundary.

    The tool schema declares ``0 < timeout <= 120``, but the agent transport
    invokes handlers straight from model arguments with no schema enforcement
    (``CommandCatalog.invoke`` -> ``spec.handler(**arguments)``), the same gap
    frida guards with ``_bound_timeout``. A non-positive value would reach
    ``Future.result(timeout<=0)``, which returns immediately and flips the
    runner to ``_wedged`` -- bricking a healthy session until ``web.close`` --
    while a huge one would park the session thread and a pool worker for as long
    as the page took. Reject the first and cap the second before any work is
    queued, so a stray timeout can never wedge a live browser.
    """
    value = float(timeout)
    if value <= 0:
        raise WebError("invalid_params", "timeout must be positive")
    return min(value, _MAX_NAV_TIMEOUT_S)


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _bounded_header_map(value: object) -> tuple[dict[str, str], bool]:
    """Copy a CDP header map into a bounded dict, reporting whether it was cut.

    CDP hands the request/response headers as a name->value object (repeated
    headers already folded, joined by newlines). Bound the header count, each
    value, and the total bytes so a page that returns thousands of headers or a
    megabyte-long value cannot grow the per-request entry that lives in the ring.
    """
    if not isinstance(value, dict):
        return {}, False
    out: dict[str, str] = {}
    truncated = False
    budget = _MAX_HEADER_MAP_BYTES
    for name, raw in value.items():
        if len(out) >= _MAX_HEADERS:
            truncated = True
            break
        name_s = str(name)
        val, cut = _bounded_metadata(raw, _MAX_HEADER_VALUE_BYTES)
        cost = len(name_s.encode("utf-8", "replace")) + len(val.encode("utf-8", "replace"))
        if cost > budget:
            truncated = True
            break
        budget -= cost
        out[name_s] = val
        if cut:
            truncated = True
    return out, truncated


# Read both Web Storage areas in one page hop. Each area is dumped defensively:
# an opaque origin makes ``window.localStorage`` throw, so we trap per-area and
# report the error name rather than failing the whole read. Key count and value
# length are bounded in-page so a hostile page cannot balloon the response.
_STORAGE_SCRIPT = """(cfg) => {
  const dump = (store) => {
    try {
      const total = store.length;
      const out = [];
      for (let i = 0; i < total && out.length < cfg.maxKeys; i++) {
        const k = store.key(i);
        let v = "";
        try { v = String(store.getItem(k) ?? ""); } catch (e) { v = ""; }
        const cut = v.length > cfg.maxValueChars;
        out.push({
          key: String(k),
          value: cut ? v.slice(0, cfg.maxValueChars) : v,
          value_truncated: cut
        });
      }
      return { entries: out, total: total, error: null };
    } catch (e) {
      return { entries: [], total: 0, error: String((e && e.name) || e) };
    }
  };
  let origin = "";
  try { origin = String(location.origin || ""); } catch (e) { origin = ""; }
  return {
    origin: origin,
    local: dump(window.localStorage),
    session: dump(window.sessionStorage)
  };
}"""


def _fold_storage(part: object) -> tuple[list[JsonObject], int, str | None]:
    """Normalise one Web Storage area's page-side dump into bounded rows."""
    if not isinstance(part, dict):
        return [], 0, None
    error = part.get("error")
    total = 0
    try:
        total = int(part.get("total") or 0)
    except (TypeError, ValueError):
        total = 0
    entries: list[JsonObject] = []
    for item in part.get("entries") or []:
        if not isinstance(item, dict):
            continue
        key = _bounded_metadata(item.get("key"), _MAX_METADATA_BYTES)[0]
        raw_value = item.get("value")
        value = raw_value if isinstance(raw_value, str) else ""
        truncated = bool(item.get("value_truncated"))
        if len(value) > _MAX_STORAGE_VALUE_CHARS:
            value = value[:_MAX_STORAGE_VALUE_CHARS]
            truncated = True
        entries.append({"key": key, "value": value, "value_truncated": truncated})
    error_text = error if isinstance(error, str) and error else None
    return entries, total, error_text


# Enumerate the page's forms in one hop. Field values are captured only for
# hidden and submit inputs (CSRF tokens, action markers) -- never for password
# or text inputs -- and every list and value is bounded in-page.
_FORMS_SCRIPT = """(cfg) => {
  const out = [];
  const list = document.forms;
  const total = list.length;
  for (let i = 0; i < total && out.length < cfg.maxForms; i++) {
    const f = list[i];
    let action = "";
    try { action = String(f.action || ""); } catch (e) { action = ""; }
    const fields = [];
    const elements = f.elements;
    const fieldTotal = elements.length;
    let fieldCut = false;
    for (let j = 0; j < fieldTotal; j++) {
      if (fields.length >= cfg.maxFields) { fieldCut = true; break; }
      const el = elements[j];
      const tag = String(el.tagName || "").toLowerCase();
      const type = String(el.type || "").toLowerCase();
      let value = "";
      if (type === "hidden" || type === "submit") {
        try { value = String(el.value || "").slice(0, cfg.maxValueChars); }
        catch (e) { value = ""; }
      }
      fields.push({
        tag: tag,
        type: type,
        name: String(el.name || ""),
        value: value,
        required: !!el.required
      });
    }
    out.push({
      name: String(f.name || ""),
      id: String(f.id || ""),
      action: action,
      method: String(f.method || "get").toLowerCase(),
      enctype: String(f.enctype || ""),
      field_count: fieldTotal,
      fields: fields,
      fields_truncated: fieldCut
    });
  }
  return { forms: out, total: total };
}"""


def _fold_form(raw: object, page_host: str) -> JsonObject:
    """Normalise one page-side form dump into a bounded, triage-friendly row."""
    form = raw if isinstance(raw, dict) else {}
    fields: list[JsonObject] = []
    has_password = False
    has_file = False
    for item in form.get("fields") or []:
        if not isinstance(item, dict):
            continue
        field_type = _bounded_metadata(item.get("type"), _MAX_METADATA_BYTES)[0]
        if field_type == "password":
            has_password = True
        if field_type == "file":
            has_file = True
        value = item.get("value")
        value = value if isinstance(value, str) else ""
        fields.append(
            {
                "tag": _bounded_metadata(item.get("tag"), _MAX_METADATA_BYTES)[0],
                "type": field_type,
                "name": _bounded_metadata(item.get("name"), _MAX_METADATA_BYTES)[0],
                "value": value[:_MAX_FIELD_VALUE_CHARS],
                "required": bool(item.get("required")),
            }
        )
    action = _bounded_metadata(form.get("action"), _MAX_URL_BYTES)[0]
    action_host = ""
    if action:
        try:
            action_host = urlsplit(action).netloc
        except ValueError:
            action_host = ""
    field_count = form.get("field_count")
    return {
        "name": _bounded_metadata(form.get("name"), _MAX_METADATA_BYTES)[0],
        "id": _bounded_metadata(form.get("id"), _MAX_METADATA_BYTES)[0],
        "action": action,
        "action_external": bool(action_host) and action_host != page_host,
        "method": _bounded_metadata(form.get("method"), _MAX_METADATA_BYTES)[0],
        "enctype": _bounded_metadata(form.get("enctype"), _MAX_METADATA_BYTES)[0],
        "field_count": int(field_count) if isinstance(field_count, int) else len(fields),
        "fields": fields,
        "fields_truncated": bool(form.get("fields_truncated")),
        "has_password": has_password,
        "has_file": has_file,
    }


_META_SCRIPT = """(cfg) => {
  const metas = [];
  const metaEls = document.getElementsByTagName('meta');
  const metaTotal = metaEls.length;
  let refresh = null, csp = null;
  for (let i = 0; i < metaTotal; i++) {
    const m = metaEls[i];
    const httpEquiv = String(m.getAttribute('http-equiv') || '');
    const content = String(m.getAttribute('content') || '').slice(0, cfg.maxContent);
    const he = httpEquiv.toLowerCase();
    if (he === 'refresh' && refresh === null) refresh = content;
    if (he === 'content-security-policy' && csp === null) csp = content;
    if (metas.length < cfg.maxMetas) {
      metas.push({
        name: String(m.getAttribute('name') || ''),
        property: String(m.getAttribute('property') || ''),
        http_equiv: httpEquiv,
        charset: String(m.getAttribute('charset') || ''),
        content: content
      });
    }
  }
  const links = [];
  const linkEls = document.getElementsByTagName('link');
  const linkTotal = linkEls.length;
  for (let i = 0; i < linkTotal && links.length < cfg.maxLinks; i++) {
    const l = linkEls[i];
    let href = '';
    try { href = String(l.href || ''); } catch (e) { href = ''; }
    links.push({
      rel: String(l.getAttribute('rel') || ''),
      href: href,
      type: String(l.getAttribute('type') || '')
    });
  }
  let base = '';
  try { const b = document.querySelector('base'); base = b ? String(b.href || '') : ''; }
  catch (e) { base = ''; }
  let lang = '';
  try { lang = String(document.documentElement.getAttribute('lang') || ''); }
  catch (e) { lang = ''; }
  return {
    title: String(document.title || ''),
    charset: String(document.characterSet || ''),
    lang: lang,
    base: base,
    metas: metas,
    meta_total: metaTotal,
    links: links,
    link_total: linkTotal,
    refresh: refresh,
    csp: csp
  };
}"""


def _parse_meta_refresh(content: object) -> JsonObject | None:
    """Split a meta-refresh content string into {delay, url}.

    The grammar is ``<seconds>[; url=<target>]`` (case-insensitive, quotes
    optional). A bare number is a self-refresh with no url. Anything unparseable
    yields None so the caller reports no redirect rather than a wrong one.
    """
    if not isinstance(content, str) or not content.strip():
        return None
    head, _, tail = content.partition(";")
    try:
        delay = int(float(head.strip()))
    except ValueError:
        return None
    url: str | None = None
    tail = tail.strip()
    if tail:
        _, _, target = tail.partition("=")
        target = target.strip().strip("'\"")
        url = _bounded_metadata(target, _MAX_URL_BYTES)[0] if target else None
    return {"delay": delay, "url": url}


def _fold_meta_tag(raw: object) -> JsonObject:
    """Normalise one page-side <meta> dump into a bounded row."""
    item = raw if isinstance(raw, dict) else {}
    content = item.get("content")
    content = content if isinstance(content, str) else ""
    return {
        "name": _bounded_metadata(item.get("name"), _MAX_METADATA_BYTES)[0],
        "property": _bounded_metadata(item.get("property"), _MAX_METADATA_BYTES)[0],
        "http_equiv": _bounded_metadata(item.get("http_equiv"), _MAX_METADATA_BYTES)[0],
        "charset": _bounded_metadata(item.get("charset"), _MAX_METADATA_BYTES)[0],
        "content": content[:_MAX_META_CONTENT_CHARS],
    }


def _fold_meta_link(raw: object) -> JsonObject:
    """Normalise one page-side <link> dump into a bounded row."""
    item = raw if isinstance(raw, dict) else {}
    return {
        "rel": _bounded_metadata(item.get("rel"), _MAX_METADATA_BYTES)[0],
        "href": _bounded_metadata(item.get("href"), _MAX_URL_BYTES)[0],
        "type": _bounded_metadata(item.get("type"), _MAX_METADATA_BYTES)[0],
    }


_LINKS_SCRIPT = """(cfg) => {
  const anchors = [];
  const aEls = document.querySelectorAll('a[href]');
  const anchorTotal = aEls.length;
  for (let i = 0; i < anchorTotal && anchors.length < cfg.maxAnchors; i++) {
    const a = aEls[i];
    let href = '';
    try { href = String(a.href || ''); } catch (e) { href = ''; }
    anchors.push({
      href: href,
      text: String(a.textContent || '').trim().slice(0, cfg.maxText),
      target: String(a.getAttribute('target') || ''),
      rel: String(a.getAttribute('rel') || '')
    });
  }
  const specs = [
    ['script[src]', 'src', 'script'],
    ['link[href]', 'href', 'link'],
    ['img[src]', 'src', 'img'],
    ['iframe[src]', 'src', 'iframe'],
    ['source[src]', 'src', 'source'],
    ['video[src]', 'src', 'video'],
    ['audio[src]', 'src', 'audio'],
    ['embed[src]', 'src', 'embed'],
    ['object[data]', 'data', 'object']
  ];
  const resources = [];
  let resourceTotal = 0;
  for (let s = 0; s < specs.length; s++) {
    const els = document.querySelectorAll(specs[s][0]);
    resourceTotal += els.length;
    for (let i = 0; i < els.length && resources.length < cfg.maxResources; i++) {
      let url = '';
      try { url = String(els[i][specs[s][1]] || ''); } catch (e) { url = ''; }
      resources.push({ url: url, kind: specs[s][2] });
    }
  }
  return {
    anchors: anchors,
    anchor_total: anchorTotal,
    resources: resources,
    resource_total: resourceTotal
  };
}"""


_PERF_SCRIPT = """(cfg) => {
  const round = (x) => (typeof x === 'number' && isFinite(x) ? Math.round(x) : null);
  let nav = null;
  try {
    const entries = performance.getEntriesByType('navigation');
    if (entries && entries.length) {
      const n = entries[0];
      nav = {
        type: String(n.type || ''),
        redirect_count: n.redirectCount || 0,
        dns_ms: round(n.domainLookupEnd - n.domainLookupStart),
        connect_ms: round(n.connectEnd - n.connectStart),
        tls_ms: n.secureConnectionStart > 0 ? round(n.connectEnd - n.secureConnectionStart) : 0,
        ttfb_ms: round(n.responseStart - n.requestStart),
        response_ms: round(n.responseEnd - n.responseStart),
        dom_interactive_ms: round(n.domInteractive),
        dom_content_loaded_ms: round(n.domContentLoadedEventEnd),
        load_ms: round(n.loadEventEnd),
        transfer_size: n.transferSize || 0,
        encoded_body_size: n.encodedBodySize || 0,
        decoded_body_size: n.decodedBodySize || 0
      };
    }
  } catch (e) { nav = null; }
  const resources = [];
  let resourceTotal = 0;
  try {
    const res = performance.getEntriesByType('resource');
    resourceTotal = res.length;
    const sorted = res.slice().sort((a, b) => (b.duration || 0) - (a.duration || 0));
    for (let i = 0; i < sorted.length && resources.length < cfg.maxResources; i++) {
      const r = sorted[i];
      resources.push({
        url: String(r.name || '').slice(0, cfg.maxUrl),
        initiator_type: String(r.initiatorType || ''),
        duration_ms: round(r.duration),
        transfer_size: r.transferSize || 0
      });
    }
  } catch (e) {}
  return { navigation: nav, resources: resources, resource_total: resourceTotal };
}"""


def _link_host(url: str) -> str:
    try:
        return urlsplit(url).netloc
    except ValueError:
        return ""


def _link_origin(url: str) -> str | None:
    """scheme://host for an http(s)-style URL, else None (mailto/tel/js/data)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _fold_links(raw: object, page_url: str) -> JsonObject:
    """Fold a page-side anchor/subresource dump into a bounded outbound-ref map."""
    data = raw if isinstance(raw, dict) else {}
    page_host = _link_host(page_url)

    origins: OrderedDict[str, JsonObject] = OrderedDict()

    def _note_origin(url: str) -> None:
        origin = _link_origin(url)
        if origin is None:
            return
        entry = origins.get(origin)
        if entry is None:
            if len(origins) >= _MAX_LINK_ORIGINS:
                return
            host = _link_host(url)
            entry = {
                "origin": origin,
                "host": host,
                "count": 0,
                "external": bool(host) and host != page_host,
            }
            origins[origin] = entry
        entry["count"] = int(entry["count"]) + 1

    anchors: list[JsonObject] = []
    for item in data.get("anchors") or []:
        if not isinstance(item, dict):
            continue
        href = _bounded_metadata(item.get("href"), _MAX_URL_BYTES)[0]
        host = _link_host(href)
        anchors.append(
            {
                "href": href,
                "text": _bounded_metadata(item.get("text"), _MAX_METADATA_BYTES)[0],
                "target": _bounded_metadata(item.get("target"), _MAX_METADATA_BYTES)[0],
                "rel": _bounded_metadata(item.get("rel"), _MAX_METADATA_BYTES)[0],
                "host": host,
                "external": bool(host) and host != page_host,
            }
        )
        _note_origin(href)

    resources: list[JsonObject] = []
    for item in data.get("resources") or []:
        if not isinstance(item, dict):
            continue
        url = _bounded_metadata(item.get("url"), _MAX_URL_BYTES)[0]
        host = _link_host(url)
        resources.append(
            {
                "url": url,
                "kind": _bounded_metadata(item.get("kind"), _MAX_METADATA_BYTES)[0],
                "host": host,
                "external": bool(host) and host != page_host,
            }
        )
        _note_origin(url)

    ranked = sorted(origins.values(), key=lambda row: int(row["count"]), reverse=True)
    anchor_total = data.get("anchor_total")
    anchor_total_int = int(anchor_total) if isinstance(anchor_total, int) else len(anchors)
    resource_total = data.get("resource_total")
    resource_total_int = (
        int(resource_total) if isinstance(resource_total, int) else len(resources)
    )
    return {
        "url": page_url,
        "anchors": anchors,
        "anchor_count": len(anchors),
        "anchor_total": anchor_total_int,
        "anchors_truncated": anchor_total_int > len(anchors),
        "resources": resources,
        "resource_count": len(resources),
        "resource_total": resource_total_int,
        "resources_truncated": resource_total_int > len(resources),
        "origins": ranked,
        "origin_count": len(ranked),
        "external_origin_count": sum(1 for row in ranked if row["external"]),
    }


def _fold_frames(rows: list[JsonObject], main_url: str) -> JsonObject:
    """Fold a page-side frame dump into a bounded, host-classified frame list."""
    main_host = _link_host(main_url)
    frames: list[JsonObject] = []
    truncated = False
    cross_origin = 0
    for raw in rows:
        if len(frames) >= _MAX_FRAMES:
            truncated = True
            break
        url = _bounded_metadata(raw.get("url"), _MAX_URL_BYTES)[0]
        host = _link_host(url)
        is_main = bool(raw.get("is_main"))
        external = bool(host) and host != main_host
        if external and not is_main:
            cross_origin += 1
        parent_raw = raw.get("parent_url")
        parent_url = (
            _bounded_metadata(parent_raw, _MAX_URL_BYTES)[0]
            if parent_raw is not None
            else None
        )
        frames.append(
            {
                "url": url,
                "name": _bounded_metadata(raw.get("name"), _MAX_METADATA_BYTES)[0],
                "is_main": is_main,
                "parent_url": parent_url,
                "depth": int(raw.get("depth") or 0),
                "host": host,
                "external": external,
            }
        )
    return {
        "url": main_url,
        "frames": frames,
        "count": len(frames),
        "total": len(rows),
        "truncated": truncated,
        "cross_origin_count": cross_origin,
    }


_DOM_QUERY_SCRIPT = """(cfg) => {
  let nodes;
  try {
    nodes = document.querySelectorAll(cfg.selector);
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
  const total = nodes.length;
  const out = [];
  for (let i = 0; i < total && out.length < cfg.maxElements; i++) {
    const el = nodes[i];
    const attrs = {};
    const names = el.getAttributeNames ? el.getAttributeNames() : [];
    for (let a = 0; a < names.length && a < cfg.maxAttrs; a++) {
      attrs[names[a]] = String(el.getAttribute(names[a]) || '').slice(0, cfg.maxAttrChars);
    }
    out.push({
      tag: String(el.tagName || '').toLowerCase(),
      text: String(el.textContent || '').trim().slice(0, cfg.maxText),
      attributes: attrs,
      attr_count: names.length,
      html: String(el.outerHTML || '').slice(0, cfg.maxHtml)
    });
  }
  return { total: total, elements: out };
}"""


def _fold_dom_query(raw: object, selector: str) -> JsonObject:
    """Fold a page-side querySelectorAll dump into a bounded element list."""
    data = raw if isinstance(raw, dict) else {}
    elements: list[JsonObject] = []
    truncated = False
    for item in data.get("elements") or []:
        if not isinstance(item, dict):
            continue
        if len(elements) >= _MAX_DOM_QUERY:
            truncated = True
            break
        attrs: JsonObject = {}
        attrs_in = item.get("attributes")
        if isinstance(attrs_in, dict):
            for key, value in list(attrs_in.items())[:_MAX_DOM_ATTRS]:
                attrs[str(key)[:256]] = _bounded_metadata(value, _MAX_DOM_ATTR_CHARS)[0]
        elements.append(
            {
                "tag": _bounded_metadata(item.get("tag"), 64)[0],
                "text": _bounded_metadata(item.get("text"), _MAX_DOM_TEXT)[0],
                "attributes": attrs,
                "attr_count": int(item.get("attr_count") or len(attrs)),
                "html": _bounded_metadata(item.get("html"), _MAX_DOM_HTML)[0],
            }
        )
    total = data.get("total")
    total_int = int(total) if isinstance(total, int) else len(elements)
    return {
        "selector": selector,
        "elements": elements,
        "count": len(elements),
        "total": total_int,
        "truncated": truncated or total_int > len(elements),
    }


def summarize_requests(
    items: list[JsonObject], *, dropped: int = 0, top: int = 10
) -> JsonObject:
    """Fold captured network requests into a one-look triage summary.

    Pure over the rows the CDP event wiring records (url/method/resourceType/
    status/mimeType), so it needs no live page and stays testable in isolation.
    host is parsed from each url; a row still awaiting its response carries a
    null status and is counted as pending. Both ranked lists are capped at
    ``top``.
    """
    top = max(1, min(int(top), _MAX_TOP_STATS))
    methods: Counter[str] = Counter()
    status_classes: Counter[str] = Counter()
    resource_types: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    mime_types: Counter[str] = Counter()
    pending = 0
    for row in items:
        methods[str(row.get("method") or "").upper() or "?"] += 1
        status = row.get("status")
        if isinstance(status, int):
            status_classes[f"{status // 100}xx"] += 1
        else:
            status_classes["pending"] += 1
            pending += 1
        rtype = str(row.get("resourceType") or "").strip().lower()
        if rtype:
            resource_types[rtype] += 1
        host = ""
        try:
            host = urlsplit(str(row.get("url") or "")).hostname or ""
        except ValueError:
            host = ""
        if host:
            hosts[host] += 1
        mime = str(row.get("mimeType") or "").split(";", 1)[0].strip().lower()
        if mime:
            mime_types[mime] += 1

    def _ranked(counter: Counter[str]) -> list[tuple[str, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:top]

    return {
        "total": len(items),
        "dropped": dropped,
        "pending": pending,
        "methods": dict(sorted(methods.items(), key=lambda kv: (-kv[1], kv[0]))),
        "status_classes": dict(sorted(status_classes.items())),
        "resource_types": dict(
            sorted(resource_types.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
        "top_hosts": [{"host": h, "count": c} for h, c in _ranked(hosts)],
        "host_count": len(hosts),
        "top_mime_types": [
            {"mime_type": m, "count": c} for m, c in _ranked(mime_types)
        ],
        "mime_type_count": len(mime_types),
    }


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


def _spill_text(
    text: str,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
) -> tuple[str, Path | None, bool]:
    """Inline a prefix, spill the rest, or refuse when the capture cap is hit.

    CDP already delivered the whole payload. Writing it to the session artifact
    dir still fills the disk before retention runs: a single media response is
    enough. Returns ``(inline, spill_path_or_none, truncated)``.
    """
    payload = text.encode("utf-8", errors="replace")
    size = len(payload)
    if size > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=size,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    if size <= _MAX_INLINE_BODY:
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


def _spill_bytes(
    raw: bytes,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
) -> Path:
    """Write raw bytes to a session artifact, refusing over the capture cap.

    The bytes counterpart of ``_spill_text``: a binary response body cannot be
    represented as JSON text, so it always goes to disk. The cap is measured on
    the real bytes, not on a base64 expansion of them.
    """
    if len(raw) > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=len(raw),
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
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
    out.write_bytes(raw)
    written, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
    if over:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=written,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    return out


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
        # Per-request header maps for web.network.headers, kept out of the
        # `requests` rows so web.network.list/failed stay lean. Bounded in
        # lockstep with the request ring.
        self.headers: OrderedDict[str, JsonObject] = OrderedDict()
        # Per-request POST bodies for web.network.post_data, likewise kept off
        # the request rows and bounded in lockstep with the ring.
        self.post_data: OrderedDict[str, JsonObject] = OrderedDict()
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
        timeout = _bound_nav_timeout(timeout)

        with self._lock:
            if session_id in self._sessions:
                raise WebError("invalid_state", "web session already open", session_id=session_id)
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
                response = None
                if url:
                    response = page.goto(
                        url, timeout=timeout * 1000.0, wait_until="domcontentloaded"
                    )
                # Summarised here rather than by a second call: between the two,
                # a browser exists that no session yet refers to, and a failure
                # in that window would leave it with nothing able to close it.
                summary = {
                    "opened": True,
                    "url": _bounded_metadata(page.url, _MAX_URL_BYTES)[0],
                    "title": _safe_title(page),
                    "headless": headless,
                }
                status = _response_status(response)
                if status is not None:
                    summary["status"] = status
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
        if not hasattr(handle, "headers"):
            # Real sessions declare this buffer; a bare test handle may not.
            handle.headers = OrderedDict()
        if not hasattr(handle, "post_data"):
            handle.post_data = OrderedDict()
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
            entry: JsonObject = {
                "requestId": params.get("requestId"),
                "url": url,
                "method": method,
                "resourceType": resource_type,
                "status": None,
                "mimeType": None,
            }
            if url_truncated or method_truncated or type_truncated:
                entry["metadata_truncated"] = True
            req_headers, headers_truncated = _bounded_header_map(req.get("headers"))
            has_post = bool(req.get("hasPostData"))
            post_raw = req.get("postData")
            post_body = ""
            post_truncated = False
            if isinstance(post_raw, str) and post_raw:
                post_body, post_truncated = _bounded_metadata(
                    post_raw, _MAX_POST_BODY_BYTES
                )
            content_type = None
            for name, val in req_headers.items():
                if name.lower() == "content-type":
                    content_type = val
                    break
            rid = str(params.get("requestId"))
            with handle.lock:
                handle.requests[rid] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    handle.requests.popitem(last=False)
                    handle.requests_dropped += 1
                handle.headers[rid] = {
                    "request": req_headers,
                    "response": {},
                    "truncated": headers_truncated,
                }
                while len(handle.headers) > _MAX_REQUESTS:
                    handle.headers.popitem(last=False)
                if has_post or post_body:
                    handle.post_data[rid] = {
                        "has_post_data": has_post,
                        "data": post_body,
                        "size": len(post_body),
                        "truncated": post_truncated,
                        "content_type": content_type,
                    }
                    while len(handle.post_data) > _MAX_REQUESTS:
                        handle.post_data.popitem(last=False)

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            mime_type, mime_truncated = _bounded_metadata(
                resp.get("mimeType"), _MAX_METADATA_BYTES
            )
            resp_headers, headers_truncated = _bounded_header_map(resp.get("headers"))
            rid = str(params.get("requestId"))
            with handle.lock:
                entry = handle.requests.get(rid)
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = mime_type
                    if mime_truncated:
                        entry["metadata_truncated"] = True
                slot = handle.headers.get(rid)
                if slot is not None:
                    slot["response"] = resp_headers
                    if headers_truncated:
                        slot["truncated"] = True

        def on_failed(params: JsonObject) -> None:
            error_text, error_truncated = _bounded_metadata(
                params.get("errorText"), _MAX_METADATA_BYTES
            )
            blocked, blocked_truncated = _bounded_metadata(
                params.get("blockedReason"), _MAX_METADATA_BYTES
            )
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    entry["failed"] = True
                    entry["error_text"] = error_text
                    entry["canceled"] = bool(params.get("canceled"))
                    if blocked:
                        entry["blocked_reason"] = blocked
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
            if url_truncated or language_truncated:
                entry["metadata_truncated"] = True
            with handle.lock:
                handle.scripts[str(params.get("scriptId"))] = entry
                while len(handle.scripts) > _MAX_SCRIPTS:
                    handle.scripts.popitem(last=False)
                    handle.scripts_dropped += 1

        def on_console(params: JsonObject) -> None:
            text, text_truncated = _clip_console_text(params)
            entry: JsonObject = {
                "type": str(params.get("type") or "log"),
                "text": text,
            }
            if text_truncated:
                entry["text_truncated"] = True
            with handle.lock:
                if (
                    handle.console.maxlen is not None
                    and len(handle.console) == handle.console.maxlen
                ):
                    handle.console_dropped += 1
                handle.console.append(entry)

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.loadingFailed", on_failed)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        handle = self._get(session_id)
        timeout = _bound_nav_timeout(timeout)

        def work() -> JsonObject:
            try:
                response = handle.page.goto(
                    url, timeout=timeout * 1000.0, wait_until="domcontentloaded"
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"navigation failed: {exc}", url=url) from exc
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }
            status = _response_status(response)
            if status is not None:
                result["status"] = status
            return result

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

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        return {
            "requests": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
        }

    def network_stats(self, session_id: str, *, top: int = 10) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        return summarize_requests(items, dropped=dropped, top=top)

    def network_failed(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            failed = [row for row in handle.requests.values() if row.get("failed")]
            dropped = handle.requests_dropped
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = failed[start : start + cap]
        return {
            "requests": window,
            "count": len(window),
            "total": len(failed),
            "offset": start,
            "has_more": start + len(window) < len(failed),
            "dropped": dropped,
        }

    def network_headers(self, session_id: str, request_id: str) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.requests.get(request_id)
            slot = getattr(handle, "headers", {}).get(request_id)
        if entry is None:
            raise WebError("not_found", "unknown request id", request_id=request_id)
        request_headers = dict((slot or {}).get("request") or {})
        response_headers = dict((slot or {}).get("response") or {})
        return {
            "request_id": request_id,
            "url": entry.get("url"),
            "method": entry.get("method"),
            "status": entry.get("status"),
            "request_headers": request_headers,
            "request_header_count": len(request_headers),
            "response_headers": response_headers,
            "response_header_count": len(response_headers),
            "headers_truncated": bool((slot or {}).get("truncated")),
        }

    def network_post_data(self, session_id: str, request_id: str) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.requests.get(request_id)
            slot = getattr(handle, "post_data", {}).get(request_id)
        if entry is None:
            raise WebError("not_found", "unknown request id", request_id=request_id)
        slot = slot or {}
        return {
            "request_id": request_id,
            "url": entry.get("url"),
            "method": entry.get("method"),
            "has_post_data": bool(slot.get("has_post_data")),
            "content_type": slot.get("content_type"),
            "data": slot.get("data", ""),
            "size": int(slot.get("size", 0)),
            "truncated": bool(slot.get("truncated")),
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
            # CDP has no body for some requests -- a redirect, or a body already
            # evicted from its cache. Keep the documented shape (empty body, not
            # base64, not truncated) with body_error explaining why, so a caller
            # reading result["body"] does not hit a missing key on this path.
            return {
                **entry,
                "body": "",
                "base64_encoded": False,
                "body_truncated": False,
                "body_error": str(exc),
            }
        if not isinstance(body, str):
            body = str(body)
        if base64_encoded:
            # CDP returns base64 for a binary body (image, font, wasm...). The
            # earlier code fed that base64 *string* to the text spill, so a large
            # binary body wrote base64 into the .bin artifact -- not the bytes a
            # caller opening body_path expects -- and measured the cap against
            # the ~33% larger base64. Decode once, cap on the real size, and
            # spill the actual bytes; a binary body is never inlined as text.
            try:
                raw = base64.b64decode(body, validate=False)
            except (ValueError, binascii.Error) as exc:
                return {**entry, "body_error": f"response body was not valid base64: {exc}"}
            spill_path = _spill_bytes(
                raw,
                artifact_dir=artifact_dir,
                filename=f"body-{uuid4().hex}.bin",
                kind="response body",
            )
            result = dict(entry)
            result["body"] = ""
            result["body_truncated"] = False
            result["body_path"] = str(spill_path)
            result["body_bytes"] = len(raw)
            result["base64_encoded"] = True
            return result
        inline, spill, cut = _spill_text(
            body,
            artifact_dir=artifact_dir,
            filename=f"body-{uuid4().hex}.bin",
            kind="response body",
        )
        result = dict(entry)
        result["body"] = inline
        result["body_truncated"] = cut
        if spill is not None:
            result["body_path"] = str(spill)
        result["base64_encoded"] = False
        return result

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        # Newest tail, and total for parity with every other paginated reader:
        # has_more alone says "there is more", total says how much is buffered,
        # so a caller can size its next limit instead of guessing. No offset is
        # needed here -- the max limit equals the ring capacity, so one call can
        # return the whole buffer.
        page = held[-capped:]
        return {
            "console": page,
            "count": len(page),
            "total": len(held),
            "has_more": len(held) > capped,
            "dropped": dropped,
        }

    def scripts(
        self,
        session_id: str,
        *,
        wasm_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            values = list(handle.scripts.values())
        if wasm_only:
            values = [s for s in values if str(s.get("language")).lower() == "webassembly"]
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

    def dom_snapshot(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

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
                          truncated: text.length > cap
                        };
                    }""",
                    _MAX_INLINE_BODY,
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            if not isinstance(clipped, dict):
                raise WebError("backend_error", "dom snapshot returned no document")
            html = clipped.get("html")
            text = html if isinstance(html, str) else ""
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "html": text[:_MAX_INLINE_BODY],
                "truncated": bool(clipped.get("truncated")) or len(text) > _MAX_INLINE_BODY,
            }

        return self._runner(handle).call(work)

    def storage(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            cfg = {
                "maxKeys": _MAX_STORAGE_KEYS,
                "maxValueChars": _MAX_STORAGE_VALUE_CHARS,
            }
            try:
                raw = handle.page.evaluate(_STORAGE_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"storage read failed: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "storage read returned no data")
            local_entries, local_total, local_err = _fold_storage(raw.get("local"))
            session_entries, session_total, session_err = _fold_storage(raw.get("session"))
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "origin": _bounded_metadata(raw.get("origin"), _MAX_URL_BYTES)[0],
                "local_storage": local_entries,
                "local_storage_count": len(local_entries),
                "local_storage_truncated": local_total > len(local_entries),
                "session_storage": session_entries,
                "session_storage_count": len(session_entries),
                "session_storage_truncated": session_total > len(session_entries),
            }
            if local_err:
                result["local_storage_error"] = _bounded_metadata(
                    local_err, _MAX_METADATA_BYTES
                )[0]
            if session_err:
                result["session_storage_error"] = _bounded_metadata(
                    session_err, _MAX_METADATA_BYTES
                )[0]
            return result

        return self._runner(handle).call(work)

    def cookies(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                raw = handle.context.cookies()
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cookie read failed: {exc}") from exc
            rows = raw if isinstance(raw, list) else []
            cookies: list[JsonObject] = []
            truncated = False
            for item in rows:
                if len(cookies) >= _MAX_COOKIES:
                    truncated = True
                    break
                if not isinstance(item, dict):
                    continue
                value = item.get("value")
                value = value if isinstance(value, str) else ("" if value is None else str(value))
                value_cut = len(value) > _MAX_COOKIE_VALUE_CHARS
                if value_cut:
                    value = value[:_MAX_COOKIE_VALUE_CHARS]
                expires = item.get("expires")
                expires_num = (
                    float(expires)
                    if isinstance(expires, (int, float)) and expires >= 0
                    else None
                )
                same_site = item.get("sameSite")
                cookies.append(
                    {
                        "name": _bounded_metadata(item.get("name"), _MAX_METADATA_BYTES)[0],
                        "value": value,
                        "value_truncated": value_cut,
                        "domain": _bounded_metadata(item.get("domain"), _MAX_METADATA_BYTES)[0],
                        "path": _bounded_metadata(item.get("path"), _MAX_METADATA_BYTES)[0],
                        "http_only": bool(item.get("httpOnly")),
                        "secure": bool(item.get("secure")),
                        "same_site": same_site if isinstance(same_site, str) else None,
                        "expires": expires_num,
                        "session": expires_num is None,
                    }
                )
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "cookies": cookies,
                "count": len(cookies),
                "total": len(rows),
                "truncated": truncated,
            }

        return self._runner(handle).call(work)

    def forms(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            cfg = {
                "maxForms": _MAX_FORMS,
                "maxFields": _MAX_FORM_FIELDS,
                "maxValueChars": _MAX_FIELD_VALUE_CHARS,
            }
            try:
                raw = handle.page.evaluate(_FORMS_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"form read failed: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "form read returned no data")
            page_url = _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0]
            try:
                page_host = urlsplit(page_url).netloc
            except ValueError:
                page_host = ""
            rows = raw.get("forms") or []
            forms = [_fold_form(item, page_host) for item in rows]
            total = raw.get("total")
            total_int = int(total) if isinstance(total, int) else len(forms)
            return {
                "url": page_url,
                "forms": forms,
                "count": len(forms),
                "total": total_int,
                "truncated": total_int > len(forms),
            }

        return self._runner(handle).call(work)

    def performance(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            cfg = {"maxResources": _MAX_PERF_RESOURCES, "maxUrl": _MAX_URL_BYTES}
            try:
                raw = handle.page.evaluate(_PERF_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError(
                    "backend_error", f"performance read failed: {exc}"
                ) from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "performance read returned no data")
            page_url = _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0]
            nav_raw = raw.get("navigation")
            nav: JsonObject | None = None
            if isinstance(nav_raw, dict):
                nav = {
                    "type": _bounded_metadata(nav_raw.get("type"), _MAX_METADATA_BYTES)[0],
                    "redirect_count": nav_raw.get("redirect_count"),
                    "dns_ms": nav_raw.get("dns_ms"),
                    "connect_ms": nav_raw.get("connect_ms"),
                    "tls_ms": nav_raw.get("tls_ms"),
                    "ttfb_ms": nav_raw.get("ttfb_ms"),
                    "response_ms": nav_raw.get("response_ms"),
                    "dom_interactive_ms": nav_raw.get("dom_interactive_ms"),
                    "dom_content_loaded_ms": nav_raw.get("dom_content_loaded_ms"),
                    "load_ms": nav_raw.get("load_ms"),
                    "transfer_size": nav_raw.get("transfer_size"),
                    "encoded_body_size": nav_raw.get("encoded_body_size"),
                    "decoded_body_size": nav_raw.get("decoded_body_size"),
                }
            resources: list[JsonObject] = []
            for item in raw.get("resources") or []:
                if not isinstance(item, dict):
                    continue
                resources.append(
                    {
                        "url": _bounded_metadata(item.get("url"), _MAX_URL_BYTES)[0],
                        "initiator_type": _bounded_metadata(
                            item.get("initiator_type"), _MAX_METADATA_BYTES
                        )[0],
                        "duration_ms": item.get("duration_ms"),
                        "transfer_size": item.get("transfer_size"),
                    }
                )
            total = raw.get("resource_total")
            total_int = int(total) if isinstance(total, int) else len(resources)
            return {
                "url": page_url,
                "navigation": nav,
                "resources": resources,
                "resource_count": len(resources),
                "resource_total": total_int,
                "truncated": total_int > len(resources),
            }

        return self._runner(handle).call(work)

    def meta(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            cfg = {
                "maxMetas": _MAX_META_TAGS,
                "maxLinks": _MAX_META_LINKS,
                "maxContent": _MAX_META_CONTENT_CHARS,
            }
            try:
                raw = handle.page.evaluate(_META_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"meta read failed: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "meta read returned no data")
            page_url = _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0]
            metas = [_fold_meta_tag(item) for item in raw.get("metas") or []]
            links = [_fold_meta_link(item) for item in raw.get("links") or []]
            meta_total = raw.get("meta_total")
            meta_total_int = int(meta_total) if isinstance(meta_total, int) else len(metas)
            link_total = raw.get("link_total")
            link_total_int = int(link_total) if isinstance(link_total, int) else len(links)
            title = _bounded_metadata(raw.get("title"), _MAX_METADATA_BYTES)[0]
            csp = raw.get("csp")
            csp_out = (
                _bounded_metadata(csp, _MAX_META_CONTENT_CHARS)[0]
                if isinstance(csp, str)
                else None
            )
            return {
                "url": page_url,
                "title": title,
                "charset": _bounded_metadata(raw.get("charset"), _MAX_METADATA_BYTES)[0],
                "lang": _bounded_metadata(raw.get("lang"), _MAX_METADATA_BYTES)[0],
                "base": _bounded_metadata(raw.get("base"), _MAX_URL_BYTES)[0],
                "metas": metas,
                "meta_count": len(metas),
                "meta_total": meta_total_int,
                "metas_truncated": meta_total_int > len(metas),
                "links": links,
                "link_count": len(links),
                "link_total": link_total_int,
                "links_truncated": link_total_int > len(links),
                "refresh": _parse_meta_refresh(raw.get("refresh")),
                "csp": csp_out,
            }

        return self._runner(handle).call(work)

    def links(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            cfg = {
                "maxAnchors": _MAX_ANCHORS,
                "maxResources": _MAX_SUB_RESOURCES,
                "maxText": 200,
            }
            try:
                raw = handle.page.evaluate(_LINKS_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"link read failed: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "link read returned no data")
            page_url = _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0]
            return _fold_links(raw, page_url)

        return self._runner(handle).call(work)

    def frames(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                page_frames = list(handle.page.frames)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"frame read failed: {exc}") from exc
            rows: list[JsonObject] = []
            for frame in page_frames:
                parent = getattr(frame, "parent_frame", None)
                depth = 0
                walk = parent
                while walk is not None and depth < 64:
                    depth += 1
                    walk = getattr(walk, "parent_frame", None)
                parent_url = (getattr(parent, "url", "") or "") if parent is not None else None
                rows.append(
                    {
                        "url": getattr(frame, "url", "") or "",
                        "name": getattr(frame, "name", "") or "",
                        "is_main": parent is None,
                        "parent_url": parent_url,
                        "depth": depth,
                    }
                )
            main_url = _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0]
            return _fold_frames(rows, main_url)

        return self._runner(handle).call(work)

    def dom_query(self, session_id: str, selector: str, *, limit: int = 50) -> JsonObject:
        handle = self._get(session_id)
        sel = str(selector or "").strip()
        if not sel:
            raise WebError("invalid_params", "selector is required")

        def work() -> JsonObject:
            cfg = {
                "selector": sel,
                "maxElements": max(1, min(int(limit), _MAX_DOM_QUERY)),
                "maxAttrs": _MAX_DOM_ATTRS,
                "maxAttrChars": _MAX_DOM_ATTR_CHARS,
                "maxText": _MAX_DOM_TEXT,
                "maxHtml": _MAX_DOM_HTML,
            }
            try:
                raw = handle.page.evaluate(_DOM_QUERY_SCRIPT, cfg)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom query failed: {exc}") from exc
            if isinstance(raw, dict) and raw.get("error"):
                raise WebError("invalid_params", f"invalid selector: {raw['error']}")
            return _fold_dom_query(raw, sel)

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
        handle = self._get(session_id)
        with handle.lock:
            entries = [
                har_entry(
                    method=e.get("method"),
                    url=e.get("url"),
                    status=e.get("status"),
                    mime_type=e.get("mimeType") or "",
                    resource_type=e.get("resourceType"),
                )
                for e in handle.requests.values()
            ]
        serialized = serialize_har(entries, max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES)
        if serialized.size > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise WebError(
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


def _response_status(response: Any) -> int | None:
    """HTTP status of a navigation, or None when it produced no response.

    page.goto only raises for transport failures (DNS, refused, timeout); a
    4xx/5xx main document resolves normally, so without surfacing this a
    navigation onto an error page reports the same success as a real hit. goto
    also returns None for about:blank and same-document navigations, which is
    an absent status rather than a failure.
    """
    if response is None:
        return None
    try:
        status = response.status
    except Exception:  # noqa: BLE001
        return None
    return status if isinstance(status, int) else None


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
