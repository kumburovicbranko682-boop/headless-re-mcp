"""Dependency-free Source Map v3 parsing for js.sourcemap.

A minified bundle usually ships a ``.map`` (referenced by a trailing
``//# sourceMappingURL=`` comment, inline as a ``data:`` URI, or as an adjacent
file). The map's ``sourcesContent`` holds the *original* pre-minification source
text -- real identifiers, structure, comments -- which is a far better
"unminify" than reformatting the minified code. This module locates and parses
the map (flat maps and index maps with ``sections``) and flattens it to a list
of (source name, original content) pairs, with no third-party dependency so it
stays available whenever the file is readable.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import unquote

JsonObject = dict[str, Any]

# Matches the trailing pragma in both // and /* ... */ comment forms, with the
# modern '#' and the legacy '@' spellings. The URL runs to the first whitespace
# or quote so a data: URI (which has no spaces) is captured whole.
_SOURCEMAP_URL_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s'\"]+)")
_DATA_URI_RE = re.compile(r"^data:([^,]*),(.*)$", re.DOTALL)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


class SourceMapError(Exception):
    """Raised for a malformed map or an unfetchable reference.

    ``code`` is one of the backend's error codes so the caller can map it onto
    the JsReError envelope without a translation table.
    """

    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def find_source_mapping_url(source: str) -> str | None:
    """Return the last ``sourceMappingURL`` value in a JS file, or None.

    Last, not first: a bundle can carry commented-out or vendored pragmas
    earlier in the file, and the effective one is the final pragma the engine
    would honour.
    """
    matches = list(_SOURCEMAP_URL_RE.finditer(source))
    if not matches:
        return None
    return matches[-1].group(1).strip()


def is_probably_map_json(text: str) -> bool:
    """Whether ``text`` looks like a map document rather than JS source."""
    return text.lstrip()[:1] == "{"


def is_remote_url(url: str) -> bool:
    """Whether a sourceMappingURL points off-host (needs fetching, not local)."""
    return bool(_SCHEME_RE.match(url)) or url.startswith("//")


def decode_data_uri(uri: str, *, max_bytes: int) -> str:
    """Decode a ``data:`` sourceMappingURL to its JSON text.

    Handles the base64 form (``data:application/json;base64,....``) and the
    url-encoded text form (``data:application/json,%7B...``); the payload is
    bounded so a hostile inline map cannot balloon memory.
    """
    match = _DATA_URI_RE.match(uri)
    if match is None:
        raise SourceMapError("invalid_params", "malformed data: URI in sourceMappingURL")
    meta, payload = match.group(1), match.group(2)
    if ";base64" in meta.lower():
        try:
            raw = base64.b64decode(payload, validate=False)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise SourceMapError(
                "backend_error", f"inline source map base64 is invalid: {exc}"
            ) from exc
        return raw[:max_bytes].decode("utf-8", errors="replace")
    return unquote(payload)[:max_bytes]


def parse_source_map(text: str) -> JsonObject:
    """Parse map JSON into a dict, or raise SourceMapError."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SourceMapError("backend_error", f"source map is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SourceMapError("backend_error", "source map JSON must be an object")
    return data


def _join_root(root: str, name: str) -> str:
    """Apply sourceRoot to a source name the way the v3 spec prepends it."""
    if not root or _SCHEME_RE.match(name) or name.startswith("/"):
        return name
    return root.rstrip("/") + "/" + name.lstrip("/")


def _collect(
    sources_raw: Any, contents_raw: Any, root: str
) -> tuple[list[str], list[str | None]]:
    sources: list[str] = []
    contents: list[str | None] = []
    if not isinstance(sources_raw, list):
        return sources, contents
    content_list = contents_raw if isinstance(contents_raw, list) else []
    for index, name in enumerate(sources_raw):
        sources.append(_join_root(root, str(name)))
        value = content_list[index] if index < len(content_list) else None
        contents.append(value if isinstance(value, str) else None)
    return sources, contents


def flatten_sources(data: JsonObject) -> tuple[list[str], list[str | None], JsonObject]:
    """Flatten a flat or index (``sections``) map to parallel source/content lists.

    Returns ``(sources, contents, meta)`` where ``contents[i]`` is the original
    text for ``sources[i]`` or None when the map did not embed it. ``meta`` keeps
    the top-level version/file/sourceRoot and an index_map flag.
    """
    meta: JsonObject = {
        "version": data.get("version"),
        "file": data.get("file") if isinstance(data.get("file"), str) else None,
        "source_root": data.get("sourceRoot") if isinstance(data.get("sourceRoot"), str) else "",
    }
    sections = data.get("sections")
    if isinstance(sections, list):
        meta["index_map"] = True
        sources: list[str] = []
        contents: list[str | None] = []
        for section in sections:
            if not isinstance(section, dict):
                continue
            inner = section.get("map")
            if not isinstance(inner, dict):
                continue
            inner_root = inner.get("sourceRoot")
            root = inner_root if isinstance(inner_root, str) else ""
            sec_sources, sec_contents = _collect(
                inner.get("sources"), inner.get("sourcesContent"), root
            )
            sources.extend(sec_sources)
            contents.extend(sec_contents)
        return sources, contents, meta
    meta["index_map"] = False
    root_value = meta["source_root"]
    root = root_value if isinstance(root_value, str) else ""
    sources, contents = _collect(data.get("sources"), data.get("sourcesContent"), root)
    return sources, contents, meta
