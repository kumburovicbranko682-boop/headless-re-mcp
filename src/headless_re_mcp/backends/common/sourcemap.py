"""Pure-stdlib reader for a JavaScript Source Map v3 document.

js.deobfuscate / js.beautify / js.unpack_bundle drive the webcrack (Node) CLI,
so the JS static surface is capability_unavailable on a host without it. But a
source map -- the single most valuable Web-RE artifact after the bundle itself,
because it names the original file tree and often embeds the original source --
is plain JSON with a well-defined schema, and reads with the stdlib alone.
Nothing here could open one: an analyst who found an ``app.js.map`` (or followed
a ``sourceMappingURL``) had no offline way to ask "which original files does this
reveal, and does it embed their source" without a browser devtools session.
summarize_sourcemap answers that exactly -- no Node, no CLI.

It is a summary, not an extractor: it enumerates the sources, flags which embed
their original content and how long each is, and reports the mapping shape
(generated line and segment counts), but it does not return the recovered source
bodies. The VLQ ``mappings`` string is measured, never decoded, which keeps the
reader exact and cheap. Both the flat map and the v3 index map (``sections``)
are handled; every list is bounded.
"""

from __future__ import annotations

import re
from typing import Any

JsonObject = dict[str, Any]

# A path/name field is bounded so one pathological entry cannot inflate a reply;
# real source paths sit far below this. content_length is a number, never text,
# so it is reported unbounded.
_MAX_FIELD = 4096
# Big apps map thousands of files; the true count is always reported as
# sources_total, but only this many names are listed and detailed.
_MAX_LISTED = 4096

_SEGMENT = re.compile(r"[^;,]+")


class SourceMapParseError(ValueError):
    """A document that does not decode as a Source Map v3.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name.
    """


def _clip(value: object) -> str:
    text = str(value if value is not None else "")
    return text[:_MAX_FIELD] if len(text) > _MAX_FIELD else text


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clip(item) for item in value]


def _mapping_shape(mappings: object) -> tuple[int, int, int]:
    """(mappings_size, generated_lines, segment_count) for a VLQ string.

    The string is measured, not decoded: generated lines are separated by ';'
    and segments within a line by ',', so counting is exact and linear without
    ever touching the base64/VLQ payload.
    """
    if not isinstance(mappings, str) or not mappings:
        return 0, 0, 0
    generated_lines = mappings.count(";") + 1
    segment_count = sum(1 for _ in _SEGMENT.finditer(mappings))
    return len(mappings), generated_lines, segment_count


def _flat_stats(document: JsonObject) -> JsonObject:
    """Stats for one flat map: its own sources, embedded content, mapping shape.

    Used directly for a flat source map and once per section of an index map,
    so the index-map path can aggregate the same numbers across its sections.
    """
    sources = _str_list(document.get("sources"))
    content = document.get("sourcesContent")
    content = content if isinstance(content, list) else []
    embedded = 0
    detail: list[JsonObject] = []
    for index, source in enumerate(sources):
        has_content = index < len(content) and isinstance(content[index], str)
        if has_content:
            embedded += 1
        if len(detail) < _MAX_LISTED:
            detail.append(
                {
                    "source": source,
                    "has_content": has_content,
                    "content_length": len(content[index]) if has_content else None,
                }
            )
    names = document.get("names")
    names_total = len(names) if isinstance(names, list) else 0
    mappings_size, generated_lines, segment_count = _mapping_shape(document.get("mappings"))
    ignore = document.get("x_google_ignoreList")
    ignore_list = [int(i) for i in ignore if isinstance(i, int)] if isinstance(ignore, list) else []
    return {
        "sources": sources,
        "sources_total": len(sources),
        "sources_content_embedded": embedded,
        "sources_detail": detail,
        "names_total": names_total,
        "mappings_size": mappings_size,
        "generated_lines": generated_lines,
        "segment_count": segment_count,
        "ignore_list": ignore_list[:_MAX_LISTED],
    }


def summarize_sourcemap(document: Any) -> JsonObject:
    """Bounded, exact summary of a parsed Source Map v3 document.

    Raises SourceMapParseError when the document is not a source map (not an
    object, or lacking every one of version / mappings / sections); the caller
    turns that into the transport's invalid-input envelope. A flat map reports
    its own stats; an index map reports section_count and the aggregate of its
    sections' stats. Nothing here decodes the VLQ payload or returns source
    bodies -- it enumerates and measures.
    """
    if not isinstance(document, dict):
        raise SourceMapParseError("not a Source Map: top level is not an object")
    has_marker = any(key in document for key in ("version", "mappings", "sections"))
    if not has_marker:
        raise SourceMapParseError("not a Source Map v3: no version, mappings or sections")

    version = document.get("version")
    version = version if isinstance(version, int) else None
    base: JsonObject = {
        "version": version,
        "file": _clip(document.get("file")),
        "source_root": _clip(document.get("sourceRoot")),
    }

    sections = document.get("sections")
    if isinstance(sections, list) and "mappings" not in document:
        sources: list[str] = []
        detail: list[JsonObject] = []
        embedded = 0
        names_total = 0
        mappings_size = 0
        generated_lines = 0
        segment_count = 0
        for section in sections:
            inner = section.get("map") if isinstance(section, dict) else None
            if not isinstance(inner, dict):
                continue
            stats = _flat_stats(inner)
            embedded += stats["sources_content_embedded"]
            names_total += stats["names_total"]
            mappings_size += stats["mappings_size"]
            generated_lines += stats["generated_lines"]
            segment_count += stats["segment_count"]
            for src in stats["sources"]:
                if len(sources) < _MAX_LISTED:
                    sources.append(src)
            for item in stats["sources_detail"]:
                if len(detail) < _MAX_LISTED:
                    detail.append(item)
        base.update(
            {
                "is_index_map": True,
                "section_count": len(sections),
                "sources": sources,
                "sources_total": len(sources),
                "sources_content_embedded": embedded,
                "sources_detail": detail,
                "names_total": names_total,
                "mappings_size": mappings_size,
                "generated_lines": generated_lines,
                "segment_count": segment_count,
                "ignore_list": [],
            }
        )
        return base

    base["is_index_map"] = False
    base["section_count"] = 0
    base.update(_flat_stats(document))
    return base
