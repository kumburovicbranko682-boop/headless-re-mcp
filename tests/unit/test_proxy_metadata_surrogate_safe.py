"""Proxy flow metadata must never carry a lone surrogate to the web egress.

mitmproxy decodes a request line's non-UTF-8 bytes with ``surrogateescape``, so
``pretty_url`` / ``host`` / a header name or value can hold a lone surrogate
(e.g. ``\\udc80`` from a raw ``0x80``). The web console returns these tool
results through a Starlette ``JSONResponse`` that does
``json.dumps(..., ensure_ascii=False).encode("utf-8")``; a lone surrogate raises
UnicodeEncodeError while the response renders -- outside the route's try/except
-- so one hostile flow becomes an uncatchable 500. ``_bounded_metadata`` (and
the header-name path) now scrub such code points at the single chokepoint.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.proxy.client import (
    _bounded_headers,
    _bounded_metadata,
    _FlowRecorder,
)

# One code point mitmproxy's surrogateescape produces from a raw 0x80 byte.
_SURROGATE = "\udc80"


def _renders_as_json(payload: object) -> str:
    """Render exactly as the web console does: the real Starlette JSONResponse.

    Raises UnicodeEncodeError if any string still holds a lone surrogate.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(payload).render(payload).decode("utf-8")


def test_bounded_metadata_scrubs_a_surrogate_in_the_fits_case() -> None:
    text, cut = _bounded_metadata(f"http://x/{_SURROGATE}/1", 1024)
    assert _SURROGATE not in text
    assert cut is False
    # It must stay encodable, which is the whole point.
    assert text.encode("utf-8")


def test_bounded_metadata_leaves_a_valid_string_unchanged() -> None:
    """The scrub only drops unencodable code points; real text round-trips."""
    text, cut = _bounded_metadata("https://example.com/搜索?q=café", 1024)
    assert text == "https://example.com/搜索?q=café"
    assert cut is False


def test_bounded_headers_scrubs_surrogates_in_names_and_values() -> None:
    part = SimpleNamespace(
        headers=SimpleNamespace(
            items=lambda multi=False: [
                (f"X-Weird{_SURROGATE}", f"val{_SURROGATE}ue"),
            ]
        )
    )
    out, _truncated = _bounded_headers(part)
    for name, value in out.items():
        assert _SURROGATE not in name
        assert _SURROGATE not in value
    # The whole map must render through the web egress without raising.
    _renders_as_json(out)


def test_flow_summary_with_a_surrogate_url_renders_through_the_web_egress() -> None:
    """End-to-end: a recorded flow summary must survive JSONResponse rendering."""
    recorder = _FlowRecorder()
    request = SimpleNamespace(
        method="GET",
        pretty_url=f"http://x/{_SURROGATE}/1",
        host=f"x{_SURROGATE}",
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": f"text/{_SURROGATE}plain"},
        raw_content=None,
    )
    recorder.response(SimpleNamespace(id="0", request=request, response=response))

    summary = recorder.snapshot()
    rendered = _renders_as_json({"flows": summary})

    reloaded = json.loads(rendered)["flows"][0]
    assert _SURROGATE not in reloaded["url"]
    assert _SURROGATE not in reloaded["host"]
    assert _SURROGATE not in reloaded["content_type"]


def test_the_web_json_response_would_have_crashed_without_the_scrub() -> None:
    """Pin the egress behaviour the scrub exists to avoid: a raw surrogate 500s."""
    with pytest.raises(UnicodeEncodeError):
        _renders_as_json({"url": f"http://x/{_SURROGATE}"})
