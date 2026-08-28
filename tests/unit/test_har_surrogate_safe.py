"""A captured URL with a lone surrogate must not fail the whole HAR export.

mitmproxy decodes a request's non-UTF-8 path bytes with ``surrogateescape`` and
the proxy recorder stores ``pretty_url`` verbatim, so a hostile client can put a
lone surrogate (e.g. ``\\udc80`` from a raw ``0x80`` path byte) into a flow
summary. ``serialize_har`` encodes with ``ensure_ascii=False`` and the exporters
``write_text(..., encoding="utf-8")``; a lone surrogate makes both raise
UnicodeEncodeError, turning one bad flow into a failed export of every flow.
``har_entry`` now scrubs its string fields, so the HAR stays valid UTF-8.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.common.har import build_har, har_entry, serialize_har
from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
from headless_re_mcp.backends.web.client import WebBackend

# One code point mitmproxy's surrogateescape produces from a raw 0x80 path byte.
_SURROGATE = "\udc80"


def test_serialize_har_survives_a_lone_surrogate_in_the_url() -> None:
    """The shared serializer must not raise, and its bytes must decode as UTF-8."""
    entry = har_entry(
        method="GET",
        url=f"http://x/{_SURROGATE}/1",
        status=200,
        mime_type="text/plain",
    )
    result = serialize_har([entry], max_bytes=1_000_000)

    # The returned text encodes cleanly (this is what the exporters write out).
    reloaded = json.loads(result.text.encode("utf-8").decode("utf-8"))
    got = reloaded["log"]["entries"][0]["request"]["url"]
    assert _SURROGATE not in got
    assert got.startswith("http://x/")


def test_har_entry_scrubs_surrogates_from_every_string_field() -> None:
    entry = har_entry(
        method=f"GE{_SURROGATE}T",
        url=f"http://x/{_SURROGATE}",
        status=200,
        mime_type=f"text/{_SURROGATE}plain",
        resource_type=f"XH{_SURROGATE}R",
    )
    # Encoding the whole entry must not raise, and no field keeps a surrogate.
    blob = json.dumps(build_har([entry]), ensure_ascii=False).encode("utf-8")
    assert blob  # did not raise
    assert _SURROGATE not in entry["request"]["method"]
    assert _SURROGATE not in entry["request"]["url"]
    assert _SURROGATE not in entry["response"]["content"]["mimeType"]
    assert _SURROGATE not in entry["_resourceType"]


def test_legitimate_non_ascii_is_preserved() -> None:
    """The scrub must only drop the unencodable code points, not real characters."""
    entry = har_entry(
        method="GET",
        url="https://example.com/搜索?q=café",
        status=200,
        mime_type="application/json",
    )
    assert entry["request"]["url"] == "https://example.com/搜索?q=café"
    # queryString is parsed from the (now clean) URL and stays intact too.
    params = [(p["name"], p["value"]) for p in entry["request"]["queryString"]]
    assert params == [("q", "café")]


class _WebHandle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests = {
            "0": {
                "requestId": "0",
                "url": f"https://example.com/{_SURROGATE}",
                "method": "GET",
                "resourceType": "Document",
                "status": 200,
                "mimeType": "text/html",
            }
        }


def test_web_har_export_writes_a_valid_file_despite_a_surrogate_url(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle())
    out = tmp_path / "capture.har"

    payload = backend.har_export("s", out)

    assert payload["entry_count"] == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert _SURROGATE not in doc["log"]["entries"][0]["request"]["url"]


def test_proxy_export_har_writes_a_valid_file_despite_a_surrogate_url(
    tmp_path: Path,
) -> None:
    recorder = _FlowRecorder()
    request = SimpleNamespace(
        method="GET",
        pretty_url=f"http://x/{_SURROGATE}/1",
        host="x",
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain"},
        raw_content=None,
    )
    recorder.response(SimpleNamespace(id="0", request=request, response=response))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    out = tmp_path / "capture.har"

    payload = backend.export_har("s", out)

    assert payload["entry_count"] == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert _SURROGATE not in doc["log"]["entries"][0]["request"]["url"]
