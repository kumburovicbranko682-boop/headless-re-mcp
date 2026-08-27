"""Web capture pages must fit the transport budget by their encoded size.

web.network.list, web.console, and web.scripts window their captures by row
count, but each row's size is a variable -- a request/script url is bounded at
16 KiB and a console line at 8 KiB -- so a full page can still encode past the
262144-byte result budget and be discarded whole (rows, counts, and pagination
cursors) for a ~16 KiB summary. Each method now trims its window with
fit_json_list before has_more is computed. These tests drive real oversized
captures through the real budget and check the page is trimmed below the
requested limit, the encoded reply fits, and has_more still says there is more.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from threading import Lock
from typing import Any

from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
from headless_re_mcp.backends.web.client import WebBackend


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class _FakeHandle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.requests_dropped = 0
        self.console: list[dict[str, Any]] = []
        self.console_dropped = 0
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts_dropped = 0


def _backend_with(handle: _FakeHandle, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


def test_network_list_page_is_trimmed_to_the_encoded_budget(monkeypatch: Any) -> None:
    # 300 requests, each url ~16 KiB (the per-entry cap): a 100-row window is
    # ~1.6 MB, far past the budget, so the row limit never bites -- the size
    # does.
    handle = _FakeHandle()
    long_url = "https://example.test/" + "u" * 16000
    for index in range(300):
        handle.requests[str(index)] = {
            "requestId": str(index),
            "url": f"{long_url}/{index}",
            "method": "GET",
            "resourceType": "Script",
            "status": 200,
            "mimeType": "text/javascript",
        }
    backend = _backend_with(handle, monkeypatch)

    payload = backend.network_list("s", offset=0, limit=100)

    assert 0 < payload["count"] < 100
    assert len(payload["requests"]) == payload["count"]
    assert payload["total"] == 300
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_network_list_small_page_is_returned_whole(monkeypatch: Any) -> None:
    handle = _FakeHandle()
    for index in range(10):
        handle.requests[str(index)] = {
            "requestId": str(index),
            "url": f"https://example.test/{index}",
            "method": "GET",
            "resourceType": "Script",
            "status": 200,
            "mimeType": "text/javascript",
        }
    backend = _backend_with(handle, monkeypatch)

    payload = backend.network_list("s", offset=0, limit=100)

    assert payload["count"] == 10
    assert payload["has_more"] is False
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_scripts_page_is_trimmed_to_the_encoded_budget(monkeypatch: Any) -> None:
    handle = _FakeHandle()
    long_url = "https://example.test/" + "u" * 16000
    for index in range(300):
        handle.scripts[str(index)] = {
            "scriptId": str(index),
            "url": f"{long_url}/{index}.js",
            "language": "JavaScript",
        }
    backend = _backend_with(handle, monkeypatch)

    payload = backend.scripts("s", offset=0, limit=100)

    assert 0 < payload["count"] < 100
    assert len(payload["scripts"]) == payload["count"]
    assert payload["total"] == 300
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_console_budget_cut_keeps_the_newest_and_sets_has_more(monkeypatch: Any) -> None:
    # 200 held messages, each text ~8 KiB, limit 2000: the row cap never fires
    # (held < capped), so the ring-eviction has_more stays False and the cut
    # must come from the size budget alone. console is a most-recent-N view, so
    # the trim must keep the newest rows and drop the oldest.
    handle = _FakeHandle()
    for index in range(200):
        handle.console.append({"type": "log", "text": f"{index:04d}:" + "x" * 8000})
    backend = _backend_with(handle, monkeypatch)

    payload = backend.console("s", limit=2000)

    assert 0 < payload["count"] < 200
    assert payload["has_more"] is True
    # Newest kept, oldest dropped: the last row is message 199 and the first
    # kept row is not message 0.
    assert payload["console"][-1]["text"].startswith("0199:")
    assert not payload["console"][0]["text"].startswith("0000:")
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES
