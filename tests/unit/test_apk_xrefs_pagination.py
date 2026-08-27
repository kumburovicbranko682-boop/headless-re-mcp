"""apk.xrefs must page a method's callers, not just cap the first screenful.

The reader used to keep the first ``limit`` callers in graph-walk order and
raise ``has_more`` with no ``offset`` to reach the rest, so a method with more
callers than one page had every caller past the first unreachable. It is now a
paged reader like ``apk.classes``/``methods``/``strings``: the collected callers
are sorted, sliced by ``offset``/``limit``, and reported with ``total`` and
``scan_capped``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient


class _Call:
    def __init__(self, class_name: str, method: str) -> None:
        self.class_name = class_name
        self.name = method


class _Method:
    def __init__(self, name: str, calls: list[_Call]) -> None:
        self.name = name
        self._calls = calls

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _Call, int]]:
        return [(None, call, index) for index, call in enumerate(self._calls)]


class _Parsed:
    def __init__(self, methods: list[_Method]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


def _client(monkeypatch: Any, calls: list[_Call]) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _Parsed([_Method("decrypt", calls)]),
    )
    return client


def test_xrefs_pages_are_a_stable_sorted_partition(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Walking pages with offset reassembles the whole sorted list exactly once."""
    calls = [_Call(f"Lcom/example/C{index:02d};", "invoke") for index in range(7)]
    client = _client(monkeypatch, calls)
    expected = sorted((call.class_name, call.name) for call in calls)

    seen: list[tuple[str, str]] = []
    for start in (0, 3, 6):
        payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=start, limit=3)
        assert payload["offset"] == start
        assert payload["total"] == 7
        assert payload["count"] == len(payload["callers"])
        page = [(item["class"], item["method"]) for item in payload["callers"]]
        assert page == expected[start : start + 3]
        seen.extend(page)
    assert seen == expected

    tail = client.xrefs(tmp_path / "app.apk", "decrypt", offset=6, limit=3)
    assert tail["has_more"] is False
    head = client.xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=3)
    assert head["has_more"] is True


def test_xrefs_offset_past_the_end_is_an_empty_complete_page(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An offset beyond the collected list yields nothing and is not partial."""
    calls = [_Call(f"Lcom/example/C{index:02d};", "invoke") for index in range(4)]
    client = _client(monkeypatch, calls)

    payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=99, limit=10)
    assert payload["callers"] == []
    assert payload["count"] == 0
    assert payload["total"] == 4
    assert payload["offset"] == 99
    assert payload["has_more"] is False


def test_xrefs_reports_scan_capped_when_collection_stops_early(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """scan_capped and has_more answer different questions and must not be merged.

    Once the collection hits the scan cap, more callers may exist upstream even
    though this page holds every collected row (has_more False, scan_capped True).
    """
    calls = [_Call(f"Lcom/example/C{index:03d};", "invoke") for index in range(10)]
    client = _client(monkeypatch, calls)
    monkeypatch.setattr(apk_client, "_MAX_XREFS_COLLECT", 4)

    payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=100)
    assert payload["total"] == 4
    assert payload["count"] == 4
    assert payload["scan_capped"] is True
    assert payload["has_more"] is False
