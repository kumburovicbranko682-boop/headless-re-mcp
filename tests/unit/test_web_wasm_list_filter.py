"""web.wasm.list must actually filter to WebAssembly, not just re-list scripts.

``web.wasm.list`` and ``web.scripts`` are the same backend method: the service
routes both through ``WebBackend.scripts``, and the only thing that makes one a
WASM view and the other the full list is a single flag -- ``web.wasm.list`` hard
-codes ``wasm_only=True`` while ``web.scripts`` defaults it to ``False``. The
backend then keeps only rows whose ``language`` is ``"webassembly"``
(case-insensitively), and does so *before* it paginates, so ``total`` and
``has_more`` describe the WASM set, not the whole ring buffer.

``test_web_scripts_fields.py`` already covers the dropped-eviction disclosure for
both tools -- but each of its handles is homogeneous (all-JavaScript for
``web.scripts``, all-WebAssembly for ``web.wasm.list``), so the filter never has
to *discriminate*: with an all-WASM ring, ``[s for s in values if lang ==
"webassembly"]`` returns the same four rows whether the predicate runs or not.
Drop the ``wasm_only`` branch entirely, or filter the wrong field, and that suite
stays green while ``web.wasm.list`` quietly starts returning every JavaScript
script on the page -- exactly the noise a caller asking "what WASM is loaded?"
used the tool to avoid.

These tests pin the discrimination the homogeneous handles cannot: a mixed ring
of JavaScript and WebAssembly must yield only the WASM rows under ``wasm_only``
and every row without it; the WASM ``language`` match must be case-insensitive;
``total`` must be the filtered count (proving the filter precedes pagination, so a
window past the WASM count is empty rather than spilling JS); and the service must
hand the backend ``wasm_only=True`` for ``web.wasm.list`` and ``False`` for
``web.scripts`` -- the wiring half that decides which view a caller actually gets.
"""

from __future__ import annotations

from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.core.service import AnalysisService


class _MixedHandle:
    """A capture ring holding both JavaScript and WebAssembly, in mixed case.

    Insertion order interleaves the two languages so a correct filter has to
    pick WASM rows out from between JS ones, and the three WASM rows spell
    ``language`` three different ways to exercise the case-insensitive match.
    """

    def __init__(self) -> None:
        self.lock = Lock()
        rows = [
            ("j0", "https://x/0.js", "JavaScript"),
            ("w0", "https://x/0.wasm", "WebAssembly"),
            ("j1", "https://x/1.js", "JavaScript"),
            ("w1", "https://x/1.wasm", "webassembly"),
            ("j2", "https://x/2.js", "JavaScript"),
            ("w2", "https://x/2.wasm", "WEBASSEMBLY"),
            ("j3", "https://x/3.js", "JavaScript"),
        ]
        self.scripts = {
            sid: {"scriptId": sid, "url": url, "language": lang} for sid, url, lang in rows
        }
        self.scripts_dropped = 0


_WASM_IDS = {"w0", "w1", "w2"}
_JS_IDS = {"j0", "j1", "j2", "j3"}


def _backend(monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _MixedHandle())
    return backend


def test_scripts_without_wasm_only_returns_every_language(monkeypatch: Any) -> None:
    """The full-list view keeps both JavaScript and WebAssembly rows."""
    payload = _backend(monkeypatch).scripts("s")
    ids = {row["scriptId"] for row in payload["scripts"]}
    assert ids == _WASM_IDS | _JS_IDS
    assert payload["total"] == 7
    assert payload["count"] == 7


def test_wasm_only_keeps_wasm_and_drops_javascript(monkeypatch: Any) -> None:
    """The crux: ``wasm_only`` yields only the WASM rows, none of the JS ones.

    A homogeneous handle cannot show this -- an all-WASM ring returns the same
    rows with or without the predicate. Here the four JavaScript rows must be
    absent and all three WebAssembly rows present, and the mixed spelling
    (``WebAssembly`` / ``webassembly`` / ``WEBASSEMBLY``) proves the match is
    case-insensitive rather than an exact-string accident.
    """
    payload = _backend(monkeypatch).scripts("s", wasm_only=True)
    ids = {row["scriptId"] for row in payload["scripts"]}
    assert ids == _WASM_IDS
    assert ids.isdisjoint(_JS_IDS)
    assert payload["total"] == 3
    assert payload["count"] == 3
    assert all(
        str(row["language"]).lower() == "webassembly" for row in payload["scripts"]
    )


def test_wasm_only_paginates_over_the_filtered_set_not_the_whole_ring(
    monkeypatch: Any,
) -> None:
    """``total`` is the WASM count, proving the filter runs before the slice.

    With the filter applied first, offset/limit walk the three WASM rows:
    ``offset=1, limit=1`` returns one WASM row, ``total`` is 3, and ``has_more``
    is true because 1+1 < 3. If the slice ran *before* the filter, ``total``
    would be 7 and a window near the end could hand back JavaScript rows the
    caller explicitly filtered out.
    """
    payload = _backend(monkeypatch).scripts("s", wasm_only=True, offset=1, limit=1)
    assert payload["total"] == 3
    assert payload["offset"] == 1
    assert payload["count"] == 1
    assert payload["has_more"] is True
    assert payload["scripts"][0]["scriptId"] in _WASM_IDS

    # A window that starts past the WASM count is empty -- not a JS spillover.
    tail = _backend(monkeypatch).scripts("s", wasm_only=True, offset=3, limit=10)
    assert tail["scripts"] == []
    assert tail["total"] == 3
    assert tail["has_more"] is False


class _CapturingWeb:
    """Records the ``wasm_only`` the service hands the backend for each op."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def scripts(
        self, session_id: str, *, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        del session_id
        self.calls.append({"wasm_only": wasm_only, "offset": offset, "limit": limit})
        return {
            "scripts": [],
            "count": 0,
            "total": 0,
            "offset": offset,
            "has_more": False,
            "dropped": 0,
        }

    def close_all(self) -> None:
        """service.close_all() drains every backend; this stub has nothing to do."""


def test_service_routes_wasm_list_and_scripts_with_the_right_flag() -> None:
    """web.wasm.list must hand the backend ``wasm_only=True``; web.scripts False.

    Both tools are the same backend call; the flag is the whole difference. This
    pins the service half so a refactor that dropped the hard-coded ``True`` on
    ``web_wasm_list`` (making it an alias of ``web.scripts``) is caught even
    though the backend filter itself still works.
    """
    service = AnalysisService()
    capturing = _CapturingWeb()
    service._web_backend = capturing  # type: ignore[assignment]
    try:
        assert service.web_wasm_list("s").ok is True
        assert capturing.calls[-1]["wasm_only"] is True

        assert service.web_scripts("s").ok is True
        assert capturing.calls[-1]["wasm_only"] is False

        # web.scripts still lets a caller opt in explicitly.
        assert service.web_scripts("s", wasm_only=True).ok is True
        assert capturing.calls[-1]["wasm_only"] is True
    finally:
        service.close_all()
