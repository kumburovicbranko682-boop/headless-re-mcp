"""web.dom.snapshot spills an over-cap document instead of truncating it.

A large DOM (a generated or obfuscated single-page app) used to be cut to the
200 KB inline buffer with no way to recover the rest -- unlike script sources
and response bodies, which have long spilled the whole payload to an artifact.
These check the DOM now behaves the same: inline stays inline, and anything
past the buffer lands whole on disk with html_path pointing at it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    """Stand in for the browser: slice the document the way the real JS does."""

    def __init__(self, html: str) -> None:
        self._html = html
        self.url = "https://example/app"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        text = self._html
        return {"html": text[:cap], "truncated": len(text) > cap}

    def title(self) -> str:
        return "Example"


def _backend(monkeypatch: Any, html: str) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(html)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_a_small_dom_stays_inline_with_no_artifact(monkeypatch: Any, tmp_path: Path) -> None:
    html = "<html><body>small</body></html>"
    payload = _backend(monkeypatch, html).dom_snapshot("s", tmp_path)
    assert payload["html"] == html
    assert payload["truncated"] is False
    assert payload["bytes"] == len(html.encode("utf-8"))
    assert "html_path" not in payload
    # Nothing was written -- an inline snapshot must not litter the artifact dir.
    assert list(tmp_path.iterdir()) == []


def test_an_over_cap_dom_is_spilled_whole_and_only_a_prefix_inlined(
    monkeypatch: Any, tmp_path: Path
) -> None:
    html = "d" * (_MAX_INLINE_BODY + 12_345)
    payload = _backend(monkeypatch, html).dom_snapshot("s", tmp_path)
    assert payload["truncated"] is True
    assert payload["bytes"] == len(html)
    assert len(payload["html"]) == _MAX_INLINE_BODY
    spilled = Path(payload["html_path"])
    assert spilled.parent == tmp_path
    # The artifact is the whole document, byte for byte -- not the inlined prefix.
    assert spilled.read_text(encoding="utf-8") == html


def test_each_spill_gets_its_own_filename(monkeypatch: Any, tmp_path: Path) -> None:
    html = "e" * (_MAX_INLINE_BODY + 1)
    backend = _backend(monkeypatch, html)
    first = backend.dom_snapshot("s", tmp_path)
    second = backend.dom_snapshot("s", tmp_path)
    assert first["html_path"] != second["html_path"]
    assert Path(first["html_path"]).is_file()
    assert Path(second["html_path"]).is_file()


def test_bytes_counts_utf8_not_characters(monkeypatch: Any, tmp_path: Path) -> None:
    # A café-heavy DOM: each accented char is two UTF-8 bytes, so a char count
    # would understate the real payload. bytes must be the encoded length, and
    # the spilled file must round-trip the exact characters.
    html = "café" * (_MAX_INLINE_BODY)  # well past the inline buffer
    payload = _backend(monkeypatch, html).dom_snapshot("s", tmp_path)
    assert payload["bytes"] == len(html.encode("utf-8"))
    assert payload["bytes"] > len(html)
    assert Path(payload["html_path"]).read_text(encoding="utf-8") == html
