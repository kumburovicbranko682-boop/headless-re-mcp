"""web.dom.snapshot inlines a prefix, spills the whole document, names both."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    url = "https://example/app"

    def __init__(self, html: str) -> None:
        self._html = html

    def evaluate(self, script: str) -> str:
        del script
        return self._html

    def title(self) -> str:
        return "Example"


def _snapshot(monkeypatch: Any, html: str, artifact_dir: Path) -> dict[str, Any]:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(html)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend.dom_snapshot("s", artifact_dir)


def test_web_dom_snapshot_over_the_buffer_spills_the_whole_document(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A DOM past the inline buffer used to drop every byte past the cut.

    Now the html field holds only the leading buffer, truncated says so, and
    html_path names a file with the *whole* document -- the same inline-plus-
    spill contract web.script.source uses for a large script source. Asserting
    the spilled file equals the full DOM is what proves the tail is no longer
    lost; a mutation that stops passing the whole text to the spill would leave
    the file a prefix and fail here.
    """
    html = "<html>" + ("x" * (_MAX_INLINE_BODY + 5000)) + "</html>"
    payload = _snapshot(monkeypatch, html, tmp_path)

    assert payload["truncated"] is True
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    assert payload["bytes"] == len(html.encode("utf-8"))
    assert len(payload["html"]) == _MAX_INLINE_BODY
    assert payload["html"] == html[:_MAX_INLINE_BODY]

    spilled = Path(payload["html_path"])
    assert spilled.is_file()
    assert spilled.parent == tmp_path
    assert spilled.read_text(encoding="utf-8") == html
    # No stray content/dom/body aliases -- the catalog only names html.
    assert "content" not in payload
    assert "dom" not in payload
    assert "body" not in payload


def test_web_dom_snapshot_that_fits_the_buffer_inlines_with_no_spill(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A document under the buffer is returned whole, truncated False, no path.

    The complement of the spill test: a spill file written for a small DOM, or
    truncated set when nothing was cut, would each be a false alarm the caller
    reads as a lost tail. Nothing must be written to the artifact dir.
    """
    html = "<html><body>hello</body></html>"
    payload = _snapshot(monkeypatch, html, tmp_path)

    assert payload["truncated"] is False
    assert payload["html"] == html
    assert payload["bytes"] == len(html.encode("utf-8"))
    assert "html_path" not in payload
    assert list(tmp_path.iterdir()) == []


def test_web_dom_snapshot_docstring_names_html_truncated_and_the_spill_path() -> None:
    doc = _tool_docstring("web.dom.snapshot")
    assert "html" in doc
    assert "truncated" in doc
    assert "html_path" in doc
