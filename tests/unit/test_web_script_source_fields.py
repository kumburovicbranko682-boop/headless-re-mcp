"""web.script.source description must name source and truncated."""

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


class _Cdp:
    def send(self, method: str, params: dict[str, Any]) -> dict[str, str]:
        return {"scriptSource": "y" * (_MAX_INLINE_BODY + 40)}


def test_web_script_source_names_source_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said source and never named the payload.

    Measured: truncated True, source 200000 chars (the cap), bytes 200040,
    source_path set, no code or text field. Looking for those after a
    successful call reads as a missing script, and a 200000-char string
    with no truncated flag reads as the whole file.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_Cdp()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.script_source("s", "42", tmp_path)
    repeated = backend.script_source("s", "42", tmp_path)
    assert "code" not in payload
    assert "text" not in payload
    assert payload["truncated"] is True
    assert payload["bytes"] == _MAX_INLINE_BODY + 40
    assert len(payload["source"]) == _MAX_INLINE_BODY
    assert "source_path" in payload
    assert payload["source_path"] != repeated["source_path"]
    assert Path(str(payload["source_path"])).is_file()
    assert Path(str(repeated["source_path"])).is_file()
    doc = _tool_docstring("web.script.source")
    assert "source" in doc
    assert "truncated" in doc
    assert "source_path" in doc


def test_web_script_source_documents_the_spill_artifact() -> None:
    """A spilled source is a registered artifact; the description must say so.

    The service wires source_path through _register_capture, so the payload
    carries artifact_id -- the only handle artifacts.read accepts. This mirrors
    the web.network.get pin; the registration behaviour itself is pinned in
    test_web_spill_registration.
    """
    doc = _tool_docstring("web.script.source")
    assert "artifact_id" in doc
    assert "artifacts.read" in doc
    # Registration can fail (full/locked store); the doc must name the
    # artifact_error fallback so an agent expecting an id knows to read source_path.
    assert "artifact_error" in doc
    # A Wasm script has no text source here; the doc must say so and point at
    # the byte-yielding path so wasm.list -> script.source is not a dead end.
    assert "is_wasm" in doc
    assert "web.network.get" in doc


def test_web_script_source_points_a_spilled_js_source_at_the_deobfuscators() -> None:
    """A large obfuscated JS source spills to source_path; the doc must say what next.

    The is_wasm branch already tells an agent holding a WASM script where the
    bytes are (web.network.get -> wasm.wat/info). The far more common case -- a
    minified or obfuscated JS bundle whose source is too big to inline and so
    lands in source_path -- had no such pointer, even though service_jsre's own
    module docstring states the js.* tools are meant to run "against a web
    session's saved artifacts" and js.deobfuscate takes exactly a file path with
    no session-tree restriction. Without the note an agent reads the spilled
    path as an opaque blob and never connects it to js.deobfuscate/js.beautify,
    the one step that turns it back into readable code. Pin the producer-side
    hand-off the same way the is_wasm note is pinned.
    """
    doc = " ".join(_tool_docstring("web.script.source").split())
    assert "source_path" in doc
    assert "js.deobfuscate" in doc
    assert "js.beautify" in doc
