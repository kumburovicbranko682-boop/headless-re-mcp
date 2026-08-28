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


class _WasmCdp:
    """A Wasm module: getScriptSource is empty, the WAT comes from disassembly."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(method)
        if method == "Debugger.getScriptSource":
            return {"scriptSource": "", "bytecode": "AGFzbQE="}
        if method == "Debugger.disassembleWasmModule":
            return {
                "totalNumberOfLines": 3,
                "chunk": {"lines": ["(module", '  (func $add (export "add")', "    i32.add)"]},
            }
        raise AssertionError(f"unexpected CDP method {method}")


class _ChunkedWasmCdp:
    """A Wasm module whose WAT streams across chunks via streamId."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._served = False

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(method)
        if method == "Debugger.getScriptSource":
            return {"scriptSource": "", "bytecode": "AGFzbQE="}
        if method == "Debugger.disassembleWasmModule":
            return {
                "totalNumberOfLines": 4,
                "streamId": "stream-1",
                "chunk": {"lines": ["(module", "  (func $a"]},
            }
        if method == "Debugger.nextWasmDisassemblyChunk":
            if self._served:
                return {"chunk": {"lines": []}}
            self._served = True
            return {"chunk": {"lines": ["    i32.add)", ")"]}}
        raise AssertionError(f"unexpected CDP method {method}")


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
    assert payload["language"] == "javascript"
    assert "source_path" in payload
    assert payload["source_path"] != repeated["source_path"]
    assert Path(str(payload["source_path"])).is_file()
    assert Path(str(repeated["source_path"])).is_file()
    doc = _tool_docstring("web.script.source")
    assert "source" in doc
    assert "truncated" in doc
    assert "source_path" in doc


def test_web_script_source_disassembles_a_wasm_module(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A Wasm module has no scriptSource; script.source must return its WAT.

    getScriptSource hands back an empty scriptSource with the module in a
    `bytecode` field, so the reader has to fall back to
    Debugger.disassembleWasmModule. Without that, web.script.source returned an
    empty string for exactly the modules web.wasm.list surfaces.
    """
    backend = WebBackend()
    cdp = _WasmCdp()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=cdp))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.script_source("s", "9", tmp_path)
    assert payload["language"] == "webassembly"
    assert "i32.add" in payload["source"]
    assert '"add"' in payload["source"]
    assert payload["truncated"] is False
    assert "Debugger.disassembleWasmModule" in cdp.calls


def test_web_script_source_streams_chunked_wasm_disassembly(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """WAT longer than one chunk must be followed via the disassembly streamId."""
    backend = WebBackend()
    cdp = _ChunkedWasmCdp()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=cdp))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.script_source("s", "11", tmp_path)
    assert payload["language"] == "webassembly"
    # Lines from both the first chunk and the continuation are present.
    assert "(module" in payload["source"]
    assert "i32.add)" in payload["source"]
    assert cdp.calls.count("Debugger.nextWasmDisassemblyChunk") >= 1
