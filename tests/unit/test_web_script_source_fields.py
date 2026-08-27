"""web.script.source description must name source and truncated."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend, WebError
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
    """Mimic CDP's wasm reply: empty scriptSource, module under bytecode."""

    def __init__(self, reply: dict[str, str]) -> None:
        self._reply = reply

    def send(self, method: str, params: dict[str, Any]) -> dict[str, str]:
        return self._reply


# A short blob standing in for a module; only the base64 round-trip matters here.
_WASM_BLOB = bytes([0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C])


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


def test_web_script_source_hands_back_wasm_module_bytes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A wasm module arrives as empty scriptSource + base64 bytecode.

    Reading only scriptSource returned an empty string for every wasm script;
    the module bytes have to be decoded from bytecode and spilled as a real
    .wasm so the static wabt path can pick them up.
    """
    reply = {
        "scriptSource": "",
        "bytecode": base64.b64encode(_WASM_BLOB).decode("ascii"),
    }
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_WasmCdp(reply)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.script_source("s", "9", tmp_path)
    assert payload["wasm"] is True
    assert payload["language"] == "WebAssembly"
    assert payload["bytes"] == len(_WASM_BLOB)
    assert payload["source"] == ""
    assert payload["truncated"] is False
    out = Path(str(payload["source_path"]))
    assert out.suffix == ".wasm"
    assert out.read_bytes() == _WASM_BLOB


def test_web_script_source_rejects_corrupt_wasm_bytecode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Undecodable bytecode is a structured backend_error, not a raw traceback."""
    reply = {"scriptSource": "", "bytecode": "not*valid*base64"}
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_WasmCdp(reply)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    with pytest.raises(WebError) as info:
        backend.script_source("s", "9", tmp_path)
    assert info.value.code == "backend_error"
