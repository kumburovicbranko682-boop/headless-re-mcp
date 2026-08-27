"""web.script.source description must name source and truncated."""

from __future__ import annotations

import ast
import base64
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


_WASM_BYTES = b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00"


class _CdpWasm:
    """CDP getScriptSource for a Wasm script: empty source, base64 bytecode."""

    def send(self, method: str, params: dict[str, Any]) -> dict[str, str]:
        return {
            "scriptSource": "",
            "bytecode": base64.b64encode(_WASM_BYTES).decode("ascii"),
        }


def test_web_script_source_pulls_the_wasm_bytecode(tmp_path: Path, monkeypatch: Any) -> None:
    """A Wasm script returns its bytes in bytecode, not scriptSource.

    Chromium leaves scriptSource empty for Wasm and puts the module in the
    bytecode field, which the client dropped -- so a listed Wasm module had no
    retrievable bytes. Assert the module now lands as an is_wasm payload with a
    wasm_path file that is byte-identical to what CDP returned.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_CdpWasm()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.script_source("s", "7", tmp_path)
    assert payload["is_wasm"] is True
    assert payload["source"] == ""
    assert payload["wasm_bytes"] == len(_WASM_BYTES)
    assert "wasm_path" in payload
    wasm_file = Path(str(payload["wasm_path"]))
    assert wasm_file.is_file()
    assert wasm_file.read_bytes() == _WASM_BYTES
    assert wasm_file.suffix == ".wasm"
    # A plain JS script must not grow wasm fields.
    doc = _tool_docstring("web.script.source")
    assert "wasm_path" in doc
