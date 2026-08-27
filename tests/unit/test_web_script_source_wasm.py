"""web.script.source must hand back a wasm module's bytecode, not an empty string.

CDP's Debugger.getScriptSource returns an empty ``scriptSource`` for a
WebAssembly script and carries the module in a base64 ``bytecode`` field.
Reading scriptSource alone reported source="" for every module web.wasm.list
surfaces -- indistinguishable from a genuinely empty script. These tests pin
the fallback: the bytecode comes back as base64 with base64_encoded set, while
ordinary JavaScript is untouched.
"""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend
from headless_re_mcp.tools.web import build_web_tools

_WASM_BYTES = b"\x00asm\x01\x00\x00\x00" + b"\x01\x02\x03\x04" * 8


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
    """Stand in for a CDP session returning a fixed getScriptSource reply."""

    def __init__(self, reply: dict[str, Any]) -> None:
        self._reply = reply

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._reply


def _backend(monkeypatch: Any, reply: dict[str, Any]) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_Cdp(reply)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_a_wasm_module_returns_its_bytecode_not_an_empty_source(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Empty scriptSource + base64 bytecode reads as the module, not "".

    The old code returned source="" for every wasm script, silently dropping
    the module. Now source is the base64 bytecode, base64_encoded True, and
    decoding it round-trips to the original wasm bytes.
    """
    encoded = base64.b64encode(_WASM_BYTES).decode("ascii")
    backend = _backend(monkeypatch, {"scriptSource": "", "bytecode": encoded})
    payload = backend.script_source("s", "7", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["source"] == encoded
    assert payload["bytes"] == len(encoded)
    assert payload["truncated"] is False
    # No spill for a small module; the base64 is inline and decodes cleanly.
    assert "source_path" not in payload
    assert base64.b64decode(payload["source"]) == _WASM_BYTES


def test_a_large_wasm_module_spills_and_stays_base64(tmp_path: Path, monkeypatch: Any) -> None:
    """A module over the inline cap spills to an artifact, still base64.

    The spilled file holds the base64 text; base64_encoded stays true so the
    caller decodes rather than treating the artifact as raw wasm.
    """
    encoded = "QQ" + "A" * (_MAX_INLINE_BODY + 40)  # valid base64 alphabet, over the cap
    backend = _backend(monkeypatch, {"scriptSource": "", "bytecode": encoded})
    payload = backend.script_source("s", "8", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["truncated"] is True
    assert payload["bytes"] == len(encoded)
    spill = payload.get("source_path")
    assert isinstance(spill, str)
    written = Path(spill).read_text(encoding="utf-8")
    assert written == encoded
    # The inline prefix is a prefix of the whole base64, not the whole thing.
    assert encoded.startswith(payload["source"])
    assert len(payload["source"]) == _MAX_INLINE_BODY


def test_javascript_source_is_not_flagged_base64(tmp_path: Path, monkeypatch: Any) -> None:
    """Ordinary JS keeps its text source and base64_encoded is false."""
    backend = _backend(monkeypatch, {"scriptSource": "export const x = 1;\n"})
    payload = backend.script_source("s", "9", tmp_path)
    assert payload["base64_encoded"] is False
    assert payload["source"] == "export const x = 1;\n"
    assert payload["truncated"] is False
    assert "source_path" not in payload


def test_an_empty_script_with_no_bytecode_stays_empty(tmp_path: Path, monkeypatch: Any) -> None:
    """No source and no bytecode is a genuinely empty script, not base64."""
    backend = _backend(monkeypatch, {"scriptSource": ""})
    payload = backend.script_source("s", "10", tmp_path)
    assert payload["source"] == ""
    assert payload["base64_encoded"] is False
    assert payload["bytes"] == 0
    assert payload["truncated"] is False


def test_docstring_names_base64_and_wasm() -> None:
    """The catalog must warn that a wasm source is base64 bytecode."""
    doc = _tool_docstring("web.script.source")
    assert "base64_encoded" in doc
    lowered = doc.lower()
    assert "wasm" in lowered or "webassembly" in lowered
