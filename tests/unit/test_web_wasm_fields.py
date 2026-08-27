"""web.wasm.get extracts a live WebAssembly module for offline analysis.

web.wasm.list surfaced modules with no way to pull them: getScriptSource
returns the engine's textual disassembly for wasm, not the binary, so the
listed modules could never reach the wasm.wat / wasm.info tools that exist to
analyse them. wasm_get pulls the raw bytecode (Debugger.getWasmBytecode) and,
being binary, always spills it to a .wasm artifact -- the binary sibling of
web.script.source. These tests pin that behaviour, the fault contract, and the
tool description.
"""

from __future__ import annotations

import ast
import base64
import threading
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools

_WASM = b"\x00asm\x01\x00\x00\x00" + bytes(range(64)) * 4


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


class _Handle:
    def __init__(self, cdp: object, scripts: dict[str, Any]) -> None:
        self.lock = threading.Lock()
        self.scripts = scripts
        self.cdp = cdp


class _Runner:
    def __init__(self, wrap: Any) -> None:
        self._wrap = wrap

    def call(self, work: Any, timeout: float | None = None) -> Any:
        del timeout
        return self._wrap(work)


def _backend(cdp: object, scripts: dict[str, Any], wrap: Any = lambda w: w()) -> WebBackend:
    handle = _Handle(cdp, scripts)
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[assignment]
    backend._runner = lambda h: _Runner(wrap)  # type: ignore[assignment]
    return backend


class _Cdp:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert method == "Debugger.getWasmBytecode"
        assert params == {"scriptId": "w1"}
        return {"bytecode": base64.b64encode(self._payload).decode("ascii")}


def test_wasm_get_spills_the_module_bytes_to_a_file(tmp_path: Path) -> None:
    backend = _backend(
        _Cdp(_WASM), {"w1": {"language": "WebAssembly", "url": "https://x/m.wasm"}}
    )
    payload = backend.wasm_get("s", "w1", tmp_path)
    assert payload["scriptId"] == "w1"
    assert payload["url"] == "https://x/m.wasm"
    assert payload["bytes"] == len(_WASM)
    out = Path(payload["wasm_path"])
    assert out.parent == tmp_path and out.suffix == ".wasm"
    # The raw binary is on disk verbatim, ready for wasm.wat / wasm.info.
    assert out.read_bytes() == _WASM
    # A binary module is never inlined as text.
    assert "source" not in payload and "body" not in payload


def test_wasm_get_rejects_an_unknown_script_id(tmp_path: Path) -> None:
    backend = _backend(object(), {})
    with pytest.raises(WebError) as info:
        backend.wasm_get("s", "nope", tmp_path)
    assert info.value.code == "not_found"
    assert list(tmp_path.iterdir()) == []


def test_wasm_get_rejects_a_javascript_script(tmp_path: Path) -> None:
    backend = _backend(object(), {"w1": {"language": "JavaScript", "url": "https://x/a.js"}})
    with pytest.raises(WebError) as info:
        backend.wasm_get("s", "w1", tmp_path)
    assert info.value.code == "invalid_params"
    assert list(tmp_path.iterdir()) == []


def test_wasm_get_propagates_a_session_fault(tmp_path: Path) -> None:
    def raise_timeout(work: object) -> object:
        del work
        raise WebError("timeout", "browser did not respond")

    backend = _backend(object(), {"w1": {"language": "webassembly"}}, wrap=raise_timeout)
    with pytest.raises(WebError) as info:
        backend.wasm_get("s", "w1", tmp_path)
    assert info.value.code == "timeout"
    assert list(tmp_path.iterdir()) == []


def test_wasm_get_refuses_a_module_over_the_cap(tmp_path: Path, monkeypatch: Any) -> None:
    from headless_re_mcp.backends.web import client as web_client

    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 16)
    backend = _backend(_Cdp(_WASM), {"w1": {"language": "WebAssembly"}})
    with pytest.raises(WebError) as info:
        backend.wasm_get("s", "w1", tmp_path)
    assert info.value.code == "too_large"
    # Refused before writing, so nothing spilled.
    assert list(tmp_path.iterdir()) == []


def test_web_wasm_get_registers_the_module_for_retention(tmp_path: Path) -> None:
    """A spilled module must be reclaimable, like every other web capture."""
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        created = service.create_session("https://example.com/app", target="web")
        session_id = created.data["session"]["id"]

        def fake_wasm_get(session_id: str, script_id: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            spill = artifact_dir / "wasm-x.wasm"
            spill.write_bytes(_WASM)
            return {
                "scriptId": script_id,
                "url": "https://x/m.wasm",
                "bytes": len(_WASM),
                "wasm_path": str(spill),
            }

        service._web_backend.wasm_get = fake_wasm_get  # type: ignore[method-assign]
        got = service.web_wasm_get(session_id, "w1")
        assert got.ok, got.error
        assert got.data is not None
        assert got.data["artifact_id"]
        assert "artifact_error" not in got.data
        listed = service.repository.list_artifacts(session_id)["artifacts"]
        kinds = {item["kind"] for item in listed}
        assert "web_wasm_module" in kinds
    finally:
        service.close_all()


def test_web_wasm_get_description_names_wasm_path() -> None:
    doc = _tool_docstring("web.wasm.get")
    assert "wasm_path" in doc
    assert "wasm.wat" in doc or "wasm.info" in doc
