"""web.script_source must return WASM module bytes, not an empty source.

For a ``wasm://`` script modern CDP ``Debugger.getScriptSource`` returns an empty
``scriptSource`` plus a base64 ``bytecode`` field carrying the module. The
backend used to read only ``scriptSource``, so ``web.script_source`` silently
returned an empty result (``bytes == 0``, ``source == ""``) for every WASM script
``web.wasm_list`` surfaces -- the last step of the "find WASM in a live page,
then inspect it" workflow yielded nothing. It now spills the decoded module bytes
(the binary counterpart of the ``network_get`` binary path) so the caller can
disassemble them. Verified live against Chromium; this guards the branch without
needing a browser.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend

# A real (tiny) module: magic + version, two exported functions. This base64 is
# exactly what Chromium hands back in the getScriptSource ``bytecode`` field for
# a wasm:// script.
_WASM_B64 = "AGFzbQEAAAABBwFgAn9/AX8DAwIAAAcNAgNhZGQAAANzdWIAAQoRAgcAIAAgAWoLBwAgACABaws="
_WASM_BYTES = base64.b64decode(_WASM_B64)


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _WasmCdp:
    """Stands in for the CDP session's response on a wasm:// script."""

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"scriptSource": "", "bytecode": _WASM_B64}


def test_wasm_script_source_spills_the_real_module_bytes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_WasmCdp()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    payload = backend.script_source("s", "5", tmp_path)

    # The module comes back as bytes on disk, flagged as WebAssembly, never as an
    # empty text source.
    assert payload["language"] == "webassembly"
    assert payload["source"] == ""
    assert payload["truncated"] is False
    assert payload["bytes"] == len(_WASM_BYTES)
    spilled = Path(payload["source_path"])
    assert spilled.parent == tmp_path
    assert spilled.suffix == ".wasm"
    raw = spilled.read_bytes()
    assert raw == _WASM_BYTES
    assert raw[:4] == b"\x00asm"  # the bytes are a real module, not base64 text


def test_non_wasm_script_still_takes_the_text_path(tmp_path: Path, monkeypatch: Any) -> None:
    """A JS script (scriptSource present, no bytecode) is unaffected by the guard."""

    class _JsCdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return {"scriptSource": "console.log(1);"}

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(cdp=_JsCdp()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    payload = backend.script_source("s", "1", tmp_path)

    assert payload["source"] == "console.log(1);"
    assert "language" not in payload
    assert "source_path" not in payload
    assert payload["truncated"] is False
