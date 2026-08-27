"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
)
from headless_re_mcp.backends.jsre.wasm_summary import summarize_wasm, summarize_wasm_bytes

__all__ = ["JsClient", "WasmClient", "JsReError", "summarize_wasm", "summarize_wasm_bytes"]
