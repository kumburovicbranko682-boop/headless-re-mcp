"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    parse_wasm_exports,
    parse_wasm_imports,
)

__all__ = [
    "JsClient",
    "WasmClient",
    "JsReError",
    "parse_wasm_imports",
    "parse_wasm_exports",
]
