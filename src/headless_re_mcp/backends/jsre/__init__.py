"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    parse_wasm_exports,
    parse_wasm_functions,
    parse_wasm_imports,
    parse_wasm_names,
    parse_wasm_sections,
)

__all__ = [
    "JsClient",
    "WasmClient",
    "JsReError",
    "parse_wasm_imports",
    "parse_wasm_exports",
    "parse_wasm_sections",
    "parse_wasm_names",
    "parse_wasm_functions",
]
