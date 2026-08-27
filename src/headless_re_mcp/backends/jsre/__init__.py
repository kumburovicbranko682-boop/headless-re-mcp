"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    parse_wasm_data,
    parse_wasm_exports,
    parse_wasm_functions,
    parse_wasm_globals,
    parse_wasm_imports,
    parse_wasm_memory,
    parse_wasm_names,
    parse_wasm_sections,
    parse_wasm_strings,
    parse_wasm_tables,
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
    "parse_wasm_strings",
    "parse_wasm_globals",
    "parse_wasm_data",
    "parse_wasm_memory",
    "parse_wasm_tables",
]
