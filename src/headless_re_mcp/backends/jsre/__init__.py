"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
)
from headless_re_mcp.backends.jsre.wasm_summary import (
    extract_wasm_names,
    extract_wasm_names_bytes,
    extract_wasm_sections,
    extract_wasm_sections_bytes,
    extract_wasm_strings,
    extract_wasm_strings_bytes,
    list_wasm_exports,
    list_wasm_exports_bytes,
    list_wasm_functions,
    list_wasm_functions_bytes,
    list_wasm_imports,
    list_wasm_imports_bytes,
    summarize_wasm,
    summarize_wasm_bytes,
)

__all__ = [
    "JsClient",
    "WasmClient",
    "JsReError",
    "summarize_wasm",
    "summarize_wasm_bytes",
    "extract_wasm_strings",
    "extract_wasm_strings_bytes",
    "extract_wasm_names",
    "extract_wasm_names_bytes",
    "extract_wasm_sections",
    "extract_wasm_sections_bytes",
    "list_wasm_functions",
    "list_wasm_functions_bytes",
    "list_wasm_exports",
    "list_wasm_exports_bytes",
    "list_wasm_imports",
    "list_wasm_imports_bytes",
]
