"""JavaScript / WebAssembly static tooling (webcrack + wabt subprocesses)."""

from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    scan_urls,
)

__all__ = ["JsClient", "WasmClient", "JsReError", "scan_urls"]
