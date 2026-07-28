"""Native desktop shell helpers (no WebView / browser chrome)."""

from __future__ import annotations

__all__ = ["run_cli_setup", "run_native_gui"]

from headless_re_mcp.native_app.bootstrap import run_cli_setup
from headless_re_mcp.native_app.gui import run_native_gui
