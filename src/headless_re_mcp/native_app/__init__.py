"""Native desktop shell helpers (no WebView / browser chrome)."""

from __future__ import annotations

from headless_re_mcp.native_app.bootstrap import run_cli_setup

__all__ = ["run_cli_setup", "run_native_gui"]


def run_native_gui() -> int:
    # gui.py imports PySide6. Importing it at package load used to make
    # `from headless_re_mcp.native_app import bootstrap` fail collection on
    # the hosted quality job, which never installs the native extra.
    from headless_re_mcp.native_app.gui import run_native_gui as _run

    return _run()
