"""Local loopback web console (M13).

Binds ``127.0.0.1`` only, requires a random local token, and calls the same
``AnalysisService`` instance used by MCP — no duplicated business logic.
"""

from __future__ import annotations

from headless_re_mcp.web.app import create_app, run_web
from headless_re_mcp.web.auth import ensure_web_token, load_or_create_web_token

__all__ = [
    "create_app",
    "ensure_web_token",
    "load_or_create_web_token",
    "run_web",
]
