"""Local loopback web console (M13).

Binds ``127.0.0.1`` only, requires a random local token, and calls the same
``AnalysisService`` instance used by MCP — no duplicated business logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from headless_re_mcp.web.auth import ensure_web_token, load_or_create_web_token

if TYPE_CHECKING:
    from headless_re_mcp.web.app import create_app, run_web

__all__ = [
    "create_app",
    "ensure_web_token",
    "load_or_create_web_token",
    "run_web",
]


def __getattr__(name: str) -> Any:
    # ``create_app``/``run_web`` live in ``web.app``, which imports fastapi (the
    # optional ``web`` extra). Bind them lazily rather than at package import so
    # that importing a web *utility* submodule (web.setup, web.deps, web.monitor,
    # web.launch_util, web.commands) does not pull the whole fastapi server in
    # through this __init__. Installer IDA configuration imports web.setup on a
    # base install that never asked for the web extra; eager-importing web.app
    # here turned that into a bare ``No module named 'fastapi'`` crash far from
    # anything web-served. The names stay on the package's public surface --
    # ``from headless_re_mcp.web import create_app`` still works, and still
    # requires fastapi at that point, which is correct: you are about to serve.
    if name in ("create_app", "run_web"):
        from headless_re_mcp.web import app

        return getattr(app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
