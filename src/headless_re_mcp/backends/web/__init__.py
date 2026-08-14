"""Browser (Chrome DevTools Protocol via Playwright) dynamic backend."""

from headless_re_mcp.backends.web.client import WebBackend, WebError

__all__ = ["WebBackend", "WebError"]
