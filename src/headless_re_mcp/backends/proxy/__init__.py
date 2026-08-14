"""HTTP(S) interception backend (mitmproxy, in-process addon)."""

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError

__all__ = ["ProxyBackend", "ProxyError"]
