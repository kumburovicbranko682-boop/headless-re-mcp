"""Shared backend process / RPC helpers."""

from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)

__all__ = ["ManagedSubprocessMixin", "no_window_popen_kwargs"]
