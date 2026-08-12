"""Unified headless reverse-engineering MCP."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

try:
    # Read from installed metadata rather than a literal: the literal here and
    # the one in pyproject.toml drifted apart once already, and a health
    # endpoint that reports the wrong version is worse than one that reports
    # nothing.
    __version__ = _installed_version("headless-re-mcp")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0+unknown"

__all__ = ["__version__"]
