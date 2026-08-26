"""Compatibility exports for the shared redaction helpers."""

from __future__ import annotations

from headless_re_mcp.redaction import MAX_DEPTH, is_secret_key, masked_secret, redact

__all__ = ["MAX_DEPTH", "is_secret_key", "masked_secret", "redact"]
