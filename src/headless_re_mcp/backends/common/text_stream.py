"""Bounded helpers for subprocess diagnostic text streams."""

from __future__ import annotations

from typing import TextIO

_TRUNCATION_MARKER = "… [truncated]"


def read_bounded_text_line(stream: TextIO, *, max_chars: int) -> str | None:
    """Read and drain one line while retaining at most ``max_chars`` characters."""
    cap = max(1, int(max_chars))
    chunk = stream.readline(cap + 2)
    if chunk == "":
        return None

    complete = chunk.endswith("\n")
    text = chunk.rstrip("\r\n") if complete else chunk
    truncated = len(text) > cap
    if not complete and len(chunk) > cap:
        truncated = True
        while chunk and not chunk.endswith("\n"):
            chunk = stream.readline(cap + 2)

    if not truncated:
        return text
    marker = _TRUNCATION_MARKER[:cap]
    return text[: max(0, cap - len(marker))] + marker
