"""_read_capped is the byte ceiling on every bounded subprocess's output.

run_bounded reads a child's stdout/stderr on threads through this helper; it is
the thing that stops a runaway or hostile tool from filling memory with a
gigabyte of output. The subprocess plumbing needs a real process, but the cap
arithmetic and the truncation flag are pure and were never pinned on their own.
A fake stream that hands back scripted chunks exercises the boundaries exactly.
"""

from __future__ import annotations

from headless_re_mcp.backends.common.bounded_run import _read_capped


class _FakeStream:
    """Yields the queued byte pieces from read(), then EOF (b"")."""

    def __init__(self, *pieces: bytes) -> None:
        self._pieces = list(pieces)

    def read(self, _size: int) -> bytes:
        if self._pieces:
            return self._pieces.pop(0)
        return b""


class _ExplodingStream:
    def __init__(self, *pieces: bytes, exc: Exception) -> None:
        self._pieces = list(pieces)
        self._exc = exc

    def read(self, _size: int) -> bytes:
        if self._pieces:
            return self._pieces.pop(0)
        raise self._exc


def _run(stream: object, cap: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    truncated = [False]
    _read_capped(stream, cap, chunks, truncated)
    return b"".join(chunks), truncated[0]


def test_output_under_the_cap_is_kept_whole() -> None:
    data, truncated = _run(_FakeStream(b"abc", b"def"), cap=100)
    assert data == b"abcdef"
    assert truncated is False


def test_output_exactly_at_the_cap_is_not_truncated() -> None:
    """A stream that fills the cap exactly and then ends is a complete read."""
    data, truncated = _run(_FakeStream(b"abcde"), cap=5)
    assert data == b"abcde"
    assert truncated is False


def test_a_single_oversized_piece_is_cut_to_the_cap_and_flagged() -> None:
    data, truncated = _run(_FakeStream(b"abcdefghij"), cap=4)
    assert data == b"abcd"
    assert truncated is True


def test_bytes_after_the_cap_keep_the_flag_set_and_add_nothing() -> None:
    """Once full, later pieces must not grow the buffer but must stay flagged."""
    data, truncated = _run(_FakeStream(b"abc", b"defgh", b"ijk"), cap=4)
    assert data == b"abcd"
    assert truncated is True


def test_an_empty_stream_yields_nothing_and_is_not_truncated() -> None:
    data, truncated = _run(_FakeStream(), cap=10)
    assert data == b""
    assert truncated is False


def test_a_broken_pipe_returns_what_was_read_without_raising() -> None:
    """A closed pipe mid-read (ValueError/OSError) is swallowed, not propagated."""
    for exc in (ValueError("I/O operation on closed file"), OSError("pipe")):
        data, truncated = _run(_ExplodingStream(b"partial", exc=exc), cap=100)
        assert data == b"partial"
        assert truncated is False
