from __future__ import annotations

import io
from collections import deque

from headless_re_mcp.backends.x64dbg.client import XdbgClient


def test_xdbg_diagnostic_reader_bounds_each_retained_line() -> None:
    """The 200-entry deque bounded count but not bytes.

    Feeding 300 100,000-character lines retained 20,000,000 characters in the
    last 200 entries. Diagnostic lines must be clipped while they are read.
    """
    client = object.__new__(XdbgClient)
    target: deque[str] = deque(maxlen=200)
    stream = io.StringIO(("x" * 100_000 + "\n") * 300)

    client._read_log(stream, target)

    assert len(target) == 200
    assert max(map(len, target)) <= 8_192
    assert sum(map(len, target)) <= 200 * 8_192
    assert all(line.endswith("[truncated]") for line in target)
