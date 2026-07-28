from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.ida.gate import run_idalib_gate
from headless_re_mcp.config import Settings


@pytest.mark.integration
@pytest.mark.headless
def test_idalib_opens_fixture_without_analyzer_window() -> None:
    raw = os.environ.get("HEADLESS_RE_IDA_GATE_BINARY")
    if not raw:
        pytest.skip("HEADLESS_RE_IDA_GATE_BINARY is not configured")
    result = run_idalib_gate(Path(raw), Settings.load(), timeout=600)
    assert result.ok, result.to_dict()
    assert result.payload["function_count"] > 0
    assert not result.analyzer_windows
