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
    # The binary path and IDA itself are independent preconditions: conftest's
    # _default_ida_gate_binary points this env var at the native fixture whenever
    # that fixture exists (built for the r2/other gates), which says nothing about
    # whether IDA is installed. Without this second guard the gate hard-fails at
    # run_idalib_gate's "IDA home is not configured" RuntimeError on any machine
    # that has the fixtures but no IDA -- a missing backend read as a failure,
    # which is exactly the skip-masquerading-as-failure this suite forbids.
    if Settings.load().ida_home is None:
        pytest.skip("IDA home is not configured — idalib Gate not run (skip != pass)")
    result = run_idalib_gate(Path(raw), Settings.load(), timeout=600)
    assert result.ok, result.to_dict()
    assert result.payload["function_count"] > 0
    assert not result.analyzer_windows
