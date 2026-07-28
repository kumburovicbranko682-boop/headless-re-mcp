from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.core.models import Architecture


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
    ],
)
def test_official_xdbg_command_loop_is_headless(variable: str, architecture: Architecture) -> None:
    raw = os.environ.get(variable)
    if not raw:
        pytest.skip(f"{variable} is not configured")
    result = run_command_loop_gate(Path(raw), architecture)
    assert result.ok, result
    assert not result.analyzer_windows
