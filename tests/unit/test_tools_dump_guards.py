"""Fail-closed coverage for the tool binding modules' envelope dumpers.

Every ``tools/*`` module carries the same ``_dump`` helper: it serializes a
Result envelope and refuses anything that does not come back as an object,
rather than handing a malformed payload to the transport. The happy path is
exercised by each tool's own tests; this pins the guard across all binding
modules at once, plus the one meta tool whose handler the wider suite did not
invoke.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools import (
    apk,
    device,
    dynamic,
    dynamic_analysis,
    frida,
    ghidra,
    js_wasm,
    meta,
    proxy,
    r2,
    trace,
    ui,
    unpack,
    web,
    windbg,
    workspace,
)
from headless_re_mcp.tools.meta import build_meta_tools

_DumpFn = Callable[[Result[dict[str, Any]]], dict[str, Any]]

_DUMPERS: dict[str, _DumpFn] = {
    "apk": apk._dump,
    "device": device._dump,
    "dynamic": dynamic._dump,
    "dynamic_analysis": dynamic_analysis._dump,
    "frida": frida._dump,
    "ghidra": ghidra._dump,
    "js_wasm": js_wasm._dump,
    "meta": meta._dump,
    "proxy": proxy._dump,
    "r2": r2._dump,
    "trace": trace._dump,
    "ui": ui._dump,
    "unpack": unpack._dump,
    "web": web._dump,
    "windbg": windbg._dump,
    "workspace": workspace._dump,
}


class _NonObjectResult:
    """A Result stand-in whose serialization is not an object."""

    def model_dump(self, mode: str = "python") -> list[str]:
        return ["not", "an", "object"]


@pytest.mark.parametrize("dumper", list(_DUMPERS.values()), ids=list(_DUMPERS))
def test_dump_refuses_a_non_object_envelope(dumper: _DumpFn) -> None:
    fake = cast(Result[dict[str, Any]], _NonObjectResult())
    with pytest.raises(TypeError, match="did not serialize to an object"):
        dumper(fake)


def test_artifacts_gc_tool_serializes_its_envelope() -> None:
    # The other meta tools are invoked by the wider suite; artifacts.gc is not,
    # so drive its bound handler once to pin the dump-and-return line.
    analysis = AnalysisService()
    try:
        tools = {tool.name: tool for tool in build_meta_tools(analysis)}
        payload = tools["artifacts.gc"].handler(max_total_bytes=1024)
    finally:
        analysis.close_all()

    assert isinstance(payload, dict)
    assert payload["ok"] is True
