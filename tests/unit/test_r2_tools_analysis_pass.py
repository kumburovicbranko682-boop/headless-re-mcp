"""The r2 address tools expose the analysis-depth knob end to end.

The R2Client grew an ``analysis`` parameter (aa/aac/aar/aaa) because the
shallow default misses stripped-binary functions and ARM literal-pool data
refs. That knob is only real for MCP callers if the tool layer publishes it
in the input schema and the service threads it down unchanged; a client-only
parameter would leave every session-based caller stuck on ``aa``. These tests
pin both halves: the schema names the four allowlisted passes with ``aa`` as
the default, and each handler forwards the chosen pass to the service.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.models import Result
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.r2 import build_r2_tools

_ADDRESS_TOOLS = ("r2.disasm", "r2.xrefs", "r2.xrefs_to", "r2.xrefs_from")


class _RecordingService:
    """Stands in for AnalysisService; records the kwargs each tool passes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _record(self, method: str, kwargs: dict[str, Any]) -> Result[dict[str, Any]]:
        self.calls.append((method, kwargs))
        return Result(ok=True, data={})

    def r2_disasm(self, session_id: str, address: int, **kwargs: Any) -> Result[dict[str, Any]]:
        return self._record("r2_disasm", kwargs)

    def r2_xrefs(self, session_id: str, address: int, **kwargs: Any) -> Result[dict[str, Any]]:
        return self._record("r2_xrefs", kwargs)

    def r2_xrefs_to(self, session_id: str, address: int, **kwargs: Any) -> Result[dict[str, Any]]:
        return self._record("r2_xrefs_to", kwargs)

    def r2_xrefs_from(
        self, session_id: str, address: int, **kwargs: Any
    ) -> Result[dict[str, Any]]:
        return self._record("r2_xrefs_from", kwargs)


def _handlers() -> dict[str, Any]:
    service = _RecordingService()
    bindings = build_r2_tools(service)  # type: ignore[arg-type]
    return {"service": service, **{b.name: b.handler for b in bindings}}


def test_r2_address_tools_publish_the_analysis_pass_enum() -> None:
    named = _handlers()
    for name in _ADDRESS_TOOLS:
        props = input_schema_for(named[name])["properties"]
        assert "analysis_pass" in props, (name, sorted(props))
        prop = props["analysis_pass"]
        assert prop.get("enum") == ["aa", "aac", "aar", "aaa"], (name, prop)
        assert prop.get("default") == "aa", (name, prop)


def test_r2_address_tools_thread_the_analysis_pass_to_the_service() -> None:
    named = _handlers()
    service: _RecordingService = named["service"]

    # The default stays the shallow pass -- existing callers see no change.
    for name in _ADDRESS_TOOLS:
        named[name](session_id="s", address=0x401000)
    assert [kwargs["analysis"] for _, kwargs in service.calls] == ["aa"] * 4

    # A caller-chosen deeper pass reaches the service verbatim.
    service.calls.clear()
    for name in _ADDRESS_TOOLS:
        named[name](session_id="s", address=0x401000, analysis_pass="aaa")
    assert [(m, kwargs["analysis"]) for m, kwargs in service.calls] == [
        ("r2_disasm", "aaa"),
        ("r2_xrefs", "aaa"),
        ("r2_xrefs_to", "aaa"),
        ("r2_xrefs_from", "aaa"),
    ]


def test_r2_tool_docstrings_explain_when_the_deeper_pass_matters() -> None:
    # The schema alone says "aa|aac|aar|aaa"; the docstring must say why a
    # caller would ever pay for aaa, or the knob is undiscoverable.
    named = _handlers()
    for name in _ADDRESS_TOOLS:
        doc = (named[name].__doc__ or "").replace("\n", " ")
        assert "analysis_pass" in doc, name
        assert "aaa" in doc, name
        assert "stripped" in doc, name
