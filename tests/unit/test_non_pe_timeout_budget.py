"""A non-PE tool's transport deadline must cover the timeout it advertises.

``ResourcePolicy.timeout_seconds`` is a hard ceiling on the whole tool call,
enforced by both the MCP adapter (it offloads the handler with that timeout) and
the agent orchestrator (``min(tool_timeout, policy)``). Every non-PE tool that
takes a ``timeout`` parameter blocks synchronously for its duration: the Android
CLIs (apktool / jadx), Ghidra headless, radare2/rizin, the JS/WASM node tools,
and the browser open/navigate calls all run inside the call and return only when
the work (or their own timeout) finishes.

If the transport ceiling is smaller than the advertised ``timeout`` maximum, the
transport kills the call first and the advertised timeout can never be reached --
so a plain ``apk.decode`` of a real APK (default 600s) dies at the 60s default
ceiling. This test pins the invariant for the whole non-PE surface so that a new
tool, or a raised ``timeout`` bound, cannot silently reintroduce that gap.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

# The tracks this repository calls "non-PE": Android, Web, JS/WASM, radare2/rizin
# and Ghidra. Every ``timeout`` parameter on these tools is expressed in seconds
# and bounds the call itself, so the rule below applies uniformly.
_NON_PE_PREFIXES = (
    "apk.",
    "device.",
    "frida.",
    "js.",
    "wasm.",
    "proxy.",
    "web.",
    "r2.",
    "ghidra.",
)

# The agent clamps every per-tool deadline to this hard ceiling
# (orchestrator: ``max(0.1, min(tool_timeout, 1800.0))``). A timeout maximum above
# it could never be honoured even with a matching policy, so a non-PE tool that
# advertised one -- e.g. a millisecond-valued bound that slipped in as seconds --
# should trip this test rather than demand an impossible policy.
_AGENT_CEILING_S = 1800.0


def _timeout_maximum(schema: dict[str, Any] | None) -> tuple[str, float] | None:
    """Return the (param, maximum) of the largest ``timeout`` bound in a schema."""
    props = (schema or {}).get("properties") or {}
    best: tuple[str, float] | None = None
    for name, prop in props.items():
        if "timeout" not in name.lower():
            continue
        maximum = prop.get("maximum")
        if maximum is None:
            continue
        if best is None or maximum > best[1]:
            best = (name, float(maximum))
    return best


def _non_pe_timeout_tools() -> list[tuple[str, str, float, float]]:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        rows: list[tuple[str, str, float, float]] = []
        for binding in bindings:
            if not binding.name.startswith(_NON_PE_PREFIXES):
                continue
            spec = catalog.require(binding.name)
            found = _timeout_maximum(spec.input_schema)
            if found is None:
                continue
            param, maximum = found
            rows.append(
                (binding.name, param, maximum, spec.resource_policy.timeout_seconds)
            )
        return rows
    finally:
        analysis.close_all()


_ROWS = _non_pe_timeout_tools()


def test_the_discovery_found_a_representative_non_pe_timeout_surface() -> None:
    # Guards against the invariant test passing vacuously if binding or schema
    # extraction ever stops surfacing these parameters.
    names = {name for name, _param, _max, _policy in _ROWS}
    assert {"apk.decode", "ghidra.functions", "r2.open", "web.open"} <= names, sorted(
        names
    )


@pytest.mark.parametrize(
    ("name", "param", "maximum", "policy"),
    _ROWS,
    ids=[row[0] for row in _ROWS],
)
def test_transport_deadline_covers_the_advertised_timeout(
    name: str, param: str, maximum: float, policy: float
) -> None:
    assert maximum <= _AGENT_CEILING_S, (
        f"{name}.{param} advertises a timeout maximum of {maximum:g}, which exceeds "
        f"the agent's {_AGENT_CEILING_S:g}s ceiling; the transport could never honour "
        "it. If this is a millisecond-valued bound it does not belong in this rule."
    )
    assert policy >= maximum, (
        f"{name} advertises `{param}` up to {maximum:g}s but its transport deadline is "
        f"only {policy:g}s, so the call is killed before that timeout can be reached. "
        "Raise its ResourcePolicy.timeout_seconds (see _TOOL_TIMEOUTS in catalog.py)."
    )
