"""The tool layer's ``_dump`` guard: every envelope must be a JSON object.

Each non-PE tool module wraps its service call and hands the result to the MCP
transport through a private ``_dump`` that serializes the ``Result`` and refuses
anything that is not a JSON object. A real envelope always serializes to a dict,
so the guard is a defensive floor -- but it is the floor the transport relies on,
and it was unpinned: the ``raise TypeError`` fired for no test, so a change that
let a non-object envelope through (a bare list, a scalar) would pass silently.

These are pure: no service, no session, no tool launch -- just the serializer
contract, proven for every non-PE tool surface at once.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from headless_re_mcp.core.results import _success

# The non-PE tool surfaces: Android (apk/device/frida), web, proxy, JS/WASM, the
# shared dynamic-analysis surface, and the native reverse-engineering line
# (radare2 and Ghidra, which read ELF/Mach-O as well as PE). Each carries its own
# copy of _dump. The PE-only surfaces are excluded on purpose: tools.dynamic
# fronts the Windows x64dbg RPC and tools.meta the IDA address-sync tools.
_NON_PE_TOOL_MODULES = [
    "headless_re_mcp.tools.apk",
    "headless_re_mcp.tools.device",
    "headless_re_mcp.tools.frida",
    "headless_re_mcp.tools.js_wasm",
    "headless_re_mcp.tools.proxy",
    "headless_re_mcp.tools.web",
    "headless_re_mcp.tools.dynamic_analysis",
    "headless_re_mcp.tools.r2",
    "headless_re_mcp.tools.ghidra",
]


@pytest.mark.parametrize("module_name", _NON_PE_TOOL_MODULES)
def test_dump_passes_a_real_envelope_through_as_an_object(module_name: str) -> None:
    module = importlib.import_module(module_name)
    dumped = module._dump(_success({"value": 1}))
    assert isinstance(dumped, dict)
    assert dumped["ok"] is True
    assert dumped["data"] == {"value": 1}


@pytest.mark.parametrize("module_name", _NON_PE_TOOL_MODULES)
def test_dump_rejects_an_envelope_that_is_not_an_object(module_name: str) -> None:
    module = importlib.import_module(module_name)
    # A stand-in whose serialization is a JSON array, not an object: the guard
    # must reject it rather than hand the transport a non-object envelope.
    not_an_object = SimpleNamespace(model_dump=lambda mode="json": [1, 2, 3])
    with pytest.raises(TypeError, match="did not serialize to an object"):
        module._dump(not_an_object)
