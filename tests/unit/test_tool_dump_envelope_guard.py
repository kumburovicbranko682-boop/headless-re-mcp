"""Every non-PE tool module's ``_dump`` refuses an envelope that is not an object.

Each protocol-independent tool module turns a :class:`Result` into a plain dict
via a private ``_dump`` helper before handing it to the MCP layer. The helper
asserts the serialised envelope is a JSON object and raises ``TypeError`` if it
is not, because a caller that receives a bare list or scalar where an
``ok/data/error/meta`` object is promised cannot tell success from failure. The
guard is the same across the Android (``apk``/``device``/``frida``), web
(``web``/``js_wasm``/``proxy``) and radare2/Ghidra (``r2``/``ghidra``) surfaces;
this pins that contract on all of them at once so a refactor cannot quietly drop
it from one module.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

# The non-PE tool modules, one per track dimension. Each exposes a module-level
# ``_dump`` with the identical envelope-shape guard.
_MODULES = [
    "headless_re_mcp.tools.apk",
    "headless_re_mcp.tools.device",
    "headless_re_mcp.tools.frida",
    "headless_re_mcp.tools.js_wasm",
    "headless_re_mcp.tools.web",
    "headless_re_mcp.tools.proxy",
    "headless_re_mcp.tools.r2",
    "headless_re_mcp.tools.ghidra",
    # The work-direction selector that gates the Android/Web tool surface.
    "headless_re_mcp.tools.workspace",
]


class _NotAnObject:
    """Stand-in Result whose serialisation is a list, not an object."""

    def model_dump(self, *, mode: str = "python") -> Any:
        return ["not", "an", "object"]


class _AnObject:
    def model_dump(self, *, mode: str = "python") -> Any:
        return {"ok": True, "data": None, "error": None, "meta": {}}


@pytest.mark.parametrize("module_name", _MODULES)
def test_dump_rejects_a_non_object_envelope(module_name: str) -> None:
    module = importlib.import_module(module_name)
    with pytest.raises(TypeError, match="did not serialize to an object"):
        module._dump(_NotAnObject())  # type: ignore[attr-defined]


@pytest.mark.parametrize("module_name", _MODULES)
def test_dump_passes_a_real_object_envelope_through(module_name: str) -> None:
    module = importlib.import_module(module_name)
    dumped = module._dump(_AnObject())  # type: ignore[attr-defined]
    assert dumped == {"ok": True, "data": None, "error": None, "meta": {}}


def test_detection_report_to_dict_carries_the_same_envelope_guard() -> None:
    """DetectionReport.to_dict promises an object and refuses anything else.

    The detection report is handed to callers as a plain dict the same way tool
    envelopes are; a serialisation that came back as a list would be sliced and
    key-accessed downstream with confusing errors. Pydantic's own model_dump
    always returns a dict, so the guard is reached through a subclass whose
    serialisation is broken -- the same shape a hostile refactor would produce.
    """
    from headless_re_mcp.detection.models import DetectionReport

    class _Broken(DetectionReport):
        def model_dump(self, **_kwargs: Any) -> Any:  # type: ignore[override]
            return ["not", "an", "object"]

    with pytest.raises(TypeError, match="did not serialize to an object"):
        _Broken.model_construct().to_dict()
