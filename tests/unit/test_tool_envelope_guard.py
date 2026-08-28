"""The ``_dump`` envelope guard on every non-PE tool surface.

Each tool module funnels its handler's ``Result`` through a private ``_dump``
that insists the serialized envelope is a JSON object before it reaches the
transport. A handler that returned a bare list or scalar would otherwise be
forwarded as a malformed tool result; ``_dump`` turns that into a clear
``TypeError`` at the boundary. The happy path is exercised by every tool test,
so here we pin the refusal for the Android (apk/frida/device) and Web/JS
(web/js_wasm/proxy) surfaces.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest

_MODULES = [
    "headless_re_mcp.tools.apk",
    "headless_re_mcp.tools.frida",
    "headless_re_mcp.tools.device",
    "headless_re_mcp.tools.web",
    "headless_re_mcp.tools.js_wasm",
    "headless_re_mcp.tools.proxy",
]


class _Envelope:
    def __init__(self, value: Any) -> None:
        self._value = value

    def model_dump(self, mode: str = "json") -> Any:
        return self._value


@pytest.mark.parametrize("module_path", _MODULES)
def test_dump_passes_through_an_object_envelope(module_path: str) -> None:
    dump = importlib.import_module(module_path)._dump
    assert dump(_Envelope({"ok": True})) == {"ok": True}


@pytest.mark.parametrize("module_path", _MODULES)
def test_dump_rejects_a_non_object_envelope(module_path: str) -> None:
    dump = importlib.import_module(module_path)._dump
    # A handler whose envelope serialized to a list (or any non-dict) must be
    # refused at the boundary rather than forwarded as a malformed result.
    with pytest.raises(TypeError):
        dump(_Envelope([1, 2, 3]))
    with pytest.raises(TypeError):
        dump(_Envelope(SimpleNamespace()))
