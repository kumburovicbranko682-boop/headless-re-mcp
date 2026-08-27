"""frida.hook.template must name the probe fields it actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.tools.frida import build_frida_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _hook_return() -> str:
    source = Path(FridaClient.hook_template.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def hook_template(self, pid: int")
    chunk = source[start : source.index("def _attach_local(", start)]
    return chunk[chunk.rindex("return {") :]


def test_frida_hook_template_answers_with_loaded_not_hooked() -> None:
    """The catalog said destroy and named persisted, not the rest.

    Measured: hook_template returns pid, template, loaded, device plus
    persisted and note from _PROBE_DISCLOSURE. There is no hooked, handle
    or session. Looking for hooked after success retries a template that
    already unloaded.
    """
    returned = _hook_return()
    assert '"pid": pid' in returned
    assert '"template": template' in returned
    assert '"loaded": True' in returned
    assert '"device": "local"' in returned
    assert "**_PROBE_DISCLOSURE" in returned
    assert '"hooked"' not in returned
    assert '"handle"' not in returned
    disclosure = Path(FridaClient.hook_template.__code__.co_filename).read_text(encoding="utf-8")
    start = disclosure.index("_PROBE_DISCLOSURE = {")
    block = disclosure[start : disclosure.index("}", start) + 1]
    assert '"persisted": False' in block
    described = _tool_docstring("frida.hook.template")
    assert "Answers with pid" in described
    assert "loaded" in described
    assert "persisted" in described
    assert "no hooked" in described
