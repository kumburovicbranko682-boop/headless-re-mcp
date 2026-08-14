"""ui.text.set must name the fields the setter actually returns."""from __future__ import annotationsimport astfrom pathlib import Pathfrom headless_re_mcp.core.ui_uia import set_value_uiafrom headless_re_mcp.core.ui_win32 import set_window_textfrom headless_re_mcp.tools.ui import build_ui_toolsdef _tool_docstring(name: str) -> str:
    source = Path(build_ui_tools.__code__.co_filename).read_text(encoding="utf-8")
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
    return ""def test_ui_text_set_puts_the_result_in_action_not_set() -> None:
    """The catalog said set text and never named the payload.

    Measured: set_window_text and set_value_uia return hwnd, action, text
    and backend. There is no set field. Looking for set after a successful
    WM_SETTEXT reads as a miss, so the overnight driver posts the same
    string again.
    """
    win32 = Path(set_window_text.__code__.co_filename).read_text(encoding="utf-8")
    start = win32.index("def set_window_text(")
    chunk = win32[start : win32.index("def get_window_text(", start)]
    returned = chunk[chunk.rindex("return {") :]
    assert '"hwnd"' in returned
    assert '"action"' in returned
    assert '"text"' in returned
    assert '"backend"' in returned
    assert '"set"' not in returned
    uia = Path(set_value_uia.__code__.co_filename).read_text(encoding="utf-8")
    ustart = uia.index("def set_value_uia(")
    unext = uia.find("\ndef ", ustart + 1)
    uchunk = uia[ustart:] if unext == -1 else uia[ustart:unext]
    uret = uchunk[uchunk.rindex("return {") :]
    assert '"hwnd"' in uret
    assert '"action"' in uret
    assert '"set"' not in uret
    described = _tool_docstring("ui.text.set")
    assert "Answers with hwnd" in described
    assert "action" in described
    assert "no set field" in described.replace("\n", " ")
