"""ui.click_at must name the fields the click helper actually returns."""from __future__ import annotationsimport astfrom pathlib import Pathfrom headless_re_mcp.core.ui_win32 import click_hwnd_atfrom headless_re_mcp.tools.ui import build_ui_toolsdef _tool_docstring(name: str) -> str:
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
    return ""def test_ui_click_at_puts_the_point_in_x_y_not_clicked() -> None:
    """The catalog said background click and never named the payload.

    Measured: click_hwnd_at returns hwnd, action, x, y, backend,
    foreground_required and injection_required. There is no clicked field
    and no client_x/client_y. Looking for clicked after a successful
    PostMessage reads as a miss, so the overnight driver clicks the same
    client point again.
    """
    source = Path(click_hwnd_at.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def click_hwnd_at(")
    chunk = source[start : source.index("def close_hwnd(", start)]
    returned = chunk[chunk.rindex("return {") :]
    assert '"hwnd"' in returned
    assert '"action"' in returned
    assert '"x"' in returned
    assert '"y"' in returned
    assert '"backend"' in returned
    assert '"clicked"' not in returned
    assert '"client_x"' not in returned
    described = _tool_docstring("ui.click_at")
    assert "Answers with hwnd" in described
    assert " x" in described or ", x," in described
    assert "no clicked" in described.replace("\n", " ")
