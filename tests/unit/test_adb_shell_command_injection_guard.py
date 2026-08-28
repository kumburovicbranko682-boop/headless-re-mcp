"""Every adb device-shell command is on a reviewed, injection-safe allowlist.

``adb/client.py`` deliberately exposes no raw-shell tool: each capability is a
named operation whose arguments are validated against strict patterns before
they reach ``device.shell`` (the module docstring: "a package name or serial
can never smuggle extra arguments"). That guarantee matters because a list
handed to adbutils' ``shell`` is *not* inherently safe -- adbutils joins it with
``list2cmdline`` (Windows-style quoting), which does not neutralise the POSIX
metacharacters (``;`` ``|`` ``&`` ``$(...)``) that the device's ``/system/bin/sh``
interprets. So the only thing standing between a caller-supplied string and a
command injection on the device is the discipline that every dynamic piece of a
shell command is a validated identifier or a numeric coercion.

That discipline was, until this guard, enforced only by prose and code review.
This test pins it three ways, the same freeze-the-surface idiom the pagination
and error-code taxonomy guards use:

1. ``device.shell`` may be reached only through the single ``_device_shell``
   chokepoint, so no call site can quietly bypass the vetting below.
2. The set of shell-command *templates* (constants kept verbatim, dynamic slots
   rendered as ``{expr}``) must equal a frozen, reviewed allowlist. Any new or
   changed shell command breaks the test, forcing a human to look at exactly the
   spot where an injection could enter and confirm each ``{...}`` slot is a
   validated value before adding it here.
3. Every interpolated slot must be a bare name or an ``int(...)`` / ``str(...)``
   coercion -- never a concatenation, subscript, nested f-string, or other shape
   that could carry an unvetted substring even within an allowlisted template.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

# The reviewed set of shell commands adb/client.py may run on a device. Each
# ``{expr}`` slot's value is validated or numeric at its call site:
#   {package}    -- _check_package / _PACKAGE_RE (via _apk_package_name)
#   {pkg}        -- _check_package(...) return value
#   {remote_path}-- re.match(r"^/[\w./\-]+$", ...) before use
#   {bind_host}  -- _BIND_HOST_RE.match(...) before use
#   {int(port)}  -- integer, range-checked 1..65535
#   {str(capped)}-- integer, clamped 1.._MAX_LOGCAT_LINES
# Changing this set means reviewing that invariant at the changed call site.
_EXPECTED_SHELL_TEMPLATES = frozenset(
    {
        "ps",
        "ps -A",
        "pm path {package}",
        "pidof {package}",
        "getprop",
        "getprop ro.product.model",
        "getprop ro.product.device",
        "getprop ro.build.version.sdk",
        "getprop ro.build.version.release",
        "getprop ro.product.cpu.abi",
        "pm list packages",
        "pm list packages -3",
        "monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
        "am force-stop {pkg}",
        "logcat -d -t {str(capped)}",
        "chmod 755 {remote_path}",
        "su -c 'nohup {remote_path} -l {bind_host}:{int(port)} >/dev/null 2>&1 &'",
    }
)


def _adb_client_source() -> str:
    path = Path(headless_re_mcp.__file__).parent / "backends" / "adb" / "client.py"
    return path.read_text(encoding="utf-8")


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_func(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(cur)
    return None


def _render(
    expr: ast.expr, fn: ast.FunctionDef | ast.AsyncFunctionDef | None
) -> tuple[list[str], list[ast.expr]]:
    """Render a shell-command argument to template strings + its dynamic slots.

    Returns a list because a ternary (``args = "a" if flag else "b"``) yields one
    template per branch. ``dynamic`` collects the interpolated sub-expressions so
    the slot-shape check can vet them directly rather than by re-parsing text.
    """
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value], []
    if isinstance(expr, ast.JoinedStr):
        parts: list[str] = []
        dynamic: list[ast.expr] = []
        for value in expr.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{" + ast.unparse(value.value) + "}")
                dynamic.append(value.value)
            else:  # pragma: no cover - defensive
                parts.append("{?}")
        return ["".join(parts)], dynamic
    if isinstance(expr, (ast.List, ast.Tuple)):
        tokens: list[str] = []
        dynamic = []
        for elt in expr.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                tokens.append(elt.value)
            else:
                tokens.append("{" + ast.unparse(elt) + "}")
                dynamic.append(elt)
        return [" ".join(tokens)], dynamic
    if isinstance(expr, ast.IfExp):
        body_t, body_d = _render(expr.body, fn)
        else_t, else_d = _render(expr.orelse, fn)
        return body_t + else_t, body_d + else_d
    if isinstance(expr, ast.Name):
        templates: list[str] = []
        dynamic = []
        found = False
        if fn is not None:
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == expr.id for t in node.targets
                ):
                    found = True
                    t, d = _render(node.value, fn)
                    templates += t
                    dynamic += d
        if not found:
            return ["{" + expr.id + "}"], [expr]
        return templates, dynamic
    return ["{" + ast.unparse(expr) + "}"], [expr]


def _shell_calls(
    tree: ast.AST, parents: dict[ast.AST, ast.AST]
) -> tuple[list[str], list[ast.expr]]:
    """(templates, dynamic slots) across every ``_device_shell(dev, cmd, ...)``."""
    templates: list[str] = []
    dynamic: list[ast.expr] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Name) or func.id != "_device_shell":
            continue
        assert len(node.args) >= 2, ast.unparse(node)
        fn = _enclosing_func(node, parents)
        rendered, slots = _render(node.args[1], fn)
        templates += rendered
        dynamic += slots
    return templates, dynamic


def _is_simple_slot(node: ast.expr) -> bool:
    """A bare name, or ``int(name)`` / ``str(name)`` -- nothing else."""
    if isinstance(node, ast.Name):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"int", "str"}
    ):
        return len(node.args) == 1 and isinstance(node.args[0], ast.Name)
    return False


def test_device_shell_is_the_only_path_to_shell() -> None:
    """No ``.shell(...)`` outside the ``_device_shell`` chokepoint.

    If a call site reaches ``device.shell`` directly it skips the template
    allowlist entirely, so a raw f-string command could be introduced without
    this guard ever seeing it.
    """
    tree = ast.parse(_adb_client_source())
    parents = _parents(tree)
    chokepoint = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_device_shell"
    )
    stray: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "shell":
            continue
        fn = _enclosing_func(node, parents)
        if fn is not chokepoint:
            stray.append(ast.unparse(node))
    assert stray == [], (
        "these `.shell(...)` calls bypass the _device_shell chokepoint, so their "
        "command is never vetted by the injection allowlist: " + str(stray)
    )


def test_scan_finds_the_known_shell_commands() -> None:
    """Non-vacuity: the scan reaches the real call sites, so a broken renderer
    cannot let the allowlist check pass on an empty set."""
    tree = ast.parse(_adb_client_source())
    templates, _ = _shell_calls(tree, _parents(tree))
    seen = set(templates)
    # Both a list-built command and the interpolated su -c launch line, plus a
    # spread across the surface, must be present.
    assert "pm path {package}" in seen, sorted(seen)
    assert (
        "su -c 'nohup {remote_path} -l {bind_host}:{int(port)} >/dev/null 2>&1 &'"
        in seen
    ), sorted(seen)
    assert len(seen) >= 15, f"scan looks broken, only saw {sorted(seen)}"


def test_every_adb_shell_command_is_on_the_reviewed_allowlist() -> None:
    tree = ast.parse(_adb_client_source())
    templates, _ = _shell_calls(tree, _parents(tree))
    seen = set(templates)
    unexpected = sorted(seen - _EXPECTED_SHELL_TEMPLATES)
    missing = sorted(_EXPECTED_SHELL_TEMPLATES - seen)
    assert not unexpected, (
        "adb/client.py runs a device-shell command not on the reviewed allowlist. "
        "Every `{...}` slot must be a validated identifier or a numeric coercion "
        "(a list arg is NOT injection-safe -- adbutils joins it without POSIX "
        "quoting). Confirm the new command's slots are validated, then add it to "
        f"_EXPECTED_SHELL_TEMPLATES: {unexpected}"
    )
    assert not missing, (
        "an allowlisted shell command is no longer emitted; drop it from "
        f"_EXPECTED_SHELL_TEMPLATES so the set stays a live record: {missing}"
    )


def test_every_interpolated_slot_is_a_bare_name_or_numeric_coercion() -> None:
    tree = ast.parse(_adb_client_source())
    _, dynamic = _shell_calls(tree, _parents(tree))
    complex_slots = sorted(
        ast.unparse(node) for node in dynamic if not _is_simple_slot(node)
    )
    assert complex_slots == [], (
        "these interpolated shell-command slots are not a bare name or an "
        "int()/str() coercion; a concatenation, subscript, or nested f-string can "
        "carry an unvetted substring past the validators into the device shell: "
        + str(complex_slots)
    )
