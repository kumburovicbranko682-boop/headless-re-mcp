"""Every non-PE caller-facing method that takes a ``timeout`` must reach a clamp.

``test_non_pe_timeout_schema_bounds`` pins the *advertised* half: the schema
declares ``timeout`` with a finite maximum. But that schema runs only on the MCP
transport; the agent and OpenAI-bridge transports call the backend handlers
directly and skip it. On those paths the only thing keeping a caller-supplied
``timeout=1e9`` from parking a shared worker effectively forever -- or, handed
straight to ``page.goto`` / ``run_bounded`` / a frida attach, outliving every
other bound in the system -- is the backend's own clamp: ``clamp_cli_timeout``
for the CLIs, ``_bound_nav_timeout`` for the browser, ``_bound_timeout`` for
frida. A wedged call that never returns is the one failure an unattended mission
cannot recover from, so this runtime backstop matters even more than the
limit/offset one its sibling guard pins.

That backstop exists in every reader today, but reaching it is not always a
single inline call: the CLI readers delegate to a module-level ``_run`` that
clamps, ``jadx.decompile`` delegates to ``export_sources`` which delegates to
``_run``, ``jsre.beautify`` delegates to ``deobfuscate``, and the frida readers
delegate to ``_attach_local`` / ``_run_local_script`` which clamp. So this guard
does not look for a clamp *inside* each method; it builds the intra-module call
graph and asserts every ``timeout``-taking method on a public backend class can
*reach* one of the three clamp primitives through its own calls. A new reader
that takes a timeout and neither clamps it nor routes it to something that does
trips here, at the layer a schema-skipping transport actually hits.

The two ``timeout`` params on the private helper classes (``_Runner.call`` and
``_ProxyInstance.start``) are excluded by the public-class scoping: neither is a
caller input -- ``call`` receives a timeout its backend method already bounded,
and ``start`` uses a fixed internal default -- so requiring them to re-clamp
would be meaningless.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

_NON_PE_BACKENDS = frozenset(
    {"web", "proxy", "adb", "frida", "apk", "jsre", "jadx", "apktool"}
)

# The three functions that actually bound a timeout. A method is safe when its
# own calls can reach one of these; everything else (``_run``, ``_attach_local``,
# ``export_sources`` ...) is safe only by delegating, transitively, to one.
_CLAMP_PRIMITIVES = frozenset(
    {"clamp_cli_timeout", "_bound_nav_timeout", "_bound_timeout"}
)


def _backends_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent / "backends"


def _arg_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = fn.args
    names: set[str] = set()
    for group in (args.posonlyargs, args.args, args.kwonlyargs):
        names.update(arg.arg for arg in group)
    return names


def _direct_call_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names this function calls in its own body, not descending into closures.

    The clamp and the delegation both happen at the method's own statement level
    (``deadline = _bound_timeout(...)``, ``return self._run(...)``); the inner
    ``work``/``use`` closures only touch the driver. Skipping nested functions
    keeps their calls from muddying the call graph.
    """
    names: set[str] = set()

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name):
                    names.add(func.id)
                elif isinstance(func, ast.Attribute):
                    names.add(func.attr)
            visit(child)

    visit(fn)
    return names


def _module_call_graph(tree: ast.AST) -> dict[str, set[str]]:
    """name -> the names it directly calls, over every def in the module."""
    graph: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            graph.setdefault(node.name, set()).update(_direct_call_names(node))
    return graph


def _safe_names(graph: dict[str, set[str]]) -> set[str]:
    """Fixed point: names that call a clamp primitive, or reach one via calls."""
    safe = {name for name, calls in graph.items() if calls & _CLAMP_PRIMITIVES}
    changed = True
    while changed:
        changed = False
        for name, calls in graph.items():
            if name not in safe and (calls & safe):
                safe.add(name)
                changed = True
    return safe


def _scan() -> dict[tuple[str, str], bool]:
    """(backend, method) -> whether a public-class timeout method reaches a clamp."""
    result: dict[tuple[str, str], bool] = {}
    for path in sorted(_backends_dir().glob("*/client.py")):
        backend = path.parent.name
        if backend not in _NON_PE_BACKENDS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        graph = _module_call_graph(tree)
        safe = _safe_names(graph)
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef) or cls.name.startswith("_"):
                continue
            for node in cls.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if "timeout" in _arg_names(node):
                    result[(backend, node.name)] = node.name in safe
    return result


def test_scan_reaches_and_recognises_the_known_timeout_methods() -> None:
    """Non-vacuity, both directions: the scan finds the known timeout methods --
    including the pure-delegation ones (``jadx.decompile``, ``jsre.beautify``)
    that exercise the transitive reachability -- and marks their real clamps
    reachable, so the violation guard below cannot pass by finding nothing or by
    a checker that is stuck on.
    """
    scanned = _scan()
    expected = {
        ("web", "open"),  # inline _bound_nav_timeout
        ("frida", "attach"),  # delegates to _attach_local
        ("frida", "modules"),  # delegates to _run_local_script
        ("apktool", "decode"),  # delegates to module-level _run
        ("jadx", "decompile"),  # decompile -> export_sources -> _run
        ("jsre", "beautify"),  # beautify -> deobfuscate -> _run
    }
    assert expected <= set(scanned), (
        f"the timeout-method scan looks broken, saw {sorted(scanned)}"
    )
    assert all(scanned[key] for key in expected), {
        key: scanned[key] for key in expected
    }


def test_every_non_pe_timeout_method_reaches_a_backend_clamp() -> None:
    scanned = _scan()
    unclamped = sorted(key for key, ok in scanned.items() if not ok)
    assert unclamped == [], (
        "these non-PE backend methods take a `timeout` but no call path from them "
        "reaches clamp_cli_timeout / _bound_nav_timeout / _bound_timeout, so a "
        "transport skipping the schema could hand them an unbounded wait that "
        f"parks a worker or outlives every other bound: {unclamped}"
    )
