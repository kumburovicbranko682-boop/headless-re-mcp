"""Every non-PE paginated reader must clamp ``limit`` and floor ``offset`` at the
backend, not merely in its schema.

``test_non_pe_pagination_schema_bounds`` pins the *advertised* half of the
contract: the pydantic schema declares ``limit`` with a maximum and ``offset``
with a minimum of 0. But that schema runs only on the MCP transport; the agent
and OpenAI-bridge transports call the backend handlers directly and skip it. On
those paths the schema's ceiling is not enforced, so the *runtime backstop* --
the backend's own ``max(1, min(int(limit), MAX))`` clamp and ``max(0,
int(offset))`` floor -- is the only thing standing between a caller-supplied
``limit=10**9`` and a reader that tries to materialise everything, or a negative
``offset`` and a Python slice that wraps to the end and returns the wrong page.

That backstop exists in every reader today, but it was pinned only piecemeal
(``test_apk_clamp_page``, ``test_device_logcat_bounds``, ``test_frida_java_input_bounds``
and the per-backend envelope tests). A newly added reader could declare a bounded
schema -- satisfying the schema guard -- yet forget the backend clamp, and
nothing would catch it. This is the source-scan sibling of that schema guard and
of ``test_non_pe_error_conversion_guard``: it reads each non-PE backend client and
fails if any method taking a ``limit`` never routes it through ``min(...)`` (or the
shared ``_clamp_page`` helper), or any method taking an ``offset`` never floors it
through ``max(...)`` (or that helper). The accepted forms are exactly the two the
codebase uses -- an inline ``min``/``max`` naming the param, or a ``_clamp_page``
call that clamps both -- so a reader that trusts the schema and drops the runtime
clamp trips here the moment it lands.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

# The non-PE backend package dirs (each holds a client.py). jadx/apktool have no
# limit/offset readers today but are scanned so a future one there is covered too.
_NON_PE_BACKENDS = frozenset(
    {"web", "proxy", "adb", "frida", "apk", "jsre", "jadx", "apktool"}
)

# Shared clamp helper: a call to it clamps both offset and limit, so a reader
# that delegates to it (the apk.* readers do) satisfies both checks.
_CLAMP_HELPERS = frozenset({"_clamp_page"})

# (backend, method) pairs exempt from the runtime clamp. Empty by design -- a new
# entry is the deliberate, documented decision this guard exists to force, the
# same fail-closed shape as the schema guard's _UNBOUNDED_NUMERIC_OK.
_CLAMP_EXEMPT: frozenset[tuple[str, str]] = frozenset()


def _backends_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent / "backends"


def _arg_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every parameter name a function declares (positional, normal, kw-only)."""
    args = fn.args
    names: set[str] = set()
    for group in (args.posonlyargs, args.args, args.kwonlyargs):
        names.update(arg.arg for arg in group)
    return names


def _calls_a_helper(node: ast.AST) -> bool:
    """True when the body calls one of the shared clamp helpers by name."""
    return any(
        isinstance(sub, ast.Call)
        and isinstance(sub.func, ast.Name)
        and sub.func.id in _CLAMP_HELPERS
        for sub in ast.walk(node)
    )


def _builtin_call_names_param(node: ast.AST, builtin: str, param: str) -> bool:
    """True when a ``builtin(...)`` call anywhere in ``node`` references ``param``.

    This is the clamp shape the readers use -- ``min(int(limit), MAX)`` /
    ``max(0, int(offset))`` -- where the param sits (possibly wrapped in
    ``int()``) inside the builtin's argument subtree.
    """
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == builtin
            and any(isinstance(n, ast.Name) and n.id == param for n in ast.walk(sub))
        ):
            return True
    return False


def _clamps_limit(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return _builtin_call_names_param(fn, "min", "limit") or _calls_a_helper(fn)


def _floors_offset(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return _builtin_call_names_param(fn, "max", "offset") or _calls_a_helper(fn)


def _scan() -> tuple[dict[tuple[str, str], bool], dict[tuple[str, str], bool]]:
    """Return two maps: (backend, method) -> whether limit is clamped / offset floored.

    Scoped to backend *class methods* -- the caller-facing readers on
    WebBackend / ProxyBackend / AdbBackend / FridaBackend / ApkClient / JsClient
    that receive the raw caller ``limit`` / ``offset`` and fetch against it.
    Module-level slicing helpers (``_page``, ``_cap_names``, ``_capped_file_listing``)
    also take a ``limit``, but it is the page size the reader has *already*
    clamped before handing them an in-memory list, so re-clamping there would be
    meaningless; the ``_clamp_page`` helper the readers delegate to is likewise
    module-level. Only methods that declare the param are included, so a broken
    scan shows up as a missing key rather than a vacuous pass.
    """
    limit_methods: dict[tuple[str, str], bool] = {}
    offset_methods: dict[tuple[str, str], bool] = {}
    for path in sorted(_backends_dir().glob("*/client.py")):
        backend = path.parent.name
        if backend not in _NON_PE_BACKENDS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for node in cls.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                names = _arg_names(node)
                key = (backend, node.name)
                if "limit" in names:
                    limit_methods[key] = _clamps_limit(node)
                if "offset" in names:
                    offset_methods[key] = _floors_offset(node)
    return limit_methods, offset_methods


def test_scan_reaches_and_recognises_the_known_paginated_readers() -> None:
    """Non-vacuity, both directions: the scan must find the well-known readers,
    and its clamp detector must return True for their real (inline and helper)
    clamps -- otherwise the violation guards below would pass by finding nothing
    to check, or by a detector that is stuck on.
    """
    limit_methods, offset_methods = _scan()

    expected_limit = {
        ("web", "network_list"),
        ("proxy", "flows"),
        ("apk", "classes"),  # clamps via the _clamp_page helper
        ("frida", "modules"),  # clamps inline via min()
        ("adb", "properties"),
        ("jsre", "unpack_bundle"),
    }
    assert expected_limit <= set(limit_methods), (
        f"the limit-reader scan looks broken, saw {sorted(limit_methods)}"
    )
    # The detector recognises both clamp forms as clamped.
    assert all(limit_methods[key] for key in expected_limit), {
        key: limit_methods[key] for key in expected_limit
    }

    expected_offset = {
        ("web", "network_list"),
        ("proxy", "flows"),
        ("apk", "classes"),
        ("jsre", "unpack_bundle"),
        ("frida", "applications"),
    }
    assert expected_offset <= set(offset_methods), (
        f"the offset-reader scan looks broken, saw {sorted(offset_methods)}"
    )
    assert all(offset_methods[key] for key in expected_offset), {
        key: offset_methods[key] for key in expected_offset
    }


def test_every_non_pe_limit_param_is_clamped_at_the_backend() -> None:
    limit_methods, _ = _scan()
    unclamped = sorted(
        key for key, ok in limit_methods.items() if not ok and key not in _CLAMP_EXEMPT
    )
    assert unclamped == [], (
        "these non-PE backend readers take a `limit` but never route it through "
        "min(...) or _clamp_page, so a transport skipping the schema could hand "
        f"them an unbounded page size as 'return everything': {unclamped}"
    )


def test_every_non_pe_offset_param_is_floored_at_the_backend() -> None:
    _, offset_methods = _scan()
    unfloored = sorted(
        key for key, ok in offset_methods.items() if not ok and key not in _CLAMP_EXEMPT
    )
    assert unfloored == [], (
        "these non-PE backend readers take an `offset` but never floor it through "
        "max(...) or _clamp_page, so a negative offset from a schema-skipping "
        f"transport would slice from the end and return the wrong page: {unfloored}"
    )
