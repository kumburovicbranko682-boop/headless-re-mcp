"""Read-only mode has to bind to the real tool surface, not just a probe.

`test_write_policy.py` pins the *mechanism* on a synthetic one-tool catalog: a
read-only deployment refuses a write and allows a read. What it cannot catch is
the surface drifting away from that mechanism -- a tool filed under the wrong
effect. A write tool misfiled as read-only stays writable in a read-only
deployment (the exact failure `local_full_access` exists to prevent), and a read
tool that somehow acquires the guard would make read-only mode refuse the reads
it is supposed to serve. These exercise every bound tool so the per-tool
read/write classification cannot silently diverge from what the guard enforces.
"""

from __future__ import annotations

import contextlib
import io
from typing import Any

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

# artifacts.gc would do real deletion under full access, so it is never invoked
# with full access here. Under read-only it is safe: the guard refuses before the
# handler runs, which is exactly what the refusal test needs to prove.
UNSAFE_UNDER_FULL_ACCESS = {"artifacts.gc"}

DUMMY: dict[str, Any] = {
    "string": "\u0000nonexistent",
    "integer": 0,
    "number": 0.0,
    "boolean": False,
    "array": [],
    "object": {},
}


def _hostile_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    properties = schema.get("properties") or {}
    for name in schema.get("required") or []:
        prop = properties.get(name) or {}
        kind = prop.get("type")
        if isinstance(kind, list):
            kind = kind[0]
        if name == "session_id":
            arguments[name] = "does-not-exist"
        elif kind in DUMMY:
            arguments[name] = DUMMY[kind]
        elif prop.get("enum"):
            arguments[name] = prop["enum"][0]
        else:
            arguments[name] = "does-not-exist"
    return arguments


def _invoke(name: str, catalog: CommandCatalog) -> dict[str, Any]:
    # The write guard lives on the *bound catalog spec*, not on the raw factory
    # binding: bind_all_tools registers `guard_write(handler)` into the catalog
    # while handing back the unwrapped handler. Reading the policy means going
    # through the catalog's handler, which is what every real transport does.
    spec = catalog.get(name)
    assert spec is not None and spec.handler is not None
    arguments = _hostile_arguments(spec.input_schema or {})
    # Handlers may log while failing; that is not what these assert.
    with (
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        return spec.handler(**arguments)


def _error_code(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    error = result.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) else None


def test_every_write_tool_is_refused_when_the_deployment_is_read_only() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        # Flip after binding: the guard reads the flag per call, so a running
        # server can be put read-only without rebuilding the surface.
        catalog.write_allowed = False

        write_tools = 0
        offenders: list[str] = []
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            if not spec.write:
                continue
            write_tools += 1
            # Safe even for artifacts.gc: the guard short-circuits before any work.
            result = _invoke(binding.name, catalog)
            refused = (
                isinstance(result, dict)
                and result.get("ok") is False
                and _error_code(result) == "write_disabled"
            )
            if not refused:
                offenders.append(f"{binding.name}: {result!r}")
        assert write_tools > 0, "no write tools were bound; the classification looks empty"
        assert offenders == [], offenders
    finally:
        analysis.close_all()


def test_no_read_tool_is_refused_when_the_deployment_is_read_only() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        catalog.write_allowed = False

        read_tools = 0
        refused: list[str] = []
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            if spec.write:
                continue
            read_tools += 1
            result = _invoke(binding.name, catalog)
            # A read tool is never wrapped by the guard, so it can fail on the
            # bad session but must never come back as write_disabled.
            if _error_code(result) == "write_disabled":
                refused.append(binding.name)
        assert read_tools > 0, "no read tools were bound; the classification looks empty"
        assert refused == [], refused
    finally:
        analysis.close_all()


def test_write_tools_reach_their_handler_under_full_access() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        # Default settings leave local_full_access on, so write_allowed is True.
        assert catalog.write_allowed is True

        checked = 0
        wrongly_refused: list[str] = []
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            if not spec.write or binding.name in UNSAFE_UNDER_FULL_ACCESS:
                continue
            checked += 1
            result = _invoke(binding.name, catalog)
            # It runs and fails on the hostile session/args -- what it must not do
            # is get short-circuited as write_disabled while full access is on.
            if _error_code(result) == "write_disabled":
                wrongly_refused.append(binding.name)
        assert checked > 0
        assert wrongly_refused == [], wrongly_refused
    finally:
        analysis.close_all()


def test_the_guarded_surface_matches_the_write_classification() -> None:
    """The guard is applied per tool from `spec.write`; nothing else may decide it.

    If the guarded set and the write-classified set ever differ, either a write
    tool escaped the guard or a read tool acquired it -- both are silent policy
    holes, so they are pinned to equality rather than probed one by one.
    """

    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        catalog.write_allowed = False

        guarded: set[str] = set()
        classified_write: set[str] = set()
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            if spec.write:
                classified_write.add(binding.name)
            if _error_code(_invoke(binding.name, catalog)) == "write_disabled":
                guarded.add(binding.name)
        assert guarded == classified_write
    finally:
        analysis.close_all()
