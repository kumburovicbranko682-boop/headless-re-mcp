"""Every non-PE tool that takes a `timeout` must bound it above and below.

The non-PE lines drive a browser, a device, external CLIs and a JVM, and each
call runs on a shared worker. A caller-supplied timeout is the ceiling on how
long one of those workers can be parked, so an unbounded or absurd value (a bare
``timeout: float``, a negative one, ``1e9``) is a denial-of-service vector: it
either pins a worker effectively forever or, if handed straight to a driver,
lets a wedged call outlive every other bound in the system. Fifteen non-PE
operations expose a timeout today -- the web drivers (open / navigate / click /
type / wait), the JS/WASM CLIs (js.deobfuscate / beautify / unpack_bundle,
wasm.wat / info) and the APK tools (decompile / decode / repack / sign /
export_sources) -- and every one declares ``Field(gt=0, le=...)`` so the MCP
path refuses a bad value up front.

This is that invariant made a drift guard, a sibling of the port and pagination
guards: it scans the whole non-PE tool surface and fails if any tool exposes a
``timeout`` that is not a number with a non-negative lower bound and a finite
upper bound. A new tool cannot ship an unbounded wait, and cannot silently drop
the ceiling its siblings all carry.
"""

from __future__ import annotations

import math
from typing import Any, cast

from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.web import build_web_tools
from headless_re_mcp.tools.workspace import build_workspace_tools

# Every builder that makes up the non-PE surface. Each takes the live service
# only so its handlers can close over it; input_schema_for reads the signature
# alone, so a dummy stands in and no backend has to be present.
_NON_PE_BUILDERS = (
    build_web_tools,
    build_proxy_tools,
    build_device_tools,
    build_frida_tools,
    build_apk_tools,
    build_js_wasm_tools,
    build_workspace_tools,
)


def _non_pe_timeout_properties() -> dict[str, dict[str, Any]]:
    """Map every non-PE tool that declares a ``timeout`` param to that schema."""
    found: dict[str, dict[str, Any]] = {}
    for builder in _NON_PE_BUILDERS:
        for bound in builder(cast(Any, object())):
            schema = input_schema_for(bound.handler)
            timeout = schema.get("properties", {}).get("timeout")
            if timeout is not None:
                found[bound.name] = timeout
    return found


def _lower_bound_ok(timeout: dict[str, Any]) -> bool:
    """A positive floor: exclusiveMinimum >= 0 (gt=0) or minimum > 0 (ge=... )."""
    excl = timeout.get("exclusiveMinimum")
    incl = timeout.get("minimum")
    if excl is not None and excl >= 0:
        return True
    return incl is not None and incl > 0


def test_every_non_pe_timeout_param_is_bounded_above_and_below() -> None:
    timeouts = _non_pe_timeout_properties()

    # The scan must actually see the known timeout-bearing tools -- otherwise a
    # broken enumeration would make this guard vacuously pass.
    known = {"web.open", "web.wait", "js.deobfuscate", "wasm.info", "apk.decompile"}
    assert known <= set(timeouts), (
        f"expected the known timeout tools in the scan, saw {sorted(timeouts)}"
    )

    for name, timeout in timeouts.items():
        assert timeout.get("type") == "number", (
            f"{name}: timeout must be a number, got {timeout}"
        )
        # A lower floor keeps 0 and negatives out: a zero-second wait is a
        # degenerate refusal and a negative one is nonsense.
        assert _lower_bound_ok(timeout), (
            f"{name}: timeout needs a non-negative lower bound, got {timeout}"
        )
        # A finite ceiling is the whole point: it is the cap on how long a shared
        # worker can be parked. A bare float (no maximum) or an infinite one trips.
        maximum = timeout.get("maximum")
        assert maximum is not None, f"{name}: timeout must declare a maximum, got {timeout}"
        assert isinstance(maximum, (int, float)) and not isinstance(maximum, bool), (
            f"{name}: timeout maximum must be numeric, got {maximum!r}"
        )
        assert math.isfinite(maximum) and maximum > 0, (
            f"{name}: timeout maximum must be finite and positive, got {maximum}"
        )
