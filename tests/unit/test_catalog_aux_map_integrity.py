"""The catalog's auxiliary name maps must not reference phantom tools.

``_declared_spec`` builds every ``CommandSpec`` from ``_ALL_TOOL_NAMES`` (guarded
at import by the ``len(...) != 265`` assertion), and it reaches into three
side tables while doing so:

* ``_WEB_NAMES`` -- grants the legacy Web transport,
* ``_SERVICE_OVERRIDES`` -- redirects a tool to a differently named service
  method, and
* ``_TOOL_TIMEOUTS`` -- raises a tool's resource-policy timeout above the
  60-second default.

All three are consulted with ``in`` / ``.get(...)``, so a key that is *not* a
real tool name is simply never read. Nothing raises. That makes them the exact
"phantom reference" drift the effect-policy ``len`` check protects the three
effect sets from, except here the failure is silent: rename ``static.open`` in
``_FILE_WRITE_NAMES`` without updating ``_TOOL_TIMEOUTS`` and the renamed tool
quietly falls back to the 60s ceiling that the 1800s override existed to lift;
drop a tool from the tool sets but leave it in ``_WEB_NAMES`` and the stray
entry evaporates instead of erroring. ``test_web_command_adapter.py`` only
asserts the adapter's write methods equal ``write_names(WEB)`` -- both sides are
derived from the same built specs, so a stray key that never became a spec is
invisible there.

These tests lock every side-table key to a real tool *and* to the effect it is
supposed to have on the built spec, so a rename that forgets one of the maps
fails loudly instead of shipping a silent transport/timeout regression.
"""

from __future__ import annotations

from headless_re_mcp.tools import catalog as catalog_module
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport


def test_every_web_name_is_a_real_tool_that_gets_the_web_transport() -> None:
    web_specs = {
        spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.WEB)
    }
    # Equality (not just subset) also catches a WEB spec that lost its
    # _WEB_NAMES entry, and confirms _WEB_NAMES is the sole source of the Web
    # transport rather than a stale mirror of it.
    assert web_specs == set(catalog_module._WEB_NAMES), (
        "the set of Web-transport tools diverged from _WEB_NAMES: "
        f"{web_specs ^ set(catalog_module._WEB_NAMES)}"
    )


def test_every_service_override_key_redirects_a_real_tool() -> None:
    offenders: dict[str, str] = {}
    for name, method in catalog_module._SERVICE_OVERRIDES.items():
        spec = COMMAND_CATALOG.get(name)
        if spec is None:
            offenders[name] = "not a catalog tool"
        elif spec.service_method != method:
            offenders[name] = f"override {method!r} not applied (got {spec.service_method!r})"
    assert not offenders, f"_SERVICE_OVERRIDES has phantom or unwired keys: {offenders}"


def test_every_tool_timeout_key_raises_a_real_tool_above_the_default() -> None:
    offenders: dict[str, str] = {}
    for name, timeout in catalog_module._TOOL_TIMEOUTS.items():
        spec = COMMAND_CATALOG.get(name)
        if spec is None:
            offenders[name] = "not a catalog tool"
        elif spec.resource_policy.timeout_seconds != timeout:
            offenders[name] = (
                f"timeout {timeout} not applied (got {spec.resource_policy.timeout_seconds})"
            )
    assert not offenders, f"_TOOL_TIMEOUTS has phantom or unwired keys: {offenders}"
