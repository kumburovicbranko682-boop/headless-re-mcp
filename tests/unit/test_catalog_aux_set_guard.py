"""The catalog's name-keyed side tables must not drift from the real tool set.

``_WEB_NAMES``, ``_SERVICE_OVERRIDES`` and ``_TOOL_TIMEOUTS`` are keyed by tool
name but consulted with ``in`` / ``.get`` against the declared tool set rather
than iterated. A key that no longer names a real tool is therefore *silently*
dead config -- a mistyped ``_WEB_NAMES`` entry never grants the WEB transport, a
``_SERVICE_OVERRIDES`` key typo falls through to the derived default method, and
a ``_TOOL_TIMEOUTS`` key typo drops the timeout override -- with no error at
import or call time. ``catalog.py`` now guards this the same way it guards the
effect-policy count; these tests pin both the invariant and the behaviour it
protects (that each table entry actually takes effect on its spec).
"""

from __future__ import annotations

from headless_re_mcp.tools.catalog import (
    _ALL_TOOL_NAMES,
    _SERVICE_OVERRIDES,
    _TOOL_TIMEOUTS,
    _WEB_NAMES,
    CommandCatalog,
    CommandTransport,
)


def test_every_aux_table_key_names_a_real_tool() -> None:
    assert _WEB_NAMES <= _ALL_TOOL_NAMES
    assert _SERVICE_OVERRIDES.keys() <= _ALL_TOOL_NAMES
    assert _TOOL_TIMEOUTS.keys() <= _ALL_TOOL_NAMES


def test_web_names_actually_expose_the_web_transport() -> None:
    catalog = CommandCatalog()
    for name in _WEB_NAMES:
        spec = catalog.require(name)
        assert CommandTransport.WEB in spec.transports, name


def test_service_overrides_actually_win_over_the_derived_method() -> None:
    catalog = CommandCatalog()
    for name, method in _SERVICE_OVERRIDES.items():
        spec = catalog.require(name)
        assert spec.service_method == method, name


def test_tool_timeout_overrides_actually_reach_the_resource_policy() -> None:
    catalog = CommandCatalog()
    for name, timeout in _TOOL_TIMEOUTS.items():
        spec = catalog.require(name)
        assert spec.resource_policy.timeout_seconds == timeout, name
