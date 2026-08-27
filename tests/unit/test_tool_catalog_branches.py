"""Guard, conflict, and dispatch branches of the shared command catalog.

The catalog is the one registry MCP, the legacy web surface, and the agent all
read, so its invariants are what stop a tool from being served with the wrong
effects, a duplicated name, or a silently changed service binding. The happy
surface is asserted in ``test_tool_catalog_agent.py``; this file drives the
error and dispatch edges that keep a mis-declared tool from ever shipping.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
    _declared_spec,
)

_MCP = frozenset({CommandTransport.MCP})
_READ = frozenset({ToolEffect.READ_ONLY})


def _spec(
    name: str = "x.new",
    *,
    service_method: str = "x_new",
    effects: frozenset[ToolEffect] = _READ,
    transports: frozenset[CommandTransport] = _MCP,
) -> CommandSpec:
    return CommandSpec(name, service_method, transports, effects)


# --------------------------------------------------------------------------
# _declared_spec
# --------------------------------------------------------------------------


def test_declared_spec_refuses_a_tool_with_no_effects_policy() -> None:
    with pytest.raises(KeyError, match="no explicit effects policy"):
        _declared_spec("totally.unclassified.tool")


# --------------------------------------------------------------------------
# CommandCatalog construction invariants
# --------------------------------------------------------------------------


def test_construction_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        CommandCatalog([_spec(), _spec()])


def test_construction_rejects_a_spec_with_no_effects() -> None:
    with pytest.raises(ValueError, match="explicit effects"):
        CommandCatalog([_spec(effects=frozenset())])


# --------------------------------------------------------------------------
# register
# --------------------------------------------------------------------------


def test_register_refuses_a_spec_missing_effects() -> None:
    catalog = CommandCatalog([_spec()])
    with pytest.raises(ValueError, match="effects missing"):
        catalog.register(_spec(name="y.new", service_method="y_new", effects=frozenset()))


def test_register_adds_a_brand_new_tool() -> None:
    catalog = CommandCatalog([_spec()])
    fresh = _spec(name="brand.new", service_method="brand_new")
    catalog.register(fresh)
    assert catalog.get("brand.new") is fresh


def test_register_refuses_a_changed_service_method() -> None:
    catalog = CommandCatalog([_spec()])
    with pytest.raises(ValueError, match="service method changed"):
        catalog.register(_spec(service_method="rebound"))


def test_register_refuses_a_changed_effects_or_transport_policy() -> None:
    catalog = CommandCatalog([_spec()])
    stronger = _spec(effects=frozenset({ToolEffect.STATE_CHANGE}))
    with pytest.raises(ValueError, match="policy changed"):
        catalog.register(stronger)


# --------------------------------------------------------------------------
# require / schemas
# --------------------------------------------------------------------------


def test_require_reports_an_unclassified_tool() -> None:
    with pytest.raises(KeyError, match="unclassified and unavailable"):
        CommandCatalog([_spec()]).require("nope")


def test_write_names_lists_only_the_state_changing_tools() -> None:
    reader = _spec(name="r.read", service_method="r_read")
    writer = _spec(
        name="w.write",
        service_method="w_write",
        effects=frozenset({ToolEffect.STATE_CHANGE}),
    )
    catalog = CommandCatalog([reader, writer])
    assert catalog.write_names(CommandTransport.MCP) == frozenset({"w.write"})
    # confirm_required tracks the write effect, tool by tool.
    assert catalog.require("w.write").confirm_required is True
    assert catalog.require("r.read").confirm_required is False


def test_schemas_maps_each_transport_tool_to_its_schema() -> None:
    handler = lambda: {"ok": True}  # noqa: E731
    bound = _spec().bind_mcp(handler, input_schema={"type": "object"}, description="d")
    catalog = CommandCatalog([bound])
    schemas = catalog.schemas(CommandTransport.MCP)
    assert schemas == {"x.new": {"type": "object"}}


# --------------------------------------------------------------------------
# invoke
# --------------------------------------------------------------------------


def test_invoke_refuses_a_tool_with_no_handler_bound() -> None:
    catalog = CommandCatalog([_spec()])
    with pytest.raises(RuntimeError, match="handler is not bound"):
        catalog.invoke("x.new", {})


def test_invoke_converts_a_handler_exception_into_an_envelope() -> None:
    """The agent transport must stay alive: a raising tool returns an error
    envelope rather than propagating and killing the run loop."""

    def boom(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("tool blew up")

    bound = _spec().bind_mcp(boom, input_schema={"type": "object"}, description="d")
    catalog = CommandCatalog([bound])

    result = catalog.invoke("x.new", {})

    assert result["ok"] is False
    assert result["error"]["message"]
