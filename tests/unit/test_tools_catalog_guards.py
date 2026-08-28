"""Construction, registration and invocation guards for the command catalog.

``test_write_policy.py`` pins the read-only write refusal through the real
catalog. This file targets the pure structural guards: ``_declared_spec`` for
an unclassified name, ``CommandCatalog`` construction invariants, ``register``
policy checks, ``require`` for an unknown tool, the ``write_names``/``schemas``
query helpers, and the three ``invoke`` arcs (bound success, unbound handler,
handler exception wrapped in an envelope).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from headless_re_mcp.tools import catalog as catalog_module
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def _spec(
    name: str,
    *,
    service_method: str | None = None,
    effects: frozenset[ToolEffect] = frozenset({ToolEffect.READ_ONLY}),
    transports: frozenset[CommandTransport] = frozenset(
        {CommandTransport.MCP, CommandTransport.AGENT}
    ),
) -> CommandSpec:
    return CommandSpec(
        name=name,
        service_method=service_method or name.replace(".", "_"),
        transports=transports,
        effects=effects,
    )


def test_declared_spec_rejects_an_unclassified_name() -> None:
    with pytest.raises(KeyError, match="no explicit effects policy"):
        catalog_module._declared_spec("totally.unknown.tool")


def test_catalog_rejects_duplicate_specs() -> None:
    spec = _spec("dup.tool")
    with pytest.raises(ValueError, match="unique"):
        CommandCatalog([spec, spec])


def test_catalog_rejects_specs_without_effects() -> None:
    with pytest.raises(ValueError, match="explicit effects"):
        CommandCatalog([_spec("bare.tool", effects=frozenset())])


def test_register_rejects_a_spec_without_effects() -> None:
    cat = CommandCatalog([_spec("base.tool")])
    with pytest.raises(ValueError, match="effects missing"):
        cat.register(_spec("other.tool", effects=frozenset()))


def test_register_adds_a_brand_new_spec() -> None:
    cat = CommandCatalog([_spec("base.tool")])
    fresh = _spec("fresh.tool")
    cat.register(fresh)
    assert cat.get("fresh.tool") is fresh


def test_register_rejects_a_changed_service_method() -> None:
    base = _spec("base.tool")
    cat = CommandCatalog([base])
    with pytest.raises(ValueError, match="service method changed"):
        cat.register(replace(base, service_method="renamed"))


def test_register_rejects_a_changed_effect_policy() -> None:
    base = _spec("base.tool")
    cat = CommandCatalog([base])
    with pytest.raises(ValueError, match="policy changed"):
        cat.register(replace(base, effects=frozenset({ToolEffect.STATE_CHANGE})))


def test_require_raises_for_an_unknown_tool() -> None:
    cat = CommandCatalog()
    with pytest.raises(KeyError, match="unclassified and unavailable"):
        cat.require("does.not.exist")


def test_write_names_and_schemas_reflect_the_transport() -> None:
    cat = CommandCatalog()
    web_writes = cat.write_names(CommandTransport.WEB)
    assert web_writes
    assert all(cat.require(name).confirm_required for name in web_writes)
    schemas = cat.schemas(CommandTransport.MCP)
    assert schemas
    assert all(isinstance(schema, dict) for schema in schemas.values())


def test_confirm_required_tracks_write_effects() -> None:
    assert _spec("w", effects=frozenset({ToolEffect.STATE_CHANGE})).confirm_required is True
    assert _spec("r", effects=frozenset({ToolEffect.READ_ONLY})).confirm_required is False


def test_agent_auto_execute_is_read_only_specs_only() -> None:
    assert _spec("r", effects=frozenset({ToolEffect.READ_ONLY})).agent_auto_execute is True
    assert _spec("w", effects=frozenset({ToolEffect.STATE_CHANGE})).agent_auto_execute is False


def test_uncategorized_names_is_empty_for_a_fully_classified_catalog() -> None:
    assert CommandCatalog().uncategorized_names() == ()


def test_invoke_runs_a_bound_write_then_refuses_when_read_only() -> None:
    cat = CommandCatalog([_spec("w.tool", effects=frozenset({ToolEffect.STATE_CHANGE}))])
    calls: list[dict[str, Any]] = []

    def handler(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"ok": True, "data": None, "error": None, "meta": {}}

    bound = cat.bind_handler("w.tool", handler, input_schema={"type": "object"}, description="d")
    assert bound.confirm_required is True

    assert cat.invoke("w.tool", {"value": 1})["ok"] is True
    assert calls == [{"value": 1}]

    cat.write_allowed = False
    refused = cat.invoke("w.tool", {})
    assert refused["ok"] is False
    assert refused["error"]["code"] == "write_disabled"
    assert refused["error"]["details"]["tool"] == "w.tool"


def test_invoke_requires_a_bound_handler() -> None:
    cat = CommandCatalog([_spec("u.tool")])
    with pytest.raises(RuntimeError, match="handler is not bound"):
        cat.invoke("u.tool", {})


def test_invoke_wraps_handler_exceptions_in_an_envelope() -> None:
    cat = CommandCatalog([_spec("e.tool")])

    def boom(**kwargs: Any) -> dict[str, Any]:
        raise ValueError("nope")

    cat.bind_handler("e.tool", boom, input_schema={}, description=None)
    envelope = cat.invoke("e.tool", {})
    assert envelope["ok"] is False
    assert envelope["error"] is not None


def test_invoke_reports_an_unexpected_argument_as_invalid_params() -> None:
    # The agent transport binds the model's JSON arguments straight onto the
    # handler with no schema coercion. A misspelled name makes ``**arguments``
    # fail to bind; that must read as the caller's fixable mistake, not a
    # server-defect internal_error incident.
    cat = CommandCatalog([_spec("r.tool")])

    def handler(session_id: str) -> dict[str, Any]:
        return {"ok": True, "data": None, "error": None, "meta": {}}

    cat.bind_handler("r.tool", handler, input_schema={}, description=None)
    envelope = cat.invoke("r.tool", {"session_id": "s", "sesion_id": "typo"})

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "invalid_params"
    assert envelope["error"]["details"]["tool"] == "r.tool"


def test_invoke_reports_a_missing_required_argument_as_invalid_params() -> None:
    cat = CommandCatalog([_spec("m.tool")])

    def handler(session_id: str, address: int) -> dict[str, Any]:
        return {"ok": True, "data": None, "error": None, "meta": {}}

    cat.bind_handler("m.tool", handler, input_schema={}, description=None)
    envelope = cat.invoke("m.tool", {"session_id": "s"})

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "invalid_params"


def test_invoke_keeps_an_in_body_type_error_as_internal_error() -> None:
    # A TypeError raised inside a handler whose arguments bound fine is a real
    # fault, not a bad-arguments one, so it must still surface as the logged
    # internal_error incident rather than be relabelled invalid_params.
    cat = CommandCatalog([_spec("b.tool")])

    def handler(session_id: str) -> dict[str, Any]:
        raise TypeError("unsupported operand deep inside the handler")

    cat.bind_handler("b.tool", handler, input_schema={}, description=None)
    envelope = cat.invoke("b.tool", {"session_id": "s"})

    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "internal_error"
