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


def _typed_tool(cat: CommandCatalog, name: str = "typed.tool") -> None:
    def handler(session_id: str, address: int = 0) -> dict[str, Any]:
        return {"ok": True, "data": None, "error": None, "meta": {}}

    cat.bind_handler(name, handler, input_schema={"type": "object"}, description="d")


@pytest.mark.parametrize(
    ("arguments", "needle"),
    [
        ({"sessionId": "abc"}, "missing a required argument"),
        ({"session_id": "abc", "bogus": 1}, "unexpected keyword argument"),
        ({}, "missing a required argument"),
    ],
)
def test_invoke_reclassifies_bad_arguments_as_invalid_params(
    arguments: dict[str, Any], needle: str
) -> None:
    """A misspelled, extra or missing argument is the caller's fault.

    spec.handler(**arguments) would raise TypeError, which the envelope files as
    an internal_error with a logged incident -- telling an unattended model the
    server broke on a call it could fix by renaming a field. It must instead read
    as invalid_params so the caller corrects the arguments and retries.
    """
    cat = CommandCatalog([_spec("typed.tool")])
    _typed_tool(cat)

    result = cat.invoke("typed.tool", arguments)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_params"
    assert result["error"]["details"]["tool"] == "typed.tool"
    assert needle in result["error"]["message"]


def test_invoke_runs_a_valid_typed_call() -> None:
    cat = CommandCatalog([_spec("typed.tool")])
    _typed_tool(cat)

    assert cat.invoke("typed.tool", {"session_id": "abc", "address": 5})["ok"] is True


def test_invoke_keeps_a_handler_internal_type_error_as_internal_error() -> None:
    """Only the argument binding is reclassified; a defect inside the handler is not.

    The signature pre-check passes for well-formed arguments, so a TypeError the
    handler raises for its own reason still reaches the envelope as internal_error
    -- the reclassification must not swallow genuine server defects.
    """
    cat = CommandCatalog([_spec("boom.tool")])

    def handler(session_id: str) -> dict[str, Any]:
        raise TypeError("genuine internal defect")

    cat.bind_handler("boom.tool", handler, input_schema={"type": "object"}, description="d")

    result = cat.invoke("boom.tool", {"session_id": "abc"})

    assert result["ok"] is False
    assert result["error"]["code"] == "internal_error"


def test_invoke_lets_a_kwargs_handler_accept_any_argument() -> None:
    """A **kwargs handler binds anything, so the check never rejects its calls."""
    cat = CommandCatalog([_spec("open.tool")])

    def handler(**kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "data": kwargs, "error": None, "meta": {}}

    cat.bind_handler("open.tool", handler, input_schema={"type": "object"}, description="d")

    assert cat.invoke("open.tool", {"anything": 1, "else": 2})["ok"] is True
