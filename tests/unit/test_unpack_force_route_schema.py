"""unpack.plan / unpack.start must advertise force_route as the routing enum.

``force_route`` lets a caller pin the unpack route past detection. The service
(``recommend_unpack_route``) only accepts the five names in
``_ALLOWED_FORCE_ROUTES`` and raises ``ValueError`` for anything else -- yet the
tools declared it a bare ``str``, so the schema promised "any string." An agent
guessing ``"dynamic"`` or ``"upx_unpack"`` passed schema validation and reached
the service before being rejected, and the real route names were never visible
to it. The sibling ``mode`` parameter on the same tools is already a proper
enum; this pins ``force_route`` to the same contract so bad values are refused
at the boundary and the choices are discoverable.
"""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools
from headless_re_mcp.unpack.recommend import (
    _ALLOWED_FORCE_ROUTES,
    ForceRoute,
    recommend_unpack_route,
)


def _force_route_schema(tool_name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == tool_name
    )
    return input_schema_for(handler)["properties"]["force_route"]


def _enum_values(schema: dict[str, object]) -> list[str]:
    for option in schema["anyOf"]:  # type: ignore[index]
        if isinstance(option, dict) and "enum" in option:
            return list(option["enum"])
    raise AssertionError(f"no enum branch in force_route schema: {schema}")


def test_force_route_schema_matches_the_service_allowlist() -> None:
    for tool_name in ("unpack.plan", "unpack.start"):
        schema = _force_route_schema(tool_name)
        # Optional: omitting it (null) means "let detection route".
        assert {"type": "null"} in schema["anyOf"]  # type: ignore[operator]
        assert schema["default"] is None
        assert sorted(_enum_values(schema)) == sorted(_ALLOWED_FORCE_ROUTES)


def test_force_route_literal_is_the_single_source_of_truth() -> None:
    from typing import get_args

    # The runtime allowlist is derived from the Literal, so the schema the tools
    # publish and the set the service enforces cannot drift apart.
    assert set(get_args(ForceRoute)) == set(_ALLOWED_FORCE_ROUTES)


def test_service_still_rejects_a_route_outside_the_set() -> None:
    # Defense in depth: a programmatic caller bypassing the tool schema is still
    # refused, with the allowed names named in the error.
    try:
        recommend_unpack_route([], force_route="upx_unpack")
    except ValueError as exc:
        assert "force_route must be one of" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected ValueError for an unknown force_route")
