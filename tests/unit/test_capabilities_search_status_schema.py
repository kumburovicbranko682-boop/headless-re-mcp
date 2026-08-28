"""capabilities.search must advertise its readiness filter as the ProbeStatus enum."""

from __future__ import annotations

from headless_re_mcp.doctor import ProbeStatus
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def _status_schema() -> dict:
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "capabilities.search"
    )
    return input_schema_for(handler)["properties"]["status"]


def test_status_is_an_enum_matching_probe_status() -> None:
    """status was a bare str, so the schema advertised no readiness vocabulary.

    ``list_capabilities`` compares the filter against each capability's probed
    status, which is exactly a ``ProbeStatus`` value, and a value outside that
    set matches nothing. Typed as ``str | None`` the discovery tool gave the
    agent no hint, so a natural filter like ``available`` or ``ok`` returned an
    empty list that reads as "nothing is ready" rather than "not a status". The
    schema must expose the ProbeStatus vocabulary as an enum -- and stay in
    lockstep with it -- while ``None`` (no filter) keeps validating.
    """
    schema = _status_schema()
    variants = schema["anyOf"]

    enum = next(variant["enum"] for variant in variants if "enum" in variant)
    assert set(enum) == {member.value for member in ProbeStatus}
    # The query-everything path (no filter) still validates.
    assert any(variant.get("type") == "null" for variant in variants)
    assert schema.get("default") is None
