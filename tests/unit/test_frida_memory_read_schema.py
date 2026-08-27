"""frida.memory.read must refuse a negative address at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _props(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    schema = input_schema_for(handler)["properties"]
    assert isinstance(schema, dict)
    return schema


def test_frida_memory_read_schema_floors_the_address_at_zero() -> None:
    """The catalog accepted any integer address, including negatives.

    dynamic.memory.read already floors address at zero; frida.memory.read passed
    address straight through to Frida's ptr(), where a negative value is a
    wrapped pointer, not a rejection. size was already bounded 1..262144, so the
    address was the lone unbounded half of the same read.
    """
    props = _props("frida.memory.read")
    address = props["address"]
    assert isinstance(address, dict)
    assert address.get("type") == "integer"
    assert address.get("minimum") == 0
    assert "maximum" not in address
    # The sibling bound the address should have matched all along.
    size = props["size"]
    assert isinstance(size, dict)
    assert size.get("minimum") == 1
    assert size.get("maximum") == 262144
