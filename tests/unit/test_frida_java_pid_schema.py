"""frida.java.classes/methods must floor pid at 0 and name the sentinel."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _binding(name: str) -> object:
    return next(
        binding
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )


def test_java_pid_is_floored_at_zero() -> None:
    """The catalog accepted any integer pid, including negatives.

    pid=0 is a sentinel meaning "this session's most recently spawned/attached
    pid"; only a positive pid names a real process. A negative pid used to slip
    the schema and surface as _authorize's "pid must be a positive integer" long
    after the call was accepted -- the confusing half of an otherwise bounded
    signature (limit was already 1..2000). Floor it at 0 so the sentinel stays
    valid and a negative is refused up front.
    """
    for name in ("frida.java.classes", "frida.java.methods"):
        props = input_schema_for(_binding(name).handler)["properties"]  # type: ignore[attr-defined]
        pid = props["pid"]
        assert isinstance(pid, dict)
        assert pid.get("type") == "integer"
        assert pid.get("minimum") == 0
        # 0 is the sentinel, not a ceiling, so the pid must stay open above.
        assert "maximum" not in pid
        assert pid.get("default") == 0


def test_java_docstrings_name_the_pid_sentinel() -> None:
    """pid=0 was the default with no hint of what it selected.

    A caller reading the schema saw an integer defaulting to 0 and no clue that
    0 means "the app you just spawned". Lock the docstrings so the sentinel and
    the non-negative floor stay documented next to the tool.
    """
    for name in ("frida.java.classes", "frida.java.methods"):
        doc = _binding(name).handler.__doc__ or ""  # type: ignore[attr-defined]
        assert "pid defaults to 0" in doc
        assert "spawned/attached pid" in doc
        assert "negative pid is refused" in doc
