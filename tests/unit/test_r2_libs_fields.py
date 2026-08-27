"""r2.libs must parse ilj's string array, which the shared item mapper drops.

radare2 is not in CI, so these drive R2Client.libraries with the run() output
mocked. The ilj shape (a JSON array of library-name strings) is the one the
official r2pipe-api documents (enumerateLibraries(): string[]); the first test
also shows why r2.libs cannot reuse enrich_r2_payload -- that mapper keeps only
dict entries and would report an empty list for a dynamically linked binary.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    _MAX_LIBRARIES,
    R2Client,
    R2Error,
    _require_allowed_command,
)
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _client_over(raw: str, *, truncated: bool = False) -> R2Client:
    client = R2Client(executable=Path("/nonexistent/r2"))

    def fake_run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> Any:
        assert commands == ["ilj"]
        payload: dict[str, Any] = {"raw": raw, "commands": commands}
        if truncated:
            payload["truncated"] = True
        return payload

    client.run = fake_run  # type: ignore[method-assign]
    return client


def test_r2_libs_parses_the_string_array_the_mapper_would_drop() -> None:
    """ilj yields strings; the shared mapper keeps only addressed dicts.

    Measured: the same JSON array of names through enrich_r2_payload comes back
    items=[] (every string skipped), which reads as a static binary; libraries()
    returns the names. This is why r2.libs does not reuse the mapper.
    """
    names = ["libc.so.6", "libm.so.6", "libdl.so.2"]
    raw = json.dumps(names)

    mapped = enrich_r2_payload({"raw": raw, "commands": ["ilj"]}, binary=Path("x"))
    assert mapped["items"] == []  # the bug r2.libs must not reproduce

    payload = _client_over(raw).libraries(Path("bin"))
    assert payload["libraries"] == names
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["truncated"] is False
    assert "items" not in payload


def test_r2_libs_skips_an_r2_banner_before_the_array() -> None:
    """r2 -q0 can print a banner; parse_r2_json finds the array after it."""
    raw = 'WARN: using default bits\n["libssl.so.1.1","libcrypto.so.1.1"]'
    payload = _client_over(raw).libraries(Path("bin"))
    assert payload["libraries"] == ["libssl.so.1.1", "libcrypto.so.1.1"]


def test_r2_libs_tolerates_object_entries_too() -> None:
    """A future r2 that enriches each entry as an object must not be dropped."""
    raw = json.dumps([{"name": "libfoo.so"}, {"library": "libbar.so"}])
    payload = _client_over(raw).libraries(Path("bin"))
    assert payload["libraries"] == ["libfoo.so", "libbar.so"]


def test_r2_libs_empty_list_is_a_static_binary_not_an_error() -> None:
    """[] means nothing linked (static), which is a fact, not a failure."""
    payload = _client_over("[]").libraries(Path("bin"))
    assert payload["libraries"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0


def test_r2_libs_non_list_output_is_a_backend_error() -> None:
    """Output r2 could not render as a JSON list must not read as 'none linked'.

    A truthful "could not read the library list" beats a false empty list.
    """
    with pytest.raises(R2Error) as caught:
        _client_over("ERROR: cannot open file\n").libraries(Path("bin"))
    assert caught.value.code == "backend_error"


def test_r2_libs_caps_a_hostile_library_count() -> None:
    """A binary claiming thousands of libs is bounded and says so."""
    names = [f"lib{index}.so" for index in range(_MAX_LIBRARIES + 50)]
    payload = _client_over(json.dumps(names)).libraries(Path("bin"))
    assert payload["count"] == _MAX_LIBRARIES
    assert payload["truncated"] is True
    assert payload["total"] == _MAX_LIBRARIES + 50


def test_r2_libs_flags_a_cut_output_buffer() -> None:
    """When r2's own output buffer was cut, the lib list may be short a few."""
    raw = json.dumps(["liba.so", "libb.so"])
    payload = _client_over(raw, truncated=True).libraries(Path("bin"))
    assert payload["output_truncated"] is True


def test_ilj_is_whitelisted_and_bogus_commands_are_not() -> None:
    _require_allowed_command("ilj")  # must not raise
    with pytest.raises(R2Error):
        _require_allowed_command("il; rm -rf /")


def test_r2_libs_description_names_its_fields() -> None:
    doc = _tool_docstring("r2.libs")
    assert "libraries" in doc
    assert "items" in doc  # explains why the field is libraries, not items
    assert "static" in doc
    assert "backend_error" in doc
