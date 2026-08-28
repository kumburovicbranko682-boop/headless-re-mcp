"""An empty JSON-array command reads as an empty list, not a parse failure.

r2's ``axj`` prints nothing at all -- not ``[]`` -- for an address with no
references. enrich_r2_payload used to see that empty output, fail to parse it,
and return ``parsed: False`` with no ``items`` or ``count``: a zero-xref result
then looked identical to a broken decode and dropped the shape r2.xrefs
documents. It must instead read as an empty list.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.r2.mapping import enrich_r2_payload


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    return binary


def test_empty_axj_output_is_an_empty_xref_list(tmp_path: Path) -> None:
    payload = enrich_r2_payload(
        {"raw": "", "commands": ["aa", "axj @ 0x401000"], "address": 0x401000},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is True
    assert payload["items"] == []
    assert payload["count"] == 0
    # The requested address still round-trips so a caller knows which node the
    # empty answer is about.
    assert payload["address_va"] == 0x401000
    assert isinstance(payload["address"], dict)


def test_empty_aflj_output_is_an_empty_function_list(tmp_path: Path) -> None:
    payload = enrich_r2_payload(
        {"raw": "   \n", "commands": ["aa", "aflj"]},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is True
    assert payload["items"] == []
    assert payload["count"] == 0


def test_empty_text_info_stays_unparsed(tmp_path: Path) -> None:
    """``i`` is text, not a JSON array; empty info is not an empty list."""
    payload = enrich_r2_payload(
        {"raw": "", "commands": ["i"]},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is False
    assert "items" not in payload
    assert "count" not in payload


def test_nonempty_axj_is_unaffected(tmp_path: Path) -> None:
    import json

    entries = [{"from": 0x401100, "to": 0x401000, "type": "CALL"}]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["aa", "axj @ 0x401000"], "address": 0x401000},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is True
    assert payload["count"] == 1
    assert payload["items"][0]["from_address"]["va"] == 0x401100
