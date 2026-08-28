"""parse_r2_json scans untrusted r2 stdout for the first JSON document.

The non-JSON listings (``i`` / ``is`` / ``il``) echo symbol, library and
section names lifted straight from the analysed binary, so their free text can
be a megabyte of ``[`` and ``{`` with no valid document in it. parse_r2_json
runs in ``enrich_r2_payload`` after the r2 subprocess has already returned,
with no deadline, and it tried ``raw_decode`` at every brace -- O(index) per
failure building the JSONDecodeError's line/column, so O(n^2) over the flood --
and caught only JSONDecodeError, so a deep ``[[[[`` run raised RecursionError
out of the C scanner and escaped as an internal_error. This mirrors the guard
already in die._parse_json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.mapping import (
    _MAX_JSON_SCANS,
    enrich_r2_payload,
    parse_r2_json,
)


def _minimal_pe(tmp_path: Path) -> Path:
    path = tmp_path / "demo64.exe"
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 20 : pe_offset + 22] = (0xF0).to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
    data[optional_off + 24 : optional_off + 32] = (0x140000000).to_bytes(8, "little")
    data[optional_off + 56 : optional_off + 60] = (0x10000).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    return path


def test_a_brace_flood_attempts_a_bounded_number_of_decodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A megabyte of braces must not become a million O(n) decode attempts.

    Deterministic where a wall-clock bound would be flaky: count the actual
    raw_decode calls. Before the cap this ran once per brace (100k); after it
    stops at _MAX_JSON_SCANS.
    """
    calls = 0
    real = json.JSONDecoder.raw_decode

    def counting(self: json.JSONDecoder, s: str, idx: int = 0):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return real(self, s, idx)

    monkeypatch.setattr(json.JSONDecoder, "raw_decode", counting)

    result = parse_r2_json("{" * 100_000)

    assert result is None
    assert calls <= _MAX_JSON_SCANS, f"scanned {calls} braces; cap is {_MAX_JSON_SCANS}"


def test_a_brace_flood_stays_fast(tmp_path: Path) -> None:
    """The O(n^2) sanity check: 200k braces used to be seconds of CPU.

    Generous threshold so a loaded runner does not flake; the pre-cap cost at
    this size was already several seconds and grows with the square.
    """
    started = time.perf_counter()
    result = parse_r2_json("{" * 200_000)
    elapsed = time.perf_counter() - started

    assert result is None
    assert elapsed < 3.0, f"brace flood took {elapsed:.1f}s"


def test_a_deeply_nested_candidate_does_not_escape() -> None:
    """A long unclosed ``[`` run raises RecursionError from the C scanner.

    parse_r2_json caught only JSONDecodeError, so before the fix this call
    raised RecursionError instead of returning; a symbol name full of ``[``
    echoed by ``is`` was enough to reach it.
    """
    hostile = "not json\n" + "[" * 60_000

    assert parse_r2_json(hostile) is None


def test_a_hostile_listing_reaches_enrich_as_unparsed_not_a_crash(
    tmp_path: Path,
) -> None:
    """enrich_r2_payload wraps a non-JSON ``is`` listing; it must degrade, not raise."""
    binary = _minimal_pe(tmp_path)
    hostile = "symbols:\n" + "[" * 60_000

    out = enrich_r2_payload({"raw": hostile, "commands": ["is"]}, binary=binary)

    assert out["parsed"] is False


def test_a_real_array_after_a_brace_heavy_banner_still_parses(tmp_path: Path) -> None:
    """The cap must not cost a real payload that sits behind a short preamble."""
    banner = "note {parsing} [warn]\n"
    payload = json.dumps([{"offset": 0x140001000, "name": "entry0", "size": 16}])

    parsed = parse_r2_json(banner + payload)

    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "entry0"
