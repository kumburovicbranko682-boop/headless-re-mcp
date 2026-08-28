"""Cross-validate the DEX map_list census (and debug-info count) against androguard.

A session over an APK now reports the DEX structural census -- the map_list's
per-section-type counts, the Dalvik analogue of a WASM section table -- and,
as its headline, how many methods carry source-line/local-variable debug
info (the map's ``debug_info_item`` count): what a ``-g`` / debuggable build
ships and a release build does not, the DEX pair to DWARF, a PDB and the WASM
name section. The map_list walk is ours, so androguard referees it two
independent ways over the committed fixture's real classes.dex:

androguard's own map_list parser (``DEX.map_list.map_item``) reads the same
12-byte entries through an entirely separate ECMA/Dalvik implementation, so
type for type and count for count the whole census must match -- and the
headline ``debug_info_items`` must equal androguard's own count for the
``debug_info_item`` type, cross-checking the debug-availability number, not
just re-reading the reader's own walk.

androguard comes from the ``[android]`` extra. skip != pass: the gate skips,
naming the missing piece, only when androguard or the fixture is absent.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _session_dex(apk: Path) -> dict:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["apk"]["dex"]
    finally:
        service.close_all()


def _androguard_dex(apk: Path):
    from loguru import logger

    logger.remove()
    from androguard.core.dex import DEX

    data = zipfile.ZipFile(apk).read("classes.dex")
    return DEX(data)


@pytest.mark.integration
def test_map_census_agrees_with_androguard(tmp_path: Path) -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — DEX map census gate not run (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE} — DEX map census gate not run (skip != pass)")

    dex_facts = _session_dex(_FIXTURE)
    d = _androguard_dex(_FIXTURE)

    # androguard's own map_list parser reads the same 12-byte entries; its
    # TypeMapItem names lower-cased are exactly the census keys.
    expected = {mi.get_type().name.lower(): mi.get_size() for mi in d.map_list.map_item}
    assert dex_facts["map_counts"] == expected


@pytest.mark.integration
def test_debug_info_headline_matches_androguards_map_count(tmp_path: Path) -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — DEX map census gate not run (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE} — DEX map census gate not run (skip != pass)")

    dex_facts = _session_dex(_FIXTURE)
    d = _androguard_dex(_FIXTURE)

    # The debug-availability headline, tied to androguard's independent count
    # for the same section type and to the reader's own census entry: all
    # three must agree (zero here -- a release fixture carries no debug info).
    androguard_debug = {
        mi.get_type().name.lower(): mi.get_size() for mi in d.map_list.map_item
    }.get("debug_info_item", 0)
    assert dex_facts["debug_info_items"] == androguard_debug
    assert dex_facts["debug_info_items"] == dex_facts["map_counts"].get("debug_info_item", 0)
