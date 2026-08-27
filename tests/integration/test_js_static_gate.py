"""JS static gate: webcrack deobfuscation and bundle unpacking on Linux.

test_web_re_gate.py has a single js.deobfuscate check that asserts only "code is
a non-empty string", which a plain reformat would satisfy. It never proves the
obfuscation was actually undone, never touches js.beautify, and never touches
js.unpack_bundle -- the bundle splitter, which was in fact broken against modern
webcrack (the client pre-created the output directory webcrack refuses to reuse).

This gate drives the webcrack-backed surface through AnalysisService against
committed fixtures: the obfuscator.io-style sample whose hidden string must
reappear once the string array is inlined, and a classic-webpack bundle that must
split back into its entry and per-module files. It also pins the not_found path.

Skips with an explicit "skip != pass" when webcrack is absent; verified against
webcrack 2.16.0 on Node 22.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_OBFUSCATED = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_BUNDLE = _PROJECT_ROOT / "fixtures" / "web" / "webpack_bundle.js"
# The sample hides "H3adl3ss" in a rotated \x-escaped string array; a real
# deobfuscation inlines it back into readable source.
_HIDDEN_STRING = "H3adl3ss"


def _webcrack_available() -> bool:
    return JsClient().available


@pytest.mark.integration
def test_js_deobfuscate_recovers_the_hidden_string() -> None:
    if not _webcrack_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _OBFUSCATED.is_file(), f"fixture missing: {_OBFUSCATED}"

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_OBFUSCATED))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str) and code
        # Proof the string array was actually decoded, not just reformatted.
        assert _HIDDEN_STRING in code
        assert result.data["bytes"] > 0
        assert result.data["truncated"] is False
        assert "tool_failed" not in result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_beautify_returns_source() -> None:
    if not _webcrack_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _OBFUSCATED.is_file(), f"fixture missing: {_OBFUSCATED}"

    service = AnalysisService()
    try:
        result = service.js_beautify(str(_OBFUSCATED))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str) and result.data["code"]
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_splits_into_modules() -> None:
    """A webpack bundle is recovered into its entry plus per-module files.

    This is the regression gate for the pre-created-output-directory bug: with
    that bug present the call fails with backend_error before writing anything.
    """
    if not _webcrack_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _BUNDLE.is_file(), f"fixture missing: {_BUNDLE}"

    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_BUNDLE))
        assert result.ok, result.error
        files = set(result.data["files"])
        assert result.data["file_count"] >= 3
        # The entry and the two split modules must all be recovered.
        assert {"index.js", "1.js", "2.js"} <= files, sorted(files)

        out_dir = Path(result.data["output_dir"])
        assert out_dir.is_dir()
        on_disk = {p.name for p in out_dir.iterdir()}
        assert {"index.js", "1.js", "2.js"} <= on_disk, sorted(on_disk)

        # Pagination windows the sorted listing.
        page = service.js_unpack_bundle(str(_BUNDLE), offset=1, limit=2)
        assert page.ok, page.error
        assert page.data["offset"] == 1
        assert page.data["count"] == 2
        assert page.data["has_more"] is True
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_reports_a_missing_file() -> None:
    if not _webcrack_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        missing = str(_OBFUSCATED.parent / "definitely_absent.js")
        result = service.js_deobfuscate(missing)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()
