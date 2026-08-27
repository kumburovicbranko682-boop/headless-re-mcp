"""js.deobfuscate / js.beautify gate: prove a real decode, not just output.

The web RE gate already runs ``js.deobfuscate`` on the obfuscated fixture, but
only asserts ``bytes > 0`` -- a webcrack that echoed an error banner, or handed
the input straight back, would satisfy that too. And ``js.beautify`` (the
formatting-focused alias) has no live coverage at all.

The committed fixture hides the string ``H3adl3ss`` as ``\\x48\\x33...`` escape
sequences, so the literal never appears in the source. If it appears *decoded*
in webcrack's output, webcrack genuinely evaluated the escapes rather than
merely running. This gate pins exactly that for both tool names.

skip != pass: with Node/webcrack absent the gate skips loudly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
# The fixture stores this only as \x-escapes; the literal must not appear in the
# source, so its decoded presence in the output is proof webcrack evaluated them.
_DECODED_SECRET = "H3adl3ss"


def _assert_secret_is_hidden_in_source() -> None:
    raw = _JS_FIXTURE.read_text(encoding="utf-8")
    assert _DECODED_SECRET not in raw, "fixture no longer hides the secret as escapes"


@pytest.mark.integration
def test_js_deobfuscate_decodes_hidden_strings() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Decode Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    _assert_secret_is_hidden_in_source()

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert result.data["bytes"] > 0, result.data
        assert result.data.get("tool_failed") is not True, result.data
        # The escape sequences were evaluated: the plaintext secret now appears.
        assert _DECODED_SECRET in code, code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_beautify_reaches_webcrack_and_decodes() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Decode Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    _assert_secret_is_hidden_in_source()

    service = AnalysisService()
    try:
        # beautify is the formatting-facing alias; prove it actually reaches
        # webcrack and produces the same decoded output, not a stub.
        result = service.js_beautify(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert _DECODED_SECRET in result.data["code"], result.data["code"]
    finally:
        service.close_all()
