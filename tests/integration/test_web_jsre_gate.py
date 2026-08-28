"""Web static JS gate: webcrack beautify, the error contract, and the size bound.

``test_web_re_gate.py`` proves the happy paths -- ``js.deobfuscate`` decodes a
hidden string and ``js.unpack_bundle`` splits a webpack bundle. Three things it
never touches, all exercised here against **real** webcrack through the same
``js.*`` service the tools use:

* **``js.beautify``** has no live coverage at all. It is a thin alias of
  ``deobfuscate``, but nothing proved that path actually unminifies real input;
  the gate feeds a single-line minified script and asserts it comes back as
  multi-line, spaced, semantically intact code.
* **the error contract on malformed input**. ``JsClient`` promises that a webcrack
  that exits non-zero with no output surfaces a structured ``backend_error``
  (with ``exit_code``/``stderr``), never a crash or an ``internal_error`` incident.
  Until now that branch was only ever asserted against a *mocked* subprocess; here
  a genuinely un-parseable file drives real webcrack into a real non-zero exit.
* **the input size bound**. ``js.*`` refuses an input over 16 MiB as ``too_large``
  *before* launching webcrack, so an unattended pass pointed at a captured bundle
  cannot pin a core for the whole timeout. That resource bound had no live test.

skip != pass: skips honestly when webcrack (Node 22/24) is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient
from headless_re_mcp.core.service import AnalysisService

# The 16 MiB ceiling _require_existing_file enforces; matches _MAX_INPUT_BYTES.
_MAX_INPUT_BYTES = 16 * 1024 * 1024

# A single-line, minified script: no newlines, tight operators, an inline
# function body. Beautifying it must visibly change the shape (multi-line, spaced)
# while keeping the program.
_MINIFIED = "const a=1;function f(x){return x+a}console.log(f(2));"


@pytest.mark.integration
def test_js_beautify_unminifies_real_input(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS beautify Gate not run (skip != pass)")
    source = tmp_path / "mini.js"
    source.write_text(_MINIFIED, encoding="utf-8")

    service = AnalysisService()
    try:
        result = service.js_beautify(str(source))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str) and result.data["bytes"] > 0
        # The input was one physical line; a real unminify expands it.
        assert _MINIFIED.count("\n") == 0
        assert code.count("\n") >= 3, code
        # Operators and blocks are spaced out, and the program is preserved.
        assert "function f(x) {" in code, code
        assert "return x + a;" in code, code
        assert "console.log(f(2));" in code, code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_rejects_malformed_input_with_a_structured_error(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS error-contract Gate not run (skip != pass)")
    # Not valid JavaScript by any parse: webcrack's babel front end bails out
    # non-zero with nothing on stdout, which is the branch under test.
    broken = tmp_path / "broken.js"
    broken.write_text("function ( { const x = ;;; @@@ <<<>>> \n)))(((", encoding="utf-8")

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(broken))
        # The contract: a failed tool is a structured backend_error, not a raised
        # exception surfaced as internal_error and not a crash of the worker.
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error", result.error
        assert result.error.code != "internal_error"
        details = result.error.details
        # The child's real non-zero exit and its diagnostics are carried through,
        # so a caller can see *why* it failed rather than a bare "failed".
        assert int(details.get("exit_code", 0)) != 0, details
        assert isinstance(details.get("stderr"), str) and details["stderr"], details
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_refuses_oversized_input(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS size-bound Gate not run (skip != pass)")
    # One byte over the ceiling: refused up front, before webcrack is launched.
    oversized = tmp_path / "huge.js"
    oversized.write_bytes(b"//" + b"a" * (_MAX_INPUT_BYTES + 1))

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(oversized))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large", result.error
        details = result.error.details
        assert details.get("max_file_size") == _MAX_INPUT_BYTES, details
        assert int(details.get("size", 0)) > _MAX_INPUT_BYTES, details
    finally:
        service.close_all()
