"""webcrack live gate: js.deobfuscate / js.unpack_bundle over the real CLI.

Every js.* test mocks ``run_bounded`` -- the backend has never run real webcrack.
That leaves the load-bearing CLI contract unverified: js.deobfuscate reads the
deobfuscated source from webcrack's *stdout*, and js.unpack_bundle relies on
``webcrack <file> -o <dir>`` writing module files into that directory. Both are
version-sensitive webcrack/Node behaviors -- a CLI change (output moved to a
file, a new required subcommand, a different flag) would pass every mock-based
test and only break against the real tool.

This gate runs the discovered webcrack on inputs built in tmp:

* a minified one-liner, asserting the backend returns non-empty ``code`` from
  stdout, reformatted (multi-line where the input had no newline) with the
  string content preserved and no false ``tool_failed`` -- proving the stdout
  contract, not webcrack's deobfuscation quality; and
* a tiny CommonJS bundle, asserting ``-o`` produced and listed real module
  files (``file_count >= 2``) with no false ``tool_failed``.

It drives the JsClient directly (like the apk gates) so there is no artifact
root to manage. Skip != pass: it skips with a reason when webcrack is not on
PATH and runs for real when it is. CI installs it, so a skip there is a genuine
regression rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient

_MINIFIED = (
    "const a=['secret_marker_42','log'];const b=function(c,d){return a[c];};console[b(1)](b(0));"
)

_BUNDLE = (
    "(function(modules){function require(id){var m={exports:{}};"
    "modules[id](m,m.exports,require);return m.exports;}require(0);})(["
    "function(module,exports,require){exports.greet=function(){return require(1).name;};"
    "console.log(exports.greet());},"
    "function(module,exports,require){module.exports={name:'mod_one_marker'};}"
    "]);"
)


def _webcrack_or_skip() -> JsClient:
    client = JsClient()
    if not client.available:
        pytest.skip("webcrack not on PATH — JS Gate not run (skip != pass)")
    return client


@pytest.mark.integration
def test_deobfuscate_reads_real_stdout(tmp_path: Path) -> None:
    client = _webcrack_or_skip()
    src = tmp_path / "app.js"
    src.write_text(_MINIFIED, encoding="utf-8")

    data = client.deobfuscate(src, timeout=120.0)

    code = data["code"]
    assert code, "webcrack emitted no code on stdout"
    assert "tool_failed" not in data, data.get("stderr")
    assert data["truncated"] is False
    assert data["bytes"] == len(code.encode("utf-8"))
    # webcrack parses and re-prints, so a one-line minified input comes back
    # formatted over several lines. This is the version-robust proof that the
    # real tool ran and its stdout reached us, not a mock's canned string.
    assert "\n" in code
    assert "\n" not in _MINIFIED
    assert code.strip() != _MINIFIED
    # ... and the literal content survives the round trip through the CLI.
    assert "secret_marker_42" in code


@pytest.mark.integration
def test_unpack_bundle_writes_real_modules(tmp_path: Path) -> None:
    client = _webcrack_or_skip()
    src = tmp_path / "bundle.js"
    src.write_text(_BUNDLE, encoding="utf-8")
    out = tmp_path / "unpacked"

    data = client.unpack_bundle(src, out, timeout=300.0, limit=100)

    assert "tool_failed" not in data, data.get("stderr")
    # webcrack split the bundle into module files under -o (entry + modules),
    # so the directory listing the backend built is non-trivial.
    assert data["file_count"] >= 2
    assert data["total"] == data["file_count"]
    assert data["count"] == len(data["files"])
    assert any(name.endswith(".js") for name in data["files"])
    # the files really exist on disk where the backend said they are.
    listed = out / data["files"][0]
    assert listed.is_file()
