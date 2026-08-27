"""describe_js: tool-free JavaScript identity facts (no webcrack).

The JS line otherwise depends entirely on webcrack (deobfuscate / unpack), so a
script on a machine without it yields nothing. describe_js reads the facts a
reverser reads first and that need no tool: the size, the line shape (one very
long line is the signature of a minified bundle), and whether a
``sourceMappingURL`` points at the original sources -- inline or external.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import (
    SessionRegistry,
    describe_js,
    describe_web_asset,
)


def test_reads_size_and_line_shape(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_bytes(b"const a = 1;\nconst b = 2;\n")
    info = describe_js(path)["js"]
    assert info["size"] == 26
    assert info["line_count"] == 2
    assert info["max_line_length"] == 12
    assert info["source_map"] is None
    assert info["source_map_inline"] is False
    assert info["truncated"] is False


def test_reads_an_external_source_map(tmp_path: Path) -> None:
    path = tmp_path / "bundle.js"
    path.write_bytes(b"var x=1;\n//# sourceMappingURL=bundle.js.map\n")
    info = describe_js(path)["js"]
    assert info["source_map"] == "bundle.js.map"
    assert info["source_map_inline"] is False


def test_reads_the_legacy_at_directive(tmp_path: Path) -> None:
    # Older tooling emitted //@ sourceMappingURL= instead of //# .
    path = tmp_path / "old.js"
    path.write_bytes(b"y=2\n//@ sourceMappingURL=/static/old.map")
    assert describe_js(path)["js"]["source_map"] == "/static/old.map"


def test_takes_the_last_source_map_directive(tmp_path: Path) -> None:
    # Per the spec a consumer takes the final directive; a decoy earlier in the
    # file must not win over the real one at the end.
    path = tmp_path / "two.js"
    path.write_bytes(
        b"//# sourceMappingURL=decoy.map\ncode;\n//# sourceMappingURL=real.js.map\n"
    )
    assert describe_js(path)["js"]["source_map"] == "real.js.map"


def test_flags_an_inline_source_map_without_storing_it(tmp_path: Path) -> None:
    # An inline map is a (potentially huge) data: URI; flag it but never store
    # the payload in the identity facts.
    path = tmp_path / "inline.js"
    path.write_bytes(b"var z=3;//# sourceMappingURL=data:application/json;base64," + b"A" * 4096)
    info = describe_js(path)["js"]
    assert info["source_map"] is None
    assert info["source_map_inline"] is True


def test_a_single_long_line_reads_as_minified(tmp_path: Path) -> None:
    path = tmp_path / "min.js"
    path.write_bytes(b"!function(){var a=1}();" * 5000)
    info = describe_js(path)["js"]
    assert info["line_count"] == 1
    assert info["max_line_length"] == info["size"]


def test_ignores_a_non_js_suffix(tmp_path: Path) -> None:
    path = tmp_path / "page.html"
    path.write_bytes(b"<html></html>")
    # describe_js reads only JavaScript suffixes.
    assert describe_js(path) == {}
    # The web-asset dispatcher routes .html to its own reader, not describe_js.
    assert "html" in describe_web_asset(path)


def test_session_over_a_local_js_carries_the_facts(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_bytes(b"var x=1;\n//# sourceMappingURL=app.js.map\n")
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.WEB
    assert "wasm" not in session.metadata
    assert session.metadata["js"]["source_map"] == "app.js.map"
