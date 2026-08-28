"""describe_js: tool-free JavaScript identity facts (no webcrack).

The JS line otherwise depends entirely on webcrack (deobfuscate / unpack), so a
script on a machine without it yields nothing. describe_js reads the facts a
reverser reads first and that need no tool: the size, the line shape (one very
long line is the signature of a minified bundle), and whether a
``sourceMappingURL`` points at the original sources -- inline or external --
plus what the referenced map actually delivers when it is at hand.
"""

from __future__ import annotations

import base64
import json
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


class TestJsUrlCensus:
    """describe_js carries the raw-bytes URL census the binary formats share.

    A bundle's fetch/XHR/WebSocket targets are the script-level "what does
    this talk to" fact; the census lists a bounded sample, an exact count and
    the cleartext (http/ws/ftp) share -- the same three facts an ELF or PE
    session reports, read the same way.
    """

    def test_endpoints_are_listed_counted_and_split_by_transport(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "app.js"
        path.write_bytes(
            b'fetch("https://api.example.com/v1");'
            b'new WebSocket("ws://c2.example.com/beacon");'
            b'img.src="http://track.example.com/p.gif";'
            b'const secure=new WebSocket("wss://live.example.com/s");'
        )
        info = describe_js(path)["js"]
        assert sorted(info["urls"]) == [
            "http://track.example.com/p.gif",
            "https://api.example.com/v1",
            "ws://c2.example.com/beacon",
            "wss://live.example.com/s",
        ]
        assert info["url_count"] == 4
        # http and ws carry no transport security; https and wss do.
        assert info["cleartext_url_count"] == 2

    def test_a_script_with_no_endpoints_reads_an_empty_census(self, tmp_path: Path) -> None:
        path = tmp_path / "pure.js"
        path.write_bytes(b"const add = (a, b) => a + b;\nexport default add;\n")
        info = describe_js(path)["js"]
        assert info["urls"] == []
        assert info["url_count"] == 0
        assert info["cleartext_url_count"] == 0

    def test_a_repeated_endpoint_counts_once(self, tmp_path: Path) -> None:
        path = tmp_path / "dup.js"
        path.write_bytes(b'a("https://api.example.com/x");b("https://api.example.com/x");')
        info = describe_js(path)["js"]
        assert info["urls"] == ["https://api.example.com/x"]
        assert info["url_count"] == 1

    def test_session_over_a_js_carries_the_census(self, tmp_path: Path) -> None:
        path = tmp_path / "app.js"
        path.write_bytes(b'fetch("http://c2.example.com/cmd");')
        session = SessionRegistry().create(str(path))
        js = session.metadata["js"]
        assert js["urls"] == ["http://c2.example.com/cmd"]
        assert js["cleartext_url_count"] == 1


def _map_doc(**overrides: object) -> bytes:
    doc: dict[str, object] = {
        "version": 3,
        "file": "app.js",
        "sources": ["src/a.ts", "src/b.ts"],
        "sourcesContent": ["let a = 1;", "let b = 2;"],
        "names": ["a", "b"],
        "mappings": "AAAA,CAAC",
    }
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


class TestSourceMapFacts:
    """source_map_facts reports what the referenced map actually delivers.

    The directive is only a claim; the prize is whether the original sources
    travel inside the map (sourcesContent) -- recovering the pre-minification
    codebase outright versus merely getting names and line numbers. An inline
    data: URI is decoded in place; an external reference is read next to the
    script under the SRI containment rules. Anything unreadable is
    resolved=False, never a guess.
    """

    def test_no_directive_means_no_facts(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.js"
        path.write_bytes(b"var q = 1;\n")
        assert describe_js(path)["js"]["source_map_facts"] is None

    def test_an_external_map_with_embedded_sources_is_the_prize(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(_map_doc())
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map\n")
        facts = describe_js(path)["js"]["source_map_facts"]
        assert facts == {
            "kind": "external",
            "resolved": True,
            "version": 3,
            "sources_count": 2,
            "sources_content": "embedded",
            "names_count": 2,
            "mappings": True,
        }

    def test_a_map_without_sources_content_only_gives_names(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(_map_doc(sourcesContent=None))
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map\n")
        facts = describe_js(path)["js"]["source_map_facts"]
        assert facts["resolved"] is True
        assert facts["sources_content"] == "absent"

    def test_a_partially_embedded_map_reads_as_partial(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(_map_doc(sourcesContent=["let a = 1;", None]))
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map\n")
        assert describe_js(path)["js"]["source_map_facts"]["sources_content"] == "partial"

    def test_a_missing_map_is_an_unbacked_claim(self, tmp_path: Path) -> None:
        path = tmp_path / "lone.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=shipped-nowhere.js.map\n")
        facts = describe_js(path)["js"]["source_map_facts"]
        assert facts == {"kind": "external", "resolved": False}

    def test_remote_and_escaping_references_are_not_read(self, tmp_path: Path) -> None:
        # A remote URL, a root-relative path and a traversal escaping the tree:
        # none of them may be read from local disk.
        for url in (b"https://cdn.example/app.js.map", b"/maps/app.js.map", b"../../etc/passwd"):
            path = tmp_path / "esc.js"
            path.write_bytes(b"var a=1;\n//# sourceMappingURL=" + url + b"\n")
            facts = describe_js(path)["js"]["source_map_facts"]
            assert facts == {"kind": "external", "resolved": False}, url

    def test_a_cache_buster_does_not_defeat_resolution(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(_map_doc())
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map?v=1234\n")
        assert describe_js(path)["js"]["source_map_facts"]["resolved"] is True

    def test_malformed_json_is_resolved_false(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(b"not json at all {{{")
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map\n")
        assert describe_js(path)["js"]["source_map_facts"] == {
            "kind": "external",
            "resolved": False,
        }

    def test_an_inline_base64_map_is_decoded_in_place(self, tmp_path: Path) -> None:
        payload = base64.b64encode(_map_doc())
        path = tmp_path / "inline.js"
        path.write_bytes(
            b"var a=1;\n//# sourceMappingURL=data:application/json;base64," + payload + b"\n"
        )
        facts = describe_js(path)["js"]["source_map_facts"]
        assert facts["kind"] == "inline"
        assert facts["resolved"] is True
        assert facts["sources_content"] == "embedded"
        assert facts["sources_count"] == 2

    def test_an_inline_percent_encoded_map_is_decoded_in_place(self, tmp_path: Path) -> None:
        # The non-base64 data: form percent-encodes the JSON payload.
        payload = _map_doc().replace(b" ", b"%20").replace(b",", b"%2C")
        path = tmp_path / "pct.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=data:application/json," + payload + b"\n")
        facts = describe_js(path)["js"]["source_map_facts"]
        assert facts["kind"] == "inline"
        assert facts["resolved"] is True

    def test_corrupt_inline_base64_is_resolved_false(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.js"
        path.write_bytes(
            b"var a=1;\n//# sourceMappingURL=data:application/json;base64,!!!not-base64!!!\n"
        )
        assert describe_js(path)["js"]["source_map_facts"] == {
            "kind": "inline",
            "resolved": False,
        }

    def test_a_non_object_map_is_resolved_false(self, tmp_path: Path) -> None:
        (tmp_path / "app.js.map").write_bytes(b'["valid json", "wrong shape"]')
        path = tmp_path / "app.js"
        path.write_bytes(b"var a=1;\n//# sourceMappingURL=app.js.map\n")
        assert describe_js(path)["js"]["source_map_facts"]["resolved"] is False
