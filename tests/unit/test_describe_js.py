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


class TestJsPayloadCensus:
    """describe_js flags long encoded literals and names what they decode to.

    The dropper shape the binary formats already report as embedded payloads:
    a script carrying its next stage as one long base64 or hex string. The
    census counts every 256+ character blob, decodes each blob's opening
    characters and runs the shared overlay sniff over the bytes -- so "the
    script carries a zip" and "the PE trails a zip" are the same fact.
    """

    def test_a_base64_zip_literal_is_named(self, tmp_path: Path) -> None:
        stage = base64.b64encode(b"PK\x03\x04" + b"\x00" * 200).decode()
        path = tmp_path / "dropper.js"
        path.write_bytes(f'var s = "{stage}"; eval(atob(s));'.encode())
        info = describe_js(path)["js"]
        assert info["embedded_payloads"] == [
            {"kind": "zip", "encoding": "base64", "chars": len(stage), "offset": 9}
        ]
        assert info["embedded_payload_count"] == 1
        assert info["encoded_blob_count"] == 1

    def test_a_hex_pe_literal_classifies_as_hex(self, tmp_path: Path) -> None:
        # Hex is a subset of the base64 alphabet; a pure even-length hex run
        # must decode as hex (yielding the MZ magic), not as base64 garbage.
        stage = (b"MZ" + b"\x00" * 150).hex()
        path = tmp_path / "shell.js"
        path.write_bytes(f'var h = "{stage}";'.encode())
        payloads = describe_js(path)["js"]["embedded_payloads"]
        assert payloads == [
            {"kind": "pe", "encoding": "hex", "chars": len(stage), "offset": 9}
        ]

    def test_a_blob_with_no_magic_counts_but_is_not_listed(self, tmp_path: Path) -> None:
        # The encrypted-stage shape: a big literal that decodes to nothing
        # recognizable. It joins the blob count -- that count next to an empty
        # payload list is itself the signal -- but the list stays honest.
        noise = base64.b64encode(b"\xf3\x9c" * 200).decode()
        path = tmp_path / "enc.js"
        path.write_bytes(f'var k = "{noise}";'.encode())
        info = describe_js(path)["js"]
        assert info["embedded_payloads"] == []
        assert info["embedded_payload_count"] == 0
        assert info["encoded_blob_count"] == 1

    def test_short_literals_do_not_count(self, tmp_path: Path) -> None:
        # 255 characters is below the blob threshold: ordinary string data,
        # inline SVGs and small icons stay out of the census.
        path = tmp_path / "small.js"
        path.write_bytes(b'var icon = "' + b"A" * 255 + b'";')
        info = describe_js(path)["js"]
        assert info["encoded_blob_count"] == 0
        assert info["embedded_payloads"] == []

    def test_a_clean_script_reads_an_empty_census(self, tmp_path: Path) -> None:
        path = tmp_path / "clean.js"
        path.write_bytes(b"export const add = (a, b) => a + b;\n")
        info = describe_js(path)["js"]
        assert info["embedded_payloads"] == []
        assert info["embedded_payload_count"] == 0
        assert info["encoded_blob_count"] == 0

    def test_the_payload_list_caps_but_the_count_stays_exact(self, tmp_path: Path) -> None:
        stage = base64.b64encode(b"PK\x03\x04" + b"\x00" * 200).decode()
        body = "".join(f'var s{i} = "{stage}";\n' for i in range(40))
        path = tmp_path / "many.js"
        path.write_bytes(body.encode())
        info = describe_js(path)["js"]
        assert info["embedded_payload_count"] == 32  # _JS_MAX_PAYLOADS
        assert info["encoded_blob_count"] == 40

    def test_session_over_a_dropper_carries_the_census(self, tmp_path: Path) -> None:
        stage = base64.b64encode(b"\x7fELF" + b"\x00" * 200).decode()
        path = tmp_path / "dropper.js"
        path.write_bytes(f'const bin = "{stage}";'.encode())
        session = SessionRegistry().create(str(path))
        payloads = session.metadata["js"]["embedded_payloads"]
        assert [p["kind"] for p in payloads] == ["elf"]


class TestJsDynamicCodeMarkers:
    """describe_js counts the string-to-code constructs obfuscation leans on.

    A static, byte-level census -- the same honesty contract as the binary
    facts: it counts what is literally in the bytes (an aliased eval escapes
    it), and all-zero counts on a clean script are a real answer.
    """

    def test_each_marker_counts_its_own_hits(self, tmp_path: Path) -> None:
        path = tmp_path / "obf.js"
        path.write_bytes(
            b'eval("x"); eval ("y");\n'
            b'new Function("return 1")(); Function("return 2")();\n'
            b"atob(p); unescape(q);\n"
            b"String.fromCharCode(72, 105); document.write(m);\n"
        )
        markers = describe_js(path)["js"]["dynamic_code_markers"]
        assert markers == {
            "eval": 2,
            "function_constructor": 2,
            "atob": 1,
            "unescape": 1,
            "from_char_code": 1,
            "document_write": 1,
        }

    def test_word_boundaries_keep_lookalikes_out(self, tmp_path: Path) -> None:
        # evaluate(), myFunction() and datob() are ordinary identifiers; only
        # the exact constructs count.
        path = tmp_path / "plain.js"
        path.write_bytes(b"evaluate(1); myFunction(2); datob(3); medieval(4);")
        markers = describe_js(path)["js"]["dynamic_code_markers"]
        assert all(count == 0 for count in markers.values()), markers

    def test_a_clean_script_reads_all_zeros(self, tmp_path: Path) -> None:
        path = tmp_path / "clean.js"
        path.write_bytes(b"export const add = (a, b) => a + b;\n")
        markers = describe_js(path)["js"]["dynamic_code_markers"]
        assert set(markers) == {
            "eval",
            "function_constructor",
            "atob",
            "unescape",
            "from_char_code",
            "document_write",
        }
        assert all(count == 0 for count in markers.values())


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
