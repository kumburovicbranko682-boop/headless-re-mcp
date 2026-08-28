"""describe_html: tool-free HTML page facts (no browser).

Where a page loads its code from is the first thing a web reverser maps.
describe_html reads that with stdlib html.parser -- no browser: script counts
(external vs inline), the hosts scripts/stylesheets/iframes reach, the forms
the page submits (action, method, named fields), and the title. These cover a
realistic page, host de-duplication across tag kinds, the title, that a
relative src contributes no host, the form facts, a non-HTML suffix, malformed
markup, and the facts flowing through session metadata.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import SessionRegistry, describe_html

_PAGE = b"""<!doctype html><html><head><title>  Login  </title>
<link rel="stylesheet" href="https://cdn.example.com/app.css">
<script src="https://cdn.example.com/vendor.js"></script>
<script src="/local/app.js"></script>
</head><body>
<script>window.x = 1;</script>
<script>var y = 2;</script>
<iframe src="https://tracker.example.net/frame"></iframe>
</body></html>"""


def test_reads_script_and_resource_shape(tmp_path: Path) -> None:
    path = tmp_path / "page.html"
    path.write_bytes(_PAGE)
    info = describe_html(path)["html"]
    assert info["title"] == "Login"
    assert info["script_count"] == 4
    assert info["external_script_count"] == 2
    assert info["inline_script_count"] == 2
    assert info["external_scripts"] == [
        "https://cdn.example.com/vendor.js",
        "/local/app.js",
    ]
    assert info["stylesheet_count"] == 1
    assert info["iframe_count"] == 1
    assert info["truncated"] is False


def test_hosts_are_deduplicated_across_tag_kinds(tmp_path: Path) -> None:
    # cdn.example.com appears on both a script and the stylesheet; the iframe
    # adds a second host; the relative /local/app.js contributes none.
    path = tmp_path / "page.html"
    path.write_bytes(_PAGE)
    info = describe_html(path)["html"]
    assert info["external_host_count"] == 2
    assert info["external_hosts"] == ["cdn.example.com", "tracker.example.net"]


def test_a_page_with_no_scripts_reads_as_empty_counts(tmp_path: Path) -> None:
    path = tmp_path / "bare.htm"
    path.write_bytes(b"<html><head><title>x</title></head><body><p>hi</p></body></html>")
    info = describe_html(path)["html"]
    assert info["script_count"] == 0
    assert info["external_host_count"] == 0
    assert info["title"] == "x"
    assert info["form_count"] == 0
    assert info["forms"] == []


def test_forms_report_action_method_and_named_fields(tmp_path: Path) -> None:
    """A form is the page's submit surface: where the data it collects goes.

    The action, the method (defaulting to GET exactly as a browser submits it)
    and the named fields are all identity facts; unnamed fields are never
    submitted, so they are not reported, and a cross-origin action contributes
    its host like any other resource.
    """
    path = tmp_path / "login.html"
    path.write_bytes(
        b"<html><body>"
        b'<form action="https://auth.example.com/login" method="POST">'
        b'<input name="user"><input type="password" name="pass">'
        b'<input type="submit" value="go">'
        b'<textarea name="note"></textarea><select name="lang"></select>'
        b"</form>"
        b"<form><input name='q'></form>"
        b"</body></html>"
    )
    info = describe_html(path)["html"]
    assert info["form_count"] == 2
    assert info["forms"] == [
        {
            "action": "https://auth.example.com/login",
            "method": "post",
            "input_names": ["user", "pass", "note", "lang"],
        },
        {"action": None, "method": "get", "input_names": ["q"]},
    ]
    assert "auth.example.com" in info["external_hosts"]


def test_a_field_outside_any_form_is_not_reported(tmp_path: Path) -> None:
    # A bare <input> (search boxes wired up by script) belongs to no form and
    # must not be attributed to one that closed earlier.
    path = tmp_path / "loose.html"
    path.write_bytes(
        b"<html><body>"
        b'<form action="/a"><input name="inside"></form>'
        b'<input name="outside">'
        b"</body></html>"
    )
    info = describe_html(path)["html"]
    assert info["form_count"] == 1
    assert info["forms"] == [{"action": "/a", "method": "get", "input_names": ["inside"]}]


def test_an_unnamed_submit_input_is_not_a_field(tmp_path: Path) -> None:
    path = tmp_path / "submit.html"
    path.write_bytes(b'<form action="/s"><input type="submit" value="Go"></form>')
    info = describe_html(path)["html"]
    assert info["forms"] == [{"action": "/s", "method": "get", "input_names": []}]


def test_malformed_markup_does_not_raise(tmp_path: Path) -> None:
    # Unclosed tags and a stray script: the parser is lenient and still counts
    # what it can rather than failing session creation.
    path = tmp_path / "broken.html"
    path.write_bytes(b"<html><body><script src=https://x.example.com/a.js><div><p>")
    info = describe_html(path)["html"]
    assert info["script_count"] == 1
    assert info["external_host_count"] == 1


def test_ignores_a_non_html_suffix(tmp_path: Path) -> None:
    path = tmp_path / "app.js"
    path.write_bytes(b"<html></html>")
    assert describe_html(path) == {}


def _sri_token(algorithm: str, data: bytes) -> str:
    """A well-formed SRI token: <alg>-<base64 digest of data>."""
    return f"{algorithm}-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


class TestSubresourceIntegrity:
    """describe_html verifies each SRI pin against the file next to the page.

    integrity="sha384-..." is the page's own tamper-evidence: a browser
    refuses a pinned script or stylesheet whose bytes no longer hash to the
    pin. For a captured site (page and assets side by side on disk) the reader
    recomputes each pin: True is a load the browser would allow, False one it
    would block, and None means unverifiable -- a remote URL, a path outside
    the page's tree, a missing file, or a token no browser accepts either.
    """

    def _facts(self, tmp_path: Path, page: str) -> dict:
        path = tmp_path / "page.html"
        path.write_text(page, encoding="utf-8")
        return describe_html(path)["html"]

    def test_matching_pins_verify_for_script_and_stylesheet(self, tmp_path: Path) -> None:
        script = b"window.__lib = 1;\n"
        sheet = b"body{margin:0}\n"
        (tmp_path / "lib.js").write_bytes(script)
        (tmp_path / "app.css").write_bytes(sheet)
        info = self._facts(
            tmp_path,
            f'<html><head><script src="lib.js" integrity="{_sri_token("sha384", script)}">'
            "</script>"
            f'<link rel="stylesheet" href="app.css" integrity="{_sri_token("sha256", sheet)}">'
            "</head></html>",
        )
        assert info["sri_count"] == 2
        assert info["sri"] == [
            {
                "tag": "script",
                "url": "lib.js",
                "integrity": _sri_token("sha384", script),
                "ok": True,
            },
            {
                "tag": "stylesheet",
                "url": "app.css",
                "integrity": _sri_token("sha256", sheet),
                "ok": True,
            },
        ]

    def test_a_stale_pin_reads_false(self, tmp_path: Path) -> None:
        # The asset was modified after the pin was minted (or the pin after
        # the asset): the recomputed digest diverges -- the load a browser
        # would block, and the tamper signal an analyst wants.
        (tmp_path / "lib.js").write_bytes(b"window.__patched = 1;\n")
        info = self._facts(
            tmp_path,
            f'<script src="lib.js" integrity="{_sri_token("sha512", b"the original")}"></script>',
        )
        assert [e["ok"] for e in info["sri"]] == [False]

    def test_unresolvable_urls_stay_unverified(self, tmp_path: Path) -> None:
        # A remote asset, a root-relative path (no server root exists on
        # disk), and a traversal escaping the page's tree: the last names a
        # real file, which is exactly why the walk must refuse to read it.
        outside = tmp_path / "esc.js"
        outside.write_bytes(b"window.__esc = 1;\n")
        pages = tmp_path / "site"
        pages.mkdir()
        token = _sri_token("sha256", outside.read_bytes())
        path = pages / "page.html"
        path.write_text(
            f'<script src="https://cdn.example.com/v.js" integrity="{token}"></script>'
            f'<script src="/v.js" integrity="{token}"></script>'
            f'<script src="../esc.js" integrity="{token}"></script>'
            f'<script src="gone.js" integrity="{token}"></script>',
            encoding="utf-8",
        )
        info = describe_html(path)["html"]
        assert [e["ok"] for e in info["sri"]] == [None, None, None, None]

    def test_tokens_a_browser_rejects_stay_unverified(self, tmp_path: Path) -> None:
        # An alien algorithm, broken base64, and a digest of the wrong size
        # for its label: browsers ignore such tokens, so no verdict is honest.
        script = b"window.__x = 1;\n"
        (tmp_path / "x.js").write_bytes(script)
        sha256_b64 = base64.b64encode(hashlib.sha256(script).digest()).decode()
        info = self._facts(
            tmp_path,
            '<script src="x.js" integrity="md5-AAAA"></script>'
            '<script src="x.js" integrity="sha256-not*base64!"></script>'
            f'<script src="x.js" integrity="sha384-{sha256_b64}"></script>',
        )
        assert [e["ok"] for e in info["sri"]] == [None, None, None]

    def test_a_multi_token_pin_yields_one_verdict_each(self, tmp_path: Path) -> None:
        # One attribute may pin several hashes; each is auditable on its own,
        # so a stale sha256 next to a fresh sha384 reads False beside True.
        script = b"window.__multi = 1;\n"
        (tmp_path / "m.js").write_bytes(script)
        good = _sri_token("sha384", script)
        stale = _sri_token("sha256", b"an older build")
        info = self._facts(tmp_path, f'<script src="m.js" integrity="{stale} {good}"></script>')
        assert info["sri_count"] == 2
        assert [(e["integrity"], e["ok"]) for e in info["sri"]] == [(stale, False), (good, True)]

    def test_a_query_string_does_not_defeat_resolution(self, tmp_path: Path) -> None:
        # Cache-busting queries (lib.js?v=2) name the same file on disk; the
        # digest options suffix (?options per the SRI grammar) is likewise
        # not part of the base64.
        script = b"window.__v2 = 1;\n"
        (tmp_path / "lib.js").write_bytes(script)
        info = self._facts(
            tmp_path,
            f'<script src="lib.js?v=2" integrity="{_sri_token("sha256", script)}?opt"></script>',
        )
        assert [e["ok"] for e in info["sri"]] == [True]

    def test_a_page_without_pins_reports_none(self, tmp_path: Path) -> None:
        info = self._facts(tmp_path, '<script src="plain.js"></script>')
        assert info["sri_count"] == 0
        assert info["sri"] == []

    def test_the_pin_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        token = _sri_token("sha256", b"x")
        tags = "".join(
            f'<script src="s{i}.js" integrity="{token}"></script>' for i in range(300)
        )
        info = self._facts(tmp_path, f"<html><head>{tags}</head></html>")
        assert info["sri_count"] == 300
        assert len(info["sri"]) == 256


def test_session_over_a_local_html_carries_the_facts(tmp_path: Path) -> None:
    path = tmp_path / "index.html"
    path.write_bytes(_PAGE)
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.WEB
    assert "wasm" not in session.metadata
    assert session.metadata["html"]["external_script_count"] == 2
    assert session.metadata["html"]["title"] == "Login"
