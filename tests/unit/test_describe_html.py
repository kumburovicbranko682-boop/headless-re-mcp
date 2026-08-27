"""describe_html: tool-free HTML page facts (no browser).

Where a page loads its code from is the first thing a web reverser maps.
describe_html reads that with stdlib html.parser -- no browser: script counts
(external vs inline), the hosts scripts/stylesheets/iframes reach, and the
title. These cover a realistic page, host de-duplication across tag kinds, the
title, that a relative src contributes no host, a non-HTML suffix, malformed
markup, and the facts flowing through session metadata.
"""

from __future__ import annotations

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


def test_session_over_a_local_html_carries_the_facts(tmp_path: Path) -> None:
    path = tmp_path / "index.html"
    path.write_bytes(_PAGE)
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.WEB
    assert "wasm" not in session.metadata
    assert session.metadata["html"]["external_script_count"] == 2
    assert session.metadata["html"]["title"] == "Login"
