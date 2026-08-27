"""A capture URL that urlsplit rejects yields an empty query pane, not a crash.

The HAR exporter fills "Query String Parameters" from whatever URL the capture
recorded. A hostile or corrupted capture can hold a URL the parser refuses --
an unbalanced IPv6 bracket raises ValueError -- and one bad row must not abort
the export of every other entry.
"""

from __future__ import annotations

from headless_re_mcp.backends.common.har import _query_string


def test_a_url_urlsplit_rejects_yields_no_query_pairs() -> None:
    assert _query_string("http://[::1") == []
