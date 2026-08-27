"""Unit coverage for the network redirect-trail folding (no browser needed).

CDP reuses one requestId across a redirect chain and delivers each hop's status
in the *next* requestWillBeSent's redirectResponse -- never via responseReceived.
``_redirect_trail`` folds those hops onto the request entry so a chain like
``A -(301)-> B (200)`` keeps the 301 and its URL instead of collapsing to just
``B (200)``. The CDP event handlers are closures over a live session, so this
pins the pure folding logic that the live gate then confirms end to end.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.web.client import _MAX_REDIRECTS, _redirect_trail


def test_no_redirect_response_records_nothing() -> None:
    assert _redirect_trail({"url": "https://x/"}, None) is None
    assert _redirect_trail(None, None) is None
    assert _redirect_trail({"url": "https://x/"}, {}) is None


def test_first_hop_captures_url_and_status() -> None:
    prior = {"url": "https://site/start", "status": None}
    redirect = {"url": "https://site/start", "status": 301}
    trail = _redirect_trail(prior, redirect)
    assert trail == [{"url": "https://site/start", "status": 301}]


def test_second_hop_extends_the_prior_trail_in_order() -> None:
    prior = {
        "url": "https://site/mid",
        "redirects": [{"url": "https://site/start", "status": 301}],
    }
    redirect = {"url": "https://site/mid", "status": 302}
    trail = _redirect_trail(prior, redirect)
    assert trail == [
        {"url": "https://site/start", "status": 301},
        {"url": "https://site/mid", "status": 302},
    ]


def test_hop_url_falls_back_to_prior_url_when_absent() -> None:
    """redirectResponse without a url still records the hop, using prior.url."""
    prior = {"url": "https://site/from"}
    redirect = {"status": 307}
    trail = _redirect_trail(prior, redirect)
    assert trail == [{"url": "https://site/from", "status": 307}]


def test_long_hop_url_is_bounded() -> None:
    prior: dict[str, Any] = {}
    redirect = {"url": "https://site/" + "a" * (32 * 1024), "status": 301}
    trail = _redirect_trail(prior, redirect)
    assert trail is not None
    # Bounded to _MAX_URL_BYTES (16 KiB) rather than the ~32 KiB original.
    assert len(trail[0]["url"].encode("utf-8")) <= 16 * 1024


def test_trail_is_capped_against_a_redirect_loop() -> None:
    prior: dict[str, Any] = {
        "redirects": [{"url": f"https://site/{i}", "status": 302} for i in range(_MAX_REDIRECTS)]
    }
    trail = _redirect_trail(prior, {"url": "https://site/overflow", "status": 302})
    assert trail is not None
    assert len(trail) == _MAX_REDIRECTS
