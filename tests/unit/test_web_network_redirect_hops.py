"""web.network.list keeps every redirect hop instead of collapsing the chain.

CDP reuses one requestId for a whole redirect chain: each hop after the first
arrives as another ``Network.requestWillBeSent`` for the *same* id, carrying the
finished hop's status and URL in ``redirectResponse`` -- a redirect never fires
``Network.responseReceived``, so that field is the only place a 3xx ever
appears. The old handler ignored it and overwrote the entry keyed by requestId,
so ``web.network.list`` showed only the final hop: the 301/302/307 that decides
where traffic really goes -- the very thing a login-flow or SSO analysis needs
to read -- silently vanished, and nothing said a redirect ever happened.

The handler now stores each finished hop under a synthetic ``id:redirect:N``
key before the requestId is reused, marked ``redirect: true`` with its 3xx
``status`` and ``redirected_to`` (the URL it forwarded to). These tests drive
the CDP handlers directly with hand-written events; a live gate proves the same
against a real Chromium and a really redirecting origin.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_REQUESTS,
    WebBackend,
    _WebSession,
)
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Cdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        del method, params

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired_session() -> tuple[_WebSession, _Cdp]:
    cdp = _Cdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp


def _will_be_sent(
    request_id: str, url: str, *, redirect_from: tuple[str, int] | None = None
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "requestId": request_id,
        "request": {"url": url, "method": "GET"},
        "type": "Document",
    }
    if redirect_from is not None:
        from_url, status = redirect_from
        params["redirectResponse"] = {
            "url": from_url,
            "status": status,
            "mimeType": "text/html",
        }
    return params


def test_a_redirect_hop_survives_as_its_own_entry() -> None:
    """The bug: the 302 hop was overwritten by the hop it forwarded to.

    After a /login -> /home redirect the capture used to hold one entry, for
    /home, with no trace that /login answered 302. Now the finished hop stays,
    marked as a redirect with its status and target, and the new hop follows.
    """
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]

    on_request(_will_be_sent("r1", "https://site/login"))
    on_request(
        _will_be_sent(
            "r1", "https://site/home", redirect_from=("https://site/login", 302)
        )
    )

    entries = list(handle.requests.values())
    assert len(entries) == 2

    hop = entries[0]
    assert hop["url"] == "https://site/login"
    assert hop["status"] == 302
    assert hop["redirect"] is True
    assert hop["redirected_to"] == "https://site/home"
    assert hop["mimeType"] == "text/html"
    assert hop["requestId"] == "r1:redirect:1"

    final = entries[1]
    assert final["requestId"] == "r1"
    assert final["url"] == "https://site/home"
    # The final hop has not answered yet, and is not itself a redirect.
    assert final["status"] is None
    assert "redirect" not in final
    assert "redirected_to" not in final


def test_a_two_hop_chain_lists_every_hop_in_wire_order() -> None:
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_response = cdp.handlers["Network.responseReceived"]

    on_request(_will_be_sent("r7", "https://a/1"))
    on_request(_will_be_sent("r7", "https://a/2", redirect_from=("https://a/1", 301)))
    on_request(_will_be_sent("r7", "https://a/3", redirect_from=("https://a/2", 307)))
    on_response(
        {"requestId": "r7", "response": {"status": 200, "mimeType": "text/plain"}}
    )

    rows = [
        (entry["url"], entry["status"], entry.get("redirected_to"))
        for entry in handle.requests.values()
    ]
    assert rows == [
        ("https://a/1", 301, "https://a/2"),
        ("https://a/2", 307, "https://a/3"),
        ("https://a/3", 200, None),
    ]
    # responseReceived touched only the final hop; the 3xx statuses stand.
    assert [entry["requestId"] for entry in handle.requests.values()] == [
        "r7:redirect:1",
        "r7:redirect:2",
        "r7",
    ]


def test_a_plain_request_carries_no_redirect_fields() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_will_be_sent("r2", "https://plain/"))
    entry = handle.requests["r2"]
    assert "redirect" not in entry
    assert "redirected_to" not in entry


def test_redirect_entries_count_against_the_request_ring_cap() -> None:
    """Synthetic hop entries live in the same bounded ring, not beside it."""
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_request(_will_be_sent("chain", "https://c/0"))
    for hop in range(_MAX_REQUESTS + 5):
        on_request(
            _will_be_sent(
                "chain",
                f"https://c/{hop + 1}",
                redirect_from=(f"https://c/{hop}", 302),
            )
        )
    assert len(handle.requests) == _MAX_REQUESTS
    assert handle.requests_dropped > 0


def test_web_network_list_docstring_names_the_redirect_fields() -> None:
    doc = " ".join(_tool_docstring("web.network.list").split())
    assert "redirect true" in doc
    assert "redirected_to" in doc
    assert "not collapsed" in doc
