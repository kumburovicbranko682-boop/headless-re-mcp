"""proxy.flow.get must serve an errored (response-less) flow, not choke on it.

The recorder's ``error`` hook captures flows mitmproxy could not complete -- a
refused TLS handshake, an unreachable upstream, a reset mid-request -- because
for an RE session "this host refused the handshake" is often the finding. Such a
flow has a request but ``response is None`` and a null status, and it is kept in
the raw store so ``proxy.flows`` can advertise it.

``test_proxy_error_flows.py`` pins that the errored flow is *retained* (its
``recorder.raw()`` returns the flow, not ``_OMITTED_BODY``), and its comment
states the point is "so flow_get does not 404 a row the list advertises" -- but
no test actually drives ``ProxyBackend.flow_get`` on an errored flow. That path
reads the response defensively (``getattr(resp, "status_code", None)``,
``_bounded_headers(resp) if resp else ...``, ``_raw_body(None) -> b""``), while
the *request* side reads members directly (``req.method``, ``req.pretty_url``).
Nothing stops a later "make the two sides consistent" edit from turning the
response reads direct too -- ``resp.status_code`` on an errored flow is an
``AttributeError`` on ``None`` (measured), which would make flow_get raise
``internal_error`` on exactly the flows this backend went out of its way to
capture. These tests close that gap: flow_get on an errored flow returns a
well-formed record with a null status and an empty response body, and the
request side still comes back populated.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend


def _errored_flow(flow_id: str = "e1") -> Any:
    """A retained flow shaped like mitmproxy's on a failed request: no response.

    The request carries the members flow_get reads directly; ``raw_content`` is
    present so ``_raw_body`` takes its normal path rather than its exception
    fallback. ``response`` is ``None`` -- the whole point of the case.
    """
    request = SimpleNamespace(
        method="POST",
        pretty_url=f"http://api.example.test/{flow_id}",
        headers={"content-type": "application/json"},
        raw_content=b'{"probe": true}',
    )
    return SimpleNamespace(
        id=flow_id,
        request=request,
        response=None,
        error=SimpleNamespace(msg="net::ERR_CONNECTION_REFUSED"),
    )


def _backend_returning(flow: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def test_flow_get_on_an_errored_flow_returns_a_null_status_record(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = _backend_returning(_errored_flow("e1"), monkeypatch)

    payload = backend.flow_get("s", "e1", tmp_path)

    assert payload["id"] == "e1"
    # The response side must degrade cleanly: null status, empty header map,
    # empty body -- never an AttributeError from reading members off None.
    assert payload["response"]["status"] is None
    assert payload["response"]["headers"] == {}
    assert payload["response"]["body"] == ""
    assert payload["response"]["size"] == 0
    # No response body means nothing should have spilled to an artifact.
    assert list(tmp_path.iterdir()) == []


def test_flow_get_on_an_errored_flow_still_carries_the_request(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The request is exactly what an agent wants from a failed flow -- what it
    tried to send to the host that refused it -- so it must survive."""
    backend = _backend_returning(_errored_flow("e2"), monkeypatch)

    payload = backend.flow_get("s", "e2", tmp_path)

    assert payload["request"]["method"] == "POST"
    assert payload["request"]["url"] == "http://api.example.test/e2"
    assert payload["request"]["headers"] == {"content-type": "application/json"}
    # The request body is retained and inlined as text (well under the cap).
    assert payload["request"]["body"] == '{"probe": true}'
