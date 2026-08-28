"""proxy.secrets detects credentials that crossed the wire in the live capture.

js.secrets/apk.secrets scan a file at rest; proxy.secrets runs the same shared
detector table over each retained flow's url, request/response headers and
decoded request/response bodies -- the Authorization header, the token echoed in
a JSON response, the OAuth secret riding a redirect url that a static pass never
sees. These cover the per-location where, dedup across flows, the detector
summary, the url/content-type pre-filters, name_filter, include_generic, the
gzip-decoded body, value truncation, the findings cap and scan budget, paging,
service routing and the read-only classification.

Secret-looking test values are assembled from fragments at runtime so the
contiguous string never appears in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
import gzip
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    _FlowRecorder,
)
from headless_re_mcp.tools.proxy import build_proxy_tools

# Assembled so the whole secret never appears contiguously in this file.
_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"
_JWT = (
    "ey" + "JhbGciOiJIUzI1NiJ9"
    + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    + "." + "dozjgNryP4J3jVmNHl0w5N" + "_XgL0n3I9PlFUP0THsR8U"
)
_BASIC_URL = "https://admin:" + "s3cr3t" + "@internal.test/login"
_HIGH_ENTROPY = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _flow_obj(
    fid: str,
    *,
    method: str = "GET",
    url: str = "http://api.test/",
    host: str = "api.test",
    req_headers: dict[str, str] | None = None,
    req_body: bytes = b"",
    status: int | None = 200,
    resp_headers: dict[str, str] | None = None,
    resp_body: bytes = b"",
    content_encoding: str = "",
) -> Any:
    resp_h = dict(resp_headers or {})
    if content_encoding:
        resp_h["content-encoding"] = content_encoding
    request = SimpleNamespace(
        method=method,
        pretty_url=url,
        host=host,
        headers=dict(req_headers or {}),
        raw_content=req_body,
        content=req_body,
        timestamp_start=1000.0,
    )
    response = SimpleNamespace(
        status_code=status,
        headers=resp_h,
        raw_content=resp_body,
    )
    return SimpleNamespace(id=fid, request=request, response=response)


def _recorder(flows: list[Any]) -> _FlowRecorder:
    recorder = _FlowRecorder(capacity=100)
    for flow in flows:
        recorder.response(flow)
    return recorder


def _backend(recorder: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def _by_detector(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["detector"]: row for row in out["secrets"]}


def test_proxy_secrets_finds_in_response_body(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/a", resp_body=f'{{"key":"{_AWS}"}}'.encode()),
            _flow_obj("2", url="http://api.test/b", resp_body=b'{"ok":true}'),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["total"] == 1
    assert out["scan_capped"] is False
    row = out["secrets"][0]
    assert row["detector"] == "aws_access_key_id"
    assert row["value"] == _AWS
    assert row["count"] == 1
    assert row["where"] == ["response_body"]
    assert row["first_flow"]["id"] == "1"
    assert row["first_flow"]["where"] == "response_body"
    assert out["detectors"] == ["aws_access_key_id"]


def test_proxy_secrets_finds_in_request_headers(monkeypatch: Any) -> None:
    rec = _recorder(
        [_flow_obj("1", method="POST", req_headers={"Authorization": f"Bearer {_JWT}"})]
    )
    row = _backend(rec, monkeypatch).secrets("s")["secrets"][0]
    assert row["detector"] == "jwt"
    assert row["value"] == _JWT
    assert row["where"] == ["request_headers"]


def test_proxy_secrets_finds_in_url(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1", url=_BASIC_URL)])
    row = _backend(rec, monkeypatch).secrets("s")["secrets"][0]
    assert row["detector"] == "basic_auth_url"
    assert row["where"] == ["url"]
    assert row["first_flow"]["url"].startswith("https://admin:")


def test_proxy_secrets_dedupes_across_flows(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/1", resp_body=f"k={_AWS}".encode()),
            _flow_obj("2", url="http://api.test/2", resp_body=f"k={_AWS}".encode()),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["total"] == 1
    row = out["secrets"][0]
    assert row["count"] == 2
    # First occurrence pins the reference flow.
    assert row["first_flow"]["id"] == "1"


def test_proxy_secrets_merges_locations_in_one_flow(monkeypatch: Any) -> None:
    # The same token in the request header and the response body: one finding,
    # count 2, both locations, reference pinned to the first (header) hit.
    rec = _recorder(
        [
            _flow_obj(
                "1",
                req_headers={"Authorization": f"Bearer {_JWT}"},
                resp_body=f'{{"echo":"{_JWT}"}}'.encode(),
            )
        ]
    )
    row = _backend(rec, monkeypatch).secrets("s")["secrets"][0]
    assert row["count"] == 2
    assert row["where"] == ["request_headers", "response_body"]
    assert row["first_flow"]["where"] == "request_headers"


def test_proxy_secrets_reports_multiple_detector_kinds(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", resp_body=f"aws={_AWS} stripe={_STRIPE}".encode()),
            _flow_obj("2", req_headers={"Authorization": f"Bearer {_JWT}"}),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["total"] == 3
    assert out["detectors"] == ["aws_access_key_id", "jwt", "stripe_secret_key"]


def test_proxy_secrets_no_secrets_is_empty(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1", resp_body=b"nothing sensitive here")])
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["total"] == 0
    assert out["secrets"] == []
    assert out["detectors"] == []


def test_proxy_secrets_name_filter_matches_detector_or_value(monkeypatch: Any) -> None:
    rec = _recorder(
        [_flow_obj("1", resp_body=f"aws={_AWS} stripe={_STRIPE}".encode())]
    )
    backend = _backend(rec, monkeypatch)
    by_kind = backend.secrets("s", name_filter="STRIPE")
    assert [r["detector"] for r in by_kind["secrets"]] == ["stripe_secret_key"]
    by_value = backend.secrets("s", name_filter=_AWS.lower())
    assert [r["detector"] for r in by_value["secrets"]] == ["aws_access_key_id"]


def test_proxy_secrets_include_generic_is_opt_in(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1", resp_body=_HIGH_ENTROPY.encode())])
    backend = _backend(rec, monkeypatch)
    assert backend.secrets("s")["total"] == 0
    out = backend.secrets("s", include_generic=True)
    assert [r["detector"] for r in out["secrets"]] == ["generic_high_entropy"]
    assert out["secrets"][0]["value"] == _HIGH_ENTROPY


def test_proxy_secrets_decodes_gzip_response(monkeypatch: Any) -> None:
    payload = gzip.compress(f'{{"key":"{_AWS}"}}'.encode())
    rec = _recorder(
        [
            _flow_obj(
                "1",
                resp_headers={"content-type": "application/json"},
                resp_body=payload,
                content_encoding="gzip",
            )
        ]
    )
    row = _backend(rec, monkeypatch).secrets("s")["secrets"][0]
    assert row["detector"] == "aws_access_key_id"
    assert row["where"] == ["response_body"]


def test_proxy_secrets_value_truncated(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_PROXY_SECRET_VALUE", 8)
    rec = _recorder([_flow_obj("1", resp_body=f"tok={_JWT}".encode())])
    row = _backend(rec, monkeypatch).secrets("s")["secrets"][0]
    assert row["value_truncated"] is True
    assert len(row["value"]) == 8


def test_proxy_secrets_url_filter_narrows_scope(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/x", resp_body=f"k={_AWS}".encode()),
            _flow_obj("2", url="http://cdn.test/y", resp_body=f"k={_STRIPE}".encode()),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s", url_filter="cdn.test")
    assert [r["detector"] for r in out["secrets"]] == ["stripe_secret_key"]


def test_proxy_secrets_content_type_filter_narrows_scope(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", resp_headers={"content-type": "application/json"},
                      resp_body=f"k={_AWS}".encode()),
            _flow_obj("2", resp_headers={"content-type": "text/html"},
                      resp_body=f"k={_STRIPE}".encode()),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s", content_type_filter="json")
    assert [r["detector"] for r in out["secrets"]] == ["aws_access_key_id"]


def test_proxy_secrets_pages_and_reports_has_more(monkeypatch: Any) -> None:
    # Three distinct detectors -> three findings, page two at a time.
    rec = _recorder(
        [_flow_obj("1", resp_body=f"a={_AWS} s={_STRIPE} j={_JWT}".encode())]
    )
    out = _backend(rec, monkeypatch).secrets("s", offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 3
    assert out["has_more"] is True
    assert out["offset"] == 0


def test_proxy_secrets_findings_cap_sets_scan_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_PROXY_SECRET_FINDINGS", 1)
    rec = _recorder([_flow_obj("1", resp_body=f"a={_AWS} s={_STRIPE}".encode())])
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["scan_capped"] is True
    assert out["total"] == 1


def test_proxy_secrets_scan_budget_caps_the_walk(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_SEARCH_SCAN_BYTES", 8)
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/1", resp_body=f"first has {_AWS}".encode()),
            _flow_obj("2", url="http://api.test/2", resp_body=f"second has {_STRIPE}".encode()),
        ]
    )
    out = _backend(rec, monkeypatch).secrets("s")
    assert out["scan_capped"] is True
    # The first flow's body already blew the tiny budget; the second went
    # unscanned even though it also carried a secret.
    assert [r["detector"] for r in out["secrets"]] == ["aws_access_key_id"]


def test_proxy_secrets_ignores_omitted_bodies_but_scans_url(monkeypatch: Any) -> None:
    summary = {"id": "1", "seq": 1, "method": "GET", "url": _BASIC_URL,
               "host": "internal.test", "status": 200}
    stub = SimpleNamespace(snapshot=lambda: [summary], raw=lambda fid: _OMITTED_BODY)
    row = _backend(stub, monkeypatch).secrets("s")["secrets"][0]
    assert row["detector"] == "basic_auth_url"
    assert row["where"] == ["url"]


def test_service_proxy_secrets_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_secrets(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"secrets": [], "total": 0}

        monkeypatch.setattr(service._proxy_backend, "secrets", fake_secrets)
        result = service.proxy_secrets(
            "sess", limit=5, url_filter="api", name_filter="jwt", include_generic=True
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["limit"] == 5
        assert captured["url_filter"] == "api"
        assert captured["name_filter"] == "jwt"
        assert captured["include_generic"] is True
    finally:
        service.close_all()


def test_proxy_secrets_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("proxy.secrets").split())
    assert "detector" in doc
    assert "where" in doc
    assert "scan_capped" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "proxy.secrets" in _READ_ONLY_NAMES
