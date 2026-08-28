"""proxy.secrets classifies a capture against the credential table, by leak site.

The core is scan_flow_secrets, pure over the recorder's two views (summary rows
plus a flow_id -> raw-flow lookup), so these drive it with fake rows and a fake
lookup returning minimal request/response stand-ins. No live proxy needed. The
credential table and redaction are shared with js.secrets/apk.secrets.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    scan_flow_secrets,
)
from headless_re_mcp.tools.proxy import build_proxy_tools

_AWS = "AKIAIOSFODNN7EXAMPLE"
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3In0.SflKxwRJSMeKKF2QT4"
_STRIPE = "sk_live_0123456789abcdefABCDEF"


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


class _Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._items)


class _Part:
    def __init__(self, headers: list[tuple[str, str]], body: bytes) -> None:
        self.headers = _Headers(headers)
        self.raw_content = body


def _flow(
    *,
    req_headers: list[tuple[str, str]] | None = None,
    req_body: bytes = b"",
    resp_headers: list[tuple[str, str]] | None = None,
    resp_body: bytes = b"",
) -> Any:
    return SimpleNamespace(
        request=_Part(req_headers or [], req_body),
        response=_Part(resp_headers or [], resp_body),
    )


def _row(flow_id: str, method: str, url: str, host: str, status: int) -> dict[str, Any]:
    return {
        "id": flow_id,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
    }


def _by_kind(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(f["kind"]): f for f in payload["findings"]}


def test_finds_a_token_in_an_authorization_header() -> None:
    rows = [_row("1", "GET", "https://api.example/me", "api.example", 200)]
    raw = {"1": _flow(req_headers=[("Authorization", f"Bearer {_JWT}")])}
    payload = scan_flow_secrets(rows, lambda fid: raw.get(fid))
    finding = _by_kind(payload)["jwt"]
    assert finding["count"] == 1
    assert finding["fields"] == ["request_headers"]
    assert finding["flow_count"] == 1
    assert finding["locations"][0]["field"] == "request_headers"
    assert finding["locations"][0]["id"] == "1"
    assert _JWT not in str(finding["preview"])


def test_finds_a_key_in_the_url_of_an_evicted_flow() -> None:
    # Body evicted: only the summary url is scannable, but that still catches a
    # key leaked as a query parameter.
    rows = [_row("9", "GET", f"https://api/x?key={_AWS}", "api", 200)]
    payload = scan_flow_secrets(rows, lambda _fid: _OMITTED_BODY)
    finding = _by_kind(payload)["aws_access_key_id"]
    assert finding["fields"] == ["url"]
    assert payload["body_unavailable"] == 1


def test_dedupes_one_secret_across_fields_and_flows() -> None:
    # Same JWT in a request header on flow 1 and echoed in a response body on
    # flow 2: one finding, two occurrences, two fields, two flows.
    rows = [
        _row("1", "GET", "https://api/a", "api", 200),
        _row("2", "GET", "https://api/b", "api", 200),
    ]
    raw = {
        "1": _flow(req_headers=[("Authorization", f"Bearer {_JWT}")]),
        "2": _flow(resp_body=f'{{"id_token":"{_JWT}"}}'.encode()),
    }
    payload = scan_flow_secrets(rows, lambda fid: raw.get(fid))
    finding = _by_kind(payload)["jwt"]
    assert finding["count"] == 2
    assert set(finding["fields"]) == {"request_headers", "response_body"}
    assert finding["flow_count"] == 2
    assert payload["total"] == 1
    assert payload["total_findings"] == 2


def test_orders_high_severity_first() -> None:
    rows = [_row("1", "POST", "https://api/pay", "api", 200)]
    raw = {
        "1": _flow(
            req_body=f'{{"stripe":"{_STRIPE}","jwt":"{_JWT}"}}'.encode()
        )
    }
    payload = scan_flow_secrets(rows, lambda fid: raw.get(fid))
    severities = [f["severity"] for f in payload["findings"]]
    assert severities[0] == "high"  # stripe_secret_key before the medium jwt
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1}[s])


def test_clean_capture_has_no_findings() -> None:
    rows = [_row("1", "GET", "https://api/health", "api", 200)]
    raw = {"1": _flow(resp_body=b'{"status":"ok"}')}
    payload = scan_flow_secrets(rows, lambda fid: raw.get(fid))
    assert payload["findings"] == []
    assert payload["kinds"] == {}
    assert payload["scanned"] == 1


def test_caps_the_finding_list() -> None:
    rows = [
        _row(str(i), "GET", f"https://api/{i}?key=sk_live_{i:022d}ABCDEF", "api", 200)
        for i in range(5)
    ]
    payload = scan_flow_secrets(rows, lambda _fid: None, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["truncated"] is True


def test_empty_capture() -> None:
    payload = scan_flow_secrets([], lambda _fid: None)
    assert payload["count"] == 0
    assert payload["scanned"] == 0
    assert payload["total_findings"] == 0
    assert payload["truncated"] is False


def test_locations_are_bounded() -> None:
    import headless_re_mcp.backends.proxy.client as proxy_client

    # The same key leaks in 20 flows; keep at most ten sample locations.
    rows = [_row(str(i), "GET", f"https://api/{i}?key={_AWS}", "api", 200) for i in range(20)]
    payload = scan_flow_secrets(rows, lambda _fid: None)
    finding = _by_kind(payload)["aws_access_key_id"]
    assert finding["count"] == 20
    assert finding["flow_count"] == 20
    assert len(finding["locations"]) == proxy_client._MAX_SECRET_LOCATIONS


def test_service_proxy_secrets_dispatch() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())

    class _Recorder:
        def snapshot(self) -> list[dict[str, Any]]:
            return [_row("1", "GET", f"https://api/x?key={_AWS}", "api", 200)]

        def raw(self, _fid: str) -> Any:
            return None

    service._proxy_backend._get = lambda _sid: SimpleNamespace(  # type: ignore[attr-defined]
        recorder=_Recorder()
    )
    result = service.proxy_secrets("sess-1")
    assert result.ok, result.error
    assert result.data is not None
    assert "aws_access_key_id" in _by_kind(result.data)


def test_proxy_secrets_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_proxy_tools(service)}
    assert "proxy.secrets" in names


def test_proxy_secrets_docstring_names_the_shape() -> None:
    doc = " ".join(_tool_docstring("proxy.secrets").split())
    assert "findings" in doc
    assert "flow_count" in doc
    assert "locations" in doc
    assert "body_unavailable" in doc
    assert "redact" in doc.lower()
