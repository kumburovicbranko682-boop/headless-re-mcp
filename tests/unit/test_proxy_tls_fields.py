"""proxy.tls folds per-flow upstream TLS handshakes into a per-host inventory.

The core is fold_tls, pure over the recorder's TLS side-table rows, so these
drive it with fake rows plus one end-to-end capture through _FlowRecorder to
prove the handshake fields (version, cipher, alpn, sni and the leaf cert) are
snapshotted off mitmproxy's server_conn, and that a cleartext flow is recorded
as such.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_TLS_ALTNAMES,
    _cert_summary,
    _extract_tls,
    _FlowRecorder,
    fold_tls,
)
from headless_re_mcp.core.service_proxy import ProxyAnalysisMixin
from headless_re_mcp.tools.proxy import build_proxy_tools


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


def _row(
    host: str,
    *,
    tls: bool = True,
    version: str | None = "TLSv1.3",
    cipher: str | None = "TLS_AES_256_GCM_SHA384",
    alpn: str | None = "h2",
    sni: str | None = None,
    cert: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "host": host,
        "scheme": "https" if tls else "http",
        "tls": tls,
        "version": version,
        "cipher": cipher,
        "alpn": alpn,
        "sni": sni if sni is not None else host,
        "cert": cert,
    }


def _cert(
    *,
    cn: str = "api.example",
    issuer: str = "Let's Encrypt",
    altnames: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        cn=cn,
        issuer=[("C", "US"), ("CN", issuer)],
        serial=1234567890,
        notbefore="2026-01-01T00:00:00Z",
        notafter="2026-04-01T00:00:00Z",
        altnames=altnames if altnames is not None else ["api.example", "www.api.example"],
    )


# ---- fold_tls: the pure per-host roll-up -----------------------------------


def test_fold_tls_folds_by_host_with_distinct_versions_and_ciphers() -> None:
    rows = [
        _row("a.example", version="TLSv1.3", cipher="C1"),
        _row("a.example", version="TLSv1.2", cipher="C2"),
        _row("b.example", version="TLSv1.3", cipher="C1"),
    ]
    result = fold_tls(rows)
    assert result["total"] == 2
    assert result["count"] == 2
    assert result["total_flows"] == 3
    by_host = {h["host"]: h for h in result["hosts"]}
    # a.example is busiest (2 flows), ranks first.
    assert result["hosts"][0]["host"] == "a.example"
    assert by_host["a.example"]["flows"] == 2
    assert by_host["a.example"]["versions"] == ["TLSv1.2", "TLSv1.3"]
    assert by_host["a.example"]["ciphers"] == ["C1", "C2"]
    assert by_host["a.example"]["tls"] is True
    assert by_host["a.example"]["cleartext"] is False


def test_fold_tls_flags_cleartext_and_weak() -> None:
    rows = [
        _row("secure.example", version="TLSv1.3"),
        _row("plain.example", tls=False, version=None, cipher=None, alpn=None),
        _row("old.example", version="TLSv1"),
        _row("old.example", version="TLSv1.2"),
    ]
    result = fold_tls(rows)
    by_host = {h["host"]: h for h in result["hosts"]}
    assert by_host["plain.example"]["cleartext"] is True
    assert by_host["plain.example"]["tls"] is False
    assert by_host["plain.example"]["weak"] is False
    # A single obsolete negotiation flags the whole host, even alongside a good one.
    assert by_host["old.example"]["weak"] is True
    assert by_host["secure.example"]["weak"] is False
    agg = result["aggregate"]
    assert agg["total_hosts"] == 3
    assert agg["tls_hosts"] == 2
    assert agg["cleartext_hosts"] == 1
    assert agg["weak_hosts"] == 1


def test_fold_tls_keeps_first_non_null_cert() -> None:
    cert = {"subject": "api.example", "issuer": "Let's Encrypt"}
    rows = [
        _row("api.example", cert=None),
        _row("api.example", cert=cert),
        _row("api.example", cert={"subject": "other"}),
    ]
    result = fold_tls(rows)
    host = result["hosts"][0]
    assert host["cert"] == cert


def test_fold_tls_pages_and_reports_truncation() -> None:
    rows = [_row(f"h{i}.example") for i in range(5)]
    result = fold_tls(rows, limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["truncated"] is True


def test_fold_tls_handles_an_empty_capture() -> None:
    result = fold_tls([])
    assert result["hosts"] == []
    assert result["total"] == 0
    assert result["total_flows"] == 0
    assert result["aggregate"] == {
        "total_hosts": 0,
        "tls_hosts": 0,
        "cleartext_hosts": 0,
        "weak_hosts": 0,
    }


# ---- _cert_summary: defensive leaf-certificate extraction -------------------


def test_cert_summary_pulls_issuer_cn_and_fields() -> None:
    sc = SimpleNamespace(certificate_list=[_cert()])
    summary = _cert_summary(sc)
    assert summary is not None
    assert summary["subject"] == "api.example"
    assert summary["issuer"] == "Let's Encrypt"
    assert summary["serial"] == "1234567890"
    assert summary["not_after"] == "2026-04-01T00:00:00Z"
    assert summary["altnames"] == ["api.example", "www.api.example"]
    assert summary["altnames_truncated"] is False


def test_cert_summary_caps_altnames() -> None:
    many = [f"n{i}.example" for i in range(_MAX_TLS_ALTNAMES + 10)]
    sc = SimpleNamespace(certificate_list=[_cert(altnames=many)])
    summary = _cert_summary(sc)
    assert summary is not None
    assert len(summary["altnames"]) == _MAX_TLS_ALTNAMES
    assert summary["altnames_truncated"] is True


def test_cert_summary_falls_back_to_cert_attribute() -> None:
    sc = SimpleNamespace(certificate_list=None, cert=_cert(cn="fallback"))
    summary = _cert_summary(sc)
    assert summary is not None
    assert summary["subject"] == "fallback"


def test_cert_summary_none_without_a_certificate() -> None:
    assert _cert_summary(None) is None
    assert _cert_summary(SimpleNamespace(certificate_list=None, cert=None)) is None


# ---- _extract_tls: reading one flow's server_conn --------------------------


def test_extract_tls_reads_server_conn_and_decodes_alpn_bytes() -> None:
    flow = SimpleNamespace(
        server_conn=SimpleNamespace(
            tls_established=True,
            tls_version="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256",
            sni="api.example",
            alpn=b"h2",
            certificate_list=[_cert()],
        )
    )
    row = _extract_tls(flow, "api.example", "https")
    assert row["tls"] is True
    assert row["version"] == "TLSv1.3"
    assert row["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert row["sni"] == "api.example"
    assert row["alpn"] == "h2"
    assert row["cert"]["subject"] == "api.example"


def test_extract_tls_cleartext_flow_has_no_crypto() -> None:
    flow = SimpleNamespace(server_conn=None)
    row = _extract_tls(flow, "plain.example", "http")
    assert row["tls"] is False
    assert row["version"] is None
    assert row["cipher"] is None
    assert row["cert"] is None


# ---- end to end through the recorder ---------------------------------------


def test_recorder_snapshots_tls_and_fold_reports_it() -> None:
    recorder = _FlowRecorder()
    recorder.response(
        SimpleNamespace(
            id="f1",
            request=SimpleNamespace(
                method="GET", pretty_url="https://api.example/x", host="api.example",
                scheme="https",
            ),
            response=SimpleNamespace(status_code=200, headers={"content-type": "application/json"}),
            server_conn=SimpleNamespace(
                tls_established=True,
                tls_version="TLSv1.2",
                cipher="ECDHE-RSA-AES128-GCM-SHA256",
                sni="api.example",
                alpn="http/1.1",
                certificate_list=[_cert()],
            ),
        )
    )
    recorder.response(
        SimpleNamespace(
            id="f2",
            request=SimpleNamespace(
                method="GET", pretty_url="http://plain.example/y", host="plain.example",
                scheme="http",
            ),
            response=SimpleNamespace(status_code=200, headers={}),
            server_conn=None,
        )
    )
    snapshot = recorder.tls_snapshot()
    assert len(snapshot) == 2

    result = fold_tls(snapshot)
    by_host = {h["host"]: h for h in result["hosts"]}
    assert by_host["api.example"]["tls"] is True
    assert by_host["api.example"]["versions"] == ["TLSv1.2"]
    assert by_host["api.example"]["cert"]["issuer"] == "Let's Encrypt"
    assert by_host["plain.example"]["cleartext"] is True
    assert result["aggregate"]["weak_hosts"] == 0


def test_recorder_clear_drops_tls() -> None:
    recorder = _FlowRecorder()
    recorder.response(
        SimpleNamespace(
            id="f1",
            request=SimpleNamespace(
                method="GET", pretty_url="https://h/a", host="h", scheme="https"
            ),
            response=SimpleNamespace(status_code=200, headers={}),
            server_conn=SimpleNamespace(tls_established=True, tls_version="TLSv1.3"),
        )
    )
    assert len(recorder.tls_snapshot()) == 1
    recorder.clear()
    assert recorder.tls_snapshot() == []


# ---- service dispatch + tool registration ----------------------------------


class _StubService(ProxyAnalysisMixin):
    def __init__(self, backend: Any) -> None:
        self._proxy_backend = backend


def test_service_proxy_tls_dispatches_to_backend() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class _FakeBackend:
        def tls(self, session_id: str, *, limit: int = 100) -> dict[str, Any]:
            calls.append((session_id, {"limit": limit}))
            return {"hosts": [], "total": 0}

    service = _StubService(_FakeBackend())
    result = service.proxy_tls("sess-1", limit=25)
    assert result.ok is True
    assert calls == [("sess-1", {"limit": 25})]


def test_proxy_tls_is_registered_and_documented() -> None:
    doc = _tool_docstring("proxy.tls")
    assert doc
    assert "cleartext" in doc
    assert "weak" in doc
    for field in ("versions", "ciphers", "cert", "aggregate", "sni", "alpn"):
        assert field in doc
