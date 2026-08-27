"""proxy.ca.install_android must name the push, not an install."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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


def test_ca_install_android_answers_with_pushed_to_not_installed() -> None:
    """The catalog said install and never named the payload.

    Measured against ProxyAnalysisMixin.proxy_ca_install_android: success
    is pushed_to and note. There is no installed, ok or path field.
    Looking for installed after a successful call reads as a system CA
    that was never imported; the note says root and remount are still
    required.
    """
    source = Path(
        ProxyAnalysisMixin.proxy_ca_install_android.__code__.co_filename
    ).read_text(encoding="utf-8")
    start = source.index("def proxy_ca_install_android")
    chunk = source[start : source.index("def _proxy_wrap", start)]
    marker = chunk.index("data = {")
    returned = chunk[marker : chunk.index("}", marker) + 1]
    assert '"pushed_to"' in returned
    assert '"note"' in returned
    assert '"installed"' not in returned
    assert '"ok"' not in returned
    assert '"path"' not in returned
    doc = _tool_docstring("proxy.ca.install_android")
    assert "Answers with pushed_to" in doc
    assert "note" in doc
    assert "installed" in doc


class TestCaInstallSurfacesLanding:
    """proxy.ca.install_android reports whether the CA actually reached tmp.

    The push it delegates to now verifies the landing; carrying that through
    keeps the CA flow from claiming the PEM is on the device just because adb
    returned.
    """

    def _service(self, tmp_path: Any, push_return: dict[str, Any]) -> tuple[Any, str]:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        created = service.create_session("https://example.com", target="web")
        assert created.data is not None
        session_id = str(created.data["session"]["id"])
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("x", encoding="utf-8")
        service._proxy_backend.ca_cert_path = lambda: cert  # type: ignore[method-assign]
        service._adb_backend.push = (  # type: ignore[method-assign]
            lambda serial, local_path, remote_path: dict(push_return)
        )
        return service, session_id

    def test_a_verified_landing_is_reported(self, tmp_path: Any) -> None:
        service, session_id = self._service(
            tmp_path,
            {"local": "c", "remote": "/data/local/tmp/mitmproxy-ca-cert.pem",
             "size": 42, "pushed": True, "remote_size": 42},
        )
        try:
            result = service.proxy_ca_install_android(session_id, "emulator-5554")
            assert result.ok, result.error
            assert result.data is not None
            assert result.data["landed"] is True
            assert result.data["remote_size"] == 42
            assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
        finally:
            service.close_all()

    def test_a_push_that_did_not_land_is_flagged(self, tmp_path: Any) -> None:
        service, session_id = self._service(
            tmp_path,
            {"local": "c", "remote": "/data/local/tmp/mitmproxy-ca-cert.pem",
             "size": 42, "pushed": False, "remote_size": None},
        )
        try:
            result = service.proxy_ca_install_android(session_id, "emulator-5554")
            assert result.ok, result.error
            assert result.data is not None
            assert result.data["landed"] is False
            assert "did not land" in str(result.data["note"])
        finally:
            service.close_all()

    def test_an_unverifiable_push_reports_null(self, tmp_path: Any) -> None:
        service, session_id = self._service(
            tmp_path,
            {"local": "c", "remote": "/data/local/tmp/mitmproxy-ca-cert.pem", "size": 42},
        )
        try:
            result = service.proxy_ca_install_android(session_id, "emulator-5554")
            assert result.ok, result.error
            assert result.data is not None
            assert result.data["landed"] is None
            assert "could not be verified" in str(result.data["note"])
        finally:
            service.close_all()
