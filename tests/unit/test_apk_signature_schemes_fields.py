"""apk.certificates surfaces which signing schemes (v1/v2/v3) signed the APK."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _signature_schemes
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Cert:
    def __init__(self) -> None:
        self.subject = "CN=Test"
        self.issuer = "CN=Test"
        self.serial_number = 1
        self.sha256_fingerprint = "aa"


class _SchemeApk:
    """A fake APK whose is_signed_v* probes drive scheme detection."""

    def __init__(self, v1: bool, v2: bool, v3: bool) -> None:
        self._v1, self._v2, self._v3 = v1, v2, v3

    def get_signature_names(self) -> list[str]:
        return ["META-INF/K.RSA"] if self._v1 else []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert()]

    def is_signed_v1(self) -> bool:
        return self._v1

    def is_signed_v2(self) -> bool:
        return self._v2

    def is_signed_v3(self) -> bool:
        return self._v3


def _certs(v1: bool, v2: bool, v3: bool) -> dict:
    client = ApkClient()
    client._apk = lambda _path: _SchemeApk(v1, v2, v3)  # type: ignore[method-assign]
    return client.certificates(Path("dummy.apk"))


def test_signature_schemes_helper_reads_each_probe() -> None:
    """The helper maps is_signed_v1/v2/v3 straight through to a {v1,v2,v3} dict."""
    assert _signature_schemes(_SchemeApk(True, False, False)) == {
        "v1": True,
        "v2": False,
        "v3": False,
    }
    assert _signature_schemes(_SchemeApk(True, True, True)) == {
        "v1": True,
        "v2": True,
        "v3": True,
    }


def test_v1_only_apk_is_flagged_janus() -> None:
    """A v1-only APK (no v2/v3) is reported as v1_only -- the Janus signal."""
    payload = _certs(True, False, False)
    assert payload["signature_schemes"] == {"v1": True, "v2": False, "v3": False}
    assert payload["v1_only"] is True
    assert payload["v1_signed"] is True


def test_v2_v3_signed_apk_is_not_v1_only() -> None:
    """A modern v1+v2+v3 APK closes Janus, so v1_only is false."""
    payload = _certs(True, True, True)
    assert payload["signature_schemes"] == {"v1": True, "v2": True, "v3": True}
    assert payload["v1_only"] is False


def test_v2_only_apk_reports_no_v1() -> None:
    """A v2-only APK (no JAR signature) reports v1 false and is not v1_only."""
    payload = _certs(False, True, False)
    assert payload["signature_schemes"] == {"v1": False, "v2": True, "v3": False}
    assert payload["v1_only"] is False
    # v1_signed reflects the JAR signature files, which a v2-only APK lacks.
    assert payload["v1_signed"] is False


def test_unsigned_apk_is_not_v1_only() -> None:
    """An unsigned APK is all-false, and v1_only stays false (nothing to warn)."""
    payload = _certs(False, False, False)
    assert payload["signature_schemes"] == {"v1": False, "v2": False, "v3": False}
    assert payload["v1_only"] is False


def test_schemes_helper_survives_missing_probes() -> None:
    """An androguard too old to expose is_signed_v* degrades to all-false."""

    class _Old:
        def get_signature_names(self) -> list[str]:
            return ["META-INF/K.RSA"]

        def get_certificates(self) -> list[_Cert]:
            return [_Cert()]

    assert _signature_schemes(_Old()) == {"v1": False, "v2": False, "v3": False}
    client = ApkClient()
    client._apk = lambda _path: _Old()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    # v1_signed still derives from the signature files, independent of the probes.
    assert payload["v1_signed"] is True
    assert payload["v1_only"] is False


def test_schemes_helper_survives_raising_probes() -> None:
    """A probe that raises (odd signing block) is treated as absent, not fatal."""

    class _Boom:
        def is_signed_v1(self) -> bool:
            raise RuntimeError("bad signing block")

        def is_signed_v2(self) -> bool:
            return True

        def is_signed_v3(self) -> bool:
            raise ValueError("truncated")

    assert _signature_schemes(_Boom()) == {"v1": False, "v2": True, "v3": False}


def test_certificates_docstring_names_the_scheme_fields() -> None:
    """The tool docstring documents the new scheme fields and the Janus reason."""
    doc = _tool_docstring("apk.certificates")
    for token in ("signature_schemes", "v1_only", "Janus"):
        assert token in doc
