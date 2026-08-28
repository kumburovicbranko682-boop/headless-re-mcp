"""apk.secrets scans the DEX string pool for hard-coded credentials.

It mocks the parsed analysis with a fake string pool and checks: each catalog
pattern fires on a representative sample, non-secret strings are ignored, dedup
by (kind, match), the kinds roll-up, the 256-char match cap, pagination, both
scan ceilings, the catalog invariants and the tool docstring.
"""

from __future__ import annotations

import ast
import types
from pathlib import Path

import headless_re_mcp.backends.apk.client as apk_client
from headless_re_mcp.backends.apk.client import _APK_SECRET_CATALOG, ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

SAMPLES = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "google_api_key": "AIza" + "B" * 35,
    "google_oauth_token": "ya29." + "A" * 30,
    "github_token": "ghp_" + "c" * 36,
    "slack_token": "xoxb-1234567890abcdef",
    "slack_webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
    "stripe_secret_key": "sk_live_" + "d" * 24,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    "twilio_api_key": "SK" + "0" * 32,
    "twilio_account_sid": "AC" + "f" * 32,
    "firebase_db": "https://myapp-12345.firebaseio.com",
}


class _Str:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _Analysis:
    def __init__(self, values: list[str]) -> None:
        self._strings = [_Str(v) for v in values]

    def get_strings(self) -> list[_Str]:
        return self._strings


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    parsed = types.SimpleNamespace(analysis=_Analysis(values))
    client._parsed = lambda _path: parsed  # type: ignore[method-assign,return-value]
    return client


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


def test_every_catalog_kind_fires_on_its_sample() -> None:
    # One sample per kind is present in SAMPLES; the catalog must cover them all.
    catalog_kinds = {kind for kind, _ in _APK_SECRET_CATALOG}
    assert catalog_kinds == set(SAMPLES), catalog_kinds ^ set(SAMPLES)
    payload = _client(list(SAMPLES.values())).secrets(Path("d.apk"))
    found = {(row["kind"], row["match"]) for row in payload["secrets"]}
    for kind, sample in SAMPLES.items():
        assert (kind, sample) in found, kind
    assert payload["kinds"] == sorted(SAMPLES)


def test_non_secret_strings_are_ignored() -> None:
    clean = ["hello world", "AKIAshort", "version=1.2.3", "just a config value"]
    payload = _client(clean).secrets(Path("d"))
    assert payload["secrets"] == []
    assert payload["kinds"] == []
    assert payload["total"] == 0


def test_dedup_by_kind_and_match() -> None:
    key = SAMPLES["aws_access_key_id"]
    payload = _client([key, f"prefix {key} suffix", key]).secrets(Path("d"))
    aws = [r for r in payload["secrets"] if r["kind"] == "aws_access_key_id"]
    assert len(aws) == 1


def test_match_is_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_SECRET_MATCH_LEN", 8)
    payload = _client([SAMPLES["google_api_key"]]).secrets(Path("d"))
    row = next(r for r in payload["secrets"] if r["kind"] == "google_api_key")
    assert row["match"] == "AIzaBBBB"
    assert len(row["match"]) == 8


def test_pagination_reports_total_and_has_more() -> None:
    values = [SAMPLES["firebase_db"].replace("myapp", f"app{i:02d}") for i in range(5)]
    payload = _client(values).secrets(Path("d"), offset=1, limit=2)
    assert payload["total"] == 5
    assert payload["count"] == 2
    assert payload["offset"] == 1
    assert payload["has_more"] is True


def test_secret_collect_ceiling_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_SECRETS_COLLECT", 1)
    two = f"{SAMPLES['github_token']} {SAMPLES['stripe_secret_key']}"
    payload = _client([two]).secrets(Path("d"))
    assert payload["total"] == 1
    assert payload["scan_capped"] is True


def test_string_scan_ceiling_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_SECRET_STRINGS_SCAN", 1)
    values = [SAMPLES["aws_access_key_id"], SAMPLES["github_token"], SAMPLES["jwt"]]
    payload = _client(values).secrets(Path("d"))
    # Only the first string is scanned before the ceiling stops the walk.
    assert payload["total"] == 1
    assert payload["scan_capped"] is True


def test_catalog_is_well_formed() -> None:
    kinds = [kind for kind, _ in _APK_SECRET_CATALOG]
    assert len(kinds) == len(set(kinds)), "duplicate secret kinds"
    assert all(kind and pattern for kind, pattern in _APK_SECRET_CATALOG)


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.secrets")
    assert "Answers with" in doc
    assert "secrets" in doc and "kinds" in doc
    assert "scan_capped" in doc
