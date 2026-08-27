"""apk.secrets pulls hardcoded-credential shapes out of the DEX string pool.

The fake parsed APK stands in for androguard's analysis.get_strings so the
secret regexes, category labelling, de-duplication, sorting, bounding and
pagination are what get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import (
    _MAX_STRINGS_COLLECT,
    ApkClient,
)
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


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeParsed:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = [_FakeString(v) for v in values]

    def get_strings(self) -> list[_FakeString]:
        return self._values


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]
    return client


def test_matches_known_shapes_and_labels_categories() -> None:
    """Each family is detected, extracted bare, and tagged with its category.

    Measured: a Google key embedded in a larger literal comes back as just the
    key, an AWS id and a JWT are found, and a plain sentence yields nothing.
    """
    google = "AIza" + "A" * 35
    aws = "AKIA" + "B" * 16
    jwt = "eyJhbGciOi.eyJzdWIiOi.SIGabc_-"
    client = _client(
        [
            f"key={google};next",
            aws,
            jwt,
            "just an ordinary sentence with no token",
        ]
    )
    payload = client.secrets(Path("dummy.apk"))
    got = {(row["category"], row["value"]) for row in payload["secrets"]}
    assert ("google_api_key", google) in got
    assert ("aws_access_key_id", aws) in got
    assert ("jwt", jwt) in got
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_private_key_header_detected() -> None:
    """A PEM private-key header is flagged even without the body."""
    payload = _client(
        ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"]
    ).secrets(Path("dummy.apk"))
    cats = {row["category"] for row in payload["secrets"]}
    assert cats == {"private_key"}
    assert payload["total"] == 2


def test_duplicates_collapse_and_sorted() -> None:
    """The same token seen twice is one row; rows sort by (category, value)."""
    google = "AIza" + "C" * 35
    payload = _client([google, google, "AKIA" + "D" * 16]).secrets(Path("dummy.apk"))
    assert payload["total"] == 2
    cats = [row["category"] for row in payload["secrets"]]
    assert cats == sorted(cats)


def test_paginates() -> None:
    """A page that fills the limit reports has_more with a stable window."""
    values = ["AIza" + f"{i:035d}" for i in range(25)]
    client = _client(values)
    first = client.secrets(Path("dummy.apk"), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    second = client.secrets(Path("dummy.apk"), offset=10, limit=10)
    assert second["offset"] == 10
    assert second["secrets"][0]["value"] != first["secrets"][0]["value"]


def test_scan_capped_over_collection_ceiling() -> None:
    """More distinct matches than the collection cap sets scan_capped."""
    values = ["AIza" + f"{i:035d}" for i in range(_MAX_STRINGS_COLLECT + 50)]
    payload = _client(values).secrets(Path("dummy.apk"), offset=0, limit=2000)
    assert payload["total"] == _MAX_STRINGS_COLLECT
    assert payload["scan_capped"] is True


def test_empty_when_no_secrets() -> None:
    payload = _client(["nothing", "to", "see"]).secrets(Path("dummy.apk"))
    assert payload["secrets"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_secrets_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.secrets")
    assert "Answers with secrets" in doc
    assert "category" in doc
    assert "scan_capped" in doc
