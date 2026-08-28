"""apk.secrets detects embedded credentials in the DEX string pool.

The mobile analogue of js.secrets, running the shared credential-detector table
over each DEX string constant. These cover detection, the source pivot field,
dedup/aggregation, the detector summary, the filter, the empty case, the
include_generic gate, value/source clipping, the findings cap and the scan
budget, paging, sorting, and the read-only classification. The fake parsed
object mirrors androguard's analysis.get_strings() surface, exactly like
test_apk_strings_fields.py.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

# Canonical fake credentials (pattern-valid, not real). The Slack values are
# assembled from fragments so the contiguous secret never appears in this file's
# committed bytes -- GitHub push protection flags a whole Slack token/webhook
# even as a test value -- while the detector still sees the full string.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
STRIPE_KEY = "sk_live_" + "0123456789abcdef0123abcd"
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghijklmn"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


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
        self._values = values

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(v) for v in self._values]


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]
    return client


def _run(values: list[str], **kwargs: Any) -> dict[str, Any]:
    return _client(values).secrets(Path("dummy.apk"), **kwargs)


def test_detects_a_secret_and_echoes_its_source() -> None:
    out = _run([f"api key is {AWS_KEY}", "unrelated"])
    assert out["total"] == 1
    row = out["secrets"][0]
    assert row["detector"] == "aws_access_key_id"
    assert row["value"] == AWS_KEY
    assert row["source"] == f"api key is {AWS_KEY}"
    assert row["count"] == 1
    assert out["detectors"] == ["aws_access_key_id"]
    assert out["scan_capped"] is False


def test_deduplicates_and_counts_across_constants() -> None:
    out = _run([f"a {AWS_KEY}", f"b {AWS_KEY}", "noise"])
    assert out["total"] == 1
    assert out["secrets"][0]["count"] == 2


def test_multiple_detector_kinds_are_summarised() -> None:
    out = _run([AWS_KEY, GH_TOKEN, STRIPE_KEY, JWT, SLACK_TOKEN])
    assert out["total"] == 5
    assert out["detectors"] == [
        "aws_access_key_id",
        "github_token",
        "jwt",
        "slack_token",
        "stripe_secret_key",
    ]


def test_no_secrets_is_empty_not_an_error() -> None:
    out = _run(["hello", "Ljava/lang/Object;", "a", "b"])
    assert out["secrets"] == []
    assert out["total"] == 0
    assert out["detectors"] == []


def test_name_filter_matches_detector_or_value_case_insensitively() -> None:
    out = _run([AWS_KEY, GH_TOKEN], name_filter="GITHUB")
    assert [s["value"] for s in out["secrets"]] == [GH_TOKEN]
    out2 = _run([AWS_KEY, GH_TOKEN], name_filter=AWS_KEY[:8])
    assert [s["value"] for s in out2["secrets"]] == [AWS_KEY]


def test_generic_high_entropy_is_gated_by_include_generic() -> None:
    token = "aB3xZ9kQ2wE7rT1yU5iO0pL4mN6vC8bX0zA2sD4fG6h"
    assert _run([token])["total"] == 0
    out = _run([token], include_generic=True)
    assert [s["detector"] for s in out["secrets"]] == ["generic_high_entropy"]


def test_value_and_source_truncation_flags() -> None:
    long_jwt = "eyJ" + "a" * 250 + ".eyJ" + "b" * 250 + "." + "c" * 250
    padded = "leading noise " + AWS_KEY + " " + "x" * 400
    out = _run([long_jwt, padded])
    by_detector = {s["detector"]: s for s in out["secrets"]}
    assert by_detector["jwt"]["value_truncated"] is True
    assert len(by_detector["jwt"]["value"]) == 512
    aws = by_detector["aws_access_key_id"]
    assert aws["value"] == AWS_KEY  # short match, not truncated
    assert aws["source_truncated"] is True
    assert len(aws["source"]) == 256


def test_findings_cap_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_SECRET_FINDINGS", 2)
    keys = [f"AKIA{i:016d}" for i in range(5)]
    out = _run(keys, limit=2000)
    assert out["scan_capped"] is True
    assert out["total"] == 2


def test_scan_budget_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_SECRET_SCAN_STRINGS", 2)
    # The secret sits behind two noise constants, past the scan budget.
    out = _run(["noise0", "noise1", f"late {AWS_KEY}"], limit=2000)
    assert out["scan_capped"] is True
    assert out["total"] == 0


def test_pages_and_reports_has_more() -> None:
    keys = [f"AKIA{i:016d}" for i in range(10)]
    out = _run(keys, limit=3)
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["has_more"] is True


def test_sorted_by_detector_then_count() -> None:
    other_aws = "ASIAZZZZZZZZZZZZZZZZ"
    out = _run([f"a {AWS_KEY}", f"b {AWS_KEY}", other_aws, GH_TOKEN])
    detectors = [s["detector"] for s in out["secrets"]]
    assert detectors == ["aws_access_key_id", "aws_access_key_id", "github_token"]
    assert out["secrets"][0]["value"] == AWS_KEY
    assert out["secrets"][0]["count"] == 2
    assert out["secrets"][1]["value"] == other_aws


def test_page_limit_is_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_STRINGS_PAGE", 2)
    keys = [f"AKIA{i:016d}" for i in range(6)]
    out = _run(keys, limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_apk_secrets_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("apk.secrets").split())
    assert "secrets" in doc
    assert "detectors" in doc
    assert "source" in doc
    assert "include_generic" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "apk.secrets" in _READ_ONLY_NAMES
