"""The shared endpoint/secret aggregation over a (text, ref) corpus.

finding_aggregate.py is the step above endpoint_scan.py / secret_scan.py that the
native lines (radare2, Ghidra) share: dedup by value, count occurrences, merge a
per-string reference into each finding, summarise hosts, filter by name, sort,
page and cap. These exercise it directly -- the ref merge (added, None-skipped,
never clobbering a real field), dedup+count, include_paths / include_generic,
name_filter, host summary, paging + has_more, and scan_capped passthrough --
independent of any backend.

Secret-looking values are assembled from fragments at runtime so the contiguous
string never lands in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.common.finding_aggregate import (
    aggregate_endpoints,
    aggregate_secrets,
)

_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"


def _pair(text: str, **ref: Any) -> tuple[str, dict[str, Any]]:
    return text, dict(ref)


def test_endpoints_url_host_path_and_ref_merge() -> None:
    out = aggregate_endpoints(
        [
            _pair("https://api.example.com/v1/users", address="0x401000", note=None),
            _pair("/api/health", address="0x401200"),
            _pair("plain text, nothing here", address="0x401300"),
        ]
    )
    by_value = {e["value"]: e for e in out["endpoints"]}
    users = by_value["https://api.example.com/v1/users"]
    assert users["kind"] == "url"
    assert users["host"] == "api.example.com"
    assert users["scheme"] == "https"
    # The ref is merged onto the finding; a None value in the ref is dropped.
    assert users["address"] == "0x401000"
    assert "note" not in users
    assert by_value["/api/health"]["kind"] == "path"
    assert out["hosts"] == ["api.example.com"]


def test_ref_never_clobbers_a_real_finding_field() -> None:
    # A ref carrying keys that collide with the finding's own fields must not win.
    out = aggregate_endpoints(
        [_pair("https://h.example/a", value="X", host="evil.example", address="0x1")]
    )
    row = out["endpoints"][0]
    assert row["value"] == "https://h.example/a"
    assert row["host"] == "h.example"
    assert row["address"] == "0x1"


def test_endpoints_dedup_counts_and_keeps_first_ref() -> None:
    out = aggregate_endpoints(
        [
            _pair("go https://x.example/a", address="0x1000"),
            _pair("again https://x.example/a", address="0x1100"),
        ]
    )
    row = next(e for e in out["endpoints"] if e["value"] == "https://x.example/a")
    assert row["count"] == 2
    assert row["address"] == "0x1000"


def test_endpoints_include_paths_false_and_name_filter() -> None:
    corpus = [
        _pair("https://alpha.example/a"),
        _pair("https://beta.example/b"),
        _pair("/api/things"),
    ]
    only_urls = aggregate_endpoints(corpus, include_paths=False)
    assert {e["kind"] for e in only_urls["endpoints"]} == {"url"}
    filtered = aggregate_endpoints(corpus, name_filter="alpha")
    assert filtered["total"] == 1
    assert filtered["endpoints"][0]["host"] == "alpha.example"


def test_endpoints_paging_and_scan_capped_passthrough() -> None:
    corpus = [_pair(f"https://h{i:02d}.example/x") for i in range(5)]
    page = aggregate_endpoints(corpus, offset=0, limit=2, scan_capped=True)
    assert page["total"] == 5
    assert len(page["endpoints"]) == 2
    assert page["has_more"] is True
    assert page["scan_capped"] is True
    tail = aggregate_endpoints(corpus, offset=4, limit=2)
    assert tail["offset"] == 4
    assert tail["has_more"] is False
    assert len(tail["endpoints"]) == 1


def test_empty_text_is_skipped() -> None:
    out = aggregate_endpoints([_pair(""), _pair("https://h.example/a")])
    assert out["total"] == 1


def test_secrets_detects_and_merges_ref() -> None:
    out = aggregate_secrets(
        [
            _pair(f"key={_AWS}", address="0x2000"),
            _pair(f"stripe {_STRIPE}", address="0x2100"),
            _pair("harmless", address="0x2200"),
        ]
    )
    by_detector = {s["detector"]: s for s in out["secrets"]}
    assert by_detector["aws_access_key_id"]["value"] == _AWS
    assert by_detector["aws_access_key_id"]["address"] == "0x2000"
    assert by_detector["stripe_secret_key"]["value"] == _STRIPE
    assert out["detectors"] == ["aws_access_key_id", "stripe_secret_key"]


def test_secrets_generic_gated_dedup_and_name_filter() -> None:
    token = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"
    corpus = [_pair(token), _pair(f"a {_AWS}"), _pair(f"b {_AWS}")]
    off = aggregate_secrets(corpus)
    assert not any(s["detector"] == "generic_high_entropy" for s in off["secrets"])
    aws_row = next(s for s in off["secrets"] if s["detector"] == "aws_access_key_id")
    assert aws_row["count"] == 2
    on = aggregate_secrets(corpus, include_generic=True)
    assert any(s["detector"] == "generic_high_entropy" for s in on["secrets"])
    filtered = aggregate_secrets(corpus, name_filter="aws")
    assert filtered["total"] == 1
    assert filtered["secrets"][0]["detector"] == "aws_access_key_id"
