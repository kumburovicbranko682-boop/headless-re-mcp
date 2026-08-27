"""describe_har: tool-free HTTP Archive (HAR) facts (no mitmproxy).

A ``.har`` is the JSON transcript a proxy or browser writes. describe_har reads
its shape -- request count, methods, hosts, status mix, WebSocket presence, and
which tool recorded it -- so a captured session gets identity facts at session
creation without a proxy running. These cover a real capture, WebSocket
detection, a malformed entry mixed into a good file, and the fail-closed paths.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import SessionRegistry, describe_har


def _write_har(path: Path, entries: list[dict], **log: object) -> Path:
    doc = {"log": {"version": "1.2", "entries": entries, **log}}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_reads_a_real_capture(tmp_path: Path) -> None:
    har = _write_har(
        tmp_path / "cap.har",
        [
            {
                "request": {"method": "get", "url": "https://api.example.com/v1/users?q=1"},
                "response": {"status": 200, "content": {"size": 1234}},
            },
            {
                "request": {"method": "POST", "url": "https://api.example.com/v1/login"},
                "response": {"status": 302, "content": {"size": 0}},
            },
            {
                "request": {"method": "GET", "url": "https://cdn.example.net/app.js"},
                "response": {"status": 404, "content": {"size": 50}},
            },
        ],
        creator={"name": "mitmproxy", "version": "10"},
        pages=[{"id": "p1"}],
    )
    info = describe_har(har)["har"]
    assert info["entry_count"] == 3
    assert info["page_count"] == 1
    assert info["creator"] == "mitmproxy"
    # A lowercase method is normalised so GET and get do not split the count.
    assert info["methods"] == {"GET": 2, "POST": 1}
    assert info["host_count"] == 2
    assert info["hosts"] == ["api.example.com", "cdn.example.net"]
    assert info["status_classes"] == {"2xx": 1, "3xx": 1, "4xx": 1}
    assert info["total_response_bytes"] == 1284
    assert info["has_websocket"] is False
    assert info["truncated"] is False


def test_detects_websocket_traffic(tmp_path: Path) -> None:
    har = _write_har(
        tmp_path / "ws.har",
        [
            {
                "request": {"method": "GET", "url": "wss://live.example.com/socket"},
                "response": {"status": 101},
                "_webSocketMessages": [{"type": "send", "data": "hello"}],
            }
        ],
    )
    info = describe_har(har)["har"]
    assert info["has_websocket"] is True
    assert info["host_count"] == 1


def test_a_malformed_entry_is_skipped_not_fatal(tmp_path: Path) -> None:
    # A good request beside a non-dict entry and one missing its request: the
    # count reflects every entry, but only the readable fields contribute.
    har = _write_har(
        tmp_path / "mixed.har",
        [
            {"request": {"method": "GET", "url": "https://ok.example.com/"},
             "response": {"status": 200, "content": {"size": 10}}},
            "not-an-entry",
            {"response": {"status": 500}},
        ],
    )
    info = describe_har(har)["har"]
    assert info["entry_count"] == 3
    assert info["methods"] == {"GET": 1}
    assert info["status_classes"] == {"2xx": 1, "5xx": 1}
    assert info["host_count"] == 1


def test_malformed_json_yields_empty(tmp_path: Path) -> None:
    path = tmp_path / "broken.har"
    path.write_text("{ not valid json", encoding="utf-8")
    assert describe_har(path) == {}


def test_json_without_har_shape_yields_empty(tmp_path: Path) -> None:
    # Valid JSON, but no log.entries -- not a HAR, so no facts (never raises).
    path = tmp_path / "other.har"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    assert describe_har(path) == {}


def test_ignores_a_non_har_suffix(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
    assert describe_har(path) == {}


def test_session_over_a_local_har_carries_the_facts(tmp_path: Path) -> None:
    har = _write_har(
        tmp_path / "session.har",
        [{"request": {"method": "GET", "url": "https://x.example.com/"},
          "response": {"status": 200, "content": {"size": 5}}}],
        creator={"name": "chrome"},
    )
    session = SessionRegistry().create(str(har))
    assert session.target is TargetKind.WEB
    assert "wasm" not in session.metadata
    assert session.metadata["har"]["entry_count"] == 1
    assert session.metadata["har"]["creator"] == "chrome"
