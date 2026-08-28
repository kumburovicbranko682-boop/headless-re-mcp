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
    # This capture declares body sizes (1234, 50) but carries no content.text
    # -- exactly the shape of a size-only export -- so both non-empty bodies
    # read as stripped, none captured, none mismatched.
    assert info["body_integrity"] == {
        "responses_with_body": 2,
        "bodies_captured": 2 - 2,
        "bodies_stripped": 2,
        "bodies_size_mismatch": 0,
    }


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


def _resp(size: int, text: str | None = None, encoding: str | None = None) -> dict:
    content: dict = {"size": size, "mimeType": "text/plain"}
    if text is not None:
        content["text"] = text
    if encoding is not None:
        content["encoding"] = encoding
    return {
        "request": {"method": "GET", "url": "https://h.example.com/a"},
        "response": {"status": 200, "content": content},
    }


class TestHarBodyIntegrity:
    """describe_har says whether a capture's response bodies are actually there.

    A shared .har is often trimmed: bodies scrubbed for privacy, or a capture
    cut short. Per HAR 1.2, content.size is the body's byte length and
    content.text is the body (base64 when content.encoding says so). Comparing
    the decoded length with the declared size tells a whole capture from a
    stripped or truncated one -- the HAR analogue of the DEX checksum verdict.
    """

    def test_matching_bodies_read_as_captured(self, tmp_path: Path) -> None:
        import base64

        har = _write_har(
            tmp_path / "whole.har",
            [
                _resp(5, "hello"),
                _resp(5, base64.b64encode(b"world").decode(), "base64"),
            ],
        )
        assert describe_har(har)["har"]["body_integrity"] == {
            "responses_with_body": 2,
            "bodies_captured": 2,
            "bodies_stripped": 0,
            "bodies_size_mismatch": 0,
        }

    def test_a_size_without_text_reads_as_stripped(self, tmp_path: Path) -> None:
        # The privacy-scrubbed share: the entry keeps its declared size but the
        # body was removed -- an absence a byte total alone would hide.
        har = _write_har(tmp_path / "scrubbed.har", [_resp(2048)])
        integrity = describe_har(har)["har"]["body_integrity"]
        assert integrity["responses_with_body"] == 1
        assert integrity["bodies_stripped"] == 1
        assert integrity["bodies_captured"] == 0

    def test_a_short_body_reads_as_a_size_mismatch(self, tmp_path: Path) -> None:
        # A truncated capture: the body text is present but shorter than the
        # size the header promised -- neither whole nor honestly empty.
        har = _write_har(tmp_path / "cut.har", [_resp(100, "only-a-little")])
        integrity = describe_har(har)["har"]["body_integrity"]
        assert integrity["bodies_captured"] == 1
        assert integrity["bodies_size_mismatch"] == 1

    def test_a_multibyte_body_is_measured_in_bytes_not_chars(self, tmp_path: Path) -> None:
        # HAR size is bytes; a 3-char string of 3-byte runes is 9 bytes, so a
        # size of 9 matches and a size of 3 (the char count) is the mismatch.
        body = "\u4e00\u4e8c\u4e09"  # three CJK chars, 3 bytes each in UTF-8
        assert describe_har(_write_har(tmp_path / "u9.har", [_resp(9, body)]))["har"][
            "body_integrity"
        ]["bodies_size_mismatch"] == 0
        assert describe_har(_write_har(tmp_path / "u3.har", [_resp(3, body)]))["har"][
            "body_integrity"
        ]["bodies_size_mismatch"] == 1

    def test_corrupt_base64_cannot_pass_as_a_body(self, tmp_path: Path) -> None:
        # An entry claiming base64 whose text does not decode can represent no
        # honest size -- it is counted as a mismatch, not silently accepted.
        har = _write_har(tmp_path / "corrupt.har", [_resp(4, "not*valid*base64!", "base64")])
        integrity = describe_har(har)["har"]["body_integrity"]
        assert integrity["bodies_captured"] == 1
        assert integrity["bodies_size_mismatch"] == 1

    def test_an_empty_body_is_not_a_missing_body(self, tmp_path: Path) -> None:
        # A 204/redirect with size 0 declares no body, so it is neither counted
        # among responses_with_body nor flagged as stripped.
        har = _write_har(tmp_path / "empty.har", [_resp(0, "")])
        assert describe_har(har)["har"]["body_integrity"] == {
            "responses_with_body": 0,
            "bodies_captured": 0,
            "bodies_stripped": 0,
            "bodies_size_mismatch": 0,
        }


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
