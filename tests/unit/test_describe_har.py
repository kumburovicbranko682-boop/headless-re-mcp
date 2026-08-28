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
    # None of these entries declares a request body (no bodySize), so the
    # upload-side verdict is empty rather than absent.
    assert info["request_body_integrity"] == {
        "requests_with_body": 0,
        "bodies_captured": 0,
        "bodies_stripped": 0,
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


def _post(body_size: int, text: str | None = None, encoding: str | None = None) -> dict:
    request: dict = {"method": "POST", "url": "https://h.example.com/login", "bodySize": body_size}
    if text is not None or encoding is not None:
        post_data: dict = {"mimeType": "application/json"}
        if text is not None:
            post_data["text"] = text
        if encoding is not None:
            post_data["encoding"] = encoding
        request["postData"] = post_data
    return {"request": request, "response": {"status": 200, "content": {"size": 0}}}


class TestHarRequestBodyIntegrity:
    """describe_har says whether uploaded (POST/PUT) bodies survived the capture.

    The mirror of the response-body verdict: a shared capture may keep every
    response yet scrub the credentials a login POSTed. Per HAR 1.2,
    request.bodySize is the uploaded body's byte length and postData.text is
    that body; comparing them tells a whole upload from a scrubbed or
    truncated one.
    """

    def test_matching_upload_reads_as_captured(self, tmp_path: Path) -> None:
        import base64

        har = _write_har(
            tmp_path / "up.har",
            [
                _post(5, "hello"),
                _post(5, base64.b64encode(b"world").decode(), "base64"),
            ],
        )
        assert describe_har(har)["har"]["request_body_integrity"] == {
            "requests_with_body": 2,
            "bodies_captured": 2,
            "bodies_stripped": 0,
            "bodies_size_mismatch": 0,
        }

    def test_a_scrubbed_upload_reads_as_stripped(self, tmp_path: Path) -> None:
        # The credentials case: bodySize says a body was sent, but postData
        # (or its text) was removed before the .har was shared.
        no_postdata = _write_har(tmp_path / "s1.har", [_post(64)])
        integrity = describe_har(no_postdata)["har"]["request_body_integrity"]
        assert integrity["requests_with_body"] == 1
        assert integrity["bodies_stripped"] == 1
        assert integrity["bodies_captured"] == 0
        # postData present but its text field emptied reads the same way.
        empty_text = _write_har(tmp_path / "s2.har", [_post(64, "")])
        assert (
            describe_har(empty_text)["har"]["request_body_integrity"]["bodies_stripped"] == 1
        )

    def test_a_truncated_upload_reads_as_a_size_mismatch(self, tmp_path: Path) -> None:
        har = _write_har(tmp_path / "cut.har", [_post(500, "half-the-body")])
        integrity = describe_har(har)["har"]["request_body_integrity"]
        assert integrity["bodies_captured"] == 1
        assert integrity["bodies_size_mismatch"] == 1

    def test_a_get_without_a_body_is_not_counted(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "get.har",
            [{"request": {"method": "GET", "url": "https://h.example.com/", "bodySize": 0},
              "response": {"status": 200, "content": {"size": 0}}}],
        )
        assert describe_har(har)["har"]["request_body_integrity"] == {
            "requests_with_body": 0,
            "bodies_captured": 0,
            "bodies_stripped": 0,
            "bodies_size_mismatch": 0,
        }

    def test_an_unknown_body_size_is_not_counted(self, tmp_path: Path) -> None:
        # bodySize -1 is HAR's "not available" sentinel, not a real body; it
        # must not be mistaken for an upload nor flagged as stripped.
        har = _write_har(tmp_path / "unk.har", [_post(-1)])
        assert describe_har(har)["har"]["request_body_integrity"]["requests_with_body"] == 0


def _typed(url: str, mime: str, body: bytes, base64_encode: bool = True) -> dict:
    import base64

    content: dict = {"size": len(body), "mimeType": mime}
    if base64_encode:
        content["text"] = base64.b64encode(body).decode("ascii")
        content["encoding"] = "base64"
    else:
        content["text"] = body.decode("utf-8")
    return {
        "request": {"method": "GET", "url": url},
        "response": {"status": 200, "content": content},
    }


# A DOS/PE-header-sized blob: MZ magic padded to 0x40 bytes, the minimum a
# real executable can be and the floor the sniffer requires.
_PE_SHAPED = b"MZ" + b"\x90" * 62


class TestHarMimeMasquerade:
    """describe_har flags executable bytes served under a textual mimeType.

    A PE behind text/html is the drive-by / HTML-smuggling shape: the body a
    page fetched as "text" opens with executable or container magic. The
    declared type comes from the capture's mimeType (the Content-Type the
    server sent); the sniff reads the decoded bytes. Honest binary
    declarations (application/octet-stream) are never flagged -- the fact is
    the lie, not the payload.
    """

    def test_a_pe_behind_text_html_is_flagged(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "m.har", [_typed("https://evil.example.com/update", "text/html", _PE_SHAPED)]
        )
        info = describe_har(har)["har"]
        assert info["mime_masquerade_count"] == 1
        assert info["mime_masquerades"] == [
            {
                "url": "https://evil.example.com/update",
                "mime_type": "text/html",
                "sniffed": "pe",
            }
        ]

    def test_each_magic_reads_under_its_own_name(self, tmp_path: Path) -> None:
        bodies = [
            (b"\x7fELF" + b"\x00" * 12, "elf"),
            (b"\x00asm\x01\x00\x00\x00", "wasm"),
            (b"PK\x03\x04" + b"\x00" * 12, "zip"),
            (b"dex\n035\x00" + b"\x00" * 8, "dex"),
            (b"\x1f\x8b\x08\x00" + b"\x00" * 8, "gzip"),
            (b"\xcf\xfa\xed\xfe" + b"\x00" * 12, "macho"),
            (b"\xca\xfe\xba\xbe" + b"\x00" * 12, "java_class_or_fat_macho"),
        ]
        har = _write_har(
            tmp_path / "kinds.har",
            [_typed(f"https://x.example.com/{kind}", "text/plain", body) for body, kind in bodies],
        )
        info = describe_har(har)["har"]
        assert info["mime_masquerade_count"] == len(bodies)
        assert [m["sniffed"] for m in info["mime_masquerades"]] == [k for _, k in bodies]

    def test_an_honest_binary_declaration_is_not_a_lie(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "honest.har",
            [
                _typed(
                    "https://x.example.com/setup.exe", "application/octet-stream", _PE_SHAPED
                ),
                _typed(
                    "https://x.example.com/pkg.zip",
                    "application/zip",
                    b"PK\x03\x04" + b"\x00" * 8,
                ),
            ],
        )
        assert describe_har(har)["har"]["mime_masquerade_count"] == 0

    def test_honest_text_is_not_flagged(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "text.har",
            [
                _typed(
                    "https://x.example.com/app.js",
                    "application/javascript",
                    b"console.log(1);",
                    base64_encode=False,
                )
            ],
        )
        assert describe_har(har)["har"]["mime_masquerade_count"] == 0

    def test_prose_opening_with_mz_is_not_an_executable(self, tmp_path: Path) -> None:
        # Two letters are not a DOS header: bodies shorter than 0x40 bytes
        # never read as pe, so "MZ curve analysis" prose stays unflagged.
        har = _write_har(
            tmp_path / "mz.har",
            [_typed("https://x.example.com/note.txt", "text/plain", b"MZ curve analysis")],
        )
        assert describe_har(har)["har"]["mime_masquerade_count"] == 0

    def test_a_charset_parameter_does_not_hide_the_claim(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "cs.har",
            [
                _typed(
                    "https://x.example.com/w",
                    "text/plain; charset=utf-8",
                    b"\x00asm\x01\x00\x00\x00",
                )
            ],
        )
        info = describe_har(har)["har"]
        assert info["mime_masquerade_count"] == 1
        assert info["mime_masquerades"][0]["sniffed"] == "wasm"

    def test_corrupt_base64_cannot_be_sniffed(self, tmp_path: Path) -> None:
        har = _write_har(
            tmp_path / "corrupt.har",
            [{
                "request": {"method": "GET", "url": "https://x.example.com/y"},
                "response": {"status": 200, "content": {
                    "size": 64, "mimeType": "text/html",
                    "text": "!!!not base64!!!", "encoding": "base64",
                }},
            }],
        )
        assert describe_har(har)["har"]["mime_masquerade_count"] == 0

    def test_the_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        entries = [
            _typed(f"https://x.example.com/{i}", "text/html", _PE_SHAPED) for i in range(40)
        ]
        har = _write_har(tmp_path / "many.har", entries)
        info = describe_har(har)["har"]
        assert info["mime_masquerade_count"] == 40
        assert len(info["mime_masquerades"]) == 32


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
