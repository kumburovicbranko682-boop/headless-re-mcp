"""Cross-validate the JS payload census against file(1) and GNU grep.

A session over a ``.js`` script now reads the dropper shape the binary formats
already report: the long base64/hex literals it carries, what their opening
bytes decode to (zip/pe/elf/gzip -- the stage-two payload, or None for the
no-magic encrypted case), and how often the script reaches for the
string-to-code constructs obfuscation leans on (eval, the Function
constructor, atob, unescape, fromCharCode, document.write).

Two independent referees, one per half of the census:

- file(1) referees the decoded payloads. The gate glues a *real* container
  (built by zipfile/gzip, never by echoing magic), base64- or hex-encodes it
  into a script, and reads back the blob the session located by its reported
  ``offset`` and ``chars``. Decoding that exact slice and handing it to
  file(1) referees the offset (one character early or late and the decode no
  longer opens with the container magic), the length and the kind's name at
  once -- libmagic's database is maintained entirely apart from this codebase.

- GNU grep -oE referees the dynamic-code marker counts. grep counts the same
  byte-level patterns with its own regex engine, so the reader's hit counts
  must match grep's line for line.

skip != pass: each half skips, naming the missing tool, only when file(1) or
grep is absent.
"""

from __future__ import annotations

import base64
import gzip
import io
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService


def _session_js(path: Path) -> dict[str, Any]:
    """The js metadata block off a session over the script."""
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["js"]
    finally:
        service.close_all()


def _file_verdict(payload: bytes, tmp_path: Path) -> str:
    """libmagic's brief name for the payload bytes."""
    slice_path = tmp_path / "decoded.slice"
    slice_path.write_bytes(payload)
    result = subprocess.run(
        ["file", "--brief", str(slice_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return result.stdout.strip().lower()


def _zip_bytes() -> bytes:
    # Stored (not deflated) so the archive clears the 256-character blob
    # threshold once base64-encoded: a real self-extractor's payload is large.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("stage2.txt", "the next stage " * 32)
    return buffer.getvalue()


def _decode_reported_blob(script: bytes, payload: dict[str, Any]) -> bytes:
    """The blob bytes the session pointed at, decoded by its own encoding.

    Reads ``chars`` characters from ``offset`` in the raw script -- the exact
    span the reader reported -- then decodes them. If the offset or length is
    wrong the slice will not be the literal, and file(1) will not see the
    container magic, so this is a real check of the located span.
    """
    literal = script[payload["offset"] : payload["offset"] + payload["chars"]]
    if payload["encoding"] == "hex":
        return bytes.fromhex(literal.decode("ascii"))
    return base64.b64decode(literal)


# file(1)'s brief output contains these substrings for each kind the census
# names; the mapping is the only shared vocabulary between reader and referee.
_FILE_SUBSTRING = {
    "zip": "zip archive",
    "gzip": "gzip compressed",
    "elf": "elf ",
    "pe": "pe32",
}


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["zip", "gzip", "elf"])
def test_decoded_payload_kind_agrees_with_file(tmp_path: Path, kind: str) -> None:
    if shutil.which("file") is None:
        pytest.skip("file(1) not installed — JS payload census gate not run (skip != pass)")

    if kind == "zip":
        container = _zip_bytes()
    elif kind == "gzip":
        # Incompressible input so the gzip stream stays well past the blob
        # threshold rather than collapsing to a few dozen bytes.
        container = gzip.compress(bytes((i * 53 + 7) & 0xFF for i in range(512)))
    else:  # a real ELF: gcc's own output, not hand-built magic
        gcc = shutil.which("gcc")
        if gcc is None:
            pytest.skip("gcc not installed — ELF leg not built (skip != pass)")
        source = tmp_path / "s.c"
        source.write_text("int main(void){return 0;}\n")
        elf = tmp_path / "s.bin"
        subprocess.run([gcc, "-o", str(elf), str(source)], check=True, timeout=120)
        container = elf.read_bytes()

    encoded = base64.b64encode(container).decode()
    script = f'var stage = "{encoded}";\neval(atob(stage));\n'.encode()
    path = tmp_path / f"{kind}_dropper.js"
    path.write_bytes(script)

    js = _session_js(path)
    matching = [p for p in js["embedded_payloads"] if p["kind"] == kind]
    assert matching, js["embedded_payloads"]
    payload = matching[0]
    assert payload["encoding"] == "base64"

    # The referee: decode the span the session reported and let file(1) name
    # it. A correct offset/length yields the container magic; file must see it.
    decoded = _decode_reported_blob(script, payload)
    verdict = _file_verdict(decoded, tmp_path)
    assert _FILE_SUBSTRING[kind] in verdict, verdict


@pytest.mark.integration
def test_a_hex_encoded_payload_agrees_with_file(tmp_path: Path) -> None:
    if shutil.which("file") is None:
        pytest.skip("file(1) not installed — JS payload census gate not run (skip != pass)")

    container = _zip_bytes()
    script = f'var h = "{container.hex()}";\n'.encode()
    path = tmp_path / "hex_dropper.js"
    path.write_bytes(script)

    js = _session_js(path)
    hex_payloads = [p for p in js["embedded_payloads"] if p["encoding"] == "hex"]
    assert hex_payloads, js["embedded_payloads"]
    payload = hex_payloads[0]
    assert payload["kind"] == "zip"

    decoded = _decode_reported_blob(script, payload)
    assert "zip archive" in _file_verdict(decoded, tmp_path)


@pytest.mark.integration
def test_a_no_magic_blob_is_counted_but_file_shrugs(tmp_path: Path) -> None:
    if shutil.which("file") is None:
        pytest.skip("file(1) not installed — JS payload census gate not run (skip != pass)")

    # A big literal that decodes to noise: the encrypted-stage shape. It joins
    # the blob count but not the payload list, and file(1) must agree there is
    # no recognizable format in the decoded bytes.
    noise = bytes((i * 37 + 11) & 0xFF for i in range(300))
    encoded = base64.b64encode(noise).decode()
    script = f'var k = "{encoded}";\n'.encode()
    path = tmp_path / "encrypted.js"
    path.write_bytes(script)

    js = _session_js(path)
    assert js["encoded_blob_count"] >= 1
    assert js["embedded_payloads"] == []
    verdict = _file_verdict(noise, tmp_path)
    assert not any(sub in verdict for sub in _FILE_SUBSTRING.values()), verdict


# The grep -oE pattern that counts each marker, mirroring the reader's regex.
# grep's ERE has no \b, so [^A-Za-z0-9_] guards (or a start anchor) stand in
# for the word boundary; the counts must still match the reader's.
_MARKER_GREP = {
    "eval": r"(^|[^A-Za-z0-9_])eval[[:space:]]*\(",
    "atob": r"(^|[^A-Za-z0-9_])atob[[:space:]]*\(",
    "unescape": r"(^|[^A-Za-z0-9_])unescape[[:space:]]*\(",
    "from_char_code": r"(^|[^A-Za-z0-9_])String[[:space:]]*\.[[:space:]]*fromCharCode",
    "document_write": r"(^|[^A-Za-z0-9_])document[[:space:]]*\.[[:space:]]*write[[:space:]]*\(",
}


def _grep_count(pattern: str, path: Path) -> int:
    """How many matches GNU grep -oE finds -- its own regex engine, counted."""
    result = subprocess.run(
        ["grep", "-oE", pattern, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # grep exits 1 with no output when there are no matches: that is zero, not
    # an error. Any other nonzero code is a real failure.
    if result.returncode not in (0, 1):
        raise AssertionError(result.stderr)
    return sum(1 for line in result.stdout.splitlines() if line)


@pytest.mark.integration
def test_dynamic_code_marker_counts_agree_with_grep(tmp_path: Path) -> None:
    if shutil.which("grep") is None:
        pytest.skip("grep not installed — marker gate not run (skip != pass)")

    # A script exercising every marker more than once, on one line and across
    # lines, so a count that silently collapses duplicates would be caught.
    script = (
        b'eval("a"); eval ("b");\n'
        b"var f = atob(x) + atob(y) + atob(z);\n"
        b"unescape(p);\n"
        b"var s = String.fromCharCode(72) + String . fromCharCode(105);\n"
        b'document.write("<i>"); document . write("<b>");\n'
    )
    path = tmp_path / "markers.js"
    path.write_bytes(script)

    markers = _session_js(path)["dynamic_code_markers"]
    for name, pattern in _MARKER_GREP.items():
        assert markers[name] == _grep_count(pattern, path), name
    # The referee saw real hits, so the comparison cannot pass vacuously.
    assert _grep_count(_MARKER_GREP["eval"], path) == 2
    assert _grep_count(_MARKER_GREP["atob"], path) == 3
