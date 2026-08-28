"""Cross-validate the URL census against GNU strings across the formats.

A session now reports the endpoint literals baked into the target -- the first
triage question ("who does it talk to?") answered tool-free at creation. The
byte scanner and its two encodings are ours, so GNU strings referees them: it
extracts the same printable runs independently (``-e s`` for raw ASCII,
``-e l`` for the UTF-16LE that wide strings and a .NET #US heap hold), and its
output is pushed through the census's own published grammar -- the RFC 3986
charset, the scheme allowlist, the XML-namespace skip -- so the two URL sets
must match exactly.

Each format's arm proves the part only that format exercises:

* ELF (gcc): narrow literals in .rodata of a real compile -- and the namespace
  decoy is shown present in the raw strings output, so the skip is a filter at
  work, not a missed read;
* PE/.NET (mcs): C# literals land in the #US heap wide -- narrow strings
  provably cannot see them, so agreement means the UTF-16LE arm did the work;
* WASM (wat2wasm): text staged in data segments of a toolchain-built module;
* APK (zip): literals in a *deflated* member -- provably invisible to strings
  over the raw archive -- must surface through the member-wise inflating walk,
  refereed by unzip + strings over the extracted tree;
* Web (JS/HTML): the census the web line carries just like the binaries -- a
  bundle's fetch/WebSocket targets and a page's endpoints beyond the parsed
  src/href hosts; both are text, so strings -e s reads them directly, and the
  HTML arm additionally shows the xmlns namespace present in the raw output
  yet dropped by both sides.

A plain gcc probe is the negative: an empty census is the shared answer. gcc,
binutils (strings) and unzip ship with the CI runner or its apt step; mcs and
wabt come from the workflow's installs. skip != pass: each test skips only
when its own referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_APK_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

# The census's published grammar, applied to the referee's output so both
# sides play by identical rules: scheme allowlist, RFC 3986 charset, bounded
# length, XML namespace identifiers excluded.
_URL_TEXT_RE = re.compile(
    r"(?:https?|wss?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{1,2048}",
    re.IGNORECASE,
)
_NAMESPACE_PREFIXES = (
    "http://schemas.android.com/",
    "http://schemas.microsoft.com/",
    "http://schemas.openxmlformats.org/",
    "http://www.w3.org/",
    "http://ns.adobe.com/",
    "http://purl.org/",
)


def _session_census(binary: Path, namespace: str) -> dict[str, object]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"][namespace]
        return {
            "urls": facts["urls"],
            "url_count": facts["url_count"],
            "cleartext_url_count": facts["cleartext_url_count"],
        }
    finally:
        service.close_all()


def _strings_output(strings: str, target: Path, encoding: str) -> str:
    result = subprocess.run(
        [strings, "-a", "-e", encoding, str(target)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return result.stdout


def _referee_urls(strings: str, targets: list[Path]) -> set[str]:
    """GNU strings' printable runs pushed through the census's own grammar."""
    found: set[str] = set()
    for target in targets:
        for encoding in ("s", "l"):
            for match in _URL_TEXT_RE.finditer(_strings_output(strings, target, encoding)):
                url = match.group(0)
                if not url.lower().startswith(_NAMESPACE_PREFIXES):
                    found.add(url)
    return found


# ---------------------------------------------------------------------------
# ELF: narrow literals in a real gcc build, refereed by strings.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_gcc_probe_reads_the_same_endpoints_as_strings(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF URL gate not run (skip != pass)")
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    source = tmp_path / "probe.c"
    source.write_text(
        'const char *const urls[] = {\n'
        '    "https://api.example.com/v1",\n'
        '    "http://plain.example/beacon",\n'
        '    "https://api.example.com/v1",\n'  # a duplicate literal: one entry
        '    "http://schemas.android.com/apk/res/android",\n'  # namespace decoy
        "};\n"
        "int main(void) { return (int)urls[0][0]; }\n"
    )
    binary = tmp_path / "probe"
    subprocess.run(
        [gcc, str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )

    census = _session_census(binary, "native")
    referee = _referee_urls(strings, [binary])
    assert set(census["urls"]) == referee
    assert {"https://api.example.com/v1", "http://plain.example/beacon"} <= referee
    assert census["url_count"] == len(referee)
    # The decoy is genuinely in the image -- strings sees it raw -- and both
    # sides still exclude it: a namespace names a format, not an endpoint.
    assert "http://schemas.android.com/apk/res/android" in _strings_output(
        strings, binary, "s"
    )
    assert "http://schemas.android.com/apk/res/android" not in census["urls"]
    assert census["cleartext_url_count"] == sum(
        1 for url in referee if not url.lower().startswith(("https://", "wss://"))
    )


@pytest.mark.integration
def test_a_plain_gcc_probe_is_clean_for_both(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF URL gate not run (skip != pass)")
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    source = tmp_path / "plain.c"
    source.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "plain"
    subprocess.run(
        [gcc, str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )

    census = _session_census(binary, "native")
    assert census == {"urls": [], "url_count": 0, "cleartext_url_count": 0}
    assert _referee_urls(strings, [binary]) == set()


# ---------------------------------------------------------------------------
# PE/.NET: C# literals live wide in the #US heap; only the UTF-16LE arm and
# strings -e l can see them.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_an_mcs_wide_heap_reads_like_strings_e_l(tmp_path: Path) -> None:
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono) not installed — .NET URL gate not run (skip != pass)")
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    source = tmp_path / "probe.cs"
    source.write_text(
        "class Probe {\n"
        '    static readonly string Primary = "https://api.example.com/v1";\n'
        '    static readonly string Fallback = "http://plain.example/beacon";\n'
        "    static int Main() { return Primary.Length + Fallback.Length; }\n"
        "}\n"
    )
    assembly = tmp_path / "probe.exe"
    subprocess.run(
        [mcs, "-nologo", f"-out:{assembly}", str(source)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    census = _session_census(assembly, "pe")
    referee = _referee_urls(strings, [assembly])
    assert set(census["urls"]) == referee
    assert {"https://api.example.com/v1", "http://plain.example/beacon"} <= referee
    assert census["url_count"] == len(referee)
    # The literals are wide: narrow strings provably cannot see them, so the
    # agreement above is the UTF-16LE arm's work, not an ASCII coincidence.
    narrow = _strings_output(strings, assembly, "s")
    assert "https://api.example.com/v1" not in narrow
    assert "http://plain.example/beacon" not in narrow


# ---------------------------------------------------------------------------
# WASM: text staged in the data segments of a wat2wasm-built module.
# ---------------------------------------------------------------------------


def _wat_escape(data: bytes) -> str:
    return "".join(f"\\{byte:02x}" for byte in data)


@pytest.mark.integration
def test_a_wat2wasm_data_segment_reads_like_strings(tmp_path: Path) -> None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — WASM URL gate not run (skip != pass)")
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    segments = [
        b"endpoint https://api.example.com/v1 retry 3",
        b"fallback http://plain.example/beacon end",
        b"plain configuration text with no endpoints",
    ]
    lines = ["(module", "  (memory 1)"]
    offset = 0
    for payload in segments:
        lines.append(f'  (data (i32.const {offset}) "{_wat_escape(payload)}")')
        offset += len(payload) + 64
    lines.append(")")
    source = tmp_path / "urls.wat"
    source.write_text("\n".join(lines))
    module = tmp_path / "urls.wasm"
    subprocess.run(
        [wat2wasm, str(source), "-o", str(module)], check=True, capture_output=True, timeout=120
    )

    census = _session_census(module, "wasm")
    referee = _referee_urls(strings, [module])
    assert set(census["urls"]) == referee
    assert referee == {"https://api.example.com/v1", "http://plain.example/beacon"}
    assert census["url_count"] == 2
    assert census["cleartext_url_count"] == 1


# ---------------------------------------------------------------------------
# APK: literals in a deflated member are invisible to strings over the raw
# archive; the member-wise walk must surface them, refereed over the
# unzip-extracted tree.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_an_apk_reads_inflated_members_like_unzip_plus_strings(tmp_path: Path) -> None:
    if not _APK_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_APK_FIXTURE}")
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip not installed — extraction referee missing (skip != pass)")

    apk = tmp_path / "planted.apk"
    apk.write_bytes(_APK_FIXTURE.read_bytes())
    config = (
        b"endpoint https://api.example.com/v1\n"
        b"fallback http://plain.example/beacon\n" + b"# padding line\n" * 40
    )
    with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/config.txt", config)

    # Deflate hid the literals: strings over the raw archive cannot see them,
    # so whatever the census reports came from inflating the member.
    assert "https://api.example.com/v1" not in _strings_output(strings, apk, "s")

    extracted = tmp_path / "tree"
    subprocess.run(
        [unzip, "-o", "-q", str(apk), "-d", str(extracted)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    members = sorted(p for p in extracted.rglob("*") if p.is_file())
    referee = _referee_urls(strings, members)

    census = _session_census(apk, "apk")
    assert set(census["urls"]) == referee
    assert referee == {"https://api.example.com/v1", "http://plain.example/beacon"}
    assert census["url_count"] == 2
    assert census["cleartext_url_count"] == 1


# ---------------------------------------------------------------------------
# Web: a JS bundle and an HTML page are text, so strings -e s sees their
# endpoints directly -- the census must match run for run, and its namespace
# skip must still drop an XHTML xmlns the page really declares.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_js_bundle_reads_the_same_endpoints_as_strings(tmp_path: Path) -> None:
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    bundle = tmp_path / "app.js"
    bundle.write_text(
        'const api=fetch("https://api.example.com/v1");\n'
        'const beacon=new Image();beacon.src="http://plain.example/beacon";\n'
        'const live=new WebSocket("wss://live.example.com/s");\n'
        'const cmd=new WebSocket("ws://c2.example.com/beacon");\n'
        'const dup=fetch("https://api.example.com/v1");\n'  # one entry, not two
    )

    census = _session_census(bundle, "js")
    referee = _referee_urls(strings, [bundle])
    assert set(census["urls"]) == referee
    assert {
        "https://api.example.com/v1",
        "http://plain.example/beacon",
        "wss://live.example.com/s",
        "ws://c2.example.com/beacon",
    } <= referee
    assert census["url_count"] == len(referee)
    # http and ws are cleartext; https and wss are not -- computed the same
    # way on both sides.
    assert census["cleartext_url_count"] == sum(
        1 for url in referee if not url.lower().startswith(("https://", "wss://"))
    )


@pytest.mark.integration
def test_an_html_page_reads_the_same_endpoints_as_strings(tmp_path: Path) -> None:
    strings = shutil.which("strings")
    if strings is None:
        pytest.skip("strings (binutils) not installed — referee missing (skip != pass)")

    page = tmp_path / "index.html"
    page.write_text(
        '<!doctype html><html xmlns="http://www.w3.org/1999/xhtml"><head>\n'
        '<script src="https://cdn.example.com/app.js"></script></head><body>\n'
        '<form action="http://insecure.example.com/login" method="post"></form>\n'
        '<script>fetch("https://api.example.com/x");</script>\n'
        "</body></html>\n"
    )

    census = _session_census(page, "html")
    referee = _referee_urls(strings, [page])
    assert set(census["urls"]) == referee
    # The endpoints the parser would and would not have found alike are in.
    assert {
        "https://cdn.example.com/app.js",
        "http://insecure.example.com/login",
        "https://api.example.com/x",
    } <= referee
    assert census["url_count"] == len(referee)
    # The decoy is genuinely on the page -- strings sees it raw -- and both
    # sides drop it: an xmlns names a format, not an endpoint.
    assert "http://www.w3.org/1999/xhtml" in _strings_output(strings, page, "s")
    assert "http://www.w3.org/1999/xhtml" not in census["urls"]
    assert census["cleartext_url_count"] == sum(
        1 for url in referee if not url.lower().startswith(("https://", "wss://"))
    )
