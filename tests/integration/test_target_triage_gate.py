"""Live Gate for session target triage: the dispatch that routes a file to a backend.

``classify_target`` is the first decision every analysis makes -- it reads the
extension, then the magic bytes, and decides whether a path is a Windows PE, an
Android package, or a web asset, which in turn decides which backend the
session binds and which tools are allowed. It is pure stdlib (no IDA, no
androguard, no browser), yet the only end-to-end coverage of the routing it
drives was the Android gate's APK case; the web-target line (``.wasm`` /
``.js`` / ``.html`` and the ``\\x00asm`` magic and http(s) URLs) and the
documented "unknown falls back to PE" edge went through ``create_session``
untested.

This gate drives the real service so the classification and the session it
produces are checked together: every ``TargetKind`` branch is created from a
synthetic or committed fixture and the resulting session's target, binary
binding, and (for PE) architecture are asserted; an ELF named without an
extension is pinned to the intended behaviour (classified PE, then refused by
``create_session`` with ``not a PE file`` rather than silently mis-opened); an
http(s) URL becomes a browserless web session with no binary; and the routing
guard is proven both directions -- the PE-only ``static.open`` refuses a web or
apk session, and the apk-only ``apk.open`` refuses a PE session, each with
``target_mismatch`` rather than a crash. Pure Python over committed and
synthetic fixtures, so it never skips.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_REPO = Path(__file__).resolve().parents[2]
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_DOTNET = _REPO / "fixtures" / "dotnet" / "minimal_clr_hint.exe"
_JS = _REPO / "fixtures" / "web" / "obfuscated_sample.js"

_WASM_HEADER = b"\x00asm\x01\x00\x00\x00"
# A real ELF magic with just enough header bytes to be recognisable; the point
# is that the classifier does *not* mistake it for a web asset and does not
# claim it as a valid PE either.
_ELF_HEADER = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _session(service: AnalysisService, target: Path | str) -> dict:
    created = service.create_session(str(target))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert isinstance(session, dict)
    return session


@pytest.mark.integration
def test_classify_target_covers_every_branch(tmp_path: Path) -> None:
    _require(_PE)
    _require(_DOTNET)
    _require(_JS)

    wasm_magic = tmp_path / "module_without_extension"
    wasm_magic.write_bytes(_WASM_HEADER + b"rest")
    wasm_suffix = tmp_path / "module.wasm"
    wasm_suffix.write_bytes(_WASM_HEADER)
    html = tmp_path / "page.html"
    html.write_text("<!doctype html><h1>hi</h1>", encoding="utf-8")
    elf = tmp_path / "libnative_without_extension"
    elf.write_bytes(_ELF_HEADER)

    # Extension precedence, then magic, with PE as the deliberate fallback.
    assert classify_target(_PE) is TargetKind.PE
    assert classify_target(_DOTNET) is TargetKind.PE  # managed PE is still MZ
    assert classify_target(_JS) is TargetKind.WEB
    assert classify_target(wasm_suffix) is TargetKind.WEB
    assert classify_target(html) is TargetKind.WEB
    assert classify_target(wasm_magic) is TargetKind.WEB  # \x00asm magic, no suffix
    assert classify_target(elf) is TargetKind.PE  # unrecognised -> PE fallback
    assert classify_target("https://example.com/app") is TargetKind.WEB
    assert classify_target("http://127.0.0.1:8080/x.bin") is TargetKind.WEB


@pytest.mark.integration
def test_create_session_binds_the_classified_target(tmp_path: Path) -> None:
    _require(_PE)
    _require(_DOTNET)
    _require(_JS)
    service = _service(tmp_path)

    pe = _session(service, _PE)
    assert pe["target"] == "pe"
    assert pe["architecture"] in {"x86", "x64"}
    assert pe["sha256"]

    managed = _session(service, _DOTNET)
    assert managed["target"] == "pe"
    assert managed["architecture"] in {"x86", "x64"}

    # A downloaded web asset is a web session with a real binary bound to it.
    wasm = tmp_path / "module.wasm"
    wasm.write_bytes(_WASM_HEADER)
    wasm_session = _session(service, wasm)
    assert wasm_session["target"] == "web"
    assert wasm_session["binary"]
    assert wasm_session["sha256"]

    js_session = _session(service, _JS)
    assert js_session["target"] == "web"
    assert js_session["binary"]


@pytest.mark.integration
def test_url_is_a_browserless_web_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    # No file on disk and no browser required: create must still succeed and
    # leave the binary unbound, because the locator is a remote URL.
    session = _session(service, "https://example.com/app")
    assert session["target"] == "web"
    assert not session["binary"]
    assert session["locator"] == "https://example.com/app"


@pytest.mark.integration
def test_elf_falls_back_to_pe_and_is_refused_honestly(tmp_path: Path) -> None:
    service = _service(tmp_path)
    elf = tmp_path / "libnative_without_extension"
    elf.write_bytes(_ELF_HEADER)

    # Classified PE (the fallback), then create_session refuses it as a PE
    # rather than opening it as something it is not. The refusal is a client
    # error, not an incident.
    assert classify_target(elf) is TargetKind.PE
    created = service.create_session(str(elf))
    assert not created.ok and created.error is not None
    assert created.error.code == "invalid_request"
    assert "not a PE file" in created.error.message


@pytest.mark.integration
def test_target_guard_refuses_cross_backend_tools(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)

    pe = _session(service, _PE)
    wasm = tmp_path / "module.wasm"
    wasm.write_bytes(_WASM_HEADER)
    web = _session(service, wasm)

    # PE-only static.open must refuse a web session, not attempt to open it.
    static_on_web = service.open_static(web["id"])
    assert not static_on_web.ok and static_on_web.error is not None
    assert static_on_web.error.code == "target_mismatch"

    # apk-only apk.open must refuse a PE session for the same reason.
    apk_on_pe = service.apk_open(pe["id"])
    assert not apk_on_pe.ok and apk_on_pe.error is not None
    assert apk_on_pe.error.code == "target_mismatch"
