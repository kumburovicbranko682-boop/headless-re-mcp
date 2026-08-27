"""Lifecycle, classification and hydration guard paths of the session registry.

``core/session.py`` is the substrate the Android and Web dynamic tracks sit on:
``classify_target`` tells an APK from a web asset from a PE, ``describe_apk``
reads package identity without a decompiler, web targets may be a remote URL or
a local ``.js``/``.wasm``, and the registry gates state transitions and restores
unclean rows after a console restart. The existing suite covers the PE happy
path and retirement; this file covers the branch arms around it.
"""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    Session,
    SessionState,
    TargetKind,
)
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionNotFound,
    SessionRegistry,
    _architecture_from_stored,
    _is_android_package,
    _parse_stored_datetime,
    classify_target,
    describe_apk,
    detect_pe_architecture,
    hydrate_persisted_sessions,
    session_from_store_row,
)


def _write_pe(path: Path, machine: int = 0x8664) -> Path:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)
    return path


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


# ---------------------------------------------------------------------------
# SessionRegistry.create


def test_create_binds_a_local_web_asset_as_a_binary(tmp_path: Path) -> None:
    asset = tmp_path / "bundle.js"
    asset.write_text("console.log(1)\n", encoding="utf-8")
    registry = SessionRegistry()

    session = registry.create(asset)

    assert session.target is TargetKind.WEB
    assert session.binary == asset.resolve()
    assert session.sha256 is not None


def test_create_treats_a_url_as_a_web_target_without_a_binary(tmp_path: Path) -> None:
    registry = SessionRegistry()

    session = registry.create("https://example.com/app")

    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.com/app"


def test_create_reads_apk_identity_metadata(tmp_path: Path) -> None:
    apk = _write_apk(tmp_path / "app.apk")
    registry = SessionRegistry()

    session = registry.create(apk)

    assert session.target is TargetKind.APK
    facts = session.metadata["apk"]
    assert facts["dex_count"] == 1
    assert facts["native_abis"] == ["arm64-v8a"]
    assert facts["signed_v1"] is True


def test_create_refuses_a_target_that_is_a_directory(tmp_path: Path) -> None:
    a_dir = tmp_path / "somedir"
    a_dir.mkdir()
    registry = SessionRegistry()

    with pytest.raises(ValueError, match="not a regular file"):
        registry.create(a_dir)


# ---------------------------------------------------------------------------
# adopt / transition / attach / remove_closed guards


def test_adopt_tracks_a_closed_row_for_retirement() -> None:
    registry = SessionRegistry()
    closed = Session(target=TargetKind.WEB, locator="https://x", state=SessionState.CLOSED)

    registry.adopt(closed)

    assert closed.id in registry._closed_order


def test_transition_to_the_same_state_is_a_noop(tmp_path: Path) -> None:
    registry = SessionRegistry()
    session = registry.create(_write_pe(tmp_path / "f.exe"))

    same = registry.transition(session.id, SessionState.CREATED)

    assert same.state is SessionState.CREATED


def test_attach_backend_is_refused_on_a_closing_session(tmp_path: Path) -> None:
    registry = SessionRegistry()
    session = registry.create(_write_pe(tmp_path / "f.exe"))
    registry.transition(session.id, SessionState.CLOSING)
    handle = BackendHandle(
        kind=BackendKind.FRIDA, worker_id="frida:test", pid=7, capabilities=frozenset()
    )

    with pytest.raises(InvalidStateTransition):
        registry.attach_backend(session.id, handle)


def test_remove_closed_refuses_a_live_session(tmp_path: Path) -> None:
    registry = SessionRegistry()
    session = registry.create(_write_pe(tmp_path / "f.exe"))

    with pytest.raises(InvalidStateTransition, match="only closed sessions"):
        registry.remove_closed(session.id)


def test_remove_closed_handles_a_closed_row_not_in_the_queue() -> None:
    registry = SessionRegistry()
    closed = Session(target=TargetKind.WEB, locator="https://x", state=SessionState.CLOSED)
    # Present but never retired through the queue, so the queue lookup misses.
    registry._sessions[closed.id] = closed

    registry.remove_closed(closed.id)

    assert closed.id not in registry._sessions


def test_a_state_change_on_a_missing_session_is_not_found() -> None:
    registry = SessionRegistry()

    with pytest.raises(SessionNotFound):
        registry.transition("deadbeef" * 4, SessionState.OPENING)


# ---------------------------------------------------------------------------
# hydrate_persisted_sessions


def test_hydrate_returns_zero_when_the_source_raises() -> None:
    class _Boom:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[object], int]:
            raise RuntimeError("db locked")

    assert hydrate_persisted_sessions(SessionRegistry(), _Boom()) == 0


def test_hydrate_skips_rows_that_are_not_mappings() -> None:
    class _Source:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[object], int]:
            return [123, "not-a-row", ["also", "wrong"]], 3

    assert hydrate_persisted_sessions(SessionRegistry(), _Source()) == 0


# ---------------------------------------------------------------------------
# session_from_store_row


@pytest.mark.parametrize("bad_id", ["", "../escape", "a/b"])
def test_store_row_rejects_a_bad_id(bad_id: str) -> None:
    assert session_from_store_row({"id": bad_id, "binary": "/tmp/x"}) is None


def test_store_row_defaults_an_unknown_state_to_created(tmp_path: Path) -> None:
    binary = _write_pe(tmp_path / "k.exe")

    session = session_from_store_row(
        {"id": "ab" * 16, "binary": str(binary), "state": "not-a-state"}
    )

    assert session is not None
    assert session.state is SessionState.CREATED


def test_store_row_rejects_an_empty_locator() -> None:
    assert session_from_store_row({"id": "ab" * 16, "binary": ""}) is None


def test_store_row_keeps_a_web_url_without_a_binary() -> None:
    session = session_from_store_row(
        {"id": "ab" * 16, "binary": "https://example.com/app.js", "state": "ready"}
    )

    assert session is not None
    assert session.binary is None
    assert session.locator == "https://example.com/app.js"


# ---------------------------------------------------------------------------
# _architecture_from_stored


def test_architecture_from_stored_ignores_blank_and_unknown() -> None:
    assert _architecture_from_stored("") is None
    assert _architecture_from_stored("sparc") is None
    assert _architecture_from_stored("x64") is Architecture.X64


# ---------------------------------------------------------------------------
# _parse_stored_datetime


def test_parse_stored_datetime_normalises_and_falls_back() -> None:
    aware = datetime(2020, 1, 1, tzinfo=UTC)
    assert _parse_stored_datetime(aware) is aware

    naive = datetime(2020, 1, 1)
    assert _parse_stored_datetime(naive).tzinfo is UTC

    fallback = _parse_stored_datetime("not-a-timestamp")
    assert fallback.tzinfo is UTC


# ---------------------------------------------------------------------------
# target classification


def test_is_android_package_is_false_for_a_broken_zip(tmp_path: Path) -> None:
    fake = tmp_path / "broken"
    fake.write_bytes(b"PK\x03\x04 not really a zip")

    assert _is_android_package(fake) is False


def test_classify_target_reads_magic_bytes(tmp_path: Path) -> None:
    wasm = tmp_path / "mod"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert classify_target(wasm) is TargetKind.WEB

    apk = _write_apk(tmp_path / "noext")
    assert classify_target(apk) is TargetKind.APK


def test_classify_target_falls_back_to_pe(tmp_path: Path) -> None:
    # Unrecognised magic keeps the original "not a PE" error rather than a vaguer one.
    elf = tmp_path / "elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    assert classify_target(elf) is TargetKind.PE

    plain_zip = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain_zip, "w") as archive:
        archive.writestr("readme.txt", b"no manifest here")
    assert classify_target(plain_zip) is TargetKind.PE


def test_describe_apk_requires_a_manifest(tmp_path: Path) -> None:
    zipped = tmp_path / "nomanifest.apk"
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("classes.dex", b"dex")

    with pytest.raises(ValueError, match="has no AndroidManifest"):
        describe_apk(zipped)


def test_describe_apk_rejects_a_non_archive(tmp_path: Path) -> None:
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"this is not a zip")

    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(bad)


# ---------------------------------------------------------------------------
# detect_pe_architecture guards


def test_detect_pe_rejects_a_non_pe(tmp_path: Path) -> None:
    tiny = tmp_path / "tiny"
    tiny.write_bytes(b"MZ")
    with pytest.raises(ValueError, match="not a PE file"):
        detect_pe_architecture(tiny)


def test_detect_pe_rejects_a_bad_pe_header(tmp_path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"XX\0\0"
    path = tmp_path / "bad.exe"
    path.write_bytes(image)

    with pytest.raises(ValueError, match="invalid PE header"):
        detect_pe_architecture(path)


def test_detect_pe_rejects_an_unsupported_machine(tmp_path: Path) -> None:
    path = _write_pe(tmp_path / "arm.exe", machine=0x1234)

    with pytest.raises(ValueError, match="unsupported PE machine"):
        detect_pe_architecture(path)
