"""Guard, degradation, and rehydration branches of the session registry.

The registry and its store-row rehydration are shared by every track: PE, APK,
and web sessions all live and die through the same lifecycle, and a console
restart re-binds them from SQLite. This file drives the reachable edges the
happy-path suites leave: the local-web-asset branch of create, the transition
and attach guards, closed-session removal, and the row parser that must skip a
bad row rather than resurrect a corrupt session.
"""

from __future__ import annotations

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


def _apk_bytes(tmp_path: Path, name: str = "app.apk") -> Path:
    import zipfile

    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libfoo.so", b"so")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


# --------------------------------------------------------------------------
# create
# --------------------------------------------------------------------------


def test_create_hashes_a_local_web_asset(tmp_path: Path) -> None:
    asset = tmp_path / "bundle.js"
    asset.write_text("console.log(1)", encoding="utf-8")
    registry = SessionRegistry()
    session = registry.create(asset)
    assert session.target is TargetKind.WEB
    assert session.binary == asset.resolve()
    assert session.sha256


def test_create_refuses_a_target_that_is_not_a_regular_file(tmp_path: Path) -> None:
    # A directory resolves but is not a file; the non-web path rejects it.
    registry = SessionRegistry()
    with pytest.raises(ValueError, match="not a regular file"):
        registry.create(tmp_path)


def test_create_reads_apk_metadata(tmp_path: Path) -> None:
    registry = SessionRegistry()
    session = registry.create(_apk_bytes(tmp_path))
    assert session.target is TargetKind.APK
    assert session.metadata["apk"]["native_abis"] == ["arm64-v8a"]
    assert session.metadata["apk"]["dex_count"] == 1


def test_create_from_a_remote_web_url_keeps_the_url_and_has_no_binary() -> None:
    # A remote target has no local asset to hash; the session records only the
    # locator so the web backend can drive the browser to it later.
    registry = SessionRegistry()
    session = registry.create("https://example.com/app")
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.com/app"
    assert session.sha256 is None


# --------------------------------------------------------------------------
# adopt / transition / attach / remove
# --------------------------------------------------------------------------


def test_adopt_tracks_a_closed_session_for_retirement() -> None:
    registry = SessionRegistry()
    closed = Session(target=TargetKind.WEB, locator="http://x/", state=SessionState.CLOSED)
    registry.adopt(closed)
    assert registry.get(closed.id).state is SessionState.CLOSED
    assert closed.id in registry._closed_order


def test_transition_to_the_same_state_is_a_no_op() -> None:
    registry = SessionRegistry()
    session = registry.adopt(Session(target=TargetKind.WEB, locator="http://x/"))
    same = registry.transition(session.id, SessionState.CREATED)
    assert same.state is SessionState.CREATED


def test_transition_of_a_missing_session_is_not_found() -> None:
    registry = SessionRegistry()
    with pytest.raises(SessionNotFound):
        registry.transition("nope", SessionState.OPENING)


def test_attach_to_a_closing_session_is_refused() -> None:
    registry = SessionRegistry()
    session = registry.adopt(Session(target=TargetKind.WEB, locator="http://x/"))
    registry.transition(session.id, SessionState.CLOSING)
    handle = BackendHandle(kind=BackendKind.WEB, worker_id="w1")
    with pytest.raises(InvalidStateTransition):
        registry.attach_backend(session.id, handle)


def test_remove_closed_refuses_a_live_session() -> None:
    registry = SessionRegistry()
    session = registry.adopt(Session(target=TargetKind.WEB, locator="http://x/"))
    with pytest.raises(InvalidStateTransition, match="only closed"):
        registry.remove_closed(session.id)


def test_remove_closed_handles_a_session_absent_from_the_order() -> None:
    # A closed session that never entered the retirement deque still removes
    # cleanly rather than tripping over the missing bookkeeping entry.
    registry = SessionRegistry()
    closed = Session(target=TargetKind.WEB, locator="http://x/", state=SessionState.CLOSED)
    registry._sessions[closed.id] = closed  # injected without touching _closed_order
    registry.remove_closed(closed.id)
    assert registry._sessions == {}


# --------------------------------------------------------------------------
# hydrate_persisted_sessions
# --------------------------------------------------------------------------


class _Source:
    def __init__(self, rows: list[object], *, error: bool = False) -> None:
        self._rows = rows
        self._error = error

    def list_unclean_sessions(
        self, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[object], int]:
        if self._error:
            raise RuntimeError("db unavailable")
        return self._rows, len(self._rows)


def test_hydrate_returns_zero_when_the_source_raises() -> None:
    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Source([], error=True)) == 0


def test_hydrate_skips_a_non_mapping_row_and_restores_a_valid_one(tmp_path: Path) -> None:
    asset = tmp_path / "bundle.js"
    asset.write_text("x", encoding="utf-8")
    good = {"id": "a" * 32, "state": "ready", "binary": str(asset)}
    registry = SessionRegistry()
    restored = hydrate_persisted_sessions(registry, _Source([123, good]))
    assert restored == 1
    assert registry.get("a" * 32).metadata["restored"] is True


# --------------------------------------------------------------------------
# session_from_store_row
# --------------------------------------------------------------------------


def test_row_with_a_bad_id_is_skipped() -> None:
    assert session_from_store_row({"id": ""}) is None
    assert session_from_store_row({"id": "../escape"}) is None


def test_row_with_an_unparseable_state_falls_back_to_created(tmp_path: Path) -> None:
    asset = tmp_path / "b.js"
    asset.write_text("x", encoding="utf-8")
    row = {"id": "b" * 32, "state": "not-a-state", "binary": str(asset)}
    session = session_from_store_row(row)
    assert session is not None
    assert session.state is SessionState.CREATED


def test_row_without_a_locator_is_skipped() -> None:
    assert session_from_store_row({"id": "c" * 32, "binary": ""}) is None


def test_row_for_a_remote_web_target_keeps_the_url() -> None:
    row = {"id": "d" * 32, "binary": "https://example/app.js"}
    session = session_from_store_row(row)
    assert session is not None
    assert session.binary is None
    assert session.locator == "https://example/app.js"


def test_row_survives_a_resolve_that_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom_resolve(self: Path, *a: object, **k: object) -> Path:
        raise OSError("symlink loop")

    monkeypatch.setattr(Path, "resolve", boom_resolve)
    row = {"id": "e" * 32, "binary": str(tmp_path / "gone.bin")}
    session = session_from_store_row(row)
    assert session is not None
    assert session.metadata.get("missing_file") is True


def test_row_flags_a_missing_local_binary() -> None:
    row = {"id": "f" * 32, "binary": "/definitely/not/here.exe"}
    session = session_from_store_row(row)
    assert session is not None
    assert session.binary is None
    assert session.metadata["missing_file"] is True


# --------------------------------------------------------------------------
# small parsers
# --------------------------------------------------------------------------


def test_architecture_from_stored_handles_blank_and_bad() -> None:
    assert _architecture_from_stored("") is None
    assert _architecture_from_stored("sparc") is None
    assert _architecture_from_stored("x64") is Architecture.X64


def test_parse_stored_datetime_covers_every_shape() -> None:
    naive = datetime(2020, 1, 1, 12, 0, 0)
    assert _parse_stored_datetime(naive).tzinfo is not None
    assert _parse_stored_datetime("").tzinfo is UTC
    assert _parse_stored_datetime("not-a-date").tzinfo is UTC
    parsed = _parse_stored_datetime("2021-05-05T00:00:00+00:00")
    assert parsed.year == 2021


# --------------------------------------------------------------------------
# classify_target magic-byte fallbacks (files named without a known suffix)
# --------------------------------------------------------------------------


def test_classify_falls_back_to_magic_bytes_for_a_suffixless_wasm(tmp_path: Path) -> None:
    module = tmp_path / "module"  # no .wasm suffix, so magic decides
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert classify_target(module) is TargetKind.WEB


def test_classify_recognises_an_apk_by_zip_magic_and_manifest(tmp_path: Path) -> None:
    # Named without .apk: PK magic plus an AndroidManifest entry classifies it,
    # which also drives the true return of the package sniffer.
    package = _apk_bytes(tmp_path, name="package")
    assert classify_target(package) is TargetKind.APK


def test_classify_treats_an_unrecognised_blob_as_pe(tmp_path: Path) -> None:
    blob = tmp_path / "data"
    blob.write_bytes(b"\xde\xad\xbe\xef not any known magic")
    assert classify_target(blob) is TargetKind.PE


# --------------------------------------------------------------------------
# apk / pe readers
# --------------------------------------------------------------------------


def test_is_android_package_is_false_for_a_non_zip(tmp_path: Path) -> None:
    junk = tmp_path / "x.bin"
    junk.write_bytes(b"not a zip")
    assert _is_android_package(junk) is False


def test_describe_apk_refuses_a_non_zip(tmp_path: Path) -> None:
    junk = tmp_path / "x.apk"
    junk.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(junk)


def test_describe_apk_refuses_an_archive_with_no_manifest(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "y.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    with pytest.raises(ValueError, match="no AndroidManifest"):
        describe_apk(path)


def _pe(tmp_path: Path, machine: bytes, *, name: str = "a.exe") -> Path:
    # Minimal PE stub: MZ header, e_lfanew at 0x3C pointing past it, PE\0\0 sig.
    path = tmp_path / name
    header = bytearray(0x100)
    header[0:2] = b"MZ"
    pe_off = 0x80
    header[0x3C:0x40] = pe_off.to_bytes(4, "little")
    header[pe_off : pe_off + 4] = b"PE\0\0"
    header[pe_off + 4 : pe_off + 6] = machine
    path.write_bytes(bytes(header))
    return path


def test_detect_pe_architecture_reads_x86_and_x64(tmp_path: Path) -> None:
    assert detect_pe_architecture(_pe(tmp_path, b"\x4c\x01", name="x86.exe")) is Architecture.X86
    assert detect_pe_architecture(_pe(tmp_path, b"\x64\x86", name="x64.exe")) is Architecture.X64


def test_detect_pe_architecture_rejects_non_pe_inputs(tmp_path: Path) -> None:
    not_mz = tmp_path / "n.bin"
    not_mz.write_bytes(b"ZZ" + b"\x00" * 64)
    with pytest.raises(ValueError, match="not a PE file"):
        detect_pe_architecture(not_mz)

    bad_header = tmp_path / "b.exe"
    buf = bytearray(0x100)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x80).to_bytes(4, "little")
    buf[0x80:0x84] = b"XX\0\0"  # not the PE signature
    bad_header.write_bytes(bytes(buf))
    with pytest.raises(ValueError, match="invalid PE header"):
        detect_pe_architecture(bad_header)

    with pytest.raises(ValueError, match="unsupported PE machine"):
        detect_pe_architecture(_pe(tmp_path, b"\x00\x00", name="unknown.exe"))
