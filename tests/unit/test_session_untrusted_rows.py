"""Fail-closed contract of the session layer against hostile or degraded input.

Three surfaces meet untrusted data here and each must refuse quietly instead of
propagating garbage into a live registry:

* ``session_from_store_row`` rebuilds sessions from SQLite rows that survived a
  crash -- ids, states, locators and timestamps are whatever the old process
  managed to write before dying;
* ``classify_target`` / ``describe_apk`` / ``detect_pe_architecture`` sniff
  caller-supplied files whose contents are adversarial by definition;
* ``SessionRegistry`` guards its state machine so a wedged caller cannot attach
  workers to dead sessions or delete live ones.
"""

from __future__ import annotations

import hashlib
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.models import (
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
    classify_target,
    describe_apk,
    detect_pe_architecture,
    hydrate_persisted_sessions,
    session_from_store_row,
)

_GOOD_ID = "ab" * 16


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


# ---------------------------------------------------------------------------
# session_from_store_row: every row field arrives from a crashed process
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile_id",
    ["", "   ", "../../etc/shadow", "abc/def", "a\\b" if Path("a\\b").name != "a\\b" else "x/y"],
)
def test_store_row_rejects_ids_that_are_not_plain_names(hostile_id: str) -> None:
    # The id becomes a path component for artifacts and threads, so anything
    # with separators is a traversal attempt, not a session.
    row = {"id": hostile_id, "binary": "C:/x.exe", "state": "ready"}
    assert session_from_store_row(row) is None


def test_store_row_without_a_locator_is_skipped() -> None:
    assert session_from_store_row({"id": _GOOD_ID, "binary": "", "state": "ready"}) is None
    assert session_from_store_row({"id": _GOOD_ID, "state": "ready"}) is None


def test_store_row_with_an_unknown_state_restores_as_created(tmp_path: Path) -> None:
    # A corrupted state column must not crash hydration; the session comes
    # back dormant and the caller re-opens it explicitly.
    binary = tmp_path / "keep.exe"
    _write_minimal_pe(binary)
    session = session_from_store_row({"id": _GOOD_ID, "binary": str(binary), "state": "warp-speed"})
    assert session is not None
    assert session.state is SessionState.CREATED


def test_store_row_for_a_remote_web_target_keeps_the_url(tmp_path: Path) -> None:
    session = session_from_store_row(
        {"id": _GOOD_ID, "binary": "https://example.test/app.js", "state": "ready"}
    )
    assert session is not None
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.test/app.js"
    # A URL never had an on-disk file, so it must not be flagged as missing.
    assert "missing_file" not in session.metadata


def test_store_row_survives_a_resolve_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # resolve() can fail on dead network mounts or over-long stored paths; the
    # row must still hydrate (flagged missing) instead of aborting hydration.
    locator = str(tmp_path / "flaky.exe")
    original = Path.resolve

    def _resolve(self: Path, strict: bool = False) -> Path:
        if str(self) == locator:
            raise OSError("mount is gone")
        return original(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _resolve)
    session = session_from_store_row({"id": _GOOD_ID, "binary": locator, "state": "ready"})
    assert session is not None
    assert session.binary is None
    assert session.locator == locator
    assert session.metadata.get("missing_file") is True


def test_store_row_drops_an_architecture_it_does_not_speak(tmp_path: Path) -> None:
    missing = tmp_path / "gone.exe"
    session = session_from_store_row(
        {"id": _GOOD_ID, "binary": str(missing), "state": "ready", "architecture": "sparc"}
    )
    assert session is not None
    assert session.architecture is None
    # And a row that never recorded one stays None rather than guessing.
    bare = session_from_store_row({"id": _GOOD_ID, "binary": str(missing), "state": "ready"})
    assert bare is not None
    assert bare.architecture is None


def test_store_row_normalises_stored_timestamps(tmp_path: Path) -> None:
    missing = tmp_path / "gone.exe"
    naive = datetime(2024, 5, 1, 12, 0, 0)
    aware = datetime(2024, 5, 2, 12, 0, 0, tzinfo=UTC)
    session = session_from_store_row(
        {
            "id": _GOOD_ID,
            "binary": str(missing),
            "state": "ready",
            "created_at": naive,
            "updated_at": aware,
        }
    )
    assert session is not None
    # A naive datetime from an old schema is pinned to UTC, not local time.
    assert session.created_at == naive.replace(tzinfo=UTC)
    assert session.updated_at == aware


def test_store_row_falls_back_to_now_for_garbage_timestamps(tmp_path: Path) -> None:
    missing = tmp_path / "gone.exe"
    session = session_from_store_row(
        {"id": _GOOD_ID, "binary": str(missing), "state": "ready", "created_at": "not-a-date"}
    )
    assert session is not None
    assert session.created_at.tzinfo is not None


# ---------------------------------------------------------------------------
# hydrate_persisted_sessions: a broken store must not break startup
# ---------------------------------------------------------------------------


def test_hydrate_returns_zero_when_the_store_raises() -> None:
    class _Exploding:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[Any], int]:
            raise RuntimeError("database is locked")

    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Exploding()) == 0
    assert registry.list() == []


def test_hydrate_skips_rows_that_are_not_mappings() -> None:
    class _Junk:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[Any], int]:
            return (["not a row", 42, None], 3)

    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Junk()) == 0
    assert registry.list() == []


# ---------------------------------------------------------------------------
# SessionRegistry: state machine guard rails
# ---------------------------------------------------------------------------


def test_transition_to_the_current_state_is_a_quiet_no_op(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    _write_minimal_pe(binary)
    registry = SessionRegistry()
    session = registry.create(binary)
    before = registry.get(session.id).updated_at
    same = registry.transition(session.id, SessionState.CREATED)
    assert same.state is SessionState.CREATED
    # A no-op must not pretend the session changed.
    assert registry.get(session.id).updated_at == before


def test_registry_operations_on_an_unknown_id_raise_session_not_found() -> None:
    registry = SessionRegistry()
    with pytest.raises(SessionNotFound):
        registry.transition("feedface" * 4, SessionState.OPENING)
    with pytest.raises(SessionNotFound):
        registry.update_metadata("feedface" * 4, {"k": "v"})


def test_backends_cannot_attach_to_a_session_on_its_way_out(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    _write_minimal_pe(binary)
    registry = SessionRegistry()
    session = registry.create(binary)
    registry.transition(session.id, SessionState.CLOSING)
    handle = BackendHandle(kind=BackendKind.IDA, worker_id="w1")
    with pytest.raises(InvalidStateTransition):
        registry.attach_backend(session.id, handle)


def test_remove_closed_refuses_a_live_session(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    _write_minimal_pe(binary)
    registry = SessionRegistry()
    session = registry.create(binary)
    with pytest.raises(InvalidStateTransition):
        registry.remove_closed(session.id)
    # The refusal must not have removed anything.
    assert registry.get(session.id).state is SessionState.CREATED


def test_adopting_a_closed_session_enters_the_retirement_queue() -> None:
    # A closed row adopted after restart must be evictable exactly like a
    # session that closed in-process, or restarts would leak registry entries.
    registry = SessionRegistry()
    dormant = Session(target=TargetKind.PE, locator="x", state=SessionState.CLOSED)
    adopted = registry.adopt(dormant)
    assert adopted.state is SessionState.CLOSED
    registry.remove_closed(adopted.id)
    with pytest.raises(SessionNotFound):
        registry.get(adopted.id)


# ---------------------------------------------------------------------------
# create(): target classification against caller-supplied files
# ---------------------------------------------------------------------------


def test_create_hashes_a_local_web_asset(tmp_path: Path) -> None:
    payload = b"console.log('hi')\n"
    asset = tmp_path / "loader.js"
    asset.write_bytes(payload)
    registry = SessionRegistry()
    session = registry.create(asset)
    assert session.target is TargetKind.WEB
    assert session.binary == asset.resolve()
    assert session.sha256 == hashlib.sha256(payload).hexdigest()


def test_create_rejects_a_directory(tmp_path: Path) -> None:
    registry = SessionRegistry()
    with pytest.raises(ValueError, match="not a regular file"):
        registry.create(tmp_path)


def test_create_keeps_a_remote_url_without_touching_the_disk() -> None:
    registry = SessionRegistry()
    session = registry.create("https://example.test/app")
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.sha256 is None
    assert session.locator == "https://example.test/app"


def test_classify_recognises_magic_bytes_when_the_extension_lies(tmp_path: Path) -> None:
    # Droppers rename payloads; the sniffer must go by content for files
    # whose extension says nothing.
    wasm = tmp_path / "blob"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert classify_target(wasm) is TargetKind.WEB
    package = tmp_path / "payload.bin"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
    assert classify_target(package) is TargetKind.APK


def test_create_reads_apk_identity_facts(tmp_path: Path) -> None:
    package = tmp_path / "sample.apk"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("classes2.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libnative.so", b"elf")
        archive.writestr("lib/incomplete", b"not under an abi dir")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    registry = SessionRegistry()
    session = registry.create(package)
    assert session.target is TargetKind.APK
    facts = session.metadata["apk"]
    assert facts["native_abis"] == ["arm64-v8a"]
    assert facts["dex_count"] == 2
    assert facts["signed_v1"] is True


def test_describe_apk_refuses_a_file_that_is_not_a_zip(tmp_path: Path) -> None:
    fake = tmp_path / "junk.apk"
    fake.write_bytes(b"definitely not a zip archive")
    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(fake)


def test_describe_apk_refuses_a_zip_without_a_manifest(tmp_path: Path) -> None:
    hollow = tmp_path / "hollow.apk"
    with zipfile.ZipFile(hollow, "w") as archive:
        archive.writestr("readme.txt", b"nothing android here")
    with pytest.raises(ValueError, match="archive has no AndroidManifest.xml"):
        describe_apk(hollow)


def test_classify_falls_back_to_pe_for_a_corrupt_zip(tmp_path: Path) -> None:
    # PK magic with a broken central directory: the android probe fails
    # closed and the caller gets the original "not a PE" diagnostics.
    mystery = tmp_path / "mystery.bin"
    mystery.write_bytes(b"PK\x03\x04" + b"\xff" * 32)
    assert classify_target(mystery) is TargetKind.PE


# ---------------------------------------------------------------------------
# detect_pe_architecture: crafted headers
# ---------------------------------------------------------------------------


def test_detect_rejects_a_file_without_an_mz_stub(tmp_path: Path) -> None:
    bogus = tmp_path / "short.exe"
    bogus.write_bytes(b"ZM" + b"\0" * 62)
    with pytest.raises(ValueError, match="not a PE file"):
        detect_pe_architecture(bogus)
    truncated = tmp_path / "tiny.exe"
    truncated.write_bytes(b"MZ")
    with pytest.raises(ValueError, match="not a PE file"):
        detect_pe_architecture(truncated)


def test_detect_rejects_an_mz_stub_pointing_at_garbage(tmp_path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"XX\0\0"
    crafted = tmp_path / "badsig.exe"
    crafted.write_bytes(image)
    with pytest.raises(ValueError, match="invalid PE header"):
        detect_pe_architecture(crafted)


def test_detect_rejects_a_machine_it_cannot_debug(tmp_path: Path) -> None:
    crafted = tmp_path / "arm.exe"
    _write_minimal_pe(crafted, machine=0x01C4)
    with pytest.raises(ValueError, match="unsupported PE machine 0x01c4"):
        detect_pe_architecture(crafted)
