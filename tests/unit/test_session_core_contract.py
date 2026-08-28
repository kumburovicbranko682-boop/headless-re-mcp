"""Device-free contract tests for the shared session core.

``core/session.py`` is the module every backend leans on: it classifies a
target, reads a binary's identity without a tool, mints and retires sessions,
and rehydrates unclean SQLite rows after a console restart. The happy paths and
the ELF/Mach-O detectors are pinned elsewhere; these tests close the remaining
error, guard and degradation branches -- a directory handed to ``create``, a
closed session adopted from the store, a hostile row id, an unreadable archive,
a truncated PE/ELF/Mach-O header -- so the core keeps failing the safe way
without needing a device, a browser or a running tool.
"""

from __future__ import annotations

import pathlib
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
    _read_fat_slices,
    classify_target,
    describe_apk,
    detect_elf_architecture,
    detect_macho_architecture,
    detect_pe_architecture,
    hydrate_persisted_sessions,
    session_from_store_row,
)


def _write_minimal_pe(path: Path, machine: int) -> Path:
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
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


# --- SessionRegistry.create -------------------------------------------------


def test_create_binds_a_local_web_asset_with_a_binary(tmp_path: Path) -> None:
    """A downloaded .js/.wasm is a web target that *does* have a local file.

    ``create`` must record it with a resolved binary path and a content hash --
    the web tools can then read the on-disk asset -- rather than treating every
    web target as a locator-only remote URL.
    """
    asset = tmp_path / "bundle.js"
    asset.write_text("console.log(1)", encoding="utf-8")
    session = SessionRegistry().create(asset)
    assert session.target is TargetKind.WEB
    assert session.binary == asset.resolve()
    assert session.locator == str(asset.resolve())
    assert session.sha256


def test_create_refuses_a_directory_as_a_local_target(tmp_path: Path) -> None:
    """A directory resolves and exists, but it is not a regular file.

    ``classify_target`` cannot read magic from a directory, so it falls through
    to PE; ``create`` must then reject it with a clear message instead of
    handing a directory to the PE machine probe.
    """
    with pytest.raises(ValueError, match="not a regular file"):
        SessionRegistry().create(tmp_path)


def test_create_binds_an_apk_with_stdlib_only_metadata(tmp_path: Path) -> None:
    """An APK opens with cheap identity facts and no dependency on androguard."""
    session = SessionRegistry().create(_write_apk(tmp_path / "app.apk"))
    assert session.target is TargetKind.APK
    assert session.binary == (tmp_path / "app.apk").resolve()
    assert session.metadata["apk"]["native_abis"] == ["arm64-v8a"]
    assert session.metadata["apk"]["dex_count"] == 1


def test_create_records_a_remote_web_url_as_a_locator_only(tmp_path: Path) -> None:
    """A remote http(s) target has no local file, so it is locator-only.

    ``create`` must not try to hash or stat a URL: it records the locator and
    leaves the binary and content hash unset for the web tools to fetch live.
    """
    session = SessionRegistry().create("https://example.com/app")
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.com/app"
    assert session.sha256 is None


# --- SessionRegistry lifecycle guards --------------------------------------


def test_adopt_a_closed_session_enters_the_retirement_queue() -> None:
    """A closed row rebound from the store must be retirable like any closure.

    ``adopt`` records a CLOSED session in the closed-order deque so the bounded
    history logic can later evict it -- otherwise a restart would resurrect
    closed sessions that never counted against the retention cap.
    """
    closed = Session(target=TargetKind.PE, locator="/x", state=SessionState.CLOSED)
    registry = SessionRegistry()
    adopted = registry.adopt(closed)
    assert adopted.state is SessionState.CLOSED
    assert closed.id in registry._closed_order


def test_transition_to_the_same_state_is_a_no_op(tmp_path: Path) -> None:
    """Asking for the state a session is already in returns it unchanged.

    The same-state short-circuit runs before the allowed-transition table, so a
    caller re-asserting CREATED is not rejected as an illegal CREATED->CREATED.
    """
    session = SessionRegistry().create(_write_minimal_pe(tmp_path / "a.exe", 0x8664))
    registry = SessionRegistry()
    reborn = registry.adopt(session)
    assert reborn.state is SessionState.CREATED
    same = registry.transition(session.id, SessionState.CREATED)
    assert same.state is SessionState.CREATED


def test_attach_backend_refuses_a_closing_session(tmp_path: Path) -> None:
    """A backend cannot bind to a session that is on its way out.

    Attaching to a CLOSING/CLOSED session would leave a worker bound to a tree
    that is being torn down, so the registry refuses it as an invalid state.
    """
    binary = _write_minimal_pe(tmp_path / "a.exe", 0x8664)
    registry = SessionRegistry()
    session = registry.create(binary)
    registry.transition(session.id, SessionState.CLOSING)
    handle = BackendHandle(kind=BackendKind.IDA, worker_id="ida:x", pid=1)
    with pytest.raises(InvalidStateTransition, match="CLOSING|closing"):
        registry.attach_backend(session.id, handle)


def test_remove_closed_refuses_a_live_session(tmp_path: Path) -> None:
    """Only a closed session may be dropped; a live one is protected."""
    binary = _write_minimal_pe(tmp_path / "a.exe", 0x8664)
    registry = SessionRegistry()
    session = registry.create(binary)
    with pytest.raises(InvalidStateTransition, match="only closed sessions"):
        registry.remove_closed(session.id)


def test_mutating_a_missing_session_raises_session_not_found() -> None:
    """The mutating accessors resolve through ``_require``, which fails cleanly.

    A transition/attach/detach/update against an unknown id must be a typed
    SessionNotFound (mapped to session_not_found) rather than a bare KeyError
    from a dict lookup deep inside the registry.
    """
    registry = SessionRegistry()
    missing = "ff" * 16
    with pytest.raises(SessionNotFound):
        registry.transition(missing, SessionState.OPENING)
    with pytest.raises(SessionNotFound):
        registry.detach_backend(missing, BackendKind.IDA)
    with pytest.raises(SessionNotFound):
        registry.update_metadata(missing, {"k": "v"})


# --- hydrate_persisted_sessions --------------------------------------------


def test_hydrate_returns_zero_when_the_store_raises() -> None:
    """A failed store read must not abort startup; it restores nothing."""

    class _Broken:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[object], int]:
            raise RuntimeError("sqlite is unhappy")

    assert hydrate_persisted_sessions(SessionRegistry(), _Broken()) == 0


def test_hydrate_skips_rows_that_are_not_mappings(tmp_path: Path) -> None:
    """A garbled store handing back non-mapping rows is tolerated, not fatal."""
    binary = _write_minimal_pe(tmp_path / "keep.exe", 0x8664)
    good = {"id": "ab" * 16, "binary": str(binary), "state": "ready"}
    rows: list[object] = [good, "not-a-mapping", None, 42]

    class _Source:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[object], int]:
            return rows, len(rows)

    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Source()) == 1
    assert registry.get("ab" * 16).state is SessionState.CREATED


# --- session_from_store_row -------------------------------------------------


@pytest.mark.parametrize("bad_id", ["", "   ", "../evil", "a/b", "."])
def test_store_row_rejects_a_non_single_component_id(bad_id: str) -> None:
    """A row id must be a single path component; anything else is dropped.

    The id names an on-disk artifact tree, so a traversing or empty id is a
    fail-closed skip rather than a session bound to a path outside its tree.
    """
    assert session_from_store_row({"id": bad_id, "binary": "/x", "state": "ready"}) is None


def test_store_row_rejects_an_empty_locator() -> None:
    """A row with no binary/locator has nothing to bind, so it is skipped."""
    assert session_from_store_row({"id": "ab" * 16, "binary": "", "state": "ready"}) is None


def test_store_row_defaults_an_unparseable_state_to_created() -> None:
    """A corrupt state string rehydrates as CREATED, not a crash.

    Restored workers are dormant CREATED sessions regardless, but the parse must
    survive a value the enum cannot name instead of raising during startup.
    """
    binary_path = "/does/not/matter"
    session = session_from_store_row(
        {"id": "ab" * 16, "binary": binary_path, "state": "frobnicate"}
    )
    assert session is not None
    assert session.state is SessionState.CREATED


def test_store_row_keeps_a_remote_web_url_as_a_locator() -> None:
    """An http(s) web row has no local file; it stays a locator with no binary."""
    session = session_from_store_row(
        {"id": "ab" * 16, "binary": "https://example.com/app.js", "state": "ready"}
    )
    assert session is not None
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.com/app.js"
    assert session.metadata.get("missing_file") is not True


def test_store_row_falls_back_to_the_raw_path_when_resolve_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pathological path (ELOOP, too-long) that cannot resolve is tolerated.

    ``resolve`` can raise OSError; the row must still rehydrate with the raw
    locator and a missing_file marker rather than failing the whole restore.
    """
    raw = str(tmp_path / "prog.bin")

    def _boom(self: Path, strict: bool = False) -> Path:
        raise OSError("ELOOP")

    monkeypatch.setattr(pathlib.Path, "resolve", _boom)
    session = session_from_store_row({"id": "ab" * 16, "binary": raw, "state": "ready"})
    assert session is not None
    assert session.binary is None
    assert session.locator == raw
    assert session.metadata.get("missing_file") is True


# --- stored-value helpers ---------------------------------------------------


def test_architecture_from_stored_declines_empty_and_unknown() -> None:
    assert _architecture_from_stored(None) is None
    assert _architecture_from_stored("") is None
    assert _architecture_from_stored("   ") is None
    assert _architecture_from_stored("sparc") is None
    assert _architecture_from_stored("x64") is Architecture.X64


def test_parse_stored_datetime_accepts_datetime_instances() -> None:
    """A datetime already in hand is returned, gaining UTC only if naive."""
    aware = datetime(2020, 1, 1, tzinfo=UTC)
    assert _parse_stored_datetime(aware) == aware
    naive = datetime(2020, 1, 1)  # noqa: DTZ001 -- deliberately naive input
    coerced = _parse_stored_datetime(naive)
    assert coerced.tzinfo is UTC
    assert coerced.replace(tzinfo=None) == naive


def test_parse_stored_datetime_falls_back_on_a_bad_string() -> None:
    """An unparseable timestamp becomes a fresh UTC now rather than raising."""
    parsed = _parse_stored_datetime("not-a-date")
    assert isinstance(parsed, datetime)
    assert parsed.tzinfo is UTC


# --- archive and header detectors ------------------------------------------


def test_is_android_package_rejects_an_unreadable_archive(tmp_path: Path) -> None:
    """PK magic on a truncated/garbage archive is not an APK; it falls to PE."""
    fake = tmp_path / "broken.bin"
    fake.write_bytes(b"PK\x03\x04not-a-real-zip")
    assert _is_android_package(fake) is False
    assert classify_target(fake) is TargetKind.PE


def test_classify_target_detects_an_apk_by_content(tmp_path: Path) -> None:
    """A zip carrying AndroidManifest.xml is an APK even without a .apk name."""
    unnamed = _write_apk(tmp_path / "payload.bin")
    assert _is_android_package(unnamed) is True
    assert classify_target(unnamed) is TargetKind.APK


def test_classify_target_detects_wasm_by_magic(tmp_path: Path) -> None:
    """A bare WebAssembly module (\\x00asm) classifies as a web target."""
    wasm = tmp_path / "module"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert classify_target(wasm) is TargetKind.WEB


def test_describe_apk_rejects_an_archive_without_a_manifest(tmp_path: Path) -> None:
    """A readable zip with no AndroidManifest.xml is not a describable APK."""
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("readme.txt", "hello")
    with pytest.raises(ValueError, match="has no AndroidManifest.xml"):
        describe_apk(plain)


def test_describe_apk_rejects_an_unreadable_archive(tmp_path: Path) -> None:
    """A non-zip handed to describe_apk is a clear ValueError, not a stack trace."""
    plain = tmp_path / "notzip.apk"
    plain.write_text("this is not an archive", encoding="utf-8")
    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(plain)


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (b"MZ", "not a PE file"),  # too short for the DOS header
        (b"XX" + bytes(62), "not a PE file"),  # 64 bytes but no MZ
    ],
)
def test_detect_pe_architecture_rejects_a_non_pe(
    tmp_path: Path, payload: bytes, match: str
) -> None:
    binary = tmp_path / "bad.exe"
    binary.write_bytes(payload)
    with pytest.raises(ValueError, match=match):
        detect_pe_architecture(binary)


def test_detect_pe_architecture_rejects_a_broken_pe_header(tmp_path: Path) -> None:
    """A valid DOS stub whose PE offset does not point at 'PE\\0\\0' is refused."""
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"NOPE"
    binary = tmp_path / "broken.exe"
    binary.write_bytes(image)
    with pytest.raises(ValueError, match="invalid PE header"):
        detect_pe_architecture(binary)


def test_detect_pe_architecture_rejects_an_unsupported_machine(tmp_path: Path) -> None:
    binary = _write_minimal_pe(tmp_path / "mips.exe", 0x0166)
    with pytest.raises(ValueError, match="unsupported PE machine"):
        detect_pe_architecture(binary)


def test_elf_and_macho_detectors_decline_a_missing_file(tmp_path: Path) -> None:
    """An unreadable path is None (arch unknown), never an exception.

    These never raise by contract: classify_target routes only real magic here,
    but a file that vanished between classify and detect must still open as a
    session with no architecture label.
    """
    missing = tmp_path / "gone"
    assert detect_elf_architecture(missing) is None
    assert detect_macho_architecture(missing) is None


def test_read_fat_slices_declines_a_truncated_arch_table(tmp_path: Path) -> None:
    """A sane fat header whose arch table is cut short is not a fat Mach-O."""
    header = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big") + bytes(10)
    truncated = tmp_path / "truncated"
    truncated.write_bytes(header)
    assert _read_fat_slices(truncated) is None


def test_read_fat_slices_declines_an_unreadable_file(tmp_path: Path) -> None:
    """An OSError while reading the fat header yields None, not a crash."""
    assert _read_fat_slices(tmp_path / "nope") is None
    assert _read_fat_slices(tmp_path) is None  # a directory is unreadable as a file
