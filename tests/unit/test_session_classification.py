"""Non-PE target detection and the session-lifecycle branches it flows through.

classify_target and describe_apk are the entry point for every Android/Web
session: they decide APK vs WEB vs PE from extension then magic bytes, and read
cheap identity facts from a package without a decompiler. This pins that matrix
(including the malformed-zip and no-manifest guards) plus the SessionRegistry
branches a web-local-asset / APK session exercises that test_session.py does not:
the web local-file binary path, the not-a-regular-file refusal, same-state
transition, attach-to-closed refusal, remove_closed guards, and rehydration of a
restored web/apk row.
"""

from __future__ import annotations

import zipfile
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
    hydrate_persisted_sessions,
    session_from_store_row,
)


def _minimal_apk(
    path: Path, *, manifest: bool = True, extra: dict[str, bytes] | None = None
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        if manifest:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return path


# ---------------------------------------------------------------------------
# classify_target: extension first, then magic bytes
# ---------------------------------------------------------------------------
def test_classify_target_reads_http_urls_as_web() -> None:
    assert classify_target("https://example.com/app") is TargetKind.WEB
    assert classify_target("http://127.0.0.1:8080/x") is TargetKind.WEB


@pytest.mark.parametrize("suffix", [".apk", ".aab", ".apks", ".xapk"])
def test_classify_target_reads_android_suffixes_as_apk(tmp_path: Path, suffix: str) -> None:
    target = tmp_path / f"app{suffix}"
    target.write_bytes(b"not even a zip")  # suffix wins before magic
    assert classify_target(target) is TargetKind.APK


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".har"])
def test_classify_target_reads_web_suffixes_as_web(tmp_path: Path, suffix: str) -> None:
    target = tmp_path / f"asset{suffix}"
    target.write_bytes(b"anything")
    assert classify_target(target) is TargetKind.WEB


def test_classify_target_reads_magic_bytes_for_extensionless_files(tmp_path: Path) -> None:
    pe = tmp_path / "blob_pe"
    pe.write_bytes(b"MZ\x90\x00" + b"\x00" * 8)
    assert classify_target(pe) is TargetKind.PE

    wasm = tmp_path / "blob_wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert classify_target(wasm) is TargetKind.WEB


def test_classify_target_reads_a_zip_with_a_manifest_as_apk(tmp_path: Path) -> None:
    apk = _minimal_apk(tmp_path / "packed")  # no .apk suffix -> falls to magic bytes
    assert classify_target(apk) is TargetKind.APK


def test_classify_target_treats_a_zip_without_a_manifest_as_pe(tmp_path: Path) -> None:
    zip_no_manifest = tmp_path / "archive"
    with zipfile.ZipFile(zip_no_manifest, "w") as archive:
        archive.writestr("readme.txt", b"hi")
    assert classify_target(zip_no_manifest) is TargetKind.PE


def test_classify_target_treats_a_corrupt_zip_as_pe(tmp_path: Path) -> None:
    # PK magic so the APK probe runs, but a truncated central directory: the
    # _is_android_package guard must swallow BadZipFile and fall back to PE.
    corrupt = tmp_path / "corrupt"
    corrupt.write_bytes(b"PK\x03\x04" + b"\x00" * 8)
    assert classify_target(corrupt) is TargetKind.PE


def test_classify_target_treats_an_unreadable_path_as_pe(tmp_path: Path) -> None:
    # A directory has no suffix and cannot be opened as a file -> OSError -> PE.
    assert classify_target(tmp_path) is TargetKind.PE


# ---------------------------------------------------------------------------
# describe_apk: cheap identity facts, stdlib-only
# ---------------------------------------------------------------------------
def test_describe_apk_reports_abis_dex_count_and_v1_signature(tmp_path: Path) -> None:
    apk = _minimal_apk(
        tmp_path / "app.apk",
        extra={
            "lib/arm64-v8a/libfoo.so": b"\x7fELF",
            "lib/armeabi-v7a/libfoo.so": b"\x7fELF",
            "lib/": b"",  # a bare lib/ entry contributes no abi
            "classes.dex": b"dex\n",
            "classes2.dex": b"dex\n",
            "META-INF/CERT.RSA": b"\x30\x82",
        },
    )
    facts = describe_apk(apk)["apk"]
    assert facts["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert facts["dex_count"] == 2
    assert facts["signed_v1"] is True
    assert facts["entry_count"] >= 6


def test_describe_apk_reports_an_unsigned_package(tmp_path: Path) -> None:
    apk = _minimal_apk(tmp_path / "app.apk", extra={"classes.dex": b"dex\n"})
    facts = describe_apk(apk)["apk"]
    assert facts["native_abis"] == []
    assert facts["dex_count"] == 1
    assert facts["signed_v1"] is False


def test_describe_apk_rejects_a_corrupt_archive(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.apk"
    corrupt.write_bytes(b"PK\x03\x04 not a real zip")
    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(corrupt)


def test_describe_apk_rejects_an_archive_without_a_manifest(tmp_path: Path) -> None:
    no_manifest = tmp_path / "nomanifest.apk"
    _minimal_apk(no_manifest, manifest=False, extra={"classes.dex": b"dex\n"})
    with pytest.raises(ValueError, match="no AndroidManifest.xml"):
        describe_apk(no_manifest)


# ---------------------------------------------------------------------------
# SessionRegistry.create: the non-PE creation branches
# ---------------------------------------------------------------------------
def test_create_a_web_local_asset_records_a_binary_and_hash(tmp_path: Path) -> None:
    asset = tmp_path / "bundle.js"
    asset.write_text("var a=1;", encoding="utf-8")
    registry = SessionRegistry()
    session = registry.create(asset)
    assert session.target is TargetKind.WEB
    assert session.binary == asset.resolve()
    assert session.sha256 is not None and len(session.sha256) == 64


def test_create_a_remote_web_url_has_no_binary() -> None:
    registry = SessionRegistry()
    session = registry.create("https://example.com/app", target=TargetKind.WEB)
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.locator == "https://example.com/app"


def test_create_an_apk_carries_describe_facts(tmp_path: Path) -> None:
    apk = _minimal_apk(tmp_path / "app.apk", extra={"classes.dex": b"dex\n"})
    registry = SessionRegistry()
    session = registry.create(apk)
    assert session.target is TargetKind.APK
    assert session.metadata["apk"]["dex_count"] == 1


def test_create_refuses_a_target_that_is_not_a_regular_file(tmp_path: Path) -> None:
    # A directory classifies as PE (unreadable magic) but is not a regular file.
    registry = SessionRegistry()
    with pytest.raises(ValueError, match="not a regular file"):
        registry.create(tmp_path)


# ---------------------------------------------------------------------------
# SessionRegistry lifecycle branches
# ---------------------------------------------------------------------------
def test_transition_to_the_same_state_is_a_noop(tmp_path: Path) -> None:
    asset = tmp_path / "a.js"
    asset.write_text("1", encoding="utf-8")
    registry = SessionRegistry()
    session = registry.create(asset)
    same = registry.transition(session.id, SessionState.CREATED)
    assert same.state is SessionState.CREATED


def test_attach_backend_to_a_closed_session_is_refused(tmp_path: Path) -> None:
    asset = tmp_path / "a.js"
    asset.write_text("1", encoding="utf-8")
    registry = SessionRegistry()
    session = registry.create(asset)
    registry.transition(session.id, SessionState.CLOSING)
    registry.transition(session.id, SessionState.CLOSED)
    handle = BackendHandle(kind=BackendKind.WEB, worker_id="web:test", pid=1)
    with pytest.raises(InvalidStateTransition, match="cannot attach"):
        registry.attach_backend(session.id, handle)


def test_remove_closed_refuses_an_open_session(tmp_path: Path) -> None:
    asset = tmp_path / "a.js"
    asset.write_text("1", encoding="utf-8")
    registry = SessionRegistry()
    session = registry.create(asset)
    with pytest.raises(InvalidStateTransition, match="only closed sessions"):
        registry.remove_closed(session.id)


def test_metadata_update_on_a_missing_session_raises_not_found() -> None:
    registry = SessionRegistry()
    with pytest.raises(SessionNotFound):
        registry.update_metadata("does-not-exist", {"k": "v"})


def test_adopt_a_closed_row_enters_the_retirement_queue() -> None:
    registry = SessionRegistry()
    closed = Session(target=TargetKind.WEB, locator="https://x", state=SessionState.CLOSED)
    adopted = registry.adopt(closed)
    assert adopted.state is SessionState.CLOSED
    # A closed adopted session is still readable and can be removed as closed.
    registry.remove_closed(adopted.id)
    with pytest.raises(SessionNotFound):
        registry.get(adopted.id)


# ---------------------------------------------------------------------------
# rehydration of restored web/apk rows
# ---------------------------------------------------------------------------
def test_session_from_store_row_rehydrates_a_remote_web_row() -> None:
    row = {"id": "abc123", "state": "bogus-state", "binary": "https://example.com/app"}
    session = session_from_store_row(row)
    assert session is not None
    assert session.target is TargetKind.WEB
    assert session.binary is None
    assert session.state is SessionState.CREATED  # unknown stored state falls back
    assert session.metadata["restored"] is True


def test_session_from_store_row_rejects_a_traversal_id() -> None:
    assert session_from_store_row({"id": "../evil", "state": "created", "binary": "x"}) is None


def test_session_from_store_row_rejects_a_row_without_a_locator() -> None:
    assert session_from_store_row({"id": "abc", "state": "created", "binary": ""}) is None


class _RaisingSource:
    def list_unclean_sessions(self, *, offset: int = 0, limit: int = 100) -> tuple[list[Any], int]:
        raise RuntimeError("sqlite is down")


class _MixedSource:
    def list_unclean_sessions(self, *, offset: int = 0, limit: int = 100) -> tuple[list[Any], int]:
        # A non-Mapping row is skipped; the mapping row rehydrates.
        rows: list[Any] = ["not a mapping", {"id": "web1", "state": "created", "binary": "https://x"}]
        return rows, len(rows)


def test_hydrate_tolerates_a_failing_source() -> None:
    assert hydrate_persisted_sessions(SessionRegistry(), _RaisingSource()) == 0


def test_hydrate_skips_non_mapping_rows_and_restores_the_rest() -> None:
    registry = SessionRegistry()
    restored = hydrate_persisted_sessions(registry, _MixedSource())
    assert restored == 1
    assert registry.get("web1").target is TargetKind.WEB
