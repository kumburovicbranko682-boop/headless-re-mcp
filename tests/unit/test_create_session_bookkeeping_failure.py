"""create_session answers with a session even when writing it down fails.

``note_session_created`` runs after the session already exists: the registry
holds it and the caller is about to be handed its id. A store the bookkeeping
cannot open -- a disk cleanup, a scanner quarantine, a volume that came back
unmounted -- must therefore not turn a session that really was created into a
traceback: the caller would retry against a registry that already holds the
"failed" session. And it must not be swallowed outright either, because the
session now exists only in process memory -- it will not survive a restart
(``hydrate_persisted_sessions`` reads the store) and it never entered the
audit trail. The contract is ``_note_failed``'s: the failure lands in
``result.meta`` as ``persisted: False`` plus a ``persist_error``, and the
result stays ok.

close_session has had exactly this pinned
(``test_close_returns_an_envelope_even_if_the_bookkeeping_throws``) since the
contract was written down; the create side runs through the same helper, but
nothing forced its except branch, so a ``raise`` reintroduced at the create
call-site -- or the branch deleted outright -- passed the whole suite.
"""

from __future__ import annotations

from typing import Any


def _minimal_pe(path: Any) -> Any:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)
    return path


def _service(tmp_path: Any) -> Any:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def test_create_returns_a_usable_session_even_if_the_bookkeeping_throws(
    tmp_path: Any,
) -> None:
    service = _service(tmp_path)

    def explode(*_: object, **__: object) -> None:
        raise OSError("unable to open database file")

    service.repository.note_session_created = explode  # type: ignore[method-assign]
    try:
        created = service.create_session(str(_minimal_pe(tmp_path / "target.exe")))

        # The session did get created; failing to write that down must not
        # undo it or dress it up as a failure.
        assert created.ok, created.error
        assert created.data is not None
        session_id = str(created.data["session"]["id"])
        assert service.registry.get(session_id) is not None
        # Nor may it be hidden: this session lives only in process memory now,
        # so the caller has to be told the audit trail did not get it.
        assert created.meta["persisted"] is False
        assert "unable to open database file" in str(created.meta["persist_error"])
    finally:
        service.close_all()


def test_a_healthy_create_carries_no_failure_flag(tmp_path: Any) -> None:
    """The flag means something only if it is absent when nothing failed."""
    service = _service(tmp_path)
    try:
        created = service.create_session(str(_minimal_pe(tmp_path / "target.exe")))

        assert created.ok, created.error
        assert "persisted" not in created.meta
        assert "persist_error" not in created.meta
    finally:
        service.close_all()
