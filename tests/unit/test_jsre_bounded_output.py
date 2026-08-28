"""_bounded_output must degrade a failed spill, never turn a big module into an error.

The WASM tools (wasm.wat / wasm.info) have no session artifact companion, so when
their output runs past the inline cap the only way to recover the tail is the
spill file _bounded_output writes when the caller offers a path. That write is
deliberately best-effort: a full disk or an unwritable artifact root must leave
the truncated text in place -- an agent still gets the head of the module and the
truncated flag, not a backend error standing in for a missing convenience file.

The service-level test pins the happy path (a real spill file appears under the
jsre root). This pins the other half: the spill write failing.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.jsre import client as jsre_client


def test_bounded_output_keeps_truncated_text_when_the_spill_write_fails(
    tmp_path: Path,
) -> None:
    """A spill path whose parent cannot be made degrades to the truncated head.

    The parent of the spill path is a regular file here, so mkdir(parents=True)
    raises an OSError exactly as a full or read-only artifact root would. The
    contract: truncated stays True, the inline head and byte count are intact,
    output_path is absent (there is no file to point at), and nothing is raised.
    """
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file, not a directory")
    # parent (tmp/blocker) is a file, so creating tmp/blocker/sub must fail.
    spill_path = blocker / "sub" / "module.wat"

    text = "A" * (jsre_client._MAX_INLINE + 500)
    result = jsre_client._bounded_output(
        text, "wat", include_bytes=True, spill_path=spill_path
    )

    assert result["truncated"] is True
    assert "output_path" not in result
    assert result["wat"] == text[: jsre_client._MAX_INLINE]
    assert result["bytes"] == len(text.encode("utf-8"))
    assert not spill_path.exists()


def test_bounded_output_names_the_spill_when_the_write_succeeds(tmp_path: Path) -> None:
    """The sibling success path: a writable spill path yields output_path with all bytes.

    Kept beside the failure case so the pair reads as one contract -- the failure
    test proves the degradation is not just that the write happened to no-op.
    """
    spill_path = tmp_path / "out" / "module.wat"
    text = "B" * (jsre_client._MAX_INLINE + 500)

    result = jsre_client._bounded_output(
        text, "wat", include_bytes=True, spill_path=spill_path
    )

    assert result["truncated"] is True
    assert result["output_path"] == str(spill_path)
    assert spill_path.read_bytes() == text.encode("utf-8")
