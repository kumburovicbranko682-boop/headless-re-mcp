"""``adb.pull`` re-checks after the transfer, because the pre-stat probe is best-effort.

Before moving bytes, ``pull`` tries ``sync.stat`` to refuse a directory or an
oversize file up front -- but that probe is wrapped in a bare ``except`` and
skipped entirely when the device does not answer it::

    if sync is not None:
        try:
            info = _call(sync.stat, remote_path, ...)
        except Exception:
            info = None            # probe unavailable -> pre-stat checks skipped
        else:
            ... refuse dir / refuse size ...

So on any device whose ``stat`` is missing or errors, the whole transfer runs
unguarded, and three post-transfer checks are the only thing standing between
the caller and a lie::

    _call(dev.sync.pull, remote_path, str(local_path), ...)
    if local_path.is_dir():
        shutil.rmtree(local_path, ignore_errors=True)
        raise AdbError("invalid_params", "refusing to keep a pulled directory", ...)
    if not local_path.exists():
        raise AdbError("not_found", "pull wrote no local file; ...", ...)
    pulled, over = capped_file_size(local_path, cap=cap)
    if over:
        raise AdbError("too_large", "pulled file exceeds capture cap", ...)

Every existing ``pull`` test has a working ``stat`` and a ``pull`` that writes a
small file, so the pre-stat guards fire (or the happy path runs) and none of
these three ever execute. They are exactly the fallbacks that a homogeneous
fixture renders inert:

* **A clean pull that wrote nothing is ``not_found``, not a size-0 success.**
  ``adb sync`` can report a clean pull yet create no local file when the remote
  path does not exist and adbutils does not raise. ``capped_file_size`` returns
  0 for a missing file, so without the ``exists`` check the reply is a size-0
  "success" the caller opens as a real empty file. Delete the check and a pull
  of a path that is not there reads as an empty download.

* **A directory the probe missed is refused *and* deleted.** If ``stat`` was
  unavailable and ``adb`` pulls a whole directory, the ``is_dir`` branch removes
  the tree and raises rather than returning a directory as a pulled "file".
  Delete it and a pulled tree is left on disk and reported as a success.

* **The size cap is re-enforced against the bytes actually written.** The
  pre-stat size refusal reads the device's claimed size; the post-transfer
  ``capped_file_size`` reads what really landed, so a probe that under-reported
  (or never ran) cannot smuggle an oversize file past the budget.

These inject a device whose ``stat`` raises -- forcing the pre-stat probe off --
and a ``pull`` that writes nothing, a directory, or oversize bytes, so each
post-transfer guard runs on its own. No adbutils, no emulator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _ProbelessSync:
    """A sync channel whose ``stat`` never answers, forcing the pre-stat probe off.

    ``mode`` selects what ``pull`` does with the local path once the transfer
    "succeeds": write nothing, create a directory, or write ``payload`` bytes.
    """

    def __init__(self, *, mode: str, payload: bytes = b"") -> None:
        self._mode = mode
        self._payload = payload

    def stat(self, remote: str, timeout: float | None = None) -> object:
        del remote, timeout
        raise RuntimeError("stat unavailable")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        if self._mode == "nothing":
            return
        if self._mode == "directory":
            Path(local).mkdir()
            return
        Path(local).write_bytes(self._payload)


class _FakeDev:
    def __init__(self, sync: _ProbelessSync) -> None:
        self.sync = sync


def _backend_with(sync: _ProbelessSync) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(sync)  # type: ignore[method-assign]
    return backend


def test_a_clean_pull_that_wrote_nothing_is_not_found(tmp_path: Path) -> None:
    """A missing remote can pull cleanly yet write no file: that is not_found.

    With the stat probe unavailable, nothing catches the missing remote up
    front; the post-transfer ``exists`` check is the only guard. Without it the
    caller would get ``size: 0`` and treat a path that is not there as a real
    empty download.
    """
    local = tmp_path / "gone.bin"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_ProbelessSync(mode="nothing")).pull("emulator-5554", "/sdcard/gone", local)
    assert excinfo.value.code == "not_found"
    assert not local.exists()


def test_a_directory_the_probe_missed_is_refused_and_removed(tmp_path: Path) -> None:
    """A directory pulled past a dead stat probe is refused and cleaned up.

    The pre-stat directory refusal never ran (stat raised), so the
    post-transfer ``is_dir`` branch must both reject the transfer and delete the
    tree -- otherwise a whole directory is left on disk and reported as a pulled
    file.
    """
    local = tmp_path / "tree"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_ProbelessSync(mode="directory")).pull(
            "emulator-5554", "/sdcard/dir", local
        )
    assert excinfo.value.code == "invalid_params"
    assert not local.exists()


def test_the_size_cap_is_re_enforced_against_the_bytes_that_landed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What actually landed is measured, not the device's claimed size.

    The stat probe is off, so the pre-stat size refusal never runs; the
    post-transfer ``capped_file_size`` reads the real file. Shrinking the cap to
    ten bytes makes a fifty-byte pull exceed it, and the transfer is refused as
    too_large even though the device offered no size at all.
    """
    monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 10)
    local = tmp_path / "big.bin"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(_ProbelessSync(mode="bytes", payload=b"x" * 50)).pull(
            "emulator-5554", "/sdcard/big", local
        )
    assert excinfo.value.code == "too_large"


def test_a_small_file_pulled_past_a_dead_probe_still_succeeds(tmp_path: Path) -> None:
    """The fallbacks do not punish an honest small pull when the probe is silent.

    A device with no working ``stat`` is common (older adbutils, restricted
    shells); a legitimate small file must still transfer and report its size, so
    the post-transfer checks stay scoped to their failure cases.
    """
    local = tmp_path / "ok.bin"
    payload = _backend_with(_ProbelessSync(mode="bytes", payload=b"hello"))
    result = payload.pull("emulator-5554", "/sdcard/ok.bin", local)
    assert result == {"remote": "/sdcard/ok.bin", "local": str(local), "size": 5}
    assert local.read_bytes() == b"hello"
