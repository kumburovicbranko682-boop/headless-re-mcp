"""A caller input path the filesystem cannot name fails cleanly, never crashes.

``pathlib.Path.is_file()`` swallows ENOENT but *re-raises* ENAMETOOLONG (and
EACCES and friends), so the ``if not path.is_file(): raise not_found`` idiom the
file-input backends use crashed with an uncaught ``OSError`` when a caller
passed a path whose component ran past the filesystem's NAME_MAX (255 bytes on
ext4/most POSIX). ``backends/common/paths.is_regular_file`` routes those probes
through ``os.path.isfile``, which catches every ``OSError`` and answers False,
so an impossible path reads as the ``not_found`` it always should have.

The shared helper is pinned directly; each backend below is pinned at its own
call site so a site that grew a fresh ``Path.is_file()`` would still be caught.
Every over-length name here has an existing parent (``tmp_path``), so the kernel
reaches the over-length final component -- that is what makes ``Path.is_file()``
raise rather than quietly return False for a missing file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.paths import is_regular_file
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.backends.jsre.client import JsReError, _require_existing_file

# One component past NAME_MAX (255 on ext4/most POSIX); a plain str would join
# under tmp_path so the parent exists and the long leaf is the failing component.
_LONG = "A" * 300


def test_is_regular_file_answers_false_instead_of_raising(tmp_path: Path) -> None:
    """The helper never raises where Path.is_file() would, and is otherwise exact."""
    over_length = tmp_path / f"{_LONG}.bin"
    # The bug it exists to prevent: pathlib raises here rather than answering.
    with pytest.raises(OSError):
        over_length.is_file()
    assert is_regular_file(over_length) is False

    present = tmp_path / "real.bin"
    present.write_bytes(b"x")
    assert is_regular_file(present) is True
    assert is_regular_file(tmp_path / "missing.bin") is False
    # A directory is not a regular file, same as Path.is_file / os.path.isfile.
    assert is_regular_file(tmp_path) is False


def test_jsre_require_existing_file_rejects_an_over_length_path(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / f"{_LONG}.wasm", missing="wasm file not found")
    assert caught.value.code == "not_found"


def test_apk_require_rejects_an_over_length_path(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True  # reach the path probe without androguard installed
    with pytest.raises(ApkError) as caught:
        client._require(tmp_path / f"{_LONG}.apk")
    assert caught.value.code == "not_found"


def test_apktool_decode_rejects_an_over_length_apk(tmp_path: Path) -> None:
    tool = tmp_path / "apktool"
    tool.write_text("#!/bin/sh\n")  # a real file makes `available` True
    client = ApktoolClient(apktool=tool)
    assert client.available
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / f"{_LONG}.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_apktool_sign_rejects_an_over_length_apk(tmp_path: Path) -> None:
    signer = tmp_path / "apksigner"
    signer.write_text("#!/bin/sh\n")
    client = ApktoolClient(apksigner=signer)
    assert client.signer_available
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / f"{_LONG}.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_jadx_export_sources_rejects_an_over_length_apk(tmp_path: Path) -> None:
    executable = tmp_path / "jadx"
    executable.write_text("#!/bin/sh\n")
    client = JadxClient(executable)
    assert client.available
    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / f"{_LONG}.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_adb_install_rejects_an_over_length_local_apk(tmp_path: Path) -> None:
    # The local-file probe precedes the device round-trip, so no adbutils is
    # needed to reach it -- exactly why a bad path must fail fast here.
    backend = AdbBackend()
    with pytest.raises(AdbError) as caught:
        backend.install("emulator-5554", str(tmp_path / f"{_LONG}.apk"))
    assert caught.value.code == "not_found"


def test_adb_push_rejects_an_over_length_local_file(tmp_path: Path) -> None:
    backend = AdbBackend()
    with pytest.raises(AdbError) as caught:
        backend.push("emulator-5554", str(tmp_path / f"{_LONG}.bin"), "/data/local/tmp/x")
    assert caught.value.code == "not_found"
