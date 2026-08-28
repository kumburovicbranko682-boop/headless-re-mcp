"""Edge-path coverage for backends/apktool/client.py.

Targets the subprocess wrapper's timeout and launch-failure arms and the
decode/build/sign validation guards, using POSIX shell scripts as stand-ins
for the JVM tools.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError, _run

pytestmark = pytest.mark.skipif(os.name == "nt", reason="fake tools are POSIX shell scripts")


def _script(tmp_path: Path, body: str, *, name: str = "tool.sh") -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


def _apk(tmp_path: Path, *, name: str = "sample.apk") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\0")
    return path


# --- _run wrapper arms ---


def test_run_binds_the_jvm_to_the_deadline(tmp_path: Path) -> None:
    hang = _script(tmp_path, "sleep 30", name="hang.sh")

    with pytest.raises(ApktoolError) as caught:
        _run([str(hang)], timeout=0.5)

    assert caught.value.code == "timeout"
    assert caught.value.details["timeout"] == 0.5


def test_run_maps_a_launch_failure(tmp_path: Path) -> None:
    not_executable = tmp_path / "tool.sh"
    not_executable.write_text("just text")

    with pytest.raises(ApktoolError) as caught:
        _run([str(not_executable)], timeout=5.0)

    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


# --- decode guards and flag plumbing ---


def test_decode_requires_the_apk_to_exist(tmp_path: Path) -> None:
    apktool = _script(tmp_path, "exit 0", name="apktool.sh")
    client = ApktoolClient(apktool=apktool)

    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "missing.apk", tmp_path / "out")

    assert caught.value.code == "not_found"


def test_decode_passes_the_no_resources_flag(tmp_path: Path) -> None:
    out_dir = tmp_path / "decoded"
    apktool = _script(
        tmp_path,
        f'echo "$@" > "{tmp_path}/args.txt"\n'
        f'mkdir -p "{out_dir}"\n'
        f'touch "{out_dir}/AndroidManifest.xml"',
        name="apktool.sh",
    )
    client = ApktoolClient(apktool=apktool)

    result = client.decode(_apk(tmp_path), out_dir, no_resources=True)

    assert result["decoded_dir"] == str(out_dir)
    assert result["has_resources"] is False
    assert (tmp_path / "args.txt").read_text().split()[-1] == "-r"


# --- build guards ---


def test_build_requires_a_configured_apktool(tmp_path: Path) -> None:
    client = ApktoolClient()

    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path, tmp_path / "out.apk")

    assert caught.value.code == "capability_unavailable"


def test_build_requires_the_decoded_directory_to_exist(tmp_path: Path) -> None:
    apktool = _script(tmp_path, "exit 0", name="apktool.sh")
    client = ApktoolClient(apktool=apktool)

    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "missing", tmp_path / "out.apk")

    assert caught.value.code == "not_found"


def test_build_maps_a_failed_rebuild(tmp_path: Path) -> None:
    apktool = _script(tmp_path, "echo brokenAAPT >&2; exit 1", name="apktool.sh")
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>")
    client = ApktoolClient(apktool=apktool)

    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1
    assert "brokenAAPT" in str(caught.value.details["stderr"])


# --- sign guards ---


def test_sign_requires_the_apk_to_exist(tmp_path: Path) -> None:
    apksigner = _script(tmp_path, "exit 0", name="apksigner.sh")
    client = ApktoolClient(apksigner=apksigner)

    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "missing.apk", tmp_path / "signed.apk")

    assert caught.value.code == "not_found"


def test_sign_requires_the_keystore_to_exist(tmp_path: Path) -> None:
    apksigner = _script(tmp_path, "exit 0", name="apksigner.sh")
    client = ApktoolClient(apksigner=apksigner)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            _apk(tmp_path),
            tmp_path / "signed.apk",
            keystore=tmp_path / "missing.keystore",
        )

    assert caught.value.code == "not_found"
    assert "keystore" in caught.value.message


def test_sign_requires_credentials_for_a_custom_keystore(tmp_path: Path) -> None:
    apksigner = _script(tmp_path, "exit 0", name="apksigner.sh")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"jks")
    client = ApktoolClient(apksigner=apksigner)

    with pytest.raises(ApktoolError) as caught:
        client.sign(_apk(tmp_path), tmp_path / "signed.apk", keystore=keystore)

    assert caught.value.code == "invalid_params"
    assert "keystore_password" in caught.value.message
