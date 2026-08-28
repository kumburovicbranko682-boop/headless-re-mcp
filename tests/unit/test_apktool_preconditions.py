"""apktool/apksigner preconditions: what is refused before (or around) the JVM.

The execution tests drive decode/build/sign past the ``_run`` seam; these cover
the guards that decide whether the JVM is launched at all -- an unconfigured
tool degrading to capability_unavailable, a missing apk/dir/keystore reported as
not_found rather than an opaque Java error after startup cost -- and the one
launch fault the seam itself must classify (an OSError from spawning the script)
as backend_error, matching the sibling adapters.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


def _executable(path: Path) -> Path:
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def test_run_maps_a_launch_oserror_to_backend_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A script that cannot be spawned is a backend problem, not an internal fault.

    apktool/apksigner are launcher scripts; if run_bounded raises OSError -- the
    JRE gone, the launcher not executable, the file vanished after the is_file
    check -- the seam must classify it as backend_error naming the launch, the
    same mapping jadx/ghidra/jsre use, rather than letting the raw OSError become
    an internal_error incident for a backend misconfiguration.
    """
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        raise OSError("jre missing")

    monkeypatch.setattr(apktool_client, "run_bounded", boom)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run([str(tmp_path / "apktool"), "d"], timeout=600.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


def test_decode_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    """A configured apktool pointed at a nonexistent apk is not_found, not a launch.

    The guard fires before the JVM starts, so the caller learns the input is
    missing rather than paying JVM startup for an opaque failure. The reply
    carries the path it looked for.
    """
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    assert client.available is True
    missing = tmp_path / "nope.apk"
    with pytest.raises(ApktoolError) as caught:
        client.decode(missing, tmp_path / "out")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_build_without_apktool_degrades_to_capability_unavailable(tmp_path: Path) -> None:
    """No apktool configured means build degrades, rather than erroring hard.

    build must answer capability_unavailable when apktool is not configured --
    the readiness contract that lets the server come up without it -- not a
    not_found or an internal_error.
    """
    client = ApktoolClient(None, None)
    assert client.available is False
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_a_dangling_configured_apktool_names_the_bad_path(tmp_path: Path) -> None:
    """Unset and typo'd HEADLESS_RE_APKTOOL must be distinguishable failures.

    Both degrade to capability_unavailable, but the dangling arm carries the
    configured path so the operator fixes the setting rather than reinstalling
    apktool -- the same unset/dangling split webcrack, r2 and jadx report.
    """
    dangling = tmp_path / "vendor" / "apktool"  # never created
    client = ApktoolClient(dangling, None)
    assert client.available is False
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"
    assert caught.value.details["executable"] == str(dangling)


def test_a_dangling_configured_apksigner_names_the_bad_path(tmp_path: Path) -> None:
    dangling = tmp_path / "vendor" / "apksigner"  # never created
    client = ApktoolClient(None, dangling)
    assert client.signer_available is False
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "app.apk", tmp_path / "signed.apk")
    assert caught.value.code == "capability_unavailable"
    assert caught.value.details["executable"] == str(dangling)


def test_build_reports_a_missing_decoded_directory_as_not_found(tmp_path: Path) -> None:
    """A decoded directory that is not there is not_found, before any launch.

    Distinct from a directory that exists but is not an apktool decode (that is
    invalid_params): a path that is not a directory at all is a missing input,
    named so the caller can see which path was wrong.
    """
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    missing = tmp_path / "gone"
    with pytest.raises(ApktoolError) as caught:
        client.build(missing, tmp_path / "out.apk")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_build_failure_is_a_backend_error_carrying_the_exit_code(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A nonzero apktool build (with no output written) is a backend_error.

    When apktool exits nonzero and leaves no apk, build must surface that as a
    backend_error carrying the exit code, not return a rebuilt-apk reply for a
    file that was never produced.
    """
    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del cmd, timeout, env
        return "", "apktool: build error", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_sign_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    """A configured apksigner pointed at a nonexistent apk is not_found.

    The guard fires before the signing JVM starts (and before any keystore or
    password handling), so a missing input is reported as such rather than as a
    signing failure.
    """
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    assert client.signer_available is True
    missing = tmp_path / "nope.apk"
    with pytest.raises(ApktoolError) as caught:
        client.sign(missing, tmp_path / "signed.apk")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing)


def test_sign_reports_a_missing_keystore_as_not_found(tmp_path: Path) -> None:
    """A keystore path that does not exist is not_found, before the JVM launches.

    sign resolves the keystore (custom, or the Android debug default) and must
    refuse a nonexistent one up front -- launching apksigner against a missing
    keystore only fails later with a Java error, and the reply here names the
    path that was not found.
    """
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    apk = _real_apk(tmp_path / "in.apk")
    missing_keystore = tmp_path / "absent.jks"
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=missing_keystore,
            keystore_password="pw",
            key_alias="a",
        )
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(missing_keystore)
