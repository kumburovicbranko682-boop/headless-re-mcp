"""Device-free coverage for the ADB backend's pure parsers.

The adb client keeps its output/manifest parsing in small module-level
functions so they can be reasoned about without a device. None of them were
exercised: the install/uninstall tests monkeypatch ``_apk_package_name``
away to a fixed string, so the real manifest reader -- which parses an
attacker-supplied AndroidManifest.xml to decide which package gets
installed, launched or uninstalled -- had no coverage at all, and neither
did the ``pidof``/``ps -A`` PID reader or the device/stat row normalizers.

These pin:

- ``_apk_package_name`` recovers the id from a plain-text manifest and from
  the UTF-16 string pool of a compiled one, skips framework packages
  (``android.*`` / ``com.android.*``), and -- the load-bearing part --
  never returns a value that fails the package pattern, so a manifest whose
  ``package="..."`` is a path-traversal string yields None rather than a
  string that would later reach ``pm``. Missing/broken archives degrade to
  None, not an exception.
- ``_pids_for_package`` parses a pidof list, falls back to scanning ``ps -A``
  when pidof is unavailable, reads [] for a live-but-empty result, and
  returns None when the shell itself errors.
- ``_device_info_row`` / ``_file_mode_size`` accept both the attribute
  objects modern adbutils returns and the bare tuples older versions do.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

from headless_re_mcp.backends.adb.client import (
    _apk_package_name,
    _device_info_row,
    _file_mode_size,
    _pids_for_package,
)


def _apk(path: Path, manifest: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    return path


def test_apk_package_name_reads_a_plaintext_manifest(tmp_path: Path) -> None:
    apk = _apk(tmp_path / "text.apk", b'<manifest package="com.example.app"/>')
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_reads_the_utf16_string_pool(tmp_path: Path) -> None:
    # A compiled manifest stores strings UTF-16-LE with no `package="` literal,
    # so the reader has to fall through to the string-pool scan near the word
    # "package". Not valid to match via the plaintext regex.
    blob = ("package\x00com.example.app").encode("utf-16-le")
    apk = _apk(tmp_path / "binary.apk", blob)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_skips_framework_packages(tmp_path: Path) -> None:
    # The scan must not return an android.* / com.android.* token that happens
    # to sit near the marker; the real application id follows it.
    blob = ("package\x00com.android.internal com.example.app").encode("utf-16-le")
    apk = _apk(tmp_path / "framework.apk", blob)
    assert _apk_package_name(apk) == "com.example.app"


def test_apk_package_name_never_returns_an_invalid_id(tmp_path: Path) -> None:
    # A hostile manifest whose package attribute is a traversal string must not
    # come back as that string: it fails the package pattern, and no valid
    # token exists to fall back to, so the answer is None -- never a value that
    # would later be spliced into a pm command.
    apk = _apk(tmp_path / "hostile.apk", b'<manifest package="../../etc/passwd"/>')
    assert _apk_package_name(apk) is None


def test_apk_package_name_on_a_non_zip_is_none(tmp_path: Path) -> None:
    junk = tmp_path / "not.apk"
    junk.write_bytes(b"this is not a zip archive at all\n")
    assert _apk_package_name(junk) is None


def test_apk_package_name_without_a_manifest_is_none(tmp_path: Path) -> None:
    path = tmp_path / "nomanifest.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\n")
    assert _apk_package_name(path) is None


def test_device_info_row_from_attribute_object() -> None:
    info = SimpleNamespace(serial="emulator-5554", state="device")
    assert _device_info_row(info) == {"serial": "emulator-5554", "state": "device"}


def test_device_info_row_from_legacy_tuple() -> None:
    assert _device_info_row(("0123abcd", "offline")) == {
        "serial": "0123abcd",
        "state": "offline",
    }


def test_device_info_row_defaults_blank_state_to_unknown() -> None:
    info = SimpleNamespace(serial="dev1", state="")
    assert _device_info_row(info) == {"serial": "dev1", "state": "unknown"}


def test_device_info_row_from_single_element_tuple_defaults_the_state() -> None:
    # Some adbutils shapes carry only the serial; the missing state must still
    # normalize to "unknown" rather than an index error.
    assert _device_info_row(("solo-serial",)) == {"serial": "solo-serial", "state": "unknown"}


def test_apk_package_name_recovers_when_utf8_decode_fails(tmp_path: Path) -> None:
    # A compiled manifest whose bytes are not valid UTF-8 must not raise out of
    # the plaintext attempt: the reader falls through to the UTF-16 string-pool
    # scan and still finds the id.
    blob = b"\xff\xfe" + ("package\x00com.example.app").encode("utf-16-le")
    apk = _apk(tmp_path / "badutf8.apk", blob)
    assert _apk_package_name(apk) == "com.example.app"


def test_file_mode_size_from_attribute_object() -> None:
    info = SimpleNamespace(mode=0o100644, size=4096)
    assert _file_mode_size(info) == (0o100644, 4096)


def test_file_mode_size_from_legacy_tuple() -> None:
    assert _file_mode_size((0o040000, 0)) == (0o040000, 0)


def test_file_mode_size_coalesces_none() -> None:
    info = SimpleNamespace(mode=None, size=None)
    assert _file_mode_size(info) == (0, 0)


class _FakeDev:
    """A device whose shell() replays canned output keyed by the argv/string."""

    def __init__(self, responses: dict[object, object]) -> None:
        self._responses = responses

    def shell(self, args: object, timeout: float | None = None) -> str:
        del timeout
        key = tuple(args) if isinstance(args, list) else args
        value = self._responses[key]
        if isinstance(value, BaseException):
            raise value
        return str(value)


def test_pids_for_package_parses_a_pidof_list() -> None:
    dev = _FakeDev({("pidof", "com.example.app"): "1234 5678"})
    assert _pids_for_package(dev, "com.example.app") == [1234, 5678]


def test_pids_for_package_empty_pidof_is_empty_list() -> None:
    dev = _FakeDev({("pidof", "com.example.app"): ""})
    assert _pids_for_package(dev, "com.example.app") == []


def test_pids_for_package_falls_back_to_ps_when_pidof_missing() -> None:
    dev = _FakeDev(
        {
            ("pidof", "com.example.app"): "/system/bin/sh: pidof: not found",
            "ps -A": (
                "USER   PID  PPID  NAME\n"
                "u0_a1  4321  100  com.example.app\n"
                "root   1     0    init\n"
            ),
        }
    )
    assert _pids_for_package(dev, "com.example.app") == [4321]


def test_pids_for_package_shell_error_is_none() -> None:
    dev = _FakeDev({("pidof", "com.example.app"): RuntimeError("boom")})
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_none_when_pidof_missing_and_ps_errors() -> None:
    # pidof is unavailable *and* the ps -A fallback itself errors: there is no
    # answer to report, so the reader returns None rather than an empty list
    # (which would read as "package present but not running").
    dev = _FakeDev(
        {
            ("pidof", "com.example.app"): "/system/bin/sh: pidof: not found",
            "ps -A": RuntimeError("device offline"),
        }
    )
    assert _pids_for_package(dev, "com.example.app") is None


def test_pids_for_package_ps_scan_takes_the_first_numeric_token_per_line() -> None:
    # The ps fallback reads the first numeric column in the first three tokens
    # of a matching line; a non-numeric leading USER column must be skipped.
    dev = _FakeDev(
        {
            ("pidof", "com.example.app"): "pidof: unknown option",
            "ps -A": (
                "u0_a1 4321 100 com.example.app\n"
                "u0_a1 4322 100 com.example.app:remote\n"
            ),
        }
    )
    assert _pids_for_package(dev, "com.example.app") == [4321, 4322]


def test_pids_for_package_ps_scan_stops_at_sixteen_matches() -> None:
    # Guards against a pathological ps table growing the result without bound.
    lines = "\n".join(f"u0_a1 {1000 + i} 100 com.example.app" for i in range(40))
    dev = _FakeDev(
        {
            ("pidof", "com.example.app"): "no such tool",
            "ps -A": lines + "\n",
        }
    )
    pids = _pids_for_package(dev, "com.example.app")
    assert pids is not None
    assert len(pids) == 16
    assert pids[0] == 1000


def test_pids_for_package_ps_line_without_a_numeric_token_is_skipped() -> None:
    # A matching ps line whose first three columns are all non-numeric yields no
    # pid; the reader moves on rather than mis-reading a name as a pid.
    dev = _FakeDev(
        {
            ("pidof", "com.example.app"): "pidof: not found",
            "ps -A": "USER PPID NAME com.example.app\n",
        }
    )
    assert _pids_for_package(dev, "com.example.app") == []


def test_pids_for_package_nonempty_pidof_without_digits_is_none() -> None:
    # pidof answered, the text is not a "missing tool" message, yet no token
    # parses as a pid: that is a malformed result, reported as None.
    dev = _FakeDev({("pidof", "com.example.app"): "???"})
    assert _pids_for_package(dev, "com.example.app") is None
