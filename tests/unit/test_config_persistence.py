"""update_config_values holds the autonomy grants and installer paths.

It is the only writer of the user config.json, invoked when a human clicks
"remember this approval" and when the dependency bundle installer records tool
paths. Losing unrelated keys on merge would silently drop someone's IDA path;
crashing on a corrupt file would make one bad write permanent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from headless_re_mcp import config as config_module
from headless_re_mcp.config import Settings, update_config_values


def test_a_merge_keeps_unrelated_keys_and_overwrites_named_ones(tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "config.json"
    update_config_values({"ida_home": "C:/ida", "http_port": 8765}, config_path=path)
    returned = update_config_values({"http_port": 9000}, config_path=path)

    assert returned == path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"ida_home": "C:/ida", "http_port": 9000}


def test_load_resolves_the_radare2_binary_name_from_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Settings.load must recognize the radare2 binary, like doctor and R2Client.

    R2Client._discover and the doctor probe both accept r2/rizin/radare2. A host
    with only the long-named ``radare2`` binary on PATH (no r2/rizin alias) left
    settings.r2 unset because the loader consulted only r2 then rizin -- the same
    binary-name gap one layer up. The client still worked through its own
    discovery, but config disagreed with the other two on what counts as radare2.
    """
    radare2 = tmp_path / "radare2"
    radare2.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        config_module.shutil,
        "which",
        lambda cmd: str(radare2) if cmd == "radare2" else None,
    )
    monkeypatch.delenv("HEADLESS_RE_R2", raising=False)

    settings = Settings.load(tmp_path / "no-such-config.json")

    assert settings.r2 == radare2.resolve()


def test_none_deletes_a_key_and_deleting_a_missing_key_is_quiet(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    update_config_values({"upx": "/usr/bin/upx", "keep": 1}, config_path=path)
    update_config_values({"upx": None, "never_there": None}, config_path=path)

    assert json.loads(path.read_text(encoding="utf-8")) == {"keep": 1}


def test_a_path_value_is_stored_as_a_string(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    update_config_values({"artifact_root": tmp_path / "artifacts"}, config_path=path)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["artifact_root"] == str(tmp_path / "artifacts")


def test_config_update_atomically_merges_values(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"kept": "value", "removed": True}),
        encoding="utf-8",
    )

    result = update_config_values(
        {"added_path": tmp_path / "tool.exe", "removed": None},
        config_path=path,
    )

    assert result == path
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "kept": "value",
        "added_path": str(tmp_path / "tool.exe"),
    }
    assert list(tmp_path.glob(".config.json-*.tmp")) == []


def test_config_update_preserves_original_if_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "config.json"
    original = '{"kept": true}\n'
    path.write_text(original, encoding="utf-8")

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        assert Path(source).is_file()
        assert Path(destination) == path
        raise OSError("replace failed")

    monkeypatch.setattr("headless_re_mcp.config.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        update_config_values({"new": "value"}, config_path=path)

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".config.json-*.tmp")) == []


@pytest.mark.parametrize("damaged", [b"{", b"[]", b"\xff"])
def test_config_update_refuses_to_overwrite_invalid_existing_config(
    tmp_path: Path,
    damaged: bytes,
) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(damaged)

    with pytest.raises(ValueError, match="existing config"):
        update_config_values({"local_full_access": True}, config_path=path)

    assert path.read_bytes() == damaged
    assert list(tmp_path.glob(".config.json-*.tmp")) == []


def test_config_reads_are_bounded_and_oversized_files_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_module, "_MAX_CONFIG_FILE_BYTES", 64)
    path = tmp_path / "config.json"
    payload = b'{"padding":"' + b"x" * 64 + b'"}'
    path.write_bytes(payload)

    with pytest.raises(ValueError, match="existing config"):
        update_config_values({"local_full_access": True}, config_path=path)
    assert path.read_bytes() == payload

    with pytest.raises(ValueError, match="configuration file exceeds 64 bytes"):
        Settings.load(path)


def test_config_update_refuses_a_file_it_could_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_module, "_MAX_CONFIG_FILE_BYTES", 128)
    path = tmp_path / "config.json"
    original = b'{"kept": true}\n'
    path.write_bytes(original)

    with pytest.raises(ValueError, match="configuration file exceeds 128 bytes"):
        update_config_values({"padding": "x" * 256}, config_path=path)

    assert path.read_bytes() == original
    assert list(tmp_path.glob(".config.json-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_config_update_restricts_permissions_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"existing": true}', encoding="utf-8")
    path.chmod(0o644)

    update_config_values({"new": "value"}, config_path=path)

    assert path.stat().st_mode & 0o777 == 0o600
