"""update_config_values holds the autonomy grants and installer paths.

It is the only writer of the user config.json, invoked when a human clicks
"remember this approval" and when the dependency bundle installer records tool
paths. Losing unrelated keys on merge would silently drop someone's IDA path;
crashing on a corrupt file would make one bad write permanent. Nothing tested
it directly -- callers only ever mocked it.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.config import update_config_values


def test_a_merge_keeps_unrelated_keys_and_overwrites_named_ones(tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "config.json"
    update_config_values({"ida_home": "C:/ida", "http_port": 8765}, config_path=path)
    returned = update_config_values({"http_port": 9000}, config_path=path)

    assert returned == path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"ida_home": "C:/ida", "http_port": 9000}


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


def test_a_corrupt_existing_file_is_replaced_not_fatal(tmp_path: Path) -> None:
    """One bad write (power loss, hand edit) must not wedge every later save."""
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    update_config_values({"http_port": 8765}, config_path=path)

    assert json.loads(path.read_text(encoding="utf-8")) == {"http_port": 8765}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_written_config_is_private_on_posix(tmp_path: Path) -> None:
    """config.json can carry autonomy grants; other local users get no say."""
    path = tmp_path / "config.json"
    update_config_values({"agent_auto_approve_tools": ["a.b"]}, config_path=path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
