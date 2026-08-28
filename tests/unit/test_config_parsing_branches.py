"""Settings parsing fallbacks and host-side IDA discovery guards in config.py.

The parsing helpers back every track's Settings load: an unreadable isolation
command or integer must fall back rather than stop the server from starting.
The install discovery runs on the setup status page for all work directions,
so its Linux glob path deserves the same guard coverage as the Windows one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp import config as config_module
from headless_re_mcp.config import validate_ida_home


class TestCommandParsing:
    def test_a_string_default_is_split_like_an_operator_wrote_it(self) -> None:
        got = config_module._as_command(None, "virsh snapshot-revert vm clean")
        assert got == ("virsh", "snapshot-revert", "vm", "clean")

    def test_no_raw_and_no_usable_default_yields_an_empty_command(self) -> None:
        assert config_module._as_command(None, None) == ()
        assert config_module._as_command(None, 42) == ()

    def test_a_list_default_drops_blank_parts(self) -> None:
        got = config_module._as_command(None, ["run", " ", "now"])
        assert got == ("run", "now")


class TestIntParsing:
    def test_unreadable_raw_and_default_fall_back(self) -> None:
        assert config_module._as_int("abc", "also-not-int", fallback=7) == 7

    def test_an_unstringable_default_falls_back(self) -> None:
        assert config_module._as_int(None, object(), fallback=3) == 3

    def test_a_readable_default_wins_over_the_fallback(self) -> None:
        assert config_module._as_int("nope", "12", fallback=3) == 12


class TestIdaHomeValidation:
    def test_an_empty_path_is_named_as_such(self) -> None:
        verdict = validate_ida_home("")
        assert verdict["ok"] is False
        assert verdict["code"] == "empty_path"


class TestLinuxInstallDiscovery:
    def test_a_missing_home_directory_is_skipped_quietly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "gone"))
        # Must not raise; /opt may or may not contribute on the host.
        candidates = config_module.list_ida_install_candidates()
        assert isinstance(candidates, list)

    def test_an_install_with_the_native_idalib_is_found_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        install = home / "idapro-9.1"
        install.mkdir(parents=True)
        (install / "libidalib.so").write_bytes(b"\x7fELF")
        # A second glob pattern reaching the same install via a symlink must
        # not produce a duplicate candidate.
        (home / "ida-9.1").symlink_to(install)
        # A lookalike without the runtime is not a candidate.
        (home / "idapro-8.4").mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        candidates = config_module.list_ida_install_candidates()
        assert candidates.count(install.resolve()) == 1
        assert home / "idapro-8.4" not in candidates
