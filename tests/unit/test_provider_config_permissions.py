"""The provider config holds API keys, so its file and directory stay owner-only.

``ProviderConfigStore._write`` persists via ``mkstemp`` (which opens at 0o600) +
``os.replace``, then chmods the final file 0o600; ``__init__`` chmods the parent
directory 0o700. No test covered the resulting on-disk modes, and that omission
matters precisely because ``mkstemp``'s default already makes the *current* file
safe: a "just write the file" refactor to ``self.path.write_text(...)`` would
create it under the process umask -- 0o644 (group/other readable) on the usual
0o022 default -- and quietly publish every stored API key to any local account,
with the existing provider tests (URL security, size bounds) none the wiser.

Pin the security invariant end to end: neither the config file nor its directory
grants any group or other permission, and the owner keeps read+write. The
directory arm is non-vacuous against the explicit chmod too -- a fresh
``mkdir`` yields 0o755 under the common umask, so only ``_best_effort_protect``
brings it to 0o700.

POSIX-only: on Windows the same guarantee is carried by ``icacls`` (see
``_best_effort_protect``), whose access model these Unix mode bits do not
describe.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX file-mode bits; Windows carries this through icacls"
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_saved_config_file_is_not_readable_by_group_or_other(tmp_path: Path) -> None:
    config = tmp_path / "cfg" / "providers.json"
    store = ProviderConfigStore(config)
    store.save(
        ProviderProfile("default", "https://api.example/v1", "model", api_key="sk-secret")
    )
    mode = _mode(config)
    assert mode & 0o077 == 0, (
        "the provider config holds API keys and must not be group/other accessible; "
        f"got {oct(mode)}"
    )
    assert mode & 0o600 == 0o600, (
        f"the owner must keep read+write on its own config; got {oct(mode)}"
    )


def test_config_directory_is_not_accessible_by_group_or_other(tmp_path: Path) -> None:
    config_dir = tmp_path / "cfg"
    ProviderConfigStore(config_dir / "providers.json")
    mode = _mode(config_dir)
    assert mode & 0o077 == 0, (
        "the provider config directory must not be group/other accessible; "
        f"got {oct(mode)}"
    )
