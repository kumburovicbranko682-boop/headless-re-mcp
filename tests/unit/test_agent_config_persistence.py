from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile


def _profile(*, api_key: str = "provider-secret") -> ProviderProfile:
    return ProviderProfile(
        id="default",
        base_url="https://provider.example/v1",
        model="example-model",
        api_key=api_key,
    )


def test_provider_config_save_is_atomic_and_leaves_no_temporary_secret(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)

    public = store.save(_profile())

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert public["configured"] is True
    assert saved["profiles"]["default"]["api_key"] == "provider-secret"
    assert list(tmp_path.glob(".providers.json-*.tmp")) == []


def test_a_surrogate_in_a_profile_field_is_refused_in_the_stores_voice(
    tmp_path: Path,
) -> None:
    """json.loads lets a lone \\ud800 escape into a profile field.

    The size check's encode raised the raw codec error as the save route's
    "validation" message. Refused rather than repaired because these fields
    include the API key, where a silent '?' would surface later as an
    inexplicable auth failure. The file on disk must stay untouched.
    """
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(_profile())
    before = path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="cannot be encoded as UTF-8"):
        store.save(_profile(api_key="secret \ud800 key"))

    assert path.read_text(encoding="utf-8") == before


def test_provider_config_preserves_original_if_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "providers.json"
    original = '{"profiles": {}, "current": null}'
    path.write_text(original, encoding="utf-8")
    store = ProviderConfigStore(path)

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        temporary = Path(source)
        assert temporary.is_file()
        assert "new-provider-secret" in temporary.read_text(encoding="utf-8")
        assert Path(destination) == path
        if os.name != "nt":
            assert temporary.stat().st_mode & 0o777 == 0o600
        raise OSError("replace failed")

    monkeypatch.setattr("headless_re_mcp.agent.config.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        store.save(_profile(api_key="new-provider-secret"))

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".providers.json-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_provider_config_is_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)

    store.save(_profile())

    assert path.stat().st_mode & 0o777 == 0o600
