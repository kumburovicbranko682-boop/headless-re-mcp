"""The provider store holds real API keys; everything it shows must be masked.

providers.json is the one file in the deployment that legitimately contains a
provider credential in the clear, so two properties carry the risk: the file
itself must be private (0600/0700 on POSIX; icacls best-effort on Windows), and
every outward-facing form -- ``public()``, ``list_public()``, the Zerofall
import preview -- must carry only the mask, never the key. Nothing pinned
either property before.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.redaction import masked_secret

KEY = "sk-live-abcdef0123456789"


def _store(tmp_path: Path) -> ProviderConfigStore:
    return ProviderConfigStore(tmp_path / "meta" / "providers.json")


def _profile(**overrides: object) -> ProviderProfile:
    kwargs: dict = {
        "id": "default",
        "base_url": "https://api.example.com/v1",
        "model": "gpt-4.1-mini",
        "api_key": KEY,
    }
    kwargs.update(overrides)
    return ProviderProfile(**kwargs)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_saved_provider_file_is_private_on_posix(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save(_profile())

    assert store.path.is_file()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    # The file is where the key legitimately lives -- it must actually be there,
    # or the "private file" guarantee would be protecting nothing.
    assert KEY in store.path.read_text(encoding="utf-8")


def test_the_public_form_masks_the_key_but_reports_it_configured(tmp_path: Path) -> None:
    store = _store(tmp_path)
    saved = store.save(_profile())

    for label, blob in (
        ("save() return", saved),
        ("list_public()", store.list_public()),
    ):
        text = json.dumps(blob)
        assert KEY not in text, label
        assert "api_key_masked" in text, label

    assert saved["configured"] is True
    assert saved["api_key_masked"] == masked_secret(KEY) == f"{KEY[:2]}…{KEY[-2:]}"


def test_an_unconfigured_profile_says_so_without_inventing_a_mask() -> None:
    public = _profile(api_key=None).public()
    assert public["configured"] is False
    assert public["api_key_masked"] is None


def test_masked_secret_never_shows_more_than_the_edges() -> None:
    assert masked_secret(None) is None
    assert masked_secret("") is None
    # Short keys reveal nothing at all, not even their length.
    assert masked_secret("12345678") == "********"
    assert masked_secret("123456789") == "12…89"


def test_the_zerofall_preview_masks_every_credential_it_would_import(tmp_path: Path) -> None:
    store_raw = {
        "ai": {"apiBaseUrl": "https://api.example.com"},
        "apiKey": KEY,
        "providerApiKeys": {"openai": "sk-other-9876543210zyxw"},
        "model": "gpt-4.1-mini",
        "somethingUnknown": 1,
    }
    result = _store(tmp_path).preview_zerofall(store_raw)

    text = json.dumps(result, ensure_ascii=False)
    assert KEY not in text
    assert "sk-other-9876543210zyxw" not in text
    assert result["fields"]["apiKey"] == masked_secret(KEY)
    assert result["fields"]["providerApiKeys"]["openai"] == masked_secret(
        "sk-other-9876543210zyxw"
    )
    assert result["requires_confirmation"] is True
    assert "somethingUnknown" in result["ignored"]


def test_the_environment_key_overrides_the_file_and_still_never_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deployments keep the key out of the file entirely via HEADLESS_RE_PROVIDER_*."""
    store = _store(tmp_path)
    store.save(_profile(api_key=None))
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_API_KEY", "env-secret-key-123456")

    loaded = store.get("default")
    assert loaded.api_key == "env-secret-key-123456"

    text = json.dumps(store.list_public())
    assert "env-secret-key-123456" not in text
    # And the file on disk never gained the environment's key.
    assert "env-secret-key-123456" not in store.path.read_text(encoding="utf-8")


def test_a_stored_only_round_trip_keeps_the_environment_key_out_of_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """save(get(...)) is how routes warm caches; it must not bake env values in.

    The model-probe route and the provider PUT's absent-field fallbacks both
    read a profile and save it back. Reading the effective (env-merged) view
    for that round trip copied HEADLESS_RE_PROVIDER_API_KEY — the mechanism
    whose whole point is keeping the key out of providers.json — into the
    file, along with the env base_url/model overrides.
    """
    store = _store(tmp_path)
    store.save(_profile(api_key=None))
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_API_KEY", "env-secret-key-123456")
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_BASE_URL", "https://env-gateway.example/v1")

    stored = store.get("default", stored_only=True)
    assert stored.api_key is None
    assert stored.base_url == "https://api.example.com/v1"
    stored.known_models = ["model-a"]
    store.save(stored, make_current=False)

    text = store.path.read_text(encoding="utf-8")
    assert "env-secret-key-123456" not in text
    assert "env-gateway.example" not in text
    # The effective view still merges the environment for live use.
    assert store.get("default").api_key == "env-secret-key-123456"
    assert store.get("default").base_url == "https://env-gateway.example/v1"
