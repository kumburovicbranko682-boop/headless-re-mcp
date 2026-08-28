from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent import config as provider_config
from headless_re_mcp.agent.config import (
    ProviderConfigStore,
    ProviderProfile,
    normalize_base_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@provider.example/v1",
        "https://access-token@provider.example",
        "http://:password@127.0.0.1:8000/v1",
    ],
)
def test_provider_base_url_rejects_embedded_credentials(url: str) -> None:
    with pytest.raises(ValueError, match="must not include credentials"):
        normalize_base_url(url)

    with pytest.raises(ValueError, match="must not include credentials"):
        ProviderProfile("unsafe", url, "model")


def test_provider_base_url_still_normalizes_safe_urls() -> None:
    assert normalize_base_url("HTTPS://provider.example:8443/api/") == (
        "https://provider.example:8443/api/v1"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.example/v1",
        "http://192.0.2.10:8000",
    ],
)
def test_provider_api_keys_are_not_sent_over_remote_plaintext(url: str) -> None:
    with pytest.raises(ValueError, match="API keys require HTTPS"):
        ProviderProfile("unsafe", url, "model", api_key="secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000",
    ],
)
def test_provider_api_keys_may_use_local_plaintext(url: str) -> None:
    profile = ProviderProfile("local", url, "model", api_key="secret")
    assert profile.base_url.startswith("http://")


def test_remote_plaintext_without_a_secret_remains_supported() -> None:
    profile = ProviderProfile("public", "http://provider.example", "model")
    assert profile.base_url == "http://provider.example/v1"


def test_list_public_skips_one_unusable_profile_instead_of_500ing(
    tmp_path: Path,
) -> None:
    # A single malformed profile -- here a hand-edited base_url -- used to make
    # _profile_from_raw raise straight out through the GET /api/providers route,
    # which has no error handler, so one bad entry hid every good one behind a
    # 500. The valid profiles must still list; the broken one is dropped like a
    # non-dict entry.
    import json

    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(ProviderProfile("good", "https://api.openai.com/v1", "m"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["profiles"]["bad"] = {"base_url": "not-a-url", "model": "m"}
    path.write_text(json.dumps(data), encoding="utf-8")

    listed = store.list_public()
    assert [profile["id"] for profile in listed["profiles"]] == ["good"]


def test_list_public_tolerates_a_bad_env_override_of_a_profile_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The env override is checked before the stored value, so a valid saved
    # profile plus a malformed HEADLESS_RE_PROVIDER_<ID>_BASE_URL is enough to
    # break _profile_from_raw. The list endpoint must degrade, not 500.
    store = ProviderConfigStore(tmp_path / "providers.json")
    store.save(ProviderProfile("default", "https://api.openai.com/v1", "m"))
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_DEFAULT_BASE_URL", "ftp://bad")

    listed = store.list_public()
    assert listed["profiles"] == []


def test_provider_config_is_rejected_before_an_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 64)
    path = tmp_path / "providers.json"
    path.write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(ValueError, match="provider config exceeds 64 bytes"):
        ProviderConfigStore(path).list_public()


def test_provider_config_refuses_writes_that_it_could_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 1024)
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(ProviderProfile("default", "https://provider.example", "small"))
    original = path.read_bytes()

    with pytest.raises(ValueError, match="provider config exceeds 1024 bytes"):
        store.save(
            ProviderProfile(
                "oversized",
                "https://provider.example",
                "x" * 2048,
            )
        )

    assert path.read_bytes() == original
